"""Adversarial worker tests: checkpoint replay, crash recovery, and tamper failure."""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec
from quantlens_worker import runner
from quantlens_worker.artifacts import ArtifactIntegrityError, load_sealed_artifacts
from quantlens_worker.report import render_report


@pytest.fixture()
def client(var_env):
    with TestClient(app) as test_client:
        yield test_client


def _accept(client: TestClient, *, symbol: str = "SPY") -> str:
    spec = default_spec(symbol)
    spec["data"]["range"] = {"start": "2012-01-01", "end": "2019-12-31"}
    response = client.post("/runs", json=validated_run_payload(client, spec))
    assert response.status_code == 201, response.json()
    return response.json()["run_id"]


def _accept_spec(client: TestClient, spec: dict) -> str:
    response = client.post("/runs", json=validated_run_payload(client, spec))
    assert response.status_code == 201, response.json()
    return response.json()["run_id"]


def test_report_retry_replays_sealed_artifacts_without_recomputing_or_recharging(
        client, monkeypatch):
    run_id = _accept(client)
    original_battery = runner.run_battery
    original_render = runner.render_report
    calls = {"battery": 0, "render": 0}

    def counted_battery(*args, **kwargs):
        calls["battery"] += 1
        return original_battery(*args, **kwargs)

    def flaky_render(*args, **kwargs):
        calls["render"] += 1
        if calls["render"] == 1:
            raise RuntimeError("simulated template outage")
        return original_render(*args, **kwargs)

    monkeypatch.setattr(runner, "run_battery", counted_battery)
    monkeypatch.setattr(runner, "render_report", flaky_render)
    before = db.entitlement_status()["used"]

    assert runner.process_next() == "published"
    assert calls == {"battery": 1, "render": 2}
    assert db.entitlement_status()["used"] == before + 1
    assert db.get_reservation(run_id)["status"] == "settled"
    history = [status for status, _ in db.get_run(run_id)["history"]]
    assert history.count("ledger_sealed") == 1


def test_crash_after_checkpoint_is_recovered_without_recompute(client, monkeypatch):
    run_id = _accept(client)
    original_battery = runner.run_battery
    original_settle = runner.db.settle_reservation
    calls = {"battery": 0, "settle": 0}

    def counted_battery(*args, **kwargs):
        calls["battery"] += 1
        return original_battery(*args, **kwargs)

    def crash_once(run_id_arg):
        calls["settle"] += 1
        if calls["settle"] == 1:
            raise KeyboardInterrupt("simulated worker death")
        return original_settle(run_id_arg)

    monkeypatch.setattr(runner, "run_battery", counted_battery)
    monkeypatch.setattr(runner.db, "settle_reservation", crash_once)
    monkeypatch.setenv("QL_STALE_RUN_SECONDS", "0")
    with pytest.raises(KeyboardInterrupt):
        runner.process_next()

    assert db.get_run(run_id)["status"] == "ledger_sealed"
    assert db.get_reservation(run_id)["status"] == "reserved"
    assert (db.var_dir() / "artifacts" / run_id / "manifest.json").exists()

    assert runner.process_next() == "published"  # stale lease recovery happens first
    assert calls["battery"] == 1
    assert db.get_reservation(run_id)["status"] == "settled"
    assert "recovered_queued" in [status for status, _ in db.get_run(run_id)["history"]]


def test_persistent_settlement_failure_holds_quota_and_withholds_evidence_until_recovery(
        client, monkeypatch):
    before = db.entitlement_status()
    run_id = _accept(client)
    original_battery = runner.run_battery
    original_settle = runner.db.settle_reservation
    calls = {"battery": 0, "settle": 0}

    def counted_battery(*args, **kwargs):
        calls["battery"] += 1
        return original_battery(*args, **kwargs)

    def unavailable_settlement(_run_id):
        calls["settle"] += 1
        raise RuntimeError("simulated persistent settlement outage")

    monkeypatch.setattr(runner, "run_battery", counted_battery)
    monkeypatch.setattr(runner.db, "settle_reservation", unavailable_settlement)
    monkeypatch.setenv("QL_STALE_RUN_SECONDS", "0")

    assert runner.process_next() == "ledger_sealed"
    pending = db.get_run(run_id)
    assert pending["error"]["code"] == "SETTLEMENT_PENDING"
    assert pending["error"]["settlement_pending"] is True
    assert pending["reservation"]["status"] == "reserved"
    assert db.entitlement_status()["used"] == before["used"]
    assert db.entitlement_status()["reserved"] == before["reserved"] + 1
    assert calls == {"battery": 1, "settle": runner.MAX_RETRIES + 1}
    assert [status for status, _ in pending["history"]].count("ledger_sealed") == 1

    evidence = client.get(f"/runs/{run_id}/evidence")
    assert evidence.status_code == 409
    assert evidence.json()["code"] == "SETTLEMENT_PENDING"
    report = client.get(f"/runs/{run_id}/report")
    assert report.status_code == 409
    assert report.json()["code"] == "SETTLEMENT_PENDING"

    monkeypatch.setattr(runner.db, "settle_reservation", original_settle)
    assert runner.process_next() == "published"
    recovered = db.get_run(run_id)
    assert recovered["reservation"]["status"] == "settled"
    assert db.entitlement_status()["used"] == before["used"] + 1
    assert db.entitlement_status()["reserved"] == before["reserved"]
    assert calls["battery"] == 1
    assert client.get(f"/runs/{run_id}/evidence").status_code == 200
    assert client.get(f"/runs/{run_id}/report").status_code == 200


def test_tampered_sealed_artifact_cannot_render(client):
    run_id = _accept(client)
    assert runner.process_next() == "published"
    run = db.get_run(run_id)
    run_dir = db.var_dir() / "artifacts" / run_id
    ledger = json.loads((run_dir / "ledger_index.json").read_text())
    target = run_dir / ledger["entries"][0]["path"]
    target.write_bytes(target.read_bytes() + b"\n")

    with pytest.raises(ArtifactIntegrityError, match="hash mismatch"):
        render_report(run_dir, expected_run=run)


def test_ledger_path_traversal_is_rejected_before_read(client):
    run_id = _accept(client)
    assert runner.process_next() == "published"
    run = db.get_run(run_id)
    run_dir = db.var_dir() / "artifacts" / run_id
    ledger_path = run_dir / "ledger_index.json"
    ledger = json.loads(ledger_path.read_text())
    ledger["entries"][0]["path"] = "../manifest.json"
    ledger_path.write_text(json.dumps(ledger))

    with pytest.raises(ArtifactIntegrityError, match="unsafe ledger entry path"):
        load_sealed_artifacts(run_dir, expected_run=run)


def test_manifest_must_match_current_engine_runtime_and_battery(client):
    run_id = _accept(client)
    assert runner.process_next() == "published"
    run = db.get_run(run_id)
    run_dir = db.var_dir() / "artifacts" / run_id
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["engine_semver"] = "999.0.0"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ArtifactIntegrityError, match="engine_semver is not current"):
        load_sealed_artifacts(run_dir, expected_run=run)


def test_sealed_spec_hash_is_recomputed_from_spec_bytes(client):
    run_id = _accept(client)
    assert runner.process_next() == "published"
    run = db.get_run(run_id)
    run_dir = db.var_dir() / "artifacts" / run_id
    ledger_path = run_dir / "ledger_index.json"
    ledger = json.loads(ledger_path.read_text())
    spec_entry = next(entry for entry in ledger["entries"] if entry["kind"] == "spec")
    spec_path = run_dir / spec_entry["path"]
    wrapper = json.loads(spec_path.read_text())
    wrapper["payload"]["spec"]["meta"]["name"] = "coherently rehashed tamper"
    body = json.dumps(
        wrapper, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode()
    new_sha = hashlib.sha256(body).hexdigest()
    spec_path.write_bytes(body)
    spec_entry["sha256"] = new_sha
    spec_entry["artifact_id"] = f"spec-{new_sha[:12]}"
    ledger["result_hash"] = "sha256:" + hashlib.sha256(
        "".join(sorted(entry["sha256"] for entry in ledger["entries"])).encode(),
    ).hexdigest()
    ledger_path.write_text(json.dumps(ledger))
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["result_hash"] = ledger["result_hash"]
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ArtifactIntegrityError, match="spec hash does not match"):
        load_sealed_artifacts(run_dir, expected_run=run)


def test_terminal_preseal_system_failure_releases_reservation(client, monkeypatch):
    run_id = _accept(client)
    before = db.entitlement_status()["used"]

    def unavailable_snapshot(*_args, **_kwargs):
        raise RuntimeError("snapshot service unavailable")

    monkeypatch.setattr(runner, "verify_snapshot_integrity", unavailable_snapshot)
    assert runner.process_next() == "system_failed"
    entitlement = db.entitlement_status()
    assert entitlement["used"] == before
    assert entitlement["reserved"] == 0
    assert db.get_reservation(run_id)["status"] == "released"
    assert db.get_run(run_id)["error"]["quota_charged"] is False


def test_runner_loads_and_seals_requested_alternate_benchmark(client):
    spec = default_spec("SPY")
    spec["benchmark"]["symbol"] = "TLT"
    spec["data"]["range"] = {"start": "2012-01-01", "end": "2019-12-31"}
    run_id = _accept_spec(client, spec)

    assert runner.process_next() == "published"
    run_dir = db.var_dir() / "artifacts" / run_id
    _, _, payloads = load_sealed_artifacts(run_dir, expected_run=db.get_run(run_id))
    assert payloads["is_result"]["benchmark_symbol"] == "TLT"
    assert payloads["oos_result"]["benchmark_symbol"] == "TLT"
    assert payloads["is_result"]["benchmark_entry"]["symbol"] == "TLT"
    assert payloads["data_gaps"]["benchmark_symbol"] == "TLT"
    assert "benchmark" in payloads["data_gaps"]
