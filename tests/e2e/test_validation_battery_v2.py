"""P0 acceptance contract for Validation Battery v2."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import math

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec
from quantlens_worker import runner
from quantlens_worker.artifacts import ArtifactIntegrityError, _canonical
from quantlens_worker.battery_v2 import run_development_battery_v2
from quantlens_worker.evidence_v2 import build_evidence_view_v2
from quantlens_worker.final_holdout import (
    FinalHoldoutError, evaluate_final_holdout, make_capsule,
)
from quantlens_worker.regimes import classify_regimes
from quantlens_worker.temporal_integrity import (
    TemporalIntegrityError,
    build_temporal_integrity_receipt,
    validate_temporal_integrity_receipt,
)
from quantlens_worker.validation_partition import build_partitions, validate_fold_laws
from quantlens_worker.validation_plan import build_validation_plan, sha256_json

@pytest.fixture()
def client(var_env):
    with TestClient(app) as value:
        yield value


def _spec() -> dict:
    value = default_spec("QQQ")
    value["data"]["range"] = {"start": "2015-01-01", "end": "2020-12-31"}
    return value


def _create_v2(client: TestClient, spec: dict | None = None) -> tuple[str, dict]:
    spec = copy.deepcopy(spec or _spec())
    validation = client.post("/specs/validate", json={
        "spec": spec, "battery_profile": "battery-v2",
    })
    assert validation.status_code == 200, validation.json()
    validated = validation.json()
    assert validated["valid"]
    assert validated["battery_profile"]["profile_id"] == "battery-v2"
    assert "never used for tuning or counterfactuals" in validated["restatement"]
    assert "sweeps MA windows" not in validated["restatement"]
    response = client.post(
        "/runs",
        json=validated_run_payload(client, spec, battery_profile="battery-v2"),
    )
    assert response.status_code == 201, response.json()
    return response.json()["run_id"], validated


def _frame(n: int = 1_600) -> pd.DataFrame:
    closes = [100.0 + 0.025 * index + 4.0 * math.sin(index / 31.0)
              for index in range(n)]
    dates = pd.bdate_range("2010-01-04", periods=n).strftime("%Y-%m-%d")
    opens = [closes[0], *closes[:-1]]
    return pd.DataFrame({
        "date": dates,
        "open": opens,
        "high": [max(o, c) * 1.001 for o, c in zip(opens, closes)],
        "low": [min(o, c) * 0.999 for o, c in zip(opens, closes)],
        "close": closes,
        "volume": [1_000_000] * n,
    })


def test_profile_hash_confirmation_is_required_for_v2(client):
    spec = _spec()
    validation = client.post("/specs/validate", json={
        "spec": spec, "battery_profile": "battery-v2",
    }).json()
    stale = client.post("/runs", json={
        "spec": spec, "confirmed": True, "restatement_seen": True,
        "confirmed_spec_hash": validation["spec_hash"],
        "battery_profile": "battery-v2",
        "confirmed_battery_profile_hash": "sha256:" + "0" * 64,
    })
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "BATTERY_CONFIRMATION_STALE"


def test_partition_folds_are_continuous_non_overlapping_and_prefix_isolated():
    spec = _spec()
    frame = _frame()
    plan = build_validation_plan(spec, len(frame))
    partitions = build_partitions(frame, plan)
    validate_fold_laws(partitions.artifact)
    folds = partitions.artifact["folds"]
    assert folds
    assert all(fold["test_end_index"] <= partitions.artifact["development"]["end_index"]
               for fold in folds)
    assert all(fold["visible_prefix_end_index"] == fold["test_end_index"] for fold in folds)
    assert partitions.artifact["development"]["end_index"] == \
        partitions.artifact["final_holdout"]["start_index"]
    assert partitions.development["date"].iloc[-1] < \
        partitions.final_capsule_frame["date"].iloc[partitions.final_local_start]


def test_regime_labels_are_t_minus_one_and_cover_only_four_states():
    frame = _frame(900)
    baseline = classify_regimes(frame)
    changed = frame.copy()
    changed.loc[850:, "close"] *= 10.0
    mutated = classify_regimes(changed)
    assert baseline.loc[:850, "regime"].tolist() == mutated.loc[:850, "regime"].tolist()
    assert set(baseline["regime"].dropna()) <= {
        "up_low", "up_high", "down_low", "down_high",
    }


def test_development_battery_is_deterministic_and_has_no_parameter_selection():
    spec = _spec()
    frame = _frame()
    plan = build_validation_plan(spec, len(frame))
    partitions = build_partitions(frame, plan)
    first = run_development_battery_v2(
        partitions.development, spec, plan, partitions.artifact)
    second = run_development_battery_v2(
        partitions.development, spec, plan, partitions.artifact)
    assert first == second
    assert first["sensitivity"]["grid"] == []
    assert first["walk_forward"]["parameter_selection"] == "forbidden"
    parameters = set(inspect.signature(evaluate_final_holdout).parameters)
    assert not ({"grid", "cost_multiplier", "agent_prompt", "selection"} & parameters)


def test_small_data_is_structurally_inconclusive_without_final_consumption():
    spec = _spec()
    frame = _frame(600)
    plan = build_validation_plan(spec, len(frame))
    partitions = build_partitions(frame, plan)
    result = run_development_battery_v2(
        partitions.development, spec, plan, partitions.artifact)
    assert partitions.artifact["status"] == "INCONCLUSIVE"
    assert result["evidence_status"]["battery_status"] == "INCONCLUSIVE"


def test_temporal_receipt_tamper_fails_closed(client):
    run_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    run = db.get_run_internal(run_id)
    _manifest, _ledger, payloads = runner.load_sealed_artifacts(
        db.var_dir() / "artifacts" / run_id, expected_run=run)
    tampered = copy.deepcopy(payloads["temporal_integrity"])
    tampered["boundaries"]["final_holdout"]["start_index"] -= 1
    with pytest.raises(TemporalIntegrityError):
        validate_temporal_integrity_receipt(
            tampered,
            validation_plan=payloads["validation_plan"],
            partitions=payloads["partitions"],
            spec_hash=run["spec_hash"],
            snapshot_sha256=payloads["snapshot_ref"]["sha256"],
            final_audit=payloads["final_holdout_execution_audit"],
        )


def test_end_to_end_v2_has_single_final_read_and_agent_projection_has_no_final_taint(client):
    run_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    evidence = client.get(f"/runs/{run_id}/evidence")
    assert evidence.status_code == 200, evidence.json()
    view = evidence.json()
    assert view["evidence_view_version"] == "v2"
    audit = view["final_holdout_execution_audit"]
    assert audit["primary_evaluation_count"] == 1
    assert audit["counterfactual_evaluation_count"] == 0
    assert view["sensitivity"]["grid"] == []
    projection = json.dumps(view["agent_projection"], sort_keys=True).lower()
    for forbidden in ("final", "holdout", "sha256", "capsule", "2015-", "2020-"):
        assert forbidden not in projection
    explanation = client.get(f"/runs/{run_id}/explanation")
    assert explanation.status_code == 200, explanation.json()
    body = explanation.json()
    assert body["scope"] == "development_only"
    assert body["generation"]["provider_invoked"] is False
    run = db.get_run_internal(run_id)
    second_claim = db.claim_final_holdout(
        run_id, spec_hash=run["spec_hash"],
        validation_plan_hash=view["validation_plan"]["validation_plan_hash"],
    )
    assert second_claim["claimed"] is False
    assert second_claim["state"] == "final.result"


def test_result_persisted_before_seal_recovers_without_second_evaluation(
    client, monkeypatch,
):
    run_id, _ = _create_v2(client)
    original_evaluate = runner.evaluate_final_holdout
    original_complete = runner.db.complete_final_holdout
    calls = {"evaluate": 0, "complete": 0}

    def counted_evaluate(*args, **kwargs):
        calls["evaluate"] += 1
        return original_evaluate(*args, **kwargs)

    def complete_then_crash(run_id_value, result):
        calls["complete"] += 1
        original_complete(run_id_value, result)
        if calls["complete"] == 1:
            raise RuntimeError("simulated crash after durable final result")

    monkeypatch.setattr(runner, "evaluate_final_holdout", counted_evaluate)
    monkeypatch.setattr(runner.db, "complete_final_holdout", complete_then_crash)
    assert runner.process_next() == "published"
    assert calls["evaluate"] == 1
    run = db.get_run_internal(run_id)
    _manifest, _ledger, payloads = runner.load_sealed_artifacts(
        db.var_dir() / "artifacts" / run_id, expected_run=run)
    assert payloads["final_holdout_execution_audit"]["recovered_result"] is True


def test_final_capability_is_consumed_exactly_once():
    spec = _spec()
    frame = _frame(900)
    capsule = make_capsule(
        frame, 200, capsule_sha256="sha256:" + "a" * 64)
    kwargs = {
        "confirmed_spec_hash": "sha256:" + "b" * 64,
        "validation_plan_hash": "sha256:" + "c" * 64,
        "locked_rule": spec["rule"],
        "base_costs": spec["costs"],
        "benchmark_symbol": "QQQ",
    }
    evaluate_final_holdout(capsule, **kwargs)
    with pytest.raises(FinalHoldoutError, match="already been consumed"):
        evaluate_final_holdout(capsule, **kwargs)


def test_cross_run_reveal_reuses_identical_result_and_rejects_changed_rule(
    client, monkeypatch,
):
    calls = {"evaluate": 0}
    original = runner.evaluate_final_holdout

    def counted(*args, **kwargs):
        calls["evaluate"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "evaluate_final_holdout", counted)
    first_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    second_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    assert calls["evaluate"] == 1
    second_view = client.get(f"/runs/{second_id}/evidence").json()
    second_audit = second_view["final_holdout_execution_audit"]
    assert second_audit["reused_across_run"] is True
    assert second_audit["run_primary_evaluation_count"] == 0
    assert second_view["final_holdout_result"] == \
        client.get(f"/runs/{first_id}/evidence").json()["final_holdout_result"]

    changed = _spec()
    changed["rule"]["ma_days"] = 199  # same final boundary; different locked plan/spec
    changed["validation"]["sensitivity"]["grid"]["ma_days"].append(199)
    changed["validation"]["sensitivity"]["grid"]["ma_days"].sort()
    changed_id, _ = _create_v2(client, changed)
    assert runner.process_next() == "system_failed"
    rejected = db.get_run_internal(changed_id)
    assert rejected["error"]["code"] == "FINAL_HOLDOUT_CONSUMED"
    assert calls["evaluate"] == 1


def test_evidence_recomputes_server_plan_from_sealed_spec(client):
    run_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    run = db.get_run_internal(run_id)
    manifest, ledger, payloads = runner.load_sealed_artifacts(
        db.var_dir() / "artifacts" / run_id, expected_run=run)
    forged = copy.deepcopy(payloads)
    forged["validation_plan"]["plan_version"] = "attacker-plan"
    plan_body = {key: value for key, value in forged["validation_plan"].items()
                 if key != "validation_plan_hash"}
    forged["validation_plan"]["validation_plan_hash"] = sha256_json(plan_body)
    binding = forged["final_holdout_result"]["execution_binding"]
    binding["validation_plan_hash"] = forged["validation_plan"]["validation_plan_hash"]
    forged["final_holdout_execution_audit"]["validation_plan_hash"] = \
        forged["validation_plan"]["validation_plan_hash"]
    forged["final_holdout_execution_audit"]["execution_binding"] = copy.deepcopy(binding)
    forged["temporal_integrity"] = build_temporal_integrity_receipt(
        validation_plan=forged["validation_plan"],
        partitions=forged["partitions"], spec_hash=run["spec_hash"],
        snapshot_sha256=manifest["snapshot_sha256"],
        final_audit=forged["final_holdout_execution_audit"],
    )
    with pytest.raises(ArtifactIntegrityError, match="not reproduced"):
        build_evidence_view_v2(
            manifest, ledger, forged, run["confirmation_receipt"])


def test_control_plane_anchor_rejects_self_consistent_artifact_rewrite(client):
    run_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    run_dir = db.var_dir() / "artifacts" / run_id
    artifact_path = run_dir / "artifact_validation_plan.json"
    wrapper = json.loads(artifact_path.read_text())
    wrapper["payload"]["plan_version"] = "self-consistent-forgery"
    artifact_body = _canonical(wrapper)
    artifact_path.write_bytes(artifact_body)
    artifact_sha = hashlib.sha256(artifact_body).hexdigest()

    ledger_path = run_dir / "ledger_index.json"
    ledger = json.loads(ledger_path.read_text())
    entry = next(item for item in ledger["entries"]
                 if item["kind"] == "validation_plan")
    entry["sha256"] = artifact_sha
    entry["artifact_id"] = f"validation_plan-{artifact_sha[:12]}"
    ledger["result_hash"] = "sha256:" + hashlib.sha256(
        "".join(sorted(item["sha256"] for item in ledger["entries"])).encode()
    ).hexdigest()
    ledger_path.write_bytes(_canonical(ledger))
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["result_hash"] = ledger["result_hash"]
    manifest_path.write_bytes(_canonical(manifest))

    assert client.get(f"/runs/{run_id}/evidence").status_code == 409
    assert client.get(f"/runs/{run_id}/report").status_code == 409
    assert client.get(f"/runs/{run_id}/explanation").status_code == 409


def test_v2_report_has_profile_specific_semantics_and_producer(client):
    run_id, _ = _create_v2(client)
    assert runner.process_next() == "published"
    report = client.get(f"/runs/{run_id}/report")
    assert report.status_code == 200, report.text
    text = report.text.lower()
    for required in (
        "development walk-forward", "development-only cost stress",
        "final primary return", "no parameter search",
        "walk forward stability", "development cost fragility", "regime coverage",
        "independent os principal", "production mac",
    ):
        assert required in text
    for forbidden in (
        "final counterfactual", "parameter sweep", "parameter grid",
        "+battery-v1",
    ):
        assert forbidden not in text
    ledger = client.get(f"/runs/{run_id}/artifacts").json()
    assert all(item["producer"].endswith("+battery-v2")
               for item in ledger["entries"])


def test_v1_default_remains_compatible(client):
    spec = _spec()
    response = client.post("/runs", json=validated_run_payload(client, spec))
    assert response.status_code == 201
    assert runner.process_next() == "published"
    evidence = client.get(f"/runs/{response.json()['run_id']}/evidence").json()
    assert evidence["evidence_view_version"] == "v1"
