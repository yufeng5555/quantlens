"""The Gate 2 proof slice: one local E2E flow from mock-parsed hypothesis through edit,
confirmation, queue, worker, sealed ledger, manifest v0, and the HTML Strategy Evidence
Report — plus ledger-level determinism (AT-3.1/3.2 local approximation), manifest
completeness (AT-12.2), failure paths, quota semantics, and synthetic labeling."""

import json
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec, load_manifest_schema
from quantlens_worker.runner import process_next


@pytest.fixture()
def client(var_env):
    with TestClient(app) as c:
        yield c


def _confirm_and_run(client, spec) -> str:
    r = client.post("/runs", json=validated_run_payload(client, spec))
    assert r.status_code == 201, r.json()
    return r.json()["run_id"]


def test_full_local_e2e_from_hypothesis_to_report(client):
    # 1. MOCK parse
    p = client.post("/parse", json={
        "hypothesis": "own QQQ when it's above its 200-day average, otherwise cash"}).json()
    assert p["status"] == "draft"
    spec = p["draft"]
    # 2. user edits a card (edits win — AT-1.5)
    spec["costs"]["slippage_bps"] = 8
    spec["data"]["range"] = {"start": "2010-01-01", "end": "2020-12-31"}
    # 3. confirm (restatement seen, hash-bound) and 4. queue
    run_id = _confirm_and_run(client, spec)
    assert client.get(f"/runs/{run_id}").json()["status"] == "queued"
    # 5. worker processes
    assert process_next() == "published"
    run = client.get(f"/runs/{run_id}").json()
    lifecycle = [s for s, _ in run["history"]]
    assert lifecycle == ["confirmed", "validated", "queued", "snapshot_pinned",
                        "running_engine", "running_battery", "ledger_sealed",
                        "report_rendered", "published"]
    # 6. report exists and carries the required sections
    rep = client.get(f"/runs/{run_id}/report")
    assert rep.status_code == 200
    html = rep.text
    for needle in [
        "SYNTHETIC DATA", "Strategy Evidence Report",
        "What was tested", "Methodology", "Data &amp; provenance",
        "In-sample", "Out-of-sample", "the honest estimate",
        "Transaction-cost stress", "Parameter sensitivity",
        "Falsification", "Show the math", "Research follow-up checklist",
        "Limitations", "Standing disclosure",
        "not investment advice, not an\n    approval, and not a forecast",
    ]:
        assert needle.split("\n")[0] in html, f"report missing: {needle}"
    # user's edited slippage appears, not the default
    assert "8 bps slippage" in html
    # every artifact id in the ledger resolves to a file
    ledger = client.get(f"/runs/{run_id}/artifacts").json()
    art_dir = db.var_dir() / "artifacts" / run_id
    for entry in ledger["entries"]:
        assert (art_dir / entry["path"]).exists()
    # manifest v0 is schema-complete (AT-12.2)
    manifest = client.get(f"/runs/{run_id}/manifest").json()
    jsonschema.validate(manifest, load_manifest_schema())
    assert manifest["data_label"] == "SYNTHETIC"
    assert manifest["result_hash"] == ledger["result_hash"]


def test_ledger_determinism_same_spec_same_hashes(client):
    """AT-3.1 locally: identical spec + snapshot + engine => identical artifact hashes
    and result hash across two independent worker executions."""
    spec = default_spec("SPY")
    spec["data"]["range"] = {"start": "2012-01-01", "end": "2019-12-31"}
    id_a = _confirm_and_run(client, spec)
    id_b = _confirm_and_run(client, spec)
    assert process_next() == "published"
    assert process_next() == "published"
    ledger_a = client.get(f"/runs/{id_a}/artifacts").json()
    ledger_b = client.get(f"/runs/{id_b}/artifacts").json()
    hashes_a = {e["kind"]: e["sha256"] for e in ledger_a["entries"] if e["kind"] != "spec"}
    hashes_b = {e["kind"]: e["sha256"] for e in ledger_b["entries"] if e["kind"] != "spec"}
    assert hashes_a == hashes_b
    # spec artifacts differ only by embedded hash? No — identical spec => identical too.
    assert ledger_a["result_hash"] == ledger_b["result_hash"]


def test_manifest_missing_field_fails_schema_check():
    manifest_schema = load_manifest_schema()
    for field in manifest_schema["required"]:
        broken = {k: "x" for k in manifest_schema["required"]}
        broken.pop(field)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(broken, manifest_schema)


def test_preflight_data_quality_blocker_creates_no_run_or_reservation(client):
    spec = default_spec("SPY")
    spec["data"]["range"] = {"start": "2004-01-02", "end": "2030-12-31"}  # beyond coverage
    validation = client.post("/specs/validate", json={"spec": spec})
    assert validation.status_code == 200, validation.text
    validated = validation.json()
    assert validated["valid"] is True
    assert validated["preflight"]["can_run"] is False

    before_entitlement = client.get("/entitlement").json()
    with db.connect() as conn:
        before_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        before_reservations = conn.execute(
            "SELECT COUNT(*) FROM entitlement_reservations",
        ).fetchone()[0]

    response = client.post("/runs", json={
        "spec": spec,
        "confirmed": True,
        "restatement_seen": True,
        "confirmed_spec_hash": validated["spec_hash"],
        "confirmed_battery_profile_hash": validated["battery_profile"]["profile_hash"],
        "confirmed_preflight_hash": validated["preflight"]["preflight_hash"],
        "acknowledged_preflight_warning_ids": validated["preflight"][
            "required_acknowledgement_ids"
        ],
    })
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "PREFLIGHT_BLOCKED"
    assert client.get("/entitlement").json() == before_entitlement
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == before_runs
        assert conn.execute(
            "SELECT COUNT(*) FROM entitlement_reservations",
        ).fetchone()[0] == before_reservations


def test_quota_decrements_exactly_once_per_sealed_run(client):
    before = client.get("/entitlement").json()["used"]
    spec = default_spec("TLT")
    spec["data"]["range"] = {"start": "2012-01-01", "end": "2018-12-31"}
    _confirm_and_run(client, spec)
    process_next()
    after = client.get("/entitlement").json()["used"]
    assert after == before + 1


def test_synthetic_labels_present_end_to_end(client):
    spec = default_spec("GLD")
    spec["data"]["range"] = {"start": "2012-01-01", "end": "2018-12-31"}
    run_id = _confirm_and_run(client, spec)
    process_next()
    manifest = client.get(f"/runs/{run_id}/manifest").json()
    assert manifest["data_label"] == "SYNTHETIC"
    assert manifest["snapshot_id"].startswith("syn-")
    html = client.get(f"/runs/{run_id}/report").text
    assert "SYNTHETIC DATA" in html
    assert "NOT market data" in html
    assert "illustrative" in html
