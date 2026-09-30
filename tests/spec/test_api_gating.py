"""API-level gating: AT-1.2 (drafts never show performance), AT-1.4 (compute impossible
without confirmation; parsing-correction instrumented), AT-1.5 (the user-edited spec is
exactly what gets queued), deflection logging (AT-2.4)."""

import pytest
from fastapi.testclient import TestClient

from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec

from conftest import validated_run_payload


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QL_VAR_DIR", str(tmp_path / "var"))
    with TestClient(app) as c:
        yield c


def test_validate_never_returns_performance(client):
    r = client.post("/specs/validate", json={"spec": default_spec()})
    body = r.json()
    assert body["valid"]
    assert body["performance"] is None
    assert "has not been run" in body["not_run_notice"]
    assert "restatement" in body


def _run_payload(client, spec):
    """Confirm the way the UI does: validate -> take the server's spec hash -> submit."""
    return validated_run_payload(client, spec)


def test_run_without_confirmation_is_impossible(client):
    payload = _run_payload(client, default_spec())
    r = client.post("/runs", json={**payload, "confirmed": False})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "CONFIRMATION_REQUIRED"


def test_run_without_seeing_restatement_is_impossible(client):
    payload = _run_payload(client, default_spec())
    r = client.post("/runs", json={**payload, "restatement_seen": False})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "CONFIRMATION_REQUIRED"


def test_stale_confirmation_cannot_authorize_changed_spec(client):
    spec = default_spec()
    payload = _run_payload(client, spec)
    spec["costs"]["slippage_bps"] = 50  # edited after the restatement was confirmed
    r = client.post("/runs", json={**payload, "spec": spec})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "CONFIRMATION_STALE"


def test_missing_spec_hash_rejected(client):
    r = client.post("/runs", json={"spec": default_spec(), "confirmed": True,
                                   "restatement_seen": True})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "CONFIRMATION_STALE"


def test_invalid_spec_cannot_be_queued_even_if_confirmed(client):
    spec = default_spec()
    spec["universe"]["symbol"] = "ZZZ"
    from quantlens_schema import spec_hash
    r = client.post("/runs", json={"spec": spec, "confirmed": True,
                                   "restatement_seen": True,
                                   "confirmed_spec_hash": spec_hash(spec)})
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "SPEC_INVALID"


def test_user_edited_spec_is_queued_verbatim(client):
    spec = default_spec("SPY")
    spec["rule"]["ma_days"] = 150  # user edit wins over any draft (AT-1.5)
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = [100, 150, 200, 250]
    spec["costs"]["slippage_bps"] = 10
    r = client.post("/runs", json=_run_payload(client, spec))
    assert r.status_code == 201
    run_id = r.json()["run_id"]
    stored = client.get(f"/runs/{run_id}").json()
    assert stored["spec"] == spec
    assert stored["status"] == "queued"


def test_parsing_correction_event_instrumented(client):
    r = client.post("/events", json={
        "type": "parsing_correction",
        "payload": {"field": "rule.ma_days", "from": 200, "to": 150}})
    assert r.status_code == 201
    events = db.list_events("parsing_correction")
    assert len(events) == 1
    assert events[0]["payload"]["field"] == "rule.ma_days"


def test_deflections_logged_by_category_without_hypothesis_text(client):
    client.post("/parse", json={"hypothesis": "what should I buy right now?"})
    events = db.list_events("deflection")
    assert len(events) == 1
    assert events[0]["payload"]["category"] == "advice_seeking"
    assert "hypothesis" not in events[0]["payload"]  # text stays out of logs (02 §10)


def test_report_endpoint_refuses_before_run_completes(client):
    r = client.post("/runs", json=_run_payload(client, default_spec()))
    run_id = r.json()["run_id"]
    rep = client.get(f"/runs/{run_id}/report")
    assert rep.status_code == 409
    assert rep.json()["code"] == "REPORT_NOT_READY"


def test_entitlement_is_labeled_mock(client):
    ent = client.get("/entitlement").json()
    assert ent["mock"] is True
    assert ent["remaining"] == ent["quota"] - ent["used"] > 0
    assert ent["label"] == (
        "Local preview allowance — tenant-owned, non-production Gate 5 workspace"
    )


def test_artifact_endpoints_reject_unknown_or_crafted_run_ids(client):
    for run_id in ["nonexistent", "..", "..%2F..%2Fsecrets", "../../etc/passwd"]:
        for suffix in ("manifest", "artifacts", "report", "explanation"):
            r = client.get(f"/runs/{run_id}/{suffix}")
            assert r.status_code == 404, (run_id, suffix, r.status_code)
