"""Gate 3 §5.1 — GET /runs/{run_id}/evidence returns the verified EvidenceViewV1 bound to
the sealed manifest/ledger, and fails closed for unsealed, failed, tampered, or unknown
runs. Acceptance: workspace, printable report, manifest, and ledger expose the same
result_hash; no partial financial values ever leave a non-verified run."""

import json

import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec
from quantlens_worker.evidence import ALLOWED_CHECK_STATUSES, EVIDENCE_VIEW_VERSION
from quantlens_worker.runner import process_next


@pytest.fixture()
def client(var_env):
    with TestClient(app) as c:
        yield c


def _confirm_and_run(client, spec) -> str:
    r = client.post("/runs", json=validated_run_payload(client, spec))
    assert r.status_code == 201, r.json()
    return r.json()["run_id"]


def _published_run(client, symbol="QQQ") -> str:
    spec = default_spec(symbol)
    spec["data"]["range"] = {"start": "2010-01-01", "end": "2020-12-31"}
    run_id = _confirm_and_run(client, spec)
    assert process_next() == "published"
    return run_id


def test_evidence_binds_identity_to_manifest_ledger_and_report(client):
    run_id = _published_run(client)
    view = client.get(f"/runs/{run_id}/evidence").json()
    manifest = client.get(f"/runs/{run_id}/manifest").json()
    ledger = client.get(f"/runs/{run_id}/artifacts").json()
    run = client.get(f"/runs/{run_id}").json()

    assert view["evidence_view_version"] == EVIDENCE_VIEW_VERSION
    identity = view["identity"]
    assert identity["run_id"] == run_id
    assert identity["manifest_id"] == manifest["manifest_id"] == f"mfst-{run_id}"
    assert identity["spec_hash"] == run["spec_hash"] == manifest["spec_hash"]
    assert identity["snapshot_id"] == manifest["snapshot_id"]
    assert identity["snapshot_sha256"] == manifest["snapshot_sha256"]
    assert identity["engine_semver"] == manifest["engine_semver"]
    assert identity["image_digest"] == manifest["image_digest"]
    assert identity["data_label"] == "SYNTHETIC"
    # one result_hash across workspace view, manifest, ledger, and printable report
    assert identity["result_hash"] == manifest["result_hash"] == ledger["result_hash"]
    report_html = client.get(f"/runs/{run_id}/report").text
    assert identity["result_hash"][:24] in report_html
    # every artifact reference matches the sealed ledger index exactly
    by_kind = {e["kind"]: e for e in ledger["entries"]}
    assert {a["kind"] for a in view["artifacts"]} == set(by_kind)
    for ref in view["artifacts"]:
        assert ref["artifact_id"] == by_kind[ref["kind"]]["artifact_id"]
        assert ref["sha256"] == by_kind[ref["kind"]]["sha256"]


def test_evidence_projection_is_complete_and_neutral(client):
    spec = default_spec("SPY")
    spec["data"]["range"] = {"start": "2010-01-01", "end": "2020-12-31"}
    run_id = _confirm_and_run(client, spec)
    assert process_next() == "published"
    view = client.get(f"/runs/{run_id}/evidence").json()

    assert view["assumptions"]["spec"] == spec  # sealed assumptions, verbatim
    assert "restatement" in view["assumptions"]
    # every declared stress multiplier is present
    declared = sorted(spec["validation"]["cost_stress"]["multipliers"])
    assert sorted(r["multiplier"] for r in view["cost_stress"]["rows"]) == declared
    # the full declared sensitivity grid is present — never only a best cell
    assert [c["ma_days"] for c in view["sensitivity"]["grid"]] == \
        sorted(spec["validation"]["sensitivity"]["grid"]["ma_days"])
    # falsification always present with the closed status vocabulary
    findings = view["falsification"]["findings"]
    assert len(findings) == 3
    for f in findings:
        assert f["status"] in ALLOWED_CHECK_STATUSES
    assert view["status"]["battery_status"] in ALLOWED_CHECK_STATUSES
    assert {c["id"] for c in view["status"]["checks"]} == \
        {"oos_decay", "cost_fragility", "parameter_fragility"}
    # both segments carry verified series + metrics; the UI never recomputes them
    for segment in ("is", "oos"):
        result = view["results"][segment]
        assert result["equity_series"]["date"]
        assert result["strategy_metrics"]["total_return"] is not None
    assert view["oos_execution_audit"]["primary_evaluation_count"] == 1


def test_unknown_run_is_404(client):
    assert client.get("/runs/nonexistent/evidence").status_code == 404


def test_unsealed_run_fails_closed_as_not_run(client):
    spec = default_spec("TLT")
    spec["data"]["range"] = {"start": "2010-01-01", "end": "2020-12-31"}
    run_id = _confirm_and_run(client, spec)  # queued; worker never runs
    r = client.get(f"/runs/{run_id}/evidence")
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "EVIDENCE_NOT_AVAILABLE"
    assert body["battery_status"] == "NOT RUN"
    assert "results" not in body and "identity" not in body


def test_failed_run_fails_closed_as_not_run(client):
    spec = default_spec("SPY")
    spec["data"]["range"] = {"start": "2010-01-01", "end": "2020-12-31"}
    run_id = _confirm_and_run(client, spec)
    db.set_status(run_id, "data_quality_failed", {
        "code": "RANGE_OUTSIDE_COVERAGE",
        "message": "The requested range is outside sealed coverage.",
        "quota_charged": False,
    })
    r = client.get(f"/runs/{run_id}/evidence")
    assert r.status_code == 409
    assert r.json()["battery_status"] == "NOT RUN"


def test_tampered_artifact_fails_closed(client):
    run_id = _published_run(client)
    art_dir = db.var_dir() / "artifacts" / run_id
    target = art_dir / "artifact_falsification.json"
    body = json.loads(target.read_bytes())
    body["payload"]["findings"][0]["status"] = "PASS"  # forge a verdict
    target.write_text(json.dumps(body))
    r = client.get(f"/runs/{run_id}/evidence")
    assert r.status_code == 409
    assert r.json()["code"] == "EVIDENCE_INTEGRITY_FAILURE"
    assert "results" not in r.json()


def test_report_fails_closed_on_tamper_and_recovers_on_restore(client):
    """P1-1 — the printable report re-checks the sealed checkpoint on every request:
    tampering any artifact refuses the report (and raw manifest/ledger routes), and
    restoring the original bytes makes the same routes serve again."""
    run_id = _published_run(client)
    target = db.var_dir() / "artifacts" / run_id / "artifact_oos_result.json"
    original = target.read_bytes()

    assert client.get(f"/runs/{run_id}/report").status_code == 200
    target.write_bytes(original.replace(b'"total_return"', b'"total_returm"', 1))
    for route in ("report", "manifest", "artifacts", "evidence"):
        r = client.get(f"/runs/{run_id}/{route}")
        assert r.status_code == 409, route
        body = r.json()
        code = body.get("code") or body.get("detail", {}).get("code")
        assert code in ("REPORT_INTEGRITY_FAILURE", "EVIDENCE_INTEGRITY_FAILURE"), route

    target.write_bytes(original)  # reopen: byte-identical restore verifies again
    assert client.get(f"/runs/{run_id}/report").status_code == 200
    assert client.get(f"/runs/{run_id}/evidence").status_code == 200


def test_tampered_manifest_fails_closed(client):
    run_id = _published_run(client)
    path = db.var_dir() / "artifacts" / run_id / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["result_hash"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(manifest))
    r = client.get(f"/runs/{run_id}/evidence")
    assert r.status_code == 409
    assert r.json()["code"] == "EVIDENCE_INTEGRITY_FAILURE"


def test_report_and_evidence_share_one_projection(client):
    """The printable report's headline numbers must appear verbatim in the evidence view
    (shared projection — values cannot drift between surfaces)."""
    run_id = _published_run(client, symbol="GLD")
    view = client.get(f"/runs/{run_id}/evidence").json()
    html = client.get(f"/runs/{run_id}/report").text
    oos = view["results"]["oos"]["strategy_metrics"]
    assert f"{oos['total_return'] * 100:+.2f}%" in html
    assert f"{oos['sharpe']:.2f}" in html
    assert view["identity"]["snapshot_id"] in html
