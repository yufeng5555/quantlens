"""Gate 5A API ownership boundaries.

Identity is injected only through FastAPI dependency overrides, exactly as a verified
provider adapter would supply it.  No test header, query string, or body can choose the
tenant/user scope.
"""

from __future__ import annotations

import copy

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pandas as pd
import pytest

from quantlens_api import db
from quantlens_api import app as api_module
from quantlens_api.app import app
from quantlens_api.auth import Principal, require_principal
from quantlens_schema import default_spec, spec_hash


PRINCIPAL_A = Principal(
    tenant_id="tenant_alpha",
    user_id="user_alpha",
    roles=frozenset({"owner"}),
    auth_mode="test-provider",
    display_label="Alpha owner",
    authenticated=True,
    security_boundary=True,
)
PRINCIPAL_B = Principal(
    tenant_id="tenant_alpha",
    user_id="user_beta",
    roles=frozenset({"analyst"}),
    auth_mode="test-provider",
    display_label="Alpha second user",
    authenticated=True,
    security_boundary=True,
)
PRINCIPAL_C = Principal(
    tenant_id="tenant_charlie",
    user_id="user_charlie",
    roles=frozenset({"owner"}),
    auth_mode="test-provider",
    display_label="Charlie owner",
    authenticated=True,
    security_boundary=True,
)
UNPROVISIONED_PRINCIPAL = Principal(
    tenant_id="tenant_unprovisioned",
    user_id="user_unprovisioned",
    roles=frozenset({"owner"}),
    auth_mode="test-provider",
    display_label="Unprovisioned owner",
    authenticated=True,
    security_boundary=True,
)


PUBLIC_ROUTES = {
    ("GET", "/health"),
    ("GET", "/dataset-imports/config"),
    ("GET", "/universe"),
    ("GET", "/templates"),
}
# The sign-in front door. These take no principal on purpose — a session cannot
# be required in order to create one — so they are neither public metadata nor
# principal-protected. Every entry is a credential endpoint and must be reviewed
# as one; keeping the set closed and separate is what stops an ordinary
# unprotected route from being added here unnoticed. Their own security laws
# (single use, expiry, no enumeration, digests at rest) live in
# tests/spec/test_magic_link_security_v1.py.
UNAUTHENTICATED_AUTH_ROUTES = {
    ("POST", "/auth/email"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/signout"),
    ("GET", "/auth/google/start"),
    ("GET", "/auth/google/callback"),
}
PROTECTED_ROUTES = {
    ("GET", "/session"),
    ("POST", "/auth/report-role"),
    ("GET", "/market-data/config"),
    ("POST", "/market-data/instruments/resolve"),
    ("POST", "/market-data/acquisitions"),
    ("GET", "/market-data/acquisitions/{acquisition_id}"),
    ("POST", "/dataset-imports"),
    # Lists only the caller's own quarantined uploads, and discards one of them.
    # Both are behind the boundary for the same reason the upload itself is.
    ("GET", "/dataset-imports"),
    ("DELETE", "/dataset-imports/{import_id}"),
    ("GET", "/dataset-imports/{import_id}"),
    ("POST", "/dataset-imports/{import_id}/validate"),
    ("POST", "/dataset-imports/{import_id}/seal"),
    ("GET", "/datasets"),
    # Seeds the CC BY market bundle into the caller's own workspace, so it writes
    # under the caller's principal and belongs behind the boundary like any import.
    ("POST", "/datasets/bundle"),
    ("GET", "/datasets/{dataset_id}"),
    ("POST", "/parse"),
    ("POST", "/specs/validate"),
    ("POST", "/runs"),
    ("GET", "/runs"),
    ("GET", "/runs/{run_id}"),
    ("DELETE", "/runs/{run_id}"),
    ("POST", "/runs/{run_id}/archive"),
    ("POST", "/runs/{run_id}/restore"),
    ("GET", "/runs/{run_id}/report"),
    ("GET", "/runs/{run_id}/evidence"),
    ("GET", "/runs/{run_id}/explanation"),
    ("GET", "/runs/{run_id}/research-copilot"),
    ("GET", "/runs/{run_id}/manifest"),
    ("GET", "/runs/{run_id}/artifacts"),
    ("GET", "/entitlement"),
    ("POST", "/events"),
    # Gate 7A.1 experiment lineage + private annotations (all principal-scoped).
    ("GET", "/experiments"),
    ("GET", "/experiments/{family_id}"),
    ("PATCH", "/experiments/{family_id}"),
    ("GET", "/runs/{run_id}/workspace-metadata"),
    ("PUT", "/runs/{run_id}/annotations"),
}

NOT_AVAILABLE = {
    "detail": {
        "code": "ITEM_NOT_AVAILABLE",
        "message": "This item isn't available in this workspace.",
    }
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QL_VAR_DIR", str(tmp_path / "var"))
    with TestClient(app) as test_client:
        # Entitlements are tenant-owned.  Provisioning the second Alpha user with the
        # same quota leaves one shared tenant allowance, while Charlie is independent.
        db.provision_local_principal(
            PRINCIPAL_A.tenant_id, PRINCIPAL_A.user_id, quota=6)
        db.provision_local_principal(
            PRINCIPAL_B.tenant_id, PRINCIPAL_B.user_id, quota=6)
        db.provision_local_principal(
            PRINCIPAL_C.tenant_id, PRINCIPAL_C.user_id, quota=2)
        yield test_client


def _request_as(client: TestClient, principal: Principal, method: str, path: str,
                **kwargs):
    """Issue one request under a server-resolved principal, never a request header."""
    previous = app.dependency_overrides.get(require_principal)

    def resolved_principal() -> Principal:
        return principal

    app.dependency_overrides[require_principal] = resolved_principal
    try:
        return client.request(method, path, **kwargs)
    finally:
        if previous is None:
            app.dependency_overrides.pop(require_principal, None)
        else:
            app.dependency_overrides[require_principal] = previous


def _request_without_override(client: TestClient, method: str, path: str, **kwargs):
    previous = app.dependency_overrides.pop(require_principal, None)
    try:
        return client.request(method, path, **kwargs)
    finally:
        if previous is not None:
            app.dependency_overrides[require_principal] = previous


def _create_run(client: TestClient, principal: Principal) -> str:
    spec = default_spec()
    validated = _request_as(
        client, principal, "POST", "/specs/validate", json={"spec": spec})
    assert validated.status_code == 200, validated.text
    accepted = _request_as(client, principal, "POST", "/runs", json={
        "spec": spec,
        "confirmed": True,
        "restatement_seen": True,
        "confirmed_spec_hash": validated.json()["spec_hash"],
        "confirmed_battery_profile_hash": validated.json()["battery_profile"][
            "profile_hash"],
        "confirmed_preflight_hash": validated.json()["preflight"][
            "preflight_hash"],
        "acknowledged_preflight_warning_ids": validated.json()["preflight"][
            "required_acknowledgement_ids"],
    })
    assert accepted.status_code == 201, accepted.text
    return accepted.json()["run_id"]


def _csv() -> bytes:
    """Small realistic daily-bar file with enough history for a 20-day strategy."""
    dates = pd.bdate_range("2020-01-02", periods=620)
    close = pd.Series([100.0 + index * 0.04 for index in range(len(dates))])
    frame = pd.DataFrame({
        "Date": dates.strftime("%Y-%m-%d"),
        "Open": close - 0.02,
        "High": close + 0.12,
        "Low": close - 0.12,
        "Close": close,
        "Volume": 1_000_000,
    })
    return frame.to_csv(index=False, lineterminator="\n").encode()


def _validation_body(inspection: dict) -> dict:
    return {
        "symbol": "ACME",
        "mapping": inspection["suggested_mapping"],
        "timezone": "America/New_York",
        "prices_adjusted": True,
        "rights_attested": True,
    }


def _dsl_11_spec(dataset: dict) -> dict:
    spec = default_spec("SPY")
    spec["dsl_version"] = "1.1"
    spec["universe"]["symbol"] = dataset["symbol"]
    spec["meta"]["name"] = "Principal-owned private trend audit"
    spec["rule"]["ma_days"] = 20
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = [10, 20, 30]
    spec["data"] = {
        "snapshot_policy": "pinned",
        "source": {
            "kind": "user_provided",
            "dataset_id": dataset["dataset_id"],
            "dataset_manifest_sha256": dataset["dataset_manifest_sha256"],
        },
        "range": dataset["coverage"],
    }
    return spec


def test_route_inventory_has_only_four_public_business_routes(client, monkeypatch):
    business_routes = [
        route for route in app.routes if isinstance(route, APIRoute)
    ]
    inventory = {
        (method, route.path)
        for route in business_routes
        for method in route.methods
    }
    assert inventory == PUBLIC_ROUTES | UNAUTHENTICATED_AUTH_ROUTES | PROTECTED_ROUTES

    for route in business_routes:
        classified = {(method, route.path) for method in route.methods}
        has_principal = any(
            dependency.call is require_principal
            for dependency in route.dependant.dependencies
        )
        if classified <= PUBLIC_ROUTES or classified <= UNAUTHENTICATED_AUTH_ROUTES:
            assert not has_principal, route.path
        else:
            assert classified <= PROTECTED_ROUTES, route.path
            assert has_principal, route.path

    # A sign-in route mints or clears a bearer credential, so its response must
    # never be cacheable even though it takes no principal.
    for _, path in sorted(UNAUTHENTICATED_AUTH_ROUTES):
        assert api_module._is_private_path(path), path

    # Public metadata remains available even when no external provider is configured.
    # This exercises route behavior rather than relying only on dependency introspection.
    monkeypatch.setenv("QL_AUTH_MODE", "external")
    for method, path in sorted(PUBLIC_ROUTES):
        response = _request_without_override(client, method, path)
        assert response.status_code == 200, (path, response.text)
        assert response.headers.get("cache-control") != "private, no-store"


def test_every_private_route_marks_success_and_error_responses_noncacheable(client):
    missing_import = "imp_" + "0" * 32
    missing_acquisition = "acq_" + "0" * 32
    missing_dataset = "ds_" + "0" * 32
    missing_run = "run_" + "0" * 32
    missing_family = "family_" + "0" * 32
    mapping = {field: field.title() for field in ("date", "open", "high", "low", "close")}
    validate_body = {
        "symbol": "ACME", "mapping": mapping, "timezone": "America/New_York",
        "prices_adjusted": True, "rights_attested": True,
    }
    probes = [
        ("GET", "/session", {}),
        ("POST", "/market-data/instruments/resolve", {"json": {"symbol": "QQQ"}}),
        ("POST", "/market-data/acquisitions", {
            "headers": {"Idempotency-Key": "private-route-probe"},
            "json": {
                "symbol": "QQQ", "start": "2024-01-02", "end": "2024-02-02",
                "adjustment_mode": "splits",
                "confirmed_instrument_id": "US:XNAS:QQQ",
                "display_name": "Private route probe", "confirmed": True,
            },
        }),
        ("GET", f"/market-data/acquisitions/{missing_acquisition}", {}),
        ("POST", "/dataset-imports", {
            "content": b"Date,Open,High,Low,Close\n2020-01-02,1,1,1,1\n",
            "headers": {"content-type": "text/csv"},
        }),
        ("GET", "/dataset-imports", {}),
        ("DELETE", f"/dataset-imports/{missing_import}", {}),
        ("GET", f"/dataset-imports/{missing_import}", {}),
        ("POST", f"/dataset-imports/{missing_import}/validate", {"json": validate_body}),
        ("POST", f"/dataset-imports/{missing_import}/seal", {"json": {
            **validate_body, "display_name": "Missing",
            "confirmed_profile_hash": "sha256:" + "0" * 64,
            "acknowledged_warnings": [],
        }}),
        ("GET", "/datasets", {}),
        # Returns the caller's own sealed library, so it must be no-store like any
        # other workspace read.
        ("POST", "/datasets/bundle", {}),
        ("GET", f"/datasets/{missing_dataset}", {}),
        ("POST", "/parse", {"json": {"hypothesis": "Test a trend rule"}}),
        ("POST", "/specs/validate", {"json": {"spec": default_spec()}}),
        ("POST", "/runs", {"json": {"spec": default_spec()}}),
        ("GET", "/runs", {}),
        ("GET", "/experiments", {}),
        ("GET", f"/experiments/{missing_family}", {}),
        ("PATCH", f"/experiments/{missing_family}", {"json": {
            "title": "Private route probe", "expected_revision": 1,
        }}),
        ("GET", f"/runs/{missing_run}", {}),
        ("GET", f"/runs/{missing_run}/workspace-metadata", {}),
        ("PUT", f"/runs/{missing_run}/annotations", {"json": {
            "note": "", "tags": [], "expected_revision": 0,
        }}),
        ("DELETE", f"/runs/{missing_run}", {}),
        ("POST", f"/runs/{missing_run}/archive", {}),
        ("POST", f"/runs/{missing_run}/restore", {}),
        ("GET", f"/runs/{missing_run}/report", {}),
        ("GET", f"/runs/{missing_run}/evidence", {}),
        ("GET", f"/runs/{missing_run}/explanation", {}),
        ("GET", f"/runs/{missing_run}/research-copilot", {}),
        ("GET", f"/runs/{missing_run}/manifest", {}),
        ("GET", f"/runs/{missing_run}/artifacts", {}),
        ("GET", "/entitlement", {}),
        ("POST", "/events", {"json": {"type": "notify_me", "payload": {}}}),
    ]
    for method, path, kwargs in probes:
        response = _request_as(client, PRINCIPAL_A, method, path, **kwargs)
        assert response.headers.get("cache-control") == "private, no-store", path
        assert response.headers.get("pragma") == "no-cache", path
        vary = {part.strip() for part in response.headers.get("vary", "").split(",")}
        assert {"Authorization", "Cookie"} <= vary, path


def test_private_vary_preserves_cors_origin_and_sanitizes_unhandled_failures(
    client, monkeypatch,
):
    origin = "http://localhost:3000"

    healthy = _request_as(
        client, PRINCIPAL_A, "GET", "/session", headers={"Origin": origin})
    assert healthy.status_code == 200
    assert healthy.headers["access-control-allow-origin"] == origin
    healthy_vary = {part.strip() for part in healthy.headers["vary"].split(",")}
    assert {"Origin", "Authorization", "Cookie"} <= healthy_vary

    def fail_without_leaking(*_args, **_kwargs):
        raise RuntimeError("secret sqlite path /private/tenant_alpha.db")

    monkeypatch.setattr(db, "record_event", fail_without_leaking)
    failed = _request_as(
        client, PRINCIPAL_A, "POST", "/events",
        json={"type": "notify_me", "payload": {}},
        headers={"Origin": origin},
    )
    assert failed.status_code == 500
    assert failed.json() == {"detail": {
        "code": "INTERNAL_ERROR",
        "message": "An unexpected error occurred.",
    }}
    assert "secret" not in failed.text
    assert "tenant_alpha" not in failed.text
    assert failed.headers["cache-control"] == "private, no-store"
    assert failed.headers["pragma"] == "no-cache"
    assert failed.headers["cross-origin-resource-policy"] == "same-origin"
    assert failed.headers["x-content-type-options"] == "nosniff"
    assert failed.headers["access-control-allow-origin"] == origin
    failed_vary = {part.strip() for part in failed.headers["vary"].split(",")}
    assert {"Origin", "Authorization", "Cookie"} <= failed_vary


def test_public_unhandled_failure_uses_same_sanitized_500_contract(client, monkeypatch):
    def fail_without_leaking():
        raise RuntimeError("secret filesystem path /private/universe.json")

    monkeypatch.setattr(api_module, "load_universe", fail_without_leaking)
    response = client.get("/universe")
    assert response.status_code == 500
    assert response.json() == {"detail": {
        "code": "INTERNAL_ERROR",
        "message": "An unexpected error occurred.",
    }}
    assert "secret" not in response.text
    assert "private/universe" not in response.text
    assert response.headers.get("cache-control") != "private, no-store"


def test_unprovisioned_import_is_rejected_before_raw_quarantine_write(client):
    assert db.tenant_is_provisioned(UNPROVISIONED_PRINCIPAL.tenant_id) is False
    quarantine = db.var_dir() / "data-imports" / "quarantine"
    before = set(quarantine.glob("*.bin")) if quarantine.exists() else set()

    response = _request_as(
        client, UNPROVISIONED_PRINCIPAL, "POST", "/dataset-imports",
        content=_csv(), headers={"content-type": "text/csv"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": {
        "code": "WORKSPACE_NOT_PROVISIONED",
        "message": "This workspace is not provisioned for private data imports.",
    }}
    after = set(quarantine.glob("*.bin")) if quarantine.exists() else set()
    assert after == before


def test_import_persistence_failure_removes_new_quarantine_file(
    client, monkeypatch,
):
    quarantine = db.var_dir() / "data-imports" / "quarantine"
    before = set(quarantine.glob("*.bin")) if quarantine.exists() else set()

    def fail_persistence(*_args, **_kwargs):
        raise RuntimeError("database receipt failure with private details")

    monkeypatch.setattr(db, "create_dataset_import", fail_persistence)
    response = _request_as(
        client, PRINCIPAL_A, "POST", "/dataset-imports",
        content=_csv(), headers={"content-type": "text/csv"},
    )

    assert response.status_code == 500
    assert response.json()["detail"]["code"] == "INTERNAL_ERROR"
    assert "private details" not in response.text
    after = set(quarantine.glob("*.bin")) if quarantine.exists() else set()
    assert after == before


def test_event_payload_cannot_spoof_identity_and_events_remain_user_isolated(client):
    payload_a = {
        "field": "rule.ma_days",
        "tenant_id": PRINCIPAL_C.tenant_id,
        "Tenant_ID": "forged-case-variant",
        "tenantId": "forged-camel-variant",
        "user_id": PRINCIPAL_B.user_id,
        "nested": {
            "actor_id": PRINCIPAL_C.tenant_id,
            "ACTOR_ID": "forged-uppercase-variant",
            "actor-id": "forged-separator-variant",
            "safe": "alpha",
            "items": [
                {
                    "tenant_id": "forged",
                    "userId": "forged-camel-variant",
                    "USER-ID": "forged-separator-variant",
                    "value": 1,
                },
            ],
        },
    }
    payload_b = {
        "field": "cost_bps",
        "actor_id": PRINCIPAL_C.tenant_id,
        "ActorId": "forged-camel-variant",
        "nested": {
            "user_id": PRINCIPAL_A.user_id,
            "User_ID": "forged-case-variant",
            "safe": "beta",
        },
    }
    alpha = _request_as(
        client, PRINCIPAL_A, "POST", "/events",
        json={"type": "parsing_correction", "payload": payload_a})
    beta = _request_as(
        client, PRINCIPAL_B, "POST", "/events",
        json={"type": "parsing_correction", "payload": payload_b})
    assert alpha.status_code == beta.status_code == 201

    alpha_events = db.list_events_for_principal(
        PRINCIPAL_A.tenant_id, PRINCIPAL_A.user_id, "parsing_correction")
    beta_events = db.list_events_for_principal(
        PRINCIPAL_B.tenant_id, PRINCIPAL_B.user_id, "parsing_correction")
    assert len(alpha_events) == len(beta_events) == 1
    assert alpha_events[0]["actor_id"] == PRINCIPAL_A.tenant_id
    assert alpha_events[0]["user_id"] == PRINCIPAL_A.user_id
    assert beta_events[0]["actor_id"] == PRINCIPAL_B.tenant_id
    assert beta_events[0]["user_id"] == PRINCIPAL_B.user_id
    assert alpha_events[0]["payload"] == {
        "field": "rule.ma_days",
        "nested": {"safe": "alpha", "items": [{"value": 1}]},
    }
    assert beta_events[0]["payload"] == {
        "field": "cost_bps", "nested": {"safe": "beta"},
    }


@pytest.mark.parametrize("foreign_principal", [PRINCIPAL_B, PRINCIPAL_C])
def test_foreign_run_id_is_indistinguishable_from_random_before_readiness_checks(
    client, monkeypatch, foreign_principal,
):
    run_id = _create_run(client, PRINCIPAL_A)
    random_id = "not-a-real-run-id"

    owner_status = _request_as(client, PRINCIPAL_A, "GET", f"/runs/{run_id}")
    assert owner_status.status_code == 200
    assert owner_status.json()["status"] == "queued"
    owner_report = _request_as(client, PRINCIPAL_A, "GET", f"/runs/{run_id}/report")
    assert owner_report.status_code == 409
    assert owner_report.json()["code"] == "REPORT_NOT_READY"

    def readiness_must_not_run(_run_id: str) -> bool:
        raise AssertionError("foreign object authorization must precede filesystem readiness")

    explanation_calls = []

    class ExplanationMustNotRun:
        @classmethod
        def from_environment(cls):
            explanation_calls.append("constructed")
            raise AssertionError("foreign object authorization must precede explanation")

    class ResearchCopilotMustNotRun:
        @classmethod
        def from_environment(cls):
            explanation_calls.append("research-copilot-constructed")
            raise AssertionError(
                "foreign object authorization must precede research copilot")

    monkeypatch.setattr(api_module, "_checkpoint_exists", readiness_must_not_run)
    monkeypatch.setattr(api_module, "ExplanationService", ExplanationMustNotRun)
    monkeypatch.setattr(
        api_module, "DevelopmentResearchCopilot", ResearchCopilotMustNotRun)
    for suffix in (
        "", "/report", "/evidence", "/explanation", "/research-copilot",
        "/manifest", "/artifacts", "/workspace-metadata",
    ):
        exact = _request_as(
            client, foreign_principal, "GET", f"/runs/{run_id}{suffix}")
        missing = _request_as(
            client, foreign_principal, "GET", f"/runs/{random_id}{suffix}")
        assert exact.status_code == missing.status_code == 404, suffix
        assert exact.json() == missing.json() == NOT_AVAILABLE, suffix
    assert explanation_calls == []


def test_entitlement_is_tenant_scoped_while_runs_remain_user_scoped(client):
    run_id = _create_run(client, PRINCIPAL_A)

    alpha_a = _request_as(client, PRINCIPAL_A, "GET", "/entitlement")
    alpha_b = _request_as(client, PRINCIPAL_B, "GET", "/entitlement")
    charlie = _request_as(client, PRINCIPAL_C, "GET", "/entitlement")
    assert alpha_a.status_code == alpha_b.status_code == charlie.status_code == 200
    assert alpha_a.json() == alpha_b.json()
    assert alpha_a.json()["quota"] == 6
    assert alpha_a.json()["reserved"] == 1
    assert alpha_a.json()["remaining"] == 5
    assert charlie.json()["quota"] == 2
    assert charlie.json()["reserved"] == 0
    assert charlie.json()["remaining"] == 2
    for body in (alpha_a.json(), alpha_b.json(), charlie.json()):
        assert "actor_id" not in body
        assert "tenant_id" not in body
        assert "user_id" not in body

    # Sharing the tenant entitlement does not grant access to another user's run.
    denied = _request_as(client, PRINCIPAL_B, "GET", f"/runs/{run_id}")
    assert denied.status_code == 404
    assert denied.json() == NOT_AVAILABLE


def test_run_workspace_is_newest_first_and_scoped_to_exact_principal(client):
    alpha_first = _create_run(client, PRINCIPAL_A)
    alpha_second = _create_run(client, PRINCIPAL_A)
    beta = _create_run(client, PRINCIPAL_B)
    charlie = _create_run(client, PRINCIPAL_C)

    response = _request_as(client, PRINCIPAL_A, "GET", "/runs")
    assert response.status_code == 200, response.text
    runs = response.json()["runs"]
    assert [item["run_id"] for item in runs] == [alpha_second, alpha_first]
    assert set(runs[0]) == {
        "run_id", "title", "status", "created_at", "updated_at",
        "battery_status", "evidence_available", "symbol", "data_source",
        "battery_profile", "evidence_view_version", "failed_checks",
        "artifact_contract_id", "verified_financial_semantics",
        "research_mode", "management_state", "archived_at", "deleted_at",
        # Gate 7A.1 additive workspace metadata (never note bodies).
        "family_id", "family_title", "relationship", "tags", "has_note",
        "annotation_revision",
    }
    assert runs[0]["title"] == "SPY trend filter"
    assert runs[0]["status"] == "queued"
    assert runs[0]["battery_status"] == "NOT RUN"
    assert runs[0]["battery_profile"] == "battery-v1"
    assert runs[0]["evidence_view_version"] is None
    assert runs[0]["evidence_available"] is False
    assert runs[0]["artifact_contract_id"] is None
    assert runs[0]["verified_financial_semantics"] is False
    assert "actor_id" not in response.text
    assert "user_id" not in response.text
    assert beta not in response.text
    assert charlie not in response.text

    limited = _request_as(client, PRINCIPAL_A, "GET", "/runs?limit=1")
    assert limited.status_code == 200
    assert [item["run_id"] for item in limited.json()["runs"]] == [alpha_second]

    # Browser-controlled headers and extra query parameters never select ownership.
    spoofed = _request_as(
        client, PRINCIPAL_A, "GET",
        f"/runs?limit=10&tenant_id={PRINCIPAL_C.tenant_id}&user_id={PRINCIPAL_B.user_id}",
        headers={
            "X-Tenant-Id": PRINCIPAL_C.tenant_id,
            "X-User-Id": PRINCIPAL_B.user_id,
        },
    )
    assert [item["run_id"] for item in spoofed.json()["runs"]] == [
        alpha_second, alpha_first,
    ]

    assert _request_as(client, PRINCIPAL_A, "GET", "/runs?limit=0").status_code == 422
    assert _request_as(client, PRINCIPAL_A, "GET", "/runs?limit=51").status_code == 422


def test_run_workspace_reports_battery_only_from_verified_sealed_evidence(
    client, monkeypatch,
):
    run_id = _create_run(client, PRINCIPAL_A)
    db.settle_reservation(run_id)
    db.set_status(run_id, "published")
    monkeypatch.setattr(api_module, "_checkpoint_exists", lambda _run_id: True)
    monkeypatch.setattr(api_module, "legacy_checkpoint_issue", lambda _run: None)
    monkeypatch.setattr(
        api_module,
        "load_verified_evidence",
        lambda *_args, **_kwargs: {
            "evidence_view_version": "v1",
            "status": {"battery_status": "PASS"},
        },
    )

    verified = _request_as(client, PRINCIPAL_A, "GET", "/runs").json()["runs"]
    assert verified == [{
        "run_id": run_id,
        "research_mode": "formal",
        "management_state": "active",
        "archived_at": None,
        "deleted_at": None,
        "title": "SPY trend filter",
        "symbol": "SPY",
        "data_source": "sample",
        "status": "published",
        "created_at": verified[0]["created_at"],
        "updated_at": verified[0]["updated_at"],
        "battery_status": "PASS",
        "battery_profile": "battery-v1",
        "evidence_view_version": "v1",
        "evidence_available": True,
        "artifact_contract_id": None,
        "verified_financial_semantics": False,
        "failed_checks": 0,
        # Gate 7A.1 additive workspace metadata defaults (no lineage row).
        "family_id": None,
        "family_title": None,
        "relationship": None,
        "tags": [],
        "has_note": False,
        "annotation_revision": 0,
    }]

    def refuse_tampered(*_args, **_kwargs):
        raise api_module.ArtifactIntegrityError("private artifact path and hash mismatch")

    monkeypatch.setattr(api_module, "load_verified_evidence", refuse_tampered)
    refused_response = _request_as(client, PRINCIPAL_A, "GET", "/runs")
    assert refused_response.status_code == 200
    refused = refused_response.json()["runs"][0]
    assert refused["battery_status"] == "NOT RUN"
    assert refused["evidence_available"] is False
    assert "private artifact" not in refused_response.text


@pytest.mark.parametrize("foreign_principal", [PRINCIPAL_B, PRINCIPAL_C])
def test_import_dataset_and_dsl_binding_cannot_cross_principal_scope(
    client, foreign_principal,
):
    inspected_response = _request_as(
        client, PRINCIPAL_A, "POST", "/dataset-imports",
        content=_csv(), headers={"content-type": "text/csv"},
    )
    assert inspected_response.status_code == 201, inspected_response.text
    inspection = inspected_response.json()
    import_id = inspection["import_id"]
    random_import_id = "imp_" + "f" * 32
    validation_body = _validation_body(inspection)
    seal_stub = {
        **validation_body,
        "display_name": "Foreign attempt",
        "confirmed_profile_hash": "sha256:" + "0" * 64,
        "acknowledged_warnings": [],
    }

    for method, suffix, kwargs in (
        ("GET", "", {}),
        ("POST", "/validate", {"json": validation_body}),
        ("POST", "/seal", {"json": seal_stub}),
        # The one route here that destroys bytes. It must be exactly as blind to
        # a foreign import as every read beside it, and must not distinguish a
        # real foreign id from an invented one.
        ("DELETE", "", {}),
    ):
        exact = _request_as(
            client, foreign_principal, method,
            f"/dataset-imports/{import_id}{suffix}", **kwargs)
        missing = _request_as(
            client, foreign_principal, method,
            f"/dataset-imports/{random_import_id}{suffix}", **kwargs)
        assert exact.status_code == missing.status_code == 404, (method, suffix)
        assert exact.json() == missing.json() == NOT_AVAILABLE, (method, suffix)

    # The refused discard must not have settled or unlinked anything.
    still_open = _request_as(
        client, PRINCIPAL_A, "GET", f"/dataset-imports/{import_id}")
    assert still_open.status_code == 200, still_open.text
    assert still_open.json()["status"] == "inspected"

    # The listing is likewise scoped: a foreign workspace sees none of these.
    foreign_listing = _request_as(client, foreign_principal, "GET", "/dataset-imports")
    assert foreign_listing.status_code == 200, foreign_listing.text
    assert foreign_listing.json()["imports"] == []
    owner_listing = _request_as(client, PRINCIPAL_A, "GET", "/dataset-imports")
    assert [item["import_id"] for item in owner_listing.json()["imports"]] == [import_id]

    validated_response = _request_as(
        client, PRINCIPAL_A, "POST", f"/dataset-imports/{import_id}/validate",
        json=validation_body,
    )
    assert validated_response.status_code == 200, validated_response.text
    validation = validated_response.json()["validation"]
    sealed_response = _request_as(
        client, PRINCIPAL_A, "POST", f"/dataset-imports/{import_id}/seal", json={
            **validation_body,
            "display_name": "Alpha private daily bars",
            "confirmed_profile_hash": validation["profile_hash"],
            "acknowledged_warnings": validation["quality"]["warnings"],
        },
    )
    assert sealed_response.status_code == 201, sealed_response.text
    dataset = sealed_response.json()["dataset"]

    owner_list = _request_as(client, PRINCIPAL_A, "GET", "/datasets").json()["datasets"]
    foreign_list = _request_as(
        client, foreign_principal, "GET", "/datasets").json()["datasets"]
    assert [item["dataset_id"] for item in owner_list] == [dataset["dataset_id"]]
    assert foreign_list == []

    exact_detail = _request_as(
        client, foreign_principal, "GET", f"/datasets/{dataset['dataset_id']}")
    random_detail = _request_as(
        client, foreign_principal, "GET", "/datasets/not-a-real-dataset")
    assert exact_detail.status_code == random_detail.status_code == 404
    assert exact_detail.json() == random_detail.json() == NOT_AVAILABLE

    private_spec = _dsl_11_spec(dataset)
    owner_validation = _request_as(
        client, PRINCIPAL_A, "POST", "/specs/validate", json={"spec": private_spec})
    assert owner_validation.status_code == 200
    assert owner_validation.json()["valid"] is True, owner_validation.text

    foreign_validation = _request_as(
        client, foreign_principal, "POST", "/specs/validate",
        json={"spec": copy.deepcopy(private_spec)},
    )
    assert foreign_validation.status_code == 200
    assert foreign_validation.json()["valid"] is False
    assert foreign_validation.json()["errors"] == [{
        "layer": "scope",
        "code": "DATASET_NOT_SEALED",
        "message": "The selected user dataset is missing, withdrawn, or not sealed.",
        "suggestion": "Return to Data Workspace and seal the dataset before running.",
    }]

    before = _request_as(client, foreign_principal, "GET", "/entitlement").json()
    rejected_run = _request_as(client, foreign_principal, "POST", "/runs", json={
        "spec": private_spec,
        "confirmed": True,
        "restatement_seen": True,
        "confirmed_spec_hash": spec_hash(private_spec),
    })
    after = _request_as(client, foreign_principal, "GET", "/entitlement").json()
    assert rejected_run.status_code == 422
    assert rejected_run.json()["detail"]["code"] == "SPEC_INVALID"
    assert after == before  # rejected foreign binding reserves no quota
