"""Focused tests for the provider-neutral Gate 5 authentication contract."""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
import pytest

from quantlens_api import db
from quantlens_api.app import app as api_app
from quantlens_api.auth import (
    AuthProvider,
    Principal,
    clear_auth_provider,
    configure_auth_provider,
    require_principal,
    session_public_view,
)


def _request(host: str = "127.0.0.1", headers: dict[str, str] | None = None) -> Request:
    encoded_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/session",
        "raw_path": b"/session",
        "query_string": b"",
        "headers": encoded_headers,
        "client": (host, 41234),
        "server": ("127.0.0.1", 8000),
    })


@pytest.fixture(autouse=True)
def _clean_auth_provider(monkeypatch):
    clear_auth_provider()
    monkeypatch.delenv("QL_AUTH_MODE", raising=False)
    monkeypatch.delenv("QL_LOCAL_TENANT_ID", raising=False)
    monkeypatch.delenv("QL_LOCAL_USER_ID", raising=False)
    monkeypatch.delenv("QL_LOCAL_DISPLAY_LABEL", raising=False)
    yield
    clear_auth_provider()


def test_principal_is_immutable_and_validates_safe_opaque_ids():
    principal = Principal(
        tenant_id="tenant_acme_01",
        user_id="user_123",
        roles=frozenset({"owner", "analyst"}),
        auth_mode="oidc",
        display_label="Research workspace",
        authenticated=True,
        security_boundary=True,
    )
    with pytest.raises(FrozenInstanceError):
        principal.user_id = "user_other"  # type: ignore[misc]

    for unsafe in ("../tenant", "user@example.com", "two words", "a", "tenant."):
        with pytest.raises(ValueError):
            Principal(
                tenant_id=unsafe,
                user_id="user_safe",
                roles=frozenset({"owner"}),
                auth_mode="oidc",
                display_label="Workspace",
                authenticated=True,
                security_boundary=True,
            )


def test_local_preview_returns_one_server_configured_insecure_principal(monkeypatch):
    monkeypatch.setenv("QL_LOCAL_TENANT_ID", "tenant_dev_42")
    monkeypatch.setenv("QL_LOCAL_USER_ID", "user_dev_42")
    monkeypatch.setenv("QL_LOCAL_DISPLAY_LABEL", "My local workspace")

    principal = asyncio.run(require_principal(_request()))

    assert principal.tenant_id == "tenant_dev_42"
    assert principal.user_id == "user_dev_42"
    assert principal.roles == frozenset({"owner"})
    assert principal.auth_mode == "local-preview"
    assert principal.display_label == "My local workspace"
    assert principal.authenticated is False
    assert principal.security_boundary is False


def test_custom_local_principal_is_provisioned_at_app_startup(monkeypatch, var_env):
    monkeypatch.setenv("QL_LOCAL_TENANT_ID", "tenant_custom_local")
    monkeypatch.setenv("QL_LOCAL_USER_ID", "user_custom_local")

    with TestClient(api_app):
        assert db.tenant_is_provisioned("tenant_custom_local") is True
        entitlement = db.entitlement_status("tenant_custom_local")
        assert entitlement["remaining"] > 0


def test_local_preview_ignores_spoofed_identity_and_proxy_headers(monkeypatch):
    monkeypatch.setenv("QL_LOCAL_TENANT_ID", "tenant_server")
    monkeypatch.setenv("QL_LOCAL_USER_ID", "user_server")
    request = _request(headers={
        "X-User": "user_attacker",
        "X-Tenant": "tenant_attacker",
        "X-Forwarded-For": "203.0.113.20",
    })

    principal = asyncio.run(require_principal(request))

    assert principal.tenant_id == "tenant_server"
    assert principal.user_id == "user_server"


def test_local_preview_rejects_non_loopback_client():
    with pytest.raises(HTTPException) as caught:
        asyncio.run(require_principal(_request(host="192.0.2.55")))
    assert caught.value.status_code == 403
    assert caught.value.detail["code"] == "LOCAL_PREVIEW_LOOPBACK_ONLY"


def test_invalid_local_identifier_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("QL_LOCAL_TENANT_ID", "../../other-tenant")
    with pytest.raises(HTTPException) as caught:
        asyncio.run(require_principal(_request()))
    assert caught.value.status_code == 503
    assert caught.value.detail["code"] == "AUTH_LOCAL_CONFIG_INVALID"
    assert "../../other-tenant" not in str(caught.value.detail)


@pytest.mark.parametrize("mode,code", [
    ("external", "AUTH_PROVIDER_NOT_CONFIGURED"),
    ("public", "AUTH_MODE_UNSAFE"),
    ("mystery-provider", "AUTH_PROVIDER_NOT_CONFIGURED"),
])
def test_unconfigured_nonlocal_modes_fail_closed(monkeypatch, mode, code):
    monkeypatch.setenv("QL_AUTH_MODE", mode)
    with pytest.raises(HTTPException) as caught:
        asyncio.run(require_principal(_request()))
    assert caught.value.status_code == 503
    assert caught.value.detail["code"] == code


class _StaticProvider:
    mode = "oidc"

    async def authenticate(self, _request: Request) -> Principal:
        return Principal(
            tenant_id="tenant_verified",
            user_id="user_verified",
            roles=frozenset({"analyst"}),
            auth_mode=self.mode,
            display_label="Verified analyst",
            authenticated=True,
            security_boundary=True,
        )


def test_configured_external_provider_satisfies_protocol_and_dependency(monkeypatch):
    provider: AuthProvider = _StaticProvider()
    configure_auth_provider(provider)
    monkeypatch.setenv("QL_AUTH_MODE", "oidc")

    principal = asyncio.run(require_principal(_request(host="203.0.113.50")))

    assert principal.tenant_id == "tenant_verified"
    assert principal.authenticated is True
    assert principal.security_boundary is True


def test_public_session_view_hides_internal_ids_and_states_local_risk():
    principal = asyncio.run(require_principal(_request()))
    view = session_public_view(principal)

    assert "tenant_id" not in view
    assert "user_id" not in view
    assert view["authenticated"] is False
    assert view["security_boundary"] is False
    assert view["local_preview"] is True
    assert "not authenticated" in view["notice"]


def test_fastapi_dependency_is_trivially_overridable_for_tenant_tests():
    app = FastAPI()

    @app.get("/private")
    async def private_route(principal: Principal = Depends(require_principal)) -> dict:
        return {"tenant_id": principal.tenant_id}

    injected = Principal(
        tenant_id="tenant_test_b",
        user_id="user_test_b",
        roles=frozenset({"owner"}),
        auth_mode="test-provider",
        display_label="Tenant B",
        authenticated=True,
        security_boundary=True,
    )
    app.dependency_overrides[require_principal] = lambda: injected

    with TestClient(app) as client:
        response = client.get("/private")
    assert response.status_code == 200
    assert response.json() == {"tenant_id": "tenant_test_b"}
