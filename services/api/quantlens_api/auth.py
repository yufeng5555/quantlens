"""Provider-neutral identity contract for private QuantLens API routes.

``local-preview`` deliberately preserves the current single-developer workflow, but
it is *not* authentication and it is *not* an account security boundary.  It only
accepts a direct loopback client and never derives identity from request headers.

Production identity is supplied by an :class:`AuthProvider`.  No provider is bundled
here: selecting an external mode without explicitly configuring its provider fails
closed instead of silently becoming an anonymous session.
"""

from __future__ import annotations

from dataclasses import dataclass
import inspect
import ipaddress
import os
import re
import unicodedata
from typing import Awaitable, Protocol, runtime_checkable

from fastapi import HTTPException, Request, status


LOCAL_PREVIEW_MODE = "local-preview"
# Keep the existing local ownership alias so migrated database rows retain their owner
# without rewriting artifact hashes. Artifact readability is a separate, versioned
# compatibility decision: an older checkpoint may still require a rebuild when its
# integrity contract predates the current verifier. This identifier is not a claim that
# an anonymous browser session is authenticated.
DEFAULT_LOCAL_TENANT_ID = "local-anonymous"
DEFAULT_LOCAL_USER_ID = "local-anonymous"
DEFAULT_LOCAL_DISPLAY_LABEL = "Local preview workspace"

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_MODE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_UNSAFE_AUTH_MODES = frozenset({"anonymous", "none", "public"})


def validate_opaque_identifier(value: str, *, field_name: str) -> str:
    """Validate an opaque storage-safe identifier without interpreting its meaning.

    IDs are intentionally limited to a compact ASCII alphabet: no path separators,
    dots, whitespace, email addresses, control characters, or Unicode lookalikes.
    """
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 3-64 ASCII letters, digits, '_' or '-', "
            "beginning with a letter or digit"
        )
    return value


def _validate_display_label(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("display_label must be a string")
    label = value.strip()
    if not 1 <= len(label) <= 80:
        raise ValueError("display_label must contain 1-80 characters")
    if any(unicodedata.category(char).startswith("C") for char in label):
        raise ValueError("display_label must not contain control characters")
    return label


def _validate_auth_mode(value: str) -> str:
    if not isinstance(value, str) or not _MODE_PATTERN.fullmatch(value):
        raise ValueError("auth_mode must be a safe lowercase mode identifier")
    return value


@dataclass(frozen=True, slots=True)
class Principal:
    """Immutable authenticated-or-preview request identity.

    ``authenticated`` and ``security_boundary`` are explicit so a local preview can
    never be mistaken for a signed-in account merely because it has stable IDs.
    """

    tenant_id: str
    user_id: str
    roles: frozenset[str]
    auth_mode: str
    display_label: str
    authenticated: bool
    security_boundary: bool

    def __post_init__(self) -> None:
        validate_opaque_identifier(self.tenant_id, field_name="tenant_id")
        validate_opaque_identifier(self.user_id, field_name="user_id")
        object.__setattr__(self, "auth_mode", _validate_auth_mode(self.auth_mode))
        object.__setattr__(self, "display_label", _validate_display_label(self.display_label))

        try:
            immutable_roles = frozenset(self.roles)
        except TypeError as exc:
            raise ValueError("roles must be an iterable of role identifiers") from exc
        if not immutable_roles:
            raise ValueError("roles must contain at least one role")
        if any(not isinstance(role, str) or not _ROLE_PATTERN.fullmatch(role)
               for role in immutable_roles):
            raise ValueError("roles must be safe lowercase role identifiers")
        object.__setattr__(self, "roles", immutable_roles)

        if not isinstance(self.authenticated, bool):
            raise ValueError("authenticated must be a boolean")
        if not isinstance(self.security_boundary, bool):
            raise ValueError("security_boundary must be a boolean")


@runtime_checkable
class AuthProvider(Protocol):
    """Adapter contract for a real identity provider.

    The adapter performs credential verification and returns a fully validated
    principal.  It should raise ``HTTPException(401)`` for absent/invalid credentials.
    """

    mode: str

    def authenticate(self, request: Request) -> Principal | Awaitable[Principal]:
        """Verify the request and return its principal."""
        ...


class LocalPreviewAuthProvider:
    """Single, server-configured, explicitly unauthenticated local identity."""

    mode = LOCAL_PREVIEW_MODE

    @staticmethod
    def _is_direct_loopback(request: Request) -> bool:
        client = request.client
        if client is None or not client.host:
            return False
        host = client.host.strip().lower()
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def authenticate(self, request: Request) -> Principal:
        # Deliberately ignore X-User, X-Tenant, X-Forwarded-For, and similar headers.
        # A reverse proxy would turn this into a non-boundary, which is why the public
        # session view always reports the local mode as unauthenticated/insecure.
        if not self._is_direct_loopback(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "LOCAL_PREVIEW_LOOPBACK_ONLY",
                    "message": "Local preview identity is available only on loopback.",
                },
            )
        try:
            return configured_local_preview_principal()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "AUTH_LOCAL_CONFIG_INVALID",
                    "message": "The local preview identity configuration is invalid.",
                },
            ) from exc


def configured_local_preview_principal() -> Principal:
    """Resolve the server-owned local identity without accepting request input.

    App startup uses the same validated value to provision the local SQLite entitlement,
    so a safe custom ``QL_LOCAL_TENANT_ID`` cannot produce a session that is immediately
    unusable. External providers are provisioned by their own control plane instead.
    """
    return Principal(
        tenant_id=os.getenv("QL_LOCAL_TENANT_ID", DEFAULT_LOCAL_TENANT_ID),
        user_id=os.getenv("QL_LOCAL_USER_ID", DEFAULT_LOCAL_USER_ID),
        roles=frozenset({"owner"}),
        auth_mode=LOCAL_PREVIEW_MODE,
        display_label=os.getenv("QL_LOCAL_DISPLAY_LABEL", DEFAULT_LOCAL_DISPLAY_LABEL),
        authenticated=False,
        security_boundary=False,
    )


_local_provider = LocalPreviewAuthProvider()
_external_provider: AuthProvider | None = None


def configure_auth_provider(provider: AuthProvider) -> None:
    """Install one process-local external provider adapter.

    App startup code may call this after constructing a real OIDC/vendor adapter.
    Tests normally need only ``app.dependency_overrides[require_principal]``.
    """
    if not isinstance(provider, AuthProvider):
        raise TypeError("provider must implement the AuthProvider protocol")
    mode = _validate_auth_mode(provider.mode)
    if mode == LOCAL_PREVIEW_MODE or mode in _UNSAFE_AUTH_MODES:
        raise ValueError("external provider mode must be an explicit secure mode")
    global _external_provider
    _external_provider = provider


def clear_auth_provider() -> None:
    """Remove the external adapter (primarily for isolated app/test lifecycles)."""
    global _external_provider
    _external_provider = None


async def require_principal(request: Request) -> Principal:
    """FastAPI dependency that returns a scoped principal or fails closed."""
    raw_mode = os.getenv("QL_AUTH_MODE", LOCAL_PREVIEW_MODE)
    mode = raw_mode.strip().lower()

    if mode == LOCAL_PREVIEW_MODE:
        return _local_provider.authenticate(request)

    if mode in _UNSAFE_AUTH_MODES:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_MODE_UNSAFE",
                "message": "Anonymous/public auth modes are not enabled for private routes.",
            },
        )

    provider = _external_provider
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_PROVIDER_NOT_CONFIGURED",
                "message": "The selected authentication provider is not configured.",
            },
        )

    if mode != provider.mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_MODE_UNSUPPORTED",
                "message": "The selected authentication mode has no matching provider.",
            },
        )

    result = provider.authenticate(request)
    principal = await result if inspect.isawaitable(result) else result
    if not isinstance(principal, Principal):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_PROVIDER_CONTRACT",
                "message": "The authentication provider returned an invalid principal.",
            },
        )
    if (principal.auth_mode != mode or not principal.authenticated
            or not principal.security_boundary):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_PROVIDER_CONTRACT",
                "message": "The authentication provider did not establish a secure session.",
            },
        )
    return principal


def session_public_view(principal: Principal) -> dict[str, object]:
    """Return UI-safe session status without exposing internal opaque identifiers."""
    local_preview = principal.auth_mode == LOCAL_PREVIEW_MODE
    return {
        "display_label": principal.display_label,
        "roles": sorted(principal.roles),
        "auth_mode": principal.auth_mode,
        "authenticated": principal.authenticated,
        "security_boundary": principal.security_boundary,
        "local_preview": local_preview,
        "notice": (
            "Local preview only. This session is not authenticated and does not "
            "provide an account security boundary."
            if local_preview
            else "Authenticated private workspace session."
        ),
    }
