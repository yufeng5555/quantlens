"""Dormant loopback-only HTTP factory for the plan-anchor authority.

``create_plan_anchor_authority_app`` returns a FastAPI instance exposing exactly
``POST /v1/validation-plan-anchors`` with no global app object, docs, OpenAPI,
Redoc, CORS, debug, reload, startup key load or import-time database open.  The
direct ASGI client address must be loopback; ``Host``, ``Forwarded``,
``X-Forwarded-*`` and every other caller-identity header are ignored.  Loopback is
transport isolation, not authentication — every request still needs the signed
CONTROL_PLANE_REGISTRAR envelope, which the authority verifies.

The transport accepts ``application/json`` (optional UTF-8 charset) on the exact
frozen path with no query string, streams and caps the body at 1 MiB, recursively
rejects duplicate JSON keys and returns canonical compact JSON with
``Cache-Control: no-store``.  Initial success and exact retry return byte-identical
responses; error responses carry only a stable sanitized code — never exception
text, SQL, plan content, key bytes or file paths.

``main()`` reads authority-only configuration when explicitly executed, binds only
``127.0.0.1`` and rejects any alternate host.  No acceptance flow invokes it or
opens a listening socket.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from quantlens_schema.plan_anchor_protocol_v1 import (
    PLAN_ANCHOR_ISSUE_PATH_V1,
    canonical_json_bytes,
)

from .authority_v1 import (
    PlanAnchorAuthorityConfig,
    PlanAnchorAuthorityError,
    PlanAnchorAuthorityUnavailableError,
    PlanAnchorAuthorityV1,
    PlanAnchorIssueAuthenticationError,
    PlanAnchorIssueConflictError,
    PlanAnchorIssueRequestError,
)

MAX_ISSUE_REQUEST_BYTES = 1_048_576

_RESPONSE_VERSION = "plan-anchor-issue-response-v1"
# The route path and its raw-byte form are derived from the one neutral protocol
# constant; there is no second hard-coded copy to drift from it.
_ISSUE_PATH = PLAN_ANCHOR_ISSUE_PATH_V1
_ISSUE_RAW_PATH = PLAN_ANCHOR_ISSUE_PATH_V1.encode("ascii")
_LOOPBACK_HOSTS = ("127.0.0.1", "::1")
_NO_STORE = "no-store"
# A bounded nesting depth is enforced explicitly; the deepest valid envelope is
# far shallower, so this only ever rejects abusive input.
_MAX_JSON_DEPTH = 64


def _sanitized(status_code: int, code: str) -> Response:
    return Response(
        content=canonical_json_bytes({"code": code}),
        status_code=status_code,
        media_type="application/json",
        headers={"Cache-Control": _NO_STORE},
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError("duplicate JSON object key")
        mapping[key] = value
    return mapping


def _content_type_ok(raw: str) -> bool:
    """Accept exactly ``application/json`` with no parameters or one charset=utf-8.

    Unknown parameters, a duplicate charset, a value-less parameter and any other
    malformed parameter are rejected.  Caller must ensure exactly one header value
    was supplied before calling this.
    """
    parts = raw.split(";")
    if parts[0].strip().lower() != "application/json":
        return False
    seen_charset = False
    for parameter in parts[1:]:
        name, separator, value = parameter.partition("=")
        if separator != "=":
            return False  # malformed parameter with no value
        if name.strip().lower() != "charset" or seen_charset:
            return False  # unknown parameter or duplicate charset
        seen_charset = True
        if not _charset_is_utf8(value.strip()):
            return False
    return True


def _charset_is_utf8(value: str) -> bool:
    """Accept only bare ``utf-8`` or exactly one properly matched quoted value.

    A lone or unbalanced quote (``"utf-8`` / ``utf-8"`` / ``""utf-8""``) is
    rejected; only ``utf-8`` or ``"utf-8"`` (case-insensitive) passes.
    """
    if value.lower() == "utf-8":
        return True
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].lower() == "utf-8"
    return False


def _within_json_depth(value: object, limit: int) -> bool:
    """Iteratively bound container nesting so no depth can exhaust the stack."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(node, dict):
            for item in node.values():
                stack.append((item, depth + 1))
        elif isinstance(node, list):
            for item in node:
                stack.append((item, depth + 1))
    return True


def create_plan_anchor_authority_app(authority: PlanAnchorAuthorityV1) -> FastAPI:
    """Build the dormant loopback-only issue endpoint around one authority."""
    if not isinstance(authority, PlanAnchorAuthorityV1):
        raise PlanAnchorAuthorityError(
            "the service factory requires a constructed PlanAnchorAuthorityV1"
        )
    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    # Wrong method, unknown/trailing/double-slash/dot/percent-encoded path aliases
    # never reach the endpoint; the framework's default 404/405 bodies are replaced
    # with deterministic sanitized JSON codes carrying Cache-Control: no-store and
    # reflecting no input.  These transport-layer codes sit outside the issue-
    # outcome status law (400/401/403/409/413/503), which governs only the endpoint.
    @app.exception_handler(StarletteHTTPException)
    async def _sanitized_transport_error(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        if exc.status_code == 405:
            return _sanitized(405, "METHOD_NOT_ALLOWED")
        if exc.status_code == 404:
            return _sanitized(404, "NOT_FOUND")
        return _sanitized(400, "INVALID_REQUEST")

    @app.post(_ISSUE_PATH)
    async def issue_validation_plan_anchor(request: Request) -> Response:
        client = request.client
        if client is None or client.host not in _LOOPBACK_HOSTS:
            return _sanitized(403, "LOOPBACK_REQUIRED")
        # The decoded route path already matched; the raw bytes must match too so
        # a percent-encoded alias can never reach the endpoint.
        if request.scope.get("path") != _ISSUE_PATH \
                or bytes(request.scope.get("raw_path", b"")) != _ISSUE_RAW_PATH:
            return _sanitized(400, "INVALID_REQUEST")
        if request.scope.get("query_string", b"") != b"":
            return _sanitized(400, "INVALID_REQUEST")
        # Exactly one Content-Type header, application/json, with no parameters
        # or exactly one charset=utf-8.  A duplicate header, duplicate charset,
        # unknown parameter or malformed parameter fails closed.
        content_types = request.headers.getlist("content-type")
        if len(content_types) != 1 or not _content_type_ok(content_types[0]):
            return _sanitized(400, "INVALID_REQUEST")

        received = bytearray()
        async for chunk in request.stream():
            received.extend(chunk)
            if len(received) > MAX_ISSUE_REQUEST_BYTES:
                return _sanitized(413, "PAYLOAD_TOO_LARGE")
        try:
            envelope = json.loads(
                bytes(received).decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (ValueError, UnicodeDecodeError, RecursionError):
            # RecursionError covers JSON nested past the interpreter limit; the
            # explicit bound below covers abusive-but-parseable nesting.
            return _sanitized(400, "INVALID_REQUEST")
        if not _within_json_depth(envelope, _MAX_JSON_DEPTH):
            return _sanitized(400, "INVALID_REQUEST")
        if not isinstance(envelope, dict) \
                or set(envelope) != {"issue_request", "body"} \
                or not isinstance(envelope["issue_request"], dict) \
                or not isinstance(envelope["body"], dict):
            return _sanitized(400, "INVALID_REQUEST")

        try:
            result = authority.issue_anchor(
                envelope["issue_request"], body=envelope["body"])
        except PlanAnchorIssueRequestError:
            return _sanitized(400, "INVALID_REQUEST")
        except PlanAnchorIssueAuthenticationError:
            return _sanitized(401, "AUTHENTICATION_FAILED")
        except PlanAnchorIssueConflictError as exc:
            return _sanitized(409, exc.code)
        except PlanAnchorAuthorityUnavailableError:
            return _sanitized(503, "AUTHORITY_UNAVAILABLE")
        except PlanAnchorAuthorityError:
            return _sanitized(503, "AUTHORITY_UNAVAILABLE")

        payload = {
            "response_version": _RESPONSE_VERSION,
            "anchor": result.anchor,
            "registered_signed_anchor_bytes_hex":
                result.registered_signed_anchor_bytes.hex(),
            "registration_receipt": result.registration_receipt,
            "registered_signed_receipt_bytes_hex":
                result.registered_signed_receipt_bytes.hex(),
        }
        # ``replayed`` never appears on the wire: an initial success and an exact
        # retry return byte-identical status, body and headers.
        return Response(
            content=canonical_json_bytes(payload),
            status_code=200,
            media_type="application/json",
            headers={"Cache-Control": _NO_STORE},
        )

    return app


def main() -> None:
    """Explicit local entry point; never invoked by any acceptance flow."""
    host = os.environ.get("QL_PLAN_ANCHOR_AUTHORITY_HOST", "127.0.0.1")
    if host != "127.0.0.1":
        raise PlanAnchorAuthorityError(
            "the plan-anchor authority binds only 127.0.0.1"
        )
    port = int(os.environ.get("QL_PLAN_ANCHOR_AUTHORITY_PORT", "8931"))
    issuer_bundle = json.loads(
        Path(os.environ["QL_PLAN_ANCHOR_ISSUER_TRUST_BUNDLE_FILE"]).read_text(
            encoding="utf-8"))
    registrar_bundle = json.loads(
        Path(os.environ["QL_PLAN_ANCHOR_REGISTRAR_TRUST_BUNDLE_FILE"]).read_text(
            encoding="utf-8"))
    config = PlanAnchorAuthorityConfig(
        authority_var_dir=Path(
            os.environ["QL_PLAN_ANCHOR_AUTHORITY_VAR_DIR"]),
        authority_id=os.environ["QL_PLAN_ANCHOR_AUTHORITY_ID"],
        issuer_key_id=os.environ["QL_PLAN_ANCHOR_ISSUER_KEY_ID"],
        # The environment value is a path only; the seed itself never transits
        # the environment.
        issuer_private_key_file=Path(
            os.environ["QL_PLAN_ANCHOR_ISSUER_PRIVATE_KEY_FILE"]),
        issuer_trust_bundle=issuer_bundle,
        expected_issuer_trust_bundle_sha256=os.environ[
            "QL_PLAN_ANCHOR_ISSUER_TRUST_BUNDLE_SHA256"],
        registrar_trust_bundle=registrar_bundle,
        expected_registrar_trust_bundle_sha256=os.environ[
            "QL_PLAN_ANCHOR_REGISTRAR_TRUST_BUNDLE_SHA256"],
    )
    application = create_plan_anchor_authority_app(PlanAnchorAuthorityV1(config))
    import uvicorn  # deferred so importing this module never loads a server

    uvicorn.run(application, host="127.0.0.1", port=port, log_level="warning")


__all__ = [
    "MAX_ISSUE_REQUEST_BYTES",
    "create_plan_anchor_authority_app",
    "main",
]
