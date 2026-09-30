"""Dormant loopback-only HTTP factory for the final-holdout authority.

``create_final_holdout_authority_app`` returns a FastAPI instance exposing
exactly the six frozen ``POST`` routes of contract 37 section 4 and dispatching
each to the matching :class:`FinalHoldoutAuthorityV1` method.  There is no
module-level ``app``; importing this module opens no socket, reads no
environment, key or database, starts no thread and invokes no factory.  The
explicit :func:`main` runner binds only ``127.0.0.1`` or ``::1`` and is never
called by any acceptance flow.

Loopback is transport isolation, not authentication: every request additionally
carries the signed ``FINAL_EVALUATOR``/``CONTROL_PLANE_REGISTRAR`` envelope the
authority verifies.  The actual ASGI peer address must parse as an IP loopback;
``Host``, ``Forwarded`` and ``X-Forwarded-*`` never establish trust.  The
transport accepts exactly one ``application/json`` (optional single UTF-8
charset) Content-Type on the exact decoded-and-raw route path with no query
string, no content encoding, streams and caps the body (16 MiB for capsule
registration, 1 MiB for every other route), recursively rejects duplicate JSON
keys, rejects non-finite numbers, trailing bytes and abusive nesting, and binds
each concrete path ``lease_id`` byte-for-byte to the closed body ``lease_id``.

A malformed or pre-parse transport failure returns only the canonical unsigned
sanitized body for its status.  Every other outcome returns the authority's
exact ``signed_response_wrapper_bytes`` unchanged, at that wrapper's own
``service_response.status_code``; a signer/authority failure after a fully
parsed request returns only the unsigned canonical ``503 AUTHORITY_UNAVAILABLE``.
Every response carries ``Cache-Control: no-store``; no signed wrapper is ever
reserialized, and docs, OpenAPI, Redoc, CORS, debug and reload stay disabled.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from quantlens_schema.final_holdout_access_protocol_v1 import (
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_LEASE_PATH_V1,
    FINAL_HOLDOUT_UNSIGNED_TRANSPORT_BODIES,
    MAX_CAPSULE_REGISTRATION_BODY_BYTES,
    MAX_CLIENT_REQUEST_BODY_BYTES,
    canonical_json_bytes,
)

from .holdout_authority_v1 import (
    FinalHoldoutAuthorityConfig,
    FinalHoldoutAuthorityConfigurationError,
    FinalHoldoutAuthorityError,
    FinalHoldoutAuthorityUnavailableError,
    FinalHoldoutAuthorityV1,
    FinalHoldoutRequestError,
)

_NO_STORE = "no-store"
_JSON = "application/json"
# Per-request loopback is decided from the actual ASGI peer IP; the runner binds
# only the two literal loopback hosts.
_RUNNER_HOSTS = ("127.0.0.1", "::1")
# A bounded nesting depth is enforced explicitly; the deepest valid envelope is
# far shallower, so this only ever rejects abusive input.
_MAX_JSON_DEPTH = 64


def _unsigned(status_code: int) -> Response:
    """One canonical unsigned sanitized transport body for its status."""
    return Response(
        content=canonical_json_bytes(
            FINAL_HOLDOUT_UNSIGNED_TRANSPORT_BODIES[status_code]),
        status_code=status_code,
        media_type=_JSON,
        headers={"Cache-Control": _NO_STORE},
    )


def _signed_passthrough(wrapper_bytes: bytes, status_code: int) -> Response:
    """Return the authority's exact signed wrapper bytes, never reserialized."""
    return Response(
        content=bytes(wrapper_bytes),
        status_code=status_code,
        media_type=_JSON,
        headers={"Cache-Control": _NO_STORE},
    )


def _client_is_loopback(request: Request) -> bool:
    client = request.client
    if client is None or not client.host:
        return False
    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


def _content_type_ok(raw: str) -> bool:
    """Accept exactly ``application/json`` with no parameters or one charset."""
    parts = raw.split(";")
    if parts[0].strip().lower() != _JSON:
        return False
    seen_charset = False
    for parameter in parts[1:]:
        name, separator, value = parameter.partition("=")
        if separator != "=":
            return False
        if name.strip().lower() != "charset" or seen_charset:
            return False
        seen_charset = True
        if not _charset_is_utf8(value.strip()):
            return False
    return True


def _charset_is_utf8(value: str) -> bool:
    if value.lower() == "utf-8":
        return True
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].lower() == "utf-8"
    return False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError("duplicate JSON object key")
        mapping[key] = value
    return mapping


def _reject_constant(_token: str) -> Any:
    raise ValueError("non-finite JSON constant")


def _finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


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


def _transport_error(request: Request, expected_path: str) -> Response | None:
    """Return a sanitized transport error, or ``None`` when the request is clean.

    Trust requires the actual ASGI loopback peer; the decoded and raw route path
    must both equal the exact expected path so a percent alias, normalization
    difference or query string can never reach the authority; content encodings
    and any Content-Type other than one ``application/json`` fail closed.
    """
    if not _client_is_loopback(request):
        return _unsigned(403)
    scope = request.scope
    raw_path = scope.get("raw_path")
    try:
        expected_raw_path = expected_path.encode("ascii")
    except UnicodeEncodeError:
        # A percent-decoded non-ASCII path parameter may still match Starlette's
        # dynamic route.  It can never be one of the frozen ASCII lease IDs.
        return _unsigned(400)
    if not isinstance(raw_path, bytes) \
            or scope.get("path") != expected_path \
            or raw_path != expected_raw_path:
        return _unsigned(400)
    if scope.get("query_string", b"") != b"":
        return _unsigned(400)
    if request.headers.getlist("content-encoding"):
        return _unsigned(400)
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1 or not _content_type_ok(content_types[0]):
        return _unsigned(400)
    return None


async def _read_envelope(
    request: Request, max_bytes: int
) -> tuple[Response, None] | tuple[None, dict[str, Any]]:
    """Stream, size-cap and strictly parse the closed transport envelope."""
    received = bytearray()
    async for chunk in request.stream():
        # Reject before copying an oversized ASGI chunk so the cap is also a
        # memory bound rather than merely a post-allocation validation.
        if len(chunk) > max_bytes - len(received):
            return _unsigned(413), None
        received.extend(chunk)
    try:
        envelope = json.loads(
            bytes(received).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError covers JSON nested past the interpreter limit; the
        # explicit bound below covers abusive-but-parseable nesting.
        return _unsigned(400), None
    if not _within_json_depth(envelope, _MAX_JSON_DEPTH):
        return _unsigned(400), None
    if not isinstance(envelope, dict) \
            or set(envelope) != {"client_request", "body"} \
            or not isinstance(envelope["client_request"], dict) \
            or not isinstance(envelope["body"], dict):
        return _unsigned(400), None
    return None, envelope


def _error_response(exc: FinalHoldoutAuthorityError) -> Response:
    """Pass through a signed authority error, else a canonical unsigned body.

    A signer that could sign carries the exact signed wrapper and its status; a
    dead signer (or any unavailability after parsing) can only be the unsigned
    503, and an unparseable client-request envelope the unsigned 400.
    """
    wrapper = exc.signed_response_wrapper_bytes
    if wrapper is not None and exc.service_response is not None:
        return _signed_passthrough(wrapper, int(exc.service_response["status_code"]))
    if isinstance(exc, FinalHoldoutRequestError):
        return _unsigned(400)
    return _unsigned(503)


async def _dispatch(
    request: Request,
    *,
    expected_path: str,
    max_bytes: int,
    invoke: Callable[[dict[str, Any], dict[str, Any]], Any],
    path_lease_id: str | None = None,
) -> Response:
    """Shared transport pipeline shared by all six routes."""
    transport = _transport_error(request, expected_path)
    if transport is not None:
        return transport
    error, envelope = await _read_envelope(request, max_bytes)
    if envelope is None:
        assert error is not None
        return error
    body = envelope["body"]
    # The concrete path lease id must equal the closed body lease id byte for
    # byte; this fails before any authority logic.
    if path_lease_id is not None and body.get("lease_id") != path_lease_id:
        return _unsigned(400)
    try:
        result = invoke(envelope["client_request"], body)
    except FinalHoldoutAuthorityError as exc:
        return _error_response(exc)
    except Exception:
        # A complete request that reaches an unexpected internal failure still
        # receives the one sanitized unsigned unavailable response.  Never
        # reflect or log exception text: it may contain key paths or plaintext.
        return _unsigned(503)
    return _signed_passthrough(
        result.signed_response_wrapper_bytes,
        int(result.service_response["status_code"]),
    )


def create_final_holdout_authority_app(
    authority: FinalHoldoutAuthorityV1,
) -> FastAPI:
    """Build the dormant loopback-only six-route app around one authority."""
    if not isinstance(authority, FinalHoldoutAuthorityV1):
        raise FinalHoldoutAuthorityError(
            "the service factory requires a constructed FinalHoldoutAuthorityV1")
    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    # Wrong method, unknown/trailing/dot/double-slash/percent path aliases never
    # reach an endpoint; the framework 404/405 bodies become deterministic
    # sanitized codes.  These transport codes sit outside the signed status law.
    @app.exception_handler(StarletteHTTPException)
    async def _sanitized_transport_error(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        if not _client_is_loopback(request):
            return _unsigned(403)
        if exc.status_code == 405:
            return _unsigned(405)
        if exc.status_code == 404:
            return _unsigned(404)
        return _unsigned(400)

    @app.post(FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1)
    async def register_capsule(request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
            max_bytes=MAX_CAPSULE_REGISTRATION_BODY_BYTES,
            invoke=lambda cr, body: authority.register_capsule(cr, body=body),
        )

    @app.post(FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1)
    async def register_anchor(request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
            max_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            invoke=lambda cr, body: authority.register_anchor(cr, body=body),
        )

    @app.post(FINAL_HOLDOUT_LEASE_PATH_V1)
    async def create_lease(request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_LEASE_PATH_V1,
            max_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            invoke=lambda cr, body: authority.create_lease(cr, body=body),
        )

    @app.post(FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1)
    async def consume(lease_id: str, request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            max_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            invoke=lambda cr, body: authority.consume(cr, body=body),
            path_lease_id=lease_id,
        )

    @app.post(FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1)
    async def complete(lease_id: str, request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            max_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            invoke=lambda cr, body: authority.complete(cr, body=body),
            path_lease_id=lease_id,
        )

    @app.post(FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1)
    async def retrieve_audit(lease_id: str, request: Request) -> Response:
        return await _dispatch(
            request,
            expected_path=FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            max_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            invoke=lambda cr, body: authority.retrieve_audit(cr, body=body),
            path_lease_id=lease_id,
        )

    return app


def main() -> None:
    """Explicit local entry point; never invoked by any acceptance flow."""
    host = os.environ.get("QL_FINAL_HOLDOUT_AUTHORITY_HOST", "127.0.0.1")
    if host not in _RUNNER_HOSTS:
        raise FinalHoldoutAuthorityConfigurationError(
            "the final-holdout authority binds only 127.0.0.1 or ::1")
    port = int(os.environ.get("QL_FINAL_HOLDOUT_AUTHORITY_PORT", "8941"))
    authority_bundle = json.loads(
        Path(os.environ["QL_FINAL_HOLDOUT_AUTHORITY_TRUST_BUNDLE_FILE"]).read_text(
            encoding="utf-8"))
    client_bundle = json.loads(
        Path(os.environ["QL_FINAL_HOLDOUT_CLIENT_TRUST_BUNDLE_FILE"]).read_text(
            encoding="utf-8"))
    issuer_bundle = json.loads(
        Path(os.environ[
            "QL_FINAL_HOLDOUT_PLAN_ANCHOR_ISSUER_TRUST_BUNDLE_FILE"]).read_text(
            encoding="utf-8"))
    config = FinalHoldoutAuthorityConfig(
        authority_var_dir=Path(
            os.environ["QL_FINAL_HOLDOUT_AUTHORITY_VAR_DIR"]),
        authority_id=os.environ["QL_FINAL_HOLDOUT_AUTHORITY_ID"],
        authority_signer_key_id=os.environ[
            "QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID"],
        # The environment carries only a path; the seed itself never transits it.
        authority_signer_private_key_file=Path(
            os.environ["QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_PRIVATE_KEY_FILE"]),
        authority_trust_bundle=authority_bundle,
        expected_authority_trust_bundle_sha256=os.environ[
            "QL_FINAL_HOLDOUT_AUTHORITY_TRUST_BUNDLE_SHA256"],
        client_trust_bundle=client_bundle,
        expected_client_trust_bundle_sha256=os.environ[
            "QL_FINAL_HOLDOUT_CLIENT_TRUST_BUNDLE_SHA256"],
        plan_anchor_issuer_trust_bundle=issuer_bundle,
        expected_plan_anchor_issuer_trust_bundle_sha256=os.environ[
            "QL_FINAL_HOLDOUT_PLAN_ANCHOR_ISSUER_TRUST_BUNDLE_SHA256"],
        payload_encryption_key_id=os.environ[
            "QL_FINAL_HOLDOUT_PAYLOAD_ENCRYPTION_KEY_ID"],
        payload_encryption_key_file=Path(
            os.environ["QL_FINAL_HOLDOUT_PAYLOAD_ENCRYPTION_KEY_FILE"]),
    )
    application = create_final_holdout_authority_app(
        FinalHoldoutAuthorityV1(config))
    import uvicorn  # deferred so importing this module never loads a server

    uvicorn.run(
        application,
        host=host,
        port=port,
        log_level="warning",
        # Uvicorn otherwise trusts forwarding headers from loopback by default
        # and rewrites scope["client"], violating the direct-peer trust law.
        proxy_headers=False,
    )


__all__ = [
    "create_final_holdout_authority_app",
    "main",
]
