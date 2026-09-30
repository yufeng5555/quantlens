"""Loopback-only HTTP surface for the control-plane registrar.

``create_control_plane_registrar_app`` returns a FastAPI instance exposing
exactly the three registrar-protocol POST paths with no global app object,
docs, OpenAPI, Redoc, CORS, debug, reload or import-time database open. The
direct ASGI client address must be loopback; ``Host``, ``Forwarded``,
``X-Forwarded-*`` and every other caller-identity header are ignored.
Loopback is transport isolation for the worker-side hop; the authority-side
hops each carry the registrar's signed CONTROL_PLANE_REGISTRAR envelope,
which the authorities verify.

The transport accepts ``application/json`` (optional UTF-8 charset) on the
exact frozen paths with no query string, streams and caps the body at 1 MiB,
recursively rejects duplicate JSON keys and returns canonical compact JSON
with ``Cache-Control: no-store``. Error responses carry only a stable
sanitized code — never exception text, SQL, plan content, key bytes or file
paths.

``main()`` reads registrar-only configuration when explicitly executed,
binds only ``127.0.0.1`` and rejects any alternate host. No acceptance flow
invokes it or opens a listening socket.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from fastapi import FastAPI, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from quantlens_schema.control_plane_registrar_protocol_v1 import (
    ControlPlaneRegistrarProtocolError,
    MAX_REGISTRAR_REQUEST_BYTES,
    REGISTRAR_FLOW_ISSUE_ANCHOR,
    REGISTRAR_FLOW_REGISTER_ANCHOR,
    REGISTRAR_FLOW_REGISTER_CAPSULE,
    REGISTRAR_ISSUE_ANCHOR_PATH_V1,
    REGISTRAR_REGISTER_ANCHOR_PATH_V1,
    REGISTRAR_REGISTER_CAPSULE_PATH_V1,
    REGISTRAR_RESPONSE_VERSION_V1,
    canonical_json_bytes,
    validate_registrar_anchor_request_v1,
    validate_registrar_capsule_request_v1,
    validate_registrar_issue_request_v1,
)

from .registrar_v1 import (
    ControlPlaneRegistrarConfig,
    ControlPlaneRegistrarError,
    ControlPlaneRegistrarV1,
    RegistrarRequestError,
    RegistrarRunConflictError,
    RegistrarUpstreamError,
)

_LOOPBACK_HOSTS = ("127.0.0.1", "::1")
_NO_STORE = "no-store"
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
    parts = raw.split(";")
    if parts[0].strip().lower() != "application/json":
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


def _within_json_depth(value: object, limit: int) -> bool:
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


def create_control_plane_registrar_app(
    registrar: ControlPlaneRegistrarV1,
) -> FastAPI:
    """Build the loopback-only registrar endpoints around one registrar."""
    if not isinstance(registrar, ControlPlaneRegistrarV1):
        raise ControlPlaneRegistrarError(
            "the service factory requires a constructed ControlPlaneRegistrarV1"
        )
    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None,
        redirect_slashes=False)

    @app.exception_handler(StarletteHTTPException)
    async def _sanitized_transport_error(
        request: Request, exc: StarletteHTTPException
    ) -> Response:
        if exc.status_code == 405:
            return _sanitized(405, "METHOD_NOT_ALLOWED")
        if exc.status_code == 404:
            return _sanitized(404, "NOT_FOUND")
        return _sanitized(400, "INVALID_REQUEST")

    async def _handle(
        request: Request,
        *,
        path: str,
        flow: str,
        validate: Callable[[object], Mapping[str, Any]],
        execute: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Response:
        client = request.client
        if client is None or client.host not in _LOOPBACK_HOSTS:
            return _sanitized(403, "LOOPBACK_REQUIRED")
        if request.scope.get("path") != path \
                or bytes(request.scope.get("raw_path", b"")) \
                != path.encode("ascii"):
            return _sanitized(400, "INVALID_REQUEST")
        if request.scope.get("query_string", b"") != b"":
            return _sanitized(400, "INVALID_REQUEST")
        content_types = request.headers.getlist("content-type")
        if len(content_types) != 1 or not _content_type_ok(content_types[0]):
            return _sanitized(400, "INVALID_REQUEST")
        received = bytearray()
        async for chunk in request.stream():
            received.extend(chunk)
            if len(received) > MAX_REGISTRAR_REQUEST_BYTES:
                return _sanitized(413, "PAYLOAD_TOO_LARGE")
        try:
            envelope = json.loads(
                bytes(received).decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (ValueError, UnicodeDecodeError, RecursionError):
            return _sanitized(400, "INVALID_REQUEST")
        if not _within_json_depth(envelope, _MAX_JSON_DEPTH):
            return _sanitized(400, "INVALID_REQUEST")
        try:
            document = validate(envelope)
        except ControlPlaneRegistrarProtocolError:
            return _sanitized(400, "INVALID_REQUEST")
        try:
            result = execute(document)
        except RegistrarRunConflictError:
            return _sanitized(409, "REGISTRAR_RUN_CONFLICT")
        except RegistrarRequestError:
            return _sanitized(400, "INVALID_REQUEST")
        except RegistrarUpstreamError as error:
            if error.authority_status is not None:
                return _sanitized(502, "AUTHORITY_REFUSED")
            return _sanitized(502, "AUTHORITY_UNREACHABLE")
        except ControlPlaneRegistrarError:
            return _sanitized(503, "REGISTRAR_UNAVAILABLE")
        payload = {
            "response_version": REGISTRAR_RESPONSE_VERSION_V1,
            "flow": flow,
            "result": dict(result),
        }
        return Response(
            content=canonical_json_bytes(payload),
            status_code=200,
            media_type="application/json",
            headers={"Cache-Control": _NO_STORE},
        )

    @app.post(REGISTRAR_ISSUE_ANCHOR_PATH_V1)
    async def issue_anchor(request: Request) -> Response:
        return await _handle(
            request,
            path=REGISTRAR_ISSUE_ANCHOR_PATH_V1,
            flow=REGISTRAR_FLOW_ISSUE_ANCHOR,
            validate=validate_registrar_issue_request_v1,
            execute=lambda document: registrar.issue_anchor(
                document["validation_plan"]),
        )

    @app.post(REGISTRAR_REGISTER_CAPSULE_PATH_V1)
    async def register_capsule(request: Request) -> Response:
        return await _handle(
            request,
            path=REGISTRAR_REGISTER_CAPSULE_PATH_V1,
            flow=REGISTRAR_FLOW_REGISTER_CAPSULE,
            validate=validate_registrar_capsule_request_v1,
            execute=lambda document: registrar.register_capsule(
                document["validation_plan"],
                document["primary_observations"]),
        )

    @app.post(REGISTRAR_REGISTER_ANCHOR_PATH_V1)
    async def register_anchor(request: Request) -> Response:
        return await _handle(
            request,
            path=REGISTRAR_REGISTER_ANCHOR_PATH_V1,
            flow=REGISTRAR_FLOW_REGISTER_ANCHOR,
            validate=validate_registrar_anchor_request_v1,
            execute=lambda document: registrar.register_anchor(
                document["capsule_id"], document["issued"]),
        )

    return app


def main() -> None:
    """Explicit local entry point; never invoked by any acceptance flow."""
    host = os.environ.get("QL_CONTROL_PLANE_REGISTRAR_HOST", "127.0.0.1")
    if host != "127.0.0.1":
        raise ControlPlaneRegistrarError(
            "the control-plane registrar binds only 127.0.0.1"
        )
    port = int(os.environ.get("QL_CONTROL_PLANE_REGISTRAR_PORT", "8951"))
    config = ControlPlaneRegistrarConfig(
        registrar_var_dir=Path(
            os.environ["QL_CONTROL_PLANE_REGISTRAR_VAR_DIR"]),
        plan_anchor_authority_url=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_PLAN_ANCHOR_AUTHORITY_URL"],
        plan_anchor_authority_id=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_PLAN_ANCHOR_AUTHORITY_ID"],
        plan_anchor_registrar_key_id=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_PLAN_ANCHOR_KEY_ID"],
        # The environment values are paths only; no seed ever transits the
        # environment.
        plan_anchor_registrar_private_key_file=Path(os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_PLAN_ANCHOR_KEY_FILE"]),
        holdout_authority_url=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_HOLDOUT_AUTHORITY_URL"],
        holdout_authority_id=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_HOLDOUT_AUTHORITY_ID"],
        holdout_registrar_key_id=os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_HOLDOUT_KEY_ID"],
        holdout_registrar_private_key_file=Path(os.environ[
            "QL_CONTROL_PLANE_REGISTRAR_HOLDOUT_KEY_FILE"]),
    )
    application = create_control_plane_registrar_app(
        ControlPlaneRegistrarV1(config))
    import uvicorn  # deferred so importing this module never loads a server

    uvicorn.run(application, host="127.0.0.1", port=port, log_level="warning")


__all__ = [
    "create_control_plane_registrar_app",
    "main",
]
