"""Worker-side client for the separate control-plane registrar process.

The corrected branch delegates the three CONTROL_PLANE_REGISTRAR flows to a
registrar SERVICE over one pinned loopback origin. This client holds no key
material at all: the registrar process signs the authority requests with its
own role keys, and everything the client receives is proved downstream — the
issued anchor against the hash-pinned issuer bundle by the worker-side
verifier, and the registered capsule/anchor identities by the authority-signed
lease and consume flow. A malicious or misconfigured registrar can therefore
only produce typed fail-closed refusals, never unverified evidence.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Mapping

from quantlens_schema.control_plane_registrar_protocol_v1 import (
    ControlPlaneRegistrarProtocolError,
    REGISTRAR_FLOW_ISSUE_ANCHOR,
    REGISTRAR_FLOW_REGISTER_ANCHOR,
    REGISTRAR_FLOW_REGISTER_CAPSULE,
    REGISTRAR_FLOW_PATHS_V1,
    REGISTRAR_REQUEST_VERSION_V1,
    canonical_json_bytes,
    validate_registrar_response_v1,
)

_LOOPBACK_ORIGIN_RE = re.compile(r"^http://127\.0\.0\.1(:\d{1,5})?$")


class RegistrarClientError(RuntimeError):
    """The registrar endpoint refused, failed or answered off-protocol."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistrarClientError(message)


def registrar_origin_configured(value: str | None) -> bool:
    """Whether one value is an exact loopback registrar origin."""
    return isinstance(value, str) and \
        _LOOPBACK_ORIGIN_RE.fullmatch(value) is not None


class ControlPlaneRegistrarClientV1:
    """Three loopback POST flows against the registrar-protocol paths."""

    def __init__(self, base_url: str, *,
                 timeout_seconds: float = 60.0) -> None:
        _require(registrar_origin_configured(base_url),
                 "the registrar base URL must be an exact loopback origin")
        _require(
            isinstance(timeout_seconds, (int, float))
            and not isinstance(timeout_seconds, bool) and timeout_seconds > 0,
            "the registrar timeout must be a positive number")
        self._base_url = base_url
        self._timeout_seconds = float(timeout_seconds)
        # An empty proxy handler so a hostile ``*_proxy`` environment variable
        # can never re-route registrar traffic off the loopback interface.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def _flow(self, flow: str, envelope: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self._base_url + REGISTRAR_FLOW_PATHS_V1[flow],
            data=canonical_json_bytes(envelope),
            method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(
                    request, timeout=self._timeout_seconds) as response:
                status = int(response.status)
                payload = response.read()
        except urllib.error.HTTPError as error:
            status = int(error.code)
            payload = error.read()
        except (urllib.error.URLError, OSError) as error:
            raise RegistrarClientError(
                "the control-plane registrar endpoint could not be "
                "reached") from error
        _require(status == 200,
                 f"the control-plane registrar refused the {flow} flow")
        try:
            document = json.loads(payload.decode("utf-8"))
            validated = validate_registrar_response_v1(document, flow=flow)
        except (ValueError, UnicodeDecodeError,
                ControlPlaneRegistrarProtocolError) as error:
            raise RegistrarClientError(
                "the control-plane registrar answered off-protocol"
            ) from error
        return dict(validated["result"])

    def issue_anchor(self, validation_plan: Mapping[str, Any]) -> dict:
        return self._flow(REGISTRAR_FLOW_ISSUE_ANCHOR, {
            "request_version": REGISTRAR_REQUEST_VERSION_V1,
            "validation_plan": json.loads(json.dumps(validation_plan)),
        })

    def register_capsule(self, validation_plan: Mapping[str, Any],
                         primary_observations: Mapping[str, Any]) -> dict:
        return self._flow(REGISTRAR_FLOW_REGISTER_CAPSULE, {
            "request_version": REGISTRAR_REQUEST_VERSION_V1,
            "validation_plan": json.loads(json.dumps(validation_plan)),
            "primary_observations": json.loads(
                json.dumps(primary_observations)),
        })

    def register_anchor(self, capsule_id: str,
                        issued: Mapping[str, Any]) -> dict:
        return self._flow(REGISTRAR_FLOW_REGISTER_ANCHOR, {
            "request_version": REGISTRAR_REQUEST_VERSION_V1,
            "capsule_id": capsule_id,
            "issued": {
                "anchor": json.loads(json.dumps(issued["anchor"])),
                "registration_receipt": json.loads(
                    json.dumps(issued["registration_receipt"])),
                "registered_signed_anchor_bytes_hex": str(
                    issued["registered_signed_anchor_bytes_hex"]),
                "registered_signed_receipt_bytes_hex": str(
                    issued["registered_signed_receipt_bytes_hex"]),
            },
        })


__all__ = [
    "ControlPlaneRegistrarClientV1",
    "RegistrarClientError",
    "registrar_origin_configured",
]
