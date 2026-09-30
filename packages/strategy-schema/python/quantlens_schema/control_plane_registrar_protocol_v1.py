"""Neutral control-plane registrar protocol, version 1.

The worker-side registrar client and the separate control-plane registrar
service share exactly this vocabulary: three loopback POST flows that carry
one JSON envelope each. The registrar process holds the CONTROL_PLANE_REGISTRAR
role keys and converts these envelopes into the signed authority requests of
the plan-anchor and final-holdout protocols; the worker never sees a registrar
key and this module never constructs, signs or verifies an authority request.

Every validator is closed over its exact key set and fails with the typed
:class:`ControlPlaneRegistrarProtocolError` so both sides reject unknown or
missing fields identically.
"""

from __future__ import annotations

from typing import Any

from .plan_anchor_protocol_v1 import canonical_json_bytes

CONTROL_PLANE_REGISTRAR_PROTOCOL_V1 = "control-plane-registrar-v1"

REGISTRAR_REQUEST_VERSION_V1 = "control-plane-registrar-request-v1"
REGISTRAR_RESPONSE_VERSION_V1 = "control-plane-registrar-response-v1"

REGISTRAR_ISSUE_ANCHOR_PATH_V1 = "/registrar/v1/plan-anchors"
REGISTRAR_REGISTER_CAPSULE_PATH_V1 = "/registrar/v1/capsules"
REGISTRAR_REGISTER_ANCHOR_PATH_V1 = "/registrar/v1/anchor-registrations"

REGISTRAR_FLOW_ISSUE_ANCHOR = "issue_anchor"
REGISTRAR_FLOW_REGISTER_CAPSULE = "register_capsule"
REGISTRAR_FLOW_REGISTER_ANCHOR = "register_anchor"

REGISTRAR_FLOW_PATHS_V1 = {
    REGISTRAR_FLOW_ISSUE_ANCHOR: REGISTRAR_ISSUE_ANCHOR_PATH_V1,
    REGISTRAR_FLOW_REGISTER_CAPSULE: REGISTRAR_REGISTER_CAPSULE_PATH_V1,
    REGISTRAR_FLOW_REGISTER_ANCHOR: REGISTRAR_REGISTER_ANCHOR_PATH_V1,
}

MAX_REGISTRAR_REQUEST_BYTES = 1_048_576

# The exact key set of the issued-anchor material the registrar returns from
# the plan-anchor authority and later re-submits to the final-holdout
# authority. The hex fields carry the authority-registered canonical bytes so
# the worker-side verifier can prove the anchor without trusting the registrar.
ISSUED_ANCHOR_FIELDS_V1 = (
    "anchor",
    "registration_receipt",
    "registered_signed_anchor_bytes_hex",
    "registered_signed_receipt_bytes_hex",
)


class ControlPlaneRegistrarProtocolError(ValueError):
    """A registrar envelope violated the closed protocol grammar."""


def _reject(message: str) -> None:
    raise ControlPlaneRegistrarProtocolError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def _closed_object(value: object, fields: tuple[str, ...],
                   label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    assert isinstance(value, dict)
    presented = set(value)
    expected = set(fields)
    _require(
        presented == expected,
        f"{label} must carry exactly the fields {sorted(expected)}; "
        f"got {sorted(presented)}",
    )
    return value


def _json_object_field(value: object, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and bool(value),
             f"{label} must be a non-empty JSON object")
    assert isinstance(value, dict)
    return value


def _hex_field(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and len(value) > 0 and len(value) % 2 == 0
        and all(character in "0123456789abcdef" for character in value),
        f"{label} must be non-empty lowercase hex",
    )
    assert isinstance(value, str)
    return value


def _request_version(value: object) -> None:
    _require(value == REGISTRAR_REQUEST_VERSION_V1,
             "request_version must be the exact registrar protocol version")


def validate_registrar_issue_request_v1(envelope: object) -> dict[str, Any]:
    """Closed grammar of the issue-anchor flow envelope."""
    document = _closed_object(
        envelope, ("request_version", "validation_plan"),
        "issue-anchor envelope")
    _request_version(document["request_version"])
    _json_object_field(document["validation_plan"], "validation_plan")
    return document


def validate_registrar_capsule_request_v1(envelope: object) -> dict[str, Any]:
    """Closed grammar of the register-capsule flow envelope."""
    document = _closed_object(
        envelope,
        ("request_version", "validation_plan", "primary_observations"),
        "register-capsule envelope")
    _request_version(document["request_version"])
    _json_object_field(document["validation_plan"], "validation_plan")
    _json_object_field(document["primary_observations"], "primary_observations")
    return document


def validate_registrar_anchor_request_v1(envelope: object) -> dict[str, Any]:
    """Closed grammar of the register-anchor flow envelope."""
    document = _closed_object(
        envelope, ("request_version", "capsule_id", "issued"),
        "register-anchor envelope")
    _request_version(document["request_version"])
    _require(
        isinstance(document["capsule_id"], str) and bool(document["capsule_id"]),
        "capsule_id must be a non-empty string")
    issued = _closed_object(
        document["issued"], ISSUED_ANCHOR_FIELDS_V1, "issued")
    _json_object_field(issued["anchor"], "issued.anchor")
    _json_object_field(issued["registration_receipt"],
                       "issued.registration_receipt")
    _hex_field(issued["registered_signed_anchor_bytes_hex"],
               "issued.registered_signed_anchor_bytes_hex")
    _hex_field(issued["registered_signed_receipt_bytes_hex"],
               "issued.registered_signed_receipt_bytes_hex")
    return document


def validate_registrar_response_v1(document: object, *,
                                   flow: str) -> dict[str, Any]:
    """Closed grammar of a registrar success response for one flow."""
    _require(flow in REGISTRAR_FLOW_PATHS_V1, f"unknown registrar flow {flow!r}")
    envelope = _closed_object(
        document, ("response_version", "flow", "result"),
        "registrar response")
    _require(envelope["response_version"] == REGISTRAR_RESPONSE_VERSION_V1,
             "response_version must be the exact registrar protocol version")
    _require(envelope["flow"] == flow,
             "the registrar response names a different flow")
    result = _json_object_field(envelope["result"], "result")
    if flow == REGISTRAR_FLOW_ISSUE_ANCHOR:
        issued = _closed_object(result, ISSUED_ANCHOR_FIELDS_V1, "result")
        _json_object_field(issued["anchor"], "result.anchor")
        _json_object_field(issued["registration_receipt"],
                           "result.registration_receipt")
        _hex_field(issued["registered_signed_anchor_bytes_hex"],
                   "result.registered_signed_anchor_bytes_hex")
        _hex_field(issued["registered_signed_receipt_bytes_hex"],
                   "result.registered_signed_receipt_bytes_hex")
    return envelope


__all__ = [
    "CONTROL_PLANE_REGISTRAR_PROTOCOL_V1",
    "ControlPlaneRegistrarProtocolError",
    "ISSUED_ANCHOR_FIELDS_V1",
    "MAX_REGISTRAR_REQUEST_BYTES",
    "REGISTRAR_FLOW_ISSUE_ANCHOR",
    "REGISTRAR_FLOW_PATHS_V1",
    "REGISTRAR_FLOW_REGISTER_ANCHOR",
    "REGISTRAR_FLOW_REGISTER_CAPSULE",
    "REGISTRAR_ISSUE_ANCHOR_PATH_V1",
    "REGISTRAR_REGISTER_ANCHOR_PATH_V1",
    "REGISTRAR_REGISTER_CAPSULE_PATH_V1",
    "REGISTRAR_REQUEST_VERSION_V1",
    "REGISTRAR_RESPONSE_VERSION_V1",
    "canonical_json_bytes",
    "validate_registrar_anchor_request_v1",
    "validate_registrar_capsule_request_v1",
    "validate_registrar_issue_request_v1",
    "validate_registrar_response_v1",
]
