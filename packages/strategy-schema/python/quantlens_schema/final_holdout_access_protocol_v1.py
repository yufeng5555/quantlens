"""Neutral Gate E Stop B3a final-holdout access protocol byte law.

This module owns the public, implementation-neutral half of the
``final-holdout-access-v1`` protocol: the frozen domain separators, identifiers,
roles, routes, body versions, ID grammars and status/code/message law; closed
fail-closed validators and canonical bytes for the client and authority public
trust bundles, signed client requests, signed service responses and their exact
response wrappers, the two B3a registration bodies and success bodies, the generic
error body, the derived capsule payload, the exact closed capsule AAD object and
its domain-prefixed AAD bytes; and the accepted Stop A
``final-holdout-access-audit-v1`` schema/cross-field/time law, moved here without
changing one byte of accepted mapping behavior, plus canonical unsigned and signed
audit byte helpers under the frozen audit domain.

The independent final-holdout authority and the dormant worker wrapper share these
exact bytes without sharing an implementation package: this module imports only the
standard library, ``jsonschema``, the neutral ``plan_anchor_protocol_v1`` and the
neutral ``market_observation_protocol_v2``.  It imports no worker, authority, API,
producer, network, clock, cryptography, random, filesystem-data or private-key
code, reads only sealed schema bytes, exposes no crypto verify, clock, random ID,
AES, database or service helper, and is not re-exported through
``quantlens_schema.__init__``.  Validation always happens before canonicalization;
public helpers return fresh JSON trees and never mutate or alias caller input.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import jsonschema

from quantlens_schema.market_observation_protocol_v2 import (
    MarketObservationCanonicalizationError,
    canonical_market_observations_v2_bytes,
    canonicalize_market_observations_v2,
)
from quantlens_schema.plan_anchor_protocol_v1 import (
    CONTROL_PLANE_REGISTRAR_ROLE,
    PlanAnchorProtocolError,
    canonical_signed_anchor_bytes,
    canonical_unsigned_registration_receipt_bytes,
    validate_complete_validation_plan_v3,
)


class FinalHoldoutAccessProtocolError(ValueError):
    """One candidate value violates the frozen final-holdout access protocol law."""


# ------------------------------------------------------------------ frozen domains
# Distinct ASCII domain separators, each terminated by one NUL byte.  The NUL byte
# is appended explicitly so no escape sequence appears in source.  The capsule-AAD
# domain is deliberately a non-signature domain.

FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1 = (
    b"QuantLens.final-holdout-client-request-v1" + bytes([0])
)
FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1 = (
    b"QuantLens.final-holdout-service-response-v1" + bytes([0])
)
FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1 = (
    b"QuantLens.final-holdout-access-audit-v1" + bytes([0])
)
FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1 = (
    b"QuantLens.final-holdout-capsule-aad-v1" + bytes([0])
)

# -------------------------------------------------------------- frozen identifiers

FINAL_HOLDOUT_ACCESS_PROTOCOL = "final-holdout-access-v1"
FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1 = "final-holdout-capsule-payload-v1"
FINAL_HOLDOUT_CAPSULE_AAD_VERSION_V1 = "final-holdout-capsule-aad-v1"
FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1 = (
    "final-holdout-capsule-registration-body-v1"
)
FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1 = (
    "final-holdout-anchor-registration-body-v1"
)
FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1 = "final-holdout-lease-request-body-v1"
FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1 = (
    "final-holdout-consume-request-body-v1"
)
FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1 = (
    "final-holdout-completion-request-body-v1"
)
FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1 = (
    "final-holdout-audit-retrieval-body-v1"
)
FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1 = "final-holdout-client-request-v1"
FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1 = "final-holdout-service-response-v1"
FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-capsule-registration-response-body-v1"
)
FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-anchor-registration-response-body-v1"
)
FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1 = "final-holdout-error-response-body-v1"
FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1 = "final-holdout-lease-response-body-v1"
FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-consume-response-body-v1"
)
FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-lease-denial-response-body-v1"
)
FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-terminal-audit-response-body-v1"
)
FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1 = (
    "final-holdout-audit-pending-response-body-v1"
)
FINAL_HOLDOUT_CLIENT_PUBLIC_KEYS_VERSION_V1 = "final-holdout-client-public-keys-v1"
FINAL_HOLDOUT_AUTHORITY_PUBLIC_KEYS_VERSION_V1 = (
    "final-holdout-authority-public-keys-v1"
)
FINAL_HOLDOUT_ACCESS_AUDIT_VERSION_V1 = "final-holdout-access-audit-v1"

FINAL_EVALUATOR_ROLE = "FINAL_EVALUATOR"
FINAL_HOLDOUT_CLIENT_ROLES = (CONTROL_PLANE_REGISTRAR_ROLE, FINAL_EVALUATOR_ROLE)

# ------------------------------------------------------------------ frozen routes

FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1 = "/v1/final-holdout-capsules"
FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1 = "/v1/final-holdout-anchors"
FINAL_HOLDOUT_LEASE_PATH_V1 = "/v1/final-holdout-leases"
FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1 = "/v1/final-holdout-leases/{lease_id}/consume"
FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1 = (
    "/v1/final-holdout-leases/{lease_id}/complete"
)
FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1 = (
    "/v1/final-holdout-audits/{lease_id}/retrieve"
)

# --------------------------------------------------------------- frozen size caps

MAX_CAPSULE_REGISTRATION_BODY_BYTES = 16_777_216
MAX_CLIENT_REQUEST_BODY_BYTES = 1_048_576

# ------------------------------------------------------- frozen status/code law

FINAL_HOLDOUT_ERROR_STATUS_MESSAGES: dict[int, str] = {
    400: "The request is invalid.",
    401: "Authentication failed.",
    403: "The operation is not permitted.",
    409: "The request conflicts with durable authority state.",
    410: "The requested authority state is no longer available.",
    503: "The authority is unavailable.",
}

# The only status/code pairs a B3a signed result may carry.
FINAL_HOLDOUT_B3A_STATUS_CODES: tuple[tuple[int, str], ...] = (
    (200, "CAPSULE_REGISTERED"),
    (200, "ANCHOR_REGISTERED"),
    (400, "INVALID_REQUEST"),
    (401, "AUTHENTICATION_FAILED"),
    (403, "ROLE_NOT_PERMITTED"),
    (409, "REQUEST_ID_CONFLICT"),
    (409, "NONCE_REPLAY"),
    (409, "RUN_ALREADY_REGISTERED"),
    (409, "CAPSULE_ALREADY_BOUND"),
    (409, "ANCHOR_ALREADY_REGISTERED"),
    (409, "IDENTIFIER_COLLISION"),
    (409, "BINDING_MISMATCH"),
    (410, "ANCHOR_EXPIRED"),
    (503, "AUTHORITY_UNAVAILABLE"),
)

# Closed codes and body versions reserved now for B3b; no B3a validator emits them.
FINAL_HOLDOUT_B3B_RESERVED_STATUS_CODES: tuple[tuple[int, str, str], ...] = (
    (200, "LEASE_ISSUED", FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1),
    (200, "PLAINTEXT_RELEASED", FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1),
    (200, "EVALUATION_COMPLETED",
     FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1),
    (200, "TERMINAL_AUDIT_RETURNED",
     FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1),
    (202, "AUDIT_PENDING", FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1),
    (409, "LEASE_ALREADY_EXISTS",
     FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1),
    (409, "LEASE_STATE_CONFLICT", FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1),
    (409, "COMPLETION_STATE_CONFLICT", FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1),
    (410, "ANCHOR_EXPIRED", FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1),
    (410, "LEASE_EXPIRED", FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1),
    (410, "PLAINTEXT_ALREADY_RELEASED",
     FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1),
    (503, "AUTHORITY_UNAVAILABLE", FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1),
)

# Transport failures before a complete closed request use only these unsigned
# bodies; they reflect no request value.  The 503 body is the sole post-parse
# unsigned application response, emitted only on signer failure.
FINAL_HOLDOUT_UNSIGNED_TRANSPORT_BODIES: dict[int, dict[str, str]] = {
    400: {"code": "INVALID_REQUEST"},
    403: {"code": "LOOPBACK_REQUIRED"},
    404: {"code": "NOT_FOUND"},
    405: {"code": "METHOD_NOT_ALLOWED"},
    413: {"code": "PAYLOAD_TOO_LARGE"},
    503: {"code": "AUTHORITY_UNAVAILABLE"},
}

# ---------------------------------------------------------------- frozen grammars

_SHA256_PREFIX = "sha256:"
_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REQUEST_ID_RE = re.compile(r"^fha-req-[0-9a-f]{32}$")
_CAPSULE_ID_RE = re.compile(r"^fha-cap-[0-9a-f]{32}$")
_LEASE_ID_RE = re.compile(r"^fha-lease-[0-9a-f]{32}$")
_ANCHOR_ID_RE = re.compile(r"^vpa-[0-9a-f]{32}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_AES_NONCE_RE = re.compile(r"^[0-9a-f]{24}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_PUBLIC_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX_RE = re.compile(r"^[0-9a-f]+$")
_ERROR_CODE_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_PATH_RE = re.compile(r"^/[\x21-\x7e]*$")

# The registered bytes of one signed anchor or receipt are small canonical JSON
# documents; a bounded decode keeps a hostile hex field from allocating without
# limit before validation.
_MAX_REGISTERED_BYTES_HEX_CHARS = 262_144

_FROZEN_ROUTE_PATTERNS = (
    re.compile(r"^/v1/final-holdout-capsules$"),
    re.compile(r"^/v1/final-holdout-anchors$"),
    re.compile(r"^/v1/final-holdout-leases$"),
    re.compile(r"^/v1/final-holdout-leases/fha-lease-[0-9a-f]{32}/consume$"),
    re.compile(r"^/v1/final-holdout-leases/fha-lease-[0-9a-f]{32}/complete$"),
    re.compile(r"^/v1/final-holdout-audits/fha-lease-[0-9a-f]{32}/retrieve$"),
)

_CLIENT_REQUEST_FIELDS = (
    "request_version",
    "request_id",
    "authority_id",
    "caller_role",
    "caller_key_id",
    "method",
    "path",
    "timestamp",
    "nonce",
    "body_sha256",
    "signature_algorithm",
    "signature",
)
_SERVICE_RESPONSE_FIELDS = (
    "response_version",
    "authority_id",
    "authority_key_id",
    "status_code",
    "request_id",
    "request_nonce",
    "timestamp",
    "body_sha256",
    "signature_algorithm",
    "signature",
)
_RESPONSE_WRAPPER_FIELDS = ("service_response", "body")
_CLIENT_WRAPPER_FIELDS = ("client_request", "body")
_TRUST_BUNDLE_FIELDS = ("bundle_version", "authority_id", "keys")
_CLIENT_KEY_FIELDS = (
    "key_id", "role", "algorithm", "status", "public_key_hex",
    "not_before", "not_after",
)
_AUTHORITY_KEY_FIELDS = (
    "key_id", "algorithm", "status", "public_key_hex", "not_before", "not_after",
)
_KEY_STATUSES = ("active", "inactive")
_RESPONSE_STATUS_CODES = (200, 202, 400, 401, 403, 409, 410, 503)

_CAPSULE_REGISTRATION_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "validation_plan",
    "primary_observations",
)
_ANCHOR_REGISTRATION_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "capsule_id",
    "anchor",
    "registered_signed_anchor_bytes_hex",
    "registration_receipt",
    "registered_signed_receipt_bytes_hex",
)
_CAPSULE_PAYLOAD_FIELDS = (
    "payload_version",
    "access_protocol",
    "evaluation_start_offset",
    "primary_observations",
    "benchmark_observations",
)
_CAPSULE_AAD_FIELDS = (
    "aad_version",
    "access_protocol",
    "authority_id",
    "capsule_id",
    "payload_encryption_algorithm",
    "payload_encryption_key_id",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "confirmed_spec_hash",
    "primary_snapshot_sha256",
    "benchmark_snapshot_sha256",
    "validation_plan_hash",
    "complete_validation_plan_sha256",
    "locked_rule_sha256",
    "base_costs_sha256",
    "final_window",
    "primary_observations_sha256",
    "benchmark_observations_sha256",
    "capsule_payload_sha256",
)
_FINAL_WINDOW_FIELDS = (
    "n_bars", "start_index", "end_index", "bars",
    "warmup_start_index", "warmup_bars",
)
_CAPSULE_RESPONSE_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "capsule_id",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "validation_plan_hash",
    "complete_validation_plan_sha256",
    "capsule_payload_sha256",
    "primary_observations_sha256",
    "benchmark_observations_sha256",
    "registered_at",
    "state",
)
_ANCHOR_RESPONSE_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "capsule_id",
    "anchor_id",
    "anchor_sha256",
    "registration_receipt_sha256",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "registered_at",
    "anchor_expires_at",
    "state",
)
_ERROR_RESPONSE_BODY_FIELDS = ("body_version", "code", "message", "request_id")

_RELEASE_ID_V3 = "quantlens-financial-v3"

FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE = "final-holdout-access-audit-v1.json"
_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schema"
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def _reject(message: str) -> None:
    raise FinalHoldoutAccessProtocolError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def canonical_json_bytes(value: object) -> bytes:
    """Frozen canonical JSON: sorted keys, compact separators, ASCII, finite only."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FinalHoldoutAccessProtocolError(
            "final-holdout access protocol values must be finite canonical JSON"
        ) from exc


def _sha256_prefixed(payload: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(payload).hexdigest()


def _fresh_json_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    decoded = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    if not isinstance(decoded, dict):
        _reject(f"{label} must be a JSON object")
    assert isinstance(decoded, dict)
    return decoded


def _closed_fields(
    candidate: Mapping[str, Any], fields: tuple[str, ...], label: str
) -> None:
    keys = set(candidate)
    expected = set(fields)
    if keys != expected:
        missing = sorted(expected - keys)
        surplus = sorted(str(key) for key in keys - expected)
        _reject(
            f"{label} must have exactly the sealed fields"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; unknown: {', '.join(surplus)}" if surplus else "")
        )


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        _reject(f"{label} must be a printable-ASCII identity of at most 128 characters")
    assert isinstance(value, str)
    return value


def _prefixed_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _PREFIXED_SHA256_RE.fullmatch(value) is None:
        _reject(f"{label} must be sha256: plus 64 lowercase hex characters")
    assert isinstance(value, str)
    return value


def _utc_second(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        _reject(f"{label} must be a whole-second UTC timestamp")
    assert isinstance(value, str)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise FinalHoldoutAccessProtocolError(
            f"{label} is not a real UTC instant"
        ) from exc


def _pattern(value: object, pattern: re.Pattern[str], label: str, law: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _reject(f"{label} must match {law}")
    assert isinstance(value, str)
    return value


def _neutral_market(step):
    try:
        return step()
    except MarketObservationCanonicalizationError as exc:
        raise FinalHoldoutAccessProtocolError(str(exc)) from exc


def _neutral_anchor(step):
    try:
        return step()
    except PlanAnchorProtocolError as exc:
        raise FinalHoldoutAccessProtocolError(str(exc)) from exc


# --------------------------------------------------------------- trust bundles


def _validated_trust_bundle(
    bundle: object,
    *,
    bundle_version: str,
    key_fields: tuple[str, ...],
    with_role: bool,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    tree = _fresh_json_object(bundle, label)
    _closed_fields(tree, _TRUST_BUNDLE_FIELDS, label)
    _require(
        tree["bundle_version"] == bundle_version,
        f"{label} version must be " + bundle_version,
    )
    _identity(tree["authority_id"], f"{label} authority_id")
    keys = tree["keys"]
    if not isinstance(keys, list) or not keys:
        _reject(f"{label} must list at least one key")
    previous_sort_key: tuple[str, ...] | None = None
    seen_key_ids: set[str] = set()
    seen_public_keys: set[str] = set()
    for index, entry in enumerate(keys):
        entry_label = f"{label} key[{index}]"
        if not isinstance(entry, dict) or set(entry) != set(key_fields):
            _reject(
                f"{entry_label} must have exactly these keys: "
                + ", ".join(key_fields)
            )
        key_id = _identity(entry["key_id"], f"{entry_label}.key_id")
        if with_role:
            _require(
                entry["role"] in FINAL_HOLDOUT_CLIENT_ROLES,
                f"{entry_label}.role must be one of the two frozen client roles",
            )
        _require(
            entry["algorithm"] == "ed25519",
            f"{entry_label}.algorithm is pinned to ed25519",
        )
        _require(
            entry["status"] in _KEY_STATUSES,
            f"{entry_label}.status must be active or inactive",
        )
        public_key_hex = entry["public_key_hex"]
        if not isinstance(public_key_hex, str) or \
                _PUBLIC_KEY_HEX_RE.fullmatch(public_key_hex) is None:
            _reject(f"{entry_label}.public_key_hex must be 64 lowercase hex characters")
        _require(
            len(bytes.fromhex(public_key_hex)) == 32,
            f"{entry_label}.public_key_hex must decode to exactly 32 bytes",
        )
        not_before = _utc_second(entry["not_before"], f"{entry_label}.not_before")
        not_after = _utc_second(entry["not_after"], f"{entry_label}.not_after")
        _require(
            not_before < not_after,
            f"{entry_label} validity interval must satisfy not_before < not_after",
        )
        sort_key = (entry["role"], key_id) if with_role else (key_id,)
        _require(
            previous_sort_key is None or sort_key > previous_sort_key,
            f"{label} keys must be strictly sorted by "
            + ("(role, key_id)" if with_role else "key_id"),
        )
        previous_sort_key = sort_key
        _require(key_id not in seen_key_ids, f"{label} key ids must be unique")
        seen_key_ids.add(key_id)
        _require(
            public_key_hex not in seen_public_keys,
            f"{label} public-key bytes must be unique",
        )
        seen_public_keys.add(public_key_hex)
    return tree, canonical_json_bytes(tree)


def validate_final_holdout_client_trust_bundle_v1(bundle: object) -> dict[str, Any]:
    """Validate the closed client public trust bundle; returns a fresh tree."""
    tree, _payload = _validated_trust_bundle(
        bundle,
        bundle_version=FINAL_HOLDOUT_CLIENT_PUBLIC_KEYS_VERSION_V1,
        key_fields=_CLIENT_KEY_FIELDS,
        with_role=True,
        label="final-holdout client trust bundle",
    )
    return tree


def canonical_final_holdout_client_trust_bundle_bytes(bundle: object) -> bytes:
    _tree, payload = _validated_trust_bundle(
        bundle,
        bundle_version=FINAL_HOLDOUT_CLIENT_PUBLIC_KEYS_VERSION_V1,
        key_fields=_CLIENT_KEY_FIELDS,
        with_role=True,
        label="final-holdout client trust bundle",
    )
    return payload


def final_holdout_client_trust_bundle_hash(bundle: object) -> str:
    """``sha256:`` plus SHA-256 of the canonical client trust bundle bytes."""
    return _sha256_prefixed(
        canonical_final_holdout_client_trust_bundle_bytes(bundle))


def validate_final_holdout_authority_trust_bundle_v1(bundle: object) -> dict[str, Any]:
    """Validate the closed authority public trust bundle; returns a fresh tree."""
    tree, _payload = _validated_trust_bundle(
        bundle,
        bundle_version=FINAL_HOLDOUT_AUTHORITY_PUBLIC_KEYS_VERSION_V1,
        key_fields=_AUTHORITY_KEY_FIELDS,
        with_role=False,
        label="final-holdout authority trust bundle",
    )
    return tree


def canonical_final_holdout_authority_trust_bundle_bytes(bundle: object) -> bytes:
    _tree, payload = _validated_trust_bundle(
        bundle,
        bundle_version=FINAL_HOLDOUT_AUTHORITY_PUBLIC_KEYS_VERSION_V1,
        key_fields=_AUTHORITY_KEY_FIELDS,
        with_role=False,
        label="final-holdout authority trust bundle",
    )
    return payload


def final_holdout_authority_trust_bundle_hash(bundle: object) -> str:
    """``sha256:`` plus SHA-256 of the canonical authority trust bundle bytes."""
    return _sha256_prefixed(
        canonical_final_holdout_authority_trust_bundle_bytes(bundle))


# ------------------------------------------------------------- client requests


def validate_final_holdout_client_request_v1(request: object) -> dict[str, Any]:
    """Fail-closed validation of one closed signed client request envelope.

    Version, method, roles, algorithm and route grammar are exact constants;
    identities, nonce, hash and signature are never normalized; the timestamp must
    be a real whole-second UTC instant; the path must be one exact frozen route
    with no query string.  Returns a fresh plain JSON tree.
    """
    candidate = _fresh_json_object(request, "final-holdout client request")
    _closed_fields(candidate, _CLIENT_REQUEST_FIELDS, "final-holdout client request")
    _require(
        candidate["request_version"] == FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
        "client request version must be " + FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
    )
    _pattern(
        candidate["request_id"], _REQUEST_ID_RE,
        "client request request_id", "fha-req- plus 32 lowercase hex",
    )
    _identity(candidate["authority_id"], "client request authority_id")
    _require(
        candidate["caller_role"] in FINAL_HOLDOUT_CLIENT_ROLES,
        "client request caller_role must be one of the two frozen client roles",
    )
    _identity(candidate["caller_key_id"], "client request caller_key_id")
    _require(candidate["method"] == "POST", "client request method is pinned to POST")
    path = candidate["path"]
    if not isinstance(path, str) or _PATH_RE.fullmatch(path) is None \
            or "?" in path or "#" in path:
        _reject("client request path must be a frozen route with no query string")
    assert isinstance(path, str)
    _require(
        any(pattern.fullmatch(path) is not None
            for pattern in _FROZEN_ROUTE_PATTERNS),
        "client request path is not one of the frozen final-holdout routes",
    )
    _utc_second(candidate["timestamp"], "client request timestamp")
    _pattern(
        candidate["nonce"], _NONCE_RE,
        "client request nonce", "32 lowercase hex characters",
    )
    _prefixed_sha256(candidate["body_sha256"], "client request body_sha256")
    _require(
        candidate["signature_algorithm"] == "ed25519",
        "client request signature algorithm is pinned to ed25519",
    )
    _pattern(
        candidate["signature"], _SIGNATURE_RE,
        "client request signature", "128 lowercase hex characters",
    )
    return candidate


def canonical_unsigned_final_holdout_client_request_bytes(request: object) -> bytes:
    """Canonical bytes of the closed request with only ``signature`` removed.

    Client signatures cover ``FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1`` plus
    exactly these bytes.
    """
    candidate = validate_final_holdout_client_request_v1(request)
    del candidate["signature"]
    return canonical_json_bytes(candidate)


def canonical_signed_final_holdout_client_request_bytes(request: object) -> bytes:
    """Canonical bytes of the complete closed signed request, no domain prefix."""
    return canonical_json_bytes(validate_final_holdout_client_request_v1(request))


# ----------------------------------------------------------- service responses


def validate_final_holdout_service_response_v1(response: object) -> dict[str, Any]:
    """Fail-closed validation of one closed signed service response envelope."""
    candidate = _fresh_json_object(response, "final-holdout service response")
    _closed_fields(
        candidate, _SERVICE_RESPONSE_FIELDS, "final-holdout service response")
    _require(
        candidate["response_version"] == FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1,
        "service response version must be "
        + FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1,
    )
    _identity(candidate["authority_id"], "service response authority_id")
    _identity(candidate["authority_key_id"], "service response authority_key_id")
    status = candidate["status_code"]
    if isinstance(status, bool) or status not in _RESPONSE_STATUS_CODES:
        _reject("service response status_code is outside the frozen status law")
    _pattern(
        candidate["request_id"], _REQUEST_ID_RE,
        "service response request_id", "fha-req- plus 32 lowercase hex",
    )
    _pattern(
        candidate["request_nonce"], _NONCE_RE,
        "service response request_nonce", "32 lowercase hex characters",
    )
    _utc_second(candidate["timestamp"], "service response timestamp")
    _prefixed_sha256(candidate["body_sha256"], "service response body_sha256")
    _require(
        candidate["signature_algorithm"] == "ed25519",
        "service response signature algorithm is pinned to ed25519",
    )
    _pattern(
        candidate["signature"], _SIGNATURE_RE,
        "service response signature", "128 lowercase hex characters",
    )
    return candidate


def canonical_unsigned_final_holdout_service_response_bytes(
    response: object,
) -> bytes:
    """Canonical bytes of the closed response with only ``signature`` removed.

    Response signatures cover ``FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1`` plus
    exactly these bytes.
    """
    candidate = validate_final_holdout_service_response_v1(response)
    del candidate["signature"]
    return canonical_json_bytes(candidate)


def canonical_signed_final_holdout_service_response_bytes(
    response: object,
) -> bytes:
    """Canonical bytes of the complete closed signed response, no domain prefix."""
    return canonical_json_bytes(
        validate_final_holdout_service_response_v1(response))


# ------------------------------------------------------------- response bodies


def validate_final_holdout_capsule_registration_response_body_v1(
    body: object,
) -> dict[str, Any]:
    """Validate the exact closed CAPSULE_REGISTERED success body."""
    candidate = _fresh_json_object(body, "capsule registration response body")
    _closed_fields(
        candidate, _CAPSULE_RESPONSE_BODY_FIELDS,
        "capsule registration response body",
    )
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1,
        "capsule registration response body version must be "
        + FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1,
    )
    _require(
        candidate["code"] == "CAPSULE_REGISTERED",
        "capsule registration response code must be CAPSULE_REGISTERED",
    )
    _pattern(
        candidate["request_id"], _REQUEST_ID_RE,
        "capsule registration response request_id",
        "fha-req- plus 32 lowercase hex",
    )
    _pattern(
        candidate["capsule_id"], _CAPSULE_ID_RE,
        "capsule registration response capsule_id",
        "fha-cap- plus 32 lowercase hex",
    )
    _require(
        candidate["release_id"] == _RELEASE_ID_V3,
        "capsule registration response release must be " + _RELEASE_ID_V3,
    )
    for field in ("tenant_id", "workspace_id", "run_id"):
        _identity(candidate[field], f"capsule registration response {field}")
    for field in (
        "validation_plan_hash",
        "complete_validation_plan_sha256",
        "capsule_payload_sha256",
        "primary_observations_sha256",
        "benchmark_observations_sha256",
    ):
        _prefixed_sha256(candidate[field], f"capsule registration response {field}")
    _require(
        candidate["benchmark_observations_sha256"]
        == candidate["primary_observations_sha256"],
        "capsule registration response benchmark hash must equal the primary hash",
    )
    _utc_second(candidate["registered_at"], "capsule registration registered_at")
    _require(
        candidate["state"] == "REGISTERED",
        "capsule registration response state must be REGISTERED",
    )
    return candidate


def validate_final_holdout_anchor_registration_response_body_v1(
    body: object,
) -> dict[str, Any]:
    """Validate the exact closed ANCHOR_REGISTERED success body."""
    candidate = _fresh_json_object(body, "anchor registration response body")
    _closed_fields(
        candidate, _ANCHOR_RESPONSE_BODY_FIELDS,
        "anchor registration response body",
    )
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1,
        "anchor registration response body version must be "
        + FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1,
    )
    _require(
        candidate["code"] == "ANCHOR_REGISTERED",
        "anchor registration response code must be ANCHOR_REGISTERED",
    )
    _pattern(
        candidate["request_id"], _REQUEST_ID_RE,
        "anchor registration response request_id", "fha-req- plus 32 lowercase hex",
    )
    _pattern(
        candidate["capsule_id"], _CAPSULE_ID_RE,
        "anchor registration response capsule_id", "fha-cap- plus 32 lowercase hex",
    )
    _pattern(
        candidate["anchor_id"], _ANCHOR_ID_RE,
        "anchor registration response anchor_id", "vpa- plus 32 lowercase hex",
    )
    for field in ("anchor_sha256", "registration_receipt_sha256"):
        _prefixed_sha256(candidate[field], f"anchor registration response {field}")
    _require(
        candidate["release_id"] == _RELEASE_ID_V3,
        "anchor registration response release must be " + _RELEASE_ID_V3,
    )
    for field in ("tenant_id", "workspace_id", "run_id"):
        _identity(candidate[field], f"anchor registration response {field}")
    registered_at = _utc_second(
        candidate["registered_at"], "anchor registration registered_at")
    expires_at = _utc_second(
        candidate["anchor_expires_at"], "anchor registration anchor_expires_at")
    _require(
        registered_at < expires_at,
        "anchor registration must precede the anchor expiry",
    )
    _require(
        candidate["state"] == "REGISTERED",
        "anchor registration response state must be REGISTERED",
    )
    return candidate


def validate_final_holdout_error_response_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed generic signed error body."""
    candidate = _fresh_json_object(body, "final-holdout error response body")
    _closed_fields(
        candidate, _ERROR_RESPONSE_BODY_FIELDS, "final-holdout error response body")
    _require(
        candidate["body_version"] == FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1,
        "error response body version must be "
        + FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1,
    )
    code = candidate["code"]
    if not isinstance(code, str) or _ERROR_CODE_RE.fullmatch(code) is None:
        _reject("error response code must be a frozen uppercase code")
    message = candidate["message"]
    _require(
        isinstance(message, str)
        and message in FINAL_HOLDOUT_ERROR_STATUS_MESSAGES.values(),
        "error response message must be one exact status-fixed generic message",
    )
    _pattern(
        candidate["request_id"], _REQUEST_ID_RE,
        "error response request_id", "fha-req- plus 32 lowercase hex",
    )
    return candidate


_BODY_VALIDATORS = {
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1:
        validate_final_holdout_capsule_registration_response_body_v1,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1:
        validate_final_holdout_anchor_registration_response_body_v1,
    FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1:
        validate_final_holdout_error_response_body_v1,
    FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1:
        lambda body: validate_final_holdout_lease_response_body_v1(body),
    FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1:
        lambda body: validate_final_holdout_consume_response_body_v1(body),
    FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1:
        lambda body: validate_final_holdout_lease_denial_response_body_v1(body),
    FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1:
        lambda body: validate_final_holdout_terminal_audit_response_body_v1(body),
    FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1:
        lambda body: validate_final_holdout_audit_pending_response_body_v1(body),
}

# The frozen (status_code, code, body_version) triple law.  B3a success codes
# bind their registration response versions; every B3a error code (including
# 410 ANCHOR_EXPIRED) binds the generic error response version; B3b binds
# exactly to its reserved triples.  Validating the triple before any status
# message lookup makes a malformed 200 generic-error wrapper fail closed as a
# FinalHoldoutAccessProtocolError, never a raw KeyError.
_B3A_SUCCESS_TRIPLES = (
    (200, "CAPSULE_REGISTERED",
     FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1),
    (200, "ANCHOR_REGISTERED",
     FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1),
)
_B3A_ERROR_TRIPLES = tuple(
    (status, code, FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1)
    for status, code in FINAL_HOLDOUT_B3A_STATUS_CODES
    if (status, code) not in {
        (200, "CAPSULE_REGISTERED"), (200, "ANCHOR_REGISTERED")}
)
_COMBINED_STATUS_TRIPLE_SET = frozenset(
    _B3A_SUCCESS_TRIPLES + _B3A_ERROR_TRIPLES
    + tuple(FINAL_HOLDOUT_B3B_RESERVED_STATUS_CODES)
)

# Registration-success bodies whose registered_at binds the response timestamp.
_REGISTRATION_RESPONSE_VERSIONS = (
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1,
)


def validate_final_holdout_response_wrapper_v1(wrapper: object) -> dict[str, Any]:
    """Validate one complete signed response wrapper against the combined law.

    The wrapper has exactly ``service_response`` and ``body``; the response body
    hash must bind the canonical body bytes; the status/code pair must be one of
    the frozen B3a+B3b pairs; the body request id must equal the envelope; and
    each body version binds its version-specific timestamp/state cross-fields.
    B3a accepted bytes are unchanged: registration and error bodies validate
    exactly as before.
    """
    candidate = _fresh_json_object(wrapper, "final-holdout response wrapper")
    _closed_fields(
        candidate, _RESPONSE_WRAPPER_FIELDS, "final-holdout response wrapper")
    response = validate_final_holdout_service_response_v1(
        candidate["service_response"])
    body = candidate["body"]
    if not isinstance(body, dict) or not isinstance(body.get("body_version"), str):
        _reject("final-holdout response wrapper body must carry a frozen body version")
    assert isinstance(body, dict)
    validator = _BODY_VALIDATORS.get(body["body_version"])
    if validator is None:
        _reject("final-holdout response wrapper body version is not a known body")
    assert validator is not None
    valid_body = validator(body)
    body_bytes = canonical_json_bytes(valid_body)
    _require(
        response["body_sha256"] == _sha256_prefixed(body_bytes),
        "service response body hash does not bind the wrapper body",
    )
    status = response["status_code"]
    code = valid_body["code"]
    version = valid_body["body_version"]
    # The complete (status_code, code, body_version) triple is enforced BEFORE
    # any status-message lookup, so a malformed 200 generic-error wrapper (or a
    # generic 409/200 code paired with the wrong body version) fails closed
    # here rather than raising a raw KeyError downstream.
    _require(
        (status, code, version) in _COMBINED_STATUS_TRIPLE_SET,
        "response (status_code, code, body_version) triple is outside the "
        "frozen B3a+B3b status law",
    )
    _require(
        valid_body["request_id"] == response["request_id"],
        "wrapper body request id must equal the signed envelope request id",
    )
    timestamp = response["timestamp"]
    if version == FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1:
        _require(
            valid_body["message"] == FINAL_HOLDOUT_ERROR_STATUS_MESSAGES[status],
            "error body message must be the exact generic message for its status",
        )
    elif version in _REGISTRATION_RESPONSE_VERSIONS:
        _require(status == 200, "registration success bodies use HTTP 200 exactly")
        _require(
            valid_body["registered_at"] == timestamp,
            "registration registered_at must equal the response timestamp",
        )
    elif version == FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1:
        _require(status == 200, "lease success uses HTTP 200 exactly")
        _require(
            valid_body["issued_at"] == timestamp,
            "lease issued_at must equal the response timestamp",
        )
    elif version == FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1:
        _require(status == 200, "consume success uses HTTP 200 exactly")
        _require(
            valid_body["consumed_at"] == timestamp,
            "consume consumed_at must equal the response timestamp",
        )
    elif version == FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1:
        # A lease denial's audit decided_at binds the response timestamp; the
        # audit request id equals the lease request, i.e. the body request id.
        audit = validate_final_holdout_access_audit_v1(valid_body["terminal_audit"])
        _require(
            audit["decided_at"] == timestamp,
            "lease denial audit decided_at must equal the response timestamp",
        )
    elif version == FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1:
        _require(status == 200, "terminal audit uses HTTP 200 exactly")
        # The body request id (completion/retrieval) already binds the envelope;
        # the embedded audit request id is the original lease request and is
        # deliberately NOT bound to the current envelope request id here.
    elif version == FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1:
        _require(status == 202, "audit pending uses HTTP 202 exactly")
    return {"service_response": response, "body": valid_body}


def canonical_final_holdout_response_wrapper_bytes(wrapper: object) -> bytes:
    """Canonical JSON bytes of the complete valid signed response wrapper."""
    return canonical_json_bytes(validate_final_holdout_response_wrapper_v1(wrapper))


# ------------------------------------------------------ capsule registration law


def _one_instrument_document(observations: object, label: str) -> dict[str, Any]:
    canonical = _neutral_market(
        lambda: canonicalize_market_observations_v2(observations))
    _require(
        len(canonical["instruments"]) == 1,
        f"{label} must contain exactly one instrument",
    )
    return canonical


def _validated_plan_for_capsule(validation_plan: object) -> dict[str, Any]:
    plan = _neutral_anchor(
        lambda: validate_complete_validation_plan_v3(validation_plan))
    _require(
        plan["final_access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "validation plan final access protocol must be "
        + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    authorities = plan["authorities"]
    _identity(authorities["holdout_authority_id"], "plan holdout_authority_id")
    _identity(authorities["holdout_authority_key_id"], "plan holdout_authority_key_id")
    _require(
        plan["production_capabilities"] == {
            "external_anchor_ready": True,
            "external_holdout_ready": True,
            "unconfigured_behavior": "fail_closed",
        },
        "validation plan production capability state must be exactly the frozen "
        "fail-closed configuration",
    )
    return plan


def validate_final_holdout_capsule_registration_body_v1(
    body: object,
) -> dict[str, Any]:
    """Fail-closed validation and derivation of one capsule registration body.

    Validates the complete plan through the neutral plan law, canonicalizes the
    single submitted primary instrument under the shared market law, requires its
    snapshot/calendar identity to equal the plan, derives the frozen DSL 1.2
    same-as-universe benchmark as a fresh canonical-identical copy of primary,
    requires the exact ``warmup_bars + final_window.bars`` session count, derives
    ``evaluation_start_offset`` and the complete closed payload, and returns fresh
    validated trees plus canonical hashes.  No caller-provided benchmark, payload,
    offset, capsule ID or summary hash is accepted.
    """
    candidate = _fresh_json_object(body, "capsule registration body")
    _closed_fields(
        candidate, _CAPSULE_REGISTRATION_BODY_FIELDS, "capsule registration body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
        "capsule registration body version must be "
        + FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
    )
    _require(
        candidate["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "capsule registration access protocol must be "
        + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    plan = _validated_plan_for_capsule(candidate["validation_plan"])
    primary = _one_instrument_document(
        candidate["primary_observations"], "primary observations")
    _require(
        primary["snapshot_sha256"] == plan["snapshot_sha256"],
        "primary observations snapshot must equal the plan snapshot",
    )
    _require(
        primary["exchange_calendar_id"] == plan["exchange_calendar_id"],
        "primary observations exchange calendar must equal the plan calendar",
    )
    _require(
        primary["exchange_calendar_version"] == plan["exchange_calendar_version"],
        "primary observations calendar version must equal the plan calendar version",
    )
    window = plan["final_window"]
    expected_sessions = window["warmup_bars"] + window["bars"]
    _require(
        len(primary["instruments"][0]["sessions"]) == expected_sessions,
        "primary observations must contain exactly the reviewed warm-up plus "
        "final evaluation suffix",
    )
    evaluation_start_offset = window["start_index"] - window["warmup_start_index"]
    _require(
        evaluation_start_offset == window["warmup_bars"],
        "evaluation offset must equal the plan warm-up span",
    )
    # The frozen DSL 1.2 benchmark is derived, canonical-identical to primary:
    # hold_from_first_decision on same_as_universe admits no second dataset.
    benchmark = json.loads(canonical_json_bytes(primary).decode("utf-8"))
    primary_bytes = _neutral_market(
        lambda: canonical_market_observations_v2_bytes(primary))
    benchmark_bytes = _neutral_market(
        lambda: canonical_market_observations_v2_bytes(benchmark))
    _require(
        benchmark_bytes == primary_bytes
        and benchmark["instruments"][0]["symbol"]
        == primary["instruments"][0]["symbol"]
        and benchmark["instruments"][0]["currency"]
        == primary["instruments"][0]["currency"]
        and benchmark["snapshot_sha256"] == primary["snapshot_sha256"],
        "derived benchmark must be canonical-identical to the primary observations",
    )
    observations_hash = _sha256_prefixed(primary_bytes)
    payload = {
        "payload_version": FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
        "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "evaluation_start_offset": evaluation_start_offset,
        "primary_observations": primary,
        "benchmark_observations": benchmark,
    }
    payload_bytes = canonical_json_bytes(payload)
    return {
        "validation_plan": plan,
        "primary_observations": primary,
        "benchmark_observations": benchmark,
        "capsule_payload": json.loads(payload_bytes.decode("utf-8")),
        "evaluation_start_offset": evaluation_start_offset,
        "primary_observations_sha256": observations_hash,
        "benchmark_observations_sha256": observations_hash,
        "capsule_payload_sha256": _sha256_prefixed(payload_bytes),
    }


def canonical_final_holdout_capsule_registration_body_bytes(body: object) -> bytes:
    """Canonical JSON bytes of the valid capsule registration body.

    The observation document canonicalizes under the shared market law before
    hashing, so equivalent supported scalar spellings share one body identity.
    """
    validated = validate_final_holdout_capsule_registration_body_v1(body)
    return canonical_json_bytes({
        "body_version": FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
        "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "validation_plan": validated["validation_plan"],
        "primary_observations": validated["primary_observations"],
    })


def validate_final_holdout_capsule_payload_v1(payload: object) -> dict[str, Any]:
    """Validate the exact closed derived capsule payload; returns a fresh tree."""
    candidate = _fresh_json_object(payload, "final-holdout capsule payload")
    _closed_fields(
        candidate, _CAPSULE_PAYLOAD_FIELDS, "final-holdout capsule payload")
    _require(
        candidate["payload_version"] == FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
        "capsule payload version must be "
        + FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
    )
    _require(
        candidate["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "capsule payload access protocol must be " + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    offset = candidate["evaluation_start_offset"]
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        _reject("capsule payload evaluation offset must be a non-negative integer")
    primary = _one_instrument_document(
        candidate["primary_observations"], "capsule payload primary observations")
    benchmark = _one_instrument_document(
        candidate["benchmark_observations"],
        "capsule payload benchmark observations",
    )
    primary_bytes = _neutral_market(
        lambda: canonical_market_observations_v2_bytes(primary))
    benchmark_bytes = _neutral_market(
        lambda: canonical_market_observations_v2_bytes(benchmark))
    _require(
        benchmark_bytes == primary_bytes,
        "capsule payload benchmark must be canonical-identical to primary under "
        "the frozen same-as-universe law",
    )
    return {
        "payload_version": FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
        "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "evaluation_start_offset": offset,
        "primary_observations": primary,
        "benchmark_observations": benchmark,
    }


def canonical_final_holdout_capsule_payload_bytes(payload: object) -> bytes:
    """Canonical JSON bytes of the complete valid capsule payload."""
    return canonical_json_bytes(validate_final_holdout_capsule_payload_v1(payload))


# ------------------------------------------------------------------ capsule AAD


def validate_final_holdout_capsule_aad_v1(aad: object) -> dict[str, Any]:
    """Validate the exact closed capsule AAD object; returns a fresh tree.

    Under frozen DSL 1.2 the benchmark snapshot and observation hashes must equal
    their primary counterparts, and the six final-window integers must satisfy the
    reviewed window arithmetic exactly.
    """
    candidate = _fresh_json_object(aad, "final-holdout capsule AAD")
    _closed_fields(candidate, _CAPSULE_AAD_FIELDS, "final-holdout capsule AAD")
    _require(
        candidate["aad_version"] == FINAL_HOLDOUT_CAPSULE_AAD_VERSION_V1,
        "capsule AAD version must be " + FINAL_HOLDOUT_CAPSULE_AAD_VERSION_V1,
    )
    _require(
        candidate["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "capsule AAD access protocol must be " + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    _identity(candidate["authority_id"], "capsule AAD authority_id")
    _pattern(
        candidate["capsule_id"], _CAPSULE_ID_RE,
        "capsule AAD capsule_id", "fha-cap- plus 32 lowercase hex",
    )
    _require(
        candidate["payload_encryption_algorithm"] == "aes-256-gcm",
        "capsule AAD encryption algorithm is pinned to aes-256-gcm",
    )
    _identity(
        candidate["payload_encryption_key_id"],
        "capsule AAD payload_encryption_key_id",
    )
    _require(
        candidate["release_id"] == _RELEASE_ID_V3,
        "capsule AAD release must be " + _RELEASE_ID_V3,
    )
    for field in ("tenant_id", "workspace_id", "run_id"):
        _identity(candidate[field], f"capsule AAD {field}")
    for field in (
        "confirmed_spec_hash",
        "primary_snapshot_sha256",
        "benchmark_snapshot_sha256",
        "validation_plan_hash",
        "complete_validation_plan_sha256",
        "locked_rule_sha256",
        "base_costs_sha256",
        "primary_observations_sha256",
        "benchmark_observations_sha256",
        "capsule_payload_sha256",
    ):
        _prefixed_sha256(candidate[field], f"capsule AAD {field}")
    _require(
        candidate["benchmark_snapshot_sha256"]
        == candidate["primary_snapshot_sha256"],
        "capsule AAD benchmark snapshot must equal the primary snapshot under "
        "the frozen same-as-universe law",
    )
    _require(
        candidate["benchmark_observations_sha256"]
        == candidate["primary_observations_sha256"],
        "capsule AAD benchmark observation hash must equal the primary hash under "
        "the frozen same-as-universe law",
    )
    window = candidate["final_window"]
    if not isinstance(window, dict) or set(window) != set(_FINAL_WINDOW_FIELDS):
        _reject(
            "capsule AAD final_window must have exactly these keys: "
            + ", ".join(_FINAL_WINDOW_FIELDS)
        )
    assert isinstance(window, dict)
    for field in _FINAL_WINDOW_FIELDS:
        value = window[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _reject(
                f"capsule AAD final_window.{field} must be a non-negative integer"
            )
    _require(
        window["end_index"] == window["n_bars"],
        "capsule AAD final window must end at the last observation",
    )
    _require(
        window["start_index"] < window["end_index"]
        and window["bars"] == window["end_index"] - window["start_index"],
        "capsule AAD final window bars must equal its end-exclusive index span",
    )
    _require(
        window["warmup_start_index"] <= window["start_index"]
        and window["warmup_bars"]
        == window["start_index"] - window["warmup_start_index"],
        "capsule AAD warm-up boundary must immediately precede the final window",
    )
    return candidate


def canonical_final_holdout_capsule_aad_v1_bytes(aad: object) -> bytes:
    """The exact AAD bytes: the frozen capsule-AAD domain plus canonical JSON.

    This is the single shared owner of the AES-GCM associated-data bytes; no
    authority-local variant or ad-hoc serialization is permitted.
    """
    return FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1 + canonical_json_bytes(
        validate_final_holdout_capsule_aad_v1(aad))


# ------------------------------------------------------- anchor registration law


def _decoded_registered_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2 != 0 \
            or len(value) > _MAX_REGISTERED_BYTES_HEX_CHARS \
            or _LOWER_HEX_RE.fullmatch(value) is None:
        _reject(
            f"{label} must be non-empty bounded lowercase hex of even length"
        )
    assert isinstance(value, str)
    return bytes.fromhex(value)


def validate_final_holdout_anchor_registration_body_v1(
    body: object,
) -> dict[str, Any]:
    """Fail-closed validation of one closed anchor registration body.

    Enforces the exact contract shape, decodes both bounded lowercase-hex byte
    fields, validates the anchor and receipt objects with the existing neutral B2
    law, and proves the decoded bytes equal their complete canonical mappings.
    It performs no signature or time verification; the authority owns those trust
    decisions.  Returns a fresh plain JSON tree plus the decoded byte fields.
    """
    candidate = _fresh_json_object(body, "anchor registration body")
    _closed_fields(
        candidate, _ANCHOR_REGISTRATION_BODY_FIELDS, "anchor registration body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
        "anchor registration body version must be "
        + FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
    )
    _require(
        candidate["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "anchor registration access protocol must be "
        + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    _pattern(
        candidate["capsule_id"], _CAPSULE_ID_RE,
        "anchor registration capsule_id", "fha-cap- plus 32 lowercase hex",
    )
    anchor_bytes = _decoded_registered_bytes(
        candidate["registered_signed_anchor_bytes_hex"],
        "registered signed anchor bytes",
    )
    receipt_bytes = _decoded_registered_bytes(
        candidate["registered_signed_receipt_bytes_hex"],
        "registered signed receipt bytes",
    )
    anchor = candidate["anchor"]
    canonical_anchor = _neutral_anchor(
        lambda: canonical_signed_anchor_bytes(anchor))
    _require(
        anchor_bytes == canonical_anchor,
        "registered signed anchor bytes must equal the canonical anchor mapping",
    )
    receipt = candidate["registration_receipt"]
    _neutral_anchor(
        lambda: canonical_unsigned_registration_receipt_bytes(receipt))
    canonical_receipt = canonical_json_bytes(receipt)
    _require(
        receipt_bytes == canonical_receipt,
        "registered signed receipt bytes must equal the canonical receipt mapping",
    )
    fresh_anchor = json.loads(canonical_anchor.decode("utf-8"))
    fresh_receipt = json.loads(canonical_receipt.decode("utf-8"))
    _require(
        fresh_receipt["anchor_id"] == fresh_anchor["anchor_id"],
        "registration receipt must bind the submitted anchor id",
    )
    return {
        "body_version": FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
        "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
        "capsule_id": candidate["capsule_id"],
        "anchor": fresh_anchor,
        "registered_signed_anchor_bytes_hex": (
            candidate["registered_signed_anchor_bytes_hex"]),
        "registration_receipt": fresh_receipt,
        "registered_signed_receipt_bytes_hex": (
            candidate["registered_signed_receipt_bytes_hex"]),
    }


def canonical_final_holdout_anchor_registration_body_bytes(body: object) -> bytes:
    """Canonical JSON bytes of the complete valid anchor registration body."""
    return canonical_json_bytes(
        validate_final_holdout_anchor_registration_body_v1(body))


# ----------------------------------------------------- final-access audit (moved)


def _load_audit_schema() -> dict[str, Any]:
    cached = _SCHEMA_CACHE.get(FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE)
    if cached is not None:
        return cached
    try:
        value = json.loads(
            (_SCHEMA_ROOT / FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE)
            .read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalHoldoutAccessProtocolError(
            f"cannot load Gate E schema: {FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE}"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("additionalProperties") is not False
        or value.get("type") != "object"
        or not isinstance(value.get("properties"), dict)
        or not isinstance(value.get("required"), list)
        or not str(value.get("$id", "")).endswith(
            "/" + FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE)
    ):
        raise FinalHoldoutAccessProtocolError(
            "Gate E schema is not a closed object schema: "
            + FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE
        )
    _SCHEMA_CACHE[FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE] = value
    return value


def _audit_canonical_json_bytes(value: object) -> bytes:
    """Canonical bytes for the audit path with the exact legacy error message.

    The accepted worker law reported precisely this message for NaN/non-finite or
    non-JSON input; the wrapper re-raises ``str(exc)``, so the neutral owner must
    preserve the byte-exact legacy message here rather than the module-generic one.
    """
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FinalHoldoutAccessProtocolError(
            "Gate E contracts accept only finite canonical JSON values"
        ) from exc


def validate_final_holdout_access_audit_v1(value: object) -> dict[str, Any]:
    """Validate one canonical final-holdout-access-audit-v1 record.

    This is the accepted Stop A schema/cross-field/time law, moved here with the
    same sealed schema bytes, the same closed-shape and format checks, the same
    outcome/lease/consumption coherence rules and byte-exact legacy error
    messages.  Unlike the legacy worker surface, this neutral public validator
    returns a fresh JSON tree with no alias to the caller mapping; the worker
    wrapper alone preserves the legacy return-the-input behavior.
    """
    if not isinstance(value, dict):
        _reject("final-holdout-access-audit-v1 must be a JSON object")
    assert isinstance(value, dict)
    payload = _audit_canonical_json_bytes(value)
    try:
        jsonschema.Draft202012Validator(
            _load_audit_schema(),
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)
    except jsonschema.ValidationError as exc:
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in exc.absolute_path
        )
        raise FinalHoldoutAccessProtocolError(
            f"final-holdout-access-audit-v1 contract violation at {path}: "
            f"{exc.message}"
        ) from exc
    audit = value
    requested = _audit_utc_second(audit["requested_at"], "requested_at")
    decided = _audit_utc_second(audit["decided_at"], "decided_at")
    _require(requested <= decided, "audit decision cannot precede its request")
    consumed = audit["consumed_at"]
    if consumed is not None:
        _require(
            _audit_utc_second(consumed, "consumed_at") >= decided,
            "audit consumption cannot precede its decision",
        )
    outcome = audit["outcome"]
    lease_id = audit["lease_id"]
    reason = audit["denial_reason"]
    if outcome == "denied":
        _require(
            lease_id is None and consumed is None and isinstance(reason, str),
            "a denied audit records no lease or consumption and states a reason",
        )
    elif outcome == "lease_expired":
        _require(
            isinstance(lease_id, str) and consumed is None and isinstance(reason, str),
            "an expired-lease audit binds its lease, no consumption, and a reason",
        )
    else:
        _require(
            isinstance(lease_id, str) and isinstance(consumed, str) and reason is None,
            "an evaluation audit binds its lease and consumption with no denial reason",
        )
    fresh = json.loads(payload.decode("utf-8"))
    assert isinstance(fresh, dict)
    return fresh


def _audit_utc_second(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        _reject(f"{label} must be a whole-second UTC timestamp")
    assert isinstance(value, str)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise FinalHoldoutAccessProtocolError(
            f"{label} is not a real UTC instant"
        ) from exc


def canonical_unsigned_final_holdout_access_audit_bytes(audit: object) -> bytes:
    """Canonical bytes of the valid audit with only ``signature`` removed.

    Audit signatures cover ``FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1`` plus exactly
    these bytes.
    """
    valid = validate_final_holdout_access_audit_v1(
        _fresh_json_object(audit, "final-holdout-access-audit-v1"))
    del valid["signature"]
    return canonical_json_bytes(valid)


def canonical_signed_final_holdout_access_audit_bytes(audit: object) -> bytes:
    """Canonical bytes of the complete valid signed audit, no domain prefix."""
    return canonical_json_bytes(validate_final_holdout_access_audit_v1(
        _fresh_json_object(audit, "final-holdout-access-audit-v1")))


# ============================================================ B3b request bodies
# The four closed one-use access request bodies (contract 37 sections 4.3-4.6).
# Each is a closed object with the frozen body version and access protocol; the
# authority owns all trust, timing, signing and persistence.

_LEASE_REQUEST_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "capsule_id",
    "capsule_payload_sha256",
    "anchor_id",
    "anchor_sha256",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "confirmed_spec_hash",
    "snapshot_sha256",
    "validation_plan_hash",
    "complete_validation_plan_sha256",
    "locked_rule_sha256",
    "base_costs_sha256",
)
_CONSUME_REQUEST_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "release_id",
    "lease_id",
    "anchor_id",
    "capsule_id",
    "capsule_payload_sha256",
    "run_id",
)
_COMPLETION_REQUEST_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "release_id",
    "lease_id",
    "anchor_id",
    "capsule_id",
    "run_id",
    "outcome",
)
_AUDIT_RETRIEVAL_BODY_FIELDS = (
    "body_version",
    "access_protocol",
    "release_id",
    "lease_id",
    "anchor_id",
    "capsule_id",
    "run_id",
)
_COMPLETION_OUTCOMES = ("evaluation_succeeded", "evaluation_failed")


def _request_body_common(candidate: Mapping[str, Any], label: str) -> None:
    _require(
        candidate["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
        f"{label} access protocol must be " + FINAL_HOLDOUT_ACCESS_PROTOCOL,
    )
    _require(
        candidate["release_id"] == _RELEASE_ID_V3,
        f"{label} release must be " + _RELEASE_ID_V3,
    )
    _pattern(candidate["capsule_id"], _CAPSULE_ID_RE,
             f"{label} capsule_id", "fha-cap- plus 32 lowercase hex")
    _pattern(candidate["anchor_id"], _ANCHOR_ID_RE,
             f"{label} anchor_id", "vpa- plus 32 lowercase hex")
    for field in ("tenant_id", "workspace_id", "run_id"):
        if field in candidate:
            _identity(candidate[field], f"{label} {field}")


def validate_final_holdout_lease_request_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed lease request body (contract 37 section 4.3)."""
    candidate = _fresh_json_object(body, "lease request body")
    _closed_fields(candidate, _LEASE_REQUEST_BODY_FIELDS, "lease request body")
    _require(
        candidate["body_version"] == FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
        "lease request body version must be "
        + FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
    )
    _request_body_common(candidate, "lease request")
    _identity(candidate["tenant_id"], "lease request tenant_id")
    for field in (
        "capsule_payload_sha256", "anchor_sha256", "confirmed_spec_hash",
        "snapshot_sha256", "validation_plan_hash",
        "complete_validation_plan_sha256", "locked_rule_sha256",
        "base_costs_sha256",
    ):
        _prefixed_sha256(candidate[field], f"lease request {field}")
    return candidate


def canonical_final_holdout_lease_request_body_bytes(body: object) -> bytes:
    return canonical_json_bytes(
        validate_final_holdout_lease_request_body_v1(body))


def validate_final_holdout_consume_request_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed consume request body (contract 37 section 4.4)."""
    candidate = _fresh_json_object(body, "consume request body")
    _closed_fields(candidate, _CONSUME_REQUEST_BODY_FIELDS, "consume request body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
        "consume request body version must be "
        + FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
    )
    _request_body_common(candidate, "consume request")
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "consume request lease_id", "fha-lease- plus 32 lowercase hex")
    _identity(candidate["run_id"], "consume request run_id")
    _prefixed_sha256(
        candidate["capsule_payload_sha256"], "consume request capsule_payload_sha256")
    return candidate


def canonical_final_holdout_consume_request_body_bytes(body: object) -> bytes:
    return canonical_json_bytes(
        validate_final_holdout_consume_request_body_v1(body))


def validate_final_holdout_completion_request_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed completion request body (contract 37 section 4.5)."""
    candidate = _fresh_json_object(body, "completion request body")
    _closed_fields(
        candidate, _COMPLETION_REQUEST_BODY_FIELDS, "completion request body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
        "completion request body version must be "
        + FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
    )
    _request_body_common(candidate, "completion request")
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "completion request lease_id", "fha-lease- plus 32 lowercase hex")
    _identity(candidate["run_id"], "completion request run_id")
    _require(
        candidate["outcome"] in _COMPLETION_OUTCOMES,
        "completion outcome must be exactly evaluation_succeeded or "
        "evaluation_failed",
    )
    return candidate


def canonical_final_holdout_completion_request_body_bytes(body: object) -> bytes:
    return canonical_json_bytes(
        validate_final_holdout_completion_request_body_v1(body))


def validate_final_holdout_audit_retrieval_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed audit retrieval body (contract 37 section 4.6)."""
    candidate = _fresh_json_object(body, "audit retrieval body")
    _closed_fields(candidate, _AUDIT_RETRIEVAL_BODY_FIELDS, "audit retrieval body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
        "audit retrieval body version must be "
        + FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
    )
    _request_body_common(candidate, "audit retrieval")
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "audit retrieval lease_id", "fha-lease- plus 32 lowercase hex")
    _identity(candidate["run_id"], "audit retrieval run_id")
    return candidate


def canonical_final_holdout_audit_retrieval_body_bytes(body: object) -> bytes:
    return canonical_json_bytes(
        validate_final_holdout_audit_retrieval_body_v1(body))


# =========================================================== B3b response bodies

FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE = "The terminal access audit is not available yet."

_LEASE_RESPONSE_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "release_id",
    "lease_id",
    "capsule_id",
    "anchor_id",
    "run_id",
    "anchor_sha256",
    "capsule_payload_sha256",
    "issued_at",
    "lease_expires_at",
    "state",
)
_CONSUME_RESPONSE_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "release_id",
    "lease_id",
    "capsule_id",
    "anchor_id",
    "run_id",
    "capsule_payload_sha256",
    "evaluation_start_offset",
    "primary_observations",
    "benchmark_observations",
    "consumed_at",
    "completion_deadline",
    "state",
)
_LEASE_DENIAL_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "terminal_audit",
    "signed_terminal_audit_bytes_hex",
)
_TERMINAL_AUDIT_BODY_FIELDS = (
    "body_version",
    "code",
    "request_id",
    "lease_id",
    "terminal_audit",
    "signed_terminal_audit_bytes_hex",
)
_AUDIT_PENDING_BODY_FIELDS = (
    "body_version",
    "code",
    "message",
    "request_id",
    "lease_id",
)
_LEASE_DENIAL_CODES = ("LEASE_ALREADY_EXISTS", "ANCHOR_EXPIRED")
_TERMINAL_AUDIT_CODES = ("EVALUATION_COMPLETED", "TERMINAL_AUDIT_RETURNED")


def _embedded_signed_audit(
    candidate: Mapping[str, Any], label: str
) -> dict[str, Any]:
    """Validate a body's terminal audit and prove its hex is the signed bytes."""
    audit = validate_final_holdout_access_audit_v1(candidate["terminal_audit"])
    hex_value = candidate["signed_terminal_audit_bytes_hex"]
    if not isinstance(hex_value, str) or not hex_value \
            or len(hex_value) % 2 != 0 \
            or len(hex_value) > _MAX_REGISTERED_BYTES_HEX_CHARS \
            or _LOWER_HEX_RE.fullmatch(hex_value) is None:
        _reject(f"{label} signed audit hex must be bounded lowercase hex")
    signed_bytes = bytes.fromhex(hex_value)
    _require(
        signed_bytes == canonical_signed_final_holdout_access_audit_bytes(audit),
        f"{label} signed audit hex must decode to the canonical signed audit",
    )
    return audit


def validate_final_holdout_lease_response_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed LEASE_ISSUED success body (work package 5.1)."""
    candidate = _fresh_json_object(body, "lease response body")
    _closed_fields(candidate, _LEASE_RESPONSE_BODY_FIELDS, "lease response body")
    _require(
        candidate["body_version"] == FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1,
        "lease response body version must be "
        + FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1,
    )
    _require(candidate["code"] == "LEASE_ISSUED",
             "lease response code must be LEASE_ISSUED")
    _pattern(candidate["request_id"], _REQUEST_ID_RE,
             "lease response request_id", "fha-req- plus 32 lowercase hex")
    _require(candidate["release_id"] == _RELEASE_ID_V3,
             "lease response release must be " + _RELEASE_ID_V3)
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "lease response lease_id", "fha-lease- plus 32 lowercase hex")
    _pattern(candidate["capsule_id"], _CAPSULE_ID_RE,
             "lease response capsule_id", "fha-cap- plus 32 lowercase hex")
    _pattern(candidate["anchor_id"], _ANCHOR_ID_RE,
             "lease response anchor_id", "vpa- plus 32 lowercase hex")
    _identity(candidate["run_id"], "lease response run_id")
    _prefixed_sha256(candidate["anchor_sha256"], "lease response anchor_sha256")
    _prefixed_sha256(candidate["capsule_payload_sha256"],
                     "lease response capsule_payload_sha256")
    issued = _utc_second(candidate["issued_at"], "lease response issued_at")
    expires = _utc_second(candidate["lease_expires_at"],
                          "lease response lease_expires_at")
    _require(issued < expires,
             "lease response issued_at must precede lease_expires_at")
    _require(candidate["state"] == "ISSUED",
             "lease response state must be ISSUED")
    return candidate


def validate_final_holdout_consume_response_body_v1(body: object) -> dict[str, Any]:
    """Validate the exact closed PLAINTEXT_RELEASED body (work package 5.2)."""
    candidate = _fresh_json_object(body, "consume response body")
    _closed_fields(candidate, _CONSUME_RESPONSE_BODY_FIELDS, "consume response body")
    _require(
        candidate["body_version"] == FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1,
        "consume response body version must be "
        + FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1,
    )
    _require(candidate["code"] == "PLAINTEXT_RELEASED",
             "consume response code must be PLAINTEXT_RELEASED")
    _pattern(candidate["request_id"], _REQUEST_ID_RE,
             "consume response request_id", "fha-req- plus 32 lowercase hex")
    _require(candidate["release_id"] == _RELEASE_ID_V3,
             "consume response release must be " + _RELEASE_ID_V3)
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "consume response lease_id", "fha-lease- plus 32 lowercase hex")
    _pattern(candidate["capsule_id"], _CAPSULE_ID_RE,
             "consume response capsule_id", "fha-cap- plus 32 lowercase hex")
    _pattern(candidate["anchor_id"], _ANCHOR_ID_RE,
             "consume response anchor_id", "vpa- plus 32 lowercase hex")
    _identity(candidate["run_id"], "consume response run_id")
    _prefixed_sha256(candidate["capsule_payload_sha256"],
                     "consume response capsule_payload_sha256")
    offset = candidate["evaluation_start_offset"]
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        _reject("consume response evaluation offset must be a non-negative integer")
    primary = _one_instrument_document(
        candidate["primary_observations"], "consume response primary observations")
    benchmark = _one_instrument_document(
        candidate["benchmark_observations"],
        "consume response benchmark observations")
    _require(
        _neutral_market(lambda: canonical_market_observations_v2_bytes(benchmark))
        == _neutral_market(lambda: canonical_market_observations_v2_bytes(primary)),
        "consume response benchmark must be canonical-identical to primary",
    )
    consumed = _utc_second(candidate["consumed_at"], "consume response consumed_at")
    deadline = _utc_second(candidate["completion_deadline"],
                           "consume response completion_deadline")
    _require(consumed < deadline,
             "consume response consumed_at must precede completion_deadline")
    _require(candidate["state"] == "CONSUMED",
             "consume response state must be CONSUMED")
    # Normalization is load-bearing: the returned tree carries the separately
    # canonicalized fresh observation documents, never the caller's aliases, so
    # a shared input object yields two distinct fresh returned subtrees.
    candidate["primary_observations"] = primary
    candidate["benchmark_observations"] = benchmark
    return candidate


def validate_final_holdout_lease_denial_response_body_v1(
    body: object,
) -> dict[str, Any]:
    """Validate the exact closed lease denial body (work package 5.3)."""
    candidate = _fresh_json_object(body, "lease denial response body")
    _closed_fields(candidate, _LEASE_DENIAL_BODY_FIELDS, "lease denial response body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1,
        "lease denial response body version must be "
        + FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1,
    )
    _require(candidate["code"] in _LEASE_DENIAL_CODES,
             "lease denial code must be LEASE_ALREADY_EXISTS or ANCHOR_EXPIRED")
    _pattern(candidate["request_id"], _REQUEST_ID_RE,
             "lease denial response request_id", "fha-req- plus 32 lowercase hex")
    audit = _embedded_signed_audit(candidate, "lease denial")
    _require(audit["outcome"] == "denied",
             "lease denial audit outcome must be denied")
    _require(
        audit["lease_id"] is None and audit["consumed_at"] is None,
        "lease denial audit records no lease or consumption",
    )
    _require(
        audit["denial_reason"] == candidate["code"],
        "lease denial audit denial_reason must equal the body code",
    )
    _require(
        audit["request_id"] == candidate["request_id"],
        "lease denial audit request_id must equal the lease request id",
    )
    return candidate


def validate_final_holdout_terminal_audit_response_body_v1(
    body: object,
) -> dict[str, Any]:
    """Validate the exact closed terminal audit body (work package 5.4)."""
    candidate = _fresh_json_object(body, "terminal audit response body")
    _closed_fields(
        candidate, _TERMINAL_AUDIT_BODY_FIELDS, "terminal audit response body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1,
        "terminal audit response body version must be "
        + FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1,
    )
    _require(candidate["code"] in _TERMINAL_AUDIT_CODES,
             "terminal audit code must be EVALUATION_COMPLETED or "
             "TERMINAL_AUDIT_RETURNED")
    _pattern(candidate["request_id"], _REQUEST_ID_RE,
             "terminal audit response request_id", "fha-req- plus 32 lowercase hex")
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "terminal audit response lease_id", "fha-lease- plus 32 lowercase hex")
    audit = _embedded_signed_audit(candidate, "terminal audit")
    _require(
        audit["lease_id"] == candidate["lease_id"],
        "terminal audit body lease id must equal the audit lease id",
    )
    # Code/outcome matrix: a completion result reports only an evaluation
    # outcome; a retrieval may return a completed evaluation or a lease expiry.
    if candidate["code"] == "EVALUATION_COMPLETED":
        allowed_outcomes = ("evaluation_succeeded", "evaluation_failed")
    else:  # TERMINAL_AUDIT_RETURNED
        allowed_outcomes = (
            "lease_expired", "evaluation_succeeded", "evaluation_failed")
    _require(
        audit["outcome"] in allowed_outcomes,
        "terminal audit outcome is not permitted for its body code",
    )
    return candidate


def validate_final_holdout_audit_pending_response_body_v1(
    body: object,
) -> dict[str, Any]:
    """Validate the exact closed AUDIT_PENDING body (work package 5.5)."""
    candidate = _fresh_json_object(body, "audit pending response body")
    _closed_fields(
        candidate, _AUDIT_PENDING_BODY_FIELDS, "audit pending response body")
    _require(
        candidate["body_version"]
        == FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1,
        "audit pending response body version must be "
        + FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1,
    )
    _require(candidate["code"] == "AUDIT_PENDING",
             "audit pending code must be AUDIT_PENDING")
    _require(
        candidate["message"] == FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE,
        "audit pending message must be the exact frozen message",
    )
    _pattern(candidate["request_id"], _REQUEST_ID_RE,
             "audit pending response request_id", "fha-req- plus 32 lowercase hex")
    _pattern(candidate["lease_id"], _LEASE_ID_RE,
             "audit pending response lease_id", "fha-lease- plus 32 lowercase hex")
    return candidate


__all__ = [
    "FINAL_EVALUATOR_ROLE",
    "FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1",
    "FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE",
    "FINAL_HOLDOUT_ACCESS_AUDIT_SCHEMA_FILE",
    "FINAL_HOLDOUT_ACCESS_AUDIT_VERSION_V1",
    "FINAL_HOLDOUT_ACCESS_PROTOCOL",
    "FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1",
    "FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1",
    "FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1",
    "FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1",
    "FINAL_HOLDOUT_AUTHORITY_PUBLIC_KEYS_VERSION_V1",
    "FINAL_HOLDOUT_B3A_STATUS_CODES",
    "FINAL_HOLDOUT_B3B_RESERVED_STATUS_CODES",
    "FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1",
    "FINAL_HOLDOUT_CAPSULE_AAD_VERSION_V1",
    "FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1",
    "FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1",
    "FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1",
    "FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_CLIENT_PUBLIC_KEYS_VERSION_V1",
    "FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1",
    "FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1",
    "FINAL_HOLDOUT_CLIENT_ROLES",
    "FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1",
    "FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1",
    "FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1",
    "FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1",
    "FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_ERROR_STATUS_MESSAGES",
    "FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_LEASE_PATH_V1",
    "FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1",
    "FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1",
    "FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1",
    "FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1",
    "FINAL_HOLDOUT_UNSIGNED_TRANSPORT_BODIES",
    "FinalHoldoutAccessProtocolError",
    "MAX_CAPSULE_REGISTRATION_BODY_BYTES",
    "MAX_CLIENT_REQUEST_BODY_BYTES",
    "canonical_final_holdout_anchor_registration_body_bytes",
    "canonical_final_holdout_audit_retrieval_body_bytes",
    "canonical_final_holdout_authority_trust_bundle_bytes",
    "canonical_final_holdout_completion_request_body_bytes",
    "canonical_final_holdout_consume_request_body_bytes",
    "canonical_final_holdout_lease_request_body_bytes",
    "canonical_final_holdout_capsule_aad_v1_bytes",
    "canonical_final_holdout_capsule_payload_bytes",
    "canonical_final_holdout_capsule_registration_body_bytes",
    "canonical_final_holdout_client_trust_bundle_bytes",
    "canonical_final_holdout_response_wrapper_bytes",
    "canonical_json_bytes",
    "canonical_signed_final_holdout_access_audit_bytes",
    "canonical_signed_final_holdout_client_request_bytes",
    "canonical_signed_final_holdout_service_response_bytes",
    "canonical_unsigned_final_holdout_access_audit_bytes",
    "canonical_unsigned_final_holdout_client_request_bytes",
    "canonical_unsigned_final_holdout_service_response_bytes",
    "final_holdout_authority_trust_bundle_hash",
    "final_holdout_client_trust_bundle_hash",
    "validate_final_holdout_access_audit_v1",
    "validate_final_holdout_anchor_registration_body_v1",
    "validate_final_holdout_anchor_registration_response_body_v1",
    "validate_final_holdout_audit_pending_response_body_v1",
    "validate_final_holdout_audit_retrieval_body_v1",
    "validate_final_holdout_authority_trust_bundle_v1",
    "validate_final_holdout_capsule_aad_v1",
    "validate_final_holdout_capsule_payload_v1",
    "validate_final_holdout_capsule_registration_body_v1",
    "validate_final_holdout_capsule_registration_response_body_v1",
    "validate_final_holdout_client_request_v1",
    "validate_final_holdout_client_trust_bundle_v1",
    "validate_final_holdout_completion_request_body_v1",
    "validate_final_holdout_consume_request_body_v1",
    "validate_final_holdout_consume_response_body_v1",
    "validate_final_holdout_error_response_body_v1",
    "validate_final_holdout_lease_denial_response_body_v1",
    "validate_final_holdout_lease_request_body_v1",
    "validate_final_holdout_lease_response_body_v1",
    "validate_final_holdout_response_wrapper_v1",
    "validate_final_holdout_service_response_v1",
    "validate_final_holdout_terminal_audit_response_body_v1",
]
