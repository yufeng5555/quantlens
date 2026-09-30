"""Neutral Gate E Stop B2a plan-anchor protocol law.

This module owns the public, implementation-neutral half of the plan-anchor
protocol: the frozen domain-separator constants, the canonical JSON byte law, the
canonical signed/unsigned anchor and registration-receipt bytes, and the complete
fail-closed validation of one ``validation-plan-v3`` mapping — closed schema,
internal self-hash recomputation and the frozen fraction/window/development/warm-up
cross-field law — together with the derivation of every plan-derived anchor binding.

The future issuance authority and the dormant worker verifier must share these exact
bytes without sharing an implementation package, so this module imports no worker,
API, authority, network, clock or private-key code and is not re-exported through
``quantlens_schema.__init__``.  It reads only the sealed schema bytes under
``packages/strategy-schema/schema``.  Nothing active imports it; the dormant Stop B2a
verifier and focused tests are its only consumers.

Signing-byte law (Stop B contract section 4, frozen 2026-07-21):

- anchor signatures cover the anchor domain separator plus the canonical JSON bytes
  of the complete closed anchor with only ``signature`` removed;
- registration-receipt signatures cover the distinct receipt domain separator plus
  the canonical JSON bytes of the complete closed receipt with only ``signature``
  removed;
- the registered signed-anchor bytes are the canonical JSON bytes of the complete
  anchor, without any domain prefix;
- a signature from one domain is invalid in every other domain.

Validation always happens before canonicalization: unknown, missing, malformed or
non-finite values fail closed before any byte is produced for signature use.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Mapping

import jsonschema


class PlanAnchorProtocolError(ValueError):
    """One candidate value violates the frozen plan-anchor protocol law."""


# Distinct ASCII domain separators, each terminated by one NUL byte.  The NUL byte is
# appended explicitly so no escape sequence appears in source.
ANCHOR_DOMAIN_V1 = b"QuantLens.validation-plan-anchor-v1" + bytes([0])
PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1 = (
    b"QuantLens.validation-plan-anchor-issue-request-v1" + bytes([0])
)
PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1 = (
    b"QuantLens.validation-plan-anchor-registration-receipt-v1" + bytes([0])
)

VALIDATION_PLAN_V3_SCHEMA_FILE = "validation-plan-v3.json"
_PLAN_ANCHOR_V1_SCHEMA_FILE = "validation-plan-anchor-v1.json"

_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schema"
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}

_SHA256_PREFIX = "sha256:"
_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REQUEST_ID_RE = re.compile(r"^vpr-[0-9a-f]{32}$")
_ANCHOR_ID_RE = re.compile(r"^vpa-[0-9a-f]{32}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")

# The reviewed warm-up floor of the frozen Battery v3 law.  It dominates the 63-bar
# volatility lookback, so the exact derived warm-up is max(lookback, 200); the sealed
# plan schema additionally pins final_warmup_bars >= 200.
_FINAL_WARMUP_FLOOR_BARS = 200

_RECEIPT_VERSION_V1 = "plan-anchor-registration-receipt-v1"
_RECEIPT_FIELDS = (
    "receipt_version",
    "authority_id",
    "request_id",
    "request_sha256",
    "request_nonce",
    "anchor_id",
    "issuer_key_id",
    "unsigned_anchor_sha256",
    "signed_anchor_sha256",
    "registered_signed_anchor_bytes_sha256",
    "registered_at",
    "state",
    "signature_algorithm",
    "signature",
)


def _reject(message: str) -> None:
    raise PlanAnchorProtocolError(message)


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
        raise PlanAnchorProtocolError(
            "plan-anchor protocol values must be finite canonical JSON"
        ) from exc


def _sha256_prefixed(payload: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(payload).hexdigest()


def _fresh_json_object(value: object, label: str) -> dict[str, Any]:
    """Return a fresh plain JSON tree of one mapping; fail closed on anything else."""
    if not isinstance(value, Mapping):
        _reject(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    decoded = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    if not isinstance(decoded, dict):
        _reject(f"{label} must be a JSON object")
    assert isinstance(decoded, dict)
    return decoded


def _load_sealed_schema(filename: str) -> dict[str, Any]:
    if filename not in (VALIDATION_PLAN_V3_SCHEMA_FILE, _PLAN_ANCHOR_V1_SCHEMA_FILE):
        _reject(f"unsupported sealed schema: {filename!r}")
    cached = _SCHEMA_CACHE.get(filename)
    if cached is not None:
        return cached
    try:
        schema = json.loads((_SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlanAnchorProtocolError(
            f"cannot load sealed schema: {filename}"
        ) from exc
    if (
        not isinstance(schema, dict)
        or schema.get("additionalProperties") is not False
        or schema.get("type") != "object"
        or not isinstance(schema.get("properties"), dict)
        or not isinstance(schema.get("required"), list)
        or not str(schema.get("$id", "")).endswith("/" + filename)
    ):
        raise PlanAnchorProtocolError(
            f"sealed schema is not a closed object schema: {filename}"
        )
    _SCHEMA_CACHE[filename] = schema
    return schema


def _validate_with_schema(filename: str, value: dict[str, Any], label: str) -> None:
    try:
        jsonschema.Draft202012Validator(_load_sealed_schema(filename)).validate(value)
    except jsonschema.ValidationError as exc:
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in exc.absolute_path
        )
        raise PlanAnchorProtocolError(
            f"{label} contract violation at {path}: {exc.message}"
        ) from exc


def _utc_second(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        _reject(f"{label} must be a whole-second UTC timestamp")
    assert isinstance(value, str)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PlanAnchorProtocolError(f"{label} is not a real UTC instant") from exc


def validate_complete_validation_plan_v3(validation_plan: object) -> dict[str, Any]:
    """Fail-closed validation of one complete validation-plan-v3 mapping.

    Validates the closed sealed schema, recomputes the internal self-hash by removing
    only ``validation_plan_hash``, and rechecks the frozen fraction/window/
    development/warm-up cross-field law.  Returns a fresh plain JSON tree.
    """
    plan = _fresh_json_object(validation_plan, "validation-plan-v3")
    _validate_with_schema(VALIDATION_PLAN_V3_SCHEMA_FILE, plan, "validation-plan-v3")

    body = {key: value for key, value in plan.items() if key != "validation_plan_hash"}
    _require(
        plan["validation_plan_hash"] == _sha256_prefixed(canonical_json_bytes(body)),
        "validation-plan-v3 self-hash does not cover the plan body",
    )

    window = plan["final_window"]
    n_bars = plan["n_bars"]
    _require(
        window["n_bars"] == n_bars,
        "final window observation count must equal the plan observation count",
    )
    _require(window["end_index"] == n_bars, "final window must end at n_bars")
    _require(
        window["start_index"] == plan["development_bars"],
        "final window must start where development ends",
    )
    _require(
        window["bars"] == window["end_index"] - window["start_index"],
        "final window bars must equal its end-exclusive index span",
    )
    _require(
        plan["development_bars"] + window["bars"] == n_bars,
        "development and final windows must partition the observations",
    )
    _require(
        window["warmup_bars"]
        == window["start_index"] - window["warmup_start_index"],
        "warm-up boundary must immediately precede the final window",
    )
    _require(
        window["warmup_bars"]
        == min(plan["final_warmup_bars"], window["start_index"]),
        "warm-up span must equal the derived warm-up clipped only at zero",
    )
    _require(
        plan["final_holdout_fraction"] == window["bars"] / n_bars,
        "effective fraction must equal its derived final-window share exactly",
    )
    derived_bars = int(
        (Decimal(n_bars) * Decimal(str(plan["registered_final_holdout_fraction"])))
        .to_integral_value(rounding=ROUND_HALF_EVEN)
    )
    _require(
        window["bars"] == max(1, derived_bars),
        "final window bars must follow the frozen half-even registration rule",
    )
    walk_forward = plan["walk_forward"]
    _require(
        plan["minimum_train_bars"]
        == max(
            walk_forward["minimum_train_floor_bars"],
            walk_forward["minimum_train_lookback_multiple"]
            * plan["max_indicator_lookback"],
        ),
        "minimum training span must follow the frozen walk-forward law",
    )
    _require(
        plan["development_bars"]
        >= plan["minimum_train_bars"] + walk_forward["minimum_short_fold_bars"],
        "development must hold the minimum training span plus one evaluation fold",
    )
    _require(
        plan["final_warmup_bars"]
        == max(plan["max_indicator_lookback"], _FINAL_WARMUP_FLOOR_BARS),
        "warm-up requirement must follow the frozen lookback/floor law",
    )
    return plan


def complete_validation_plan_hash_v3(validation_plan: object) -> str:
    """``sha256:`` hash of the canonical bytes of the entire valid plan.

    The hashed bytes include the plan's already-recomputed ``validation_plan_hash``;
    this value is deliberately distinct from the plan's internal self-hash.
    """
    plan = validate_complete_validation_plan_v3(validation_plan)
    return _sha256_prefixed(canonical_json_bytes(plan))


def derive_anchor_bindings_from_plan_v3(validation_plan: object) -> dict[str, Any]:
    """Derive every plan-derived anchor binding from the complete valid plan.

    All values are fresh copies computed from the validated plan itself; no
    caller-built summary, normalization or rounding is involved.  The anchor
    snapshot digest is the plan's prefixed snapshot hash with one and only one
    leading ``sha256:`` removed.
    """
    plan = validate_complete_validation_plan_v3(validation_plan)
    snapshot = plan["snapshot_sha256"]
    _require(
        isinstance(snapshot, str) and snapshot.startswith(_SHA256_PREFIX),
        "plan snapshot hash must carry exactly one sha256: prefix",
    )
    return {
        "release_id": plan["release_id"],
        "tenant_id": plan["tenant_id"],
        "workspace_id": plan["workspace_id"],
        "run_id": plan["run_id"],
        "confirmed_spec_hash": plan["confirmed_spec_hash"],
        "snapshot_sha256": snapshot[len(_SHA256_PREFIX):],
        "validation_plan_version": plan["plan_version"],
        "validation_plan_sha256": _sha256_prefixed(canonical_json_bytes(plan)),
        "locked_rule_sha256": plan["locked_rule_sha256"],
        "base_costs_sha256": plan["base_costs_sha256"],
        "final_holdout_fraction": plan["final_holdout_fraction"],
        "final_window": dict(plan["final_window"]),
        "issuer_key_id": plan["authorities"]["anchor_issuer_key_id"],
    }


def _validated_anchor(anchor: object) -> dict[str, Any]:
    """Closed-shape validation of one complete signed anchor, as a fresh tree.

    The worker verifier still calls the existing Stop A validator as the authoritative
    worker-side check.  These neutral canonical-byte helpers mirror its five frozen
    cross-field invariants as a fail-closed signer boundary, because the independent
    B2b authority must share the wire law without importing a worker package.
    """
    candidate = _fresh_json_object(anchor, "validation-plan-anchor-v1")
    _validate_with_schema(
        _PLAN_ANCHOR_V1_SCHEMA_FILE, candidate, "validation-plan-anchor-v1")
    window = candidate["final_window"]
    _require(
        window["end_index"] == window["n_bars"],
        "anchor final window must end at the last observation",
    )
    _require(
        window["start_index"] < window["end_index"]
        and window["bars"] == window["end_index"] - window["start_index"],
        "anchor final window bars must equal its end-exclusive index span",
    )
    _require(
        window["warmup_start_index"] <= window["start_index"]
        and window["warmup_bars"]
        == window["start_index"] - window["warmup_start_index"],
        "anchor warm-up boundary must immediately precede the final window",
    )
    _require(
        candidate["final_holdout_fraction"]
        == window["bars"] / window["n_bars"],
        "anchor fraction must equal its derived final-window share exactly",
    )
    issued = _utc_second(candidate["issued_at"], "anchor issued_at")
    expires = _utc_second(candidate["expires_at"], "anchor expires_at")
    _require(expires > issued, "anchor expiry must be after issuance")
    return candidate


def canonical_unsigned_anchor_bytes(anchor: object) -> bytes:
    """Canonical JSON bytes of the complete closed anchor with only ``signature`` removed.

    Anchor signatures cover ``ANCHOR_DOMAIN_V1`` plus exactly these bytes.
    """
    candidate = _validated_anchor(anchor)
    del candidate["signature"]
    return canonical_json_bytes(candidate)


def canonical_signed_anchor_bytes(anchor: object) -> bytes:
    """Canonical JSON bytes of the complete closed anchor, without a domain prefix.

    These are the exact registered signed-anchor bytes a durable authority stores.
    """
    return canonical_json_bytes(_validated_anchor(anchor))


def _validated_registration_receipt(receipt: object) -> dict[str, Any]:
    candidate = _fresh_json_object(receipt, "plan-anchor registration receipt")
    keys = set(candidate)
    expected = set(_RECEIPT_FIELDS)
    if keys != expected:
        missing = sorted(expected - keys)
        surplus = sorted(str(key) for key in keys - expected)
        _reject(
            "registration receipt must have exactly the sealed receipt fields"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; unknown: {', '.join(surplus)}" if surplus else "")
        )
    _require(
        candidate["receipt_version"] == _RECEIPT_VERSION_V1,
        "registration receipt version must be " + _RECEIPT_VERSION_V1,
    )
    for field in ("authority_id", "issuer_key_id"):
        value = candidate[field]
        if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
            _reject(f"receipt {field} must be a printable-ASCII identity")
    if not isinstance(candidate["request_id"], str) or \
            _REQUEST_ID_RE.fullmatch(candidate["request_id"]) is None:
        _reject("receipt request_id must match vpr- plus 32 lowercase hex")
    if not isinstance(candidate["anchor_id"], str) or \
            _ANCHOR_ID_RE.fullmatch(candidate["anchor_id"]) is None:
        _reject("receipt anchor_id must match vpa- plus 32 lowercase hex")
    if not isinstance(candidate["request_nonce"], str) or \
            _NONCE_RE.fullmatch(candidate["request_nonce"]) is None:
        _reject("receipt request_nonce must be 32 lowercase hex characters")
    for field in (
        "request_sha256",
        "unsigned_anchor_sha256",
        "signed_anchor_sha256",
        "registered_signed_anchor_bytes_sha256",
    ):
        value = candidate[field]
        if not isinstance(value, str) or _PREFIXED_SHA256_RE.fullmatch(value) is None:
            _reject(
                f"receipt {field} must be sha256: plus 64 lowercase hex characters"
            )
    _require(
        candidate["registered_signed_anchor_bytes_sha256"]
        == candidate["signed_anchor_sha256"],
        "receipt registered-bytes hash must equal its signed-anchor hash",
    )
    _utc_second(candidate["registered_at"], "receipt registered_at")
    _require(
        candidate["state"] == "REGISTERED",
        "registration receipt state must be exactly REGISTERED",
    )
    _require(
        candidate["signature_algorithm"] == "ed25519",
        "registration receipt signature algorithm is pinned to ed25519",
    )
    if not isinstance(candidate["signature"], str) or \
            _SIGNATURE_RE.fullmatch(candidate["signature"]) is None:
        _reject("receipt signature must be 128 lowercase hex characters")
    return candidate


def canonical_unsigned_registration_receipt_bytes(receipt: object) -> bytes:
    """Canonical JSON bytes of the complete closed receipt with only ``signature`` removed.

    Receipt signatures cover ``PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1`` plus
    exactly these bytes.
    """
    candidate = _validated_registration_receipt(receipt)
    del candidate["signature"]
    return canonical_json_bytes(candidate)


# ---------------------------------------------------------------------------------
# Stop B2b additions: the closed issue body/request wire law and the shared issuer
# public trust-bundle law.  The registrar and the independent issuance authority
# share exactly these bytes; neither imports the other's implementation package.

PLAN_ANCHOR_ISSUE_BODY_VERSION_V1 = "plan-anchor-issue-body-v1"
PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1 = "plan-anchor-issue-request-v1"
PLAN_ANCHOR_ISSUE_PATH_V1 = "/v1/validation-plan-anchors"
CONTROL_PLANE_REGISTRAR_ROLE = "CONTROL_PLANE_REGISTRAR"
PLAN_ANCHOR_PUBLIC_KEYS_VERSION_V1 = "plan-anchor-public-keys-v1"

_ISSUE_BODY_FIELDS = ("body_version", "validation_plan")
_ISSUE_REQUEST_FIELDS = (
    "request_version",
    "request_id",
    "authority_id",
    "registrar_role",
    "registrar_key_id",
    "method",
    "path",
    "timestamp",
    "nonce",
    "body_sha256",
    "signature_algorithm",
    "signature",
)
_TRUST_BUNDLE_FIELDS = ("bundle_version", "authority_id", "keys")
_TRUST_KEY_FIELDS = (
    "key_id", "algorithm", "status", "public_key_hex", "not_before", "not_after",
)
_KEY_STATUSES = ("active", "inactive")
_PUBLIC_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _closed_fields(candidate: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
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


def validate_plan_anchor_issue_body_v1(body: object) -> dict[str, Any]:
    """Fail-closed validation of one closed plan-anchor issue body.

    The body carries the complete ``validation-plan-v3`` and nothing else: no plan
    digest, anchor identity, nonce, issuer, lifetime, issue time or expiry can be
    submitted by the caller.  Returns a fresh plain JSON tree.
    """
    candidate = _fresh_json_object(body, "plan-anchor issue body")
    _closed_fields(candidate, _ISSUE_BODY_FIELDS, "plan-anchor issue body")
    _require(
        candidate["body_version"] == PLAN_ANCHOR_ISSUE_BODY_VERSION_V1,
        "issue body version must be " + PLAN_ANCHOR_ISSUE_BODY_VERSION_V1,
    )
    plan = validate_complete_validation_plan_v3(candidate["validation_plan"])
    return {
        "body_version": PLAN_ANCHOR_ISSUE_BODY_VERSION_V1,
        "validation_plan": plan,
    }


def canonical_plan_anchor_issue_body_bytes(body: object) -> bytes:
    """Canonical JSON bytes of the complete valid closed issue body."""
    return canonical_json_bytes(validate_plan_anchor_issue_body_v1(body))


def validate_plan_anchor_issue_request_v1(request: object) -> dict[str, Any]:
    """Fail-closed validation of one closed signed issue-request envelope.

    Method, path, role, algorithm and version are exact constants; identities,
    nonce, hash and signature are never normalized; the timestamp must be a real
    whole-second UTC instant.  Returns a fresh plain JSON tree.
    """
    candidate = _fresh_json_object(request, "plan-anchor issue request")
    _closed_fields(candidate, _ISSUE_REQUEST_FIELDS, "plan-anchor issue request")
    _require(
        candidate["request_version"] == PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1,
        "issue request version must be " + PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1,
    )
    if not isinstance(candidate["request_id"], str) or \
            _REQUEST_ID_RE.fullmatch(candidate["request_id"]) is None:
        _reject("issue request request_id must match vpr- plus 32 lowercase hex")
    for field in ("authority_id", "registrar_key_id"):
        value = candidate[field]
        if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
            _reject(f"issue request {field} must be a printable-ASCII identity")
    _require(
        candidate["registrar_role"] == CONTROL_PLANE_REGISTRAR_ROLE,
        "issue request registrar_role must be " + CONTROL_PLANE_REGISTRAR_ROLE,
    )
    _require(
        candidate["method"] == "POST",
        "issue request method is pinned to POST",
    )
    _require(
        candidate["path"] == PLAN_ANCHOR_ISSUE_PATH_V1,
        "issue request path is pinned to " + PLAN_ANCHOR_ISSUE_PATH_V1,
    )
    _utc_second(candidate["timestamp"], "issue request timestamp")
    if not isinstance(candidate["nonce"], str) or \
            _NONCE_RE.fullmatch(candidate["nonce"]) is None:
        _reject("issue request nonce must be 32 lowercase hex characters")
    if not isinstance(candidate["body_sha256"], str) or \
            _PREFIXED_SHA256_RE.fullmatch(candidate["body_sha256"]) is None:
        _reject(
            "issue request body_sha256 must be sha256: plus 64 lowercase hex "
            "characters"
        )
    _require(
        candidate["signature_algorithm"] == "ed25519",
        "issue request signature algorithm is pinned to ed25519",
    )
    if not isinstance(candidate["signature"], str) or \
            _SIGNATURE_RE.fullmatch(candidate["signature"]) is None:
        _reject("issue request signature must be 128 lowercase hex characters")
    return candidate


def canonical_unsigned_plan_anchor_issue_request_bytes(request: object) -> bytes:
    """Canonical JSON bytes of the complete closed request with only ``signature`` removed.

    Registrar signatures cover ``PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1`` plus exactly
    these bytes.
    """
    candidate = validate_plan_anchor_issue_request_v1(request)
    del candidate["signature"]
    return canonical_json_bytes(candidate)


def canonical_signed_plan_anchor_issue_request_bytes(request: object) -> bytes:
    """Canonical JSON bytes of the complete closed signed request, no domain prefix.

    A registration receipt's ``request_sha256`` is ``sha256:`` plus the SHA-256 of
    exactly these bytes; raw HTTP whitespace is never part of idempotency identity.
    """
    return canonical_json_bytes(validate_plan_anchor_issue_request_v1(request))


def validate_plan_anchor_public_trust_bundle_v1(bundle: object) -> dict[str, Any]:
    """Validate the closed issuer public trust bundle and return a fresh tree.

    This is the accepted Stop B2a law, moved here so the worker verifier and the
    independent issuance authority share one trust-root byte law: closed objects
    only, keys in strictly ascending ``key_id`` order, unique key IDs and unique
    public-key bytes, a non-empty key list, and coherent whole-second UTC validity
    intervals.  No private material is ever present or accepted, no crypto key
    object is constructed, no clock is read and no key is selected.
    """
    tree, _payload = _validated_trust_bundle(bundle)
    return tree


def canonical_plan_anchor_public_trust_bundle_bytes(bundle: object) -> bytes:
    """Canonical JSON bytes of the complete valid issuer public trust bundle."""
    _tree, payload = _validated_trust_bundle(bundle)
    return payload


def plan_anchor_public_trust_bundle_hash(bundle: object) -> str:
    """``sha256:`` plus SHA-256 of the canonical public trust bundle bytes."""
    return _sha256_prefixed(canonical_plan_anchor_public_trust_bundle_bytes(bundle))


def _validated_trust_bundle(bundle: object) -> tuple[dict[str, Any], bytes]:
    if not isinstance(bundle, Mapping):
        _reject("public trust bundle must be a mapping")
    assert isinstance(bundle, Mapping)
    payload = canonical_json_bytes(dict(bundle))
    tree = json.loads(payload.decode("utf-8"))
    if not isinstance(tree, dict) or set(tree) != set(_TRUST_BUNDLE_FIELDS):
        _reject(
            "public trust bundle must have exactly these keys: "
            + ", ".join(_TRUST_BUNDLE_FIELDS)
        )
    _require(
        tree["bundle_version"] == PLAN_ANCHOR_PUBLIC_KEYS_VERSION_V1,
        "public trust bundle version must be " + PLAN_ANCHOR_PUBLIC_KEYS_VERSION_V1,
    )
    authority_id = tree["authority_id"]
    if not isinstance(authority_id, str) or \
            _IDENTITY_RE.fullmatch(authority_id) is None:
        _reject(
            "trust bundle authority_id must be a printable-ASCII identity of at "
            "most 128 characters"
        )
    keys = tree["keys"]
    if not isinstance(keys, list) or not keys:
        _reject("public trust bundle must list at least one key")
    previous_key_id: str | None = None
    seen_public_keys: set[str] = set()
    for index, entry in enumerate(keys):
        label = f"trust bundle key[{index}]"
        if not isinstance(entry, dict) or set(entry) != set(_TRUST_KEY_FIELDS):
            _reject(
                f"{label} must have exactly these keys: "
                + ", ".join(_TRUST_KEY_FIELDS)
            )
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or _IDENTITY_RE.fullmatch(key_id) is None:
            _reject(
                f"{label}.key_id must be a printable-ASCII identity of at most "
                "128 characters"
            )
        _require(
            entry["algorithm"] == "ed25519",
            f"{label}.algorithm is pinned to ed25519",
        )
        _require(
            entry["status"] in _KEY_STATUSES,
            f"{label}.status must be active or inactive",
        )
        public_key_hex = entry["public_key_hex"]
        if not isinstance(public_key_hex, str) or \
                _PUBLIC_KEY_HEX_RE.fullmatch(public_key_hex) is None:
            _reject(
                f"{label}.public_key_hex must be 64 lowercase hex characters"
            )
        _require(
            len(bytes.fromhex(public_key_hex)) == 32,
            f"{label}.public_key_hex must decode to exactly 32 bytes",
        )
        not_before = _utc_second(entry["not_before"], f"{label}.not_before")
        not_after = _utc_second(entry["not_after"], f"{label}.not_after")
        _require(
            not_before < not_after,
            f"{label} validity interval must satisfy not_before < not_after",
        )
        _require(
            previous_key_id is None or key_id > previous_key_id,
            "trust bundle keys must be strictly ordered by unique key_id",
        )
        previous_key_id = key_id
        _require(
            public_key_hex not in seen_public_keys,
            "trust bundle public-key bytes must be unique",
        )
        seen_public_keys.add(public_key_hex)
    return tree, payload


__all__ = [
    "ANCHOR_DOMAIN_V1",
    "CONTROL_PLANE_REGISTRAR_ROLE",
    "PLAN_ANCHOR_ISSUE_BODY_VERSION_V1",
    "PLAN_ANCHOR_ISSUE_PATH_V1",
    "PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1",
    "PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1",
    "PLAN_ANCHOR_PUBLIC_KEYS_VERSION_V1",
    "PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1",
    "VALIDATION_PLAN_V3_SCHEMA_FILE",
    "PlanAnchorProtocolError",
    "canonical_json_bytes",
    "canonical_plan_anchor_issue_body_bytes",
    "canonical_plan_anchor_public_trust_bundle_bytes",
    "canonical_signed_anchor_bytes",
    "canonical_signed_plan_anchor_issue_request_bytes",
    "canonical_unsigned_anchor_bytes",
    "canonical_unsigned_plan_anchor_issue_request_bytes",
    "canonical_unsigned_registration_receipt_bytes",
    "complete_validation_plan_hash_v3",
    "derive_anchor_bindings_from_plan_v3",
    "plan_anchor_public_trust_bundle_hash",
    "validate_complete_validation_plan_v3",
    "validate_plan_anchor_issue_body_v1",
    "validate_plan_anchor_issue_request_v1",
    "validate_plan_anchor_public_trust_bundle_v1",
]
