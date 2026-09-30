"""Dormant Gate E Stop B2a worker-side plan-anchor verifier.

``verify_validation_plan_anchor_v1`` turns one closed ``validation-plan-anchor-v1``
mapping into a fresh JSON projection only when every independent check passes:

1. the complete validation-plan-v3 schema, self-hash and cross-field law (through the
   neutral protocol module, never a caller-built expected-hash summary);
2. the sealed Stop A anchor schema and cross-field law (through the existing dormant
   ``gate_e_contracts`` validator, never a duplicate);
3. the exact Gate E anchor domain over the canonical unsigned bytes;
4. an Ed25519 signature from one active key of a closed, hash-pinned public trust
   bundle whose canonical hash equals the separately configured expected value;
5. strict issue/expiry/key-validity boundaries and the 3600-second maximum lifetime;
6. every plan-derived run/spec/snapshot/plan/rule/cost/fraction/window binding,
   where the bound plan hash covers the entire valid plan including its already
   recomputed internal self-hash;
7. byte equality with the authority's durable registered signed-anchor bytes; and
8. an authority-signed registration receipt, under its own distinct domain, binding
   the authenticated issue request and those exact anchor bytes.

The verifier holds no private key, reads no clock, network, environment, database or
key file, and performs no issuance.  ``now`` is supplied by the trusted caller as a
timezone-aware whole-second UTC datetime.  The module is not exported by the package
``__init__``, is not imported by any active path, and activates nothing; the focused
Stop B2a tests are its only consumers.  Receipt ``request_sha256``/``request_nonce``
are validated for shape only here — the authenticated issue request they bind is
persisted and enforced by the separate B2b authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from quantlens_schema.plan_anchor_protocol_v1 import (
    ANCHOR_DOMAIN_V1,
    PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1,
    PlanAnchorProtocolError,
    canonical_json_bytes,
    canonical_plan_anchor_public_trust_bundle_bytes,
    canonical_signed_anchor_bytes,
    canonical_unsigned_anchor_bytes,
    canonical_unsigned_registration_receipt_bytes,
    complete_validation_plan_hash_v3,
    derive_anchor_bindings_from_plan_v3,
    plan_anchor_public_trust_bundle_hash,
    validate_complete_validation_plan_v3,
)

from .gate_e_contracts import (
    GateEContractError,
    validate_validation_plan_anchor_v1,
)


class PlanAnchorVerificationError(ValueError):
    """One candidate anchor, plan, bundle or receipt fails closed verification."""


MAX_ANCHOR_LIFETIME_SECONDS = 3600

_VERIFICATION_VERSION = "plan-anchor-verification-v1"
_SHA256_PREFIX = "sha256:"
_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Fields the anchor must bind byte-for-byte to values derived from the complete plan.
_PLAN_BOUND_ANCHOR_FIELDS = (
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "confirmed_spec_hash",
    "snapshot_sha256",
    "validation_plan_version",
    "validation_plan_sha256",
    "locked_rule_sha256",
    "base_costs_sha256",
    "final_holdout_fraction",
    "final_window",
    "issuer_key_id",
)


def _reject(message: str) -> None:
    raise PlanAnchorVerificationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        _reject(f"{label} must be a printable-ASCII identity of at most 128 characters")
    assert isinstance(value, str)
    return value


def _utc_instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        _reject(f"{label} must be a whole-second UTC timestamp")
    assert isinstance(value, str)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PlanAnchorVerificationError(f"{label} is not a real UTC instant") from exc
    return parsed.replace(tzinfo=timezone.utc)


def canonical_public_trust_bundle_bytes(bundle: object) -> bytes:
    """Validate the closed public trust bundle and return its canonical bytes.

    This is the accepted Stop B2a behavior, now delegated to the shared neutral
    trust-root byte law so the worker and the independent issuance authority never
    maintain two copies.  Failure messages and the public exception type are
    unchanged: closed objects only, keys in strictly ascending ``key_id`` order,
    unique key IDs and unique public-key bytes, a non-empty key list, and coherent
    whole-second UTC validity intervals.  No private material is ever present or
    accepted.
    """
    try:
        return canonical_plan_anchor_public_trust_bundle_bytes(bundle)
    except PlanAnchorProtocolError as exc:
        raise PlanAnchorVerificationError(str(exc)) from exc


def public_trust_bundle_hash(bundle: object) -> str:
    """``sha256:`` plus SHA-256 of the canonical public trust bundle bytes."""
    try:
        return plan_anchor_public_trust_bundle_hash(bundle)
    except PlanAnchorProtocolError as exc:
        raise PlanAnchorVerificationError(str(exc)) from exc


def _protocol(step):
    """Run one neutral-protocol step, converting failures to verification errors."""
    try:
        return step()
    except PlanAnchorProtocolError as exc:
        raise PlanAnchorVerificationError(str(exc)) from exc


def _validated_now(now: object) -> datetime:
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() != timedelta(0)
        or now.microsecond != 0
    ):
        _reject(
            "now must be a timezone-aware UTC datetime with microsecond == 0"
        )
    assert isinstance(now, datetime)
    return now


def _key_valid_at(entry: Mapping[str, Any], instant: datetime, label: str) -> None:
    not_before = _utc_instant(entry["not_before"], "trust key not_before")
    not_after = _utc_instant(entry["not_after"], "trust key not_after")
    _require(
        not_before <= instant < not_after,
        f"issuer key is not valid at {label}",
    )


def _verify_ed25519(
    public_key_hex: str, signature_hex: str, message: bytes, label: str
) -> None:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except Exception as exc:  # fail closed on any unusable key material
        raise PlanAnchorVerificationError(
            f"{label}: issuer public key is not a usable Ed25519 key"
        ) from exc
    try:
        public_key.verify(bytes.fromhex(signature_hex), message)
    except InvalidSignature as exc:
        raise PlanAnchorVerificationError(
            f"{label}: signature does not verify under the pinned domain and key"
        ) from exc


def verify_validation_plan_anchor_v1(
    anchor: object,
    *,
    validation_plan: object,
    trust_bundle: object,
    expected_trust_bundle_sha256: object,
    expected_authority_id: object,
    registered_signed_anchor_bytes: object,
    registration_receipt: object,
    now: object,
) -> dict[str, Any]:
    """Verify one signed plan anchor against the complete plan and trust state."""
    verified_now = _validated_now(now)

    # The bundle pin is validated before the bundle is read and before any key use.
    if not isinstance(expected_trust_bundle_sha256, str) or \
            _PREFIXED_SHA256_RE.fullmatch(expected_trust_bundle_sha256) is None:
        _reject(
            "expected trust bundle hash must be sha256: plus 64 lowercase hex; "
            "a bare or uppercase digest is never normalized"
        )
    expected_authority = _identity(expected_authority_id, "expected authority id")

    plan = _protocol(lambda: validate_complete_validation_plan_v3(validation_plan))
    bindings = _protocol(lambda: derive_anchor_bindings_from_plan_v3(plan))
    plan_full_hash = _protocol(lambda: complete_validation_plan_hash_v3(plan))
    _require(
        plan["authorities"]["anchor_authority_id"] == expected_authority,
        "expected authority does not match the plan anchor authority",
    )

    bundle_bytes = canonical_public_trust_bundle_bytes(trust_bundle)
    bundle_hash = _SHA256_PREFIX + hashlib.sha256(bundle_bytes).hexdigest()
    _require(
        bundle_hash == expected_trust_bundle_sha256,
        "trust bundle hash does not match the separately pinned expected value",
    )
    bundle = json.loads(bundle_bytes.decode("utf-8"))
    _require(
        bundle["authority_id"] == expected_authority,
        "expected authority does not match the trust bundle authority",
    )

    if not isinstance(anchor, Mapping):
        _reject("anchor must be a mapping")
    assert isinstance(anchor, Mapping)
    anchor_plain = _protocol(
        lambda: json.loads(canonical_json_bytes(dict(anchor)).decode("utf-8")))
    try:
        validate_validation_plan_anchor_v1(anchor_plain)
    except GateEContractError as exc:
        raise PlanAnchorVerificationError(str(exc)) from exc

    for field in _PLAN_BOUND_ANCHOR_FIELDS:
        _require(
            anchor_plain[field] == bindings[field],
            f"anchor {field} does not match the value derived from the plan",
        )
    _require(
        anchor_plain["validation_plan_sha256"] == plan_full_hash,
        "anchor plan hash must cover the entire valid plan, not a summary",
    )

    issued_at = _utc_instant(anchor_plain["issued_at"], "anchor issued_at")
    expires_at = _utc_instant(anchor_plain["expires_at"], "anchor expires_at")
    lifetime = (expires_at - issued_at).total_seconds()
    _require(
        0 < lifetime <= MAX_ANCHOR_LIFETIME_SECONDS,
        "anchor lifetime must be positive and at most "
        f"{MAX_ANCHOR_LIFETIME_SECONDS} seconds",
    )
    _require(issued_at <= verified_now, "anchor is issued in the future")
    _require(verified_now < expires_at, "anchor is expired at verification time")

    unsigned_anchor_bytes = _protocol(
        lambda: canonical_unsigned_anchor_bytes(anchor_plain))
    signed_anchor_bytes = _protocol(
        lambda: canonical_signed_anchor_bytes(anchor_plain))
    unsigned_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
        unsigned_anchor_bytes).hexdigest()
    signed_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
        signed_anchor_bytes).hexdigest()

    if type(registered_signed_anchor_bytes) is not bytes:
        _reject("registered signed-anchor bytes must be bytes")
    _require(
        registered_signed_anchor_bytes == signed_anchor_bytes,
        "registered signed-anchor bytes do not equal the canonical anchor bytes",
    )
    registered_hash = _SHA256_PREFIX + hashlib.sha256(
        registered_signed_anchor_bytes).hexdigest()

    if not isinstance(registration_receipt, Mapping):
        _reject("registration receipt must be a mapping")
    assert isinstance(registration_receipt, Mapping)
    receipt_plain = _protocol(
        lambda: json.loads(
            canonical_json_bytes(dict(registration_receipt)).decode("utf-8")))
    unsigned_receipt_bytes = _protocol(
        lambda: canonical_unsigned_registration_receipt_bytes(receipt_plain))
    _require(
        receipt_plain["authority_id"] == expected_authority,
        "registration receipt authority does not match the expected authority",
    )
    _require(
        receipt_plain["anchor_id"] == anchor_plain["anchor_id"],
        "registration receipt does not bind this anchor id",
    )
    _require(
        receipt_plain["issuer_key_id"] == anchor_plain["issuer_key_id"],
        "registration receipt does not bind the anchor issuer key",
    )
    _require(
        receipt_plain["unsigned_anchor_sha256"] == unsigned_anchor_hash,
        "registration receipt unsigned-anchor hash does not match the anchor",
    )
    _require(
        receipt_plain["signed_anchor_sha256"] == signed_anchor_hash,
        "registration receipt signed-anchor hash does not match the anchor",
    )
    _require(
        receipt_plain["registered_signed_anchor_bytes_sha256"] == registered_hash,
        "registration receipt registered-bytes hash does not match the bytes",
    )
    registered_at = _utc_instant(
        receipt_plain["registered_at"], "receipt registered_at")
    _require(
        issued_at <= registered_at,
        "registration cannot precede anchor issuance",
    )
    _require(
        registered_at < expires_at,
        "registration cannot occur at or after anchor expiry",
    )
    _require(
        registered_at <= verified_now,
        "registration receipt is from the future",
    )

    issuer_key_id = anchor_plain["issuer_key_id"]
    key_entry = next(
        (entry for entry in bundle["keys"] if entry["key_id"] == issuer_key_id),
        None,
    )
    if key_entry is None:
        _reject("anchor issuer key is unknown to the pinned trust bundle")
    assert key_entry is not None
    _require(
        key_entry["status"] == "active",
        "anchor issuer key is not active in the pinned trust bundle",
    )
    _key_valid_at(key_entry, issued_at, "anchor issuance")
    _key_valid_at(key_entry, registered_at, "anchor registration")
    _key_valid_at(key_entry, verified_now, "verification time")

    _verify_ed25519(
        key_entry["public_key_hex"],
        anchor_plain["signature"],
        ANCHOR_DOMAIN_V1 + unsigned_anchor_bytes,
        "anchor",
    )
    _verify_ed25519(
        key_entry["public_key_hex"],
        receipt_plain["signature"],
        PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1 + unsigned_receipt_bytes,
        "registration receipt",
    )

    receipt_hash = _SHA256_PREFIX + hashlib.sha256(
        canonical_json_bytes(receipt_plain)).hexdigest()
    result = {
        "verification_version": _VERIFICATION_VERSION,
        "authority_id": expected_authority,
        "anchor": anchor_plain,
        "validation_plan_sha256": plan_full_hash,
        "trust_bundle_sha256": bundle_hash,
        "registered_signed_anchor_sha256": registered_hash,
        "registration_receipt_sha256": receipt_hash,
        "verified_at": verified_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return json.loads(canonical_json_bytes(result).decode("utf-8"))


__all__ = [
    "MAX_ANCHOR_LIFETIME_SECONDS",
    "PlanAnchorVerificationError",
    "canonical_public_trust_bundle_bytes",
    "public_trust_bundle_hash",
    "verify_validation_plan_anchor_v1",
]
