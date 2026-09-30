"""Dormant Gate E Stop B2b plan-anchor issuance authority.

``PlanAnchorAuthorityV1`` authenticates one signed ``CONTROL_PLANE_REGISTRAR``
issue request, validates its complete ``validation-plan-v3`` through the shared
neutral protocol law, derives every anchor binding from that plan, signs one
``validation-plan-anchor-v1`` and its registration receipt under their distinct
domains, atomically persists the exact request/body/anchor/receipt bytes in an
authority-only SQLite database and returns fresh result trees only after commit.

Trust roots are two separately hash-pinned public bundles: the issuer bundle uses
the shared neutral law also consumed by the Stop B2a worker verifier; the registrar
bundle is authority-owned and role-separated.  Both pins are validated before any
key lookup, public-key construction or private-key-file open.  The issuer private
key is an existing raw 32-byte Ed25519 seed file outside the repository, loaded
once under strict fail-closed hygiene; no default, generation, fallback or hot
reload exists, and no error, repr or log includes key contents or a detailed
secret path.

This module imports only the neutral protocol, its private store, the standard
library and ``cryptography``.  It never imports the worker, API, runner, Battery,
report or web code, opens no socket and reads no environment.  Nothing active
imports it; the dormant HTTP factory and focused Stop B2b tests are its only
consumers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from quantlens_schema.plan_anchor_protocol_v1 import (
    ANCHOR_DOMAIN_V1,
    CONTROL_PLANE_REGISTRAR_ROLE,
    PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1,
    PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1,
    PlanAnchorProtocolError,
    canonical_json_bytes,
    canonical_plan_anchor_public_trust_bundle_bytes,
    canonical_signed_anchor_bytes,
    canonical_unsigned_anchor_bytes,
    canonical_unsigned_plan_anchor_issue_request_bytes,
    canonical_unsigned_registration_receipt_bytes,
    derive_anchor_bindings_from_plan_v3,
    validate_plan_anchor_issue_body_v1,
    validate_plan_anchor_issue_request_v1,
    validate_plan_anchor_public_trust_bundle_v1,
)

from .store_v1 import PlanAnchorAuthorityStoreError, PlanAnchorAuthorityStoreV1

ANCHOR_LIFETIME_SECONDS = 3600
MAX_ISSUE_REQUEST_AGE_SECONDS = 60

_SCHEMA_VERSION = "plan-anchor-authority-db-v1"
_REGISTRAR_BUNDLE_VERSION = "plan-anchor-registrar-public-keys-v1"
_SHA256_PREFIX = "sha256:"
_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLIC_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_REGISTRAR_BUNDLE_FIELDS = ("bundle_version", "authority_id", "keys")
_REGISTRAR_KEY_FIELDS = (
    "key_id", "role", "algorithm", "status", "public_key_hex",
    "not_before", "not_after",
)
_KEY_STATUSES = ("active", "inactive")
_CONFLICT_CODES = (
    "REQUEST_ID_CONFLICT",
    "NONCE_REPLAY",
    "RUN_ALREADY_REGISTERED",
    "IDENTIFIER_COLLISION",
)

# Anchor fields whose values are derived from the complete plan (Stop B2a law).
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


class PlanAnchorAuthorityError(ValueError):
    """Base class for every typed plan-anchor authority failure."""


class PlanAnchorAuthorityConfigurationError(PlanAnchorAuthorityError):
    """The authority configuration, trust roots or key hygiene failed closed."""


class PlanAnchorIssueRequestError(PlanAnchorAuthorityError):
    """The submitted issue request or body violates the closed wire law."""


class PlanAnchorIssueAuthenticationError(PlanAnchorAuthorityError):
    """The registrar authentication, freshness or key validity failed."""


class PlanAnchorIssueConflictError(PlanAnchorAuthorityError):
    """A durable uniqueness rule rejects this issuance; ``code`` is stable."""

    def __init__(self, code: str, message: str) -> None:
        if code not in _CONFLICT_CODES:
            raise PlanAnchorAuthorityConfigurationError(
                "conflict code is outside the frozen conflict vocabulary"
            )
        super().__init__(message)
        self.code = code


class PlanAnchorAuthorityUnavailableError(PlanAnchorAuthorityError):
    """The authority cannot prove a durable, uncorrupted outcome."""


def _config_fail(message: str) -> None:
    raise PlanAnchorAuthorityConfigurationError(message)


def _persisted_blob(row: Mapping[str, Any], column: str) -> bytes:
    """Return a persisted BLOB column, requiring exact ``bytes`` storage.

    SQLite can store TEXT or INTEGER in a BLOB-affinity column.  ``bytes(text)``
    raises and ``bytes(large_int)`` allocates that many zero bytes, so persisted
    values are never coerced: anything other than real ``bytes`` is sanitized
    unavailability, never decoded, hashed or allocated against.
    """
    try:
        value = row[column]
    except (KeyError, IndexError) as exc:
        raise PlanAnchorAuthorityUnavailableError(
            "persisted registration is missing a required column"
        ) from exc
    if type(value) is not bytes:
        raise PlanAnchorAuthorityUnavailableError(
            "persisted registration column is not stored as bytes"
        )
    return value


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        _config_fail(
            f"{label} must be a printable-ASCII identity of at most 128 characters"
        )
    assert isinstance(value, str)
    return value


def _fresh_mapping_copy(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _config_fail(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    try:
        return json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    except PlanAnchorProtocolError as exc:
        raise PlanAnchorAuthorityConfigurationError(
            f"{label} must be finite canonical JSON"
        ) from exc


def _utc_instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        raise PlanAnchorAuthorityUnavailableError(
            f"{label} must be a whole-second UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, _UTC_FORMAT)
    except ValueError as exc:
        raise PlanAnchorAuthorityUnavailableError(
            f"{label} is not a real UTC instant"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.strftime(_UTC_FORMAT)


def _validated_registrar_bundle(bundle: object) -> tuple[dict[str, Any], bytes]:
    """Closed registrar trust-bundle law: role-separated, sorted, unique, coherent."""
    if not isinstance(bundle, Mapping):
        _config_fail("registrar trust bundle must be a mapping")
    assert isinstance(bundle, Mapping)
    try:
        payload = canonical_json_bytes(dict(bundle))
    except PlanAnchorProtocolError as exc:
        raise PlanAnchorAuthorityConfigurationError(
            "registrar trust bundle must be finite canonical JSON"
        ) from exc
    tree = json.loads(payload.decode("utf-8"))
    if not isinstance(tree, dict) or set(tree) != set(_REGISTRAR_BUNDLE_FIELDS):
        _config_fail(
            "registrar trust bundle must have exactly these keys: "
            + ", ".join(_REGISTRAR_BUNDLE_FIELDS)
        )
    if tree["bundle_version"] != _REGISTRAR_BUNDLE_VERSION:
        _config_fail(
            "registrar trust bundle version must be " + _REGISTRAR_BUNDLE_VERSION
        )
    _identity(tree["authority_id"], "registrar bundle authority_id")
    keys = tree["keys"]
    if not isinstance(keys, list) or not keys:
        _config_fail("registrar trust bundle must list at least one key")
    previous_key_id: str | None = None
    seen_public_keys: set[str] = set()
    for index, entry in enumerate(keys):
        label = f"registrar bundle key[{index}]"
        if not isinstance(entry, dict) or set(entry) != set(_REGISTRAR_KEY_FIELDS):
            _config_fail(
                f"{label} must have exactly these keys: "
                + ", ".join(_REGISTRAR_KEY_FIELDS)
            )
        key_id = _identity(entry["key_id"], f"{label}.key_id")
        if entry["role"] != CONTROL_PLANE_REGISTRAR_ROLE:
            _config_fail(f"{label}.role must be " + CONTROL_PLANE_REGISTRAR_ROLE)
        if entry["algorithm"] != "ed25519":
            _config_fail(f"{label}.algorithm is pinned to ed25519")
        if entry["status"] not in _KEY_STATUSES:
            _config_fail(f"{label}.status must be active or inactive")
        public_key_hex = entry["public_key_hex"]
        if not isinstance(public_key_hex, str) or \
                _PUBLIC_KEY_HEX_RE.fullmatch(public_key_hex) is None:
            _config_fail(f"{label}.public_key_hex must be 64 lowercase hex characters")
        if len(bytes.fromhex(public_key_hex)) != 32:
            _config_fail(f"{label}.public_key_hex must decode to exactly 32 bytes")
        not_before = _utc_instant_config(entry["not_before"], f"{label}.not_before")
        not_after = _utc_instant_config(entry["not_after"], f"{label}.not_after")
        if not not_before < not_after:
            _config_fail(
                f"{label} validity interval must satisfy not_before < not_after"
            )
        if previous_key_id is not None and not key_id > previous_key_id:
            _config_fail(
                "registrar bundle keys must be strictly ordered by unique key_id"
            )
        previous_key_id = key_id
        if public_key_hex in seen_public_keys:
            _config_fail("registrar bundle public-key bytes must be unique")
        seen_public_keys.add(public_key_hex)
    return tree, payload


def _utc_instant_config(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        _config_fail(f"{label} must be a whole-second UTC timestamp")
    assert isinstance(value, str)
    try:
        parsed = datetime.strptime(value, _UTC_FORMAT)
    except ValueError as exc:
        raise PlanAnchorAuthorityConfigurationError(
            f"{label} is not a real UTC instant"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def canonical_registrar_trust_bundle_bytes(bundle: object) -> bytes:
    """Canonical JSON bytes of the complete valid registrar trust bundle."""
    _tree, payload = _validated_registrar_bundle(bundle)
    return payload


def registrar_trust_bundle_hash(bundle: object) -> str:
    """``sha256:`` plus SHA-256 of the canonical registrar trust bundle bytes."""
    return _SHA256_PREFIX + hashlib.sha256(
        canonical_registrar_trust_bundle_bytes(bundle)).hexdigest()


@dataclass(frozen=True, slots=True)
class PlanAnchorAuthorityConfig:
    authority_var_dir: Path
    authority_id: str
    issuer_key_id: str
    issuer_private_key_file: Path = field(repr=False)
    issuer_trust_bundle: Mapping[str, Any]
    expected_issuer_trust_bundle_sha256: str
    registrar_trust_bundle: Mapping[str, Any]
    expected_registrar_trust_bundle_sha256: str
    busy_timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        if not isinstance(self.authority_var_dir, Path) \
                or not self.authority_var_dir.is_absolute():
            _config_fail("authority variable directory must be an absolute path")
        if not isinstance(self.issuer_private_key_file, Path) \
                or not self.issuer_private_key_file.is_absolute():
            _config_fail("issuer private key path must be an absolute path")
        _identity(self.authority_id, "authority_id")
        _identity(self.issuer_key_id, "issuer_key_id")
        if isinstance(self.busy_timeout_ms, bool) \
                or not isinstance(self.busy_timeout_ms, int) \
                or self.busy_timeout_ms <= 0:
            _config_fail("busy timeout must be a positive integer of milliseconds")
        # Deep-copy both public bundles so later caller mutation cannot change the
        # authority's trust roots.
        object.__setattr__(
            self, "issuer_trust_bundle",
            _fresh_mapping_copy(self.issuer_trust_bundle, "issuer trust bundle"),
        )
        object.__setattr__(
            self, "registrar_trust_bundle",
            _fresh_mapping_copy(
                self.registrar_trust_bundle, "registrar trust bundle"),
        )


@dataclass(frozen=True, slots=True)
class PlanAnchorRegistrationResult:
    anchor: dict[str, Any]
    registered_signed_anchor_bytes: bytes
    registration_receipt: dict[str, Any]
    registered_signed_receipt_bytes: bytes
    replayed: bool


class PlanAnchorAuthorityV1:
    """One-transaction plan-anchor issuance over the shared neutral byte law."""

    def __init__(
        self,
        config: PlanAnchorAuthorityConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        token_hex: Callable[[int], str] | None = None,
    ) -> None:
        if not isinstance(config, PlanAnchorAuthorityConfig):
            _config_fail("config must be a PlanAnchorAuthorityConfig")
        self._config = config
        self._clock = clock if clock is not None else _default_clock
        self._token_hex = token_hex if token_hex is not None else secrets.token_hex

        # Both public trust pins are validated before any key lookup, public-key
        # construction or private-key-file open.
        for pin, label in (
            (config.expected_issuer_trust_bundle_sha256, "issuer"),
            (config.expected_registrar_trust_bundle_sha256, "registrar"),
        ):
            if not isinstance(pin, str) or _PREFIXED_SHA256_RE.fullmatch(pin) is None:
                _config_fail(
                    f"expected {label} trust bundle hash must be sha256: plus 64 "
                    "lowercase hex; a bare or uppercase digest is never normalized"
                )
        try:
            issuer_tree = validate_plan_anchor_public_trust_bundle_v1(
                config.issuer_trust_bundle)
            issuer_bytes = canonical_plan_anchor_public_trust_bundle_bytes(
                config.issuer_trust_bundle)
        except PlanAnchorProtocolError as exc:
            raise PlanAnchorAuthorityConfigurationError(str(exc)) from exc
        issuer_hash = _SHA256_PREFIX + hashlib.sha256(issuer_bytes).hexdigest()
        if issuer_hash != config.expected_issuer_trust_bundle_sha256:
            _config_fail(
                "issuer trust bundle hash does not match the separately pinned "
                "expected value"
            )
        registrar_tree, registrar_bytes = _validated_registrar_bundle(
            config.registrar_trust_bundle)
        registrar_hash = _SHA256_PREFIX + hashlib.sha256(
            registrar_bytes).hexdigest()
        if registrar_hash != config.expected_registrar_trust_bundle_sha256:
            _config_fail(
                "registrar trust bundle hash does not match the separately "
                "pinned expected value"
            )
        if issuer_tree["authority_id"] != config.authority_id:
            _config_fail(
                "issuer trust bundle authority does not match the configured "
                "authority"
            )
        if registrar_tree["authority_id"] != config.authority_id:
            _config_fail(
                "registrar trust bundle authority does not match the configured "
                "authority"
            )
        issuer_entry = next(
            (entry for entry in issuer_tree["keys"]
             if entry["key_id"] == config.issuer_key_id),
            None,
        )
        if issuer_entry is None:
            _config_fail(
                "configured issuer key is unknown to the pinned issuer bundle")
        if issuer_entry["status"] != "active":
            _config_fail(
                "configured issuer key is not active in the pinned issuer bundle")
        # Role separation compares the COMPLETE issuer public-key set against the
        # COMPLETE registrar public-key set: any overlap, including a non-selected
        # or inactive key, collapses the two trust roles and is rejected.
        issuer_hexes = {
            entry["public_key_hex"] for entry in issuer_tree["keys"]
        }
        registrar_hexes = {
            entry["public_key_hex"] for entry in registrar_tree["keys"]
        }
        if issuer_hexes & registrar_hexes:
            _config_fail(
                "issuer and registrar public-key sets must be disjoint to "
                "preserve role separation"
            )
        self._issuer_tree = issuer_tree
        self._issuer_hash = issuer_hash
        self._issuer_entry = issuer_entry
        self._registrar_tree = registrar_tree
        self._registrar_hash = registrar_hash

        # Only after both pins have passed may the private seed file be touched.
        self._issuer_private_key = _load_issuer_private_key(
            config.issuer_private_key_file,
            config.authority_var_dir,
            issuer_entry["public_key_hex"],
        )

        # The metadata record travels into the store so a fresh database commits
        # its schema, version, application id and singleton metadata row in one
        # exclusive transaction.  An existing database must already carry its
        # exact row; the authority only compares, never writes or repairs.
        expected_metadata = {
            "schema_version": _SCHEMA_VERSION,
            "authority_id": config.authority_id,
            "issuer_key_id": config.issuer_key_id,
            "issuer_public_key_hex": self._issuer_entry["public_key_hex"],
            "issuer_trust_bundle_sha256": self._issuer_hash,
            "registrar_trust_bundle_sha256": self._registrar_hash,
        }
        try:
            self._store = PlanAnchorAuthorityStoreV1(
                config.authority_var_dir,
                busy_timeout_ms=config.busy_timeout_ms,
                metadata=expected_metadata,
                created_at=_format_utc(self._trusted_now()),
            )
        except PlanAnchorAuthorityStoreError as exc:
            raise PlanAnchorAuthorityUnavailableError(str(exc)) from exc

        self._compare_metadata(expected_metadata)

    # --------------------------------------------------------------- preflight

    def _compare_metadata(self, expected: Mapping[str, str]) -> None:
        try:
            existing = self._store.read_metadata()
        except PlanAnchorAuthorityStoreError as exc:
            raise PlanAnchorAuthorityUnavailableError(str(exc)) from exc
        if existing is None:
            raise PlanAnchorAuthorityUnavailableError(
                "authority metadata row is unreadable"
            )
        for column, value in expected.items():
            if existing.get(column) != value:
                _config_fail(
                    "authority restart configuration does not match the durable "
                    f"metadata for {column}"
                )

    def _trusted_now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
            or value.microsecond != 0
        ):
            raise PlanAnchorAuthorityUnavailableError(
                "trusted clock must return aware UTC time at exact whole-second "
                "precision; the authority never truncates it"
            )
        return value

    def _generated_token(self, label: str) -> str:
        value = self._token_hex(16)
        if not isinstance(value, str) or _TOKEN_HEX_RE.fullmatch(value) is None:
            raise PlanAnchorAuthorityUnavailableError(
                f"token generator returned an unusable {label}"
            )
        return value

    # ------------------------------------------------------------ issue anchor

    def issue_anchor(
        self,
        issue_request: object,
        *,
        body: object,
    ) -> PlanAnchorRegistrationResult:
        try:
            request = validate_plan_anchor_issue_request_v1(issue_request)
            valid_body = validate_plan_anchor_issue_body_v1(body)
            body_bytes = canonical_json_bytes(valid_body)
        except PlanAnchorProtocolError as exc:
            raise PlanAnchorIssueRequestError(str(exc)) from exc
        body_hash = _SHA256_PREFIX + hashlib.sha256(body_bytes).hexdigest()
        if request["body_sha256"] != body_hash:
            raise PlanAnchorIssueRequestError(
                "issue request body hash does not bind the submitted body"
            )
        # The request/plan authority and issuer *semantic* checks are deferred
        # until the durable request-ID lookup proves this is a new request.  An
        # exact retry or any changed-byte retry under a registered request id must
        # yield the stable REQUEST_ID_CONFLICT law, never a semantic 400.
        plan = valid_body["validation_plan"]
        try:
            signed_request_bytes = canonical_json_bytes(request)
            unsigned_request_bytes = (
                canonical_unsigned_plan_anchor_issue_request_bytes(request))
        except PlanAnchorProtocolError as exc:
            raise PlanAnchorIssueRequestError(str(exc)) from exc
        request_timestamp = _utc_instant_auth(
            request["timestamp"], "issue request timestamp")

        registrar_entry = self._registrar_key_entry(request["registrar_key_id"])
        self._registrar_key_valid_at(
            registrar_entry, request_timestamp, "the signed request timestamp")
        self._verify_registrar_signature(
            registrar_entry, request["signature"], unsigned_request_bytes)

        outcome: dict[str, Any] = {}

        def transaction(txn: Any) -> None:
            txn_now = self._trusted_now()
            # Revalidate both trust pins, the body binding, the registrar
            # signature and the current registrar-key state under the write lock.
            self._revalidate_trust_pins()
            if request["body_sha256"] != body_hash:
                raise PlanAnchorIssueRequestError(
                    "issue request body hash does not bind the submitted body"
                )
            self._registrar_key_valid_at(
                registrar_entry, txn_now, "the trusted transaction time")
            self._verify_registrar_signature(
                registrar_entry, request["signature"], unsigned_request_bytes)

            # The exact request-ID lookup comes before any new-request freshness
            # or current issuer-lifetime law: recovery of committed bytes is not
            # a new issuance.
            row = txn.fetch_request(request["request_id"])
            if row is not None:
                stored_request = _persisted_blob(row, "request_bytes")
                stored_body = _persisted_blob(row, "body_bytes")
                if stored_request == signed_request_bytes \
                        and stored_body == body_bytes:
                    self._verify_persisted_record(row)
                    outcome["replayed"] = True
                    return
                # A byte difference is a caller conflict only when the durable
                # row itself is intact; a corrupted row is unavailability, never
                # a conflict verdict against the caller.
                self._verify_persisted_record(row)
                raise PlanAnchorIssueConflictError(
                    "REQUEST_ID_CONFLICT",
                    "request id is already registered with different canonical "
                    "request or body bytes",
                )

            # The request id is confirmed new: only now do the request/plan
            # authority and issuer semantic checks run, so a registered request
            # id never downgrades a conflict into a semantic rejection.
            if request["authority_id"] != self._config.authority_id:
                raise PlanAnchorIssueRequestError(
                    "issue request authority does not match this authority"
                )
            if plan["authorities"]["anchor_authority_id"] \
                    != self._config.authority_id:
                raise PlanAnchorIssueRequestError(
                    "plan anchor authority does not match this authority"
                )
            if plan["authorities"]["anchor_issuer_key_id"] \
                    != self._config.issuer_key_id:
                raise PlanAnchorIssueRequestError(
                    "plan anchor issuer key does not match this authority's signer"
                )

            age_seconds = (txn_now - request_timestamp).total_seconds()
            if not 0 <= age_seconds <= MAX_ISSUE_REQUEST_AGE_SECONDS:
                raise PlanAnchorIssueAuthenticationError(
                    "issue request timestamp is stale or from the future"
                )
            issued_at = txn_now
            expires_at = txn_now + timedelta(seconds=ANCHOR_LIFETIME_SECONDS)
            self._issuer_covers_lifetime(issued_at, expires_at)

            nonce_owner = txn.nonce_request_id(request["nonce"])
            if nonce_owner is not None:
                # A conflict verdict is only issued against an intact durable
                # owner row; a corrupted owner is unavailability, never a
                # downgraded conflict against the caller.
                self._verify_conflict_owner(txn, nonce_owner)
                raise PlanAnchorIssueConflictError(
                    "NONCE_REPLAY",
                    "request nonce was already consumed by another request",
                )
            bindings = self._derive_bindings(plan)
            run_owner = txn.run_request_id(
                bindings["release_id"], bindings["tenant_id"],
                bindings["workspace_id"], bindings["run_id"],
            )
            if run_owner is not None:
                self._verify_conflict_owner(txn, run_owner)
                raise PlanAnchorIssueConflictError(
                    "RUN_ALREADY_REGISTERED",
                    "this run tuple already holds its one registered anchor",
                )

            anchor_id = "vpa-" + self._generated_token("anchor id")
            anchor_nonce = self._generated_token("anchor nonce")
            anchor = {
                "anchor_version": "validation-plan-anchor-v1",
                "anchor_id": anchor_id,
                "release_id": bindings["release_id"],
                "tenant_id": bindings["tenant_id"],
                "workspace_id": bindings["workspace_id"],
                "run_id": bindings["run_id"],
                "confirmed_spec_hash": bindings["confirmed_spec_hash"],
                "snapshot_sha256": bindings["snapshot_sha256"],
                "validation_plan_version": bindings["validation_plan_version"],
                "validation_plan_sha256": bindings["validation_plan_sha256"],
                "locked_rule_sha256": bindings["locked_rule_sha256"],
                "base_costs_sha256": bindings["base_costs_sha256"],
                "final_holdout_fraction": bindings["final_holdout_fraction"],
                "final_window": dict(bindings["final_window"]),
                "issued_at": _format_utc(issued_at),
                "expires_at": _format_utc(expires_at),
                "nonce": anchor_nonce,
                "issuer_key_id": self._config.issuer_key_id,
                "signature_algorithm": "ed25519",
                "signature": "0" * 128,
            }
            unsigned_anchor = self._neutral(
                lambda: canonical_unsigned_anchor_bytes(anchor))
            anchor["signature"] = self._sign(ANCHOR_DOMAIN_V1 + unsigned_anchor)
            signed_anchor = self._neutral(
                lambda: canonical_signed_anchor_bytes(anchor))
            unsigned_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
                unsigned_anchor).hexdigest()
            signed_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
                signed_anchor).hexdigest()
            request_hash = _SHA256_PREFIX + hashlib.sha256(
                signed_request_bytes).hexdigest()

            receipt = {
                "receipt_version": "plan-anchor-registration-receipt-v1",
                "authority_id": self._config.authority_id,
                "request_id": request["request_id"],
                "request_sha256": request_hash,
                "request_nonce": request["nonce"],
                "anchor_id": anchor_id,
                "issuer_key_id": self._config.issuer_key_id,
                "unsigned_anchor_sha256": unsigned_anchor_hash,
                "signed_anchor_sha256": signed_anchor_hash,
                "registered_signed_anchor_bytes_sha256": signed_anchor_hash,
                "registered_at": _format_utc(issued_at),
                "state": "REGISTERED",
                "signature_algorithm": "ed25519",
                "signature": "0" * 128,
            }
            unsigned_receipt = self._neutral(
                lambda: canonical_unsigned_registration_receipt_bytes(receipt))
            receipt["signature"] = self._sign(
                PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1 + unsigned_receipt)
            self._neutral(
                lambda: canonical_unsigned_registration_receipt_bytes(receipt))
            receipt_bytes = self._neutral(lambda: canonical_json_bytes(receipt))
            receipt_hash = _SHA256_PREFIX + hashlib.sha256(
                receipt_bytes).hexdigest()

            txn.insert_registration({
                "request_id": request["request_id"],
                "request_nonce": request["nonce"],
                "registrar_key_id": request["registrar_key_id"],
                "request_timestamp": request["timestamp"],
                "request_sha256": request_hash,
                "request_bytes": signed_request_bytes,
                "body_sha256": body_hash,
                "body_bytes": body_bytes,
                "release_id": bindings["release_id"],
                "tenant_id": bindings["tenant_id"],
                "workspace_id": bindings["workspace_id"],
                "run_id": bindings["run_id"],
                "anchor_id": anchor_id,
                "anchor_nonce": anchor_nonce,
                "issued_at": anchor["issued_at"],
                "expires_at": anchor["expires_at"],
                "registered_at": receipt["registered_at"],
                "issuer_key_id": self._config.issuer_key_id,
                "unsigned_anchor_sha256": unsigned_anchor_hash,
                "unsigned_anchor_bytes": unsigned_anchor,
                "anchor_signature_hex": anchor["signature"],
                "signed_anchor_sha256": signed_anchor_hash,
                "registered_signed_anchor_bytes_sha256": signed_anchor_hash,
                "signed_anchor_bytes": signed_anchor,
                "receipt_sha256": receipt_hash,
                "receipt_bytes": receipt_bytes,
                "state": "REGISTERED",
            })
            outcome["replayed"] = False

        try:
            self._store.run_registration_transaction(transaction)
        except PlanAnchorAuthorityError:
            raise
        except PlanAnchorAuthorityStoreError as exc:
            if exc.collision:
                raise PlanAnchorIssueConflictError(
                    "IDENTIFIER_COLLISION",
                    "authority-generated anchor identifiers collided; the "
                    "request is never treated as idempotent success",
                ) from exc
            raise PlanAnchorAuthorityUnavailableError(str(exc)) from exc

        # New issuance and exact replay both finish through the same fresh
        # post-commit read + full verification on a new connection, so a replay
        # never returns the in-transaction row.
        try:
            row = self._store.read_registration(request["request_id"])
        except PlanAnchorAuthorityStoreError as exc:
            raise PlanAnchorAuthorityUnavailableError(str(exc)) from exc
        if row is None:
            raise PlanAnchorAuthorityUnavailableError(
                "committed registration could not be re-read"
            )
        self._verify_persisted_record(row)
        return self._result_from_row(row, replayed=bool(outcome["replayed"]))

    # ------------------------------------------------------------- inner steps

    def _verify_conflict_owner(self, txn: Any, owner_request_id: str) -> None:
        owner_row = txn.fetch_request(owner_request_id)
        if owner_row is None:
            raise PlanAnchorAuthorityUnavailableError(
                "a durable owner row referenced by a uniqueness index is missing"
            )
        self._verify_persisted_record(owner_row)

    def _neutral(self, step: Callable[[], Any]) -> Any:
        try:
            return step()
        except PlanAnchorProtocolError as exc:
            raise PlanAnchorAuthorityUnavailableError(str(exc)) from exc

    def _derive_bindings(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        return self._neutral(lambda: derive_anchor_bindings_from_plan_v3(plan))

    def _sign(self, message: bytes) -> str:
        try:
            return self._issuer_private_key.sign(message).hex()
        except Exception as exc:  # fail closed; never partially publish
            raise PlanAnchorAuthorityUnavailableError(
                "issuer signing failed before commit"
            ) from exc

    def _revalidate_trust_pins(self) -> None:
        issuer_bytes = self._neutral(
            lambda: canonical_plan_anchor_public_trust_bundle_bytes(
                self._config.issuer_trust_bundle))
        issuer_hash = _SHA256_PREFIX + hashlib.sha256(issuer_bytes).hexdigest()
        _tree, registrar_bytes = _validated_registrar_bundle(
            self._config.registrar_trust_bundle)
        registrar_hash = _SHA256_PREFIX + hashlib.sha256(
            registrar_bytes).hexdigest()
        if issuer_hash != self._config.expected_issuer_trust_bundle_sha256 \
                or registrar_hash != \
                self._config.expected_registrar_trust_bundle_sha256:
            raise PlanAnchorAuthorityUnavailableError(
                "trust bundle pins failed revalidation inside the transaction"
            )

    def _registrar_key_entry(self, registrar_key_id: str) -> dict[str, Any]:
        entry = next(
            (candidate for candidate in self._registrar_tree["keys"]
             if candidate["key_id"] == registrar_key_id),
            None,
        )
        if entry is None:
            raise PlanAnchorIssueAuthenticationError(
                "registrar key is unknown to the pinned registrar bundle"
            )
        if entry["role"] != CONTROL_PLANE_REGISTRAR_ROLE:
            raise PlanAnchorIssueAuthenticationError(
                "registrar key does not carry the registrar role"
            )
        if entry["status"] != "active":
            raise PlanAnchorIssueAuthenticationError(
                "registrar key is not active in the pinned registrar bundle"
            )
        return entry

    def _registrar_key_valid_at(
        self, entry: Mapping[str, Any], instant: datetime, label: str
    ) -> None:
        not_before = _utc_instant_auth(entry["not_before"], "registrar not_before")
        not_after = _utc_instant_auth(entry["not_after"], "registrar not_after")
        if not not_before <= instant < not_after:
            raise PlanAnchorIssueAuthenticationError(
                f"registrar key is not valid at {label}"
            )

    def _verify_registrar_signature(
        self, entry: Mapping[str, Any], signature_hex: str, unsigned: bytes
    ) -> None:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(entry["public_key_hex"]))
        except Exception as exc:
            raise PlanAnchorIssueAuthenticationError(
                "registrar public key is not a usable Ed25519 key"
            ) from exc
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1 + unsigned,
            )
        except InvalidSignature as exc:
            raise PlanAnchorIssueAuthenticationError(
                "registrar signature does not verify under the pinned domain "
                "and key"
            ) from exc

    def _issuer_covers_lifetime(
        self, issued_at: datetime, expires_at: datetime
    ) -> None:
        entry = self._issuer_entry
        if entry["status"] != "active":
            raise PlanAnchorAuthorityUnavailableError(
                "issuer key is not active in the pinned issuer bundle"
            )
        not_before = _utc_instant(entry["not_before"], "issuer not_before")
        not_after = _utc_instant(entry["not_after"], "issuer not_after")
        if not (not_before <= issued_at and expires_at <= not_after):
            raise PlanAnchorAuthorityUnavailableError(
                "issuer key cannot cover the complete fixed anchor lifetime; "
                "the authority never silently shortens it"
            )

    def _verify_issuer_signature(
        self, signature_hex: str, message: bytes, label: str
    ) -> None:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(self._issuer_entry["public_key_hex"]))
            public_key.verify(bytes.fromhex(signature_hex), message)
        except Exception as exc:
            raise PlanAnchorAuthorityUnavailableError(
                f"persisted {label} signature failed verification"
            ) from exc

    # -------------------------------------------------- persisted verification

    def _verify_persisted_record(self, row: Mapping[str, Any]) -> None:
        """Complete fail-closed verification of one durable registration row."""
        unavailable = PlanAnchorAuthorityUnavailableError
        try:
            stored_request_bytes = _persisted_blob(row, "request_bytes")
            stored_body_bytes = _persisted_blob(row, "body_bytes")
            stored_signed_anchor = _persisted_blob(row, "signed_anchor_bytes")
            stored_unsigned_anchor = _persisted_blob(row, "unsigned_anchor_bytes")
            stored_receipt_bytes = _persisted_blob(row, "receipt_bytes")
            request = validate_plan_anchor_issue_request_v1(
                json.loads(stored_request_bytes.decode("utf-8")))
            request_bytes = canonical_json_bytes(request)
            unsigned_request = (
                canonical_unsigned_plan_anchor_issue_request_bytes(request))
            body = validate_plan_anchor_issue_body_v1(
                json.loads(stored_body_bytes.decode("utf-8")))
            body_bytes = canonical_json_bytes(body)
            anchor = json.loads(stored_signed_anchor.decode("utf-8"))
            signed_anchor = canonical_signed_anchor_bytes(anchor)
            unsigned_anchor = canonical_unsigned_anchor_bytes(anchor)
            receipt = json.loads(stored_receipt_bytes.decode("utf-8"))
            unsigned_receipt = (
                canonical_unsigned_registration_receipt_bytes(receipt))
            receipt_bytes = canonical_json_bytes(receipt)
            bindings = derive_anchor_bindings_from_plan_v3(
                body["validation_plan"])
        except (PlanAnchorProtocolError, ValueError, TypeError, KeyError,
                RecursionError) as exc:
            # RecursionError covers a deeply nested corrupted JSON BLOB; it maps
            # to sanitized unavailability, never a raw 500.
            raise unavailable(
                "persisted registration bytes failed closed re-validation"
            ) from exc

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted registration failed the {label} verification"
                )

        check(request_bytes == stored_request_bytes, "request byte identity")
        check(body_bytes == stored_body_bytes, "body byte identity")
        check(receipt_bytes == stored_receipt_bytes, "receipt byte identity")
        check(signed_anchor == stored_signed_anchor, "anchor byte identity")
        check(unsigned_anchor == stored_unsigned_anchor,
              "unsigned anchor byte identity")

        request_hash = _SHA256_PREFIX + hashlib.sha256(request_bytes).hexdigest()
        body_hash = _SHA256_PREFIX + hashlib.sha256(body_bytes).hexdigest()
        unsigned_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
            unsigned_anchor).hexdigest()
        signed_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
            signed_anchor).hexdigest()
        receipt_hash = _SHA256_PREFIX + hashlib.sha256(receipt_bytes).hexdigest()

        check(row["request_id"] == request["request_id"], "request id")
        check(row["request_nonce"] == request["nonce"], "request nonce")
        check(row["registrar_key_id"] == request["registrar_key_id"],
              "registrar key id")
        check(row["request_timestamp"] == request["timestamp"],
              "request timestamp")
        check(row["request_sha256"] == request_hash, "request hash")
        check(row["body_sha256"] == body_hash, "body hash")
        check(request["body_sha256"] == body_hash, "request body binding")
        check(request["authority_id"] == self._config.authority_id,
              "request authority")
        plan_authorities = body["validation_plan"]["authorities"]
        check(plan_authorities["anchor_authority_id"] == self._config.authority_id,
              "plan anchor authority")
        check(plan_authorities["anchor_issuer_key_id"]
              == self._config.issuer_key_id, "plan issuer key")

        for anchor_field in _PLAN_BOUND_ANCHOR_FIELDS:
            check(anchor[anchor_field] == bindings[anchor_field],
                  f"anchor {anchor_field} binding")
        check(row["release_id"] == bindings["release_id"], "release column")
        check(row["tenant_id"] == bindings["tenant_id"], "tenant column")
        check(row["workspace_id"] == bindings["workspace_id"], "workspace column")
        check(row["run_id"] == bindings["run_id"], "run column")
        check(anchor["anchor_id"] == row["anchor_id"], "anchor id")
        check(anchor["nonce"] == row["anchor_nonce"], "anchor nonce")
        check(anchor["issued_at"] == row["issued_at"], "issued_at column")
        check(anchor["expires_at"] == row["expires_at"], "expires_at column")
        check(anchor["issuer_key_id"] == row["issuer_key_id"], "issuer column")
        check(anchor["issuer_key_id"] == self._config.issuer_key_id,
              "issuer identity")
        check(anchor["signature"] == row["anchor_signature_hex"],
              "anchor signature column")
        check(row["unsigned_anchor_sha256"] == unsigned_anchor_hash,
              "unsigned anchor hash")
        check(row["signed_anchor_sha256"] == signed_anchor_hash,
              "signed anchor hash")
        check(row["registered_signed_anchor_bytes_sha256"] == signed_anchor_hash,
              "registered bytes hash")
        check(row["receipt_sha256"] == receipt_hash, "receipt hash")
        check(row["state"] == "REGISTERED", "terminal state")

        issued_at = _utc_instant(anchor["issued_at"], "persisted issued_at")
        expires_at = _utc_instant(anchor["expires_at"], "persisted expires_at")
        registered_at = _utc_instant(
            row["registered_at"], "persisted registered_at")
        check(
            (expires_at - issued_at).total_seconds() == ANCHOR_LIFETIME_SECONDS,
            "fixed anchor lifetime",
        )
        # The frozen issuance law sets registered_at == issued_at exactly; any
        # drift is a tampered or non-conforming record.
        check(registered_at == issued_at, "registered_at equals issued_at")
        check(registered_at < expires_at, "registration precedes expiry")

        # The persisted issuer signature/key validity is rechecked at the
        # original issue and registration instants — never at the current time.
        not_before = _utc_instant(
            self._issuer_entry["not_before"], "issuer not_before")
        not_after = _utc_instant(
            self._issuer_entry["not_after"], "issuer not_after")
        check(not_before <= issued_at and expires_at <= not_after,
              "issuer key coverage at the original instants")
        check(not_before <= registered_at < not_after,
              "issuer key validity at registration")

        check(receipt["request_id"] == row["request_id"], "receipt request id")
        check(receipt["request_nonce"] == row["request_nonce"],
              "receipt request nonce")
        check(receipt["request_sha256"] == row["request_sha256"],
              "receipt request hash")
        check(receipt["authority_id"] == self._config.authority_id,
              "receipt authority")
        check(receipt["anchor_id"] == row["anchor_id"], "receipt anchor id")
        check(receipt["issuer_key_id"] == row["issuer_key_id"],
              "receipt issuer key")
        check(receipt["unsigned_anchor_sha256"] == unsigned_anchor_hash,
              "receipt unsigned hash")
        check(receipt["signed_anchor_sha256"] == signed_anchor_hash,
              "receipt signed hash")
        check(receipt["registered_signed_anchor_bytes_sha256"]
              == signed_anchor_hash, "receipt registered hash")
        check(receipt["registered_at"] == row["registered_at"],
              "receipt registration time")
        check(receipt["state"] == "REGISTERED", "receipt state")

        registrar_entry = next(
            (candidate for candidate in self._registrar_tree["keys"]
             if candidate["key_id"] == request["registrar_key_id"]),
            None,
        )
        check(registrar_entry is not None, "registrar key registration")
        assert registrar_entry is not None
        try:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(registrar_entry["public_key_hex"])
            ).verify(
                bytes.fromhex(request["signature"]),
                PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1 + unsigned_request,
            )
        except Exception as exc:
            raise unavailable(
                "persisted request signature failed verification"
            ) from exc
        self._verify_issuer_signature(
            anchor["signature"], ANCHOR_DOMAIN_V1 + unsigned_anchor, "anchor")
        self._verify_issuer_signature(
            receipt["signature"],
            PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1 + unsigned_receipt,
            "receipt",
        )

    def _result_from_row(
        self, row: Mapping[str, Any], *, replayed: bool
    ) -> PlanAnchorRegistrationResult:
        signed_anchor = _persisted_blob(row, "signed_anchor_bytes")
        receipt_bytes = _persisted_blob(row, "receipt_bytes")
        try:
            anchor = json.loads(signed_anchor.decode("utf-8"))
            receipt = json.loads(receipt_bytes.decode("utf-8"))
        except (ValueError, TypeError, RecursionError) as exc:
            raise PlanAnchorAuthorityUnavailableError(
                "persisted registration bytes could not be projected"
            ) from exc
        return PlanAnchorRegistrationResult(
            anchor=anchor,
            registered_signed_anchor_bytes=signed_anchor,
            registration_receipt=receipt,
            registered_signed_receipt_bytes=receipt_bytes,
            replayed=replayed,
        )


def _utc_instant_auth(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        raise PlanAnchorIssueRequestError(
            f"{label} must be a whole-second UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, _UTC_FORMAT)
    except ValueError as exc:
        raise PlanAnchorIssueRequestError(
            f"{label} is not a real UTC instant"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _load_issuer_private_key(
    key_path: Path, var_dir: Path, expected_public_hex: str
) -> Ed25519PrivateKey:
    """Load the raw 32-byte Ed25519 seed under strict fail-closed hygiene.

    Every message is deliberately generic: no key contents and no detailed
    secret path ever appear in errors, repr or logs.
    """
    generic = "issuer private key file failed the fail-closed hygiene checks"

    def fail() -> None:
        # ``from None`` suppresses any OSError context so no base path or
        # filename can reach ``traceback.format_exception``.
        raise PlanAnchorAuthorityConfigurationError(generic) from None

    if not key_path.is_absolute() or not var_dir.is_absolute():
        fail()
    # Every path-touching syscall is wrapped: an OSError carries the filename,
    # so it must never surface in a traceback.
    try:
        if not var_dir.is_dir():
            fail()
        for path in (key_path, var_dir):
            for component in (path, *path.parents):
                if component.is_symlink():
                    fail()
        for directory in (key_path.parent, var_dir):
            info = os.lstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() \
                    or stat.S_IMODE(info.st_mode) != 0o700:
                fail()
        # A pre-open lstat guard keeps a FIFO from blocking the open below; the
        # opened descriptor's fstat remains the authoritative check.
        pre = os.lstat(key_path)
        if not stat.S_ISREG(pre.st_mode):
            fail()
        fd = os.open(str(key_path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except PlanAnchorAuthorityConfigurationError:
        raise
    except OSError:
        raise PlanAnchorAuthorityConfigurationError(generic) from None
    try:
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                    or info.st_nlink != 1 \
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
                fail()
            seed = os.read(fd, 33)
            trailing = os.read(fd, 1)
        except PlanAnchorAuthorityConfigurationError:
            raise
        except OSError:
            raise PlanAnchorAuthorityConfigurationError(generic) from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if len(seed) != 32 or trailing != b"":
        raise PlanAnchorAuthorityConfigurationError(generic) from None
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        raise PlanAnchorAuthorityConfigurationError(generic) from None
    derived_hex = private_key.public_key().public_bytes_raw().hex()
    if derived_hex != expected_public_hex:
        _config_fail(
            "issuer private key does not correspond to the pinned issuer "
            "public key"
        )
    return private_key


__all__ = [
    "ANCHOR_LIFETIME_SECONDS",
    "MAX_ISSUE_REQUEST_AGE_SECONDS",
    "PlanAnchorAuthorityConfig",
    "PlanAnchorRegistrationResult",
    "PlanAnchorAuthorityError",
    "PlanAnchorAuthorityConfigurationError",
    "PlanAnchorIssueRequestError",
    "PlanAnchorIssueAuthenticationError",
    "PlanAnchorIssueConflictError",
    "PlanAnchorAuthorityUnavailableError",
    "canonical_registrar_trust_bundle_bytes",
    "registrar_trust_bundle_hash",
    "PlanAnchorAuthorityV1",
]
