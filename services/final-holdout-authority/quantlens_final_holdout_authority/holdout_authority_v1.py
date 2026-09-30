"""Dormant Gate E Stop B3a/B3b final-holdout authority.

``FinalHoldoutAuthorityV1`` authenticates signed ``CONTROL_PLANE_REGISTRAR``
requests over the neutral final-holdout byte law, derives and AES-256-GCM
encrypts one capsule payload — exactly the reviewed warm-up plus final suffix and
its frozen same-as-universe benchmark — independently validates one externally
signed B2 plan anchor and registration receipt, and atomically persists only
signed request bytes, safe lineage, ciphertext and exact signed safe-response
bytes in its authority-only SQLite store.  A byte-identical retry returns the
originally persisted safe response bytes.  The coherent B3b slice adds
FINAL_EVALUATOR lease issuance and trusted-time lease expiry/completion-timeout
processing with signed terminal audits.  Consume, complete, audit retrieval and
HTTP service behavior remain outside this milestone.

Response law: only an authenticated result that newly owns its reserved request
ID and nonce persists its canonical signed wrapper bytes in the same transaction
as state.  Pre-authentication invalid/authentication failures, request-ID
conflicts, nonce replays and unavailable results are signed-but-ephemeral when
the signer is usable, never attach to another request's row and leave at most a
bounded untrusted-attempt hash.  If response signing itself fails, the
transaction rolls back and ``FinalHoldoutAuthorityUnavailableError`` is raised;
no application layer may synthesize signed bytes after that failure.

This module imports only the standard library, ``cryptography``, the two neutral
protocol modules and its private ``holdout_store_v1``.  It never imports the
worker, API, B2 authority, pandas, runner, Battery, report or web code, opens no
socket, reads no environment and generates no key.  Nothing active imports it;
focused Stop B3a/B3b tests are its only consumers.
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantlens_schema.final_holdout_access_protocol_v1 import (
    FINAL_EVALUATOR_ROLE,
    FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1,
    FINAL_HOLDOUT_ACCESS_AUDIT_VERSION_V1,
    FINAL_HOLDOUT_ACCESS_PROTOCOL,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
    FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1,
    FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
    FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1,
    FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_ERROR_STATUS_MESSAGES,
    FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_LEASE_PATH_V1,
    FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1,
    FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1,
    FinalHoldoutAccessProtocolError,
    MAX_CAPSULE_REGISTRATION_BODY_BYTES,
    MAX_CLIENT_REQUEST_BODY_BYTES,
    canonical_final_holdout_capsule_aad_v1_bytes,
    canonical_final_holdout_consume_request_body_bytes,
    canonical_final_holdout_lease_request_body_bytes,
    canonical_final_holdout_client_trust_bundle_bytes,
    canonical_final_holdout_authority_trust_bundle_bytes,
    canonical_final_holdout_response_wrapper_bytes,
    canonical_json_bytes,
    canonical_unsigned_final_holdout_client_request_bytes,
    canonical_signed_final_holdout_access_audit_bytes,
    canonical_unsigned_final_holdout_access_audit_bytes,
    canonical_unsigned_final_holdout_service_response_bytes,
    validate_final_holdout_anchor_registration_body_v1,
    validate_final_holdout_authority_trust_bundle_v1,
    validate_final_holdout_capsule_payload_v1,
    validate_final_holdout_capsule_registration_body_v1,
    validate_final_holdout_client_request_v1,
    validate_final_holdout_client_trust_bundle_v1,
    validate_final_holdout_consume_request_body_v1,
    validate_final_holdout_lease_request_body_v1,
    validate_final_holdout_response_wrapper_v1,
    FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
    FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1,
    FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE,
    canonical_final_holdout_completion_request_body_bytes,
    canonical_final_holdout_audit_retrieval_body_bytes,
    validate_final_holdout_completion_request_body_v1,
    validate_final_holdout_audit_retrieval_body_v1,
)
from quantlens_schema.plan_anchor_protocol_v1 import (
    ANCHOR_DOMAIN_V1,
    CONTROL_PLANE_REGISTRAR_ROLE,
    PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1,
    PlanAnchorProtocolError,
    canonical_plan_anchor_public_trust_bundle_bytes,
    canonical_signed_anchor_bytes,
    canonical_unsigned_anchor_bytes,
    canonical_unsigned_registration_receipt_bytes,
    derive_anchor_bindings_from_plan_v3,
    validate_complete_validation_plan_v3,
    validate_plan_anchor_public_trust_bundle_v1,
)

from .holdout_store_v1 import (
    AUTHORITY_DB_SCHEMA_VERSION,
    MAX_BUSY_TIMEOUT_MS,
    FinalHoldoutAuthorityStoreError,
    FinalHoldoutAuthorityStoreV1,
)

MAX_CLIENT_REQUEST_AGE_SECONDS = 60

# One registration draws authority-generated identifiers (capsule ID and AES
# nonce) from a single shared budget of 16 attempts total; exhaustion is
# AUTHORITY_UNAVAILABLE, never fallback.  Frozen by the Codex B3a acceptance
# clarification of 2026-07-22.
IDENTIFIER_GENERATION_ATTEMPTS = 16

_MAX_ANCHOR_LIFETIME_SECONDS = 3600
_SHA256_PREFIX = "sha256:"
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPSULE_ID_RE = re.compile(r"^fha-cap-[0-9a-f]{32}$")
_LEASE_ID_RE = re.compile(r"^fha-lease-[0-9a-f]{32}$")
_REQUEST_ID_RE = re.compile(r"^fha-req-[0-9a-f]{32}$")
_AES_NONCE_HEX_RE = re.compile(r"^[0-9a-f]{24}$")
_ANCHOR_ID_RE = re.compile(r"^vpa-[0-9a-f]{32}$")
_NONCE_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE_HEX_RE = re.compile(r"^[0-9a-f]{128}$")
_TOKEN_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_AES_KEY_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CAPSULE_OPERATION = "CAPSULE_REGISTER"
_ANCHOR_OPERATION = "ANCHOR_REGISTER"
_LEASE_OPERATION = "LEASE"
_CONSUME_OPERATION = "CONSUME"
_COMPLETE_OPERATION = "COMPLETE"
_AUDIT_RETRIEVE_OPERATION = "AUDIT_RETRIEVE"

_LEASE_LIFETIME_SECONDS = 120
_COMPLETION_LIFETIME_SECONDS = 1800

# Anchor fields whose values must equal the bindings derived from the complete
# registered plan (the accepted Stop B2a law).
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


class FinalHoldoutAuthorityError(ValueError):
    """Base class for every typed final-holdout authority failure.

    When the signer was usable the error carries the signed-but-ephemeral (or,
    for persisted semantic denials, the exact persisted) response: its status
    code, frozen code, closed body, signed envelope and canonical wrapper bytes.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        response_body: dict[str, Any] | None = None,
        service_response: dict[str, Any] | None = None,
        signed_response_wrapper_bytes: bytes | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.response_body = response_body
        self.service_response = service_response
        self.signed_response_wrapper_bytes = signed_response_wrapper_bytes


class FinalHoldoutAuthorityConfigurationError(FinalHoldoutAuthorityError):
    """The authority configuration, trust roots or key hygiene failed closed."""


class FinalHoldoutRequestError(FinalHoldoutAuthorityError):
    """The submitted request or body violates the closed wire law (400)."""


class FinalHoldoutAuthenticationError(FinalHoldoutAuthorityError):
    """The caller authentication, role, freshness or key validity failed."""


class FinalHoldoutConflictError(FinalHoldoutAuthorityError):
    """A durable uniqueness, binding or freshness rule rejects this request."""


class FinalHoldoutAuthorityUnavailableError(FinalHoldoutAuthorityError):
    """The authority cannot prove a durable, uncorrupted, signable outcome."""


def _config_fail(message: str) -> None:
    raise FinalHoldoutAuthorityConfigurationError(message)


def _persisted_blob(row: Mapping[str, Any], column: str) -> bytes:
    """Return a persisted BLOB column, requiring exact ``bytes`` storage."""
    try:
        value = row[column]
    except (KeyError, IndexError) as exc:
        raise FinalHoldoutAuthorityUnavailableError(
            "persisted authority row is missing a required column"
        ) from exc
    if type(value) is not bytes:
        raise FinalHoldoutAuthorityUnavailableError(
            "persisted authority column is not stored as bytes"
        )
    return value


def _fresh_mapping_copy(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _config_fail(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    try:
        return json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    except FinalHoldoutAccessProtocolError as exc:
        raise FinalHoldoutAuthorityConfigurationError(
            f"{label} must be finite canonical JSON"
        ) from exc


def _utc_instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        raise FinalHoldoutAuthorityUnavailableError(
            f"{label} must be a whole-second UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, _UTC_FORMAT)
    except ValueError as exc:
        raise FinalHoldoutAuthorityUnavailableError(
            f"{label} is not a real UTC instant"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.strftime(_UTC_FORMAT)


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class FinalHoldoutAuthorityConfig:
    authority_var_dir: Path
    authority_id: str
    authority_signer_key_id: str
    authority_signer_private_key_file: Path = field(repr=False)
    authority_trust_bundle: Mapping[str, Any]
    expected_authority_trust_bundle_sha256: str
    client_trust_bundle: Mapping[str, Any]
    expected_client_trust_bundle_sha256: str
    plan_anchor_issuer_trust_bundle: Mapping[str, Any]
    expected_plan_anchor_issuer_trust_bundle_sha256: str
    payload_encryption_key_id: str
    payload_encryption_key_file: Path = field(repr=False)
    busy_timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        if not isinstance(self.authority_var_dir, Path) \
                or not self.authority_var_dir.is_absolute():
            _config_fail("authority variable directory must be an absolute path")
        if not isinstance(self.authority_signer_private_key_file, Path) \
                or not self.authority_signer_private_key_file.is_absolute():
            _config_fail("authority signer key path must be an absolute path")
        if not isinstance(self.payload_encryption_key_file, Path) \
                or not self.payload_encryption_key_file.is_absolute():
            _config_fail("payload encryption key path must be an absolute path")
        for value, label in (
            (self.authority_id, "authority_id"),
            (self.authority_signer_key_id, "authority_signer_key_id"),
            (self.payload_encryption_key_id, "payload_encryption_key_id"),
        ):
            if not isinstance(value, str) \
                    or re.fullmatch(r"[\x21-\x7e]{1,128}", value) is None:
                _config_fail(
                    f"{label} must be a printable-ASCII identity of at most 128 "
                    "characters"
                )
        if isinstance(self.busy_timeout_ms, bool) \
                or not isinstance(self.busy_timeout_ms, int) \
                or not 1 <= self.busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
            _config_fail(
                "busy timeout must be a non-bool integer between 1 and "
                f"{MAX_BUSY_TIMEOUT_MS} milliseconds inclusive"
            )
        # Deep-copy every public bundle so later caller mutation cannot change
        # the authority's trust roots.
        object.__setattr__(
            self, "authority_trust_bundle",
            _fresh_mapping_copy(
                self.authority_trust_bundle, "authority trust bundle"),
        )
        object.__setattr__(
            self, "client_trust_bundle",
            _fresh_mapping_copy(self.client_trust_bundle, "client trust bundle"),
        )
        object.__setattr__(
            self, "plan_anchor_issuer_trust_bundle",
            _fresh_mapping_copy(
                self.plan_anchor_issuer_trust_bundle,
                "plan-anchor issuer trust bundle"),
        )


@dataclass(frozen=True, slots=True)
class FinalHoldoutCapsuleRegistrationResult:
    response_body: dict[str, Any]
    service_response: dict[str, Any]
    signed_response_wrapper_bytes: bytes
    replayed: bool


@dataclass(frozen=True, slots=True)
class FinalHoldoutAnchorRegistrationResult:
    response_body: dict[str, Any]
    service_response: dict[str, Any]
    signed_response_wrapper_bytes: bytes
    replayed: bool


def _load_private_key_bytes(key_path: Path, *, expected_length: int) -> bytes:
    """Read one strict owner-only private key file; generic errors only."""
    generic = "authority private key file failed the fail-closed hygiene checks"

    def fail() -> None:
        raise FinalHoldoutAuthorityConfigurationError(generic) from None

    if not key_path.is_absolute():
        fail()
    try:
        for component in (key_path, *key_path.parents):
            if component.is_symlink():
                fail()
        info = os.lstat(key_path.parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() \
                or stat.S_IMODE(info.st_mode) != 0o700:
            fail()
        pre = os.lstat(key_path)
        if not stat.S_ISREG(pre.st_mode):
            fail()
        fd = os.open(str(key_path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FinalHoldoutAuthorityConfigurationError:
        raise
    except OSError:
        raise FinalHoldoutAuthorityConfigurationError(generic) from None
    try:
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                    or info.st_nlink != 1 \
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
                fail()
            payload = os.read(fd, expected_length + 2)
            trailing = os.read(fd, 1)
        except FinalHoldoutAuthorityConfigurationError:
            raise
        except OSError:
            raise FinalHoldoutAuthorityConfigurationError(generic) from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if trailing != b"":
        raise FinalHoldoutAuthorityConfigurationError(generic) from None
    return payload


class FinalHoldoutAuthorityV1:
    """Transactional registration plus the coherent B3b lease/expiry slice."""

    def __init__(
        self,
        config: FinalHoldoutAuthorityConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        token_hex: Callable[[int], str] | None = None,
        nonce_bytes: Callable[[int], bytes] | None = None,
    ) -> None:
        if not isinstance(config, FinalHoldoutAuthorityConfig):
            _config_fail("config must be a FinalHoldoutAuthorityConfig")
        self._config = config
        self._clock = clock if clock is not None else _default_clock
        self._token_hex = token_hex if token_hex is not None else secrets.token_hex
        self._nonce_bytes = (
            nonce_bytes if nonce_bytes is not None else secrets.token_bytes)

        # Every expected hash pin is validated before any bundle read, key
        # lookup, public-key construction or private-key-file open.
        for pin, label in (
            (config.expected_authority_trust_bundle_sha256, "authority"),
            (config.expected_client_trust_bundle_sha256, "client"),
            (config.expected_plan_anchor_issuer_trust_bundle_sha256,
             "plan-anchor issuer"),
        ):
            if not isinstance(pin, str) or _PREFIXED_SHA256_RE.fullmatch(pin) is None:
                _config_fail(
                    f"expected {label} trust bundle hash must be sha256: plus 64 "
                    "lowercase hex; a bare or uppercase digest is never normalized"
                )

        try:
            authority_tree = validate_final_holdout_authority_trust_bundle_v1(
                config.authority_trust_bundle)
            authority_bytes = canonical_final_holdout_authority_trust_bundle_bytes(
                config.authority_trust_bundle)
            client_tree = validate_final_holdout_client_trust_bundle_v1(
                config.client_trust_bundle)
            client_bytes = canonical_final_holdout_client_trust_bundle_bytes(
                config.client_trust_bundle)
        except FinalHoldoutAccessProtocolError as exc:
            raise FinalHoldoutAuthorityConfigurationError(str(exc)) from exc
        try:
            issuer_tree = validate_plan_anchor_public_trust_bundle_v1(
                config.plan_anchor_issuer_trust_bundle)
            issuer_bytes = canonical_plan_anchor_public_trust_bundle_bytes(
                config.plan_anchor_issuer_trust_bundle)
        except PlanAnchorProtocolError as exc:
            raise FinalHoldoutAuthorityConfigurationError(str(exc)) from exc

        authority_hash = _SHA256_PREFIX + hashlib.sha256(authority_bytes).hexdigest()
        client_hash = _SHA256_PREFIX + hashlib.sha256(client_bytes).hexdigest()
        issuer_hash = _SHA256_PREFIX + hashlib.sha256(issuer_bytes).hexdigest()
        if authority_hash != config.expected_authority_trust_bundle_sha256:
            _config_fail(
                "authority trust bundle hash does not match the separately "
                "pinned expected value"
            )
        if client_hash != config.expected_client_trust_bundle_sha256:
            _config_fail(
                "client trust bundle hash does not match the separately pinned "
                "expected value"
            )
        if issuer_hash != config.expected_plan_anchor_issuer_trust_bundle_sha256:
            _config_fail(
                "plan-anchor issuer trust bundle hash does not match the "
                "separately pinned expected value"
            )
        if authority_tree["authority_id"] != config.authority_id:
            _config_fail(
                "authority trust bundle authority does not match the configured "
                "authority"
            )
        if client_tree["authority_id"] != config.authority_id:
            _config_fail(
                "client trust bundle authority does not match the configured "
                "authority"
            )

        signer_entry = next(
            (entry for entry in authority_tree["keys"]
             if entry["key_id"] == config.authority_signer_key_id),
            None,
        )
        if signer_entry is None:
            _config_fail(
                "configured authority signer key is unknown to the pinned "
                "authority bundle"
            )
        assert signer_entry is not None
        if signer_entry["status"] != "active":
            _config_fail(
                "configured authority signer key is not active in the pinned "
                "authority bundle"
            )
        construction_now = self._trusted_now()
        self._signer_valid_at_or_config_fail(signer_entry, construction_now)

        # At least one active registrar key and one active evaluator key must be
        # configured, and role separation compares the COMPLETE public-key sets:
        # any overlap between client keys and the authority signer collapses the
        # trust roles and is rejected.
        active_roles = {
            entry["role"]
            for entry in client_tree["keys"] if entry["status"] == "active"
        }
        if CONTROL_PLANE_REGISTRAR_ROLE not in active_roles \
                or FINAL_EVALUATOR_ROLE not in active_roles:
            _config_fail(
                "client trust bundle must configure an active registrar key and "
                "an active evaluator key"
            )
        client_hexes = {entry["public_key_hex"] for entry in client_tree["keys"]}
        authority_hexes = {
            entry["public_key_hex"] for entry in authority_tree["keys"]
        }
        if client_hexes & authority_hexes:
            _config_fail(
                "client and authority public-key sets must be disjoint to "
                "preserve role separation"
            )

        self._authority_tree = authority_tree
        self._authority_hash = authority_hash
        self._signer_entry = signer_entry
        self._client_tree = client_tree
        self._client_hash = client_hash
        self._issuer_tree = issuer_tree
        self._issuer_hash = issuer_hash

        # Only after every pin has passed may private key material be touched.
        signer_seed = _load_private_key_bytes(
            config.authority_signer_private_key_file, expected_length=32)
        if len(signer_seed) != 32:
            raise FinalHoldoutAuthorityConfigurationError(
                "authority private key file failed the fail-closed hygiene checks"
            ) from None
        try:
            self._signer_private_key = Ed25519PrivateKey.from_private_bytes(
                signer_seed)
        except Exception:
            raise FinalHoldoutAuthorityConfigurationError(
                "authority private key file failed the fail-closed hygiene checks"
            ) from None
        derived_hex = (
            self._signer_private_key.public_key().public_bytes_raw().hex())
        if derived_hex != signer_entry["public_key_hex"]:
            _config_fail(
                "authority signer private key does not correspond to the pinned "
                "authority public key"
            )

        aes_payload = _load_private_key_bytes(
            config.payload_encryption_key_file, expected_length=65)
        aes_text = aes_payload.decode("ascii", errors="replace")
        if aes_text.endswith("\n"):
            aes_text = aes_text[:-1]
        if _AES_KEY_HEX_RE.fullmatch(aes_text) is None:
            raise FinalHoldoutAuthorityConfigurationError(
                "authority private key file failed the fail-closed hygiene checks"
            ) from None
        self._aes_key = bytes.fromhex(aes_text)
        if len(self._aes_key) != 32:
            raise FinalHoldoutAuthorityConfigurationError(
                "authority private key file failed the fail-closed hygiene checks"
            ) from None

        # Role/material separation: signer seed, AES key and every configured
        # public key must be pairwise distinct byte strings, and the two private
        # key files must be distinct by normalized path and inode.
        if self._aes_key == signer_seed:
            _config_fail(
                "authority signer and payload encryption material must be "
                "distinct"
            )
        if self._aes_key.hex() in (client_hexes | authority_hexes):
            _config_fail(
                "payload encryption material must be distinct from every "
                "configured public key"
            )
        if signer_seed.hex() in (client_hexes | authority_hexes):
            _config_fail(
                "authority signer private material must be distinct from every "
                "configured public key"
            )
        signer_path = Path(
            os.path.realpath(config.authority_signer_private_key_file))
        aes_path = Path(os.path.realpath(config.payload_encryption_key_file))
        if signer_path == aes_path:
            _config_fail(
                "authority signer and payload encryption key paths must be "
                "distinct"
            )
        try:
            signer_stat = os.stat(signer_path)
            aes_stat = os.stat(aes_path)
        except OSError:
            raise FinalHoldoutAuthorityConfigurationError(
                "authority private key file failed the fail-closed hygiene checks"
            ) from None
        if (signer_stat.st_dev, signer_stat.st_ino) \
                == (aes_stat.st_dev, aes_stat.st_ino):
            _config_fail(
                "authority signer and payload encryption key files must be "
                "distinct inodes"
            )

        expected_metadata = {
            "schema_version": AUTHORITY_DB_SCHEMA_VERSION,
            "authority_id": config.authority_id,
            "authority_signer_key_id": config.authority_signer_key_id,
            "authority_signer_public_key_hex": signer_entry["public_key_hex"],
            "authority_trust_bundle_sha256": authority_hash,
            "client_trust_bundle_sha256": client_hash,
            "plan_anchor_issuer_trust_bundle_sha256": issuer_hash,
            "payload_encryption_key_id": config.payload_encryption_key_id,
            "payload_encryption_key_sha256": (
                _SHA256_PREFIX + hashlib.sha256(self._aes_key).hexdigest()),
        }
        try:
            self._store = FinalHoldoutAuthorityStoreV1(
                config.authority_var_dir,
                busy_timeout_ms=config.busy_timeout_ms,
                metadata=expected_metadata,
                created_at=_format_utc(construction_now),
            )
        except FinalHoldoutAuthorityStoreError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc
        self._compare_metadata(expected_metadata)

    # --------------------------------------------------------------- preflight

    def _compare_metadata(self, expected: Mapping[str, str]) -> None:
        try:
            existing = self._store.read_metadata()
        except FinalHoldoutAuthorityStoreError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc
        if existing is None:
            raise FinalHoldoutAuthorityUnavailableError(
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
            raise FinalHoldoutAuthorityUnavailableError(
                "trusted clock must return aware UTC time at exact whole-second "
                "precision; the authority never truncates it"
            )
        return value

    def _signer_valid_at_or_config_fail(
        self, entry: Mapping[str, Any], instant: datetime
    ) -> None:
        not_before = _utc_instant(entry["not_before"], "signer not_before")
        not_after = _utc_instant(entry["not_after"], "signer not_after")
        if not not_before <= instant < not_after:
            _config_fail(
                "configured authority signer key is not valid at the trusted time"
            )

    def _signer_usable_at(self, instant: datetime) -> None:
        entry = self._signer_entry
        if entry["status"] != "active":
            raise FinalHoldoutAuthorityUnavailableError(
                "authority signer key is not active in the pinned bundle"
            )
        not_before = _utc_instant(entry["not_before"], "signer not_before")
        not_after = _utc_instant(entry["not_after"], "signer not_after")
        if not not_before <= instant < not_after:
            raise FinalHoldoutAuthorityUnavailableError(
                "authority signer key is not valid at the response signature time"
            )

    def _generated_token(self, label: str) -> str:
        value = self._token_hex(16)
        if not isinstance(value, str) or _TOKEN_HEX_RE.fullmatch(value) is None:
            raise FinalHoldoutAuthorityUnavailableError(
                f"token generator returned an unusable {label}"
            )
        return value

    def _generated_aes_nonce(self) -> bytes:
        value = self._nonce_bytes(12)
        if type(value) is not bytes or len(value) != 12:
            raise FinalHoldoutAuthorityUnavailableError(
                "nonce generator returned unusable AES nonce material"
            )
        return value

    def _neutral(self, step: Callable[[], Any]) -> Any:
        try:
            return step()
        except FinalHoldoutAccessProtocolError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc

    def _sign(self, message: bytes) -> str:
        try:
            return self._signer_private_key.sign(message).hex()
        except Exception as exc:  # fail closed; never partially publish
            raise FinalHoldoutAuthorityUnavailableError(
                "authority response signing failed; the transaction rolls back "
                "and no signed bytes are synthesized"
            ) from exc

    # ---------------------------------------------------------- signed responses

    def _signed_wrapper(
        self,
        *,
        status_code: int,
        body: Mapping[str, Any],
        request_id: str,
        request_nonce: str,
        now: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, bytes]:
        """Sign one closed response; returns (response, body, wrapper/env/body bytes)."""
        self._signer_usable_at(now)
        body_bytes = self._neutral(lambda: canonical_json_bytes(dict(body)))
        response = {
            "response_version": FINAL_HOLDOUT_SERVICE_RESPONSE_VERSION_V1,
            "authority_id": self._config.authority_id,
            "authority_key_id": self._config.authority_signer_key_id,
            "status_code": status_code,
            "request_id": request_id,
            "request_nonce": request_nonce,
            "timestamp": _format_utc(now),
            "body_sha256": _SHA256_PREFIX + hashlib.sha256(body_bytes).hexdigest(),
            "signature_algorithm": "ed25519",
            "signature": "0" * 128,
        }
        unsigned = self._neutral(
            lambda: canonical_unsigned_final_holdout_service_response_bytes(
                response))
        response["signature"] = self._sign(
            FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1 + unsigned)
        wrapper = {"service_response": response, "body": dict(body)}
        wrapper_bytes = self._neutral(
            lambda: canonical_final_holdout_response_wrapper_bytes(wrapper))
        response_bytes = self._neutral(lambda: canonical_json_bytes(response))
        fresh = json.loads(wrapper_bytes.decode("utf-8"))
        return (
            fresh["service_response"], fresh["body"],
            wrapper_bytes, response_bytes, body_bytes,
        )

    def _raise_signed_error(
        self,
        error_class: type[FinalHoldoutAuthorityError],
        *,
        status_code: int,
        code: str,
        request_id: str,
        request_nonce: str,
        message: str,
        record_hash: str | None = None,
    ) -> None:
        """Raise one signed-but-ephemeral error; records a bounded attempt hash."""
        now = self._trusted_now()
        body = {
            "body_version": FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1,
            "code": code,
            "message": FINAL_HOLDOUT_ERROR_STATUS_MESSAGES[status_code],
            "request_id": request_id,
        }
        response, fresh_body, wrapper_bytes, _response_bytes, _body_bytes = (
            self._signed_wrapper(
                status_code=status_code, body=body,
                request_id=request_id, request_nonce=request_nonce, now=now,
            ))
        if record_hash is not None:
            self._record_untrusted_attempt(record_hash, code, now)
        raise error_class(
            message,
            status_code=status_code,
            code=code,
            response_body=fresh_body,
            service_response=response,
            signed_response_wrapper_bytes=wrapper_bytes,
        )

    def _raise_signed_unavailable(
        self, auth: Mapping[str, Any], message: str
    ) -> None:
        """One signed-but-ephemeral 503; only signer failure stays unsigned.

        Trust-pin, encryption, identifier-exhaustion, durable-store and
        durable-revalidation failures with a usable signer produce a signed
        ``AUTHORITY_UNAVAILABLE`` response that reserves nothing and persists
        nothing.  If signing that response itself fails, the plain
        ``FinalHoldoutAuthorityUnavailableError`` raised by the signer path
        propagates instead — no application layer synthesizes signed bytes.
        """
        self._raise_signed_error(
            FinalHoldoutAuthorityUnavailableError,
            status_code=503,
            code="AUTHORITY_UNAVAILABLE",
            request_id=auth["request"]["request_id"],
            request_nonce=auth["request"]["nonce"],
            message=message,
            record_hash=auth["request_hash"],
        )

    def _record_untrusted_attempt(
        self, request_hash: str, reason_code: str, now: datetime
    ) -> None:
        try:
            self._store.run_transaction(
                lambda txn: txn.record_untrusted_attempt(
                    request_hash, reason_code, _format_utc(now)))
        except FinalHoldoutAuthorityStoreError:
            # The bounded rejection record is best-effort; the caller's typed
            # failure is never masked by a full or unavailable attempt table.
            pass

    # ------------------------------------------------------------ authentication

    def _authenticated_request(
        self,
        client_request: object,
        *,
        operation: str,
        expected_path: str,
        body_bytes: bytes,
        body_version: str,
        max_body_bytes: int,
        required_role: str = CONTROL_PLANE_REGISTRAR_ROLE,
    ) -> dict[str, Any]:
        """Authenticate one signed request for ``required_role`` outside the txn.

        B3a registration requires the registrar role; B3b access requires the
        FINAL_EVALUATOR role.  A caller presenting the wrong role that still
        fully authenticates under its stated key receives a signed 403; an
        unknown key, invalid signature, wrong domain or out-of-window key
        remains a signed 401.  The closed store schema also forbids reserving an
        operation under a role its CHECK does not permit, so both outcomes are
        signed but ephemeral."""
        try:
            request = validate_final_holdout_client_request_v1(client_request)
            unsigned_bytes = (
                canonical_unsigned_final_holdout_client_request_bytes(request))
            signed_bytes = canonical_json_bytes(request)
        except FinalHoldoutAccessProtocolError as exc:
            # A request that cannot yield its closed identity cannot receive a
            # signed response; only a bounded rejection hash is recorded.
            digest = _SHA256_PREFIX + hashlib.sha256(
                repr(client_request).encode("utf-8", errors="replace")).hexdigest()
            self._record_untrusted_attempt(
                digest, "INVALID_REQUEST", self._trusted_now())
            raise FinalHoldoutRequestError(str(exc)) from exc

        request_hash = _SHA256_PREFIX + hashlib.sha256(signed_bytes).hexdigest()
        request_id = request["request_id"]
        request_nonce = request["nonce"]

        def signed_reject(
            error_class: type[FinalHoldoutAuthorityError],
            status_code: int, code: str, message: str,
        ) -> None:
            self._raise_signed_error(
                error_class,
                status_code=status_code, code=code,
                request_id=request_id, request_nonce=request_nonce,
                message=message, record_hash=request_hash,
            )

        if request["authority_id"] != self._config.authority_id:
            signed_reject(
                FinalHoldoutAuthenticationError, 401, "AUTHENTICATION_FAILED",
                "request authority does not match this authority")
        if request["path"] != expected_path or request["method"] != "POST":
            signed_reject(
                FinalHoldoutRequestError, 400, "INVALID_REQUEST",
                "request path does not bind this operation's frozen route")
        if len(body_bytes) < 2 or len(body_bytes) > max_body_bytes:
            signed_reject(
                FinalHoldoutRequestError, 400, "INVALID_REQUEST",
                "canonical body size is outside the frozen operation cap")
        body_hash = _SHA256_PREFIX + hashlib.sha256(body_bytes).hexdigest()
        if request["body_sha256"] != body_hash:
            signed_reject(
                FinalHoldoutRequestError, 400, "INVALID_REQUEST",
                "request body hash does not bind the submitted body")
        request_timestamp = _utc_instant(
            request["timestamp"], "request timestamp")
        if request["caller_role"] != required_role:
            # Only a request that fully AUTHENTICATES under the stated wrong-role
            # key receives the role denial; an unknown key, invalid signature,
            # wrong domain or out-of-window key remains a signed authentication
            # failure.  Either way the closed store schema forbids reserving an
            # operation under a role its CHECK does not permit, so both outcomes
            # are signed but ephemeral.
            entry = self._client_key_entry(
                request["caller_role"], request["caller_key_id"])
            if entry is None or entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, request_timestamp):
                signed_reject(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is unknown or not active in the pinned client "
                    "bundle")
            assert entry is not None
            try:
                self._verify_client_signature(entry, request, unsigned_bytes)
            except FinalHoldoutAuthenticationError:
                signed_reject(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request signature does not hold under the pinned domain "
                    "and key")
            signed_reject(
                FinalHoldoutAuthenticationError, 403, "ROLE_NOT_PERMITTED",
                "the caller role is not permitted to perform this operation")
        entry = self._client_key_entry(
            required_role, request["caller_key_id"])
        if entry is None or entry["status"] != "active":
            signed_reject(
                FinalHoldoutAuthenticationError, 401, "AUTHENTICATION_FAILED",
                "caller key is unknown or not active in the pinned client bundle")
        assert entry is not None
        if not self._client_key_valid_at(entry, request_timestamp):
            signed_reject(
                FinalHoldoutAuthenticationError, 401, "AUTHENTICATION_FAILED",
                "caller key is not valid at the signed request timestamp")
        try:
            self._verify_client_signature(entry, request, unsigned_bytes)
        except FinalHoldoutAuthenticationError:
            signed_reject(
                FinalHoldoutAuthenticationError, 401, "AUTHENTICATION_FAILED",
                "request signature does not hold under the pinned domain and key")
        # Freshness is deliberately NOT judged here: the exact request-ID lookup
        # inside the transaction comes first, because recovery of committed
        # bytes is not a new registration (the accepted B2b law).
        return {
            "request_timestamp": request_timestamp,
            "request": request,
            "entry": entry,
            "signed_bytes": signed_bytes,
            "unsigned_bytes": unsigned_bytes,
            "request_hash": request_hash,
            "body_hash": body_hash,
            "operation": operation,
            "body_version": body_version,
            "body_size": len(body_bytes),
            "path": expected_path,
        }

    def _client_key_entry(
        self, role: str, key_id: str
    ) -> dict[str, Any] | None:
        return next(
            (entry for entry in self._client_tree["keys"]
             if entry["key_id"] == key_id and entry["role"] == role),
            None,
        )

    @staticmethod
    def _client_key_valid_at(
        entry: Mapping[str, Any], instant: datetime
    ) -> bool:
        not_before = _utc_instant(entry["not_before"], "client key not_before")
        not_after = _utc_instant(entry["not_after"], "client key not_after")
        return not_before <= instant < not_after

    def _verify_client_signature(
        self, entry: Mapping[str, Any], request: Mapping[str, Any],
        unsigned_bytes: bytes,
    ) -> None:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(entry["public_key_hex"]))
        except Exception as exc:
            raise FinalHoldoutAuthenticationError(
                "client public key is not a usable Ed25519 key"
            ) from exc
        try:
            public_key.verify(
                bytes.fromhex(request["signature"]),
                FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1 + unsigned_bytes,
            )
        except InvalidSignature as exc:
            raise FinalHoldoutAuthenticationError(
                "request signature does not hold under the pinned domain and key"
            ) from exc

    def _revalidate_trust_pins(self) -> None:
        authority_bytes = self._neutral(
            lambda: canonical_final_holdout_authority_trust_bundle_bytes(
                self._config.authority_trust_bundle))
        client_bytes = self._neutral(
            lambda: canonical_final_holdout_client_trust_bundle_bytes(
                self._config.client_trust_bundle))
        try:
            issuer_bytes = canonical_plan_anchor_public_trust_bundle_bytes(
                self._config.plan_anchor_issuer_trust_bundle)
        except PlanAnchorProtocolError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc
        if (
            _SHA256_PREFIX + hashlib.sha256(authority_bytes).hexdigest()
            != self._config.expected_authority_trust_bundle_sha256
            or _SHA256_PREFIX + hashlib.sha256(client_bytes).hexdigest()
            != self._config.expected_client_trust_bundle_sha256
            or _SHA256_PREFIX + hashlib.sha256(issuer_bytes).hexdigest()
            != self._config.expected_plan_anchor_issuer_trust_bundle_sha256
        ):
            raise FinalHoldoutAuthorityUnavailableError(
                "trust bundle pins failed revalidation inside the transaction"
            )

    # ----------------------------------------------------- durable request logic

    def _resolve_request_row(
        self,
        txn: Any,
        auth: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Replay/conflict law: exact retry recovers; only proved success owners conflict.

        Changed bytes against a fully reconstructed success owner produce a
        caller conflict.  A denial owner cannot independently reconstruct its
        original body size, so changed request-id or nonce collisions fail
        closed as authority unavailability instead.
        """
        request = auth["request"]
        row = txn.fetch_authenticated_request(request["request_id"])
        if row is not None:
            stored_request = _persisted_blob(row, "request_bytes")
            if stored_request == auth["signed_bytes"] \
                    and row["body_sha256"] == auth["body_hash"] \
                    and row["operation"] == auth["operation"]:
                return row
            # A byte difference is a caller conflict only when the durable
            # owner — request row, signed result and its complete success or
            # denial lineage — fully re-proves; a corrupted owner is
            # unavailability, never a conflict verdict against the caller (the
            # accepted B2b law).
            self._verify_owner_state(txn, row)
            raise _PendingSignedError(
                FinalHoldoutConflictError, 409, "REQUEST_ID_CONFLICT",
                "request id is already reserved with different canonical "
                "request or body bytes",
            )
        nonce_owner = txn.nonce_request_id(request["nonce"])
        if nonce_owner is not None:
            owner_row = txn.fetch_authenticated_request(nonce_owner)
            if owner_row is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a durable nonce owner referenced by a uniqueness index "
                    "is missing"
                )
            self._verify_owner_state(txn, owner_row)
            raise _PendingSignedError(
                FinalHoldoutConflictError, 409, "NONCE_REPLAY",
                "request nonce was already consumed by another request",
            )
        return None

    def _verify_owner_state(self, txn: Any, owner_row: Mapping[str, Any]) -> None:
        """Fully re-prove one durable owner before any conflict verdict.

        The owner's signed result, self-authenticating request row and complete
        lineage are all required.  A SUCCESS owner must own exactly its own
        intact lineage row, whose validators re-prove the exact body size and
        hash by canonical reconstruction; only then may a caller-facing
        ``REQUEST_ID_CONFLICT``/``NONCE_REPLAY`` verdict be issued.  A DENIAL
        owner deliberately has no durable body or lineage, so its
        ``body_size_bytes`` has no independent reconstruction source; under the
        conservative law a denial owner is therefore NEVER a fully proved
        conflict basis — even after every provable column re-validates and the
        absence of lineage is proven, the outcome is sanitized unavailability,
        never a conflict verdict against the caller.  (A byte-identical denial
        replay remains fully supported: there the CURRENT request supplies the
        exact body for hash-and-size binding.)
        """
        owner_id = str(owner_row["request_id"])
        operation = str(owner_row["operation"])
        if operation == _CONSUME_OPERATION:
            # A successful CONSUME owner deliberately persists NO safe response
            # (plaintext is never stored).  It is reproved from the lease it
            # consumed: its canonical body and authenticated_at=consumed_at are
            # independently reconstructible from the durable lease/capsule/
            # anchor rows, so a consume owner IS a fully proved basis for a
            # caller-facing REQUEST_ID_CONFLICT/NONCE_REPLAY verdict.
            lease = txn.fetch_lease_by_consume_request(owner_id)
            if lease is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a reserved consume request owns no durable consumed lease"
                )
            self._verify_persisted_lease_lineage(txn, lease)
            return
        if operation == _COMPLETE_OPERATION:
            # A COMPLETE owner carries a lease-scoped body whose exact canonical
            # bytes are reconstructible from the completed lease lineage; the
            # lease re-proof re-binds this exact completion request/body, its
            # safe wrapper and its evaluator ownership, so a completion owner IS
            # a fully proved conflict basis (never a degraded unavailability).
            lease = txn.fetch_lease_by_completion_request(owner_id)
            if lease is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a reserved completion request owns no durable completed "
                    "lease")
            self._verify_persisted_lease_lineage(txn, lease)
            return
        if operation == _AUDIT_RETRIEVE_OPERATION:
            # A retrieval owner is likewise fully reconstructible: its canonical
            # body, evaluator ownership and terminal/pending snapshot are all
            # re-proved from the durable lease lineage and terminal audit.
            safe_row = txn.fetch_safe_response(owner_id)
            if safe_row is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a reserved audit retrieval request has no persisted safe "
                    "response")
            self._verify_persisted_retrieval(txn, owner_row, safe_row)
            return
        safe_row = txn.fetch_safe_response(owner_id)
        if safe_row is None:
            raise FinalHoldoutAuthorityUnavailableError(
                "a reserved request has no persisted safe response"
            )
        self._verify_persisted_safe_response(owner_row, safe_row)
        self._verify_persisted_request(owner_row, safe_row=safe_row)
        code = str(safe_row["response_code"])
        capsule_row = txn.fetch_capsule_by_request(owner_id)
        anchor_row = txn.fetch_anchor_by_request(owner_id)
        if code == "CAPSULE_REGISTERED":
            if capsule_row is None or anchor_row is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "an owner success lineage is missing or contradictory"
                )
            self._verify_persisted_capsule(txn, capsule_row)
        elif code == "ANCHOR_REGISTERED":
            if anchor_row is None or capsule_row is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "an owner success lineage is missing or contradictory"
                )
            capsule = txn.fetch_capsule(str(anchor_row["capsule_id"]))
            if capsule is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a registered anchor references a missing capsule row"
                )
            plan, bindings = self._verify_persisted_capsule(txn, capsule)
            lease = txn.fetch_lease_by_anchor(anchor_row["anchor_id"])
            if lease is None:
                self._verify_persisted_anchor(
                    txn, anchor_row, capsule, plan, bindings,
                    expected_state="REGISTERED")
            else:
                proved_lease, proved_capsule, proved_anchor, _decision = (
                    self._verify_persisted_lease_lineage(txn, lease))
                if proved_lease["anchor_id"] != anchor_row["anchor_id"] \
                        or proved_anchor["anchor_id"] != anchor_row["anchor_id"] \
                        or proved_capsule["capsule_id"] != capsule["capsule_id"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "an anchor replay references contradictory lease "
                        "lineage")
        elif code == "LEASE_ISSUED":
            if capsule_row is not None or anchor_row is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a lease owner has contradictory registration lineage")
            lease_row = txn.fetch_lease_by_request(owner_id)
            if lease_row is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "an issued lease owner has no durable lease row")
            self._verify_persisted_lease_lineage(txn, lease_row)
        else:
            if capsule_row is not None or anchor_row is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a denied registration owns a durable lineage row"
                )
            # Conservative law: a denial owner's body size has no independent
            # durable reconstruction source, so it can never be a fully proved
            # basis for a conflict verdict against a different caller.
            raise FinalHoldoutAuthorityUnavailableError(
                "a denial owner cannot support a conflict verdict; its body "
                "size lacks an independent durable reconstruction source"
            )

    def _reserve_request(
        self, txn: Any, auth: Mapping[str, Any], now: datetime
    ) -> None:
        """Reserve the authenticated request ID and nonce inside the transaction."""
        request = auth["request"]
        txn.insert_authenticated_request({
            "request_id": request["request_id"],
            "request_nonce": request["nonce"],
            "operation": auth["operation"],
            "authority_id": request["authority_id"],
            "caller_role": request["caller_role"],
            "caller_key_id": request["caller_key_id"],
            "method": request["method"],
            "path": auth["path"],
            "request_timestamp": request["timestamp"],
            "request_sha256": auth["request_hash"],
            "request_bytes": auth["signed_bytes"],
            "body_version": auth["body_version"],
            "body_sha256": auth["body_hash"],
            "body_size_bytes": auth["body_size"],
            "authenticated_at": _format_utc(now),
        })

    def _prepare_result(
        self,
        auth: Mapping[str, Any],
        *,
        status_code: int,
        body: Mapping[str, Any],
        now: datetime,
    ) -> tuple[
        dict[str, Any], dict[str, Any], bytes, dict[str, Any]
    ]:
        """Sign and prepare one safe result without changing durable state."""
        request = auth["request"]
        response, fresh_body, wrapper_bytes, response_bytes, body_bytes = (
            self._signed_wrapper(
                status_code=status_code, body=body,
                request_id=request["request_id"],
                request_nonce=request["nonce"], now=now,
            ))
        record = {
            "request_id": request["request_id"],
            "operation": auth["operation"],
            "status_code": status_code,
            "response_code": str(fresh_body["code"]),
            "authority_key_id": self._config.authority_signer_key_id,
            "response_timestamp": response["timestamp"],
            "body_sha256": response["body_sha256"],
            "body_bytes": body_bytes,
            "service_response_sha256": (
                _SHA256_PREFIX + hashlib.sha256(response_bytes).hexdigest()),
            "service_response_bytes": response_bytes,
            "response_wrapper_sha256": (
                _SHA256_PREFIX + hashlib.sha256(wrapper_bytes).hexdigest()),
            "response_wrapper_bytes": wrapper_bytes,
            "contains_plaintext": 0,
            "created_at": _format_utc(now),
        }
        return response, fresh_body, wrapper_bytes, record

    @staticmethod
    def _insert_prepared_result(
        txn: Any,
        prepared: tuple[
            dict[str, Any], dict[str, Any], bytes, dict[str, Any]
        ],
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        """Insert bytes that were already signed before state mutation."""
        response, fresh_body, wrapper_bytes, record = prepared
        txn.insert_safe_response(record)
        return response, fresh_body, wrapper_bytes

    def _persist_result(
        self,
        txn: Any,
        auth: Mapping[str, Any],
        *,
        status_code: int,
        body: Mapping[str, Any],
        now: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        """Prepare and persist exact signed bytes for a reserved request."""
        return self._insert_prepared_result(
            txn,
            self._prepare_result(
                auth, status_code=status_code, body=body, now=now),
        )

    def _verify_persisted_safe_response(
        self,
        request_row: Mapping[str, Any],
        safe_row: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        """Complete fail-closed re-proof of one safe_service_responses row.

        Every column is bound: exact storage classes; the wrapper, envelope and
        body byte identities recanonicalize exactly; all three hash columns
        recompute; status/code/key/timestamps/created_at/contains_plaintext
        bind the signed envelope, the frozen status law and the configured
        signer; the response signature re-verifies under the response domain;
        and the row cross-binds its owning authenticated request (id, nonce,
        operation).  Returns the revalidated (response, body, wrapper bytes).
        """
        unavailable = FinalHoldoutAuthorityUnavailableError

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted safe response failed the {label} re-validation"
                )

        wrapper_bytes = _persisted_blob(safe_row, "response_wrapper_bytes")
        body_bytes = _persisted_blob(safe_row, "body_bytes")
        response_bytes = _persisted_blob(safe_row, "service_response_bytes")
        for column in (
            "request_id", "operation", "response_code", "authority_key_id",
            "response_timestamp", "body_sha256", "service_response_sha256",
            "response_wrapper_sha256", "created_at",
        ):
            check(type(safe_row[column]) is str, f"{column} storage class")
        for column in ("status_code", "contains_plaintext"):
            check(type(safe_row[column]) is int, f"{column} storage class")
        check(safe_row["contains_plaintext"] == 0, "plaintext flag")
        check(
            _REQUEST_ID_RE.fullmatch(safe_row["request_id"]) is not None,
            "request id grammar",
        )
        for column in ("body_sha256", "service_response_sha256",
                       "response_wrapper_sha256"):
            check(
                _PREFIXED_SHA256_RE.fullmatch(safe_row[column]) is not None,
                f"{column} grammar",
            )
        _utc_instant(safe_row["response_timestamp"],
                     "persisted response timestamp")
        _utc_instant(safe_row["created_at"], "persisted response created_at")
        check(
            safe_row["created_at"] == safe_row["response_timestamp"],
            "created_at binding",
        )
        try:
            wrapper = json.loads(wrapper_bytes.decode("utf-8"))
            valid = validate_final_holdout_response_wrapper_v1(wrapper)
            recomputed = canonical_final_holdout_response_wrapper_bytes(wrapper)
        except (FinalHoldoutAccessProtocolError, ValueError, TypeError,
                RecursionError) as exc:
            raise unavailable(
                "persisted response bytes failed closed re-validation"
            ) from exc
        response = valid["service_response"]
        body = valid["body"]
        check(recomputed == wrapper_bytes, "wrapper byte identity")
        check(canonical_json_bytes(body) == body_bytes, "body byte identity")
        check(canonical_json_bytes(response) == response_bytes,
              "envelope byte identity")
        check(
            safe_row["body_sha256"] == response["body_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(body_bytes).hexdigest(),
            "body hash",
        )
        check(
            safe_row["service_response_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(response_bytes).hexdigest(),
            "envelope hash",
        )
        check(
            safe_row["response_wrapper_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(wrapper_bytes).hexdigest(),
            "wrapper hash",
        )
        check(safe_row["status_code"] == response["status_code"],
              "status binding")
        check(safe_row["response_code"] == body["code"], "code binding")
        check(
            safe_row["authority_key_id"] == response["authority_key_id"]
            == self._config.authority_signer_key_id,
            "signer identity",
        )
        check(response["authority_id"] == self._config.authority_id,
              "authority identity")
        check(safe_row["response_timestamp"] == response["timestamp"],
              "timestamp binding")
        check(
            safe_row["request_id"] == response["request_id"]
            == request_row["request_id"],
            "request binding",
        )
        check(response["request_nonce"] == request_row["request_nonce"],
              "request nonce binding")
        check(safe_row["operation"] == request_row["operation"],
              "operation binding")
        try:
            unsigned = canonical_unsigned_final_holdout_service_response_bytes(
                response)
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(self._signer_entry["public_key_hex"])
            ).verify(
                bytes.fromhex(response["signature"]),
                FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1 + unsigned,
            )
        except (FinalHoldoutAccessProtocolError, InvalidSignature,
                ValueError) as exc:
            raise unavailable(
                "persisted response signature failed re-validation"
            ) from exc
        return response, body, wrapper_bytes

    def _recovered_result(
        self, auth: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], bytes, int, str]:
        """Fresh post-commit read plus complete durable-row revalidation."""
        request_id = auth["request"]["request_id"]
        try:
            safe_row = self._store.read_safe_response(request_id)
            request_row = self._store.read_authenticated_request(request_id)
        except FinalHoldoutAuthorityStoreError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc
        if safe_row is None or request_row is None:
            raise FinalHoldoutAuthorityUnavailableError(
                "committed safe response could not be re-read"
            )
        self._verify_persisted_request(
            request_row, safe_row=safe_row, auth=auth)
        response, body, wrapper_bytes = self._verify_persisted_safe_response(
            request_row, safe_row)
        return response, body, wrapper_bytes, int(safe_row["status_code"]), \
            str(safe_row["response_code"])

    def _finish(
        self,
        auth: Mapping[str, Any],
        outcome: Mapping[str, Any],
        result_class: type,
    ):
        response, body, wrapper_bytes, status, code = (
            self._recovered_result(auth))
        if outcome["kind"] == "denial":
            error_class: type[FinalHoldoutAuthorityError]
            if status == 400:
                error_class = FinalHoldoutRequestError
            elif status in (401, 403):
                error_class = FinalHoldoutAuthenticationError
            elif status == 503:
                error_class = FinalHoldoutAuthorityUnavailableError
            else:
                error_class = FinalHoldoutConflictError
            raise error_class(
                str(outcome["message"]),
                status_code=status,
                code=code,
                response_body=body,
                service_response=response,
                signed_response_wrapper_bytes=wrapper_bytes,
            )
        return result_class(
            response_body=body,
            service_response=response,
            signed_response_wrapper_bytes=wrapper_bytes,
            replayed=bool(outcome["kind"] == "replayed"),
        )

    def _run_registration(
        self,
        auth: Mapping[str, Any],
        semantic: Callable[[Any, datetime], tuple[int, dict[str, Any]] | dict],
        result_class: type,
        *,
        verify_replay: Callable[[Any, Mapping[str, Any]], None],
    ):
        """Shared transaction skeleton for both registration operations."""
        outcome: dict[str, Any] = {}

        def transaction(txn: Any) -> None:
            txn_now = self._trusted_now()
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, txn_now)
            entry = auth["entry"]
            if entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, txn_now):
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is not valid at the trusted transaction time",
                )
                return
            try:
                replay_row = self._resolve_request_row(txn, auth)
            except _PendingSignedError as pending:
                # Due lease transitions are part of every explicit operation.
                # Commit them before emitting this ephemeral caller failure.
                outcome["pending"] = pending
                return
            if replay_row is not None:
                stored = txn.fetch_safe_response(auth["request"]["request_id"])
                if stored is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved request has no persisted safe response"
                    )
                # An exact replay re-proves the durable state it recovers:
                # the reserved request row, the persisted safe response and
                # every operation-specific lineage row fail closed on any
                # tampering.
                self._verify_persisted_request(
                    replay_row, safe_row=stored, auth=auth)
                response, _body, _wrapper = (
                    self._verify_persisted_safe_response(replay_row, stored))
                # Explicit current-auth binding: the recovered signed envelope
                # must carry exactly this request's identity and nonce.
                if response["request_id"] != auth["request"]["request_id"] \
                        or response["request_nonce"] != auth["request"]["nonce"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "the persisted response does not bind the current "
                        "authenticated request identity and nonce"
                    )
                verify_replay(txn, stored)
                outcome["kind"] = "replayed" \
                    if int(stored["status_code"]) == 200 else "denial"
                outcome["message"] = (
                    "the persisted result for this exact request was recovered")
                return
            age_seconds = (
                txn_now - auth["request_timestamp"]).total_seconds()
            if not 0 <= age_seconds <= MAX_CLIENT_REQUEST_AGE_SECONDS:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request timestamp is stale or from the future",
                )
                return
            self._reserve_request(txn, auth, txn_now)
            decided = semantic(txn, txn_now)
            status_code, body, kind, message = decided
            self._persist_result(
                txn, auth, status_code=status_code, body=body, now=txn_now)
            outcome["kind"] = kind
            outcome["message"] = message

        try:
            self._store.run_transaction(transaction)
            pending = outcome.get("pending")
            if isinstance(pending, _PendingSignedError):
                self._raise_signed_error(
                    pending.error_class,
                    status_code=pending.status_code,
                    code=pending.code,
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message=pending.message,
                    record_hash=auth["request_hash"],
                )
        except _PendingSignedError as pending:
            self._raise_signed_error(
                pending.error_class,
                status_code=pending.status_code,
                code=pending.code,
                request_id=auth["request"]["request_id"],
                request_nonce=auth["request"]["nonce"],
                message=pending.message,
                record_hash=auth["request_hash"],
            )
        except FinalHoldoutAuthorityUnavailableError as exc:
            # Trust-pin, encryption, exhaustion and durable-revalidation
            # failures roll back to zero reservation and, when the signer is
            # usable, become one signed-but-ephemeral 503.
            self._raise_signed_unavailable(auth, str(exc))
        except FinalHoldoutAuthorityError:
            raise
        except FinalHoldoutAuthorityStoreError as exc:
            if exc.collision:
                self._raise_signed_error(
                    FinalHoldoutConflictError,
                    status_code=409,
                    code="IDENTIFIER_COLLISION",
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message="authority-generated identifiers collided; the "
                    "request is never treated as idempotent success",
                    record_hash=auth["request_hash"],
                )
            self._raise_signed_unavailable(auth, str(exc))
        try:
            return self._finish(auth, outcome, result_class)
        except FinalHoldoutAuthorityUnavailableError as exc:
            self._raise_signed_unavailable(auth, str(exc))

    # --------------------------------------------------------- B3b lease/audits

    def _signed_access_audit(
        self,
        *,
        release_id: str,
        anchor_id: str,
        anchor_sha256: str,
        tenant_id: str,
        workspace_id: str,
        run_id: str,
        request_id: str,
        lease_id: str | None,
        requested_at: str,
        decided_at: str,
        consumed_at: str | None,
        outcome: str,
        denial_reason: str | None,
        now: datetime,
    ) -> tuple[dict[str, Any], bytes, bytes]:
        """Create one canonical signed audit before any terminal transition."""
        self._signer_usable_at(now)
        audit = {
            "audit_version": FINAL_HOLDOUT_ACCESS_AUDIT_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": release_id,
            "anchor_id": anchor_id,
            "anchor_sha256": anchor_sha256,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "run_id": run_id,
            "request_id": request_id,
            "lease_id": lease_id,
            "requested_at": requested_at,
            "decided_at": decided_at,
            "consumed_at": consumed_at,
            "outcome": outcome,
            "denial_reason": denial_reason,
            "authority_id": self._config.authority_id,
            "authority_key_id": self._config.authority_signer_key_id,
            "signature_algorithm": "ed25519",
            "signature": "0" * 128,
        }
        unsigned = self._neutral(
            lambda: canonical_unsigned_final_holdout_access_audit_bytes(audit))
        audit["signature"] = self._sign(
            FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1 + unsigned)
        signed = self._neutral(
            lambda: canonical_signed_final_holdout_access_audit_bytes(audit))
        fresh = json.loads(signed.decode("utf-8"))
        assert isinstance(fresh, dict)
        return fresh, unsigned, signed

    def _insert_terminal_audit(
        self,
        txn: Any,
        *,
        audit: Mapping[str, Any],
        unsigned_bytes: bytes,
        signed_bytes: bytes,
        created_at: str,
    ) -> None:
        txn.insert_terminal_audit({
            "lease_request_id": audit["request_id"],
            "lease_id": audit["lease_id"],
            "release_id": audit["release_id"],
            "anchor_id": audit["anchor_id"],
            "anchor_sha256": audit["anchor_sha256"],
            "tenant_id": audit["tenant_id"],
            "workspace_id": audit["workspace_id"],
            "run_id": audit["run_id"],
            "outcome": audit["outcome"],
            "requested_at": audit["requested_at"],
            "decided_at": audit["decided_at"],
            "consumed_at": audit["consumed_at"],
            "denial_reason": audit["denial_reason"],
            "authority_id": audit["authority_id"],
            "authority_key_id": audit["authority_key_id"],
            "unsigned_audit_sha256": (
                _SHA256_PREFIX + hashlib.sha256(unsigned_bytes).hexdigest()),
            "unsigned_audit_bytes": unsigned_bytes,
            "audit_signature_hex": audit["signature"],
            "signed_audit_sha256": (
                _SHA256_PREFIX + hashlib.sha256(signed_bytes).hexdigest()),
            "signed_audit_bytes": signed_bytes,
            "created_at": created_at,
        })

    @staticmethod
    def _lease_request_body_from_rows(
        capsule: Mapping[str, Any], anchor: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "body_version": FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "capsule_id": capsule["capsule_id"],
            "capsule_payload_sha256": capsule["payload_sha256"],
            "anchor_id": anchor["anchor_id"],
            "anchor_sha256": anchor["anchor_sha256"],
            "release_id": capsule["release_id"],
            "tenant_id": capsule["tenant_id"],
            "workspace_id": capsule["workspace_id"],
            "run_id": capsule["run_id"],
            "confirmed_spec_hash": capsule["confirmed_spec_sha256"],
            "snapshot_sha256": capsule["primary_snapshot_sha256"],
            "validation_plan_hash": capsule["validation_plan_sha256"],
            "complete_validation_plan_sha256": (
                capsule["complete_validation_plan_sha256"]),
            "locked_rule_sha256": capsule["locked_rule_sha256"],
            "base_costs_sha256": capsule["base_costs_sha256"],
        }

    @staticmethod
    def _consume_request_body_from_rows(
        capsule: Mapping[str, Any], anchor: Mapping[str, Any],
        lease: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "body_version": FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": capsule["release_id"],
            "lease_id": lease["lease_id"],
            "anchor_id": anchor["anchor_id"],
            "capsule_id": capsule["capsule_id"],
            "capsule_payload_sha256": capsule["payload_sha256"],
            "run_id": capsule["run_id"],
        }

    @staticmethod
    def _completion_request_body_from_rows(
        capsule: Mapping[str, Any], anchor: Mapping[str, Any],
        lease: Mapping[str, Any], outcome: str,
    ) -> dict[str, Any]:
        return {
            "body_version": FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": capsule["release_id"],
            "lease_id": lease["lease_id"],
            "anchor_id": anchor["anchor_id"],
            "capsule_id": capsule["capsule_id"],
            "run_id": capsule["run_id"],
            "outcome": outcome,
        }

    @staticmethod
    def _audit_retrieval_body_from_rows(
        capsule: Mapping[str, Any], anchor: Mapping[str, Any],
        lease: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "body_version": FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": capsule["release_id"],
            "lease_id": lease["lease_id"],
            "anchor_id": anchor["anchor_id"],
            "capsule_id": capsule["capsule_id"],
            "run_id": capsule["run_id"],
        }

    def _verify_persisted_terminal_audit(
        self,
        row: Mapping[str, Any],
        *,
        expected: Mapping[str, Any],
        expected_created_at: str,
    ) -> tuple[dict[str, Any], bytes]:
        """Re-prove one durable audit, its signature and complete lineage."""
        def check(condition: bool, label: str) -> None:
            if not condition:
                raise FinalHoldoutAuthorityUnavailableError(
                    f"persisted terminal audit failed the {label} re-validation")

        unsigned = _persisted_blob(row, "unsigned_audit_bytes")
        signed = _persisted_blob(row, "signed_audit_bytes")
        text_columns = (
            "lease_request_id", "release_id", "anchor_id", "anchor_sha256",
            "tenant_id", "workspace_id", "run_id", "outcome",
            "requested_at", "decided_at", "authority_id", "authority_key_id",
            "unsigned_audit_sha256", "audit_signature_hex",
            "signed_audit_sha256", "created_at",
        )
        for column in text_columns:
            check(type(row[column]) is str, f"{column} storage class")
        for column in ("lease_id", "consumed_at", "denial_reason"):
            check(row[column] is None or type(row[column]) is str,
                  f"{column} storage class")
        try:
            audit = json.loads(signed.decode("utf-8"))
            canonical_signed = canonical_signed_final_holdout_access_audit_bytes(
                audit)
            canonical_unsigned = (
                canonical_unsigned_final_holdout_access_audit_bytes(audit))
        except (FinalHoldoutAccessProtocolError, ValueError, TypeError,
                RecursionError) as exc:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted terminal audit bytes failed closed re-validation"
            ) from exc
        check(canonical_signed == signed, "signed byte identity")
        check(canonical_unsigned == unsigned, "unsigned byte identity")
        check(
            row["unsigned_audit_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(unsigned).hexdigest(),
            "unsigned hash",
        )
        check(
            row["signed_audit_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(signed).hexdigest(),
            "signed hash",
        )
        check(row["audit_signature_hex"] == audit["signature"],
              "signature column")
        try:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(self._signer_entry["public_key_hex"])
            ).verify(
                bytes.fromhex(audit["signature"]),
                FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1 + unsigned,
            )
        except (InvalidSignature, ValueError) as exc:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted terminal audit signature failed re-validation"
            ) from exc
        for field, value in expected.items():
            row_field = "lease_request_id" if field == "request_id" else field
            check(audit[field] == value and row[row_field] == value,
                  f"{field} binding")
        check(
            row["lease_request_id"] == audit["request_id"]
            and row["authority_id"] == audit["authority_id"]
            == self._config.authority_id
            and row["authority_key_id"] == audit["authority_key_id"]
            == self._config.authority_signer_key_id,
            "authority/request binding",
        )
        check(row["created_at"] == expected_created_at,
              "created_at binding")
        _utc_instant(row["created_at"], "persisted audit created_at")
        return dict(audit), signed

    def _verify_persisted_completion(
        self,
        txn: Any,
        *,
        capsule: Mapping[str, Any],
        anchor: Mapping[str, Any],
        lease: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Re-prove one durable completion request and its safe wrapper.

        Returns the revalidated safe completion response body so the caller can
        cross-bind it, byte-for-byte, to the persisted terminal audit.  The
        completion outcome is fixed by the durable lease state, so a tampered
        outcome, evaluator, timestamp or embedded audit fails closed here.
        """
        def check(condition: bool, label: str) -> None:
            if not condition:
                raise FinalHoldoutAuthorityUnavailableError(
                    f"persisted completion failed the {label} re-validation")

        outcome = (
            "evaluation_succeeded" if lease["state"] == "SUCCEEDED"
            else "evaluation_failed")
        completion_body = self._completion_request_body_from_rows(
            capsule, anchor, lease, outcome)
        completion_bytes = canonical_final_holdout_completion_request_body_bytes(
            completion_body)
        completion_id = str(lease["completion_request_id"])
        completion_row = txn.fetch_authenticated_request(completion_id)
        check(completion_row is not None, "completion request existence")
        assert completion_row is not None
        safe_row = txn.fetch_safe_response(completion_id)
        check(safe_row is not None, "completion response existence")
        assert safe_row is not None
        self._verify_persisted_request(
            completion_row, safe_row=safe_row,
            expected_operation=_COMPLETE_OPERATION,
            expected_body=completion_bytes)
        check(
            completion_row["caller_key_id"] == lease["evaluator_key_id"],
            "completion evaluator binding",
        )
        _response, response_body, _wrapper = (
            self._verify_persisted_safe_response(completion_row, safe_row))
        check(
            int(safe_row["status_code"]) == 200
            and safe_row["response_code"] == "EVALUATION_COMPLETED",
            "completion response identity",
        )
        check(
            response_body["body_version"]
            == FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1
            and response_body["code"] == "EVALUATION_COMPLETED"
            and response_body["lease_id"] == lease["lease_id"]
            and response_body["request_id"] == completion_id,
            "completion response binding",
        )
        # The signed completion response timestamp equals the terminal instant.
        check(safe_row["response_timestamp"] == lease["terminal_at"],
              "completion response timestamp")
        return dict(response_body)

    def _verify_persisted_retrieval(
        self,
        txn: Any,
        request_row: Mapping[str, Any],
        safe_row: Mapping[str, Any],
        *,
        auth: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        """Re-prove one durable audit-retrieval request and its safe wrapper.

        The retrieval body is reconstructed from the durable capsule/anchor/lease
        so its exact canonical bytes, size and hash re-bind; the request re-proves
        its operation, body and lease-scoped path; the stored evaluator equals the
        lease evaluator; and the response's status/code/request/lease binding all
        hold.  A terminal wrapper must embed byte-for-byte the exact durable
        terminal audit.  A pending wrapper must be temporally valid at its
        persisted response timestamp — captured while the lease was still
        nonterminal — even if the lease has since terminalized.  Used by both the
        exact-retry path and the owner-state conflict re-proof, so a retrieval
        owner is a fully proved basis for a caller-facing conflict verdict.
        """
        unavailable = FinalHoldoutAuthorityUnavailableError

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted retrieval failed the {label} re-validation")

        response, body, wrapper = self._verify_persisted_safe_response(
            request_row, safe_row)
        code = str(safe_row["response_code"])
        check(code in ("TERMINAL_AUDIT_RETURNED", "AUDIT_PENDING"),
              "retrieval response code")
        lease = txn.fetch_lease(str(body["lease_id"]))
        check(lease is not None, "retrieval lease existence")
        assert lease is not None
        proved_lease, capsule, anchor, _decision = (
            self._verify_persisted_lease_lineage(txn, lease))
        retrieval_body = self._audit_retrieval_body_from_rows(
            capsule, anchor, proved_lease)
        retrieval_bytes = canonical_final_holdout_audit_retrieval_body_bytes(
            retrieval_body)
        self._verify_persisted_request(
            request_row, safe_row=safe_row, auth=auth,
            expected_operation=_AUDIT_RETRIEVE_OPERATION,
            expected_body=retrieval_bytes)
        # Evaluator ownership: only the lease's evaluator may hold a retrieval.
        check(
            request_row["caller_key_id"] == proved_lease["evaluator_key_id"],
            "retrieval evaluator ownership",
        )
        check(
            body["request_id"] == request_row["request_id"]
            and body["lease_id"] == proved_lease["lease_id"],
            "retrieval response binding",
        )
        instant = _utc_instant(
            str(safe_row["response_timestamp"]), "retrieval response timestamp")
        if code == "AUDIT_PENDING":
            check(
                int(safe_row["status_code"]) == 202
                and body["body_version"]
                == FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1
                and body["code"] == "AUDIT_PENDING"
                and body["message"] == FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE,
                "pending response identity",
            )
            # The pending snapshot was captured after the lease was decided and
            # at or before it terminalized (if it has since terminalized).  The
            # boundary is inclusive: a pending transaction commits before any
            # completion under the store's exclusive write lock, but both stamp
            # whole-second trusted time and may tie within one second.
            decided = _utc_instant(
                proved_lease["decided_at"], "lease decided_at")
            check(decided <= instant, "pending follows lease decision")
            if proved_lease["terminal_at"] is not None:
                terminal = _utc_instant(
                    proved_lease["terminal_at"], "lease terminal_at")
                check(instant <= terminal,
                      "pending precedes lease terminalization")
        else:
            check(
                int(safe_row["status_code"]) == 200
                and body["body_version"]
                == FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1
                and body["code"] == "TERMINAL_AUDIT_RETURNED",
                "terminal response identity",
            )
            check(
                proved_lease["state"] in ("SUCCEEDED", "FAILED", "EXPIRED"),
                "terminal lease state",
            )
            audit_row = txn.fetch_terminal_audit_by_lease(
                proved_lease["lease_id"])
            check(audit_row is not None, "terminal audit existence")
            assert audit_row is not None
            # Causal time (P1-2): a persisted terminal snapshot must be stamped
            # at or after both the lease terminalization and its signed audit's
            # creation; a wrapper timestamp corrupted earlier fails closed.
            terminal = _utc_instant(
                proved_lease["terminal_at"], "lease terminal_at")
            audit_created = _utc_instant(
                str(audit_row["created_at"]), "terminal audit created_at")
            check(terminal <= instant and audit_created <= instant,
                  "terminal snapshot causal lower bound")
            signed = _persisted_blob(audit_row, "signed_audit_bytes")
            check(
                body["signed_terminal_audit_bytes_hex"] == signed.hex()
                and body["terminal_audit"] == json.loads(signed.decode("utf-8")),
                "terminal wrapper audit identity",
            )
        return response, body, wrapper

    def _verify_persisted_lease_lineage(
        self, txn: Any, lease: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Re-prove a lease and every supported capsule/anchor/request edge.

        Every closed lease state is fully re-proved: ``ISSUED``; the live
        ``CONSUMED`` window; the automatic terminal states ``EXPIRED`` and
        ``FAILED/COMPLETION_TIMEOUT``; and the explicit terminal states
        ``SUCCEEDED`` and ``FAILED/EXPLICIT_EVALUATION_FAILED``.  The explicit
        terminal states additionally re-prove the durable completion request,
        its persisted safe completion wrapper, evaluator binding and the exact
        signed terminal audit that wrapper embedded.
        """
        def check(condition: bool, label: str) -> None:
            if not condition:
                raise FinalHoldoutAuthorityUnavailableError(
                    f"persisted lease failed the {label} re-validation")

        text_required = (
            "lease_id", "lease_request_id", "anchor_id", "evaluator_key_id",
            "requested_at", "decided_at", "expires_at", "state",
        )
        for column in text_required:
            check(type(lease[column]) is str, f"{column} storage class")
        for column in (
            "consume_request_id", "consumed_at", "completion_deadline",
            "completion_request_id", "terminal_at", "terminal_reason_code",
        ):
            check(lease[column] is None or type(lease[column]) is str,
                  f"{column} storage class")
        check(_LEASE_ID_RE.fullmatch(lease["lease_id"]) is not None,
              "lease id grammar")
        check(_REQUEST_ID_RE.fullmatch(lease["lease_request_id"]) is not None,
              "lease request id grammar")
        check(
            lease["state"] in (
                "ISSUED", "CONSUMED", "SUCCEEDED", "FAILED", "EXPIRED"),
            "supported lifecycle state",
        )
        requested = _utc_instant(lease["requested_at"], "lease requested_at")
        decided = _utc_instant(lease["decided_at"], "lease decided_at")
        expires = _utc_instant(lease["expires_at"], "lease expires_at")
        check(requested <= decided < expires, "lease time law")

        anchor = txn.fetch_anchor(lease["anchor_id"])
        check(anchor is not None, "anchor existence")
        assert anchor is not None
        capsule = txn.fetch_capsule(anchor["capsule_id"])
        check(capsule is not None, "capsule existence")
        assert capsule is not None
        plan, bindings = self._verify_persisted_capsule(txn, capsule)
        anchor_state = {
            "ISSUED": "LEASED",
            "CONSUMED": "CONSUMED",
            "SUCCEEDED": "TERMINAL",
            "FAILED": "TERMINAL",
            "EXPIRED": "TERMINAL",
        }[lease["state"]]
        self._verify_persisted_anchor(
            txn, anchor, capsule, plan, bindings,
            expected_state=anchor_state)
        anchor_expiry = _utc_instant(anchor["expires_at"], "anchor expires_at")
        check(
            expires == min(
                decided + timedelta(seconds=_LEASE_LIFETIME_SECONDS),
                anchor_expiry,
            ),
            "clipped expiry",
        )

        body = self._lease_request_body_from_rows(capsule, anchor)
        body_bytes = canonical_final_holdout_lease_request_body_bytes(body)
        request_row = txn.fetch_authenticated_request(lease["lease_request_id"])
        safe_row = txn.fetch_safe_response(lease["lease_request_id"])
        decision = txn.fetch_access_decision(lease["lease_request_id"])
        check(request_row is not None and safe_row is not None
              and decision is not None, "lease owner rows")
        assert request_row is not None and safe_row is not None
        assert decision is not None
        self._verify_persisted_request(
            request_row, safe_row=safe_row,
            expected_operation=_LEASE_OPERATION,
            expected_authenticated_at=lease["decided_at"],
            expected_body=body_bytes)
        check(
            lease["requested_at"] == request_row["request_timestamp"],
            "signed request timestamp binding",
        )
        check(
            lease["evaluator_key_id"] == request_row["caller_key_id"],
            "signed evaluator key binding",
        )
        response, response_body, _wrapper = self._verify_persisted_safe_response(
            request_row, safe_row)
        check(
            int(safe_row["status_code"]) == 200
            and safe_row["response_code"] == "LEASE_ISSUED",
            "lease response identity",
        )
        response_bindings = {
            "request_id": lease["lease_request_id"],
            "release_id": capsule["release_id"],
            "lease_id": lease["lease_id"],
            "capsule_id": capsule["capsule_id"],
            "anchor_id": anchor["anchor_id"],
            "run_id": capsule["run_id"],
            "anchor_sha256": anchor["anchor_sha256"],
            "capsule_payload_sha256": capsule["payload_sha256"],
            "issued_at": lease["decided_at"],
            "lease_expires_at": lease["expires_at"],
            "state": "ISSUED",
        }
        for field, value in response_bindings.items():
            check(response_body.get(field) == value,
                  f"lease response {field}")
        check(response["timestamp"] == lease["decided_at"],
              "lease response timestamp")

        for column in (
            "lease_request_id", "release_id", "tenant_id", "workspace_id",
            "run_id", "capsule_id", "anchor_id", "anchor_sha256",
            "requested_at", "decided_at", "decision",
        ):
            check(type(decision[column]) is str,
                  f"decision {column} storage class")
        check(decision["lease_id"] == lease["lease_id"]
              and decision["denial_reason"] is None,
              "decision lease binding")
        decision_bindings = {
            "lease_request_id": lease["lease_request_id"],
            "release_id": capsule["release_id"],
            "tenant_id": capsule["tenant_id"],
            "workspace_id": capsule["workspace_id"],
            "run_id": capsule["run_id"],
            "capsule_id": capsule["capsule_id"],
            "anchor_id": anchor["anchor_id"],
            "anchor_sha256": anchor["anchor_sha256"],
            "requested_at": lease["requested_at"],
            "decided_at": lease["decided_at"],
            "decision": "LEASE_ISSUED",
        }
        for field, value in decision_bindings.items():
            check(decision[field] == value, f"decision {field}")
        evaluator = self._client_key_entry(
            FINAL_EVALUATOR_ROLE, lease["evaluator_key_id"])
        check(evaluator is not None and evaluator["status"] == "active"
              and self._client_key_valid_at(evaluator, requested)
              and self._client_key_valid_at(evaluator, decided),
              "evaluator key binding")
        completion_safe_body: dict[str, Any] | None = None
        if lease["state"] == "ISSUED":
            check(all(lease[column] is None for column in (
                "consume_request_id", "consumed_at", "completion_deadline",
                "completion_request_id", "terminal_at",
                "terminal_reason_code")), "issued null columns")
        elif lease["state"] in ("CONSUMED", "SUCCEEDED", "FAILED"):
            # Every consumed-or-later lease carries the durable consume columns.
            check(
                type(lease["consume_request_id"]) is str
                and type(lease["consumed_at"]) is str
                and type(lease["completion_deadline"]) is str,
                "consumed columns",
            )
            # State-specific completion/terminal column law.  A durable explicit
            # completion (SUCCEEDED or explicit FAILED) carries a completion
            # request id and its private terminal reason; a timeout FAILED never
            # has a completion request; a live CONSUMED lease has neither.
            if lease["state"] == "CONSUMED":
                check(
                    lease["completion_request_id"] is None
                    and lease["terminal_at"] is None
                    and lease["terminal_reason_code"] is None,
                    "consumed pending columns",
                )
            elif lease["state"] == "SUCCEEDED":
                check(
                    type(lease["completion_request_id"]) is str
                    and type(lease["terminal_at"]) is str
                    and lease["terminal_reason_code"]
                    == "EVALUATION_SUCCEEDED",
                    "succeeded columns",
                )
            elif lease["completion_request_id"] is not None:
                check(
                    lease["state"] == "FAILED"
                    and type(lease["completion_request_id"]) is str
                    and type(lease["terminal_at"]) is str
                    and lease["terminal_reason_code"]
                    == "EXPLICIT_EVALUATION_FAILED",
                    "explicit-failed columns",
                )
            else:
                check(
                    lease["state"] == "FAILED"
                    and lease["completion_request_id"] is None
                    and type(lease["terminal_at"]) is str
                    and lease["terminal_reason_code"] == "COMPLETION_TIMEOUT",
                    "timeout-failed columns",
                )
            consumed = _utc_instant(lease["consumed_at"], "lease consumed_at")
            deadline = _utc_instant(
                lease["completion_deadline"], "lease completion_deadline")
            check(decided <= consumed < deadline, "consume time law")
            check(
                deadline == min(
                    consumed + timedelta(seconds=1800), anchor_expiry),
                "completion deadline clipping",
            )
            consume_body = self._consume_request_body_from_rows(
                capsule, anchor, lease)
            consume_bytes = canonical_final_holdout_consume_request_body_bytes(
                consume_body)
            consume_row = txn.fetch_authenticated_request(
                lease["consume_request_id"])
            check(consume_row is not None, "consume request existence")
            assert consume_row is not None
            check(txn.fetch_safe_response(lease["consume_request_id"]) is None,
                  "plaintext response absence")
            self._verify_persisted_request(
                consume_row, safe_row=None,
                expected_operation=_CONSUME_OPERATION,
                expected_authenticated_at=lease["consumed_at"],
                expected_body=consume_bytes)
            # Evaluator-key binding (P0): the durable consumer must be exactly
            # the evaluator that holds the lease; a stolen consume can never
            # produce a durable CONSUMED row that survives this re-proof.
            check(
                consume_row["caller_key_id"] == lease["evaluator_key_id"],
                "consume evaluator binding",
            )
            # An explicit terminal completion re-proves its completion request,
            # its persisted safe completion wrapper and its evaluator binding.
            if lease["completion_request_id"] is not None:
                completion_safe_body = self._verify_persisted_completion(
                    txn, capsule=capsule, anchor=anchor, lease=lease)
        else:
            check(
                all(lease[column] is None for column in (
                    "consume_request_id", "consumed_at",
                    "completion_deadline", "completion_request_id",
                ))
                and type(lease["terminal_at"]) is str
                and lease["terminal_reason_code"] == "LEASE_EXPIRED",
                "expired columns",
            )

        audit_row = txn.fetch_terminal_audit_by_lease(lease["lease_id"])
        audit_owner_row = txn.fetch_terminal_audit_by_lease_request(
            lease["lease_request_id"])
        if lease["state"] in ("ISSUED", "CONSUMED"):
            check(
                audit_row is None and audit_owner_row is None,
                "nonterminal audit absence",
            )
        else:
            check(
                audit_row is not None
                and audit_owner_row is not None
                and dict(audit_row) == dict(audit_owner_row),
                "terminal audit ownership",
            )
            assert audit_row is not None
            terminal = _utc_instant(
                lease["terminal_at"], "lease terminal_at")
            if lease["state"] == "EXPIRED":
                check(terminal >= expires, "expiry terminal boundary")
                terminal_outcome = "lease_expired"
                terminal_denial = "LEASE_EXPIRED"
                terminal_consumed_at = None
            elif lease["completion_request_id"] is not None:
                # An explicit completion is bounded by the consume/deadline
                # half-open window: it can only be signed strictly before the
                # completion deadline, else due processing times it out first.
                consumed = _utc_instant(
                    lease["consumed_at"], "lease consumed_at")
                deadline = _utc_instant(
                    lease["completion_deadline"],
                    "lease completion_deadline")
                check(consumed <= terminal < deadline,
                      "completion terminal boundary")
                terminal_outcome = (
                    "evaluation_succeeded" if lease["state"] == "SUCCEEDED"
                    else "evaluation_failed")
                terminal_denial = None
                terminal_consumed_at = lease["consumed_at"]
            else:
                deadline = _utc_instant(
                    lease["completion_deadline"],
                    "lease completion_deadline")
                check(terminal >= deadline, "timeout terminal boundary")
                terminal_outcome = "evaluation_failed"
                terminal_denial = None
                terminal_consumed_at = lease["consumed_at"]
            audit, signed = self._verify_persisted_terminal_audit(
                audit_row,
                expected={
                    "release_id": capsule["release_id"],
                    "anchor_id": anchor["anchor_id"],
                    "anchor_sha256": anchor["anchor_sha256"],
                    "tenant_id": capsule["tenant_id"],
                    "workspace_id": capsule["workspace_id"],
                    "run_id": capsule["run_id"],
                    "request_id": lease["lease_request_id"],
                    "lease_id": lease["lease_id"],
                    "requested_at": decision["requested_at"],
                    "decided_at": decision["decided_at"],
                    "consumed_at": terminal_consumed_at,
                    "outcome": terminal_outcome,
                    "denial_reason": terminal_denial,
                },
                expected_created_at=lease["terminal_at"],
            )
            # A durable explicit-completion wrapper must embed byte-for-byte the
            # exact persisted terminal audit it returned to the evaluator.
            if completion_safe_body is not None:
                check(
                    completion_safe_body["terminal_audit"] == audit
                    and completion_safe_body["signed_terminal_audit_bytes_hex"]
                    == signed.hex(),
                    "completion wrapper audit identity",
                )
        return dict(lease), dict(capsule), dict(anchor), dict(decision)

    def _verify_resolved_anchor_lifecycle(
        self, txn: Any, anchor: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Re-prove a resolved anchor and any lease that owns its state."""
        capsule = txn.fetch_capsule(str(anchor["capsule_id"]))
        if capsule is None:
            raise FinalHoldoutAuthorityUnavailableError(
                "a resolved anchor references a missing capsule row")
        plan, bindings = self._verify_persisted_capsule(txn, capsule)
        lease = txn.fetch_lease_by_anchor(str(anchor["anchor_id"]))
        if lease is None:
            self._verify_persisted_anchor(
                txn, anchor, capsule, plan, bindings,
                expected_state="REGISTERED")
        else:
            proved_lease, proved_capsule, proved_anchor, _decision = (
                self._verify_persisted_lease_lineage(txn, lease))
            if proved_lease["anchor_id"] != anchor["anchor_id"] \
                    or proved_anchor["anchor_id"] != anchor["anchor_id"] \
                    or proved_capsule["capsule_id"] != capsule["capsule_id"]:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a resolved anchor references contradictory lease lineage")
        return dict(capsule), dict(plan), dict(bindings)

    def _expire_due_in_transaction(self, txn: Any, now: datetime) -> None:
        """Process every due nonterminal lease in one global stable order."""
        now_text = _format_utc(now)
        due: list[tuple[str, str, str, dict[str, Any]]] = []
        for row in txn.due_issued_leases(now_text):
            due.append((str(row["expires_at"]), str(row["lease_id"]),
                        "ISSUED", row))
        for row in txn.due_consumed_leases(now_text):
            due.append((str(row["completion_deadline"]), str(row["lease_id"]),
                        "CONSUMED", row))
        due.sort(key=lambda item: (item[0], item[1]))
        for _deadline, lease_id, state, row in due:
            lease, capsule, anchor, decision = (
                self._verify_persisted_lease_lineage(txn, row))
            if lease["state"] != state:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a due lease changed state during its locked scan")
            if state == "ISSUED":
                outcome = "lease_expired"
                denial_reason = "LEASE_EXPIRED"
                consumed_at = None
            else:
                outcome = "evaluation_failed"
                denial_reason = None
                consumed_at = lease["consumed_at"]
            audit, unsigned, signed = self._signed_access_audit(
                release_id=capsule["release_id"],
                anchor_id=anchor["anchor_id"],
                anchor_sha256=anchor["anchor_sha256"],
                tenant_id=capsule["tenant_id"],
                workspace_id=capsule["workspace_id"],
                run_id=capsule["run_id"],
                request_id=lease["lease_request_id"],
                lease_id=lease_id,
                requested_at=decision["requested_at"],
                decided_at=decision["decided_at"],
                consumed_at=consumed_at,
                outcome=outcome,
                denial_reason=denial_reason,
                now=now,
            )
            self._insert_terminal_audit(
                txn, audit=audit, unsigned_bytes=unsigned,
                signed_bytes=signed, created_at=now_text)
            if state == "ISSUED":
                txn.expire_issued_lease(lease_id, now_text)
                txn.transition_anchor(anchor["anchor_id"], "LEASED", "TERMINAL")
            else:
                txn.timeout_consumed_lease(lease_id, now_text)
                txn.transition_anchor(
                    anchor["anchor_id"], "CONSUMED", "TERMINAL")

    def expire_due(self) -> None:
        """Synchronously expire/timeout all due leases using trusted time."""
        def transaction(txn: Any) -> None:
            now = self._trusted_now()
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, now)

        try:
            self._store.run_transaction(transaction)
        except FinalHoldoutAuthorityError:
            raise
        except FinalHoldoutAuthorityStoreError as exc:
            raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc

    def _fresh_lease_id(self, txn: Any) -> str:
        for _ in range(IDENTIFIER_GENERATION_ATTEMPTS):
            candidate = "fha-lease-" + self._generated_token("lease id")
            if txn.fetch_lease(candidate) is None:
                return candidate
        raise FinalHoldoutAuthorityUnavailableError(
            "authority lease identifier generation exhausted its bounded "
            "attempt budget")

    def _persist_lease_denial(
        self,
        txn: Any,
        *,
        auth: Mapping[str, Any],
        body: Mapping[str, Any],
        capsule: Mapping[str, Any],
        anchor: Mapping[str, Any],
        code: str,
        status_code: int,
        now: datetime,
    ) -> tuple[int, dict[str, Any], str, str]:
        """Persist one authenticated semantic denial and its signed audit."""
        now_text = _format_utc(now)
        audit, unsigned, signed = self._signed_access_audit(
            release_id=str(capsule["release_id"]),
            anchor_id=str(anchor["anchor_id"]),
            anchor_sha256=str(anchor["anchor_sha256"]),
            tenant_id=str(capsule["tenant_id"]),
            workspace_id=str(capsule["workspace_id"]),
            run_id=str(capsule["run_id"]),
            request_id=auth["request"]["request_id"],
            lease_id=None,
            requested_at=auth["request"]["timestamp"],
            decided_at=now_text,
            consumed_at=None,
            outcome="denied",
            denial_reason=code,
            now=now,
        )
        txn.insert_access_decision({
            "lease_request_id": auth["request"]["request_id"],
            "release_id": capsule["release_id"],
            "tenant_id": capsule["tenant_id"],
            "workspace_id": capsule["workspace_id"],
            "run_id": capsule["run_id"],
            "capsule_id": capsule["capsule_id"],
            "anchor_id": anchor["anchor_id"],
            "anchor_sha256": anchor["anchor_sha256"],
            "lease_id": None,
            "requested_at": auth["request"]["timestamp"],
            "decided_at": now_text,
            "decision": "LEASE_DENIED",
            "denial_reason": code,
        })
        self._insert_terminal_audit(
            txn, audit=audit, unsigned_bytes=unsigned,
            signed_bytes=signed, created_at=now_text)
        response_body = {
            "body_version": FINAL_HOLDOUT_LEASE_DENIAL_RESPONSE_BODY_VERSION_V1,
            "code": code,
            "request_id": auth["request"]["request_id"],
            "terminal_audit": audit,
            "signed_terminal_audit_bytes_hex": signed.hex(),
        }
        return (
            status_code, response_body, "denial",
            "the authenticated lease request was durably denied",
        )

    def _verify_lease_denial_replay(
        self,
        txn: Any,
        *,
        auth: Mapping[str, Any],
        body: Mapping[str, Any],
        safe_row: Mapping[str, Any],
    ) -> None:
        request_id = auth["request"]["request_id"]
        request_row = txn.fetch_authenticated_request(request_id)
        decision = txn.fetch_access_decision(request_id)
        audit_row = txn.fetch_terminal_audit_by_lease_request(request_id)
        if request_row is None or decision is None or audit_row is None:
            raise FinalHoldoutAuthorityUnavailableError(
                "a persisted lease denial is missing its durable lineage")
        self._verify_persisted_request(
            request_row, safe_row=safe_row, auth=auth,
            expected_operation=_LEASE_OPERATION,
            expected_body=canonical_final_holdout_lease_request_body_bytes(body))
        _response, response_body, _wrapper = (
            self._verify_persisted_safe_response(request_row, safe_row))
        capsule = txn.fetch_capsule(body["capsule_id"])
        anchor = txn.fetch_anchor(body["anchor_id"])
        if capsule is None or anchor is None:
            raise FinalHoldoutAuthorityUnavailableError(
                "a persisted lease denial references missing registered lineage")
        plan, bindings = self._verify_persisted_capsule(txn, capsule)
        # A prior durable lease may have advanced this anchor after the denial;
        # otherwise ANCHOR_EXPIRED leaves it REGISTERED.  The exact state is
        # still re-proved against that durable lease when one exists.
        existing = txn.fetch_lease_by_anchor(anchor["anchor_id"])
        if existing is None:
            self._verify_persisted_anchor(
                txn, anchor, capsule, plan, bindings,
                expected_state="REGISTERED")
        else:
            proved_lease, proved_capsule, proved_anchor, _decision = (
                self._verify_persisted_lease_lineage(txn, existing))
            if proved_lease["anchor_id"] != anchor["anchor_id"] \
                    or proved_anchor["anchor_id"] != anchor["anchor_id"] \
                    or proved_capsule["capsule_id"] != capsule["capsule_id"]:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a lease denial references contradictory durable lineage")
        expected_code = str(safe_row["response_code"])
        if expected_code not in ("LEASE_ALREADY_EXISTS", "ANCHOR_EXPIRED"):
            raise FinalHoldoutAuthorityUnavailableError(
                "a lease denial row carries an impossible response code")
        expected_decision = {
            "lease_request_id": request_id,
            "release_id": capsule["release_id"],
            "tenant_id": capsule["tenant_id"],
            "workspace_id": capsule["workspace_id"],
            "run_id": capsule["run_id"],
            "capsule_id": capsule["capsule_id"],
            "anchor_id": anchor["anchor_id"],
            "anchor_sha256": anchor["anchor_sha256"],
            "lease_id": None,
            "requested_at": auth["request"]["timestamp"],
            "decision": "LEASE_DENIED",
            "denial_reason": expected_code,
        }
        for field, expected in expected_decision.items():
            if decision[field] != expected:
                raise FinalHoldoutAuthorityUnavailableError(
                    f"persisted lease denial decision failed {field} binding")
        if decision["decided_at"] != safe_row["response_timestamp"]:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted lease denial decision time is inconsistent")
        audit, signed = self._verify_persisted_terminal_audit(
            audit_row,
            expected={
                "release_id": capsule["release_id"],
                "anchor_id": anchor["anchor_id"],
                "anchor_sha256": anchor["anchor_sha256"],
                "tenant_id": capsule["tenant_id"],
                "workspace_id": capsule["workspace_id"],
                "run_id": capsule["run_id"],
                "request_id": request_id,
                "lease_id": None,
                "requested_at": decision["requested_at"],
                "decided_at": decision["decided_at"],
                "consumed_at": None,
                "outcome": "denied",
                "denial_reason": expected_code,
            },
            expected_created_at=str(decision["decided_at"]),
        )
        if response_body["terminal_audit"] != audit \
                or response_body["signed_terminal_audit_bytes_hex"] \
                != signed.hex():
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted lease denial response does not embed its audit")

    @staticmethod
    def _verify_generic_lease_denial_replay(
        txn: Any,
        *,
        request_id: str,
        safe_row: Mapping[str, Any],
    ) -> None:
        """Prove a generic binding denial owns no semantic lease lineage."""
        if str(safe_row["response_code"]) != "BINDING_MISMATCH":
            raise FinalHoldoutAuthorityUnavailableError(
                "a generic lease denial carries an impossible response code")
        if any(row is not None for row in (
            txn.fetch_lease_by_request(request_id),
            txn.fetch_access_decision(request_id),
            txn.fetch_terminal_audit_by_lease_request(request_id),
            txn.fetch_capsule_by_request(request_id),
            txn.fetch_anchor_by_request(request_id),
        )):
            raise FinalHoldoutAuthorityUnavailableError(
                "a generic lease denial owns contradictory durable lineage")

    def create_lease(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutAnchorRegistrationResult:
        """Authenticate one evaluator and durably issue or deny one lease."""
        try:
            valid_body = validate_final_holdout_lease_request_body_v1(body)
            body_bytes = canonical_final_holdout_lease_request_body_bytes(
                valid_body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        auth = self._authenticated_request(
            client_request,
            operation=_LEASE_OPERATION,
            expected_path=FINAL_HOLDOUT_LEASE_PATH_V1,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
            max_body_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            required_role=FINAL_EVALUATOR_ROLE,
        )
        outcome: dict[str, Any] = {}

        def transaction(txn: Any) -> None:
            now = self._trusted_now()
            now_text = _format_utc(now)
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, now)
            entry = auth["entry"]
            if entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, now):
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is not valid at the trusted transaction time")
                return
            try:
                replay_row = self._resolve_request_row(txn, auth)
            except _PendingSignedError as pending:
                # Due terminal transitions have already been signed.  Preserve
                # and commit them before emitting this ephemeral caller error.
                outcome["pending"] = pending
                return
            if replay_row is not None:
                safe_row = txn.fetch_safe_response(
                    auth["request"]["request_id"])
                if safe_row is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved lease request has no persisted safe response")
                self._verify_persisted_request(
                    replay_row, safe_row=safe_row, auth=auth,
                    expected_operation=_LEASE_OPERATION,
                    expected_body=body_bytes)
                _response, _stored_body, _wrapper = (
                    self._verify_persisted_safe_response(replay_row, safe_row))
                code = str(safe_row["response_code"])
                if code == "LEASE_ISSUED":
                    lease = txn.fetch_lease_by_request(
                        auth["request"]["request_id"])
                    if lease is None:
                        raise FinalHoldoutAuthorityUnavailableError(
                            "an issued lease response has no durable lease")
                    self._verify_persisted_lease_lineage(txn, lease)
                    if lease["state"] == "ISSUED":
                        outcome["kind"] = "replayed"
                        outcome["message"] = "the issued lease was recovered"
                        return
                    if lease["state"] == "EXPIRED":
                        outcome["pending"] = _PendingSignedError(
                            FinalHoldoutConflictError, 410, "LEASE_EXPIRED",
                            "an expired lease is terminal and cannot be replayed")
                        return
                    outcome["pending"] = _PendingSignedError(
                        FinalHoldoutConflictError, 409,
                        "LEASE_STATE_CONFLICT",
                        "only an issued lease may recover its original response")
                    return
                if code in ("LEASE_ALREADY_EXISTS", "ANCHOR_EXPIRED"):
                    self._verify_lease_denial_replay(
                        txn, auth=auth, body=valid_body, safe_row=safe_row)
                else:
                    self._verify_generic_lease_denial_replay(
                        txn,
                        request_id=auth["request"]["request_id"],
                        safe_row=safe_row,
                    )
                outcome["kind"] = "denial"
                outcome["message"] = "the persisted lease denial was recovered"
                return

            age_seconds = (now - auth["request_timestamp"]).total_seconds()
            if not 0 <= age_seconds <= MAX_CLIENT_REQUEST_AGE_SECONDS:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request timestamp is stale or from the future")
                return
            capsule = txn.fetch_capsule(valid_body["capsule_id"])
            anchor = txn.fetch_anchor(valid_body["anchor_id"])
            if capsule is None or anchor is None \
                    or anchor["capsule_id"] != valid_body["capsule_id"]:
                # Generic binding errors must not mask corruption in whatever
                # durable objects did resolve.  Re-prove each such object and
                # the complete lifecycle implied by an existing anchor before
                # returning a caller-facing semantic verdict.
                if capsule is not None:
                    self._verify_persisted_capsule(txn, capsule)
                if anchor is not None:
                    self._verify_resolved_anchor_lifecycle(txn, anchor)
                decided = self._denial_body(
                    now, auth, 409, "BINDING_MISMATCH",
                    "the lease request does not resolve one registered lineage")
                self._reserve_request(txn, auth, now)
                self._persist_result(
                    txn, auth, status_code=decided[0], body=decided[1], now=now)
                outcome["kind"], outcome["message"] = decided[2], decided[3]
                return
            plan, bindings = self._verify_persisted_capsule(txn, capsule)
            expected_body = self._lease_request_body_from_rows(capsule, anchor)
            if valid_body != expected_body:
                # Re-prove both immutable rows and any lease/audit that owns
                # the anchor's current lifecycle state before blaming the
                # caller for a binding mismatch.
                self._verify_resolved_anchor_lifecycle(txn, anchor)
                decided = self._denial_body(
                    now, auth, 409, "BINDING_MISMATCH",
                    "the lease request does not exactly bind the registered "
                    "capsule, plan and anchor")
                self._reserve_request(txn, auth, now)
                self._persist_result(
                    txn, auth, status_code=decided[0], body=decided[1], now=now)
                outcome["kind"], outcome["message"] = decided[2], decided[3]
                return

            existing = txn.fetch_lease_by_anchor(anchor["anchor_id"])
            if existing is not None:
                proved_lease, proved_capsule, proved_anchor, _decision = (
                    self._verify_persisted_lease_lineage(txn, existing))
                if proved_lease["anchor_id"] != anchor["anchor_id"] \
                        or proved_anchor["anchor_id"] != anchor["anchor_id"] \
                        or proved_capsule["capsule_id"] != capsule["capsule_id"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "an existing lease references contradictory durable "
                        "lineage")
                self._reserve_request(txn, auth, now)
                decided = self._persist_lease_denial(
                    txn, auth=auth, body=valid_body,
                    capsule=capsule, anchor=anchor,
                    code="LEASE_ALREADY_EXISTS", status_code=409, now=now)
                self._persist_result(
                    txn, auth, status_code=decided[0], body=decided[1], now=now)
                outcome["kind"], outcome["message"] = decided[2], decided[3]
                return

            self._verify_persisted_anchor(
                txn, anchor, capsule, plan, bindings,
                expected_state="REGISTERED")

            anchor_expires = _utc_instant(
                anchor["expires_at"], "registered anchor expires_at")
            if not now < anchor_expires:
                self._reserve_request(txn, auth, now)
                decided = self._persist_lease_denial(
                    txn, auth=auth, body=valid_body,
                    capsule=capsule, anchor=anchor,
                    code="ANCHOR_EXPIRED", status_code=410, now=now)
                self._persist_result(
                    txn, auth, status_code=decided[0], body=decided[1], now=now)
                outcome["kind"], outcome["message"] = decided[2], decided[3]
                return

            expires = min(
                now + timedelta(seconds=_LEASE_LIFETIME_SECONDS),
                anchor_expires)
            if not now < expires:
                raise FinalHoldoutAuthorityUnavailableError(
                    "the clipped lease expiry is not after its issue time")
            lease_id = self._fresh_lease_id(txn)
            expires_text = _format_utc(expires)
            success_body = {
                "body_version": FINAL_HOLDOUT_LEASE_RESPONSE_BODY_VERSION_V1,
                "code": "LEASE_ISSUED",
                "request_id": auth["request"]["request_id"],
                "release_id": capsule["release_id"],
                "lease_id": lease_id,
                "capsule_id": capsule["capsule_id"],
                "anchor_id": anchor["anchor_id"],
                "run_id": capsule["run_id"],
                "anchor_sha256": anchor["anchor_sha256"],
                "capsule_payload_sha256": capsule["payload_sha256"],
                "issued_at": now_text,
                "lease_expires_at": expires_text,
                "state": "ISSUED",
            }
            # The safe wrapper must be completely signed while the durable
            # anchor is still REGISTERED and before lease/decision rows exist.
            # A signer failure therefore aborts before any lifecycle mutation;
            # the already-reserved request is rolled back with the transaction.
            prepared_result = self._prepare_result(
                auth, status_code=200, body=success_body, now=now)
            self._reserve_request(txn, auth, now)
            txn.insert_lease({
                "lease_id": lease_id,
                "lease_request_id": auth["request"]["request_id"],
                "anchor_id": anchor["anchor_id"],
                "evaluator_key_id": auth["request"]["caller_key_id"],
                "requested_at": auth["request"]["timestamp"],
                "decided_at": now_text,
                "expires_at": expires_text,
                "consume_request_id": None,
                "consumed_at": None,
                "completion_deadline": None,
                "completion_request_id": None,
                "terminal_at": None,
                "terminal_reason_code": None,
                "state": "ISSUED",
            })
            txn.insert_access_decision({
                "lease_request_id": auth["request"]["request_id"],
                "release_id": capsule["release_id"],
                "tenant_id": capsule["tenant_id"],
                "workspace_id": capsule["workspace_id"],
                "run_id": capsule["run_id"],
                "capsule_id": capsule["capsule_id"],
                "anchor_id": anchor["anchor_id"],
                "anchor_sha256": anchor["anchor_sha256"],
                "lease_id": lease_id,
                "requested_at": auth["request"]["timestamp"],
                "decided_at": now_text,
                "decision": "LEASE_ISSUED",
                "denial_reason": None,
            })
            txn.transition_anchor(anchor["anchor_id"], "REGISTERED", "LEASED")
            self._insert_prepared_result(txn, prepared_result)
            outcome["kind"] = "success"
            outcome["message"] = "lease issued"

        try:
            self._store.run_transaction(transaction)
            pending = outcome.get("pending")
            if isinstance(pending, _PendingSignedError):
                self._raise_signed_error(
                    pending.error_class,
                    status_code=pending.status_code,
                    code=pending.code,
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message=pending.message,
                    record_hash=auth["request_hash"],
                )
        except _PendingSignedError as pending:
            self._raise_signed_error(
                pending.error_class,
                status_code=pending.status_code,
                code=pending.code,
                request_id=auth["request"]["request_id"],
                request_nonce=auth["request"]["nonce"],
                message=pending.message,
                record_hash=auth["request_hash"],
            )
        except FinalHoldoutAuthorityUnavailableError as exc:
            self._raise_signed_unavailable(auth, str(exc))
        except FinalHoldoutAuthorityStoreError as exc:
            if exc.collision:
                self._raise_signed_error(
                    FinalHoldoutConflictError,
                    status_code=409,
                    code="IDENTIFIER_COLLISION",
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message="authority-generated identifiers collided",
                    record_hash=auth["request_hash"],
                )
            self._raise_signed_unavailable(auth, str(exc))
        try:
            return self._finish(
                auth, outcome, FinalHoldoutAnchorRegistrationResult)
        except FinalHoldoutAuthorityUnavailableError as exc:
            self._raise_signed_unavailable(auth, str(exc))

    # -------------------------------------------------------------- consume

    def _reprove_referenced_lineage(
        self,
        txn: Any,
        valid_body: Mapping[str, Any],
        *,
        proved_capsule: Mapping[str, Any] | None,
        proved_anchor: Mapping[str, Any] | None,
    ) -> None:
        """Re-prove any caller-referenced capsule/anchor before a mismatch verdict.

        Corruption in a durable object the consume request names — whether the
        lease is unknown, or a valid lease is combined with an existing but
        corrupted capsule/anchor — must fail closed as sanitized unavailability,
        never be masked by a ``BINDING_MISMATCH``.  Objects already re-proved as
        the resolved lease's own lineage are deduplicated.
        """
        capsule_id = valid_body["capsule_id"]
        anchor_id = valid_body["anchor_id"]
        if proved_capsule is None \
                or proved_capsule["capsule_id"] != capsule_id:
            referenced_capsule = txn.fetch_capsule(capsule_id)
            if referenced_capsule is not None:
                self._verify_persisted_capsule(txn, referenced_capsule)
        if proved_anchor is None or proved_anchor["anchor_id"] != anchor_id:
            referenced_anchor = txn.fetch_anchor(anchor_id)
            if referenced_anchor is not None:
                self._verify_resolved_anchor_lifecycle(txn, referenced_anchor)

    def _reload_aes_key(self) -> bytes:
        """Re-read the strict owner-only AES key inside an operation and bind it.

        Consume never relies only on the cached key: the file is re-read with
        the exact construction hygiene, decoded, and its SHA-256 bound to the
        value sealed at construction — which ``_compare_metadata`` already
        proved equals the store metadata ``payload_encryption_key_sha256``.  A
        key file changed, shortened, mode-loosened or corrupted after
        construction fails closed here as sanitized unavailability, releasing no
        plaintext.
        """
        try:
            payload = _load_private_key_bytes(
                self._config.payload_encryption_key_file, expected_length=65)
            text = payload.decode("ascii", errors="replace")
            if text.endswith("\n"):
                text = text[:-1]
            if _AES_KEY_HEX_RE.fullmatch(text) is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "the reloaded payload encryption key failed hygiene "
                    "re-checks")
            reloaded = bytes.fromhex(text)
        except FinalHoldoutAuthorityConfigurationError as exc:
            raise FinalHoldoutAuthorityUnavailableError(
                "the reloaded payload encryption key failed hygiene re-checks"
            ) from exc
        if len(reloaded) != 32 or hashlib.sha256(reloaded).hexdigest() \
                != hashlib.sha256(self._aes_key).hexdigest():
            raise FinalHoldoutAuthorityUnavailableError(
                "the reloaded payload encryption key does not match the sealed "
                "metadata key digest")
        return reloaded

    def consume(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutAnchorRegistrationResult:
        """Authenticate one evaluator and release one lease's plaintext once.

        A successful consume persists only its authenticated request and the
        ISSUED->CONSUMED lease / LEASED->CONSUMED anchor transitions; it never
        writes plaintext, its wrapper/body bytes or any derived hash to
        ``safe_service_responses`` or anywhere else.  Every consume non-success
        is signed-but-ephemeral, and after a committed consume every retry or
        new consume returns an ephemeral ``410 PLAINTEXT_ALREADY_RELEASED``.
        """
        try:
            valid_body = validate_final_holdout_consume_request_body_v1(body)
            body_bytes = canonical_final_holdout_consume_request_body_bytes(
                valid_body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        expected_path = FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1.format(
            lease_id=valid_body["lease_id"])
        auth = self._authenticated_request(
            client_request,
            operation=_CONSUME_OPERATION,
            expected_path=expected_path,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
            max_body_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            required_role=FINAL_EVALUATOR_ROLE,
        )
        outcome: dict[str, Any] = {}
        already_released = _PendingSignedError(
            FinalHoldoutConflictError, 410, "PLAINTEXT_ALREADY_RELEASED",
            "the final-holdout plaintext for this request was already released")

        def transaction(txn: Any) -> None:
            now = self._trusted_now()
            now_text = _format_utc(now)
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, now)
            entry = auth["entry"]
            if entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, now):
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is not valid at the trusted transaction time")
                return
            try:
                replay_row = self._resolve_request_row(txn, auth)
            except _PendingSignedError as pending:
                outcome["pending"] = pending
                return
            if replay_row is not None:
                # Consume persists no safe response; a reserved consume request
                # therefore means its plaintext was already released.  Reprove
                # the lease it consumed, then return the ephemeral 410.
                lease = txn.fetch_lease_by_consume_request(
                    auth["request"]["request_id"])
                if lease is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved consume request owns no durable consumed "
                        "lease")
                self._verify_persisted_lease_lineage(txn, lease)
                outcome["pending"] = already_released
                return

            age_seconds = (now - auth["request_timestamp"]).total_seconds()
            if not 0 <= age_seconds <= MAX_CLIENT_REQUEST_AGE_SECONDS:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request timestamp is stale or from the future")
                return

            lease = txn.fetch_lease(valid_body["lease_id"])
            if lease is None:
                # Corruption in any caller-referenced capsule/anchor that DOES
                # resolve must fail closed (503) and is never masked by the
                # unknown-lease mismatch verdict.
                self._reprove_referenced_lineage(
                    txn, valid_body, proved_capsule=None, proved_anchor=None)
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the consume request does not resolve one registered lease")
                return
            proved_lease, capsule, anchor, _decision = (
                self._verify_persisted_lease_lineage(txn, lease))
            # A valid lease combined with an existing but corrupted referenced
            # capsule/anchor must fail closed (503), never a mismatch verdict.
            self._reprove_referenced_lineage(
                txn, valid_body, proved_capsule=capsule, proved_anchor=anchor)
            expected_body = self._consume_request_body_from_rows(
                capsule, anchor, proved_lease)
            if valid_body != expected_body:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the consume request does not exactly bind the registered "
                    "lease lineage")
                return

            # Evaluator-key binding (P0): only the exact evaluator that holds
            # the durable lease may consume it.  This is enforced before any
            # state disclosure, decrypt, sign or mutation, so a second active
            # evaluator can never steal or even probe another's lease.
            if auth["request"]["caller_key_id"] \
                    != proved_lease["evaluator_key_id"]:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the consume request does not bind the registered lease "
                    "evaluator")
                return

            state = proved_lease["state"]
            if state == "EXPIRED":
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 410, "LEASE_EXPIRED",
                    "the lease expired before consumption")
                return
            if state != "ISSUED":
                # CONSUMED, or FAILED via completion timeout: the one plaintext
                # was already released for this lease.
                outcome["pending"] = already_released
                return

            lease_expires = _utc_instant(
                proved_lease["expires_at"], "lease expires_at")
            if not now < lease_expires:
                # Half-open boundary: due processing should already have
                # expired it; fail closed to the terminal lease-expiry verdict.
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 410, "LEASE_EXPIRED",
                    "the lease reached its expiry before consumption")
                return
            anchor_expires = _utc_instant(
                anchor["expires_at"], "anchor expires_at")
            completion_deadline = min(
                now + timedelta(seconds=_COMPLETION_LIFETIME_SECONDS),
                anchor_expires)
            if not now < completion_deadline:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 410, "LEASE_EXPIRED",
                    "no completion window remains before anchor expiry")
                return

            # Reload the strict AES key inside the transaction and decrypt.
            reloaded = self._reload_aes_key()
            aad_bytes = _persisted_blob(capsule, "aad_bytes")
            ciphertext = _persisted_blob(capsule, "ciphertext")
            tag = _persisted_blob(capsule, "authentication_tag")
            try:
                plaintext = AESGCM(reloaded).decrypt(
                    bytes.fromhex(capsule["aes_nonce_hex"]),
                    ciphertext + tag, aad_bytes)
            except Exception as exc:
                raise FinalHoldoutAuthorityUnavailableError(
                    "capsule ciphertext failed authenticated decryption under "
                    "the reloaded key") from exc
            if capsule["payload_sha256"] != _SHA256_PREFIX \
                    + hashlib.sha256(plaintext).hexdigest():
                raise FinalHoldoutAuthorityUnavailableError(
                    "decrypted payload hash does not match the sealed capsule "
                    "payload hash")
            try:
                payload = self._neutral(
                    lambda: validate_final_holdout_capsule_payload_v1(
                        json.loads(plaintext.decode("utf-8"))))
            except (ValueError, TypeError, RecursionError) as exc:
                raise FinalHoldoutAuthorityUnavailableError(
                    "decrypted payload failed closed re-validation") from exc
            if canonical_json_bytes(payload) != plaintext:
                raise FinalHoldoutAuthorityUnavailableError(
                    "decrypted payload is not the exact canonical payload")
            if payload["evaluation_start_offset"] \
                    != capsule["evaluation_start_offset"]:
                raise FinalHoldoutAuthorityUnavailableError(
                    "decrypted payload offset does not match the capsule")

            # Fresh, mutation-isolated observation documents.
            primary = json.loads(
                canonical_json_bytes(payload["primary_observations"])
                .decode("utf-8"))
            benchmark = json.loads(
                canonical_json_bytes(payload["benchmark_observations"])
                .decode("utf-8"))
            deadline_text = _format_utc(completion_deadline)
            success_body = {
                "body_version": FINAL_HOLDOUT_CONSUME_RESPONSE_BODY_VERSION_V1,
                "code": "PLAINTEXT_RELEASED",
                "request_id": auth["request"]["request_id"],
                "release_id": capsule["release_id"],
                "lease_id": proved_lease["lease_id"],
                "capsule_id": capsule["capsule_id"],
                "anchor_id": anchor["anchor_id"],
                "run_id": capsule["run_id"],
                "capsule_payload_sha256": capsule["payload_sha256"],
                "evaluation_start_offset": payload["evaluation_start_offset"],
                "primary_observations": primary,
                "benchmark_observations": benchmark,
                "consumed_at": now_text,
                "completion_deadline": deadline_text,
                "state": "CONSUMED",
            }
            # Sign the plaintext wrapper BEFORE any lifecycle mutation, so a
            # signer failure aborts before the transitions and releases nothing.
            response, fresh_body, wrapper_bytes, _resp_bytes, _body_bytes = (
                self._signed_wrapper(
                    status_code=200, body=success_body,
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"], now=now))
            # Record only the fact that a plaintext-bearing response has been
            # prepared before any persistence begins.  If any subsequent store
            # operation fails, the outer handler must discard the response and
            # perform no further database IO.
            outcome["plaintext_prepared"] = True
            self._reserve_request(txn, auth, now)
            txn.consume_lease(
                proved_lease["lease_id"], auth["request"]["request_id"],
                now_text, deadline_text)
            txn.transition_anchor(anchor["anchor_id"], "LEASED", "CONSUMED")
            # The plaintext wrapper is NEVER persisted; it is returned once from
            # memory after the transaction commits.
            outcome["consume"] = (response, fresh_body, wrapper_bytes)
            outcome["kind"] = "consume_success"

        try:
            self._store.run_transaction(transaction)
            pending = outcome.get("pending")
            if isinstance(pending, _PendingSignedError):
                self._raise_signed_error(
                    pending.error_class,
                    status_code=pending.status_code,
                    code=pending.code,
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message=pending.message,
                    record_hash=auth["request_hash"],
                )
        except _PendingSignedError as pending:
            self._raise_signed_error(
                pending.error_class,
                status_code=pending.status_code,
                code=pending.code,
                request_id=auth["request"]["request_id"],
                request_nonce=auth["request"]["nonce"],
                message=pending.message,
                record_hash=auth["request_hash"],
            )
        except FinalHoldoutAuthorityUnavailableError as exc:
            # If an in-memory plaintext wrapper was prepared before the failure,
            # discard it and emit only an ephemeral 503 WITHOUT any DB write.
            if outcome.pop("plaintext_prepared", False) \
                    or outcome.pop("consume", None) is not None:
                self._discard_plaintext_and_raise_503(auth, str(exc))
            self._raise_signed_unavailable(auth, str(exc))
        except FinalHoldoutAuthorityStoreError as exc:
            # An indeterminate commit, or any store failure after the plaintext
            # wrapper was prepared, is a durably ambiguous outcome: discard the
            # plaintext, perform NO further DB read/write/retry (no
            # untrusted_attempts, no collision retry), and emit only an
            # ephemeral 503 without a record-hash write.  A later fresh request
            # alone resolves the durable lease state.
            if exc.commit_indeterminate \
                    or outcome.pop("plaintext_prepared", False) \
                    or outcome.pop("consume", None) is not None:
                self._discard_plaintext_and_raise_503(
                    auth,
                    "the consume outcome is durably indeterminate; no plaintext "
                    "is released")
            if exc.collision:
                self._raise_signed_error(
                    FinalHoldoutConflictError,
                    status_code=409,
                    code="IDENTIFIER_COLLISION",
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message="authority-generated identifiers collided",
                    record_hash=auth["request_hash"],
                )
            self._raise_signed_unavailable(auth, str(exc))

        if outcome.get("kind") == "consume_success":
            response, fresh_body, wrapper_bytes = outcome["consume"]
            return FinalHoldoutAnchorRegistrationResult(
                response_body=fresh_body,
                service_response=response,
                signed_response_wrapper_bytes=wrapper_bytes,
                replayed=False,
            )
        raise FinalHoldoutAuthorityUnavailableError(
            "consume completed without producing a result")

    def _discard_plaintext_and_raise_503(
        self, auth: Mapping[str, Any], message: str
    ) -> None:
        """Emit an ephemeral 503 with NO database write after a plaintext abort.

        Used only when a consume plaintext wrapper was prepared or the commit
        was indeterminate.  It signs the sanitized 503 (no store access, so no
        ``untrusted_attempts`` row and no retry); if the response signer itself
        is dead the bare unsigned unavailable propagates, which the contract
        permits as its sole post-parse unsigned failure.  It never returns
        plaintext.
        """
        self._raise_signed_error(
            FinalHoldoutAuthorityUnavailableError,
            status_code=503,
            code="AUTHORITY_UNAVAILABLE",
            request_id=auth["request"]["request_id"],
            request_nonce=auth["request"]["nonce"],
            message=message,
            record_hash=None,
        )

    # -------------------------------------------------------------- complete

    def complete(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutAnchorRegistrationResult:
        """Authenticate one evaluator and durably finalize one consumed lease.

        A consumed lease is conditionally advanced ``CONSUMED->SUCCEEDED`` or
        ``CONSUMED->FAILED`` and its anchor ``CONSUMED->TERMINAL`` in one
        transaction that also writes the signed terminal audit and the exact
        persisted completion wrapper.  The closed outcome maps privately to
        ``EVALUATION_SUCCEEDED`` / ``EXPLICIT_EVALUATION_FAILED``.  An exact
        retry recovers the byte-identical wrapper; any changed body, replayed
        nonce, racing completion or elapsed deadline loses under the closed law.
        """
        try:
            valid_body = validate_final_holdout_completion_request_body_v1(body)
            body_bytes = canonical_final_holdout_completion_request_body_bytes(
                valid_body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        expected_path = FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1.format(
            lease_id=valid_body["lease_id"])
        auth = self._authenticated_request(
            client_request,
            operation=_COMPLETE_OPERATION,
            expected_path=expected_path,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
            max_body_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            required_role=FINAL_EVALUATOR_ROLE,
        )
        outcome: dict[str, Any] = {}

        def transaction(txn: Any) -> None:
            now = self._trusted_now()
            now_text = _format_utc(now)
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, now)
            entry = auth["entry"]
            if entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, now):
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is not valid at the trusted transaction time")
                return
            try:
                replay_row = self._resolve_request_row(txn, auth)
            except _PendingSignedError as pending:
                outcome["pending"] = pending
                return
            if replay_row is not None:
                # Exact completion retry: recover the byte-identical wrapper.
                safe_row = txn.fetch_safe_response(
                    auth["request"]["request_id"])
                if safe_row is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved completion request has no persisted safe "
                        "response")
                self._verify_persisted_request(
                    replay_row, safe_row=safe_row, auth=auth,
                    expected_operation=_COMPLETE_OPERATION,
                    expected_body=body_bytes)
                response, stored_body, wrapper = (
                    self._verify_persisted_safe_response(replay_row, safe_row))
                if response["request_id"] != auth["request"]["request_id"] \
                        or response["request_nonce"] != auth["request"]["nonce"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "the persisted completion response does not bind the "
                        "current request identity and nonce")
                lease = txn.fetch_lease_by_completion_request(
                    auth["request"]["request_id"])
                if lease is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved completion request owns no durable "
                        "completed lease")
                self._verify_persisted_lease_lineage(txn, lease)
                outcome["kind"] = "replayed"
                outcome["result"] = (response, stored_body, wrapper)
                return

            age_seconds = (now - auth["request_timestamp"]).total_seconds()
            if not 0 <= age_seconds <= MAX_CLIENT_REQUEST_AGE_SECONDS:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request timestamp is stale or from the future")
                return

            lease = txn.fetch_lease(valid_body["lease_id"])
            if lease is None:
                self._reprove_referenced_lineage(
                    txn, valid_body, proved_capsule=None, proved_anchor=None)
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the completion request does not resolve one registered "
                    "lease")
                return
            proved_lease, capsule, anchor, decision = (
                self._verify_persisted_lease_lineage(txn, lease))
            self._reprove_referenced_lineage(
                txn, valid_body, proved_capsule=capsule, proved_anchor=anchor)
            expected_body = self._completion_request_body_from_rows(
                capsule, anchor, proved_lease, valid_body["outcome"])
            if valid_body != expected_body:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the completion request does not exactly bind the "
                    "registered lease lineage")
                return
            if auth["request"]["caller_key_id"] \
                    != proved_lease["evaluator_key_id"]:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the completion request does not bind the registered lease "
                    "evaluator")
                return

            state = proved_lease["state"]
            if state == "EXPIRED":
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 410, "LEASE_EXPIRED",
                    "the lease expired before completion")
                return
            if state == "ISSUED":
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "COMPLETION_STATE_CONFLICT",
                    "the lease has not released its plaintext and cannot be "
                    "completed")
                return
            if state in ("SUCCEEDED", "FAILED"):
                # A racing completion or a completion timeout already reached a
                # terminal state; the loser never reconstructs a winner.
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "COMPLETION_STATE_CONFLICT",
                    "the lease already reached a terminal completion state")
                return

            # state == CONSUMED: due processing has already timed out any lease
            # past its half-open deadline, so a live consumed lease is strictly
            # before its deadline; a survivor otherwise is durable corruption.
            deadline = _utc_instant(
                proved_lease["completion_deadline"],
                "lease completion_deadline")
            if not now < deadline:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a consumed lease survived due processing past its "
                    "completion deadline")
            # Causal time (P1-1): the terminal instant must not precede the
            # lease's own consumption.  A backward trusted clock therefore fails
            # closed before any signing or persistence, leaving the durable
            # CONSUMED lease, its anchor and audits exactly as they were.
            consumed = _utc_instant(
                proved_lease["consumed_at"], "lease consumed_at")
            if now < consumed:
                raise FinalHoldoutAuthorityUnavailableError(
                    "the trusted completion instant precedes the lease "
                    "consumption instant")

            if valid_body["outcome"] == "evaluation_succeeded":
                new_state = "SUCCEEDED"
                terminal_reason = "EVALUATION_SUCCEEDED"
                audit_outcome = "evaluation_succeeded"
            else:
                new_state = "FAILED"
                terminal_reason = "EXPLICIT_EVALUATION_FAILED"
                audit_outcome = "evaluation_failed"

            # Sign the terminal audit and completion wrapper BEFORE any
            # lifecycle mutation, so a dead signer aborts before the transition.
            audit, unsigned, signed = self._signed_access_audit(
                release_id=capsule["release_id"],
                anchor_id=anchor["anchor_id"],
                anchor_sha256=anchor["anchor_sha256"],
                tenant_id=capsule["tenant_id"],
                workspace_id=capsule["workspace_id"],
                run_id=capsule["run_id"],
                request_id=proved_lease["lease_request_id"],
                lease_id=proved_lease["lease_id"],
                requested_at=decision["requested_at"],
                decided_at=decision["decided_at"],
                consumed_at=proved_lease["consumed_at"],
                outcome=audit_outcome,
                denial_reason=None,
                now=now,
            )
            response_body = {
                "body_version":
                    FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1,
                "code": "EVALUATION_COMPLETED",
                "request_id": auth["request"]["request_id"],
                "lease_id": proved_lease["lease_id"],
                "terminal_audit": audit,
                "signed_terminal_audit_bytes_hex": signed.hex(),
            }
            prepared_result = self._prepare_result(
                auth, status_code=200, body=response_body, now=now)
            self._reserve_request(txn, auth, now)
            self._insert_terminal_audit(
                txn, audit=audit, unsigned_bytes=unsigned,
                signed_bytes=signed, created_at=now_text)
            txn.complete_lease(
                proved_lease["lease_id"], auth["request"]["request_id"],
                now_text, new_state, terminal_reason)
            txn.transition_anchor(anchor["anchor_id"], "CONSUMED", "TERMINAL")
            response, fresh_body, wrapper_bytes = self._insert_prepared_result(
                txn, prepared_result)
            outcome["kind"] = "success"
            outcome["result"] = (response, fresh_body, wrapper_bytes)

        self._run_terminal_transaction(auth, outcome, transaction)
        if outcome.get("kind") in ("success", "replayed"):
            response, fresh_body, wrapper_bytes = outcome["result"]
            return FinalHoldoutAnchorRegistrationResult(
                response_body=fresh_body,
                service_response=response,
                signed_response_wrapper_bytes=wrapper_bytes,
                replayed=bool(outcome["kind"] == "replayed"),
            )
        raise FinalHoldoutAuthorityUnavailableError(
            "complete finished without producing a result")

    # ------------------------------------------------------- audit retrieval

    def retrieve_audit(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutAnchorRegistrationResult:
        """Authenticate one evaluator and return one lease's audit or pending.

        A nonterminal lease returns only the frozen ``202 AUDIT_PENDING`` body;
        a terminal lease returns the exact persisted signed terminal audit in
        the ``200 TERMINAL_AUDIT_RETURNED`` body.  The first authenticated
        retrieval is safely persisted so an exact retry returns byte-identical
        bytes; a later new retrieval after the lease turns terminal returns the
        terminal audit.  No observation, ciphertext, plan or private terminal
        reason is ever exposed.
        """
        try:
            valid_body = validate_final_holdout_audit_retrieval_body_v1(body)
            body_bytes = canonical_final_holdout_audit_retrieval_body_bytes(
                valid_body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        expected_path = FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1.format(
            lease_id=valid_body["lease_id"])
        auth = self._authenticated_request(
            client_request,
            operation=_AUDIT_RETRIEVE_OPERATION,
            expected_path=expected_path,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
            max_body_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
            required_role=FINAL_EVALUATOR_ROLE,
        )
        outcome: dict[str, Any] = {}

        def transaction(txn: Any) -> None:
            now = self._trusted_now()
            self._revalidate_trust_pins()
            self._expire_due_in_transaction(txn, now)
            entry = auth["entry"]
            if entry["status"] != "active" \
                    or not self._client_key_valid_at(entry, now):
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "caller key is not valid at the trusted transaction time")
                return
            try:
                replay_row = self._resolve_request_row(txn, auth)
            except _PendingSignedError as pending:
                outcome["pending"] = pending
                return
            if replay_row is not None:
                # Exact retrieval retry: fully re-prove the durable retrieval —
                # its reconstructed body, evaluator ownership, response binding
                # and terminal/pending snapshot — then recover the byte-identical
                # wrapper.  A pending retry after later terminalization still
                # returns its original pending bytes (never the terminal audit).
                safe_row = txn.fetch_safe_response(
                    auth["request"]["request_id"])
                if safe_row is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a reserved audit retrieval request has no persisted "
                        "safe response")
                response, stored_body, wrapper = (
                    self._verify_persisted_retrieval(
                        txn, replay_row, safe_row, auth=auth))
                if response["request_id"] != auth["request"]["request_id"] \
                        or response["request_nonce"] != auth["request"]["nonce"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "the persisted retrieval response does not bind the "
                        "current request identity and nonce")
                outcome["kind"] = "recovered"
                outcome["result"] = (response, stored_body, wrapper)
                return

            age_seconds = (now - auth["request_timestamp"]).total_seconds()
            if not 0 <= age_seconds <= MAX_CLIENT_REQUEST_AGE_SECONDS:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutAuthenticationError, 401,
                    "AUTHENTICATION_FAILED",
                    "request timestamp is stale or from the future")
                return

            lease = txn.fetch_lease(valid_body["lease_id"])
            if lease is None:
                self._reprove_referenced_lineage(
                    txn, valid_body, proved_capsule=None, proved_anchor=None)
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the audit retrieval request does not resolve one "
                    "registered lease")
                return
            proved_lease, capsule, anchor, _decision = (
                self._verify_persisted_lease_lineage(txn, lease))
            self._reprove_referenced_lineage(
                txn, valid_body, proved_capsule=capsule, proved_anchor=anchor)
            expected_body = self._audit_retrieval_body_from_rows(
                capsule, anchor, proved_lease)
            if valid_body != expected_body:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the audit retrieval request does not exactly bind the "
                    "registered lease lineage")
                return
            if auth["request"]["caller_key_id"] \
                    != proved_lease["evaluator_key_id"]:
                outcome["pending"] = _PendingSignedError(
                    FinalHoldoutConflictError, 409, "BINDING_MISMATCH",
                    "the audit retrieval request does not bind the registered "
                    "lease evaluator")
                return

            # Causal time (P1-2): a fresh retrieval snapshot must not be stamped
            # before the fact it reports.  Every retrieval is at/after the lease
            # decision; a terminal retrieval is additionally at/after the lease
            # terminalization and its signed audit's creation.  A backward clock
            # fails closed before any persistence.
            decided = _utc_instant(
                proved_lease["decided_at"], "lease decided_at")
            if now < decided:
                raise FinalHoldoutAuthorityUnavailableError(
                    "the trusted retrieval instant precedes the lease decision "
                    "instant")

            if proved_lease["state"] in ("ISSUED", "CONSUMED"):
                response_body = {
                    "body_version":
                        FINAL_HOLDOUT_AUDIT_PENDING_RESPONSE_BODY_VERSION_V1,
                    "code": "AUDIT_PENDING",
                    "message": FINAL_HOLDOUT_AUDIT_PENDING_MESSAGE,
                    "request_id": auth["request"]["request_id"],
                    "lease_id": proved_lease["lease_id"],
                }
                status_code = 202
            else:
                audit_row = txn.fetch_terminal_audit_by_lease(
                    proved_lease["lease_id"])
                if audit_row is None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a terminal lease has no durable terminal audit")
                terminal = _utc_instant(
                    proved_lease["terminal_at"], "lease terminal_at")
                audit_created = _utc_instant(
                    str(audit_row["created_at"]), "terminal audit created_at")
                if now < terminal or now < audit_created:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "the trusted retrieval instant precedes the lease "
                        "terminalization or its audit creation")
                # The lease-lineage re-proof already fully revalidated this
                # audit row, its signature and its byte identity.
                signed = _persisted_blob(audit_row, "signed_audit_bytes")
                audit = json.loads(signed.decode("utf-8"))
                response_body = {
                    "body_version":
                        FINAL_HOLDOUT_TERMINAL_AUDIT_RESPONSE_BODY_VERSION_V1,
                    "code": "TERMINAL_AUDIT_RETURNED",
                    "request_id": auth["request"]["request_id"],
                    "lease_id": proved_lease["lease_id"],
                    "terminal_audit": audit,
                    "signed_terminal_audit_bytes_hex": signed.hex(),
                }
                status_code = 200
            prepared_result = self._prepare_result(
                auth, status_code=status_code, body=response_body, now=now)
            self._reserve_request(txn, auth, now)
            response, fresh_body, wrapper_bytes = self._insert_prepared_result(
                txn, prepared_result)
            outcome["kind"] = "fresh"
            outcome["result"] = (response, fresh_body, wrapper_bytes)

        self._run_terminal_transaction(auth, outcome, transaction)
        if outcome.get("kind") in ("fresh", "recovered"):
            response, fresh_body, wrapper_bytes = outcome["result"]
            return FinalHoldoutAnchorRegistrationResult(
                response_body=fresh_body,
                service_response=response,
                signed_response_wrapper_bytes=wrapper_bytes,
                replayed=bool(outcome["kind"] == "recovered"),
            )
        raise FinalHoldoutAuthorityUnavailableError(
            "retrieve_audit finished without producing a result")

    def _run_terminal_transaction(
        self,
        auth: Mapping[str, Any],
        outcome: dict[str, Any],
        transaction: Callable[[Any], None],
    ) -> None:
        """Run one complete/retrieve transaction and map its typed failures.

        These two operations persist only ordinary signed safe responses (never
        plaintext), so their post-transaction failure mapping mirrors the lease
        skeleton: a pending signed caller error, a signed-but-ephemeral 503 for
        every unavailability, and an identifier collision that is never treated
        as idempotent success.
        """
        try:
            self._store.run_transaction(transaction)
            pending = outcome.get("pending")
            if isinstance(pending, _PendingSignedError):
                self._raise_signed_error(
                    pending.error_class,
                    status_code=pending.status_code,
                    code=pending.code,
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message=pending.message,
                    record_hash=auth["request_hash"],
                )
        except _PendingSignedError as pending:
            self._raise_signed_error(
                pending.error_class,
                status_code=pending.status_code,
                code=pending.code,
                request_id=auth["request"]["request_id"],
                request_nonce=auth["request"]["nonce"],
                message=pending.message,
                record_hash=auth["request_hash"],
            )
        except FinalHoldoutAuthorityUnavailableError as exc:
            self._raise_signed_unavailable(auth, str(exc))
        except FinalHoldoutAuthorityStoreError as exc:
            if exc.collision:
                self._raise_signed_error(
                    FinalHoldoutConflictError,
                    status_code=409,
                    code="IDENTIFIER_COLLISION",
                    request_id=auth["request"]["request_id"],
                    request_nonce=auth["request"]["nonce"],
                    message="authority-generated identifiers collided",
                    record_hash=auth["request_hash"],
                )
            self._raise_signed_unavailable(auth, str(exc))

    # ------------------------------------------------------- capsule registration

    def register_capsule(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutCapsuleRegistrationResult:
        try:
            derived = validate_final_holdout_capsule_registration_body_v1(body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        body_bytes = canonical_json_bytes({
            "body_version": FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "validation_plan": derived["validation_plan"],
            "primary_observations": derived["primary_observations"],
        })
        auth = self._authenticated_request(
            client_request,
            operation=_CAPSULE_OPERATION,
            expected_path=FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
            max_body_bytes=MAX_CAPSULE_REGISTRATION_BODY_BYTES,
        )
        plan = derived["validation_plan"]

        def semantic(txn: Any, txn_now: datetime):
            authorities = plan["authorities"]
            if authorities["holdout_authority_id"] != self._config.authority_id \
                    or authorities["holdout_authority_key_id"] \
                    != self._config.authority_signer_key_id:
                return self._denial_body(
                    txn_now, auth, 409, "BINDING_MISMATCH",
                    "the plan does not bind this authority identity and signer")
            existing = txn.run_capsule_id(
                plan["release_id"], plan["tenant_id"],
                plan["workspace_id"], plan["run_id"],
            )
            if existing is not None:
                return self._denial_body(
                    txn_now, auth, 409, "RUN_ALREADY_REGISTERED",
                    "this run tuple already holds its one registered capsule")
            budget = {"remaining": IDENTIFIER_GENERATION_ATTEMPTS}
            capsule_id = self._fresh_capsule_id(txn, budget)
            aes_nonce = self._fresh_aes_nonce(txn, budget)
            plan_bytes = canonical_json_bytes(plan)
            plan_self_hash = plan["validation_plan_hash"]
            complete_plan_hash = _SHA256_PREFIX + hashlib.sha256(
                plan_bytes).hexdigest()
            window = plan["final_window"]
            aad_object = {
                "aad_version": "final-holdout-capsule-aad-v1",
                "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
                "authority_id": self._config.authority_id,
                "capsule_id": capsule_id,
                "payload_encryption_algorithm": "aes-256-gcm",
                "payload_encryption_key_id": (
                    self._config.payload_encryption_key_id),
                "release_id": plan["release_id"],
                "tenant_id": plan["tenant_id"],
                "workspace_id": plan["workspace_id"],
                "run_id": plan["run_id"],
                "confirmed_spec_hash": plan["confirmed_spec_hash"],
                "primary_snapshot_sha256": plan["snapshot_sha256"],
                "benchmark_snapshot_sha256": plan["snapshot_sha256"],
                "validation_plan_hash": plan_self_hash,
                "complete_validation_plan_sha256": complete_plan_hash,
                "locked_rule_sha256": plan["locked_rule_sha256"],
                "base_costs_sha256": plan["base_costs_sha256"],
                "final_window": dict(window),
                "primary_observations_sha256": (
                    derived["primary_observations_sha256"]),
                "benchmark_observations_sha256": (
                    derived["benchmark_observations_sha256"]),
                "capsule_payload_sha256": derived["capsule_payload_sha256"],
            }
            aad_bytes = self._neutral(
                lambda: canonical_final_holdout_capsule_aad_v1_bytes(aad_object))
            payload_bytes = canonical_json_bytes(derived["capsule_payload"])
            try:
                sealed = AESGCM(self._aes_key).encrypt(
                    aes_nonce, payload_bytes, aad_bytes)
            except Exception as exc:
                raise FinalHoldoutAuthorityUnavailableError(
                    "capsule payload encryption failed closed"
                ) from exc
            ciphertext, tag = sealed[:-16], sealed[-16:]
            instrument = derived["primary_observations"]["instruments"][0]
            success_body = {
                "body_version": (
                    FINAL_HOLDOUT_CAPSULE_REGISTRATION_RESPONSE_BODY_VERSION_V1),
                "code": "CAPSULE_REGISTERED",
                "request_id": auth["request"]["request_id"],
                "capsule_id": capsule_id,
                "release_id": plan["release_id"],
                "tenant_id": plan["tenant_id"],
                "workspace_id": plan["workspace_id"],
                "run_id": plan["run_id"],
                "validation_plan_hash": plan_self_hash,
                "complete_validation_plan_sha256": complete_plan_hash,
                "capsule_payload_sha256": derived["capsule_payload_sha256"],
                "primary_observations_sha256": (
                    derived["primary_observations_sha256"]),
                "benchmark_observations_sha256": (
                    derived["benchmark_observations_sha256"]),
                "registered_at": _format_utc(txn_now),
                "state": "REGISTERED",
            }
            txn.insert_capsule({
                "capsule_id": capsule_id,
                "registration_request_id": auth["request"]["request_id"],
                "payload_version": FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
                "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
                "authority_id": self._config.authority_id,
                "holdout_authority_key_id": (
                    self._config.authority_signer_key_id),
                "registered_at": _format_utc(txn_now),
                "release_id": plan["release_id"],
                "tenant_id": plan["tenant_id"],
                "workspace_id": plan["workspace_id"],
                "run_id": plan["run_id"],
                "confirmed_spec_sha256": plan["confirmed_spec_hash"],
                "primary_snapshot_sha256": plan["snapshot_sha256"],
                "benchmark_snapshot_sha256": plan["snapshot_sha256"],
                "validation_plan_sha256": plan_self_hash,
                "complete_validation_plan_sha256": complete_plan_hash,
                "validation_plan_bytes": plan_bytes,
                "locked_rule_sha256": plan["locked_rule_sha256"],
                "base_costs_sha256": plan["base_costs_sha256"],
                "market_observations_version": (
                    plan["market_observations_version"]),
                "canonicalization_policy_version": (
                    plan["canonicalization_policy_version"]),
                "exchange_calendar_id": plan["exchange_calendar_id"],
                "exchange_calendar_version": plan["exchange_calendar_version"],
                "primary_instrument_id": instrument["symbol"],
                "benchmark_instrument_id": instrument["symbol"],
                "currency": instrument["currency"],
                "n_bars": plan["n_bars"],
                "development_bars": plan["development_bars"],
                "final_start_index": window["start_index"],
                "final_end_index": window["end_index"],
                "final_bars": window["bars"],
                "warmup_start_index": window["warmup_start_index"],
                "warmup_bars": window["warmup_bars"],
                "evaluation_start_offset": derived["evaluation_start_offset"],
                "capsule_observation_count": (
                    window["warmup_bars"] + window["bars"]),
                "registered_final_holdout_fraction_json": (
                    canonical_json_bytes(
                        plan["registered_final_holdout_fraction"]
                    ).decode("utf-8")),
                "final_holdout_fraction_json": (
                    canonical_json_bytes(
                        plan["final_holdout_fraction"]).decode("utf-8")),
                "primary_observations_sha256": (
                    derived["primary_observations_sha256"]),
                "benchmark_observations_sha256": (
                    derived["benchmark_observations_sha256"]),
                "payload_sha256": derived["capsule_payload_sha256"],
                "payload_size_bytes": len(payload_bytes),
                "encryption_algorithm": "aes-256-gcm",
                "encryption_key_id": self._config.payload_encryption_key_id,
                "aes_nonce_hex": aes_nonce.hex(),
                "aad_sha256": _SHA256_PREFIX + hashlib.sha256(
                    aad_bytes).hexdigest(),
                "aad_bytes": aad_bytes,
                "ciphertext_sha256": _SHA256_PREFIX + hashlib.sha256(
                    ciphertext).hexdigest(),
                "ciphertext": ciphertext,
                "authentication_tag": tag,
            })
            return 200, success_body, "success", "capsule registered"

        def verify_replay(txn: Any, stored: Mapping[str, Any]) -> None:
            request_id = auth["request"]["request_id"]
            capsule_row = txn.fetch_capsule_by_request(request_id)
            anchor_row = txn.fetch_anchor_by_request(request_id)
            if str(stored["response_code"]) != "CAPSULE_REGISTERED":
                # A recovered denial must PROVE the absence of durable state:
                # no capsule or anchor row may reference the denied request.
                if capsule_row is not None or anchor_row is not None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a denied registration owns a durable lineage row"
                    )
                return
            if capsule_row is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a registered capsule success has no durable capsule row"
                )
            if anchor_row is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a capsule registration owns a contradictory anchor row"
                )
            self._verify_persisted_capsule(txn, capsule_row)

        return self._run_registration(
            auth, semantic, FinalHoldoutCapsuleRegistrationResult,
            verify_replay=verify_replay)

    def _reject_invalid_body(self, client_request: object, message: str) -> None:
        """One invalid body: signed-but-ephemeral when the envelope parses."""
        try:
            request = validate_final_holdout_client_request_v1(client_request)
        except FinalHoldoutAccessProtocolError:
            digest = _SHA256_PREFIX + hashlib.sha256(
                repr(client_request).encode("utf-8", errors="replace")).hexdigest()
            self._record_untrusted_attempt(
                digest, "INVALID_REQUEST", self._trusted_now())
            raise FinalHoldoutRequestError(message) from None
        request_hash = _SHA256_PREFIX + hashlib.sha256(
            canonical_json_bytes(request)).hexdigest()
        self._raise_signed_error(
            FinalHoldoutRequestError,
            status_code=400,
            code="INVALID_REQUEST",
            request_id=request["request_id"],
            request_nonce=request["nonce"],
            message=message,
            record_hash=request_hash,
        )

    def _denial_body(
        self, txn_now: datetime, auth: Mapping[str, Any],
        status_code: int, code: str, message: str,
    ) -> tuple[int, dict[str, Any], str, str]:
        body = {
            "body_version": FINAL_HOLDOUT_ERROR_RESPONSE_BODY_VERSION_V1,
            "code": code,
            "message": FINAL_HOLDOUT_ERROR_STATUS_MESSAGES[status_code],
            "request_id": auth["request"]["request_id"],
        }
        return status_code, body, "denial", message

    @staticmethod
    def _spend_generation_attempt(budget: dict[str, int]) -> None:
        if budget["remaining"] <= 0:
            raise FinalHoldoutAuthorityUnavailableError(
                "authority identifier generation exhausted its shared bounded "
                "budget of attempts"
            )
        budget["remaining"] -= 1

    def _fresh_capsule_id(self, txn: Any, budget: dict[str, int]) -> str:
        while True:
            self._spend_generation_attempt(budget)
            candidate = "fha-cap-" + self._generated_token("capsule id")
            if txn.fetch_capsule(candidate) is None:
                return candidate

    def _fresh_aes_nonce(self, txn: Any, budget: dict[str, int]) -> bytes:
        while True:
            self._spend_generation_attempt(budget)
            candidate = self._generated_aes_nonce()
            if txn.aes_nonce_capsule_id(candidate.hex()) is None:
                return candidate

    # -------------------------------------------------------- anchor registration

    def register_anchor(
        self, client_request: object, *, body: object,
    ) -> FinalHoldoutAnchorRegistrationResult:
        try:
            valid_body = validate_final_holdout_anchor_registration_body_v1(body)
        except FinalHoldoutAccessProtocolError as exc:
            self._reject_invalid_body(client_request, str(exc))
            raise AssertionError  # unreachable
        body_bytes = canonical_json_bytes(valid_body)
        auth = self._authenticated_request(
            client_request,
            operation=_ANCHOR_OPERATION,
            expected_path=FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
            body_bytes=body_bytes,
            body_version=FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
            max_body_bytes=MAX_CLIENT_REQUEST_BODY_BYTES,
        )
        anchor = valid_body["anchor"]
        receipt = valid_body["registration_receipt"]

        def semantic(txn: Any, txn_now: datetime):
            capsule = txn.fetch_capsule(valid_body["capsule_id"])
            if capsule is None:
                return self._denial_body(
                    txn_now, auth, 409, "BINDING_MISMATCH",
                    "the submitted bindings do not resolve to one registered "
                    "capsule")
            # The durable encrypted capsule and its registered plan are fully
            # re-proved before any anchor trust decision reads them.
            plan, bindings = self._verify_persisted_capsule(txn, capsule)
            plan_anchor_authority = plan["authorities"]["anchor_authority_id"]
            if self._issuer_tree["authority_id"] != plan_anchor_authority:
                return self._denial_body(
                    txn_now, auth, 409, "BINDING_MISMATCH",
                    "the configured plan-anchor issuer bundle does not serve "
                    "this plan's anchor authority")
            if receipt["authority_id"] != plan_anchor_authority:
                return self._denial_body(
                    txn_now, auth, 400, "INVALID_REQUEST",
                    "the embedded receipt does not bind the plan's anchor "
                    "authority")
            issuer_entry = self._issuer_key_entry(anchor["issuer_key_id"])
            if issuer_entry is None or issuer_entry["status"] != "active":
                return self._denial_body(
                    txn_now, auth, 400, "INVALID_REQUEST",
                    "the embedded anchor issuer key is not a trusted active key")
            try:
                unsigned_anchor = canonical_unsigned_anchor_bytes(anchor)
                unsigned_receipt = (
                    canonical_unsigned_registration_receipt_bytes(receipt))
            except PlanAnchorProtocolError as exc:
                raise FinalHoldoutAuthorityUnavailableError(str(exc)) from exc
            signed_anchor = bytes.fromhex(
                valid_body["registered_signed_anchor_bytes_hex"])
            signed_receipt = bytes.fromhex(
                valid_body["registered_signed_receipt_bytes_hex"])
            issuer_ok = (
                self._issuer_signature_holds(
                    issuer_entry, anchor["signature"],
                    ANCHOR_DOMAIN_V1 + unsigned_anchor)
                and self._issuer_signature_holds(
                    issuer_entry, receipt["signature"],
                    PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1
                    + unsigned_receipt)
            )
            if not issuer_ok:
                return self._denial_body(
                    txn_now, auth, 400, "INVALID_REQUEST",
                    "an embedded B2 signature does not hold under its domain")
            unsigned_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
                unsigned_anchor).hexdigest()
            signed_anchor_hash = _SHA256_PREFIX + hashlib.sha256(
                signed_anchor).hexdigest()
            receipt_hash = _SHA256_PREFIX + hashlib.sha256(
                signed_receipt).hexdigest()
            issued_at = _utc_instant(anchor["issued_at"], "anchor issued_at")
            expires_at = _utc_instant(anchor["expires_at"], "anchor expires_at")
            registered_at = _utc_instant(
                receipt["registered_at"], "receipt registered_at")
            receipt_ok = (
                receipt["issuer_key_id"] == anchor["issuer_key_id"]
                and receipt["unsigned_anchor_sha256"] == unsigned_anchor_hash
                and receipt["signed_anchor_sha256"] == signed_anchor_hash
                and receipt["registered_signed_anchor_bytes_sha256"]
                == signed_anchor_hash
                and receipt["state"] == "REGISTERED"
                and issued_at <= registered_at < expires_at
                and (expires_at - issued_at).total_seconds()
                <= _MAX_ANCHOR_LIFETIME_SECONDS
                and self._issuer_key_valid_over(
                    issuer_entry, (issued_at, registered_at, txn_now))
            )
            if not receipt_ok:
                return self._denial_body(
                    txn_now, auth, 400, "INVALID_REQUEST",
                    "the embedded receipt does not bind the submitted anchor")
            if not issued_at <= txn_now:
                return self._denial_body(
                    txn_now, auth, 400, "INVALID_REQUEST",
                    "the submitted anchor is issued in the future")
            if not txn_now < expires_at:
                return self._denial_body(
                    txn_now, auth, 410, "ANCHOR_EXPIRED",
                    "the submitted anchor is expired at the trusted time")
            if not self._anchor_binds_capsule(anchor, bindings):
                return self._denial_body(
                    txn_now, auth, 409, "BINDING_MISMATCH",
                    "the submitted bindings do not equal the registered "
                    "capsule and plan")
            if txn.fetch_anchor(anchor["anchor_id"]) is not None:
                return self._denial_body(
                    txn_now, auth, 409, "ANCHOR_ALREADY_REGISTERED",
                    "this anchor id already holds its one registration")
            if txn.fetch_anchor_by_capsule(valid_body["capsule_id"]) is not None:
                return self._denial_body(
                    txn_now, auth, 409, "CAPSULE_ALREADY_BOUND",
                    "this capsule already holds its one registered anchor")
            nonce_owner = txn.anchor_nonce_anchor_id(anchor["nonce"])
            if nonce_owner is not None:
                return self._denial_body(
                    txn_now, auth, 409, "IDENTIFIER_COLLISION",
                    "the anchor nonce is already owned by a registered anchor")
            success_body = {
                "body_version": (
                    FINAL_HOLDOUT_ANCHOR_REGISTRATION_RESPONSE_BODY_VERSION_V1),
                "code": "ANCHOR_REGISTERED",
                "request_id": auth["request"]["request_id"],
                "capsule_id": valid_body["capsule_id"],
                "anchor_id": anchor["anchor_id"],
                "anchor_sha256": signed_anchor_hash,
                "registration_receipt_sha256": receipt_hash,
                "release_id": capsule["release_id"],
                "tenant_id": capsule["tenant_id"],
                "workspace_id": capsule["workspace_id"],
                "run_id": capsule["run_id"],
                "registered_at": _format_utc(txn_now),
                "anchor_expires_at": anchor["expires_at"],
                "state": "REGISTERED",
            }
            txn.insert_anchor({
                "anchor_id": anchor["anchor_id"],
                "capsule_id": valid_body["capsule_id"],
                "registration_request_id": auth["request"]["request_id"],
                "anchor_nonce": anchor["nonce"],
                "issuer_key_id": anchor["issuer_key_id"],
                "issued_at": anchor["issued_at"],
                "expires_at": anchor["expires_at"],
                "registered_at": _format_utc(txn_now),
                "unsigned_anchor_sha256": unsigned_anchor_hash,
                "unsigned_anchor_bytes": unsigned_anchor,
                "anchor_signature_hex": anchor["signature"],
                "anchor_sha256": signed_anchor_hash,
                "signed_anchor_bytes": signed_anchor,
                "receipt_sha256": receipt_hash,
                "signed_receipt_bytes": signed_receipt,
                "state": "REGISTERED",
            })
            return 200, success_body, "success", "anchor registered"

        def verify_replay(txn: Any, stored: Mapping[str, Any]) -> None:
            request_id = auth["request"]["request_id"]
            anchor_row = txn.fetch_anchor_by_request(request_id)
            capsule_ref = txn.fetch_capsule_by_request(request_id)
            if str(stored["response_code"]) != "ANCHOR_REGISTERED":
                # A recovered denial must PROVE the absence of durable state:
                # no anchor or capsule row may reference the denied request.
                if anchor_row is not None or capsule_ref is not None:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "a denied registration owns a durable lineage row"
                    )
                return
            if anchor_row is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a registered anchor success has no durable anchor row"
                )
            if capsule_ref is not None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "an anchor registration owns a contradictory capsule row"
                )
            capsule = txn.fetch_capsule(str(anchor_row["capsule_id"]))
            if capsule is None:
                raise FinalHoldoutAuthorityUnavailableError(
                    "a registered anchor references a missing capsule row"
                )
            plan, bindings = self._verify_persisted_capsule(txn, capsule)
            lease = txn.fetch_lease_by_anchor(anchor_row["anchor_id"])
            if lease is None:
                self._verify_persisted_anchor(
                    txn, anchor_row, capsule, plan, bindings,
                    expected_state="REGISTERED")
            else:
                proved_lease, proved_capsule, proved_anchor, _decision = (
                    self._verify_persisted_lease_lineage(txn, lease))
                if proved_lease["anchor_id"] != anchor_row["anchor_id"] \
                        or proved_anchor["anchor_id"] != anchor_row["anchor_id"] \
                        or proved_capsule["capsule_id"] != capsule["capsule_id"]:
                    raise FinalHoldoutAuthorityUnavailableError(
                        "an anchor registration replay references "
                        "contradictory lease lineage")

        return self._run_registration(
            auth, semantic, FinalHoldoutAnchorRegistrationResult,
            verify_replay=verify_replay)

    def _issuer_key_entry(self, key_id: str) -> dict[str, Any] | None:
        return next(
            (entry for entry in self._issuer_tree["keys"]
             if entry["key_id"] == key_id),
            None,
        )

    @staticmethod
    def _issuer_signature_holds(
        entry: Mapping[str, Any], signature_hex: str, message: bytes
    ) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(entry["public_key_hex"])
            ).verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError):
            return False
        return True

    def _issuer_key_valid_over(
        self, entry: Mapping[str, Any], instants: tuple[datetime, ...]
    ) -> bool:
        not_before = _utc_instant(entry["not_before"], "issuer not_before")
        not_after = _utc_instant(entry["not_after"], "issuer not_after")
        return all(not_before <= instant < not_after for instant in instants)

    def _capsule_plan(
        self, capsule: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Revalidate the registered plan bytes; returns (plan, bindings).

        The persisted bytes must BE the canonical bytes of the valid plan, not
        merely parse to an object whose recanonicalization matches a hash: a
        whitespace-different or otherwise non-canonical persisted plan fails
        closed even when its parsed content is unchanged.
        """
        plan_bytes = _persisted_blob(capsule, "validation_plan_bytes")
        try:
            plan = validate_complete_validation_plan_v3(
                json.loads(plan_bytes.decode("utf-8")))
            bindings = derive_anchor_bindings_from_plan_v3(plan)
        except (PlanAnchorProtocolError, ValueError, TypeError,
                RecursionError) as exc:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted capsule plan bytes failed closed re-validation"
            ) from exc
        if canonical_json_bytes(plan) != plan_bytes:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted capsule plan bytes are not the exact canonical "
                "plan bytes"
            )
        complete_plan_hash = _SHA256_PREFIX + hashlib.sha256(
            plan_bytes).hexdigest()
        if complete_plan_hash != capsule["complete_validation_plan_sha256"]:
            raise FinalHoldoutAuthorityUnavailableError(
                "persisted capsule plan hash failed the durable binding check"
            )
        return plan, bindings

    def _verify_persisted_request(
        self,
        request_row: Mapping[str, Any],
        *,
        safe_row: Mapping[str, Any] | None,
        auth: Mapping[str, Any] | None = None,
        expected_operation: str | None = None,
        expected_authenticated_at: str | None = None,
        expected_body: bytes | None = None,
    ) -> dict[str, Any]:
        """Complete fail-closed re-proof of one authenticated_requests row.

        Every column is bound: exact storage classes and grammars; the stored
        signed request bytes parse and revalidate under the neutral law, their
        canonical bytes and hash are recomputed, and every embedded field binds
        its column; the operation binds its frozen route, body version and size
        cap; the caller key must exist, be active and valid at the recorded
        request timestamp with a holding Ed25519 signature.  The row is
        self-authenticating in every path: ``authenticated_at`` binds the
        persisted signed authority result that owns the request (its response
        timestamp, which equals its ``created_at``), and — whenever the exact
        canonical body is reconstructible from durable success lineage or from
        the current authenticated request — ``body_sha256`` and
        ``body_size_bytes`` bind those exact bytes.  A mutated row is
        unavailability — never a freed nonce, a fresh reservation, a conflict
        verdict against a caller or a recovered response.
        """
        unavailable = FinalHoldoutAuthorityUnavailableError

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted request failed the {label} re-validation"
                )

        request_bytes = _persisted_blob(request_row, "request_bytes")
        for column in (
            "request_id", "request_nonce", "operation", "authority_id",
            "caller_role", "caller_key_id", "method", "path",
            "request_timestamp", "request_sha256", "body_version",
            "body_sha256", "authenticated_at",
        ):
            check(type(request_row[column]) is str, f"{column} storage class")
        check(type(request_row["body_size_bytes"]) is int,
              "body_size_bytes storage class")
        check(
            _REQUEST_ID_RE.fullmatch(request_row["request_id"]) is not None,
            "request id grammar",
        )
        check(
            _NONCE_HEX_RE.fullmatch(request_row["request_nonce"]) is not None,
            "request nonce grammar",
        )
        for column in ("request_sha256", "body_sha256"):
            check(
                _PREFIXED_SHA256_RE.fullmatch(request_row[column]) is not None,
                f"{column} grammar",
            )
        request_timestamp = _utc_instant(
            request_row["request_timestamp"], "persisted request timestamp")
        _utc_instant(request_row["authenticated_at"],
                     "persisted request authenticated_at")
        # A persisted safe result owns every operation except a successful
        # consume.  Consume intentionally persists no plaintext response, so
        # its authenticated_at is instead bound to the durable consumed_at
        # supplied by its exact lease lineage.
        if safe_row is not None:
            check(
                request_row["authenticated_at"]
                == safe_row["response_timestamp"] == safe_row["created_at"],
                "authenticated_at binding",
            )
        else:
            check(
                expected_authenticated_at is not None
                and request_row["authenticated_at"]
                == expected_authenticated_at,
                "plaintext-free authenticated_at binding",
            )
        if expected_body is not None:
            check(
                request_row["body_sha256"]
                == _SHA256_PREFIX + hashlib.sha256(expected_body).hexdigest()
                and request_row["body_size_bytes"] == len(expected_body),
                "body reconstruction binding",
            )
        operation_laws = {
            _CAPSULE_OPERATION: (
                FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
                FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
                MAX_CAPSULE_REGISTRATION_BODY_BYTES,
            ),
            _ANCHOR_OPERATION: (
                FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
                FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
                MAX_CLIENT_REQUEST_BODY_BYTES,
            ),
            _LEASE_OPERATION: (
                FINAL_HOLDOUT_LEASE_PATH_V1,
                FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
                MAX_CLIENT_REQUEST_BODY_BYTES,
            ),
            _CONSUME_OPERATION: (
                None,
                FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
                MAX_CLIENT_REQUEST_BODY_BYTES,
            ),
            _COMPLETE_OPERATION: (
                None,
                FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
                MAX_CLIENT_REQUEST_BODY_BYTES,
            ),
            _AUDIT_RETRIEVE_OPERATION: (
                None,
                FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
                MAX_CLIENT_REQUEST_BODY_BYTES,
            ),
        }
        law = operation_laws.get(str(request_row["operation"]))
        check(law is not None, "operation vocabulary")
        assert law is not None
        expected_path, expected_body_version, size_cap = law
        # The three evaluator lease-scoped operations carry the lease id in their
        # path; the exact path is reconstructed from the canonical body.
        _templated_paths = {
            _CONSUME_OPERATION: FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1,
            _COMPLETE_OPERATION: FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1,
            _AUDIT_RETRIEVE_OPERATION: FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1,
        }
        if request_row["operation"] in _templated_paths:
            check(expected_body is not None, "lease-scoped body reconstruction")
            assert expected_body is not None
            try:
                reconstructed = json.loads(expected_body.decode("utf-8"))
                expected_path = _templated_paths[
                    request_row["operation"]].format(
                        lease_id=reconstructed["lease_id"])
            except (KeyError, UnicodeDecodeError, ValueError, TypeError) as exc:
                raise unavailable(
                    "persisted lease-scoped request body failed path "
                    "reconstruction"
                ) from exc
        expected_role = (
            CONTROL_PLANE_REGISTRAR_ROLE
            if request_row["operation"] in (
                _CAPSULE_OPERATION, _ANCHOR_OPERATION)
            else FINAL_EVALUATOR_ROLE
        )
        check(
            request_row["caller_role"] == expected_role
            and request_row["method"] == "POST"
            and request_row["path"] == expected_path
            and request_row["body_version"] == expected_body_version
            and 2 <= request_row["body_size_bytes"] <= size_cap,
            "operation law binding",
        )
        check(
            request_row["authority_id"] == self._config.authority_id,
            "authority identity",
        )

        try:
            embedded = validate_final_holdout_client_request_v1(
                json.loads(request_bytes.decode("utf-8")))
            canonical_signed = canonical_json_bytes(embedded)
            unsigned_bytes = (
                canonical_unsigned_final_holdout_client_request_bytes(embedded))
        except (FinalHoldoutAccessProtocolError, ValueError, TypeError,
                RecursionError) as exc:
            raise unavailable(
                "persisted request bytes failed closed re-validation"
            ) from exc
        check(canonical_signed == request_bytes, "request byte identity")
        check(
            request_row["request_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(canonical_signed).hexdigest(),
            "request hash",
        )
        embedded_bindings = (
            ("request_id", "request_id"),
            ("nonce", "request_nonce"),
            ("authority_id", "authority_id"),
            ("caller_role", "caller_role"),
            ("caller_key_id", "caller_key_id"),
            ("method", "method"),
            ("path", "path"),
            ("timestamp", "request_timestamp"),
            ("body_sha256", "body_sha256"),
        )
        for field, column in embedded_bindings:
            check(embedded[field] == request_row[column], f"{column} binding")

        entry = self._client_key_entry(
            str(request_row["caller_role"]), str(request_row["caller_key_id"]))
        check(
            entry is not None and entry["status"] == "active"
            and self._client_key_valid_at(entry, request_timestamp),
            "caller key status",
        )
        assert entry is not None
        try:
            self._verify_client_signature(entry, embedded, unsigned_bytes)
        except FinalHoldoutAuthenticationError as exc:
            raise unavailable(
                "persisted request signature failed re-validation"
            ) from exc

        if auth is not None:
            check(request_bytes == auth["signed_bytes"],
                  "current request byte binding")
            check(request_row["request_sha256"] == auth["request_hash"],
                  "current request hash binding")
            check(request_row["body_sha256"] == auth["body_hash"],
                  "current body hash binding")
            check(request_row["body_size_bytes"] == auth["body_size"],
                  "current body size binding")
            check(request_row["operation"] == auth["operation"],
                  "current operation binding")
        if expected_operation is not None:
            check(request_row["operation"] == expected_operation,
                  "owning operation binding")
        if expected_authenticated_at is not None:
            check(
                request_row["authenticated_at"] == expected_authenticated_at,
                "owning registration time binding",
            )
        return dict(embedded)

    def _verify_persisted_capsule(
        self, txn: Any, capsule: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Complete fail-closed re-proof of one durable encrypted capsule row.

        Every persisted safe-lineage column is bound back to its owner: exact
        SQLite storage classes and canonical grammars; the configured authority
        identity, signer key and encryption key; the revalidated canonical plan
        (identities, spec/snapshot/rule/cost hashes, protocol versions, calendar,
        window integers, fraction JSON); the authenticated-decrypted canonical
        payload (instrument, currency, offset, count, observation hashes); the
        exact stored AAD bytes under the neutral AAD law; and the original
        authenticated request row plus the persisted signed success-response
        wrapper.  Any single-column mutation in the database fails closed with
        no bytes and no state change.  Returns the revalidated (plan, bindings).
        """
        unavailable = FinalHoldoutAuthorityUnavailableError
        aad_bytes = _persisted_blob(capsule, "aad_bytes")
        ciphertext = _persisted_blob(capsule, "ciphertext")
        tag = _persisted_blob(capsule, "authentication_tag")

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted capsule failed the {label} re-validation"
                )

        # Exact storage classes for every non-BLOB column (BLOBs go through
        # _persisted_blob above and below).
        text_columns = (
            "capsule_id", "registration_request_id", "payload_version",
            "access_protocol", "authority_id", "holdout_authority_key_id",
            "registered_at", "release_id", "tenant_id", "workspace_id",
            "run_id", "confirmed_spec_sha256", "primary_snapshot_sha256",
            "benchmark_snapshot_sha256", "validation_plan_sha256",
            "complete_validation_plan_sha256", "locked_rule_sha256",
            "base_costs_sha256", "market_observations_version",
            "canonicalization_policy_version", "exchange_calendar_id",
            "exchange_calendar_version", "primary_instrument_id",
            "benchmark_instrument_id", "currency",
            "registered_final_holdout_fraction_json",
            "final_holdout_fraction_json", "primary_observations_sha256",
            "benchmark_observations_sha256", "payload_sha256",
            "encryption_algorithm", "encryption_key_id", "aes_nonce_hex",
            "aad_sha256", "ciphertext_sha256",
        )
        integer_columns = (
            "n_bars", "development_bars", "final_start_index",
            "final_end_index", "final_bars", "warmup_start_index",
            "warmup_bars", "evaluation_start_offset",
            "capsule_observation_count", "payload_size_bytes",
        )
        for column in text_columns:
            check(type(capsule[column]) is str, f"{column} storage class")
        for column in integer_columns:
            check(type(capsule[column]) is int, f"{column} storage class")
        check(
            _CAPSULE_ID_RE.fullmatch(capsule["capsule_id"]) is not None,
            "capsule id grammar",
        )
        check(
            _REQUEST_ID_RE.fullmatch(
                capsule["registration_request_id"]) is not None,
            "registration request id grammar",
        )
        check(
            _AES_NONCE_HEX_RE.fullmatch(capsule["aes_nonce_hex"]) is not None,
            "AES nonce grammar",
        )
        for column in (
            "confirmed_spec_sha256", "primary_snapshot_sha256",
            "benchmark_snapshot_sha256", "validation_plan_sha256",
            "complete_validation_plan_sha256", "locked_rule_sha256",
            "base_costs_sha256", "primary_observations_sha256",
            "benchmark_observations_sha256", "payload_sha256", "aad_sha256",
            "ciphertext_sha256",
        ):
            check(
                _PREFIXED_SHA256_RE.fullmatch(capsule[column]) is not None,
                f"{column} grammar",
            )
        _utc_instant(capsule["registered_at"], "persisted capsule registered_at")

        # Configured-identity bindings.
        check(
            capsule["payload_version"]
            == FINAL_HOLDOUT_CAPSULE_PAYLOAD_VERSION_V1,
            "payload version identity",
        )
        check(
            capsule["access_protocol"] == FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "access protocol identity",
        )
        check(
            capsule["authority_id"] == self._config.authority_id,
            "authority identity",
        )
        check(
            capsule["holdout_authority_key_id"]
            == self._config.authority_signer_key_id,
            "holdout signer identity",
        )
        check(
            capsule["encryption_algorithm"] == "aes-256-gcm"
            and capsule["encryption_key_id"]
            == self._config.payload_encryption_key_id,
            "encryption identity",
        )

        # Canonical-plan bindings: every lineage column derives from the
        # revalidated plan bytes, never from the row itself.
        plan, bindings = self._capsule_plan(capsule)
        authorities = plan["authorities"]
        check(
            authorities["holdout_authority_id"] == self._config.authority_id
            and authorities["holdout_authority_key_id"]
            == self._config.authority_signer_key_id,
            "plan holdout authority binding",
        )
        plan_bindings = (
            ("release_id", plan["release_id"]),
            ("tenant_id", plan["tenant_id"]),
            ("workspace_id", plan["workspace_id"]),
            ("run_id", plan["run_id"]),
            ("confirmed_spec_sha256", plan["confirmed_spec_hash"]),
            ("primary_snapshot_sha256", plan["snapshot_sha256"]),
            ("benchmark_snapshot_sha256", plan["snapshot_sha256"]),
            ("validation_plan_sha256", plan["validation_plan_hash"]),
            ("market_observations_version",
             plan["market_observations_version"]),
            ("canonicalization_policy_version",
             plan["canonicalization_policy_version"]),
            ("exchange_calendar_id", plan["exchange_calendar_id"]),
            ("exchange_calendar_version", plan["exchange_calendar_version"]),
            ("registered_final_holdout_fraction_json",
             canonical_json_bytes(
                 plan["registered_final_holdout_fraction"]).decode("utf-8")),
            ("final_holdout_fraction_json",
             canonical_json_bytes(
                 plan["final_holdout_fraction"]).decode("utf-8")),
        )
        for column, expected in plan_bindings:
            check(capsule[column] == expected, f"{column} plan binding")
        plan_window = plan["final_window"]
        window_bindings = (
            ("n_bars", plan["n_bars"]),
            ("development_bars", plan["development_bars"]),
            ("final_start_index", plan_window["start_index"]),
            ("final_end_index", plan_window["end_index"]),
            ("final_bars", plan_window["bars"]),
            ("warmup_start_index", plan_window["warmup_start_index"]),
            ("warmup_bars", plan_window["warmup_bars"]),
            ("evaluation_start_offset", plan_window["warmup_bars"]),
            ("capsule_observation_count",
             plan_window["warmup_bars"] + plan_window["bars"]),
        )
        for column, expected in window_bindings:
            check(capsule[column] == expected, f"{column} window binding")
        check(len(tag) == 16, "authentication tag shape")
        check(
            capsule["ciphertext_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(ciphertext).hexdigest(),
            "ciphertext hash",
        )
        check(
            aad_bytes.startswith(FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1),
            "AAD domain",
        )
        try:
            aad_object = json.loads(
                aad_bytes[len(FINAL_HOLDOUT_CAPSULE_AAD_DOMAIN_V1):]
                .decode("utf-8"))
            recomputed_aad = self._neutral(
                lambda: canonical_final_holdout_capsule_aad_v1_bytes(aad_object))
        except (ValueError, TypeError, RecursionError) as exc:
            raise unavailable(
                "persisted capsule AAD bytes failed closed re-validation"
            ) from exc
        check(recomputed_aad == aad_bytes, "AAD byte identity")
        check(
            capsule["aad_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(aad_bytes).hexdigest(),
            "AAD hash",
        )
        window_columns = {
            "n_bars": capsule["n_bars"],
            "start_index": capsule["final_start_index"],
            "end_index": capsule["final_end_index"],
            "bars": capsule["final_bars"],
            "warmup_start_index": capsule["warmup_start_index"],
            "warmup_bars": capsule["warmup_bars"],
        }
        aad_bindings = (
            ("authority_id", self._config.authority_id),
            ("capsule_id", capsule["capsule_id"]),
            ("payload_encryption_key_id",
             self._config.payload_encryption_key_id),
            ("release_id", capsule["release_id"]),
            ("tenant_id", capsule["tenant_id"]),
            ("workspace_id", capsule["workspace_id"]),
            ("run_id", capsule["run_id"]),
            ("confirmed_spec_hash", capsule["confirmed_spec_sha256"]),
            ("primary_snapshot_sha256", capsule["primary_snapshot_sha256"]),
            ("benchmark_snapshot_sha256", capsule["benchmark_snapshot_sha256"]),
            ("validation_plan_hash", capsule["validation_plan_sha256"]),
            ("complete_validation_plan_sha256",
             capsule["complete_validation_plan_sha256"]),
            ("locked_rule_sha256", capsule["locked_rule_sha256"]),
            ("base_costs_sha256", capsule["base_costs_sha256"]),
            ("final_window", window_columns),
            ("primary_observations_sha256",
             capsule["primary_observations_sha256"]),
            ("benchmark_observations_sha256",
             capsule["benchmark_observations_sha256"]),
            ("capsule_payload_sha256", capsule["payload_sha256"]),
        )
        for field, expected in aad_bindings:
            check(aad_object.get(field) == expected, f"AAD {field} binding")
        try:
            plaintext = AESGCM(self._aes_key).decrypt(
                bytes.fromhex(capsule["aes_nonce_hex"]), ciphertext + tag,
                aad_bytes)
        except Exception as exc:
            raise unavailable(
                "persisted capsule ciphertext failed authenticated decryption"
            ) from exc
        check(
            len(plaintext) == capsule["payload_size_bytes"]
            and capsule["payload_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(plaintext).hexdigest(),
            "payload hash",
        )
        try:
            payload = self._neutral(
                lambda: validate_final_holdout_capsule_payload_v1(
                    json.loads(plaintext.decode("utf-8"))))
        except (ValueError, TypeError, RecursionError) as exc:
            raise unavailable(
                "persisted capsule plaintext failed closed re-validation"
            ) from exc
        check(canonical_json_bytes(payload) == plaintext, "payload byte identity")
        check(
            payload["evaluation_start_offset"]
            == capsule["evaluation_start_offset"],
            "payload offset binding",
        )
        instrument = payload["primary_observations"]["instruments"][0]
        sessions = instrument["sessions"]
        check(
            len(sessions) == capsule["capsule_observation_count"],
            "payload observation count",
        )
        primary_document_hash = _SHA256_PREFIX + hashlib.sha256(
            canonical_json_bytes(payload["primary_observations"])).hexdigest()
        benchmark_document_hash = _SHA256_PREFIX + hashlib.sha256(
            canonical_json_bytes(payload["benchmark_observations"])).hexdigest()
        check(
            capsule["primary_observations_sha256"] == primary_document_hash
            and capsule["benchmark_observations_sha256"]
            == benchmark_document_hash
            and benchmark_document_hash == primary_document_hash,
            "payload observation hash",
        )
        check(
            capsule["primary_instrument_id"] == instrument["symbol"]
            and capsule["benchmark_instrument_id"] == instrument["symbol"],
            "payload instrument binding",
        )
        check(
            capsule["currency"] == instrument["currency"],
            "payload currency binding",
        )
        check(
            payload["primary_observations"]["snapshot_sha256"]
            == plan["snapshot_sha256"]
            and payload["primary_observations"]["exchange_calendar_id"]
            == plan["exchange_calendar_id"]
            and payload["primary_observations"]["exchange_calendar_version"]
            == plan["exchange_calendar_version"],
            "payload snapshot/calendar binding",
        )

        # Cross-check against the original authenticated request and the exact
        # persisted signed success response this capsule was registered under.
        # The exact canonical registration body is reconstructed from the
        # revalidated plan and decrypted observations, proving the request
        # row's body hash AND size from durable facts.
        reconstructed_body = canonical_json_bytes({
            "body_version": FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "validation_plan": plan,
            "primary_observations": payload["primary_observations"],
        })
        request_row = txn.fetch_authenticated_request(
            capsule["registration_request_id"])
        check(request_row is not None, "registration request existence")
        assert request_row is not None
        safe_row = txn.fetch_safe_response(capsule["registration_request_id"])
        check(safe_row is not None, "registration safe-response existence")
        assert safe_row is not None
        self._verify_persisted_request(
            request_row,
            safe_row=safe_row,
            expected_operation=_CAPSULE_OPERATION,
            expected_authenticated_at=str(capsule["registered_at"]),
            expected_body=reconstructed_body,
        )
        response, response_body, _wrapper_bytes = (
            self._verify_persisted_safe_response(request_row, safe_row))
        check(
            int(safe_row["status_code"]) == 200
            and safe_row["response_code"] == "CAPSULE_REGISTERED",
            "registration safe-response identity",
        )
        response_bindings = (
            ("capsule_id", capsule["capsule_id"]),
            ("request_id", capsule["registration_request_id"]),
            ("release_id", capsule["release_id"]),
            ("tenant_id", capsule["tenant_id"]),
            ("workspace_id", capsule["workspace_id"]),
            ("run_id", capsule["run_id"]),
            ("validation_plan_hash", capsule["validation_plan_sha256"]),
            ("complete_validation_plan_sha256",
             capsule["complete_validation_plan_sha256"]),
            ("capsule_payload_sha256", capsule["payload_sha256"]),
            ("primary_observations_sha256",
             capsule["primary_observations_sha256"]),
            ("benchmark_observations_sha256",
             capsule["benchmark_observations_sha256"]),
            ("registered_at", capsule["registered_at"]),
        )
        for field, expected in response_bindings:
            check(response_body.get(field) == expected,
                  f"registration response {field} binding")
        check(
            response["timestamp"] == capsule["registered_at"]
            and response["authority_id"] == self._config.authority_id
            and response["authority_key_id"]
            == self._config.authority_signer_key_id,
            "registration response envelope binding",
        )
        return plan, bindings

    def _anchor_binds_capsule(
        self, anchor: Mapping[str, Any], bindings: Mapping[str, Any]
    ) -> bool:
        """Every plan-derived binding must hold against the registered plan."""
        return all(
            anchor[field] == bindings[field]
            for field in _PLAN_BOUND_ANCHOR_FIELDS
        )

    def _verify_persisted_anchor(
        self,
        txn: Any,
        anchor_row: Mapping[str, Any],
        capsule: Mapping[str, Any],
        plan: Mapping[str, Any],
        bindings: Mapping[str, Any],
        *,
        expected_state: str = "REGISTERED",
    ) -> None:
        """Complete fail-closed re-proof of one durable registered-anchor row.

        Every persisted column is bound back to its owner: exact storage
        classes and canonical grammars; the recomputed canonical signed and
        unsigned anchor and receipt bytes and their hashes; the issuer trust
        bundle's authority, key status, validity windows and both Ed25519
        signatures under their distinct domains; every plan/capsule binding of
        the embedded anchor; and the original authenticated request row plus
        the exact persisted signed success-response wrapper.  Any single-column
        mutation in the database fails closed with no bytes and no state
        change.
        """
        unavailable = FinalHoldoutAuthorityUnavailableError

        def check(condition: bool, label: str) -> None:
            if not condition:
                raise unavailable(
                    f"persisted anchor failed the {label} re-validation"
                )

        unsigned_bytes = _persisted_blob(anchor_row, "unsigned_anchor_bytes")
        signed_bytes = _persisted_blob(anchor_row, "signed_anchor_bytes")
        receipt_bytes = _persisted_blob(anchor_row, "signed_receipt_bytes")
        for column in (
            "anchor_id", "capsule_id", "registration_request_id",
            "anchor_nonce", "issuer_key_id", "issued_at", "expires_at",
            "registered_at", "unsigned_anchor_sha256", "anchor_signature_hex",
            "anchor_sha256", "receipt_sha256", "state",
        ):
            check(type(anchor_row[column]) is str, f"{column} storage class")
        check(
            _ANCHOR_ID_RE.fullmatch(anchor_row["anchor_id"]) is not None,
            "anchor id grammar",
        )
        check(
            anchor_row["capsule_id"] == capsule["capsule_id"],
            "capsule binding",
        )
        check(
            _REQUEST_ID_RE.fullmatch(
                anchor_row["registration_request_id"]) is not None,
            "registration request id grammar",
        )
        check(
            _NONCE_HEX_RE.fullmatch(anchor_row["anchor_nonce"]) is not None,
            "anchor nonce grammar",
        )
        check(
            _SIGNATURE_HEX_RE.fullmatch(
                anchor_row["anchor_signature_hex"]) is not None,
            "anchor signature grammar",
        )
        for column in ("unsigned_anchor_sha256", "anchor_sha256",
                       "receipt_sha256"):
            check(
                _PREFIXED_SHA256_RE.fullmatch(anchor_row[column]) is not None,
                f"{column} grammar",
            )
        issued_at = _utc_instant(
            anchor_row["issued_at"], "persisted anchor issued_at")
        expires_at = _utc_instant(
            anchor_row["expires_at"], "persisted anchor expires_at")
        b3_registered_at = _utc_instant(
            anchor_row["registered_at"], "persisted anchor registered_at")
        # The original B3 registration must itself sit inside the anchor's
        # lifetime: issued_at <= B3 registered_at < expires_at.
        check(
            issued_at <= b3_registered_at < expires_at,
            "registration time law",
        )
        check(
            expected_state in ("REGISTERED", "LEASED", "CONSUMED", "TERMINAL")
            and anchor_row["state"] == expected_state,
            "anchor state",
        )

        # Recompute the canonical anchor and receipt from the stored bytes.
        try:
            anchor = json.loads(signed_bytes.decode("utf-8"))
            canonical_signed = canonical_signed_anchor_bytes(anchor)
            canonical_unsigned = canonical_unsigned_anchor_bytes(anchor)
            receipt = json.loads(receipt_bytes.decode("utf-8"))
            unsigned_receipt = (
                canonical_unsigned_registration_receipt_bytes(receipt))
            canonical_receipt = canonical_json_bytes(receipt)
        except (PlanAnchorProtocolError, FinalHoldoutAccessProtocolError,
                ValueError, TypeError, RecursionError) as exc:
            raise unavailable(
                "persisted anchor bytes failed closed re-validation"
            ) from exc
        check(canonical_signed == signed_bytes, "signed anchor byte identity")
        check(canonical_unsigned == unsigned_bytes,
              "unsigned anchor byte identity")
        check(canonical_receipt == receipt_bytes, "receipt byte identity")
        check(
            anchor_row["unsigned_anchor_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(canonical_unsigned).hexdigest(),
            "unsigned anchor hash",
        )
        check(
            anchor_row["anchor_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(canonical_signed).hexdigest(),
            "signed anchor hash",
        )
        check(
            anchor_row["receipt_sha256"]
            == _SHA256_PREFIX + hashlib.sha256(canonical_receipt).hexdigest(),
            "receipt hash",
        )

        # Column-to-content bindings of the embedded anchor and receipt.
        check(anchor["anchor_id"] == anchor_row["anchor_id"], "anchor id")
        check(anchor["nonce"] == anchor_row["anchor_nonce"], "anchor nonce")
        check(
            anchor["issuer_key_id"] == anchor_row["issuer_key_id"]
            == receipt["issuer_key_id"],
            "issuer key identity",
        )
        check(anchor["issued_at"] == anchor_row["issued_at"], "issued_at")
        check(anchor["expires_at"] == anchor_row["expires_at"], "expires_at")
        check(
            anchor["signature"] == anchor_row["anchor_signature_hex"],
            "anchor signature column",
        )
        check(receipt["anchor_id"] == anchor_row["anchor_id"],
              "receipt anchor binding")
        check(
            receipt["unsigned_anchor_sha256"]
            == anchor_row["unsigned_anchor_sha256"]
            and receipt["signed_anchor_sha256"] == anchor_row["anchor_sha256"]
            and receipt["registered_signed_anchor_bytes_sha256"]
            == anchor_row["anchor_sha256"]
            and receipt["state"] == "REGISTERED",
            "receipt hash bindings",
        )
        receipt_registered = _utc_instant(
            receipt["registered_at"], "persisted receipt registered_at")
        check(
            issued_at <= receipt_registered < expires_at
            and (expires_at - issued_at).total_seconds()
            <= _MAX_ANCHOR_LIFETIME_SECONDS,
            "receipt time bindings",
        )

        # Every plan/capsule binding must hold against the registered plan.
        check(self._anchor_binds_capsule(anchor, bindings), "plan binding")
        plan_anchor_authority = plan["authorities"]["anchor_authority_id"]
        check(
            receipt["authority_id"] == plan_anchor_authority
            and self._issuer_tree["authority_id"] == plan_anchor_authority,
            "anchor authority binding",
        )

        # Issuer trust: active key, validity at the recorded instants, and both
        # Ed25519 signatures under their distinct domains.
        issuer_entry = self._issuer_key_entry(anchor["issuer_key_id"])
        check(
            issuer_entry is not None and issuer_entry["status"] == "active",
            "issuer key status",
        )
        assert issuer_entry is not None
        check(
            self._issuer_key_valid_over(
                issuer_entry,
                (issued_at, receipt_registered, b3_registered_at)),
            "issuer key validity",
        )
        check(
            self._issuer_signature_holds(
                issuer_entry, anchor["signature"],
                ANCHOR_DOMAIN_V1 + canonical_unsigned),
            "anchor signature",
        )
        check(
            self._issuer_signature_holds(
                issuer_entry, receipt["signature"],
                PLAN_ANCHOR_REGISTRATION_RECEIPT_DOMAIN_V1 + unsigned_receipt),
            "receipt signature",
        )

        # Cross-check against the original authenticated request and the exact
        # persisted signed success response this anchor was registered under.
        # The exact canonical registration body is reconstructed from the
        # durable anchor row's own canonical bytes, proving the request row's
        # body hash AND size from durable facts.
        reconstructed_body = canonical_json_bytes({
            "body_version": FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "capsule_id": anchor_row["capsule_id"],
            "anchor": anchor,
            "registered_signed_anchor_bytes_hex": signed_bytes.hex(),
            "registration_receipt": receipt,
            "registered_signed_receipt_bytes_hex": receipt_bytes.hex(),
        })
        request_row = txn.fetch_authenticated_request(
            anchor_row["registration_request_id"])
        check(request_row is not None, "registration request existence")
        assert request_row is not None
        safe_row = txn.fetch_safe_response(
            anchor_row["registration_request_id"])
        check(safe_row is not None, "registration safe-response existence")
        assert safe_row is not None
        self._verify_persisted_request(
            request_row,
            safe_row=safe_row,
            expected_operation=_ANCHOR_OPERATION,
            expected_authenticated_at=str(anchor_row["registered_at"]),
            expected_body=reconstructed_body,
        )
        response, response_body, _wrapper_bytes = (
            self._verify_persisted_safe_response(request_row, safe_row))
        check(
            int(safe_row["status_code"]) == 200
            and safe_row["response_code"] == "ANCHOR_REGISTERED",
            "registration safe-response identity",
        )
        response_bindings = (
            ("request_id", anchor_row["registration_request_id"]),
            ("capsule_id", anchor_row["capsule_id"]),
            ("anchor_id", anchor_row["anchor_id"]),
            ("anchor_sha256", anchor_row["anchor_sha256"]),
            ("registration_receipt_sha256", anchor_row["receipt_sha256"]),
            ("release_id", capsule["release_id"]),
            ("tenant_id", capsule["tenant_id"]),
            ("workspace_id", capsule["workspace_id"]),
            ("run_id", capsule["run_id"]),
            ("registered_at", anchor_row["registered_at"]),
            ("anchor_expires_at", anchor_row["expires_at"]),
        )
        for field, expected in response_bindings:
            check(response_body.get(field) == expected,
                  f"registration response {field} binding")
        check(
            response["timestamp"] == anchor_row["registered_at"]
            and response["authority_id"] == self._config.authority_id
            and response["authority_key_id"]
            == self._config.authority_signer_key_id,
            "registration response envelope binding",
        )


class _PendingSignedError(Exception):
    """Internal marker: abort the transaction, then raise one signed error."""

    def __init__(
        self,
        error_class: type[FinalHoldoutAuthorityError],
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.status_code = status_code
        self.code = code
        self.message = message


__all__ = [
    "MAX_CLIENT_REQUEST_AGE_SECONDS",
    "FinalHoldoutAuthorityConfig",
    "FinalHoldoutCapsuleRegistrationResult",
    "FinalHoldoutAnchorRegistrationResult",
    "FinalHoldoutAuthorityError",
    "FinalHoldoutAuthorityConfigurationError",
    "FinalHoldoutRequestError",
    "FinalHoldoutAuthenticationError",
    "FinalHoldoutConflictError",
    "FinalHoldoutAuthorityUnavailableError",
    "FinalHoldoutAuthorityV1",
]
