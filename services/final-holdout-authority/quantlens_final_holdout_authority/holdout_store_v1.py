"""Authority-only SQLite persistence for the dormant final-holdout authority.

This module owns exactly the complete final B3 authority database schema — the
nine ``STRICT`` tables and three explicit indexes frozen by the controlling B3
contract, including every lease, access-decision, terminal-audit and safe-response
table B3b will need — plus the fail-closed connection preflight and the
transaction mechanics.  It imports nothing but the standard library — never the
neutral protocol, worker, API or web code — and it never calls or references the
main control-plane database helpers or the main variable-directory environment
variable.  B3b may add logic but may not migrate, repair or replace a valid B3a
store.

Initialization is race-safe with two explicit paths: an absent database file is
claimed with ``O_CREAT | O_EXCL``, its inode is pinned from the claiming
descriptor, and only that claimant initializes the application id, user version,
exact tables, exact indexes AND the singleton authority-metadata row in one
``BEGIN EXCLUSIVE`` transaction.  Any existing path is first inspected through the
accepted B2b non-mutating base-plus-WAL preflight: the base file and any durable
``-wal`` sidecar are copied through O_NOFOLLOW-pinned descriptors into a private
snapshot after strict WAL frame-alignment/salt/rolling-checksum validation, and
the copy alone is opened for exact application-id, user-version, schema
fingerprint, PRAGMA and integrity verification, so an invalid, foreign, corrupt or
partially committed store is rejected without changing the original database, WAL
or SHM bytes.  No automatic repair, checkpoint, migration, deletion or rebuild
exists anywhere in this module.

Every write runs under ``BEGIN IMMEDIATE`` with closed predicates, uniqueness and
exact rowcounts; ``untrusted_attempts`` alone is capped and prunable, its oldest
rows removed in the same transaction before insertion; and a successful consume
response can never be stored in ``safe_service_responses``.  A ``COMMIT``
exception is reported as an indeterminate durable outcome — the connection is
closed without a rollback claim and the call never retries or reads itself to
success.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import struct
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

# One process-wide lock serializes authority operations within a cooperative
# same-process race, and a LOCK_EX on the authority directory serializes across
# cooperating processes.  Same-inode verification of each SQLite open is
# deterministic (the connection's own reported main file), so a concurrent
# same-process reader holding its own descriptor never destabilizes it.
_OPERATION_LOCK = threading.Lock()

_SNAPSHOT_CHUNK = 1 << 20

AUTHORITY_DB_APPLICATION_ID = 0x514C4648  # "QLFH"
AUTHORITY_DB_USER_VERSION = 1
AUTHORITY_DB_FILENAME = "final-holdout-authority.sqlite3"
AUTHORITY_DB_SCHEMA_VERSION = "final-holdout-authority-db-v1"

# The only capped, prunable table: a bounded rejection-event record, never a
# reservation.  Oldest rows are deleted transactionally before insertion.
# Frozen by the Codex B3a acceptance clarification of 2026-07-22.
UNTRUSTED_ATTEMPT_MAX_ROWS = 1024

# Busy timeouts are accepted only as non-bool integers in [1, 60000] milliseconds
# inclusive (default 30000); frozen by the same acceptance clarification.
MAX_BUSY_TIMEOUT_MS = 60_000

_SQLITE_HEADER = b"SQLite format 3" + bytes([0])
_EXPECTED_TABLES = (
    "access_decisions",
    "authenticated_requests",
    "authority_metadata",
    "encrypted_capsules",
    "leases",
    "registered_anchors",
    "safe_service_responses",
    "terminal_audits",
    "untrusted_attempts",
)

_HEADER_LENGTH = 100
_HEADER_USER_VERSION = slice(60, 64)
_HEADER_APPLICATION_ID = slice(68, 72)
_HEADER_WRITE_FORMAT = 18  # 2 => write-ahead log
_HEADER_READ_FORMAT = 19  # 2 => write-ahead log
_WAL_FORMAT = 2

# The expected schema is frozen as an explicit canonical fingerprint, independent
# of the production DDL below: a divergence between the DDL and this contract
# value is a rejected build, and a live database must reproduce this exact
# fingerprint.
_EXPECTED_SCHEMA_FINGERPRINT = (
    "sha256:00cc13ad3f98440bea0391055eb61af895dc26677573802accd02b9055e5c91e"
)

_METADATA_IDENTITY_COLUMNS = (
    "schema_version",
    "authority_id",
    "authority_signer_key_id",
    "authority_signer_public_key_hex",
    "authority_trust_bundle_sha256",
    "client_trust_bundle_sha256",
    "plan_anchor_issuer_trust_bundle_sha256",
    "payload_encryption_key_id",
    "payload_encryption_key_sha256",
)
_METADATA_COLUMNS = (*_METADATA_IDENTITY_COLUMNS, "created_at")

_AUTHENTICATED_REQUEST_COLUMNS = (
    "request_id",
    "request_nonce",
    "operation",
    "authority_id",
    "caller_role",
    "caller_key_id",
    "method",
    "path",
    "request_timestamp",
    "request_sha256",
    "request_bytes",
    "body_version",
    "body_sha256",
    "body_size_bytes",
    "authenticated_at",
)

_ENCRYPTED_CAPSULE_COLUMNS = (
    "capsule_id",
    "registration_request_id",
    "payload_version",
    "access_protocol",
    "authority_id",
    "holdout_authority_key_id",
    "registered_at",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "confirmed_spec_sha256",
    "primary_snapshot_sha256",
    "benchmark_snapshot_sha256",
    "validation_plan_sha256",
    "complete_validation_plan_sha256",
    "validation_plan_bytes",
    "locked_rule_sha256",
    "base_costs_sha256",
    "market_observations_version",
    "canonicalization_policy_version",
    "exchange_calendar_id",
    "exchange_calendar_version",
    "primary_instrument_id",
    "benchmark_instrument_id",
    "currency",
    "n_bars",
    "development_bars",
    "final_start_index",
    "final_end_index",
    "final_bars",
    "warmup_start_index",
    "warmup_bars",
    "evaluation_start_offset",
    "capsule_observation_count",
    "registered_final_holdout_fraction_json",
    "final_holdout_fraction_json",
    "primary_observations_sha256",
    "benchmark_observations_sha256",
    "payload_sha256",
    "payload_size_bytes",
    "encryption_algorithm",
    "encryption_key_id",
    "aes_nonce_hex",
    "aad_sha256",
    "aad_bytes",
    "ciphertext_sha256",
    "ciphertext",
    "authentication_tag",
)

_REGISTERED_ANCHOR_COLUMNS = (
    "anchor_id",
    "capsule_id",
    "registration_request_id",
    "anchor_nonce",
    "issuer_key_id",
    "issued_at",
    "expires_at",
    "registered_at",
    "unsigned_anchor_sha256",
    "unsigned_anchor_bytes",
    "anchor_signature_hex",
    "anchor_sha256",
    "signed_anchor_bytes",
    "receipt_sha256",
    "signed_receipt_bytes",
    "state",
)

_SAFE_RESPONSE_COLUMNS = (
    "request_id",
    "operation",
    "status_code",
    "response_code",
    "authority_key_id",
    "response_timestamp",
    "body_sha256",
    "body_bytes",
    "service_response_sha256",
    "service_response_bytes",
    "response_wrapper_sha256",
    "response_wrapper_bytes",
    "contains_plaintext",
    "created_at",
)

# B3b one-use access columns (existing frozen schema; no DDL change).
_LEASE_COLUMNS = (
    "lease_id",
    "lease_request_id",
    "anchor_id",
    "evaluator_key_id",
    "requested_at",
    "decided_at",
    "expires_at",
    "consume_request_id",
    "consumed_at",
    "completion_deadline",
    "completion_request_id",
    "terminal_at",
    "terminal_reason_code",
    "state",
)
_ACCESS_DECISION_COLUMNS = (
    "lease_request_id",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "capsule_id",
    "anchor_id",
    "anchor_sha256",
    "lease_id",
    "requested_at",
    "decided_at",
    "decision",
    "denial_reason",
)
_TERMINAL_AUDIT_COLUMNS = (
    "lease_request_id",
    "lease_id",
    "release_id",
    "anchor_id",
    "anchor_sha256",
    "tenant_id",
    "workspace_id",
    "run_id",
    "outcome",
    "requested_at",
    "decided_at",
    "consumed_at",
    "denial_reason",
    "authority_id",
    "authority_key_id",
    "unsigned_audit_sha256",
    "unsigned_audit_bytes",
    "audit_signature_hex",
    "signed_audit_sha256",
    "signed_audit_bytes",
    "created_at",
)

_LEGAL_ANCHOR_TRANSITIONS = frozenset({
    ("REGISTERED", "LEASED"),
    ("LEASED", "CONSUMED"),
    ("CONSUMED", "TERMINAL"),
    ("LEASED", "TERMINAL"),
})

# The exact frozen DDL of the complete final B3 schema (contract 37 section 6.1):
# nine STRICT tables and three explicit indexes, byte-for-byte.

_CREATE_STATEMENTS = (
    """
CREATE TABLE authority_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version TEXT NOT NULL CHECK(schema_version = 'final-holdout-authority-db-v1'),
    authority_id TEXT NOT NULL,
    authority_signer_key_id TEXT NOT NULL,
    authority_signer_public_key_hex TEXT NOT NULL CHECK(length(authority_signer_public_key_hex) = 64 AND authority_signer_public_key_hex NOT GLOB '*[^0-9a-f]*'),
    authority_trust_bundle_sha256 TEXT NOT NULL CHECK(length(authority_trust_bundle_sha256) = 71 AND substr(authority_trust_bundle_sha256, 1, 7) = 'sha256:' AND substr(authority_trust_bundle_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    client_trust_bundle_sha256 TEXT NOT NULL CHECK(length(client_trust_bundle_sha256) = 71 AND substr(client_trust_bundle_sha256, 1, 7) = 'sha256:' AND substr(client_trust_bundle_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    plan_anchor_issuer_trust_bundle_sha256 TEXT NOT NULL CHECK(length(plan_anchor_issuer_trust_bundle_sha256) = 71 AND substr(plan_anchor_issuer_trust_bundle_sha256, 1, 7) = 'sha256:' AND substr(plan_anchor_issuer_trust_bundle_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    payload_encryption_key_id TEXT NOT NULL,
    payload_encryption_key_sha256 TEXT NOT NULL CHECK(length(payload_encryption_key_sha256) = 71 AND substr(payload_encryption_key_sha256, 1, 7) = 'sha256:' AND substr(payload_encryption_key_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL
) STRICT
""",
    """
CREATE TABLE authenticated_requests (
    request_id TEXT PRIMARY KEY CHECK(length(request_id) = 40 AND substr(request_id, 1, 8) = 'fha-req-' AND substr(request_id, 9) NOT GLOB '*[^0-9a-f]*'),
    request_nonce TEXT NOT NULL UNIQUE CHECK(length(request_nonce) = 32 AND request_nonce NOT GLOB '*[^0-9a-f]*'),
    operation TEXT NOT NULL CHECK(operation IN ('CAPSULE_REGISTER','ANCHOR_REGISTER','LEASE','CONSUME','COMPLETE','AUDIT_RETRIEVE')),
    authority_id TEXT NOT NULL,
    caller_role TEXT NOT NULL CHECK(caller_role IN ('CONTROL_PLANE_REGISTRAR','FINAL_EVALUATOR')),
    caller_key_id TEXT NOT NULL,
    method TEXT NOT NULL CHECK(method = 'POST'),
    path TEXT NOT NULL,
    request_timestamp TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 71 AND substr(request_sha256, 1, 7) = 'sha256:' AND substr(request_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    request_bytes BLOB NOT NULL CHECK(length(request_bytes) > 0),
    body_version TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK(length(body_sha256) = 71 AND substr(body_sha256, 1, 7) = 'sha256:' AND substr(body_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    body_size_bytes INTEGER NOT NULL CHECK(body_size_bytes >= 2),
    authenticated_at TEXT NOT NULL,
    CHECK((operation IN ('CAPSULE_REGISTER','ANCHOR_REGISTER') AND caller_role = 'CONTROL_PLANE_REGISTRAR') OR (operation IN ('LEASE','CONSUME','COMPLETE','AUDIT_RETRIEVE') AND caller_role = 'FINAL_EVALUATOR')),
    CHECK((operation = 'CAPSULE_REGISTER' AND body_size_bytes <= 16777216) OR (operation <> 'CAPSULE_REGISTER' AND body_size_bytes <= 1048576))
) STRICT
""",
    """
CREATE TABLE untrusted_attempts (
    attempt_id INTEGER PRIMARY KEY,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 71 AND substr(request_sha256, 1, 7) = 'sha256:' AND substr(request_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64 AND reason_code NOT GLOB '*[^A-Z0-9_]*'),
    observed_at TEXT NOT NULL
) STRICT
""",
    """
CREATE TABLE encrypted_capsules (
    capsule_id TEXT PRIMARY KEY CHECK(length(capsule_id) = 40 AND substr(capsule_id, 1, 8) = 'fha-cap-' AND substr(capsule_id, 9) NOT GLOB '*[^0-9a-f]*'),
    registration_request_id TEXT NOT NULL UNIQUE REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    payload_version TEXT NOT NULL CHECK(payload_version = 'final-holdout-capsule-payload-v1'),
    access_protocol TEXT NOT NULL CHECK(access_protocol = 'final-holdout-access-v1'),
    authority_id TEXT NOT NULL,
    holdout_authority_key_id TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    release_id TEXT NOT NULL CHECK(release_id = 'quantlens-financial-v3'),
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    confirmed_spec_sha256 TEXT NOT NULL CHECK(length(confirmed_spec_sha256) = 71 AND substr(confirmed_spec_sha256, 1, 7) = 'sha256:' AND substr(confirmed_spec_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    primary_snapshot_sha256 TEXT NOT NULL CHECK(length(primary_snapshot_sha256) = 71 AND substr(primary_snapshot_sha256, 1, 7) = 'sha256:' AND substr(primary_snapshot_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    benchmark_snapshot_sha256 TEXT NOT NULL CHECK(length(benchmark_snapshot_sha256) = 71 AND substr(benchmark_snapshot_sha256, 1, 7) = 'sha256:' AND substr(benchmark_snapshot_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    validation_plan_sha256 TEXT NOT NULL CHECK(length(validation_plan_sha256) = 71 AND substr(validation_plan_sha256, 1, 7) = 'sha256:' AND substr(validation_plan_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    complete_validation_plan_sha256 TEXT NOT NULL CHECK(length(complete_validation_plan_sha256) = 71 AND substr(complete_validation_plan_sha256, 1, 7) = 'sha256:' AND substr(complete_validation_plan_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    validation_plan_bytes BLOB NOT NULL CHECK(length(validation_plan_bytes) > 0),
    locked_rule_sha256 TEXT NOT NULL CHECK(length(locked_rule_sha256) = 71 AND substr(locked_rule_sha256, 1, 7) = 'sha256:' AND substr(locked_rule_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    base_costs_sha256 TEXT NOT NULL CHECK(length(base_costs_sha256) = 71 AND substr(base_costs_sha256, 1, 7) = 'sha256:' AND substr(base_costs_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    market_observations_version TEXT NOT NULL CHECK(market_observations_version = 'market-observations-v2'),
    canonicalization_policy_version TEXT NOT NULL CHECK(canonicalization_policy_version = 'market-observation-canonicalization-v2'),
    exchange_calendar_id TEXT NOT NULL,
    exchange_calendar_version TEXT NOT NULL,
    primary_instrument_id TEXT NOT NULL,
    benchmark_instrument_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    n_bars INTEGER NOT NULL CHECK(n_bars > 0),
    development_bars INTEGER NOT NULL CHECK(development_bars > 0),
    final_start_index INTEGER NOT NULL CHECK(final_start_index >= 0),
    final_end_index INTEGER NOT NULL CHECK(final_end_index > final_start_index),
    final_bars INTEGER NOT NULL CHECK(final_bars > 0),
    warmup_start_index INTEGER NOT NULL CHECK(warmup_start_index >= 0),
    warmup_bars INTEGER NOT NULL CHECK(warmup_bars >= 0),
    evaluation_start_offset INTEGER NOT NULL CHECK(evaluation_start_offset >= 0),
    capsule_observation_count INTEGER NOT NULL CHECK(capsule_observation_count > 0),
    registered_final_holdout_fraction_json TEXT NOT NULL,
    final_holdout_fraction_json TEXT NOT NULL,
    primary_observations_sha256 TEXT NOT NULL CHECK(length(primary_observations_sha256) = 71 AND substr(primary_observations_sha256, 1, 7) = 'sha256:' AND substr(primary_observations_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    benchmark_observations_sha256 TEXT NOT NULL CHECK(length(benchmark_observations_sha256) = 71 AND substr(benchmark_observations_sha256, 1, 7) = 'sha256:' AND substr(benchmark_observations_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 71 AND substr(payload_sha256, 1, 7) = 'sha256:' AND substr(payload_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    payload_size_bytes INTEGER NOT NULL CHECK(payload_size_bytes > 0),
    encryption_algorithm TEXT NOT NULL CHECK(encryption_algorithm = 'aes-256-gcm'),
    encryption_key_id TEXT NOT NULL,
    aes_nonce_hex TEXT NOT NULL UNIQUE CHECK(length(aes_nonce_hex) = 24 AND aes_nonce_hex NOT GLOB '*[^0-9a-f]*'),
    aad_sha256 TEXT NOT NULL CHECK(length(aad_sha256) = 71 AND substr(aad_sha256, 1, 7) = 'sha256:' AND substr(aad_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    aad_bytes BLOB NOT NULL CHECK(length(aad_bytes) > 0),
    ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256) = 71 AND substr(ciphertext_sha256, 1, 7) = 'sha256:' AND substr(ciphertext_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) = payload_size_bytes),
    authentication_tag BLOB NOT NULL CHECK(length(authentication_tag) = 16),
    UNIQUE(release_id, tenant_id, workspace_id, run_id),
    CHECK(benchmark_snapshot_sha256 = primary_snapshot_sha256),
    CHECK(benchmark_instrument_id = primary_instrument_id),
    CHECK(benchmark_observations_sha256 = primary_observations_sha256),
    CHECK(final_end_index = n_bars),
    CHECK(final_start_index = development_bars),
    CHECK(final_bars = final_end_index - final_start_index),
    CHECK(warmup_bars = final_start_index - warmup_start_index),
    CHECK(evaluation_start_offset = warmup_bars),
    CHECK(capsule_observation_count = warmup_bars + final_bars)
) STRICT
""",
    """
CREATE TABLE registered_anchors (
    anchor_id TEXT PRIMARY KEY CHECK(length(anchor_id) = 36 AND substr(anchor_id, 1, 4) = 'vpa-' AND substr(anchor_id, 5) NOT GLOB '*[^0-9a-f]*'),
    capsule_id TEXT NOT NULL UNIQUE REFERENCES encrypted_capsules(capsule_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    registration_request_id TEXT NOT NULL UNIQUE REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    anchor_nonce TEXT NOT NULL UNIQUE CHECK(length(anchor_nonce) = 32 AND anchor_nonce NOT GLOB '*[^0-9a-f]*'),
    issuer_key_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    unsigned_anchor_sha256 TEXT NOT NULL CHECK(length(unsigned_anchor_sha256) = 71 AND substr(unsigned_anchor_sha256, 1, 7) = 'sha256:' AND substr(unsigned_anchor_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    unsigned_anchor_bytes BLOB NOT NULL CHECK(length(unsigned_anchor_bytes) > 0),
    anchor_signature_hex TEXT NOT NULL CHECK(length(anchor_signature_hex) = 128 AND anchor_signature_hex NOT GLOB '*[^0-9a-f]*'),
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256) = 71 AND substr(anchor_sha256, 1, 7) = 'sha256:' AND substr(anchor_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    signed_anchor_bytes BLOB NOT NULL CHECK(length(signed_anchor_bytes) > 0),
    receipt_sha256 TEXT NOT NULL CHECK(length(receipt_sha256) = 71 AND substr(receipt_sha256, 1, 7) = 'sha256:' AND substr(receipt_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    signed_receipt_bytes BLOB NOT NULL CHECK(length(signed_receipt_bytes) > 0),
    state TEXT NOT NULL CHECK(state IN ('REGISTERED','LEASED','CONSUMED','TERMINAL'))
) STRICT
""",
    """
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY CHECK(length(lease_id) = 42 AND substr(lease_id, 1, 10) = 'fha-lease-' AND substr(lease_id, 11) NOT GLOB '*[^0-9a-f]*'),
    lease_request_id TEXT NOT NULL UNIQUE REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    anchor_id TEXT NOT NULL UNIQUE REFERENCES registered_anchors(anchor_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    evaluator_key_id TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consume_request_id TEXT UNIQUE REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    consumed_at TEXT,
    completion_deadline TEXT,
    completion_request_id TEXT UNIQUE REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    terminal_at TEXT,
    terminal_reason_code TEXT,
    state TEXT NOT NULL CHECK(state IN ('ISSUED','CONSUMED','SUCCEEDED','FAILED','EXPIRED')),
    CHECK(
        (state = 'ISSUED' AND consume_request_id IS NULL AND consumed_at IS NULL AND completion_deadline IS NULL AND completion_request_id IS NULL AND terminal_at IS NULL AND terminal_reason_code IS NULL)
        OR (state = 'CONSUMED' AND consume_request_id IS NOT NULL AND consumed_at IS NOT NULL AND completion_deadline IS NOT NULL AND completion_request_id IS NULL AND terminal_at IS NULL AND terminal_reason_code IS NULL)
        OR (state = 'SUCCEEDED' AND consume_request_id IS NOT NULL AND consumed_at IS NOT NULL AND completion_deadline IS NOT NULL AND completion_request_id IS NOT NULL AND terminal_at IS NOT NULL AND terminal_reason_code = 'EVALUATION_SUCCEEDED')
        OR (state = 'FAILED' AND consume_request_id IS NOT NULL AND consumed_at IS NOT NULL AND completion_deadline IS NOT NULL AND terminal_at IS NOT NULL AND terminal_reason_code IN ('EXPLICIT_EVALUATION_FAILED','COMPLETION_TIMEOUT') AND ((terminal_reason_code = 'EXPLICIT_EVALUATION_FAILED' AND completion_request_id IS NOT NULL) OR (terminal_reason_code = 'COMPLETION_TIMEOUT' AND completion_request_id IS NULL)))
        OR (state = 'EXPIRED' AND consume_request_id IS NULL AND consumed_at IS NULL AND completion_deadline IS NULL AND completion_request_id IS NULL AND terminal_at IS NOT NULL AND terminal_reason_code = 'LEASE_EXPIRED')
    )
) STRICT
""",
    """
CREATE TABLE access_decisions (
    lease_request_id TEXT PRIMARY KEY REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    release_id TEXT NOT NULL CHECK(release_id = 'quantlens-financial-v3'),
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    capsule_id TEXT NOT NULL,
    anchor_id TEXT NOT NULL,
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256) = 71 AND substr(anchor_sha256, 1, 7) = 'sha256:' AND substr(anchor_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    lease_id TEXT UNIQUE REFERENCES leases(lease_id) ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    requested_at TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('LEASE_ISSUED','LEASE_DENIED')),
    denial_reason TEXT,
    CHECK((decision = 'LEASE_ISSUED' AND lease_id IS NOT NULL AND denial_reason IS NULL) OR (decision = 'LEASE_DENIED' AND lease_id IS NULL AND denial_reason IS NOT NULL AND length(denial_reason) BETWEEN 1 AND 256))
) STRICT
""",
    """
CREATE TABLE terminal_audits (
    lease_request_id TEXT PRIMARY KEY REFERENCES access_decisions(lease_request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    lease_id TEXT UNIQUE REFERENCES leases(lease_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    release_id TEXT NOT NULL CHECK(release_id = 'quantlens-financial-v3'),
    anchor_id TEXT NOT NULL,
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256) = 71 AND substr(anchor_sha256, 1, 7) = 'sha256:' AND substr(anchor_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('denied','lease_expired','evaluation_succeeded','evaluation_failed')),
    requested_at TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    consumed_at TEXT,
    denial_reason TEXT,
    authority_id TEXT NOT NULL,
    authority_key_id TEXT NOT NULL,
    unsigned_audit_sha256 TEXT NOT NULL CHECK(length(unsigned_audit_sha256) = 71 AND substr(unsigned_audit_sha256, 1, 7) = 'sha256:' AND substr(unsigned_audit_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    unsigned_audit_bytes BLOB NOT NULL CHECK(length(unsigned_audit_bytes) > 0),
    audit_signature_hex TEXT NOT NULL CHECK(length(audit_signature_hex) = 128 AND audit_signature_hex NOT GLOB '*[^0-9a-f]*'),
    signed_audit_sha256 TEXT NOT NULL CHECK(length(signed_audit_sha256) = 71 AND substr(signed_audit_sha256, 1, 7) = 'sha256:' AND substr(signed_audit_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    signed_audit_bytes BLOB NOT NULL CHECK(length(signed_audit_bytes) > 0),
    created_at TEXT NOT NULL,
    CHECK(
        (outcome = 'denied' AND lease_id IS NULL AND consumed_at IS NULL AND denial_reason IS NOT NULL)
        OR (outcome = 'lease_expired' AND lease_id IS NOT NULL AND consumed_at IS NULL AND denial_reason = 'LEASE_EXPIRED')
        OR (outcome IN ('evaluation_succeeded','evaluation_failed') AND lease_id IS NOT NULL AND consumed_at IS NOT NULL AND denial_reason IS NULL)
    )
) STRICT
""",
    """
CREATE TABLE safe_service_responses (
    request_id TEXT PRIMARY KEY REFERENCES authenticated_requests(request_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    operation TEXT NOT NULL CHECK(operation IN ('CAPSULE_REGISTER','ANCHOR_REGISTER','LEASE','CONSUME','COMPLETE','AUDIT_RETRIEVE')),
    status_code INTEGER NOT NULL CHECK(status_code BETWEEN 200 AND 599),
    response_code TEXT NOT NULL CHECK(length(response_code) BETWEEN 1 AND 64 AND response_code NOT GLOB '*[^A-Z0-9_]*'),
    authority_key_id TEXT NOT NULL,
    response_timestamp TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK(length(body_sha256) = 71 AND substr(body_sha256, 1, 7) = 'sha256:' AND substr(body_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    body_bytes BLOB NOT NULL CHECK(length(body_bytes) > 0),
    service_response_sha256 TEXT NOT NULL CHECK(length(service_response_sha256) = 71 AND substr(service_response_sha256, 1, 7) = 'sha256:' AND substr(service_response_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    service_response_bytes BLOB NOT NULL CHECK(length(service_response_bytes) > 0),
    response_wrapper_sha256 TEXT NOT NULL CHECK(length(response_wrapper_sha256) = 71 AND substr(response_wrapper_sha256, 1, 7) = 'sha256:' AND substr(response_wrapper_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    response_wrapper_bytes BLOB NOT NULL CHECK(length(response_wrapper_bytes) > 0),
    contains_plaintext INTEGER NOT NULL CHECK(contains_plaintext = 0),
    created_at TEXT NOT NULL
) STRICT
""",
    """
CREATE INDEX leases_due_issued_v1 ON leases(expires_at, lease_id) WHERE state = 'ISSUED'
""",
    """
CREATE INDEX leases_due_consumed_v1 ON leases(completion_deadline, lease_id) WHERE state = 'CONSUMED'
""",
    """
CREATE INDEX access_decisions_by_anchor_v1 ON access_decisions(anchor_id, decided_at, lease_request_id)
""",
)


class FinalHoldoutAuthorityStoreError(RuntimeError):
    """The authority database is unusable, inconsistent or in an unknown state."""

    def __init__(
        self,
        message: str,
        *,
        collision: bool = False,
        commit_indeterminate: bool = False,
    ) -> None:
        super().__init__(message)
        self.collision = collision
        self.commit_indeterminate = commit_indeterminate


def _fail(message: str, **flags: bool) -> None:
    raise FinalHoldoutAuthorityStoreError(message, **flags)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _reject_symlink_components(path: Path, label: str) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            _fail(f"{label} must not traverse or be a symlink")


def _owner_only_directory(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise FinalHoldoutAuthorityStoreError(f"{label} is not inspectable") from exc
    _require(stat.S_ISDIR(info.st_mode), f"{label} must be a directory")
    _require(info.st_uid == os.geteuid(), f"{label} must be owned by the effective user")
    _require(
        stat.S_IMODE(info.st_mode) == 0o700,
        f"{label} must be an owner-only mode 0700 directory",
    )


def _owner_only_file(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise FinalHoldoutAuthorityStoreError(f"{label} is not inspectable") from exc
    _require(stat.S_ISREG(info.st_mode), f"{label} must be a regular file")
    _require(info.st_uid == os.geteuid(), f"{label} must be owned by the effective user")
    _require(
        stat.S_IMODE(info.st_mode) == 0o600,
        f"{label} must be an owner-only mode 0600 file",
    )


def _normalized_sql(value: object) -> str | None:
    if value is None:
        return None
    return " ".join(str(value).split())


def _schema_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    """Exact structural snapshot: objects, normalized SQL, columns and indexes.

    This is the accepted B2b ``_schema_snapshot()`` law over the complete final
    B3 table set: the whole ``sqlite_schema`` object list (every table, index,
    trigger and view plus normalized SQL) is captured, so an extra trigger, view
    or index — beyond the expected SQLite autoindexes and the three frozen
    explicit indexes — changes the fingerprint and is rejected.
    """
    objects = sorted(
        [str(row[0]), str(row[1]), _normalized_sql(row[2])]
        for row in connection.execute(
            "SELECT type, name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_stat%'"
        )
    )
    tables: dict[str, Any] = {}
    for table in _EXPECTED_TABLES:
        columns = [
            [row[1], row[2], row[3], row[4], row[5], row[6]]
            for row in connection.execute(f"PRAGMA table_xinfo({table})")
        ]
        indexes = []
        for index_row in connection.execute(f"PRAGMA index_list({table})"):
            index_name = str(index_row[1])
            key_columns = [
                row[2]
                for row in connection.execute(f"PRAGMA index_xinfo({index_name})")
                if row[5] == 1
            ]
            indexes.append(
                [index_name, index_row[2], str(index_row[3]), index_row[4],
                 key_columns]
            )
        tables[table] = {"columns": columns, "indexes": sorted(indexes)}
    return {"objects": objects, "tables": tables}


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    payload = json.dumps(
        _schema_snapshot(connection),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _verify_exact_schema_and_integrity(connection: sqlite3.Connection) -> None:
    # The B3 contract requires the complete PRAGMA integrity_check, not the
    # lighter quick_check the B2b store used.
    try:
        integrity_check = [tuple(row) for row in connection.execute(
            "PRAGMA integrity_check")]
        fingerprint = _schema_fingerprint(connection)
    except sqlite3.Error as exc:
        raise FinalHoldoutAuthorityStoreError(
            "authority database schema inspection failed"
        ) from exc
    _require(
        integrity_check == [("ok",)],
        "authority database integrity_check is not exactly ok",
    )
    _require(
        fingerprint == _EXPECTED_SCHEMA_FINGERPRINT,
        "authority database schema does not exactly match the frozen authority "
        "schema fingerprint; extra or altered tables, indexes, triggers or views "
        "are rejected without repair",
    )


def _read_header_identity(descriptor: int) -> None:
    """Verify the SQLite header identity from an open descriptor; pure read."""
    try:
        header = os.pread(descriptor, _HEADER_LENGTH, 0)
    except OSError as exc:
        raise FinalHoldoutAuthorityStoreError(
            "authority database header is not readable"
        ) from exc
    _require(
        len(header) == _HEADER_LENGTH and header[:len(_SQLITE_HEADER)]
        == _SQLITE_HEADER,
        "authority database file does not carry the SQLite header",
    )
    _require(
        int.from_bytes(header[_HEADER_APPLICATION_ID], "big")
        == AUTHORITY_DB_APPLICATION_ID,
        "existing database does not carry the authority application id",
    )
    _require(
        int.from_bytes(header[_HEADER_USER_VERSION], "big")
        == AUTHORITY_DB_USER_VERSION,
        "existing database does not carry the authority user version",
    )
    _require(
        header[_HEADER_WRITE_FORMAT] == _WAL_FORMAT
        and header[_HEADER_READ_FORMAT] == _WAL_FORMAT,
        "existing database is not in the write-ahead-log journal format",
    )


_WAL_HEADER_LENGTH = 32
_WAL_MAGIC = (0x377F0682, 0x377F0683)
_WAL_FORMAT_VERSION = 3007000
_WAL_FRAME_HEADER_LENGTH = 24


def _wal_running_checksum(
    big_endian: bool, seed: tuple[int, int], data: bytes
) -> tuple[int, int]:
    fmt = ">I" if big_endian else "<I"
    s0, s1 = seed
    for offset in range(0, len(data), 8):
        (x0,) = struct.unpack(fmt, data[offset:offset + 4])
        (x1,) = struct.unpack(fmt, data[offset + 4:offset + 8])
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF
    return s0, s1


def _validate_wal_bytes(raw: bytes) -> None:
    """Strictly validate a nonempty WAL: header, complete-frame alignment to EOF,
    and every frame's salt plus rolling checksum.

    The authority is fail-closed.  SQLite would silently drop a frame whose salt
    does not match the header salt (or a partial trailing frame) and accept the
    older state, which could silently discard a later committed registration.  So
    ANY frame-salt mismatch or partial trailing byte fails closed — every frame
    salt must equal the checked header salt and the file must be exactly the
    header plus a whole number of frames.

    Availability limitation (documented, deliberately NOT fail-open): a genuine
    rewound-and-reused WAL that legitimately carries a stale prior-cycle tail is
    rejected rather than accepted.  For this authority-only, one-capsule-per-run
    store under the directory lock the WAL is checkpointed between operations, so
    that state does not arise in normal operation; refusing it is preferred over
    ever silently losing a committed frame.
    """
    _require(
        len(raw) >= _WAL_HEADER_LENGTH,
        "copied WAL is shorter than its own header; failing closed",
    )
    (magic,) = struct.unpack(">I", raw[0:4])
    _require(magic in _WAL_MAGIC, "copied WAL header magic is invalid")
    big_endian = bool(magic & 1)
    (version,) = struct.unpack(">I", raw[4:8])
    _require(
        version == _WAL_FORMAT_VERSION,
        "copied WAL header format version is invalid",
    )
    (page_size,) = struct.unpack(">I", raw[8:12])
    _require(
        page_size >= 512 and (page_size & (page_size - 1)) == 0,
        "copied WAL header page size is invalid",
    )
    header_salt = raw[16:24]
    header_checksum = struct.unpack(">II", raw[24:32])
    _require(
        _wal_running_checksum(big_endian, (0, 0), raw[0:24]) == header_checksum,
        "copied WAL header checksum does not hold; failing closed",
    )
    frame_size = _WAL_FRAME_HEADER_LENGTH + page_size
    _require(
        (len(raw) - _WAL_HEADER_LENGTH) % frame_size == 0,
        "copied WAL is not aligned to whole frames (partial trailing frame); "
        "failing closed",
    )
    seed = header_checksum
    offset = _WAL_HEADER_LENGTH
    while offset < len(raw):
        _require(
            raw[offset + 8:offset + 16] == header_salt,
            "copied WAL frame salt does not match the header salt; failing closed",
        )
        page = raw[offset + _WAL_FRAME_HEADER_LENGTH:offset + frame_size]
        seed = _wal_running_checksum(big_endian, seed, raw[offset:offset + 8])
        seed = _wal_running_checksum(big_endian, seed, page)
        stored = struct.unpack(">II", raw[offset + 16:offset + 24])
        _require(
            seed == stored,
            "copied WAL frame checksum does not hold; failing closed",
        )
        offset += frame_size


def _verify_connection_inode(
    connection: sqlite3.Connection, expected_path: Path, pinned_stat: os.stat_result
) -> None:
    """Deterministic same-inode verification of one fresh SQLite connection.

    The B2b store proved the open through a process-wide descriptor census; that
    census is order- and state-dependent — a legitimate concurrent same-process
    reader, garbage collection between the two counts, or SQLite reusing a
    deferred descriptor makes the exact ``before + 1`` invariant fail on a valid
    store.  This replacement is deterministic: SQLite itself reports the main
    database file through ``PRAGMA database_list``, and that reported path must
    resolve — with symlinks fully expanded — to exactly the pinned device and
    inode, while the caller separately holds the pin descriptor open and
    re-verifies its identity fingerprint across the open.  A decoy, symlink or
    substituted inode either changes the reported path resolution, changes the
    pinned identity fingerprint, or fails the subsequent header/schema/metadata
    verification of the bytes actually visible through the connection.
    """
    try:
        rows = [tuple(row) for row in connection.execute("PRAGMA database_list")]
    except sqlite3.Error as exc:
        raise FinalHoldoutAuthorityStoreError(
            "the SQLite connection cannot report its database file; failing "
            "closed"
        ) from exc
    main_files = [str(row[2]) for row in rows if str(row[1]) == "main"]
    _require(
        len(main_files) == 1 and bool(main_files[0]),
        "the SQLite connection does not report exactly one main database file",
    )
    reported = Path(main_files[0])
    _require(
        os.path.realpath(reported) == os.path.realpath(expected_path),
        "SQLite did not open the pinned authority database path; aborting "
        "without mutation",
    )
    try:
        reported_stat = os.stat(reported)
    except OSError as exc:
        raise FinalHoldoutAuthorityStoreError(
            "the SQLite-reported database file is not inspectable; failing "
            "closed"
        ) from exc
    _require(
        os.path.samestat(reported_stat, pinned_stat),
        "SQLite did not open exactly the pinned authority inode; aborting "
        "without mutation",
    )


def _hash_open_descriptor(descriptor: int) -> tuple[str, int]:
    """Return (sha256-hex, byte length) of a descriptor read fully via pread."""
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, _SNAPSHOT_CHUNK, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest(), offset


def _write_private_bytes(target: Path, payload: bytes) -> None:
    """Write bytes to a fresh private 0600 file with a partial-write-safe loop."""
    out = os.open(
        str(target),
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        written = 0
        view = memoryview(payload)
        while written < len(view):
            count = os.write(out, view[written:])
            if count <= 0:
                raise FinalHoldoutAuthorityStoreError(
                    "authority snapshot write made no progress; failing closed"
                )
            written += count
    finally:
        os.close(out)


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return None if row is None else {key: row[key] for key in row.keys()}


def _cursor_rowcount(cursor: sqlite3.Cursor) -> int:
    """The affected row count of one write cursor; a test-visible seam."""
    return int(cursor.rowcount)


def _execute_exact(
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple,
    expected_rowcount: int,
    label: str,
) -> None:
    """Execute one write and require it to affect exactly the expected rows.

    Every B3a write is exact: an INSERT that reports zero or two affected rows,
    or a bounded prune whose DELETE count differs from the computed overflow,
    is an unknown durable state and fails closed inside the open transaction so
    the surrounding ROLLBACK leaves no partial or half-initialized store.
    """
    cursor = connection.execute(sql, parameters)
    if _cursor_rowcount(cursor) != expected_rowcount:
        _fail(
            f"authority {label} affected an unexpected number of rows; "
            "failing closed"
        )


class _B3aTransaction:
    """The only surface an authority callback sees while the write lock is held.

    The historical private class name is retained for compatibility.  B3a uses
    the registration-side operations; dormant B3b additionally uses the closed
    lease, decision, terminal-audit and conditional-transition primitives below.
    Policy, authentication, signing and decryption remain authority-owned.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def _fetch_one(
        self, sql: str, parameters: tuple, label: str
    ) -> dict[str, Any] | None:
        try:
            return _row_dict(self._connection.execute(sql, parameters).fetchone())
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(f"{label} failed") from exc

    def fetch_authenticated_request(self, request_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM authenticated_requests WHERE request_id = ?",
            (str(request_id),), "authority request lookup")

    def nonce_request_id(self, request_nonce: str) -> str | None:
        row = self._fetch_one(
            "SELECT request_id FROM authenticated_requests "
            "WHERE request_nonce = ?",
            (str(request_nonce),), "authority nonce lookup")
        return None if row is None else str(row["request_id"])

    def insert_authenticated_request(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "authenticated_requests", _AUTHENTICATED_REQUEST_COLUMNS, record,
            collision_sql="SELECT 1 FROM authenticated_requests "
            "WHERE request_id = ? OR request_nonce = ?",
            collision_params=(
                str(record.get("request_id", "")),
                str(record.get("request_nonce", "")),
            ),
        )

    def fetch_safe_response(self, request_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM safe_service_responses WHERE request_id = ?",
            (str(request_id),), "authority safe-response lookup")

    def insert_safe_response(self, record: Mapping[str, Any]) -> None:
        keys = set(record)
        _require(
            keys == set(_SAFE_RESPONSE_COLUMNS),
            "safe response record must carry exactly the sealed column set",
        )
        _require(
            record["contains_plaintext"] == 0
            and str(record["response_code"]) != "PLAINTEXT_RELEASED",
            "a successful consume response can never enter safe_service_responses",
        )
        self._insert(
            "safe_service_responses", _SAFE_RESPONSE_COLUMNS, record,
            collision_sql="SELECT 1 FROM safe_service_responses "
            "WHERE request_id = ?",
            collision_params=(str(record.get("request_id", "")),),
        )

    def fetch_capsule(self, capsule_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM encrypted_capsules WHERE capsule_id = ?",
            (str(capsule_id),), "authority capsule lookup")

    def fetch_capsule_by_request(self, request_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM encrypted_capsules WHERE registration_request_id = ?",
            (str(request_id),), "authority capsule request lookup")

    def run_capsule_id(
        self, release_id: str, tenant_id: str, workspace_id: str, run_id: str
    ) -> str | None:
        row = self._fetch_one(
            "SELECT capsule_id FROM encrypted_capsules WHERE release_id = ? "
            "AND tenant_id = ? AND workspace_id = ? AND run_id = ?",
            (str(release_id), str(tenant_id), str(workspace_id), str(run_id)),
            "authority run lookup")
        return None if row is None else str(row["capsule_id"])

    def aes_nonce_capsule_id(self, aes_nonce_hex: str) -> str | None:
        row = self._fetch_one(
            "SELECT capsule_id FROM encrypted_capsules WHERE aes_nonce_hex = ?",
            (str(aes_nonce_hex),), "authority AES nonce lookup")
        return None if row is None else str(row["capsule_id"])

    def insert_capsule(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "encrypted_capsules", _ENCRYPTED_CAPSULE_COLUMNS, record,
            collision_sql="SELECT 1 FROM encrypted_capsules "
            "WHERE capsule_id = ? OR aes_nonce_hex = ?",
            collision_params=(
                str(record.get("capsule_id", "")),
                str(record.get("aes_nonce_hex", "")),
            ),
        )

    def fetch_anchor(self, anchor_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM registered_anchors WHERE anchor_id = ?",
            (str(anchor_id),), "authority anchor lookup")

    def fetch_anchor_by_capsule(self, capsule_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM registered_anchors WHERE capsule_id = ?",
            (str(capsule_id),), "authority anchor capsule lookup")

    def fetch_anchor_by_request(self, request_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM registered_anchors WHERE registration_request_id = ?",
            (str(request_id),), "authority anchor request lookup")

    def anchor_nonce_anchor_id(self, anchor_nonce: str) -> str | None:
        row = self._fetch_one(
            "SELECT anchor_id FROM registered_anchors WHERE anchor_nonce = ?",
            (str(anchor_nonce),), "authority anchor nonce lookup")
        return None if row is None else str(row["anchor_id"])

    def insert_anchor(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "registered_anchors", _REGISTERED_ANCHOR_COLUMNS, record,
            collision_sql="SELECT 1 FROM registered_anchors "
            "WHERE anchor_id = ? OR anchor_nonce = ? OR capsule_id = ?",
            collision_params=(
                str(record.get("anchor_id", "")),
                str(record.get("anchor_nonce", "")),
                str(record.get("capsule_id", "")),
            ),
        )

    def record_untrusted_attempt(
        self, request_sha256: str, reason_code: str, observed_at: str
    ) -> None:
        """Insert one bounded rejection record, pruning oldest rows in-transaction."""
        try:
            count = self._connection.execute(
                "SELECT COUNT(*) FROM untrusted_attempts").fetchone()[0]
            overflow = int(count) + 1 - UNTRUSTED_ATTEMPT_MAX_ROWS
            if overflow > 0:
                _execute_exact(
                    self._connection,
                    "DELETE FROM untrusted_attempts WHERE attempt_id IN ("
                    "SELECT attempt_id FROM untrusted_attempts "
                    "ORDER BY attempt_id LIMIT ?)",
                    (overflow,),
                    overflow,
                    "untrusted-attempt prune",
                )
            _execute_exact(
                self._connection,
                "INSERT INTO untrusted_attempts "
                "(request_sha256, reason_code, observed_at) VALUES (?, ?, ?)",
                (str(request_sha256), str(reason_code), str(observed_at)),
                1,
                "untrusted-attempt insert",
            )
        except FinalHoldoutAuthorityStoreError:
            raise
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority untrusted-attempt record failed"
            ) from exc

    # --------------------------------------------------------- B3b lifecycle
    # One-use access primitives over the existing frozen tables.  The store
    # never signs, decrypts, authenticates or interprets policy; it only reads,
    # inserts and conditionally updates with the exact predecessor state in the
    # UPDATE predicate and an exact rowcount.

    def fetch_lease(self, lease_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM leases WHERE lease_id = ?",
            (str(lease_id),), "authority lease lookup")

    def fetch_lease_by_anchor(self, anchor_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM leases WHERE anchor_id = ?",
            (str(anchor_id),), "authority lease anchor lookup")

    def fetch_lease_by_request(self, request_id: str) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM leases WHERE lease_request_id = ?",
            (str(request_id),), "authority lease request lookup")

    def fetch_lease_by_consume_request(
        self, request_id: str
    ) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM leases WHERE consume_request_id = ?",
            (str(request_id),), "authority lease consume-request lookup")

    def fetch_lease_by_completion_request(
        self, request_id: str
    ) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM leases WHERE completion_request_id = ?",
            (str(request_id),), "authority lease completion-request lookup")

    def fetch_access_decision(
        self, lease_request_id: str
    ) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM access_decisions WHERE lease_request_id = ?",
            (str(lease_request_id),), "authority access decision lookup")

    def fetch_terminal_audit_by_lease(
        self, lease_id: str
    ) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM terminal_audits WHERE lease_id = ?",
            (str(lease_id),), "authority terminal audit lookup")

    def fetch_terminal_audit_by_lease_request(
        self, lease_request_id: str
    ) -> dict[str, Any] | None:
        return self._fetch_one(
            "SELECT * FROM terminal_audits WHERE lease_request_id = ?",
            (str(lease_request_id),), "authority terminal audit request lookup")

    def due_issued_leases(self, now: str) -> list[dict[str, Any]]:
        """All ISSUED leases whose expiry is at or before ``now`` (half-open)."""
        try:
            rows = self._connection.execute(
                "SELECT * FROM leases WHERE state = 'ISSUED' AND expires_at <= ? "
                "ORDER BY expires_at, lease_id", (str(now),)).fetchall()
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority due-issued lease scan failed") from exc
        return [dict(_row_dict(row) or {}) for row in rows]

    def due_consumed_leases(self, now: str) -> list[dict[str, Any]]:
        """All CONSUMED leases whose completion deadline is at or before now."""
        try:
            rows = self._connection.execute(
                "SELECT * FROM leases WHERE state = 'CONSUMED' AND "
                "completion_deadline <= ? ORDER BY completion_deadline, lease_id",
                (str(now),)).fetchall()
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority due-consumed lease scan failed") from exc
        return [dict(_row_dict(row) or {}) for row in rows]

    def insert_lease(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "leases", _LEASE_COLUMNS, record,
            collision_sql="SELECT 1 FROM leases WHERE lease_id = ? "
            "OR anchor_id = ? OR lease_request_id = ?",
            collision_params=(
                str(record.get("lease_id", "")),
                str(record.get("anchor_id", "")),
                str(record.get("lease_request_id", "")),
            ),
        )

    def insert_access_decision(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "access_decisions", _ACCESS_DECISION_COLUMNS, record,
            collision_sql="SELECT 1 FROM access_decisions "
            "WHERE lease_request_id = ? OR lease_id = ?",
            collision_params=(
                str(record.get("lease_request_id", "")),
                record.get("lease_id"),
            ),
        )

    def insert_terminal_audit(self, record: Mapping[str, Any]) -> None:
        self._insert(
            "terminal_audits", _TERMINAL_AUDIT_COLUMNS, record,
            collision_sql="SELECT 1 FROM terminal_audits "
            "WHERE lease_request_id = ? OR lease_id = ?",
            collision_params=(
                str(record.get("lease_request_id", "")),
                record.get("lease_id"),
            ),
        )

    def _transition_exact(
        self, sql: str, parameters: tuple, label: str
    ) -> None:
        """Execute one conditional lifecycle update with sanitized DB errors."""
        try:
            _execute_exact(
                self._connection, sql, parameters, 1, label)
        except FinalHoldoutAuthorityStoreError:
            raise
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                f"authority {label} failed") from exc

    def transition_anchor(
        self, anchor_id: str, from_state: str, to_state: str
    ) -> None:
        """Conditionally advance one anchor with the old state in the predicate."""
        transition = (str(from_state), str(to_state))
        _require(
            transition in _LEGAL_ANCHOR_TRANSITIONS,
            "anchor state transition is outside the closed B3 lifecycle",
        )
        self._transition_exact(
            "UPDATE registered_anchors SET state = ? "
            "WHERE anchor_id = ? AND state = ?",
            (transition[1], str(anchor_id), transition[0]),
            "anchor state transition",
        )

    def consume_lease(
        self, lease_id: str, consume_request_id: str, consumed_at: str,
        completion_deadline: str,
    ) -> None:
        self._transition_exact(
            "UPDATE leases SET state = 'CONSUMED', consume_request_id = ?, "
            "consumed_at = ?, completion_deadline = ? "
            "WHERE lease_id = ? AND state = 'ISSUED'",
            (str(consume_request_id), str(consumed_at),
             str(completion_deadline), str(lease_id)),
            "lease consume transition",
        )

    def complete_lease(
        self, lease_id: str, completion_request_id: str, terminal_at: str,
        state: str, terminal_reason_code: str,
    ) -> None:
        self._transition_exact(
            "UPDATE leases SET state = ?, completion_request_id = ?, "
            "terminal_at = ?, terminal_reason_code = ? "
            "WHERE lease_id = ? AND state = 'CONSUMED'",
            (str(state), str(completion_request_id), str(terminal_at),
             str(terminal_reason_code), str(lease_id)),
            "lease completion transition",
        )

    def expire_issued_lease(
        self, lease_id: str, terminal_at: str
    ) -> None:
        self._transition_exact(
            "UPDATE leases SET state = 'EXPIRED', terminal_at = ?, "
            "terminal_reason_code = 'LEASE_EXPIRED' "
            "WHERE lease_id = ? AND state = 'ISSUED'",
            (str(terminal_at), str(lease_id)),
            "lease expiry transition",
        )

    def timeout_consumed_lease(
        self, lease_id: str, terminal_at: str
    ) -> None:
        self._transition_exact(
            "UPDATE leases SET state = 'FAILED', terminal_at = ?, "
            "terminal_reason_code = 'COMPLETION_TIMEOUT' "
            "WHERE lease_id = ? AND state = 'CONSUMED'",
            (str(terminal_at), str(lease_id)),
            "lease timeout transition",
        )

    def _insert(
        self,
        table: str,
        columns: tuple[str, ...],
        record: Mapping[str, Any],
        *,
        collision_sql: str,
        collision_params: tuple,
    ) -> None:
        keys = set(record)
        _require(
            keys == set(columns),
            f"{table} record must carry exactly the sealed column set",
        )
        placeholders = ", ".join("?" for _ in columns)
        try:
            _execute_exact(
                self._connection,
                f"INSERT INTO {table} ({', '.join(columns)}) "
                f"VALUES ({placeholders})",
                tuple(record[column] for column in columns),
                1,
                f"{table} insert",
            )
        except sqlite3.IntegrityError as exc:
            # A uniqueness failure is a collision only when a persisted row
            # actually owns one of the proposed identifiers; every other
            # integrity failure is sanitized unavailability.
            if self._identifier_owned(collision_sql, collision_params):
                raise FinalHoldoutAuthorityStoreError(
                    f"authority {table} identifier collided with a persisted row",
                    collision=True,
                ) from exc
            raise FinalHoldoutAuthorityStoreError(
                f"authority {table} insert failed closed",
            ) from exc
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                f"authority {table} insert failed"
            ) from exc

    def _identifier_owned(self, sql: str, params: tuple) -> bool:
        try:
            return self._connection.execute(sql, params).fetchone() is not None
        except sqlite3.Error:
            return False  # unknown ownership is never reported as a collision


class FinalHoldoutAuthorityStoreV1:
    """Fail-closed, authority-only SQLite store with race-safe initialization."""

    def __init__(
        self,
        var_dir: Path,
        *,
        busy_timeout_ms: int = 30_000,
        metadata: Mapping[str, Any] | None = None,
        created_at: str | None = None,
    ) -> None:
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int) \
                or not 1 <= busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
            _fail(
                "busy timeout must be a non-bool integer between 1 and "
                f"{MAX_BUSY_TIMEOUT_MS} milliseconds inclusive"
            )
        if not isinstance(var_dir, Path) or not var_dir.is_absolute():
            _fail("authority variable directory must be an absolute path")
        _reject_symlink_components(var_dir, "authority variable directory")
        _require(var_dir.is_dir(), "authority variable directory must exist")
        _owner_only_directory(var_dir, "authority variable directory")
        self._busy_timeout_ms = int(busy_timeout_ms)
        self._db_path = var_dir / AUTHORITY_DB_FILENAME
        self._initial_metadata = self._validated_metadata(metadata, created_at)
        self._initialize_or_preflight()

    @staticmethod
    def _validated_metadata(
        metadata: Mapping[str, Any] | None, created_at: str | None
    ) -> dict[str, str] | None:
        if metadata is None and created_at is None:
            return None
        if not isinstance(metadata, Mapping) or \
                set(metadata) != set(_METADATA_IDENTITY_COLUMNS):
            _fail(
                "authority metadata record must carry exactly the sealed "
                "identity columns"
            )
        assert isinstance(metadata, Mapping)
        record: dict[str, str] = {}
        for column in _METADATA_IDENTITY_COLUMNS:
            value = metadata[column]
            if not isinstance(value, str) or not value:
                _fail("authority metadata values must be non-empty strings")
            record[column] = value
        if not isinstance(created_at, str) or not created_at:
            _fail("authority metadata creation time must be a non-empty string")
        record["created_at"] = created_at
        return record

    @property
    def db_path(self) -> Path:
        return self._db_path

    # ------------------------------------------------------------- initialization

    def _initialize_or_preflight(self) -> None:
        with _OPERATION_LOCK:
            try:
                dir_fd = os.open(
                    str(self._db_path.parent), os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority directory cannot be pinned"
                ) from exc
            try:
                fcntl.flock(dir_fd, fcntl.LOCK_EX)
                if not os.path.lexists(self._db_path) and self._claim_and_init():
                    return
                self._read_only_preflight()
                self._recheck_file_modes()
            finally:
                os.close(dir_fd)  # releases the directory LOCK_EX

    def _claim_and_init(self) -> bool:
        """Claim a fresh database and initialize it; True if this call claimed it."""
        try:
            claim_fd = os.open(
                self._db_path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            return False  # another invocation claimed it; the caller preflights
        except OSError as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority database path cannot be claimed"
            ) from exc
        try:
            self._initialize_via_claim(claim_fd)
        finally:
            os.close(claim_fd)
        self._recheck_file_modes()
        return True

    def _pinned_identity_or_fail(
        self, pinned: tuple[int, int], label: str
    ) -> None:
        try:
            info = os.lstat(self._db_path)
        except OSError as exc:
            raise FinalHoldoutAuthorityStoreError(
                f"authority database inode changed {label}; aborting without "
                "mutation"
            ) from exc
        _require(
            stat.S_ISREG(info.st_mode)
            and (info.st_dev, info.st_ino) == pinned,
            f"authority database inode changed {label}; aborting without "
            "mutation",
        )

    def _initialize_via_claim(self, claim_fd: int) -> None:
        if self._initial_metadata is None:
            _fail(
                "authority database initialization requires the metadata record"
            )
        assert self._initial_metadata is not None
        claim = os.fstat(claim_fd)
        _require(
            stat.S_ISREG(claim.st_mode) and claim.st_uid == os.geteuid()
            and claim.st_nlink == 1 and stat.S_IMODE(claim.st_mode) == 0o600,
            "claimed authority database descriptor failed verification",
        )
        pinned = (claim.st_dev, claim.st_ino)
        claim_identity = (claim.st_dev, claim.st_ino)
        try:
            connection = sqlite3.connect(
                self._db_path.as_uri() + "?mode=rw", uri=True,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority database initialization open failed"
            ) from exc
        committed = False
        try:
            # Immediately after connect and BEFORE any schema SQL: SQLite must
            # have opened exactly the claimed inode (deterministic same-inode
            # verification through the connection's own reported main file).
            _verify_connection_inode(connection, self._db_path, claim)
            current = os.fstat(claim_fd)
            _require(
                (current.st_dev, current.st_ino) == claim_identity,
                "claimed authority inode changed across the SQLite open; "
                "aborting without mutation",
            )
            self._pinned_identity_or_fail(pinned, "across the initialization open")
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                self._apply_connection_local_pragmas(connection)
                connection.execute("BEGIN EXCLUSIVE")
                connection.execute(
                    f"PRAGMA application_id={AUTHORITY_DB_APPLICATION_ID}")
                connection.execute(
                    f"PRAGMA user_version={AUTHORITY_DB_USER_VERSION}")
                for statement in _CREATE_STATEMENTS:
                    connection.execute(statement)
                columns = ", ".join(("singleton", *_METADATA_COLUMNS))
                placeholders = ", ".join(
                    "?" for _ in range(len(_METADATA_COLUMNS) + 1))
                _execute_exact(
                    connection,
                    f"INSERT INTO authority_metadata ({columns}) "
                    f"VALUES ({placeholders})",
                    (1, *(self._initial_metadata[column]
                          for column in _METADATA_COLUMNS)),
                    1,
                    "metadata initialization insert",
                )
                self._assert_effective_pragmas(connection)
            except FinalHoldoutAuthorityStoreError:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            except sqlite3.Error as exc:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise FinalHoldoutAuthorityStoreError(
                    "authority database initialization failed"
                ) from exc
            try:
                connection.execute("COMMIT")
                committed = True
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority initialization COMMIT failed with an "
                    "indeterminate durable outcome",
                    commit_indeterminate=True,
                ) from exc
        finally:
            connection.close()
        if committed:
            self._verify_initialized_via_claim(claim_fd, pinned, claim_identity)

    def _verify_initialized_via_claim(
        self, claim_fd: int, pinned: tuple[int, int],
        claim_identity: tuple[int, int],
    ) -> None:
        """Fresh post-close verification of the claimed inode before accepting."""
        after = os.fstat(claim_fd)
        _require(
            (after.st_dev, after.st_ino) == claim_identity
            and stat.S_ISREG(after.st_mode) and after.st_uid == os.geteuid()
            and after.st_nlink == 1 and stat.S_IMODE(after.st_mode) == 0o600,
            "claimed authority inode changed after initialization; failing closed",
        )
        _read_header_identity(claim_fd)
        self._pinned_identity_or_fail(pinned, "after initialization")
        self._recheck_file_modes()
        with self._verified_connection() as connection:
            try:
                metadata_rows = connection.execute(
                    "SELECT COUNT(*) FROM authority_metadata").fetchone()[0]
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority initialization verification read failed"
                ) from exc
            _require(
                metadata_rows == 1,
                "initialized database does not contain exactly one metadata row",
            )

    def _apply_connection_local_pragmas(
        self, connection: sqlite3.Connection
    ) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")

    def _apply_query_only(self, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA query_only=ON")

    def _assert_effective_pragmas(self, connection: sqlite3.Connection) -> None:
        for pragma, expected, label in (
            ("PRAGMA application_id", AUTHORITY_DB_APPLICATION_ID,
             "application_id"),
            ("PRAGMA user_version", AUTHORITY_DB_USER_VERSION, "user_version"),
            ("PRAGMA foreign_keys", 1, "foreign_keys=ON"),
            ("PRAGMA busy_timeout", self._busy_timeout_ms, "busy_timeout"),
            ("PRAGMA synchronous", 2, "synchronous=FULL"),
            ("PRAGMA trusted_schema", 0, "trusted_schema=OFF"),
        ):
            if connection.execute(pragma).fetchone()[0] != expected:
                _fail(f"authority connection failed the {label} check")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() \
                != "wal":
            _fail("authority connection failed the journal_mode=WAL check")

    def _read_only_preflight(self) -> None:
        """Inspect an existing path WAL-aware without mutating one source byte."""
        self._reject_rollback_journal()
        snapshot_dir = Path(tempfile.mkdtemp(prefix="ql-holdout-preflight-"))
        try:
            os.chmod(snapshot_dir, 0o700)
            recorded = self._snapshot_durable_sources(snapshot_dir)
            self._reverify_durable_sources(recorded)  # unchanged by the copy
            self._verify_snapshot(snapshot_dir / self._db_path.name)
            self._reverify_durable_sources(recorded)  # unchanged by inspection
        finally:
            shutil.rmtree(snapshot_dir, ignore_errors=True)

    def _pin_durable_source(
        self, path: Path, label: str, *, require_wal_header: bool
    ) -> tuple[tuple, str, bytes]:
        """Open one durable source O_NOFOLLOW; return (identity, hash, bytes)."""
        try:
            source_fd = os.open(
                str(path),
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            raise FinalHoldoutAuthorityStoreError(
                f"{label} cannot be opened for inspection"
            ) from exc
        try:
            info = os.fstat(source_fd)
            _require(
                stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600,
                f"{label} identity failed inspection",
            )
            if label.endswith("database"):
                _read_header_identity(source_fd)
            digest, _length = _hash_open_descriptor(source_fd)
            chunks: list[bytes] = []
            offset = 0
            while True:
                chunk = os.pread(source_fd, _SNAPSHOT_CHUNK, offset)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(source_fd)
        if require_wal_header and payload:
            _validate_wal_bytes(payload)
        return self._identity_fingerprint(info), digest, payload

    def _snapshot_durable_sources(self, snapshot_dir: Path) -> dict[str, Any]:
        listing = sorted(os.listdir(self._db_path.parent))
        base_id, base_hash, base_payload = self._pin_durable_source(
            self._db_path, "authority database", require_wal_header=False)
        _require(len(base_payload) != 0, "authority database file is zero bytes")
        _write_private_bytes(snapshot_dir / self._db_path.name, base_payload)

        sidecar_set = {
            suffix
            for suffix in ("-wal", "-shm")
            if os.path.lexists(self._db_path.with_name(self._db_path.name + suffix))
        }
        wal_record: tuple | None = None
        wal_path = self._db_path.with_name(self._db_path.name + "-wal")
        if "-wal" in sidecar_set:
            wal_id, wal_hash, wal_payload = self._pin_durable_source(
                wal_path, "authority database -wal", require_wal_header=True)
            wal_record = (wal_id, wal_hash)
            if wal_payload:  # a nonempty WAL is copied so SQLite applies it
                _write_private_bytes(
                    snapshot_dir / (self._db_path.name + "-wal"), wal_payload)
        return {
            "listing": listing,
            "base": (base_id, base_hash),
            "wal": wal_record,
            "sidecar_set": frozenset(sidecar_set),
        }

    def _reverify_durable_sources(self, recorded: dict[str, Any]) -> None:
        current_set = {
            suffix
            for suffix in ("-wal", "-shm")
            if os.path.lexists(self._db_path.with_name(self._db_path.name + suffix))
        }
        _require(
            frozenset(current_set) == recorded["sidecar_set"],
            "authority sidecar set changed during inspection; failing closed",
        )
        base_id, base_hash, _payload = self._pin_durable_source(
            self._db_path, "authority database", require_wal_header=False)
        _require(
            (base_id, base_hash) == recorded["base"],
            "authority database changed during inspection; failing closed",
        )
        if recorded["wal"] is not None:
            wal_path = self._db_path.with_name(self._db_path.name + "-wal")
            wal_id, wal_hash, _wal_payload = self._pin_durable_source(
                wal_path, "authority database -wal", require_wal_header=True)
            _require(
                (wal_id, wal_hash) == recorded["wal"],
                "authority -wal changed during inspection; failing closed",
            )
        _require(
            sorted(os.listdir(self._db_path.parent)) == recorded["listing"],
            "authority directory listing changed during inspection",
        )

    def _verify_snapshot(self, snapshot_base: Path) -> None:
        # The private copy is opened WAL-aware (a committed pending WAL is applied
        # against the copy, never the source; the -shm is rebuilt by SQLite).
        try:
            connection = sqlite3.connect(
                snapshot_base.as_uri() + "?mode=rw", uri=True,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority snapshot cannot be opened for inspection"
            ) from exc
        try:
            try:
                self._apply_connection_local_pragmas(connection)
                self._apply_query_only(connection)
                query_only = connection.execute(
                    "PRAGMA query_only").fetchone()[0]
                metadata_rows = connection.execute(
                    "SELECT COUNT(*) FROM authority_metadata").fetchone()[0]
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority snapshot inspection failed"
                ) from exc
            self._assert_effective_pragmas(connection)
            _require(
                query_only == 1,
                "authority snapshot failed the query_only=ON check",
            )
            _verify_exact_schema_and_integrity(connection)
            _require(
                metadata_rows == 1,
                "existing database must already contain exactly one authority "
                "metadata row; an unfinished database is never completed or "
                "repaired",
            )
        finally:
            connection.close()

    def _reject_rollback_journal(self) -> None:
        """A ``-journal`` rollback sidecar is never opened, applied or removed.

        The authority database is WAL-only; a rollback journal next to it means
        some foreign, non-WAL writer touched the store.  It is rejected BEFORE
        any SQLite open (which could otherwise roll the base file back), with
        every source byte untouched.
        """
        journal = self._db_path.with_name(self._db_path.name + "-journal")
        if os.path.lexists(journal):
            _fail(
                "a rollback-journal sidecar is present next to the authority "
                "database; failing closed without opening or repairing it"
            )

    def _recheck_file_modes(self) -> None:
        self._reject_rollback_journal()
        _owner_only_file(self._db_path, "authority database file")
        for suffix in ("-wal", "-shm"):
            sidecar = self._db_path.with_name(self._db_path.name + suffix)
            if os.path.lexists(sidecar):
                _owner_only_file(sidecar, f"authority database {suffix} file")

    def _revalidate_path_invariants(self) -> None:
        _reject_symlink_components(self._db_path, "authority database path")
        _owner_only_directory(self._db_path.parent, "authority database directory")

    @staticmethod
    def _identity_fingerprint(info: os.stat_result) -> tuple:
        return (
            info.st_dev, info.st_ino, info.st_nlink, info.st_uid, info.st_gid,
            info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    # ------------------------------------------------------------- connections

    @contextlib.contextmanager
    def _operate(self) -> Iterator[sqlite3.Connection]:
        """A checked read-write connection under the cooperative race boundary.

        The process-wide thread lock plus a LOCK_EX on a pinned
        authority-directory descriptor serialize cooperating threads and
        processes.  The O_NOFOLLOW pin descriptor is held open across the
        connect; the open is then tied to the pinned inode deterministically
        through the connection's own reported main database file plus the
        unchanged pin fingerprint — never through a descriptor census.
        """
        with _OPERATION_LOCK:
            self._recheck_file_modes()
            self._revalidate_path_invariants()
            try:
                dir_fd = os.open(
                    str(self._db_path.parent), os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority directory cannot be pinned"
                ) from exc
            try:
                fcntl.flock(dir_fd, fcntl.LOCK_EX)
                try:
                    with self._verified_connection() as connection:
                        yield connection
                finally:
                    self._recheck_file_modes()
            finally:
                os.close(dir_fd)  # releases the directory LOCK_EX

    @contextlib.contextmanager
    def _verified_connection(self) -> Iterator[sqlite3.Connection]:
        try:
            pin_fd = os.open(
                str(self._db_path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority database is not openable without creation"
            ) from exc
        try:
            yield from self._verified_connection_on(pin_fd)
        finally:
            os.close(pin_fd)

    def _verified_connection_on(
        self, pin_fd: int
    ) -> Iterator[sqlite3.Connection]:
        before = os.fstat(pin_fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600,
            "authority database file identity failed pre-connect inspection",
        )
        _read_header_identity(pin_fd)
        pinned = (before.st_dev, before.st_ino)
        before_fingerprint = self._identity_fingerprint(before)
        try:
            connection = sqlite3.connect(
                self._db_path.as_uri() + "?mode=rw", uri=True,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise FinalHoldoutAuthorityStoreError(
                "authority database connection failed"
            ) from exc
        try:
            try:
                # Deterministic same-inode verification: the connection's own
                # reported main file must resolve to the pinned inode, and the
                # pin descriptor's identity must be unchanged across the open.
                # This never depends on a descriptor census, so a concurrent
                # same-process reader cannot destabilize it.
                _verify_connection_inode(connection, self._db_path, before)
                after = os.fstat(pin_fd)
                _require(
                    self._identity_fingerprint(after) == before_fingerprint,
                    "authority database identity changed across the SQLite open; "
                    "aborting without mutation",
                )
                self._pinned_identity_or_fail(pinned, "across the SQLite open")
                self._revalidate_path_invariants()
                connection.row_factory = sqlite3.Row
                identity = (
                    (connection.execute("PRAGMA application_id").fetchone()[0]
                     == AUTHORITY_DB_APPLICATION_ID, "application_id"),
                    (connection.execute("PRAGMA user_version").fetchone()[0]
                     == AUTHORITY_DB_USER_VERSION, "user_version"),
                    (str(connection.execute("PRAGMA journal_mode").fetchone()[0])
                     .lower() == "wal", "journal_mode=WAL"),
                )
                for passed, label in identity:
                    if not passed:
                        _fail(
                            f"authority connection failed the {label} "
                            "check")
                _verify_exact_schema_and_integrity(connection)
                self._apply_connection_local_pragmas(connection)
                local = (
                    (connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1,
                     "foreign_keys=ON"),
                    (connection.execute("PRAGMA busy_timeout").fetchone()[0]
                     == self._busy_timeout_ms, "busy_timeout"),
                    (connection.execute("PRAGMA synchronous").fetchone()[0] == 2,
                     "synchronous=FULL"),
                    (connection.execute("PRAGMA trusted_schema").fetchone()[0]
                     == 0, "trusted_schema=OFF"),
                )
                for passed, label in local:
                    if not passed:
                        _fail(
                            f"authority connection failed the {label} "
                            "check")
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority connection PRAGMA verification failed"
                ) from exc
            yield connection
        finally:
            connection.close()

    # ------------------------------------------------------------- transactions

    def run_transaction(
        self, callback: Callable[[_B3aTransaction], Any]
    ) -> Any:
        with self._operate() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(
                    "authority transaction cannot acquire the write lock"
                ) from exc
            try:
                outcome = callback(_B3aTransaction(connection))
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            try:
                connection.execute("COMMIT")
            except sqlite3.Error as exc:
                # The durable outcome of a failed COMMIT is indeterminate.  Never
                # re-sign, retry or claim a rollback happened; a later exact retry
                # inspects the durable row to learn whether this commit won.
                raise FinalHoldoutAuthorityStoreError(
                    "authority COMMIT failed with an indeterminate durable "
                    "outcome",
                    commit_indeterminate=True,
                ) from exc
        return outcome

    # ------------------------------------------------------------- fresh reads

    def _read_one(
        self, sql: str, parameters: tuple, label: str
    ) -> dict[str, Any] | None:
        with self._operate() as connection:
            try:
                return _row_dict(connection.execute(sql, parameters).fetchone())
            except sqlite3.Error as exc:
                raise FinalHoldoutAuthorityStoreError(f"{label} failed") from exc

    def read_metadata(self) -> dict[str, Any] | None:
        return self._read_one(
            "SELECT * FROM authority_metadata", (), "authority metadata read")

    def read_authenticated_request(
        self, request_id: str
    ) -> dict[str, Any] | None:
        return self._read_one(
            "SELECT * FROM authenticated_requests WHERE request_id = ?",
            (str(request_id),), "authority request read")

    def read_safe_response(self, request_id: str) -> dict[str, Any] | None:
        return self._read_one(
            "SELECT * FROM safe_service_responses WHERE request_id = ?",
            (str(request_id),), "authority safe-response read")

    def read_capsule(self, capsule_id: str) -> dict[str, Any] | None:
        return self._read_one(
            "SELECT * FROM encrypted_capsules WHERE capsule_id = ?",
            (str(capsule_id),), "authority capsule read")

    def read_anchor(self, anchor_id: str) -> dict[str, Any] | None:
        return self._read_one(
            "SELECT * FROM registered_anchors WHERE anchor_id = ?",
            (str(anchor_id),), "authority anchor read")


__all__ = [
    "AUTHORITY_DB_APPLICATION_ID",
    "AUTHORITY_DB_FILENAME",
    "AUTHORITY_DB_SCHEMA_VERSION",
    "AUTHORITY_DB_USER_VERSION",
    "MAX_BUSY_TIMEOUT_MS",
    "UNTRUSTED_ATTEMPT_MAX_ROWS",
    "FinalHoldoutAuthorityStoreError",
    "FinalHoldoutAuthorityStoreV1",
]
