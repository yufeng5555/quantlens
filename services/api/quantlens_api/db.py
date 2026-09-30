"""Local run/queue/event/entitlement store — SQLite stand-in for planned Postgres.

Quota contract: ``used`` is the number of settled (charged) runs, ``reserved`` is the
number accepted but not yet settled/released, and admission capacity is
``remaining = quota - used - reserved``. Workers settle by ``run_id`` at ledger seal and
release by ``run_id`` on an uncharged terminal failure. Both operations are safe to retry.

``init_db`` additively backfills old run rows into the reservation ledger. Legacy rows
cannot receive confirmation receipts because older versions did not persist the exact
server restatement; newly accepted runs always do. Local-only; replaced, not extended,
when S4+ infra arrives.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

from .experiment_metadata import (
    EMPTY_DIFF_JSON,
    EMPTY_DIFF_SHA256,
    LINEAGE_DIFF_CONTRACT_VERSION,
    default_family_title,
)
from .corrected_read_expectations import (
    CorrectedReadExpectationsError,
    load_corrected_read_expectations,
)
from .release_activation import (
    CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR,
    CAPABILITY_KIND_FINAL_HOLDOUT,
    CAPABILITY_KIND_PLAN_ANCHOR,
    CLOCK_SKEW_ALLOWANCE_SECONDS,
    DEFAULT_PROBE_MAX_AGE_SECONDS,
    DERIVED_AUTHORITY_EVALUATORS,
    RELEASE_STATE_ABORTED,
    RELEASE_STATE_ACTIVE,
    RELEASE_STATE_PREPARED,
    RELEASE_STATE_SUPERSEDED,
    RELEASE_SEAL_FACTS,
    CapabilityProbeError,
    ComponentHashError,
    ReleaseStateError,
    UnknownReleaseError,
    build_activation_receipt,
    build_run_release_binding,
    canonical_json as _release_canonical_json,
    canonical_sha256 as _release_canonical_sha256,
    capability_probe_set_sha256,
    check_release_transition,
    evaluate_component_hashes,
    evaluate_control_plane_registrar,
    evaluate_expectation_document,
    evaluate_presentation_release_seal,
    evaluate_worker_heartbeat,
    prefixed_sha256 as _release_prefixed_sha256,
    probe_age_seconds,
    validate_release_registration,
)
from .runtime_contract import (
    STORAGE_SCHEMA_VERSION,
    WORKER_RUNTIME_CONTRACT,
    serving_worker_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_DB_CONNECT_ATTEMPTS = 5
DEFAULT_DB_RETRY_BASE_SECONDS = 0.1
DEFAULT_WORKER_HEARTBEAT_MAX_AGE_SECONDS = 10.0
LOCAL_WORKER_ID = "local-backtest-worker"

_TRANSIENT_SQLITE_MESSAGES = (
    "unable to open database file",
    "cannot open database",
    "database is locked",
    "database is busy",
    "disk i/o error",
    "temporarily unavailable",
)

# A full volume is its own failure class, and it was previously anonymous: SQLite
# reports it as a bare ``OperationalError``, no fragment above matches, and every
# caller therefore either surfaced an untyped 500 or died. It is deliberately NOT
# added to the transient list — a retry against a volume with no free bytes cannot
# succeed, and hiding it behind a backoff loop would turn a nameable operator
# condition into a silent stall. It is named instead, so /health, /status and every
# write path can all report the same thing: this volume is out of room.
_STORAGE_EXHAUSTED_MESSAGES = (
    "database or disk is full",
    "disk is full",
    "no space left on device",
)

# Enough headroom for one run's artifacts, its ledger and the WAL that carries
# them, plus one 12 MB upload and the normalized dataset it seals into, with
# margin. Below this every API route that writes refuses before it starts, rather
# than accepting work the volume cannot hold.
DEFAULT_MIN_FREE_STORAGE_BYTES = 64 * 1024 * 1024


def var_dir() -> Path:
    d = Path(os.environ.get("QL_VAR_DIR", REPO_ROOT / "var"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return var_dir() / "quantlens.db"


MOCK_ACTOR = "local-anonymous"          # pseudonymous local-preview tenant (Gate 5)
MOCK_QUOTA = 25                          # mock entitlement allowance, plainly labeled in UI
MOCK_SANDBOX_QUOTA = 100                 # separate non-billable local test-run allowance

# Who created a dataset import. A legacy row predates the column and is NULL,
# which is read as the reader's own upload -- the only value that existed then.
IMPORT_ORIGIN_USER_UPLOAD = "user_upload"
IMPORT_ORIGIN_BUNDLE_SEED = "bundle_seed"

RESEARCH_MODES = frozenset({"formal", "sandbox"})
RUN_ARCHIVE_FILTERS = frozenset({"false", "true", "all"})

LIFECYCLE = [
    "queued", "snapshot_pinned", "running_engine", "running_battery",
    "ledger_sealed", "report_rendered", "published",
]
FAILURES = ["validation_failed", "data_quality_failed", "system_failed"]

MARKET_DATA_ACQUISITION_STATES = (
    "queued", "resolving", "fetching", "validated", "sealed", "failed",
)
_MARKET_DATA_ACQUISITION_TRANSITIONS = {
    "queued": {"resolving", "failed"},
    "resolving": {"fetching", "failed"},
    "fetching": {"validated", "failed"},
    "validated": {"sealed", "failed"},
    "sealed": set(),
    "failed": set(),
}


class QuotaExceededError(RuntimeError):
    """Raised when an accepted run cannot atomically reserve entitlement."""

    def __init__(self, entitlement: dict, *, quota_kind: str = "formal"):
        super().__init__("entitlement quota exhausted")
        self.entitlement = entitlement
        self.quota_kind = quota_kind


class UnknownRunError(LookupError):
    """Raised when a run-scoped mutation is attempted for an unknown run id."""


class ReservationStateError(RuntimeError):
    """Raised when callers try to reverse a terminal reservation decision."""


class RunManagementStateError(RuntimeError):
    """Raised when a run cannot enter the requested management state."""

    def __init__(self, action: str, status: str, reason: str):
        super().__init__(reason)
        self.action = action
        self.status = status
        self.reason = reason


class MarketDataIdempotencyConflict(RuntimeError):
    """An idempotency key was already bound to a different canonical request."""


class MarketDataAcquisitionStateError(RuntimeError):
    """A licensed-data acquisition attempted an invalid persisted transition."""


class RunIdempotencyConflictError(RuntimeError):
    """A run-creation idempotency key is bound to a different canonical request."""


class LineageStateError(RuntimeError):
    """A lineage write violated the frozen `lineage-v1` contract in-transaction."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class AnnotationConflictError(RuntimeError):
    """An annotation write used a stale optimistic-concurrency revision."""

    def __init__(self, current_revision: int):
        super().__init__(f"annotation revision is {current_revision}")
        self.current_revision = current_revision


class FamilyConflictError(RuntimeError):
    """A family write used a stale optimistic-concurrency revision."""

    def __init__(self, current_revision: int):
        super().__init__(f"family revision is {current_revision}")
        self.current_revision = current_revision


class RunDeletedError(RuntimeError):
    """The target run is soft-deleted and must be restored before this write."""


class DatabaseUnavailableError(sqlite3.OperationalError):
    """A bounded set of SQLite connection attempts exhausted a transient failure."""


class StorageExhaustedError(sqlite3.OperationalError):
    """The volume backing the control plane has no room left to write.

    Subclasses ``OperationalError`` so existing SQLite failure handling still
    catches it, while giving the condition a name that survives into logs, the
    public health view and the run-admission refusal.
    """


def _ownership_ids(*, actor_id: str | None = None,
                   tenant_id: str | None = None,
                   user_id: str | None = None) -> tuple[str, str]:
    """Resolve the additive Gate 5 ownership tuple.

    ``actor_id`` is a legacy name for tenant ownership and remains accepted so the
    existing local API, manifests, and artifacts do not change shape during the
    identity-boundary migration. New principal-aware callers should pass
    ``tenant_id`` and ``user_id`` explicitly.
    """
    if tenant_id is not None and actor_id is not None and tenant_id != actor_id:
        raise ValueError("actor_id and tenant_id identify different tenants")
    tenant = tenant_id or actor_id or MOCK_ACTOR
    user = user_id or tenant
    if not tenant or not user:
        raise ValueError("tenant_id and user_id must be non-empty")
    return tenant, user


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_sha256(value: object) -> str:
    body = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def final_reveal_key(
    actor_id: str, snapshot_sha256: str, final_boundary: dict,
) -> tuple[str, str]:
    """Fail-closed research-lineage key until a first-class lineage id exists."""
    boundary_sha = _canonical_sha256(final_boundary)
    key = _canonical_sha256({
        "actor_id": actor_id,
        "snapshot_sha256": snapshot_sha256,
        "final_boundary_sha256": boundary_sha,
    })
    return key, boundary_sha


def is_transient_database_error(exc: BaseException) -> bool:
    """Return whether retrying this SQLite control-plane failure is reasonable.

    The list is deliberately narrow. Schema errors, malformed SQL, read-only stores,
    corruption, and runtime-contract violations remain fail-fast rather than being
    hidden behind a retry loop.
    """
    if isinstance(exc, DatabaseUnavailableError):
        return True
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).casefold()
    return any(fragment in message for fragment in _TRANSIENT_SQLITE_MESSAGES)


def is_storage_exhausted_error(exc: BaseException) -> bool:
    """Return whether this failure is the volume running out of room.

    Recognized from either side of the boundary: SQLite's own ``database or disk
    is full`` and the ``ENOSPC`` an artifact or snapshot write raises. Never true
    for a transient control-plane fault — the two classes are disjoint, and
    ``is_transient_database_error`` keeps returning False here so nothing retries.
    """
    if isinstance(exc, StorageExhaustedError):
        return True
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return True
    if not isinstance(exc, sqlite3.Error):
        return False
    message = str(exc).casefold()
    return any(fragment in message for fragment in _STORAGE_EXHAUSTED_MESSAGES)


def min_free_storage_bytes() -> int:
    try:
        return max(0, int(os.environ.get(
            "QL_MIN_FREE_STORAGE_BYTES", DEFAULT_MIN_FREE_STORAGE_BYTES)))
    except (TypeError, ValueError):
        return DEFAULT_MIN_FREE_STORAGE_BYTES


def storage_health(*, floor_bytes: int | None = None) -> dict:
    """Measure free room on the volume that holds the control plane.

    ``sufficient`` is a three-state answer on purpose. ``True`` and ``False`` are
    measurements; ``None`` means the platform did not let us measure, and an
    unmeasurable volume is not evidence of a full one, so admission must not
    refuse on that ground. The path itself is never published.
    """
    floor = min_free_storage_bytes() if floor_bytes is None else max(0, floor_bytes)
    try:
        usage = shutil.disk_usage(var_dir())
    except OSError:
        return {
            "measured": False,
            "free_bytes": None,
            "total_bytes": None,
            "floor_bytes": floor,
            "sufficient": None,
            "state": "unmeasurable",
        }
    free = int(usage.free)
    sufficient = free >= floor
    return {
        "measured": True,
        "free_bytes": free,
        "total_bytes": int(usage.total),
        "floor_bytes": floor,
        "sufficient": sufficient,
        "state": "sufficient" if sufficient else "exhausted",
    }


def _db_connect_attempts() -> int:
    try:
        return max(1, min(10, int(os.environ.get(
            "QL_DB_CONNECT_ATTEMPTS", DEFAULT_DB_CONNECT_ATTEMPTS))))
    except (TypeError, ValueError):
        return DEFAULT_DB_CONNECT_ATTEMPTS


def _db_retry_base_seconds() -> float:
    try:
        return max(0.0, min(2.0, float(os.environ.get(
            "QL_DB_RETRY_BASE_SECONDS", DEFAULT_DB_RETRY_BASE_SECONDS))))
    except (TypeError, ValueError):
        return DEFAULT_DB_RETRY_BASE_SECONDS


def connect() -> sqlite3.Connection:
    """Open and configure SQLite with bounded retry for transient availability faults.

    This covers the exact control-plane failure that previously killed the worker
    before it could claim a queued run. A successfully opened partial connection is
    always closed before retrying so failed PRAGMA setup cannot leak descriptors.
    """
    attempts = _db_connect_attempts()
    base_delay = _db_retry_base_seconds()
    for attempt in range(1, attempts + 1):
        conn: sqlite3.Connection | None = None
        try:
            # Re-resolve and recreate the state directory on every attempt. Temporary
            # directories can disappear between long-lived local-preview operations.
            path = db_path()
            conn = sqlite3.connect(path, timeout=30)
            conn.row_factory = sqlite3.Row
            # The queue claim trigger deliberately depends on this connection-local
            # function. A legacy worker uses a plain connection without it, so SQLite
            # rejects queued -> snapshot_pinned rather than mixing runtimes. The
            # value is the process's serving contract, which is byte-identical to
            # WORKER_RUNTIME_CONTRACT unless this process was explicitly launched
            # to serve an isolated corrected-release queue.
            conn.create_function(
                "ql_worker_contract", 0, lambda: serving_worker_contract(),
                deterministic=True,
            )
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except sqlite3.OperationalError as exc:
            if conn is not None:
                conn.close()
            if is_storage_exhausted_error(exc):
                # Name it here rather than letting a bare OperationalError travel
                # up as an anonymous 500 or an unexplained worker exit.
                raise StorageExhaustedError(
                    "the control-plane volume has no free space") from exc
            transient = is_transient_database_error(exc)
            if not transient:
                raise
            if attempt >= attempts:
                raise DatabaseUnavailableError(
                    "SQLite control plane remained unavailable after bounded retries"
                ) from exc
            time.sleep(base_delay * (2 ** (attempt - 1)))
    raise AssertionError("database connection retry loop ended unexpectedly")


def init_db() -> None:
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            research_mode TEXT NOT NULL DEFAULT 'formal'
                CHECK (research_mode IN ('formal', 'sandbox')),
            spec_json TEXT NOT NULL,
            spec_hash TEXT NOT NULL,
            spec_version INTEGER NOT NULL DEFAULT 1,
            battery_profile TEXT NOT NULL DEFAULT 'battery-v1',
            battery_profile_hash TEXT NOT NULL DEFAULT '',
            required_worker_contract TEXT NOT NULL DEFAULT 'quantlens-worker-v1',
            status TEXT NOT NULL,
            history_json TEXT NOT NULL,
            error_json TEXT,
            retries INTEGER NOT NULL DEFAULT 0,
            archived_at TEXT,
            deleted_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            type TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entitlement (
            actor_id TEXT PRIMARY KEY,
            quota INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS entitlement_reservations (
            run_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            chargeable INTEGER NOT NULL DEFAULT 1 CHECK (chargeable IN (0, 1)),
            state TEXT NOT NULL CHECK (state IN ('reserved', 'settled', 'released')),
            reserved_at TEXT NOT NULL,
            settled_at TEXT,
            released_at TEXT,
            FOREIGN KEY (run_id) REFERENCES runs(run_id),
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE INDEX IF NOT EXISTS entitlement_reservations_actor_state
            ON entitlement_reservations(actor_id, state);
        CREATE TABLE IF NOT EXISTS confirmation_receipts (
            receipt_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL UNIQUE,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            spec_hash TEXT NOT NULL,
            battery_profile TEXT NOT NULL DEFAULT 'battery-v1',
            battery_profile_hash TEXT NOT NULL DEFAULT '',
            restatement_text TEXT NOT NULL,
            restatement_hash TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id),
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE TABLE IF NOT EXISTS final_holdout_claims (
            run_id TEXT PRIMARY KEY,
            reveal_key TEXT,
            spec_hash TEXT NOT NULL,
            validation_plan_hash TEXT NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN ('final.ready', 'final.inflight', 'final.result', 'system_failed')
            ),
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE TABLE IF NOT EXISTS final_holdout_reveals (
            reveal_key TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            final_boundary_sha256 TEXT NOT NULL,
            spec_hash TEXT NOT NULL,
            validation_plan_hash TEXT NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN ('final.ready', 'final.inflight', 'final.result', 'system_failed')
            ),
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS validation_anchors (
            run_id TEXT PRIMARY KEY,
            temporal_integrity_sha256 TEXT NOT NULL,
            partitions_sha256 TEXT NOT NULL,
            validation_plan_sha256 TEXT NOT NULL,
            final_execution_binding_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE TABLE IF NOT EXISTS dataset_imports (
            import_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('inspected', 'sealed', 'rejected')),
            source_format TEXT NOT NULL,
            source_size INTEGER NOT NULL,
            source_sha256 TEXT NOT NULL,
            row_count INTEGER NOT NULL,
            columns_json TEXT NOT NULL,
            inspection_json TEXT NOT NULL,
            validation_json TEXT,
            error_json TEXT,
            dataset_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE TABLE IF NOT EXISTS datasets (
            dataset_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            symbol TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('sealed', 'withdrawn')),
            dataset_manifest_sha256 TEXT NOT NULL,
            snapshot_id TEXT NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            -- Which bundled ticker this row IS, or NULL for anything a reader imported.
            -- Written only by market_bundle.seed_symbol, so it is what separates the CC BY
            -- series QuantLens ships from a file the reader uploaded -- including a file
            -- they named SPY, and one whose bytes happen to equal the bundle's. Seeding
            -- used to key on the ticker alone, and so withheld the licensed series from
            -- anyone who already owned that ticker while reporting success.
            bundle_symbol TEXT,
            row_count INTEGER NOT NULL,
            coverage_start TEXT NOT NULL,
            coverage_end TEXT NOT NULL,
            quality_json TEXT NOT NULL,
            relative_storage_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE INDEX IF NOT EXISTS datasets_actor_status
            ON datasets(actor_id, status, created_at);
        CREATE TABLE IF NOT EXISTS market_data_acquisitions (
            acquisition_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            idempotency_key_sha256 TEXT NOT NULL,
            symbol TEXT NOT NULL,
            requested_start TEXT NOT NULL,
            requested_end TEXT NOT NULL,
            adjustment_mode TEXT NOT NULL,
            confirmed_instrument_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN (
                'queued', 'resolving', 'fetching', 'validated', 'sealed', 'failed'
            )),
            history_json TEXT NOT NULL,
            instrument_json TEXT,
            calendar_json TEXT,
            dataset_id TEXT,
            error_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS market_data_acquisitions_principal_request
            ON market_data_acquisitions(actor_id, user_id, request_sha256);
        CREATE UNIQUE INDEX IF NOT EXISTS market_data_acquisitions_principal_idempotency
            ON market_data_acquisitions(actor_id, user_id, idempotency_key_sha256);
        CREATE INDEX IF NOT EXISTS market_data_acquisitions_principal_created
            ON market_data_acquisitions(actor_id, user_id, created_at);
        CREATE TABLE IF NOT EXISTS market_data_idempotency_keys (
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            idempotency_key_sha256 TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            acquisition_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (actor_id, user_id, idempotency_key_sha256),
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id),
            FOREIGN KEY (acquisition_id) REFERENCES market_data_acquisitions(acquisition_id)
        );
        CREATE INDEX IF NOT EXISTS market_data_idempotency_acquisition
            ON market_data_idempotency_keys(acquisition_id);
        CREATE TABLE IF NOT EXISTS market_data_usage_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            acquisition_id TEXT,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN (
                'instrument_resolve', 'daily_fetch', 'acquisition_reuse',
                'calendar_gate'
            )),
            symbol TEXT NOT NULL,
            requested_start TEXT,
            requested_end TEXT,
            provider_request_count INTEGER NOT NULL CHECK (provider_request_count >= 0),
            cache_hit INTEGER NOT NULL CHECK (cache_hit IN (0, 1)),
            outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'reused')),
            error_code TEXT,
            FOREIGN KEY (actor_id) REFERENCES entitlement(actor_id)
        );
        CREATE INDEX IF NOT EXISTS market_data_usage_principal_ts
            ON market_data_usage_events(actor_id, user_id, ts, id);
        CREATE INDEX IF NOT EXISTS market_data_usage_acquisition
            ON market_data_usage_events(acquisition_id, id);
        CREATE TABLE IF NOT EXISTS experiment_families (
            family_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
            description TEXT NOT NULL DEFAULT ''
                CHECK (length(description) <= 2000),
            revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS experiment_families_principal_created
            ON experiment_families(actor_id, user_id, created_at);
        CREATE TABLE IF NOT EXISTS run_lineage (
            run_id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            parent_run_id TEXT,
            relationship TEXT NOT NULL
                CHECK (relationship IN ('baseline', 'variation', 'rerun')),
            parent_spec_hash TEXT,
            child_spec_hash TEXT NOT NULL,
            diff_contract_version TEXT NOT NULL DEFAULT 'lineage-diff-v1',
            changed_assumptions_json TEXT NOT NULL,
            changed_assumptions_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CHECK (
                (relationship = 'baseline'
                    AND parent_run_id IS NULL AND parent_spec_hash IS NULL)
                OR (relationship IN ('variation', 'rerun')
                    AND parent_run_id IS NOT NULL AND parent_spec_hash IS NOT NULL)
            ),
            CHECK (run_id != COALESCE(parent_run_id, '')),
            FOREIGN KEY (run_id) REFERENCES runs(run_id),
            FOREIGN KEY (family_id) REFERENCES experiment_families(family_id),
            FOREIGN KEY (parent_run_id) REFERENCES runs(run_id)
        );
        CREATE INDEX IF NOT EXISTS run_lineage_family_created
            ON run_lineage(family_id, created_at);
        CREATE INDEX IF NOT EXISTS run_lineage_parent
            ON run_lineage(parent_run_id);
        CREATE UNIQUE INDEX IF NOT EXISTS run_lineage_one_baseline_per_family
            ON run_lineage(family_id) WHERE relationship = 'baseline';
        CREATE TABLE IF NOT EXISTS run_annotations (
            run_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            note_text TEXT NOT NULL DEFAULT ''
                CHECK (length(note_text) <= 8000),
            revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE TABLE IF NOT EXISTS run_tags (
            run_id TEXT NOT NULL,
            display_tag TEXT NOT NULL CHECK (length(display_tag) BETWEEN 1 AND 32),
            normalized_tag TEXT NOT NULL CHECK (length(normalized_tag) >= 1),
            ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
            PRIMARY KEY (run_id, normalized_tag),
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS run_tags_run_ordinal
            ON run_tags(run_id, ordinal);
        CREATE TABLE IF NOT EXISTS run_creation_idempotency (
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            idempotency_key_sha256 TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            run_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (actor_id, user_id, idempotency_key_sha256),
            FOREIGN KEY (run_id) REFERENCES runs(run_id)
        );
        CREATE TABLE IF NOT EXISTS runtime_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
            worker_id TEXT PRIMARY KEY,
            runtime_contract TEXT NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN ('starting', 'ready', 'busy', 'recovering', 'stopped')
            ),
            started_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS worker_heartbeats_contract_seen
            ON worker_heartbeats(runtime_contract, last_seen_at);
        -- Doc 50 §3.2: one structural executable-readiness observation per
        -- isolated-contract worker, recorded beside its liveness beat. The
        -- baseline worker never writes a row, so legacy stores and laws are
        -- byte-identical.
        CREATE TABLE IF NOT EXISTS worker_execution_readiness (
            worker_id TEXT PRIMARY KEY,
            runtime_contract TEXT NOT NULL,
            observed_json TEXT NOT NULL,
            observed_sha256 TEXT NOT NULL,
            observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS worker_execution_readiness_contract_seen
            ON worker_execution_readiness(runtime_contract, observed_at);
        -- Email magic-link accounts. The address is stored once, here; every
        -- other table, artifact and manifest refers to the opaque account_id,
        -- so ownership carries no personal data. Passwords do not exist.
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            email_normalized TEXT NOT NULL UNIQUE,
            display_label TEXT NOT NULL,
            report_role TEXT NOT NULL CHECK (report_role IN ('novice', 'expert')),
            role_chosen INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_seen_at TEXT
        );
        -- Login links and sessions are bearer credentials, so only their
        -- SHA-256 digests are stored: a leaked database mints nothing.
        CREATE TABLE IF NOT EXISTS auth_login_tokens (
            token_sha256 TEXT PRIMARY KEY,
            email_normalized TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS auth_login_tokens_email
            ON auth_login_tokens(email_normalized, expires_at);
        -- In-flight external sign-in attempts. Only the digest is stored, for
        -- the same reason login tokens are: the raw value is a bearer value
        -- held by the browser, and a leaked store must not be able to complete
        -- somebody's sign-in.
        CREATE TABLE IF NOT EXISTS auth_oauth_states (
            state_sha256 TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            -- The PKCE verifier for this attempt. It never leaves the server:
            -- only its digest travels to the provider, and only this row can
            -- supply it at exchange time. That is what binds an authorization
            -- code to the one flow that requested it.
            code_verifier TEXT
        );
        CREATE INDEX IF NOT EXISTS auth_oauth_states_expiry
            ON auth_oauth_states(expires_at);
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_sha256 TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS auth_sessions_account
            ON auth_sessions(account_id, expires_at);
        CREATE TABLE IF NOT EXISTS release_activations (
            release_row_id TEXT PRIMARY KEY,
            release_id TEXT NOT NULL,
            release_state TEXT NOT NULL DEFAULT 'PREPARED'
                CHECK (release_state IN ('PREPARED', 'ACTIVE', 'SUPERSEDED', 'ABORTED')),
            required_worker_contract TEXT NOT NULL,
            presentation_contract_id TEXT NOT NULL,
            signer_key_id TEXT NOT NULL,
            release_tuple_json TEXT NOT NULL,
            release_tuple_sha256 TEXT NOT NULL,
            component_hashes_json TEXT NOT NULL,
            component_hashes_sha256 TEXT NOT NULL,
            required_capabilities_json TEXT NOT NULL,
            required_capabilities_sha256 TEXT NOT NULL,
            prepared_by TEXT NOT NULL,
            prepared_at TEXT NOT NULL,
            activated_by TEXT,
            activated_at TEXT,
            activation_receipt_sha256 TEXT,
            terminal_at TEXT,
            terminal_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS release_activations_single_active
            ON release_activations(release_state) WHERE release_state = 'ACTIVE';
        CREATE UNIQUE INDEX IF NOT EXISTS release_activations_single_prepared
            ON release_activations(release_id) WHERE release_state = 'PREPARED';
        CREATE INDEX IF NOT EXISTS release_activations_state_prepared
            ON release_activations(release_state, prepared_at);
        CREATE TABLE IF NOT EXISTS release_capability_probes (
            release_row_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
            authority_id TEXT,
            key_id TEXT,
            observed_json TEXT NOT NULL,
            observed_sha256 TEXT NOT NULL,
            not_ready_reason TEXT,
            observed_at TEXT NOT NULL,
            PRIMARY KEY (release_row_id, capability),
            FOREIGN KEY (release_row_id) REFERENCES release_activations(release_row_id)
        );
        CREATE TABLE IF NOT EXISTS release_activation_receipts (
            receipt_id TEXT PRIMARY KEY,
            release_row_id TEXT NOT NULL UNIQUE,
            release_id TEXT NOT NULL,
            release_tuple_sha256 TEXT NOT NULL,
            component_hashes_sha256 TEXT NOT NULL,
            capability_probe_sha256 TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            FOREIGN KEY (release_row_id) REFERENCES release_activations(release_row_id)
        );
        CREATE TABLE IF NOT EXISTS run_release_bindings (
            run_id TEXT PRIMARY KEY,
            release_row_id TEXT NOT NULL,
            release_id TEXT NOT NULL,
            required_worker_contract TEXT NOT NULL,
            release_tuple_json TEXT NOT NULL,
            release_tuple_sha256 TEXT NOT NULL,
            accepted_run_json TEXT NOT NULL,
            accepted_run_sha256 TEXT NOT NULL,
            capability_state_json TEXT NOT NULL,
            bound_at TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs(run_id),
            FOREIGN KEY (release_row_id) REFERENCES release_activations(release_row_id)
        );
        CREATE INDEX IF NOT EXISTS run_release_bindings_release
            ON run_release_bindings(release_row_id, bound_at);
        CREATE TABLE IF NOT EXISTS corrected_read_expectation_documents (
            component TEXT NOT NULL CHECK (component IN (
                'plan_anchors', 'financial_semantics', 'metric_semantics',
                'calendars', 'snapshots', 'validation_plans')),
            entry_key TEXT NOT NULL,
            document_json TEXT NOT NULL,
            registered_at TEXT NOT NULL,
            PRIMARY KEY (component, entry_key)
        );
        """)
        stored_schema = conn.execute(
            "SELECT value FROM runtime_metadata WHERE key = 'storage_schema_version'"
        ).fetchone()
        if stored_schema is None:
            conn.execute(
                "INSERT INTO runtime_metadata(key, value) VALUES "
                "('storage_schema_version', ?)",
                (STORAGE_SCHEMA_VERSION,),
            )
        elif stored_schema["value"] != STORAGE_SCHEMA_VERSION:
            raise RuntimeError("local database storage schema is not compatible")
        conn.execute(
            "INSERT OR IGNORE INTO entitlement(actor_id, quota, used) VALUES (?, ?, 0)",
            (MOCK_ACTOR, MOCK_QUOTA),
        )
        # Additive Gate 4/Gate 5 migration for local stores created by an earlier
        # preview. SQLite has no portable ADD COLUMN IF NOT EXISTS, so inspect before
        # altering. ``actor_id`` is the legacy tenant ownership alias retained for
        # manifest/artifact compatibility; historical single-user rows become owned by
        # the same value in ``user_id``.
        table_columns = {
            table: {
                row["name"]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for table in (
                "runs", "events", "confirmation_receipts",
                "dataset_imports", "datasets", "final_holdout_claims",
                "entitlement_reservations",
            )
        }
        if "reveal_key" not in table_columns["final_holdout_claims"]:
            conn.execute("ALTER TABLE final_holdout_claims ADD COLUMN reveal_key TEXT")
        dataset_import_columns = table_columns["dataset_imports"]
        if "validation_json" not in dataset_import_columns:
            conn.execute("ALTER TABLE dataset_imports ADD COLUMN validation_json TEXT")
        # Who created this import. The bundle seeder holds rows in the SAME
        # 'inspected' state a reader's upload sits in, for the ~140ms it takes to
        # validate and seal one series. Without this column the two are
        # indistinguishable, and a "waiting to be reviewed" list would offer the
        # reader a Discard button that silently destroys a licensed CC BY series
        # mid-seed.
        #
        # Rows written before this column exists stay NULL and are read as the
        # reader's own. That is deliberate, and it is the safe direction. The only
        # legacy row this mislabels is a seed orphaned by a crash mid-seal, which
        # the reader can then discard -- the correct outcome for it anyway. The
        # alternative, backfilling by matching the bundled files' SHA-256, is what
        # `market_bundle.bundle_digests` already warns against in its own
        # docstring: a reader may upload the identical CC BY CSV, and an unsealed
        # import carries no display name to disambiguate it with. That backfill
        # would hide a genuine upload from its owner and make it undiscardable --
        # reintroducing the lockout this whole change exists to remove.
        if "origin" not in dataset_import_columns:
            conn.execute("ALTER TABLE dataset_imports ADD COLUMN origin TEXT")
        if "bundle_symbol" not in table_columns["datasets"]:
            conn.execute("ALTER TABLE datasets ADD COLUMN bundle_symbol TEXT")
        if "required_worker_contract" not in table_columns["runs"]:
            conn.execute(
                "ALTER TABLE runs ADD COLUMN required_worker_contract TEXT NOT NULL "
                "DEFAULT 'quantlens-worker-v1'"
            )
        if "battery_profile" not in table_columns["runs"]:
            conn.execute(
                "ALTER TABLE runs ADD COLUMN battery_profile TEXT NOT NULL "
                "DEFAULT 'battery-v1'"
            )
        if "battery_profile_hash" not in table_columns["runs"]:
            conn.execute(
                "ALTER TABLE runs ADD COLUMN battery_profile_hash TEXT NOT NULL DEFAULT ''"
            )
        if "research_mode" not in table_columns["runs"]:
            conn.execute(
                "ALTER TABLE runs ADD COLUMN research_mode TEXT NOT NULL DEFAULT 'formal' "
                "CHECK (research_mode IN ('formal', 'sandbox'))"
            )
        if "archived_at" not in table_columns["runs"]:
            conn.execute("ALTER TABLE runs ADD COLUMN archived_at TEXT")
        if "deleted_at" not in table_columns["runs"]:
            conn.execute("ALTER TABLE runs ADD COLUMN deleted_at TEXT")
        chargeable_added = "chargeable" not in table_columns["entitlement_reservations"]
        if chargeable_added:
            conn.execute(
                "ALTER TABLE entitlement_reservations ADD COLUMN chargeable INTEGER "
                "NOT NULL DEFAULT 1 CHECK (chargeable IN (0, 1))"
            )
            conn.execute(
                "UPDATE entitlement_reservations SET chargeable = CASE "
                "WHEN (SELECT research_mode FROM runs "
                "      WHERE runs.run_id = entitlement_reservations.run_id) = 'formal' "
                "THEN 1 ELSE 0 END"
            )
        else:
            mismatch = conn.execute(
                "SELECT 1 FROM entitlement_reservations AS reservation "
                "JOIN runs ON runs.run_id = reservation.run_id "
                "WHERE reservation.chargeable != CASE "
                "WHEN runs.research_mode = 'formal' THEN 1 ELSE 0 END LIMIT 1"
            ).fetchone()
            if mismatch is not None:
                raise RuntimeError(
                    "reservation chargeability does not match immutable research mode")
        if "battery_profile" not in table_columns["confirmation_receipts"]:
            conn.execute(
                "ALTER TABLE confirmation_receipts ADD COLUMN battery_profile TEXT NOT NULL "
                "DEFAULT 'battery-v1'"
            )
        if "battery_profile_hash" not in table_columns["confirmation_receipts"]:
            conn.execute(
                "ALTER TABLE confirmation_receipts ADD COLUMN battery_profile_hash TEXT NOT NULL "
                "DEFAULT ''"
            )
        from quantlens_worker.config import battery_config_hash
        v1_profile_hash = battery_config_hash("battery-v1")
        conn.execute(
            "UPDATE runs SET battery_profile = 'battery-v1' "
            "WHERE battery_profile IS NULL OR battery_profile = ''"
        )
        conn.execute(
            "UPDATE runs SET battery_profile_hash = ? "
            "WHERE battery_profile_hash IS NULL OR battery_profile_hash = ''",
            (v1_profile_hash,),
        )
        conn.execute(
            "UPDATE confirmation_receipts SET battery_profile = 'battery-v1' "
            "WHERE battery_profile IS NULL OR battery_profile = ''"
        )
        conn.execute(
            "UPDATE confirmation_receipts SET battery_profile_hash = ? "
            "WHERE battery_profile_hash IS NULL OR battery_profile_hash = ''",
            (v1_profile_hash,),
        )
        conn.execute(
            "UPDATE runs SET required_worker_contract = ? "
            "WHERE required_worker_contract IS NULL OR required_worker_contract = ''",
            (WORKER_RUNTIME_CONTRACT,),
        )
        for table in ("runs", "confirmation_receipts", "dataset_imports", "datasets"):
            if "user_id" not in table_columns[table]:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN user_id TEXT")
            conn.execute(
                f"UPDATE {table} SET user_id = actor_id "
                "WHERE user_id IS NULL OR user_id = ''"
            )
        if "actor_id" not in table_columns["events"]:
            conn.execute("ALTER TABLE events ADD COLUMN actor_id TEXT")
        if "user_id" not in table_columns["events"]:
            conn.execute("ALTER TABLE events ADD COLUMN user_id TEXT")
        conn.execute(
            "UPDATE events SET actor_id = ? WHERE actor_id IS NULL OR actor_id = ''",
            (MOCK_ACTOR,),
        )
        conn.execute(
            "UPDATE events SET user_id = actor_id WHERE user_id IS NULL OR user_id = ''"
        )
        conn.executescript("""
            CREATE INDEX IF NOT EXISTS runs_principal_created
                ON runs(actor_id, user_id, created_at);
            CREATE INDEX IF NOT EXISTS runs_principal_management
                ON runs(actor_id, user_id, research_mode, deleted_at, archived_at, created_at);
            CREATE INDEX IF NOT EXISTS events_principal_type
                ON events(actor_id, user_id, type, id);
            CREATE INDEX IF NOT EXISTS confirmation_receipts_principal_run
                ON confirmation_receipts(actor_id, user_id, run_id);
            CREATE INDEX IF NOT EXISTS dataset_imports_principal_updated
                ON dataset_imports(actor_id, user_id, updated_at);
            CREATE INDEX IF NOT EXISTS datasets_principal_status
                ON datasets(actor_id, user_id, status, created_at);
            -- One sealed copy of a bundled series per principal, enforced by storage.
            -- Seeding checked "do I own this ticker" and then inserted, with nothing
            -- between the two steps: the signup background seed racing the /data button,
            -- or two open tabs, both saw the ticker missing and both sealed it, leaving
            -- rows a reader cannot tell apart (same generated name, same row count).
            -- Deliberately NOT keyed on symbol: owning your own SPY beside the licensed
            -- SPY is legitimate and must keep working. The status clause matters too --
            -- without it a withdrawn series would permanently block re-seeding it.
            CREATE UNIQUE INDEX IF NOT EXISTS datasets_bundle_symbol_per_principal
                ON datasets(actor_id, user_id, bundle_symbol)
                WHERE bundle_symbol IS NOT NULL AND status = 'sealed';
            CREATE INDEX IF NOT EXISTS runs_worker_contract_queue
                ON runs(required_worker_contract, status, created_at);
            DROP TRIGGER IF EXISTS runs_worker_contract_guard;
            CREATE TRIGGER runs_worker_contract_guard
            BEFORE UPDATE OF status ON runs
            WHEN OLD.status = 'queued'
              AND NEW.status = 'snapshot_pinned'
              AND COALESCE(NEW.required_worker_contract, '') != ql_worker_contract()
            BEGIN
                SELECT RAISE(ABORT, 'worker runtime contract mismatch');
            END;
            DROP TRIGGER IF EXISTS runs_research_mode_immutable_guard;
            CREATE TRIGGER runs_research_mode_immutable_guard
            BEFORE UPDATE OF research_mode ON runs
            WHEN NEW.research_mode != OLD.research_mode
            BEGIN
                SELECT RAISE(ABORT, 'research mode is immutable');
            END;
            DROP TRIGGER IF EXISTS runs_sandbox_profile_insert_guard;
            CREATE TRIGGER runs_sandbox_profile_insert_guard
            BEFORE INSERT ON runs
            WHEN NEW.research_mode = 'sandbox' AND NEW.battery_profile != 'battery-v1'
            BEGIN
                SELECT RAISE(ABORT, 'sandbox runs require battery-v1');
            END;
            DROP TRIGGER IF EXISTS runs_sandbox_profile_update_guard;
            CREATE TRIGGER runs_sandbox_profile_update_guard
            BEFORE UPDATE OF battery_profile, research_mode ON runs
            WHEN NEW.research_mode = 'sandbox' AND NEW.battery_profile != 'battery-v1'
            BEGIN
                SELECT RAISE(ABORT, 'sandbox runs require battery-v1');
            END;
            DROP TRIGGER IF EXISTS entitlement_reservation_chargeable_immutable_guard;
            CREATE TRIGGER entitlement_reservation_chargeable_immutable_guard
            BEFORE UPDATE OF chargeable ON entitlement_reservations
            WHEN NEW.chargeable != OLD.chargeable
            BEGIN
                SELECT RAISE(ABORT, 'reservation chargeability is immutable');
            END;
            DROP TRIGGER IF EXISTS entitlement_reservation_mode_guard;
            CREATE TRIGGER entitlement_reservation_mode_guard
            BEFORE INSERT ON entitlement_reservations
            WHEN NEW.chargeable != COALESCE((
                SELECT CASE WHEN research_mode = 'formal' THEN 1 ELSE 0 END
                FROM runs WHERE run_id = NEW.run_id
            ), -1)
            BEGIN
                SELECT RAISE(ABORT, 'reservation chargeability does not match research mode');
            END;
            DROP TRIGGER IF EXISTS runs_research_identity_immutable_guard;
            CREATE TRIGGER runs_research_identity_immutable_guard
            BEFORE UPDATE OF actor_id, user_id, spec_json, spec_hash,
                spec_version, battery_profile, battery_profile_hash,
                required_worker_contract ON runs
            WHEN NEW.actor_id != OLD.actor_id
              OR NEW.user_id != OLD.user_id
              OR NEW.spec_json != OLD.spec_json
              OR NEW.spec_hash != OLD.spec_hash
              OR NEW.spec_version != OLD.spec_version
              OR NEW.battery_profile != OLD.battery_profile
              OR NEW.battery_profile_hash != OLD.battery_profile_hash
              OR NEW.required_worker_contract != OLD.required_worker_contract
            BEGIN
                SELECT RAISE(ABORT, 'run research identity is immutable');
            END;
            DROP TRIGGER IF EXISTS experiment_families_principal_immutable_guard;
            CREATE TRIGGER experiment_families_principal_immutable_guard
            BEFORE UPDATE OF family_id, actor_id, user_id, created_at
                ON experiment_families
            WHEN NEW.family_id != OLD.family_id
              OR NEW.actor_id != OLD.actor_id
              OR NEW.user_id != OLD.user_id
              OR NEW.created_at != OLD.created_at
            BEGIN
                SELECT RAISE(ABORT, 'experiment family identity is immutable');
            END;
            DROP TRIGGER IF EXISTS run_lineage_principal_guard;
            CREATE TRIGGER run_lineage_principal_guard
            BEFORE INSERT ON run_lineage
            WHEN COALESCE((SELECT actor_id || '/' || user_id FROM runs
                           WHERE run_id = NEW.run_id), 'missing-run')
                 != COALESCE((SELECT actor_id || '/' || user_id
                              FROM experiment_families
                              WHERE family_id = NEW.family_id), 'missing-family')
              OR (NEW.parent_run_id IS NOT NULL AND (
                    COALESCE((SELECT actor_id || '/' || user_id FROM runs
                              WHERE run_id = NEW.parent_run_id), 'missing-parent')
                    != COALESCE((SELECT actor_id || '/' || user_id FROM runs
                                 WHERE run_id = NEW.run_id), 'missing-run')
                    OR COALESCE((SELECT research_mode FROM runs
                                 WHERE run_id = NEW.parent_run_id), 'missing-parent')
                    != COALESCE((SELECT research_mode FROM runs
                                 WHERE run_id = NEW.run_id), 'missing-run')))
            BEGIN
                SELECT RAISE(ABORT, 'lineage rows cannot cross principals or modes');
            END;
            DROP TRIGGER IF EXISTS run_lineage_graph_guard;
            CREATE TRIGGER run_lineage_graph_guard
            BEFORE INSERT ON run_lineage
            WHEN NEW.parent_run_id IS NOT NULL AND (
                COALESCE((SELECT family_id FROM run_lineage
                          WHERE run_id = NEW.parent_run_id), '') != NEW.family_id
                OR EXISTS (
                    WITH RECURSIVE ancestors(run_id) AS (
                        SELECT NEW.parent_run_id
                        UNION
                        SELECT edge.parent_run_id
                        FROM run_lineage AS edge
                        JOIN ancestors ON edge.run_id = ancestors.run_id
                        WHERE edge.parent_run_id IS NOT NULL
                    )
                    SELECT 1 FROM ancestors WHERE run_id = NEW.run_id
                )
            )
            BEGIN
                SELECT RAISE(ABORT,
                    'lineage parent must be in the same family and acyclic');
            END;
            DROP TRIGGER IF EXISTS run_lineage_insert_only_update_guard;
            CREATE TRIGGER run_lineage_insert_only_update_guard
            BEFORE UPDATE ON run_lineage
            BEGIN
                SELECT RAISE(ABORT, 'run lineage is insert-only');
            END;
            DROP TRIGGER IF EXISTS run_lineage_insert_only_delete_guard;
            CREATE TRIGGER run_lineage_insert_only_delete_guard
            BEFORE DELETE ON run_lineage
            BEGIN
                SELECT RAISE(ABORT, 'run lineage is insert-only');
            END;
            DROP TRIGGER IF EXISTS run_creation_idempotency_update_guard;
            CREATE TRIGGER run_creation_idempotency_update_guard
            BEFORE UPDATE ON run_creation_idempotency
            BEGIN
                SELECT RAISE(ABORT, 'run creation idempotency records are insert-only');
            END;
            DROP TRIGGER IF EXISTS run_creation_idempotency_delete_guard;
            CREATE TRIGGER run_creation_idempotency_delete_guard
            BEFORE DELETE ON run_creation_idempotency
            BEGIN
                SELECT RAISE(ABORT, 'run creation idempotency records are insert-only');
            END;
            DROP TRIGGER IF EXISTS run_annotations_principal_guard;
            CREATE TRIGGER run_annotations_principal_guard
            BEFORE INSERT ON run_annotations
            WHEN COALESCE((SELECT actor_id || '/' || user_id FROM runs
                           WHERE run_id = NEW.run_id), 'missing-run')
                 != NEW.actor_id || '/' || NEW.user_id
            BEGIN
                SELECT RAISE(ABORT, 'annotation rows cannot cross principals');
            END;
            DROP TRIGGER IF EXISTS run_annotations_identity_guard;
            CREATE TRIGGER run_annotations_identity_guard
            BEFORE UPDATE OF run_id, actor_id, user_id, created_at
                ON run_annotations
            WHEN NEW.run_id != OLD.run_id
              OR NEW.actor_id != OLD.actor_id
              OR NEW.user_id != OLD.user_id
              OR NEW.created_at != OLD.created_at
            BEGIN
                SELECT RAISE(ABORT, 'annotation ownership is immutable');
            END;
            DROP TRIGGER IF EXISTS release_activation_receipts_insert_only_update_guard;
            CREATE TRIGGER release_activation_receipts_insert_only_update_guard
            BEFORE UPDATE ON release_activation_receipts
            BEGIN
                SELECT RAISE(ABORT, 'activation receipts are insert-only');
            END;
            DROP TRIGGER IF EXISTS release_activation_receipts_insert_only_delete_guard;
            CREATE TRIGGER release_activation_receipts_insert_only_delete_guard
            BEFORE DELETE ON release_activation_receipts
            BEGIN
                SELECT RAISE(ABORT, 'activation receipts are insert-only');
            END;
            DROP TRIGGER IF EXISTS run_release_bindings_insert_only_update_guard;
            CREATE TRIGGER run_release_bindings_insert_only_update_guard
            BEFORE UPDATE ON run_release_bindings
            BEGIN
                SELECT RAISE(ABORT, 'run release bindings are insert-only');
            END;
            DROP TRIGGER IF EXISTS run_release_bindings_insert_only_delete_guard;
            CREATE TRIGGER run_release_bindings_insert_only_delete_guard
            BEFORE DELETE ON run_release_bindings
            BEGIN
                SELECT RAISE(ABORT, 'run release bindings are insert-only');
            END;
            DROP TRIGGER IF EXISTS release_activations_identity_immutable_guard;
            CREATE TRIGGER release_activations_identity_immutable_guard
            BEFORE UPDATE OF release_row_id, release_id, required_worker_contract,
                presentation_contract_id, signer_key_id, release_tuple_json,
                release_tuple_sha256, component_hashes_json, component_hashes_sha256,
                required_capabilities_json, required_capabilities_sha256,
                prepared_by, prepared_at, created_at ON release_activations
            BEGIN
                SELECT RAISE(ABORT, 'release preparation identity is immutable');
            END;
            DROP TRIGGER IF EXISTS release_activations_state_transition_guard;
            CREATE TRIGGER release_activations_state_transition_guard
            BEFORE UPDATE OF release_state ON release_activations
            WHEN OLD.release_state IN ('SUPERSEDED', 'ABORTED')
              OR (OLD.release_state = 'ACTIVE'
                  AND NEW.release_state != 'SUPERSEDED')
              OR (OLD.release_state = 'PREPARED'
                  AND NEW.release_state NOT IN ('ACTIVE', 'ABORTED'))
            BEGIN
                SELECT RAISE(ABORT, 'illegal release state transition');
            END;
            DROP TRIGGER IF EXISTS corrected_read_expectations_insert_only_update_guard;
            CREATE TRIGGER corrected_read_expectations_insert_only_update_guard
            BEFORE UPDATE ON corrected_read_expectation_documents
            BEGIN
                SELECT RAISE(ABORT, 'corrected read expectations are insert-only');
            END;
            DROP TRIGGER IF EXISTS corrected_read_expectations_insert_only_delete_guard;
            CREATE TRIGGER corrected_read_expectations_insert_only_delete_guard
            BEFORE DELETE ON corrected_read_expectation_documents
            BEGIN
                SELECT RAISE(ABORT, 'corrected read expectations are insert-only');
            END;
        """)
        # Claim the bundled rows that were sealed before the column existed, so the first
        # click after this ships does not re-seed a library that already holds the bundle.
        #
        # Runs AFTER the index above, and uses OR IGNORE, deliberately. A store that
        # already carries the duplicates this change exists to prevent would otherwise
        # raise IntegrityError here -- and init_db runs at API startup, where a raise is
        # not a failed migration but a machine that never boots again. OR IGNORE skips the
        # offending row instead of aborting the statement, so exactly one row per principal
        # takes the key and any duplicate stays NULL and merely unclaimed.
        #
        # Two recognisers, because one is not enough for the rows that actually exist.
        #
        # The basis marker is unforgeable: _apply_return_basis is the only writer of
        # quality["return_basis"], it is driven by price_adjustment, and TOTAL_RETURN is
        # passed only by market_bundle -- no request model carries that field.
        #
        # But it misses every row seeded before the basis itself was corrected, and the
        # deployed volume turned out to be made entirely of those: eight series carrying
        # the old price-return wording. For them the recogniser is the bundled bytes AND
        # the generated display name together. Bytes alone would be unsafe -- a reader may
        # upload the same file, and the import path stamps it price-return -- so claiming
        # a row needs both, which no upload produces by accident.
        try:
            from . import market_bundle
            from .dataset_imports import RETURN_BASIS_TEXT, TOTAL_RETURN

            conn.execute(
                "UPDATE OR IGNORE datasets SET bundle_symbol = symbol "
                "WHERE bundle_symbol IS NULL AND status = 'sealed' "
                "AND quality_json LIKE ?",
                (f'%{RETURN_BASIS_TEXT[TOTAL_RETURN]}%',),
            )
            for symbol, digest in market_bundle.bundled_source_digests().items():
                conn.execute(
                    "UPDATE OR IGNORE datasets SET bundle_symbol = ? "
                    "WHERE bundle_symbol IS NULL AND status = 'sealed' "
                    "AND symbol = ? AND source_sha256 = ? AND display_name = ?",
                    (symbol, symbol, digest,
                     market_bundle.bundled_display_name(symbol)),
                )
        except market_bundle.BundleUnavailable:
            logger.info("Optional market bundle is absent; backfill skipped")
        except Exception:  # noqa: BLE001 - a migration must never keep the API down
            logger.warning("bundled dataset backfill skipped", exc_info=True)

        # Additive migration for stores created before run-scoped reservations existed.
        # Active work consumes capacity; sealed work is charged; terminal pre-seal
        # failures are released. PK(run_id) keeps repeated startup migration idempotent.
        conn.execute("""
            INSERT OR IGNORE INTO entitlement_reservations(
                run_id, actor_id, chargeable, state, reserved_at, settled_at, released_at
            )
            SELECT
                run_id,
                actor_id,
                CASE WHEN research_mode = 'formal' THEN 1 ELSE 0 END,
                CASE
                    WHEN status IN ('ledger_sealed', 'report_rendered', 'published')
                         OR history_json LIKE '%"ledger_sealed"%'
                        THEN 'settled'
                    WHEN status IN (
                        'validation_failed', 'data_quality_failed',
                        'system_failed', 'timeout_failed'
                    ) THEN 'released'
                    ELSE 'reserved'
                END,
                created_at,
                CASE WHEN status IN ('ledger_sealed', 'report_rendered', 'published')
                           OR history_json LIKE '%"ledger_sealed"%'
                    THEN updated_at ELSE NULL END,
                CASE WHEN status IN (
                    'validation_failed', 'data_quality_failed',
                    'system_failed', 'timeout_failed'
                ) THEN updated_at ELSE NULL END
            FROM runs
            WHERE actor_id IN (SELECT actor_id FROM entitlement)
        """)
        # The per-run ledger is authoritative after migration and repairs historical
        # double-decrements from the former actor-only charging API.
        conn.execute("""
            UPDATE entitlement
            SET used = (
                SELECT COUNT(*)
                FROM entitlement_reservations
                WHERE entitlement_reservations.actor_id = entitlement.actor_id
                  AND entitlement_reservations.chargeable = 1
                  AND entitlement_reservations.state = 'settled'
            )
        """)


# ------------------------------------------------------------------ worker liveness

class SandboxAdmissionError(RuntimeError):
    """New sandbox admission is closed while a corrected release is ACTIVE.

    Raised inside the acceptance transaction (Stop F5, doc 48 §4 — the
    recorded A6 option-2 decision): a v3-serving worker must never execute
    battery-v1 sandbox work, so no new sandbox run may be accepted while
    the release pointer is ACTIVE. Existing sandbox runs and their history
    stay readable and unaffected.
    """


class WorkerAdmissionError(RuntimeError):
    """No fresh worker heartbeat exists for the exact contract to be stamped.

    Raised inside the acceptance transaction (doc 47 §5.6): admission is
    authorized only by a live heartbeat for the contract the run will
    actually carry, checked on the same connection after the release pointer
    is read — a healthy baseline worker can never admit work that is about
    to be stamped for the isolated corrected queue, and the pointer cannot
    change between the check and the insert.
    """

    def __init__(self, required_contract: str, reason: str):
        super().__init__(
            f"no admissible worker for contract {required_contract!r}: "
            f"{reason}")
        self.required_contract = required_contract
        self.reason = reason


def _worker_heartbeat_required() -> bool:
    value = os.environ.get("QL_REQUIRE_WORKER_HEARTBEAT", "").strip().lower()
    if not value:
        return True
    return value not in {"0", "false", "no", "off"}


def _heartbeat_worker_id(runtime_contract: str) -> str:
    """One liveness row per serving contract on a shared store.

    The baseline contract keeps the historical id byte-for-byte, so nothing
    changes for existing stores or tests. An isolated corrected-release
    worker gets its own row, because a baseline worker and a release worker
    heartbeating concurrently must never clobber each other's liveness —
    admission and capability probes filter by exact contract.
    """
    if runtime_contract == WORKER_RUNTIME_CONTRACT:
        return LOCAL_WORKER_ID
    return f"{LOCAL_WORKER_ID}:{runtime_contract}"


def record_worker_heartbeat(
    *,
    state: str = "ready",
    worker_id: str | None = None,
    execution_readiness: dict | None = None,
) -> None:
    """Upsert one compatible worker heartbeat without exposing process details.

    The single-worker local queue only needs one liveness row per serving
    contract. Production queueing will replace this table with durable
    leases; keeping the contract small prevents the local stand-in from
    pretending to be a distributed scheduler.

    ``execution_readiness`` (doc 50 §3.2) is the isolated-contract worker's
    own structural executable-readiness observation, recorded write-through
    in the same transaction as the liveness beat. The baseline worker passes
    None and its behavior is byte-identical to before.
    """
    if state not in {"starting", "ready", "busy", "recovering", "stopped"}:
        raise ValueError("unsupported worker heartbeat state")
    contract = serving_worker_contract()
    resolved_worker_id = (
        worker_id if worker_id is not None else _heartbeat_worker_id(contract)
    )
    now = _now()
    with connect() as conn:
        conn.execute(
            "INSERT INTO worker_heartbeats("
            "worker_id, runtime_contract, state, started_at, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(worker_id) DO UPDATE SET "
            "runtime_contract = excluded.runtime_contract, "
            "state = excluded.state, "
            "started_at = CASE "
            "  WHEN worker_heartbeats.state = 'stopped' "
            "    OR worker_heartbeats.runtime_contract != excluded.runtime_contract "
            "  THEN excluded.started_at ELSE worker_heartbeats.started_at END, "
            "last_seen_at = excluded.last_seen_at",
            (resolved_worker_id, contract, state, now, now),
        )
        if execution_readiness is not None:
            _record_worker_execution_readiness_in(
                conn, worker_id=resolved_worker_id,
                runtime_contract=contract,
                document=execution_readiness, now=now)


def _record_worker_execution_readiness_in(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    runtime_contract: str,
    document: dict,
    now: str,
) -> None:
    if not isinstance(document, dict) or not document:
        raise ValueError(
            "an execution-readiness observation must be a non-empty document")
    observed_json = _release_canonical_json(document)
    conn.execute(
        "INSERT INTO worker_execution_readiness("
        "worker_id, runtime_contract, observed_json, observed_sha256, "
        "observed_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(worker_id) DO UPDATE SET "
        "runtime_contract = excluded.runtime_contract, "
        "observed_json = excluded.observed_json, "
        "observed_sha256 = excluded.observed_sha256, "
        "observed_at = excluded.observed_at",
        (worker_id, runtime_contract, observed_json,
         _release_prefixed_sha256(observed_json.encode("ascii")), now),
    )


# ------------------------------------------------------ magic-link accounts


class AuthRateLimitError(RuntimeError):
    """This address already holds its allowance of live sign-in links.

    Answering this honestly would disclose whether a given address is in use,
    so the caller receives the ordinary accepted body.
    """


class AuthInstanceBusyError(RuntimeError):
    """The whole instance reached its sign-in bound for the current window.

    Unlike the per-address bound this is global state: it says nothing about
    whether any particular address has an account, so it discloses nothing and
    can be reported honestly. Reporting it honestly matters — the alternative
    is telling someone a link is on its way when none was sent.
    """


class AuthCapacityError(RuntimeError):
    """This deployment is not accepting further accounts."""


def issue_login_token(email_normalized: str, token_sha256: str, *,
                      created_at: str, expires_at: str,
                      max_live: int,
                      max_per_window: int | None = None,
                      window_start: str | None = None) -> None:
    """Record one unconsumed login-token digest, or refuse to flood an inbox.

    Two bounds, both evaluated inside the same immediate transaction as the
    insert so concurrent requests cannot both pass them: how many live links one
    address may hold, and — for a deployment that mails to whatever address a
    stranger types — how many this instance may mint per window at all.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        live = conn.execute(
            "SELECT COUNT(*) AS c FROM auth_login_tokens "
            "WHERE email_normalized = ? AND consumed_at IS NULL "
            "AND expires_at > ?",
            (email_normalized, created_at),
        ).fetchone()["c"]
        if live >= max_live:
            raise AuthRateLimitError(
                "too many unconsumed sign-in links for this address")
        if max_per_window is not None and window_start is not None:
            # Every mint is already recorded here, consumed or not, so the
            # tokens table is itself the instance-wide send record.
            minted = conn.execute(
                "SELECT COUNT(*) AS c FROM auth_login_tokens WHERE created_at > ?",
                (window_start,),
            ).fetchone()["c"]
            if minted >= max_per_window:
                raise AuthInstanceBusyError(
                    "this deployment reached its sign-in link bound for the window")
        conn.execute(
            "INSERT INTO auth_login_tokens("
            "token_sha256, email_normalized, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_sha256, email_normalized, created_at, expires_at),
        )


def _establish_account_session_in(
    conn: sqlite3.Connection,
    *,
    email: str,
    now: str,
    account_id: str,
    display_label_for,
    default_role: str,
    session_sha256: str,
    session_expires_at: str,
    max_accounts: int | None,
) -> dict:
    """Resolve one address to an account and open a session for it.

    Shared by every way of proving an address: an emailed link and an external
    identity provider differ entirely in how they establish that the person
    controls the address, and not at all in what happens once they have. One
    implementation means an account reached two ways is the same account, with
    the same isolation, the same allowance and the same stored preference.

    Must be called inside an open transaction; the caller owns the boundary.
    """
    account = conn.execute(
        "SELECT account_id, display_label, report_role, role_chosen "
        "FROM accounts WHERE email_normalized = ?",
        (email,),
    ).fetchone()
    if account is None:
        if max_accounts is not None:
            existing = conn.execute(
                "SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
            if existing >= max_accounts:
                # Raising rolls the caller's transaction back, so nothing this
                # sign-in consumed is spent on an account that was not created.
                raise AuthCapacityError(
                    "this deployment is not accepting further accounts")
        # The label policy lives with the identity module; storage only
        # applies it to the address the caller proved.
        label = display_label_for(email)
        conn.execute(
            "INSERT INTO accounts("
            "account_id, email_normalized, display_label, report_role, "
            "role_chosen, created_at, last_seen_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            (account_id, email, label, default_role, now, now),
        )
        # A new account with no allowance could sign in but do nothing, so the
        # starter allowance is granted in the same transaction that creates it.
        # This is the same plainly-labeled local allowance the preview
        # workspace uses; a real billing control plane replaces it when one
        # exists.
        conn.execute(
            "INSERT INTO entitlement(actor_id, quota, used) VALUES (?, ?, 0) "
            "ON CONFLICT(actor_id) DO NOTHING",
            (account_id, MOCK_QUOTA),
        )
        resolved = {
            "account_id": account_id,
            "display_label": label,
            "report_role": default_role,
            "role_chosen": 0,
            "created": True,
        }
    else:
        conn.execute(
            "UPDATE accounts SET last_seen_at = ? WHERE account_id = ?",
            (now, account["account_id"]),
        )
        resolved = {
            "account_id": account["account_id"],
            "display_label": account["display_label"],
            "report_role": account["report_role"],
            "role_chosen": int(account["role_chosen"]),
            "created": False,
        }
    conn.execute(
        "INSERT INTO auth_sessions("
        "session_sha256, account_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (session_sha256, resolved["account_id"], now, session_expires_at),
    )
    resolved["email"] = email
    resolved["expires_at"] = session_expires_at
    return resolved


def open_account_session(email_normalized: str, *, now: str, account_id: str,
                         display_label_for, default_role: str,
                         session_sha256: str, session_expires_at: str,
                         max_accounts: int | None = None) -> dict:
    """Open a session for an address an external provider has just proved.

    There is no token to consume: the provider's own exchange is what
    established control of the address, and it is single-use on their side.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        return _establish_account_session_in(
            conn,
            email=email_normalized,
            now=now,
            account_id=account_id,
            display_label_for=display_label_for,
            default_role=default_role,
            session_sha256=session_sha256,
            session_expires_at=session_expires_at,
            max_accounts=max_accounts,
        )


def redeem_login_token(token_sha256: str, *, now: str, account_id: str,
                       display_label_for, default_role: str,
                       session_sha256: str, session_expires_at: str,
                       max_accounts: int | None = None) -> dict | None:
    """Consume one login token and open a session, atomically.

    Returns None when the token is unknown, already consumed or expired — the
    three cases a caller must treat identically. The whole redemption is one
    transaction: the guarded UPDATE is what makes a link single-use even when
    two requests race, and the account row is created on first sign-in.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT email_normalized, expires_at, consumed_at "
            "FROM auth_login_tokens WHERE token_sha256 = ?",
            (token_sha256,),
        ).fetchone()
        if row is None or row["consumed_at"] is not None \
                or row["expires_at"] <= now:
            return None
        consumed = conn.execute(
            "UPDATE auth_login_tokens SET consumed_at = ? "
            "WHERE token_sha256 = ? AND consumed_at IS NULL",
            (now, token_sha256),
        )
        if consumed.rowcount != 1:
            # Another request redeemed it between the read and the update.
            return None
        # Raising out of the shared helper (an account cap) rolls this whole
        # transaction back, including the guarded consume above, so a link that
        # could not create an account is not silently burned: the reader can
        # follow the same link again once capacity exists.
        return _establish_account_session_in(
            conn,
            email=row["email_normalized"],
            now=now,
            account_id=account_id,
            display_label_for=display_label_for,
            default_role=default_role,
            session_sha256=session_sha256,
            session_expires_at=session_expires_at,
            max_accounts=max_accounts,
        )


def start_oauth_state(state_sha256: str, *, created_at: str, expires_at: str,
                      code_verifier: str, max_live: int,
                      window_start: str) -> None:
    """Record one in-flight external sign-in, or refuse to accumulate them.

    Starting a sign-in costs nothing to the person who starts it, so without a
    bound anyone could fill this table indefinitely. The bound is on live,
    unconsumed attempts in the current window, evaluated inside the same
    immediate transaction as the insert.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        live = conn.execute(
            "SELECT COUNT(*) AS c FROM auth_oauth_states "
            "WHERE consumed_at IS NULL AND expires_at > ? AND created_at > ?",
            (created_at, window_start),
        ).fetchone()["c"]
        if live >= max_live:
            raise AuthInstanceBusyError(
                "too many sign-in attempts are already in flight")
        conn.execute(
            "INSERT INTO auth_oauth_states("
            "state_sha256, created_at, expires_at, code_verifier) "
            "VALUES (?, ?, ?, ?)",
            (state_sha256, created_at, expires_at, code_verifier),
        )


def consume_oauth_state(state_sha256: str, *, now: str) -> str | None:
    """Spend one in-flight sign-in exactly once and return its PKCE verifier.

    Returns None when the state is unknown, already spent or expired — the
    three cases a caller must treat identically, because distinguishing them
    tells an attacker which guesses were close. The guarded UPDATE is what
    makes it single-use when two callbacks race.

    The verifier comes back with it because the two must not be separable: an
    authorization code may only be exchanged using the verifier belonging to
    the very flow that requested that code.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT expires_at, consumed_at, code_verifier "
            "FROM auth_oauth_states WHERE state_sha256 = ?",
            (state_sha256,),
        ).fetchone()
        if row is None or row["consumed_at"] is not None or row["expires_at"] <= now:
            return None
        spent = conn.execute(
            "UPDATE auth_oauth_states SET consumed_at = ? "
            "WHERE state_sha256 = ? AND consumed_at IS NULL",
            (now, state_sha256),
        )
        if spent.rowcount != 1:
            return None
        return row["code_verifier"]


def release_oauth_state(state_sha256: str) -> None:
    """Settle an attempt that ended without a session.

    A refusal must not leave a row occupying the in-flight allowance until it
    expires; otherwise a handful of abandoned or forged callbacks would close
    the only front door for everyone else until the window rolls over.
    """
    with connect() as conn:
        conn.execute(
            "DELETE FROM auth_oauth_states WHERE state_sha256 = ?", (state_sha256,))


def purge_expired_oauth_states(cutoff: str) -> int:
    """Drop settled sign-in attempts. Purely housekeeping; never load-bearing."""
    with connect() as conn:
        cursor = conn.execute(
            "DELETE FROM auth_oauth_states WHERE expires_at <= ?", (cutoff,))
        return cursor.rowcount


def count_open_dataset_imports(actor_id: str) -> int:
    """Uploads this account holds in quarantine — inspected, not yet sealed.

    Sealed and rejected imports are settled and do not count: the bound is on
    how much unfinished work one account may keep on the shared volume, not on
    how much research it may do.

    Rows the bundle seeder is holding mid-seal are excluded. The cap bounds work
    the caller submitted and can settle; a server-driven seed is neither, it is
    already bounded by the size of the bundle, and counting it would spend a
    reader's slot on something they can neither see nor discard.
    """
    with connect() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM dataset_imports "
            "WHERE actor_id = ? AND status = 'inspected' "
            "AND (origin IS NULL OR origin != ?)",
            (actor_id, IMPORT_ORIGIN_BUNDLE_SEED),
        ).fetchone()["c"]


def discard_login_token(token_sha256: str) -> None:
    """Drop an unconsumed token whose link was never delivered.

    A mint that could not be sent must not spend the address's live-link
    allowance or the instance's window budget: the person asked once, received
    nothing, and would otherwise be throttled for a message that does not
    exist. Only an unconsumed row is removed, so this can never undo a
    redemption.
    """
    with connect() as conn:
        conn.execute(
            "DELETE FROM auth_login_tokens "
            "WHERE token_sha256 = ? AND consumed_at IS NULL",
            (token_sha256,),
        )


def resolve_auth_session(session_sha256: str, now: str) -> dict | None:
    """Look up one live session by digest; expired or revoked reads as absent."""
    with connect() as conn:
        row = conn.execute(
            "SELECT s.account_id, s.expires_at, s.revoked_at, "
            "a.email_normalized, a.display_label, a.report_role, a.role_chosen "
            "FROM auth_sessions s JOIN accounts a ON a.account_id = s.account_id "
            "WHERE s.session_sha256 = ?",
            (session_sha256,),
        ).fetchone()
    if row is None or row["revoked_at"] is not None or row["expires_at"] <= now:
        return None
    return dict(row)


def revoke_auth_session(session_sha256: str, now: str) -> None:
    """Sign out one session; unknown digests are a silent no-op."""
    with connect() as conn:
        conn.execute(
            "UPDATE auth_sessions SET revoked_at = ? "
            "WHERE session_sha256 = ? AND revoked_at IS NULL",
            (now, session_sha256),
        )


def set_account_report_role(account_id: str, report_role: str) -> None:
    """Record the reader's chosen report presentation."""
    with connect() as conn:
        conn.execute(
            "UPDATE accounts SET report_role = ?, role_chosen = 1 "
            "WHERE account_id = ?",
            (report_role, account_id),
        )


def get_account(account_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM accounts WHERE account_id = ?", (account_id,),
        ).fetchone()
    return dict(row) if row else None


def record_worker_execution_readiness(
    worker_id: str,
    runtime_contract: str,
    document: dict,
) -> None:
    """Record one worker-observed execution-readiness document directly.

    The runner's heartbeat is the production writer (through
    :func:`record_worker_heartbeat`); this entry point exists for reviewed
    harnesses and operational tooling that must record the observation of a
    worker process which is not this process.
    """
    with connect() as conn:
        _record_worker_execution_readiness_in(
            conn, worker_id=worker_id, runtime_contract=runtime_contract,
            document=document, now=_now())


def _worker_heartbeat_max_age_seconds() -> float:
    try:
        return max(1.0, min(300.0, float(os.environ.get(
            "QL_WORKER_HEARTBEAT_MAX_AGE_SECONDS",
            DEFAULT_WORKER_HEARTBEAT_MAX_AGE_SECONDS,
        ))))
    except (TypeError, ValueError):
        return DEFAULT_WORKER_HEARTBEAT_MAX_AGE_SECONDS


def worker_health(*, max_age_seconds: float | None = None,
                  runtime_contract: str | None = None) -> dict:
    """Return a sanitized, admission-safe view of compatible worker liveness.

    ``runtime_contract`` defaults to the process's serving contract, which is
    the legacy constant unless this process was explicitly launched for an
    isolated corrected-release queue — admission can never be satisfied by a
    worker serving the other queue.
    """
    max_age = (
        _worker_heartbeat_max_age_seconds()
        if max_age_seconds is None
        else max(0.0, float(max_age_seconds))
    )
    contract = runtime_contract or serving_worker_contract()
    with connect() as conn:
        row = conn.execute(
            "SELECT state, started_at, last_seen_at FROM worker_heartbeats "
            "WHERE worker_id = ? AND runtime_contract = ?",
            (_heartbeat_worker_id(contract), contract),
        ).fetchone()
    if row is None:
        return {
            "available": False,
            "state": "not_started",
            "reason": "worker_not_started",
            "last_seen_at": None,
            "heartbeat_age_seconds": None,
            "max_age_seconds": max_age,
        }
    try:
        seen = datetime.fromisoformat(row["last_seen_at"])
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - seen).total_seconds())
    except (TypeError, ValueError):
        age = float("inf")
    stopped = row["state"] == "stopped"
    stale = age > max_age
    available = not stopped and not stale
    reason = None
    if stopped:
        reason = "worker_stopped"
    elif stale:
        reason = "heartbeat_stale"
    # Doc 50 §3.2: a live isolated-contract worker is not admissible unless
    # its own recorded execution-readiness observation says the process can
    # structurally execute a new corrected run — the health view must agree
    # with the acceptance-transaction law. The baseline contract keeps its
    # historical shape byte-for-byte.
    if available and contract != WORKER_RUNTIME_CONTRACT:
        with connect() as conn:
            readiness_facts = _control_plane_registrar_facts(
                conn, contract, now=datetime.now(timezone.utc),
                max_age_seconds=max_age)
        ready, readiness_reason, pending = (
            evaluate_control_plane_registrar(readiness_facts))
        if not ready:
            available = False
            reason = f"{readiness_reason}:{','.join(pending)}"
    return {
        "available": available,
        "state": row["state"] if not stale else "unavailable",
        "reason": reason,
        "last_seen_at": row["last_seen_at"],
        "heartbeat_age_seconds": None if age == float("inf") else round(age, 3),
        "max_age_seconds": max_age,
    }


# ------------------------------------------------------------------ runs / queue

def create_run(spec: dict, spec_hash: str, actor_id: str | None = None,
               confirmed_restatement: str = "", *, tenant_id: str | None = None,
               user_id: str | None = None, battery_profile: str = "battery-v1",
               battery_profile_hash: str = "",
               research_mode: str = "formal") -> str:
    """Create a queued run and reserve its mode-specific capacity atomically.

    Formal runs reserve the tenant's billable allowance. Sandbox runs reserve a
    separate, non-chargeable local test allowance and are constrained to battery-v1,
    which has no Validation Battery v2 final-holdout capability.

    ``actor_id`` is the legacy tenant-only call form. Gate 5 callers should pass both
    ``tenant_id`` and ``user_id`` so ownership is explicit at creation time.
    """
    if research_mode not in RESEARCH_MODES:
        raise ValueError("research_mode must be 'formal' or 'sandbox'")
    if research_mode == "sandbox" and battery_profile != "battery-v1":
        raise ValueError("sandbox runs require battery-v1")
    tenant, user = _ownership_ids(
        actor_id=actor_id, tenant_id=tenant_id, user_id=user_id)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run_id = _insert_run_in(
            conn, spec, spec_hash, tenant=tenant, user=user,
            confirmed_restatement=confirmed_restatement,
            battery_profile=battery_profile,
            battery_profile_hash=battery_profile_hash,
            research_mode=research_mode,
        )
    return run_id


def _insert_run_in(conn: sqlite3.Connection, spec: dict, spec_hash: str, *,
                   tenant: str, user: str, confirmed_restatement: str,
                   battery_profile: str, battery_profile_hash: str,
                   research_mode: str) -> str:
    """Insert one queued run + reservation + receipt inside an open transaction."""
    run_id = uuid.uuid4().hex
    now = _now()
    history = [["confirmed", now], ["validated", now], ["queued", now]]
    chargeable = research_mode == "formal"
    entitlement = (
        _entitlement_status(conn, tenant)
        if chargeable else _sandbox_entitlement_status(conn, tenant)
    )
    if entitlement["remaining"] <= 0:
        raise QuotaExceededError(
            entitlement, quota_kind="formal" if chargeable else "sandbox")
    # §9: read the single release pointer exactly once at acceptance, inside
    # this same transaction. While no ACTIVE release exists — every store this
    # repository can produce before Stop F — the stamp is byte-identical to
    # the legacy constant and no binding row is written. Idempotent replays
    # resolve before this function is reached, so a retry can never re-stamp.
    release = _active_release_in(conn)
    # Stop F5 / doc 48 §4 (A6 option 2, doc 47 Stop D ruling): while a
    # corrected release is ACTIVE, NEW sandbox admission is refused in the
    # acceptance transaction itself — a v3-serving worker must never
    # execute battery-v1 sandbox work, and no research mode may keep the
    # legacy routing. Existing sandbox runs and their history are
    # unaffected; the transaction rolls back with nothing reserved.
    if release is not None and research_mode == "sandbox":
        raise SandboxAdmissionError(
            "new sandbox admission is closed while a corrected release "
            "is active")
    required_contract = (
        release["required_worker_contract"] if release is not None
        else WORKER_RUNTIME_CONTRACT
    )
    # Doc 47 §5.6: the authoritative admission check runs here, on this
    # transaction's own connection, against the exact contract just derived
    # from the pointer — never a process-default contract and never a
    # pre-transaction health snapshot. The route-level check remains a
    # friendly early 503; this one is the law.
    if _worker_heartbeat_required():
        now_dt = datetime.now(timezone.utc)
        heartbeat = conn.execute(
            "SELECT state, last_seen_at FROM worker_heartbeats "
            "WHERE worker_id = ? AND runtime_contract = ?",
            (_heartbeat_worker_id(required_contract), required_contract),
        ).fetchone()
        admissible, reason = evaluate_worker_heartbeat(
            dict(heartbeat) if heartbeat is not None else None,
            now=now_dt,
            max_age_seconds=_worker_heartbeat_max_age_seconds(),
        )
        if not admissible:
            raise WorkerAdmissionError(
                required_contract, reason or "no admissible worker")
        # Doc 50 §3.2: liveness alone can never admit a release-stamped run.
        # The serving worker's own recorded execution-readiness document —
        # fresh, integrity-hashed and naming this exact contract — must say
        # the process can structurally execute a new corrected run, or
        # acceptance refuses on this same connection before anything is
        # reserved. The baseline queue is untouched.
        if release is not None:
            readiness_facts = _control_plane_registrar_facts(
                conn, required_contract, now=now_dt,
                max_age_seconds=_worker_heartbeat_max_age_seconds())
            ready, readiness_reason, pending = (
                evaluate_control_plane_registrar(readiness_facts))
            if not ready:
                raise WorkerAdmissionError(
                    required_contract,
                    f"{readiness_reason}:{','.join(pending)}")
    conn.execute(
        "INSERT INTO runs(run_id, actor_id, user_id, research_mode, spec_json, spec_hash, "
        "spec_version, battery_profile, battery_profile_hash, "
        "required_worker_contract, status, history_json, "
        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, tenant, user, research_mode, json.dumps(spec), spec_hash, 1,
         battery_profile, battery_profile_hash,
         required_contract, "queued",
         json.dumps(history), now, now),
    )
    if release is not None:
        capability_state = {
            probe["capability"]: {
                "ready": int(probe["ready"]),
                "observed_sha256": probe["observed_sha256"],
                "observed_at": probe["observed_at"],
            }
            for probe in conn.execute(
                "SELECT capability, ready, observed_sha256, observed_at "
                "FROM release_capability_probes WHERE release_row_id = ?",
                (release["release_row_id"],),
            ).fetchall()
        }
        binding = build_run_release_binding(
            dict(release), run_id=run_id, tenant_id=tenant,
            workspace_id=user, research_mode=research_mode,
            battery_profile=battery_profile,
            battery_profile_hash=battery_profile_hash,
            confirmed_spec_hash=spec_hash,
            dsl_schema_version=spec.get("dsl_version"),
            rule=spec.get("rule"), base_costs=spec.get("costs"),
            capability_state=capability_state, bound_at=now)
        conn.execute(
            "INSERT INTO run_release_bindings("
            "run_id, release_row_id, release_id, required_worker_contract, "
            "release_tuple_json, release_tuple_sha256, accepted_run_json, "
            "accepted_run_sha256, capability_state_json, bound_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (binding["run_id"], binding["release_row_id"],
             binding["release_id"], binding["required_worker_contract"],
             binding["release_tuple_json"], binding["release_tuple_sha256"],
             binding["accepted_run_json"], binding["accepted_run_sha256"],
             binding["capability_state_json"], binding["bound_at"]),
        )
    conn.execute(
        "INSERT INTO entitlement_reservations("
        "run_id, actor_id, chargeable, state, reserved_at) "
        "VALUES (?, ?, ?, 'reserved', ?)",
        (run_id, tenant, int(chargeable), now),
    )
    receipt_id = f"confirm_{uuid.uuid4().hex}"
    restatement_hash = hashlib.sha256(confirmed_restatement.encode("utf-8")).hexdigest()
    conn.execute(
        "INSERT INTO confirmation_receipts(receipt_id, run_id, actor_id, user_id, "
        "spec_hash, battery_profile, battery_profile_hash, restatement_text, "
        "restatement_hash, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (receipt_id, run_id, tenant, user, spec_hash, battery_profile,
         battery_profile_hash, confirmed_restatement,
         restatement_hash, now),
    )
    return run_id


def _run_dict(row: sqlite3.Row, reservation_row: sqlite3.Row | None,
              receipt_row: sqlite3.Row | None) -> dict:
    d = dict(row)
    d["spec"] = json.loads(d.pop("spec_json"))
    d["history"] = json.loads(d.pop("history_json"))
    d["error"] = json.loads(d["error_json"]) if d.get("error_json") else None
    d.pop("error_json", None)
    d["reservation"] = _reservation_dict(reservation_row) if reservation_row else None
    d["confirmation_receipt"] = _confirmation_dict(receipt_row) if receipt_row else None
    d["validation_anchor"] = get_validation_anchor(d["run_id"])
    return d


def get_run_internal(run_id: str) -> dict | None:
    """Trusted worker/admin lookup by globally unique run id.

    Request handlers must use :func:`get_run_for_principal` instead; that function
    performs tenant and user filtering in SQL and therefore does not disclose whether
    a foreign run id exists.
    """
    with connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        reservation_row = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        receipt_row = conn.execute(
            "SELECT * FROM confirmation_receipts WHERE run_id = ?", (run_id,),
        ).fetchone()
    return _run_dict(row, reservation_row, receipt_row)


def get_run_for_principal(run_id: str, tenant_id: str, user_id: str) -> dict | None:
    """Return a run only when both tenant and user ownership match in SQL."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ? AND actor_id = ? AND user_id = ?",
            (run_id, tenant_id, user_id),
        ).fetchone()
        if row is None:
            return None
        reservation_row = conn.execute(
            "SELECT * FROM entitlement_reservations "
            "WHERE run_id = ? AND actor_id = ?",
            (run_id, tenant_id),
        ).fetchone()
        receipt_row = conn.execute(
            "SELECT * FROM confirmation_receipts "
            "WHERE run_id = ? AND actor_id = ? AND user_id = ?",
            (run_id, tenant_id, user_id),
        ).fetchone()
    return _run_dict(row, reservation_row, receipt_row)


def list_runs_for_principal(
    tenant_id: str,
    user_id: str,
    *,
    limit: int = 10,
    research_mode: str = "formal",
    archived: str = "false",
    family_id: str | None = None,
    tag: str | None = None,
) -> list[dict]:
    """List newest runs owned by exactly one tenant+user principal.

    Ownership filtering happens in SQL before any run is materialized.  This keeps the
    workspace index subject to the same non-disclosure boundary as the single-run read;
    a shared tenant entitlement never makes another user's research discoverable.
    ``family_id``/``tag`` (normalized identity) narrow the list without ever
    exposing note bodies.
    """
    if isinstance(limit, bool) or not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    if research_mode not in RESEARCH_MODES | {"all"}:
        raise ValueError("research_mode must be formal, sandbox, or all")
    if archived not in RUN_ARCHIVE_FILTERS:
        raise ValueError("archived must be false, true, or all")
    clauses = ["actor_id = ?", "user_id = ?", "deleted_at IS NULL"]
    parameters: list[object] = [tenant_id, user_id]
    if research_mode != "all":
        clauses.append("research_mode = ?")
        parameters.append(research_mode)
    if archived == "false":
        clauses.append("archived_at IS NULL")
    elif archived == "true":
        clauses.append("archived_at IS NOT NULL")
    if family_id is not None:
        clauses.append(
            "run_id IN (SELECT run_id FROM run_lineage WHERE family_id = ?)")
        parameters.append(family_id)
    if tag is not None:
        clauses.append(
            "run_id IN (SELECT run_id FROM run_tags WHERE normalized_tag = ?)")
        parameters.append(tag)
    parameters.append(limit)
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM runs WHERE " + " AND ".join(clauses) + " "
            "ORDER BY created_at DESC, run_id DESC LIMIT ?",
            tuple(parameters),
        ).fetchall()
        runs = []
        for row in rows:
            run_id = row["run_id"]
            reservation_row = conn.execute(
                "SELECT * FROM entitlement_reservations "
                "WHERE run_id = ? AND actor_id = ?",
                (run_id, tenant_id),
            ).fetchone()
            receipt_row = conn.execute(
                "SELECT * FROM confirmation_receipts "
                "WHERE run_id = ? AND actor_id = ? AND user_id = ?",
                (run_id, tenant_id, user_id),
            ).fetchone()
            run = _run_dict(row, reservation_row, receipt_row)
            # Additive lineage-v1 workspace metadata; never note bodies.
            lineage_row = conn.execute(
                "SELECT lineage.family_id AS family_id, "
                "lineage.relationship AS relationship, "
                "family.title AS family_title "
                "FROM run_lineage AS lineage "
                "JOIN experiment_families AS family "
                "ON family.family_id = lineage.family_id "
                "WHERE lineage.run_id = ?",
                (run_id,),
            ).fetchone()
            annotation = _annotation_view_in(conn, run_id)
            run["family_id"] = lineage_row["family_id"] if lineage_row else None
            run["family_title"] = (
                lineage_row["family_title"] if lineage_row else None)
            run["relationship"] = (
                lineage_row["relationship"] if lineage_row else None)
            run["tags"] = annotation["tags"]
            run["has_note"] = annotation["note"] != ""
            run["annotation_revision"] = annotation["revision"]
            runs.append(run)
    return runs


def _management_state(run: dict) -> str:
    if run.get("deleted_at"):
        return "deleted"
    if run.get("archived_at"):
        return "archived"
    return "active"


def _assert_terminal_management_status(status: str, action: str) -> None:
    if status not in {"published", *FAILURES}:
        raise RunManagementStateError(
            action,
            status,
            f"only terminal runs can be {action}",
        )


def _set_run_management_state(
    run_id: str, tenant_id: str, user_id: str, *, action: str,
) -> dict:
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status, archived_at, deleted_at FROM runs "
            "WHERE run_id = ? AND actor_id = ? AND user_id = ?",
            (run_id, tenant_id, user_id),
        ).fetchone()
        if row is None:
            raise UnknownRunError(f"unknown run {run_id}")
        _assert_terminal_management_status(row["status"], action)
        if action == "archive":
            if row["deleted_at"] is not None:
                raise RunManagementStateError(
                    action, row["status"], "a deleted run must be restored before archiving")
            if row["archived_at"] is None:
                conn.execute(
                    "UPDATE runs SET archived_at = ? WHERE run_id = ?",
                    (now, run_id),
                )
        elif action == "restore":
            if row["deleted_at"] is not None:
                # Preserve archived_at so a run deleted from Archive returns there.
                conn.execute(
                    "UPDATE runs SET deleted_at = NULL WHERE run_id = ?",
                    (run_id,),
                )
            elif row["archived_at"] is not None:
                conn.execute(
                    "UPDATE runs SET archived_at = NULL WHERE run_id = ?",
                    (run_id,),
                )
        elif action == "delete":
            if row["deleted_at"] is None:
                conn.execute(
                    "UPDATE runs SET deleted_at = ? WHERE run_id = ?",
                    (now, run_id),
                )
        else:  # defensive: management action is never supplied by request data
            raise ValueError(f"unsupported run management action: {action}")
    managed = get_run_for_principal(run_id, tenant_id, user_id)
    if managed is None:  # the scoped row cannot disappear without an external writer
        raise UnknownRunError(f"unknown run {run_id}")
    managed["management_state"] = _management_state(managed)
    return managed


def archive_run_for_principal(run_id: str, tenant_id: str, user_id: str) -> dict:
    return _set_run_management_state(
        run_id, tenant_id, user_id, action="archive")


def restore_run_for_principal(run_id: str, tenant_id: str, user_id: str) -> dict:
    return _set_run_management_state(
        run_id, tenant_id, user_id, action="restore")


def soft_delete_run_for_principal(run_id: str, tenant_id: str, user_id: str) -> dict:
    return _set_run_management_state(
        run_id, tenant_id, user_id, action="delete")


# ------------------------------------------------- experiment lineage (lineage-v1)
#
# Mutable workspace metadata (families, notes, tags) lives OUTSIDE the artifact
# ledger. Nothing in this section reads, writes, or reinterprets sealed evidence,
# financial values, or the final holdout; it stores relationships and private text
# scoped to the exact (actor_id, user_id) principal.

def _lineage_view_row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return {
        "family_id": row["family_id"],
        "parent_run_id": row["parent_run_id"],
        "relationship": row["relationship"],
        "parent_spec_hash": row["parent_spec_hash"],
        "child_spec_hash": row["child_spec_hash"],
        "diff_contract_version": row["diff_contract_version"],
        "changed_assumptions": json.loads(row["changed_assumptions_json"]),
        "changed_assumptions_sha256": row["changed_assumptions_sha256"],
        "created_at": row["created_at"],
    }


def _lineage_view_in(conn: sqlite3.Connection, run_id: str) -> dict | None:
    return _lineage_view_row(conn.execute(
        "SELECT * FROM run_lineage WHERE run_id = ?", (run_id,)).fetchone())


def _run_tags_in(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    """Per-run response tags: ``{display_tag, normalized_tag}`` sorted by ordinal."""
    return [
        {"display_tag": row["display_tag"],
         "normalized_tag": row["normalized_tag"]}
        for row in conn.execute(
            "SELECT display_tag, normalized_tag FROM run_tags "
            "WHERE run_id = ? ORDER BY ordinal",
            (run_id,)).fetchall()
    ]


def _annotation_view_in(conn: sqlite3.Connection, run_id: str) -> dict:
    row = conn.execute(
        "SELECT * FROM run_annotations WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        return {"note": "", "tags": _run_tags_in(conn, run_id),
                "revision": 0, "updated_at": None}
    return {
        "note": row["note_text"],
        "tags": _run_tags_in(conn, run_id),
        "revision": row["revision"],
        "updated_at": row["updated_at"],
    }


def find_run_idempotency(tenant_id: str, user_id: str,
                         idempotency_key_sha256: str) -> dict | None:
    """Resolve an existing idempotency binding for the exact principal."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM run_creation_idempotency "
            "WHERE actor_id = ? AND user_id = ? AND idempotency_key_sha256 = ?",
            (tenant_id, user_id, idempotency_key_sha256),
        ).fetchone()
    if row is None:
        return None
    return {"run_id": row["run_id"], "request_sha256": row["request_sha256"]}


def get_lineage_for_run(run_id: str) -> dict | None:
    """Trusted lineage read by run id (principal scoping happens at the caller)."""
    with connect() as conn:
        return _lineage_view_in(conn, run_id)


def _create_lineage_in(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    child_spec: dict,
    child_spec_hash: str,
    tenant: str,
    user: str,
    research_mode: str,
    battery_profile: str,
    battery_profile_hash: str,
    parent_run_id: str,
    confirmed_parent_spec_hash: str,
    relationship: str,
    diff: dict,
) -> tuple[dict, bool]:
    """Create/inherit the family and record the child edge, all in-transaction.

    Every check is re-verified under the write lock so the API's earlier
    friendly checks cannot be raced. Returns ``(lineage_view, family_created)``.
    """
    if relationship not in {"variation", "rerun"}:
        raise LineageStateError(
            "LINEAGE_RELATION_INVALID", "baseline is server-only")
    if parent_run_id == run_id:
        raise LineageStateError(
            "LINEAGE_CYCLE", "a run cannot be its own parent")
    parent = conn.execute(
        "SELECT * FROM runs WHERE run_id = ? AND actor_id = ? AND user_id = ?",
        (parent_run_id, tenant, user),
    ).fetchone()
    if parent is None or parent["deleted_at"]:
        raise LineageStateError(
            "LINEAGE_PARENT_NOT_FOUND",
            "the lineage parent is missing, foreign, or deleted")
    if parent["spec_hash"] != confirmed_parent_spec_hash:
        raise LineageStateError(
            "LINEAGE_PARENT_CHANGED",
            "the confirmed parent spec hash does not match the sealed parent")
    parent_spec = json.loads(parent["spec_json"])
    # The child row is already inserted in this same transaction, stamped
    # from the release pointer at acceptance. Comparing the parent against
    # the child's actual stamp (identical to the fixed constant while no
    # ACTIVE release exists) makes the check literal: a family can never mix
    # runs bound to different worker contracts, before or after a release.
    child_row = conn.execute(
        "SELECT required_worker_contract FROM runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    child_contract = (
        child_row["required_worker_contract"] if child_row is not None
        else WORKER_RUNTIME_CONTRACT
    )
    if (parent["research_mode"] != research_mode
            or parent["battery_profile"] != battery_profile
            or parent["battery_profile_hash"] != battery_profile_hash
            or parent["required_worker_contract"] != child_contract
            or parent_spec.get("dsl_version") != child_spec.get("dsl_version")):
        raise LineageStateError(
            "LINEAGE_CONTEXT_MISMATCH",
            "parent and child must share research mode, DSL version, battery "
            "profile identity, and worker contract")
    now = _now()
    parent_edge = conn.execute(
        "SELECT * FROM run_lineage WHERE run_id = ?", (parent_run_id,),
    ).fetchone()
    family_created = False
    if parent_edge is None:
        family_id = uuid.uuid4().hex
        title = default_family_title(parent_spec.get("meta", {}).get("name"))
        conn.execute(
            "INSERT INTO experiment_families(family_id, actor_id, user_id, "
            "title, description, revision, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (family_id, tenant, user, title, "", 1, now, now),
        )
        # Frozen §5.1 baseline shape: NULL parent fields, the run's own spec
        # hash, the exact ASCII bytes "[]", and the fixed empty-diff hash.
        conn.execute(
            "INSERT INTO run_lineage(run_id, family_id, parent_run_id, "
            "relationship, parent_spec_hash, child_spec_hash, "
            "diff_contract_version, changed_assumptions_json, "
            "changed_assumptions_sha256, created_at) "
            "VALUES (?,?,NULL,'baseline',NULL,?,?,?,?,?)",
            (parent_run_id, family_id, parent["spec_hash"],
             LINEAGE_DIFF_CONTRACT_VERSION, EMPTY_DIFF_JSON, EMPTY_DIFF_SHA256,
             now),
        )
        family_created = True
    else:
        family_id = parent_edge["family_id"]
        family = conn.execute(
            "SELECT 1 FROM experiment_families "
            "WHERE family_id = ? AND actor_id = ? AND user_id = ?",
            (family_id, tenant, user),
        ).fetchone()
        if family is None:
            raise LineageStateError(
                "LINEAGE_PARENT_NOT_FOUND",
                "the parent's family is not owned by this principal")
    conn.execute(
        "INSERT INTO run_lineage(run_id, family_id, parent_run_id, "
        "relationship, parent_spec_hash, child_spec_hash, "
        "diff_contract_version, changed_assumptions_json, "
        "changed_assumptions_sha256, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (run_id, family_id, parent_run_id, relationship,
         confirmed_parent_spec_hash, child_spec_hash,
         LINEAGE_DIFF_CONTRACT_VERSION, diff["canonical_json"],
         diff["changed_assumptions_sha256"], now),
    )
    view = {
        "family_id": family_id,
        "parent_run_id": parent_run_id,
        "relationship": relationship,
        "parent_spec_hash": confirmed_parent_spec_hash,
        "child_spec_hash": child_spec_hash,
        "diff_contract_version": LINEAGE_DIFF_CONTRACT_VERSION,
        "changed_assumptions": diff["changed_assumptions"],
        "changed_assumptions_sha256": diff["changed_assumptions_sha256"],
        "created_at": now,
    }
    return view, family_created


def create_run_managed(
    spec: dict,
    spec_hash: str,
    *,
    tenant_id: str,
    user_id: str,
    confirmed_restatement: str = "",
    battery_profile: str = "battery-v1",
    battery_profile_hash: str = "",
    research_mode: str = "formal",
    lineage: dict | None = None,
    idempotency: dict | None = None,
) -> dict:
    """Atomic run creation with optional lineage and idempotency binding.

    One ``BEGIN IMMEDIATE`` transaction commits the idempotency record, run,
    reservation, receipt, family/edges, diff, and the redacted audit event —
    or nothing. A replayed key returns the original run without a second
    reservation or event; the same key with a different canonical request
    raises :class:`RunIdempotencyConflictError`.
    """
    if research_mode not in RESEARCH_MODES:
        raise ValueError("research_mode must be 'formal' or 'sandbox'")
    if research_mode == "sandbox" and battery_profile != "battery-v1":
        raise ValueError("sandbox runs require battery-v1")
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if idempotency is not None:
            existing = conn.execute(
                "SELECT * FROM run_creation_idempotency "
                "WHERE actor_id = ? AND user_id = ? "
                "AND idempotency_key_sha256 = ?",
                (tenant_id, user_id, idempotency["idempotency_key_sha256"]),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != idempotency["request_sha256"]:
                    raise RunIdempotencyConflictError(
                        "this idempotency key is bound to a different request")
                return {
                    "run_id": existing["run_id"],
                    "idempotent": True,
                    "lineage": _lineage_view_in(conn, existing["run_id"]),
                    "family_created": False,
                }
        run_id = _insert_run_in(
            conn, spec, spec_hash, tenant=tenant_id, user=user_id,
            confirmed_restatement=confirmed_restatement,
            battery_profile=battery_profile,
            battery_profile_hash=battery_profile_hash,
            research_mode=research_mode,
        )
        lineage_view = None
        family_created = False
        if lineage is not None:
            lineage_view, family_created = _create_lineage_in(
                conn,
                run_id=run_id,
                child_spec=spec,
                child_spec_hash=spec_hash,
                tenant=tenant_id,
                user=user_id,
                research_mode=research_mode,
                battery_profile=battery_profile,
                battery_profile_hash=battery_profile_hash,
                parent_run_id=lineage["parent_run_id"],
                confirmed_parent_spec_hash=lineage["confirmed_parent_spec_hash"],
                relationship=lineage["relationship"],
                diff=lineage["diff"],
            )
            _record_event_in(conn, "experiment_lineage_created", {
                "family_id": lineage_view["family_id"],
                "run_id": run_id,
                "parent_run_id": lineage_view["parent_run_id"],
                "relationship": lineage_view["relationship"],
                "changed_assumption_count":
                    len(lineage_view["changed_assumptions"]),
                "changed_assumptions_sha256":
                    lineage_view["changed_assumptions_sha256"],
                "family_created": family_created,
            }, tenant_id=tenant_id, user_id=user_id)
        if idempotency is not None:
            conn.execute(
                "INSERT INTO run_creation_idempotency(actor_id, user_id, "
                "idempotency_key_sha256, request_sha256, run_id, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (tenant_id, user_id, idempotency["idempotency_key_sha256"],
                 idempotency["request_sha256"], run_id, _now()),
            )
        return {
            "run_id": run_id,
            "idempotent": False,
            "lineage": lineage_view,
            "family_created": family_created,
        }


# --------------------------------------------- experiment families & annotations

def _family_public(row: sqlite3.Row) -> dict:
    return {
        "family_id": row["family_id"],
        "title": row["title"],
        "description": row["description"],
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _family_aggregates_in(conn: sqlite3.Connection, family_id: str) -> dict:
    baseline = conn.execute(
        "SELECT lineage.run_id AS run_id, runs.research_mode AS research_mode "
        "FROM run_lineage AS lineage JOIN runs ON runs.run_id = lineage.run_id "
        "WHERE lineage.family_id = ? AND lineage.relationship = 'baseline'",
        (family_id,),
    ).fetchone()
    visible = conn.execute(
        "SELECT COUNT(*) AS count FROM run_lineage AS lineage "
        "JOIN runs ON runs.run_id = lineage.run_id "
        "WHERE lineage.family_id = ? AND runs.deleted_at IS NULL",
        (family_id,),
    ).fetchone()
    has_notes = conn.execute(
        "SELECT 1 FROM run_annotations AS annotation "
        "JOIN run_lineage AS lineage ON lineage.run_id = annotation.run_id "
        "JOIN runs ON runs.run_id = annotation.run_id "
        "WHERE lineage.family_id = ? AND runs.deleted_at IS NULL "
        "AND annotation.note_text != '' LIMIT 1",
        (family_id,),
    ).fetchone()
    # Aggregation collapses one normalized identity across visible runs. The
    # display winner is the earliest visible run by created_at ASC, run_id ASC,
    # then lowest ordinal; aggregated tags sort by normalized identity.
    winners: dict[str, str] = {}
    for row in conn.execute(
        "SELECT tag.normalized_tag AS normalized_tag, "
        "tag.display_tag AS display_tag "
        "FROM run_tags AS tag "
        "JOIN run_lineage AS lineage ON lineage.run_id = tag.run_id "
        "JOIN runs ON runs.run_id = tag.run_id "
        "WHERE lineage.family_id = ? AND runs.deleted_at IS NULL "
        "ORDER BY runs.created_at ASC, runs.run_id ASC, tag.ordinal ASC",
        (family_id,),
    ).fetchall():
        winners.setdefault(row["normalized_tag"], row["display_tag"])
    tags = [
        {"display_tag": winners[normalized], "normalized_tag": normalized}
        for normalized in sorted(winners)
    ]
    return {
        "research_mode": baseline["research_mode"] if baseline else None,
        "baseline_run_id": baseline["run_id"] if baseline else None,
        "visible_run_count": visible["count"],
        "has_notes": has_notes is not None,
        "tags": tags,
    }


def list_experiment_families_for_principal(
    tenant_id: str,
    user_id: str,
    *,
    research_mode: str = "formal",
    limit: int = 50,
    cursor: dict | None = None,
) -> dict:
    """Stable, principal-scoped family summaries ordered by
    ``updated_at DESC, family_id ASC`` with keyset pagination."""
    if research_mode not in RESEARCH_MODES:
        raise ValueError("research_mode must be formal or sandbox")
    if isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    clauses = ["family.actor_id = ?", "family.user_id = ?"]
    parameters: list[object] = [tenant_id, user_id]
    clauses.append(
        "(SELECT runs.research_mode FROM run_lineage AS lineage "
        " JOIN runs ON runs.run_id = lineage.run_id "
        " WHERE lineage.family_id = family.family_id "
        " AND lineage.relationship = 'baseline') = ?")
    parameters.append(research_mode)
    if cursor is not None:
        clauses.append(
            "(family.updated_at < ? OR "
            "(family.updated_at = ? AND family.family_id > ?))")
        parameters.extend(
            [cursor["updated_at"], cursor["updated_at"], cursor["family_id"]])
    parameters.append(limit + 1)
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM experiment_families AS family WHERE "
            + " AND ".join(clauses)
            + " ORDER BY family.updated_at DESC, family.family_id ASC LIMIT ?",
            tuple(parameters),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        experiments = []
        for row in rows:
            summary = _family_public(row)
            summary.update(_family_aggregates_in(conn, row["family_id"]))
            experiments.append(summary)
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = {
            "updated_at": last["updated_at"], "family_id": last["family_id"]}
    return {
        "experiments": experiments,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


def get_experiment_family_for_principal(
    family_id: str, tenant_id: str, user_id: str,
) -> dict | None:
    """Family detail with §5.5 visibility: deleted members are omitted unless a
    visible child directly references them, in which case only a
    ``{run_id, removed: true}`` tombstone appears. Counts exclude tombstones."""
    with connect() as conn:
        family = conn.execute(
            "SELECT * FROM experiment_families "
            "WHERE family_id = ? AND actor_id = ? AND user_id = ?",
            (family_id, tenant_id, user_id),
        ).fetchone()
        if family is None:
            return None
        member_rows = conn.execute(
            "SELECT lineage.run_id AS run_id, "
            "lineage.parent_run_id AS parent_run_id, "
            "lineage.relationship AS relationship, "
            "lineage.diff_contract_version AS diff_contract_version, "
            "lineage.changed_assumptions_json AS changed_assumptions_json, "
            "lineage.changed_assumptions_sha256 AS changed_assumptions_sha256, "
            "runs.spec_hash AS spec_hash, runs.status AS status, "
            "runs.research_mode AS research_mode, "
            "runs.archived_at AS archived_at, runs.deleted_at AS deleted_at, "
            "runs.created_at AS run_created_at "
            "FROM run_lineage AS lineage JOIN runs ON runs.run_id = lineage.run_id "
            "WHERE lineage.family_id = ? "
            "ORDER BY runs.created_at ASC, runs.run_id ASC",
            (family_id,),
        ).fetchall()
        visible_parent_refs = {
            row["parent_run_id"] for row in conn.execute(
                "SELECT lineage.parent_run_id AS parent_run_id "
                "FROM run_lineage AS lineage "
                "JOIN runs ON runs.run_id = lineage.run_id "
                "WHERE lineage.family_id = ? AND runs.deleted_at IS NULL "
                "AND lineage.parent_run_id IS NOT NULL",
                (family_id,),
            ).fetchall()
        }
        # Frozen §5.4 member union: an ordinary member and a deleted-parent
        # tombstone, nothing else. No battery/evidence status, no financial or
        # Agent value, and the evidence projection helper is never called.
        members: list[dict] = []
        for row in member_rows:
            if row["deleted_at"]:
                if row["run_id"] in visible_parent_refs:
                    members.append({"run_id": row["run_id"], "removed": True})
                continue
            annotation = _annotation_view_in(conn, row["run_id"])
            members.append({
                "run_id": row["run_id"],
                "removed": False,
                "parent_run_id": row["parent_run_id"],
                "relationship": row["relationship"],
                "spec_hash": row["spec_hash"],
                "status": row["status"],
                "research_mode": row["research_mode"],
                "archived_at": row["archived_at"],
                "created_at": row["run_created_at"],
                "diff_contract_version": row["diff_contract_version"],
                "changed_assumptions":
                    json.loads(row["changed_assumptions_json"]),
                "changed_assumptions_sha256":
                    row["changed_assumptions_sha256"],
                "annotation_revision": annotation["revision"],
                "has_note": annotation["note"] != "",
                "tags": annotation["tags"],
            })
        experiment = _family_public(family)
        experiment.update(_family_aggregates_in(conn, family_id))
    return {"experiment": experiment, "members": members}


def update_family_for_principal(
    family_id: str,
    tenant_id: str,
    user_id: str,
    *,
    title: str | None,
    description: str | None,
    expected_revision: int,
) -> dict | None:
    """Optimistically rename/describe a family; audit commits with the write."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM experiment_families "
            "WHERE family_id = ? AND actor_id = ? AND user_id = ?",
            (family_id, tenant_id, user_id),
        ).fetchone()
        if row is None:
            return None
        if row["revision"] != expected_revision:
            raise FamilyConflictError(row["revision"])
        next_title = row["title"] if title is None else title
        next_description = (
            row["description"] if description is None else description)
        now = _now()
        updated = conn.execute(
            "UPDATE experiment_families SET title = ?, description = ?, "
            "revision = revision + 1, updated_at = ? "
            "WHERE family_id = ? AND revision = ?",
            (next_title, next_description, now, family_id, expected_revision),
        )
        if updated.rowcount != 1:
            raise FamilyConflictError(row["revision"])
        _record_event_in(conn, "experiment_family_updated", {
            "family_id": family_id,
            "revision": expected_revision + 1,
            "title_length": len(next_title),
            "title_sha256": hashlib.sha256(
                next_title.encode("utf-8")).hexdigest(),
            "description_length": len(next_description),
            "description_sha256": hashlib.sha256(
                next_description.encode("utf-8")).hexdigest(),
        }, tenant_id=tenant_id, user_id=user_id)
        refreshed = conn.execute(
            "SELECT * FROM experiment_families WHERE family_id = ?",
            (family_id,),
        ).fetchone()
        experiment = _family_public(refreshed)
        experiment.update(_family_aggregates_in(conn, family_id))
    return experiment


def get_workspace_metadata_for_principal(
    run_id: str, tenant_id: str, user_id: str,
) -> dict | None:
    """Lineage/family/annotation view. The exact owner may read a soft-deleted
    run's metadata for restore context; writes are refused elsewhere."""
    with connect() as conn:
        run = conn.execute(
            "SELECT run_id FROM runs "
            "WHERE run_id = ? AND actor_id = ? AND user_id = ?",
            (run_id, tenant_id, user_id),
        ).fetchone()
        if run is None:
            return None
        lineage = _lineage_view_in(conn, run_id)
        family = None
        if lineage is not None:
            family_row = conn.execute(
                "SELECT * FROM experiment_families "
                "WHERE family_id = ? AND actor_id = ? AND user_id = ?",
                (lineage["family_id"], tenant_id, user_id),
            ).fetchone()
            if family_row is not None:
                family = {
                    "family_id": family_row["family_id"],
                    "title": family_row["title"],
                    "description": family_row["description"],
                    "revision": family_row["revision"],
                }
        annotation = _annotation_view_in(conn, run_id)
    return {
        "run_id": run_id,
        "family": family,
        "lineage": lineage,
        "annotation": annotation,
    }


def replace_annotations_for_principal(
    run_id: str,
    tenant_id: str,
    user_id: str,
    *,
    note: str,
    tags: list[tuple[str, str, int]],
    expected_revision: int,
) -> dict | None:
    """Atomically replace the note plus the complete ordered tag set.

    Revision 0 inserts; later writes use optimistic concurrency. A stale write
    changes nothing and raises :class:`AnnotationConflictError`. Soft-deleted
    runs raise :class:`RunDeletedError` until restored.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute(
            "SELECT run_id, deleted_at FROM runs "
            "WHERE run_id = ? AND actor_id = ? AND user_id = ?",
            (run_id, tenant_id, user_id),
        ).fetchone()
        if run is None:
            return None
        if run["deleted_at"]:
            raise RunDeletedError("restore the run before editing annotations")
        existing = conn.execute(
            "SELECT * FROM run_annotations WHERE run_id = ?", (run_id,),
        ).fetchone()
        now = _now()
        if existing is None:
            if expected_revision != 0:
                raise AnnotationConflictError(0)
            conn.execute(
                "INSERT INTO run_annotations(run_id, actor_id, user_id, "
                "note_text, revision, created_at, updated_at) "
                "VALUES (?,?,?,?,1,?,?)",
                (run_id, tenant_id, user_id, note, now, now),
            )
            new_revision = 1
        else:
            if existing["revision"] != expected_revision:
                raise AnnotationConflictError(existing["revision"])
            updated = conn.execute(
                "UPDATE run_annotations SET note_text = ?, "
                "revision = revision + 1, updated_at = ? "
                "WHERE run_id = ? AND revision = ?",
                (note, now, run_id, expected_revision),
            )
            if updated.rowcount != 1:
                raise AnnotationConflictError(existing["revision"])
            new_revision = expected_revision + 1
        conn.execute("DELETE FROM run_tags WHERE run_id = ?", (run_id,))
        for display_tag, normalized_tag, ordinal in tags:
            conn.execute(
                "INSERT INTO run_tags(run_id, display_tag, normalized_tag, "
                "ordinal) VALUES (?,?,?,?)",
                (run_id, display_tag, normalized_tag, ordinal),
            )
        _record_event_in(conn, "run_annotations_updated", {
            "run_id": run_id,
            "revision": new_revision,
            "tag_count": len(tags),
            "note_length": len(note),
            "note_sha256": hashlib.sha256(note.encode("utf-8")).hexdigest(),
        }, tenant_id=tenant_id, user_id=user_id)
        return {
            "note": note,
            "tags": [
                {"display_tag": display, "normalized_tag": normalized}
                for display, normalized, _ordinal in tags
            ],
            "revision": new_revision,
            "updated_at": now,
        }


def get_run(run_id: str) -> dict | None:
    """Legacy trusted lookup; new request handlers must use principal scoping."""
    return get_run_internal(run_id)


TERMINAL_FAILURE_STATUSES = ("system_failed", "data_quality_failed")


def set_status(run_id: str, status: str, error: dict | None = None) -> None:
    now = _now()
    with connect() as conn:
        row = conn.execute(
            "SELECT history_json, status FROM runs WHERE run_id = ?",
            (run_id,)).fetchone()
        # Doc 50 §3.3: a published run owns sealed evidence, so no later
        # writer may downgrade it to a failure. Two workers can legitimately
        # hold one run (the stale-claim requeue), and a loser that fails
        # closed after the winner published would otherwise mark a run
        # failed while its sealed record exists. Every other transition,
        # including the requeue back to 'queued', is untouched.
        if (row is not None and row["status"] == "published"
                and status in TERMINAL_FAILURE_STATUSES):
            return
        history = json.loads(row["history_json"]) if row else []
        history.append([status, now])
        conn.execute(
            "UPDATE runs SET status = ?, history_json = ?, error_json = ?, updated_at = ?"
            " WHERE run_id = ?",
            (status, json.dumps(history), json.dumps(error) if error else None, now, run_id),
        )


def bump_retries(run_id: str) -> int:
    with connect() as conn:
        conn.execute("UPDATE runs SET retries = retries + 1 WHERE run_id = ?", (run_id,))
        row = conn.execute("SELECT retries FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return int(row["retries"])


def claim_next_queued() -> str | None:
    """Atomically claim the oldest queued run for this process's contract."""
    with connect() as conn:
        row = conn.execute(
            "SELECT run_id FROM runs WHERE status = 'queued' "
            "AND required_worker_contract = ? ORDER BY created_at LIMIT 1",
            (serving_worker_contract(),),
        ).fetchone()
        if row is None:
            return None
        run_id = row["run_id"]
        cur = conn.execute(
            "UPDATE runs SET status = 'snapshot_pinned', updated_at = ? "
            "WHERE run_id = ? AND status = 'queued'", (_now(), run_id),
        )
        if cur.rowcount != 1:
            return None
    # record the transition in history via set_status idempotently
    set_status(run_id, "snapshot_pinned")
    return run_id


# ------------------------------------------------------------------ entitlement (MOCK)

def _entitlement_status(conn: sqlite3.Connection, actor_id: str) -> dict:
    row = conn.execute("SELECT * FROM entitlement WHERE actor_id = ?", (actor_id,)).fetchone()
    reserved_row = conn.execute(
        "SELECT COUNT(*) AS count FROM entitlement_reservations "
        "WHERE actor_id = ? AND chargeable = 1 AND state = 'reserved'", (actor_id,),
    ).fetchone()
    quota = int(row["quota"]) if row else 0
    used = int(row["used"]) if row else 0
    reserved = int(reserved_row["count"])
    remaining = quota - used - reserved
    return {
        "actor_id": actor_id,
        "quota": quota,
        "used": used,
        "reserved": reserved,
        "remaining": remaining,
        "available": remaining > 0,
        "status": "available" if remaining > 0 else "exhausted",
        "mock": True,
        "label": "Local preview allowance — tenant-owned, non-production Gate 5 workspace",
    }


def _sandbox_entitlement_status(conn: sqlite3.Connection, actor_id: str) -> dict:
    """Return the isolated, fail-closed local sandbox allowance for one tenant."""
    provisioned = conn.execute(
        "SELECT 1 FROM entitlement WHERE actor_id = ?", (actor_id,),
    ).fetchone() is not None
    counts = conn.execute(
        "SELECT "
        "SUM(CASE WHEN state = 'settled' THEN 1 ELSE 0 END) AS used, "
        "SUM(CASE WHEN state = 'reserved' THEN 1 ELSE 0 END) AS reserved "
        "FROM entitlement_reservations WHERE actor_id = ? AND chargeable = 0",
        (actor_id,),
    ).fetchone()
    quota = MOCK_SANDBOX_QUOTA if provisioned else 0
    used = int(counts["used"] or 0)
    reserved = int(counts["reserved"] or 0)
    remaining = quota - used - reserved
    return {
        "actor_id": actor_id,
        "quota": quota,
        "used": used,
        "reserved": reserved,
        "remaining": remaining,
        "available": remaining > 0,
        "status": "available" if remaining > 0 else "exhausted",
        "mock": True,
        "label": "Local sandbox allowance — non-billable development runs only",
    }


def entitlement_status(actor_id: str = MOCK_ACTOR) -> dict:
    with connect() as conn:
        return _entitlement_status(conn, actor_id)


def sandbox_entitlement_status(actor_id: str = MOCK_ACTOR) -> dict:
    with connect() as conn:
        return _sandbox_entitlement_status(conn, actor_id)


def tenant_is_provisioned(tenant_id: str) -> bool:
    """Return whether the billing/control plane has admitted this tenant.

    Dataset quarantine files reference ``entitlement(actor_id)`` through their database
    receipt.  Checking this before writing raw bytes avoids creating an unowned orphan
    when a provider resolves a principal that has not yet been provisioned.  The foreign
    key remains the final, transactional backstop against a check/insert race.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM entitlement WHERE actor_id = ?", (tenant_id,),
        ).fetchone()
    return row is not None


def provision_local_principal(tenant_id: str, user_id: str,
                              quota: int = MOCK_QUOTA) -> dict:
    """Provision a local/test principal without introducing a fake production IdP.

    Entitlement remains tenant-owned in Gate 5, so ``user_id`` is returned for callers
    but is not inserted into the tenant entitlement table. This helper is deliberately
    named local and should be replaced by the billing/provisioning control plane when a
    real identity provider is connected.
    """
    tenant, user = _ownership_ids(tenant_id=tenant_id, user_id=user_id)
    if quota < 0:
        raise ValueError("quota must be non-negative")
    with connect() as conn:
        conn.execute(
            "INSERT INTO entitlement(actor_id, quota, used) VALUES (?, ?, 0) "
            "ON CONFLICT(actor_id) DO UPDATE SET quota = excluded.quota",
            (tenant, quota),
        )
        result = _entitlement_status(conn, tenant)
    result["user_id"] = user
    return result


def has_remaining(actor_id: str = MOCK_ACTOR) -> bool:
    return entitlement_status(actor_id)["remaining"] > 0


def _reservation_dict(row: sqlite3.Row, *, applied: bool | None = None) -> dict:
    chargeable = bool(row["chargeable"])
    result = {
        "run_id": row["run_id"],
        "actor_id": row["actor_id"],
        "chargeable": chargeable,
        "status": row["state"],
        "quota_charged": chargeable and row["state"] == "settled",
        "reserved_at": row["reserved_at"],
        "settled_at": row["settled_at"],
        "released_at": row["released_at"],
    }
    if applied is not None:
        result["applied"] = applied
    return result


def _confirmation_dict(row: sqlite3.Row) -> dict:
    return {
        "receipt_id": row["receipt_id"],
        "run_id": row["run_id"],
        "actor_id": row["actor_id"],
        "user_id": row["user_id"],
        "spec_hash": row["spec_hash"],
        "battery_profile": row["battery_profile"],
        "battery_profile_hash": row["battery_profile_hash"],
        "restatement": row["restatement_text"],
        "restatement_hash": row["restatement_hash"],
        "issued_at": row["issued_at"],
    }


def _validation_anchor_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def get_validation_anchor(run_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM validation_anchors WHERE run_id = ?", (run_id,),
        ).fetchone()
    return _validation_anchor_dict(row) if row else None


def seal_validation_anchor(
    run_id: str, *, temporal_integrity: dict, partitions: dict,
    validation_plan: dict, final_execution_binding: dict | None,
) -> dict:
    """Write-once local control-plane hashes outside the artifact directory."""
    values = {
        "temporal_integrity_sha256": _canonical_sha256(temporal_integrity),
        "partitions_sha256": _canonical_sha256(partitions),
        "validation_plan_sha256": _canonical_sha256(validation_plan),
        "final_execution_binding_sha256": _canonical_sha256(final_execution_binding),
    }
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute(
            "SELECT research_mode FROM runs WHERE run_id = ?", (run_id,),
        ).fetchone()
        if run is None:
            raise UnknownRunError(f"unknown run {run_id}")
        if run["research_mode"] != "formal":
            raise ReservationStateError(
                "sandbox runs cannot seal a formal validation anchor")
        conn.execute(
            "INSERT OR IGNORE INTO validation_anchors("
            "run_id, temporal_integrity_sha256, partitions_sha256, "
            "validation_plan_sha256, final_execution_binding_sha256, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, values["temporal_integrity_sha256"], values["partitions_sha256"],
             values["validation_plan_sha256"],
             values["final_execution_binding_sha256"], now),
        )
        row = conn.execute(
            "SELECT * FROM validation_anchors WHERE run_id = ?", (run_id,),
        ).fetchone()
        if row is None or any(row[key] != value for key, value in values.items()):
            raise ValueError("validation control-plane anchor is write-once and changed")
    return _validation_anchor_dict(row)


def get_final_holdout_claim(run_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM final_holdout_claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        reveal_key = value.get("reveal_key")
        if reveal_key:
            reveal = conn.execute(
                "SELECT * FROM final_holdout_reveals WHERE reveal_key = ?",
                (reveal_key,),
            ).fetchone()
            if reveal is None:
                raise RuntimeError("final holdout run mapping has no reveal ledger row")
            value["state"] = reveal["state"]
            value["spec_hash"] = reveal["spec_hash"]
            value["validation_plan_hash"] = reveal["validation_plan_hash"]
            raw_result = reveal["result_json"]
        else:
            # Pre-v2-ledger rows cannot be safely shared across runs. Preserve their
            # terminal/per-run state, but never manufacture a lineage key for them.
            raw_result = value.get("result_json")
    value.pop("result_json", None)
    value["result"] = json.loads(raw_result) if raw_result else None
    return value


def ensure_final_holdout_ready(
    run_id: str, *, spec_hash: str, validation_plan_hash: str,
    actor_id: str, snapshot_sha256: str, final_boundary: dict,
) -> dict:
    """Bind a run to the tenant+snapshot+boundary reveal ledger atomically.

    A previously sealed identical result is reusable. A different spec/plan targeting
    the same final bytes is rejected before any capability can be minted.
    """
    now = _now()
    reveal_key, boundary_sha = final_reveal_key(
        actor_id, snapshot_sha256, final_boundary)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute(
            "SELECT research_mode FROM runs WHERE run_id = ?", (run_id,),
        ).fetchone()
        if run is None:
            raise UnknownRunError(f"unknown run {run_id}")
        if run["research_mode"] != "formal":
            raise ReservationStateError(
                "sandbox runs cannot access the formal final holdout")
        reveal = conn.execute(
            "SELECT * FROM final_holdout_reveals WHERE reveal_key = ?",
            (reveal_key,),
        ).fetchone()
        if reveal is None:
            conn.execute(
                "INSERT INTO final_holdout_reveals("
                "reveal_key, actor_id, snapshot_sha256, final_boundary_sha256, "
                "spec_hash, validation_plan_hash, state, result_json, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 'final.ready', NULL, ?, ?)",
                (reveal_key, actor_id, snapshot_sha256, boundary_sha, spec_hash,
                 validation_plan_hash, now, now),
            )
        elif (reveal["actor_id"] != actor_id
              or reveal["snapshot_sha256"] != snapshot_sha256
              or reveal["final_boundary_sha256"] != boundary_sha):
            raise ValueError("final reveal lineage key collision")
        elif (reveal["spec_hash"] != spec_hash
              or reveal["validation_plan_hash"] != validation_plan_hash):
            raise ValueError(
                "final holdout was already revealed for another locked spec/plan; "
                "use a new snapshot or cutoff")
        conn.execute(
            "INSERT OR IGNORE INTO final_holdout_claims("
            "run_id, reveal_key, spec_hash, validation_plan_hash, state, result_json, "
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, 'final.ready', NULL, ?, ?)",
            (run_id, reveal_key, spec_hash, validation_plan_hash, now, now),
        )
        row = conn.execute(
            "SELECT * FROM final_holdout_claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        if (row["reveal_key"] != reveal_key or row["spec_hash"] != spec_hash
                or row["validation_plan_hash"] != validation_plan_hash):
            raise ValueError("final holdout claim binding does not match the sealed plan")
    return get_final_holdout_claim(run_id)


def claim_final_holdout(
    run_id: str, *, spec_hash: str, validation_plan_hash: str,
) -> dict:
    """Atomically move ready -> inflight.  Every later claim is refused."""
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM final_holdout_claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        if row is None:
            raise ValueError("final holdout claim is not ready")
        reveal_key = row["reveal_key"]
        if not reveal_key:
            raise ValueError("legacy final holdout claim has no cross-run reveal binding")
        reveal = conn.execute(
            "SELECT * FROM final_holdout_reveals WHERE reveal_key = ?", (reveal_key,),
        ).fetchone()
        if reveal is None:
            raise ValueError("final holdout reveal ledger row is missing")
        if (row["spec_hash"] != spec_hash or row["validation_plan_hash"] != validation_plan_hash
                or reveal["spec_hash"] != spec_hash
                or reveal["validation_plan_hash"] != validation_plan_hash):
            raise ValueError("final holdout claim binding does not match the sealed plan")
        if reveal["state"] != "final.ready":
            return {
                "claimed": False,
                "state": reveal["state"],
                "result": (json.loads(reveal["result_json"])
                           if reveal["result_json"] else None),
                "reused_across_run": (
                    reveal["state"] == "final.result" and row["result_json"] is None),
            }
        changed = conn.execute(
            "UPDATE final_holdout_reveals SET state = 'final.inflight', updated_at = ? "
            "WHERE reveal_key = ? AND state = 'final.ready'",
            (now, reveal_key),
        )
        if changed.rowcount != 1:
            raise RuntimeError("final holdout claim lost its atomic transition")
        conn.execute(
            "UPDATE final_holdout_claims SET state = 'final.inflight', updated_at = ? "
            "WHERE run_id = ?", (now, run_id),
        )
    return {"claimed": True, "state": "final.inflight", "result": None,
            "reused_across_run": False}


def complete_final_holdout(run_id: str, result: dict) -> None:
    now = _now()
    body = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        mapping = conn.execute(
            "SELECT reveal_key FROM final_holdout_claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        if mapping is None or not mapping["reveal_key"]:
            raise RuntimeError("final holdout result has no reveal-ledger mapping")
        changed = conn.execute(
            "UPDATE final_holdout_reveals SET state = 'final.result', result_json = ?, "
            "updated_at = ? WHERE reveal_key = ? AND state = 'final.inflight'",
            (body, now, mapping["reveal_key"]),
        )
        if changed.rowcount != 1:
            raise RuntimeError("final holdout result cannot be written twice")
        conn.execute(
            "UPDATE final_holdout_claims SET state = 'final.result', result_json = ?, "
            "updated_at = ? WHERE run_id = ?", (body, now, run_id),
        )


def fail_inflight_final_holdout(run_id: str) -> bool:
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        mapping = conn.execute(
            "SELECT reveal_key FROM final_holdout_claims WHERE run_id = ?", (run_id,),
        ).fetchone()
        if mapping is None or not mapping["reveal_key"]:
            return False
        changed = conn.execute(
            "UPDATE final_holdout_reveals SET state = 'system_failed', updated_at = ? "
            "WHERE reveal_key = ? AND state = 'final.inflight' AND result_json IS NULL",
            (_now(), mapping["reveal_key"]),
        )
        if changed.rowcount:
            conn.execute(
                "UPDATE final_holdout_claims SET state = 'system_failed', updated_at = ? "
                "WHERE run_id = ?", (_now(), run_id),
            )
    return changed.rowcount == 1


def get_reservation(run_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
    return _reservation_dict(row) if row else None


def get_confirmation_receipt(run_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM confirmation_receipts WHERE run_id = ?", (run_id,),
        ).fetchone()
    return _confirmation_dict(row) if row else None


def reserve_entitlement(run_id: str, actor_id: str | None = None) -> dict:
    """Idempotently reserve capacity for an existing run.

    Normal acceptance uses :func:`create_run`, which performs this operation in the same
    transaction as run creation. This public operation exists for repair/migration and is
    safe to retry: an existing reservation is returned without consuming another unit.
    """
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute(
            "SELECT actor_id, research_mode FROM runs WHERE run_id = ?", (run_id,),
        ).fetchone()
        if run is None:
            raise UnknownRunError(f"unknown run {run_id}")
        run_actor = run["actor_id"]
        if actor_id is not None and actor_id != run_actor:
            raise ReservationStateError("reservation actor does not match run actor")
        existing = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        if existing is not None:
            expected_chargeable = run["research_mode"] == "formal"
            if bool(existing["chargeable"]) != expected_chargeable:
                raise ReservationStateError(
                    "reservation chargeability does not match run research mode")
            return _reservation_dict(existing, applied=False)
        chargeable = run["research_mode"] == "formal"
        entitlement = (
            _entitlement_status(conn, run_actor)
            if chargeable else _sandbox_entitlement_status(conn, run_actor)
        )
        if entitlement["remaining"] <= 0:
            raise QuotaExceededError(
                entitlement, quota_kind="formal" if chargeable else "sandbox")
        now = _now()
        conn.execute(
            "INSERT INTO entitlement_reservations("
            "run_id, actor_id, chargeable, state, reserved_at) "
            "VALUES (?, ?, ?, 'reserved', ?)",
            (run_id, run_actor, int(chargeable), now),
        )
        row = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        return _reservation_dict(row, applied=True)


def settle_reservation(run_id: str) -> dict:
    """Settle one reservation; only formal/chargeable rows increment paid usage."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run is None:
            raise UnknownRunError(f"unknown run {run_id}")
        row = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        if row is None:
            raise ReservationStateError(f"run {run_id} has no entitlement reservation")
        if row["state"] == "settled":
            return _reservation_dict(row, applied=False)
        now = _now()
        if row["state"] == "released":
            # Doc 50 §3.3: the billable boundary is authoritative over an
            # earlier compensation. Two workers can legitimately hold one
            # run (the documented stale-claim requeue), and a loser that
            # fails closed releases the reservation while the winner is
            # still computing. When the winner then reaches its billable
            # artifact, settling must win — otherwise a run that owns
            # sealed evidence is stranded uncharged and its product read
            # stays withheld behind the settlement gate. Compensation is
            # valid only while no billable artifact exists; the released
            # timestamp is preserved so the reversal stays auditable.
            resettled = conn.execute(
                "UPDATE entitlement_reservations SET state = 'settled', "
                "settled_at = ? WHERE run_id = ? AND state = 'released'",
                (now, run_id),
            )
            if resettled.rowcount != 1:
                raise ReservationStateError(
                    f"reservation for run {run_id} could not be settled")
            if bool(row["chargeable"]):
                charged = conn.execute(
                    "UPDATE entitlement SET used = used + 1 WHERE actor_id = ?",
                    (row["actor_id"],),
                )
                if charged.rowcount != 1:
                    raise ReservationStateError(
                        "chargeable reservation has no provisioned entitlement")
            _record_event_in(conn, "reservation_settled_after_release", {
                "run_id": run_id,
                "released_at": row["released_at"],
                "settled_at": now,
            }, tenant_id=row["actor_id"], user_id=row["actor_id"])
            settled_row = conn.execute(
                "SELECT * FROM entitlement_reservations WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            return _reservation_dict(settled_row, applied=True)
        cur = conn.execute(
            "UPDATE entitlement_reservations SET state = 'settled', settled_at = ? "
            "WHERE run_id = ? AND state = 'reserved'", (now, run_id),
        )
        if cur.rowcount != 1:
            raise ReservationStateError(f"reservation for run {run_id} could not be settled")
        if bool(row["chargeable"]):
            charged = conn.execute(
                "UPDATE entitlement SET used = used + 1 WHERE actor_id = ?",
                (row["actor_id"],),
            )
            if charged.rowcount != 1:
                raise ReservationStateError(
                    "chargeable reservation has no provisioned entitlement")
        settled = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        return _reservation_dict(settled, applied=True)


def release_reservation(run_id: str) -> dict:
    """Atomically and idempotently release an uncharged run reservation."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run is None:
            raise UnknownRunError(f"unknown run {run_id}")
        row = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        if row is None:
            raise ReservationStateError(f"run {run_id} has no entitlement reservation")
        if row["state"] == "released":
            return _reservation_dict(row, applied=False)
        if row["state"] == "settled":
            raise ReservationStateError(f"reservation for run {run_id} is already settled")
        now = _now()
        cur = conn.execute(
            "UPDATE entitlement_reservations SET state = 'released', released_at = ? "
            "WHERE run_id = ? AND state = 'reserved'", (now, run_id),
        )
        if cur.rowcount != 1:
            raise ReservationStateError(f"reservation for run {run_id} could not be released")
        released = conn.execute(
            "SELECT * FROM entitlement_reservations WHERE run_id = ?", (run_id,),
        ).fetchone()
        return _reservation_dict(released, applied=True)


def decrement_at_seal(run_id: str) -> bool:
    """Compatibility alias during migration; the argument is now strictly a run id."""
    return settle_reservation(run_id)["quota_charged"]


# ------------------------------------------------------------------ events

def _event_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "ts": row["ts"],
        "actor_id": row["actor_id"],
        "user_id": row["user_id"],
        "type": row["type"],
        "payload": json.loads(row["payload_json"]),
    }


_RESERVED_EVENT_IDENTITY_KEYS = frozenset({"tenantid", "userid", "actorid"})


def _is_reserved_event_identity_key(key: object) -> bool:
    """Recognize common case and separator aliases for ownership fields.

    JSON clients can spell the same identity claim as ``Tenant_ID``, ``tenantId``,
    or ``tenant-id``.  Normalizing ASCII letters and separators before comparison
    prevents those presentation variants from surviving as caller-controlled identity
    metadata.  Non-string mapping keys are not identity aliases and are left for the
    normal JSON encoder contract.
    """
    if not isinstance(key, str):
        return False
    normalized = "".join(character for character in key.casefold() if character.isalnum())
    return normalized in _RESERVED_EVENT_IDENTITY_KEYS


def _sanitize_event_payload(value):
    """Remove caller-supplied ownership claims at every payload nesting level.

    Event ownership comes exclusively from the server-resolved principal columns.  A
    recursive filter also prevents a later analytics export from accidentally treating a
    nested client claim as authoritative identity metadata.
    """
    if isinstance(value, dict):
        return {
            key: _sanitize_event_payload(item)
            for key, item in value.items()
            if not _is_reserved_event_identity_key(key)
        }
    if isinstance(value, list):
        return [_sanitize_event_payload(item) for item in value]
    return value


def _record_event_in(conn: sqlite3.Connection, event_type: str, payload: dict,
                     *, tenant_id: str, user_id: str) -> None:
    """Append a redacted audit event inside the caller's open transaction.

    Mutations and their audit trail commit or roll back together: an event
    insertion failure aborts the surrounding business mutation.
    """
    safe_payload = _sanitize_event_payload(payload)
    conn.execute(
        "INSERT INTO events(ts, actor_id, user_id, type, payload_json) "
        "VALUES (?,?,?,?,?)",
        (_now(), tenant_id, user_id, event_type, json.dumps(safe_payload)),
    )


def record_event(event_type: str, payload: dict, actor_id: str | None = None,
                 *, tenant_id: str | None = None,
                 user_id: str | None = None) -> None:
    """Record a principal-owned event; ``actor_id`` is the legacy tenant form."""
    tenant, user = _ownership_ids(
        actor_id=actor_id, tenant_id=tenant_id, user_id=user_id)
    with connect() as conn:
        _record_event_in(conn, event_type, payload, tenant_id=tenant, user_id=user)


def list_events_for_principal(tenant_id: str, user_id: str,
                              event_type: str | None = None) -> list[dict]:
    q = "SELECT * FROM events WHERE actor_id = ? AND user_id = ?"
    params: list[str] = [tenant_id, user_id]
    if event_type:
        q += " AND type = ?"
        params.append(event_type)
    q += " ORDER BY id"
    with connect() as conn:
        rows = conn.execute(q, tuple(params)).fetchall()
    return [_event_dict(row) for row in rows]


def list_events(event_type: str | None = None) -> list[dict]:
    """Legacy trusted event audit; request handlers should use principal scoping."""
    q = "SELECT * FROM events" + (" WHERE type = ?" if event_type else "") + " ORDER BY id"
    with connect() as conn:
        rows = conn.execute(q, (event_type,) if event_type else ()).fetchall()
    return [_event_dict(row) for row in rows]


# ------------------------------------------------ licensed market-data acquisition jobs

def _idempotency_key_sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _market_data_acquisition_dict(row: sqlite3.Row) -> dict:
    value = dict(row)
    value["history"] = json.loads(value.pop("history_json"))
    value["instrument"] = (
        json.loads(value.pop("instrument_json"))
        if value.get("instrument_json") else None
    )
    value.pop("instrument_json", None)
    value["calendar_validation"] = (
        json.loads(value.pop("calendar_json"))
        if value.get("calendar_json") else None
    )
    value.pop("calendar_json", None)
    value["error"] = (
        json.loads(value.pop("error_json"))
        if value.get("error_json") else None
    )
    value.pop("error_json", None)
    return value


def create_or_get_market_data_acquisition(
    *, provider_id: str, request_sha256: str, idempotency_key: str,
    symbol: str, requested_start: str, requested_end: str,
    adjustment_mode: str, confirmed_instrument_id: str, display_name: str,
    tenant_id: str, user_id: str,
) -> tuple[dict, bool]:
    """Persist one principal-scoped canonical request exactly once.

    The raw idempotency token is never stored. A repeated canonical request returns the
    original job even when the caller supplied a new retry token; a retry token already
    bound to different parameters fails closed.
    """
    tenant, user = _ownership_ids(tenant_id=tenant_id, user_id=user_id)
    if not idempotency_key:
        raise ValueError("idempotency_key must be non-empty")
    if not request_sha256.startswith("sha256:") or len(request_sha256) != 71:
        raise ValueError("request_sha256 must be a sha256 digest")
    token_sha = _idempotency_key_sha256(idempotency_key)
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        binding = conn.execute(
            "SELECT request_sha256, acquisition_id "
            "FROM market_data_idempotency_keys "
            "WHERE actor_id = ? AND user_id = ? AND idempotency_key_sha256 = ?",
            (tenant, user, token_sha),
        ).fetchone()
        if binding is not None:
            if binding["request_sha256"] != request_sha256:
                raise MarketDataIdempotencyConflict(
                    "idempotency key is already bound to another request"
                )
            by_token = conn.execute(
                "SELECT * FROM market_data_acquisitions "
                "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
                (binding["acquisition_id"], tenant, user),
            ).fetchone()
            if by_token is None:
                raise MarketDataAcquisitionStateError(
                    "idempotency binding references an unavailable acquisition"
                )
            return _market_data_acquisition_dict(by_token), False
        # Additive migration path for jobs written before the multi-key binding table
        # existed. The original digest remains on the job, so preserve its semantics
        # and backfill the durable binding inside this transaction.
        legacy_by_token = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE actor_id = ? AND user_id = ? AND idempotency_key_sha256 = ?",
            (tenant, user, token_sha),
        ).fetchone()
        if legacy_by_token is not None:
            if legacy_by_token["request_sha256"] != request_sha256:
                raise MarketDataIdempotencyConflict(
                    "idempotency key is already bound to another request"
                )
            conn.execute(
                "INSERT INTO market_data_idempotency_keys("
                "actor_id, user_id, idempotency_key_sha256, request_sha256, "
                "acquisition_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tenant, user, token_sha, request_sha256,
                    legacy_by_token["acquisition_id"], now,
                ),
            )
            return _market_data_acquisition_dict(legacy_by_token), False
        by_request = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE actor_id = ? AND user_id = ? AND request_sha256 = ?",
            (tenant, user, request_sha256),
        ).fetchone()
        if by_request is not None:
            conn.execute(
                "INSERT INTO market_data_idempotency_keys("
                "actor_id, user_id, idempotency_key_sha256, request_sha256, "
                "acquisition_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tenant, user, token_sha, request_sha256,
                    by_request["acquisition_id"], now,
                ),
            )
            return _market_data_acquisition_dict(by_request), False
        acquisition_id = f"acq_{uuid.uuid4().hex}"
        history = [["queued", now]]
        conn.execute(
            "INSERT INTO market_data_acquisitions("
            "acquisition_id, actor_id, user_id, provider_id, request_sha256, "
            "idempotency_key_sha256, symbol, requested_start, requested_end, "
            "adjustment_mode, confirmed_instrument_id, display_name, status, history_json, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)",
            (
                acquisition_id, tenant, user, provider_id, request_sha256, token_sha,
                symbol, requested_start, requested_end, adjustment_mode,
                confirmed_instrument_id, display_name, json.dumps(history), now, now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM market_data_acquisitions WHERE acquisition_id = ?",
            (acquisition_id,),
        ).fetchone()
        conn.execute(
            "INSERT INTO market_data_idempotency_keys("
            "actor_id, user_id, idempotency_key_sha256, request_sha256, "
            "acquisition_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (tenant, user, token_sha, request_sha256, acquisition_id, now),
        )
    if row is None:  # pragma: no cover - same-transaction insert/read invariant
        raise RuntimeError("market-data acquisition was not persisted")
    return _market_data_acquisition_dict(row), True


def get_market_data_acquisition_for_principal(
    acquisition_id: str, tenant_id: str, user_id: str,
) -> dict | None:
    """Read one acquisition only when both tenant and user match in SQL."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
            (acquisition_id, tenant_id, user_id),
        ).fetchone()
    return _market_data_acquisition_dict(row) if row else None


def get_market_data_acquisition_for_dataset(
    dataset_id: str, tenant_id: str, user_id: str,
) -> dict | None:
    """The sealed acquisition row that produced one licensed dataset, or None.

    Read-only Stop F4b accessor: the corrected execution chain derives its
    exchange-calendar identity from the acquisition's stored validation
    receipt, and a dataset without one fails closed at execution time.
    Principal-scoped in SQL like every other acquisition read.
    """
    if not isinstance(dataset_id, str) or not dataset_id:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE dataset_id = ? AND actor_id = ? AND user_id = ?",
            (dataset_id, tenant_id, user_id),
        ).fetchone()
    return _market_data_acquisition_dict(row) if row else None


def transition_market_data_acquisition_for_principal(
    acquisition_id: str, status: str, *, tenant_id: str, user_id: str,
    instrument: dict | None = None, calendar_validation: dict | None = None,
    dataset_id: str | None = None, error: dict | None = None,
) -> dict:
    """Move a licensed-data job through the closed persisted state machine."""
    if status not in MARKET_DATA_ACQUISITION_STATES:
        raise ValueError("unsupported market-data acquisition status")
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
            (acquisition_id, tenant_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("market-data acquisition is unavailable")
        current = row["status"]
        if status not in _MARKET_DATA_ACQUISITION_TRANSITIONS[current]:
            raise MarketDataAcquisitionStateError(
                f"cannot transition market-data acquisition from {current} to {status}"
            )
        persisted_instrument = (
            json.dumps(instrument, sort_keys=True) if instrument is not None
            else row["instrument_json"]
        )
        persisted_calendar = (
            json.dumps(calendar_validation, sort_keys=True)
            if calendar_validation is not None else row["calendar_json"]
        )
        persisted_dataset_id = dataset_id or row["dataset_id"]
        persisted_error = json.dumps(error, sort_keys=True) if error is not None else None
        if status == "fetching" and not persisted_instrument:
            raise MarketDataAcquisitionStateError(
                "fetching requires a resolved canonical instrument"
            )
        if status == "validated" and not persisted_calendar:
            raise MarketDataAcquisitionStateError(
                "validated requires an exchange-calendar receipt"
            )
        if status == "sealed" and not persisted_dataset_id:
            raise MarketDataAcquisitionStateError("sealed requires a dataset id")
        if status == "failed" and not persisted_error:
            raise MarketDataAcquisitionStateError("failed requires a safe error receipt")
        history = json.loads(row["history_json"])
        history.append([status, now])
        conn.execute(
            "UPDATE market_data_acquisitions SET status = ?, history_json = ?, "
            "instrument_json = ?, calendar_json = ?, dataset_id = ?, error_json = ?, "
            "updated_at = ? WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
            (
                status, json.dumps(history), persisted_instrument, persisted_calendar,
                persisted_dataset_id, persisted_error, now,
                acquisition_id, tenant_id, user_id,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM market_data_acquisitions "
            "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
            (acquisition_id, tenant_id, user_id),
        ).fetchone()
    if updated is None:  # pragma: no cover - same-transaction ownership invariant
        raise RuntimeError("market-data acquisition transition was not persisted")
    return _market_data_acquisition_dict(updated)


def record_market_data_usage(
    *, provider_id: str, operation: str, symbol: str,
    provider_request_count: int, cache_hit: bool, outcome: str,
    tenant_id: str, user_id: str, acquisition_id: str | None = None,
    requested_start: str | None = None, requested_end: str | None = None,
    error_code: str | None = None,
) -> None:
    """Record only bounded billing/audit metadata, never payloads or credentials."""
    if operation not in {
        "instrument_resolve", "daily_fetch", "acquisition_reuse", "calendar_gate",
    }:
        raise ValueError("unsupported market-data usage operation")
    if outcome not in {"succeeded", "failed", "reused"}:
        raise ValueError("unsupported market-data usage outcome")
    if isinstance(provider_request_count, bool) or provider_request_count < 0:
        raise ValueError("provider_request_count must be non-negative")
    tenant, user = _ownership_ids(tenant_id=tenant_id, user_id=user_id)
    with connect() as conn:
        conn.execute(
            "INSERT INTO market_data_usage_events("
            "ts, acquisition_id, actor_id, user_id, provider_id, operation, symbol, "
            "requested_start, requested_end, provider_request_count, cache_hit, outcome, "
            "error_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _now(), acquisition_id, tenant, user, provider_id, operation, symbol,
                requested_start, requested_end, provider_request_count,
                int(cache_hit), outcome, error_code,
            ),
        )


def list_market_data_usage_for_principal(
    tenant_id: str, user_id: str, *, acquisition_id: str | None = None,
) -> list[dict]:
    """Trusted/test audit lookup with the same exact principal scope as acquisitions."""
    q = (
        "SELECT * FROM market_data_usage_events WHERE actor_id = ? AND user_id = ?"
    )
    params: list[str] = [tenant_id, user_id]
    if acquisition_id is not None:
        q += " AND acquisition_id = ?"
        params.append(acquisition_id)
    q += " ORDER BY id"
    with connect() as conn:
        rows = conn.execute(q, tuple(params)).fetchall()
    values = []
    for row in rows:
        value = dict(row)
        value["cache_hit"] = bool(value["cache_hit"])
        values.append(value)
    return values


# ------------------------------------------------------------------ Gate 4 datasets

def create_dataset_import(import_id: str, inspection: dict,
                          actor_id: str | None = None, *,
                          tenant_id: str | None = None,
                          user_id: str | None = None,
                          origin: str = IMPORT_ORIGIN_USER_UPLOAD) -> dict:
    """Create an inspected import owned by one tenant/user principal.

    ``actor_id`` without ``user_id`` is the legacy single-user tenant form.
    ``origin`` separates a reader's upload from a row the bundle seeder is
    holding while it seals; only the former is the reader's to see or discard.
    """
    tenant, user = _ownership_ids(
        actor_id=actor_id, tenant_id=tenant_id, user_id=user_id)
    now = _now()
    with connect() as conn:
        conn.execute(
            "INSERT INTO dataset_imports(import_id, actor_id, user_id, status, source_format, "
            "source_size, source_sha256, row_count, columns_json, inspection_json, "
            "created_at, updated_at, origin) "
            "VALUES (?, ?, ?, 'inspected', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (import_id, tenant, user, inspection["source_format"], inspection["source_size"],
             inspection["source_sha256"], inspection["row_count"],
             json.dumps(inspection["columns"]), json.dumps(inspection), now, now,
             origin),
        )
    return get_dataset_import_for_principal(import_id, tenant, user)


def _dataset_import_dict(row: sqlite3.Row) -> dict:
    value = dict(row)
    value["columns"] = json.loads(value.pop("columns_json"))
    value["inspection"] = json.loads(value.pop("inspection_json"))
    validation_json = value.pop("validation_json", None)
    value["validation"] = json.loads(validation_json) if validation_json else None
    value["error"] = json.loads(value["error_json"]) if value.get("error_json") else None
    value.pop("error_json", None)
    return value


def get_dataset_import_for_principal(import_id: str, tenant_id: str,
                                     user_id: str) -> dict | None:
    """Return an import only when tenant and user ownership match in SQL."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM dataset_imports "
            "WHERE import_id = ? AND actor_id = ? AND user_id = ?",
            (import_id, tenant_id, user_id),
        ).fetchone()
    return _dataset_import_dict(row) if row else None


def get_dataset_import(import_id: str, actor_id: str = MOCK_ACTOR) -> dict | None:
    """Legacy tenant-only lookup retained for the single-user local API."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM dataset_imports WHERE import_id = ? AND actor_id = ?",
            (import_id, actor_id),
        ).fetchone()
    return _dataset_import_dict(row) if row else None


def save_dataset_validation_for_principal(import_id: str, validation: dict,
                                          tenant_id: str, user_id: str) -> dict:
    """Persist validation only when tenant and user ownership match in SQL."""
    with connect() as conn:
        updated = conn.execute(
            "UPDATE dataset_imports SET validation_json = ?, updated_at = ? "
            "WHERE import_id = ? AND actor_id = ? AND user_id = ? "
            "AND status = 'inspected'",
            (json.dumps(validation), _now(), import_id, tenant_id, user_id),
        ).rowcount
    if updated != 1:
        raise ValueError("dataset import is not available for validation")
    result = get_dataset_import_for_principal(import_id, tenant_id, user_id)
    if result is None:  # defensive: update and read occur in separate connections
        raise ValueError("dataset import ownership changed during validation")
    return result


def save_dataset_validation(import_id: str, validation: dict,
                            actor_id: str = MOCK_ACTOR) -> dict:
    """Legacy single-user validation wrapper."""
    return save_dataset_validation_for_principal(
        import_id, validation, actor_id, actor_id)


def reject_dataset_import(import_id: str, error: dict,
                          actor_id: str = MOCK_ACTOR) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE dataset_imports SET status = 'rejected', error_json = ?, updated_at = ? "
            "WHERE import_id = ? AND actor_id = ? AND status = 'inspected'",
            (json.dumps(error), _now(), import_id, actor_id),
        )


def reject_dataset_import_for_principal(import_id: str, error: dict,
                                        tenant_id: str, user_id: str) -> bool:
    """Reject only the requesting principal's still-inspected import."""
    with connect() as conn:
        updated = conn.execute(
            "UPDATE dataset_imports SET status = 'rejected', error_json = ?, "
            "updated_at = ? WHERE import_id = ? AND actor_id = ? AND user_id = ? "
            "AND status = 'inspected'",
            (json.dumps(error), _now(), import_id, tenant_id, user_id),
        ).rowcount
    return updated == 1


def discard_dataset_import_for_principal(import_id: str, tenant_id: str,
                                         user_id: str) -> bool:
    """Settle the principal's own import AND scrub the preview of their rows.

    Rejecting alone leaves ``inspection_json`` in place -- a sample of the
    reader's actual rows, plus their column headers -- while the product tells
    them the upload was removed. ``expire_dataset_import`` already treats those
    two columns as sensitive and wipes them, so a discard the reader explicitly
    asked for must not be less thorough than a sweep nobody has scheduled.

    Scoped to ``status = 'inspected'``: a sealed import's inspection is part of a
    dataset's provenance and is not this route's to erase.
    """
    error = {
        "code": "IMPORT_DISCARDED",
        "severity": "info",
        "message": "Discarded by the workspace owner before sealing.",
    }
    with connect() as conn:
        updated = conn.execute(
            "UPDATE dataset_imports SET status = 'rejected', columns_json = '[]', "
            "inspection_json = '{}', validation_json = NULL, error_json = ?, "
            "updated_at = ? WHERE import_id = ? AND actor_id = ? AND user_id = ? "
            "AND status = 'inspected'",
            (json.dumps(error), _now(), import_id, tenant_id, user_id),
        ).rowcount
    return updated == 1


def list_open_dataset_imports_for_principal(tenant_id: str,
                                            user_id: str) -> list[dict]:
    """Uploads this principal is holding in quarantine, oldest first.

    These are exactly the rows ``count_open_dataset_imports`` bounds. Until this
    existed, the web app tracked one upload in local component state, so a reload
    stranded every earlier one: still counted against the cap, still occupying the
    shared volume, and with no identifier left anywhere the reader could reach.
    A control that says "discard one" needs something to point at.

    Bundle-seed rows are excluded and must stay excluded. They sit in the same
    'inspected' state for the ~140ms it takes to seal one series, so listing them
    offered the reader a Discard button that silently destroyed a licensed CC BY
    series, under copy ("nothing here has been added to your library", "uploaded
    …") that is false for a row the reader never uploaded.
    """
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM dataset_imports "
            "WHERE actor_id = ? AND user_id = ? AND status = 'inspected' "
            "AND (origin IS NULL OR origin != ?) "
            "ORDER BY created_at, import_id",
            (tenant_id, user_id, IMPORT_ORIGIN_BUNDLE_SEED),
        ).fetchall()
    return [_dataset_import_dict(row) for row in rows]


def list_expired_dataset_imports(cutoff: str,
                                 actor_id: str = MOCK_ACTOR) -> list[dict]:
    """Return only the identifiers needed to retire stale quarantine records."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT import_id, status, updated_at FROM dataset_imports "
            "WHERE actor_id = ? AND status IN ('inspected', 'rejected') "
            "AND updated_at <= ? "
            "AND (columns_json != '[]' OR inspection_json != '{}' "
            "OR validation_json IS NOT NULL) "
            "ORDER BY updated_at, import_id",
            (actor_id, cutoff),
        ).fetchall()
    return [dict(row) for row in rows]


def list_dataset_import_ids() -> set[str]:
    """Return all known import ids so orphan cleanup cannot cross actor boundaries."""
    with connect() as conn:
        rows = conn.execute("SELECT import_id FROM dataset_imports").fetchall()
    return {str(row["import_id"]) for row in rows}


def expire_dataset_import(import_id: str, actor_id: str = MOCK_ACTOR) -> bool:
    """Reduce an abandoned or failed import to a non-sensitive terminal receipt."""
    error = {
        "code": "QUARANTINE_TTL_EXPIRED",
        "message": "The local quarantined upload expired before sealing.",
    }
    with connect() as conn:
        updated = conn.execute(
            "UPDATE dataset_imports SET status = 'rejected', columns_json = '[]', "
            "inspection_json = '{}', validation_json = NULL, error_json = ?, "
            "updated_at = ? WHERE import_id = ? AND actor_id = ? "
            "AND status IN ('inspected', 'rejected')",
            (json.dumps(error), _now(), import_id, actor_id),
        ).rowcount
    return updated == 1


def register_dataset_for_principal(import_id: str, *, dataset_id: str,
                                   display_name: str, symbol: str,
                                   dataset_manifest_sha256: str,
                                   snapshot_id: str, snapshot_sha256: str,
                                   source_sha256: str, quality: dict,
                                   relative_storage_key: str,
                                   tenant_id: str, user_id: str,
                                   bundle_symbol: str | None = None) -> dict:
    """Seal one import for the same tenant/user principal in one transaction.

    ``bundle_symbol`` is the bundled ticker this row IS, and only
    ``market_bundle.seed_symbol`` ever passes it: no request model carries the field, so a
    reader cannot claim their upload is the licensed series. A second sealed row for the
    same principal and ticker raises ``sqlite3.IntegrityError`` from the partial unique
    index rather than quietly duplicating -- the INSERT is already inside BEGIN IMMEDIATE,
    so two racing seeders are serialized and the loser loses loudly.
    """
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        source = conn.execute(
            "SELECT status FROM dataset_imports "
            "WHERE import_id = ? AND actor_id = ? AND user_id = ?",
            (import_id, tenant_id, user_id),
        ).fetchone()
        if source is None or source["status"] != "inspected":
            raise ValueError("dataset import is not in an inspectable state")
        conn.execute(
            "INSERT INTO datasets(dataset_id, actor_id, user_id, display_name, symbol, status, "
            "dataset_manifest_sha256, snapshot_id, snapshot_sha256, source_sha256, "
            "bundle_symbol, row_count, coverage_start, coverage_end, quality_json, "
            "relative_storage_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'sealed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (dataset_id, tenant_id, user_id, display_name, symbol, dataset_manifest_sha256,
             snapshot_id, snapshot_sha256, source_sha256, bundle_symbol,
             quality["row_count"],
             quality["coverage"]["start"], quality["coverage"]["end"],
             json.dumps(quality), relative_storage_key, now),
        )
        conn.execute(
            "UPDATE dataset_imports SET status = 'sealed', dataset_id = ?, "
            "columns_json = '[]', inspection_json = '{}', validation_json = NULL, "
            "error_json = NULL, updated_at = ? "
            "WHERE import_id = ? AND actor_id = ? AND user_id = ?",
            (dataset_id, now, import_id, tenant_id, user_id),
        )
    result = get_dataset_for_principal(dataset_id, tenant_id, user_id)
    if result is None:
        raise ValueError("sealed dataset ownership could not be verified")
    return result


def register_licensed_dataset_for_principal(
    *, dataset_id: str, display_name: str, symbol: str,
    dataset_manifest_sha256: str, snapshot_id: str, snapshot_sha256: str,
    provider_payload_sha256: str, quality: dict, relative_storage_key: str,
    tenant_id: str, user_id: str, acquisition_id: str | None = None,
) -> dict:
    """Register a DatasetManifestV2 seal without inventing a BYOD import receipt.

    Licensed acquisition has its own provider/rights receipt and never passes through
    the upload quarantine state machine.  The existing dataset registry remains the
    actor-owned lookup boundary used by the worker. When ``acquisition_id`` is supplied,
    dataset registration and the job's terminal ``sealed`` transition commit in the
    same SQLite transaction so a failed job can never expose a registered dataset.
    """
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        acquisition = None
        if acquisition_id is not None:
            acquisition = conn.execute(
                "SELECT status, history_json FROM market_data_acquisitions "
                "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ?",
                (acquisition_id, tenant_id, user_id),
            ).fetchone()
            if acquisition is None or acquisition["status"] != "validated":
                raise MarketDataAcquisitionStateError(
                    "licensed dataset registration requires a validated acquisition"
                )
        conn.execute(
            "INSERT INTO datasets(dataset_id, actor_id, user_id, display_name, symbol, status, "
            "dataset_manifest_sha256, snapshot_id, snapshot_sha256, source_sha256, "
            "row_count, coverage_start, coverage_end, quality_json, relative_storage_key, "
            "created_at) VALUES (?, ?, ?, ?, ?, 'sealed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dataset_id, tenant_id, user_id, display_name, symbol,
                dataset_manifest_sha256.removeprefix("sha256:"),
                snapshot_id, snapshot_sha256,
                provider_payload_sha256.removeprefix("sha256:"),
                quality["row_count"], quality["coverage"]["start"],
                quality["coverage"]["end"], json.dumps(quality),
                relative_storage_key, now,
            ),
        )
        if acquisition_id is not None:
            history = json.loads(acquisition["history_json"])
            history.append(["sealed", now])
            updated = conn.execute(
                "UPDATE market_data_acquisitions SET status = 'sealed', "
                "history_json = ?, dataset_id = ?, error_json = NULL, updated_at = ? "
                "WHERE acquisition_id = ? AND actor_id = ? AND user_id = ? "
                "AND status = 'validated'",
                (
                    json.dumps(history), dataset_id, now, acquisition_id,
                    tenant_id, user_id,
                ),
            ).rowcount
            if updated != 1:
                raise MarketDataAcquisitionStateError(
                    "licensed acquisition could not be completed atomically"
                )
    result = get_dataset_for_principal(dataset_id, tenant_id, user_id)
    if result is None:
        raise ValueError("licensed dataset ownership could not be verified")
    return result


def register_dataset(import_id: str, *, dataset_id: str, display_name: str,
                     symbol: str, dataset_manifest_sha256: str,
                     snapshot_id: str, snapshot_sha256: str, source_sha256: str,
                     quality: dict, relative_storage_key: str,
                     actor_id: str | None = None, tenant_id: str | None = None,
                     user_id: str | None = None) -> dict:
    """Legacy-compatible wrapper; principal callers should use the strict variant."""
    tenant, user = _ownership_ids(
        actor_id=actor_id, tenant_id=tenant_id, user_id=user_id)
    return register_dataset_for_principal(
        import_id,
        dataset_id=dataset_id,
        display_name=display_name,
        symbol=symbol,
        dataset_manifest_sha256=dataset_manifest_sha256,
        snapshot_id=snapshot_id,
        snapshot_sha256=snapshot_sha256,
        source_sha256=source_sha256,
        quality=quality,
        relative_storage_key=relative_storage_key,
        tenant_id=tenant,
        user_id=user,
    )


def _dataset_dict(row: sqlite3.Row) -> dict:
    value = dict(row)
    value["quality"] = json.loads(value.pop("quality_json"))
    value["dataset_manifest_sha256"] = "sha256:" + value["dataset_manifest_sha256"]
    value["snapshot_sha256"] = value["snapshot_sha256"]
    value["coverage"] = {
        "start": value.pop("coverage_start"), "end": value.pop("coverage_end")}
    return value


def get_dataset_for_principal(dataset_id: str, tenant_id: str,
                              user_id: str) -> dict | None:
    """Return a sealed dataset only when tenant and user match in SQL."""
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM datasets WHERE dataset_id = ? AND actor_id = ? "
            "AND user_id = ? AND status = 'sealed'",
            (dataset_id, tenant_id, user_id),
        ).fetchone()
    return _dataset_dict(row) if row else None


def get_dataset_internal(dataset_id: str, tenant_id: str | None = None,
                         user_id: str | None = None) -> dict | None:
    """Trusted worker/admin dataset lookup.

    Workers should pass the ownership copied from the already trusted run row. With no
    ownership arguments this is an unscoped globally-unique-id lookup for recovery and
    migration only.
    """
    q = "SELECT * FROM datasets WHERE dataset_id = ? AND status = 'sealed'"
    params: list[str] = [dataset_id]
    if tenant_id is not None:
        q += " AND actor_id = ?"
        params.append(tenant_id)
    if user_id is not None:
        if tenant_id is None:
            raise ValueError("tenant_id is required when user_id is supplied")
        q += " AND user_id = ?"
        params.append(user_id)
    with connect() as conn:
        row = conn.execute(q, tuple(params)).fetchone()
    return _dataset_dict(row) if row else None


def get_dataset(dataset_id: str, actor_id: str = MOCK_ACTOR) -> dict | None:
    """Legacy tenant-only lookup retained for current worker/tests."""
    return get_dataset_internal(dataset_id, actor_id)


def list_datasets_for_principal(tenant_id: str, user_id: str) -> list[dict]:
    """List only sealed datasets owned by the requesting tenant and user."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM datasets WHERE actor_id = ? AND user_id = ? "
            "AND status = 'sealed' ORDER BY created_at DESC",
            (tenant_id, user_id),
        ).fetchall()
    return [_dataset_dict(row) for row in rows]


def list_datasets(actor_id: str = MOCK_ACTOR) -> list[dict]:
    """Legacy tenant-only listing retained for the local single-user API."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM datasets WHERE actor_id = ? AND status = 'sealed' "
            "ORDER BY created_at DESC", (actor_id,),
        ).fetchall()
    return [_dataset_dict(row) for row in rows]


def dataset_directory(dataset: dict) -> Path:
    relative = Path(dataset["relative_storage_key"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("unsafe dataset storage key")
    root = (var_dir() / "datasets").resolve()
    candidate = (root / relative).resolve()
    if candidate.parent.parent != root:
        raise ValueError("dataset storage key escapes the dataset root")
    return candidate


# ------------------------------------------------- release activation (Gate E §9)
#
# The corrected-release control plane is additive and inert: no startup path
# writes a release row, registration never affects queue routing, and the one
# PREPARED -> ACTIVE transaction below is built and tested here but executed
# against a real store only by the separately reviewed Stop F release decision.
# All durable state lives in the four dedicated release tables; the runs table
# and every legacy projection are untouched by construction.

def _release_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["release_tuple"] = json.loads(d["release_tuple_json"])
    d["component_hashes"] = json.loads(d["component_hashes_json"])
    d["required_capabilities"] = json.loads(d["required_capabilities_json"])
    return d


def _active_release_in(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """The single ACTIVE release row, or None while the control plane is inert.

    ``release_activations_single_active`` makes multiplicity impossible at the
    storage level, so ``fetchone`` is exact, not merely conventional.
    """
    return conn.execute(
        "SELECT * FROM release_activations WHERE release_state = ?",
        (RELEASE_STATE_ACTIVE,),
    ).fetchone()


def _release_row_in(conn: sqlite3.Connection, release_row_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM release_activations WHERE release_row_id = ?",
        (release_row_id,),
    ).fetchone()
    if row is None:
        raise UnknownReleaseError(
            f"release row {release_row_id!r} does not exist")
    return row


def get_release(release_row_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM release_activations WHERE release_row_id = ?",
            (release_row_id,),
        ).fetchone()
    return _release_dict(row) if row else None


def get_run_release_binding(run_id: str) -> dict | None:
    """The immutable release binding stamped at acceptance, or None.

    Read-only accessor for the doc 47 §A3 product-read law: every v3 read
    must bind the sealed evidence to the run's recorded release identity.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM run_release_bindings WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        return None
    binding = dict(row)
    binding["release_tuple"] = json.loads(binding["release_tuple_json"])
    binding["accepted_run"] = json.loads(binding["accepted_run_json"])
    binding["capability_state"] = json.loads(binding["capability_state_json"])
    return binding


def get_release_activation_receipt(release_row_id: str) -> dict | None:
    """The immutable activation receipt for one release row, or None.

    At most one receipt can exist (UNIQUE on release_row_id); it survives a
    later rollback, so historical bindings stay auditable (§A3).
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM release_activation_receipts "
            "WHERE release_row_id = ?",
            (release_row_id,),
        ).fetchone()
    if row is None:
        return None
    receipt = dict(row)
    receipt["receipt"] = json.loads(receipt["receipt_json"])
    return receipt


def assemble_accepted_run_envelope(run_id: str) -> dict:
    """Assemble the closed nine-field accepted-run envelope for one run.

    Read-only (doc 47 §A3/F0): the envelope the v3 resolver binds a sealed
    manifest against is composed at read time from the server-held run row
    and its confirmation receipt — never from a caller document and never by
    reshaping the stored insert-only binding. Raises when the run or its
    receipt is missing; the restatement-hash law is re-checked here so an
    inconsistent store fails closed before any resolver runs.
    """
    with connect() as conn:
        run = conn.execute(
            "SELECT run_id, actor_id, spec_hash, spec_version, created_at, "
            "battery_profile, battery_profile_hash FROM runs "
            "WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        receipt = conn.execute(
            "SELECT restatement_text, restatement_hash "
            "FROM confirmation_receipts WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    if run is None:
        raise UnknownRunError(f"unknown run {run_id}")
    if receipt is None:
        raise ReleaseStateError(
            "the run has no confirmation receipt; no accepted-run envelope "
            "can be assembled")
    restatement = receipt["restatement_text"]
    expected_hash = hashlib.sha256(restatement.encode("utf-8")).hexdigest()
    if receipt["restatement_hash"] != expected_hash:
        raise ReleaseStateError(
            "the stored confirmation restatement fails its hash law; no "
            "accepted-run envelope can be assembled")
    return {
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "spec_hash": run["spec_hash"],
        "spec_version": run["spec_version"],
        "created_at": run["created_at"],
        "confirmation_restatement": restatement,
        "confirmation_receipt_hash": receipt["restatement_hash"],
        "battery_profile_id": run["battery_profile"],
        "battery_config_hash": run["battery_profile_hash"],
    }


CORRECTED_READ_EXPECTATION_COMPONENTS = (
    "plan_anchors", "financial_semantics", "metric_semantics",
    "calendars", "snapshots", "validation_plans",
)
_SNAPSHOT_DOCUMENT_KEYS = frozenset({
    "market_observations_version", "snapshot_sha256",
    "exchange_calendar_id", "exchange_calendar_version", "instruments",
})
_VALIDATION_PLAN_VIEW_KEYS = frozenset({
    "profile_id", "profile_hash", "plan_version", "validation_plan_hash",
    "full_plan_sha256", "spec_hash", "snapshot_sha256",
})
_PREFIXED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPECTATION_KEY_RE = re.compile(r"^[\x21-\x7e]{1,256}$")


def _canonical_document_json(value) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


def register_corrected_read_expectation(
    component: str, entry_key: str, document,
) -> dict:
    """Write-once registration of one corrected read-time expectation entry.

    Stop F2a (doc 47 §5.2): this store is the control-plane trusted source
    the v3 product read assembles its validator registry and plan-anchor
    mapping from. Entries are insert-only and each component enforces its
    key law here, so a stored entry can never disagree with its own key:

    - ``financial_semantics`` / ``metric_semantics``: the document IS the
      canonical digest string registered under the semantics version key;
    - ``calendars``: exactly ``{"sessions": [...]}``;
    - ``snapshots``: exactly the closed market-document shape whose
      embedded ``snapshot_sha256`` equals the entry key;
    - ``validation_plans``: exactly the closed seven-field plan view whose
      ``validation_plan_hash`` equals the entry key;
    - ``plan_anchors``: any closed document whose canonical hash equals
      the entry key (shape and identity are re-validated on every read by
      the dormant resolver; signature verification is the registration-time
      law of the trusted writer).

    Registration never affects routing or eligibility: the shipped
    presentation registry stays inert until the separately reviewed F2b
    re-seal, so a populated store still cannot serve a v3 view.
    """
    if component not in CORRECTED_READ_EXPECTATION_COMPONENTS:
        raise ValueError(
            f"unknown corrected read-expectation component {component!r}")
    if not isinstance(entry_key, str) or not _EXPECTATION_KEY_RE.fullmatch(
            entry_key):
        raise ValueError(
            "expectation entry keys must be printable ASCII identifiers")
    if component in ("financial_semantics", "metric_semantics"):
        if not isinstance(document, str) or not _PREFIXED_DIGEST_RE.fullmatch(
                document):
            raise ValueError(
                "semantics expectations must be canonical SHA-256 digests")
    elif component == "calendars":
        if not isinstance(document, dict) or set(document) != {"sessions"} \
                or not isinstance(document["sessions"], list) \
                or not all(isinstance(item, str)
                           for item in document["sessions"]):
            raise ValueError(
                "calendar expectations must be exactly a sessions date list")
    elif component == "snapshots":
        if not isinstance(document, dict) \
                or set(document) != _SNAPSHOT_DOCUMENT_KEYS:
            raise ValueError(
                "snapshot expectations must be the closed market-document "
                "shape")
        if not _PREFIXED_DIGEST_RE.fullmatch(entry_key) \
                or document.get("snapshot_sha256") != entry_key:
            raise ValueError(
                "a snapshot expectation must be keyed by its own embedded "
                "snapshot digest")
    elif component == "validation_plans":
        if not isinstance(document, dict) \
                or set(document) != _VALIDATION_PLAN_VIEW_KEYS:
            raise ValueError(
                "validation-plan expectations must be the closed "
                "seven-field plan view")
        if not _PREFIXED_DIGEST_RE.fullmatch(entry_key) \
                or document.get("validation_plan_hash") != entry_key:
            raise ValueError(
                "a validation-plan expectation must be keyed by its own "
                "plan self-hash")
    else:  # plan_anchors
        if not isinstance(document, dict):
            raise ValueError(
                "plan-anchor expectations must be document objects")
        if not _PREFIXED_DIGEST_RE.fullmatch(entry_key) \
                or _canonical_sha256(document) != entry_key:
            raise ValueError(
                "a plan-anchor expectation must be keyed by the canonical "
                "hash of its own bytes")
    body = _canonical_document_json(document)
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT OR IGNORE INTO corrected_read_expectation_documents("
            "component, entry_key, document_json, registered_at"
            ") VALUES (?, ?, ?, ?)",
            (component, entry_key, body, now),
        )
        row = conn.execute(
            "SELECT * FROM corrected_read_expectation_documents "
            "WHERE component = ? AND entry_key = ?",
            (component, entry_key),
        ).fetchone()
        if row is None or row["document_json"] != body:
            raise ValueError(
                "corrected read expectations are write-once and changed")
    return {
        "component": component,
        "entry_key": entry_key,
        "document": json.loads(row["document_json"]),
        "registered_at": row["registered_at"],
    }


def get_corrected_read_expectations(component: str) -> dict:
    """All registered entries for one component: {entry_key: document}.

    Read-only; an empty mapping simply means nothing is registered yet, and
    the read module refuses empty components by law (F0d), so an
    unpopulated store keeps every v3 read fail-closed.
    """
    if component not in CORRECTED_READ_EXPECTATION_COMPONENTS:
        raise ValueError(
            f"unknown corrected read-expectation component {component!r}")
    with connect() as conn:
        rows = conn.execute(
            "SELECT entry_key, document_json "
            "FROM corrected_read_expectation_documents WHERE component = ?",
            (component,),
        ).fetchall()
    return {
        row["entry_key"]: json.loads(row["document_json"]) for row in rows
    }


def get_active_release() -> dict | None:
    with connect() as conn:
        row = _active_release_in(conn)
    return _release_dict(row) if row else None


def prepare_release(
    *,
    release_id: str,
    required_worker_contract: str,
    presentation_contract_id: str,
    signer_key_id: str,
    release_tuple: dict,
    component_hashes: dict,
    required_capabilities: dict,
    prepared_by: str,
) -> dict:
    """Register one corrected release as PREPARED (§9). Routing-inert.

    Every tuple entry, component hash and capability expectation is caller
    data persisted verbatim; nothing here imports or names the dormant
    identifiers. At most one PREPARED row may exist per ``release_id``
    (partial unique index); re-preparing after an abort is legal.
    """
    registration = validate_release_registration(
        release_id=release_id,
        required_worker_contract=required_worker_contract,
        presentation_contract_id=presentation_contract_id,
        signer_key_id=signer_key_id,
        release_tuple=release_tuple,
        component_hashes=component_hashes,
        required_capabilities=required_capabilities,
        prepared_by=prepared_by,
        baseline_worker_contract=WORKER_RUNTIME_CONTRACT,
    )
    release_row_id = uuid.uuid4().hex
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO release_activations("
                "release_row_id, release_id, release_state, "
                "required_worker_contract, presentation_contract_id, "
                "signer_key_id, release_tuple_json, release_tuple_sha256, "
                "component_hashes_json, component_hashes_sha256, "
                "required_capabilities_json, required_capabilities_sha256, "
                "prepared_by, prepared_at, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (release_row_id, registration["release_id"],
                 RELEASE_STATE_PREPARED,
                 registration["required_worker_contract"],
                 registration["presentation_contract_id"],
                 registration["signer_key_id"],
                 registration["release_tuple_json"],
                 registration["release_tuple_sha256"],
                 registration["component_hashes_json"],
                 registration["component_hashes_sha256"],
                 registration["required_capabilities_json"],
                 registration["required_capabilities_sha256"],
                 registration["prepared_by"], now, now, now),
            )
        except sqlite3.IntegrityError as exc:
            # SQLite names the indexed column, not the partial index, in its
            # UNIQUE violation message.
            if "release_activations.release_id" in str(exc):
                raise ReleaseStateError(
                    f"a PREPARED release already exists for "
                    f"{registration['release_id']!r}"
                ) from exc
            raise
        _record_event_in(conn, "release_prepared", {
            "release_row_id": release_row_id,
            "release_id": registration["release_id"],
            "required_worker_contract":
                registration["required_worker_contract"],
            "release_tuple_sha256": registration["release_tuple_sha256"],
        }, tenant_id=registration["prepared_by"],
           user_id=registration["prepared_by"])
        row = _release_row_in(conn, release_row_id)
        return _release_dict(row)


def _record_capability_probe(
    release_row_id: str,
    capability: str,
    *,
    ready: bool,
    observed: dict,
    authority_id: str | None = None,
    key_id: str | None = None,
    not_ready_reason: str | None = None,
) -> dict:
    """PRIVATE raw probe writer (doc 47 §5.7: never a production entry point).

    Production readiness is derived exclusively by
    :func:`probe_release_capabilities`' closed evaluators; focused tests
    reach this writer only through the reviewed harness in ``tests/``. The
    stored document embeds the registered expectation for its capability, so
    the activation transaction can prove the probe was evaluated against the
    registration rather than a substituted expectation — and activation now
    re-evaluates the stored observation itself, so a caller-authored boolean
    alone can never satisfy it. Re-probing replaces the previous
    observation; probes on non-PREPARED releases are illegal.
    """
    if not ready and not (not_ready_reason or "").strip():
        raise ValueError("a not-ready probe must state its reason")
    if not isinstance(observed, dict):
        raise ValueError("the observed document must be a mapping")
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _release_row_in(conn, release_row_id)
        if row["release_state"] != RELEASE_STATE_PREPARED:
            raise ReleaseStateError(
                "capability probes may only be recorded for a PREPARED release")
        required = json.loads(row["required_capabilities_json"])
        if capability not in required:
            raise CapabilityProbeError(
                capability, "not declared by this release's registration")
        document = {
            "capability": capability,
            "expected": required[capability],
            "observed": observed,
        }
        observed_json = _release_canonical_json(document)
        conn.execute(
            "INSERT INTO release_capability_probes("
            "release_row_id, capability, ready, authority_id, key_id, "
            "observed_json, observed_sha256, not_ready_reason, observed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(release_row_id, capability) DO UPDATE SET "
            "ready = excluded.ready, authority_id = excluded.authority_id, "
            "key_id = excluded.key_id, observed_json = excluded.observed_json, "
            "observed_sha256 = excluded.observed_sha256, "
            "not_ready_reason = excluded.not_ready_reason, "
            "observed_at = excluded.observed_at",
            (release_row_id, capability, int(bool(ready)), authority_id,
             key_id, observed_json,
             _release_prefixed_sha256(observed_json.encode("ascii")),
             None if ready else not_ready_reason, now),
        )
        probe = conn.execute(
            "SELECT * FROM release_capability_probes "
            "WHERE release_row_id = ? AND capability = ?",
            (release_row_id, capability),
        ).fetchone()
        return dict(probe)


def _component_hash_observation(registered: dict) -> dict[str, str | None]:
    """Recompute each registered component digest from repository bytes.

    A missing, unreadable or root-escaping component observes as None so the
    caller fails closed instead of raising during observation.
    """
    root = REPO_ROOT.resolve()
    observation: dict[str, str | None] = {}
    for component in registered:
        candidate = (root / component).resolve()
        if root not in candidate.parents or not candidate.is_file():
            observation[component] = None
            continue
        observation[component] = _release_prefixed_sha256(
            candidate.read_bytes())
    return observation


def _verify_registered_component_hashes(row: sqlite3.Row) -> None:
    """§9 step 2, first half: registered component digests match file bytes."""
    registered = json.loads(row["component_hashes_json"])
    observation = _component_hash_observation(registered)
    for component, expected in registered.items():
        actual = observation[component]
        if actual is None:
            raise ComponentHashError(
                component, "component file is missing or escapes the root")
        if actual != expected:
            raise ComponentHashError(
                component, "registered digest does not match component bytes")


_LOCAL_RUNTIME_DIGEST_RE = re.compile(r"^local-runtime-sha256:[0-9a-f]{64}$")
_SEALED_REGISTRY_RELATIVE = (
    "services/backtest-worker/quantlens_worker/sealed_build_registrations.json"
)


def _presentation_release_seal_facts(release: dict, expected: dict) -> dict:
    """Stop F6 fact gathering for the presentation-release-seal probe.

    Read-only observation over repository bytes, the deployment byte pin
    and the sealed expectations file — never over the registry loader
    (byte observation stays independent of any loader admission law) and
    never over a caller-authored boolean. Facts, not verdicts: the pure
    evaluator in release_activation derives readiness from these. Since the
    Stop F2b re-seal the shipped registry satisfies every fact for the
    frozen release identity; a drifted pin, row or digest turns the exact
    fact false again.
    """
    facts = {name: "unavailable" for name in (
        "registry_pin", "registry_row", "build_digest",
        "expectations_release", "runtime_image_digest")}
    pin = os.environ.get("QL_SEALED_BUILD_REGISTRY_SHA256", "").strip()
    try:
        raw = (REPO_ROOT / _SEALED_REGISTRY_RELATIVE).read_bytes()
    except OSError:
        raw = None
    if not pin:
        facts["registry_pin"] = "unconfigured"
    elif raw is None:
        facts["registry_pin"] = "unreadable"
    elif "sha256:" + hashlib.sha256(raw).hexdigest() == pin:
        facts["registry_pin"] = "match"
    else:
        facts["registry_pin"] = "mismatch"

    contract_id = expected.get("presentation_contract_id") if isinstance(
        expected, dict) else None
    matching_digests: list[str] = []
    if raw is not None:
        try:
            registry = json.loads(raw.decode("utf-8"))
            registrations = registry["registrations"]
            assert isinstance(registrations, list)
        except (AssertionError, KeyError, TypeError, ValueError):
            facts["registry_row"] = "malformed"
        else:
            matching_digests = [
                str(item.get("image_digest"))
                for item in registrations
                if isinstance(item, dict)
                and item.get("contract_id") == contract_id
                and isinstance(item.get("image_digest"), str)
                and _LOCAL_RUNTIME_DIGEST_RE.fullmatch(item["image_digest"])
            ]
            facts["registry_row"] = (
                "registered" if matching_digests else "absent")

    try:
        expectations = load_corrected_read_expectations()
    except CorrectedReadExpectationsError:
        expectations = None
    if expectations is not None:
        facts["expectations_release"] = expectations.activation_release
        if expectations.runtime_image_digest is None:
            facts["runtime_image_digest"] = "null"
            facts["build_digest"] = "absent"
        else:
            facts["runtime_image_digest"] = "sealed"
            facts["build_digest"] = (
                "registered"
                if expectations.runtime_image_digest in matching_digests
                else "absent")
    return facts


# Doc 50 §3.2: the closed authority-environment name lists this control plane
# observes. They restate the worker's AUTHORITY_ENVIRONMENT surface split per
# authority; the worker package cannot be imported here (it imports this
# module), so the focused suite pins the two lists to the worker constant.
_PLAN_ANCHOR_ENVIRONMENT = (
    "QL_PLAN_ANCHOR_AUTHORITY_URL",
    "QL_PLAN_ANCHOR_AUTHORITY_ID",
    "QL_PLAN_ANCHOR_ISSUER_KEY_ID",
    "QL_PLAN_ANCHOR_ISSUER_BUNDLE_FILE",
    "QL_PLAN_ANCHOR_ISSUER_BUNDLE_SHA256",
)
_FINAL_HOLDOUT_ENVIRONMENT = (
    "QL_FINAL_HOLDOUT_AUTHORITY_URL",
    "QL_FINAL_HOLDOUT_AUTHORITY_ID",
    "QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID",
    "QL_FINAL_HOLDOUT_TRUST_BUNDLE_FILE",
    "QL_FINAL_HOLDOUT_TRUST_BUNDLE_SHA256",
    "QL_FINAL_HOLDOUT_EVALUATOR_KEY_ID",
    "QL_FINAL_HOLDOUT_EVALUATOR_KEY_FILE",
)


def _authority_environment_values(names: tuple[str, ...]) -> dict[str, str]:
    return {name: (os.environ.get(name) or "").strip() for name in names}


def _trust_bundle_facts(
    file_value: str, pin_value: str, key_id: str,
) -> tuple[str, str, str]:
    """(pin_fact, key_fact, canonical_bundle_hash) for one pinned bundle.

    Byte observation only: read the configured bundle file, hash its
    repository-wide canonical JSON form (byte-identical to the neutral
    protocol canonicalization for every valid bundle — the API layer may
    not import the protocol modules, a Gate B boundary law) and compare it
    to the configured pin; look for the declared key id among the bundle
    keys. Bundle VALIDITY stays worker-side: the execution-time verifier is
    the authority on the bundle grammar.
    """
    if not file_value or not pin_value:
        return "unconfigured", "unavailable", "unavailable"
    try:
        raw = Path(file_value).read_bytes()
        bundle = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return "unreadable", "unavailable", "unavailable"
    try:
        observed_hash = _release_prefixed_sha256(
            _release_canonical_json(bundle).encode("ascii"))
    except (TypeError, ValueError, UnicodeEncodeError):
        return "malformed", "unavailable", "unavailable"
    pin_fact = "match" if observed_hash == pin_value else "mismatch"
    entries = bundle.get("keys") if isinstance(bundle, dict) else None
    key_fact = "absent"
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key_id") == key_id:
                key_fact = "present"
                break
    return pin_fact, key_fact, observed_hash


def _evaluator_key_file_fact(path_value: str) -> str:
    """Owner-only regular 32-byte seed file, observed without reading bytes."""
    if not path_value:
        return "unconfigured"
    try:
        info = os.stat(Path(path_value), follow_symlinks=False)
    except OSError:
        return "missing"
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 \
            or info.st_size != 32:
        return "insecure"
    return "held"


def _plan_anchor_authority_facts() -> dict:
    """Doc 50 §3.2 fact gathering for the plan-anchor authority capability.

    Configuration and byte observation only — the closed environment names,
    the pinned issuer trust-bundle bytes and the declared issuer key id.
    Never a network probe: whether the authority process answers is an
    execution-time concern that fails closed in the corrected branch.
    """
    values = _authority_environment_values(_PLAN_ANCHOR_ENVIRONMENT)
    pin_fact, key_fact, observed_hash = _trust_bundle_facts(
        values["QL_PLAN_ANCHOR_ISSUER_BUNDLE_FILE"],
        values["QL_PLAN_ANCHOR_ISSUER_BUNDLE_SHA256"],
        values["QL_PLAN_ANCHOR_ISSUER_KEY_ID"],
    )
    return {
        "environment": (
            "configured" if all(values.values()) else "incomplete"),
        "issuer_bundle_pin": pin_fact,
        "issuer_key": key_fact,
        "authority_id": values["QL_PLAN_ANCHOR_AUTHORITY_ID"] or "unavailable",
        "issuer_key_id": (
            values["QL_PLAN_ANCHOR_ISSUER_KEY_ID"] or "unavailable"),
        "issuer_bundle_sha256": observed_hash,
    }


def _final_holdout_authority_facts() -> dict:
    """Doc 50 §3.2 fact gathering for the final-holdout authority capability."""
    values = _authority_environment_values(_FINAL_HOLDOUT_ENVIRONMENT)
    pin_fact, key_fact, observed_hash = _trust_bundle_facts(
        values["QL_FINAL_HOLDOUT_TRUST_BUNDLE_FILE"],
        values["QL_FINAL_HOLDOUT_TRUST_BUNDLE_SHA256"],
        values["QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID"],
    )
    return {
        "environment": (
            "configured" if all(values.values()) else "incomplete"),
        "trust_bundle_pin": pin_fact,
        "signer_key": key_fact,
        "evaluator_key": _evaluator_key_file_fact(
            values["QL_FINAL_HOLDOUT_EVALUATOR_KEY_FILE"]),
        "authority_id": (
            values["QL_FINAL_HOLDOUT_AUTHORITY_ID"] or "unavailable"),
        "signer_key_id": (
            values["QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID"]
            or "unavailable"),
        "trust_bundle_sha256": observed_hash,
        "evaluator_key_id": (
            values["QL_FINAL_HOLDOUT_EVALUATOR_KEY_ID"] or "unavailable"),
    }


def _control_plane_registrar_facts(
    conn: sqlite3.Connection,
    required_contract: str,
    *,
    now: datetime,
    max_age_seconds: float,
) -> dict:
    """Doc 50 §3.2 fact gathering for structural executable readiness.

    Store observation only: the latest execution-readiness document the
    serving worker recorded beside its liveness beat. The worker itself is
    the process that must execute, so its own configuration observation —
    integrity-hashed, fresh within the liveness window and naming the exact
    serving contract — is the honest readiness source; this producer never
    performs network I/O and never re-reads the worker's environment.
    """
    facts = {
        "worker_observation": "absent",
        "authority_environment": "unavailable",
        "control_plane_registrar": "unavailable",
        "evaluator_key": "unavailable",
        "worker_contract": "unavailable",
    }
    row = conn.execute(
        "SELECT observed_json, observed_sha256, observed_at "
        "FROM worker_execution_readiness WHERE runtime_contract = ? "
        "ORDER BY observed_at DESC LIMIT 1",
        (required_contract,),
    ).fetchone()
    if row is None:
        return facts
    recomputed = _release_prefixed_sha256(row["observed_json"].encode("ascii"))
    if recomputed != row["observed_sha256"]:
        facts["worker_observation"] = "malformed"
        return facts
    age = probe_age_seconds(row["observed_at"], now)
    if age < -CLOCK_SKEW_ALLOWANCE_SECONDS:
        facts["worker_observation"] = "clock_skew"
        return facts
    if age > max_age_seconds:
        facts["worker_observation"] = "stale"
        return facts
    try:
        document = json.loads(row["observed_json"])
    except ValueError:
        facts["worker_observation"] = "malformed"
        return facts
    if not isinstance(document, dict) \
            or document.get("serving_contract") != required_contract:
        facts["worker_observation"] = "foreign_contract"
        return facts
    facts["worker_observation"] = "fresh"
    facts["worker_contract"] = str(document.get("serving_contract"))
    for name in ("authority_environment", "control_plane_registrar",
                 "evaluator_key"):
        value = document.get(name)
        facts[name] = value if isinstance(value, str) else "unavailable"
    return facts


def probe_release_capabilities(
    release_row_id: str,
    *,
    heartbeat_max_age_seconds: float | None = None,
) -> dict:
    """Observe and record every capability the release registration declares.

    This is the honest probe producer: it reads only the control-plane
    store, the environment contract and repository/file bytes, and performs
    no network I/O. Each kind fails closed when unconfigured. Since Stop F6
    the presentation release seal derives its readiness from exact observed
    facts; since the doc 50 §3.2 repair the two authority capabilities and
    the registrar readiness are ALSO derived — from the closed authority
    environment, the pinned trust-bundle bytes and the serving worker's own
    recorded execution-readiness document — never from a caller-supplied
    observation document, which this producer no longer accepts. Any unmet
    prerequisite is recorded by its exact fact name — structurally, never
    by flag.
    """
    heartbeat_max_age = (
        _worker_heartbeat_max_age_seconds()
        if heartbeat_max_age_seconds is None
        else max(0.0, float(heartbeat_max_age_seconds))
    )
    release = get_release(release_row_id)
    if release is None:
        raise UnknownReleaseError(
            f"release row {release_row_id!r} does not exist")
    required = release["required_capabilities"]
    now_dt = datetime.now(timezone.utc)
    results: dict[str, dict] = {}
    for capability in sorted(required):
        expected = required[capability]
        authority_id: str | None = None
        key_id: str | None = None
        if capability == "presentation_release_seal":
            facts = _presentation_release_seal_facts(release, expected)
            ready, reason, pending = evaluate_presentation_release_seal(
                facts, expected_release_id=release["release_id"])
            observed = dict(facts)
            observed["pending_prerequisites"] = pending
            if ready and isinstance(expected, dict):
                # Activation re-derives readiness by field equality against
                # the registered expectation, so a ready observation carries
                # the matched contract identity explicitly.
                observed["presentation_contract_id"] = str(
                    expected.get("presentation_contract_id"))
        elif capability == "worker_runtime":
            with connect() as conn:
                heartbeat = conn.execute(
                    "SELECT worker_id, runtime_contract, state, last_seen_at "
                    "FROM worker_heartbeats WHERE runtime_contract = ? "
                    "ORDER BY last_seen_at DESC LIMIT 1",
                    (release["required_worker_contract"],),
                ).fetchone()
            heartbeat_dict = dict(heartbeat) if heartbeat else None
            ready, reason = evaluate_worker_heartbeat(
                heartbeat_dict, now=now_dt, max_age_seconds=heartbeat_max_age)
            observed = heartbeat_dict or {
                "runtime_contract": release["required_worker_contract"],
                "heartbeat": "absent",
            }
            if ready:
                # Stop F6: observe the repository's runtime image digest so
                # a registration that declares worker_runtime.image_digest
                # (the F2b-mandatory identity) can be genuinely probed. On
                # this single-machine boundary the API recomputation equals
                # the worker's own; execution re-proves the equality through
                # the corrected branch's runtime-identity law either way.
                from quantlens_worker.config import (
                    image_digest as _runtime_image_digest,
                )

                observed = dict(observed)
                observed["image_digest"] = _runtime_image_digest()
                expect_ready, expect_reason = evaluate_expectation_document(
                    expected, observed)
                ready, reason = expect_ready, expect_reason
        elif capability == "component_hashes":
            registered = release["component_hashes"]
            observation = _component_hash_observation(registered)
            ready, reason = evaluate_component_hashes(registered, observation)
            observed_components = {
                path: digest or "missing"
                for path, digest in observation.items()
            }
            # Doc 50 §3.2: restate the canonical digest of the OBSERVED
            # component set so the registration's component_hashes_sha256
            # declaration is provable by the generic equality law.
            observed = {
                "components": observed_components,
                "component_hashes_sha256": _release_canonical_sha256(
                    observed_components),
            }
            if ready and isinstance(expected, dict):
                expect_ready, expect_reason = evaluate_expectation_document(
                    expected, observed)
                ready, reason = expect_ready, expect_reason
        else:
            # Doc 50 §3.2: the remaining kinds are derived — configuration
            # and byte facts for the two authorities, the serving worker's
            # recorded execution-readiness document for the registrar. The
            # identity fields the facts restate are then compared
            # field-for-field against the registered expectation.
            if capability == CAPABILITY_KIND_PLAN_ANCHOR:
                facts = _plan_anchor_authority_facts()
                key_field = "issuer_key_id"
            elif capability == CAPABILITY_KIND_FINAL_HOLDOUT:
                facts = _final_holdout_authority_facts()
                key_field = "signer_key_id"
            else:
                assert capability == CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR
                with connect() as conn:
                    facts = _control_plane_registrar_facts(
                        conn, release["required_worker_contract"],
                        now=now_dt, max_age_seconds=heartbeat_max_age)
                key_field = None
            _, evaluator = DERIVED_AUTHORITY_EVALUATORS[capability]
            ready, reason, pending = evaluator(facts)
            observed = dict(facts)
            observed["pending_prerequisites"] = pending
            if ready and isinstance(expected, dict):
                expect_ready, expect_reason = evaluate_expectation_document(
                    expected, observed)
                ready, reason = expect_ready, expect_reason
            raw_authority = facts.get("authority_id")
            authority_id = (
                raw_authority
                if isinstance(raw_authority, str)
                and raw_authority != "unavailable" else None)
            if key_field is not None:
                raw_key = facts.get(key_field)
                key_id = (
                    raw_key
                    if isinstance(raw_key, str) and raw_key != "unavailable"
                    else None)
        results[capability] = _record_capability_probe(
            release_row_id, capability, ready=ready, observed=observed,
            authority_id=authority_id, key_id=key_id,
            not_ready_reason=reason)
    return results


def _verify_corrected_release_expectations_in(
    conn: sqlite3.Connection, row: sqlite3.Row,
) -> None:
    """Stop F2b (doc 48 §8 obligation): re-validate the sealed expectations
    file, the registration's declared runtime identity and the populated
    store inside the activation transaction.

    Laws, all fail-closed with the typed expectations error:

    1. the sealed file must load under its byte pin with a non-null runtime
       digest (the loader enforces both since the F2b seal);
    2. the file's ``activation_release`` must equal the release identity the
       row is registering;
    3. the registration's mandatory ``worker_runtime.image_digest``
       declaration must equal the file's sealed ``runtime_image_digest`` —
       the declared runtime identity IS the reviewed sealed identity, never
       a merely self-consistent one;
    4. every semantics entry the store already holds must restate the
       file's minted digests exactly (the file is the review authority for
       what the store may contain); components without a file authority
       (calendars, snapshots, plans, anchors) are validated by their own
       registration-time key laws instead.
    """
    expectations = load_corrected_read_expectations()
    if expectations.activation_release != row["release_id"]:
        raise CorrectedReadExpectationsError(
            "corrected read expectations are not admissible: the sealed "
            "file names a different activation release than this "
            "registration")
    required = json.loads(row["required_capabilities_json"])
    runtime = required.get("worker_runtime")
    declared = runtime.get("image_digest") if isinstance(runtime, dict) else None
    if declared != expectations.runtime_image_digest:
        raise CorrectedReadExpectationsError(
            "corrected read expectations are not admissible: the declared "
            "worker_runtime.image_digest does not equal the sealed "
            "runtime_image_digest")
    minted = {
        "financial_semantics": dict(expectations.financial_semantics),
        "metric_semantics": dict(expectations.metric_semantics),
    }
    for component, authority in minted.items():
        rows = conn.execute(
            "SELECT entry_key, document_json "
            "FROM corrected_read_expectation_documents WHERE component = ?",
            (component,),
        ).fetchall()
        for stored in rows:
            document = json.loads(stored["document_json"])
            if authority.get(stored["entry_key"]) != document:
                raise CorrectedReadExpectationsError(
                    "corrected read expectations are not admissible: the "
                    f"populated {component} store disagrees with the sealed "
                    "file")


def _verify_capability_probes_in(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    now: datetime,
    max_age_seconds: float,
) -> str:
    """§9 step 2, second half: every required capability probe holds.

    Each probe must exist, be ready, be fresh within the bounded window,
    hash-match its stored document, and embed the registered expectation.
    Returns the digest binding the exact probe set for the receipt.
    """
    required = json.loads(row["required_capabilities_json"])
    probes = {
        probe["capability"]: probe
        for probe in conn.execute(
            "SELECT * FROM release_capability_probes WHERE release_row_id = ?",
            (row["release_row_id"],),
        ).fetchall()
    }
    checked: dict[str, dict] = {}
    for capability in sorted(required):
        probe = probes.get(capability)
        if probe is None:
            raise CapabilityProbeError(capability, "no probe recorded")
        if int(probe["ready"]) != 1:
            raise CapabilityProbeError(
                capability,
                probe["not_ready_reason"] or "probe reported not ready")
        age = probe_age_seconds(probe["observed_at"], now)
        if age < -CLOCK_SKEW_ALLOWANCE_SECONDS:
            raise CapabilityProbeError(
                capability,
                "probe observation time is beyond the clock-skew allowance")
        if age > max_age_seconds:
            raise CapabilityProbeError(
                capability,
                f"probe is stale ({age:.1f}s old; window {max_age_seconds:.1f}s)")
        recomputed = _release_prefixed_sha256(
            probe["observed_json"].encode("ascii"))
        if recomputed != probe["observed_sha256"]:
            raise CapabilityProbeError(
                capability, "stored observation fails its integrity digest")
        document = json.loads(probe["observed_json"])
        if document.get("expected") != required[capability]:
            raise CapabilityProbeError(
                capability,
                "probe was evaluated against a different expectation")
        # Doc 47 §5.7: activation independently re-derives readiness from
        # the stored observation against the registered expectation — the
        # recorded boolean alone can never authorize this transition.
        derived_ready, derived_reason = evaluate_expectation_document(
            required[capability], document.get("observed"))
        if not derived_ready:
            raise CapabilityProbeError(
                capability,
                "stored observation no longer satisfies the registered "
                f"expectation: {derived_reason}")
        if capability == "presentation_release_seal":
            # Doc 50 §3.1 repair: the generic field-equality law above only
            # proves the expectation subset (the contract id). The seal
            # verdict must be re-derived transactionally from the CLOSED
            # five-fact evaluator, twice over: (1) the stored observation
            # must carry every derived fact and pass the evaluator — a
            # ready=1 record with absent or false facts can never
            # authorize; (2) the facts are re-derived FRESH from the
            # repository bytes, the deployment pin and the sealed
            # expectations file inside this same transaction, so a
            # repository that drifted after the probe was recorded refuses
            # here regardless of what the stored document claims.
            observed = document.get("observed")
            observed = observed if isinstance(observed, dict) else {}
            missing_facts = [
                name for name in RELEASE_SEAL_FACTS if name not in observed
            ]
            if missing_facts:
                raise CapabilityProbeError(
                    capability,
                    "stored seal observation is missing derived facts: "
                    + ",".join(missing_facts))
            stored_ready, _, stored_pending = (
                evaluate_presentation_release_seal(
                    observed, expected_release_id=row["release_id"]))
            if not stored_ready:
                raise CapabilityProbeError(
                    capability,
                    "stored seal observation fails the closed fact "
                    "evaluator: " + ",".join(stored_pending))
            if observed.get("presentation_contract_id") != (
                    row["presentation_contract_id"]):
                raise CapabilityProbeError(
                    capability,
                    "stored seal observation names a different "
                    "presentation contract")
            fresh = _presentation_release_seal_facts(
                dict(row), required[capability])
            fresh_ready, _, fresh_pending = (
                evaluate_presentation_release_seal(
                    fresh, expected_release_id=row["release_id"]))
            if not fresh_ready:
                raise CapabilityProbeError(
                    capability,
                    "transactional re-derivation of the seal facts "
                    "refuses: " + ",".join(fresh_pending))
        if capability in DERIVED_AUTHORITY_EVALUATORS:
            # Doc 50 §3.2: the two authority capabilities and the registrar
            # readiness are execution prerequisites, so activation re-runs
            # their closed fact evaluators twice — over the STORED
            # observation (a ready=1 record with absent or false facts can
            # never authorize) and over facts re-derived FRESH inside this
            # same transaction from the environment contract, the pinned
            # trust-bundle bytes and the worker's recorded readiness row.
            fact_names, evaluator = DERIVED_AUTHORITY_EVALUATORS[capability]
            observed = document.get("observed")
            observed = observed if isinstance(observed, dict) else {}
            missing_facts = [
                name for name in fact_names if name not in observed
            ]
            if missing_facts:
                raise CapabilityProbeError(
                    capability,
                    "stored observation is missing derived facts: "
                    + ",".join(missing_facts))
            stored_ready, _, stored_pending = evaluator(observed)
            if not stored_ready:
                raise CapabilityProbeError(
                    capability,
                    "stored observation fails the closed fact evaluator: "
                    + ",".join(stored_pending))
            if capability == CAPABILITY_KIND_PLAN_ANCHOR:
                fresh = _plan_anchor_authority_facts()
            elif capability == CAPABILITY_KIND_FINAL_HOLDOUT:
                fresh = _final_holdout_authority_facts()
            else:
                fresh = _control_plane_registrar_facts(
                    conn, row["required_worker_contract"],
                    now=now, max_age_seconds=max_age_seconds)
            fresh_ready, _, fresh_pending = evaluator(fresh)
            if not fresh_ready:
                raise CapabilityProbeError(
                    capability,
                    "transactional re-derivation of the derived facts "
                    "refuses: " + ",".join(fresh_pending))
            fresh_expect_ready, fresh_expect_reason = (
                evaluate_expectation_document(required[capability], fresh))
            if not fresh_expect_ready:
                raise CapabilityProbeError(
                    capability,
                    "transactional re-derivation observes a different "
                    f"identity: {fresh_expect_reason}")
        checked[capability] = dict(probe)
    return capability_probe_set_sha256(checked)


def activate_prepared_release(
    release_row_id: str,
    *,
    actor_id: str,
    user_id: str,
    probe_max_age_seconds: float | None = None,
) -> dict:
    """The §9 PREPARED -> ACTIVE transition in one BEGIN IMMEDIATE transaction.

    Steps, all inside one write transaction that commits exactly once:
    1. no other active corrected release; 2. every registered component hash
    and required capability probe holds; 3. the single active release pointer
    is set with a guarded UPDATE; 4. the acting principal, time and immutable
    activation receipt are recorded; 5. one commit on clean exit. Any failure
    rolls the store back to exactly the pre-call state.
    """
    max_age = (
        DEFAULT_PROBE_MAX_AGE_SECONDS
        if probe_max_age_seconds is None else max(0.0, probe_max_age_seconds)
    )
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _release_row_in(conn, release_row_id)
        if row["release_state"] != RELEASE_STATE_PREPARED:
            raise ReleaseStateError(
                "only a PREPARED release can be activated; "
                f"this one is {row['release_state']}")
        check_release_transition(row["release_state"], RELEASE_STATE_ACTIVE)
        if _active_release_in(conn) is not None:
            raise ReleaseStateError(
                "another corrected release is already active")
        # Doc 47 §5.5: the semantic registration validation runs again inside
        # this transaction, over the stored row, before PREPARED may become
        # ACTIVE — a row that no longer satisfies the closed corrected-release
        # schema (however it got that way) can never activate.
        validate_release_registration(
            release_id=row["release_id"],
            required_worker_contract=row["required_worker_contract"],
            presentation_contract_id=row["presentation_contract_id"],
            signer_key_id=row["signer_key_id"],
            release_tuple=json.loads(row["release_tuple_json"]),
            component_hashes=json.loads(row["component_hashes_json"]),
            required_capabilities=json.loads(
                row["required_capabilities_json"]),
            prepared_by=row["prepared_by"],
            baseline_worker_contract=WORKER_RUNTIME_CONTRACT,
        )
        _verify_registered_component_hashes(row)
        # Stop F2b: the sealed expectations file, the declared runtime
        # identity and the populated store must agree before PREPARED may
        # become ACTIVE (doc 48 §8 obligation, in this same transaction).
        _verify_corrected_release_expectations_in(conn, row)
        probe_digest = _verify_capability_probes_in(
            conn, row, now=now_dt, max_age_seconds=max_age)
        cur = conn.execute(
            "UPDATE release_activations SET release_state = ?, "
            "activated_by = ?, activated_at = ?, updated_at = ? "
            "WHERE release_row_id = ? AND release_state = ?",
            (RELEASE_STATE_ACTIVE, user_id, now, now,
             release_row_id, RELEASE_STATE_PREPARED),
        )
        if cur.rowcount != 1:
            raise ReleaseStateError("release was concurrently transitioned")
        receipt = build_activation_receipt(
            dict(row), actor_id=actor_id, user_id=user_id,
            activated_at=now, capability_probe_sha256=probe_digest)
        receipt_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO release_activation_receipts("
            "receipt_id, release_row_id, release_id, release_tuple_sha256, "
            "component_hashes_sha256, capability_probe_sha256, actor_id, "
            "user_id, activated_at, receipt_json, receipt_sha256) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (receipt_id, release_row_id, row["release_id"],
             row["release_tuple_sha256"], row["component_hashes_sha256"],
             probe_digest, actor_id, user_id, now,
             receipt["receipt_json"], receipt["receipt_sha256"]),
        )
        conn.execute(
            "UPDATE release_activations SET activation_receipt_sha256 = ?, "
            "updated_at = ? WHERE release_row_id = ?",
            (receipt["receipt_sha256"], now, release_row_id),
        )
        _record_event_in(conn, "release_activated", {
            "release_row_id": release_row_id,
            "release_id": row["release_id"],
            "required_worker_contract": row["required_worker_contract"],
            "release_tuple_sha256": row["release_tuple_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
        }, tenant_id=actor_id, user_id=user_id)
        activated = _release_dict(_release_row_in(conn, release_row_id))
        activated["activation_receipt"] = receipt["receipt"]
        return activated


def _terminate_release(
    release_row_id: str,
    *,
    expected_state: str,
    target_state: str,
    event_type: str,
    actor_id: str,
    user_id: str,
    reason: str,
) -> dict:
    if not (reason or "").strip():
        raise ValueError("a terminal release transition must state its reason")
    now = _now()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _release_row_in(conn, release_row_id)
        if row["release_state"] != expected_state:
            raise ReleaseStateError(
                f"only a {expected_state} release can move to {target_state}; "
                f"this one is {row['release_state']}")
        check_release_transition(row["release_state"], target_state)
        cur = conn.execute(
            "UPDATE release_activations SET release_state = ?, "
            "terminal_at = ?, terminal_reason = ?, updated_at = ? "
            "WHERE release_row_id = ? AND release_state = ?",
            (target_state, now, reason, now, release_row_id, expected_state),
        )
        if cur.rowcount != 1:
            raise ReleaseStateError("release was concurrently transitioned")
        _record_event_in(conn, event_type, {
            "release_row_id": release_row_id,
            "release_id": row["release_id"],
            "reason": reason,
        }, tenant_id=actor_id, user_id=user_id)
        return _release_dict(_release_row_in(conn, release_row_id))


def abort_prepared_release(
    release_row_id: str, *, actor_id: str, user_id: str, reason: str,
) -> dict:
    """Withdraw a PREPARED release before it ever routed work (terminal)."""
    return _terminate_release(
        release_row_id, expected_state=RELEASE_STATE_PREPARED,
        target_state=RELEASE_STATE_ABORTED, event_type="release_aborted",
        actor_id=actor_id, user_id=user_id, reason=reason)


def rollback_active_release(
    release_row_id: str, *, actor_id: str, user_id: str, reason: str,
) -> dict:
    """§9 rollback: ACTIVE -> SUPERSEDED in one new transaction.

    Routing changes purely because no ACTIVE row remains afterwards; nothing
    is written to runs, reservations, receipts, bindings, artifacts or
    evidence, and the activation receipt is preserved for audit.
    """
    return _terminate_release(
        release_row_id, expected_state=RELEASE_STATE_ACTIVE,
        target_state=RELEASE_STATE_SUPERSEDED, event_type="release_superseded",
        actor_id=actor_id, user_id=user_id, reason=reason)
