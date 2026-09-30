"""Authority-only SQLite persistence for the dormant plan-anchor authority.

This module owns exactly the authority database schema, the fail-closed connection
preflight and the transaction mechanics.  It imports nothing but the standard
library — never the neutral protocol, worker, API or web code — and it never calls
or references the main control-plane database helpers or the main variable-directory
environment variable.

Initialization is race-safe with two explicit paths: an absent database file is
claimed with ``O_CREAT | O_EXCL``, its inode is pinned from the claiming descriptor,
and only that claimant initializes the application id, user version, exact tables
AND the singleton authority-metadata row in one ``BEGIN EXCLUSIVE`` transaction.
Any existing path is first inspected through a read-only, query-only connection
against the exact known schema — object types and names, normalized SQL,
``table_xinfo``/``index_list``/``index_xinfo``, no extra trigger/view/index beyond
the expected SQLite autoindexes, ``quick_check`` exactly ``ok`` and exactly one
metadata row — and a mismatched, zero-byte, corrupt, unfinished or unknown-schema
file is rejected byte-for-byte unchanged.  No automatic repair, completion,
replacement or ``INSERT OR REPLACE`` exists anywhere in this module.

Operational calls never create or follow anything: each opens the database with
``O_RDONLY | O_CLOEXEC | O_NOFOLLOW``, requires a regular owner-only single-link
file, pins ``st_dev``/``st_ino``, connects with URI ``mode=rw`` only, re-compares
the path identity after the SQLite open and reverifies the exact schema, integrity
and PRAGMAs before use.  The store owns ``BEGIN IMMEDIATE``, rollback, commit and
close; an authority callback receives only a narrow transaction object with exact
request lookup, nonce/run lookup and one registration insert.  A ``COMMIT``
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

# One process-wide lock serializes authority operations so the deterministic
# fd-count tie below is meaningful within a cooperative same-process race, and a
# LOCK_EX on the authority directory serializes across cooperating processes.
_OPERATION_LOCK = threading.Lock()

# Read chunk for hashing/copying the base file during the snapshot preflight.
_SNAPSHOT_CHUNK = 1 << 20

AUTHORITY_DB_APPLICATION_ID = 0x514C5041  # "QLPA"
AUTHORITY_DB_USER_VERSION = 1
AUTHORITY_DB_FILENAME = "plan-anchor-authority.sqlite3"

_SQLITE_HEADER = b"SQLite format 3" + bytes([0])
_EXPECTED_TABLES = ("anchor_registrations", "authority_metadata")

# Frozen SQLite header layout (100-byte header) used for a pure, side-effect-free
# identity read: no connection is opened to learn the application id, user version
# or journal format.  Big-endian per the SQLite file format.
_HEADER_LENGTH = 100
_HEADER_USER_VERSION = slice(60, 64)
_HEADER_APPLICATION_ID = slice(68, 72)
_HEADER_WRITE_FORMAT = 18  # 2 => write-ahead log
_HEADER_READ_FORMAT = 19  # 2 => write-ahead log
_WAL_FORMAT = 2

# The expected schema is frozen as an explicit canonical fingerprint, independent
# of the production DDL below: a divergence between the DDL and this contract value
# is a rejected build, and a live database must reproduce this exact fingerprint.
_EXPECTED_SCHEMA_FINGERPRINT = (
    "sha256:187f7fdae6ac47fa16bcf7fa5650cd4e676cb8ae758e52e4357b79c844ddb179"
)

_METADATA_IDENTITY_COLUMNS = (
    "schema_version",
    "authority_id",
    "issuer_key_id",
    "issuer_public_key_hex",
    "issuer_trust_bundle_sha256",
    "registrar_trust_bundle_sha256",
)
_METADATA_COLUMNS = (*_METADATA_IDENTITY_COLUMNS, "created_at")

_REGISTRATION_COLUMNS = (
    "request_id",
    "request_nonce",
    "registrar_key_id",
    "request_timestamp",
    "request_sha256",
    "request_bytes",
    "body_sha256",
    "body_bytes",
    "release_id",
    "tenant_id",
    "workspace_id",
    "run_id",
    "anchor_id",
    "anchor_nonce",
    "issued_at",
    "expires_at",
    "registered_at",
    "issuer_key_id",
    "unsigned_anchor_sha256",
    "unsigned_anchor_bytes",
    "anchor_signature_hex",
    "signed_anchor_sha256",
    "registered_signed_anchor_bytes_sha256",
    "signed_anchor_bytes",
    "receipt_sha256",
    "receipt_bytes",
    "state",
)

_CREATE_METADATA = """
CREATE TABLE authority_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    issuer_public_key_hex TEXT NOT NULL,
    issuer_trust_bundle_sha256 TEXT NOT NULL,
    registrar_trust_bundle_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""

_CREATE_REGISTRATIONS = """
CREATE TABLE anchor_registrations (
    request_id TEXT PRIMARY KEY,
    request_nonce TEXT NOT NULL UNIQUE,
    registrar_key_id TEXT NOT NULL,
    request_timestamp TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    request_bytes BLOB NOT NULL,
    body_sha256 TEXT NOT NULL,
    body_bytes BLOB NOT NULL,
    release_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    anchor_id TEXT NOT NULL UNIQUE,
    anchor_nonce TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    unsigned_anchor_sha256 TEXT NOT NULL,
    unsigned_anchor_bytes BLOB NOT NULL,
    anchor_signature_hex TEXT NOT NULL,
    signed_anchor_sha256 TEXT NOT NULL,
    registered_signed_anchor_bytes_sha256 TEXT NOT NULL,
    signed_anchor_bytes BLOB NOT NULL,
    receipt_sha256 TEXT NOT NULL,
    receipt_bytes BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state = 'REGISTERED'),
    UNIQUE(release_id, tenant_id, workspace_id, run_id)
)
"""


class PlanAnchorAuthorityStoreError(RuntimeError):
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
    raise PlanAnchorAuthorityStoreError(message, **flags)


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
        raise PlanAnchorAuthorityStoreError(f"{label} is not inspectable") from exc
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
        raise PlanAnchorAuthorityStoreError(f"{label} is not inspectable") from exc
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

    The whole ``sqlite_schema`` object list (every table, index, trigger and view
    plus normalized SQL) is captured, so an extra trigger/view/index — beyond the
    expected SQLite autoindexes — changes the fingerprint and is rejected.
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
    try:
        quick_check = [tuple(row) for row in connection.execute(
            "PRAGMA quick_check")]
        fingerprint = _schema_fingerprint(connection)
    except sqlite3.Error as exc:
        raise PlanAnchorAuthorityStoreError(
            "authority database schema inspection failed"
        ) from exc
    _require(
        quick_check == [("ok",)],
        "authority database integrity quick_check is not exactly ok",
    )
    _require(
        fingerprint == _EXPECTED_SCHEMA_FINGERPRINT,
        "authority database schema does not exactly match the frozen authority "
        "schema fingerprint; extra or altered tables, indexes, triggers or views "
        "are rejected without repair",
    )


def _read_header_identity(descriptor: int) -> None:
    """Verify the SQLite header identity from an open descriptor; pure read.

    Reads the 100-byte header via ``pread`` (no offset side effect) and requires
    the magic, application id, user version and both journal-format bytes — so the
    WAL format is confirmed without opening a mutating SQLite connection.
    """
    try:
        header = os.pread(descriptor, _HEADER_LENGTH, 0)
    except OSError as exc:
        raise PlanAnchorAuthorityStoreError(
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
    salt must equal the verified header salt and the file must be exactly the
    header plus a whole number of frames.

    Availability limitation (documented, deliberately NOT fail-open): a genuine
    rewound-and-reused WAL that legitimately carries a stale prior-cycle tail is
    rejected rather than accepted.  For this authority-only, one-anchor-per-run
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
        "copied WAL header checksum does not verify; failing closed",
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
            "copied WAL frame checksum does not verify; failing closed",
        )
        offset += frame_size


def _process_fd_root() -> str:
    """The kernel-provided view of this process's open descriptors, or fail closed."""
    for candidate in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(candidate):
            return candidate
    _fail(
        "the process descriptor table is not enumerable; the authority cannot "
        "prove the SQLite open and fails closed"
    )
    raise AssertionError  # unreachable


def _count_pinned_fds(pinned: tuple[int, int]) -> int:
    """Count this process's open descriptors whose fstat matches ``pinned``.

    The fd number is fstat'd directly (``os.stat`` on ``/dev/fd/N`` does not
    resolve to the target on macOS).  An unenumerable or unreadable table is
    ambiguous and fails closed rather than guessing.
    """
    fd_root = _process_fd_root()
    try:
        entries = os.listdir(fd_root)
    except OSError as exc:
        raise PlanAnchorAuthorityStoreError(
            "the process descriptor table is not readable; failing closed"
        ) from exc
    count = 0
    for entry in entries:
        try:
            number = int(entry)
        except ValueError:
            continue
        try:
            info = os.fstat(number)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == pinned:
            count += 1
    return count


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
                raise PlanAnchorAuthorityStoreError(
                    "authority snapshot write made no progress; failing closed"
                )
            written += count
    finally:
        os.close(out)


class _RegistrationTransaction:
    """The only surface an authority callback sees while the write lock is held."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def fetch_request(self, request_id: str) -> dict[str, Any] | None:
        try:
            cursor = self._connection.execute(
                "SELECT * FROM anchor_registrations WHERE request_id = ?",
                (str(request_id),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority request lookup failed"
            ) from exc
        if row is None:
            return None
        return {key: row[key] for key in row.keys()}

    def nonce_request_id(self, request_nonce: str) -> str | None:
        try:
            cursor = self._connection.execute(
                "SELECT request_id FROM anchor_registrations "
                "WHERE request_nonce = ?",
                (str(request_nonce),),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority nonce lookup failed"
            ) from exc
        return None if row is None else str(row[0])

    def run_request_id(
        self, release_id: str, tenant_id: str, workspace_id: str, run_id: str
    ) -> str | None:
        try:
            cursor = self._connection.execute(
                "SELECT request_id FROM anchor_registrations WHERE release_id = ? "
                "AND tenant_id = ? AND workspace_id = ? AND run_id = ?",
                (str(release_id), str(tenant_id), str(workspace_id), str(run_id)),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority run lookup failed"
            ) from exc
        return None if row is None else str(row[0])

    def insert_registration(self, record: Mapping[str, Any]) -> None:
        keys = set(record)
        expected = set(_REGISTRATION_COLUMNS)
        _require(
            keys == expected,
            "registration record must carry exactly the sealed column set",
        )
        columns = ", ".join(_REGISTRATION_COLUMNS)
        placeholders = ", ".join("?" for _ in _REGISTRATION_COLUMNS)
        try:
            self._connection.execute(
                f"INSERT INTO anchor_registrations ({columns}) "
                f"VALUES ({placeholders})",
                tuple(record[column] for column in _REGISTRATION_COLUMNS),
            )
        except sqlite3.IntegrityError as exc:
            # A uniqueness failure is a collision only when a persisted row
            # actually owns the proposed authority-generated identifiers; every
            # other integrity failure is sanitized unavailability.
            if self._identifier_owned(
                str(record["anchor_id"]), str(record["anchor_nonce"])
            ):
                raise PlanAnchorAuthorityStoreError(
                    "authority-generated anchor identifier collided with a "
                    "persisted registration",
                    collision=True,
                ) from exc
            raise PlanAnchorAuthorityStoreError(
                "authority registration insert failed closed",
            ) from exc
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority registration insert failed"
            ) from exc

    def _identifier_owned(self, anchor_id: str, anchor_nonce: str) -> bool:
        try:
            row = self._connection.execute(
                "SELECT 1 FROM anchor_registrations "
                "WHERE anchor_id = ? OR anchor_nonce = ?",
                (anchor_id, anchor_nonce),
            ).fetchone()
        except sqlite3.Error:
            return False  # unknown ownership is never reported as a collision
        return row is not None


class PlanAnchorAuthorityStoreV1:
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
                or busy_timeout_ms <= 0:
            _fail("busy timeout must be a positive integer of milliseconds")
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
        # Both branches run under the process-wide lock and a LOCK_EX on the
        # authority directory, so a cooperative racer cannot swap the file under
        # the claim or the preflight copy.
        with _OPERATION_LOCK:
            try:
                dir_fd = os.open(
                    str(self._db_path.parent), os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                raise PlanAnchorAuthorityStoreError(
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
            raise PlanAnchorAuthorityStoreError(
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
            raise PlanAnchorAuthorityStoreError(
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
        before_count = _count_pinned_fds(pinned)
        try:
            connection = sqlite3.connect(
                self._db_path.as_uri() + "?mode=rw", uri=True,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority database initialization open failed"
            ) from exc
        committed = False
        try:
            # Immediately after connect and BEFORE any PRAGMA/SQL: SQLite must have
            # opened exactly the claimed inode.  The O_EXCL claim fd is held open
            # (O_RDWR) the whole time, so a swap-connect-decoy-restore that makes
            # SQLite initialize a different inode is detected and rejected.
            _require(
                _count_pinned_fds(pinned) == before_count + 1,
                "SQLite did not open exactly the claimed authority inode; "
                "aborting without mutation",
            )
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
                connection.execute(_CREATE_METADATA)
                connection.execute(_CREATE_REGISTRATIONS)
                columns = ", ".join(("singleton", *_METADATA_COLUMNS))
                placeholders = ", ".join(
                    "?" for _ in range(len(_METADATA_COLUMNS) + 1))
                connection.execute(
                    f"INSERT INTO authority_metadata ({columns}) "
                    f"VALUES ({placeholders})",
                    (1, *(self._initial_metadata[column]
                          for column in _METADATA_COLUMNS)),
                )
                # Set-and-read-back every frozen effective PRAGMA before commit.
                self._assert_effective_pragmas(connection)
            except PlanAnchorAuthorityStoreError:
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
                raise PlanAnchorAuthorityStoreError(
                    "authority database initialization failed"
                ) from exc
            # The one-transaction commit: schema, version, application id and the
            # singleton metadata row become durable together or not at all.  A
            # COMMIT exception is an indeterminate durable outcome: close without
            # a rollback claim and never retry or read to success in this call.
            try:
                connection.execute("COMMIT")
                committed = True
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
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
        # A fresh verified read connection (lock + directory flock still held)
        # confirms header/schema/metadata through the fd-count tie.
        with self._verified_connection() as connection:
            try:
                metadata_rows = connection.execute(
                    "SELECT COUNT(*) FROM authority_metadata").fetchone()[0]
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
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
                _fail(f"authority connection failed the {label} verification")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() \
                != "wal":
            _fail("authority connection failed the journal_mode=WAL verification")

    def _read_only_preflight(self) -> None:
        """Inspect an existing path WAL-aware without mutating one source byte.

        ``immutable=1`` silently ignores a committed-but-uncheckpointed WAL, so a
        crash/response-loss state would be misread.  Instead the base file and any
        durable ``-wal`` sidecar are copied — through O_NOFOLLOW-pinned descriptors
        with a partial-write-safe loop — into a private 0700 snapshot with 0600
        files, and the copy is opened WAL-aware while the snapshot rebuilds its own
        ``-shm``.  The ``-shm`` is never copied (it is volatile and may disagree
        with the WAL).  The exact durable-sidecar set, plus each source's full
        stat and content hash and the complete directory listing, are verified
        unchanged before opening the snapshot and again after verifying it.
        """
        var_dir = self._db_path.parent
        snapshot_dir = Path(tempfile.mkdtemp(prefix="ql-anchor-preflight-"))
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
            # O_NONBLOCK so opening a FIFO/socket sidecar returns immediately
            # (and is then rejected as non-regular) instead of blocking forever;
            # it has no effect on the regular files that are actually accepted.
            source_fd = os.open(
                str(path),
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            raise PlanAnchorAuthorityStoreError(
                f"{label} cannot be opened for inspection"
            ) from exc
        try:
            info = os.fstat(source_fd)
            # A symlink is already refused by O_NOFOLLOW; a FIFO/socket/device is
            # not regular; a hardlink has st_nlink != 1.
            _require(
                stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600,
                f"{label} identity failed inspection",
            )
            if label.endswith("database"):
                _read_header_identity(source_fd)
            digest, _length = _hash_open_descriptor(source_fd)
            payload = b""
            offset = 0
            while True:
                chunk = os.pread(source_fd, _SNAPSHOT_CHUNK, offset)
                if not chunk:
                    break
                payload += chunk
                offset += len(chunk)
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
            raise PlanAnchorAuthorityStoreError(
                "authority snapshot cannot be opened for inspection"
            ) from exc
        try:
            try:
                # The snapshot is a private copy, so applying and reading back the
                # frozen connection-local PRAGMAs never touches the source.  The
                # complete frozen set — journal_mode=WAL, foreign_keys=ON,
                # busy_timeout, synchronous=FULL, trusted_schema=OFF,
                # application_id, user_version — plus query_only=ON is required,
                # exactly as every other authority connection.
                self._apply_connection_local_pragmas(connection)
                self._apply_query_only(connection)
                query_only = connection.execute(
                    "PRAGMA query_only").fetchone()[0]
                metadata_rows = connection.execute(
                    "SELECT COUNT(*) FROM authority_metadata").fetchone()[0]
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority snapshot inspection failed"
                ) from exc
            self._assert_effective_pragmas(connection)
            _require(
                query_only == 1,
                "authority snapshot failed the query_only=ON verification",
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

    def _recheck_file_modes(self) -> None:
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
        # Every dimension that a rename, relink or replacement would disturb.  A
        # same-inode rename-away-and-back still changes st_ctime_ns, so this fully
        # ties the pinned inode across the SQLite open.
        return (
            info.st_dev, info.st_ino, info.st_nlink, info.st_uid, info.st_gid,
            info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        )

    # ------------------------------------------------------------- connections

    @contextlib.contextmanager
    def _operate(self) -> Iterator[sqlite3.Connection]:
        """A verified read-write connection under the cooperative race boundary.

        The process-wide thread lock plus a LOCK_EX on a pinned authority-directory
        descriptor (never the DB descriptor — that yields SQLITE_BUSY on macOS)
        serialize cooperating threads/processes, so the fd-count tie is meaningful.
        The O_NOFOLLOW pin descriptor is held open across the connect; immediately
        after ``sqlite3.connect`` and before any SQL, exactly one additional
        process descriptor must resolve to the pinned inode — proving SQLite opened
        the pinned identity — together with unchanged fstat/path/parent invariants.
        This holds only under the frozen owner-only/cooperative threat model; the
        public stdlib exposes no handle to prove it against a hostile same-UID
        adversary, and nothing here reads CPython private layout.
        """
        with _OPERATION_LOCK:
            self._recheck_file_modes()
            self._revalidate_path_invariants()
            try:
                dir_fd = os.open(
                    str(self._db_path.parent), os.O_RDONLY | os.O_CLOEXEC)
            except OSError as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority directory cannot be pinned"
                ) from exc
            try:
                fcntl.flock(dir_fd, fcntl.LOCK_EX)
                try:
                    with self._verified_connection() as connection:
                        yield connection
                finally:
                    # Post-close DB/-wal/-shm mode recheck runs on EVERY exit —
                    # success or any begin/callback/commit/read exception — while
                    # the lock, directory flock and pin are still held and the
                    # SQLite connection is already closed.
                    self._recheck_file_modes()
            finally:
                os.close(dir_fd)  # releases the directory LOCK_EX

    @contextlib.contextmanager
    def _verified_connection(self) -> Iterator[sqlite3.Connection]:
        try:
            pin_fd = os.open(
                str(self._db_path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise PlanAnchorAuthorityStoreError(
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
            "authority database file identity failed pre-connect verification",
        )
        _read_header_identity(pin_fd)
        pinned = (before.st_dev, before.st_ino)
        before_fingerprint = self._identity_fingerprint(before)
        before_count = _count_pinned_fds(pinned)
        try:
            connection = sqlite3.connect(
                self._db_path.as_uri() + "?mode=rw", uri=True,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise PlanAnchorAuthorityStoreError(
                "authority database connection failed"
            ) from exc
        try:
            # Connection setup and verification.  Any sqlite error HERE (before
            # the yield) is a verification failure; errors raised by the caller
            # during the yielded transaction are not swallowed by this handler.
            try:
                # Immediately after connect and BEFORE any SQL: exactly one new
                # descriptor must resolve to the pinned inode, so SQLite opened
                # the pinned identity and no swap-connect-restore slipped a decoy
                # under it.
                _require(
                    _count_pinned_fds(pinned) == before_count + 1,
                    "SQLite did not open exactly the pinned authority inode; "
                    "aborting without mutation",
                )
                after = os.fstat(pin_fd)
                _require(
                    self._identity_fingerprint(after) == before_fingerprint,
                    "authority database identity changed across the SQLite open; "
                    "aborting without mutation",
                )
                self._pinned_identity_or_fail(pinned, "across the SQLite open")
                self._revalidate_path_invariants()
                connection.row_factory = sqlite3.Row
                # Identity and schema are verified BEFORE any connection-local
                # PRAGMA, and the journal mode is only QUERIED — never switched —
                # so a wrong-app or unknown-schema file is rejected unmodified.
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
                            "verification")
                _verify_exact_schema_and_integrity(connection)
                # These connection-local PRAGMAs never write the database file;
                # each is then read back and required to hold its exact value.
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
                            "verification")
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority connection PRAGMA verification failed"
                ) from exc
            yield connection
        finally:
            connection.close()

    # ------------------------------------------------------------- transactions

    def _begin(self, connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _commit(self, connection: sqlite3.Connection) -> None:
        connection.execute("COMMIT")

    def run_registration_transaction(
        self, callback: Callable[[_RegistrationTransaction], Any]
    ) -> Any:
        with self._operate() as connection:
            try:
                self._begin(connection)
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority transaction cannot acquire the write lock"
                ) from exc
            try:
                outcome = callback(_RegistrationTransaction(connection))
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            try:
                self._commit(connection)
            except sqlite3.Error as exc:
                # The durable outcome of a failed COMMIT is indeterminate.  Never
                # re-sign, retry or claim a rollback happened; a later exact retry
                # inspects the durable row to learn whether this commit won.
                raise PlanAnchorAuthorityStoreError(
                    "authority COMMIT failed with an indeterminate durable "
                    "outcome",
                    commit_indeterminate=True,
                ) from exc
        return outcome

    # ------------------------------------------------------------- fresh reads

    def read_registration(self, request_id: str) -> dict[str, Any] | None:
        with self._operate() as connection:
            try:
                cursor = connection.execute(
                    "SELECT * FROM anchor_registrations WHERE request_id = ?",
                    (str(request_id),),
                )
                row = cursor.fetchone()
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority registration read failed"
                ) from exc
            return None if row is None else {key: row[key] for key in row.keys()}

    def read_metadata(self) -> dict[str, Any] | None:
        with self._operate() as connection:
            try:
                cursor = connection.execute("SELECT * FROM authority_metadata")
                row = cursor.fetchone()
            except sqlite3.Error as exc:
                raise PlanAnchorAuthorityStoreError(
                    "authority metadata read failed"
                ) from exc
            return None if row is None else {key: row[key] for key in row.keys()}


__all__ = [
    "AUTHORITY_DB_APPLICATION_ID",
    "AUTHORITY_DB_USER_VERSION",
    "AUTHORITY_DB_FILENAME",
    "PlanAnchorAuthorityStoreError",
    "PlanAnchorAuthorityStoreV1",
]
