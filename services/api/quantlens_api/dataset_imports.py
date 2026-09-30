"""Local, fail-closed BYOD CSV ingestion for Gate 4.

Raw bytes enter a quarantine path named only by a server-generated import id.  Inspect
never creates a runnable dataset.  Seal re-reads the bytes, checks the user's explicit
mapping and declarations, normalizes only the six allowed daily OHLCV fields, validates
every row with the worker's runtime rules, and writes immutable provenance artifacts.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import numpy as np
import pandas as pd

from quantlens_schema import load_dataset_manifest_schema
from quantlens_worker.snapshot import (
    DataQualityError,
    SNAPSHOT_IDENTITY_VERSION,
    USER_UPLOAD_EXECUTION,
    _validate_raw_frame,
    canonical_snapshot_identity,
    verify_snapshot_integrity,
)

MAX_UPLOAD_BYTES = 12 * 1024 * 1024
# How many inspected-but-not-yet-sealed uploads one account may hold at once.
# The per-upload size limit above bounds a single request; it does not bound a
# caller who simply repeats the request. On a deployment where anyone may
# register, the shared volume that holds every account's sealed evidence is
# what fills up, so quarantine is bounded per account too.
#
# This used to claim the allowance was freed again by "the existing quarantine
# cleanup". It is not: `cleanup_expired_quarantines` below is callable but
# nothing schedules it, so that sentence described a sweep that never runs while
# five fumbled uploads locked an account out of BYOD entirely. What frees a slot
# is sealing, or `DELETE /dataset-imports/{import_id}` -- the discard control the
# refusal message had been naming for far longer than it existed.
MAX_OPEN_DATASET_IMPORTS = 5
# What was done to the prices before they arrived. The report states what its figures
# mean, so this cannot be a cosmetic label: describing a dividend-adjusted series as
# price return tells a reader their real holding-period return would have been higher
# than the number shown, when the dividends are already in it.
SPLIT_ADJUSTED_PRICE_RETURN = "user_attested_split_adjusted_ohlc"
TOTAL_RETURN = "operator_attested_total_return_ohlc"
PRICE_ADJUSTMENTS = frozenset({SPLIT_ADJUSTED_PRICE_RETURN, TOTAL_RETURN})

# What the dataset card and the preflight tell a reader these numbers mean. Kept beside
# the basis values so the two can never drift into saying different things.
RETURN_BASIS_TEXT = {
    SPLIT_ADJUSTED_PRICE_RETURN:
        "split-adjusted price return only; dividends are not included",
    TOTAL_RETURN:
        "total return; dividends and distributions are reinvested",
}


def _apply_return_basis(quality: dict, price_adjustment: str) -> dict:
    quality["return_basis"] = RETURN_BASIS_TEXT[price_adjustment]
    return quality

MAX_UPLOAD_ROWS = 250_000
MAX_UPLOAD_COLUMNS = 64
PREVIEW_ROWS = 6
DEFAULT_QUARANTINE_TTL_SECONDS = 24 * 60 * 60
REQUIRED_MAPPING = ("date", "open", "high", "low", "close")
ALL_MAPPING = (*REQUIRED_MAPPING, "volume")
ALLOWED_TIMEZONES = (
    "America/New_York", "UTC", "Europe/London", "Asia/Hong_Kong",
    "Asia/Shanghai", "Asia/Tokyo",
)
_HEADER_ALIASES = {
    "date": {"date", "datetime", "timestamp", "time", "session", "tradedate"},
    "open": {"open", "openprice", "pxopen", "adjopen", "adjustedopen"},
    "high": {"high", "highprice", "pxhigh", "adjhigh", "adjustedhigh"},
    "low": {"low", "lowprice", "pxlow", "adjlow", "adjustedlow"},
    "close": {"close", "closeprice", "pxclose", "adjclose", "adjustedclose"},
    "volume": {"volume", "vol", "shares", "sharevolume", "adjvolume"},
}
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _header_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def _json_safe(value: object) -> object:
    if value is None or pd.isna(value):
        return None
    if isinstance(value, (np.integer, np.floating)):
        value = value.item()
    return value if isinstance(value, (str, int, float, bool)) else str(value)


def _mapping_candidate_columns(frame: pd.DataFrame) -> list[str]:
    """Allowlist preview fields by market-data role and compatible value type.

    A blacklist can never enumerate every PII label.  Inspection therefore returns values
    only for recognized date/OHLCV aliases whose non-null cells all parse as the role's
    required type.  Unrecognized extras — including numeric account-like columns — never
    enter the preview or mapping choices.
    """
    alias_to_field = {
        alias: field for field, aliases in _HEADER_ALIASES.items() for alias in aliases
    }
    candidates: list[str] = []
    for column in frame.columns:
        field = alias_to_field.get(_header_key(column))
        if field is None:
            continue
        values = frame[column].dropna()
        if values.empty:
            continue
        if field == "date":
            # Numeric identifiers must not become dates merely because pandas can coerce
            # them to nanosecond timestamps.
            if pd.api.types.is_numeric_dtype(values):
                continue
            text = values.astype(str).str.strip()
            compatible = bool((text != "").all()) and bool(
                pd.to_datetime(text, errors="coerce").notna().all())
        else:
            if pd.api.types.is_bool_dtype(values):
                continue
            compatible = bool(pd.to_numeric(values, errors="coerce").notna().all())
        if compatible:
            candidates.append(str(column))
    return candidates


def _issue(code: str, severity: str, message: str) -> dict:
    return {"code": code, "severity": severity, "message": message}


def quarantine_path(var_dir: Path, import_id: str) -> Path:
    if not re.fullmatch(r"imp_[0-9a-f]{32}", import_id):
        raise DataQualityError("IMPORT_ID_INVALID", "Import identifier is invalid.")
    root = var_dir / "data-imports" / "quarantine"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{import_id}.bin"


def cleanup_expired_quarantines(
    var_dir: Path,
    *,
    ttl_seconds: int = DEFAULT_QUARANTINE_TTL_SECONDS,
    now: datetime | None = None,
    actor_id: str = "local-anonymous",
) -> dict[str, int]:
    """Remove abandoned/rejected quarantine bytes older than the inactivity TTL.

    This is intentionally callable but not scheduled at Gate 4.  Database rows are
    reduced to a terminal, non-sensitive receipt only after the corresponding bytes are
    gone (or already absent).  Safe, old orphan files from a crash between file creation
    and DB insertion are removed as well.  No filesystem name or path is returned.
    """
    if ttl_seconds < 0:
        raise ValueError("ttl_seconds must be non-negative")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    cutoff = current - timedelta(seconds=ttl_seconds)

    # Local import prevents the ingestion module from imposing a DB dependency on its
    # pure inspection/normalization helpers.
    from . import db

    records = db.list_expired_dataset_imports(cutoff.isoformat(), actor_id=actor_id)
    stats = {
        "examined": len(records),
        "removed": 0,
        "already_absent": 0,
        "orphaned_removed": 0,
        "failed": 0,
    }
    for record in records:
        path = quarantine_path(var_dir, record["import_id"])
        existed = path.exists()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            stats["failed"] += 1
            continue
        if db.expire_dataset_import(record["import_id"], actor_id=actor_id):
            stats["removed" if existed else "already_absent"] += 1

    root = var_dir / "data-imports" / "quarantine"
    known_ids = db.list_dataset_import_ids()
    if root.exists():
        cutoff_timestamp = cutoff.timestamp()
        for candidate in root.iterdir():
            match = re.fullmatch(r"(imp_[0-9a-f]{32})\.bin", candidate.name)
            if match is None or match.group(1) in known_ids:
                continue
            try:
                if candidate.is_file() and candidate.stat().st_mtime <= cutoff_timestamp:
                    candidate.unlink()
                    stats["orphaned_removed"] += 1
            except OSError:
                stats["failed"] += 1
    return stats


def _preflight_csv_shape(raw: bytes) -> tuple[int, int]:
    """Count logical CSV records/fields before pandas can allocate a DataFrame.

    The scanner is intentionally small and byte-oriented: CSV structural characters are
    ASCII and cannot occur inside a UTF-8 continuation byte.  It understands RFC-style
    quoted commas, escaped quotes and embedded newlines, but never materializes a row.
    This makes a one-line comma bomb fail as soon as field 65 is encountered and makes
    a tiny-row upload fail as soon as data row 250,001 is encountered.
    """
    index = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    in_quotes = False
    at_field_start = True
    record_has_content = False
    columns = 1
    header_columns: int | None = None
    data_rows = 0

    def finish_record() -> None:
        nonlocal at_field_start, record_has_content, columns, header_columns, data_rows
        if record_has_content:
            if header_columns is None:
                header_columns = columns
            else:
                data_rows += 1
                if data_rows > MAX_UPLOAD_ROWS:
                    raise DataQualityError(
                        "UPLOAD_TOO_MANY_ROWS",
                        f"CSV uploads are limited to {MAX_UPLOAD_ROWS:,} data rows.",
                    )
        at_field_start = True
        record_has_content = False
        columns = 1

    while index < len(raw):
        byte = raw[index]
        if byte == 0:
            raise DataQualityError("UPLOAD_BINARY", "The file contains binary NUL bytes, not plain UTF-8 CSV.")
        if in_quotes:
            if byte == 34:  # quote
                if index + 1 < len(raw) and raw[index + 1] == 34:
                    record_has_content = True
                    index += 2
                    continue
                in_quotes = False
            else:
                record_has_content = True
            index += 1
            continue
        if byte == 34 and at_field_start:  # opening quote
            in_quotes = True
            at_field_start = False
            record_has_content = True
            index += 1
            continue
        if byte == 44:  # comma
            columns += 1
            if columns > MAX_UPLOAD_COLUMNS:
                raise DataQualityError(
                    "UPLOAD_TOO_MANY_COLUMNS",
                    f"CSV records are limited to {MAX_UPLOAD_COLUMNS} columns; an over-wide record was rejected before parsing.",
                )
            at_field_start = True
            record_has_content = True
            index += 1
            continue
        if byte in (10, 13):  # LF or CR/CRLF outside a quoted field
            finish_record()
            if byte == 13 and index + 1 < len(raw) and raw[index + 1] == 10:
                index += 2
            else:
                index += 1
            continue
        # Match pandas' default skip_blank_lines behavior for whitespace-only records.
        if byte not in (9, 11, 12, 32):
            record_has_content = True
        at_field_start = False
        index += 1

    if in_quotes:
        raise DataQualityError(
            "UPLOAD_CSV_INVALID",
            "The CSV has an unterminated quoted field; check for a missing closing quote.",
        )
    finish_record()
    if header_columns is None or data_rows == 0:
        raise DataQualityError("UPLOAD_EMPTY", "The CSV contains headers but no rows.")
    return data_rows, header_columns


def inspect_csv_bytes(raw: bytes) -> dict:
    if not raw:
        raise DataQualityError("UPLOAD_EMPTY", "The selected file is empty.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise DataQualityError(
            "UPLOAD_TOO_LARGE",
            f"CSV uploads are limited to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB in this local build.",
        )
    if raw.startswith((b"PK\x03\x04", b"PAR1")):
        raise DataQualityError(
            "UPLOAD_FORMAT_UNSUPPORTED",
            "This release accepts plain UTF-8 CSV only. XLSX/ZIP and Parquet are rejected rather than decoded unsafely.",
        )
    preflight_rows, preflight_columns = _preflight_csv_shape(raw)
    try:
        frame = pd.read_csv(io.BytesIO(raw), encoding="utf-8-sig", low_memory=False)
    except UnicodeDecodeError as exc:
        raise DataQualityError("UPLOAD_ENCODING", "CSV must be UTF-8; a UTF-8 BOM is accepted.") from exc
    except (pd.errors.ParserError, ValueError) as exc:
        raise DataQualityError("UPLOAD_CSV_INVALID", "The CSV could not be parsed safely.") from exc
    if frame.empty:
        raise DataQualityError("UPLOAD_EMPTY", "The CSV contains headers but no rows.")
    if len(frame) > MAX_UPLOAD_ROWS:
        raise DataQualityError("UPLOAD_TOO_MANY_ROWS", f"Limit: {MAX_UPLOAD_ROWS:,} daily rows.")
    if len(frame.columns) > MAX_UPLOAD_COLUMNS:
        raise DataQualityError("UPLOAD_TOO_MANY_COLUMNS", f"Limit: {MAX_UPLOAD_COLUMNS} columns.")
    # Defense in depth: the cheap preflight and full parser must agree on the basic shape.
    if len(frame) != preflight_rows or len(frame.columns) != preflight_columns:
        raise DataQualityError(
            "UPLOAD_CSV_INVALID",
            "The CSV structure is ambiguous: its parsed row or column count changed during validation.",
        )
    columns = [str(column).strip() for column in frame.columns]
    if any(not column for column in columns) or len(set(columns)) != len(columns):
        raise DataQualityError("UPLOAD_HEADERS_INVALID", "Column names must be non-empty and unique.")
    frame.columns = columns
    candidate_columns = _mapping_candidate_columns(frame)

    by_key = {_header_key(column): column for column in candidate_columns}
    mapping: dict[str, str | None] = {}
    for field in ALL_MAPPING:
        matches = [by_key[alias] for alias in _HEADER_ALIASES[field] if alias in by_key]
        mapping[field] = matches[0] if len(matches) == 1 else None
    if mapping["volume"] is None:
        mapping["volume"] = "__zero__"
    issues = [
        _issue(f"MAP_{field.upper()}_REQUIRED", "blocking",
               f"Choose the CSV column for {field}; QuantLens will not guess it.")
        for field in REQUIRED_MAPPING if mapping[field] is None
    ]
    if mapping["volume"] == "__zero__":
        issues.append(_issue(
            "VOLUME_OPTIONAL", "warning",
            "No volume column was recognized. You may seal volume as zero because the current rule family does not use it.",
        ))
    preview = [
        {column: _json_safe(value) for column, value in row.items()}
        for row in frame[candidate_columns].head(PREVIEW_ROWS).to_dict(orient="records")
    ]
    return {
        "source_format": "csv", "source_size": len(raw),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "row_count": int(len(frame)), "columns": candidate_columns,
        "source_column_count": len(columns),
        "excluded_non_market_column_count": len(columns) - len(candidate_columns),
        # Compatibility field for the current local UI; it carries the same positive-
        # allowlist count and no longer implies a header-name blacklist.
        "redacted_extra_column_count": len(columns) - len(candidate_columns),
        "suggested_mapping": mapping, "preview": preview, "issues": issues,
        "limits": {"max_bytes": MAX_UPLOAD_BYTES, "max_rows": MAX_UPLOAD_ROWS,
                   "max_columns": MAX_UPLOAD_COLUMNS},
    }


def create_import(var_dir: Path, raw: bytes) -> tuple[str, dict]:
    inspection = inspect_csv_bytes(raw)
    import_id = f"imp_{uuid.uuid4().hex}"
    path = quarantine_path(var_dir, import_id)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return import_id, inspection


def finalize_quarantine(var_dir: Path, import_id: str) -> None:
    quarantine_path(var_dir, import_id).unlink(missing_ok=True)


def _dataset_storage_directory(var_dir: Path, actor_id: str, dataset_id: str) -> Path:
    """Resolve only server-valid opaque ownership/dataset identifiers under datasets/."""
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", actor_id)
            or not re.fullmatch(r"ds_[0-9a-f]{32}", dataset_id)):
        raise ValueError("unsafe dataset storage target")
    root = (var_dir / "datasets").resolve()
    candidate = (root / actor_id / dataset_id).resolve()
    if candidate.parent.parent != root:
        raise ValueError("dataset storage target escapes root")
    return candidate


def discard_dataset_directory(var_dir: Path, actor_id: str, dataset_id: str) -> None:
    """Remove only a server-generated, not-yet-registered dataset directory."""
    dataset_root = _dataset_storage_directory(var_dir, actor_id, dataset_id)
    if not dataset_root.exists():
        return
    for path in dataset_root.iterdir():
        if not path.is_file():
            raise ValueError("unexpected nested path in dataset cleanup target")
        path.unlink()
    dataset_root.rmdir()


def _read_quarantined(var_dir: Path, import_id: str, expected_sha256: str) -> bytes:
    try:
        raw = quarantine_path(var_dir, import_id).read_bytes()
    except OSError as exc:
        raise DataQualityError(
            "IMPORT_EXPIRED", "The quarantined upload is unavailable; inspect it again.") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise DataQualityError(
            "UPLOAD_TAMPERED", "The quarantined bytes changed after inspection; sealing was refused.")
    return raw


def _normalize(raw: bytes, mapping: dict[str, str], symbol: str) -> tuple[pd.DataFrame, dict]:
    frame = pd.read_csv(io.BytesIO(raw), encoding="utf-8-sig", low_memory=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    columns = set(frame.columns)
    if set(mapping) != set(ALL_MAPPING):
        raise DataQualityError("MAPPING_INVALID", "Confirm all six canonical fields.")
    selected = [mapping[field] for field in REQUIRED_MAPPING]
    if any(column not in columns for column in selected):
        raise DataQualityError("MAPPING_INVALID", "A mapped column is absent from the CSV.")
    if len(set(selected)) != len(selected):
        raise DataQualityError("MAPPING_INVALID", "Required fields must use different columns.")
    volume_source = mapping["volume"]
    if volume_source != "__zero__" and volume_source not in columns:
        raise DataQualityError("MAPPING_INVALID", "The mapped volume column is absent.")
    if volume_source in selected:
        raise DataQualityError("MAPPING_INVALID", "Volume cannot reuse a date or price column.")

    dates = pd.to_datetime(frame[mapping["date"]], errors="coerce", utc=False)
    if dates.isna().any():
        raise DataQualityError(
            "DATES_INVALID", f"{int(dates.isna().sum())} row(s) contain an unreadable date.")
    if any((d.hour, d.minute, d.second, d.microsecond) != (0, 0, 0, 0) for d in dates):
        raise DataQualityError(
            "INTRADAY_UNSUPPORTED",
            "At least one value includes a time of day. This release accepts daily session dates only.",
        )
    normalized = pd.DataFrame({
        "date": dates.dt.strftime("%Y-%m-%d"),
        "open": frame[mapping["open"]], "high": frame[mapping["high"]],
        "low": frame[mapping["low"]], "close": frame[mapping["close"]],
        "volume": 0 if volume_source == "__zero__" else frame[volume_source],
    })
    coverage = {"start": normalized["date"].iloc[0], "end": normalized["date"].iloc[-1]}
    clean = _validate_raw_frame(normalized, symbol, coverage)
    if len(clean) < 10:
        raise DataQualityError(
            "RANGE_TOO_SPARSE", "At least 10 valid daily rows are required to seal a dataset.")

    expected = pd.bdate_range(coverage["start"], coverage["end"]).strftime("%Y-%m-%d")
    present = set(clean["date"])
    missing = [day for day in expected if day not in present]
    gap, max_gap = 0, 0
    for day in expected:
        gap = 0 if day in present else gap + 1
        max_gap = max(max_gap, gap)
    # The runtime's gap policy is stricter and remains authoritative.  Here the user gets
    # an actionable review before sealing; a >3-day gap is blocked immediately.
    if max_gap > 3:
        raise DataQualityError(
            "GAP_BEYOND_THRESHOLD",
            f"The file has a {max_gap}-business-day gap; the declared policy allows at most 3.",
        )
    close_returns = clean["close"].pct_change().abs().dropna()
    suspicious_jump_dates = clean.loc[
        close_returns[close_returns > 0.45].index, "date"
    ].head(5).tolist()
    zero_volume_ratio = float((clean["volume"] == 0).mean())
    warning_codes = (
        (["VOLUME_FILLED_ZERO"] if volume_source == "__zero__" else [])
        + (["MISSING_BUSINESS_DAYS"] if missing else [])
        + (["SUSPICIOUS_PRICE_JUMP"] if suspicious_jump_dates else [])
        + (["ZERO_VOLUME_HIGH"] if volume_source != "__zero__" and zero_volume_ratio > 0.2 else [])
    )
    issues = []
    if volume_source == "__zero__":
        issues.append(_issue(
            "VOLUME_FILLED_ZERO", "warning",
            "Volume is unavailable and will be stored as zero. The current rule does not use volume.",
        ))
    if missing:
        issues.append(_issue(
            "MISSING_BUSINESS_DAYS", "warning",
            f"{len(missing)} expected weekday session(s) are absent; QuantLens will not fill them silently.",
        ))
    if suspicious_jump_dates:
        issues.append(_issue(
            "SUSPICIOUS_PRICE_JUMP", "warning",
            "One or more close-to-close moves exceed 45%. Re-check the split-adjustment convention.",
        ))
    if volume_source != "__zero__" and zero_volume_ratio > 0.2:
        issues.append(_issue(
            "ZERO_VOLUME_HIGH", "warning",
            f"{zero_volume_ratio:.1%} of rows have zero volume; confirm this is expected for the source.",
        ))
    quality = {
        "row_count": int(len(clean)), "coverage": coverage,
        "missing_business_days": len(missing), "max_consecutive_missing": max_gap,
        "missing_day_examples": missing[:5],
        "volume_policy": "filled_zero" if volume_source == "__zero__" else "mapped",
        "zero_volume_ratio": zero_volume_ratio,
        "suspicious_price_jump_count": int((close_returns > 0.45).sum()),
        "suspicious_price_jump_examples": suspicious_jump_dates,
        "price_min": float(clean[["open", "high", "low", "close"]].min().min()),
        "price_max": float(clean[["open", "high", "low", "close"]].max().max()),
        # Overwritten by _apply_return_basis once the declared adjustment is known. The
        # placeholder is the conservative one: understating what a series contains is
        # safer than promising a reader that dividends are already inside it.
        "return_basis": RETURN_BASIS_TEXT[SPLIT_ADJUSTED_PRICE_RETURN],
        "blocking_issues": 0,
        "warnings": warning_codes,
        "issues": issues,
        "checks": {
            "schema": {"status": "ready", "label": "Schema"},
            "coverage": {"status": "ready", "label": "Coverage"},
            "continuity": {
                "status": "needs_review" if missing else "ready", "label": "Continuity"},
            "prices": {
                "status": "needs_review" if suspicious_jump_dates else "ready",
                "label": "Prices & corporate actions",
            },
        },
        "review_status": "review_required" if warning_codes else "ready_to_seal",
    }
    return clean, quality


def validate_import(var_dir: Path, record: dict, *, symbol: str,
                    mapping: dict[str, str], timezone_name: str,
                    prices_adjusted: bool, rights_attested: bool,
                    price_adjustment: str = SPLIT_ADJUSTED_PRICE_RETURN) -> dict:
    """Re-read quarantined bytes and return a content-bound review receipt.

    This is intentionally separate from sealing: a user must see the quality findings
    before an immutable dataset can be created.  The receipt hash binds the exact bytes,
    mapping and semantic attestations that were reviewed.
    """
    symbol = symbol.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9.]{0,9}", symbol):
        raise DataQualityError("SYMBOL_INVALID", "Use a 1–10 character uppercase symbol.")
    if timezone_name not in ALLOWED_TIMEZONES:
        raise DataQualityError("TIMEZONE_INVALID", "Choose a supported market timezone.")
    if price_adjustment not in PRICE_ADJUSTMENTS:
        raise DataQualityError(
            "PRICE_ADJUSTMENT_INVALID",
            "The declared price-adjustment basis is outside the supported set.",
        )
    if not prices_adjusted:
        raise DataQualityError(
            "ADJUSTMENT_ATTESTATION_REQUIRED",
            "Unadjusted prices require corporate-action metadata, which this release does not yet accept.",
        )
    if not rights_attested:
        raise DataQualityError(
            "RIGHTS_ATTESTATION_REQUIRED",
            "Confirm that you are authorized to use this file for private analysis.",
        )
    raw = _read_quarantined(var_dir, record["import_id"], record["source_sha256"])
    fresh = inspect_csv_bytes(raw)
    if fresh["columns"] != record["columns"] or fresh["row_count"] != record["row_count"]:
        raise DataQualityError("INSPECTION_STALE", "The inspected structure changed before validation.")
    clean, quality = _normalize(raw, mapping, symbol)
    _apply_return_basis(quality, price_adjustment)
    profile = {
        "source_sha256": record["source_sha256"],
        "symbol": symbol,
        "mapping": mapping,
        "timezone": timezone_name,
        "prices_adjusted": True,
        # Bound into the receipt hash: a reader confirms the basis they were shown, so
        # a seal cannot quietly claim a different one than the review displayed.
        "price_adjustment": price_adjustment,
        "rights_attested": True,
        "normalizer_version": "gate4-csv-v1",
        "quality": quality,
    }
    profile_hash = hashlib.sha256(_canonical(profile)).hexdigest()
    return {
        "profile_hash": f"sha256:{profile_hash}",
        "profile": profile,
        "quality": quality,
        "can_seal": True,
        "normalized_preview": [
            {key: _json_safe(value) for key, value in row.items()}
            for row in clean.head(PREVIEW_ROWS).to_dict(orient="records")
        ],
    }


def seal_import(var_dir: Path, record: dict, *, actor_id: str, symbol: str,
                mapping: dict[str, str], timezone_name: str,
                prices_adjusted: bool, rights_attested: bool,
                confirmed_profile_hash: str,
                acknowledged_warnings: list[str],
                price_adjustment: str = SPLIT_ADJUSTED_PRICE_RETURN,
                ) -> tuple[dict, dict, str]:
    validation = validate_import(
        var_dir, record, symbol=symbol, mapping=mapping,
        timezone_name=timezone_name, prices_adjusted=prices_adjusted,
        rights_attested=rights_attested, price_adjustment=price_adjustment,
    )
    if confirmed_profile_hash != validation["profile_hash"]:
        raise DataQualityError(
            "VALIDATION_RECEIPT_STALE",
            "The bytes, mapping, or declarations differ from the validation you reviewed.",
        )
    expected_warnings = set(validation["quality"]["warnings"])
    missing_acknowledgements = sorted(expected_warnings - set(acknowledged_warnings))
    if missing_acknowledgements:
        raise DataQualityError(
            "WARNINGS_NOT_ACKNOWLEDGED",
            "Review and acknowledge these warnings before sealing: "
            + ", ".join(missing_acknowledgements),
        )
    symbol = symbol.strip().upper()
    raw = _read_quarantined(var_dir, record["import_id"], record["source_sha256"])
    fresh = inspect_csv_bytes(raw)
    if (fresh["columns"] != record["columns"] or fresh["row_count"] != record["row_count"]):
        raise DataQualityError("INSPECTION_STALE", "The inspected structure changed before sealing.")
    clean, quality = _normalize(raw, mapping, symbol)
    _apply_return_basis(quality, price_adjustment)

    dataset_id = f"ds_{uuid.uuid4().hex}"
    dataset_root = _dataset_storage_directory(var_dir, actor_id, dataset_id)
    dataset_root.mkdir(parents=True, mode=0o700, exist_ok=False)
    try:
        normalized_path = dataset_root / "normalized.csv"
        clean.to_csv(normalized_path, index=False, lineterminator="\n", float_format="%.10g")
        normalized_bytes = normalized_path.read_bytes()
        normalized_sha = hashlib.sha256(normalized_bytes).hexdigest()
        logical_rows_sha = hashlib.sha256(_canonical(clean.to_dict(orient="records"))).hexdigest()
        quality["source_sha256"] = record["source_sha256"]
        quality["normalized_sha256"] = normalized_sha
        quality["timezone"] = timezone_name
        quality["prices_adjusted_attested"] = True
        quality_bytes = _canonical(quality)
        (dataset_root / "quality_report.json").write_bytes(quality_bytes)
        dataset_manifest = {
            "manifest_version": "dataset-v1", "dataset_id": dataset_id,
            "actor_id": actor_id, "source_format": "csv",
            "source_size": record["source_size"], "source_sha256": record["source_sha256"],
            "mapping": mapping, "timezone": timezone_name,
            "price_adjustment": price_adjustment,
            "rights_attested": True, "symbol": symbol,
            "row_count": quality["row_count"], "coverage": quality["coverage"],
            "normalized_sha256": normalized_sha, "logical_rows_sha256": logical_rows_sha,
            "quality_report_sha256": hashlib.sha256(quality_bytes).hexdigest(),
            "normalizer_version": "gate4-csv-v1", "created_at": _now(),
        }
        jsonschema.validate(
            dataset_manifest, load_dataset_manifest_schema(),
            format_checker=jsonschema.FormatChecker(),
        )
        manifest_bytes = _canonical(dataset_manifest)
        (dataset_root / "dataset_manifest.json").write_bytes(manifest_bytes)
        dataset_manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

        # The engine snapshot contains only the normalized canonical fields.  The
        # generator binds the opaque dataset id, owner and provenance manifest hash.
        engine_csv = dataset_root / f"{symbol}.csv"
        os.link(normalized_path, engine_csv)
        snapshot_meta = {
            "identity_version": SNAPSHOT_IDENTITY_VERSION,
            "label": "USER_UPLOADED",
            "description": "User-provided daily OHLC data normalized locally by QuantLens.",
            "generator": {
                "name": "quantlens-byod-importer", "version": "gate4-csv-v1",
                "dataset_id": dataset_id, "actor_id": actor_id,
                "dataset_manifest_sha256": dataset_manifest_sha,
            },
            "calendar": f"User-provided daily sessions; timezone declared {timezone_name}.",
            "coverage": {symbol: quality["coverage"]},
            "files": {f"{symbol}.csv": normalized_sha}, "splits": {symbol: []},
            "adjustment_convention": "user attested OHLC are split-adjusted; no transform applied",
            "execution": dict(USER_UPLOAD_EXECUTION),
        }
        snapshot_sha, snapshot_id = canonical_snapshot_identity(snapshot_meta)
        snapshot_meta["sha256"] = snapshot_sha
        snapshot_meta["snapshot_id"] = snapshot_id
        (dataset_root / "snapshot.json").write_text(
            json.dumps(snapshot_meta, indent=2, sort_keys=True), encoding="utf-8")
        verified = verify_snapshot_integrity(dataset_root)
    except Exception:
        for path in dataset_root.iterdir():
            if path.is_file():
                path.unlink()
        dataset_root.rmdir()
        raise
    return verified, quality, dataset_manifest_sha
