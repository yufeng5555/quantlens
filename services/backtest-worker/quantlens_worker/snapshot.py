"""Synthetic snapshot loading: content-addressed fixture directory + integrity checks,
split back-adjustment, coverage and gap policy (AT-7.2). Local stand-in for the S4
snapshot service; inputs are immutable committed CSVs."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd

from .config import BATTERY_CONFIG

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SNAPSHOT_DIR = REPO_ROOT / "data" / "synthetic"
SNAPSHOT_IDENTITY_VERSION = "snapshot-identity-v1"
REQUIRED_COLUMNS = ("date", "open", "high", "low", "close", "volume")
EXPECTED_EXECUTION = {
    "bar_frequency": "daily",
    "decision_price": "close",
    "fill_price": "next_session_open",
    "date_semantics": "synthetic session date; timezone-free",
}
USER_UPLOAD_EXECUTION = {
    "bar_frequency": "daily",
    "decision_price": "close",
    "fill_price": "next_session_open",
    "date_semantics": "user-declared exchange-local session date; timezone-free after normalization",
}
LICENSED_PROVIDER_EXECUTION = {
    "bar_frequency": "daily",
    "decision_price": "close",
    "fill_price": "next_session_open",
    "date_semantics": (
        "provider-confirmed exchange-local session date; timezone-free after normalization"
    ),
}
ALLOWED_DATA_LABELS = frozenset({
    "SYNTHETIC", "USER_UPLOADED", "LICENSED_PROVIDER",
})


class DataQualityError(Exception):
    """Loud data-quality failure: the run fails with no quota charge (02 §6)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def canonical_snapshot_identity(meta: dict) -> tuple[str, str]:
    """Return the canonical top-level digest and derived snapshot id.

    File bytes are bound through ``files``; the remaining fields bind every input that
    changes coverage, corporate-action adjustment, or execution interpretation.  The two
    self-referential top-level identity fields and descriptive copy are intentionally not
    part of the payload.
    """
    required = (
        "identity_version", "label", "generator", "calendar", "coverage", "files",
        "splits", "adjustment_convention", "execution",
    )
    missing = [key for key in required if key not in meta]
    if missing:
        raise DataQualityError(
            "SNAPSHOT_MANIFEST_INVALID",
            f"Snapshot manifest is missing identity fields: {', '.join(missing)}.")
    if meta["identity_version"] != SNAPSHOT_IDENTITY_VERSION:
        raise DataQualityError(
            "SNAPSHOT_IDENTITY_VERSION",
            f"Unsupported snapshot identity version {meta['identity_version']!r}.")
    payload = {key: meta[key] for key in required}
    try:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise DataQualityError(
            "SNAPSHOT_MANIFEST_INVALID",
            "Snapshot identity metadata must be finite canonical JSON.") from exc
    digest = hashlib.sha256(canonical).hexdigest()
    prefix = {
        "SYNTHETIC": "syn",
        "USER_UPLOADED": "usr",
        "LICENSED_PROVIDER": "lic",
    }.get(meta.get("label"))
    if prefix is None:
        raise DataQualityError(
            "SNAPSHOT_LABEL", "Snapshot label is outside the closed vocabulary."
        )
    return digest, f"{prefix}-{digest[:16]}"


def snapshot_dir() -> Path:
    return Path(os.environ.get("QL_SNAPSHOT_DIR", DEFAULT_SNAPSHOT_DIR))


def load_snapshot_meta(directory: Path | None = None) -> dict:
    d = directory or snapshot_dir()
    manifest_path = d / "snapshot.json"
    try:
        meta = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise DataQualityError(
            "SNAPSHOT_MANIFEST_INVALID", "Snapshot manifest is missing or invalid JSON.") from exc
    if not isinstance(meta, dict):
        raise DataQualityError(
            "SNAPSHOT_MANIFEST_INVALID", "Snapshot manifest must be a JSON object.")
    if meta.get("label") not in ALLOWED_DATA_LABELS:
        raise DataQualityError(
            "SNAPSHOT_LABEL",
            "Snapshot label must be SYNTHETIC, USER_UPLOADED, or LICENSED_PROVIDER.")
    if meta.get("label") in {"USER_UPLOADED", "LICENSED_PROVIDER"}:
        provenance_path = d / "dataset_manifest.json"
        try:
            provenance_bytes = provenance_path.read_bytes()
            provenance = json.loads(provenance_bytes)
        except (OSError, json.JSONDecodeError) as exc:
            raise DataQualityError(
                "DATASET_MANIFEST_INVALID",
                "Dataset-backed snapshot is missing a valid dataset manifest.") from exc
        expected = (meta.get("generator") or {}).get("dataset_manifest_sha256")
        actual = hashlib.sha256(provenance_bytes).hexdigest()
        if expected != actual:
            raise DataQualityError(
                "DATASET_MANIFEST_TAMPERED",
                "Dataset manifest does not match the hash bound into the snapshot.")
        # This enriched copy is sealed into the run's snapshot_ref artifact.  These
        # fields are intentionally outside the canonical snapshot identity because the
        # generator already binds the dataset-manifest hash.
        meta["dataset_manifest_sha256"] = actual
        meta["dataset_manifest"] = provenance
    return meta


def verify_snapshot_integrity(directory: Path | None = None) -> dict:
    """Re-hash files and recompute the canonical metadata-bound snapshot identity."""
    d = directory or snapshot_dir()
    meta = load_snapshot_meta(d)
    files = meta.get("files")
    if not isinstance(files, dict) or not files:
        raise DataQualityError(
            "SNAPSHOT_MANIFEST_INVALID", "Snapshot files must be a non-empty object.")
    verified_files = {}
    for name, expected in sorted(files.items()):
        if not isinstance(name, str) or Path(name).name != name:
            raise DataQualityError(
                "SNAPSHOT_MANIFEST_INVALID", f"Unsafe fixture path in manifest: {name!r}.")
        try:
            actual = hashlib.sha256((d / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise DataQualityError(
                "SNAPSHOT_TAMPERED", f"Fixture {name} is missing or unreadable.") from exc
        if actual != expected:
            raise DataQualityError(
                "SNAPSHOT_TAMPERED",
                f"Fixture {name} does not match the snapshot manifest checksum.")
        verified_files[name] = actual

    identity_meta = dict(meta, files=verified_files)
    actual_sha, actual_id = canonical_snapshot_identity(identity_meta)
    if meta.get("sha256") != actual_sha or meta.get("snapshot_id") != actual_id:
        raise DataQualityError(
            "SNAPSHOT_IDENTITY_MISMATCH",
            "Snapshot sha256/id does not match its canonical files, coverage, splits, "
            "adjustment, and execution metadata.")
    if meta.get("label") == "SYNTHETIC":
        expected_execution = EXPECTED_EXECUTION
    elif meta.get("label") == "USER_UPLOADED":
        expected_execution = USER_UPLOAD_EXECUTION
    else:
        expected_execution = LICENSED_PROVIDER_EXECUTION
    if meta.get("execution") != expected_execution:
        raise DataQualityError(
            "SNAPSHOT_EXECUTION_UNSUPPORTED",
            "Snapshot execution metadata does not match daily close-decision, "
            "next-session-open engine semantics.")
    return meta


def _parse_iso_date(value: object, *, code: str, label: str) -> date:
    if not isinstance(value, str):
        raise DataQualityError(code, f"{label} must be a YYYY-MM-DD string.")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise DataQualityError(code, f"{label} is not a valid calendar date: {value!r}.") from exc
    if parsed.isoformat() != value:
        raise DataQualityError(code, f"{label} must use canonical YYYY-MM-DD format.")
    return parsed


def _validate_splits(splits: list[dict], symbol: str) -> None:
    if not isinstance(splits, list):
        raise DataQualityError(
            "SPLIT_METADATA_INVALID", f"Split metadata for {symbol} must be a list.")
    previous: date | None = None
    for split in splits:
        if not isinstance(split, dict) or set(split) != {"date", "ratio"}:
            raise DataQualityError(
                "SPLIT_METADATA_INVALID",
                f"Every split for {symbol} must contain exactly date and ratio.")
        split_date = _parse_iso_date(
            split["date"], code="SPLIT_METADATA_INVALID", label="split date")
        try:
            ratio = float(split["ratio"])
        except (TypeError, ValueError) as exc:
            raise DataQualityError(
                "SPLIT_METADATA_INVALID", "Split ratio must be finite and positive.") from exc
        if not np.isfinite(ratio) or ratio <= 0:
            raise DataQualityError(
                "SPLIT_METADATA_INVALID", "Split ratio must be finite and positive.")
        if previous is not None and split_date <= previous:
            raise DataQualityError(
                "SPLIT_METADATA_INVALID", "Split dates must be ordered and unique.")
        previous = split_date


def _validate_raw_frame(df: pd.DataFrame, symbol: str, coverage: dict) -> pd.DataFrame:
    if list(df.columns) != list(REQUIRED_COLUMNS):
        raise DataQualityError(
            "OHLC_SCHEMA_INVALID",
            f"{symbol} must have exactly these ordered columns: {', '.join(REQUIRED_COLUMNS)}.")
    if df.empty:
        raise DataQualityError("RANGE_TOO_SPARSE", f"{symbol} fixture contains no bars.")

    raw_dates = df["date"]
    parsed_dates = pd.to_datetime(raw_dates, format="%Y-%m-%d", errors="coerce")
    canonical_dates = parsed_dates.dt.strftime("%Y-%m-%d")
    if parsed_dates.isna().any() or not canonical_dates.equals(raw_dates):
        raise DataQualityError(
            "DATES_INVALID", f"{symbol} contains a missing or non-canonical calendar date.")
    if (parsed_dates.dt.dayofweek >= 5).any():
        raise DataQualityError(
            "DATES_INVALID", f"{symbol} contains weekend bars outside its Mon–Fri calendar.")
    if raw_dates.duplicated().any():
        raise DataQualityError("DATES_DUPLICATE", f"{symbol} contains duplicate dates.")
    if not raw_dates.is_monotonic_increasing:
        raise DataQualityError("DATES_UNORDERED", f"{symbol} dates must be strictly increasing.")

    clean = df.copy()
    for column in REQUIRED_COLUMNS[1:]:
        clean[column] = pd.to_numeric(clean[column], errors="coerce")
    prices = clean[["open", "high", "low", "close"]].to_numpy(dtype=float)
    if not np.isfinite(prices).all() or (prices <= 0).any():
        raise DataQualityError(
            "OHLC_INVALID", f"{symbol} OHLC prices must be finite and strictly positive.")
    invalid_shape = (
        (clean["high"] < clean[["open", "close"]].max(axis=1))
        | (clean["low"] > clean[["open", "close"]].min(axis=1))
        | (clean["low"] > clean["high"])
    )
    if invalid_shape.any():
        raise DataQualityError(
            "OHLC_INVALID",
            f"{symbol} has bars where low/high do not contain both open and close.")
    volume = clean["volume"].to_numpy(dtype=float)
    if not np.isfinite(volume).all() or (volume < 0).any():
        raise DataQualityError(
            "VOLUME_INVALID", f"{symbol} volume must be finite and non-negative.")

    if not isinstance(coverage, dict) or set(coverage) != {"start", "end"}:
        raise DataQualityError(
            "COVERAGE_INVALID", f"Coverage for {symbol} must contain exactly start and end.")
    coverage_start = _parse_iso_date(
        coverage["start"], code="COVERAGE_INVALID", label="coverage start")
    coverage_end = _parse_iso_date(
        coverage["end"], code="COVERAGE_INVALID", label="coverage end")
    if coverage_start > coverage_end:
        raise DataQualityError("COVERAGE_INVALID", "Coverage start must not follow its end.")
    if raw_dates.iloc[0] != coverage["start"] or raw_dates.iloc[-1] != coverage["end"]:
        raise DataQualityError(
            "COVERAGE_MISMATCH",
            f"Coverage metadata for {symbol} does not match the first and last fixture bars.")
    return clean


def _apply_splits(df: pd.DataFrame, splits: list[dict]) -> pd.DataFrame:
    """Back-adjust: for each split (date, ratio), divide all prices strictly before the
    split date by the ratio. Post-split prices are untouched, so a held position's value
    stays continuous across the split (AT-7.4)."""
    df = df.copy()
    for split in splits:
        mask = df["date"] < split["date"]
        ratio = float(split["ratio"])
        for col in ("open", "high", "low", "close"):
            df.loc[mask, col] = df.loc[mask, col] / ratio
        df.loc[mask, "volume"] = df.loc[mask, "volume"] * ratio
    return df


def load_frame(symbol: str, start: str, end: str, directory: Path | None = None) -> tuple[pd.DataFrame, dict]:
    """Load one symbol's adjusted frame for [start, end] plus a data-quality summary.

    Returns (frame indexed 0..n-1 with date/open/close columns, gap_report dict).
    Raises DataQualityError on missing coverage or gaps beyond the declared policy.
    """
    d = directory or snapshot_dir()
    meta = verify_snapshot_integrity(d)
    requested_start = _parse_iso_date(
        start, code="RANGE_INVALID", label="requested start")
    requested_end = _parse_iso_date(end, code="RANGE_INVALID", label="requested end")
    if requested_start > requested_end:
        raise DataQualityError(
            "RANGE_INVALID", f"Requested range start {start} follows end {end}.")

    coverage_map = meta.get("coverage")
    if not isinstance(coverage_map, dict):
        raise DataQualityError(
            "COVERAGE_INVALID", "Snapshot coverage metadata must be an object.")
    coverage = coverage_map.get(symbol)
    if coverage is None:
        raise DataQualityError("SYMBOL_NOT_IN_SNAPSHOT",
                               f"{symbol} is not covered by snapshot {meta['snapshot_id']}.")
    coverage_start = _parse_iso_date(
        coverage.get("start"), code="COVERAGE_INVALID", label="coverage start")
    coverage_end = _parse_iso_date(
        coverage.get("end"), code="COVERAGE_INVALID", label="coverage end")
    if requested_start < coverage_start or requested_end > coverage_end:
        raise DataQualityError(
            "RANGE_OUTSIDE_COVERAGE",
            f"Requested range {start}..{end} exceeds snapshot coverage "
            f"{coverage['start']}..{coverage['end']} for {symbol}.")

    fixture_name = f"{symbol}.csv"
    if fixture_name not in meta["files"]:
        raise DataQualityError(
            "SYMBOL_NOT_IN_SNAPSHOT",
            f"{symbol} has coverage metadata but no fixture in snapshot {meta['snapshot_id']}.")
    try:
        raw = pd.read_csv(d / fixture_name, dtype={"date": str})
    except (OSError, pd.errors.ParserError) as exc:
        raise DataQualityError(
            "OHLC_SCHEMA_INVALID", f"Could not read normalized OHLC fixture for {symbol}.") from exc
    df = _validate_raw_frame(raw, symbol, coverage)
    split_map = meta.get("splits")
    if not isinstance(split_map, dict):
        raise DataQualityError(
            "SPLIT_METADATA_INVALID", "Snapshot splits metadata must be an object.")
    splits = split_map.get(symbol, [])
    _validate_splits(splits, symbol)
    if splits:
        df = _apply_splits(df, splits)
        # Corporate-action math must not turn an otherwise valid raw fixture into
        # non-finite/non-positive or internally inconsistent adjusted OHLC.
        df = _validate_raw_frame(df, symbol, coverage)
    df = df[(df["date"] >= start) & (df["date"] <= end)].reset_index(drop=True)
    if len(df) < 10:
        raise DataQualityError("RANGE_TOO_SPARSE",
                               f"Only {len(df)} bars in range {start}..{end} for {symbol}.")

    # Gap policy is evaluated against the requested boundaries, not the first/last row
    # that happened to survive filtering.  That prevents silent missing leading/trailing
    # business days while retaining the declared small-gap policy.
    expected = pd.bdate_range(start, end).strftime("%Y-%m-%d")
    present = set(df["date"])
    missing = [d_ for d_ in expected if d_ not in present]
    max_gap, run_len, prev_missing = 0, 0, False
    gaps: list[dict] = []
    for d_ in expected:
        if d_ not in present:
            run_len = run_len + 1 if prev_missing else 1
            if run_len == 1:
                gaps.append({"start": d_, "days": 1})
            else:
                gaps[-1]["days"] = run_len
            prev_missing = True
            max_gap = max(max_gap, run_len)
        else:
            prev_missing = False
            run_len = 0
    limit = BATTERY_CONFIG["missing_bars"]["max_consecutive_gap_days"]
    if max_gap > limit:
        raise DataQualityError(
            "GAP_BEYOND_THRESHOLD",
            f"{symbol} has a {max_gap}-day gap in {start}..{end}; the declared policy "
            f"allows at most {limit} consecutive missing days.")
    gap_report = {
        "policy": BATTERY_CONFIG["missing_bars"]["description"],
        "requested_range": {"start": start, "end": end},
        "returned_range": {"start": df["date"].iloc[0], "end": df["date"].iloc[-1]},
        "missing_day_count": len(missing),
        "gaps": gaps,
        "max_consecutive": max_gap,
    }
    return df, gap_report
