"""Neutral Gate E canonicalization for market-observations-v2 economic fields.

This is the accepted Stop A canonicalizer implementation, moved verbatim from the
dormant worker module so the worker wrapper and the neutral final-holdout access
protocol share one market-observation byte law without importing one another.  It
remains a pure, data-only canonicalizer: no producer, snapshot, engine, filesystem,
clock, network or configuration access, and no import beyond the standard library.
The active dataset importer and snapshot producer are unchanged; its only production
importers are the exception-preserving worker wrapper and the neutral
``final_holdout_access_protocol_v1`` module, plus focused tests.

Frozen dtype policy for the economic session scalars (open/high/low/close/volume):

- supported inputs are the built-in ``int`` and IEEE-754 doubles (built-in ``float`` or
  a float subclass such as a NumPy 64-bit floating scalar);
- ``bool``, NaN, infinities, numeric strings (no implicit string-number coercion),
  decimals, complex values, date objects and every other dtype are rejected;
- an integer-valued double canonicalizes to the equal built-in ``int``, so equivalent
  supported integer/float scalar inputs always produce identical canonical bytes;
- prices must be strictly positive and volume non-negative, as in the sealed
  ``market-observations-v2`` schema;
- each session must be internally coherent under the reviewed
  ``FinancialSemanticValidatorV1`` high/low law: a high below any other session price
  or a low above any other session price is an impossible observation and fails.

Sessions canonicalize row by row: the canonical form of one session is a pure function
of that session alone, and ordering checks consult only the immediately preceding date,
so no future row is ever read.  Duplicate or unordered dates, duplicate or unordered
instruments and every non-canonical calendar date fail closed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date
from typing import Any

MARKET_OBSERVATIONS_VERSION = "market-observations-v2"
CANONICALIZATION_POLICY_VERSION = "market-observation-canonicalization-v2"

SESSION_FIELDS = ("date", "open", "high", "low", "close", "volume")
PRICE_FIELDS = ("open", "high", "low", "close")
INSTRUMENT_FIELDS = ("symbol", "currency", "sessions")
TOP_LEVEL_FIELDS = (
    "market_observations_version",
    "snapshot_sha256",
    "exchange_calendar_id",
    "exchange_calendar_version",
    "instruments",
)

_SNAPSHOT_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINTABLE_RE = re.compile(r"^[\x21-\x7e]+$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9.\-]{0,14}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class MarketObservationCanonicalizationError(ValueError):
    """One candidate value violates the frozen market-observation dtype policy."""


def _reject(message: str) -> None:
    raise MarketObservationCanonicalizationError(message)


def canonical_economic_scalar(
    value: object, label: str, *, minimum_exclusive: bool
) -> int | float:
    """Canonicalize one supported economic scalar under the frozen dtype policy."""
    if isinstance(value, bool):
        _reject(f"{label} must be a number, not a bool")
    if type(value) is int:
        result: int | float = int(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            _reject(f"{label} must be finite, not NaN or infinity")
        result = int(value) if float(value).is_integer() else float(value)
    elif isinstance(value, str):
        _reject(f"{label} must be a number; string-number coercion is not performed")
    else:
        _reject(f"{label} has an unsupported dtype: {type(value).__name__}")
    if minimum_exclusive:
        if not result > 0:
            _reject(f"{label} must be strictly positive")
    elif result < 0:
        _reject(f"{label} must be non-negative")
    return result


def _canonical_date(value: object, label: str) -> str:
    if not isinstance(value, str):
        _reject(f"{label} must be a canonical YYYY-MM-DD string")
    assert isinstance(value, str)
    if _DATE_RE.fullmatch(value) is None:
        _reject(f"{label} must be a canonical YYYY-MM-DD string")
    try:
        if date.fromisoformat(value).isoformat() != value:
            raise ValueError
    except ValueError:
        _reject(f"{label} is not a real calendar date")
    return value


def _closed(value: object, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        _reject(f"{label} must have exactly these keys: {', '.join(fields)}")
    assert isinstance(value, dict)
    return value


def canonicalize_session(session: object) -> dict[str, Any]:
    """Canonicalize one OHLCV session from that session's fields alone."""
    row = _closed(session, SESSION_FIELDS, "session")
    canonical: dict[str, Any] = {"date": _canonical_date(row["date"], "session.date")}
    for field in PRICE_FIELDS:
        canonical[field] = canonical_economic_scalar(
            row[field], f"session.{field}", minimum_exclusive=True)
    canonical["volume"] = canonical_economic_scalar(
        row["volume"], "session.volume", minimum_exclusive=False)
    # The reviewed high/low law of FinancialSemanticValidatorV1: the session high is
    # the maximum traded price and the session low the minimum, boundaries inclusive.
    # (Strict positivity is already enforced per scalar above.)
    if (
        canonical["high"] < max(canonical["open"], canonical["close"], canonical["low"])
        or canonical["low"] > min(canonical["open"], canonical["close"], canonical["high"])
    ):
        _reject("session OHLCV values are internally inconsistent")
    return canonical


def canonical_session_bytes(session: object) -> bytes:
    """Canonical JSON bytes of one session; stable under any change to other rows."""
    return _canonical_bytes(canonicalize_session(session))


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MarketObservationCanonicalizationError(
            "canonical market observations must be finite JSON values"
        ) from exc


def _printable(value: object, label: str) -> str:
    if not isinstance(value, str) or _PRINTABLE_RE.fullmatch(value) is None:
        _reject(f"{label} must be a non-empty printable-ASCII string")
    assert isinstance(value, str)
    return value


def canonicalize_instrument(instrument: object) -> dict[str, Any]:
    entry = _closed(instrument, INSTRUMENT_FIELDS, "instrument")
    symbol = entry["symbol"]
    currency = entry["currency"]
    if not isinstance(symbol, str) or _SYMBOL_RE.fullmatch(symbol) is None:
        _reject("instrument.symbol does not match the sealed symbol grammar")
    if not isinstance(currency, str) or _CURRENCY_RE.fullmatch(currency) is None:
        _reject("instrument.currency must be a three-letter uppercase code")
    sessions = entry["sessions"]
    if not isinstance(sessions, list) or not sessions:
        _reject("instrument.sessions must be a non-empty list")
    canonical_sessions: list[dict[str, Any]] = []
    previous_date: str | None = None
    for session in sessions:
        canonical = canonicalize_session(session)
        if previous_date is not None and canonical["date"] <= previous_date:
            _reject("instrument sessions must have unique, strictly increasing dates")
        previous_date = canonical["date"]
        canonical_sessions.append(canonical)
    return {"symbol": symbol, "currency": currency, "sessions": canonical_sessions}


def canonicalize_market_observations_v2(payload: object) -> dict[str, Any]:
    """Canonicalize one complete market-observations-v2 document."""
    document = _closed(payload, TOP_LEVEL_FIELDS, "market observations")
    if document["market_observations_version"] != MARKET_OBSERVATIONS_VERSION:
        _reject("market_observations_version must be " + MARKET_OBSERVATIONS_VERSION)
    snapshot_sha256 = document["snapshot_sha256"]
    if not isinstance(snapshot_sha256, str) or \
            _SNAPSHOT_SHA256_RE.fullmatch(snapshot_sha256) is None:
        _reject("snapshot_sha256 must be sha256: followed by 64 lowercase hex characters")
    canonical: dict[str, Any] = {
        "market_observations_version": MARKET_OBSERVATIONS_VERSION,
        "snapshot_sha256": snapshot_sha256,
        "exchange_calendar_id": _printable(
            document["exchange_calendar_id"], "exchange_calendar_id"),
        "exchange_calendar_version": _printable(
            document["exchange_calendar_version"], "exchange_calendar_version"),
    }
    instruments = document["instruments"]
    if not isinstance(instruments, list) or not instruments:
        _reject("instruments must be a non-empty list")
    canonical_instruments: list[dict[str, Any]] = []
    previous_key: tuple[str, str] | None = None
    for instrument in instruments:
        entry = canonicalize_instrument(instrument)
        key = (entry["symbol"], entry["currency"])
        if previous_key is not None and key <= previous_key:
            _reject("instruments must be unique and canonically ordered")
        previous_key = key
        canonical_instruments.append(entry)
    canonical["instruments"] = canonical_instruments
    return canonical


def canonical_market_observations_v2_bytes(payload: object) -> bytes:
    return _canonical_bytes(canonicalize_market_observations_v2(payload))


def canonical_market_observations_v2_sha256(payload: object) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_market_observations_v2_bytes(payload)).hexdigest()


__all__ = [
    "CANONICALIZATION_POLICY_VERSION",
    "INSTRUMENT_FIELDS",
    "MARKET_OBSERVATIONS_VERSION",
    "MarketObservationCanonicalizationError",
    "PRICE_FIELDS",
    "SESSION_FIELDS",
    "TOP_LEVEL_FIELDS",
    "canonical_economic_scalar",
    "canonical_market_observations_v2_bytes",
    "canonical_market_observations_v2_sha256",
    "canonical_session_bytes",
    "canonicalize_instrument",
    "canonicalize_market_observations_v2",
    "canonicalize_session",
]
