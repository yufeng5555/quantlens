"""Canonical market-data types and fail-closed validation.

Licensing, acquisition, and revision metadata live in the immutable series receipt;
canonical bars contain only stable market observations and identity semantics.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import date
from enum import Enum
from typing import Protocol, Sequence, runtime_checkable


class AdjustmentMode(str, Enum):
    NONE = "none"
    SPLITS = "splits"
    DIVIDENDS = "dividends"
    ALL = "all"


class MarketDataError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class LicenseNotConfirmed(MarketDataError):
    def __init__(self) -> None:
        super().__init__(
            "MARKET_DATA_LICENSE_NOT_CONFIRMED",
            "Commercial display and derived-research rights have not been confirmed.",
        )


class RateLimited(MarketDataError):
    def __init__(self, retry_after_seconds: int | None = None) -> None:
        super().__init__(
            "MARKET_DATA_RATE_LIMITED",
            "The market-data provider rate limit was reached; retry later.",
        )
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class ProviderCapabilities:
    provider_id: str
    daily_bars: bool
    intraday_bars: bool
    corporate_actions: bool
    adjustment_modes: tuple[AdjustmentMode, ...]
    requires_commercial_rights_confirmation: bool = True


@dataclass(frozen=True)
class InstrumentRef:
    instrument_id: str
    symbol: str
    display_name: str
    asset_class: str
    currency: str
    mic: str
    country: str


@dataclass(frozen=True)
class CanonicalDailyBar:
    instrument_id: str
    symbol: str
    session_date: str
    open: float
    high: float
    low: float
    close: float
    volume: float
    currency: str
    mic: str
    adjustment_mode: AdjustmentMode


@dataclass(frozen=True)
class CorporateAction:
    instrument_id: str
    symbol: str
    ex_date: str
    action_type: str
    split_ratio: float | None = None
    cash_amount: float | None = None
    currency: str | None = None
    source_version: str = ""


@dataclass(frozen=True)
class ProviderSourceManifest:
    provider_id: str
    feed: str
    license_tier: str
    rights_policy_sha256: str
    external_display_approved: bool
    non_display_analytics_approved: bool
    report_export_approved: bool
    raw_retention_days: int
    derived_artifact_retention_days: int
    required_attribution: str
    retrieved_at: str
    timezone: str
    adjustment_mode: AdjustmentMode
    revision: str | None
    provider_payload_sha256: str
    normalized_rows_sha256: str
    request_sha256: str
    chunks: tuple[dict[str, object], ...]

    def public_dict(self) -> dict[str, object]:
        """Return non-secret audit metadata suitable for a sealed dataset.

        The commercial contract reference never enters this object.  Only a digest of
        the complete, versioned rights policy is retained.
        """
        value = asdict(self)
        value["adjustment_mode"] = self.adjustment_mode.value
        return value


@dataclass(frozen=True)
class FetchedDailySeries:
    instrument: InstrumentRef
    requested_start: str
    requested_end: str
    bars: tuple[CanonicalDailyBar, ...]
    source_manifest: ProviderSourceManifest


@runtime_checkable
class MarketDataProvider(Protocol):
    def capabilities(self) -> ProviderCapabilities: ...

    def resolve_instrument(self, symbol: str) -> InstrumentRef: ...

    def fetch_daily_series(
        self,
        instrument: InstrumentRef,
        *,
        start: date,
        end: date,
        adjustment_mode: AdjustmentMode,
    ) -> FetchedDailySeries: ...

    def fetch_corporate_actions(
        self, instrument: InstrumentRef, *, start: date, end: date
    ) -> Sequence[CorporateAction]: ...

def validate_daily_bars(
    bars: Sequence[CanonicalDailyBar],
) -> tuple[CanonicalDailyBar, ...]:
    if not bars:
        raise MarketDataError("MARKET_DATA_EMPTY", "No daily observations were returned.")
    ordered = tuple(bars)
    identities = {(bar.instrument_id, bar.symbol, bar.currency, bar.mic) for bar in ordered}
    if len(identities) != 1:
        raise MarketDataError(
            "MARKET_DATA_IDENTITY_MIXED", "A dataset cannot mix instrument identities."
        )
    dates: list[date] = []
    for bar in ordered:
        try:
            session = date.fromisoformat(bar.session_date)
        except ValueError as exc:
            raise MarketDataError(
                "MARKET_DATA_SESSION_INVALID", "Session dates must use YYYY-MM-DD."
            ) from exc
        dates.append(session)
        prices = (bar.open, bar.high, bar.low, bar.close)
        if any(not math.isfinite(value) or value <= 0 for value in prices):
            raise MarketDataError(
                "MARKET_DATA_PRICE_INVALID", "OHLC values must be finite and positive."
            )
        if bar.low > min(bar.open, bar.close) or bar.high < max(bar.open, bar.close):
            raise MarketDataError(
                "MARKET_DATA_OHLC_INVALID", "Each session must satisfy low ≤ open/close ≤ high."
            )
        if bar.high < bar.low:
            raise MarketDataError(
                "MARKET_DATA_OHLC_INVALID", "Session high cannot be below session low."
            )
        if not math.isfinite(bar.volume) or bar.volume < 0:
            raise MarketDataError(
                "MARKET_DATA_VOLUME_INVALID", "Volume must be finite and non-negative."
            )
        if bar.adjustment_mode != ordered[0].adjustment_mode:
            raise MarketDataError(
                "MARKET_DATA_ADJUSTMENT_MIXED",
                "A dataset cannot mix price-adjustment conventions.",
            )
    if dates != sorted(dates):
        raise MarketDataError(
            "MARKET_DATA_ORDER_INVALID", "Daily observations must be sorted by session date."
        )
    if len(set(dates)) != len(dates):
        raise MarketDataError(
            "MARKET_DATA_DUPLICATE_SESSION", "Duplicate session dates are not allowed."
        )
    return ordered


def validate_freshness(
    bars: Sequence[CanonicalDailyBar], *, as_of: date, max_age_days: int
) -> None:
    if max_age_days < 0:
        raise ValueError("max_age_days must be non-negative")
    validated = validate_daily_bars(bars)
    last_session = date.fromisoformat(validated[-1].session_date)
    age = (as_of - last_session).days
    if age < 0 or age > max_age_days:
        raise MarketDataError(
            "MARKET_DATA_STALE",
            "The latest confirmed market session is outside the allowed freshness window.",
        )


def canonical_bars_sha256(bars: Sequence[CanonicalDailyBar]) -> str:
    validated = validate_daily_bars(bars)
    payload = []
    for bar in validated:
        value = asdict(bar)
        value["adjustment_mode"] = bar.adjustment_mode.value
        payload.append(value)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
