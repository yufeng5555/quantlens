"""Deterministic acquisition boundary between a vendor adapter and dataset sealing."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import date

from .base import (
    AdjustmentMode,
    CanonicalDailyBar,
    InstrumentRef,
    MarketDataError,
    MarketDataProvider,
    ProviderSourceManifest,
    canonical_bars_sha256,
    validate_daily_bars,
)


@dataclass(frozen=True)
class DailyDataAcquisition:
    instrument: InstrumentRef
    bars: tuple[CanonicalDailyBar, ...]
    source_manifest: ProviderSourceManifest
    canonical_csv: bytes

    @property
    def coverage(self) -> dict[str, str]:
        return {
            "start": self.bars[0].session_date,
            "end": self.bars[-1].session_date,
        }


def canonical_daily_bars_csv(bars: tuple[CanonicalDailyBar, ...]) -> bytes:
    """Serialize only the engine's six canonical fields in a stable representation."""
    validated = validate_daily_bars(bars)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("date", "open", "high", "low", "close", "volume"))
    for bar in validated:
        writer.writerow((
            bar.session_date,
            format(bar.open, ".17g"),
            format(bar.high, ".17g"),
            format(bar.low, ".17g"),
            format(bar.close, ".17g"),
            format(bar.volume, ".17g"),
        ))
    return stream.getvalue().encode("utf-8")


def acquire_daily_data(
    provider: MarketDataProvider,
    *,
    symbol: str,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode = AdjustmentMode.SPLITS,
) -> DailyDataAcquisition:
    """Fetch and validate EOD data without writing it or making it runnable.

    Sealing is deliberately a separate step.  This function rejects unsupported
    adjustment semantics, observations outside the requested range, mismatched
    manifests, and short samples before bytes can reach the dataset registry.
    """
    _assert_daily_request_supported(
        provider, start=start, end=end, adjustment_mode=adjustment_mode,
    )
    instrument = provider.resolve_instrument(symbol)
    return _acquire_resolved_daily_data(
        provider,
        instrument=instrument,
        start=start,
        end=end,
        adjustment_mode=adjustment_mode,
    )


def acquire_daily_data_for_instrument(
    provider: MarketDataProvider,
    *,
    instrument: InstrumentRef,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode = AdjustmentMode.SPLITS,
) -> DailyDataAcquisition:
    """Acquire a previously resolved canonical instrument without resolving it twice.

    The user-facing licensed-data flow resolves and displays canonical identity before
    fetching. This entry point preserves that exact binding while repeating every range,
    capability, payload, and manifest validation performed by :func:`acquire_daily_data`.
    """
    _assert_daily_request_supported(
        provider, start=start, end=end, adjustment_mode=adjustment_mode,
    )
    return _acquire_resolved_daily_data(
        provider,
        instrument=instrument,
        start=start,
        end=end,
        adjustment_mode=adjustment_mode,
    )


def _assert_daily_request_supported(
    provider: MarketDataProvider,
    *,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode,
) -> None:
    if end < start:
        raise ValueError("end must be on or after start")
    if (end - start).days > 365 * 40 + 10:
        raise MarketDataError(
            "MARKET_DATA_RANGE_TOO_WIDE",
            "A single daily-data acquisition cannot exceed 40 years.",
        )
    capabilities = provider.capabilities()
    if not capabilities.daily_bars or adjustment_mode not in capabilities.adjustment_modes:
        raise MarketDataError(
            "MARKET_DATA_CAPABILITY_UNAVAILABLE",
            "The configured provider cannot supply the requested daily adjustment mode.",
        )


def _acquire_resolved_daily_data(
    provider: MarketDataProvider,
    *,
    instrument: InstrumentRef,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode,
) -> DailyDataAcquisition:
    capabilities = provider.capabilities()
    fetched = provider.fetch_daily_series(
        instrument,
        start=start,
        end=end,
        adjustment_mode=adjustment_mode,
    )
    if fetched.instrument != instrument:
        raise MarketDataError(
            "MARKET_DATA_BINDING_MISMATCH",
            "The fetched series does not match the resolved instrument.",
        )
    validated = validate_daily_bars(fetched.bars)
    if len(validated) < 10:
        raise MarketDataError(
            "MARKET_DATA_RANGE_TOO_SPARSE",
            "At least 10 validated daily sessions are required for research.",
        )
    if any(
        bar.instrument_id != instrument.instrument_id
        or bar.adjustment_mode != adjustment_mode
        for bar in validated
    ):
        raise MarketDataError(
            "MARKET_DATA_BINDING_MISMATCH",
            "Returned observations do not match the resolved instrument and adjustment mode.",
        )
    first = date.fromisoformat(validated[0].session_date)
    last = date.fromisoformat(validated[-1].session_date)
    if first < start or last > end:
        raise MarketDataError(
            "MARKET_DATA_RANGE_MISMATCH",
            "The provider returned observations outside the confirmed request window.",
        )
    manifest = fetched.source_manifest
    if (
        manifest.provider_id != capabilities.provider_id
        or manifest.adjustment_mode != adjustment_mode
        or manifest.normalized_rows_sha256 != canonical_bars_sha256(validated)
    ):
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_MISMATCH",
            "The provider source receipt does not match the validated observations.",
        )
    return DailyDataAcquisition(
        instrument=instrument,
        bars=validated,
        source_manifest=manifest,
        canonical_csv=canonical_daily_bars_csv(validated),
    )
