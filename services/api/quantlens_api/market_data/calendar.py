"""Exact, version-pinned exchange-session validation for licensed daily data.

This boundary intentionally does *not* approximate exchange sessions with weekdays,
US federal holidays, or a provider's returned rows.  A licensed series is usable only
when its dates exactly equal the sessions produced by a reviewed MIC-to-calendar
mapping and the installed calendar packages match the audited versions below.

Only XNAS is enabled in v1.  Adding another MIC is a product/security review: the new
mapping must be explicit, covered by holiday/exception tests, and released with new
pinned package versions when applicable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol, Sequence, runtime_checkable

from .base import CanonicalDailyBar, InstrumentRef, MarketDataError


PANDAS_MARKET_CALENDARS_VERSION = "5.3.2"
EXCHANGE_CALENDARS_VERSION = "4.13.2"


@dataclass(frozen=True)
class _ReviewedCalendar:
    mic: str
    pandas_market_calendars_name: str
    calendar_id: str


# NASDAQ is the reviewed pandas_market_calendars alias for XNAS.  Do not silently
# substitute NYSE, weekdays, federal holidays, or a provider-specific calendar.
_REVIEWED_CALENDARS: dict[str, _ReviewedCalendar] = {
    "XNAS": _ReviewedCalendar(
        mic="XNAS",
        pandas_market_calendars_name="NASDAQ",
        calendar_id="pandas_market_calendars:NASDAQ",
    ),
}


@dataclass(frozen=True)
class ExchangeCalendarReceipt:
    calendar_id: str
    calendar_version: str
    mic: str
    requested_start: str
    requested_end: str
    expected_session_count: int
    observed_session_count: int
    exact_match: bool = True
    dependency_versions: dict[str, str] = field(default_factory=dict)

    def public_dict(self) -> dict[str, object]:
        return asdict(self)


@runtime_checkable
class ExchangeCalendarVerifier(Protocol):
    def assert_available(self) -> None: ...

    def assert_instrument_supported(self, instrument: InstrumentRef) -> None: ...

    def validate_daily_sessions(
        self,
        instrument: InstrumentRef,
        bars: Sequence[CanonicalDailyBar],
        *,
        start: date,
        end: date,
    ) -> ExchangeCalendarReceipt: ...


class UnavailableExchangeCalendarVerifier:
    """Explicit fail-closed verifier for tests and disabled deployments."""

    error_code = "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE"
    error_message = (
        "Licensed acquisition requires the reviewed, version-pinned exchange-session "
        "calendar runtime."
    )

    def assert_available(self) -> None:
        raise MarketDataError(self.error_code, self.error_message)

    def assert_instrument_supported(self, instrument: InstrumentRef) -> None:
        del instrument
        self.assert_available()

    def validate_daily_sessions(
        self,
        instrument: InstrumentRef,
        bars: Sequence[CanonicalDailyBar],
        *,
        start: date,
        end: date,
    ) -> ExchangeCalendarReceipt:
        del instrument, bars, start, end
        self.assert_available()
        raise AssertionError("unreachable")  # pragma: no cover


class PinnedExchangeCalendarVerifier:
    """Validate XNAS daily rows against the exact reviewed NASDAQ session index."""

    def _calendar_module(self):
        try:
            installed_pmc = version("pandas-market-calendars")
            installed_exchange = version("exchange-calendars")
        except PackageNotFoundError as exc:
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE",
                "The reviewed exchange-session calendar runtime is not installed.",
            ) from exc
        if (
            installed_pmc != PANDAS_MARKET_CALENDARS_VERSION
            or installed_exchange != EXCHANGE_CALENDARS_VERSION
        ):
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_VERSION_MISMATCH",
                "The installed exchange-session calendar versions do not match the "
                "reviewed production pins.",
            )
        try:
            return import_module("pandas_market_calendars")
        except (ImportError, RuntimeError) as exc:
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE",
                "The reviewed exchange-session calendar runtime cannot be loaded.",
            ) from exc

    def assert_available(self) -> None:
        module = self._calendar_module()
        try:
            for spec in _REVIEWED_CALENDARS.values():
                module.get_calendar(spec.pandas_market_calendars_name)
        except Exception as exc:  # noqa: BLE001 - dependency internals stay private
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE",
                "The reviewed exchange-session calendar cannot be initialized.",
            ) from exc

    def assert_instrument_supported(self, instrument: InstrumentRef) -> None:
        self.assert_available()
        if instrument.mic not in _REVIEWED_CALENDARS:
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNSUPPORTED",
                "No reviewed exchange-session calendar is available for this MIC.",
            )

    def _expected_sessions(
        self, *, mic: str, start: date, end: date,
    ) -> tuple[date, ...]:
        if start > end:
            raise MarketDataError(
                "MARKET_DATA_RANGE_INVALID",
                "The market-data start date must not be after the end date.",
            )
        spec = _REVIEWED_CALENDARS.get(mic)
        if spec is None:
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNSUPPORTED",
                "No reviewed exchange-session calendar is available for this MIC.",
            )
        module = self._calendar_module()
        try:
            calendar = module.get_calendar(spec.pandas_market_calendars_name)
            sessions = calendar.valid_days(start_date=start, end_date=end)
        except Exception as exc:  # noqa: BLE001 - dependency internals stay private
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE",
                "The reviewed exchange-session calendar could not produce sessions.",
            ) from exc
        return tuple(timestamp.date() for timestamp in sessions)

    def validate_daily_sessions(
        self,
        instrument: InstrumentRef,
        bars: Sequence[CanonicalDailyBar],
        *,
        start: date,
        end: date,
    ) -> ExchangeCalendarReceipt:
        # Keep these checks here even though canonical provider validation normally
        # runs first.  The calendar is a standalone trust boundary and must fail closed
        # when invoked independently or by a future queue worker.
        observed: list[date] = []
        for bar in bars:
            if bar.mic != instrument.mic:
                raise MarketDataError(
                    "MARKET_DATA_EXCHANGE_CALENDAR_MISMATCH",
                    "An observation MIC does not match the confirmed instrument.",
                )
            try:
                session = date.fromisoformat(bar.session_date)
            except (TypeError, ValueError) as exc:
                raise MarketDataError(
                    "MARKET_DATA_SESSION_INVALID",
                    "Session dates must use YYYY-MM-DD.",
                ) from exc
            if session < start or session > end:
                raise MarketDataError(
                    "MARKET_DATA_EXCHANGE_CALENDAR_MISMATCH",
                    "An observation falls outside the confirmed request range.",
                )
            observed.append(session)

        if len(observed) != len(set(observed)):
            raise MarketDataError(
                "MARKET_DATA_DUPLICATE_SESSION",
                "Duplicate exchange sessions are not allowed.",
            )
        if any(left >= right for left, right in zip(observed, observed[1:])):
            raise MarketDataError(
                "MARKET_DATA_ORDER_INVALID",
                "Exchange sessions must be strictly increasing.",
            )

        expected = self._expected_sessions(
            mic=instrument.mic, start=start, end=end,
        )
        if tuple(observed) != expected:
            raise MarketDataError(
                "MARKET_DATA_EXCHANGE_CALENDAR_MISMATCH",
                "The provider sessions do not exactly match the reviewed exchange "
                "calendar.",
            )

        spec = _REVIEWED_CALENDARS[instrument.mic]
        dependency_versions = {
            "pandas_market_calendars": PANDAS_MARKET_CALENDARS_VERSION,
            "exchange_calendars": EXCHANGE_CALENDARS_VERSION,
        }
        return ExchangeCalendarReceipt(
            calendar_id=spec.calendar_id,
            calendar_version=(
                f"pandas_market_calendars={PANDAS_MARKET_CALENDARS_VERSION};"
                f"exchange_calendars={EXCHANGE_CALENDARS_VERSION}"
            ),
            mic=instrument.mic,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            expected_session_count=len(expected),
            observed_session_count=len(observed),
            exact_match=True,
            dependency_versions=dependency_versions,
        )


def strict_exchange_calendar_available() -> bool:
    """Report only the reviewed, correctly pinned runtime as available."""
    try:
        PinnedExchangeCalendarVerifier().assert_available()
    except MarketDataError:
        return False
    return True


__all__ = [
    "EXCHANGE_CALENDARS_VERSION",
    "PANDAS_MARKET_CALENDARS_VERSION",
    "ExchangeCalendarReceipt",
    "ExchangeCalendarVerifier",
    "PinnedExchangeCalendarVerifier",
    "UnavailableExchangeCalendarVerifier",
    "strict_exchange_calendar_available",
]
