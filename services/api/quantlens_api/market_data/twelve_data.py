"""Fail-closed Twelve Data daily adapter.

The adapter is stateless: bars and their source receipt are returned atomically.  Long
ranges are chunked below the vendor's observation ceiling, and the v1 engine accepts
split-adjusted prices only so reports continue to mean price return without dividends.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .base import (
    AdjustmentMode,
    CanonicalDailyBar,
    CorporateAction,
    FetchedDailySeries,
    InstrumentRef,
    MarketDataError,
    ProviderCapabilities,
    ProviderSourceManifest,
    RateLimited,
    canonical_bars_sha256,
    validate_daily_bars,
)
from .rights import RightsPolicy

JsonRequester = Callable[[str, Mapping[str, str]], Mapping[str, object]]
DateClock = Callable[[], date]

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# Roughly 2,520 US sessions: comfortably below the documented 5,000-observation cap.
MAX_CHUNK_CALENDAR_DAYS = 3650
ADAPTER_VERSION = "twelve-data-eod-v1"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def _business_days(start: date, end_exclusive: date) -> int:
    count = 0
    cursor = start
    while cursor < end_exclusive:
        if cursor.weekday() < 5:
            count += 1
        cursor += timedelta(days=1)
    return count


def _identity_token(value: object) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(value).strip().upper()).strip("_")


def _request_chunks(start: date, end: date) -> tuple[tuple[date, date], ...]:
    chunks: list[tuple[date, date]] = []
    cursor = start
    while cursor <= end:
        chunk_end = min(end, cursor + timedelta(days=MAX_CHUNK_CALENDAR_DAYS))
        chunks.append((cursor, chunk_end))
        cursor = chunk_end + timedelta(days=1)
    return tuple(chunks)


class TwelveDataProvider:
    provider_id = "twelve_data"
    api_base = "https://api.twelvedata.com"

    def __init__(
        self,
        *,
        api_key: str,
        rights_policy: RightsPolicy,
        request_json: JsonRequester | None = None,
        today: DateClock | None = None,
    ) -> None:
        if not api_key.strip():
            raise MarketDataError(
                "MARKET_DATA_CREDENTIAL_MISSING", "A server-side provider key is required."
            )
        if rights_policy.provider_id != self.provider_id:
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "The market-data rights policy names a different provider.",
            )
        self._today = today or (lambda: datetime.now(timezone.utc).date())
        rights_policy.assert_active(as_of=self._today())
        self._api_key = api_key
        self._rights = rights_policy
        self._requester = request_json or self._request_json

    def __repr__(self) -> str:
        return (
            "TwelveDataProvider(api_key=<redacted>, "
            f"rights_policy_sha256={self._rights.sha256()!r})"
        )

    def _request_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        query = urlencode(params)
        request = Request(
            f"{self.api_base}{path}?{query}",
            headers={
                "Accept": "application/json",
                "Authorization": f"apikey {self._api_key}",
                "User-Agent": "QuantLens/market-data-v1",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed HTTPS host
                content_type = str(response.headers.get("Content-Type", "")).lower()
                if not content_type.startswith("application/json"):
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_INVALID",
                        "The provider returned an unexpected response format.",
                    )
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > MAX_RESPONSE_BYTES:
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_TOO_LARGE",
                        "The provider response exceeded the configured safety limit.",
                    )
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_TOO_LARGE",
                        "The provider response exceeded the configured safety limit.",
                    )
                decoded = json.loads(raw.decode("utf-8"))
                if not isinstance(decoded, Mapping):
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_INVALID",
                        "The provider response was not a JSON object.",
                    )
                return decoded
        except HTTPError as exc:
            if exc.code == 429:
                retry = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    retry_seconds = int(retry) if retry is not None else None
                except ValueError:
                    retry_seconds = None
                raise RateLimited(retry_seconds) from None
            raise MarketDataError(
                "MARKET_DATA_PROVIDER_UNAVAILABLE",
                "The configured market-data provider could not complete the request.",
            ) from None
        except MarketDataError:
            raise
        except (URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError,
                TypeError, ValueError):
            raise MarketDataError(
                "MARKET_DATA_PROVIDER_UNAVAILABLE",
                "The configured market-data provider could not complete the request.",
            ) from None

    @staticmethod
    def _provider_error(payload: Mapping[str, object]) -> None:
        if payload.get("status") != "error":
            return
        if str(payload.get("code")) == "429":
            raise RateLimited()
        raise MarketDataError(
            "MARKET_DATA_PROVIDER_REJECTED",
            "The configured market-data provider rejected the request.",
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_id=self.provider_id,
            daily_bars=True,
            intraday_bars=False,
            corporate_actions=False,
            adjustment_modes=(AdjustmentMode.SPLITS,),
        )

    def resolve_instrument(self, symbol: str) -> InstrumentRef:
        normalized = symbol.strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9.]{0,14}", normalized):
            raise MarketDataError("MARKET_DATA_SYMBOL_INVALID", "Enter a valid symbol.")
        payload = self._requester("/symbol_search", {"symbol": normalized})
        self._provider_error(payload)
        matches = payload.get("data")
        if not isinstance(matches, list):
            raise MarketDataError(
                "MARKET_DATA_INSTRUMENT_NOT_FOUND", "The instrument could not be resolved."
            )
        exact: list[tuple[Mapping[str, object], InstrumentRef]] = []
        for item in matches:
            if not isinstance(item, Mapping):
                continue
            if str(item.get("symbol", "")).upper() != normalized:
                continue
            if str(item.get("country", "")).lower() not in {"united states", "us", "usa"}:
                continue
            candidate = InstrumentRef(
                instrument_id=(
                    f"US:{str(item.get('mic_code') or '').strip().upper()}:{normalized}"
                ),
                symbol=normalized,
                display_name=str(item.get("instrument_name") or item.get("name") or normalized),
                asset_class=str(item.get("instrument_type") or item.get("type") or ""),
                currency=str(item.get("currency") or "").strip().upper(),
                mic=str(item.get("mic_code") or "").strip().upper(),
                country="US",
            )
            if candidate.mic and candidate.currency and candidate.asset_class:
                exact.append((item, candidate))
        if not exact:
            raise MarketDataError(
                "MARKET_DATA_INSTRUMENT_NOT_FOUND",
                "The symbol did not resolve to a supported US instrument.",
            )
        licensed: list[tuple[Mapping[str, object], InstrumentRef]] = []
        for item, candidate in exact:
            try:
                self._rights.assert_research_use(candidate, as_of=self._today())
            except MarketDataError:
                continue
            licensed.append((item, candidate))
        if not licensed:
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_SCOPE_MISMATCH",
                "The resolved instrument is outside the activated market-data rights.",
            )
        if len(licensed) != 1:
            raise MarketDataError(
                "MARKET_DATA_INSTRUMENT_AMBIGUOUS",
                "The symbol did not resolve to one licensed US instrument.",
            )
        return licensed[0][1]

    @staticmethod
    def _validate_meta(meta: object, instrument: InstrumentRef) -> Mapping[str, object]:
        if not isinstance(meta, Mapping):
            raise MarketDataError(
                "MARKET_DATA_IDENTITY_UNVERIFIED",
                "The provider response lacked verifiable instrument metadata.",
            )
        if (
            str(meta.get("symbol", "")).upper() != instrument.symbol
            or str(meta.get("interval", "")).lower() != "1day"
            or str(meta.get("currency", "")).upper() != instrument.currency
            or str(meta.get("mic_code", "")).upper() != instrument.mic
            or _identity_token(meta.get("type") or meta.get("instrument_type"))
            != _identity_token(instrument.asset_class)
        ):
            raise MarketDataError(
                "MARKET_DATA_IDENTITY_MISMATCH",
                "The provider response did not match the resolved instrument.",
            )
        timezone_name = str(meta.get("exchange_timezone", ""))
        if timezone_name != "America/New_York":
            raise MarketDataError(
                "MARKET_DATA_IDENTITY_MISMATCH",
                "The provider response used an unexpected exchange timezone.",
            )
        return meta

    @staticmethod
    def _validate_chunk_edges(
        bars: Sequence[CanonicalDailyBar], *, start: date, end: date
    ) -> None:
        if not bars:
            raise MarketDataError("MARKET_DATA_EMPTY", "No daily observations were returned.")
        first = date.fromisoformat(bars[0].session_date)
        last = date.fromisoformat(bars[-1].session_date)
        if first < start or last > end:
            raise MarketDataError(
                "MARKET_DATA_RANGE_MISMATCH",
                "The provider returned observations outside the requested range.",
            )
        if _business_days(start, first) > 3 or _business_days(last + timedelta(days=1), end + timedelta(days=1)) > 3:
            raise MarketDataError(
                "MARKET_DATA_RANGE_TRUNCATED",
                "The provider did not cover the confirmed request window.",
            )

    @staticmethod
    def _validate_internal_continuity(bars: Sequence[CanonicalDailyBar]) -> None:
        """Reject silent internal truncation without pretending weekends are sessions.

        A full exchange calendar is required before activation.  Until that v2 gate is
        present, more than three missing weekdays between adjacent US-ETF observations is
        too large to explain as an ordinary holiday sequence and fails closed.
        """
        for previous, current in zip(bars, bars[1:]):
            previous_day = date.fromisoformat(previous.session_date)
            current_day = date.fromisoformat(current.session_date)
            missing_weekdays = _business_days(
                previous_day + timedelta(days=1), current_day,
            )
            if missing_weekdays > 3:
                raise MarketDataError(
                    "MARKET_DATA_SESSION_GAP",
                    "The provider series contains an unexplained internal session gap.",
                )

    def fetch_daily_series(
        self,
        instrument: InstrumentRef,
        *,
        start: date,
        end: date,
        adjustment_mode: AdjustmentMode,
    ) -> FetchedDailySeries:
        if end < start:
            raise ValueError("end must be on or after start")
        if end > self._today():
            raise MarketDataError(
                "MARKET_DATA_FUTURE_RANGE",
                "Daily market data cannot be sealed for a future date.",
            )
        if adjustment_mode is not AdjustmentMode.SPLITS:
            raise MarketDataError(
                "MARKET_DATA_ADJUSTMENT_UNSUPPORTED",
                "This engine supports split-adjusted price-return data only.",
            )
        self._rights.assert_research_use(instrument, as_of=self._today())

        retrieved_at = datetime.now(timezone.utc).isoformat()
        all_bars: list[CanonicalDailyBar] = []
        chunk_receipts: list[dict[str, object]] = []
        request_records: list[dict[str, str]] = []
        payload_hashes: list[str] = []
        for chunk_start, chunk_end in _request_chunks(start, end):
            params = {
                "symbol": instrument.symbol,
                "mic_code": instrument.mic,
                "country": "United States",
                "type": instrument.asset_class,
                "interval": "1day",
                "start_date": chunk_start.isoformat(),
                "end_date": chunk_end.isoformat(),
                "order": "asc",
                "timezone": "America/New_York",
                "adjust": AdjustmentMode.SPLITS.value,
                "format": "JSON",
            }
            payload = self._requester("/time_series", params)
            self._provider_error(payload)
            self._validate_meta(payload.get("meta"), instrument)
            values = payload.get("values")
            if not isinstance(values, list):
                raise MarketDataError(
                    "MARKET_DATA_PAYLOAD_INVALID",
                    "The provider response contained no daily bars.",
                )
            chunk_bars: list[CanonicalDailyBar] = []
            for item in values:
                if not isinstance(item, Mapping):
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_INVALID", "A provider bar was not an object."
                    )
                session = str(item.get("datetime", ""))
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", session):
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_INVALID",
                        "A provider daily bar had a non-canonical session date.",
                    )
                try:
                    chunk_bars.append(CanonicalDailyBar(
                        instrument_id=instrument.instrument_id,
                        symbol=instrument.symbol,
                        session_date=session,
                        open=float(item["open"]),
                        high=float(item["high"]),
                        low=float(item["low"]),
                        close=float(item["close"]),
                        volume=float(item["volume"]),
                        currency=instrument.currency,
                        mic=instrument.mic,
                        adjustment_mode=AdjustmentMode.SPLITS,
                    ))
                except (KeyError, TypeError, ValueError):
                    raise MarketDataError(
                        "MARKET_DATA_PAYLOAD_INVALID",
                        "A provider bar failed canonical parsing.",
                    ) from None
            validated_chunk = validate_daily_bars(chunk_bars)
            self._validate_chunk_edges(
                validated_chunk, start=chunk_start, end=chunk_end,
            )
            self._validate_internal_continuity(validated_chunk)
            all_bars.extend(validated_chunk)
            payload_sha = "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()
            payload_hashes.append(payload_sha)
            request_records.append(params)
            chunk_receipts.append({
                "requested_start": chunk_start.isoformat(),
                "requested_end": chunk_end.isoformat(),
                "actual_start": validated_chunk[0].session_date,
                "actual_end": validated_chunk[-1].session_date,
                "row_count": len(validated_chunk),
                "provider_payload_sha256": payload_sha,
            })

        validated = validate_daily_bars(all_bars)
        self._validate_internal_continuity(validated)
        normalized_sha = canonical_bars_sha256(validated)
        provider_payload_sha = "sha256:" + hashlib.sha256(
            _canonical_json(payload_hashes)
        ).hexdigest()
        request_sha = "sha256:" + hashlib.sha256(
            _canonical_json({"path": "/time_series", "chunks": request_records})
        ).hexdigest()
        manifest = ProviderSourceManifest(
            provider_id=self.provider_id,
            feed="time_series/1day",
            license_tier=self._rights.account_tier,
            rights_policy_sha256=self._rights.sha256(),
            external_display_approved=self._rights.external_display,
            non_display_analytics_approved=self._rights.non_display_analytics,
            report_export_approved=self._rights.report_export,
            raw_retention_days=self._rights.raw_retention_days,
            derived_artifact_retention_days=(
                self._rights.derived_artifact_retention_days
            ),
            required_attribution=self._rights.required_attribution,
            retrieved_at=retrieved_at,
            timezone="America/New_York",
            adjustment_mode=AdjustmentMode.SPLITS,
            revision=None,
            provider_payload_sha256=provider_payload_sha,
            normalized_rows_sha256=normalized_sha,
            request_sha256=request_sha,
            chunks=tuple(chunk_receipts),
        )
        return FetchedDailySeries(
            instrument=instrument,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            bars=validated,
            source_manifest=manifest,
        )

    def fetch_corporate_actions(
        self, instrument: InstrumentRef, *, start: date, end: date
    ) -> Sequence[CorporateAction]:
        del instrument, start, end
        raise MarketDataError(
            "MARKET_DATA_CAPABILITY_UNAVAILABLE",
            "Separate corporate-action ingestion is not enabled for this provider contract.",
        )
