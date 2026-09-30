"""Tenant-scoped orchestration for licensed daily-data acquisition jobs.

This module is the only product path that may connect a configured provider to the
immutable DatasetManifestV2 registry. It deliberately keeps acquisition synchronous for
the local v1 control plane while persisting every state transition; a durable external
queue can later call the same orchestration function without changing API receipts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone

from .. import db
from ..dataset_imports import discard_dataset_directory
from .acquisition import acquire_daily_data_for_instrument
from .base import (
    AdjustmentMode,
    InstrumentRef,
    MarketDataError,
    MarketDataProvider,
)
from .calendar import (
    ExchangeCalendarReceipt,
    ExchangeCalendarVerifier,
    PinnedExchangeCalendarVerifier,
)
from .config import activated_rights_policy_from_env, market_data_provider_from_env
from .dataset_manifest import seal_licensed_acquisition
from .rights import RightsPolicy


logger = logging.getLogger("quantlens.market_data")


@dataclass(frozen=True)
class LicensedDataRuntime:
    provider: MarketDataProvider
    policy: RightsPolicy
    calendar: ExchangeCalendarVerifier


def licensed_data_runtime_from_env() -> LicensedDataRuntime:
    """Build the server-only runtime after the explicit operator activation gate."""
    policy = activated_rights_policy_from_env()
    calendar = PinnedExchangeCalendarVerifier()
    # Keep every licensed route inert before a provider adapter can make a paid/network
    # request.  Package/version/calendar checks are part of activation, not post-fetch
    # quality cleanup.
    calendar.assert_available()
    provider = market_data_provider_from_env()
    if provider is None:  # activation above makes this unreachable, kept fail closed
        raise MarketDataError(
            "MARKET_DATA_NOT_ACTIVATED",
            "Licensed market data is not activated for this deployment.",
        )
    return LicensedDataRuntime(
        provider=provider,
        policy=policy,
        calendar=calendar,
    )


def _canonical_sha256(value: object) -> str:
    body = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _provider_id(runtime: LicensedDataRuntime) -> str:
    provider_id = runtime.provider.capabilities().provider_id
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,39}", provider_id):
        raise MarketDataError(
            "MARKET_DATA_PROVIDER_INVALID",
            "The configured market-data provider identity is invalid.",
        )
    if runtime.policy.provider_id != provider_id:
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_INVALID",
            "The active market-data policy does not match the configured provider.",
        )
    return provider_id


def _safe_identity_text(value: str, *, field: str, max_length: int = 160) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or re.search(r"[\x00-\x1f\x7f-\x9f]", normalized)
    ):
        raise MarketDataError(
            "MARKET_DATA_IDENTITY_UNVERIFIED",
            f"The resolved instrument {field} is invalid.",
        )
    return normalized


def canonical_instrument_view(instrument: InstrumentRef) -> dict[str, str]:
    """Allowlist provider identity fields; never reflect an arbitrary payload."""
    return {
        "instrument_id": _safe_identity_text(
            instrument.instrument_id, field="identifier", max_length=120,
        ),
        "symbol": _safe_identity_text(instrument.symbol, field="symbol", max_length=16),
        "display_name": _safe_identity_text(
            instrument.display_name, field="display name", max_length=160,
        ),
        "asset_class": _safe_identity_text(
            instrument.asset_class, field="asset class", max_length=80,
        ),
        "currency": _safe_identity_text(
            instrument.currency, field="currency", max_length=12,
        ),
        "mic": _safe_identity_text(instrument.mic, field="MIC", max_length=12),
        "country": _safe_identity_text(
            instrument.country, field="country", max_length=40,
        ),
    }


def resolve_canonical_instrument(
    runtime: LicensedDataRuntime, *, symbol: str,
) -> tuple[InstrumentRef, dict[str, object]]:
    provider_id = _provider_id(runtime)
    normalized = symbol.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9.]{0,14}", normalized):
        raise MarketDataError("MARKET_DATA_SYMBOL_INVALID", "Enter a valid symbol.")
    instrument = runtime.provider.resolve_instrument(normalized)
    runtime.policy.assert_research_use(
        instrument, as_of=datetime.now(timezone.utc).date(),
    )
    # Reject an unreviewed MIC immediately after identity resolution and before any
    # daily-series request can incur provider usage or enter the sealing pipeline.
    runtime.calendar.assert_instrument_supported(instrument)
    identity = canonical_instrument_view(instrument)
    if identity["symbol"] != normalized:
        raise MarketDataError(
            "MARKET_DATA_IDENTITY_MISMATCH",
            "The provider resolved a different symbol than the confirmed request.",
        )
    return instrument, {
        "provider": provider_id,
        "instrument": identity,
        "frequency": "daily",
        "adjustment_mode": AdjustmentMode.SPLITS.value,
        "return_basis": "split-adjusted price return; dividends are not included",
        "required_attribution": runtime.policy.required_attribution,
    }


def acquisition_request_sha256(
    runtime: LicensedDataRuntime,
    *,
    symbol: str,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode,
    confirmed_instrument_id: str,
    tenant_id: str,
    user_id: str,
) -> str:
    """Hash only canonical acquisition identity, scoped by current rights digest."""
    return _canonical_sha256({
        "provider_id": _provider_id(runtime),
        "rights_policy_sha256": runtime.policy.sha256(),
        "symbol": symbol.strip().upper(),
        "start": start.isoformat(),
        "end": end.isoformat(),
        "adjustment_mode": adjustment_mode.value,
        "confirmed_instrument_id": confirmed_instrument_id.strip(),
        # Hashes are not correlatable across principals even if two tenants submit the
        # same request. SQL uniqueness is also scoped by this exact ownership tuple.
        "tenant_id": tenant_id,
        "user_id": user_id,
    })


def acquisition_public_view(job: dict) -> dict[str, object]:
    """Return a safe status receipt with no ownership, retry token, rows, or secrets."""
    return {
        key: job[key]
        for key in (
            "acquisition_id", "provider_id", "request_sha256", "symbol",
            "requested_start", "requested_end", "adjustment_mode",
            "confirmed_instrument_id", "display_name", "status", "history",
            "instrument", "calendar_validation", "dataset_id", "error",
            "created_at", "updated_at",
        )
    }


def _calendar_receipt(
    receipt: ExchangeCalendarReceipt,
    *,
    instrument: InstrumentRef,
    row_count: int,
    start: date,
    end: date,
) -> dict[str, object]:
    value = receipt.public_dict()
    if (
        receipt.exact_match is not True
        or receipt.mic != instrument.mic
        or receipt.requested_start != start.isoformat()
        or receipt.requested_end != end.isoformat()
        or receipt.observed_session_count != row_count
        or receipt.expected_session_count != row_count
        or not receipt.calendar_id
        or not receipt.calendar_version
    ):
        raise MarketDataError(
            "MARKET_DATA_EXCHANGE_CALENDAR_MISMATCH",
            "The provider sessions do not exactly match the reviewed exchange calendar.",
        )
    return value


def _fail_job(
    job: dict,
    error: MarketDataError,
    *,
    tenant_id: str,
    user_id: str,
) -> dict:
    return db.transition_market_data_acquisition_for_principal(
        job["acquisition_id"],
        "failed",
        tenant_id=tenant_id,
        user_id=user_id,
        error={"code": error.code, "message": str(error)},
    )


def create_and_process_acquisition(
    runtime: LicensedDataRuntime,
    *,
    symbol: str,
    start: date,
    end: date,
    adjustment_mode: AdjustmentMode,
    confirmed_instrument_id: str,
    display_name: str,
    idempotency_key: str,
    tenant_id: str,
    user_id: str,
) -> tuple[dict, bool]:
    """Persist, execute, seal, and register one canonical request or reuse it."""
    provider_id = _provider_id(runtime)
    normalized_symbol = symbol.strip().upper()
    request_sha = acquisition_request_sha256(
        runtime,
        symbol=normalized_symbol,
        start=start,
        end=end,
        adjustment_mode=adjustment_mode,
        confirmed_instrument_id=confirmed_instrument_id,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    job, created = db.create_or_get_market_data_acquisition(
        provider_id=provider_id,
        request_sha256=request_sha,
        idempotency_key=idempotency_key,
        symbol=normalized_symbol,
        requested_start=start.isoformat(),
        requested_end=end.isoformat(),
        adjustment_mode=adjustment_mode.value,
        confirmed_instrument_id=confirmed_instrument_id.strip(),
        display_name=display_name.strip(),
        tenant_id=tenant_id,
        user_id=user_id,
    )
    if not created:
        db.record_market_data_usage(
            acquisition_id=job["acquisition_id"],
            provider_id=provider_id,
            operation="acquisition_reuse",
            symbol=normalized_symbol,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            provider_request_count=0,
            cache_hit=True,
            outcome="reused",
            tenant_id=tenant_id,
            user_id=user_id,
        )
        return job, False

    seal = None
    dataset = None
    try:
        # A business-day approximation is not allowed to trigger paid provider calls.
        # The production default raises here before resolve/fetch; exact test calendars
        # exercise the complete flow without weakening this release blocker.
        try:
            runtime.calendar.assert_available()
        except MarketDataError as exc:
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="calendar_gate",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                provider_request_count=0,
                cache_hit=False,
                outcome="failed",
                error_code=exc.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, exc, tenant_id=tenant_id, user_id=user_id), True

        job = db.transition_market_data_acquisition_for_principal(
            job["acquisition_id"], "resolving",
            tenant_id=tenant_id, user_id=user_id,
        )
        try:
            instrument, _public = resolve_canonical_instrument(
                runtime, symbol=normalized_symbol,
            )
        except MarketDataError as exc:
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="instrument_resolve",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                provider_request_count=1,
                cache_hit=False,
                outcome="failed",
                error_code=exc.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, exc, tenant_id=tenant_id, user_id=user_id), True
        except Exception as exc:  # noqa: BLE001 - provider exceptions stay private
            logger.error(
                "licensed resolve failed acquisition_id=%s exception_type=%s",
                job["acquisition_id"], type(exc).__name__,
            )
            safe = MarketDataError(
                "MARKET_DATA_PROVIDER_UNAVAILABLE",
                "The configured market-data provider could not complete the request.",
            )
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="instrument_resolve",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                provider_request_count=1,
                cache_hit=False,
                outcome="failed",
                error_code=safe.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, safe, tenant_id=tenant_id, user_id=user_id), True
        db.record_market_data_usage(
            acquisition_id=job["acquisition_id"],
            provider_id=provider_id,
            operation="instrument_resolve",
            symbol=normalized_symbol,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            provider_request_count=1,
            cache_hit=False,
            outcome="succeeded",
            tenant_id=tenant_id,
            user_id=user_id,
        )
        identity = canonical_instrument_view(instrument)
        if identity["instrument_id"] != confirmed_instrument_id.strip():
            return _fail_job(
                job,
                MarketDataError(
                    "MARKET_DATA_INSTRUMENT_CONFIRMATION_STALE",
                    "The confirmed instrument no longer matches the provider resolution.",
                ),
                tenant_id=tenant_id,
                user_id=user_id,
            ), True

        job = db.transition_market_data_acquisition_for_principal(
            job["acquisition_id"], "fetching",
            tenant_id=tenant_id, user_id=user_id, instrument=identity,
        )
        try:
            acquired = acquire_daily_data_for_instrument(
                runtime.provider,
                instrument=instrument,
                start=start,
                end=end,
                adjustment_mode=adjustment_mode,
            )
        except MarketDataError as exc:
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="daily_fetch",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                # The adapter is one high-level call. A failed multi-chunk vendor call
                # cannot report exact partial chunk usage until a telemetry hook exists.
                provider_request_count=1,
                cache_hit=False,
                outcome="failed",
                error_code=exc.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, exc, tenant_id=tenant_id, user_id=user_id), True
        except Exception as exc:  # noqa: BLE001 - provider exceptions stay private
            logger.error(
                "licensed fetch failed acquisition_id=%s exception_type=%s",
                job["acquisition_id"], type(exc).__name__,
            )
            safe = MarketDataError(
                "MARKET_DATA_PROVIDER_UNAVAILABLE",
                "The configured market-data provider could not complete the request.",
            )
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="daily_fetch",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                provider_request_count=1,
                cache_hit=False,
                outcome="failed",
                error_code=safe.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, safe, tenant_id=tenant_id, user_id=user_id), True
        db.record_market_data_usage(
            acquisition_id=job["acquisition_id"],
            provider_id=provider_id,
            operation="daily_fetch",
            symbol=normalized_symbol,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            provider_request_count=max(1, len(acquired.source_manifest.chunks)),
            cache_hit=False,
            outcome="succeeded",
            tenant_id=tenant_id,
            user_id=user_id,
        )

        try:
            calendar = runtime.calendar.validate_daily_sessions(
                instrument,
                acquired.bars,
                start=start,
                end=end,
            )
            calendar_value = _calendar_receipt(
                calendar,
                instrument=instrument,
                row_count=len(acquired.bars),
                start=start,
                end=end,
            )
        except MarketDataError as exc:
            db.record_market_data_usage(
                acquisition_id=job["acquisition_id"],
                provider_id=provider_id,
                operation="calendar_gate",
                symbol=normalized_symbol,
                requested_start=start.isoformat(),
                requested_end=end.isoformat(),
                provider_request_count=0,
                cache_hit=False,
                outcome="failed",
                error_code=exc.code,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            return _fail_job(job, exc, tenant_id=tenant_id, user_id=user_id), True
        db.record_market_data_usage(
            acquisition_id=job["acquisition_id"],
            provider_id=provider_id,
            operation="calendar_gate",
            symbol=normalized_symbol,
            requested_start=start.isoformat(),
            requested_end=end.isoformat(),
            provider_request_count=0,
            cache_hit=False,
            outcome="succeeded",
            tenant_id=tenant_id,
            user_id=user_id,
        )
        job = db.transition_market_data_acquisition_for_principal(
            job["acquisition_id"], "validated",
            tenant_id=tenant_id, user_id=user_id,
            calendar_validation=calendar_value,
        )

        seal = seal_licensed_acquisition(
            db.var_dir(),
            acquired,
            actor_id=tenant_id,
            policy=runtime.policy,
            activation_confirmed=True,
        )
        try:
            dataset = db.register_licensed_dataset_for_principal(
                dataset_id=seal.dataset_id,
                display_name=display_name.strip(),
                symbol=seal.manifest["instrument"]["symbol"],
                dataset_manifest_sha256=seal.manifest_sha256,
                snapshot_id=seal.snapshot["snapshot_id"],
                snapshot_sha256=seal.snapshot["sha256"],
                provider_payload_sha256=seal.manifest["provider_payload_sha256"],
                quality=seal.quality,
                relative_storage_key=f"{tenant_id}/{seal.dataset_id}",
                tenant_id=tenant_id,
                user_id=user_id,
                acquisition_id=job["acquisition_id"],
            )
        except Exception:
            # Registration + terminal transition are one transaction. A post-commit
            # ownership read can still fail independently, so recover only when both
            # records prove the transaction reached its terminal state.
            dataset = db.get_dataset_for_principal(
                seal.dataset_id, tenant_id, user_id,
            )
            persisted_job = db.get_market_data_acquisition_for_principal(
                job["acquisition_id"], tenant_id, user_id,
            )
            if (
                dataset is not None
                and persisted_job is not None
                and persisted_job["status"] == "sealed"
                and persisted_job["dataset_id"] == dataset["dataset_id"]
            ):
                return persisted_job, True
            if dataset is None:
                discard_dataset_directory(db.var_dir(), tenant_id, seal.dataset_id)
                seal = None
            raise
        job = db.get_market_data_acquisition_for_principal(
            job["acquisition_id"], tenant_id, user_id,
        )
        if job is None or job["status"] != "sealed":  # pragma: no cover - DB invariant
            raise db.MarketDataAcquisitionStateError(
                "sealed licensed acquisition is unavailable after commit"
            )
        return job, True
    except MarketDataError as exc:
        if seal is not None and dataset is None:
            discard_dataset_directory(db.var_dir(), tenant_id, seal.dataset_id)
        return _fail_job(job, exc, tenant_id=tenant_id, user_id=user_id), True
    except Exception as exc:  # noqa: BLE001 - sanitize provider/DB failures at boundary
        if seal is not None and dataset is None:
            discard_dataset_directory(db.var_dir(), tenant_id, seal.dataset_id)
        logger.error(
            "licensed acquisition failed acquisition_id=%s exception_type=%s",
            job["acquisition_id"], type(exc).__name__,
        )
        safe = MarketDataError(
            "MARKET_DATA_ACQUISITION_FAILED",
            "The licensed dataset could not be acquired and sealed consistently.",
        )
        return _fail_job(job, safe, tenant_id=tenant_id, user_id=user_id), True


__all__ = [
    "LicensedDataRuntime",
    "acquisition_public_view",
    "acquisition_request_sha256",
    "canonical_instrument_view",
    "create_and_process_acquisition",
    "licensed_data_runtime_from_env",
    "resolve_canonical_instrument",
]
