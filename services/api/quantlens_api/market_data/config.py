"""Server-only market-data provider configuration."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Mapping

from .base import MarketDataError, MarketDataProvider
from .calendar import strict_exchange_calendar_available
from .rights import RightsPolicy


def rights_policy_from_env() -> RightsPolicy:
    raw = os.environ.get("QL_MARKET_DATA_RIGHTS_POLICY_JSON", "").strip()
    if not raw:
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_MISSING",
            "A versioned commercial rights policy is required.",
        )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_INVALID",
            "The configured market-data rights policy is invalid.",
        ) from None
    if not isinstance(decoded, Mapping):
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_INVALID",
            "The configured market-data rights policy is invalid.",
        )
    return RightsPolicy.from_mapping(decoded)


def market_data_provider_from_env() -> MarketDataProvider | None:
    provider = os.environ.get("QL_MARKET_DATA_PROVIDER", "").strip().lower()
    if not provider:
        return None
    if provider != "twelve_data":
        raise MarketDataError(
            "MARKET_DATA_PROVIDER_UNKNOWN", "The configured market-data provider is unsupported."
        )
    from .twelve_data import TwelveDataProvider

    return TwelveDataProvider(
        api_key=os.environ.get("QL_TWELVE_DATA_API_KEY", ""),
        rights_policy=activated_rights_policy_from_env(),
    )


def activated_rights_policy_from_env() -> RightsPolicy:
    """Return the current policy only after the explicit licensed-data activation gate.

    A credential or policy file by itself is configuration, not authorization.  This
    helper is used at seal/run/report/export boundaries so a partially configured
    deployment cannot accidentally make licensed observations usable.
    """
    if os.environ.get("QL_MARKET_DATA_PROVIDER", "").strip().lower() != "twelve_data":
        raise MarketDataError(
            "MARKET_DATA_NOT_ACTIVATED",
            "Licensed market data is not activated for this deployment.",
        )
    if not os.environ.get("QL_TWELVE_DATA_API_KEY", "").strip():
        raise MarketDataError(
            "MARKET_DATA_NOT_ACTIVATED",
            "Licensed market data is not activated for this deployment.",
        )
    if os.environ.get("QL_MARKET_DATA_ACTIVATED", "").strip().lower() not in {
        "1", "true", "yes",
    }:
        raise MarketDataError(
            "MARKET_DATA_NOT_ACTIVATED",
            "Licensed market data is configured but has not been activated.",
        )
    policy = rights_policy_from_env()
    policy.assert_active(as_of=datetime.now(timezone.utc).date())
    if policy.provider_id != "twelve_data":
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_INVALID",
            "The active market-data policy does not match the configured provider.",
        )
    return policy


def market_data_public_config() -> dict[str, object]:
    """Return a credential-free readiness view for the product UI."""
    provider = os.environ.get("QL_MARKET_DATA_PROVIDER", "").strip().lower()
    if not provider:
        return {
            "status": "not_configured",
            "provider": None,
            "daily_bars": False,
            "message": "Connect a licensed daily-data provider or import an authorized CSV.",
        }
    if provider != "twelve_data":
        return {
            "status": "unsupported_configuration",
            "provider": provider,
            "daily_bars": False,
            "message": "The configured market-data provider is not supported by this build.",
        }
    has_key = bool(os.environ.get("QL_TWELVE_DATA_API_KEY", "").strip())
    try:
        policy = rights_policy_from_env()
        policy.assert_active(as_of=datetime.now(timezone.utc).date())
    except MarketDataError:
        policy = None
    contract_configured = bool(
        has_key
        and policy is not None
        and policy.provider_id == "twelve_data"
        and policy.external_display
        and policy.non_display_analytics
        and policy.account_tier
    )
    explicitly_activated = os.environ.get(
        "QL_MARKET_DATA_ACTIVATED", ""
    ).strip().lower() in {"1", "true", "yes"}
    operator_activated = contract_configured and explicitly_activated
    calendar_available = strict_exchange_calendar_available()
    activated = operator_activated and calendar_available
    return {
        "status": (
            "activated" if activated else
            "blocked_calendar_unavailable" if operator_activated else
            "configured_not_activated" if contract_configured else
            "configuration_incomplete"
        ),
        "provider": "twelve_data",
        # Activation is a separate operator decision after contract review. Merely
        # installing a credential and policy never makes licensed data runnable.
        "daily_bars": activated,
        "report_export": bool(activated and policy and policy.report_export),
        "message": (
            "Licensed daily data is activated with boundary-specific rights checks."
            if activated else
            "Provider activation is blocked until a pinned exchange-session calendar "
            "is installed and reviewed."
            if operator_activated else
            "Provider credentials and contract policy are configured; licensed data "
            "remains inert until an operator explicitly activates it."
            if contract_configured
            else "Credentials or the versioned commercial-use policy are incomplete."
        ),
    }


__all__ = [
    "activated_rights_policy_from_env",
    "market_data_provider_from_env",
    "market_data_public_config",
    "rights_policy_from_env",
]
