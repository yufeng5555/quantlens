"""Versioned, server-only commercial rights policy for licensed market data."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import date
from typing import Mapping

from .base import InstrumentRef, LicenseNotConfirmed, MarketDataError


RIGHTS_POLICY_VERSION = "market-data-rights-v1"


def _token(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.strip().upper()).strip("_")


@dataclass(frozen=True)
class RightsPolicy:
    policy_version: str
    policy_id: str
    provider_id: str
    account_tier: str
    effective_date: str
    expires_date: str
    allowed_mics: tuple[str, ...]
    allowed_asset_classes: tuple[str, ...]
    allowed_currencies: tuple[str, ...]
    external_display: bool
    non_display_analytics: bool
    report_export: bool
    raw_retention_days: int
    derived_artifact_retention_days: int
    required_attribution: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> "RightsPolicy":
        expected = {
            "policy_version", "policy_id", "provider_id", "account_tier",
            "effective_date", "expires_date", "allowed_mics",
            "allowed_asset_classes", "allowed_currencies", "external_display",
            "non_display_analytics", "report_export", "raw_retention_days",
            "derived_artifact_retention_days", "required_attribution",
        }
        if set(raw) != expected:
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "The configured market-data rights policy has missing or unknown fields.",
            )
        sequence_fields = (
            "allowed_mics", "allowed_asset_classes", "allowed_currencies",
        )
        if any(
            not isinstance(raw[field], (list, tuple))
            or isinstance(raw[field], (str, bytes))
            or any(not isinstance(item, str) for item in raw[field])
            for field in sequence_fields
        ) or any(
            type(raw[field]) is not bool
            for field in ("external_display", "non_display_analytics", "report_export")
        ) or any(
            type(raw[field]) is not int
            for field in ("raw_retention_days", "derived_artifact_retention_days")
        ):
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "The configured market-data rights policy contains invalid field types.",
            )
        try:
            policy = cls(
                policy_version=str(raw["policy_version"]),
                policy_id=str(raw["policy_id"]).strip(),
                provider_id=str(raw["provider_id"]).strip().lower(),
                account_tier=str(raw["account_tier"]).strip(),
                effective_date=str(raw["effective_date"]),
                expires_date=str(raw["expires_date"]),
                allowed_mics=tuple(_token(str(v)) for v in raw["allowed_mics"]),
                allowed_asset_classes=tuple(
                    _token(str(v)) for v in raw["allowed_asset_classes"]
                ),
                allowed_currencies=tuple(
                    _token(str(v)) for v in raw["allowed_currencies"]
                ),
                external_display=raw["external_display"] is True,
                non_display_analytics=raw["non_display_analytics"] is True,
                report_export=raw["report_export"] is True,
                raw_retention_days=int(raw["raw_retention_days"]),
                derived_artifact_retention_days=int(
                    raw["derived_artifact_retention_days"]
                ),
                required_attribution=str(raw["required_attribution"]).strip(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "The configured market-data rights policy could not be parsed.",
            ) from None
        policy._validate_shape()
        return policy

    def _validate_shape(self) -> None:
        try:
            effective = date.fromisoformat(self.effective_date)
            expires = date.fromisoformat(self.expires_date)
        except ValueError:
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "Rights-policy dates must use YYYY-MM-DD.",
            ) from None
        if (
            self.policy_version != RIGHTS_POLICY_VERSION
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}", self.policy_id)
            or not self.provider_id
            or not self.account_tier
            or effective > expires
            or not self.allowed_mics
            or not self.allowed_asset_classes
            or not self.allowed_currencies
            or self.raw_retention_days < 1
            or self.derived_artifact_retention_days < 1
            or not self.required_attribution
            or len(self.required_attribution) > 240
            or bool(re.search(r"[\x00-\x1f\x7f-\x9f]", self.required_attribution))
        ):
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_POLICY_INVALID",
                "The configured market-data rights policy is incomplete or inconsistent.",
            )

    def assert_active(self, *, as_of: date) -> None:
        if not (
            date.fromisoformat(self.effective_date)
            <= as_of
            <= date.fromisoformat(self.expires_date)
        ):
            raise LicenseNotConfirmed()

    def assert_research_use(self, instrument: InstrumentRef, *, as_of: date) -> None:
        self.assert_instrument_scope(instrument, as_of=as_of)
        if not self.non_display_analytics:
            raise LicenseNotConfirmed()

    def assert_instrument_scope(self, instrument: InstrumentRef, *, as_of: date) -> None:
        """Re-check active dates and the closed instrument scope at every boundary."""
        self.assert_active(as_of=as_of)
        if (
            _token(instrument.mic) not in self.allowed_mics
            or _token(instrument.asset_class) not in self.allowed_asset_classes
            or _token(instrument.currency) not in self.allowed_currencies
        ):
            raise MarketDataError(
                "MARKET_DATA_RIGHTS_SCOPE_MISMATCH",
                "The instrument falls outside the configured commercial data rights.",
            )

    def assert_report_display(self, instrument: InstrumentRef, *, as_of: date) -> None:
        self.assert_instrument_scope(instrument, as_of=as_of)
        if not self.external_display:
            raise MarketDataError(
                "MARKET_DATA_REPORT_DISPLAY_NOT_LICENSED",
                "The current market-data agreement does not permit report display.",
            )

    def assert_report_export(
        self, *, as_of: date, instrument: InstrumentRef | None = None
    ) -> None:
        if instrument is None:
            self.assert_active(as_of=as_of)
        else:
            self.assert_report_display(instrument, as_of=as_of)
        if not self.report_export:
            raise MarketDataError(
                "MARKET_DATA_REPORT_EXPORT_NOT_LICENSED",
                "The current market-data agreement does not permit report export.",
            )

    def sha256(self) -> str:
        payload = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()


__all__ = ["RIGHTS_POLICY_VERSION", "RightsPolicy"]
