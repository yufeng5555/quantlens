"""Licensed observations -> DatasetManifestV2 -> boundary-specific rights gates.

This module is intentionally server-only.  It stores no provider credential and no raw
contract/order-form reference.  A sealed manifest contains only a digest of the complete
versioned rights policy, the licensed feed identity, canonical observation hashes and the
minimum attribution/use/retention terms required to re-check later use.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping

import jsonschema

from quantlens_schema import load_dataset_manifest_schema
from quantlens_worker.snapshot import (
    LICENSED_PROVIDER_EXECUTION,
    SNAPSHOT_IDENTITY_VERSION,
    canonical_snapshot_identity,
    verify_snapshot_integrity,
)

from .acquisition import DailyDataAcquisition
from .base import InstrumentRef, MarketDataError, canonical_bars_sha256
from .rights import RIGHTS_POLICY_VERSION, RightsPolicy


DATASET_MANIFEST_V2 = "dataset-v2"
LICENSED_NORMALIZER_VERSION = "licensed-daily-v2"


class DatasetRightsOperation(str, Enum):
    SEAL = "seal"
    RUN = "run"
    REPORT = "report"
    EXPORT = "export"


@dataclass(frozen=True)
class LicensedDatasetSeal:
    dataset_id: str
    directory: Path
    manifest: dict[str, object]
    manifest_sha256: str
    snapshot: dict[str, object]
    quality: dict[str, object]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _parse_retrieved_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset retrieval time is missing."
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset retrieval time is invalid."
        ) from None
    if parsed.tzinfo is None:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset retrieval time must include UTC offset."
        )
    return parsed.astimezone(timezone.utc)


def _instrument_from_manifest(manifest: Mapping[str, object]) -> InstrumentRef:
    raw = manifest.get("instrument")
    if not isinstance(raw, Mapping):
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset instrument identity is missing."
        )
    try:
        return InstrumentRef(
            instrument_id=str(raw["instrument_id"]),
            symbol=str(raw["symbol"]),
            display_name=str(raw["display_name"]),
            asset_class=str(raw["asset_class"]),
            currency=str(raw["currency"]),
            mic=str(raw["mic"]),
            country=str(raw["country"]),
        )
    except KeyError:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset instrument identity is incomplete."
        ) from None


def validate_dataset_manifest_v2(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict):
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset manifest must be an object."
        )
    try:
        jsonschema.validate(
            manifest,
            load_dataset_manifest_schema(DATASET_MANIFEST_V2),
            format_checker=jsonschema.FormatChecker(),
        )
    except jsonschema.ValidationError as exc:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID",
            "The licensed dataset manifest does not match DatasetManifestV2.",
        ) from exc
    coverage = manifest["coverage"]
    if date.fromisoformat(coverage["start"]) > date.fromisoformat(coverage["end"]):
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "Dataset coverage is reversed."
        )
    return manifest


def assert_dataset_rights(
    manifest: object,
    *,
    operation: DatasetRightsOperation,
    policy: RightsPolicy,
    as_of: date,
) -> None:
    """Re-check a sealed licensed dataset against the current complete policy.

    The manifest's digest is not treated as authorization by itself.  Every operation
    requires the current server policy, its exact digest, active dates, instrument scope,
    declared use flags, attribution and conservative retention window to still agree.
    """
    value = validate_dataset_manifest_v2(manifest)
    source = value["source"]
    rights = value["rights"]
    use = rights["use"]
    retention = rights["retention"]
    instrument = _instrument_from_manifest(value)

    if (
        policy.policy_version != RIGHTS_POLICY_VERSION
        or policy.provider_id != source["provider_id"]
        or policy.account_tier != source["tier"]
        or policy.sha256() != rights["policy_sha256"]
    ):
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_POLICY_STALE",
            "The sealed dataset no longer matches the current commercial-use policy.",
        )
    if (
        use["non_display_analytics"] is not policy.non_display_analytics
        or use["external_display"] is not policy.external_display
        or use["report_export"] is not policy.report_export
        or retention["raw_days"] != policy.raw_retention_days
        or retention["derived_artifact_days"] != policy.derived_artifact_retention_days
        or rights["required_attribution"] != policy.required_attribution
    ):
        raise MarketDataError(
            "MARKET_DATA_RIGHTS_RECEIPT_MISMATCH",
            "The dataset rights receipt contradicts the current commercial-use policy.",
        )

    if operation in {DatasetRightsOperation.SEAL, DatasetRightsOperation.RUN}:
        policy.assert_research_use(instrument, as_of=as_of)
    elif operation == DatasetRightsOperation.REPORT:
        policy.assert_report_display(instrument, as_of=as_of)
    elif operation == DatasetRightsOperation.EXPORT:
        policy.assert_report_export(as_of=as_of, instrument=instrument)
    else:  # pragma: no cover - Enum keeps public callers inside the closed set
        raise ValueError(f"unsupported dataset rights operation: {operation!r}")

    # The raw vendor payload is never retained by this sealer.  Derived use is bounded
    # conservatively from retrieval; a renewal/re-acquisition can create a new snapshot.
    retrieved = _parse_retrieved_at(value["retrieved_at"])
    last_derived_day = (
        retrieved + timedelta(days=int(retention["derived_artifact_days"]))
    ).date()
    if operation != DatasetRightsOperation.SEAL and as_of > last_derived_day:
        raise MarketDataError(
            "MARKET_DATA_RETENTION_EXPIRED",
            "The licensed dataset is outside its permitted derived-artifact retention window.",
        )


def load_dataset_manifest(directory: Path) -> tuple[dict[str, object], str]:
    try:
        body = (directory / "dataset_manifest.json").read_bytes()
        parsed = json.loads(body)
    except (OSError, json.JSONDecodeError) as exc:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_INVALID", "The sealed dataset manifest is unavailable."
        ) from exc
    version = parsed.get("manifest_version") if isinstance(parsed, dict) else None
    if version == DATASET_MANIFEST_V2:
        validate_dataset_manifest_v2(parsed)
    elif version == "dataset-v1":
        try:
            jsonschema.validate(
                parsed,
                load_dataset_manifest_schema("dataset-v1"),
                format_checker=jsonschema.FormatChecker(),
            )
        except jsonschema.ValidationError as exc:
            raise MarketDataError(
                "MARKET_DATA_MANIFEST_INVALID", "The BYOD dataset manifest is invalid."
            ) from exc
    else:
        raise MarketDataError(
            "MARKET_DATA_MANIFEST_VERSION_UNSUPPORTED",
            "The sealed dataset manifest version is unsupported.",
        )
    return parsed, _sha256(body)


def assert_dataset_directory_rights(
    directory: Path,
    *,
    operation: DatasetRightsOperation,
    policy: RightsPolicy,
    as_of: date,
) -> dict[str, object]:
    manifest, _digest = load_dataset_manifest(directory)
    if manifest.get("manifest_version") == DATASET_MANIFEST_V2:
        assert_dataset_rights(
            manifest, operation=operation, policy=policy, as_of=as_of
        )
    return manifest


def _safe_dataset_directory(var_dir: Path, actor_id: str, dataset_id: str) -> Path:
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", actor_id)
        or not re.fullmatch(r"ds_[0-9a-f]{32}", dataset_id)
    ):
        raise ValueError("unsafe licensed dataset storage target")
    root = (var_dir / "datasets").resolve()
    candidate = (root / actor_id / dataset_id).resolve()
    if candidate.parent.parent != root:
        raise ValueError("licensed dataset storage target escapes root")
    return candidate


def _assert_acquisition_receipt(
    acquisition: DailyDataAcquisition, policy: RightsPolicy
) -> None:
    source = acquisition.source_manifest
    if (
        source.provider_id != policy.provider_id
        or source.license_tier != policy.account_tier
        or source.rights_policy_sha256 != policy.sha256()
        or source.external_display_approved is not policy.external_display
        or source.non_display_analytics_approved is not policy.non_display_analytics
        or source.report_export_approved is not policy.report_export
        or source.raw_retention_days != policy.raw_retention_days
        or source.derived_artifact_retention_days
        != policy.derived_artifact_retention_days
        or source.required_attribution != policy.required_attribution
        or source.normalized_rows_sha256
        != canonical_bars_sha256(acquisition.bars)
    ):
        raise MarketDataError(
            "MARKET_DATA_ACQUISITION_RECEIPT_MISMATCH",
            "The acquisition receipt does not match the current rights policy and rows.",
        )


def seal_licensed_acquisition(
    var_dir: Path,
    acquisition: DailyDataAcquisition,
    *,
    actor_id: str,
    policy: RightsPolicy,
    activation_confirmed: bool = False,
    now: datetime | None = None,
) -> LicensedDatasetSeal:
    """Seal normalized provider data without storing raw payloads or secrets.

    The default is deliberately inert. Production callers must first pass the server's
    explicit provider-activation boundary and then set ``activation_confirmed``; merely
    possessing normalized rows and a policy object cannot make a dataset runnable.
    """
    if not activation_confirmed:
        raise MarketDataError(
            "MARKET_DATA_NOT_ACTIVATED",
            "Licensed market-data sealing is configured but has not been activated.",
        )
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    _assert_acquisition_receipt(acquisition, policy)
    source = acquisition.source_manifest
    instrument = acquisition.instrument
    policy.assert_research_use(instrument, as_of=current.date())

    dataset_id = f"ds_{uuid.uuid4().hex}"
    directory = _safe_dataset_directory(var_dir, actor_id, dataset_id)
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    try:
        normalized_path = directory / "normalized.csv"
        with normalized_path.open("xb") as handle:
            handle.write(acquisition.canonical_csv)
            handle.flush()
            os.fsync(handle.fileno())
        normalized_csv_sha = _sha256(acquisition.canonical_csv)
        quality = {
            "row_count": len(acquisition.bars),
            "coverage": acquisition.coverage,
            "blocking_issues": 0,
            "warnings": [],
            "source": "licensed_provider",
            "identity": {
                "instrument_id": instrument.instrument_id,
                "symbol": instrument.symbol,
                "mic": instrument.mic,
                "currency": instrument.currency,
            },
            "adjustment_mode": source.adjustment_mode.value,
            "raw_payload_retained": False,
        }
        quality_body = _canonical(quality)
        (directory / "quality_report.json").write_bytes(quality_body)
        manifest: dict[str, object] = {
            "manifest_version": DATASET_MANIFEST_V2,
            "dataset_id": dataset_id,
            "actor_id": actor_id,
            "source": {
                "kind": "licensed_provider",
                "provider_id": source.provider_id,
                "feed": source.feed,
                "tier": source.license_tier,
            },
            "instrument": {
                "instrument_id": instrument.instrument_id,
                "symbol": instrument.symbol,
                "display_name": instrument.display_name,
                "asset_class": instrument.asset_class,
                "mic": instrument.mic,
                "currency": instrument.currency,
                "country": instrument.country,
            },
            "frequency": "daily",
            "timezone": source.timezone,
            "adjustment_mode": source.adjustment_mode.value,
            "row_count": len(acquisition.bars),
            "coverage": acquisition.coverage,
            "retrieved_at": source.retrieved_at,
            "revision": source.revision,
            "provider_payload_sha256": source.provider_payload_sha256,
            "normalized_rows_sha256": source.normalized_rows_sha256,
            "normalized_csv_sha256": normalized_csv_sha,
            "quality_report_sha256": _sha256(quality_body),
            "rights": {
                "policy_version": policy.policy_version,
                "policy_sha256": policy.sha256(),
                "use": {
                    "non_display_analytics": policy.non_display_analytics,
                    "external_display": policy.external_display,
                    "report_export": policy.report_export,
                },
                "retention": {
                    "raw_days": policy.raw_retention_days,
                    "derived_artifact_days": policy.derived_artifact_retention_days,
                },
                "required_attribution": policy.required_attribution,
            },
            "normalizer_version": LICENSED_NORMALIZER_VERSION,
            "created_at": current.isoformat(),
        }
        validate_dataset_manifest_v2(manifest)
        assert_dataset_rights(
            manifest,
            operation=DatasetRightsOperation.SEAL,
            policy=policy,
            as_of=current.date(),
        )
        manifest_body = _canonical(manifest)
        (directory / "dataset_manifest.json").write_bytes(manifest_body)
        manifest_sha = _sha256(manifest_body)

        engine_csv = directory / f"{instrument.symbol}.csv"
        os.link(normalized_path, engine_csv)
        snapshot: dict[str, object] = {
            "identity_version": SNAPSHOT_IDENTITY_VERSION,
            "label": "LICENSED_PROVIDER",
            "description": "Licensed daily observations normalized and sealed by QuantLens.",
            "generator": {
                "name": "quantlens-licensed-data-sealer",
                "version": LICENSED_NORMALIZER_VERSION,
                "dataset_id": dataset_id,
                "actor_id": actor_id,
                "dataset_manifest_sha256": manifest_sha.removeprefix("sha256:"),
            },
            "calendar": (
                f"Provider-confirmed {instrument.mic} daily sessions; "
                f"timezone {source.timezone}."
            ),
            "coverage": {instrument.symbol: acquisition.coverage},
            "files": {
                f"{instrument.symbol}.csv": normalized_csv_sha.removeprefix("sha256:")
            },
            "splits": {instrument.symbol: []},
            "adjustment_convention": source.adjustment_mode.value,
            "execution": dict(LICENSED_PROVIDER_EXECUTION),
        }
        snapshot_sha, snapshot_id = canonical_snapshot_identity(snapshot)
        snapshot["sha256"] = snapshot_sha
        snapshot["snapshot_id"] = snapshot_id
        (directory / "snapshot.json").write_text(
            json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8"
        )
        verified = verify_snapshot_integrity(directory)
    except Exception:
        for path in directory.iterdir():
            if path.is_file():
                path.unlink()
        directory.rmdir()
        raise
    return LicensedDatasetSeal(
        dataset_id=dataset_id,
        directory=directory,
        manifest=manifest,
        manifest_sha256=manifest_sha,
        snapshot=verified,
        quality=quality,
    )


__all__ = [
    "DATASET_MANIFEST_V2",
    "DatasetRightsOperation",
    "LICENSED_NORMALIZER_VERSION",
    "LicensedDatasetSeal",
    "assert_dataset_directory_rights",
    "assert_dataset_rights",
    "load_dataset_manifest",
    "seal_licensed_acquisition",
    "validate_dataset_manifest_v2",
]
