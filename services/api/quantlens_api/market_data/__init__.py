"""Provider-neutral market-data contracts for QuantLens.

The research engine never calls a vendor directly.  A provider adapter first returns
canonical, validated observations plus a source manifest; a separate ingestion step can
then seal those observations into the same immutable dataset boundary used by BYOD CSVs.
"""

from .base import (
    AdjustmentMode,
    CanonicalDailyBar,
    CorporateAction,
    FetchedDailySeries,
    InstrumentRef,
    LicenseNotConfirmed,
    MarketDataError,
    MarketDataProvider,
    ProviderCapabilities,
    ProviderSourceManifest,
    RateLimited,
    canonical_bars_sha256,
    validate_daily_bars,
    validate_freshness,
)
from .acquisition import (
    DailyDataAcquisition,
    acquire_daily_data,
    acquire_daily_data_for_instrument,
    canonical_daily_bars_csv,
)
from .calendar import (
    ExchangeCalendarReceipt,
    ExchangeCalendarVerifier,
    PinnedExchangeCalendarVerifier,
    UnavailableExchangeCalendarVerifier,
    strict_exchange_calendar_available,
)
from .config import (
    activated_rights_policy_from_env,
    market_data_provider_from_env,
    market_data_public_config,
    rights_policy_from_env,
)
from .dataset_manifest import (
    DATASET_MANIFEST_V2,
    DatasetRightsOperation,
    LicensedDatasetSeal,
    assert_dataset_directory_rights,
    assert_dataset_rights,
    load_dataset_manifest,
    seal_licensed_acquisition,
    validate_dataset_manifest_v2,
)
from .rights import RIGHTS_POLICY_VERSION, RightsPolicy
from .service import (
    LicensedDataRuntime,
    acquisition_public_view,
    create_and_process_acquisition,
    licensed_data_runtime_from_env,
    resolve_canonical_instrument,
)

__all__ = [
    "AdjustmentMode",
    "CanonicalDailyBar",
    "DailyDataAcquisition",
    "DATASET_MANIFEST_V2",
    "DatasetRightsOperation",
    "CorporateAction",
    "FetchedDailySeries",
    "ExchangeCalendarReceipt",
    "ExchangeCalendarVerifier",
    "PinnedExchangeCalendarVerifier",
    "InstrumentRef",
    "LicenseNotConfirmed",
    "MarketDataError",
    "MarketDataProvider",
    "ProviderCapabilities",
    "ProviderSourceManifest",
    "LicensedDatasetSeal",
    "LicensedDataRuntime",
    "RateLimited",
    "RIGHTS_POLICY_VERSION",
    "RightsPolicy",
    "acquire_daily_data",
    "acquire_daily_data_for_instrument",
    "acquisition_public_view",
    "activated_rights_policy_from_env",
    "assert_dataset_directory_rights",
    "assert_dataset_rights",
    "canonical_daily_bars_csv",
    "canonical_bars_sha256",
    "create_and_process_acquisition",
    "licensed_data_runtime_from_env",
    "market_data_provider_from_env",
    "market_data_public_config",
    "load_dataset_manifest",
    "rights_policy_from_env",
    "resolve_canonical_instrument",
    "seal_licensed_acquisition",
    "validate_daily_bars",
    "validate_freshness",
    "validate_dataset_manifest_v2",
    "UnavailableExchangeCalendarVerifier",
    "strict_exchange_calendar_available",
]
