"""Dormant Gate E worker wrapper over the neutral market-observation canonicalizer.

The accepted Stop A implementation moved verbatim to the uniquely named neutral
module ``quantlens_schema.market_observation_protocol_v2`` so the independent
final-holdout access authority and this dormant worker surface share one byte law
without importing one another.  This wrapper performs no work: it explicitly
re-exports every accepted public name — the same objects, bytes, hashes, errors and
mutation behavior — and adds nothing.  The active dataset importer and snapshot
producer remain unchanged; focused tests are this module's only consumers.
"""

from __future__ import annotations

from quantlens_schema.market_observation_protocol_v2 import (
    CANONICALIZATION_POLICY_VERSION,
    INSTRUMENT_FIELDS,
    MARKET_OBSERVATIONS_VERSION,
    MarketObservationCanonicalizationError,
    PRICE_FIELDS,
    SESSION_FIELDS,
    TOP_LEVEL_FIELDS,
    canonical_economic_scalar,
    canonical_market_observations_v2_bytes,
    canonical_market_observations_v2_sha256,
    canonical_session_bytes,
    canonicalize_instrument,
    canonicalize_market_observations_v2,
    canonicalize_session,
)

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
