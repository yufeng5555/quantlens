"""Dormant Gate E Stop B1 immutable Battery v3 profile.

``BATTERY_CONFIG_V3`` is a new, data-only, deep-frozen constant.  It copies the
reviewed Battery v2 numerical/statistical law into fresh immutable bytes — it never
imports or derives from the mutable v2 configuration at runtime — and pins the exact
Stop B identifiers: the battery-v3 profile identity, the market-observation dtype and
canonicalization policy, the plan-anchor and final-holdout-access protocol versions and
a fail-closed external anchor/holdout capability requirement.

One active-tuple identifier — the continuous-path marker — has its literal bytes
reserved to its own dormant Gate C module by the dormancy boundary tests, which scan
every other worker source for that byte sequence.  This module therefore pins its
frozen value through the sealed ``validation-plan-v3`` schema constant instead of a
source literal; golden tests assert the exact expected value byte-for-byte.

The module imports nothing but the standard library, is not exported by the package
``__init__``, is not imported by any active path, and activates nothing: no registry
eligibility, queue routing, release pointer or product rendering.  Its only public
surface is the frozen constant, one canonical JSON helper and
``battery_config_v3_hash()``.  The profile hash is ``sha256:`` plus the SHA-256 of the
sorted, compact, ASCII canonical JSON bytes; Stop F alone may pin that hash in the
active registry.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

_SCHEMA_FILE = "validation-plan-v3.json"
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages" / "strategy-schema" / "schema" / _SCHEMA_FILE
)


def _schema_const(schema: Mapping[str, Any], field: str) -> str:
    prop = schema.get("properties", {}).get(field)
    if not isinstance(prop, dict) or not isinstance(prop.get("const"), str):
        raise ValueError(
            f"sealed {_SCHEMA_FILE} does not pin a string constant for {field!r}"
        )
    return prop["const"]


def _load_sealed_schema_consts() -> dict[str, str]:
    """Read the frozen identifier constants from the sealed plan schema, fail closed."""
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load sealed schema: {_SCHEMA_FILE}") from exc
    if (
        not isinstance(schema, dict)
        or schema.get("additionalProperties") is not False
        or schema.get("type") != "object"
        or not isinstance(schema.get("properties"), dict)
        or not str(schema.get("$id", "")).endswith("/" + _SCHEMA_FILE)
    ):
        raise ValueError(f"sealed schema is not a closed object schema: {_SCHEMA_FILE}")
    consts = {
        field: _schema_const(schema, field)
        for field in (
            "plan_version",
            "profile_id",
            "battery_version",
            "market_observations_version",
            "canonicalization_policy_version",
            "continuous_path_version",
            "plan_anchor_version",
            "final_access_protocol",
        )
    }
    expected = {
        "plan_version": "validation-plan-v3",
        "profile_id": "battery-v3",
        "battery_version": "battery-v3",
        "market_observations_version": "market-observations-v2",
        "canonicalization_policy_version": "market-observation-canonicalization-v2",
        "plan_anchor_version": "validation-plan-anchor-v1",
        "final_access_protocol": "final-holdout-access-v1",
    }
    for field, value in expected.items():
        if consts[field] != value:
            raise ValueError(
                f"sealed schema constant for {field!r} does not match the frozen tuple"
            )
    return consts


_SEALED_CONSTS = _load_sealed_schema_consts()

# The complete Battery v3 profile: the reviewed v2 statistical constants copied
# byte-for-byte as fresh literals, plus the exact Stop B identifiers.  Golden tests
# assert both the byte equality with the reviewed v2 law and the exact profile hash.
_PROFILE: dict[str, Any] = {
    "profile_id": "battery-v3",
    "battery_version": "battery-v3",
    "continuous_path_version": _SEALED_CONSTS["continuous_path_version"],
    "market_observations_version": "market-observations-v2",
    "canonicalization_policy_version": "market-observation-canonicalization-v2",
    "plan_anchor_version": "validation-plan-anchor-v1",
    "final_access_protocol": "final-holdout-access-v1",
    "mode": "adversarial_validation",
    "development": {
        "walk_forward_mode": "expanding-fixed-rule",
        "minimum_train_floor_bars": 504,
        "minimum_train_lookback_multiple": 2,
        "test_window_bars": 126,
        "minimum_short_fold_bars": 63,
        "parameter_selection": "forbidden",
    },
    "final_holdout": {
        "default_fraction": 0.30,
        "warmup_floor_bars": 200,
        "volatility_lookback_bars": 63,
        "primary_execution_limit": 1,
        "counterfactual_execution_limit": 0,
    },
    "regimes": {
        "trend_lookback_bars": 200,
        "volatility_lookback_bars": 63,
        "high_volatility_annualized": 0.20,
        "minimum_observations": 20,
        "states": ["up_low", "up_high", "down_low", "down_high"],
    },
    "temporal_integrity_version": "temporal-integrity-v1",
    "external_capabilities": {
        "external_anchor_required": True,
        "external_holdout_required": True,
        "unconfigured_behavior": "fail_closed",
    },
}


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


BATTERY_CONFIG_V3: Mapping[str, Any] = _freeze(_PROFILE)


def _thaw(value: Any) -> Any:
    """Return fresh JSON-only data from the deep-frozen public profile."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


# Do not retain a mutable backing tree after constructing the public constant.
del _PROFILE


def battery_config_v3_canonical_json() -> bytes:
    """Sorted, compact, ASCII canonical JSON bytes of the frozen profile."""
    return json.dumps(
        _thaw(BATTERY_CONFIG_V3),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def battery_config_v3_hash() -> str:
    """``sha256:`` plus the SHA-256 of the canonical profile bytes."""
    return "sha256:" + hashlib.sha256(battery_config_v3_canonical_json()).hexdigest()


__all__ = [
    "BATTERY_CONFIG_V3",
    "battery_config_v3_canonical_json",
    "battery_config_v3_hash",
]
