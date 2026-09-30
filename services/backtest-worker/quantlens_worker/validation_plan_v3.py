"""Dormant Gate E Stop B1 pure validation-plan-v3 builder.

``build_validation_plan_v3`` is a pure function over three closed, server-owned
mappings: the accepted-run binding, the canonical observation identity and the external
capability state.  It recomputes the locked-rule and base-cost hashes from canonical
copies, derives the final window with the frozen v2-compatible half-even rule and the
reviewed warm-up law, binds the immutable Battery v3 profile hash, computes the plan
self-hash over every other field and validates the finished plan against the sealed
``validation-plan-v3`` schema before returning a fresh JSON-only mapping.

It never accepts folds, windows, warm-up indices, plan hashes, profile hashes,
final-access results or caller-selected authority policy, and it never reads the
control-plane database, snapshot loader, clock, network or filesystem beyond the sealed
schema bytes.  The continuous-path marker reaches the plan through the frozen
``BATTERY_CONFIG_V3`` value only; its literal bytes are reserved to the reviewed
dormant Gate C module.  This module is not exported by the package ``__init__``, is
not imported by any active path, and activates nothing.  Focused tests are its only
consumers.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Mapping

import jsonschema

from .battery_config_v3 import BATTERY_CONFIG_V3, battery_config_v3_hash


class ValidationPlanV3Error(ValueError):
    """One candidate input violates the frozen validation-plan-v3 build law."""


VALIDATION_PLAN_V3_SCHEMA_FILE = "validation-plan-v3.json"
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages" / "strategy-schema" / "schema" / VALIDATION_PLAN_V3_SCHEMA_FILE
)
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}

_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

ACCEPTED_RUN_FIELDS = (
    "release_id",
    "required_worker_contract",
    "tenant_id",
    "workspace_id",
    "run_id",
    "dsl_schema_version",
    "confirmed_spec_hash",
    "rule",
    "base_costs",
    "registered_final_holdout_fraction",
)
OBSERVATION_FIELDS = (
    "market_observations_version",
    "canonicalization_policy_version",
    "snapshot_sha256",
    "exchange_calendar_id",
    "exchange_calendar_version",
    "n_bars",
)
CAPABILITY_FIELDS = (
    "anchor_authority_id",
    "anchor_issuer_key_id",
    "holdout_authority_id",
    "holdout_authority_key_id",
    "external_anchor_ready",
    "external_holdout_ready",
)

_RULE_TYPES = ("price_vs_ma", "ma_crossover")
_RULE_REQUIRED_FIELDS = ("type", "ma_days")
_RULE_ALLOWED_FIELDS = ("type", "ma_days", "fast_ma_days")
_COST_FIELDS = ("commission_bps", "slippage_bps")

# Frozen tuple identifiers the accepted run must present exactly.  The remaining
# version constants come from the immutable Battery v3 profile below.
_RELEASE_ID = "quantlens-financial-v3"
_REQUIRED_WORKER_CONTRACT = "quantlens-worker-v3"
_DSL_SCHEMA_VERSION = "1.2"


def _reject(message: str) -> None:
    raise ValidationPlanV3Error(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationPlanV3Error(
            "validation-plan-v3 accepts only finite canonical JSON values"
        ) from exc


def _sha256_canonical_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _load_schema() -> dict[str, Any]:
    cached = _SCHEMA_CACHE.get(VALIDATION_PLAN_V3_SCHEMA_FILE)
    if cached is not None:
        return cached
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationPlanV3Error(
            f"cannot load sealed schema: {VALIDATION_PLAN_V3_SCHEMA_FILE}"
        ) from exc
    if (
        not isinstance(schema, dict)
        or schema.get("additionalProperties") is not False
        or schema.get("type") != "object"
        or not isinstance(schema.get("properties"), dict)
        or not isinstance(schema.get("required"), list)
        or not str(schema.get("$id", "")).endswith(
            "/" + VALIDATION_PLAN_V3_SCHEMA_FILE)
    ):
        raise ValidationPlanV3Error(
            f"sealed schema is not a closed object schema: "
            f"{VALIDATION_PLAN_V3_SCHEMA_FILE}"
        )
    _SCHEMA_CACHE[VALIDATION_PLAN_V3_SCHEMA_FILE] = schema
    return schema


def _closed_mapping(
    value: object, fields: tuple[str, ...], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    keys = set(value)
    expected = set(fields)
    if keys != expected:
        missing = sorted(expected - keys)
        surplus = sorted(str(key) for key in keys - expected)
        _reject(
            f"{label} must have exactly these keys: {', '.join(fields)}"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; unknown: {', '.join(surplus)}" if surplus else "")
        )
    return {field: value[field] for field in fields}


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY_RE.fullmatch(value) is None:
        _reject(
            f"{label} must be a non-empty printable-ASCII string of at most "
            "128 characters"
        )
    assert isinstance(value, str)
    return value


def _prefixed_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _PREFIXED_SHA256_RE.fullmatch(value) is None:
        _reject(f"{label} must be sha256: followed by 64 lowercase hex characters")
    assert isinstance(value, str)
    return value


def _exact(value: object, expected: str, label: str) -> str:
    if not isinstance(value, str) or value != expected:
        _reject(f"{label} must be exactly {expected!r}")
    return value


def _int_in_range(
    value: object, label: str, *, minimum: int, maximum: int | None = None
) -> int:
    if type(value) is not int:
        _reject(f"{label} must be an integer, not a bool or other type")
    assert type(value) is int
    if value < minimum or (maximum is not None and value > maximum):
        bound = f"at least {minimum}" if maximum is None else \
            f"between {minimum} and {maximum}"
        _reject(f"{label} must be {bound}")
    return int(value)


def _canonical_scalar(
    value: object, label: str, *, minimum: float, maximum: float
) -> int | float:
    """Canonicalize one bounded numeric scalar under the reviewed dtype law.

    Bools and non-finite values are rejected.  Built-in ``int`` and ``float`` values
    retain their exact JSON numeric type so the resulting hash matches the accepted
    strategy specification byte-for-byte; in particular, ``1`` and ``1.0`` are not
    silently collapsed into the same binding.
    """
    if type(value) is int:
        result: int | float = int(value)
    elif type(value) is float:
        if not math.isfinite(value):
            _reject(f"{label} must be finite, not NaN or infinity")
        result = float(value)
    else:
        _reject(f"{label} has an unsupported dtype: {type(value).__name__}")
    assert isinstance(result, (int, float))
    if result < minimum or result > maximum:
        _reject(f"{label} must be between {minimum} and {maximum}")
    return result


def _canonical_rule(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject("accepted_run.rule must be a mapping")
    assert isinstance(value, Mapping)
    keys = set(value)
    if not set(_RULE_REQUIRED_FIELDS) <= keys or not keys <= set(_RULE_ALLOWED_FIELDS):
        _reject(
            "accepted_run.rule must have exactly the sealed DSL 1.2 rule keys: "
            + ", ".join(_RULE_ALLOWED_FIELDS)
        )
    rule_type = value["type"]
    if rule_type not in _RULE_TYPES:
        _reject("accepted_run.rule.type is not a sealed DSL 1.2 rule type")
    ma_days = _int_in_range(
        value["ma_days"], "accepted_run.rule.ma_days", minimum=2, maximum=400)
    fast = value.get("fast_ma_days")
    if fast is not None:
        fast = _int_in_range(
            fast, "accepted_run.rule.fast_ma_days", minimum=2, maximum=400)
    if rule_type == "ma_crossover":
        if fast is None:
            _reject("a confirmed ma_crossover rule must bind fast_ma_days")
        assert isinstance(fast, int)
        if fast >= ma_days:
            _reject("a confirmed ma_crossover rule requires fast_ma_days < ma_days")
    elif fast is not None:
        _reject("a confirmed price_vs_ma rule must not bind fast_ma_days")
    return {"type": rule_type, "ma_days": ma_days, "fast_ma_days": fast}


def _canonical_costs(value: object) -> dict[str, Any]:
    costs = _closed_mapping(value, _COST_FIELDS, "accepted_run.base_costs")
    return {
        field: _canonical_scalar(
            costs[field], f"accepted_run.base_costs.{field}",
            minimum=0, maximum=100,
        )
        for field in _COST_FIELDS
    }


def _fraction(value: object, label: str) -> float:
    if type(value) not in (int, float):
        _reject(f"{label} must be a number, not a bool or other type")
    assert type(value) in (int, float)
    numeric = float(value)
    if not math.isfinite(numeric):
        _reject(f"{label} must be finite, not NaN or infinity")
    if not 0.0 < numeric < 1.0:
        _reject(f"{label} must be strictly between 0 and 1")
    return numeric


def _capability_ready(value: object, label: str) -> bool:
    if value is not True:
        _reject(
            f"{label} must be exactly true; an unconfigured external capability "
            "fails closed"
        )
    return True


def build_validation_plan_v3(
    *,
    accepted_run: Mapping[str, object],
    observations: Mapping[str, object],
    capabilities: Mapping[str, object],
) -> dict[str, object]:
    """Build one immutable validation-plan-v3 from the three closed server mappings."""
    run = _closed_mapping(accepted_run, ACCEPTED_RUN_FIELDS, "accepted_run")
    obs = _closed_mapping(observations, OBSERVATION_FIELDS, "observations")
    caps = _closed_mapping(capabilities, CAPABILITY_FIELDS, "capabilities")
    profile = BATTERY_CONFIG_V3

    _exact(run["release_id"], _RELEASE_ID, "accepted_run.release_id")
    _exact(
        run["required_worker_contract"], _REQUIRED_WORKER_CONTRACT,
        "accepted_run.required_worker_contract",
    )
    _exact(
        run["dsl_schema_version"], _DSL_SCHEMA_VERSION,
        "accepted_run.dsl_schema_version",
    )
    tenant_id = _identity(run["tenant_id"], "accepted_run.tenant_id")
    workspace_id = _identity(run["workspace_id"], "accepted_run.workspace_id")
    run_id = _identity(run["run_id"], "accepted_run.run_id")
    confirmed_spec_hash = _prefixed_sha256(
        run["confirmed_spec_hash"], "accepted_run.confirmed_spec_hash")
    rule = _canonical_rule(run["rule"])
    costs = _canonical_costs(run["base_costs"])
    registered_fraction = _fraction(
        run["registered_final_holdout_fraction"],
        "accepted_run.registered_final_holdout_fraction",
    )

    _exact(
        obs["market_observations_version"],
        profile["market_observations_version"],
        "observations.market_observations_version",
    )
    _exact(
        obs["canonicalization_policy_version"],
        profile["canonicalization_policy_version"],
        "observations.canonicalization_policy_version",
    )
    snapshot_sha256 = _prefixed_sha256(
        obs["snapshot_sha256"], "observations.snapshot_sha256")
    exchange_calendar_id = _identity(
        obs["exchange_calendar_id"], "observations.exchange_calendar_id")
    exchange_calendar_version = _identity(
        obs["exchange_calendar_version"], "observations.exchange_calendar_version")
    n_bars = _int_in_range(obs["n_bars"], "observations.n_bars", minimum=1)

    authorities = {
        field: _identity(caps[field], f"capabilities.{field}")
        for field in CAPABILITY_FIELDS[:4]
    }
    _capability_ready(
        caps["external_anchor_ready"], "capabilities.external_anchor_ready")
    _capability_ready(
        caps["external_holdout_ready"], "capabilities.external_holdout_ready")

    development_law = profile["development"]
    holdout_law = profile["final_holdout"]
    regime_law_config = profile["regimes"]

    # Frozen v2-compatible derivation: half-even bar rounding, then the exact
    # effective fraction as the correctly-rounded IEEE-754 quotient bars / n_bars.
    final_bars = int(
        (Decimal(n_bars) * Decimal(str(registered_fraction)))
        .to_integral_value(rounding=ROUND_HALF_EVEN)
    )
    final_bars = max(1, final_bars)
    _require(
        final_bars < n_bars,
        "the derived final window leaves an empty development region",
    )
    development_bars = n_bars - final_bars

    lookback_values = [rule["ma_days"]]
    if rule["fast_ma_days"] is not None:
        lookback_values.append(rule["fast_ma_days"])
    max_indicator_lookback = max(lookback_values)
    minimum_train_bars = max(
        int(development_law["minimum_train_floor_bars"]),
        int(development_law["minimum_train_lookback_multiple"])
        * max_indicator_lookback,
    )
    _require(
        development_bars
        >= minimum_train_bars + int(development_law["minimum_short_fold_bars"]),
        "the development region cannot hold the minimum training window plus one "
        "evaluation fold",
    )

    # Warm-up: maximum indicator lookback, the 200-bar floor and the 63-bar
    # volatility lookback, clipped only at observation zero.
    final_warmup_bars = max(
        max_indicator_lookback,
        int(holdout_law["warmup_floor_bars"]),
        int(regime_law_config["volatility_lookback_bars"]),
    )
    start_index = development_bars
    warmup_start_index = max(0, start_index - final_warmup_bars)
    warmup_bars = start_index - warmup_start_index

    effective_fraction = final_bars / n_bars
    _require(
        0.0 < effective_fraction < 1.0,
        "the effective final-holdout fraction must be strictly between 0 and 1",
    )

    body: dict[str, Any] = {
        "plan_version": "validation-plan-v3",
        "profile_id": profile["profile_id"],
        "battery_version": profile["battery_version"],
        "profile_hash": battery_config_v3_hash(),
        "release_id": _RELEASE_ID,
        "required_worker_contract": _REQUIRED_WORKER_CONTRACT,
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": run_id,
        "dsl_schema_version": _DSL_SCHEMA_VERSION,
        "confirmed_spec_hash": confirmed_spec_hash,
        "locked_rule_sha256": _sha256_canonical_json(rule),
        "base_costs_sha256": _sha256_canonical_json(costs),
        "market_observations_version": profile["market_observations_version"],
        "canonicalization_policy_version": (
            profile["canonicalization_policy_version"]),
        "snapshot_sha256": snapshot_sha256,
        "exchange_calendar_id": exchange_calendar_id,
        "exchange_calendar_version": exchange_calendar_version,
        "n_bars": n_bars,
        "continuous_path_version": profile["continuous_path_version"],
        "plan_anchor_version": profile["plan_anchor_version"],
        "final_access_protocol": profile["final_access_protocol"],
        "registered_final_holdout_fraction": registered_fraction,
        "final_holdout_fraction": effective_fraction,
        "final_window": {
            "n_bars": n_bars,
            "start_index": start_index,
            "end_index": n_bars,
            "bars": final_bars,
            "warmup_start_index": warmup_start_index,
            "warmup_bars": warmup_bars,
        },
        "development_bars": development_bars,
        "max_indicator_lookback": max_indicator_lookback,
        "minimum_train_bars": minimum_train_bars,
        "final_warmup_bars": final_warmup_bars,
        "walk_forward": {
            "mode": development_law["walk_forward_mode"],
            "parameter_selection": development_law["parameter_selection"],
            "minimum_train_floor_bars": (
                development_law["minimum_train_floor_bars"]),
            "minimum_train_lookback_multiple": (
                development_law["minimum_train_lookback_multiple"]),
            "test_window_bars": development_law["test_window_bars"],
            "minimum_short_fold_bars": (
                development_law["minimum_short_fold_bars"]),
        },
        "regime_law": {
            "trend": "benchmark_close[t-1] >= SMA200[t-1]",
            "volatility": "annualized_realized_vol_63[t-1] >= 0.20",
            "states": list(regime_law_config["states"]),
            "minimum_observations": regime_law_config["minimum_observations"],
        },
        "authorities": authorities,
        "production_capabilities": {
            "external_anchor_ready": True,
            "external_holdout_ready": True,
            "unconfigured_behavior": "fail_closed",
        },
        "integrity_bindings": {
            "temporal_integrity": "direct_payload_sha256_required",
            "final_holdout_execution_audit": "direct_payload_sha256_required",
        },
    }
    plan = {**body, "validation_plan_hash": _sha256_canonical_json(body)}

    try:
        jsonschema.Draft202012Validator(_load_schema()).validate(plan)
    except jsonschema.ValidationError as exc:
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in exc.absolute_path
        )
        raise ValidationPlanV3Error(
            f"validation-plan-v3 contract violation at {path}: {exc.message}"
        ) from exc

    # Fail-closed cross-field laws the closed schema cannot express.
    window = plan["final_window"]
    _require(window["end_index"] == n_bars, "final window must end at n_bars")
    _require(
        window["bars"] == window["end_index"] - window["start_index"],
        "final window bars must equal its end-exclusive index span",
    )
    _require(
        window["warmup_bars"]
        == window["start_index"] - window["warmup_start_index"],
        "warm-up boundary must immediately precede the final window",
    )
    _require(
        plan["final_holdout_fraction"] == window["bars"] / window["n_bars"],
        "effective fraction must equal its derived final-window share exactly",
    )
    _require(
        plan["development_bars"] + window["bars"] == plan["n_bars"],
        "development and final windows must partition the observations",
    )

    result = json.loads(_canonical_json_bytes(plan).decode("utf-8"))
    assert isinstance(result, dict)
    return result


__all__ = [
    "ACCEPTED_RUN_FIELDS",
    "CAPABILITY_FIELDS",
    "OBSERVATION_FIELDS",
    "VALIDATION_PLAN_V3_SCHEMA_FILE",
    "ValidationPlanV3Error",
    "build_validation_plan_v3",
]
