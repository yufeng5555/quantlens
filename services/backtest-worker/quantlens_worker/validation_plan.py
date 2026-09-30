"""Server-owned Validation Battery profiles and immutable v2 plan construction."""

from __future__ import annotations

import hashlib
import json

from .config import BATTERY_CONFIG_V2, battery_config_hash

BATTERY_V1 = "battery-v1"
BATTERY_V2 = "battery-v2"
SUPPORTED_BATTERY_PROFILES = frozenset({BATTERY_V1, BATTERY_V2})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def max_indicator_lookback(rule: dict) -> int:
    values = [int(rule["ma_days"])]
    if rule.get("fast_ma_days") is not None:
        values.append(int(rule["fast_ma_days"]))
    return max(values)


def profile_descriptor(profile: str) -> dict:
    if profile not in SUPPORTED_BATTERY_PROFILES:
        raise ValueError(f"unsupported battery profile: {profile!r}")
    if profile == BATTERY_V1:
        return {
            "profile_id": BATTERY_V1,
            "profile_hash": battery_config_hash(BATTERY_V1),
            "plan_summary": {
                "mode": "legacy_is_oos_with_preregistered_counterfactuals",
                "compatibility": "frozen",
            },
        }
    cfg = BATTERY_CONFIG_V2
    return {
        "profile_id": BATTERY_V2,
        "profile_hash": battery_config_hash(BATTERY_V2),
        "plan_summary": {
            "mode": cfg["development"]["walk_forward_mode"],
            "rule_policy": "locked; no parameter selection",
            "test_window_bars": cfg["development"]["test_window_bars"],
            "minimum_short_fold_bars": cfg["development"]["minimum_short_fold_bars"],
            "final_holdout": "access-controlled, one-time holdout",
            "production_gap": (
                "independent OS principal or object-store ACL not implemented"
            ),
            "regimes": list(cfg["regimes"]["states"]),
        },
    }


def validation_restatement_suffix(profile: str) -> str:
    if profile == BATTERY_V1:
        return ""
    if profile != BATTERY_V2:
        raise ValueError(f"unsupported battery profile: {profile!r}")
    return (
        " Validation Battery v2 locks the confirmed rule before execution. It uses "
        "development-only expanding walk-forward evaluation without parameter tuning, "
        "then permits exactly one primary read of an access-controlled final holdout. "
        "The research agent receives development evidence only. The local capability "
        "boundary is not yet an independent OS principal or object-store ACL; those "
        "remain production hardening gaps."
    )


def profile_restatement(base: str, spec: dict, profile: str) -> str:
    """Replace v1-only claims before appending the v2 confirmation language."""
    if profile == BATTERY_V1:
        return base
    if profile != BATTERY_V2:
        raise ValueError(f"unsupported battery profile: {profile!r}")
    percent = int(round(
        float(spec["validation"]["is_oos_split"]["oos_fraction"]) * 100))
    first_marker = f"The final {percent}% of the window is held out-of-sample:"
    benchmark_marker = " Benchmark:"
    if first_marker not in base or benchmark_marker not in base:
        raise ValueError("base restatement no longer exposes the registered holdout clause")
    prefix, tail = base.split(first_marker, 1)
    _old_holdout, after_holdout = tail.split(benchmark_marker, 1)
    value = (
        prefix
        + f"The final {percent}% is an access-controlled, single-use holdout. It is "
          "evaluated once at base costs after the rule and plan are locked; it is never "
          "used for tuning or counterfactuals."
        + benchmark_marker + after_holdout
    )
    sweep_marker = "The battery also sweeps MA windows"
    confirmation_marker = " Confirming runs"
    if sweep_marker not in value or confirmation_marker not in value:
        raise ValueError("base restatement no longer exposes the legacy sweep clause")
    before_sweep, sweep_tail = value.split(sweep_marker, 1)
    _old_sweep, after_sweep = sweep_tail.split(confirmation_marker, 1)
    value = (
        before_sweep
        + "The battery uses fixed-rule expanding walk-forward folds on development data, "
          "development-only cost stress, and preregistered regime analysis. It performs "
          "no parameter search or selection and always reports falsification findings."
        + confirmation_marker + after_sweep
    )
    return value + validation_restatement_suffix(profile)


def build_validation_plan(spec: dict, n_bars: int) -> dict:
    """Build the complete v2 plan from server law plus the confirmed spec.

    The client never supplies folds, regime thresholds, minimum samples, or final access
    policy.  The existing ``oos_fraction`` is interpreted as the final-holdout fraction.
    """
    cfg = BATTERY_CONFIG_V2
    fraction = float(spec["validation"]["is_oos_split"]["oos_fraction"])
    lookback = max_indicator_lookback(spec["rule"])
    final_bars = max(1, int(round(n_bars * fraction)))
    development_bars = n_bars - final_bars
    minimum_train = max(
        int(cfg["development"]["minimum_train_floor_bars"]),
        int(cfg["development"]["minimum_train_lookback_multiple"]) * lookback,
    )
    warmup = max(
        lookback,
        int(cfg["final_holdout"]["warmup_floor_bars"]),
        int(cfg["final_holdout"]["volatility_lookback_bars"]),
    )
    body = {
        "profile_id": BATTERY_V2,
        "profile_hash": battery_config_hash(BATTERY_V2),
        "plan_version": "validation-plan-v2",
        "n_bars": int(n_bars),
        "development_bars": int(development_bars),
        "final_holdout_bars": int(final_bars),
        "final_holdout_fraction": fraction,
        "max_indicator_lookback": lookback,
        "minimum_train_bars": minimum_train,
        "test_window_bars": int(cfg["development"]["test_window_bars"]),
        "minimum_short_fold_bars": int(
            cfg["development"]["minimum_short_fold_bars"]),
        "final_warmup_bars": warmup,
        "walk_forward_mode": "expanding-fixed-rule",
        "parameter_selection": "forbidden",
        "regime_law": {
            "trend": "benchmark_close[t-1] >= SMA200[t-1]",
            "volatility": "annualized_realized_vol_63[t-1] >= 0.20",
            "states": list(cfg["regimes"]["states"]),
            "minimum_observations": cfg["regimes"]["minimum_observations"],
        },
        "access_policy": {
            "development_battery": "development_only",
            "final_evaluator": "single_use_capability_only",
            "explanation_agent": "development_evidence_only",
            "production_gap": (
                "independent_os_principal_or_object_store_acl_not_implemented"
            ),
        },
    }
    return {**body, "validation_plan_hash": sha256_json(body)}


__all__ = [
    "BATTERY_V1", "BATTERY_V2", "SUPPORTED_BATTERY_PROFILES",
    "build_validation_plan", "max_indicator_lookback", "profile_descriptor",
    "sha256_json", "validation_restatement_suffix",
    "profile_restatement",
]
