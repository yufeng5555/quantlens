"""Validation Battery v2 development-only evaluation.

This module never receives the final-holdout capsule.  It performs fixed-rule expanding
walk-forward analysis, preregistered development cost stress, and no-lookahead regimes.
"""

from __future__ import annotations

import math
import statistics

import pandas as pd

from .battery import FAIL, INCONCLUSIVE, PASS, _segment_result
from .config import INITIAL_CAPITAL
from .engine import compute_metrics
from .regimes import analyze_regimes
from .validation_plan import sha256_json


def _scaled_trades(trades: list[dict], scale: float) -> list[dict]:
    money_fields = {"shares", "notional", "commission", "slippage"}
    return [
        {key: (float(value) * scale if key in money_fields else value)
         for key, value in trade.items()}
        for trade in trades
    ]


def _stitch(results: list[dict], *, benchmark: bool = False) -> tuple[pd.DataFrame, list[dict]]:
    capital = float(INITIAL_CAPITAL)
    frames: list[pd.DataFrame] = []
    trades: list[dict] = []
    for result in results:
        raw = result["raw"]
        source = raw["benchmark"] if benchmark else raw["equity"]
        if source.empty:
            continue
        scale = capital / INITIAL_CAPITAL
        current = source.copy()
        current["equity"] = current["equity"].astype(float) * scale
        frames.append(current)
        fold_trades = ([raw["benchmark_entry"]] if benchmark and raw["benchmark_entry"]
                       else ([] if benchmark else raw["trades"]))
        trades.extend(_scaled_trades(fold_trades, scale))
        capital = float(current["equity"].iloc[-1])
    if not frames:
        return pd.DataFrame(columns=["date", "equity", "position"]), []
    return pd.concat(frames, ignore_index=True), trades


def _slim_stitched(
    results: list[dict], *, benchmark_symbol: str,
) -> tuple[dict, pd.DataFrame, pd.DataFrame, list[dict]]:
    equity, trades = _stitch(results)
    benchmark, benchmark_trades = _stitch(results, benchmark=True)
    strategy_metrics = compute_metrics(equity, trades, INITIAL_CAPITAL)
    benchmark_metrics = (
        compute_metrics(benchmark, benchmark_trades, INITIAL_CAPITAL)
        if not benchmark.empty else {"n_bars": 0, "note": "no benchmark window"}
    )
    return ({
        "status": "COMPLETE",
        "strategy_metrics": strategy_metrics,
        "comparison_strategy_metrics": dict(strategy_metrics),
        "benchmark_metrics": benchmark_metrics,
        "benchmark_symbol": benchmark_symbol,
        "comparison_start": (
            str(benchmark["date"].iloc[0]) if not benchmark.empty else None),
        "equity_series": {
            "date": equity["date"].astype(str).tolist(),
            "equity": equity["equity"].tolist(),
            "position": equity["position"].tolist(),
        },
        "benchmark_series": {
            "date": benchmark["date"].astype(str).tolist(),
            "equity": benchmark["equity"].tolist(),
        },
        "trades": trades,
        "benchmark_entry": benchmark_trades[0] if benchmark_trades else None,
    }, equity, benchmark, trades)


def _walk_forward(
    development: pd.DataFrame,
    folds: list[dict],
    *,
    rule: dict,
    costs: dict,
    benchmark_frame: pd.DataFrame | None,
    benchmark_symbol: str,
    cost_multiplier: float = 1.0,
) -> tuple[dict, dict, pd.DataFrame, pd.DataFrame, list[dict]]:
    results: list[dict] = []
    fold_rows: list[dict] = []
    for fold in folds:
        test_end = int(fold["test_end_index"])
        test_start = int(fold["test_start_index"])
        # Physical prefix: this execution cannot read any bar after its test end.
        prefix = development.iloc[:test_end].reset_index(drop=True)
        benchmark_prefix = (
            benchmark_frame.iloc[:test_end].reset_index(drop=True)
            if benchmark_frame is not None else None
        )
        result = _segment_result(
            prefix, rule, costs, (test_start, test_end),
            cost_multiplier=cost_multiplier,
            benchmark_df=benchmark_prefix,
            benchmark_symbol=benchmark_symbol,
        )
        results.append(result)
        fold_rows.append({
            **fold,
            "locked_rule_sha256": sha256_json(rule),
            "cost_multiplier": float(cost_multiplier),
            "strategy_metrics": result["strategy"],
            "benchmark_metrics": result["benchmark"],
        })

    stitched, equity, benchmark, trades = _slim_stitched(
        results, benchmark_symbol=benchmark_symbol)
    returns = [float(row["strategy_metrics"].get("total_return", 0.0))
               for row in fold_rows]
    sharpes = [float(row["strategy_metrics"].get("sharpe", 0.0))
               for row in fold_rows]
    summary = {
        "mode": "expanding-fixed-rule",
        "parameter_selection": "forbidden",
        "locked_rule_sha256": sha256_json(rule),
        "cost_multiplier": float(cost_multiplier),
        "fold_count": len(fold_rows),
        "folds": fold_rows,
        "median_fold_sharpe": statistics.median(sharpes) if sharpes else None,
        "positive_fold_ratio": (
            sum(value > 0 for value in returns) / len(returns) if returns else None),
        "worst_fold_return": min(returns) if returns else None,
        "fold_return_dispersion": (
            statistics.pstdev(returns) if len(returns) > 1 else 0.0 if returns else None),
        "stitched_development_total_return": (
            stitched["strategy_metrics"].get("total_return")
            if stitched.get("status") == "COMPLETE" else None),
    }
    return summary, stitched, equity, benchmark, trades


def _finding(identifier: str, status: str, summary: str, evidence: dict) -> dict:
    return {
        "id": identifier,
        "status": status,
        "rule": "server-owned Validation Battery v2 law",
        "summary": summary,
        "evidence": evidence,
    }


def run_development_battery_v2(
    development: pd.DataFrame,
    spec: dict,
    validation_plan: dict,
    partitions: dict,
    *,
    benchmark_frame: pd.DataFrame | None = None,
) -> dict:
    rule = dict(spec["rule"])
    costs = dict(spec["costs"])
    symbol = spec["universe"]["symbol"]
    benchmark_value = spec["benchmark"]["symbol"]
    benchmark_symbol = symbol if benchmark_value == "same_as_universe" else benchmark_value
    folds = list(partitions["folds"])

    if not folds:
        development_result = {
            "status": INCONCLUSIVE,
            "reason": partitions.get("reason") or "insufficient development history",
            "strategy_metrics": {"n_bars": 0},
            "comparison_strategy_metrics": {"n_bars": 0},
            "benchmark_metrics": {"n_bars": 0},
            "benchmark_symbol": benchmark_symbol,
            "equity_series": {"date": [], "equity": [], "position": []},
            "benchmark_series": {"date": [], "equity": []},
            "trades": [],
            "benchmark_entry": None,
        }
        walk_forward = {
            "mode": "expanding-fixed-rule", "parameter_selection": "forbidden",
            "fold_count": 0, "folds": [], "status": INCONCLUSIVE,
        }
        regime_analysis = {
            "analysis_version": "regime-analysis-v1", "states": [],
            "coverage": {"development_observations": len(development),
                         "classified_observations": 0,
                         "unclassified_warmup_observations": len(development),
                         "state_observations_sum": 0},
            "status": INCONCLUSIVE,
        }
        cost_stress = {
            "basis": "development_walk_forward_only", "multipliers": [], "rows": [],
            "required_2x_present": False, "status": INCONCLUSIVE,
        }
    else:
        walk_forward, development_result, equity, benchmark, trades = _walk_forward(
            development, folds, rule=rule, costs=costs,
            benchmark_frame=benchmark_frame, benchmark_symbol=benchmark_symbol,
        )
        walk_forward["status"] = PASS
        regime_market = benchmark_frame if benchmark_frame is not None else development
        regime_analysis = analyze_regimes(
            regime_market, equity, benchmark, trades,
        )
        declared_multipliers = sorted(
            {float(value) for value in spec["validation"]["cost_stress"]["multipliers"]})
        stress_rows = []
        for multiplier in declared_multipliers:
            if math.isclose(multiplier, 1.0):
                stressed = development_result
            else:
                _wf, stressed, _eq, _bench, _trades = _walk_forward(
                    development, folds, rule=rule, costs=costs,
                    benchmark_frame=benchmark_frame,
                    benchmark_symbol=benchmark_symbol,
                    cost_multiplier=multiplier,
                )
            stress_rows.append({
                "multiplier": multiplier,
                "development": {
                    key: stressed["strategy_metrics"].get(key)
                    for key in ("total_return", "sharpe", "total_costs")
                },
            })
        cost_stress = {
            "basis": "development_walk_forward_only",
            "multipliers": declared_multipliers,
            "rows": stress_rows,
            "base_costs_bps": costs,
            "required_2x_present": 2.0 in declared_multipliers,
            "status": PASS if 2.0 in declared_multipliers else INCONCLUSIVE,
            "note": "The final holdout is never re-run for cost counterfactuals.",
        }

    sensitivity = {
        "basis": "locked_rule_only",
        "status": "NOT_RUN",
        "grid": [],
        "parameter_selection": "forbidden",
        "locked_rule_sha256": sha256_json(rule),
        "note": "Validation Battery v2 performs no parameter search or selection.",
    }

    wf_ratio = walk_forward.get("positive_fold_ratio")
    if wf_ratio is None:
        wf_status = INCONCLUSIVE
        wf_summary = "Walk-forward stability is unavailable because no valid fold exists."
    else:
        wf_status = PASS if wf_ratio >= 0.5 else FAIL
        wf_summary = (
            "At least half of the fixed-rule development folds were positive."
            if wf_status == PASS else
            "Fewer than half of the fixed-rule development folds were positive."
        )

    base = next((r for r in cost_stress["rows"] if r["multiplier"] == 1.0), None)
    doubled = next((r for r in cost_stress["rows"] if r["multiplier"] == 2.0), None)
    if base is None or doubled is None:
        cost_status = INCONCLUSIVE
        cost_summary = "Development cost fragility is unavailable without 1x and 2x cases."
    else:
        base_return = base["development"].get("total_return")
        stressed_return = doubled["development"].get("total_return")
        fragile = bool(
            stressed_return is not None and (
                stressed_return < 0
                or (base_return is not None and base_return > 0
                    and stressed_return < 0.5 * base_return)
            )
        )
        cost_status = FAIL if fragile else PASS
        cost_summary = (
            "The fixed rule is fragile under doubled development transaction costs."
            if fragile else "The fixed rule survived doubled development transaction costs."
        )
    regime_status = regime_analysis["status"]
    findings = [
        _finding("walk_forward_stability", wf_status, wf_summary, {
            "positive_fold_ratio": wf_ratio,
            "fold_count": walk_forward.get("fold_count", 0),
            "worst_fold_return": walk_forward.get("worst_fold_return"),
        }),
        _finding("development_cost_fragility", cost_status, cost_summary, {
            "base": base, "doubled": doubled,
        }),
        _finding("regime_coverage", regime_status,
                 "Each preregistered regime needs at least 20 development observations.",
                 {"coverage": regime_analysis["coverage"],
                  "states": [{"regime": item["regime"],
                              "status": item["status"],
                              "observations": item["observations"]}
                             for item in regime_analysis.get("states", [])]}),
    ]
    statuses = [item["status"] for item in findings]
    battery_status = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS
    inconclusive = [item["id"] for item in findings if item["status"] == INCONCLUSIVE]
    falsification = {
        "non_suppressible": True,
        "battery_version": "battery-v2",
        "required_checks": [item["id"] for item in findings],
        "checks_run": [item["id"] for item in findings],
        "findings": findings,
        "any_failing": FAIL in statuses,
        "any_inconclusive": bool(inconclusive),
        "status": battery_status,
        "completeness": {
            "all_required_reported": True,
            "all_checks_conclusive": not inconclusive,
            "unavailable_checks": inconclusive,
            "evidence_complete": not inconclusive,
        },
    }
    return {
        "development_result": development_result,
        "walk_forward": walk_forward,
        "regime_analysis": regime_analysis,
        "sensitivity": sensitivity,
        "cost_stress": cost_stress,
        "falsification": falsification,
        "evidence_status": {
            "evidence_complete": not inconclusive,
            "battery_status": battery_status,
            "final_holdout_status": "NOT_RUN",
        },
    }


__all__ = ["run_development_battery_v2"]
