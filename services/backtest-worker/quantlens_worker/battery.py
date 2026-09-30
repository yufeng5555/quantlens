"""Battery v1: IS/OOS separation, transaction-cost stress, parameter sensitivity, and
falsification findings — all deterministic engine artifacts (no LLM anywhere).

IS/OOS isolation (AT-8.1): the sensitivity sweep receives ONLY the in-sample slice of the
data — out-of-sample rows are physically absent from anything a sweep can read. Every
actual OOS engine execution (one primary evaluation plus declared counterfactual cost
stresses) is recorded; the base 1x stress reuses the primary result. OOS signal warm-up may
read earlier (in-sample/past) bars — past data only, never future.
"""

from __future__ import annotations

import math

import pandas as pd

from .config import BATTERY_CONFIG, INITIAL_CAPITAL
from .engine import backtest, compute_metrics
from .snapshot import DataQualityError

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"


def split_indices(n: int, oos_fraction: float) -> tuple[int, int]:
    """(is_end, n): IS = bars [0, is_end), OOS = bars [is_end, n)."""
    oos_bars = max(1, int(round(n * oos_fraction)))
    is_end = n - oos_bars
    if is_end < 10:
        raise ValueError("In-sample window too small after split")
    return is_end, n


def _segment_result(df: pd.DataFrame, rule: dict, costs: dict, window: tuple[int, int],
                    cost_multiplier: float = 1.0,
                    benchmark_df: pd.DataFrame | None = None,
                    benchmark_symbol: str | None = None) -> dict:
    # Capital is passed explicitly so the whole battery (engine accounting, metric
    # baselines, benchmark entry) shares one configured value — nothing is frozen into
    # a default argument or a display string (P1-6).
    r = backtest(
        df, rule, costs, cost_multiplier=cost_multiplier, window=window,
        benchmark_df=benchmark_df, benchmark_symbol=benchmark_symbol,
        initial_capital=INITIAL_CAPITAL)
    bench_start = r["benchmark"]["date"].iloc[0] if not r["benchmark"].empty else None
    # The segment metric always covers the declared evaluation window.  A second metric
    # view is retained for direct benchmark comparisons from the benchmark entry date.
    strat = compute_metrics(r["equity"], r["trades"], INITIAL_CAPITAL)
    comparison_strat = compute_metrics(
        r["equity"], r["trades"], INITIAL_CAPITAL, comparison_start=bench_start)
    # The benchmark's single entry fill (same cost model) counts as a trade so the
    # report's fills/costs columns agree with the stated methodology (AT-6.1).
    bench_trades = [r["benchmark_entry"]] if r["benchmark_entry"] else []
    bench = compute_metrics(r["benchmark"], bench_trades, INITIAL_CAPITAL) \
        if not r["benchmark"].empty else {"n_bars": 0, "note": "no benchmark window"}
    return {"raw": r, "strategy": strat, "comparison_strategy": comparison_strat,
            "benchmark": bench,
            "comparison_start": bench_start}


def run_battery(df: pd.DataFrame, spec: dict,
                benchmark_df: pd.DataFrame | None = None) -> dict:
    """Full battery on one loaded frame. Returns a dict of artifact payloads."""
    rule = spec["rule"]
    costs = spec["costs"]
    frac = spec["validation"]["is_oos_split"]["oos_fraction"]
    grid = spec["validation"]["sensitivity"]["grid"]["ma_days"]
    multipliers = sorted(spec["validation"]["cost_stress"]["multipliers"])
    benchmark_spec_symbol = spec["benchmark"]["symbol"]
    benchmark_symbol = (spec["universe"]["symbol"]
                        if benchmark_spec_symbol == "same_as_universe"
                        else benchmark_spec_symbol)

    if benchmark_spec_symbol != "same_as_universe" and benchmark_df is None:
        raise ValueError(
            f"benchmark_df is required for alternate benchmark {benchmark_spec_symbol}")
    if benchmark_df is not None:
        benchmark_dates = benchmark_df["date"].reset_index(drop=True)
        strategy_dates = df["date"].reset_index(drop=True)
        if len(benchmark_df) != len(df) or not benchmark_dates.equals(strategy_dates):
            raise DataQualityError(
                "BENCHMARK_DATE_MISMATCH",
                "Strategy and benchmark frames do not have exactly the same ordered dates "
                "over the requested range.")

    n = len(df)
    is_end, _ = split_indices(n, frac)
    is_df = df.iloc[:is_end].reset_index(drop=True)  # the ONLY frame sweeps may touch
    is_benchmark_df = (benchmark_df.iloc[:is_end].reset_index(drop=True)
                       if benchmark_df is not None else None)

    # All IS cells use the same warmup and the same evaluation interval.  The largest
    # declared window determines the first bar on which every cell has a prior, defined
    # close signal that can be acted on at the open.
    windows = [rule["ma_days"], *grid]
    if rule.get("fast_ma_days") is not None:
        windows.append(rule["fast_ma_days"])
    shared_warmup_bars = max(windows)
    is_eval_start = shared_warmup_bars
    if is_eval_start >= is_end:
        raise DataQualityError(
            "INSUFFICIENT_IS_EVALUATION",
            "In-sample evaluation has no actionable observation after the shared "
            f"{shared_warmup_bars}-bar warmup")
    is_window = (is_eval_start, is_end)

    # --- primary segments -------------------------------------------------
    is_res = _segment_result(
        is_df, rule, costs, is_window, benchmark_df=is_benchmark_df,
        benchmark_symbol=benchmark_symbol)

    oos_execution_records: list[dict] = []

    def execute_oos(purpose: str, cost_multiplier: float) -> tuple[dict, str]:
        """Execute and record every actual read of the held-out evaluation window."""
        result = _segment_result(
            df, rule, costs, (is_end, n), cost_multiplier=cost_multiplier,
            benchmark_df=benchmark_df, benchmark_symbol=benchmark_symbol)
        execution_id = f"oos-exec-{len(oos_execution_records) + 1:03d}"
        oos_execution_records.append({
            "execution_id": execution_id,
            "purpose": purpose,
            "cost_multiplier": cost_multiplier,
            "warmup": {
                "start": df["date"].iloc[0],
                "end": df["date"].iloc[is_end - 1],
                "bars": is_end,
            },
            "evaluation": {
                "start": df["date"].iloc[is_end],
                "end": df["date"].iloc[n - 1],
                "bars": n - is_end,
            },
            "strategy_n_bars": result["strategy"].get("n_bars", 0),
            "strategy_n_trades": result["strategy"].get("n_trades", 0),
        })
        return result, execution_id

    # OOS: full frame for signal warm-up (past bars), accounting window = OOS bars only.
    oos_res, primary_oos_execution_id = execute_oos("primary_evaluation", 1.0)

    segments = {
        "is": {
            "start": df["date"].iloc[0],
            "end": df["date"].iloc[is_end - 1],
            "bars": is_end,
            "warmup": {
                "start": df["date"].iloc[0],
                "end": df["date"].iloc[is_eval_start - 1],
                "bars": shared_warmup_bars,
            },
            "evaluation": {
                "start": df["date"].iloc[is_eval_start],
                "end": df["date"].iloc[is_end - 1],
                "bars": is_end - is_eval_start,
            },
        },
        "oos": {
            "start": df["date"].iloc[is_end],
            "end": df["date"].iloc[n - 1],
            "bars": n - is_end,
            "evaluation": {
                "start": df["date"].iloc[is_end],
                "end": df["date"].iloc[n - 1],
                "bars": n - is_end,
            },
            "prior_data_warmup_bars": is_end,
        },
    }

    # --- sensitivity (IS ONLY) -------------------------------------------
    chosen = rule["ma_days"]
    cells = []
    for w in sorted(grid):
        cell_rule = dict(rule, ma_days=w)
        if rule["type"] == "ma_crossover" and rule["fast_ma_days"] is not None \
                and rule["fast_ma_days"] >= w:
            cells.append({"ma_days": w, "skipped": "fast >= slow for this cell"})
            continue
        # The chosen cell is exactly the primary IS execution; reuse it instead of
        # performing a duplicate 1x/base execution.
        res = is_res if w == chosen else _segment_result(
            is_df, cell_rule, costs, is_window, benchmark_df=is_benchmark_df,
            benchmark_symbol=benchmark_symbol)
        cells.append({"ma_days": w,
                      "sharpe": res["strategy"].get("sharpe", 0.0),
                      "total_return": res["strategy"].get("total_return", 0.0),
                      "max_drawdown": res["strategy"].get("max_drawdown", 0.0),
                      "n_trades": res["strategy"].get("n_trades", 0),
                      "exposure": res["strategy"].get("exposure", 0.0),
                      "evaluation_start": df["date"].iloc[is_eval_start],
                      "evaluation_end": df["date"].iloc[is_end - 1],
                      "evaluation_bars": is_end - is_eval_start})
    valid_cells = [c for c in cells if "skipped" not in c]
    chosen_cell = next((c for c in valid_cells if c["ma_days"] == chosen), None)
    percentile = None
    if chosen_cell and len(valid_cells) > 1:
        below = sum(1 for c in valid_cells if c["sharpe"] <= chosen_cell["sharpe"])
        percentile = round(100.0 * below / len(valid_cells))
    neighbors = []
    if chosen_cell:
        ordered = sorted(valid_cells, key=lambda c: c["ma_days"])
        idx = ordered.index(chosen_cell)
        neighbors = [ordered[i] for i in (idx - 1, idx + 1) if 0 <= i < len(ordered)]

    sensitivity = {
        "basis": "in_sample_only",
        "metric": BATTERY_CONFIG["parameter_fragility"]["metric"],
        "grid": cells,
        "chosen_ma_days": chosen,
        "chosen_cell": chosen_cell,
        "chosen_percentile_in_grid": percentile,
        "neighbors": neighbors,
        "shared_warmup_bars": shared_warmup_bars,
        "evaluation": segments["is"]["evaluation"],
        "note": "Sweeps read the in-sample slice only; the full grid is shown, never only "
                "the best cell, and every valid cell uses the same post-warmup evaluation "
                "interval (AT-9.1).",
    }

    if is_res["strategy"].get("n_bars", 0) < 1:
        raise DataQualityError(
            "INSUFFICIENT_IS_EVALUATION",
            "Chosen/base cell has no actionable post-warmup observation")

    # --- cost stress (IS and OOS, reported separately) --------------------
    stress_rows = []
    for m in multipliers:
        if float(m) == 1.0:
            is_m = is_res
            oos_m = oos_res
            oos_execution_id = primary_oos_execution_id
            reused_primary = True
        else:
            is_m = _segment_result(
                is_df, rule, costs, is_window, cost_multiplier=m,
                benchmark_df=is_benchmark_df, benchmark_symbol=benchmark_symbol)
            oos_m, oos_execution_id = execute_oos("cost_stress", m)
            reused_primary = False
        stress_rows.append({
            "multiplier": m,
            "is": {k: is_m["strategy"].get(k) for k in ("total_return", "sharpe", "total_costs")},
            "oos": {k: oos_m["strategy"].get(k) for k in ("total_return", "sharpe", "total_costs")},
            "oos_execution_id": oos_execution_id,
            "reused_primary_evaluation": reused_primary,
        })
    cost_stress = {"multipliers": multipliers, "rows": stress_rows,
                   "base_costs_bps": costs,
                   "required_2x_present": any(float(m) == 2.0 for m in multipliers),
                   "note": "IS and OOS reported separately; no blended headline (AT-8.2)."}

    # --- falsification (non-suppressible; every check always reported) ----
    findings = []
    cfg = BATTERY_CONFIG

    is_sharpe = is_res["strategy"].get("sharpe", 0.0)
    oos_sharpe = oos_res["strategy"].get("sharpe", 0.0)
    is_ret = is_res["strategy"].get("total_return", 0.0)
    oos_ret = oos_res["strategy"].get("total_return", 0.0)
    is_activity = (is_res["strategy"].get("n_trades", 0) > 0
                   and is_res["strategy"].get("exposure", 0.0) > 0)
    oos_activity = (oos_res["strategy"].get("n_trades", 0) > 0
                    and oos_res["strategy"].get("exposure", 0.0) > 0)
    decay_fired = (is_sharpe > 0 and oos_sharpe < cfg["oos_decay"]["sharpe_retention_min"] * is_sharpe) \
        or (is_ret > 0 and oos_ret < 0)
    if not is_activity:
        decay_status = INCONCLUSIVE
        decay_summary = (
            "Out-of-sample decay is unavailable because the strategy had no in-sample "
            "trades and positive exposure in the common evaluation interval.")
    elif decay_fired:
        decay_status = FAIL
        decay_summary = (
            "Out-of-sample performance decays materially versus in-sample — the "
            "in-sample result may be fitted to noise.")
    elif not oos_activity:
        decay_status = INCONCLUSIVE
        decay_summary = (
            "Out-of-sample decay is unavailable because the held-out interval had no "
            "executed exposure and the declared decay threshold did not otherwise fire.")
    else:
        decay_status = PASS
        decay_summary = (
            "Out-of-sample performance did not decay beyond the declared threshold.")
    findings.append({
        "id": "oos_decay", "status": decay_status,
        "rule": cfg["oos_decay"]["description"],
        "evidence": {"is_sharpe": is_sharpe, "oos_sharpe": oos_sharpe,
                     "is_total_return": is_ret, "oos_total_return": oos_ret,
                     "is_activity_available": is_activity,
                     "oos_activity_available": oos_activity},
        "summary": decay_summary,
    })

    base_row = next((r for r in stress_rows if float(r["multiplier"]) == 1.0), None)
    stressed_row = next((r for r in stress_rows
                         if float(r["multiplier"]) ==
                         float(cfg["cost_fragility"]["stress_multiplier"])), None)
    b_oos = base_row["oos"]["total_return"] if base_row else None
    s_oos = stressed_row["oos"]["total_return"] if stressed_row else None
    no_effective_base_cost = (
        float(costs["commission_bps"]) + float(costs["slippage_bps"]) == 0.0)
    cost_fired = False
    if base_row is None or stressed_row is None:
        cost_status = INCONCLUSIVE
        cost_summary = (
            "Cost fragility is unavailable because both the base 1x case and the required "
            "2x cost-stress case were not executed.")
    elif not oos_activity:
        cost_status = INCONCLUSIVE
        cost_summary = (
            "Cost fragility is unavailable because the OOS interval had no trades or "
            "positive exposure to stress.")
    elif no_effective_base_cost:
        cost_status = INCONCLUSIVE
        cost_summary = (
            "Cost fragility is unavailable because doubling a zero-cost model applies no "
            "additional economic stress.")
    elif b_oos is None or s_oos is None or not math.isfinite(b_oos) or not math.isfinite(s_oos):
        cost_status = INCONCLUSIVE
        cost_summary = "Cost fragility is unavailable because a required return is missing."
    else:
        cost_fired = (s_oos < 0) or (
            b_oos > 0
            and s_oos < cfg["cost_fragility"]["return_retention_min"] * b_oos)
        cost_status = FAIL if cost_fired else PASS
        cost_summary = (
            "The result does not survive doubled transaction costs — the edge may be "
            "smaller than the friction required to capture it."
            if cost_fired else
            "The result survived the declared 2x cost stress.")
    findings.append({
        "id": "cost_fragility", "status": cost_status,
        "rule": cfg["cost_fragility"]["description"],
        "evidence": {"base_oos_return": b_oos,
                     "stressed_oos_return": s_oos,
                     "required_multiplier": cfg["cost_fragility"]["stress_multiplier"],
                     "base_case_present": base_row is not None,
                     "required_stress_present": stressed_row is not None,
                     "oos_activity_available": oos_activity},
        "summary": cost_summary,
    })

    param_fired, worst = False, None
    ref = chosen_cell.get("sharpe") if chosen_cell else None
    if chosen_cell is None:
        param_status = INCONCLUSIVE
        param_summary = "Parameter fragility is unavailable because the chosen cell is missing."
    elif not neighbors:
        param_status = INCONCLUSIVE
        param_summary = (
            "Parameter fragility is unavailable because the chosen cell has no valid "
            "adjacent grid neighbor.")
    elif ref is None or not math.isfinite(ref) or ref == 0:
        param_status = INCONCLUSIVE
        param_summary = (
            "Parameter fragility is unavailable because the chosen cell's reference "
            "Sharpe is missing, non-finite, or zero.")
    elif any(nb.get("sharpe") is None or not math.isfinite(nb["sharpe"])
             for nb in neighbors):
        param_status = INCONCLUSIVE
        param_summary = (
            "Parameter fragility is unavailable because an adjacent cell has no finite "
            "Sharpe observation.")
    else:
        for nb in neighbors:
            loss = math.inf if (ref > 0 and nb["sharpe"] <= 0) else \
                ((ref - nb["sharpe"]) / abs(ref))
            if loss >= cfg["parameter_fragility"]["neighbor_loss_max"]:
                param_fired = True
                if worst is None or nb["sharpe"] < worst["sharpe"]:
                    worst = nb
        param_status = FAIL if param_fired else PASS
        param_summary = (
            "Nearby parameter choices lose a large share of the chosen cell's result — "
            "the chosen window may be a lucky cell."
            if param_fired else
            "Adjacent parameter choices hold up within the declared threshold.")
    findings.append({
        "id": "parameter_fragility", "status": param_status,
        "rule": cfg["parameter_fragility"]["description"],
        "evidence": {"chosen_cell": chosen_cell, "neighbors": neighbors,
                     "reference_sharpe": ref, "worst_neighbor": worst},
        "summary": param_summary,
    })

    required_checks = ["oos_decay", "cost_fragility", "parameter_fragility"]
    unavailable_checks = [f["id"] for f in findings if f["status"] == INCONCLUSIVE]
    all_required_reported = {f["id"] for f in findings} == set(required_checks)
    evidence_complete = all_required_reported and not unavailable_checks
    if any(f["status"] == FAIL for f in findings):
        battery_status = FAIL
    elif unavailable_checks:
        battery_status = INCONCLUSIVE
    else:
        battery_status = PASS
    falsification = {
        "non_suppressible": True,
        "battery_version": cfg["battery_version"],
        "checks_run": [f["id"] for f in findings],
        "required_checks": required_checks,
        "findings": findings,
        "any_failing": any(f["status"] == FAIL for f in findings),
        "any_inconclusive": bool(unavailable_checks),
        "status": battery_status,
        "completeness": {
            "all_required_reported": all_required_reported,
            "all_checks_conclusive": not unavailable_checks,
            "unavailable_checks": unavailable_checks,
            "evidence_complete": evidence_complete,
        },
    }

    def _slim(res: dict) -> dict:
        eq = res["raw"]["equity"]
        bench = res["raw"]["benchmark"]
        return {
            "strategy_metrics": res["strategy"],
            "comparison_strategy_metrics": res["comparison_strategy"],
            "benchmark_metrics": res["benchmark"],
            "benchmark_symbol": res["raw"]["benchmark_symbol"],
            "comparison_start": res["comparison_start"],
            "equity_series": {"date": eq["date"].tolist(),
                              "equity": eq["equity"].tolist(),
                              "position": eq["position"].tolist()},
            "benchmark_series": {"date": bench["date"].tolist() if not bench.empty else [],
                                 "equity": bench["equity"].tolist() if not bench.empty else []},
            "trades": res["raw"]["trades"],
            "benchmark_entry": res["raw"]["benchmark_entry"],
        }

    primary_count = sum(
        r["purpose"] == "primary_evaluation" for r in oos_execution_records)
    oos_execution_audit = {
        "count": len(oos_execution_records),
        "primary_evaluation_count": primary_count,
        "cost_stress_execution_count": len(oos_execution_records) - primary_count,
        "count_semantics": (
            "count includes the one primary OOS estimate and every distinct preregistered "
            "cost-stress counterfactual; the base 1x row reuses the primary execution"),
        "base_1x_reused_for_cost_stress": any(
            row["reused_primary_evaluation"] for row in stress_rows),
        "records": oos_execution_records,
    }

    return {
        "segments": segments,
        "is_result": _slim(is_res),
        "oos_result": _slim(oos_res),
        "oos_executions": len(oos_execution_records),
        "oos_primary_executions": primary_count,
        "oos_execution_audit": oos_execution_audit,
        "sensitivity": sensitivity,
        "cost_stress": cost_stress,
        "falsification": falsification,
        "evidence_complete": evidence_complete,
        "battery_status": battery_status,
        "benchmark_symbol": benchmark_symbol,
    }
