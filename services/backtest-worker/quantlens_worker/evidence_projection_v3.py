"""Development evidence projection for a v3 run (Gate E Stop C2).

Projects one dormant continuous-development coordinator output — a plain data
mapping of executions produced under the corrected fill semantics — into the
seven development-side sealed artifact payloads: ``development_result``,
``walk_forward``, ``regime_analysis``, ``sensitivity``, ``cost_stress``,
``falsification`` and ``evidence_status``.  Every projected number re-expresses
the independent semantic validator's own reconstruction laws (display metrics,
fold carry-chain baselines, regime labels, falsification truth table) so the
sealed payloads are exactly what that validator re-derives on read.

Boundary law: this module receives the coordinator output and the expected
continuous-path marker as ARGUMENTS — it imports neither dormant Gate C/D
module, names neither, and carries no reserved marker literal; the exact marker
values are enforced downstream by the sealed schemas, the resolver and the
validator.  Imports are stdlib plus the dormant Gate B ledger module (for the
shared canonical hash helper) only.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import json
import math
import statistics
from typing import Any, Mapping, Sequence

from .valuation_ledger_v1 import sha256_json

ANNUALIZATION_SESSIONS = 252

_REGIMES = ("up_low", "up_high", "down_low", "down_high")
_MINIMUM_REGIME_OBSERVATIONS = 20
_REGIME_NOTE = (
    "Non-contiguous regime observations are not used to compute drawdown.")
_COST_STRESS_NOTE = (
    "The final holdout is never re-run for cost counterfactuals.")
_SENSITIVITY_NOTE = (
    "Validation Battery v3 performs no parameter search or selection.")
_FINDING_RULE = "server-owned Validation Battery v3 law"
_BATTERY_VERSION = "battery-v3"

_EXECUTION_KEYS = frozenset({
    "execution_id", "role", "purpose", "window", "cost_multiplier",
    "carry_in", "carry_in_sha256", "carry_out", "carry_out_sha256",
    "bars", "fills",
})
_FOLD_ROW_SOURCE_KEYS = (
    "fold_id", "train_start_index", "train_end_index", "train_start",
    "train_end", "train_bars", "test_start_index", "test_end_index",
    "test_start", "test_end", "test_bars", "visible_prefix_end_index",
    "visible_prefix_sha256",
)


class EvidenceProjectionV3Error(ValueError):
    """One projection input violates a coordinator/validator law; fail closed."""


def _fail(detail: str) -> None:
    raise EvidenceProjectionV3Error(detail)


def _require(condition: bool, detail: str) -> None:
    if not condition:
        _fail(detail)


def _fresh(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        raise EvidenceProjectionV3Error(
            f"{label} must contain only finite canonical JSON values"
        ) from exc


def _canonical_equal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) \
        == json.dumps(right, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label} must be a number")
    numeric = float(value)
    if not math.isfinite(numeric):
        _fail(f"{label} must be finite")
    return numeric


def _index(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def reconstruct_display_metrics_v3(
    bars: Sequence[Mapping[str, Any]],
    fills: Sequence[Mapping[str, Any]],
    metric_baseline: float,
) -> dict[str, Any]:
    """The independent validator's exact display-metric reconstruction law.

    Fourteen display metrics over one execution's bars/fills with the supplied
    metric baseline prefixed onto the equity path: sample standard deviation,
    252-session annualization, ``math.fsum`` cost totals, and a zero Sharpe for
    degenerate return series.
    """
    _require(bool(bars), "an execution must contain at least one bar")
    baseline = _number(metric_baseline, "metric_baseline")
    _require(baseline > 0, "metric_baseline must be positive")
    equities = [_number(bar["equity"], "bar.equity") for bar in bars]
    metric_path = [baseline, *equities]
    returns = [current / previous - 1.0
               for previous, current in zip(metric_path, metric_path[1:])]
    std = statistics.stdev(returns) if len(returns) >= 2 else 0.0
    peak = metric_path[0]
    max_drawdown = 0.0
    for value in metric_path:
        peak = max(peak, value)
        max_drawdown = min(max_drawdown, value / peak - 1.0)
    n = len(bars)
    return {
        "start_date": bars[0]["date"],
        "end_date": bars[-1]["date"],
        "n_bars": n,
        "initial_capital": baseline,
        "n_return_observations": len(returns),
        "total_return": equities[-1] / baseline - 1.0,
        "cagr": (equities[-1] / baseline) ** (ANNUALIZATION_SESSIONS / n) - 1.0,
        "ann_vol": std * math.sqrt(ANNUALIZATION_SESSIONS),
        "sharpe": (
            statistics.fmean(returns) / std * math.sqrt(ANNUALIZATION_SESSIONS)
            if len(returns) >= 2 and std > 0 else 0.0),
        "max_drawdown": max_drawdown,
        "n_trades": len(fills),
        "total_costs": math.fsum(
            float(fill["commission"]) + float(fill["slippage_amount"])
            for fill in fills),
        "exposure": statistics.fmean(float(bar["position"]) for bar in bars),
        "final_equity": equities[-1],
    }


def fold_metric_baseline_v3(
    fold_position: int,
    fold_execution: Mapping[str, Any],
    previous_fold_execution: Mapping[str, Any] | None,
    initial_capital: float,
) -> float:
    """The validator's carry-chain fold baseline law.

    The first fold starts at the contract initial capital; every carried fold
    values its carry-in at the prior fold's closing price, after proving the
    carry-in equals the prior fold's carry-out both as an object and by hash.
    """
    if fold_position == 0:
        return float(initial_capital)
    _require(previous_fold_execution is not None,
             "a carried fold requires its predecessor execution")
    assert previous_fold_execution is not None
    carry_in = fold_execution["carry_in"]
    _require(
        _canonical_equal(carry_in, previous_fold_execution["carry_out"])
        and fold_execution["carry_in_sha256"]
        == previous_fold_execution["carry_out_sha256"],
        "fold carry-in does not equal the prior fold carry-out object and hash",
    )
    previous_close = _number(
        previous_fold_execution["bars"][-1]["close"], "prior fold close")
    baseline = (
        float(carry_in["cash"]) + float(carry_in["shares"]) * previous_close)
    _require(
        math.isfinite(baseline) and baseline > 0,
        "the prior-close fold metric baseline must be finite and positive",
    )
    return baseline


def _validated_execution(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != _EXECUTION_KEYS:
        _fail(f"{label} must carry exactly the closed execution key set")
    assert isinstance(raw, Mapping)
    _require(bool(raw["bars"]), f"{label} must contain at least one bar")
    return dict(raw)


def index_executions_v3(
    executions: Sequence[Any],
    *,
    folds: Sequence[Mapping[str, Any]],
    multipliers: Sequence[float],
    development_evaluation: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify the flat coordinator execution list under the closed coverage law.

    Exactly ``2 + 2*F + 2*M`` development executions must be present (one
    primary pair, one fold-slice pair per fold at multiplier 1.0, one
    cost-stress pair per declared multiplier over the full development
    evaluation window); the independent validator's full-ledger count adds the
    final-holdout pair on top of this development set.  Every non-1.0
    execution must be a cost-stress path — non-1.0 fold slices are never
    retained by the coordinator.
    """
    start = _index(development_evaluation["start_index"], "evaluation start")
    end = _index(development_evaluation["end_index_exclusive"],
                 "evaluation end", minimum=1)
    primary: dict[str, dict[str, Any]] = {}
    fold_slices: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
    stress: dict[float, dict[str, dict[str, Any]]] = {}
    seen_ids: set[str] = set()
    for position, raw in enumerate(executions):
        execution = _validated_execution(raw, f"executions[{position}]")
        execution_id = execution["execution_id"]
        _require(execution_id not in seen_ids,
                 "execution ids must be unique across the coordinator output")
        seen_ids.add(execution_id)
        role = execution["role"]
        purpose = execution["purpose"]
        multiplier = _number(execution["cost_multiplier"], "cost_multiplier")
        window = (execution["window"]["start_index"],
                  execution["window"]["end_index_exclusive"])
        _require(role in ("strategy", "benchmark"),
                 "execution role must be strategy or benchmark")
        if multiplier != 1.0:
            _require(
                purpose == "cost_stress",
                "only cost-stress executions may carry a non-1.0 multiplier",
            )
        if purpose == "primary_evaluation":
            _require(window == (start, end),
                     "primary execution window must equal the development "
                     "evaluation window")
            _require(multiplier == 1.0,
                     "the primary evaluation runs at multiplier 1.0")
            _require(role not in primary,
                     "duplicate primary execution for one role")
            primary[role] = execution
        elif purpose == "fold_slice":
            _require(multiplier == 1.0,
                     "retained fold slices run at multiplier 1.0")
            bucket = fold_slices.setdefault(window, {})
            _require(role not in bucket,
                     "duplicate fold-slice execution for one role/window")
            bucket[role] = execution
        elif purpose == "cost_stress":
            _require(window == (start, end),
                     "cost-stress windows must cover the development "
                     "evaluation window only")
            bucket = stress.setdefault(multiplier, {})
            _require(role not in bucket,
                     "duplicate cost-stress execution for one role/multiplier")
            bucket[role] = execution
        else:
            _fail("development projection accepts no final-holdout execution")

    _require(set(primary) == {"strategy", "benchmark"},
             "the primary evaluation pair is incomplete")
    declared_windows = [
        (_index(fold["test_start_index"], "fold test_start_index"),
         _index(fold["test_end_index"], "fold test_end_index", minimum=1))
        for fold in folds
    ]
    _require(
        set(fold_slices) == set(declared_windows)
        and all(set(pair) == {"strategy", "benchmark"}
                for pair in fold_slices.values()),
        "fold-slice coverage does not match the declared partition folds",
    )
    _require(
        set(stress) == {float(value) for value in multipliers}
        and all(set(pair) == {"strategy", "benchmark"}
                for pair in stress.values()),
        "cost-stress coverage does not match the declared multipliers",
    )
    expected_count = 2 + 2 * len(folds) + 2 * len(multipliers)
    _require(len(seen_ids) == expected_count,
             "execution coverage contains an undeclared, missing, or "
             "duplicate role/purpose pair")
    return {
        "primary": primary,
        "fold_slices": [fold_slices[window] for window in declared_windows],
        "cost_stress": stress,
    }


def _canonical_multipliers(spec: Mapping[str, Any]) -> list[float]:
    validation = spec.get("validation")
    if not isinstance(validation, Mapping) \
            or not isinstance(validation.get("cost_stress"), Mapping) \
            or not isinstance(
                validation["cost_stress"].get("multipliers"), list):
        _fail("spec.validation.cost_stress.multipliers is missing")
    values = [
        _number(value, "cost stress multiplier")
        for value in validation["cost_stress"]["multipliers"]
    ]
    _require(bool(values), "cost stress multipliers must be non-empty")
    _require(all(value >= 0 for value in values),
             "cost stress multipliers must be non-negative")
    _require(len(set(values)) == len(values),
             "cost stress multipliers must be unique")
    _require(1.0 in values, "cost stress multipliers must include exactly 1.0")
    return sorted(values)


def _fresh_carry(execution: Mapping[str, Any], initial_capital: float,
                 label: str) -> None:
    expected = {"cash": float(initial_capital), "shares": 0.0, "position": 0}
    _require(
        _canonical_equal(execution["carry_in"], expected),
        f"{label} must start from a fresh flat carry at the contract capital",
    )


def _series_labels(closes: Sequence[float], dates: Sequence[str]) -> dict:
    """The validator's exact t-1 regime labeling law over benchmark closes."""
    daily: list[float | None] = [None]
    daily.extend(closes[index] / closes[index - 1] - 1.0
                 for index in range(1, len(closes)))
    output: dict[str, str | None] = {}
    for index, session in enumerate(dates):
        if index < 200 or index < 64:
            output[session] = None
            continue
        prior_returns = [value for value in daily[index - 63:index]
                         if value is not None]
        if len(prior_returns) != 63:
            output[session] = None
            continue
        trend = "up" if closes[index - 1] >= statistics.fmean(
            closes[index - 200:index]) else "down"
        volatility = "high" if statistics.stdev(prior_returns) \
            * math.sqrt(252) >= 0.20 else "low"
        output[session] = f"{trend}_{volatility}"
    return output


def _daily_returns(execution: Mapping[str, Any], initial: float) -> dict:
    previous = initial
    values: dict[str, float] = {}
    for bar in execution["bars"]:
        equity = float(bar["equity"])
        values[bar["date"]] = equity / previous - 1.0
        previous = equity
    return values


def _project_regimes(
    primary: Mapping[str, Mapping[str, Any]],
    benchmark_market: Mapping[str, Any],
    initial_capital: float,
) -> dict[str, Any]:
    strategy = primary["strategy"]
    benchmark = primary["benchmark"]
    dates = benchmark_market["dates"]
    closes = [_number(value, "benchmark close")
              for value in benchmark_market["closes"]]
    labels = _series_labels(closes, dates)
    strategy_returns = _daily_returns(strategy, float(initial_capital))
    benchmark_returns = _daily_returns(benchmark, float(initial_capital))
    _require(
        set(strategy_returns) == set(benchmark_returns),
        "strategy and benchmark primary windows are not aligned",
    )
    _require(
        set(strategy_returns) <= set(labels),
        "the benchmark market series does not cover the primary window",
    )
    strategy_bars = {bar["date"]: bar for bar in strategy["bars"]}
    trade_counts: dict[str, int] = {}
    for fill in strategy["fills"]:
        trade_counts[fill["session"]] = \
            trade_counts.get(fill["session"], 0) + 1
    states: list[dict[str, Any]] = []
    for state in _REGIMES:
        sessions = [session for session in strategy_returns
                    if labels.get(session) == state]
        observations = len(sessions)
        states.append({
            "regime": state,
            "status": ("PASS" if observations >= _MINIMUM_REGIME_OBSERVATIONS
                       else "INCONCLUSIVE"),
            "observations": observations,
            "strategy_compounded_return": (
                math.prod(1 + strategy_returns[session]
                          for session in sessions) - 1
                if observations else None),
            "benchmark_compounded_return": (
                math.prod(1 + benchmark_returns[session]
                          for session in sessions) - 1
                if observations else None),
            "mean_daily_excess_return": (
                statistics.fmean(
                    strategy_returns[session] - benchmark_returns[session]
                    for session in sessions)
                if observations else None),
            "exposure": (
                statistics.fmean(
                    strategy_bars[session]["position"]
                    for session in sessions)
                if observations else None),
            "trade_count": sum(
                trade_counts.get(session, 0) for session in sessions),
            "max_drawdown": None,
            "note": _REGIME_NOTE,
        })
    classified = sum(item["observations"] for item in states)
    coverage = {
        "development_observations": len(strategy["bars"]),
        "classified_observations": classified,
        "unclassified_warmup_observations": len(strategy["bars"]) - classified,
        "state_observations_sum": classified,
    }
    status = "PASS" if all(
        item["status"] == "PASS" for item in states) else "INCONCLUSIVE"
    return {
        "analysis_version": "regime-analysis-v1",
        "classification_law": {
            "trend": "benchmark_close[t-1] >= SMA200[t-1]",
            "volatility": "annualized_realized_vol_63[t-1] >= 0.20",
            "lookahead": False,
            "minimum_observations": _MINIMUM_REGIME_OBSERVATIONS,
        },
        "states": states,
        "coverage": coverage,
        "status": status,
    }


def _finding(identifier: str, status: str, summary: str,
             evidence: dict) -> dict[str, Any]:
    return {
        "id": identifier,
        "status": status,
        "rule": _FINDING_RULE,
        "summary": summary,
        "evidence": evidence,
    }


def project_development_evidence_v3(
    *,
    coordinator_output: Mapping[str, Any],
    expected_continuous_path_version: str,
    partitions: Mapping[str, Any],
    spec: Mapping[str, Any],
    initial_capital: float,
    benchmark_market: Mapping[str, Any],
) -> dict[str, Any]:
    """Project one coordinator output into the seven development payloads."""
    if not isinstance(coordinator_output, Mapping):
        _fail("coordinator_output must be a mapping")
    coordinator = _fresh(dict(coordinator_output), "coordinator_output")
    partitions = _fresh(dict(partitions), "partitions")
    spec = _fresh(dict(spec), "spec")
    market = _fresh(dict(benchmark_market), "benchmark_market")
    capital = _number(initial_capital, "initial_capital")
    _require(capital > 0, "initial_capital must be positive")

    marker = coordinator.get("continuous_path_version")
    _require(
        isinstance(expected_continuous_path_version, str)
        and bool(expected_continuous_path_version)
        and marker == expected_continuous_path_version,
        "coordinator output does not carry the expected continuous-path "
        "marker",
    )

    folds = partitions.get("folds")
    if not isinstance(folds, list) or not folds:
        _fail("partitions.folds must be a non-empty array")
    evaluation = coordinator.get("development_evaluation")
    expected_evaluation = {
        "start_index": _index(folds[0]["test_start_index"],
                              "first fold test_start_index"),
        "end_index_exclusive": _index(folds[-1]["test_end_index"],
                                      "last fold test_end_index", minimum=1),
    }
    expected_evaluation["observation_count"] = (
        expected_evaluation["end_index_exclusive"]
        - expected_evaluation["start_index"])
    _require(
        evaluation == expected_evaluation,
        "coordinator development_evaluation contradicts the partition folds",
    )

    multipliers = _canonical_multipliers(spec)
    indexed = index_executions_v3(
        coordinator.get("executions") or [],
        folds=folds, multipliers=multipliers,
        development_evaluation=evaluation)
    primary = indexed["primary"]
    fold_pairs = indexed["fold_slices"]
    stress = indexed["cost_stress"]

    # Fresh-carry and benchmark-entry laws over the full evaluation paths.
    for role in ("strategy", "benchmark"):
        _fresh_carry(primary[role], capital, f"primary {role} execution")
        for multiplier in multipliers:
            _fresh_carry(stress[multiplier][role], capital,
                         f"cost-stress {role} execution at {multiplier}")
    _require(
        len(primary["benchmark"]["fills"]) == 1,
        "the benchmark primary execution must contain exactly one entry fill",
    )
    # The 1.0 stress path must be byte-identical to the primary evaluation.
    for role in ("strategy", "benchmark"):
        base = stress[1.0][role]
        for field in ("window", "carry_in", "carry_in_sha256", "carry_out",
                      "carry_out_sha256", "bars", "fills"):
            _require(
                _canonical_equal(base[field], primary[role][field]),
                "the 1.0 cost-stress path must be identical to the primary "
                f"evaluation ({role}/{field})",
            )

    # Benchmark market alignment at exact global indices over the window.
    dates = market.get("dates")
    closes = market.get("closes")
    if not isinstance(dates, list) or not isinstance(closes, list) \
            or len(dates) != len(closes):
        _fail("benchmark_market must carry aligned dates and closes")
    development_end = _index(
        partitions["development"]["end_index"], "development end_index",
        minimum=1)
    _require(len(dates) >= development_end,
             "benchmark_market must cover the full development region")
    start = evaluation["start_index"]
    for offset, bar in enumerate(primary["benchmark"]["bars"]):
        _require(
            dates[start + offset] == bar["date"],
            "benchmark_market dates do not match the primary window at the "
            "same global indices",
        )

    locked_rule_sha256 = sha256_json(spec["rule"])
    strategy_metrics = reconstruct_display_metrics_v3(
        primary["strategy"]["bars"], primary["strategy"]["fills"], capital)
    benchmark_metrics = reconstruct_display_metrics_v3(
        primary["benchmark"]["bars"], primary["benchmark"]["fills"], capital)

    # Fold rows under the carry-chain baseline law, per role.
    fold_rows: list[dict[str, Any]] = []
    fold_returns: list[float] = []
    fold_sharpes: list[float] = []
    for position, (fold, pair) in enumerate(zip(folds, fold_pairs)):
        row: dict[str, Any] = {
            key: fold[key] for key in _FOLD_ROW_SOURCE_KEYS if key in fold}
        row["locked_rule_sha256"] = locked_rule_sha256
        row["cost_multiplier"] = 1.0
        for role, target in (("strategy", "strategy_metrics"),
                             ("benchmark", "benchmark_metrics")):
            baseline = fold_metric_baseline_v3(
                position, pair[role],
                fold_pairs[position - 1][role] if position else None,
                capital)
            row[target] = reconstruct_display_metrics_v3(
                pair[role]["bars"], pair[role]["fills"], baseline)
        fold_rows.append(row)
        fold_returns.append(float(row["strategy_metrics"]["total_return"]))
        fold_sharpes.append(float(row["strategy_metrics"]["sharpe"]))

    walk_forward = {
        "continuous_path_version": marker,
        "development_evaluation": dict(evaluation),
        "mode": "expanding-fixed-rule",
        "parameter_selection": "forbidden",
        "locked_rule_sha256": locked_rule_sha256,
        "cost_multiplier": 1.0,
        "fold_count": len(fold_rows),
        "folds": fold_rows,
        "median_fold_sharpe": statistics.median(fold_sharpes),
        "positive_fold_ratio": (
            sum(value > 0 for value in fold_returns) / len(fold_returns)),
        "worst_fold_return": min(fold_returns),
        "fold_return_dispersion": (
            statistics.pstdev(fold_returns) if len(fold_returns) > 1 else 0.0),
        "stitched_development_total_return": (
            float(strategy_metrics["total_return"])),
        "status": "PASS",
    }

    benchmark_value = spec["benchmark"]["symbol"]
    benchmark_symbol = (
        spec["universe"]["symbol"] if benchmark_value == "same_as_universe"
        else benchmark_value)
    development_result = {
        "status": "COMPLETE",
        "strategy_metrics": strategy_metrics,
        "comparison_strategy_metrics": dict(strategy_metrics),
        "benchmark_metrics": benchmark_metrics,
        "benchmark_symbol": benchmark_symbol,
        "comparison_start": primary["benchmark"]["bars"][0]["date"],
        "equity_series": {
            "date": [bar["date"] for bar in primary["strategy"]["bars"]],
            "equity": [bar["equity"] for bar in primary["strategy"]["bars"]],
            "position": [bar["position"]
                         for bar in primary["strategy"]["bars"]],
        },
        "benchmark_series": {
            "date": [bar["date"] for bar in primary["benchmark"]["bars"]],
            "equity": [bar["equity"] for bar in primary["benchmark"]["bars"]],
        },
        "trades": [dict(fill) for fill in primary["strategy"]["fills"]],
        "benchmark_entry": dict(primary["benchmark"]["fills"][0]),
    }

    regime_analysis = _project_regimes(primary, market, capital)

    sensitivity = {
        "basis": "locked_rule_only",
        "status": "NOT_RUN",
        "grid": [],
        "parameter_selection": "forbidden",
        "locked_rule_sha256": locked_rule_sha256,
        "note": _SENSITIVITY_NOTE,
    }

    rows = []
    for multiplier in multipliers:
        stressed = reconstruct_display_metrics_v3(
            stress[multiplier]["strategy"]["bars"],
            stress[multiplier]["strategy"]["fills"], capital)
        rows.append({
            "multiplier": multiplier,
            "development": {
                "total_return": stressed["total_return"],
                "sharpe": stressed["sharpe"],
                "total_costs": stressed["total_costs"],
            },
        })
    required_2x_present = 2.0 in multipliers
    cost_stress = {
        "basis": "development_walk_forward_only",
        "multipliers": list(multipliers),
        "rows": rows,
        "base_costs_bps": dict(spec["costs"]),
        "required_2x_present": required_2x_present,
        "status": "PASS" if required_2x_present else "INCONCLUSIVE",
        "note": _COST_STRESS_NOTE,
    }

    # Falsification truth table (the validator's exact recomputation law).
    ratio = walk_forward["positive_fold_ratio"]
    wf_status = "PASS" if ratio >= 0.5 else "FAIL"
    wf_summary = (
        "At least half of the fixed-rule development folds were positive."
        if wf_status == "PASS" else
        "Fewer than half of the fixed-rule development folds were positive.")
    base = next((row for row in rows if row["multiplier"] == 1.0), None)
    doubled = next((row for row in rows if row["multiplier"] == 2.0), None)
    if base is None or doubled is None:
        cost_status = "INCONCLUSIVE"
        cost_summary = (
            "Development cost fragility is unavailable without 1x and 2x "
            "cases.")
    else:
        base_return = base["development"]["total_return"]
        doubled_return = doubled["development"]["total_return"]
        fragile = doubled_return < 0 or (
            base_return > 0 and doubled_return < 0.5 * base_return)
        cost_status = "FAIL" if fragile else "PASS"
        cost_summary = (
            "The fixed rule is fragile under doubled development transaction "
            "costs." if fragile else
            "The fixed rule survived doubled development transaction costs.")
    findings = [
        _finding("walk_forward_stability", wf_status, wf_summary, {
            "positive_fold_ratio": ratio,
            "fold_count": walk_forward["fold_count"],
            "worst_fold_return": walk_forward["worst_fold_return"],
        }),
        _finding("development_cost_fragility", cost_status, cost_summary, {
            "base": base, "doubled": doubled,
        }),
        _finding(
            "regime_coverage", regime_analysis["status"],
            "Each preregistered regime needs at least 20 development "
            "observations.",
            {
                "coverage": regime_analysis["coverage"],
                "states": [
                    {"regime": item["regime"], "status": item["status"],
                     "observations": item["observations"]}
                    for item in regime_analysis["states"]
                ],
            }),
    ]
    statuses = [item["status"] for item in findings]
    battery_status = (
        "FAIL" if "FAIL" in statuses
        else "INCONCLUSIVE" if "INCONCLUSIVE" in statuses else "PASS")
    inconclusive = [item["id"] for item in findings
                    if item["status"] == "INCONCLUSIVE"]
    falsification = {
        "non_suppressible": True,
        "battery_version": _BATTERY_VERSION,
        "required_checks": [item["id"] for item in findings],
        "checks_run": [item["id"] for item in findings],
        "findings": findings,
        "any_failing": "FAIL" in statuses,
        "any_inconclusive": bool(inconclusive),
        "status": battery_status,
        "completeness": {
            "all_required_reported": True,
            "all_checks_conclusive": not inconclusive,
            "unavailable_checks": inconclusive,
            "evidence_complete": not inconclusive,
        },
    }

    return _fresh({
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
    }, "projected evidence")


__all__ = [
    "ANNUALIZATION_SESSIONS",
    "EvidenceProjectionV3Error",
    "fold_metric_baseline_v3",
    "index_executions_v3",
    "project_development_evidence_v3",
    "reconstruct_display_metrics_v3",
]
