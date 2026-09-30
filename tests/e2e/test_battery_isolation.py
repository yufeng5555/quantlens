"""AT-8.1/8.2 — IS/OOS isolation and separation; AT-9.1/9.2 — sensitivity grid honesty
and fragility flagging."""

import numpy as np
import pandas as pd
import pytest

from quantlens_schema import default_spec, semantic_lint
from quantlens_worker.battery import run_battery, split_indices
from quantlens_worker.snapshot import DataQualityError
from tests.conftest import bday_frame


def _frame(n=900, seed=5):
    rng = np.random.default_rng(seed)
    log_p = np.cumsum(0.0004 + 0.012 * rng.normal(0, 1, n))
    closes = (100 * np.exp(log_p)).round(4).tolist()
    return bday_frame("2015-01-01", closes)


def _spec(grid=(20, 50, 100, 200), ma=50):
    spec = default_spec("SPY")
    spec["rule"]["ma_days"] = ma
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = list(grid)
    spec["data"]["range"] = {"start": "2015-01-01", "end": "2018-12-31"}
    return spec


def test_sweeps_cannot_see_oos_data():
    """Mutating the OOS region must not change any sensitivity cell (AT-8.1)."""
    df = _frame()
    spec = _spec()
    is_end, n = split_indices(len(df), spec["validation"]["is_oos_split"]["oos_fraction"])

    base = run_battery(df, spec)

    mutated = df.copy(deep=True)
    mutated.loc[is_end:, "close"] = mutated.loc[is_end:, "close"] * 3.0  # violent OOS change
    mutated.loc[is_end:, "open"] = mutated.loc[is_end:, "open"] * 3.0
    changed = run_battery(mutated, spec)

    assert base["sensitivity"] == changed["sensitivity"], \
        "sensitivity sweep depends on out-of-sample data — leakage"
    assert base["is_result"]["strategy_metrics"] == changed["is_result"]["strategy_metrics"]
    assert base["oos_result"]["strategy_metrics"] != changed["oos_result"]["strategy_metrics"]


def test_every_oos_execution_is_recorded_and_base_1x_is_reused():
    battery = run_battery(_frame(), _spec())
    audit = battery["oos_execution_audit"]
    # Primary 1x plus the three non-base stress cases (0x, 2x, 4x).
    assert battery["oos_executions"] == 4
    assert battery["oos_primary_executions"] == 1
    assert audit["count"] == len(audit["records"]) == 4
    assert audit["primary_evaluation_count"] == 1
    assert audit["cost_stress_execution_count"] == 3
    assert audit["base_1x_reused_for_cost_stress"] is True
    base = next(r for r in battery["cost_stress"]["rows"] if r["multiplier"] == 1)
    assert base["reused_primary_evaluation"] is True
    assert base["oos_execution_id"] == audit["records"][0]["execution_id"]


def test_segments_do_not_overlap_and_cover_range():
    df = _frame()
    battery = run_battery(df, _spec())
    seg = battery["segments"]
    assert seg["is"]["end"] < seg["oos"]["start"]
    assert seg["is"]["bars"] + seg["oos"]["bars"] == len(df)
    assert seg["is"]["start"] == df["date"].iloc[0]
    assert seg["oos"]["end"] == df["date"].iloc[-1]


def test_every_declared_grid_cell_is_reported(  ):
    grid = (20, 50, 100, 200)
    battery = run_battery(_frame(), _spec(grid=grid))
    reported = [c["ma_days"] for c in battery["sensitivity"]["grid"]]
    assert reported == sorted(grid), "full grid must be reported, never only the best cell"
    assert battery["sensitivity"]["chosen_cell"] is not None
    assert battery["sensitivity"]["chosen_percentile_in_grid"] is not None
    assert battery["sensitivity"]["basis"] == "in_sample_only"
    evaluation = battery["segments"]["is"]["evaluation"]
    assert battery["is_result"]["strategy_metrics"]["start_date"] == evaluation["start"]
    assert {c["evaluation_start"] for c in battery["sensitivity"]["grid"]} == \
        {evaluation["start"]}
    assert {c["evaluation_end"] for c in battery["sensitivity"]["grid"]} == \
        {evaluation["end"]}
    assert {c["evaluation_bars"] for c in battery["sensitivity"]["grid"]} == \
        {evaluation["bars"]}


def test_fragile_neighbors_produce_named_finding():
    """Engineered fragility: chosen window rides a resonant swing; neighbors whipsaw.
    The parameter_fragility finding must fire (AT-9.2)."""
    n = 900
    t = np.arange(n)
    rng = np.random.default_rng(7)
    is_end = int(n * 0.7)
    drift = np.where(t < is_end, 0.0006, -0.0009)
    vol = np.where(t < is_end, 0.010, 0.016)
    swings = 0.04 * np.sin(2 * np.pi * t / 45)
    closes = (100 * np.exp(np.cumsum(drift + vol * rng.normal(0, 1, n)) + swings)).round(4).tolist()
    df = bday_frame("2015-01-01", closes)
    spec = _spec(grid=(10, 50, 100, 200), ma=10)
    spec["data"]["range"] = {"start": df["date"].iloc[0], "end": df["date"].iloc[-1]}
    battery = run_battery(df, spec)
    finding = next(f for f in battery["falsification"]["findings"]
                   if f["id"] == "parameter_fragility")
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["neighbors"], "finding must cite the neighbor cells"


def test_exact_warmup_boundary_has_no_fake_is_result():
    df = bday_frame("2010-01-04", [100.0 + i * 0.1 for i in range(800)])
    spec = _spec(grid=(399, 400), ma=400)
    spec["validation"]["is_oos_split"]["oos_fraction"] = 0.5
    spec["data"]["range"] = {
        "start": df["date"].iloc[0], "end": df["date"].iloc[-1]}
    assert "LINT_IS_EVALUATION_AFTER_WARMUP" in {
        e["rule_id"] for e in semantic_lint(spec)}
    with pytest.raises(DataQualityError) as exc:
        run_battery(df, spec)
    assert exc.value.code == "INSUFFICIENT_IS_EVALUATION"
