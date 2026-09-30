"""AT-6.1/6.2 — the benchmark starts at the strategy's first tradable decision date
(never earlier), pays the same entry cost model, and uses the same data; golden asserts
equal start dates."""

import pytest

from quantlens_schema import default_spec
from quantlens_worker.battery import run_battery
from quantlens_worker.engine import backtest
from quantlens_worker.snapshot import DataQualityError, load_frame
from tests.conftest import bday_frame, make_snapshot_dir

COSTS = {"commission_bps": 10, "slippage_bps": 20}


def test_benchmark_starts_at_first_fill_with_same_entry_costs():
    # The first fully defined signal is long, so the rule's first possible decision and
    # its first actual fill coincide on this golden.
    closes = [100, 101, 102, 103, 99, 100, 104, 108, 112, 110, 108, 111, 115]
    df = bday_frame("2024-01-01", [float(c) for c in closes])
    rule = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 3}
    result = backtest(df, rule, COSTS)

    assert result["trades"], "strategy must trade in this tape"
    first_fill_date = result["trades"][0]["date"]
    bench = result["benchmark"]
    assert bench["date"].iloc[0] == first_fill_date, "equal start dates (AT-6.1)"

    entry = result["benchmark_entry"]
    assert entry["fill_price"] == result["trades"][0]["fill_price"]
    comm_rate, slip_rate = 10 / 1e4, 20 / 1e4
    assert entry["commission"] == pytest.approx(entry["notional"] * comm_rate, rel=1e-12)
    assert entry["slippage"] == pytest.approx(entry["notional"] * slip_rate, rel=1e-12)
    # Same capital, same fee model => identical first-day accounting for both lines.
    assert bench["equity"].iloc[0] == pytest.approx(
        result["equity"].loc[result["equity"]["date"] == first_fill_date, "equity"].iloc[0],
        rel=1e-12)


def test_benchmark_never_starts_before_a_signal_could_act():
    # Strategy never goes long (price always below MA): benchmark still starts only at
    # the first bar where a defined signal could have been acted on, not at bar 0.
    closes = [float(100 - i) for i in range(30)]
    df = bday_frame("2024-01-01", closes)
    rule = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 5}
    result = backtest(df, rule, COSTS)
    assert result["trades"] == []
    # first defined signal at index 4 (5-day MA), first actionable fill at index 5
    assert result["benchmark"]["date"].iloc[0] == df["date"].iloc[5]


def test_benchmark_start_and_prefix_do_not_depend_on_future_long_signal():
    prefix = [float(100 - i) for i in range(12)]
    extended = prefix + [95.0, 100.0, 110.0, 120.0, 130.0]
    rule = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 5}
    short_df = bday_frame("2024-01-01", prefix)
    long_df = bday_frame("2024-01-01", extended)
    short = backtest(short_df, rule, COSTS)
    long = backtest(long_df, rule, COSTS)

    expected_start = short_df["date"].iloc[5]
    assert short["benchmark"]["date"].iloc[0] == expected_start
    assert long["benchmark"]["date"].iloc[0] == expected_start
    common = long["benchmark"].iloc[:len(short["benchmark"])].reset_index(drop=True)
    assert common.to_dict(orient="list") == \
        short["benchmark"].reset_index(drop=True).to_dict(orient="list")


def test_alternate_benchmark_uses_its_own_prices_on_identical_dates():
    strategy = bday_frame("2024-01-01", [100.0 + i for i in range(30)])
    alternate = bday_frame(
        "2024-01-01", [200.0 - i for i in range(30)],
        opens=[250.0 - i for i in range(30)])
    rule = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 5}
    result = backtest(
        strategy, rule, COSTS, benchmark_df=alternate, benchmark_symbol="TLT")

    entry_idx = result["bench_start_idx"]
    entry = result["benchmark_entry"]
    assert entry["symbol"] == "TLT"
    assert entry["date"] == strategy["date"].iloc[entry_idx]
    assert entry["fill_price"] == alternate["open"].iloc[entry_idx]
    assert entry["fill_price"] != strategy["open"].iloc[entry_idx]


def test_alternate_benchmark_dates_must_align_exactly():
    strategy = bday_frame("2024-01-01", [100.0 + i for i in range(30)])
    alternate = strategy.drop(index=10).reset_index(drop=True)
    rule = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 5}
    with pytest.raises(ValueError, match="same ordered dates"):
        backtest(strategy, rule, COSTS, benchmark_df=alternate, benchmark_symbol="TLT")


def test_battery_retains_benchmark_entry_ledger_and_cost_metrics():
    strategy = bday_frame("2020-01-01", [100.0 + i * 0.2 for i in range(120)])
    alternate = bday_frame("2020-01-01", [200.0 - i * 0.1 for i in range(120)])
    spec = default_spec("SPY")
    spec["rule"]["ma_days"] = 5
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = [3, 5, 10]
    spec["benchmark"]["symbol"] = "TLT"
    spec["data"]["range"] = {
        "start": strategy["date"].iloc[0], "end": strategy["date"].iloc[-1]}

    battery = run_battery(strategy, spec, benchmark_df=alternate)
    entry = battery["is_result"]["benchmark_entry"]
    metrics = battery["is_result"]["benchmark_metrics"]
    assert battery["benchmark_symbol"] == "TLT"
    assert entry["symbol"] == "TLT"
    assert metrics["n_trades"] == 1
    assert metrics["total_costs"] == pytest.approx(
        entry["commission"] + entry["slippage"], rel=1e-12)


def test_battery_classifies_alternate_benchmark_date_mismatch_as_data_quality():
    strategy = bday_frame("2020-01-01", [100.0 + i * 0.2 for i in range(120)])
    alternate = strategy.drop(index=50).reset_index(drop=True)
    spec = default_spec("SPY")
    spec["rule"]["ma_days"] = 5
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = [3, 5, 10]
    spec["benchmark"]["symbol"] = "TLT"
    with pytest.raises(DataQualityError) as exc:
        run_battery(strategy, spec, benchmark_df=alternate)
    assert exc.value.code == "BENCHMARK_DATE_MISMATCH"


def test_alternate_benchmark_applies_its_own_split_metadata_before_alignment(tmp_path):
    n = 120
    strategy_raw = bday_frame("2020-01-01", [100.0 + i * 0.2 for i in range(n)])
    underlying = [200.0 + i * 0.4 for i in range(n)]
    alternate_close = [value if i < 60 else value / 2 for i, value in enumerate(underlying)]
    alternate_open = [value - 0.2 if i < 60 else (value - 0.2) / 2
                      for i, value in enumerate(underlying)]
    alternate_raw = bday_frame("2020-01-01", alternate_close, alternate_open)
    split_date = alternate_raw["date"].iloc[60]
    snap = make_snapshot_dir(
        tmp_path / "snap", {"SPY": strategy_raw, "TLT": alternate_raw},
        splits={"TLT": [{"date": split_date, "ratio": 2.0}]})
    start, end = strategy_raw["date"].iloc[0], strategy_raw["date"].iloc[-1]
    strategy, _ = load_frame("SPY", start, end, snap)
    alternate, _ = load_frame("TLT", start, end, snap)

    spec = default_spec("SPY")
    spec["rule"]["ma_days"] = 5
    spec["validation"]["sensitivity"]["grid"]["ma_days"] = [3, 5, 10]
    spec["benchmark"]["symbol"] = "TLT"
    battery = run_battery(strategy, spec, benchmark_df=alternate)
    entry = battery["is_result"]["benchmark_entry"]
    adjusted_open = alternate.loc[alternate["date"] == entry["date"], "open"].iloc[0]
    raw_open = alternate_raw.loc[alternate_raw["date"] == entry["date"], "open"].iloc[0]
    assert entry["fill_price"] == adjusted_open
    assert entry["fill_price"] == pytest.approx(raw_open / 2, rel=1e-12)
