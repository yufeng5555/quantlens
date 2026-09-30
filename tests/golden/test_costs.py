"""AT-7.1 — itemized commission+slippage on every fill; a 10-trade golden sums exactly;
the zero-cost configuration reproduces the frictionless result."""

import numpy as np
import pandas as pd
import pytest

from quantlens_worker.engine import backtest, compute_metrics
from tests.conftest import bday_frame

RULE = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 2}
COSTS = {"commission_bps": 10, "slippage_bps": 20}

# 3-up/3-down sawtooth around SMA(2): each up-leg triggers a buy, each down-leg a sell.
# 5 full cycles => 5 buys + 5 sells = 10 fills.
CYCLE = [100.0, 104.0, 108.0, 104.0, 99.0, 95.0]
CLOSES = (CYCLE * 5) + [100.0, 104.0]  # tail keeps the last sell inside the window


def _tape():
    return bday_frame("2023-01-02", CLOSES)


def test_ten_trade_cost_golden_sums_exactly():
    result = backtest(_tape(), RULE, COSTS)
    trades = result["trades"]
    ten = trades[:10]
    assert [t["side"] for t in ten] == ["buy", "sell"] * 5

    comm_rate, slip_rate = 10 / 1e4, 20 / 1e4
    for t in ten:
        assert t["commission"] == pytest.approx(t["notional"] * comm_rate, rel=1e-12)
        assert t["slippage"] == pytest.approx(t["notional"] * slip_rate, rel=1e-12)

    total_comm = sum(t["commission"] for t in ten)
    total_slip = sum(t["slippage"] for t in ten)
    total_notional = sum(t["notional"] for t in ten)
    assert total_comm == pytest.approx(total_notional * comm_rate, rel=1e-12)
    assert total_slip == pytest.approx(total_notional * slip_rate, rel=1e-12)

    # Cash conservation: final equity = capital + sum(pnl) - all fees, replayed by hand.
    cash, shares = 100_000.0, 0.0
    for t in result["trades"]:
        if t["side"] == "buy":
            cash -= t["notional"] + t["commission"] + t["slippage"]
            shares += t["shares"]
        else:
            cash += t["notional"] - t["commission"] - t["slippage"]
            shares -= t["shares"]
    final_close = float(_tape()["close"].iloc[-1])
    assert result["equity"]["equity"].iloc[-1] == pytest.approx(
        cash + shares * final_close, rel=1e-12)


def test_zero_cost_config_reproduces_frictionless_result():
    zero_by_config = backtest(_tape(), RULE, {"commission_bps": 0, "slippage_bps": 0})
    zero_by_multiplier = backtest(_tape(), RULE, COSTS, cost_multiplier=0.0)
    assert zero_by_config["equity"]["equity"].tolist() == \
        zero_by_multiplier["equity"]["equity"].tolist()
    assert all(t["commission"] == 0.0 and t["slippage"] == 0.0
               for t in zero_by_config["trades"])
    # Frictionless final equity replayed independently.
    cash, shares = 100_000.0, 0.0
    for t in zero_by_config["trades"]:
        if t["side"] == "buy":
            cash, shares = 0.0, cash / t["fill_price"]
        else:
            cash, shares = shares * t["fill_price"], 0.0
    final_close = float(_tape()["close"].iloc[-1])
    assert zero_by_config["equity"]["equity"].iloc[-1] == pytest.approx(
        cash + shares * final_close, rel=1e-12)


def test_costs_strictly_reduce_final_equity_here():
    frictionless = backtest(_tape(), RULE, {"commission_bps": 0, "slippage_bps": 0})
    with_costs = backtest(_tape(), RULE, COSTS)
    assert with_costs["equity"]["equity"].iloc[-1] < frictionless["equity"]["equity"].iloc[-1]


def test_metrics_prepend_initial_capital_and_include_first_fill_economics():
    """Two end-of-day observations, hand-computed from a 100k start.

    The first -1% observation represents first-fill economics.  Omitting initial capital
    would incorrectly report +2.02% total return, no -1% drawdown, and only one return.
    """
    equity = pd.DataFrame({
        "date": ["2024-01-02", "2024-01-03"],
        "equity": [99_000.0, 101_000.0],
        "position": [1, 1],
    })
    trades = [{
        "date": "2024-01-02", "commission": 800.0, "slippage": 200.0,
    }]
    metrics = compute_metrics(equity, trades, 100_000.0)
    returns = np.array([-0.01, 101_000.0 / 99_000.0 - 1.0])

    assert metrics["initial_capital"] == 100_000.0
    assert metrics["n_bars"] == 2
    assert metrics["n_return_observations"] == 2
    assert metrics["total_return"] == pytest.approx(0.01, rel=1e-12)
    assert metrics["cagr"] == pytest.approx(1.01 ** (252 / 2) - 1, rel=1e-12)
    assert metrics["ann_vol"] == pytest.approx(
        returns.std(ddof=1) * np.sqrt(252), rel=1e-12)
    assert metrics["sharpe"] == pytest.approx(
        returns.mean() / returns.std(ddof=1) * np.sqrt(252), rel=1e-12)
    assert metrics["max_drawdown"] == pytest.approx(-0.01, rel=1e-12)
    assert metrics["total_costs"] == 1000.0


def test_comparison_start_cannot_silently_discard_prior_economics():
    equity = pd.DataFrame({
        "date": ["2024-01-02", "2024-01-03"],
        "equity": [105_000.0, 99_000.0],
        "position": [1, 1],
    })
    with pytest.raises(ValueError, match="discard prior strategy economics"):
        compute_metrics(equity, [], 100_000.0, comparison_start="2024-01-03")
