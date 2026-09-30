"""AT-5.2 — decision at close t fills at open t+1; 5-bar hand-computed golden matches
exactly. Expected values are derived by explicit arithmetic in this file, independent of
engine internals."""

import pytest

from quantlens_worker.engine import backtest, compute_signal
from tests.conftest import bday_frame

# Hand-built 5-bar tape. SMA(2) of close: [-, 11, 11.5, 12, 11].
# Signal (close > SMA2):      [-, True, False, True, False]
# Desired position (shifted): [-, -,    True,  False, True]
CLOSES = [10.0, 12.0, 11.0, 13.0, 9.0]
OPENS = [10.0, 11.0, 12.0, 12.0, 10.0]
RULE = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 2}
COSTS = {"commission_bps": 100, "slippage_bps": 0}  # 1% commission for readable math
CAPITAL = 100_000.0


def test_five_bar_golden_exact():
    df = bday_frame("2024-01-01", CLOSES, OPENS)
    result = backtest(df, RULE, COSTS, initial_capital=CAPITAL)
    trades = result["trades"]

    # Fill 1: buy at open[2]=12 (signal fired at close[1]).
    shares1 = CAPITAL / (12.0 * 1.01)
    assert trades[0]["side"] == "buy"
    assert trades[0]["date"] == df["date"].iloc[2]
    assert trades[0]["fill_price"] == 12.0
    assert trades[0]["shares"] == pytest.approx(shares1, rel=1e-12)
    assert trades[0]["commission"] == pytest.approx(shares1 * 12.0 * 0.01, rel=1e-12)
    assert trades[0]["slippage"] == 0.0

    # Fill 2: sell at open[3]=12 (signal off at close[2]).
    cash_after_sell = shares1 * 12.0 * (1 - 0.01)
    assert trades[1]["side"] == "sell"
    assert trades[1]["date"] == df["date"].iloc[3]
    assert trades[1]["fill_price"] == 12.0

    # Fill 3: buy at open[4]=10 (signal on at close[3]).
    shares2 = cash_after_sell / (10.0 * 1.01)
    assert trades[2]["side"] == "buy"
    assert trades[2]["date"] == df["date"].iloc[4]
    assert len(trades) == 3

    eq = result["equity"]["equity"].tolist()
    assert eq[0] == CAPITAL                      # flat, no signal defined yet
    assert eq[1] == CAPITAL                      # signal defined at close[1]; not filled yet
    assert eq[2] == pytest.approx(shares1 * 11.0, rel=1e-12)   # long into close[2]
    assert eq[3] == pytest.approx(cash_after_sell, rel=1e-12)  # flat after selling at open[3]
    assert eq[4] == pytest.approx(shares2 * 9.0, rel=1e-12)    # long into close[4]


def test_signal_itself_is_not_traded_same_bar():
    """The bar where the signal fires must never be the fill bar."""
    df = bday_frame("2024-01-01", CLOSES, OPENS)
    sig = compute_signal(df["close"], RULE)
    result = backtest(df, RULE, COSTS, initial_capital=CAPITAL)
    first_signal_bar = sig.idxmax()  # bar 1
    assert bool(sig.iloc[first_signal_bar])
    assert result["trades"][0]["date"] == df["date"].iloc[first_signal_bar + 1]
