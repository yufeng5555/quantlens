"""AT-5.1 — a synthetic spike at date T cannot affect positions dated <= T, and a
+1-bar signal shift changes results (the execution lag is real, not cosmetic)."""

import numpy as np

from quantlens_worker.engine import backtest, compute_signal
from tests.conftest import bday_frame

RULE = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 5}
COSTS = {"commission_bps": 1, "slippage_bps": 5}


def _wavy_closes(n: int) -> list[float]:
    # Deterministic wavy tape that crosses its MA repeatedly.
    return [100.0 + 8.0 * np.sin(i / 6.0) + i * 0.05 for i in range(n)]


def test_future_spike_cannot_change_past_positions():
    n, spike_at = 60, 45
    base = _wavy_closes(n)
    spiked = list(base)
    spiked[spike_at] = base[spike_at] * 3.0  # violent future event

    r_base = backtest(bday_frame("2024-01-01", base), RULE, COSTS)
    r_spiked = backtest(bday_frame("2024-01-01", spiked), RULE, COSTS)

    pos_base = r_base["equity"]["position"].tolist()
    pos_spiked = r_spiked["equity"]["position"].tolist()
    # Positions up to and including bar T are identical; the spike can first affect the
    # fill at open of T+1.
    assert pos_base[: spike_at + 1] == pos_spiked[: spike_at + 1]
    eq_base = r_base["equity"]["equity"].tolist()
    eq_spiked = r_spiked["equity"]["equity"].tolist()
    assert eq_base[:spike_at] == eq_spiked[:spike_at]


def test_one_bar_shift_changes_results():
    closes = _wavy_closes(80)
    df = bday_frame("2024-01-01", closes)
    result = backtest(df, RULE, COSTS)

    # Same-bar-fill counterfactual computed independently: fill at open[t] when sig[t]
    # (this would be look-ahead — deciding and filling before the close that decides).
    sig = compute_signal(df["close"], RULE).tolist()
    cash, shares, fee = 100_000.0, 0.0, 6.0 / 1e4
    for t in range(len(df)):
        px = float(df["open"].iloc[t])
        if sig[t] and shares == 0.0:
            shares = cash / (px * (1 + fee)); cash = 0.0
        elif not sig[t] and shares > 0.0:
            cash = shares * px * (1 - fee); shares = 0.0
    lookahead_final = cash + shares * float(df["close"].iloc[-1])

    engine_final = result["equity"]["equity"].iloc[-1]
    assert abs(engine_final - lookahead_final) > 1e-6, \
        "engine must not equal the same-bar (look-ahead) fill accounting"
