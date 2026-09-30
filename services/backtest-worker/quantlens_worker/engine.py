"""Deterministic long/flat MA engine (pandas/numpy).

Conventions (documented in every report's methodology section):
- Signal computed on adjusted close at bar t; position takes effect at bar t+1 and is
  filled at bar t+1's open ("decide at close t, fill at open t+1").
- Long/flat, full notional, fractional shares.
- Itemized commission and slippage in basis points of fill notional, on every fill.
- Benchmark: buy-and-hold from the first date on which the strategy has a fully defined
  signal that could be acted on, paying the same entry cost model ("hold from first
  decision", AT-6.1). This date never depends on a later signal outcome.
- No wall-clock, no randomness, no network. Same inputs => byte-identical outputs.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .config import INITIAL_CAPITAL, TRADING_DAYS_PER_YEAR


def sma(series: pd.Series, window: int) -> pd.Series:
    return series.rolling(window, min_periods=window).mean()


def compute_signal(close: pd.Series, rule: dict) -> pd.Series:
    """Boolean desired-position series at decision time (bar t close). NaN warmup => flat."""
    if rule["type"] == "price_vs_ma":
        ma = sma(close, rule["ma_days"])
        sig = close > ma
        sig[ma.isna()] = False
    elif rule["type"] == "ma_crossover":
        fast = sma(close, rule["fast_ma_days"])
        slow = sma(close, rule["ma_days"])
        sig = fast > slow
        sig[fast.isna() | slow.isna()] = False
    else:
        raise ValueError(f"Unsupported rule type {rule['type']}")
    return sig.astype(bool)


def first_signal_index(rule: dict) -> int:
    """Index of the first bar with a defined signal (0-based): the warmup length - 1."""
    return rule["ma_days"] - 1


def _cost_rate(costs: dict, multiplier: float) -> tuple[float, float]:
    return (costs["commission_bps"] * multiplier / 1e4,
            costs["slippage_bps"] * multiplier / 1e4)


def backtest(df: pd.DataFrame, rule: dict, costs: dict, cost_multiplier: float = 1.0,
             window: tuple[int, int] | None = None,
             initial_capital: float = INITIAL_CAPITAL,
             benchmark_df: pd.DataFrame | None = None,
             benchmark_symbol: str | None = None) -> dict:
    """Run the strategy and its fair benchmark.

    df: frame with date/open/close over the FULL available slice (signal warmup may use
        bars before the accounting window — always past data, never future).
    window: (start_idx, end_idx_exclusive) accounting window within df. Positions are
        held/valued and trades filled only inside it. Default: whole frame.
    """
    n = len(df)
    i0, i1 = window or (0, n)
    if not (0 <= i0 < i1 <= n):
        raise ValueError(f"Bad accounting window ({i0}, {i1}) for {n} bars")

    close = df["close"].reset_index(drop=True)
    open_ = df["open"].reset_index(drop=True)
    dates = df["date"].reset_index(drop=True)
    benchmark_source = benchmark_df if benchmark_df is not None else df
    benchmark_dates = benchmark_source["date"].reset_index(drop=True)
    if len(benchmark_source) != n or not benchmark_dates.equals(dates):
        raise ValueError(
            "benchmark_df must have exactly the same ordered dates as the strategy frame")
    benchmark_open = benchmark_source["open"].reset_index(drop=True)
    benchmark_close = benchmark_source["close"].reset_index(drop=True)
    sig = compute_signal(close, rule)
    # Desired position for bar t is the signal from bar t-1 (fill at open of t).
    desired = sig.shift(1, fill_value=False)

    comm_rate, slip_rate = _cost_rate(costs, cost_multiplier)
    fee_rate = comm_rate + slip_rate

    cash, shares = float(initial_capital), 0.0
    position = 0
    trades: list[dict] = []
    equity_rows: list[dict] = []
    first_fill_idx: int | None = None

    for t in range(i0, i1):
        want = bool(desired.iloc[t])
        px = float(open_.iloc[t])
        if want and position == 0:
            buy_shares = cash / (px * (1.0 + fee_rate))
            notional = buy_shares * px
            commission = notional * comm_rate
            slippage = notional * slip_rate
            cash -= notional + commission + slippage
            shares = buy_shares
            position = 1
            if first_fill_idx is None:
                first_fill_idx = t
            trades.append({"date": dates.iloc[t], "side": "buy", "fill_price": px,
                           "shares": buy_shares, "notional": notional,
                           "commission": commission, "slippage": slippage})
        elif not want and position == 1:
            notional = shares * px
            commission = notional * comm_rate
            slippage = notional * slip_rate
            cash += notional - commission - slippage
            trades.append({"date": dates.iloc[t], "side": "sell", "fill_price": px,
                           "shares": shares, "notional": notional,
                           "commission": commission, "slippage": slippage})
            shares = 0.0
            position = 0
        equity_rows.append({"date": dates.iloc[t], "equity": cash + shares * float(close.iloc[t]),
                            "position": position})

    equity = pd.DataFrame(equity_rows)

    # --- Fair benchmark: hold from the strategy's first tradable decision (AT-6.1).
    # First tradable decision: the first bar inside the window after a fully defined signal.
    # This boundary is fixed by the rule/window alone.  Using the first eventual long fill
    # would make the benchmark's historical prefix depend on future signal outcomes.
    first_defined = first_signal_index(rule) + 1  # fill bar for the first defined signal
    bench_start = max(first_defined, i0)
    benchmark_rows: list[dict] = []
    if bench_start < i1:
        px0 = float(benchmark_open.iloc[bench_start])
        b_shares = initial_capital / (px0 * (1.0 + fee_rate))
        b_notional = b_shares * px0
        bench_entry = {"date": dates.iloc[bench_start], "side": "buy", "fill_price": px0,
                       "symbol": benchmark_symbol,
                       "shares": b_shares, "notional": b_notional,
                       "commission": b_notional * comm_rate,
                       "slippage": b_notional * slip_rate}
        b_cash = initial_capital - b_notional - bench_entry["commission"] - bench_entry["slippage"]
        for t in range(bench_start, i1):
            benchmark_rows.append({"date": dates.iloc[t],
                                   "equity": b_cash + b_shares * float(benchmark_close.iloc[t]),
                                   "position": 1})
    else:
        bench_entry = None
    benchmark = pd.DataFrame(benchmark_rows)

    return {
        "equity": equity,
        "trades": trades,
        "benchmark": benchmark,
        "benchmark_entry": bench_entry,
        "benchmark_symbol": benchmark_symbol,
        "first_fill_idx": first_fill_idx,
        "bench_start_idx": bench_start if bench_start < i1 else None,
        "window": (i0, i1),
        "cost_multiplier": cost_multiplier,
        "initial_capital": initial_capital,
    }


# ------------------------------------------------------------------ metrics

def _drawdown(equity: np.ndarray) -> float:
    peaks = np.maximum.accumulate(equity)
    dd = equity / peaks - 1.0
    return float(dd.min()) if len(dd) else 0.0


def compute_metrics(equity: pd.DataFrame, trades: list[dict], initial_capital: float,
                    comparison_start: str | None = None) -> dict:
    """Deterministic metrics over the equity series (optionally from comparison_start).
    Every value ships with its formula for the Show-the-Math affordance (AT-4.3 subset).

    ``equity`` contains end-of-bar observations, so ``initial_capital`` is prepended as
    the start-of-window observation for metric math.  This is economically material: the
    first return then includes the first fill's costs and the fill-open-to-close move, and
    the same observation participates in CAGR, volatility, Sharpe, and drawdown.
    """
    initial_capital = float(initial_capital)
    if not np.isfinite(initial_capital) or initial_capital <= 0:
        raise ValueError("initial_capital must be finite and positive")
    df = equity
    if comparison_start is not None:
        preceding = equity[equity["date"] < comparison_start]
        prior_trades = [trade for trade in trades if trade["date"] < comparison_start]
        if prior_trades or (not preceding.empty and not np.all(
                preceding["equity"].to_numpy(dtype=float) == initial_capital)):
            raise ValueError(
                "comparison_start cannot discard prior strategy economics; use a fresh "
                "accounting window or an explicit starting-equity baseline")
        df = equity[equity["date"] >= comparison_start].reset_index(drop=True)
    if df.empty:
        return {"n_bars": 0, "note": "empty window"}
    eq = df["equity"].to_numpy(dtype=float)
    if not np.isfinite(eq).all() or (eq <= 0).any():
        raise ValueError("equity observations must be finite and positive")
    metric_path = np.concatenate(([initial_capital], eq))
    rets = np.diff(metric_path) / metric_path[:-1]
    n = len(eq)
    total_return = float(eq[-1] / initial_capital - 1.0)
    years = n / TRADING_DAYS_PER_YEAR
    cagr = float((eq[-1] / initial_capital) ** (1.0 / years) - 1.0) \
        if years > 0 else 0.0
    ann_vol = float(rets.std(ddof=1) * np.sqrt(TRADING_DAYS_PER_YEAR)) if len(rets) > 1 else 0.0
    sharpe = float(rets.mean() / rets.std(ddof=1) * np.sqrt(TRADING_DAYS_PER_YEAR)) \
        if len(rets) > 1 and rets.std(ddof=1) > 0 else 0.0
    metric_trades = trades
    if comparison_start is not None:
        metric_trades = [t for t in trades if t["date"] >= comparison_start]
    total_costs = float(sum(t["commission"] + t["slippage"] for t in metric_trades))
    exposure = float(df["position"].mean()) if "position" in df else 1.0
    return {
        "start_date": df["date"].iloc[0], "end_date": df["date"].iloc[-1], "n_bars": n,
        "initial_capital": initial_capital,
        "n_return_observations": len(rets),
        "total_return": total_return,
        "cagr": cagr,
        "ann_vol": ann_vol,
        "sharpe": sharpe,
        "max_drawdown": _drawdown(metric_path),
        "n_trades": len(metric_trades),
        "total_costs": total_costs,
        "exposure": exposure,
        "final_equity": float(eq[-1]),
        "formulas": {
            "total_return": "equity_end / initial_capital - 1",
            "cagr": "(equity_end / initial_capital)^(252 / n_bars) - 1",
            "ann_vol": "stdev([first_equity / initial_capital - 1, then daily returns], ddof=1) * sqrt(252)",
            "sharpe": "mean([first_equity / initial_capital - 1, then daily returns]) / stdev(..., ddof=1) * sqrt(252), rf = 0",
            "max_drawdown": "min([initial_capital, equity] / running_peak - 1)",
            "total_costs": "sum(commission + slippage) over fills",
            "exposure": "mean(position) over bars in window",
        },
    }
