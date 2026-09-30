"""Predeclared, no-lookahead regime analysis for daily ETF/equity data."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .config import BATTERY_CONFIG_V2, INITIAL_CAPITAL, TRADING_DAYS_PER_YEAR

REGIME_STATES = ("up_low", "up_high", "down_low", "down_high")


def _returns(equity: pd.Series, initial: float = INITIAL_CAPITAL) -> pd.Series:
    values = equity.astype(float).to_numpy()
    if not len(values):
        return pd.Series(dtype=float)
    prior = np.concatenate(([float(initial)], values[:-1]))
    return pd.Series(values / prior - 1.0)


def classify_regimes(market: pd.DataFrame) -> pd.DataFrame:
    """Label bar t using only data available by t-1."""
    close = market["close"].astype(float).reset_index(drop=True)
    prior_close = close.shift(1)
    prior_sma200 = close.rolling(200, min_periods=200).mean().shift(1)
    daily_returns = close.pct_change()
    prior_vol63 = daily_returns.rolling(63, min_periods=63).std(ddof=1).shift(1) \
        * math.sqrt(TRADING_DAYS_PER_YEAR)
    valid = prior_close.notna() & prior_sma200.notna() & prior_vol63.notna()
    trend = np.where(prior_close >= prior_sma200, "up", "down")
    volatility = np.where(
        prior_vol63 >= BATTERY_CONFIG_V2["regimes"]["high_volatility_annualized"],
        "high", "low",
    )
    labels = pd.Series([None] * len(close), dtype=object)
    labels.loc[valid] = [
        f"{t}_{v}" for t, v in zip(trend[valid.to_numpy()], volatility[valid.to_numpy()])
    ]
    return pd.DataFrame({
        "date": market["date"].astype(str).reset_index(drop=True),
        "regime": labels,
        "prior_close": prior_close,
        "prior_sma200": prior_sma200,
        "prior_ann_vol63": prior_vol63,
    })


def analyze_regimes(
    market: pd.DataFrame,
    strategy_equity: pd.DataFrame,
    benchmark_equity: pd.DataFrame,
    trades: list[dict],
) -> dict:
    labels = classify_regimes(market)
    strategy = strategy_equity[["date", "equity", "position"]].copy()
    strategy["date"] = strategy["date"].astype(str)
    strategy["strategy_return"] = _returns(strategy["equity"])
    benchmark = benchmark_equity[["date", "equity"]].copy()
    benchmark["date"] = benchmark["date"].astype(str)
    benchmark["benchmark_return"] = _returns(benchmark["equity"])
    joined = strategy.merge(
        benchmark[["date", "benchmark_return"]], on="date", how="left",
    ).merge(labels[["date", "regime"]], on="date", how="left")
    joined["benchmark_return"] = joined["benchmark_return"].fillna(0.0)
    trade_counts: dict[str, int] = {}
    for trade in trades:
        date = str(trade.get("date"))
        trade_counts[date] = trade_counts.get(date, 0) + 1

    minimum = int(BATTERY_CONFIG_V2["regimes"]["minimum_observations"])
    states: list[dict] = []
    for state in REGIME_STATES:
        rows = joined[joined["regime"] == state]
        observations = len(rows)
        conclusive = observations >= minimum
        states.append({
            "regime": state,
            "status": "PASS" if conclusive else "INCONCLUSIVE",
            "observations": observations,
            "strategy_compounded_return": (
                float((1.0 + rows["strategy_return"]).prod() - 1.0)
                if observations else None
            ),
            "benchmark_compounded_return": (
                float((1.0 + rows["benchmark_return"]).prod() - 1.0)
                if observations else None
            ),
            "mean_daily_excess_return": (
                float((rows["strategy_return"] - rows["benchmark_return"]).mean())
                if observations else None
            ),
            "exposure": float(rows["position"].mean()) if observations else None,
            "trade_count": sum(trade_counts.get(date, 0) for date in rows["date"]),
            "max_drawdown": None,
            "note": (
                "Non-contiguous regime observations are not used to compute drawdown."
            ),
        })

    classified = int(joined["regime"].notna().sum())
    return {
        "analysis_version": "regime-analysis-v1",
        "classification_law": {
            "trend": "benchmark_close[t-1] >= SMA200[t-1]",
            "volatility": "annualized_realized_vol_63[t-1] >= 0.20",
            "lookahead": False,
            "minimum_observations": minimum,
        },
        "states": states,
        "coverage": {
            "development_observations": len(joined),
            "classified_observations": classified,
            "unclassified_warmup_observations": len(joined) - classified,
            "state_observations_sum": sum(item["observations"] for item in states),
        },
        "status": (
            "PASS" if all(item["status"] == "PASS" for item in states)
            else "INCONCLUSIVE"
        ),
    }


__all__ = ["REGIME_STATES", "analyze_regimes", "classify_regimes"]
