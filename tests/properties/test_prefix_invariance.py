"""AT-5.3 — prefix-invariance property for every indicator/signal in the closed v1
library (SMA; price_vs_ma and ma_crossover signals): the value at bar t computed on the
prefix [0..t] equals the value at bar t computed on the full series."""

import numpy as np
import pandas as pd
import pytest

from quantlens_worker.engine import compute_signal, sma


def _tape(n: int = 120) -> pd.Series:
    # Deterministic pseudo-random walk (seeded) with regime flips.
    rng = np.random.default_rng(42)
    steps = rng.normal(0.0004, 0.012, n)
    return pd.Series(100.0 * np.exp(np.cumsum(steps)))


def test_sma_prefix_invariant():
    close = _tape()
    full = sma(close, 20)
    for t in range(len(close)):
        prefix = sma(close.iloc[: t + 1].reset_index(drop=True), 20)
        a, b = prefix.iloc[-1], full.iloc[t]
        assert (pd.isna(a) and pd.isna(b)) or a == pytest.approx(b, rel=1e-12)


@pytest.mark.parametrize("rule", [
    {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 10},
    {"type": "ma_crossover", "fast_ma_days": 5, "ma_days": 15},
])
def test_signal_prefix_invariant(rule):
    close = _tape()
    full = compute_signal(close, rule)
    for t in range(len(close)):
        prefix = compute_signal(close.iloc[: t + 1].reset_index(drop=True), rule)
        assert bool(prefix.iloc[-1]) == bool(full.iloc[t]), f"bar {t} depends on the future"
