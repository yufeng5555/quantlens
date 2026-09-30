"""Engine/battery configuration and versioning. Everything here feeds the manifest."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ENGINE_SEMVER = "0.1.0"
INITIAL_CAPITAL = 100_000.0
TRADING_DAYS_PER_YEAR = 252

# Battery v1 is frozen.  Keep the historical public name as an alias because sealed
# v1 checkpoints and downstream callers depend on it byte-for-byte.
BATTERY_CONFIG_V1 = {
    "battery_version": "v1-gate2",
    "checks": ["is_oos_split", "cost_stress", "parameter_sensitivity", "falsification"],
    "oos_decay": {
        "sharpe_retention_min": 0.5,
        "description": "Finding fires if OOS Sharpe < 50% of IS Sharpe, or OOS total return is negative while IS is positive.",
    },
    "cost_fragility": {
        "stress_multiplier": 2,
        "return_retention_min": 0.5,
        "description": "Finding fires if at 2x costs the OOS total return is negative, or retains < 50% of the base-cost OOS return.",
    },
    "parameter_fragility": {
        "neighbor_loss_max": 0.30,
        "metric": "sharpe",
        "description": "Finding fires if a +-1-step grid neighbor loses >= 30% of the chosen cell's IS Sharpe (or flips sign).",
    },
    "missing_bars": {
        "max_consecutive_gap_days": 3,
        "description": "Synthetic calendar is Mon-Fri. Gaps <= 3 consecutive expected days are skipped and listed; longer gaps fail the run as data_quality_failed (no quota charge).",
    },
}
BATTERY_CONFIG = BATTERY_CONFIG_V1

# Battery v2 is server-owned.  The strategy may choose the final-holdout fraction via
# the existing registered field, but it cannot alter any walk-forward/regime law below.
BATTERY_CONFIG_V2 = {
    "battery_version": "battery-v2",
    "profile_id": "battery-v2",
    "mode": "adversarial_validation",
    "development": {
        "walk_forward_mode": "expanding-fixed-rule",
        "minimum_train_floor_bars": 504,
        "minimum_train_lookback_multiple": 2,
        "test_window_bars": 126,
        "minimum_short_fold_bars": 63,
        "parameter_selection": "forbidden",
    },
    "final_holdout": {
        "default_fraction": 0.30,
        "warmup_floor_bars": 200,
        "volatility_lookback_bars": 63,
        "primary_execution_limit": 1,
        "counterfactual_execution_limit": 0,
    },
    "regimes": {
        "trend_lookback_bars": 200,
        "volatility_lookback_bars": 63,
        "high_volatility_annualized": 0.20,
        "minimum_observations": 20,
        "states": ["up_low", "up_high", "down_low", "down_high"],
    },
    "temporal_integrity_version": "temporal-integrity-v1",
}


def battery_config_for_profile(profile: str = "battery-v1") -> dict:
    if profile == "battery-v1":
        return BATTERY_CONFIG_V1
    if profile == "battery-v2":
        return BATTERY_CONFIG_V2
    raise ValueError(f"unsupported battery profile: {profile!r}")


def battery_config_hash(profile: str = "battery-v1") -> str:
    canonical = json.dumps(
        battery_config_for_profile(profile), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def image_digest() -> str:
    """Gate 2 stand-in for a container digest, binding code, locks, and runtime ABI.

    This is not presented as a real container digest. It prevents two materially different
    local runtimes from claiming the same execution identity; S5 replaces it with an
    immutable image digest.
    """
    src_dir = Path(__file__).resolve().parent
    repo_root = src_dir.parents[2]
    h = hashlib.sha256()
    for path in sorted(src_dir.glob("*.py")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    for template_name in ("report.html.j2", "report_v2.html.j2"):
        tmpl = src_dir / "templates" / template_name
        if tmpl.exists():
            h.update(str(tmpl.relative_to(repo_root)).encode())
            h.update(tmpl.read_bytes())
    for relative in ("requirements-hashes.lock", "apps/web/package-lock.json"):
        lock = repo_root / relative
        if lock.exists():
            h.update(relative.encode())
            h.update(lock.read_bytes())
    runtime = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "cache_tag": sys.implementation.cache_tag,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "thread_limits": {
            name: os.environ.get(name)
            for name in (
                "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS",
            )
        },
    }
    h.update(json.dumps(runtime, sort_keys=True, separators=(",", ":")).encode())
    return f"local-runtime-sha256:{h.hexdigest()}"
