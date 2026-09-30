"""Single-purpose final-holdout evaluator with a narrow, auditable interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

import pandas as pd

from .battery import _segment_result
from .validation_plan import sha256_json


class FinalHoldoutError(RuntimeError):
    pass


@dataclass
class FinalHoldoutCapsule:
    """Capability-limited, one-use access to the final frame.

    This is an in-process capability boundary, not a separate OS security principal.
    The frame reference is cleared on the first lease and every later lease fails.
    """

    capsule_id: str
    _frame: pd.DataFrame | None = field(repr=False)
    _benchmark_frame: pd.DataFrame | None = field(default=None, repr=False)
    _evaluation_start: int = field(default=0, repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def public_ref(self) -> dict:
        return {"capsule_id": self.capsule_id, "opaque": True}

    def consume(self) -> tuple[pd.DataFrame, pd.DataFrame | None, int]:
        with self._lock:
            if self._consumed or self._frame is None:
                raise FinalHoldoutError("final holdout capability has already been consumed")
            frame = self._frame
            benchmark = self._benchmark_frame
            start = self._evaluation_start
            self._consumed = True
            self._frame = None
            self._benchmark_frame = None
            return frame, benchmark, start


def make_capsule(
    frame: pd.DataFrame,
    evaluation_start: int,
    *,
    capsule_sha256: str,
    benchmark_frame: pd.DataFrame | None = None,
) -> FinalHoldoutCapsule:
    if not 0 < evaluation_start < len(frame):
        raise FinalHoldoutError("final capsule has no warmup or no evaluation observations")
    return FinalHoldoutCapsule(
        capsule_id="fhc-" + capsule_sha256.removeprefix("sha256:")[:24],
        _frame=frame.copy(),
        _benchmark_frame=benchmark_frame.copy() if benchmark_frame is not None else None,
        _evaluation_start=evaluation_start,
    )


def _slim(result: dict) -> dict:
    equity = result["raw"]["equity"]
    benchmark = result["raw"]["benchmark"]
    return {
        "status": "COMPLETE",
        "strategy_metrics": result["strategy"],
        "comparison_strategy_metrics": result["comparison_strategy"],
        "benchmark_metrics": result["benchmark"],
        "benchmark_symbol": result["raw"]["benchmark_symbol"],
        "comparison_start": result["comparison_start"],
        "equity_series": {
            "date": equity["date"].tolist(),
            "equity": equity["equity"].tolist(),
            "position": equity["position"].tolist(),
        },
        "benchmark_series": {
            "date": benchmark["date"].tolist() if not benchmark.empty else [],
            "equity": benchmark["equity"].tolist() if not benchmark.empty else [],
        },
        "trades": result["raw"]["trades"],
        "benchmark_entry": result["raw"]["benchmark_entry"],
    }


def evaluate_final_holdout(
    capsule: FinalHoldoutCapsule,
    *,
    confirmed_spec_hash: str,
    validation_plan_hash: str,
    locked_rule: dict,
    base_costs: dict,
    benchmark_symbol: str,
) -> dict:
    """Evaluate exactly the locked rule/base costs.

    There is intentionally no parameter grid, cost multiplier, selection result, agent
    prompt, or callback in this signature.  One-time access is enforced atomically by
    the control plane before this pure evaluator is called.
    """
    if not confirmed_spec_hash.startswith("sha256:"):
        raise FinalHoldoutError("confirmed spec hash is not sealed")
    if not validation_plan_hash.startswith("sha256:"):
        raise FinalHoldoutError("validation plan hash is not sealed")
    if set(base_costs) != {"commission_bps", "slippage_bps"}:
        raise FinalHoldoutError("final evaluator accepts base transaction costs only")
    frame, benchmark_frame, evaluation_start = capsule.consume()
    end = len(frame)
    result = _segment_result(
        frame,
        dict(locked_rule),
        dict(base_costs),
        (evaluation_start, end),
        cost_multiplier=1.0,
        benchmark_df=benchmark_frame,
        benchmark_symbol=benchmark_symbol,
    )
    value = _slim(result)
    value["execution_binding"] = {
        "capsule_id": capsule.capsule_id,
        "confirmed_spec_hash": confirmed_spec_hash,
        "validation_plan_hash": validation_plan_hash,
        "locked_rule_sha256": sha256_json(locked_rule),
        "base_costs_sha256": sha256_json(base_costs),
        "cost_multiplier": 1.0,
    }
    return value


__all__ = [
    "FinalHoldoutCapsule", "FinalHoldoutError", "evaluate_final_holdout", "make_capsule",
]
