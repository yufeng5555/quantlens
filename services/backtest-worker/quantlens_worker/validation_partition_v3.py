"""Access-controlled time partitions for a validation-plan-v3 (Gate E Stop C1).

Derives the frozen fixed-rule expanding walk-forward folds and the sealed
final-holdout boundary from one complete, already-validated validation-plan-v3.
The v3 plan nests its fold constants under ``walk_forward`` and its holdout
boundary under ``final_window``; this module reads that closed shape, re-uses
the frozen v2 fold law verbatim (``validate_fold_laws``) as a self-check, and
emits a partitions artifact whose ``final_holdout`` block binds the plan's
``final_window`` byte-for-byte — the exact window equality the dormant v3
resolver enforces against the authenticated plan anchor.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

import pandas as pd

from .validation_partition import frame_sha256, validate_fold_laws

PARTITION_VERSION_V3 = "validation-partitions-v3"

_FINAL_WINDOW_FIELDS = (
    "n_bars", "start_index", "end_index", "bars",
    "warmup_start_index", "warmup_bars",
)


class ValidationPartitionV3Error(ValueError):
    """One v3 partition input contradicts the sealed plan boundary law."""


def _fail(detail: str) -> None:
    raise ValidationPartitionV3Error(detail)


def _require(condition: bool, detail: str) -> None:
    if not condition:
        _fail(detail)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _index(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    assert isinstance(value, int)
    return value


def _date(frame: pd.DataFrame, index: int) -> str:
    return str(frame["date"].iloc[index])


@dataclass(frozen=True)
class ValidationPartitionsV3:
    development: pd.DataFrame
    development_benchmark: pd.DataFrame | None
    final_capsule_frame: pd.DataFrame
    final_capsule_benchmark: pd.DataFrame | None
    final_local_start: int
    artifact: dict


def build_partitions_v3(
    frame: pd.DataFrame,
    plan: Mapping[str, Any],
    benchmark_frame: pd.DataFrame | None = None,
) -> ValidationPartitionsV3:
    """Partition one observation frame under a sealed validation-plan-v3.

    The plan is trusted as already validated by its builder; every boundary it
    declares is still re-proved here against the loaded frame, and any
    contradiction fails closed instead of producing a partial partition.
    """
    if not isinstance(plan, Mapping):
        _fail("plan must be a validation-plan-v3 mapping")
    n = len(frame)
    _require(
        _index(plan.get("n_bars"), "plan.n_bars", minimum=1) == n,
        "validation plan length does not match the loaded frame",
    )
    if benchmark_frame is not None and (
        len(benchmark_frame) != n
        or not benchmark_frame["date"].reset_index(drop=True).equals(
            frame["date"].reset_index(drop=True))
    ):
        _fail("benchmark frame is not aligned with the strategy frame")

    window = plan.get("final_window")
    if not isinstance(window, Mapping) or set(window) != set(_FINAL_WINDOW_FIELDS):
        _fail(
            "plan.final_window must have exactly these keys: "
            + ", ".join(_FINAL_WINDOW_FIELDS)
        )
    assert isinstance(window, Mapping)
    final_start = _index(window["start_index"], "final_window.start_index",
                         minimum=1)
    final_end = _index(window["end_index"], "final_window.end_index", minimum=1)
    final_bars = _index(window["bars"], "final_window.bars", minimum=1)
    warmup_start = _index(
        window["warmup_start_index"], "final_window.warmup_start_index")
    warmup = _index(window["warmup_bars"], "final_window.warmup_bars")
    _require(window["n_bars"] == n, "final_window.n_bars must equal the frame")
    _require(final_end == n, "final window must end at the last observation")
    _require(final_bars == final_end - final_start,
             "final window bars must equal its end-exclusive span")
    _require(warmup == final_start - warmup_start,
             "warm-up must immediately precede the final window")
    _require(
        plan.get("development_bars") == final_start,
        "plan development_bars must equal the final window start",
    )

    walk_forward = plan.get("walk_forward")
    if not isinstance(walk_forward, Mapping):
        _fail("plan.walk_forward must be a mapping")
    assert isinstance(walk_forward, Mapping)
    minimum_train = _index(
        plan.get("minimum_train_bars"), "plan.minimum_train_bars", minimum=1)
    test_window = _index(
        walk_forward.get("test_window_bars"),
        "walk_forward.test_window_bars", minimum=1)
    minimum_short = _index(
        walk_forward.get("minimum_short_fold_bars"),
        "walk_forward.minimum_short_fold_bars", minimum=1)

    development_end = final_start
    development = frame.iloc[:development_end].reset_index(drop=True).copy()
    development_benchmark = (
        benchmark_frame.iloc[:development_end].reset_index(drop=True).copy()
        if benchmark_frame is not None else None
    )
    final_capsule_frame = frame.iloc[warmup_start:].reset_index(drop=True).copy()
    final_capsule_benchmark = (
        benchmark_frame.iloc[warmup_start:].reset_index(drop=True).copy()
        if benchmark_frame is not None else None
    )

    # The frozen v2 fold law, re-derived with the v3-shaped constants.
    folds: list[dict] = []
    cursor = minimum_train
    while cursor < development_end:
        remaining = development_end - cursor
        if remaining < minimum_short:
            if folds:
                folds[-1]["test_end_index"] = development_end
                folds[-1]["test_end"] = _date(frame, development_end - 1)
                folds[-1]["test_bars"] = (
                    folds[-1]["test_end_index"] - folds[-1]["test_start_index"])
            break
        size = min(test_window, remaining)
        if remaining > test_window and remaining - test_window < minimum_short:
            size = remaining
        test_end = cursor + size
        folds.append({
            "fold_id": f"wf-{len(folds) + 1:03d}",
            "train_start_index": 0,
            "train_end_index": cursor,
            "train_start": _date(frame, 0),
            "train_end": _date(frame, cursor - 1),
            "train_bars": cursor,
            "test_start_index": cursor,
            "test_end_index": test_end,
            "test_start": _date(frame, cursor),
            "test_end": _date(frame, test_end - 1),
            "test_bars": size,
            "visible_prefix_end_index": test_end,
            "visible_prefix_sha256": frame_sha256(frame.iloc[:test_end]),
        })
        cursor = test_end

    # A valid v3 plan proves development >= minimum_train + one short fold at
    # build time, so an empty fold set here is an input contradiction.
    _require(bool(folds),
             "a sealed v3 plan must yield at least one walk-forward fold")

    artifact = {
        "partition_version": PARTITION_VERSION_V3,
        "status": "READY",
        "reason": None,
        "n_bars": n,
        "development": {
            "start_index": 0,
            "end_index": development_end,
            "start": _date(frame, 0),
            "end": _date(frame, development_end - 1),
            "bars": development_end,
            "input_sha256": frame_sha256(development),
        },
        "final_holdout": {
            "start_index": final_start,
            "end_index": n,
            "start": _date(frame, final_start),
            "end": _date(frame, n - 1),
            "bars": final_bars,
            "warmup_start_index": warmup_start,
            "warmup_bars": warmup,
            "capsule_sha256": frame_sha256(final_capsule_frame),
            "evaluation_input_sha256": frame_sha256(frame.iloc[final_start:]),
        },
        "folds": folds,
        "laws": {
            "mode": "expanding-fixed-rule",
            "continuous_non_overlapping_tests": True,
            "prefix_ends_at_test_end": True,
            "parameter_selection": "forbidden",
            "short_remainder_policy": "merge_if_under_63_bars",
        },
    }

    # Self-checks before anything is returned: the frozen fold law holds under
    # the v3 constants, and the sealed window block reconstructs the plan's
    # final_window byte-for-byte (the resolver's anchor-window equality).
    try:
        validate_fold_laws(artifact, {
            "n_bars": n,
            "development_bars": development_end,
            "minimum_train_bars": minimum_train,
            "test_window_bars": test_window,
            "minimum_short_fold_bars": minimum_short,
        })
    except ValueError as exc:
        _fail(f"derived folds violate the frozen fold law: {exc}")
    final_block = artifact["final_holdout"]
    reconstructed = {
        "n_bars": artifact["n_bars"],
        "start_index": final_block["start_index"],
        "end_index": final_block["end_index"],
        "bars": final_block["bars"],
        "warmup_start_index": final_block["warmup_start_index"],
        "warmup_bars": final_block["warmup_bars"],
    }
    _require(
        _canonical_bytes(reconstructed) == _canonical_bytes(dict(window)),
        "sealed partition window does not reproduce the plan final_window "
        "byte-for-byte",
    )

    return ValidationPartitionsV3(
        development=development,
        development_benchmark=development_benchmark,
        final_capsule_frame=final_capsule_frame,
        final_capsule_benchmark=final_capsule_benchmark,
        final_local_start=warmup,
        artifact=artifact,
    )


__all__ = [
    "PARTITION_VERSION_V3",
    "ValidationPartitionV3Error",
    "ValidationPartitionsV3",
    "build_partitions_v3",
]
