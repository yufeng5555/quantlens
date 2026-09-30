"""Access-controlled time partitions for Validation Battery v2.

Development functions receive a frame that ends before the final holdout starts.  Fold
executors receive prefixes that end at each fold's test boundary.  The final evaluator
receives a separate opaque capsule constructed only after the plan is sealed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import pandas as pd


def frame_sha256(frame: pd.DataFrame) -> str:
    columns = [name for name in ("date", "open", "high", "low", "close", "volume")
               if name in frame.columns]
    records = frame.loc[:, columns].to_dict(orient="records")
    body = json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False, default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class ValidationPartitions:
    development: pd.DataFrame
    development_benchmark: pd.DataFrame | None
    final_capsule_frame: pd.DataFrame
    final_capsule_benchmark: pd.DataFrame | None
    final_local_start: int
    artifact: dict


def _date(frame: pd.DataFrame, index: int) -> str:
    return str(frame["date"].iloc[index])


def build_partitions(
    frame: pd.DataFrame,
    plan: dict,
    benchmark_frame: pd.DataFrame | None = None,
) -> ValidationPartitions:
    n = len(frame)
    if int(plan["n_bars"]) != n:
        raise ValueError("validation plan length does not match the loaded frame")
    if benchmark_frame is not None and (
        len(benchmark_frame) != n
        or not benchmark_frame["date"].reset_index(drop=True).equals(
            frame["date"].reset_index(drop=True))
    ):
        raise ValueError("benchmark frame is not aligned with the strategy frame")

    development_end = int(plan["development_bars"])
    final_start = development_end
    minimum_train = int(plan["minimum_train_bars"])
    test_window = int(plan["test_window_bars"])
    minimum_short = int(plan["minimum_short_fold_bars"])
    warmup = min(int(plan["final_warmup_bars"]), final_start)
    warmup_start = final_start - warmup

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

    status = "READY" if folds else "INCONCLUSIVE"
    reason = None if folds else (
        "The development partition is too short for the fixed minimum training window "
        "plus a 63-observation evaluation fold."
    )
    artifact = {
        "partition_version": "validation-partitions-v2",
        "status": status,
        "reason": reason,
        "n_bars": n,
        "development": {
            "start_index": 0,
            "end_index": development_end,
            "start": _date(frame, 0) if development_end else None,
            "end": _date(frame, development_end - 1) if development_end else None,
            "bars": development_end,
            "input_sha256": frame_sha256(development),
        },
        "final_holdout": {
            "start_index": final_start,
            "end_index": n,
            "start": _date(frame, final_start) if final_start < n else None,
            "end": _date(frame, n - 1) if n else None,
            "bars": n - final_start,
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
    return ValidationPartitions(
        development=development,
        development_benchmark=development_benchmark,
        final_capsule_frame=final_capsule_frame,
        final_capsule_benchmark=final_capsule_benchmark,
        final_local_start=warmup,
        artifact=artifact,
    )


def validate_fold_laws(partitions: dict, validation_plan: dict | None = None) -> None:
    folds = partitions.get("folds")
    if not isinstance(folds, list):
        raise ValueError("partition folds are missing")
    prior_end = None
    for index, fold in enumerate(folds):
        if fold.get("train_start_index") != 0:
            raise ValueError("walk-forward training windows must expand from index zero")
        start = fold.get("test_start_index")
        end = fold.get("test_end_index")
        if not isinstance(start, int) or not isinstance(end, int) or start >= end:
            raise ValueError("walk-forward test window is invalid")
        if fold.get("train_end_index") != start:
            raise ValueError("walk-forward train/test windows are not adjacent")
        if fold.get("train_bars") != start:
            raise ValueError("walk-forward train-bar count is inconsistent")
        if fold.get("test_bars") != end - start:
            raise ValueError("walk-forward test-bar count is inconsistent")
        if index and prior_end != start:
            raise ValueError("walk-forward test windows are not continuous")
        if fold.get("visible_prefix_end_index") != end:
            raise ValueError("fold prefix escapes its test end")
        prior_end = end
    final = partitions.get("final_holdout") or {}
    development = partitions.get("development") or {}
    n_bars = partitions.get("n_bars")
    if not isinstance(n_bars, int) or n_bars < 1:
        raise ValueError("partition total bar count is invalid")
    if (development.get("start_index") != 0
            or development.get("bars") != development.get("end_index")):
        raise ValueError("development boundary accounting is inconsistent")
    if development.get("end_index") != final.get("start_index"):
        raise ValueError("development and final partitions are not adjacent")
    if (final.get("end_index") != n_bars
            or final.get("bars") != final.get("end_index") - final.get("start_index")):
        raise ValueError("final boundary accounting is inconsistent")
    if folds and folds[-1].get("test_end_index") != development.get("end_index"):
        raise ValueError("walk-forward folds do not cover the development evaluation tail")
    if validation_plan is not None:
        minimum_train = int(validation_plan["minimum_train_bars"])
        test_window = int(validation_plan["test_window_bars"])
        minimum_short = int(validation_plan["minimum_short_fold_bars"])
        development_end = int(validation_plan["development_bars"])
        if int(validation_plan["n_bars"]) != n_bars:
            raise ValueError("partition total bar count contradicts validation plan")
        if development.get("end_index") != development_end:
            raise ValueError("partition development boundary contradicts validation plan")
        expected: list[tuple[int, int, int]] = []
        cursor = minimum_train
        while cursor < development_end:
            remaining = development_end - cursor
            if remaining < minimum_short:
                if expected:
                    first, _end, _bars = expected[-1]
                    expected[-1] = (first, development_end, development_end - first)
                break
            size = min(test_window, remaining)
            if remaining > test_window and remaining - test_window < minimum_short:
                size = remaining
            expected.append((cursor, cursor + size, size))
            cursor += size
        actual = [
            (fold.get("test_start_index"), fold.get("test_end_index"),
             fold.get("test_bars"))
            for fold in folds
        ]
        if actual != expected:
            raise ValueError("walk-forward folds do not match the server-owned fold law")


__all__ = ["ValidationPartitions", "build_partitions", "frame_sha256", "validate_fold_laws"]
