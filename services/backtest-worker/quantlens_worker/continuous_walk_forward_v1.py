"""Dormant Gate-C continuous walk-forward coordinator.

This module proves continuous state carry across walk-forward folds without changing
any active QuantLens execution path.  It is execution-model-neutral: it coordinates
fold prefixes and carry state only.  It computes no metric, no strategy signal, no
fill price and no Gate-D execution economics — those laws belong to the injected
segment executor (producer side) and to Codex's independent Gate-C validator work.

The active engine, Battery, runner, artifact, Evidence, report, API and web paths
never import this module.  It may import only the neutral Gate-B value builders in
``valuation_ledger_v1`` plus the standard library, and it never imports pandas: the
frame inputs are handled structurally so both pandas ``DataFrame`` objects and simple
sequence fixtures work (frozen in
``docs/planning/21-gate7a2-gatec-continuous-walk-forward-contract.md`` and
``docs/planning/22-claude-gatec-continuous-work-package.md``).
"""

from __future__ import annotations

import copy
import math
import re
from collections.abc import Mapping as MappingABC, Sequence as SequenceABC
from typing import Any, Callable, Mapping, Sequence

from .valuation_ledger_v1 import (
    ValuationLedgerContractError,
    build_carry_v1,
    build_execution_v1,
    build_window_v1,
    execution_sort_key_v1,
    sha256_json,
    validate_execution_contract_v1,
)


CONTINUOUS_PATH_VERSION = "continuous-development-path-v1"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTOR_RESULT_KEYS = frozenset({"strategy", "benchmark"})
_ROLES = ("strategy", "benchmark")


def _fail(detail: str) -> None:
    raise ValuationLedgerContractError(detail)


def _index(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be sha256: followed by 64 lowercase hex characters")
    return value


def derive_development_evaluation_v1(partitions: Mapping[str, Any]) -> dict[str, int]:
    """Derive the exact development-evaluation window from a READY fold artifact.

    The economic OOS path starts at the first declared test fold, not at index zero:
    the expanding training prefix is signal warm-up, never a zero-return observation.
    Every fold law from the controlling contract is enforced independently here; a
    non-READY, empty, gapped, overlapping, reordered or incomplete fold set fails
    closed.
    """
    if not isinstance(partitions, MappingABC):
        _fail("partitions must be the validation-partitions artifact object")
    if partitions.get("status") != "READY":
        _fail("only a READY partitions artifact has a continuous development path")
    development = partitions.get("development")
    if not isinstance(development, MappingABC):
        _fail("partitions.development must be an object")
    if _index(development.get("start_index"), "partitions.development.start_index") != 0:
        _fail("partitions.development.start_index must be exactly 0")
    development_end = _index(
        development.get("end_index"), "partitions.development.end_index", minimum=1,
    )
    if "bars" in development:
        development_bars = _index(
            development.get("bars"), "partitions.development.bars", minimum=1,
        )
        if development_bars != development_end:
            _fail("partitions.development.bars must equal its end_index")
    folds = partitions.get("folds")
    if not isinstance(folds, list) or not folds:
        _fail("partitions.folds must be a non-empty array")
    prior_end: int | None = None
    seen_fold_ids: set[str] = set()
    for position, fold in enumerate(folds):
        label = f"partitions.folds[{position}]"
        if not isinstance(fold, MappingABC):
            _fail(f"{label} must be an object")
        fold_id = fold.get("fold_id")
        if not isinstance(fold_id, str) or not fold_id:
            _fail(f"{label}.fold_id must be a non-empty string")
        if fold_id in seen_fold_ids:
            _fail(f"{label}.fold_id must be unique")
        seen_fold_ids.add(fold_id)
        start = _index(fold.get("test_start_index"), f"{label}.test_start_index")
        end = _index(fold.get("test_end_index"), f"{label}.test_end_index", minimum=1)
        if end <= start:
            _fail(f"{label} test window must be non-empty")
        if _index(fold.get("train_start_index"), f"{label}.train_start_index") != 0:
            _fail(f"{label} training window must expand from index zero")
        train_end = _index(
            fold.get("train_end_index"), f"{label}.train_end_index", minimum=1,
        )
        if train_end != start:
            _fail(f"{label} train and test windows must be adjacent")
        visible_prefix_end = _index(
            fold.get("visible_prefix_end_index"),
            f"{label}.visible_prefix_end_index",
            minimum=1,
        )
        if visible_prefix_end != end:
            _fail(f"{label} physical prefix must end exactly at its test end")
        if "train_bars" in fold:
            train_bars = _index(
                fold.get("train_bars"), f"{label}.train_bars", minimum=1,
            )
            if train_bars != start:
                _fail(f"{label}.train_bars must equal its test_start_index")
        if "test_bars" in fold:
            test_bars = _index(
                fold.get("test_bars"), f"{label}.test_bars", minimum=1,
            )
            if test_bars != end - start:
                _fail(f"{label}.test_bars must equal its test window size")
        if prior_end is not None and start != prior_end:
            _fail(f"{label} test windows must be ordered, non-overlapping and contiguous")
        prior_end = end
    if prior_end != development_end:
        _fail("the final fold must end exactly at partitions.development.end_index")
    start_index = int(folds[0]["test_start_index"])
    end_index_exclusive = int(folds[-1]["test_end_index"])
    return {
        "start_index": start_index,
        "end_index_exclusive": end_index_exclusive,
        "observation_count": end_index_exclusive - start_index,
    }


def _canonical_multipliers(values: object) -> list[float]:
    if isinstance(values, (str, bytes)) or not isinstance(values, SequenceABC):
        _fail("cost_multipliers must be a sequence of numbers")
    multipliers: list[float] = []
    for position, raw in enumerate(values):
        label = f"cost_multipliers[{position}]"
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            _fail(f"{label} must be a JSON number")
        value = float(raw)
        if not math.isfinite(value):
            _fail(f"{label} must be finite")
        if value < 0:
            _fail(f"{label} must not be negative")
        multipliers.append(value)
    if not multipliers:
        _fail("cost_multipliers must not be empty")
    if len(set(multipliers)) != len(multipliers):
        _fail("cost_multipliers must not contain duplicates")
    if 1.0 not in multipliers:
        _fail("cost_multipliers must include exactly 1.0")
    return sorted(multipliers)


def _canonical_initial_carry(value: object) -> dict[str, Any]:
    if not isinstance(value, MappingABC):
        _fail("initial_carry must be a carry object")
    try:
        return build_carry_v1(**dict(value))
    except TypeError:
        _fail("initial_carry must have exactly cash, shares, and position")
    raise AssertionError("unreachable")


def _frame_length(frame: Any, label: str) -> int:
    try:
        return len(frame)
    except TypeError:
        _fail(f"{label} must have a length")
    raise AssertionError("unreachable")


def _prefix_copy(frame: Any, end: int, label: str) -> Any:
    """Return a fresh deep copy of the physical prefix ending at ``end``.

    Pandas frames are handled structurally (``iloc``/``copy``/``reset_index``)
    without importing pandas; plain sequences of rows are deep-copied lists.  The
    executor may mutate its copy freely — the caller's input never changes.
    """
    iloc = getattr(frame, "iloc", None)
    if iloc is not None:
        prefix = iloc[:end]
        copy_method = getattr(prefix, "copy", None)
        if callable(copy_method):
            try:
                prefix = copy_method(deep=True)
            except TypeError:
                prefix = copy_method()
        reset_index = getattr(prefix, "reset_index", None)
        if callable(reset_index):
            try:
                prefix = reset_index(drop=True)
            except TypeError:
                pass
        return prefix
    if isinstance(frame, SequenceABC) and not isinstance(frame, (str, bytes)):
        return copy.deepcopy(list(frame[:end]))
    _fail(f"{label} must be a pandas-like frame or a sequence of rows")
    raise AssertionError("unreachable")


def _frame_date(frame: Any, index: int, label: str) -> str:
    """Read the exact sealed date string at one zero-based source-frame index."""
    iloc = getattr(frame, "iloc", None)
    try:
        row = iloc[index] if iloc is not None else frame[index]
        value = row["date"]
    except Exception as exc:
        raise ValuationLedgerContractError(
            f"{label}[{index}] has no readable date field"
        ) from exc
    if not isinstance(value, str) or not value:
        _fail(f"{label}[{index}].date must be the exact sealed date string")
    return value


def _window_source_dates(frame: Any, start: int, end: int, label: str) -> list[str]:
    return [_frame_date(frame, index, label) for index in range(start, end)]


def _accepted_fold_execution(
    result: object,
    *,
    role: str,
    fold: Mapping[str, Any],
    cost_multiplier: float,
    expected_carry_in: Mapping[str, Any],
    expected_carry_in_sha256: str,
    expected_dates: Sequence[str],
    spec_hash: str,
    snapshot_sha256: str,
    call_label: str,
) -> dict[str, Any]:
    """Fail-closed acceptance of one executor-returned fold-slice execution."""
    if not isinstance(result, MappingABC) or frozenset(result) != _EXECUTOR_RESULT_KEYS:
        _fail(f"{call_label}: the segment executor must return exactly strategy and benchmark")
    raw = result[role]
    if not isinstance(raw, MappingABC):
        _fail(f"{call_label}: the {role} execution must be an object")
    # Deep copy BEFORE validation so a later executor-side mutation of the object it
    # returned can never change what the coordinator accepted.
    execution = copy.deepcopy(dict(raw))
    try:
        validate_execution_contract_v1(
            execution, spec_hash=spec_hash, snapshot_sha256=snapshot_sha256,
        )
    except ValuationLedgerContractError:
        raise
    except Exception as exc:  # malformed values must fail closed, never leak upward
        raise ValuationLedgerContractError(
            f"{call_label}: the {role} execution violates the valuation contract"
        ) from exc
    if execution["role"] != role:
        _fail(f"{call_label}: the {role} slot returned role {execution['role']!r}")
    if execution["purpose"] != "fold_slice":
        _fail(f"{call_label}: fold executions must have purpose fold_slice")
    if execution["cost_multiplier"] != cost_multiplier:
        _fail(f"{call_label}: fold execution multiplier does not match the requested one")
    window = execution["window"]
    if window["start_index"] != fold["test_start_index"] or \
            window["end_index_exclusive"] != fold["test_end_index"]:
        _fail(f"{call_label}: fold execution window does not match the declared fold")
    # Carry chaining requires BOTH the exact carry object and its canonical hash to
    # equal the carried-forward state — a replaced carry with a self-consistently
    # recomputed hash is still a reset, and fails here.
    if execution["carry_in"] != expected_carry_in:
        _fail(f"{call_label}: fold carry-in object does not equal the carried-forward state")
    if execution["carry_in_sha256"] != expected_carry_in_sha256:
        _fail(f"{call_label}: fold carry-in hash does not equal the carried-forward state")
    # Every returned date binds to the role's source frame at the SAME zero-based
    # indices: no offset, no remapping, no fabricated calendar.
    if window["start_date"] != expected_dates[0] or window["end_date"] != expected_dates[-1]:
        _fail(f"{call_label}: fold window dates do not bind to the source frame")
    for position, bar in enumerate(execution["bars"]):
        if bar["date"] != expected_dates[position]:
            _fail(
                f"{call_label}: bar[{position}] date does not bind to the source "
                "frame at the same index"
            )
    return execution


def _full_path_execution(
    *,
    role: str,
    purpose: str,
    slices: Sequence[Mapping[str, Any]],
    evaluation: Mapping[str, int],
    cost_multiplier: float,
    initial_carry: Mapping[str, Any],
    spec_hash: str,
    snapshot_sha256: str,
) -> dict[str, Any]:
    """Assemble one continuous full-window execution from raw fold records.

    Bars and fills are concatenated in fold order, unchanged: nothing is scaled,
    rounded, repaired or synthesized.  ``build_execution_v1`` then re-derives the
    identity and re-checks the window, date, and carry-out laws, so an inconsistent
    assembly fails closed instead of sealing.
    """
    bars = [bar for item in slices for bar in item["bars"]]
    fills = [fill for item in slices for fill in item["fills"]]
    if not bars:
        _fail("a continuous path requires at least one bar")
    window = build_window_v1(
        start_date=bars[0]["date"],
        end_date=bars[-1]["date"],
        start_index=evaluation["start_index"],
        end_index_exclusive=evaluation["end_index_exclusive"],
    )
    return build_execution_v1(
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        role=role,
        purpose=purpose,
        window=window,
        cost_multiplier=cost_multiplier,
        carry_in=initial_carry,
        carry_out=slices[-1]["carry_out"],
        bars=bars,
        fills=fills,
    )


def run_continuous_development_paths_v1(
    *,
    development: Any,
    benchmark_development: Any | None,
    partitions: Mapping[str, Any],
    spec_hash: str,
    snapshot_sha256: str,
    initial_carry: Mapping[str, Any],
    cost_multipliers: Sequence[float],
    segment_executor: Callable[..., Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """Coordinate one continuous development OOS path per role and per multiplier.

    For each declared multiplier, strategy and benchmark state initialize exactly
    once from independent fresh copies of ``initial_carry``, then carry fold to
    fold: each fold receives the previous fold's exact carry-out as carry-in, and
    the last fold's carry-out is the continuous path's carry-out.  An open final
    position stays open (mark-to-market, no forced liquidation).  Fold slices are
    literal projections of the one carried path; the coordinator never scales,
    liquidates or re-enters state because a statistical fold ended.
    """
    evaluation = derive_development_evaluation_v1(partitions)
    spec_hash = _sha(spec_hash, "spec_hash")
    snapshot_sha256 = _sha(snapshot_sha256, "snapshot_sha256")
    initial = _canonical_initial_carry(initial_carry)
    initial_sha256 = sha256_json(initial)
    multipliers = _canonical_multipliers(cost_multipliers)
    if not callable(segment_executor):
        _fail("segment_executor must be callable")
    if development is None:
        _fail("development frame is required")
    benchmark_source = development if benchmark_development is None else benchmark_development
    end_exclusive = evaluation["end_index_exclusive"]
    if _frame_length(development, "development") < end_exclusive:
        _fail("development frame is shorter than the development evaluation window")
    if _frame_length(benchmark_source, "benchmark_development") < end_exclusive:
        _fail("benchmark frame is shorter than the development evaluation window")
    if benchmark_development is not None:
        # Strategy and benchmark may carry distinct PRICE series, but their
        # reviewed session dates must align index-for-index through the whole
        # evaluated range (contract 21 / validation_partition alignment law).
        # This fails closed BEFORE any segment-executor call.
        for index in range(end_exclusive):
            if _frame_date(benchmark_source, index, "benchmark_development") != \
                    _frame_date(development, index, "development"):
                _fail(
                    "benchmark_development sessions must equal development "
                    f"sessions index-for-index (mismatch at index {index})"
                )
    folds = partitions["folds"]
    # The binding calendar per role and fold: the exact date strings at the same
    # zero-based indices of each role's source frame, extracted once.
    fold_dates: list[dict[str, list[str]]] = [
        {
            "strategy": _window_source_dates(
                development, int(fold["test_start_index"]),
                int(fold["test_end_index"]), "development",
            ),
            "benchmark": _window_source_dates(
                benchmark_source, int(fold["test_start_index"]),
                int(fold["test_end_index"]), "benchmark_development",
            ),
        }
        for fold in folds
    ]

    executions: list[dict[str, Any]] = []
    for multiplier in multipliers:
        # Fresh, independent state per role and per multiplier: carry objects are
        # never shared between roles or between multiplier paths.
        carries = {role: copy.deepcopy(initial) for role in _ROLES}
        carry_hashes = {role: initial_sha256 for role in _ROLES}
        slices: dict[str, list[dict[str, Any]]] = {role: [] for role in _ROLES}
        for position, fold in enumerate(folds):
            fold_end = int(fold["test_end_index"])
            call_label = (
                f"segment_executor(multiplier={multiplier!r}, fold={position})"
            )
            result = segment_executor(
                strategy_prefix=_prefix_copy(development, fold_end, "development"),
                benchmark_prefix=_prefix_copy(
                    benchmark_source, fold_end, "benchmark_development",
                ),
                fold=copy.deepcopy(dict(fold)),
                strategy_carry_in=copy.deepcopy(carries["strategy"]),
                benchmark_carry_in=copy.deepcopy(carries["benchmark"]),
                cost_multiplier=multiplier,
                spec_hash=spec_hash,
                snapshot_sha256=snapshot_sha256,
            )
            for role in _ROLES:
                execution = _accepted_fold_execution(
                    result,
                    role=role,
                    fold=fold,
                    cost_multiplier=multiplier,
                    expected_carry_in=carries[role],
                    expected_carry_in_sha256=carry_hashes[role],
                    expected_dates=fold_dates[position][role],
                    spec_hash=spec_hash,
                    snapshot_sha256=snapshot_sha256,
                    call_label=call_label,
                )
                slices[role].append(execution)
                carries[role] = copy.deepcopy(execution["carry_out"])
                carry_hashes[role] = execution["carry_out_sha256"]
        for role in _ROLES:
            role_slices = slices[role]
            executions.append(_full_path_execution(
                role=role,
                purpose="cost_stress",
                slices=role_slices,
                evaluation=evaluation,
                cost_multiplier=multiplier,
                initial_carry=initial,
                spec_hash=spec_hash,
                snapshot_sha256=snapshot_sha256,
            ))
            if multiplier == 1.0:
                # The 1.0 primary pair is built from the SAME exact concatenated
                # records as the 1.0 cost-stress pair: only purpose and the derived
                # execution identity differ.
                executions.append(_full_path_execution(
                    role=role,
                    purpose="primary_evaluation",
                    slices=role_slices,
                    evaluation=evaluation,
                    cost_multiplier=multiplier,
                    initial_carry=initial,
                    spec_hash=spec_hash,
                    snapshot_sha256=snapshot_sha256,
                ))
                # Only the 1.0 fold slices are retained; other multipliers' fold
                # objects exist solely to assemble that multiplier's full path.
                executions.extend(role_slices)

    identifiers = [execution["execution_id"] for execution in executions]
    if len(identifiers) != len(set(identifiers)):
        _fail("continuous path produced a duplicate execution identity")
    executions.sort(key=execution_sort_key_v1)
    return {
        "continuous_path_version": CONTINUOUS_PATH_VERSION,
        "development_evaluation": dict(evaluation),
        "executions": executions,
    }


__all__ = [
    "CONTINUOUS_PATH_VERSION",
    "derive_development_evaluation_v1",
    "run_continuous_development_paths_v1",
]
