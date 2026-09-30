"""Server-authoritative research readiness checks performed before queue admission.

Preflight loads the exact pinned data that a worker would receive, but it never runs a
strategy, computes a signal, previews performance, or claims a final holdout.  Its only
job is to establish whether the confirmed study can produce the declared validation
structure and to surface factual data/assumption warnings before compute is accepted.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path

from quantlens_worker.config import BATTERY_CONFIG_V2
from quantlens_worker.snapshot import (
    DataQualityError,
    load_frame,
    snapshot_dir,
    verify_snapshot_integrity,
)
from quantlens_worker.validation_plan import (
    BATTERY_V1,
    BATTERY_V2,
    build_validation_plan,
    max_indicator_lookback,
)


PREFLIGHT_VERSION = "research-preflight-v1"

# Stop F5: the corrected profile joins preflight. The API never imports the
# dormant battery-v3 modules, so the corrected plan arithmetic is mirrored
# below from the reviewed v2 numerical law the immutable v3 profile copies
# byte-for-byte; the focused F5 suite cross-checks the mirror against the
# dormant source of truth.
BATTERY_V3 = "battery-v3"


def principal_source_context(
    spec: dict, *, tenant_id: str, user_id: str,
) -> tuple[Path, dict | None]:
    """Resolve a source only through the principal-scoped sealed registry."""
    if spec.get("dsl_version") == "1.0":
        return snapshot_dir(), None
    from . import db  # local import keeps the pure evaluator usable in unit tests

    source = (spec.get("data") or {}).get("source") or {}
    dataset = db.get_dataset_for_principal(
        source.get("dataset_id", ""), tenant_id, user_id)
    if dataset is None:
        raise DataQualityError(
            "DATASET_NOT_SEALED",
            "The selected dataset is missing, withdrawn, or not sealed for this workspace.",
        )
    return db.dataset_directory(dataset), dataset


def _issue(
    issue_id: str,
    severity: str,
    category: str,
    message: str,
    suggestion: str,
    evidence: dict | None = None,
) -> dict:
    return {
        "id": issue_id,
        "severity": severity,
        "category": category,
        "message": message,
        "suggestion": suggestion,
        "evidence": evidence or {},
    }


def _canonical_sha256(value: object) -> str:
    body = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _strict_fold_count(plan: dict) -> int:
    """Mirror the server-owned expanding-fold law without reading outcome data."""
    development_end = int(plan["development_bars"])
    cursor = int(plan["minimum_train_bars"])
    test_window = int(plan["test_window_bars"])
    minimum_short = int(plan["minimum_short_fold_bars"])
    folds = 0
    while cursor < development_end:
        remaining = development_end - cursor
        if remaining < minimum_short:
            break
        size = min(test_window, remaining)
        if remaining > test_window and remaining - test_window < minimum_short:
            size = remaining
        folds += 1
        cursor += size
    return folds


def _corrected_plan_view(spec: dict, n_bars: int) -> dict:
    """Mirror the corrected battery-v3 plan arithmetic for preflight only.

    The immutable battery-v3 profile copies the reviewed v2 development and
    final-holdout constants byte-for-byte; the corrected final window uses
    half-even bar rounding. Only the five fields the shared fold/readiness
    reporting consumes are derived here — the sealed validation-plan-v3 is
    built exclusively by the corrected execution branch at run time.
    """
    cfg = BATTERY_CONFIG_V2
    fraction = float(spec["validation"]["is_oos_split"]["oos_fraction"])
    final_bars = int(
        (Decimal(n_bars) * Decimal(str(fraction)))
        .to_integral_value(rounding=ROUND_HALF_EVEN)
    )
    final_bars = max(1, final_bars)
    lookback = max_indicator_lookback(spec["rule"])
    minimum_train = max(
        int(cfg["development"]["minimum_train_floor_bars"]),
        int(cfg["development"]["minimum_train_lookback_multiple"]) * lookback,
    )
    return {
        "development_bars": int(n_bars - final_bars),
        "final_holdout_bars": int(final_bars),
        "minimum_train_bars": int(minimum_train),
        "test_window_bars": int(cfg["development"]["test_window_bars"]),
        "minimum_short_fold_bars": int(
            cfg["development"]["minimum_short_fold_bars"]),
    }


def _valid_standard_grid_windows(spec: dict) -> list[int]:
    grid = sorted(set(spec["validation"]["sensitivity"]["grid"]["ma_days"]))
    if spec["rule"]["type"] != "ma_crossover":
        return grid
    fast = spec["rule"].get("fast_ma_days")
    return [window for window in grid if fast is None or fast < window]


def evaluate_preflight(
    spec: dict,
    *,
    battery_profile: str,
    spec_hash: str,
    profile_hash: str,
    source_directory: Path,
    dataset: dict | None = None,
) -> dict:
    """Return a closed preflight contract for one already schema-valid spec.

    ``source_directory`` must already have been resolved through the principal-scoped
    dataset registry (or be the bundled synthetic directory).  Dataset ownership and
    licensed-rights checks stay in the API control plane and are repeated at run create.
    """
    if battery_profile not in {BATTERY_V1, BATTERY_V2, BATTERY_V3}:
        raise ValueError("unsupported preflight battery profile")

    blockers: list[dict] = []
    warnings: list[dict] = []
    checks: list[dict] = []
    plan_view: dict = {}
    data_view: dict = {}
    snapshot_binding: dict = {}

    symbol = spec["universe"]["symbol"]
    requested = spec["data"]["range"]
    try:
        snapshot = verify_snapshot_integrity(source_directory)
        frame, gaps = load_frame(
            symbol, requested["start"], requested["end"], source_directory)
    except DataQualityError as exc:
        blockers.append(_issue(
            f"PREFLIGHT_{exc.code}", "blocker", "data", exc.message,
            "Correct the data source or requested range, then run preflight again.",
            {"data_quality_code": exc.code},
        ))
        snapshot = None
        frame = None
        gaps = None
    else:
        snapshot_binding = {
            "snapshot_sha256": snapshot.get("sha256"),
            "dataset_manifest_sha256": (
                dataset.get("dataset_manifest_sha256") if dataset else None
            ),
        }
        data_view = {
            "label": snapshot.get("label"),
            "missing_business_days": int(gaps["missing_day_count"]),
            "max_consecutive_missing": int(gaps["max_consecutive"]),
            "returned_range": gaps["returned_range"],
            "return_basis": (
                (dataset or {}).get("quality", {}).get("return_basis")
                or snapshot.get("adjustment_convention")
            ),
        }
        checks.append({
            "id": "PREFLIGHT_DATA_EXECUTABLE",
            "status": "pass",
            "label": "Pinned data is readable and executable",
            "evidence": {
                "actual_bars": int(len(frame)),
                "actual_start": str(frame["date"].iloc[0]),
                "actual_end": str(frame["date"].iloc[-1]),
            },
        })

        benchmark_symbol = spec["benchmark"]["symbol"]
        if benchmark_symbol != "same_as_universe":
            try:
                benchmark, _benchmark_gaps = load_frame(
                    benchmark_symbol, requested["start"], requested["end"],
                    source_directory,
                )
            except DataQualityError as exc:
                blockers.append(_issue(
                    f"PREFLIGHT_BENCHMARK_{exc.code}", "blocker", "benchmark",
                    "The alternate benchmark cannot be loaded over the requested window.",
                    "Choose an aligned benchmark or change the requested range.",
                    {"data_quality_code": exc.code, "benchmark": benchmark_symbol},
                ))
            else:
                aligned = (
                    len(benchmark) == len(frame)
                    and benchmark["date"].reset_index(drop=True).equals(
                        frame["date"].reset_index(drop=True)
                    )
                )
                if not aligned:
                    blockers.append(_issue(
                        "PREFLIGHT_BENCHMARK_DATE_MISMATCH", "blocker", "benchmark",
                        "The strategy and alternate benchmark do not have identical ordered sessions.",
                        "Use an aligned benchmark or the same instrument as the strategy.",
                        {"benchmark": benchmark_symbol},
                    ))
                else:
                    checks.append({
                        "id": "PREFLIGHT_BENCHMARK_ALIGNED",
                        "status": "pass",
                        "label": "Benchmark sessions are exactly aligned",
                        "evidence": {"benchmark": benchmark_symbol, "bars": len(benchmark)},
                    })

        n_bars = int(len(frame))
        lookback = max_indicator_lookback(spec["rule"])
        plan_view = {
            "actual_bars": n_bars,
            "actual_start": str(frame["date"].iloc[0]),
            "actual_end": str(frame["date"].iloc[-1]),
            "max_rule_lookback": lookback,
        }
        if battery_profile in (BATTERY_V2, BATTERY_V3):
            plan = (
                build_validation_plan(spec, n_bars)
                if battery_profile == BATTERY_V2
                else _corrected_plan_view(spec, n_bars)
            )
            fold_count = _strict_fold_count(plan)
            plan_view.update({
                "development_bars": int(plan["development_bars"]),
                "final_holdout_bars": int(plan["final_holdout_bars"]),
                "minimum_train_bars": int(plan["minimum_train_bars"]),
                "minimum_fold_bars": int(plan["minimum_short_fold_bars"]),
                "expected_fold_count": fold_count,
                "parameter_selection": "forbidden",
            })
            if fold_count == 0:
                required = int(plan["minimum_train_bars"]) + int(
                    plan["minimum_short_fold_bars"])
                blockers.append(_issue(
                    "PREFLIGHT_STRICT_NO_VALID_FOLD", "blocker", "validation",
                    "Strict validation has no complete development walk-forward fold.",
                    "Widen the requested range or reduce the confirmed rule lookback.",
                    {
                        "development_bars": int(plan["development_bars"]),
                        "minimum_required_development_bars": required,
                    },
                ))
            elif fold_count == 1:
                warnings.append(_issue(
                    "PREFLIGHT_SINGLE_FOLD", "warning", "validation",
                    "Strict validation has only one development fold, so cross-fold dispersion is unavailable.",
                    "You may continue, or widen the range for more walk-forward coverage.",
                    {"expected_fold_count": 1},
                ))
            else:
                checks.append({
                    "id": "PREFLIGHT_STRICT_FOLDS_READY",
                    "status": "pass",
                    "label": "Strict walk-forward plan is executable",
                    "evidence": {"expected_fold_count": fold_count},
                })
        else:
            fraction = float(spec["validation"]["is_oos_split"]["oos_fraction"])
            oos_bars = max(1, int(round(n_bars * fraction)))
            is_bars = n_bars - oos_bars
            windows = [spec["rule"]["ma_days"]]
            windows.extend(spec["validation"]["sensitivity"]["grid"]["ma_days"])
            fast = spec["rule"].get("fast_ma_days")
            if fast is not None:
                windows.append(fast)
            warmup = max(windows)
            plan_view.update({
                "in_sample_bars": is_bars,
                "out_of_sample_bars": oos_bars,
                "shared_warmup_bars": warmup,
                "in_sample_evaluation_bars": max(0, is_bars - warmup),
            })
            if is_bars <= warmup:
                blockers.append(_issue(
                    "PREFLIGHT_STANDARD_NO_IS_EVALUATION", "blocker", "validation",
                    "Standard audit has no in-sample observation after the shared warmup.",
                    "Widen the range or reduce the moving-average windows.",
                    {"in_sample_bars": is_bars, "shared_warmup_bars": warmup},
                ))
            else:
                checks.append({
                    "id": "PREFLIGHT_STANDARD_SPLIT_READY",
                    "status": "pass",
                    "label": "Standard audit split is executable",
                    "evidence": {
                        "in_sample_evaluation_bars": is_bars - warmup,
                        "out_of_sample_bars": oos_bars,
                    },
                })
            valid_grid = _valid_standard_grid_windows(spec)
            if len(valid_grid) <= 1:
                warnings.append(_issue(
                    "PREFLIGHT_NO_VALID_GRID_NEIGHBOR", "warning", "validation",
                    "The chosen sensitivity cell has no valid neighboring MA window, so parameter fragility will be inconclusive.",
                    "Add at least one valid neighboring slow window if you need that check.",
                    {"valid_grid_windows": valid_grid},
                ))

        if snapshot.get("label") == "SYNTHETIC":
            warnings.append(_issue(
                "PREFLIGHT_SAMPLE_DATA", "warning", "data",
                "This run uses bundled synthetic sample data, not observed market data.",
                "Use this source for product testing only; bind a sealed observed dataset for market research.",
                {"data_label": "SYNTHETIC"},
            ))

        quality = (dataset or {}).get("quality") or {}
        for raw in quality.get("issues", []):
            if not isinstance(raw, dict) or raw.get("severity") != "warning":
                continue
            code = raw.get("code")
            if not isinstance(code, str) or not code:
                continue
            warnings.append(_issue(
                f"PREFLIGHT_{code}", "warning", "data",
                str(raw.get("message") or "The sealed dataset has a quality warning."),
                "Review the sealed dataset quality receipt before continuing.",
                {"dataset_warning_code": code},
            ))
        return_basis = quality.get("return_basis")
        if isinstance(return_basis, str) and "dividends are not included" in return_basis:
            warnings.append(_issue(
                "PREFLIGHT_PRICE_RETURN_ONLY", "warning", "data",
                "The sealed dataset represents price return only; dividends are not included.",
                "Interpret benchmark and strategy results on the same documented price-return basis.",
                {"return_basis": return_basis},
            ))

        costs = spec["costs"]
        if float(costs["commission_bps"]) + float(costs["slippage_bps"]) == 0:
            warnings.append(_issue(
                "PREFLIGHT_ZERO_COST_STRESS", "warning", "assumptions",
                "Base commission and slippage are both zero, so multiplying costs cannot test trading friction.",
                "Continue only if a frictionless experiment is intentional.",
                {"commission_bps": 0, "slippage_bps": 0},
            ))

    blockers.sort(key=lambda item: item["id"])
    warnings.sort(key=lambda item: item["id"])
    required = [item["id"] for item in warnings]
    hash_payload = {
        "version": PREFLIGHT_VERSION,
        "spec_hash": spec_hash,
        "profile_hash": profile_hash,
        "snapshot_binding": snapshot_binding,
        "blockers": [
            {"id": item["id"], "evidence": item["evidence"]} for item in blockers
        ],
        "warnings": [
            {"id": item["id"], "evidence": item["evidence"]} for item in warnings
        ],
        "plan": plan_view,
    }
    preflight_hash = _canonical_sha256(hash_payload)
    can_run = not blockers
    status = "blocked" if blockers else "ready_with_warnings" if warnings else "ready"
    return {
        "version": PREFLIGHT_VERSION,
        "status": status,
        "can_run": can_run,
        "preflight_hash": preflight_hash,
        "blockers": blockers,
        "warnings": warnings,
        "required_acknowledgement_ids": required,
        "checks": checks,
        "plan": plan_view,
        "data": data_view,
    }


__all__ = [
    "PREFLIGHT_VERSION", "evaluate_preflight", "principal_source_context",
]
