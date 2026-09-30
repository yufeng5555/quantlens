"""Temporal-integrity receipt construction and semantic re-verification."""

from __future__ import annotations

from .validation_partition import validate_fold_laws


class TemporalIntegrityError(ValueError):
    pass


def build_temporal_integrity_receipt(
    *,
    validation_plan: dict,
    partitions: dict,
    spec_hash: str,
    snapshot_sha256: str,
    final_audit: dict,
) -> dict:
    development = partitions["development"]
    final = partitions["final_holdout"]
    return {
        "receipt_version": "temporal-integrity-v1",
        "battery_plan_sha256": validation_plan["validation_plan_hash"],
        "spec_hash": spec_hash,
        "snapshot_sha256": snapshot_sha256,
        "development_input_sha256": development["input_sha256"],
        "final_holdout_input_sha256": final["evaluation_input_sha256"],
        "boundaries": {
            "development": {
                "start_index": development["start_index"],
                "end_index": development["end_index"],
                "bars": development["bars"],
            },
            "final_holdout": {
                "start_index": final["start_index"],
                "end_index": final["end_index"],
                "bars": final["bars"],
                "warmup_start_index": final["warmup_start_index"],
                "warmup_bars": final["warmup_bars"],
            },
        },
        "walk_forward": {
            "mode": "expanding-fixed-rule",
            "folds": [
                {
                    key: fold[key]
                    for key in (
                        "fold_id", "train_start_index", "train_end_index",
                        "test_start_index", "test_end_index", "test_bars",
                        "visible_prefix_end_index", "visible_prefix_sha256",
                    )
                }
                for fold in partitions["folds"]
            ],
            "laws": dict(partitions["laws"]),
        },
        "executions": {
            "final_holdout_primary_count": final_audit["primary_evaluation_count"],
            "final_holdout_counterfactual_count": final_audit[
                "counterfactual_evaluation_count"],
            "final_execution_binding": final_audit.get("execution_binding"),
        },
        "access_policy": {
            "development_battery": "development_only",
            "final_evaluator": "single_use_capability_only",
            "explanation_agent": "development_evidence_only",
            "production_gap": (
                "independent_os_principal_or_object_store_acl_not_implemented"
            ),
        },
    }


def validate_temporal_integrity_receipt(
    receipt: dict,
    *,
    validation_plan: dict,
    partitions: dict,
    spec_hash: str,
    snapshot_sha256: str,
    final_audit: dict,
) -> None:
    try:
        validate_fold_laws(partitions, validation_plan)
        expected = build_temporal_integrity_receipt(
            validation_plan=validation_plan,
            partitions=partitions,
            spec_hash=spec_hash,
            snapshot_sha256=snapshot_sha256,
            final_audit=final_audit,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TemporalIntegrityError("temporal receipt sources are malformed") from exc
    if receipt != expected:
        raise TemporalIntegrityError(
            "temporal-integrity receipt contradicts the sealed plan or partitions")
    if receipt["executions"]["final_holdout_primary_count"] not in {0, 1}:
        raise TemporalIntegrityError("final holdout primary execution count is invalid")
    if receipt["executions"]["final_holdout_counterfactual_count"] != 0:
        raise TemporalIntegrityError("final holdout counterfactual execution is forbidden")


__all__ = [
    "TemporalIntegrityError", "build_temporal_integrity_receipt",
    "validate_temporal_integrity_receipt",
]
