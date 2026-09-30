"""EvidenceViewV2 semantic gate and development-only agent projection."""

from __future__ import annotations

import copy
import hashlib

from .artifacts import ArtifactIntegrityError, _canonical
from .temporal_integrity import (
    TemporalIntegrityError,
    validate_temporal_integrity_receipt,
)
from .validation_plan import BATTERY_V2, build_validation_plan, sha256_json

_STATUSES = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})
_ICONS = {"PASS": "✓", "FAIL": "✗", "INCONCLUSIVE": "?"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactIntegrityError(f"evidence semantics (v2): {message}")


def _validate_series(result: dict, segment: dict, label: str) -> None:
    series = result.get("equity_series") or {}
    dates = series.get("date") or []
    equity = series.get("equity") or []
    positions = series.get("position") or []
    if result.get("status") == "INCONCLUSIVE":
        _require(not dates and not equity, f"{label} inconclusive result contains claims")
        return
    _require(result.get("status") == "COMPLETE", f"{label} status is invalid")
    _require(len(dates) == len(equity) == len(positions) > 0,
             f"{label} series are not aligned")
    _require(all(dates[index] < dates[index + 1] for index in range(len(dates) - 1)),
             f"{label} dates are not strictly increasing")
    _require(segment["start"] <= dates[0] <= dates[-1] <= segment["end"],
             f"{label} series escapes its sealed partition")
    metrics = result.get("strategy_metrics") or {}
    _require(metrics.get("n_bars") == len(dates),
             f"{label} metrics do not cover the sealed series")


def _agent_projection(payloads: dict) -> dict:
    development = payloads["development_result"]
    metrics = development.get("strategy_metrics") or {}
    walk_forward = payloads["walk_forward"]
    regimes = payloads["regime_analysis"]
    findings = payloads["falsification"].get("findings", [])
    # No dates, hashes, artifact ids, capsule ids, final fields, raw series, or receipt
    # bytes cross this boundary.
    return {
        "projection_version": "agent-development-projection-v1",
        "scope": "development_only",
        "development_metrics": {
            key: metrics.get(key)
            for key in (
                "total_return", "cagr", "ann_vol", "sharpe", "max_drawdown",
                "n_trades", "total_costs", "exposure",
            )
        },
        "walk_forward": {
            key: walk_forward.get(key)
            for key in (
                "fold_count", "median_fold_sharpe", "positive_fold_ratio",
                "worst_fold_return", "fold_return_dispersion",
            )
        },
        "regimes": [
            {
                key: state.get(key)
                for key in (
                    "regime", "status", "observations",
                    "strategy_compounded_return", "benchmark_compounded_return",
                    "mean_daily_excess_return", "exposure", "trade_count",
                )
            }
            for state in regimes.get("states", [])
        ],
        "checks": [
            {"id": item.get("id"), "status": item.get("status")}
            for item in findings
        ],
    }


def build_evidence_view_v2(
    manifest: dict, ledger: dict, payloads: dict, receipt: dict,
) -> dict:
    plan = payloads["validation_plan"]
    spec = payloads["spec"]["spec"]
    partitions = payloads["partitions"]
    _require(plan.get("profile_id") == BATTERY_V2, "validation profile is not battery-v2")
    plan_body = {key: value for key, value in plan.items()
                 if key != "validation_plan_hash"}
    _require(plan.get("validation_plan_hash") == sha256_json(plan_body),
             "validation plan hash does not match its bytes")
    _require(plan.get("profile_hash") == manifest.get("battery_config_hash"),
             "validation profile hash does not match the manifest")
    _require(receipt.get("battery_profile") == BATTERY_V2 and
             receipt.get("battery_profile_hash") == plan.get("profile_hash"),
             "confirmation receipt is not bound to battery-v2")
    _require(receipt.get("spec_hash") == manifest.get("spec_hash"),
             "confirmation receipt is bound to another spec")

    final_audit = payloads["final_holdout_execution_audit"]
    try:
        validate_temporal_integrity_receipt(
            payloads["temporal_integrity"],
            validation_plan=plan,
            partitions=partitions,
            spec_hash=manifest["spec_hash"],
            snapshot_sha256=manifest["snapshot_sha256"],
            final_audit=final_audit,
        )
    except TemporalIntegrityError as exc:
        raise ArtifactIntegrityError(f"evidence semantics (v2): {exc}") from exc

    development = payloads["development_result"]
    final = payloads["final_holdout_result"]
    _validate_series(development, partitions["development"], "development")
    _validate_series(final, partitions["final_holdout"], "final holdout")
    primary = final_audit.get("primary_evaluation_count")
    _require(primary in {0, 1}, "final primary execution count is invalid")
    _require(final_audit.get("counterfactual_evaluation_count") == 0,
             "a final counterfactual execution was recorded")
    if final.get("status") == "COMPLETE":
        _require(primary == 1, "complete final result lacks its single execution")
        binding = final.get("execution_binding") or {}
        expected_binding = {
            "capsule_id": final_audit.get("capsule_id"),
            "confirmed_spec_hash": manifest["spec_hash"],
            "validation_plan_hash": plan["validation_plan_hash"],
            "locked_rule_sha256": sha256_json(spec["rule"]),
            "base_costs_sha256": sha256_json(spec["costs"]),
            "cost_multiplier": 1.0,
        }
        _require(binding == expected_binding and
                 final_audit.get("execution_binding") == expected_binding,
                 "final result is not bound to the locked spec/plan/base costs")
    else:
        _require(primary == 0, "inconclusive final result consumed the holdout")

    sensitivity = payloads["sensitivity"]
    _require(sensitivity.get("parameter_selection") == "forbidden" and
             sensitivity.get("grid") == [],
             "battery-v2 performed or exposed parameter selection")
    _require(payloads["walk_forward"].get("parameter_selection") == "forbidden",
             "walk-forward does not declare fixed-rule execution")

    findings = payloads["falsification"].get("findings")
    _require(isinstance(findings, list) and findings, "required findings are missing")
    for item in findings:
        _require(item.get("status") in _STATUSES,
                 f"finding {item.get('id')!r} has an invalid status")
    status = "FAIL" if any(item["status"] == "FAIL" for item in findings) else (
        "INCONCLUSIVE" if any(item["status"] == "INCONCLUSIVE" for item in findings)
        else "PASS"
    )
    evidence_status = payloads["evidence_status"]
    _require(evidence_status.get("battery_status") == status,
             "evidence status contradicts the findings")

    presented_findings = []
    for finding in findings:
        value = copy.deepcopy(finding)
        value.update({
            "status_label": finding["status"],
            "status_css": finding["status"].lower(),
            "status_icon": _ICONS[finding["status"]],
        })
        presented_findings.append(value)
    falsification = copy.deepcopy(payloads["falsification"])
    falsification["findings"] = presented_findings
    artifacts = [
        {"artifact_id": item["artifact_id"], "kind": item["kind"],
         "sha256": item["sha256"]}
        for item in ledger["entries"]
    ]
    recomputed_plan = build_validation_plan(spec, int(partitions.get("n_bars", -1)))
    _require(plan == recomputed_plan,
             "validation plan was not reproduced from the sealed spec and bar count")
    identity = {
        "run_id": manifest["manifest_id"].removeprefix("mfst-"),
        "manifest_id": manifest["manifest_id"],
        "manifest_version": manifest["manifest_version"],
        "manifest_sha256": hashlib.sha256(_canonical(manifest)).hexdigest(),
        "ledger_index_sha256": hashlib.sha256(_canonical(ledger)).hexdigest(),
        "spec_hash": manifest["spec_hash"],
        "spec_version": manifest["spec_version"],
        "dsl_schema_version": manifest["dsl_schema_version"],
        "snapshot_id": manifest["snapshot_id"],
        "snapshot_sha256": manifest["snapshot_sha256"],
        "engine_semver": manifest["engine_semver"],
        "image_digest": manifest["image_digest"],
        "battery_config_hash": manifest["battery_config_hash"],
        "battery_profile": BATTERY_V2,
        "result_hash": manifest["result_hash"],
        "created_at": manifest["created_at"],
        "confirmation_receipt_hash": manifest["confirmation_receipt_hash"],
        "data_label": manifest["data_label"],
    }
    data_provenance = copy.deepcopy(payloads.get("data_provenance") or {
        "data_label": manifest["data_label"],
        "snapshot_id": manifest["snapshot_id"],
        "snapshot_sha256": manifest["snapshot_sha256"],
    })
    dev_segment = dict(partitions["development"])
    dev_segment["evaluation"] = {
        "start": development["equity_series"]["date"][0]
        if development["equity_series"]["date"] else dev_segment.get("start"),
        "end": development["equity_series"]["date"][-1]
        if development["equity_series"]["date"] else dev_segment.get("end"),
        "bars": len(development["equity_series"]["date"]),
    }
    final_segment = dict(partitions["final_holdout"])
    final_segment["evaluation"] = {
        "start": final["equity_series"]["date"][0]
        if final["equity_series"]["date"] else final_segment.get("start"),
        "end": final["equity_series"]["date"][-1]
        if final["equity_series"]["date"] else final_segment.get("end"),
        "bars": len(final["equity_series"]["date"]),
    }
    return {
        "evidence_view_version": "v2",
        "evidence_semantics_version": "v2",
        "identity": identity,
        "data_provenance": data_provenance,
        "artifacts": artifacts,
        "confirmation": {
            "receipt_id": receipt.get("receipt_id"),
            "restatement": receipt["restatement"],
            "restatement_hash": receipt["restatement_hash"],
            "spec_hash": receipt["spec_hash"],
            "battery_profile": receipt["battery_profile"],
            "battery_profile_hash": receipt["battery_profile_hash"],
            "issued_at": receipt.get("issued_at"),
        },
        "assumptions": {"spec": spec, "restatement": receipt["restatement"]},
        "status": {
            "battery_status": status,
            "evidence_complete": bool(evidence_status.get("evidence_complete")),
            "checks": [{"id": item["id"], "status": item["status"]}
                       for item in findings],
        },
        "validation_plan": copy.deepcopy(plan),
        "partitions": copy.deepcopy(partitions),
        "segments": {"is": dev_segment, "oos": final_segment},
        "results": {"is": copy.deepcopy(development), "oos": copy.deepcopy(final)},
        "development_result": copy.deepcopy(development),
        "final_holdout_result": copy.deepcopy(final),
        "walk_forward": copy.deepcopy(payloads["walk_forward"]),
        "regime_analysis": copy.deepcopy(payloads["regime_analysis"]),
        "oos_execution_audit": copy.deepcopy(final_audit),
        "final_holdout_execution_audit": copy.deepcopy(final_audit),
        "cost_stress": copy.deepcopy(payloads["cost_stress"]),
        "sensitivity": copy.deepcopy(sensitivity),
        "falsification": falsification,
        "temporal_integrity": copy.deepcopy(payloads["temporal_integrity"]),
        "data_gaps": copy.deepcopy(payloads["data_gaps"]),
        "snapshot": copy.deepcopy(payloads["snapshot_ref"]),
        "agent_projection": _agent_projection(payloads),
    }


def development_only_explanation(view: dict) -> dict:
    projection = copy.deepcopy(view["agent_projection"])
    return {
        "explanation_view_version": "v2-development-only",
        "status": "completed",
        "scope": "development_only",
        "generation": {
            "ai_used": False,
            "provider_invoked": False,
            "provider_data_transmitted": False,
            "ai_influenced_output": False,
            "provider": "deterministic-template",
            "fallback_used": False,
        },
        "explanation": {
            "title": "Development validation summary",
            "projection": projection,
            "disclosure": (
                "This explanation uses development evidence only. The final holdout is "
                "rendered separately by a deterministic server template."
            ),
        },
    }


__all__ = ["build_evidence_view_v2", "development_only_explanation"]
