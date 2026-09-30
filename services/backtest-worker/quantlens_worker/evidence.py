"""EvidenceViewV1 — the single integrity-checked projection shared by every surface.

Two layers gate every displayed value:

1. **Hash validity** — :func:`quantlens_worker.artifacts.load_presentation_artifacts`
   re-reads the checkpoint, rejects any byte-level mismatch or missing binding, and
   requires one exact frozen presentation contract.
2. **Semantic validity** (this module, ``EVIDENCE_SEMANTICS_VERSION``) — a hash-consistent
   ledger written by a broken or malicious producer must still satisfy the declared
   invariants: expected artifact kinds and findings, the exact registered cost
   multipliers, the complete sensitivity grid, aligned IS/OOS series and metrics, the
   declared benchmark identity, a sealed confirmation receipt that hashes to the
   manifest's receipt hash, and internally consistent statuses. The overall battery
   status is derived exactly once here, from the validated findings, and shared by the
   workspace and the printable report.

Any violation raises :class:`ArtifactIntegrityError`; presentation surfaces fail closed
rather than showing partial or contradictory values.
"""

from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path

from .artifacts import (
    ArtifactIntegrityError,
    _canonical,
    data_provenance_for_snapshot,
    load_presentation_artifacts,
)
from .config import BATTERY_CONFIG
from .evidence_v2 import build_evidence_view_v2

EVIDENCE_VIEW_VERSION = "v1"
EVIDENCE_SEMANTICS_VERSION = "v1"

# These bindings compare numbers which were either copied from the same deterministic
# result or recomputed from its sealed initial/final equity.  A tolerance at the scale of
# normal binary floating-point roundoff is appropriate; display-rounding-sized drift is
# not.  Keep both values explicit so changing the trust contract is a reviewed decision.
SEMANTIC_FLOAT_REL_TOL = 1e-12
SEMANTIC_FLOAT_ABS_TOL = 1e-12

# The only allowed check vocabulary anywhere in the product (06 §5.2): a check either
# passed, failed, could not be concluded, or was never run. Nothing else.
ALLOWED_CHECK_STATUSES = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})
NOT_RUN = "NOT RUN"
REQUIRED_CHECK_IDS = ("oos_decay", "cost_fragility", "parameter_fragility")

_STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "INCONCLUSIVE": "?"}


def _fail(message: str) -> None:
    raise ArtifactIntegrityError(f"evidence semantics ({EVIDENCE_SEMANTICS_VERSION}): {message}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_close(actual: object, expected: object, label: str) -> None:
    _require(_is_number(actual) and _is_number(expected),
             f"{label} is not a numeric claim")
    actual_number = float(actual)
    expected_number = float(expected)
    _require(math.isfinite(actual_number) and math.isfinite(expected_number),
             f"{label} is not finite")
    _require(
        math.isclose(
            actual_number,
            expected_number,
            rel_tol=SEMANTIC_FLOAT_REL_TOL,
            abs_tol=SEMANTIC_FLOAT_ABS_TOL,
        ),
        f"{label} contradicts its canonical source",
    )


def _semantic_values_match(actual: object, expected: object) -> bool:
    """Compare copied structured evidence with the same tight numeric tolerance."""
    if _is_number(actual) or _is_number(expected):
        if not (_is_number(actual) and _is_number(expected)):
            return False
        return math.isfinite(float(actual)) and math.isfinite(float(expected)) and math.isclose(
            float(actual),
            float(expected),
            rel_tol=SEMANTIC_FLOAT_REL_TOL,
            abs_tol=SEMANTIC_FLOAT_ABS_TOL,
        )
    if isinstance(actual, dict) or isinstance(expected, dict):
        if not (isinstance(actual, dict) and isinstance(expected, dict)):
            return False
        return actual.keys() == expected.keys() and all(
            _semantic_values_match(actual[key], expected[key]) for key in actual)
    if isinstance(actual, list) or isinstance(expected, list):
        if not (isinstance(actual, list) and isinstance(expected, list)):
            return False
        return len(actual) == len(expected) and all(
            _semantic_values_match(a, e) for a, e in zip(actual, expected)
        )
    return actual == expected


def _require_same_value(actual: object, expected: object, label: str) -> None:
    _require(_semantic_values_match(actual, expected),
             f"{label} contradicts its canonical source")


def _validate_metric_accounting(name: str, metrics: dict, equity: list) -> None:
    """Bind headline return claims back to the sealed equity path."""
    _require(isinstance(metrics, dict), f"{name}: metrics missing")
    _require(isinstance(equity, list) and equity,
             f"{name}: no equity path exists for metric accounting")
    _require(all(_is_number(value) and math.isfinite(float(value)) and float(value) > 0
                 for value in equity),
             f"{name}: equity path contains a non-finite or non-positive value")
    final_equity = equity[-1]
    _require_close(metrics.get("final_equity"), final_equity,
                   f"{name}.final_equity")
    initial_capital = metrics.get("initial_capital")
    _require(_is_number(initial_capital) and math.isfinite(float(initial_capital))
             and float(initial_capital) > 0,
             f"{name}.initial_capital is missing, non-finite, or non-positive")
    expected_return = float(final_equity) / float(initial_capital) - 1.0
    _require_close(metrics.get("total_return"), expected_return,
                   f"{name}.total_return")


def derive_battery_status(findings: list[dict]) -> str:
    """The one place the overall battery status is computed (P1-2)."""
    statuses = [str(f.get("status", "")).upper() for f in findings]
    if any(s == "FAIL" for s in statuses):
        return "FAIL"
    if any(s == "INCONCLUSIVE" for s in statuses):
        return "INCONCLUSIVE"
    return "PASS"


def _validate_series_alignment(name: str, segment: dict, result: dict) -> None:
    # Accounting covers the sealed post-warmup *evaluation* interval of the segment
    # (the battery seals warmup and evaluation sub-windows explicitly).
    evaluation = segment.get("evaluation")
    _require(isinstance(evaluation, dict),
             f"{name}: sealed segment declares no evaluation window")
    _require(segment.get("start") <= evaluation.get("start", "") and
             evaluation.get("end", "") <= segment.get("end"),
             f"{name}: evaluation window escapes the sealed segment bounds")
    series = result.get("equity_series")
    _require(isinstance(series, dict), f"{name}: equity series missing")
    dates = series.get("date")
    equity = series.get("equity")
    position = series.get("position")
    _require(isinstance(dates, list) and dates, f"{name}: equity series has no dates")
    _require(
        isinstance(equity, list) and len(equity) == len(dates),
        f"{name}: equity values are not aligned with dates")
    _require(
        isinstance(position, list) and len(position) == len(dates),
        f"{name}: position series is not aligned with dates")
    _require(all(dates[i] < dates[i + 1] for i in range(len(dates) - 1)),
             f"{name}: series dates are not strictly increasing")
    _require(evaluation.get("bars") == len(dates),
             f"{name}: sealed evaluation bar count does not match its series length")
    _require(dates[0] == evaluation.get("start") and dates[-1] == evaluation.get("end"),
             f"{name}: series boundaries do not match the sealed evaluation window")
    metrics = result.get("strategy_metrics")
    _require(isinstance(metrics, dict), f"{name}: strategy metrics missing")
    _require(metrics.get("n_bars") == len(dates),
             f"{name}: strategy metrics cover a different bar count than the series")
    capital = metrics.get("initial_capital")
    _require(isinstance(capital, (int, float)) and capital > 0,
             f"{name}: sealed initial capital is missing or non-positive")
    comparison = result.get("comparison_strategy_metrics")
    _require(isinstance(comparison, dict),
             f"{name}: benchmark-aligned comparison metrics missing")
    _validate_metric_accounting(f"{name}.strategy_metrics", metrics, equity)
    _validate_metric_accounting(
        f"{name}.comparison_strategy_metrics", comparison, equity)
    bench = result.get("benchmark_series")
    _require(isinstance(bench, dict), f"{name}: benchmark series missing")
    bench_dates = bench.get("date", [])
    bench_equity = bench.get("equity", [])
    _require(len(bench_dates) == len(bench_equity),
             f"{name}: benchmark series values are not aligned with dates")
    if bench_dates:
        _require(evaluation.get("start") <= bench_dates[0] and
                 bench_dates[-1] <= evaluation.get("end"),
                 f"{name}: benchmark series escapes the sealed evaluation window")
        benchmark_metrics = result.get("benchmark_metrics")
        _require(isinstance(benchmark_metrics, dict),
                 f"{name}: benchmark metrics missing")
        _require(benchmark_metrics.get("n_bars") == len(bench_dates),
                 f"{name}: benchmark metrics cover a different bar count than the series")
        _validate_metric_accounting(
            f"{name}.benchmark_metrics", benchmark_metrics, bench_equity)


def _row_at_multiplier(rows: list, multiplier: float) -> dict | None:
    return next(
        (row for row in rows
         if isinstance(row, dict)
         and _is_number(row.get("multiplier"))
         and math.isclose(float(row["multiplier"]), multiplier,
                          rel_tol=0.0, abs_tol=SEMANTIC_FLOAT_ABS_TOL)),
        None,
    )


def _validate_cost_stress_bindings(payloads: dict) -> None:
    """The base stress row is a projection of the one primary IS/OOS result."""
    stress = payloads["cost_stress"]
    rows = stress.get("rows", [])
    _require(isinstance(rows, list), "cost-stress rows are not a list")
    base_row = _row_at_multiplier(rows, 1.0)
    _require(isinstance(base_row, dict), "cost-stress has no canonical 1x row")

    for segment, result_name in (("is", "is_result"), ("oos", "oos_result")):
        row_metrics = base_row.get(segment)
        canonical = payloads[result_name].get("comparison_strategy_metrics")
        _require(isinstance(row_metrics, dict),
                 f"cost-stress 1x {segment.upper()} row is missing")
        _require(isinstance(canonical, dict),
                 f"cost-stress 1x {segment.upper()} canonical metrics are missing")
        for field in ("total_return", "sharpe", "total_costs"):
            _require_close(
                row_metrics.get(field),
                canonical.get(field),
                f"cost-stress 1x {segment.upper()}.{field}",
            )

    audit = payloads["oos_execution_audit"]
    primary_records = [
        record for record in audit.get("records", [])
        if isinstance(record, dict) and record.get("purpose") == "primary_evaluation"
    ]
    _require(len(primary_records) == 1,
             "cost-stress 1x row cannot bind to one primary OOS execution")
    _require(base_row.get("reused_primary_evaluation") is True,
             "cost-stress 1x row does not declare primary-result reuse")
    _require(base_row.get("oos_execution_id") == primary_records[0].get("execution_id"),
             "cost-stress 1x row is bound to a different OOS execution")
    _require(audit.get("base_1x_reused_for_cost_stress") is True,
             "OOS audit contradicts the required 1x primary-result reuse")


def _validate_sensitivity_bindings(payloads: dict) -> None:
    """Bind the selected grid claim to both the grid and canonical primary IS result."""
    sensitivity = payloads["sensitivity"]
    chosen_days = sensitivity.get("chosen_ma_days")
    chosen_cell = sensitivity.get("chosen_cell")
    grid = sensitivity.get("grid", [])
    _require(isinstance(chosen_cell, dict),
             "sensitivity chosen cell is missing")
    grid_cell = next(
        (cell for cell in grid
         if isinstance(cell, dict) and cell.get("ma_days") == chosen_days),
        None,
    )
    _require(isinstance(grid_cell, dict) and "skipped" not in grid_cell,
             "sensitivity grid has no valid chosen cell")
    _require_same_value(chosen_cell, grid_cell,
                        "sensitivity chosen cell/grid cell")

    primary = payloads["is_result"].get("strategy_metrics")
    _require(isinstance(primary, dict),
             "sensitivity canonical primary IS metrics are missing")
    for field in ("sharpe", "total_return", "max_drawdown", "n_trades", "exposure"):
        _require_close(chosen_cell.get(field), primary.get(field),
                       f"sensitivity chosen cell.{field}")

    segment = payloads["segments"]["is"]
    evaluation = segment.get("evaluation", {})
    _require_same_value(sensitivity.get("evaluation"), evaluation,
                        "sensitivity evaluation window")
    for cell_field, evaluation_field in (
        ("evaluation_start", "start"),
        ("evaluation_end", "end"),
        ("evaluation_bars", "bars"),
    ):
        _require_same_value(
            chosen_cell.get(cell_field),
            evaluation.get(evaluation_field),
            f"sensitivity chosen cell.{cell_field}",
        )
    _require_same_value(
        sensitivity.get("shared_warmup_bars"),
        segment.get("warmup", {}).get("bars"),
        "sensitivity shared warmup",
    )

    # Neighbor evidence must name the actual adjacent valid cells, not independently
    # editable copies with more favorable values.
    valid_cells = [cell for cell in grid
                   if isinstance(cell, dict) and "skipped" not in cell]
    ordered = sorted(valid_cells, key=lambda cell: cell.get("ma_days"))
    chosen_index = ordered.index(grid_cell)
    expected_neighbors = [
        ordered[index] for index in (chosen_index - 1, chosen_index + 1)
        if 0 <= index < len(ordered)
    ]
    _require_same_value(sensitivity.get("neighbors"), expected_neighbors,
                        "sensitivity neighbors")


def _finding_map(findings: list[dict]) -> dict[str, dict]:
    return {str(finding.get("id")): finding for finding in findings}


def _canonical_activity(metrics: dict) -> bool:
    n_trades = metrics.get("n_trades")
    exposure = metrics.get("exposure")
    _require(_is_number(n_trades) and _is_number(exposure),
             "canonical activity inputs are not numeric")
    return float(n_trades) > 0 and float(exposure) > 0


def _validate_oos_decay_finding(finding: dict, payloads: dict) -> None:
    evidence = finding["evidence"]
    is_metrics = payloads["is_result"]["strategy_metrics"]
    oos_metrics = payloads["oos_result"]["strategy_metrics"]
    bindings = {
        "is_sharpe": is_metrics.get("sharpe"),
        "oos_sharpe": oos_metrics.get("sharpe"),
        "is_total_return": is_metrics.get("total_return"),
        "oos_total_return": oos_metrics.get("total_return"),
    }
    for field, expected in bindings.items():
        _require_close(evidence.get(field), expected,
                       f"finding oos_decay evidence.{field}")
    is_activity = _canonical_activity(is_metrics)
    oos_activity = _canonical_activity(oos_metrics)
    _require(evidence.get("is_activity_available") is is_activity,
             "finding oos_decay evidence.is_activity_available contradicts canonical metrics")
    _require(evidence.get("oos_activity_available") is oos_activity,
             "finding oos_decay evidence.oos_activity_available contradicts canonical metrics")

    is_sharpe = float(is_metrics["sharpe"])
    oos_sharpe = float(oos_metrics["sharpe"])
    is_return = float(is_metrics["total_return"])
    oos_return = float(oos_metrics["total_return"])
    decay_fired = (
        is_sharpe > 0
        and oos_sharpe
        < BATTERY_CONFIG["oos_decay"]["sharpe_retention_min"] * is_sharpe
    ) or (is_return > 0 and oos_return < 0)
    expected_status = (
        "INCONCLUSIVE" if not is_activity else
        "FAIL" if decay_fired else
        "INCONCLUSIVE" if not oos_activity else
        "PASS"
    )
    _require(str(finding.get("status", "")).upper() == expected_status,
             "finding oos_decay status contradicts canonical result metrics")


def _validate_cost_fragility_finding(finding: dict, payloads: dict) -> None:
    evidence = finding["evidence"]
    rows = payloads["cost_stress"].get("rows", [])
    required_multiplier = float(BATTERY_CONFIG["cost_fragility"]["stress_multiplier"])
    base_row = _row_at_multiplier(rows, 1.0)
    stressed_row = _row_at_multiplier(rows, required_multiplier)
    base_return = base_row.get("oos", {}).get("total_return") if base_row else None
    stressed_return = stressed_row.get("oos", {}).get("total_return") \
        if stressed_row else None
    oos_activity = _canonical_activity(payloads["oos_result"]["strategy_metrics"])

    _require_same_value(evidence.get("base_oos_return"), base_return,
                        "finding cost_fragility evidence.base_oos_return")
    _require_same_value(evidence.get("stressed_oos_return"), stressed_return,
                        "finding cost_fragility evidence.stressed_oos_return")
    _require_close(evidence.get("required_multiplier"), required_multiplier,
                   "finding cost_fragility evidence.required_multiplier")
    _require(evidence.get("base_case_present") is (base_row is not None),
             "finding cost_fragility evidence.base_case_present contradicts cost stress")
    _require(evidence.get("required_stress_present") is (stressed_row is not None),
             "finding cost_fragility evidence.required_stress_present contradicts cost stress")
    _require(evidence.get("oos_activity_available") is oos_activity,
             "finding cost_fragility evidence.oos_activity_available contradicts canonical metrics")

    costs = payloads["spec"]["spec"]["costs"]
    no_effective_base_cost = (
        float(costs["commission_bps"]) + float(costs["slippage_bps"]) == 0.0
    )
    if base_row is None or stressed_row is None or not oos_activity \
            or no_effective_base_cost:
        expected_status = "INCONCLUSIVE"
    elif not (_is_number(base_return) and _is_number(stressed_return)) \
            or not (math.isfinite(float(base_return))
                    and math.isfinite(float(stressed_return))):
        expected_status = "INCONCLUSIVE"
    else:
        fired = float(stressed_return) < 0 or (
            float(base_return) > 0
            and float(stressed_return)
            < BATTERY_CONFIG["cost_fragility"]["return_retention_min"]
            * float(base_return)
        )
        expected_status = "FAIL" if fired else "PASS"
    _require(str(finding.get("status", "")).upper() == expected_status,
             "finding cost_fragility status contradicts canonical stress results")


def _validate_parameter_fragility_finding(finding: dict, payloads: dict) -> None:
    evidence = finding["evidence"]
    sensitivity = payloads["sensitivity"]
    chosen_cell = sensitivity.get("chosen_cell")
    neighbors = sensitivity.get("neighbors")
    _require_same_value(evidence.get("chosen_cell"), chosen_cell,
                        "finding parameter_fragility evidence.chosen_cell")
    _require_same_value(evidence.get("neighbors"), neighbors,
                        "finding parameter_fragility evidence.neighbors")
    reference = chosen_cell.get("sharpe") if isinstance(chosen_cell, dict) else None
    _require_same_value(evidence.get("reference_sharpe"), reference,
                        "finding parameter_fragility evidence.reference_sharpe")

    expected_worst = None
    if chosen_cell is None or not neighbors or not _is_number(reference) \
            or not math.isfinite(float(reference)) or float(reference) == 0:
        expected_status = "INCONCLUSIVE"
    elif any(not _is_number(neighbor.get("sharpe"))
             or not math.isfinite(float(neighbor["sharpe"]))
             for neighbor in neighbors):
        expected_status = "INCONCLUSIVE"
    else:
        fired = False
        for neighbor in neighbors:
            neighbor_sharpe = float(neighbor["sharpe"])
            loss = math.inf if float(reference) > 0 and neighbor_sharpe <= 0 else (
                (float(reference) - neighbor_sharpe) / abs(float(reference))
            )
            if loss >= BATTERY_CONFIG["parameter_fragility"]["neighbor_loss_max"]:
                fired = True
                if expected_worst is None or neighbor_sharpe < float(expected_worst["sharpe"]):
                    expected_worst = neighbor
        expected_status = "FAIL" if fired else "PASS"
    _require_same_value(evidence.get("worst_neighbor"), expected_worst,
                        "finding parameter_fragility evidence.worst_neighbor")
    _require(str(finding.get("status", "")).upper() == expected_status,
             "finding parameter_fragility status contradicts canonical sensitivity grid")


def _validate_falsification_bindings(findings: list[dict], payloads: dict) -> None:
    finding_by_id = _finding_map(findings)
    validators = {
        "oos_decay": _validate_oos_decay_finding,
        "cost_fragility": _validate_cost_fragility_finding,
        "parameter_fragility": _validate_parameter_fragility_finding,
    }
    config_keys = {
        "oos_decay": "oos_decay",
        "cost_fragility": "cost_fragility",
        "parameter_fragility": "parameter_fragility",
    }
    for finding_id, validator in validators.items():
        finding = finding_by_id[finding_id]
        _require(
            finding.get("rule") == BATTERY_CONFIG[config_keys[finding_id]]["description"],
            f"finding {finding_id} rule text contradicts the sealed battery configuration",
        )
        validator(finding, payloads)


def validate_evidence_semantics(manifest: dict, ledger: dict, payloads: dict,
                                receipt: dict) -> str:
    """Check every declared invariant; return the derived overall battery status."""
    spec = payloads["spec"]["spec"]

    # --- versioned source -> provenance -> Run Manifest binding (Gate 4) ----
    if spec.get("dsl_version") in {"1.1", "1.2"}:
        licensed = spec.get("dsl_version") == "1.2"
        expected_manifest = "v2" if licensed else "v1"
        expected_label = "LICENSED_PROVIDER" if licensed else "USER_UPLOADED"
        _require(manifest.get("manifest_version") == expected_manifest and
                 manifest.get("data_label") == expected_label,
                 f"DSL {spec.get('dsl_version')} is not sealed by a {expected_label} "
                 f"Run Manifest {expected_manifest}")
        try:
            expected_provenance = data_provenance_for_snapshot(
                spec, payloads["snapshot_ref"], actor_id=manifest.get("actor_id"))
        except (ArtifactIntegrityError, KeyError) as exc:
            _fail(f"user-data provenance is invalid: {exc}")
        _require(payloads.get("data_provenance") == expected_provenance,
                 "data_provenance does not match the sealed snapshot and confirmed source")
        _require(manifest.get("dataset_id") == expected_provenance["dataset_id"] and
                 manifest.get("dataset_manifest_sha256") ==
                 expected_provenance["dataset_manifest_sha256"],
                 f"Run Manifest {expected_manifest} is not bound to the same dataset "
                 "as the evidence")
        if licensed:
            _require(
                manifest.get("provider_id") == expected_provenance["provider_id"]
                and manifest.get("instrument_id")
                == expected_provenance["instrument_id"]
                and manifest.get("rights_policy_sha256")
                == expected_provenance["rights_policy_sha256"],
                "Run Manifest v2 is not bound to licensed identity and rights",
            )
    else:
        _require(manifest.get("manifest_version") == "v0" and
                 manifest.get("data_label") == "SYNTHETIC",
                 "DSL 1.0 is not sealed by a SYNTHETIC Run Manifest v0")

    # --- confirmation receipt binds to the manifest (P1-3) -----------------
    _require(isinstance(receipt, dict), "confirmation receipt is missing")
    receipt_text = receipt.get("restatement")
    _require(isinstance(receipt_text, str) and bool(receipt_text.strip()),
             "confirmation receipt text is empty")
    text_hash = hashlib.sha256(receipt_text.encode("utf-8")).hexdigest()
    _require(text_hash == receipt.get("restatement_hash"),
             "confirmation receipt text does not hash to its recorded receipt hash")
    _require(manifest.get("confirmation_receipt_hash") == text_hash,
             "confirmation receipt does not match the hash sealed in the manifest")
    _require(receipt.get("spec_hash") == manifest.get("spec_hash"),
             "confirmation receipt was issued for a different spec")

    # --- registered cost-stress multipliers, exactly (P1-2) ----------------
    declared = sorted(float(m) for m in spec["validation"]["cost_stress"]["multipliers"])
    stress = payloads["cost_stress"]
    sealed_multipliers = [float(m) for m in stress.get("multipliers", [])]
    _require(sealed_multipliers == declared,
             "sealed cost-stress multipliers differ from the registered spec multipliers")
    row_multipliers = [float(r.get("multiplier")) for r in stress.get("rows", [])]
    _require(row_multipliers == declared,
             "cost-stress rows do not cover every registered multiplier exactly once")
    _require(bool(stress.get("required_2x_present")) == (2.0 in declared),
             "required_2x_present flag contradicts the registered multipliers")

    # --- complete sensitivity grid (P1-2) ----------------------------------
    sensitivity = payloads["sensitivity"]
    declared_grid = sorted(spec["validation"]["sensitivity"]["grid"]["ma_days"])
    sealed_grid = [c.get("ma_days") for c in sensitivity.get("grid", [])]
    _require(sealed_grid == declared_grid,
             "sealed sensitivity grid does not cover the declared grid exactly")
    _require(sensitivity.get("chosen_ma_days") == spec["rule"]["ma_days"],
             "sensitivity chosen cell does not match the confirmed rule window")
    _require(sensitivity.get("basis") == "in_sample_only",
             "sensitivity sweep basis is not in_sample_only")

    # --- segments and series alignment (P1-2) ------------------------------
    segments = payloads["segments"]
    _require(set(segments) >= {"is", "oos"}, "sealed segments are incomplete")
    _require(segments["is"]["end"] < segments["oos"]["start"],
             "in-sample and out-of-sample segments overlap or are unordered")
    _validate_series_alignment("in-sample", segments["is"], payloads["is_result"])
    _validate_series_alignment("out-of-sample", segments["oos"], payloads["oos_result"])

    # --- cross-artifact numeric trust roots -------------------------------
    # Hash-consistent artifacts can still disagree semantically.  Bind duplicated
    # headline facts back to the one primary result that produced them.
    _validate_sensitivity_bindings(payloads)
    _validate_cost_stress_bindings(payloads)

    # --- benchmark identity (P1-2/P1-6) ------------------------------------
    expected_benchmark = spec["universe"]["symbol"] \
        if spec["benchmark"]["symbol"] == "same_as_universe" else spec["benchmark"]["symbol"]
    for name in ("is_result", "oos_result"):
        _require(payloads[name].get("benchmark_symbol") == expected_benchmark,
                 f"{name}: sealed benchmark symbol differs from the confirmed benchmark")

    # --- findings and status consistency (P1-2) -----------------------------
    falsification = payloads["falsification"]
    _require(falsification.get("non_suppressible") is True,
             "falsification section is not marked non-suppressible")
    _require(falsification.get("battery_version") == BATTERY_CONFIG["battery_version"],
             "falsification battery version contradicts the sealed configuration")
    findings = falsification.get("findings", [])
    finding_ids = [f.get("id") for f in findings]
    _require(finding_ids == list(REQUIRED_CHECK_IDS),
             "falsification findings do not cover the required checks exactly")
    _require(list(falsification.get("required_checks", [])) == list(REQUIRED_CHECK_IDS),
             "sealed required_checks list is not the declared battery")
    _require(list(falsification.get("checks_run", [])) == finding_ids,
             "checks_run does not match the reported findings")
    for finding in findings:
        status = str(finding.get("status", "")).upper()
        _require(status in ALLOWED_CHECK_STATUSES,
                 f"finding {finding.get('id')} carries unknown status {status!r}")
        _require(isinstance(finding.get("evidence"), dict),
                 f"finding {finding.get('id')} has no structured evidence")

    _validate_falsification_bindings(findings, payloads)

    derived = derive_battery_status(findings)
    inconclusive_ids = [f["id"] for f in findings
                        if str(f.get("status")).upper() == "INCONCLUSIVE"]
    any_failing = any(str(f.get("status")).upper() == "FAIL" for f in findings)

    _require(str(falsification.get("status", "")).upper() == derived,
             "falsification.status contradicts the statuses of its own findings")
    _require(bool(falsification.get("any_failing")) == any_failing,
             "any_failing flag contradicts the findings")
    _require(bool(falsification.get("any_inconclusive")) == bool(inconclusive_ids),
             "any_inconclusive flag contradicts the findings")
    completeness = falsification.get("completeness", {})
    _require(completeness.get("all_required_reported") is True,
             "completeness claims required checks are missing")
    _require(sorted(completeness.get("unavailable_checks", [])) == sorted(inconclusive_ids),
             "completeness unavailable_checks contradicts the findings")
    expected_complete = not inconclusive_ids
    _require(bool(completeness.get("evidence_complete")) == expected_complete,
             "completeness evidence_complete contradicts the findings")
    _require(bool(completeness.get("all_checks_conclusive")) == expected_complete,
             "completeness all_checks_conclusive contradicts the findings")

    evidence_status = payloads["evidence_status"]
    _require(str(evidence_status.get("battery_status", "")).upper() == derived,
             "evidence_status.battery_status contradicts the validated findings")
    _require(bool(evidence_status.get("evidence_complete")) == expected_complete,
             "evidence_status.evidence_complete contradicts the validated findings")

    # --- OOS execution audit (P1-3 honesty) ---------------------------------
    audit = payloads["oos_execution_audit"]
    _require(audit.get("primary_evaluation_count") == 1,
             "the audit does not prove exactly one primary OOS evaluation")
    records = audit.get("records", [])
    primary_records = [r for r in records if r.get("purpose") == "primary_evaluation"]
    _require(len(primary_records) == 1,
             "audit records do not contain exactly one primary evaluation")
    _require(audit.get("count") == len(records),
             "audit count does not match its own records")
    _require(audit.get("count") ==
             1 + int(audit.get("cost_stress_execution_count", -1)),
             "audit counts are internally inconsistent")

    return derived


def _presented_findings(falsification: dict) -> list[dict]:
    findings = []
    for finding in falsification.get("findings", []):
        status = str(finding.get("status", "INCONCLUSIVE")).upper()
        presented = copy.deepcopy(finding)
        presented["status"] = status
        presented["status_label"] = status
        presented["status_css"] = status.lower()
        presented["status_icon"] = _STATUS_ICON[status]
        findings.append(presented)
    return findings


def build_evidence_view(manifest: dict, ledger: dict, payloads: dict,
                        receipt: dict) -> dict:
    """Project hash-valid payloads into EvidenceViewV1 after semantic validation."""
    if isinstance(payloads.get("validation_plan"), dict):
        return build_evidence_view_v2(manifest, ledger, payloads, receipt)
    derived_status = validate_evidence_semantics(manifest, ledger, payloads, receipt)

    falsification = copy.deepcopy(payloads["falsification"])
    falsification["findings"] = _presented_findings(payloads["falsification"])

    spec = payloads["spec"]["spec"]
    artifacts = [
        {"artifact_id": e["artifact_id"], "kind": e["kind"], "sha256": e["sha256"]}
        for e in ledger["entries"]
    ]

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
        "result_hash": manifest["result_hash"],
        "created_at": manifest["created_at"],
        "confirmation_receipt_hash": manifest["confirmation_receipt_hash"],
        "data_label": manifest["data_label"],
    }
    if manifest["manifest_version"] in {"v1", "v2"}:
        identity.update({
            "dataset_id": manifest["dataset_id"],
            "dataset_manifest_sha256": manifest["dataset_manifest_sha256"],
        })
        if manifest["manifest_version"] == "v2":
            identity.update({
                "dataset_manifest_version": manifest["dataset_manifest_version"],
                "provider_id": manifest["provider_id"],
                "instrument_id": manifest["instrument_id"],
                "rights_policy_sha256": manifest["rights_policy_sha256"],
            })
        data_provenance = copy.deepcopy(payloads["data_provenance"])
        source_snapshot = payloads["snapshot_ref"]
        # Presentation receives only safe snapshot semantics.  The full sealed snapshot
        # still lives in the hash-checked ledger, but owner/mapping/file details do not.
        presented_snapshot = {
            key: copy.deepcopy(source_snapshot[key])
            for key in (
                "label", "description", "snapshot_id", "sha256", "calendar",
                "coverage", "adjustment_convention", "execution",
            ) if key in source_snapshot
        }
    else:
        data_provenance = {
            "data_label": "SYNTHETIC",
            "snapshot_id": manifest["snapshot_id"],
            "snapshot_sha256": manifest["snapshot_sha256"],
        }
        presented_snapshot = payloads["snapshot_ref"]

    return {
        "evidence_view_version": EVIDENCE_VIEW_VERSION,
        "evidence_semantics_version": EVIDENCE_SEMANTICS_VERSION,
        "identity": identity,
        "data_provenance": data_provenance,
        "artifacts": artifacts,
        "confirmation": {
            "receipt_id": receipt.get("receipt_id"),
            "restatement": receipt["restatement"],
            "restatement_hash": receipt["restatement_hash"],
            "spec_hash": receipt["spec_hash"],
            "issued_at": receipt.get("issued_at"),
        },
        "assumptions": {
            "spec": spec,
            # The exact sealed receipt the user confirmed — never re-generated prose.
            "restatement": receipt["restatement"],
            "execution": {
                "frequency": spec["calendar"]["frequency"],
                "convention": "Decide at each bar's close; fill at the next bar's open. "
                              "Long/flat, full notional, fractional shares; itemized "
                              "commission and slippage on every fill's notional.",
                "benchmark_rule": "Buy-and-hold from the strategy's first tradable "
                                  "decision, paying the same entry cost model.",
            },
        },
        "status": {
            "battery_status": derived_status,
            "evidence_complete": bool(
                payloads["falsification"]["completeness"]["evidence_complete"]),
            "checks": [
                {"id": f["id"], "status": f["status"]} for f in falsification["findings"]
            ],
        },
        "segments": payloads["segments"],
        "results": {"is": payloads["is_result"], "oos": payloads["oos_result"]},
        "oos_execution_audit": payloads["oos_execution_audit"],
        "cost_stress": payloads["cost_stress"],
        "sensitivity": payloads["sensitivity"],
        "falsification": falsification,
        "data_gaps": payloads["data_gaps"],
        "snapshot": presented_snapshot,
    }


def load_verified_evidence(run_dir: Path, *, expected_run: dict) -> dict:
    """Re-read, hash-check, semantically validate, and project one sealed run.

    Fails closed (:class:`ArtifactIntegrityError`) on any byte-level or semantic
    mismatch, including a control-plane receipt that no longer hashes to the sealed
    ``confirmation_receipt_hash``.
    """
    manifest, ledger, payloads, contract = load_presentation_artifacts(
        run_dir, expected_run=expected_run,
    )
    view = build_evidence_view(
        manifest, ledger, payloads, receipt=expected_run["confirmation_receipt"],
    )
    # This additive descriptor is outside the immutable financial payload and does not
    # alter any historical artifact or result hash.  It prevents displayable legacy
    # evidence from being mistaken for the future corrected financial contract.
    view["artifact_contract"] = contract.public_descriptor()
    return view
