"""Privacy-minimized Development facts projected from EvidenceViewV2.

This module never copies, walks, or serializes the source evidence object.  Every fact is
read from one reviewed development aggregate path and rebuilt under a closed vocabulary.
The opaque binding commits only to that rebuilt projection, not to run/dataset identity.
"""

from __future__ import annotations

import hashlib
import json
import math

from pydantic import ValidationError

from .research_contracts import (
    DevelopmentFactV1,
    DevelopmentProjectionV1,
    RESEARCH_PROJECTION_VERSION,
    ResearchCheckStatus,
    ResearchFactId,
    ResearchScope,
    ResearchUnit,
)


class ResearchProjectionError(ValueError):
    """Evidence cannot be represented by the closed Development projection."""


_Spec = tuple[ResearchUnit, int]
_FACT_SPECS: dict[ResearchFactId, _Spec] = {
    ResearchFactId.DEVELOPMENT_TOTAL_RETURN: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.DEVELOPMENT_CAGR: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.DEVELOPMENT_ANN_VOL: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.DEVELOPMENT_SHARPE: (ResearchUnit.RATIO, 2),
    ResearchFactId.DEVELOPMENT_MAX_DRAWDOWN: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.DEVELOPMENT_TRADE_COUNT: (ResearchUnit.COUNT, 0),
    ResearchFactId.DEVELOPMENT_TOTAL_COSTS: (ResearchUnit.USD, 2),
    ResearchFactId.DEVELOPMENT_EXPOSURE: (ResearchUnit.DECIMAL_FRACTION, 1),
    ResearchFactId.WALK_FORWARD_FOLD_COUNT: (ResearchUnit.COUNT, 0),
    ResearchFactId.WALK_FORWARD_MEDIAN_SHARPE: (ResearchUnit.RATIO, 2),
    ResearchFactId.WALK_FORWARD_POSITIVE_RATIO: (ResearchUnit.DECIMAL_FRACTION, 0),
    ResearchFactId.WALK_FORWARD_WORST_RETURN: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.WALK_FORWARD_RETURN_DISPERSION: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.COST_STRESS_BASE_RETURN: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.COST_STRESS_DOUBLE_RETURN: (ResearchUnit.DECIMAL_FRACTION, 2),
    ResearchFactId.COST_STRESS_BASE_COSTS: (ResearchUnit.USD, 2),
    ResearchFactId.COST_STRESS_DOUBLE_COSTS: (ResearchUnit.USD, 2),
    ResearchFactId.REGIME_UP_LOW_OBSERVATIONS: (ResearchUnit.COUNT, 0),
    ResearchFactId.REGIME_UP_LOW_STATUS: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.REGIME_UP_HIGH_OBSERVATIONS: (ResearchUnit.COUNT, 0),
    ResearchFactId.REGIME_UP_HIGH_STATUS: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.REGIME_DOWN_LOW_OBSERVATIONS: (ResearchUnit.COUNT, 0),
    ResearchFactId.REGIME_DOWN_LOW_STATUS: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.REGIME_DOWN_HIGH_OBSERVATIONS: (ResearchUnit.COUNT, 0),
    ResearchFactId.REGIME_DOWN_HIGH_STATUS: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.CHECK_WALK_FORWARD: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.CHECK_COST_FRAGILITY: (ResearchUnit.CHECK_STATUS, 0),
    ResearchFactId.CHECK_REGIME_COVERAGE: (ResearchUnit.CHECK_STATUS, 0),
}

_REGIME_FACTS = {
    "up_low": (
        ResearchFactId.REGIME_UP_LOW_OBSERVATIONS,
        ResearchFactId.REGIME_UP_LOW_STATUS,
    ),
    "up_high": (
        ResearchFactId.REGIME_UP_HIGH_OBSERVATIONS,
        ResearchFactId.REGIME_UP_HIGH_STATUS,
    ),
    "down_low": (
        ResearchFactId.REGIME_DOWN_LOW_OBSERVATIONS,
        ResearchFactId.REGIME_DOWN_LOW_STATUS,
    ),
    "down_high": (
        ResearchFactId.REGIME_DOWN_HIGH_OBSERVATIONS,
        ResearchFactId.REGIME_DOWN_HIGH_STATUS,
    ),
}

_CHECK_FACTS = {
    "walk_forward_stability": ResearchFactId.CHECK_WALK_FORWARD,
    "development_cost_fragility": ResearchFactId.CHECK_COST_FRAGILITY,
    "regime_coverage": ResearchFactId.CHECK_REGIME_COVERAGE,
}


def _fail(message: str) -> None:
    raise ResearchProjectionError(f"development projection: {message}")


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        _fail(f"{label} is unavailable")
    return value


def _status(value: object, label: str) -> ResearchCheckStatus:
    if type(value) is not str:  # reject String subclasses and coercion
        _fail(f"{label} is invalid")
    try:
        return ResearchCheckStatus(value)
    except ValueError:
        _fail(f"{label} is invalid")


def _numeric(value: object, fact_id: ResearchFactId) -> int | float:
    if isinstance(value, bool) or type(value) not in {int, float}:
        _fail(f"{fact_id.value} is not strict numeric evidence")
    if not math.isfinite(float(value)):
        _fail(f"{fact_id.value} is not finite")
    return value


def _validate_fact_value(
    fact_id: ResearchFactId, value: int | float | ResearchCheckStatus,
) -> None:
    unit, _precision = _FACT_SPECS[fact_id]
    if unit is ResearchUnit.CHECK_STATUS:
        if not isinstance(value, ResearchCheckStatus):
            _fail(f"{fact_id.value} has the wrong value type")
        return
    if isinstance(value, bool) or type(value) not in {int, float}:
        _fail(f"{fact_id.value} has the wrong value type")
    number = float(value)
    if not math.isfinite(number):
        _fail(f"{fact_id.value} is not finite")
    if unit is ResearchUnit.COUNT:
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            _fail(f"{fact_id.value} is outside the count boundary")
    elif unit is ResearchUnit.USD:
        if not 0 <= number <= 1_000_000_000_000_000:
            _fail(f"{fact_id.value} is outside the monetary boundary")
    elif unit is ResearchUnit.RATIO:
        if abs(number) > 1_000_000:
            _fail(f"{fact_id.value} is outside the ratio boundary")
    else:
        if fact_id in {
            ResearchFactId.DEVELOPMENT_EXPOSURE,
            ResearchFactId.WALK_FORWARD_POSITIVE_RATIO,
        } and not 0 <= number <= 1:
            _fail(f"{fact_id.value} is outside the unit interval")
        if fact_id is ResearchFactId.DEVELOPMENT_MAX_DRAWDOWN and \
                not -1 <= number <= 0:
            _fail(f"{fact_id.value} is outside the drawdown boundary")
        if fact_id in {
            ResearchFactId.DEVELOPMENT_ANN_VOL,
            ResearchFactId.WALK_FORWARD_RETURN_DISPERSION,
        } and not 0 <= number <= 1_000_000:
            _fail(f"{fact_id.value} is outside the dispersion boundary")
        if fact_id not in {
            ResearchFactId.DEVELOPMENT_EXPOSURE,
            ResearchFactId.WALK_FORWARD_POSITIVE_RATIO,
            ResearchFactId.DEVELOPMENT_MAX_DRAWDOWN,
            ResearchFactId.DEVELOPMENT_ANN_VOL,
            ResearchFactId.WALK_FORWARD_RETURN_DISPERSION,
        } and not -1 <= number <= 1_000_000:
            _fail(f"{fact_id.value} is outside the fraction boundary")


def _fact(
    fact_id: ResearchFactId, value: int | float | ResearchCheckStatus,
) -> DevelopmentFactV1:
    _validate_fact_value(fact_id, value)
    unit, precision = _FACT_SPECS[fact_id]
    return DevelopmentFactV1(
        fact_id=fact_id,
        value=value,
        unit=unit,
        display_precision=precision,
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ResearchProjectionError(
            "development projection: facts are not canonical JSON") from exc


def _binding_for(facts: list[DevelopmentFactV1]) -> str:
    body = {
        "projection_version": RESEARCH_PROJECTION_VERSION,
        "scope": ResearchScope.DEVELOPMENT_ONLY.value,
        "facts": [fact.model_dump(mode="json") for fact in facts],
    }
    return "dvb1-" + hashlib.sha256(_canonical(body)).hexdigest()


def validate_development_projection(projection: DevelopmentProjectionV1) -> None:
    """Verify fact membership, order, units, precision, values, and opaque binding."""

    facts = projection.facts
    expected_ids = list(_FACT_SPECS)
    actual_ids = [fact.fact_id for fact in facts]
    if actual_ids != expected_ids:
        _fail("fact membership or canonical order is invalid")
    for fact in facts:
        expected_unit, expected_precision = _FACT_SPECS[fact.fact_id]
        if fact.unit is not expected_unit or fact.display_precision != expected_precision:
            _fail(f"{fact.fact_id.value} display contract is invalid")
        _validate_fact_value(fact.fact_id, fact.value)
    if projection.opaque_development_binding != _binding_for(facts):
        _fail("opaque development binding is stale")


def build_development_projection(evidence_view: dict) -> DevelopmentProjectionV1:
    """Build the only object permitted to cross the Research Copilot boundary.

    Deliberately read individual reviewed fields.  Never copy or recursively inspect the
    evidence view, so forbidden siblings cannot become part of the provider request.
    """

    view = _object(evidence_view, "evidence view")
    if view.get("evidence_view_version") != "v2" or \
            view.get("evidence_semantics_version") != "v2":
        _fail("EvidenceViewV2 is required")
    status = _object(view.get("status"), "evidence status")
    # An INCONCLUSIVE development check is itself useful aggregate evidence and is
    # represented explicitly by CHECK_STATUS facts.  Reject a malformed completeness
    # flag, but do not erase an honest inconclusive result.
    if type(status.get("evidence_complete")) is not bool:
        _fail("development completeness status is invalid")
    sensitivity = _object(view.get("sensitivity"), "sensitivity declaration")
    if sensitivity.get("parameter_selection") != "forbidden" or \
            sensitivity.get("grid") != []:
        _fail("fixed-rule development declaration is invalid")

    development = _object(view.get("development_result"), "development result")
    if development.get("status") != "COMPLETE":
        _fail("development result is not complete")
    metrics = _object(development.get("strategy_metrics"), "development metrics")
    facts_by_id: dict[ResearchFactId, DevelopmentFactV1] = {}

    metric_map = {
        ResearchFactId.DEVELOPMENT_TOTAL_RETURN: "total_return",
        ResearchFactId.DEVELOPMENT_CAGR: "cagr",
        ResearchFactId.DEVELOPMENT_ANN_VOL: "ann_vol",
        ResearchFactId.DEVELOPMENT_SHARPE: "sharpe",
        ResearchFactId.DEVELOPMENT_MAX_DRAWDOWN: "max_drawdown",
        ResearchFactId.DEVELOPMENT_TRADE_COUNT: "n_trades",
        ResearchFactId.DEVELOPMENT_TOTAL_COSTS: "total_costs",
        ResearchFactId.DEVELOPMENT_EXPOSURE: "exposure",
    }
    for fact_id, key in metric_map.items():
        facts_by_id[fact_id] = _fact(fact_id, _numeric(metrics.get(key), fact_id))

    walk_forward = _object(view.get("walk_forward"), "walk-forward summary")
    if walk_forward.get("parameter_selection") != "forbidden":
        _fail("walk-forward parameter selection declaration is invalid")
    walk_map = {
        ResearchFactId.WALK_FORWARD_FOLD_COUNT: "fold_count",
        ResearchFactId.WALK_FORWARD_MEDIAN_SHARPE: "median_fold_sharpe",
        ResearchFactId.WALK_FORWARD_POSITIVE_RATIO: "positive_fold_ratio",
        ResearchFactId.WALK_FORWARD_WORST_RETURN: "worst_fold_return",
        ResearchFactId.WALK_FORWARD_RETURN_DISPERSION: "fold_return_dispersion",
    }
    for fact_id, key in walk_map.items():
        facts_by_id[fact_id] = _fact(
            fact_id, _numeric(walk_forward.get(key), fact_id))

    cost_stress = _object(view.get("cost_stress"), "development cost stress")
    if cost_stress.get("basis") != "development_walk_forward_only":
        _fail("cost stress is not development-only")
    rows = cost_stress.get("rows")
    if not isinstance(rows, list):
        _fail("cost-stress rows are unavailable")
    by_multiplier: dict[float, dict] = {}
    for row in rows:
        item = _object(row, "cost-stress row")
        multiplier = item.get("multiplier")
        if type(multiplier) not in {int, float} or isinstance(multiplier, bool):
            _fail("cost-stress multiplier is invalid")
        numeric_multiplier = float(multiplier)
        if not math.isfinite(numeric_multiplier) or not 0 <= numeric_multiplier <= 1_000:
            _fail("cost-stress multiplier is outside its boundary")
        if numeric_multiplier in by_multiplier:
            _fail("cost-stress multiplier is duplicated")
        by_multiplier[numeric_multiplier] = _object(
            item.get("development"), "cost-stress development aggregate")
    if not {1.0, 2.0} <= set(by_multiplier):
        _fail("base and doubled cost-stress aggregates are required")
    for multiplier, return_id, costs_id in (
        (1.0, ResearchFactId.COST_STRESS_BASE_RETURN,
         ResearchFactId.COST_STRESS_BASE_COSTS),
        (2.0, ResearchFactId.COST_STRESS_DOUBLE_RETURN,
         ResearchFactId.COST_STRESS_DOUBLE_COSTS),
    ):
        row = by_multiplier[multiplier]
        facts_by_id[return_id] = _fact(
            return_id, _numeric(row.get("total_return"), return_id))
        facts_by_id[costs_id] = _fact(
            costs_id, _numeric(row.get("total_costs"), costs_id))

    regime_analysis = _object(view.get("regime_analysis"), "regime analysis")
    states = regime_analysis.get("states")
    if not isinstance(states, list):
        _fail("regime states are unavailable")
    state_index: dict[str, dict] = {}
    for raw_state in states:
        state = _object(raw_state, "regime state")
        name = state.get("regime")
        if name not in _REGIME_FACTS or name in state_index:
            _fail("regime state membership is invalid")
        state_index[name] = state
    if set(state_index) != set(_REGIME_FACTS):
        _fail("all preregistered regime states are required")
    for name, (observations_id, status_id) in _REGIME_FACTS.items():
        state = state_index[name]
        facts_by_id[observations_id] = _fact(
            observations_id, _numeric(state.get("observations"), observations_id))
        facts_by_id[status_id] = _fact(
            status_id, _status(state.get("status"), status_id.value))

    falsification = _object(view.get("falsification"), "development checks")
    findings = falsification.get("findings")
    if not isinstance(findings, list):
        _fail("development check findings are unavailable")
    finding_index: dict[str, dict] = {}
    for raw_finding in findings:
        finding = _object(raw_finding, "development check")
        identifier = finding.get("id")
        if identifier in _CHECK_FACTS and identifier in finding_index:
            _fail("development check is duplicated")
        if identifier in _CHECK_FACTS:
            finding_index[identifier] = finding
    if set(finding_index) != set(_CHECK_FACTS):
        _fail("all required development checks are required")
    for identifier, fact_id in _CHECK_FACTS.items():
        facts_by_id[fact_id] = _fact(
            fact_id,
            _status(finding_index[identifier].get("status"), fact_id.value),
        )

    facts = [facts_by_id[fact_id] for fact_id in _FACT_SPECS]
    try:
        projection = DevelopmentProjectionV1(
            opaque_development_binding=_binding_for(facts),
            facts=facts,
        )
    except ValidationError as exc:
        raise ResearchProjectionError(
            "development projection: strict projection contract failed") from exc
    validate_development_projection(projection)
    return projection


__all__ = [
    "ResearchProjectionError",
    "build_development_projection",
    "validate_development_projection",
]
