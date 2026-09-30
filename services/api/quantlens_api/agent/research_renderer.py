"""Validation, deterministic rendering, and complete-output guard for ResearchPlanV1."""

from __future__ import annotations

import copy
import re
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN

from .research_contracts import (
    DevelopmentFactV1,
    DevelopmentProjectionV1,
    RESEARCH_PLAN_VERSION,
    ResearchActionId,
    ResearchCheckStatus,
    ResearchComparator,
    ResearchFactId,
    ResearchFollowUpV1,
    ResearchPlanItem,
    ResearchPlanV1,
    ResearchTemplateId,
    ResearchUnit,
)
from .research_projection import validate_development_projection


class ResearchGuardError(ValueError):
    """A provider plan or rendered Research Copilot view failed closed."""


_TEMPLATE_RULES: dict[
    ResearchTemplateId, tuple[tuple[ResearchFactId, ...], ResearchComparator]
] = {
    ResearchTemplateId.DEVELOPMENT_RISK_RETURN: (
        (
            ResearchFactId.DEVELOPMENT_TOTAL_RETURN,
            ResearchFactId.DEVELOPMENT_SHARPE,
            ResearchFactId.DEVELOPMENT_MAX_DRAWDOWN,
        ),
        ResearchComparator.RISK_RETURN_CONTEXT,
    ),
    ResearchTemplateId.WALK_FORWARD_STABILITY: (
        (
            ResearchFactId.WALK_FORWARD_POSITIVE_RATIO,
            ResearchFactId.WALK_FORWARD_MEDIAN_SHARPE,
            ResearchFactId.WALK_FORWARD_WORST_RETURN,
            ResearchFactId.WALK_FORWARD_FOLD_COUNT,
        ),
        ResearchComparator.STABILITY_CONTEXT,
    ),
    ResearchTemplateId.COST_STRESS_RESILIENCE: (
        (
            ResearchFactId.COST_STRESS_BASE_RETURN,
            ResearchFactId.COST_STRESS_BASE_COSTS,
            ResearchFactId.COST_STRESS_DOUBLE_RETURN,
            ResearchFactId.COST_STRESS_DOUBLE_COSTS,
        ),
        ResearchComparator.BASE_VS_STRESSED,
    ),
    ResearchTemplateId.REGIME_COVERAGE: (
        (
            ResearchFactId.REGIME_UP_LOW_OBSERVATIONS,
            ResearchFactId.REGIME_UP_LOW_STATUS,
            ResearchFactId.REGIME_UP_HIGH_OBSERVATIONS,
            ResearchFactId.REGIME_UP_HIGH_STATUS,
            ResearchFactId.REGIME_DOWN_LOW_OBSERVATIONS,
            ResearchFactId.REGIME_DOWN_LOW_STATUS,
            ResearchFactId.REGIME_DOWN_HIGH_OBSERVATIONS,
            ResearchFactId.REGIME_DOWN_HIGH_STATUS,
        ),
        ResearchComparator.COVERAGE_CONTEXT,
    ),
    ResearchTemplateId.VALIDATION_CHECKS: (
        (
            ResearchFactId.CHECK_WALK_FORWARD,
            ResearchFactId.CHECK_COST_FRAGILITY,
            ResearchFactId.CHECK_REGIME_COVERAGE,
        ),
        ResearchComparator.STATUS_ONLY,
    ),
}

_ACTION_RULES: dict[
    ResearchActionId, tuple[ResearchTemplateId, tuple[ResearchFactId, ...]]
] = {
    ResearchActionId.REVIEW_WALK_FORWARD: (
        ResearchTemplateId.WALK_FORWARD_STABILITY,
        _TEMPLATE_RULES[ResearchTemplateId.WALK_FORWARD_STABILITY][0],
    ),
    ResearchActionId.REVIEW_COST_STRESS: (
        ResearchTemplateId.COST_STRESS_RESILIENCE,
        _TEMPLATE_RULES[ResearchTemplateId.COST_STRESS_RESILIENCE][0],
    ),
    ResearchActionId.REVIEW_REGIME_COVERAGE: (
        ResearchTemplateId.REGIME_COVERAGE,
        _TEMPLATE_RULES[ResearchTemplateId.REGIME_COVERAGE][0],
    ),
}

_BIDI_CLASSES = frozenset({"R", "AL", "RLE", "RLO", "RLI", "LRE", "LRO", "LRI", "FSI", "PDI"})
_ADVICE_RE = re.compile(
    r"(?:\b(?:buy|sell|trade|invest|allocate|recommend|guarantee|guaranteed)\b|"
    r"\byou\s+should\b|\bbest\s+(?:stock|etf|investment)\b)",
    re.IGNORECASE,
)

_DISCLOSURE = (
    "Development evidence only. Final-holdout evidence is not available to this "
    "Research Copilot. The summary describes sealed research measurements and does "
    "not direct a financial action."
)


def _fail(message: str) -> None:
    raise ResearchGuardError(f"research guard: {message}")


def validate_provider_payload_safety(raw: object) -> None:
    """Reject Unicode/Bidi tricks, advice prose, arbitrary numbers, and payload bombs.

    ResearchPlanV1 has no numeric provider-owned fields.  All values/numbers displayed to
    users come later from the trusted Development projection.
    """

    node_count = 0

    def visit(value: object, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > 512 or depth > 16:
            _fail("provider payload exceeds structural limits")
        if isinstance(value, str):
            if len(value) > 256:
                _fail("provider string exceeds its boundary")
            if any(
                ord(char) > 127
                or unicodedata.category(char) in {"Cc", "Cf"}
                or unicodedata.bidirectional(char) in _BIDI_CLASSES
                for char in value
            ) or unicodedata.normalize("NFKC", value) != value:
                _fail("provider payload contains Unicode or direction controls")
            if _ADVICE_RE.search(value):
                _fail("provider payload contains advisory language")
            return
        if type(value) in {int, float} or isinstance(value, bool):
            _fail("provider payload contains a provider-owned scalar")
        if value is None:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    _fail("provider payload contains a non-string key")
                visit(key, depth + 1)
                visit(item, depth + 1)
            return
        _fail("provider payload contains an unsupported value type")

    visit(raw, 0)


def _fact_index(projection: DevelopmentProjectionV1) -> dict[ResearchFactId, DevelopmentFactV1]:
    validate_development_projection(projection)
    return {fact.fact_id: fact for fact in projection.facts}


def validate_research_plan(
    plan: ResearchPlanV1, projection: DevelopmentProjectionV1,
) -> None:
    """Validate the complete provider plan against server-owned signatures."""

    index = _fact_index(projection)
    if plan.opaque_development_binding != projection.opaque_development_binding:
        _fail("plan carries a stale development binding")
    seen: set[ResearchTemplateId] = set()
    for item in plan.items:
        if item.template_id in seen:
            _fail("plan repeats a template")
        seen.add(item.template_id)
        rule = _TEMPLATE_RULES.get(item.template_id)
        if rule is None:
            _fail("plan selected an unknown template")
        expected_facts, expected_comparator = rule
        if tuple(item.fact_ids) != expected_facts:
            _fail("plan fact membership or order is invalid")
        if item.comparator is not expected_comparator:
            _fail("plan comparator is invalid")
        if any(fact_id not in index for fact_id in item.fact_ids):
            _fail("plan selected an unknown fact")
    if plan.follow_up is not None:
        action_rule = _ACTION_RULES.get(plan.follow_up.action_id)
        if action_rule is None:
            _fail("plan selected an unknown follow-up action")
        required_template, supporting_facts = action_rule
        if required_template not in seen:
            _fail("follow-up action lacks its supporting template")
        if tuple(plan.follow_up.supporting_fact_ids) != supporting_facts:
            _fail("follow-up supporting facts are invalid")
        if any(fact_id not in index for fact_id in supporting_facts):
            _fail("follow-up selected an unknown fact")


def canonical_research_plan(projection: DevelopmentProjectionV1) -> ResearchPlanV1:
    """Return the complete deterministic fallback plan."""

    index = _fact_index(projection)
    check_cost = index[ResearchFactId.CHECK_COST_FRAGILITY].value
    check_walk = index[ResearchFactId.CHECK_WALK_FORWARD].value
    check_regime = index[ResearchFactId.CHECK_REGIME_COVERAGE].value
    if check_cost is not ResearchCheckStatus.PASS:
        action_id = ResearchActionId.REVIEW_COST_STRESS
    elif check_walk is not ResearchCheckStatus.PASS:
        action_id = ResearchActionId.REVIEW_WALK_FORWARD
    elif check_regime is not ResearchCheckStatus.PASS:
        action_id = ResearchActionId.REVIEW_REGIME_COVERAGE
    else:
        action_id = ResearchActionId.REVIEW_WALK_FORWARD
    _action_template, action_facts = _ACTION_RULES[action_id]
    plan = ResearchPlanV1(
        opaque_development_binding=projection.opaque_development_binding,
        items=[
            ResearchPlanItem(
                template_id=template_id,
                fact_ids=list(facts),
                comparator=comparator,
            )
            for template_id, (facts, comparator) in _TEMPLATE_RULES.items()
        ],
        follow_up=ResearchFollowUpV1(
            action_id=action_id,
            supporting_fact_ids=list(action_facts),
        ),
    )
    validate_research_plan(plan, projection)
    return plan


def _decimal(value: int | float) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ResearchGuardError("research guard: fact is not decimal-safe") from exc
    if not number.is_finite():
        _fail("fact is not finite")
    return number


def _format_fact(fact: DevelopmentFactV1) -> str:
    if fact.unit is ResearchUnit.CHECK_STATUS:
        if not isinstance(fact.value, ResearchCheckStatus):
            _fail("status fact is invalid")
        return fact.value.value.title()
    if isinstance(fact.value, ResearchCheckStatus):
        _fail("numeric fact contains a status")
    precision = fact.display_precision
    quantum = Decimal(1).scaleb(-precision)
    value = _decimal(fact.value)
    if fact.unit is ResearchUnit.DECIMAL_FRACTION:
        return f"{(value * 100).quantize(quantum, rounding=ROUND_HALF_EVEN):.{precision}f}%"
    if fact.unit is ResearchUnit.RATIO:
        return f"{value.quantize(quantum, rounding=ROUND_HALF_EVEN):.{precision}f}"
    if fact.unit is ResearchUnit.COUNT:
        return f"{int(value):,}"
    if fact.unit is ResearchUnit.USD:
        return f"${value.quantize(quantum, rounding=ROUND_HALF_EVEN):,.{precision}f}"
    _fail("fact unit is unsupported")


def _citation(fact: DevelopmentFactV1) -> dict:
    return {
        "fact_id": fact.fact_id.value,
        "value": fact.value.value
        if isinstance(fact.value, ResearchCheckStatus) else fact.value,
        "formatted_value": _format_fact(fact),
        "unit": fact.unit.value,
        "display_precision": fact.display_precision,
    }


def _block_text(
    template_id: ResearchTemplateId, facts: list[DevelopmentFactV1],
) -> str:
    values = [_format_fact(fact) for fact in facts]
    if template_id is ResearchTemplateId.DEVELOPMENT_RISK_RETURN:
        return (
            f"Development price return was {values[0]}, annualized Sharpe was "
            f"{values[1]}, and maximum drawdown was {values[2]}."
        )
    if template_id is ResearchTemplateId.WALK_FORWARD_STABILITY:
        return (
            f"Positive development folds represented {values[0]}; median fold Sharpe "
            f"was {values[1]}, the worst fold return was {values[2]}, and the fixed rule "
            f"was evaluated across {values[3]} folds."
        )
    if template_id is ResearchTemplateId.COST_STRESS_RESILIENCE:
        return (
            f"At base development costs, price return was {values[0]} and modeled "
            f"costs were {values[1]}; under the preregistered doubled-cost stress, "
            f"price return was {values[2]} and modeled costs were {values[3]}."
        )
    if template_id is ResearchTemplateId.REGIME_COVERAGE:
        labels = ("up/low-volatility", "up/high-volatility",
                  "down/low-volatility", "down/high-volatility")
        pairs = [
            f"{label}: {values[index]} observations ({values[index + 1]})"
            for label, index in zip(labels, range(0, 8, 2), strict=True)
        ]
        return "Preregistered development regime coverage was " + "; ".join(pairs) + "."
    if template_id is ResearchTemplateId.VALIDATION_CHECKS:
        return (
            f"Development checks reported walk-forward stability {values[0]}, cost "
            f"fragility {values[1]}, and regime coverage {values[2]}."
        )
    _fail("template is unsupported")


_ACTION_COPY = {
    ResearchActionId.REVIEW_WALK_FORWARD: (
        "Review walk-forward evidence",
        "Open the aggregate fold-evidence review after confirmation. This action does "
        "not launch a run or change a parameter.",
    ),
    ResearchActionId.REVIEW_COST_STRESS: (
        "Review development cost stress",
        "Open the base-versus-stressed development evidence after confirmation. This "
        "action does not launch a run or change a parameter.",
    ),
    ResearchActionId.REVIEW_REGIME_COVERAGE: (
        "Review regime coverage",
        "Open the preregistered development coverage review after confirmation. This "
        "action does not launch a run or change a parameter.",
    ),
}


def render_research_plan(
    plan: ResearchPlanV1, projection: DevelopmentProjectionV1,
) -> dict:
    """Render only server-owned copy with values from the validated projection."""

    validate_research_plan(plan, projection)
    index = _fact_index(projection)
    blocks = []
    for item in plan.items:
        facts = [index[fact_id] for fact_id in item.fact_ids]
        blocks.append({
            "template_id": item.template_id.value,
            "comparator": item.comparator.value,
            "fact_ids": [fact_id.value for fact_id in item.fact_ids],
            "text": _block_text(item.template_id, facts),
            "citations": [_citation(fact) for fact in facts],
        })
    pending_action = None
    if plan.follow_up is not None:
        label, description = _ACTION_COPY[plan.follow_up.action_id]
        pending_action = {
            "action_id": plan.follow_up.action_id.value,
            "status": "confirmation_required",
            "execution_state": "not_started",
            "auto_execute": False,
            "supporting_fact_ids": [
                fact_id.value for fact_id in plan.follow_up.supporting_fact_ids
            ],
            "label": label,
            "description": description,
        }
    return {
        "research_plan_version": RESEARCH_PLAN_VERSION,
        "scope": "development_only",
        "title": "Development research review",
        "blocks": blocks,
        "pending_action": pending_action,
        "disclosure": _DISCLOSURE,
    }


def guard_research_output(
    rendered: dict,
    plan: ResearchPlanV1,
    projection: DevelopmentProjectionV1,
) -> None:
    """Accept only the byte-for-byte logical output of the deterministic renderer."""

    expected = render_research_plan(plan, projection)
    if rendered != expected:
        _fail("rendered output differs from the deterministic server render")
    strings: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                collect(key)
                collect(item)

    collect(rendered)
    for value in strings:
        if any(
            unicodedata.category(char) in {"Cc", "Cf"}
            or unicodedata.bidirectional(char) in _BIDI_CLASSES
            for char in value
        ):
            _fail("rendered output contains direction controls")
        if _ADVICE_RE.search(value):
            _fail("rendered output contains advisory language")


__all__ = [
    "ResearchGuardError",
    "canonical_research_plan",
    "guard_research_output",
    "render_research_plan",
    "validate_provider_payload_safety",
    "validate_research_plan",
]
