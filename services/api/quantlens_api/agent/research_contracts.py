"""Closed contracts for the Development Research Copilot provider boundary.

The provider receives only a server-built projection of aggregate development facts.
It can select server-owned templates and propose one server-owned, unexecuted follow-up
action.  It cannot produce prose, financial values, units, instruments, parameters, or
tool calls.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, StrictFloat, StrictInt, StrictStr

from .contracts import StrictAgentModel


RESEARCH_PROJECTION_VERSION = "DevelopmentProjectionV1"
RESEARCH_PLAN_VERSION = "ResearchPlanV1"
RESEARCH_PROVIDER_CONTRACT_VERSION = "quantlens-research-provider-v1"
RESEARCH_POLICY_VERSION = "development-research-policy-v1"


class ResearchScope(str, Enum):
    DEVELOPMENT_ONLY = "development_only"


class ResearchUnit(str, Enum):
    DECIMAL_FRACTION = "decimal_fraction"
    RATIO = "ratio"
    COUNT = "count"
    USD = "USD"
    CHECK_STATUS = "check_status"


class ResearchCheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ResearchFactId(str, Enum):
    DEVELOPMENT_TOTAL_RETURN = "development.performance.total_return"
    DEVELOPMENT_CAGR = "development.performance.cagr"
    DEVELOPMENT_ANN_VOL = "development.performance.annualized_volatility"
    DEVELOPMENT_SHARPE = "development.performance.sharpe"
    DEVELOPMENT_MAX_DRAWDOWN = "development.performance.max_drawdown"
    DEVELOPMENT_TRADE_COUNT = "development.activity.trade_count"
    DEVELOPMENT_TOTAL_COSTS = "development.activity.total_costs"
    DEVELOPMENT_EXPOSURE = "development.activity.exposure"

    WALK_FORWARD_FOLD_COUNT = "development.walk_forward.fold_count"
    WALK_FORWARD_MEDIAN_SHARPE = "development.walk_forward.median_fold_sharpe"
    WALK_FORWARD_POSITIVE_RATIO = "development.walk_forward.positive_fold_ratio"
    WALK_FORWARD_WORST_RETURN = "development.walk_forward.worst_fold_return"
    WALK_FORWARD_RETURN_DISPERSION = "development.walk_forward.fold_return_dispersion"

    COST_STRESS_BASE_RETURN = "development.cost_stress.base.total_return"
    COST_STRESS_DOUBLE_RETURN = "development.cost_stress.doubled.total_return"
    COST_STRESS_BASE_COSTS = "development.cost_stress.base.total_costs"
    COST_STRESS_DOUBLE_COSTS = "development.cost_stress.doubled.total_costs"

    REGIME_UP_LOW_OBSERVATIONS = "development.regime.up_low.observations"
    REGIME_UP_LOW_STATUS = "development.regime.up_low.status"
    REGIME_UP_HIGH_OBSERVATIONS = "development.regime.up_high.observations"
    REGIME_UP_HIGH_STATUS = "development.regime.up_high.status"
    REGIME_DOWN_LOW_OBSERVATIONS = "development.regime.down_low.observations"
    REGIME_DOWN_LOW_STATUS = "development.regime.down_low.status"
    REGIME_DOWN_HIGH_OBSERVATIONS = "development.regime.down_high.observations"
    REGIME_DOWN_HIGH_STATUS = "development.regime.down_high.status"

    CHECK_WALK_FORWARD = "development.check.walk_forward_stability"
    CHECK_COST_FRAGILITY = "development.check.cost_fragility"
    CHECK_REGIME_COVERAGE = "development.check.regime_coverage"


ResearchFactValue = StrictFloat | StrictInt | ResearchCheckStatus


class DevelopmentFactV1(StrictAgentModel):
    fact_id: ResearchFactId
    value: ResearchFactValue
    unit: ResearchUnit
    display_precision: StrictInt = Field(ge=0, le=4)


class DevelopmentProjectionV1(StrictAgentModel):
    projection_version: Literal[RESEARCH_PROJECTION_VERSION] = RESEARCH_PROJECTION_VERSION
    scope: Literal[ResearchScope.DEVELOPMENT_ONLY] = ResearchScope.DEVELOPMENT_ONLY
    opaque_development_binding: StrictStr = Field(pattern=r"^dvb1-[0-9a-f]{64}$")
    facts: list[DevelopmentFactV1] = Field(min_length=1, max_length=64)


class ResearchTemplateId(str, Enum):
    DEVELOPMENT_RISK_RETURN = "summarize_development_risk_return"
    WALK_FORWARD_STABILITY = "summarize_walk_forward_stability"
    COST_STRESS_RESILIENCE = "compare_base_and_doubled_development_costs"
    REGIME_COVERAGE = "summarize_preregistered_regime_coverage"
    VALIDATION_CHECKS = "summarize_development_validation_checks"


class ResearchComparator(str, Enum):
    RISK_RETURN_CONTEXT = "risk_return_context"
    STABILITY_CONTEXT = "stability_context"
    BASE_VS_STRESSED = "base_vs_stressed"
    COVERAGE_CONTEXT = "coverage_context"
    STATUS_ONLY = "status_only"


class ResearchActionId(str, Enum):
    REVIEW_WALK_FORWARD = "review_walk_forward_evidence"
    REVIEW_COST_STRESS = "review_cost_stress_evidence"
    REVIEW_REGIME_COVERAGE = "review_regime_coverage_evidence"


class ResearchPlanItem(StrictAgentModel):
    template_id: ResearchTemplateId
    fact_ids: list[ResearchFactId] = Field(min_length=1, max_length=8)
    comparator: ResearchComparator


class ResearchFollowUpV1(StrictAgentModel):
    action_id: ResearchActionId
    supporting_fact_ids: list[ResearchFactId] = Field(min_length=1, max_length=8)


class ResearchPlanV1(StrictAgentModel):
    plan_version: Literal[RESEARCH_PLAN_VERSION] = RESEARCH_PLAN_VERSION
    opaque_development_binding: StrictStr = Field(pattern=r"^dvb1-[0-9a-f]{64}$")
    items: list[ResearchPlanItem] = Field(min_length=1, max_length=5)
    follow_up: ResearchFollowUpV1 | None = None


class ResearchProviderRequest(StrictAgentModel):
    contract_version: Literal[RESEARCH_PROVIDER_CONTRACT_VERSION] = \
        RESEARCH_PROVIDER_CONTRACT_VERSION
    operation: Literal["plan_development_research_summary"] = \
        "plan_development_research_summary"
    policy_version: Literal[RESEARCH_POLICY_VERSION] = RESEARCH_POLICY_VERSION
    projection: DevelopmentProjectionV1
    available_template_ids: list[ResearchTemplateId] = Field(min_length=1, max_length=10)
    available_action_ids: list[ResearchActionId] = Field(min_length=1, max_length=10)
    timeout_ms: StrictInt = Field(ge=100, le=30_000)
    max_output_chars: StrictInt = Field(ge=512, le=32_768)


__all__ = [
    "DevelopmentFactV1",
    "DevelopmentProjectionV1",
    "RESEARCH_PLAN_VERSION",
    "RESEARCH_POLICY_VERSION",
    "RESEARCH_PROJECTION_VERSION",
    "RESEARCH_PROVIDER_CONTRACT_VERSION",
    "ResearchActionId",
    "ResearchCheckStatus",
    "ResearchComparator",
    "ResearchFactId",
    "ResearchFollowUpV1",
    "ResearchPlanItem",
    "ResearchPlanV1",
    "ResearchProviderRequest",
    "ResearchScope",
    "ResearchTemplateId",
    "ResearchUnit",
]
