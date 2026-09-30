"""Strict contracts for evidence-grounded explanation planning.

The future model-facing object is deliberately a *plan*, never prose.  A plan can only
select server-owned templates and already-catalogued fact IDs, declare the comparison
semantics, and echo one opaque binding to the current verified evidence projection.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import Field, StrictBool, StrictInt, StrictStr

from .contracts import ProviderMetadata, StrictAgentModel


EXPLANATION_VIEW_VERSION = "v1"
NARRATIVE_PLAN_VERSION = "NarrativePlanV1"
NARRATIVE_POLICY_VERSION = "narrative-policy-v1"
NARRATIVE_PROVIDER_CONTRACT_VERSION = "quantlens-narrative-provider-v1"
NARRATIVE_CATALOG_VERSION = "NarrativeFactCatalogV1"


class NarrativeTemplateId(str, Enum):
    OOS_TOTAL_RETURN = "compare_oos_strategy_and_benchmark_total_return"
    OOS_MAX_DRAWDOWN = "compare_oos_strategy_and_benchmark_max_drawdown"
    OOS_COST_STRESS = "compare_oos_base_and_2x_cost_total_return"
    FALSIFICATION_STATUS = "summarize_falsification_statuses"


class NarrativeComparator(str, Enum):
    HIGHER_VALUE = "higher_value"
    SMALLER_ABSOLUTE_MAGNITUDE = "smaller_absolute_magnitude"
    STATUS_ONLY = "status_only"


NarrativeFactId = Annotated[
    StrictStr,
    Field(
        min_length=1,
        max_length=160,
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    ),
]


class NarrativePlanItem(StrictAgentModel):
    template_id: NarrativeTemplateId
    fact_ids: list[NarrativeFactId] = Field(min_length=1, max_length=3)
    comparator: NarrativeComparator


class NarrativePlanV1(StrictAgentModel):
    plan_version: Literal[NARRATIVE_PLAN_VERSION] = NARRATIVE_PLAN_VERSION
    opaque_evidence_binding: StrictStr = Field(pattern=r"^evb1-[0-9a-f]{64}$")
    items: list[NarrativePlanItem] = Field(min_length=1, max_length=4)


class NarrativeProviderRequest(StrictAgentModel):
    """Privacy-minimized request shape for a future provider.

    No values, units, context, hashes, pointers, paths, prose, or raw evidence cross this
    boundary in Gate 6A.  A later gate may add a separately reviewed safe projection.
    """

    contract_version: Literal[NARRATIVE_PROVIDER_CONTRACT_VERSION] = \
        NARRATIVE_PROVIDER_CONTRACT_VERSION
    operation: Literal["plan_verified_explanation"] = "plan_verified_explanation"
    policy_version: Literal[NARRATIVE_POLICY_VERSION] = NARRATIVE_POLICY_VERSION
    catalog_version: Literal[NARRATIVE_CATALOG_VERSION] = NARRATIVE_CATALOG_VERSION
    opaque_evidence_binding: StrictStr = Field(pattern=r"^evb1-[0-9a-f]{64}$")
    available_fact_ids: list[NarrativeFactId] = Field(min_length=1, max_length=500)
    available_template_ids: list[NarrativeTemplateId] = Field(min_length=1, max_length=20)
    timeout_ms: StrictInt = Field(ge=100, le=30_000)
    max_output_chars: StrictInt = Field(ge=1_024, le=100_000)


class CompletedNarrativeProviderResult(StrictAgentModel):
    status: Literal["completed"]
    plan: NarrativePlanV1
    metadata: ProviderMetadata


class UnavailableNarrativeProviderResult(StrictAgentModel):
    status: Literal["unavailable"]
    plan: None = None
    metadata: ProviderMetadata
    failure_code: Literal[
        "EXPLANATION_PROVIDER_DISABLED",
        "EXPLANATION_PROVIDER_UNKNOWN",
        "EXPLANATION_PROVIDER_UNAVAILABLE",
        "EXPLANATION_PROVIDER_TIMEOUT",
    ]


NarrativeProviderResult = Annotated[
    Union[CompletedNarrativeProviderResult, UnavailableNarrativeProviderResult],
    Field(discriminator="status"),
]


class ExplanationGenerationMetadata(StrictAgentModel):
    ai_used: StrictBool
    provider_invoked: StrictBool
    provider_data_transmitted: StrictBool
    ai_influenced_output: StrictBool
    provider: StrictStr = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    model: StrictStr | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
    request_id: StrictStr | None = Field(
        default=None, pattern=r"^req-sha256:[0-9a-f]{64}$")
    finish_reason: StrictStr | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    fallback_used: StrictBool
    fallback_code: StrictStr | None = Field(default=None, max_length=120)
    policy_version: Literal[NARRATIVE_POLICY_VERSION] = NARRATIVE_POLICY_VERSION


__all__ = [
    "CompletedNarrativeProviderResult",
    "EXPLANATION_VIEW_VERSION",
    "ExplanationGenerationMetadata",
    "NARRATIVE_CATALOG_VERSION",
    "NARRATIVE_PLAN_VERSION",
    "NARRATIVE_POLICY_VERSION",
    "NARRATIVE_PROVIDER_CONTRACT_VERSION",
    "NarrativeComparator",
    "NarrativeFactId",
    "NarrativePlanItem",
    "NarrativePlanV1",
    "NarrativeProviderRequest",
    "NarrativeProviderResult",
    "NarrativeTemplateId",
    "UnavailableNarrativeProviderResult",
]
