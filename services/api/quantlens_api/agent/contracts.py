"""Closed, strict contracts at the QuantLens model-provider boundary.

These models intentionally accept JSON-shaped data only and reject coercion and unknown
fields.  They are not an SDK for a specific vendor and they contain no transport code.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictBool, StrictInt, StrictStr


AGENT_CONTRACT_VERSION = "quantlens-agent-v1"
BRIEFING_POLICY_VERSION = "briefing-policy-v1"


class StrictAgentModel(BaseModel):
    """Base model shared by every value that crosses the provider boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class AgentOperation(str, Enum):
    BRIEF_HYPOTHESIS = "brief_hypothesis"


class BriefingInput(StrictAgentModel):
    hypothesis: StrictStr = Field(max_length=10_000)


class ProviderRequest(StrictAgentModel):
    contract_version: Literal[AGENT_CONTRACT_VERSION] = AGENT_CONTRACT_VERSION
    operation: AgentOperation
    policy_version: Literal[BRIEFING_POLICY_VERSION] = BRIEFING_POLICY_VERSION
    input: BriefingInput
    timeout_ms: StrictInt = Field(ge=100, le=30_000)
    max_output_chars: StrictInt = Field(ge=256, le=100_000)


class ProviderUsage(StrictAgentModel):
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)


class ProviderMetadata(StrictAgentModel):
    ai_used: StrictBool
    provider: StrictStr = Field(min_length=1, max_length=64)
    model: StrictStr | None = Field(default=None, max_length=160)
    request_id: StrictStr | None = Field(default=None, max_length=256)
    finish_reason: StrictStr | None = Field(default=None, max_length=64)
    usage: ProviderUsage | None = None


class ClarificationQuestion(StrictAgentModel):
    field: StrictStr = Field(min_length=1, max_length=120)
    kind: Literal["symbol", "rule", "windows", "date_range", "costs"]
    material: StrictBool
    question: StrictStr = Field(min_length=1, max_length=1_000)
    options: list[StrictStr] | None = Field(default=None, max_length=100)
    default: JsonValue | None = None


class RecognizedFields(StrictAgentModel):
    symbol: StrictStr | None = Field(default=None, pattern=r"^[A-Z]{1,6}$")
    rule_type: Literal["price_vs_ma", "ma_crossover"] | None = None
    fast_ma_days: StrictInt | None = Field(default=None, ge=2, le=400)
    ma_days: StrictInt | None = Field(default=None, ge=2, le=400)


class CorrectionDirective(StrictAgentModel):
    """Select one server-owned correction; providers never manufacture a template."""

    template_id: Literal["nearest_supported_ma"]


class DraftBriefing(StrictAgentModel):
    status: Literal["draft"]
    category: Literal["supported"] = "supported"
    draft: dict[StrictStr, JsonValue]
    default_fields: list[StrictStr]
    message: StrictStr = Field(min_length=1, max_length=4_000)


class ClarifyBriefing(StrictAgentModel):
    status: Literal["ambiguous"]
    category: StrictStr = Field(min_length=1, max_length=120)
    message: StrictStr = Field(min_length=1, max_length=4_000)
    questions: list[ClarificationQuestion] = Field(min_length=1, max_length=20)
    recognized_fields: RecognizedFields | None = None


class UnsupportedBriefing(StrictAgentModel):
    status: Literal["unsupported"]
    category: StrictStr = Field(min_length=1, max_length=120)
    message: StrictStr = Field(min_length=1, max_length=4_000)
    correction: CorrectionDirective


class AdviceDeflectionBriefing(StrictAgentModel):
    status: Literal["advice_deflection"]
    category: Literal["advice_seeking"] = "advice_seeking"
    message: StrictStr = Field(min_length=1, max_length=4_000)


BriefingOutput = Annotated[
    Union[
        DraftBriefing,
        ClarifyBriefing,
        UnsupportedBriefing,
        AdviceDeflectionBriefing,
    ],
    Field(discriminator="status"),
]


class CompletedProviderResult(StrictAgentModel):
    status: Literal["completed"]
    output: BriefingOutput
    metadata: ProviderMetadata


class UnavailableProviderResult(StrictAgentModel):
    status: Literal["unavailable"]
    output: None = None
    metadata: ProviderMetadata
    failure_code: StrictStr = Field(min_length=1, max_length=120)


BriefingProviderResult = Annotated[
    Union[CompletedProviderResult, UnavailableProviderResult],
    Field(discriminator="status"),
]


class GenerationMetadata(StrictAgentModel):
    ai_used: StrictBool
    provider: StrictStr
    model: StrictStr | None = None
    request_id: StrictStr | None = None
    finish_reason: StrictStr | None = None
    usage: ProviderUsage | None = None
    fallback_used: StrictBool
    fallback_code: StrictStr | None = None
    policy_version: Literal[BRIEFING_POLICY_VERSION] = BRIEFING_POLICY_VERSION
