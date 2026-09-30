"""Provider-neutral, local-only agent boundary for QuantLens.

Gate 6A deliberately ships no live model adapter.  The public surface is a strict
structured contract plus a disabled provider that fails closed to deterministic
QuantLens behavior.
"""

from .briefing import BriefingService
from .contracts import (
    AGENT_CONTRACT_VERSION,
    BRIEFING_POLICY_VERSION,
    AgentOperation,
    BriefingProviderResult,
    ProviderMetadata,
    ProviderRequest,
)
from .providers import DisabledBriefingProvider, create_briefing_provider
from .explanation import ExplanationService
from .narrative_contracts import (
    EXPLANATION_VIEW_VERSION,
    NARRATIVE_PLAN_VERSION,
    NARRATIVE_POLICY_VERSION,
    NarrativeComparator,
    NarrativePlanV1,
    NarrativeTemplateId,
)
from .narrative_providers import (
    DisabledExplanationProvider,
    create_explanation_provider,
)
from .research_contracts import (
    DevelopmentProjectionV1,
    RESEARCH_PLAN_VERSION,
    RESEARCH_POLICY_VERSION,
    RESEARCH_PROJECTION_VERSION,
    ResearchActionId,
    ResearchComparator,
    ResearchFactId,
    ResearchPlanV1,
    ResearchTemplateId,
    ResearchUnit,
)
from .research_copilot import DevelopmentResearchCopilot
from .research_projection import build_development_projection
from .research_providers import DisabledResearchProvider, create_research_provider

__all__ = [
    "AGENT_CONTRACT_VERSION",
    "BRIEFING_POLICY_VERSION",
    "AgentOperation",
    "BriefingProviderResult",
    "BriefingService",
    "DisabledBriefingProvider",
    "DisabledExplanationProvider",
    "DisabledResearchProvider",
    "DevelopmentProjectionV1",
    "DevelopmentResearchCopilot",
    "EXPLANATION_VIEW_VERSION",
    "ExplanationService",
    "NARRATIVE_PLAN_VERSION",
    "NARRATIVE_POLICY_VERSION",
    "NarrativeComparator",
    "NarrativePlanV1",
    "NarrativeTemplateId",
    "ProviderMetadata",
    "ProviderRequest",
    "RESEARCH_PLAN_VERSION",
    "RESEARCH_POLICY_VERSION",
    "RESEARCH_PROJECTION_VERSION",
    "ResearchActionId",
    "ResearchComparator",
    "ResearchFactId",
    "ResearchPlanV1",
    "ResearchTemplateId",
    "ResearchUnit",
    "build_development_projection",
    "create_briefing_provider",
    "create_explanation_provider",
    "create_research_provider",
]
