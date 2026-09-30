"""Atomic Development Research Copilot service.

No provider response is user-visible.  A provider can only choose a strict plan; the
server validates the complete plan, renders server-owned copy, and guards the complete
render before returning it.  Every failure falls back atomically to the canonical plan.
"""

from __future__ import annotations

from collections.abc import Callable
import json
import re

from pydantic import BaseModel, ValidationError

from .research_contracts import (
    DevelopmentProjectionV1,
    RESEARCH_POLICY_VERSION,
    ResearchActionId,
    ResearchPlanV1,
    ResearchProviderRequest,
    ResearchTemplateId,
)
from .research_projection import (
    ResearchProjectionError,
    build_development_projection,
)
from .research_providers import (
    DisabledResearchProvider,
    ResearchPlanningProvider,
    create_research_provider,
)
from .research_renderer import (
    ResearchGuardError,
    canonical_research_plan,
    guard_research_output,
    render_research_plan,
    validate_provider_payload_safety,
    validate_research_plan,
)


FALLBACK_RESEARCH_EVIDENCE_INVALID = "RESEARCH_EVIDENCE_INVALID"
FALLBACK_RESEARCH_PROVIDER_ERROR = "RESEARCH_PROVIDER_ERROR"
FALLBACK_RESEARCH_PROVIDER_TIMEOUT = "RESEARCH_PROVIDER_TIMEOUT"
FALLBACK_RESEARCH_PROVIDER_RESULT_INVALID = "RESEARCH_PROVIDER_RESULT_INVALID"
FALLBACK_RESEARCH_PLAN_REJECTED = "RESEARCH_PLAN_REJECTED"
FALLBACK_RESEARCH_RENDER_REJECTED = "RESEARCH_RENDER_REJECTED"
FALLBACK_RESEARCH_GUARD_REJECTED = "RESEARCH_GUARD_REJECTED"
FALLBACK_RESEARCH_CANONICAL_FAILED = "RESEARCH_CANONICAL_FAILED"


_CandidateRenderer = Callable[[ResearchPlanV1, DevelopmentProjectionV1], dict]
_CandidateGuard = Callable[[dict, ResearchPlanV1, DevelopmentProjectionV1], None]


class DevelopmentResearchCopilot:
    """Review aggregate Development evidence without financial producer capability."""

    def __init__(
        self,
        provider: ResearchPlanningProvider | None = None,
        *,
        candidate_renderer: _CandidateRenderer | None = None,
        candidate_guard: _CandidateGuard | None = None,
    ):
        self._provider = provider if provider is not None else create_research_provider()
        self._candidate_renderer = candidate_renderer or render_research_plan
        self._candidate_guard = candidate_guard or guard_research_output

    @classmethod
    def from_environment(cls) -> "DevelopmentResearchCopilot":
        return cls(create_research_provider())

    def review(self, evidence_view: dict) -> dict:
        """Return a guarded development review or a content-free unavailable view."""

        try:
            projection = build_development_projection(evidence_view)
            canonical_plan = canonical_research_plan(projection)
            canonical_render = render_research_plan(canonical_plan, projection)
            guard_research_output(canonical_render, canonical_plan, projection)
        except (ResearchProjectionError, ResearchGuardError, ValidationError,
                TypeError, ValueError):
            return self._unavailable(FALLBACK_RESEARCH_EVIDENCE_INVALID)

        try:
            request = ResearchProviderRequest(
                projection=projection,
                available_template_ids=list(ResearchTemplateId),
                available_action_ids=list(ResearchActionId),
                timeout_ms=8_000,
                max_output_chars=16_384,
            )
        except ValidationError:
            return self._canonical(
                canonical_render, projection, FALLBACK_RESEARCH_CANONICAL_FAILED)

        if isinstance(self._provider, DisabledResearchProvider):
            return self._canonical(
                canonical_render, projection, self._provider.failure_code)

        try:
            raw_result = self._provider.invoke(request)
        except TimeoutError:
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_PROVIDER_TIMEOUT,
                provider_invoked=True,
                provider_data_transmitted=True,
            )
        except Exception:
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_PROVIDER_ERROR,
                provider_invoked=True,
                provider_data_transmitted=True,
            )

        try:
            json_value = raw_result.model_dump(mode="json") \
                if isinstance(raw_result, BaseModel) else raw_result
            validate_provider_payload_safety(json_value)
            encoded = json.dumps(
                json_value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            if len(encoded.encode("ascii")) > request.max_output_chars:
                raise ValueError("provider result exceeds output boundary")
            plan = ResearchPlanV1.model_validate_json(encoded, strict=True)
        except (ResearchGuardError, ValidationError, TypeError, ValueError):
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_PROVIDER_RESULT_INVALID,
                provider_invoked=True,
                provider_data_transmitted=True,
            )

        try:
            validate_research_plan(plan, projection)
        except Exception:
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_PLAN_REJECTED,
                provider_invoked=True,
                provider_data_transmitted=True,
            )
        try:
            candidate = self._candidate_renderer(plan, projection)
        except Exception:
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_RENDER_REJECTED,
                provider_invoked=True,
                provider_data_transmitted=True,
            )
        try:
            self._candidate_guard(candidate, plan, projection)
        except Exception:
            return self._canonical(
                canonical_render,
                projection,
                FALLBACK_RESEARCH_GUARD_REJECTED,
                provider_invoked=True,
                provider_data_transmitted=True,
            )
        return self._completed(
            analysis=candidate,
            projection=projection,
            generation=self._generation(
                ai_used=True,
                provider_invoked=True,
                provider_data_transmitted=True,
                ai_influenced_output=True,
                fallback_used=False,
                fallback_code=None,
            ),
        )

    def _canonical(
        self,
        analysis: dict,
        projection: DevelopmentProjectionV1,
        code: str,
        *,
        provider_invoked: bool = False,
        provider_data_transmitted: bool = False,
    ) -> dict:
        return self._completed(
            analysis=copy_json(analysis),
            projection=projection,
            generation=self._generation(
                ai_used=False,
                provider_invoked=provider_invoked,
                provider_data_transmitted=provider_data_transmitted,
                ai_influenced_output=False,
                fallback_used=True,
                fallback_code=code,
            ),
        )

    def _generation(
        self,
        *,
        ai_used: bool,
        provider_invoked: bool,
        provider_data_transmitted: bool,
        ai_influenced_output: bool,
        fallback_used: bool,
        fallback_code: str | None,
    ) -> dict:
        provider_name = "disabled"
        candidate_name = getattr(self._provider, "name", None)
        if provider_invoked and isinstance(candidate_name, str) and re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{0,63}", candidate_name
        ):
            provider_name = candidate_name
        return {
            "ai_used": ai_used,
            "provider_invoked": provider_invoked,
            "provider_data_transmitted": provider_data_transmitted,
            "ai_influenced_output": ai_influenced_output,
            "provider": provider_name,
            "fallback_used": fallback_used,
            "fallback_code": fallback_code,
            "policy_version": RESEARCH_POLICY_VERSION,
        }

    @staticmethod
    def _completed(
        *,
        analysis: dict,
        projection: DevelopmentProjectionV1,
        generation: dict,
    ) -> dict:
        return {
            "research_copilot_view_version": "v1",
            "status": "completed",
            "scope": "development_only",
            "binding": {
                "opaque_development_binding": projection.opaque_development_binding,
            },
            "generation": generation,
            "analysis": analysis,
        }

    @staticmethod
    def _unavailable(code: str) -> dict:
        return {
            "research_copilot_view_version": "v1",
            "status": "unavailable",
            "scope": "development_only",
            "binding": None,
            "generation": {
                "ai_used": False,
                "provider_invoked": False,
                "provider_data_transmitted": False,
                "ai_influenced_output": False,
                "provider": "disabled",
                "fallback_used": True,
                "fallback_code": code,
                "policy_version": RESEARCH_POLICY_VERSION,
            },
            "analysis": None,
        }


def copy_json(value: dict) -> dict:
    """Copy a trusted render through canonical JSON without importing mutable systems."""

    return json.loads(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ))


__all__ = [
    "DevelopmentResearchCopilot",
    "FALLBACK_RESEARCH_CANONICAL_FAILED",
    "FALLBACK_RESEARCH_EVIDENCE_INVALID",
    "FALLBACK_RESEARCH_GUARD_REJECTED",
    "FALLBACK_RESEARCH_PLAN_REJECTED",
    "FALLBACK_RESEARCH_PROVIDER_ERROR",
    "FALLBACK_RESEARCH_PROVIDER_RESULT_INVALID",
    "FALLBACK_RESEARCH_PROVIDER_TIMEOUT",
    "FALLBACK_RESEARCH_RENDER_REJECTED",
]
