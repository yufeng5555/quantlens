"""Gate 6A evidence explanation service with atomic deterministic fallback."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import re

from pydantic import BaseModel, TypeAdapter, ValidationError

from quantlens_worker.narrative_facts import (
    NarrativeFactCatalogError,
    build_narrative_fact_catalog,
)

from .narrative_contracts import (
    EXPLANATION_VIEW_VERSION,
    NARRATIVE_CATALOG_VERSION,
    NARRATIVE_PLAN_VERSION,
    NARRATIVE_POLICY_VERSION,
    CompletedNarrativeProviderResult,
    ExplanationGenerationMetadata,
    NarrativePlanV1,
    NarrativeProviderRequest,
    NarrativeProviderResult,
    NarrativeTemplateId,
    UnavailableNarrativeProviderResult,
)
from .narrative_providers import ExplanationProvider, create_explanation_provider
from .narrative_renderer import (
    NarrativeGuardError,
    build_current_binding,
    canonical_narrative_plan,
    guard_narrative_explanation,
    render_narrative_plan,
    validate_narrative_plan,
)


FALLBACK_EVIDENCE_INVALID = "EXPLANATION_EVIDENCE_INVALID"
FALLBACK_PROVIDER_ERROR = "EXPLANATION_PROVIDER_ERROR"
FALLBACK_PROVIDER_TIMEOUT = "EXPLANATION_PROVIDER_TIMEOUT"
FALLBACK_PROVIDER_RESULT_INVALID = "EXPLANATION_PROVIDER_RESULT_INVALID"
FALLBACK_PROVIDER_METADATA_INVALID = "EXPLANATION_PROVIDER_METADATA_INVALID"
FALLBACK_PLAN_REJECTED = "EXPLANATION_PLAN_REJECTED"
FALLBACK_RENDER_REJECTED = "EXPLANATION_RENDER_REJECTED"
FALLBACK_GUARD_REJECTED = "EXPLANATION_GUARD_REJECTED"
FALLBACK_CANONICAL_FAILED = "EXPLANATION_CANONICAL_FAILED"


_RESULT_ADAPTER = TypeAdapter(NarrativeProviderResult)
_CandidateRenderer = Callable[[NarrativePlanV1, dict, dict], dict]
_CandidateGuard = Callable[[dict, NarrativePlanV1, dict, dict], None]


class ExplanationService:
    """Plan, render, and guard one verified evidence view.

    Provider failure affects only the optional narrative.  It cannot mutate the supplied
    evidence, a run, an entitlement, a report, or any financial artifact because this
    service has no such capability.  The provider candidate is constructed on a separate
    path and is returned only after complete validation.
    """

    def __init__(
        self,
        provider: ExplanationProvider | None = None,
        *,
        candidate_renderer: _CandidateRenderer | None = None,
        candidate_guard: _CandidateGuard | None = None,
    ):
        self._provider = provider if provider is not None else create_explanation_provider()
        # Injection points are intentionally limited to the optional provider candidate.
        # Canonical fallback always uses the trusted renderer and guard below.
        self._candidate_renderer = candidate_renderer or render_narrative_plan
        self._candidate_guard = candidate_guard or guard_narrative_explanation

    @classmethod
    def from_environment(cls) -> "ExplanationService":
        return cls(create_explanation_provider())

    def explain(self, evidence_view: dict) -> dict:
        """Return ExplanationViewV1 or a content-free fail-closed unavailable view."""

        # Keep this invariant at the service boundary as well as at every HTTP caller.
        # That makes a future internal caller fail closed before catalog construction or
        # provider invocation instead of relying on route-specific ordering.
        status = evidence_view.get("status") if isinstance(evidence_view, dict) else None
        if not isinstance(status, dict) or status.get("evidence_complete") is not True:
            return self._unavailable(FALLBACK_EVIDENCE_INVALID)

        try:
            catalog = build_narrative_fact_catalog(evidence_view)
            binding = build_current_binding(evidence_view, catalog)
            canonical_plan = canonical_narrative_plan(binding)
            canonical_explanation = render_narrative_plan(
                canonical_plan, catalog, binding)
            guard_narrative_explanation(
                canonical_explanation, canonical_plan, catalog, binding)
        except (NarrativeFactCatalogError, NarrativeGuardError, ValidationError,
                TypeError, ValueError):
            return self._unavailable(FALLBACK_EVIDENCE_INVALID)

        try:
            request = NarrativeProviderRequest(
                catalog_version=NARRATIVE_CATALOG_VERSION,
                opaque_evidence_binding=binding["opaque_evidence_binding"],
                available_fact_ids=sorted(fact["fact_id"] for fact in catalog["facts"]),
                available_template_ids=list(NarrativeTemplateId),
                timeout_ms=8_000,
                max_output_chars=16_384,
            )
        except ValidationError:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_CANONICAL_FAILED)

        try:
            raw_result = self._provider.invoke(request)
        except TimeoutError:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_PROVIDER_TIMEOUT,
                provider_invoked=self._external_provider_invoked(),
                provider_data_transmitted=self._external_provider_invoked())
        except Exception:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_PROVIDER_ERROR,
                provider_invoked=self._external_provider_invoked(),
                provider_data_transmitted=self._external_provider_invoked())

        try:
            json_value = raw_result.model_dump(mode="json") \
                if isinstance(raw_result, BaseModel) else raw_result
            encoded_result = json.dumps(
                json_value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            )
            # JSON mode accepts the string representation of closed enums while still
            # rejecting coercion of numbers/bools and every extra field.
            result = _RESULT_ADAPTER.validate_json(encoded_result, strict=True)
        except (ValidationError, TypeError, ValueError):
            return self._canonical(
                canonical_explanation, binding, FALLBACK_PROVIDER_RESULT_INVALID,
                provider_invoked=self._external_provider_invoked(),
                provider_data_transmitted=self._external_provider_invoked())

        if isinstance(result, UnavailableNarrativeProviderResult):
            return self._canonical(
                canonical_explanation, binding, result.failure_code,
                provider_invoked=self._external_provider_invoked(),
                provider_data_transmitted=self._external_provider_invoked())

        if not self._provider_metadata_is_safe(result):
            return self._canonical(
                canonical_explanation, binding, FALLBACK_PROVIDER_METADATA_INVALID,
                provider_invoked=self._external_provider_invoked(),
                provider_data_transmitted=self._external_provider_invoked())

        plan = result.plan
        try:
            validate_narrative_plan(plan, catalog, binding)
        except Exception:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_PLAN_REJECTED,
                provider_invoked=True, provider_data_transmitted=True)
        try:
            # Plan validation is embedded in rendering and checks binding, template/fact
            # signatures, units, context, source integrity, and comparison direction.
            candidate = self._candidate_renderer(plan, catalog, binding)
        except Exception:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_RENDER_REJECTED,
                provider_invoked=True, provider_data_transmitted=True)
        try:
            self._candidate_guard(candidate, plan, catalog, binding)
        except Exception:
            return self._canonical(
                canonical_explanation, binding, FALLBACK_GUARD_REJECTED,
                provider_invoked=True, provider_data_transmitted=True)

        return self._completed(
            explanation=candidate,
            binding=binding,
            generation=ExplanationGenerationMetadata(
                ai_used=True,
                provider_invoked=True,
                provider_data_transmitted=True,
                ai_influenced_output=True,
                provider=result.metadata.provider,
                model=result.metadata.model,
                request_id=self._safe_request_id(result.metadata.request_id),
                finish_reason=result.metadata.finish_reason,
                fallback_used=False,
                fallback_code=None,
            ).model_dump(mode="json"),
        )

    def _provider_metadata_is_safe(self, result: CompletedNarrativeProviderResult) -> bool:
        safe_name = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
        safe_model = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}")
        safe_finish = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
        return bool(
            result.metadata.ai_used is True
            and result.metadata.provider == self._provider.name
            and result.metadata.provider != "disabled"
            and safe_name.fullmatch(result.metadata.provider) is not None
            and (
                result.metadata.model is None
                or safe_model.fullmatch(result.metadata.model) is not None
            )
            and (
                result.metadata.finish_reason is None
                or safe_finish.fullmatch(result.metadata.finish_reason) is not None
            )
        )

    def _external_provider_invoked(self) -> bool:
        """Disabled/unknown adapters are inert and count as no provider invocation."""

        return getattr(self._provider, "name", "disabled") != "disabled"

    @staticmethod
    def _safe_request_id(request_id: str | None) -> str | None:
        if request_id is None:
            return None
        return "req-sha256:" + hashlib.sha256(request_id.encode()).hexdigest()

    @staticmethod
    def _completed(*, explanation: dict, binding: dict, generation: dict) -> dict:
        return {
            "explanation_view_version": EXPLANATION_VIEW_VERSION,
            "narrative_plan_version": NARRATIVE_PLAN_VERSION,
            "status": "completed",
            "generation": generation,
            "binding": binding,
            "explanation": explanation,
        }

    def _canonical(
        self, explanation: dict, binding: dict, code: str, *,
        provider_invoked: bool = False,
        provider_data_transmitted: bool = False,
    ) -> dict:
        return self._completed(
            explanation=explanation,
            binding=binding,
            generation=ExplanationGenerationMetadata(
                ai_used=False,
                provider_invoked=provider_invoked,
                provider_data_transmitted=provider_data_transmitted,
                ai_influenced_output=False,
                provider=(
                    self._safe_provider_name_for_disclosure()
                    if provider_invoked else "disabled"
                ),
                model=None,
                request_id=None,
                finish_reason="fallback",
                fallback_used=True,
                fallback_code=code,
            ).model_dump(mode="json"),
        )

    def _safe_provider_name_for_disclosure(self) -> str:
        """Name a contacted provider only when its server-owned label is safe.

        A fallback must not imply that no provider was contacted after data crossed the
        boundary. Conversely, an unsafe provider-supplied label is never reflected.
        """

        name = getattr(self._provider, "name", None)
        if isinstance(name, str) and re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", name) is not None:
            return name
        return "disabled"

    @staticmethod
    def _unavailable(code: str) -> dict:
        return {
            "explanation_view_version": EXPLANATION_VIEW_VERSION,
            "narrative_plan_version": NARRATIVE_PLAN_VERSION,
            "status": "unavailable",
            "generation": ExplanationGenerationMetadata(
                ai_used=False,
                provider_invoked=False,
                provider_data_transmitted=False,
                ai_influenced_output=False,
                provider="disabled",
                model=None,
                request_id=None,
                finish_reason="unavailable",
                fallback_used=True,
                fallback_code=code,
            ).model_dump(mode="json"),
            "binding": None,
            "explanation": None,
        }


__all__ = [
    "ExplanationService",
    "FALLBACK_CANONICAL_FAILED",
    "FALLBACK_EVIDENCE_INVALID",
    "FALLBACK_GUARD_REJECTED",
    "FALLBACK_PLAN_REJECTED",
    "FALLBACK_PROVIDER_ERROR",
    "FALLBACK_PROVIDER_METADATA_INVALID",
    "FALLBACK_PROVIDER_RESULT_INVALID",
    "FALLBACK_PROVIDER_TIMEOUT",
    "FALLBACK_RENDER_REJECTED",
]
