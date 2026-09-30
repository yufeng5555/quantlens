"""Atomic hypothesis-briefing service with deterministic whole-result fallback."""

from __future__ import annotations

from pydantic import TypeAdapter, ValidationError

from quantlens_schema.validator import SUPPORTED_SCOPE_STATEMENT

from ..mock_parser import PARSER_LABEL, parse_hypothesis
from .contracts import (
    AGENT_CONTRACT_VERSION,
    BRIEFING_POLICY_VERSION,
    AgentOperation,
    BriefingInput,
    BriefingProviderResult,
    CompletedProviderResult,
    GenerationMetadata,
    ProviderRequest,
    UnavailableProviderResult,
)
from .providers import BriefingProvider, create_briefing_provider


FALLBACK_PROVIDER_ERROR = "AGENT_PROVIDER_ERROR"
FALLBACK_PROVIDER_RESULT_INVALID = "AGENT_PROVIDER_RESULT_INVALID"
FALLBACK_PROVIDER_POLICY_REJECTED = "AGENT_PROVIDER_POLICY_REJECTED"

_RESULT_ADAPTER = TypeAdapter(BriefingProviderResult)


class BriefingService:
    """Invoke one closed provider operation or discard it completely on any failure."""

    def __init__(self, provider: BriefingProvider | None = None):
        self._provider = provider if provider is not None else create_briefing_provider()

    @classmethod
    def from_environment(cls) -> "BriefingService":
        return cls(create_briefing_provider())

    def parse(self, hypothesis: str) -> dict:
        """Return a backward-compatible ParseResponse with explicit provenance.

        The deterministic response is constructed independently.  A failed provider
        result is never patched into it field by field, which prevents partial model
        prose, draft fragments, or metadata from leaking through fallback.
        """

        try:
            request = ProviderRequest(
                operation=AgentOperation.BRIEF_HYPOTHESIS,
                policy_version=BRIEFING_POLICY_VERSION,
                input=BriefingInput(hypothesis=hypothesis),
                timeout_ms=8_000,
                max_output_chars=32_000,
            )
        except ValidationError:
            # The provider contract has an explicit payload ceiling. Local deterministic
            # behavior remains compatible when text is too large to cross that future
            # external boundary.
            return self._fallback(hypothesis, FALLBACK_PROVIDER_POLICY_REJECTED)
        try:
            raw_result = self._provider.invoke(request)
        except Exception:
            return self._fallback(hypothesis, FALLBACK_PROVIDER_ERROR)

        try:
            result = _RESULT_ADAPTER.validate_python(raw_result, strict=True)
        except ValidationError:
            return self._fallback(hypothesis, FALLBACK_PROVIDER_RESULT_INVALID)

        if isinstance(result, UnavailableProviderResult):
            return self._fallback(hypothesis, result.failure_code)

        if not self._provider_result_is_safe(result):
            return self._fallback(hypothesis, FALLBACK_PROVIDER_POLICY_REJECTED)

        output = result.output.model_dump(mode="json", exclude_none=True)
        # Parser/scope labels are server-owned.  Provider contracts do not permit either
        # field, so model output cannot relabel itself or rewrite the supported boundary.
        response = {
            "parser": f"structured-provider:{result.metadata.provider}",
            "supported_scope": SUPPORTED_SCOPE_STATEMENT,
            **output,
            "contract_version": AGENT_CONTRACT_VERSION,
            "generation": GenerationMetadata(
                ai_used=True,
                provider=result.metadata.provider,
                model=result.metadata.model,
                request_id=result.metadata.request_id,
                finish_reason=result.metadata.finish_reason,
                usage=result.metadata.usage,
                fallback_used=False,
                fallback_code=None,
                policy_version=BRIEFING_POLICY_VERSION,
            ).model_dump(mode="json"),
        }
        return response

    @staticmethod
    def _provider_result_is_safe(result: CompletedProviderResult) -> bool:
        del result
        # Gate 6A installs only the disabled provider. Even a structurally valid injected
        # provider result fails closed until the next gate adds both (a) a briefing policy
        # linter for free text/numerals/advice/certainty and (b) server-side resolution of
        # correction template IDs. This prevents strict schema validation from being
        # mistaken for content-policy approval.
        return False

    @staticmethod
    def _fallback(hypothesis: str, code: str) -> dict:
        deterministic = parse_hypothesis(hypothesis)
        # Build a fresh envelope around the complete deterministic object.  Nothing from
        # an invalid provider response is copied into this result.
        return {
            **deterministic,
            "contract_version": AGENT_CONTRACT_VERSION,
            "generation": GenerationMetadata(
                ai_used=False,
                provider="disabled",
                model=None,
                request_id=None,
                finish_reason="fallback",
                usage=None,
                fallback_used=True,
                fallback_code=code,
                policy_version=BRIEFING_POLICY_VERSION,
            ).model_dump(mode="json"),
        }


__all__ = [
    "BriefingService",
    "FALLBACK_PROVIDER_ERROR",
    "FALLBACK_PROVIDER_POLICY_REJECTED",
    "FALLBACK_PROVIDER_RESULT_INVALID",
    "PARSER_LABEL",
]
