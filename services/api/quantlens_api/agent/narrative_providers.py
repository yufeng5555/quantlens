"""Fail-closed provider factory for Gate 6A explanation planning.

There is no live adapter, transport, credential lookup, SDK, or network operation here.
Unknown configuration produces the same inert provider with a stable reason code.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from .contracts import ProviderMetadata
from .narrative_contracts import (
    NarrativeProviderRequest,
    UnavailableNarrativeProviderResult,
)


FALLBACK_PROVIDER_DISABLED = "EXPLANATION_PROVIDER_DISABLED"
FALLBACK_PROVIDER_UNKNOWN = "EXPLANATION_PROVIDER_UNKNOWN"


@runtime_checkable
class ExplanationProvider(Protocol):
    name: str

    def invoke(self, request: NarrativeProviderRequest) -> object:
        """Return a value that the service will validate strictly."""
        ...


class DisabledExplanationProvider:
    name = "disabled"

    def __init__(self, *, failure_code: str = FALLBACK_PROVIDER_DISABLED):
        if failure_code not in {FALLBACK_PROVIDER_DISABLED, FALLBACK_PROVIDER_UNKNOWN}:
            raise ValueError("disabled explanation provider failure code is not closed")
        self.failure_code = failure_code

    def invoke(self, request: NarrativeProviderRequest) -> UnavailableNarrativeProviderResult:
        del request
        return UnavailableNarrativeProviderResult(
            status="unavailable",
            metadata=ProviderMetadata(
                ai_used=False,
                provider=self.name,
                model=None,
                request_id=None,
                finish_reason="disabled",
                usage=None,
            ),
            failure_code=self.failure_code,
        )


def create_explanation_provider(configured_name: str | None = None) -> ExplanationProvider:
    raw_name = configured_name
    if raw_name is None:
        raw_name = os.getenv("QL_NARRATIVE_PROVIDER", "disabled")
    name = raw_name.strip().lower() if isinstance(raw_name, str) else ""
    if name == "disabled":
        return DisabledExplanationProvider()
    return DisabledExplanationProvider(failure_code=FALLBACK_PROVIDER_UNKNOWN)


__all__ = [
    "DisabledExplanationProvider",
    "ExplanationProvider",
    "FALLBACK_PROVIDER_DISABLED",
    "FALLBACK_PROVIDER_UNKNOWN",
    "create_explanation_provider",
]
