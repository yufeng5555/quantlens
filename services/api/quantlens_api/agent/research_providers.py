"""Provider-neutral, network-free adapters for Development Research Copilot v1."""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from .research_contracts import ResearchProviderRequest


RESEARCH_PROVIDER_DISABLED = "RESEARCH_PROVIDER_DISABLED"
RESEARCH_PROVIDER_UNKNOWN = "RESEARCH_PROVIDER_UNKNOWN"


@runtime_checkable
class ResearchPlanningProvider(Protocol):
    """A provider may return only a raw ResearchPlanV1-shaped value."""

    name: str

    def invoke(self, request: ResearchProviderRequest) -> object:
        ...


class DisabledResearchProvider:
    """Inert adapter. It has no transport, credential, tool, or execution capability."""

    name = "disabled"

    def __init__(self, *, failure_code: str = RESEARCH_PROVIDER_DISABLED):
        self.failure_code = failure_code

    def invoke(self, request: ResearchProviderRequest) -> None:
        del request
        return None


def create_research_provider(
    configured_name: str | None = None,
) -> ResearchPlanningProvider:
    """Return an installed provider or the inert adapter; never guess a transport."""

    raw_name = configured_name
    if raw_name is None:
        raw_name = os.getenv("QL_RESEARCH_PROVIDER", "disabled")
    name = raw_name.strip().lower() if isinstance(raw_name, str) else ""
    if name == "disabled":
        return DisabledResearchProvider()
    return DisabledResearchProvider(failure_code=RESEARCH_PROVIDER_UNKNOWN)


__all__ = [
    "DisabledResearchProvider",
    "RESEARCH_PROVIDER_DISABLED",
    "RESEARCH_PROVIDER_UNKNOWN",
    "ResearchPlanningProvider",
    "create_research_provider",
]
