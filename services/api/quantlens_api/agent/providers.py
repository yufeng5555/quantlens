"""Provider factory for the Gate 6A local briefing boundary.

No live provider is installed.  Both the default and every unknown configuration return
the same inert adapter; an environment typo can therefore never trigger a guessed vendor,
credential scan, import, or network call.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from .contracts import (
    ProviderMetadata,
    ProviderRequest,
    UnavailableProviderResult,
)


FALLBACK_PROVIDER_DISABLED = "AGENT_PROVIDER_DISABLED"
FALLBACK_PROVIDER_UNKNOWN = "AGENT_PROVIDER_UNKNOWN"


@runtime_checkable
class BriefingProvider(Protocol):
    """Minimal synchronous provider contract; transports remain outside Gate 6A."""

    name: str

    def invoke(self, request: ProviderRequest) -> object:
        """Return a value validated as a strict provider result by the service."""
        ...


class DisabledBriefingProvider:
    """Inert provider that performs no I/O and reports an explicit failure code."""

    name = "disabled"

    def __init__(self, *, failure_code: str = FALLBACK_PROVIDER_DISABLED):
        self.failure_code = failure_code

    def invoke(self, request: ProviderRequest) -> UnavailableProviderResult:
        # Deliberately do not inspect hypothesis text.  It stays inside the deterministic
        # parser and cannot be logged or transmitted by this adapter.
        del request
        return UnavailableProviderResult(
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


def create_briefing_provider(configured_name: str | None = None) -> BriefingProvider:
    """Return only a known, installed provider; otherwise fail closed.

    Gate 6A knows exactly one safe value: ``disabled``.  Unknown names are not reflected
    into public metadata because environment values are configuration, not user content.
    """

    raw_name = configured_name
    if raw_name is None:
        raw_name = os.getenv("QL_AGENT_PROVIDER", "disabled")
    name = raw_name.strip().lower() if isinstance(raw_name, str) else ""
    if name == "disabled":
        return DisabledBriefingProvider()
    return DisabledBriefingProvider(failure_code=FALLBACK_PROVIDER_UNKNOWN)
