"""Active full-resolution read boundary for sealed ledger-v1 candidates.

Doc 47 §5.1 (binding): every product read must replay the complete dormant
ledger-v1 resolver — byte re-reads of the sealed ledger, wrappers and
receipt, the exact reviewed tuple, a registered build identity and an
independent semantic-validator replay — before any v3 view may be
constructed. Loading only the manifest and stored receipt is insufficient:
a post-seal mutation of ledger or wrapper bytes would otherwise never be
re-checked at the API, report or export boundary.

This module is the single reviewed ACTIVE importer of the dormant chain
(``candidate_seal_v3`` / ``evidence_contract_registry_v3``). The importer-set
and chain-dormancy laws name exactly this file, and the API consumes it only
inside its one product chokepoint (``_v3_checkpoint_response``: evidence,
report and export all pass through it).

Trusted-source law (recorded in doc 48): every component of the financial
validator registry handed to the independent replay must come from
control-plane-held trusted sources — Stop F2a registered expectations, the
active snapshot store, the anchor stores — never from candidate bytes, which
would let a candidate author its own trust anchors. Until F2a registers
those expectations no such source exists, so on every store this repository
can produce the read refuses in a typed way before the resolver runs: the
fail-closed posture doc 47 §8 requires ahead of activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .candidate_seal_v3 import load_sealed_candidate_v3
from .evidence_contract_registry import SEALED_BUILD_REGISTRATIONS
from .evidence_contract_registry_v3 import (
    GateELedgerV1ResolutionError,
    ReviewedGateEBuildRegistration,
    ReviewedGateERegistry,
    frozen_gate_e_active_tuple,
    resolve_dormant_ledger_v1_contract_v3,
)


# The frozen Gate-E identities this module needs are derived from the
# reviewed tuple builder rather than restated as literals, so no dormant
# marker value ever appears in an active source file.
_FROZEN_PROBE_TUPLE = frozen_gate_e_active_tuple(
    battery_config_hash="sha256:" + "0" * 64)
_ARTIFACT_PRODUCER = _FROZEN_PROBE_TUPLE.artifact_producer
_PRESENTATION_CONTRACT_ID = _FROZEN_PROBE_TUPLE.presentation_contract_id

# The five registered validator-registry components plus the authenticated
# plan anchors; each must arrive from a control-plane trusted source and be
# non-empty before the resolver may run.
_TRUSTED_COMPONENT_FIELDS = {
    "plan_anchors": "authenticated_plan_anchors",
    "financial_semantics": "registered_financial_semantics",
    "metric_semantics": "registered_metric_semantics",
    "calendars": "registered_calendars",
    "snapshots": "registered_snapshots",
    "validation_plans": "registered_validation_plans",
}


class V3ProductReadError(RuntimeError):
    """One typed fail-closed product-read refusal; carries no sealed values.

    ``reason`` is a closed identifier; when the dormant resolver itself
    refused, ``state`` and ``code`` carry its typed classification and no
    candidate-derived detail travels with them.
    """

    def __init__(
        self,
        reason: str,
        *,
        state: str | None = None,
        code: str | None = None,
    ):
        self.reason = reason
        self.state = state
        self.code = code
        detail = reason if code is None else f"{reason}:{state}:{code}"
        super().__init__(f"sealed candidate cannot be read: {detail}")


@dataclass(frozen=True)
class TrustedProductReadInputs:
    """Control-plane-held inputs for one product read.

    Every field is server-derived data the API layer assembles from its own
    store: the closed nine-field accepted-run envelope, the run identity the
    principal was authorized against, the authenticated plan anchors, and
    the five registered validator-registry components. None of these may be
    derived from candidate bytes. An empty mapping means "no trusted source
    exists" and the read refuses; Stop F2a is the stop that first registers
    these expectations.
    """

    accepted_run_envelope: Mapping[str, Any]
    expected_tenant_id: str
    expected_workspace_id: str
    expected_run_id: str
    authenticated_plan_anchors: Mapping[str, Mapping[str, Any]]
    registered_financial_semantics: Mapping[str, str]
    registered_metric_semantics: Mapping[str, str]
    registered_calendars: Mapping[str, Mapping[str, Any]]
    registered_snapshots: Mapping[str, Mapping[str, Any]]
    registered_validation_plans: Mapping[str, Mapping[str, Any]]


def resolve_v3_product_read(
    run_dir: Path, *, trusted: TrustedProductReadInputs,
) -> dict[str, Any]:
    """Fully re-resolve one sealed candidate for a product read, or refuse.

    The only production entry point (doc 47 §A1 pattern): it takes no
    build-registration or contract-registry argument, so no caller can
    substitute the registered build identities — they come from the sealed,
    hash-pinned shipped registry alone. Since the separately reviewed Stop
    F2b re-seal that registry carries exactly one corrected-contract
    registration (the frozen runtime identity), so a fully trusted-sourced
    read resolves only a candidate sealed by exactly that runtime; every
    other digest still refuses. Focused tests exercise the identical law
    through the private core with reviewed fixture registrations, which
    production code never imports.
    """
    registrations = tuple(
        ReviewedGateEBuildRegistration(
            presentation_contract_id=row.contract_id,
            image_digest=row.image_digest,
        )
        for row in SEALED_BUILD_REGISTRATIONS
        if row.contract_id == _PRESENTATION_CONTRACT_ID
    )
    return _resolve_v3_product_read_against(
        run_dir, trusted=trusted, build_registrations=registrations)


def _resolve_v3_product_read_against(
    run_dir: Path,
    *,
    trusted: TrustedProductReadInputs,
    build_registrations: Sequence[ReviewedGateEBuildRegistration],
) -> dict[str, Any]:
    """Private full-resolution core; build registrations are explicit here so
    the reviewed test harness can prove the identical law over a fixture
    registry. The law, identical for the production wrapper and the harness:

    1. every trusted component must be typed and non-empty (fail-closed
       until F2a registers the corrected expectations);
    2. the sealed candidate is re-read byte-for-byte from disk — ledger,
       wrappers, receipt and manifest all re-checked;
    3. the financial validator registry is assembled exclusively from the
       trusted inputs, never from candidate bytes;
    4. the complete dormant resolver runs, including the independent
       semantic-validator replay, before any view material is returned.
    """
    if not isinstance(trusted, TrustedProductReadInputs):
        raise V3ProductReadError("untyped_trusted_inputs")
    missing = sorted(
        component
        for component, field in _TRUSTED_COMPONENT_FIELDS.items()
        if not isinstance(getattr(trusted, field), Mapping)
        or not getattr(trusted, field)
    )
    if missing:
        raise V3ProductReadError(
            "trusted_sources_unavailable:" + ",".join(missing))

    try:
        loaded = load_sealed_candidate_v3(
            run_dir, reviewed_producers=(_ARTIFACT_PRODUCER,))
    except Exception as exc:
        # Any byte, wrapper or manifest-contract problem is one typed
        # refusal; no partially loaded material leaves this boundary.
        raise V3ProductReadError("candidate_unreadable") from exc

    manifest = loaded["manifest"]
    validator_registry = {
        "producers": [_ARTIFACT_PRODUCER],
        "financial_semantics": dict(trusted.registered_financial_semantics),
        "metric_semantics": dict(trusted.registered_metric_semantics),
        "calendars": {
            key: dict(value)
            for key, value in trusted.registered_calendars.items()
        },
        "snapshots": {
            key: dict(value)
            for key, value in trusted.registered_snapshots.items()
        },
        "validation_plans": {
            key: dict(value)
            for key, value in trusted.registered_validation_plans.items()
        },
    }
    reviewed_registry = ReviewedGateERegistry(
        financial_validator_registry=validator_registry,
        authenticated_plan_anchors={
            key: dict(value)
            for key, value in trusted.authenticated_plan_anchors.items()
        },
        accepted_run_envelope=dict(trusted.accepted_run_envelope),
        expected_tenant_id=trusted.expected_tenant_id,
        expected_workspace_id=trusted.expected_workspace_id,
        expected_run_id=trusted.expected_run_id,
    )
    try:
        reviewed_tuple = frozen_gate_e_active_tuple(
            battery_config_hash=manifest.get("battery_config_hash"))
        resolved = resolve_dormant_ledger_v1_contract_v3(
            manifest=manifest,
            ledger_index=loaded["ledger_index"],
            artifact_wrappers=loaded["artifact_wrappers"],
            semantic_receipt=loaded["semantic_receipt"],
            reviewed_active_tuple=reviewed_tuple,
            reviewed_build_registrations=list(build_registrations),
            reviewed_registry=reviewed_registry,
        )
    except GateELedgerV1ResolutionError as exc:
        raise V3ProductReadError(
            "resolution_refused", state=exc.state, code=exc.code) from exc
    return {
        "manifest": manifest,
        "semantic_receipt": loaded["semantic_receipt"],
        "resolved": resolved,
    }


__all__ = [
    "TrustedProductReadInputs",
    "V3ProductReadError",
    "resolve_v3_product_read",
]
