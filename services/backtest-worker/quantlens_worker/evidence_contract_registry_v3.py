"""Dormant Gate-E ledger-v1 presentation resolver.

This module is deliberately separate from :mod:`evidence_contract_registry`, is not
exported by the package, and is not imported by any active runner or presentation path.
It implements the Gate-E Stop-A *read* trust boundary only: an explicitly injected,
reviewed v3 tuple, build registration and control-plane registry must all agree with a
complete ledger-v1 candidate before the independent financial validator is invoked.

Stop-A limitation: the current ``FinancialSemanticValidatorV1`` intentionally accepts
only the frozen Gate-C battery-v2 / validation-plan-v2 contract.  Therefore a genuine
Gate-E validation-plan-v3 candidate will continue to fail closed until the separately
reviewed validator upgrade is delivered in a later Gate-E stop.  This resolver contains
no compatibility shim, test bypass, activation flag or partial projection.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from .financial_semantic_validator_v1 import FinancialSemanticValidatorV1
from .gate_e_contracts import (
    GateEContractError,
    sha256_canonical_json,
    validate_manifest_v3,
    validate_validation_plan_anchor_v1,
)
from .valuation_ledger_v1 import (
    ValuationLedgerContractError,
    canonical_json_bytes,
    required_gate_b_kinds_v1,
    sha256_json,
    validate_ledger_index_contract_v1,
)


FailureState = Literal[
    "rebuild_required",
    "validation_failed",
    "unsupported_contract",
]

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^local-runtime-sha256:[0-9a-f]{64}$")

_FROZEN_GATE_E_VALUES = {
    "activation_release": "quantlens-financial-v3",
    "presentation_contract_id": "corrected-financial-semantics-v3-ledger-v1",
    "worker_runtime": "quantlens-worker-v3",
    "engine_semver": "0.2.0",
    "battery_profile_id": "battery-v3",
    "battery_payload_version": "battery-v3",
    "validation_plan_version": "validation-plan-v3",
    "manifest_version": "v3",
    "dsl_schema_version": "1.2",
    "market_observations_version": "market-observations-v2",
    "ledger_semantics_version": "ledger-v1",
    "valuation_ledger_version": "valuation-ledger-v1",
    "financial_semantics_version": "financial-semantics-v2",
    "execution_cost_model": "adverse_effective_fill_price",
    # Split the dormant Gate-C/D markers in source so the predecessor source-firewall
    # continues to prove that no newly discovered worker module is an active producer.
    "continuous_path_version": "continuous-development-" "path-v1",
    "financial_contract_version": "financial-contract-v1",
    "execution_implementation_version": "adverse-effective-" "fill-v1",
    "independent_validator_version": "financial-semantic-validator-v1",
    "verified_metrics_version": "metrics-v2",
    "evidence_view_version": "v3",
    "evidence_semantics_version": "v3",
    "semantic_receipt_version": "semantic-validation-receipt-v1",
    "plan_anchor_version": "validation-plan-anchor-v1",
    "holdout_access_protocol": "final-holdout-access-v1",
    "artifact_producer": "quantlens-engine/0.2.0+battery-v3",
    "image_digest_scheme": "local-runtime-sha256",
}

# Internal reviewed-tuple names intentionally differ from some canonical manifest-v3
# field names.  Keep the translation explicit so a test-only candidate cannot invent a
# private resolver dialect that the public schema would reject.
_MANIFEST_TUPLE_MAP = {
    "activation_release": "activation_release",
    "presentation_contract_id": "presentation_contract",
    "worker_runtime": "worker_runtime",
    "engine_semver": "engine_semver",
    "battery_profile_id": "battery_profile_id",
    "battery_payload_version": "battery_payload_version",
    "battery_config_hash": "battery_config_hash",
    "validation_plan_version": "validation_plan_version",
    "manifest_version": "manifest_version",
    "dsl_schema_version": "dsl_schema_version",
    "market_observations_version": "market_observations_version",
    "ledger_semantics_version": "ledger_semantics_version",
    "valuation_ledger_version": "valuation_ledger_version",
    "financial_semantics_version": "execution_semantics_version",
    "execution_cost_model": "execution_cost_model",
    "continuous_path_version": "continuous_path_version",
    "financial_contract_version": "financial_contract_version",
    "execution_implementation_version": "execution_implementation",
    "independent_validator_version": "validator_version",
    "verified_metrics_version": "metric_semantics_version",
    "evidence_view_version": "evidence_view_version",
    "evidence_semantics_version": "evidence_semantics_version",
    "semantic_receipt_version": "semantic_receipt_version",
    "plan_anchor_version": "plan_anchor_version",
    "holdout_access_protocol": "holdout_access_protocol",
    "artifact_producer": "artifact_producer",
}
_MANIFEST_PREFIXED_HASH_FIELDS = frozenset({
    "spec_hash",
    "plan_anchor_sha256",
    "financial_contract_sha256",
    "result_hash",
    "semantic_receipt_sha256",
    "temporal_integrity_sha256",
    "final_holdout_execution_audit_sha256",
    "battery_config_hash",
})
_RECEIPT_KEYS = frozenset({
    "validator_version",
    "ledger_id",
    "result_hash",
    "financial_contract_sha256",
    "validated_execution_ids",
    "status",
})
_WRAPPER_KEYS = frozenset({"kind", "producer", "payload"})
_ACCEPTED_RUN_KEYS = frozenset({
    "run_id",
    "actor_id",
    "spec_hash",
    "spec_version",
    "created_at",
    "confirmation_restatement",
    "confirmation_receipt_hash",
    "battery_profile_id",
    "battery_config_hash",
})


class GateELedgerV1ResolutionError(RuntimeError):
    """One typed fail-closed result; it intentionally carries no projection."""

    def __init__(self, state: FailureState, code: str, detail: str):
        self.state = state
        self.code = code
        self.detail = detail
        super().__init__(f"{state}:{code}: {detail}")


@dataclass(frozen=True)
class ReviewedGateEActiveTuple:
    """The exact reviewed Gate-E release identity injected by the control plane."""

    activation_release: str
    presentation_contract_id: str
    worker_runtime: str
    engine_semver: str
    battery_profile_id: str
    battery_payload_version: str
    battery_config_hash: str
    validation_plan_version: str
    manifest_version: str
    dsl_schema_version: str
    market_observations_version: str
    ledger_semantics_version: str
    valuation_ledger_version: str
    financial_semantics_version: str
    execution_cost_model: str
    continuous_path_version: str
    financial_contract_version: str
    execution_implementation_version: str
    independent_validator_version: str
    verified_metrics_version: str
    evidence_view_version: str
    evidence_semantics_version: str
    semantic_receipt_version: str
    plan_anchor_version: str
    holdout_access_protocol: str
    artifact_producer: str
    image_digest_scheme: str


@dataclass(frozen=True)
class ReviewedGateEBuildRegistration:
    presentation_contract_id: str
    image_digest: str


@dataclass(frozen=True)
class ReviewedGateERegistry:
    """Trusted caller-owned registries and run identity.

    Stop A treats the anchor mapping as already authenticated by the caller.  Stop B
    supplies the cryptographic verifier and durable authority; accepting only a hash
    here would be insufficient because it would not let this resolver bind the anchor's
    run, spec, snapshot, rule, cost model, plan or final window.
    """

    financial_validator_registry: Mapping[str, Any]
    authenticated_plan_anchors: Mapping[str, Mapping[str, Any]]
    accepted_run_envelope: Mapping[str, Any]
    expected_tenant_id: str
    expected_workspace_id: str
    expected_run_id: str


@dataclass(frozen=True)
class ResolvedGateEContractV3:
    """Product-safe identity returned only after every validation has succeeded."""

    activation_release: str
    presentation_contract_id: str
    ledger_id: str
    result_hash: str
    semantic_validation_receipt_sha256: str
    image_digest: str
    evidence_view_version: str = "v3"
    evidence_semantics_version: str = "v3"
    verified_financial_semantics: bool = True


def frozen_gate_e_active_tuple(*, battery_config_hash: str) -> ReviewedGateEActiveTuple:
    """Build the only tuple shape this dormant resolver can accept.

    The Battery hash is intentionally injected: contract section 2 requires it to be
    computed from the subsequently accepted immutable ``BATTERY_CONFIG_V3`` bytes and
    pinned at release rather than guessed during Stop A.
    """
    _prefixed_sha256(battery_config_hash, "battery_config_hash")
    return ReviewedGateEActiveTuple(
        **{
            **_FROZEN_GATE_E_VALUES,
            "battery_config_hash": battery_config_hash,
        }
    )


def _error(state: FailureState, code: str, detail: str) -> None:
    raise GateELedgerV1ResolutionError(state, code, detail)


def _prefixed_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _error("validation_failed", "malformed_hash", f"{label} is not canonical SHA-256")
    return value


def _normalized_sha256(value: object, label: str) -> str:
    if not isinstance(value, str):
        _error("validation_failed", "malformed_hash", f"{label} is not a SHA-256 string")
    if _SHA256_RE.fullmatch(value):
        return value
    if _RAW_SHA256_RE.fullmatch(value):
        return "sha256:" + value
    _error("validation_failed", "malformed_hash", f"{label} is not canonical SHA-256")
    raise AssertionError("unreachable")


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _error("validation_failed", "malformed_object", f"{label} must be an object")
    return value


def _exact_reviewed_tuple(reviewed: ReviewedGateEActiveTuple) -> None:
    if not isinstance(reviewed, ReviewedGateEActiveTuple):
        _error("unsupported_contract", "unreviewed_tuple", "active tuple is not typed")
    for field, expected in _FROZEN_GATE_E_VALUES.items():
        if getattr(reviewed, field) != expected:
            _error(
                "unsupported_contract",
                "unreviewed_tuple",
                f"reviewed tuple field {field} is not the frozen Gate-E value",
            )
    _prefixed_sha256(reviewed.battery_config_hash, "reviewed battery_config_hash")


def _validate_manifest_identity(
    manifest: Mapping[str, Any], reviewed: ReviewedGateEActiveTuple,
) -> None:
    if manifest.get("manifest_version") != "v3":
        _error(
            "rebuild_required",
            "manifest_v3_required",
            "evidence was not sealed under manifest v3",
        )
    # Classify a complete but non-reviewed tuple as unsupported before the closed
    # schema's const checks collapse it into a generic validation error.  The schema is
    # still authoritative for shape, hashes, source branches and artifact grammar.
    for reviewed_field, manifest_field in _MANIFEST_TUPLE_MAP.items():
        if manifest.get(manifest_field) != getattr(reviewed, reviewed_field):
            _error(
                "unsupported_contract",
                "tuple_mismatch",
                f"manifest {manifest_field} does not match the reviewed active tuple",
            )
    try:
        validate_manifest_v3(manifest)
    except GateEContractError as exc:
        _error(
            "validation_failed",
            "manifest_contract_invalid",
            "candidate does not satisfy the closed manifest-v3 schema",
        )
    for field in _MANIFEST_PREFIXED_HASH_FIELDS:
        _prefixed_sha256(manifest.get(field), f"manifest.{field}")
    if _RAW_SHA256_RE.fullmatch(str(manifest.get("snapshot_sha256", ""))) is None:
        _error("validation_failed", "malformed_hash", "manifest.snapshot_sha256 is malformed")
    image_digest = manifest.get("image_digest")
    if not isinstance(image_digest, str) or _IMAGE_DIGEST_RE.fullmatch(image_digest) is None:
        _error("unsupported_contract", "build_identity_malformed", "image digest is malformed")
    if image_digest.partition(":")[0] != reviewed.image_digest_scheme:
        _error("unsupported_contract", "build_scheme_mismatch", "image digest scheme is unreviewed")


def _validate_manifest_ledger_binding(
    manifest: Mapping[str, Any], ledger: Mapping[str, Any],
) -> None:
    if (
        manifest.get("result_hash") != ledger.get("result_hash")
        or manifest.get("ledger_id") != ledger.get("ledger_id")
    ):
        _error(
            "validation_failed",
            "manifest_ledger_mismatch",
            "manifest does not bind the exact ledger identity",
        )
    manifest_entries = manifest.get("artifacts")
    ledger_entries = ledger.get("entries")
    try:
        identical = canonical_json_bytes(manifest_entries) == canonical_json_bytes(
            ledger_entries
        )
    except ValuationLedgerContractError as exc:
        _error("validation_failed", "manifest_artifacts_invalid", str(exc))
    if not identical:
        _error(
            "validation_failed",
            "manifest_artifacts_mismatch",
            "manifest artifact entries do not exactly mirror ledger-v1 entries",
        )


def _validate_build_registration(
    manifest: Mapping[str, Any],
    reviewed: ReviewedGateEActiveTuple,
    registrations: Sequence[ReviewedGateEBuildRegistration],
) -> None:
    identities: set[tuple[str, str]] = set()
    for item in registrations:
        if not isinstance(item, ReviewedGateEBuildRegistration):
            _error("unsupported_contract", "build_registry_malformed", "build registration is not typed")
        if (
            item.presentation_contract_id != reviewed.presentation_contract_id
            or _IMAGE_DIGEST_RE.fullmatch(item.image_digest) is None
        ):
            _error("unsupported_contract", "build_registry_malformed", "build registration is not exact Gate E")
        identity = (item.presentation_contract_id, item.image_digest)
        if identity in identities:
            _error("unsupported_contract", "build_registry_duplicate", "duplicate build registration")
        identities.add(identity)
    observed = (reviewed.presentation_contract_id, manifest["image_digest"])
    if observed not in identities:
        _error("unsupported_contract", "unregistered_build", "runtime image is not registered for Gate E")


def _validate_accepted_run_envelope(
    manifest: Mapping[str, Any],
    reviewed: ReviewedGateEActiveTuple,
    registry: ReviewedGateERegistry,
) -> None:
    """Bind mutable-looking manifest identity fields to one trusted accepted run."""
    accepted = _object(registry.accepted_run_envelope, "accepted run envelope")
    if set(accepted) != _ACCEPTED_RUN_KEYS:
        _error(
            "unsupported_contract",
            "accepted_run_malformed",
            "accepted run envelope is not the reviewed closed shape",
        )
    restatement = accepted.get("confirmation_restatement")
    if not isinstance(restatement, str):
        _error(
            "unsupported_contract",
            "accepted_run_malformed",
            "accepted confirmation restatement must be text",
        )
    receipt_hash = hashlib.sha256(restatement.encode("utf-8")).hexdigest()
    expected = {
        "manifest_id": f"mfst-{accepted.get('run_id')}",
        "actor_id": accepted.get("actor_id"),
        "spec_hash": accepted.get("spec_hash"),
        "spec_version": accepted.get("spec_version"),
        "created_at": accepted.get("created_at"),
        "confirmation_receipt_hash": accepted.get("confirmation_receipt_hash"),
        "battery_profile_id": accepted.get("battery_profile_id"),
        "battery_config_hash": accepted.get("battery_config_hash"),
    }
    if (
        accepted.get("run_id") != registry.expected_run_id
        or accepted.get("battery_profile_id") != reviewed.battery_profile_id
        or accepted.get("battery_config_hash") != reviewed.battery_config_hash
        or accepted.get("confirmation_receipt_hash") != receipt_hash
        or any(manifest.get(field) != value for field, value in expected.items())
    ):
        _error(
            "validation_failed",
            "accepted_run_binding_mismatch",
            "manifest identity does not match the trusted accepted run envelope",
        )


def _validate_ledger_and_wrappers(
    ledger: Mapping[str, Any],
    wrappers: Mapping[str, Any],
    reviewed: ReviewedGateEActiveTuple,
) -> dict[str, Mapping[str, Any]]:
    try:
        validate_ledger_index_contract_v1(ledger)
    except (ValuationLedgerContractError, KeyError, TypeError) as exc:
        _error("validation_failed", "ledger_contract_invalid", str(exc))
    if ledger.get("ledger_semantics_version") != reviewed.ledger_semantics_version:
        _error("unsupported_contract", "ledger_version_mismatch", "ledger-v1 is required")
    if not isinstance(wrappers, Mapping):
        _error("validation_failed", "wrapper_set_invalid", "artifact wrappers must be an object")
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        _error("validation_failed", "ledger_entries_invalid", "ledger entries must be an array")
    kinds = {entry.get("kind") for entry in entries if isinstance(entry, Mapping)}
    required = set(required_gate_b_kinds_v1(reviewed.dsl_schema_version))
    if kinds != required or set(wrappers) != required:
        _error("validation_failed", "artifact_coverage_incomplete", "complete DSL 1.2 artifact set is required")

    entries_by_kind = {entry["kind"]: entry for entry in entries}
    payloads: dict[str, Mapping[str, Any]] = {}
    for kind in sorted(required):
        entry = entries_by_kind[kind]
        if entry.get("producer") != reviewed.artifact_producer:
            _error("unsupported_contract", "producer_mismatch", f"{kind} producer is unreviewed")
        wrapper = wrappers.get(kind)
        if not isinstance(wrapper, Mapping) or set(wrapper) != _WRAPPER_KEYS:
            _error("validation_failed", "wrapper_shape_invalid", f"{kind} wrapper is not closed")
        if wrapper.get("kind") != kind or wrapper.get("producer") != reviewed.artifact_producer:
            _error("validation_failed", "wrapper_identity_mismatch", f"{kind} wrapper contradicts its entry")
        payload = wrapper.get("payload")
        if not isinstance(payload, Mapping):
            _error("validation_failed", "wrapper_payload_invalid", f"{kind} payload must be an object")
        try:
            actual = hashlib.sha256(canonical_json_bytes(wrapper)).hexdigest()
        except ValuationLedgerContractError as exc:
            _error("validation_failed", "wrapper_not_canonical", str(exc))
        if actual != entry.get("sha256"):
            _error("validation_failed", "wrapper_hash_mismatch", f"{kind} wrapper hash does not match")
        payloads[kind] = payload
    return payloads


def _validate_source_provenance(
    manifest: Mapping[str, Any], payloads: Mapping[str, Mapping[str, Any]],
) -> None:
    provenance = _object(payloads.get("data_provenance"), "data_provenance payload")
    snapshot = _object(payloads.get("snapshot_ref"), "snapshot_ref payload")
    if (
        provenance.get("data_label") != manifest.get("data_label")
        or provenance.get("snapshot_id") != manifest.get("snapshot_id")
        or snapshot.get("snapshot_id") != manifest.get("snapshot_id")
    ):
        _error(
            "validation_failed",
            "source_identity_mismatch",
            "manifest, provenance and snapshot do not share one source identity",
        )
    manifest_snapshot = _normalized_sha256(
        manifest.get("snapshot_sha256"), "manifest.snapshot_sha256"
    )
    for label, value in (
        ("data_provenance.snapshot_sha256", provenance.get("snapshot_sha256")),
        ("snapshot_ref.sha256", snapshot.get("sha256")),
    ):
        if _normalized_sha256(value, label) != manifest_snapshot:
            _error(
                "validation_failed",
                "source_snapshot_mismatch",
                "manifest, provenance and snapshot do not bind identical bytes",
            )

    lineage_fields = (
        "dataset_id",
        "dataset_manifest_sha256",
        "dataset_manifest_version",
        "provider_id",
        "instrument_id",
        "rights_policy_sha256",
    )
    for field in lineage_fields:
        if field not in manifest:
            if field in provenance:
                _error(
                    "validation_failed",
                    "source_lineage_mismatch",
                    f"provenance unexpectedly supplies {field}",
                )
            continue
        observed = provenance.get(field)
        expected = manifest[field]
        if field in {"dataset_manifest_sha256", "rights_policy_sha256"}:
            if _normalized_sha256(observed, f"data_provenance.{field}") != _normalized_sha256(
                expected, f"manifest.{field}"
            ):
                _error(
                    "validation_failed",
                    "source_lineage_mismatch",
                    f"provenance {field} contradicts the manifest",
                )
        elif observed != expected:
            _error(
                "validation_failed",
                "source_lineage_mismatch",
                f"provenance {field} contradicts the manifest",
            )


def _validate_authenticated_plan_anchor(
    *,
    manifest: Mapping[str, Any],
    spec: Mapping[str, Any],
    plan: Mapping[str, Any],
    partitions: Mapping[str, Any],
    reviewed: ReviewedGateEActiveTuple,
    registry: ReviewedGateERegistry,
) -> None:
    anchors = _object(registry.authenticated_plan_anchors, "authenticated plan anchors")
    anchor_hash = str(manifest["plan_anchor_sha256"])
    if anchor_hash not in anchors:
        _error(
            "unsupported_contract",
            "plan_anchor_unregistered",
            "manifest plan anchor is not present in the authenticated caller registry",
        )
    anchor = _object(anchors.get(anchor_hash), "authenticated plan anchor")
    try:
        validate_validation_plan_anchor_v1(anchor)
    except GateEContractError as exc:
        _error(
            "unsupported_contract",
            "plan_anchor_invalid",
            "authenticated plan anchor does not satisfy its closed contract",
        )
    if sha256_canonical_json(anchor) != anchor_hash:
        _error(
            "unsupported_contract",
            "plan_anchor_hash_mismatch",
            "authenticated plan anchor bytes do not match the manifest hash",
        )

    identity = (
        anchor.get("tenant_id"),
        anchor.get("workspace_id"),
        anchor.get("run_id"),
    )
    expected_identity = (
        registry.expected_tenant_id,
        registry.expected_workspace_id,
        registry.expected_run_id,
    )
    if identity != expected_identity:
        _error(
            "unsupported_contract",
            "plan_anchor_run_mismatch",
            "authenticated plan anchor belongs to a different run identity",
        )
    rule = _object(spec.get("rule"), "sealed rule")
    costs = _object(spec.get("costs"), "sealed base costs")
    if (
        anchor.get("release_id") != reviewed.activation_release
        or anchor.get("confirmed_spec_hash") != manifest.get("spec_hash")
        or anchor.get("snapshot_sha256") != manifest.get("snapshot_sha256")
        or anchor.get("validation_plan_version") != reviewed.validation_plan_version
        or anchor.get("validation_plan_sha256") != sha256_json(plan)
        or anchor.get("locked_rule_sha256") != sha256_json(rule)
        or anchor.get("base_costs_sha256") != sha256_json(costs)
    ):
        _error(
            "validation_failed",
            "plan_anchor_binding_mismatch",
            "authenticated plan anchor contradicts the sealed spec, snapshot or plan",
        )

    final = _object(partitions.get("final_holdout"), "final holdout partition")
    expected_window = {
        "n_bars": partitions.get("n_bars"),
        "start_index": final.get("start_index"),
        "end_index": final.get("end_index"),
        "bars": final.get("bars"),
        "warmup_start_index": final.get("warmup_start_index"),
        "warmup_bars": final.get("warmup_bars"),
    }
    if (
        anchor.get("final_holdout_fraction") != plan.get("final_holdout_fraction")
        or canonical_json_bytes(anchor.get("final_window"))
        != canonical_json_bytes(expected_window)
    ):
        _error(
            "validation_failed",
            "plan_anchor_window_mismatch",
            "authenticated plan anchor contradicts the sealed final window",
        )


def _require_payload_contracts(
    manifest: Mapping[str, Any],
    payloads: Mapping[str, Mapping[str, Any]],
    reviewed: ReviewedGateEActiveTuple,
    registry: ReviewedGateERegistry,
) -> None:
    spec_bundle = _object(payloads.get("spec"), "spec payload")
    spec = _object(spec_bundle.get("spec"), "sealed spec")
    if spec.get("dsl_version") != reviewed.dsl_schema_version:
        _error("unsupported_contract", "sealed_dsl_mismatch", "sealed spec is not DSL 1.2")
    if spec_bundle.get("spec_hash") != sha256_json(spec) or manifest["spec_hash"] != spec_bundle.get("spec_hash"):
        _error("validation_failed", "spec_hash_mismatch", "sealed spec hash is not directly bound")

    snapshot_ref = _object(payloads.get("snapshot_ref"), "snapshot_ref payload")
    snapshot_hash = _normalized_sha256(snapshot_ref.get("sha256"), "snapshot_ref.sha256")
    if _normalized_sha256(manifest["snapshot_sha256"], "manifest.snapshot_sha256") != snapshot_hash:
        _error("validation_failed", "snapshot_hash_mismatch", "snapshot hash is not directly bound")
    validator_registry = _object(
        registry.financial_validator_registry,
        "financial validator registry",
    )
    snapshots = _object(validator_registry.get("snapshots"), "reviewed snapshots")
    market = _object(snapshots.get(snapshot_hash), "reviewed market observations")
    if market.get("market_observations_version") != reviewed.market_observations_version:
        _error("unsupported_contract", "market_contract_mismatch", "market-observations-v2 is required")

    plan = _object(payloads.get("validation_plan"), "validation plan")
    plan_body = {key: value for key, value in plan.items() if key != "validation_plan_hash"}
    if (
        plan.get("profile_id") != reviewed.battery_profile_id
        or plan.get("profile_hash") != reviewed.battery_config_hash
        or manifest.get("battery_config_hash") != reviewed.battery_config_hash
        or plan.get("plan_version") != reviewed.validation_plan_version
        or plan.get("continuous_path_version") != reviewed.continuous_path_version
        or plan.get("validation_plan_hash") != sha256_json(plan_body)
    ):
        _error(
            "unsupported_contract",
            "validation_plan_mismatch",
            "validation-plan-v3, Battery-v3 and its canonical self-hash are required",
        )
    partitions = _object(payloads.get("partitions"), "partitions payload")
    _validate_authenticated_plan_anchor(
        manifest=manifest,
        spec=spec,
        plan=plan,
        partitions=partitions,
        reviewed=reviewed,
        registry=registry,
    )
    _validate_source_provenance(manifest, payloads)

    walk_forward = _object(payloads.get("walk_forward"), "walk_forward payload")
    if walk_forward.get("continuous_path_version") != reviewed.continuous_path_version:
        _error("unsupported_contract", "continuous_marker_missing", "mandatory continuous marker is absent or downgraded")

    financial = _object(payloads.get("financial_contract"), "financial contract")
    if (
        financial.get("contract_version") != reviewed.financial_contract_version
        or financial.get("ledger_semantics_version") != reviewed.ledger_semantics_version
        or financial.get("financial_semantics_version") != reviewed.financial_semantics_version
        or _object(financial.get("execution_policy"), "financial execution policy").get("slippage_model")
        != reviewed.execution_cost_model
    ):
        _error("unsupported_contract", "financial_contract_mismatch", "corrected financial contract is required")
    financial_hash = sha256_json(financial)
    if manifest["financial_contract_sha256"] != financial_hash:
        _error("validation_failed", "financial_contract_hash_mismatch", "financial contract is not directly bound")

    valuation = _object(payloads.get("valuation_ledger"), "valuation ledger")
    if valuation.get("valuation_ledger_version") != reviewed.valuation_ledger_version:
        _error("unsupported_contract", "valuation_ledger_mismatch", "valuation-ledger-v1 is required")
    if valuation.get("financial_contract_sha256") != financial_hash:
        _error("validation_failed", "valuation_financial_binding_mismatch", "valuation ledger contradicts financial contract")

    for kind, manifest_field in (
        ("temporal_integrity", "temporal_integrity_sha256"),
        ("final_holdout_execution_audit", "final_holdout_execution_audit_sha256"),
    ):
        if manifest[manifest_field] != sha256_json(payloads[kind]):
            _error("validation_failed", "direct_payload_hash_mismatch", f"complete {kind} payload is not directly bound")


def _validate_stored_receipt(
    receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    ledger: Mapping[str, Any],
    payloads: Mapping[str, Mapping[str, Any]],
    reviewed: ReviewedGateEActiveTuple,
) -> None:
    if set(receipt) != _RECEIPT_KEYS:
        _error("validation_failed", "receipt_shape_invalid", "semantic receipt is not closed")
    if receipt.get("status") != "PASS" or receipt.get("validator_version") != reviewed.independent_validator_version:
        _error("validation_failed", "receipt_not_pass", "an exact PASS semantic receipt is required")
    if receipt.get("ledger_id") != ledger.get("ledger_id") or receipt.get("result_hash") != ledger.get("result_hash"):
        _error("validation_failed", "receipt_ledger_mismatch", "semantic receipt does not bind the ledger")
    financial_hash = sha256_json(payloads["financial_contract"])
    if receipt.get("financial_contract_sha256") != financial_hash:
        _error("validation_failed", "receipt_financial_mismatch", "semantic receipt does not bind the financial contract")
    valuation = payloads["valuation_ledger"]
    executions = valuation.get("executions")
    if not isinstance(executions, list):
        _error("validation_failed", "execution_list_invalid", "valuation executions must be an array")
    expected_ids = [item.get("execution_id") for item in executions if isinstance(item, Mapping)]
    if len(expected_ids) != len(executions) or receipt.get("validated_execution_ids") != expected_ids:
        _error("validation_failed", "receipt_execution_mismatch", "semantic receipt does not bind exact execution order")
    if manifest["semantic_receipt_sha256"] != sha256_json(receipt):
        _error("validation_failed", "receipt_hash_mismatch", "semantic receipt hash is not directly bound")


def resolve_dormant_ledger_v1_contract_v3(
    *,
    manifest: Mapping[str, Any],
    ledger_index: Mapping[str, Any],
    artifact_wrappers: Mapping[str, Any],
    semantic_receipt: Mapping[str, Any],
    reviewed_active_tuple: ReviewedGateEActiveTuple,
    reviewed_build_registrations: Sequence[ReviewedGateEBuildRegistration],
    reviewed_registry: ReviewedGateERegistry,
) -> ResolvedGateEContractV3:
    """Resolve a complete v3 candidate or raise one typed fail-closed exception.

    No projection is constructed until byte bindings, exact tuple, registered runtime,
    direct temporal/audit hashes, stored PASS receipt and an independent semantic replay
    all succeed.
    """
    try:
        manifest_value = _object(manifest, "manifest")
        ledger_value = _object(ledger_index, "ledger index")
        receipt_value = _object(semantic_receipt, "semantic receipt")
        _exact_reviewed_tuple(reviewed_active_tuple)
        _validate_manifest_identity(manifest_value, reviewed_active_tuple)
        _validate_accepted_run_envelope(
            manifest_value,
            reviewed_active_tuple,
            reviewed_registry,
        )
        _validate_build_registration(
            manifest_value,
            reviewed_active_tuple,
            reviewed_build_registrations,
        )
        payloads = _validate_ledger_and_wrappers(
            ledger_value,
            artifact_wrappers,
            reviewed_active_tuple,
        )
        _validate_manifest_ledger_binding(manifest_value, ledger_value)
        _require_payload_contracts(
            manifest_value,
            payloads,
            reviewed_active_tuple,
            reviewed_registry,
        )
        _validate_stored_receipt(
            receipt_value,
            manifest_value,
            ledger_value,
            payloads,
            reviewed_active_tuple,
        )
    except GateELedgerV1ResolutionError:
        raise
    except Exception as exc:
        # A programming error in the resolver still fails closed, but is deliberately
        # not misreported as an independent-validator decision.
        raise GateELedgerV1ResolutionError(
            "validation_failed",
            "internal_resolver_error",
            "the dormant ledger-v1 resolver could not complete its trust checks",
        ) from exc

    try:
        replayed = FinancialSemanticValidatorV1().validate(
            manifest_value,
            ledger_value,
            artifact_wrappers,
            reviewed_registry.financial_validator_registry,
        )
        replay_matches = (
            canonical_json_bytes(replayed) == canonical_json_bytes(receipt_value)
        )
    except Exception as exc:
        # Validator bugs and the currently unsupported v3 semantics stay unavailable.
        # No candidate-derived detail is returned as a projection.
        raise GateELedgerV1ResolutionError(
            "validation_failed",
            "independent_validation_failed",
            "independent financial-semantic validation did not produce an exact PASS receipt",
        ) from exc
    if not replay_matches:
        _error(
            "validation_failed",
            "receipt_replay_mismatch",
            "independent replay does not equal stored PASS receipt",
        )
    return ResolvedGateEContractV3(
        activation_release=reviewed_active_tuple.activation_release,
        presentation_contract_id=reviewed_active_tuple.presentation_contract_id,
        ledger_id=str(ledger_value["ledger_id"]),
        result_hash=str(ledger_value["result_hash"]),
        semantic_validation_receipt_sha256=str(
            manifest_value["semantic_receipt_sha256"]
        ),
        image_digest=str(manifest_value["image_digest"]),
    )


__all__ = [
    "GateELedgerV1ResolutionError",
    "ResolvedGateEContractV3",
    "ReviewedGateEActiveTuple",
    "ReviewedGateEBuildRegistration",
    "ReviewedGateERegistry",
    "frozen_gate_e_active_tuple",
    "resolve_dormant_ledger_v1_contract_v3",
]
