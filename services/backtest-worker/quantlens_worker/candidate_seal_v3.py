"""Sealed v3 candidate assembly and double validation (Gate E Stop C4).

Joins the development-side evidence payloads with the final-holdout payloads
into the complete eighteen-kind artifact set, writes the candidate through the
existing write-once dormant ledger writer, runs the independent semantic
validator before anything is treated as sealed, builds the manifest around the
resulting receipt, and re-opens the written bytes through the dormant v3
resolver so a candidate is only ever accepted after both an in-memory and an
on-disk proof.

The manifest is written into its own sibling directory so the frozen candidate
directory closure law stays exactly as its owner wrote it, and neither of the
active checkpoint names is ever created — a sealed candidate here is evidence
for review, never an activation.

Nothing in this module registers a runtime, a plan anchor or a release: the
reviewed registry, producer allowlist and build registration all arrive as
explicit caller inputs, and production registration remains a later stop.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evidence_contract_registry_v3 import (
    _MANIFEST_TUPLE_MAP,
    ReviewedGateEBuildRegistration,
    ReviewedGateERegistry,
    frozen_gate_e_active_tuple,
    resolve_dormant_ledger_v1_contract_v3,
)
from .gate_e_contracts import (
    GATE_E_ARTIFACT_KINDS,
    GATE_E_ARTIFACT_PRODUCER,
    GATE_E_CONTINUOUS_PATH_VERSION,
    GATE_E_EXECUTION_IMPLEMENTATION,
    validate_manifest_v3,
)
from .temporal_integrity import build_temporal_integrity_receipt
from .valuation_ledger_io import (
    CANDIDATE_DIRECTORY_NAME,
    _write_once,
    load_dormant_candidate_ledger_v1,
    validate_and_store_semantic_receipt_v1,
    write_dormant_candidate_ledger_v1,
)
from .valuation_ledger_v1 import build_valuation_ledger_v1, sha256_json

SEAL_DIRECTORY_NAME = "ledger-v1-candidate-seal"
MANIFEST_FILENAME = "manifest_v3.json"

_DEVELOPMENT_KINDS = (
    "development_result", "walk_forward", "regime_analysis", "sensitivity",
    "cost_stress", "falsification",
)
# Every const-pinned manifest identifier is emitted from the reviewed active
# tuple through the registry's own attribute->field map, so this module can
# never drift from the sealed manifest contract.


class CandidateSealV3Error(RuntimeError):
    """One candidate input contradicts the sealed v3 artifact law."""


def _fail(detail: str) -> None:
    raise CandidateSealV3Error(detail)


def _require(condition: bool, detail: str) -> None:
    if not condition:
        _fail(detail)


def _fresh(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        raise CandidateSealV3Error(
            f"{label} must contain only finite canonical JSON values"
        ) from exc


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def assemble_candidate_payloads_v3(
    *,
    spec: Mapping[str, Any],
    validation_plan: Mapping[str, Any],
    partitions: Mapping[str, Any],
    financial_contract: Mapping[str, Any],
    development_evidence: Mapping[str, Any],
    development_executions: Sequence[Mapping[str, Any]],
    final_projection: Mapping[str, Any],
    final_holdout_execution_audit: Mapping[str, Any],
    snapshot_ref: Mapping[str, Any],
    data_provenance: Mapping[str, Any],
    data_gaps: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Join the development and final payloads into the eighteen sealed kinds."""
    spec = _fresh(dict(spec), "spec")
    validation_plan = _fresh(dict(validation_plan), "validation_plan")
    partitions = _fresh(dict(partitions), "partitions")
    financial_contract = _fresh(dict(financial_contract), "financial_contract")
    development_evidence = _fresh(
        dict(development_evidence), "development_evidence")
    final_projection = _fresh(dict(final_projection), "final_projection")
    audit = _fresh(dict(final_holdout_execution_audit), "final audit")

    _require(spec.get("dsl_version") == "1.2",
             "a sealed v3 candidate requires the sealed DSL 1.2 spec")
    _require(validation_plan.get("plan_version") == "validation-plan-v3",
             "the sealed plan is not a validation-plan-v3 payload")
    _require(partitions.get("partition_version") == "validation-partitions-v3",
             "the sealed partitions are not a validation-partitions-v3 payload")
    _require(
        development_evidence["walk_forward"]["continuous_path_version"]
        == validation_plan["continuous_path_version"],
        "the development evidence and sealed plan disagree on the "
        "continuous-path contract",
    )
    _require(
        audit["execution_binding"]["validation_plan_hash"]
        == validation_plan["validation_plan_hash"],
        "the final audit binds a different validation plan",
    )

    spec_hash = sha256_json(spec)
    snapshot_sha256 = snapshot_ref["sha256"]
    if not str(snapshot_sha256).startswith("sha256:"):
        snapshot_sha256 = "sha256:" + str(snapshot_sha256)

    executions = [dict(item) for item in development_executions]
    executions.extend(
        dict(final_projection["executions"][role])
        for role in ("strategy", "benchmark"))
    valuation_ledger = build_valuation_ledger_v1(
        financial_contract=financial_contract,
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        executions=executions,
    )

    # The development projector cannot know the final status; the sealed
    # candidate owns that one field and leaves the re-derived battery status
    # untouched.
    evidence_status = dict(development_evidence["evidence_status"])
    evidence_status["final_holdout_status"] = "COMPLETE"

    temporal_integrity = build_temporal_integrity_receipt(
        validation_plan=validation_plan,
        partitions=partitions,
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        final_audit=audit,
    )

    payloads: dict[str, dict[str, Any]] = {
        "spec": {"spec": spec, "spec_hash": spec_hash},
        "validation_plan": validation_plan,
        "partitions": partitions,
        "financial_contract": financial_contract,
        "valuation_ledger": valuation_ledger,
        "final_holdout_result": final_projection["final_holdout_result"],
        "final_holdout_execution_audit": audit,
        "temporal_integrity": temporal_integrity,
        "evidence_status": evidence_status,
        "data_gaps": _fresh(dict(data_gaps), "data_gaps"),
        "data_provenance": _fresh(dict(data_provenance), "data_provenance"),
        "snapshot_ref": _fresh(dict(snapshot_ref), "snapshot_ref"),
    }
    for kind in _DEVELOPMENT_KINDS:
        payloads[kind] = development_evidence[kind]

    _require(
        set(payloads) == set(GATE_E_ARTIFACT_KINDS),
        "the assembled candidate does not carry exactly the sealed artifact "
        "kinds",
    )
    return _fresh(payloads, "candidate payloads")


def build_manifest_v3(
    *,
    run_id: str,
    actor_id: str,
    created_at: str,
    spec_version: int,
    snapshot_id: str,
    data_label: str,
    image_digest: str,
    battery_config_hash: str,
    confirmation_receipt_hash: str,
    plan_anchor_sha256: str,
    ledger_index: Mapping[str, Any],
    payloads: Mapping[str, Mapping[str, Any]],
    semantic_receipt: Mapping[str, Any],
    lineage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and validate the closed manifest-v3 around a stored receipt."""
    reviewed = frozen_gate_e_active_tuple(
        battery_config_hash=battery_config_hash)
    snapshot_sha256 = str(payloads["snapshot_ref"]["sha256"])
    if snapshot_sha256.startswith("sha256:"):
        snapshot_sha256 = snapshot_sha256[len("sha256:"):]

    manifest: dict[str, Any] = {
        field: getattr(reviewed, attribute)
        for attribute, field in _MANIFEST_TUPLE_MAP.items()
    }
    manifest.update({
        # manifest-v3 is a closed schema: the run identity reaches it only
        # through the derived manifest id.
        "manifest_id": f"mfst-{run_id}",
        "actor_id": actor_id,
        "created_at": created_at,
        "spec_hash": payloads["spec"]["spec_hash"],
        "spec_version": spec_version,
        "snapshot_id": snapshot_id,
        "snapshot_sha256": snapshot_sha256,
        "data_label": data_label,
        "image_digest": image_digest,
        "confirmation_receipt_hash": confirmation_receipt_hash,
        "plan_anchor_sha256": plan_anchor_sha256,
        "financial_contract_sha256": sha256_json(
            payloads["financial_contract"]),
        "temporal_integrity_sha256": sha256_json(
            payloads["temporal_integrity"]),
        "final_holdout_execution_audit_sha256": sha256_json(
            payloads["final_holdout_execution_audit"]),
        "semantic_receipt_sha256": sha256_json(semantic_receipt),
        "ledger_id": ledger_index["ledger_id"],
        "result_hash": ledger_index["result_hash"],
        "artifacts": copy.deepcopy(list(ledger_index["entries"])),
    })
    if lineage:
        manifest.update(_fresh(dict(lineage), "lineage"))
    return validate_manifest_v3(manifest)


def seal_candidate_v3(
    run_dir: Path,
    *,
    payloads: Mapping[str, Mapping[str, Any]],
    validator_registry: Mapping[str, Any],
    resolver_registry: ReviewedGateERegistry,
    reviewed_build_registrations: Sequence[ReviewedGateEBuildRegistration],
    reviewed_producers: Sequence[str],
    manifest_fields: Mapping[str, Any],
    producer: str = GATE_E_ARTIFACT_PRODUCER,
) -> dict[str, Any]:
    """Write, doubly validate and seal one complete v3 candidate.

    Order: write the candidate artifacts write-once; validate the reopened
    bytes with the independent semantic validator and persist its receipt only
    on success; build the manifest around that receipt; write the manifest
    write-once; then re-open everything and resolve it through the dormant v3
    resolver.  A pre-seal validation failure raises before the manifest exists.
    """
    run_dir = Path(run_dir)
    _require(
        isinstance(resolver_registry, ReviewedGateERegistry),
        "the resolver trust boundary requires the reviewed registry type",
    )
    _require(
        all(isinstance(item, ReviewedGateEBuildRegistration)
            for item in reviewed_build_registrations),
        "build registrations must be the reviewed registration type",
    )
    ledger_index = write_dormant_candidate_ledger_v1(
        run_dir, payloads, producer=producer,
        reviewed_producers=list(reviewed_producers))

    preseal_manifest = {
        "result_hash": ledger_index["result_hash"],
        "spec_hash": payloads["spec"]["spec_hash"],
        "snapshot_sha256": payloads["snapshot_ref"]["sha256"],
    }
    receipt = validate_and_store_semantic_receipt_v1(
        run_dir, manifest=preseal_manifest,
        reviewed_registry=validator_registry,
        reviewed_producers=list(reviewed_producers))

    manifest = build_manifest_v3(
        ledger_index=ledger_index, payloads=payloads,
        semantic_receipt=receipt, **manifest_fields)
    seal_dir = run_dir / SEAL_DIRECTORY_NAME
    seal_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_once(seal_dir / MANIFEST_FILENAME, _canonical_bytes(manifest))

    # Post-read proof: nothing is sealed until the written bytes resolve.
    reloaded = load_sealed_candidate_v3(run_dir,
                                        reviewed_producers=reviewed_producers)
    resolved = resolve_dormant_ledger_v1_contract_v3(
        manifest=reloaded["manifest"],
        ledger_index=reloaded["ledger_index"],
        artifact_wrappers=reloaded["artifact_wrappers"],
        semantic_receipt=reloaded["semantic_receipt"],
        reviewed_active_tuple=frozen_gate_e_active_tuple(
            battery_config_hash=manifest["battery_config_hash"]),
        reviewed_build_registrations=list(reviewed_build_registrations),
        reviewed_registry=resolver_registry,
    )
    _require(
        not (run_dir / "manifest.json").exists()
        and not (run_dir / "ledger_index.json").exists(),
        "a sealed candidate must never create an active checkpoint name",
    )
    return {
        "run_dir": run_dir,
        "candidate_dir": run_dir / CANDIDATE_DIRECTORY_NAME,
        "seal_dir": seal_dir,
        "manifest": manifest,
        "ledger_index": ledger_index,
        "semantic_receipt": receipt,
        "resolved": resolved,
    }


def load_sealed_candidate_v3(
    run_dir: Path, *, reviewed_producers: Sequence[str],
) -> dict[str, Any]:
    """Re-open one sealed candidate from disk with full byte re-verification."""
    run_dir = Path(run_dir)
    candidate = load_dormant_candidate_ledger_v1(
        run_dir, reviewed_producers=list(reviewed_producers))
    manifest_path = run_dir / SEAL_DIRECTORY_NAME / MANIFEST_FILENAME
    receipt_path = (
        run_dir / CANDIDATE_DIRECTORY_NAME / "semantic_validation_receipt.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CandidateSealV3Error(
            "the sealed manifest or its receipt is missing or unreadable"
        ) from exc
    return {
        "manifest": validate_manifest_v3(manifest),
        "ledger_index": candidate["ledger_index"],
        "artifact_wrappers": candidate["artifact_wrappers"],
        "semantic_receipt": receipt,
        "payloads": candidate["payloads"],
    }


__all__ = [
    "MANIFEST_FILENAME",
    "SEAL_DIRECTORY_NAME",
    "CandidateSealV3Error",
    "assemble_candidate_payloads_v3",
    "build_manifest_v3",
    "load_sealed_candidate_v3",
    "seal_candidate_v3",
]
