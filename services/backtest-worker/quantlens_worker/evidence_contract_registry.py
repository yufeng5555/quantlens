"""Frozen presentation contracts for sealed QuantLens evidence.

This module is intentionally data-only.  It does not import the mutable engine
configuration and it never rewrites an old manifest, ledger, receipt, or database row.
The registry translates identifiers that were actually sealed by the legacy worker into
an explicit presentation contract, and — since the separately reviewed Stop F2b
re-seal — additionally carries the one corrected-active row whose registered key is
the frozen Gate E release identity.  Unknown or cross-wired identifiers fail closed.

The current runtime digest remains useful as an opaque execution identity, but it is not
a financial-semantics version.  A presentation contract therefore verifies its digest
*scheme* while the strict resume loader separately requires the exact current digest.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


LEDGER_V0_NOTE = (
    "Gate 2 ledger v0: write-once content-hashed artifacts; report rendering "
    "replays and verifies this sealed index."
)
LEDGER_V0_INDEX_KEYS = frozenset({"entries", "result_hash", "note"})
LEDGER_V0_ENTRY_KEYS = frozenset({
    "artifact_id", "kind", "sha256", "path", "producer",
})


class UnknownPresentationContractError(RuntimeError):
    """The sealed identifiers do not match an active frozen presentation contract."""


@dataclass(frozen=True)
class ContractKey:
    engine_semver: str
    battery_profile_id: str
    battery_payload_version: str
    battery_config_hash: str
    validation_plan_version: str | None
    artifact_producer: str
    image_digest_scheme: str


@dataclass(frozen=True)
class PresentationContract:
    contract_id: str
    key: ContractKey | None
    evidence_view_version: str
    evidence_semantics_version: str
    ledger_semantics_version: str
    execution_semantics_version: str
    execution_cost_model: str
    allowed_manifest_dsl_pairs: frozenset[tuple[str, str]]
    presentation_status: Literal["legacy_active", "dormant", "corrected_active"]
    verified_financial_semantics: bool

    def public_descriptor(self) -> dict[str, object]:
        """Return only stable, product-safe labels; never expose matching internals."""
        return {
            "contract_id": self.contract_id,
            "presentation_status": self.presentation_status,
            "evidence_view_version": self.evidence_view_version,
            "evidence_semantics_version": self.evidence_semantics_version,
            "ledger_semantics_version": self.ledger_semantics_version,
            "execution_semantics_version": self.execution_semantics_version,
            "execution_cost_model": self.execution_cost_model,
            "verified_financial_semantics": self.verified_financial_semantics,
            "verified_surface_eligibility": (
                "eligible" if self.verified_financial_semantics
                else "rebuild_required"
            ),
        }


@dataclass(frozen=True)
class SealedBuildRegistration:
    """One exact historical runtime identity admitted for read-only presentation."""

    contract_id: str
    image_digest: str


_MANIFEST_DSL_PAIRS = frozenset({
    ("v0", "1.0"),
    ("v1", "1.1"),
    ("v2", "1.2"),
})

# These hashes are frozen literals.  Recomputing them from mutable current configuration
# would silently reinterpret historical evidence after a future config edit.
LEGACY_BATTERY_V1 = PresentationContract(
    contract_id="legacy-battery-v1-ledger-v0",
    key=ContractKey(
        engine_semver="0.1.0",
        battery_profile_id="battery-v1",
        battery_payload_version="v1-gate2",
        battery_config_hash=(
            "sha256:c8466b8988df6d1d066f6cd12b3fd194"
            "649f67bf716ea131d16ecb0ce51401b2"
        ),
        validation_plan_version=None,
        artifact_producer="quantlens-engine/0.1.0+battery-v1",
        image_digest_scheme="local-runtime-sha256",
    ),
    evidence_view_version="v1",
    evidence_semantics_version="v1",
    ledger_semantics_version="ledger-v0",
    execution_semantics_version="linear-execution-friction-v0",
    execution_cost_model="linear_execution_friction",
    allowed_manifest_dsl_pairs=_MANIFEST_DSL_PAIRS,
    presentation_status="legacy_active",
    verified_financial_semantics=False,
)

LEGACY_BATTERY_V2 = PresentationContract(
    contract_id="legacy-battery-v2-ledger-v0",
    key=ContractKey(
        engine_semver="0.1.0",
        battery_profile_id="battery-v2",
        battery_payload_version="battery-v2",
        battery_config_hash=(
            "sha256:9893df089aa06b4c6e861985e0816dd3"
            "621a8f4daf3813bad4e2b1da878b9917"
        ),
        validation_plan_version="validation-plan-v2",
        artifact_producer="quantlens-engine/0.1.0+battery-v2",
        image_digest_scheme="local-runtime-sha256",
    ),
    evidence_view_version="v2",
    evidence_semantics_version="v2",
    ledger_semantics_version="ledger-v0",
    execution_semantics_version="linear-execution-friction-v0",
    execution_cost_model="linear_execution_friction",
    allowed_manifest_dsl_pairs=_MANIFEST_DSL_PAIRS,
    presentation_status="legacy_active",
    verified_financial_semantics=False,
)

# The corrected financial contract is named but deliberately has no guessed key.  Gates
# B–D must freeze its actual identifiers before Gate E may activate it.
DORMANT_CORRECTED_FINANCIAL_CONTRACT = PresentationContract(
    contract_id="corrected-financial-semantics-dormant",
    key=None,
    evidence_view_version="dormant",
    evidence_semantics_version="dormant",
    ledger_semantics_version="ledger-v1",
    execution_semantics_version="financial-semantics-v2",
    execution_cost_model="adverse_effective_fill_price",
    allowed_manifest_dsl_pairs=frozenset(),
    presentation_status="dormant",
    # Activation is itself part of the future Gate E release, never a property of a
    # merely named dormant contract.
    verified_financial_semantics=False,
)

# Stop F2b re-seal (doc 47 §6 step 9; doc 48 §14): the one corrected-active
# registration.  Every value is hand-restated from the reviewed frozen release
# identity (the same values the hash-pinned Stop F1 fixture registry restates)
# — never imported from the dormant Gate E modules, so a drift on either side
# fails the focused laws loudly instead of auto-tracking it.  The runtime
# digest deliberately lives outside this module: build identities are sealed
# in the independently pinned registry companion below.
CORRECTED_FINANCIAL_V3 = PresentationContract(
    contract_id="corrected-financial-semantics-v3-ledger-v1",
    key=ContractKey(
        engine_semver="0.2.0",
        battery_profile_id="battery-v3",
        battery_payload_version="battery-v3",
        battery_config_hash=(
            "sha256:08d179f17878d19e31d337071c25d4fb"
            "3bbe92a2080f8f0d0ee4a4c35c07652b"
        ),
        validation_plan_version="validation-plan-v3",
        artifact_producer="quantlens-engine/0.2.0+battery-v3",
        image_digest_scheme="local-runtime-sha256",
    ),
    evidence_view_version="v3",
    evidence_semantics_version="v3",
    ledger_semantics_version="ledger-v1",
    execution_semantics_version="financial-semantics-v2",
    execution_cost_model="adverse_effective_fill_price",
    allowed_manifest_dsl_pairs=frozenset({("v3", "1.2")}),
    presentation_status="corrected_active",
    verified_financial_semantics=True,
)

PRESENTATION_CONTRACTS = (
    LEGACY_BATTERY_V1,
    LEGACY_BATTERY_V2,
    DORMANT_CORRECTED_FINANCIAL_CONTRACT,
    CORRECTED_FINANCIAL_V3,
)


def _release_build_registrations() -> tuple[SealedBuildRegistration, ...]:
    """Load reviewed release identities from data outside the local digest bootstrap.

    The local runtime digest hashes this Python module. Embedding that module's own final
    digest inside itself would be a circular fixed-point problem. Release identities are
    therefore frozen in an exact-schema JSON companion which the real immutable image
    digest replaces in deployment. The registry bytes are independently pinned by
    deployment configuration so editing this companion cannot silently expand the
    presentation allowlist. A missing pin, mismatch, or malformed registry fails closed.
    """
    path = Path(__file__).with_name("sealed_build_registrations.json")
    try:
        raw = path.read_bytes()
        expected_sha256 = os.environ["QL_SEALED_BUILD_REGISTRY_SHA256"]
        value = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("sealed build registry is missing or malformed") from exc
    except KeyError as exc:
        raise RuntimeError("sealed build registry pin is not configured") from exc
    actual_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_sha256) or not hmac.compare_digest(
            actual_sha256, expected_sha256):
        raise RuntimeError("sealed build registry does not match its deployment pin")
    if not isinstance(value, dict) or set(value) != {"format", "registrations"} or \
            value.get("format") != "sealed-build-registry-v1" or \
            not isinstance(value.get("registrations"), list):
        raise RuntimeError("sealed build registry has an unsupported shape")
    # Stop F2b: the corrected-active contract registers its build identity
    # through this same sealed companion; before the re-seal only the two
    # legacy-active contracts were admissible here.
    active_ids = {
        contract.contract_id for contract in PRESENTATION_CONTRACTS
        if contract.presentation_status in ("legacy_active", "corrected_active")
    }
    registrations: list[SealedBuildRegistration] = []
    seen: set[tuple[str, str]] = set()
    for item in value["registrations"]:
        if not isinstance(item, dict) or set(item) != {"contract_id", "image_digest"}:
            raise RuntimeError("sealed build registration has an unsupported shape")
        contract_id = item.get("contract_id")
        digest = item.get("image_digest")
        if contract_id not in active_ids or not isinstance(digest, str) or not re.fullmatch(
                r"local-runtime-sha256:[0-9a-f]{64}", digest):
            raise RuntimeError("sealed build registration is not an active exact identity")
        identity = (contract_id, digest)
        if identity in seen:
            raise RuntimeError("sealed build registry contains a duplicate identity")
        seen.add(identity)
        registrations.append(SealedBuildRegistration(contract_id, digest))
    return tuple(registrations)

# These are the complete sealed checkpoints present at the compatibility freeze.  The
# manifest is not itself inside ``result_hash``, so admitting only a digest *scheme* would
# let an attacker substitute an arbitrary runtime identity.  Historical builds therefore
# require an exact registration. Current-runtime equality belongs only to the strict
# resume loader and cannot silently admit a new presentation tuple.
SEALED_BUILD_REGISTRATIONS = (
    SealedBuildRegistration(
        contract_id=LEGACY_BATTERY_V1.contract_id,
        image_digest=(
            "local-runtime-sha256:"
            "8ab1d99349d426df8629b15f03bdb4e28ad5c9339e43fa2250c6724052d3065a"
        ),
    ),
    SealedBuildRegistration(
        contract_id=LEGACY_BATTERY_V1.contract_id,
        image_digest=(
            "local-runtime-sha256:"
            "b0253fcb06599aac177fb6b77fb00dc8a2df045ef21aaa669f3b16135126560b"
        ),
    ),
) + _release_build_registrations()


def registered_presentation_producers() -> frozenset[str]:
    return frozenset(
        contract.key.artifact_producer
        for contract in PRESENTATION_CONTRACTS
        if contract.presentation_status == "legacy_active" and contract.key is not None
    )


def _single_ledger_producer(ledger: dict[str, Any]) -> str:
    entries = ledger.get("entries")
    if not isinstance(entries, list) or not entries:
        raise UnknownPresentationContractError("ledger has no contract-bearing entries")
    producers = {
        entry.get("producer") for entry in entries if isinstance(entry, dict)
    }
    if len(producers) != 1:
        raise UnknownPresentationContractError(
            "ledger entries do not share one artifact producer")
    producer = next(iter(producers))
    if not isinstance(producer, str) or not producer:
        raise UnknownPresentationContractError("ledger producer is invalid")
    return producer


def observe_contract(
    manifest: dict[str, Any], ledger: dict[str, Any], payloads: dict[str, Any],
) -> ContractKey:
    """Extract the legacy identifiers only after byte/hash verification has succeeded."""
    if set(ledger) != set(LEDGER_V0_INDEX_KEYS) or ledger.get("note") != LEDGER_V0_NOTE:
        raise UnknownPresentationContractError(
            "ledger does not match the frozen ledger-v0 index shape")
    entries = ledger.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(entry, dict) or set(entry) != set(LEDGER_V0_ENTRY_KEYS)
        for entry in entries
    ):
        raise UnknownPresentationContractError(
            "ledger entries do not match the frozen ledger-v0 shape")

    plan = payloads.get("validation_plan")
    if plan is None:
        profile = "battery-v1"
        plan_version = None
    elif isinstance(plan, dict):
        profile = plan.get("profile_id")
        plan_version = plan.get("plan_version")
    else:
        raise UnknownPresentationContractError("validation plan is malformed")

    falsification = payloads.get("falsification")
    payload_version = (
        falsification.get("battery_version")
        if isinstance(falsification, dict) else None
    )
    image_digest = manifest.get("image_digest")
    digest_scheme = (
        image_digest.partition(":")[0]
        if isinstance(image_digest, str) and ":" in image_digest else ""
    )
    values = {
        "engine_semver": manifest.get("engine_semver"),
        "battery_profile_id": profile,
        "battery_payload_version": payload_version,
        "battery_config_hash": manifest.get("battery_config_hash"),
        "validation_plan_version": plan_version,
        "artifact_producer": _single_ledger_producer(ledger),
        "image_digest_scheme": digest_scheme,
    }
    if any(not isinstance(value, str) or not value for key, value in values.items()
           if key != "validation_plan_version"):
        raise UnknownPresentationContractError(
            "sealed evidence has incomplete contract identifiers")
    if plan_version is not None and not isinstance(plan_version, str):
        raise UnknownPresentationContractError("validation plan version is invalid")
    return ContractKey(**values)  # type: ignore[arg-type]


def resolve_presentation_contract(
    manifest: dict[str, Any], ledger: dict[str, Any], payloads: dict[str, Any],
) -> PresentationContract:
    """Resolve one exact frozen tuple; every unknown or mixed tuple fails closed."""
    observed = observe_contract(manifest, ledger, payloads)
    matches = [
        contract for contract in PRESENTATION_CONTRACTS
        if contract.presentation_status == "legacy_active" and contract.key == observed
    ]
    if len(matches) != 1:
        raise UnknownPresentationContractError(
            "sealed evidence contract is not registered for presentation")
    contract = matches[0]
    pair = (manifest.get("manifest_version"), manifest.get("dsl_schema_version"))
    if pair not in contract.allowed_manifest_dsl_pairs:
        raise UnknownPresentationContractError(
            "manifest and DSL versions do not match the registered contract")
    sealed_digest = manifest.get("image_digest")
    frozen_digests = {
        build.image_digest for build in SEALED_BUILD_REGISTRATIONS
        if build.contract_id == contract.contract_id
    }
    if sealed_digest not in frozen_digests:
        raise UnknownPresentationContractError(
            "sealed runtime identity is not registered for this presentation contract")
    return contract


__all__ = [
    "CORRECTED_FINANCIAL_V3", "ContractKey",
    "DORMANT_CORRECTED_FINANCIAL_CONTRACT",
    "LEDGER_V0_ENTRY_KEYS", "LEDGER_V0_INDEX_KEYS", "LEDGER_V0_NOTE",
    "LEGACY_BATTERY_V1", "LEGACY_BATTERY_V2", "PRESENTATION_CONTRACTS",
    "PresentationContract", "SEALED_BUILD_REGISTRATIONS", "SealedBuildRegistration",
    "UnknownPresentationContractError", "observe_contract",
    "registered_presentation_producers", "resolve_presentation_contract",
]
