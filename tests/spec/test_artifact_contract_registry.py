"""Gate 7A.2 contract-registry tests.

These tests exercise only the frozen presentation tuple resolver.  Artifact byte/hash
verification is covered by the loader tests; this file makes the compatibility matrix
and its fail-closed boundaries explicit and cheap to run.
"""

from __future__ import annotations

import copy

import pytest

from quantlens_worker.config import image_digest
from quantlens_worker.evidence_contract_registry import (
    DORMANT_CORRECTED_FINANCIAL_CONTRACT,
    LEDGER_V0_NOTE,
    LEGACY_BATTERY_V1,
    LEGACY_BATTERY_V2,
    PRESENTATION_CONTRACTS,
    SEALED_BUILD_REGISTRATIONS,
    UnknownPresentationContractError,
    _release_build_registrations,
    resolve_presentation_contract,
)


LEGAL_MANIFEST_DSL_PAIRS = (
    ("v0", "1.0"),
    ("v1", "1.1"),
    ("v2", "1.2"),
)


def _contract_inputs(contract, *, digest: str | None = None):
    assert contract.key is not None
    manifest = {
        "manifest_version": "v2",
        "dsl_schema_version": "1.2",
        "engine_semver": contract.key.engine_semver,
        "battery_config_hash": contract.key.battery_config_hash,
        "image_digest": digest or image_digest(),
    }
    ledger = {
        "entries": [{
            "artifact_id": "sha256:artifact",
            "kind": "metrics",
            "sha256": "sha256:payload",
            "path": "metrics.json",
            "producer": contract.key.artifact_producer,
        }],
        "result_hash": "sha256:result",
        "note": LEDGER_V0_NOTE,
    }
    payloads = {
        "falsification": {
            "battery_version": contract.key.battery_payload_version,
        },
    }
    if contract.key.validation_plan_version is not None:
        payloads["validation_plan"] = {
            "profile_id": contract.key.battery_profile_id,
            "plan_version": contract.key.validation_plan_version,
        }
    return manifest, ledger, payloads


@pytest.mark.parametrize(
    ("contract", "manifest_version", "dsl_schema_version"),
    [
        (contract, manifest_version, dsl_schema_version)
        for contract in (LEGACY_BATTERY_V1, LEGACY_BATTERY_V2)
        for manifest_version, dsl_schema_version in LEGAL_MANIFEST_DSL_PAIRS
    ],
    ids=[
        f"{contract.contract_id}-{manifest_version}-{dsl_schema_version}"
        for contract in (LEGACY_BATTERY_V1, LEGACY_BATTERY_V2)
        for manifest_version, dsl_schema_version in LEGAL_MANIFEST_DSL_PAIRS
    ],
)
def test_all_six_legal_registered_release_tuples_resolve(
    contract, manifest_version, dsl_schema_version,
):
    current_digest = image_digest()
    manifest, ledger, payloads = _contract_inputs(
        contract, digest=current_digest)
    manifest["manifest_version"] = manifest_version
    manifest["dsl_schema_version"] = dsl_schema_version

    resolved = resolve_presentation_contract(
        manifest, ledger, payloads)

    assert resolved is contract


def test_exact_registered_v1_historical_digest_resolves():
    registration = next(
        item for item in SEALED_BUILD_REGISTRATIONS
        if item.contract_id == LEGACY_BATTERY_V1.contract_id
    )
    manifest, ledger, payloads = _contract_inputs(
        LEGACY_BATTERY_V1, digest=registration.image_digest)

    resolved = resolve_presentation_contract(
        manifest, ledger, payloads)

    assert resolved is LEGACY_BATTERY_V1


def test_current_release_digest_is_frozen_for_both_legacy_contracts():
    current_digest = image_digest()
    registered_contracts = {
        item.contract_id for item in SEALED_BUILD_REGISTRATIONS
        if item.image_digest == current_digest
    }
    assert {
        LEGACY_BATTERY_V1.contract_id,
        LEGACY_BATTERY_V2.contract_id,
    }.issubset(registered_contracts)


def test_release_registry_requires_an_independent_deployment_pin(monkeypatch):
    monkeypatch.delenv("QL_SEALED_BUILD_REGISTRY_SHA256", raising=False)
    with pytest.raises(RuntimeError, match="pin is not configured"):
        _release_build_registrations()


def test_release_registry_rejects_a_mismatched_deployment_pin(monkeypatch):
    monkeypatch.setenv(
        "QL_SEALED_BUILD_REGISTRY_SHA256", "sha256:" + "0" * 64)
    with pytest.raises(RuntimeError, match="does not match its deployment pin"):
        _release_build_registrations()


def _mutate_profile(_manifest, _ledger, payloads):
    payloads["validation_plan"]["profile_id"] = "battery-v1"


def _mutate_payload_version(_manifest, _ledger, payloads):
    payloads["falsification"]["battery_version"] = "battery-v3"


def _mutate_battery_hash(manifest, _ledger, _payloads):
    manifest["battery_config_hash"] = "sha256:" + "0" * 64


def _mutate_plan_version(_manifest, _ledger, payloads):
    payloads["validation_plan"]["plan_version"] = "validation-plan-v3"


def _mutate_producer(_manifest, ledger, _payloads):
    ledger["entries"][0]["producer"] = "quantlens-engine/0.1.0+battery-v3"


def _mutate_engine(manifest, _ledger, _payloads):
    manifest["engine_semver"] = "0.2.0"


def _mutate_digest_scheme(manifest, _ledger, _payloads):
    manifest["image_digest"] = "container-sha256:" + "1" * 64


def _mutate_ledger_index_shape(_manifest, ledger, _payloads):
    ledger["unexpected"] = "not-ledger-v0"


def _mutate_ledger_entry_shape(_manifest, ledger, _payloads):
    ledger["entries"][0]["unexpected"] = "not-ledger-v0"


def _mutate_ledger_note(_manifest, ledger, _payloads):
    ledger["note"] = "a later ledger interpretation"


def _mutate_manifest_dsl_pair(manifest, _ledger, _payloads):
    manifest["manifest_version"] = "v0"
    manifest["dsl_schema_version"] = "1.1"


@pytest.mark.parametrize(
    "mutation",
    [
        _mutate_profile,
        _mutate_payload_version,
        _mutate_battery_hash,
        _mutate_plan_version,
        _mutate_producer,
        _mutate_engine,
        _mutate_digest_scheme,
        _mutate_ledger_index_shape,
        _mutate_ledger_entry_shape,
        _mutate_ledger_note,
        _mutate_manifest_dsl_pair,
    ],
    ids=lambda mutation: mutation.__name__.removeprefix("_mutate_"),
)
def test_any_contract_identifier_or_ledger_shape_mutation_fails_closed(mutation):
    current_digest = image_digest()
    manifest, ledger, payloads = _contract_inputs(
        LEGACY_BATTERY_V2, digest=current_digest)
    manifest, ledger, payloads = copy.deepcopy((manifest, ledger, payloads))
    mutation(manifest, ledger, payloads)

    with pytest.raises(UnknownPresentationContractError):
        resolve_presentation_contract(
            manifest, ledger, payloads)


def test_unregistered_same_scheme_digest_fails_closed():
    current_digest = image_digest()
    unregistered_digest = "local-runtime-sha256:" + "f" * 64
    assert unregistered_digest != current_digest
    assert unregistered_digest not in {
        item.image_digest for item in SEALED_BUILD_REGISTRATIONS
    }
    manifest, ledger, payloads = _contract_inputs(
        LEGACY_BATTERY_V1, digest=unregistered_digest)

    with pytest.raises(UnknownPresentationContractError):
        resolve_presentation_contract(
            manifest, ledger, payloads)


def test_dormant_corrected_contract_has_no_resolvable_key():
    assert DORMANT_CORRECTED_FINANCIAL_CONTRACT.presentation_status == "dormant"
    assert DORMANT_CORRECTED_FINANCIAL_CONTRACT.key is None
    assert DORMANT_CORRECTED_FINANCIAL_CONTRACT in PRESENTATION_CONTRACTS

    current_digest = image_digest()
    manifest, ledger, payloads = _contract_inputs(
        LEGACY_BATTERY_V2, digest=current_digest)
    manifest["engine_semver"] = "1.0.0"
    manifest["battery_config_hash"] = "sha256:" + "c" * 64
    ledger["entries"][0]["producer"] = (
        "quantlens-engine/1.0.0+corrected-financial-semantics")
    payloads["validation_plan"] = {
        "profile_id": "corrected-financial-semantics",
        "plan_version": "validation-plan-v3",
    }
    payloads["falsification"]["battery_version"] = "battery-v3"

    with pytest.raises(UnknownPresentationContractError):
        resolve_presentation_contract(
            manifest, ledger, payloads)
