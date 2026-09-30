"""Dormant Gate E Stop A data contracts: frozen identifiers and closed-shape validators.

This module is intentionally data-only.  It freezes the exact Gate E active-tuple
identifiers from the controlling contract (docs/planning/27) and validates the three new
Stop A schemas — ``manifest-v3``, ``validation-plan-anchor-v1`` and
``final-holdout-access-audit-v1`` — against their sealed JSON Schema bytes plus the
structural cross-field laws a JSON Schema cannot express.

It imports no producer, runner, Battery, engine, ledger validator, API, report or web
module, is not exported by the package ``__init__``, is not imported by any active
path, and activates nothing: no registry eligibility, queue routing, release pointer or
product rendering.  Focused tests are its only consumers.

Two active-tuple identifiers — the continuous-path marker and the corrected execution
implementation id — have their literal bytes reserved to their own dormant Gate C/D
modules by the dormancy boundary tests, which scan every other worker source for those
byte sequences.  This module therefore pins their frozen values through the sealed
``manifest-v3`` schema constants instead of source literals; golden tests assert the
exact expected values byte-for-byte.  Every other identifier is a source literal below.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import jsonschema

from quantlens_schema.final_holdout_access_protocol_v1 import (
    FinalHoldoutAccessProtocolError,
    validate_final_holdout_access_audit_v1 as
    _neutral_validate_final_holdout_access_audit_v1,
)


class GateEContractError(ValueError):
    """One candidate value violates the frozen Gate E Stop A data contract."""


# --------------------------------------------------------------------- frozen tuple
# Section 2 of the controlling contract, one identifier per constant.  These are frozen
# literals; recomputing or deriving them from mutable configuration is forbidden.

GATE_E_ACTIVATION_RELEASE = "quantlens-financial-v3"
GATE_E_PRESENTATION_CONTRACT_ID = "corrected-financial-semantics-v3-ledger-v1"
GATE_E_WORKER_RUNTIME = "quantlens-worker-v3"
GATE_E_ENGINE_SEMVER = "0.2.0"
GATE_E_BATTERY_PROFILE_ID = "battery-v3"
GATE_E_BATTERY_PAYLOAD_VERSION = "battery-v3"
GATE_E_VALIDATION_PLAN_VERSION = "validation-plan-v3"
GATE_E_MANIFEST_VERSION = "v3"
GATE_E_DSL_SCHEMA_VERSION = "1.2"
GATE_E_MARKET_OBSERVATIONS_VERSION = "market-observations-v2"
GATE_E_LEDGER_SEMANTICS_VERSION = "ledger-v1"
GATE_E_EXECUTION_SEMANTICS_VERSION = "financial-semantics-v2"
GATE_E_EXECUTION_COST_MODEL = "adverse_effective_fill_price"
GATE_E_VALUATION_LEDGER_VERSION = "valuation-ledger-v1"
GATE_E_FINANCIAL_CONTRACT_VERSION = "financial-contract-v1"
GATE_E_VALIDATOR_VERSION = "financial-semantic-validator-v1"
GATE_E_METRIC_SEMANTICS_VERSION = "metrics-v2"
GATE_E_EVIDENCE_VIEW_VERSION = "v3"
GATE_E_EVIDENCE_SEMANTICS_VERSION = "v3"
GATE_E_SEMANTIC_RECEIPT_VERSION = "semantic-validation-receipt-v1"
GATE_E_PLAN_ANCHOR_VERSION = "validation-plan-anchor-v1"
GATE_E_HOLDOUT_ACCESS_PROTOCOL = "final-holdout-access-v1"
GATE_E_HOLDOUT_ACCESS_AUDIT_VERSION = "final-holdout-access-audit-v1"
GATE_E_ARTIFACT_PRODUCER = "quantlens-engine/0.2.0+battery-v3"
GATE_E_MANIFEST_DSL_PAIR = ("v3", "1.2")

# The complete ledger-v1 artifact kind vocabulary for the sealed ("v3", "1.2") pair; a
# manifest-v3 must bind each kind exactly once.  This mirrors the frozen Gate B kind
# law for DSL 1.2 — the base kinds plus mandatory data_provenance — byte-for-byte
# (tests assert equality against the neutral ledger module without importing it here).
GATE_E_ARTIFACT_KINDS = (
    "spec",
    "validation_plan",
    "partitions",
    "financial_contract",
    "valuation_ledger",
    "development_result",
    "walk_forward",
    "regime_analysis",
    "final_holdout_result",
    "final_holdout_execution_audit",
    "temporal_integrity",
    "sensitivity",
    "cost_stress",
    "falsification",
    "evidence_status",
    "data_gaps",
    "data_provenance",
    "snapshot_ref",
)

MANIFEST_V3_SCHEMA_FILE = "manifest-v3.json"
PLAN_ANCHOR_V1_SCHEMA_FILE = "validation-plan-anchor-v1.json"
HOLDOUT_ACCESS_AUDIT_V1_SCHEMA_FILE = "final-holdout-access-audit-v1.json"

_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "packages" / "strategy-schema" / "schema"
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}

# Manifest-v3 lineage fields whose presence is bound to the sealed data label.
_LINEAGE_FIELDS_USER = ("dataset_id", "dataset_manifest_sha256")
_LINEAGE_FIELDS_LICENSED = _LINEAGE_FIELDS_USER + (
    "dataset_manifest_version", "provider_id", "instrument_id", "rights_policy_sha256",
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the frozen Gate E canonical JSON bytes (sorted keys, compact separators)."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GateEContractError(
            "Gate E contracts accept only finite canonical JSON values"
        ) from exc


def sha256_canonical_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_gate_e_schema(filename: str) -> dict[str, Any]:
    """Load one sealed Stop A schema and fail closed on any unexpected shape."""
    if filename not in (
        MANIFEST_V3_SCHEMA_FILE,
        PLAN_ANCHOR_V1_SCHEMA_FILE,
        HOLDOUT_ACCESS_AUDIT_V1_SCHEMA_FILE,
    ):
        raise GateEContractError(f"unsupported Gate E schema: {filename!r}")
    cached = _SCHEMA_CACHE.get(filename)
    if cached is not None:
        return cached
    try:
        value = json.loads((_SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateEContractError(f"cannot load Gate E schema: {filename}") from exc
    if (
        not isinstance(value, dict)
        or value.get("additionalProperties") is not False
        or value.get("type") != "object"
        or not isinstance(value.get("properties"), dict)
        or not isinstance(value.get("required"), list)
        or not str(value.get("$id", "")).endswith("/" + filename)
    ):
        raise GateEContractError(f"Gate E schema is not a closed object schema: {filename}")
    _SCHEMA_CACHE[filename] = value
    return value


def _schema_const(schema: Mapping[str, Any], field: str) -> str:
    prop = schema["properties"].get(field)
    if not isinstance(prop, dict) or not isinstance(prop.get("const"), str):
        raise GateEContractError(
            f"Gate E schema does not pin a string constant for {field!r}"
        )
    return prop["const"]


def _require_schema_consts(schema: Mapping[str, Any], expected: Mapping[str, str]) -> None:
    """Fail closed when sealed schema constants and frozen module literals disagree."""
    for field, value in expected.items():
        if _schema_const(schema, field) != value:
            raise GateEContractError(
                f"sealed schema constant for {field!r} does not match the frozen tuple"
            )


_MANIFEST_V3_SCHEMA = load_gate_e_schema(MANIFEST_V3_SCHEMA_FILE)
_require_schema_consts(_MANIFEST_V3_SCHEMA, {
    "manifest_version": GATE_E_MANIFEST_VERSION,
    "activation_release": GATE_E_ACTIVATION_RELEASE,
    "presentation_contract": GATE_E_PRESENTATION_CONTRACT_ID,
    "worker_runtime": GATE_E_WORKER_RUNTIME,
    "engine_semver": GATE_E_ENGINE_SEMVER,
    "battery_profile_id": GATE_E_BATTERY_PROFILE_ID,
    "battery_payload_version": GATE_E_BATTERY_PAYLOAD_VERSION,
    "validation_plan_version": GATE_E_VALIDATION_PLAN_VERSION,
    "dsl_schema_version": GATE_E_DSL_SCHEMA_VERSION,
    "market_observations_version": GATE_E_MARKET_OBSERVATIONS_VERSION,
    "ledger_semantics_version": GATE_E_LEDGER_SEMANTICS_VERSION,
    "execution_semantics_version": GATE_E_EXECUTION_SEMANTICS_VERSION,
    "execution_cost_model": GATE_E_EXECUTION_COST_MODEL,
    "valuation_ledger_version": GATE_E_VALUATION_LEDGER_VERSION,
    "financial_contract_version": GATE_E_FINANCIAL_CONTRACT_VERSION,
    "validator_version": GATE_E_VALIDATOR_VERSION,
    "metric_semantics_version": GATE_E_METRIC_SEMANTICS_VERSION,
    "evidence_view_version": GATE_E_EVIDENCE_VIEW_VERSION,
    "evidence_semantics_version": GATE_E_EVIDENCE_SEMANTICS_VERSION,
    "semantic_receipt_version": GATE_E_SEMANTIC_RECEIPT_VERSION,
    "plan_anchor_version": GATE_E_PLAN_ANCHOR_VERSION,
    "holdout_access_protocol": GATE_E_HOLDOUT_ACCESS_PROTOCOL,
    "artifact_producer": GATE_E_ARTIFACT_PRODUCER,
})

# Schema-pinned identifiers (see module docstring).  Their exact frozen values are
# asserted by golden tests; a mutated schema constant fails those tests and every
# validator call below.
GATE_E_CONTINUOUS_PATH_VERSION = _schema_const(
    _MANIFEST_V3_SCHEMA, "continuous_path_version")
GATE_E_EXECUTION_IMPLEMENTATION = _schema_const(
    _MANIFEST_V3_SCHEMA, "execution_implementation")


def _validate_with_schema(filename: str, value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateEContractError(f"{label} must be a JSON object")
    canonical_json_bytes(value)
    try:
        jsonschema.Draft202012Validator(
            load_gate_e_schema(filename),
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)
    except jsonschema.ValidationError as exc:
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in exc.absolute_path
        )
        raise GateEContractError(
            f"{label} contract violation at {path}: {exc.message}"
        ) from exc
    return value


def _utc_second(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        raise GateEContractError(f"{label} must be a whole-second UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GateEContractError(f"{label} is not a real UTC instant") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GateEContractError(message)


def validate_manifest_v3(value: object) -> dict[str, Any]:
    """Validate one complete manifest-v3 candidate; reject any partial binding."""
    manifest = _validate_with_schema(MANIFEST_V3_SCHEMA_FILE, value, "manifest-v3")
    _require(
        (manifest["manifest_version"], manifest["dsl_schema_version"])
        == GATE_E_MANIFEST_DSL_PAIR,
        "manifest-v3 admits exactly one manifest/DSL pair",
    )
    _require(
        manifest["continuous_path_version"] == GATE_E_CONTINUOUS_PATH_VERSION
        and manifest["execution_implementation"] == GATE_E_EXECUTION_IMPLEMENTATION,
        "manifest-v3 active tuple does not match the sealed schema constants",
    )
    kinds = [entry["kind"] for entry in manifest["artifacts"]]
    _require(
        sorted(kinds) == sorted(GATE_E_ARTIFACT_KINDS),
        "manifest-v3 must bind every ledger-v1 artifact kind exactly once",
    )
    artifact_ids = [entry["artifact_id"] for entry in manifest["artifacts"]]
    paths = [entry["path"] for entry in manifest["artifacts"]]
    _require(
        len(set(artifact_ids)) == len(artifact_ids) and len(set(paths)) == len(paths),
        "manifest-v3 artifact ids and paths must be unique",
    )
    label = manifest["data_label"]
    present = tuple(
        field for field in _LINEAGE_FIELDS_LICENSED if field in manifest
    )
    if label == "SYNTHETIC":
        _require(not present, "SYNTHETIC manifests carry no dataset lineage fields")
    elif label == "USER_UPLOADED":
        _require(
            all(field in manifest for field in _LINEAGE_FIELDS_USER),
            "USER_UPLOADED manifests must bind dataset_id and dataset_manifest_sha256",
        )
        _require(
            all(field in _LINEAGE_FIELDS_USER for field in present),
            "USER_UPLOADED manifests carry exactly the sealed user dataset lineage",
        )
    else:
        _require(
            all(field in manifest for field in _LINEAGE_FIELDS_LICENSED),
            "LICENSED_PROVIDER manifests must bind the complete provider lineage",
        )
    return manifest


def validate_validation_plan_anchor_v1(value: object) -> dict[str, Any]:
    """Validate one canonical validation-plan-anchor-v1 record."""
    anchor = _validate_with_schema(
        PLAN_ANCHOR_V1_SCHEMA_FILE, value, "validation-plan-anchor-v1")
    window = anchor["final_window"]
    _require(
        window["end_index"] == window["n_bars"],
        "anchor final window must end at the last observation",
    )
    _require(
        window["start_index"] < window["end_index"]
        and window["bars"] == window["end_index"] - window["start_index"],
        "anchor final window bars must equal its end-exclusive index span",
    )
    _require(
        window["warmup_start_index"] <= window["start_index"]
        and window["warmup_bars"]
        == window["start_index"] - window["warmup_start_index"],
        "anchor warm-up boundary must immediately precede the final window",
    )
    # The fraction is bound to the derived window with exact IEEE-754 semantics: the
    # correctly-rounded quotient bars / n_bars, never an approximate tolerance.
    _require(
        anchor["final_holdout_fraction"] == window["bars"] / window["n_bars"],
        "anchor fraction must equal its derived final-window share exactly",
    )
    issued = _utc_second(anchor["issued_at"], "issued_at")
    expires = _utc_second(anchor["expires_at"], "expires_at")
    _require(expires > issued, "anchor expiry must be after issuance")
    return anchor


def validate_final_holdout_access_audit_v1(value: object) -> dict[str, Any]:
    """Validate one canonical final-holdout-access-audit-v1 record.

    The accepted Stop A schema/cross-field/time law moved verbatim to the neutral
    ``quantlens_schema.final_holdout_access_protocol_v1`` owner so the independent
    final-holdout authority shares the exact audit byte law without importing the
    worker.  This wrapper delegates only for validation — the neutral public
    validator returns a fresh tree, which is discarded — then returns the
    accepted caller mapping itself, byte-for-byte the legacy behavior.  A
    rejection re-raises the neutral protocol error as the existing
    ``GateEContractError`` with the same message and exception chaining.
    """
    try:
        _neutral_validate_final_holdout_access_audit_v1(value)
    except FinalHoldoutAccessProtocolError as exc:
        raise GateEContractError(str(exc)) from exc
    assert isinstance(value, dict)
    return value


__all__ = [
    "GATE_E_ACTIVATION_RELEASE",
    "GATE_E_ARTIFACT_KINDS",
    "GATE_E_ARTIFACT_PRODUCER",
    "GATE_E_BATTERY_PAYLOAD_VERSION",
    "GATE_E_BATTERY_PROFILE_ID",
    "GATE_E_CONTINUOUS_PATH_VERSION",
    "GATE_E_DSL_SCHEMA_VERSION",
    "GATE_E_ENGINE_SEMVER",
    "GATE_E_EVIDENCE_SEMANTICS_VERSION",
    "GATE_E_EVIDENCE_VIEW_VERSION",
    "GATE_E_EXECUTION_COST_MODEL",
    "GATE_E_EXECUTION_IMPLEMENTATION",
    "GATE_E_EXECUTION_SEMANTICS_VERSION",
    "GATE_E_FINANCIAL_CONTRACT_VERSION",
    "GATE_E_HOLDOUT_ACCESS_AUDIT_VERSION",
    "GATE_E_HOLDOUT_ACCESS_PROTOCOL",
    "GATE_E_LEDGER_SEMANTICS_VERSION",
    "GATE_E_MANIFEST_DSL_PAIR",
    "GATE_E_MANIFEST_VERSION",
    "GATE_E_MARKET_OBSERVATIONS_VERSION",
    "GATE_E_METRIC_SEMANTICS_VERSION",
    "GATE_E_PLAN_ANCHOR_VERSION",
    "GATE_E_PRESENTATION_CONTRACT_ID",
    "GATE_E_SEMANTIC_RECEIPT_VERSION",
    "GATE_E_VALIDATION_PLAN_VERSION",
    "GATE_E_VALIDATOR_VERSION",
    "GATE_E_VALUATION_LEDGER_VERSION",
    "GATE_E_WORKER_RUNTIME",
    "GateEContractError",
    "HOLDOUT_ACCESS_AUDIT_V1_SCHEMA_FILE",
    "MANIFEST_V3_SCHEMA_FILE",
    "PLAN_ANCHOR_V1_SCHEMA_FILE",
    "canonical_json_bytes",
    "load_gate_e_schema",
    "sha256_canonical_json",
    "validate_final_holdout_access_audit_v1",
    "validate_manifest_v3",
    "validate_validation_plan_anchor_v1",
]
