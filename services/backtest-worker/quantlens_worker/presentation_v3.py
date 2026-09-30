"""Active presentation resolution for sealed ledger-v1 evidence candidates.

This module is the Stop E product-projection leg for the corrected release.
It reads a run's sealed candidate bytes (the write-once seal directory a
reviewed test-lane sealer produced) and resolves them against the ACTIVE
presentation registry data — contracts, sealed build registrations — before
any surface may project them. It imports nothing from the dormant Gate C/D/E
lanes: every contract identifier and tuple value it handles arrives either
from the sealed bytes themselves or from registry rows passed in as data.

Fail-closed by construction: a sealed candidate resolves only against a
registered corrected-active row whose key identities, versions and sealed
build registration all match exactly.  The separately reviewed Stop F2b
re-seal introduced exactly one such row — the frozen Gate E release identity
— so any other contract id, any key drift, and any unregistered runtime
digest still raises.  Tests exercise the identical law through the
hash-pinned reviewed fixture harness; there is no environment switch and no
partial flag.
"""

from __future__ import annotations

import html as html_escape
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evidence_contract_registry import (
    PRESENTATION_CONTRACTS,
    SEALED_BUILD_REGISTRATIONS,
)
from .validation_plan import sha256_json


# Sealed candidate layout (write-once; never the active checkpoint names).
V3_SEAL_DIRECTORY = "ledger-v1-candidate-seal"
V3_MANIFEST_FILENAME = "manifest_v3.json"
V3_CANDIDATE_DIRECTORY = "ledger-v1-candidate"
V3_RECEIPT_FILENAME = "semantic_validation_receipt.json"

# The activation status the separately reviewed Stop F2b re-seal introduced
# into the registry; no other path may mint rows carrying it.
CORRECTED_ACTIVE_STATUS = "corrected_active"

# manifest-v3 fields that make up the presentation tuple of the evidence view
# (the closed TS shape's ``active_tuple``). ``battery_config_hash`` is part of
# the sealed identity, not the tuple.
V3_TUPLE_FIELDS = (
    "activation_release", "presentation_contract", "worker_runtime",
    "engine_semver", "battery_profile_id", "battery_payload_version",
    "validation_plan_version", "manifest_version", "dsl_schema_version",
    "market_observations_version", "ledger_semantics_version",
    "execution_semantics_version", "execution_cost_model",
    "continuous_path_version", "valuation_ledger_version",
    "financial_contract_version", "execution_implementation",
    "validator_version", "metric_semantics_version", "evidence_view_version",
    "evidence_semantics_version", "semantic_receipt_version",
    "plan_anchor_version", "holdout_access_protocol", "artifact_producer",
)
V3_IDENTITY_FIELDS = (
    "manifest_id", "spec_hash", "spec_version", "snapshot_id",
    "snapshot_sha256", "image_digest", "battery_config_hash", "result_hash",
    "created_at", "confirmation_receipt_hash", "data_label",
)
V3_BINDING_FIELDS = (
    "plan_anchor_sha256", "financial_contract_sha256", "ledger_id",
    "semantic_receipt_sha256", "temporal_integrity_sha256",
    "final_holdout_execution_audit_sha256",
)


class V3CheckpointMissingError(RuntimeError):
    """The run has no sealed ledger-v1 candidate checkpoint."""


class V3ResolutionError(RuntimeError):
    """The sealed candidate does not resolve against the registry data."""

    def __init__(self, reason: str):
        super().__init__(f"sealed candidate cannot be presented: {reason}")
        self.reason = reason


def v3_checkpoint_exists(run_dir: Path) -> bool:
    """True when the run directory holds a sealed v3 candidate checkpoint."""
    return (
        (run_dir / V3_SEAL_DIRECTORY / V3_MANIFEST_FILENAME).is_file()
        and (run_dir / V3_CANDIDATE_DIRECTORY / V3_RECEIPT_FILENAME).is_file()
    )


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V3ResolutionError(f"{label} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise V3ResolutionError(f"{label} is not a JSON object")
    return value


def load_v3_checkpoint(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Load the sealed manifest and receipt bytes for one run, fail-closed."""
    if not v3_checkpoint_exists(run_dir):
        raise V3CheckpointMissingError(
            "the run has no sealed ledger-v1 candidate checkpoint")
    manifest = _read_json_object(
        run_dir / V3_SEAL_DIRECTORY / V3_MANIFEST_FILENAME, "sealed manifest")
    receipt = _read_json_object(
        run_dir / V3_CANDIDATE_DIRECTORY / V3_RECEIPT_FILENAME,
        "validation receipt")
    return {"manifest": manifest, "semantic_receipt": receipt}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise V3ResolutionError(reason)


def _require_fields(manifest: Mapping[str, Any]) -> None:
    for field in V3_TUPLE_FIELDS + V3_IDENTITY_FIELDS + V3_BINDING_FIELDS:
        value = manifest.get(field)
        if field == "spec_version":
            _require(isinstance(value, int) and value >= 1,
                     "sealed manifest spec_version is invalid")
        else:
            _require(isinstance(value, str) and len(value) >= 1,
                     f"sealed manifest field {field!r} is missing")


def resolve_v3_presentation(
    manifest: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve one sealed candidate against the SHIPPED registry, or raise.

    This is the only production entry point (doc 47 §A1, binding): it takes
    no registry arguments, so no caller can substitute contract rows or
    build registrations. Since the separately reviewed Stop F2b re-seal the
    shipped registry carries exactly one corrected-active row — the frozen
    Gate E release identity with its sealed runtime build registration — so
    only a candidate sealed under exactly that identity can resolve; every
    other tuple still raises. Focused tests exercise the identical law
    through a hash-pinned reviewed fixture harness over the private core,
    which production code never imports.
    """
    return _resolve_v3_presentation_against(
        manifest, receipt,
        contracts=PRESENTATION_CONTRACTS,
        build_registrations=SEALED_BUILD_REGISTRATIONS,
    )


def _resolve_v3_presentation_against(
    manifest: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    contracts: Sequence[Any],
    build_registrations: Sequence[Any],
) -> dict[str, Any]:
    """Private resolution core; registry rows are explicit, never defaulted.

    The law, identical for the production wrapper and the reviewed test
    harness:

    1. the manifest's presentation contract must be a registered row whose
       ``presentation_status`` is the corrected-active status;
    2. the row's key identities must equal the sealed manifest fields;
    3. the row's evidence/ledger/execution versions must equal the manifest;
    4. a sealed build registration must bind the exact runtime image digest;
    5. the recorded receipt must hash-match the manifest binding and
       cross-bind the ledger, result and financial-contract identities with
       PASS status.
    """
    contract_rows = tuple(contracts)
    registrations = tuple(build_registrations)

    _require_fields(manifest)
    _require(manifest.get("evidence_view_version") == "v3",
             "sealed manifest does not declare the v3 evidence view")
    _require(manifest.get("evidence_semantics_version") == "v3",
             "sealed manifest does not declare the v3 evidence semantics")

    contract_id = manifest["presentation_contract"]
    row = next(
        (contract for contract in contract_rows
         if contract.contract_id == contract_id), None)
    _require(row is not None,
             "the sealed presentation contract is not a registered row")
    _require(row.presentation_status == CORRECTED_ACTIVE_STATUS,
             "the presentation contract is not activated")
    _require(row.key is not None,
             "the presentation contract carries no registered key")

    key = row.key
    _require(key.engine_semver == manifest["engine_semver"],
             "engine version does not match the registered key")
    _require(key.battery_profile_id == manifest["battery_profile_id"],
             "battery profile does not match the registered key")
    _require(key.battery_payload_version == manifest["battery_payload_version"],
             "battery payload version does not match the registered key")
    _require(key.battery_config_hash == manifest["battery_config_hash"],
             "battery configuration hash does not match the registered key")
    _require(key.validation_plan_version == manifest["validation_plan_version"],
             "validation plan version does not match the registered key")
    _require(key.artifact_producer == manifest["artifact_producer"],
             "artifact producer does not match the registered key")
    _require(
        isinstance(manifest["image_digest"], str)
        and manifest["image_digest"].startswith(key.image_digest_scheme + ":"),
        "runtime digest does not use the registered scheme")

    _require(row.evidence_view_version == manifest["evidence_view_version"],
             "evidence view version does not match the registered row")
    _require(
        row.evidence_semantics_version == manifest["evidence_semantics_version"],
        "evidence semantics version does not match the registered row")
    _require(row.ledger_semantics_version == manifest["ledger_semantics_version"],
             "ledger semantics version does not match the registered row")
    _require(
        row.execution_semantics_version
        == manifest["execution_semantics_version"],
        "execution semantics version does not match the registered row")
    _require(row.execution_cost_model == manifest["execution_cost_model"],
             "execution cost model does not match the registered row")

    _require(
        any(registration.contract_id == contract_id
            and registration.image_digest == manifest["image_digest"]
            for registration in registrations),
        "the sealed runtime identity has no build registration")

    _require(sha256_json(dict(receipt)) == manifest["semantic_receipt_sha256"],
             "the recorded receipt does not hash-match the sealed binding")
    _require(receipt.get("status") == "PASS",
             "the recorded receipt is not a PASS receipt")
    _require(receipt.get("ledger_id") == manifest["ledger_id"],
             "the recorded receipt names a different ledger")
    _require(receipt.get("result_hash") == manifest["result_hash"],
             "the recorded receipt names a different result")
    _require(
        receipt.get("financial_contract_sha256")
        == manifest["financial_contract_sha256"],
        "the recorded receipt names a different financial contract")
    ids = receipt.get("validated_execution_ids")
    _require(
        isinstance(ids, list) and len(ids) >= 1
        and all(isinstance(item, str) and item for item in ids)
        and len(set(ids)) == len(ids),
        "the recorded receipt has no usable execution records")

    return {"contract": row, "manifest": dict(manifest),
            "semantic_receipt": dict(receipt)}


def build_evidence_view_v3(
    manifest: Mapping[str, Any], receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Project resolved sealed bytes into the closed v3 evidence view shape.

    Pure projection: every value is copied verbatim from the sealed bytes.
    Callers must resolve first — this function performs no registry check.
    """
    return {
        "evidence_view_version": "v3",
        "evidence_semantics_version": "v3",
        "active_tuple": {
            field: manifest[field] for field in V3_TUPLE_FIELDS
        },
        "identity": {
            field: manifest[field] for field in V3_IDENTITY_FIELDS
        },
        "bindings": {
            field: manifest[field] for field in V3_BINDING_FIELDS
        },
        "semantic_receipt": {
            "validator_version": receipt["validator_version"],
            "ledger_id": receipt["ledger_id"],
            "result_hash": receipt["result_hash"],
            "financial_contract_sha256": receipt["financial_contract_sha256"],
            "validated_execution_ids": list(
                receipt["validated_execution_ids"]),
            "status": receipt["status"],
        },
    }


def _rows(values: Mapping[str, Any]) -> str:
    return "".join(
        "<tr><th scope=\"row\">{name}</th><td><code>{value}</code></td></tr>"
        .format(name=html_escape.escape(str(name)),
                value=html_escape.escape(str(value)))
        for name, value in values.items()
    )


def render_report_v3_html(view: Mapping[str, Any]) -> str:
    """Render the sealed-record report for one resolved v3 evidence view.

    Pure text rendering over the closed view: every displayed value is the
    sealed server value, escaped verbatim; nothing is recomputed, interpreted
    or ranked. The report carries the contract 27 §10 disclosures and the
    standing non-advice statements. Callers must resolve the candidate first;
    this function renders whatever closed view it is given.
    """
    identity = dict(view["identity"])
    bindings = dict(view["bindings"])
    active_tuple = dict(view["active_tuple"])
    receipt = dict(view["semantic_receipt"])
    execution_count = len(receipt.get("validated_execution_ids", []))
    disclosures = (
        ("Execution model", (
            "Fills are priced by the sealed execution model named in the "
            "contract tuple ({model}); the exact identities are recorded "
            "above and are not restated here."
        ).format(model=html_escape.escape(
            str(active_tuple.get("execution_cost_model"))))),
        ("Costs", (
            "Commission and slippage identities are sealed inside the "
            "validation plan this record binds; the report restates none of "
            "them independently."
        )),
        ("Benchmark alignment", (
            "Benchmark comparisons are defined by the sealed validation plan "
            "and appear only on surfaces that project the validated ledger."
        )),
        ("Validation plan", (
            "Validation plan version {plan}."
        ).format(plan=html_escape.escape(
            str(active_tuple.get("validation_plan_version"))))),
        ("Data lineage", (
            "Data label {label}; snapshot {snapshot}."
        ).format(
            label=html_escape.escape(str(identity.get("data_label"))),
            snapshot=html_escape.escape(str(identity.get("snapshot_id"))))),
        ("Limitations", (
            "This record proves what was sealed and checked, not how a "
            "strategy will behave in the future. Past results do not "
            "determine future results."
        )),
        ("Advice status", (
            "This report is not investment advice and not a forecast. "
            "Completion of the validation battery is not an endorsement of "
            "any strategy."
        )),
    )
    disclosure_html = "".join(
        "<section><h3>{title}</h3><p>{body}</p></section>".format(
            title=html_escape.escape(title), body=body)
        for title, body in disclosures
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Sealed evidence record</title></head><body>"
        "<main>"
        "<h1>Sealed evidence record (contract v3)</h1>"
        "<p>This report presents the sealed contract identities and the "
        "recorded independent-validation receipt for one run. It contains no "
        "performance figures: metric surfaces project only the validated "
        "ledger.</p>"
        "<h2>Validation receipt</h2>"
        "<p>Recorded status <code>{status}</code> by <code>{validator}</code> "
        "over {count} sealed execution record{plural}.</p>"
        "<table>{receipt_rows}</table>"
        "<h2>Sealed identity</h2><table>{identity_rows}</table>"
        "<h2>Payload bindings</h2><table>{binding_rows}</table>"
        "<h2>Contract tuple</h2><table>{tuple_rows}</table>"
        "<h2>Disclosures</h2>{disclosures}"
        "</main></body></html>"
    ).format(
        status=html_escape.escape(str(receipt.get("status"))),
        validator=html_escape.escape(str(receipt.get("validator_version"))),
        count=execution_count,
        plural="" if execution_count == 1 else "s",
        receipt_rows=_rows({
            "Ledger": receipt.get("ledger_id"),
            "Result hash": receipt.get("result_hash"),
            "Financial contract": receipt.get("financial_contract_sha256"),
        }),
        identity_rows=_rows(identity),
        binding_rows=_rows(bindings),
        tuple_rows=_rows(active_tuple),
        disclosures=disclosure_html,
    )
