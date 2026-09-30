"""Write-once local IO for the dormant Gate-B ledger candidate.

This namespace is intentionally different from the active ``ledger_index.json`` and
``manifest.json`` checkpoint.  The default runner does not import it.  A caller must
inject a reviewed *test* producer allowlist, so no production producer becomes active by
merely importing or exercising this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Collection, Mapping

from .financial_semantic_validator_v1 import FinancialSemanticValidatorV1
from .valuation_ledger_v1 import (
    FINANCIAL_CONTRACT_VERSION,
    ValuationLedgerContractError,
    build_ledger_entry_v1,
    build_ledger_index_v1,
    canonical_json_bytes,
    required_gate_b_kinds_v1,
    sha256_json,
    validate_ledger_index_contract_v1,
    validate_schema_v1,
    validate_valuation_ledger_contract_v1,
)


CANDIDATE_DIRECTORY_NAME = "ledger-v1-candidate"
INDEX_FILENAME = "ledger_v1_index.json"
RECEIPT_FILENAME = "semantic_validation_receipt.json"


class DormantLedgerIOError(RuntimeError):
    """A candidate write/read is unsafe, incomplete, mutated, or unregistered."""


def _fail(detail: str, cause: BaseException | None = None) -> None:
    error = DormantLedgerIOError(detail)
    if cause is None:
        raise error
    raise error from cause


def _write_once(path: Path, body: bytes) -> None:
    """Atomically create a file; accept only an identical deterministic retry."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        _fail(f"symlink candidate file is forbidden: {path.name}")
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as exc:
            _fail(f"cannot read existing candidate file: {path.name}", exc)
        if existing != body:
            _fail(f"write-once candidate differs: {path.name}")
        return
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != body:
                _fail(f"write-once candidate differs: {path.name}")
    except OSError as exc:
        _fail(f"cannot write candidate file: {path.name}", exc)
    finally:
        temporary.unlink(missing_ok=True)


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read canonical JSON object from {path.name}", exc)
    if not isinstance(value, dict):
        _fail(f"{path.name} must contain a JSON object")
    return value


def _safe_file(directory: Path, raw_name: object) -> Path:
    if not isinstance(raw_name, str) or not raw_name:
        _fail("candidate entry path must be a non-empty string")
    relative = Path(raw_name)
    if relative.is_absolute() or len(relative.parts) != 1 or relative.name != raw_name:
        _fail(f"unsafe candidate path: {raw_name!r}")
    candidate = directory / relative
    if candidate.is_symlink():
        _fail(f"symlink candidate file is forbidden: {raw_name}")
    try:
        root = directory.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _fail(f"missing candidate file: {raw_name}", exc)
    if resolved.parent != root:
        _fail(f"candidate path escapes its directory: {raw_name}")
    return resolved


def _prefixed_hash(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a SHA-256 string")
    if value.startswith("sha256:"):
        digest = value[7:]
    else:
        digest = value
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        _fail(f"{label} must contain 64 lowercase hex characters")
    return "sha256:" + digest


def _dsl_version(payloads: Mapping[str, Mapping[str, Any]]) -> str:
    spec_bundle = payloads.get("spec")
    spec = spec_bundle.get("spec") if isinstance(spec_bundle, dict) else None
    value = spec.get("dsl_version") if isinstance(spec, dict) else None
    if not isinstance(value, str):
        _fail("candidate spec has no sealed DSL version")
    return value


def _validate_candidate_payloads(
    payloads: Mapping[str, Mapping[str, Any]], *, producer: str,
    reviewed_producers: Collection[str],
) -> frozenset[str]:
    if not isinstance(payloads, dict) or any(
            not isinstance(kind, str) or not isinstance(payload, dict)
            for kind, payload in payloads.items()):
        _fail("candidate payloads must be a kind-to-object map")
    if not isinstance(producer, str) or producer not in set(reviewed_producers):
        _fail("candidate producer is not in the injected reviewed test registry")
    try:
        required = required_gate_b_kinds_v1(_dsl_version(payloads))
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)
    actual = set(payloads)
    if actual != set(required):
        missing = sorted(set(required) - actual)
        unexpected = sorted(actual - set(required))
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        _fail("candidate Gate-B artifact set mismatch (" + "; ".join(details) + ")")

    financial_contract = payloads["financial_contract"]
    valuation_ledger = payloads["valuation_ledger"]
    try:
        validate_schema_v1(FINANCIAL_CONTRACT_VERSION, financial_contract)
        validate_valuation_ledger_contract_v1(valuation_ledger, financial_contract)
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)
    spec_hash = payloads["spec"].get("spec_hash")
    if valuation_ledger.get("spec_hash") != _prefixed_hash(spec_hash, "spec.spec_hash"):
        _fail("valuation_ledger spec_hash contradicts the sealed spec artifact")
    snapshot_hash = payloads["snapshot_ref"].get("sha256")
    if valuation_ledger.get("snapshot_sha256") != _prefixed_hash(
            snapshot_hash, "snapshot_ref.sha256"):
        _fail("valuation_ledger snapshot_sha256 contradicts snapshot_ref")
    return required


def write_dormant_candidate_ledger_v1(
    run_dir: Path,
    payloads: Mapping[str, Mapping[str, Any]],
    *,
    producer: str,
    reviewed_producers: Collection[str],
) -> dict[str, Any]:
    """Write a complete dormant ledger into a separate candidate directory.

    The function never writes ``ledger_index.json`` or ``manifest.json`` and therefore
    cannot create a checkpoint the current runner/report loader would accept.
    """
    required = _validate_candidate_payloads(
        payloads, producer=producer, reviewed_producers=reviewed_producers,
    )
    entries: list[dict[str, Any]] = []
    bodies: dict[str, bytes] = {}
    for kind in sorted(required):
        try:
            entry, body = build_ledger_entry_v1(
                kind=kind, producer=producer, payload=payloads[kind],
            )
        except ValuationLedgerContractError as exc:
            _fail(str(exc), exc)
        entries.append(entry)
        bodies[entry["path"]] = body
    try:
        index = build_ledger_index_v1(entries)
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)
    index_body = canonical_json_bytes(index)

    candidate_dir = Path(run_dir) / CANDIDATE_DIRECTORY_NAME
    if candidate_dir.is_symlink():
        _fail("candidate directory cannot be a symlink")
    candidate_dir.mkdir(parents=True, exist_ok=True)
    for name, body in bodies.items():
        _write_once(candidate_dir / name, body)
    _write_once(candidate_dir / INDEX_FILENAME, index_body)

    allowed_names = set(bodies) | {INDEX_FILENAME, RECEIPT_FILENAME}
    unexpected = sorted(
        child.name for child in candidate_dir.iterdir()
        if child.name not in allowed_names and not child.name.startswith(".")
    )
    if unexpected:
        _fail("candidate directory contains unexpected files: " + ", ".join(unexpected))
    return index


def load_dormant_candidate_ledger_v1(
    run_dir: Path,
    *,
    reviewed_producers: Collection[str],
) -> dict[str, Any]:
    """Read and verify every candidate wrapper, binding and required kind."""
    candidate_dir = Path(run_dir) / CANDIDATE_DIRECTORY_NAME
    if candidate_dir.is_symlink() or not candidate_dir.is_dir():
        _fail("dormant ledger candidate directory is missing or unsafe")
    index = _read_object(_safe_file(candidate_dir, INDEX_FILENAME))
    try:
        validate_ledger_index_contract_v1(index)
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)

    payloads: dict[str, dict[str, Any]] = {}
    artifact_wrappers: dict[str, dict[str, Any]] = {}
    expected_files = {INDEX_FILENAME}
    reviewed = set(reviewed_producers)
    for entry in index["entries"]:
        if entry["producer"] not in reviewed:
            _fail("candidate entry producer is not in the injected reviewed test registry")
        path = _safe_file(candidate_dir, entry["path"])
        expected_files.add(entry["path"])
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() != entry["sha256"]:
            _fail(f"candidate artifact hash mismatch: {entry['kind']}")
        try:
            wrapper = json.loads(body)
        except json.JSONDecodeError as exc:
            _fail(f"candidate wrapper is invalid JSON: {entry['kind']}", exc)
        if not isinstance(wrapper, dict) or set(wrapper) != {"kind", "producer", "payload"}:
            _fail(f"candidate wrapper has an unsupported shape: {entry['kind']}")
        if wrapper["kind"] != entry["kind"] or wrapper["producer"] != entry["producer"] \
                or not isinstance(wrapper["payload"], dict):
            _fail(f"candidate wrapper contradicts its entry: {entry['kind']}")
        if canonical_json_bytes(wrapper) != body:
            _fail(f"candidate wrapper is not canonical JSON: {entry['kind']}")
        artifact_wrappers[entry["kind"]] = wrapper
        payloads[entry["kind"]] = wrapper["payload"]

    receipt_path = candidate_dir / RECEIPT_FILENAME
    if receipt_path.exists():
        expected_files.add(RECEIPT_FILENAME)
    unexpected = sorted(
        child.name for child in candidate_dir.iterdir()
        if not child.name.startswith(".") and child.name not in expected_files
    )
    if unexpected:
        _fail("candidate directory contains unexpected files: " + ", ".join(unexpected))
    producer_values = {entry["producer"] for entry in index["entries"]}
    if len(producer_values) != 1:
        _fail("candidate artifacts do not share one exact producer identity")
    producer = next(iter(producer_values))
    _validate_candidate_payloads(
        payloads, producer=producer, reviewed_producers=reviewed,
    )
    return {
        "ledger_index": index,
        "artifact_wrappers": artifact_wrappers,
        "payloads": payloads,
    }


def _write_semantic_validation_receipt_v1(
    run_dir: Path,
    receipt: Mapping[str, Any],
    *,
    ledger_index: Mapping[str, Any],
    financial_contract: Mapping[str, Any],
    execution_ids: Collection[str],
) -> None:
    """Write the consumer receipt outside the ledger/result hash after validation."""
    try:
        validate_schema_v1("semantic-validation-receipt-v1", receipt)
        validate_ledger_index_contract_v1(ledger_index)
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)
    if receipt["ledger_id"] != ledger_index["ledger_id"] or \
            receipt["result_hash"] != ledger_index["result_hash"]:
        _fail("validation receipt does not bind the candidate ledger")
    if receipt["financial_contract_sha256"] != sha256_json(financial_contract):
        _fail("validation receipt does not bind the financial contract")
    if receipt["validated_execution_ids"] != list(execution_ids):
        _fail("validation receipt does not bind the exact execution order")
    candidate_dir = Path(run_dir) / CANDIDATE_DIRECTORY_NAME
    if candidate_dir.is_symlink() or not candidate_dir.is_dir():
        _fail("candidate ledger must exist before its consumer receipt")
    _write_once(candidate_dir / RECEIPT_FILENAME, canonical_json_bytes(receipt))


def validate_and_store_semantic_receipt_v1(
    run_dir: Path,
    *,
    manifest: Mapping[str, Any],
    reviewed_registry: Mapping[str, Any],
    reviewed_producers: Collection[str],
) -> dict[str, Any]:
    """Validate one dormant candidate and persist only its successful receipt.

    Loading reconstructs and verifies the exact artifact wrappers covered by the
    candidate index.  The independent semantic validator then consumes only those
    parsed copies plus the explicitly injected manifest and reviewed registry.  A
    typed validator failure propagates before the write-once receipt helper is ever
    reached, so failed candidates cannot acquire a semantic receipt.
    """
    candidate = load_dormant_candidate_ledger_v1(
        run_dir,
        reviewed_producers=reviewed_producers,
    )
    receipt = FinancialSemanticValidatorV1().validate(
        manifest,
        candidate["ledger_index"],
        candidate["artifact_wrappers"],
        reviewed_registry,
    )
    valuation_ledger = candidate["payloads"]["valuation_ledger"]
    execution_ids = [
        execution["execution_id"]
        for execution in valuation_ledger["executions"]
    ]
    _write_semantic_validation_receipt_v1(
        run_dir,
        receipt,
        ledger_index=candidate["ledger_index"],
        financial_contract=candidate["payloads"]["financial_contract"],
        execution_ids=execution_ids,
    )
    return receipt


def load_semantic_validation_receipt_v1(
    run_dir: Path, *, ledger_index: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_dir = Path(run_dir) / CANDIDATE_DIRECTORY_NAME
    receipt = _read_object(_safe_file(candidate_dir, RECEIPT_FILENAME))
    try:
        validate_schema_v1("semantic-validation-receipt-v1", receipt)
    except ValuationLedgerContractError as exc:
        _fail(str(exc), exc)
    if receipt["ledger_id"] != ledger_index.get("ledger_id") or \
            receipt["result_hash"] != ledger_index.get("result_hash"):
        _fail("stored semantic receipt does not bind the candidate ledger")
    return receipt


__all__ = [
    "CANDIDATE_DIRECTORY_NAME",
    "DormantLedgerIOError",
    "INDEX_FILENAME",
    "RECEIPT_FILENAME",
    "load_dormant_candidate_ledger_v1",
    "load_semantic_validation_receipt_v1",
    "validate_and_store_semantic_receipt_v1",
    "write_dormant_candidate_ledger_v1",
]
