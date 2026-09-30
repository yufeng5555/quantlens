"""Write-once ledger artifacts and verified Run Manifest checkpoints.

The worker treats the ledger + manifest as the durable boundary between computation and
presentation.  A report may only be rendered from :func:`load_sealed_artifacts`, which
re-reads every file, rejects unsafe paths, verifies every hash, and checks the manifest's
bindings.  This makes a report retry cheap and prevents a modified artifact from being
silently presented as sealed evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

import jsonschema

from quantlens_schema import (
    load_dataset_manifest_schema,
    load_manifest_schema,
    spec_hash,
)

from .config import ENGINE_SEMVER, battery_config_hash, image_digest
from .evidence_contract_registry import (
    LEDGER_V0_NOTE,
    PresentationContract,
    UnknownPresentationContractError,
    registered_presentation_producers,
    resolve_presentation_contract,
)
from .snapshot import DataQualityError, canonical_snapshot_identity
from .validation_plan import BATTERY_V1, BATTERY_V2

PRODUCER = f"quantlens-engine/{ENGINE_SEMVER}+battery-v1"
PRODUCER_V2 = f"quantlens-engine/{ENGINE_SEMVER}+battery-v2"


def producer_for_profile(profile: str) -> str:
    if profile == BATTERY_V1:
        return PRODUCER
    if profile == BATTERY_V2:
        return PRODUCER_V2
    raise ArtifactIntegrityError(f"unsupported artifact producer profile: {profile!r}")

REQUIRED_ARTIFACT_KINDS_V0 = frozenset({
    "spec", "segments", "is_result", "oos_result", "oos_execution_audit",
    "sensitivity", "cost_stress", "falsification", "evidence_status",
    "data_gaps", "snapshot_ref",
})
# Backward-compatible public name used by the Gate 2 tests and any local callers.
REQUIRED_ARTIFACT_KINDS = REQUIRED_ARTIFACT_KINDS_V0
REQUIRED_ARTIFACT_KINDS_V1 = REQUIRED_ARTIFACT_KINDS_V0 | {"data_provenance"}
REQUIRED_ARTIFACT_KINDS_BATTERY_V2 = frozenset({
    "spec", "validation_plan", "partitions", "development_result",
    "walk_forward", "regime_analysis", "final_holdout_result",
    "final_holdout_execution_audit", "temporal_integrity", "sensitivity",
    "cost_stress", "falsification", "evidence_status", "data_gaps", "snapshot_ref",
})


class ArtifactIntegrityError(RuntimeError):
    """A purported sealed ledger is incomplete, unsafe, or does not match its hashes."""


class UnsupportedArtifactContractError(ArtifactIntegrityError):
    """A hash-valid checkpoint has no registered read-only presentation contract."""


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _canonical_sha256(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _unprefixed_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ArtifactIntegrityError(f"{label} must be a SHA-256 string")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ArtifactIntegrityError(f"{label} must contain a lowercase SHA-256 digest")
    return digest


def required_artifact_kinds_for_spec(
    spec: dict, battery_profile: str = BATTERY_V1,
) -> frozenset[str]:
    """Return the versioned evidence contract without changing the v1.0 ledger."""
    version = spec.get("dsl_version") if isinstance(spec, dict) else None
    if battery_profile == BATTERY_V2:
        if version not in {"1.0", "1.1", "1.2"}:
            raise ArtifactIntegrityError(f"unsupported sealed DSL version: {version!r}")
        return (REQUIRED_ARTIFACT_KINDS_BATTERY_V2 | {"data_provenance"}
                if version in {"1.1", "1.2"}
                else REQUIRED_ARTIFACT_KINDS_BATTERY_V2)
    if battery_profile != BATTERY_V1:
        raise ArtifactIntegrityError(f"unsupported battery profile: {battery_profile!r}")
    if version == "1.0":
        return REQUIRED_ARTIFACT_KINDS_V0
    if version == "1.1":
        return REQUIRED_ARTIFACT_KINDS_V1
    if version == "1.2":
        return REQUIRED_ARTIFACT_KINDS_V1
    raise ArtifactIntegrityError(f"unsupported sealed DSL version: {version!r}")


def _validate_financial_payload_contract(payloads: dict[str, dict]) -> frozenset[str]:
    """Return the exact versioned financial-artifact contract or fail closed.

    The write-once ledger and its ``result_hash`` are reserved for deterministic
    financial evidence.  Presentation, agent, and narrative records must use a
    separate producer namespace/storage path; accepting an arbitrary extra payload
    here would silently make model-derived bytes part of the financial result identity.
    """
    if not isinstance(payloads, dict):
        raise ArtifactIntegrityError("financial artifact payloads must be an object")
    spec_bundle = payloads.get("spec")
    sealed_spec = spec_bundle.get("spec") if isinstance(spec_bundle, dict) else None
    if not isinstance(sealed_spec, dict):
        raise ArtifactIntegrityError(
            "financial artifact payloads require a sealed spec bundle")
    plan = payloads.get("validation_plan")
    profile = plan.get("profile_id") if isinstance(plan, dict) else BATTERY_V1
    required = required_artifact_kinds_for_spec(sealed_spec, profile)
    actual = set(payloads)
    missing = set(required) - actual
    unexpected = actual - set(required)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(sorted(missing)))
        if unexpected:
            details.append("unexpected: " + ", ".join(sorted(map(str, unexpected))))
        raise ArtifactIntegrityError(
            "financial artifact contract mismatch (" + "; ".join(details) + ")")
    if any(not isinstance(payloads[kind], dict) for kind in required):
        raise ArtifactIntegrityError("every financial artifact payload must be an object")
    return required


def data_provenance_for_snapshot(spec: dict, snapshot_meta: dict, *, actor_id: str) -> dict:
    """Validate and safely project a dataset-backed provenance identity.

    The source spec, snapshot generator and canonical dataset manifest must all bind to
    the same immutable dataset.  The returned artifact deliberately excludes the upload
    filename, column mapping, owner id and every local filesystem detail.
    """
    version = spec.get("dsl_version")
    if version not in {"1.1", "1.2"}:
        raise ArtifactIntegrityError("data provenance requires DSL 1.1 or 1.2")
    source = (spec.get("data") or {}).get("source")
    expected_kind = "user_provided" if version == "1.1" else "licensed_provider"
    expected_label = "USER_UPLOADED" if version == "1.1" else "LICENSED_PROVIDER"
    expected_dataset_version = "dataset-v1" if version == "1.1" else "dataset-v2"
    if not isinstance(source, dict) or source.get("kind") != expected_kind:
        raise ArtifactIntegrityError(
            f"DSL {version} has no {expected_kind} dataset source")
    if snapshot_meta.get("label") != expected_label:
        raise ArtifactIntegrityError(
            f"DSL {version} must execute a {expected_label} snapshot")

    generator = snapshot_meta.get("generator")
    dataset_manifest = snapshot_meta.get("dataset_manifest")
    if not isinstance(generator, dict) or not isinstance(dataset_manifest, dict):
        raise ArtifactIntegrityError("user snapshot has no sealed dataset provenance")
    try:
        jsonschema.validate(
            dataset_manifest,
            load_dataset_manifest_schema(expected_dataset_version),
            format_checker=jsonschema.FormatChecker(),
        )
    except jsonschema.ValidationError as exc:
        raise ArtifactIntegrityError(
            f"{expected_dataset_version} schema validation failed") from exc

    canonical_manifest_sha = hashlib.sha256(_canonical(dataset_manifest)).hexdigest()
    snapshot_manifest_sha = _unprefixed_sha256(
        snapshot_meta.get("dataset_manifest_sha256"), label="snapshot dataset-manifest hash")
    generator_manifest_sha = _unprefixed_sha256(
        generator.get("dataset_manifest_sha256"), label="generator dataset-manifest hash")
    source_manifest_sha = _unprefixed_sha256(
        source.get("dataset_manifest_sha256"), label="spec dataset-manifest hash")
    if len({canonical_manifest_sha, snapshot_manifest_sha, generator_manifest_sha,
            source_manifest_sha}) != 1:
        raise ArtifactIntegrityError(
            "spec, snapshot and dataset manifest hashes do not bind to the same dataset")

    dataset_id = source.get("dataset_id")
    if (not isinstance(dataset_id, str) or generator.get("dataset_id") != dataset_id or
            dataset_manifest.get("dataset_id") != dataset_id):
        raise ArtifactIntegrityError(
            "spec, snapshot and dataset manifest ids do not bind to the same dataset")
    if generator.get("actor_id") != actor_id or dataset_manifest.get("actor_id") != actor_id:
        raise ArtifactIntegrityError("dataset ownership does not match the accepted run actor")

    symbol = (spec.get("universe") or {}).get("symbol")
    manifest_symbol = (
        dataset_manifest.get("symbol") if version == "1.1"
        else (dataset_manifest.get("instrument") or {}).get("symbol")
    )
    if manifest_symbol != symbol:
        raise ArtifactIntegrityError("dataset symbol does not match the confirmed universe")
    coverage = dataset_manifest.get("coverage")
    requested = (spec.get("data") or {}).get("range")
    if not isinstance(coverage, dict) or not isinstance(requested, dict):
        raise ArtifactIntegrityError("dataset coverage or requested range is malformed")
    if requested.get("start", "") < coverage.get("start", "") or \
            requested.get("end", "") > coverage.get("end", ""):
        raise ArtifactIntegrityError("confirmed run range escapes the sealed dataset coverage")
    if (snapshot_meta.get("coverage") or {}).get(symbol) != coverage:
        raise ArtifactIntegrityError("snapshot coverage contradicts the dataset manifest")

    # This is the public-safe, fixed provenance projection.  Do not add source paths,
    # original filenames, user ids, or the uploaded header mapping here.
    value = {
        "data_label": expected_label,
        "snapshot_id": snapshot_meta.get("snapshot_id"),
        "snapshot_sha256": snapshot_meta.get("sha256"),
        "dataset_id": dataset_id,
        "dataset_manifest_sha256": canonical_manifest_sha,
        "symbol": symbol,
        "coverage": coverage,
        "timezone": dataset_manifest.get("timezone"),
        "row_count": dataset_manifest.get("row_count"),
    }
    if version == "1.1":
        value.update({
            "source_sha256": dataset_manifest.get("source_sha256"),
            "price_adjustment": dataset_manifest.get("price_adjustment"),
        })
    else:
        licensed_source = dataset_manifest["source"]
        instrument = dataset_manifest["instrument"]
        rights = dataset_manifest["rights"]
        value.update({
            "dataset_manifest_version": "dataset-v2",
            "provider_id": licensed_source["provider_id"],
            "feed": licensed_source["feed"],
            "tier": licensed_source["tier"],
            "instrument_id": instrument["instrument_id"],
            "mic": instrument["mic"],
            "currency": instrument["currency"],
            "adjustment_mode": dataset_manifest["adjustment_mode"],
            "retrieved_at": dataset_manifest["retrieved_at"],
            "revision": dataset_manifest["revision"],
            "provider_payload_sha256": dataset_manifest["provider_payload_sha256"],
            "normalized_rows_sha256": dataset_manifest["normalized_rows_sha256"],
            "rights_policy_sha256": rights["policy_sha256"],
            "required_attribution": rights["required_attribution"],
            "rights": rights["use"],
        })
    return value


def _write_once(path: Path, body: bytes) -> None:
    """Atomically create ``path``; an identical retry is accepted, mutation is rejected.

    A temporary file is fsynced and hard-linked into place, so a process crash cannot
    expose a half-written final artifact.  ``os.link`` fails rather than replacing an
    existing checkpoint.  Retrying deterministic work therefore succeeds only when the
    bytes are identical.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != body:
            raise ArtifactIntegrityError(f"write-once artifact differs: {path.name}")
        return
    tmp = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    try:
        with tmp.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != body:
                raise ArtifactIntegrityError(f"write-once artifact differs: {path.name}")
    finally:
        tmp.unlink(missing_ok=True)


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError(f"cannot read valid JSON from {path.name}") from exc
    if not isinstance(value, dict):
        raise ArtifactIntegrityError(f"{path.name} must contain a JSON object")
    return value


def _safe_entry_path(run_dir: Path, raw_path: object) -> Path:
    """Resolve one ledger entry without permitting absolute paths or traversal."""
    if not isinstance(raw_path, str) or not raw_path:
        raise ArtifactIntegrityError("ledger entry path must be a non-empty string")
    relative = Path(raw_path)
    if relative.is_absolute() or len(relative.parts) != 1 or relative.name != raw_path:
        raise ArtifactIntegrityError(f"unsafe ledger entry path: {raw_path!r}")
    candidate = run_dir / relative
    if candidate.is_symlink():
        raise ArtifactIntegrityError(f"symlink artifacts are not allowed: {raw_path}")
    try:
        resolved = candidate.resolve(strict=True)
        root = run_dir.resolve(strict=True)
    except OSError as exc:
        raise ArtifactIntegrityError(f"missing ledger artifact: {raw_path}") from exc
    if resolved.parent != root:
        raise ArtifactIntegrityError(f"artifact escapes run directory: {raw_path}")
    return resolved


def _result_hash(entries: list[dict]) -> str:
    return "sha256:" + hashlib.sha256(
        "".join(sorted(entry["sha256"] for entry in entries)).encode()
    ).hexdigest()


def write_artifacts(run_dir: Path, payloads: dict[str, dict]) -> dict:
    """Write each battery payload as a content-hashed JSON artifact + a ledger index.

    Returns {"entries": [...], "result_hash": ...}.
    """
    # Validate before creating the directory or writing even one file.  In particular,
    # an agent/narrative record can never be folded into the financial result hash.
    _validate_financial_payload_contract(payloads)
    plan = payloads.get("validation_plan")
    profile = plan.get("profile_id") if isinstance(plan, dict) else BATTERY_V1
    producer = producer_for_profile(profile)
    run_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for kind in sorted(payloads):
        body = _canonical({"kind": kind, "producer": producer, "payload": payloads[kind]})
        sha = hashlib.sha256(body).hexdigest()
        artifact_id = f"{kind}-{sha[:12]}"
        path = run_dir / f"artifact_{kind}.json"
        _write_once(path, body)
        entries.append({"artifact_id": artifact_id, "kind": kind, "sha256": sha,
                        "path": path.name, "producer": producer})
    result_hash = _result_hash(entries)
    index = {"entries": entries, "result_hash": result_hash,
             "note": LEDGER_V0_NOTE}
    _write_once(run_dir / "ledger_index.json", _canonical(index))
    return index


def build_manifest(run_dir: Path, run: dict, spec: dict, snapshot_meta: dict,
                   result_hash: str) -> dict:
    receipt = run.get("confirmation_receipt")
    if not isinstance(receipt, dict) or not receipt.get("restatement_hash"):
        raise ArtifactIntegrityError(
            "run has no confirmation receipt; a manifest cannot seal without one")
    version = spec.get("dsl_version")
    if version == "1.0":
        if snapshot_meta.get("label") != "SYNTHETIC":
            raise ArtifactIntegrityError("DSL 1.0 must seal a SYNTHETIC snapshot")
        manifest_version = "v0"
        data_label = "SYNTHETIC"
        provenance_fields: dict[str, str] = {}
    elif version in {"1.1", "1.2"}:
        provenance = data_provenance_for_snapshot(
            spec, snapshot_meta, actor_id=run["actor_id"])
        manifest_version = "v1" if version == "1.1" else "v2"
        data_label = provenance["data_label"]
        provenance_fields = {
            "dataset_id": provenance["dataset_id"],
            "dataset_manifest_sha256": provenance["dataset_manifest_sha256"],
        }
        if version == "1.2":
            provenance_fields.update({
                "dataset_manifest_version": provenance["dataset_manifest_version"],
                "provider_id": provenance["provider_id"],
                "instrument_id": provenance["instrument_id"],
                "rights_policy_sha256": provenance["rights_policy_sha256"],
            })
    else:
        raise ArtifactIntegrityError(f"unsupported DSL version for manifest: {version!r}")

    manifest = {
        "manifest_id": f"mfst-{run['run_id']}",
        "manifest_version": manifest_version,
        "spec_hash": spec_hash(spec),
        "spec_version": run.get("spec_version", 1),
        "dsl_schema_version": spec["dsl_version"],
        "snapshot_id": snapshot_meta["snapshot_id"],
        "snapshot_sha256": snapshot_meta["sha256"],
        "engine_semver": ENGINE_SEMVER,
        "image_digest": image_digest(),
        "battery_config_hash": battery_config_hash(
            run.get("battery_profile", BATTERY_V1)),
        "actor_id": run["actor_id"],
        "created_at": run["created_at"],  # stamped by the control plane, not the engine
        "result_hash": result_hash,
        "data_label": data_label,
        "confirmation_receipt_hash": receipt["restatement_hash"],
        **provenance_fields,
    }
    try:
        jsonschema.validate(manifest, load_manifest_schema(manifest_version))
    except jsonschema.ValidationError as exc:
        raise ArtifactIntegrityError(
            f"manifest {manifest_version} schema validation failed") from exc
    _write_once(run_dir / "manifest.json", _canonical(manifest))
    return manifest


def verify_ledger(
    run_dir: Path,
    *,
    required_kinds: set[str] | frozenset[str] | None = None,
    _allowed_producers: frozenset[str] | None = None,
) -> tuple[dict, dict[str, Any]]:
    """Verify the ledger index and return it with payloads keyed by artifact kind."""
    index = _read_object(run_dir / "ledger_index.json")
    entries = index.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ArtifactIntegrityError("ledger_index.json has no artifact entries")

    seen_kinds: set[str] = set()
    seen_paths: set[str] = set()
    payloads: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ArtifactIntegrityError("ledger entry must be an object")
        kind = entry.get("kind")
        raw_path = entry.get("path")
        expected_sha = entry.get("sha256")
        if not isinstance(kind, str) or not kind:
            raise ArtifactIntegrityError("ledger entry kind is invalid")
        if kind in seen_kinds or raw_path in seen_paths:
            raise ArtifactIntegrityError(f"duplicate ledger kind/path: {kind}")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            raise ArtifactIntegrityError(f"invalid SHA-256 for artifact {kind}")
        artifact_path = _safe_entry_path(run_dir, raw_path)
        body = artifact_path.read_bytes()
        actual_sha = hashlib.sha256(body).hexdigest()
        if actual_sha != expected_sha:
            raise ArtifactIntegrityError(f"artifact hash mismatch: {kind}")
        wrapper = _read_object(artifact_path)
        allowed_producers = _allowed_producers or frozenset({PRODUCER, PRODUCER_V2})
        if (entry.get("producer") != wrapper.get("producer")
                or entry.get("producer") not in allowed_producers):
            raise ArtifactIntegrityError(f"artifact producer is not current: {kind}")
        if wrapper.get("kind") != kind:
            raise ArtifactIntegrityError(f"artifact wrapper mismatch: {kind}")
        if entry.get("artifact_id") != f"{kind}-{actual_sha[:12]}":
            raise ArtifactIntegrityError(f"artifact id mismatch: {kind}")
        if "payload" not in wrapper:
            raise ArtifactIntegrityError(f"artifact payload missing: {kind}")
        seen_kinds.add(kind)
        seen_paths.add(raw_path)
        payloads[kind] = wrapper["payload"]

    required = set(required_kinds or ())
    missing = required - seen_kinds
    if missing:
        raise ArtifactIntegrityError(
            "sealed ledger is incomplete; missing: " + ", ".join(sorted(missing))
        )
    calculated = _result_hash(entries)
    if index.get("result_hash") != calculated:
        raise ArtifactIntegrityError("ledger result_hash mismatch")
    plan = payloads.get("validation_plan")
    profile = plan.get("profile_id") if isinstance(plan, dict) else BATTERY_V1
    if _allowed_producers is None:
        expected_producer = producer_for_profile(profile)
        if any(entry.get("producer") != expected_producer for entry in entries):
            raise ArtifactIntegrityError(
                "artifact producer does not match the sealed validation profile")
    elif len({entry.get("producer") for entry in entries}) != 1:
        raise ArtifactIntegrityError(
            "historical artifact entries do not share one registered producer")
    return index, payloads


def _load_artifacts(
    run_dir: Path,
    *,
    expected_run: dict | None,
    presentation: bool,
) -> tuple[dict, dict, dict[str, Any], PresentationContract | None]:
    """Shared byte/identity checks with an explicit strict-or-presentation boundary."""
    # Read hashes first, then derive the versioned artifact contract from the sealed spec.
    # This preserves exact v0 checkpoint compatibility while making provenance mandatory
    # for v1 rather than guessing from whichever manifest happens to be present.
    ledger, payloads = verify_ledger(
        run_dir,
        _allowed_producers=(
            registered_presentation_producers() if presentation else None
        ),
    )
    manifest = _read_object(run_dir / "manifest.json")
    spec_payload = payloads.get("spec")
    if not isinstance(spec_payload, dict) or not isinstance(spec_payload.get("spec"), dict):
        raise ArtifactIntegrityError("spec artifact is malformed")
    sealed_spec = spec_payload["spec"]
    plan = payloads.get("validation_plan")
    profile = plan.get("profile_id") if isinstance(plan, dict) else BATTERY_V1
    required = required_artifact_kinds_for_spec(sealed_spec, profile)
    missing = set(required) - set(payloads)
    unexpected = set(payloads) - set(required)
    if missing:
        raise ArtifactIntegrityError(
            "sealed ledger is incomplete; missing: " + ", ".join(sorted(missing)))
    if unexpected:
        raise ArtifactIntegrityError(
            "sealed financial ledger has non-financial artifact kinds: "
            + ", ".join(sorted(unexpected)))
    sealed_version = sealed_spec.get("dsl_version")
    expected_manifest_version = {
        "1.0": "v0", "1.1": "v1", "1.2": "v2",
    }.get(sealed_version)
    if expected_manifest_version is None:
        raise ArtifactIntegrityError(
            f"unsupported sealed DSL version: {sealed_version!r}")
    if manifest.get("manifest_version") != expected_manifest_version:
        raise ArtifactIntegrityError(
            "manifest version does not match the sealed DSL/data-source contract")
    try:
        jsonschema.validate(manifest, load_manifest_schema(expected_manifest_version))
    except jsonschema.ValidationError as exc:
        raise ArtifactIntegrityError(
            f"manifest {expected_manifest_version} schema validation failed") from exc
    if manifest.get("result_hash") != ledger["result_hash"]:
        raise ArtifactIntegrityError("manifest is not bound to this ledger result hash")

    snapshot_payload = payloads.get("snapshot_ref")
    if not isinstance(snapshot_payload, dict):
        raise ArtifactIntegrityError("snapshot_ref artifact is malformed")
    sealed_spec_hash = spec_payload.get("spec_hash")
    if manifest.get("spec_hash") != sealed_spec_hash:
        raise ArtifactIntegrityError("manifest/spec artifact hash mismatch")
    recomputed_spec_hash = spec_hash(sealed_spec)
    if sealed_spec_hash != recomputed_spec_hash:
        raise ArtifactIntegrityError("sealed spec hash does not match sealed spec bytes")
    if (manifest.get("snapshot_id") != snapshot_payload.get("snapshot_id") or
            manifest.get("snapshot_sha256") != snapshot_payload.get("sha256")):
        raise ArtifactIntegrityError("manifest/snapshot artifact binding mismatch")
    try:
        canonical_snapshot_sha, canonical_snapshot_id = canonical_snapshot_identity(
            snapshot_payload,
        )
    except DataQualityError as exc:
        raise ArtifactIntegrityError("sealed snapshot identity is malformed") from exc
    if (snapshot_payload.get("sha256") != canonical_snapshot_sha or
            snapshot_payload.get("snapshot_id") != canonical_snapshot_id):
        raise ArtifactIntegrityError("sealed snapshot metadata identity mismatch")
    if manifest.get("data_label") != snapshot_payload.get("label"):
        raise ArtifactIntegrityError("manifest data label contradicts the sealed snapshot")

    if expected_manifest_version == "v0":
        if snapshot_payload.get("label") != "SYNTHETIC":
            raise ArtifactIntegrityError("manifest v0 may only bind SYNTHETIC data")
    else:
        provenance = data_provenance_for_snapshot(
            sealed_spec, snapshot_payload, actor_id=manifest.get("actor_id"))
        if payloads.get("data_provenance") != provenance:
            raise ArtifactIntegrityError(
                "data_provenance artifact does not match the sealed source and snapshot")
        if (manifest.get("dataset_id") != provenance["dataset_id"] or
                manifest.get("dataset_manifest_sha256") !=
                provenance["dataset_manifest_sha256"] or
                manifest.get("snapshot_id") != provenance["snapshot_id"] or
                manifest.get("snapshot_sha256") != provenance["snapshot_sha256"]):
            raise ArtifactIntegrityError(
                f"Run Manifest {expected_manifest_version} is not triple-bound to "
                "source, provenance and snapshot")
        if expected_manifest_version == "v2" and (
            manifest.get("dataset_manifest_version") != "dataset-v2"
            or manifest.get("provider_id") != provenance["provider_id"]
            or manifest.get("instrument_id") != provenance["instrument_id"]
            or manifest.get("rights_policy_sha256")
            != provenance["rights_policy_sha256"]
        ):
            raise ArtifactIntegrityError(
                "Run Manifest v2 is not bound to licensed source identity and rights")
    presentation_contract: PresentationContract | None = None
    if presentation:
        try:
            presentation_contract = resolve_presentation_contract(
                manifest, ledger, payloads,
            )
        except UnknownPresentationContractError as exc:
            raise UnsupportedArtifactContractError(
                "sealed evidence has no registered presentation contract"
            ) from exc
    else:
        current_bindings = {
            "engine_semver": ENGINE_SEMVER,
            "image_digest": image_digest(),
            "battery_config_hash": battery_config_hash(profile),
        }
        for field, expected in current_bindings.items():
            if manifest.get(field) != expected:
                raise ArtifactIntegrityError(f"manifest {field} is not current")
    if expected_run is not None:
        if manifest.get("manifest_id") != f"mfst-{expected_run['run_id']}":
            raise ArtifactIntegrityError("manifest belongs to another run")
        if manifest.get("actor_id") != expected_run["actor_id"]:
            raise ArtifactIntegrityError("manifest actor does not match run")
        if sealed_spec_hash != expected_run["spec_hash"]:
            raise ArtifactIntegrityError("sealed spec does not match accepted run")
        if profile != expected_run.get("battery_profile", BATTERY_V1):
            raise ArtifactIntegrityError(
                "sealed validation profile does not match accepted run")
        if manifest.get("battery_config_hash") != expected_run.get(
                "battery_profile_hash", battery_config_hash(BATTERY_V1)):
            raise ArtifactIntegrityError(
                "manifest validation-profile hash does not match accepted run")
        # Complete identity binding: every control-plane identity field exposed from the
        # manifest must match the accepted run row — nothing is silently mutable.
        if manifest.get("created_at") != expected_run["created_at"]:
            raise ArtifactIntegrityError("manifest created_at does not match accepted run")
        if manifest.get("spec_version") != expected_run.get("spec_version", 1):
            raise ArtifactIntegrityError("manifest spec_version does not match accepted run")
        receipt = expected_run.get("confirmation_receipt")
        if not isinstance(receipt, dict) or \
                manifest.get("confirmation_receipt_hash") != receipt.get("restatement_hash"):
            raise ArtifactIntegrityError(
                "sealed confirmation receipt hash does not match the run's receipt")
        if (receipt.get("battery_profile", BATTERY_V1) != profile
                or receipt.get("battery_profile_hash") !=
                manifest.get("battery_config_hash")):
            raise ArtifactIntegrityError(
                "confirmation receipt is not bound to the sealed validation profile")
        expected_receipt_hash = hashlib.sha256(
            str(receipt.get("restatement", "")).encode("utf-8")).hexdigest()
        if expected_receipt_hash != receipt.get("restatement_hash"):
            raise ArtifactIntegrityError(
                "confirmation receipt text does not hash to its sealed receipt hash")
        if profile == BATTERY_V2:
            anchor = expected_run.get("validation_anchor")
            if not isinstance(anchor, dict):
                raise ArtifactIntegrityError(
                    "battery-v2 has no write-once control-plane validation anchor")
            expected_anchor = {
                "temporal_integrity_sha256": _canonical_sha256(
                    payloads.get("temporal_integrity")),
                "partitions_sha256": _canonical_sha256(payloads.get("partitions")),
                "validation_plan_sha256": _canonical_sha256(
                    payloads.get("validation_plan")),
                "final_execution_binding_sha256": _canonical_sha256(
                    (payloads.get("final_holdout_result") or {}).get(
                        "execution_binding")),
            }
            if any(anchor.get(key) != value
                   for key, value in expected_anchor.items()):
                raise ArtifactIntegrityError(
                    "sealed battery-v2 evidence contradicts its control-plane anchor")
    return manifest, ledger, payloads, presentation_contract


def load_sealed_artifacts(
    run_dir: Path, *, expected_run: dict | None = None,
) -> tuple[dict, dict, dict[str, Any]]:
    """Strict loader for current-runtime resume, promotion, sealing, and recovery.

    This intentionally retains the exact current engine, runtime-image, and battery hash
    checks.  Presentation code must use :func:`load_presentation_artifacts` instead.
    """
    manifest, ledger, payloads, _contract = _load_artifacts(
        run_dir, expected_run=expected_run, presentation=False,
    )
    return manifest, ledger, payloads


def load_presentation_artifacts(
    run_dir: Path, *, expected_run: dict | None = None,
) -> tuple[dict, dict, dict[str, Any], PresentationContract]:
    """Read one registered historical checkpoint without comparing current image bytes.

    The loader is read-only: it cannot resume, promote, reseal, or rewrite a checkpoint.
    Every existing path/hash/schema/spec/snapshot/provenance/receipt/run binding remains
    mandatory.  Only the mutable *current runtime equality* check is replaced by an exact
    match against the frozen presentation registry.
    """
    manifest, ledger, payloads, contract = _load_artifacts(
        run_dir, expected_run=expected_run, presentation=True,
    )
    if contract is None:  # Defensive: presentation=True must resolve exactly one tuple.
        raise UnsupportedArtifactContractError(
            "sealed evidence has no registered presentation contract")
    return manifest, ledger, payloads, contract
