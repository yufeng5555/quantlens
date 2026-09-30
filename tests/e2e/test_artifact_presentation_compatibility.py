"""Gate 7A.2 Gate A — strict resume versus historical presentation boundary.

Historical checkpoints remain byte-for-byte readable under their original contract,
but they cannot be resumed by a different runtime or enter financial-semantics-gated
surfaces.  Unknown tuples fail closed with a stable rebuild state, and presentation
reads never rewrite the checkpoint or its control-plane row.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import app as api_module
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec
from quantlens_worker import artifacts as artifacts_module
from quantlens_worker.artifacts import (
    ArtifactIntegrityError,
    load_presentation_artifacts,
    load_sealed_artifacts,
)
from quantlens_worker.evidence_contract_registry import SEALED_BUILD_REGISTRATIONS
from quantlens_worker.runner import process_next


@pytest.fixture()
def client(var_env):
    with TestClient(app) as test_client:
        yield test_client


def _published_run(client: TestClient, *, profile: str) -> str:
    spec = default_spec("QQQ")
    spec["data"]["range"] = {"start": "2015-01-01", "end": "2020-12-31"}
    response = client.post(
        "/runs",
        json=validated_run_payload(client, spec, battery_profile=profile),
    )
    assert response.status_code == 201, response.text
    run_id = response.json()["run_id"]
    assert process_next() == "published"
    return run_id


def _replace_manifest_image(run_dir: Path, image_digest: str) -> None:
    path = run_dir / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["image_digest"] = image_digest
    path.write_bytes(json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode())


def _directory_state(run_dir: Path) -> dict[str, tuple[bytes, int]]:
    """Capture content and modification time without depending on directory atime."""
    return {
        str(path.relative_to(run_dir)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(run_dir.rglob("*"))
        if path.is_file()
    }


def _registered_v1_image() -> str:
    images = [
        build.image_digest for build in SEALED_BUILD_REGISTRATIONS
        if build.contract_id == "legacy-battery-v1-ledger-v0"
    ]
    assert images, "the compatibility registry must freeze a historical v1 build"
    return images[0]


def _registered_v2_release_image() -> str:
    current = artifacts_module.image_digest()
    images = [
        build.image_digest for build in SEALED_BUILD_REGISTRATIONS
        if build.contract_id == "legacy-battery-v2-ledger-v0"
        and build.image_digest == current
    ]
    assert len(images) == 1, (
        "the current battery v2 release must be frozen exactly once"
    )
    return images[0]


def test_registered_old_image_v1_is_read_only_presentation_not_resumable(
    client: TestClient, var_env: Path,
):
    run_id = _published_run(client, profile="battery-v1")
    run_dir = var_env / "artifacts" / run_id
    _replace_manifest_image(run_dir, _registered_v1_image())
    expected_run = db.get_run_internal(run_id)
    assert expected_run is not None

    before_files = _directory_state(run_dir)
    before_row = copy.deepcopy(expected_run)

    manifest, ledger, payloads, contract = load_presentation_artifacts(
        run_dir, expected_run=expected_run,
    )
    assert manifest["image_digest"] == _registered_v1_image()
    assert ledger["result_hash"] == manifest["result_hash"]
    assert "validation_plan" not in payloads
    assert contract.contract_id == "legacy-battery-v1-ledger-v0"

    with pytest.raises(ArtifactIntegrityError, match="image_digest is not current"):
        load_sealed_artifacts(run_dir, expected_run=expected_run)

    evidence = client.get(f"/runs/{run_id}/evidence")
    assert evidence.status_code == 200, evidence.text
    descriptor = evidence.json()["artifact_contract"]
    assert descriptor == {
        "contract_id": "legacy-battery-v1-ledger-v0",
        "presentation_status": "legacy_active",
        "evidence_view_version": "v1",
        "evidence_semantics_version": "v1",
        "ledger_semantics_version": "ledger-v0",
        "execution_semantics_version": "linear-execution-friction-v0",
        "execution_cost_model": "linear_execution_friction",
        "verified_financial_semantics": False,
        "verified_surface_eligibility": "rebuild_required",
    }
    report = client.get(f"/runs/{run_id}/report")
    assert report.status_code == 200, report.text
    assert "Original historical evidence contract" in report.text
    assert "linear execution friction" in report.text

    assert _directory_state(run_dir) == before_files
    assert db.get_run_internal(run_id) == before_row


def test_unknown_image_returns_one_path_free_typed_rebuild_state(
    client: TestClient, var_env: Path,
):
    run_id = _published_run(client, profile="battery-v1")
    run_dir = var_env / "artifacts" / run_id
    _replace_manifest_image(
        run_dir,
        "local-runtime-sha256:" + "f" * 64,
    )
    before_files = _directory_state(run_dir)
    before_row = copy.deepcopy(db.get_run_internal(run_id))

    expected = {
        "code": "ARTIFACT_CONTRACT_REBUILD_REQUIRED",
        "run_id": run_id,
        "message": (
            "This checkpoint's sealed contract is not registered for safe historical "
            "presentation. Its files remain preserved and were not rewritten. Create a "
            "new run from the saved accepted spec to use the current contract."
        ),
        "rebuild": {
            "available": True,
            "source": "saved_accepted_spec",
        },
    }
    evidence = client.get(f"/runs/{run_id}/evidence")
    report = client.get(f"/runs/{run_id}/report")
    assert evidence.status_code == report.status_code == 409
    assert evidence.json() == report.json() == expected

    encoded = json.dumps(expected, sort_keys=True)
    for private_detail in (
        str(var_env), str(run_dir), "manifest.json", "ledger_index.json",
        "artifact_spec.json", "/Users/", "/private/",
    ):
        assert private_detail not in encoded
    assert "identity" not in expected and "results" not in expected
    assert _directory_state(run_dir) == before_files
    assert db.get_run_internal(run_id) == before_row


class _MustNotConstruct:
    @classmethod
    def from_environment(cls):
        raise AssertionError("Research Copilot crossed the financial-contract gate")


def test_current_legacy_v2_copilot_requires_financial_rebuild_before_provider(
    client: TestClient, monkeypatch,
):
    run_id = _published_run(client, profile="battery-v2")
    monkeypatch.setattr(
        api_module, "DevelopmentResearchCopilot", _MustNotConstruct,
    )

    response = client.get(f"/runs/{run_id}/research-copilot")
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "FINANCIAL_SEMANTICS_REBUILD_REQUIRED"
    assert body["run_id"] == run_id
    assert body["artifact_contract"] == {
        "contract_id": "legacy-battery-v2-ledger-v0",
        "presentation_status": "legacy_active",
        "evidence_view_version": "v2",
        "evidence_semantics_version": "v2",
        "ledger_semantics_version": "ledger-v0",
        "execution_semantics_version": "linear-execution-friction-v0",
        "execution_cost_model": "linear_execution_friction",
        "verified_financial_semantics": False,
        "verified_surface_eligibility": "rebuild_required",
    }
    assert body["rebuild"] == {
        "available": True,
        "source": "saved_accepted_spec",
    }
    assert "analysis" not in body and "binding" not in body


def test_frozen_v2_release_remains_presentable_after_runtime_upgrade(
    client: TestClient, var_env: Path, monkeypatch,
):
    """A future worker may present, but can never resume, the frozen v2 release."""
    run_id = _published_run(client, profile="battery-v2")
    run_dir = var_env / "artifacts" / run_id
    expected_run = db.get_run_internal(run_id)
    assert expected_run is not None

    release_image = _registered_v2_release_image()
    sealed_manifest = json.loads((run_dir / "manifest.json").read_bytes())
    assert sealed_manifest["image_digest"] == release_image
    before_files = _directory_state(run_dir)
    before_row = copy.deepcopy(expected_run)

    future_image = "local-runtime-sha256:" + "a" * 64
    assert future_image != release_image
    monkeypatch.setattr(artifacts_module, "image_digest", lambda: future_image)

    manifest, ledger, payloads, contract = load_presentation_artifacts(
        run_dir, expected_run=expected_run,
    )
    assert manifest["image_digest"] == release_image
    assert ledger["result_hash"] == manifest["result_hash"]
    assert payloads["validation_plan"]["profile_id"] == "battery-v2"
    assert contract.contract_id == "legacy-battery-v2-ledger-v0"

    with pytest.raises(ArtifactIntegrityError, match="image_digest is not current"):
        load_sealed_artifacts(run_dir, expected_run=expected_run)

    assert _directory_state(run_dir) == before_files
    assert db.get_run_internal(run_id) == before_row
