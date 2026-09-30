"""Golden freeze for the legacy ledger-v0 byte and read-only presentation contract.

Battery v1 and v2 intentionally share the same canonical ledger envelope even though
their artifact sets and producers differ.  These tests make that historical boundary
explicit: changing the note, field set, entry order, canonical JSON bytes, or result
identity requires a deliberate compatibility decision.  Merely presenting a registered
checkpoint must never rewrite the durable ledger.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from conftest import validated_run_payload
from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec
from quantlens_worker.artifacts import load_presentation_artifacts
from quantlens_worker.evidence_contract_registry import (
    LEDGER_V0_ENTRY_KEYS,
    LEDGER_V0_INDEX_KEYS,
    LEDGER_V0_NOTE,
)
from quantlens_worker.runner import process_next


@pytest.fixture()
def client(var_env):
    with TestClient(app) as test_client:
        yield test_client


EXPECTED = {
    "battery-v1": {
        "contract_id": "legacy-battery-v1-ledger-v0",
        "producer": "quantlens-engine/0.1.0+battery-v1",
        "kinds": (
            "cost_stress",
            "data_gaps",
            "evidence_status",
            "falsification",
            "is_result",
            "oos_execution_audit",
            "oos_result",
            "segments",
            "sensitivity",
            "snapshot_ref",
            "spec",
        ),
        "ledger_sha256": (
            "sha256:82dba7e370c1e73f37c9a797ce800900"
            "3b27191a69e20fa3982ed545114b4d2a"
        ),
        "result_hash": (
            "sha256:c970c7768b067337c07248f1bd063ca2"
            "7b9b14e3324e7ee09322cfccf258e2c1"
        ),
    },
    "battery-v2": {
        "contract_id": "legacy-battery-v2-ledger-v0",
        "producer": "quantlens-engine/0.1.0+battery-v2",
        "kinds": (
            "cost_stress",
            "data_gaps",
            "development_result",
            "evidence_status",
            "falsification",
            "final_holdout_execution_audit",
            "final_holdout_result",
            "partitions",
            "regime_analysis",
            "sensitivity",
            "snapshot_ref",
            "spec",
            "temporal_integrity",
            "validation_plan",
            "walk_forward",
        ),
        "ledger_sha256": (
            "sha256:41fe0b99b32d4d92c541f7e20b8fb115"
            "d2d7812b8486fd88e92b2a112648e7a3"
        ),
        "result_hash": (
            "sha256:d5bbd47d710e268388b70f8d87b5bd51"
            "a34b067d63a37a6cf2154af41f7aa4fa"
        ),
    },
}


def _publish(client: TestClient, profile: str) -> str:
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


@pytest.mark.parametrize("profile", ["battery-v1", "battery-v2"])
def test_legacy_ledger_v0_bytes_and_presentation_are_frozen(
    client: TestClient, var_env, profile: str,
):
    run_id = _publish(client, profile)
    run_dir = var_env / "artifacts" / run_id
    ledger_path = run_dir / "ledger_index.json"
    expected = EXPECTED[profile]

    before_bytes = ledger_path.read_bytes()
    before_mtime_ns = ledger_path.stat().st_mtime_ns
    ledger = json.loads(before_bytes)

    # ledger-v0 is canonical JSON with an exact index and entry schema.
    assert before_bytes == json.dumps(
        ledger,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    assert set(ledger) == set(LEDGER_V0_INDEX_KEYS)
    assert ledger["note"] == LEDGER_V0_NOTE == (
        "Gate 2 ledger v0: write-once content-hashed artifacts; report rendering "
        "replays and verifies this sealed index."
    )
    assert tuple(entry["kind"] for entry in ledger["entries"]) == expected["kinds"]
    for entry in ledger["entries"]:
        assert set(entry) == set(LEDGER_V0_ENTRY_KEYS)
        assert entry["producer"] == expected["producer"]
        assert entry["path"] == f"artifact_{entry['kind']}.json"
        assert entry["artifact_id"] == f"{entry['kind']}-{entry['sha256'][:12]}"
        assert len(entry["sha256"]) == 64
        assert set(entry["sha256"]) <= set("0123456789abcdef")

    assert "sha256:" + hashlib.sha256(before_bytes).hexdigest() == \
        expected["ledger_sha256"]
    assert ledger["result_hash"] == expected["result_hash"]

    expected_run = db.get_run_internal(run_id)
    assert expected_run is not None
    manifest, loaded_ledger, _payloads, contract = load_presentation_artifacts(
        run_dir,
        expected_run=expected_run,
    )
    assert loaded_ledger == ledger
    assert manifest["result_hash"] == ledger["result_hash"]
    assert contract.contract_id == expected["contract_id"]

    # Historical presentation is a read, not an implicit migration or reseal.
    assert ledger_path.read_bytes() == before_bytes
    assert ledger_path.stat().st_mtime_ns == before_mtime_ns
