"""Shared helpers: build tiny content-addressed synthetic snapshot directories for
golden tests (split/gap/pipeline fixtures) without hand-maintaining checksums."""

import hashlib
import json
import os
from pathlib import Path

# The sealed-build presentation registry is a separately pinned release asset. Tests use
# the reviewed Gate 7A.2 pin; production injects the same value through deployment config.
os.environ.setdefault(
    "QL_SEALED_BUILD_REGISTRY_SHA256",
    "sha256:6350a4bf95626794c1ea9afbe6fac0bf8b6305279831fb30979db9d82f690f82",
)
# The sealed corrected read-time expectations (Stop F2a; runtime digest
# sealed at the Stop F2b re-seal, re-sealed at the doc 50 §3.2 repair, and again
# at the return-basis template re-seal) carry their own independent byte pin.
os.environ.setdefault(
    "QL_CORRECTED_READ_EXPECTATIONS_SHA256",
    "sha256:9eb50321cc31f4132c16ea37e7fd395cb0fd0b6fa3859bc4ac4b3d20fb031b6f",
)

import pandas as pd
import pytest

from quantlens_api.app import app as api_app
from quantlens_api.auth import Principal, require_principal
from quantlens_worker.snapshot import (
    EXPECTED_EXECUTION,
    SNAPSHOT_IDENTITY_VERSION,
    canonical_snapshot_identity,
)


TEST_PRINCIPAL = Principal(
    tenant_id="local-anonymous",
    user_id="local-anonymous",
    roles=frozenset({"owner"}),
    auth_mode="test-provider",
    display_label="Test local workspace",
    authenticated=True,
    security_boundary=True,
)


@pytest.fixture(autouse=True)
def _api_test_principal(monkeypatch):
    """Use an explicit server-side identity in API tests.

    Starlette's TestClient is intentionally not treated as loopback by the production
    local-preview provider.  Tests therefore exercise FastAPI's supported dependency
    override instead of weakening the runtime loopback check or accepting identity
    headers.  Individual isolation tests may replace this override temporarily.
    """
    # Unit/integration tests often drive ``runner.process_next`` in-process rather than
    # starting the long-lived worker heartbeat thread. Disable production admission by
    # default; focused liveness tests explicitly turn it back on.
    monkeypatch.setenv("QL_REQUIRE_WORKER_HEARTBEAT", "0")
    previous = api_app.dependency_overrides.get(require_principal)
    api_app.dependency_overrides[require_principal] = lambda: TEST_PRINCIPAL
    try:
        yield
    finally:
        if previous is None:
            api_app.dependency_overrides.pop(require_principal, None)
        else:
            api_app.dependency_overrides[require_principal] = previous


def make_snapshot_dir(root: Path, frames: dict[str, pd.DataFrame],
                      splits: dict[str, list[dict]] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    files = {}
    coverage = {}
    for sym, df in frames.items():
        path = root / f"{sym}.csv"
        df.to_csv(path, index=False, lineterminator="\n")
        files[f"{sym}.csv"] = hashlib.sha256(path.read_bytes()).hexdigest()
        coverage[sym] = {"start": df["date"].iloc[0], "end": df["date"].iloc[-1]}
    meta = {
        "identity_version": SNAPSHOT_IDENTITY_VERSION,
        "label": "SYNTHETIC",
        "description": "Test fixture snapshot (synthetic, generated in-test).",
        "generator": {"version": "test", "base_seed": 0},
        "calendar": "Business days Mon-Fri, no holiday calendar (synthetic convention).",
        "coverage": coverage,
        "files": files,
        "splits": splits or {},
        "adjustment_convention": "back-adjust: pre-split prices divided by ratio",
        "execution": dict(EXPECTED_EXECUTION),
    }
    digest, snapshot_id = canonical_snapshot_identity(meta)
    meta["sha256"] = digest
    meta["snapshot_id"] = snapshot_id
    (root / "snapshot.json").write_text(json.dumps(meta, indent=2, sort_keys=True))
    return root


def bday_frame(start: str, closes: list[float], opens: list[float] | None = None) -> pd.DataFrame:
    dates = pd.bdate_range(start, periods=len(closes)).strftime("%Y-%m-%d")
    opens = opens or ([closes[0]] + closes[:-1])
    return pd.DataFrame({
        "date": dates,
        "open": opens,
        "high": [max(o, c) * 1.001 for o, c in zip(opens, closes)],
        "low": [min(o, c) * 0.999 for o, c in zip(opens, closes)],
        "close": closes,
        "volume": [1_000_000] * len(closes),
    })


def validated_run_payload(
    client,
    spec: dict,
    *,
    battery_profile: str = "battery-v1",
    research_mode: str = "formal",
    acknowledged_warning_ids: list[str] | None = None,
) -> dict:
    """Build the exact admission receipt returned by ``/specs/validate``.

    Successful run submissions must bind both the static confirmation and the current
    server-authoritative Research Preflight.  Keeping that handshake in one test helper
    prevents unrelated integration tests from copying stale warning IDs or inventing a
    preflight hash.  Tests that exercise an earlier gate intentionally build their own
    incomplete payload instead.
    """
    response = client.post(
        "/specs/validate",
        json={"spec": spec, "battery_profile": battery_profile},
    )
    assert response.status_code == 200, response.text
    validated = response.json()
    assert validated["valid"] is True, validated
    preflight = validated["preflight"]
    assert preflight["can_run"] is True, preflight
    required = preflight["required_acknowledgement_ids"]
    return {
        "spec": spec,
        "research_mode": research_mode,
        "battery_profile": battery_profile,
        "confirmed": True,
        "restatement_seen": True,
        "confirmed_spec_hash": validated["spec_hash"],
        "confirmed_battery_profile_hash": validated["battery_profile"]["profile_hash"],
        "confirmed_preflight_hash": preflight["preflight_hash"],
        "acknowledged_preflight_warning_ids": (
            list(required)
            if acknowledged_warning_ids is None
            else list(acknowledged_warning_ids)
        ),
    }


@pytest.fixture()
def var_env(tmp_path, monkeypatch):
    """Isolated var/ (queue, artifacts, entitlement) per test."""
    monkeypatch.setenv("QL_VAR_DIR", str(tmp_path / "var"))
    return tmp_path / "var"
