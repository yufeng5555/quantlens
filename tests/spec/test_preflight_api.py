"""API admission contract for the server-authoritative Research Preflight."""

from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

from quantlens_api import db
from quantlens_api.app import app
from quantlens_schema import default_spec, spec_hash

from conftest import bday_frame, make_snapshot_dir, validated_run_payload


@pytest.fixture()
def client(var_env):
    with TestClient(app) as value:
        yield value


def _validate(client: TestClient, spec: dict, profile: str = "battery-v1") -> dict:
    response = client.post(
        "/specs/validate",
        json={"spec": spec, "battery_profile": profile},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is True, body
    return body


def _preflight_payload(
    validation: dict,
    spec: dict,
    *,
    profile: str = "battery-v1",
) -> dict:
    preflight = validation["preflight"]
    return {
        "spec": spec,
        "battery_profile": profile,
        "confirmed": True,
        "restatement_seen": True,
        "confirmed_spec_hash": validation["spec_hash"],
        "confirmed_battery_profile_hash": validation["battery_profile"]["profile_hash"],
        "confirmed_preflight_hash": preflight["preflight_hash"],
        "acknowledged_preflight_warning_ids": preflight[
            "required_acknowledgement_ids"
        ],
    }


def _control_plane_counts() -> dict[str, int]:
    with db.connect() as conn:
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "runs",
                "entitlement_reservations",
                "final_holdout_claims",
                "final_holdout_reveals",
            )
        }


def test_validate_returns_preflight_without_performance_or_state_change(client):
    before = _control_plane_counts()
    body = _validate(client, default_spec(), "battery-v2")

    preflight = body["preflight"]
    assert preflight["version"] == "research-preflight-v1"
    assert preflight["status"] in {"ready", "ready_with_warnings"}
    assert preflight["can_run"] is True
    assert preflight["preflight_hash"].startswith("sha256:")
    assert body["performance"] is None
    serialized = str(preflight).lower()
    assert "sharpe" not in serialized
    assert "final_holdout_result" not in serialized
    assert "capability" not in serialized
    assert _control_plane_counts() == before


def test_preflight_blocker_creates_no_run_or_reservation(
    client, tmp_path, monkeypatch,
):
    # Keep the calendar window wide enough for static lint, but remove alternating
    # sessions.  Every gap remains within policy while the actual executable IS segment
    # has no post-warmup observation.  Only data-backed preflight can detect this.
    full = bday_frame(
        "2020-01-02", [100.0 + index * 0.01 for index in range(520)]
    )
    sparse = full.iloc[
        sorted(set([0, len(full) - 1, *range(0, len(full), 2)]))
    ].reset_index(drop=True)
    source = make_snapshot_dir(tmp_path / "sparse", {"SPY": sparse})
    monkeypatch.setenv("QL_SNAPSHOT_DIR", str(source))
    spec = default_spec("SPY")
    spec["data"]["range"] = {
        "start": sparse["date"].iloc[0],
        "end": sparse["date"].iloc[-1],
    }

    validation = _validate(client, spec)
    preflight = validation["preflight"]
    assert preflight["can_run"] is False
    assert preflight["status"] == "blocked"
    assert "PREFLIGHT_STANDARD_NO_IS_EVALUATION" in {
        issue["id"] for issue in preflight["blockers"]
    }
    before = _control_plane_counts()

    response = client.post(
        "/runs", json=_preflight_payload(validation, spec)
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "PREFLIGHT_BLOCKED"
    assert _control_plane_counts() == before


@pytest.mark.parametrize("value", [None, "sha256:" + "0" * 64])
def test_missing_or_stale_preflight_hash_is_rejected(client, value):
    payload = validated_run_payload(client, default_spec())
    payload["confirmed_preflight_hash"] = value

    response = client.post("/runs", json=payload)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "PREFLIGHT_STALE"
    assert _control_plane_counts()["runs"] == 0
    assert _control_plane_counts()["entitlement_reservations"] == 0


def test_warning_acknowledgements_require_the_exact_current_set(client):
    payload = validated_run_payload(client, default_spec())
    required = payload["acknowledged_preflight_warning_ids"]
    assert required  # bundled sample data always requires an explicit warning receipt

    variants = [
        [],
        required[:-1],
        [*required, "PREFLIGHT_NOT_A_REAL_WARNING"],
        [*required, required[0]],
    ]
    for acknowledged in variants:
        response = client.post(
            "/runs",
            json={
                **payload,
                "acknowledged_preflight_warning_ids": acknowledged,
            },
        )
        assert response.status_code == 409, response.text
        detail = response.json()["detail"]
        assert detail["code"] == "PREFLIGHT_WARNINGS_UNACKNOWLEDGED"
        assert detail["required_acknowledgement_ids"] == required

    assert _control_plane_counts()["runs"] == 0
    assert _control_plane_counts()["entitlement_reservations"] == 0


def test_snapshot_change_invalidates_preflight_receipt(
    client, tmp_path, monkeypatch,
):
    closes_a = [100.0 + index * 0.01 for index in range(900)]
    closes_b = [100.0 + index * 0.02 for index in range(900)]
    frame_a = bday_frame("2018-01-02", closes_a)
    frame_b = bday_frame("2018-01-02", closes_b)
    source_a = make_snapshot_dir(tmp_path / "source-a", {"SPY": frame_a})
    source_b = make_snapshot_dir(tmp_path / "source-b", {"SPY": frame_b})
    spec = default_spec("SPY")
    spec["data"]["range"] = {
        "start": frame_a["date"].iloc[0],
        "end": frame_a["date"].iloc[-1],
    }

    monkeypatch.setenv("QL_SNAPSHOT_DIR", str(source_a))
    validation = _validate(client, spec)
    payload = _preflight_payload(validation, spec)
    monkeypatch.setenv("QL_SNAPSHOT_DIR", str(source_b))

    response = client.post("/runs", json=payload)
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "PREFLIGHT_STALE"
    assert detail["expected_preflight_hash"] != payload["confirmed_preflight_hash"]
    assert _control_plane_counts()["runs"] == 0


def test_spec_edit_invalidates_preflight_even_with_fresh_spec_confirmation(client):
    spec = default_spec()
    validation = _validate(client, spec)
    payload = _preflight_payload(validation, spec)
    edited = copy.deepcopy(spec)
    edited["costs"] = {"commission_bps": 0, "slippage_bps": 0}
    payload["spec"] = edited
    # Simulate a freshly restated spec while deliberately retaining the old preflight.
    payload["confirmed_spec_hash"] = spec_hash(edited)

    response = client.post("/runs", json=payload)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "PREFLIGHT_STALE"
    assert _control_plane_counts()["runs"] == 0


def test_profile_edit_invalidates_preflight_even_with_fresh_profile_confirmation(client):
    spec = default_spec()
    standard = _validate(client, spec, "battery-v1")
    strict = _validate(client, spec, "battery-v2")
    payload = _preflight_payload(standard, spec)
    payload["battery_profile"] = "battery-v2"
    payload["confirmed_battery_profile_hash"] = strict["battery_profile"][
        "profile_hash"
    ]

    response = client.post("/runs", json=payload)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "PREFLIGHT_STALE"
    assert _control_plane_counts()["runs"] == 0

