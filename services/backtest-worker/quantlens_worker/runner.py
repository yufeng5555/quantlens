"""Durable local worker for the Gate 2 run lifecycle.

The ledger/manifest pair is the compute checkpoint.  Before that checkpoint a retry may
re-run deterministic compute while retaining the quota reservation.  After it, retries
verify and replay sealed artifacts into the report; they never re-run the engine, battery,
or quota charge.  Stale active rows are eventually requeued so a process crash cannot
strand a reservation forever.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quantlens_api import db
from quantlens_api.market_data.base import MarketDataError
from quantlens_api.market_data.config import activated_rights_policy_from_env
from quantlens_api.market_data.dataset_manifest import (
    DatasetRightsOperation,
    assert_dataset_directory_rights,
)
from quantlens_api.runtime_contract import (
    ISOLATED_WORKER_CONTRACTS,
    assert_expected_runtime,
    assert_run_compatible,
    public_runtime_view,
    serving_worker_contract,
)

from .artifacts import (
    ArtifactIntegrityError,
    build_manifest,
    data_provenance_for_snapshot,
    load_sealed_artifacts,
    write_artifacts,
)
from .battery import run_battery
from .battery_v2 import run_development_battery_v2
from .corrected_execution_v3 import (
    corrected_execution_ready,
    corrected_execution_refusal,
    execute_corrected_run,
    execution_readiness_observation,
)
from .final_holdout import evaluate_final_holdout, make_capsule
from .report import render_report
from .snapshot import DataQualityError, load_frame, snapshot_dir, verify_snapshot_integrity
from .temporal_integrity import build_temporal_integrity_receipt
from .validation_partition import build_partitions
from .validation_plan import BATTERY_V1, BATTERY_V2, build_validation_plan

MAX_RETRIES = 2
DEFAULT_STALE_SECONDS = 60
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 2.0
DEFAULT_CONTROL_RECOVERY_BASE_SECONDS = 0.5
MAX_CONTROL_RECOVERY_SECONDS = 5.0
ACTIVE_STATUSES = frozenset({
    "snapshot_pinned", "running_engine", "running_battery", "ledger_sealed",
    "report_rendered",
})
TERMINAL_STATUSES = frozenset({
    "published", "validation_failed", "data_quality_failed", "system_failed",
})

logger = logging.getLogger("quantlens.worker")


class FinalHoldoutConsumedError(RuntimeError):
    """The one-time final capsule cannot legally be read again."""


def _bounded_float_env(name: str, default: float, *, minimum: float,
                       maximum: float) -> float:
    try:
        return max(minimum, min(maximum, float(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def _control_recovery_delay(failure_count: int) -> float:
    base = _bounded_float_env(
        "QL_WORKER_RECOVERY_BASE_SECONDS",
        DEFAULT_CONTROL_RECOVERY_BASE_SECONDS,
        minimum=0.0,
        maximum=2.0,
    )
    return min(MAX_CONTROL_RECOVERY_SECONDS, base * (2 ** max(0, failure_count - 1)))


class WorkerHeartbeat:
    """Keep an API-visible liveness lease fresh while long backtests are running."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._state_lock = threading.Lock()
        self._state = "starting"
        self._thread = threading.Thread(
            target=self._run,
            name="quantlens-worker-heartbeat",
            daemon=True,
        )
        self._interval = _bounded_float_env(
            "QL_WORKER_HEARTBEAT_INTERVAL_SECONDS",
            DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            minimum=0.25,
            maximum=30.0,
        )

    def _current_state(self) -> str:
        with self._state_lock:
            return self._state

    def set_state(self, state: str) -> None:
        with self._state_lock:
            self._state = state

    def _beat(self) -> None:
        # Doc 50 §3.2: a worker serving an isolated corrected contract must
        # carry its structural executable-readiness observation with every
        # liveness beat — admission and activation refuse when the recorded
        # facts say this process could not execute a new corrected run. The
        # baseline contract records liveness exactly as before.
        readiness = None
        if serving_worker_contract() in ISOLATED_WORKER_CONTRACTS:
            readiness = execution_readiness_observation()
        db.record_worker_heartbeat(
            state=self._current_state(), execution_readiness=readiness)

    def start(self) -> None:
        self._beat()
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._beat()
            except sqlite3.OperationalError as exc:
                if not db.is_transient_database_error(exc):
                    logger.exception("worker heartbeat failed permanently")
                    return
                logger.warning("worker heartbeat delayed: database unavailable")
            except Exception:  # noqa: BLE001 — liveness helper cannot kill compute
                logger.exception("worker heartbeat failed unexpectedly")

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=max(1.0, self._interval * 2))
        try:
            db.record_worker_heartbeat(state="stopped")
        except Exception:  # noqa: BLE001 — shutdown is best-effort
            logger.warning("could not persist stopped worker heartbeat", exc_info=True)


def _run_dir(run_id: str) -> Path:
    d = db.var_dir() / "artifacts" / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _set_ledger_status_if_needed(run_id: str) -> None:
    current = db.get_run_internal(run_id)
    if current and current["status"] not in {"ledger_sealed", "report_rendered", "published"}:
        if any(status == "ledger_sealed" for status, _ in current["history"]):
            # Resume changes the control-plane cursor, not the immutable lifecycle fact.
            # Do not append a second "sealed" event that could be mistaken for resealing.
            with db.connect() as conn:
                conn.execute(
                    "UPDATE runs SET status = 'ledger_sealed', error_json = NULL, "
                    "updated_at = ? WHERE run_id = ?",
                    (datetime.now(timezone.utc).isoformat(), run_id),
                )
        else:
            db.set_status(run_id, "ledger_sealed")


def _load_or_promote_checkpoint(run: dict, run_dir: Path):
    """Return a strict current checkpoint; never relabel an orphan ledger as current."""
    ledger_path = run_dir / "ledger_index.json"
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists() and not ledger_path.exists():
        raise ArtifactIntegrityError("manifest exists without its ledger index")
    if manifest_path.exists():
        return load_sealed_artifacts(run_dir, expected_run=run)
    if ledger_path.exists():
        # ledger-v0 does not seal the runtime/image identity that produced it.  Building a
        # new manifest here would stamp old computation with the *current* image digest.
        # Preserve every byte and fail closed; a future ledger version may add a write-once
        # pre-manifest execution binding that makes promotion provable.
        raise ArtifactIntegrityError(
            "orphan ledger has no sealed runtime binding and cannot be promoted")

    reservation = db.get_reservation(run["run_id"])
    sealed_in_history = any(status == "ledger_sealed" for status, _ in run["history"])
    if sealed_in_history or (reservation and reservation["status"] == "settled"):
        raise ArtifactIntegrityError("run is marked sealed but its checkpoint is missing")
    return None


def _resolve_snapshot(run: dict) -> tuple[Path, dict, dict | None]:
    """Resolve the confirmed source to one actor-owned, integrity-checked snapshot.

    Gate 4 deliberately resolves the dataset again in the worker rather than trusting
    the earlier API validation.  Dataset withdrawal, DB tampering, file tampering or a
    stale source hash therefore fails closed before compute and before quota settlement.
    """
    spec = run["spec"]
    version = spec.get("dsl_version")
    if version == "1.0":
        directory = snapshot_dir()
        snapshot_meta = verify_snapshot_integrity(directory)
        if snapshot_meta.get("label") != "SYNTHETIC":
            raise DataQualityError(
                "SNAPSHOT_LABEL",
                "DSL 1.0 runs may only use the bundled SYNTHETIC snapshot.",
            )
        return directory, snapshot_meta, None
    if version not in {"1.1", "1.2"}:
        raise DataQualityError(
            "DSL_VERSION_UNSUPPORTED", f"Worker cannot execute DSL version {version!r}.")

    source = (spec.get("data") or {}).get("source")
    expected_kind = "user_provided" if version == "1.1" else "licensed_provider"
    if not isinstance(source, dict) or source.get("kind") != expected_kind:
        raise DataQualityError(
            "DATASET_SOURCE_INVALID",
            f"DSL {version} has no sealed {expected_kind} dataset source.",
        )
    dataset_id = source.get("dataset_id")
    dataset = db.get_dataset_internal(
        dataset_id, run["actor_id"], run.get("user_id", run["actor_id"]))
    if dataset is None:
        raise DataQualityError(
            "DATASET_NOT_AVAILABLE",
            "The confirmed dataset is missing, withdrawn, not sealed, or owned by another actor.",
        )
    if source.get("dataset_manifest_sha256") != dataset.get("dataset_manifest_sha256"):
        raise DataQualityError(
            "DATASET_BINDING_STALE",
            "The confirmed dataset-manifest hash no longer matches the sealed dataset record.",
        )
    try:
        directory = db.dataset_directory(dataset)
    except (KeyError, TypeError, ValueError) as exc:
        raise DataQualityError(
            "DATASET_STORAGE_INVALID", "The sealed dataset storage binding is unsafe.") from exc
    if version == "1.2":
        try:
            assert_dataset_directory_rights(
                directory,
                operation=DatasetRightsOperation.RUN,
                policy=activated_rights_policy_from_env(),
                as_of=datetime.now(timezone.utc).date(),
            )
        except MarketDataError as exc:
            raise DataQualityError(exc.code, str(exc)) from exc
    snapshot_meta = verify_snapshot_integrity(directory)
    if (snapshot_meta.get("snapshot_id") != dataset.get("snapshot_id") or
            snapshot_meta.get("sha256") != dataset.get("snapshot_sha256")):
        raise DataQualityError(
            "DATASET_SNAPSHOT_STALE",
            "The dataset snapshot identity no longer matches its sealed registry record.",
        )
    try:
        provenance = data_provenance_for_snapshot(
            spec, snapshot_meta, actor_id=run["actor_id"])
    except ArtifactIntegrityError as exc:
        logger.warning(
            "dataset provenance binding failed run_id=%s dataset_id=%s",
            run["run_id"], dataset_id, exc_info=True,
        )
        raise DataQualityError(
            "DATASET_BINDING_INVALID",
            "The sealed dataset could not be bound to this confirmed run.",
        ) from exc
    registry_bindings = {
        "dataset_id": dataset.get("dataset_id"),
        "dataset_manifest_sha256": str(
            dataset.get("dataset_manifest_sha256", "")).removeprefix("sha256:"),
        "symbol": dataset.get("symbol"),
        "coverage": dataset.get("coverage"),
        "row_count": dataset.get("row_count"),
    }
    if version == "1.1":
        registry_bindings["source_sha256"] = dataset.get("source_sha256")
    else:
        registry_bindings["provider_payload_sha256"] = (
            "sha256:" + str(dataset.get("source_sha256", "")).removeprefix("sha256:")
        )
    if any(provenance.get(field) != expected
           for field, expected in registry_bindings.items()):
        raise DataQualityError(
            "DATASET_REGISTRY_MISMATCH",
            "Dataset manifest provenance contradicts the sealed registry record.",
        )
    return directory, snapshot_meta, provenance


def _run_battery_v2_payloads(
    run: dict,
    frame,
    *,
    benchmark_frame,
    benchmark_symbol: str,
    snapshot_meta: dict,
    data_gaps: dict,
) -> dict[str, dict]:
    spec = run["spec"]
    plan = build_validation_plan(spec, len(frame))
    partitions = build_partitions(frame, plan, benchmark_frame)
    development = run_development_battery_v2(
        partitions.development,
        spec,
        plan,
        partitions.artifact,
        benchmark_frame=partitions.development_benchmark,
    )

    if not partitions.artifact["folds"]:
        final_result = {
            "status": "INCONCLUSIVE",
            "reason": "The fixed development plan has no valid fold; the final holdout "
                      "was not consumed.",
            "strategy_metrics": {"n_bars": 0},
            "comparison_strategy_metrics": {"n_bars": 0},
            "benchmark_metrics": {"n_bars": 0},
            "benchmark_symbol": benchmark_symbol,
            "equity_series": {"date": [], "equity": [], "position": []},
            "benchmark_series": {"date": [], "equity": []},
            "trades": [],
            "benchmark_entry": None,
        }
        final_audit = {
            "audit_version": "final-holdout-audit-v1",
            "state": "not_claimed_insufficient_development_data",
            "primary_evaluation_count": 0,
            "counterfactual_evaluation_count": 0,
            "recovered_result": False,
            "reused_across_run": False,
            "run_primary_evaluation_count": 0,
            "execution_binding": None,
        }
    else:
        final_boundary = {
            key: partitions.artifact["final_holdout"][key]
            for key in (
                "start_index", "end_index", "warmup_start_index", "warmup_bars",
                "evaluation_input_sha256",
            )
        }
        try:
            db.ensure_final_holdout_ready(
                run["run_id"], spec_hash=run["spec_hash"],
                validation_plan_hash=plan["validation_plan_hash"],
                actor_id=run["actor_id"], snapshot_sha256=snapshot_meta["sha256"],
                final_boundary=final_boundary,
            )
        except ValueError as exc:
            raise FinalHoldoutConsumedError(str(exc)) from exc
        claim = db.claim_final_holdout(
            run["run_id"], spec_hash=run["spec_hash"],
            validation_plan_hash=plan["validation_plan_hash"],
        )
        if claim["claimed"]:
            capsule = make_capsule(
                partitions.final_capsule_frame,
                partitions.final_local_start,
                capsule_sha256=partitions.artifact["final_holdout"]["capsule_sha256"],
                benchmark_frame=partitions.final_capsule_benchmark,
            )
            try:
                final_result = evaluate_final_holdout(
                    capsule,
                    confirmed_spec_hash=run["spec_hash"],
                    validation_plan_hash=plan["validation_plan_hash"],
                    locked_rule=spec["rule"],
                    base_costs=spec["costs"],
                    benchmark_symbol=benchmark_symbol,
                )
                db.complete_final_holdout(run["run_id"], final_result)
            except Exception:
                db.fail_inflight_final_holdout(run["run_id"])
                raise
            recovered = False
        elif claim["state"] == "final.result" and isinstance(claim["result"], dict):
            # Crash recovery after the result was durably stored but before ledger seal.
            final_result = claim["result"]
            recovered = not bool(claim.get("reused_across_run"))
        else:
            db.fail_inflight_final_holdout(run["run_id"])
            raise FinalHoldoutConsumedError(
                "The one-time final holdout was already claimed without a recoverable result.")
        final_audit = {
            "audit_version": "final-holdout-audit-v1",
            "state": "final.result",
            "primary_evaluation_count": 1,
            "counterfactual_evaluation_count": 0,
            "recovered_result": recovered,
            "reused_across_run": bool(claim.get("reused_across_run")),
            "run_primary_evaluation_count": 1 if claim["claimed"] else 0,
            "capsule_id": final_result["execution_binding"]["capsule_id"],
            "validation_plan_hash": plan["validation_plan_hash"],
            "confirmed_spec_hash": run["spec_hash"],
            "execution_binding": dict(final_result["execution_binding"]),
        }

    evidence_status = dict(development["evidence_status"])
    evidence_status["final_holdout_status"] = final_result["status"]
    if final_result["status"] != "COMPLETE":
        evidence_status["evidence_complete"] = False
        evidence_status["battery_status"] = "INCONCLUSIVE"
    temporal = build_temporal_integrity_receipt(
        validation_plan=plan,
        partitions=partitions.artifact,
        spec_hash=run["spec_hash"],
        snapshot_sha256=snapshot_meta["sha256"],
        final_audit=final_audit,
    )
    return {
        "spec": {"spec": spec, "spec_hash": run["spec_hash"]},
        "validation_plan": plan,
        "partitions": partitions.artifact,
        "development_result": development["development_result"],
        "walk_forward": development["walk_forward"],
        "regime_analysis": development["regime_analysis"],
        "final_holdout_result": final_result,
        "final_holdout_execution_audit": final_audit,
        "temporal_integrity": temporal,
        "sensitivity": development["sensitivity"],
        "cost_stress": development["cost_stress"],
        "falsification": development["falsification"],
        "evidence_status": evidence_status,
        "data_gaps": data_gaps,
        "snapshot_ref": snapshot_meta,
    }


def _compute_and_seal(run: dict, run_dir: Path):
    run_id = run["run_id"]
    spec = run["spec"]
    source_dir, snapshot_meta, data_provenance = _resolve_snapshot(run)

    if run.get("battery_profile", BATTERY_V1) == BATTERY_V2:
        prior_claim = db.get_final_holdout_claim(run_id)
        if prior_claim and prior_claim["state"] in {"final.inflight", "system_failed"}:
            db.fail_inflight_final_holdout(run_id)
            raise FinalHoldoutConsumedError(
                "An interrupted final-holdout claim is terminal and cannot read the "
                "capsule a second time.")

    db.set_status(run_id, "running_engine")
    start = spec["data"]["range"]["start"]
    end = spec["data"]["range"]["end"]
    symbol = spec["universe"]["symbol"]
    frame, gap_report = load_frame(symbol, start, end, source_dir)

    benchmark_value = spec["benchmark"]["symbol"]
    benchmark_symbol = symbol if benchmark_value == "same_as_universe" else benchmark_value
    benchmark_frame = None
    benchmark_gap_report = None
    if benchmark_symbol != symbol:
        if spec.get("dsl_version") in {"1.1", "1.2"}:
            raise DataQualityError(
                "DATASET_BENCHMARK_UNSUPPORTED",
                "A sealed single-symbol dataset must use same_as_universe benchmark.",
            )
        benchmark_frame, benchmark_gap_report = load_frame(
            benchmark_symbol, start, end, source_dir,
        )

    db.set_status(run_id, "running_battery")
    profile = run.get("battery_profile", BATTERY_V1)
    battery = None
    audit = None
    if profile == BATTERY_V1:
        battery = run_battery(frame, spec, benchmark_df=benchmark_frame)
        audit = battery.get("oos_execution_audit")
        if not isinstance(audit, dict) or audit.get("primary_evaluation_count") != 1:
            raise RuntimeError("battery did not seal a valid one-primary-run OOS audit")
        if "evidence_complete" not in battery or "battery_status" not in battery:
            raise RuntimeError("battery did not declare evidence completeness")
    elif profile != BATTERY_V2:
        raise RuntimeError(f"unsupported validation profile: {profile!r}")

    data_gaps = dict(gap_report)
    data_gaps["universe_symbol"] = symbol
    data_gaps["benchmark_symbol"] = benchmark_symbol
    if benchmark_gap_report is not None:
        data_gaps["benchmark"] = benchmark_gap_report

    if profile == BATTERY_V2:
        # Keep the legacy literal payload declaration below auditable for the
        # producer-boundary contract while routing the separately versioned V2
        # artifact set through its deterministic builder.
        payloads: dict[str, dict] = _run_battery_v2_payloads(
            run,
            frame,
            benchmark_frame=benchmark_frame,
            benchmark_symbol=benchmark_symbol,
            snapshot_meta=snapshot_meta,
            data_gaps=data_gaps,
        )
    else:
        payloads = {
            "spec": {"spec": spec, "spec_hash": run["spec_hash"]},
            "segments": battery["segments"],
            "is_result": battery["is_result"],
            "oos_result": battery["oos_result"],
            "oos_execution_audit": audit,
            "sensitivity": battery["sensitivity"],
            "cost_stress": battery["cost_stress"],
            "falsification": battery["falsification"],
            "evidence_status": {
                "evidence_complete": battery["evidence_complete"],
                "battery_status": battery["battery_status"],
            },
            "data_gaps": data_gaps,
            # Seal the full metadata identity, not only a display label and two top hashes.
            "snapshot_ref": snapshot_meta,
        }
    if profile == BATTERY_V2:
        run["validation_anchor"] = db.seal_validation_anchor(
            run_id,
            temporal_integrity=payloads["temporal_integrity"],
            partitions=payloads["partitions"],
            validation_plan=payloads["validation_plan"],
            final_execution_binding=payloads["final_holdout_result"].get(
                "execution_binding"),
        )
    if data_provenance is not None:
        payloads["data_provenance"] = data_provenance
    ledger_index = write_artifacts(run_dir, payloads)
    build_manifest(run_dir, run, spec, snapshot_meta, ledger_index["result_hash"])
    checkpoint = load_sealed_artifacts(run_dir, expected_run=run)
    _set_ledger_status_if_needed(run_id)
    db.settle_reservation(run_id)  # run-scoped and idempotent; exactly one charge
    return checkpoint


def _execute(run: dict) -> None:
    run_id = run["run_id"]
    run_dir = _run_dir(run_id)
    checkpoint = _load_or_promote_checkpoint(run, run_dir)
    if checkpoint is None:
        checkpoint = _compute_and_seal(run, run_dir)
    else:
        _set_ledger_status_if_needed(run_id)
        # Handles a crash between ledger status and settlement; already-settled is a no-op.
        db.settle_reservation(run_id)

    if run.get("spec", {}).get("dsl_version") == "1.2":
        source = (run["spec"].get("data") or {}).get("source") or {}
        dataset = db.get_dataset_internal(
            source.get("dataset_id"), run["actor_id"],
            run.get("user_id", run["actor_id"]),
        )
        if dataset is None:
            raise DataQualityError(
                "DATASET_NOT_AVAILABLE",
                "The licensed dataset is no longer available for report display.",
            )
        try:
            assert_dataset_directory_rights(
                db.dataset_directory(dataset),
                operation=DatasetRightsOperation.REPORT,
                policy=activated_rights_policy_from_env(),
                as_of=datetime.now(timezone.utc).date(),
            )
        except MarketDataError as exc:
            raise DataQualityError(exc.code, str(exc)) from exc

    # Deliberately reload again inside render_report.  The first verification establishes
    # resumability; the second guarantees the exact bytes presented have not changed.
    render_report(run_dir, expected_run=run)
    current = db.get_run_internal(run_id)
    if current and current["status"] != "report_rendered":
        db.set_status(run_id, "report_rendered")
    db.set_status(run_id, "published")


def _release_if_unsealed(run_id: str) -> bool:
    """Release a reserved unit. Return whether quota is already charged (sealed)."""
    reservation = db.get_reservation(run_id)
    if reservation is None:
        return False
    if reservation["status"] == "reserved":
        if _has_verified_checkpoint(run_id):
            # The immutable checkpoint is the billable boundary. A later failure may need
            # settlement compensation, but it must never return the held unit to capacity.
            return False
        db.release_reservation(run_id)
        return False
    return bool(reservation["quota_charged"])


def _has_verified_checkpoint(run_id: str) -> bool:
    """Return whether the run already owns a complete, integrity-checked checkpoint."""
    run = db.get_run_internal(run_id)
    if run is None:
        return False
    run_dir = db.var_dir() / "artifacts" / run_id
    if not (run_dir / "manifest.json").exists() or not (run_dir / "ledger_index.json").exists():
        return False
    try:
        load_sealed_artifacts(run_dir, expected_run=run)
    except ArtifactIntegrityError:
        return False
    return True


def _settlement_is_pending(run_id: str) -> bool:
    reservation = db.get_reservation(run_id)
    return bool(
        reservation
        and reservation["status"] == "reserved"
        and _has_verified_checkpoint(run_id)
    )


def _mark_settlement_pending(run_id: str, exc: Exception) -> None:
    """Keep a sealed run compensatable without recording a second seal transition."""
    logger.exception(
        "quota settlement remains pending run_id=%s", run_id,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    error = {
        "code": "SETTLEMENT_PENDING",
        "message": (
            "The sealed checkpoint is awaiting quota settlement. "
            "Internal diagnostics were recorded locally."
        ),
        "quota_charged": False,
        "settlement_pending": True,
    }
    with db.connect() as conn:
        conn.execute(
            "UPDATE runs SET status = 'ledger_sealed', error_json = ?, updated_at = ? "
            "WHERE run_id = ?",
            (json.dumps(error), datetime.now(timezone.utc).isoformat(), run_id),
        )


def process_run(run_id: str) -> str:
    """Execute one run attempt. Retriable failures return it to ``queued``."""
    run = db.get_run_internal(run_id)
    if run is None:
        raise ValueError(f"unknown run {run_id}")
    # A direct process_run call must be just as safe as the queue claim path.  Do this
    # before any status mutation, retry accounting, or entitlement decision.
    assert_run_compatible(run)
    if run["status"] in TERMINAL_STATUSES:
        return run["status"]
    if run["required_worker_contract"] in ISOLATED_WORKER_CONTRACTS:
        # Stop F4 dispatch: the corrected branch owns the isolated-contract
        # law. The exact corrected tuple executes through the corrected
        # orchestration when the separate authority deployment and the
        # control-plane registrar seam are configured (Stop F4b) — the
        # branch owns its own compensation there, because the legacy
        # checkpoint predicate cannot see a sealed corrected candidate.
        # Every other tuple, and every shipped unconfigured store, keeps
        # the typed fail-closed refusal with the reservation refunded and
        # nothing sealed or published by this legacy pipeline.
        if corrected_execution_ready(run):
            return execute_corrected_run(
                run, resolve_snapshot=_resolve_snapshot)
        refusal = corrected_execution_refusal(run)
        charged = _release_if_unsealed(run_id)
        db.set_status(run_id, "system_failed", {
            "code": refusal["code"],
            "message": refusal["message"],
            "quota_charged": charged,
        })
        return db.get_run_internal(run_id)["status"]
    if run["status"] == "queued":
        db.set_status(run_id, "snapshot_pinned")
        run = db.get_run_internal(run_id)
    try:
        _execute(run)
    except FinalHoldoutConsumedError as exc:
        charged = _release_if_unsealed(run_id)
        db.set_status(run_id, "system_failed", {
            "code": "FINAL_HOLDOUT_CONSUMED",
            "message": "The access-controlled final holdout cannot be revealed again "
                       "for a changed rule or interrupted claim. Use a new snapshot or "
                       "cutoff before evaluating another locked plan.",
            "quota_charged": charged,
        })
    except DataQualityError as exc:
        if _settlement_is_pending(run_id):
            _mark_settlement_pending(run_id, exc)
        else:
            charged = _release_if_unsealed(run_id)
            db.set_status(run_id, "data_quality_failed", {
                "code": exc.code, "message": exc.message, "quota_charged": charged,
            })
    except sqlite3.OperationalError as exc:
        # A control-plane outage is not a failed research attempt. Do not consume the
        # run's retry budget or release its reservation. If SQLite has recovered enough
        # to accept a write, make the resumable queue state explicit immediately;
        # otherwise stale-run recovery will safely perform the same transition later.
        if not db.is_transient_database_error(exc):
            raise
        logger.exception(
            "transient database outage interrupted run_id=%s; preserving for recovery",
            run_id,
        )
        try:
            db.set_status(run_id, "queued", {
                "code": "CONTROL_PLANE_RECOVERING",
                "message": (
                    "Execution paused because the local research service was "
                    "temporarily unavailable. The run will resume automatically."
                ),
            })
        except sqlite3.OperationalError as recovery_exc:
            if not db.is_transient_database_error(recovery_exc):
                raise
        raise
    except Exception as exc:  # noqa: BLE001 — process boundary; BaseException means crash
        logger.exception(
            "run attempt failed run_id=%s status=%s next_attempt=%s",
            run_id, db.get_run_internal(run_id)["status"],
            db.get_run_internal(run_id)["retries"] + 1,
        )
        retries = db.bump_retries(run_id)
        if retries <= MAX_RETRIES:
            # Reservation remains held (or settled after seal). A retry must not create a
            # new entitlement decision and will resume from the verified checkpoint.
            db.set_status(run_id, "queued", {
                "code": "RETRYING",
                "message": (
                    f"Attempt {retries} failed and will be retried automatically. "
                    "Internal diagnostics were recorded locally."
                ),
            })
        elif _settlement_is_pending(run_id):
            # A verified checkpoint is the billable boundary. Never release its hold merely
            # because settlement is temporarily unavailable: leave it sealed so stale-run
            # recovery can retry the idempotent settlement without recomputing.
            _mark_settlement_pending(run_id, exc)
        else:
            charged = _release_if_unsealed(run_id)
            db.set_status(run_id, "system_failed", {
                "code": "SYSTEM_FAILED",
                "message": (
                    "The run failed after automatic retries. "
                    "Internal diagnostics were recorded locally."
                ),
                "quota_charged": charged,
            })
    return db.get_run_internal(run_id)["status"]


def recover_stale_runs(stale_after_seconds: int | None = None) -> list[str]:
    """Atomically requeue abandoned active rows after their lease window expires.

    Gate 2 intentionally runs one local worker, so ``updated_at`` plus a timeout is enough
    to recover a crashed process.  This is *not* a distributed lease: running two workers
    while one phase exceeds the timeout could requeue live work.  S4+ must replace it with
    owner tokens, heartbeats, and compare-and-swap lease renewal before concurrency.
    """
    seconds = stale_after_seconds
    if seconds is None:
        seconds = int(os.environ.get("QL_STALE_RUN_SECONDS", DEFAULT_STALE_SECONDS))
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(0, seconds))
    now = datetime.now(timezone.utc).isoformat()
    recovered: list[str] = []
    # Recovery is scoped to this process's queue: a baseline worker must never
    # requeue work another isolated-contract worker legitimately holds, and
    # vice versa. In the shipped default (no isolated contract stamped on any
    # row) the baseline predicate selects exactly the rows it always did.
    serving = serving_worker_contract()
    if serving in ISOLATED_WORKER_CONTRACTS:
        contract_clause = "AND required_worker_contract = ?"
        contract_params: tuple[str, ...] = (serving,)
    else:
        isolated = tuple(sorted(ISOLATED_WORKER_CONTRACTS))
        contract_clause = (
            "AND required_worker_contract NOT IN ("
            + ",".join("?" for _ in isolated) + ")"
        )
        contract_params = isolated
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        placeholders = ",".join("?" for _ in ACTIVE_STATUSES)
        rows = conn.execute(
            f"SELECT run_id, status, history_json, updated_at FROM runs "
            f"WHERE status IN ({placeholders}) {contract_clause} "
            f"ORDER BY created_at",
            tuple(sorted(ACTIVE_STATUSES)) + contract_params,
        ).fetchall()
        for row in rows:
            try:
                updated = datetime.fromisoformat(row["updated_at"])
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                updated = datetime.min.replace(tzinfo=timezone.utc)
            if updated > cutoff:
                continue
            history = json.loads(row["history_json"])
            history.append(["recovered_queued", now])
            cur = conn.execute(
                "UPDATE runs SET status = 'queued', history_json = ?, updated_at = ? "
                "WHERE run_id = ? AND status = ? AND updated_at = ?",
                (json.dumps(history), now, row["run_id"], row["status"], row["updated_at"]),
            )
            if cur.rowcount == 1:
                recovered.append(row["run_id"])
    return recovered


def process_next() -> str | None:
    """Recover stale work, claim the oldest run, and exhaust its bounded retries."""
    recover_stale_runs()
    run_id = db.claim_next_queued()
    if run_id is None:
        return None
    status = process_run(run_id)
    while status == "queued":
        # Retry the same run rather than accidentally claiming another actor's work.
        db.set_status(run_id, "snapshot_pinned")
        status = process_run(run_id)
    return status


def _initialize_database_with_recovery() -> None:
    """Wait through transient startup storage faults; fail fast on invalid stores."""
    failures = 0
    while True:
        try:
            db.init_db()
            return
        except sqlite3.OperationalError as exc:
            if not db.is_transient_database_error(exc):
                raise
            failures += 1
            delay = _control_recovery_delay(failures)
            logger.exception(
                "worker database unavailable during startup; retrying in %.2fs",
                delay,
            )
            time.sleep(delay)


def _poll_forever(heartbeat: WorkerHeartbeat) -> None:
    """Poll without allowing a transient control-plane failure to kill the worker."""
    consecutive_control_failures = 0
    recover_interrupted_run = False
    while True:
        try:
            heartbeat.set_state("busy")
            if recover_interrupted_run:
                # This is a single-worker queue and the prior iteration exited its
                # processing stack. Any active row is therefore abandoned, not live.
                # Recover it immediately instead of waiting the normal stale lease.
                recover_stale_runs(stale_after_seconds=0)
                recover_interrupted_run = False
            result = process_next()
            consecutive_control_failures = 0
            heartbeat.set_state("ready")
            if result is None:
                time.sleep(0.5)
            else:
                print(f"[worker] run finished: {result}", flush=True)
        except KeyboardInterrupt:
            return
        except sqlite3.OperationalError as exc:
            if not db.is_transient_database_error(exc):
                raise
            consecutive_control_failures += 1
            recover_interrupted_run = True
            heartbeat.set_state("recovering")
            delay = _control_recovery_delay(consecutive_control_failures)
            logger.exception(
                "worker control plane temporarily unavailable; retrying in %.2fs",
                delay,
            )
            time.sleep(delay)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("QL_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    assert_expected_runtime("worker")
    _initialize_database_with_recovery()
    runtime = public_runtime_view()
    print(
        f"[worker] polling local queue at {db.db_path()} "
        f"(contract: {runtime['worker_runtime_contract']}; "
        f"serving: {serving_worker_contract()}; snapshot: {snapshot_dir()})",
        flush=True,
    )
    heartbeat = WorkerHeartbeat()
    heartbeat.start()
    try:
        _poll_forever(heartbeat)
    finally:
        heartbeat.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
