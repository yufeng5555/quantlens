"""Final-holdout execution and audit payloads for a v3 run (Gate E Stop C3).

Consumes one released plaintext body from the external holdout authority and
produces the sealed final-side payloads: the strategy/benchmark execution pair
(through an INJECTED window executor, so no dormant producer module is named
here), the ``final_holdout_result`` payload whose metrics the independent
validator re-derives, and the v3 ``final_holdout_execution_audit`` payload whose
bare-payload digest the resolver binds directly in manifest v3.

Every identifier in the released body is cross-bound to the lease that released
it, the evaluation window is proved against the sealed partitions, and the
audit's access block carries the authority's own verified terminal audit — so
the sealed evidence records exactly which one-use lease produced it.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable, Mapping

from .evidence_projection_v3 import reconstruct_display_metrics_v3
from .valuation_ledger_v1 import sha256_json

FINAL_HOLDOUT_AUDIT_VERSION_V3 = "final-holdout-audit-v3"
ACCESS_PROTOCOL_V1 = "final-holdout-access-v1"

_EXECUTION_KEYS = frozenset({
    "execution_id", "role", "purpose", "window", "cost_multiplier",
    "carry_in", "carry_in_sha256", "carry_out", "carry_out_sha256",
    "bars", "fills",
})
_LEASE_BOUND_FIELDS = (
    "release_id", "lease_id", "capsule_id", "anchor_id", "run_id",
    "capsule_payload_sha256",
)


class FinalExecutionV3Error(ValueError):
    """One final-holdout input contradicts its lease, plan or partitions."""


def _fail(detail: str) -> None:
    raise FinalExecutionV3Error(detail)


def _require(condition: bool, detail: str) -> None:
    if not condition:
        _fail(detail)


def _fresh(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        raise FinalExecutionV3Error(
            f"{label} must contain only finite canonical JSON values"
        ) from exc


def execute_final_holdout_v3(
    *,
    consume_body: Mapping[str, Any],
    lease: Mapping[str, Any],
    partitions: Mapping[str, Any],
    locked_rule: Mapping[str, Any],
    base_costs: Mapping[str, Any],
    initial_capital: float,
    benchmark_symbol: str,
    spec_hash: str,
    snapshot_sha256: str,
    validation_plan_hash: str,
    window_executor: Callable[..., Mapping[str, Any]],
) -> dict[str, Any]:
    """Run the one final-holdout evaluation and project its result payload."""
    consume_body = _fresh(dict(consume_body), "consume_body")
    lease = _fresh(dict(lease), "lease")
    partitions = _fresh(dict(partitions), "partitions")
    _require(callable(window_executor), "window_executor must be callable")
    capital = float(initial_capital)
    _require(capital > 0, "initial_capital must be positive")

    _require(consume_body.get("code") == "PLAINTEXT_RELEASED"
             and consume_body.get("state") == "CONSUMED",
             "the released body is not a consumed plaintext release")
    for field in _LEASE_BOUND_FIELDS:
        _require(
            consume_body.get(field) == lease.get(field),
            f"the released body and its lease disagree on {field}",
        )

    window = partitions["final_holdout"]
    start = int(window["start_index"])
    end = int(window["end_index"])
    warmup_start = int(window["warmup_start_index"])
    warmup_bars = int(window["warmup_bars"])
    _require(
        int(consume_body["evaluation_start_offset"]) == warmup_bars,
        "the released evaluation offset contradicts the sealed warm-up span",
    )

    primary = consume_body["primary_observations"]
    benchmark = consume_body["benchmark_observations"]
    _require(
        json.dumps(primary, sort_keys=True, separators=(",", ":"))
        == json.dumps(benchmark, sort_keys=True, separators=(",", ":")),
        "the released benchmark document is not canonical-identical to the "
        "primary document",
    )
    sessions = primary["instruments"][0]["sessions"]
    _require(
        len(sessions) == end - warmup_start,
        "the released capsule length contradicts the sealed final window",
    )

    # The physical frame origin is the warm-up start; global indices are never
    # rebased, so the executor receives the sealed absolute window.
    frame = [
        {
            "date": row["date"], "open": row["open"], "high": row["high"],
            "low": row["low"], "close": row["close"],
            "volume": row.get("volume", 0),
        }
        for row in sessions
    ]
    executions: dict[str, dict[str, Any]] = {}
    for role in ("strategy", "benchmark"):
        raw = window_executor(
            frame=frame,
            frame_start_index=warmup_start,
            start_index=start,
            end_index_exclusive=end,
            role=role,
            purpose="final_holdout",
            rule=dict(locked_rule),
            costs=dict(base_costs),
            cost_multiplier=1.0,
            carry_in={"cash": capital, "shares": 0.0, "position": 0},
            benchmark_entry_index=None if role == "strategy" else start,
            spec_hash=spec_hash,
            snapshot_sha256=snapshot_sha256,
        )
        execution = copy.deepcopy(dict(raw))
        _require(set(execution) == _EXECUTION_KEYS,
                 f"the {role} execution does not carry the closed key set")
        _require(
            execution["role"] == role
            and execution["purpose"] == "final_holdout"
            and float(execution["cost_multiplier"]) == 1.0,
            f"the {role} execution identity contradicts the final-holdout law",
        )
        _require(
            (execution["window"]["start_index"],
             execution["window"]["end_index_exclusive"]) == (start, end),
            f"the {role} execution window contradicts the sealed final window",
        )
        executions[role] = execution
    _require(
        len(executions["benchmark"]["fills"]) == 1,
        "the final benchmark must enter exactly once at its first session",
    )

    strategy_metrics = reconstruct_display_metrics_v3(
        executions["strategy"]["bars"], executions["strategy"]["fills"],
        capital)
    benchmark_metrics = reconstruct_display_metrics_v3(
        executions["benchmark"]["bars"], executions["benchmark"]["fills"],
        capital)
    final_holdout_result = {
        "status": "COMPLETE",
        "strategy_metrics": strategy_metrics,
        "comparison_strategy_metrics": dict(strategy_metrics),
        "benchmark_metrics": benchmark_metrics,
        "benchmark_symbol": benchmark_symbol,
        "comparison_start": executions["benchmark"]["bars"][0]["date"],
        "equity_series": {
            "date": [bar["date"] for bar in executions["strategy"]["bars"]],
            "equity": [bar["equity"]
                       for bar in executions["strategy"]["bars"]],
            "position": [bar["position"]
                         for bar in executions["strategy"]["bars"]],
        },
        "benchmark_series": {
            "date": [bar["date"] for bar in executions["benchmark"]["bars"]],
            "equity": [bar["equity"]
                       for bar in executions["benchmark"]["bars"]],
        },
        "trades": [dict(fill) for fill in executions["strategy"]["fills"]],
        "benchmark_entry": dict(executions["benchmark"]["fills"][0]),
        "execution_binding": {
            "capsule_id": consume_body["capsule_id"],
            "confirmed_spec_hash": spec_hash,
            "validation_plan_hash": validation_plan_hash,
            "locked_rule_sha256": sha256_json(locked_rule),
            "base_costs_sha256": sha256_json(base_costs),
            "cost_multiplier": 1.0,
        },
    }
    return _fresh({
        "executions": executions,
        "final_holdout_result": final_holdout_result,
    }, "final holdout projection")


def build_final_holdout_execution_audit_v3(
    *,
    final_holdout_result: Mapping[str, Any],
    lease: Mapping[str, Any],
    consume_receipt: Mapping[str, Any],
    terminal_audit: Mapping[str, Any],
    authority_id: str,
) -> dict[str, Any]:
    """Build the v3 final-holdout execution audit around its access record."""
    final_holdout_result = _fresh(
        dict(final_holdout_result), "final_holdout_result")
    lease = _fresh(dict(lease), "lease")
    consume_receipt = _fresh(dict(consume_receipt), "consume_receipt")
    terminal_audit = _fresh(dict(terminal_audit), "terminal_audit")

    _require(
        "primary_observations" not in consume_receipt
        and "benchmark_observations" not in consume_receipt,
        "the consume receipt must never carry released observation data",
    )
    for field in _LEASE_BOUND_FIELDS:
        _require(consume_receipt.get(field) == lease.get(field),
                 f"the consume receipt and lease disagree on {field}")
    _require(terminal_audit.get("lease_id") == lease["lease_id"],
             "the terminal audit belongs to a different lease")
    _require(terminal_audit.get("outcome") == "evaluation_succeeded",
             "a sealed final result requires a succeeded terminal audit")
    _require(terminal_audit.get("denial_reason") is None,
             "a succeeded terminal audit carries no denial reason")
    _require(terminal_audit.get("consumed_at")
             == consume_receipt.get("consumed_at"),
             "the terminal audit and consume receipt disagree on consumed_at")
    _require(terminal_audit.get("authority_id") == authority_id,
             "the terminal audit names a different authority")
    binding = final_holdout_result["execution_binding"]
    _require(binding["capsule_id"] == lease["capsule_id"],
             "the execution binding names a different capsule")

    return _fresh({
        "audit_version": FINAL_HOLDOUT_AUDIT_VERSION_V3,
        "state": "final.result",
        "primary_evaluation_count": 1,
        "counterfactual_evaluation_count": 0,
        "recovered_result": False,
        "reused_across_run": False,
        "run_primary_evaluation_count": 1,
        "capsule_id": binding["capsule_id"],
        "validation_plan_hash": binding["validation_plan_hash"],
        "confirmed_spec_hash": binding["confirmed_spec_hash"],
        "execution_binding": dict(binding),
        "holdout_access": {
            "access_protocol": ACCESS_PROTOCOL_V1,
            "authority_id": authority_id,
            "lease_id": lease["lease_id"],
            "anchor_id": lease["anchor_id"],
            "anchor_sha256": lease["anchor_sha256"],
            "capsule_payload_sha256": lease["capsule_payload_sha256"],
            "run_id": lease["run_id"],
            "consumed_at": consume_receipt["consumed_at"],
            "completion_outcome": terminal_audit["outcome"],
            "terminal_audit": terminal_audit,
        },
    }, "final holdout execution audit")


__all__ = [
    "ACCESS_PROTOCOL_V1",
    "FINAL_HOLDOUT_AUDIT_VERSION_V3",
    "FinalExecutionV3Error",
    "build_final_holdout_execution_audit_v3",
    "execute_final_holdout_v3",
]
