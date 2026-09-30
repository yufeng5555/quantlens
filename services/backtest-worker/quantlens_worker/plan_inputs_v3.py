"""Trusted input assembly for the validation-plan-v3 builder (Gate E Stop C1).

Pure, dormant shaping helpers that compose the three closed mappings the v3
plan builder accepts — ``accepted_run``, ``observations`` and ``capabilities``
— from a run identity, a confirmed DSL 1.2 strategy specification, a resolved
observation identity and a configured external-capability state.

This module deliberately performs shape closure only: every semantic law
(frozen tuple identifiers, rule/cost dtypes, fraction bounds, capability
readiness) is owned and re-proved by the builder itself, so no second copy of
that law can drift here.  It imports neither the dormant plan builder nor the
immutable Battery v3 profile — their test-only dormancy boundaries stay exact —
and never reads the environment, clock or filesystem.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

# Frozen Gate E tuple identifiers the control plane stamps on a v3 run.  The
# builder independently requires these exact values, so a drifted literal here
# fails closed downstream instead of producing a different plan.
RELEASE_ID_V3 = "quantlens-financial-v3"
REQUIRED_WORKER_CONTRACT_V3 = "quantlens-worker-v3"
MARKET_OBSERVATIONS_VERSION_V3 = "market-observations-v2"
CANONICALIZATION_POLICY_VERSION_V3 = "market-observation-canonicalization-v2"

RUN_IDENTITY_FIELDS = (
    "tenant_id",
    "workspace_id",
    "run_id",
    "confirmed_spec_hash",
)
OBSERVATION_IDENTITY_FIELDS = (
    "snapshot_sha256",
    "exchange_calendar_id",
    "exchange_calendar_version",
    "n_bars",
)
CAPABILITY_STATE_FIELDS = (
    "anchor_authority_id",
    "anchor_issuer_key_id",
    "holdout_authority_id",
    "holdout_authority_key_id",
    "external_anchor_ready",
    "external_holdout_ready",
)
_RULE_FIELDS = ("type", "ma_days", "fast_ma_days")
_COST_FIELDS = ("commission_bps", "slippage_bps")
_SPEC_REQUIRED_FIELDS = ("dsl_version", "rule", "costs", "validation")


class PlanInputAssemblyV3Error(ValueError):
    """One assembly input cannot be shaped into a closed builder mapping."""


def _fail(detail: str) -> None:
    raise PlanInputAssemblyV3Error(detail)


def _fresh(value: Any, label: str) -> Any:
    """Return a mutation-isolated canonical-JSON copy of one input value."""
    try:
        return json.loads(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        raise PlanInputAssemblyV3Error(
            f"{label} must contain only finite canonical JSON values"
        ) from exc


def _closed(value: object, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be a mapping")
    assert isinstance(value, Mapping)
    keys = set(value)
    expected = set(fields)
    if keys != expected:
        missing = sorted(expected - keys)
        surplus = sorted(str(key) for key in keys - expected)
        _fail(
            f"{label} must have exactly these keys: {', '.join(fields)}"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; unknown: {', '.join(surplus)}" if surplus else "")
        )
    return {field: value[field] for field in fields}


def _spec_section(spec: Mapping[str, Any], field: str) -> Any:
    if field not in spec:
        _fail(f"confirmed_spec.{field} is missing")
    return spec[field]


def assemble_accepted_run_v3(
    *, run_identity: Mapping[str, Any], confirmed_spec: Mapping[str, Any],
) -> dict[str, Any]:
    """Shape the closed ``accepted_run`` mapping from identity plus spec."""
    identity = _closed(run_identity, RUN_IDENTITY_FIELDS, "run_identity")
    if not isinstance(confirmed_spec, Mapping):
        _fail("confirmed_spec must be a mapping")
    assert isinstance(confirmed_spec, Mapping)
    for field in _SPEC_REQUIRED_FIELDS:
        _spec_section(confirmed_spec, field)

    rule_source = _spec_section(confirmed_spec, "rule")
    if not isinstance(rule_source, Mapping):
        _fail("confirmed_spec.rule must be a mapping")
    assert isinstance(rule_source, Mapping)
    unknown = sorted(set(rule_source) - set(_RULE_FIELDS))
    if unknown:
        _fail(
            "confirmed_spec.rule carries keys outside the sealed DSL 1.2 rule "
            "shape: " + ", ".join(str(key) for key in unknown)
        )
    rule = {field: rule_source[field]
            for field in _RULE_FIELDS if field in rule_source}

    costs = _closed(
        _spec_section(confirmed_spec, "costs"), _COST_FIELDS,
        "confirmed_spec.costs")

    validation = _spec_section(confirmed_spec, "validation")
    if not isinstance(validation, Mapping) \
            or not isinstance(validation.get("is_oos_split"), Mapping) \
            or "oos_fraction" not in validation["is_oos_split"]:
        _fail("confirmed_spec.validation.is_oos_split.oos_fraction is missing")

    return _fresh({
        "release_id": RELEASE_ID_V3,
        "required_worker_contract": REQUIRED_WORKER_CONTRACT_V3,
        "tenant_id": identity["tenant_id"],
        "workspace_id": identity["workspace_id"],
        "run_id": identity["run_id"],
        "dsl_schema_version": confirmed_spec["dsl_version"],
        "confirmed_spec_hash": identity["confirmed_spec_hash"],
        "rule": rule,
        "base_costs": costs,
        "registered_final_holdout_fraction": (
            validation["is_oos_split"]["oos_fraction"]),
    }, "accepted_run")


def assemble_observations_v3(
    *, observation_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Shape the closed ``observations`` mapping from a resolved identity."""
    identity = _closed(
        observation_identity, OBSERVATION_IDENTITY_FIELDS,
        "observation_identity")
    return _fresh({
        "market_observations_version": MARKET_OBSERVATIONS_VERSION_V3,
        "canonicalization_policy_version": CANONICALIZATION_POLICY_VERSION_V3,
        "snapshot_sha256": identity["snapshot_sha256"],
        "exchange_calendar_id": identity["exchange_calendar_id"],
        "exchange_calendar_version": identity["exchange_calendar_version"],
        "n_bars": identity["n_bars"],
    }, "observations")


def assemble_capabilities_v3(
    *, capability_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Shape the closed ``capabilities`` mapping from configured state."""
    return _fresh(
        _closed(capability_state, CAPABILITY_STATE_FIELDS, "capability_state"),
        "capabilities")


def assemble_validation_plan_inputs_v3(
    *,
    run_identity: Mapping[str, Any],
    confirmed_spec: Mapping[str, Any],
    observation_identity: Mapping[str, Any],
    capability_state: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Compose all three closed builder inputs in one call."""
    return {
        "accepted_run": assemble_accepted_run_v3(
            run_identity=run_identity, confirmed_spec=confirmed_spec),
        "observations": assemble_observations_v3(
            observation_identity=observation_identity),
        "capabilities": assemble_capabilities_v3(
            capability_state=capability_state),
    }


__all__ = [
    "CANONICALIZATION_POLICY_VERSION_V3",
    "CAPABILITY_STATE_FIELDS",
    "MARKET_OBSERVATIONS_VERSION_V3",
    "OBSERVATION_IDENTITY_FIELDS",
    "PlanInputAssemblyV3Error",
    "RELEASE_ID_V3",
    "REQUIRED_WORKER_CONTRACT_V3",
    "RUN_IDENTITY_FIELDS",
    "assemble_accepted_run_v3",
    "assemble_capabilities_v3",
    "assemble_observations_v3",
    "assemble_validation_plan_inputs_v3",
]
