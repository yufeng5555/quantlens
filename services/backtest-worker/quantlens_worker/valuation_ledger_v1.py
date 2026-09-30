"""Neutral, dormant Gate-B ``ledger-v1`` contracts and hash builders.

The active worker never imports this module.  It contains no engine, battery, runner,
database, report, Agent, registry, filesystem, clock, or network integration.  Its only
purpose is to build and validate the exact data shapes frozen in
``docs/planning/19-gate7a2-gateb-ledger-validator-contract.md`` for local tests.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import date
from pathlib import Path
from typing import Any, Mapping, Sequence

import jsonschema


LEDGER_SEMANTICS_VERSION = "ledger-v1"
VALUATION_LEDGER_VERSION = "valuation-ledger-v1"
FINANCIAL_CONTRACT_VERSION = "financial-contract-v1"
FINANCIAL_SEMANTICS_VERSION = "financial-semantics-v2"
MARKET_OBSERVATIONS_VERSION = "market-observations-v1"
MARKET_OBSERVATIONS_V2_VERSION = "market-observations-v2"
VALIDATOR_VERSION = "financial-semantic-validator-v1"

EXECUTION_ROLES = frozenset({"strategy", "benchmark"})
EXECUTION_PURPOSES = frozenset({
    "primary_evaluation", "fold_slice", "cost_stress", "final_holdout",
})

GATE_B_REQUIRED_KINDS = frozenset({
    "spec",
    "validation_plan",
    "partitions",
    "financial_contract",
    "valuation_ledger",
    "development_result",
    "walk_forward",
    "regime_analysis",
    "final_holdout_result",
    "final_holdout_execution_audit",
    "temporal_integrity",
    "sensitivity",
    "cost_stress",
    "falsification",
    "evidence_status",
    "data_gaps",
    "snapshot_ref",
})

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID_RE = re.compile(r"^exec-[0-9a-f]{64}$")
_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "packages" / "strategy-schema" / "schema"
_SCHEMA_FILES = {
    FINANCIAL_CONTRACT_VERSION: "financial-contract-v1.json",
    MARKET_OBSERVATIONS_VERSION: "market-observations-v1.json",
    MARKET_OBSERVATIONS_V2_VERSION: "market-observations-v2.json",
    "valuation-execution-v1": "valuation-execution-v1.json",
    LEDGER_SEMANTICS_VERSION: "valuation-ledger-index-v1.json",
    "semantic-validation-receipt-v1": "semantic-validation-receipt-v1.json",
}


class ValuationLedgerContractError(ValueError):
    """One candidate value violates the frozen Gate-B data contract."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the exact frozen Gate-B canonical JSON bytes."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValuationLedgerContractError(
            "ledger-v1 accepts only finite canonical JSON values"
        ) from exc


def sha256_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_ledger_v1_schema(contract: str) -> dict[str, Any]:
    filename = _SCHEMA_FILES.get(contract)
    if filename is None:
        raise ValuationLedgerContractError(f"unsupported Gate-B schema: {contract!r}")
    try:
        value = json.loads((_SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValuationLedgerContractError(f"cannot load Gate-B schema: {contract}") from exc
    if not isinstance(value, dict):
        raise ValuationLedgerContractError(f"{contract} schema must be an object")
    return value


def validate_schema_v1(contract: str, value: Mapping[str, Any]) -> None:
    """Validate exact structure and reject NaN/Infinity before JSON Schema."""
    canonical_json_bytes(value)
    try:
        jsonschema.Draft202012Validator(
            load_ledger_v1_schema(contract),
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)
    except jsonschema.ValidationError as exc:
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in exc.absolute_path
        )
        raise ValuationLedgerContractError(
            f"{contract} contract violation at {path}: {exc.message}"
        ) from exc


def _closed(value: object, keys: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValuationLedgerContractError(
            f"{label} must have exactly these keys: {', '.join(sorted(keys))}"
        )
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValuationLedgerContractError(
            f"{label} must be sha256: followed by 64 lowercase hex characters"
        )
    return value


def _finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValuationLedgerContractError(f"{label} must be a finite JSON number")
    result = float(value)
    if not math.isfinite(result):
        raise ValuationLedgerContractError(f"{label} must be a finite JSON number")
    return result


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValuationLedgerContractError(f"{label} must be an integer >= {minimum}")
    return value


def _date(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValuationLedgerContractError(f"{label} must be YYYY-MM-DD")
    try:
        if date.fromisoformat(value).isoformat() != value:
            raise ValueError
    except ValueError as exc:
        raise ValuationLedgerContractError(f"{label} must be canonical YYYY-MM-DD") from exc
    return value


def build_financial_contract_v1(
    *,
    financial_semantics_sha256: str,
    metric_semantics_version: str,
    metric_semantics_sha256: str,
    initial_capital: float,
    base_currency: str,
    exchange_calendar_id: str,
    exchange_calendar_version: str,
    acquisition_validation_receipt_sha256: str,
) -> dict[str, Any]:
    """Build the only reviewed Gate-B financial-policy subset."""
    value = {
        "contract_version": FINANCIAL_CONTRACT_VERSION,
        "ledger_semantics_version": LEDGER_SEMANTICS_VERSION,
        "financial_semantics_version": FINANCIAL_SEMANTICS_VERSION,
        "financial_semantics_sha256": _sha256(
            financial_semantics_sha256, "financial_semantics_sha256"
        ),
        "metric_semantics_version": metric_semantics_version,
        "metric_semantics_sha256": _sha256(
            metric_semantics_sha256, "metric_semantics_sha256"
        ),
        "initial_capital": _finite(initial_capital, "initial_capital"),
        "return_basis": {
            "kind": "price_return",
            "split_adjusted": True,
            "distribution_policy": "excluded",
            "source": "dataset_manifest",
        },
        "cash_return_policy": {
            "kind": "zero_yield",
            "annual_rate": 0.0,
            "day_count": "252_sessions",
        },
        "risk_free_policy": {"kind": "same_as_cash_policy"},
        "minimum_acceptable_return_policy": {
            "kind": "same_as_risk_free_policy",
        },
        "currency_policy": {
            "base_currency": base_currency,
            "fx_policy": "single_currency_only",
        },
        "calendar_binding": {
            "exchange_calendar_id": exchange_calendar_id,
            "exchange_calendar_version": exchange_calendar_version,
            "acquisition_validation_receipt_sha256": _sha256(
                acquisition_validation_receipt_sha256,
                "acquisition_validation_receipt_sha256",
            ),
        },
        "position_sizing_policy": {
            "kind": "full_notional_fractional_shares",
        },
        "execution_policy": {
            "decision_time": "close_t",
            "fill_time": "next_valid_session_open",
            "slippage_model": "adverse_effective_fill_price",
            "terminal_policy": "mark_to_market_no_forced_liquidation",
        },
    }
    validate_schema_v1(FINANCIAL_CONTRACT_VERSION, value)
    return value


def build_market_observations_v1(
    *,
    snapshot_sha256: str,
    exchange_calendar_id: str,
    exchange_calendar_version: str,
    instruments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build injected read-only snapshot evidence; it is never a ledger artifact."""
    value = {
        "market_observations_version": MARKET_OBSERVATIONS_VERSION,
        "snapshot_sha256": _sha256(snapshot_sha256, "snapshot_sha256"),
        "exchange_calendar_id": exchange_calendar_id,
        "exchange_calendar_version": exchange_calendar_version,
        "instruments": [copy.deepcopy(dict(instrument)) for instrument in instruments],
    }
    validate_schema_v1(MARKET_OBSERVATIONS_VERSION, value)
    instrument_keys = [
        (instrument["symbol"], instrument["currency"])
        for instrument in value["instruments"]
    ]
    if instrument_keys != sorted(instrument_keys) or len(instrument_keys) != len(set(instrument_keys)):
        raise ValuationLedgerContractError(
            "market observation instruments must be unique and canonically ordered"
        )
    for instrument in value["instruments"]:
        session_dates = [session["date"] for session in instrument["sessions"]]
        if session_dates != sorted(session_dates) or len(session_dates) != len(set(session_dates)):
            raise ValuationLedgerContractError(
                "market observation sessions must be unique and strictly increasing"
            )
    return value


def build_market_observations_v2(
    *,
    snapshot_sha256: str,
    exchange_calendar_id: str,
    exchange_calendar_version: str,
    instruments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build dormant Gate-C reviewed evidence with exact OHLCV sessions.

    Unlike v1, this contract retains every column used by
    ``validation_partition.frame_sha256`` so an independent consumer can reproduce
    prefix, development, capsule, and final-evaluation digests byte-for-byte.
    """
    value = {
        "market_observations_version": MARKET_OBSERVATIONS_V2_VERSION,
        "snapshot_sha256": _sha256(snapshot_sha256, "snapshot_sha256"),
        "exchange_calendar_id": exchange_calendar_id,
        "exchange_calendar_version": exchange_calendar_version,
        "instruments": [copy.deepcopy(dict(instrument)) for instrument in instruments],
    }
    validate_schema_v1(MARKET_OBSERVATIONS_V2_VERSION, value)
    instrument_keys = [
        (instrument["symbol"], instrument["currency"])
        for instrument in value["instruments"]
    ]
    if instrument_keys != sorted(instrument_keys) or len(instrument_keys) != len(set(instrument_keys)):
        raise ValuationLedgerContractError(
            "market observation instruments must be unique and canonically ordered"
        )
    for instrument in value["instruments"]:
        session_dates = [session["date"] for session in instrument["sessions"]]
        if session_dates != sorted(session_dates) or len(session_dates) != len(set(session_dates)):
            raise ValuationLedgerContractError(
                "market observation sessions must be unique and strictly increasing"
            )
        for session in instrument["sessions"]:
            opening = _finite(session["open"], "session.open")
            high = _finite(session["high"], "session.high")
            low = _finite(session["low"], "session.low")
            close = _finite(session["close"], "session.close")
            volume = _finite(session["volume"], "session.volume")
            if (
                min(opening, high, low, close) <= 0
                or high < max(opening, close)
                or low > min(opening, close)
                or volume < 0
            ):
                raise ValuationLedgerContractError(
                    "market observation OHLCV values are internally inconsistent"
                )
    return value


def build_carry_v1(*, cash: float, shares: float, position: int) -> dict[str, Any]:
    value = {
        "cash": _finite(cash, "carry.cash"),
        "shares": _finite(shares, "carry.shares"),
        "position": _integer(position, "carry.position"),
    }
    if value["cash"] < 0 or value["shares"] < 0 or value["position"] not in {0, 1}:
        raise ValuationLedgerContractError("carry must be non-negative and long/flat")
    return value


def build_window_v1(
    *,
    start_date: str,
    end_date: str,
    start_index: int,
    end_index_exclusive: int,
) -> dict[str, Any]:
    start = _integer(start_index, "window.start_index")
    end = _integer(end_index_exclusive, "window.end_index_exclusive", minimum=1)
    if end <= start:
        raise ValuationLedgerContractError("window.end_index_exclusive must exceed start_index")
    value = {
        "start_date": _date(start_date, "window.start_date"),
        "end_date": _date(end_date, "window.end_date"),
        "start_index": start,
        "end_index_exclusive": end,
        "observation_count": end - start,
    }
    if value["end_date"] < value["start_date"]:
        raise ValuationLedgerContractError("window end_date precedes start_date")
    return value


def execution_identity_v1(
    *,
    spec_hash: str,
    snapshot_sha256: str,
    role: str,
    purpose: str,
    window: Mapping[str, Any],
    cost_multiplier: float,
    carry_in_sha256: str,
) -> dict[str, Any]:
    if role not in EXECUTION_ROLES:
        raise ValuationLedgerContractError(f"unsupported execution role: {role!r}")
    if purpose not in EXECUTION_PURPOSES:
        raise ValuationLedgerContractError(f"unsupported execution purpose: {purpose!r}")
    window_value = _closed(
        copy.deepcopy(dict(window)),
        {"start_date", "end_date", "start_index", "end_index_exclusive", "observation_count"},
        "window",
    )
    expected_window = build_window_v1(
        start_date=window_value["start_date"],
        end_date=window_value["end_date"],
        start_index=window_value["start_index"],
        end_index_exclusive=window_value["end_index_exclusive"],
    )
    if window_value != expected_window:
        raise ValuationLedgerContractError("window observation_count contradicts its indices")
    multiplier = _finite(cost_multiplier, "cost_multiplier")
    if multiplier < 0:
        raise ValuationLedgerContractError("cost_multiplier cannot be negative")
    return {
        "spec_hash": _sha256(spec_hash, "spec_hash"),
        "snapshot_sha256": _sha256(snapshot_sha256, "snapshot_sha256"),
        "role": role,
        "purpose": purpose,
        "window": window_value,
        "cost_multiplier": multiplier,
        "carry_in_sha256": _sha256(carry_in_sha256, "carry_in_sha256"),
    }


def stable_execution_id_v1(**identity_fields: Any) -> str:
    return "exec-" + hashlib.sha256(
        canonical_json_bytes(execution_identity_v1(**identity_fields))
    ).hexdigest()


def build_execution_v1(
    *,
    spec_hash: str,
    snapshot_sha256: str,
    role: str,
    purpose: str,
    window: Mapping[str, Any],
    cost_multiplier: float,
    carry_in: Mapping[str, Any],
    carry_out: Mapping[str, Any],
    bars: Sequence[Mapping[str, Any]],
    fills: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one exact execution object without producer-computed metrics."""
    carry_in_value = _closed(
        copy.deepcopy(dict(carry_in)), {"cash", "shares", "position"}, "carry_in"
    )
    carry_out_value = _closed(
        copy.deepcopy(dict(carry_out)), {"cash", "shares", "position"}, "carry_out"
    )
    # Rebuild rather than silently coerce an invalid carry.
    if carry_in_value != build_carry_v1(**carry_in_value) or \
            carry_out_value != build_carry_v1(**carry_out_value):
        raise ValuationLedgerContractError("carry values are not canonical")
    carry_in_hash = sha256_json(carry_in_value)
    identity = execution_identity_v1(
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        role=role,
        purpose=purpose,
        window=window,
        cost_multiplier=cost_multiplier,
        carry_in_sha256=carry_in_hash,
    )
    execution_id = "exec-" + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    value = {
        "execution_id": execution_id,
        "role": role,
        "purpose": purpose,
        "window": copy.deepcopy(identity["window"]),
        "cost_multiplier": identity["cost_multiplier"],
        "carry_in": carry_in_value,
        "carry_in_sha256": carry_in_hash,
        "carry_out": carry_out_value,
        "carry_out_sha256": sha256_json(carry_out_value),
        "bars": [copy.deepcopy(dict(bar)) for bar in bars],
        "fills": [copy.deepcopy(dict(fill)) for fill in fills],
    }
    validate_schema_v1("valuation-execution-v1", value)
    window_value = value["window"]
    bar_dates = [bar["date"] for bar in value["bars"]]
    if len(bar_dates) != window_value["observation_count"]:
        raise ValuationLedgerContractError("bar count contradicts the execution window")
    if bar_dates != sorted(bar_dates) or len(bar_dates) != len(set(bar_dates)):
        raise ValuationLedgerContractError("bar dates must be unique and strictly increasing")
    if bar_dates[0] != window_value["start_date"] or bar_dates[-1] != window_value["end_date"]:
        raise ValuationLedgerContractError("bar dates do not cover the exact execution window")
    if any(fill["session"] not in set(bar_dates) for fill in value["fills"]):
        raise ValuationLedgerContractError("every fill session must be inside its execution")
    last_bar = value["bars"][-1]
    if value["carry_out"] != {
        "cash": last_bar["cash"],
        "shares": last_bar["shares"],
        "position": last_bar["position"],
    }:
        raise ValuationLedgerContractError("carry_out must equal the final bar state")
    return value


def execution_sort_key_v1(execution: Mapping[str, Any]) -> tuple[Any, ...]:
    window = execution["window"]
    return (
        window["start_index"],
        window["end_index_exclusive"],
        execution["purpose"],
        execution["role"],
        execution["cost_multiplier"],
        execution["execution_id"],
    )


def validate_execution_contract_v1(
    execution: Mapping[str, Any], *, spec_hash: str, snapshot_sha256: str,
) -> None:
    validate_schema_v1("valuation-execution-v1", execution)
    carry_in = execution["carry_in"]
    carry_out = execution["carry_out"]
    if execution["carry_in_sha256"] != sha256_json(carry_in) or \
            execution["carry_out_sha256"] != sha256_json(carry_out):
        raise ValuationLedgerContractError("execution carry hash mismatch")
    expected_id = stable_execution_id_v1(
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        role=execution["role"],
        purpose=execution["purpose"],
        window=execution["window"],
        cost_multiplier=execution["cost_multiplier"],
        carry_in_sha256=execution["carry_in_sha256"],
    )
    if execution["execution_id"] != expected_id:
        raise ValuationLedgerContractError("execution_id does not bind its canonical identity")
    bars = execution["bars"]
    window = execution["window"]
    dates = [bar["date"] for bar in bars]
    if len(dates) != window["observation_count"] or dates != sorted(dates) or \
            len(dates) != len(set(dates)) or dates[0] != window["start_date"] or \
            dates[-1] != window["end_date"]:
        raise ValuationLedgerContractError("execution date/window contract mismatch")
    last = bars[-1]
    if carry_out != {"cash": last["cash"], "shares": last["shares"], "position": last["position"]}:
        raise ValuationLedgerContractError("carry_out does not equal the final bar state")


def build_valuation_ledger_v1(
    *,
    financial_contract: Mapping[str, Any],
    spec_hash: str,
    snapshot_sha256: str,
    executions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the exact valuation_ledger artifact payload from dormant executions."""
    validate_schema_v1(FINANCIAL_CONTRACT_VERSION, financial_contract)
    spec = _sha256(spec_hash, "spec_hash")
    snapshot = _sha256(snapshot_sha256, "snapshot_sha256")
    execution_values = [copy.deepcopy(dict(item)) for item in executions]
    if not execution_values:
        raise ValuationLedgerContractError("valuation ledger requires at least one execution")
    for execution in execution_values:
        validate_execution_contract_v1(execution, spec_hash=spec, snapshot_sha256=snapshot)
    execution_values.sort(key=execution_sort_key_v1)
    ids = [execution["execution_id"] for execution in execution_values]
    if len(ids) != len(set(ids)):
        raise ValuationLedgerContractError("valuation ledger execution IDs must be unique")
    return {
        "valuation_ledger_version": VALUATION_LEDGER_VERSION,
        "financial_contract_sha256": sha256_json(financial_contract),
        "spec_hash": spec,
        "snapshot_sha256": snapshot,
        "executions": execution_values,
    }


def validate_valuation_ledger_contract_v1(
    valuation_ledger: Mapping[str, Any], financial_contract: Mapping[str, Any],
) -> None:
    value = _closed(
        valuation_ledger,
        {
            "valuation_ledger_version",
            "financial_contract_sha256",
            "spec_hash",
            "snapshot_sha256",
            "executions",
        },
        "valuation_ledger",
    )
    if value["valuation_ledger_version"] != VALUATION_LEDGER_VERSION:
        raise ValuationLedgerContractError("unsupported valuation ledger version")
    validate_schema_v1(FINANCIAL_CONTRACT_VERSION, financial_contract)
    if value["financial_contract_sha256"] != sha256_json(financial_contract):
        raise ValuationLedgerContractError("financial contract hash mismatch")
    spec = _sha256(value["spec_hash"], "spec_hash")
    snapshot = _sha256(value["snapshot_sha256"], "snapshot_sha256")
    executions = value["executions"]
    if not isinstance(executions, list) or not executions:
        raise ValuationLedgerContractError("executions must be a non-empty array")
    for execution in executions:
        validate_execution_contract_v1(execution, spec_hash=spec, snapshot_sha256=snapshot)
    if executions != sorted(executions, key=execution_sort_key_v1):
        raise ValuationLedgerContractError("executions are not in canonical order")
    ids = [execution["execution_id"] for execution in executions]
    if len(ids) != len(set(ids)):
        raise ValuationLedgerContractError("duplicate execution_id")
    canonical_json_bytes(value)


def build_artifact_wrapper_v1(
    *, kind: str, producer: str, payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(kind, str) or re.fullmatch(r"[a-z][a-z0-9_]*", kind) is None:
        raise ValuationLedgerContractError("artifact kind is malformed")
    if not isinstance(producer, str) or not producer or not producer.isascii() or \
            any(character.isspace() for character in producer):
        raise ValuationLedgerContractError("producer must be a non-empty ASCII identity")
    value = {"kind": kind, "producer": producer, "payload": copy.deepcopy(dict(payload))}
    canonical_json_bytes(value)
    return value


def build_ledger_entry_v1(*, kind: str, producer: str, payload: Mapping[str, Any]) -> tuple[dict, bytes]:
    wrapper = build_artifact_wrapper_v1(kind=kind, producer=producer, payload=payload)
    body = canonical_json_bytes(wrapper)
    digest = hashlib.sha256(body).hexdigest()
    entry = {
        "artifact_id": f"{kind}-{digest[:12]}",
        "kind": kind,
        "sha256": digest,
        "path": f"artifact_{kind}.json",
        "producer": producer,
    }
    return entry, body


def build_ledger_index_v1(entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    values = [copy.deepcopy(dict(entry)) for entry in entries]
    if not values:
        raise ValuationLedgerContractError("ledger-v1 requires at least one entry")
    values.sort(key=lambda entry: (entry["kind"], entry["path"]))
    binding = {"ledger_semantics_version": LEDGER_SEMANTICS_VERSION, "entries": values}
    result_hash = sha256_json(binding)
    index = {
        "ledger_semantics_version": LEDGER_SEMANTICS_VERSION,
        "ledger_id": "ldg-" + result_hash.removeprefix("sha256:"),
        "entries": values,
        "result_hash": result_hash,
    }
    validate_ledger_index_contract_v1(index)
    return index


def validate_ledger_index_contract_v1(index: Mapping[str, Any]) -> None:
    validate_schema_v1(LEDGER_SEMANTICS_VERSION, index)
    entries = index["entries"]
    if entries != sorted(entries, key=lambda entry: (entry["kind"], entry["path"])):
        raise ValuationLedgerContractError("ledger entries are not in canonical order")
    kinds = [entry["kind"] for entry in entries]
    paths = [entry["path"] for entry in entries]
    artifact_ids = [entry["artifact_id"] for entry in entries]
    if len(kinds) != len(set(kinds)) or len(paths) != len(set(paths)) or \
            len(artifact_ids) != len(set(artifact_ids)):
        raise ValuationLedgerContractError("duplicate ledger kind, path, or artifact_id")
    for entry in entries:
        if entry["path"] != f"artifact_{entry['kind']}.json" or \
                entry["artifact_id"] != f"{entry['kind']}-{entry['sha256'][:12]}":
            raise ValuationLedgerContractError("ledger entry identity/path mismatch")
    binding = {"ledger_semantics_version": LEDGER_SEMANTICS_VERSION, "entries": entries}
    expected_hash = sha256_json(binding)
    if index["result_hash"] != expected_hash or \
            index["ledger_id"] != "ldg-" + expected_hash.removeprefix("sha256:"):
        raise ValuationLedgerContractError("ledger result_hash or ledger_id mismatch")


def build_validation_receipt_v1(
    *,
    ledger_index: Mapping[str, Any],
    financial_contract_sha256: str,
    validated_execution_ids: Sequence[str],
) -> dict[str, Any]:
    validate_ledger_index_contract_v1(ledger_index)
    ids = list(validated_execution_ids)
    if any(not isinstance(value, str) or _EXECUTION_ID_RE.fullmatch(value) is None for value in ids):
        raise ValuationLedgerContractError("validation receipt has malformed execution ID")
    if len(ids) != len(set(ids)):
        raise ValuationLedgerContractError("validation receipt execution IDs must be unique")
    receipt = {
        "validator_version": VALIDATOR_VERSION,
        "ledger_id": ledger_index["ledger_id"],
        "result_hash": ledger_index["result_hash"],
        "financial_contract_sha256": _sha256(
            financial_contract_sha256, "financial_contract_sha256"
        ),
        "validated_execution_ids": ids,
        "status": "PASS",
    }
    validate_schema_v1("semantic-validation-receipt-v1", receipt)
    return receipt


def required_gate_b_kinds_v1(dsl_version: str) -> frozenset[str]:
    if dsl_version == "1.0":
        return GATE_B_REQUIRED_KINDS
    if dsl_version in {"1.1", "1.2"}:
        return GATE_B_REQUIRED_KINDS | {"data_provenance"}
    raise ValuationLedgerContractError(f"unsupported sealed DSL version: {dsl_version!r}")


__all__ = [
    "EXECUTION_PURPOSES",
    "EXECUTION_ROLES",
    "FINANCIAL_CONTRACT_VERSION",
    "FINANCIAL_SEMANTICS_VERSION",
    "GATE_B_REQUIRED_KINDS",
    "LEDGER_SEMANTICS_VERSION",
    "MARKET_OBSERVATIONS_VERSION",
    "MARKET_OBSERVATIONS_V2_VERSION",
    "VALIDATOR_VERSION",
    "VALUATION_LEDGER_VERSION",
    "ValuationLedgerContractError",
    "build_artifact_wrapper_v1",
    "build_carry_v1",
    "build_execution_v1",
    "build_financial_contract_v1",
    "build_ledger_entry_v1",
    "build_ledger_index_v1",
    "build_market_observations_v1",
    "build_market_observations_v2",
    "build_validation_receipt_v1",
    "build_valuation_ledger_v1",
    "build_window_v1",
    "canonical_json_bytes",
    "execution_identity_v1",
    "execution_sort_key_v1",
    "load_ledger_v1_schema",
    "required_gate_b_kinds_v1",
    "sha256_json",
    "stable_execution_id_v1",
    "validate_execution_contract_v1",
    "validate_ledger_index_contract_v1",
    "validate_schema_v1",
    "validate_valuation_ledger_contract_v1",
]
