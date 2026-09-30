"""Pure consumer-side validation for the dormant Gate-B financial ledger.

The validator accepts parsed, copied data only.  It performs no I/O and deliberately
shares no executable financial code with the evidence producer.  Byte integrity and
financial correctness are separate checks: the former is reconstructed from artifact
wrappers and the ledger index; the latter is reconstructed from fills and per-session
valuations.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from datetime import date
from typing import Any, Mapping, Sequence


VALIDATOR_VERSION = "financial-semantic-validator-v1"
MONEY_ABSOLUTE_TOLERANCE = 1e-8
QUANTITY_ABSOLUTE_TOLERANCE = 1e-12
METRIC_ABSOLUTE_TOLERANCE = 1e-12
METRIC_RELATIVE_TOLERANCE = 1e-12
ANNUALIZATION_SESSIONS = 252

_CODES = frozenset({
    "LEDGER_V1_SCHEMA_INVALID",
    "LEDGER_V1_NONFINITE_NUMBER",
    "LEDGER_V1_BINDING_MISMATCH",
    "LEDGER_V1_UNSUPPORTED_CONTRACT",
    "LEDGER_V1_POLICY_MISMATCH",
    "LEDGER_V1_CURRENCY_MISMATCH",
    "LEDGER_V1_DATE_SEQUENCE_INVALID",
    "LEDGER_V1_EXECUTION_ID_MISMATCH",
    "LEDGER_V1_CARRY_HASH_MISMATCH",
    "LEDGER_V1_FILL_MISMATCH",
    "LEDGER_V1_ACCOUNTING_MISMATCH",
    "LEDGER_V1_METRIC_MISMATCH",
    "LEDGER_V1_FOLD_MISMATCH",
    "LEDGER_V1_COST_STRESS_MISMATCH",
    "LEDGER_V1_REGIME_MISMATCH",
    "LEDGER_V1_FALSIFICATION_MISMATCH",
    "LEDGER_V1_COVERAGE_INCOMPLETE",
    "LEDGER_V1_CONTINUITY_MISMATCH",
    "LEDGER_V1_FOLD_SLICE_MISMATCH",
    "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
})

_CONTINUOUS_PATH_VERSION = "continuous-development-path-v1"
_DEVELOPMENT_EVALUATION_KEYS = frozenset({
    "start_index", "end_index_exclusive", "observation_count",
})
_VALIDATION_PLAN_KEYS = frozenset({
    "profile_id", "profile_hash", "plan_version", "n_bars",
    "development_bars", "final_holdout_bars", "final_holdout_fraction",
    "max_indicator_lookback", "minimum_train_bars", "test_window_bars",
    "minimum_short_fold_bars", "final_warmup_bars", "walk_forward_mode",
    "parameter_selection", "regime_law", "access_policy",
    "validation_plan_hash",
})
# The later sealed plan contract nests six Gate-C scalars and records the
# registered and effective holdout shares separately.
_VALIDATION_PLAN_V3_KEYS = frozenset({
    "plan_version", "profile_id", "battery_version", "profile_hash",
    "release_id", "required_worker_contract", "tenant_id", "workspace_id",
    "run_id", "dsl_schema_version", "confirmed_spec_hash",
    "locked_rule_sha256", "base_costs_sha256", "market_observations_version",
    "canonicalization_policy_version", "snapshot_sha256",
    "exchange_calendar_id", "exchange_calendar_version", "n_bars",
    "continuous_path_version", "plan_anchor_version", "final_access_protocol",
    "registered_final_holdout_fraction", "final_holdout_fraction",
    "final_window", "development_bars", "max_indicator_lookback",
    "minimum_train_bars", "final_warmup_bars", "walk_forward", "regime_law",
    "authorities", "production_capabilities", "integrity_bindings",
    "validation_plan_hash",
})
_V3_WALK_FORWARD_KEYS = frozenset({
    "mode", "parameter_selection", "minimum_train_floor_bars",
    "minimum_train_lookback_multiple", "test_window_bars",
    "minimum_short_fold_bars",
})
_V3_FINAL_WINDOW_KEYS = frozenset({
    "n_bars", "start_index", "end_index", "bars",
    "warmup_start_index", "warmup_bars",
})
# Gate C admits exactly these (profile, plan) contract pairs; a crossed pair
# is never a supported candidate.
_GATE_C_PLAN_CONTRACTS = frozenset({
    ("battery-v2", "validation-plan-v2"),
    ("battery-v3", "validation-plan-v3"),
})
_GATE_C_PARTITION_VERSION = {
    "validation-plan-v2": "validation-partitions-v2",
    "validation-plan-v3": "validation-partitions-v3",
}
_PARTITION_KEYS = frozenset({
    "partition_version", "status", "reason", "n_bars", "development",
    "final_holdout", "folds", "laws",
})
_DEVELOPMENT_PARTITION_KEYS = frozenset({
    "start_index", "end_index", "start", "end", "bars", "input_sha256",
})
_FINAL_PARTITION_KEYS = frozenset({
    "start_index", "end_index", "start", "end", "bars",
    "warmup_start_index", "warmup_bars", "capsule_sha256",
    "evaluation_input_sha256",
})
_FOLD_PARTITION_KEYS = frozenset({
    "fold_id", "train_start_index", "train_end_index", "train_start",
    "train_end", "train_bars", "test_start_index", "test_end_index",
    "test_start", "test_end", "test_bars", "visible_prefix_end_index",
    "visible_prefix_sha256",
})
_PARTITION_LAW_KEYS = frozenset({
    "mode", "continuous_non_overlapping_tests", "prefix_ends_at_test_end",
    "parameter_selection", "short_remainder_policy",
})

_SHA = re.compile(r"sha256:[0-9a-f]{64}")
_RAW_SHA = re.compile(r"[0-9a-f]{64}")
_LEDGER_ID = re.compile(r"ldg-[0-9a-f]{64}")
_EXECUTION_ID = re.compile(r"exec-[0-9a-f]{64}")
_CURRENCY = re.compile(r"[A-Z]{3}")
_ASCII_TOKEN = re.compile(r"[\x21-\x7e]+")

_LEDGER_KEYS = frozenset({
    "ledger_semantics_version", "ledger_id", "entries", "result_hash",
})
_ENTRY_KEYS = frozenset({"artifact_id", "kind", "sha256", "path", "producer"})
_WRAPPER_KEYS = frozenset({"kind", "producer", "payload"})
_REGISTRY_KEYS = frozenset({
    "producers", "financial_semantics", "metric_semantics", "calendars", "snapshots",
})
_REGISTRY_OPTIONAL_KEYS = frozenset({"validation_plans"})
# Trust boundary: callers inject this frozen control-plane registry independently of
# the candidate artifacts.  Candidate-derived anchors would provide no authenticity.
_VALIDATION_PLAN_ANCHOR_KEYS = frozenset({
    "profile_id", "profile_hash", "plan_version", "validation_plan_hash",
    "full_plan_sha256", "spec_hash", "snapshot_sha256",
})
_MARKET_DOCUMENT_KEYS = frozenset({
    "market_observations_version", "snapshot_sha256", "exchange_calendar_id",
    "exchange_calendar_version", "instruments",
})
_MARKET_INSTRUMENT_KEYS = frozenset({"symbol", "currency", "sessions"})
_MARKET_SESSION_V1_KEYS = frozenset({"date", "open", "close"})
_MARKET_SESSION_V2_KEYS = frozenset({
    "date", "open", "high", "low", "close", "volume",
})
_CONTRACT_KEYS = frozenset({
    "contract_version", "ledger_semantics_version", "financial_semantics_version",
    "financial_semantics_sha256", "metric_semantics_version",
    "metric_semantics_sha256", "initial_capital", "return_basis",
    "cash_return_policy", "risk_free_policy", "minimum_acceptable_return_policy",
    "currency_policy", "calendar_binding", "position_sizing_policy", "execution_policy",
})
_RETURN_KEYS = frozenset({"kind", "split_adjusted", "distribution_policy", "source"})
_CASH_KEYS = frozenset({"kind", "annual_rate", "day_count"})
_ONE_KIND_KEYS = frozenset({"kind"})
_CURRENCY_KEYS = frozenset({"base_currency", "fx_policy"})
_CALENDAR_KEYS = frozenset({
    "exchange_calendar_id", "exchange_calendar_version",
    "acquisition_validation_receipt_sha256",
})
_EXECUTION_POLICY_KEYS = frozenset({
    "decision_time", "fill_time", "slippage_model", "terminal_policy",
})
_VALUATION_KEYS = frozenset({
    "valuation_ledger_version", "financial_contract_sha256", "spec_hash",
    "snapshot_sha256", "executions",
})
_EXECUTION_KEYS = frozenset({
    "execution_id", "role", "purpose", "window", "cost_multiplier", "carry_in",
    "carry_in_sha256", "carry_out", "carry_out_sha256", "bars", "fills",
})
_WINDOW_KEYS = frozenset({
    "start_date", "end_date", "start_index", "end_index_exclusive", "observation_count",
})
_CARRY_KEYS = frozenset({"cash", "shares", "position"})
_BAR_KEYS = frozenset({
    "date", "close", "cash", "shares", "position_value", "equity", "position",
    "daily_commission", "daily_slippage", "cash_return",
})
_FILL_KEYS = frozenset({
    "side", "shares", "reference_price", "effective_price", "executed_notional",
    "commission", "slippage_amount", "session",
})
_DISPLAY_METRICS = (
    "start_date", "end_date", "n_bars", "initial_capital",
    "n_return_observations", "total_return", "cagr", "ann_vol", "sharpe",
    "max_drawdown", "n_trades", "total_costs", "exposure", "final_equity",
)
_PURPOSES = frozenset({
    "primary_evaluation", "fold_slice", "cost_stress", "final_holdout",
})
_ROLES = frozenset({"strategy", "benchmark"})
_REGIMES = ("up_low", "up_high", "down_low", "down_high")
_BASE_REQUIRED_KINDS = frozenset({
    "spec", "validation_plan", "partitions", "financial_contract",
    "valuation_ledger", "development_result", "walk_forward", "regime_analysis",
    "final_holdout_result", "final_holdout_execution_audit", "temporal_integrity",
    "sensitivity", "cost_stress", "falsification", "evidence_status", "data_gaps",
    "snapshot_ref",
})


class FinancialSemanticValidationError(ValueError):
    """One closed, product-safe failure with no partial financial projection."""

    def __init__(
        self,
        code: str,
        path: str,
        detail: str,
        execution_id: str | None = None,
    ):
        if code not in _CODES:
            raise AssertionError(f"unknown validator error code: {code}")
        self.code = code
        self.path = path
        self.execution_id = execution_id
        self.detail = detail
        super().__init__(f"{code} at {path}: {detail}")


def _fail(
    code: str, path: str, detail: str, execution_id: str | None = None,
) -> None:
    raise FinancialSemanticValidationError(code, path, detail, execution_id)


def canonical_json_bytes_v1(value: Any) -> bytes:
    """Frozen Gate-B canonical JSON representation."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FinancialSemanticValidationError(
            "LEDGER_V1_NONFINITE_NUMBER", "$", "value is not finite canonical JSON",
        ) from exc


def sha256_json_v1(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes_v1(value)).hexdigest()


def _object(value: Any, keys: frozenset[str], path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be an object")
    actual = frozenset(value)
    if actual != keys:
        _fail(
            "LEDGER_V1_SCHEMA_INVALID",
            path,
            f"closed schema mismatch (missing={sorted(keys - actual)}, extra={sorted(actual - keys)})",
        )
    return value


def _array(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be an array")
    if nonempty and not value:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must not be empty")
    return value


def _number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be a JSON number")
    result = float(value)
    if not math.isfinite(result):
        _fail("LEDGER_V1_NONFINITE_NUMBER", path, "must be finite")
    return result


def _integer(value: Any, path: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be an integer")
    if minimum is not None and value < minimum:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, f"must be at least {minimum}")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be a non-empty string")
    return value


def _iso_date(value: Any, path: str) -> str:
    value = _text(value, path)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be an ISO exchange-session date")
    if parsed.isoformat() != value or not value.isascii():
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be canonical ASCII YYYY-MM-DD")
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be sha256: plus 64 lowercase hex")
    return value


def _raw_sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _RAW_SHA.fullmatch(value) is None:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "must be 64 lowercase hex characters")
    return value


def _enum(value: Any, allowed: Sequence[str] | frozenset[str], path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        _fail("LEDGER_V1_SCHEMA_INVALID", path, f"must be one of {sorted(allowed)}")
    return value


def _money(actual: float, expected: float, path: str, execution_id: str | None = None) -> None:
    if abs(actual - expected) > MONEY_ABSOLUTE_TOLERANCE:
        _fail(
            "LEDGER_V1_ACCOUNTING_MISMATCH", path,
            f"sealed {actual!r} != reconstructed {expected!r}", execution_id,
        )


def _quantity(actual: float, expected: float, path: str, execution_id: str | None = None) -> None:
    if abs(actual - expected) > QUANTITY_ABSOLUTE_TOLERANCE:
        _fail(
            "LEDGER_V1_ACCOUNTING_MISMATCH", path,
            f"sealed {actual!r} != reconstructed {expected!r}", execution_id,
        )


def _metric(
    actual: float, expected: float, path: str, execution_id: str | None = None,
    *, code: str = "LEDGER_V1_METRIC_MISMATCH",
) -> None:
    if not math.isclose(
        actual, expected,
        rel_tol=METRIC_RELATIVE_TOLERANCE,
        abs_tol=METRIC_ABSOLUTE_TOLERANCE,
    ):
        _fail(code, path, f"sealed {actual!r} != reconstructed {expected!r}", execution_id)


def _validate_registry(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.registry", "must be an object")
    actual = frozenset(value)
    if (
        not _REGISTRY_KEYS <= actual
        or not (actual - _REGISTRY_KEYS) <= _REGISTRY_OPTIONAL_KEYS
    ):
        _fail(
            "LEDGER_V1_SCHEMA_INVALID",
            "$.registry",
            "registry schema is missing required keys or contains unsupported keys",
        )
    registry = value
    producers = _array(registry["producers"], "$.registry.producers", nonempty=True)
    if any(not isinstance(item, str) or not item for item in producers):
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", "$.registry.producers", "contains an invalid producer")
    if producers != sorted(producers) or len(producers) != len(set(producers)):
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", "$.registry.producers", "must be sorted and unique")
    for name in ("financial_semantics", "metric_semantics", "calendars", "snapshots"):
        if not isinstance(registry[name], Mapping):
            _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"$.registry.{name}", "must be an object")
    for name in ("financial_semantics", "metric_semantics"):
        for version, digest in registry[name].items():
            if not isinstance(version, str) or not _ASCII_TOKEN.fullmatch(version):
                _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"$.registry.{name}", "invalid version")
            _sha(digest, f"$.registry.{name}.{version}")
    plan_registry = registry.get("validation_plans")
    if plan_registry is not None:
        if not isinstance(plan_registry, Mapping):
            _fail(
                "LEDGER_V1_UNSUPPORTED_CONTRACT",
                "$.registry.validation_plans",
                "must be an object",
            )
        for plan_hash, raw_anchor in plan_registry.items():
            path = f"$.registry.validation_plans.{plan_hash}"
            _sha(plan_hash, "$.registry.validation_plans")
            anchor = _object(raw_anchor, _VALIDATION_PLAN_ANCHOR_KEYS, path)
            if _sha(anchor["validation_plan_hash"], f"{path}.validation_plan_hash") != plan_hash:
                _fail(
                    "LEDGER_V1_BINDING_MISMATCH",
                    f"{path}.validation_plan_hash",
                    "validation-plan registry key mismatch",
                )
            _text(anchor["profile_id"], f"{path}.profile_id")
            _sha(anchor["profile_hash"], f"{path}.profile_hash")
            _text(anchor["plan_version"], f"{path}.plan_version")
            _sha(anchor["full_plan_sha256"], f"{path}.full_plan_sha256")
            _sha(anchor["spec_hash"], f"{path}.spec_hash")
            _sha(anchor["snapshot_sha256"], f"{path}.snapshot_sha256")
    return registry


def _validate_market_document(value: Any, snapshot_key: str) -> dict[str, Any]:
    path = f"$.registry.snapshots.{snapshot_key}"
    doc = _object(value, _MARKET_DOCUMENT_KEYS, path)
    version = doc["market_observations_version"]
    if version not in {"market-observations-v1", "market-observations-v2"}:
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"{path}.market_observations_version", "unsupported market document")
    if _sha(doc["snapshot_sha256"], f"{path}.snapshot_sha256") != snapshot_key:
        _fail("LEDGER_V1_BINDING_MISMATCH", f"{path}.snapshot_sha256", "snapshot registry key mismatch")
    calendar_id = _text(doc["exchange_calendar_id"], f"{path}.exchange_calendar_id")
    calendar_version = _text(doc["exchange_calendar_version"], f"{path}.exchange_calendar_version")
    instruments = _array(doc["instruments"], f"{path}.instruments", nonempty=True)
    parsed: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for index, raw in enumerate(instruments):
        item_path = f"{path}.instruments[{index}]"
        item = _object(raw, _MARKET_INSTRUMENT_KEYS, item_path)
        symbol = _text(item["symbol"], f"{item_path}.symbol")
        currency = _text(item["currency"], f"{item_path}.currency")
        if _CURRENCY.fullmatch(currency) is None:
            _fail("LEDGER_V1_CURRENCY_MISMATCH", f"{item_path}.currency", "must be three uppercase letters")
        key = (symbol, currency)
        if key in parsed:
            _fail("LEDGER_V1_SCHEMA_INVALID", item_path, "duplicate instrument")
        sessions_raw = _array(item["sessions"], f"{item_path}.sessions", nonempty=True)
        sessions: list[str] = []
        prices: dict[str, tuple[float, float]] = {}
        records: list[dict[str, Any]] = []
        session_keys = (
            _MARKET_SESSION_V2_KEYS
            if version == "market-observations-v2"
            else _MARKET_SESSION_V1_KEYS
        )
        for session_index, raw_session in enumerate(sessions_raw):
            session_path = f"{item_path}.sessions[{session_index}]"
            session = _object(raw_session, session_keys, session_path)
            session_date = _iso_date(session["date"], f"{session_path}.date")
            opening = _number(session["open"], f"{session_path}.open")
            close = _number(session["close"], f"{session_path}.close")
            if opening <= 0 or close <= 0:
                _fail("LEDGER_V1_SCHEMA_INVALID", session_path, "prices must be positive")
            if version == "market-observations-v2":
                high = _number(session["high"], f"{session_path}.high")
                low = _number(session["low"], f"{session_path}.low")
                volume = _number(session["volume"], f"{session_path}.volume")
                if (
                    min(high, low) <= 0
                    or high < max(opening, close)
                    or low > min(opening, close)
                    or volume < 0
                ):
                    _fail(
                        "LEDGER_V1_SCHEMA_INVALID",
                        session_path,
                        "OHLCV values are internally inconsistent",
                    )
            sessions.append(session_date)
            prices[session_date] = (opening, close)
            # Preserve reviewed JSON numeric representations for exact digest replay.
            records.append(dict(session))
        if sessions != sorted(sessions) or len(sessions) != len(set(sessions)):
            _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{item_path}.sessions", "dates must be increasing and unique")
        parsed[key] = {
            "dates": sessions,
            "prices": prices,
            "records": records,
            "market_observations_version": version,
        }
        order.append(key)
    if order != sorted(order):
        _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.instruments", "must be sorted by symbol and currency")
    return {
        "calendar_id": calendar_id,
        "calendar_version": calendar_version,
        "snapshot_sha256": snapshot_key,
        "market_observations_version": version,
        "instruments": parsed,
    }


def _required_kinds(spec: Mapping[str, Any]) -> frozenset[str]:
    version = spec.get("dsl_version")
    if version not in {"1.0", "1.1", "1.2"}:
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", "$.artifacts.spec.payload.spec.dsl_version", "unsupported DSL version")
    return _BASE_REQUIRED_KINDS | ({"data_provenance"} if version in {"1.1", "1.2"} else set())


def _validate_ledger_and_wrappers(
    manifest: Mapping[str, Any], ledger_value: Any, artifacts_value: Any,
    registry: Mapping[str, Any],
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    ledger = _object(ledger_value, _LEDGER_KEYS, "$.ledger")
    if ledger["ledger_semantics_version"] != "ledger-v1":
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.ledger.ledger_semantics_version", "must equal ledger-v1")
    ledger_id = _text(ledger["ledger_id"], "$.ledger.ledger_id")
    if _LEDGER_ID.fullmatch(ledger_id) is None:
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.ledger.ledger_id", "malformed ledger ID")
    result_hash = _sha(ledger["result_hash"], "$.ledger.result_hash")
    entries_raw = _array(ledger["entries"], "$.ledger.entries", nonempty=True)
    entries: list[Mapping[str, Any]] = []
    entry_order: list[tuple[str, str]] = []
    kinds: set[str] = set()
    paths: set[str] = set()
    artifact_ids: set[str] = set()
    for index, raw in enumerate(entries_raw):
        path = f"$.ledger.entries[{index}]"
        entry = _object(raw, _ENTRY_KEYS, path)
        kind = _text(entry["kind"], f"{path}.kind")
        digest = _raw_sha(entry["sha256"], f"{path}.sha256")
        artifact_id = _text(entry["artifact_id"], f"{path}.artifact_id")
        entry_path = _text(entry["path"], f"{path}.path")
        producer = _text(entry["producer"], f"{path}.producer")
        if artifact_id != f"{kind}-{digest[:12]}":
            _fail("LEDGER_V1_BINDING_MISMATCH", f"{path}.artifact_id", "artifact identity mismatch")
        if entry_path != f"artifact_{kind}.json" or "/" in entry_path or "\\" in entry_path:
            _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.path", "unsafe or noncanonical artifact path")
        if producer not in registry["producers"]:
            _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"{path}.producer", "producer is not reviewed")
        if kind in kinds or entry_path in paths or artifact_id in artifact_ids:
            _fail("LEDGER_V1_SCHEMA_INVALID", path, "duplicate kind, path, or artifact ID")
        kinds.add(kind)
        paths.add(entry_path)
        artifact_ids.add(artifact_id)
        entry_order.append((kind, entry_path))
        entries.append(entry)
    if entry_order != sorted(entry_order):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.ledger.entries", "entries are not canonically ordered")

    if not isinstance(artifacts_value, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts", "must be a kind-to-wrapper object")
    if set(artifacts_value) != kinds:
        _fail("LEDGER_V1_COVERAGE_INCOMPLETE", "$.artifacts", "wrapper set does not equal ledger entries")
    payloads: dict[str, Any] = {}
    by_kind = {entry["kind"]: entry for entry in entries}
    for kind in sorted(kinds):
        path = f"$.artifacts.{kind}"
        wrapper = _object(artifacts_value[kind], _WRAPPER_KEYS, path)
        entry = by_kind[kind]
        if wrapper["kind"] != kind or wrapper["producer"] != entry["producer"]:
            _fail("LEDGER_V1_BINDING_MISMATCH", path, "wrapper identity does not match its entry")
        if not isinstance(wrapper["payload"], Mapping):
            _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.payload", "artifact payload must be an object")
        actual_sha = hashlib.sha256(canonical_json_bytes_v1(wrapper)).hexdigest()
        if actual_sha != entry["sha256"]:
            _fail("LEDGER_V1_BINDING_MISMATCH", path, "artifact bytes do not match entry hash")
        payloads[kind] = wrapper["payload"]

    binding = {"ledger_semantics_version": "ledger-v1", "entries": entries}
    expected_result = sha256_json_v1(binding)
    if result_hash != expected_result:
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.ledger.result_hash", "full-entry result binding mismatch")
    if ledger_id != "ldg-" + expected_result.removeprefix("sha256:"):
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.ledger.ledger_id", "ledger ID mismatch")
    if not isinstance(manifest, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.manifest", "must be an object")
    if manifest.get("result_hash") != result_hash:
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.manifest.result_hash", "manifest result binding mismatch")

    spec_bundle = payloads.get("spec")
    if not isinstance(spec_bundle, Mapping) or set(spec_bundle) != {"spec", "spec_hash"} or not isinstance(spec_bundle.get("spec"), Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.spec.payload", "malformed sealed spec bundle")
    spec_hash = sha256_json_v1(spec_bundle["spec"])
    if spec_bundle["spec_hash"] != spec_hash or manifest.get("spec_hash") != spec_hash:
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.artifacts.spec.payload.spec_hash", "spec binding mismatch")
    required = _required_kinds(spec_bundle["spec"])
    if kinds != required:
        _fail(
            "LEDGER_V1_COVERAGE_INCOMPLETE", "$.ledger.entries",
            f"required artifact kinds mismatch (missing={sorted(required-kinds)}, extra={sorted(kinds-required)})",
        )
    return ledger, payloads


def _validate_contract(
    value: Any, registry: Mapping[str, Any], snapshot_doc: Mapping[str, Any],
) -> Mapping[str, Any]:
    path = "$.artifacts.financial_contract.payload"
    contract = _object(value, _CONTRACT_KEYS, path)
    fixed = {
        "contract_version": "financial-contract-v1",
        "ledger_semantics_version": "ledger-v1",
        "financial_semantics_version": "financial-semantics-v2",
    }
    for key, expected in fixed.items():
        if contract[key] != expected:
            _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.{key}", f"must equal {expected}")
    financial_version = contract["financial_semantics_version"]
    financial_hash = _sha(contract["financial_semantics_sha256"], f"{path}.financial_semantics_sha256")
    if registry["financial_semantics"].get(financial_version) != financial_hash:
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"{path}.financial_semantics_sha256", "unreviewed financial semantics")
    metric_version = _text(contract["metric_semantics_version"], f"{path}.metric_semantics_version")
    if not metric_version.isascii():
        _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.metric_semantics_version", "must be ASCII")
    metric_hash = _sha(contract["metric_semantics_sha256"], f"{path}.metric_semantics_sha256")
    if registry["metric_semantics"].get(metric_version) != metric_hash:
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"{path}.metric_semantics_sha256", "unreviewed metric semantics")
    initial = _number(contract["initial_capital"], f"{path}.initial_capital")
    if initial <= 0:
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.initial_capital", "must be positive")
    basis = _object(contract["return_basis"], _RETURN_KEYS, f"{path}.return_basis")
    if basis != {
        "kind": "price_return", "split_adjusted": True,
        "distribution_policy": "excluded", "source": "dataset_manifest",
    }:
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.return_basis", "unsupported return basis")
    cash = _object(contract["cash_return_policy"], _CASH_KEYS, f"{path}.cash_return_policy")
    if cash.get("kind") != "zero_yield" or cash.get("day_count") != "252_sessions" or _number(cash.get("annual_rate"), f"{path}.cash_return_policy.annual_rate") != 0.0:
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.cash_return_policy", "unsupported cash return policy")
    if _object(contract["risk_free_policy"], _ONE_KIND_KEYS, f"{path}.risk_free_policy").get("kind") != "same_as_cash_policy":
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.risk_free_policy", "unsupported risk-free policy")
    if _object(contract["minimum_acceptable_return_policy"], _ONE_KIND_KEYS, f"{path}.minimum_acceptable_return_policy").get("kind") != "same_as_risk_free_policy":
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.minimum_acceptable_return_policy", "unsupported MAR policy")
    currency = _object(contract["currency_policy"], _CURRENCY_KEYS, f"{path}.currency_policy")
    base_currency = _text(currency["base_currency"], f"{path}.currency_policy.base_currency")
    if _CURRENCY.fullmatch(base_currency) is None or currency["fx_policy"] != "single_currency_only":
        _fail("LEDGER_V1_CURRENCY_MISMATCH", f"{path}.currency_policy", "unsupported currency policy")
    calendar = _object(contract["calendar_binding"], _CALENDAR_KEYS, f"{path}.calendar_binding")
    receipt_hash = _sha(calendar["acquisition_validation_receipt_sha256"], f"{path}.calendar_binding.acquisition_validation_receipt_sha256")
    calendar_key = f"{calendar['exchange_calendar_id']}|{calendar['exchange_calendar_version']}|{receipt_hash}"
    calendar_value = registry["calendars"].get(calendar_key)
    if not isinstance(calendar_value, Mapping) or set(calendar_value) != {"sessions"}:
        _fail("LEDGER_V1_UNSUPPORTED_CONTRACT", f"{path}.calendar_binding", "calendar binding is not reviewed")
    calendar_sessions = [_iso_date(item, f"$.registry.calendars.{calendar_key}.sessions") for item in _array(calendar_value["sessions"], f"$.registry.calendars.{calendar_key}.sessions", nonempty=True)]
    if calendar_sessions != sorted(calendar_sessions) or len(calendar_sessions) != len(set(calendar_sessions)):
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"$.registry.calendars.{calendar_key}.sessions", "calendar sessions must be sorted and unique")
    if snapshot_doc["calendar_id"] != calendar["exchange_calendar_id"] or snapshot_doc["calendar_version"] != calendar["exchange_calendar_version"]:
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.calendar_binding", "snapshot calendar mismatch")
    for instrument, market in snapshot_doc["instruments"].items():
        if market["dates"] != calendar_sessions:
            _fail(
                "LEDGER_V1_DATE_SEQUENCE_INVALID",
                "$.registry.snapshots",
                f"sealed sessions for {instrument!r} do not exactly equal the reviewed calendar",
            )
    sizing = _object(contract["position_sizing_policy"], _ONE_KIND_KEYS, f"{path}.position_sizing_policy")
    if sizing["kind"] != "full_notional_fractional_shares":
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.position_sizing_policy", "unsupported sizing policy")
    execution_policy = _object(contract["execution_policy"], _EXECUTION_POLICY_KEYS, f"{path}.execution_policy")
    if execution_policy != {
        "decision_time": "close_t", "fill_time": "next_valid_session_open",
        "slippage_model": "adverse_effective_fill_price",
        "terminal_policy": "mark_to_market_no_forced_liquidation",
    }:
        _fail("LEDGER_V1_POLICY_MISMATCH", f"{path}.execution_policy", "unsupported execution policy")
    return contract


def _snapshot_binding(manifest: Mapping[str, Any], payloads: Mapping[str, Any]) -> str:
    snapshot = payloads["snapshot_ref"]
    if not isinstance(snapshot, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.snapshot_ref.payload", "must be an object")
    raw = snapshot.get("sha256")
    if not isinstance(raw, str):
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.artifacts.snapshot_ref.payload.sha256", "missing snapshot digest")
    normalized = raw if raw.startswith("sha256:") else "sha256:" + raw
    _sha(normalized, "$.artifacts.snapshot_ref.payload.sha256")
    manifest_raw = manifest.get("snapshot_sha256")
    manifest_normalized = manifest_raw if isinstance(manifest_raw, str) and manifest_raw.startswith("sha256:") else "sha256:" + str(manifest_raw)
    if manifest_normalized != normalized:
        _fail("LEDGER_V1_BINDING_MISMATCH", "$.manifest.snapshot_sha256", "snapshot binding mismatch")
    return normalized


def _validate_carry(value: Any, digest: Any, path: str, execution_id: str) -> dict[str, float | int]:
    carry = _object(value, _CARRY_KEYS, path)
    cash = _number(carry["cash"], f"{path}.cash")
    shares = _number(carry["shares"], f"{path}.shares")
    position = _integer(carry["position"], f"{path}.position")
    if cash < 0 or shares < 0 or position not in (0, 1):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "carry values are outside the long/flat contract", execution_id)
    if (shares > 0) != (position == 1):
        _fail("LEDGER_V1_ACCOUNTING_MISMATCH", path, "carry position contradicts shares", execution_id)
    digest = _sha(digest, path + "_sha256")
    if digest != sha256_json_v1(carry):
        _fail("LEDGER_V1_CARRY_HASH_MISMATCH", path + "_sha256", "carry hash mismatch", execution_id)
    return {"cash": cash, "shares": shares, "position": position}


def _sample_std(values: Sequence[float]) -> float:
    return statistics.stdev(values) if len(values) >= 2 else 0.0


def _reconstruct_metrics(
    bars: Sequence[Mapping[str, Any]], fills: Sequence[Mapping[str, Any]], initial_capital: float,
) -> dict[str, Any]:
    equities = [float(bar["equity"]) for bar in bars]
    metric_path = [initial_capital, *equities]
    returns = [current / previous - 1.0 for previous, current in zip(metric_path, metric_path[1:])]
    n = len(bars)
    total_return = equities[-1] / initial_capital - 1.0
    std = _sample_std(returns)
    peak = metric_path[0]
    max_drawdown = 0.0
    for value in metric_path:
        peak = max(peak, value)
        max_drawdown = min(max_drawdown, value / peak - 1.0)
    return {
        "start_date": bars[0]["date"],
        "end_date": bars[-1]["date"],
        "n_bars": n,
        "initial_capital": initial_capital,
        "n_return_observations": len(returns),
        "total_return": total_return,
        "cagr": (equities[-1] / initial_capital) ** (ANNUALIZATION_SESSIONS / n) - 1.0,
        "ann_vol": std * math.sqrt(ANNUALIZATION_SESSIONS),
        "sharpe": statistics.fmean(returns) / std * math.sqrt(ANNUALIZATION_SESSIONS) if len(returns) >= 2 and std > 0 else 0.0,
        "max_drawdown": max_drawdown,
        "n_trades": len(fills),
        "total_costs": math.fsum(float(fill["commission"]) + float(fill["slippage_amount"]) for fill in fills),
        "exposure": statistics.fmean(float(bar["position"]) for bar in bars),
        "final_equity": equities[-1],
    }


def _validate_execution(
    raw: Any,
    valuation: Mapping[str, Any],
    contract: Mapping[str, Any],
    spec: Mapping[str, Any],
    market_document: Mapping[str, Any],
    calendar_sessions: Sequence[str],
    path: str,
    gate_c_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    execution = _object(raw, _EXECUTION_KEYS, path)
    execution_id = _text(execution["execution_id"], f"{path}.execution_id")
    if _EXECUTION_ID.fullmatch(execution_id) is None:
        _fail("LEDGER_V1_EXECUTION_ID_MISMATCH", f"{path}.execution_id", "malformed execution ID")
    role = _enum(execution["role"], _ROLES, f"{path}.role")
    purpose = _enum(execution["purpose"], _PURPOSES, f"{path}.purpose")
    multiplier = _number(execution["cost_multiplier"], f"{path}.cost_multiplier")
    if multiplier < 0:
        _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.cost_multiplier", "must be non-negative", execution_id)
    window = _object(execution["window"], _WINDOW_KEYS, f"{path}.window")
    start_date = _iso_date(window["start_date"], f"{path}.window.start_date")
    end_date = _iso_date(window["end_date"], f"{path}.window.end_date")
    start_index = _integer(window["start_index"], f"{path}.window.start_index", minimum=0)
    end_index = _integer(window["end_index_exclusive"], f"{path}.window.end_index_exclusive", minimum=1)
    count = _integer(window["observation_count"], f"{path}.window.observation_count", minimum=1)
    if end_index <= start_index or count != end_index - start_index:
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.window", "index/count law mismatch", execution_id)

    universe_symbol = spec.get("universe", {}).get("symbol") if isinstance(spec.get("universe"), Mapping) else None
    benchmark_value = spec.get("benchmark", {}).get("symbol") if isinstance(spec.get("benchmark"), Mapping) else None
    benchmark_symbol = universe_symbol if benchmark_value == "same_as_universe" else benchmark_value
    symbol = universe_symbol if role == "strategy" else benchmark_symbol
    currency = contract["currency_policy"]["base_currency"]
    market = market_document["instruments"].get((symbol, currency))
    if market is None:
        _fail("LEDGER_V1_CURRENCY_MISMATCH", path, "role has no same-currency sealed market series", execution_id)
    dates = market["dates"]
    if end_index > len(dates):
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.window", "window escapes snapshot", execution_id)
    expected_dates = dates[start_index:end_index]
    if expected_dates[0] != start_date or expected_dates[-1] != end_date or any(item not in calendar_sessions for item in expected_dates):
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.window", "date/calendar binding mismatch", execution_id)

    identity = {
        "spec_hash": valuation["spec_hash"],
        "snapshot_sha256": valuation["snapshot_sha256"],
        "role": role,
        "purpose": purpose,
        "window": window,
        "cost_multiplier": execution["cost_multiplier"],
        "carry_in_sha256": execution["carry_in_sha256"],
    }
    expected_id = "exec-" + hashlib.sha256(canonical_json_bytes_v1(identity)).hexdigest()
    if execution_id != expected_id:
        _fail("LEDGER_V1_EXECUTION_ID_MISMATCH", f"{path}.execution_id", "canonical identity mismatch", execution_id)
    carry_in = _validate_carry(execution["carry_in"], execution["carry_in_sha256"], f"{path}.carry_in", execution_id)
    carry_out = _validate_carry(execution["carry_out"], execution["carry_out_sha256"], f"{path}.carry_out", execution_id)

    fills_raw = _array(execution["fills"], f"{path}.fills")
    fills_by_date: dict[str, list[dict[str, Any]]] = {}
    parsed_fills: list[dict[str, Any]] = []
    last_fill_index = -1
    costs = spec.get("costs")
    if not isinstance(costs, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.spec.payload.spec.costs", "missing cost law")
    commission_bps = _number(
        costs.get("commission_bps"),
        "$.artifacts.spec.payload.spec.costs.commission_bps",
    )
    slippage_bps = _number(
        costs.get("slippage_bps"),
        "$.artifacts.spec.payload.spec.costs.slippage_bps",
    )
    if commission_bps < 0 or slippage_bps < 0:
        _fail(
            "LEDGER_V1_POLICY_MISMATCH",
            "$.artifacts.spec.payload.spec.costs",
            "commission_bps and slippage_bps must be non-negative",
            execution_id,
        )
    commission_rate = commission_bps * multiplier / 1e4
    slippage_rate = slippage_bps * multiplier / 1e4
    for fill_index, fill_raw in enumerate(fills_raw):
        fill_path = f"{path}.fills[{fill_index}]"
        fill = _object(fill_raw, _FILL_KEYS, fill_path)
        session = _iso_date(fill["session"], f"{fill_path}.session")
        if session not in expected_dates:
            _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{fill_path}.session", "fill outside window", execution_id)
        session_index = expected_dates.index(session)
        if session_index < last_fill_index:
            _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.fills", "fill session order changed", execution_id)
        last_fill_index = session_index
        side = _enum(fill["side"], ("buy", "sell"), f"{fill_path}.side")
        shares = _number(fill["shares"], f"{fill_path}.shares")
        reference = _number(fill["reference_price"], f"{fill_path}.reference_price")
        effective = _number(fill["effective_price"], f"{fill_path}.effective_price")
        notional = _number(fill["executed_notional"], f"{fill_path}.executed_notional")
        commission = _number(fill["commission"], f"{fill_path}.commission")
        slippage = _number(fill["slippage_amount"], f"{fill_path}.slippage_amount")
        if min(shares, reference, effective, notional) <= 0 or min(commission, slippage) < 0:
            _fail("LEDGER_V1_FILL_MISMATCH", fill_path, "invalid fill scalar", execution_id)
        opening = market["prices"][session][0]
        if abs(reference - opening) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", f"{fill_path}.reference_price", "not the sealed session open", execution_id)
        expected_effective = reference * (1 + slippage_rate if side == "buy" else 1 - slippage_rate)
        if abs(effective - expected_effective) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", f"{fill_path}.effective_price", "adverse-fill price mismatch", execution_id)
        expected_notional = shares * effective
        expected_slippage = shares * abs(effective - reference)
        if abs(notional - expected_notional) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", f"{fill_path}.executed_notional", "notional mismatch", execution_id)
        if abs(commission - expected_notional * commission_rate) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", f"{fill_path}.commission", "commission mismatch", execution_id)
        if abs(slippage - expected_slippage) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", f"{fill_path}.slippage_amount", "slippage mismatch", execution_id)
        parsed = {
            "side": side, "shares": shares, "reference_price": reference,
            "effective_price": effective, "executed_notional": notional,
            "commission": commission, "slippage_amount": slippage, "session": session,
        }
        parsed_fills.append(parsed)
        fills_by_date.setdefault(session, []).append(parsed)

    cash = float(carry_in["cash"])
    shares = float(carry_in["shares"])
    position = int(carry_in["position"])
    bars_raw = _array(execution["bars"], f"{path}.bars", nonempty=True)
    if len(bars_raw) != count:
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.bars", "bar count does not match window", execution_id)
    parsed_bars: list[dict[str, Any]] = []
    actual_dates: list[str] = []
    for bar_index, bar_raw in enumerate(bars_raw):
        bar_path = f"{path}.bars[{bar_index}]"
        bar = _object(bar_raw, _BAR_KEYS, bar_path)
        session = _iso_date(bar["date"], f"{bar_path}.date")
        actual_dates.append(session)
        close = _number(bar["close"], f"{bar_path}.close")
        if abs(close - market["prices"].get(session, (math.nan, math.nan))[1]) > MONEY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_ACCOUNTING_MISMATCH", f"{bar_path}.close", "close does not match sealed market data", execution_id)
        cash_return = _number(bar["cash_return"], f"{bar_path}.cash_return")
        if cash_return != 0.0:
            _fail("LEDGER_V1_POLICY_MISMATCH", f"{bar_path}.cash_return", "zero-yield policy violated", execution_id)
        cash += cash_return
        session_fills = fills_by_date.get(session, [])
        expected_commission = math.fsum(fill["commission"] for fill in session_fills)
        expected_slippage = math.fsum(fill["slippage_amount"] for fill in session_fills)
        for fill in session_fills:
            # Canonical replay law: every sealed value is checked against an
            # independent recomputation from the trusted session price, the
            # sealed cost rates and the current canonical account state; the
            # state that carries into the next session is then advanced from
            # those recomputed values only.  A residual that is merely inside
            # tolerance is proof of nothing beyond this fill, so it is never
            # allowed to accumulate into later expectations.
            if fill["side"] == "buy":
                if position != 0:
                    _fail("LEDGER_V1_FILL_MISMATCH", bar_path, "buy attempts to pyramid long/flat account", execution_id)
                expected_shares = cash / (fill["effective_price"] * (1.0 + commission_rate))
                if abs(fill["shares"] - expected_shares) > QUANTITY_ABSOLUTE_TOLERANCE:
                    _fail(
                        "LEDGER_V1_FILL_MISMATCH", f"{bar_path}.shares",
                        "buy quantity is not the exact full-notional fractional size",
                        execution_id,
                    )
                # The reported residual is proved against the frozen
                # full-notional law before it is discarded.
                if abs(cash - fill["executed_notional"] - fill["commission"]) \
                        > MONEY_ABSOLUTE_TOLERANCE:
                    _fail(
                        "LEDGER_V1_FILL_MISMATCH", bar_path,
                        "buy does not implement full-notional fractional sizing",
                        execution_id,
                    )
                cash = 0.0
                shares += expected_shares
                position = 1
            else:
                if position != 1 or abs(fill["shares"] - shares) > QUANTITY_ABSOLUTE_TOLERANCE:
                    _fail("LEDGER_V1_FILL_MISMATCH", bar_path, "sell does not liquidate current holding", execution_id)
                expected_notional = shares * fill["effective_price"]
                expected_commission = expected_notional * commission_rate
                if abs(fill["executed_notional"] - expected_notional) \
                        > MONEY_ABSOLUTE_TOLERANCE \
                        or abs(fill["commission"] - expected_commission) \
                        > MONEY_ABSOLUTE_TOLERANCE:
                    _fail(
                        "LEDGER_V1_FILL_MISMATCH", bar_path,
                        "sell proceeds do not match the independently "
                        "recomputed liquidation",
                        execution_id,
                    )
                cash = (cash + expected_notional) - expected_commission
                shares = 0.0
                position = 0
        if cash < -MONEY_ABSOLUTE_TOLERANCE or shares < -QUANTITY_ABSOLUTE_TOLERANCE:
            _fail("LEDGER_V1_FILL_MISMATCH", bar_path, "cash or holdings became negative", execution_id)
        sealed_cash = _number(bar["cash"], f"{bar_path}.cash")
        sealed_shares = _number(bar["shares"], f"{bar_path}.shares")
        sealed_position = _integer(bar["position"], f"{bar_path}.position")
        position_value = _number(bar["position_value"], f"{bar_path}.position_value")
        equity = _number(bar["equity"], f"{bar_path}.equity")
        daily_commission = _number(bar["daily_commission"], f"{bar_path}.daily_commission")
        daily_slippage = _number(bar["daily_slippage"], f"{bar_path}.daily_slippage")
        for name, value in (
            ("cash", sealed_cash), ("shares", sealed_shares),
            ("position_value", position_value), ("equity", equity),
            ("daily_commission", daily_commission), ("daily_slippage", daily_slippage),
        ):
            if value < 0:
                _fail("LEDGER_V1_SCHEMA_INVALID", f"{bar_path}.{name}", "must be non-negative", execution_id)
        if close <= 0 or equity <= 0:
            _fail("LEDGER_V1_SCHEMA_INVALID", bar_path, "close and equity must be positive", execution_id)
        _money(sealed_cash, cash, f"{bar_path}.cash", execution_id)
        _quantity(sealed_shares, shares, f"{bar_path}.shares", execution_id)
        if sealed_position != position or sealed_position != (1 if sealed_shares > 0 else 0):
            _fail("LEDGER_V1_ACCOUNTING_MISMATCH", f"{bar_path}.position", "position mismatch", execution_id)
        _money(position_value, shares * close, f"{bar_path}.position_value", execution_id)
        _money(equity, cash + shares * close, f"{bar_path}.equity", execution_id)
        _money(daily_commission, expected_commission, f"{bar_path}.daily_commission", execution_id)
        _money(daily_slippage, expected_slippage, f"{bar_path}.daily_slippage", execution_id)
        parsed_bars.append({
            "date": session, "close": close, "cash": sealed_cash,
            "shares": sealed_shares, "position_value": position_value, "equity": equity,
            "position": sealed_position, "daily_commission": daily_commission,
            "daily_slippage": daily_slippage, "cash_return": cash_return,
        })
    if actual_dates != expected_dates or len(actual_dates) != len(set(actual_dates)):
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", f"{path}.bars", "dates do not exactly equal the snapshot window", execution_id)
    _money(float(carry_out["cash"]), cash, f"{path}.carry_out.cash", execution_id)
    _quantity(float(carry_out["shares"]), shares, f"{path}.carry_out.shares", execution_id)
    if carry_out["position"] != position:
        _fail("LEDGER_V1_CARRY_HASH_MISMATCH", f"{path}.carry_out.position", "carry-out mismatch", execution_id)
    initial_capital = float(contract["initial_capital"])
    metric_baseline = initial_capital
    if gate_c_context is not None and purpose == "fold_slice":
        if start_index == gate_c_context["start_index"]:
            metric_baseline = initial_capital
        else:
            if start_index <= 0:
                _fail(
                    "LEDGER_V1_CONTINUITY_MISMATCH",
                    f"{path}.window.start_index",
                    "a carried fold requires one reviewed prior session",
                    execution_id,
                )
            previous_session = dates[start_index - 1]
            previous_close = market["prices"][previous_session][1]
            metric_baseline = (
                float(carry_in["cash"])
                + float(carry_in["shares"]) * float(previous_close)
            )
            if not math.isfinite(metric_baseline) or metric_baseline <= 0:
                _fail(
                    "LEDGER_V1_CONTINUITY_MISMATCH",
                    f"{path}.carry_in",
                    "the prior-close fold metric baseline must be finite and positive",
                    execution_id,
                )
    try:
        metrics = _reconstruct_metrics(parsed_bars, parsed_fills, metric_baseline)
    except (OverflowError, ValueError, ZeroDivisionError) as exc:
        raise FinancialSemanticValidationError(
            "LEDGER_V1_NONFINITE_NUMBER", path,
            "metric reconstruction produced invalid arithmetic", execution_id,
        ) from exc
    if any(
        isinstance(value, float) and not math.isfinite(value)
        for value in metrics.values()
    ):
        _fail(
            "LEDGER_V1_NONFINITE_NUMBER", path,
            "metric reconstruction produced a non-finite value", execution_id,
        )
    return {
        "execution_id": execution_id, "role": role, "purpose": purpose,
        "window": dict(window), "cost_multiplier": multiplier,
        "bars": parsed_bars, "fills": parsed_fills,
        "metrics": metrics,
        "metric_baseline": metric_baseline,
        "carry_in": carry_in,
        "carry_in_raw": dict(execution["carry_in"]),
        "carry_in_sha256": execution["carry_in_sha256"],
        "carry_out": carry_out,
        "carry_out_raw": dict(execution["carry_out"]),
        "carry_out_sha256": execution["carry_out_sha256"],
        "bars_raw": list(bars_raw),
        "fills_raw": list(fills_raw),
        "symbol": symbol,
    }


def _compare_metrics(
    sealed: Any,
    expected: Mapping[str, Any],
    path: str,
    execution_id: str,
    *,
    fields: Sequence[str] = _DISPLAY_METRICS,
    code: str = "LEDGER_V1_METRIC_MISMATCH",
) -> None:
    if not isinstance(sealed, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "metrics must be an object", execution_id)
    for field in fields:
        if field not in sealed:
            _fail("LEDGER_V1_SCHEMA_INVALID", f"{path}.{field}", "required displayed metric is missing", execution_id)
        actual = sealed[field]
        wanted = expected[field]
        if field in {"start_date", "end_date"}:
            if actual != wanted:
                _fail(code, f"{path}.{field}", "date metric mismatch", execution_id)
        elif field in {"n_bars", "n_return_observations", "n_trades"}:
            if _integer(actual, f"{path}.{field}", minimum=0) != wanted:
                _fail(code, f"{path}.{field}", "count metric mismatch", execution_id)
        else:
            _metric(_number(actual, f"{path}.{field}"), float(wanted), f"{path}.{field}", execution_id, code=code)


def _execution_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    window = item["window"]
    return (
        window["start_index"], window["end_index_exclusive"], item["purpose"],
        item["role"], float(item["cost_multiplier"]), item["execution_id"],
    )


def _find_exact(
    executions: Sequence[Mapping[str, Any]], purpose: str, role: str,
    *, window: tuple[int, int] | None = None, multiplier: float | None = None,
    code: str = "LEDGER_V1_COVERAGE_INCOMPLETE",
) -> Mapping[str, Any]:
    matches = [item for item in executions if item["purpose"] == purpose and item["role"] == role]
    if window is not None:
        matches = [item for item in matches if (item["window"]["start_index"], item["window"]["end_index_exclusive"]) == window]
    if multiplier is not None:
        matches = [item for item in matches if math.isclose(item["cost_multiplier"], multiplier, rel_tol=0, abs_tol=METRIC_ABSOLUTE_TOLERANCE)]
    if len(matches) != 1:
        _fail(code, "$.artifacts.valuation_ledger.payload.executions", f"expected exactly one {purpose}/{role} execution")
    return matches[0]


def _declared_partition_window(
    partitions: Mapping[str, Any], name: str,
) -> tuple[int, int]:
    path = f"$.artifacts.partitions.payload.{name}"
    value = partitions.get(name)
    if not isinstance(value, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", path, "partition must be an object")
    start = _integer(value.get("start_index"), f"{path}.start_index", minimum=0)
    end = _integer(value.get("end_index"), f"{path}.end_index", minimum=1)
    if start >= end:
        _fail("LEDGER_V1_DATE_SEQUENCE_INVALID", path, "partition window must be non-empty")
    return start, end


def _market_frame_sha256(
    market: Mapping[str, Any], start: int, end: int,
) -> str:
    return sha256_json_v1(market["records"][start:end])


def _expected_fold_windows(
    minimum_train: int, test_window: int, minimum_short: int,
    development_end: int,
) -> list[tuple[int, int, int]]:
    expected: list[tuple[int, int, int]] = []
    cursor = minimum_train
    while cursor < development_end:
        remaining = development_end - cursor
        if remaining < minimum_short:
            if expected:
                start, _end, _bars = expected[-1]
                expected[-1] = (start, development_end, development_end - start)
            break
        size = min(test_window, remaining)
        if remaining > test_window and remaining - test_window < minimum_short:
            size = remaining
        expected.append((cursor, cursor + size, size))
        cursor += size
    return expected


def _gate_c_plan_view(raw: Any) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    """Return (sealed plan, flat Gate-C view) for either sealed plan contract.

    The earlier plan payload is already flat and is returned unchanged for both
    values, so every law below reads exactly the object it read before.  The
    later payload nests six Gate-C scalars and stores the EFFECTIVE holdout
    share under ``final_holdout_fraction`` while the registered specification
    value lives in ``registered_final_holdout_fraction``; the view republishes
    the registered value under the flat name — that is the fraction Gate C
    binds to the sealed strategy spec — and the effective share is proved here
    against its own derived window instead.
    """
    declared = raw.get("plan_version") if isinstance(raw, Mapping) else None
    if declared != "validation-plan-v3":
        plan = _object(
            raw, _VALIDATION_PLAN_KEYS, "$.artifacts.validation_plan.payload",
        )
        return plan, plan

    plan = _object(
        raw, _VALIDATION_PLAN_V3_KEYS, "$.artifacts.validation_plan.payload",
    )
    walk_forward = _object(
        plan["walk_forward"], _V3_WALK_FORWARD_KEYS,
        "$.artifacts.validation_plan.payload.walk_forward",
    )
    window = _object(
        plan["final_window"], _V3_FINAL_WINDOW_KEYS,
        "$.artifacts.validation_plan.payload.final_window",
    )
    n_bars = _integer(
        plan["n_bars"], "$.artifacts.validation_plan.payload.n_bars",
        minimum=1,
    )
    bars = _integer(
        window["bars"],
        "$.artifacts.validation_plan.payload.final_window.bars", minimum=1,
    )
    if _integer(
        window["n_bars"],
        "$.artifacts.validation_plan.payload.final_window.n_bars", minimum=1,
    ) != n_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.final_window.n_bars",
            "final window length contradicts the sealed plan frame",
        )
    # Exact identity, never an approximate tolerance: the effective share must
    # be the correctly-rounded quotient of its own derived final window.
    if _number(
        plan["final_holdout_fraction"],
        "$.artifacts.validation_plan.payload.final_holdout_fraction",
    ) != bars / n_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.final_holdout_fraction",
            "effective fraction is not the exact derived final-window share",
        )
    view = {
        "profile_id": plan["profile_id"],
        "plan_version": plan["plan_version"],
        "profile_hash": plan["profile_hash"],
        "walk_forward_mode": walk_forward["mode"],
        "parameter_selection": walk_forward["parameter_selection"],
        "n_bars": plan["n_bars"],
        "development_bars": plan["development_bars"],
        "final_holdout_bars": window["bars"],
        "minimum_train_bars": plan["minimum_train_bars"],
        "test_window_bars": walk_forward["test_window_bars"],
        "minimum_short_fold_bars": walk_forward["minimum_short_fold_bars"],
        "final_warmup_bars": plan["final_warmup_bars"],
        "final_holdout_fraction": plan["registered_final_holdout_fraction"],
        "max_indicator_lookback": plan["max_indicator_lookback"],
    }
    return plan, view


def _gate_c_context(
    payloads: Mapping[str, Any], spec: Mapping[str, Any],
    market_document: Mapping[str, Any], contract: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Derive Gate-C windows from sealed inputs, never from reported outcomes."""
    walk_forward = payloads.get("walk_forward")
    if not isinstance(walk_forward, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.walk_forward.payload", "must be an object")
    marker = walk_forward.get("continuous_path_version")
    if marker is None:
        return None
    if marker != _CONTINUOUS_PATH_VERSION:
        _fail(
            "LEDGER_V1_UNSUPPORTED_CONTRACT",
            "$.artifacts.walk_forward.payload.continuous_path_version",
            "unsupported continuous-path contract",
        )
    if market_document["market_observations_version"] != "market-observations-v2":
        _fail(
            "LEDGER_V1_UNSUPPORTED_CONTRACT",
            "$.registry.snapshots",
            "Gate C requires reviewed market-observations-v2 with exact OHLCV sessions",
        )

    sealed_plan, plan = _gate_c_plan_view(payloads.get("validation_plan"))
    plan_body = {
        key: value for key, value in sealed_plan.items()
        if key != "validation_plan_hash"
    }
    if _sha(
        sealed_plan["validation_plan_hash"],
        "$.artifacts.validation_plan.payload.validation_plan_hash",
    ) != sha256_json_v1(plan_body):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.validation_plan_hash",
            "validation plan hash does not bind the complete plan",
        )
    plan_hash = sealed_plan["validation_plan_hash"]
    plan_registry = registry.get("validation_plans")
    anchor = (
        plan_registry.get(plan_hash)
        if isinstance(plan_registry, Mapping)
        else None
    )
    expected_anchor = {
        "profile_id": sealed_plan["profile_id"],
        "profile_hash": sealed_plan["profile_hash"],
        "plan_version": sealed_plan["plan_version"],
        "validation_plan_hash": plan_hash,
        "full_plan_sha256": sha256_json_v1(sealed_plan),
        "spec_hash": payloads["spec"]["spec_hash"],
        "snapshot_sha256": market_document["snapshot_sha256"],
    }
    if not isinstance(anchor, Mapping) or not _canonical_equal(anchor, expected_anchor):
        _fail(
            "LEDGER_V1_BINDING_MISMATCH",
            "$.registry.validation_plans",
            "the complete Gate-C validation plan is not approved by the control plane",
        )
    if (
        (plan["profile_id"], plan["plan_version"]) not in _GATE_C_PLAN_CONTRACTS
        or plan["walk_forward_mode"] != "expanding-fixed-rule"
        or plan["parameter_selection"] != "forbidden"
    ):
        _fail(
            "LEDGER_V1_UNSUPPORTED_CONTRACT",
            "$.artifacts.validation_plan.payload",
            "unsupported Gate-C validation plan",
        )
    _sha(plan["profile_hash"], "$.artifacts.validation_plan.payload.profile_hash")
    n_bars = _integer(plan["n_bars"], "$.artifacts.validation_plan.payload.n_bars", minimum=1)
    development_end = _integer(
        plan["development_bars"],
        "$.artifacts.validation_plan.payload.development_bars",
        minimum=1,
    )
    final_bars = _integer(
        plan["final_holdout_bars"],
        "$.artifacts.validation_plan.payload.final_holdout_bars",
        minimum=1,
    )
    minimum_train = _integer(
        plan["minimum_train_bars"],
        "$.artifacts.validation_plan.payload.minimum_train_bars",
        minimum=1,
    )
    test_window = _integer(
        plan["test_window_bars"],
        "$.artifacts.validation_plan.payload.test_window_bars",
        minimum=1,
    )
    minimum_short = _integer(
        plan["minimum_short_fold_bars"],
        "$.artifacts.validation_plan.payload.minimum_short_fold_bars",
        minimum=1,
    )
    final_warmup = _integer(
        plan["final_warmup_bars"],
        "$.artifacts.validation_plan.payload.final_warmup_bars",
        minimum=0,
    )
    if development_end + final_bars != n_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload",
            "development and final counters do not cover the plan frame exactly",
        )
    fraction = _number(
        plan["final_holdout_fraction"],
        "$.artifacts.validation_plan.payload.final_holdout_fraction",
    )
    validation = spec.get("validation")
    split_definition = (
        validation.get("is_oos_split")
        if isinstance(validation, Mapping)
        else None
    )
    if not isinstance(split_definition, Mapping):
        _fail(
            "LEDGER_V1_SCHEMA_INVALID",
            "$.artifacts.spec.payload.spec.validation.is_oos_split",
            "Gate C requires a sealed final-holdout fraction",
        )
    spec_fraction = _number(
        split_definition.get("oos_fraction"),
        "$.artifacts.spec.payload.spec.validation.is_oos_split.oos_fraction",
    )
    if fraction <= 0 or fraction >= 1 or max(1, int(round(n_bars * fraction))) != final_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.final_holdout_fraction",
            "final-holdout fraction contradicts the sealed bar count",
        )
    if fraction != spec_fraction:
        _fail(
            "LEDGER_V1_BINDING_MISMATCH",
            "$.artifacts.validation_plan.payload.final_holdout_fraction",
            "validation plan fraction differs from the sealed strategy spec",
        )
    rule = spec.get("rule")
    if not isinstance(rule, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.spec.payload.spec.rule", "must be an object")
    lookbacks = [
        _integer(rule.get("ma_days"), "$.artifacts.spec.payload.spec.rule.ma_days", minimum=2),
    ]
    if rule.get("fast_ma_days") is not None:
        lookbacks.append(_integer(
            rule.get("fast_ma_days"),
            "$.artifacts.spec.payload.spec.rule.fast_ma_days",
            minimum=2,
        ))
    if _integer(
        plan["max_indicator_lookback"],
        "$.artifacts.validation_plan.payload.max_indicator_lookback",
        minimum=2,
    ) != max(lookbacks):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.max_indicator_lookback",
            "plan lookback does not match the frozen strategy rule",
        )

    universe = spec.get("universe")
    if not isinstance(universe, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.spec.payload.spec.universe", "must be an object")
    symbol = _text(universe.get("symbol"), "$.artifacts.spec.payload.spec.universe.symbol")
    currency = contract["currency_policy"]["base_currency"]
    market = market_document["instruments"].get((symbol, currency))
    if market is None:
        _fail("LEDGER_V1_CURRENCY_MISMATCH", "$.registry.snapshots", "strategy market series is missing")
    dates = market["dates"]
    if len(dates) != n_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.validation_plan.payload.n_bars",
            "plan length does not equal the sealed market-session count",
        )

    partitions = _object(
        payloads.get("partitions"),
        _PARTITION_KEYS,
        "$.artifacts.partitions.payload",
    )
    if partitions["partition_version"] \
            != _GATE_C_PARTITION_VERSION[plan["plan_version"]]:
        _fail(
            "LEDGER_V1_UNSUPPORTED_CONTRACT",
            "$.artifacts.partitions.payload.partition_version",
            "unsupported Gate-C partition artifact",
        )
    if partitions.get("status") != "READY":
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.status",
            "continuous development paths require a READY partition set",
        )
    if partitions["reason"] is not None:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.reason",
            "a READY partition cannot carry an inconclusive reason",
        )
    if _integer(partitions["n_bars"], "$.artifacts.partitions.payload.n_bars", minimum=1) != n_bars:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.n_bars",
            "partition length contradicts the validation plan",
        )
    development = _object(
        partitions.get("development"),
        _DEVELOPMENT_PARTITION_KEYS,
        "$.artifacts.partitions.payload.development",
    )
    development_start = _integer(
        development.get("start_index"),
        "$.artifacts.partitions.payload.development.start_index",
        minimum=0,
    )
    sealed_development_end = _integer(
        development.get("end_index"),
        "$.artifacts.partitions.payload.development.end_index",
        minimum=1,
    )
    if development_start != 0 or sealed_development_end != development_end:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.development.start_index",
            "development origin or boundary contradicts the validation plan",
        )
    if (
        _integer(development["bars"], "$.artifacts.partitions.payload.development.bars", minimum=1)
        != development_end
        or development["start"] != dates[0]
        or development["end"] != dates[development_end - 1]
        or development["input_sha256"] != _market_frame_sha256(market, 0, development_end)
    ):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.development",
            "development counters, dates, or input digest do not match sealed sessions",
        )

    final = _object(
        partitions.get("final_holdout"),
        _FINAL_PARTITION_KEYS,
        "$.artifacts.partitions.payload.final_holdout",
    )
    final_start = _integer(
        final["start_index"],
        "$.artifacts.partitions.payload.final_holdout.start_index",
        minimum=1,
    )
    final_end = _integer(
        final["end_index"],
        "$.artifacts.partitions.payload.final_holdout.end_index",
        minimum=1,
    )
    warmup = min(final_warmup, final_start)
    warmup_start = final_start - warmup
    if (
        final_start != development_end
        or final_end != n_bars
        or _integer(final["bars"], "$.artifacts.partitions.payload.final_holdout.bars", minimum=1)
        != final_bars
        or final["start"] != dates[final_start]
        or final["end"] != dates[final_end - 1]
        or _integer(
            final["warmup_start_index"],
            "$.artifacts.partitions.payload.final_holdout.warmup_start_index",
            minimum=0,
        ) != warmup_start
        or _integer(
            final["warmup_bars"],
            "$.artifacts.partitions.payload.final_holdout.warmup_bars",
            minimum=0,
        ) != warmup
        or final["capsule_sha256"] != _market_frame_sha256(market, warmup_start, final_end)
        or final["evaluation_input_sha256"]
        != _market_frame_sha256(market, final_start, final_end)
    ):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.final_holdout",
            "final holdout is not the exact adjacent plan-sized sealed-session suffix",
        )

    laws = _object(
        partitions.get("laws"),
        _PARTITION_LAW_KEYS,
        "$.artifacts.partitions.payload.laws",
    )
    expected_laws = {
        "mode": "expanding-fixed-rule",
        "continuous_non_overlapping_tests": True,
        "prefix_ends_at_test_end": True,
        "parameter_selection": "forbidden",
        "short_remainder_policy": "merge_if_under_63_bars",
    }
    if not _canonical_equal(laws, expected_laws):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.laws",
            "partition laws differ from the Gate-C contract",
        )

    declared_folds = partitions.get("folds")
    if not isinstance(declared_folds, list) or not declared_folds:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.folds",
            "continuous development paths require at least one fold",
        )
    folds: list[dict[str, Any]] = []
    prior_end: int | None = None
    expected_windows = _expected_fold_windows(
        minimum_train, test_window, minimum_short, development_end,
    )
    if len(declared_folds) != len(expected_windows):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.folds",
            "fold count contradicts the validation-plan schedule",
        )
    for index, raw in enumerate(declared_folds):
        path = f"$.artifacts.partitions.payload.folds[{index}]"
        raw = _object(raw, _FOLD_PARTITION_KEYS, path)
        fold_id = _text(raw.get("fold_id"), f"{path}.fold_id")
        if fold_id != f"wf-{index + 1:03d}":
            _fail(
                "LEDGER_V1_CONTINUITY_MISMATCH",
                f"{path}.fold_id",
                "fold IDs must be ordered and contiguous from wf-001",
            )
        train_start = _integer(raw.get("train_start_index"), f"{path}.train_start_index", minimum=0)
        train_end = _integer(raw.get("train_end_index"), f"{path}.train_end_index", minimum=1)
        test_start = _integer(raw.get("test_start_index"), f"{path}.test_start_index", minimum=1)
        test_end = _integer(raw.get("test_end_index"), f"{path}.test_end_index", minimum=1)
        visible_end = _integer(
            raw.get("visible_prefix_end_index"),
            f"{path}.visible_prefix_end_index",
            minimum=1,
        )
        expected_start, expected_end, expected_bars = expected_windows[index]
        if (
            train_start != 0
            or train_end != test_start
            or test_end <= test_start
            or visible_end != test_end
            or (test_start, test_end) != (expected_start, expected_end)
            or _integer(raw["train_bars"], f"{path}.train_bars", minimum=1) != train_end
            or _integer(raw["test_bars"], f"{path}.test_bars", minimum=1) != expected_bars
            or raw["train_start"] != dates[0]
            or raw["train_end"] != dates[train_end - 1]
            or raw["test_start"] != dates[test_start]
            or raw["test_end"] != dates[test_end - 1]
            or raw["visible_prefix_sha256"] != _market_frame_sha256(market, 0, test_end)
        ):
            _fail(
                "LEDGER_V1_CONTINUITY_MISMATCH",
                path,
                "fold schedule, counters, dates, or visible-prefix digest mismatch",
            )
        if prior_end is not None and test_start != prior_end:
            _fail(
                "LEDGER_V1_CONTINUITY_MISMATCH",
                path,
                "fold test windows must be ordered and contiguous",
            )
        prior_end = test_end
        folds.append({
            "fold_id": fold_id,
            "start_index": test_start,
            "end_index_exclusive": test_end,
        })
    if folds[-1]["end_index_exclusive"] != development_end:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.folds",
            "the final fold must end at the development boundary",
        )

    derived = {
        "start_index": folds[0]["start_index"],
        "end_index_exclusive": folds[-1]["end_index_exclusive"],
        "observation_count": folds[-1]["end_index_exclusive"] - folds[0]["start_index"],
    }
    sealed = _object(
        walk_forward.get("development_evaluation"),
        _DEVELOPMENT_EVALUATION_KEYS,
        "$.artifacts.walk_forward.payload.development_evaluation",
    )
    sealed_parsed = {
        "start_index": _integer(
            sealed["start_index"],
            "$.artifacts.walk_forward.payload.development_evaluation.start_index",
            minimum=1,
        ),
        "end_index_exclusive": _integer(
            sealed["end_index_exclusive"],
            "$.artifacts.walk_forward.payload.development_evaluation.end_index_exclusive",
            minimum=1,
        ),
        "observation_count": _integer(
            sealed["observation_count"],
            "$.artifacts.walk_forward.payload.development_evaluation.observation_count",
            minimum=1,
        ),
    }
    if sealed_parsed != derived:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.walk_forward.payload.development_evaluation",
            "sealed development-evaluation window does not match the fold-derived OOS tail",
        )
    cost_definition = validation.get("cost_stress") if isinstance(validation, Mapping) else None
    if not isinstance(cost_definition, Mapping):
        _fail(
            "LEDGER_V1_SCHEMA_INVALID",
            "$.artifacts.spec.payload.spec.validation.cost_stress",
            "Gate C requires registered cost-stress multipliers",
        )
    raw_multipliers = cost_definition.get("multipliers")
    if not isinstance(raw_multipliers, list) or not raw_multipliers:
        _fail(
            "LEDGER_V1_SCHEMA_INVALID",
            "$.artifacts.spec.payload.spec.validation.cost_stress.multipliers",
            "must be a non-empty array",
        )
    multipliers = [
        _number(
            value,
            f"$.artifacts.spec.payload.spec.validation.cost_stress.multipliers[{index}]",
        )
        for index, value in enumerate(raw_multipliers)
    ]
    if (
        multipliers != sorted(multipliers)
        or len(multipliers) != len(set(multipliers))
        or 1.0 not in multipliers
        or any(value < 0 for value in multipliers)
    ):
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.spec.payload.spec.validation.cost_stress.multipliers",
            "registered multipliers must be non-negative, sorted, unique, and include 1.0",
        )
    return {
        **derived,
        "folds": folds,
        "final_window": (final_start, final_end),
        "cost_multipliers": multipliers,
    }


def _canonical_equal(left: Any, right: Any) -> bool:
    return canonical_json_bytes_v1(left) == canonical_json_bytes_v1(right)


def _find_gate_c_execution(
    executions: Sequence[Mapping[str, Any]],
    *,
    purpose: str,
    role: str,
    window: tuple[int, int],
    multiplier: float,
    code: str = "LEDGER_V1_CONTINUITY_MISMATCH",
) -> Mapping[str, Any]:
    matches = [
        item for item in executions
        if item["purpose"] == purpose
        and item["role"] == role
        and (
            item["window"]["start_index"],
            item["window"]["end_index_exclusive"],
        ) == window
        and item["cost_multiplier"] == multiplier
    ]
    if len(matches) != 1:
        _fail(
            code,
            "$.artifacts.valuation_ledger.payload.executions",
            f"expected exactly one Gate-C {purpose}/{role}/{multiplier!r} execution",
        )
    return matches[0]


def _desired_position_at_close(
    closes: Sequence[float], rule: Mapping[str, Any], decision_index: int,
) -> int:
    if decision_index < 0:
        return 0
    rule_type = rule.get("type")
    slow = _integer(
        rule.get("ma_days"),
        "$.artifacts.spec.payload.spec.rule.ma_days",
        minimum=2,
    )
    if rule_type == "price_vs_ma":
        if decision_index + 1 < slow:
            return 0
        slow_average = statistics.fmean(
            closes[decision_index - slow + 1:decision_index + 1]
        )
        return int(closes[decision_index] > slow_average)
    if rule_type == "ma_crossover":
        fast = _integer(
            rule.get("fast_ma_days"),
            "$.artifacts.spec.payload.spec.rule.fast_ma_days",
            minimum=2,
        )
        if decision_index + 1 < max(fast, slow):
            return 0
        fast_average = statistics.fmean(
            closes[decision_index - fast + 1:decision_index + 1]
        )
        slow_average = statistics.fmean(
            closes[decision_index - slow + 1:decision_index + 1]
        )
        return int(fast_average > slow_average)
    _fail(
        "LEDGER_V1_UNSUPPORTED_CONTRACT",
        "$.artifacts.spec.payload.spec.rule.type",
        "Gate C supports only price_vs_ma and ma_crossover",
    )
    raise AssertionError("unreachable")


def _validate_gate_c_strategy_timing(
    item: Mapping[str, Any], rule: Mapping[str, Any], market: Mapping[str, Any],
) -> None:
    execution_id = item["execution_id"]
    fills_by_session: dict[str, list[Mapping[str, Any]]] = {}
    for fill in item["fills"]:
        fills_by_session.setdefault(fill["session"], []).append(fill)
    closes = [float(market["prices"][session][1]) for session in market["dates"]]
    position = int(item["carry_in"]["position"])
    start = int(item["window"]["start_index"])
    for offset, bar in enumerate(item["bars"]):
        session_index = start + offset
        desired = _desired_position_at_close(closes, rule, session_index - 1)
        expected_side = None
        if desired != position:
            expected_side = "buy" if desired == 1 else "sell"
        session_fills = fills_by_session.get(bar["date"], [])
        if expected_side is None:
            if session_fills:
                _fail(
                    "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "a fill occurred without a prior-close position transition",
                    execution_id,
                )
        elif len(session_fills) != 1 or session_fills[0]["side"] != expected_side:
            _fail(
                "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                f"prior-close signal requires exactly one {expected_side} on the next session",
                execution_id,
            )
        position = desired
        if int(bar["position"]) != position:
            _fail(
                "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "end-of-session position contradicts the independently reconstructed signal",
                execution_id,
            )


def _validate_gate_c_benchmark_timing(
    item: Mapping[str, Any], *, scope: str,
) -> None:
    fills = item["fills"]
    first_session = item["bars"][0]["date"]
    if len(fills) != 1 or fills[0]["side"] != "buy" or fills[0]["session"] != first_session:
        _fail(
            "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
            "$.artifacts.valuation_ledger.payload.executions",
            f"the {scope} benchmark must buy once on its first session and never re-enter",
            item["execution_id"],
        )
    if any(int(bar["position"]) != 1 for bar in item["bars"]):
        _fail(
            "LEDGER_V1_SIGNAL_TIMING_MISMATCH",
            "$.artifacts.valuation_ledger.payload.executions",
            f"the {scope} benchmark must remain invested through its full window",
            item["execution_id"],
        )


def _validate_gate_c(
    payloads: Mapping[str, Any],
    executions: Sequence[Mapping[str, Any]],
    context: Mapping[str, Any],
    contract: Mapping[str, Any],
    spec: Mapping[str, Any],
    market_document: Mapping[str, Any],
) -> None:
    evaluation_window = (
        int(context["start_index"]), int(context["end_index_exclusive"]),
    )
    cost_stress = payloads.get("cost_stress")
    if not isinstance(cost_stress, Mapping) or not isinstance(cost_stress.get("multipliers"), list):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.cost_stress.payload", "malformed cost-stress artifact")
    sealed_multipliers = [
        _number(value, "$.artifacts.cost_stress.payload.multipliers")
        for value in cost_stress["multipliers"]
    ]
    multipliers = list(context["cost_multipliers"])
    if sealed_multipliers != multipliers:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.cost_stress.payload.multipliers",
            "reported multipliers do not exactly equal the sealed spec multipliers",
        )
    rows = cost_stress.get("rows")
    if not isinstance(rows, list) or [
        _number(row.get("multiplier"), f"$.artifacts.cost_stress.payload.rows[{index}].multiplier")
        if isinstance(row, Mapping) else float("nan")
        for index, row in enumerate(rows)
    ] != multipliers:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.cost_stress.payload.rows",
            "cost-stress rows must cover every sealed spec multiplier exactly once",
        )

    expected_initial = {
        "cash": float(contract["initial_capital"]),
        "shares": 0.0,
        "position": 0,
    }
    rule = spec.get("rule")
    if not isinstance(rule, Mapping):
        _fail(
            "LEDGER_V1_UNSUPPORTED_CONTRACT",
            "$.artifacts.spec.payload.spec.rule",
            "Gate C requires one frozen moving-average rule",
        )
    currency = contract["currency_policy"]["base_currency"]

    primary_by_role: dict[str, Mapping[str, Any]] = {}
    stress_by_key: dict[tuple[str, float], Mapping[str, Any]] = {}
    for role in _ROLES:
        primary = _find_gate_c_execution(
            executions,
            purpose="primary_evaluation",
            role=role,
            window=evaluation_window,
            multiplier=1.0,
        )
        primary_by_role[role] = primary
        if not _canonical_equal(primary["carry_in_raw"], expected_initial):
            _fail(
                "LEDGER_V1_CONTINUITY_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "the continuous primary path must initialize from fresh contract capital",
                primary["execution_id"],
            )
        market = market_document["instruments"].get((primary["symbol"], currency))
        if market is None:
            _fail("LEDGER_V1_CURRENCY_MISMATCH", "$.registry.snapshots", "role market series is missing")
        if role == "strategy":
            _validate_gate_c_strategy_timing(primary, rule, market)
        else:
            _validate_gate_c_benchmark_timing(primary, scope="development")
        for multiplier in multipliers:
            stressed = _find_gate_c_execution(
                executions,
                purpose="cost_stress",
                role=role,
                window=evaluation_window,
                multiplier=multiplier,
            )
            stress_by_key[(role, multiplier)] = stressed
            if not _canonical_equal(stressed["carry_in_raw"], expected_initial):
                _fail(
                    "LEDGER_V1_CONTINUITY_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "each cost path must initialize independently from fresh contract capital",
                    stressed["execution_id"],
                )
            if role == "strategy":
                _validate_gate_c_strategy_timing(stressed, rule, market)
            else:
                _validate_gate_c_benchmark_timing(stressed, scope="development")

    folds = list(context["folds"])
    for role in _ROLES:
        primary = primary_by_role[role]
        fold_items = [
            _find_gate_c_execution(
                executions,
                purpose="fold_slice",
                role=role,
                window=(fold["start_index"], fold["end_index_exclusive"]),
                multiplier=1.0,
                code="LEDGER_V1_FOLD_SLICE_MISMATCH",
            )
            for fold in folds
        ]
        if (
            not _canonical_equal(primary["carry_in_raw"], fold_items[0]["carry_in_raw"])
            or primary["carry_in_sha256"] != fold_items[0]["carry_in_sha256"]
            or not _canonical_equal(primary["carry_out_raw"], fold_items[-1]["carry_out_raw"])
            or primary["carry_out_sha256"] != fold_items[-1]["carry_out_sha256"]
        ):
            _fail(
                "LEDGER_V1_FOLD_SLICE_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "primary carry endpoints do not equal the first/last fold endpoints",
                primary["execution_id"],
            )
        for prior, current in zip(fold_items, fold_items[1:]):
            if (
                not _canonical_equal(prior["carry_out_raw"], current["carry_in_raw"])
                or prior["carry_out_sha256"] != current["carry_in_sha256"]
            ):
                _fail(
                    "LEDGER_V1_CONTINUITY_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "adjacent folds do not share one exact canonical carry state",
                    current["execution_id"],
                )
        concatenated_bars = [bar for item in fold_items for bar in item["bars_raw"]]
        concatenated_fills = [fill for item in fold_items for fill in item["fills_raw"]]
        if (
            not _canonical_equal(concatenated_bars, primary["bars_raw"])
            or not _canonical_equal(concatenated_fills, primary["fills_raw"])
        ):
            _fail(
                "LEDGER_V1_FOLD_SLICE_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "fold bars and fills are not literal primary-path projections",
                primary["execution_id"],
            )
        compounded = math.prod(
            1.0 + float(item["metrics"]["total_return"])
            for item in fold_items
        ) - 1.0
        _metric(
            compounded,
            float(primary["metrics"]["total_return"]),
            "$.artifacts.valuation_ledger.payload.executions",
            primary["execution_id"],
            code="LEDGER_V1_FOLD_SLICE_MISMATCH",
        )

        base_stress = stress_by_key[(role, 1.0)]
        for field in (
            "window", "carry_in_raw", "carry_in_sha256", "carry_out_raw",
            "carry_out_sha256", "bars_raw", "fills_raw",
        ):
            if field.endswith("_sha256"):
                equal = primary[field] == base_stress[field]
            else:
                equal = _canonical_equal(primary[field], base_stress[field])
            if not equal:
                _fail(
                    "LEDGER_V1_CONTINUITY_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "the 1.0 cost path is not economically identical to the primary path",
                    base_stress["execution_id"],
                )

    final_window = tuple(context["final_window"])
    if evaluation_window[1] > final_window[0]:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.partitions.payload.final_holdout",
            "continuous development and final-holdout windows overlap",
        )
    for role in _ROLES:
        final_item = _find_gate_c_execution(
            executions,
            purpose="final_holdout",
            role=role,
            window=final_window,
            multiplier=1.0,
        )
        if not _canonical_equal(final_item["carry_in_raw"], expected_initial):
            _fail(
                "LEDGER_V1_CONTINUITY_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "the final holdout must initialize separately from development carry",
                final_item["execution_id"],
            )
        market = market_document["instruments"].get((final_item["symbol"], currency))
        if market is None:
            _fail(
                "LEDGER_V1_CURRENCY_MISMATCH",
                "$.registry.snapshots",
                "final-holdout role market series is missing",
            )
        if role == "strategy":
            _validate_gate_c_strategy_timing(final_item, rule, market)
        else:
            _validate_gate_c_benchmark_timing(final_item, scope="final-holdout")

    expected_count = 4 + 2 * len(folds) + 2 * len(multipliers)
    if len(executions) != expected_count:
        _fail(
            "LEDGER_V1_CONTINUITY_MISMATCH",
            "$.artifacts.valuation_ledger.payload.executions",
            "Gate-C role, fold, or multiplier coverage is incomplete or duplicated",
        )


def _validate_claims(
    payloads: Mapping[str, Any],
    executions: Sequence[Mapping[str, Any]],
    gate_c_context: Mapping[str, Any] | None = None,
) -> None:
    development = payloads["development_result"]
    final = payloads["final_holdout_result"]
    if not isinstance(development, Mapping) or not isinstance(final, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts", "result artifacts must be objects")
    partitions = payloads["partitions"]
    walk_forward = payloads["walk_forward"]
    if not isinstance(partitions, Mapping) or not isinstance(walk_forward, Mapping):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts", "fold artifacts must be objects")
    declared_development_window = _declared_partition_window(partitions, "development")
    development_window = (
        (
            int(gate_c_context["start_index"]),
            int(gate_c_context["end_index_exclusive"]),
        )
        if gate_c_context is not None
        else declared_development_window
    )
    final_window = _declared_partition_window(partitions, "final_holdout")
    if development_window[1] > final_window[0]:
        _fail(
            "LEDGER_V1_COVERAGE_INCOMPLETE",
            "$.artifacts.partitions.payload",
            "development and final-holdout partitions overlap",
        )
    for role, field in (("strategy", "strategy_metrics"), ("benchmark", "benchmark_metrics")):
        item = _find_exact(
            executions, "primary_evaluation", role, window=development_window,
        )
        if not math.isclose(item["cost_multiplier"], 1.0, rel_tol=0, abs_tol=METRIC_ABSOLUTE_TOLERANCE):
            _fail(
                "LEDGER_V1_COVERAGE_INCOMPLETE",
                "$.artifacts.valuation_ledger.payload.executions",
                "primary_evaluation must use the 1.0 cost multiplier",
                item["execution_id"],
            )
        _compare_metrics(development.get(field), item["metrics"], f"$.artifacts.development_result.payload.{field}", item["execution_id"])
        final_item = _find_exact(
            executions, "final_holdout", role, window=final_window,
        )
        if not math.isclose(final_item["cost_multiplier"], 1.0, rel_tol=0, abs_tol=METRIC_ABSOLUTE_TOLERANCE):
            _fail(
                "LEDGER_V1_COVERAGE_INCOMPLETE",
                "$.artifacts.valuation_ledger.payload.executions",
                "final_holdout must use the 1.0 cost multiplier",
                final_item["execution_id"],
            )
        _compare_metrics(final.get(field), final_item["metrics"], f"$.artifacts.final_holdout_result.payload.{field}", final_item["execution_id"])

    declared_folds = partitions.get("folds")
    sealed_folds = walk_forward.get("folds")
    if not isinstance(declared_folds, list) or not isinstance(sealed_folds, list) or len(declared_folds) != len(sealed_folds):
        _fail("LEDGER_V1_FOLD_MISMATCH", "$.artifacts.walk_forward.payload.folds", "declared/sealed fold coverage mismatch")
    fold_returns: list[float] = []
    fold_sharpes: list[float] = []
    for index, (declared, sealed) in enumerate(zip(declared_folds, sealed_folds)):
        if not isinstance(declared, Mapping) or not isinstance(sealed, Mapping) or declared.get("fold_id") != sealed.get("fold_id"):
            _fail("LEDGER_V1_FOLD_MISMATCH", f"$.artifacts.walk_forward.payload.folds[{index}]", "fold identity mismatch")
        window = (declared.get("test_start_index"), declared.get("test_end_index"))
        for role, field in (("strategy", "strategy_metrics"), ("benchmark", "benchmark_metrics")):
            item = _find_exact(executions, "fold_slice", role, window=window, code="LEDGER_V1_FOLD_MISMATCH")
            if not math.isclose(item["cost_multiplier"], 1.0, rel_tol=0, abs_tol=METRIC_ABSOLUTE_TOLERANCE):
                _fail(
                    "LEDGER_V1_FOLD_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "fold_slice must use the 1.0 cost multiplier",
                    item["execution_id"],
                )
            _compare_metrics(sealed.get(field), item["metrics"], f"$.artifacts.walk_forward.payload.folds[{index}].{field}", item["execution_id"], code="LEDGER_V1_FOLD_MISMATCH")
        strategy = _find_exact(executions, "fold_slice", "strategy", window=window, code="LEDGER_V1_FOLD_MISMATCH")
        fold_returns.append(float(strategy["metrics"]["total_return"]))
        fold_sharpes.append(float(strategy["metrics"]["sharpe"]))
    summary_expected = {
        "fold_count": len(declared_folds),
        "median_fold_sharpe": statistics.median(fold_sharpes) if fold_sharpes else None,
        "positive_fold_ratio": sum(value > 0 for value in fold_returns) / len(fold_returns) if fold_returns else None,
        "worst_fold_return": min(fold_returns) if fold_returns else None,
        "fold_return_dispersion": statistics.pstdev(fold_returns) if len(fold_returns) > 1 else (0.0 if fold_returns else None),
        "stitched_development_total_return": float(_find_exact(executions, "primary_evaluation", "strategy")["metrics"]["total_return"]),
    }
    for field, wanted in summary_expected.items():
        actual = walk_forward.get(field)
        if wanted is None:
            if actual is not None:
                _fail("LEDGER_V1_FOLD_MISMATCH", f"$.artifacts.walk_forward.payload.{field}", "must be null")
        elif field == "fold_count":
            if actual != wanted:
                _fail("LEDGER_V1_FOLD_MISMATCH", f"$.artifacts.walk_forward.payload.{field}", "summary mismatch")
        else:
            _metric(_number(actual, f"$.artifacts.walk_forward.payload.{field}"), wanted, f"$.artifacts.walk_forward.payload.{field}", code="LEDGER_V1_FOLD_MISMATCH")

    cost_stress = payloads["cost_stress"]
    if not isinstance(cost_stress, Mapping) or not isinstance(cost_stress.get("multipliers"), list) or not isinstance(cost_stress.get("rows"), list):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.cost_stress.payload", "malformed cost-stress artifact")
    multipliers = [_number(value, "$.artifacts.cost_stress.payload.multipliers") for value in cost_stress["multipliers"]]
    if multipliers != sorted(multipliers) or len(multipliers) != len(set(multipliers)):
        _fail("LEDGER_V1_COST_STRESS_MISMATCH", "$.artifacts.cost_stress.payload.multipliers", "multipliers must be sorted and unique")
    rows = cost_stress["rows"]
    if len(rows) != len(multipliers):
        _fail("LEDGER_V1_COST_STRESS_MISMATCH", "$.artifacts.cost_stress.payload.rows", "row coverage mismatch")
    for role in _ROLES:
        primary = _find_exact(executions, "primary_evaluation", role)
        final = _find_exact(executions, "final_holdout", role)
        if primary["window"]["end_index_exclusive"] > final["window"]["start_index"]:
            _fail(
                "LEDGER_V1_COST_STRESS_MISMATCH",
                "$.artifacts.valuation_ledger.payload.executions",
                "development and final-holdout windows overlap",
                final["execution_id"],
            )
    for index, (multiplier, row) in enumerate(zip(multipliers, rows)):
        if not isinstance(row, Mapping) or _number(row.get("multiplier"), f"$.artifacts.cost_stress.payload.rows[{index}].multiplier") != multiplier:
            _fail("LEDGER_V1_COST_STRESS_MISMATCH", f"$.artifacts.cost_stress.payload.rows[{index}]", "multiplier mismatch")
        for role in _ROLES:
            stressed = _find_exact(
                executions, "cost_stress", role, multiplier=multiplier,
                code="LEDGER_V1_COST_STRESS_MISMATCH",
            )
            primary = _find_exact(executions, "primary_evaluation", role)
            stressed_window = (
                stressed["window"]["start_index"],
                stressed["window"]["end_index_exclusive"],
            )
            primary_window = (
                primary["window"]["start_index"],
                primary["window"]["end_index_exclusive"],
            )
            if stressed_window != primary_window:
                _fail(
                    "LEDGER_V1_COST_STRESS_MISMATCH",
                    "$.artifacts.valuation_ledger.payload.executions",
                    "cost stress must cover the declared development window only",
                    stressed["execution_id"],
                )
        strategy = _find_exact(executions, "cost_stress", "strategy", multiplier=multiplier, code="LEDGER_V1_COST_STRESS_MISMATCH")
        _compare_metrics(
            row.get("development"), strategy["metrics"],
            f"$.artifacts.cost_stress.payload.rows[{index}].development",
            strategy["execution_id"], fields=("total_return", "sharpe", "total_costs"),
            code="LEDGER_V1_COST_STRESS_MISMATCH",
        )

    expected_execution_count = 4 + 2 * len(declared_folds) + 2 * len(multipliers)
    if len(executions) != expected_execution_count:
        _fail(
            "LEDGER_V1_COVERAGE_INCOMPLETE",
            "$.artifacts.valuation_ledger.payload.executions",
            "execution coverage contains an undeclared, missing, or duplicate role/purpose pair",
        )


def _daily_returns(item: Mapping[str, Any], initial: float) -> dict[str, float]:
    previous = initial
    values: dict[str, float] = {}
    for bar in item["bars"]:
        equity = float(bar["equity"])
        values[bar["date"]] = equity / previous - 1.0
        previous = equity
    return values


def _labels(prices: Sequence[float], dates: Sequence[str]) -> dict[str, str | None]:
    daily: list[float | None] = [None]
    daily.extend(prices[index] / prices[index - 1] - 1.0 for index in range(1, len(prices)))
    output: dict[str, str | None] = {}
    for index, session in enumerate(dates):
        if index < 200 or index < 64:
            output[session] = None
            continue
        prior_returns = [value for value in daily[index - 63:index] if value is not None]
        if len(prior_returns) != 63:
            output[session] = None
            continue
        trend = "up" if prices[index - 1] >= statistics.fmean(prices[index - 200:index]) else "down"
        volatility = "high" if statistics.stdev(prior_returns) * math.sqrt(252) >= 0.20 else "low"
        output[session] = f"{trend}_{volatility}"
    return output


def _validate_regimes(
    payloads: Mapping[str, Any], executions: Sequence[Mapping[str, Any]],
    market_doc: Mapping[str, Any], contract: Mapping[str, Any], spec: Mapping[str, Any],
) -> dict[str, Any]:
    regime = payloads["regime_analysis"]
    if not isinstance(regime, Mapping) or not isinstance(regime.get("states"), list):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.regime_analysis.payload", "malformed regime artifact")
    strategy = _find_exact(executions, "primary_evaluation", "strategy")
    benchmark = _find_exact(executions, "primary_evaluation", "benchmark")
    universe_symbol = spec["universe"]["symbol"]
    benchmark_value = spec["benchmark"]["symbol"]
    benchmark_symbol = universe_symbol if benchmark_value == "same_as_universe" else benchmark_value
    currency = contract["currency_policy"]["base_currency"]
    market = market_doc["instruments"].get((benchmark_symbol, currency))
    if market is None:
        _fail("LEDGER_V1_REGIME_MISMATCH", "$.artifacts.regime_analysis.payload", "benchmark market series missing")
    close_values = [market["prices"][session][1] for session in market["dates"]]
    labels = _labels(close_values, market["dates"])
    strategy_returns = _daily_returns(strategy, float(contract["initial_capital"]))
    benchmark_returns = _daily_returns(benchmark, float(contract["initial_capital"]))
    if set(strategy_returns) != set(benchmark_returns):
        _fail(
            "LEDGER_V1_REGIME_MISMATCH",
            "$.artifacts.valuation_ledger.payload.executions",
            "strategy and benchmark primary windows are not aligned",
        )
    strategy_bars = {bar["date"]: bar for bar in strategy["bars"]}
    trade_counts: dict[str, int] = {}
    for fill in strategy["fills"]:
        trade_counts[fill["session"]] = trade_counts.get(fill["session"], 0) + 1
    expected_states: list[dict[str, Any]] = []
    minimum = 20
    for state in _REGIMES:
        sessions = [session for session in strategy_returns if labels.get(session) == state]
        observations = len(sessions)
        expected_states.append({
            "regime": state,
            "status": "PASS" if observations >= minimum else "INCONCLUSIVE",
            "observations": observations,
            "strategy_compounded_return": math.prod(1 + strategy_returns[session] for session in sessions) - 1 if observations else None,
            "benchmark_compounded_return": math.prod(1 + benchmark_returns[session] for session in sessions) - 1 if observations else None,
            "mean_daily_excess_return": statistics.fmean(strategy_returns[session] - benchmark_returns[session] for session in sessions) if observations else None,
            "exposure": statistics.fmean(strategy_bars[session]["position"] for session in sessions) if observations else None,
            "trade_count": sum(trade_counts.get(session, 0) for session in sessions),
            "max_drawdown": None,
            "note": "Non-contiguous regime observations are not used to compute drawdown.",
        })
    states = regime["states"]
    if len(states) != 4:
        _fail("LEDGER_V1_REGIME_MISMATCH", "$.artifacts.regime_analysis.payload.states", "four states required")
    numeric = (
        "observations", "strategy_compounded_return", "benchmark_compounded_return",
        "mean_daily_excess_return", "exposure", "trade_count",
    )
    for index, (sealed, expected) in enumerate(zip(states, expected_states)):
        if not isinstance(sealed, Mapping) or sealed.get("regime") != expected["regime"] or sealed.get("status") != expected["status"]:
            _fail("LEDGER_V1_REGIME_MISMATCH", f"$.artifacts.regime_analysis.payload.states[{index}]", "state identity/status mismatch")
        if sealed.get("max_drawdown") is not None or sealed.get("note") != expected["note"]:
            _fail(
                "LEDGER_V1_REGIME_MISMATCH",
                f"$.artifacts.regime_analysis.payload.states[{index}]",
                "non-contiguous drawdown policy or explanatory note mismatch",
            )
        for field in numeric:
            actual = sealed.get(field)
            wanted = expected[field]
            if wanted is None:
                if actual is not None:
                    _fail("LEDGER_V1_REGIME_MISMATCH", f"$.artifacts.regime_analysis.payload.states[{index}].{field}", "must be null")
            elif field in {"observations", "trade_count"}:
                if actual != wanted:
                    _fail("LEDGER_V1_REGIME_MISMATCH", f"$.artifacts.regime_analysis.payload.states[{index}].{field}", "count mismatch")
            else:
                _metric(_number(actual, f"$.artifacts.regime_analysis.payload.states[{index}].{field}"), wanted, f"$.artifacts.regime_analysis.payload.states[{index}].{field}", code="LEDGER_V1_REGIME_MISMATCH")
    coverage = regime.get("coverage")
    expected_coverage = {
        "development_observations": len(strategy["bars"]),
        "classified_observations": sum(item["observations"] for item in expected_states),
        "unclassified_warmup_observations": len(strategy["bars"]) - sum(item["observations"] for item in expected_states),
        "state_observations_sum": sum(item["observations"] for item in expected_states),
    }
    if coverage != expected_coverage:
        _fail("LEDGER_V1_REGIME_MISMATCH", "$.artifacts.regime_analysis.payload.coverage", "coverage mismatch")
    expected_status = "PASS" if all(item["status"] == "PASS" for item in expected_states) else "INCONCLUSIVE"
    if regime.get("status") != expected_status:
        _fail("LEDGER_V1_REGIME_MISMATCH", "$.artifacts.regime_analysis.payload.status", "aggregate status mismatch")
    return {"states": expected_states, "coverage": expected_coverage, "status": expected_status}


def _validate_falsification(payloads: Mapping[str, Any], regimes: Mapping[str, Any]) -> None:
    walk = payloads["walk_forward"]
    stress = payloads["cost_stress"]
    falsification = payloads["falsification"]
    if not isinstance(falsification, Mapping) or not isinstance(falsification.get("findings"), list):
        _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.falsification.payload", "malformed findings")
    required_ids = {
        "walk_forward_stability", "development_cost_fragility", "regime_coverage",
    }
    raw_findings = falsification["findings"]
    if len(raw_findings) != len(required_ids) or any(
        not isinstance(item, Mapping) for item in raw_findings
    ):
        _fail(
            "LEDGER_V1_FALSIFICATION_MISMATCH",
            "$.artifacts.falsification.payload.findings",
            "exactly three object findings are required",
        )
    finding_ids = [item.get("id") for item in raw_findings]
    if any(not isinstance(item, str) for item in finding_ids) or \
            len(set(finding_ids)) != len(finding_ids) or set(finding_ids) != required_ids:
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.findings", "required findings mismatch")
    findings = {item["id"]: item for item in raw_findings}
    ratio = walk.get("positive_fold_ratio")
    wf_status = "INCONCLUSIVE" if ratio is None else ("PASS" if _number(ratio, "$.artifacts.walk_forward.payload.positive_fold_ratio") >= 0.5 else "FAIL")
    wf = findings["walk_forward_stability"]
    if wf.get("status") != wf_status or not isinstance(wf.get("evidence"), Mapping):
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.findings.walk_forward_stability", "status/evidence mismatch")
    expected_wf = {
        "positive_fold_ratio": ratio,
        "fold_count": walk.get("fold_count", 0),
        "worst_fold_return": walk.get("worst_fold_return"),
    }
    if wf["evidence"] != expected_wf:
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.findings.walk_forward_stability.evidence", "numeric evidence mismatch")
    rows = stress.get("rows") if isinstance(stress, Mapping) else None
    base = next((row for row in rows or [] if row.get("multiplier") == 1.0), None)
    doubled = next((row for row in rows or [] if row.get("multiplier") == 2.0), None)
    if base is None or doubled is None:
        cost_status = "INCONCLUSIVE"
    else:
        base_return = base["development"].get("total_return")
        doubled_return = doubled["development"].get("total_return")
        fragile = doubled_return is not None and (doubled_return < 0 or (base_return is not None and base_return > 0 and doubled_return < 0.5 * base_return))
        cost_status = "FAIL" if fragile else "PASS"
    cost = findings["development_cost_fragility"]
    if cost.get("status") != cost_status or cost.get("evidence") != {"base": base, "doubled": doubled}:
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.findings.development_cost_fragility", "numeric evidence/status mismatch")
    regime = findings["regime_coverage"]
    expected_regime_evidence = {
        "coverage": regimes["coverage"],
        "states": [{"regime": item["regime"], "status": item["status"], "observations": item["observations"]} for item in regimes["states"]],
    }
    if regime.get("status") != regimes["status"] or regime.get("evidence") != expected_regime_evidence:
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.findings.regime_coverage", "regime finding mismatch")
    statuses = [wf_status, cost_status, regimes["status"]]
    battery_status = "FAIL" if "FAIL" in statuses else ("INCONCLUSIVE" if "INCONCLUSIVE" in statuses else "PASS")
    if falsification.get("status") != battery_status or payloads["evidence_status"].get("battery_status") != battery_status:
        _fail("LEDGER_V1_FALSIFICATION_MISMATCH", "$.artifacts.falsification.payload.status", "battery status mismatch")


class FinancialSemanticValidatorV1:
    """Side-effect-free, fail-closed validator for one complete dormant ledger."""

    def validate(
        self,
        manifest: Mapping[str, Any],
        ledger_index: Mapping[str, Any],
        artifact_payload_map: Mapping[str, Any],
        reviewed_registry: Mapping[str, Any],
    ) -> dict[str, Any]:
        registry = _validate_registry(reviewed_registry)
        ledger, payloads = _validate_ledger_and_wrappers(
            manifest, ledger_index, artifact_payload_map, registry,
        )
        snapshot_hash = _snapshot_binding(manifest, payloads)
        snapshot_value = registry["snapshots"].get(snapshot_hash)
        if snapshot_value is None:
            _fail("LEDGER_V1_BINDING_MISMATCH", "$.registry.snapshots", "sealed snapshot is not supplied")
        market_document = _validate_market_document(snapshot_value, snapshot_hash)
        contract = _validate_contract(payloads["financial_contract"], registry, market_document)

        valuation = _object(payloads["valuation_ledger"], _VALUATION_KEYS, "$.artifacts.valuation_ledger.payload")
        if valuation["valuation_ledger_version"] != "valuation-ledger-v1":
            _fail("LEDGER_V1_SCHEMA_INVALID", "$.artifacts.valuation_ledger.payload.valuation_ledger_version", "unsupported valuation ledger")
        financial_hash = sha256_json_v1(contract)
        if valuation["financial_contract_sha256"] != financial_hash:
            _fail("LEDGER_V1_BINDING_MISMATCH", "$.artifacts.valuation_ledger.payload.financial_contract_sha256", "financial contract binding mismatch")
        spec_hash = payloads["spec"]["spec_hash"]
        if valuation["spec_hash"] != spec_hash:
            _fail("LEDGER_V1_BINDING_MISMATCH", "$.artifacts.valuation_ledger.payload.spec_hash", "spec binding mismatch")
        if valuation["snapshot_sha256"] != snapshot_hash:
            _fail("LEDGER_V1_BINDING_MISMATCH", "$.artifacts.valuation_ledger.payload.snapshot_sha256", "snapshot binding mismatch")
        calendar = contract["calendar_binding"]
        calendar_key = f"{calendar['exchange_calendar_id']}|{calendar['exchange_calendar_version']}|{calendar['acquisition_validation_receipt_sha256']}"
        calendar_sessions = registry["calendars"][calendar_key]["sessions"]
        executions_raw = _array(valuation["executions"], "$.artifacts.valuation_ledger.payload.executions", nonempty=True)
        spec = payloads["spec"]["spec"]
        gate_c_context = _gate_c_context(
            payloads, spec, market_document, contract, registry,
        )
        executions: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, raw in enumerate(executions_raw):
            item = _validate_execution(
                raw, valuation, contract, spec, market_document, calendar_sessions,
                f"$.artifacts.valuation_ledger.payload.executions[{index}]",
                gate_c_context,
            )
            if item["execution_id"] in seen:
                _fail("LEDGER_V1_EXECUTION_ID_MISMATCH", f"$.artifacts.valuation_ledger.payload.executions[{index}].execution_id", "duplicate execution ID", item["execution_id"])
            seen.add(item["execution_id"])
            executions.append(item)
        if [_execution_key(item) for item in executions] != sorted(
            _execution_key(item) for item in executions
        ):
            _fail(
                "LEDGER_V1_SCHEMA_INVALID",
                "$.artifacts.valuation_ledger.payload.executions",
                "executions are not canonically ordered",
            )
        if gate_c_context is not None:
            _validate_gate_c(
                payloads, executions, gate_c_context, contract, spec, market_document,
            )
        _validate_claims(payloads, executions, gate_c_context)
        regimes = _validate_regimes(payloads, executions, market_document, contract, spec)
        _validate_falsification(payloads, regimes)
        return {
            "validator_version": VALIDATOR_VERSION,
            "ledger_id": ledger["ledger_id"],
            "result_hash": ledger["result_hash"],
            "financial_contract_sha256": financial_hash,
            "validated_execution_ids": [item["execution_id"] for item in executions],
            "status": "PASS",
        }


def validate_financial_semantics_v1(
    manifest: Mapping[str, Any],
    ledger_index: Mapping[str, Any],
    artifact_payload_map: Mapping[str, Any],
    reviewed_registry: Mapping[str, Any],
) -> dict[str, Any]:
    return FinancialSemanticValidatorV1().validate(
        manifest, ledger_index, artifact_payload_map, reviewed_registry,
    )


__all__ = [
    "ANNUALIZATION_SESSIONS",
    "FinancialSemanticValidationError",
    "FinancialSemanticValidatorV1",
    "METRIC_ABSOLUTE_TOLERANCE",
    "METRIC_RELATIVE_TOLERANCE",
    "MONEY_ABSOLUTE_TOLERANCE",
    "QUANTITY_ABSOLUTE_TOLERANCE",
    "VALIDATOR_VERSION",
    "canonical_json_bytes_v1",
    "sha256_json_v1",
    "validate_financial_semantics_v1",
]
