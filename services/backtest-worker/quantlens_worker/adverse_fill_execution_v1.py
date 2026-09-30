"""Dormant Gate-D adverse effective-fill producer.

This module implements the producer side of the adverse effective-fill laws the
dormant ``ledger-v1`` contract and the independent validator already enforce
(frozen in ``docs/planning/24-gate7a2-gated-adverse-fill-contract.md`` and bounded
by ``docs/planning/25-claude-gated-adverse-fill-work-package.md``).

It is isolated and dormant: the active engine, Battery v1/v2, final-holdout
producer, runner, artifact, Evidence, report, API and web paths never import it,
and it never imports them.  It writes only ``valuation-execution-v1`` candidate
objects through the neutral Gate-B builders, calculates no displayed metric, and
never calls the independent validator.  Focused tests alone inject its segment
executor into the Gate-C coordinator; this module never imports that coordinator,
preserving the dependency direction.

Legacy ``slippage_bps`` semantics elsewhere are untouched: the historical
``linear_execution_friction`` interpretation of the active paths is permanent, and
this module's adverse-price interpretation exists only behind the dormant
corrected contract.
"""

from __future__ import annotations

import copy
import math
import re
from collections.abc import Mapping as MappingABC, Sequence as SequenceABC
from datetime import date as _date_type
from typing import Any, Callable, Mapping

from .valuation_ledger_v1 import (
    ValuationLedgerContractError,
    build_carry_v1,
    build_execution_v1,
)


ADVERSE_FILL_EXECUTION_VERSION = "adverse-effective-fill-v1"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROLES = frozenset({"strategy", "benchmark"})
_DIRECT_PURPOSES = frozenset({"fold_slice", "final_holdout"})
_RULE_TYPES = frozenset({"price_vs_ma", "ma_crossover"})
_RULE_KEYS = frozenset({"type", "fast_ma_days", "ma_days"})
_EXECUTOR_KEYS = frozenset({
    "strategy_prefix", "benchmark_prefix", "fold", "strategy_carry_in",
    "benchmark_carry_in", "cost_multiplier", "spec_hash", "snapshot_sha256",
})


def _fail(detail: str) -> None:
    raise ValuationLedgerContractError(detail)


def _finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label} must be a JSON number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        # An arbitrarily large Python int overflows float(): still a typed
        # contract failure, never a leaked native exception.
        _fail(f"{label} must be finite")
        raise AssertionError("unreachable")
    if not math.isfinite(result):
        _fail(f"{label} must be finite")
    return result


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be sha256: followed by 64 lowercase hex characters")
    return value


def _iso_date(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be an ISO YYYY-MM-DD string")
    try:
        if _date_type.fromisoformat(value).isoformat() != value:
            raise ValueError
    except ValueError:
        _fail(f"{label} must be canonical ISO YYYY-MM-DD")
    return value


def _window_length(value: object, label: str) -> int:
    """Reviewed Strategy-DSL moving-average window: an integer in 2..400."""
    if isinstance(value, bool) or not isinstance(value, int) or not 2 <= value <= 400:
        _fail(f"{label} must be an integer from 2 through 400")
    return value


def _frozen_rule(rule: object) -> dict[str, Any]:
    """Validate and deep-copy the frozen reviewed rule subset."""
    if not isinstance(rule, MappingABC):
        _fail("rule must be a mapping")
    if not set(rule) <= _RULE_KEYS or "type" not in rule or "ma_days" not in rule:
        _fail("rule must contain only type, ma_days and optional fast_ma_days")
    rule_type = rule["type"]
    # The isinstance guard runs first so an unhashable value fails closed with
    # the typed contract error instead of leaking a TypeError.
    if not isinstance(rule_type, str) or rule_type not in _RULE_TYPES:
        _fail("unsupported rule type")
    ma_days = _window_length(rule.get("ma_days"), "rule.ma_days")
    fast = rule.get("fast_ma_days")
    if rule_type == "ma_crossover":
        fast = _window_length(fast, "rule.fast_ma_days")
        if fast >= ma_days:
            _fail("rule.fast_ma_days must be strictly less than rule.ma_days")
        return {"type": rule_type, "fast_ma_days": fast, "ma_days": ma_days}
    if fast is not None:
        _fail("price_vs_ma takes no fast moving-average window")
    return {"type": rule_type, "fast_ma_days": None, "ma_days": ma_days}


def _slowest_window(rule: Mapping[str, Any]) -> int:
    ma_days = int(rule["ma_days"])
    fast = rule.get("fast_ma_days")
    return max(ma_days, int(fast)) if fast is not None else ma_days


def _frozen_costs(costs: object) -> dict[str, float]:
    if not isinstance(costs, MappingABC):
        _fail("costs must be a mapping")
    if set(costs) != {"commission_bps", "slippage_bps"}:
        _fail("costs must have exactly commission_bps and slippage_bps")
    commission_bps = _finite_number(costs["commission_bps"], "costs.commission_bps")
    slippage_bps = _finite_number(costs["slippage_bps"], "costs.slippage_bps")
    # The reviewed Strategy DSL bounds both rates to 0..100 basis points.
    if not 0 <= commission_bps <= 100 or not 0 <= slippage_bps <= 100:
        _fail("costs rates must be within 0 and 100 basis points")
    return {"commission_bps": commission_bps, "slippage_bps": slippage_bps}


def _canonical_carry(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, MappingABC):
        _fail(f"{label} must be a carry object")
    try:
        carry = build_carry_v1(**dict(value))
    except ValuationLedgerContractError:
        # Already the typed contract failure — pass it through unchanged.
        # (This clause must precede the ValueError one: the contract error is a
        # ValueError subclass.)
        raise
    except TypeError:
        _fail(f"{label} must have exactly cash, shares, and position")
        raise AssertionError("unreachable")
    except (OverflowError, ValueError):
        # An arbitrarily large Python int overflows the neutral builder's
        # float() conversion: normalize to the typed fail-closed path.
        _fail(f"{label} values must be finite JSON numbers")
        raise AssertionError("unreachable")
    if (carry["shares"] > 0) != (carry["position"] == 1):
        _fail(f"{label} position contradicts its share count")
    return carry


def _frame_rows(
    frame: Any, expected_length: int, label: str,
) -> tuple[list[str], list[float], list[float]]:
    """Read only date/open/close from a pandas frame or a sequence of rows."""
    if frame is None:
        _fail(f"{label} frame is required")
    try:
        length = len(frame)
    except TypeError:
        _fail(f"{label} frame must have a length")
        raise AssertionError("unreachable")
    if length != expected_length:
        # Shorter frames are incomplete history; longer frames carry future
        # rows. The counts are deliberately NOT interpolated: an adversarially
        # huge window index must not turn message formatting itself into a
        # native integer-string ValueError.
        _fail(f"{label} frame must contain exactly the physical window rows")
    iloc = getattr(frame, "iloc", None)
    dates: list[str] = []
    opens: list[float] = []
    closes: list[float] = []
    previous_date: str | None = None
    for index in range(length):
        try:
            row = iloc[index] if iloc is not None else frame[index]
            raw_date = row["date"]
            raw_open = row["open"]
            raw_close = row["close"]
        except Exception as exc:
            raise ValuationLedgerContractError(
                f"{label}[{index}] must expose date, open and close"
            ) from exc
        session = _iso_date(raw_date, f"{label}[{index}].date")
        if previous_date is not None and session <= previous_date:
            _fail(f"{label} dates must be strictly increasing and unique")
        previous_date = session
        opening = _finite_number(raw_open, f"{label}[{index}].open")
        close = _finite_number(raw_close, f"{label}[{index}].close")
        if opening <= 0 or close <= 0:
            _fail(f"{label}[{index}] prices must be positive")
        dates.append(session)
        opens.append(opening)
        closes.append(close)
    return dates, opens, closes


def _sma(closes: SequenceABC, end_inclusive: int, window: int) -> float:
    """Simple moving average of the ``window`` closes ending at ``end_inclusive``."""
    values = closes[end_inclusive - window + 1: end_inclusive + 1]
    try:
        return math.fsum(values) / window
    except OverflowError:
        # Finite positive prices can still overflow the exact summation (two
        # 1e308 closes exceed the float range) even though their true mean is
        # finite. Compute the mathematically valid average max-scale
        # normalized, and verify the result stays finite.
        scale = max(abs(value) for value in values)
        result = math.fsum(value / scale for value in values) / window * scale
        if not math.isfinite(result):
            _fail("moving-average computation produced a non-finite value")
        return result


def _desired_strategy_position(
    rule: Mapping[str, Any], closes: SequenceABC, prior_local: int,
) -> bool:
    """Frozen signal law at the prior reviewed close (fully defined by warm-up)."""
    ma_days = int(rule["ma_days"])
    if rule["type"] == "price_vs_ma":
        return closes[prior_local] > _sma(closes, prior_local, ma_days)
    fast = int(rule["fast_ma_days"])
    return _sma(closes, prior_local, fast) > _sma(closes, prior_local, ma_days)


def execute_adverse_fill_window_v1(
    *,
    frame: Any,
    frame_start_index: int,
    start_index: int,
    end_index_exclusive: int,
    role: str,
    purpose: str,
    rule: Mapping[str, Any],
    costs: Mapping[str, Any],
    cost_multiplier: float,
    carry_in: Mapping[str, Any],
    benchmark_entry_index: int | None,
    spec_hash: str,
    snapshot_sha256: str,
) -> dict[str, Any]:
    """Produce one exact ``valuation-execution-v1`` under the frozen Gate-D laws.

    Prior reviewed close ``t`` authorizes exactly one complete transition fill at
    the next sequence session open ``t+1``; slippage moves the effective price and
    is never a second cash debit; commission is charged once on effective
    notional; buys deploy all available cash into fractional shares and sells
    liquidate every held share.  Global window indices are never rebased.
    """
    # isinstance guards run before membership so unhashable values fail closed
    # with the typed contract error instead of leaking a TypeError.
    if not isinstance(role, str) or role not in _ROLES:
        _fail("unsupported execution role")
    if not isinstance(purpose, str) or purpose not in _DIRECT_PURPOSES:
        _fail("unsupported direct purpose")
    rule_value = _frozen_rule(rule)
    costs_value = _frozen_costs(costs)
    multiplier = _finite_number(cost_multiplier, "cost_multiplier")
    # The reviewed Strategy DSL bounds declared stress multipliers to 0..10.
    if not 0 <= multiplier <= 10:
        _fail("cost_multiplier must be within 0 and 10")
    spec_hash = _sha(spec_hash, "spec_hash")
    snapshot_sha256 = _sha(snapshot_sha256, "snapshot_sha256")
    frame_start = _integer(frame_start_index, "frame_start_index")
    start = _integer(start_index, "start_index")
    end = _integer(end_index_exclusive, "end_index_exclusive", minimum=1)
    if end <= start:
        _fail("end_index_exclusive must exceed start_index")
    if start < frame_start:
        _fail("start_index precedes the physical frame origin")
    carry = _canonical_carry(carry_in, "carry_in")

    commission_rate = costs_value["commission_bps"] * multiplier / 1e4
    slippage_rate = costs_value["slippage_bps"] * multiplier / 1e4
    if not math.isfinite(commission_rate) or not math.isfinite(slippage_rate):
        _fail("computed execution rates must be finite")
    if slippage_rate >= 1:
        _fail("slippage rate must stay below 1 to keep adverse sell prices positive")

    if role == "strategy":
        if benchmark_entry_index is not None:
            _fail("strategy executions take no benchmark entry index")
    else:
        benchmark_entry_index = _integer(
            benchmark_entry_index, "benchmark_entry_index",
        )
        # The single benchmark entry must be consistent with the incoming carry:
        # an entry before this window demands an already-long carry (never a
        # silent re-entry); an entry inside or after it demands a flat carry.
        if benchmark_entry_index < start and carry["position"] != 1:
            _fail("benchmark carry must already be long after its one entry")
        if benchmark_entry_index >= start and carry["position"] != 0:
            _fail("benchmark carry cannot be long before its one entry")

    if purpose == "final_holdout":
        # The final holdout runs from fresh capital at base costs only.
        if multiplier != 1.0:
            _fail("final_holdout executions must use the 1.0 cost multiplier")
        if carry["position"] != 0 or carry["shares"] != 0.0:
            _fail("final_holdout executions cannot inherit development carry")
        if role == "benchmark" and benchmark_entry_index != start:
            _fail(
                "final_holdout benchmark must enter exactly at its first "
                "accounting session"
            )

    dates, opens, closes = _frame_rows(frame, end - frame_start, "frame")
    first_local = start - frame_start
    if role == "strategy" and first_local < _slowest_window(rule_value):
        _fail(
            "insufficient signal warm-up: the physical history must contain the "
            "complete slowest moving-average window before the first accounting "
            "session"
        )
    if role == "strategy" and first_local < 1:
        _fail("the first accounting session requires a prior reviewed close")

    cash = float(carry["cash"])
    shares = float(carry["shares"])
    position = int(carry["position"])
    bars: list[dict[str, Any]] = []
    fills: list[dict[str, Any]] = []
    for global_index in range(start, end):
        local = global_index - frame_start
        session = dates[local]
        if role == "strategy":
            desired = _desired_strategy_position(rule_value, closes, local - 1)
        else:
            desired = global_index >= int(benchmark_entry_index)  # type: ignore[arg-type]
        commission_today = 0.0
        slippage_today = 0.0
        if desired and position == 0:
            if cash <= 0:
                _fail(f"zero cash for a required buy at session {session}")
            reference_price = opens[local]
            effective_price = reference_price * (1 + slippage_rate)
            if effective_price <= 0 or not math.isfinite(effective_price):
                _fail(f"invalid effective buy price at session {session}")
            buy_shares = cash / (effective_price * (1 + commission_rate))
            executed_notional = buy_shares * effective_price
            commission = executed_notional * commission_rate
            slippage_amount = buy_shares * (effective_price - reference_price)
            fills.append({
                "side": "buy", "shares": buy_shares,
                "reference_price": reference_price,
                "effective_price": effective_price,
                "executed_notional": executed_notional,
                "commission": commission,
                "slippage_amount": slippage_amount,
                "session": session,
            })
            # The full-notional sizing law makes this identically zero; writing
            # the zero avoids a sign-flipping rounding residue in sealed cash.
            cash = 0.0
            shares = buy_shares
            position = 1
            commission_today += commission
            slippage_today += slippage_amount
        elif not desired and position == 1:
            reference_price = opens[local]
            effective_price = reference_price * (1 - slippage_rate)
            if effective_price <= 0 or not math.isfinite(effective_price):
                _fail(f"invalid effective sell price at session {session}")
            shares_sold = shares
            executed_notional = shares_sold * effective_price
            commission = executed_notional * commission_rate
            slippage_amount = shares_sold * (reference_price - effective_price)
            fills.append({
                "side": "sell", "shares": shares_sold,
                "reference_price": reference_price,
                "effective_price": effective_price,
                "executed_notional": executed_notional,
                "commission": commission,
                "slippage_amount": slippage_amount,
                "session": session,
            })
            cash = cash + executed_notional - commission
            shares = 0.0
            position = 0
            commission_today += commission
            slippage_today += slippage_amount
        if cash < 0 or not math.isfinite(cash):
            _fail(f"cash became negative or non-finite at session {session}")
        close = closes[local]
        bars.append({
            "date": session, "close": close, "cash": cash, "shares": shares,
            "position_value": shares * close, "equity": cash + shares * close,
            "position": position, "daily_commission": commission_today,
            "daily_slippage": slippage_today, "cash_return": 0.0,
        })

    window = {
        "start_date": dates[first_local],
        "end_date": dates[end - frame_start - 1],
        "start_index": start,
        "end_index_exclusive": end,
        "observation_count": end - start,
    }
    return build_execution_v1(
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        role=role,
        purpose=purpose,
        window=window,
        cost_multiplier=multiplier,
        carry_in=carry,
        carry_out={"cash": cash, "shares": shares, "position": position},
        bars=bars,
        fills=fills,
    )


def make_adverse_fill_segment_executor_v1(
    *,
    rule: Mapping[str, Any],
    costs: Mapping[str, Any],
    development_evaluation_start: int,
) -> Callable[..., Mapping[str, Mapping[str, Any]]]:
    """Freeze reviewed inputs and return the exact Gate-C segment executor.

    The returned keyword-only callable emits one strategy/benchmark ``fold_slice``
    pair per call, uses frame origin zero for Gate-C development prefixes, and
    treats ``development_evaluation_start`` as the benchmark's single global entry
    index.  This factory never imports the Gate-C coordinator: tests inject the
    callable, preserving the dependency direction.
    """
    frozen_rule = _frozen_rule(rule)
    frozen_costs = _frozen_costs(costs)
    entry_index = _integer(
        development_evaluation_start, "development_evaluation_start",
    )

    def segment_executor(**kwargs: Any) -> dict[str, dict[str, Any]]:
        if set(kwargs) != _EXECUTOR_KEYS:
            _fail("segment executor requires exactly the Gate-C keyword protocol")
        fold = kwargs["fold"]
        if not isinstance(fold, MappingABC):
            _fail("fold must be a mapping")
        test_start = _integer(fold.get("test_start_index"), "fold.test_start_index")
        test_end = _integer(
            fold.get("test_end_index"), "fold.test_end_index", minimum=1,
        )
        # A misbound factory must not be able to create a delayed benchmark
        # entry: a flat incoming carry demands the entry be exactly THIS fold's
        # first test session, and a long carry demands a strictly earlier one.
        benchmark_carry = _canonical_carry(
            kwargs["benchmark_carry_in"], "benchmark_carry_in",
        )
        if benchmark_carry["position"] == 0 and entry_index != test_start:
            _fail(
                "a flat benchmark carry requires the development evaluation "
                "entry to equal this fold's first test session"
            )
        if benchmark_carry["position"] == 1 and entry_index >= test_start:
            _fail(
                "a long benchmark carry requires the development evaluation "
                "entry to be strictly earlier than this fold"
            )
        strategy_prefix = kwargs["strategy_prefix"]
        benchmark_prefix = kwargs["benchmark_prefix"]
        strategy_dates, _opens, _closes = _frame_rows(
            strategy_prefix, test_end, "strategy_prefix",
        )
        benchmark_dates, _bopens, _bcloses = _frame_rows(
            benchmark_prefix, test_end, "benchmark_prefix",
        )
        if strategy_dates != benchmark_dates:
            _fail(
                "strategy and benchmark prefixes must share identical ordered "
                "session dates"
            )
        common = {
            "frame_start_index": 0,
            "start_index": test_start,
            "end_index_exclusive": test_end,
            "purpose": "fold_slice",
            "rule": copy.deepcopy(frozen_rule),
            "costs": copy.deepcopy(frozen_costs),
            "cost_multiplier": kwargs["cost_multiplier"],
            "spec_hash": kwargs["spec_hash"],
            "snapshot_sha256": kwargs["snapshot_sha256"],
        }
        return {
            "strategy": execute_adverse_fill_window_v1(
                frame=strategy_prefix,
                role="strategy",
                carry_in=kwargs["strategy_carry_in"],
                benchmark_entry_index=None,
                **common,
            ),
            "benchmark": execute_adverse_fill_window_v1(
                frame=benchmark_prefix,
                role="benchmark",
                carry_in=kwargs["benchmark_carry_in"],
                benchmark_entry_index=entry_index,
                **common,
            ),
        }

    return segment_executor


__all__ = [
    "ADVERSE_FILL_EXECUTION_VERSION",
    "execute_adverse_fill_window_v1",
    "make_adverse_fill_segment_executor_v1",
]
