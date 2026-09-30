"""Deterministic NarrativePlanV1 renderer and complete-output guard.

All financial numerals, units, contexts, and source references are inserted from the
server-built fact catalog.  Provider output never reaches the returned prose directly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN

from .narrative_contracts import (
    EXPLANATION_VIEW_VERSION,
    NARRATIVE_CATALOG_VERSION,
    NARRATIVE_PLAN_VERSION,
    NarrativeComparator,
    NarrativePlanItem,
    NarrativePlanV1,
    NarrativeTemplateId,
)


_HASH_RE = re.compile(r"[0-9a-f]{64}")
_RESULT_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")
_BINDING_RE = re.compile(r"evb1-[0-9a-f]{64}")
_FACT_ID_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_NUMERIC_TOKEN_RE = re.compile(
    r"(?<![\w])(?:[$€£])?[+\-]?(?:\d{1,3}(?:,\d{3})+|\d+)"
    r"(?:\.\d+)?(?:[eE][+\-]?\d+)?(?:%|bps?)?(?![\w])",
    re.IGNORECASE,
)
_MARKUP_RE = re.compile(
    r"(?:https?://|www\.|<\/?[a-z!][^>]*>|\[[^\]]+\]\([^)]*\)|`|\*\*|__|!\[|^\s*#{1,6}\s)",
    re.IGNORECASE | re.MULTILINE,
)
_CONTEXT_KEYS = {
    "segment", "series", "stress_multiplier", "grid_cell",
    "evaluation_windows", "data_label", "benchmark_symbol",
}
_FACT_KEYS = {
    "fact_id", "artifact_id", "artifact_sha256", "json_pointer",
    "value", "unit", "display", "context",
}
_UNITS = {"USD", "fraction", "ratio", "count", "check_status"}
_DISCLOSURE = (
    "Generated only from sealed evidence for research evaluation; "
    "it does not direct any action."
)
_TITLE = "Evidence-grounded performance summary"


class NarrativeGuardError(ValueError):
    """A plan, catalog, render, or policy check failed closed."""


def _fail(message: str) -> None:
    raise NarrativeGuardError(f"narrative guard: {message}")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise NarrativeGuardError("narrative guard: value is not canonical JSON") from exc


def _catalog_digest(catalog: dict) -> str:
    return hashlib.sha256(_canonical(catalog)).hexdigest()


def build_current_binding(evidence_view: dict, catalog: dict) -> dict:
    """Return the current opaque binding and its safe public provenance fields."""

    if not isinstance(evidence_view, dict) or not isinstance(catalog, dict):
        _fail("binding inputs are not objects")
    if evidence_view.get("evidence_view_version") != "v1":
        _fail("evidence view version is not current")
    if evidence_view.get("evidence_semantics_version") != "v1":
        _fail("evidence semantics version is not current")
    if catalog.get("catalog_version") != NARRATIVE_CATALOG_VERSION:
        _fail("fact catalog version is not current")
    identity = evidence_view.get("identity")
    if not isinstance(identity, dict):
        _fail("evidence identity is missing")
    result_hash = identity.get("result_hash")
    run_id = identity.get("run_id")
    manifest_sha256 = identity.get("manifest_sha256")
    ledger_index_sha256 = identity.get("ledger_index_sha256")
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        _fail("run id is invalid")
    if not isinstance(result_hash, str) or _RESULT_HASH_RE.fullmatch(result_hash) is None:
        _fail("result hash is invalid")
    if not isinstance(manifest_sha256, str) or _HASH_RE.fullmatch(manifest_sha256) is None:
        _fail("manifest hash is invalid")
    if not isinstance(ledger_index_sha256, str) or \
            _HASH_RE.fullmatch(ledger_index_sha256) is None:
        _fail("ledger-index hash is invalid")

    catalog_sha256 = _catalog_digest(catalog)
    public = {
        "run_id": run_id,
        "evidence_view_version": "v1",
        "evidence_semantics_version": "v1",
        "catalog_version": NARRATIVE_CATALOG_VERSION,
        "result_hash": result_hash,
        "manifest_sha256": manifest_sha256,
        "ledger_index_sha256": ledger_index_sha256,
        "catalog_sha256": catalog_sha256,
    }
    token = "evb1-" + hashlib.sha256(_canonical(public)).hexdigest()
    return {"opaque_evidence_binding": token, **public}


def _validate_current_binding(binding: dict, catalog: dict) -> None:
    if not isinstance(binding, dict) or set(binding) != {
        "opaque_evidence_binding", "run_id", "evidence_view_version",
        "evidence_semantics_version", "catalog_version", "result_hash",
        "manifest_sha256", "ledger_index_sha256", "catalog_sha256",
    }:
        _fail("binding shape is not closed")
    token = binding.get("opaque_evidence_binding")
    if not isinstance(token, str) or _BINDING_RE.fullmatch(token) is None:
        _fail("opaque evidence binding is invalid")
    public = {key: value for key, value in binding.items()
              if key != "opaque_evidence_binding"}
    if not isinstance(public.get("run_id"), str) or \
            re.fullmatch(r"[0-9a-f]{32}", public["run_id"]) is None:
        _fail("binding run id is invalid")
    if public.get("evidence_view_version") != "v1" or \
            public.get("evidence_semantics_version") != "v1" or \
            public.get("catalog_version") != NARRATIVE_CATALOG_VERSION:
        _fail("binding contract is stale")
    if not isinstance(public.get("result_hash"), str) or \
            _RESULT_HASH_RE.fullmatch(public["result_hash"]) is None:
        _fail("binding result hash is invalid")
    for key in ("manifest_sha256", "ledger_index_sha256"):
        if not isinstance(public.get(key), str) or _HASH_RE.fullmatch(public[key]) is None:
            _fail(f"binding {key} is invalid")
    if public.get("catalog_sha256") != _catalog_digest(catalog):
        _fail("binding fact-catalog hash is stale")
    expected = "evb1-" + hashlib.sha256(_canonical(public)).hexdigest()
    if token != expected:
        _fail("binding is stale or the fact catalog changed")


_TEMPLATE_RULES = {
    NarrativeTemplateId.OOS_TOTAL_RETURN: {
        "fact_ids": (
            "result.oos.comparison.total_return",
            "result.oos.benchmark.total_return",
        ),
        "comparator": NarrativeComparator.HIGHER_VALUE,
        "units": ("fraction", "fraction"),
        "contexts": (("oos", "comparison"), ("oos", "benchmark")),
    },
    NarrativeTemplateId.OOS_MAX_DRAWDOWN: {
        "fact_ids": (
            "result.oos.comparison.max_drawdown",
            "result.oos.benchmark.max_drawdown",
        ),
        "comparator": NarrativeComparator.SMALLER_ABSOLUTE_MAGNITUDE,
        "units": ("fraction", "fraction"),
        "contexts": (("oos", "comparison"), ("oos", "benchmark")),
    },
    NarrativeTemplateId.OOS_COST_STRESS: {
        "fact_ids": (
            "cost_stress.1x.oos.total_return",
            "cost_stress.2x.oos.total_return",
        ),
        "comparator": NarrativeComparator.HIGHER_VALUE,
        "units": ("fraction", "fraction"),
        "contexts": (("oos", "strategy"), ("oos", "strategy")),
    },
    NarrativeTemplateId.FALSIFICATION_STATUS: {
        "fact_ids": (
            "falsification.oos_decay.status",
            "falsification.cost_fragility.status",
            "falsification.parameter_fragility.status",
        ),
        "comparator": NarrativeComparator.STATUS_ONLY,
        "units": ("check_status", "check_status", "check_status"),
        "contexts": (
            ("is_vs_oos", "strategy"),
            ("oos", "strategy"),
            ("is", "strategy"),
        ),
    },
}


def canonical_narrative_plan(binding: dict) -> NarrativePlanV1:
    """Return the complete server-owned fallback plan."""

    return NarrativePlanV1(
        opaque_evidence_binding=binding["opaque_evidence_binding"],
        items=[
            NarrativePlanItem(
                template_id=template_id,
                fact_ids=list(rule["fact_ids"]),
                comparator=rule["comparator"],
            )
            for template_id, rule in _TEMPLATE_RULES.items()
        ],
    )


def _fact_index(catalog: dict) -> dict[str, dict]:
    if not isinstance(catalog, dict) or set(catalog) != {
        "catalog_version", "source_contract", "fact_count", "facts",
    }:
        _fail("fact catalog shape is not closed")
    if catalog.get("catalog_version") != NARRATIVE_CATALOG_VERSION:
        _fail("fact catalog version is unsupported")
    source = catalog.get("source_contract")
    if source != {"evidence_view_version": "v1", "evidence_semantics_version": "v1"}:
        _fail("fact catalog source contract is stale")
    facts = catalog.get("facts")
    if not isinstance(facts, list) or catalog.get("fact_count") != len(facts):
        _fail("fact catalog count is invalid")
    index: dict[str, dict] = {}
    for fact in facts:
        if not isinstance(fact, dict) or set(fact) != _FACT_KEYS:
            _fail("fact shape is not closed")
        fact_id = fact.get("fact_id")
        if not isinstance(fact_id, str) or _FACT_ID_RE.fullmatch(fact_id) is None or \
                fact_id in index:
            _fail("fact id is invalid or duplicated")
        artifact_id = fact.get("artifact_id")
        artifact_sha256 = fact.get("artifact_sha256")
        pointer = fact.get("json_pointer")
        if not isinstance(artifact_sha256, str) or \
                _HASH_RE.fullmatch(artifact_sha256) is None:
            _fail(f"fact {fact_id} hash is invalid")
        if not isinstance(artifact_id, str) or \
                not artifact_id.endswith("-" + artifact_sha256[:12]):
            _fail(f"fact {fact_id} source id and hash disagree")
        if not isinstance(pointer, str) or not pointer.startswith("/") or \
                any(char in pointer for char in "\r\n\x00"):
            _fail(f"fact {fact_id} pointer is invalid")
        if fact.get("unit") not in _UNITS:
            _fail(f"fact {fact_id} unit is invalid")
        if not isinstance(fact.get("context"), dict) or \
                set(fact["context"]) != _CONTEXT_KEYS:
            _fail(f"fact {fact_id} context is incomplete")
        value = fact.get("value")
        if fact["unit"] == "check_status":
            if value not in {"PASS", "FAIL", "INCONCLUSIVE"}:
                _fail(f"fact {fact_id} status is invalid")
        elif not isinstance(value, (int, float)) or isinstance(value, bool) or \
                not math.isfinite(float(value)):
            _fail(f"fact {fact_id} value is not finite numeric evidence")
        index[fact_id] = fact
    return index


def _validate_plan(plan: NarrativePlanV1, catalog: dict, binding: dict) -> dict[str, dict]:
    _validate_current_binding(binding, catalog)
    if plan.opaque_evidence_binding != binding["opaque_evidence_binding"]:
        _fail("plan carries a stale evidence binding")
    index = _fact_index(catalog)
    seen: set[NarrativeTemplateId] = set()
    for item in plan.items:
        if item.template_id in seen:
            _fail("plan repeats a template")
        seen.add(item.template_id)
        rule = _TEMPLATE_RULES.get(item.template_id)
        if rule is None:
            _fail("plan selected an unknown template")
        if tuple(item.fact_ids) != rule["fact_ids"]:
            _fail(f"{item.template_id.value} fact order or membership is invalid")
        if item.comparator is not rule["comparator"]:
            _fail(f"{item.template_id.value} comparison direction is invalid")
        for fact_id, unit, (segment, series) in zip(
            item.fact_ids, rule["units"], rule["contexts"], strict=True,
        ):
            fact = index.get(fact_id)
            if fact is None:
                _fail(f"plan references unknown fact {fact_id}")
            if fact["unit"] != unit:
                _fail(f"fact {fact_id} unit does not match its template")
            context = fact["context"]
            if context["segment"] != segment or context["series"] != series:
                _fail(f"fact {fact_id} context does not match its template")
        if item.template_id is NarrativeTemplateId.OOS_COST_STRESS:
            if index[item.fact_ids[0]]["context"]["stress_multiplier"] != 1.0 or \
                    index[item.fact_ids[1]]["context"]["stress_multiplier"] != 2.0:
                _fail("cost-stress template does not compare base and 2x context")
    return index


def validate_narrative_plan(
    plan: NarrativePlanV1, catalog: dict, binding: dict,
) -> None:
    """Validate a plan without rendering it; useful for atomic failure attribution."""

    _validate_plan(plan, catalog, binding)


def _decimal(value: object) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise NarrativeGuardError("narrative guard: fact is not decimal-safe") from exc
    if not result.is_finite():
        _fail("fact is not finite")
    return result


def _format_fact(fact: dict) -> str:
    unit = fact["unit"]
    value = fact["value"]
    if unit == "check_status":
        return {"PASS": "Pass", "FAIL": "Fail", "INCONCLUSIVE": "Inconclusive"}[value]
    display = fact.get("display")
    if not isinstance(display, dict) or display.get("rounding_mode") != "ROUND_HALF_EVEN":
        _fail(f"fact {fact['fact_id']} lacks HALF_EVEN display authority")
    places = display.get("decimal_places")
    scale = display.get("scale")
    if not isinstance(places, int) or not isinstance(scale, (int, float)):
        _fail(f"fact {fact['fact_id']} display specification is invalid")
    scaled = _decimal(value) * _decimal(scale)
    quantum = Decimal(1).scaleb(-places)
    rounded = scaled.quantize(quantum, rounding=ROUND_HALF_EVEN)
    if rounded == 0:
        rounded = abs(rounded)  # Never render a misleading negative zero.
    if unit == "USD":
        return f"${rounded:,.{places}f}"
    if unit == "fraction":
        return f"{rounded:.{places}f}%"
    if unit == "ratio":
        return f"{rounded:.{places}f}"
    if unit == "count":
        return f"{rounded:.0f}"
    _fail(f"fact {fact['fact_id']} unit is unsupported")
    raise AssertionError("unreachable")


def _citation(fact: dict) -> dict:
    return {
        "fact_id": fact["fact_id"],
        "value": fact["value"],
        "formatted_value": _format_fact(fact),
        "unit": fact["unit"],
        "context": copy.deepcopy(fact["context"]),
        "artifact_id": fact["artifact_id"],
        "artifact_sha256": fact["artifact_sha256"],
        "json_pointer": fact["json_pointer"],
    }


def _window(fact: dict, segment: str) -> tuple[str, str]:
    windows = fact["context"]["evaluation_windows"]
    window = windows.get(segment) if isinstance(windows, dict) else None
    if not isinstance(window, dict):
        _fail(f"fact {fact['fact_id']} lacks its evaluation window")
    start, end = window.get("start"), window.get("end")
    if not isinstance(start, str) or not isinstance(end, str):
        _fail(f"fact {fact['fact_id']} evaluation window is invalid")
    return start, end


def _display_number(fact: dict) -> Decimal:
    display = fact["display"]
    scaled = _decimal(fact["value"]) * _decimal(display["scale"])
    quantum = Decimal(1).scaleb(-display["decimal_places"])
    rounded = scaled.quantize(quantum, rounding=ROUND_HALF_EVEN)
    return abs(rounded) if rounded == 0 else rounded


def _higher_label(left: Decimal, right: Decimal, left_label: str, right_label: str) -> str:
    if left == right:
        return "The two values were equal"
    return f"{left_label if left > right else right_label} had the higher value"


def _smaller_absolute_label(
    left: Decimal, right: Decimal, left_label: str, right_label: str,
) -> str:
    left_abs, right_abs = abs(left), abs(right)
    if left_abs == right_abs:
        return "The two absolute declines were equal"
    return f"{left_label if left_abs < right_abs else right_label} had the smaller absolute decline"


def _render_block(item: NarrativePlanItem, index: dict[str, dict]) -> dict:
    facts = [index[fact_id] for fact_id in item.fact_ids]
    citations = [_citation(fact) for fact in facts]
    values = [citation["formatted_value"] for citation in citations]
    template_id = item.template_id

    if template_id is NarrativeTemplateId.OOS_TOTAL_RETURN:
        start, end = _window(facts[0], "oos")
        symbol = facts[1]["context"]["benchmark_symbol"]
        direction = _higher_label(
            _display_number(facts[0]), _display_number(facts[1]),
            "The benchmark-aligned strategy", f"The {symbol} benchmark",
        )
        text = (
            f"In the out-of-sample window ({start} to {end}), the benchmark-aligned "
            f"strategy's total "
            f"return was {values[0]}, while the {symbol} benchmark's was {values[1]}. "
            f"{direction}."
        )
    elif template_id is NarrativeTemplateId.OOS_MAX_DRAWDOWN:
        start, end = _window(facts[0], "oos")
        symbol = facts[1]["context"]["benchmark_symbol"]
        direction = _smaller_absolute_label(
            _display_number(facts[0]), _display_number(facts[1]),
            "The benchmark-aligned strategy", f"The {symbol} benchmark",
        )
        text = (
            f"In the out-of-sample window ({start} to {end}), maximum drawdown was "
            f"{values[0]} for the benchmark-aligned strategy and {values[1]} for the "
            f"{symbol} benchmark. "
            f"{direction}."
        )
    elif template_id is NarrativeTemplateId.OOS_COST_STRESS:
        start, end = _window(facts[0], "oos")
        direction = _higher_label(
            _display_number(facts[0]), _display_number(facts[1]),
            "The base-cost result", "The 2x-cost result",
        )
        text = (
            f"In the out-of-sample window ({start} to {end}), strategy total return "
            f"was {values[0]} at base cost and {values[1]} at 2× cost. {direction}."
        )
    elif template_id is NarrativeTemplateId.FALSIFICATION_STATUS:
        text = (
            f"The sealed checks reported out-of-sample decay: {values[0]}; cost "
            f"fragility: {values[1]}; and parameter fragility: {values[2]}."
        )
    else:  # pragma: no cover - strict enum plus rule validation makes this unreachable.
        _fail("unknown template reached renderer")
        raise AssertionError("unreachable")

    return {
        "template_id": template_id.value,
        "comparator": item.comparator.value,
        "fact_ids": list(item.fact_ids),
        "text": text,
        "citations": citations,
    }


def render_narrative_plan(plan: NarrativePlanV1, catalog: dict, binding: dict) -> dict:
    """Render one strict plan without accepting any provider-authored prose."""

    index = _validate_plan(plan, catalog, binding)
    return {
        "title": _TITLE,
        "format": "plain_text_blocks_v1",
        "blocks": [_render_block(item, index) for item in plan.items],
        "disclosure": _DISCLOSURE,
    }


_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ɡ": "g", "ı": "i",
})
_PROHIBITED_PHRASES = (
    "buy now", "sell now", "you should buy", "you should sell", "should invest",
    "investment advice", "financial advice", "recommended trade", "enter position",
    "exit position", "guaranteed", "guarantee", "risk free", "riskfree",
    "certain profit", "will outperform", "always wins", "never lose", "certified",
    "officially approved", "audited result", "completely safe", "safe investment",
)


def _policy_normalize(value: str) -> tuple[str, str]:
    value = unicodedata.normalize("NFKC", value).casefold().translate(_CONFUSABLES)
    value = "".join(
        char for char in unicodedata.normalize("NFKD", value)
        if unicodedata.category(char) not in {"Mn", "Cf", "Cc", "Cs"}
    )
    spaced = " ".join(re.sub(r"[^a-z0-9]+", " ", value).split())
    return spaced, spaced.replace(" ", "")


def _guard_policy_and_markup(value: str) -> None:
    if any(
        unicodedata.category(char) in {"Cf", "Cc", "Cs"}
        or unicodedata.bidirectional(char) in {
            "RLE", "RLO", "LRE", "LRO", "PDF", "FSI", "LRI", "RLI", "PDI",
        }
        for char in value
    ):
        _fail("rendered prose contains a control, zero-width, or bidi character")
    if _MARKUP_RE.search(value):
        _fail("rendered prose contains HTML, Markdown, or a link")
    normalized, compact = _policy_normalize(value)
    for phrase in _PROHIBITED_PHRASES:
        phrase_normalized, phrase_compact = _policy_normalize(phrase)
        if phrase_normalized in normalized or phrase_compact in compact:
            _fail("rendered prose violates action, certainty, safety, or certification policy")


def validate_narrative_text_policy(value: str) -> None:
    """Validate one plain-text renderer fragment under Unicode-normalized policy."""

    if not isinstance(value, str):
        _fail("rendered prose is not a string")
    _guard_policy_and_markup(value)


def _numeric_tokens(value: str) -> list[str]:
    normalized = unicodedata.normalize("NFKC", value).translate(str.maketrans({
        "−": "-", "﹣": "-", "－": "-", "＋": "+",
    }))
    return [match.group(0) for match in _NUMERIC_TOKEN_RE.finditer(normalized)]


def validate_owned_numeric_tokens(value: str, owned_parts: list[str]) -> None:
    """Reject scientific/bps/currency/Unicode numerals not owned by renderer parts."""

    if not isinstance(value, str) or not all(isinstance(part, str) for part in owned_parts):
        _fail("numeric ownership inputs are not strings")
    observed = _numeric_tokens(value)
    allowed = {token for part in owned_parts for token in _numeric_tokens(part)}
    if any(token not in allowed for token in observed):
        _fail("rendered prose contains a non-evidence numeral")


def _allowed_numeric_tokens(block: dict) -> set[str]:
    values: list[str] = []
    for citation in block["citations"]:
        values.append(citation["formatted_value"])
        context = citation["context"]
        benchmark_symbol = context.get("benchmark_symbol")
        if isinstance(benchmark_symbol, str):
            values.append(benchmark_symbol)
        multiplier = context.get("stress_multiplier")
        if multiplier is not None:
            values.append(str(int(multiplier)) if float(multiplier).is_integer()
                          else str(multiplier))
        grid_cell = context.get("grid_cell")
        if isinstance(grid_cell, dict):
            values.extend(str(value) for value in grid_cell.values())
        windows = context.get("evaluation_windows")
        if isinstance(windows, dict):
            for window in windows.values():
                if isinstance(window, dict):
                    values.extend(str(value) for value in window.values())
    return {token for value in values for token in _numeric_tokens(value)}


def guard_narrative_explanation(
    explanation: dict, plan: NarrativePlanV1, catalog: dict, binding: dict,
) -> None:
    """Reject any complete render that is not exactly reproducible from current facts."""

    _validate_current_binding(binding, catalog)
    expected = render_narrative_plan(plan, catalog, binding)
    if explanation != expected:
        _fail("rendered output differs from the deterministic server render")
    if not isinstance(explanation, dict) or set(explanation) != {
        "title", "format", "blocks", "disclosure",
    }:
        _fail("explanation shape is not closed")
    if explanation["title"] != _TITLE or explanation["format"] != \
            "plain_text_blocks_v1" or explanation["disclosure"] != _DISCLOSURE:
        _fail("standing title, format, or disclosure changed")

    _guard_policy_and_markup(explanation["title"])
    _guard_policy_and_markup(explanation["disclosure"])
    for block in explanation["blocks"]:
        if set(block) != {
            "template_id", "comparator", "fact_ids", "text", "citations",
        }:
            _fail("rendered block shape is not closed")
        _guard_policy_and_markup(block["text"])
        allowed = _allowed_numeric_tokens(block)
        validate_owned_numeric_tokens(block["text"], list(allowed))


__all__ = [
    "NarrativeGuardError",
    "build_current_binding",
    "canonical_narrative_plan",
    "guard_narrative_explanation",
    "render_narrative_plan",
    "validate_narrative_plan",
    "validate_narrative_text_policy",
    "validate_owned_numeric_tokens",
]
