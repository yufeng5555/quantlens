"""Privacy-safe, deterministic facts for a future narrative planner.

``build_narrative_fact_catalog`` accepts only the already verified ``EvidenceViewV1``
projection.  It never reads a run directory, database row, upload, spec, confirmation
restatement, or other mutable/private source.  The result is a closed allowlist of facts
whose values resolve through JSON Pointers to sealed financial artifact payloads.

This module deliberately has no engine, battery, runner, artifact-writer, report, or API
dependency.  Structural checks here are defense in depth; they do not replace obtaining
the input through ``load_verified_evidence`` first.
"""

from __future__ import annotations

import hashlib
import math
import re


CATALOG_VERSION = "NarrativeFactCatalogV1"
EVIDENCE_VIEW_VERSION = "v1"
EVIDENCE_SEMANTICS_VERSION = "v1"

_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SYMBOL_RE = re.compile(r"[A-Z0-9][A-Z0-9._-]{0,15}")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CHECK_STATUSES = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})
_REQUIRED_ARTIFACT_KINDS = frozenset({
    "is_result", "oos_result", "cost_stress", "sensitivity", "falsification",
})
_CONTEXT_KEYS = frozenset({
    "segment", "series", "stress_multiplier", "grid_cell", "evaluation_windows",
    "data_label", "benchmark_symbol",
})


class NarrativeFactCatalogError(ValueError):
    """The supplied view cannot produce a strict, privacy-safe fact catalog."""


def _fail(message: str) -> None:
    raise NarrativeFactCatalogError(f"narrative fact catalog: {message}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _finite_number(value: object, label: str) -> int | float:
    _require(isinstance(value, (int, float)) and not isinstance(value, bool),
             f"{label} is not numeric")
    _require(math.isfinite(float(value)), f"{label} is not finite")
    return value


def _display_spec(unit: str) -> dict:
    specs = {
        "USD": {
            "notation": "currency",
            "scale": 1,
            "decimal_places": 2,
            "rounding_mode": "ROUND_HALF_EVEN",
            "currency": "USD",
        },
        "fraction": {
            "notation": "percent",
            "scale": 100,
            "decimal_places": 2,
            "rounding_mode": "ROUND_HALF_EVEN",
            "currency": None,
        },
        "ratio": {
            "notation": "decimal",
            "scale": 1,
            "decimal_places": 3,
            "rounding_mode": "ROUND_HALF_EVEN",
            "currency": None,
        },
        "count": {
            "notation": "integer",
            "scale": 1,
            "decimal_places": 0,
            "rounding_mode": "ROUND_HALF_EVEN",
            "currency": None,
        },
        "check_status": {
            "notation": "closed_enum",
            "scale": None,
            "decimal_places": None,
            "rounding_mode": "NOT_APPLICABLE",
            "currency": None,
        },
    }
    _require(unit in specs, f"unknown unit {unit!r}")
    return dict(specs[unit])


def _artifact_index(view: dict) -> dict[str, dict]:
    artifacts = view.get("artifacts")
    _require(isinstance(artifacts, list), "EvidenceViewV1.artifacts is missing")
    result: dict[str, dict] = {}
    for artifact in artifacts:
        _require(isinstance(artifact, dict), "artifact reference is not an object")
        kind = artifact.get("kind")
        artifact_id = artifact.get("artifact_id")
        sha256 = artifact.get("sha256")
        _require(isinstance(kind, str) and kind not in result,
                 "artifact kinds must be unique strings")
        _require(isinstance(sha256, str) and _HASH_RE.fullmatch(sha256) is not None,
                 f"artifact {kind!r} has an invalid SHA-256")
        _require(artifact_id == f"{kind}-{sha256[:12]}",
                 f"artifact {kind!r} id is not content-addressed")
        result[kind] = {
            "artifact_id": artifact_id,
            "artifact_sha256": sha256,
        }
    _require(_REQUIRED_ARTIFACT_KINDS <= result.keys(),
             "EvidenceViewV1 lacks a required claim-source artifact")
    identity = view.get("identity")
    _require(isinstance(identity, dict), "EvidenceViewV1.identity is missing")
    result_hash = "sha256:" + hashlib.sha256(
        "".join(sorted(item["artifact_sha256"] for item in result.values())).encode()
    ).hexdigest()
    _require(identity.get("result_hash") == result_hash,
             "artifact references are not bound to identity.result_hash")
    return result


def _artifact_payloads(view: dict) -> dict[str, dict]:
    results = view.get("results")
    _require(isinstance(results, dict), "EvidenceViewV1.results is missing")
    payloads = {
        "is_result": results.get("is"),
        "oos_result": results.get("oos"),
        "cost_stress": view.get("cost_stress"),
        "sensitivity": view.get("sensitivity"),
        "falsification": view.get("falsification"),
    }
    _require(all(isinstance(value, dict) for value in payloads.values()),
             "EvidenceViewV1 claim-source payload is missing")
    return payloads


def _resolve_json_pointer(payload: object, pointer: str) -> object:
    _require(isinstance(pointer, str) and pointer.startswith("/"),
             "fact JSON pointer must start with '/'")
    current = payload
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            _require(token in current, f"JSON pointer does not resolve: {pointer}")
            current = current[token]
        elif isinstance(current, list):
            _require(token.isdigit(), f"JSON pointer list token is invalid: {pointer}")
            index = int(token)
            _require(0 <= index < len(current), f"JSON pointer is out of range: {pointer}")
            current = current[index]
        else:
            _fail(f"JSON pointer traverses a scalar: {pointer}")
    return current


def _evaluation_windows(view: dict) -> dict[str, dict]:
    segments = view.get("segments")
    _require(isinstance(segments, dict), "EvidenceViewV1.segments is missing")
    windows: dict[str, dict] = {}
    for segment in ("is", "oos"):
        segment_value = segments.get(segment)
        _require(isinstance(segment_value, dict), f"{segment} segment is missing")
        evaluation = segment_value.get("evaluation")
        _require(isinstance(evaluation, dict),
                 f"{segment} evaluation window is missing")
        start = evaluation.get("start")
        end = evaluation.get("end")
        bars = evaluation.get("bars")
        _require(isinstance(start, str) and _DATE_RE.fullmatch(start) is not None,
                 f"{segment} evaluation start is unsafe or invalid")
        _require(isinstance(end, str) and _DATE_RE.fullmatch(end) is not None,
                 f"{segment} evaluation end is unsafe or invalid")
        _require(start <= end, f"{segment} evaluation window is reversed")
        _require(isinstance(bars, int) and not isinstance(bars, bool) and bars > 0,
                 f"{segment} evaluation bar count is invalid")
        windows[segment] = {"start": start, "end": end, "bars": bars}
    return windows


def _base_context(view: dict) -> tuple[str, str, dict[str, dict]]:
    identity = view.get("identity")
    _require(isinstance(identity, dict), "EvidenceViewV1.identity is missing")
    data_label = identity.get("data_label")
    _require(data_label in {"SYNTHETIC", "USER_UPLOADED", "LICENSED_PROVIDER"},
             "data label is outside the closed vocabulary")
    results = view["results"]
    is_symbol = results["is"].get("benchmark_symbol")
    oos_symbol = results["oos"].get("benchmark_symbol")
    _require(is_symbol == oos_symbol and isinstance(is_symbol, str)
             and _SYMBOL_RE.fullmatch(is_symbol) is not None,
             "benchmark symbol is inconsistent or unsafe")
    return data_label, is_symbol, _evaluation_windows(view)


def _context(*, data_label: str, benchmark_symbol: str, windows: dict[str, dict],
             segment: str, series: str, stress_multiplier: float | None = None,
             grid_cell: dict | None = None) -> dict:
    _require(segment in {"is", "oos", "is_vs_oos"}, "fact segment is invalid")
    _require(series in {"strategy", "comparison", "benchmark"},
             "fact series is invalid")
    relevant = ("is", "oos") if segment == "is_vs_oos" else (segment,)
    value = {
        "segment": segment,
        "series": series,
        "stress_multiplier": stress_multiplier,
        "grid_cell": grid_cell,
        "evaluation_windows": {key: dict(windows[key]) for key in relevant},
        "data_label": data_label,
        "benchmark_symbol": benchmark_symbol,
    }
    _require(value.keys() == _CONTEXT_KEYS, "fact context is incomplete")
    return value


def _fact(*, fact_id: str, artifact_kind: str, pointer: str, unit: str,
          context: dict, artifacts: dict[str, dict], payloads: dict[str, dict]) -> dict:
    _require(re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", fact_id) is not None,
             f"fact id is unstable or unsafe: {fact_id!r}")
    source = artifacts[artifact_kind]
    value = _resolve_json_pointer(payloads[artifact_kind], pointer)
    if unit == "check_status":
        _require(isinstance(value, str) and value in _CHECK_STATUSES,
                 f"{fact_id} is not a closed check status")
    else:
        _finite_number(value, fact_id)
        if unit == "count":
            _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
                     f"{fact_id} is not a non-negative integer count")
    _require(context.keys() == _CONTEXT_KEYS, f"{fact_id} context is incomplete")
    return {
        "fact_id": fact_id,
        "artifact_id": source["artifact_id"],
        "artifact_sha256": source["artifact_sha256"],
        "json_pointer": pointer,
        "value": value,
        "unit": unit,
        "display": _display_spec(unit),
        "context": context,
    }


_RESULT_METRICS = (
    ("initial_capital", "USD"),
    ("final_equity", "USD"),
    ("total_return", "fraction"),
    ("cagr", "fraction"),
    ("ann_vol", "fraction"),
    ("sharpe", "ratio"),
    ("max_drawdown", "fraction"),
    ("n_trades", "count"),
    ("total_costs", "USD"),
    ("exposure", "fraction"),
)
_SERIES_METRICS = (
    ("strategy", "strategy_metrics"),
    ("comparison", "comparison_strategy_metrics"),
    ("benchmark", "benchmark_metrics"),
)
_STRESS_METRICS = (
    ("total_return", "fraction"),
    ("sharpe", "ratio"),
    ("total_costs", "USD"),
)
_SENSITIVITY_METRICS = (
    ("sharpe", "ratio"),
    ("total_return", "fraction"),
    ("max_drawdown", "fraction"),
    ("n_trades", "count"),
    ("exposure", "fraction"),
)


def build_narrative_fact_catalog(evidence_view: object) -> dict:
    """Return ``NarrativeFactCatalogV1`` from a verified ``EvidenceViewV1`` only.

    The catalog is deterministic and contains no free text or caller-controlled metadata.
    Numeric values are finite; non-numeric values are limited to the closed finding-status
    enum.  Every value resolves to the named sealed artifact payload through its pointer.
    """
    _require(isinstance(evidence_view, dict), "input is not an EvidenceViewV1 object")
    view = evidence_view
    _require(view.get("evidence_view_version") == EVIDENCE_VIEW_VERSION,
             "input does not carry EvidenceViewV1")
    _require(view.get("evidence_semantics_version") == EVIDENCE_SEMANTICS_VERSION,
             "input was not projected under the required evidence semantics")

    artifacts = _artifact_index(view)
    payloads = _artifact_payloads(view)
    data_label, benchmark_symbol, windows = _base_context(view)
    facts: list[dict] = []

    for segment in ("is", "oos"):
        artifact_kind = f"{segment}_result"
        for series, metric_set in _SERIES_METRICS:
            context = _context(
                data_label=data_label,
                benchmark_symbol=benchmark_symbol,
                windows=windows,
                segment=segment,
                series=series,
            )
            for metric, unit in _RESULT_METRICS:
                facts.append(_fact(
                    fact_id=f"result.{segment}.{series}.{metric}",
                    artifact_kind=artifact_kind,
                    pointer=f"/{metric_set}/{metric}",
                    unit=unit,
                    context=context,
                    artifacts=artifacts,
                    payloads=payloads,
                ))

    stress_rows = payloads["cost_stress"].get("rows")
    _require(isinstance(stress_rows, list), "cost-stress rows are missing")
    for multiplier, multiplier_id in ((1.0, "1x"), (2.0, "2x")):
        matches = [
            (index, row) for index, row in enumerate(stress_rows)
            if isinstance(row, dict)
            and isinstance(row.get("multiplier"), (int, float))
            and not isinstance(row.get("multiplier"), bool)
            and math.isclose(float(row["multiplier"]), multiplier,
                             rel_tol=0.0, abs_tol=1e-12)
        ]
        _require(len(matches) == 1, f"cost-stress {multiplier_id} row is not unique")
        row_index, _row = matches[0]
        for segment in ("is", "oos"):
            context = _context(
                data_label=data_label,
                benchmark_symbol=benchmark_symbol,
                windows=windows,
                segment=segment,
                series="strategy",
                stress_multiplier=multiplier,
            )
            for metric, unit in _STRESS_METRICS:
                facts.append(_fact(
                    fact_id=f"cost_stress.{multiplier_id}.{segment}.{metric}",
                    artifact_kind="cost_stress",
                    pointer=f"/rows/{row_index}/{segment}/{metric}",
                    unit=unit,
                    context=context,
                    artifacts=artifacts,
                    payloads=payloads,
                ))

    sensitivity = payloads["sensitivity"]
    chosen_cell = sensitivity.get("chosen_cell")
    _require(isinstance(chosen_cell, dict), "sensitivity chosen cell is missing")
    ma_days = chosen_cell.get("ma_days")
    _require(isinstance(ma_days, int) and not isinstance(ma_days, bool) and ma_days > 0,
             "sensitivity chosen grid cell is invalid")
    sensitivity_context = _context(
        data_label=data_label,
        benchmark_symbol=benchmark_symbol,
        windows=windows,
        segment="is",
        series="strategy",
        grid_cell={"ma_days": ma_days},
    )
    for metric, unit in _SENSITIVITY_METRICS:
        facts.append(_fact(
            fact_id=f"sensitivity.chosen.{metric}",
            artifact_kind="sensitivity",
            pointer=f"/chosen_cell/{metric}",
            unit=unit,
            context=sensitivity_context,
            artifacts=artifacts,
            payloads=payloads,
        ))

    finding_contexts = {
        "oos_decay": _context(
            data_label=data_label, benchmark_symbol=benchmark_symbol, windows=windows,
            segment="is_vs_oos", series="strategy"),
        "cost_fragility": _context(
            data_label=data_label, benchmark_symbol=benchmark_symbol, windows=windows,
            segment="oos", series="strategy", stress_multiplier=2.0),
        "parameter_fragility": _context(
            data_label=data_label, benchmark_symbol=benchmark_symbol, windows=windows,
            segment="is", series="strategy", grid_cell={"ma_days": ma_days}),
    }
    findings = payloads["falsification"].get("findings")
    _require(isinstance(findings, list), "falsification findings are missing")
    for finding_id in ("oos_decay", "cost_fragility", "parameter_fragility"):
        matches = [(index, finding) for index, finding in enumerate(findings)
                   if isinstance(finding, dict) and finding.get("id") == finding_id]
        _require(len(matches) == 1, f"finding {finding_id} is not unique")
        index, _finding = matches[0]
        facts.append(_fact(
            fact_id=f"falsification.{finding_id}.status",
            artifact_kind="falsification",
            pointer=f"/findings/{index}/status",
            unit="check_status",
            context=finding_contexts[finding_id],
            artifacts=artifacts,
            payloads=payloads,
        ))

    fact_ids = [fact["fact_id"] for fact in facts]
    _require(len(fact_ids) == len(set(fact_ids)), "fact ids are not unique")
    return {
        "catalog_version": CATALOG_VERSION,
        "source_contract": {
            "evidence_view_version": EVIDENCE_VIEW_VERSION,
            "evidence_semantics_version": EVIDENCE_SEMANTICS_VERSION,
        },
        "fact_count": len(facts),
        "facts": facts,
    }
