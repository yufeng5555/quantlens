"""Template-only Strategy Evidence Report renderer (no LLM anywhere at Gate 2).

Every number is read from sealed artifact payloads and rendered with fixed template
sentences. Copy discipline: no recommendation/approval/certainty language (AT-11.4 /
AT-13.10 subset); the standing disclosure and synthetic-data labels are non-dismissible
template blocks.
"""

from __future__ import annotations

import json
import os
import copy
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .artifacts import load_presentation_artifacts, load_sealed_artifacts
from .evidence import build_evidence_view

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _fmt_pct(value, digits: int = 2) -> str:
    if value is None:
        return "—"
    return f"{value * 100:+.{digits}f}%"


def _fmt_num(value, digits: int = 2) -> str:
    if value is None:
        return "—"
    return f"{value:.{digits}f}"


def _fmt_money(value) -> str:
    if value is None:
        return "—"
    return f"${value:,.2f}"


def _build_environment() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR),
                      autoescape=select_autoescape(["html", "j2"]))
    env.filters["pct"] = _fmt_pct
    env.filters["num"] = _fmt_num
    env.filters["money"] = _fmt_money
    return env


# One Environment for the process, so each template is parsed once instead of on every
# render. Jinja caches compiled templates on the Environment, and this one is built from
# immutable inputs -- a fixed directory and three pure formatters -- so sharing it
# changes no rendered byte. Measured on the legacy template: 26.1ms -> 15.8ms.
#
# Deliberately banked rather than taken on its own: report.py is hashed into the
# worker's image digest, so it was only worth spending alongside a re-seal the template
# corrections were already forcing.
_ENVIRONMENT = _build_environment()


def equity_svg(is_series: dict, oos_series: dict, is_bench: dict, oos_bench: dict,
               width: int = 900, height: int = 280) -> str:
    """Deterministic inline SVG: strategy vs benchmark equity, IS/OOS visually separated
    by a divider. A data table accompanies the chart in the template (AT-13.7)."""
    dates = is_series["date"] + oos_series["date"]
    equity = is_series["equity"] + oos_series["equity"]
    if not dates:
        return "<svg role='img' aria-label='No equity data'></svg>"
    bench_dates = is_bench["date"] + oos_bench["date"]
    bench_eq = is_bench["equity"] + oos_bench["equity"]

    all_vals = equity + bench_eq
    lo, hi = min(all_vals), max(all_vals)
    pad = (hi - lo) * 0.05 or 1.0
    lo, hi = lo - pad, hi + pad
    n = len(dates)
    x_of = lambda i: 60 + (width - 80) * (i / max(n - 1, 1))
    y_of = lambda v: 20 + (height - 60) * (1 - (v - lo) / (hi - lo))

    def poly(xs, vs):
        return " ".join(f"{x_of(i):.1f},{y_of(v):.1f}" for i, v in zip(xs, vs))

    strat_pts = poly(range(n), equity)
    date_index = {d: i for i, d in enumerate(dates)}
    bench_idx = [date_index[d] for d in bench_dates if d in date_index]
    bench_pts = poly(bench_idx, bench_eq[: len(bench_idx)])
    split_x = x_of(len(is_series["date"]) - 0.5) if oos_series["date"] else None

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Equity curves: strategy and benchmark, in-sample and out-of-sample separated" '
        f'style="max-width:100%;height:auto;background:#fbfcfd;border:1px solid #d9e0e7;border-radius:8px">',
        f'<text x="60" y="16" font-size="12" fill="#4a5a68">equity ({_fmt_money(lo)} – {_fmt_money(hi)})</text>',
    ]
    if split_x is not None:
        parts.append(f'<line x1="{split_x:.1f}" y1="20" x2="{split_x:.1f}" y2="{height-30}" '
                     f'stroke="#a4262c" stroke-dasharray="5,4" stroke-width="1.5"/>')
        parts.append(f'<text x="{split_x + 6:.1f}" y="34" font-size="12" fill="#a4262c">OOS starts (held-out primary estimate)</text>')
    if bench_pts:
        parts.append(f'<polyline points="{bench_pts}" fill="none" stroke="#8aa0b2" stroke-width="1.5"/>')
    parts.append(f'<polyline points="{strat_pts}" fill="none" stroke="#0a5c74" stroke-width="2"/>')
    parts.append(f'<text x="60" y="{height - 10}" font-size="12" fill="#4a5a68">{dates[0]} → {dates[-1]} · dark: strategy · light: benchmark (hold from first decision)</text>')
    parts.append("</svg>")
    return "".join(parts)


def segment_equity_svg(series: dict, benchmark: dict, *, segment_label: str,
                       width: int = 900, height: int = 260) -> str:
    """Render one validation segment on its own capital base.

    Validation Battery v2's development and final-holdout results are independent
    simulations that each start from the declared initial capital.  Joining their
    endpoints would imply a continuous portfolio that never existed, so this renderer
    deliberately accepts and draws exactly one segment.
    """
    dates = list(series.get("date") or [])
    equity = list(series.get("equity") or [])
    bench_dates = list(benchmark.get("date") or [])
    bench_eq = list(benchmark.get("equity") or [])
    if not dates or not equity:
        return (f"<svg role='img' aria-label='No {segment_label} equity data' "
                "style='max-width:100%;height:auto'></svg>")

    timeline = sorted(set(dates) | set(bench_dates))
    date_index = {value: idx for idx, value in enumerate(timeline)}
    all_vals = equity + bench_eq
    lo, hi = min(all_vals), max(all_vals)
    pad = (hi - lo) * 0.05 or 1.0
    lo, hi = lo - pad, hi + pad
    x_of = lambda i: 60 + (width - 80) * (i / max(len(timeline) - 1, 1))
    y_of = lambda value: 20 + (height - 60) * (1 - (value - lo) / (hi - lo))

    def poly(source_dates: list, values: list) -> str:
        return " ".join(
            f"{x_of(date_index[day]):.1f},{y_of(value):.1f}"
            for day, value in zip(source_dates, values)
            if day in date_index
        )

    strategy_points = poly(dates, equity)
    benchmark_points = poly(bench_dates, bench_eq)
    label = str(segment_label).replace("&", "and").replace('"', "")
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{label} equity curves: strategy and benchmark; independent capital base" '
        f'style="max-width:100%;height:auto;background:#fbfcfd;border:1px solid #d9e0e7;border-radius:8px">',
        f'<text x="60" y="16" font-size="12" fill="#4a5a68">equity ({_fmt_money(lo)} – {_fmt_money(hi)})</text>',
    ]
    if benchmark_points:
        parts.append(
            f'<polyline points="{benchmark_points}" fill="none" '
            'stroke="#8aa0b2" stroke-width="1.5"/>'
        )
    parts.append(
        f'<polyline points="{strategy_points}" fill="none" '
        'stroke="#0a5c74" stroke-width="2"/>'
    )
    parts.append(
        f'<text x="60" y="{height - 10}" font-size="12" fill="#4a5a68">'
        f'{dates[0]} → {dates[-1]} · dark: strategy · light: benchmark '
        '(hold from first decision)</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def _report_view(shared: dict) -> dict:
    """Renderer view model derived from the shared EvidenceViewV1 projection.

    The printable report and the interactive workspace read the same
    integrity-checked, semantically validated projection (06 §5.1), so their values
    cannot drift apart.
    """
    if shared.get("evidence_view_version") == "v2":
        return {
            "evidence_view_version": "v2",
            "spec": shared["assumptions"]["spec"],
            "restatement": shared["assumptions"]["restatement"],
            "development_result": shared["development_result"],
            "final_result": shared["final_holdout_result"],
            "final_audit": shared["final_holdout_execution_audit"],
            "walk_forward": shared["walk_forward"],
            "regime_analysis": shared["regime_analysis"],
            "development_cost_stress": copy.deepcopy(shared["cost_stress"]),
            "findings": shared["falsification"]["findings"],
            "validation_plan": shared["validation_plan"],
            "snapshot": shared["snapshot"],
            "data_provenance": shared["data_provenance"],
            "gaps": shared["data_gaps"],
            "evidence_complete": shared["status"]["evidence_complete"],
            "battery_status": shared["status"]["battery_status"],
        }
    cost_stress = copy.deepcopy(shared["cost_stress"])
    return {
        "spec": shared["assumptions"]["spec"],
        "restatement": shared["assumptions"]["restatement"],  # sealed receipt text
        "segments": shared["segments"],
        "is_result": shared["results"]["is"],
        "oos_result": shared["results"]["oos"],
        "oos_execution_audit": shared["oos_execution_audit"],
        "oos_executions": shared["oos_execution_audit"]["primary_evaluation_count"],
        "sensitivity": shared["sensitivity"],
        "cost_stress": cost_stress,
        "falsification": shared["falsification"],
        "snapshot": shared["snapshot"],
        "data_provenance": shared["data_provenance"],
        "gaps": shared["data_gaps"],
        "evidence_complete": shared["status"]["evidence_complete"],
        "battery_status": shared["status"]["battery_status"],
    }


def _render_report_html(
    run_dir: Path, *, expected_run: dict, presentation: bool,
) -> str:
    """Render after either the strict runtime or registered presentation loader.

    No caller may supply live battery objects, and no caller may serve a previously
    written file: the bytes returned here are bound to the shared EvidenceViewV1
    projection of this exact request. Any artifact, index, manifest, or receipt
    mismatch raises before Jinja sees a single value.
    """
    if presentation:
        manifest, ledger_index, payloads, artifact_contract = \
            load_presentation_artifacts(run_dir, expected_run=expected_run)
    else:
        manifest, ledger_index, payloads = load_sealed_artifacts(
            run_dir, expected_run=expected_run,
        )
        artifact_contract = None
    shared = build_evidence_view(manifest, ledger_index, payloads,
                                 receipt=expected_run["confirmation_receipt"])
    view = _report_view(shared)
    spec = view["spec"]
    env = _ENVIRONMENT

    artifact_ids = {e["kind"]: e["artifact_id"] for e in ledger_index["entries"]}
    artifact_hashes = {e["kind"]: e["sha256"] for e in ledger_index["entries"]}

    if view.get("evidence_view_version") == "v2":
        development_svg = segment_equity_svg(
            view["development_result"]["equity_series"],
            view["development_result"]["benchmark_series"],
            segment_label="Development",
        )
        final_svg = segment_equity_svg(
            view["final_result"]["equity_series"],
            view["final_result"]["benchmark_series"],
            segment_label="Final holdout",
        )
        return env.get_template("report_v2.html.j2").render(
            spec=spec, manifest=manifest, ledger=ledger_index,
            research_mode=expected_run.get("research_mode", "formal"),
            artifact_ids=artifact_ids, identity=shared["identity"],
            restatement=view["restatement"],
            development_result=view["development_result"],
            final_result=view["final_result"], final_audit=view["final_audit"],
            walk_forward=view["walk_forward"],
            regime_analysis=view["regime_analysis"],
            development_cost_stress=view["development_cost_stress"],
            findings=view["findings"], validation_plan=view["validation_plan"],
            evidence_complete=view["evidence_complete"],
            battery_status=view["battery_status"], snapshot=view["snapshot"],
            data_provenance=view["data_provenance"], gaps=view["gaps"],
            development_chart=development_svg, final_chart=final_svg,
            artifact_contract=(
                artifact_contract.public_descriptor()
                if artifact_contract is not None else None
            ),
        )

    is_svg = segment_equity_svg(
        view["is_result"]["equity_series"], view["is_result"]["benchmark_series"],
        segment_label="In-sample",
    )
    oos_svg = segment_equity_svg(
        view["oos_result"]["equity_series"], view["oos_result"]["benchmark_series"],
        segment_label="Out-of-sample",
    )

    return env.get_template("report.html.j2").render(
        spec=spec, manifest=manifest, ledger=ledger_index, artifact_ids=artifact_ids,
        research_mode=expected_run.get("research_mode", "formal"),
        artifact_hashes=artifact_hashes, identity=shared["identity"],
        segments=view["segments"],
        is_result=view["is_result"], oos_result=view["oos_result"],
        oos_executions=view["oos_executions"],
        oos_execution_audit=view["oos_execution_audit"],
        sensitivity=view["sensitivity"], cost_stress=view["cost_stress"],
        falsification=view["falsification"],
        evidence_complete=view["evidence_complete"], battery_status=view["battery_status"],
        snapshot=view["snapshot"], gaps=view["gaps"], restatement=view["restatement"],
        data_provenance=view["data_provenance"],
        is_chart=is_svg, oos_chart=oos_svg,
        spec_json=json.dumps(spec, indent=2, sort_keys=True),
        artifact_contract=(
            artifact_contract.public_descriptor()
            if artifact_contract is not None else None
        ),
    )


def render_report_html(run_dir: Path, *, expected_run: dict) -> str:
    """Render read-only HTML through the frozen historical presentation registry."""
    return _render_report_html(
        run_dir, expected_run=expected_run, presentation=True,
    )


def render_report(run_dir: Path, *, expected_run: dict) -> Path:
    """Render and atomically persist the report artifact for the worker pipeline."""
    # Worker publication is a current-runtime operation, not historical presentation.
    html = _render_report_html(
        run_dir, expected_run=expected_run, presentation=False,
    )
    out = run_dir / "report.html"
    tmp = run_dir / f".report.{os.getpid()}.tmp"
    try:
        tmp.write_text(html)
        os.replace(tmp, out)
    finally:
        tmp.unlink(missing_ok=True)
    return out
