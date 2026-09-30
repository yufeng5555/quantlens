"""Focused accessibility and fail-safe copy guards for the report surfaces."""

from __future__ import annotations

import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REPORT_TEMPLATE = (
    REPO
    / "services"
    / "backtest-worker"
    / "quantlens_worker"
    / "templates"
    / "report.html.j2"
)
REPORT_V2_TEMPLATE = REPORT_TEMPLATE.with_name("report_v2.html.j2")
REPORT_RENDERER = REPORT_TEMPLATE.parents[1] / "report.py"


def test_every_report_table_region_is_keyboard_focusable_and_named():
    template = REPORT_TEMPLATE.read_text()
    wrappers = re.findall(r'<div class="tablewrap"[^>]*>', template)
    assert len(wrappers) >= 8
    for wrapper in wrappers:
        assert 'role="region"' in wrapper
        assert 'tabindex="0"' in wrapper
        label = re.search(r'aria-labelledby="([^"]+)"', wrapper)
        assert label, wrapper
        assert f'id="{label.group(1)}"' in template


def test_every_report_table_header_is_nonempty_and_scoped():
    template = REPORT_TEMPLATE.read_text()
    headers = re.findall(r"<th\b[^>]*>.*?</th>", template, flags=re.DOTALL)
    assert headers
    for header in headers:
        opening = header.split(">", 1)[0]
        assert re.search(r'scope="(?:col|row)"', opening), header
        content = re.sub(r"<[^>]+>", "", header, flags=re.DOTALL)
        assert content.strip(), header


def test_missing_evidence_is_never_presented_as_pass():
    template = REPORT_TEMPLATE.read_text()
    for status in ("PASS", "FAIL", "INCONCLUSIVE", "NOT RUN"):
        assert status in template
    assert "Missing stress evidence is not a pass" in template
    assert "missing neighbor comparison must not be described as a pass" in template
    assert "required_evidence_missing" in template
    assert "default(1)" not in template
    assert "default(0) | money" not in template


def test_report_data_provenance_is_source_conditional_and_privacy_safe():
    template = REPORT_TEMPLATE.read_text()
    assert "data_label == 'USER_UPLOADED'" in template
    assert "source accuracy was not independently authenticated" in template
    for label in (
        "Dataset ID", "Dataset manifest SHA-256", "Adjustment convention", "Coverage"
    ):
        assert label in template
    # The report deliberately projects safe provenance fields rather than dumping the
    # snapshot manifest, where implementation-only storage metadata could later appear.
    for unsafe in ("original_filename", "local_path", "relative_storage_key"):
        assert unsafe not in template


def test_v2_report_never_joins_independent_development_and_final_equity_curves():
    template = REPORT_V2_TEMPLATE.read_text()
    renderer = REPORT_RENDERER.read_text()
    assert "{{ development_chart | safe }}" in template
    assert "{{ final_chart | safe }}" in template
    assert "{{ equity_chart | safe }}" not in template
    assert 'segment_label="Development"' in renderer
    assert 'segment_label="Final holdout"' in renderer
    assert "separate initial-capital bases" in template


def test_standard_report_never_joins_independent_is_and_oos_equity_curves():
    template = REPORT_TEMPLATE.read_text()
    renderer = REPORT_RENDERER.read_text()
    assert "{{ is_chart | safe }}" in template
    assert "{{ oos_chart | safe }}" in template
    assert "{{ equity_chart | safe }}" not in template
    assert 'segment_label="In-sample"' in renderer
    assert 'segment_label="Out-of-sample"' in renderer
    assert "separate initial-capital bases" in template


def test_v2_report_scopes_audit_status_and_discloses_investor_return_limits():
    template = " ".join(REPORT_V2_TEMPLATE.read_text().split())
    for expected in (
        "does <strong>not</strong> grade final-holdout performance",
        "split-adjusted price return",
        "Dividends and distributions are excluded",
        "Uninvested cash earns 0%",
        "Sharpe also uses rf = 0",
        "constant bps assumptions",
        "checks sample coverage only",
    ):
        assert expected in template


def test_every_report_version_discloses_zero_cash_yield():
    for path in (REPORT_TEMPLATE, REPORT_V2_TEMPLATE):
        assert "Uninvested cash earns 0%" in " ".join(path.read_text().split())


def test_product_shell_landmarks_and_controls_are_not_nested():
    # The mature application shell has one navigation sidebar and one compact top bar;
    # environment state lives in the workspace pill rather than a prototype warning.
    layout = (REPO / "apps" / "web" / "app" / "layout.tsx").read_text()
    header = (REPO / "apps" / "web" / "app" / "components" / "SiteHeader.tsx").read_text()
    # The same shell surface is a complementary landmark on desktop and a
    # modal dialog on narrow screens. Keep a neutral element so it never
    # retains an implicit complementary role while acting as a dialog.
    assert '<div\n        className="app-sidebar"' in header
    assert 'role={drawerMode && open ? "dialog" : "complementary"}' in header
    assert 'aria-modal={drawerMode && open ? true : undefined}' in header
    assert 'inert={drawerMode && !open ? true : undefined}' in header
    assert 'aria-hidden={drawerMode && !open ? true : undefined}' in header
    assert 'inert={drawerMode && open ? true : undefined}' in header
    assert 'aria-hidden={drawerMode && open ? true : undefined}' in header
    assert '<header className="app-topbar">' in header
    assert 'className="workspace-pill' in header
    assert "proto-banner" not in layout
    assert "proto-banner" not in header
    assert layout.count("<header") == 0, "layout must not add a second banner landmark"

    for relative in ("page.tsx", "runs/[id]/page.tsx", "runs/[id]/EvidenceWorkspace.tsx",
                     "methodology/page.tsx", "components/SiteHeader.tsx"):
        source = (REPO / "apps" / "web" / "app" / relative).read_text()
        assert not re.search(
            r"<(?:Link|a)\b[^>]*>\s*<button\b", source, flags=re.DOTALL
        )
