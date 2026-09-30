"""AT-3.1 (engine level) — same spec+snapshot+engine => byte-identical serialized outputs.
AT-3.3 — pinning enforced: all Python and web dependencies are exact-pinned and lockfiles
exist. (Battery/ledger-level determinism is covered in tests/e2e; twice-daily CI is S5.)"""

import json
import re
from pathlib import Path

from quantlens_worker.config import image_digest
from quantlens_worker.engine import backtest
from tests.conftest import bday_frame

REPO = Path(__file__).resolve().parents[2]


def _serialize(result) -> str:
    return json.dumps({
        "equity": result["equity"].to_dict(orient="list"),
        "trades": result["trades"],
        "benchmark": result["benchmark"].to_dict(orient="list"),
    }, sort_keys=True)


def test_engine_output_byte_identical_across_runs():
    closes = [100.0 + 10.0 * ((i // 7) % 2) + 0.3 * i for i in range(90)]
    df = bday_frame("2023-06-01", closes)
    rule = {"type": "ma_crossover", "fast_ma_days": 4, "ma_days": 12}
    costs = {"commission_bps": 2, "slippage_bps": 3}
    a = _serialize(backtest(df, rule, costs))
    b = _serialize(backtest(df.copy(deep=True), rule, costs))
    assert a == b


def test_python_requirements_exact_pinned_with_lockfile():
    lines = [ln.strip() for ln in (REPO / "requirements.txt").read_text().splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    for ln in lines:
        assert re.fullmatch(r"[A-Za-z0-9_.\-\[\]]+==[A-Za-z0-9_.\-]+", ln), \
            f"unpinned python dependency: {ln}"
    assert (REPO / "requirements-lock.txt").exists(), "pip freeze lockfile missing"


def test_web_dependencies_exact_pinned_with_lockfile():
    pkg = json.loads((REPO / "apps" / "web" / "package.json").read_text())
    for section in ("dependencies", "devDependencies"):
        for name, version in pkg.get(section, {}).items():
            assert re.fullmatch(r"\d+\.\d+\.\d+", version), \
                f"unpinned web dependency: {name}@{version}"
    assert (REPO / "apps" / "web" / "package-lock.json").exists(), "npm lockfile missing"


def test_local_execution_digest_binds_runtime_and_thread_limits(monkeypatch):
    monkeypatch.setenv("OMP_NUM_THREADS", "1")
    one_thread = image_digest()
    assert re.fullmatch(r"local-runtime-sha256:[0-9a-f]{64}", one_thread)
    monkeypatch.setenv("OMP_NUM_THREADS", "2")
    assert image_digest() != one_thread
