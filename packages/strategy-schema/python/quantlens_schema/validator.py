"""Strategy DSL v1.0/v1.1 validation: schema -> semantic lint -> scope check.

Error contract (AT-2.1/2.2/2.3):
- schema errors:  {"layer": "schema", "json_path": ..., "constraint": ..., "message": ..., "suggestion": ...}
- lint errors:    {"layer": "lint", "rule_id": ..., "json_path": ..., "message": ..., "suggestion": ...}
- scope errors:   {"layer": "scope", "code": ..., "message": ..., "supported_scope": ...,
                   "correction": {"template": <spec|None>, "notify_option": ...}}
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from datetime import date
from pathlib import Path

import jsonschema

DSL_SCHEMA_VERSION = "1.2"
SUPPORTED_DSL_VERSIONS = frozenset({"1.0", "1.1", "1.2"})

_PKG_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _PKG_ROOT / "schema" / "strategy-v1.json"
_SCHEMA_11_PATH = _PKG_ROOT / "schema" / "strategy-v1.1.json"
_SCHEMA_12_PATH = _PKG_ROOT / "schema" / "strategy-v1.2.json"
_MANIFEST_SCHEMA_PATH = _PKG_ROOT / "schema" / "manifest-v0.json"
_MANIFEST_V1_SCHEMA_PATH = _PKG_ROOT / "schema" / "manifest-v1.json"
_MANIFEST_V2_SCHEMA_PATH = _PKG_ROOT / "schema" / "manifest-v2.json"
_DATASET_MANIFEST_SCHEMA_PATH = _PKG_ROOT / "schema" / "dataset-manifest-v1.json"
_DATASET_MANIFEST_V2_SCHEMA_PATH = _PKG_ROOT / "schema" / "dataset-manifest-v2.json"
_UNIVERSE_PATH = _PKG_ROOT / "universe.json"

SUPPORTED_SCOPE_STATEMENT = (
    "QuantLens v1 supports exactly one strategy family — long/flat moving-average rules "
    "(price vs MA, or fast/slow MA crossover; long the ETF or in cash) — on a fixed, "
    "curated list of liquid US-listed ETFs, tested on daily data with next-open execution. "
    "Individual stocks, options, shorting, leverage, intraday data, crypto, rotation, and "
    "fixed-allocation portfolios are not supported yet. Gate 4 may bind one sealed, "
    "user-provided daily CSV dataset to that same single-asset rule family."
)


def load_schema(version: str = "1.0") -> dict:
    if version == "1.0":
        path = _SCHEMA_PATH
    elif version == "1.1":
        path = _SCHEMA_11_PATH
    elif version == "1.2":
        path = _SCHEMA_12_PATH
    else:
        raise ValueError(f"unsupported strategy schema version: {version!r}")
    return json.loads(path.read_text())


def load_manifest_schema(version: str = "v0") -> dict:
    if version == "v0":
        path = _MANIFEST_SCHEMA_PATH
    elif version == "v1":
        path = _MANIFEST_V1_SCHEMA_PATH
    elif version == "v2":
        path = _MANIFEST_V2_SCHEMA_PATH
    else:
        raise ValueError(f"unsupported run manifest version: {version!r}")
    return json.loads(path.read_text())


def load_dataset_manifest_schema(version: str = "dataset-v1") -> dict:
    """Load the closed dataset-manifest contract for one explicit version.

    ``dataset-v1`` remains the BYOD upload receipt. ``dataset-v2`` is reserved for
    normalized licensed-provider observations and deliberately has a different source
    and rights shape rather than weakening the existing upload schema.
    """
    if version == "dataset-v1":
        path = _DATASET_MANIFEST_SCHEMA_PATH
    elif version == "dataset-v2":
        path = _DATASET_MANIFEST_V2_SCHEMA_PATH
    else:
        raise ValueError(f"unsupported dataset manifest version: {version!r}")
    return json.loads(path.read_text())


def load_universe() -> dict:
    return json.loads(_UNIVERSE_PATH.read_text())


def universe_symbols() -> list[str]:
    return [s["symbol"] for s in load_universe()["symbols"]]


# ---------------------------------------------------------------- display names

NAME_MAX_LENGTH = 120

# C0/C1 control characters plus the Unicode line/paragraph separators, built from
# code points so no literal control byte ever lives in this source file.
_CONTROL_CHARS = re.compile(
    "[" + "".join(
        re.escape(chr(cp))
        for cp in (*range(0x00, 0x20), *range(0x7F, 0xA0), 0x2028, 0x2029)
    ) + "]"
)
_WHITESPACE_RUNS = re.compile(r"\s+")


def normalize_display_name(name: str) -> str:
    """Canonical display-name form: NFKC, control/newline characters stripped,
    whitespace collapsed, trimmed, bounded to NAME_MAX_LENGTH characters.

    Applied server-side before validation and hashing so a pasted name with
    embedded newlines or zero-width characters can never reach reports, sealed
    restatements, or run titles. Idempotent by construction."""
    normalized = unicodedata.normalize("NFKC", name)
    normalized = _CONTROL_CHARS.sub(" ", normalized)
    normalized = _WHITESPACE_RUNS.sub(" ", normalized).strip()
    return normalized[:NAME_MAX_LENGTH].strip()


def normalize_spec_names(spec: dict) -> dict:
    """Normalize the user-editable display name in place (when shaped correctly)
    and return the spec. Malformed shapes pass through for schema validation to
    reject with its usual error contract."""
    meta = spec.get("meta") if isinstance(spec, dict) else None
    if isinstance(meta, dict) and isinstance(meta.get("name"), str):
        meta["name"] = normalize_display_name(meta["name"])
    return spec


# ---------------------------------------------------------------- defaults

def default_spec(symbol: str = "SPY", name: str | None = None) -> dict:
    """The transparent defaults shown on every rule card (defaults are always displayed,
    never silently applied — AT-1.1/1.3)."""
    return {
        "dsl_version": "1.0",
        "meta": {"name": name or f"{symbol} trend filter"},
        "universe": {"symbol": symbol},
        "family": "ma_long_flat",
        "rule": {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 200},
        "calendar": {"frequency": "daily", "execution": "next_open"},
        "costs": {"commission_bps": 1, "slippage_bps": 5},
        "benchmark": {"type": "hold_from_first_decision", "symbol": "same_as_universe"},
        "data": {"snapshot_policy": "pinned", "range": {"start": "2005-01-01", "end": "2024-12-31"}},
        "validation": {
            "is_oos_split": {"oos_fraction": 0.3},
            "sensitivity": {"grid": {"ma_days": [100, 150, 200, 250]}},
            "cost_stress": {"multipliers": [0, 1, 2, 4]},
        },
    }


# Which spec fields carry defaults the user has not explicitly authored (UI labels these).
DEFAULT_FIELDS = [
    "rule.ma_days", "costs.commission_bps", "costs.slippage_bps", "benchmark",
    "data.range", "validation.is_oos_split.oos_fraction",
    "validation.sensitivity.grid.ma_days", "validation.cost_stress.multipliers",
]


# ---------------------------------------------------------------- layer 1: JSON Schema

_SUGGESTIONS = {
    "dsl_version": ('Use "1.0" for the bundled synthetic fixture, "1.1" for a sealed '
                    'user dataset, or "1.2" for a sealed licensed-provider dataset.'),
    "family": 'Set family to "ma_long_flat" — the only family v1 executes.',
    "rule": "Provide rule.type (price_vs_ma or ma_crossover) and rule.ma_days (2–400).",
    "ma_days": "Use an integer MA window between 2 and 400 days.",
    "fast_ma_days": "fast_ma_days must be an integer 2–400 (ma_crossover) or null (price_vs_ma).",
    "commission_bps": "Commission must be 0–100 basis points per fill.",
    "slippage_bps": "Slippage must be 0–100 basis points per fill.",
    "oos_fraction": "Use an out-of-sample fraction strictly between 0 and 1 (default 0.3).",
    "range": "Provide data.range.start and data.range.end as YYYY-MM-DD dates.",
    "symbol": "Use one uppercase ETF ticker from the curated list.",
    "execution": 'Only "next_open" execution is supported (decide at close t, fill at open t+1).',
    "frequency": 'Only "daily" frequency is supported in v1.',
}


def _suggestion_for(path: str, validator: str) -> str:
    for key, text in sorted(_SUGGESTIONS.items(), key=lambda kv: -len(kv[0])):
        if path.endswith(key) or f".{key}." in path + ".":
            return text
    if validator == "required":
        return "Add the missing required field; see the DSL v1.0 schema."
    if validator == "additionalProperties":
        return "Remove the unrecognized field; the v1 schema is closed (deferred keys are reserved explicitly)."
    return "See packages/strategy-schema/schema/strategy-v1.json for the allowed shape."


def validate_schema(spec: dict) -> list[dict]:
    # FormatChecker enforces real calendar dates for "format": "date" (impossible dates
    # like 2024-02-31 fail here with a JSON path, not deep in the engine).
    version = spec.get("dsl_version") if isinstance(spec, dict) else None
    if version not in SUPPORTED_DSL_VERSIONS:
        return [{
            "layer": "schema", "json_path": "$.dsl_version", "constraint": "const",
            "message": f"{version!r} is not a supported DSL version.",
            "suggestion": ('Use dsl_version "1.0" for bundled synthetic data, "1.1" '
                           'for a sealed user dataset, or "1.2" for licensed data.'),
        }]
    validator = jsonschema.Draft202012Validator(
        load_schema(version), format_checker=jsonschema.FormatChecker())
    errors = []
    for err in sorted(validator.iter_errors(spec), key=lambda e: list(e.absolute_path)):
        path = "$" + "".join(
            f"[{p}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path
        )
        errors.append({
            "layer": "schema",
            "json_path": path,
            "constraint": err.validator,
            "message": err.message,
            "suggestion": _suggestion_for(path, err.validator),
        })
    return errors


# ---------------------------------------------------------------- layer 2: semantic lint

MIN_RANGE_BARS_FACTOR = 2  # range must hold at least 2x the largest window in trading days


def _parse_date(s: str) -> date | None:
    try:
        return date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def semantic_lint(spec: dict, battery_profile: str = "battery-v1") -> list[dict]:
    """Named-rule lint (AT-2.2). Assumes schema-valid input.

    Battery v2 locks the confirmed rule and explicitly forbids parameter search.  Its
    legacy sensitivity-grid field remains in the closed DSL for compatibility, but it
    is not executed.  Profile-aware lint therefore must not let an unused grid reject
    an otherwise executable Strict-validation study.
    """
    errors: list[dict] = []

    def add(rule_id, path, message, suggestion):
        errors.append({"layer": "lint", "rule_id": rule_id, "json_path": path,
                       "message": message, "suggestion": suggestion})

    rule = spec["rule"]
    if rule["type"] == "ma_crossover":
        fast = rule.get("fast_ma_days")
        if fast is None:
            add("LINT_CROSSOVER_NEEDS_FAST", "$.rule.fast_ma_days",
                "ma_crossover requires fast_ma_days.", "Set fast_ma_days (e.g., 50) below ma_days.")
        elif fast >= rule["ma_days"]:
            add("LINT_FAST_LT_SLOW", "$.rule.fast_ma_days",
                f"fast_ma_days ({fast}) must be strictly less than ma_days ({rule['ma_days']}).",
                "Choose fast < slow, e.g., 50/200.")
    if rule["type"] == "price_vs_ma" and rule.get("fast_ma_days") is not None:
        add("LINT_FAST_UNUSED", "$.rule.fast_ma_days",
            "price_vs_ma does not use fast_ma_days.", "Set fast_ma_days to null.")

    start = _parse_date(spec["data"]["range"]["start"])
    end = _parse_date(spec["data"]["range"]["end"])
    for label, value in (("start", start), ("end", end)):
        if value is None:
            add("LINT_DATE_INVALID", f"$.data.range.{label}",
                f"{label} is not a real calendar date.",
                "Use a valid YYYY-MM-DD date.")
    if start and end:
        if end <= start:
            add("LINT_DATE_ORDER", "$.data.range",
                f"end ({end}) must be after start ({start}).", "Swap or widen the date range.")
        else:
            grid = spec["validation"]["sensitivity"]["grid"]["ma_days"]
            active_windows = [rule["ma_days"]]
            # battery-v2 and the corrected battery-v3 never execute the
            # legacy sensitivity grid; an unused grid must not reject an
            # otherwise executable locked-rule study.
            if battery_profile not in ("battery-v2", "battery-v3"):
                active_windows.extend(grid)
            max_window = max(active_windows)
            approx_bars = int((end - start).days * 5 / 7)
            need = max_window * MIN_RANGE_BARS_FACTOR
            if approx_bars < need:
                add("LINT_RANGE_MIN_LENGTH", "$.data.range",
                    f"Range holds ~{approx_bars} trading days; needs at least {need} "
                    f"(2x the largest MA window, {max_window}).",
                    "Widen the date range or shrink the MA windows / sensitivity grid.")

    frac = spec["validation"]["is_oos_split"]["oos_fraction"]
    if not (0.1 <= frac <= 0.5):
        add("LINT_OOS_FRACTION", "$.validation.is_oos_split.oos_fraction",
            f"oos_fraction {frac} outside [0.1, 0.5]; IS and OOS must both be substantial "
            "and can never overlap.", "Use a fraction between 0.1 and 0.5 (default 0.3).")
    if start and end and end > start:
        active_windows = [rule["ma_days"]]
        if battery_profile not in ("battery-v2", "battery-v3"):
            active_windows.extend(
                spec["validation"]["sensitivity"]["grid"]["ma_days"])
        max_window = max(active_windows)
        approx_bars = int((end - start).days * 5 / 7)
        approx_oos = max(1, int(round(approx_bars * frac)))
        approx_is = approx_bars - approx_oos
        if approx_is <= max_window:
            add("LINT_IS_EVALUATION_AFTER_WARMUP", "$.data.range",
                f"The split leaves about {approx_is} in-sample bars, which does not leave "
                f"an actionable evaluation bar after the shared {max_window}-bar warmup.",
                "Widen the range, reduce the largest MA window, or use a smaller OOS split.")

    symbols = universe_symbols()
    sym = spec["universe"]["symbol"]
    uploaded = spec.get("dsl_version") in {"1.1", "1.2"}
    if not uploaded and sym not in symbols:
        add("LINT_SYMBOL_UNIVERSE", "$.universe.symbol",
            f"{sym} is not in the curated liquid-US-ETF universe v1.",
            f"Choose one of: {', '.join(symbols)}.")
    bench = spec["benchmark"]["symbol"]
    if bench != "same_as_universe" and (uploaded or bench not in symbols):
        add("LINT_BENCHMARK_UNIVERSE", "$.benchmark.symbol",
            f"Benchmark symbol {bench} is not in the curated universe.",
            'Use "same_as_universe" or a curated-list symbol.')

    grid = spec["validation"]["sensitivity"]["grid"]["ma_days"]
    if battery_profile not in ("battery-v2", "battery-v3") \
            and rule["ma_days"] not in grid:
        add("LINT_GRID_CONTAINS_CHOSEN", "$.validation.sensitivity.grid.ma_days",
            f"The sensitivity grid must contain the chosen window ({rule['ma_days']}) so the "
            "chosen cell's neighborhood can be reported honestly (AT-9.1).",
            f"Add {rule['ma_days']} to the grid.")
    mults = spec["validation"]["cost_stress"]["multipliers"]
    if 1 not in mults and 1.0 not in mults:
        add("LINT_STRESS_INCLUDES_BASE", "$.validation.cost_stress.multipliers",
            "Cost-stress multipliers must include 1 (the base cost case).",
            "Add 1 to the multipliers list (default [0, 1, 2, 4]).")
    if 2 not in mults and 2.0 not in mults:
        add("LINT_STRESS_INCLUDES_2X", "$.validation.cost_stress.multipliers",
            "Cost-stress multipliers must include 2 so the declared cost-fragility check "
            "can reach a conclusive result.",
            "Add 2 to the multipliers list (default [0, 1, 2, 4]).")
    return errors


# ---------------------------------------------------------------- layer 3: scope check

def _nearest_template(spec: dict) -> dict | None:
    """Nearest supported template, pre-filled from the user's idea where possible (PRD §7)."""
    template = default_spec()
    sym = (spec.get("universe") or {}).get("symbol")
    if isinstance(sym, str) and sym in universe_symbols():
        template = default_spec(symbol=sym)
    template["meta"]["name"] = "Nearest supported template (MA trend filter)"
    return template


def scope_check(spec: dict) -> list[dict]:
    """Rejects reserved/deferred capabilities with explanation + correction path (AT-2.3/2.5)."""
    errors: list[dict] = []

    def add(code, message, notify):
        errors.append({
            "layer": "scope", "code": code, "message": message,
            "supported_scope": SUPPORTED_SCOPE_STATEMENT,
            "correction": {"template": _nearest_template(spec), "notify_option": notify},
        })

    fam = spec.get("family")
    if fam in ("rotation", "fixed_weights"):
        add("SCOPE_FAMILY_DEFERRED",
            f'Strategy family "{fam}" is reserved in the schema but deferred beyond v1.',
            f'Notify me when "{fam}" is supported (request stays in this workspace).')
    if (spec.get("universe") or {}).get("symbols") is not None:
        add("SCOPE_MULTI_ASSET_DEFERRED",
            "Multi-asset universes are deferred beyond v1; v1 tests exactly one curated ETF.",
            "Notify me when multi-asset universes are supported (request stays in this workspace).")
    validation = spec.get("validation") or {}
    for key in ("walk_forward", "regime"):
        if key in validation:
            add(f"SCOPE_{key.upper()}_DEFERRED",
                f'"{key}" is reserved in the schema but deferred beyond v1 '
                "(v1 battery: IS/OOS split, cost stress, parameter sensitivity, falsification).",
                f'Notify me when {key} is supported (request stays in this workspace).')
    return errors


def validate_full(spec: dict, battery_profile: str = "battery-v1") -> dict:
    """Full stack. Lint/scope only run when the schema layer passes."""
    schema_errors = validate_schema(spec)
    if schema_errors:
        return {"valid": False, "errors": schema_errors}
    errors = scope_check(spec) + semantic_lint(spec, battery_profile=battery_profile)
    return {"valid": not errors, "errors": errors}


# ---------------------------------------------------------------- hashing + restatement

def canonical_spec_json(spec: dict) -> str:
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def spec_hash(spec: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_spec_json(spec).encode()).hexdigest()


def restatement(spec: dict) -> str:
    """Plain-language restatement the user must confirm before any compute (AT-1.4)."""
    s = copy.deepcopy(spec)
    sym = s["universe"]["symbol"]
    rule = s["rule"]
    if rule["type"] == "price_vs_ma":
        rule_txt = (f"long {sym} whenever its closing price is above its "
                    f"{rule['ma_days']}-day moving average, otherwise fully in cash")
    else:
        rule_txt = (f"long {sym} whenever its {rule['fast_ma_days']}-day moving average is "
                    f"above its {rule['ma_days']}-day moving average, otherwise fully in cash")
    bench = s["benchmark"]["symbol"]
    bench_sym = sym if bench == "same_as_universe" else bench
    rng = s["data"]["range"]
    costs = s["costs"]
    validation = s["validation"]
    frac = validation["is_oos_split"]["oos_fraction"]
    grid = validation["sensitivity"]["grid"]["ma_days"]
    mults = validation["cost_stress"]["multipliers"]
    uploaded = s.get("dsl_version") in {"1.1", "1.2"}
    if uploaded:
        source = s["data"]["source"]
        if source.get("kind") == "licensed_provider":
            data_text = (
                "on the sealed LICENSED_PROVIDER daily dataset "
                f"{source['dataset_id']} (dataset manifest "
                f"{source['dataset_manifest_sha256'][:23]}...; provider rights are "
                "re-checked before run, report display, and export)"
            )
        else:
            data_text = (
                "on your sealed USER_UPLOADED daily dataset "
                f"{source['dataset_id']} (dataset manifest "
                f"{source['dataset_manifest_sha256'][:23]}...)"
            )
    else:
        data_text = "on SYNTHETIC sample data (bundled sample series — not market data)"
    # Every material field that affects the run appears here; the API binds confirmation
    # to the hash of exactly this spec, so a stale confirmation can never authorize a
    # changed spec (audit requirement on AT-1.4).
    return (
        f"You'll be {rule_txt}. Decisions use each day's close and execute at the next day's "
        f"open. Each trade pays {costs['commission_bps']} bps commission and "
        f"{costs['slippage_bps']} bps slippage. Test window: {rng['start']} to {rng['end']} "
        f"{data_text}. The final "
        f"{int(round(frac * 100))}% of the window is held out-of-sample: its primary 1x "
        f"estimate is evaluated exactly once, and the declared cost-stress multipliers "
        f"re-run it only as preregistered counterfactuals. Benchmark: buy-and-hold "
        f"{bench_sym} from your strategy's first tradable "
        f"decision, paying the same entry costs. The battery also sweeps MA windows "
        f"{', '.join(str(g) for g in grid)} on the in-sample window only, stresses costs at "
        f"{', '.join(f'{m}x' for m in mults)}, and always reports falsification findings. "
        f"Confirming runs this battery; it does not make this strategy advisable, and no "
        f"performance exists until the run completes."
    )
