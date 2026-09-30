"""AT-2.2 — semantic lint rejects fast >= slow, end-before-start ranges, OOS bounds,
symbols outside the curated universe list — with named rule IDs."""

import copy

from quantlens_schema import default_spec, semantic_lint


def _rule_ids(spec):
    return {e["rule_id"] for e in semantic_lint(spec)}


def test_clean_spec_has_no_lint_errors():
    assert semantic_lint(default_spec()) == []


def test_fast_ge_slow_rejected():
    spec = copy.deepcopy(default_spec())
    spec["rule"] = {"type": "ma_crossover", "fast_ma_days": 200, "ma_days": 200}
    assert "LINT_FAST_LT_SLOW" in _rule_ids(spec)


def test_crossover_without_fast_rejected():
    spec = copy.deepcopy(default_spec())
    spec["rule"] = {"type": "ma_crossover", "fast_ma_days": None, "ma_days": 200}
    assert "LINT_CROSSOVER_NEEDS_FAST" in _rule_ids(spec)


def test_end_before_start_rejected():
    spec = copy.deepcopy(default_spec())
    spec["data"]["range"] = {"start": "2024-12-31", "end": "2005-01-01"}
    assert "LINT_DATE_ORDER" in _rule_ids(spec)


def test_range_too_short_for_windows_rejected():
    spec = copy.deepcopy(default_spec())
    spec["data"]["range"] = {"start": "2024-01-01", "end": "2024-12-31"}
    assert "LINT_RANGE_MIN_LENGTH" in _rule_ids(spec)


def test_oos_fraction_bounds_guard_overlap():
    for frac in (0.05, 0.6):
        spec = copy.deepcopy(default_spec())
        spec["validation"]["is_oos_split"]["oos_fraction"] = frac
        assert "LINT_OOS_FRACTION" in _rule_ids(spec), frac


def test_symbol_outside_curated_universe_rejected():
    spec = copy.deepcopy(default_spec())
    spec["universe"]["symbol"] = "ZZZ"
    ids = _rule_ids(spec)
    assert "LINT_SYMBOL_UNIVERSE" in ids


def test_benchmark_symbol_outside_universe_rejected():
    spec = copy.deepcopy(default_spec())
    spec["benchmark"]["symbol"] = "ZZZ"
    assert "LINT_BENCHMARK_UNIVERSE" in _rule_ids(spec)


def test_grid_must_contain_chosen_window():
    spec = copy.deepcopy(default_spec())
    spec["rule"]["ma_days"] = 120  # not in default grid
    assert "LINT_GRID_CONTAINS_CHOSEN" in _rule_ids(spec)


def test_stress_multipliers_must_include_base():
    spec = copy.deepcopy(default_spec())
    spec["validation"]["cost_stress"]["multipliers"] = [0, 2, 4]
    assert "LINT_STRESS_INCLUDES_BASE" in _rule_ids(spec)


def test_every_lint_error_names_rule_and_suggestion():
    spec = copy.deepcopy(default_spec())
    spec["universe"]["symbol"] = "ZZZ"
    spec["data"]["range"] = {"start": "2024-12-31", "end": "2005-01-01"}
    for err in semantic_lint(spec):
        assert err["rule_id"].startswith("LINT_")
        assert err["message"] and err["suggestion"] and err["json_path"]
