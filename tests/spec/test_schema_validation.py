"""AT-2.1 — schema-invalid specs are rejected with JSON path, violated constraint, and a
suggested fix. Also AT-1.1's schema half: the supported draft validates."""

import copy

from quantlens_schema import default_spec, validate_full, validate_schema


def test_default_spec_is_valid():
    assert validate_full(default_spec()) == {"valid": True, "errors": []}


def test_crossover_spec_is_valid():
    spec = default_spec("QQQ")
    spec["rule"] = {"type": "ma_crossover", "fast_ma_days": 50, "ma_days": 200}
    assert validate_full(spec)["valid"]


def _first_error(spec):
    errors = validate_schema(spec)
    assert errors, "expected schema rejection"
    return errors[0]


def test_missing_required_field_reports_path_constraint_suggestion():
    spec = copy.deepcopy(default_spec())
    del spec["rule"]
    err = _first_error(spec)
    assert err["layer"] == "schema"
    assert err["constraint"] == "required"
    assert "rule" in err["message"]
    assert err["suggestion"]


def test_bad_ma_days_type_reports_json_path():
    spec = copy.deepcopy(default_spec())
    spec["rule"]["ma_days"] = "two hundred"
    err = _first_error(spec)
    assert err["json_path"] == "$.rule.ma_days"
    assert err["suggestion"].startswith("Use an integer MA window")


def test_ma_days_out_of_bounds_rejected():
    spec = copy.deepcopy(default_spec())
    spec["rule"]["ma_days"] = 5000
    err = _first_error(spec)
    assert err["json_path"] == "$.rule.ma_days"
    assert err["constraint"] == "maximum"


def test_unknown_field_rejected_closed_schema():
    spec = copy.deepcopy(default_spec())
    spec["surprise"] = True
    err = _first_error(spec)
    assert err["constraint"] == "additionalProperties"


def test_wrong_dsl_version_rejected():
    spec = copy.deepcopy(default_spec())
    spec["dsl_version"] = "2.0"
    err = _first_error(spec)
    assert err["json_path"] == "$.dsl_version"


def test_bad_date_format_rejected():
    spec = copy.deepcopy(default_spec())
    spec["data"]["range"]["start"] = "01/01/2005"
    err = _first_error(spec)
    assert "$.data.range.start" == err["json_path"]


def test_lint_and_scope_do_not_run_on_schema_invalid_input():
    spec = copy.deepcopy(default_spec())
    spec["rule"]["ma_days"] = -1
    result = validate_full(spec)
    assert not result["valid"]
    assert all(e["layer"] == "schema" for e in result["errors"])
