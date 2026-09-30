"""AT-2.3 / AT-2.5 — out-of-scope and deferred-capability requests produce no runnable
spec; the response states the v1 supported scope and offers a correction path (nearest
supported template + notify-me), never a silent partial spec."""

import copy

from quantlens_schema import default_spec, validate_full
from quantlens_schema.validator import scope_check, SUPPORTED_SCOPE_STATEMENT


def test_clean_spec_passes_scope():
    assert scope_check(default_spec()) == []


def _assert_scope_error(errors, code):
    match = [e for e in errors if e["code"] == code]
    assert match, f"expected {code} in {[e.get('code') for e in errors]}"
    err = match[0]
    assert err["supported_scope"] == SUPPORTED_SCOPE_STATEMENT
    assert err["correction"]["notify_option"]
    template = err["correction"]["template"]
    assert template is not None
    assert validate_full(template)["valid"], "correction template must itself be runnable"


def test_rotation_family_deferred_with_template_path():
    spec = copy.deepcopy(default_spec())
    spec["family"] = "rotation"
    result = validate_full(spec)
    assert not result["valid"]
    _assert_scope_error(result["errors"], "SCOPE_FAMILY_DEFERRED")


def test_fixed_weights_family_deferred():
    spec = copy.deepcopy(default_spec())
    spec["family"] = "fixed_weights"
    _assert_scope_error(validate_full(spec)["errors"], "SCOPE_FAMILY_DEFERRED")


def test_walk_forward_reserved_key_rejected():
    spec = copy.deepcopy(default_spec())
    spec["validation"]["walk_forward"] = {"windows": 5}
    _assert_scope_error(validate_full(spec)["errors"], "SCOPE_WALK_FORWARD_DEFERRED")


def test_regime_reserved_key_rejected():
    spec = copy.deepcopy(default_spec())
    spec["validation"]["regime"] = {"segments": "auto"}
    _assert_scope_error(validate_full(spec)["errors"], "SCOPE_REGIME_DEFERRED")


def test_multi_asset_universe_deferred_and_template_keeps_users_symbol():
    spec = copy.deepcopy(default_spec("QQQ"))
    spec["universe"]["symbols"] = ["QQQ", "SPY"]
    errors = validate_full(spec)["errors"]
    _assert_scope_error(errors, "SCOPE_MULTI_ASSET_DEFERRED")
    err = [e for e in errors if e["code"] == "SCOPE_MULTI_ASSET_DEFERRED"][0]
    # nearest template is pre-filled from the user's idea where possible (PRD §7)
    assert err["correction"]["template"]["universe"]["symbol"] == "QQQ"
