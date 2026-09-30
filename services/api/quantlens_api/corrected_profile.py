"""Corrected validation profile admission source (Gate E Stop F5).

Doc 47 §A5: battery-v3 admission may open only when the exact activated
corrected release, the immutable run binding, the registered battery-v3
configuration and hash, the registered descriptor and restatement, and a
successful preflight all agree. This module owns the API-side identity for
three of those legs:

- the ADMISSION GATE (``corrected_admission_refusal``): the two-message
  fail-closed refusal stays for every store without an ACTIVE corrected
  release or with an incoherent sealed expectations file. Registration
  itself guarantees tuple exactness (``RELEASE_TUPLE_CANONICAL_SHA256``
  refuses any non-reviewed tuple), so an ACTIVE row is always the exact
  corrected release.
- the DESCRIPTOR (``corrected_profile_descriptor``): the profile hash
  comes ONLY from the sealed corrected read expectations file — the
  pin-checked API-side authority whose equality with the immutable
  battery-v3 configuration hash is a sealed F2a law. The API never imports
  the dormant worker configuration module.
- the RESTATEMENT (``corrected_profile_restatement``): the plain-language
  confirmation for the corrected profile, transforming the same registered
  clauses the battery-v2 restatement law owns and appending the corrected
  suffix (locked rule, expanding walk-forward, one-time externally
  controlled holdout, corrected financial semantics).

The DSL law also lives here: the reviewed corrected release tuple pins
``dsl_schema_version`` to 1.2, so admission refuses any other spec version
before descriptor work begins — a run that could never execute must never
be accepted.
"""

from __future__ import annotations

from . import db
from .corrected_read_expectations import (
    CorrectedReadExpectationsError,
    load_corrected_read_expectations,
)

BATTERY_V3_PROFILE = "battery-v3"
CORRECTED_DSL_VERSION = "1.2"


def corrected_admission_refusal() -> dict | None:
    """The typed two-message refusal, or None when admission is open.

    Message one: no ACTIVE corrected release exists. Message two: a release
    is ACTIVE but this service version cannot open acceptance for it — the
    sealed expectations file is missing, unpinned, malformed, or names a
    different activation release. Fail-closed and release-aware, never a
    feature flag.
    """
    release = db.get_active_release()
    if release is None:
        return {
            "code": "BATTERY_PROFILE_NOT_RELEASED",
            "message": ("The corrected validation profile is not part of "
                        "any activated release on this service."),
        }
    try:
        expectations = load_corrected_read_expectations()
    except CorrectedReadExpectationsError:
        expectations = None
    if (expectations is None
            or expectations.activation_release != release["release_id"]):
        return {
            "code": "BATTERY_PROFILE_NOT_RELEASED",
            "message": ("An activated release exists, but its registration "
                        "does not open acceptance for the corrected "
                        "validation profile on this service version."),
        }
    return None


def corrected_dsl_refusal(spec: dict) -> dict | None:
    """The corrected profile executes sealed DSL 1.2 licensed studies only."""
    if spec.get("dsl_version") == CORRECTED_DSL_VERSION:
        return None
    return {
        "code": "BATTERY_PROFILE_DSL_UNSUPPORTED",
        "message": ("The corrected validation profile executes only sealed "
                    "DSL 1.2 licensed-provider studies. Bind a sealed "
                    "licensed dataset and validate again."),
    }


def corrected_profile_descriptor() -> dict:
    """The registered battery-v3 descriptor from the sealed expectations file."""
    expectations = load_corrected_read_expectations()
    return {
        "profile_id": BATTERY_V3_PROFILE,
        "profile_hash": expectations.battery_config_hash,
        "plan_summary": {
            "mode": "expanding-fixed-rule",
            "rule_policy": "locked; no parameter selection",
            "final_holdout": (
                "externally controlled, one-time holdout released by a "
                "separate authority process"
            ),
            "financial_semantics": "corrected financial semantics (sealed)",
            "execution_model": "adverse effective fill price",
        },
    }


def corrected_restatement_suffix() -> str:
    return (
        " The corrected validation profile locks the confirmed rule before "
        "execution. It uses development-only expanding walk-forward "
        "evaluation without parameter tuning, then permits exactly one "
        "primary read of the final holdout, which is released one time by a "
        "separate external authority process and never re-opened. Results "
        "are sealed under the corrected financial semantics with adverse "
        "effective fill pricing; the evidence view for this profile opens "
        "only after the corrected release registry is re-sealed."
    )


def corrected_profile_restatement(base: str, spec: dict) -> str:
    """Replace v1-only claims before appending the corrected confirmation.

    Mirrors the registered battery-v2 restatement transformation law: the
    holdout clause and the legacy sweep clause are replaced, never merely
    appended to, so the confirmed text can never carry a stale legacy
    claim; a missing registered clause fails closed.
    """
    percent = int(round(
        float(spec["validation"]["is_oos_split"]["oos_fraction"]) * 100))
    first_marker = f"The final {percent}% of the window is held out-of-sample:"
    benchmark_marker = " Benchmark:"
    if first_marker not in base or benchmark_marker not in base:
        raise ValueError(
            "base restatement no longer exposes the registered holdout clause")
    prefix, tail = base.split(first_marker, 1)
    _old_holdout, after_holdout = tail.split(benchmark_marker, 1)
    value = (
        prefix
        + f"The final {percent}% is an externally controlled, single-use "
          "holdout released one time by a separate authority process. It is "
          "evaluated once at base costs after the rule and plan are locked; "
          "it is never used for tuning or counterfactuals."
        + benchmark_marker + after_holdout
    )
    sweep_marker = "The battery also sweeps MA windows"
    confirmation_marker = " Confirming runs"
    if sweep_marker not in value or confirmation_marker not in value:
        raise ValueError(
            "base restatement no longer exposes the legacy sweep clause")
    before_sweep, sweep_tail = value.split(sweep_marker, 1)
    _old_sweep, after_sweep = sweep_tail.split(confirmation_marker, 1)
    value = (
        before_sweep
        + "The battery uses fixed-rule expanding walk-forward folds on "
          "development data, development-only cost stress, and preregistered "
          "regime analysis under the corrected financial semantics. It "
          "performs no parameter search or selection and always reports "
          "falsification findings."
        + confirmation_marker + after_sweep
    )
    return value + corrected_restatement_suffix()


__all__ = [
    "BATTERY_V3_PROFILE",
    "CORRECTED_DSL_VERSION",
    "corrected_admission_refusal",
    "corrected_dsl_refusal",
    "corrected_profile_descriptor",
    "corrected_profile_restatement",
    "corrected_restatement_suffix",
]
