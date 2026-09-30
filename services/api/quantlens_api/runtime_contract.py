"""Fail-closed compatibility contract shared by the API and local worker.

The SQLite queue is intentionally small and local, but it can still be corrupted when
an older worker process remains alive while a newer API starts enqueueing work.  Each
accepted run is therefore stamped with the worker protocol it requires.  The database
claim trigger calls a connection-local SQLite function, so a legacy worker that neither
knows nor registers that function cannot move a queued run into execution.
"""

from __future__ import annotations

import os


# Bump the worker protocol whenever queue semantics, sealed-artifact expectations, or
# executable strategy/schema support changes incompatibly.  Existing queued work will
# then remain safely unclaimed until a matching worker is available.
WORKER_RUNTIME_CONTRACT = "quantlens-worker-v2"
STORAGE_SCHEMA_VERSION = "quantlens-sqlite-v1"
API_BUILD_CONTRACT = "quantlens-api-v1"

# Gate E Stop D: the corrected-release queue is isolated from the baseline
# queue by contract identity. A process serves exactly one contract; work
# stamped for an isolated contract is invisible to baseline workers and vice
# versa, at both the claim SELECT and the database claim trigger.
WORKER_CONTRACT_V3 = "quantlens-worker-v3"
ISOLATED_WORKER_CONTRACTS = frozenset({WORKER_CONTRACT_V3})


class RuntimeContractMismatch(RuntimeError):
    """Raised before work is claimed or executed by an incompatible process."""


def assert_expected_runtime(component: str) -> None:
    """Fail startup when the launcher and imported code disagree.

    ``scripts/dev.sh`` derives the expectation from the installed API package and passes
    it to every child.  A stale interpreter/module tree therefore fails before polling.
    Direct tests and library callers may omit the environment variable.
    """
    expected = os.environ.get("QL_EXPECTED_WORKER_CONTRACT", "").strip()
    if expected and expected != WORKER_RUNTIME_CONTRACT:
        raise RuntimeContractMismatch(
            f"{component} runtime contract mismatch: expected {expected!r}; "
            f"loaded {WORKER_RUNTIME_CONTRACT!r}"
        )


def serving_worker_contract() -> str:
    """The single worker contract this process serves.

    Unset — the shipped default everywhere — this is byte-identical to
    ``WORKER_RUNTIME_CONTRACT``. A worker explicitly launched for the
    corrected release sets ``QL_WORKER_SERVING_CONTRACT`` to an isolated
    contract; any other value fails closed before work could be claimed.
    """
    value = os.environ.get("QL_WORKER_SERVING_CONTRACT", "").strip()
    if not value:
        return WORKER_RUNTIME_CONTRACT
    if value != WORKER_RUNTIME_CONTRACT and value not in ISOLATED_WORKER_CONTRACTS:
        raise RuntimeContractMismatch(
            f"unknown serving worker contract {value!r}"
        )
    return value


# Gate E Stop F3 (doc 47 §5.3, binding): the corrected engine identity is
# process-scoped, never a global bump. The legacy constant
# (quantlens_worker.config.ENGINE_SEMVER, "0.1.0") stays frozen for the
# baseline process and every legacy artifact; a process explicitly serving
# the isolated corrected contract derives "0.2.0" here and nowhere else.
# Both values are hand-restated (the dormant Gate E law is never imported
# by active code); a focused drift test pins them to the dormant constants,
# so a silent change on either side fails review loudly.
BASELINE_ENGINE_SEMVER = "0.1.0"
CORRECTED_ENGINE_SEMVER = "0.2.0"
_ENGINE_SEMVER_BY_CONTRACT = {
    WORKER_RUNTIME_CONTRACT: BASELINE_ENGINE_SEMVER,
    WORKER_CONTRACT_V3: CORRECTED_ENGINE_SEMVER,
}


def serving_engine_semver() -> str:
    """The engine identity of the ONE contract this process serves.

    Path-scoped by law: no baseline code path may consume this — legacy
    producers keep reading their frozen module constant directly, so
    legacy artifact identities stay byte-identical. Only the corrected
    execution branch (Stop F4) may derive its engine identity here, and
    an unknown serving contract fails closed inside
    :func:`serving_worker_contract` before any identity is derived.
    """
    return _ENGINE_SEMVER_BY_CONTRACT[serving_worker_contract()]


def assert_run_compatible(run: dict) -> None:
    required = run.get("required_worker_contract")
    if required != serving_worker_contract():
        raise RuntimeContractMismatch(
            "queued run requires an incompatible worker runtime contract"
        )


def public_runtime_view() -> dict[str, str]:
    """Non-sensitive versions used by launch probes and diagnostics."""
    return {
        "api_build_contract": API_BUILD_CONTRACT,
        "storage_schema_version": STORAGE_SCHEMA_VERSION,
        "worker_runtime_contract": WORKER_RUNTIME_CONTRACT,
    }
