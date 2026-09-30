"""Corrected-release execution branch (Gate E Stop F4).

Doc 47 row F4 (conditional GO): a process serving the isolated corrected
worker contract executes a claimed corrected-release run through the Stop C
producer chain — and for EVERY other tuple the doc 44 fail-closed
cancellation stays exactly as it was. This module owns that dispatch law so
the legacy runner references one active name and nothing dormant.

Stop F4b (this stage) wires the real C1→C2→C3→C4 orchestration behind the
F4a dispatch law, in the exact reviewed C4 order: market observations →
plan inputs → validation plan → partitions → continuous development paths
under the adverse-fill executor → development evidence projection → capsule
observations → externally issued and signature-checked plan anchor →
one-use final-holdout access through the dormant production client against
a SEPARATE authority process → final execution → access audit → financial
contract → payload assembly → ``seal_candidate_v3``'s frozen sealing order.

Honesty boundaries the review must be able to lean on:

- The authorities are never in-process objects: the worker holds only its
  own evaluator key, talks to both authorities over pinned loopback
  transports, and proves the plan anchor against the hash-pinned issuer
  bundle with a caller-supplied clock before trusting or registering it.
- The CONTROL_PLANE_REGISTRAR flow (issue the anchor, register the
  encrypted capsule and the anchor at the final-holdout authority) is owned
  by the SEPARATE control-plane registrar process (doc 50 §3.2 repair): the
  worker resolves a keyless loopback client to it from the closed
  ``REGISTRAR_ENVIRONMENT`` surface, so the registrar role keys never enter
  this process. A store that configures neither the registrar endpoint nor
  the reviewed test seam keeps the F4a ``RELEASE_EXECUTION_UNCONFIGURED``
  refusal.
- Engine identity is derived exclusively from
  ``runtime_contract.serving_engine_semver()`` (Stop F3 path-scoping law);
  the frozen legacy module constant is never consulted here.
- The runtime image identity sealed into the manifest is the process's own
  ``config.image_digest()``, and it must equal the digest the ACTIVE
  release declared for ``worker_runtime`` — an undeclared or different
  runtime refuses before any compute (doc 48 §7 bound criterion).
- The F2a writer obligations run before sealing: the anchor signature is
  proved before ``db.register_corrected_read_expectation`` sees it, the
  semantics digests come only from the sealed expectations file, and the
  executed snapshot/calendar/validation-plan documents are registered
  write-once; the validator and resolver registries are then assembled
  from that trusted store, never from run inputs.

Admission for battery-v3 remains closed until F5, so every run reaching
this branch was created through a reviewed fixture lane.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import pandas as pd
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quantlens_api import db
from quantlens_api.corrected_read_expectations import (
    load_corrected_read_expectations,
)
from quantlens_api.release_activation import RELEASE_STATE_ACTIVE
from quantlens_api.runtime_contract import (
    WORKER_CONTRACT_V3,
    serving_engine_semver,
    serving_worker_contract,
)

from .adverse_fill_execution_v1 import (
    execute_adverse_fill_window_v1,
    make_adverse_fill_segment_executor_v1,
)
from .battery_config_v3 import battery_config_v3_hash
from .candidate_seal_v3 import (
    MANIFEST_FILENAME,
    SEAL_DIRECTORY_NAME,
    assemble_candidate_payloads_v3,
    load_sealed_candidate_v3,
    seal_candidate_v3,
)
from .config import INITIAL_CAPITAL, image_digest
from .continuous_walk_forward_v1 import (
    CONTINUOUS_PATH_VERSION,
    derive_development_evaluation_v1,
    run_continuous_development_paths_v1,
)
from .evidence_contract_registry_v3 import (
    ReviewedGateEBuildRegistration,
    ReviewedGateERegistry,
)
from .evidence_projection_v3 import project_development_evidence_v3
from .final_execution_v3 import (
    build_final_holdout_execution_audit_v3,
    execute_final_holdout_v3,
)
from .holdout_client_v1 import (
    FinalHoldoutClientV1,
    loopback_urllib_transport_v1,
)
from .plan_anchor_verifier_v1 import verify_validation_plan_anchor_v1
from .plan_inputs_v3 import assemble_validation_plan_inputs_v3
from .registrar_client_v1 import (
    ControlPlaneRegistrarClientV1,
    registrar_origin_configured,
)
from .snapshot import DataQualityError, load_frame
from .validation_partition_v3 import build_partitions_v3
from .validation_plan_v3 import build_validation_plan_v3
from .valuation_ledger_v1 import (
    build_carry_v1,
    build_financial_contract_v1,
    build_market_observations_v2,
    sha256_json,
)

logger = logging.getLogger("quantlens.worker.corrected_execution_v3")


# The corrected battery identity this branch may execute; every other
# profile stamped with an isolated contract keeps the doc 44 refusal.
CORRECTED_BATTERY_PROFILE = "battery-v3"

# The closed authority-configuration surface. The corrected chain requires
# BOTH separately running authorities, both hash-pinned public trust
# bundles, the expected authority/key identities the sealed plan must
# carry, and the worker's OWN evaluator key. The values name separate
# authority processes and worker-held client material only — never an
# in-process authority object and never an authority signing seed.
AUTHORITY_ENVIRONMENT = (
    "QL_PLAN_ANCHOR_AUTHORITY_URL",
    "QL_PLAN_ANCHOR_AUTHORITY_ID",
    "QL_PLAN_ANCHOR_ISSUER_KEY_ID",
    "QL_PLAN_ANCHOR_ISSUER_BUNDLE_FILE",
    "QL_PLAN_ANCHOR_ISSUER_BUNDLE_SHA256",
    "QL_FINAL_HOLDOUT_AUTHORITY_URL",
    "QL_FINAL_HOLDOUT_AUTHORITY_ID",
    "QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID",
    "QL_FINAL_HOLDOUT_TRUST_BUNDLE_FILE",
    "QL_FINAL_HOLDOUT_TRUST_BUNDLE_SHA256",
    "QL_FINAL_HOLDOUT_EVALUATOR_KEY_ID",
    "QL_FINAL_HOLDOUT_EVALUATOR_KEY_FILE",
)

# The closed registrar-configuration surface. One loopback origin naming the
# SEPARATE control-plane registrar process; no registrar key material may ever
# appear in this process's environment contract — the registrar role keys are
# named only by the registrar service's own QL_CONTROL_PLANE_REGISTRAR_*_KEY_*
# variables, which the worker never reads.
REGISTRAR_ENVIRONMENT = (
    "QL_CONTROL_PLANE_REGISTRAR_URL",
)

_UNREGISTERED_REFUSAL = {
    "code": "RELEASE_EXECUTION_UNREGISTERED",
    "message": (
        "This run is bound to a corrected release whose execution "
        "path is not registered on this worker. No results were "
        "produced."
    ),
}
_UNCONFIGURED_REFUSAL = {
    "code": "RELEASE_EXECUTION_UNCONFIGURED",
    "message": (
        "This run matches the corrected release exactly, but the worker "
        "process has no configured authority endpoints and pinned trust "
        "bundles for the corrected execution chain. No results were "
        "produced."
    ),
}


class CorrectedExecutionRefusal(RuntimeError):
    """One typed fail-closed terminal refusal from the corrected branch."""

    def __init__(self, code: str, message: str, *,
                 status: str = "system_failed") -> None:
        self.code = code
        self.message = message
        self.status = status
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ControlPlaneRegistrar:
    """The registrar-side protocol seam the worker cannot honestly own.

    Issuing a plan anchor and registering the encrypted capsule plus the
    anchor at the final-holdout authority are CONTROL_PLANE_REGISTRAR
    responsibilities: the registrar key must stay disjoint from both the
    authority signing keys and this worker's evaluator key, or one process
    could mint itself fresh holdout access. Production resolves this seam to
    the keyless loopback client of the SEPARATE registrar process (doc 50
    §3.2 repair); the reviewed cross-process test harness may still install
    one built on the real authority children.
    """

    issue_anchor: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    register_capsule: Callable[
        [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
    register_anchor: Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


# The reviewed test seam. When it is None — every production process — the
# registrar is resolved from the closed REGISTRAR_ENVIRONMENT surface
# instead, and a store configuring neither keeps the F4a typed refusal.
_control_plane_registrar: ControlPlaneRegistrar | None = None


def registrar_endpoint_configured() -> bool:
    """True when the registrar environment names an exact loopback origin."""
    return registrar_origin_configured(
        (os.environ.get("QL_CONTROL_PLANE_REGISTRAR_URL") or "").strip()
        or None)


def _resolve_control_plane_registrar() -> ControlPlaneRegistrar | None:
    """The single seam resolution: reviewed test seam, else production client.

    The production client holds no registrar key material — it only carries
    envelopes to the separate registrar process, and everything it returns
    is proved downstream (the anchor against the hash-pinned issuer bundle,
    the capsule/anchor identities by the authority-signed lease flow).
    """
    if _control_plane_registrar is not None:
        return _control_plane_registrar
    if not registrar_endpoint_configured():
        return None
    client = ControlPlaneRegistrarClientV1(
        os.environ["QL_CONTROL_PLANE_REGISTRAR_URL"].strip())
    return ControlPlaneRegistrar(
        issue_anchor=client.issue_anchor,
        register_capsule=client.register_capsule,
        register_anchor=client.register_anchor,
    )


@dataclass(frozen=True)
class AuthorityConfiguration:
    """Parsed worker-side authority material from the closed env surface."""

    plan_anchor_authority_url: str
    plan_anchor_authority_id: str
    plan_anchor_issuer_key_id: str
    plan_anchor_issuer_bundle: Mapping[str, Any]
    plan_anchor_issuer_bundle_sha256: str
    holdout_authority_url: str
    holdout_authority_id: str
    holdout_signer_key_id: str
    holdout_trust_bundle: Mapping[str, Any]
    holdout_trust_bundle_sha256: str
    evaluator_key_id: str
    evaluator_signer: Callable[[bytes], bytes]


def authority_material_configured() -> bool:
    """True when every authority endpoint and trust-bundle pin is set.

    The F4b orchestration refuses without this; the values name separate
    authority processes, never in-process authority objects.
    """
    return all(
        (os.environ.get(name) or "").strip() for name in AUTHORITY_ENVIRONMENT
    )


EXECUTION_READINESS_VERSION = "corrected-execution-readiness-v1"


def _evaluator_key_fact() -> str:
    """Config/byte observation of the worker's own evaluator key file."""
    path_value = (
        os.environ.get("QL_FINAL_HOLDOUT_EVALUATOR_KEY_FILE") or "").strip()
    if not path_value:
        return "unconfigured"
    try:
        info = os.stat(Path(path_value), follow_symlinks=False)
    except OSError:
        return "missing"
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 \
            or info.st_size != 32:
        return "insecure"
    return "held"


def execution_readiness_observation() -> dict[str, str]:
    """The worker's own structural executable-readiness facts (doc 50 §3.2).

    Pure configuration and byte observation — no network I/O and no key
    bytes: the closed authority surface, the registrar seam resolution and
    the evaluator key file hygiene. The v3 heartbeat records this document
    beside its liveness row so admission and activation can refuse when the
    process is structurally unable to execute a new corrected run; the pure
    evaluator lives with the other capability evaluators in the control
    plane, never here.
    """
    if _control_plane_registrar is not None:
        registrar_fact = "installed"
    elif registrar_endpoint_configured():
        registrar_fact = "configured"
    else:
        registrar_fact = "unconfigured"
    return {
        "readiness_version": EXECUTION_READINESS_VERSION,
        "serving_contract": serving_worker_contract(),
        "authority_environment": (
            "configured" if authority_material_configured() else "incomplete"),
        "control_plane_registrar": registrar_fact,
        "evaluator_key": _evaluator_key_fact(),
    }


def _fail(code: str, message: str, *, status: str = "system_failed") -> None:
    raise CorrectedExecutionRefusal(code, message, status=status)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail("CORRECTED_EXECUTION_FAILED", message)


def _read_json_file(path_value: str, label: str) -> Mapping[str, Any]:
    try:
        return json.loads(Path(path_value).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _fail("CORRECTED_EXECUTION_FAILED",
              f"the configured {label} file is missing or malformed")
    raise AssertionError  # unreachable


def _load_evaluator_signer(path_value: str) -> Callable[[bytes], bytes]:
    """Load the worker's own Ed25519 evaluator seed with file hygiene.

    The evaluator key is the ONLY private material this branch may hold: it
    signs the worker's client requests and nothing the authority signs.
    """
    path = Path(path_value)
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail("CORRECTED_EXECUTION_FAILED",
              "the configured evaluator key file is missing")
        raise AssertionError  # unreachable
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        _fail("CORRECTED_EXECUTION_FAILED",
              "the evaluator key file must be a regular owner-only file")
    seed = path.read_bytes()
    if len(seed) != 32:
        _fail("CORRECTED_EXECUTION_FAILED",
              "the evaluator key file must hold exactly one raw Ed25519 seed")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return lambda message: private_key.sign(message)


def _load_authority_configuration() -> AuthorityConfiguration:
    values = {name: (os.environ.get(name) or "").strip()
              for name in AUTHORITY_ENVIRONMENT}
    _require(all(values.values()),
             "the closed authority-configuration surface is incomplete")
    return AuthorityConfiguration(
        plan_anchor_authority_url=values["QL_PLAN_ANCHOR_AUTHORITY_URL"],
        plan_anchor_authority_id=values["QL_PLAN_ANCHOR_AUTHORITY_ID"],
        plan_anchor_issuer_key_id=values["QL_PLAN_ANCHOR_ISSUER_KEY_ID"],
        plan_anchor_issuer_bundle=_read_json_file(
            values["QL_PLAN_ANCHOR_ISSUER_BUNDLE_FILE"],
            "plan-anchor issuer trust bundle"),
        plan_anchor_issuer_bundle_sha256=(
            values["QL_PLAN_ANCHOR_ISSUER_BUNDLE_SHA256"]),
        holdout_authority_url=values["QL_FINAL_HOLDOUT_AUTHORITY_URL"],
        holdout_authority_id=values["QL_FINAL_HOLDOUT_AUTHORITY_ID"],
        holdout_signer_key_id=(
            values["QL_FINAL_HOLDOUT_AUTHORITY_SIGNER_KEY_ID"]),
        holdout_trust_bundle=_read_json_file(
            values["QL_FINAL_HOLDOUT_TRUST_BUNDLE_FILE"],
            "final-holdout authority trust bundle"),
        holdout_trust_bundle_sha256=(
            values["QL_FINAL_HOLDOUT_TRUST_BUNDLE_SHA256"]),
        evaluator_key_id=values["QL_FINAL_HOLDOUT_EVALUATOR_KEY_ID"],
        evaluator_signer=_load_evaluator_signer(
            values["QL_FINAL_HOLDOUT_EVALUATOR_KEY_FILE"]),
    )


def corrected_execution_refusal(run: Mapping[str, Any]) -> dict[str, str]:
    """The typed refusal for one isolated-contract run, per doc 47 row F4.

    The doc 44 fail-closed cancellation is preserved for every tuple that
    is not EXACTLY the corrected release: a serving-contract mismatch, a
    non-corrected battery profile, a battery hash that does not equal the
    immutable battery-v3 configuration hash, a missing immutable release
    binding, or a release row that is not ACTIVE. Only the exact corrected
    tuple advances to the unconfigured refusal — and only a store that
    configures the closed authority surface AND resolves a control-plane
    registrar (the separate registrar process, or the reviewed test seam)
    executes instead (``corrected_execution_ready``).
    """
    if (
        serving_worker_contract() != WORKER_CONTRACT_V3
        or run.get("required_worker_contract") != WORKER_CONTRACT_V3
        or run.get("research_mode") != "formal"
        or run.get("battery_profile") != CORRECTED_BATTERY_PROFILE
        or run.get("battery_profile_hash") != battery_config_v3_hash()
    ):
        return dict(_UNREGISTERED_REFUSAL)
    binding = db.get_run_release_binding(run["run_id"])
    if binding is None:
        return dict(_UNREGISTERED_REFUSAL)
    release = db.get_release(binding["release_row_id"])
    if (
        release is None
        or release["release_state"] != RELEASE_STATE_ACTIVE
        or release["release_id"] != binding["release_id"]
        or release["release_tuple_sha256"] != binding["release_tuple_sha256"]
        or binding["required_worker_contract"] != WORKER_CONTRACT_V3
    ):
        return dict(_UNREGISTERED_REFUSAL)
    return dict(_UNCONFIGURED_REFUSAL)


def corrected_execution_ready(run: Mapping[str, Any]) -> bool:
    """True only when the exact corrected tuple can honestly execute here.

    Requires the F4a dispatch law to classify the run as the exact
    corrected release, plus either an already-sealed candidate (crash
    resume publishes verified bytes and needs no authority contact) or the
    configured authority surface with a resolvable control-plane registrar
    (the separate registrar process named by ``REGISTRAR_ENVIRONMENT``, or
    the reviewed test seam). A store configuring neither keeps the typed
    refusal.
    """
    if corrected_execution_refusal(run)["code"] \
            != _UNCONFIGURED_REFUSAL["code"]:
        return False
    if _has_sealed_candidate(run["run_id"]):
        return True
    return (
        authority_material_configured()
        and _resolve_control_plane_registrar() is not None
    )


# --------------------------------------------------------------- execution


def _run_dir(run_id: str) -> Path:
    directory = db.var_dir() / "artifacts" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _corrected_producer() -> str:
    # Stop F3 path-scoping law: this branch is the single reviewed consumer
    # of the corrected engine identity.
    return f"quantlens-engine/{serving_engine_semver()}+" \
           f"{CORRECTED_BATTERY_PROFILE}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _has_sealed_candidate(run_id: str) -> bool:
    """Whether this run owns a byte-verifiable sealed v3 candidate."""
    run_dir = db.var_dir() / "artifacts" / run_id
    if not (run_dir / SEAL_DIRECTORY_NAME / MANIFEST_FILENAME).exists():
        return False
    try:
        load_sealed_candidate_v3(
            run_dir, reviewed_producers=[_corrected_producer()])
    except Exception:  # noqa: BLE001 — an unverifiable candidate is no checkpoint
        return False
    return True


def _release_if_uncandidate(run_id: str) -> bool:
    """Corrected-branch mirror of the runner's reservation compensation.

    A sealed v3 candidate is the billable boundary for this branch — the
    legacy checkpoint predicate cannot see it, so the compensation decision
    must be made here with the v3 loader.
    """
    reservation = db.get_reservation(run_id)
    if reservation is None:
        return False
    if reservation["status"] == "reserved":
        if _has_sealed_candidate(run_id):
            # The immutable sealed candidate is the billable boundary; a
            # later failure needs settlement, never a returned unit.
            return False
        db.release_reservation(run_id)
        return False
    return bool(reservation["quota_charged"])


def _publish_sealed(run_id: str) -> str:
    """ledger_sealed → settled → published for one sealed candidate."""
    current = db.get_run_internal(run_id)
    if current and current["status"] != "ledger_sealed":
        if any(status == "ledger_sealed" for status, _ in current["history"]):
            # Resume moves the cursor, not the immutable lifecycle fact.
            with db.connect() as conn:
                conn.execute(
                    "UPDATE runs SET status = 'ledger_sealed', "
                    "error_json = NULL, updated_at = ? WHERE run_id = ?",
                    (datetime.now(timezone.utc).isoformat(), run_id),
                )
        else:
            db.set_status(run_id, "ledger_sealed")
    try:
        db.settle_reservation(run_id)
    except Exception as exc:  # noqa: BLE001 — sealed work stays compensatable
        logger.exception(
            "corrected settlement remains pending run_id=%s", run_id)
        error = {
            "code": "SETTLEMENT_PENDING",
            "message": (
                "The sealed candidate is awaiting quota settlement. "
                "Internal diagnostics were recorded locally."
            ),
            "quota_charged": False,
            "settlement_pending": True,
        }
        with db.connect() as conn:
            conn.execute(
                "UPDATE runs SET status = 'ledger_sealed', error_json = ?, "
                "updated_at = ? WHERE run_id = ?",
                (json.dumps(error), datetime.now(timezone.utc).isoformat(),
                 run_id),
            )
        return "ledger_sealed"
    db.set_status(run_id, "published")
    return "published"


def _declared_runtime_digest(release: Mapping[str, Any]) -> str:
    """The runtime image digest the ACTIVE release authorizes, fail closed."""
    capabilities = release.get("required_capabilities") or {}
    worker_runtime = capabilities.get("worker_runtime") or {}
    declared = worker_runtime.get("image_digest")
    own = image_digest()
    if not isinstance(declared, str) or not declared:
        _fail(
            "RELEASE_EXECUTION_RUNTIME_UNAUTHORIZED",
            "The ACTIVE corrected release does not declare a worker_runtime "
            "image digest, so this process cannot prove it is the reviewed "
            "runtime. No results were produced.",
        )
    if declared != own:
        _fail(
            "RELEASE_EXECUTION_RUNTIME_UNAUTHORIZED",
            "The ACTIVE corrected release authorizes a different worker "
            "runtime image digest than this process. No results were "
            "produced.",
        )
    return own


def _calendar_receipt(run: Mapping[str, Any], spec: Mapping[str, Any],
                      n_bars: int, provenance: Mapping[str, Any]) -> dict:
    """Resolve the exchange-calendar identity from the acquisition receipt.

    The only durable production source for the calendar tuple is the
    acquisition row's stored validation receipt. The confirmed run range
    must equal the receipt's validated range so the registered calendar
    sessions are deterministic per dataset (the write-once store law), and
    the receipt's observed session count must equal the loaded frame.
    """
    dataset_id = ((spec.get("data") or {}).get("source") or {}).get(
        "dataset_id")
    acquisition = db.get_market_data_acquisition_for_dataset(
        dataset_id, run["actor_id"], run.get("user_id", run["actor_id"]))
    receipt = (acquisition or {}).get("calendar_validation")
    if not receipt:
        raise DataQualityError(
            "DATASET_CALENDAR_UNAVAILABLE",
            "The corrected chain requires the dataset's sealed exchange-"
            "calendar validation receipt and none is registered.",
        )
    if acquisition.get("status") != "sealed":
        raise DataQualityError(
            "DATASET_CALENDAR_UNAVAILABLE",
            "The dataset's acquisition record is not sealed.",
        )
    if receipt.get("exact_match") is not True:
        raise DataQualityError(
            "DATASET_CALENDAR_RECEIPT_MISMATCH",
            "The stored exchange-calendar receipt did not validate an "
            "exact session match.",
        )
    requested = (spec.get("data") or {}).get("range") or {}
    if (receipt.get("requested_start") != requested.get("start")
            or receipt.get("requested_end") != requested.get("end")):
        raise DataQualityError(
            "DATASET_CALENDAR_RANGE_MISMATCH",
            "The confirmed run range must equal the exchange-calendar "
            "receipt's validated range for corrected execution.",
        )
    if receipt.get("observed_session_count") != n_bars:
        raise DataQualityError(
            "DATASET_CALENDAR_SESSIONS_MISMATCH",
            "The loaded frame does not carry exactly the receipt's "
            "validated session count.",
        )
    if receipt.get("mic") != provenance.get("mic"):
        raise DataQualityError(
            "DATASET_CALENDAR_RECEIPT_MISMATCH",
            "The exchange-calendar receipt names a different market than "
            "the sealed dataset.",
        )
    calendar_id = receipt.get("calendar_id")
    calendar_version = receipt.get("calendar_version")
    if not isinstance(calendar_id, str) or not calendar_id \
            or not isinstance(calendar_version, str) or not calendar_version:
        raise DataQualityError(
            "DATASET_CALENDAR_RECEIPT_MISMATCH",
            "The exchange-calendar receipt does not carry a usable "
            "calendar identity.",
        )
    return {
        "calendar_id": calendar_id,
        "calendar_version": calendar_version,
        "receipt_sha256": sha256_json(dict(receipt)),
    }


def _locked_rule(spec: Mapping[str, Any]) -> dict[str, Any]:
    rule = spec.get("rule") or {}
    fast = rule.get("fast_ma_days")
    return {
        "type": rule.get("type"),
        "ma_days": rule.get("ma_days"),
        "fast_ma_days": fast if fast is not None else None,
    }


def _sessions_from_frame(frame: Any) -> list[dict[str, Any]]:
    return [
        {
            "date": str(row.date),
            "open": float(row.open),
            "high": float(row.high),
            "low": float(row.low),
            "close": float(row.close),
            "volume": float(row.volume),
        }
        for row in frame.itertuples(index=False)
    ]


def _final_holdout_access(
    client: FinalHoldoutClientV1,
    *,
    lease_fields: Mapping[str, Any],
    evaluate: Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """One complete lease→consume→evaluate→complete→audit access.

    Mirrors the dormant client driver but hands the lease to the evaluator,
    which the corrected final execution needs for its cross-binding law. A
    crashed evaluation still reports ``evaluation_failed`` so the authority
    writes a terminal audit before the failure propagates.
    """
    lease = client.create_lease(**lease_fields)
    identifiers = {
        "lease_id": lease["lease_id"],
        "anchor_id": lease["anchor_id"],
        "capsule_id": lease["capsule_id"],
        "run_id": lease["run_id"],
    }
    consume_body = client.consume(
        capsule_payload_sha256=lease["capsule_payload_sha256"], **identifiers)
    try:
        projection = evaluate(consume_body, lease)
    except BaseException:
        client.complete(outcome="evaluation_failed", **identifiers)
        raise
    client.complete(outcome="evaluation_succeeded", **identifiers)
    retrieved = client.retrieve_audit(**identifiers)
    receipt = {key: value for key, value in consume_body.items()
               if key not in ("primary_observations",
                              "benchmark_observations")}
    return {
        "lease": lease,
        "consume_receipt": receipt,
        "terminal_audit": retrieved["terminal_audit"],
        "projection": projection,
    }


def _register_expectation(component: str, entry_key: str,
                          document: Any) -> None:
    """Write-once registration honoring the F2a writer obligations."""
    db.register_corrected_read_expectation(component, entry_key, document)


def execute_corrected_run(
    run: Mapping[str, Any],
    *,
    resolve_snapshot: Callable[[Mapping[str, Any]], tuple],
) -> str:
    """Execute one claimed exact-corrected-tuple run; return terminal status.

    ``resolve_snapshot`` is the runner's reviewed dataset resolution chain,
    injected so both pipelines share one fail-closed dataset trust law.
    Every failure terminates here with the corrected branch's own
    reservation compensation — the legacy checkpoint predicate cannot see a
    sealed v3 candidate, so the legacy ladder must never handle this run.
    """
    run_id = run["run_id"]
    try:
        return _execute_corrected(run, resolve_snapshot=resolve_snapshot)
    except CorrectedExecutionRefusal as refusal:
        charged = _release_if_uncandidate(run_id)
        db.set_status(run_id, refusal.status, {
            "code": refusal.code,
            "message": refusal.message,
            "quota_charged": charged,
        })
    except DataQualityError as exc:
        charged = _release_if_uncandidate(run_id)
        db.set_status(run_id, "data_quality_failed", {
            "code": exc.code,
            "message": exc.message,
            "quota_charged": charged,
        })
    except Exception:  # noqa: BLE001 — the corrected branch fails closed
        logger.exception("corrected execution failed run_id=%s", run_id)
        charged = _release_if_uncandidate(run_id)
        db.set_status(run_id, "system_failed", {
            "code": "CORRECTED_EXECUTION_FAILED",
            "message": (
                "Corrected execution failed before a sealed candidate "
                "existed. No results were produced; internal diagnostics "
                "were recorded locally."
            ),
            "quota_charged": charged,
        })
    return db.get_run_internal(run_id)["status"]


def _execute_corrected(
    run: Mapping[str, Any],
    *,
    resolve_snapshot: Callable[[Mapping[str, Any]], tuple],
) -> str:
    run_id = run["run_id"]
    run_dir = _run_dir(run_id)

    # Crash resume: a byte-verifiable sealed candidate is the checkpoint —
    # it is never recomputed (the one-use holdout could not be re-consumed
    # honestly anyway); the control-plane cursor is repaired instead.
    if _has_sealed_candidate(run_id):
        return _publish_sealed(run_id)

    registrar = _resolve_control_plane_registrar()
    _require(registrar is not None,
             "no control-plane registrar is resolvable")
    configuration = _load_authority_configuration()

    binding = db.get_run_release_binding(run_id)
    _require(binding is not None, "the immutable release binding vanished")
    release = db.get_release(binding["release_row_id"])
    _require(
        release is not None
        and release["release_state"] == RELEASE_STATE_ACTIVE,
        "the corrected release is no longer ACTIVE",
    )
    runtime_digest = _declared_runtime_digest(release)

    expectations = load_corrected_read_expectations()
    _require(
        expectations.activation_release == binding["release_id"],
        "the sealed expectations file names a different activation release",
    )
    _require(
        expectations.battery_config_hash == battery_config_v3_hash(),
        "the sealed expectations file contradicts the immutable battery-v3 "
        "configuration hash",
    )

    if run["status"] == "queued":
        db.set_status(run_id, "snapshot_pinned")
    db.set_status(run_id, "running_engine")

    spec = run["spec"]
    spec_hash = run["spec_hash"]
    _require(
        sha256_json(spec) == spec_hash,
        "the stored spec no longer matches its confirmed canonical hash",
    )
    accepted = binding["accepted_run"]
    _require(
        accepted.get("confirmed_spec_hash") == spec_hash
        and accepted.get("tenant_id") == run["actor_id"]
        and accepted.get("workspace_id")
        == run.get("user_id", run["actor_id"])
        and accepted.get("battery_profile") == CORRECTED_BATTERY_PROFILE
        and accepted.get("battery_profile_hash") == battery_config_v3_hash()
        and accepted.get("dsl_schema_version") == spec.get("dsl_version"),
        "the immutable release binding contradicts the claimed run",
    )

    directory, snapshot_meta, provenance = resolve_snapshot(run)
    _require(
        isinstance(provenance, dict)
        and provenance.get("data_label") == "LICENSED_PROVIDER",
        "corrected execution requires a sealed licensed dataset",
    )
    symbol = (spec.get("universe") or {}).get("symbol")
    data_range = (spec.get("data") or {}).get("range") or {}
    frame, gap_report = load_frame(
        symbol, data_range.get("start"), data_range.get("end"), directory)
    n_bars = len(frame)
    sessions = _sessions_from_frame(frame)
    snapshot_sha256 = "sha256:" + str(snapshot_meta["sha256"])

    calendar = _calendar_receipt(run, spec, n_bars, provenance)

    snapshot_document = build_market_observations_v2(
        snapshot_sha256=snapshot_sha256,
        exchange_calendar_id=calendar["calendar_id"],
        exchange_calendar_version=calendar["calendar_version"],
        instruments=[{
            "symbol": symbol,
            "currency": provenance["currency"],
            "sessions": [dict(row) for row in sessions],
        }],
    )
    # Execute over the CANONICAL sealed observations: the independent
    # validator re-derives every development/capsule digest from the sealed
    # market document, so the chain must consume exactly those bytes — the
    # same session↔document identity the reviewed C4 recipe relies on.
    sessions = [dict(row)
                for row in snapshot_document["instruments"][0]["sessions"]]
    frame = pd.DataFrame(sessions)

    plan = build_validation_plan_v3(**assemble_validation_plan_inputs_v3(
        run_identity={
            "tenant_id": run["actor_id"],
            "workspace_id": run.get("user_id", run["actor_id"]),
            "run_id": run_id,
            "confirmed_spec_hash": spec_hash,
        },
        confirmed_spec=spec,
        observation_identity={
            "snapshot_sha256": snapshot_sha256,
            "exchange_calendar_id": calendar["calendar_id"],
            "exchange_calendar_version": calendar["calendar_version"],
            "n_bars": n_bars,
        },
        capability_state={
            "anchor_authority_id": configuration.plan_anchor_authority_id,
            "anchor_issuer_key_id": configuration.plan_anchor_issuer_key_id,
            "holdout_authority_id": configuration.holdout_authority_id,
            "holdout_authority_key_id": configuration.holdout_signer_key_id,
            "external_anchor_ready": True,
            "external_holdout_ready": True,
        },
    ))
    locked_rule = _locked_rule(spec)
    base_costs = dict(spec.get("costs") or {})
    _require(
        sha256_json(locked_rule) == plan["locked_rule_sha256"]
        and sha256_json(base_costs) == plan["base_costs_sha256"],
        "the executable rule/cost bindings drifted from the sealed plan",
    )
    partitions = build_partitions_v3(frame, plan).artifact

    db.set_status(run_id, "running_battery")

    multipliers = list(
        ((spec.get("validation") or {}).get("cost_stress") or {})
        .get("multipliers") or [])
    _require(1.0 in [float(value) for value in multipliers],
             "corrected execution requires the unit cost-stress multiplier")
    evaluation_start = derive_development_evaluation_v1(
        partitions)["start_index"]
    coordinator = run_continuous_development_paths_v1(
        development=sessions[:plan["development_bars"]],
        benchmark_development=None,
        partitions=partitions,
        spec_hash=spec_hash,
        snapshot_sha256=snapshot_sha256,
        initial_carry=build_carry_v1(
            cash=INITIAL_CAPITAL, shares=0.0, position=0),
        cost_multipliers=[float(value) for value in multipliers],
        segment_executor=make_adverse_fill_segment_executor_v1(
            rule=locked_rule,
            costs=base_costs,
            development_evaluation_start=evaluation_start,
        ),
    )
    development_evidence = project_development_evidence_v3(
        coordinator_output=coordinator,
        expected_continuous_path_version=CONTINUOUS_PATH_VERSION,
        partitions=partitions,
        spec=spec,
        initial_capital=INITIAL_CAPITAL,
        benchmark_market={
            "dates": [row["date"] for row in
                      sessions[:plan["development_bars"]]],
            "closes": [row["close"] for row in
                       sessions[:plan["development_bars"]]],
        },
    )

    window = plan["final_window"]
    capsule_observations = build_market_observations_v2(
        snapshot_sha256=snapshot_sha256,
        exchange_calendar_id=calendar["calendar_id"],
        exchange_calendar_version=calendar["calendar_version"],
        instruments=[{
            "symbol": symbol,
            "currency": provenance["currency"],
            "sessions": [dict(row) for row in sessions[
                window["warmup_start_index"]:window["end_index"]]],
        }],
    )

    # Control-plane registrar flow: the separate registrar process (or the
    # reviewed test seam) issues and registers; this process only verifies.
    issued = registrar.issue_anchor(plan)
    anchor_document = issued["anchor"]
    # F2a writer law: the anchor signature is proved against the hash-pinned
    # issuer bundle BEFORE the anchor may enter the trusted store.
    verify_validation_plan_anchor_v1(
        anchor_document,
        validation_plan=plan,
        trust_bundle=configuration.plan_anchor_issuer_bundle,
        expected_trust_bundle_sha256=(
            configuration.plan_anchor_issuer_bundle_sha256),
        expected_authority_id=configuration.plan_anchor_authority_id,
        registered_signed_anchor_bytes=bytes.fromhex(
            issued["registered_signed_anchor_bytes_hex"]),
        registration_receipt=issued["registration_receipt"],
        now=_utc_now(),
    )
    plan_anchor_sha256 = sha256_json(anchor_document)

    capsule = registrar.register_capsule(plan, capsule_observations)
    anchor_registration = registrar.register_anchor(
        capsule["capsule_id"], issued)

    client = FinalHoldoutClientV1(
        authority_id=configuration.holdout_authority_id,
        caller_key_id=configuration.evaluator_key_id,
        signer=configuration.evaluator_signer,
        trust_bundle=configuration.holdout_trust_bundle,
        expected_trust_bundle_sha256=configuration.holdout_trust_bundle_sha256,
        transport=loopback_urllib_transport_v1(
            configuration.holdout_authority_url, timeout_seconds=30.0),
        now=_utc_now,
    )

    def _evaluate(consume_body: Mapping[str, Any],
                  lease: Mapping[str, Any]) -> dict[str, Any]:
        return execute_final_holdout_v3(
            consume_body=consume_body,
            lease=lease,
            partitions=partitions,
            locked_rule=locked_rule,
            base_costs=base_costs,
            initial_capital=INITIAL_CAPITAL,
            benchmark_symbol=symbol,
            spec_hash=spec_hash,
            snapshot_sha256=snapshot_sha256,
            validation_plan_hash=plan["validation_plan_hash"],
            window_executor=execute_adverse_fill_window_v1,
        )

    access = _final_holdout_access(
        client,
        lease_fields={
            "capsule_id": capsule["capsule_id"],
            "capsule_payload_sha256": capsule["capsule_payload_sha256"],
            "anchor_id": anchor_registration["anchor_id"],
            "anchor_sha256": anchor_registration["anchor_sha256"],
            "tenant_id": plan["tenant_id"],
            "workspace_id": plan["workspace_id"],
            "run_id": plan["run_id"],
            "confirmed_spec_hash": plan["confirmed_spec_hash"],
            "snapshot_sha256": plan["snapshot_sha256"],
            "validation_plan_hash": plan["validation_plan_hash"],
            "complete_validation_plan_sha256": (
                capsule["complete_validation_plan_sha256"]),
            "locked_rule_sha256": plan["locked_rule_sha256"],
            "base_costs_sha256": plan["base_costs_sha256"],
        },
        evaluate=_evaluate,
    )
    final_projection = access["projection"]
    audit = build_final_holdout_execution_audit_v3(
        final_holdout_result=final_projection["final_holdout_result"],
        lease=access["lease"],
        consume_receipt=access["consume_receipt"],
        terminal_audit=access["terminal_audit"],
        authority_id=configuration.holdout_authority_id,
    )

    financial_contract = build_financial_contract_v1(
        financial_semantics_sha256=(
            expectations.financial_semantics["financial-semantics-v2"]),
        metric_semantics_version="metrics-v2",
        metric_semantics_sha256=(
            expectations.metric_semantics["metrics-v2"]),
        initial_capital=INITIAL_CAPITAL,
        base_currency=provenance["currency"],
        exchange_calendar_id=calendar["calendar_id"],
        exchange_calendar_version=calendar["calendar_version"],
        acquisition_validation_receipt_sha256=calendar["receipt_sha256"],
    )

    payloads = assemble_candidate_payloads_v3(
        spec=spec,
        validation_plan=plan,
        partitions=partitions,
        financial_contract=financial_contract,
        development_evidence=development_evidence,
        development_executions=coordinator["executions"],
        final_projection=final_projection,
        final_holdout_execution_audit=audit,
        snapshot_ref={
            "snapshot_id": snapshot_meta["snapshot_id"],
            "sha256": snapshot_meta["sha256"],
        },
        data_provenance=dict(provenance),
        data_gaps={
            "gaps": gap_report["gaps"],
            "policy": gap_report["policy"],
        },
    )

    # F2a writer obligations: register the executed documents write-once,
    # then assemble both registries from the trusted store — never from the
    # run inputs this process just computed.
    _register_expectation(
        "financial_semantics", "financial-semantics-v2",
        expectations.financial_semantics["financial-semantics-v2"])
    _register_expectation(
        "metric_semantics", "metrics-v2",
        expectations.metric_semantics["metrics-v2"])
    _register_expectation("plan_anchors", plan_anchor_sha256, anchor_document)
    _register_expectation(
        "snapshots", snapshot_document["snapshot_sha256"], snapshot_document)
    _register_expectation(
        "calendars",
        f"{calendar['calendar_id']}|{calendar['calendar_version']}|"
        f"{calendar['receipt_sha256']}",
        {"sessions": [row["date"] for row in sessions]})
    _register_expectation(
        "validation_plans", plan["validation_plan_hash"], {
            "profile_id": plan["profile_id"],
            "profile_hash": plan["profile_hash"],
            "plan_version": plan["plan_version"],
            "validation_plan_hash": plan["validation_plan_hash"],
            "full_plan_sha256": sha256_json(plan),
            "spec_hash": spec_hash,
            "snapshot_sha256": snapshot_sha256,
        })

    producer = _corrected_producer()
    validator_registry = {
        "producers": [producer],
        "financial_semantics": db.get_corrected_read_expectations(
            "financial_semantics"),
        "metric_semantics": db.get_corrected_read_expectations(
            "metric_semantics"),
        "calendars": db.get_corrected_read_expectations("calendars"),
        "snapshots": db.get_corrected_read_expectations("snapshots"),
        "validation_plans": db.get_corrected_read_expectations(
            "validation_plans"),
    }
    resolver_registry = ReviewedGateERegistry(
        financial_validator_registry=validator_registry,
        authenticated_plan_anchors=db.get_corrected_read_expectations(
            "plan_anchors"),
        accepted_run_envelope=db.assemble_accepted_run_envelope(run_id),
        expected_tenant_id=run["actor_id"],
        expected_workspace_id=run.get("user_id", run["actor_id"]),
        expected_run_id=run_id,
    )
    build_registrations = [ReviewedGateEBuildRegistration(
        presentation_contract_id=(
            binding["release_tuple"]["presentation_contract"]),
        image_digest=runtime_digest,
    )]
    confirmation = run.get("confirmation_receipt") or {}
    manifest_fields = {
        "run_id": run_id,
        "actor_id": run["actor_id"],
        "created_at": run["created_at"],
        "spec_version": run["spec_version"],
        "snapshot_id": snapshot_meta["snapshot_id"],
        "data_label": provenance["data_label"],
        "image_digest": runtime_digest,
        "battery_config_hash": plan["profile_hash"],
        "confirmation_receipt_hash": confirmation.get("restatement_hash"),
        "plan_anchor_sha256": plan_anchor_sha256,
        "lineage": {
            "dataset_id": provenance["dataset_id"],
            "dataset_manifest_sha256": provenance["dataset_manifest_sha256"],
            "dataset_manifest_version": (
                provenance["dataset_manifest_version"]),
            "provider_id": provenance["provider_id"],
            "instrument_id": provenance["instrument_id"],
            "rights_policy_sha256": provenance["rights_policy_sha256"],
        },
    }

    seal_candidate_v3(
        run_dir,
        payloads=payloads,
        validator_registry=validator_registry,
        resolver_registry=resolver_registry,
        reviewed_build_registrations=build_registrations,
        reviewed_producers=[producer],
        manifest_fields=manifest_fields,
        producer=producer,
    )
    return _publish_sealed(run_id)


__all__ = [
    "AUTHORITY_ENVIRONMENT",
    "CORRECTED_BATTERY_PROFILE",
    "EXECUTION_READINESS_VERSION",
    "REGISTRAR_ENVIRONMENT",
    "AuthorityConfiguration",
    "ControlPlaneRegistrar",
    "CorrectedExecutionRefusal",
    "authority_material_configured",
    "corrected_execution_ready",
    "corrected_execution_refusal",
    "execute_corrected_run",
    "execution_readiness_observation",
    "registrar_endpoint_configured",
]
