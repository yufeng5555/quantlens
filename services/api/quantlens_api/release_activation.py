"""Release-activation law for the Gate E corrected release (doc 27 §9).

Pure logic only: the legal release-state transition table, registration-input
validation, canonical hashing, activation-receipt construction and probe
freshness arithmetic. This module performs no SQL, no file access and no
network access, and imports nothing from the worker package or any dormant
Gate C/D/E module. Every release tuple entry, component hash and authority
identity arrives as registration DATA supplied by an explicit caller and is
persisted verbatim by :mod:`quantlens_api.db`; this module never names them.

The control plane stays inert while no ``ACTIVE`` release row exists, and no
startup path ever writes a release row. Registration alone never affects queue
routing.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Mapping


RELEASE_STATE_PREPARED = "PREPARED"
RELEASE_STATE_ACTIVE = "ACTIVE"
RELEASE_STATE_SUPERSEDED = "SUPERSEDED"
RELEASE_STATE_ABORTED = "ABORTED"

RELEASE_STATES = frozenset({
    RELEASE_STATE_PREPARED,
    RELEASE_STATE_ACTIVE,
    RELEASE_STATE_SUPERSEDED,
    RELEASE_STATE_ABORTED,
})

# PREPARED may be withdrawn (ABORTED) before it ever routed work, or move to
# ACTIVE through the one reviewed §9 transaction. ACTIVE may only be rolled
# back to SUPERSEDED, which changes routing for future runs and nothing else.
# Both terminal states are final at the database trigger level as well.
LEGAL_RELEASE_TRANSITIONS: Mapping[str, frozenset[str]] = {
    RELEASE_STATE_PREPARED: frozenset({RELEASE_STATE_ACTIVE, RELEASE_STATE_ABORTED}),
    RELEASE_STATE_ACTIVE: frozenset({RELEASE_STATE_SUPERSEDED}),
    RELEASE_STATE_SUPERSEDED: frozenset(),
    RELEASE_STATE_ABORTED: frozenset(),
}

RELEASE_ACTIVATION_RECEIPT_VERSION = "release-activation-receipt-v1"

# The control-plane accepted-run identity persisted with every run stamped
# under an ACTIVE release. It carries exactly the fields the control plane
# owns at acceptance — the server-held confirmed spec hash among them, so a
# later worker never trusts a caller-supplied hash. Registered battery
# quantities (for example the final-holdout fraction) stay worker-side by
# design: composing the full v3 accepted-run document from this binding plus
# the registered battery configuration is the claiming worker's job.
RELEASE_BINDING_ACCEPTED_RUN_VERSION = "release-binding-accepted-run-v1"

# The closed set of capability kinds a preparation must declare. Since the
# doc 50 §3.2 repair EVERY kind is a mandatory execution prerequisite: a
# corrected release that cannot prove its authorities, its registrar, its
# runtime, its components and its presentation seal can never advertise a
# profile whose shipped execution path is guaranteed to refuse. Each kind's
# readiness is derived from configuration, repository bytes or the
# control-plane store — never from a caller-authored flag (§13).
CAPABILITY_KIND_PLAN_ANCHOR = "plan_anchor_authority"
CAPABILITY_KIND_FINAL_HOLDOUT = "final_holdout_authority"
CAPABILITY_KIND_WORKER_RUNTIME = "worker_runtime"
CAPABILITY_KIND_COMPONENT_HASHES = "component_hashes"
CAPABILITY_KIND_RELEASE_SEAL = "presentation_release_seal"
CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR = "control_plane_registrar"

CAPABILITY_KINDS = (
    CAPABILITY_KIND_PLAN_ANCHOR,
    CAPABILITY_KIND_FINAL_HOLDOUT,
    CAPABILITY_KIND_WORKER_RUNTIME,
    CAPABILITY_KIND_COMPONENT_HASHES,
    CAPABILITY_KIND_RELEASE_SEAL,
    CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR,
)

DEFAULT_PROBE_MAX_AGE_SECONDS = 600.0

# Doc 47 §5.7: timestamps ahead of the verifying clock are rejected beyond a
# small documented allowance instead of reading as maximally fresh. 30s
# covers realistic local clock drift; anything larger is treated as a
# fabricated observation time.
CLOCK_SKEW_ALLOWANCE_SECONDS = 30.0

# Frozen not-ready reasons. ``release_seal_pending`` is load-bearing: the
# Stop D probe producer emits it unconditionally for the presentation release
# seal because only the separately reviewed Stop F re-seal may teach the
# control plane to observe a registered corrected identity. Until then no
# code path in this repository can produce a ready seal probe, so the shipped
# configuration can never satisfy activation — structurally, not by flag.
REASON_RELEASE_SEAL_PENDING = "release_seal_pending"
REASON_OBSERVATION_MISSING = "observation_missing"
REASON_WORKER_NOT_RUNNING = "no_compatible_worker_heartbeat"
REASON_WORKER_STOPPED = "worker_stopped"
REASON_WORKER_STALE = "heartbeat_stale"
REASON_CLOCK_SKEW = "timestamp_beyond_clock_skew"
REASON_COMPONENT_DRIFT = "component_hash_drift"
# Doc 50 §3.2: derived authority-configuration and executable-readiness
# pendings. Like the seal reason, each stays one frozen constant while the
# recorded observation names the exact unmet facts.
REASON_AUTHORITY_CONFIGURATION_PENDING = "authority_configuration_pending"
REASON_EXECUTION_READINESS_PENDING = "execution_readiness_pending"

_IDENTITY_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Registered component paths are repo-relative POSIX paths without traversal.
_COMPONENT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_TUPLE_VALUE_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
# The exact local runtime-identity grammar the sealed build registry uses;
# the F2b-mandatory ``worker_runtime.image_digest`` declaration must match it.
_IMAGE_DIGEST_RE = re.compile(r"^local-runtime-sha256:[0-9a-f]{64}$")


class ReleaseActivationError(RuntimeError):
    """Base class for every release-activation control-plane failure."""


class ReleaseRegistrationError(ReleaseActivationError, ValueError):
    """A preparation registration input is malformed; nothing is persisted."""


class UnknownReleaseError(ReleaseActivationError):
    """The referenced release row does not exist."""


class ReleaseStateError(ReleaseActivationError):
    """The requested transition is illegal for the release's current state."""


class CapabilityProbeError(ReleaseActivationError):
    """A required capability probe is missing, stale, tampered or not ready."""

    def __init__(self, capability: str, reason: str):
        super().__init__(f"capability {capability!r} blocks activation: {reason}")
        self.capability = capability
        self.reason = reason


class ComponentHashError(ReleaseActivationError):
    """A registered component hash no longer matches the component bytes."""

    def __init__(self, component: str, reason: str):
        super().__init__(f"component {component!r} blocks activation: {reason}")
        self.component = component
        self.reason = reason


def canonical_json(value: object) -> str:
    """The repository-wide canonical JSON form used for hashing."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


def prefixed_sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_sha256(value: object) -> str:
    return prefixed_sha256(canonical_json(value).encode("ascii"))


def _require_identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTITY_RE.fullmatch(value):
        raise ReleaseRegistrationError(
            f"{label} must be 1-128 printable ASCII characters"
        )
    return value


# The closed corrected-release registration schema (doc 47 §5.5, binding).
# Exactly these 25 tuple fields, in the sealed manifest grammar, and their
# exact frozen values — enforced through the pinned canonical hash below, so
# this module never contains the two firewalled marker values as literals.
# The pin is cross-checked against the dormant source of truth by a focused
# drift test; a silent change on either side fails that test, never here.
RELEASE_REGISTRATION_SCHEMA_VERSION = "corrected-release-registration-v1"
RELEASE_TUPLE_FIELDS = (
    "activation_release", "presentation_contract", "worker_runtime",
    "engine_semver", "battery_profile_id", "battery_payload_version",
    "validation_plan_version", "manifest_version", "dsl_schema_version",
    "market_observations_version", "ledger_semantics_version",
    "execution_semantics_version", "execution_cost_model",
    "continuous_path_version", "valuation_ledger_version",
    "financial_contract_version", "execution_implementation",
    "validator_version", "metric_semantics_version", "evidence_view_version",
    "evidence_semantics_version", "semantic_receipt_version",
    "plan_anchor_version", "holdout_access_protocol", "artifact_producer",
)
RELEASE_TUPLE_CANONICAL_SHA256 = (
    "sha256:c2c4355b508ec1328cb603ced0702d3260a278795071e33d301a9c430b3e27d2"
)


def _validate_release_tuple(release_tuple: object) -> dict[str, str]:
    if not isinstance(release_tuple, Mapping):
        raise ReleaseRegistrationError(
            "release_tuple must be a mapping of frozen identifiers"
        )
    presented = set(release_tuple)
    expected = set(RELEASE_TUPLE_FIELDS)
    if presented - expected:
        raise ReleaseRegistrationError(
            "release_tuple carries fields outside the closed corrected-"
            f"release schema: {sorted(presented - expected)}"
        )
    if expected - presented:
        raise ReleaseRegistrationError(
            "release_tuple is missing closed corrected-release fields: "
            f"{sorted(expected - presented)}"
        )
    normalized: dict[str, str] = {}
    for key in RELEASE_TUPLE_FIELDS:
        value = release_tuple[key]
        if not isinstance(value, str) or not _TUPLE_VALUE_RE.fullmatch(value):
            raise ReleaseRegistrationError(
                "release_tuple values must be 1-256 printable ASCII characters"
            )
        normalized[key] = value
    if canonical_sha256(normalized) != RELEASE_TUPLE_CANONICAL_SHA256:
        raise ReleaseRegistrationError(
            "release_tuple values do not match the reviewed corrected-release "
            "tuple; registration is refused"
        )
    return normalized


def _validate_component_hashes(component_hashes: object) -> dict[str, str]:
    if not isinstance(component_hashes, Mapping):
        raise ReleaseRegistrationError(
            "component_hashes must map repo-relative paths to sha256 digests"
        )
    normalized: dict[str, str] = {}
    for path, digest in component_hashes.items():
        if (not isinstance(path, str) or not _COMPONENT_PATH_RE.fullmatch(path)
                or ".." in path.split("/")):
            raise ReleaseRegistrationError(
                "component paths must be traversal-free repo-relative POSIX paths"
            )
        if not isinstance(digest, str) or not _PREFIXED_SHA256_RE.fullmatch(digest):
            raise ReleaseRegistrationError(
                "component digests must match sha256:<64 lowercase hex>"
            )
        normalized[path] = digest
    return normalized


def _validate_required_capabilities(required: object) -> dict[str, dict[str, str]]:
    if not isinstance(required, Mapping) or not required:
        raise ReleaseRegistrationError(
            "required_capabilities must map capability kinds to expectations"
        )
    normalized: dict[str, dict[str, str]] = {}
    for kind, expectation in required.items():
        if kind not in CAPABILITY_KINDS:
            raise ReleaseRegistrationError(
                f"unknown capability kind {kind!r}; the reviewed set is closed"
            )
        if not isinstance(expectation, Mapping):
            raise ReleaseRegistrationError(
                "each capability expectation must be a mapping of identifiers"
            )
        fields: dict[str, str] = {}
        for name, value in expectation.items():
            if not isinstance(name, str) or not _IDENTITY_RE.fullmatch(name):
                raise ReleaseRegistrationError(
                    "capability expectation names must be printable identifiers"
                )
            if not isinstance(value, str) or not _TUPLE_VALUE_RE.fullmatch(value):
                raise ReleaseRegistrationError(
                    "capability expectation values must be printable ASCII"
                )
            fields[name] = value
        normalized[kind] = fields
    # Doc 50 §3.2 repair: EVERY capability kind is a mandatory execution
    # prerequisite. A registration that omits any of them describes a release
    # whose shipped execution path could refuse after admission opened, so it
    # can never even prepare.
    missing = [kind for kind in CAPABILITY_KINDS if kind not in normalized]
    if missing:
        raise ReleaseRegistrationError(
            "every corrected-release preparation must declare the complete "
            f"execution-prerequisite capability set; missing: {missing}"
        )
    # Stop F2b (doc 48 §8 obligation, binding): the registered release
    # identity must carry the runtime build digest. A registration that does
    # not declare ``worker_runtime.image_digest`` in the exact sealed grammar
    # can never prepare, so every ACTIVE release declares the runtime
    # identity the §A3 read term and the execution-time law verify.
    declared_digest = normalized[CAPABILITY_KIND_WORKER_RUNTIME].get(
        "image_digest")
    if not isinstance(declared_digest, str) or not _IMAGE_DIGEST_RE.fullmatch(
            declared_digest):
        raise ReleaseRegistrationError(
            "worker_runtime.image_digest must be declared as an exact "
            "local-runtime digest (Stop F2b)"
        )
    # Doc 50 §3.2: the derived execution-prerequisite kinds declare closed
    # identity fields so the generic observation-equality law always binds a
    # concrete external identity — an empty declaration would collapse the
    # equality law into a tautology.
    for kind, fields in (
        (CAPABILITY_KIND_PLAN_ANCHOR,
         ("authority_id", "issuer_key_id", "issuer_bundle_sha256")),
        (CAPABILITY_KIND_FINAL_HOLDOUT,
         ("authority_id", "signer_key_id", "trust_bundle_sha256",
          "evaluator_key_id")),
        (CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR, ("worker_contract",)),
        (CAPABILITY_KIND_COMPONENT_HASHES, ("component_hashes_sha256",)),
    ):
        if set(normalized[kind]) != set(fields):
            raise ReleaseRegistrationError(
                f"the {kind!r} expectation must declare exactly the fields "
                f"{sorted(fields)}"
            )
    for kind, field in (
        (CAPABILITY_KIND_PLAN_ANCHOR, "issuer_bundle_sha256"),
        (CAPABILITY_KIND_FINAL_HOLDOUT, "trust_bundle_sha256"),
        (CAPABILITY_KIND_COMPONENT_HASHES, "component_hashes_sha256"),
    ):
        if not _PREFIXED_SHA256_RE.fullmatch(normalized[kind][field]):
            raise ReleaseRegistrationError(
                f"{kind}.{field} must match sha256:<64 lowercase hex>"
            )
    return normalized


def validate_release_registration(
    *,
    release_id: object,
    required_worker_contract: object,
    presentation_contract_id: object,
    signer_key_id: object,
    release_tuple: object,
    component_hashes: object,
    required_capabilities: object,
    prepared_by: object,
    baseline_worker_contract: str,
) -> dict[str, str]:
    """Normalize and canonicalize one preparation registration, or fail closed.

    Returns the exact column values :func:`quantlens_api.db.prepare_release`
    persists. The registration is rejected when the corrected release would
    reuse the baseline worker contract: routing isolation between the legacy
    queue and the corrected queue is the point of the release stamp. Per the
    binding doc 47 §5.5 direction, the tuple is a closed exact schema and the
    three top-level identifiers must equal their tuple counterparts, so a
    registration can never bind a release row to identities its own tuple
    does not carry. The same validation runs again inside the activation
    transaction before PREPARED may become ACTIVE.
    """
    normalized_release_id = _require_identity(release_id, "release_id")
    contract = _require_identity(
        required_worker_contract, "required_worker_contract")
    if contract == baseline_worker_contract:
        raise ReleaseRegistrationError(
            "a corrected release must declare its own worker contract; "
            "reusing the baseline contract would collapse queue isolation"
        )
    tuple_fields = _validate_release_tuple(release_tuple)
    if normalized_release_id != tuple_fields["activation_release"]:
        raise ReleaseRegistrationError(
            "release_id must equal the tuple's activation_release identity"
        )
    if contract != tuple_fields["worker_runtime"]:
        raise ReleaseRegistrationError(
            "required_worker_contract must equal the tuple's worker_runtime"
        )
    normalized_presentation_id = _require_identity(
        presentation_contract_id, "presentation_contract_id")
    if normalized_presentation_id != tuple_fields["presentation_contract"]:
        raise ReleaseRegistrationError(
            "presentation_contract_id must equal the tuple's "
            "presentation_contract identity"
        )
    hash_fields = _validate_component_hashes(component_hashes)
    capability_fields = _validate_required_capabilities(required_capabilities)
    # Doc 50 §3.1 repair: the presentation-release-seal expectation must name
    # exactly the presentation contract this registration registers — the
    # seal facts are derived per contract id, so a foreign expectation would
    # decouple the probed facts from the registered identity.
    seal_expectation = capability_fields[CAPABILITY_KIND_RELEASE_SEAL]
    if seal_expectation.get("presentation_contract_id") != (
            normalized_presentation_id):
        raise ReleaseRegistrationError(
            "the presentation_release_seal expectation must declare "
            "presentation_contract_id equal to the registration's "
            "presentation contract"
        )
    # Doc 50 §3.2 cross-binds: the registrar-readiness expectation names
    # exactly the worker contract this registration routes to, and the
    # component-hashes expectation restates the canonical digest of exactly
    # the registered component set — the probed byte-set can never diverge
    # from the registered one.
    registrar_expectation = capability_fields[
        CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR]
    if registrar_expectation.get("worker_contract") != contract:
        raise ReleaseRegistrationError(
            "the control_plane_registrar expectation must declare "
            "worker_contract equal to the registration's required worker "
            "contract"
        )
    components_expectation = capability_fields[CAPABILITY_KIND_COMPONENT_HASHES]
    if components_expectation.get("component_hashes_sha256") != (
            canonical_sha256(hash_fields)):
        raise ReleaseRegistrationError(
            "the component_hashes expectation must restate the canonical "
            "digest of exactly the registered component set"
        )
    return {
        "release_id": normalized_release_id,
        "required_worker_contract": contract,
        "presentation_contract_id": normalized_presentation_id,
        "signer_key_id": _require_identity(signer_key_id, "signer_key_id"),
        "prepared_by": _require_identity(prepared_by, "prepared_by"),
        "release_tuple_json": canonical_json(tuple_fields),
        "release_tuple_sha256": canonical_sha256(tuple_fields),
        "component_hashes_json": canonical_json(hash_fields),
        "component_hashes_sha256": canonical_sha256(hash_fields),
        "required_capabilities_json": canonical_json(capability_fields),
        "required_capabilities_sha256": canonical_sha256(capability_fields),
    }


def check_release_transition(current: str, target: str) -> None:
    """Raise :class:`ReleaseStateError` unless ``current -> target`` is legal."""
    if target not in LEGAL_RELEASE_TRANSITIONS.get(current, frozenset()):
        raise ReleaseStateError(
            f"illegal release state transition {current!r} -> {target!r}"
        )


def probe_age_seconds(observed_at: str, now: datetime) -> float:
    """SIGNED age of one observation; unparseable timestamps are infinitely old.

    A negative age means the recorded time is ahead of the verifying clock.
    Callers must reject ages below ``-CLOCK_SKEW_ALLOWANCE_SECONDS`` (doc 47
    §5.7) — the previous zero-clamp made a future-dated record read as
    maximally fresh.
    """
    try:
        observed = datetime.fromisoformat(observed_at)
    except (TypeError, ValueError):
        return float("inf")
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return (now - observed).total_seconds()


def capability_probe_set_sha256(
    probes: Mapping[str, Mapping[str, object]],
) -> str:
    """One digest binding the exact probe set an activation relied on."""
    summary = {
        capability: {
            "observed_sha256": probe["observed_sha256"],
            "observed_at": probe["observed_at"],
            "ready": int(probe["ready"]),
        }
        for capability, probe in probes.items()
    }
    return canonical_sha256(summary)


def build_run_release_binding(
    release: Mapping[str, object],
    *,
    run_id: str,
    tenant_id: str,
    workspace_id: str,
    research_mode: str,
    battery_profile: str,
    battery_profile_hash: str,
    confirmed_spec_hash: str,
    dsl_schema_version: object,
    rule: object,
    base_costs: object,
    capability_state: Mapping[str, object],
    bound_at: str,
) -> dict[str, str]:
    """Compose the immutable per-run binding written under an ACTIVE release.

    Returns the exact ``run_release_bindings`` column values: the complete
    release tuple verbatim (§9), the canonical control-plane accepted-run
    document, and the capability state frozen at acceptance.
    """
    accepted_run = {
        "accepted_run_version": RELEASE_BINDING_ACCEPTED_RUN_VERSION,
        "release_id": release["release_id"],
        "required_worker_contract": release["required_worker_contract"],
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "run_id": run_id,
        "research_mode": research_mode,
        "battery_profile": battery_profile,
        "battery_profile_hash": battery_profile_hash,
        "confirmed_spec_hash": confirmed_spec_hash,
        "dsl_schema_version": dsl_schema_version,
        "rule": rule,
        "base_costs": base_costs,
    }
    accepted_run_json = canonical_json(accepted_run)
    return {
        "run_id": run_id,
        "release_row_id": str(release["release_row_id"]),
        "release_id": str(release["release_id"]),
        "required_worker_contract": str(release["required_worker_contract"]),
        "release_tuple_json": str(release["release_tuple_json"]),
        "release_tuple_sha256": str(release["release_tuple_sha256"]),
        "accepted_run_json": accepted_run_json,
        "accepted_run_sha256": prefixed_sha256(
            accepted_run_json.encode("ascii")),
        "capability_state_json": canonical_json(dict(capability_state)),
        "bound_at": bound_at,
    }


def evaluate_expectation_document(
    expected: Mapping[str, str],
    observation: object,
) -> tuple[bool, str | None]:
    """Compare one registered expectation against a caller-supplied document.

    Pure data equality: every registered field must be present and exactly
    equal in the observation. An absent or malformed observation fails
    closed — an unconfigured external capability is never ready.
    """
    if not isinstance(observation, Mapping):
        return False, REASON_OBSERVATION_MISSING
    for name in sorted(expected):
        if name not in observation:
            return False, f"{REASON_OBSERVATION_MISSING}:{name}"
        if observation[name] != expected[name]:
            return False, f"observation_mismatch:{name}"
    return True, None


# Stop F6 (doc 47 row F6): the presentation-release-seal probe derives its
# readiness from exact observed facts instead of an unconditional constant.
# Every fact must hold for readiness: the sealed build-registry byte pin,
# the exact corrected registry row, the build digest agreement between the
# registry row and the sealed expectations file, the expectations file's
# activation-release identity, and the sealed (non-null) runtime image
# digest. Every store this repository can produce before the separately
# reviewed F2b re-seal fails at least the registry-row, build-digest and
# runtime-digest facts, so the probe still reports pending — structurally,
# never by flag — while the pending prerequisites become observable.
RELEASE_SEAL_FACTS = (
    "registry_pin",
    "registry_row",
    "build_digest",
    "expectations_release",
    "runtime_image_digest",
)


def evaluate_presentation_release_seal(
    facts: Mapping[str, object],
    *,
    expected_release_id: str,
) -> tuple[bool, str | None, list[str]]:
    """Derive seal readiness from the observed fact set, fail closed.

    Returns ``(ready, not_ready_reason, pending_prerequisites)``. The
    reason stays the frozen ``release_seal_pending`` constant whenever any
    prerequisite is unmet, so the Stop D probe laws keep their exact pins;
    the pending list makes the unmet prerequisites observable in the
    recorded probe document.
    """
    pending: list[str] = []
    if facts.get("registry_pin") != "match":
        pending.append("registry_pin")
    if facts.get("registry_row") != "registered":
        pending.append("registry_row")
    if facts.get("build_digest") != "registered":
        pending.append("build_digest")
    if facts.get("expectations_release") != expected_release_id:
        pending.append("expectations_release")
    if facts.get("runtime_image_digest") != "sealed":
        pending.append("runtime_image_digest")
    if pending:
        return False, REASON_RELEASE_SEAL_PENDING, pending
    return True, None, []


# Doc 50 §3.2: the derived authority-configuration facts. Like the seal
# facts, every fact must hold for readiness and each is observed from the
# environment contract and file bytes — never from a network probe and never
# from a caller-authored boolean.
PLAN_ANCHOR_AUTHORITY_FACTS = (
    "environment",
    "issuer_bundle_pin",
    "issuer_key",
)

FINAL_HOLDOUT_AUTHORITY_FACTS = (
    "environment",
    "trust_bundle_pin",
    "signer_key",
    "evaluator_key",
)

# Doc 50 §3.2: the derived executable-readiness facts. ``worker_observation``
# is the control-plane store's view of the serving worker's own recorded
# execution-readiness document; the remaining facts restate that document.
CONTROL_PLANE_REGISTRAR_FACTS = (
    "worker_observation",
    "authority_environment",
    "control_plane_registrar",
    "evaluator_key",
)


def evaluate_plan_anchor_authority(
    facts: Mapping[str, object],
) -> tuple[bool, str | None, list[str]]:
    """Derive plan-anchor authority readiness from observed facts, fail closed."""
    pending: list[str] = []
    if facts.get("environment") != "configured":
        pending.append("environment")
    if facts.get("issuer_bundle_pin") != "match":
        pending.append("issuer_bundle_pin")
    if facts.get("issuer_key") != "present":
        pending.append("issuer_key")
    if pending:
        return False, REASON_AUTHORITY_CONFIGURATION_PENDING, pending
    return True, None, []


def evaluate_final_holdout_authority(
    facts: Mapping[str, object],
) -> tuple[bool, str | None, list[str]]:
    """Derive final-holdout authority readiness from observed facts."""
    pending: list[str] = []
    if facts.get("environment") != "configured":
        pending.append("environment")
    if facts.get("trust_bundle_pin") != "match":
        pending.append("trust_bundle_pin")
    if facts.get("signer_key") != "present":
        pending.append("signer_key")
    if facts.get("evaluator_key") != "held":
        pending.append("evaluator_key")
    if pending:
        return False, REASON_AUTHORITY_CONFIGURATION_PENDING, pending
    return True, None, []


def evaluate_control_plane_registrar(
    facts: Mapping[str, object],
) -> tuple[bool, str | None, list[str]]:
    """Derive executable readiness from the worker's recorded observation.

    ``control_plane_registrar`` reads ready for either resolution of the
    seam — the separate registrar process named by the worker's closed
    registrar environment ("configured") or the reviewed test seam
    ("installed"); anything else means the process is structurally unable
    to execute a new corrected run.
    """
    pending: list[str] = []
    if facts.get("worker_observation") != "fresh":
        pending.append("worker_observation")
    if facts.get("authority_environment") != "configured":
        pending.append("authority_environment")
    if facts.get("control_plane_registrar") not in ("installed", "configured"):
        pending.append("control_plane_registrar")
    if facts.get("evaluator_key") != "held":
        pending.append("evaluator_key")
    if pending:
        return False, REASON_EXECUTION_READINESS_PENDING, pending
    return True, None, []


# The derived-fact law shared by the probe producer and the activation
# transaction: which capability kinds re-derive through which closed
# evaluator (the presentation seal keeps its own five-fact branch).
DERIVED_AUTHORITY_EVALUATORS = {
    CAPABILITY_KIND_PLAN_ANCHOR: (
        PLAN_ANCHOR_AUTHORITY_FACTS, evaluate_plan_anchor_authority),
    CAPABILITY_KIND_FINAL_HOLDOUT: (
        FINAL_HOLDOUT_AUTHORITY_FACTS, evaluate_final_holdout_authority),
    CAPABILITY_KIND_CONTROL_PLANE_REGISTRAR: (
        CONTROL_PLANE_REGISTRAR_FACTS, evaluate_control_plane_registrar),
}


def evaluate_worker_heartbeat(
    heartbeat: Mapping[str, object] | None,
    *,
    now: datetime,
    max_age_seconds: float,
) -> tuple[bool, str | None]:
    """Readiness of one compatible worker heartbeat row (or None)."""
    if heartbeat is None:
        return False, REASON_WORKER_NOT_RUNNING
    if heartbeat.get("state") == "stopped":
        return False, REASON_WORKER_STOPPED
    age = probe_age_seconds(str(heartbeat.get("last_seen_at")), now)
    if age < -CLOCK_SKEW_ALLOWANCE_SECONDS:
        return False, REASON_CLOCK_SKEW
    if age > max_age_seconds:
        return False, REASON_WORKER_STALE
    return True, None


def evaluate_component_hashes(
    registered: Mapping[str, str],
    actual: Mapping[str, str | None],
) -> tuple[bool, str | None]:
    """Readiness of the registered component set against recomputed digests.

    ``actual`` maps each registered path to its recomputed digest, or None
    when the component file is missing or unreadable.
    """
    drifted = sorted(
        path for path, expected in registered.items()
        if actual.get(path) != expected
    )
    if drifted:
        return False, f"{REASON_COMPONENT_DRIFT}:{','.join(drifted)}"
    return True, None


def build_activation_receipt(
    release: Mapping[str, object],
    *,
    actor_id: str,
    user_id: str,
    activated_at: str,
    capability_probe_sha256: str,
) -> dict[str, object]:
    """Construct the immutable §9 step-4 activation receipt.

    The receipt binds the release identity, every registered digest, the exact
    capability-probe set, the acting principal and the activation time. Its
    canonical bytes are hashed so later readers can prove the stored row was
    not rewritten; the insert-only database triggers enforce the same law at
    the SQL level.
    """
    receipt = {
        "receipt_version": RELEASE_ACTIVATION_RECEIPT_VERSION,
        "release_row_id": release["release_row_id"],
        "release_id": release["release_id"],
        "release_state": RELEASE_STATE_ACTIVE,
        "release_tuple_sha256": release["release_tuple_sha256"],
        "component_hashes_sha256": release["component_hashes_sha256"],
        "capability_probe_sha256": capability_probe_sha256,
        "presentation_contract_id": release["presentation_contract_id"],
        "required_worker_contract": release["required_worker_contract"],
        "signer_key_id": release["signer_key_id"],
        "actor_id": actor_id,
        "user_id": user_id,
        "activated_at": activated_at,
    }
    receipt_json = canonical_json(receipt)
    return {
        "receipt": receipt,
        "receipt_json": receipt_json,
        "receipt_sha256": prefixed_sha256(receipt_json.encode("ascii")),
    }
