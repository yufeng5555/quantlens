"""Pure Gate 7A.1 experiment-lineage and annotation logic (`lineage-v1`).

This module is deliberately side-effect free: it computes the deterministic
``lineage-diff-v1`` semantic diff, classifies rerun/variation, validates mutable
workspace metadata text (family titles/descriptions, notes, tags), and builds the
canonical idempotency request binding.  It never touches the database, the
engine, evidence, metrics, or any Agent surface — persistence lives in
:mod:`quantlens_api.db` and policy lives in the API layer.  Mutable workspace
metadata must never be confused with or hashed into immutable research evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata


LINEAGE_DIFF_CONTRACT_VERSION = "lineage-diff-v1"
IDEMPOTENCY_CONTRACT_VERSION = "run-create-idempotency-v1"

CLIENT_RELATIONSHIPS = frozenset({"variation", "rerun"})

# Frozen §5.1 baseline shape: the exact ASCII bytes "[]" and their SHA-256.
EMPTY_DIFF_JSON = "[]"
EMPTY_DIFF_SHA256 = (
    "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945")

# Frozen §5.2 idempotency header pattern.
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

FAMILY_TITLE_MAX = 120
FAMILY_DESCRIPTION_MAX = 2_000
NOTE_TEXT_MAX = 8_000
TAG_DISPLAY_MAX = 32
MAX_TAGS_PER_RUN = 10


class LineageDiffError(ValueError):
    """The two specs differ on a path outside the reviewed semantic allowlist.

    The server never labels an unknown difference as immaterial: the lineage
    write is blocked until the allowlist is reviewed (``UNSUPPORTED_DIFF_SCHEMA``).
    """

    def __init__(self, paths: list[str]):
        super().__init__(
            "specs differ on unreviewed paths: " + ", ".join(sorted(paths)))
        self.code = "UNSUPPORTED_DIFF_SCHEMA"
        self.paths = sorted(paths)


class MetadataValidationError(ValueError):
    """A family/annotation text or tag input violates the frozen contract."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# Frozen §5.3 reviewed leaves — this exact order and these exact labels.
# ``meta.name`` is the only excluded leaf; ``dsl_version`` is equal by the §5.2
# context check and is therefore never emitted (a differing dsl_version reaching
# this function is an unreviewed difference and blocks).
_REVIEWED_PATHS: tuple[tuple[str, str], ...] = (
    ("universe.symbol", "Instrument"),
    ("family", "Strategy family"),
    ("rule.type", "Rule type"),
    ("rule.fast_ma_days", "Fast moving-average window"),
    ("rule.ma_days", "Slow moving-average window"),
    ("calendar.frequency", "Data frequency"),
    ("calendar.execution", "Execution timing"),
    ("benchmark.type", "Benchmark entry rule"),
    ("benchmark.symbol", "Benchmark instrument"),
    ("data.snapshot_policy", "Snapshot policy"),
    ("data.source.kind", "Data source kind"),
    ("data.source.dataset_id", "Dataset identity"),
    ("data.source.dataset_manifest_sha256", "Dataset manifest binding"),
    ("data.range.start", "Requested range start"),
    ("data.range.end", "Requested range end"),
    ("costs.commission_bps", "Commission (bps per fill)"),
    ("costs.slippage_bps", "Legacy execution friction (bps per fill)"),
    ("validation.is_oos_split.oos_fraction", "Out-of-sample share"),
    ("validation.sensitivity.grid.ma_days", "Sensitivity grid windows"),
    ("validation.cost_stress.multipliers", "Cost stress multipliers"),
)

_REVIEWED_LOOKUP = {path: label for path, label in _REVIEWED_PATHS}

_EXCLUDED_PATHS = frozenset({"meta.name"})

_MISSING = object()
_MISSING_PUBLIC = {"__missing__": True}


def _flatten(value: object, prefix: str, out: dict[str, object]) -> None:
    """Flatten a spec into leaf paths. Arrays are leaves and preserve order."""
    if isinstance(value, dict):
        for key in value:
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            _flatten(value[key], child_prefix, out)
        if not value and prefix:
            out[prefix] = value
    else:
        out[prefix] = value


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def _leaves(spec: dict) -> dict[str, object]:
    flat: dict[str, object] = {}
    _flatten(spec, "", flat)
    return flat


def compute_lineage_diff(parent_spec: dict, child_spec: dict) -> dict:
    """Deterministic ``lineage-diff-v1`` semantic diff of two confirmed specs.

    Runs only after the §5.2 context-equality checks (research mode, DSL
    version, battery profile ID/hash, worker contract), so both specs use the
    same supported schema.  Returns ``{"diff_contract_version",
    "changed_assumptions", "canonical_json", "changed_assumptions_sha256"}``.
    Raises :class:`LineageDiffError` for any unreviewed differing leaf.  Never
    reads or computes performance, metrics, evidence, or a verdict.
    """
    parent_flat = _leaves(parent_spec)
    child_flat = _leaves(child_spec)

    # Frozen §5.3 makes missing/null equivalent only when *both* rules are
    # price_vs_ma.  Normalizing each side independently creates a false
    # before=null/after=null change when rule types differ, so this is a
    # cross-spec rule rather than a per-spec flattening rule.
    parent_rule = parent_spec.get("rule")
    child_rule = child_spec.get("rule")
    both_price_vs_ma = (
        isinstance(parent_rule, dict)
        and isinstance(child_rule, dict)
        and parent_rule.get("type") == "price_vs_ma"
        and child_rule.get("type") == "price_vs_ma"
    )
    if both_price_vs_ma:
        parent_flat.setdefault("rule.fast_ma_days", None)
        child_flat.setdefault("rule.fast_ma_days", None)

    unreviewed: list[str] = []
    for path in sorted(set(parent_flat) | set(child_flat)):
        if path in _EXCLUDED_PATHS or path in _REVIEWED_LOOKUP:
            continue
        before = parent_flat.get(path, _MISSING)
        after = child_flat.get(path, _MISSING)
        # An identical unknown leaf is tolerated for defensive forward
        # compatibility; any unknown differing leaf blocks the lineage write.
        if before != after:
            unreviewed.append(path)
    if unreviewed:
        raise LineageDiffError(unreviewed)

    entries: list[dict] = []
    for path, label in _REVIEWED_PATHS:
        before = parent_flat.get(path, _MISSING)
        after = child_flat.get(path, _MISSING)
        if before == after:
            continue
        # Logical key order path,label,before,after; canonical serialization
        # below re-sorts keys for the hashed bytes.
        entries.append({
            "path": path,
            "label": label,
            # JSON null is a real DSL value, so an absent reviewed leaf needs
            # an unambiguous JSON-safe marker.  The reviewed scalar domains do
            # not admit objects, making this marker collision-free.
            "before": dict(_MISSING_PUBLIC) if before is _MISSING else before,
            "after": dict(_MISSING_PUBLIC) if after is _MISSING else after,
        })

    canonical = _canonical_json(entries)
    return {
        "diff_contract_version": LINEAGE_DIFF_CONTRACT_VERSION,
        "changed_assumptions": entries,
        "canonical_json": canonical,
        "changed_assumptions_sha256":
            "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def classify_relationship(changed_assumptions: list[dict]) -> str:
    """Identical research semantics are a rerun; any reviewed change is a variation."""
    return "rerun" if not changed_assumptions else "variation"


# ------------------------------------------------------------------ text safety

def _contains_forbidden_characters(text: str, *, allow_newlines: bool) -> bool:
    """Reject control and direction-override characters.

    Every bidirectional override/embedding/isolate control (U+202A–U+202E,
    U+2066–U+2069, U+200E/U+200F) is Unicode category Cf, so checking Cc/Cf
    covers the contract without banning legitimate right-to-left scripts.
    Notes/descriptions allow LF and tab; titles/tags reject all Cc/Cf.
    """
    for char in text:
        if char in ("\n", "\t") and allow_newlines:
            continue
        if unicodedata.category(char) in {"Cc", "Cf"}:
            return True
    return False


def validate_family_title(raw: object) -> str:
    if not isinstance(raw, str):
        raise MetadataValidationError("The family title must be text.")
    # Reject controls before trimming: Python's strip() also removes several
    # Cc information separators, but the contract rejects every Cc/Cf rather
    # than silently discarding them.
    if _contains_forbidden_characters(raw, allow_newlines=False):
        raise MetadataValidationError(
            "The family title cannot contain control or direction-override "
            "characters.")
    title = raw.strip()
    if not 1 <= len(title) <= FAMILY_TITLE_MAX:
        raise MetadataValidationError(
            f"The family title must be 1 to {FAMILY_TITLE_MAX} characters.")
    return title


def validate_family_description(raw: object) -> str:
    if not isinstance(raw, str):
        raise MetadataValidationError("The family description must be text.")
    # Descriptions may intentionally begin/end with LF or tab. They are not a
    # trimmed identity field, so preserve the exact allowed plain text.
    description = raw
    if len(description) > FAMILY_DESCRIPTION_MAX:
        raise MetadataValidationError(
            f"The family description is limited to {FAMILY_DESCRIPTION_MAX} "
            "characters.")
    if _contains_forbidden_characters(description, allow_newlines=True):
        raise MetadataValidationError(
            "The family description cannot contain control or "
            "direction-override characters.")
    return description


def default_family_title(source_name: object) -> str:
    """Derive a valid family title from a source strategy display name."""
    if (not isinstance(source_name, str)
            or _contains_forbidden_characters(
                source_name, allow_newlines=False)):
        return "Untitled research"
    candidate = source_name.strip()
    candidate = candidate[:FAMILY_TITLE_MAX].strip()
    if not candidate or _contains_forbidden_characters(
            candidate, allow_newlines=False):
        return "Untitled research"
    return candidate


def validate_note_text(raw: object) -> str:
    if not isinstance(raw, str):
        raise MetadataValidationError("The note must be plain text.")
    if len(raw) > NOTE_TEXT_MAX:
        raise MetadataValidationError(
            f"The note is limited to {NOTE_TEXT_MAX} characters.")
    if _contains_forbidden_characters(raw, allow_newlines=True):
        raise MetadataValidationError(
            "The note cannot contain control or direction-override characters.")
    return raw


def normalize_tag(raw: object) -> tuple[str, str]:
    """Frozen §5.1 order: NFKC, trim Unicode whitespace, validate 1–32 code
    points, then case-fold for identity. Returns ``(display_tag, normalized_tag)``."""
    if not isinstance(raw, str):
        raise MetadataValidationError("Each tag must be text.")
    normalized_input = unicodedata.normalize("NFKC", raw)
    if _contains_forbidden_characters(
            normalized_input, allow_newlines=False):
        raise MetadataValidationError(
            "Tags cannot contain control or direction-override characters.")
    display = normalized_input.strip()
    if not 1 <= len(display) <= TAG_DISPLAY_MAX:
        raise MetadataValidationError(
            f"Each tag must be 1 to {TAG_DISPLAY_MAX} characters.")
    normalized = display.casefold()
    if not normalized:
        raise MetadataValidationError("Each tag must contain visible characters.")
    return display, normalized


def validate_tags(raw_tags: object) -> list[tuple[str, str, int]]:
    """Validate a complete replacement tag set.

    Returns ordered ``(display_tag, normalized_tag, ordinal)`` triples with the
    zero-based submitted order.  A normalized-identity collision is an error —
    never a silent deduplication.
    """
    if not isinstance(raw_tags, list):
        raise MetadataValidationError("Tags must be a list of text values.")
    if len(raw_tags) > MAX_TAGS_PER_RUN:
        raise MetadataValidationError(
            f"A run is limited to {MAX_TAGS_PER_RUN} tags.")
    seen: set[str] = set()
    validated: list[tuple[str, str, int]] = []
    for ordinal, raw in enumerate(raw_tags):
        display, normalized = normalize_tag(raw)
        if normalized in seen:
            raise MetadataValidationError(
                "Two submitted tags collapse to the same normalized identity.")
        seen.add(normalized)
        validated.append((display, normalized, ordinal))
    return validated


def validate_idempotency_key(raw: object) -> str:
    if not isinstance(raw, str) or not IDEMPOTENCY_KEY_PATTERN.fullmatch(raw):
        raise MetadataValidationError(
            "The Idempotency-Key header must match ^[A-Za-z0-9._:-]{1,128}$.")
    return raw


def canonical_idempotency_request(
    *,
    tenant_id: str,
    user_id: str,
    spec_hash: str,
    research_mode: str,
    battery_profile: str,
    battery_profile_hash: str,
    confirmed_preflight_hash: str | None,
    acknowledged_preflight_warning_ids: list[str],
    lineage_parent_run_id: str | None,
    lineage_confirmed_parent_spec_hash: str | None,
    lineage_relationship: str | None,
) -> tuple[str, str]:
    """Frozen §5.2 canonical request: ASCII JSON, sorted keys, compact
    separators, ``allow_nan=False``, over the normalized client request and
    confirmed bindings only.  Server-generated family/run/reservation/receipt
    IDs and live worker state are excluded by construction.  Returns
    ``(canonical_json, sha256_hex)``."""
    payload = {
        "contract": IDEMPOTENCY_CONTRACT_VERSION,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "spec_hash": spec_hash,
        "research_mode": research_mode,
        "battery_profile": battery_profile,
        "battery_profile_hash": battery_profile_hash,
        "confirmed_preflight_hash": confirmed_preflight_hash,
        "acknowledged_preflight_warning_ids":
            sorted(set(acknowledged_preflight_warning_ids)),
        "lineage_parent_run_id": lineage_parent_run_id,
        "lineage_confirmed_parent_spec_hash": lineage_confirmed_parent_spec_hash,
        "lineage_relationship": lineage_relationship,
    }
    canonical = _canonical_json(payload)
    return canonical, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "CLIENT_RELATIONSHIPS",
    "EMPTY_DIFF_JSON",
    "EMPTY_DIFF_SHA256",
    "FAMILY_DESCRIPTION_MAX",
    "FAMILY_TITLE_MAX",
    "IDEMPOTENCY_CONTRACT_VERSION",
    "IDEMPOTENCY_KEY_PATTERN",
    "LINEAGE_DIFF_CONTRACT_VERSION",
    "LineageDiffError",
    "MAX_TAGS_PER_RUN",
    "MetadataValidationError",
    "NOTE_TEXT_MAX",
    "TAG_DISPLAY_MAX",
    "canonical_idempotency_request",
    "classify_relationship",
    "compute_lineage_diff",
    "default_family_title",
    "normalize_tag",
    "validate_family_description",
    "validate_family_title",
    "validate_idempotency_key",
    "validate_note_text",
    "validate_tags",
]
