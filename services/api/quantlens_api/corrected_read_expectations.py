"""Sealed corrected read-time expectations (Stop F2a; sealed at Stop F2b).

This module owns the REVIEWED release-level expectation values for the
corrected release's product-read trust chain: the deterministic battery-v3
configuration hash, the minted financial/metric semantics digests (each the
canonical hash of a reviewed identity document shipped beside this file),
and the sealed runtime image digest. The file is admitted only under its
external byte pin (``QL_CORRECTED_READ_EXPECTATIONS_SHA256``), mirroring
the sealed build-registry pattern, and the loader fails closed on a missing
pin, a byte mismatch, or any schema deviation.

F2b seal (doc 47 §6 step 9; doc 48 §14): ``runtime_image_digest`` carries
the exact frozen runtime identity the F3-F6 code freeze produced — the same
digest the re-sealed build registry registers for the corrected contract —
and null is no longer admissible: a file claiming the pre-seal placeholder
refuses to load. The activation transaction re-validates the populated
store and the registration's declared ``worker_runtime.image_digest``
against this file (``db.activate_prepared_release``). The read chokepoint
consumes the run-scoped store (``db.get_corrected_read_expectations``), not
this file; this file is the review and activation authority for what that
store may contain.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_EXPECTATIONS_FILENAME = "corrected_read_expectations_v1.json"
_EXPECTED_FORMAT = "corrected-read-expectations-v1"
_TOP_LEVEL_KEYS = frozenset({
    "format", "activation_release", "battery_config_hash",
    "financial_semantics", "metric_semantics", "semantics_documents",
    "runtime_image_digest",
})
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^local-runtime-sha256:[0-9a-f]{64}$")


class CorrectedReadExpectationsError(RuntimeError):
    """The sealed expectations file is unavailable, unpinned or malformed."""


@dataclass(frozen=True)
class CorrectedReadExpectations:
    activation_release: str
    battery_config_hash: str
    financial_semantics: Mapping[str, str]
    metric_semantics: Mapping[str, str]
    semantics_documents: Mapping[str, str]
    runtime_image_digest: str


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise CorrectedReadExpectationsError(
            f"corrected read expectations are not admissible: {reason}")


def _digest_map(value: object, label: str) -> dict[str, str]:
    _require(isinstance(value, dict) and len(value) >= 1,
             f"{label} must be a non-empty object")
    normalized: dict[str, str] = {}
    for version, digest in value.items():
        _require(isinstance(version, str) and 1 <= len(version) <= 128,
                 f"{label} versions must be short identifiers")
        _require(isinstance(digest, str)
                 and _PREFIXED_SHA256_RE.fullmatch(digest) is not None,
                 f"{label} digests must be canonical SHA-256")
        normalized[version] = digest
    return normalized


def load_corrected_read_expectations() -> CorrectedReadExpectations:
    """Load and re-verify the sealed expectations file, or fail closed."""
    path = Path(__file__).resolve().parent / _EXPECTATIONS_FILENAME
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CorrectedReadExpectationsError(
            "corrected read expectations are not admissible: the sealed "
            "file is missing or unreadable") from exc
    expected_pin = os.environ.get("QL_CORRECTED_READ_EXPECTATIONS_SHA256")
    _require(isinstance(expected_pin, str) and len(expected_pin) > 0,
             "no external byte pin is configured")
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    _require(actual == expected_pin,
             "the sealed file does not match its external byte pin")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise CorrectedReadExpectationsError(
            "corrected read expectations are not admissible: the sealed "
            "file is not valid JSON") from exc
    _require(isinstance(document, dict)
             and set(document) == _TOP_LEVEL_KEYS,
             "the sealed file is not the closed expectations shape")
    _require(document["format"] == _EXPECTED_FORMAT,
             "the sealed file declares an unreviewed format")
    _require(isinstance(document["activation_release"], str)
             and len(document["activation_release"]) >= 1,
             "activation_release must be a release identifier")
    _require(isinstance(document["battery_config_hash"], str)
             and _PREFIXED_SHA256_RE.fullmatch(
                 document["battery_config_hash"]) is not None,
             "battery_config_hash must be canonical SHA-256")
    financial = _digest_map(
        document["financial_semantics"], "financial_semantics")
    metric = _digest_map(document["metric_semantics"], "metric_semantics")
    documents = document["semantics_documents"]
    _require(isinstance(documents, dict)
             and set(documents) == set(financial) | set(metric),
             "semantics_documents must name one document per digest")
    for version, filename in documents.items():
        _require(isinstance(filename, str)
                 and filename.endswith(".json") and "/" not in filename,
                 "semantics documents must be sibling JSON files")
    digest = document["runtime_image_digest"]
    # Stop F2b: the pre-seal null placeholder is no longer admissible; the
    # sealed file must carry the exact frozen runtime identity.
    _require(isinstance(digest, str)
             and _IMAGE_DIGEST_RE.fullmatch(digest) is not None,
             "runtime_image_digest must be the exact sealed runtime digest; "
             "the pre-F2b null placeholder is no longer admissible")
    return CorrectedReadExpectations(
        activation_release=document["activation_release"],
        battery_config_hash=document["battery_config_hash"],
        financial_semantics=financial,
        metric_semantics=metric,
        semantics_documents=dict(documents),
        runtime_image_digest=digest,
    )


def semantics_document_digest(filename: str) -> str:
    """Canonical digest of one reviewed semantics identity document."""
    from .release_activation import canonical_sha256

    _require(isinstance(filename, str)
             and filename.endswith(".json") and "/" not in filename,
             "semantics documents must be sibling JSON files")
    path = Path(__file__).resolve().parent / filename
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorrectedReadExpectationsError(
            "corrected read expectations are not admissible: a named "
            "semantics document is missing or malformed") from exc
    return canonical_sha256(document)


__all__ = [
    "CorrectedReadExpectations",
    "CorrectedReadExpectationsError",
    "load_corrected_read_expectations",
    "semantics_document_digest",
]
