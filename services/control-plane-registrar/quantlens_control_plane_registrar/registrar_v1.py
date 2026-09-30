"""Control-plane registrar core: signed authority flows plus the one-issue law.

The registrar owns exactly the three CONTROL_PLANE_REGISTRAR responsibilities
of the corrected chain — issue a validation-plan anchor at the plan-anchor
authority, register the encrypted-capsule material and register the issued
anchor at the final-holdout authority. It signs those requests with its own
role keys, loaded from owner-only seed files that are DISJOINT from every
authority signing seed and from the worker evaluator seed: the environment
contracts of the three processes share no key-file variable, so no single
process configuration can both register and consume holdout access.

The durable one-issue law: at most one validation plan may ever be issued an
anchor per run identity (``tenant_id|workspace_id|run_id``). A byte-identical
re-issue is passed through (the authority replays idempotently, which is what
a crash-resumed worker needs); a DIFFERENT plan for an already-served run
identity is refused before any authority sees it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quantlens_schema.plan_anchor_protocol_v1 import (
    PLAN_ANCHOR_ISSUE_BODY_VERSION_V1,
    PLAN_ANCHOR_ISSUE_PATH_V1,
    PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1,
    PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1,
    CONTROL_PLANE_REGISTRAR_ROLE,
    canonical_json_bytes,
    canonical_plan_anchor_issue_body_bytes,
    canonical_unsigned_plan_anchor_issue_request_bytes,
)
from quantlens_schema.final_holdout_access_protocol_v1 import (
    FINAL_HOLDOUT_ACCESS_PROTOCOL,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
    FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
    FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1,
    FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1,
    FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
    canonical_final_holdout_anchor_registration_body_bytes,
    canonical_final_holdout_capsule_registration_body_bytes,
    canonical_unsigned_final_holdout_client_request_bytes,
)

REGISTRAR_DB_FILENAME = "control-plane-registrar.sqlite3"

_LOOPBACK_ORIGIN_RE = re.compile(r"^http://127\.0\.0\.1(:\d{1,5})?$")


class ControlPlaneRegistrarError(RuntimeError):
    """Configuration or invariant failure inside the registrar process."""


class RegistrarRequestError(ValueError):
    """The caller's registrar envelope cannot be served."""


class RegistrarRunConflictError(RegistrarRequestError):
    """A different validation plan was already issued for this run identity."""


class RegistrarUpstreamError(RuntimeError):
    """The authority refused or could not be reached; nothing was issued."""

    def __init__(self, message: str, *, authority_status: int | None = None):
        super().__init__(message)
        self.authority_status = authority_status


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlPlaneRegistrarError(message)


def _load_registrar_signer(path: Path, label: str) -> Callable[[bytes], bytes]:
    """Load one raw Ed25519 registrar seed with owner-only file hygiene."""
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise ControlPlaneRegistrarError(
            f"the {label} registrar key file is missing") from error
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ControlPlaneRegistrarError(
            f"the {label} registrar key file must be a regular owner-only file")
    seed = path.read_bytes()
    if len(seed) != 32:
        raise ControlPlaneRegistrarError(
            f"the {label} registrar key file must hold exactly one raw "
            "Ed25519 seed")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return lambda message: private_key.sign(message)


def _loopback_post(base_url: str, *, timeout_seconds: float = 30.0,
                   ) -> Callable[[str, bytes], tuple[int, bytes]]:
    """A stdlib POST pinned to one loopback origin with proxies disabled."""
    _require(
        isinstance(base_url, str)
        and _LOOPBACK_ORIGIN_RE.fullmatch(base_url) is not None,
        "the authority base URL must be an exact loopback origin",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def post(path: str, payload: bytes) -> tuple[int, bytes]:
        request = urllib.request.Request(
            base_url + path, data=payload, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as error:
            return int(error.code), error.read()
        except (urllib.error.URLError, OSError) as error:
            raise RegistrarUpstreamError(
                "the authority endpoint could not be reached") from error

    return post


def _sha256_prefixed(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_identity(validation_plan: Mapping[str, Any]) -> str:
    parts = []
    for field in ("tenant_id", "workspace_id", "run_id"):
        value = validation_plan.get(field)
        if not isinstance(value, str) or not value:
            raise RegistrarRequestError(
                f"the validation plan must carry a non-empty {field}")
        parts.append(value)
    return "|".join(parts)


@dataclass(frozen=True)
class ControlPlaneRegistrarConfig:
    """Registrar-only configuration; key files are paths, never key bytes."""

    registrar_var_dir: Path
    plan_anchor_authority_url: str
    plan_anchor_authority_id: str
    plan_anchor_registrar_key_id: str
    plan_anchor_registrar_private_key_file: Path
    holdout_authority_url: str
    holdout_authority_id: str
    holdout_registrar_key_id: str
    holdout_registrar_private_key_file: Path
    busy_timeout_ms: int = 5_000


class ControlPlaneRegistrarV1:
    """The reviewed production registrar behind the three protocol flows."""

    def __init__(self, config: ControlPlaneRegistrarConfig, *,
                 token_hex: Callable[[], str] | None = None,
                 now: Callable[[], str] | None = None) -> None:
        _require(isinstance(config, ControlPlaneRegistrarConfig),
                 "the registrar requires a ControlPlaneRegistrarConfig")
        var_dir = config.registrar_var_dir
        _require(var_dir.is_dir(),
                 "the registrar var directory must already exist")
        info = os.stat(var_dir, follow_symlinks=False)
        _require(not info.st_mode & 0o077,
                 "the registrar var directory must be owner-only")
        self._config = config
        self._plan_anchor_sign = _load_registrar_signer(
            config.plan_anchor_registrar_private_key_file, "plan-anchor")
        self._holdout_sign = _load_registrar_signer(
            config.holdout_registrar_private_key_file, "final-holdout")
        self._post_plan_anchor = _loopback_post(config.plan_anchor_authority_url)
        self._post_holdout = _loopback_post(config.holdout_authority_url)
        self._token_hex = token_hex or (lambda: secrets.token_hex(16))
        self._now = now or _utc_timestamp
        self._db_path = var_dir / REGISTRAR_DB_FILENAME
        self._init_store()

    # ---------------------------------------------------------------- store

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        connection.execute(
            f"PRAGMA busy_timeout = {int(self._config.busy_timeout_ms)}")
        return connection

    def _init_store(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS registrar_issued_runs ("
                "run_identity TEXT PRIMARY KEY, "
                "validation_plan_sha256 TEXT NOT NULL, "
                "issued_at TEXT NOT NULL)"
            )

    def _reserve_run_identity(self, run_identity: str,
                              plan_sha256: str) -> None:
        """The durable one-issue law, decided before any authority contact."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT validation_plan_sha256 FROM registrar_issued_runs "
                "WHERE run_identity = ?",
                (run_identity,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO registrar_issued_runs("
                    "run_identity, validation_plan_sha256, issued_at) "
                    "VALUES (?, ?, ?)",
                    (run_identity, plan_sha256, self._now()),
                )
                return
            if row["validation_plan_sha256"] != plan_sha256:
                raise RegistrarRunConflictError(
                    "a different validation plan was already issued an "
                    "anchor for this run identity")
            # Byte-identical plan: the crash-resume passthrough; the
            # authority's own idempotent replay law returns the original
            # anchor bytes.

    # ---------------------------------------------------------------- flows

    def issue_anchor(self, validation_plan: Mapping[str, Any]) -> dict:
        """Obtain one signed anchor from the plan-anchor authority child."""
        run_identity = _run_identity(validation_plan)
        plan = json.loads(json.dumps(validation_plan))
        body = {
            "body_version": PLAN_ANCHOR_ISSUE_BODY_VERSION_V1,
            "validation_plan": plan,
        }
        # Canonicalization VALIDATES the complete sealed validation-plan
        # grammar; an inadmissible plan is refused BEFORE the run identity
        # is reserved and before anything is signed.
        try:
            body_bytes = canonical_plan_anchor_issue_body_bytes(body)
        except Exception as error:  # noqa: BLE001 — sanitized typed refusal
            raise RegistrarRequestError(
                "the validation plan is not admissible") from error
        plan_sha256 = _sha256_prefixed(canonical_json_bytes(plan))
        self._reserve_run_identity(run_identity, plan_sha256)
        request = {
            "request_version": PLAN_ANCHOR_ISSUE_REQUEST_VERSION_V1,
            "request_id": "vpr-" + self._token_hex(),
            "authority_id": self._config.plan_anchor_authority_id,
            "registrar_role": CONTROL_PLANE_REGISTRAR_ROLE,
            "registrar_key_id": self._config.plan_anchor_registrar_key_id,
            "method": "POST",
            "path": PLAN_ANCHOR_ISSUE_PATH_V1,
            "timestamp": self._now(),
            "nonce": self._token_hex(),
            "body_sha256": _sha256_prefixed(body_bytes),
            "signature_algorithm": "ed25519",
            "signature": "0" * 128,
        }
        request["signature"] = self._plan_anchor_sign(
            PLAN_ANCHOR_ISSUE_REQUEST_DOMAIN_V1
            + canonical_unsigned_plan_anchor_issue_request_bytes(request)
        ).hex()
        status, payload = self._post_plan_anchor(
            PLAN_ANCHOR_ISSUE_PATH_V1,
            canonical_json_bytes({"issue_request": request, "body": body}))
        document = self._parsed_authority_payload(status, payload)
        issued = {
            field: document.get(field)
            for field in (
                "anchor", "registration_receipt",
                "registered_signed_anchor_bytes_hex",
                "registered_signed_receipt_bytes_hex",
            )
        }
        if not all(issued.values()):
            raise RegistrarUpstreamError(
                "the plan-anchor authority response is missing issued-anchor "
                "material", authority_status=status)
        return issued

    def register_capsule(self, validation_plan: Mapping[str, Any],
                         primary_observations: Mapping[str, Any]) -> dict:
        """Register the capsule material at the final-holdout authority."""
        body = {
            "body_version": FINAL_HOLDOUT_CAPSULE_REGISTRATION_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "validation_plan": json.loads(json.dumps(validation_plan)),
            "primary_observations": json.loads(
                json.dumps(primary_observations)),
        }
        try:
            body_bytes = (
                canonical_final_holdout_capsule_registration_body_bytes(body))
        except Exception as error:  # noqa: BLE001 — sanitized typed refusal
            raise RegistrarRequestError(
                "the capsule registration body is not admissible") from error
        return self._holdout_registration(
            FINAL_HOLDOUT_CAPSULE_REGISTRATION_PATH_V1, body, body_bytes)

    def register_anchor(self, capsule_id: str,
                        issued: Mapping[str, Any]) -> dict:
        """Register the issued anchor at the final-holdout authority."""
        if not isinstance(capsule_id, str) or not capsule_id:
            raise RegistrarRequestError("capsule_id must be a non-empty string")
        body = {
            "body_version": FINAL_HOLDOUT_ANCHOR_REGISTRATION_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "capsule_id": capsule_id,
            "anchor": json.loads(json.dumps(issued["anchor"])),
            "registered_signed_anchor_bytes_hex": str(
                issued["registered_signed_anchor_bytes_hex"]),
            "registration_receipt": json.loads(
                json.dumps(issued["registration_receipt"])),
            "registered_signed_receipt_bytes_hex": str(
                issued["registered_signed_receipt_bytes_hex"]),
        }
        try:
            body_bytes = (
                canonical_final_holdout_anchor_registration_body_bytes(body))
        except Exception as error:  # noqa: BLE001 — sanitized typed refusal
            raise RegistrarRequestError(
                "the anchor registration body is not admissible") from error
        return self._holdout_registration(
            FINAL_HOLDOUT_ANCHOR_REGISTRATION_PATH_V1, body, body_bytes)

    # ------------------------------------------------------------- internals

    def _holdout_registration(self, path: str, body: Mapping[str, Any],
                              body_bytes: bytes) -> dict:
        request = {
            "request_version": FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
            "request_id": "fha-req-" + self._token_hex(),
            "authority_id": self._config.holdout_authority_id,
            "caller_role": CONTROL_PLANE_REGISTRAR_ROLE,
            "caller_key_id": self._config.holdout_registrar_key_id,
            "method": "POST",
            "path": path,
            "timestamp": self._now(),
            "nonce": self._token_hex(),
            "body_sha256": _sha256_prefixed(body_bytes),
            "signature_algorithm": "ed25519",
            "signature": "0" * 128,
        }
        request["signature"] = self._holdout_sign(
            FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1
            + canonical_unsigned_final_holdout_client_request_bytes(request)
        ).hex()
        status, payload = self._post_holdout(
            path,
            canonical_json_bytes({"client_request": request, "body": body}))
        document = self._parsed_authority_payload(status, payload)
        result = document.get("body")
        if not isinstance(result, dict):
            raise RegistrarUpstreamError(
                "the final-holdout authority response carries no body",
                authority_status=status)
        return result

    @staticmethod
    def _parsed_authority_payload(status: int, payload: bytes) -> dict:
        if status != 200:
            raise RegistrarUpstreamError(
                "the authority refused the registrar request",
                authority_status=status)
        try:
            document = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise RegistrarUpstreamError(
                "the authority returned a malformed response",
                authority_status=status) from error
        if not isinstance(document, dict):
            raise RegistrarUpstreamError(
                "the authority returned a malformed response",
                authority_status=status)
        return document


__all__ = [
    "ControlPlaneRegistrarConfig",
    "ControlPlaneRegistrarError",
    "ControlPlaneRegistrarV1",
    "REGISTRAR_DB_FILENAME",
    "RegistrarRequestError",
    "RegistrarRunConflictError",
    "RegistrarUpstreamError",
]
