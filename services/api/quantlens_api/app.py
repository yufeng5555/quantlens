"""QuantLens research-audit control plane — FastAPI, local/private preview.

Boundaries honored here (02 §1/§3): Gate 6A has a provider-neutral briefing contract,
but the installed provider is disabled and falls back atomically to the deterministic
parser (no LLM or network); every spec passes
schema -> scope -> lint before queueing; compute is impossible without explicit user
confirmation of the plain-language restatement; drafts never carry performance. Gate 5A
adds a provider-neutral principal and tenant+user object scoping. Gate 6A adds an inert,
strict model-provider contract whose complete output still falls back to the deterministic
parser. The runnable local-preview identity remains explicitly unauthenticated. No live
model, billing, or external IdP is configured here.
"""

from __future__ import annotations

import base64
import binascii
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
from typing import Literal
import jsonschema
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel, ConfigDict, Field, model_validator

from quantlens_schema import (
    default_spec, load_universe, normalize_spec_names, restatement, spec_hash,
    validate_full,
)
from quantlens_schema.validator import SUPPORTED_SCOPE_STATEMENT, DEFAULT_FIELDS

from quantlens_worker.artifacts import (
    ArtifactIntegrityError,
    UnsupportedArtifactContractError,
    load_presentation_artifacts,
)
from quantlens_worker.evidence import NOT_RUN, load_verified_evidence
from quantlens_worker.evidence_v2 import development_only_explanation
from quantlens_worker.presentation_v3 import (
    V3CheckpointMissingError,
    V3ResolutionError,
    build_evidence_view_v3,
    load_v3_checkpoint,
    render_report_v3_html,
    resolve_v3_presentation,
    v3_checkpoint_exists,
)
from quantlens_worker.presentation_read_v3 import (
    TrustedProductReadInputs,
    V3ProductReadError,
    resolve_v3_product_read,
)
from quantlens_worker.narrative_facts import (
    NarrativeFactCatalogError,
    build_narrative_fact_catalog,
)
from quantlens_worker.report import render_report_html
from quantlens_worker.snapshot import DataQualityError, verify_snapshot_integrity
from quantlens_worker.validation_plan import (
    BATTERY_V1,
    BATTERY_V2,
    profile_restatement,
    profile_descriptor,
)

from . import db
from . import google_auth
from . import magic_link
from . import market_bundle
from . import seeding
from .request_limits import RequestBodyLimit
from .agent import BriefingService, DevelopmentResearchCopilot, ExplanationService
from .agent.narrative_renderer import NarrativeGuardError, build_current_binding
from .agent.research_projection import (
    ResearchProjectionError,
    build_development_projection,
)
from .artifact_compat import (
    financial_semantics_rebuild_issue,
    legacy_checkpoint_issue,
    unsupported_artifact_contract_issue,
)
from .auth import (
    LOCAL_PREVIEW_MODE,
    Principal,
    configure_auth_provider,
    configured_local_preview_principal,
    require_principal,
    session_public_view,
)
from .corrected_profile import (
    corrected_admission_refusal,
    corrected_dsl_refusal,
    corrected_profile_descriptor,
    corrected_profile_restatement,
)
from .dataset_imports import (
    ALLOWED_TIMEZONES,
    MAX_OPEN_DATASET_IMPORTS,
    MAX_UPLOAD_BYTES,
    TOTAL_RETURN,
    create_import,
    discard_dataset_directory,
    finalize_quarantine,
    seal_import,
    validate_import,
)
from .mock_parser import PARSER_LABEL
from .experiment_metadata import (
    LineageDiffError,
    MetadataValidationError,
    canonical_idempotency_request,
    classify_relationship,
    compute_lineage_diff,
    normalize_tag,
    validate_family_description,
    validate_family_title,
    validate_idempotency_key,
    validate_note_text,
    validate_tags,
)
from .preflight import evaluate_preflight, principal_source_context
from .release_activation import (
    RELEASE_STATE_ACTIVE,
    RELEASE_STATE_SUPERSEDED,
    RELEASE_TUPLE_FIELDS,
    ReleaseStateError,
    canonical_sha256,
)
from .market_data import (
    AdjustmentMode,
    DatasetRightsOperation,
    LicensedDataRuntime,
    MarketDataError,
    acquisition_public_view,
    activated_rights_policy_from_env,
    assert_dataset_directory_rights,
    create_and_process_acquisition,
    licensed_data_runtime_from_env,
    market_data_public_config,
    resolve_canonical_instrument,
)
from .runtime_contract import (
    WORKER_RUNTIME_CONTRACT,
    assert_expected_runtime,
    public_runtime_view,
)


logger = logging.getLogger("quantlens.api")


# Every mode whose principal is backed by a row in `accounts`. They differ only
# in how the address was proved, so anything that depends on having an account —
# the stored report preference, the session view that carries it — must test
# membership here rather than name one of them.
ACCOUNT_BOUNDARY_MODES = frozenset({
    magic_link.MAGIC_LINK_MODE,
    google_auth.GOOGLE_MODE,
})


def _resolve_magic_link_session(
    session_sha256: str, now: datetime,
) -> magic_link.AccountSession | None:
    """Storage adapter for the magic-link provider: read-only, fail-closed."""
    row = db.resolve_auth_session(session_sha256, now.isoformat())
    if row is None:
        return None
    return magic_link.AccountSession(
        account_id=row["account_id"],
        email=row["email_normalized"],
        display_label=row["display_label"],
        report_role=row["report_role"],
        expires_at=row["expires_at"],
    )


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    assert_expected_runtime("api")
    db.init_db()
    configured_mode = os.getenv("QL_AUTH_MODE", LOCAL_PREVIEW_MODE).strip().lower()
    if configured_mode in ACCOUNT_BOUNDARY_MODES:
        # Installing the provider is the single step that turns this deployment
        # from an unauthenticated local preview into an account boundary. Both
        # modes resolve the same session cookie — they differ only in how an
        # address was proved — so the mode is passed through to the principal
        # rather than assumed, and the workspace page can say honestly which
        # sign-in this deployment offers.
        configure_auth_provider(magic_link.MagicLinkAuthProvider(
            _resolve_magic_link_session, mode=configured_mode))
    if os.getenv("QL_AUTH_MODE", LOCAL_PREVIEW_MODE).strip().lower() == LOCAL_PREVIEW_MODE:
        try:
            local_principal = configured_local_preview_principal()
        except ValueError:
            # Keep startup observable; protected requests return the sanitized 503 from
            # require_principal until the invalid server configuration is corrected.
            pass
        else:
            db.provision_local_principal(
                local_principal.tenant_id,
                local_principal.user_id,
            )
    yield


app = FastAPI(title="QuantLens Research Audit API", version="0.5.0",
              lifespan=_lifespan)

_PUBLIC_API_PATHS = frozenset({
    "/health", "/dataset-imports/config", "/universe", "/templates",
})
_FRAMEWORK_PUBLIC_PATHS = frozenset({
    "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc",
})


@app.middleware("http")
async def _private_response_headers(request: Request, call_next):
    """Sanitize failures and keep private workspace responses out of all caches."""
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001 — API boundary; response must remain sanitized
        # Never reflect an exception string, SQL detail, path, or worker trace.  The
        # caller gets a stable contract while the full exception remains in local logs.
        logger.exception(
            "unhandled API error method=%s path=%s",
            request.method, request.url.path,
        )
        response = _internal_error_response()
    if _is_private_path(request.url.path):
        _apply_private_security_headers(response)
    return response


def _is_private_path(path: str) -> bool:
    return path not in _PUBLIC_API_PATHS and path not in _FRAMEWORK_PUBLIC_PATHS


def _merge_vary_header(response, *tokens: str) -> None:
    """Append Vary tokens without erasing CORS's existing ``Origin`` directive."""
    existing = [part.strip() for part in response.headers.get("Vary", "").split(",")
                if part.strip()]
    if "*" in existing:
        return
    seen = {part.casefold() for part in existing}
    for token in tokens:
        if token.casefold() not in seen:
            existing.append(token)
            seen.add(token.casefold())
    response.headers["Vary"] = ", ".join(existing)


def _apply_private_security_headers(response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Pragma"] = "no-cache"
    _merge_vary_header(response, "Authorization", "Cookie")
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _internal_error_response() -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": {
        "code": "INTERNAL_ERROR",
        "message": "An unexpected error occurred.",
    }})


@app.exception_handler(Exception)
async def _unexpected_error(request: Request, exc: Exception):
    """Last-resort sanitized response for failures outside request middleware."""
    logger.error(
        "unhandled framework error method=%s path=%s",
        request.method, request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    response = _internal_error_response()
    if _is_private_path(request.url.path):
        _apply_private_security_headers(response)
    return response


def _storage_refused_detail(storage: dict) -> dict:
    """Refusal BEFORE anything was written. Only this path may promise atomicity."""
    return {
        "code": "STORAGE_EXHAUSTED",
        "message": (
            "This deployment's storage volume is out of room, so nothing was "
            "started: no work was enqueued and no run allowance was reserved. "
            "An operator has to free space or grow the volume."
        ),
        "storage": storage,
    }


def _storage_failed_mid_request_detail(storage: dict) -> dict:
    """The volume filled part-way through a request that had already begun.

    Deliberately a different code and a weaker claim than the refusal above. This
    body is emitted by a handler that fires on any route, and at least one of them
    commits as it goes -- ``POST /datasets/bundle`` seals one series per iteration --
    so promising that nothing was written would be a statement the product cannot
    back on the very screen that lists what was.
    """
    return {
        "code": "STORAGE_EXHAUSTED_MID_REQUEST",
        "message": (
            "This deployment's storage volume ran out of room while this request "
            "was being carried out, so the request did not finish. Whatever was "
            "already sealed before that point is unaffected and is still listed. "
            "An operator has to free space or grow the volume."
        ),
        "storage": storage,
    }


async def _storage_exhausted_response(
        request: Request, exc: BaseException) -> JSONResponse:
    storage = db.storage_health()
    logger.error(
        "control-plane storage exhausted method=%s path=%s error=%s "
        "free_bytes=%s floor_bytes=%s",
        request.method, request.url.path, type(exc).__name__,
        storage["free_bytes"], storage["floor_bytes"],
    )
    response = JSONResponse(
        status_code=507,
        content={"detail": _storage_failed_mid_request_detail(storage)},
        headers={"Retry-After": "60"},
    )
    if _is_private_path(request.url.path):
        _apply_private_security_headers(response)
    return response


@app.exception_handler(sqlite3.OperationalError)
async def _control_plane_storage_error(
        request: Request, exc: sqlite3.OperationalError):
    """Report a full volume as itself rather than as an anonymous 500.

    A full disk previously reached the caller as ``INTERNAL_ERROR`` with nothing in
    the response or the log naming the actual condition, so the one failure an
    operator can actually fix looked identical to a code defect. Every other
    operational failure is put straight back, so the sanitizing middleware above
    keeps handling it exactly as before.
    """
    if not db.is_storage_exhausted_error(exc):
        raise exc
    return await _storage_exhausted_response(request, exc)


@app.exception_handler(OSError)
async def _filesystem_storage_error(request: Request, exc: OSError):
    """The same condition arriving from the file side rather than from SQLite.

    Quarantined uploads and sealed dataset directories are plain file writes, so a
    full volume reaches them as ``ENOSPC`` -- which is not a ``sqlite3`` error at
    all and so would still have been an anonymous 500. Every other ``OSError`` is
    put straight back untouched.
    """
    if not db.is_storage_exhausted_error(exc):
        raise exc
    return await _storage_exhausted_response(request, exc)


# Add CORS after the failure/header boundary so Starlette wraps it on the outside.  This
# keeps allowed-origin response headers available even when an inner route fails, while
# the inner middleware can still merge private Vary dimensions without clobbering them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "X-CSRF-Token", "Idempotency-Key",
    ],
    allow_credentials=False,
)

# Added last, so it runs FIRST -- outside CORS and outside the response-header middleware,
# and therefore before routing and before any dependency can be resolved. That ordering is
# the whole point: a body declared as a route parameter is read and parsed before
# require_principal is ever consulted, so an anonymous caller's 401 is billed to this
# process in full. Nothing inside a route can undo that. See request_limits.py.
app.add_middleware(RequestBodyLimit)


def _workspace_item_not_found() -> HTTPException:
    """One missing/foreign response shape prevents object-existence disclosure."""
    return HTTPException(status_code=404, detail={
        "code": "ITEM_NOT_AVAILABLE",
        "message": "This item isn't available in this workspace.",
    })


class ParseBody(BaseModel):
    hypothesis: str


class SpecBody(BaseModel):
    spec: dict
    battery_profile: str = BATTERY_V1


class RunLineageIntent(BaseModel):
    """Frozen §5.2 lineage intent — client diff/family fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    parent_run_id: str
    confirmed_parent_spec_hash: str
    relationship: Literal["variation", "rerun"]


class RunBody(BaseModel):
    spec: dict
    research_mode: Literal["formal", "sandbox"] = "formal"
    confirmed: bool = False
    restatement_seen: bool = False
    confirmed_spec_hash: str | None = None
    battery_profile: str = BATTERY_V1
    confirmed_battery_profile_hash: str | None = None
    confirmed_preflight_hash: str | None = None
    acknowledged_preflight_warning_ids: list[str] = Field(default_factory=list)
    lineage: RunLineageIntent | None = None

    @model_validator(mode="before")
    @classmethod
    def _reject_reserved_lineage_keys(cls, data: object) -> object:
        # The outer body stays tolerant for ordinary-create compatibility, but
        # server-owned lineage material may never be injected at the top level.
        if isinstance(data, dict):
            reserved = {"family_id", "lineage_diff", "changed_assumptions"}
            present = sorted(reserved & set(data))
            if present:
                raise ValueError(
                    "server-owned lineage fields are not accepted: "
                    + ", ".join(present))
        return data


class ExperimentPatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    description: str | None = None
    expected_revision: int = Field(ge=1, strict=True)


class AnnotationsPutBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str
    tags: list[str]
    expected_revision: int = Field(ge=0, strict=True)


class EventBody(BaseModel):
    type: str
    payload: dict = Field(default_factory=dict)


class DatasetValidateBody(BaseModel):
    symbol: str
    mapping: dict[str, str]
    timezone: str = "America/New_York"
    prices_adjusted: bool = False
    rights_attested: bool = False


class DatasetSealBody(DatasetValidateBody):
    display_name: str
    confirmed_profile_hash: str
    acknowledged_warnings: list[str] = Field(default_factory=list)


class MarketDataResolveBody(BaseModel):
    symbol: str = Field(min_length=1, max_length=15)


class MarketDataAcquisitionBody(BaseModel):
    symbol: str = Field(min_length=1, max_length=15)
    start: date
    end: date
    adjustment_mode: Literal["splits"] = "splits"
    confirmed_instrument_id: str = Field(min_length=3, max_length=120)
    display_name: str = Field(min_length=1, max_length=80)
    confirmed: bool = False


def _market_data_http_status(code: str) -> int:
    if code == "MARKET_DATA_RATE_LIMITED":
        return 429
    if code in {
        "MARKET_DATA_PROVIDER_UNAVAILABLE", "MARKET_DATA_PROVIDER_REJECTED",
    }:
        return 503
    if code in {
        "MARKET_DATA_NOT_ACTIVATED", "MARKET_DATA_LICENSE_NOT_CONFIRMED",
        "MARKET_DATA_RIGHTS_POLICY_MISSING", "MARKET_DATA_RIGHTS_POLICY_INVALID",
        "MARKET_DATA_RIGHTS_POLICY_STALE", "MARKET_DATA_CREDENTIAL_MISSING",
        "MARKET_DATA_EXCHANGE_CALENDAR_UNAVAILABLE",
        "MARKET_DATA_EXCHANGE_CALENDAR_VERSION_MISMATCH",
        "MARKET_DATA_INSTRUMENT_CONFIRMATION_STALE",
        "MARKET_DATA_ACQUISITION_FAILED",
    }:
        return 409
    return 422


def licensed_data_runtime_dependency() -> LicensedDataRuntime:
    """FastAPI seam: production uses activated env config; tests inject fake providers."""
    try:
        return licensed_data_runtime_from_env()
    except MarketDataError as exc:
        raise HTTPException(
            status_code=_market_data_http_status(exc.code),
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _dataset_binding_errors(spec: dict, principal: Principal) -> list[dict]:
    """Control-plane ownership/binding checks that pure JSON Schema cannot perform."""
    version = spec.get("dsl_version")
    if version not in {"1.1", "1.2"}:
        return []
    source = (spec.get("data") or {}).get("source") or {}
    dataset = db.get_dataset_for_principal(
        source.get("dataset_id", ""), principal.tenant_id, principal.user_id)
    if dataset is None:
        return [{
            "layer": "scope", "code": "DATASET_NOT_SEALED",
            "message": "The selected user dataset is missing, withdrawn, or not sealed.",
            "suggestion": "Return to Data Workspace and seal the dataset before running.",
        }]
    errors = []
    if source.get("dataset_manifest_sha256") != dataset["dataset_manifest_sha256"]:
        errors.append({
            "layer": "scope", "code": "DATASET_BINDING_STALE",
            "message": "The strategy references a different dataset-manifest hash.",
            "suggestion": "Re-select the sealed dataset and review the restatement again.",
        })
    if spec.get("universe", {}).get("symbol") != dataset["symbol"]:
        errors.append({
            "layer": "scope", "code": "DATASET_SYMBOL_MISMATCH",
            "message": "The strategy symbol does not match the sealed dataset symbol.",
            "suggestion": f"Use {dataset['symbol']} or choose another sealed dataset.",
        })
    requested = spec.get("data", {}).get("range", {})
    if (requested.get("start", "") < dataset["coverage"]["start"] or
            requested.get("end", "") > dataset["coverage"]["end"]):
        errors.append({
            "layer": "scope", "code": "DATASET_RANGE_OUTSIDE_COVERAGE",
            "message": "The requested test window exceeds the sealed dataset coverage.",
            "suggestion": f"Use {dataset['coverage']['start']} through {dataset['coverage']['end']}.",
        })
    if version == "1.2":
        try:
            assert_dataset_directory_rights(
                db.dataset_directory(dataset),
                operation=DatasetRightsOperation.RUN,
                policy=activated_rights_policy_from_env(),
                as_of=datetime.now(timezone.utc).date(),
            )
        except (MarketDataError, ValueError):
            errors.append({
                "layer": "scope", "code": "LICENSED_DATASET_NOT_RUNNABLE",
                "message": (
                    "The licensed dataset is not currently authorized for research use."
                ),
                "suggestion": (
                    "Ask an operator to verify provider activation, current rights, "
                    "instrument scope, and retention before confirming the run."
                ),
            })
    return errors


def _research_preflight(
    spec: dict,
    *,
    battery_profile: dict,
    principal: Principal,
) -> dict:
    """Evaluate readiness against the exact principal-scoped pinned data.

    Callers must complete schema/scope validation and dataset binding checks first.
    Keeping resolution here makes both validation and queue admission use the same
    authoritative data path while the evaluator itself remains side-effect free.
    """
    try:
        source_directory, dataset = principal_source_context(
            spec,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
        )
    except DataQualityError as exc:
        # A sealed source can only disappear between the binding check and this read if
        # its registry state changed concurrently. Fail closed without creating a run or
        # reservation; the next validation request will surface the normal binding error.
        raise HTTPException(status_code=409, detail={
            "code": "PREFLIGHT_SOURCE_STALE",
            "message": exc.message,
        }) from exc
    return evaluate_preflight(
        spec,
        battery_profile=battery_profile["profile_id"],
        spec_hash=spec_hash(spec),
        profile_hash=battery_profile["profile_hash"],
        source_directory=source_directory,
        dataset=dataset,
    )


def _dataset_public_view(dataset: dict) -> dict:
    """Return safe provenance without paths, original names, or raw rows."""
    try:
        snapshot = verify_snapshot_integrity(db.dataset_directory(dataset))
    except (DataQualityError, ValueError) as exc:
        raise HTTPException(status_code=409, detail={
            "code": "DATASET_INTEGRITY_FAILURE",
            "message": "This sealed dataset failed its integrity check and cannot be used.",
        }) from exc
    manifest = snapshot["dataset_manifest"]
    if manifest.get("manifest_version") == "dataset-v2":
        rights = manifest["rights"]
        instrument = manifest["instrument"]
        source = manifest["source"]
        return {
            "dataset_id": dataset["dataset_id"],
            "display_name": dataset["display_name"],
            "symbol": dataset["symbol"],
            "status": dataset["status"],
            "dataset_manifest_sha256": dataset["dataset_manifest_sha256"],
            "snapshot_id": dataset["snapshot_id"],
            "snapshot_sha256": dataset["snapshot_sha256"],
            "row_count": dataset["row_count"],
            "coverage": dataset["coverage"],
            "quality": dataset["quality"],
            "created_at": dataset["created_at"],
            "provenance": {
                "data_label": "LICENSED_PROVIDER",
                "dataset_id": manifest["dataset_id"],
                "dataset_manifest_sha256": (
                    f"sha256:{snapshot['dataset_manifest_sha256']}"
                ),
                "provider": {
                    "provider_id": source["provider_id"],
                    "feed": source["feed"],
                    "tier": source["tier"],
                },
                "instrument": {
                    "instrument_id": instrument["instrument_id"],
                    "symbol": instrument["symbol"],
                    "display_name": instrument["display_name"],
                    "asset_class": instrument["asset_class"],
                    "mic": instrument["mic"],
                    "currency": instrument["currency"],
                },
                "coverage": manifest["coverage"],
                "row_count": manifest["row_count"],
                "timezone": manifest["timezone"],
                "adjustment_mode": manifest["adjustment_mode"],
                "retrieved_at": manifest["retrieved_at"],
                "revision": manifest["revision"],
                "provider_payload_sha256": manifest["provider_payload_sha256"],
                "normalized_rows_sha256": manifest["normalized_rows_sha256"],
                "normalized_csv_sha256": manifest["normalized_csv_sha256"],
                "rights": {
                    "use": rights["use"],
                    "retention": rights["retention"],
                    "required_attribution": rights["required_attribution"],
                },
                "notice": (
                    "Licensed provider observations; use, display, retention, and export "
                    "rights are re-checked at every boundary."
                ),
            },
        }
    return {
        "dataset_id": dataset["dataset_id"],
        "display_name": dataset["display_name"],
        "symbol": dataset["symbol"],
        "status": dataset["status"],
        "dataset_manifest_sha256": dataset["dataset_manifest_sha256"],
        "snapshot_id": dataset["snapshot_id"],
        "snapshot_sha256": dataset["snapshot_sha256"],
        "row_count": dataset["row_count"],
        "coverage": dataset["coverage"],
        "quality": dataset["quality"],
        "created_at": dataset["created_at"],
        "provenance": {
            "data_label": "USER_UPLOADED",
            "dataset_id": manifest["dataset_id"],
            "dataset_manifest_sha256": f"sha256:{snapshot['dataset_manifest_sha256']}",
            "source_sha256": f"sha256:{manifest['source_sha256']}",
            "normalized_sha256": f"sha256:{manifest['normalized_sha256']}",
            "logical_rows_sha256": f"sha256:{manifest['logical_rows_sha256']}",
            "quality_report_sha256": f"sha256:{manifest['quality_report_sha256']}",
            "source_format": manifest["source_format"],
            "source_size": manifest["source_size"],
            "symbol": manifest["symbol"],
            "row_count": manifest["row_count"],
            "coverage": manifest["coverage"],
            "timezone": manifest["timezone"],
            "price_adjustment": manifest["price_adjustment"],
            "normalizer_version": manifest["normalizer_version"],
            "created_at": manifest["created_at"],
            # Who supplied it and what the numbers mean both follow the manifest. The
            # operator-attested basis is written only by the bundle seeder, so it is
            # what separates data QuantLens shipped from data the reader imported.
            "notice": (
                (
                    "Bundled historical data supplied by QuantLens under CC BY 4.0; "
                    "upstream source accuracy was not independently authenticated. "
                    "Total return — dividends and distributions are reinvested."
                )
                if manifest["price_adjustment"] == TOTAL_RETURN
                else (
                    "User-provided, integrity-checked data; source accuracy was not "
                    "independently authenticated. Price return only; dividends are not "
                    "included."
                )
            ),
        },
    }


def _dataset_import_public_view(record: dict) -> dict:
    value = dict(record)
    value.pop("actor_id", None)
    value.pop("user_id", None)
    return value


def _dataset_import_summary_view(record: dict) -> dict:
    """Just enough to recognize and discard one waiting upload.

    Deliberately not the full record: a list is a browsing surface, and the
    column samples and validation receipt inside an inspection are the reader's
    own data. No filename is included because none is ever stored.
    """
    return {
        "import_id": record["import_id"],
        "status": record["status"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
        "row_count": record["row_count"],
        "source_size": record["source_size"],
        "column_count": len(record.get("columns") or []),
        # "validated", not "reviewed": running the validator is a fact the server
        # observed. Whether a human read the result is not, and the panel this
        # feeds is headed "waiting to be reviewed", so claiming the review was
        # done would have the row contradicting its own heading.
        "validated": record.get("validation") is not None,
        "review_status": (
            (record.get("validation") or {}).get("quality", {}).get("review_status")),
    }


def _confirmation_public_view(receipt: dict | None) -> dict | None:
    if receipt is None:
        return None
    value = dict(receipt)
    value.pop("actor_id", None)
    value.pop("user_id", None)
    return value


def _reservation_public_view(reservation: dict | None) -> dict | None:
    if reservation is None:
        return None
    value = dict(reservation)
    value.pop("actor_id", None)
    return value


def _entitlement_public_view(principal: Principal) -> dict:
    """Tenant-scoped allowance without exposing its internal ownership identifier."""
    value = dict(db.entitlement_status(principal.tenant_id))
    value.pop("actor_id", None)
    value["scope"] = "current local workspace"
    return value


def _sandbox_entitlement_public_view(principal: Principal) -> dict:
    value = dict(db.sandbox_entitlement_status(principal.tenant_id))
    value.pop("actor_id", None)
    value["scope"] = "current local workspace"
    return value


def _run_management_public_view(run: dict) -> dict:
    # Match the database's NULL-based workspace filters exactly. A corrupt
    # non-NULL timestamp (including an empty string) must never be relabeled as
    # active and leak into an active-workspace response.
    state = (
        "deleted" if run.get("deleted_at") is not None
        else "archived" if run.get("archived_at") is not None
        else "active"
    )
    return {
        "research_mode": run.get("research_mode", "formal"),
        "management_state": state,
        "archived_at": run.get("archived_at"),
        "deleted_at": run.get("deleted_at"),
    }


def _env_enabled(name: str, *, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().casefold() not in {"0", "false", "no", "off"}


def _worker_public_health() -> dict:
    """Expose actionable liveness without leaking process or storage details."""
    try:
        return db.worker_health()
    except sqlite3.OperationalError as exc:
        if not db.is_transient_database_error(exc):
            raise
        return {
            "available": False,
            "state": "unavailable",
            "reason": "control_plane_unavailable",
            "last_seen_at": None,
            "heartbeat_age_seconds": None,
            "max_age_seconds": None,
        }


def _require_worker_for_admission() -> None:
    """Fail before reservation when no compatible worker can accept the run."""
    if not _env_enabled("QL_REQUIRE_WORKER_HEARTBEAT", default=True):
        return
    worker = _worker_public_health()
    if worker["available"]:
        return
    raise HTTPException(
        status_code=503,
        detail={
            "code": "WORKER_UNAVAILABLE",
            "message": (
                "Research execution is temporarily unavailable. Nothing was "
                "enqueued and no run allowance was reserved. Retry after the local "
                "worker is healthy."
            ),
            "worker": worker,
        },
        headers={"Retry-After": "3"},
    )


def _require_storage_room() -> None:
    """Fail before writing anything when the volume is below its free-space floor.

    A run admitted onto a full volume does not fail cleanly: the write that dies is
    the ledger seal or the artifact, deep inside the worker, after the allowance is
    already reserved. Measuring first turns that into a refusal that costs nothing.

    Run admission is not the only way to fill the volume, and on this deployment it
    is not even the fastest -- an upload is 12 MB and its slot is returned on seal,
    so upload/seal/upload is unbounded. Every route that writes user bytes checks
    the same floor, or the floor would protect the one path that is not the problem.
    """
    storage = db.storage_health()
    if storage["sufficient"] is not False:
        return
    raise HTTPException(
        status_code=507,
        detail=_storage_refused_detail(storage),
        headers={"Retry-After": "60"},
    )


def _queue_warning_seconds() -> float:
    try:
        return max(0.0, min(3600.0, float(os.environ.get(
            "QL_QUEUE_WARNING_SECONDS", "10"))))
    except (TypeError, ValueError):
        return 10.0


def _run_execution_public_view(run: dict) -> dict:
    """Explain queue delay separately from immutable research lifecycle status."""
    status = run["status"]
    if status != "queued":
        return {
            "state": "processing" if status not in {
                "published", "validation_failed", "data_quality_failed", "system_failed",
            } else "terminal",
            "delayed": False,
            "message": None,
        }
    try:
        queued_at = datetime.fromisoformat(run["updated_at"])
        if queued_at.tzinfo is None:
            queued_at = queued_at.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - queued_at).total_seconds())
    except (TypeError, ValueError):
        age = 0.0
    delayed = age >= _queue_warning_seconds()
    worker = _worker_public_health()
    if not worker["available"]:
        state = "worker_unavailable" if delayed else "waiting_for_worker"
        message = (
            "The run is safely queued, but no healthy execution worker is currently "
            "available. It will resume automatically after the worker recovers."
        )
    elif delayed:
        state = "queue_delayed"
        message = (
            "The execution worker is healthy, but this run has waited longer than "
            "expected. Its reservation remains safe."
        )
    else:
        state = "queued"
        message = "The run is queued for the healthy execution worker."
    return {
        "state": state,
        "delayed": delayed,
        "queued_for_seconds": round(age, 3),
        "message": message,
        "worker": worker,
    }


@app.get("/health")
def health() -> dict:
    worker = _worker_public_health()
    # Three of these fields were hard-coded to describe a local preview, and stayed that
    # way once the same code was deployed behind an account boundary with a licensed data
    # bundle. On a product whose claim is that every assumption is stated, its own public
    # self-description was wrong in three places and machine-readable. They now report
    # what this process is actually configured as.
    auth_mode = (os.environ.get("QL_AUTH_MODE") or "").strip() or "local-preview"
    authenticated = auth_mode != "local-preview"
    # Free space is reported for the same reason the worker heartbeat is: it is the
    # other way this deployment stops being able to accept work, and until now it
    # was invisible everywhere — no statvfs call existed in the product at all.
    storage = db.storage_health()
    return {"ok": True,
            "ready": worker["available"] and storage["sufficient"] is not False,
            "worker": worker,
            "storage": storage,
            "mode": "hosted" if authenticated else "local-preview",
            **public_runtime_view(),
            "auth_mode": auth_mode,
            "identity_boundary": (
                f"every workspace route requires a session ({auth_mode})"
                if authenticated
                else "provider-neutral; local preview is not authenticated"),
            "data": (
                "bundled synthetic fixtures, the CC BY 4.0 market bundle, or sealed "
                "user CSV")}


@app.get("/session")
def session(principal: Principal = Depends(require_principal)) -> dict:
    """UI-safe identity status; opaque ownership identifiers never leave the API."""
    view = session_public_view(principal)
    if principal.auth_mode in ACCOUNT_BOUNDARY_MODES:
        account = db.get_account(principal.tenant_id)
        if account is not None:
            # The reader's chosen presentation travels with the session so the
            # web app can render the right report depth on first paint. The
            # address itself is never part of this view.
            view["report_role"] = account["report_role"]
            view["report_role_chosen"] = bool(account["role_chosen"])
    return view


# ------------------------------------------------------------------ sign-in
#
# Email magic links: no password is ever accepted, stored or transmitted. The
# request path answers identically for known and unknown addresses so it can
# never enumerate accounts, and it fails closed when the deployment has no
# configured way to actually deliver mail.


class SignInRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str


class ReportRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_role: str


_SIGN_IN_ACCEPTED = {
    "status": "sent",
    "message": "If that address can sign in, a link is on its way. "
               "It expires in 15 minutes and works once.",
}


@app.post("/auth/email", status_code=202)
def request_sign_in_link(payload: SignInRequest, request: Request) -> dict:
    """Mint and deliver one single-use sign-in link."""
    if not magic_link.email_sender_configured():
        # Never claim to have sent mail this deployment cannot send.
        raise HTTPException(status_code=503, detail={
            "code": "AUTH_EMAIL_NOT_CONFIGURED",
            "message": "Sign-in email delivery is not configured for this deployment.",
        })
    try:
        email = magic_link.normalize_email(payload.email)
    except magic_link.MagicLinkError:
        raise HTTPException(status_code=422, detail={
            "code": "AUTH_EMAIL_INVALID",
            "message": "Enter one ordinary email address.",
        }) from None

    token = magic_link.mint_secret()
    now = magic_link.utc_now()
    try:
        db.issue_login_token(
            email, magic_link.digest(token),
            created_at=now.isoformat(),
            expires_at=(now + magic_link.LOGIN_TOKEN_TTL).isoformat(),
            max_live=magic_link.MAX_LIVE_TOKENS_PER_EMAIL,
            max_per_window=magic_link.sign_in_emails_per_hour(),
            window_start=(now - magic_link.SIGN_IN_EMAIL_WINDOW).isoformat(),
        )
    except db.AuthInstanceBusyError:
        # Global state, so this discloses nothing about the address and can be
        # said plainly. Claiming a link was sent would be a lie.
        logger.warning("sign-in link refused: instance at its window bound")
        raise HTTPException(
            status_code=429,
            detail={
                "code": "AUTH_SIGN_IN_BUSY",
                "message": "This workspace has already sent as many sign-in "
                           "links as it allows this hour. Nothing was sent — "
                           "please try again shortly.",
            },
            headers={"Retry-After": "900"},
        ) from None
    except db.AuthRateLimitError:
        # Deliberately the same body as success: a throttled address must not
        # be distinguishable from an unthrottled one.
        logger.warning("sign-in link refused: address holds its live-link allowance")
        return dict(_SIGN_IN_ACCEPTED)

    try:
        magic_link.deliver_sign_in_link(email, token, request)
    except magic_link.MagicLinkError:
        # The link was minted but never reached anyone, so it must not spend
        # this address's allowance or the instance's window budget — otherwise
        # a misconfigured sender silently throttles everyone who tries.
        db.discard_login_token(magic_link.digest(token))
        logger.warning("sign-in link delivery failed", exc_info=True)
        raise HTTPException(status_code=503, detail={
            "code": "AUTH_EMAIL_UNAVAILABLE",
            "message": "The sign-in email could not be sent. Try again shortly.",
        }) from None
    return dict(_SIGN_IN_ACCEPTED)


@app.get("/auth/callback")
def consume_sign_in_link(token: str, request: Request) -> JSONResponse:
    """Redeem one link and open a session cookie."""
    now = magic_link.utc_now()
    session_secret = magic_link.mint_secret()
    try:
        redeemed = db.redeem_login_token(
            magic_link.digest(token),
            now=now.isoformat(),
            account_id=magic_link.new_account_id(),
            display_label_for=magic_link.display_label_for,
            default_role=magic_link.DEFAULT_REPORT_ROLE,
            session_sha256=magic_link.digest(session_secret),
            session_expires_at=(now + magic_link.SESSION_TTL).isoformat(),
            max_accounts=magic_link.max_accounts(),
        )
    except db.AuthCapacityError:
        # Said plainly rather than disguised as a broken link: the link is fine
        # and stays usable, this deployment simply has no room right now.
        logger.warning("account creation refused: deployment at its account bound")
        raise HTTPException(status_code=503, detail={
            "code": "AUTH_ACCOUNTS_AT_CAPACITY",
            "message": "This workspace is not accepting new accounts right now. "
                       "Your sign-in link is still valid — try again later.",
        }) from None
    if redeemed is None:
        # Unknown, already used and expired are one answer: a link that does
        # not work reveals nothing about which of the three it was.
        raise HTTPException(status_code=401, detail={
            "code": "AUTH_LINK_INVALID",
            "message": "This sign-in link has expired or was already used. "
                       "Request a new one.",
        })
    response = JSONResponse({
        "status": "signed_in",
        "report_role": redeemed["report_role"],
        "report_role_chosen": bool(redeemed["role_chosen"]),
        "first_sign_in": bool(redeemed["created"]),
    })
    response.set_cookie(
        magic_link.SESSION_COOKIE_NAME,
        session_secret,
        max_age=int(magic_link.SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=magic_link.cookie_is_secure(request),
        path="/",
    )
    return response


@app.post("/auth/signout")
def sign_out(request: Request) -> JSONResponse:
    """Revoke this session server-side and clear the cookie."""
    raw = request.cookies.get(magic_link.SESSION_COOKIE_NAME)
    if raw:
        db.revoke_auth_session(
            magic_link.digest(raw), magic_link.utc_now().isoformat())
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(magic_link.SESSION_COOKIE_NAME, path="/")
    return response


# --------------------------------------------------------- Google sign-in
#
# The other way to prove control of an address, for a deployment with no domain
# of its own to send mail from. It ends where the emailed link ends: the same
# account row, the same session cookie, the same isolation.


def _session_response(redeemed: dict, request: Request, *, location: str | None = None):
    """One place where a proven address becomes a session cookie."""
    if location is None:
        response = JSONResponse({
            "status": "signed_in",
            "report_role": redeemed["report_role"],
            "report_role_chosen": bool(redeemed["role_chosen"]),
            "first_sign_in": bool(redeemed["created"]),
        })
    else:
        response = RedirectResponse(url=location, status_code=303)
    response.set_cookie(
        magic_link.SESSION_COOKIE_NAME,
        redeemed["session_secret"],
        max_age=int(magic_link.SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=magic_link.cookie_is_secure(request),
        path="/",
    )
    if redeemed["created"]:
        # A workspace holding only a generated series makes every guarantee this
        # product prints a statement about an invented instrument, so a new account
        # receives the licensed bundle without having to ask for it.
        #
        # After the response, never inside it. Sealing eight series is slow enough to
        # be felt, and a data fault here must never be able to fail a sign-in: an
        # unseeded workspace is recoverable through the Data page button, whereas an
        # account that could not be created is not.
        #
        # Queued rather than run here, so a cohort signing in together is served one at a
        # time. Ten background tasks each seeding at once cost the same total -- the GIL
        # serializes the pandas work anyway -- but left everybody finishing at the end of
        # it, the first account included. See seeding.py.
        response.background = BackgroundTask(
            seeding.submit,
            db.var_dir(), account_id=redeemed["account_id"])
    return response


def _signin_page(slug: str) -> str:
    origin = (os.environ.get("QL_PUBLIC_WEB_ORIGIN") or "").strip().rstrip("/")
    return f"{origin}/signin?error={slug}"


@app.get("/auth/google/start")
def begin_google_sign_in(request: Request):
    """Leave for Google, carrying one single-use state bound to this browser.

    Both routes here are reached by a top-level browser navigation, so every
    outcome is a redirect to a page. A JSON error body would be rendered as raw
    text to somebody who only pressed a button.
    """
    if not google_auth.google_sign_in_configured():
        logger.warning("google sign-in unavailable: client id or secret is not configured")
        return RedirectResponse(url=_signin_page("unavailable"), status_code=303)

    state = google_auth.new_state()
    verifier = google_auth.new_code_verifier()
    now = magic_link.utc_now()
    # Opportunistic housekeeping: settled attempts are dead weight, and this is
    # the only route that runs often enough to sweep them.
    db.purge_expired_oauth_states(now.isoformat())
    try:
        db.start_oauth_state(
            google_auth.state_digest(state),
            created_at=now.isoformat(),
            expires_at=(now + google_auth.STATE_TTL).isoformat(),
            code_verifier=verifier,
            max_live=google_auth.max_in_flight_sign_ins(),
            window_start=(now - google_auth.STATE_TTL).isoformat(),
        )
    except db.AuthInstanceBusyError:
        logger.warning("google sign-in refused: too many attempts in flight")
        return RedirectResponse(url=_signin_page("busy"), status_code=303)

    try:
        destination = google_auth.authorization_url(state, verifier)
    except google_auth.GoogleAuthError as error:
        logger.warning("google sign-in unavailable: %s", error)
        db.release_oauth_state(google_auth.state_digest(state))
        return RedirectResponse(url=_signin_page("unavailable"), status_code=303)

    response = RedirectResponse(url=destination, status_code=303)
    # The database row stops replay; this cookie is what binds the callback to
    # the browser that began the flow, so an attacker cannot start a sign-in
    # and walk a victim through completing it.
    response.set_cookie(
        google_auth.STATE_COOKIE_NAME,
        state,
        max_age=int(google_auth.STATE_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=magic_link.cookie_is_secure(request),
        path="/",
    )
    return response


@app.get("/auth/google/callback")
def complete_google_sign_in(
    request: Request, code: str = "", state: str = "", error: str = "",
):
    """Return from Google, prove the address, and open a session.

    Every refusal lands the browser back on the sign-in page with a reason,
    because this route is reached by a redirect: a JSON error body would be
    rendered as raw text to somebody who only clicked a button.
    """
    def refused(reason: str, code_slug: str, *, release: str | None = None):
        logger.warning("google sign-in refused: %s", reason)
        if release is not None:
            # Settle the row rather than leave it holding an in-flight slot
            # until it expires; abandoned attempts must not close the door.
            db.release_oauth_state(release)
        failure = RedirectResponse(url=_signin_page(code_slug), status_code=303)
        failure.delete_cookie(google_auth.STATE_COOKIE_NAME, path="/")
        return failure

    if not google_auth.google_sign_in_configured():
        return refused("client id or secret is not configured", "unavailable")

    presented = request.cookies.get(google_auth.STATE_COOKIE_NAME) or ""
    # Both halves must agree: the value this browser was given, and a row that
    # has not been spent.
    if (not state or not presented
            or not secrets.compare_digest(
                google_auth.state_digest(state),
                google_auth.state_digest(presented))):
        return refused("state cookie missing or mismatched", "state")

    # Google reports a refusal here rather than by omitting the code. Pressing
    # Cancel is not a failure of ours and must not be reported as one.
    if error:
        return refused(f"provider returned {error}", "cancelled",
                       release=google_auth.state_digest(state))

    verifier = db.consume_oauth_state(
        google_auth.state_digest(state), now=magic_link.utc_now().isoformat())
    if verifier is None:
        return refused("state unknown, already spent, or expired", "state")

    try:
        identity = google_auth.exchange_code_for_identity(code, verifier)
    except google_auth.GoogleAuthError as failure:
        return refused(f"code exchange failed: {failure}", "provider")

    now = magic_link.utc_now()
    session_secret = magic_link.mint_secret()
    try:
        redeemed = db.open_account_session(
            identity.email,
            now=now.isoformat(),
            account_id=magic_link.new_account_id(),
            display_label_for=magic_link.display_label_for,
            default_role=magic_link.DEFAULT_REPORT_ROLE,
            session_sha256=magic_link.digest(session_secret),
            session_expires_at=(now + magic_link.SESSION_TTL).isoformat(),
            max_accounts=magic_link.max_accounts(),
        )
    except db.AuthCapacityError:
        return refused("deployment is at its account bound", "capacity")

    redeemed["session_secret"] = session_secret
    origin = (os.environ.get("QL_PUBLIC_WEB_ORIGIN") or "").strip().rstrip("/")
    # A first-time reader is asked how their reports should read; a returning
    # one goes straight to their workspace.
    landing = "/" if redeemed["role_chosen"] else "/signin/role"
    response = _session_response(redeemed, request, location=f"{origin}{landing}")
    response.delete_cookie(google_auth.STATE_COOKIE_NAME, path="/")
    return response


@app.post("/auth/report-role")
def choose_report_role(
    payload: ReportRoleRequest,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Record how deep this reader wants their reports rendered."""
    if principal.auth_mode not in ACCOUNT_BOUNDARY_MODES:
        raise HTTPException(status_code=409, detail={
            "code": "AUTH_ACCOUNT_REQUIRED",
            "message": "Report presentation is stored per signed-in account.",
        })
    try:
        role = magic_link.normalize_report_role(payload.report_role)
    except magic_link.MagicLinkError:
        raise HTTPException(status_code=422, detail={
            "code": "AUTH_ROLE_INVALID",
            "message": "Choose either the plain-language or the professional report.",
        }) from None
    db.set_account_report_role(principal.tenant_id, role)
    return {"status": "saved", "report_role": role}


@app.get("/dataset-imports/config")
def dataset_import_config() -> dict:
    return {
        "accepted_formats": ["csv"], "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        "scope": "One symbol, daily OHLC; volume optional. UTF-8 CSV only.",
        "required_fields": ["date", "open", "high", "low", "close"],
        "optional_fields": ["volume"], "timezones": list(ALLOWED_TIMEZONES),
        "parquet_status": "not_enabled_until_pyarrow_and_decompression_limits_are_pinned",
    }


@app.get("/market-data/config")
def market_data_config(
    _principal: Principal = Depends(require_principal),
) -> dict:
    """Credential-free provider readiness for the Data workspace."""
    return market_data_public_config()


@app.post("/market-data/instruments/resolve")
def resolve_market_data_instrument(
    body: MarketDataResolveBody,
    principal: Principal = Depends(require_principal),
    runtime: LicensedDataRuntime = Depends(licensed_data_runtime_dependency),
):
    """Resolve one licensed canonical identity before the user confirms acquisition."""
    if not db.tenant_is_provisioned(principal.tenant_id):
        raise HTTPException(status_code=403, detail={
            "code": "WORKSPACE_NOT_PROVISIONED",
            "message": "This workspace is not provisioned for licensed market data.",
        })
    symbol = body.symbol.strip().upper()
    provider_id = runtime.policy.provider_id
    try:
        _instrument, public = resolve_canonical_instrument(runtime, symbol=symbol)
    except MarketDataError as exc:
        db.record_market_data_usage(
            provider_id=provider_id,
            operation="instrument_resolve",
            symbol=symbol,
            provider_request_count=1,
            cache_hit=False,
            outcome="failed",
            error_code=exc.code,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
        )
        raise HTTPException(
            status_code=_market_data_http_status(exc.code),
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except Exception as exc:  # noqa: BLE001 - do not reflect provider exception details
        logger.error(
            "instrument resolution failed provider=%s exception_type=%s",
            provider_id, type(exc).__name__,
        )
        db.record_market_data_usage(
            provider_id=provider_id,
            operation="instrument_resolve",
            symbol=symbol,
            provider_request_count=1,
            cache_hit=False,
            outcome="failed",
            error_code="MARKET_DATA_PROVIDER_UNAVAILABLE",
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
        )
        raise HTTPException(status_code=503, detail={
            "code": "MARKET_DATA_PROVIDER_UNAVAILABLE",
            "message": "The configured market-data provider could not complete the request.",
        }) from exc
    db.record_market_data_usage(
        provider_id=str(public["provider"]),
        operation="instrument_resolve",
        symbol=symbol,
        provider_request_count=1,
        cache_hit=False,
        outcome="succeeded",
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
    )
    return public


@app.post("/market-data/acquisitions")
def create_market_data_acquisition(
    body: MarketDataAcquisitionBody,
    idempotency_key: str = Header(
        min_length=8, max_length=128, alias="Idempotency-Key",
    ),
    principal: Principal = Depends(require_principal),
    runtime: LicensedDataRuntime = Depends(licensed_data_runtime_dependency),
):
    """Execute the persisted licensed-data v1 job without a network fallback."""
    if not db.tenant_is_provisioned(principal.tenant_id):
        raise HTTPException(status_code=403, detail={
            "code": "WORKSPACE_NOT_PROVISIONED",
            "message": "This workspace is not provisioned for licensed market data.",
        })
    if not body.confirmed:
        raise HTTPException(status_code=422, detail={
            "code": "MARKET_DATA_CONFIRMATION_REQUIRED",
            "message": "Confirm the canonical instrument and price-return convention first.",
        })
    if body.end < body.start:
        raise HTTPException(status_code=422, detail={
            "code": "MARKET_DATA_RANGE_INVALID",
            "message": "The end date must be on or after the start date.",
        })
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=422, detail={
            "code": "DISPLAY_NAME_INVALID",
            "message": "Dataset name must contain a visible character.",
        })
    try:
        job, created = create_and_process_acquisition(
            runtime,
            symbol=body.symbol,
            start=body.start,
            end=body.end,
            adjustment_mode=AdjustmentMode(body.adjustment_mode),
            confirmed_instrument_id=body.confirmed_instrument_id,
            display_name=display_name,
            idempotency_key=idempotency_key,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
        )
    except db.MarketDataIdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail={
            "code": "MARKET_DATA_IDEMPOTENCY_CONFLICT",
            "message": "This retry key is already bound to another acquisition request.",
        }) from exc
    public = acquisition_public_view(job)
    payload = {"acquisition": public, "idempotent": not created}
    if job["status"] == "failed":
        error = job.get("error") or {
            "code": "MARKET_DATA_ACQUISITION_FAILED",
            "message": "The licensed dataset could not be acquired.",
        }
        return JSONResponse(
            status_code=_market_data_http_status(error["code"]),
            content={"detail": {
                **error,
                "acquisition_id": job["acquisition_id"],
                "status": "failed",
            }},
        )
    return JSONResponse(status_code=201 if created else 200, content=payload)


@app.get("/market-data/acquisitions/{acquisition_id}")
def market_data_acquisition_status(
    acquisition_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    job = db.get_market_data_acquisition_for_principal(
        acquisition_id, principal.tenant_id, principal.user_id,
    )
    if job is None:
        raise _workspace_item_not_found()
    return {"acquisition": acquisition_public_view(job)}


@app.post("/dataset-imports", status_code=201)
async def inspect_dataset_upload(
    request: Request,
    principal: Principal = Depends(require_principal),
) -> dict:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"text/csv", "application/csv", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail={
            "code": "UPLOAD_CONTENT_TYPE",
            "message": "Send a plain UTF-8 CSV as text/csv. Other formats are not enabled.",
        })
    declared_length = request.headers.get("content-length")
    if declared_length:
        try:
            too_large = int(declared_length) > MAX_UPLOAD_BYTES
        except ValueError:
            too_large = True
        if too_large:
            raise HTTPException(status_code=413, detail={
                "code": "UPLOAD_TOO_LARGE", "message": "Upload exceeds the local size limit."})
    # Dataset-import rows have a tenant entitlement foreign key.  Reject an unresolved
    # control-plane principal before raw bytes ever reach quarantine; the local default
    # workspace is provisioned by init_db, while external tenants must be admitted by the
    # real billing/provisioning layer.
    if not db.tenant_is_provisioned(principal.tenant_id):
        raise HTTPException(status_code=403, detail={
            "code": "WORKSPACE_NOT_PROVISIONED",
            "message": "This workspace is not provisioned for private data imports.",
        })
    # The per-upload size limit bounds one request; it does not bound a caller
    # who repeats it. Where anyone may register, that would let one account fill
    # the volume every account's evidence shares. Checked before any bytes are
    # read, so a refused upload costs no disk and no transfer.
    if db.count_open_dataset_imports(principal.tenant_id) >= MAX_OPEN_DATASET_IMPORTS:
        raise HTTPException(status_code=409, detail={
            "code": "UPLOAD_QUARANTINE_FULL",
            "message": "This workspace already has the maximum number of "
                       "uploads waiting to be reviewed. Seal or discard one "
                       "before starting another.",
            # The refusal now travels with the list it is talking about. It named
            # a "discard" control for a long time before one existed, and a reader
            # whose page had been reloaded had no identifier left to act on.
            **_open_import_allowance(principal),
        })
    # Also before any bytes are read: the quarantine slot is returned on seal, so
    # upload/seal/upload is unbounded and this is the fastest way to fill the volume.
    _require_storage_room()
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail={
                "code": "UPLOAD_TOO_LARGE", "message": "Upload exceeds the local size limit."})
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        import_id, inspection = create_import(db.var_dir(), raw)
        try:
            record = db.create_dataset_import(
                import_id, inspection,
                tenant_id=principal.tenant_id, user_id=principal.user_id,
            )
            if record is None:
                raise RuntimeError("dataset import receipt was not persisted")
        except Exception:
            # The database receipt owns the quarantine lifecycle.  If persistence loses
            # that race or otherwise fails, leave no untracked raw file behind.
            finalize_quarantine(db.var_dir(), import_id)
            raise
    except DataQualityError as exc:
        raise HTTPException(status_code=422, detail={
            "code": exc.code, "message": exc.message}) from exc
    return {
        "import_id": import_id, "status": record["status"], **inspection,
        "privacy": "Raw rows remain local and quarantined until seal; filenames are not stored.",
    }


def _import_already_sealed_detail() -> dict:
    """Say what this build can actually do, and stop there.

    The first draft of this told the reader to "remove the dataset from the
    library instead" -- a control that does not exist anywhere in the product.
    Naming an unbuilt control in a refusal is the exact defect this whole change
    was written to remove, reintroduced one layer up. The wording now matches the
    retention table on /account, which is the one place that states this limit.
    """
    return {
        "code": "IMPORT_ALREADY_SEALED",
        "message": "This upload was already sealed into a dataset, so there is "
                   "nothing waiting to discard. The dataset stays in your "
                   "library: this build has no in-product delete control for "
                   "sealed datasets yet.",
    }


def _open_import_allowance(principal: Principal) -> dict:
    open_count = db.count_open_dataset_imports(principal.tenant_id)
    return {
        "open_imports": open_count,
        "max_open_imports": MAX_OPEN_DATASET_IMPORTS,
        "remaining_import_slots": max(0, MAX_OPEN_DATASET_IMPORTS - open_count),
    }


@app.get("/dataset-imports")
def list_open_dataset_imports(
    principal: Principal = Depends(require_principal),
) -> dict:
    """The uploads this workspace is holding, and how many slots are left."""
    records = db.list_open_dataset_imports_for_principal(
        principal.tenant_id, principal.user_id)
    return {
        "imports": [_dataset_import_summary_view(record) for record in records],
        **_open_import_allowance(principal),
    }


@app.delete("/dataset-imports/{import_id}")
def discard_dataset_upload(
    import_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Discard one waiting upload and return its slot.

    The quarantine-full refusal has always told the reader to "seal or discard
    one", and until now discarding was not a thing the product could do -- the
    scoped rejection existed in the control plane with no route reaching it, so
    five fumbled uploads locked an account out of its own headline feature with
    no self-service and no operator recovery short of sqlite3 on the box.

    The row is settled BEFORE the bytes are removed. The other order can leave a
    row still claiming a slot while pointing at bytes that are gone, which fails
    later, at seal, as something far less legible than this.
    """
    record = db.get_dataset_import_for_principal(
        import_id, principal.tenant_id, principal.user_id)
    if record is None:
        raise _workspace_item_not_found()
    if record.get("origin") == db.IMPORT_ORIGIN_BUNDLE_SEED:
        # Not the reader's to discard. Worded without tense on purpose: this same
        # branch answers for a series still mid-seal and for one that finished
        # long ago, and "being sealed" would be false about the second.
        raise HTTPException(status_code=409, detail={
            "code": "IMPORT_NOT_DISCARDABLE",
            "message": "That import is a bundled series QuantLens seeded into "
                       "this workspace, not an upload of yours waiting to be "
                       "reviewed.",
        })
    if record["status"] == "sealed":
        raise HTTPException(status_code=409, detail=_import_already_sealed_detail())
    settled = db.discard_dataset_import_for_principal(
        import_id, principal.tenant_id, principal.user_id)
    if not settled:
        # The row was 'inspected' when it was read a moment ago and is not now.
        # Either a concurrent seal won -- in which case saying "discarded" would
        # be false about a dataset that is live in the library -- or a concurrent
        # discard already settled it, which is the idempotent case.
        current = db.get_dataset_import_for_principal(
            import_id, principal.tenant_id, principal.user_id)
        if current is not None and current["status"] == "sealed":
            raise HTTPException(
                status_code=409, detail=_import_already_sealed_detail())
    # Idempotent on purpose: an already-rejected row reaches here too, and a
    # repeated discard must still reclaim any bytes a previous attempt left.
    finalize_quarantine(db.var_dir(), import_id)
    return {
        "status": "discarded",
        "import_id": import_id,
        **_open_import_allowance(principal),
    }


@app.get("/dataset-imports/{import_id}")
def dataset_import_status(
    import_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    record = db.get_dataset_import_for_principal(
        import_id, principal.tenant_id, principal.user_id)
    if record is None:
        raise _workspace_item_not_found()
    return _dataset_import_public_view(record)


@app.post("/dataset-imports/{import_id}/validate")
def validate_dataset_upload(
    import_id: str,
    body: DatasetValidateBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    record = db.get_dataset_import_for_principal(
        import_id, principal.tenant_id, principal.user_id)
    if record is None:
        raise _workspace_item_not_found()
    if record["status"] != "inspected":
        raise HTTPException(status_code=409, detail={
            "code": "IMPORT_NOT_VALIDATABLE", "message": "This import is not validatable."})
    try:
        validation = validate_import(
            db.var_dir(), record, symbol=body.symbol, mapping=body.mapping,
            timezone_name=body.timezone, prices_adjusted=body.prices_adjusted,
            rights_attested=body.rights_attested,
        )
        db.save_dataset_validation_for_principal(
            import_id, validation, principal.tenant_id, principal.user_id)
    except DataQualityError as exc:
        raise HTTPException(status_code=422, detail={
            "code": exc.code, "message": exc.message}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "IMPORT_VALIDATION_FAILED",
            "message": "The import changed state before validation completed.",
        }) from exc
    return {
        "import_id": import_id,
        "status": validation["quality"]["review_status"],
        "validation": validation,
        "provenance_notice": (
            "User-provided, integrity-checked data; QuantLens has not independently "
            "authenticated the source or checked market accuracy independently."
        ),
    }


@app.post("/dataset-imports/{import_id}/seal", status_code=201)
def seal_dataset_upload(
    import_id: str,
    body: DatasetSealBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    record = db.get_dataset_import_for_principal(
        import_id, principal.tenant_id, principal.user_id)
    if record is None:
        raise _workspace_item_not_found()
    if record["status"] == "sealed" and record.get("dataset_id"):
        # A prior request may have committed the sealed dataset and then crashed before
        # deleting the raw quarantine bytes.  Every idempotent retry repairs that gap.
        finalize_quarantine(db.var_dir(), import_id)
        dataset = db.get_dataset_for_principal(
            record["dataset_id"], principal.tenant_id, principal.user_id)
        if dataset:
            return {"status": "sealed", "dataset": _dataset_public_view(dataset),
                    "idempotent": True}
    if record["status"] != "inspected":
        raise HTTPException(status_code=409, detail={
            "code": "IMPORT_NOT_SEALABLE", "message": "This import is not sealable."})
    if not record.get("validation"):
        raise HTTPException(status_code=409, detail={
            "code": "VALIDATION_REQUIRED",
            "message": "Validate and review the data-quality receipt before sealing."})
    if body.confirmed_profile_hash != record["validation"].get("profile_hash"):
        raise HTTPException(status_code=409, detail={
            "code": "VALIDATION_RECEIPT_STALE",
            "message": "The validation receipt does not match the latest reviewed result."})
    display_name = body.display_name.strip()
    if not display_name or len(display_name) > 80:
        raise HTTPException(status_code=422, detail={
            "code": "DISPLAY_NAME_INVALID", "message": "Dataset name must be 1–80 characters."})
    # Sealing writes a normalized dataset directory alongside the quarantined bytes,
    # so it needs its own room. Refusing here leaves the import sealable later.
    _require_storage_room()
    try:
        snapshot, quality, manifest_sha = seal_import(
            db.var_dir(), record, actor_id=principal.tenant_id, symbol=body.symbol,
            mapping=body.mapping, timezone_name=body.timezone,
            prices_adjusted=body.prices_adjusted,
            rights_attested=body.rights_attested,
            confirmed_profile_hash=body.confirmed_profile_hash,
            acknowledged_warnings=body.acknowledged_warnings,
        )
    except DataQualityError as exc:
        raise HTTPException(status_code=422, detail={
            "code": exc.code, "message": exc.message}) from exc
    except (ValueError, jsonschema.ValidationError) as exc:
        logger.warning(
            "dataset seal consistency failure import_id=%s", import_id,
            exc_info=True,
        )
        raise HTTPException(status_code=409, detail={
            "code": "DATASET_SEAL_FAILED",
            "message": "The dataset could not be sealed consistently; no runnable dataset was registered.",
        }) from exc

    dataset_id = snapshot["dataset_manifest"]["dataset_id"]
    try:
        dataset = db.register_dataset_for_principal(
            import_id, dataset_id=dataset_id, display_name=display_name,
            symbol=snapshot["dataset_manifest"]["symbol"],
            dataset_manifest_sha256=manifest_sha,
            snapshot_id=snapshot["snapshot_id"], snapshot_sha256=snapshot["sha256"],
            source_sha256=record["source_sha256"], quality=quality,
            relative_storage_key=f"{principal.tenant_id}/{dataset_id}",
            tenant_id=principal.tenant_id, user_id=principal.user_id,
        )
    except Exception as exc:
        # Registration commits before performing its final ownership read.  Recover a
        # committed row instead of deleting its files; otherwise remove the complete
        # normalized directory so a transient persistence failure cannot leave an
        # unregistered private-data orphan.  If even the ownership read is unavailable,
        # preserve the directory rather than risk deleting a dataset that did commit.
        ownership_check_completed = False
        try:
            committed_dataset = db.get_dataset_for_principal(
                dataset_id, principal.tenant_id, principal.user_id)
            ownership_check_completed = True
        except Exception:
            committed_dataset = None
        if committed_dataset is not None:
            dataset = committed_dataset
        else:
            if ownership_check_completed:
                discard_dataset_directory(
                    db.var_dir(), principal.tenant_id, dataset_id)
            if not isinstance(exc, (ValueError, jsonschema.ValidationError)):
                raise
            logger.warning(
                "dataset registry consistency failure import_id=%s dataset_id=%s",
                import_id, dataset_id, exc_info=True,
            )
            raise HTTPException(status_code=409, detail={
                "code": "DATASET_SEAL_FAILED",
                "message": "The dataset could not be sealed consistently; no runnable dataset was registered.",
            }) from exc
    finalize_quarantine(db.var_dir(), import_id)
    return {"status": "sealed", "dataset": _dataset_public_view(dataset), "idempotent": False}


@app.get("/datasets")
def datasets(principal: Principal = Depends(require_principal)) -> dict:
    owned = db.list_datasets_for_principal(principal.tenant_id, principal.user_id)
    return {"datasets": [_dataset_public_view(item) for item in owned],
            "data_label": "SEALED_DATASETS"}


@app.post("/datasets/bundle", status_code=201)
def seed_bundled_market_data(
    principal: Principal = Depends(require_principal),
) -> dict:
    """Import the CC BY 4.0 market bundle into the caller's own workspace.

    Real data cannot be swapped in under the bundled snapshot -- the worker requires
    that default to stay SYNTHETIC so a run on it is never mistaken for a run on a
    real instrument -- so it arrives as ordinary per-actor sealed datasets. This
    endpoint is the operator doing the import on the caller's behalf, which the CC BY
    grant permits and every commercial licence surveyed does not.

    Idempotent per bundled series, not per ticker. It used to skip any ticker the caller
    already owned anything for, so a reader who had imported their own SPY never received
    the licensed 4,828-row one and was told the import had succeeded. Owning both is
    legitimate and now works: the skip reads the bundle_symbol only the seeder writes.
    """
    # This loop seals one series per iteration and each iteration commits, so running
    # out of room part-way leaves a genuinely partial import. Check the floor first.
    _require_storage_room()
    owned = db.list_datasets_for_principal(principal.tenant_id, principal.user_id)
    held = {item["bundle_symbol"] for item in owned if item.get("bundle_symbol")}
    try:
        wanted = market_bundle.bundled_symbols()
    except market_bundle.BundleUnavailable as exc:
        raise HTTPException(status_code=503, detail={
            "code": "MARKET_BUNDLE_UNAVAILABLE", "message": str(exc)}) from exc

    seeded: list[dict] = []
    unavailable: list[str] = []
    for symbol in wanted:
        if symbol in held:
            continue
        try:
            dataset = market_bundle.seed_symbol(
                db.var_dir(), symbol,
                tenant_id=principal.tenant_id, user_id=principal.user_id)
        except market_bundle.BundleAlreadySeeded:
            # A concurrent seeder won; the workspace holds the series either way.
            held.add(symbol)
            continue
        except (market_bundle.BundleUnavailable, DataQualityError):
            # One unusable series must not cost the caller the other seven. Naming it in
            # the response is what stops the page reporting a clean success over a
            # partial one.
            logger.warning("market bundle seed failed symbol=%s", symbol, exc_info=True)
            unavailable.append(symbol)
            continue
        seeded.append(_dataset_public_view(dataset))

    return {
        "seeded": seeded,
        "already_present": sorted(held & set(wanted)),
        "unavailable": sorted(unavailable),
        "attribution": market_bundle.bundle_manifest()["required_attribution"],
    }


@app.get("/datasets/{dataset_id}")
def dataset_detail(
    dataset_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    dataset = db.get_dataset_for_principal(
        dataset_id, principal.tenant_id, principal.user_id)
    if dataset is None:
        raise _workspace_item_not_found()
    return _dataset_public_view(dataset)


@app.get("/universe")
def universe() -> dict:
    return load_universe()


@app.get("/templates")
def templates() -> dict:
    t1 = default_spec("SPY"); t1["meta"]["name"] = "SPY · 200-day trend · 2005–2024"
    t2 = default_spec("QQQ")
    t2["rule"] = {"type": "ma_crossover", "fast_ma_days": 50, "ma_days": 200}
    t2["meta"]["name"] = "QQQ · 50/200-day crossover · 2005–2024"
    t3 = default_spec("TLT")
    t3["rule"] = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": 150}
    t3["validation"]["sensitivity"]["grid"]["ma_days"] = [100, 150, 200, 250]
    t3["meta"]["name"] = "TLT · 150-day trend · 2005–2024"
    return {"label": "Sample strategies — starting points you edit and confirm; nothing runs "
                     "until you confirm. They begin on the clearly labeled sample series; "
                     "a sealed private CSV can be selected in Studio.",
            "templates": [t1, t2, t3], "default_fields": DEFAULT_FIELDS}


@app.post("/parse")
def parse(
    body: ParseBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    # The Gate 6A factory contains no live/network provider. Resolving it for the request
    # also means an unknown configuration fails closed without a process restart.
    result = BriefingService.from_environment().parse(body.hypothesis)
    if result["status"] in ("advice_deflection", "unsupported"):
        # deflections are logged by category (AT-2.4); hypothesis text stays out of logs (02 §10)
        db.record_event(
            "deflection",
            {"category": result.get("category"), "status": result["status"]},
            tenant_id=principal.tenant_id, user_id=principal.user_id,
        )
    return result


BATTERY_V3_PROFILE = "battery-v3"


def _corrected_profile_descriptor_or_refuse(spec: dict) -> dict:
    """Stop F5 (doc 47 §A5): resolve the corrected descriptor or refuse.

    The two-message BATTERY_PROFILE_NOT_RELEASED refusal stays for every
    store without an ACTIVE corrected release or with an incoherent sealed
    expectations file; registration itself guarantees an ACTIVE release is
    the exact reviewed tuple. When admission is open, the DSL law runs
    before descriptor work: the corrected tuple pins DSL 1.2, so any other
    spec version is refused instead of accepting a run that could never
    execute. Never a feature flag.
    """
    refusal = corrected_admission_refusal()
    if refusal is not None:
        raise HTTPException(status_code=422, detail=refusal)
    dsl_refusal = corrected_dsl_refusal(spec)
    if dsl_refusal is not None:
        raise HTTPException(status_code=422, detail=dsl_refusal)
    return corrected_profile_descriptor()


def _descriptor_for_profile(profile: str) -> dict:
    """Descriptor lookup for already-accepted runs (replay/read paths)."""
    if profile == BATTERY_V3_PROFILE:
        return corrected_profile_descriptor()
    return profile_descriptor(profile)


def _restatement_for_profile(spec: dict, profile: str) -> str:
    if profile == BATTERY_V3_PROFILE:
        return corrected_profile_restatement(restatement(spec), spec)
    return profile_restatement(restatement(spec), spec, profile)


def _sandbox_admission_closed_refusal() -> dict:
    return {
        "code": "SANDBOX_ADMISSION_CLOSED",
        "message": (
            "New sandbox runs are closed while a corrected release is "
            "active. Formal runs remain available, and existing sandbox "
            "runs and their history are unaffected."
        ),
    }


@app.post("/specs/validate")
def validate_spec(
    body: SpecBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    # Display names are normalized (NFKC, control characters stripped, bounded) before
    # validation and hashing, so the confirmed hash always covers the canonical name.
    if body.battery_profile == BATTERY_V3_PROFILE:
        battery_profile = _corrected_profile_descriptor_or_refuse(body.spec)
    else:
        try:
            battery_profile = profile_descriptor(body.battery_profile)
        except ValueError:
            raise HTTPException(status_code=422, detail={
                "code": "BATTERY_PROFILE_UNSUPPORTED",
                "message": "The requested validation profile is not server-owned or supported.",
            })
    normalize_spec_names(body.spec)
    result = validate_full(body.spec, battery_profile=body.battery_profile)
    if result["valid"]:
        binding_errors = _dataset_binding_errors(body.spec, principal)
        if binding_errors:
            result = {"valid": False, "errors": binding_errors}
    out = {"parser": PARSER_LABEL, "valid": result["valid"], "errors": result["errors"],
           "performance": None,
           "not_run_notice": "This spec has not been run. No performance exists until you "
                             "confirm the restatement and the run completes."}
    if result["valid"]:
        current_hash = spec_hash(body.spec)
        preflight = _research_preflight(
            body.spec,
            battery_profile=battery_profile,
            principal=principal,
        )
        out["restatement"] = _restatement_for_profile(
            body.spec, body.battery_profile)
        out["spec_hash"] = current_hash
        out["battery_profile"] = battery_profile
        out["preflight"] = preflight
    return out


def _lineage_public_view(lineage: dict | None) -> dict | None:
    """Frozen §5.4 lineage projection for the run-creation response."""
    if lineage is None:
        return None
    return {
        "family_id": lineage["family_id"],
        "parent_run_id": lineage["parent_run_id"],
        "relationship": lineage["relationship"],
        "diff_contract_version": lineage["diff_contract_version"],
        "changed_assumptions": lineage["changed_assumptions"],
        "changed_assumptions_sha256": lineage["changed_assumptions_sha256"],
    }


@app.post("/runs", status_code=201, response_model=None)
def create_run(
    body: RunBody,
    principal: Principal = Depends(require_principal),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict | JSONResponse:
    if body.battery_profile == BATTERY_V3_PROFILE:
        battery_profile = _corrected_profile_descriptor_or_refuse(body.spec)
    else:
        try:
            battery_profile = profile_descriptor(body.battery_profile)
        except ValueError:
            raise HTTPException(status_code=422, detail={
                "code": "BATTERY_PROFILE_UNSUPPORTED",
                "message": "The requested validation profile is not server-owned or supported.",
            })
    # Stop F5 / doc 48 §4 (A6 option 2): while a corrected release is
    # ACTIVE, NEW sandbox admission is refused — a v3-serving worker must
    # never execute battery-v1 sandbox work. The in-transaction law in
    # db._insert_run_in is the authority; this is the friendly early 422.
    if body.research_mode == "sandbox" and db.get_active_release() is not None:
        raise HTTPException(
            status_code=422, detail=_sandbox_admission_closed_refusal())
    if body.research_mode == "sandbox" and body.battery_profile != BATTERY_V1:
        raise HTTPException(status_code=422, detail={
            "code": "SANDBOX_PROFILE_UNSUPPORTED",
            "message": "Sandbox runs are development-only and require battery-v1; "
                       "they cannot access the battery-v2 final holdout.",
        })
    expected_profile_hash = battery_profile["profile_hash"]
    # The same name normalization as /specs/validate runs before canonical request
    # binding so retries hash the exact same normalized bytes as first creation.
    normalize_spec_names(body.spec)
    current_hash = spec_hash(body.spec)
    # ---- lineage-v1: idempotency binding + replay resolution (frozen §5.2). A
    # lineage create must carry an opaque Idempotency-Key; a plain create may.
    if body.lineage is not None and idempotency_key is None:
        raise HTTPException(status_code=422, detail={
            "code": "IDEMPOTENCY_KEY_REQUIRED",
            "message": "A lineage create requires an opaque Idempotency-Key "
                       "header.",
        })
    idempotency_binding: dict | None = None
    if idempotency_key is not None:
        try:
            validate_idempotency_key(idempotency_key)
        except MetadataValidationError as exc:
            raise HTTPException(status_code=422, detail={
                "code": "IDEMPOTENCY_KEY_INVALID",
                "message": exc.message,
            }) from exc
        _canonical_request, request_sha = canonical_idempotency_request(
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            spec_hash=current_hash,
            research_mode=body.research_mode,
            battery_profile=body.battery_profile,
            battery_profile_hash=expected_profile_hash,
            confirmed_preflight_hash=body.confirmed_preflight_hash,
            acknowledged_preflight_warning_ids=(
                body.acknowledged_preflight_warning_ids),
            lineage_parent_run_id=(
                body.lineage.parent_run_id if body.lineage else None),
            lineage_confirmed_parent_spec_hash=(
                body.lineage.confirmed_parent_spec_hash if body.lineage else None),
            lineage_relationship=(
                body.lineage.relationship if body.lineage else None),
        )
        idempotency_binding = {
            "idempotency_key_sha256":
                hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
            "request_sha256": request_sha,
        }
        # Replay is resolved BEFORE worker admission and before re-running any
        # mutable preflight check: a response-loss retry must return the
        # original run even when the worker is now offline.
        existing = db.find_run_idempotency(
            principal.tenant_id, principal.user_id,
            idempotency_binding["idempotency_key_sha256"])
        if existing is not None:
            if existing["request_sha256"] != request_sha:
                raise HTTPException(status_code=409, detail={
                    "code": "RUN_IDEMPOTENCY_CONFLICT",
                    "message": "This idempotency key is already bound to a "
                               "different request.",
                })
            replayed = db.get_run_for_principal(
                existing["run_id"], principal.tenant_id, principal.user_id)
            if replayed is None:  # defensive: binding and scoped read must agree
                raise HTTPException(status_code=500, detail={
                    "code": "RUN_OWNERSHIP_INCONSISTENT",
                    "message": "The run was not accepted consistently.",
                })
            receipt = replayed.get("confirmation_receipt") or {}
            return JSONResponse(status_code=200, content={
                "run_id": replayed["run_id"],
                "status": replayed["status"],
                "execution": _run_execution_public_view(replayed),
                **_run_management_public_view(replayed),
                "spec_hash": replayed["spec_hash"],
                "restatement": receipt.get("restatement", ""),
                "battery_profile": _descriptor_for_profile(
                    replayed.get("battery_profile", BATTERY_V1)),
                "preflight_hash": body.confirmed_preflight_hash,
                "acknowledged_preflight_warning_ids":
                    sorted(set(body.acknowledged_preflight_warning_ids)),
                "confirmation_receipt": _confirmation_public_view(
                    replayed["confirmation_receipt"]),
                "reservation": _reservation_public_view(replayed["reservation"]),
                "entitlement": _entitlement_public_view(principal),
                "sandbox_entitlement": (
                    _sandbox_entitlement_public_view(principal)
                    if replayed.get("research_mode") == "sandbox" else None
                ),
                "idempotent": True,
                "lineage": _lineage_public_view(
                    db.get_lineage_for_run(replayed["run_id"])),
            })
    # Confirmation and other mutable admission gates apply only to a first create.
    # The frozen idempotency contract resolves a response-loss replay after request
    # syntax/binding validation but before these checks, so an already-accepted run is
    # still recoverable if confirmation state or server admission availability changes.
    if not body.confirmed or not body.restatement_seen:
        raise HTTPException(status_code=409, detail={
            "code": "CONFIRMATION_REQUIRED",
            "message": "Compute is impossible until you have seen and confirmed the "
                       "plain-language restatement of the full rule set (AT-1.4)."})
    # Existing v1 clients are implicitly bound to the frozen server default. Battery v2
    # and the corrected battery-v3 always require the hash returned by /specs/validate.
    if ((body.battery_profile in (BATTERY_V2, BATTERY_V3_PROFILE)
         and body.confirmed_battery_profile_hash != expected_profile_hash)
        or (body.confirmed_battery_profile_hash is not None
            and body.confirmed_battery_profile_hash != expected_profile_hash)):
        raise HTTPException(status_code=409, detail={
            "code": "BATTERY_CONFIRMATION_STALE",
            "message": "The validation profile changed after confirmation. Review the "
                       "current server-owned validation plan before running.",
            "expected_battery_profile_hash": expected_profile_hash,
        })
    # Confirmation binds to the exact spec that was restated: a stale confirmation can
    # never authorize a changed first-create spec (audit hardening on AT-1.4/1.5).
    if body.confirmed_spec_hash != current_hash:
        raise HTTPException(status_code=409, detail={
            "code": "CONFIRMATION_STALE",
            "message": "The spec changed after the restatement you confirmed. Review and "
                       "confirm the current restatement before running.",
            "expected_spec_hash": current_hash})
    # ---- lineage-v1: parent resolution, context equality, and the server diff.
    lineage_intent: dict | None = None
    if body.lineage is not None:
        parent = db.get_run_for_principal(
            body.lineage.parent_run_id, principal.tenant_id, principal.user_id)
        if parent is None or parent.get("deleted_at"):
            # Missing, foreign, and deleted parents share the non-disclosing 404.
            raise _workspace_item_not_found()
        if parent["spec_hash"] != body.lineage.confirmed_parent_spec_hash:
            raise HTTPException(status_code=409, detail={
                "code": "LINEAGE_PARENT_CHANGED",
                "message": "The confirmed parent spec hash does not match the "
                           "parent run.",
                "expected_parent_spec_hash": parent["spec_hash"],
            })
        # The child's worker contract is stamped from the release pointer at
        # acceptance, so the parent is compared against that resolved stamp —
        # identical to the fixed constant while no release is ACTIVE, and the
        # same law the in-transaction lineage guard enforces authoritatively.
        active_release = db.get_active_release()
        expected_child_contract = (
            active_release["required_worker_contract"]
            if active_release is not None else WORKER_RUNTIME_CONTRACT
        )
        if (parent.get("research_mode", "formal") != body.research_mode
                or parent.get("battery_profile") != body.battery_profile
                or parent.get("battery_profile_hash") != expected_profile_hash
                or parent.get("required_worker_contract")
                != expected_child_contract
                or parent["spec"].get("dsl_version")
                != body.spec.get("dsl_version")):
            raise HTTPException(status_code=409, detail={
                "code": "LINEAGE_CONTEXT_MISMATCH",
                "message": "Parent and child must share research mode, DSL "
                           "version, battery profile identity, and worker "
                           "contract. v1 never groups unlike evidence "
                           "contracts.",
            })
        try:
            diff = compute_lineage_diff(parent["spec"], body.spec)
        except LineageDiffError as exc:
            raise HTTPException(status_code=422, detail={
                "code": "UNSUPPORTED_DIFF_SCHEMA",
                "message": "The specs differ on fields outside the reviewed "
                           "semantic allowlist; the lineage write is blocked "
                           "until the allowlist is reviewed.",
                "paths": exc.paths,
            }) from exc
        derived = classify_relationship(diff["changed_assumptions"])
        if body.lineage.relationship == "rerun" and derived == "variation":
            raise HTTPException(status_code=409, detail={
                "code": "LINEAGE_SPEC_DIFFERENT",
                "message": "A rerun requires identical research semantics after "
                           "excluding the display name.",
                "changed_assumption_count":
                    len(diff["changed_assumptions"]),
            })
        if body.lineage.relationship == "variation" and derived == "rerun":
            raise HTTPException(status_code=409, detail={
                "code": "LINEAGE_SPEC_IDENTICAL",
                "message": "A variation requires at least one reviewed semantic "
                           "change.",
            })
        lineage_intent = {
            "parent_run_id": body.lineage.parent_run_id,
            "confirmed_parent_spec_hash":
                body.lineage.confirmed_parent_spec_hash,
            "relationship": body.lineage.relationship,
            "diff": diff,
        }
    result = validate_full(body.spec, battery_profile=body.battery_profile)
    if result["valid"]:
        binding_errors = _dataset_binding_errors(body.spec, principal)
        if binding_errors:
            result = {"valid": False, "errors": binding_errors}
    if not result["valid"]:
        raise HTTPException(status_code=422, detail={
            "code": "SPEC_INVALID", "errors": result["errors"],
            "supported_scope": SUPPORTED_SCOPE_STATEMENT})
    preflight = _research_preflight(
        body.spec,
        battery_profile=battery_profile,
        principal=principal,
    )
    if not preflight["can_run"]:
        raise HTTPException(status_code=422, detail={
            "code": "PREFLIGHT_BLOCKED",
            "message": (
                "The confirmed study is not executable on the exact pinned data. "
                "Correct the blocking items and validate again."
            ),
            "preflight": preflight,
        })
    if body.confirmed_preflight_hash != preflight["preflight_hash"]:
        raise HTTPException(status_code=409, detail={
            "code": "PREFLIGHT_STALE",
            "message": (
                "The research preflight changed or was not confirmed. Review the "
                "current data and validation plan before running."
            ),
            "expected_preflight_hash": preflight["preflight_hash"],
            "preflight": preflight,
        })
    required_warning_ids = preflight["required_acknowledgement_ids"]
    provided_warning_ids = body.acknowledged_preflight_warning_ids
    required_set = set(required_warning_ids)
    provided_set = set(provided_warning_ids)
    if (provided_set != required_set
            or len(provided_warning_ids) != len(provided_set)):
        raise HTTPException(status_code=409, detail={
            "code": "PREFLIGHT_WARNINGS_UNACKNOWLEDGED",
            "message": (
                "Review and acknowledge exactly the current research preflight "
                "warnings before running."
            ),
            "required_acknowledgement_ids": required_warning_ids,
            "missing_acknowledgement_ids": sorted(required_set - provided_set),
            "unexpected_acknowledgement_ids": sorted(provided_set - required_set),
            "preflight": preflight,
        })
    restatement_text = _restatement_for_profile(
        body.spec, body.battery_profile)
    # Admission is the last reversible boundary before quota reservation. A dead or
    # incompatible worker must produce an actionable 503, never an accepted run that
    # appears to work forever while remaining queued. A volume with no room left is
    # the same class of refusal and is checked in the same place.
    _require_worker_for_admission()
    _require_storage_room()
    lineage_view: dict | None = None
    idempotent = False
    try:
        if lineage_intent is not None or idempotency_binding is not None:
            managed = db.create_run_managed(
                body.spec,
                current_hash,
                confirmed_restatement=restatement_text,
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
                battery_profile=body.battery_profile,
                battery_profile_hash=expected_profile_hash,
                research_mode=body.research_mode,
                lineage=lineage_intent,
                idempotency=idempotency_binding,
            )
            run_id = managed["run_id"]
            idempotent = managed["idempotent"]
            lineage_view = _lineage_public_view(managed["lineage"])
        else:
            run_id = db.create_run(
                body.spec,
                current_hash,
                confirmed_restatement=restatement_text,
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
                battery_profile=body.battery_profile,
                battery_profile_hash=expected_profile_hash,
                research_mode=body.research_mode,
            )
    except db.RunIdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "RUN_IDEMPOTENCY_CONFLICT",
            "message": "This idempotency key is already bound to a different "
                       "request.",
        }) from exc
    except db.SandboxAdmissionError as exc:
        # The in-transaction A6 law refused (nothing enqueued, nothing
        # reserved); same typed shape as the friendly early 422.
        raise HTTPException(
            status_code=422,
            detail=_sandbox_admission_closed_refusal()) from exc
    except db.WorkerAdmissionError as exc:
        # The in-transaction exact-contract admission law refused (nothing
        # was enqueued or reserved; the transaction rolled back). Same shape
        # as the friendly early 503, with the exact contract's health view.
        raise HTTPException(
            status_code=503,
            detail={
                "code": "WORKER_UNAVAILABLE",
                "message": (
                    "Research execution is temporarily unavailable. Nothing "
                    "was enqueued and no run allowance was reserved. Retry "
                    "after the local worker is healthy."
                ),
                "worker": db.worker_health(
                    runtime_contract=exc.required_contract),
            },
            headers={"Retry-After": "3"},
        ) from exc
    except db.LineageStateError as exc:
        if exc.code == "LINEAGE_PARENT_NOT_FOUND":
            raise _workspace_item_not_found() from exc
        raise HTTPException(status_code=409, detail={
            "code": exc.code,
            "message": exc.message,
        }) from exc
    except db.QuotaExceededError as exc:
        entitlement_view = dict(exc.entitlement)
        entitlement_view.pop("actor_id", None)
        sandbox = exc.quota_kind == "sandbox"
        raise HTTPException(status_code=429, detail={
            "code": "SANDBOX_QUOTA_EXCEEDED" if sandbox else "QUOTA_EXCEEDED",
            "message": (
                "The local sandbox allowance is used up. Nothing was enqueued."
                if sandbox else
                "The local preview allowance is used up. Nothing was enqueued. "
                "No credit was used."
            ),
            "entitlement": entitlement_view}, headers={"Retry-After": "60"}) from exc
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:  # defensive: creation and scoped read must agree
        raise HTTPException(status_code=500, detail={
            "code": "RUN_OWNERSHIP_INCONSISTENT",
            "message": "The run was not accepted consistently.",
        })
    payload = {
        "run_id": run_id,
        "status": "queued",
        "execution": _run_execution_public_view(run),
        **_run_management_public_view(run),
        "spec_hash": current_hash,
        "restatement": restatement_text,
        "battery_profile": battery_profile,
        "preflight_hash": preflight["preflight_hash"],
        "acknowledged_preflight_warning_ids": required_warning_ids,
        "confirmation_receipt": _confirmation_public_view(run["confirmation_receipt"]),
        "reservation": _reservation_public_view(run["reservation"]),
        "entitlement": _entitlement_public_view(principal),
        "sandbox_entitlement": (
            _sandbox_entitlement_public_view(principal)
            if body.research_mode == "sandbox" else None
        ),
        "idempotent": idempotent,
        "lineage": lineage_view,
    }
    if idempotent:
        # A key resolved inside the atomic transaction (concurrent first
        # creates racing one key) is still a replay: HTTP 200, original run.
        payload["status"] = run["status"]
        return JSONResponse(status_code=200, content=payload)
    return payload


def _workspace_run_summary(
    run: dict, bundled_dataset_ids: frozenset[str] | set[str] = frozenset(),
) -> dict:
    """Project one run into the small, integrity-aware workspace index contract."""
    battery_status = NOT_RUN
    evidence_available = False
    evidence_view_version = None
    artifact_contract_id = None
    verified_financial_semantics = False
    failed_checks = None
    reservation = run.get("reservation")
    checkpoint_is_publishable = (
        isinstance(reservation, dict)
        and reservation.get("status") == "settled"
        and _checkpoint_exists(run["run_id"])
        and legacy_checkpoint_issue(run) is None
    )
    if checkpoint_is_publishable:
        try:
            view = load_verified_evidence(
                db.var_dir() / "artifacts" / run["run_id"], expected_run=run)
        except ArtifactIntegrityError:
            # A workspace index must never turn a tampered checkpoint into a claim.
            # The detailed evidence route logs and explains the integrity refusal.
            pass
        else:
            candidate = view.get("status", {}).get("battery_status")
            if candidate in {"PASS", "FAIL", "INCONCLUSIVE"}:
                battery_status = candidate
                evidence_available = True
                candidate_version = view.get("evidence_view_version")
                if candidate_version in {"v1", "v2", "v3"}:
                    evidence_view_version = candidate_version
                artifact_contract = view.get("artifact_contract")
                if isinstance(artifact_contract, dict):
                    candidate_contract_id = artifact_contract.get("contract_id")
                    if isinstance(candidate_contract_id, str):
                        artifact_contract_id = candidate_contract_id
                    verified_financial_semantics = (
                        artifact_contract.get("verified_financial_semantics") is True
                    )
                checks = view.get("status", {}).get("checks", [])
                failed_checks = sum(
                    1 for check in checks
                    if isinstance(check, dict) and check.get("status") == "FAIL"
                )
    spec = run.get("spec", {}) if isinstance(run.get("spec"), dict) else {}
    title = spec.get("meta", {}).get("name")
    symbol = spec.get("universe", {}).get("symbol")
    source = spec.get("data", {}).get("source") \
        if isinstance(spec.get("data"), dict) else None
    source_kind = source.get("kind") if isinstance(source, dict) else None
    source_dataset_id = source.get("dataset_id") if isinstance(source, dict) else None
    data_source = (
        "licensed" if source_kind == "licensed_provider"
        else "bundled" if source_kind == "user_provided"
        and source_dataset_id in bundled_dataset_ids
        else "user" if source_kind == "user_provided"
        else "sample"
    )
    battery_profile = run.get("battery_profile")
    if battery_profile not in {BATTERY_V1, BATTERY_V2, BATTERY_V3_PROFILE}:
        battery_profile = BATTERY_V1
    return {
        "run_id": run["run_id"],
        **_run_management_public_view(run),
        "title": title if isinstance(title, str) and title.strip() else "Untitled research",
        "symbol": symbol if isinstance(symbol, str) else None,
        "data_source": data_source,
        "status": run["status"],
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
        "battery_status": battery_status,
        "battery_profile": battery_profile,
        "evidence_view_version": evidence_view_version,
        "evidence_available": evidence_available,
        "artifact_contract_id": artifact_contract_id,
        "verified_financial_semantics": verified_financial_semantics,
        "failed_checks": failed_checks,
        # Additive lineage-v1 workspace metadata (frozen §5.4); never note bodies.
        "family_id": run.get("family_id"),
        "family_title": run.get("family_title"),
        "relationship": run.get("relationship"),
        "tags": run.get("tags", []),
        "has_note": run.get("has_note", False),
        "annotation_revision": run.get("annotation_revision", 0),
    }


@app.get("/runs")
def runs_workspace(
    limit: int = 10,
    research_mode: Literal["formal", "sandbox", "all"] = "formal",
    archived: Literal["false", "true", "all"] = "false",
    family_id: str | None = None,
    tag: str | None = None,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Newest research runs for the server-resolved principal only."""
    if not 1 <= limit <= 50:
        raise HTTPException(status_code=422, detail={
            "code": "LIMIT_INVALID",
            "message": "limit must be between 1 and 50.",
        })
    normalized_tag = None
    if tag is not None:
        try:
            _display, normalized_tag = normalize_tag(tag)
        except MetadataValidationError as exc:
            raise HTTPException(status_code=422, detail={
                "code": "ANNOTATION_INVALID",
                "message": exc.message,
            }) from exc
    owned = db.list_runs_for_principal(
        principal.tenant_id,
        principal.user_id,
        limit=limit,
        research_mode=research_mode,
        archived=archived,
        family_id=family_id,
        tag=normalized_tag,
    )
    # One read for the whole page, not one per run. A CC BY series is sealed as
    # `user_provided` because the sealed contract has no other kind, so the spec
    # alone cannot tell the reader's own file from the bundle — and every bundled
    # run in this list was badged "Your data". The operator-attested basis is the
    # discriminator, and it lives on the dataset rather than in the spec.
    bundled_dataset_ids = {
        dataset["dataset_id"]
        for dataset in db.list_datasets_for_principal(
            principal.tenant_id, principal.user_id)
        if dataset.get("bundle_symbol")
    }
    return {
        "runs": [_workspace_run_summary(run, bundled_dataset_ids) for run in owned]
    }


@app.get("/runs/{run_id}")
def run_status(
    run_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    error = _public_run_error(run["error"])
    return {"run_id": run["run_id"], "status": run["status"], "history": run["history"],
            **_run_management_public_view(run),
            "error": error, "retries": run["retries"],
            "execution": _run_execution_public_view(run),
            "spec": run["spec"], "spec_hash": run["spec_hash"],
            "confirmation_receipt": _confirmation_public_view(run["confirmation_receipt"]),
            "reservation": _reservation_public_view(run["reservation"]),
            "entitlement": _entitlement_public_view(principal),
            "sandbox_entitlement": (
                _sandbox_entitlement_public_view(principal)
                if run.get("research_mode") == "sandbox" else None
            ),
            "created_at": run["created_at"], "updated_at": run["updated_at"]}


def _mutate_run_management(run_id: str, principal: Principal, action: str) -> dict:
    operations = {
        "archive": db.archive_run_for_principal,
        "restore": db.restore_run_for_principal,
        "delete": db.soft_delete_run_for_principal,
    }
    try:
        run = operations[action](run_id, principal.tenant_id, principal.user_id)
    except db.UnknownRunError:
        raise _workspace_item_not_found()
    except db.RunManagementStateError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "RUN_MANAGEMENT_CONFLICT",
            "message": exc.reason,
            "action": exc.action,
            "status": exc.status,
        }) from exc
    return {
        "run_id": run["run_id"],
        "status": run["status"],
        **_run_management_public_view(run),
    }


@app.post("/runs/{run_id}/archive")
def archive_run(
    run_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    return _mutate_run_management(run_id, principal, "archive")


@app.post("/runs/{run_id}/restore")
def restore_run(
    run_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    return _mutate_run_management(run_id, principal, "restore")


@app.delete("/runs/{run_id}")
def delete_run(
    run_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Soft-delete a terminal run; no lifecycle, quota, or artifact row is removed."""
    return _mutate_run_management(run_id, principal, "delete")


# ------------------------------------------------- experiment lineage (lineage-v1)

def _decode_experiments_cursor(cursor: str) -> dict:
    """Base64url canonical JSON of {updated_at, family_id}; malformed is 422."""
    try:
        if not cursor or re.fullmatch(r"[A-Za-z0-9_-]+", cursor) is None:
            raise ValueError("cursor is not unpadded base64url")
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded_bytes = base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True)
        decoded = json.loads(decoded_bytes.decode("ascii"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail={
            "code": "CURSOR_INVALID",
            "message": "The pagination cursor is malformed.",
        }) from exc
    if (not isinstance(decoded, dict)
            or set(decoded) != {"updated_at", "family_id"}
            or not isinstance(decoded.get("updated_at"), str)
            or not isinstance(decoded.get("family_id"), str)):
        raise HTTPException(status_code=422, detail={
            "code": "CURSOR_INVALID",
            "message": "The pagination cursor is malformed.",
        })
    canonical_body = json.dumps(
        decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    canonical_cursor = base64.urlsafe_b64encode(
        canonical_body).decode("ascii").rstrip("=")
    if canonical_cursor != cursor:
        raise HTTPException(status_code=422, detail={
            "code": "CURSOR_INVALID",
            "message": "The pagination cursor is malformed.",
        })
    return decoded


def _encode_experiments_cursor(cursor: dict) -> str:
    body = json.dumps(
        cursor, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")


@app.get("/experiments")
def list_experiments(
    limit: int = 50,
    research_mode: Literal["formal", "sandbox"] = "formal",
    cursor: str | None = None,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Principal-scoped experiment-family summaries (mutable workspace metadata)."""
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail={
            "code": "LIMIT_INVALID",
            "message": "limit must be between 1 and 100.",
        })
    decoded_cursor = _decode_experiments_cursor(cursor) if cursor else None
    page = db.list_experiment_families_for_principal(
        principal.tenant_id,
        principal.user_id,
        research_mode=research_mode,
        limit=limit,
        cursor=decoded_cursor,
    )
    return {
        "experiments": page["experiments"],
        "has_more": page["has_more"],
        "next_cursor": (
            _encode_experiments_cursor(page["next_cursor"])
            if page["next_cursor"] else None
        ),
    }


@app.get("/experiments/{family_id}")
def get_experiment(
    family_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    detail = db.get_experiment_family_for_principal(
        family_id, principal.tenant_id, principal.user_id)
    if detail is None:
        raise _workspace_item_not_found()
    return detail


@app.patch("/experiments/{family_id}")
def patch_experiment(
    family_id: str,
    body: ExperimentPatchBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Rename/describe a family with optimistic concurrency. Titles and
    descriptions are mutable workspace context, never sealed evidence."""
    provided = body.model_fields_set
    if "title" not in provided and "description" not in provided:
        raise HTTPException(status_code=422, detail={
            "code": "FAMILY_INVALID",
            "message": "Provide a new title, a new description, or both.",
        })
    # Omitted fields stay unchanged; an explicit null is invalid.
    if ("title" in provided and body.title is None) or (
            "description" in provided and body.description is None):
        raise HTTPException(status_code=422, detail={
            "code": "FAMILY_INVALID",
            "message": "Explicit null is not a valid title or description.",
        })
    try:
        title = (
            validate_family_title(body.title)
            if "title" in provided else None
        )
        description = (
            validate_family_description(body.description)
            if "description" in provided else None
        )
    except MetadataValidationError as exc:
        raise HTTPException(status_code=422, detail={
            "code": "FAMILY_INVALID",
            "message": exc.message,
        }) from exc
    try:
        experiment = db.update_family_for_principal(
            family_id,
            principal.tenant_id,
            principal.user_id,
            title=title,
            description=description,
            expected_revision=body.expected_revision,
        )
    except db.FamilyConflictError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "FAMILY_CONFLICT",
            "message": "The family changed since you loaded it. Refresh to see "
                       "the current title and description.",
            "current_revision": exc.current_revision,
        }) from exc
    if experiment is None:
        raise _workspace_item_not_found()
    return {"experiment": experiment}


@app.get("/runs/{run_id}/workspace-metadata")
def run_workspace_metadata(
    run_id: str,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Lineage/family/annotation for one owned run (readable while soft-deleted)."""
    metadata = db.get_workspace_metadata_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if metadata is None:
        raise _workspace_item_not_found()
    return metadata


@app.put("/runs/{run_id}/annotations")
def put_run_annotations(
    run_id: str,
    body: AnnotationsPutBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    """Atomically replace the private note and complete ordered tag set."""
    try:
        note = validate_note_text(body.note)
        tags = validate_tags(body.tags)
    except MetadataValidationError as exc:
        raise HTTPException(status_code=422, detail={
            "code": "ANNOTATION_INVALID",
            "message": exc.message,
        }) from exc
    try:
        annotation = db.replace_annotations_for_principal(
            run_id,
            principal.tenant_id,
            principal.user_id,
            note=note,
            tags=tags,
            expected_revision=body.expected_revision,
        )
    except db.RunDeletedError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "RUN_DELETED",
            "message": "This run was removed from the workspace. Restore it "
                       "before editing its annotations.",
        }) from exc
    except db.AnnotationConflictError as exc:
        raise HTTPException(status_code=409, detail={
            "code": "ANNOTATION_CONFLICT",
            "message": "The annotations changed since you loaded them. Refresh "
                       "or copy your text before saving again.",
            "current_revision": exc.current_revision,
        }) from exc
    if annotation is None:
        raise _workspace_item_not_found()
    return {"annotation": annotation}


_INTERNAL_RUN_ERROR_MESSAGES = {
    "RETRYING": "The run is being retried automatically.",
    "SYSTEM_FAILED": "The run could not be completed. Use the error code when requesting support.",
    "SETTLEMENT_PENDING": "The sealed run is waiting for quota settlement.",
}


def _public_run_error(error: object) -> dict | None:
    """Project a worker failure without trusting legacy/internal stored messages."""
    if not isinstance(error, dict):
        return None
    raw_code = error.get("code")
    code = raw_code if isinstance(raw_code, str) and raw_code else "RUN_FAILED"
    value: dict = {"code": code}
    if code in _INTERNAL_RUN_ERROR_MESSAGES:
        value["message"] = _INTERNAL_RUN_ERROR_MESSAGES[code]
    else:
        # Data-quality failures are intentionally authored user-facing diagnostics.  A
        # malformed/legacy value still falls back without stringifying arbitrary data.
        message = error.get("message")
        value["message"] = message if isinstance(message, str) else "The run could not be completed."
    for key in ("quota_charged", "settlement_pending"):
        if isinstance(error.get(key), bool):
            value[key] = error[key]
    return value


def _checkpoint_exists(run_id: str) -> bool:
    run_dir = db.var_dir() / "artifacts" / run_id
    return (run_dir / "manifest.json").exists() and (run_dir / "ledger_index.json").exists()


def _legacy_checkpoint_response(run: dict) -> JSONResponse | None:
    """Keep old checkpoints preserved without presenting them as current evidence."""
    if not _checkpoint_exists(run["run_id"]):
        return None
    issue = legacy_checkpoint_issue(run)
    if issue is None:
        return None
    return JSONResponse(status_code=409, content=issue)


def _unsupported_contract_response(run: dict) -> JSONResponse:
    """Typed, path-free refusal for a sealed tuple outside the frozen registry."""
    return JSONResponse(
        status_code=409,
        content=unsupported_artifact_contract_issue(run),
    )


def _v3_unresolved_response(run: dict) -> JSONResponse:
    """Typed, path-free refusal when the sealed record does not re-resolve."""
    return JSONResponse(status_code=409, content={
        "code": "EVIDENCE_V3_UNRESOLVED",
        "run_id": run["run_id"],
        "run_status": run["status"],
        "battery_status": NOT_RUN,
        "message": (
            "This run holds a sealed corrected-contract candidate, but the "
            "corrected presentation contract is not registered on this "
            "service, so nothing is shown."
        ),
    })


def _v3_release_unauthorized_response(run: dict) -> JSONResponse:
    """Typed refusal when the recorded release authorization chain breaks."""
    return JSONResponse(status_code=409, content={
        "code": "EVIDENCE_V3_RELEASE_UNAUTHORIZED",
        "run_id": run["run_id"],
        "run_status": run["status"],
        "battery_status": NOT_RUN,
        "message": (
            "This run's sealed candidate does not agree exactly with its "
            "recorded release authorization, so nothing is shown."
        ),
    })


def _v3_release_authorization(run: dict) -> JSONResponse | dict:
    """Doc 47 §A3 (binding): a v3 read is eligible only for a run that was
    accepted under an activation-authorized release. Requires the immutable
    run-release binding, the preserved activation receipt and the release
    row to exist and agree exactly on the release identity and tuple hash;
    a rolled-back (SUPERSEDED) release keeps its already-bound evidence
    auditable through its historical receipt, while ABORTED or merely
    PREPARED rows never authorize a read. Returns the binding on success."""
    run_id = run["run_id"]
    binding = db.get_run_release_binding(run_id)
    if binding is None:
        return JSONResponse(status_code=409, content={
            "code": "EVIDENCE_V3_RELEASE_UNBOUND",
            "run_id": run_id,
            "run_status": run["status"],
            "battery_status": NOT_RUN,
            "message": (
                "This run holds a sealed corrected-contract candidate, but "
                "it was not accepted under an activation-authorized release "
                "binding, so nothing is shown."
            ),
        })
    release = db.get_release(binding["release_row_id"])
    receipt = db.get_release_activation_receipt(binding["release_row_id"])
    accepted = binding.get("accepted_run")
    accepted = accepted if isinstance(accepted, dict) else {}
    if (
        release is None
        or receipt is None
        or release["release_state"] not in (
            RELEASE_STATE_ACTIVE, RELEASE_STATE_SUPERSEDED)
        or release["release_id"] != binding["release_id"]
        or receipt["release_id"] != binding["release_id"]
        or release["release_tuple_sha256"] != binding["release_tuple_sha256"]
        or receipt["release_tuple_sha256"] != binding["release_tuple_sha256"]
        or accepted.get("run_id") != run_id
        or accepted.get("tenant_id") != run["actor_id"]
        or accepted.get("workspace_id") != run["user_id"]
    ):
        return _v3_release_unauthorized_response(run)
    # §A3 runtime-identity term (F2a; declaration mandatory since F2b): the
    # run's bound release always declares the worker runtime image digest —
    # registration refuses otherwise — and the sealed manifest must equal it
    # exactly.
    capabilities = release.get("required_capabilities")
    capabilities = capabilities if isinstance(capabilities, dict) else {}
    runtime_expectation = capabilities.get("worker_runtime")
    runtime_expectation = (
        runtime_expectation if isinstance(runtime_expectation, dict) else {})
    return {
        "binding": binding,
        "declared_image_digest": runtime_expectation.get("image_digest"),
    }


def _assemble_trusted_product_read_inputs(run: dict) -> TrustedProductReadInputs:
    """Assemble the six trusted read-time components from the control-plane
    store (Stop F2a) plus the closed accepted-run envelope. Components not
    yet registered stay empty, and the read module refuses empty components
    by law (F0d), so an unpopulated store keeps every v3 read fail-closed
    without any special casing here."""
    envelope = db.assemble_accepted_run_envelope(run["run_id"])
    return TrustedProductReadInputs(
        accepted_run_envelope=envelope,
        expected_tenant_id=run["actor_id"],
        expected_workspace_id=run["user_id"],
        expected_run_id=run["run_id"],
        authenticated_plan_anchors=(
            db.get_corrected_read_expectations("plan_anchors")),
        registered_financial_semantics=(
            db.get_corrected_read_expectations("financial_semantics")),
        registered_metric_semantics=(
            db.get_corrected_read_expectations("metric_semantics")),
        registered_calendars=(
            db.get_corrected_read_expectations("calendars")),
        registered_snapshots=(
            db.get_corrected_read_expectations("snapshots")),
        registered_validation_plans=(
            db.get_corrected_read_expectations("validation_plans")),
    )


def _v3_checkpoint_response(
    run: dict,
    *,
    operation: DatasetRightsOperation = DatasetRightsOperation.REPORT,
) -> JSONResponse | dict | None:
    """Project a run's sealed ledger-v1 candidate, or refuse in a typed way.

    Returns None when the run holds no sealed candidate at all, so callers
    fall through to their existing refusals byte-identically. When a sealed
    candidate exists it is served only after, in order: the doc 47 §A3
    release-authorization chain (immutable run binding, preserved activation
    receipt, exact tuple-hash agreement including the sealed manifest and
    the F2b-mandatory declared runtime digest), the full dormant-resolver
    product read with its independent semantic replay over control-plane
    trusted sources (doc 47 §5.1), and the active presentation-registry
    resolution. Every leg stays fail-closed: without an activation there is
    no binding row, without F4 writes the trusted store is empty, and any
    identity drift from the one re-sealed corrected row refuses. A
    successful resolution returns exactly the closed v3 evidence view: the
    sealed record carries no run/publication envelope of its own.
    """
    run_dir = db.var_dir() / "artifacts" / run["run_id"]
    if not v3_checkpoint_exists(run_dir):
        return None
    settlement_pending = _settlement_pending_response(run, resource="Evidence")
    if settlement_pending is not None:
        return settlement_pending
    rights_response = _licensed_boundary_response(run, operation)
    if rights_response is not None:
        return rights_response
    authorization = _v3_release_authorization(run)
    if isinstance(authorization, JSONResponse):
        return authorization
    binding = authorization["binding"]
    declared_image_digest = authorization["declared_image_digest"]
    try:
        checkpoint = load_v3_checkpoint(run_dir)
    except (V3CheckpointMissingError, V3ResolutionError):
        logger.warning(
            "sealed candidate did not resolve run_id=%s", run["run_id"],
            exc_info=True,
        )
        return _v3_unresolved_response(run)
    sealed_manifest = checkpoint["manifest"]
    manifest_tuple = {
        field: sealed_manifest.get(field) for field in RELEASE_TUPLE_FIELDS
    }
    if (
        any(not isinstance(value, str) or not value
            for value in manifest_tuple.values())
        or canonical_sha256(manifest_tuple) != binding["release_tuple_sha256"]
        or sealed_manifest.get("activation_release") != binding["release_id"]
        or sealed_manifest.get("worker_runtime")
        != binding["required_worker_contract"]
        or (declared_image_digest is not None
            and sealed_manifest.get("image_digest") != declared_image_digest)
    ):
        return _v3_release_unauthorized_response(run)
    try:
        trusted = _assemble_trusted_product_read_inputs(run)
    except (db.UnknownRunError, ReleaseStateError):
        logger.warning(
            "accepted-run envelope could not be assembled run_id=%s",
            run["run_id"], exc_info=True,
        )
        return _v3_release_unauthorized_response(run)
    try:
        product_read = resolve_v3_product_read(run_dir, trusted=trusted)
    except V3ProductReadError:
        logger.warning(
            "sealed candidate did not pass the full product read run_id=%s",
            run["run_id"], exc_info=True,
        )
        return _v3_unresolved_response(run)
    try:
        resolve_v3_presentation(
            product_read["manifest"], product_read["semantic_receipt"])
        view = build_evidence_view_v3(
            product_read["manifest"], product_read["semantic_receipt"])
    except (V3CheckpointMissingError, V3ResolutionError):
        logger.warning(
            "sealed candidate did not resolve run_id=%s", run["run_id"],
            exc_info=True,
        )
        return _v3_unresolved_response(run)
    if view["identity"]["manifest_id"] != f"mfst-{run['run_id']}":
        return JSONResponse(status_code=409, content={
            "code": "EVIDENCE_INTEGRITY_FAILURE",
            "run_id": run["run_id"],
            "run_status": run["status"],
            "battery_status": NOT_RUN,
            "message": "This run's sealed evidence failed its integrity check "
                       "and will not be displayed.",
        })
    return view


def _settlement_pending_response(run: dict, *, resource: str) -> JSONResponse | None:
    """Withhold sealed outputs until the run-scoped quota hold is settled."""
    reservation = run.get("reservation")
    if isinstance(reservation, dict) and reservation.get("status") == "settled":
        return None
    return JSONResponse(status_code=409, content={
        "code": "SETTLEMENT_PENDING",
        "run_id": run["run_id"],
        "run_status": run["status"],
        "message": (
            f"A sealed checkpoint is present, but quota settlement is not complete. "
            f"{resource} remains unavailable until the worker compensates the settlement."
        ),
    })


def _publication_status(run: dict) -> dict:
    """Evidence availability is separate from publication status (P1-4): a sealed ledger
    is displayable evidence even when later report publication failed."""
    status = run["status"]
    if status in ("report_rendered", "published"):
        return {"status": "published"}
    if status == "ledger_sealed":
        return {"status": "pending",
                "note": "The ledger sealed; report publication is still in progress."}
    if status == "system_failed":
        return {"status": "failed",
                "error": (_public_run_error(run.get("error")) or {}).get(
                    "message", "The report could not be published.")}
    return {"status": status}


def _licensed_boundary_response(
    run: dict, operation: DatasetRightsOperation,
) -> JSONResponse | None:
    """Fail closed for licensed observations; DatasetManifestV1/BYOD is a no-op."""
    spec = run.get("spec") if isinstance(run.get("spec"), dict) else {}
    if spec.get("dsl_version") != "1.2":
        return None
    source = (spec.get("data") or {}).get("source") or {}
    dataset = db.get_dataset_internal(
        source.get("dataset_id"), run["actor_id"],
        run.get("user_id", run["actor_id"]),
    )
    if dataset is None:
        return JSONResponse(status_code=409, content={
            "code": "LICENSED_DATASET_NOT_AVAILABLE",
            "message": "The licensed dataset is no longer available.",
        })
    try:
        assert_dataset_directory_rights(
            db.dataset_directory(dataset),
            operation=operation,
            policy=activated_rights_policy_from_env(),
            as_of=datetime.now(timezone.utc).date(),
        )
    except MarketDataError as exc:
        return JSONResponse(status_code=409, content={
            "code": exc.code,
            "message": str(exc),
        })
    except ValueError:
        return JSONResponse(status_code=409, content={
            "code": "LICENSED_DATASET_STORAGE_INVALID",
            "message": "The licensed dataset storage binding is invalid.",
        })
    return None


@app.get("/runs/{run_id}/report")
def run_report(
    run_id: str,
    download: bool = False,
    principal: Principal = Depends(require_principal),
):
    """Printable report, freshly rendered per request from the re-checked sealed
    checkpoint (P1-1). A stale or tampered on-disk report.html is never served: the
    response bytes are bound deterministically to the same integrity-checked evidence
    projection the workspace uses, or nothing is served at all."""
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    if not _checkpoint_exists(run_id):
        # A sealed corrected-contract candidate renders its own sealed-record
        # report through the same fail-closed resolution branch as evidence;
        # on shipped registry data it can only refuse. Runs without either
        # checkpoint keep the existing refusal byte-identically.
        v3_result = _v3_checkpoint_response(run, operation=(
            DatasetRightsOperation.EXPORT if download
            else DatasetRightsOperation.REPORT))
        if isinstance(v3_result, JSONResponse):
            return v3_result
        if v3_result is not None:
            headers = None
            if download:
                headers = {
                    "Content-Disposition":
                        f'attachment; filename="quantlens-{run_id}.html"'
                }
            return HTMLResponse(
                render_report_v3_html(v3_result), headers=headers)
        return JSONResponse(status_code=409, content={
            "code": "REPORT_NOT_READY", "status": run["status"],
            "message": "No report exists for this run yet. Reports render only after the "
                       "evidence battery seals its ledger."})
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    settlement_pending = _settlement_pending_response(run, resource="The report")
    if settlement_pending is not None:
        return settlement_pending
    operation = (
        DatasetRightsOperation.EXPORT if download else DatasetRightsOperation.REPORT
    )
    rights_response = _licensed_boundary_response(run, operation)
    if rights_response is not None:
        return rights_response
    try:
        html = render_report_html(db.var_dir() / "artifacts" / run_id, expected_run=run)
    except UnsupportedArtifactContractError:
        logger.warning(
            "report contract is not registered run_id=%s", run_id,
            exc_info=True,
        )
        return _unsupported_contract_response(run)
    except ArtifactIntegrityError as exc:
        logger.warning(
            "report integrity verification failed run_id=%s", run_id,
            exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "REPORT_INTEGRITY_FAILURE", "status": run["status"],
            "message": "This run's sealed evidence failed its integrity check; no report "
                       "will be rendered from it."})
    headers = None
    if download:
        headers = {
            "Content-Disposition": f'attachment; filename="quantlens-{run_id}.html"'
        }
    return HTMLResponse(html, headers=headers)


@app.get("/runs/{run_id}/evidence")
def run_evidence(
    run_id: str,
    principal: Principal = Depends(require_principal),
):
    """Integrity-checked EvidenceViewV1 for one sealed run — the only data source the
    Evidence Workspace may consume. Unsealed, incomplete, mismatched, or tampered runs
    fail closed: no partial financial values are ever returned (06 §5.1).

    Evidence availability is decided by the sealed checkpoint, not by publication
    status (P1-4): if the ledger sealed but report publication later failed, the
    checkpoint is re-checked and returned with a separate ``publication`` block.
    """
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    if not _checkpoint_exists(run_id):
        # A sealed corrected-contract candidate uses its own checkpoint names;
        # it is projected (or refused, on shipped registry data) by its own
        # fail-closed branch, and runs without either checkpoint keep the
        # existing refusal byte-identically.
        v3_response = _v3_checkpoint_response(run)
        if v3_response is not None:
            return v3_response
        return JSONResponse(status_code=409, content={
            "code": "EVIDENCE_NOT_AVAILABLE",
            "run_id": run_id,
            "run_status": run["status"],
            "battery_status": NOT_RUN,
            "message": "No sealed evidence exists for this run. Evidence renders only "
                       "after the battery seals its ledger and every hash matches.",
        })
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    settlement_pending = _settlement_pending_response(run, resource="Evidence")
    if settlement_pending is not None:
        return settlement_pending
    rights_response = _licensed_boundary_response(
        run, DatasetRightsOperation.REPORT)
    if rights_response is not None:
        return rights_response
    try:
        # Read-only integrity check + projection of sealed artifacts; no engine
        # execution happens in the API process (02 §1 worker boundary is untouched).
        view = load_verified_evidence(db.var_dir() / "artifacts" / run_id,
                                      expected_run=run)
    except UnsupportedArtifactContractError:
        logger.warning(
            "evidence contract is not registered run_id=%s", run_id,
            exc_info=True,
        )
        return _unsupported_contract_response(run)
    except ArtifactIntegrityError as exc:
        logger.warning(
            "evidence integrity verification failed run_id=%s", run_id,
            exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "EVIDENCE_INTEGRITY_FAILURE",
            "run_id": run_id,
            "run_status": run["status"],
            "battery_status": NOT_RUN,
            "message": "This run's sealed evidence failed its integrity check and "
                       "will not be displayed.",
        })
    research_mode = run.get("research_mode", "formal")
    return {
        **view,
        "run_status": run["status"],
        "research_mode": research_mode,
        "evidence_scope": (
            "sandbox_test_non_formal"
            if research_mode == "sandbox" else "formal_research"
        ),
        "publication": _publication_status(run),
    }


@app.get("/runs/{run_id}/explanation")
def run_explanation(
    run_id: str,
    principal: Principal = Depends(require_principal),
):
    """Return one read-only explanation built from a fresh, integrity-checked EvidenceViewV1.

    Authorization and every existing checkpoint gate run before the explanation service
    is constructed. The endpoint accepts no client evidence, catalog, plan, or binding;
    foreign, unsealed, legacy, unsettled, tampered, and incomplete runs therefore cannot
    invoke even the currently-disabled provider boundary.
    """
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    if not _checkpoint_exists(run_id):
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_NOT_AVAILABLE",
            "run_id": run_id,
            "run_status": run["status"],
            "message": "No sealed evidence is available for an explanation.",
        })
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    settlement_pending = _settlement_pending_response(
        run, resource="The evidence explanation")
    if settlement_pending is not None:
        return settlement_pending
    rights_response = _licensed_boundary_response(
        run, DatasetRightsOperation.REPORT)
    if rights_response is not None:
        return rights_response
    try:
        # This is deliberately a server-fresh projection. No client-supplied view,
        # catalog, plan, or cached explanation can bypass artifact/semantic verification.
        view = load_verified_evidence(
            db.var_dir() / "artifacts" / run_id, expected_run=run)
    except UnsupportedArtifactContractError:
        logger.warning(
            "explanation contract is not registered run_id=%s", run_id,
            exc_info=True,
        )
        return _unsupported_contract_response(run)
    except ArtifactIntegrityError:
        logger.warning(
            "explanation evidence integrity verification failed run_id=%s",
            run_id, exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_INTEGRITY_FAILURE",
            "run_id": run_id,
            "run_status": run["status"],
            "message": "The sealed evidence failed its integrity check, so no "
                       "explanation was generated.",
        })
    status = view.get("status")
    if not isinstance(status, dict) or status.get("evidence_complete") is not True:
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_EVIDENCE_INCOMPLETE",
            "run_id": run_id,
            "run_status": run["status"],
            "message": "The declared evidence checks are incomplete, so no explanation "
                       "was generated.",
        })
    if view.get("evidence_view_version") == "v2":
        # The v1 narrative catalog contains final/OOS facts. Battery v2 never passes that
        # view to a provider: its closed projection contains development evidence only.
        return development_only_explanation(view)
    if view.get("evidence_view_version") != "v1":
        # Only the v1 view may reach the v1 narrative catalog below: its facts
        # include final/OOS material that no other contract's projection may
        # carry. Today the loader can only produce v1 or v2, so this guard is
        # inert; it exists so a future evidence version can never fall through
        # into the v1 narrative branch by omission.
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_NOT_AVAILABLE",
            "run_id": run_id,
            "run_status": run["status"],
            "message": "No explanation projection exists for this run's sealed "
                       "evidence contract.",
        })
    try:
        initial_catalog = build_narrative_fact_catalog(view)
        initial_binding = build_current_binding(view, initial_catalog)
    except (NarrativeFactCatalogError, NarrativeGuardError, TypeError, ValueError):
        logger.warning(
            "explanation fact binding failed run_id=%s", run_id,
            exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_INTEGRITY_FAILURE",
            "run_id": run_id,
            "run_status": run["status"],
            "message": "The sealed evidence could not be bound to an explanation.",
        })

    response = ExplanationService.from_environment().explain(view)

    # Re-read both ownership and every sealed byte after the provider boundary returns.
    # Even a provider that was invoked cannot make a stale/tampered candidate observable.
    fresh_run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    try:
        if fresh_run is None or legacy_checkpoint_issue(fresh_run) is not None:
            raise ArtifactIntegrityError("run binding changed")
        reservation = fresh_run.get("reservation")
        if not isinstance(reservation, dict) or reservation.get("status") != "settled":
            raise ArtifactIntegrityError("settlement binding changed")
        fresh_view = load_verified_evidence(
            db.var_dir() / "artifacts" / run_id, expected_run=fresh_run)
        fresh_status = fresh_view.get("status")
        if not isinstance(fresh_status, dict) or \
                fresh_status.get("evidence_complete") is not True:
            raise ArtifactIntegrityError("evidence completeness changed")
        fresh_catalog = build_narrative_fact_catalog(fresh_view)
        fresh_binding = build_current_binding(fresh_view, fresh_catalog)
    except (ArtifactIntegrityError, NarrativeFactCatalogError, NarrativeGuardError,
            TypeError, ValueError):
        logger.warning(
            "explanation binding changed run_id=%s", run_id,
            exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_STALE_BINDING",
            "run_id": run_id,
            "run_status": fresh_run["status"] if fresh_run else run["status"],
            "message": "The evidence binding changed while the explanation was being "
                       "prepared, so the explanation was suppressed.",
        })

    if fresh_binding != initial_binding or not isinstance(response, dict):
        return JSONResponse(status_code=409, content={
            "code": "EXPLANATION_STALE_BINDING",
            "run_id": run_id,
            "run_status": fresh_run["status"],
            "message": "The evidence binding changed while the explanation was being "
                       "prepared, so the explanation was suppressed.",
        })
    if response.get("status") == "completed":
        if response.get("binding") != fresh_binding or not isinstance(
                response.get("explanation"), dict):
            return JSONResponse(status_code=409, content={
                "code": "EXPLANATION_STALE_BINDING",
                "run_id": run_id,
                "run_status": fresh_run["status"],
                "message": "The explanation did not match the current evidence binding "
                           "and was suppressed.",
            })
        return response
    if response.get("status") == "unavailable" and \
            response.get("binding") is None and response.get("explanation") is None:
        return response
    return JSONResponse(status_code=409, content={
        "code": "EXPLANATION_STALE_BINDING",
        "run_id": run_id,
        "run_status": fresh_run["status"],
        "message": "The explanation response was not valid for the current evidence "
                   "binding and was suppressed.",
    })


@app.get("/runs/{run_id}/research-copilot")
def run_research_copilot(
    run_id: str,
    principal: Principal = Depends(require_principal),
):
    """Return a read-only Development Research Copilot review for EvidenceViewV2.

    The endpoint accepts no evidence, prompt, plan, action, or binding from the client.
    It authorizes the run first, then requires a current compatible checkpoint, settled
    quota reservation, REPORT rights, complete EvidenceViewV2, and a valid closed
    Development projection.  The installed provider is deliberately transport-free;
    the product response is the deterministic server render.

    Ownership, sealed evidence, and the opaque Development binding are all re-read after
    review construction.  Any concurrent change suppresses the complete review rather
    than returning a stale or partially checked response.
    """
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    if not _checkpoint_exists(run_id):
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_NOT_AVAILABLE",
            "message": "No sealed Validation Battery V2 evidence is available for a "
                       "development research review.",
        })
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    settlement_pending = _settlement_pending_response(
        run, resource="The development research review")
    if settlement_pending is not None:
        return settlement_pending
    rights_response = _licensed_boundary_response(
        run, DatasetRightsOperation.REPORT)
    if rights_response is not None:
        return rights_response

    try:
        view = load_verified_evidence(
            db.var_dir() / "artifacts" / run_id, expected_run=run)
    except UnsupportedArtifactContractError:
        logger.warning(
            "research copilot contract is not registered run_id=%s", run_id,
            exc_info=True,
        )
        return _unsupported_contract_response(run)
    except ArtifactIntegrityError:
        logger.warning(
            "research copilot evidence integrity verification failed run_id=%s",
            run_id, exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_INTEGRITY_FAILURE",
            "message": "The sealed evidence failed its integrity check, so no "
                       "development research review was generated.",
        })

    if view.get("evidence_view_version") != "v2" or \
            view.get("evidence_semantics_version") != "v2":
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_REQUIRES_BATTERY_V2",
            "message": "Development Research Copilot requires a newly completed "
                       "Validation Battery V2 run.",
        })
    status = view.get("status")
    if not isinstance(status, dict) or status.get("evidence_complete") is not True:
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_EVIDENCE_INCOMPLETE",
            "message": "The Development evidence checks are incomplete, so no "
                       "research review was generated.",
        })
    artifact_contract = view.get("artifact_contract")
    if not isinstance(artifact_contract, dict) or \
            artifact_contract.get("verified_financial_semantics") is not True:
        return JSONResponse(
            status_code=409,
            content=financial_semantics_rebuild_issue(run, artifact_contract),
        )
    try:
        initial_projection = build_development_projection(view)
    except (ResearchProjectionError, TypeError, ValueError):
        logger.warning(
            "research copilot development projection failed run_id=%s",
            run_id, exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_EVIDENCE_INVALID",
            "message": "The sealed Development evidence could not be prepared for a "
                       "research review.",
        })

    response = DevelopmentResearchCopilot.from_environment().review(view)

    # Re-check the server-resolved principal, compatibility, settlement, REPORT rights,
    # every sealed byte, completeness, and the privacy-minimized binding after the
    # review boundary.  Nothing from ``response`` is observable before this completes.
    fresh_run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    try:
        if fresh_run is None or not _checkpoint_exists(run_id) or \
                legacy_checkpoint_issue(fresh_run) is not None:
            raise ArtifactIntegrityError("run binding changed")
        reservation = fresh_run.get("reservation")
        if not isinstance(reservation, dict) or reservation.get("status") != "settled":
            raise ArtifactIntegrityError("settlement binding changed")
        if _licensed_boundary_response(
                fresh_run, DatasetRightsOperation.REPORT) is not None:
            raise ArtifactIntegrityError("dataset rights binding changed")
        fresh_view = load_verified_evidence(
            db.var_dir() / "artifacts" / run_id, expected_run=fresh_run)
        fresh_status = fresh_view.get("status")
        fresh_contract = fresh_view.get("artifact_contract")
        if fresh_view.get("evidence_view_version") != "v2" or \
                fresh_view.get("evidence_semantics_version") != "v2" or \
                not isinstance(fresh_status, dict) or \
                fresh_status.get("evidence_complete") is not True or \
                not isinstance(fresh_contract, dict) or \
                fresh_contract.get("verified_financial_semantics") is not True:
            raise ArtifactIntegrityError("development evidence changed")
        fresh_projection = build_development_projection(fresh_view)
    except (ArtifactIntegrityError, ResearchProjectionError, TypeError, ValueError):
        logger.warning(
            "research copilot binding changed run_id=%s", run_id, exc_info=True,
        )
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_STALE_BINDING",
            "message": "The Development evidence changed while the review was being "
                       "prepared, so the review was suppressed.",
        })

    fresh_binding = fresh_projection.opaque_development_binding
    expected_binding = {"opaque_development_binding": fresh_binding}
    generation = response.get("generation") if isinstance(response, dict) else None
    analysis = response.get("analysis") if isinstance(response, dict) else None
    pending_action = analysis.get("pending_action") \
        if isinstance(analysis, dict) else None
    pending_action_invalid = pending_action is not None and (
        not isinstance(pending_action, dict)
        or pending_action.get("status") != "confirmation_required"
        or pending_action.get("execution_state") != "not_started"
        or pending_action.get("auto_execute") is not False
    )
    if initial_projection.opaque_development_binding != fresh_binding or \
            not isinstance(response, dict) or response.get("status") != "completed" or \
            response.get("scope") != "development_only" or \
            response.get("binding") != expected_binding or \
            not isinstance(analysis, dict) or pending_action_invalid or \
            not isinstance(generation, dict) or \
            generation.get("ai_used") is not False or \
            generation.get("provider_invoked") is not False or \
            generation.get("provider_data_transmitted") is not False or \
            generation.get("ai_influenced_output") is not False or \
            generation.get("provider") != "disabled" or \
            generation.get("fallback_used") is not True:
        return JSONResponse(status_code=409, content={
            "code": "RESEARCH_COPILOT_STALE_BINDING",
            "message": "The research review did not match the current Development "
                       "evidence binding and was suppressed.",
        })
    return response


def _verified_checkpoint(run: dict) -> tuple[dict, dict]:
    """Load manifest + ledger through the registered read-only presentation boundary."""
    run_id = run["run_id"]
    if not _checkpoint_exists(run_id):
        raise HTTPException(status_code=404, detail="Run is not sealed.")
    try:
        manifest, ledger, _payloads, _contract = load_presentation_artifacts(
            db.var_dir() / "artifacts" / run_id, expected_run=run)
    except UnsupportedArtifactContractError:
        logger.warning(
            "checkpoint contract is not registered run_id=%s", run_id,
            exc_info=True,
        )
        raise HTTPException(
            status_code=409,
            detail=unsupported_artifact_contract_issue(run),
        ) from None
    except ArtifactIntegrityError:
        logger.warning(
            "checkpoint integrity verification failed run_id=%s", run_id,
            exc_info=True,
        )
        raise HTTPException(status_code=409, detail={
            "code": "EVIDENCE_INTEGRITY_FAILURE",
            "message": "This run's sealed checkpoint failed its integrity check.",
        }) from None
    return manifest, ledger


@app.get("/runs/{run_id}/manifest")
def run_manifest(
    run_id: str,
    principal: Principal = Depends(require_principal),
):
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    manifest, _ledger = _verified_checkpoint(run)
    return JSONResponse(manifest)


@app.get("/runs/{run_id}/artifacts")
def run_artifacts(
    run_id: str,
    principal: Principal = Depends(require_principal),
):
    run = db.get_run_for_principal(
        run_id, principal.tenant_id, principal.user_id)
    if run is None:
        raise _workspace_item_not_found()
    legacy_response = _legacy_checkpoint_response(run)
    if legacy_response is not None:
        return legacy_response
    _manifest, ledger = _verified_checkpoint(run)
    return JSONResponse(ledger)


@app.get("/entitlement")
def entitlement(principal: Principal = Depends(require_principal)) -> dict:
    return _entitlement_public_view(principal)


@app.post("/events", status_code=201)
def post_event(
    body: EventBody,
    principal: Principal = Depends(require_principal),
) -> dict:
    allowed = {"parsing_correction", "card_correction_loop", "notify_me",
               "confirmation", "yaml_view_opened"}
    if body.type not in allowed:
        raise HTTPException(status_code=422, detail=f"Unknown event type; allowed: {sorted(allowed)}")
    db.record_event(
        body.type, body.payload,
        tenant_id=principal.tenant_id, user_id=principal.user_id,
    )
    return {"recorded": body.type}
