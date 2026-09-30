"""Seed a workspace with the CC BY 4.0 market bundle.

The product ships a synthetic series, and `runner._resolve_snapshot` refuses to let
the bundled default snapshot be anything else -- "DSL 1.0 runs may only use the
bundled SYNTHETIC snapshot". That invariant is what stops a result computed on the
shipped default from reading as a result about a real instrument, so real data is not
swapped in underneath it. It arrives the way this product already says real data
arrives: as a per-actor sealed dataset with a manifest recording where it came from.

Seeding therefore drives the ordinary import pipeline -- inspect, validate, seal --
against bytes the operator is licensed to redistribute, rather than adding a second
private path into the dataset store. A seeded dataset is byte-identical in provenance
structure to one a user uploaded themselves; only the actor differs.

The licence is what makes this legal to do on someone else's behalf. Every commercial
vendor surveyed forbids putting their data in front of a third party without a
negotiated contract, and two of them extend that to derived values. CC BY 4.0 grants
it outright, conditional on attribution -- which is why `rights_attested` is true here
and why the attribution string is carried in `bundle.json` next to the bytes.

See docs/REAL-DATA-ACCESS.md.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from functools import lru_cache
from pathlib import Path

from . import db, dataset_imports

logger = logging.getLogger(__name__)

BUNDLE_DIR = Path(__file__).resolve().parents[3] / "data" / "market-cc-by"

# The bundle is written by scripts/build_market_bundle.py with the product's own
# column names, so the importer needs no column guessing.
MAPPING = {
    "date": "date", "open": "open", "high": "high",
    "low": "low", "close": "close", "volume": "volume",
}
TIMEZONE = "America/New_York"

# Bars are total-return adjusted (dividends reinvested, back-adjusted). Measured, not
# assumed: dividend-free GLD matches its launch price while SPY and TLT are depressed
# 1.82%/yr and 3.13%/yr, each within a few basis points of that fund's real average
# yield. An unadjusted series would show no such gradient. Declaring the split-adjusted
# price-return basis instead would make every report built on these bars tell its reader
# that dividends were excluded when they are already in the numbers.
PRICES_ADJUSTED = True
PRICE_ADJUSTMENT = dataset_imports.TOTAL_RETURN


class BundleUnavailable(Exception):
    """The bundle is missing or unreadable; seeding is skipped, never faked."""


class BundleAlreadySeeded(Exception):
    """Another seeder won the race for this ticker; the workspace already has it.

    Not a failure. The signup background seed and the Data page button can genuinely
    run at once -- as can two open tabs -- and the storage-level unique index is what
    decides between them. The loser cleans up after itself and reports this so the
    caller can count the series as present rather than as an error.
    """


def bundle_manifest() -> dict:
    try:
        return json.loads((BUNDLE_DIR / "bundle.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleUnavailable("The market bundle manifest is missing or invalid.") from exc


def bundled_symbols() -> list[str]:
    return sorted(bundle_manifest().get("coverage", {}))


def _display_name(symbol: str, coverage: dict) -> str:
    return f"{symbol} daily {coverage['start'][:4]}–{coverage['end'][:4]} (CC BY)"


def bundled_display_name(symbol: str) -> str:
    """The name seeding gives this series, for recognising rows it sealed earlier."""
    return _display_name(symbol, bundle_manifest()["coverage"][symbol])


@lru_cache(maxsize=1)
def bundled_source_digests() -> dict[str, str]:
    """sha256 of each bundled CSV, hashed once per process.

    Used to recognise rows seeded before ``datasets.bundle_symbol`` existed. Bytes alone
    are not enough to claim a row is ours -- a reader may upload the same file, and the
    import path would stamp it with the price-return basis -- so the caller pairs this
    with the generated display name. Two independent matches is what makes the claim safe.
    """
    digests: dict[str, str] = {}
    for symbol in bundled_symbols():
        try:
            digests[symbol] = hashlib.sha256(
                (BUNDLE_DIR / f"{symbol}.csv").read_bytes()).hexdigest()
        except OSError:
            continue
    return digests


def _warning_codes(quality: object) -> list[str]:
    """Every warning the reviewer would have been shown, in the receipt's own order.

    Sealing refuses to proceed past findings nobody acknowledged. The operator has
    acknowledged them: the build script asserts every rule the snapshot loader
    enforces, so a bundle carrying a blocking finding never reaches a commit.
    """
    if not isinstance(quality, dict):
        return []
    issues = quality.get("issues")
    if not isinstance(issues, list):
        return []
    return [
        issue["code"] for issue in issues
        if isinstance(issue, dict) and issue.get("severity") == "warning"
        and isinstance(issue.get("code"), str)
    ]


def seed_symbol(var_dir: Path, symbol: str, *, tenant_id: str, user_id: str) -> dict:
    """Import one bundled series into a workspace and return the sealed dataset.

    ``tenant_id`` is the storage actor, matching how the upload endpoint seals: a
    seeded dataset lands in the same per-tenant directory, under the same manifest
    schema, as one the user imported by hand.
    """
    coverage = bundle_manifest()["coverage"][symbol]
    try:
        raw = (BUNDLE_DIR / f"{symbol}.csv").read_bytes()
    except OSError as exc:
        raise BundleUnavailable(f"Bundled series {symbol} is unreadable.") from exc

    import_id, inspection = dataset_imports.create_import(var_dir, raw)
    # Marked as the seeder's own. These rows sit in the same 'inspected' state a
    # reader's upload does, so without this the "waiting to be reviewed" list
    # would offer a Discard button that destroys a licensed series mid-seal.
    db.create_dataset_import(
        import_id, inspection, tenant_id=tenant_id, user_id=user_id,
        origin=db.IMPORT_ORIGIN_BUNDLE_SEED)
    record = db.get_dataset_import(import_id, tenant_id)

    try:
        validation = dataset_imports.validate_import(
            var_dir, record, symbol=symbol, mapping=MAPPING, timezone_name=TIMEZONE,
            prices_adjusted=PRICES_ADJUSTED, price_adjustment=PRICE_ADJUSTMENT,
            # CC BY 4.0 is a public grant to redistribute with attribution, so the
            # operator genuinely holds the right it attests to here.
            rights_attested=True)
        db.save_dataset_validation(import_id, validation, actor_id=tenant_id)
        record = db.get_dataset_import(import_id, tenant_id)

        snapshot, quality, manifest_sha = dataset_imports.seal_import(
            var_dir, record, actor_id=tenant_id, symbol=symbol, mapping=MAPPING,
            timezone_name=TIMEZONE, prices_adjusted=PRICES_ADJUSTED,
            price_adjustment=PRICE_ADJUSTMENT, rights_attested=True,
            confirmed_profile_hash=validation["profile_hash"],
            acknowledged_warnings=_warning_codes(validation.get("quality")))

        dataset_id = snapshot["dataset_manifest"]["dataset_id"]
        dataset = db.register_dataset_for_principal(
            import_id, dataset_id=dataset_id,
            display_name=_display_name(symbol, coverage),
            symbol=snapshot["dataset_manifest"]["symbol"],
            dataset_manifest_sha256=manifest_sha,
            snapshot_id=snapshot["snapshot_id"], snapshot_sha256=snapshot["sha256"],
            source_sha256=record["source_sha256"], quality=quality,
            relative_storage_key=f"{tenant_id}/{dataset_id}",
            tenant_id=tenant_id, user_id=user_id,
            # The one field that says "this row IS the licensed series", and the one
            # the unique index keys on.
            bundle_symbol=symbol)
    except sqlite3.IntegrityError as exc:
        if "bundle_symbol" not in str(exc):
            _release_import(var_dir, import_id, tenant_id, user_id, "seed failed")
            raise
        # Another seeder sealed this ticker while this one was working. The workspace
        # has what it needs, so this is not an error -- but the losing attempt must not
        # keep its quarantined bytes or hold one of the caller's open-import slots.
        _release_import(var_dir, import_id, tenant_id, user_id,
                        "another seeder sealed this series first")
        raise BundleAlreadySeeded(symbol) from exc
    except Exception:
        _release_import(var_dir, import_id, tenant_id, user_id, "seed failed")
        raise

    # The upload path drops the quarantined copy once the dataset is sealed
    # (app.py:1558); seeding never did, so every seeded series left its CSV behind --
    # ~225KB each, ~1.7MB per account, and unreachable by the expiry sweep, which only
    # considers imports still inspected or rejected.
    dataset_imports.finalize_quarantine(var_dir, import_id)
    return dataset


def _release_import(var_dir: Path, import_id: str, tenant_id: str, user_id: str,
                    reason: str) -> None:
    """Give back everything a failed or superseded seed was holding.

    Both halves matter. The quarantined bytes are otherwise never reclaimed, and the
    import row is otherwise left `inspected`, which is exactly what counts against
    MAX_OPEN_DATASET_IMPORTS -- so a few lost races would quietly consume a reader's
    ability to import their own files.
    """
    try:
        db.reject_dataset_import_for_principal(
            import_id, {"code": "BUNDLE_SEED_RELEASED", "message": reason},
            tenant_id, user_id)
        dataset_imports.finalize_quarantine(var_dir, import_id)
    except Exception:  # noqa: BLE001 - cleanup must not mask the original outcome
        logger.warning("could not release seed import %s", import_id, exc_info=True)


def seed_new_workspace(var_dir: Path, *, account_id: str) -> int:
    """Fill a just-created workspace with the bundle. Never raises.

    This runs after the sign-in response has already been sent, so the person is
    already in their workspace while it works. That ordering is the whole point:
    sealing eight series takes long enough that doing it inside the sign-in request
    would make registration slower and, far worse, would let a data problem fail a
    sign-in. A workspace that ends up empty is recoverable -- the Data page still
    offers the button, and the endpoint behind it is idempotent -- whereas an
    account that could not be created is not.

    An account owns exactly one personal workspace, so tenant and user are both the
    account id, matching every ``*_for_principal`` accessor.
    """
    try:
        symbols = bundled_symbols()
    except BundleUnavailable:
        logger.warning("market bundle unavailable; workspace not seeded", exc_info=True)
        return 0

    seeded = 0
    for symbol in symbols:
        try:
            seed_symbol(var_dir, symbol, tenant_id=account_id, user_id=account_id)
            seeded += 1
        except BundleAlreadySeeded:
            # The reader reached the Data page and pressed the button before this
            # background task got here. Their workspace has the series; nothing to warn
            # about, and nothing to count.
            continue
        except Exception:  # noqa: BLE001 - a background task must not escalate
            logger.warning("could not seed %s into a new workspace", symbol, exc_info=True)
    logger.info("seeded %d/%d bundled series into a new workspace", seeded, len(symbols))
    return seeded
