"""Version boundary for checkpoints created before confirmation receipts existed.

Ownership migration and artifact compatibility are separate concerns.  A legacy row can
still belong to the correct principal while its checkpoint predates the evidence contract
the current verifier promises.  Such artifacts stay preserved, but they are never silently
upgraded or presented as current evidence.
"""

from __future__ import annotations


LEGACY_CHECKPOINT_CODE = "LEGACY_CHECKPOINT_REBUILD_REQUIRED"
UNSUPPORTED_ARTIFACT_CONTRACT_CODE = "ARTIFACT_CONTRACT_REBUILD_REQUIRED"
FINANCIAL_SEMANTICS_REBUILD_CODE = "FINANCIAL_SEMANTICS_REBUILD_REQUIRED"


def legacy_checkpoint_issue(run: dict) -> dict | None:
    """Return a safe remediation state for a pre-receipt run, otherwise ``None``.

    Current runs always persist the exact confirmation restatement and its hash.  Older
    database rows cannot reconstruct that user action after the fact, so the only honest
    transition is a new run from the saved accepted spec.
    """
    if run.get("confirmation_receipt") is not None:
        return None
    return {
        "code": LEGACY_CHECKPOINT_CODE,
        "run_id": run.get("run_id"),
        "message": (
            "This checkpoint was created before the current confirmation and integrity "
            "contract. Its files remain preserved, but QuantLens will not present them "
            "as current evidence. Create a new run from the saved accepted spec."
        ),
        "rebuild": {
            "available": isinstance(run.get("spec"), dict),
            "source": "saved_accepted_spec",
        },
    }


def unsupported_artifact_contract_issue(run: dict) -> dict:
    """Return a stable public remediation state for an unregistered sealed tuple."""
    return {
        "code": UNSUPPORTED_ARTIFACT_CONTRACT_CODE,
        "run_id": run.get("run_id"),
        "message": (
            "This checkpoint's sealed contract is not registered for safe historical "
            "presentation. Its files remain preserved and were not rewritten. Create a "
            "new run from the saved accepted spec to use the current contract."
        ),
        "rebuild": {
            "available": isinstance(run.get("spec"), dict),
            "source": "saved_accepted_spec",
        },
    }


def financial_semantics_rebuild_issue(run: dict, contract: object) -> dict:
    """Refuse contract-gated claims while retaining original historical presentation."""
    safe_contract = contract if isinstance(contract, dict) else None
    return {
        "code": FINANCIAL_SEMANTICS_REBUILD_CODE,
        "run_id": run.get("run_id"),
        "message": (
            "This run remains available as original historical evidence, but its legacy "
            "financial semantics are not eligible for contract-gated Compare, ranking, "
            "metrics-v2, or Research Copilot claims. Rebuild it after the corrected "
            "financial contract is activated."
        ),
        "artifact_contract": safe_contract,
        "rebuild": {
            "available": isinstance(run.get("spec"), dict),
            "source": "saved_accepted_spec",
        },
    }
