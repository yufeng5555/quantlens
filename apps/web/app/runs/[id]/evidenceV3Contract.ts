/**
 * Dormant Gate E Stop A contract states for Evidence v3 (docs/planning/27 §4.2, §11).
 *
 * This module is deliberately unreferenced by every page, component and route: it
 * defines the typed `unsupported_contract`, `rebuild_required` and `validation_failed`
 * states of the future ledger-v1 resolver plus one pure classifier over unknown
 * payloads. It renders nothing, fetches nothing, and asserts no financial-semantics
 * claim for any run; the atomic Gate E activation decision belongs to a later stop.
 */

import { isEvidenceViewV3, type EvidenceViewV3 } from "@schema/ts/evidence";

export type EvidenceV3ContractStateCode =
  | "unsupported_contract"
  | "rebuild_required"
  | "validation_failed";

/** The sealed identifiers do not name a registered presentation contract. */
export interface EvidenceV3UnsupportedContract {
  state: "unsupported_contract";
  code: "EVIDENCE_V3_UNSUPPORTED_CONTRACT";
  run_id: string;
  message: string;
}

/** Legacy evidence stays readable under its frozen label; only a fresh run under the
 * corrected contract can make it eligible for corrected-semantics surfaces. */
export interface EvidenceV3RebuildRequired {
  state: "rebuild_required";
  code: "EVIDENCE_V3_REBUILD_REQUIRED";
  run_id: string;
  message: string;
  rebuild: { available: boolean; source: "saved_accepted_spec" };
}

/** A payload that claims the v3 contract but fails its sealed closed-shape checks. */
export interface EvidenceV3ValidationFailed {
  state: "validation_failed";
  code: "EVIDENCE_V3_VALIDATION_FAILED";
  run_id: string;
  message: string;
}

export type EvidenceV3ContractState =
  | EvidenceV3UnsupportedContract
  | EvidenceV3RebuildRequired
  | EvidenceV3ValidationFailed;

export type EvidenceV3Resolution =
  | { state: "v3"; view: EvidenceViewV3 }
  | EvidenceV3ContractState;

/**
 * Server-owned facts the classifier can never derive from payload bytes. The
 * structural guard cannot recompute the semantic receipt hash or re-run the
 * independent validator, so `server_validated` must come from the ledger-v1
 * resolver's own recorded resolution, and `rebuild_available` from the run's
 * saved-spec state. There are deliberately no defaults.
 */
export interface EvidenceV3ResolutionContext {
  server_validated: boolean;
  rebuild_available: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Pure, total classifier over an unknown evidence payload. It performs no fetch, no
 * rendering and no recomputation; a structurally well-formed v3 payload without the
 * server-owned validated resolution resolves to `validation_failed`, never to the
 * `v3` state — surface eligibility stays a server-owned activation decision.
 */
export function resolveEvidenceV3ContractState(
  runId: string,
  payload: unknown,
  context: EvidenceV3ResolutionContext,
): EvidenceV3Resolution {
  if (isEvidenceViewV3(payload)) {
    if (context.server_validated) {
      return { state: "v3", view: payload };
    }
    return {
      state: "validation_failed",
      code: "EVIDENCE_V3_VALIDATION_FAILED",
      run_id: runId,
      message:
        "This payload matches the sealed v3 shape, but no server-owned validated "
        + "resolution accompanies it, so no part of it can be shown.",
    };
  }
  const version = isRecord(payload) ? payload["evidence_view_version"] : undefined;
  if (version === "v1" || version === "v2") {
    return {
      state: "rebuild_required",
      code: "EVIDENCE_V3_REBUILD_REQUIRED",
      run_id: runId,
      message:
        "This run was sealed under a frozen legacy contract. It stays readable "
        + "under its original label; a fresh run under the corrected contract is "
        + "required before it can appear on corrected-semantics surfaces.",
      rebuild: { available: context.rebuild_available, source: "saved_accepted_spec" },
    };
  }
  if (version === "v3") {
    return {
      state: "validation_failed",
      code: "EVIDENCE_V3_VALIDATION_FAILED",
      run_id: runId,
      message:
        "This payload claims the v3 contract but does not satisfy the sealed "
        + "closed-shape contract, so no part of it can be shown.",
    };
  }
  return {
    state: "unsupported_contract",
    code: "EVIDENCE_V3_UNSUPPORTED_CONTRACT",
    run_id: runId,
    message:
      "The sealed identifiers of this payload do not name a registered "
      + "presentation contract, so it cannot be projected.",
  };
}
