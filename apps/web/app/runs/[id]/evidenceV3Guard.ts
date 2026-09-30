import type { DataLabel, EvidenceViewV3 } from "@schema/ts/evidence";

/**
 * Runtime closed-shape guard for the sealed v3 evidence record.
 *
 * The schema package's `isEvidenceViewV3` is the sealed reference guard, but
 * the web runtime deliberately never imports package values — bundling stops
 * at the application root, and type-only imports are erased. This module is
 * the application-side runtime tier of that law and differs from the
 * reference guard in exactly one reviewed way: it checks the contract tuple
 * STRUCTURALLY (closed key set, non-empty string values) without pinning the
 * frozen tuple values. Tuple-value exactness is a server-owned resolution:
 * the research service never serves a v3 record whose tuple it has not
 * checked against the registered contract, and the sealed reference guard
 * continues to pin the exact values in the contract spec suite. Everything
 * else — closed records, hash grammars, the label/snapshot cross-bind and
 * the ledger/receipt cross-bindings — mirrors the reference guard.
 *
 * Passing this guard never means the evidence was independently validated;
 * it means the payload is faithful enough to display as a sealed record.
 */

const V3_VIEW_KEYS = [
  "evidence_view_version", "evidence_semantics_version", "active_tuple",
  "identity", "bindings", "semantic_receipt",
] as const;
const V3_TUPLE_KEYS = [
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
] as const;
const V3_IDENTITY_KEYS = [
  "manifest_id", "spec_hash", "spec_version", "snapshot_id", "snapshot_sha256",
  "image_digest", "battery_config_hash", "result_hash", "created_at",
  "confirmation_receipt_hash", "data_label",
] as const;
const V3_BINDING_KEYS = [
  "plan_anchor_sha256", "financial_contract_sha256", "ledger_id",
  "semantic_receipt_sha256", "temporal_integrity_sha256",
  "final_holdout_execution_audit_sha256",
] as const;
const V3_RECEIPT_KEYS = [
  "validator_version", "ledger_id", "result_hash", "financial_contract_sha256",
  "validated_execution_ids", "status",
] as const;

const PREFIXED_SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256_RE = /^[0-9a-f]{64}$/;
const LEDGER_ID_RE = /^ldg-[0-9a-f]{64}$/;
const IMAGE_DIGEST_RE = /^local-runtime-sha256:[0-9a-f]{64}$/;
const EXECUTION_ID_RE = /^exec-[0-9a-f]{64}$/;
const CREATED_AT_RE = /^\d{4}-\d{2}-\d{2}T/;
const V3_DATA_LABELS: readonly DataLabel[] = [
  "SYNTHETIC", "USER_UPLOADED", "LICENSED_PROVIDER",
];
const USER_SNAPSHOT_ID_RE = /^usr-[0-9a-f]{16}$/;
const LICENSED_SNAPSHOT_ID_RE = /^lic-[0-9a-f]{16}$/;

function snapshotIdentityMatchesLabel(label: DataLabel, snapshotId: string): boolean {
  if (label === "USER_UPLOADED") {
    return USER_SNAPSHOT_ID_RE.test(snapshotId);
  }
  if (label === "LICENSED_PROVIDER") {
    return LICENSED_SNAPSHOT_ID_RE.test(snapshotId);
  }
  return true; // SYNTHETIC retains the generic manifest-v0 snapshot identity.
}

function isClosedRecord(
  value: unknown, keys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => own.includes(key));
}

function isStructuralTuple(value: unknown): boolean {
  if (!isClosedRecord(value, V3_TUPLE_KEYS)) {
    return false;
  }
  if (value.evidence_view_version !== "v3"
      || value.evidence_semantics_version !== "v3") {
    return false;
  }
  return V3_TUPLE_KEYS.every((key) => {
    const field = value[key];
    return typeof field === "string" && field.length >= 1 && field.length <= 256;
  });
}

function isStructuralIdentity(value: unknown): boolean {
  if (!isClosedRecord(value, V3_IDENTITY_KEYS)) {
    return false;
  }
  return (
    typeof value.manifest_id === "string" && value.manifest_id.length >= 8
    && typeof value.spec_hash === "string" && PREFIXED_SHA256_RE.test(value.spec_hash)
    && typeof value.spec_version === "number"
    && Number.isInteger(value.spec_version) && value.spec_version >= 1
    && typeof value.snapshot_id === "string" && value.snapshot_id.length >= 8
    && typeof value.snapshot_sha256 === "string"
    && BARE_SHA256_RE.test(value.snapshot_sha256)
    && typeof value.image_digest === "string"
    && IMAGE_DIGEST_RE.test(value.image_digest)
    && typeof value.battery_config_hash === "string"
    && PREFIXED_SHA256_RE.test(value.battery_config_hash)
    && typeof value.result_hash === "string"
    && PREFIXED_SHA256_RE.test(value.result_hash)
    && typeof value.created_at === "string" && CREATED_AT_RE.test(value.created_at)
    && typeof value.confirmation_receipt_hash === "string"
    && BARE_SHA256_RE.test(value.confirmation_receipt_hash)
    && V3_DATA_LABELS.includes(value.data_label as DataLabel)
    && snapshotIdentityMatchesLabel(
      value.data_label as DataLabel, value.snapshot_id as string)
  );
}

function isStructuralBindings(value: unknown): boolean {
  if (!isClosedRecord(value, V3_BINDING_KEYS)) {
    return false;
  }
  return V3_BINDING_KEYS.every((key) => {
    const field = value[key];
    if (typeof field !== "string") {
      return false;
    }
    return key === "ledger_id"
      ? LEDGER_ID_RE.test(field)
      : PREFIXED_SHA256_RE.test(field);
  });
}

function isStructuralReceipt(value: unknown): boolean {
  if (!isClosedRecord(value, V3_RECEIPT_KEYS)) {
    return false;
  }
  const ids = value.validated_execution_ids;
  return (
    value.validator_version === "financial-semantic-validator-v1"
    && value.status === "PASS"
    && typeof value.ledger_id === "string" && LEDGER_ID_RE.test(value.ledger_id)
    && typeof value.result_hash === "string"
    && PREFIXED_SHA256_RE.test(value.result_hash)
    && typeof value.financial_contract_sha256 === "string"
    && PREFIXED_SHA256_RE.test(value.financial_contract_sha256)
    && Array.isArray(ids)
    && ids.length >= 1
    && ids.every((id) => typeof id === "string" && EXECUTION_ID_RE.test(id))
    && new Set(ids).size === ids.length
  );
}

/** Fail-closed structural guard over the sealed v3 record (see module doc). */
export function isRenderableEvidenceV3(value: unknown): value is EvidenceViewV3 {
  if (!isClosedRecord(value, V3_VIEW_KEYS)) {
    return false;
  }
  if (
    value.evidence_view_version !== "v3"
    || value.evidence_semantics_version !== "v3"
    || !isStructuralTuple(value.active_tuple)
    || !isStructuralIdentity(value.identity)
    || !isStructuralBindings(value.bindings)
    || !isStructuralReceipt(value.semantic_receipt)
  ) {
    return false;
  }
  const identity = value.identity as Record<string, unknown>;
  const bindings = value.bindings as Record<string, unknown>;
  const receipt = value.semantic_receipt as Record<string, unknown>;
  return (
    receipt.ledger_id === bindings.ledger_id
    && receipt.result_hash === identity.result_hash
    && receipt.financial_contract_sha256 === bindings.financial_contract_sha256
  );
}
