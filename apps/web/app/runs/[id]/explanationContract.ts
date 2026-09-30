import type {
  EvidenceExplanation,
  ExplanationBinding,
  ExplanationBlock,
  ExplanationCitation,
  ExplanationContextValue,
  ExplanationGenerationMetadata,
  ExplanationViewV1,
} from "@schema/ts/evidence";

const HASH = /^[0-9a-f]{64}$/;
const RESULT_HASH = /^sha256:[0-9a-f]{64}$/;
const OPAQUE_BINDING = /^evb1-[0-9a-f]{64}$/;
const MAX_CONTEXT_DEPTH = 32;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const observed = Object.keys(value);
  return observed.length === keys.length && observed.every((key) => keys.includes(key));
}

function isStringOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isContextValue(value: unknown, depth = 0): value is ExplanationContextValue {
  if (depth > MAX_CONTEXT_DEPTH) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    return value.every((item) => isContextValue(item, depth + 1));
  }
  if (!isRecord(value)) return false;
  return Object.entries(value).every(([key, item]) =>
    key !== "__proto__" && key !== "prototype" && key !== "constructor"
      && isContextValue(item, depth + 1));
}

function isGeneration(value: unknown): value is ExplanationGenerationMetadata {
  if (!isRecord(value) || !hasExactKeys(value, [
    "ai_used", "ai_influenced_output", "provider_invoked",
    "provider_data_transmitted", "provider", "model", "request_id",
    "finish_reason", "fallback_used", "fallback_code", "policy_version",
  ])) return false;
  if (typeof value.ai_used !== "boolean"
      || typeof value.ai_influenced_output !== "boolean"
      || typeof value.provider_invoked !== "boolean"
      || typeof value.provider_data_transmitted !== "boolean"
      || typeof value.fallback_used !== "boolean"
      || typeof value.provider !== "string"
      || typeof value.policy_version !== "string"
      || !isStringOrNull(value.model)
      || !isStringOrNull(value.request_id)
      || !isStringOrNull(value.finish_reason)
      || !isStringOrNull(value.fallback_code)) return false;
  // These implications prevent contradictory disclosure labels even if the transport
  // returns a syntactically well-shaped but semantically impossible object.
  if (value.provider_data_transmitted && !value.provider_invoked) return false;
  if (value.ai_used !== value.ai_influenced_output) return false;
  if (value.ai_influenced_output
      && (!value.ai_used || !value.provider_invoked || !value.provider_data_transmitted)) {
    return false;
  }
  return true;
}

function isBinding(value: unknown, expectedRunId: string): value is ExplanationBinding {
  if (!isRecord(value) || !hasExactKeys(value, [
    "opaque_evidence_binding", "run_id", "evidence_view_version",
    "evidence_semantics_version", "catalog_version", "catalog_sha256",
    "result_hash", "manifest_sha256", "ledger_index_sha256",
  ])) return false;
  return typeof value.opaque_evidence_binding === "string"
    && OPAQUE_BINDING.test(value.opaque_evidence_binding)
    && value.run_id === expectedRunId
    && value.evidence_view_version === "v1"
    && value.evidence_semantics_version === "v1"
    && value.catalog_version === "NarrativeFactCatalogV1"
    && typeof value.catalog_sha256 === "string" && HASH.test(value.catalog_sha256)
    && typeof value.result_hash === "string" && RESULT_HASH.test(value.result_hash)
    && typeof value.manifest_sha256 === "string" && HASH.test(value.manifest_sha256)
    && typeof value.ledger_index_sha256 === "string" && HASH.test(value.ledger_index_sha256);
}

function isCitation(value: unknown): value is ExplanationCitation {
  if (!isRecord(value) || !hasExactKeys(value, [
    "fact_id", "value", "formatted_value", "unit", "context",
    "artifact_id", "artifact_sha256", "json_pointer",
  ])) return false;
  const citationValue = value.value;
  return typeof value.fact_id === "string" && value.fact_id.length > 0
    && (typeof citationValue === "string" || isFiniteNumber(citationValue))
    && typeof value.formatted_value === "string"
    && typeof value.unit === "string"
    && isRecord(value.context) && isContextValue(value.context)
    && typeof value.artifact_id === "string" && value.artifact_id.length > 0
    && typeof value.artifact_sha256 === "string" && HASH.test(value.artifact_sha256)
    && typeof value.json_pointer === "string" && value.json_pointer.startsWith("/");
}

function isBlock(value: unknown): value is ExplanationBlock {
  if (!isRecord(value) || !hasExactKeys(value, [
    "template_id", "comparator", "fact_ids", "text", "citations",
  ])) return false;
  if (typeof value.template_id !== "string" || value.template_id.length === 0
      || typeof value.comparator !== "string" || value.comparator.length === 0
      || typeof value.text !== "string"
      || !Array.isArray(value.fact_ids) || value.fact_ids.length === 0
      || !value.fact_ids.every((factId) => typeof factId === "string" && factId.length > 0)
      || !Array.isArray(value.citations) || value.citations.length === 0
      || !value.citations.every(isCitation)) return false;
  const factIds = value.fact_ids as string[];
  const citations = value.citations as ExplanationCitation[];
  return factIds.length === citations.length
    && factIds.every((factId, index) => citations[index]?.fact_id === factId);
}

function isExplanation(value: unknown): value is EvidenceExplanation {
  if (!isRecord(value) || !hasExactKeys(value, [
    "title", "format", "blocks", "disclosure",
  ])) return false;
  return typeof value.title === "string"
    && value.format === "plain_text_blocks_v1"
    && typeof value.disclosure === "string"
    && Array.isArray(value.blocks) && value.blocks.length > 0
    && value.blocks.every(isBlock);
}

/** Validate untrusted JSON before it can reach the explanation renderer. */
export function isExplanationViewV1(
  value: unknown,
  expectedRunId: string,
): value is ExplanationViewV1 {
  if (!isRecord(value) || !hasExactKeys(value, [
    "explanation_view_version", "narrative_plan_version", "status",
    "generation", "binding", "explanation",
  ])) return false;
  if (value.explanation_view_version !== "v1"
      || value.narrative_plan_version !== "NarrativePlanV1"
      || (value.status !== "completed" && value.status !== "unavailable")
      || !isGeneration(value.generation)) return false;
  if (value.status === "completed") {
    return isBinding(value.binding, expectedRunId) && isExplanation(value.explanation);
  }
  return value.binding === null && value.explanation === null;
}

export function atomicUnavailableExplanation(): ExplanationViewV1 {
  return {
    explanation_view_version: "v1",
    narrative_plan_version: "NarrativePlanV1",
    status: "unavailable",
    generation: {
      ai_used: false,
      ai_influenced_output: false,
      provider_invoked: false,
      provider_data_transmitted: false,
      provider: "disabled",
      model: null,
      request_id: null,
      finish_reason: "unavailable",
      fallback_used: false,
      fallback_code: null,
      policy_version: "narrative-policy-v1",
    },
    binding: null,
    explanation: null,
  };
}
