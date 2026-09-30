/**
 * Strict client-side validation for GET /runs/{id}/research-copilot
 * ("research_copilot_view_version": "v1").
 *
 * This guard is SEMANTICALLY closed against the deterministic server surface,
 * not just structurally closed. It mirrors the backend rule tables byte for
 * byte (research_contracts.py, research_projection.py, research_renderer.py):
 *
 * - binding must match the dvb1 format; policy version is pinned; the fallback
 *   code must come from the closed set reachable without provider involvement.
 * - every fact id carries its exact expected unit and display precision;
 *   formatted values must match a safe unit-specific format with no control,
 *   bidi, or markup content.
 * - the analysis must be exactly the five canonical template blocks, once each,
 *   in canonical order, with each template's required comparator and exact
 *   ordered fact ids/citations.
 * - block text must equal the deterministic server render rebuilt from the
 *   cited formatted values — arbitrary prose, advice, or final-holdout strings
 *   cannot pass.
 * - the pending action must be one of the three review actions with its exact
 *   supporting facts and canonical server label/description, and must agree
 *   with the sealed check statuses the way the canonical planner decides.
 *
 * Membership checks use Map/Set lookups only — never the `in` operator — so
 * prototype keys ("__proto__", "constructor") cannot pass. Anything unknown,
 * missing, malformed, non-finite, holdout-flavored, provider-enabled, or
 * auto-executing rejects the whole response atomically. The opaque development
 * binding is validated for shape but never exported to a rendering surface.
 */

export type ResearchCheckStatus = "PASS" | "FAIL" | "INCONCLUSIVE";

export type ResearchCopilotActionId =
  | "review_walk_forward_evidence"
  | "review_cost_stress_evidence"
  | "review_regime_coverage_evidence";

export interface ResearchCopilotCitation {
  fact_id: string;
  value: number | ResearchCheckStatus;
  formatted_value: string;
  unit: string;
  display_precision: number;
}

export interface ResearchCopilotBlock {
  template_id: string;
  comparator: string;
  fact_ids: string[];
  text: string;
  citations: ResearchCopilotCitation[];
}

export interface ResearchCopilotPendingAction {
  action_id: ResearchCopilotActionId;
  status: "confirmation_required";
  execution_state: "not_started";
  auto_execute: false;
  supporting_fact_ids: string[];
  label: string;
  description: string;
}

export interface ResearchCopilotAnalysis {
  research_plan_version: "ResearchPlanV1";
  scope: "development_only";
  title: string;
  blocks: ResearchCopilotBlock[];
  /** The canonical backend plan always carries exactly one review action. */
  pending_action: ResearchCopilotPendingAction;
  disclosure: string;
}

export interface ResearchCopilotView {
  research_copilot_view_version: "v1";
  status: "completed";
  scope: "development_only";
  /** Validated for format only; never render or export this value. */
  binding: { opaque_development_binding: string };
  generation: {
    ai_used: false;
    provider_invoked: false;
    provider_data_transmitted: false;
    ai_influenced_output: false;
    provider: "disabled";
    fallback_used: true;
    fallback_code: string;
    policy_version: string;
  };
  analysis: ResearchCopilotAnalysis;
}

const BINDING_FORMAT = /^dvb1-[0-9a-f]{64}$/;
const POLICY_VERSION = "development-research-policy-v1";

/** Fallback codes reachable on the safe canonical path (no provider involved). */
const SAFE_FALLBACK_CODES = new Set([
  "RESEARCH_PROVIDER_DISABLED",
  "RESEARCH_PROVIDER_UNKNOWN",
  "RESEARCH_CANONICAL_FAILED",
]);

const CANONICAL_TITLE = "Development research review";
const CANONICAL_DISCLOSURE =
  "Development evidence only. Final-holdout evidence is not available to this "
  + "Research Copilot. The summary describes sealed research measurements and does "
  + "not direct a financial action.";

type ResearchUnit = "decimal_fraction" | "ratio" | "count" | "USD" | "check_status";

/** Every citable development fact: exact unit, display precision, product label. */
const FACTS = new Map<string, { unit: ResearchUnit; precision: number; label: string }>([
  ["development.performance.total_return",
    { unit: "decimal_fraction", precision: 2, label: "Development price return" }],
  ["development.performance.cagr",
    { unit: "decimal_fraction", precision: 2, label: "Development CAGR" }],
  ["development.performance.annualized_volatility",
    { unit: "decimal_fraction", precision: 2, label: "Annualized volatility" }],
  ["development.performance.sharpe",
    { unit: "ratio", precision: 2, label: "Development Sharpe" }],
  ["development.performance.max_drawdown",
    { unit: "decimal_fraction", precision: 2, label: "Maximum drawdown" }],
  ["development.activity.trade_count",
    { unit: "count", precision: 0, label: "Trades" }],
  ["development.activity.total_costs",
    { unit: "USD", precision: 2, label: "Modeled costs" }],
  ["development.activity.exposure",
    { unit: "decimal_fraction", precision: 1, label: "Time in market" }],
  ["development.walk_forward.fold_count",
    { unit: "count", precision: 0, label: "Walk-forward folds" }],
  ["development.walk_forward.median_fold_sharpe",
    { unit: "ratio", precision: 2, label: "Median fold Sharpe" }],
  ["development.walk_forward.positive_fold_ratio",
    { unit: "decimal_fraction", precision: 0, label: "Positive folds" }],
  ["development.walk_forward.worst_fold_return",
    { unit: "decimal_fraction", precision: 2, label: "Worst fold return" }],
  ["development.walk_forward.fold_return_dispersion",
    { unit: "decimal_fraction", precision: 2, label: "Fold return dispersion" }],
  ["development.cost_stress.base.total_return",
    { unit: "decimal_fraction", precision: 2, label: "Price return at base costs" }],
  ["development.cost_stress.doubled.total_return",
    { unit: "decimal_fraction", precision: 2, label: "Price return at doubled costs" }],
  ["development.cost_stress.base.total_costs",
    { unit: "USD", precision: 2, label: "Modeled costs at base" }],
  ["development.cost_stress.doubled.total_costs",
    { unit: "USD", precision: 2, label: "Modeled costs at doubled" }],
  ["development.regime.up_low.observations",
    { unit: "count", precision: 0, label: "Up / low-volatility sessions" }],
  ["development.regime.up_low.status",
    { unit: "check_status", precision: 0, label: "Up / low-volatility coverage" }],
  ["development.regime.up_high.observations",
    { unit: "count", precision: 0, label: "Up / high-volatility sessions" }],
  ["development.regime.up_high.status",
    { unit: "check_status", precision: 0, label: "Up / high-volatility coverage" }],
  ["development.regime.down_low.observations",
    { unit: "count", precision: 0, label: "Down / low-volatility sessions" }],
  ["development.regime.down_low.status",
    { unit: "check_status", precision: 0, label: "Down / low-volatility coverage" }],
  ["development.regime.down_high.observations",
    { unit: "count", precision: 0, label: "Down / high-volatility sessions" }],
  ["development.regime.down_high.status",
    { unit: "check_status", precision: 0, label: "Down / high-volatility coverage" }],
  ["development.check.walk_forward_stability",
    { unit: "check_status", precision: 0, label: "Walk-forward stability check" }],
  ["development.check.cost_fragility",
    { unit: "check_status", precision: 0, label: "Cost fragility check" }],
  ["development.check.regime_coverage",
    { unit: "check_status", precision: 0, label: "Regime coverage check" }],
]);

/** The exact backend _TEMPLATE_RULES, in canonical (insertion) order. */
const TEMPLATE_RULES: {
  template: string;
  comparator: string;
  factIds: string[];
}[] = [
  {
    template: "summarize_development_risk_return",
    comparator: "risk_return_context",
    factIds: [
      "development.performance.total_return",
      "development.performance.sharpe",
      "development.performance.max_drawdown",
    ],
  },
  {
    template: "summarize_walk_forward_stability",
    comparator: "stability_context",
    factIds: [
      "development.walk_forward.positive_fold_ratio",
      "development.walk_forward.median_fold_sharpe",
      "development.walk_forward.worst_fold_return",
      "development.walk_forward.fold_count",
    ],
  },
  {
    template: "compare_base_and_doubled_development_costs",
    comparator: "base_vs_stressed",
    factIds: [
      "development.cost_stress.base.total_return",
      "development.cost_stress.base.total_costs",
      "development.cost_stress.doubled.total_return",
      "development.cost_stress.doubled.total_costs",
    ],
  },
  {
    template: "summarize_preregistered_regime_coverage",
    comparator: "coverage_context",
    factIds: [
      "development.regime.up_low.observations",
      "development.regime.up_low.status",
      "development.regime.up_high.observations",
      "development.regime.up_high.status",
      "development.regime.down_low.observations",
      "development.regime.down_low.status",
      "development.regime.down_high.observations",
      "development.regime.down_high.status",
    ],
  },
  {
    template: "summarize_development_validation_checks",
    comparator: "status_only",
    factIds: [
      "development.check.walk_forward_stability",
      "development.check.cost_fragility",
      "development.check.regime_coverage",
    ],
  },
];

/** The exact backend _ACTION_RULES + _ACTION_COPY. */
const ACTION_RULES = new Map<ResearchCopilotActionId, {
  factIds: string[];
  label: string;
  description: string;
}>([
  ["review_walk_forward_evidence", {
    factIds: TEMPLATE_RULES[1].factIds,
    label: "Review walk-forward evidence",
    description:
      "Open the aggregate fold-evidence review after confirmation. This action does "
      + "not launch a run or change a parameter.",
  }],
  ["review_cost_stress_evidence", {
    factIds: TEMPLATE_RULES[2].factIds,
    label: "Review development cost stress",
    description:
      "Open the base-versus-stressed development evidence after confirmation. This "
      + "action does not launch a run or change a parameter.",
  }],
  ["review_regime_coverage_evidence", {
    factIds: TEMPLATE_RULES[3].factIds,
    label: "Review regime coverage",
    description:
      "Open the preregistered development coverage review after confirmation. This "
      + "action does not launch a run or change a parameter.",
  }],
]);

const STATUSES = new Set<ResearchCheckStatus>(["PASS", "FAIL", "INCONCLUSIVE"]);
const STATUS_FORMAT: Record<ResearchCheckStatus, string> = {
  PASS: "Pass", FAIL: "Fail", INCONCLUSIVE: "Inconclusive",
};

// Control, bidi, zero-width, and separator characters must never appear in any
// rendered string. Built via RegExp constructor — see workflow conventions: literal
// backslash-u escapes typed into files are emitted as raw control bytes.
const UNSAFE_CHARS = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u200b-\\u200f\\u2028-\\u202e"
  + "\\u2066-\\u2069\\ufeff]");
const MARKUP_CHARS = /[<>{}[\]\\`]/;

/** Human citation label; internal fact identifiers never reach ordinary UI. */
export function citationLabel(factId: string): string {
  return FACTS.get(factId)?.label ?? "Sealed development value";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  const present = Object.keys(record);
  return present.length === keys.length && present.every((key) => allowed.has(key));
}

/** Belt-and-braces: no key anywhere may reference the final holdout. */
function keysAreDevelopmentOnly(record: Record<string, unknown>): boolean {
  return Object.keys(record).every((key) => !/final|holdout/i.test(key));
}

function safeString(value: unknown, maxLength: number): value is string {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= maxLength
    && !UNSAFE_CHARS.test(value)
    && !MARKUP_CHARS.test(value);
}

function sameStrings(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/* -------------------------------------------------------------------------
 * Exact canonical formatting. The backend renders every numeric citation with
 * Decimal(str(value)) quantized ROUND_HALF_EVEN (research_renderer._format_fact).
 * JS String(number) produces the same shortest-round-trip digits as Python
 * str(float), so parsing that string into an exact scaled-integer decimal and
 * quantizing with BigInt arithmetic reproduces the backend output digit for
 * digit — no binary-float rounding drift, no dependency.
 * ---------------------------------------------------------------------- */

interface ExactDecimal {
  negative: boolean;
  /** Significant digits, no sign, no dot. */
  digits: string;
  /** Numeric value = digits * 10^exponent. */
  exponent: number;
}

/** Parse String(number): plain and exponent forms ("123.45", "1e-7", "1.2e+21"). */
function parseDecimalString(text: string): ExactDecimal | null {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
  if (!match) return null;
  const fracPart = match[3] ?? "";
  const exponent = (match[4] ? parseInt(match[4], 10) : 0) - fracPart.length;
  const digits = (match[2] + fracPart).replace(/^0+(?=\d)/, "");
  return { negative: match[1] === "-", digits, exponent };
}

/** round(digits * 10^(exponent + precision)) with ROUND_HALF_EVEN, exactly. */
function quantizeHalfEven(digits: string, exponent: number, precision: number): bigint {
  const shift = exponent + precision;
  if (shift >= 0) return BigInt(digits) * 10n ** BigInt(shift);
  const cut = -shift;
  const padded = digits.length > cut
    ? digits
    : "0".repeat(cut - digits.length + 1) + digits;
  let head = BigInt(padded.slice(0, padded.length - cut));
  const tail = padded.slice(padded.length - cut);
  const half = `5${"0".repeat(cut - 1)}`;
  // Equal-length digit strings compare lexicographically as numbers.
  if (tail > half || (tail === half && head % 2n === 1n)) head += 1n;
  return head;
}

/** Scaled integer -> "-1,234.56"-style string (sign-preserving, incl. -0.00). */
function renderScaled(
  scaled: bigint, negative: boolean, precision: number, grouped: boolean,
): string {
  let body = scaled.toString();
  if (precision > 0) body = body.padStart(precision + 1, "0");
  let integerPart = precision > 0 ? body.slice(0, -precision) : body;
  const fractionPart = precision > 0 ? `.${body.slice(-precision)}` : "";
  if (grouped) integerPart = integerPart.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${negative ? "-" : ""}${integerPart}${fractionPart}`;
}

/** The exact backend rendering of a validated numeric fact value, or null. */
function canonicalFormattedValue(
  value: number, unit: ResearchUnit, precision: number,
): string | null {
  const parsed = parseDecimalString(String(value));
  if (!parsed) return null;
  // String(-0) is "0": recover the sign the backend keeps through Decimal("-0.0").
  const negative = parsed.negative || Object.is(value, -0);
  if (unit === "decimal_fraction") {
    const scaled = quantizeHalfEven(parsed.digits, parsed.exponent + 2, precision);
    return `${renderScaled(scaled, negative, precision, false)}%`;
  }
  if (unit === "ratio") {
    const scaled = quantizeHalfEven(parsed.digits, parsed.exponent, precision);
    return renderScaled(scaled, negative, precision, false);
  }
  if (unit === "count") {
    const scaled = quantizeHalfEven(parsed.digits, parsed.exponent, 0);
    return renderScaled(scaled, negative, 0, true);
  }
  if (unit === "USD") {
    const scaled = quantizeHalfEven(parsed.digits, parsed.exponent, precision);
    return `$${renderScaled(scaled, negative, precision, true)}`;
  }
  return null;
}

/* Exact backend numeric boundaries (research_projection._validate_fact_value). */
const UNIT_INTERVAL_FACTS = new Set([
  "development.activity.exposure",
  "development.walk_forward.positive_fold_ratio",
]);
const DISPERSION_FACTS = new Set([
  "development.performance.annualized_volatility",
  "development.walk_forward.fold_return_dispersion",
]);
const DRAWDOWN_FACT = "development.performance.max_drawdown";

function valueWithinBoundary(factId: string, unit: ResearchUnit, value: number): boolean {
  if (unit === "count") {
    // Number.isInteger(-0) is true and -0 >= 0 holds, but the backend's strict
    // Python int can never carry or emit a negative zero — reject it outright.
    return Number.isInteger(value) && !Object.is(value, -0)
      && value >= 0 && value <= 1_000_000_000;
  }
  if (unit === "USD") return value >= 0 && value <= 1_000_000_000_000_000;
  if (unit === "ratio") return Math.abs(value) <= 1_000_000;
  // decimal_fraction families
  if (UNIT_INTERVAL_FACTS.has(factId)) return value >= 0 && value <= 1;
  if (factId === DRAWDOWN_FACT) return value >= -1 && value <= 0;
  if (DISPERSION_FACTS.has(factId)) return value >= 0 && value <= 1_000_000;
  return value >= -1 && value <= 1_000_000;
}

/** The deterministic server sentence for a template, rebuilt from its citations. */
function expectedBlockText(template: string, values: string[]): string | null {
  if (template === "summarize_development_risk_return") {
    return `Development price return was ${values[0]}, annualized Sharpe was `
      + `${values[1]}, and maximum drawdown was ${values[2]}.`;
  }
  if (template === "summarize_walk_forward_stability") {
    return `Positive development folds represented ${values[0]}; median fold Sharpe `
      + `was ${values[1]}, the worst fold return was ${values[2]}, and the fixed rule `
      + `was evaluated across ${values[3]} folds.`;
  }
  if (template === "compare_base_and_doubled_development_costs") {
    return `At base development costs, price return was ${values[0]} and modeled `
      + `costs were ${values[1]}; under the preregistered doubled-cost stress, `
      + `price return was ${values[2]} and modeled costs were ${values[3]}.`;
  }
  if (template === "summarize_preregistered_regime_coverage") {
    const labels = ["up/low-volatility", "up/high-volatility",
      "down/low-volatility", "down/high-volatility"];
    const pairs = labels.map((label, index) =>
      `${label}: ${values[index * 2]} observations (${values[index * 2 + 1]})`);
    return `Preregistered development regime coverage was ${pairs.join("; ")}.`;
  }
  if (template === "summarize_development_validation_checks") {
    return `Development checks reported walk-forward stability ${values[0]}, cost `
      + `fragility ${values[1]}, and regime coverage ${values[2]}.`;
  }
  return null;
}

function isCitationFor(value: unknown, factId: string): value is ResearchCopilotCitation {
  if (!isRecord(value) || !keysAreDevelopmentOnly(value)) return false;
  if (!hasExactKeys(value, [
    "fact_id", "value", "formatted_value", "unit", "display_precision",
  ])) return false;
  if (value.fact_id !== factId) return false;
  const rule = FACTS.get(factId);
  if (!rule) return false;
  if (value.unit !== rule.unit) return false;
  if (value.display_precision !== rule.precision) return false;
  const formatted = value.formatted_value;
  if (!safeString(formatted, 32)) return false;
  const cited = value.value;
  if (rule.unit === "check_status") {
    return STATUSES.has(cited as ResearchCheckStatus)
      && formatted === STATUS_FORMAT[cited as ResearchCheckStatus];
  }
  if (typeof cited !== "number" || !Number.isFinite(cited)) return false;
  if (!valueWithinBoundary(factId, rule.unit, cited)) return false;
  // The formatted value must be EXACTLY the backend's deterministic rendering of
  // the raw value — a forged pair like value 0.1332 / "99.99%" cannot pass even
  // when the block text is rewritten consistently.
  return formatted === canonicalFormattedValue(cited, rule.unit, rule.precision);
}

function isCanonicalBlock(
  value: unknown, rule: (typeof TEMPLATE_RULES)[number],
): value is ResearchCopilotBlock {
  if (!isRecord(value) || !keysAreDevelopmentOnly(value)) return false;
  if (!hasExactKeys(value, [
    "template_id", "comparator", "fact_ids", "text", "citations",
  ])) return false;
  if (value.template_id !== rule.template) return false;
  if (value.comparator !== rule.comparator) return false;
  const factIds = value.fact_ids;
  if (!Array.isArray(factIds) || !sameStrings(factIds as string[], rule.factIds)) {
    return false;
  }
  const citations = value.citations;
  if (!Array.isArray(citations) || citations.length !== rule.factIds.length) {
    return false;
  }
  if (!citations.every((citation, index) =>
    isCitationFor(citation, rule.factIds[index]))) return false;
  const expected = expectedBlockText(
    rule.template,
    (citations as ResearchCopilotCitation[]).map((c) => c.formatted_value));
  return expected !== null
    && safeString(value.text, 600)
    && value.text === expected;
}

/** The canonical planner's action choice, derived from the sealed check statuses. */
function expectedActionId(
  walkForward: ResearchCheckStatus,
  costFragility: ResearchCheckStatus,
  regimeCoverage: ResearchCheckStatus,
): ResearchCopilotActionId {
  if (costFragility !== "PASS") return "review_cost_stress_evidence";
  if (walkForward !== "PASS") return "review_walk_forward_evidence";
  if (regimeCoverage !== "PASS") return "review_regime_coverage_evidence";
  return "review_walk_forward_evidence";
}

function isCanonicalPendingAction(
  value: unknown, checkStatuses: ResearchCheckStatus[],
): value is ResearchCopilotPendingAction {
  if (!isRecord(value) || !keysAreDevelopmentOnly(value)) return false;
  if (!hasExactKeys(value, [
    "action_id", "status", "execution_state", "auto_execute",
    "supporting_fact_ids", "label", "description",
  ])) return false;
  const rule = ACTION_RULES.get(value.action_id as ResearchCopilotActionId);
  if (!rule) return false;
  if (value.status !== "confirmation_required") return false;
  if (value.execution_state !== "not_started") return false;
  if (value.auto_execute !== false) return false;
  const supporting = value.supporting_fact_ids;
  if (!Array.isArray(supporting) || !sameStrings(supporting as string[], rule.factIds)) {
    return false;
  }
  if (value.label !== rule.label) return false;
  if (value.description !== rule.description) return false;
  // The action must be the one the deterministic planner derives from the
  // sealed check statuses cited in the validation-checks block.
  return value.action_id === expectedActionId(
    checkStatuses[0], checkStatuses[1], checkStatuses[2]);
}

function isAnalysis(value: unknown): value is ResearchCopilotAnalysis {
  if (!isRecord(value) || !keysAreDevelopmentOnly(value)) return false;
  if (!hasExactKeys(value, [
    "research_plan_version", "scope", "title", "blocks", "pending_action",
    "disclosure",
  ])) return false;
  if (value.research_plan_version !== "ResearchPlanV1") return false;
  if (value.scope !== "development_only") return false;
  if (value.title !== CANONICAL_TITLE) return false;
  if (value.disclosure !== CANONICAL_DISCLOSURE) return false;
  const blocks = value.blocks;
  // Exactly the five canonical blocks, once each, in canonical order — the only
  // output the disabled deterministic provider surface can produce.
  if (!Array.isArray(blocks) || blocks.length !== TEMPLATE_RULES.length) return false;
  if (!blocks.every((block, index) => isCanonicalBlock(block, TEMPLATE_RULES[index]))) {
    return false;
  }
  const checkStatuses = (blocks[TEMPLATE_RULES.length - 1] as ResearchCopilotBlock)
    .citations.map((citation) => citation.value as ResearchCheckStatus);
  // The canonical plan always carries exactly one review action; a null action is
  // off the only allowed (disabled-provider) backend path and rejects atomically.
  return isCanonicalPendingAction(value.pending_action, checkStatuses);
}

export function isResearchCopilotView(body: unknown): body is ResearchCopilotView {
  if (!isRecord(body)) return false;
  if (!hasExactKeys(body, [
    "research_copilot_view_version", "status", "scope", "binding", "generation",
    "analysis",
  ])) return false;
  if (body.research_copilot_view_version !== "v1") return false;
  if (body.status !== "completed") return false;
  if (body.scope !== "development_only") return false;

  const binding = body.binding;
  if (!isRecord(binding)) return false;
  if (!hasExactKeys(binding, ["opaque_development_binding"])) return false;
  if (typeof binding.opaque_development_binding !== "string"
    || !BINDING_FORMAT.test(binding.opaque_development_binding)) return false;

  // Deterministic-generation invariants: any provider involvement, AI influence,
  // non-fallback path, foreign policy, or unexpected fallback code is unsafe for
  // this product surface and rejects atomically.
  const generation = body.generation;
  if (!isRecord(generation)) return false;
  if (!hasExactKeys(generation, [
    "ai_used", "provider_invoked", "provider_data_transmitted",
    "ai_influenced_output", "provider", "fallback_used", "fallback_code",
    "policy_version",
  ])) return false;
  if (generation.ai_used !== false) return false;
  if (generation.provider_invoked !== false) return false;
  if (generation.provider_data_transmitted !== false) return false;
  if (generation.ai_influenced_output !== false) return false;
  if (generation.provider !== "disabled") return false;
  if (generation.fallback_used !== true) return false;
  if (typeof generation.fallback_code !== "string"
    || !SAFE_FALLBACK_CODES.has(generation.fallback_code)) return false;
  if (generation.policy_version !== POLICY_VERSION) return false;

  return isAnalysis(body.analysis);
}
