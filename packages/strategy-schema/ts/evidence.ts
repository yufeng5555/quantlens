/**
 * EvidenceView — the typed contract for GET /runs/{run_id}/evidence.
 *
 * Discriminated union on ``evidence_view_version``:
 * - "v1" mirrors quantlens_worker/evidence.py   (Battery v1: IS/OOS + counterfactuals)
 * - "v2" mirrors quantlens_worker/evidence_v2.py (Battery v2: locked rule, development
 *   walk-forward, single-use final holdout)
 *
 * The server is the single source of truth. Every value is projected from sealed,
 * hash-checked ledger artifacts; the frontend renders these values verbatim and never
 * recomputes financial metrics, fold stitching, regime aggregates, or verdicts.
 */

import type { StrategySpec } from "./types";

/** The only allowed check vocabulary anywhere in the product (06 §5.2). */
export type CheckStatus = "PASS" | "FAIL" | "INCONCLUSIVE";
export type BatteryStatus = CheckStatus;
export type NotRunStatus = "NOT RUN";

export interface ArtifactRef {
  artifact_id: string;
  kind: string;
  sha256: string;
}

/** Read-only compatibility classification derived from a frozen sealed-contract registry.
 * It is presentation metadata, never part of the historical financial result hash. */
export interface ArtifactContractDescriptor {
  contract_id: string;
  presentation_status: "legacy_active" | "dormant";
  evidence_view_version: string;
  evidence_semantics_version: string;
  ledger_semantics_version: string;
  execution_semantics_version: string;
  execution_cost_model: "linear_execution_friction" | string;
  verified_financial_semantics: boolean;
  verified_surface_eligibility: "eligible" | "rebuild_required";
}

export type ManifestVersion = "v0" | "v1" | "v2";
export type DslSchemaVersion = "1.0" | "1.1" | "1.2";
export type DataLabel = "SYNTHETIC" | "USER_UPLOADED" | "LICENSED_PROVIDER";
export type BatteryProfile = "battery-v1" | "battery-v2";

export interface EvidenceIdentity {
  run_id: string;
  manifest_id: string;
  manifest_version: ManifestVersion;
  manifest_sha256: string;
  ledger_index_sha256: string;
  spec_hash: string;
  spec_version: number;
  dsl_schema_version: DslSchemaVersion;
  snapshot_id: string;
  snapshot_sha256: string;
  engine_semver: string;
  image_digest: string;
  battery_config_hash: string;
  /** Present on battery-v2 identities; v1 evidence omits it. */
  battery_profile?: BatteryProfile;
  result_hash: string;
  created_at: string;
  confirmation_receipt_hash: string;
  data_label: DataLabel;
  dataset_id?: string;
  dataset_manifest_sha256?: string;
  source_sha256?: string;
  symbol?: string;
  coverage?: { start: string; end: string };
  timezone?: string;
  price_adjustment?: string;
  row_count?: number;
}

/** The exact sealed receipt the user confirmed at acceptance time (P1-3). */
export interface ConfirmationReceipt {
  receipt_id: string | null;
  restatement: string;
  restatement_hash: string;
  spec_hash: string;
  issued_at: string | null;
  /** Battery v2 binds the confirmation to the sealed validation profile. */
  battery_profile?: BatteryProfile;
  battery_profile_hash?: string;
}

/** Publication is separate from evidence availability (P1-4). */
export interface PublicationStatus {
  status: "published" | "pending" | "failed" | string;
  note?: string;
  error?: string;
}

export interface MetricSet {
  start_date?: string;
  end_date?: string;
  n_bars: number;
  initial_capital?: number;
  n_return_observations?: number;
  total_return?: number;
  cagr?: number;
  ann_vol?: number;
  sharpe?: number;
  max_drawdown?: number;
  n_trades?: number;
  total_costs?: number;
  exposure?: number;
  final_equity?: number;
  formulas?: Record<string, string>;
  note?: string;
}

export interface EquitySeries {
  date: string[];
  equity: number[];
  position?: number[];
}

export interface SegmentResult {
  strategy_metrics: MetricSet;
  comparison_strategy_metrics: MetricSet;
  benchmark_metrics: MetricSet;
  benchmark_symbol: string;
  comparison_start: string | null;
  equity_series: EquitySeries;
  benchmark_series: { date: string[]; equity: number[] };
  trades: unknown[];
  benchmark_entry: Record<string, unknown> | null;
}

export interface SensitivityCell {
  ma_days: number;
  sharpe?: number;
  total_return?: number;
  max_drawdown?: number;
  n_trades?: number;
  skipped?: string;
}

export interface CostStressRow {
  multiplier: number;
  is: { total_return: number | null; sharpe: number | null; total_costs: number | null };
  oos: { total_return: number | null; sharpe: number | null; total_costs: number | null };
  reused_primary_evaluation?: boolean;
}

export interface FalsificationFinding {
  id: string;
  status: CheckStatus;
  status_label: CheckStatus;
  status_css: string;
  status_icon: string;
  rule: string;
  summary: string;
  evidence: Record<string, unknown>;
}

export interface EvidenceViewV1 {
  evidence_view_version: "v1";
  evidence_semantics_version: "v1";
  run_status?: string;
  publication?: PublicationStatus;
  artifact_contract: ArtifactContractDescriptor;
  identity: EvidenceIdentity;
  confirmation: ConfirmationReceipt;
  artifacts: ArtifactRef[];
  assumptions: {
    spec: StrategySpec;
    restatement: string;
    execution: { frequency: string; convention: string; benchmark_rule: string };
  };
  status: {
    battery_status: BatteryStatus;
    evidence_complete: boolean;
    checks: { id: string; status: CheckStatus }[];
  };
  segments: {
    is: { start: string; end: string; bars: number; evaluation?: unknown };
    oos: { start: string; end: string; bars: number; evaluation?: unknown };
  };
  results: { is: SegmentResult; oos: SegmentResult };
  oos_execution_audit: {
    count: number;
    primary_evaluation_count: 1;
    cost_stress_execution_count: number;
    count_semantics: string;
    base_1x_reused_for_cost_stress: boolean;
    records: unknown[];
  };
  cost_stress: {
    multipliers: number[];
    rows: CostStressRow[];
    base_costs_bps: { commission_bps: number; slippage_bps: number };
    required_2x_present: boolean;
    note: string;
  };
  sensitivity: {
    basis: "in_sample_only";
    metric: string;
    grid: SensitivityCell[];
    chosen_ma_days: number;
    chosen_cell: SensitivityCell | null;
    chosen_percentile_in_grid: number | null;
    neighbors: SensitivityCell[];
    note: string;
  };
  falsification: {
    non_suppressible: true;
    battery_version: string;
    checks_run: string[];
    required_checks: string[];
    findings: FalsificationFinding[];
    any_failing: boolean;
    any_inconclusive: boolean;
    status: BatteryStatus;
    completeness: {
      all_required_reported: boolean;
      all_checks_conclusive: boolean;
      unavailable_checks: string[];
      evidence_complete: boolean;
    };
  };
  data_gaps: Record<string, unknown>;
  snapshot: Record<string, unknown>;
}

/* ------------------------------------------------------------------ Battery v2 */

/** Battery-v2 segment results carry an explicit completion status; an INCONCLUSIVE
 * result contains empty series and no performance claims. */
export type V2ResultStatus = "COMPLETE" | "INCONCLUSIVE";

export interface FinalHoldoutExecutionBinding {
  capsule_id: string;
  confirmed_spec_hash: string;
  validation_plan_hash: string;
  locked_rule_sha256: string;
  base_costs_sha256: string;
  cost_multiplier: number;
}

export interface V2SegmentResult {
  status: V2ResultStatus;
  /** Present only when INCONCLUSIVE (why the segment produced no claims). */
  reason?: string;
  strategy_metrics: MetricSet;
  comparison_strategy_metrics: MetricSet;
  benchmark_metrics: MetricSet;
  benchmark_symbol: string;
  comparison_start?: string | null;
  equity_series: EquitySeries;
  benchmark_series: { date: string[]; equity: number[] };
  trades: unknown[];
  benchmark_entry: Record<string, unknown> | null;
  /** Present on a COMPLETE final-holdout result: binds the single execution to the
   * locked spec, sealed plan, and base costs. */
  execution_binding?: FinalHoldoutExecutionBinding;
}

export interface WalkForwardFold {
  fold_id?: number | string;
  train_start_index?: number;
  train_end_index?: number;
  test_start_index: number;
  test_end_index: number;
  test_bars?: number;
  visible_prefix_end_index?: number;
  visible_prefix_sha256?: string;
  locked_rule_sha256?: string;
  cost_multiplier?: number;
  strategy_metrics?: MetricSet;
  benchmark_metrics?: MetricSet;
}

export interface WalkForwardSummary {
  mode: "expanding-fixed-rule";
  parameter_selection: "forbidden";
  status: CheckStatus;
  fold_count: number;
  folds: WalkForwardFold[];
  locked_rule_sha256?: string;
  cost_multiplier?: number;
  median_fold_sharpe?: number | null;
  positive_fold_ratio?: number | null;
  worst_fold_return?: number | null;
  fold_return_dispersion?: number | null;
  stitched_development_total_return?: number | null;
}

export interface RegimeStateResult {
  /** Server-law regime key, e.g. "up_low" | "up_high" | "down_low" | "down_high". */
  regime: string;
  status: CheckStatus;
  observations: number;
  strategy_compounded_return: number | null;
  benchmark_compounded_return: number | null;
  mean_daily_excess_return: number | null;
  exposure: number | null;
  trade_count: number;
  max_drawdown: number | null;
  note?: string;
}

export interface RegimeAnalysis {
  analysis_version: string;
  status: CheckStatus;
  states: RegimeStateResult[];
  coverage: {
    development_observations: number;
    classified_observations: number;
    unclassified_warmup_observations: number;
    state_observations_sum: number;
  };
  law?: {
    trend?: string;
    volatility?: string;
    states?: string[];
    minimum_observations?: number;
  };
}

export interface V2CostStressRow {
  multiplier: number;
  development: {
    total_return: number | null;
    sharpe: number | null;
    total_costs: number | null;
  };
}

export interface V2CostStress {
  basis: "development_walk_forward_only";
  status: CheckStatus;
  multipliers: number[];
  rows: V2CostStressRow[];
  base_costs_bps?: { commission_bps: number; slippage_bps: number };
  required_2x_present: boolean;
  note?: string;
}

/** Battery v2 performs no parameter search: the grid is always empty by law. */
export interface V2Sensitivity {
  basis: "locked_rule_only";
  status: "NOT_RUN";
  grid: SensitivityCell[];
  parameter_selection: "forbidden";
  locked_rule_sha256: string;
  note?: string;
}

export interface ValidationPlanV2 {
  profile_id: "battery-v2";
  profile_hash: string;
  plan_version: string;
  n_bars: number;
  development_bars: number;
  final_holdout_bars: number;
  final_holdout_fraction: number;
  max_indicator_lookback: number;
  minimum_train_bars: number;
  test_window_bars: number;
  minimum_short_fold_bars: number;
  final_warmup_bars: number;
  walk_forward_mode: string;
  parameter_selection: "forbidden";
  regime_law: {
    trend: string;
    volatility: string;
    states: string[];
    minimum_observations: number;
  };
  access_policy: {
    development_battery: string;
    final_evaluator: string;
    explanation_agent: string;
  };
  validation_plan_hash: string;
}

export interface FinalHoldoutExecutionAudit {
  audit_version: string;
  state: string;
  primary_evaluation_count: 0 | 1;
  counterfactual_evaluation_count: 0;
  recovered_result: boolean;
  capsule_id?: string;
  validation_plan_hash?: string;
  confirmed_spec_hash?: string;
}

export interface TemporalIntegrityReceipt {
  receipt_version: string;
  battery_plan_sha256: string;
  spec_hash: string;
  snapshot_sha256: string;
  development_input_sha256: string;
  final_holdout_input_sha256: string;
  boundaries: {
    development: { start_index: number; end_index: number; bars: number };
    final_holdout: {
      start_index: number;
      end_index: number;
      bars: number;
      warmup_start_index: number;
      warmup_bars: number;
    };
  };
  walk_forward: {
    mode: string;
    folds: WalkForwardFold[];
    laws: Record<string, unknown>;
  };
  executions: {
    final_holdout_primary_count: number;
    final_holdout_counterfactual_count: number;
  };
  access_policy: {
    development_battery: string;
    final_evaluator: string;
    explanation_agent: string;
  };
}

export interface PartitionSegment {
  start?: string;
  end?: string;
  bars?: number;
  start_index?: number;
  end_index?: number;
  input_sha256?: string;
  evaluation_input_sha256?: string;
  warmup_start_index?: number;
  warmup_bars?: number;
  evaluation?: { start?: string; end?: string; bars?: number };
}

export interface V2Partitions {
  development: PartitionSegment;
  final_holdout: PartitionSegment;
  folds: WalkForwardFold[];
  reason?: string | null;
  laws?: Record<string, unknown>;
}

export interface DataProvenance {
  data_label: string;
  snapshot_id?: string;
  snapshot_sha256?: string;
  dataset_id?: string;
  dataset_manifest_sha256?: string;
  coverage?: { start?: string; end?: string };
  row_count?: number;
  adjustment_mode?: string;
  price_adjustment?: string;
  provider?: string;
  notice?: string;
}

/** Development-only projection sealed for the research agent boundary. No dates,
 * hashes, artifact ids, or final-holdout values cross this boundary by law. */
export interface AgentProjection {
  projection_version: string;
  scope: "development_only";
  development_metrics: Partial<Record<
    "total_return" | "cagr" | "ann_vol" | "sharpe" | "max_drawdown"
    | "n_trades" | "total_costs" | "exposure",
    number | null
  >>;
  walk_forward: {
    fold_count: number | null;
    median_fold_sharpe: number | null;
    positive_fold_ratio: number | null;
    worst_fold_return: number | null;
    fold_return_dispersion: number | null;
  };
  regimes: Array<Pick<
    RegimeStateResult,
    "regime" | "status" | "observations" | "strategy_compounded_return"
    | "benchmark_compounded_return" | "mean_daily_excess_return" | "exposure"
    | "trade_count"
  >>;
  checks: { id: string; status: CheckStatus }[];
}

export interface EvidenceViewV2 {
  evidence_view_version: "v2";
  evidence_semantics_version: "v2";
  run_status?: string;
  publication?: PublicationStatus;
  artifact_contract: ArtifactContractDescriptor;
  identity: EvidenceIdentity;
  data_provenance: DataProvenance;
  confirmation: ConfirmationReceipt;
  artifacts: ArtifactRef[];
  /** v2 assumptions intentionally carry no v1 execution block. */
  assumptions: { spec: StrategySpec; restatement: string };
  status: {
    battery_status: BatteryStatus;
    evidence_complete: boolean;
    checks: { id: string; status: CheckStatus }[];
  };
  validation_plan: ValidationPlanV2;
  partitions: V2Partitions;
  /** Compatibility aliases: is = development, oos = final holdout. */
  segments: {
    is: PartitionSegment;
    oos: PartitionSegment;
  };
  results: { is: V2SegmentResult; oos: V2SegmentResult };
  development_result: V2SegmentResult;
  final_holdout_result: V2SegmentResult;
  walk_forward: WalkForwardSummary;
  regime_analysis: RegimeAnalysis;
  /** Both names refer to the same single-execution audit record. */
  oos_execution_audit: FinalHoldoutExecutionAudit;
  final_holdout_execution_audit: FinalHoldoutExecutionAudit;
  cost_stress: V2CostStress;
  sensitivity: V2Sensitivity;
  falsification: EvidenceViewV1["falsification"];
  temporal_integrity: TemporalIntegrityReceipt;
  data_gaps: Record<string, unknown>;
  snapshot: Record<string, unknown>;
  agent_projection: AgentProjection;
}

/** The complete evidence contract: discriminate on ``evidence_view_version``.
 *
 * Closed over v1 | v2 | v3 (Gate E Stop E, contract 27 §10). The v3 member is
 * the sealed contract-state shape below: it carries identities, bindings and
 * the recorded validation receipt, never a financial claim of its own, and
 * every unknown version renders a typed unsupported state. Whether any run is
 * ever produced under the v3 contract remains the later activation decision.
 */
export type EvidenceView = EvidenceViewV1 | EvidenceViewV2 | EvidenceViewV3;

/** Fail-closed body returned with HTTP 409 when current evidence may not be shown. */
export interface CurrentEvidenceUnavailable {
  code: "EVIDENCE_NOT_AVAILABLE" | "EVIDENCE_INTEGRITY_FAILURE";
  run_id: string;
  run_status: string;
  battery_status: NotRunStatus;
  message: string;
  detail?: string;
}

/**
 * A preserved checkpoint created before the exact-confirmation receipt contract.
 *
 * It is not a battery result and therefore intentionally has no ``battery_status``.
 * The only honest transition is a fresh run from the saved accepted spec.
 */
export interface LegacyCheckpointRebuildRequired {
  code: "LEGACY_CHECKPOINT_REBUILD_REQUIRED";
  run_id: string;
  message: string;
  rebuild: {
    available: boolean;
    source: "saved_accepted_spec";
  };
}

export interface ArtifactContractRebuildRequired {
  code: "ARTIFACT_CONTRACT_REBUILD_REQUIRED";
  run_id: string;
  message: string;
  rebuild: {
    available: boolean;
    source: "saved_accepted_spec";
  };
}

export type EvidenceUnavailable =
  | CurrentEvidenceUnavailable
  | LegacyCheckpointRebuildRequired
  | ArtifactContractRebuildRequired;

/**
 * Read-only, evidence-bound explanation returned only after the API has integrity-checked the
 * complete sealed checkpoint. The model/provider may choose a closed plan in a future
 * gate; all prose, numerals, units, and citations are still rendered by QuantLens.
 */
export interface ExplanationGenerationMetadata {
  ai_used: boolean;
  /** True only if a provider response influenced the rendered explanation. */
  ai_influenced_output: boolean;
  /** Provider invocation and data transmission are separate auditable events. */
  provider_invoked: boolean;
  provider_data_transmitted: boolean;
  provider: string;
  model: string | null;
  request_id: string | null;
  finish_reason: string | null;
  fallback_used: boolean;
  fallback_code: string | null;
  policy_version: string;
}

export interface ExplanationBinding {
  opaque_evidence_binding: string;
  run_id: string;
  evidence_view_version: "v1";
  evidence_semantics_version: "v1";
  catalog_version: "NarrativeFactCatalogV1";
  catalog_sha256: string;
  result_hash: string;
  manifest_sha256: string;
  ledger_index_sha256: string;
}

export type ExplanationContextValue =
  | string | number | boolean | null
  | ExplanationContextValue[]
  | { [key: string]: ExplanationContextValue };

export interface ExplanationCitation {
  fact_id: string;
  value: number | string;
  formatted_value: string;
  unit: string;
  context: Record<string, ExplanationContextValue>;
  artifact_id: string;
  artifact_sha256: string;
  json_pointer: string;
}

export interface ExplanationBlock {
  template_id: string;
  comparator: string;
  fact_ids: string[];
  text: string;
  citations: ExplanationCitation[];
}

export interface EvidenceExplanation {
  title: string;
  format: "plain_text_blocks_v1";
  blocks: ExplanationBlock[];
  disclosure: string;
}

export interface ExplanationViewV1 {
  explanation_view_version: "v1";
  narrative_plan_version: "NarrativePlanV1";
  status: "completed" | "unavailable";
  generation: ExplanationGenerationMetadata;
  binding: ExplanationBinding | null;
  explanation: EvidenceExplanation | null;
}

/* ------------------------------------------------------- Gate E v3 contract shape */
/*
 * Sealed v3 data contract (docs/planning/27 §11 Stop A shape; §10 Stop E closure).
 * The closed EvidenceViewV3 shape and its guards were introduced dormant in Stop A;
 * Stop E closed the `EvidenceView` union over v1 | v2 | v3 so every surface handles
 * the version explicitly and unknown versions render a typed unsupported state.
 * The shape itself is unchanged and still carries no financial claim: it presents
 * sealed identities, bindings and the recorded validation receipt. Whether any run
 * is produced under this contract remains the single later activation transaction
 * owned by the Gate E acceptance, not by these types.
 */

/** The exact frozen Gate E active tuple (contract 27 §2), one key per identifier. */
export const EVIDENCE_V3_ACTIVE_TUPLE = {
  activation_release: "quantlens-financial-v3",
  presentation_contract: "corrected-financial-semantics-v3-ledger-v1",
  worker_runtime: "quantlens-worker-v3",
  engine_semver: "0.2.0",
  battery_profile_id: "battery-v3",
  battery_payload_version: "battery-v3",
  validation_plan_version: "validation-plan-v3",
  manifest_version: "v3",
  dsl_schema_version: "1.2",
  market_observations_version: "market-observations-v2",
  ledger_semantics_version: "ledger-v1",
  execution_semantics_version: "financial-semantics-v2",
  execution_cost_model: "adverse_effective_fill_price",
  continuous_path_version: "continuous-development-path-v1",
  valuation_ledger_version: "valuation-ledger-v1",
  financial_contract_version: "financial-contract-v1",
  execution_implementation: "adverse-effective-fill-v1",
  validator_version: "financial-semantic-validator-v1",
  metric_semantics_version: "metrics-v2",
  evidence_view_version: "v3",
  evidence_semantics_version: "v3",
  semantic_receipt_version: "semantic-validation-receipt-v1",
  plan_anchor_version: "validation-plan-anchor-v1",
  holdout_access_protocol: "final-holdout-access-v1",
  artifact_producer: "quantlens-engine/0.2.0+battery-v3",
} as const;

export type EvidenceV3ActiveTuple = typeof EVIDENCE_V3_ACTIVE_TUPLE;

/** Sealed identity core carried forward from manifest-v3 (legacy field grammar). */
export interface EvidenceV3Identity {
  manifest_id: string;
  spec_hash: string;
  spec_version: number;
  snapshot_id: string;
  snapshot_sha256: string;
  image_digest: string;
  battery_config_hash: string;
  result_hash: string;
  created_at: string;
  confirmation_receipt_hash: string;
  data_label: DataLabel;
}

/** Direct manifest-v3 payload bindings (contract 27 §4.1); every hash is mandatory. */
export interface EvidenceV3Bindings {
  plan_anchor_sha256: string;
  financial_contract_sha256: string;
  ledger_id: string;
  semantic_receipt_sha256: string;
  temporal_integrity_sha256: string;
  final_holdout_execution_audit_sha256: string;
}

/** Mirrors packages/strategy-schema/schema/semantic-validation-receipt-v1.json. */
export interface SemanticValidationReceiptV1 {
  validator_version: "financial-semantic-validator-v1";
  ledger_id: string;
  result_hash: string;
  financial_contract_sha256: string;
  validated_execution_ids: string[];
  status: "PASS";
}

/** Closed v3 evidence shape; a member of `EvidenceView` since Stop E. */
export interface EvidenceViewV3 {
  evidence_view_version: "v3";
  evidence_semantics_version: "v3";
  active_tuple: EvidenceV3ActiveTuple;
  identity: EvidenceV3Identity;
  bindings: EvidenceV3Bindings;
  semantic_receipt: SemanticValidationReceiptV1;
}

const V3_TUPLE_KEYS = Object.keys(
  EVIDENCE_V3_ACTIVE_TUPLE,
) as readonly (keyof EvidenceV3ActiveTuple)[];
const V3_VIEW_KEYS = [
  "evidence_view_version", "evidence_semantics_version", "active_tuple",
  "identity", "bindings", "semantic_receipt",
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
/** Manifest-v3 source branches cross-bind the label to the snapshot identity. */
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

/** Closed-record check: exactly the given keys, no extras, no array/null impostors. */
function isClosedRecord(
  value: unknown, keys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => own.includes(key));
}

export function isEvidenceV3ActiveTuple(value: unknown): value is EvidenceV3ActiveTuple {
  if (!isClosedRecord(value, V3_TUPLE_KEYS)) {
    return false;
  }
  return V3_TUPLE_KEYS.every(
    (key) => value[key] === EVIDENCE_V3_ACTIVE_TUPLE[key],
  );
}

function isEvidenceV3Identity(value: unknown): value is EvidenceV3Identity {
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
    && snapshotIdentityMatchesLabel(value.data_label as DataLabel, value.snapshot_id)
  );
}

function isEvidenceV3Bindings(value: unknown): value is EvidenceV3Bindings {
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

function isSemanticValidationReceiptV1(
  value: unknown,
): value is SemanticValidationReceiptV1 {
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
    && ids.every((id) => typeof id === "string" && EXECUTION_ID_RE.test(id))
    && new Set(ids).size === ids.length
  );
}

/**
 * Fail-closed guard for the dormant v3 shape: unknown keys, missing keys, a mutated
 * tuple constant, a malformed hash, a label/snapshot mismatch, or a cross-wired
 * ledger/receipt binding all fail.
 *
 * This guard is STRUCTURAL only. It cannot recompute `semantic_receipt_sha256` (or any
 * canonical payload hash) from the embedded receipt, so passing it never means the
 * evidence was independently validated — that resolution is server-owned and must be
 * carried separately (see apps/web evidenceV3Contract).
 */
export function isEvidenceViewV3(value: unknown): value is EvidenceViewV3 {
  if (!isClosedRecord(value, V3_VIEW_KEYS)) {
    return false;
  }
  if (
    value.evidence_view_version !== "v3"
    || value.evidence_semantics_version !== "v3"
    || !isEvidenceV3ActiveTuple(value.active_tuple)
    || !isEvidenceV3Identity(value.identity)
    || !isEvidenceV3Bindings(value.bindings)
    || !isSemanticValidationReceiptV1(value.semantic_receipt)
  ) {
    return false;
  }
  const identity = value.identity as unknown as EvidenceV3Identity;
  const bindings = value.bindings as unknown as EvidenceV3Bindings;
  const receipt = value.semantic_receipt as unknown as SemanticValidationReceiptV1;
  return (
    receipt.ledger_id === bindings.ledger_id
    && receipt.result_hash === identity.result_hash
    && receipt.financial_contract_sha256 === bindings.financial_contract_sha256
  );
}
