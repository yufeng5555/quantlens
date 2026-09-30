/**
 * TypeScript mirror of the Strategy DSL v1.0 (packages/strategy-schema/schema/strategy-v1.json).
 * The JSON Schema is the single source of truth; the API validates every spec server-side.
 * Generated-types tooling is deferred with S5 CI work — this file is hand-maintained and
 * checked against the schema by tests/properties/test_ts_types_sync.py.
 */

export type DslVersion = "1.0" | "1.1" | "1.2";
export type Family = "ma_long_flat"; // rotation / fixed_weights are reserved, deferred, and scope-rejected
export type RuleType = "price_vs_ma" | "ma_crossover";

export interface StrategySpec {
  dsl_version: DslVersion;
  meta: { name: string };
  universe: { symbol: string };
  family: Family;
  rule: {
    type: RuleType;
    fast_ma_days: number | null; // ma_crossover only
    ma_days: number; // MA window (price_vs_ma) or slow window (ma_crossover)
  };
  calendar: { frequency: "daily"; execution: "next_open" };
  costs: { commission_bps: number; slippage_bps: number };
  benchmark: { type: "hold_from_first_decision"; symbol: string };
  data: {
    snapshot_policy: "pinned";
    source?: {
      kind: "user_provided";
      dataset_id: string;
      dataset_manifest_sha256: string;
    } | {
      kind: "licensed_provider";
      dataset_id: string;
      dataset_manifest_sha256: string;
    };
    range: { start: string; end: string };
  };
  validation: {
    is_oos_split: { oos_fraction: number };
    sensitivity: { grid: { ma_days: number[] } };
    cost_stress: { multipliers: number[] };
  };
}

export interface ValidationErrorItem {
  layer: "schema" | "lint" | "scope";
  json_path?: string;
  constraint?: string;
  rule_id?: string;
  code?: string;
  message: string;
  suggestion?: string;
  supported_scope?: string;
  correction?: { template: StrategySpec | null; notify_option: string };
}

export type ParseStatus = "draft" | "ambiguous" | "unsupported" | "advice_deflection";

export interface ParseGenerationMetadata {
  /** False in Gate 6A: the installed provider is disabled and the deterministic parser ran. */
  ai_used: boolean;
  provider: string;
  model: string | null;
  request_id: string | null;
  finish_reason: string | null;
  usage: { input_tokens: number; output_tokens: number } | null;
  fallback_used: boolean;
  fallback_code: string | null;
  policy_version: string;
}

export interface ClarifyQuestion {
  field: string; // spec path the answer feeds
  question: string;
  kind: "symbol" | "rule" | "windows" | "date_range" | "costs";
  material: boolean; // material fields block compute until answered (AT-1.3)
  default?: unknown; // shown transparently; accepting it is an explicit user action
  options?: string[];
}

export interface ParseResponse {
  parser: string; // labels the actual deterministic/provider path
  contract_version: string;
  generation: ParseGenerationMetadata;
  status: ParseStatus;
  category?: string; // deflection / unsupported category (logged)
  message?: string;
  supported_scope?: string;
  draft?: StrategySpec;
  default_fields?: string[]; // fields carrying transparent defaults
  questions?: ClarifyQuestion[];
  /** Fields the deterministic parser recognized with certainty while other material
   * fields remain unresolved. This is not a runnable spec and contains no defaults. */
  recognized_fields?: {
    symbol?: string;
    rule_type?: RuleType;
    fast_ma_days?: number;
    ma_days?: number;
  };
  correction?: { template: StrategySpec | null; notify_option: string };
}

export type RunStatus =
  | "queued"
  | "snapshot_pinned"
  | "running_engine"
  | "running_battery"
  | "ledger_sealed"
  | "report_rendered"
  | "published"
  | "validation_failed"
  | "data_quality_failed"
  | "system_failed";
