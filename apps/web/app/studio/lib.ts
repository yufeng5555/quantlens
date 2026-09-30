import type { StrategySpec } from "@schema/ts/types";
import { ApiRequestError } from "../lib/errors";

export interface ApiOptions {
  /** Non-2xx statuses whose bodies are part of the caller's contract (e.g. a 404
   * poll or a 409 refusal body). Every other non-2xx response THROWS an
   * ApiRequestError built from the structured error detail — success handlers can
   * never run against an error payload. */
  allowStatuses?: number[];
  /** Extra non-sensitive request headers (e.g. `Idempotency-Key`). The JSON
   * `Content-Type` contract is owned by this module; a caller-supplied
   * content-type entry is ignored rather than honored. */
  headers?: Record<string, string>;
  /** Cancellation handle so a caller can invalidate an in-flight request (stale
   * duplicate-source loads, superseded Compare selections). */
  signal?: AbortSignal;
}

async function apiRequest<T>(
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body: unknown,
  options: ApiOptions,
): Promise<{ status: number; body: T }> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    if (name.toLowerCase() !== "content-type") headers[name] = value;
  }
  const init: RequestInit = { method, headers, signal: options.signal };
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(`/api/ql${path}`, init);
  } catch (caught) {
    // A caller-driven abort is cancellation, not a network failure; rethrow it
    // unchanged so completion guards can tell the two apart.
    if (options.signal?.aborted) throw caught;
    throw new Error("NETWORK");
  }
  return { status: res.status, body: await parseResponse<T>(res, options) };
}

export async function apiPost<T>(
  path: string, body: unknown, options: ApiOptions = {},
): Promise<{ status: number; body: T }> {
  return apiRequest<T>("POST", path, body, options);
}

export async function apiPut<T>(
  path: string, body: unknown, options: ApiOptions = {},
): Promise<{ status: number; body: T }> {
  return apiRequest<T>("PUT", path, body, options);
}

export async function apiPatch<T>(
  path: string, body: unknown, options: ApiOptions = {},
): Promise<{ status: number; body: T }> {
  return apiRequest<T>("PATCH", path, body, options);
}

export async function apiGet<T>(
  path: string, options: ApiOptions = {},
): Promise<{ status: number; body: T }> {
  return apiRequest<T>("GET", path, undefined, options);
}

export async function apiDelete<T>(
  path: string, options: ApiOptions = {},
): Promise<{ status: number; body: T }> {
  return apiRequest<T>("DELETE", path, undefined, options);
}

async function parseResponse<T>(res: Response, options: ApiOptions): Promise<T> {
  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ApiRequestError({ status: res.status });
    }
  }
  if (!res.ok && !(options.allowStatuses ?? []).includes(res.status)) {
    throw apiErrorFrom(res.status, parsed);
  }
  if (parsed === null) {
    throw new ApiRequestError({ status: res.status });
  }
  return parsed as T;
}

/** Extract a structured error (code + user-written message) from an API body. */
export function apiErrorFrom(status: number, body: unknown): ApiRequestError {
  const detail = body && typeof body === "object" && "detail" in body
    ? (body as { detail?: unknown }).detail
    : body;
  if (detail && typeof detail === "object") {
    const record = detail as { code?: unknown; message?: unknown };
    return new ApiRequestError({
      status,
      code: typeof record.code === "string" ? record.code : undefined,
      detailMessage: typeof record.message === "string" ? record.message : undefined,
    });
  }
  return new ApiRequestError({ status });
}

export function logEvent(type: string, payload: Record<string, unknown>) {
  void apiPost("/events", { type, payload }).catch(() => {});
}

/** Mirror of quantlens_schema.default_spec — the server re-validates every spec, so the
 * Python schema package remains the single authority (AT-1.5: edits win server-side). */
export function defaultSpec(symbol: string): StrategySpec {
  return {
    dsl_version: "1.0",
    meta: { name: `${symbol} trend filter` },
    universe: { symbol },
    family: "ma_long_flat",
    rule: { type: "price_vs_ma", fast_ma_days: null, ma_days: 200 },
    calendar: { frequency: "daily", execution: "next_open" },
    costs: { commission_bps: 1, slippage_bps: 5 },
    benchmark: { type: "hold_from_first_decision", symbol: "same_as_universe" },
    data: { snapshot_policy: "pinned", range: { start: "2005-01-01", end: "2024-12-31" } },
    validation: {
      is_oos_split: { oos_fraction: 0.3 },
      sensitivity: { grid: { ma_days: [100, 150, 200, 250] } },
      cost_stress: { multipliers: [0, 1, 2, 4] },
    },
  };
}

export function ensureGridContainsChosen(spec: StrategySpec): StrategySpec {
  const grid = spec.validation.sensitivity.grid.ma_days;
  if (!grid.includes(spec.rule.ma_days)) {
    return {
      ...spec,
      validation: {
        ...spec.validation,
        sensitivity: { grid: { ma_days: [...grid, spec.rule.ma_days].sort((a, b) => a - b) } },
      },
    };
  }
  return spec;
}

export type LineageRelationship = "variation" | "rerun";

/** The exact reviewed bindings an Idempotency-Key is issued for — a client mirror
 * of the server's canonical idempotent-create request (contract 13 §5.2). The same
 * fingerprint means a retry after a lost response reuses its key; any material
 * change (source, spec, rigor, purpose, preflight, warnings, or relationship)
 * must mint a fresh key. */
export interface LineageIdempotencyBinding {
  parent_run_id: string;
  confirmed_parent_spec_hash: string;
  relationship: LineageRelationship;
  confirmed_spec_hash: string;
  research_mode: string;
  battery_profile: string;
  confirmed_battery_profile_hash: string | null;
  confirmed_preflight_hash: string;
  acknowledged_preflight_warning_ids: string[];
}

export function lineageBindingFingerprint(binding: LineageIdempotencyBinding): string {
  return JSON.stringify({
    parent_run_id: binding.parent_run_id,
    confirmed_parent_spec_hash: binding.confirmed_parent_spec_hash,
    relationship: binding.relationship,
    confirmed_spec_hash: binding.confirmed_spec_hash,
    research_mode: binding.research_mode,
    battery_profile: binding.battery_profile,
    confirmed_battery_profile_hash: binding.confirmed_battery_profile_hash,
    confirmed_preflight_hash: binding.confirmed_preflight_hash,
    acknowledged_preflight_warning_ids:
      [...new Set(binding.acknowledged_preflight_warning_ids)].sort(),
  });
}

/** Opaque Idempotency-Key inside the server charset `^[A-Za-z0-9._:-]{1,128}$`.
 * Random per reviewed binding: two deliberate identical studies must never share
 * a key, or the second would silently replay the first run. */
export function freshIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `ql-dup-${hex}`;
}

export { RUN_STAGES } from "../lib/labels";
