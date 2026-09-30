/**
 * Frozen Gate 7A.1 wire shapes for the Experiment workspace (contract 13 §5.4).
 * Everything here is mutable private workspace context — titles, descriptions,
 * tags, and note indicators — never sealed research evidence, and never a
 * financial value. The frontend renders these fields verbatim and computes no
 * metric, delta, ranking, or recommendation from them.
 */

export interface ResponseTag {
  display_tag: string;
  normalized_tag: string;
}

export interface ExperimentSummary {
  family_id: string;
  title: string;
  description: string;
  revision: number;
  /** Non-null in every accepted row: a summary whose mode is missing or does
   * not match the requested view is rejected client-side (fail closed). */
  research_mode: "formal" | "sandbox";
  baseline_run_id: string | null;
  visible_run_count: number;
  has_notes: boolean;
  tags: ResponseTag[];
  created_at: string;
  updated_at: string;
}

export interface ExperimentsPageResponse {
  experiments: ExperimentSummary[];
  has_more: boolean;
  next_cursor: string | null;
}

/** One server-computed semantic diff entry. `before`/`after` are reviewed JSON
 * leaf values (scalars or arrays; a missing side uses the server's exact
 * `{"__missing__":true}` marker) and are only ever shown as serialized text. */
export interface ChangedAssumption {
  path: string;
  label: string;
  before: unknown;
  after: unknown;
}

export interface FamilyMemberVisible {
  run_id: string;
  removed: false;
  parent_run_id: string | null;
  relationship: "baseline" | "variation" | "rerun";
  spec_hash: string;
  status: string;
  research_mode: "formal" | "sandbox";
  archived_at: string | null;
  created_at: string;
  diff_contract_version: string;
  changed_assumptions: ChangedAssumption[];
  changed_assumptions_sha256: string;
  annotation_revision: number;
  has_note: boolean;
  tags: ResponseTag[];
}

/** A deleted parent still referenced by a visible child renders only as a
 * tombstone: run ID and nothing else — missing metadata is never invented. */
export interface FamilyMemberTombstone {
  run_id: string;
  removed: true;
}

export type FamilyMember = FamilyMemberVisible | FamilyMemberTombstone;

export interface ExperimentDetailResponse {
  experiment: ExperimentSummary;
  members: FamilyMember[];
}

export interface AnnotationView {
  note: string;
  tags: ResponseTag[];
  revision: number;
  updated_at: string | null;
}

/** `GET /runs/{id}/workspace-metadata` — the ONLY route that carries a private
 * note body, and it is fetched exclusively by the explicitly opened editor. */
export interface WorkspaceMetadataResponse {
  run_id: string;
  family: {
    family_id: string;
    title: string;
    description: string;
    revision: number;
  } | null;
  lineage: unknown;
  annotation: AnnotationView;
}

export const RELATIONSHIP_LABELS: Record<
  FamilyMemberVisible["relationship"], string
> = {
  baseline: "Baseline",
  variation: "Variation",
  rerun: "Rerun",
};

/** Serialize a changed-assumption leaf as plain text. JSON escaping plus React's
 * default text rendering means the value can never become markup. */
export function assumptionValueText(value: unknown): string {
  return JSON.stringify(value) ?? "null";
}

export const WORKSPACE_CONTEXT_DISCLOSURE =
  "Titles, descriptions, tags, and notes are private workspace context — not "
  + "sealed research evidence.";

export const FAMILY_TITLE_MAX = 120;
export const FAMILY_DESCRIPTION_MAX = 2000;
export const NOTE_MAX = 8000;
export const TAGS_MAX = 10;
export const TAG_MAX_CODE_POINTS = 32;

/** API text limits count Unicode code points, not UTF-16 units. */
export function codePointLength(value: string): number {
  return [...value].length;
}

/** Keep client-side text limits aligned with the API's Unicode-code-point
 * contract. Native HTML maxLength counts UTF-16 units and would otherwise
 * reject valid astral characters (for example emoji) at roughly half the
 * documented capacity. */
export function truncateCodePoints(value: string, maximum: number): string {
  const points = [...value];
  return points.length <= maximum ? value : points.slice(0, maximum).join("");
}

/** App Router dynamic params arrive percent-encoded; identifiers must be
 * decoded before use (and re-encoded with encodeURIComponent for every
 * request/href). A malformed escape falls back to the raw segment. */
export function decodeRouteParam(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Client mirror of the server tag pipeline: NFKC, trim, then a case-folded
 * identity. The server stays the authority; this only prevents the obvious
 * duplicate/oversize submissions before a round trip. */
export function normalizedTagIdentity(raw: string): string {
  return raw.normalize("NFKC").trim().toLowerCase();
}

/** Reject any experiment row that does not match the requested view exactly. */
export function summaryMatchesMode(
  summary: ExperimentSummary | null | undefined,
  mode: "formal" | "sandbox",
): boolean {
  return typeof summary?.family_id === "string"
    && summary.family_id !== ""
    && summary.research_mode === mode;
}

/** Fail-closed identity check for the family detail response: the payload must
 * name the exact requested family, carry a valid mode, and every visible
 * member must share that mode. */
export function detailMatchesFamily(
  body: ExperimentDetailResponse | null | undefined,
  familyId: string,
): boolean {
  if (!body?.experiment || body.experiment.family_id !== familyId) return false;
  if (!Array.isArray(body.members)) return false;
  const mode = body.experiment.research_mode;
  if (mode !== "formal" && mode !== "sandbox") return false;
  return (body.members ?? []).every(
    (member) => member.removed || member.research_mode === mode);
}
