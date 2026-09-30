"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";

import { apiDelete, apiGet, apiPost } from "../studio/lib";
import { toSafeError, type SafeError } from "../lib/errors";
import { instantUTC } from "../lib/format";
import {
  TOTAL_RETURN_ADJUSTMENT,
  dataSourceLabel,
  instrumentDescriptor,
  isTerminalFailure,
  runOutcome,
  type BatteryStatus,
} from "../lib/labels";
import { RELATIONSHIP_LABELS, type ResponseTag } from "../experiments/lib";

interface RunSummary {
  run_id: string;
  title: string;
  symbol: string | null;
  data_source: "sample" | "user" | "bundled" | "licensed";
  status: string;
  created_at: string;
  updated_at: string;
  battery_status: BatteryStatus;
  battery_profile?: "battery-v1" | "battery-v2";
  evidence_view_version?: "v1" | "v2" | null;
  evidence_available: boolean;
  artifact_contract_id?: string | null;
  verified_financial_semantics?: boolean;
  failed_checks: number | null;
  research_mode: "formal" | "sandbox";
  management_state: "active" | "archived" | "deleted";
  archived_at: string | null;
  deleted_at: string | null;
  // Additive lineage-v1 workspace metadata (contract 13 §5.4). Tags and note
  // indicators are private workspace context; note bodies never appear here.
  family_id?: string | null;
  family_title?: string | null;
  relationship?: "baseline" | "variation" | "rerun" | null;
  tags?: ResponseTag[];
  has_note?: boolean;
  annotation_revision?: number;
}

type StatusFilter = "all" | "completed" | "active" | "attention";
type SourceFilter = "all" | "sample" | "user" | "bundled" | "licensed";
type WorkspaceTab = "formal" | "sandbox" | "archived";

/** Exact server query per workspace tab — sandbox rows never mix into formal. */
const TAB_QUERY: Record<WorkspaceTab, string> = {
  formal: "research_mode=formal&archived=false",
  sandbox: "research_mode=sandbox&archived=false",
  archived: "research_mode=all&archived=true",
};

const TAB_LABELS: Record<WorkspaceTab, string> = {
  formal: "Formal research",
  sandbox: "Sandbox tests",
  archived: "Archived",
};

/** Archive/restore/delete apply exactly to the server's manageable terminal set:
 * "published" plus the failure terminals. "report_rendered" is still finishing
 * publication and is NOT manageable — offering the action would only invite a
 * server refusal. */
function isManageableTerminal(run: RunSummary): boolean {
  return run.status === "published" || isTerminalFailure(run.status);
}

function statusBucket(run: RunSummary): Exclude<StatusFilter, "all"> {
  const lifecycleComplete = run.status === "published" || run.status === "report_rendered";
  // A terminal lifecycle token is not enough to call a library row completed:
  // the user-facing report must also have sealed evidence available to open.
  if (lifecycleComplete && !run.evidence_available) return "attention";
  if (lifecycleComplete) return "completed";
  if (isTerminalFailure(run.status)) return "attention";
  return "active";
}

/** Treat the server query as a requested boundary, not proof that every row
 * obeyed it. A mismatched sandbox row must never gain formal-only Compare
 * controls, and archived rows must never leak into an active library. */
function runMatchesWorkspaceTab(run: RunSummary, tab: WorkspaceTab): boolean {
  const validMode = run.research_mode === "formal"
    || run.research_mode === "sandbox";
  if (!validMode) return false;
  if (tab === "archived") {
    return run.management_state === "archived"
      && typeof run.archived_at === "string"
      && run.archived_at.trim().length > 0
      && run.deleted_at === null;
  }
  return run.research_mode === tab
    && run.management_state === "active"
    && run.archived_at === null
    && run.deleted_at === null;
}

export default function RunsIndex() {
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [error, setError] = useState<SafeError | null>(null);
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<WorkspaceTab>("formal");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  // Experiment/tag filters are built from the currently loaded tab rows only,
  // so they can never mix formal, sandbox, and archived rows.
  const [familyFilter, setFamilyFilter] = useState<string>("all");
  const [tagFilter, setTagFilter] = useState<string>("all");
  const [selected, setSelected] = useState<string[]>([]);
  const [selectionNotice, setSelectionNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<SafeError | null>(null);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<RunSummary | null>(null);
  // Monotonic load token: a slow response for a previously selected tab can never
  // overwrite the currently selected tab's rows or error state.
  const loadSeqRef = useRef(0);
  // The CURRENT tab, readable from async completions: a management action that
  // finishes after a tab switch must reload the tab the user is on now — never
  // the tab captured in the action's closure.
  const tabRef = useRef<WorkspaceTab>("formal");
  const tabButtonRefs = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => { tabRef.current = tab; }, [tab]);
  const deleteDialogRef = useRef<HTMLDivElement | null>(null);
  const deleteTriggerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!deleteCandidate) return;
    const dialog = deleteDialogRef.current;
    dialog?.querySelector<HTMLElement>("button")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDeleteCandidate(null);
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(
        dialog.querySelectorAll<HTMLElement>("button:not([disabled])"));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      deleteTriggerRef.current?.focus();
    };
  }, [deleteCandidate]);

  const load = useCallback((activeTab: WorkspaceTab) => {
    const seq = ++loadSeqRef.current;
    setError(null);
    setRuns(null);
    apiGet<{ runs: RunSummary[] }>(`/runs?limit=50&${TAB_QUERY[activeTab]}`)
      .then(({ body }) => {
        if (seq !== loadSeqRef.current) return; // stale tab response — dropped
        const rows = body.runs;
        if (!Array.isArray(rows)
          || rows.some((run) => !runMatchesWorkspaceTab(run, activeTab))) {
          setRuns(null);
          setSelected([]);
          setError({
            userMessage: "The run response crossed the requested workspace "
              + "boundary, so nothing is shown.",
          });
          return;
        }
        setRuns(rows);
        // Comparison selections must never survive a reload that hid their rows.
        setSelected((current) =>
          current.filter((id) => rows.some((row) => row.run_id === id)));
      })
      .catch((caught) => {
        if (seq !== loadSeqRef.current) return;
        setRuns(null);
        setError(toSafeError(caught, "The run list could not be loaded."));
      });
  }, []);

  useEffect(() => { load(tab); }, [load, tab]);

  const rowMatchesFilters = useCallback((run: RunSummary) => (
    (statusFilter === "all" || statusBucket(run) === statusFilter)
    && (sourceFilter === "all" || run.data_source === sourceFilter)
    && (familyFilter === "all" || run.family_id === familyFilter)
    && (tagFilter === "all"
      || (run.tags ?? []).some((tag) => tag.normalized_tag === tagFilter))
  ), [statusFilter, sourceFilter, familyFilter, tagFilter]);

  // Filter changes also prune comparison selections: a run id whose row the
  // filters hid must not silently ride along into a compare link.
  useEffect(() => {
    setSelected((current) => current.filter((id) => {
      const run = runs?.find((row) => row.run_id === id);
      return run !== undefined && rowMatchesFilters(run);
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, sourceFilter, familyFilter, tagFilter]);

  // Experiment/tag filters prune safely when a reload removed their option from
  // the loaded rows — a vanished option must not keep filtering invisibly.
  useEffect(() => {
    setFamilyFilter((current) => current !== "all"
      && !(runs ?? []).some((run) => run.family_id === current)
      ? "all" : current);
    setTagFilter((current) => current !== "all"
      && !(runs ?? []).some((run) =>
        (run.tags ?? []).some((tag) => tag.normalized_tag === current))
      ? "all" : current);
  }, [runs]);

  const switchTab = (next: WorkspaceTab) => {
    if (next === tab) return;
    setTab(next);
    setRuns(null);
    setSelected([]);
    setSelectionNotice(null);
    // Experiment/tag options belong to the tab's rows; reset on every switch so
    // formal, sandbox, and archived rows never mix through a stale filter.
    setFamilyFilter("all");
    setTagFilter("all");
    setActionError(null);
    setDeleteCandidate(null);
  };

  /** Archive / restore / soft-delete. A failed action preserves the current list. */
  const manageRun = async (
    run: RunSummary, action: "archive" | "restore" | "delete",
  ) => {
    setActionBusy(run.run_id);
    setActionError(null);
    try {
      if (action === "delete") {
        await apiDelete(`/runs/${encodeURIComponent(run.run_id)}`);
      } else {
        await apiPost(`/runs/${encodeURIComponent(run.run_id)}/${action}`, {});
      }
      setDeleteCandidate(null);
      // Reload the tab the user is on NOW — the action may have completed after
      // a tab switch, and the origin tab's closure value would repaint stale rows.
      load(tabRef.current);
    } catch (caught) {
      setActionError(toSafeError(
        caught,
        action === "archive"
          ? "The run could not be archived. The list is unchanged."
          : action === "restore"
            ? "The run could not be restored. The list is unchanged."
            : "The run could not be removed. The list is unchanged.",
      ));
    } finally {
      setActionBusy(null);
    }
  };

  useEffect(() => {
    // A report's Compare action lands here with its run preselected.
    const preselect = new URLSearchParams(window.location.search).get("compare");
    if (preselect) setSelected([preselect]);
  }, []);

  const toggleSelected = (run: RunSummary) => {
    if (selected.includes(run.run_id)) {
      setSelected(selected.filter((id) => id !== run.run_id));
      setSelectionNotice(null);
      return;
    }
    if (selected.length >= 2) {
      // A third pick replaces the OLDEST slot — announced, never silent.
      const replaced = runs?.find((row) => row.run_id === selected[0]);
      setSelected([selected[1], run.run_id]);
      setSelectionNotice(
        `Replaced “${replaced?.title ?? selected[0]}” with “${run.title}” in `
        + "the comparison selection.");
      return;
    }
    setSelected([...selected, run.run_id]);
    setSelectionNotice(null);
  };

  // Experiment filter options come from the loaded tab rows, in list order.
  const familyOptions = useMemo(() => {
    const options = new Map<string, string>();
    for (const run of runs ?? []) {
      if (run.family_id && !options.has(run.family_id)) {
        options.set(run.family_id, run.family_title ?? "Untitled experiment");
      }
    }
    return [...options.entries()];
  }, [runs]);

  // Tag filter options: one entry per normalized identity, labeled with the
  // first display text seen in the loaded rows, sorted by normalized identity.
  const tagOptions = useMemo(() => {
    const options = new Map<string, string>();
    for (const run of runs ?? []) {
      for (const tag of run.tags ?? []) {
        if (!options.has(tag.normalized_tag)) {
          options.set(tag.normalized_tag, tag.display_tag);
        }
      }
    }
    return [...options.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  }, [runs]);

  const visible = useMemo(() => {
    if (!runs) return [];
    const needle = query.trim().toLowerCase();
    return runs.filter((run) => {
      if (!rowMatchesFilters(run)) return false;
      if (!needle) return true;
      // Search covers title, symbol, family title, and tag display text —
      // never private note bodies (they are not in this response at all).
      return (
        run.title.toLowerCase().includes(needle)
        || (run.symbol ?? "").toLowerCase().includes(needle)
        || (run.family_title ?? "").toLowerCase().includes(needle)
        || (run.tags ?? []).some(
          (tag) => tag.display_tag.toLowerCase().includes(needle))
      );
    });
  }, [runs, query, rowMatchesFilters]);

  // The same condition the row uses to render its selection checkbox. Comparison is
  // gated on an explicitly eligible sealed contract, and every report already carries
  // the permanent explanation, so with none eligible the toolbar must not instruct the
  // reader to tick a box that no row can show.
  const selectableCount = visible.filter(
    (run) => run.evidence_available
      && run.verified_financial_semantics === true
      && run.evidence_view_version === "v1",
  ).length;

  return (
    <main>
      <header className="page-header">
        <div>
          <p className="page-kicker">Research library</p>
          <h1>Runs &amp; Reports</h1>
          <p className="page-lede">
            Your recent runs in this workspace, with their recorded outcomes.
            Reopen a report, or duplicate a run to test a variation.
          </p>
        </div>
        <div className="page-header-actions">
          <Link className="btn-link primary" href="/studio">New research</Link>
        </div>
      </header>

      <div className="runs-tabs" role="tablist" aria-label="Workspace views">
        {(Object.keys(TAB_QUERY) as WorkspaceTab[]).map((key, index, keys) => (
          <button
            key={key}
            role="tab"
            id={`runs-tab-${key}`}
            aria-selected={tab === key}
            aria-controls="runs-tabpanel"
            tabIndex={tab === key ? 0 : -1}
            ref={(el) => { tabButtonRefs.current[index] = el; }}
            data-testid={`runs-tab-${key}`}
            className={tab === key ? "active" : ""}
            onClick={() => switchTab(key)}
            onKeyDown={(event) => {
              let next: number | null = null;
              if (event.key === "ArrowLeft") next = (index - 1 + keys.length) % keys.length;
              else if (event.key === "ArrowRight") next = (index + 1) % keys.length;
              else if (event.key === "Home") next = 0;
              else if (event.key === "End") next = keys.length - 1;
              if (next === null) return;
              event.preventDefault();
              switchTab(keys[next] as WorkspaceTab);
              tabButtonRefs.current[next]?.focus();
            }}
          >
            {TAB_LABELS[key]}
          </button>
        ))}
      </div>

      {tab === "sandbox" && (
        <p className="workspace-meta" data-testid="sandbox-tab-note" style={{ margin: "0 0 10px" }}>
          Sandbox tests produce <strong>non-formal test evidence only</strong>, from
          the separate sandbox allowance. They never access the
          Strict validation final holdout and stay out of the formal research library.
        </p>
      )}

      {actionError && (
        <div className="actionable-error" role="alert" data-testid="run-action-error">
          <strong>{actionError.userMessage}</strong>
          {actionError.reference && (
            <span className="error-ref">Ref: {actionError.reference}</span>
          )}
        </div>
      )}

      <div className="runs-toolbar" role="search">
        <input
          type="search"
          placeholder="Search by name, symbol, experiment, or tag"
          aria-label="Search runs by name, symbol, experiment, or tag"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
        >
          <option value="all">All statuses</option>
          <option value="completed">Completed</option>
          <option value="active">In progress</option>
          <option value="attention">Needs attention</option>
        </select>
        <select
          aria-label="Filter by data source"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as SourceFilter)}
        >
          <option value="all">All data sources</option>
          <option value="sample">Sample data</option>
          <option value="user">Your data</option>
          {/* Without its own option, a bundled run would match no filter but
              "All" — invisible to anyone narrowing the list. */}
          <option value="bundled">Bundled data</option>
          <option value="licensed">Licensed data</option>
        </select>
        <select
          aria-label="Filter by experiment"
          data-testid="filter-experiment"
          value={familyFilter}
          onChange={(e) => setFamilyFilter(e.target.value)}
        >
          <option value="all">All experiments</option>
          {familyOptions.map(([familyId, title]) => (
            <option key={familyId} value={familyId}>{title}</option>
          ))}
        </select>
        <select
          aria-label="Filter by tag"
          data-testid="filter-tag"
          value={tagFilter}
          onChange={(e) => setTagFilter(e.target.value)}
        >
          <option value="all">All tags</option>
          {tagOptions.map(([normalized, display]) => (
            <option key={normalized} value={normalized}>{display}</option>
          ))}
        </select>
        {tab === "formal" && (selected.length === 2 ? (
          <Link
            className="btn-link primary"
            data-testid="compare-selected"
            href={`/runs/compare?a=${encodeURIComponent(selected[0])}&b=${encodeURIComponent(selected[1])}`}
          >
            Compare selected runs
          </Link>
        ) : (
          <span className="compare-hint" data-testid="compare-hint">
            {selected.length === 1
              ? "Select one more completed run to compare."
              : selectableCount >= 2
                ? "Select two completed runs to compare."
                : selectableCount === 1
                  ? "Only one run here carries a comparison-eligible evidence "
                    + "contract, so there is nothing to compare it against."
                  : "No run here carries a comparison-eligible evidence contract. "
                    + "Each report explains why its own contract is excluded."}
          </span>
        ))}
      </div>

      {/* Restrained live region: announces only a comparison-slot replacement,
          so a third pick is never silent. */}
      <p
        className={selectionNotice ? "workspace-meta" : "visually-hidden"}
        role="status"
        data-testid="compare-replacement-notice"
        style={selectionNotice ? { margin: "0 0 10px" } : undefined}
      >
        {selectionNotice ?? ""}
      </p>

      <div role="tabpanel" id="runs-tabpanel" aria-labelledby={`runs-tab-${tab}`}>
      {error ? (
        <div className="actionable-error" role="alert">
          <strong>The run list is temporarily unavailable.</strong>
          <span>{error.userMessage}</span>
          {error.reference && <span className="error-ref">Ref: {error.reference}</span>}
          <button type="button" onClick={() => load(tab)}>Retry</button>
        </div>
      ) : runs === null ? (
        <div className="runs-state" role="status">Loading runs…</div>
      ) : runs.length === 0 ? (
        tab === "sandbox" ? (
          <div className="runs-state" data-testid="sandbox-empty">
            <strong>No sandbox tests yet.</strong>
            Choose the Sandbox test purpose in Research Studio to iterate without
            spending the formal run allowance.
          </div>
        ) : tab === "archived" ? (
          <div className="runs-state" data-testid="archived-empty">
            <strong>No archived runs.</strong>
            Archiving tidies the workspace lists; sealed evidence and audit history
            always remain.
          </div>
        ) : (
          <div className="runs-state">
            <strong>No research runs yet.</strong>
            Confirm a strategy in Research Studio to create your first auditable run.
            <p style={{ marginTop: 12 }}>
              <Link className="btn-link primary" href="/studio">Open Research Studio</Link>
            </p>
          </div>
        )
      ) : visible.length === 0 ? (
        <div className="runs-state" data-testid="runs-empty-filter">
          <strong>No runs match these filters.</strong>
          Adjust the search or filters to see the rest of the library.
        </div>
      ) : (
        <ol className="runs-list" aria-label="Research runs">
          {visible.map((run) => {
            const lifecycleComplete = run.status === "published"
              || run.status === "report_rendered";
            const outcome = lifecycleComplete && !run.evidence_available
              ? { label: "Needs attention · report evidence unavailable", tone: "warn" as const }
              : runOutcome(
                run.status, run.battery_status, run.failed_checks ?? undefined);
            return (
              <li className="run-row" key={run.run_id} data-testid={`run-row-${run.run_id}`}>
                <div className="run-row-main">
                  <div className="run-row-title-line">
                    <h3>
                      <Link href={`/runs/${encodeURIComponent(run.run_id)}`}>
                        {run.title}
                      </Link>
                    </h3>
                    <span className={`outcome-chip ${outcome.tone}`}>{outcome.label}</span>
                  </div>
                  <div className="run-row-meta">
                    {run.symbol && (
                      <span>{instrumentDescriptor(run.symbol) ?? run.symbol}</span>
                    )}
                    {/* "bundled" is the CC BY series. It is sealed as
                        `user_provided` because the sealed contract has no other
                        kind, so every one of these rows used to read "Your data". */}
                    <span>{dataSourceLabel(
                      run.data_source === "user" || run.data_source === "bundled"
                        ? "USER_UPLOADED"
                        : run.data_source === "licensed" ? "LICENSED_PROVIDER"
                          : "SYNTHETIC",
                      run.data_source === "bundled"
                        ? TOTAL_RETURN_ADJUSTMENT : undefined,
                    )}</span>
                    {run.battery_profile === "battery-v2" && (
                      <span className="chip default">Strict validation</span>
                    )}
                    {run.research_mode === "sandbox" && (
                      <span className="chip sandbox" data-testid="sandbox-badge">
                        Sandbox test
                      </span>
                    )}
                    {/* The archived view mixes modes, so every row states its
                        mode explicitly — formal rows included. */}
                    {tab === "archived" && run.research_mode !== "sandbox" && (
                      <span className="chip default" data-testid="formal-badge">
                        Formal research
                      </span>
                    )}
                    {run.management_state === "archived" && (
                      <span className="chip" data-testid="archived-badge">Archived</span>
                    )}
                    <time dateTime={run.created_at}>{instantUTC(run.created_at)}</time>
                  </div>
                  {(run.family_id || run.has_note || (run.tags ?? []).length > 0) && (
                    <div className="run-row-meta run-row-workspace">
                      {run.family_id && (
                        <span data-testid="run-family-context">
                          <Link href={`/experiments/${encodeURIComponent(run.family_id)}`}>
                            Experiment: {run.family_title ?? "Untitled experiment"}
                          </Link>
                          {run.relationship && (
                            <span className="chip default" style={{ marginLeft: 6 }}>
                              {RELATIONSHIP_LABELS[run.relationship]}
                            </span>
                          )}
                        </span>
                      )}
                      {run.has_note && (
                        <span className="chip" data-testid="run-note-indicator">
                          Private note
                        </span>
                      )}
                      {(run.tags ?? []).length > 0 && (
                        <ul className="tag-list" aria-label={`Tags for ${run.title}`}>
                          {(run.tags ?? []).map((tag) => (
                            <li className="tag-chip" key={tag.normalized_tag}>
                              {tag.display_tag}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
                <div className="run-row-actions">
                  {/* Comparison is offered only when the sealed financial contract is
                      explicitly eligible; historical evidence remains readable alone. */}
                  {tab === "formal"
                    && run.evidence_available
                    && run.verified_financial_semantics === true
                    && run.evidence_view_version === "v1" && (
                    <label className="run-select">
                      <input
                        type="checkbox"
                        checked={selected.includes(run.run_id)}
                        onChange={() => toggleSelected(run)}
                        aria-label={`Select ${run.title} for comparison`}
                      />
                      Compare
                    </label>
                  )}
                  <Link
                    className="btn-link primary"
                    href={`/runs/${encodeURIComponent(run.run_id)}`}
                  >
                    {run.evidence_available ? "Open report" : "Open run"}
                  </Link>
                  <Link
                    className="btn-link"
                    href={`/studio?fromRun=${encodeURIComponent(run.run_id)}`}
                    aria-label={run.family_id
                      // Family rows say the linkage plainly; legacy ungrouped
                      // rows make no linkage claim.
                      ? `Duplicate and edit ${run.title}. The next run will be `
                        + "linked to its experiment as a variation."
                      : `Duplicate and edit ${run.title}`}
                    title={run.family_id
                      ? "The next run will be linked to this run's experiment as a variation"
                      : undefined}
                  >
                    Duplicate &amp; edit
                  </Link>
                  {isManageableTerminal(run) && run.management_state !== "archived" && (
                    <button
                      type="button"
                      onClick={() => manageRun(run, "archive")}
                      disabled={actionBusy === run.run_id}
                      aria-label={`Archive ${run.title}`}
                    >
                      Archive
                    </button>
                  )}
                  {run.management_state === "archived" && (
                    <>
                      <button
                        type="button"
                        onClick={() => manageRun(run, "restore")}
                        disabled={actionBusy === run.run_id}
                        aria-label={`Restore ${run.title}`}
                      >
                        Restore
                      </button>
                      <button
                        type="button"
                        onClick={(event) => {
                          deleteTriggerRef.current = event.currentTarget;
                          setActionError(null);
                          setDeleteCandidate(run);
                        }}
                        disabled={actionBusy === run.run_id}
                        aria-label={`Remove ${run.title} from the workspace`}
                      >
                        Remove
                      </button>
                    </>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
      </div>

      {deleteCandidate && (
        <div className="dialog-backdrop">
          <div
            ref={deleteDialogRef}
            className="card confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-run-title"
            data-testid="delete-run-confirm"
          >
            <h2 id="delete-run-title" style={{ marginTop: 0 }}>
              Remove “{deleteCandidate.title}” from the workspace?
            </h2>
            <p>
              This removes the run from workspace lists only. Sealed evidence,
              artifacts, receipts, and the audit history are all retained, and the
              run allowance it used is <strong>not</strong> refunded. Nothing is
              erased.
            </p>
            <div className="field-row">
              <button
                className="primary"
                type="button"
                data-testid="delete-run-confirm-button"
                onClick={() => manageRun(deleteCandidate, "delete")}
                disabled={actionBusy === deleteCandidate.run_id}
              >
                Remove from workspace
              </button>
              <button type="button" onClick={() => setDeleteCandidate(null)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
