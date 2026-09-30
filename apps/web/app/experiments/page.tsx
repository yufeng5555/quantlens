"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

import { apiGet } from "../studio/lib";
import { toSafeError, type SafeError } from "../lib/errors";
import { instantUTC } from "../lib/format";
import {
  WORKSPACE_CONTEXT_DISCLOSURE,
  summaryMatchesMode,
  type ExperimentsPageResponse,
  type ExperimentSummary,
} from "./lib";

/**
 * Experiment Library — private workspace summaries of lineage families. This
 * page shows only server summary metadata (titles, descriptions, counts, tags,
 * note indicators); it never fetches evidence, metrics, or Agent routes and
 * never displays performance, verdicts, or rankings.
 */

type ExperimentTab = "formal" | "sandbox";

const TAB_LABELS: Record<ExperimentTab, string> = {
  formal: "Formal experiments",
  sandbox: "Sandbox experiments",
};

const TABS: ExperimentTab[] = ["formal", "sandbox"];

function ExperimentCard({ experiment }: { experiment: ExperimentSummary }) {
  return (
    <li
      className="card experiment-card"
      data-testid={`experiment-card-${experiment.family_id}`}
    >
      <div className="experiment-card-head">
        <h3>
          <Link href={`/experiments/${encodeURIComponent(experiment.family_id)}`}>
            {experiment.title}
          </Link>
        </h3>
        <span
          className={`chip ${experiment.research_mode === "sandbox" ? "sandbox" : "default"}`}
        >
          {experiment.research_mode === "sandbox" ? "Sandbox test" : "Formal research"}
        </span>
      </div>
      {experiment.description !== "" && (
        <p className="experiment-card-description">{experiment.description}</p>
      )}
      <div className="experiment-card-meta">
        <span>
          {experiment.visible_run_count}{" "}
          {experiment.visible_run_count === 1 ? "run" : "runs"}
        </span>
        {experiment.has_notes && (
          <span className="chip" data-testid="experiment-note-indicator">
            Private notes
          </span>
        )}
        {/* Family revision timestamps track ONLY title/description edits. */}
        <time dateTime={experiment.updated_at}>
          Family context updated {instantUTC(experiment.updated_at)}
        </time>
      </div>
      {experiment.tags.length > 0 && (
        <ul className="tag-list" aria-label="Tags">
          {experiment.tags.map((tag) => (
            <li className="tag-chip" key={tag.normalized_tag}>{tag.display_tag}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function ExperimentsIndex() {
  const [tab, setTab] = useState<ExperimentTab>("formal");
  const [rows, setRows] = useState<ExperimentSummary[] | null>(null);
  const [error, setError] = useState<SafeError | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<SafeError | null>(null);
  // Monotonic load token: a slow response for a previously selected tab can
  // never overwrite the currently selected tab's rows or error state.
  const loadSeqRef = useRef(0);
  const tabButtonRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const load = useCallback((activeTab: ExperimentTab) => {
    const seq = ++loadSeqRef.current;
    setError(null);
    setMoreError(null);
    apiGet<ExperimentsPageResponse>(
      `/experiments?limit=50&research_mode=${activeTab}`)
      .then(({ body }) => {
        if (seq !== loadSeqRef.current) return; // stale tab response — dropped
        const incoming = body.experiments;
        // Fail closed on the response as a whole. Silently filtering a
        // cross-mode row could make a compromised payload look like a genuine
        // empty library, which would blur the formal/sandbox boundary.
        if (!Array.isArray(incoming)
          || incoming.some((row) => !summaryMatchesMode(row, activeTab))) {
          setRows(null);
          setNextCursor(null);
          setError({
            userMessage: "The experiment response crossed the requested "
              + "research boundary, so nothing is shown.",
          });
          return;
        }
        setRows(incoming);
        setNextCursor(body.has_more ? body.next_cursor : null);
      })
      .catch((caught) => {
        if (seq !== loadSeqRef.current) return;
        // A failed load is an explicit failure state with retry — it must never
        // masquerade as a legitimate empty library.
        setRows(null);
        setNextCursor(null);
        setError(toSafeError(caught, "The experiment library could not be loaded."));
      });
  }, []);

  useEffect(() => { load(tab); }, [load, tab]);

  const switchTab = (next: ExperimentTab) => {
    if (next === tab) return;
    setTab(next);
    setRows(null);
    setNextCursor(null);
    setError(null);
    setMoreError(null);
    // A pagination request from the previous tab is now void: bumping the load
    // token invalidates its then/catch/finally, and the busy flag resets so the
    // fresh view's own pagination is never blocked or unblocked by it.
    loadSeqRef.current += 1;
    setMoreBusy(false);
  };

  const showMore = () => {
    if (!nextCursor || moreBusy) return;
    const seq = loadSeqRef.current;
    const cursor = nextCursor;
    const pageTab = tab;
    setMoreBusy(true);
    setMoreError(null);
    apiGet<ExperimentsPageResponse>(
      `/experiments?limit=50&research_mode=${pageTab}&cursor=${encodeURIComponent(cursor)}`)
      .then(({ body }) => {
        if (seq !== loadSeqRef.current) return; // the view changed meanwhile
        const incoming = body.experiments;
        if (!Array.isArray(incoming)
          || incoming.some((row) => !summaryMatchesMode(row, pageTab))) {
          setMoreError({
            userMessage: "More experiments crossed the requested research "
              + "boundary, so that page was not added.",
          });
          return;
        }
        setRows((current) => {
          const seen = new Set((current ?? []).map((row) => row.family_id));
          const fresh = incoming
            .filter((row) => !seen.has(row.family_id));
          return [...(current ?? []), ...fresh];
        });
        setNextCursor(body.has_more ? body.next_cursor : null);
      })
      .catch((caught) => {
        if (seq !== loadSeqRef.current) return;
        // Loaded cards stay; only the pagination step reports its failure.
        setMoreError(toSafeError(caught, "More experiments could not be loaded."));
      })
      .finally(() => {
        // Only the request that still owns the view may clear its busy flag; a
        // superseded page-more must not unlock a newer view's pagination.
        if (seq === loadSeqRef.current) setMoreBusy(false);
      });
  };

  return (
    <main>
      <header className="page-header">
        <div>
          <p className="page-kicker">Research library</p>
          <h1>Experiments</h1>
          <p className="page-lede">
            Experiment families group a baseline run with its linked variations
            and reruns. {WORKSPACE_CONTEXT_DISCLOSURE}
          </p>
        </div>
        <div className="page-header-actions">
          <Link className="btn-link primary" href="/runs">Runs &amp; Reports</Link>
        </div>
      </header>

      <div className="runs-tabs" role="tablist" aria-label="Experiment views">
        {TABS.map((key, index) => (
          <button
            key={key}
            role="tab"
            id={`experiments-tab-${key}`}
            aria-selected={tab === key}
            aria-controls="experiments-tabpanel"
            tabIndex={tab === key ? 0 : -1}
            ref={(el) => { tabButtonRefs.current[index] = el; }}
            data-testid={`experiments-tab-${key}`}
            className={tab === key ? "active" : ""}
            onClick={() => switchTab(key)}
            onKeyDown={(event) => {
              let next: number | null = null;
              if (event.key === "ArrowLeft") next = (index - 1 + TABS.length) % TABS.length;
              else if (event.key === "ArrowRight") next = (index + 1) % TABS.length;
              else if (event.key === "Home") next = 0;
              else if (event.key === "End") next = TABS.length - 1;
              if (next === null) return;
              event.preventDefault();
              switchTab(TABS[next]);
              tabButtonRefs.current[next]?.focus();
            }}
          >
            {TAB_LABELS[key]}
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id="experiments-tabpanel"
        aria-labelledby={`experiments-tab-${tab}`}
      >
        {rows === null && error === null ? (
          <div className="runs-state" role="status" data-testid="experiments-loading">
            Loading experiments…
          </div>
        ) : error !== null ? (
          <div className="actionable-error" role="alert" data-testid="experiments-error">
            <strong>The experiment library is temporarily unavailable.</strong>
            <span>{error.userMessage}</span>
            {error.reference && <span className="error-ref">Ref: {error.reference}</span>}
            <button type="button" onClick={() => load(tab)}>Retry</button>
          </div>
        ) : rows !== null && rows.length === 0 ? (
          <div
            className="runs-state"
            data-testid={`experiments-empty-${tab}`}
          >
            <strong>
              {tab === "sandbox"
                ? "No sandbox experiments yet."
                : "No formal experiments yet."}
            </strong>
            Duplicate a completed run from Runs &amp; Reports to start a linked
            experiment family; the duplicate records an explicit variation or
            rerun relationship when you confirm it.
          </div>
        ) : rows !== null ? (
          <>
            <ol className="experiment-list" aria-label="Experiment families">
              {rows.map((experiment) => (
                <ExperimentCard key={experiment.family_id} experiment={experiment} />
              ))}
            </ol>
            {moreError && (
              <div className="actionable-error" role="alert" data-testid="experiments-more-error">
                <strong>{moreError.userMessage}</strong>
                <span>The experiments above are unchanged.</span>
                <button
                  type="button"
                  data-testid="experiments-more-retry"
                  onClick={showMore}
                  disabled={moreBusy}
                >
                  Retry
                </button>
              </div>
            )}
            {nextCursor && (
              <div className="field-row" style={{ marginTop: 12 }}>
                <button
                  type="button"
                  data-testid="experiments-show-more"
                  onClick={showMore}
                  disabled={moreBusy}
                >
                  {moreBusy ? "Loading more…" : "Show more experiments"}
                </button>
              </div>
            )}
          </>
        ) : null}
      </div>
    </main>
  );
}
