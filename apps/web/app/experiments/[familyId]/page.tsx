"use client";

import { use, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

import { apiGet, apiPatch } from "../../studio/lib";
import { ApiRequestError, toSafeError, type SafeError } from "../../lib/errors";
import { instantUTC } from "../../lib/format";
import { runStateLabel } from "../../lib/labels";
import AnnotationEditor from "../AnnotationEditor";
import {
  FAMILY_DESCRIPTION_MAX, FAMILY_TITLE_MAX, RELATIONSHIP_LABELS,
  WORKSPACE_CONTEXT_DISCLOSURE, assumptionValueText, codePointLength,
  decodeRouteParam, detailMatchesFamily, summaryMatchesMode, truncateCodePoints,
  type ExperimentDetailResponse, type ExperimentSummary,
  type FamilyMember, type FamilyMemberVisible,
} from "../lib";

/**
 * Experiment detail workspace: one family, its ordered members, and the private
 * workspace context (title, description, tags, notes) around them. Everything
 * financial stays on the individual run reports — this page fetches no
 * evidence, metric, or Agent route and computes no value, delta, or ranking.
 */

type PageState =
  | { state: "loading" }
  | { state: "not_found" }
  | { state: "failed"; error: SafeError }
  | { state: "ready" };

type FamilySaveState =
  | { state: "idle" }
  | { state: "saving" }
  | { state: "saved" }
  | { state: "conflict"; message: string }
  | { state: "failed"; message: string };

function isBaseline(member: FamilyMember): boolean {
  return !member.removed && member.relationship === "baseline";
}

function MemberAssumptions({ member }: { member: FamilyMemberVisible }) {
  if (member.relationship === "baseline") {
    return (
      <p className="workspace-meta" data-testid="member-assumptions-baseline">
        Family baseline — the reference specification the other runs are
        measured against. No changed assumptions apply.
      </p>
    );
  }
  if (member.changed_assumptions.length === 0) {
    return (
      <p className="workspace-meta" data-testid="member-assumptions-empty">
        No changed assumptions — this run repeats its parent&rsquo;s sealed
        specification exactly (only the display name may differ).
      </p>
    );
  }
  return (
    <div data-testid="member-assumptions">
      <p className="workspace-meta" style={{ marginBottom: 4 }}>
        Changed assumptions (server-sealed diff):
      </p>
      <ul className="assumption-list">
        {member.changed_assumptions.map((entry) => (
          <li key={entry.path}>
            {/* Values render as serialized text only — never as markup and
                never recomputed, ranked, or scored in the browser. */}
            <strong>{entry.label}</strong>{" "}
            <code className="assumption-path">{entry.path}</code>{": "}
            <code>{assumptionValueText(entry.before)}</code>
            {" → "}
            <code>{assumptionValueText(entry.after)}</code>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ExperimentDetailPage({
  params,
}: {
  params: Promise<{ familyId: string }>;
}) {
  const { familyId: rawFamilyId } = use(params);
  // Route params arrive percent-encoded; the decoded value is the identifier
  // the API knows, and every request/href re-encodes it explicitly.
  const familyId = decodeRouteParam(rawFamilyId);
  const [detail, setDetail] = useState<ExperimentDetailResponse | null>(null);
  const [page, setPage] = useState<PageState>({ state: "loading" });
  const [familyDraft, setFamilyDraft] =
    useState<{
      title: string;
      description: string;
      expectedRevision: number;
    } | null>(null);
  const [familySave, setFamilySave] = useState<FamilySaveState>({ state: "idle" });
  const [familyRefreshing, setFamilyRefreshing] = useState(false);
  const [familyRefreshNotice, setFamilyRefreshNotice] = useState<string | null>(null);
  const [editorRunId, setEditorRunId] = useState<string | null>(null);
  const annotationTriggerRef = useRef<HTMLElement | null>(null);
  // Request epoch for THIS family context. Every async completion (GET, PATCH,
  // refresh, background sync) captures it at start and re-checks it before
  // applying state, so a late family-A response can never update family B.
  const epochRef = useRef(0);
  // Annotation saves can request more than one aggregate resync for the same
  // family. Only the newest response may commit, even though the family epoch
  // itself has not changed.
  const syncSeqRef = useRef(0);
  const familyRefreshSeqRef = useRef(0);
  const restoreAnnotationFocusRef = useRef(false);
  const familyBusy = familySave.state === "saving" || familyRefreshing;

  const load = useCallback(() => {
    const epoch = ++epochRef.current;
    setPage({ state: "loading" });
    apiGet<ExperimentDetailResponse>(
      `/experiments/${encodeURIComponent(familyId)}`)
      .then(({ body }) => {
        if (epoch !== epochRef.current) return; // superseded — dropped
        if (!detailMatchesFamily(body, familyId)) {
          // Fail closed: a payload that does not name this exact family, or
          // that mixes research modes, is never displayed.
          setPage({
            state: "failed",
            error: {
              userMessage: "The returned data did not identify this exact "
                + "experiment, so nothing is shown.",
            },
          });
          return;
        }
        setDetail(body);
        setPage({ state: "ready" });
      })
      .catch((caught) => {
        if (epoch !== epochRef.current) return;
        if (caught instanceof ApiRequestError && caught.status === 404) {
          setPage({ state: "not_found" });
          return;
        }
        setPage({
          state: "failed",
          error: toSafeError(caught, "The experiment could not be loaded."),
        });
      });
  }, [familyId]);

  useEffect(() => {
    // A family change is a hard context switch: pending completions for the
    // previous family become void, and every draft/editor surface closes
    // before the new family loads.
    setDetail(null);
    setFamilyDraft(null);
    setFamilySave({ state: "idle" });
    setFamilyRefreshing(false);
    setFamilyRefreshNotice(null);
    setEditorRunId(null);
    syncSeqRef.current += 1;
    familyRefreshSeqRef.current += 1;
    load();
    return () => { epochRef.current += 1; };
  }, [load]);

  /** Background resync after an annotation save/refresh. The editor signals
   * only the run id — never a note body — and the server stays the single
   * authority for member indicators and family-level tag/note aggregates. */
  const syncDetail = useCallback(() => {
    const epoch = epochRef.current;
    const syncSeq = ++syncSeqRef.current;
    apiGet<ExperimentDetailResponse>(
      `/experiments/${encodeURIComponent(familyId)}`)
      .then(({ body }) => {
        if (epoch !== epochRef.current || syncSeq !== syncSeqRef.current) return;
        if (!detailMatchesFamily(body, familyId)) return; // fail closed
        setDetail((current) => {
          if (!current) return body;
          // Annotation writes do not change the family revision. If a family
          // PATCH completed while this GET was in flight, retain the newer
          // title/description instead of letting an old aggregate response
          // roll the context backwards.
          const experiment = body.experiment.revision < current.experiment.revision
            ? current.experiment
            : body.experiment;
          return { ...body, experiment };
        });
      })
      .catch(() => {
        // Background sync only — the current honest view stays as-is.
      });
  }, [familyId]);

  function openFamilyEdit() {
    if (!detail) return;
    setFamilyDraft({
      title: detail.experiment.title,
      description: detail.experiment.description,
      // Pin the exact version the user began editing. Background annotation
      // aggregate syncs may update the displayed family while this draft is
      // open, but they must never silently grant this write a newer revision.
      expectedRevision: detail.experiment.revision,
    });
    setFamilySave({ state: "idle" });
    setFamilyRefreshNotice(null);
  }

  async function saveFamily() {
    if (!familyDraft || !detail) return;
    if (familyBusy || familySave.state === "conflict") return;
    const epoch = epochRef.current;
    syncSeqRef.current += 1; // invalidate an older annotation aggregate GET
    familyRefreshSeqRef.current += 1;
    setFamilySave({ state: "saving" });
    setFamilyRefreshNotice(null);
    try {
      const { body } = await apiPatch<{ experiment: ExperimentSummary }>(
        `/experiments/${encodeURIComponent(familyId)}`,
        {
          expected_revision: familyDraft.expectedRevision,
          title: familyDraft.title,
          description: familyDraft.description,
        });
      if (epoch !== epochRef.current) return; // family changed — never applied
      if (!summaryMatchesMode(body.experiment, detail.experiment.research_mode)
        || body.experiment.family_id !== familyId) {
        // Fail closed: a response naming a different family updates nothing.
        setFamilySave({
          state: "failed",
          message: "The save response did not identify this exact experiment, "
            + "so nothing was applied locally. Reload before editing again.",
        });
        return;
      }
      // Local state updates only after the server accepted the exact revision.
      setDetail((current) =>
        current ? { ...current, experiment: body.experiment } : current);
      setFamilyDraft(null);
      setFamilySave({ state: "saved" });
    } catch (caught) {
      if (epoch !== epochRef.current) return;
      if (caught instanceof ApiRequestError && caught.code === "FAMILY_CONFLICT") {
        setFamilySave({
          state: "conflict",
          message: caught.detailMessage
            ?? "The family changed since you loaded it.",
        });
        return;
      }
      if (caught instanceof ApiRequestError && caught.status === 422
        && caught.detailMessage) {
        setFamilySave({ state: "failed", message: caught.detailMessage });
        return;
      }
      setFamilySave({
        state: "failed",
        message: toSafeError(
          caught, "The workspace update could not be saved.").userMessage,
      });
    }
  }

  /** Conflict recovery: fetch the current server version. The draft inputs stay
   * exactly as typed — refreshing never overwrites or auto-retries. */
  async function refreshFamilyVersion() {
    if (familyBusy) return;
    const epoch = epochRef.current;
    const refreshSeq = ++familyRefreshSeqRef.current;
    syncSeqRef.current += 1;
    setFamilyRefreshing(true);
    try {
      const { body } = await apiGet<ExperimentDetailResponse>(
        `/experiments/${encodeURIComponent(familyId)}`);
      if (epoch !== epochRef.current
        || refreshSeq !== familyRefreshSeqRef.current) return;
      if (!detailMatchesFamily(body, familyId)) {
        setFamilySave({
          state: "failed",
          message: "The refreshed data did not identify this exact experiment, "
            + "so nothing was applied.",
        });
        return;
      }
      setDetail(body);
      // Refresh is the user's explicit decision to rebase the preserved draft
      // onto the current server version. No other background response may
      // change the revision used by the next save attempt.
      setFamilyDraft((current) => current
        ? { ...current, expectedRevision: body.experiment.revision }
        : current);
      setFamilySave({ state: "idle" });
      setFamilyRefreshNotice(
        "Current version refreshed. Review it, then save again to replace it "
        + "with your draft.");
    } catch (caught) {
      if (epoch !== epochRef.current
        || refreshSeq !== familyRefreshSeqRef.current) return;
      setFamilySave({
        state: "failed",
        message: toSafeError(
        caught, "The current version could not be refreshed.").userMessage,
      });
    } finally {
      if (epoch === epochRef.current
        && refreshSeq === familyRefreshSeqRef.current) {
        setFamilyRefreshing(false);
      }
    }
  }

  function closeEditor() {
    restoreAnnotationFocusRef.current = true;
    setEditorRunId(null);
  }

  // The editor restores background interactivity in its unmount cleanup. Focus
  // returns only after that cleanup, never while the trigger is still inert.
  useEffect(() => {
    if (editorRunId !== null || !restoreAnnotationFocusRef.current) return;
    restoreAnnotationFocusRef.current = false;
    annotationTriggerRef.current?.focus();
  }, [editorRunId]);

  if (page.state === "loading") {
    return (
      <main>
        <p role="status" data-testid="experiment-detail-loading">
          Loading the experiment workspace…
        </p>
      </main>
    );
  }

  if (page.state === "not_found") {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Experiment workspace</p>
            <h1>Experiment unavailable</h1>
          </div>
        </header>
        <div className="runs-state" data-testid="experiment-not-found">
          <strong>This experiment isn&rsquo;t available in this workspace.</strong>
          It may have been created in another workspace, or its identifier may be
          out of date.
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/experiments">
              Back to Experiments
            </Link>
          </p>
        </div>
      </main>
    );
  }

  if (page.state === "failed" || detail === null) {
    const failure = page.state === "failed"
      ? page.error
      : { userMessage: "The experiment could not be loaded." };
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Experiment workspace</p>
            <h1>Experiment unavailable</h1>
          </div>
        </header>
        <div className="actionable-error" role="alert" data-testid="experiment-detail-error">
          <strong>The experiment workspace is temporarily unavailable.</strong>
          <span>{failure.userMessage}</span>
          {"reference" in failure && failure.reference && (
            <span className="error-ref">Ref: {failure.reference}</span>
          )}
          <button type="button" onClick={load}>Retry</button>
        </div>
      </main>
    );
  }

  // App Router may reuse this component when only the dynamic parameter
  // changes. Never render family A for even one commit under family B's URL;
  // the effect below will reset and fetch the new identity.
  if (detail.experiment.family_id !== familyId) {
    return (
      <main>
        <p role="status" data-testid="experiment-detail-loading">
          Loading the experiment workspace…
        </p>
      </main>
    );
  }

  const { experiment, members } = detail;
  // Baseline first; every other member (including tombstones) keeps the exact
  // server order.
  const ordered = [
    ...members.filter(isBaseline),
    ...members.filter((member) => !isBaseline(member)),
  ];

  return (
    <main data-testid="experiment-detail">
      <header className="page-header">
        <div>
          <p className="page-kicker">Experiment workspace</p>
          <h1 data-testid="experiment-title">{experiment.title}</h1>
          {experiment.description !== "" && (
            <p className="page-lede" data-testid="experiment-description">
              {experiment.description}
            </p>
          )}
          <p className="workspace-meta" data-testid="experiment-facts">
            {experiment.research_mode === "sandbox"
              ? "Sandbox test"
              : "Formal research"}
            {" · "}
            {experiment.visible_run_count}{" "}
            {experiment.visible_run_count === 1 ? "visible run" : "visible runs"}
            {/* updated_at moves only on title/description edits, so it is
                labeled as family context — not general workspace activity. */}
            {" · family context updated "}
            {instantUTC(experiment.updated_at)}
          </p>
          {experiment.tags.length > 0 && (
            <ul className="tag-list" aria-label="Experiment tags">
              {experiment.tags.map((tag) => (
                <li className="tag-chip" key={tag.normalized_tag}>
                  {tag.display_tag}
                </li>
              ))}
            </ul>
          )}
          <p className="notice" data-testid="experiment-disclosure" style={{ marginBottom: 0 }}>
            {WORKSPACE_CONTEXT_DISCLOSURE}
          </p>
        </div>
        <div className="page-header-actions">
          <button
            type="button"
            data-testid="family-edit-open"
            disabled={familyBusy || familyDraft !== null}
            onClick={openFamilyEdit}
          >
            Edit title &amp; description
          </button>
          <Link className="btn-link" href="/experiments">Back to Experiments</Link>
        </div>
      </header>

      {familySave.state === "saved" && (
        <p className="notice" role="status" data-testid="family-save-state">
          Saved. The workspace title and description were updated.
        </p>
      )}

      {familyDraft && (
        <section
          className="card family-edit"
          data-testid="family-edit"
          aria-label="Edit experiment title and description"
          aria-busy={familyBusy}
        >
          <h2 style={{ marginTop: 0, fontSize: "1.05rem" }}>
            Edit title &amp; description
          </h2>
          <p className="workspace-meta" style={{ marginTop: 0 }}>
            Mutable workspace context, plain text only — sealed run evidence is
            not affected.
          </p>
          <div className="field">
            <label htmlFor="family-title">Title</label>
            <input
              id="family-title"
              type="text"
              value={familyDraft.title}
              disabled={familyBusy}
              onChange={(event) => {
                const title = truncateCodePoints(
                  event.target.value, FAMILY_TITLE_MAX);
                setFamilyDraft((current) =>
                  current ? { ...current, title } : current);
              }}
            />
            <small className="annotation-count">
              {/* API limits count Unicode code points, not UTF-16 units. */}
              {codePointLength(familyDraft.title)} / {FAMILY_TITLE_MAX} characters
            </small>
          </div>
          <div className="field">
            <label htmlFor="family-description">Description</label>
            <textarea
              id="family-description"
              rows={4}
              value={familyDraft.description}
              disabled={familyBusy}
              onChange={(event) => {
                const description = truncateCodePoints(
                  event.target.value, FAMILY_DESCRIPTION_MAX);
                setFamilyDraft((current) =>
                  current ? { ...current, description } : current);
              }}
            />
            <small className="annotation-count" data-testid="family-description-count">
              {codePointLength(familyDraft.description).toLocaleString("en-US")} /{" "}
              {FAMILY_DESCRIPTION_MAX.toLocaleString("en-US")} characters
            </small>
          </div>
          {familyRefreshNotice && (
            <p className="notice" role="status" data-testid="family-refresh-notice">
              {familyRefreshNotice}
            </p>
          )}
          {familySave.state === "conflict" && (
            <div className="notice warn" role="alert" data-testid="family-conflict">
              <strong>The workspace changed.</strong>{" "}
              {familySave.message} Your draft is preserved exactly as written;
              nothing was overwritten.
              <div className="field-row" style={{ marginTop: 8 }}>
                <button
                  type="button"
                  data-testid="family-refresh"
                  onClick={refreshFamilyVersion}
                  disabled={familyBusy}
                >
                  {familyRefreshing ? "Refreshing…" : "Refresh current version"}
                </button>
              </div>
            </div>
          )}
          {familySave.state === "failed" && (
            <div className="actionable-error" role="alert" data-testid="family-save-error">
              <strong>The save did not go through.</strong>
              <span>{familySave.message} Your draft is unchanged.</span>
            </div>
          )}
          <div className="field-row" style={{ marginTop: 12 }}>
            <button
              type="button"
              className="primary"
              data-testid="family-save"
              onClick={saveFamily}
              disabled={familyBusy || familySave.state === "conflict"
                || familyDraft.title.trim() === ""}
            >
              {familySave.state === "saving" ? "Saving…" : "Save workspace context"}
            </button>
            <button
              type="button"
              data-testid="family-edit-cancel"
              disabled={familyBusy}
              onClick={() => {
                setFamilyDraft(null);
                setFamilySave({ state: "idle" });
                setFamilyRefreshNotice(null);
              }}
            >
              Cancel
            </button>
          </div>
        </section>
      )}

      <section aria-labelledby="experiment-members-heading">
        <h2 id="experiment-members-heading" style={{ fontSize: "1.05rem" }}>
          Runs in this experiment
        </h2>
        {ordered.length === 0 ? (
          <div className="runs-state" data-testid="experiment-members-empty">
            <strong>No visible runs in this experiment.</strong>
            Every member run has been removed from the workspace lists; restore a
            run from Runs &amp; Reports to see it here again.
          </div>
        ) : (
          <ol className="experiment-list member-list" aria-label="Experiment member runs">
            {ordered.map((member) => member.removed ? (
              <li
                className="card member-card member-tombstone"
                key={member.run_id}
                data-testid={`member-${member.run_id}`}
              >
                <div className="member-head">
                  <span className="chip warn">Removed parent</span>
                  <code className="member-run-id">{member.run_id}</code>
                </div>
                <p className="workspace-meta" style={{ marginBottom: 0 }}>
                  This parent run was removed from the workspace. Its identity is
                  retained for lineage context only.
                </p>
              </li>
            ) : (
              <li
                className="card member-card"
                key={member.run_id}
                data-testid={`member-${member.run_id}`}
              >
                <div className="member-head">
                  <span className={`chip ${member.relationship === "baseline" ? "default" : ""}`}>
                    {RELATIONSHIP_LABELS[member.relationship]}
                  </span>
                  <span className="chip">{runStateLabel(member.status)}</span>
                  {member.archived_at && <span className="chip">Archived</span>}
                  {member.research_mode === "sandbox" && (
                    <span className="chip sandbox">Sandbox test</span>
                  )}
                  {member.has_note && (
                    <span className="chip" data-testid="member-note-indicator">
                      Private note
                    </span>
                  )}
                </div>
                <div className="member-meta">
                  <code className="member-run-id">{member.run_id}</code>
                  <time dateTime={member.created_at}>
                    Created {instantUTC(member.created_at)}
                  </time>
                  {member.parent_run_id && (
                    <span data-testid="member-parent">
                      Parent run:{" "}
                      <Link href={`/runs/${encodeURIComponent(member.parent_run_id)}`}>
                        {member.parent_run_id}
                      </Link>
                    </span>
                  )}
                </div>
                {member.tags.length > 0 && (
                  <ul className="tag-list" aria-label="Run tags">
                    {member.tags.map((tag) => (
                      <li className="tag-chip" key={tag.normalized_tag}>
                        {tag.display_tag}
                      </li>
                    ))}
                  </ul>
                )}
                <MemberAssumptions member={member} />
                <div className="field-row member-actions">
                  <Link
                    className="btn-link"
                    href={`/runs/${encodeURIComponent(member.run_id)}`}
                  >
                    Open run
                  </Link>
                  <button
                    type="button"
                    data-testid={`member-annotate-${member.run_id}`}
                    disabled={familyBusy}
                    onClick={(event) => {
                      annotationTriggerRef.current = event.currentTarget;
                      setEditorRunId(member.run_id);
                    }}
                  >
                    Notes &amp; tags
                  </button>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      {editorRunId && (
        <AnnotationEditor
          runId={editorRunId}
          onClose={closeEditor}
          onSaved={() => syncDetail()}
        />
      )}
    </main>
  );
}
