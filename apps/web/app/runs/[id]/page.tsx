"use client";

import { use, useEffect, useRef, useState } from "react";
import Link from "next/link";

import type {
  EvidenceUnavailable, EvidenceView, ExplanationViewV1,
} from "@schema/ts/evidence";
import { apiGet, apiPost } from "../../studio/lib";
import { ApiRequestError, toSafeError } from "../../lib/errors";
import EvidenceWorkspace from "./EvidenceWorkspace";
import {
  atomicUnavailableExplanation, isExplanationViewV1,
} from "./explanationContract";
import {
  isResearchCopilotView, type ResearchCopilotView,
} from "./researchCopilotContract";
import {
  DEFAULT_READING_LEVEL, ReadingLevelSwitch, type ReadingLevel,
} from "./readingLevel";
import { useWorkspaceSession, type ReportRole } from "../../components/WorkspaceSession";
import {
  RUN_STAGES,
  dataLabelBadgeClass,
  dataSourceLabel,
  instrumentDescriptor,
  runStateLabel,
} from "../../lib/labels";

interface RunState {
  run_id: string;
  status: string;
  history: [string, string][];
  error: { code?: string; message?: string; quota_charged?: boolean } | null;
  retries: number;
  spec: { meta: { name: string }; universe?: { symbol?: string } };
  research_mode?: "formal" | "sandbox";
  management_state?: "active" | "archived" | "deleted";
  execution?: {
    state: "queued" | "waiting_for_worker" | "worker_unavailable" | "queue_delayed"
      | "processing" | "terminal" | string;
    delayed: boolean;
    queued_for_seconds?: number;
    message?: string | null;
    worker?: {
      available: boolean;
      state: string;
      reason?: string | null;
      last_seen_at?: string | null;
    };
  };
}

const FAILURE_COPY: Record<string, string> = {
  validation_failed:
    "The specification failed validation at run time. No run allowance was used.",
  data_quality_failed:
    "The selected data snapshot failed a data-quality check for this specification "
    + "(for example, a gap beyond the declared threshold). No run allowance was used.",
};

const TERMINAL = ["report_rendered", "published", "validation_failed",
  "data_quality_failed", "system_failed"];

export default function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [run, setRun] = useState<RunState | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceView | null>(null);
  const [evidenceRefusal, setEvidenceRefusal] = useState<EvidenceUnavailable | null>(null);
  const [explanation, setExplanation] = useState<ExplanationViewV1 | null>(null);
  const [copilot, setCopilot] = useState<ResearchCopilotView | null>(null);
  const [copilotUnavailable, setCopilotUnavailable] = useState(false);
  const [explanationLoading, setExplanationLoading] = useState(false);
  const [manageError, setManageError] = useState<string | null>(null);
  const [sealPulse, setSealPulse] = useState(false);
  const sawSealedRef = useRef(false);
  // One research request per (run id, evidence contract, sealed manifest) — never a
  // one-shot boolean that could pin a previous run's state across navigation.
  const researchRequestKeyRef = useRef<string | null>(null);

  // A dynamic-route id change must never render or request with the previous run's
  // state. Resetting during render (the sanctioned adjust-state-on-prop-change
  // pattern) guarantees the new id starts from loading — not one frame of stale
  // run, evidence, explanation, or copilot content.
  const [renderedId, setRenderedId] = useState(id);
  if (renderedId !== id) {
    setRenderedId(id);
    setRun(null);
    setNotFound(false);
    setPollError(null);
    setEvidence(null);
    setEvidenceRefusal(null);
    setExplanation(null);
    setCopilot(null);
    setCopilotUnavailable(false);
    setExplanationLoading(false);
    setManageError(null);
    setSealPulse(false);
    sawSealedRef.current = false;
    researchRequestKeyRef.current = null;
  }

  // How deep this reader wants the report rendered. It selects wording and
  // density only — both levels project the same sealed evidence through the
  // same formatters, and neither can add, hide, or soften a value.
  const { state: sessionState, refresh: refreshSession } = useWorkspaceSession();
  const storedRole = sessionState.kind === "authenticated"
    ? sessionState.session.reportRole
    : null;
  const [readingLevel, setReadingLevel] = useState<ReadingLevel>(DEFAULT_READING_LEVEL);
  const [appliedRole, setAppliedRole] = useState<ReportRole | null>(null);
  const [savingReadingLevel, setSavingReadingLevel] = useState(false);
  const [readingLevelError, setReadingLevelError] = useState<string | null>(null);

  // Adopt the account's stored preference once the session settles, and again
  // whenever it changes. A session that is still loading never resets the level
  // the reader is currently looking at; a workspace with no stored preference —
  // every local workspace — stays on the full professional report.
  if (sessionState.kind !== "loading" && storedRole !== appliedRole) {
    setAppliedRole(storedRole);
    setReadingLevel(storedRole ?? DEFAULT_READING_LEVEL);
  }

  const changeReadingLevel = (level: ReadingLevel) => {
    setReadingLevel(level);
    setReadingLevelError(null);
    // Only an account-backed session has somewhere to store this. A local
    // workspace switches the current view and claims nothing was saved.
    if (sessionState.kind !== "authenticated") return;
    setSavingReadingLevel(true);
    void fetch("/api/ql/auth/report-role", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ report_role: level }),
    }).then((response) => {
      if (!response.ok) {
        setReadingLevelError(
          "This reading level applies to the report you are viewing, but it could "
          + "not be saved to your workspace.",
        );
        return;
      }
      setAppliedRole(level);
      refreshSession();
    }).catch(() => {
      setReadingLevelError(
        "This reading level applies to the report you are viewing, but the workspace "
        + "service could not be reached to save it.",
      );
    }).finally(() => setSavingReadingLevel(false));
  };

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        const { status, body } = await apiGet<RunState>(`/runs/${id}`, { allowStatuses: [404] });
        if (stop) return;
        if (status === 404) { setNotFound(true); return; }
        if (status < 200 || status >= 300 || !body || typeof body.status !== "string") {
          throw new Error("Run status response was unavailable or malformed.");
        }
        setPollError(null);
        setRun(body);
        const sealedNow = body.history.some(([s]) => s === "ledger_sealed");
        if (sealedNow && !sawSealedRef.current) {
          // one brief integrity pulse the moment the evidence seals — never repeated
          sawSealedRef.current = true;
          setSealPulse(true);
          setTimeout(() => setSealPulse(false), 1200);
        }
        if (!TERMINAL.includes(body.status)) {
          timer = setTimeout(poll, 900);
        }
      } catch {
        if (stop) return;
        setPollError("The latest run status could not be loaded. Retrying automatically…");
        timer = setTimeout(poll, 1_500);
      }
    }
    poll();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  const done = run?.status === "report_rendered" || run?.status === "published";
  // Sealed evidence may exist even when publication later failed (P1-4).
  const evidenceWorthFetching = done || run?.status === "system_failed";

  useEffect(() => {
    if (!evidenceWorthFetching || evidence || evidenceRefusal) return;
    let stale = false;
    apiGet<EvidenceView | EvidenceUnavailable>(
      `/runs/${id}/evidence`, { allowStatuses: [409] },
    ).then(({ status, body }) => {
      if (stale) return;
      // Sealed v3 identities carry no run_id; they bind to the run through the
      // manifest id, which embeds it. Every other version binds on run_id.
      const claimsV3 = (body as { evidence_view_version?: unknown })
        .evidence_view_version === "v3";
      const identityRunId = (body as { identity?: { run_id?: unknown } }).identity?.run_id;
      const identityManifestId = (body as { identity?: { manifest_id?: unknown } })
        .identity?.manifest_id;
      const boundToRun = claimsV3
        ? identityManifestId === `mfst-${id}`
        : identityRunId === id;
      if (status === 200 && boundToRun) {
        setEvidence(body as EvidenceView);
      } else if (status === 200) {
        // The sealed identity does not name this run: refuse rather than render
        // another run's evidence under this URL.
        setEvidenceRefusal({
          code: "EVIDENCE_NOT_AVAILABLE", run_id: id, run_status: run?.status ?? "unknown",
          battery_status: "NOT RUN",
          message: "The sealed evidence returned by the service did not identify "
            + "this run, so nothing is shown.",
        });
      } else {
        setEvidenceRefusal(body as EvidenceUnavailable);
      }
    }).catch(() => {
      if (!stale) {
        setEvidenceRefusal({
          code: "EVIDENCE_NOT_AVAILABLE", run_id: id, run_status: run?.status ?? "unknown",
          battery_status: "NOT RUN",
          message: "The evidence view could not be loaded from the research service.",
        });
      }
    });
    return () => { stale = true; };
  }, [evidenceWorthFetching, evidence, evidenceRefusal, id, run?.status]);

  useEffect(() => {
    // Downstream read-only research surfaces. Neither is requested until the
    // browser holds the complete 200 evidence contract. v1 keeps the narrative
    // /explanation contract. v2 uses the Development Research Copilot endpoint
    // exclusively — there is no fallback to the old v2 explanation projection —
    // and any non-200, malformed, adversarial, or unsafe response fails closed
    // to a single calm notice.
    if (!evidence) return;
    // The v3 contract record drives no downstream research surface: the v1
    // narrative explanation and the v2 Development Research Copilot are both
    // scoped to their own contracts, and requesting either for a v3 record
    // could only misproject it.
    if (evidence.evidence_view_version === "v3") return;
    // Sealed identity must name the current id; a stale or foreign evidence object
    // never triggers a research request.
    if (evidence.identity.run_id !== id) return;
    const requestKey =
      `${id}:${evidence.evidence_view_version}:${evidence.identity.manifest_sha256}`;
    if (researchRequestKeyRef.current === requestKey) return;
    researchRequestKeyRef.current = requestKey;
    const version = evidence.evidence_view_version;
    let stale = false;
    setExplanationLoading(true);
    const request = version === "v1"
      ? apiGet<unknown>(`/runs/${id}/explanation`).then(({ status, body }) => {
        if (stale) return;
        if (status === 200 && isExplanationViewV1(body, id)) {
          setExplanation(body);
        } else {
          setExplanation(atomicUnavailableExplanation());
        }
      }).catch(() => {
        if (!stale) setExplanation(atomicUnavailableExplanation());
      })
      : apiGet<unknown>(`/runs/${id}/research-copilot`, { allowStatuses: [409] })
        .then(({ status, body }) => {
          if (stale) return;
          if (status === 200 && isResearchCopilotView(body)) {
            setCopilot(body);
          } else {
            // 409 or an off-contract 200: suppressed atomically.
            setCopilotUnavailable(true);
          }
        }).catch(() => {
          // Other non-2xx or network failure: reported, never silent.
          if (!stale) setCopilotUnavailable(true);
        });
    void request.finally(() => {
      if (!stale) setExplanationLoading(false);
    });
    return () => { stale = true; };
  }, [evidence, id]);

  if (notFound) return (
    <main>
      <h1>This run isn&rsquo;t available in this workspace</h1>
      <p>The link may be invalid, the run may belong to another workspace, or it may have been removed.</p>
      <Link href="/runs">Back to Runs &amp; Reports</Link>
    </main>
  );
  if (!run) return <main><p role={pollError ? "alert" : "status"}>{pollError ?? "Loading run…"}</p></main>;

  const reached = new Set(run.history.map(([s]) => s));
  const failed = run.status.endsWith("_failed");
  // The server permits archive/restore only for "published" and the failure
  // terminals — never "report_rendered", which is still finishing publication.
  const manageable = run.status === "published" || failed;

  const manageRun = (action: "archive" | "restore") => {
    setManageError(null);
    void apiPost<Partial<RunState>>(
      `/runs/${encodeURIComponent(run.run_id)}/${action}`, {},
    ).then(({ body }) => {
      setRun((prev) => (prev
        ? {
          ...prev,
          management_state:
            body.management_state ?? (action === "archive" ? "archived" : "active"),
        }
        : prev));
    }).catch((caught) => {
      // Visible, actionable failure — the run keeps its current state.
      setManageError(toSafeError(
        caught,
        action === "archive"
          ? "The run could not be archived. Its workspace state is unchanged."
          : "The run could not be restored. Its workspace state is unchanged.",
      ).userMessage);
    });
  };
  // A mapped, product-voiced detail for known failure codes; raw backend text never
  // reaches this surface (unknown codes fall back to the generic copy alone).
  const mappedRunError = run.error?.code
    ? toSafeError(new ApiRequestError({ code: run.error.code }), "")
    : null;
  const runErrorDetail = mappedRunError?.userMessage ? mappedRunError : null;
  const failureCopy = run.status === "system_failed"
    ? run.error?.quota_charged
      ? "The evidence record sealed and used one run from this workspace's allowance, "
        + "but report publication failed after automatic retries. Compute was not rerun "
        + "or charged twice."
      : "The run stopped before its evidence record sealed, after automatic retries. "
        + "Its reservation was released and no run allowance was used."
    : FAILURE_COPY[run.status];
  const symbol = run.spec?.universe?.symbol;
  const descriptor = symbol ? instrumentDescriptor(symbol) : null;
  // The badge follows the dataset's own basis, not the label alone: a CC BY series
  // is stamped USER_UPLOADED by the sealed contract, so on the label alone the top
  // of every bundled report branded licensed data as the reader's own.
  // v1 keeps the basis inside the sealed dataset manifest rather than in a
  // top-level block, so this narrows instead of assuming the v2 shape.
  const evidenceBasis = evidence && "data_provenance" in evidence
    ? evidence.data_provenance?.price_adjustment
    : undefined;
  const sourceLabel = evidence
    ? dataSourceLabel(String(evidence.identity.data_label), evidenceBasis)
    : null;
  const rebuildCheckpoint = evidenceRefusal?.code === "LEGACY_CHECKPOINT_REBUILD_REQUIRED"
    || evidenceRefusal?.code === "ARTIFACT_CONTRACT_REBUILD_REQUIRED"
    ? evidenceRefusal
    : null;
  const currentEvidenceRefusal = evidenceRefusal
    && evidenceRefusal.code !== "LEGACY_CHECKPOINT_REBUILD_REQUIRED"
    && evidenceRefusal.code !== "ARTIFACT_CONTRACT_REBUILD_REQUIRED"
    ? evidenceRefusal
    : null;
  const executionNeedsAttention = run.execution?.state === "worker_unavailable"
    || run.execution?.state === "queue_delayed";

  return (
    <main>
      <header className="report-header">
        <div className="report-header-title">
          <p className="page-kicker">Research report</p>
          <h1>{run.spec?.meta?.name ?? "Untitled research"}</h1>
          <div className="report-header-sub">
            {symbol && <span>{descriptor ?? symbol}</span>}
            {sourceLabel && (
              <span className={`sample-badge${dataLabelBadgeClass(evidence ? String(evidence.identity.data_label) : null, evidenceBasis)}`}>
                {sourceLabel}
              </span>
            )}
            {run.research_mode === "sandbox" && (
              <span className="chip sandbox" data-testid="run-sandbox-badge">
                Sandbox test — test evidence only
              </span>
            )}
            {run.management_state === "archived" && (
              <span className="chip" data-testid="run-archived-badge">Archived</span>
            )}
          </div>
        </div>
        <div className="page-header-actions">
          {/* Compare reads formal v1 evidence only — sandbox test evidence is
              non-formal and never enters a comparison. */}
          {evidence && evidence.evidence_view_version === "v1"
            && evidence.artifact_contract.verified_financial_semantics === true
            && run.research_mode !== "sandbox" && (
            <Link
              className="btn-link"
              href={`/runs?compare=${encodeURIComponent(run.run_id)}`}
              title="Pick a second completed run to compare against this one"
            >
              Compare
            </Link>
          )}
          <Link className="btn-link" href={`/studio?fromRun=${encodeURIComponent(run.run_id)}`}>
            Duplicate
          </Link>
          {manageable && run.management_state !== "archived" && (
            <button
              type="button"
              className="btn-link"
              data-testid="run-archive"
              onClick={() => manageRun("archive")}
            >
              Archive
            </button>
          )}
          {run.management_state === "archived" && (
            <button
              type="button"
              className="btn-link"
              data-testid="run-restore"
              onClick={() => manageRun("restore")}
            >
              Restore
            </button>
          )}
          {evidence && (
            <a
              className="btn-link primary"
              href={`/api/ql/runs/${run.run_id}/report`}
              target="_blank"
              rel="noreferrer"
            >
              Export report
            </a>
          )}
        </div>
      </header>

      {!done && (
        <ul className="timeline" aria-label="Run lifecycle">
          {RUN_STAGES.map(([key, label]) => (
            <li key={key}
              className={[
                reached.has(key) ? "done" : run.status === key ? "active" : "",
                key === "ledger_sealed" && sealPulse ? "sealed-pulse" : "",
              ].filter(Boolean).join(" ")}>
              {label}
            </li>
          ))}
          {failed && <li className="failed">{runStateLabel(run.status)}</li>}
        </ul>
      )}

      {manageError && (
        <div className="notice warn" role="alert" data-testid="run-manage-error">
          <strong>{manageError}</strong>{" "}You can retry, or manage this run from
          Runs &amp; Reports.
        </div>
      )}

      <div aria-live="polite" role="status">
        {pollError && (
          <div className="notice warn">
            <strong>Status update delayed.</strong>{" "}{pollError}
          </div>
        )}
        {failed && !evidence && !rebuildCheckpoint && (
          <>
            {!(run.status === "system_failed" && !evidenceRefusal) && (
              <p className="workspace-status-row">
                <span className="outcome-chip warn">Checks not run</span>
              </p>
            )}
            <div className="notice bad">
              <strong>{runStateLabel(run.status)}.</strong>{" "}
              {failureCopy}
              {runErrorDetail && (
                <>
                  {" "}{runErrorDetail.userMessage}{" "}
                  <span className="error-ref">Ref: {runErrorDetail.reference}</span>
                </>
              )}
            </div>
          </>
        )}
        {!done && !failed && executionNeedsAttention && (
          <div className="notice warn" data-testid="run-execution-delay">
            <strong>
              {run.execution?.state === "worker_unavailable"
                ? "Execution worker temporarily unavailable."
                : "This run is waiting longer than expected."}
            </strong>{" "}
            {run.execution?.message
              ?? "The run remains safely queued and this page will keep checking automatically."}
            {typeof run.execution?.queued_for_seconds === "number" && (
              <> Queued for about {Math.max(1, Math.round(run.execution.queued_for_seconds))} seconds.</>
            )}
          </div>
        )}
        {!done && !failed && !executionNeedsAttention && (
          <p>
            {run.execution?.state === "waiting_for_worker"
              ? "Waiting for the execution worker…"
              : "Working…"}{" "}
            This page refreshes automatically.
          </p>
        )}
      </div>

      {evidenceWorthFetching && !evidence && !evidenceRefusal && (
        <p role="status">Loading the sealed research report…</p>
      )}

      {rebuildCheckpoint && (
        <section aria-labelledby="legacy-checkpoint-title"
          data-testid="legacy-checkpoint-rebuild">
          <div className="notice warn">
            <h2 id="legacy-checkpoint-title" style={{ marginTop: 0 }}>
              This preserved run needs to be rebuilt
            </h2>
            <p>
              {rebuildCheckpoint.code === "LEGACY_CHECKPOINT_REBUILD_REQUIRED"
                ? "This run was sealed before the current confirmation and integrity "
                  + "checks."
                : "This run's sealed contract is not registered for historical "
                  + "presentation."}{" "}
              The old files have not been deleted or changed, but no financial values
              are shown under a different contract.{" "}
              <span className="error-ref">Ref: {rebuildCheckpoint.code}</span>
            </p>
            {rebuildCheckpoint.rebuild.available ? (
              <Link className="btn-link primary" href="/studio">
                Open Research Studio to create the replacement run
              </Link>
            ) : (
              <p role="status">
                Its saved accepted spec is unavailable, so this run cannot be rebuilt
                automatically.
              </p>
            )}
          </div>
        </section>
      )}

      {currentEvidenceRefusal && (
        <section aria-label="Evidence unavailable">
          <p className="workspace-status-row">
            <span className="outcome-chip warn">Checks not run</span>
          </p>
          <div className="notice bad" data-testid="evidence-refusal">
            <strong>
              {currentEvidenceRefusal.code === "EVIDENCE_INTEGRITY_FAILURE"
                ? "Evidence integrity check failed."
                : "No sealed evidence is available."}
            </strong>{" "}
            {toSafeError(
              new ApiRequestError({ code: currentEvidenceRefusal.code }),
              "The sealed evidence for this run could not be loaded.",
            ).userMessage}{" "}
            No partial values are shown for a run whose sealed artifacts cannot be
            re-read and hash-checked.{" "}
            <span className="error-ref">Ref: {currentEvidenceRefusal.code}</span>
          </div>
        </section>
      )}

      {evidence && (evidence.evidence_view_version === "v3"
        ? evidence.identity.manifest_id === `mfst-${id}`
        : evidence.identity.run_id === id) && (
        <EvidenceWorkspace
          view={evidence}
          explanation={explanation}
          explanationLoading={explanationLoading}
          copilot={copilot}
          copilotUnavailable={copilotUnavailable}
          readingLevel={readingLevel}
          // The control travels with the report so it can sit beside the report's
          // own view controls. It must never precede the verdict and the sealed
          // metric tiles, which are required to reach the first viewport.
          readingLevelControl={(
            <ReadingLevelSwitch
              value={readingLevel}
              onChange={changeReadingLevel}
              saving={savingReadingLevel}
              saveError={readingLevelError}
            />
          )}
        />
      )}
    </main>
  );
}
