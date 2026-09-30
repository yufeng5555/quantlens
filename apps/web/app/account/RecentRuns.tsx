"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { apiGet } from "../studio/lib";
import { instantUTC } from "../lib/format";
import {
  isTerminalFailure,
  runOutcome,
  runStateLabel,
  type BatteryStatus,
} from "../lib/labels";
import styles from "./recent-runs.module.css";

interface RecentRun {
  run_id: string;
  title: string;
  status: string;
  created_at: string;
  updated_at: string;
  battery_status: BatteryStatus;
  evidence_available: boolean;
  failed_checks?: number | null;
}

interface RecentRunsResponse {
  runs: RecentRun[];
}

function statusTone(status: string): string {
  if (status === "published" || status === "report_rendered") return styles.ready;
  if (isTerminalFailure(status)) return styles.failed;
  return styles.active;
}

function RunRow({ run }: { run: RecentRun }) {
  const outcome = runOutcome(run.status, run.battery_status, run.failed_checks ?? undefined);
  const openLabel = run.evidence_available ? "Open report" : "Reopen run";

  return (
    <li className={styles.run} data-testid={`recent-run-${run.run_id}`}>
      <div className={styles.runMain}>
        <div className={styles.titleRow}>
          <h3>{run.title}</h3>
          <span className={`${styles.runStatus} ${statusTone(run.status)}`}>
            {runStateLabel(run.status)}
          </span>
        </div>
        <div className={styles.meta}>
          <time dateTime={run.created_at}>{instantUTC(run.created_at)}</time>
          <span aria-hidden="true">·</span>
          <span className={`outcome-chip ${outcome.tone}`}>
            {outcome.label}
          </span>
        </div>
      </div>
      <div className={styles.actions}>
        <Link className="btn-link primary" href={`/runs/${run.run_id}`}>
          {openLabel}
        </Link>
        <Link
          className="btn-link"
          href={`/studio?fromRun=${encodeURIComponent(run.run_id)}`}
          aria-label={`Duplicate and edit ${run.title}`}
        >
          Duplicate &amp; edit
        </Link>
      </div>
    </li>
  );
}

export default function RecentRuns() {
  const [runs, setRuns] = useState<RecentRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadRuns = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { body } = await apiGet<RecentRunsResponse>("/runs?limit=10");
      setRuns(body.runs ?? []);
    } catch {
      setRuns([]);
      setError("Recent research could not be loaded. Check that the workspace service is running, then retry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  return (
    <section className={styles.section} aria-labelledby="recent-research-title">
      <div className={styles.heading}>
        <div>
          <p className="account-kicker">Research workspace</p>
          <h2 id="recent-research-title">Recent research</h2>
          <p>Reopen evidence or start a new draft from a previous research specification.</p>
        </div>
        <Link className="btn-link primary" href="/studio">New research</Link>
      </div>

      {loading ? (
        <div className={styles.state} role="status">Loading recent research&hellip;</div>
      ) : error ? (
        <div className={`${styles.state} ${styles.error}`} role="alert">
          <div>
            <strong>Recent research is temporarily unavailable.</strong>
            <p>{error}</p>
          </div>
          <button type="button" onClick={() => void loadRuns()}>Retry</button>
        </div>
      ) : runs.length === 0 ? (
        <div className={styles.state}>
          <div>
            <strong>No research runs yet.</strong>
            <p>Confirm a strategy in Research Studio to create your first auditable run.</p>
          </div>
          <Link className="btn-link" href="/studio">Open Research Studio</Link>
        </div>
      ) : (
        <ol className={styles.list} aria-label="Recent research runs">
          {runs.map((run) => <RunRow key={run.run_id} run={run} />)}
        </ol>
      )}
    </section>
  );
}

