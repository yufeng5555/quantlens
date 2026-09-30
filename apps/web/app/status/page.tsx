"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface WorkerHealth {
  available: boolean;
  state: string;
  reason: string | null;
  last_seen_at: string | null;
  heartbeat_age_seconds: number | null;
  max_age_seconds: number | null;
}

interface StorageHealth {
  measured: boolean;
  free_bytes: number | null;
  total_bytes: number | null;
  floor_bytes: number;
  /** true/false are measurements; null means the volume could not be measured. */
  sufficient: boolean | null;
  state: string;
}

interface HealthResponse {
  ok: boolean;
  ready: boolean;
  worker: WorkerHealth;
  /** Optional so an older API that predates storage reporting still renders. */
  storage?: StorageHealth | null;
}

type StatusState =
  | { kind: "loading" }
  | { kind: "loaded"; health: HealthResponse; checkedAt: Date }
  | { kind: "unavailable"; checkedAt: Date };

const REFRESH_INTERVAL_MS = 15_000;

function isHealthResponse(value: unknown): value is HealthResponse {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<HealthResponse>;
  return typeof candidate.ok === "boolean"
    && typeof candidate.ready === "boolean"
    && !!candidate.worker
    && typeof candidate.worker.available === "boolean"
    && typeof candidate.worker.state === "string";
}

function secondsLabel(value: number): string {
  const safe = Math.max(0, value);
  if (safe < 0.05) return "less than 0.1 seconds";
  if (safe < 10) return `${safe.toFixed(1)} seconds`;
  return `${Math.round(safe)} seconds`;
}

function workerStateLabel(state: string): string {
  const labels: Record<string, string> = {
    ready: "Ready",
    busy: "Processing a run",
    starting: "Starting",
    recovering: "Recovering",
    stopped: "Stopped",
    not_started: "Not started",
    unavailable: "Heartbeat unavailable",
  };
  return labels[state] ?? "Status not recognized";
}

function workerReason(reason: string | null): string {
  const reasons: Record<string, string> = {
    worker_not_started: "The execution service has not announced readiness.",
    worker_stopped: "The execution service has stopped.",
    heartbeat_stale: "The execution service has not checked in within its expected window.",
    control_plane_unavailable: "The control plane could not read worker status.",
  };
  return reason ? reasons[reason] ?? "The execution service is not currently ready." : "";
}

function bytesLabel(value: number): string {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let scaled = Math.max(0, value);
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || scaled >= 100 || Number.isInteger(scaled) ? 0 : 1;
  // Truncate rather than round. Rounding up produced "Free space is 64.0 MB, below
  // the 64 MB that must remain" — a sentence that reads as its own contradiction —
  // and a free-space figure should never be reported larger than it is.
  const factor = 10 ** digits;
  return `${(Math.floor(scaled * factor) / factor).toFixed(digits)} ${units[unit]}`;
}

function storageSentence(storage: StorageHealth): string {
  if (!storage.measured || storage.free_bytes === null) {
    return "Free space on this workspace's volume could not be measured, so this page "
      + "cannot confirm there is room to store new work.";
  }
  const free = bytesLabel(storage.free_bytes);
  const total = storage.total_bytes !== null ? ` of ${bytesLabel(storage.total_bytes)}` : "";
  const floor = bytesLabel(storage.floor_bytes);
  // Runs are not the only thing the floor gates — uploads, dataset seals and the
  // bundle import check it too — so this does not name runs alone.
  return storage.sufficient === false
    ? `Free space is ${free}${total}, below the ${floor} that must remain before `
      + "anything new is written. Sealed evidence already stored is unaffected."
    : `Free space is ${free}${total}. New runs, uploads and dataset imports are `
      + `accepted only while at least ${floor} remains.`;
}

function checkedTime(value: Date): string {
  return value.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function SystemStatusPage() {
  const [status, setStatus] = useState<StatusState>({ kind: "loading" });
  const [refreshing, setRefreshing] = useState(false);
  const activeRequest = useRef(false);

  const refresh = useCallback(async () => {
    if (activeRequest.current) return;
    activeRequest.current = true;
    setRefreshing(true);
    try {
      const response = await fetch("/api/ql/health", { cache: "no-store" });
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok || !isHealthResponse(payload) || !payload.ok) {
        throw new Error("health response unavailable");
      }
      setStatus({ kind: "loaded", health: payload, checkedAt: new Date() });
    } catch {
      // Health pages should never reveal transport or server internals. The operator
      // gets a fail-closed product implication and can retry the live check.
      setStatus({ kind: "unavailable", checkedAt: new Date() });
    } finally {
      activeRequest.current = false;
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const health = status.kind === "loaded" ? status.health : null;
  const storage = health?.storage ?? null;
  // Absent (an API that predates storage reporting) and unmeasurable both mean
  // "no evidence of a full volume", which must not be reported as one.
  const storageExhausted = storage?.sufficient === false;
  // The worker cards report the worker. Admission additionally requires room to
  // write, so a healthy worker on a full volume must not read as "ready".
  const workerAvailable = health?.worker.available === true;
  const workerReady = health?.ready === true && workerAvailable && !storageExhausted;
  const apiAvailable = health?.ok === true;
  const checkedAt = status.kind === "loading" ? null : status.checkedAt;
  // A full volume gets its own headline. Left in the worker branch it read
  // "Research execution is temporarily unavailable", which named the wrong
  // subsystem — the worker is fine — and called "temporary" a condition that
  // resolves only when an operator acts.
  const headline = status.kind === "loading"
    ? "Checking research services"
    : workerReady
      ? "Research execution is available"
      : apiAvailable && storageExhausted
        ? "New research runs are paused: the workspace volume is out of room"
        : apiAvailable
          ? "Research execution is temporarily unavailable"
          : "Research service status cannot be confirmed";
  const tone = status.kind === "loading" ? "checking" : workerReady ? "operational" : "attention";

  return (
    <main className="status-main">
      <header className={`status-hero ${tone}`} aria-live="polite">
        <div>
          <p className="page-kicker">System Status</p>
          <div className="status-title-row">
            <span className="status-live-dot" aria-hidden="true" />
            <h1>{headline}</h1>
          </div>
          <p className="status-lede">
            A live readiness check for the QuantLens research API and execution worker.
            This page reports current state only; it does not claim historical uptime or
            an availability SLA.
          </p>
        </div>
        <div className="status-refresh">
          <button type="button" onClick={() => void refresh()} disabled={refreshing}>
            {refreshing ? "Checking…" : "Refresh status"}
          </button>
          <span>
            {checkedAt ? `Checked at ${checkedTime(checkedAt)}` : "Opening live check…"}
          </span>
        </div>
      </header>

      <section className="status-grid" aria-label="Current service readiness">
        <article className={`status-service-card ${apiAvailable ? "operational" : "attention"}`}>
          <div className="status-service-head">
            <span>Control plane</span>
            <span className="status-state-chip">{apiAvailable ? "Available" : "Not confirmed"}</span>
          </div>
          <h2>Research API</h2>
          <p>
            {apiAvailable
              ? "The interface received a valid live response from the research API."
              : "The interface cannot currently verify the API, so run admission is not confirmed."}
          </p>
        </article>

        <article className={`status-service-card ${workerAvailable ? "operational" : "attention"}`}>
          <div className="status-service-head">
            <span>Execution layer</span>
            <span className="status-state-chip">
              {!workerAvailable
                ? "Unavailable"
                /* "Ready for admission" would be false while admission is being
                   refused for room, so on a full volume it says only what it can
                   back: the worker itself is healthy. */
                : storageExhausted ? "Worker healthy" : "Ready for admission"}
            </span>
          </div>
          <h2>Research worker</h2>
          <p>
            {health
              ? `Worker state: ${workerStateLabel(health.worker.state)}. ${workerReason(health.worker.reason)}`
              : "Worker readiness cannot be confirmed until the API health check responds."}
          </p>
        </article>

        <article className={`status-service-card ${workerAvailable ? "operational" : "neutral"}`}>
          <div className="status-service-head">
            <span>Liveness signal</span>
            <span className="status-state-chip">
              {health?.worker.heartbeat_age_seconds != null ? "Observed" : "Not available"}
            </span>
          </div>
          <h2>Worker heartbeat</h2>
          {health?.worker.heartbeat_age_seconds != null ? (
            <>
              <p>
                Last heartbeat was seen {secondsLabel(health.worker.heartbeat_age_seconds)} ago.
                {health.worker.max_age_seconds != null
                  ? ` The readiness window is ${secondsLabel(health.worker.max_age_seconds)}.`
                  : ""}
              </p>
              {health.worker.last_seen_at && (
                <time dateTime={health.worker.last_seen_at}>
                  Last signal: {new Date(health.worker.last_seen_at).toLocaleString()}
                </time>
              )}
            </>
          ) : (
            <p>No current heartbeat timestamp is available.</p>
          )}
        </article>

        <article
          className={`status-service-card ${
            storageExhausted ? "attention" : storage?.measured ? "operational" : "neutral"
          }`}
        >
          <div className="status-service-head">
            <span>Storage</span>
            <span className="status-state-chip">
              {storageExhausted
                ? "Out of room"
                : storage?.measured
                  ? "Room available"
                  : "Not measured"}
            </span>
          </div>
          <h2>Workspace volume</h2>
          <p>
            {storage
              ? storageSentence(storage)
              : "Free space cannot be reported until the API health check responds."}
          </p>
        </article>
      </section>

      <section className={`status-implication ${workerReady ? "operational" : "attention"}`}>
        <p className="status-implication-label">What this means for your research</p>
        {status.kind === "loading" ? (
          <h2>Wait for the live check before starting a new run.</h2>
        ) : workerReady ? (
          <>
            <h2>You can start a new research run.</h2>
            <p>
              The API can admit work and a compatible execution worker is reporting
              within its heartbeat window. This readiness signal does not validate a
              strategy or guarantee how long a run will take.
            </p>
          </>
        ) : apiAvailable && storageExhausted ? (
          <>
            <h2>Do not start a new research run yet.</h2>
            <p>
              This workspace&rsquo;s volume is out of room, so QuantLens rejects new
              submissions before enqueueing work or reserving a run allowance.
              Evidence already sealed is unaffected, but an operator has to free
              space or grow the volume before new research can be stored.
            </p>
          </>
        ) : apiAvailable ? (
          <>
            <h2>Do not start a new research run yet.</h2>
            <p>
              QuantLens rejects new submissions before enqueueing work or reserving a
              run allowance when no healthy worker is available. Existing queued work
              remains stored and can resume when execution recovers.
            </p>
          </>
        ) : (
          <>
            <h2>Do not start a research run until status can be confirmed.</h2>
            <p>
              The interface cannot confirm whether the control plane or execution worker
              can accept work. Refresh this page after the local services recover.
            </p>
          </>
        )}
      </section>

      <footer className="status-boundary">
        <strong>Scope of this page</strong>
        <p>
          These are point-in-time operational signals from the current workspace. They
          do not measure historical uptime, data quality, model validity, research
          correctness, or future service availability.
        </p>
        <span>Refreshes every 15 seconds while this page is open.</span>
      </footer>
    </main>
  );
}
