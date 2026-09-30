"use client";

import { useEffect, useMemo, useState } from "react";

import { ApiRequestError, toSafeError, type SafeError } from "../lib/errors";
import { integer, sessionDate } from "../lib/format";

/**
 * Licensed-provider acquisition flow. Credential-free by design: readiness comes from
 * GET /market-data/config, and every state that is not fully activated renders an
 * operational status card — never an API-key input or a pretend Connect button.
 */

export interface MarketDataConfig {
  status: string;
  provider: string | null;
  daily_bars: boolean;
  report_export?: boolean;
  message: string;
}

interface ResolvedInstrument {
  provider: string;
  instrument: {
    instrument_id: string;
    symbol: string;
    display_name: string;
    asset_class: string;
    currency: string;
    mic: string;
    country?: string;
  };
  frequency: string;
  adjustment_mode: string;
  return_basis: string;
  required_attribution: string;
}

/** Mirror of acquisition_public_view: the job state machine is
 * queued → resolving → fetching → validated → sealed | failed.
 * The ONLY successful terminal state is "sealed". */
type AcquisitionStatus =
  | "queued" | "resolving" | "fetching" | "validated" | "sealed" | "failed";

interface AcquisitionReceipt {
  acquisition_id: string;
  symbol: string;
  requested_start: string;
  requested_end: string;
  display_name: string;
  status: AcquisitionStatus | string;
  dataset_id: string | null;
}

const ACQUISITION_STATUS_LABELS: Record<AcquisitionStatus, string> = {
  queued: "Queued",
  resolving: "Resolving instrument",
  fetching: "Fetching observations",
  validated: "Validated — sealing",
  sealed: "Sealed",
  failed: "Failed",
};

function acquisitionStatusLabel(status: string): string {
  return ACQUISITION_STATUS_LABELS[status as AcquisitionStatus] ?? "In progress";
}

/** Success means exactly the sealed terminal state — never an unknown status. */
function isSealed(receipt: AcquisitionReceipt): boolean {
  return receipt.status === "sealed" && Boolean(receipt.dataset_id);
}

const STATUS_TITLES: Record<string, string> = {
  not_configured: "No licensed provider connected",
  unsupported_configuration: "Configured provider isn't supported",
  configuration_incomplete: "Provider configuration is incomplete",
  configured_not_activated: "Provider configured — awaiting activation",
  blocked_calendar_unavailable: "Activation blocked — session calendar missing",
  activated: "Licensed daily data is active",
};

const OPERATOR_STEPS: Record<string, string> = {
  not_configured:
    "An operator must connect a licensed daily-data provider on the server. "
    + "Until then, import an authorized CSV instead.",
  unsupported_configuration:
    "An operator must switch the server to a supported market-data provider.",
  configuration_incomplete:
    "An operator must complete the provider credential and the versioned "
    + "commercial-use policy on the server.",
  configured_not_activated:
    "An operator must review the contract and explicitly activate licensed data. "
    + "Nothing runs before that decision.",
  blocked_calendar_unavailable:
    "An operator must install and review a pinned exchange-session calendar "
    + "before licensed data can be served.",
};

async function readApi<T>(response: Response): Promise<T> {
  const payload: unknown = await response.json().catch(() => null);
  if (response.ok && payload) return payload as T;
  const detail = payload && typeof payload === "object" && "detail" in payload
    ? (payload as { detail?: string | { code?: string; message?: string } }).detail
    : null;
  if (typeof detail === "string") {
    throw new ApiRequestError({ status: response.status, detailMessage: detail });
  }
  throw new ApiRequestError({
    status: response.status,
    code: detail?.code,
    detailMessage: detail?.message,
  });
}

function newIdempotencyKey(): string {
  const uuid = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
  return `ql-acq-${uuid}`;
}

export default function LicensedProviderPanel({
  config, onDatasetSealed,
}: {
  config: MarketDataConfig | null;
  onDatasetSealed: () => void;
}) {
  const [symbol, setSymbol] = useState("");
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState<ResolvedInstrument | null>(null);
  const [instrumentConfirmed, setInstrumentConfirmed] = useState(false);
  const [start, setStart] = useState("2015-01-01");
  const [end, setEnd] = useState("2024-12-31");
  const [displayName, setDisplayName] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [receipt, setReceipt] = useState<AcquisitionReceipt | null>(null);
  const [error, setError] = useState<SafeError | null>(null);
  // One stable retry key per submitted request identity: retries never mint a new
  // key, so the server can never create duplicates for the same user intent.
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);

  const requestIdentity = useMemo(
    () => [resolved?.instrument.instrument_id ?? "", start, end].join("|"),
    [resolved, start, end],
  );
  useEffect(() => {
    // A different instrument or window is a different request: it gets a fresh key.
    setIdempotencyKey(newIdempotencyKey());
  }, [requestIdentity]);

  if (!config) {
    return (
      <div className="data-panel data-progress-panel" role="status">
        <span className="data-spinner" aria-hidden="true" />
        <div>
          <p className="data-eyebrow">Licensed provider</p>
          <h2>Checking provider readiness…</h2>
        </div>
      </div>
    );
  }

  if (config.status !== "activated") {
    const title = STATUS_TITLES[config.status] ?? "Licensed data is unavailable";
    const step = OPERATOR_STEPS[config.status]
      ?? "An operator must review the provider configuration on the server.";
    return (
      <div className="data-panel data-enter" data-testid="licensed-status-card">
        <div className="data-panel-head">
          <div>
            <p className="data-eyebrow">Licensed provider</p>
            <h2>{title}</h2>
          </div>
          <span className="data-state attention">Not active</span>
        </div>
        <div className="data-subsection" style={{ borderTop: 0, paddingTop: 0 }}>
          <p style={{ margin: "0 0 12px", maxWidth: "64ch" }}>{config.message}</p>
          <div className="data-quality-grid" style={{ margin: "0 0 14px" }}>
            <div>
              <span>Daily bars</span>
              <strong>{config.daily_bars ? "Enabled" : "Blocked"}</strong>
            </div>
            <div>
              <span>Report export</span>
              <strong>{config.report_export ? "Enabled" : "Blocked"}</strong>
            </div>
            <div>
              <span>Provider</span>
              <strong>{config.provider ?? "None"}</strong>
            </div>
          </div>
          <div className="notice" data-testid="licensed-next-step">
            <strong>Next step (operator).</strong>{" "}{step}
          </div>
          <p style={{ margin: "10px 0 0", fontSize: "0.84rem", color: "var(--ink-soft)" }}>
            Provider credentials never pass through this browser. In the meantime, the
            Upload CSV path is fully available for data you are authorized to use.
          </p>
        </div>
      </div>
    );
  }

  async function resolveInstrument() {
    setResolving(true);
    setError(null);
    setResolved(null);
    setInstrumentConfirmed(false);
    setReceipt(null);
    try {
      const response = await fetch("/api/ql/market-data/instruments/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ symbol: symbol.trim().toUpperCase() }),
      });
      const body = await readApi<ResolvedInstrument>(response);
      setResolved(body);
      setDisplayName(`${body.instrument.display_name} · daily`);
    } catch (caught) {
      setError(toSafeError(caught, "The symbol could not be resolved."));
    } finally {
      setResolving(false);
    }
  }

  async function requestAcquisition() {
    if (!resolved || !instrumentConfirmed) return;
    setRequesting(true);
    setError(null);
    try {
      const response = await fetch("/api/ql/market-data/acquisitions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          symbol: resolved.instrument.symbol,
          start,
          end,
          adjustment_mode: resolved.adjustment_mode,
          confirmed_instrument_id: resolved.instrument.instrument_id,
          display_name: displayName.trim(),
          confirmed: true,
        }),
      });
      const body = await readApi<{ acquisition: AcquisitionReceipt }>(response);
      setReceipt(body.acquisition);
      if (isSealed(body.acquisition)) {
        onDatasetSealed();
      }
    } catch (caught) {
      setError(toSafeError(caught, "The licensed dataset could not be acquired."));
    } finally {
      setRequesting(false);
    }
  }

  const instrument = resolved?.instrument;

  return (
    <div className="data-panel data-enter" data-testid="licensed-flow">
      <div className="data-panel-head">
        <div>
          <p className="data-eyebrow">Licensed provider · {config.provider}</p>
          <h2>Acquire a licensed daily dataset</h2>
        </div>
        <span className="data-state ready">Active</span>
      </div>

      {error && (
        <div className="actionable-error" role="alert" style={{ margin: "0 26px 14px" }}
          data-testid="licensed-error">
          <strong>{error.userMessage}</strong>
          {error.reference && <span className="error-ref">Ref: {error.reference}</span>}
          <button type="button" onClick={() => (receipt || !resolved ? resolveInstrument() : requestAcquisition())}>
            Try again
          </button>
        </div>
      )}

      <section className="data-subsection" aria-labelledby="licensed-symbol-heading"
        style={{ borderTop: 0 }}>
        <div className="data-subhead">
          <div><span className="data-index">01</span><h3 id="licensed-symbol-heading">Instrument</h3></div>
          <span className={resolved ? "data-state ready" : "data-state neutral"}>
            {resolved ? "Resolved" : "Enter a symbol"}
          </span>
        </div>
        <div className="field-row" style={{ alignItems: "flex-end" }}>
          <div className="field" style={{ maxWidth: 220 }}>
            <label htmlFor="licensed-symbol">Ticker symbol</label>
            <input id="licensed-symbol" value={symbol} maxLength={15}
              placeholder="e.g. QQQ" autoCapitalize="characters"
              onChange={(event) => setSymbol(event.target.value.toUpperCase())} />
          </div>
          <button type="button" className="primary" disabled={!symbol.trim() || resolving}
            onClick={resolveInstrument}>
            {resolving ? "Resolving…" : "Resolve instrument"}
          </button>
        </div>
        {instrument && (
          <div className="data-review-banner ready" style={{ margin: "14px 0 0" }}
            data-testid="licensed-instrument-review">
            <div className="data-review-mark" aria-hidden="true">✓</div>
            <div>
              <strong>{instrument.display_name} ({instrument.symbol})</strong>
              <p>
                {instrument.asset_class} · {instrument.mic} · {instrument.currency} ·
                daily bars · {resolved?.return_basis}
              </p>
              <p style={{ marginTop: 4 }}>
                Attribution shown with this data: {resolved?.required_attribution}
              </p>
            </div>
          </div>
        )}
        {instrument && (
          <label className="data-check-row" style={{ marginTop: 12 }}>
            <input type="checkbox" checked={instrumentConfirmed}
              onChange={(event) => setInstrumentConfirmed(event.target.checked)} />
            <span><strong>This is the instrument I intend to acquire.</strong>
              <small>The canonical identity above — not the typed ticker — is what gets
              sealed into the dataset receipt.</small></span>
          </label>
        )}
      </section>

      {instrument && instrumentConfirmed && !receipt && (
        <section className="data-subsection" aria-labelledby="licensed-coverage-heading">
          <div className="data-subhead">
            <div><span className="data-index">02</span><h3 id="licensed-coverage-heading">Coverage &amp; name</h3></div>
          </div>
          <div className="field-row">
            <div className="field">
              <label htmlFor="licensed-start">Start</label>
              <input id="licensed-start" type="date" value={start}
                onChange={(event) => setStart(event.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="licensed-end">End</label>
              <input id="licensed-end" type="date" value={end}
                onChange={(event) => setEnd(event.target.value)} />
            </div>
            <div className="field" style={{ flex: "2 1 240px" }}>
              <label htmlFor="licensed-name">Dataset name</label>
              <input id="licensed-name" value={displayName} maxLength={80}
                onChange={(event) => setDisplayName(event.target.value)} />
            </div>
          </div>
          <div className="data-seal-bar" style={{ margin: "16px 0 0" }}>
            <div>
              <strong>Request the licensed acquisition</strong>
              <small>
                One sealed, immutable dataset for {instrument.display_name}{" "}
                ({instrument.symbol}), {sessionDate(start)} → {sessionDate(end)}.
                Retrying this request cannot create duplicates.
              </small>
            </div>
            <button type="button" className="primary"
              disabled={requesting || !displayName.trim()}
              onClick={requestAcquisition}
              data-testid="licensed-acquire">
              {requesting ? "Acquiring…" : "Acquire dataset"}
            </button>
          </div>
        </section>
      )}

      {receipt && (
        <section className="data-subsection" aria-labelledby="licensed-receipt-heading"
          data-testid="licensed-receipt">
          <div className="data-subhead">
            <div><span className="data-index">03</span><h3 id="licensed-receipt-heading">Acquisition receipt</h3></div>
            <span className={isSealed(receipt) ? "data-state ready"
              : receipt.status === "failed" ? "data-state attention" : "data-state neutral"}>
              {acquisitionStatusLabel(receipt.status)}
            </span>
          </div>
          {isSealed(receipt) ? (
            <div className="data-no-warnings">
              <span aria-hidden="true">✓</span>
              <p>
                <strong>{receipt.display_name} is sealed.</strong><br />
                {receipt.symbol} · {sessionDate(receipt.requested_start)} →{" "}
                {sessionDate(receipt.requested_end)}. It now appears in the dataset
                library with its full licensed provenance.
              </p>
            </div>
          ) : (
            <p className="data-profile-note">
              The acquisition is {acquisitionStatusLabel(receipt.status).toLowerCase()}
              {" "}and is not sealed yet. This page keeps the receipt; retrying the
              request cannot create a duplicate.
            </p>
          )}
          <details className="drawer" style={{ marginTop: 12 }}>
            <summary>Request details</summary>
            <div className="drawer-body">
              <dl className="data-provenance" style={{ margin: 0 }}>
                <div><dt>Acquisition</dt><dd><code>{receipt.acquisition_id}</code></dd></div>
                <div><dt>Status</dt><dd>{receipt.status}</dd></div>
                {receipt.dataset_id && (
                  <div><dt>Dataset</dt><dd><code>{receipt.dataset_id}</code></dd></div>
                )}
              </dl>
            </div>
          </details>
          <p style={{ marginTop: 10 }}>
            <button type="button" className="linkish" onClick={() => {
              setReceipt(null);
              setResolved(null);
              setSymbol("");
              setInstrumentConfirmed(false);
            }}>
              Acquire another dataset
            </button>
          </p>
        </section>
      )}
    </div>
  );
}
