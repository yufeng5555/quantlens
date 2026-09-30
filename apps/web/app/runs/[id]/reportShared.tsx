"use client";

import { useState } from "react";
import type { CheckStatus, MetricSet } from "@schema/ts/evidence";
import { exposure, money, num, pct } from "../../lib/format";
import { checkFailureGuidance, checkStatusLabel, statusChipClass } from "../../lib/labels";
import { DEFAULT_READING_LEVEL, type ReadingLevel } from "./readingLevel";

/** Shared report primitives used by both the v1 and v2 evidence renderers. */

export function StatusChip({ status, label }: { status: CheckStatus | "NOT RUN"; label?: string }) {
  return (
    <span className={`status-chip ${statusChipClass(status)}`}>
      {label ? `${label}: ` : ""}{checkStatusLabel(status)}
    </span>
  );
}

export function CopyId({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="copy-id"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/**
 * One vocabulary per metric row. The technical label is what a professional
 * report shows; the plain label restates the same sealed value in ordinary
 * words. Both levels read the identical value through the identical formatter —
 * only the row's name changes.
 */
const METRIC_ROWS: {
  key: string;
  label: string;
  plainLabel: string;
  value: (metrics: MetricSet) => string;
}[] = [
  {
    key: "total_return",
    label: "Price return",
    plainLabel: "Change in balance over the period",
    value: (m) => pct(m.total_return),
  },
  {
    key: "cagr",
    label: "CAGR",
    plainLabel: "Same result stated as a yearly rate",
    value: (m) => pct(m.cagr),
  },
  {
    key: "ann_vol",
    label: "Annualized volatility",
    plainLabel: "How bumpy the ride was",
    value: (m) => pct(m.ann_vol),
  },
  {
    key: "sharpe",
    label: "Sharpe (rf = 0)",
    plainLabel: "Result measured against the bumpiness",
    value: (m) => num(m.sharpe),
  },
  {
    key: "max_drawdown",
    label: "Max drawdown",
    plainLabel: "Deepest fall from a previous high",
    value: (m) => pct(m.max_drawdown),
  },
  {
    key: "n_trades",
    label: "Trades (fills)",
    plainLabel: "Times it bought or sold",
    value: (m) => String(m.n_trades ?? "—"),
  },
  {
    key: "total_costs",
    label: "Total costs paid",
    plainLabel: "Trading costs paid along the way",
    value: (m) => money(m.total_costs),
  },
  {
    key: "exposure",
    label: "Time in market",
    plainLabel: "Share of the period actually invested",
    value: (m) => exposure(m.exposure),
  },
  {
    key: "initial_capital",
    label: "Initial capital (sealed)",
    plainLabel: "Starting balance",
    value: (m) => money(m.initial_capital),
  },
  {
    key: "final_equity",
    label: "Final equity",
    plainLabel: "Ending balance",
    value: (m) => money(m.final_equity),
  },
];

export function MetricsTable({ metrics, benchmark, benchmarkSymbol, readingLevel }: {
  metrics: MetricSet;
  benchmark: MetricSet;
  benchmarkSymbol: string;
  readingLevel?: ReadingLevel;
}) {
  const plain = (readingLevel ?? DEFAULT_READING_LEVEL) === "novice";
  return (
    <div className="tablewrap" role="region" tabIndex={0} aria-label="Segment metrics table">
      <table>
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">
              {plain ? "This rule (aligned to the same start)" : "Strategy (benchmark-aligned)"}
            </th>
            <th scope="col">
              {plain
                ? `Just buying ${benchmarkSymbol} and holding it`
                : `Benchmark (${benchmarkSymbol}, hold from first decision)`}
            </th>
          </tr>
        </thead>
        <tbody>
          {METRIC_ROWS.map((row) => (
            <tr key={row.key}>
              <th scope="row">
                {plain ? (
                  <>
                    {row.plainLabel}
                    <span className="metric-technical">{row.label}</span>
                  </>
                ) : row.label}
              </th>
              <td>{row.value(metrics)}</td>
              <td>{row.value(benchmark)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** What a failed check means, and what to do next.
 *
 * The report used to end at the verdict: it named the check a rule failed and
 * stopped there, leaving the reader holding a "no" with nowhere to take it. The
 * engine already knows why, and what would change the answer — it just never
 * said so.
 *
 * Static copy keyed to the check id (see `CHECK_FAILURE_GUIDANCE`), never
 * generated, so the product keeps its promise that no number in it comes from a
 * language model. Renders nothing for a check that passed or could not run.
 */
export function CheckGuidance({ id, status }: { id: string; status: string }) {
  const guidance = checkFailureGuidance(id, status);
  if (!guidance) return null;
  return (
    <div className="fals-guidance" data-testid={`check-guidance-${id}`}>
      <p>{guidance.meaning}</p>
      <p><strong>What to try next.</strong>{" "}{guidance.next}</p>
    </div>
  );
}

export function FindingEvidence({ evidence }: { evidence: Record<string, unknown> }) {
  // Structured numeric evidence sealed with the finding — shown, not summarized away.
  const entries = Object.entries(evidence).filter(
    ([, v]) => typeof v === "number" || typeof v === "string" || v === null);
  if (!entries.length) return null;
  return (
    <dl className="fals-evidence">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt>{key.replaceAll("_", " ")}</dt>
          <dd>
            {typeof value === "number"
              ? (Math.abs(value) < 10 ? value.toFixed(4) : value.toLocaleString("en-US"))
              : String(value ?? "—")}
          </dd>
        </div>
      ))}
    </dl>
  );
}
