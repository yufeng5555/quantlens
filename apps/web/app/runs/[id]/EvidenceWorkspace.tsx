"use client";

import { useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import type {
  ArtifactRef, CheckStatus, EvidenceView, EvidenceViewV1, ExplanationViewV1, MetricSet,
  SensitivityCell,
} from "@schema/ts/evidence";
import EquityChart from "../../components/EquityChart";
import ExplanationPanel from "./ExplanationPanel";
import EvidenceWorkspaceV2 from "./EvidenceWorkspaceV2";
import EvidenceWorkspaceV3 from "./EvidenceWorkspaceV3";
import { isRenderableEvidenceV3 } from "./evidenceV3Guard";
import type { ResearchCopilotView } from "./researchCopilotContract";
import {
  CheckGuidance, CopyId, FindingEvidence, MetricsTable, StatusChip,
} from "./reportShared";
import {
  DEFAULT_READING_LEVEL, PlainLanguageSummary, TechnicalBlock,
  type PlainCheckFact, type PlainReportFacts, type ReadingLevel,
} from "./readingLevel";
import { exposure, instantUTC, money, num, pct } from "../../lib/format";
import {
  checkLabel,
  CURRENT_CASH_ASSUMPTION_LABEL,
  CURRENT_CASH_ASSUMPTION_NOTE,
  returnBasisCopy,
  dataLabelBadgeClass,
  dataSourceDescription,
  dataSourceLabel,
  isBundledCcBy,
  runOutcome,
} from "../../lib/labels";

type JsonObject = Record<string, unknown>;

const asObject = (value: unknown): JsonObject =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : {};

const firstText = (...values: unknown[]) => {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value;
  }
  return "Not available";
};

function ShowTheMath({ label, metrics, artifact }: {
  label: string; metrics: MetricSet; artifact: ArtifactRef | undefined;
}) {
  const formulas = metrics.formulas ?? {};
  const values: Record<string, string> = {
    total_return: pct(metrics.total_return),
    cagr: pct(metrics.cagr),
    ann_vol: pct(metrics.ann_vol),
    sharpe: num(metrics.sharpe),
    max_drawdown: pct(metrics.max_drawdown),
    total_costs: money(metrics.total_costs),
    exposure: exposure(metrics.exposure),
  };
  const inputs: Record<string, string> = {
    total_return: `initial_capital ${money(metrics.initial_capital)} · final equity ${money(metrics.final_equity)}`,
    cagr: `n_bars ${metrics.n_bars} · initial_capital ${money(metrics.initial_capital)}`,
    ann_vol: `${metrics.n_return_observations ?? "—"} return observations`,
    sharpe: `${metrics.n_return_observations ?? "—"} return observations · rf = 0`,
    max_drawdown: `equity path from ${metrics.start_date ?? "—"} to ${metrics.end_date ?? "—"}`,
    total_costs: `${metrics.n_trades ?? 0} sealed fills`,
    exposure: `positions over ${metrics.n_bars} bars`,
  };
  return (
    <div className="tablewrap" role="region" tabIndex={0}
      aria-label={`${label} metric derivations`}>
      <table>
        <caption style={{ textAlign: "left", fontSize: "0.8rem", color: "var(--ink-soft)" }}>
          {label} — every value traces to artifact{" "}
          <code>{artifact?.artifact_id ?? "unknown"}</code>{" "}
          (kind {artifact?.kind ?? "—"}, SHA-256 <code>{artifact?.sha256.slice(0, 16) ?? "—"}…</code>)
        </caption>
        <thead>
          <tr>
            <th scope="col">Metric</th><th scope="col">Displayed value</th>
            <th scope="col">Formula</th><th scope="col">Sealed inputs</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(formulas).map(([metric, formula]) => (
            <tr key={metric}>
              <th scope="row">{metric.replaceAll("_", " ")}</th>
              <td>{values[metric] ?? "—"}</td>
              <td><code>{formula}</code></td>
              <td>{inputs[metric] ?? "see artifact payload"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CostStressVisual({ view }: { view: EvidenceViewV1 }) {
  const rows = view.cost_stress.rows
    .filter((row) => typeof row.oos.total_return === "number" && Number.isFinite(row.oos.total_return))
    .sort((a, b) => a.multiplier - b.multiplier);
  if (rows.length < 2) return null;

  const width = 640;
  const height = 190;
  const padX = 48;
  const padTop = 26;
  const padBottom = 42;
  const values = rows.map((row) => row.oos.total_return as number);
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const range = maximum - minimum || 1;
  const x = (index: number) => padX + (index * (width - (2 * padX))) / (rows.length - 1);
  const y = (value: number) => padTop + ((maximum - value) / range) * (height - padTop - padBottom);
  const points = rows.map((row, index) => `${x(index)},${y(row.oos.total_return as number)}`).join(" ");
  const summary = rows
    .map((row) => `${row.multiplier} times costs: ${pct(row.oos.total_return)}`)
    .join("; ");

  return (
    <figure className="evidence-mini-visual" data-testid="cost-stress-visual">
      <div className="evidence-mini-visual-head">
        <div>
          <span className="evidence-eyebrow">Out-of-sample return</span>
          <strong>Response to declared transaction-cost multipliers</strong>
        </div>
        <span className="chip">sealed stress rows</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img"
        aria-label={`Out-of-sample cost-stress curve. ${summary}`}>
        <line className="stress-gridline" x1={padX} x2={width - padX}
          y1={padTop} y2={padTop} />
        <line className="stress-gridline" x1={padX} x2={width - padX}
          y1={height - padBottom} y2={height - padBottom} />
        <polyline className="stress-line" points={points} />
        {rows.map((row, index) => {
          const value = row.oos.total_return as number;
          return (
            <g key={row.multiplier} className="stress-point">
              <circle cx={x(index)} cy={y(value)} r="5" />
              <text className="stress-value" x={x(index)} y={Math.max(16, y(value) - 12)}
                textAnchor="middle">{pct(value)}</text>
              <text className="stress-label" x={x(index)} y={height - 15}
                textAnchor="middle">{row.multiplier}× costs</text>
            </g>
          );
        })}
      </svg>
      <figcaption>
        This line connects the exact preregistered OOS stress results below. It does not
        extrapolate beyond the declared multipliers.
      </figcaption>
    </figure>
  );
}

function SensitivityHeatmap({ view }: { view: EvidenceViewV1 }) {
  const numeric = view.sensitivity.grid.filter(
    (cell) => !cell.skipped && typeof cell.sharpe === "number" && Number.isFinite(cell.sharpe),
  );
  if (!numeric.length) return null;
  const sharpes = numeric.map((cell) => cell.sharpe as number);
  const minimum = Math.min(...sharpes);
  const maximum = Math.max(...sharpes);
  const range = maximum - minimum || 1;

  return (
    <figure className="evidence-mini-visual" data-testid="sensitivity-heatmap">
      <div className="evidence-mini-visual-head">
        <div>
          <span className="evidence-eyebrow">In-sample only</span>
          <strong>Declared MA-window sensitivity</strong>
        </div>
        <span className="heat-legend" aria-hidden="true">lower Sharpe <i /> higher Sharpe</span>
      </div>
      <div className="sensitivity-heatmap" role="list"
        aria-label="Parameter sensitivity values by moving-average window">
        {view.sensitivity.grid.map((cell) => {
          const available = !cell.skipped && typeof cell.sharpe === "number";
          const intensity = available ? ((cell.sharpe as number) - minimum) / range : 0;
          const chosen = cell.ma_days === view.sensitivity.chosen_ma_days;
          return (
            <div key={cell.ma_days} role="listitem"
              className={`sensitivity-tile${chosen ? " chosen" : ""}${available ? "" : " unavailable"}`}
              style={available ? {
                background: `rgba(20, 128, 143, ${(0.10 + (intensity * 0.42)).toFixed(3)})`,
              } : undefined}>
              <span>{cell.ma_days} days{chosen ? " · chosen" : ""}</span>
              <strong>{available ? num(cell.sharpe) : "skipped"}</strong>
              <small>{available ? `${pct(cell.total_return)} return` : cell.skipped}</small>
            </div>
          );
        })}
      </div>
      <figcaption>
        Color encodes the displayed sealed Sharpe values only; exact values and all
        skipped cells remain in the table below.
      </figcaption>
    </figure>
  );
}

const REPORT_TABS = [
  ["summary", "Summary"],
  ["robustness", "Robustness"],
  ["assumptions", "Assumptions"],
  ["audit", "Audit trail"],
] as const;

type TabKey = (typeof REPORT_TABS)[number][0];

interface Props {
  view: EvidenceView;
  explanation: ExplanationViewV1 | null;
  explanationLoading: boolean;
  copilot?: ResearchCopilotView | null;
  copilotUnavailable?: boolean;
  /** Presentation depth only — it selects wording, never data. */
  readingLevel?: ReadingLevel;
  /** The reading-level control, rendered with the report's own view controls. */
  readingLevelControl?: ReactNode;
}

/** Dispatch on the sealed evidence contract version — fail closed: only the "v1",
 * "v2" and closed-shape "v3" contracts this interface understands are ever
 * rendered. A payload that merely claims "v3" without satisfying the sealed
 * closed-shape guard, or any unknown version, is refused explicitly instead of
 * being misread through the assumptions of another contract. */
export default function EvidenceWorkspace({
  view, explanation, explanationLoading, copilot, copilotUnavailable, readingLevel,
  readingLevelControl,
}: Props) {
  const level = readingLevel ?? DEFAULT_READING_LEVEL;
  const version = (view as { evidence_view_version?: unknown }).evidence_view_version;
  if (version === "v3" && isRenderableEvidenceV3(view)) {
    return (
      <EvidenceWorkspaceV3
        view={view}
        readingLevel={level}
        readingLevelControl={readingLevelControl}
      />
    );
  }
  if (version === "v2") {
    return (
      <EvidenceWorkspaceV2
        view={view as Extract<EvidenceView, { evidence_view_version: "v2" }>}
        copilot={copilot ?? null}
        copilotUnavailable={copilotUnavailable ?? false}
        readingLevel={level}
        readingLevelControl={readingLevelControl}
      />
    );
  }
  if (version === "v1") {
    return (
      <EvidenceWorkspaceV1
        view={view as EvidenceViewV1}
        explanation={explanation}
        explanationLoading={explanationLoading}
        readingLevel={level}
        readingLevelControl={readingLevelControl}
      />
    );
  }
  return (
    <section aria-label="Evidence unavailable" data-testid="evidence-unsupported-contract">
      <div className="notice bad">
        <strong>This run&rsquo;s evidence uses a newer contract than this application
        version supports.</strong>{" "}Nothing is shown rather than risk displaying it
        unfaithfully. Update the application to view this report.
      </div>
    </section>
  );
}

interface PropsV1 {
  view: EvidenceViewV1;
  explanation: ExplanationViewV1 | null;
  explanationLoading: boolean;
  readingLevel: ReadingLevel;
  readingLevelControl?: ReactNode;
}

function EvidenceWorkspaceV1({
  view, explanation, explanationLoading, readingLevel, readingLevelControl,
}: PropsV1) {
  const [tab, setTab] = useState<TabKey>("summary");
  const [segment, setSegment] = useState<"is" | "oos">("oos");
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const reportTabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const identity = view.identity;
  const seg = view.results[segment];
  const spec = view.assumptions.spec;
  const oosMetrics = view.results.oos.strategy_metrics;
  const isMetrics = view.results.is.strategy_metrics;
  const artifactByKind = new Map(view.artifacts.map((a) => [a.kind, a]));
  const publication = view.publication;
  const identityRecord = asObject(identity);
  const snapshot = asObject(view.snapshot);
  const generator = asObject(snapshot.generator);
  const datasetManifest = asObject(snapshot.dataset_manifest);
  const specSource = asObject(asObject(spec.data).source);
  const dataLabel = firstText(identityRecord.data_label, snapshot.label, "SYNTHETIC").toUpperCase();
  // The CC BY bundle is stamped USER_UPLOADED by the sealed contract, so the label
  // alone brands licensed data as the reader's own. Only the bundle seeder writes
  // the operator-attested basis, which is what tells the two apart.
  const sealedPriceAdjustment = typeof datasetManifest.price_adjustment === "string"
    ? datasetManifest.price_adjustment : undefined;
  const isUserUploaded = dataLabel === "USER_UPLOADED"
    && !isBundledCcBy(dataLabel, sealedPriceAdjustment);
  const sourceBadge = (
    <span className={`sample-badge${dataLabelBadgeClass(dataLabel, sealedPriceAdjustment)}`}>
      {dataSourceLabel(dataLabel, sealedPriceAdjustment)}
    </span>
  );
  const datasetId = firstText(
    identityRecord.dataset_id, datasetManifest.dataset_id, generator.dataset_id,
    specSource.dataset_id,
  );
  const datasetManifestHash = firstText(
    identityRecord.dataset_manifest_sha256, snapshot.dataset_manifest_sha256,
    generator.dataset_manifest_sha256, specSource.dataset_manifest_sha256,
  );
  const coverageBySymbol = asObject(snapshot.coverage);
  const coverage = Object.keys(asObject(datasetManifest.coverage)).length
    ? asObject(datasetManifest.coverage)
    : asObject(coverageBySymbol[spec.universe.symbol]);
  const coverageStart = firstText(coverage.start);
  const coverageEnd = firstText(coverage.end);
  const adjustmentConvention = firstText(
    snapshot.adjustment_convention, datasetManifest.price_adjustment,
  );
  // The two basis sentences say opposite things, so this follows the sealed dataset
  // rather than a build-time constant. Naming price return over a dividend-adjusted
  // series invites a reader to add back a return that is already counted.
  const priceAdjustment = typeof datasetManifest.price_adjustment === "string"
    ? datasetManifest.price_adjustment : undefined;
  const returnBasis = returnBasisCopy(priceAdjustment);

  const failedChecks = view.status.checks.filter((c) => c.status === "FAIL").length;
  const outcome = runOutcome("published", view.status.battery_status, failedChecks);

  const oosComparison = view.results.oos.comparison_strategy_metrics;
  const oosBenchmark = view.results.oos.benchmark_metrics;
  const isComparison = view.results.is.comparison_strategy_metrics;
  const sortedStress = [...view.cost_stress.rows].sort((a, b) => a.multiplier - b.multiplier);
  const baseStress = sortedStress.find((row) => row.multiplier === 1)
    ?? sortedStress.find((row) => row.reused_primary_evaluation)
    ?? sortedStress[0];
  const highestStress = sortedStress.at(-1);
  const findingPriority: Record<CheckStatus, number> = { FAIL: 0, INCONCLUSIVE: 1, PASS: 2 };
  const strongestFinding = [...view.falsification.findings]
    .sort((a, b) => findingPriority[a.status] - findingPriority[b.status])[0];

  const plain = readingLevel === "novice";
  // Restatement only: every field is a sealed value passed through the same
  // formatter the professional tables use. Nothing here is derived or blended.
  const plainFacts: PlainReportFacts = {
    holdoutName: "out-of-sample window",
    holdoutDiscipline:
      `The rule was allowed to be tuned only on the earlier window `
      + `(${view.segments.is.start} to ${view.segments.is.end}). The window above `
      + `(${view.segments.oos.start} to ${view.segments.oos.end}) was held out of all `
      + `of that tuning, so it is the more honest of the two.`,
    holdoutAvailable: Number.isFinite(oosComparison.final_equity as number),
    holdoutUnavailableReason:
      "The sealed record carries no completed out-of-sample evaluation for this run.",
    initialCapital: money(oosComparison.initial_capital),
    finalEquity: money(oosComparison.final_equity),
    benchmarkSymbol: view.results.oos.benchmark_symbol,
    benchmarkFinalEquity: money(oosBenchmark.final_equity),
    strategyDrawdown: pct(oosComparison.max_drawdown),
    benchmarkDrawdown: pct(oosBenchmark.max_drawdown),
    tradeCount: String(oosComparison.n_trades ?? "—"),
    timeInMarket: exposure(oosComparison.exposure),
    checks: view.status.checks.map((check): PlainCheckFact => ({
      id: check.id, label: checkLabel(check.id), status: check.status,
    })),
    dataDescription: dataSourceDescription(dataLabel, sealedPriceAdjustment).toLowerCase(),
    isUserUploaded,
    priceAdjustment,
  };

  const chartSummary =
    `In-sample final equity ${money(isMetrics.final_equity)} over ${isMetrics.n_bars} bars ` +
    `from ${money(isMetrics.initial_capital)}; out-of-sample final equity ` +
    `${money(oosMetrics.final_equity)} over ${oosMetrics.n_bars} bars from ` +
    `${money(oosMetrics.initial_capital)}. Values come from the sealed ledger.`;

  const onSegmentKey = (e: React.KeyboardEvent, index: number) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const next = index === 0 ? 1 : 0; // two tabs: either arrow moves to the other
    setSegment(next === 0 ? "is" : "oos");
    tabRefs.current[next]?.focus();
  };

  const onReportTabKey = (e: React.KeyboardEvent, index: number) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const delta = e.key === "ArrowLeft" ? -1 : 1;
    const next = (index + delta + REPORT_TABS.length) % REPORT_TABS.length;
    setTab(REPORT_TABS[next][0]);
    reportTabRefs.current[next]?.focus();
  };

  return (
    <section aria-label="Research report">
      {!view.artifact_contract.verified_financial_semantics && (
        <div className="notice warn" data-testid="historical-contract-notice">
          <strong>Original historical evidence contract.</strong>{" "}
          This run is reproduced under <code>{view.artifact_contract.ledger_semantics_version}</code>
          {" and "}<code>{view.artifact_contract.execution_semantics_version}</code>.
          Its <code>slippage_bps</code> input means legacy linear execution friction,
          not an adverse effective fill price. The report remains readable, but this
          contract cannot enter contract-gated comparison, ranking, metrics-v2, or
          Research Copilot claims.
        </div>
      )}
      {publication && publication.status !== "published" && (
        <div className="notice warn" data-testid="publication-warning">
          <strong>Report publication {publication.status === "failed" ? "failed" : publication.status}.</strong>{" "}
          The evidence below was still sealed, re-read, and integrity-checked in full.
          The exported report is re-rendered from the sealed evidence on demand; the
          recorded publication error is listed in the Audit trail tab.
        </div>
      )}

      {plain && <PlainLanguageSummary facts={plainFacts} />}

      <section className={`verdict-banner ${outcome.tone}`} id="research-verdict-title-wrap"
        aria-labelledby="research-verdict-title" data-testid="research-verdict">
        <div>
          <span className="evidence-eyebrow">Research verdict</span>
          <h2 id="research-verdict-title">{outcome.label}</h2>
          <p>
            {plain
              ? "This line reports only what the pre-declared checks did. It is not a "
                + "score, a rating, a recommendation, or a forecast."
              : "Sealed results of the declared check battery. This is not a composite "
                + "score, recommendation, safety rating, or forecast."}
          </p>
        </div>
        {sourceBadge}
      </section>

      <TechnicalBlock level={readingLevel} testId="v1-headline-metrics-block"
        summary="The same headline in professional terms — five sealed metric tiles">
      <div className="metric-tiles" style={{ marginTop: 8 }}>
        <article className="metric-tile" data-testid="verdict-oos-benchmark">
          <span>OOS price return vs benchmark</span>
          <strong>{pct(oosComparison.total_return)}</strong>
          <p>Strategy · benchmark {pct(oosBenchmark.total_return)}</p>
        </article>
        <article className="metric-tile" data-testid="verdict-is-oos">
          <span>IS → OOS Sharpe</span>
          <strong>{num(isComparison.sharpe)} → {num(oosComparison.sharpe)}</strong>
          <p>{view.segments.is.bars} IS bars · {view.segments.oos.bars} OOS bars</p>
        </article>
        <article className="metric-tile" data-testid="verdict-cost-fragility">
          <span>Cost-stress OOS price return</span>
          <strong>{baseStress ? pct(baseStress.oos.total_return) : "—"} → {highestStress ? pct(highestStress.oos.total_return) : "—"}</strong>
          <p>{baseStress?.multiplier ?? "—"}× base view · {highestStress?.multiplier ?? "—"}× highest declared</p>
        </article>
        <article className="metric-tile" data-testid="verdict-parameter-stability">
          <span>Chosen parameter rank</span>
          <strong>{view.sensitivity.chosen_percentile_in_grid === null
            ? "—" : `${view.sensitivity.chosen_percentile_in_grid}th percentile`}</strong>
          <p>{view.sensitivity.chosen_ma_days}-day MA · IS Sharpe grid</p>
        </article>
        <article className="metric-tile" data-testid="verdict-oos-drawdown">
          <span>OOS max drawdown vs benchmark</span>
          <strong>{pct(oosComparison.max_drawdown)}</strong>
          <p>Strategy · benchmark {pct(oosBenchmark.max_drawdown)}</p>
        </article>
      </div>
      </TechnicalBlock>

      <article className={`verdict-contrary ${strongestFinding?.status_css ?? "inconclusive"}`}
        data-testid="verdict-falsifier">
        <div>
          <span className="evidence-eyebrow">
            {strongestFinding?.status === "FAIL"
              ? "Strongest failing check"
              : strongestFinding?.status === "INCONCLUSIVE"
                ? "Strongest unresolved check"
                : "Strongest available contrary-evidence check"}
          </span>
          <h3 style={{ textTransform: "none" }}>
            {strongestFinding ? checkLabel(strongestFinding.id) : "No finding available"}
          </h3>
        </div>
        {strongestFinding && <StatusChip status={strongestFinding.status} />}
        <p>{strongestFinding?.summary ?? "The sealed battery returned no falsification finding."}</p>
        <button type="button" className="linkish" style={{ justifySelf: "start" }}
          onClick={() => setTab("robustness")}>
          Review every falsification check →
        </button>
      </article>

      <TechnicalBlock level={readingLevel} testId="v1-status-chips-block"
        summary="Check-by-check status in professional terms">
      <div className="workspace-status-row" data-testid="verdict-summary">
        <span className={`outcome-chip ${outcome.tone}`}>{outcome.label}</span>
        {view.status.checks.map((c) => (
          <StatusChip key={c.id} status={c.status} label={checkLabel(c.id)} />
        ))}
        <span className={`chip ${view.status.evidence_complete ? "default" : "warn"}`}>
          {view.status.evidence_complete
            ? "Evidence record complete"
            : "Evidence record incomplete — see inconclusive checks"}
        </span>
        {sourceBadge}
        <span className="chip warn">{returnBasis.label}</span>
        <span className="chip warn">{CURRENT_CASH_ASSUMPTION_LABEL}</span>
      </div>
      </TechnicalBlock>
      <p className="workspace-meta" data-testid="return-basis-disclosure">
        <strong>{returnBasis.label}.</strong>{" "}{returnBasis.note}
      </p>
      <p className="workspace-meta" data-testid="cash-assumption-disclosure">
        <strong>{CURRENT_CASH_ASSUMPTION_LABEL}.</strong>{" "}{CURRENT_CASH_ASSUMPTION_NOTE}
      </p>
      <p className="workspace-meta">
        A status here reports only whether a declared check fired. It is not an
        endorsement, a safety rating, or a forecast.{" "}
        From sealed run data ·{" "}
        <button type="button" className="linkish" onClick={() => setTab("audit")}>
          View audit trail
        </button>
      </p>
      {isUserUploaded && (
        <p className="workspace-meta" data-testid="user-data-assurance">
          <strong>Your data — integrity-checked; source accuracy not independently authenticated.</strong>{" "}
          QuantLens sealed the normalized dataset and its provenance; it did not check
          the values against an independent market-data source.
        </p>
      )}

      {readingLevelControl}

      <div className="report-tabs" role="tablist" aria-label="Report sections">
        {REPORT_TABS.map(([key, label], index) => (
          <button
            key={key}
            role="tab"
            id={`report-tab-${key}`}
            aria-selected={tab === key}
            aria-controls={`report-panel-${key}`}
            tabIndex={tab === key ? 0 : -1}
            ref={(el) => { reportTabRefs.current[index] = el; }}
            onClick={() => setTab(key)}
            onKeyDown={(e) => onReportTabKey(e, index)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "summary" && (
        <div role="tabpanel" id="report-panel-summary" aria-labelledby="report-tab-summary"
          data-testid="report-panel-summary">
          {explanationLoading && (
            <p className="workspace-meta" role="status">Building an evidence-bound research summary…</p>
          )}
          {explanation && (explanation.status !== "completed" || explanation.binding === null
            || explanation.explanation === null
            ? <ExplanationPanel view={explanation} />
            : (
              <details className="drawer report-summary-drawer" data-testid="research-summary-drawer">
                <summary>Research summary — deterministic, built only from sealed evidence</summary>
                <div className="drawer-body">
                  <ExplanationPanel view={explanation} />
                </div>
              </details>
            ))}

          <section className="workspace-section" aria-labelledby="ws-curves">
            <div className="data-subhead" style={{ marginBottom: 0 }}>
              <h2 id="ws-curves" style={{ marginBottom: 6 }}>Equity curves</h2>
              {sourceBadge}
            </div>
            <EquityChart
              isSeries={view.results.is.equity_series}
              oosSeries={view.results.oos.equity_series}
              isBench={view.results.is.benchmark_series}
              oosBench={view.results.oos.benchmark_series}
              benchmarkSymbol={view.results.oos.benchmark_symbol}
              summary={chartSummary}
            />
          </section>

          <section className="workspace-section" aria-labelledby="ws-results">
            <h2 id="ws-results">Results — strictly separated</h2>
            <div className="seg-tabs" role="tablist" aria-label="Result segment">
              {(["is", "oos"] as const).map((key, i) => (
                <button
                  key={key}
                  role="tab"
                  id={`tab-${key}`}
                  aria-selected={segment === key}
                  aria-controls={`panel-${key}`}
                  tabIndex={segment === key ? 0 : -1}
                  ref={(el) => { tabRefs.current[i] = el; }}
                  onClick={() => setSegment(key)}
                  onKeyDown={(e) => onSegmentKey(e, i)}
                >
                  {key === "is" ? "In-sample" : "Out-of-sample"}
                </button>
              ))}
            </div>
            <div
              key={segment}
              role="tabpanel"
              id={`panel-${segment}`}
              aria-labelledby={`tab-${segment}`}
              className="context-fade"
              data-testid={`panel-${segment}`}
            >
              <p style={{ fontSize: "0.92rem" }}>
                {segment === "is"
                  ? `The window the rule was allowed to be tuned on (${view.segments.is.start} → ${view.segments.is.end}, ${view.segments.is.bars} bars). Treat it as the optimistic view.`
                  : `Held out of all tuning (${view.segments.oos.start} → ${view.segments.oos.end}, ${view.segments.oos.bars} bars). Its primary 1× estimate ran exactly once; the declared cost-stress multipliers re-ran it only as preregistered counterfactuals. Still only historical evidence on ${isUserUploaded ? "your data (source accuracy not independently authenticated)" : dataLabel === "LICENSED_PROVIDER" ? "licensed provider data" : "sample data"}.`}
              </p>
              <MetricsTable
                metrics={seg.comparison_strategy_metrics}
                benchmark={seg.benchmark_metrics}
                benchmarkSymbol={seg.benchmark_symbol}
                readingLevel={readingLevel}
              />
              <p style={{ fontSize: "0.82rem", color: "var(--ink-soft)" }}>
                Both columns are aligned to the benchmark&rsquo;s first tradable decision
                (the same alignment the printable report uses); the strategy&rsquo;s full
                declared-window metrics remain sealed separately in the audit trail.
              </p>
            </div>
            <p style={{ fontSize: "0.85rem", color: "var(--ink-soft)" }}>
              No blended in-sample + out-of-sample headline exists anywhere in this report,
              by design.
            </p>
          </section>
        </div>
      )}

      {tab === "robustness" && (
        <div role="tabpanel" id="report-panel-robustness" aria-labelledby="report-tab-robustness"
          data-testid="report-panel-robustness">
          <section className="workspace-section" aria-labelledby="ws-stress">
            <h2 id="ws-stress">Transaction-cost stress</h2>
            <p style={{ fontSize: "0.92rem" }}>
              Declared costs ({view.cost_stress.base_costs_bps.commission_bps} +{" "}
              {view.cost_stress.base_costs_bps.slippage_bps} bps) scaled by every declared
              multiplier; both segments shown separately.
            </p>
            <CostStressVisual view={view} />
            <div className="tablewrap" role="region" tabIndex={0}
              aria-label="Transaction-cost stress table">
              <table data-testid="stress-table">
                <thead>
                  <tr>
                    <th scope="col">Multiplier</th>
                    <th scope="col">IS price return</th><th scope="col">IS Sharpe</th>
                    <th scope="col">OOS price return</th><th scope="col">OOS Sharpe</th>
                    <th scope="col">OOS costs paid</th>
                  </tr>
                </thead>
                <tbody>
                  {view.cost_stress.rows.map((row) => (
                    <tr key={row.multiplier}>
                      <th scope="row">{row.multiplier}×{row.reused_primary_evaluation ? " (primary run)" : ""}</th>
                      <td>{pct(row.is.total_return)}</td><td>{num(row.is.sharpe)}</td>
                      <td>{pct(row.oos.total_return)}</td><td>{num(row.oos.sharpe)}</td>
                      <td>{money(row.oos.total_costs)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="workspace-section" aria-labelledby="ws-sensitivity">
            <h2 id="ws-sensitivity">Parameter sensitivity (in-sample only)</h2>
            <p style={{ fontSize: "0.92rem" }}>
              Every declared grid cell — never only the best one. The sweep read the in-sample
              slice exclusively.
            </p>
            <SensitivityHeatmap view={view} />
            <div className="tablewrap" role="region" tabIndex={0}
              aria-label="Parameter sensitivity grid">
              <table data-testid="sensitivity-grid">
                <thead>
                  <tr>
                    <th scope="col">MA window</th><th scope="col">IS Sharpe</th>
                    <th scope="col">IS price return</th><th scope="col">IS max drawdown</th>
                    <th scope="col">Fills</th><th scope="col">Selection</th>
                  </tr>
                </thead>
                <tbody>
                  {view.sensitivity.grid.map((cell: SensitivityCell) => (
                    <tr key={cell.ma_days}>
                      <th scope="row">{cell.ma_days} days</th>
                      {cell.skipped ? (
                        <td colSpan={4} style={{ color: "var(--ink-soft)" }}>skipped — {cell.skipped}</td>
                      ) : (
                        <>
                          <td>{num(cell.sharpe)}</td>
                          <td>{pct(cell.total_return)}</td>
                          <td>{pct(cell.max_drawdown)}</td>
                          <td>{cell.n_trades}</td>
                        </>
                      )}
                      <td>{cell.ma_days === view.sensitivity.chosen_ma_days ? "◀ chosen" : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {view.sensitivity.chosen_percentile_in_grid !== null && (
              <p style={{ fontSize: "0.92rem" }}>
                The chosen window ({view.sensitivity.chosen_ma_days} days) sits at the{" "}
                <strong>{view.sensitivity.chosen_percentile_in_grid}th percentile</strong>{" "}of
                the declared grid by in-sample Sharpe.
              </p>
            )}
          </section>

          <section className="workspace-section" aria-labelledby="ws-falsification">
            <h2 id="ws-falsification">Falsification — the strongest evidence against this idea</h2>
            <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
              This section cannot be removed from a research report. Checks run:{" "}
              {view.falsification.checks_run.map(checkLabel).join(", ")}. Thresholds are
              pre-declared in the sealed check configuration (see Audit trail).
            </p>
            <div className="fals-reveal" data-testid="falsification">
              {view.falsification.findings.map((f) => (
                <article key={f.id} className={`fals-card ${f.status_css}`}>
                  <h3 style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <StatusChip status={f.status} />
                    <span>{checkLabel(f.id)}</span>
                  </h3>
                  <p>{f.summary}</p>
                  <p style={{ fontSize: "0.82rem", color: "var(--ink-soft)" }}>
                    Rule: {f.rule}
                  </p>
                  <CheckGuidance id={f.id} status={f.status} />
                  <FindingEvidence evidence={f.evidence} />
                </article>
              ))}
            </div>
          </section>
        </div>
      )}

      {tab === "assumptions" && (
        <div role="tabpanel" id="report-panel-assumptions" aria-labelledby="report-tab-assumptions"
          data-testid="report-panel-assumptions">
          <section className="workspace-section" aria-labelledby="ws-assumptions">
            <h2 id="ws-assumptions">What was tested — the sealed confirmation</h2>
            <div className="restate" data-testid="sealed-receipt">{view.assumptions.restatement}</div>
            <p className="workspace-meta" style={{ marginTop: 6 }}>
              This is the exact statement confirmed before compute
              {view.confirmation.issued_at ? ` (${instantUTC(view.confirmation.issued_at)})` : ""}.
              It is displayed from the sealed receipt, never re-generated; its integrity
              identifiers are in the Audit trail.
            </p>
            <div className="card-grid" style={{ marginTop: 12 }}>
              <div className="card">
                <h3>Rule</h3>
                <p>{spec.rule.type === "price_vs_ma"
                  ? `Long ${spec.universe.symbol} when close > ${spec.rule.ma_days}-day SMA, else cash.`
                  : `Long ${spec.universe.symbol} when ${spec.rule.fast_ma_days}-day SMA > ${spec.rule.ma_days}-day SMA, else cash.`}
                </p>
                <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
                  Window {spec.data.range.start} → {spec.data.range.end} ·{" "}
                  {spec.costs.commission_bps} bps commission + {spec.costs.slippage_bps} bps
                  slippage per fill
                </p>
              </div>
              <div className="card">
                <h3>Execution semantics</h3>
                <p style={{ fontSize: "0.92rem" }}>{view.assumptions.execution.convention}</p>
              </div>
              <div className="card">
                <h3>Benchmark fairness</h3>
                <p style={{ fontSize: "0.92rem" }}>{view.assumptions.execution.benchmark_rule}</p>
              </div>
              <div className="card">
                <h3>Data</h3>
                <p style={{ fontSize: "0.92rem" }}>{dataSourceDescription(dataLabel, sealedPriceAdjustment)}.</p>
                <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
                  Coverage {coverageStart} → {coverageEnd} · {adjustmentConvention}
                </p>
              </div>
            </div>
          </section>
        </div>
      )}

      {tab === "audit" && (
        <div role="tabpanel" id="report-panel-audit" aria-labelledby="report-tab-audit"
          data-testid="report-panel-audit">
          <section className="workspace-section" aria-labelledby="ws-provenance">
            <h2 id="ws-provenance">Audit trail</h2>
            <p style={{ fontSize: "0.9rem", color: "var(--ink-soft)", maxWidth: "72ch" }}>
              Every number in this report is re-read from sealed, hash-checked artifacts
              before display. This tab holds the complete technical receipt: full
              identifiers, content hashes, and per-metric derivations.
            </p>
            <p className="workspace-meta">
              Result record{" "}
              <code data-testid="result-hash">{identity.result_hash}</code>{" "}
              <CopyId value={identity.result_hash} />
            </p>
            {publication && publication.status !== "published" && (
              <p className="workspace-meta" data-testid="publication-error-detail">
                Publication status: <code>{publication.status}</code>
                {publication.error && (
                  <>
                    {" "}· recorded error: <code>{publication.error}</code>
                  </>
                )}
              </p>
            )}
            <p className="field-row" style={{ gap: 10 }}>
              <a className="btn-link" href={`/api/ql/runs/${identity.run_id}/manifest`}
                target="_blank" rel="noreferrer">
                Download run manifest (JSON)
              </a>
            </p>

            <details className="drawer" data-testid="provenance-drawer">
              <summary>Provenance — snapshot, engine, and run identity</summary>
              <div className="drawer-body">
                <div className="tablewrap" role="region" tabIndex={0}
                  aria-label="Run identity and provenance">
                  <table>
                    <thead>
                      <tr><th scope="col">Identity field</th><th scope="col">Sealed value</th></tr>
                    </thead>
                    <tbody>
                      <tr><th scope="row">Run</th><td><code>{identity.run_id}</code></td></tr>
                      <tr><th scope="row">Manifest</th><td><code>{identity.manifest_id}</code> ({identity.manifest_version}) · SHA-256 <code>{identity.manifest_sha256}</code></td></tr>
                      <tr><th scope="row">Ledger index</th><td>SHA-256 <code>{identity.ledger_index_sha256}</code></td></tr>
                      <tr><th scope="row">Spec hash</th><td><code>{identity.spec_hash}</code> (v{identity.spec_version})</td></tr>
                      <tr>
                        <th scope="row">Data source</th>
                        <td>{dataSourceDescription(dataLabel, sealedPriceAdjustment)}</td>
                      </tr>
                      {isUserUploaded && (
                        <>
                          <tr><th scope="row">Dataset ID</th><td><code>{datasetId}</code></td></tr>
                          <tr><th scope="row">Dataset manifest SHA-256</th><td><code>{datasetManifestHash}</code></td></tr>
                        </>
                      )}
                      <tr><th scope="row">Coverage</th><td>{coverageStart} → {coverageEnd}</td></tr>
                      <tr><th scope="row">Adjustment convention</th><td>{adjustmentConvention}</td></tr>
                      <tr><th scope="row">Snapshot</th><td><code>{identity.snapshot_id}</code> · SHA-256 <code>{identity.snapshot_sha256}</code> · {dataLabel}</td></tr>
                      <tr><th scope="row">Engine</th><td><code>v{identity.engine_semver}</code> · runtime <code>{identity.image_digest}</code></td></tr>
                      <tr><th scope="row">Battery config</th><td><code>{identity.battery_config_hash}</code></td></tr>
                      <tr><th scope="row">Confirmation receipt</th><td>SHA-256 <code>{identity.confirmation_receipt_hash}</code></td></tr>
                      <tr><th scope="row">Result hash</th><td><code>{identity.result_hash}</code></td></tr>
                      <tr><th scope="row">Created</th><td><code>{identity.created_at}</code></td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </details>
            <details className="drawer" data-testid="artifacts-drawer">
              <summary>Ledger artifacts — every sealed file behind this view</summary>
              <div className="drawer-body tablewrap" role="region" tabIndex={0}
                aria-label="Sealed ledger artifacts">
                <table>
                  <thead>
                    <tr><th scope="col">Artifact</th><th scope="col">Kind</th><th scope="col">SHA-256</th></tr>
                  </thead>
                  <tbody>
                    {view.artifacts.map((a) => (
                      <tr key={a.artifact_id}>
                        <th scope="row"><code>{a.artifact_id}</code></th>
                        <td>{a.kind}</td>
                        <td><code>{a.sha256}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
            <details className="drawer" data-testid="show-the-math">
              <summary>Show the math — each displayed value, its formula, inputs, and artifact</summary>
              <div className="drawer-body">
                <ShowTheMath
                  label="Out-of-sample strategy metrics (full evaluation window)"
                  metrics={view.results.oos.strategy_metrics}
                  artifact={artifactByKind.get("oos_result")}
                />
                <ShowTheMath
                  label="In-sample strategy metrics (full evaluation window)"
                  metrics={view.results.is.strategy_metrics}
                  artifact={artifactByKind.get("is_result")}
                />
                <p style={{ fontSize: "0.82rem", color: "var(--ink-soft)" }}>
                  The benchmark-aligned table in the Summary tab derives from the same sealed
                  artifacts (<code>{artifactByKind.get("is_result")?.artifact_id}</code>,{" "}
                  <code>{artifactByKind.get("oos_result")?.artifact_id}</code>) using their
                  sealed comparison metrics; complete series and trade ledgers live inside
                  those artifacts, hash-bound to the manifest.
                </p>
              </div>
            </details>
          </section>
        </div>
      )}

      <p style={{ marginTop: 24 }}>
        <Link href="/studio">← Test another hypothesis</Link>
      </p>
    </section>
  );
}
