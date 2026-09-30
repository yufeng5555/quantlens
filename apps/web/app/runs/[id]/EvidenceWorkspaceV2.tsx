"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import type {
  EvidenceViewV2, RegimeStateResult, V2SegmentResult, WalkForwardFold,
} from "@schema/ts/evidence";
import {
  CheckGuidance, CopyId, FindingEvidence, MetricsTable, StatusChip,
} from "./reportShared";
import {
  DEFAULT_READING_LEVEL, PlainLanguageSummary, TechnicalBlock,
  type PlainCheckFact, type PlainReportFacts, type ReadingLevel,
} from "./readingLevel";
import ResearchCopilotPanel from "./ResearchCopilotPanel";
import type {
  ResearchCopilotActionId, ResearchCopilotView,
} from "./researchCopilotContract";
import { exposure, integer, money, num, pct } from "../../lib/format";
import {
  checkLabel,
  checkStatusLabel,
  CURRENT_CASH_ASSUMPTION_LABEL,
  CURRENT_CASH_ASSUMPTION_NOTE,
  returnBasisCopy,
  dataLabelBadgeClass,
  dataSourceDescription,
  dataSourceLabel,
  isBundledCcBy,
  regimeLabel,
  runOutcome,
} from "../../lib/labels";

/**
 * Validation Battery v2 report. Every displayed value is the sealed server value —
 * nothing here recomputes returns, Sharpe, fold stitching, regime aggregates, or the
 * verdict. Missing or inconclusive fields degrade to explicit product language.
 */

const REPORT_TABS = [
  ["summary", "Summary"],
  ["robustness", "Robustness"],
  ["assumptions", "Assumptions"],
  ["audit", "Audit trail"],
] as const;

type TabKey = (typeof REPORT_TABS)[number][0];

function ratio(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(0)}%`;
}

function SegmentUnavailable({ title, result }: { title: string; result: V2SegmentResult }) {
  return (
    <div className="notice warn">
      <strong>{title} produced no performance claims.</strong>{" "}
      {result.reason ?? "The sealed record marks this segment inconclusive."}{" "}
      No partial values are shown.
    </div>
  );
}

const CHART_W = 460;
const CHART_H = 240;

/**
 * One segment, one chart. Development and final holdout are independent experiments
 * that each start from their own sealed initial capital, so they are never joined
 * into a single continuous curve. Pure drawing of sealed series — no recomputation.
 */
function SegmentEquityChart({ title, testId, result }: {
  title: string;
  testId: string;
  result: V2SegmentResult;
}) {
  const series = result.equity_series ?? { date: [], equity: [] };
  const bench = result.benchmark_series ?? { date: [], equity: [] };
  const metrics = result.strategy_metrics ?? { n_bars: 0 };
  const symbol = result.benchmark_symbol ?? "benchmark";

  if (result.status !== "COMPLETE" || series.date.length === 0) {
    return (
      <figure className="evidence-chart-wrap" data-testid={testId}>
        <div className="evidence-mini-visual-head">
          <div>
            <span className="evidence-eyebrow">{title}</span>
            <strong>No sealed equity series</strong>
          </div>
          <span className="chip warn">Independent capital base</span>
        </div>
        <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)", margin: "6px 2px" }}>
          {result.reason ?? "This segment is inconclusive; no curve is drawn and no partial values are shown."}
        </p>
      </figure>
    );
  }

  const dates = series.date;
  const equity = series.equity;
  const n = dates.length;
  const all = [...equity, ...bench.equity];
  const lo = Math.min(...all);
  const hi = Math.max(...all);
  const pad = (hi - lo) * 0.05 || 1;
  const yLo = lo - pad;
  const yHi = hi + pad;
  const x = (i: number) => 58 + (CHART_W - 76) * (i / Math.max(n - 1, 1));
  const y = (v: number) => 22 + (CHART_H - 62) * (1 - (v - yLo) / (yHi - yLo));
  const stratPts = equity.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const dateIndex = new Map(dates.map((d, i) => [d, i]));
  const benchPts = bench.date
    .map((d, j) => ({ i: dateIndex.get(d), v: bench.equity[j] }))
    .filter((p): p is { i: number; v: number } => p.i !== undefined)
    .map((p) => `${x(p.i).toFixed(1)},${y(p.v).toFixed(1)}`)
    .join(" ");
  const summary =
    `${title}: initial capital ${money(metrics.initial_capital)}, final equity ` +
    `${money(metrics.final_equity)} over ${metrics.n_bars ?? n} bars, from the sealed record.`;

  const stride = Math.max(1, Math.ceil(n / 24));
  const benchByDate = new Map(bench.date.map((d, j) => [d, bench.equity[j]]));
  const sampled = dates
    .map((d, i) => ({ d, i }))
    .filter(({ i }) => i % stride === 0 || i === n - 1);

  return (
    <figure className="evidence-chart-wrap" data-testid={testId}>
      <div className="evidence-mini-visual-head">
        <div>
          <span className="evidence-eyebrow">{title}</span>
          <strong>Initial capital {money(metrics.initial_capital)} (sealed)</strong>
        </div>
        <span className="chip">Independent capital base</span>
      </div>
      <svg viewBox={`0 0 ${CHART_W} ${CHART_H}`} role="img"
        aria-label={`${title} equity curves from the sealed record: strategy versus benchmark (${symbol}, hold from first decision). ${summary}`}>
        <text x="58" y="14" fontSize="11" fill="var(--ink-soft)">
          equity ({money(yLo)} – {money(yHi)})
        </text>
        {benchPts && (
          <polyline points={benchPts} fill="none"
            stroke="#8aa0b2" strokeWidth="1.4" />
        )}
        <polyline points={stratPts} fill="none"
          stroke="var(--accent)" strokeWidth="2" />
        <text x="58" y={CHART_H - 10} fontSize="11" fill="var(--ink-soft)">
          {dates[0]} → {dates[n - 1]} · dark: strategy · light: benchmark ({symbol}, hold from first decision)
        </text>
      </svg>
      <figcaption style={{ fontSize: "0.8rem", color: "var(--ink-soft)", margin: "6px 2px 0" }}>
        {summary} This experiment&rsquo;s capital base is independent — its curve is
        never joined to the other segment.
      </figcaption>
      <details className="drawer">
        <summary>Chart data as a table (sampled every {stride} bar{stride > 1 ? "s" : ""})</summary>
        <div className="drawer-body tablewrap" role="region" tabIndex={0}
          aria-label={`${title} equity chart data table`}>
          <table>
            <thead>
              <tr>
                <th scope="col">Date</th>
                <th scope="col">Strategy equity</th>
                <th scope="col">Benchmark equity ({symbol})</th>
              </tr>
            </thead>
            <tbody>
              {sampled.map(({ d, i }) => (
                <tr key={d}>
                  <th scope="row">{d}</th>
                  <td>{money(equity[i])}</td>
                  <td>{benchByDate.has(d) ? money(benchByDate.get(d)!) : "— (before benchmark entry)"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

/** Copilot review actions map to local report anchors — navigation only. */
const ACTION_ANCHORS: Record<ResearchCopilotActionId, string> = {
  review_walk_forward_evidence: "v2-wf",
  review_cost_stress_evidence: "v2-stress",
  review_regime_coverage_evidence: "v2-regimes",
};

export default function EvidenceWorkspaceV2({
  view, copilot, copilotUnavailable, readingLevel, readingLevelControl,
}: {
  view: EvidenceViewV2;
  copilot?: ResearchCopilotView | null;
  copilotUnavailable?: boolean;
  readingLevel?: ReadingLevel;
  readingLevelControl?: ReactNode;
}) {
  const level = readingLevel ?? DEFAULT_READING_LEVEL;
  const plain = level === "novice";
  const [tab, setTab] = useState<TabKey>("summary");
  const reportTabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const focusAnchorRef = useRef<string | null>(null);

  // Confirmed Copilot review action: switch to Robustness, then move focus to the
  // matching sealed-evidence section once that tab panel exists in the DOM.
  const reviewEvidence = (actionId: ResearchCopilotActionId) => {
    focusAnchorRef.current = ACTION_ANCHORS[actionId];
    setTab("robustness");
  };

  useEffect(() => {
    if (tab !== "robustness" || !focusAnchorRef.current) return;
    const anchor = document.getElementById(focusAnchorRef.current);
    focusAnchorRef.current = null;
    if (anchor) {
      anchor.scrollIntoView({ block: "start" });
      anchor.focus({ preventScroll: true });
    }
  }, [tab]);

  const identity = view.identity;
  const publication = view.publication;
  const development = view.development_result;
  const finalHoldout = view.final_holdout_result;
  const audit = view.final_holdout_execution_audit ?? view.oos_execution_audit;
  const walkForward = view.walk_forward;
  const folds: WalkForwardFold[] = walkForward?.folds ?? [];
  const regimes: RegimeStateResult[] = view.regime_analysis?.states ?? [];
  const stressRows = view.cost_stress?.rows ?? [];
  const checks = view.status?.checks ?? [];
  const findings = view.falsification?.findings ?? [];
  const plan = view.validation_plan;

  const dataLabel = String(identity.data_label ?? "SYNTHETIC").toUpperCase();
  const priceAdjustment = view.data_provenance?.price_adjustment;
  // A CC BY series arrives stamped USER_UPLOADED because the sealed contract
  // closes that field to three values. It is not the reader's data, and the
  // exported report already says so — the screen used to say the opposite.
  const bundled = isBundledCcBy(dataLabel, priceAdjustment);
  const isUserUploaded = dataLabel === "USER_UPLOADED" && !bundled;
  // The two basis sentences say opposite things, so this follows the sealed dataset
  // rather than a build-time constant: a total-return series described as price return
  // invites the reader to add dividends that are already counted.
  const returnBasis = returnBasisCopy(priceAdjustment);

  const sourceBadge = (
    <span className={`sample-badge${dataLabelBadgeClass(dataLabel, priceAdjustment)}`}>
      {dataSourceLabel(dataLabel, priceAdjustment)}
    </span>
  );

  const failedChecks = checks.filter((c) => c.status === "FAIL").length;
  const outcome = runOutcome("published", view.status.battery_status, failedChecks);
  const strictOutcomeLabel = outcome.label.startsWith("Audit complete")
    ? outcome.label.replace("Audit complete", "Development audit complete")
    : outcome.label;
  const findingPriority: Record<string, number> = { FAIL: 0, INCONCLUSIVE: 1, PASS: 2 };
  const strongestFinding = [...findings]
    .sort((a, b) => (findingPriority[a.status] ?? 3) - (findingPriority[b.status] ?? 3))[0];

  const devMetrics = development?.comparison_strategy_metrics ?? { n_bars: 0 };
  const devBench = development?.benchmark_metrics ?? { n_bars: 0 };
  const finalMetrics = finalHoldout?.comparison_strategy_metrics ?? { n_bars: 0 };
  const finalBench = finalHoldout?.benchmark_metrics ?? { n_bars: 0 };
  const developmentComplete = development?.status === "COMPLETE";
  const finalComplete = finalHoldout?.status === "COMPLETE";
  const finalEvaluatedOnce = audit?.primary_evaluation_count === 1;
  const sortedStressRows = [...stressRows].sort((a, b) => a.multiplier - b.multiplier);
  const baseStress = sortedStressRows.find((row) => row.multiplier === 1)
    ?? sortedStressRows[0];
  const highestStress = sortedStressRows.at(-1);

  // Restatement only: every field is a sealed value passed through the same
  // formatter the professional tables use. Nothing here is derived or blended.
  const plainFacts: PlainReportFacts = {
    holdoutName: "final holdout",
    holdoutDiscipline: finalEvaluatedOnce
      ? "That window was locked away while the rule was being built and read exactly "
        + "once, at the end, at normal trading costs. It was never re-run to find a "
        + "better answer, which is what keeps this figure honest."
      : "The single-use holdout window was never opened for this run, so no held-out "
        + "result exists to report.",
    holdoutAvailable: finalComplete,
    holdoutUnavailableReason: finalHoldout?.reason
      ?? "The single-use final holdout was not consumed for this run.",
    initialCapital: money(finalMetrics.initial_capital),
    finalEquity: money(finalMetrics.final_equity),
    benchmarkSymbol: finalHoldout?.benchmark_symbol ?? "the benchmark fund",
    benchmarkFinalEquity: money(finalBench.final_equity),
    strategyDrawdown: pct(finalMetrics.max_drawdown),
    benchmarkDrawdown: pct(finalBench.max_drawdown),
    tradeCount: String(finalMetrics.n_trades ?? "—"),
    timeInMarket: exposure(finalMetrics.exposure),
    checks: checks.map((check): PlainCheckFact => ({
      id: check.id, label: checkLabel(check.id), status: check.status,
    })),
    dataDescription: dataSourceDescription(dataLabel, priceAdjustment).toLowerCase(),
    isUserUploaded,
    priceAdjustment,
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
    <section aria-label="Research report (Validation Battery v2)">
      {/* Folded, not removed. Every legacy contract sets this, so this notice opened
          every report with ledger-v0, linear-execution-friction-v0 and slippage_bps --
          internal contract names occupying the screen where the result belongs. The
          limitation is real and stays stated in the summary; the identifiers move
          inside, where someone who needs them can still reach them. */}
      {!view.artifact_contract.verified_financial_semantics && (
        <details className="drawer technical-block"
          data-testid="historical-contract-notice">
          <summary>
            Original historical evidence contract — readable, but not eligible for
            comparison or ranking
          </summary>
          <div className="drawer-body">
            <p>
              This run is reproduced under <code>{view.artifact_contract.ledger_semantics_version}</code>
              {" and "}<code>{view.artifact_contract.execution_semantics_version}</code>.
              Its <code>slippage_bps</code> input means legacy linear execution friction,
              not an adverse effective fill price. The report remains readable, but this
              contract cannot enter contract-gated comparison, ranking, metrics-v2, or
              Research Copilot claims.
            </p>
          </div>
        </details>
      )}
      {publication && publication.status !== "published" && (
        <div className="notice warn" data-testid="publication-warning">
          <strong>Report publication {publication.status === "failed" ? "failed" : publication.status}.</strong>{" "}
          The evidence below was still sealed, re-read, and integrity-checked in full.
          The recorded publication error is listed in the Audit trail tab.
        </div>
      )}

      {plain && <PlainLanguageSummary facts={plainFacts} />}

      <section className={`verdict-banner ${outcome.tone}`}
        aria-labelledby="research-verdict-title" data-testid="research-verdict">
        <div>
          <span className="evidence-eyebrow">Development audit verdict · Strict validation</span>
          <h2 id="research-verdict-title">{strictOutcomeLabel}</h2>
          <p>
            {plain
              ? "This line reports only what the checks written in advance did while the "
                + "rule was being built. It says nothing about the held-out result, and it "
                + "is not a score, a rating, a recommendation, or a forecast."
              : "This status grades the declared development checks only. It does not grade "
                + "final-holdout performance or approve the strategy for investment. "
                + "Historical research evidence only — not a recommendation, safety rating, "
                + "return guarantee, or live-trading result."}
          </p>
          {/* The question a reader opens a backtest to answer -- did the rule beat doing
              nothing -- was reachable only by finding two tiles further down and reading
              a benchmark figure out of a caption. Both numbers are sealed values placed
              side by side here; nothing is subtracted, ranked or concluded, because a
              derived figure is exactly what this report may not invent. */}
          {finalComplete && (
            <p className="verdict-vs-benchmark" data-testid="verdict-vs-benchmark">
              <strong>Against doing nothing:</strong>{" "}the rule returned{" "}
              {pct(finalMetrics.total_return)}{" "}over the final holdout. Buying{" "}
              {finalHoldout?.benchmark_symbol ?? "the benchmark fund"}{" "}at the same
              first decision and holding it returned{" "}{pct(finalBench.total_return)}{" "}
              over the same window, paying the same entry costs.
            </p>
          )}
        </div>
        {sourceBadge}
      </section>

      <TechnicalBlock level={level} testId="v2-headline-metrics-block"
        summary="The same headline in professional terms — six sealed metric tiles">
      <div className="metric-tiles" style={{ marginTop: 8 }}>
        <article className="metric-tile" data-testid="v2-development-return">
          <span>Development price return vs benchmark</span>
          <strong>{developmentComplete ? pct(devMetrics.total_return) : "—"}</strong>
          <p>
            {developmentComplete
              ? `Walk-forward, fixed rule · benchmark ${pct(devBench.total_return)}`
              : "Development evidence is inconclusive"}
          </p>
        </article>
        <article className="metric-tile" data-testid="v2-final-return">
          <span>Final holdout price return</span>
          <strong>{finalComplete ? pct(finalMetrics.total_return) : "Not evaluated"}</strong>
          <p>
            {finalComplete
              ? `Evaluated once at base costs · benchmark ${pct(finalBench.total_return)}`
              : "The single-use holdout was not consumed"}
          </p>
        </article>
        <article className="metric-tile" data-testid="v2-walk-forward">
          <span>Walk-forward folds</span>
          <strong>{integer(walkForward?.fold_count ?? 0)}</strong>
          <p>{ratio(walkForward?.positive_fold_ratio)} positive · fixed rule, no tuning</p>
        </article>
        <article className="metric-tile" data-testid="v2-sharpe-transition">
          <span>Development → holdout Sharpe</span>
          <strong>
            {developmentComplete ? num(devMetrics.sharpe) : "—"}
            {" → "}
            {finalComplete ? num(finalMetrics.sharpe) : "—"}
          </strong>
          <p>{devMetrics.n_bars ?? 0} development bars · {finalMetrics.n_bars ?? 0} holdout bars</p>
        </article>
        <article className="metric-tile" data-testid="v2-final-drawdown">
          <span>Final holdout max drawdown</span>
          <strong>{finalComplete ? pct(finalMetrics.max_drawdown) : "Not evaluated"}</strong>
          <p>{finalComplete ? `Strategy · benchmark ${pct(finalBench.max_drawdown)}` : "No final-holdout risk estimate exists"}</p>
        </article>
        <article className="metric-tile" data-testid="v2-cost-fragility">
          <span>Development cost-stress price return</span>
          <strong>
            {baseStress ? pct(baseStress.development?.total_return) : "—"}
            {" → "}
            {highestStress ? pct(highestStress.development?.total_return) : "—"}
          </strong>
          <p>{baseStress?.multiplier ?? "—"}× base view · {highestStress?.multiplier ?? "—"}× highest declared</p>
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
        <p>{strongestFinding?.summary ?? "The sealed validation returned no falsification finding."}</p>
        <button type="button" className="linkish" style={{ justifySelf: "start" }}
          onClick={() => setTab("robustness")}>
          Review every falsification check →
        </button>
      </article>

      <TechnicalBlock level={level} testId="v2-status-chips-block"
        summary="Check-by-check status in professional terms">
      <div className="workspace-status-row" data-testid="verdict-summary">
        <span className={`outcome-chip ${outcome.tone}`}>{strictOutcomeLabel}</span>
        {checks.map((c) => (
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
      <p className="workspace-meta" data-testid="v2-holdout-discipline">
        {finalEvaluatedOnce
          ? "Final holdout evaluated once at base costs — never reused for tuning, "
            + "parameter search, or cost counterfactuals."
          : "The single-use final holdout was not consumed; no holdout performance exists."}{" "}
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
      {/* The same assurance, correctly attributed. The bundle is not the reader's
          data, so responsibility for its usage rights and its adjustment basis is
          QuantLens's — but "not independently authenticated" stays true of it and
          must not vanish along with the wrong owner. */}
      {bundled && (
        <p className="workspace-meta" data-testid="bundled-data-assurance">
          <strong>Bundled data — supplied by QuantLens under CC BY 4.0.</strong>{" "}
          These bars were not provided by you. QuantLens sealed the normalized dataset,
          attested its total-return basis and holds the redistribution right; it did
          not check the values against an independent market-data source.
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
          {!copilot && copilotUnavailable && (
            <div className="notice warn" data-testid="v2-copilot-unavailable">
              <strong>Research review unavailable.</strong>{" "}
              {/* "right now" read as a transient fault while the notice at the top of
                  this report says the same run's contract can never carry Research
                  Copilot claims. Where that is the reason, say so. */}
              {view.artifact_contract.verified_financial_semantics
                ? "No development research review was prepared for this run."
                : "This run's evidence contract cannot carry Research Copilot claims, "
                  + "as the notice above this report states, so no development "
                  + "research review exists for it. That is a property of the sealed "
                  + "contract, not a temporary fault."}
              {" "}The sealed evidence below is complete and unaffected.
            </div>
          )}
          {!copilot && !copilotUnavailable && (
            <section
              className="copilot-panel copilot-loading"
              data-testid="v2-copilot-loading"
              role="status"
              aria-label="Preparing the research review"
            >
              <div className="copilot-head">
                <div>
                  <p className="data-eyebrow">QuantLens research review</p>
                  <p className="copilot-loading-line">
                    Preparing the research review from sealed development
                    evidence&hellip;
                  </p>
                </div>
              </div>
              <div className="copilot-skeleton" aria-hidden="true">
                <span /><span /><span />
              </div>
            </section>
          )}
          {copilot && (
            <ResearchCopilotPanel copilot={copilot} onReviewEvidence={reviewEvidence} />
          )}
          <section className="workspace-section" aria-labelledby="v2-curves">
            <div className="data-subhead" style={{ marginBottom: 0 }}>
              <h2 id="v2-curves" style={{ marginBottom: 6 }}>Equity curves — two independent experiments</h2>
              {sourceBadge}
            </div>
            <p style={{ fontSize: "0.88rem", color: "var(--ink-soft)", margin: "4px 0 10px" }}>
              Development and the final holdout each start from their own sealed initial
              capital. They are shown as separate charts on separate scales and are
              never joined into one continuous curve.
            </p>
            <div className="small-multiples" data-testid="v2-equity-multiples">
              <SegmentEquityChart
                title="Development"
                testId="v2-equity-development"
                result={development}
              />
              <SegmentEquityChart
                title="Final holdout"
                testId="v2-equity-final"
                result={finalHoldout}
              />
            </div>
          </section>

          <section className="workspace-section" aria-labelledby="v2-development">
            <h2 id="v2-development">Development — fixed-rule walk-forward</h2>
            <p style={{ fontSize: "0.92rem" }}>
              The rule was locked before execution and evaluated across{" "}
              {integer(walkForward?.fold_count ?? 0)} expanding folds. No parameter was
              searched or selected anywhere in this validation.
            </p>
            {developmentComplete ? (
              <MetricsTable
                metrics={devMetrics}
                benchmark={devBench}
                benchmarkSymbol={development?.benchmark_symbol ?? "benchmark"}
                readingLevel={level}
              />
            ) : (
              <SegmentUnavailable title="Development" result={development} />
            )}
          </section>

          <section className="workspace-section" aria-labelledby="v2-final">
            <h2 id="v2-final">Final holdout — evaluated once at base costs</h2>
            <div className="oosnote" style={{
              background: "#eef4f6", borderLeft: "4px solid var(--accent)",
              padding: "10px 14px", fontSize: "0.9rem", borderRadius: "0 10px 10px 0",
            }}>
              This access-controlled window was read exactly{" "}
              {finalEvaluatedOnce ? "once" : "zero times"}, at base costs, after the rule
              and plan were locked. A single-use, in-app capability and a cross-run
              reveal ledger prevent it from being revealed twice (protection details and
              limits are in the Audit trail). It is never re-run for counterfactuals,
              and it remains historical evidence — not a forecast or a guarantee of
              returns.
            </div>
            {finalComplete ? (
              <MetricsTable
                metrics={finalMetrics}
                benchmark={finalBench}
                benchmarkSymbol={finalHoldout?.benchmark_symbol ?? "benchmark"}
                readingLevel={level}
              />
            ) : (
              <SegmentUnavailable title="The final holdout" result={finalHoldout} />
            )}
          </section>
        </div>
      )}

      {tab === "robustness" && (
        <div role="tabpanel" id="report-panel-robustness" aria-labelledby="report-tab-robustness"
          data-testid="report-panel-robustness">
          <section className="workspace-section" aria-labelledby="v2-wf">
            <h2 id="v2-wf" tabIndex={-1}>Positive-fold coverage (development only)</h2>
            <p style={{ fontSize: "0.92rem" }}>
              This declared check asks only whether at least half of the fixed-rule
              development folds produced a positive absolute price return. It does not
              test benchmark outperformance, return magnitude, or investment quality.
            </p>
            <div className="metric-tiles">
              <article className="metric-tile">
                <span>Walk-forward windows</span>
                <strong>{integer(walkForward?.fold_count ?? 0)}</strong>
                <p>Expanding · fixed rule</p>
              </article>
              <article className="metric-tile">
                <span>Median fold Sharpe</span>
                <strong>{num(walkForward?.median_fold_sharpe)}</strong>
                <p>Sealed per-fold values below</p>
              </article>
              <article className="metric-tile">
                <span>Positive folds</span>
                <strong>{ratio(walkForward?.positive_fold_ratio)}</strong>
                <p>Share of folds with a positive price return</p>
              </article>
              <article className="metric-tile">
                <span>Worst fold price return</span>
                <strong>{pct(walkForward?.worst_fold_return)}</strong>
                <p>Dispersion {num(walkForward?.fold_return_dispersion, 4)}</p>
              </article>
            </div>
            {folds.length > 0 ? (
              <div className="tablewrap" role="region" tabIndex={0}
                aria-label="Walk-forward folds">
                <table data-testid="v2-fold-table">
                  <thead>
                    <tr>
                      <th scope="col">Fold</th>
                      <th scope="col">Test bars</th>
                      <th scope="col">Price return</th>
                      <th scope="col">Sharpe</th>
                      <th scope="col">Max drawdown</th>
                    </tr>
                  </thead>
                  <tbody>
                    {folds.map((fold, index) => (
                      <tr key={String(fold.fold_id ?? index)}>
                        <th scope="row">{String(fold.fold_id ?? index + 1)}</th>
                        <td>{fold.test_bars ?? "—"}</td>
                        <td>{pct(fold.strategy_metrics?.total_return)}</td>
                        <td>{num(fold.strategy_metrics?.sharpe)}</td>
                        <td>{pct(fold.strategy_metrics?.max_drawdown)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="notice warn">
                <strong>No valid walk-forward fold exists.</strong>{" "}The development
                history was too short for the sealed plan; stability evidence is
                inconclusive, which is never treated as a pass.
              </div>
            )}
          </section>

          <section className="workspace-section" aria-labelledby="v2-stress">
            <h2 id="v2-stress" tabIndex={-1}>Transaction-cost stress (development only)</h2>
            <p style={{ fontSize: "0.92rem" }}>
              Declared multipliers re-run the fixed rule on development folds only.{" "}
              {view.cost_stress?.note
                ?? "The final holdout is never re-run for cost counterfactuals."}
            </p>
            {stressRows.length > 0 ? (
              <div className="tablewrap" role="region" tabIndex={0}
                aria-label="Development cost stress table">
                <table data-testid="v2-stress-table">
                  <thead>
                    <tr>
                      <th scope="col">Multiplier</th>
                      <th scope="col">Development price return</th>
                      <th scope="col">Development Sharpe</th>
                      <th scope="col">Development costs paid</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stressRows.map((row) => (
                      <tr key={row.multiplier}>
                        <th scope="row">{row.multiplier}×</th>
                        <td>{pct(row.development?.total_return)}</td>
                        <td>{num(row.development?.sharpe)}</td>
                        <td>{money(row.development?.total_costs)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="notice warn">
                <strong>No development cost-stress rows were sealed.</strong>{" "}Missing
                stress evidence is inconclusive, not a pass.
              </div>
            )}
          </section>

          <section className="workspace-section" aria-labelledby="v2-regimes">
            <h2 id="v2-regimes" tabIndex={-1}>Regime analysis (preregistered, development only)</h2>
            <p style={{ fontSize: "0.92rem" }}>
              Four preregistered market states classified with prior-day information
              only. A quadrant with fewer than{" "}
              {integer(plan?.regime_law?.minimum_observations ?? 20)} observations is
              reported as inconclusive — never extrapolated. A passing state means the
              sample-size requirement was met; it does not certify profitable or stable
              performance in that regime.
            </p>
            <div className="metric-tiles" data-testid="v2-regime-grid">
              {regimes.length > 0 ? regimes.map((state) => (
                <article className="metric-tile" key={state.regime}
                  data-testid={`v2-regime-${state.regime}`}>
                  <span>{regimeLabel(state.regime)}</span>
                  <strong>
                    {state.status === "PASS"
                      ? pct(state.strategy_compounded_return)
                      : "Inconclusive"}
                  </strong>
                  <p>
                    {state.status === "PASS"
                      ? `Benchmark ${pct(state.benchmark_compounded_return)} · exposure ${exposure(state.exposure)} · ${integer(state.trade_count)} trades`
                      : `${integer(state.observations)} observations — below the preregistered minimum`}
                  </p>
                </article>
              )) : (
                <p className="workspace-meta">No regime states were sealed for this run.</p>
              )}
            </div>
          </section>

          <section className="workspace-section" aria-labelledby="v2-sensitivity">
            <h2 id="v2-sensitivity">Parameter sensitivity</h2>
            <div className="notice" data-testid="v2-locked-rule">
              <strong>Locked rule · no parameter search.</strong>{" "}Strict validation
              executes exactly the confirmed rule. No grid was swept, no alternative was
              evaluated, and no selection percentile exists for this run.
            </div>
          </section>

          <section className="workspace-section" aria-labelledby="v2-falsification">
            <h2 id="v2-falsification">Falsification — the strongest evidence against this idea</h2>
            <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
              This section cannot be removed from a research report. Checks run:{" "}
              {(view.falsification?.checks_run ?? []).map(checkLabel).join(", ") || "none"}.
              Thresholds are pre-declared in the sealed validation plan (see Audit trail).
            </p>
            <div className="fals-reveal" data-testid="falsification">
              {findings.map((f) => (
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
          <section className="workspace-section" aria-labelledby="v2-assumptions">
            <h2 id="v2-assumptions">What was tested — the sealed confirmation</h2>
            <div className="restate" data-testid="sealed-receipt">{view.assumptions.restatement}</div>
            <p className="workspace-meta" style={{ marginTop: 6 }}>
              This is the exact statement confirmed before compute. It is displayed from
              the sealed receipt, never re-generated; its integrity identifiers are in
              the Audit trail.
            </p>
            <div className="card-grid" style={{ marginTop: 12 }}>
              <div className="card">
                <h3>Rule (locked before execution)</h3>
                <p>{view.assumptions.spec.rule.type === "price_vs_ma"
                  ? `Long ${view.assumptions.spec.universe.symbol} when close > ${view.assumptions.spec.rule.ma_days}-day SMA, else cash.`
                  : `Long ${view.assumptions.spec.universe.symbol} when ${view.assumptions.spec.rule.fast_ma_days}-day SMA > ${view.assumptions.spec.rule.ma_days}-day SMA, else cash.`}
                </p>
                <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
                  {view.assumptions.spec.costs.commission_bps} bps commission +{" "}
                  {view.assumptions.spec.costs.slippage_bps} bps slippage per fill
                </p>
              </div>
              <div className="card">
                <h3>Validation plan (server-owned)</h3>
                <p style={{ fontSize: "0.9rem" }}>
                  {integer(plan?.development_bars)} development bars ·{" "}
                  {integer(plan?.final_holdout_bars)} holdout bars (
                  {plan?.final_holdout_fraction !== undefined
                    ? `${Math.round(plan.final_holdout_fraction * 100)}%`
                    : "—"} held out)
                </p>
                <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
                  Expanding walk-forward, {integer(plan?.test_window_bars)}-bar test
                  windows · parameter selection forbidden · single-use final holdout
                </p>
              </div>
              <div className="card">
                <h3>Data</h3>
                <p style={{ fontSize: "0.92rem" }}>{dataSourceDescription(dataLabel, priceAdjustment)}.</p>
                <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)" }}>
                  Window {view.assumptions.spec.data.range.start} →{" "}
                  {view.assumptions.spec.data.range.end}
                </p>
              </div>
              <div className="card">
                <h3>Research-agent boundary</h3>
                <p style={{ fontSize: "0.92rem" }}>
                  Any research summary for this run may read development evidence only.
                  The final holdout is rendered exclusively by the deterministic server
                  pipeline.
                </p>
              </div>
            </div>
          </section>
        </div>
      )}

      {tab === "audit" && (
        <div role="tabpanel" id="report-panel-audit" aria-labelledby="report-tab-audit"
          data-testid="report-panel-audit">
          <section className="workspace-section" aria-labelledby="v2-audit">
            <h2 id="v2-audit">Audit trail</h2>
            <p style={{ fontSize: "0.9rem", color: "var(--ink-soft)", maxWidth: "72ch" }}>
              Every number in this report is re-read from sealed, hash-checked artifacts
              before display. This tab holds the complete technical receipt: full
              identifiers, content hashes, the temporal-integrity receipt, and the
              single-execution record for the final holdout.
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

            <details className="drawer" data-testid="v2-temporal-receipt">
              <summary>Temporal integrity — partitions and the single final execution</summary>
              <div className="drawer-body">
                <div className="tablewrap" role="region" tabIndex={0}
                  aria-label="Temporal integrity receipt">
                  <table>
                    <thead>
                      <tr><th scope="col">Receipt field</th><th scope="col">Sealed value</th></tr>
                    </thead>
                    <tbody>
                      <tr><th scope="row">Receipt version</th><td><code>{view.temporal_integrity?.receipt_version ?? "—"}</code></td></tr>
                      <tr>
                        <th scope="row">Final-holdout executions</th>
                        <td data-testid="v2-final-execution-counts">
                          {integer(view.temporal_integrity?.executions?.final_holdout_primary_count
                            ?? audit?.primary_evaluation_count ?? 0)} primary ·{" "}
                          {integer(view.temporal_integrity?.executions?.final_holdout_counterfactual_count
                            ?? audit?.counterfactual_evaluation_count ?? 0)} counterfactual
                        </td>
                      </tr>
                      <tr><th scope="row">Execution state</th><td><code>{audit?.state ?? "—"}</code>{audit?.recovered_result ? " (recovered after crash, not re-run)" : ""}</td></tr>
                      <tr><th scope="row">Development boundary</th><td>bars {integer(view.temporal_integrity?.boundaries?.development?.bars)} · index {view.temporal_integrity?.boundaries?.development?.start_index ?? "—"} → {view.temporal_integrity?.boundaries?.development?.end_index ?? "—"}</td></tr>
                      <tr><th scope="row">Holdout boundary</th><td>bars {integer(view.temporal_integrity?.boundaries?.final_holdout?.bars)} · warm-up {integer(view.temporal_integrity?.boundaries?.final_holdout?.warmup_bars)} bars</td></tr>
                      <tr><th scope="row">Development input</th><td>SHA-256 <code>{view.temporal_integrity?.development_input_sha256 ?? "—"}</code></td></tr>
                      <tr><th scope="row">Holdout input</th><td>SHA-256 <code>{view.temporal_integrity?.final_holdout_input_sha256 ?? "—"}</code></td></tr>
                      <tr><th scope="row">Plan binding</th><td>SHA-256 <code>{view.temporal_integrity?.battery_plan_sha256 ?? "—"}</code></td></tr>
                      <tr><th scope="row">Access policy</th><td>battery: development only · final evaluator: opaque holdout reference · agent: development evidence only</td></tr>
                      <tr>
                        <th scope="row">Protection boundary</th>
                        <td data-testid="v2-protection-boundary">
                          The holdout is guarded by an in-app, access-controlled
                          single-use capability plus this cross-run reveal ledger. It is
                          not yet an independent OS principal or an object-store ACL; a
                          local machine administrator remains outside this boundary.
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </details>

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
                      <tr><th scope="row">Battery profile</th><td><code>{identity.battery_profile ?? "battery-v2"}</code></td></tr>
                      <tr><th scope="row">Manifest</th><td><code>{identity.manifest_id}</code> ({identity.manifest_version}) · SHA-256 <code>{identity.manifest_sha256}</code></td></tr>
                      <tr><th scope="row">Ledger index</th><td>SHA-256 <code>{identity.ledger_index_sha256}</code></td></tr>
                      <tr><th scope="row">Spec hash</th><td><code>{identity.spec_hash}</code> (v{identity.spec_version})</td></tr>
                      <tr><th scope="row">Validation plan</th><td>SHA-256 <code>{plan?.validation_plan_hash ?? "—"}</code></td></tr>
                      <tr><th scope="row">Data source</th><td>{dataSourceDescription(dataLabel, priceAdjustment)}</td></tr>
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
          </section>
        </div>
      )}

      <p style={{ marginTop: 24 }}>
        <Link href={`/studio?fromRun=${encodeURIComponent(identity.run_id)}`}
          data-testid="v2-create-related">
          Create related study → (keeps Strict validation and this dataset)
        </Link>
      </p>
    </section>
  );
}
