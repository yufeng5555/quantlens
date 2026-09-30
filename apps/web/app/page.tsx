"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { StrategySpec } from "@schema/ts/types";

import { apiGet } from "./studio/lib";
import { toSafeError } from "./lib/errors";
import { instantUTC, integer, sessionDate } from "./lib/format";
import {
  dataLabelBadgeClass,
  dataSourceLabel,
  instrumentDescriptor,
  runOutcome,
  strategyName,
  type BatteryStatus,
} from "./lib/labels";
import { useWorkspaceSession } from "./components/WorkspaceSession";

interface RunSummary {
  run_id: string;
  title: string;
  symbol: string | null;
  status: string;
  created_at: string;
  battery_status: BatteryStatus;
  evidence_available: boolean;
  failed_checks?: number | null;
}

interface DatasetSummary {
  dataset_id: string;
  display_name: string;
  symbol: string;
  row_count: number;
  coverage: { start: string; end: string };
  /** `price_adjustment` is what separates the CC BY bundle from the reader's own
   *  import: both carry USER_UPLOADED, and only the bundle seeder writes the
   *  operator-attested total-return basis. */
  provenance?: { data_label?: string; price_adjustment?: string };
}

interface Entitlement {
  quota: number;
  used: number;
  reserved: number;
  remaining: number;
}

interface MarketDataReadiness {
  status: string;
  provider: string | null;
  daily_bars: boolean;
}

export default function Overview() {
  const { state: sessionState } = useWorkspaceSession();
  const authenticated = sessionState.kind === "authenticated";
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<DatasetSummary[]>([]);
  const [templates, setTemplates] = useState<StrategySpec[]>([]);
  const [entitlement, setEntitlement] = useState<Entitlement | null>(null);
  // Null alone cannot say whether the allowance is still arriving or could not be
  // fetched, and the two deserve different words: a first-time reader who is told
  // "unavailable" during a normal page load reads it as a broken account.
  const [entitlementError, setEntitlementError] = useState(false);
  const [marketData, setMarketData] = useState<MarketDataReadiness | null>(null);
  const [marketDataError, setMarketDataError] = useState(false);

  useEffect(() => {
    // The desk summary counts the workspace, not just the visible rows, so the
    // list is fetched wider than it is rendered and sliced at the panel.
    apiGet<{ runs: RunSummary[] }>("/runs?limit=50")
      .then(({ body }) => { setRuns(body.runs ?? []); setRunsError(null); })
      .catch((caught) => {
        setRuns([]);
        setRunsError(toSafeError(caught, "Recent research could not be loaded.").userMessage);
      });
    apiGet<{ datasets: DatasetSummary[] }>("/datasets")
      .then(({ body }) => setDatasets(body.datasets ?? []))
      .catch(() => setDatasets([]));
    apiGet<{ templates: StrategySpec[] }>("/templates")
      .then(({ body }) => setTemplates(body.templates ?? []))
      .catch(() => setTemplates([]));
    apiGet<Entitlement>("/entitlement")
      .then(({ body }) => { setEntitlement(body); setEntitlementError(false); })
      .catch(() => { setEntitlement(null); setEntitlementError(true); });
    apiGet<MarketDataReadiness>("/market-data/config")
      .then(({ body }) => { setMarketData(body); setMarketDataError(false); })
      .catch(() => {
        // Fail closed like the Data Workspace: a config error is reported as
        // unavailable status, never silently rendered as "no provider".
        setMarketData(null);
        setMarketDataError(true);
      });
  }, []);

  // Desk summary figures. Every number is counted from the runs the workspace
  // actually returned — nothing is estimated, and an unloaded list counts zero
  // rather than guessing.
  const loadedRuns = runs ?? [];
  // Counts are reportable only when the workspace actually answered.
  const runsCounted = runs !== null && !runsError;
  const sealedCount = loadedRuns.filter((run) => run.evidence_available).length;
  const fragileCount = loadedRuns.filter(
    (run) => (run.failed_checks ?? 0) > 0).length;
  const symbolCount = new Set(
    loadedRuns.map((run) => run.symbol).filter((symbol): symbol is string =>
      Boolean(symbol))).size;
  const latestSealed = loadedRuns.find((run) => run.evidence_available) ?? null;
  const recentRuns = loadedRuns.slice(0, 6);

  if (sessionState.kind === "signed-out") {
    // Nobody has a workspace yet, so there are no counts to report and no
    // recent research to list. Showing those panels in their failure state
    // told a first-time visitor the product was broken at the exact moment it
    // was working correctly. This is the front page of a deployed instance.
    return (
      <main className="overview-main" data-testid="overview-signed-out">
        <header className="desk-header">
          <div className="desk-header-copy">
            {/* A finance student read this page, asked four clarifying questions, and
                still could not say what the product was for. The cause was structural:
                the page explained why it could be trusted before it established what
                it was for, and "secondary-market investors" told anyone who did not
                already own that label that they were in the wrong place. Purpose now
                comes first, in a situation a reader can picture. */}
            {/* Leads with the problem, not a scenario. An earlier draft opened
                "someone tells you a rule works", which asks the reader to place
                themselves in a situation most of them are not in — rules are usually
                something you read, were taught, or thought of yourself, not something
                handed to you — and it repeated the introduction's first line verbatim
                a few hundred pixels below. The problem needs no setup. */}
            <p className="page-kicker">Evidence-first quantitative research</p>
            <h1>Any backtest can be tuned until it looks good.</h1>
            {/* The heading states the problem; this states what the product does
                about it. An earlier draft restated the problem here instead, so the
                first two lines of the page said the same thing twice — the same fault
                that retired the draft before it. */}
            <p className="desk-lede">
              QuantLens makes you fix every assumption first, runs your rule once, and
              then tests it on data it has never seen. It shows you the checks it
              failed as plainly as the ones it passed.
            </p>
          </div>
          <div className="desk-header-actions">
            <Link className="btn-link primary" href="/signin">
              Sign in to start
            </Link>
            <Link className="btn-link" href="/methodology">Read the methodology</Link>
          </div>
        </header>

        <section className="overview-intro" aria-labelledby="signed-out-intro"
          data-testid="signed-out-intro">
          <h2 id="signed-out-intro">What QuantLens is for</h2>
          {/* Two columns at desk widths. Prose keeps a readable measure on the left
              while the three checks fill the space beside it — an earlier attempt
              narrowed the whole panel instead, which only moved the empty region from
              inside the box to outside it. */}
          <div className="overview-intro-body">
            <div className="overview-intro-prose">
              <p>
                Take a rule like <em>&ldquo;hold the S&amp;P 500 only while it is above
                its 200-day average.&rdquo;</em> You can find some version of that claim
                almost anywhere, usually with a backtest attached to prove it.
              </p>
              {/* The analogy carries this paragraph. An earlier draft said only that
                  "a backtest can be adjusted until it agrees" — accurate, and it left
                  the reader to build the picture themselves. Sitting the same past
                  paper until you score full marks IS the picture, and it maps exactly:
                  what you memorised was that paper, not the subject. */}
              <p>
                The trouble is how easy a backtest is to fool yourself with. If the rule
                does not make money, change 200 days to 180. Still no? Move the date
                range. Still no? Assume lower trading costs. Sooner or later some
                combination looks profitable. It is the same as memorising one practice
                exam:{" "}
                <strong>you can score full marks on that paper and still not know the
                subject.</strong>
              </p>
              {/* "QuantLens is the new exam" keeps the analogy's subject fixed. An
                  earlier draft had you sitting the exam in one sentence and your rule
                  sitting it in the next, which quietly swapped who was being tested. */}
              <p>
                QuantLens is the new exam. You fix every assumption in advance, it runs
                the test once, and then it goes looking for reasons the result should
                not be believed. The checks it fails are shown as prominently as the
                ones it passes, and each failure says what would change the answer.
              </p>
            </div>
            {/* The fastest honest answer to "what does it actually do". */}
            <ul className="overview-intro-checks">
              <li>
                <strong>Out of sample</strong>
                Does it still work on data it never saw?
              </li>
              <li>
                <strong>Real costs</strong>
                Does it survive realistic commission and slippage?
              </li>
              <li>
                <strong>Falling markets</strong>
                Has it ever been tested in a decline at all?
              </li>
            </ul>
          </div>
          <div className="overview-intro-split">
            <div>
              <h3>Who it is for</h3>
              <p>
                Students and analysts who need to judge a market claim — especially when
                someone else is going to ask how you know. No programming required.
              </p>
            </div>
            <div>
              <h3>What it is not</h3>
              {/* Stated here rather than in a footnote. A product whose claim is that
                  every assumption is stated cannot be vague about its own limits, and
                  the March 2022 boundary is the one a reader is most likely to be
                  caught out by. */}
              <p>
                It does not recommend trades, predict returns, or connect to a broker.
                The bundled data ends in March 2022, so this is a tool for studying a
                rule — not for acting on one today.
              </p>
            </div>
          </div>
        </section>

        <section className="overview-panel" aria-labelledby="signed-out-what">
          <div className="overview-panel-head">
            <h2 id="signed-out-what">What you get</h2>
          </div>
          <ul className="assumption-list" style={{ fontSize: "0.95rem" }}>
            <li>
              A private workspace. Your research and any data you upload are
              scoped to your own account and are not visible to other people.
            </li>
            <li>
              Every report is built from a sealed, hash-checked record. Reports
              can be read in plain language or at full professional detail —
              the wording changes, the numbers never do.
            </li>
            <li>
              Checks written before the run, kept in the report whether they
              pass or fail. No number in this product comes from a language
              model.
            </li>
          </ul>
          <p className="workspace-meta">
            Historical research evidence only — not investment advice, not a
            forecast, and not a claim about what happens next.
          </p>
        </section>

        {/* A stranger reached this page, read that every report is built from a sealed,
            hash-checked record, and was given no way to check anything at all before
            handing an unfamiliar fly.dev origin their Google account. Prose asking for
            trust with nothing behind it, on the one page that has to earn it.

            These two panels are what can be shown honestly without a session. The
            strategies are real product objects from the public /templates endpoint --
            the same cards a signed-in reader gets -- and the Studio they open genuinely
            works signed out, right up to the point where running one needs an account.
            The provenance is checkable on somebody else's server: the DOI resolves to
            the dataset, and the licence is what makes handing it over legal at all.
            Neither panel invents a figure, which is the constraint that ruled out the
            obvious "show a sample result" answer. */}
        <section className="overview-panel" aria-labelledby="signed-out-samples">
          <div className="overview-panel-head">
            <h2 id="signed-out-samples">See it before you sign in</h2>
            <Link href="/studio">Open the Research Studio →</Link>
          </div>
          <p className="workspace-meta" style={{ marginTop: 0 }}>
            These are the strategies the product ships. Opening one shows the exact
            specification a study runs on — instrument, rule, costs, benchmark, and what
            is held back for testing. Running it is the part that needs an account.
          </p>
          <div className="overview-strategy-grid">
            {templates.map((template) => {
              const descriptor = instrumentDescriptor(template.universe.symbol);
              return (
                <article className="overview-strategy" key={template.meta.name}
                  data-testid="signed-out-strategy-card">
                  <strong>{template.meta.name}</strong>
                  {descriptor && <p>{descriptor}</p>}
                  <p className="overview-strategy-family">
                    {strategyName(template.rule.type)}
                  </p>
                  <p>
                    {template.rule.type === "price_vs_ma"
                      ? `Long when the close is above the ${template.rule.ma_days}-day average, else cash.`
                      : `Long when the ${template.rule.fast_ma_days}-day average is above the ${template.rule.ma_days}-day, else cash.`}
                  </p>
                  {/* The mechanic alone assumes the reader already knows why anyone
                      would do this. One sentence of intent is what makes these cards
                      readable to someone who has never run a backtest. */}
                  <p className="overview-strategy-intent">
                    {template.rule.type === "price_vs_ma"
                      ? "The idea: sit out long declines by requiring the price to hold above its own trend."
                      : "The idea: follow the trend only once the shorter average confirms the longer one."}
                  </p>
                  <div className="field-row">
                    <Link
                      className="btn-link"
                      href={`/studio?template=${encodeURIComponent(template.meta.name)}`}
                    >
                      Open in Studio
                    </Link>
                  </div>
                </article>
              );
            })}
            {templates.length === 0 && (
              <p className="overview-empty">
                Sample strategies appear here when the research service is running.
              </p>
            )}
          </div>
        </section>

        <section className="overview-panel" aria-labelledby="signed-out-data">
          <div className="overview-panel-head">
            <h2 id="signed-out-data">The data, and where it came from</h2>
          </div>
          <p style={{ fontSize: "0.95rem", marginTop: 0 }}>
            This course-project release includes seeded synthetic daily OHLCV data for
            demonstrating the workflow. It includes no real market data and supports no
            market-performance conclusion. You may also import a daily CSV that you are
            entitled to use; source accuracy and usage rights remain your responsibility.
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="overview-main">
      <header className="desk-header">
        <div className="desk-header-copy">
          {/* Deliberately shorter than the signed-out lede, and with no explainer
              section under it: someone who has signed in has already decided what this
              is, and their workspace is what they came back for. The jargon goes for
              the same reason it went from the front page. */}
          <p className="page-kicker">Evidence-first quantitative research</p>
          <h1>Test a rule, then try to break the result.</h1>
          <p className="desk-lede">
            Fix your assumptions in advance, run the test once, and read what survived —
            including the checks it failed and what would change them.
          </p>
        </div>
        <div className="desk-header-actions">
          <Link className="btn-link primary" href="/studio">Start new research</Link>
          <Link className="btn-link" href="/runs">Open Runs &amp; Reports</Link>
        </div>
      </header>

      <section className="desk-metrics" aria-label="Workspace research summary">
        <article className="desk-metric">
          <p className="desk-metric-label">Sealed evidence records</p>
          {/* An unloaded or failed list reads as unknown, never as zero: "0
              sealed records" would state a fact the workspace has not
              reported yet. */}
          <p className="desk-metric-value">
            {runsCounted ? integer(sealedCount) : "—"}
          </p>
          <p className="desk-metric-note">
            {runsCounted
              ? `of your ${integer(loadedRuns.length)} most recent runs`
              : runsError ? "Count unavailable" : "Loading…"}
          </p>
        </article>
        <article className="desk-metric">
          <p className="desk-metric-label">Runs with a failing check</p>
          <p className="desk-metric-value">
            {runsCounted ? integer(fragileCount) : "—"}
          </p>
          <p className="desk-metric-note">Falsification checks that did not pass</p>
        </article>
        <article className="desk-metric">
          <p className="desk-metric-label">Instruments studied</p>
          <p className="desk-metric-value">
            {runsCounted ? integer(symbolCount) : "—"}
          </p>
          <p className="desk-metric-note">Distinct symbols in this workspace</p>
        </article>
        <article className="desk-metric">
          <p className="desk-metric-label">Research allowance left</p>
          <p className="desk-metric-value">
            {entitlement ? integer(entitlement.remaining) : "—"}
          </p>
          <p className="desk-metric-note">
            {entitlement
              ? `${integer(entitlement.used)} of ${integer(entitlement.quota)} used`
              : entitlementError ? "Allowance unavailable" : "Loading…"}
          </p>
        </article>
      </section>

      {latestSealed && (
        <section className="desk-latest" aria-labelledby="latest-evidence-title">
          <div className="desk-latest-head">
            <p className="page-kicker">Most recent sealed record</p>
            <h2 id="latest-evidence-title">{latestSealed.title}</h2>
            {latestSealed.symbol && (
              <p className="desk-latest-instrument">
                {instrumentDescriptor(latestSealed.symbol) ?? latestSealed.symbol}
              </p>
            )}
          </div>
          <div className="desk-latest-facts">
            <span
              className={`outcome-chip ${
                runOutcome(latestSealed.status, latestSealed.battery_status).tone
              }`}
            >
              {runOutcome(latestSealed.status, latestSealed.battery_status).label}
            </span>
            <time dateTime={latestSealed.created_at}>
              {instantUTC(latestSealed.created_at)}
            </time>
            <Link className="btn-link primary" href={`/runs/${latestSealed.run_id}`}>
              Open report
            </Link>
          </div>
        </section>
      )}

      <div className="overview-grid">
        <div className="overview-col">
          <section className="overview-panel" aria-labelledby="recent-runs-title">
            <div className="overview-panel-head">
              <h2 id="recent-runs-title">Recent runs</h2>
              <Link href="/runs">All runs &amp; reports →</Link>
            </div>
            {runs === null ? (
              <p className="overview-empty" role="status">Loading recent research…</p>
            ) : runsError ? (
              <div className="actionable-error" role="alert">
                <strong>Recent research is temporarily unavailable.</strong>
                <span>{runsError}</span>
              </div>
            ) : runs.length === 0 ? (
              <div className="overview-empty">
                <strong>No research yet.</strong>{" "}Open a sample strategy below or
                start from your own hypothesis. Run time depends on the data window
                and the validation rigor you choose.
              </div>
            ) : (
              <ol className="overview-run-list" aria-label="Recent research runs">
                {recentRuns.map((run) => {
                  // Same fail-closed rule as Runs & Reports: a lifecycle-complete run
                  // whose report evidence is unavailable is never shown as Completed.
                  const lifecycleComplete = run.status === "published"
                    || run.status === "report_rendered";
                  const outcome = lifecycleComplete && !run.evidence_available
                    ? {
                      label: "Needs attention · report evidence unavailable",
                      tone: "warn" as const,
                    }
                    : runOutcome(run.status, run.battery_status);
                  // The instrument is explained wherever a ticker first appears —
                  // one shared helper, no per-symbol special cases.
                  const instrument = run.symbol
                    ? instrumentDescriptor(run.symbol) ?? run.symbol
                    : null;
                  return (
                    <li key={run.run_id}>
                      <span className="run-title-block">
                        <Link className="run-title" href={`/runs/${run.run_id}`}>
                          {run.title}
                        </Link>
                        {instrument && (
                          <span className="run-instrument">{instrument}</span>
                        )}
                      </span>
                      <span className={`outcome-chip ${outcome.tone}`}>{outcome.label}</span>
                      <time dateTime={run.created_at}>{instantUTC(run.created_at)}</time>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>

          <section className="overview-panel" aria-labelledby="sample-strategies-title">
            <div className="overview-panel-head">
              <h2 id="sample-strategies-title">Sample strategies</h2>
              <Link href="/studio">Open Research Studio →</Link>
            </div>
            <div className="overview-strategy-grid">
              {(templates.length ? templates : []).map((template) => {
                const descriptor = instrumentDescriptor(template.universe.symbol);
                return (
                  <article className="overview-strategy" key={template.meta.name}
                    data-testid="overview-strategy-card">
                    <strong>{template.meta.name}</strong>
                    {descriptor && <p>{descriptor}</p>}
                    {/* Name the strategy, not just the parameters. A reader who
                        knows this is a moving-average trend filter can look up
                        whether the effect is established; "200-day trend" alone
                        tells them only what was typed. */}
                    <p className="overview-strategy-family">
                      {strategyName(template.rule.type)}
                    </p>
                    <p>
                      {template.rule.type === "price_vs_ma"
                        ? `Long when the close is above the ${template.rule.ma_days}-day average, else cash.`
                        : `Long when the ${template.rule.fast_ma_days}-day average is above the ${template.rule.ma_days}-day, else cash.`}{" "}
                      {sessionDate(template.data.range.start).slice(0, 4)}–{sessionDate(template.data.range.end).slice(0, 4)} · Sample data.
                    </p>
                    <div className="field-row">
                      {/* Carry which strategy was chosen. Without the name all
                          three of these landed on an empty Studio, so picking a
                          sample did exactly what picking nothing did. */}
                      <Link
                        className="btn-link"
                        href={`/studio?template=${encodeURIComponent(template.meta.name)}`}
                      >
                        Open in Studio
                      </Link>
                    </div>
                  </article>
                );
              })}
              {templates.length === 0 && (
                <p className="overview-empty">
                  Sample strategies appear here when the research service is running.
                </p>
              )}
            </div>
          </section>
        </div>

        <div className="overview-col">
          {/* A panel earns its place by saying something the screen does not
              already say. For a signed-in workspace this one said two things:
              that the workspace is private and whose it is — which the badge in
              the shell states — and the run allowance, which the metric tile
              directly above it states in larger type. Both were repeats, so on
              a deployed instance there is nothing left for it to carry.

              A local preview is different: that runs and data never leave this
              machine, and that sign-in, sharing and billing are not enabled, is
              a disclosure made nowhere else on this page. It stays, without the
              duplicated allowance line. */}
          {!authenticated && (
            <section className="overview-panel" aria-labelledby="workspace-status-title">
              <div className="overview-panel-head">
                <h2 id="workspace-status-title">Workspace</h2>
                <Link href="/account">Details →</Link>
              </div>
              <p style={{ margin: 0, fontSize: "0.88rem", color: "var(--ink-soft)" }}>
                <span className="sample-badge">Local research workspace</span>{" "}Research
                runs and data stay on this machine. Sign-in, team sharing, billing, and
                live provider activation are not enabled in this local environment.
              </p>
            </section>
          )}

          <section className="overview-panel" aria-labelledby="data-health-title">
            <div className="overview-panel-head">
              <h2 id="data-health-title">Data</h2>
              <Link href="/data">Manage →</Link>
            </div>
            <ul className="data-health-list">
              {marketData && (
                <li data-testid="overview-provider-readiness">
                  <span className="dh-name">Licensed provider</span>
                  <span className="dh-meta">
                    {marketData.status === "activated"
                      ? `${marketData.provider ?? "Provider"} · daily bars enabled`
                      : "Not active — operator setup required · CSV import available"}
                  </span>
                  <span className={`dh-state sample-badge${marketData.status === "activated" ? " licensed" : ""}`}>
                    {marketData.status === "activated" ? "Active" : "Not active"}
                  </span>
                </li>
              )}
              {!marketData && marketDataError && (
                <li data-testid="overview-provider-unavailable">
                  <span className="dh-name">Licensed provider</span>
                  <span className="dh-meta">
                    Status unavailable · CSV import remains available
                  </span>
                  <span className="dh-state sample-badge user-data">
                    Status unavailable
                  </span>
                </li>
              )}
              <li>
                <span className="dh-name">Bundled sample series</span>
                <span className="dh-meta">
                  8 US-listed ETFs · daily bars · fixed catalog, not market data
                </span>
                <span className="dh-state sample-badge">{dataSourceLabel("SYNTHETIC")}</span>
              </li>
              {datasets.map((dataset) => {
                const label = dataset.provenance?.data_label ?? "USER_UPLOADED";
                const basis = dataset.provenance?.price_adjustment;
                return (
                  <li key={dataset.dataset_id}>
                    <span className="dh-name">{dataset.display_name}</span>
                    <span className="dh-meta">
                      {dataset.symbol} · {integer(dataset.row_count)} sessions · through{" "}
                      {sessionDate(dataset.coverage.end)}
                    </span>
                    <span className={`dh-state sample-badge${dataLabelBadgeClass(label, basis)}`}>
                      {dataSourceLabel(label, basis)}
                    </span>
                  </li>
                );
              })}
            </ul>
            {datasets.length === 0 && (
              <p style={{ margin: "10px 0 0", fontSize: "0.8rem", color: "var(--ink-faint)" }}>
                No imported datasets yet. Import a daily OHLC CSV to research your own
                data alongside the samples.
              </p>
            )}
          </section>

          <section className="overview-panel" aria-labelledby="method-teaser-title">
            <div className="overview-panel-head">
              <h2 id="method-teaser-title">What the audit framework enforces</h2>
            </div>
            <ul style={{ margin: 0, paddingLeft: "1.15rem", fontSize: "0.85rem", color: "var(--ink-soft)", display: "grid", gap: 6 }}>
              <li>No look-ahead: decide at close, fill at the next open.</li>
              <li>Held-out evidence stays separate from development; Strict validation
                consumes its one-time final holdout exactly once.</li>
              <li>Costs stressed at preregistered multipliers.</li>
              <li>A falsification section that can never be removed.</li>
            </ul>
            <p style={{ margin: "10px 0 0", fontSize: "0.82rem" }}>
              <Link href="/methodology">How the research audit works →</Link>
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
