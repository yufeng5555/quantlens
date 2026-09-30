import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "About QuantLens — Evidence-first quantitative research",
  description:
    "Why QuantLens exists, how its evidence-first research architecture works, and "
    + "the principles that govern its quantitative research platform.",
};

const PRINCIPLES = [
  {
    index: "01",
    title: "Deterministic math",
    body: "AI may help frame a question or explain a result. It never invents, estimates, or silently changes the numbers. The research engine owns every calculation.",
  },
  {
    index: "02",
    title: "Traceable data",
    body: "Every result stays bound to its source, coverage, transformation choices, and immutable snapshot so an investor can see what the analysis actually used.",
  },
  {
    index: "03",
    title: "Adversarial validation",
    body: "The product is designed to search for fragility: held-out decay, unstable parameters, unrealistic costs, weak regimes, and unfair benchmarks.",
  },
  {
    index: "04",
    title: "Human judgment",
    body: "QuantLens supports a decision; it does not make one. The investor keeps responsibility for context, suitability, risk, and the final action.",
  },
];

const DIFFERENTIATORS = [
  {
    label: "Research Contract",
    title: "Assumptions are explicit before results exist.",
    body: "The hypothesis, instrument, data source, execution timing, costs, benchmark, validation split, and failure criteria form one reviewable contract.",
  },
  {
    label: "Robustness Map",
    title: "A strong return is not treated as strong evidence.",
    body: "Out-of-sample, walk-forward, cost, sensitivity, regime, and benchmark checks show which parts of the result are supported, conditional, or unresolved.",
  },
  {
    label: "Evidence Ledger",
    title: "Every conclusion can be traced backward.",
    body: "Reports bind the strategy specification, data identity, engine version, assumptions, artifacts, findings, and integrity receipt into an auditable record.",
  },
];

const PRODUCT_SCOPE = [
  {
    state: "Available now",
    tone: "available",
    items: [
      "Rule-based research on US-listed ETFs using daily bars",
      "Locked Research Contracts with explicit costs, benchmark, and test design",
      "Standard and Strict validation with held-out evidence and falsification",
      "Source-labeled reports, evidence hashes, run history, and comparison",
      // This shipped. It used to sit in the list below as "in development", while
      // further down the same page said the bundled series is total-return adjusted.
      "Bundled total-return ETF history, with every report stating its own basis",
    ],
  },
  {
    state: "In development",
    tone: "development",
    items: [
      "Cash-yield-aware data, distribution detail, and total-return imports",
      "Broader strategy rules, factors, portfolios, and risk diagnostics",
      "Direct licensed-data activation, scheduled monitoring, and drift alerts",
      "Authenticated team workspaces, collaboration, billing, and support",
    ],
  },
  {
    state: "Not offered",
    tone: "boundary",
    items: [
      "Personalized investment advice or security recommendations",
      "Brokerage custody, autonomous order execution, or portfolio management",
      "Promises of performance, strategy certification, or a trade signal",
      "High-frequency or institutional execution infrastructure",
    ],
  },
] as const;

export default function AboutQuantLens() {
  return (
    <main className="about-main">
      <header className="about-hero">
        <div>
          <p className="about-kicker">About QuantLens</p>
          <h1>Better investment research starts by trying to prove yourself wrong.</h1>
          <p className="about-lede">
            QuantLens is an evidence-first research tool for testing one rule-based
            market claim at a time. It turns that claim into a reproducible historical
            test, challenges the result under assumptions fixed in advance, and makes
            clear what the evidence does — and does not — support.
          </p>
          <div className="about-actions">
            <Link className="btn-link primary" href="/studio">Start a research audit</Link>
            <Link className="btn-link" href="/methodology">Read the methodology</Link>
          </div>
        </div>
        <aside className="about-manifesto" aria-label="QuantLens point of view">
          <span>Our point of view</span>
          <blockquote>
            The most dangerous backtest is not the one that fails. It is the one that
            looks convincing before its assumptions are challenged.
          </blockquote>
          <p>QuantLens is built to reveal that difference.</p>
        </aside>
      </header>

      <section className="about-problem" aria-labelledby="about-problem-title">
        <p className="about-section-index">01 · The problem</p>
        <div>
          <h2 id="about-problem-title">Most tools optimize for an impressive result. Investors need a trustworthy one.</h2>
          <p>
            Professional research platforms can be powerful but technically demanding.
            Simpler tools make it easy to produce a polished equity curve, yet often
            leave data quality, timing assumptions, overfitting, transaction costs, and
            contrary evidence buried in the workflow. QuantLens is designed for the
            space between those extremes: accessible enough to begin with a plain
            research question, rigorous enough to inspect every material assumption.
          </p>
        </div>
      </section>

      <section className="about-system" aria-labelledby="about-system-title">
        <div className="about-section-head">
          <div>
            <p className="about-section-index">02 · The QuantLens system</p>
            <h2 id="about-system-title">One research workflow. Three independent responsibilities.</h2>
          </div>
          <p>
            Keeping interpretation, computation, and validation separate is how the
            platform avoids turning an AI explanation into a financial fact.
          </p>
        </div>
        <div className="about-system-grid">
          <article>
            <span>Agent layer</span>
            <h3>Frame and investigate</h3>
            <p>Clarifies the hypothesis, identifies missing decisions, and explains the sealed evidence without changing it.</p>
          </article>
          <article>
            <span>Research engine</span>
            <h3>Compute deterministically</h3>
            <p>Applies declared rules, market timing, benchmarks, and costs through a versioned, reproducible calculation path.</p>
          </article>
          <article>
            <span>Validation layer</span>
            <h3>Search for failure</h3>
            <p>Tests held-out evidence, sensitivity, costs, regimes, and falsification criteria before a conclusion is presented.</p>
          </article>
        </div>
      </section>

      <section className="about-difference" aria-labelledby="about-difference-title">
        <div className="about-section-head">
          <div>
            <p className="about-section-index">03 · Product advantage</p>
            <h2 id="about-difference-title">Research infrastructure designed around evidence, not prediction.</h2>
          </div>
        </div>
        <div className="about-difference-grid">
          {DIFFERENTIATORS.map((item) => (
            <article key={item.label}>
              <span>{item.label}</span>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="about-principles" aria-labelledby="about-principles-title">
        <div className="about-section-head">
          <div>
            <p className="about-section-index">04 · Operating principles</p>
            <h2 id="about-principles-title">What earns trust inside QuantLens.</h2>
          </div>
        </div>
        <div className="about-principle-list">
          {PRINCIPLES.map((principle) => (
            <article key={principle.index}>
              <span>{principle.index}</span>
              <h3>{principle.title}</h3>
              <p>{principle.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="about-scope" aria-labelledby="about-scope-title">
        <div className="about-section-head">
          <div>
            <p className="about-section-index">05 · Current product scope</p>
            <h2 id="about-scope-title">A professional product starts with an honest boundary.</h2>
          </div>
          <p>
            QuantLens is useful today within a deliberately narrow research scope. We
            publish what works now, what is being built, and what the platform does not
            claim to do.
          </p>
        </div>
        <div className="about-scope-grid">
          {PRODUCT_SCOPE.map((column) => (
            <article className={column.tone} key={column.state}>
              <h3>{column.state}</h3>
              <ul>
                {column.items.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section className="about-boundary" aria-labelledby="about-boundary-title">
        <div>
          <p className="about-section-index">06 · A clear boundary</p>
          <h2 id="about-boundary-title">Research support, not a promise of return.</h2>
        </div>
        <div>
          <p>
            QuantLens does not recommend a security, certify that a strategy is safe or
            profitable, or replace an investor&rsquo;s judgment. Historical and backtested
            results are hypothetical and depend on the data and assumptions shown in
            each report. The current release does not execute trades.
          </p>
          <p>
            The return basis follows the dataset, and every report states its own. The
            bundled historical series is total-return adjusted, so dividends and
            distributions are already reinvested in the prices; the synthetic sample
            series, and imported files declared as split-adjusted, report price return
            with dividends excluded and therefore understate what owning the instrument
            returned. Uninvested cash earns 0% in the current engine, and Sharpe uses
            rf&nbsp;=&nbsp;0. These assumptions can materially affect a long/flat
            strategy. Cash-yield-aware data support is still in development.
          </p>
          <p>
            Professional means making those limits visible — not hiding them behind a
            disclaimer after the result.
          </p>
        </div>
      </section>

      <nav className="about-trust" aria-label="QuantLens trust resources">
        <div>
          <p className="about-section-index">07 · Inspect the system</p>
          <h2>Trust should have somewhere to click.</h2>
        </div>
        <div className="about-trust-links">
          <Link href="/methodology"><span>Research standards</span><strong>Methodology →</strong></Link>
          <Link href="/data"><span>Sources and coverage</span><strong>Data assurance →</strong></Link>
          <Link href="/account"><span>Storage and access</span><strong>Workspace boundary →</strong></Link>
          <Link href="/runs"><span>Evidence and history</span><strong>Research reports →</strong></Link>
          <Link href="/status"><span>Service readiness</span><strong>System status →</strong></Link>
        </div>
      </nav>

      <section className="about-cta" aria-label="Start with QuantLens">
        <div>
          <span>QuantLens</span>
          <h2>Make the next market idea earn your confidence.</h2>
        </div>
        <Link className="btn-link primary" href="/studio">Open Research Studio</Link>
      </section>
    </main>
  );
}
