import type { Metadata } from "next";

import { STRATEGY_VOCABULARY } from "../lib/labels";

export const metadata: Metadata = {
  title: "Methodology — QuantLens",
  description:
    "How the QuantLens research audit computes, stresses, and seals evidence: "
    + "two validation rigors, source-labeled data, a deterministic engine, and "
    + "integrity-checked reports.",
};

const DATA_ASSURANCE_ROWS = [
  {
    source: "Bundled sample series",
    nature:
      "A synthetic product-evaluation fixture with realistic statistical texture. "
      + "It is not market data and supports no market conclusion.",
    assurance:
      "Pinned and content-hashed like every snapshot; always labeled Sample data.",
    boundary:
      "Results describe the fixture only — never an instrument, market, or period.",
  },
  {
    source: "Your uploaded data",
    nature:
      "A daily OHLC CSV you import, normalized and sealed locally as an "
      + "immutable snapshot.",
    assurance:
      "Structure, coverage, and adjustment convention are integrity-checked and "
      + "sealed; reports cite the opaque dataset ID, never a filename.",
    boundary:
      "Source accuracy is not independently authenticated. Values, usage rights, "
      + "symbol, timezone, and adjustment attestation remain your responsibility.",
  },
  {
    source: "Licensed provider data",
    nature:
      "Daily bars acquired from a licensed market-data provider and sealed with "
      + "their rights terms.",
    assurance:
      "Available only after an operator activates the provider and every "
      + "acquisition passes resolution, validation, and rights checks.",
    boundary:
      "Availability depends on workspace and operator configuration; activation, "
      + "rights validation, and entitlement checks must pass before any acquisition "
      + "or run, and runs stay gated by the dataset's sealed rights scope.",
  },
];

export default function Methodology() {
  return (
    <main className="page-narrow">
      <header className="page-header">
        <div>
          <p className="page-kicker">Reference</p>
          <h1>Methodology</h1>
          <p className="page-lede">
            Every strategy result and report metric is produced by a deterministic
            backtest engine, sealed into a content-hashed evidence record, and re-read
            with integrity checks before display; operational values such as quotas,
            row counts, and dates are workspace state, not backtest results. Narrative
            text is fixed, evidence-bound template copy. Execution and provenance
            conventions are universal; validation rigor is not — each run is audited
            under one of the two rigors described below, and its report says which.
          </p>
        </div>
      </header>

      <section className="workspace-section">
        <h2>The strategies this build implements</h2>
        <p>
          Two, both from the same family. Naming them matters: a reader who knows
          what was tested can check whether the effect is established in the
          literature, compare it against published results, and judge whether an
          outcome is interesting or merely rediscovered. A rule described only by
          its parameters cannot be checked against anything.
        </p>
        <dl className="strategy-catalogue">
          {Object.entries(STRATEGY_VOCABULARY).map(([ruleType, entry]) => (
            <div key={ruleType}>
              <dt>
                {entry.name}{" "}
                <code>{ruleType}</code>
              </dt>
              <dd>
                <span className="strategy-family">{entry.family}</span>
                <span>{entry.behaviour}</span>
              </dd>
            </div>
          ))}
        </dl>
        <p>
          Both are <strong>long-or-flat</strong>: they hold the instrument or they
          hold cash, and never take a short position. Both are{" "}
          <strong>fully specified before any data is read</strong> — the window,
          the parameter, the costs and the checks are fixed in the confirmation
          receipt, so neither can be adjusted after seeing how it performed.
        </p>
        <p>
          Neither is original, and QuantLens does not claim otherwise. Trend
          following on a moving average is among the most studied rules in
          quantitative finance, which is precisely why it is a useful subject: an
          effect this well documented is a fair test of whether an evidence
          pipeline reports honestly, including when the answer is that the rule
          did not beat simply holding the instrument.
        </p>
      </section>

      <section className="workspace-section">
        <h2>Universal execution conventions</h2>
        <ul>
          <li><strong>Decide at close, fill at next open.</strong>{" "}Signals use each
          daily bar&rsquo;s close; positions change at the following bar&rsquo;s open. The
          bar that fires a signal is never the fill bar.</li>
          <li><strong>Long/flat only,</strong>{" "}full notional, fractional shares. No
          shorting, leverage, or intraday activity in this release.</li>
          <li><strong>Itemized costs.</strong>{" "}Commission and slippage in basis points
          of every fill&rsquo;s notional, declared up front and editable before
          confirmation.</li>
          <li><strong>Fair benchmark.</strong>{" "}Buy-and-hold starts at the
          strategy&rsquo;s first tradable decision date — never earlier — and pays the
          same entry cost model (&ldquo;hold from first decision&rdquo;).</li>
          <li><strong>Metrics.</strong>{" "}Annualized on 252 trading days; Sharpe uses
          rf&nbsp;=&nbsp;0 and sample standard deviation (ddof&nbsp;=&nbsp;1); the metric
          path starts at initial capital so first-fill costs are included. Uninvested
          cash earns 0% in the current engine, so long cash periods do not include any
          yield that might have been available from cash or Treasury bills.</li>
          <li><strong>Return basis.</strong>{" "}It follows the dataset, and every report
          states which basis produced its own figures. This release bundles synthetic
          data only. Uploaded CSVs declaring split-adjusted prices report price return
          with dividends excluded. This is not the full return an investor would receive.</li>
        </ul>
      </section>

      <section className="workspace-section">
        <h2>Two validation rigors</h2>
        <p>
          The Research Studio asks you to choose the rigor before confirmation, and the
          sealed report is bound to that choice. Neither rigor is ever silently
          substituted for the other.
        </p>

        <h3>Standard audit</h3>
        <ul>
          <li><strong>In-sample / out-of-sample split.</strong>{" "}The final declared
          fraction of the window is held out. Parameter sweeps receive only the
          in-sample slice; the out-of-sample segment&rsquo;s primary estimate executes
          exactly once per confirmed spec, with an execution audit sealed alongside
          it.</li>
          <li><strong>Parameter sensitivity.</strong>{" "}Every declared grid cell is
          computed on the in-sample window and every cell is reported, with the chosen
          cell&rsquo;s percentile and its immediate neighbors — never only the best
          cell.</li>
          <li><strong>Transaction-cost stress.</strong>{" "}The declared costs are re-run
          at every declared multiplier (default 0×, 1×, 2×, 4×) for both segments,
          reported separately — never blended.</li>
          <li><strong>Falsification.</strong>{" "}A non-suppressible section reports
          out-of-sample decay, cost fragility, and parameter fragility against
          pre-declared thresholds.</li>
          <li><strong>Limits.</strong>{" "}One chronological split is not walk-forward
          evidence, and because parameters are explored on the in-sample window, the
          out-of-sample estimate constrains — but cannot eliminate — selection effects.
          Treat a Standard audit as a research screen, not a validation of record.</li>
        </ul>

        <h3>Strict validation <em className="chip default">Recommended</em></h3>
        <ul>
          <li><strong>Locked rule.</strong>{" "}The rule and its parameters are frozen at
          confirmation. No parameter search, selection, or tuning happens anywhere in
          the run.</li>
          <li><strong>Walk-forward development.</strong>{" "}The development window is
          evaluated across expanding walk-forward folds with sealed per-fold results —
          no single lucky split.</li>
          <li><strong>Preregistered robustness checks.</strong>{" "}Cost stress and
          regime-coverage analysis run on development evidence only, against thresholds
          declared before execution. A quadrant with too few observations is reported
          inconclusive, never extrapolated.</li>
          <li><strong>Single-use final holdout.</strong>{" "}The final holdout is
          evaluated exactly once, at base costs, and its one-time reveal is recorded in
          a sealed execution audit. A later run on the same data window can never
          reveal it again.</li>
          <li><strong>What the holdout never does.</strong>{" "}No parameter is ever
          selected from final-holdout results, and the holdout is never re-run for
          cost counterfactuals or any other what-if.</li>
        </ul>
      </section>

      <section className="workspace-section">
        <h2>Data-source assurance</h2>
        <p>
          Every report labels its data source, and the label carries a different
          assurance. The differences are stated here once, truthfully.
        </p>
        <div
          className="tablewrap"
          role="region"
          aria-label="Data-source assurance matrix"
          tabIndex={0}
        >
          <table data-testid="data-assurance-matrix">
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">What it is</th>
                <th scope="col">What QuantLens seals</th>
                <th scope="col">Boundary</th>
              </tr>
            </thead>
            <tbody>
              {DATA_ASSURANCE_ROWS.map((row) => (
                <tr key={row.source}>
                  <th scope="row">{row.source}</th>
                  <td>{row.nature}</td>
                  <td>{row.assurance}</td>
                  <td>{row.boundary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="workspace-section">
        <h2>Provenance and reproducibility</h2>
        <ul>
          <li>Runs execute only against a pinned, immutable data snapshot. The
          snapshot&rsquo;s identity is sealed into every run&rsquo;s audit trail.</li>
          <li>An imported dataset receives an opaque dataset ID and a sealed dataset
          manifest binding its coverage and adjustment convention. Reports display
          those identifiers, never a local path or source filename.</li>
          <li>Every artifact — equity series, trade ledger, stress tables, robustness
          findings — is a write-once, content-hashed file; the run manifest binds the
          specification, snapshot identity, engine version, runtime digest, battery
          configuration, and the final result record.</li>
          <li>The on-screen report and the exported report render from one shared,
          integrity-checked projection of those sealed artifacts. A tampered or
          incomplete record refuses to render rather than showing partial numbers.</li>
          <li>Byte-identical replay of a sealed run on a clean worker is planned; in this
          release the evidence record is content-hashed but not yet independently
          replayed.</li>
          <li><strong>Drafting provenance.</strong>{" "}Plain-language hypotheses are
          interpreted on this machine by a deterministic rules engine. Every drafting
          response records whether any external provider was involved, and material
          fields are never guessed — unresolved fields become questions, not
          assumptions.</li>
        </ul>
      </section>

      <section className="workspace-section">
        <h2>What QuantLens is not (in this release)</h2>
        <ul>
          <li><strong>No independently authenticated market feed.</strong>{" "}Bundled
          sample series are synthetic and illustrative — they are not market data. For an
          imported source: <strong>your data is integrity-checked; source accuracy is not
          independently authenticated.</strong>{" "}
          QuantLens checks and seals the normalized structure; the source values, usage
          rights, symbol, timezone, and adjustment attestation remain your
          responsibility.</li>
          <li><strong>Not advice.</strong>{" "}QuantLens never recommends a security,
          position, timing, threshold, or action, and never certifies a strategy as safe
          or profitable. A passed check means one declared check did not fire — nothing
          more.</li>
          <li><strong>Not an autonomous trader.</strong>{" "}There is no brokerage link,
          no order execution, and no strategy generation. You author the hypothesis; the
          audit tries to break it.</li>
        </ul>
      </section>
    </main>
  );
}
