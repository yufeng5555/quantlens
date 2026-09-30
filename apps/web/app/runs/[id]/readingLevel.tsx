"use client";

import type { ReactNode } from "react";
import type { CheckStatus } from "@schema/ts/evidence";
import type { ReportRole } from "../../components/WorkspaceSession";
import { TOTAL_RETURN_ADJUSTMENT } from "../../lib/labels";

/**
 * Reading level is a presentation choice, never a data choice.
 *
 * Both levels are projected from the same sealed evidence object, through the
 * same formatters, in the same order. Nothing on this layer adds, blends,
 * rounds, re-derives, or withholds a value: every figure a plain-language
 * reader sees is a restatement of a figure the professional report shows, and
 * every failing check stays visible at both levels. Plain language changes the
 * wording and the density only.
 *
 * "expert" is the resting default for a workspace that stores no preference at
 * all — every local workspace — so the professional report renders exactly as
 * it always has where no account exists.
 *
 * An account is different: it carries a stored value from the moment it is
 * created, and that value is "novice" (see DEFAULT_REPORT_ROLE). Somebody who
 * signs in and never answers the question is far more likely to be new to this
 * than to want the full apparatus, and every figure is identical either way, so
 * the plain reading is the kinder place to land. The switch on any report moves
 * them in one click.
 */
export type ReadingLevel = ReportRole;

export const DEFAULT_READING_LEVEL: ReadingLevel = "expert";

/* ------------------------------------------------------------------ switch */

const LEVEL_CHOICES: { level: ReadingLevel; label: string; hint: string }[] = [
  {
    level: "novice",
    label: "Plain language",
    hint: "Ordinary words first, technical sections collapsed",
  },
  {
    level: "expert",
    label: "Full detail",
    hint: "The complete professional report, nothing collapsed",
  },
];

export function ReadingLevelSwitch({ value, onChange, saving, saveError }: {
  value: ReadingLevel;
  onChange: (level: ReadingLevel) => void;
  saving?: boolean;
  saveError?: string | null;
}) {
  const active = LEVEL_CHOICES.find((choice) => choice.level === value) ?? LEVEL_CHOICES[1];
  return (
    <div className="reading-level-bar" data-testid="reading-level">
      <div className="reading-level-group" role="group" aria-label="Report reading level">
        <span className="reading-level-caption">Reading level</span>
        {LEVEL_CHOICES.map((choice) => (
          <button
            key={choice.level}
            type="button"
            className="reading-level-option"
            data-testid={`reading-level-${choice.level}`}
            aria-pressed={value === choice.level}
            disabled={saving}
            onClick={() => onChange(choice.level)}
          >
            {choice.label}
          </button>
        ))}
      </div>
      <p className="reading-level-note" role={saveError ? "alert" : undefined}>
        {saveError
          ?? (saving
            ? "Saving this preference to your workspace…"
            : `${active.hint}. Wording and density only — both levels show the same `
              + "sealed numbers and the same failing checks.")}
      </p>
    </div>
  );
}

/* --------------------------------------------------------- technical block */

/**
 * A block a plain-language reader can open but does not have to read first.
 *
 * At "expert" the children render exactly as they always have — the wrapper is
 * a fragment, so the professional report's markup is unchanged. At "novice" the
 * same children move inside a closed disclosure. Nothing is dropped at either
 * level; only the reader's starting position moves.
 */
export function TechnicalBlock({ summary, level, testId, children }: {
  summary: string;
  level: ReadingLevel;
  testId?: string;
  children: ReactNode;
}) {
  if (level !== "novice") return <>{children}</>;
  return (
    <details className="drawer technical-block" data-testid={testId}>
      <summary>{summary}</summary>
      <div className="drawer-body">{children}</div>
    </details>
  );
}

/* -------------------------------------------------------------- vocabulary */

/** Plain-language questions behind each declared check id (v1 and v2 vocabularies). */
const PLAIN_CHECK_QUESTIONS: Record<string, string> = {
  oos_decay: "Did the pattern still show up outside the window it was built on?",
  cost_fragility: "Does it still hold up when trading costs are higher?",
  development_cost_fragility: "Does it still hold up when trading costs are higher?",
  parameter_fragility: "Was the chosen setting an unusually lucky one?",
  walk_forward_stability: "Did it hold up across most time slices, not just one?",
  regime_coverage: "Was it exercised in both rising and falling markets?",
};

export function plainCheckQuestion(id: string, fallback: string): string {
  return PLAIN_CHECK_QUESTIONS[id] ?? `Declared check: ${fallback}`;
}

/** Plain wording for a sealed check status. A status reports only whether a
 * declared check fired — never an endorsement — so the plain form stays factual. */
const PLAIN_CHECK_STATUS: Record<string, string> = {
  // "No problem found", in green, is read as "this strategy is fine". It is not what a
  // passing check means: a check reports only whether the one thing it was written to
  // look for happened. Naming the check keeps the sentence inside its own evidence.
  PASS: "This check found nothing",
  FAIL: "Problem found",
  INCONCLUSIVE: "Could not tell",
  "NOT RUN": "Not run",
};

export function plainCheckStatus(status: CheckStatus | "NOT RUN"): string {
  return PLAIN_CHECK_STATUS[status] ?? "Not run";
}

/** What "price return" means for a run, in the terms of the data it actually ran on.
 *
 * This drawer is the plain-language reader's only definition of the term, and the
 * two possible sentences say opposite things. Telling somebody dividends were left
 * out of figures that already contain them is not a wording slip: it invites them to
 * add back a return that is already counted, and the error runs in the flattering
 * direction. The definition therefore follows the run's dataset, like every other
 * basis statement in the product.
 */
function plainReturnBasis(priceAdjustment?: string | null): string {
  return priceAdjustment === TOTAL_RETURN_ADJUSTMENT
    ? "How much the balance changed. The price history behind this report already "
      + "has dividends put back in, so they are counted in these figures — do not "
      + "add them on top."
    : "How much the balance changed, ignoring dividends. This report's figures leave "
      + "dividends out, so they understate what owning the fund would have paid.";
}

/** Terms a professional report uses without explanation, defined once. */
export function glossaryTerms(priceAdjustment?: string | null): [string, string][] {
  return [
    ["Backtest", "Replaying a fixed rule over past prices to see what it would have done. It is a record of the past, not a prediction."],
    ["In-sample / development", "The stretch of history the rule was allowed to be built and checked against. Results here flatter the rule."],
    ["Out-of-sample / final holdout", "A stretch of history kept away from the rule while it was being built, then read once at the end. It is the more honest of the two."],
    ["Benchmark", "The simple alternative the rule is measured against — here, buying the listed fund and holding it over the same stretch."],
    ["Price return", plainReturnBasis(priceAdjustment)],
    ["CAGR", "The steady yearly rate that would have produced the same ending balance."],
    ["Volatility", "How much the balance jumped around from day to day. Higher means a bumpier ride."],
    ["Sharpe", "Return measured against how bumpy the ride was. Higher means steadier for the same result; cash is assumed to earn 0% here."],
    ["Max drawdown", "The deepest fall from a previous high point before recovering. It is what the worst stretch felt like."],
    ["Time in market", "How much of the period the rule actually held the fund. The rest of the time it sat in cash, earning 0% in this engine."],
    ["Walk-forward", "Testing the rule on one slice of history after another, moving forward, instead of on one convenient window."],
    ["Falsification check", "A test written in advance to try to break the idea. It is kept in the report whether it passes or fails."],
    ["Sealed evidence", "The run's numbers were written once, hashed, and re-read for this page. Nothing here is retyped or recalculated by hand."],
  ];
}

export function GlossaryDrawer({ priceAdjustment }: {
  priceAdjustment?: string | null;
}) {
  return (
    <details className="drawer plain-glossary" data-testid="plain-glossary">
      <summary>Plain-language glossary — every term this report uses</summary>
      <div className="drawer-body">
        <dl className="plain-glossary-list">
          {glossaryTerms(priceAdjustment).map(([term, meaning]) => (
            <div key={term}>
              <dt>{term}</dt>
              <dd>{meaning}</dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  );
}

/* ---------------------------------------------------------- plain summary */

export interface PlainCheckFact {
  id: string;
  label: string;
  status: CheckStatus | "NOT RUN";
}

/**
 * Every field is a string already formatted by the caller from the sealed
 * evidence object, or a count of sealed check records. This component performs
 * no arithmetic and holds no numeric literals about a result — it only places
 * sealed values into sentences.
 */
export interface PlainReportFacts {
  /** What this contract calls the window that was kept away from the rule. */
  holdoutName: string;
  /** One sentence on how that window was held back, in this contract's terms. */
  holdoutDiscipline: string;
  holdoutAvailable: boolean;
  holdoutUnavailableReason: string;
  initialCapital: string;
  finalEquity: string;
  benchmarkSymbol: string;
  benchmarkFinalEquity: string;
  strategyDrawdown: string;
  benchmarkDrawdown: string;
  tradeCount: string;
  timeInMarket: string;
  checks: PlainCheckFact[];
  dataDescription: string;
  isUserUploaded: boolean;
  /** The sealed dataset's price-adjustment token, straight from the run's own
   * provenance. The glossary's definition of price return follows it rather than a
   * build-wide constant, because the two definitions contradict each other. */
  priceAdjustment?: string | null;
}

export function PlainLanguageSummary({ facts }: { facts: PlainReportFacts }) {
  const failing = facts.checks.filter((check) => check.status === "FAIL");
  const unresolved = facts.checks.filter((check) => check.status === "INCONCLUSIVE");

  return (
    <section className="plain-summary" aria-labelledby="plain-summary-title"
      data-testid="plain-summary">
      <p className="evidence-eyebrow">In plain language</p>
      <h2 id="plain-summary-title">What this test found</h2>

      {facts.holdoutAvailable ? (
        <>
          <p className="plain-lead" data-testid="plain-summary-money">
            On the {facts.holdoutName} — the stretch of history the rule was kept away
            from while it was being built — a starting balance of{" "}
            <strong>{facts.initialCapital}</strong>{" "}would have ended at{" "}
            <strong>{facts.finalEquity}</strong>. Buying{" "}{facts.benchmarkSymbol}{" "}
            at the same moment and simply holding it would have ended at{" "}
            <strong>{facts.benchmarkFinalEquity}</strong>.
          </p>
          <p data-testid="plain-summary-drawdown">
            The ride mattered too. The rule&rsquo;s deepest fall from a previous high
            point was{" "}<strong>{facts.strategyDrawdown}</strong>; for simply holding{" "}
            {facts.benchmarkSymbol}{" "}it was{" "}
            <strong>{facts.benchmarkDrawdown}</strong>. It traded{" "}
            {facts.tradeCount}{" "}times and was actually invested{" "}
            {facts.timeInMarket}{" "}of the period — the rest of the time it sat in
            cash, which earns nothing in this engine.
          </p>
        </>
      ) : (
        <p className="plain-lead" data-testid="plain-summary-no-holdout">
          There is no held-out result to report. {facts.holdoutUnavailableReason}{" "}
          Nothing is estimated in its place, and no partial figure is shown.
        </p>
      )}

      <p>{facts.holdoutDiscipline}</p>

      <div className="plain-checks" data-testid="plain-checks">
        <h3>The tests written in advance to try to break this idea</h3>
        <ul>
          {facts.checks.map((check) => (
            <li key={check.id} className={`plain-check ${check.status.toLowerCase().replace(" ", "-")}`}>
              <span className="plain-check-question">
                {plainCheckQuestion(check.id, check.label)}
              </span>
              <strong className="plain-check-status">{plainCheckStatus(check.status)}</strong>
            </li>
          ))}
          {facts.checks.length === 0 && (
            <li className="plain-check">
              <span className="plain-check-question">
                No declared check result is present in this sealed record.
              </span>
            </li>
          )}
        </ul>
        <p className="plain-check-note">
          {failing.length > 0
            ? "A check that found a problem stays in this report. It is not removed, "
              + "averaged away, or offset by the checks that found nothing."
            : unresolved.length > 0
              ? "A check that could not settle is reported as unsettled rather than "
                + "counted as a pass."
              : "No declared check found a problem. That is a statement about these "
                + "specific tests on this specific history — nothing more."}
        </p>
      </div>

      <p className="plain-caveat" data-testid="plain-caveat">
        <strong>What this is not.</strong>{" "}This is what a fixed rule would have done
        on {facts.dataDescription}
        {facts.isUserUploaded
          ? " — QuantLens sealed that dataset and checked its integrity, but did not "
            + "check its values against an independent market-data source"
          : ""}
        . It is not investment advice, not a forecast, not a rating, and not a claim
        about what happens next. Past results do not carry forward.
      </p>

      <p className="plain-provenance">
        Every figure above is read back from this run&rsquo;s sealed record and shown
        with the same precision the full report uses. Switching to{" "}
        <strong>Full detail</strong>{" "}adds the derivations, the hashes, and the
        complete tables — it never changes a number.
      </p>

      <GlossaryDrawer priceAdjustment={facts.priceAdjustment} />
    </section>
  );
}
