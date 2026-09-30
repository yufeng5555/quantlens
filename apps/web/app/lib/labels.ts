/**
 * Single vocabulary for every machine state the UI can receive. Raw backend tokens
 * (snake_case statuses, ALL-CAPS battery values, check ids) must pass through these
 * maps before they reach a user; unmapped values fall back to neutral product
 * language, never to the raw token.
 */

export type BatteryStatus = "PASS" | "FAIL" | "INCONCLUSIVE" | "NOT RUN";
export type CheckStatus = "PASS" | "FAIL" | "INCONCLUSIVE";

/** Current research-engine return convention. Keep this visible anywhere a
 * performance claim could otherwise be mistaken for an investor's total return. */
export const CURRENT_RETURN_BASIS_LABEL = "Price return · dividends excluded";
export const CURRENT_RETURN_BASIS_NOTE =
  "Current reports use split-adjusted price returns. Dividends and distributions "
  + "are excluded, so these results do not represent the full holding-period return.";

export const TOTAL_RETURN_BASIS_LABEL = "Total return · dividends reinvested";
export const TOTAL_RETURN_BASIS_NOTE =
  "This dataset is total-return adjusted: dividends and distributions are reinvested "
  + "in the underlying series, so these results approximate the full holding-period "
  + "return before tax.";

/** The manifest value a dataset carries when its bars already include dividends. */
export const TOTAL_RETURN_ADJUSTMENT = "operator_attested_total_return_ohlc";

/** Which basis wording a result is entitled to.
 *
 * The two sentences say opposite things, and saying the wrong one is not a cosmetic
 * slip: telling a reader dividends were excluded from figures that already contain
 * them makes them add a return that is already counted. The basis therefore follows
 * the dataset, and anything without a declared basis keeps the price-return wording
 * the bundled synthetic series has always warranted.
 */
export function returnBasisCopy(priceAdjustment?: string | null): {
  label: string; note: string;
} {
  return priceAdjustment === TOTAL_RETURN_ADJUSTMENT
    ? { label: TOTAL_RETURN_BASIS_LABEL, note: TOTAL_RETURN_BASIS_NOTE }
    : { label: CURRENT_RETURN_BASIS_LABEL, note: CURRENT_RETURN_BASIS_NOTE };
}

/** Current cash/rf convention. This is material for long/flat strategies and
 * therefore belongs next to performance results, not only in methodology notes. */
export const CURRENT_CASH_ASSUMPTION_LABEL = "Cash yield assumed 0% · Sharpe rf = 0";
export const CURRENT_CASH_ASSUMPTION_NOTE =
  "When a strategy is flat, uninvested cash earns 0% in the current engine. Sharpe "
  + "also uses rf = 0. Long cash periods therefore omit any return that "
  + "might have been available from cash or Treasury bills.";

/** Every run-lifecycle state the control plane can report. */
export const RUN_STATE_LABELS: Record<string, string> = {
  queued: "Queued",
  snapshot_pinned: "Preparing data",
  running_engine: "Running backtest",
  running_battery: "Running robustness checks",
  ledger_sealed: "Sealing evidence",
  report_rendered: "Preparing report",
  published: "Completed",
  validation_failed: "Stopped — specification invalid",
  data_quality_failed: "Stopped — data-quality check",
  snapshot_failed: "Needs attention",
  engine_failed: "Needs attention",
  battery_failed: "Needs attention",
  ledger_failed: "Needs attention",
  render_failed: "Needs attention",
  publication_failed: "Needs attention",
  system_failed: "Needs attention",
};

export function runStateLabel(status: string): string {
  return RUN_STATE_LABELS[status] ?? "Processing";
}

export function isTerminalFailure(status: string): boolean {
  return status.endsWith("_failed");
}

/** Ordered lifecycle stages for the run progress timeline. */
export const RUN_STAGES: [string, string][] = [
  ["queued", "Queued"],
  ["snapshot_pinned", "Preparing data"],
  ["running_engine", "Running backtest"],
  ["running_battery", "Running robustness checks"],
  ["ledger_sealed", "Sealing evidence"],
  ["report_rendered", "Preparing report"],
  ["published", "Completed"],
];

export type OutcomeTone = "good" | "bad" | "warn" | "neutral" | "active";

export interface RunOutcome {
  label: string;
  tone: OutcomeTone;
}

/**
 * Outcome language for a run: one phrase that resolves the old "Ready + Battery FAIL"
 * conflict. `failedChecks` sharpens the phrase when the caller has the sealed findings.
 */
export function runOutcome(
  status: string,
  battery: BatteryStatus,
  failedChecks?: number,
): RunOutcome {
  const completed = status === "published" || status === "report_rendered";
  if (completed && battery === "PASS") {
    return {
      label: "Audit complete · no declared fragility triggered",
      tone: "good",
    };
  }
  if (completed && battery === "FAIL") {
    if (typeof failedChecks === "number" && failedChecks > 0) {
      return {
        label: `Audit complete · ${failedChecks} material fragilit${failedChecks === 1 ? "y" : "ies"}`,
        tone: "bad",
      };
    }
    return { label: "Audit complete · material fragility detected", tone: "bad" };
  }
  if (completed && battery === "INCONCLUSIVE") {
    return { label: "Audit complete · evidence inconclusive", tone: "warn" };
  }
  if (completed) {
    return { label: "Completed", tone: "neutral" };
  }
  if (status === "system_failed" && battery !== "NOT RUN") {
    // Sealed evidence exists even though publication failed afterwards.
    return runOutcome("published", battery, failedChecks);
  }
  if (isTerminalFailure(status)) {
    return { label: runStateLabel(status), tone: "warn" };
  }
  return { label: runStateLabel(status), tone: "active" };
}

/**
 * The strategies this build implements, by their recognised names.
 *
 * Both belong to the trend-following family, and both are long-or-flat: they
 * hold the instrument or they hold cash, never a short position. Naming them is
 * not decoration — a reader who cannot name what was tested cannot look up
 * whether it is a known effect, cannot compare it to published work, and cannot
 * tell whether the result is interesting or merely rediscovered.
 */
export interface StrategyVocabulary {
  /** The name this rule is known by outside this product. */
  name: string;
  /** The family it belongs to, in one phrase. */
  family: string;
  /** What it does, without symbols or parameters. */
  behaviour: string;
}

export const STRATEGY_VOCABULARY: Record<string, StrategyVocabulary> = {
  price_vs_ma: {
    name: "Moving-average trend filter",
    family: "Trend following · time-series momentum",
    behaviour:
      "Hold the instrument while its price is above its own moving average, "
      + "and hold cash otherwise. One average, used as an on/off switch.",
  },
  ma_crossover: {
    name: "Moving-average crossover",
    family: "Trend following · time-series momentum",
    behaviour:
      "Hold the instrument while a faster moving average is above a slower one, "
      + "and hold cash otherwise. The 50-day over 200-day case is the pattern "
      + "commonly called a golden cross.",
  },
};

export function strategyName(ruleType: string | undefined | null): string {
  return STRATEGY_VOCABULARY[String(ruleType ?? "")]?.name ?? "Declared rule";
}

export function strategyVocabulary(
  ruleType: string | undefined | null,
): StrategyVocabulary | null {
  return STRATEGY_VOCABULARY[String(ruleType ?? "")] ?? null;
}

/** Robustness-check ids from the sealed battery (v1 and v2 vocabularies). */
export const CHECK_LABELS: Record<string, string> = {
  oos_decay: "Out-of-sample decay",
  cost_fragility: "Cost fragility",
  parameter_fragility: "Parameter fragility",
  walk_forward_stability: "Positive-fold coverage",
  development_cost_fragility: "Development cost fragility",
  regime_coverage: "Regime coverage",
};

/** Preregistered regime quadrants (Battery v2 server law). */
export const REGIME_LABELS: Record<string, string> = {
  up_low: "Uptrend · low volatility",
  up_high: "Uptrend · high volatility",
  down_low: "Downtrend · low volatility",
  down_high: "Downtrend · high volatility",
};

export function regimeLabel(regime: string): string {
  const known = REGIME_LABELS[regime];
  if (known) return known;
  const words = regime.replaceAll(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function checkLabel(id: string): string {
  const known = CHECK_LABELS[id];
  if (known) return known;
  const words = id.replaceAll("_", " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** What a failed check means, and what the reader can do about it.
 *
 * The report used to stop at the verdict: it told someone their rule failed a
 * named check and left them holding that. A tool that only says no is worth
 * much less than one that says no and names the next question — and the engine
 * already knows the answer, it just never said it.
 *
 * Every sentence here is STATIC copy keyed to the check id, and every threshold
 * quoted is the pre-declared one from the sealed battery config (v1:
 * `BATTERY_CONFIG`, v2: `BATTERY_CONFIG_V2`). Nothing here is generated. The
 * landing page promises that no number in this product comes from a language
 * model, and this is the surface most likely to break that promise.
 */
export const CHECK_FAILURE_GUIDANCE: Record<
  string, { meaning: string; next: string }
> = {
  // v1 — fires if OOS Sharpe < 50% of IS Sharpe, or OOS return is negative
  // while IS is positive.
  oos_decay: {
    meaning: "The rule performed better on the data used to develop it than on "
      + "the data held back. Keeping less than half the Sharpe ratio out of "
      + "sample is the signature of a rule fitted to its own test window rather "
      + "than one that found something durable.",
    next: "Run the same rule, with the same parameters unchanged, on a "
      + "different instrument or a different period. If it decays there too, "
      + "the parameters were fitted rather than discovered.",
  },
  // v1 — fires if at 2x costs the OOS total return is negative, or retains
  // < 50% of the base-cost OOS return.
  cost_fragility: {
    meaning: "Doubling the declared commission and slippage removed most of the "
      + "result. The edge is close in size to the cost of trading it.",
    next: "Check how often the rule trades. An edge that survives only at "
      + "optimistic costs usually has to trade less often — or is not an edge.",
  },
  // v1 — fires if a ±1-step grid neighbour loses >= 30% of the chosen cell's
  // IS Sharpe, or flips its sign.
  parameter_fragility: {
    meaning: "Moving the parameter a single step in the tested grid loses at "
      + "least 30% of the result. The outcome depends on the exact number "
      + "chosen rather than on the idea behind it.",
    next: "Pick the parameter for a reason you can state before testing — a "
      + "horizon that matches your thesis — instead of keeping whichever value "
      + "happened to test best.",
  },
  // v2 — FAIL when fewer than half the fixed-rule development folds were positive.
  walk_forward_stability: {
    meaning: "Fewer than half of the rolling development windows were "
      + "profitable. The total return is concentrated in a minority of periods "
      + "rather than earned steadily across them.",
    next: "Look at when the positive folds fall. If they cluster in one "
      + "stretch, the result describes that stretch — one episode, not a "
      + "repeatable rule.",
  },
  // v2 — FAIL when doubled development costs turn the return negative or cut
  // it below half the base-cost return.
  development_cost_fragility: {
    meaning: "At twice the declared commission and slippage, the development "
      + "result either turned negative or lost more than half its return.",
    next: "Count how often the rule trades across the development window. Note "
      + "that the final holdout is deliberately never re-run under stressed "
      + "costs, so this is the only cost evidence this run can offer.",
  },
  // v2 — each of the four preregistered regimes needs >= 20 development
  // observations (trend over 200 bars; high volatility >= 20% annualized).
  regime_coverage: {
    meaning: "At least one of the four preregistered market conditions — "
      + "trending up or down, calm or volatile — has fewer than 20 observations "
      + "in the development window. The rule has not been tested against that "
      + "condition at all.",
    next: "Find the short regime in the evidence below, then extend the data "
      + "window to include a period that contains it. A rule never tested in a "
      + "falling market carries no evidence about falling markets.",
  },
};

/** Guidance for a failed check, or null when there is nothing honest to add. */
export function checkFailureGuidance(
  id: string, status: string,
): { meaning: string; next: string } | null {
  // Deliberately FAIL only. INCONCLUSIVE means the check could not run, which
  // is a different situation and must not be dressed up as a finding.
  if (String(status).toUpperCase() !== "FAIL") return null;
  return CHECK_FAILURE_GUIDANCE[id] ?? null;
}

export const CHECK_STATUS_LABELS: Record<BatteryStatus, string> = {
  PASS: "Passed",
  FAIL: "Failed",
  INCONCLUSIVE: "Inconclusive",
  "NOT RUN": "Not run",
};

export function checkStatusLabel(status: BatteryStatus): string {
  return CHECK_STATUS_LABELS[status] ?? "Not run";
}

export function statusChipClass(status: BatteryStatus | CheckStatus): string {
  return status === "NOT RUN" ? "notrun" : status.toLowerCase();
}

/** Canonical three-state data label derived from a spec source kind. */
export function sourceKindToDataLabel(
  kind: string | undefined | null,
): "SYNTHETIC" | "USER_UPLOADED" | "LICENSED_PROVIDER" {
  if (kind === "licensed_provider") return "LICENSED_PROVIDER";
  if (kind === "user_provided") return "USER_UPLOADED";
  return "SYNTHETIC";
}

/** Whether this series is the CC BY 4.0 bundle QuantLens ships, not the reader's file.
 *
 * The sealed evidence contract closes `data_label` to three values
 * (`narrative_facts.py` refuses anything else), so the bundle necessarily arrives
 * stamped USER_UPLOADED and cannot be given a fourth label without re-sealing the
 * worker. It is still distinguishable, and exactly: the total-return basis is
 * OPERATOR-attested and written only by the bundle seeder — the upload routes never
 * pass a basis at all, so a reader's own file always carries the user-attested
 * split-adjusted one. Same signal the API already uses to pick the CC BY notice.
 *
 * This matters because "Your data" on a licensed series is not a cosmetic slip: it
 * tells the reader they are responsible for usage rights and adjustment accuracy
 * that QuantLens itself attested to, and the exported report says the opposite.
 */
export function isBundledCcBy(
  dataLabel: string | undefined | null,
  priceAdjustment?: string | null,
): boolean {
  return String(dataLabel ?? "").toUpperCase() === "USER_UPLOADED"
    && priceAdjustment === TOTAL_RETURN_ADJUSTMENT;
}

/** Badge modifier class for the data sources (pairs with .sample-badge). */
export function dataLabelBadgeClass(
  label: string | undefined | null,
  priceAdjustment?: string | null,
): string {
  if (isBundledCcBy(label, priceAdjustment)) return " bundled";
  const value = String(label ?? "").toUpperCase();
  if (value === "USER_UPLOADED") return " user-data";
  if (value === "LICENSED_PROVIDER") return " licensed";
  return "";
}

/** Data-source labels: honest, product-voiced, never the internal enum.
 *
 * `priceAdjustment` is optional so a surface that genuinely cannot reach it still
 * compiles — but omitting it where it IS reachable reintroduces the defect, so
 * pass it wherever the dataset or run provenance is in hand.
 */
export function dataSourceLabel(
  dataLabel: string | undefined | null,
  priceAdjustment?: string | null,
): string {
  if (isBundledCcBy(dataLabel, priceAdjustment)) return "Bundled data";
  const value = String(dataLabel ?? "").toUpperCase();
  if (value === "USER_UPLOADED") return "Your data";
  if (value === "LICENSED_PROVIDER") return "Licensed data";
  return "Sample data";
}

export function dataSourceDescription(
  dataLabel: string | undefined | null,
  priceAdjustment?: string | null,
): string {
  if (isBundledCcBy(dataLabel, priceAdjustment)) {
    return "Bundled real market data supplied by QuantLens under CC BY 4.0 — "
      + "sealed and integrity-checked; upstream source accuracy not independently "
      + "authenticated";
  }
  const value = String(dataLabel ?? "").toUpperCase();
  if (value === "USER_UPLOADED") {
    return "Your imported dataset — integrity-checked; source accuracy not independently authenticated";
  }
  if (value === "LICENSED_PROVIDER") {
    return "Licensed-provider dataset — sealed and integrity-checked";
  }
  return "Bundled sample series for product evaluation — not market data";
}

/** Concise instrument descriptors; first meaningful mention pairs symbol + full name. */
export const INSTRUMENT_DESCRIPTORS: Record<string, string> = {
  SPY: "SPDR S&P 500 ETF Trust (SPY) · S&P 500 ETF",
  QQQ: "Invesco QQQ Trust (QQQ) · Nasdaq-100 ETF",
  DIA: "SPDR Dow Jones Industrial Average ETF (DIA)",
  IWM: "iShares Russell 2000 ETF (IWM)",
  EFA: "iShares MSCI EAFE ETF (EFA)",
  XLK: "Technology Select Sector SPDR Fund (XLK)",
  GLD: "SPDR Gold Shares (GLD)",
  TLT: "iShares 20+ Year Treasury Bond ETF (TLT)",
};

export function instrumentDescriptor(symbol: string): string | null {
  return INSTRUMENT_DESCRIPTORS[symbol.toUpperCase()] ?? null;
}

/** Authentication-mode tokens mapped to product language; raw values belong in
 * the Security details drawer only. */
export const AUTH_MODE_LABELS: Record<string, string> = {
  "local-preview": "Local sample session",
  "email-magic-link": "One-time email link",
  google: "Google account",
  oidc: "Single sign-on (OIDC)",
  oauth: "Single sign-on (OAuth)",
  saml: "Single sign-on (SAML)",
};

export function authModeLabel(mode: string): string {
  return AUTH_MODE_LABELS[mode] ?? "External identity provider";
}

const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  researcher: "Researcher",
  viewer: "Viewer",
  admin: "Administrator",
};

export function roleLabel(role: string): string {
  const known = ROLE_LABELS[role.toLowerCase()];
  if (known) return known;
  const words = role.replaceAll(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Workspace/session vocabulary — one compact, honest badge. */
export const WORKSPACE_LABELS = {
  sample: "Local research workspace",
  // Badge accessible name: must not start with sign-in vocabulary, or the link
  // itself reads like a sign-in control to assistive technology.
  sampleDetail:
    "Hosted account features, team sharing, billing, and live provider activation "
    + "are not enabled in this local environment",
  authenticated: "Private research workspace",
  unavailable: "Workspace unavailable",
  loading: "Checking workspace",
} as const;

/** Compact badge labels for narrow viewports — always a visible word, never a bare dot. */
export const WORKSPACE_SHORT_LABELS = {
  sample: "Local workspace",
  authenticated: "Private workspace",
  unavailable: "Unavailable",
  loading: "Checking",
} as const;
