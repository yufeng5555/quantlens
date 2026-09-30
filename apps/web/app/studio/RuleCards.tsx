"use client";

import { useState } from "react";
import type { StrategySpec } from "@schema/ts/types";
import { TOTAL_RETURN_ADJUSTMENT } from "../lib/labels";

export interface DatasetOption {
  dataset_id: string;
  display_name: string;
  symbol: string;
  status: "sealed";
  dataset_manifest_sha256: string;
  row_count: number;
  coverage: { start: string; end: string };
  quality: { warnings?: string[]; return_basis?: string };
  provenance?: {
    data_label?: "USER_UPLOADED" | "LICENSED_PROVIDER";
    /** Whether these bars already contain dividends. Only the bundle seeder writes
     * the operator-attested total-return value, so it is what tells a run bound to
     * this dataset which return basis it is entitled to claim. */
    price_adjustment?: string;
    instrument?: { display_name?: string; mic?: string; currency?: string };
    rights?: { use?: string; retention?: string };
  };
}

export function isLicensedDataset(dataset: DatasetOption | undefined): boolean {
  return dataset?.provenance?.data_label === "LICENSED_PROVIDER";
}

/** Whether these bars are the CC BY series QuantLens ships, rather than the reader's
 * own import. Only the bundle seeder writes the operator-attested basis, so it is the
 * honest discriminator — the same one the Data page badges with. */
export function isBundledDataset(dataset: DatasetOption | undefined): boolean {
  return dataset?.provenance?.price_adjustment === TOTAL_RETURN_ADJUSTMENT;
}

interface Props {
  spec: StrategySpec;
  defaultFields: string[];
  universe: { symbol: string; name: string }[];
  datasets: DatasetOption[];
  onEdit: (path: string, updater: (s: StrategySpec) => StrategySpec) => void;
  /** Which workflow zone to render: the strategy definition, or run setup &
   * robustness. Omit to render everything (legacy behavior). */
  zone?: "strategy" | "robustness";
  /** True when Strict validation (battery-v2) is selected: the sensitivity grid
   * is labeled as unused, since Strict runs a locked rule with no search. */
  strictProfile?: boolean;
}

function DefaultChip({ path, defaults }: { path: string; defaults: string[] }) {
  return defaults.some((d) => d === path || d.startsWith(path + ".")) ? (
    <span className="chip default">default — edit anytime</span>
  ) : null;
}

function CardShell({
  title, card, children, chip,
}: {
  title: string; card: string; children: React.ReactNode;
  chip?: React.ReactNode;
}) {
  return (
    <div className="studio-field-section" data-card={card}>
      <h3>{title} {chip}</h3>
      {children}
    </div>
  );
}

function RuleGroup({
  title, summary, children, defaultOpen = false,
}: {
  title: string;
  summary: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details
      className="studio-rule-group"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <span>{title}</span>
        <small>{summary}</small>
      </summary>
      <div className="studio-rule-group-grid">{children}</div>
    </details>
  );
}

export default function RuleCards({
  spec, defaultFields, universe, datasets, onEdit, zone, strictProfile,
}: Props) {
  const num = (v: string, fallback: number) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  };
  const showStrategy = zone !== "robustness";
  const showRobustness = zone !== "strategy";

  return (
    <div className="studio-rule-groups">
      {showStrategy && (
      <RuleGroup
        title="Strategy"
        summary={`${spec.universe.symbol} · ${spec.rule.type === "ma_crossover"
          ? `${spec.rule.fast_ma_days}/${spec.rule.ma_days}-day crossover`
          : `close above ${spec.rule.ma_days}-day average`}`}
        defaultOpen
      >
      <CardShell title="Research data" card="data-source"
        chip={<span className={`chip ${spec.data.source ? "sealed" : "default"}`}>
          {spec.data.source
            ? (spec.data.source.kind === "licensed_provider" ? "licensed data" : "your sealed data")
            : "sample data"}
        </span>}>
        <div className="field">
          <label htmlFor="dataset-source">Dataset used by this audit</label>
          <select
            id="dataset-source"
            value={spec.data.source?.dataset_id ?? "__synthetic__"}
            onChange={(event) => {
              const datasetId = event.target.value;
              onEdit("data.source", (current) => {
                if (datasetId === "__synthetic__") {
                  const fallback = universe.some((item) => item.symbol === current.universe.symbol)
                    ? current.universe.symbol : (universe[0]?.symbol ?? "SPY");
                  return {
                    ...current,
                    dsl_version: "1.0",
                    universe: { symbol: fallback },
                    meta: { name: `${fallback} trend audit` },
                    data: {
                      snapshot_policy: "pinned",
                      range: { start: "2005-01-01", end: "2024-12-31" },
                    },
                  };
                }
                const dataset = datasets.find((item) => item.dataset_id === datasetId);
                if (!dataset) return current;
                const licensed = isLicensedDataset(dataset);
                // The Studio tells the reader this name "names this run everywhere —
                // the report, and exports", and it is sealed into the spec. Calling a
                // CC BY series a "private-data study" put the wrong owner on the one
                // string that travels furthest and cannot be corrected afterwards.
                const sourceKind = licensed
                  ? "licensed-data"
                  : isBundledDataset(dataset) ? "bundled-data" : "private-data";
                return {
                  ...current,
                  // The DSL version follows the sealed source exactly: licensed
                  // provider data is 1.2, private uploads are 1.1.
                  dsl_version: licensed ? "1.2" : "1.1",
                  universe: { symbol: dataset.symbol },
                  benchmark: { type: "hold_from_first_decision", symbol: "same_as_universe" },
                  meta: {
                    name: `${dataset.symbol} · ${sourceKind} study`,
                  },
                  data: {
                    snapshot_policy: "pinned",
                    source: {
                      kind: licensed ? "licensed_provider" : "user_provided",
                      dataset_id: dataset.dataset_id,
                      dataset_manifest_sha256: dataset.dataset_manifest_sha256,
                    },
                    range: dataset.coverage,
                  },
                };
              });
            }}
          >
            <option value="__synthetic__">Bundled sample series (synthetic)</option>
            {datasets.map((dataset) => (
              <option key={dataset.dataset_id} value={dataset.dataset_id}>
                {dataset.display_name} · {dataset.symbol} ·{" "}
                {/* This is the one place a reader has to choose between their own
                    file and the licensed series, so it must say which is which.
                    Calling the CC BY bundle "your data" credited the reader for bytes
                    they never chose, in the list where it matters most. */}
                {isLicensedDataset(dataset)
                  ? "licensed"
                  : isBundledDataset(dataset) ? "bundled · CC BY" : "your data"} ·{" "}
                {dataset.row_count.toLocaleString("en-US")} rows
              </option>
            ))}
          </select>
        </div>
        {spec.data.source ? (() => {
          const dataset = datasets.find((item) => item.dataset_id === spec.data.source?.dataset_id);
          return dataset ? (
            <div className="dataset-binding" aria-live="polite">
              <strong>{dataset.display_name}</strong>
              {isLicensedDataset(dataset) && dataset.provenance?.instrument?.display_name && (
                <span>
                  {dataset.provenance.instrument.display_name}
                  {dataset.provenance.instrument.mic ? ` · ${dataset.provenance.instrument.mic}` : ""}
                  {dataset.provenance.instrument.currency ? ` · ${dataset.provenance.instrument.currency}` : ""}
                </span>
              )}
              <span>{dataset.symbol} · {dataset.coverage.start} → {dataset.coverage.end}</span>
              <span>{dataset.row_count.toLocaleString("en-US")} daily rows · sealed snapshot ·
                provenance recorded in the run&rsquo;s audit trail</span>
            </div>
          ) : (
            <p className="notice error">The sealed dataset is unavailable. Choose another source.</p>
          );
        })() : (
          <p className="muted">Sample series are generated locally for product evaluation and are clearly labeled — not market data.</p>
        )}
        <a className="linkish data-workspace-link" href="/data">
          {datasets.length ? "Manage sealed datasets" : "Import and validate your own CSV"} →
        </a>
      </CardShell>

      <CardShell title="Instrument" card="universe">
        <div className="field">
          <label htmlFor="symbol">
            {spec.data.source ? "Instrument bound by the sealed dataset" : "ETF (curated sample list)"}
          </label>
          <select
            id="symbol"
            value={spec.universe.symbol}
            disabled={Boolean(spec.data.source)}
            onChange={(e) =>
              onEdit("universe.symbol", (s) => ({
                ...s, universe: { symbol: e.target.value },
                meta: { name: s.meta.name.replace(s.universe.symbol, e.target.value) },
              }))
            }
          >
            {spec.data.source ? (
              <option value={spec.universe.symbol}>{spec.universe.symbol} — sealed user dataset</option>
            ) : universe.map((u) => (
              <option key={u.symbol} value={u.symbol}>{u.symbol} — {u.name}</option>
            ))}
          </select>
        </div>
      </CardShell>

      <CardShell
        title="Rule" card="rule"
        chip={<DefaultChip path="rule.ma_days" defaults={defaultFields} />}
      >
        <div className="field">
          <label htmlFor="ruletype">Rule shape</label>
          <select
            id="ruletype"
            value={spec.rule.type}
            onChange={(e) => {
              const t = e.target.value as StrategySpec["rule"]["type"];
              onEdit("rule.type", (s) => ({
                ...s,
                rule: t === "price_vs_ma"
                  ? { type: t, fast_ma_days: null, ma_days: s.rule.ma_days }
                  : { type: t, fast_ma_days: s.rule.fast_ma_days ?? 50, ma_days: s.rule.ma_days },
              }));
            }}
          >
            <option value="price_vs_ma">Price above N-day MA → long, else cash</option>
            <option value="ma_crossover">Fast MA &gt; slow MA → long, else cash</option>
          </select>
        </div>
        <div className="field-row">
          {spec.rule.type === "ma_crossover" && (
            <div className="field">
              <label htmlFor="fastma">Fast MA (days)</label>
              <input id="fastma" type="number" min={2} max={400}
                value={spec.rule.fast_ma_days ?? 50}
                onChange={(e) => onEdit("rule.fast_ma_days", (s) => ({
                  ...s, rule: { ...s.rule, fast_ma_days: num(e.target.value, 50) },
                }))}
              />
            </div>
          )}
          <div className="field">
            <label htmlFor="madays">{spec.rule.type === "ma_crossover" ? "Slow MA (days)" : "MA window (days)"}</label>
            <input id="madays" type="number" min={2} max={400}
              value={spec.rule.ma_days}
              onChange={(e) => onEdit("rule.ma_days", (s) => ({
                ...s, rule: { ...s.rule, ma_days: num(e.target.value, 200) },
              }))}
            />
          </div>
        </div>
      </CardShell>

      </RuleGroup>
      )}

      {showRobustness && (
      <RuleGroup
        title="Execution & costs"
        summary={`Next-open fills · ${spec.costs.commission_bps + spec.costs.slippage_bps} bps per fill · benchmark ${
          spec.benchmark.symbol === "same_as_universe" ? spec.universe.symbol : spec.benchmark.symbol
        }`}
        defaultOpen
      >
      <CardShell title="Execution" card="calendar"
        chip={<span className="chip">fixed in v1</span>}>
        <p style={{ fontSize: "0.92rem" }}>
          Daily bars. Decide at each day&rsquo;s <strong>close</strong>; fill at the{" "}
          <strong>next day&rsquo;s open</strong>. No intraday, shorting, or leverage in v1.
        </p>
      </CardShell>

      <CardShell
        title="Costs per trade" card="costs"
        chip={<DefaultChip path="costs" defaults={defaultFields} />}
      >
        <div className="field-row">
          <div className="field">
            <label htmlFor="comm">Commission (bps)</label>
            <input id="comm" type="number" min={0} max={100} step={0.5}
              value={spec.costs.commission_bps}
              onChange={(e) => onEdit("costs.commission_bps", (s) => ({
                ...s, costs: { ...s.costs, commission_bps: num(e.target.value, 1) },
              }))}
            />
          </div>
          <div className="field">
            <label htmlFor="slip">Slippage (bps)</label>
            <input id="slip" type="number" min={0} max={100} step={0.5}
              value={spec.costs.slippage_bps}
              onChange={(e) => onEdit("costs.slippage_bps", (s) => ({
                ...s, costs: { ...s.costs, slippage_bps: num(e.target.value, 5) },
              }))}
            />
          </div>
        </div>
      </CardShell>

      <CardShell
        title="Benchmark" card="benchmark"
        chip={<DefaultChip path="benchmark" defaults={defaultFields} />}
      >
        <p style={{ fontSize: "0.92rem" }}>
          Buy-and-hold <strong>{spec.benchmark.symbol === "same_as_universe"
            ? spec.universe.symbol : spec.benchmark.symbol}</strong>{" "}from your strategy&rsquo;s
          first tradable decision, paying the same entry costs (&ldquo;hold from first
          decision&rdquo; fairness rule).
        </p>
        {/* The choice here decides which question the whole report answers, and
            the two are not equally demanding. Left unexplained, a reader keeps
            the default and unknowingly answers only the easier one.

            It also has a consequence that is invisible from here and must not
            be: under Strict validation the regime classifier reads the
            BENCHMARK series, not the traded one (battery_v2 derives
            regime_market from the benchmark frame, and the sealed law says
            "benchmark_close[t-1] >= SMA200[t-1]"). Whichever series is chosen
            therefore becomes the definition of "market conditions" for the whole
            report, and a declared quadrant can end up with too few observations
            to judge.

            The worked example that used to sit here said "measured on the
            bundled series": QQQ against SPY over 2012-2020 emptying the
            uptrend/high-volatility quadrant, PASS to INCONCLUSIVE. That was
            measured on the bundled SYNTHETIC sample, which is what "bundled"
            meant when it was written. The product now also ships a licensed CC
            BY bundle, and the same configuration on THAT data does not empty the
            quadrant and does not change the status. Naming one outcome as
            though it were general is how this paragraph would start misleading
            people, so it states the mechanism and leaves the outcome to the run.

            The warning also has to apply to BOTH choices. Holding the default is
            not the safe option it looks like: on real data a thinly-traded
            single instrument is the more common cause of a thin quadrant, and
            for some instruments choosing a broad index IMPROVES coverage.
            Warning only about the harder comparison would push people toward the
            easier one for a reason that is not reliably true. */}
        <p className="benchmark-question" data-testid="benchmark-question">
          {spec.benchmark.symbol === "same_as_universe" ? (
            <>
              <strong>This report will answer:</strong>{" "}did the timing rule beat
              simply holding{" "}{spec.universe.symbol}{" "}itself? That isolates the
              rule, but it does not show whether the result beat an ordinary index
              fund — which is the comparison someone deciding where to put money
              actually faces.
            </>
          ) : (
            <>
              <strong>This report will answer:</strong>{" "}did the rule on{" "}
              {spec.universe.symbol}{" "}beat simply buying and holding{" "}
              {spec.benchmark.symbol}? A separate benchmark is the harder test:
              it must beat an alternative anyone could have chosen without this
              tool.
            </>
          )}
        </p>
        {/* Renders on BOTH branches. The regime consequence does not depend on
            whether the data is sealed, and a reader on real data used to be told
            nothing at all about it. */}
        <p className="benchmark-consequence" data-testid="benchmark-consequence">
          <strong>Worth knowing before you run it.</strong>{" "}Under Strict
          validation the market-condition breakdown is measured on whichever
          series is the benchmark, so{" "}
          {spec.benchmark.symbol === "same_as_universe"
            ? `holding ${spec.universe.symbol} as the benchmark also makes ${spec.universe.symbol} the definition of "the market"`
            : `choosing ${spec.benchmark.symbol} also makes it the definition of "the market"`}
          {" "}for this report. If that leaves one condition with too few
          observations to judge, the robustness check reports{" "}
          &ldquo;inconclusive&rdquo; rather than a pass — a statement about
          coverage, not a verdict on the strategy. Neither choice is reliably
          the safe one; it depends on the instrument and the window.
        </p>
        {spec.data.source && (
          // The engine refuses a cross-symbol benchmark on a sealed dataset --
          // runner.py raises DATASET_BENCHMARK_UNSUPPORTED on the DSL version alone,
          // because a sealed dataset carries exactly one instrument.
          //
          // The earlier wording here sent people to the sample series to get an
          // "index fund" comparison, which is bad advice twice over: it points a
          // real-money question at generated data, and it implies this study has no
          // index comparison. Every instrument in this universe IS an index fund, so
          // holding it is already the do-nothing alternative. What a sealed dataset
          // cannot do is compare a narrow fund against the BROAD market -- and the
          // honest route to that is a second sealed study on SPY, not synthetic bars.
          <p className="benchmark-consequence" data-testid="benchmark-dataset-locked">
            <strong>Fixed for this study.</strong>{" "}A sealed dataset supplies one
            instrument, so this study measures the rule against buying and holding{" "}
            {spec.universe.symbol}{" "}itself — the result anyone could have had with
            no tool and no trades.{" "}{spec.universe.symbol}{" "}is an index fund, so
            that is already an index comparison. To ask the broader question — did it
            beat the whole market? — run the same rule on your sealed SPY series over
            the same window and read the two reports side by side.
          </p>
        )}
        <div className="field">
          <label htmlFor="bench">
            {spec.data.source
              ? "Benchmark bound by the sealed dataset"
              : "Benchmark symbol"}
          </label>
          <select id="bench" value={spec.benchmark.symbol}
            disabled={Boolean(spec.data.source)}
            onChange={(e) => onEdit("benchmark.symbol", (s) => ({
              ...s, benchmark: { ...s.benchmark, symbol: e.target.value },
            }))}
          >
            <option value="same_as_universe">
              The same ETF the strategy trades ({spec.universe.symbol})
            </option>
            {universe.map((u) => (
              <option key={u.symbol} value={u.symbol}>
                {u.symbol}{u.symbol === "SPY" ? " — broad index fund" : ""}
              </option>
            ))}
          </select>
        </div>
      </CardShell>

      </RuleGroup>
      )}

      {showRobustness && (
      <RuleGroup
        title="Test design"
        summary={`${spec.data.range.start} → ${spec.data.range.end} · ${Math.round(
          spec.validation.is_oos_split.oos_fraction * 100,
        )}% held out · ${spec.validation.cost_stress.multipliers.length} cost levels`}
      >
      <CardShell
        title="Test window" card="data"
        chip={<DefaultChip path="data.range" defaults={defaultFields} />}
      >
        {(() => {
          // A sealed dataset bounds the editable window to its exact coverage; the
          // server re-validates the same rule (DATASET_RANGE_OUTSIDE_COVERAGE).
          const bound = spec.data.source
            ? datasets.find((item) => item.dataset_id === spec.data.source?.dataset_id)
            : undefined;
          return (
            <>
              <div className="field-row">
                <div className="field">
                  <label htmlFor="start">Start</label>
                  <input id="start" type="date" value={spec.data.range.start}
                    min={bound?.coverage.start} max={bound?.coverage.end}
                    onChange={(e) => onEdit("data.range", (s) => ({
                      ...s, data: { ...s.data, range: { ...s.data.range, start: e.target.value } },
                    }))}
                  />
                </div>
                <div className="field">
                  <label htmlFor="end">End</label>
                  <input id="end" type="date" value={spec.data.range.end}
                    min={bound?.coverage.start} max={bound?.coverage.end}
                    onChange={(e) => onEdit("data.range", (s) => ({
                      ...s, data: { ...s.data, range: { ...s.data.range, end: e.target.value } },
                    }))}
                  />
                </div>
              </div>
              {bound && (
                <p style={{ fontSize: "0.8rem", color: "var(--ink-faint)", margin: "2px 0 6px" }}>
                  Sealed coverage {bound.coverage.start} → {bound.coverage.end}; the
                  window can&rsquo;t extend beyond it.
                </p>
              )}
            </>
          );
        })()}
        <p style={{ fontSize: "0.85rem", color: "var(--ink-soft)" }}>
          The run pins an immutable data snapshot; its identity is recorded in the
          report&rsquo;s audit trail.
        </p>
      </CardShell>

      <CardShell
        title="Evidence battery" card="validation"
        chip={<DefaultChip path="validation" defaults={defaultFields} />}
      >
        <div className="field">
          <label htmlFor="oos">
            Out-of-sample share (primary estimate once; cost stresses audited separately)
          </label>
          <select id="oos" value={String(spec.validation.is_oos_split.oos_fraction)}
            onChange={(e) => onEdit("validation.is_oos_split.oos_fraction", (s) => ({
              ...s, validation: { ...s.validation, is_oos_split: { oos_fraction: Number(e.target.value) } },
            }))}
          >
            <option value="0.2">20%</option>
            <option value="0.3">30%</option>
            <option value="0.4">40%</option>
          </select>
        </div>
        <p style={{ fontSize: "0.85rem", color: "var(--ink-soft)" }} data-testid="sensitivity-grid-note">
          {strictProfile ? (
            <>
              <span className="chip">Not used by Strict validation</span>{" "}
              Sensitivity grid (Standard audit only): MA windows{" "}
              {spec.validation.sensitivity.grid.ma_days.join(", ")}. Strict validation
              locks the rule and performs no parameter search. Cost stress at{" "}
              {spec.validation.cost_stress.multipliers.map((m) => `${m}×`).join(", ")}{" "}
              runs on development evidence only, plus a non-suppressible falsification
              section.
            </>
          ) : (
            <>
              Sensitivity grid (in-sample only): MA windows{" "}
              {spec.validation.sensitivity.grid.ma_days.join(", ")} · Cost stress at{" "}
              {spec.validation.cost_stress.multipliers.map((m) => `${m}×`).join(", ")} · plus a
              non-suppressible falsification section.
            </>
          )}
        </p>
      </CardShell>
      </RuleGroup>
      )}
    </div>
  );
}
