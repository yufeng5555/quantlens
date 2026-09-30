"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";

import type { EvidenceView, EvidenceViewV1 } from "@schema/ts/evidence";
import { apiGet } from "../../studio/lib";
import { ApiRequestError } from "../../lib/errors";
import { exposure, money, num, pct, sessionDate } from "../../lib/format";
import {
  checkLabel,
  checkStatusLabel,
  dataSourceLabel,
  instrumentDescriptor,
  returnBasisCopy,
  runOutcome,
  statusChipClass,
} from "../../lib/labels";

/**
 * Side-by-side reading of two sealed evidence records. Display only: every value is
 * shown exactly as sealed — this page computes no new metric, delta, or ranking.
 */

type CompareFailureKind =
  | "session"
  | "permission"
  | "not_found"
  | "unavailable"
  | "integrity"
  | "unsupported"
  | "network"
  | "server";

type Slot =
  | { state: "loading"; id: string }
  | { state: "ready"; id: string; view: EvidenceView }
  | { state: "failed"; id: string; kind: CompareFailureKind }
  /** The response's sealed identity names a different run than this slot
   * requested. The complete comparison fails closed — no metric table. */
  | { state: "mismatch"; id: string };

const FAILURE_COPY: Record<CompareFailureKind, {
  testId: string;
  title: string;
  detail: string;
}> = {
  session: {
    testId: "compare-session-required",
    title: "Your research session is not available.",
    detail: "Sign in again, then reopen these runs. No sealed values are shown.",
  },
  permission: {
    testId: "compare-permission-denied",
    title: "One or both runs are outside your current workspace access.",
    detail: "Choose runs you can access in this workspace. No partial comparison is shown.",
  },
  not_found: {
    testId: "compare-not-found",
    title: "One or both selected runs could not be found.",
    detail: "A run may have been removed or may belong to another workspace.",
  },
  unavailable: {
    testId: "compare-unavailable",
    title: "One or both selected runs do not have sealed evidence to compare.",
    detail: "Evidence may still be processing or may not have sealed successfully. No partial values are shown.",
  },
  integrity: {
    testId: "compare-integrity-refusal",
    title: "A sealed evidence record failed its integrity check.",
    detail: "QuantLens suppressed the complete comparison; no financial values are shown.",
  },
  unsupported: {
    testId: "compare-unsupported-evidence",
    title: "One or both evidence records use an unsupported sealed contract.",
    detail: "Open the runs individually; QuantLens will not translate them into a different contract.",
  },
  network: {
    testId: "compare-network-error",
    title: "QuantLens could not reach the research service.",
    detail: "The comparison was not loaded. Check the workspace connection and try again.",
  },
  server: {
    testId: "compare-server-error",
    title: "The research service could not prepare this comparison.",
    detail: "Nothing partial is displayed. Try again after the service recovers.",
  },
};

function compareFailure(caught: unknown): CompareFailureKind {
  if (caught instanceof ApiRequestError) {
    if (caught.status === 401) return "session";
    if (caught.status === 403) return "permission";
    if (caught.status === 404
      || caught.code === "RUN_NOT_FOUND"
      || caught.code === "WORKSPACE_ITEM_NOT_FOUND") return "not_found";
    if (caught.code === "EVIDENCE_INTEGRITY_FAILURE") return "integrity";
    if (caught.code === "LEGACY_CHECKPOINT_REBUILD_REQUIRED"
      || caught.code === "ARTIFACT_CONTRACT_REBUILD_REQUIRED") return "unsupported";
    if (caught.code === "EVIDENCE_NOT_AVAILABLE"
      || caught.code === "SETTLEMENT_PENDING"
      || caught.code?.startsWith("LICENSED_")) return "unavailable";
    return "server";
  }
  if (caught instanceof Error && caught.message === "NETWORK") return "network";
  if (caught instanceof TypeError || caught instanceof DOMException) return "network";
  return "server";
}

function instrumentLine(view: EvidenceViewV1): string {
  const symbol = view.assumptions.spec.universe.symbol;
  return instrumentDescriptor(symbol) ?? symbol;
}

function ruleLine(view: EvidenceViewV1): string {
  const spec = view.assumptions.spec;
  return spec.rule.type === "price_vs_ma"
    ? `Long when close > ${spec.rule.ma_days}-day SMA, else cash`
    : `Long when ${spec.rule.fast_ma_days}-day SMA > ${spec.rule.ma_days}-day SMA, else cash`;
}

function windowLine(view: EvidenceViewV1): string {
  const range = view.assumptions.spec.data.range;
  return `${sessionDate(range.start)} → ${sessionDate(range.end)}`;
}

function costsLine(view: EvidenceViewV1): string {
  const costs = view.assumptions.spec.costs;
  return `${costs.commission_bps} bps commission + ${costs.slippage_bps} bps slippage per fill`;
}

/** The sealed dataset's own basis. It is what separates the CC BY bundle from the
 *  reader's own import, since the contract stamps both USER_UPLOADED. */
function sealedBasis(view: EvidenceViewV1): string | undefined {
  const manifest = (view.snapshot as Record<string, unknown> | undefined)
    ?.dataset_manifest as { price_adjustment?: unknown } | undefined;
  return typeof manifest?.price_adjustment === "string"
    ? manifest.price_adjustment : undefined;
}

function sourceLine(view: EvidenceViewV1): string {
  return dataSourceLabel(String(view.identity.data_label), sealedBasis(view));
}

function fragilityLines(view: EvidenceViewV1): string[] {
  return view.status.checks
    .filter((check) => check.status === "FAIL")
    .map((check) => checkLabel(check.id));
}

/** Display-only comparability review: flags differences in sealed assumptions. */
function comparabilityNotices(a: EvidenceViewV1, b: EvidenceViewV1): string[] {
  const notices: string[] = [];
  const specA = a.assumptions.spec;
  const specB = b.assumptions.spec;
  if (specA.universe.symbol !== specB.universe.symbol) {
    notices.push(
      `Different instruments (${instrumentLine(a)} vs ${instrumentLine(b)}): `
      + "absolute returns reflect different assets, not only different rules.",
    );
  }
  if (String(a.identity.data_label) !== String(b.identity.data_label)) {
    notices.push(
      `Different data sources (${sourceLine(a)} vs ${sourceLine(b)}): `
      + "the series are not drawn from the same catalog.",
    );
  }
  // Two USER_UPLOADED runs pass the data-source check above even when one is the
  // total-return CC BY bundle and the other a price-return import. That difference
  // is not cosmetic: dividends are inside one series and absent from the other, so
  // the gap between the two returns is partly just the dividends, and it runs in
  // the flattering direction for the bundled one (~1.8%/yr for SPY).
  const basisA = returnBasisCopy(sealedBasis(a)).label;
  const basisB = returnBasisCopy(sealedBasis(b)).label;
  if (basisA !== basisB) {
    notices.push(
      `Different return bases (${basisA} vs ${basisB}): one series contains `
      + "dividends and the other does not, so part of the difference between "
      + "these results is the dividends themselves, not the rules.",
    );
  }
  if (specA.data.range.start !== specB.data.range.start
    || specA.data.range.end !== specB.data.range.end) {
    notices.push(
      `Different test windows (${windowLine(a)} vs ${windowLine(b)}): `
      + "the runs cover different market periods.",
    );
  }
  if (specA.costs.commission_bps !== specB.costs.commission_bps
    || specA.costs.slippage_bps !== specB.costs.slippage_bps) {
    notices.push(
      `Different cost assumptions (${costsLine(a)} vs ${costsLine(b)}).`,
    );
  }
  if (specA.validation.is_oos_split.oos_fraction
    !== specB.validation.is_oos_split.oos_fraction) {
    notices.push(
      "Different out-of-sample splits: the held-out windows are not the same "
      + "fraction of each test.",
    );
  }
  const benchA = specA.benchmark.symbol === "same_as_universe"
    ? specA.universe.symbol : specA.benchmark.symbol;
  const benchB = specB.benchmark.symbol === "same_as_universe"
    ? specB.universe.symbol : specB.benchmark.symbol;
  if (benchA !== benchB) {
    notices.push(`Different benchmarks (${benchA} vs ${benchB}).`);
  }
  return notices;
}

function CompareRow({ label, a, b }: { label: string; a: React.ReactNode; b: React.ReactNode }) {
  return (
    <tr>
      <th scope="row">{label}</th>
      <td>{a}</td>
      <td>{b}</td>
    </tr>
  );
}

function coreMetricRows(view: EvidenceViewV1) {
  const oos = view.results.oos.comparison_strategy_metrics;
  const oosBench = view.results.oos.benchmark_metrics;
  const ins = view.results.is.comparison_strategy_metrics;
  const sorted = [...view.cost_stress.rows].sort((x, y) => x.multiplier - y.multiplier);
  const base = sorted.find((row) => row.multiplier === 1) ?? sorted[0];
  const highest = sorted.at(-1);
  return {
    oosVsBench: `${pct(oos.total_return)} · benchmark ${pct(oosBench.total_return)}`,
    sharpe: `${num(ins.sharpe)} → ${num(oos.sharpe)}`,
    stress: `${base ? pct(base.oos.total_return) : "—"} → ${highest ? pct(highest.oos.total_return) : "—"} (${base?.multiplier ?? "—"}× → ${highest?.multiplier ?? "—"}×)`,
    rank: view.sensitivity.chosen_percentile_in_grid === null
      ? "—"
      : `${view.sensitivity.chosen_percentile_in_grid}th percentile (${view.sensitivity.chosen_ma_days}-day MA)`,
  };
}

function segmentRows(view: EvidenceViewV1, segment: "is" | "oos") {
  const seg = view.results[segment];
  const metrics = seg.comparison_strategy_metrics;
  return {
    ret: pct(metrics.total_return),
    sharpe: num(metrics.sharpe),
    maxdd: pct(metrics.max_drawdown),
    exposure: exposure(metrics.exposure),
    finalEquity: money(metrics.final_equity),
    bars: `${view.segments[segment].bars} bars`,
  };
}

/** Bind a response to its requested slot: the sealed `identity.run_id` must equal
 * the exact requested run ID before anything derived from the body is shown. */
function slotFor(
  id: string, status: number, body: EvidenceView | Record<string, unknown>,
): Slot {
  if (status !== 200) {
    return { state: "failed", id, kind: "server" };
  }
  if (!body || typeof body !== "object" || !("identity" in body)) {
    return { state: "mismatch", id };
  }
  const identity = (body as { identity?: { run_id?: unknown } }).identity;
  if (identity?.run_id !== id) {
    return { state: "mismatch", id };
  }
  return { state: "ready", id, view: body as EvidenceView };
}

/** `useSearchParams` requires a Suspense boundary under static prerendering. */
export default function ComparePage() {
  return (
    <Suspense fallback={<main><p role="status">Loading sealed evidence for both runs…</p></main>}>
      <CompareContent />
    </Suspense>
  );
}

function CompareContent() {
  const searchParams = useSearchParams();
  const aId = searchParams.get("a");
  const bId = searchParams.get("b");
  const missingSelection = !aId || !bId || aId === bId;
  const [slots, setSlots] = useState<[Slot, Slot] | null>(null);

  useEffect(() => {
    if (!aId || !bId || aId === bId) {
      setSlots(null);
      return;
    }
    // Each selection has its own cancellation token. Cleanup (query change or
    // unmount) aborts both requests, and every completion re-checks the token and
    // its slot's requested run ID, so a late A/B response can never repaint a
    // newer C/D comparison and partial pairs are never mixed.
    const controller = new AbortController();
    const { signal } = controller;
    setSlots([{ state: "loading", id: aId }, { state: "loading", id: bId }]);
    ([aId, bId] as const).forEach((id, index) => {
      apiGet<EvidenceView | Record<string, unknown>>(
        `/runs/${encodeURIComponent(id)}/evidence`, { signal })
        .then(({ status, body }) => {
          if (signal.aborted) return;
          setSlots((current) => {
            if (!current || current[index].id !== id) return current;
            const next: [Slot, Slot] = [...current] as [Slot, Slot];
            next[index] = slotFor(id, status, body);
            return next;
          });
        })
        .catch((caught) => {
          if (signal.aborted) return;
          setSlots((current) => {
            if (!current || current[index].id !== id) return current;
            const next: [Slot, Slot] = [...current] as [Slot, Slot];
            next[index] = { state: "failed", id, kind: compareFailure(caught) };
            return next;
          });
        });
    });
    return () => controller.abort();
  }, [aId, bId]);

  if (missingSelection) {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Research library</p>
            <h1>Compare runs</h1>
          </div>
        </header>
        <div className="runs-state" data-testid="compare-missing-selection">
          <strong>Select exactly two completed runs to compare.</strong>
          Comparison reads the sealed evidence of two finished audits side by side.
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/runs">Choose runs in Runs &amp; Reports</Link>
          </p>
        </div>
      </main>
    );
  }

  // Search params change during render, while the effect that installs the new
  // loading slots runs after commit. Bind the rendered pair to the current URL as
  // well, otherwise a ready A/B table can flash once under a newer C/D URL.
  if (
    !slots
    || slots[0].id !== aId
    || slots[1].id !== bId
    || slots.some((slot) => slot.state === "loading")
  ) {
    return <main><p role="status">Loading sealed evidence for both runs…</p></main>;
  }

  // Identity binding failed for at least one slot: fail the whole comparison
  // closed. This is distinct from legitimate evidence unavailability.
  const mismatched = slots.filter((slot) => slot.state === "mismatch");
  if (mismatched.length > 0) {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Research library</p>
            <h1>Compare runs</h1>
          </div>
        </header>
        <div className="runs-state" data-testid="compare-identity-mismatch">
          <strong>
            The evidence returned for this comparison does not identify the
            requested {mismatched.length === 2 ? "runs" : "run"}.
          </strong>
          Every sealed evidence record names the exact run it belongs to. Here the
          sealed identity differs from the requested run, so the complete
          comparison is suppressed and no values are shown.
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/runs">Back to Runs &amp; Reports</Link>
          </p>
        </div>
      </main>
    );
  }

  const failed = slots.filter((slot): slot is Extract<Slot, { state: "failed" }> =>
    slot.state === "failed");
  if (failed.length > 0) {
    const priority: CompareFailureKind[] = [
      "session", "permission", "integrity", "not_found", "unsupported",
      "unavailable", "network", "server",
    ];
    const kind = priority.find((candidate) =>
      failed.some((slot) => slot.kind === candidate)) ?? "server";
    const copy = FAILURE_COPY[kind];
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Research library</p>
            <h1>Compare runs</h1>
          </div>
        </header>
        <div className="runs-state" data-testid={copy.testId}>
          <strong>{copy.title}</strong>{" "}
          {copy.detail}
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/runs">Back to Runs &amp; Reports</Link>
          </p>
        </div>
      </main>
    );
  }

  const [slotA, slotB] = slots as [Extract<Slot, { state: "ready" }>, Extract<Slot, { state: "ready" }>];
  // A v3 contract record is not comparable on this surface yet: comparison
  // eligibility for the corrected contract is a server-owned decision that
  // arrives with its own projection, so a v3 slot fails closed here exactly
  // like a legacy contract without the required semantics.
  const slotComparable = (view: (typeof slotA)["view"]): boolean =>
    view.evidence_view_version !== "v3"
    && view.artifact_contract?.verified_financial_semantics === true;
  if (!slotComparable(slotA.view) || !slotComparable(slotB.view)) {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Research library</p>
            <h1>Compare runs</h1>
          </div>
        </header>
        <div className="runs-state" data-testid="compare-contract-rebuild-required">
          <strong>These runs use an original historical financial contract.</strong>{" "}
          Their individual reports remain readable under the exact sealed labels, but
          side-by-side comparison is withheld until both runs are rebuilt under the
          corrected financial contract. QuantLens will not translate or rank the old
          values as though they used the new accounting semantics.
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/runs">Back to Runs &amp; Reports</Link>
          </p>
        </div>
      </main>
    );
  }
  // The side-by-side layout below reads the v1 contract (IS/OOS, cost stress rows,
  // sensitivity percentile). Battery-v2 evidence has a different sealed shape, so it
  // is declined honestly instead of being mapped onto v1 semantics.
  if (slotA.view.evidence_view_version !== "v1" || slotB.view.evidence_view_version !== "v1") {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Research library</p>
            <h1>Compare runs</h1>
          </div>
        </header>
        <div className="runs-state" data-testid="compare-unsupported-version">
          <strong>Validation Battery v2 runs can&rsquo;t be compared side by side yet.</strong>
          Their sealed evidence (walk-forward folds, single-use final holdout) doesn&rsquo;t
          map onto this v1 comparison layout, and QuantLens won&rsquo;t restate sealed
          values into a different battery&rsquo;s vocabulary. Open each report individually
          instead.
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/runs">Back to Runs &amp; Reports</Link>
          </p>
        </div>
      </main>
    );
  }
  const a = slotA.view as EvidenceViewV1;
  const b = slotB.view as EvidenceViewV1;
  const notices = comparabilityNotices(a, b);
  const outcomeA = runOutcome("published", a.status.battery_status, fragilityLines(a).length);
  const outcomeB = runOutcome("published", b.status.battery_status, fragilityLines(b).length);
  const coreA = coreMetricRows(a);
  const coreB = coreMetricRows(b);
  const fragA = fragilityLines(a);
  const fragB = fragilityLines(b);

  return (
    <main data-testid="compare-page">
      <header className="page-header">
        <div>
          <p className="page-kicker">Research library</p>
          <h1>Compare runs</h1>
          <p className="page-lede">
            Two sealed evidence records, side by side. Every value is displayed exactly
            as sealed — nothing here is recomputed, ranked, or scored.
          </p>
        </div>
        <div className="page-header-actions">
          <Link className="btn-link" href="/runs">Back to Runs &amp; Reports</Link>
        </div>
      </header>

      {notices.length > 0 && (
        <div className="notice warn" data-testid="compare-warnings">
          <strong>Read with care — these runs differ in material assumptions:</strong>
          <ul style={{ margin: "6px 0 0" }}>
            {notices.map((notice) => <li key={notice}>{notice}</li>)}
          </ul>
        </div>
      )}
      {notices.length === 0 && (
        <p className="workspace-meta" data-testid="compare-aligned">
          Instrument, data source, window, costs, split, and benchmark match; the runs
          differ only in the rule under test.
        </p>
      )}

      <div className="tablewrap" role="region" tabIndex={0} aria-labelledby="compare-title">
        <table className="compare-table">
          <caption id="compare-title" className="visually-hidden">
            Side-by-side comparison of two sealed research runs
          </caption>
          <thead>
            <tr>
              <th scope="col">Sealed value</th>
              <th scope="col" data-testid="compare-col-a">
                <Link href={`/runs/${slotA.id}`}>{a.assumptions.spec.meta.name}</Link>
              </th>
              <th scope="col" data-testid="compare-col-b">
                <Link href={`/runs/${slotB.id}`}>{b.assumptions.spec.meta.name}</Link>
              </th>
            </tr>
          </thead>
          <tbody>
            <CompareRow label="Verdict"
              a={<span className={`outcome-chip ${outcomeA.tone}`}>{outcomeA.label}</span>}
              b={<span className={`outcome-chip ${outcomeB.tone}`}>{outcomeB.label}</span>} />
            <CompareRow label="Instrument" a={instrumentLine(a)} b={instrumentLine(b)} />
            <CompareRow label="Rule" a={ruleLine(a)} b={ruleLine(b)} />
            <CompareRow label="Data source" a={sourceLine(a)} b={sourceLine(b)} />
            <CompareRow label="Test window" a={windowLine(a)} b={windowLine(b)} />
            <CompareRow label="Material fragilities"
              a={fragA.length ? fragA.join(" · ") : "None recorded"}
              b={fragB.length ? fragB.join(" · ") : "None recorded"} />
            <CompareRow label="Checks"
              a={a.status.checks.map((c) => `${checkLabel(c.id)}: ${checkStatusLabel(c.status)}`).join(" · ")}
              b={b.status.checks.map((c) => `${checkLabel(c.id)}: ${checkStatusLabel(c.status)}`).join(" · ")} />
          </tbody>
          <tbody>
            <tr><th scope="rowgroup" colSpan={3}>Core metrics (sealed)</th></tr>
            <CompareRow label="OOS price return vs benchmark" a={coreA.oosVsBench} b={coreB.oosVsBench} />
            <CompareRow label="IS → OOS Sharpe" a={coreA.sharpe} b={coreB.sharpe} />
            <CompareRow label="Cost-stress OOS return" a={coreA.stress} b={coreB.stress} />
            <CompareRow label="Chosen parameter rank" a={coreA.rank} b={coreB.rank} />
          </tbody>
          {(["oos", "is"] as const).map((segment) => {
            const rowsA = segmentRows(a, segment);
            const rowsB = segmentRows(b, segment);
            const title = segment === "oos"
              ? "Out-of-sample (held out, benchmark-aligned)"
              : "In-sample (sensitivity window, benchmark-aligned)";
            return (
              <tbody key={segment}>
                <tr><th scope="rowgroup" colSpan={3}>{title}</th></tr>
                <CompareRow label="Price return" a={rowsA.ret} b={rowsB.ret} />
                <CompareRow label="Sharpe (rf = 0)" a={rowsA.sharpe} b={rowsB.sharpe} />
                <CompareRow label="Max drawdown" a={rowsA.maxdd} b={rowsB.maxdd} />
                <CompareRow label="Time in market" a={rowsA.exposure} b={rowsB.exposure} />
                <CompareRow label="Final equity" a={rowsA.finalEquity} b={rowsB.finalEquity} />
                <CompareRow label="Window length" a={rowsA.bars} b={rowsB.bars} />
              </tbody>
            );
          })}
          <tbody>
            <tr><th scope="rowgroup" colSpan={3}>Key assumptions</th></tr>
            <CompareRow label="Execution"
              a={a.assumptions.execution.convention}
              b={b.assumptions.execution.convention} />
            <CompareRow label="Costs" a={costsLine(a)} b={costsLine(b)} />
            <CompareRow label="Held-out share"
              a={`${Math.round(a.assumptions.spec.validation.is_oos_split.oos_fraction * 100)}%`}
              b={`${Math.round(b.assumptions.spec.validation.is_oos_split.oos_fraction * 100)}%`} />
            <CompareRow label="Benchmark"
              a={a.results.oos.benchmark_symbol}
              b={b.results.oos.benchmark_symbol} />
          </tbody>
        </table>
      </div>

      <p className="workspace-meta" style={{ marginTop: 16 }}>
        Each column reads from its run&rsquo;s integrity-checked evidence record; the
        complete identifiers live in each run&rsquo;s Audit trail. This comparison is
        research evidence, not a recommendation of either rule.
      </p>
    </main>
  );
}
