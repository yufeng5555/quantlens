"use client";

import { useEffect, useRef } from "react";
import type { EquitySeries } from "@schema/ts/evidence";

interface Props {
  isSeries: EquitySeries;
  oosSeries: EquitySeries;
  isBench: { date: string[]; equity: number[] };
  oosBench: { date: string[]; equity: number[] };
  benchmarkSymbol: string;
  /** Pre-computed sentence from sealed metrics; the chart never derives numbers. */
  summary: string;
  /** Names for the two plotted segments (table + accessibility). */
  segmentLabels?: { first: string; second: string };
}

const W = 460;
const H = 240;
const money = (v: number) =>
  v.toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 });

/**
 * One independent experiment. Standard-audit IS and OOS simulations each reset to
 * their own sealed initial capital, so connecting their endpoints would fabricate a
 * continuous capital path that does not exist.
 */
function SegmentFigure({ label, series, benchmark, benchmarkSymbol }: {
  label: string;
  series: EquitySeries;
  benchmark: { date: string[]; equity: number[] };
  benchmarkSymbol: string;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const stratRef = useRef<SVGPolylineElement>(null);
  const benchRef = useRef<SVGPolylineElement>(null);

  const dates = series.date;
  const equity = series.equity;
  const benchDates = benchmark.date;
  const benchEquity = benchmark.equity;

  const all = [...equity, ...benchEquity];
  const lo = Math.min(...all);
  const hi = Math.max(...all);
  const pad = (hi - lo) * 0.05 || 1;
  const yLo = lo - pad;
  const yHi = hi + pad;
  const n = dates.length;
  const x = (i: number) => 58 + (W - 76) * (i / Math.max(n - 1, 1));
  const y = (v: number) => 22 + (H - 62) * (1 - (v - yLo) / (yHi - yLo));

  const stratPts = equity.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const dateIndex = new Map(dates.map((d, i) => [d, i]));
  const benchPts = benchDates
    .map((d, j) => ({ i: dateIndex.get(d), v: benchEquity[j] }))
    .filter((p): p is { i: number; v: number } => p.i !== undefined)
    .map((p) => `${x(p.i).toFixed(1)},${y(p.v).toFixed(1)}`)
    .join(" ");

  useEffect(() => {
    // Draw-in once on first viewport entry; stroke-dash only, no layout impact.
    const wrap = wrapRef.current;
    if (!wrap) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const curves = [stratRef.current, benchRef.current].filter(
      (c): c is SVGPolylineElement => c !== null);
    if (reduced) return; // CSS also forces the dash off; leave curves fully drawn
    for (const curve of curves) {
      const len = curve.getTotalLength();
      curve.style.strokeDasharray = `${len}`;
      curve.style.strokeDashoffset = `${len}`;
    }
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        requestAnimationFrame(() => {
          curves.forEach((c) => { c.style.strokeDashoffset = "0"; });
        });
        observer.disconnect();
      }
    }, { threshold: 0.25 });
    observer.observe(wrap);
    return () => observer.disconnect();
    // The sealed series for a run never changes; draw once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!n) {
    return (
      <figure className="evidence-chart-wrap">
        <div className="evidence-mini-visual-head">
          <div><span className="evidence-eyebrow">{label}</span><strong>No sealed equity series</strong></div>
          <span className="chip warn">Independent capital base</span>
        </div>
      </figure>
    );
  }

  const stride = Math.max(1, Math.ceil(n / 36));
  const benchByDate = new Map(benchDates.map((d, j) => [d, benchEquity[j]]));
  const sampled = dates
    .map((d, i) => ({ d, i }))
    .filter(({ i }) => i % stride === 0 || i === n - 1);

  return (
    <figure className="evidence-chart-wrap" ref={wrapRef}>
      <div className="evidence-mini-visual-head">
        <div>
          <span className="evidence-eyebrow">{label}</span>
          <strong>Initial capital {money(equity[0])} (sealed)</strong>
        </div>
        <span className="chip">Independent capital base</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`${label} equity curves from the sealed ledger: strategy versus buy-and-hold ${benchmarkSymbol}. This segment has its own initial-capital base.`}>
        <text x="58" y="14" fontSize="11" fill="var(--ink-soft)">
          equity ({money(yLo)} – {money(yHi)})
        </text>
        {benchPts && (
          <polyline ref={benchRef} points={benchPts} fill="none"
            className="chart-curve benchmark" stroke="#8aa0b2" strokeWidth="1.4" />
        )}
        <polyline ref={stratRef} points={stratPts} fill="none"
          className="chart-curve" stroke="var(--accent)" strokeWidth="2" />
        <text x="58" y={H - 10} fontSize="11" fill="var(--ink-soft)">
          {dates[0]} → {dates[n - 1]} · dark: strategy · light: benchmark ({benchmarkSymbol}, hold from first decision)
        </text>
      </svg>
      <figcaption style={{ fontSize: "0.8rem", color: "var(--ink-soft)", margin: "6px 2px 0" }}>
        {label} ends at {money(equity[equity.length - 1])}. This experiment&rsquo;s
        capital base is independent and is never joined to the other segment.
      </figcaption>
      <details className="drawer">
        <summary>Chart data as a table (sampled every {stride} bar{stride > 1 ? "s" : ""})</summary>
        <div className="drawer-body tablewrap" role="region" tabIndex={0}
          aria-label="Equity chart data table">
          <table>
            <caption style={{ textAlign: "left", fontSize: "0.8rem", color: "var(--ink-soft)" }}>
              A sample of the sealed observations, one row every {stride}{" "}
              bar{stride > 1 ? "s" : ""}: each shown value is copied unmodified from the
              sealed series, and the complete series lives in the ledger artifacts.
            </caption>
            <thead>
              <tr>
                <th scope="col">Date</th>
                <th scope="col">Strategy equity</th>
                <th scope="col">Benchmark equity ({benchmarkSymbol})</th>
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

/**
 * Standard-audit equity view: two small multiples because IS and OOS are independent
 * simulations with separate initial-capital bases. Values are drawn verbatim from the
 * sealed evidence; the component never recomputes performance.
 */
export default function EquityChart({
  isSeries, oosSeries, isBench, oosBench, benchmarkSymbol, summary,
  segmentLabels = { first: "In-sample", second: "Out-of-sample" },
}: Props) {
  return (
    <div>
      <p style={{ fontSize: "0.88rem", color: "var(--ink-soft)", margin: "4px 0 10px" }}>
        The two segments are independent experiments with separate initial-capital
        bases. They are deliberately shown on separate scales and never connected.
      </p>
      <div className="small-multiples" data-testid="v1-equity-multiples">
        <SegmentFigure label={segmentLabels.first} series={isSeries}
          benchmark={isBench} benchmarkSymbol={benchmarkSymbol} />
        <SegmentFigure label={segmentLabels.second} series={oosSeries}
          benchmark={oosBench} benchmarkSymbol={benchmarkSymbol} />
      </div>
      <p style={{ fontSize: "0.86rem", color: "var(--ink-soft)", margin: "10px 2px 0" }}>
        {summary}
      </p>
    </div>
  );
}
