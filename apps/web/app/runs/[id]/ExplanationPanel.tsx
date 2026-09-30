"use client";

import type {
  ExplanationCitation, ExplanationContextValue,
  ExplanationViewV1,
} from "@schema/ts/evidence";

const humanize = (value: string) => value.replaceAll("_", " ");

const isObject = (value: ExplanationContextValue | undefined): value is Record<string, ExplanationContextValue> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function formatWindows(value: ExplanationContextValue | undefined): string | null {
  if (!isObject(value)) return null;
  const windows = Object.entries(value).flatMap(([segment, raw]) => {
    if (!isObject(raw)) return [];
    const start = typeof raw.start === "string" ? raw.start : null;
    const end = typeof raw.end === "string" ? raw.end : null;
    const bars = typeof raw.bars === "number" ? raw.bars : null;
    if (!start || !end) return [];
    return [`${segment.toUpperCase()} ${start} → ${end}${bars === null ? "" : ` (${bars} bars)`}`];
  });
  return windows.length ? windows.join("; ") : null;
}

function formatContext(context: Record<string, ExplanationContextValue>): string {
  const parts: string[] = [];
  const segment = context.segment;
  if (typeof segment === "string") {
    const labels: Record<string, string> = {
      is: "in-sample", oos: "out-of-sample", is_vs_oos: "IS vs OOS",
    };
    parts.push(labels[segment] ?? humanize(segment));
  }
  if (typeof context.series === "string") {
    parts.push(`${humanize(context.series)} series`);
  }
  if (typeof context.stress_multiplier === "number") {
    parts.push(`${context.stress_multiplier}× cost stress`);
  }
  if (isObject(context.grid_cell)) {
    const grid = Object.entries(context.grid_cell)
      .map(([key, value]) => `${humanize(key)} ${String(value)}`).join(", ");
    if (grid) parts.push(`grid: ${grid}`);
  }
  const windows = formatWindows(context.evaluation_windows);
  if (windows) parts.push(windows);
  if (typeof context.data_label === "string") {
    const label = String(context.data_label).toUpperCase();
    parts.push(label === "USER_UPLOADED"
      ? "your data"
      : label === "LICENSED_PROVIDER"
        ? "licensed data"
        : "sample data");
  }
  if (typeof context.benchmark_symbol === "string") {
    parts.push(`benchmark ${context.benchmark_symbol}`);
  }
  return parts.join(" · ");
}

function CitationSource({ citation }: { citation: ExplanationCitation }) {
  const context = formatContext(citation.context ?? {});

  return (
    <li className="explanation-citation">
      <div className="explanation-citation-value">
        <strong>{citation.formatted_value}</strong>
        <span>{humanize(citation.unit)}</span>
      </div>
      {context && <p>{context}</p>}
      <p className="workspace-meta">
        Sealed citation — the exact artifact and integrity identifiers are in the
        Audit trail tab.
      </p>
    </li>
  );
}

export default function ExplanationPanel({ view }: { view: ExplanationViewV1 }) {
  if (view.status !== "completed" || view.binding === null
      || view.explanation === null) {
    return (
      <section className="workspace-section explanation-panel"
        aria-labelledby="evidence-explanation-title" data-testid="explanation-unavailable">
        <div className="explanation-heading">
          <div>
            <p className="data-eyebrow">Research summary</p>
            <h2 id="evidence-explanation-title">Evidence summary</h2>
          </div>
          <span className="chip warn">Summary unavailable</span>
        </div>
        <div className="notice warn">
          The summary service is unavailable right now. The integrity-checked evidence
          below is unchanged, and no partial or unbound explanation is shown.
        </div>
      </section>
    );
  }

  const { explanation } = view;
  const provenanceLabel = view.generation.ai_influenced_output
    ? "AI-assisted plan · QuantLens-rendered evidence-bound facts"
    : view.generation.provider_data_transmitted
      ? "AI plan rejected · deterministic template shown"
      : view.generation.provider_invoked
        ? "Provider invoked without transmission · deterministic template shown"
        : "Deterministic summary · built only from sealed evidence";

  return (
    <section className="workspace-section explanation-panel"
      aria-labelledby="evidence-explanation-title" data-testid="evidence-explanation">
      <div className="explanation-heading">
        <div>
          <p className="data-eyebrow">Research summary</p>
          <h2 id="evidence-explanation-title">{explanation.title}</h2>
        </div>
        <span className={`chip ${view.generation.ai_influenced_output ? "default" : "synthetic"}`}
          data-testid="explanation-provenance">
          {provenanceLabel}
        </span>
      </div>

      <p className="workspace-meta explanation-disclosure">
        {explanation.disclosure}
      </p>
      {view.generation.provider_data_transmitted
        && !view.generation.ai_influenced_output && (
        <div className="notice warn" data-testid="explanation-provider-rejected">
          A planning provider received the minimized fact-ID request, but its response
          did not influence this explanation. QuantLens discarded it completely and
          rendered the deterministic template below.
        </div>
      )}

      <div className="explanation-blocks">
        {explanation.blocks.map((block, index) => (
          <article className="explanation-block" key={`${block.template_id}-${index}`}>
            <p>{block.text}</p>
            <details className="drawer explanation-sources">
              <summary>
                {block.citations.length} sealed source{block.citations.length === 1 ? "" : "s"}
              </summary>
              <div className="drawer-body">
                <ol>
                  {block.citations.map((citation) => (
                    <CitationSource citation={citation} key={citation.fact_id} />
                  ))}
                </ol>
              </div>
            </details>
          </article>
        ))}
      </div>

      <p className="workspace-meta explanation-binding">
        Every sentence above is bound to this run&rsquo;s sealed evidence record; the
        binding identifiers are listed in the Audit trail tab.
      </p>
    </section>
  );
}
