"use client";

import { useEffect, useRef, useState } from "react";
import {
  citationLabel,
  type ResearchCopilotActionId,
  type ResearchCopilotView,
} from "./researchCopilotContract";

/**
 * Development Research Copilot review panel. Renders ONLY server-owned copy and
 * formatted values from the validated response — no client recomputation, no
 * internal identifiers, no binding material. The single pending action is
 * confirm-gated and performs local report navigation only: it never calls an
 * API, starts a run, or changes a parameter.
 */

export default function ResearchCopilotPanel({ copilot, onReviewEvidence }: {
  copilot: ResearchCopilotView;
  /** Local navigation only — switch to Robustness and focus the mapped section. */
  onReviewEvidence: (actionId: ResearchCopilotActionId) => void;
}) {
  const { analysis } = copilot;
  const pending = analysis.pending_action;
  const [confirmOpen, setConfirmOpen] = useState(false);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!confirmOpen) return;
    const dialog = dialogRef.current;
    dialog?.querySelector<HTMLElement>("button")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setConfirmOpen(false);
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(
        dialog.querySelectorAll<HTMLElement>("button:not([disabled])"));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      triggerRef.current?.focus();
    };
  }, [confirmOpen]);

  return (
    <section className="copilot-panel" data-testid="v2-copilot"
      aria-labelledby="copilot-title">
      <div className="copilot-head">
        <div>
          <p className="data-eyebrow">QuantLens research review</p>
          <h2 id="copilot-title">{analysis.title}</h2>
        </div>
        {/* Evidence-scope badge: neutral styling — this states which evidence
            segment the review covers, not the nature of the dataset. */}
        <span className="chip scope-development" data-testid="v2-copilot-scope">
          Development evidence only
        </span>
      </div>

      <ol className="copilot-blocks">
        {analysis.blocks.map((block) => (
          <li className="copilot-block" key={block.template_id}>
            <p className="copilot-text">{block.text}</p>
            <p className="copilot-citations" aria-label="Cited sealed values">
              {block.citations.map((citation) => (
                <span className="copilot-citation" key={citation.fact_id}>
                  {citationLabel(citation.fact_id)}{" "}
                  <strong>{citation.formatted_value}</strong>
                </span>
              ))}
            </p>
          </li>
        ))}
      </ol>

      {pending && (
        <div className="copilot-action" data-testid="v2-copilot-action">
          <p>{pending.description}</p>
          <button
            type="button"
            ref={triggerRef}
            data-testid="v2-copilot-action-button"
            onClick={() => setConfirmOpen(true)}
          >
            {pending.label}
          </button>
        </div>
      )}

      <p className="copilot-disclosure">{analysis.disclosure}</p>
      <details className="drawer copilot-generation" data-testid="v2-copilot-generation">
        <summary>How this review was generated</summary>
        <div className="drawer-body">
          <p>
            Deterministic QuantLens review · no external model or data
            transmission. Every value above is read from this run&rsquo;s sealed
            development evidence; the final holdout is never provided to this
            review.
          </p>
        </div>
      </details>

      {confirmOpen && pending && (
        <div className="dialog-backdrop" role="presentation">
          <div
            className="card confirm-dialog copilot-confirm"
            role="dialog"
            aria-modal="true"
            aria-labelledby="copilot-confirm-title"
            data-testid="v2-copilot-confirm"
            ref={dialogRef}
          >
            <h3 id="copilot-confirm-title">{pending.label}?</h3>
            <p>{pending.description}</p>
            <p className="copilot-confirm-boundary">
              Confirming only moves you to the matching evidence in the
              Robustness section of this report. Nothing is run, changed, or
              submitted.
            </p>
            <div className="field-row" style={{ justifyContent: "flex-end" }}>
              <button
                type="button"
                data-testid="v2-copilot-cancel"
                onClick={() => setConfirmOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="primary"
                data-testid="v2-copilot-confirm-button"
                onClick={() => {
                  setConfirmOpen(false);
                  onReviewEvidence(pending.action_id);
                }}
              >
                Open the evidence
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
