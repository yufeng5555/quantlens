"use client";

import type { ReactNode } from "react";
import type { EvidenceViewV3 } from "@schema/ts/evidence";
import { CopyId } from "./reportShared";
import { DEFAULT_READING_LEVEL, type ReadingLevel } from "./readingLevel";
import { dataLabelBadgeClass, dataSourceLabel } from "../../lib/labels";

/**
 * Sealed contract record for evidence produced under the v3 presentation
 * contract (Gate E Stop E; contract 27 §10). This panel presents exactly what
 * the closed v3 shape carries — the sealed identity, the frozen contract
 * tuple, the payload bindings and the recorded independent-validation
 * receipt. Nothing here recomputes, interprets or ranks a result, and nothing
 * on this panel is investment advice or a forecast.
 */

function SealedValueTable({ caption, testId, rows }: {
  caption: string;
  testId: string;
  rows: [string, string][];
}) {
  return (
    <div className="tablewrap" role="region" tabIndex={0} aria-label={caption}>
      <table data-testid={testId}>
        <thead>
          <tr><th scope="col">Field</th><th scope="col">Sealed value</th></tr>
        </thead>
        <tbody>
          {rows.map(([name, value]) => (
            <tr key={name}>
              <th scope="row">{name}</th>
              <td><code>{value}</code>{" "}<CopyId value={value} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function EvidenceWorkspaceV3({
  view, readingLevel, readingLevelControl,
}: {
  view: EvidenceViewV3;
  readingLevel?: ReadingLevel;
  readingLevelControl?: ReactNode;
}) {
  const { identity, active_tuple, bindings, semantic_receipt } = view;
  const executionCount = semantic_receipt.validated_execution_ids.length;
  const plain = (readingLevel ?? DEFAULT_READING_LEVEL) === "novice";
  return (
    <section aria-label="Sealed evidence record (contract v3)"
      data-testid="evidence-v3-workspace">
      {readingLevelControl}
      {plain && (
        <section className="plain-summary" aria-labelledby="v3-plain-title"
          data-testid="plain-summary-v3">
          <p className="evidence-eyebrow">In plain language</p>
          <h2 id="v3-plain-title">What this page is</h2>
          <p className="plain-lead">
            This is the receipt for a sealed run, not its results. It lists the
            fingerprints of the exact files, settings, and software version the run
            was locked to, so that anyone can check later that nothing was swapped
            or edited after the fact.
          </p>
          <p>
            There are no performance figures on this page — no balances, no returns,
            no rating. Nothing here is investment advice or a forecast.
          </p>
        </section>
      )}
      <section className="workspace-section" aria-labelledby="v3-receipt-title"
        data-testid="v3-receipt">
        <h2 id="v3-receipt-title">Independent validation receipt</h2>
        <p className="workspace-meta">
          Recorded status{" "}
          <code data-testid="v3-receipt-status">{semantic_receipt.status}</code>{" "}
          by <code>{semantic_receipt.validator_version}</code> over{" "}
          {executionCount} sealed execution record{executionCount === 1 ? "" : "s"}.
        </p>
        <SealedValueTable caption="Validation receipt bindings"
          testId="v3-receipt-bindings" rows={[
            ["Ledger", semantic_receipt.ledger_id],
            ["Result hash", semantic_receipt.result_hash],
            ["Financial contract", semantic_receipt.financial_contract_sha256],
          ]} />
      </section>

      <section className="workspace-section" aria-labelledby="v3-identity-title"
        data-testid="v3-identity">
        <h2 id="v3-identity-title">Sealed identity</h2>
        <p className="workspace-meta">
          <span className={dataLabelBadgeClass(identity.data_label)}>
            {dataSourceLabel(identity.data_label)}
          </span>{" "}
          Sealed {identity.created_at}.
        </p>
        <SealedValueTable caption="Sealed identity fields"
          testId="v3-identity-fields" rows={[
            ["Manifest", identity.manifest_id],
            ["Specification hash", identity.spec_hash],
            ["Snapshot", identity.snapshot_id],
            ["Snapshot digest", identity.snapshot_sha256],
            ["Runtime digest", identity.image_digest],
            ["Battery configuration", identity.battery_config_hash],
            ["Result hash", identity.result_hash],
            ["Confirmation receipt", identity.confirmation_receipt_hash],
          ]} />
      </section>

      <section className="workspace-section" aria-labelledby="v3-bindings-title"
        data-testid="v3-bindings">
        <h2 id="v3-bindings-title">Payload bindings</h2>
        <SealedValueTable caption="Sealed payload bindings"
          testId="v3-binding-fields" rows={[
            ["Validation plan anchor", bindings.plan_anchor_sha256],
            ["Financial contract", bindings.financial_contract_sha256],
            ["Ledger", bindings.ledger_id],
            ["Validation receipt", bindings.semantic_receipt_sha256],
            ["Temporal integrity", bindings.temporal_integrity_sha256],
            ["Final execution audit", bindings.final_holdout_execution_audit_sha256],
          ]} />
      </section>

      <section className="workspace-section" aria-labelledby="v3-tuple-title"
        data-testid="v3-tuple">
        <h2 id="v3-tuple-title">Contract tuple</h2>
        <p className="workspace-meta">
          The exact frozen identifiers this evidence was sealed under. They are
          shown for audit; they are not a rating of the strategy.
        </p>
        <SealedValueTable caption="Frozen contract tuple"
          testId="v3-tuple-fields"
          rows={Object.entries(active_tuple)} />
      </section>

      <p className="workspace-meta">
        This panel shows the sealed contract identities and the recorded
        validation receipt for this run. It is not investment advice and not a
        forecast.
      </p>
    </section>
  );
}
