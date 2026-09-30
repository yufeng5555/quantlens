"use client";

import { useWorkspaceSession } from "./WorkspaceSession";

/**
 * Standing legal disclosure, gated by workspace mode: the sample-workspace sentence
 * appears only when the session is actually the local sample mode — a hosted,
 * authenticated workspace is never re-labeled as a demo.
 */
export default function Disclosure() {
  const { state } = useWorkspaceSession();
  const sampleMode = state.kind === "local-preview";

  return (
    <footer className="disclosure" role="contentinfo">
      <strong>Disclosure.</strong>{" "}QuantLens tests rules you author against
      historical data. It never recommends a security, position, timing, threshold, or
      action, and it never certifies that a strategy is safe or profitable. Backtested
      results are hypothetical, depend on the assumptions shown in each report, and do
      not predict future returns.{" "}
      {sampleMode && (
        <>
          This local workspace uses clearly labeled sample series or data you
          import.{" "}
        </>
      )}
      <strong>Imported data is integrity-checked; source accuracy is not
      independently authenticated.</strong>{" "}Nothing here is investment advice,
      an endorsement, or a forecast.
    </footer>
  );
}
