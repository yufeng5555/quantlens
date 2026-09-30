"use client";

import { useState } from "react";
import Link from "next/link";
import {
  useWorkspaceSession,
  workspaceStatusLabel,
  type ReportRole,
  type WorkspaceSession,
} from "../components/WorkspaceSession";
import { authModeLabel, roleLabel } from "../lib/labels";
import RecentRuns from "./RecentRuns";

const REPORT_ROLE_CHOICES: { role: ReportRole; title: string; detail: string }[] = [
  {
    role: "novice",
    title: "Plain language",
    detail:
      "Each report opens with its result stated in ordinary words, and the "
      + "technical blocks start collapsed.",
  },
  {
    role: "expert",
    title: "Professional",
    detail:
      "Each report opens as the full research document, with every metric, "
      + "check, and assumption laid out at once.",
  },
];

/**
 * The stored reading preference for this account. It changes how reports are
 * worded and how densely they open — never which run data exists, which checks
 * ran, or what any sealed figure is.
 *
 * Rendered only when the session actually carries a report-role contract. A
 * provider that stores no such preference must not be offered a control its
 * API would refuse.
 */
function ReportRolePreference({ session }: { session: WorkspaceSession }) {
  const { refresh } = useWorkspaceSession();
  const [saving, setSaving] = useState<ReportRole | null>(null);
  const [error, setError] = useState<string | null>(null);
  const current = session.reportRole;
  if (current === null) return null;

  const choose = async (role: ReportRole) => {
    setSaving(role);
    setError(null);
    try {
      const response = await fetch("/api/ql/auth/report-role", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ report_role: role }),
      });
      if (!response.ok) {
        setError("That preference could not be saved. Your reports are unchanged.");
        return;
      }
      refresh();
    } catch {
      setError("The workspace service could not be reached. Your reports are unchanged.");
    } finally {
      setSaving(null);
    }
  };

  return (
    <section className="account-section" aria-labelledby="report-role-title"
      data-testid="report-role-preference">
      <div className="account-section-head">
        <p className="account-card-index" aria-hidden="true">04</p>
        <div>
          <h2 id="report-role-title">How your reports read</h2>
          <p>
            Wording and density only. Both settings show the same sealed numbers and
            the same failing checks, and either one can be opened at the other level
            from any report.
          </p>
        </div>
      </div>
      {error && <p className="auth-error" role="alert">{error}</p>}
      <div className="role-choices">
        {REPORT_ROLE_CHOICES.map((choice) => (
          <button
            key={choice.role}
            type="button"
            className={`role-choice${current === choice.role ? " selected" : ""}`}
            data-testid={`report-role-${choice.role}`}
            aria-pressed={current === choice.role}
            disabled={saving !== null}
            onClick={() => void choose(choice.role)}
          >
            <strong>{choice.title}</strong>
            <span>{choice.detail}</span>
            <span className="role-choice-cta" aria-hidden="true">
              {saving === choice.role
                ? "Saving…"
                : current === choice.role ? "Current setting" : "Use this"}
            </span>
          </button>
        ))}
      </div>
      {!session.reportRoleChosen && (
        // Reads the setting actually in force rather than naming one. An account
        // starts at plain language (DEFAULT_REPORT_ROLE), so this line used to
        // promise full professional detail on the same screen that marked Plain
        // language as the current setting.
        <p className="workspace-meta" data-testid="report-role-default-note">
          No preference has been recorded for this workspace yet, so reports open at
          the setting marked current above —{" "}
          {current === "novice" ? "plain language" : "full professional detail"}.
          Either level shows the same sealed numbers.
        </p>
      )}
    </section>
  );
}

const RETENTION_ROWS = [
  {
    data: "Raw CSV upload",
    behavior: "Deleted from quarantine after a successful seal.",
    caveat: "A failed or unfinished import is not a successful seal.",
  },
  {
    data: "Abandoned upload",
    behavior: "Discard it yourself from the Data workspace: that removes the quarantined "
      + "bytes, erases the sampled rows and column names, and frees the upload slot.",
    caveat: "A dated record that an import happened remains. Closing the tab neither "
      + "discards it nor guarantees deletion, and the 24-hour cleanup task is not "
      + "scheduled in this build.",
  },
  {
    data: "Sealed dataset",
    behavior: "Retained in the current workspace state.",
    caveat: "This build has no in-product delete control or automatic expiry yet.",
  },
  {
    data: "Run and evidence artifacts",
    behavior: "Retained in the current workspace state.",
    caveat: "Reports, manifests, ledgers, and artifacts persist; removal is currently manual.",
  },
  {
    data: "Unsubmitted draft",
    behavior: "Tab-only working state.",
    caveat: "It may disappear on refresh or when the tab closes; it is not a saved run.",
  },
];

function RetentionSection() {
  return (
    <section className="account-section" aria-labelledby="retention-title">
      <div className="account-section-head">
        <p className="account-card-index" aria-hidden="true">03</p>
        <div>
          <h2 id="retention-title">Current retention behavior</h2>
          <p>Persistence is based on the current implementation, not on a published retention policy.</p>
        </div>
      </div>
      <div
        className="tablewrap account-retention-table"
        role="region"
        aria-label="Current data retention behavior"
        tabIndex={0}
      >
        <table>
          <thead>
            <tr>
              <th scope="col">Data</th>
              <th scope="col">Current behavior</th>
              <th scope="col">Important detail</th>
            </tr>
          </thead>
          <tbody>
            {RETENTION_ROWS.map((row) => (
              <tr key={row.data}>
                <th scope="row">{row.data}</th>
                <td>{row.behavior}</td>
                <td>{row.caveat}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function LocalBoundary({ session }: { session: WorkspaceSession }) {
  return (
    <>
      <header className="account-page-head">
        <p className="account-kicker">Workspace boundary</p>
        <h1>Local research workspace &amp; data</h1>
        <p className="account-lede">
          This page describes what exists today, not a future security promise.
          Sign-in, team sharing, billing, and live provider activation are not enabled
          in this local environment; the workspace service reports a local principal,
          which keeps object ownership consistent but does not establish who is using
          this machine.
        </p>
      </header>

      <section className="account-status-card" aria-labelledby="workspace-status-title">
        <span className="account-status-mark" aria-hidden="true">L</span>
        <div>
          <p className="account-status-label" id="workspace-status-title">
            {workspaceStatusLabel({ kind: "local-preview", session })}
          </p>
          <p>
            {session.notice} There is no email, password, sign-in session, or logout in
            this build, and no external account provider is connected. Anyone who can use
            this app on the same machine may be able to reach its local data. Ending a
            browser tab is <strong>not</strong> a security boundary.
          </p>
        </div>
      </section>

      <RecentRuns />

      <div className="account-boundary-grid">
        <section className="account-boundary-card protects" aria-labelledby="protects-title">
          <p className="account-card-index" aria-hidden="true">01</p>
          <h2 id="protects-title">What this workspace protects</h2>
          <ul>
            <li>Private object requests are scoped to the active local workspace principal.</li>
            <li>Raw uploads stay in a local quarantine workflow and are removed after a successful seal.</li>
            <li>Sealed datasets and run evidence use opaque identifiers instead of source filenames in reports.</li>
            <li>Integrity checks bind normalized datasets, run inputs, and evidence artifacts.</li>
          </ul>
        </section>

        <section className="account-boundary-card limits" aria-labelledby="limits-title">
          <p className="account-card-index" aria-hidden="true">02</p>
          <h2 id="limits-title">What this workspace does not protect</h2>
          <ul>
            <li>It does not verify who is using the browser or local API.</li>
            <li>It does not isolate different people who share this machine or operating-system account.</li>
            <li>It does not provide hosted session expiry, revocation, or recovery.</li>
            <li>It does not claim that local files are encrypted or protected from a machine administrator.</li>
          </ul>
        </section>
      </div>

      <RetentionSection />

      <section className="account-beta" aria-labelledby="beta-title">
        <div>
          <p className="account-kicker">Future beta boundary</p>
          <h2 id="beta-title">A real account starts with provider-backed identity</h2>
          <p>
            Before a hosted beta, QuantLens must connect an external identity provider,
            issue and revoke server-validated sessions, enforce tenant policies at storage
            and database layers, and provide explicit retention and deletion controls.
            Those capabilities are planned; they are not represented by fake sign-in controls here.
          </p>
        </div>
        <ol className="account-beta-steps" aria-label="Future beta account boundary">
          <li><span>1</span>Provider-backed account</li>
          <li><span>2</span>Server session</li>
          <li><span>3</span>Tenant-scoped storage</li>
          <li><span>4</span>Retention &amp; deletion controls</li>
        </ol>
      </section>

      <nav className="account-actions" aria-label="Workspace actions">
        <Link className="btn-link primary" href="/data">Review local data</Link>
        <Link className="btn-link" href="/studio">Open Research Studio</Link>
      </nav>
    </>
  );
}

function AuthenticatedBoundary({ session }: { session: WorkspaceSession }) {
  return (
    <>
      <header className="account-page-head">
        <p className="account-kicker">Workspace boundary</p>
        <h1>Private research workspace &amp; data</h1>
        <p className="account-lede">
          The protected API reports an authenticated session and a server-enforced
          security boundary. Identity claims shown here come from that API response,
          never from browser-supplied workspace labels.
        </p>
      </header>

      <section className="account-status-card authenticated" aria-labelledby="workspace-status-title">
        <span className="account-status-mark" aria-hidden="true">A</span>
        <div>
          <p className="account-status-label" id="workspace-status-title">
            {workspaceStatusLabel({ kind: "authenticated", session })}
          </p>
          <p>
            Access confirmed for <strong>{session.displayLabel}</strong>, signed in via{" "}
            {authModeLabel(session.authMode)} with a server-enforced security boundary.
            Workspace role{session.roles.length === 1 ? "" : "s"}:{" "}
            <strong>{session.roles.map(roleLabel).join(", ")}</strong>.
          </p>
          <details className="drawer" data-testid="security-details">
            <summary>Security details</summary>
            <div className="drawer-body">
              <dl className="data-provenance" style={{ margin: 0 }}>
                <div><dt>Authentication mode</dt><dd><code>{session.authMode}</code></dd></div>
                <div><dt>Role tokens</dt><dd><code>{session.roles.join(", ")}</code></dd></div>
              </dl>
            </div>
          </details>
        </div>
      </section>

      <RecentRuns />

      <div className="account-boundary-grid">
        <section className="account-boundary-card protects" aria-labelledby="protects-title">
          <p className="account-card-index" aria-hidden="true">01</p>
          <h2 id="protects-title">What this session establishes</h2>
          <ul>
            <li>The configured provider established an authenticated principal.</li>
            <li>Private datasets, imports, runs, and evidence are scoped to tenant and user ownership.</li>
            <li>
              Private responses are marked no-store. Routine workspace views strip opaque
              ownership identifiers; sealed audit manifests retain their tenant binding for
              integrity verification.
            </li>
            <li>Missing and foreign objects share the same response shape to reduce existence disclosure.</li>
          </ul>
        </section>

        <section className="account-boundary-card limits" aria-labelledby="limits-title">
          <p className="account-card-index" aria-hidden="true">02</p>
          <h2 id="limits-title">What authentication does not establish</h2>
          <ul>
            <li>It does not make historical data complete, accurate, or suitable for live decisions.</li>
            <li>It does not turn a backtest into advice, an approval, or a forecast.</li>
            <li>Session lifetime, recovery, and revocation depend on the configured provider.</li>
            <li>Current retention remains implementation behavior, not a published customer policy.</li>
          </ul>
        </section>
      </div>

      <RetentionSection />

      <ReportRolePreference session={session} />

      <section className="account-beta authenticated" aria-labelledby="contract-title">
        <div>
          <p className="account-kicker">Session contract in force</p>
          <h2 id="contract-title">Identity is checked before private objects are resolved</h2>
          <p>
            QuantLens accepts this state only when the provider contract reports both an
            authenticated principal and an active security boundary. Contradictory or
            incomplete identity responses fail closed instead of becoming an anonymous account.
          </p>
        </div>
        <ol className="account-beta-steps" aria-label="Authenticated session contract">
          <li><span>1</span>Provider identity</li>
          <li><span>2</span>Server validation</li>
          <li><span>3</span>Tenant + user scope</li>
          <li><span>4</span>Private no-store responses</li>
        </ol>
      </section>

      <nav className="account-actions" aria-label="Workspace actions">
        <Link className="btn-link primary" href="/data">Review workspace data</Link>
        <Link className="btn-link" href="/studio">Open Research Studio</Link>
      </nav>
    </>
  );
}

/** Not signed in yet — which is every visitor's state before they are anything else.
 *
 * This case had no branch, so it fell through to the fail-closed "unavailable" panel and
 * told people QuantLens could not obtain a session contract and that an administrator
 * must configure the identity provider. Nothing was wrong: they had simply not signed in.
 * Reporting the ordinary case as an outage is the kind of thing that makes somebody
 * close the tab and assume the product is broken.
 */
function SignedOutBoundary() {
  return (
    <>
      <header className="account-page-head">
        <p className="account-kicker">Workspace boundary</p>
        <h1>Sign in to open your workspace</h1>
        <p className="account-lede">
          Your account details, run allowance, and data stay hidden until a session
          exists. Nothing is wrong — this page simply has nothing to show yet.
        </p>
      </header>

      <section className="account-status-card" aria-labelledby="workspace-status-title">
        <span className="account-status-mark" aria-hidden="true">→</span>
        <div>
          <p className="account-status-label" id="workspace-status-title">
            Not signed in
          </p>
          <p>
            QuantLens stores no password. Sign in with Google, or have a one-time
            link emailed to you.
          </p>
          <p style={{ marginTop: 12 }}>
            <Link className="btn-link primary" href="/signin"
              data-testid="workspace-boundary-sign-in">
              Sign in
            </Link>
          </p>
        </div>
      </section>
    </>
  );
}

function UnavailableBoundary({ retry }: { retry: () => void }) {
  return (
    <>
      <header className="account-page-head">
        <p className="account-kicker">Fail-closed workspace boundary</p>
        <h1>Workspace access unavailable</h1>
        <p className="account-lede">
          QuantLens could not obtain a valid session contract from the protected API.
          It does not assume a local identity or show a pretend authenticated account.
        </p>
      </header>

      <section className="account-status-card unavailable" aria-labelledby="workspace-status-title">
        <span className="account-status-mark" aria-hidden="true">!</span>
        <div>
          <p className="account-status-label" id="workspace-status-title">
            Workspace unavailable · access not confirmed
          </p>
          <p>
            Private workspace access remains unavailable until the API returns a complete,
            internally consistent session. This can mean the API is offline, the selected
            authentication provider is not configured, or its session could not be validated.
          </p>
        </div>
      </section>

      <div className="account-boundary-grid">
        <section className="account-boundary-card protects" aria-labelledby="closed-title">
          <p className="account-card-index" aria-hidden="true">01</p>
          <h2 id="closed-title">Why QuantLens stops here</h2>
          <ul>
            <li>No browser label can substitute for a server-confirmed principal.</li>
            <li>An HTTP error or malformed session response never becomes local-preview access.</li>
            <li>Opaque tenant and user identifiers are not guessed or exposed in the interface.</li>
          </ul>
        </section>
        <section className="account-boundary-card limits" aria-labelledby="restore-title">
          <p className="account-card-index" aria-hidden="true">02</p>
          <h2 id="restore-title">How access is restored</h2>
          <ul>
            <li>Restart the local research service; the workspace reconnects on retry.</li>
            <li>For a hosted deployment, an administrator must configure and validate the identity provider.</li>
            <li>Retry only re-checks the service; it does not create an account or bypass authentication.</li>
          </ul>
        </section>
      </div>

      <div className="account-actions">
        <button className="btn primary" type="button" onClick={retry}>Retry workspace check</button>
        <Link className="btn-link" href="/methodology">Read the methodology</Link>
      </div>
    </>
  );
}

export default function WorkspaceBoundary() {
  const { state, refresh } = useWorkspaceSession();

  return (
    <main className="account-main" data-testid="workspace-boundary" aria-live="polite">
      {state.kind === "loading" ? (
        <>
          <header className="account-page-head">
            <p className="account-kicker">Workspace boundary</p>
            <h1>Checking workspace access</h1>
            <p className="account-lede">
              Private workspace details remain hidden until the protected API confirms
              the current session contract.
            </p>
          </header>
          <section className="account-status-card loading" aria-label="Checking workspace access">
            <span className="account-status-mark" aria-hidden="true">···</span>
            <p>Checking the protected session endpoint&hellip;</p>
          </section>
        </>
      ) : state.kind === "local-preview" ? (
        <LocalBoundary session={state.session} />
      ) : state.kind === "authenticated" ? (
        <AuthenticatedBoundary session={state.session} />
      ) : state.kind === "signed-out" ? (
        <SignedOutBoundary />
      ) : (
        <UnavailableBoundary retry={refresh} />
      )}
    </main>
  );
}
