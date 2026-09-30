"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { useWorkspaceSession, type ReportRole } from "../../components/WorkspaceSession";

// Where a first Google sign-in lands. The session already exists — Google
// proved the address and the callback opened it — so this page asks the one
// question the emailed-link flow asks on its own callback, and nothing else.
// A returning reader never sees it.

const ROLE_CHOICES: { role: ReportRole; title: string; detail: string }[] = [
  {
    role: "novice",
    title: "Plain language",
    detail:
      "Each result is explained in ordinary words first, with the technical "
      + "sections available but collapsed. Best if terms like Sharpe ratio or "
      + "walk-forward are new to you.",
  },
  {
    role: "expert",
    title: "Professional",
    detail:
      "The full research report: every metric, every falsification check and "
      + "every assumption laid out at once, with no sections collapsed.",
  },
];

export default function ChooseReportRolePage() {
  const router = useRouter();
  const { state, refresh } = useWorkspaceSession();
  const [saving, setSaving] = useState<ReportRole | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Reached directly without a session, this page would ask a question it
  // cannot record and then fail on the answer. Send the visitor to the door
  // instead of letting them choose something that goes nowhere.
  useEffect(() => {
    if (state.kind !== "loading" && state.kind !== "authenticated") {
      router.replace("/signin");
    }
  }, [state.kind, router]);

  const choose = useCallback(async (role: ReportRole) => {
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
        setError("That choice could not be saved. You can change it later in Workspace.");
        setSaving(null);
        return;
      }
      refresh();
      router.replace("/");
    } catch {
      setError("The workspace service could not be reached. Try again shortly.");
      setSaving(null);
    }
  }, [refresh, router]);

  // Every hook above runs on every render. Returning early before one of them
  // changes the hook count between the loading render and the authenticated
  // render, which React refuses — and the reader sees a blank crash page at the
  // exact moment their sign-in succeeded. The guard belongs here, below them.
  if (state.kind !== "authenticated") {
    return (
      <main className="auth-main">
        <section className="auth-card">
          <p className="page-kicker">Sign-in</p>
          <h1>Checking your workspace…</h1>
        </section>
      </main>
    );
  }

  return (
    <main className="auth-main">
      <section className="auth-card wide" aria-labelledby="signin-role-title">
        <p className="page-kicker">One question before you start</p>
        <h1 id="signin-role-title">How should your reports read?</h1>
        <p className="auth-lede">
          This changes the wording and the density, never the numbers. Both
          versions show the same sealed evidence, including the checks that
          fail. You can switch at any time.
        </p>
        {error && <p className="auth-error" role="alert">{error}</p>}
        <div className="role-choices">
          {ROLE_CHOICES.map((choice) => (
            <button
              key={choice.role}
              type="button"
              className="role-choice"
              data-testid={`signin-role-${choice.role}`}
              disabled={saving !== null}
              onClick={() => void choose(choice.role)}
            >
              <strong>{choice.title}</strong>
              <span>{choice.detail}</span>
              <span className="role-choice-cta" aria-hidden="true">
                {saving === choice.role ? "Saving…" : "Choose"}
              </span>
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}
