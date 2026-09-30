"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { useWorkspaceSession, type ReportRole } from "../../components/WorkspaceSession";

// Where an emailed sign-in link lands. The page redeems the token exactly
// once, then either asks a first-time reader how they want reports rendered
// or returns a returning reader to their workspace.

type Stage =
  | { kind: "redeeming" }
  | { kind: "choose-role" }
  | { kind: "saving"; role: ReportRole }
  | { kind: "done" }
  // `linkSpent` distinguishes "your link no longer works" from "the link is
  // fine, this workspace cannot serve it right now" — only the first should
  // send the reader back to request another one.
  | { kind: "failed"; message: string; linkSpent: boolean };

const ROLE_CHOICES: {
  role: ReportRole;
  title: string;
  detail: string;
}[] = [
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

function CallbackFlow() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token");
  const { refresh } = useWorkspaceSession();
  const [stage, setStage] = useState<Stage>({ kind: "redeeming" });
  // A link may be redeemed once. React may mount an effect twice in
  // development, so the attempt is guarded — otherwise the second call would
  // consume nothing and report the link as already used.
  const attempted = useRef(false);

  useEffect(() => {
    if (attempted.current) return;
    attempted.current = true;

    if (!token) {
      setStage({
        kind: "failed",
        message: "This link is missing its sign-in token.",
        linkSpent: true,
      });
      return;
    }

    async function redeem() {
      try {
        const response = await fetch(
          `/api/ql/auth/callback?token=${encodeURIComponent(token!)}`,
          { credentials: "same-origin", headers: { Accept: "application/json" } },
        );
        if (!response.ok) {
          // A refusal that is not about the link must not be reported as a
          // broken link — the reader would keep requesting new ones forever.
          const code = await response.json()
            .then((body) => body?.detail?.code)
            .catch(() => null);
          const atCapacity = code === "AUTH_ACCOUNTS_AT_CAPACITY";
          setStage({
            kind: "failed",
            message: atCapacity
              ? "This workspace is not accepting new accounts right now. Your "
                + "link is still valid, so you can follow it again later."
              : "This sign-in link has expired or was already used. "
                + "Request a new one.",
            linkSpent: !atCapacity,
          });
          return;
        }
        const body = await response.json();
        refresh();
        if (body?.report_role_chosen === true) {
          setStage({ kind: "done" });
          router.replace("/");
          return;
        }
        setStage({ kind: "choose-role" });
      } catch {
        setStage({
          kind: "failed",
          message: "The workspace service could not be reached. Try again shortly.",
          linkSpent: false,
        });
      }
    }

    void redeem();
  }, [token, refresh, router]);

  const chooseRole = useCallback(async (role: ReportRole) => {
    setStage({ kind: "saving", role });
    try {
      const response = await fetch("/api/ql/auth/report-role", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ report_role: role }),
      });
      if (!response.ok) {
        setStage({
          kind: "failed",
          message: "That choice could not be saved. You can change it later in Workspace.",
          linkSpent: true,
        });
        return;
      }
      refresh();
      setStage({ kind: "done" });
      router.replace("/");
    } catch {
      setStage({
        kind: "failed",
        message: "The workspace service could not be reached. Try again shortly.",
        linkSpent: true,
      });
    }
  }, [refresh, router]);

  if (stage.kind === "failed") {
    return (
      <section className="auth-card" aria-labelledby="signin-failed-title">
        <p className="page-kicker">Sign-in</p>
        <h1 id="signin-failed-title">
          {stage.linkSpent ? "This link did not work" : "Not right now"}
        </h1>
        <p className="auth-error" role="alert">{stage.message}</p>
        {stage.linkSpent && (
          <a className="btn-link primary" href="/signin">Request a new link</a>
        )}
      </section>
    );
  }

  if (stage.kind === "redeeming" || stage.kind === "done") {
    return (
      <section className="auth-card" aria-labelledby="signin-progress-title">
        <p className="page-kicker">Sign-in</p>
        <h1 id="signin-progress-title">
          {stage.kind === "done" ? "Signed in" : "Signing you in…"}
        </h1>
        <p className="auth-lede" role="status">
          {stage.kind === "done"
            ? "Opening your workspace."
            : "Checking your sign-in link."}
        </p>
      </section>
    );
  }

  const saving = stage.kind === "saving";
  return (
    <section className="auth-card wide" aria-labelledby="signin-role-title">
      <p className="page-kicker">One question before you start</p>
      <h1 id="signin-role-title">How should your reports read?</h1>
      <p className="auth-lede">
        This changes the wording and the density, never the numbers. Both
        versions show the same sealed evidence, including the checks that
        fail. You can switch at any time.
      </p>
      <div className="role-choices">
        {ROLE_CHOICES.map((choice) => (
          <button
            key={choice.role}
            type="button"
            className="role-choice"
            disabled={saving}
            onClick={() => void chooseRole(choice.role)}
          >
            <strong>{choice.title}</strong>
            <span>{choice.detail}</span>
            <span className="role-choice-cta" aria-hidden="true">
              {saving && stage.role === choice.role ? "Saving…" : "Choose"}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

export default function SignInCallbackPage() {
  return (
    <main className="auth-main">
      <Suspense
        fallback={
          <section className="auth-card">
            <h1>Signing you in…</h1>
          </section>
        }
      >
        <CallbackFlow />
      </Suspense>
    </main>
  );
}
