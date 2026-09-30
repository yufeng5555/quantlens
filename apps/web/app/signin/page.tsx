"use client";

import Link from "next/link";
import { Suspense, useEffect, useState, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { useWorkspaceSession } from "../components/WorkspaceSession";

// Sign-in asks for one thing: an address, proved either by Google or by a
// one-time link. QuantLens stores no password, so there is nothing to choose,
// confirm, forget or reset. The emailed-link response is deliberately identical
// whether or not the address already has an account — this page can never be
// used to discover who has one.

type Stage =
  | { kind: "idle" }
  | { kind: "sending" }
  | { kind: "sent"; email: string }
  | { kind: "error"; message: string };

const UNAVAILABLE =
  "Sign-in email delivery is not configured for this workspace yet.";

/** Why a Google round-trip came back without a session. */
const RETURNED_ERRORS: Record<string, string> = {
  state: "That sign-in attempt could not be matched to this browser, so it was "
    + "stopped. This happens if the attempt was left open too long, or was "
    + "started somewhere else. Try again.",
  provider: "Google could not confirm that account. Nothing was signed in.",
  capacity: "This workspace is not accepting new accounts right now. Your "
    + "account was not created; try again later.",
  // Not a failure of ours, and it must not be dressed up as one.
  cancelled: "That sign-in was cancelled, so nothing happened. You can try "
    + "again whenever you like.",
  busy: "This workspace has too many sign-ins part-way through right now. "
    + "Nothing went wrong with your account — try again in a moment.",
  unavailable: "Signing in with Google is not set up on this workspace yet.",
};

function SignInForm() {
  const params = useSearchParams();
  const returnedError = RETURNED_ERRORS[params.get("error") ?? ""] ?? null;
  const [email, setEmail] = useState("");
  const [stage, setStage] = useState<Stage>({ kind: "idle" });
  // Which sign-in channels this deployment actually has. Starts false, so a slow or
  // failed readiness check offers only the channel already proven to work.
  const [emailEnabled, setEmailEnabled] = useState(false);

  useEffect(() => {
    let stale = false;
    fetch("/api/ql/health")
      .then((response) => (response.ok ? response.json() : null))
      .then((body: { auth_mode?: string } | null) => {
        if (!stale) setEmailEnabled(body?.auth_mode === "email-magic-link");
      })
      .catch(() => {});
    return () => { stale = true; };
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    const address = email.trim();
    if (!address) return;
    setStage({ kind: "sending" });
    try {
      const response = await fetch("/api/ql/auth/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email: address }),
      });
      if (response.status === 503) {
        setStage({ kind: "error", message: UNAVAILABLE });
        return;
      }
      if (response.status === 422) {
        setStage({
          kind: "error",
          message: "That does not look like an email address. Check it and try again.",
        });
        return;
      }
      if (!response.ok) {
        setStage({
          kind: "error",
          message: "The sign-in request could not be completed. Try again shortly.",
        });
        return;
      }
      setStage({ kind: "sent", email: address });
    } catch {
      setStage({
        kind: "error",
        message: "The workspace service could not be reached. Try again shortly.",
      });
    }
  }

  if (stage.kind === "sent") {
    return (
      <>
        <section className="auth-card" aria-labelledby="signin-sent-title">
          <p className="page-kicker">Check your inbox</p>
          <h1 id="signin-sent-title">A sign-in link is on its way</h1>
          <p className="auth-lede">
            If <strong>{stage.email}</strong> can sign in, the link is in that
            inbox now. It expires in 15 minutes and works once.
          </p>
          <p className="auth-note">
            No link yet? Check spam, then request another one. Requesting a new
            link does not invalidate the first — whichever you open first is the
            one that signs you in.
          </p>
          <button
            type="button"
            className="btn-link"
            onClick={() => setStage({ kind: "idle" })}
          >
            Use a different address
          </button>
        </section>
      </>
    );
  }

  return (
    <section className="auth-card" aria-labelledby="signin-title">
      <p className="page-kicker">QuantLens</p>
      <h1 id="signin-title">Sign in to your research workspace</h1>
      <p className="auth-lede">
        QuantLens stores no password.{" "}
        {emailEnabled
          ? "Choose your Google account, or have a one-time link emailed to you."
          : "Sign in with your Google account."}
      </p>

      {returnedError && (
        <p className="auth-error" role="alert" data-testid="signin-returned-error">
          {returnedError}
        </p>
      )}

      {/* A plain link, not a fetch: the browser must leave for Google and come
          back, and a redirect is the whole mechanism. */}
      <a className="btn-link primary auth-google" href="/api/ql/auth/google/start"
        data-testid="google-sign-in">
        Continue with Google
      </a>

      {/* Only offered where it works. This deployment runs QL_AUTH_MODE=google, so the
          email path answers 503 AUTH_EMAIL_NOT_CONFIGURED -- yet the form outweighed the
          button that does work, and the lede promised it. That is a wasted step and a
          broken promise on a visitor's very first action.

          Resolved from /health at run time rather than a build argument, so switching an
          instance to email links needs no rebuild of the page that offers them. Absent or
          unreadable readiness means NOT offered: never promise a channel that has not
          been confirmed. */}
      {emailEnabled && (
        <>
          <p className="auth-divider" aria-hidden="true"><span>or</span></p>

          <form onSubmit={submit} className="auth-form">
            <label htmlFor="signin-email">Email address</label>
            <input
              id="signin-email"
              name="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              placeholder="you@university.edu"
              onChange={(event) => setEmail(event.target.value)}
              disabled={stage.kind === "sending"}
            />
            <button
              type="submit"
              className="btn-link"
              disabled={stage.kind === "sending" || !email.trim()}
            >
              {stage.kind === "sending" ? "Sending…" : "Email me a sign-in link"}
            </button>
          </form>
        </>
      )}

      {stage.kind === "error" && (
        <p className="auth-error" role="alert">{stage.message}</p>
      )}

      <p className="auth-note">
        Your research runs and data stay scoped to your own workspace.
        Reports never carry your address — runs are owned by an opaque
        workspace identifier.
      </p>
      <p className="auth-note">
        <Link href="/">Return to the overview</Link>
      </p>
    </section>
  );
}

/** What somebody already signed in should see here instead of a sign-in form.
 *
 * This page never consulted the session, while the shell above it always has, so an
 * account holder who reached /signin — from autocomplete, a bookmark, a shared link, or
 * the back button — got a full sign-in form under a "Sign out" control. The product
 * contradicting itself about whether you are signed in is exactly the kind of thing it
 * cannot afford to do, and it costs a few lines to stop.
 *
 * A redirect rather than a rewritten form: the destination is the workspace, and landing
 * there is what the person was trying to do.
 */
function SignedInNotice() {
  const router = useRouter();
  const { state } = useWorkspaceSession();
  const authenticated = state.kind === "authenticated";

  useEffect(() => {
    if (authenticated) router.replace("/");
  }, [authenticated, router]);

  if (!authenticated) return null;
  return (
    <section className="auth-card" aria-labelledby="signin-title"
      data-testid="signin-already-authenticated">
      <p className="page-kicker">QuantLens</p>
      <h1 id="signin-title">You are already signed in</h1>
      <p className="auth-lede">
        Taking you to your workspace. If nothing happens,{" "}
        <Link href="/">open it directly</Link>.
      </p>
    </section>
  );
}

export default function SignInPage() {
  const { state } = useWorkspaceSession();
  if (state.kind === "authenticated") {
    return <main className="auth-main"><SignedInNotice /></main>;
  }
  return (
    <main className="auth-main">
      <Suspense
        fallback={
          <section className="auth-card">
            <h1>Sign in to your research workspace</h1>
          </section>
        }
      >
        <SignInForm />
      </Suspense>
    </main>
  );
}
