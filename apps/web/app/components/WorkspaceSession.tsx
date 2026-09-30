"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/** How deep this reader asked their reports to be rendered. */
export type ReportRole = "novice" | "expert";

export type WorkspaceSession = {
  displayLabel: string;
  roles: string[];
  authMode: string;
  authenticated: boolean;
  securityBoundary: boolean;
  localPreview: boolean;
  notice: string;
  // Present only for account-backed sessions; a local preview has no stored
  // preference, so an absent value is normal rather than a broken contract.
  reportRole: ReportRole | null;
  reportRoleChosen: boolean;
};

export type WorkspaceSessionState =
  | { kind: "loading" }
  | { kind: "local-preview"; session: WorkspaceSession }
  | { kind: "authenticated"; session: WorkspaceSession }
  // A deployed instance answers 401 to everyone who has not signed in yet.
  // That is the ordinary first state of every visitor, not a fault, and
  // conflating it with "unavailable" told newcomers the product was broken at
  // the very moment it was working correctly.
  | { kind: "signed-out" }
  | { kind: "unavailable" };

type WorkspaceSessionContextValue = {
  state: WorkspaceSessionState;
  refresh: () => void;
};

const WorkspaceSessionContext = createContext<WorkspaceSessionContextValue | null>(null);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseSession(value: unknown): WorkspaceSession | null {
  if (!isRecord(value)) return null;

  const roles = value.roles;
  if (
    typeof value.display_label !== "string"
    || value.display_label.trim().length === 0
    || !Array.isArray(roles)
    || roles.length === 0
    || !roles.every((role) => typeof role === "string" && role.trim().length > 0)
    || typeof value.auth_mode !== "string"
    || value.auth_mode.trim().length === 0
    || typeof value.authenticated !== "boolean"
    || typeof value.security_boundary !== "boolean"
    || typeof value.local_preview !== "boolean"
    || typeof value.notice !== "string"
    || value.notice.trim().length === 0
  ) {
    return null;
  }

  const reportRole = value.report_role === "novice" || value.report_role === "expert"
    ? value.report_role
    : null;

  return {
    displayLabel: value.display_label,
    roles,
    authMode: value.auth_mode,
    authenticated: value.authenticated,
    securityBoundary: value.security_boundary,
    localPreview: value.local_preview,
    notice: value.notice,
    reportRole,
    reportRoleChosen: value.report_role_chosen === true,
  };
}

function classifySession(session: WorkspaceSession): WorkspaceSessionState {
  if (
    session.authMode === "local-preview"
    && session.localPreview
    && !session.authenticated
    && !session.securityBoundary
  ) {
    return { kind: "local-preview", session };
  }

  if (
    session.authMode !== "local-preview"
    && !session.localPreview
    && session.authenticated
    && session.securityBoundary
  ) {
    return { kind: "authenticated", session };
  }

  // A contradictory or incomplete identity contract is never treated as a session.
  return { kind: "unavailable" };
}

export function WorkspaceSessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<WorkspaceSessionState>({ kind: "loading" });
  const [requestVersion, setRequestVersion] = useState(0);

  const refresh = useCallback(() => {
    setState({ kind: "loading" });
    setRequestVersion((version) => version + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();

    async function loadSession() {
      try {
        const response = await fetch("/api/ql/session", {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (response.status === 401) {
          // Not signed in yet. The service answered correctly, so this must
          // read as an invitation rather than a failure.
          setState({ kind: "signed-out" });
          return;
        }
        if (!response.ok) {
          setState({ kind: "unavailable" });
          return;
        }
        const session = parseSession(await response.json());
        setState(session ? classifySession(session) : { kind: "unavailable" });
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setState({ kind: "unavailable" });
        }
      }
    }

    void loadSession();
    return () => controller.abort();
  }, [requestVersion]);

  const value = useMemo(() => ({ state, refresh }), [state, refresh]);
  return (
    <WorkspaceSessionContext.Provider value={value}>
      {children}
    </WorkspaceSessionContext.Provider>
  );
}

export function useWorkspaceSession(): WorkspaceSessionContextValue {
  const value = useContext(WorkspaceSessionContext);
  if (!value) throw new Error("useWorkspaceSession requires WorkspaceSessionProvider");
  return value;
}

export function workspaceStatusLabel(state: WorkspaceSessionState): string {
  switch (state.kind) {
    case "local-preview":
      return "Local research workspace";
    case "authenticated":
      return "Private research workspace";
    case "signed-out":
      return "Sign in to open a workspace";
    case "unavailable":
      return "Workspace unavailable";
    default:
      return "Checking workspace";
  }
}

/** Short visible label for narrow headers; the full label stays in aria-label. */
export function workspaceStatusShortLabel(state: WorkspaceSessionState): string {
  switch (state.kind) {
    case "local-preview":
      return "Local workspace";
    case "authenticated":
      return "Private workspace";
    case "signed-out":
      return "Sign in";
    case "unavailable":
      return "Unavailable";
    default:
      return "Checking";
  }
}
