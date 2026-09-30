"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { WORKSPACE_LABELS } from "../lib/labels";
import {
  useWorkspaceSession, workspaceStatusLabel, workspaceStatusShortLabel,
} from "./WorkspaceSession";

const RESEARCH_NAV = [
  { href: "/", label: "Overview" },
  { href: "/studio", label: "Research Studio" },
  { href: "/experiments", label: "Experiments" },
  { href: "/runs", label: "Runs & Reports" },
  { href: "/data", label: "Data" },
];

const REFERENCE_NAV = [
  { href: "/methodology", label: "Methodology" },
  { href: "/about", label: "About QuantLens" },
];

// System Status describes the environment rather than the research itself, and
// the workspace page also lists recent runs — keeping either beside Runs &
// Reports read as a second history entry point. It stays one click away as a
// utility link under the workspace badge instead.
//
// The workspace itself is deliberately NOT listed here. The badge directly
// below this row is already a link to it, and carries the current status as
// well, so a "Workspace" entry stacked immediately above it was two adjacent
// links to one destination — the repeated-navigation problem this shell was
// reworked to remove, reintroduced one row lower.
const UTILITY_NAV = [
  { href: "/status", label: "System Status" },
];

function isCurrent(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

function WorkspacePill({ compact }: { compact?: boolean }) {
  const { state } = useWorkspaceSession();
  const label = workspaceStatusLabel(state);
  const statusClass = state.kind === "local-preview"
    ? "sample"
    : state.kind === "authenticated"
      ? "authenticated"
      : state.kind;
  const ariaLabel = state.kind === "local-preview"
    ? `${WORKSPACE_LABELS.sample}: ${WORKSPACE_LABELS.sampleDetail}`
    : state.kind === "authenticated"
      ? `${WORKSPACE_LABELS.authenticated}: ${state.session.displayLabel}`
      : state.kind === "signed-out"
        ? "Sign in to open a research workspace"
        : state.kind === "unavailable"
          ? `${WORKSPACE_LABELS.unavailable}: access not confirmed`
          : WORKSPACE_LABELS.loading;

  return (
    <Link
      // A visitor who is not signed in has nothing to read on the workspace
      // boundary page; send them to the door itself.
      href={state.kind === "signed-out" ? "/signin" : "/account"}
      className={`workspace-pill ${statusClass}`}
      aria-label={ariaLabel}
      title={ariaLabel}
      data-testid={compact ? "workspace-status-link" : "workspace-status-sidebar"}
    >
      <span aria-hidden="true" className="workspace-dot" />
      <span className="workspace-pill-text" aria-live={compact ? "polite" : undefined}>
        {label}
      </span>
      {/* Narrow viewports swap to a shorter visible word — never an unlabeled dot. */}
      <span className="workspace-pill-text-short" aria-hidden="true">
        {workspaceStatusShortLabel(state)}
      </span>
    </Link>
  );
}

/** Ending a session must be possible from anywhere, and must actually end it:
 *  the server revokes, then the app reloads so no stale view survives. */
function SignOutButton() {
  const { refresh } = useWorkspaceSession();
  const [leaving, setLeaving] = useState(false);
  return (
    <button
      type="button"
      className="btn-link app-topbar-signout"
      data-testid="shell-sign-out"
      disabled={leaving}
      onClick={() => {
        setLeaving(true);
        void fetch("/api/ql/auth/signout", {
          method: "POST", credentials: "same-origin",
        }).finally(() => {
          refresh();
          window.location.assign("/");
        });
      }}
    >
      {leaving ? "Signing out…" : "Sign out"}
    </button>
  );
}

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  // Below the drawer breakpoint the sidebar is a modal drawer; above it, the
  // ordinary always-visible navigation. Mirrors the globals.css media query.
  const [drawerMode, setDrawerMode] = useState(false);
  const { state } = useWorkspaceSession();
  const sidebarRef = useRef<HTMLDivElement | null>(null);
  const menuButtonRef = useRef<HTMLButtonElement | null>(null);
  const openRef = useRef(false);
  const restoreMenuFocusRef = useRef(false);

  useEffect(() => { openRef.current = open; }, [open]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 1023px)");
    const update = () => {
      const nextDrawerMode = media.matches;
      const focusWasInSidebar = sidebarRef.current?.contains(document.activeElement)
        ?? false;
      setDrawerMode(nextDrawerMode);
      if (nextDrawerMode && !openRef.current && focusWasInSidebar) {
        // Resizing a focused desktop sidebar into a closed inert drawer must
        // not strand focus on a now-unreachable link.
        restoreMenuFocusRef.current = true;
      }
      if (!nextDrawerMode && openRef.current) setOpen(false);
    };
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    // Close the drawer on navigation; keyboard users get their focus back on
    // the Menu toggle instead of being stranded in a hidden drawer.
    if (openRef.current) {
      restoreMenuFocusRef.current = true;
      setOpen(false);
    }
  }, [pathname]);

  useEffect(() => {
    // `inert` takes the page behind the drawer out of the focus and accessibility
    // trees, but it does nothing about scrolling. A touch that starts on the scrim --
    // the strip of page still visible beside the drawer on a phone -- scrolls the
    // content underneath, so a reader who opens the menu on a 7,900px page and closes
    // it again can land hundreds of pixels from where they were, with nothing on
    // screen to explain the jump.
    //
    // The offset is restored rather than merely released: `position: fixed` is what
    // actually holds iOS Safari still, and it resets the scroll offset as a side
    // effect, so putting it back is part of the same fix rather than a nicety.
    if (!(drawerMode && open)) return;
    const { body } = document;
    const scrollY = window.scrollY;
    const previous = {
      position: body.style.position,
      top: body.style.top,
      width: body.style.width,
      overflow: body.style.overflow,
    };
    body.style.position = "fixed";
    body.style.top = `-${scrollY}px`;
    body.style.width = "100%";
    body.style.overflow = "hidden";
    return () => {
      body.style.position = previous.position;
      body.style.top = previous.top;
      body.style.width = previous.width;
      body.style.overflow = previous.overflow;
      window.scrollTo(0, scrollY);
    };
  }, [drawerMode, open]);

  useEffect(() => {
    if (open || !drawerMode || !restoreMenuFocusRef.current) return;
    restoreMenuFocusRef.current = false;
    menuButtonRef.current?.focus();
  }, [open, drawerMode]);

  // While the drawer is open, focus starts on the first nav link and Tab /
  // Shift+Tab stay inside; Escape closes and returns focus to the Menu toggle.
  useEffect(() => {
    if (!open || !drawerMode) return;
    const sidebar = sidebarRef.current;
    sidebar?.querySelector<HTMLElement>(".nav-drawer-close")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        restoreMenuFocusRef.current = true;
        setOpen(false);
        return;
      }
      if (event.key !== "Tab" || !sidebar) return;
      const items = Array.from(
        sidebar.querySelectorAll<HTMLElement>("a[href], button:not([disabled])"));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (!(active instanceof HTMLElement) || !sidebar.contains(active)) {
        event.preventDefault();
        first.focus();
        return;
      }
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, drawerMode]);

  return (
    <div className={`app-frame${open ? " nav-open" : ""}`}>
      <div
        className="app-sidebar"
        id="app-sidebar"
        ref={sidebarRef}
        // A closed drawer is fully out of the keyboard and accessibility tree;
        // the desktop sidebar (no drawer mode) is never inert.
        inert={drawerMode && !open ? true : undefined}
        aria-hidden={drawerMode && !open ? true : undefined}
        role={drawerMode && open ? "dialog" : "complementary"}
        aria-modal={drawerMode && open ? true : undefined}
        aria-label={drawerMode && open ? "Site navigation" : "Research sidebar"}
      >
        <Link href="/" className="app-brand">
          <strong>QuantLens</strong>
          <span>Evidence-first quant research</span>
        </Link>
        <button
          type="button"
          className="nav-drawer-close"
          onClick={() => {
            restoreMenuFocusRef.current = true;
            setOpen(false);
          }}
        >
          Close menu
        </button>
        <nav className="app-nav" aria-label="Primary">
          <div className="app-nav-group">
            <h2 id="nav-research">Research</h2>
            {RESEARCH_NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isCurrent(pathname, item.href) ? "page" : undefined}
              >
                {item.label}
              </Link>
            ))}
          </div>
          <div className="app-nav-group">
            <h2 id="nav-reference">Reference</h2>
            {REFERENCE_NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isCurrent(pathname, item.href) ? "page" : undefined}
              >
                {item.label}
              </Link>
            ))}
          </div>
          <div className="app-nav-foot">
            {/* Utility links precede the pill so the workspace status stays the
                drawer's final stop — the reviewed keyboard contract ends on
                "where am I", not on a secondary destination. */}
            <div className="app-nav-utility">
              {UTILITY_NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={isCurrent(pathname, item.href) ? "page" : undefined}
                >
                  {item.label}
                </Link>
              ))}
            </div>
            <WorkspacePill />
          </div>
        </nav>
      </div>
      {open && (
        // Mouse-only dismiss affordance; keyboard users close the drawer with
        // Escape or the labeled Menu toggle, so this stays out of the
        // accessibility tree.
        <div
          className="app-scrim"
          aria-hidden="true"
          onClick={() => {
            restoreMenuFocusRef.current = true;
            setOpen(false);
          }}
        />
      )}
      <div
        className="app-main"
        inert={drawerMode && open ? true : undefined}
        aria-hidden={drawerMode && open ? true : undefined}
      >
        <header className="app-topbar">
          <button
            type="button"
            ref={menuButtonRef}
            className="nav-toggle"
            aria-label="Menu"
            aria-expanded={open}
            aria-controls="app-sidebar"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Close" : "Menu"}
          </button>
          <Link href="/" className="app-topbar-brand">QuantLens</Link>
          <span className="app-topbar-spacer" />
          {/* The primary action for a visitor who has not signed in. It is a
              control, not a status pill: the first thing a newcomer needs is
              somewhere to press, and burying it inside an error notice read as
              "this product is broken" rather than "you have not started yet". */}
          {state.kind === "signed-out" && (
            <Link className="btn-link primary app-topbar-signin" href="/signin"
              data-testid="shell-sign-in">
              Sign in
            </Link>
          )}
          {state.kind === "authenticated" && <SignOutButton />}
          <WorkspacePill compact />
        </header>
        {state.kind === "unavailable" && (
          <aside className="workspace-alert" aria-label="Workspace status">
            <p role="status" style={{ margin: 0 }}>
              Workspace access could not be confirmed. Private actions stay unavailable
              until the workspace service responds.
            </p>
          </aside>
        )}
        {children}
      </div>
    </div>
  );
}
