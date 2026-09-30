"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { apiGet, apiPut } from "../studio/lib";
import { ApiRequestError, toSafeError } from "../lib/errors";
import {
  NOTE_MAX, TAGS_MAX, TAG_MAX_CODE_POINTS,
  codePointLength, normalizedTagIdentity, truncateCodePoints,
  type AnnotationView, type WorkspaceMetadataResponse,
} from "./lib";

/**
 * Private notes & tags editor for one run. The note body is fetched ONLY when
 * this dialog opens (via workspace-metadata) and lives only inside it: never in
 * list responses, URLs, localStorage, data attributes, analytics events,
 * accessible announcements, or callbacks to the parent page. Saving is an
 * explicit full replacement with optimistic concurrency; a 409 preserves the
 * draft byte-for-byte. Every async completion carries the run epoch, so a late
 * response for run A can never appear in run B or mutate anything after close.
 */

type LoadState = "loading" | "failed" | "ready";

type SaveState =
  | { state: "idle" }
  | { state: "saving" }
  | { state: "saved" }
  | { state: "conflict"; message: string }
  | { state: "failed"; message: string };

interface AnnotationBaseline {
  note: string;
  tags: string[];
}

const FOCUSABLE =
  'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), '
  + '[tabindex]:not([tabindex="-1"])';

export default function AnnotationEditor({
  runId,
  onClose,
  onSaved,
}: {
  runId: string;
  /** Close without saving; the parent restores focus to the trigger. */
  onClose: () => void;
  /** Signals ONLY that this run's server-side annotation state changed (after
   * a successful save or an explicit refresh). No note body, tag list, or
   * revision crosses this boundary — the parent refetches from the server. */
  onSaved: (runId: string) => void;
}) {
  const [load, setLoad] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [revision, setRevision] = useState(0);
  const [baseline, setBaseline] = useState<AnnotationBaseline>({ note: "", tags: [] });
  const [tagInput, setTagInput] = useState("");
  const [tagIssue, setTagIssue] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const [saveState, setSaveState] = useState<SaveState>({ state: "idle" });
  const [refreshing, setRefreshing] = useState(false);
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  // Run/request epoch: bumped on run change, reload, close, and unmount. Every
  // GET/PUT completion re-checks it before touching state or the parent.
  const epochRef = useRef(0);
  const refreshSeqRef = useRef(0);
  const returnFocusSelectorRef = useRef<string | null>(null);

  const saving = saveState.state === "saving";
  const busy = saving || refreshing;
  const dirty = note !== baseline.note
    || tags.length !== baseline.tags.length
    || tags.some((tag, index) => tag !== baseline.tags[index])
    // Text in the pending chip input is user work too. Closing must never
    // discard it silently merely because Enter/comma has not been pressed yet.
    || tagInput !== "";

  const loadMetadata = useCallback(() => {
    const epoch = ++epochRef.current;
    setLoad("loading");
    setLoadError(null);
    apiGet<WorkspaceMetadataResponse>(
      `/runs/${encodeURIComponent(runId)}/workspace-metadata`)
      .then(({ body }) => {
        if (epoch !== epochRef.current) return; // superseded or closed
        if (body.run_id !== runId) {
          // Fail closed: a payload naming a different run is never shown.
          setLoadError(
            "The returned note did not identify this exact run, so nothing "
            + "is shown.");
          setLoad("failed");
          return;
        }
        const loadedTags = body.annotation.tags.map((tag) => tag.display_tag);
        setNote(body.annotation.note);
        setTags(loadedTags);
        setRevision(body.annotation.revision);
        setBaseline({ note: body.annotation.note, tags: loadedTags });
        setLoad("ready");
      })
      .catch((caught) => {
        if (epoch !== epochRef.current) return;
        setLoadError(toSafeError(
          caught, "The private note could not be loaded.").userMessage);
        setLoad("failed");
      });
  }, [runId]);

  useEffect(() => {
    loadMetadata();
    // Closing or switching runs invalidates every in-flight completion.
    return () => {
      epochRef.current += 1;
      refreshSeqRef.current += 1;
    };
  }, [loadMetadata]);

  // The dialog is portaled outside the application frame. While it is open,
  // the entire background is inert and hidden from assistive technology; this
  // makes aria-modal truthful rather than relying on a Tab loop alone.
  useEffect(() => {
    const background = document.querySelector<HTMLElement>(".app-frame");
    if (!background) return;
    const wasInert = background.inert;
    const previousAriaHidden = background.getAttribute("aria-hidden");
    background.inert = true;
    background.setAttribute("aria-hidden", "true");
    return () => {
      background.inert = wasInert;
      if (previousAriaHidden === null) background.removeAttribute("aria-hidden");
      else background.setAttribute("aria-hidden", previousAriaHidden);
    };
  }, []);

  // Escape requests close (through the unsaved-changes gate), Tab is trapped —
  // including when focus is currently outside the dialog.
  const requestCloseRef = useRef<() => void>(() => {});
  requestCloseRef.current = () => {
    if (busy) return;
    if (confirmDiscard) {
      // Escape inside the discard confirmation backs out to editing.
      setConfirmDiscard(false);
      return;
    }
    if (dirty) {
      const active = document.activeElement as HTMLElement | null;
      returnFocusSelectorRef.current = active?.id
        ? `#${active.id}`
        : active?.dataset?.testid
          ? `[data-testid="${active.dataset.testid}"]`
          : null;
      setConfirmDiscard(true);
      return;
    }
    onClose();
  };

  useEffect(() => {
    const dialog = dialogRef.current;
    // Focus enters the dialog immediately — while the metadata is still
    // loading there may be no control yet, so the dialog itself takes focus.
    (dialog?.querySelector<HTMLElement>(FOCUSABLE) ?? dialog)?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        requestCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (!items.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const active = document.activeElement;
      // True isolation: if focus escaped the dialog, pull it back inside.
      if (!(active instanceof HTMLElement) || !dialog.contains(active)) {
        event.preventDefault();
        items[0].focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
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
  }, []);

  // When the metadata arrives, move focus to the first real control.
  useEffect(() => {
    if (load !== "ready") return;
    dialogRef.current?.querySelector<HTMLElement>("#annotation-note")?.focus();
  }, [load]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (confirmDiscard) {
      dialog?.querySelector<HTMLElement>("button")?.focus();
      return;
    }
    // Returning from the discard confirmation restores the prior control.
    const selector = returnFocusSelectorRef.current;
    if (!selector) return;
    returnFocusSelectorRef.current = null;
    const previous = dialog?.querySelector<HTMLElement>(selector);
    (previous ?? dialog?.querySelector<HTMLElement>(FOCUSABLE) ?? dialog)?.focus();
  }, [confirmDiscard]);

  /** A fresh edit clears a stale Saved/Failed banner; a Conflict stays visible
   * until the user explicitly refreshes the current version. */
  function markEdited() {
    setSaveState((current) =>
      current.state === "saved" || current.state === "failed"
        ? { state: "idle" }
        : current);
  }

  function addTagFromInput() {
    if (busy) return;
    // Client mirror of the server pipeline: NFKC, trim, then 1–32 Unicode
    // code points and a case-folded identity. The server stays the authority.
    const display = tagInput.normalize("NFKC").trim();
    if (!display) return;
    if (codePointLength(display) > TAG_MAX_CODE_POINTS) {
      setTagIssue(`Tags are 1–${TAG_MAX_CODE_POINTS} characters.`);
      return;
    }
    if (tags.length >= TAGS_MAX) {
      setTagIssue(`A run can have at most ${TAGS_MAX} tags.`);
      return;
    }
    const identity = normalizedTagIdentity(display);
    if (tags.some((existing) => normalizedTagIdentity(existing) === identity)) {
      setTagIssue(`“${display}” is already one of this run's tags.`);
      return;
    }
    setTags((current) => [...current, display]);
    setTagInput("");
    setTagIssue(null);
    setAnnouncement(`Tag ${display} added.`);
    markEdited();
  }

  function removeTagAt(index: number) {
    if (busy) return;
    const removed = tags[index];
    setTags((current) => current.filter((_, i) => i !== index));
    setAnnouncement(`Tag ${removed} removed.`);
    markEdited();
  }

  function onTagKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    // Never treat IME composition keystrokes as chip commands.
    if (event.nativeEvent.isComposing || event.keyCode === 229) return;
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      addTagFromInput();
      return;
    }
    if (event.key === "Backspace" && tagInput === "" && tags.length > 0) {
      event.preventDefault();
      removeTagAt(tags.length - 1);
    }
  }

  async function save() {
    if (busy || saveState.state === "conflict") return;
    if (tagInput.trim() !== "") {
      setTagIssue("Press Enter or comma to add the pending tag before saving.");
      return;
    }
    const epoch = epochRef.current;
    setSaveState({ state: "saving" });
    setRefreshNotice(null);
    try {
      const { body } = await apiPut<{ annotation: AnnotationView }>(
        `/runs/${encodeURIComponent(runId)}/annotations`,
        { note, tags, expected_revision: revision });
      if (epoch !== epochRef.current) return; // closed or superseded — dropped
      const savedTags = body.annotation.tags.map((tag) => tag.display_tag);
      setRevision(body.annotation.revision);
      setNote(body.annotation.note);
      setTags(savedTags);
      setBaseline({ note: body.annotation.note, tags: savedTags });
      setSaveState({ state: "saved" });
      setAnnouncement("Notes and tags saved.");
      onSaved(runId);
    } catch (caught) {
      if (epoch !== epochRef.current) return;
      if (caught instanceof ApiRequestError && caught.code === "ANNOTATION_CONFLICT") {
        setSaveState({
          state: "conflict",
          message: caught.detailMessage
            ?? "The annotations changed since you loaded them.",
        });
        return;
      }
      if (caught instanceof ApiRequestError && caught.code === "RUN_DELETED") {
        setSaveState({
          state: "failed",
          message: caught.detailMessage
            ?? "This run was removed from the workspace. Restore it before "
            + "editing its annotations.",
        });
        return;
      }
      if (caught instanceof ApiRequestError && caught.status === 422
        && caught.detailMessage) {
        // The structured server message names the exact text/tag rule.
        setSaveState({ state: "failed", message: caught.detailMessage });
        return;
      }
      setSaveState({
        state: "failed",
        message: toSafeError(
          caught, "The private note could not be saved.").userMessage,
      });
    }
  }

  /** Conflict recovery: refresh only the server-side version and revision. The
   * draft note and tags stay exactly as written — never auto-overwritten. */
  async function refreshCurrentVersion() {
    if (busy) return;
    const epoch = epochRef.current;
    const refreshSeq = ++refreshSeqRef.current;
    setRefreshing(true);
    try {
      const { body } = await apiGet<WorkspaceMetadataResponse>(
        `/runs/${encodeURIComponent(runId)}/workspace-metadata`);
      if (epoch !== epochRef.current || refreshSeq !== refreshSeqRef.current) {
        return; // closed, superseded, or a newer refresh owns the editor
      }
      if (body.run_id !== runId) {
        setSaveState({
          state: "failed",
          message: "The refreshed data did not identify this exact run, so "
            + "nothing was applied.",
        });
        return;
      }
      const currentTags = body.annotation.tags.map((tag) => tag.display_tag);
      setRevision(body.annotation.revision);
      setBaseline({ note: body.annotation.note, tags: currentTags });
      setSaveState({ state: "idle" });
      setRefreshNotice(
        "Current version refreshed. Saving now replaces it with your draft.");
      onSaved(runId);
    } catch (caught) {
      if (epoch !== epochRef.current || refreshSeq !== refreshSeqRef.current) return;
      setSaveState({
        state: "failed",
        message: toSafeError(
        caught, "The current version could not be refreshed.").userMessage,
      });
    } finally {
      if (epoch === epochRef.current && refreshSeq === refreshSeqRef.current) {
        setRefreshing(false);
      }
    }
  }

  return createPortal((
    <div className="dialog-backdrop">
      <div
        ref={dialogRef}
        tabIndex={-1}
        className="card confirm-dialog annotation-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="annotation-title"
        aria-busy={busy}
        data-testid="annotation-editor"
      >
        {confirmDiscard ? (
          <div data-testid="annotation-discard-confirm">
            <h2 id="annotation-title" style={{ marginTop: 0 }}>
              Discard unsaved changes?
            </h2>
            <p>
              The private note and tags for this run have unsaved edits. Closing
              now discards them; nothing has been saved.
            </p>
            <div className="field-row">
              <button
                type="button"
                className="primary"
                onClick={() => setConfirmDiscard(false)}
              >
                Keep editing
              </button>
              <button
                type="button"
                data-testid="annotation-discard"
                onClick={onClose}
              >
                Discard changes
              </button>
            </div>
          </div>
        ) : (
          <>
            <h2 id="annotation-title" style={{ marginTop: 0 }}>
              Private notes &amp; tags
            </h2>
            <p className="workspace-meta" style={{ marginTop: 0 }}>
              Run <code>{runId}</code> · private workspace context — never part
              of sealed research evidence.
            </p>
            {load === "loading" && (
              <p role="status" data-testid="annotation-loading">
                Loading the private note…
              </p>
            )}
            {load === "failed" && (
              <div
                className="actionable-error"
                role="alert"
                data-testid="annotation-load-error"
              >
                <strong>{loadError}</strong>
                <div className="field-row">
                  <button type="button" onClick={loadMetadata}>Retry</button>
                  <button type="button" onClick={onClose}>Close</button>
                </div>
              </div>
            )}
            {load === "ready" && (
              <>
                <div className="field">
                  <label htmlFor="annotation-note">Private note</label>
                  <textarea
                    id="annotation-note"
                    rows={6}
                    value={note}
                    disabled={busy}
                    onChange={(event) => {
                      setNote(truncateCodePoints(event.target.value, NOTE_MAX));
                      markEdited();
                    }}
                  />
                  <small className="annotation-count" data-testid="note-count">
                    {/* API limits count Unicode code points. */}
                    {codePointLength(note).toLocaleString("en-US")} / 8,000
                    characters · plain text only
                  </small>
                </div>
                <div className="field">
                  <label htmlFor="annotation-tag-input">Tags</label>
                  {tags.length > 0 && (
                    <ul className="tag-list tag-editor-list" aria-label="Current tags">
                      {tags.map((tag, index) => (
                        <li className="tag-chip" key={`${tag}-${index}`}>
                          {tag}
                          <button
                            type="button"
                            className="tag-remove"
                            data-testid={`annotation-tag-remove-${index}`}
                            aria-label={`Remove tag ${tag}`}
                            disabled={busy}
                            onClick={() => removeTagAt(index)}
                          >
                            ×
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <input
                    id="annotation-tag-input"
                    type="text"
                    value={tagInput}
                    placeholder="Add a tag, then press Enter"
                    disabled={busy}
                    onChange={(event) => {
                      setTagInput(event.target.value);
                      setTagIssue(null);
                      markEdited();
                    }}
                    onKeyDown={onTagKeyDown}
                  />
                  <small className="annotation-count">
                    {tags.length} / {TAGS_MAX} tags · Enter or comma adds ·
                    Backspace in the empty input removes the last tag
                  </small>
                  {tagIssue && (
                    <small className="data-inline-error" role="alert" data-testid="tag-issue">
                      {tagIssue}
                    </small>
                  )}
                </div>
                {saveState.state === "saved" && (
                  <p className="notice" role="status" data-testid="annotation-save-state">
                    Saved. The private note and complete tag set were replaced.
                  </p>
                )}
                {refreshNotice && (
                  <p className="notice" role="status" data-testid="annotation-refresh-notice">
                    {refreshNotice}
                  </p>
                )}
                {saveState.state === "conflict" && (
                  <div className="notice warn" role="alert" data-testid="annotation-conflict">
                    <strong>The workspace changed.</strong>{" "}
                    {saveState.message} Your draft is preserved exactly as
                    written; nothing was overwritten.
                    <div className="field-row" style={{ marginTop: 8 }}>
                      <button
                        type="button"
                        data-testid="annotation-refresh"
                        onClick={refreshCurrentVersion}
                        disabled={busy}
                      >
                        {refreshing ? "Refreshing…" : "Refresh current version"}
                      </button>
                    </div>
                  </div>
                )}
                {saveState.state === "failed" && (
                  <div className="actionable-error" role="alert" data-testid="annotation-save-error">
                    <strong>The save did not go through.</strong>
                    <span>{saveState.message} Your draft is unchanged.</span>
                  </div>
                )}
                <div className="field-row" style={{ marginTop: 12 }}>
                  <button
                    type="button"
                    className="primary"
                    data-testid="annotation-save"
                    onClick={save}
                    disabled={busy || saveState.state === "conflict"}
                  >
                    {saving ? "Saving…" : "Save notes & tags"}
                  </button>
                  <button
                    type="button"
                    data-testid="annotation-close"
                    disabled={busy}
                    onClick={() => requestCloseRef.current()}
                  >
                    Close
                  </button>
                </div>
              </>
            )}
          </>
        )}
        {/* Restrained announcements: tag names and generic save status only —
            the note body is never announced. */}
        <p
          className="visually-hidden"
          aria-live="polite"
          data-testid="annotation-announcement"
        >
          {announcement}
        </p>
      </div>
    </div>
  ), document.body);
}
