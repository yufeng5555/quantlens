/**
 * Safe error adapter. Ordinary UI surfaces get an actionable `userMessage` plus an
 * optional short `reference` code. Raw backend detail, route paths, stack traces,
 * schema names, and String(error) never reach the page through this module.
 */

export interface SafeError {
  userMessage: string;
  /** Short stable reference (e.g. "QUOTA_EXCEEDED") for support conversations. */
  reference?: string;
}

/** Thrown by the API client when a response carries a structured error detail. */
export class ApiRequestError extends Error {
  readonly code?: string;
  readonly status?: number;
  readonly detailMessage?: string;

  constructor(options: { code?: string; status?: number; detailMessage?: string }) {
    super(options.detailMessage ?? options.code ?? "API request failed");
    this.name = "ApiRequestError";
    this.code = options.code;
    this.status = options.status;
    this.detailMessage = options.detailMessage;
  }
}

const CODE_MESSAGES: Record<string, string> = {
  CONFIRMATION_REQUIRED:
    "Review and confirm the research summary before running.",
  CONFIRMATION_STALE:
    "The specification changed after you reviewed it. Review the updated summary, then run again.",
  QUOTA_EXCEEDED:
    "This workspace's run allowance is used up, so nothing was started.",
  WORKER_UNAVAILABLE:
    "Research execution is temporarily unavailable. Nothing was queued and no run allowance was reserved. Wait a moment, then try again.",
  // A full volume is an operator condition, not something waiting helps with, so
  // neither of these tells the reader to try again in a moment. They are two codes
  // because only the first one can honestly promise that nothing was written: the
  // second is emitted from a request that had already started, and one of those
  // (seeding the bundle) seals a series at a time, so the screen showing this
  // message can be the same screen listing what did get through.
  STORAGE_EXHAUSTED:
    "This deployment has run out of storage, so nothing was started. Nothing was queued and no run allowance was reserved. This needs an operator to free space before research can continue.",
  STORAGE_EXHAUSTED_MID_REQUEST:
    "This deployment ran out of storage part-way through that request, so it did not finish. Anything already sealed is unaffected and is still listed. This needs an operator to free space before it can be retried.",
  SPEC_INVALID:
    "The specification has validation issues. Fix the highlighted fields and try again.",
  RUN_NOT_FOUND:
    "That run isn't available in this workspace.",
  EVIDENCE_INTEGRITY_FAILURE:
    "The sealed evidence for this run failed its integrity check, so no values are shown.",
  EVIDENCE_NOT_AVAILABLE:
    "The evidence view could not be loaded from the research service.",
  EXPLANATION_INTEGRITY_FAILURE:
    "The sealed evidence failed its integrity check, so no summary was generated.",
  REPORT_INTEGRITY_FAILURE:
    "The sealed evidence failed its integrity check, so no report will be rendered from it.",
  LEGACY_CHECKPOINT_REBUILD_REQUIRED:
    "This run predates the current evidence contract and needs to be rebuilt.",
  LOCAL_PREVIEW_BOUNDARY:
    "This workspace only accepts local requests.",
  FINAL_HOLDOUT_CONSUMED:
    "This data window's single-use final holdout was already consumed by an earlier "
    + "run and can never be revealed twice. Change the data window or snapshot, then "
    + "run again.",
  DATASET_NOT_FOUND:
    "That dataset isn't available in this workspace.",
  LIMIT_INVALID:
    "The request asked for an unsupported page size.",
  // Being signed out is the most ordinary thing that can happen here -- it is every
  // visitor's state before they are anything else -- and it was the one condition with
  // no wording, so it fell through and got reported as a failure of the service.
  AUTH_SESSION_REQUIRED:
    "Sign in to run research. Everything you have set up on this page is kept.",
  AUTH_SESSION_INVALID:
    "That session has expired. Sign in again — everything you have set up on this "
    + "page is kept.",
};

/** Whether a failure is simply "you are not signed in", which is not a fault to report
 * as one. Surfaces use this to offer a way in instead of an apology. */
export function isSignedOutError(error: SafeError | null | undefined): boolean {
  return error?.reference === "AUTH_SESSION_REQUIRED"
    || error?.reference === "AUTH_SESSION_INVALID";
}

const NETWORK_MESSAGE =
  "QuantLens couldn't reach its research service. Check that the workspace is running, then try again.";

/**
 * Convert any caught value into a safe, user-facing error. `fallback` should
 * describe the action that failed ("The run list couldn't be loaded.").
 */
export function toSafeError(caught: unknown, fallback: string): SafeError {
  if (caught instanceof ApiRequestError) {
    if (caught.code && CODE_MESSAGES[caught.code]) {
      return { userMessage: CODE_MESSAGES[caught.code], reference: caught.code };
    }
    if (caught.detailMessage && isDisplayable(caught.detailMessage)) {
      // Structured messages from our own API are written for users; still pair
      // them with the reference code when one exists.
      return { userMessage: caught.detailMessage, reference: caught.code };
    }
    return { userMessage: fallback, reference: caught.code };
  }
  if (caught instanceof TypeError || caught instanceof DOMException) {
    return { userMessage: NETWORK_MESSAGE };
  }
  if (caught instanceof Error && caught.message === "NETWORK") {
    return { userMessage: NETWORK_MESSAGE };
  }
  return { userMessage: fallback };
}

/** Reject strings that look like machine payloads rather than sentences. */
function isDisplayable(message: string): boolean {
  if (message.length > 300) return false;
  if (/[{}[\]<>\\]|Traceback|Error:|http:\/\/|https:\/\//.test(message)) return false;
  return true;
}

interface YamlMark {
  line?: number;
}

/**
 * Friendly, line-aware YAML parse message. Never returns the raw exception
 * (which embeds a code-frame snippet of the document).
 */
export function yamlErrorMessage(caught: unknown): string {
  const err = caught as { mark?: YamlMark; reason?: string } | null;
  const line = typeof err?.mark?.line === "number" ? err.mark.line + 1 : null;
  const reason = typeof err?.reason === "string" && err.reason.length <= 120
    ? err.reason
    : "the document couldn't be parsed";
  return line === null
    ? `This YAML couldn't be read: ${reason}. The cards were not changed.`
    : `Line ${line}: ${reason}. Fix the YAML near that line — the cards were not changed.`;
}
