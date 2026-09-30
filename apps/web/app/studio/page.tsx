"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { dump as yamlDump, load as yamlLoad } from "js-yaml";

import type {
  ParseResponse, StrategySpec, ValidationErrorItem,
} from "@schema/ts/types";
import RuleCards, { type DatasetOption } from "./RuleCards";
import {
  apiGet, apiPost, defaultSpec, ensureGridContainsChosen,
  freshIdempotencyKey, lineageBindingFingerprint, logEvent,
  type ApiOptions, type LineageRelationship,
} from "./lib";
import {
  ApiRequestError, isSignedOutError, toSafeError, yamlErrorMessage, type SafeError,
} from "../lib/errors";
import { duplicateName, normalizeDisplayName } from "../lib/naming";
import {
  CURRENT_CASH_ASSUMPTION_LABEL, CURRENT_CASH_ASSUMPTION_NOTE,
  dataSourceLabel, instrumentDescriptor, returnBasisCopy, sourceKindToDataLabel,
} from "../lib/labels";
import { sessionDate } from "../lib/format";

type Stage = "input" | "clarify" | "cards" | "blocked";
type BatteryProfile = "battery-v1" | "battery-v2";
type ResearchMode = "formal" | "sandbox";

/** Product vocabulary for validation rigor; protocol ids stay in confirmation details. */
const RIGOR_LABELS: Record<BatteryProfile, string> = {
  "battery-v1": "Standard audit",
  "battery-v2": "Strict validation",
};

const PURPOSE_LABELS: Record<ResearchMode, string> = {
  formal: "Formal research",
  sandbox: "Sandbox test",
};

interface PreflightIssue {
  id: string;
  severity: string;
  category: string;
  message: string;
  suggestion: string;
  evidence: Record<string, unknown>;
}

interface PreflightCheck {
  id: string;
  status: string;
  label: string;
  evidence: Record<string, unknown>;
}

/** Server-authoritative research preflight (readiness only — never performance). */
interface ResearchPreflight {
  version: string;
  status: "blocked" | "ready_with_warnings" | "ready";
  can_run: boolean;
  preflight_hash: string;
  blockers: PreflightIssue[];
  warnings: PreflightIssue[];
  required_acknowledgement_ids: string[];
  checks: PreflightCheck[];
  plan: Record<string, number | string>;
  data: {
    label?: string;
    missing_business_days?: number;
    max_consecutive_missing?: number;
    returned_range?: { start?: string; end?: string };
    return_basis?: string | null;
  };
}

interface ValidateResponse {
  valid: boolean;
  errors: ValidationErrorItem[];
  restatement?: string;
  spec_hash?: string;
  not_run_notice: string;
  battery_profile?: { profile_id: string; profile_hash: string };
  preflight?: ResearchPreflight;
}

interface SavedStudioDraft {
  version: 1;
  saved_at: string;
  hypothesis: string;
  spec: StrategySpec;
  default_fields: string[];
  battery_profile?: BatteryProfile;
  research_mode?: ResearchMode;
}

interface DuplicateRunResponse {
  run_id: string;
  spec: StrategySpec;
  spec_hash?: string;
  research_mode?: string;
  confirmation_receipt?: { battery_profile?: string } | null;
}

/** Immutable duplicate-source context for a linked duplication. Captured once from
 * the resolved source response and never edited afterwards: the confirmation POST
 * binds to exactly these values. */
interface DuplicateSourceContext {
  readonly runId: string;
  readonly title: string;
  readonly specHash: string;
  readonly researchMode: ResearchMode;
  readonly batteryProfile: BatteryProfile;
}

/** `?fromRun=` resolution. While "loading", no editable Studio surface mounts;
 * "unavailable" blocks the Studio behind an explicit "Start new research instead"
 * action so a broken source can never silently become an ungrouped draft. */
type DuplicateState =
  | { phase: "idle" }
  | { phase: "loading"; runId: string }
  | { phase: "linked"; source: DuplicateSourceContext }
  | { phase: "unavailable"; runId: string };

/** Typed lineage/idempotency refusals: the complete draft and reviewed inputs are
 * preserved and the user is returned to a reviewable state — a refusal never
 * downgrades a linked duplicate into an ungrouped run. */
const LINEAGE_REFUSAL_MESSAGES: Record<string, string> = {
  LINEAGE_SPEC_IDENTICAL:
    "You chose Variation, but the specification is identical to the source run "
    + "(only the display name differs). Change a research assumption, or choose Rerun.",
  LINEAGE_SPEC_DIFFERENT:
    "You chose Rerun, but the specification differs from the source run. Restore "
    + "the source assumptions, or choose Variation.",
  LINEAGE_PARENT_CHANGED:
    "The source run no longer matches the specification identity you reviewed, so "
    + "the link was refused.",
  LINEAGE_CONTEXT_MISMATCH:
    "A linked run must keep the source run's research purpose, validation rigor, "
    + "and evidence contract, so the link was refused.",
  RUN_IDEMPOTENCY_CONFLICT:
    "This confirmation's idempotency key is already bound to a different request, "
    + "so nothing was created.",
  UNSUPPORTED_DIFF_SCHEMA:
    "The two specifications differ on fields outside the reviewed comparison "
    + "contract, so the link was refused.",
};

function isLineageRefusalCode(code: string): boolean {
  return code.startsWith("LINEAGE_")
    || code === "RUN_IDEMPOTENCY_CONFLICT"
    || code === "UNSUPPORTED_DIFF_SCHEMA";
}

const STUDIO_DRAFT_KEY = "quantlens.studio.draft.v1";

// Spec paths whose values came from transparent defaults; used to keep "default" chips
// accurate when YAML overwrites the cards.
const DEFAULT_PATH_VALUES: [string, (s: StrategySpec) => unknown][] = [
  ["rule.ma_days", (s) => s.rule.ma_days],
  ["costs.commission_bps", (s) => s.costs.commission_bps],
  ["costs.slippage_bps", (s) => s.costs.slippage_bps],
  ["benchmark", (s) => s.benchmark],
  ["data.range", (s) => s.data.range],
  ["validation.is_oos_split.oos_fraction", (s) => s.validation.is_oos_split.oos_fraction],
  ["validation.sensitivity.grid.ma_days", (s) => s.validation.sensitivity.grid.ma_days],
  ["validation.cost_stress.multipliers", (s) => s.validation.cost_stress.multipliers],
];

function ZoneHeading({ index, title, hint }: { index: string; title: string; hint?: string }) {
  return (
    <div className="data-subhead" style={{ margin: "26px 0 8px" }}>
      <div>
        <span className="data-index">{index}</span>
        <h2 style={{ margin: 0, fontSize: "1.08rem" }}>{title}</h2>
      </div>
      {hint && <span className="data-muted">{hint}</span>}
    </div>
  );
}

/** `useSearchParams` requires a Suspense boundary under static prerendering. The
 * fallback is a neutral shell, so no editable Studio surface can mount before the
 * `?fromRun=` decision is known. */
export default function StudioPage() {
  return (
    <Suspense fallback={<main><p role="status">Preparing the Research Studio…</p></main>}>
      <Studio />
    </Suspense>
  );
}

function Studio() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const fromRun = searchParams.get("fromRun");
  // A sample strategy chosen elsewhere — the overview offers three, and its
  // buttons previously landed here on an empty Studio, which made picking one
  // indistinguishable from picking none.
  const fromTemplate = searchParams.get("template");
  const [stage, setStage] = useState<Stage>("input");
  const [hypothesis, setHypothesis] = useState("");
  const [parse, setParse] = useState<ParseResponse | null>(null);
  const [spec, setSpec] = useState<StrategySpec | null>(null);
  const [specRev, setSpecRev] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [pendingDraft, setPendingDraft] =
    useState<{ draft: StrategySpec; defaults: string[] } | null>(null);
  const [defaultFields, setDefaultFields] = useState<string[]>([]);
  const [universe, setUniverse] = useState<{ symbol: string; name: string }[]>([]);
  const [datasets, setDatasets] = useState<DatasetOption[]>([]);
  const [templates, setTemplates] = useState<StrategySpec[]>([]);
  const [templateDefaults, setTemplateDefaults] = useState<string[]>([]);
  const [errors, setErrors] = useState<ValidationErrorItem[]>([]);
  const [restatement, setRestatement] = useState<string | null>(null);
  const [specHash, setSpecHash] = useState<string | null>(null);
  const [batteryProfile, setBatteryProfile] = useState<BatteryProfile>("battery-v2");
  const [batteryProfileHash, setBatteryProfileHash] = useState<string | null>(null);
  const [researchMode, setResearchMode] = useState<ResearchMode>("formal");
  const [preflight, setPreflight] = useState<ResearchPreflight | null>(null);
  const [warningsAck, setWarningsAck] = useState(false);
  const [preflightNotice, setPreflightNotice] = useState<string | null>(null);
  const [confirmChecked, setConfirmChecked] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [yamlOpen, setYamlOpen] = useState(false);
  const [yamlText, setYamlText] = useState("");
  const [yamlRev, setYamlRev] = useState(0);
  const [yamlError, setYamlError] = useState<string | null>(null);
  const [yamlServerErrors, setYamlServerErrors] = useState<ValidationErrorItem[]>([]);
  const [yamlConflict, setYamlConflict] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notifyAck, setNotifyAck] = useState(false);
  const [requestError, setRequestError] = useState<SafeError | null>(null);
  const [savedDraft, setSavedDraft] = useState<SavedStudioDraft | null>(null);
  const [lastSavedAt, setLastSavedAt] = useState<string | null>(null);
  const [duplicate, setDuplicate] = useState<DuplicateState>(
    () => (fromRun ? { phase: "loading", runId: fromRun } : { phase: "idle" }),
  );
  const [lineageRelationship, setLineageRelationship] =
    useState<LineageRelationship | null>(null);
  const [lineageRefusal, setLineageRefusal] =
    useState<{ code: string; message: string } | null>(null);
  // clarify answers
  const [cSymbol, setCSymbol] = useState("");
  const [cRuleType, setCRuleType] = useState<"" | "price_vs_ma" | "ma_crossover">("");
  const [cFast, setCFast] = useState("");
  const [cSlow, setCSlow] = useState("");
  const [cStart, setCStart] = useState("2005-01-01");
  const [cEnd, setCEnd] = useState("2024-12-31");
  const [cComm, setCComm] = useState(1);
  const [cSlip, setCSlip] = useState(5);
  const confirmDialogRef = useRef<HTMLDivElement>(null);
  const confirmTriggerRef = useRef<HTMLButtonElement>(null);
  /** One Idempotency-Key per exact reviewed binding: reused by a retry after a
   * lost response, replaced only when the binding fingerprint changes. */
  const lineageKeyRef = useRef<{ fingerprint: string; key: string } | null>(null);
  /** Set only after a duplicate source has been adopted into editable state. If
   * the URL later leaves the linked flow, that adopted spec must be discarded —
   * it can never silently become an ordinary, ungrouped create. */
  const adoptedDuplicateRunRef = useRef<string | null>(null);
  const preflightRef = useRef<HTMLElement | null>(null);
  // Render-safe preflight focus: the panel mounts on a state update, so focus must
  // run AFTER commit — a direct .focus() call in the submit handler would race the
  // first mount (and the stale-refresh remount) and silently miss.
  const [preflightFocusTick, setPreflightFocusTick] = useState(0);

  useEffect(() => {
    if (preflightFocusTick === 0) return;
    const frame = requestAnimationFrame(() => preflightRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [preflightFocusTick]);

  // Same shape, for a submit that failed. Deliberately driven by an explicit tick
  // rather than by requestError itself: a background load failure must not yank the
  // page while somebody is typing, whereas a press of the run button must be answered
  // where they are looking. Instant, not smooth -- this is a correction, and animating
  // it fights a reduced-motion preference for no benefit.
  const requestErrorRef = useRef<HTMLDivElement | null>(null);
  const [requestErrorFocusTick, setRequestErrorFocusTick] = useState(0);

  useEffect(() => {
    if (requestErrorFocusTick === 0) return;
    const frame = requestAnimationFrame(() => {
      requestErrorRef.current?.scrollIntoView({ block: "center" });
      requestErrorRef.current?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [requestErrorFocusTick]);

  useEffect(() => {
    apiGet<{ symbols: { symbol: string; name: string }[] }>("/universe")
      .then((r) => setUniverse(r.body.symbols))
      .catch((caught) => {
        setUniverse([]);
        setRequestError(toSafeError(caught, "The instrument list could not be loaded."));
      });
    apiGet<{ templates: StrategySpec[]; default_fields: string[] }>("/templates")
      .then((r) => {
        setTemplates(r.body.templates ?? []);
        setTemplateDefaults(r.body.default_fields ?? []);
      })
      .catch(() => setTemplates([]));  // the gallery is optional; the studio still works
    apiGet<{ datasets: DatasetOption[] }>("/datasets")
      .then((r) => setDatasets(r.body.datasets ?? []))
      .catch(() => setDatasets([]));
  }, []);

  useEffect(() => {
    if (!fromRun) {
      // Navigating to the plain Studio URL abandons any pending or resolved
      // duplication; the cleanup below has already invalidated its request.
      if (adoptedDuplicateRunRef.current !== null) {
        adoptedDuplicateRunRef.current = null;
        setStage("input");
        setHypothesis("");
        setParse(null);
        setSpec(null);
        setSpecRev((revision) => revision + 1);
        setDirty(false);
        setPendingDraft(null);
        setDefaultFields([]);
        setErrors([]);
        setRestatement(null);
        setSpecHash(null);
        setBatteryProfile("battery-v2");
        setBatteryProfileHash(null);
        setResearchMode("formal");
        setPreflight(null);
        setWarningsAck(false);
        setPreflightNotice(null);
        setConfirmChecked(false);
        setConfirmOpen(false);
        setYamlOpen(false);
        setYamlText("");
        setYamlError(null);
        setYamlServerErrors([]);
        setYamlConflict(false);
        setNotifyAck(false);
        setRequestError(null);
        setLineageRelationship(null);
        setLineageRefusal(null);
        lineageKeyRef.current = null;
      }
      setDuplicate((current) => (current.phase === "idle" ? current : { phase: "idle" }));
      return;
    }
    // Fresh cancellation token per source resolution. Cleanup aborts the previous
    // attempt, and both completion paths re-check the token before touching any
    // draft state, so an abandoned or superseded source response stays inert.
    const controller = new AbortController();
    const { signal } = controller;
    setDuplicate({ phase: "loading", runId: fromRun });
    setLineageRelationship(null);
    setLineageRefusal(null);
    lineageKeyRef.current = null;

    apiGet<DuplicateRunResponse>(`/runs/${encodeURIComponent(fromRun)}`, { signal })
      .then(({ status, body }) => {
        if (signal.aborted) return;
        const sourceProfile = body.confirmation_receipt?.battery_profile;
        if (
          status !== 200
          || body.run_id !== fromRun
          || !body?.spec
          || typeof body.spec !== "object"
          || typeof body.spec.meta?.name !== "string"
          || typeof body.spec_hash !== "string"
          || !body.spec_hash
          || (body.research_mode !== "formal" && body.research_mode !== "sandbox")
          || (sourceProfile !== "battery-v1" && sourceProfile !== "battery-v2")
          || (body.research_mode === "sandbox" && sourceProfile !== "battery-v1")
        ) {
          throw new Error("The source run is unavailable in this workspace.");
        }
        const sourceTitle = body.spec.meta.name;
        // A duplicate inherits the source run's purpose and validation rigor
        // exactly — a Strict validation study is never silently downgraded, and a
        // sandbox test never silently becomes formal research. A linked duplicate
        // keeps both locked, because the API refuses cross-context lineage.
        const sourceMode: ResearchMode = body.research_mode;
        setResearchMode(sourceMode);
        setBatteryProfile(sourceProfile);
        adoptedDuplicateRunRef.current = fromRun;
        adoptSpec(
          { ...body.spec, meta: { ...body.spec.meta, name: duplicateName(sourceTitle) } },
          [],
        );
        setDuplicate({
          phase: "linked",
          source: {
            runId: fromRun,
            title: sourceTitle,
            specHash: body.spec_hash,
            researchMode: sourceMode,
            batteryProfile: sourceProfile,
          },
        });
      })
      .catch(() => {
        if (signal.aborted) return;
        setDuplicate({ phase: "unavailable", runId: fromRun });
      });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromRun]);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STUDIO_DRAFT_KEY);
      if (!raw) return;
      const candidate = JSON.parse(raw) as Partial<SavedStudioDraft>;
      if (
        candidate.version === 1
        && typeof candidate.saved_at === "string"
        && typeof candidate.hypothesis === "string"
        && candidate.spec
        && typeof candidate.spec === "object"
        && Array.isArray(candidate.default_fields)
      ) {
        setSavedDraft(candidate as SavedStudioDraft);
      } else {
        window.localStorage.removeItem(STUDIO_DRAFT_KEY);
      }
    } catch {
      window.localStorage.removeItem(STUDIO_DRAFT_KEY);
    }
  }, []);

  function writeDraft(): string {
    const savedAt = new Date().toISOString();
    const draft: SavedStudioDraft = {
      version: 1,
      saved_at: savedAt,
      hypothesis,
      spec: spec!,
      default_fields: defaultFields,
      battery_profile: batteryProfile,
      research_mode: researchMode,
    };
    window.localStorage.setItem(STUDIO_DRAFT_KEY, JSON.stringify(draft));
    return savedAt;
  }

  useEffect(() => {
    if (stage !== "cards" || !spec) return;
    const timer = window.setTimeout(() => {
      setLastSavedAt(writeDraft());
    }, 300);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batteryProfile, defaultFields, hypothesis, researchMode, spec, specRev, stage]);

  function applyTemplate(template: StrategySpec) {
    // Same overwrite discipline as re-drafting: edited cards are never silently replaced.
    if (dirty && spec) {
      setPendingDraft({ draft: template, defaults: templateDefaults });
    } else {
      adoptSpec(template, templateDefaults);
    }
  }

  useEffect(() => {
    if (!confirmOpen) return;
    const dialog = confirmDialogRef.current;
    dialog?.querySelector<HTMLElement>("input, button")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setConfirmOpen(false);
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      confirmTriggerRef.current?.focus();
    };
  }, [confirmOpen]);

  const invalidateConfirmation = () => {
    // Any spec, dataset, rigor, or purpose change invalidates the previously seen
    // restatement, bindings, AND the research preflight + warning acknowledgement.
    setRestatement(null);
    setSpecHash(null);
    setBatteryProfileHash(null);
    setPreflight(null);
    setWarningsAck(false);
    setPreflightNotice(null);
    setConfirmChecked(false);
    setConfirmOpen(false);
  };

  const choosePurpose = (mode: ResearchMode) => {
    if (mode === researchMode) return;
    // A linked duplicate keeps the source run's purpose; the API refuses
    // cross-context lineage, so the switch is locked instead of failing late.
    if (duplicate.phase === "linked") return;
    setResearchMode(mode);
    if (mode === "sandbox") {
      // Sandbox tests are development-only: they always run the Standard audit
      // and can never touch the Strict validation final holdout.
      setBatteryProfile("battery-v1");
    }
    invalidateConfirmation();
  };

  const adoptSpec = (s: StrategySpec, defaults: string[]) => {
    setSpec(ensureGridContainsChosen(s));
    setSpecRev((r) => r + 1);
    setDirty(false);
    setDefaultFields(defaults);
    setErrors([]);
    setPendingDraft(null);
    setYamlOpen(false);
    invalidateConfirmation();
    setStage("cards");
  };

  // Adopt a sample strategy named in the URL, once its definition has arrived.
  //
  // Deliberately narrow: it never runs while a duplication is resolving, it
  // never overwrites work already in progress, and it happens once per name.
  // Choosing a sample is an invitation to edit it, not a command to discard
  // whatever the reader had open.
  const adoptedTemplateRef = useRef<string | null>(null);
  useEffect(() => {
    if (!fromTemplate || fromRun || !templates.length) return;
    if (adoptedTemplateRef.current === fromTemplate) return;
    const chosen = templates.find((template) => template.meta.name === fromTemplate);
    if (!chosen) return;
    adoptedTemplateRef.current = fromTemplate;
    if (dirty && spec) {
      // The same overwrite discipline the gallery uses: ask, never clobber.
      setPendingDraft({ draft: chosen, defaults: templateDefaults });
      return;
    }
    adoptSpec(chosen, templateDefaults);
    // adoptSpec is stable for this purpose: it only calls setters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromTemplate, fromRun, templates, templateDefaults]);

  function resumeSavedDraft() {
    if (!savedDraft) return;
    setHypothesis(savedDraft.hypothesis);
    setLastSavedAt(savedDraft.saved_at);
    // Drafts saved before the rigor choice existed were authored under the
    // Standard audit and resume as exactly that — no silent upgrade either.
    const resumedMode: ResearchMode =
      savedDraft.research_mode === "sandbox" ? "sandbox" : "formal";
    setResearchMode(resumedMode);
    setBatteryProfile(
      resumedMode === "sandbox" || savedDraft.battery_profile !== "battery-v2"
        ? "battery-v1"
        : "battery-v2",
    );
    adoptSpec(savedDraft.spec, savedDraft.default_fields);
    setSavedDraft(null);
    logEvent("studio_draft_resumed", {});
  }

  function discardSavedDraft() {
    window.localStorage.removeItem(STUDIO_DRAFT_KEY);
    setSavedDraft(null);
    setLastSavedAt(null);
    logEvent("studio_draft_discarded", {});
  }

  async function submitHypothesis() {
    setBusy(true);
    setNotifyAck(false);
    setRequestError(null);
    try {
      const { body } = await apiPost<ParseResponse>("/parse", { hypothesis });
      setParse(body);
      if (body.status === "draft" && body.draft) {
        if (dirty && spec) {
          // Never silently replace user-edited cards (audit hardening).
          setPendingDraft({ draft: body.draft, defaults: body.default_fields ?? [] });
        } else {
          adoptSpec(body.draft, body.default_fields ?? []);
        }
      } else if (body.status === "ambiguous") {
        const recognized = body.recognized_fields;
        setCSymbol(recognized?.symbol ?? "");
        setCRuleType(recognized?.rule_type ?? "");
        setCFast(recognized?.fast_ma_days === undefined ? "" : String(recognized.fast_ma_days));
        setCSlow(recognized?.ma_days === undefined ? "" : String(recognized.ma_days));
        setStage("clarify");
      } else {
        setStage("blocked");
      }
    } catch (caught) {
      setRequestError(toSafeError(caught, "The hypothesis could not be interpreted."));
      setRequestErrorFocusTick((tick) => tick + 1);
    } finally {
      setBusy(false);
    }
  }

  function submitClarify() {
    // Merge clarified answers into the existing spec so user-edited fields
    // (benchmark, battery settings, …) are preserved, never silently replaced.
    if (!cSymbol || !cRuleType || !cSlow || (cRuleType === "ma_crossover" && !cFast)) return;
    const slow = Number(cSlow);
    const fast = Number(cFast);
    const base: StrategySpec = spec
      ? (JSON.parse(JSON.stringify(spec)) as StrategySpec)
      : defaultSpec(cSymbol || "SPY");
    base.universe = { symbol: cSymbol || base.universe.symbol };
    base.rule = cRuleType === "price_vs_ma"
      ? { type: "price_vs_ma", fast_ma_days: null, ma_days: slow }
      : { type: "ma_crossover", fast_ma_days: fast, ma_days: slow };
    base.data = { ...base.data, range: { start: cStart, end: cEnd } };
    base.costs = { commission_bps: cComm, slippage_bps: cSlip };
    base.meta.name = cRuleType === "price_vs_ma"
      ? `${base.universe.symbol} · ${slow}-day trend`
      : `${base.universe.symbol} · ${fast}/${slow}-day crossover`;
    const clarified = ["universe.symbol", "rule.ma_days", "data.range",
      "costs.commission_bps", "costs.slippage_bps"];
    const keptDefaults = (spec
      ? defaultFields
      : ["benchmark", "validation.is_oos_split.oos_fraction",
         "validation.sensitivity.grid.ma_days", "validation.cost_stress.multipliers"])
      .filter((d) => !clarified.some((c) => d === c || d.startsWith(c + ".") || c.startsWith(d + ".")));
    adoptSpec(base, keptDefaults);
  }

  function onEdit(path: string, updater: (s: StrategySpec) => StrategySpec) {
    setSpec((prev) => {
      if (!prev) return prev;
      const next = ensureGridContainsChosen(updater(prev));
      const wasDefault = defaultFields.some((d) => d === path || d.startsWith(path + ".") || path.startsWith(d + "."));
      if (wasDefault) {
        setDefaultFields((df) => df.filter((d) => !(d === path || d.startsWith(path + ".") || path.startsWith(d + "."))));
      } else {
        // user corrected a parsed field — instrumented for gate G-B (AT-1.4)
        logEvent("parsing_correction", { field: path });
      }
      setSpecRev((r) => r + 1);
      setDirty(true);
      invalidateConfirmation();
      return next;
    });
  }

  function onNotWhatIMeant(card: string) {
    logEvent("card_correction_loop", { card });
    if (spec) {
      setCSymbol(spec.universe.symbol);
      setCRuleType(spec.rule.type);
      setCFast(spec.rule.fast_ma_days === null ? "" : String(spec.rule.fast_ma_days));
      setCSlow(String(spec.rule.ma_days));
      setCStart(spec.data.range.start);
      setCEnd(spec.data.range.end);
      setCComm(spec.costs.commission_bps);
      setCSlip(spec.costs.slippage_bps);
    }
    setStage("clarify");
  }

  /** Validate + refresh the server preflight. Returns the fresh preflight or null. */
  async function refreshPreflight(): Promise<ResearchPreflight | null> {
    if (!spec) return null;
    const { body } = await apiPost<ValidateResponse>(
      "/specs/validate", { spec, battery_profile: batteryProfile });
    setErrors(body.errors);
    if (!(body.valid && body.restatement && body.spec_hash)) {
      setPreflight(null);
      return null;
    }
    setRestatement(body.restatement);
    setSpecHash(body.spec_hash);
    setBatteryProfileHash(body.battery_profile?.profile_hash ?? null);
    const flight = body.preflight;
    if (!flight || typeof flight.preflight_hash !== "string" || !flight.preflight_hash) {
      // Fail closed: without a server preflight nothing is runnable.
      setPreflight(null);
      setRequestError({
        userMessage: "The research preflight could not be prepared, so nothing can "
          + "run yet. Validate again in a moment.",
      });
      return null;
    }
    setPreflight(flight);
    setWarningsAck(false);
    return flight;
  }

  async function reviewAndConfirm() {
    if (!spec) return;
    setBusy(true);
    setRequestError(null);
    setPreflightNotice(null);
    setLineageRefusal(null);
    try {
      const flight = await refreshPreflight();
      if (!flight) return;
      // Explicit two-step flow: the first click only produces the persistent
      // preflight panel (blocked OR ready) and moves focus to it. Continuing to
      // the confirmation dialog is a separate, clearly labeled action inside the
      // ready panel — the modal never opens on the click that created the
      // preflight.
      setPreflightFocusTick((tick) => tick + 1);
    } catch (caught) {
      setRequestError(toSafeError(caught, "The specification could not be validated."));
      setRequestErrorFocusTick((tick) => tick + 1);
    } finally {
      setBusy(false);
    }
  }

  function continueToConfirmation() {
    if (!preflight?.can_run || !restatement || !specHash) return;
    // A linked duplicate requires the explicit variation-vs-rerun choice before
    // anything can be confirmed.
    if (duplicate.phase === "linked" && !lineageRelationship) return;
    setConfirmOpen(true);
    setConfirmChecked(false);
  }

  const preflightAcknowledged =
    preflight !== null
    && (preflight.required_acknowledgement_ids.length === 0 || warningsAck);

  async function runConfirmed() {
    if (!spec || !confirmChecked || !specHash) return;
    if (!preflight?.can_run || !preflightAcknowledged) return;
    const linkedSource = duplicate.phase === "linked" ? duplicate.source : null;
    // A linked duplicate never posts without its explicit relationship choice.
    if (linkedSource && !lineageRelationship) return;
    setBusy(true);
    setRequestError(null);
    setLineageRefusal(null);
    try {
      logEvent("confirmation", { spec_name: spec.meta.name });
      const payload: Record<string, unknown> = {
        spec,
        research_mode: researchMode,
        confirmed: true,
        restatement_seen: true,
        confirmed_spec_hash: specHash,
        // The rigor the user reviewed is echoed with its server-issued profile
        // hash; the API rejects any mismatch, so a silent downgrade is impossible.
        battery_profile: batteryProfile,
        confirmed_battery_profile_hash: batteryProfileHash,
        // The exact reviewed preflight is bound to the run: its hash plus the
        // exact current warning-ID list the user acknowledged.
        confirmed_preflight_hash: preflight.preflight_hash,
        acknowledged_preflight_warning_ids:
          [...new Set(preflight.required_acknowledgement_ids)].sort(),
      };
      const requestOptions: ApiOptions = {};
      if (linkedSource && lineageRelationship) {
        // A linked duplicate adds ONLY the lineage intent; the family, diff, and
        // classification stay server-owned. The Idempotency-Key is stable for the
        // exact reviewed binding: a retry after a lost response reuses it, while
        // any material binding change mints a fresh key.
        payload.lineage = {
          parent_run_id: linkedSource.runId,
          confirmed_parent_spec_hash: linkedSource.specHash,
          relationship: lineageRelationship,
        };
        const fingerprint = lineageBindingFingerprint({
          parent_run_id: linkedSource.runId,
          confirmed_parent_spec_hash: linkedSource.specHash,
          relationship: lineageRelationship,
          confirmed_spec_hash: specHash,
          research_mode: researchMode,
          battery_profile: batteryProfile,
          confirmed_battery_profile_hash: batteryProfileHash,
          confirmed_preflight_hash: preflight.preflight_hash,
          acknowledged_preflight_warning_ids:
            [...new Set(preflight.required_acknowledgement_ids)].sort(),
        });
        if (lineageKeyRef.current?.fingerprint !== fingerprint) {
          lineageKeyRef.current = { fingerprint, key: freshIdempotencyKey() };
        }
        requestOptions.headers = { "Idempotency-Key": lineageKeyRef.current.key };
      }
      const { status, body } = await apiPost<{ run_id?: string; detail?: { code?: string; message?: string } }>(
        "/runs", payload, requestOptions);
      // 201 is the first creation; 200 is the idempotent replay of a create whose
      // response was lost. Both name the same accepted run.
      if ((status === 201 || status === 200) && body.run_id) {
        window.localStorage.removeItem(STUDIO_DRAFT_KEY);
        setSavedDraft(null);
        setLastSavedAt(null);
        router.push(`/runs/${body.run_id}`);
      } else {
        setConfirmOpen(false);
        setErrors([{ layer: "scope", message: body.detail?.message ?? "The run was not accepted.", code: body.detail?.code }]);
      }
    } catch (caught) {
      setConfirmOpen(false);
      if (caught instanceof ApiRequestError && (
        caught.code === "PREFLIGHT_STALE"
        || caught.code === "PREFLIGHT_WARNINGS_UNACKNOWLEDGED"
        || caught.code === "PREFLIGHT_BLOCKED"
      )) {
        // Not a generic failure: return the user to a refreshed preflight state.
        setWarningsAck(false);
        setPreflightNotice(
          "The research preflight changed since you reviewed it. This is the "
          + "refreshed preflight — review it (and acknowledge any warnings) "
          + "before running again.",
        );
        try {
          const refreshed = await refreshPreflight();
          if (refreshed) {
            setPreflightFocusTick((tick) => tick + 1);
            return;
          }
        } catch {
          // fall through to the fail-closed retry error below
        }
        // The refresh itself failed: never focus a missing panel or leave a
        // silent notice — fail closed with an actionable retry.
        setPreflight(null);
        setPreflightNotice(null);
        setRequestError({
          userMessage: "The research preflight changed, and refreshing it also "
            + "failed. Use “Review & run research” to request a current "
            + "preflight and try again.",
        });
        return;
      }
      if (
        duplicate.phase === "linked"
        && caught instanceof ApiRequestError
        && caught.code
        && isLineageRefusalCode(caught.code)
      ) {
        // Typed lineage/idempotency refusal: the complete draft, the source
        // binding, and the relationship choice all stay exactly as reviewed. The
        // refusal never authorizes compute and never downgrades the linked
        // duplicate into an ungrouped run.
        setLineageRefusal({
          code: caught.code,
          message: LINEAGE_REFUSAL_MESSAGES[caught.code]
            ?? toSafeError(caught, "The linked run was refused.").userMessage,
        });
        return;
      }
      setRequestError(toSafeError(caught, "The run could not be started. No strategy was submitted."));
      // Bring the reason to the person who just pressed the button. The banner renders
      // near the top of a page that is thousands of pixels long by the time a spec is
      // complete, so a submit failure at the bottom left the button looking simply
      // dead: nothing moved into view, and focus stayed on the body.
      setRequestErrorFocusTick((tick) => tick + 1);
    } finally {
      setBusy(false);
    }
  }

  function openYaml() {
    if (!spec) return;
    logEvent("yaml_view_opened", {});
    setYamlText(yamlDump(spec, { sortKeys: false }));
    setYamlRev(specRev);
    setYamlError(null);
    setYamlServerErrors([]);
    setYamlConflict(false);
    setYamlOpen(true);
  }

  async function applyYaml(overwriteConfirmed = false) {
    if (!spec) return;
    // Conflict guard: the cards changed after this YAML snapshot was opened.
    if (specRev !== yamlRev && !overwriteConfirmed) {
      setYamlConflict(true);
      return;
    }
    let parsed: StrategySpec;
    try {
      const loaded = yamlLoad(yamlText);
      if (loaded === null || typeof loaded !== "object" || Array.isArray(loaded)) {
        setYamlError("YAML must describe a single strategy object. The cards were not changed.");
        return;
      }
      parsed = loaded as StrategySpec;
    } catch (caught) {
      setYamlError(yamlErrorMessage(caught)); // invalid YAML never touches live state
      return;
    }
    setYamlError(null);
    setRequestError(null);
    setBusy(true);
    try {
      // Server-side schema/lint/scope validation gates adoption into live state,
      // under the SAME validation rigor the run will use.
      const { body } = await apiPost<ValidateResponse>(
        "/specs/validate", { spec: parsed, battery_profile: batteryProfile });
      if (!body.valid) {
        setYamlServerErrors(body.errors);
        return;
      }
      setYamlServerErrors([]);
      setYamlConflict(false);
      setSpec(parsed);
      setSpecRev((r) => r + 1);
      setYamlRev(specRev + 1);
      setDirty(true);
      // Default chips stay only where the YAML kept the default value.
      setDefaultFields((df) => df.filter((d) => {
        const entry = DEFAULT_PATH_VALUES.find(([p]) => p === d);
        if (!entry || !spec) return false;
        return JSON.stringify(entry[1](parsed)) === JSON.stringify(entry[1](spec));
      }));
      invalidateConfirmation();
    } catch (caught) {
      setRequestError(toSafeError(caught, "The YAML could not be validated. The cards were not changed."));
    } finally {
      setBusy(false);
    }
  }

  const specDescriptor = spec ? instrumentDescriptor(spec.universe.symbol) : null;
  const benchSymbol = spec
    ? (spec.benchmark.symbol === "same_as_universe" ? spec.universe.symbol : spec.benchmark.symbol)
    : "";
  // The dataset this run is actually bound to, when the spec names a sealed one.
  const boundDataset = spec?.data.source?.dataset_id
    ? datasets.find((item) => item.dataset_id === spec.data.source?.dataset_id)
    : undefined;
  // The return basis follows that dataset, not a build-time constant. This is the box
  // the reader ticks before spending a run, and naming price return over a total-return
  // series invites them to add back dividends the figures already contain.
  const returnBasis = returnBasisCopy(boundDataset?.provenance?.price_adjustment);
  const linkedSource = duplicate.phase === "linked" ? duplicate.source : null;
  const lineageChoiceMissing = linkedSource !== null && lineageRelationship === null;
  const duplicateStateRunId = duplicate.phase === "linked"
    ? duplicate.source.runId
    : duplicate.phase === "loading" || duplicate.phase === "unavailable"
      ? duplicate.runId
      : null;
  // `useSearchParams` updates during render, while the effect that resolves or
  // clears DuplicateState runs after commit. Never expose an A editor under a B
  // URL, or a just-unlinked editor before its adopted source spec is discarded.
  const duplicateRoutePending = fromRun
    ? duplicate.phase === "idle" || duplicateStateRunId !== fromRun
    : duplicate.phase !== "idle";

  function startNewResearchInstead() {
    // Explicit abandonment: stripping ?fromRun= re-runs the resolution effect,
    // whose cleanup aborts any in-flight source request.
    router.replace("/studio");
  }

  if (duplicateRoutePending) {
    return (
      <main>
        <p role="status">Preparing the Research Studio for the selected study…</p>
      </main>
    );
  }

  // While ?fromRun= is unresolved, no editable Studio surface (cards, templates,
  // saved-draft actions) is mounted; the source load has its own dedicated state.
  if (duplicate.phase === "loading") {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Guided research</p>
            <h1>Research Studio</h1>
          </div>
        </header>
        <div className="notice" role="status" data-testid="duplicate-loading">
          <strong>Opening the source run for duplication…</strong>{" "}
          The editor stays closed until the source run&rsquo;s exact specification
          and identity have loaded.
          <div className="field-row" style={{ marginTop: 10 }}>
            <button data-testid="duplicate-abandon" onClick={startNewResearchInstead}>
              Start new research instead
            </button>
          </div>
        </div>
      </main>
    );
  }

  // A missing/foreign source is a safe stop, never a silent unlinked draft.
  if (duplicate.phase === "unavailable") {
    return (
      <main>
        <header className="page-header">
          <div>
            <p className="page-kicker">Guided research</p>
            <h1>Research Studio</h1>
          </div>
        </header>
        <div className="actionable-error" role="alert" data-testid="duplicate-error">
          <strong>That run could not be opened as a draft.</strong>
          <span>
            It may belong to another workspace or may have been removed. Nothing
            was copied and no draft was created.
          </span>
          <div className="field-row" style={{ marginTop: 10 }}>
            <button
              className="primary"
              data-testid="duplicate-start-new"
              onClick={startNewResearchInstead}
            >
              Start new research instead
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main>
      <header className="page-header">
        <div>
          <p className="page-kicker">Guided research</p>
          <h1>Research Studio</h1>
          <p className="page-lede">
            Describe a rule in plain language, refine the exact specification, then run
            the robustness audit. Nothing runs until you review and confirm.
          </p>
        </div>
      </header>

      {parse && (
        <div
          className="notice"
          data-testid="briefing-provenance"
          data-fallback-code={parse.generation.fallback_code ?? undefined}
          data-provider-used={parse.generation.ai_used ? "true" : "false"}
        >
          <strong>Draft ready for review.</strong>{" "}Every default is labeled on the
          cards, and material fields are never guessed. How drafts are generated is
          documented in Methodology.
        </div>
      )}

      {requestError && (
        <div className="actionable-error" role="alert" data-testid="request-error"
          ref={requestErrorRef} tabIndex={-1}>
          <strong>{requestError.userMessage}</strong>
          <span>No strategy was submitted.</span>
          {/* Being signed out is not a fault, and answering it with a reference code
              and nothing to press treats it like one. The draft is already saved
              locally, so the honest offer is the door, right here. */}
          {isSignedOutError(requestError) ? (
            <a className="btn-link primary" href="/api/ql/auth/google/start"
              data-testid="request-error-sign-in">
              Continue with Google
            </a>
          ) : requestError.reference ? (
            <span className="error-ref">Ref: {requestError.reference}</span>
          ) : null}
        </div>
      )}

      {linkedSource && (
        <div className="notice" role="status" data-testid="duplicate-source">
          <strong>Editing a duplicate of “{linkedSource.title}”.</strong>{" "}
          The source run and its evidence stay unchanged. This editable copy will become a
          new run only after you review and confirm it, recorded as an explicit
          variation or rerun of the source. {" "}
          <Link href={`/runs/${linkedSource.runId}`}>Open the source run</Link>
        </div>
      )}

      {lineageRefusal && (
        <div
          className="actionable-error"
          role="alert"
          data-testid="lineage-refusal"
          data-code={lineageRefusal.code}
        >
          <strong>The linked run was refused; nothing was created.</strong>
          <span>
            {lineageRefusal.message} Your draft, its reviewed inputs, and its link
            to the source run are unchanged.
          </span>
          <span className="error-ref">Ref: {lineageRefusal.code}</span>
        </div>
      )}

      {stage === "input" && savedDraft && (
        <div className="studio-saved-draft" data-testid="saved-studio-draft">
          <div>
            <span className="eyebrow">Saved research draft</span>
            <strong>{savedDraft.spec.meta.name}</strong>
            <small>
              Last saved {new Date(savedDraft.saved_at).toLocaleString("en-US")} · no results were run
            </small>
          </div>
          <div className="field-row">
            <button className="primary" onClick={resumeSavedDraft}>Resume draft</button>
            <button onClick={discardSavedDraft}>Discard</button>
          </div>
        </div>
      )}

      <ZoneHeading index="01" title="Hypothesis" hint="Plain language in, precise rules out" />
      <div className="card">
        <div className="field">
          <label htmlFor="hypothesis">Your hypothesis, in plain language</label>
          <textarea
            id="hypothesis" rows={3} value={hypothesis}
            placeholder="e.g., own SPY when it's above its 200-day average, otherwise cash, with realistic costs"
            onChange={(e) => setHypothesis(e.target.value)}
          />
        </div>
        <button className="primary" onClick={submitHypothesis} disabled={busy}>
          Draft rule cards
        </button>
      </div>

      {templates.length > 0 && stage === "input" && !pendingDraft && (
        <section aria-labelledby="template-gallery-h" data-testid="template-gallery">
          <h2 id="template-gallery-h" style={{ fontSize: "1.05rem" }}>
            Or start from a sample strategy
          </h2>
          <p style={{ fontSize: "0.88rem", color: "var(--ink-soft)", marginTop: 0 }}>
            Sample strategies are starting points you edit and confirm — nothing runs until
            you review the summary. They open on the bundled sample series; switch to your
            own sealed dataset in the Research data card.
          </p>
          <div className="card-grid">
            {templates.map((t) => (
              <div className="card" key={t.meta.name}>
                <h3>{t.meta.name}</h3>
                {instrumentDescriptor(t.universe.symbol) && (
                  <p style={{ fontSize: "0.8rem", color: "var(--ink-faint)", margin: "2px 0 4px" }}>
                    {instrumentDescriptor(t.universe.symbol)}
                  </p>
                )}
                <p style={{ fontSize: "0.88rem", color: "var(--ink-soft)" }}>
                  {t.rule.type === "price_vs_ma"
                    ? `Long ${t.universe.symbol} when close > ${t.rule.ma_days}-day SMA, else cash.`
                    : `Long ${t.universe.symbol} when ${t.rule.fast_ma_days}/${t.rule.ma_days}-day SMAs cross, else cash.`}{" "}
                  {t.data.range.start} → {t.data.range.end}.
                </p>
                <button onClick={() => applyTemplate(t)}>Open as editable cards</button>
              </div>
            ))}
          </div>
        </section>
      )}

      {pendingDraft && (
        <div className="card" data-testid="overwrite-guard">
          <div className="notice warn">
            <strong>You have edited the current rule cards.</strong>{" "}Drafting from the new
            hypothesis would replace those edits. Nothing has been changed yet.
          </div>
          <div className="field-row">
            <button className="primary"
              onClick={() => adoptSpec(pendingDraft.draft, pendingDraft.defaults)}>
              Replace my edited cards with the new draft
            </button>
            <button onClick={() => setPendingDraft(null)}>Keep my edited cards</button>
          </div>
        </div>
      )}

      {stage === "blocked" && parse && (
        <div className="card" data-testid="blocked">
          <div className={parse.status === "advice_deflection" ? "notice warn" : "notice"}>
            <strong>
              {parse.status === "advice_deflection" ? "QuantLens doesn't give advice." : "Not supported in this release — here's the honest boundary."}
            </strong>
            <p>{parse.message}</p>
          </div>
          <p style={{ fontSize: "0.9rem", color: "var(--ink-soft)" }}>{parse.supported_scope}</p>
          {parse.correction?.template && (
            <div className="field-row" style={{ alignItems: "center" }}>
              <button
                className="primary"
                onClick={() => {
                  const template = parse.correction!.template as StrategySpec;
                  setParse(null);
                  if (dirty && spec) {
                    setPendingDraft({
                      draft: template,
                      defaults: ["rule.ma_days", "costs.commission_bps", "costs.slippage_bps",
                        "benchmark", "data.range", "validation.is_oos_split.oos_fraction",
                        "validation.sensitivity.grid.ma_days", "validation.cost_stress.multipliers"],
                    });
                  } else {
                    adoptSpec(template,
                      ["rule.ma_days", "costs.commission_bps", "costs.slippage_bps",
                        "benchmark", "data.range", "validation.is_oos_split.oos_fraction",
                        "validation.sensitivity.grid.ma_days", "validation.cost_stress.multipliers"]);
                  }
                }}
              >
                Open the nearest supported template
              </button>
              <button
                onClick={() => { logEvent("notify_me", { category: parse.category }); setNotifyAck(true); }}
                disabled={notifyAck}
              >
                {notifyAck ? "Request noted in this workspace" : parse.correction.notify_option}
              </button>
            </div>
          )}
        </div>
      )}

      {stage === "clarify" && (
        <div className="card" data-testid="clarify">
          <h2 style={{ marginTop: 0 }}>A few questions before anything is drafted</h2>
          <p style={{ fontSize: "0.9rem", color: "var(--ink-soft)" }}>
            Material fields (ETF, rule shape, windows) block compute until you answer them —
            they are never invented. Date range and costs show their defaults; keeping them
            is your explicit choice.{spec ? " Your other card edits are preserved." : ""}
          </p>
          <div className="field">
            <label htmlFor="c-symbol">Which single supported ETF should this test?</label>
            <select id="c-symbol" value={cSymbol} onChange={(e) => setCSymbol(e.target.value)}>
              <option value="" disabled>Choose an ETF…</option>
              {universe.map((u) => (
                <option key={u.symbol} value={u.symbol}>{u.symbol} — {u.name}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="c-ruletype">Which moving-average rule did you mean?</label>
            <select id="c-ruletype" value={cRuleType}
              onChange={(e) => setCRuleType(e.target.value as "price_vs_ma" | "ma_crossover")}>
              <option value="" disabled>Choose a rule shape…</option>
              <option value="price_vs_ma">Price above an N-day average → long, else cash</option>
              <option value="ma_crossover">Fast MA above slow MA → long, else cash</option>
            </select>
          </div>
          <div className="field-row">
            {cRuleType === "ma_crossover" && (
              <div className="field">
                <label htmlFor="c-fast">Fast MA (days)</label>
                <input id="c-fast" type="number" min={2} max={400} value={cFast}
                  onChange={(e) => setCFast(e.target.value)} />
              </div>
            )}
            <div className="field">
              <label htmlFor="c-slow">{cRuleType === "ma_crossover" ? "Slow MA (days)" : "MA window (days)"}</label>
              <input id="c-slow" type="number" min={2} max={400} value={cSlow}
                onChange={(e) => setCSlow(e.target.value)} />
            </div>
          </div>
          <div className="field-row">
            <div className="field">
              <label htmlFor="c-start">Start (default 2005-01-01)</label>
              <input id="c-start" type="date" value={cStart} onChange={(e) => setCStart(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="c-end">End (default 2024-12-31)</label>
              <input id="c-end" type="date" value={cEnd} onChange={(e) => setCEnd(e.target.value)} />
            </div>
          </div>
          <div className="field-row">
            <div className="field">
              <label htmlFor="c-comm">Commission bps (default 1)</label>
              <input id="c-comm" type="number" min={0} max={100} step={0.5} value={cComm}
                onChange={(e) => setCComm(Number(e.target.value))} />
            </div>
            <div className="field">
              <label htmlFor="c-slip">Slippage bps (default 5)</label>
              <input id="c-slip" type="number" min={0} max={100} step={0.5} value={cSlip}
                onChange={(e) => setCSlip(Number(e.target.value))} />
            </div>
          </div>
          <button className="primary" onClick={submitClarify}
            disabled={!cSymbol || !cRuleType || !cSlow || (cRuleType === "ma_crossover" && !cFast)}>
            Update the rule cards
          </button>
        </div>
      )}

      {stage === "cards" && spec && (
        <section data-testid="cards">
          <div className="notice" role="status">
            <strong>This spec has not been run.</strong>{" "}No performance exists or is shown
            until you confirm the research summary and the audit completes.
          </div>

          <ZoneHeading index="02" title="Strategy specification"
            hint={specDescriptor ?? undefined} />
          <div className="card" style={{ marginBottom: 13 }}>
            <div className="field" style={{ margin: 0, maxWidth: 520 }}>
              <label htmlFor="research-name">Research name</label>
              <input
                id="research-name"
                value={spec.meta.name}
                maxLength={120}
                onChange={(e) => {
                  const value = e.target.value;
                  onEdit("meta.name", (s) => ({ ...s, meta: { ...s.meta, name: value } }));
                }}
                onBlur={(e) => {
                  const cleaned = normalizeDisplayName(e.target.value);
                  if (cleaned && cleaned !== spec.meta.name) {
                    onEdit("meta.name", (s) => ({ ...s, meta: { ...s.meta, name: cleaned } }));
                  }
                }}
              />
              <small style={{ color: "var(--ink-faint)" }}>
                Names this run everywhere: the run list, the report, and exports.
              </small>
            </div>
          </div>
          <RuleCards
            spec={spec} defaultFields={defaultFields} universe={universe} datasets={datasets}
            onEdit={onEdit} zone="strategy"
          />

          <ZoneHeading index="03" title="Run setup & robustness"
            hint="Execution, costs, and the checks that try to break the idea" />
          <div className="card rigor-card" data-testid="research-purpose">
            <h3 style={{ marginTop: 0 }}>Research purpose</h3>
            {linkedSource && (
              <p className="workspace-meta" data-testid="linked-purpose-note" style={{ marginTop: 0 }}>
                Locked for this linked duplicate — a linked run keeps the source
                run&rsquo;s research purpose and validation rigor.
              </p>
            )}
            <div className="rigor-options" role="radiogroup" aria-label="Research purpose">
              <label className={`rigor-option${researchMode === "formal" ? " selected" : ""}${linkedSource ? " disabled" : ""}`}>
                <input
                  type="radio"
                  name="research-purpose"
                  value="formal"
                  aria-label="Formal research purpose"
                  checked={researchMode === "formal"}
                  disabled={linkedSource !== null}
                  onChange={() => choosePurpose("formal")}
                />
                <span>
                  <strong>Formal research</strong>
                  <small>
                    The formal evidence and audit path. Produces sealed
                    formal-research evidence and uses the formal run allowance.
                  </small>
                </span>
              </label>
              <label className={`rigor-option${researchMode === "sandbox" ? " selected" : ""}${linkedSource ? " disabled" : ""}`}>
                <input
                  type="radio"
                  name="research-purpose"
                  value="sandbox"
                  aria-label="Sandbox test purpose"
                  checked={researchMode === "sandbox"}
                  disabled={linkedSource !== null}
                  onChange={() => choosePurpose("sandbox")}
                />
                <span>
                  <strong>Sandbox test</strong>
                  <small>
                    An iterative test run. Produces non-formal test evidence only,
                    from a separate sandbox allowance, always under the Standard
                    audit. Sandbox tests never access the Strict validation final
                    holdout.
                  </small>
                </span>
              </label>
            </div>
          </div>
          <div className="card rigor-card" data-testid="validation-rigor">
            <h3 style={{ marginTop: 0 }}>Validation rigor</h3>
            <div className="rigor-options" role="radiogroup" aria-label="Validation rigor">
              <label className={`rigor-option${batteryProfile === "battery-v2" ? " selected" : ""}${researchMode === "sandbox" || linkedSource ? " disabled" : ""}`}>
                <input
                  type="radio"
                  name="validation-rigor"
                  value="battery-v2"
                  checked={batteryProfile === "battery-v2"}
                  disabled={researchMode === "sandbox" || linkedSource !== null}
                  onChange={() => { setBatteryProfile("battery-v2"); invalidateConfirmation(); }}
                />
                <span>
                  <strong>Strict validation <em className="chip default">Recommended</em></strong>
                  <small>
                    Locks your rule before anything runs, evaluates it across expanding
                    walk-forward windows with no parameter tuning, then spends a one-time
                    final holdout exactly once at base costs. The holdout is never
                    re-read or re-executed; a later identical study can only reference
                    the sealed result.
                  </small>
                  {researchMode === "sandbox" && (
                    <small data-testid="strict-sandbox-note">
                      <strong>Not available for sandbox tests</strong> — Strict
                      validation is reserved for formal research.
                    </small>
                  )}
                </span>
              </label>
              <label className={`rigor-option${batteryProfile === "battery-v1" ? " selected" : ""}${linkedSource ? " disabled" : ""}`}>
                <input
                  type="radio"
                  name="validation-rigor"
                  value="battery-v1"
                  checked={batteryProfile === "battery-v1"}
                  disabled={linkedSource !== null}
                  onChange={() => { setBatteryProfile("battery-v1"); invalidateConfirmation(); }}
                />
                <span>
                  <strong>Standard audit</strong>
                  <small>
                    The original split audit: an in-sample sensitivity window, one
                    held-out estimate, and preregistered cost counterfactuals.
                  </small>
                </span>
              </label>
            </div>
          </div>
          {linkedSource && (
            <div className="card rigor-card" data-testid="lineage-relationship">
              <h3 style={{ marginTop: 0 }}>Relationship to the source run</h3>
              <p style={{ fontSize: "0.88rem", color: "var(--ink-soft)", marginTop: 0 }}>
                A linked duplicate records an explicit relationship to
                “{linkedSource.title}”. QuantLens checks the choice against the two
                exact specifications and refuses a mismatch — it never guesses.
              </p>
              <div className="rigor-options" role="radiogroup" aria-label="Relationship to the source run">
                <label className={`rigor-option${lineageRelationship === "variation" ? " selected" : ""}`}>
                  <input
                    type="radio"
                    name="lineage-relationship"
                    value="variation"
                    checked={lineageRelationship === "variation"}
                    onChange={() => setLineageRelationship("variation")}
                  />
                  <span>
                    <strong>Variation</strong>
                    <small>
                      The research assumptions changed. This run tests a different
                      idea inside the same experiment family.
                    </small>
                  </span>
                </label>
                <label className={`rigor-option${lineageRelationship === "rerun" ? " selected" : ""}`}>
                  <input
                    type="radio"
                    name="lineage-relationship"
                    value="rerun"
                    checked={lineageRelationship === "rerun"}
                    onChange={() => setLineageRelationship("rerun")}
                  />
                  <span>
                    <strong>Rerun</strong>
                    <small>
                      The research assumptions are intentionally unchanged. This run
                      repeats the source study exactly; only the display name may
                      differ.
                    </small>
                  </span>
                </label>
              </div>
            </div>
          )}
          <RuleCards
            spec={spec} defaultFields={defaultFields} universe={universe} datasets={datasets}
            onEdit={onEdit} zone="robustness"
            strictProfile={batteryProfile === "battery-v2"}
          />

          {errors.length > 0 && (
            <div className="notice bad" data-testid="errors">
              <strong>This spec can&rsquo;t run yet:</strong>
              <ul>
                {errors.map((e, i) => (
                  <li key={i}>
                    {e.message}{" "}
                    {e.suggestion && <em>{e.suggestion}</em>}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="studio-action-bar" data-testid="studio-action-bar">
            <div className="studio-save-state" role="status">
              <span>{lastSavedAt ? "Draft autosaved locally" : "Sample ready to review"}</span>
              <small>
                {lastSavedAt
                  ? `Saved ${new Date(lastSavedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`
                  : "No performance exists until the audit completes"}
              </small>
            </div>
            <div className="studio-action-buttons">
              <button onClick={() => { if (spec) setLastSavedAt(writeDraft()); }}>
                Save draft
              </button>
              <button onClick={() => onNotWhatIMeant("all")}>Revisit questions</button>
              <button onClick={() => (yamlOpen ? setYamlOpen(false) : openYaml())}>
                {yamlOpen ? "Hide advanced YAML view" : "Advanced: view as YAML"}
              </button>
              <button
                className="primary"
                onClick={reviewAndConfirm}
                disabled={busy}
                title="Validates the spec and shows the research preflight before confirmation"
              >
                Review &amp; run research
              </button>
            </div>
          </div>

          {preflight && (
            <section
              className="card preflight-panel"
              data-testid="research-preflight"
              aria-labelledby="preflight-title"
              tabIndex={-1}
              ref={preflightRef}
            >
              <div className="preflight-head">
                <h3 id="preflight-title" style={{ margin: 0 }}>Research preflight</h3>
                <span
                  className={`chip ${preflight.status === "blocked" ? "warn" : "default"}`}
                  data-testid="preflight-status"
                >
                  {preflight.status === "blocked"
                    ? "Blocked"
                    : preflight.status === "ready_with_warnings"
                      ? "Ready — review warnings"
                      : "Ready"}
                </span>
                <span className="chip">{PURPOSE_LABELS[researchMode]}</span>
              </div>
              {preflightNotice && (
                <div className="notice warn" role="alert" data-testid="preflight-refreshed">
                  <strong>Preflight refreshed.</strong>{" "}{preflightNotice}
                </div>
              )}
              {preflight.blockers.map((issue) => (
                <div
                  className="notice bad preflight-issue"
                  key={issue.id}
                  data-testid={`preflight-blocker-${issue.id}`}
                >
                  <strong>{issue.message}</strong>
                  <span>{issue.suggestion}</span>
                </div>
              ))}
              {preflight.warnings.map((issue) => (
                <div
                  className="notice warn preflight-issue"
                  key={issue.id}
                  data-testid={`preflight-warning-${issue.id}`}
                >
                  <strong>{issue.message}</strong>
                  <span>{issue.suggestion}</span>
                </div>
              ))}
              {preflight.can_run && (
                <dl className="preflight-facts" data-testid="preflight-facts">
                  <div>
                    <dt>Data</dt>
                    <dd>
                      {/* Follows the bound dataset's basis: a CC BY series is
                          stamped USER_UPLOADED, so on the label alone the preflight
                          credited the reader for bytes QuantLens supplied. */}
                      {dataSourceLabel(String(preflight.data.label ?? "SYNTHETIC"),
                        boundDataset?.provenance?.price_adjustment)} ·{" "}
                      {String(preflight.plan.actual_bars ?? "—")} sessions
                      {preflight.data.returned_range?.start
                        ? ` · ${sessionDate(String(preflight.data.returned_range.start))} → ${sessionDate(String(preflight.data.returned_range.end ?? ""))}`
                        : ""}
                      {typeof preflight.data.missing_business_days === "number"
                        ? ` · ${preflight.data.missing_business_days} missing business days`
                        : ""}
                    </dd>
                  </div>
                  <div>
                    <dt>Validation plan</dt>
                    <dd>
                      {batteryProfile === "battery-v2"
                        ? `${String(preflight.plan.development_bars ?? "—")} development bars · `
                          + `${String(preflight.plan.final_holdout_bars ?? "—")} final-holdout bars · `
                          + `${String(preflight.plan.expected_fold_count ?? "—")} walk-forward folds · no parameter selection`
                        : `${String(preflight.plan.in_sample_bars ?? "—")} in-sample bars `
                          + `(${String(preflight.plan.in_sample_evaluation_bars ?? "—")} evaluated after warmup) · `
                          + `${String(preflight.plan.out_of_sample_bars ?? "—")} out-of-sample bars`}
                    </dd>
                  </div>
                  {preflight.checks.length > 0 && (
                    <div>
                      <dt>Checks</dt>
                      <dd>
                        {preflight.checks.map((check) => (
                          <span className="chip default" key={check.id} style={{ marginRight: 6 }}>
                            {check.label}
                          </span>
                        ))}
                      </dd>
                    </div>
                  )}
                </dl>
              )}
              <p className="workspace-meta" style={{ margin: "10px 0 0" }}>
                Preflight only verifies that the pinned data can execute the declared
                validation plan. It computes no performance and says nothing about
                investment quality.
              </p>
              {preflight.can_run && (
                <div className="field-row" style={{ marginTop: 12 }}>
                  <button
                    ref={confirmTriggerRef}
                    type="button"
                    className="primary"
                    data-testid="preflight-continue"
                    onClick={continueToConfirmation}
                    disabled={busy || lineageChoiceMissing}
                  >
                    Continue to confirmation
                  </button>
                  {lineageChoiceMissing ? (
                    <span className="workspace-meta" data-testid="lineage-choice-hint">
                      Choose whether this linked run is a variation or a rerun of
                      the source before confirming.
                    </span>
                  ) : (
                    <span className="workspace-meta">
                      Nothing runs until you confirm the research summary.
                    </span>
                  )}
                </div>
              )}
            </section>
          )}

          {yamlOpen && (
            <div className="card" data-testid="yaml-view">
              <h3>Advanced YAML view <span className="chip">lossless with the cards</span></h3>
              <textarea
                className="yaml" aria-label="Strategy spec as YAML" value={yamlText}
                onChange={(e) => { setYamlText(e.target.value); setYamlConflict(false); }}
              />
              {yamlError && <div className="notice bad" data-testid="yaml-error">{yamlError}</div>}
              {yamlServerErrors.length > 0 && (
                <div className="notice bad" data-testid="yaml-server-errors">
                  <strong>This YAML doesn&rsquo;t validate; the cards were not changed:</strong>
                  <ul>
                    {yamlServerErrors.map((e, i) => (
                      <li key={i}>
                        {e.message}{" "}
                        {e.suggestion && <em>{e.suggestion}</em>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {yamlConflict ? (
                <div className="notice warn" data-testid="yaml-conflict">
                  <strong>The cards changed after this YAML view was opened.</strong>{" "}
                  Applying it would overwrite those newer edits.
                  <div className="field-row" style={{ marginTop: 8 }}>
                    <button onClick={openYaml}>Reload YAML from the current cards</button>
                    <button className="primary" onClick={() => applyYaml(true)}>
                      Overwrite the cards with this YAML anyway
                    </button>
                  </div>
                </div>
              ) : (
                <button onClick={() => applyYaml(false)} disabled={busy}>Apply YAML to the cards</button>
              )}
            </div>
          )}
        </section>
      )}

      {confirmOpen && restatement && spec && (
        <div className="dialog-backdrop">
        <div ref={confirmDialogRef} className="card confirm-dialog" role="dialog"
          aria-modal="true" aria-labelledby="confirm-title" data-testid="confirm">
          <h2 id="confirm-title" style={{ marginTop: 0 }}>Review before running</h2>
          <div className="audit-receipt" style={{ marginBottom: 12 }}>
            <dl>
              <div>
                <dt>Instrument</dt>
                <dd>{specDescriptor ?? spec.universe.symbol}</dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd>{spec.rule.type === "price_vs_ma"
                  ? `Long when close > ${spec.rule.ma_days}-day SMA, else cash`
                  : `Long when ${spec.rule.fast_ma_days}-day SMA > ${spec.rule.ma_days}-day SMA, else cash`}</dd>
              </div>
              <div>
                <dt>Data</dt>
                <dd>
                  {dataSourceLabel(sourceKindToDataLabel(spec.data.source?.kind),
                    boundDataset?.provenance?.price_adjustment)} ·{" "}
                  {sessionDate(spec.data.range.start)} → {sessionDate(spec.data.range.end)}
                </dd>
              </div>
              <div>
                <dt>Execution</dt>
                <dd>Decide at each close · fill at the next open · long/flat only</dd>
              </div>
              <div>
                <dt>Return basis</dt>
                <dd data-testid="confirm-return-basis">{returnBasis.label}</dd>
              </div>
              <div>
                <dt>Cash &amp; Sharpe</dt>
                <dd>{CURRENT_CASH_ASSUMPTION_LABEL}</dd>
              </div>
              <div>
                <dt>Costs</dt>
                <dd>{spec.costs.commission_bps} bps commission + {spec.costs.slippage_bps} bps slippage per fill</dd>
              </div>
              <div>
                <dt>Purpose</dt>
                <dd data-testid="confirm-purpose">
                  <strong>{PURPOSE_LABELS[researchMode]}</strong>
                  {researchMode === "sandbox"
                    ? " — non-formal test evidence only, from the separate sandbox allowance"
                    : " — sealed formal-research evidence from the formal run allowance"}
                </dd>
              </div>
              <div>
                <dt>Validation rigor</dt>
                <dd data-testid="confirm-rigor">
                  <strong>{RIGOR_LABELS[batteryProfile]}</strong>
                  {batteryProfile === "battery-v2"
                    ? " — locked rule, walk-forward development, development-only cost "
                      + "stress, one-time final holdout evaluated at base costs only"
                    : " — in-sample sensitivity window, held-out estimate, preregistered cost counterfactuals"}
                </dd>
              </div>
              <div>
                <dt>Validation plan</dt>
                <dd>
                  {Math.round(spec.validation.is_oos_split.oos_fraction * 100)}%{" "}
                  {batteryProfile === "battery-v2" ? "single-use final holdout" : "held out-of-sample"} ·
                  cost stress ×{spec.validation.cost_stress.multipliers.join(", ×")} ·
                  benchmark {benchSymbol}
                </dd>
              </div>
              {linkedSource && lineageRelationship && (
                <div>
                  <dt>Linked to source</dt>
                  <dd data-testid="confirm-lineage">
                    <strong>{lineageRelationship === "variation" ? "Variation" : "Rerun"}</strong>
                    {" "}of “{linkedSource.title}” · run {linkedSource.runId}
                  </dd>
                </div>
              )}
            </dl>
          </div>
          {spec.data.source?.kind === "user_provided" && (
            <div className="notice warn" style={{ marginTop: 0 }}>
              This run uses your sealed dataset. It is integrity-checked; its source
              accuracy is not independently authenticated.
            </div>
          )}
          <div className="notice warn" style={{ marginTop: 0 }} data-testid="confirm-return-assumptions">
            <strong>Performance boundary.</strong>{" "}{returnBasis.note}{" "}
            {CURRENT_CASH_ASSUMPTION_NOTE}
          </div>
          {spec.data.source?.kind === "licensed_provider" && (() => {
            const bound = datasets.find(
              (item) => item.dataset_id === spec.data.source?.dataset_id);
            return (
              <div className="notice" style={{ marginTop: 0 }} data-testid="confirm-licensed-notice">
                This run uses sealed licensed-provider data. Use and display follow the
                provider contract
                {bound?.provenance?.rights?.use ? ` (${bound.provenance.rights.use})` : ""}.
              </div>
            );
          })()}
          <details open className="drawer report-summary-drawer">
            <summary>Exact confirmation statement (sealed with the run)</summary>
            <div className="drawer-body">
              <div className="restate" style={{ fontSize: "0.88rem" }}>{restatement}</div>
            </div>
          </details>
          <details className="drawer">
            <summary>Technical receipt</summary>
            <div className="drawer-body">
              <p className="workspace-meta" style={{ margin: 0 }} data-testid="confirm-protocol">
                Validation protocol <code>{batteryProfile}</code>
                {batteryProfileHash ? <>{" "}· profile <code>{batteryProfileHash.slice(0, 23)}…</code></> : null}
              </p>
            </div>
          </details>
          <div style={{ margin: "12px 0" }}>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: "0.95rem" }}>
              <input
                type="checkbox" checked={confirmChecked}
                onChange={(e) => setConfirmChecked(e.target.checked)}
                style={{ marginTop: 4 }}
              />
              <span>
                This summary matches what I want to test. I understand the run
                produces {researchMode === "sandbox"
                  ? "non-formal test evidence"
                  : "research evidence"}, not advice or a trade signal.
              </span>
            </label>
          </div>
          {preflight !== null && preflight.warnings.length > 0 && (
            <div data-testid="confirm-preflight-warnings" style={{ margin: "0 0 12px" }}>
              {preflight.warnings.map((issue) => (
                <div className="notice warn preflight-issue" key={issue.id}>
                  <strong>{issue.message}</strong>
                  <span>{issue.suggestion}</span>
                </div>
              ))}
              <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: "0.95rem", marginTop: 8 }}>
                <input
                  type="checkbox"
                  checked={warningsAck}
                  data-testid="preflight-ack"
                  onChange={(e) => setWarningsAck(e.target.checked)}
                  style={{ marginTop: 4 }}
                />
                <span>I reviewed the current preflight warnings.</span>
              </label>
            </div>
          )}
          <div className="field-row">
            <button
              className="primary"
              onClick={runConfirmed}
              disabled={!confirmChecked || !preflightAcknowledged || busy}
            >
              Run research
            </button>
            <button onClick={() => setConfirmOpen(false)}>Keep editing</button>
          </div>
        </div>
        </div>
      )}
    </main>
  );
}
