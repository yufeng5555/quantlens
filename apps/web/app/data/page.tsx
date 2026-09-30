"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";

import { ApiRequestError, toSafeError } from "../lib/errors";
import { TOTAL_RETURN_ADJUSTMENT, instrumentDescriptor } from "../lib/labels";
import LicensedProviderPanel, { type MarketDataConfig } from "./LicensedProviderPanel";

const CANONICAL_FIELDS = ["date", "open", "high", "low", "close", "volume"] as const;
const REQUIRED_FIELDS = ["date", "open", "high", "low", "close"] as const;

/** How long an empty library keeps re-reading itself, and how often. Sized for the
 * signup seed: ~1.5s for one account, ~14s when ten sign in at once. */
const LIBRARY_RECHECK_INTERVAL_MS = 2000;
const LIBRARY_RECHECK_LIMIT = 9;

type CanonicalField = (typeof CANONICAL_FIELDS)[number];
type Phase = "idle" | "uploading" | "mapping" | "validating" | "review" | "sealing" | "sealed";

interface ImportConfig {
  accepted_formats: string[];
  max_upload_bytes: number;
  max_upload_mb: number;
  scope: string;
  required_fields: string[];
  optional_fields: string[];
  timezones: string[];
  parquet_status: string;
}

interface ImportIssue {
  code: string;
  severity: "blocking" | "warning";
  message: string;
}

interface ImportInspection {
  import_id: string;
  status: "inspected";
  source_format: "csv";
  source_size: number;
  source_sha256: string;
  row_count: number;
  columns: string[];
  source_column_count?: number;
  excluded_non_market_column_count?: number;
  redacted_extra_column_count?: number;
  suggested_mapping: Record<CanonicalField, string | null>;
  preview: Record<string, string | number | boolean | null>[];
  issues: ImportIssue[];
  limits: { max_bytes: number; max_rows: number; max_columns: number };
  privacy: string;
}

interface DatasetQuality {
  row_count: number;
  coverage: { start: string; end: string };
  missing_business_days: number;
  max_consecutive_missing: number;
  volume_policy: "mapped" | "filled_zero";
  price_min: number;
  price_max: number;
  blocking_issues: number;
  warnings: string[];
  missing_day_examples?: string[];
  zero_volume_ratio?: number;
  suspicious_price_jump_count?: number;
  suspicious_price_jump_examples?: string[];
  return_basis?: string;
  source_sha256?: string;
  normalized_sha256?: string;
  timezone?: string;
  prices_adjusted_attested?: boolean;
}

interface ValidationCheck {
  status: "ready" | "needs_review";
  label: string;
}

interface ValidationIssue {
  code: string;
  severity: "blocking" | "warning" | "info";
  message: string;
}

interface ValidatedQuality extends DatasetQuality {
  issues: ValidationIssue[];
  checks: Record<"schema" | "coverage" | "continuity" | "prices", ValidationCheck>;
  review_status: "ready_to_seal" | "review_required";
}

interface DatasetValidation {
  profile_hash: string;
  profile: Record<string, unknown>;
  quality: ValidatedQuality;
  can_seal: boolean;
  normalized_preview: Record<string, string | number | boolean | null>[];
}

interface ValidateResponse {
  import_id: string;
  status: "ready_to_seal" | "review_required";
  validation: DatasetValidation;
  provenance_notice: string;
}

/** One upload still sitting in quarantine, holding a slot. No filename is ever stored. */
interface OpenImport {
  import_id: string;
  status: string;
  created_at: string;
  updated_at: string;
  row_count: number;
  source_size: number;
  column_count: number;
  /** The validator ran. Says nothing about whether a human read the result. */
  validated: boolean;
  review_status: string | null;
}

interface OpenImportsResponse {
  imports: OpenImport[];
  open_imports: number;
  max_open_imports: number;
  remaining_import_slots: number;
}

interface DatasetRecord {
  dataset_id: string;
  display_name: string;
  symbol: string;
  status: "sealed";
  dataset_manifest_sha256: string;
  snapshot_id: string;
  snapshot_sha256: string;
  row_count: number;
  coverage: { start: string; end: string };
  quality: DatasetQuality;
  created_at: string;
  provenance: {
    data_label: "USER_UPLOADED" | "LICENSED_PROVIDER";
    notice?: string;
    timezone?: string;
    price_adjustment?: string;
    adjustment_mode?: string;
    source_sha256?: string;
    normalized_sha256?: string;
    logical_rows_sha256?: string;
    provider?: { provider_id: string; feed?: string; tier?: string };
    instrument?: {
      instrument_id: string;
      symbol: string;
      display_name: string;
      asset_class?: string;
      mic?: string;
      currency?: string;
    };
    rights?: { use?: string; retention?: string; required_attribution?: string };
  };
}

interface SealResponse {
  status: "sealed";
  dataset: DatasetRecord;
  idempotent: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Locale-stable digit grouping, matching the rest of the product's en-US pinning. */
function formatCount(value: number): string {
  return value.toLocaleString("en-US");
}

/** What the SERVER observed about this upload — never a claim about the reader. */
function importStateLabel(item: OpenImport): string {
  if (!item.validated) return "not yet validated";
  if (item.review_status === "ready_to_seal") return "validated, ready to seal";
  return "validated — findings need review";
}

function displayDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : `${date.toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    hour12: false, timeZone: "UTC",
  })} UTC`;
}

async function readApi<T>(response: Response): Promise<T> {
  const payload: unknown = await response.json().catch(() => null);
  if (response.ok && payload) return payload as T;
  const detail = payload && typeof payload === "object" && "detail" in payload
    ? (payload as { detail?: string | { code?: string; message?: string } }).detail
    : null;
  if (typeof detail === "string") {
    throw new ApiRequestError({ status: response.status, detailMessage: detail });
  }
  throw new ApiRequestError({
    status: response.status,
    code: detail?.code,
    detailMessage: detail?.message,
  });
}

function safeMessage(caught: unknown, fallback: string): string {
  const safe = toSafeError(caught, fallback);
  return safe.reference ? `${safe.userMessage} (Ref: ${safe.reference})` : safe.userMessage;
}

export default function DataWorkspace() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [config, setConfig] = useState<ImportConfig | null>(null);
  const [sourceTab, setSourceTab] = useState<"licensed" | "csv">("csv");
  const sourceTabChosenRef = useRef(false);
  const [marketData, setMarketData] = useState<MarketDataConfig | null>(null);
  const [datasets, setDatasets] = useState<DatasetRecord[]>([]);
  const [inspection, setInspection] = useState<ImportInspection | null>(null);
  const [validation, setValidation] = useState<DatasetValidation | null>(null);
  const [provenanceNotice, setProvenanceNotice] = useState("");
  const [acknowledgedWarnings, setAcknowledgedWarnings] = useState<string[]>([]);
  const [sealed, setSealed] = useState<DatasetRecord | null>(null);
  const [localName, setLocalName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [symbol, setSymbol] = useState("");
  const [timezone, setTimezone] = useState("America/New_York");
  const [mapping, setMapping] = useState<Record<CanonicalField, string>>({
    date: "", open: "", high: "", low: "", close: "", volume: "__zero__",
  });
  const [pricesAdjusted, setPricesAdjusted] = useState(false);
  const [rightsAttested, setRightsAttested] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [libraryError, setLibraryError] = useState<string | null>(null);
  const [libraryLoaded, setLibraryLoaded] = useState(false);
  const [libraryRechecks, setLibraryRechecks] = useState(0);
  const [seeding, setSeeding] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);
  const [seedCount, setSeedCount] = useState<number | null>(null);
  const [seedUnavailable, setSeedUnavailable] = useState<string[]>([]);
  const [openImports, setOpenImports] = useState<OpenImportsResponse | null>(null);
  const [openImportsStale, setOpenImportsStale] = useState(false);
  const [discarding, setDiscarding] = useState<string | null>(null);

  async function loadOpenImports() {
    try {
      const response = await fetch("/api/ql/dataset-imports");
      setOpenImports(await readApi<OpenImportsResponse>(response));
      setOpenImportsStale(false);
    } catch {
      // Keep the last known list rather than dropping the panel. Nulling it here
      // made a failed refresh silently remove every remaining upload, its id, and
      // its Discard button — the exact "no identifier left to act on" state this
      // panel exists to end. The list is marked stale instead, and says so.
      setOpenImportsStale(true);
    }
  }

  /** True while this page has a request of its own in flight against that import.
   *  Discarding mid-validate or mid-seal left the canvas on a spinner that could
   *  never resolve, because the request it was waiting on now refers to a
   *  settled row. The reader waits out the step they already started instead. */
  function isBusyWithImport(importId: string): boolean {
    return inspection?.import_id === importId
      && (phase === "validating" || phase === "sealing");
  }

  async function discardImport(importId: string) {
    setDiscarding(importId);
    try {
      const response = await fetch(`/api/ql/dataset-imports/${importId}`, {
        method: "DELETE",
      });
      await readApi<{ status: string }>(response);
      // The upload being discarded may be the one this page is mid-way through.
      // Use the full reset: a partial one left `pricesAdjusted`, `rightsAttested`
      // and `symbol` set, so the NEXT file arrived with the previous file's
      // rights attestation already ticked — a declaration the reader never made
      // about data the reader never declared it for.
      if (inspection?.import_id === importId) resetImport();
      setError(null);
      await loadOpenImports();
    } catch (reason) {
      setError(safeMessage(reason, "That upload could not be discarded."));
      // Whatever just happened, the list on screen is no longer trustworthy.
      await loadOpenImports();
    } finally {
      setDiscarding(null);
    }
  }

  async function loadBundledMarketData() {
    setSeeding(true);
    setSeedError(null);
    setSeedCount(null);
    setSeedUnavailable([]);
    try {
      const response = await fetch("/api/ql/datasets/bundle", { method: "POST" });
      const body = await readApi<{
        seeded: DatasetRecord[]; unavailable?: string[];
      }>(response);
      setSeedCount(body.seeded?.length ?? 0);
      // A series the server could not import is named rather than absorbed into a
      // clean-looking success. Reporting "nothing to do" over a partial failure is how
      // a reader ends up believing they hold data they do not have.
      setSeedUnavailable(body.unavailable ?? []);
      await loadLibrary();
    } catch (reason) {
      setSeedError(safeMessage(reason, "The bundled market data could not be imported."));
    } finally {
      setSeeding(false);
    }
  }

  async function loadLibrary() {
    try {
      const response = await fetch("/api/ql/datasets");
      const body = await readApi<{ datasets: DatasetRecord[] }>(response);
      setDatasets(body.datasets ?? []);
      setLibraryError(null);
    } catch (reason) {
      setLibraryError(safeMessage(reason, "The dataset library could not be loaded."));
    } finally {
      setLibraryLoaded(true);
    }
  }

  useEffect(() => {
    void (async () => {
      try {
        const response = await fetch("/api/ql/dataset-imports/config");
        const body = await readApi<ImportConfig>(response);
        setConfig(body);
        setTimezone(body.timezones.includes("America/New_York")
          ? "America/New_York" : body.timezones[0] ?? "UTC");
      } catch (reason) {
        setError(safeMessage(reason, "The import service could not be reached."));
      }
    })();
    void (async () => {
      try {
        const response = await fetch("/api/ql/market-data/config");
        const body = await readApi<MarketDataConfig>(response);
        setMarketData(body);
        // Default to the working path without hiding either one: licensed when the
        // provider is genuinely active, CSV otherwise. A user's explicit choice wins.
        if (!sourceTabChosenRef.current && body.status === "activated") {
          setSourceTab("licensed");
        }
      } catch {
        setMarketData({
          status: "not_configured",
          provider: null,
          daily_bars: false,
          message: "Provider readiness could not be checked. CSV import stays available.",
        });
      }
    })();
    void loadLibrary();
    // Read on mount, not just after an upload: the whole point is the uploads a
    // reload left behind, which this page previously had no way to know about.
    void loadOpenImports();
  }, []);

  // A new account's bundled series are sealed by a background task that starts only
  // after the sign-in response has been sent, so the first read of the library can
  // honestly come back empty for a few seconds. Re-read for a bounded while, or a
  // brand-new workspace sits there looking permanently empty until its owner happens
  // to reload the page.
  useEffect(() => {
    if (!libraryLoaded || libraryError || seeding) return;
    if (datasets.length > 0 || libraryRechecks >= LIBRARY_RECHECK_LIMIT) return;
    const timer = setTimeout(() => {
      setLibraryRechecks((count) => count + 1);
      void loadLibrary();
    }, LIBRARY_RECHECK_INTERVAL_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [libraryLoaded, libraryError, seeding, datasets.length, libraryRechecks]);

  // Only the bundle seeder writes the operator-attested total-return basis, so this
  // counts the licensed series already in the library without asking the server to
  // seed anything. Both the lede and the load button follow it: this page used to say
  // the bundle "is already sealed into this workspace" on the same screen as "No
  // sealed datasets yet", which is the seed window a new account actually lands in.
  const bundledCount = datasets.filter(
    (dataset) => dataset.provenance?.price_adjustment === TOTAL_RETURN_ADJUSTMENT,
  ).length;
  const bundlePresent = bundledCount > 0;
  const libraryRecheckPending =
    libraryLoaded && !libraryError && !seeding
    && datasets.length === 0 && libraryRechecks < LIBRARY_RECHECK_LIMIT;

  const requiredMapped = REQUIRED_FIELDS.every((field) => Boolean(mapping[field]));
  const reusedColumns = useMemo(() => {
    const used = REQUIRED_FIELDS.map((field) => mapping[field]).filter(Boolean);
    return new Set(used).size !== used.length;
  }, [mapping]);
  const validSymbol = /^[A-Z][A-Z0-9.]{0,9}$/.test(symbol.trim().toUpperCase());
  const readyToValidate = Boolean(
    inspection && displayName.trim() && displayName.trim().length <= 80 && validSymbol
    && requiredMapped && !reusedColumns && pricesAdjusted && rightsAttested,
  );
  const validationWarnings = validation?.quality.warnings ?? [];
  const allWarningsAcknowledged = validationWarnings.every((warning) =>
    acknowledgedWarnings.includes(warning));
  const readyToSeal = Boolean(validation?.can_seal && allWarningsAcknowledged);
  const excludedColumnCount = inspection?.excluded_non_market_column_count
    ?? inspection?.redacted_extra_column_count
    ?? 0;

  const visibleIssues = useMemo(() => {
    if (!inspection) return [];
    return inspection.issues.filter((issue) => {
      const match = /^MAP_(DATE|OPEN|HIGH|LOW|CLOSE)_REQUIRED$/.exec(issue.code);
      return !match || !mapping[match[1].toLowerCase() as CanonicalField];
    });
  }, [inspection, mapping]);

  function resetImport() {
    setPhase("idle");
    setInspection(null);
    setSealed(null);
    setValidation(null);
    setProvenanceNotice("");
    setAcknowledgedWarnings([]);
    setLocalName("");
    setDisplayName("");
    setSymbol("");
    setMapping({ date: "", open: "", high: "", low: "", close: "", volume: "__zero__" });
    setPricesAdjusted(false);
    setRightsAttested(false);
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  function invalidateValidation() {
    setValidation(null);
    setProvenanceNotice("");
    setAcknowledgedWarnings([]);
    setError(null);
    setPhase("mapping");
  }

  async function inspectFile(file: File) {
    setError(null);
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setError("Choose a plain UTF-8 CSV. XLSX, ZIP, and Parquet are not enabled in this release.");
      return;
    }
    if (config && file.size > config.max_upload_bytes) {
      setError(`This file is ${formatBytes(file.size)}; the current limit is ${config.max_upload_mb} MB.`);
      return;
    }
    setPhase("uploading");
    setLocalName(file.name);
    try {
      const response = await fetch("/api/ql/dataset-imports", {
        method: "POST",
        headers: { "Content-Type": "text/csv" },
        body: file,
      });
      const body = await readApi<ImportInspection>(response);
      const suggested = Object.fromEntries(CANONICAL_FIELDS.map((field) => [
        field, body.suggested_mapping[field] ?? (field === "volume" ? "__zero__" : ""),
      ])) as Record<CanonicalField, string>;
      setInspection(body);
      setValidation(null);
      setProvenanceNotice("");
      setAcknowledgedWarnings([]);
      setMapping(suggested);
      setDisplayName(file.name.replace(/\.csv$/i, "").replace(/[_-]+/g, " ").trim().slice(0, 80));
      setPhase("mapping");
      void loadOpenImports();
    } catch (reason) {
      setPhase("idle");
      setError(safeMessage(reason, "The CSV could not be inspected."));
      // A refusal for a full quarantine is exactly when the reader needs to see
      // what is holding the slots.
      void loadOpenImports();
    }
  }

  function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) void inspectFile(file);
  }

  function dropFile(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragActive(false);
    const file = event.dataTransfer.files?.[0];
    if (file) void inspectFile(file);
  }

  async function validateDataset() {
    if (!inspection || !readyToValidate) return;
    setPhase("validating");
    setError(null);
    try {
      const response = await fetch(`/api/ql/dataset-imports/${inspection.import_id}/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          symbol: symbol.trim().toUpperCase(),
          mapping,
          timezone,
          prices_adjusted: pricesAdjusted,
          rights_attested: rightsAttested,
        }),
      });
      const body = await readApi<ValidateResponse>(response);
      setValidation(body.validation);
      setProvenanceNotice(body.provenance_notice);
      setAcknowledgedWarnings([]);
      setPhase("review");
    } catch (reason) {
      setPhase("mapping");
      setError(safeMessage(reason, "The dataset could not be validated."));
    }
  }

  async function sealDataset() {
    if (!inspection || !validation || !readyToSeal) return;
    setPhase("sealing");
    setError(null);
    try {
      const response = await fetch(`/api/ql/dataset-imports/${inspection.import_id}/seal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: displayName.trim(),
          symbol: symbol.trim().toUpperCase(),
          mapping,
          timezone,
          prices_adjusted: pricesAdjusted,
          rights_attested: rightsAttested,
          confirmed_profile_hash: validation.profile_hash,
          acknowledged_warnings: acknowledgedWarnings,
        }),
      });
      const body = await readApi<SealResponse>(response);
      setSealed(body.dataset);
      setPhase("sealed");
      await loadLibrary();
      // Sealing settles the import, so it no longer holds a slot.
      void loadOpenImports();
    } catch (reason) {
      setPhase("review");
      setError(safeMessage(reason, "The dataset could not be sealed."));
    }
  }

  const activeStep = phase === "idle" || phase === "uploading" ? 1
    : phase === "mapping" ? 2
      : phase === "validating" || phase === "review" || phase === "sealing" ? 3 : 4;

  return (
    <main className="data-main">
      <header className="data-page-head">
        <div>
          <p className="data-kicker">Research data</p>
          <h1>Data Workspace</h1>
          {/* Follows the library rather than asserting the happy case. A new account
              reaches this page while its bundle is still being sealed, and the old
              sentence claimed the data was already here on the same screen that said
              the library was empty. */}
          <p className="data-lede" data-testid="data-lede">
            Use the bundled synthetic sample in Research Studio, or import a daily CSV
            that you are entitled to use. This release includes no real market data.
            A draft can never run a strategy.
          </p>
        </div>
        <span className="data-scope-chip">One symbol · daily bars</span>
      </header>

      <section className="data-byo" aria-labelledby="byo-heading" data-testid="bring-your-own-data">
        <p className="data-eyebrow">Before you start</p>
        <h2 id="byo-heading">Working with real market data</h2>
        <p className="data-byo-lede">
          The bundled series is <strong>synthetic, not market data</strong>. Its results
          describe only the fixture. Real market data and provider credentials are not
          included in this release. Importing your own file does not establish its
          accuracy or grant redistribution rights.
        </p>
        <details className="data-byo-how">
          <summary>How to import real daily bars</summary>
          <ol className="data-byo-steps">
            <li>
              <strong>Export daily bars you are entitled to use.</strong> Check your
              provider’s conditions. One symbol per file.
            </li>
            <li>
              <strong>Import it under “Upload CSV”.</strong> The file needs{" "}
              <code>date</code>, <code>open</code>, <code>high</code>, <code>low</code> and{" "}
              <code>close</code> columns; <code>volume</code> is optional. Up to 250,000 rows.
            </li>
            <li>
              <strong>Seal it.</strong> The importer normalizes every row, reports gaps and
              duplicates before you commit, and fingerprints the file. Runs bind to that
              fingerprint, so a result can always be traced back to the data behind it.
            </li>
          </ol>
          <p className="data-byo-note">
            QuantLens redistributes no one’s feed. You import data you already hold, under
            the terms you obtained it under — which is what keeps a personal or free data
            plan usable here, where a shared vendor feed would not be.
          </p>
        </details>
      </section>

      <div className="source-switch" role="tablist" aria-label="Data source">
        <button
          type="button"
          role="tab"
          aria-selected={sourceTab === "licensed"}
          onClick={() => { sourceTabChosenRef.current = true; setSourceTab("licensed"); }}
        >
          Licensed provider
          {marketData && marketData.status !== "activated" && (
            <span className="source-switch-state">Not active</span>
          )}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={sourceTab === "csv"}
          onClick={() => { sourceTabChosenRef.current = true; setSourceTab("csv"); }}
        >
          Upload CSV
        </button>
      </div>

      {sourceTab === "csv" && (
      <ol className="data-stepper" aria-label="Dataset import progress">
        {["Choose file", "Map & declare", "Review checks", "Sealed receipt"].map((label, index) => {
          const step = index + 1;
          return (
            <li key={label} className={step < activeStep ? "done" : step === activeStep ? "active" : ""}
              aria-current={step === activeStep ? "step" : undefined}>
              <span aria-hidden="true">{step < activeStep ? "✓" : step}</span>{label}
            </li>
          );
        })}
      </ol>
      )}

      {error && (
        <div className="data-error" role="alert">
          <strong>QuantLens stopped before creating a runnable dataset.</strong>
          <span>{error}</span>
        </div>
      )}

      {/* Uploads waiting in quarantine. This page used to track exactly one, in
          component state, so a reload stranded every earlier upload: still counted
          against the cap, still on the shared volume, and with no identifier left
          anywhere the reader could reach. Five of those locked BYOD entirely. */}
      {sourceTab === "csv" && openImports && openImports.imports.length > 0 && (
        <section className="data-pending" aria-labelledby="pending-imports-heading"
          data-testid="pending-imports">
          <div className="data-pending-head">
            <div>
              <p className="data-eyebrow">Waiting to be reviewed</p>
              <h2 id="pending-imports-heading">
                {openImports.open_imports} of {openImports.max_open_imports} upload
                {openImports.max_open_imports === 1 ? "" : " slots"} in use
              </h2>
            </div>
            <span className="data-muted">
              {openImports.remaining_import_slots === 0
                ? "No slots left — seal or discard one to upload again"
                : `${openImports.remaining_import_slots} left`}
            </span>
          </div>
          <p className="data-pending-note">
            These are CSVs you uploaded that were never sealed or discarded. Nothing
            here has been added to your library, and no filename was ever stored.
          </p>
          {openImportsStale && (
            <p className="data-pending-stale" role="status">
              This list could not be refreshed just now, so it may be out of date.
              Reload the page to check it.
            </p>
          )}
          <ul className="data-pending-list">
            {openImports.imports.map((item) => (
              <li key={item.import_id}>
                <div>
                  <code>{item.import_id}</code>
                  <span className="data-muted">
                    {formatCount(item.row_count)} rows ·{" "}
                    {item.column_count} columns · {formatBytes(item.source_size)} ·{" "}
                    {importStateLabel(item)} ·{" "}
                    uploaded {displayDate(item.created_at)}
                  </span>
                </div>
                {/* Row-scoped name, matching every other per-row action in this
                    product (runs, experiments, recent runs). Several buttons all
                    called "Discard" is a coin flip for anyone not using a mouse,
                    and this is the one that destroys data. */}
                <button type="button" className="data-pending-discard"
                  aria-label={`Discard upload ${item.import_id}`}
                  disabled={discarding !== null || isBusyWithImport(item.import_id)}
                  onClick={() => void discardImport(item.import_id)}>
                  {discarding === item.import_id ? "Discarding…" : "Discard"}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="data-layout">
        <section className="data-canvas" aria-labelledby="import-heading">
          {sourceTab === "licensed" && (
            <LicensedProviderPanel
              config={marketData}
              onDatasetSealed={() => void loadLibrary()}
            />
          )}
          {sourceTab === "csv" && phase === "idle" && (
            <div className="data-panel data-enter">
              <div className="data-panel-head">
                <div>
                  <p className="data-eyebrow">Step 1</p>
                  <h2 id="import-heading">Choose a source file</h2>
                </div>
                {config && <span className="data-muted">Up to {config.max_upload_mb} MB</span>}
              </div>
              <div className={`data-dropzone${dragActive ? " drag-active" : ""}`}
                onDragEnter={(event) => { event.preventDefault(); setDragActive(true); }}
                onDragOver={(event) => event.preventDefault()}
                onDragLeave={() => setDragActive(false)}
                onDrop={dropFile}>
                <div className="data-file-mark" aria-hidden="true">CSV</div>
                <h3>Drop a UTF-8 CSV here</h3>
                <p>or choose a file from this computer. Its filename is never sent or stored.</p>
                <input ref={inputRef} id="dataset-file" className="visually-hidden" type="file"
                  accept=".csv,text/csv" onChange={chooseFile} />
                <label htmlFor="dataset-file" className="data-file-button">Choose CSV</label>
              </div>
              <div className="data-format-note">
                <strong>Expected:</strong> one asset with session date, open, high, low and close;
                volume is optional. Intraday timestamps and unadjusted prices are rejected rather
                than interpreted silently.
              </div>
            </div>
          )}

          {sourceTab === "csv" && phase === "uploading" && (
            <div className="data-panel data-progress-panel" role="status" aria-live="polite">
              <span className="data-spinner" aria-hidden="true" />
              <div>
                <p className="data-eyebrow">Inspecting locally</p>
                <h2 id="import-heading">Reading structure and fingerprinting the file</h2>
                <p>{localName} stays quarantined and cannot be used by a strategy.</p>
              </div>
            </div>
          )}

          {sourceTab === "csv" && phase === "mapping" && inspection && (
            <div className="data-panel data-enter">
              <div className="data-panel-head">
                <div>
                  <p className="data-eyebrow">Step 2</p>
                  <h2 id="import-heading">Map, declare and validate</h2>
                </div>
                <button type="button" className="linkish" onClick={resetImport}>Choose another file</button>
              </div>

              <div className="data-file-summary" aria-label="Inspected file summary">
                <div><span>Local file</span><strong>{localName}</strong></div>
                <div><span>Rows</span><strong>{inspection.row_count.toLocaleString("en-US")}</strong></div>
                <div><span>Mapped-safe columns</span><strong>{inspection.columns.length} / {inspection.source_column_count ?? inspection.columns.length}</strong></div>
                <div><span>Size</span><strong>{formatBytes(inspection.source_size)}</strong></div>
                <div className="wide"><span>Integrity</span><strong>Integrity-checked — full fingerprint in the validation receipt</strong></div>
              </div>
              {excludedColumnCount > 0 && (
                <p className="data-profile-note" style={{ margin: "0 26px 18px" }}>
                  {excludedColumnCount} column(s) outside the supported date/OHLCV mapping allowlist were excluded from preview and mapping.
                </p>
              )}

              <section className="data-subsection" aria-labelledby="identity-heading">
                <div className="data-subhead">
                  <div><span className="data-index">01</span><h3 id="identity-heading">Dataset identity</h3></div>
                  <span className={displayName.trim() && validSymbol ? "data-state ready" : "data-state attention"}>
                    {displayName.trim() && validSymbol ? "Ready" : "Needs attention"}
                  </span>
                </div>
                <div className="data-field-grid two">
                  <div className="field">
                    <label htmlFor="dataset-name">Dataset name</label>
                    <input id="dataset-name" value={displayName} maxLength={80}
                      onChange={(event) => setDisplayName(event.target.value)}
                      aria-describedby="dataset-name-help" />
                    <small id="dataset-name-help">A private label for the library; the filename is not stored.</small>
                  </div>
                  <div className="field">
                    <label htmlFor="dataset-symbol">Symbol represented by every row</label>
                    <input id="dataset-symbol" value={symbol} maxLength={10}
                      placeholder="e.g. SPY" autoCapitalize="characters"
                      onChange={(event) => setSymbol(event.target.value.toUpperCase())}
                      aria-invalid={symbol.length > 0 && !validSymbol} />
                    <small>{symbol.length > 0 && !validSymbol
                      ? "Use 1–10 uppercase letters, numbers, or a dot."
                      : "QuantLens never infers a tradable symbol from the filename."}</small>
                  </div>
                </div>
              </section>

              <section className="data-subsection" aria-labelledby="mapping-heading">
                <div className="data-subhead">
                  <div><span className="data-index">02</span><h3 id="mapping-heading">Column mapping</h3></div>
                  <span className={requiredMapped && !reusedColumns ? "data-state ready" : "data-state attention"}>
                    {requiredMapped && !reusedColumns ? "Ready" : "Needs attention"}
                  </span>
                </div>
                <p className="data-help">Suggestions are editable. Required fields must map to different columns.</p>
                <div className="data-field-grid mapping">
                  {CANONICAL_FIELDS.map((field) => (
                    <div className="field" key={field}>
                      <label htmlFor={`map-${field}`}>
                        {field[0].toUpperCase() + field.slice(1)}
                        {field === "volume" ? <span className="data-optional"> optional</span> : null}
                      </label>
                      <select id={`map-${field}`} value={mapping[field]}
                        onChange={(event) => setMapping((current) => ({ ...current, [field]: event.target.value }))}>
                        {field === "volume" ? <option value="__zero__">No column — fill zero</option>
                          : <option value="">Choose a column…</option>}
                        {inspection.columns.map((column) => <option value={column} key={column}>{column}</option>)}
                      </select>
                    </div>
                  ))}
                </div>
                {reusedColumns && <p className="data-inline-error" role="alert">A required CSV column is mapped more than once.</p>}
              </section>

              <section className="data-subsection" aria-labelledby="declarations-heading">
                <div className="data-subhead">
                  <div><span className="data-index">03</span><h3 id="declarations-heading">Interpretation &amp; rights</h3></div>
                  <span className={pricesAdjusted && rightsAttested ? "data-state ready" : "data-state attention"}>
                    {pricesAdjusted && rightsAttested ? "Ready" : "Confirm both"}
                  </span>
                </div>
                <div className="field data-timezone-field">
                  <label htmlFor="dataset-timezone">Market timezone represented by session dates</label>
                  <select id="dataset-timezone" value={timezone}
                    onChange={(event) => setTimezone(event.target.value)}>
                    {(config?.timezones ?? ["America/New_York", "UTC"]).map((zone) =>
                      <option value={zone} key={zone}>{zone}</option>)}
                  </select>
                </div>
                <label className="data-check-row">
                  <input type="checkbox" checked={pricesAdjusted}
                    onChange={(event) => setPricesAdjusted(event.target.checked)} />
                  <span><strong>Prices are already split-adjusted.</strong>
                    <small>No transformation will be applied. Unadjusted prices require corporate-action metadata, which this release does not accept.</small></span>
                </label>
                <label className="data-check-row">
                  <input type="checkbox" checked={rightsAttested}
                    onChange={(event) => setRightsAttested(event.target.checked)} />
                  <span><strong>I am authorized to use this file for private analysis.</strong>
                    <small>QuantLens stores normalized local rows for your research and does not redistribute the raw upload.</small></span>
                </label>
              </section>

              <section className="data-subsection" aria-labelledby="preview-heading">
                <div className="data-subhead">
                  <div><span className="data-index">04</span><h3 id="preview-heading">Source preview</h3></div>
                  <span className="data-state neutral">First {inspection.preview.length} rows</span>
                </div>
                <div className="tablewrap data-preview-table" role="region" aria-label="CSV source preview" tabIndex={0}>
                  <table>
                    <thead><tr>{inspection.columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead>
                    <tbody>{inspection.preview.map((row, index) => (
                      <tr key={index}>{inspection.columns.map((column) =>
                        <td key={column}>{row[column] === null ? <span className="data-null">null</span> : String(row[column])}</td>)}</tr>
                    ))}</tbody>
                  </table>
                </div>
              </section>

              {visibleIssues.length > 0 && (
                <section className="data-issues" aria-labelledby="issues-heading">
                  <h3 id="issues-heading">Inspection notes</h3>
                  {visibleIssues.map((issue) => (
                    <div key={issue.code} className={`data-issue ${issue.severity}`}>
                      <span>{issue.severity === "blocking" ? "Blocked" : "Review"}</span>
                      <p>{issue.message}</p>
                    </div>
                  ))}
                </section>
              )}

              <div className="data-seal-bar">
                <div>
                  <strong>{readyToValidate ? "Ready for full row validation" : "Complete every required confirmation"}</strong>
                  <small>Validation re-reads the quarantined bytes. It does not create an immutable snapshot yet.</small>
                </div>
                <button type="button" className="primary" disabled={!readyToValidate}
                  onClick={validateDataset}>
                  Validate data
                </button>
              </div>
            </div>
          )}

          {sourceTab === "csv" && phase === "validating" && (
            <div className="data-panel data-progress-panel" role="status" aria-live="polite">
              <span className="data-spinner" aria-hidden="true" />
              <div>
                <p className="data-eyebrow">Step 3 · mandatory validation</p>
                <h2 id="import-heading">Checking every normalized row</h2>
                <p>QuantLens is testing schema, coverage, continuity and prices. Nothing is sealed yet.</p>
              </div>
            </div>
          )}

          {sourceTab === "csv" && (phase === "review" || phase === "sealing") && validation && inspection && (
            <div className="data-panel data-enter">
              <div className="data-panel-head">
                <div>
                  <p className="data-eyebrow">Step 3 · validation review</p>
                  <h2 id="import-heading">Review what QuantLens found</h2>
                </div>
                <button type="button" className="linkish" onClick={invalidateValidation}
                  disabled={phase === "sealing"}>Back to mapping</button>
              </div>

              <div className={`data-review-banner ${validation.quality.review_status === "review_required" ? "needs-review" : "ready"}`}>
                <div className="data-review-mark" aria-hidden="true">
                  {validation.quality.review_status === "review_required" ? "!" : "✓"}
                </div>
                <div>
                  <strong>{validation.quality.review_status === "review_required"
                    ? "Human review required before sealing"
                    : "Validation passed — ready to seal"}</strong>
                  <p>{provenanceNotice || "This receipt binds the source bytes, mapping and declarations to the validation result."}</p>
                </div>
              </div>

              <section className="data-subsection" aria-labelledby="checks-heading">
                <div className="data-subhead">
                  <div><span className="data-index">01</span><h3 id="checks-heading">Validation checks</h3></div>
                  <span className={`data-state ${validation.quality.review_status === "review_required" ? "attention" : "ready"}`}>
                    {validation.quality.review_status === "review_required" ? "Review findings" : "All ready"}
                  </span>
                </div>
                <div className="data-check-grid">
                  {(Object.entries(validation.quality.checks) as Array<[
                    "schema" | "coverage" | "continuity" | "prices", ValidationCheck
                  ]>).map(([name, check]) => (
                    <article className={`data-check-card ${check.status === "needs_review" ? "needs-review" : "ready"}`} key={name}>
                      <span className="data-check-icon" aria-hidden="true">{check.status === "ready" ? "✓" : "!"}</span>
                      <div>
                        <h4>{name[0].toUpperCase() + name.slice(1)}</h4>
                        <p><span className="data-check-status">{check.status === "ready" ? "Ready" : "Needs review"}</span> · {check.label}</p>
                      </div>
                    </article>
                  ))}
                </div>
              </section>

              <section className="data-subsection" aria-labelledby="quality-heading">
                <div className="data-subhead">
                  <div><span className="data-index">02</span><h3 id="quality-heading">Observed data profile</h3></div>
                  <span className="data-state neutral">Deterministic metrics</span>
                </div>
                <div className="data-coverage-band">
                  <div><span>Coverage starts</span><strong>{validation.quality.coverage.start}</strong></div>
                  <span className="data-coverage-line" aria-hidden="true" />
                  <div><span>Coverage ends</span><strong>{validation.quality.coverage.end}</strong></div>
                </div>
                <div className="data-quality-grid data-review-quality">
                  <div><span>Normalized rows</span><strong>{validation.quality.row_count.toLocaleString("en-US")}</strong></div>
                  <div><span>Missing business days</span><strong>{validation.quality.missing_business_days}</strong></div>
                  <div><span>Longest gap</span><strong>{validation.quality.max_consecutive_missing} day{validation.quality.max_consecutive_missing === 1 ? "" : "s"}</strong></div>
                  <div><span>Price range</span><strong>${validation.quality.price_min.toLocaleString("en-US")} – ${validation.quality.price_max.toLocaleString("en-US")}</strong></div>
                  <div><span>Zero-volume rows</span><strong>{validation.quality.zero_volume_ratio === undefined
                    ? (validation.quality.volume_policy === "mapped" ? "Measured" : "Filled by policy")
                    : `${(validation.quality.zero_volume_ratio * 100).toFixed(1)}%`}</strong></div>
                  <div><span>Suspicious jumps</span><strong>{validation.quality.suspicious_price_jump_count ?? 0}</strong></div>
                  <div><span>Volume policy</span><strong>{validation.quality.volume_policy === "mapped" ? "Mapped source column" : "Missing values filled zero"}</strong></div>
                  <div><span>Return basis</span><strong>{validation.quality.return_basis ?? "Adjusted close-to-close"}</strong></div>
                </div>
                {validation.quality.missing_day_examples && validation.quality.missing_day_examples.length > 0 && (
                  <p className="data-profile-note"><strong>Example missing sessions:</strong> {validation.quality.missing_day_examples.join(", ")}</p>
                )}
              </section>

              {validation.quality.issues.length > 0 && (
                <section className="data-issues" aria-labelledby="validation-issues-heading">
                  <h3 id="validation-issues-heading">Findings</h3>
                  {validation.quality.issues.map((issue) => (
                    <div key={`${issue.code}-${issue.message}`} className={`data-issue ${issue.severity}`}>
                      <span>{issue.severity === "blocking" ? "Blocked" : issue.severity === "warning" ? "Review" : "Info"}</span>
                      <p>{issue.message}</p>
                    </div>
                  ))}
                </section>
              )}

              <section className="data-subsection" aria-labelledby="normalized-preview-heading">
                <div className="data-subhead">
                  <div><span className="data-index">03</span><h3 id="normalized-preview-heading">Normalized preview</h3></div>
                  <span className="data-state neutral">Canonical fields</span>
                </div>
                <p className="data-help">This is the schema strategies will read after sealing, not the original CSV layout.</p>
                <div className="tablewrap data-preview-table" role="region" aria-label="Normalized dataset preview" tabIndex={0}>
                  <table>
                    <thead><tr>{CANONICAL_FIELDS.map((field) => <th scope="col" key={field}>{field}</th>)}</tr></thead>
                    <tbody>{validation.normalized_preview.map((row, index) => (
                      <tr key={index}>{CANONICAL_FIELDS.map((field) =>
                        <td key={field}>{row[field] === null || row[field] === undefined
                          ? <span className="data-null">—</span> : String(row[field])}</td>)}</tr>
                    ))}</tbody>
                  </table>
                </div>
              </section>

              <section className="data-subsection" aria-labelledby="warning-ack-heading">
                <div className="data-subhead">
                  <div><span className="data-index">04</span><h3 id="warning-ack-heading">Seal acknowledgements</h3></div>
                  <span className={`data-state ${allWarningsAcknowledged ? "ready" : "attention"}`}>
                    {allWarningsAcknowledged ? "Ready" : "Required"}
                  </span>
                </div>
                {validationWarnings.length === 0 ? (
                  <div className="data-no-warnings"><span aria-hidden="true">✓</span>
                    <p><strong>No warnings require acknowledgement.</strong><br />The immutable receipt will still preserve the complete quality profile.</p>
                  </div>
                ) : (
                  <div className="data-warning-acks">
                    <p>Warnings do not disappear after sealing. Confirm each one to bind it to the provenance receipt.</p>
                    {validationWarnings.map((warning, index) => (
                      <label className="data-warning-ack" key={`${index}-${warning}`}>
                        <input type="checkbox" checked={acknowledgedWarnings.includes(warning)}
                          onChange={(event) => setAcknowledgedWarnings((current) => event.target.checked
                            ? [...current, warning] : current.filter((item) => item !== warning))} />
                        <span><strong>I reviewed this warning</strong><small>
                          {validation.quality.issues.find((issue) => issue.code === warning)?.message ?? warning}
                        </small></span>
                      </label>
                    ))}
                  </div>
                )}
                <details className="drawer data-validation-receipt">
                  <summary>Validation receipt details</summary>
                  <div className="drawer-body">
                    <dl>
                      <div><dt>Validation profile</dt><dd><code>{validation.profile_hash}</code></dd></div>
                      <div><dt>Import quarantine</dt><dd><code>{inspection.import_id}</code></dd></div>
                      <div><dt>Source SHA-256</dt><dd><code>{inspection.source_sha256}</code></dd></div>
                      <div><dt>Timezone</dt><dd>{timezone}</dd></div>
                      <div><dt>Adjusted prices</dt><dd>{pricesAdjusted ? "Attested" : "Not attested"}</dd></div>
                    </dl>
                  </div>
                </details>
              </section>

              <div className="data-seal-bar">
                <div>
                  <strong>{readyToSeal ? "Ready to create an immutable snapshot" : "Review and acknowledge every warning"}</strong>
                  <small>Sealing locks this file, its mappings, declarations and findings under one immutable receipt.</small>
                </div>
                <button type="button" className="primary" disabled={!readyToSeal || phase === "sealing"}
                  onClick={sealDataset}>
                  {phase === "sealing" ? "Sealing snapshot…" : "Seal immutable dataset"}
                </button>
              </div>
            </div>
          )}

          {sourceTab === "csv" && phase === "sealed" && sealed && (
            <div className="data-panel data-receipt data-enter" aria-live="polite">
              <div className="data-seal-orb" aria-hidden="true">✓</div>
              <p className="data-eyebrow">Step 4 · immutable local snapshot</p>
              <h2 id="import-heading">{sealed.display_name} is sealed</h2>
              <p className="data-receipt-lede">
                {sealed.row_count.toLocaleString("en-US")} daily sessions passed every blocking check.
                Strategies can now bind to this exact manifest; later imports cannot overwrite it.
              </p>
              <div className="data-quality-grid">
                <div><span>Symbol</span><strong>{sealed.symbol}</strong></div>
                <div><span>Coverage</span><strong>{sealed.coverage.start}<br />{sealed.coverage.end}</strong></div>
                <div><span>Missing business days</span><strong>{sealed.quality.missing_business_days}</strong></div>
                <div><span>Longest gap</span><strong>{sealed.quality.max_consecutive_missing} day{sealed.quality.max_consecutive_missing === 1 ? "" : "s"}</strong></div>
                <div><span>Price range</span><strong>${sealed.quality.price_min.toLocaleString("en-US")} – ${sealed.quality.price_max.toLocaleString("en-US")}</strong></div>
                <div><span>Volume</span><strong>{sealed.quality.volume_policy === "mapped" ? "Mapped" : "Filled with zero"}</strong></div>
              </div>
              {sealed.quality.warnings.length > 0 && (
                <div className="data-warning-note">
                  <strong>Sealed with {sealed.quality.warnings.length} disclosed warning{sealed.quality.warnings.length === 1 ? "" : "s"}</strong>
                  <span>{sealed.quality.warnings.join(" · ")}</span>
                </div>
              )}
              <details className="drawer data-provenance">
                <summary>Provenance receipt</summary>
                <div className="drawer-body">
                  <dl>
                    <div><dt>Dataset ID</dt><dd><code>{sealed.dataset_id}</code></dd></div>
                    <div><dt>Dataset manifest</dt><dd><code>{sealed.dataset_manifest_sha256}</code></dd></div>
                    <div><dt>Source SHA-256</dt><dd><code>{sealed.provenance.source_sha256}</code></dd></div>
                    <div><dt>Normalized SHA-256</dt><dd><code>{sealed.provenance.normalized_sha256}</code></dd></div>
                    <div><dt>Logical rows SHA-256</dt><dd><code>{sealed.provenance.logical_rows_sha256}</code></dd></div>
                    <div><dt>Snapshot ID</dt><dd><code>{sealed.snapshot_id}</code></dd></div>
                    <div><dt>Timezone</dt><dd>{sealed.provenance.timezone}</dd></div>
                    <div><dt>Source assurance</dt><dd>{sealed.provenance.notice}</dd></div>
                    <div><dt>Created</dt><dd>{displayDate(sealed.created_at)}</dd></div>
                  </dl>
                </div>
              </details>
              <div className="data-receipt-actions">
                <Link href="/studio" className="btn-link primary">Continue to Research Studio →</Link>
                <button type="button" onClick={resetImport}>Import another dataset</button>
              </div>
            </div>
          )}
        </section>

        <aside className="data-library" aria-labelledby="library-heading">
          <div className="data-library-head">
            <div><p className="data-eyebrow">Immutable snapshots</p><h2 id="library-heading">Dataset library</h2></div>
            <span>{datasets.length}</span>
          </div>
          {libraryError && <p className="data-library-error" role="status">{libraryError}</p>}
          {!libraryError && !libraryLoaded && (
            <div className="data-empty-library" data-testid="library-loading">
              <span aria-hidden="true">◌</span>
              <p><strong>Reading your library…</strong></p>
            </div>
          )}
          {!libraryError && libraryLoaded && datasets.length === 0 && (
            <div className="data-empty-library" data-testid="empty-library">
              <span aria-hidden="true">◌</span>
              <p>
                <strong>No sealed datasets yet.</strong><br />
                Import your own permitted CSV, or use the synthetic sample in Research Studio.
              </p>
            </div>
          )}
          <div className="data-library-list">
            {datasets.map((dataset) => {
              const licensed = dataset.provenance?.data_label === "LICENSED_PROVIDER";
              const instrument = licensed
                ? [
                    dataset.provenance.instrument?.display_name,
                    dataset.provenance.instrument?.mic,
                    dataset.provenance.instrument?.currency,
                  ].filter(Boolean).join(" · ")
                : instrumentDescriptor(dataset.symbol) ?? dataset.symbol;
              const basis = licensed
                ? "Split-adjusted price return"
                : dataset.quality.return_basis ?? "Adjusted close-to-close";
              return (
                <article className="data-dataset-card" key={dataset.dataset_id}
                  data-testid={`dataset-card-${dataset.dataset_id}`}>
                  <div className="data-dataset-card-head">
                    <span className="data-symbol">{dataset.symbol}</span>
                    {/* Only the bundle seeder writes an operator-attested basis, so it
                        marks bars QuantLens supplied. Badging those "Your data" credits
                        the reader for bytes they never chose, in the one place they look
                        to tell their own imports apart. */}
                    <span className={`sample-badge${licensed ? " licensed" : " user-data"}`}>
                      {licensed
                        ? "Licensed data"
                        : dataset.provenance?.price_adjustment === TOTAL_RETURN_ADJUSTMENT
                          ? "Bundled · CC BY"
                          : "Your data"}
                    </span>
                  </div>
                  <h3>{dataset.display_name}</h3>
                  {instrument && (
                    <p className="data-instrument-line">{instrument}</p>
                  )}
                  <p>{dataset.row_count.toLocaleString("en-US")} sessions · {dataset.coverage.start} → {dataset.coverage.end}</p>
                  <dl>
                    <div><dt>Basis</dt><dd>{basis}</dd></div>
                    {licensed && dataset.provenance.rights && (
                      <div>
                        <dt>Rights</dt>
                        <dd>
                          {dataset.provenance.rights.use ?? "research use"} ·
                          retention {dataset.provenance.rights.retention ?? "per contract"}
                        </dd>
                      </div>
                    )}
                    <div><dt>Integrity</dt><dd>Sealed · integrity-checked</dd></div>
                    <div><dt>{licensed ? "Acquired" : "Imported"}</dt><dd>{displayDate(dataset.created_at)}</dd></div>
                  </dl>
                </article>
              );
            })}
          </div>
          <p className="data-library-footnote">
            Importing the same file again produces a matching integrity check, and every
            sealed dataset still keeps its own immutable identity and receipt.
          </p>
        </aside>
      </div>
    </main>
  );
}
