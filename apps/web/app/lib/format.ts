/**
 * Shared en-US formatters. Every number, date, and identifier the UI shows goes
 * through these so output is locale-stable regardless of the viewer's OS locale.
 * Research/audit instants are always rendered in UTC and say so; session dates
 * stay ISO calendar dates exactly as sealed.
 */

const LOCALE = "en-US";

const moneyFormat = new Intl.NumberFormat(LOCALE, {
  style: "currency",
  currency: "USD",
});

const moneyWholeFormat = new Intl.NumberFormat(LOCALE, {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 0,
});

const integerFormat = new Intl.NumberFormat(LOCALE);

const instantFormat = new Intl.DateTimeFormat(LOCALE, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});

export function pct(v: number | null | undefined, digits = 2): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return `${(v * 100).toFixed(digits)}%`.replace(/^(?=\d)/, "+").replace("+-", "-");
}

export function num(v: number | null | undefined, digits = 2): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return v.toFixed(digits);
}

export function money(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return moneyFormat.format(v);
}

export function moneyWhole(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return moneyWholeFormat.format(v);
}

export function integer(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return integerFormat.format(v);
}

export function exposure(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return `${(v * 100).toFixed(1)}%`;
}

/** Session dates are ISO calendar dates; render them exactly as sealed. */
export function sessionDate(value: string | null | undefined): string {
  return value && value.trim() ? value : "—";
}

/** Audit/research instants: explicit UTC, en-US, e.g. "Jul 18, 2026, 20:15 UTC". */
export function instantUTC(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return `${instantFormat.format(date)} UTC`;
}

/**
 * Identifier truncation for the audit trail. Default surfaces never show full
 * hashes; the audit trail shows this short form with the full value available
 * for copy.
 */
export function shortId(value: string | null | undefined, visible = 10): string {
  if (!value) return "—";
  const hash = value.replace(/^sha256:/, "").replace(/^local-runtime-sha256:/, "");
  if (hash.length <= visible) return hash;
  return `${hash.slice(0, visible)}…`;
}
