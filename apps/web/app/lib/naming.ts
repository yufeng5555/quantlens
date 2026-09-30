/**
 * Display-name helpers for strategies and runs. The server applies the same
 * normalization (quantlens_schema.normalize_display_name) before hashing, so the
 * client-side form is a mirror for immediate feedback, not the authority.
 */

export const NAME_MAX_LENGTH = 120;

/** C0/C1 control characters plus line/paragraph separators. */
const CONTROL_CHARS = new RegExp(
  "[\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029]",
  "g",
);

/** Trim, NFKC-normalize, strip control/newline characters, collapse whitespace. */
export function normalizeDisplayName(name: string): string {
  const normalized = name
    .normalize("NFKC")
    .replace(CONTROL_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim();
  return normalized.slice(0, NAME_MAX_LENGTH).trim();
}

const COPY_SUFFIX = /\s+(?:copy|\(copy\)|copy\s+\d+)$/i;
const COPY_PREFIX = /^copy\s+of\s+/i;
const VERSION_SUFFIX = /\s+v(\d+)$/;

/**
 * Stable duplicate naming: strip legacy "… copy" clutter, then append or advance a
 * `v2`/`v3` suffix. "QQQ · Trend 200d" → "QQQ · Trend 200d v2" → "… v3".
 */
export function duplicateName(source: string): string {
  let base = normalizeDisplayName(source).replace(COPY_PREFIX, "");
  while (COPY_SUFFIX.test(base)) base = base.replace(COPY_SUFFIX, "");
  base = base.trim();
  if (!base) return "Untitled research v2";
  const versioned = VERSION_SUFFIX.exec(base);
  if (versioned) {
    const next = Number(versioned[1]) + 1;
    return normalizeDisplayName(`${base.slice(0, versioned.index)} v${next}`);
  }
  return normalizeDisplayName(`${base} v2`);
}

/** Professional default name: "QQQ · 200-day trend · 2005–2024". */
export function defaultStudyName(spec: {
  universe: { symbol: string };
  rule: { type: string; fast_ma_days: number | null; ma_days: number };
  data: { range: { start: string; end: string } };
}): string {
  const rule = spec.rule.type === "ma_crossover"
    ? `${spec.rule.fast_ma_days}/${spec.rule.ma_days}-day crossover`
    : `${spec.rule.ma_days}-day trend`;
  const startYear = spec.data.range.start.slice(0, 4);
  const endYear = spec.data.range.end.slice(0, 4);
  return normalizeDisplayName(
    `${spec.universe.symbol} · ${rule} · ${startYear}–${endYear}`,
  );
}
