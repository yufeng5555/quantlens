"""Deterministic natural-language parser — Gate 6A's local, no-AI fallback.

Deterministic keyword/regex rules over a small canned pattern set. Clearly labeled in every
response. It never invents material fields: a hypothesis missing the ETF or the MA rule
comes back `ambiguous` with plain-language questions (AT-1.3). Advice-seeking and
out-of-scope requests are deflected with the supported-scope statement and a correction
path (AT-2.3/2.4/2.5). Hypothesis text is treated as data, never as instructions.
"""

from __future__ import annotations

import re

from quantlens_schema import default_spec, universe_symbols
from quantlens_schema.validator import SUPPORTED_SCOPE_STATEMENT, DEFAULT_FIELDS, _nearest_template

PARSER_LABEL = "mock-parser-v0 (canned deterministic parser — Gate 6A fallback; no AI provider used)"

_ADVICE = re.compile(
    r"what\s+should\s+i\s+(buy|sell|invest)|should\s+i\s+(buy|sell)|tell\s+me\s+(what|which)\s+to\s+(buy|sell)"
    r"|which\s+(stock|etf|fund)s?\s+(should|do)\s+i|is\s+(it|this)\s+a\s+good\s+(buy|investment)"
    r"|(recommend|pick)\s+(me\s+)?(a|some|the)\s+(stock|etf|fund)", re.I)

_OUT_OF_SCOPE = [
    ("options", re.compile(r"\boptions?\b|\bcalls?\b(?!\s*it)|\bputs?\b|covered\s+call", re.I)),
    ("intraday", re.compile(r"intraday|minute\s+bars?|\bhourly\b|day[- ]?trad", re.I)),
    ("leverage_short", re.compile(r"leverage[d]?|margin|\bshort(ing|s)?\b|inverse|[23]x\b", re.I)),
    ("crypto", re.compile(r"crypto|bitcoin|\bbtc\b|ethereum|\beth\b|coin\b", re.I)),
    ("futures", re.compile(r"futures?\b", re.I)),
    ("single_stocks", re.compile(r"\bstocks?\b|\bAAPL\b|\bTSLA\b|\bNVDA\b|\bMSFT\b|\bAMZN\b|\bGOOG[L]?\b|\bMETA\b", re.I)),
]

_UNSUPPORTED_FAMILY = [
    ("rotation", re.compile(r"rotat|strongest\s+(sector|etf)|switch\s+(into|between)|momentum\s+rank|rank\s+and\s+hold", re.I)),
    ("fixed_weights", re.compile(r"60\s*/\s*40|fixed\s+(allocation|weights?)|rebalance\s+(monthly|quarterly)|equal[- ]weight", re.I)),
]

def _record_interest_label(category: str) -> str:
    """Label the button by what it actually does: write a row in this workspace.

    It used to read "Notify me when X is supported", which promised a message. The
    click posts a ``notify_me`` event to the local database and nothing reads it --
    there is no HTTP endpoint over those rows and no delivery channel of any kind --
    so the promise could never be kept by anyone.
    """
    return f"Record in this workspace that I want {category.replace('_', ' ')} supported"


_CROSSOVER = re.compile(r"cross(es|ing|over)?|golden\s+cross|death\s+cross", re.I)
_WINDOW = re.compile(r"(\d{1,3})\s*[- ]?\s*day", re.I)
_BARE_PAIR = re.compile(r"\b(\d{1,3})\s*/\s*(\d{1,3})\b")

# Uppercase tokens that look like tickers but are ordinary abbreviations.
_TICKER_STOPLIST = {
    "ETF", "ETFS", "MA", "SMA", "EMA", "DMA", "MACD", "OOS", "US", "USA", "AND", "THE",
    "OR", "ON", "IN", "IF", "MY", "AN", "TO", "VS", "OK", "AI", "IS", "IT", "CASH",
    "BUY", "SELL", "LONG", "FLAT", "DAY", "DAYS", "YTD", "CAGR",
}
_TICKER_TOKEN = re.compile(r"\b[A-Z]{2,5}\b")


def _find_symbols(text: str) -> list[str]:
    """All curated-universe symbols mentioned (deduped, in text order)."""
    hits = []
    for s in universe_symbols():
        if re.search(rf"\b{s}\b", text, re.I) and s not in hits:
            hits.append(s)
    return hits


def _find_unknown_tickers(text: str) -> list[str]:
    """Uppercase ticker-shaped tokens that are NOT in the curated universe — routed to
    the explicit unsupported-stock path, never silently ignored (audit hardening)."""
    known = set(universe_symbols())
    out = []
    for tok in _TICKER_TOKEN.findall(text):
        if tok not in known and tok not in _TICKER_STOPLIST and tok not in out:
            out.append(tok)
    return out


def _questions(missing_symbol: bool, missing_rule: bool) -> list[dict]:
    """Clarification questions (AT-1.3): material fields block compute and are never
    silently invented; range/costs show their transparent defaults for explicit acceptance."""
    qs = []
    if missing_symbol:
        qs.append({
            "field": "universe.symbol", "kind": "symbol", "material": True,
            "question": "Which single ETF from the supported list should this test? "
                        "(v1 tests exactly one US-listed ETF from the curated list.)",
            "options": universe_symbols(),
        })
    if missing_rule:
        qs.append({
            "field": "rule", "kind": "rule", "material": True,
            "question": "Which moving-average rule did you mean — price above an N-day "
                        "average (price vs MA), or a fast/slow MA crossover — and with "
                        "what window(s) in days?",
            "options": ["price_vs_ma", "ma_crossover"],
        })
    qs.append({
        "field": "data.range", "kind": "date_range", "material": False,
        "question": "What date range should the test cover?",
        "default": {"start": "2005-01-01", "end": "2024-12-31"},
    })
    qs.append({
        "field": "costs", "kind": "costs", "material": False,
        "question": "What per-trade costs should apply?",
        "default": {"commission_bps": 1, "slippage_bps": 5},
    })
    return qs


def _recognized_fields(symbol: str | None, windows: list[int],
                       wants_crossover: bool, rule_is_complete: bool) -> dict:
    """Return only values explicitly present and unambiguous in the hypothesis.

    The UI uses this non-runnable seed to preserve known answers while asking about the
    unresolved material fields. Defaults never appear here.
    """
    recognized: dict = {}
    if symbol is not None:
        recognized["symbol"] = symbol
    if rule_is_complete:
        if wants_crossover:
            recognized.update({
                "rule_type": "ma_crossover",
                "fast_ma_days": windows[0],
                "ma_days": windows[-1],
            })
        elif windows:
            recognized.update({
                "rule_type": "price_vs_ma",
                "ma_days": windows[-1],
            })
    return recognized


def parse_hypothesis(text: str) -> dict:
    """Deterministic mock parse. Returns a ParseResponse-shaped dict (see ts/types.ts)."""
    base = {"parser": PARSER_LABEL, "supported_scope": SUPPORTED_SCOPE_STATEMENT}
    text = (text or "").strip()
    if not text:
        return {**base, "status": "ambiguous", "category": "empty",
                "message": "Describe the rule you want to test in plain language.",
                "questions": _questions(True, True)}

    if _ADVICE.search(text):
        # Deflection copy must not itself suggest any security, threshold, or example
        # rule — it only explains the boundary and invites the user's own rule.
        return {**base, "status": "advice_deflection", "category": "advice_seeking",
                "message": (
                    "QuantLens can't tell you what to buy or sell — it never recommends a "
                    "security, position, timing, threshold, or action. What it can do is "
                    "test a falsifiable rule that you author against historical data and "
                    "show you the evidence, including the evidence against it. If you "
                    "already have a rule of your own in mind, describe it in your words "
                    "and QuantLens will draft testable rule cards from it.")}

    for category, pat in _UNSUPPORTED_FAMILY:
        if pat.search(text):
            fam_syms = _find_symbols(text)
            template = _nearest_template(
                {"universe": {"symbol": fam_syms[0]}} if len(fam_syms) == 1 else {})
            return {**base, "status": "unsupported", "category": f"family_{category}",
                    "message": (
                        f"That idea needs the deferred '{category}' strategy family. v1 "
                        "supports only the long/flat moving-average family. The nearest "
                        "supported test is an MA trend filter on one ETF from the curated "
                        "list — a pre-filled template is offered below. No partial spec "
                        "was created."),
                    "correction": {"template": template,
                                   "notify_option": _record_interest_label(category)}}

    for category, pat in _OUT_OF_SCOPE:
        if pat.search(text):
            return {**base, "status": "unsupported", "category": f"instrument_{category}",
                    "message": (
                        f"This request involves '{category.replace('_', '/')}', which v1 "
                        "does not support. No runnable spec was created. If the underlying "
                        "idea has a trend component, you can test its trend side as a "
                        "long/flat MA rule on a supported ETF."),
                    "correction": {"template": _nearest_template({}),
                                   "notify_option": _record_interest_label(category)}}

    unknown = _find_unknown_tickers(text)
    if unknown:
        return {**base, "status": "unsupported", "category": "instrument_single_stocks",
                "message": (
                    f"'{unknown[0]}' is not in the curated liquid-US-ETF universe v1 — "
                    "individual stocks and uncurated tickers are not supported yet. No "
                    "runnable spec was created. You can test a long/flat MA rule on one "
                    "ETF from the supported list instead."),
                "correction": {"template": _nearest_template({}),
                               "notify_option": "Record in this workspace that I want "
                                                "more instruments supported"}}

    symbols = _find_symbols(text)
    windows = [int(m) for m in _WINDOW.findall(text)]
    pair = _BARE_PAIR.search(text)
    if pair:
        windows = sorted({int(pair.group(1)), int(pair.group(2))} | set(windows))
    windows = sorted(set(windows))
    wants_crossover = bool(_CROSSOVER.search(text)) or len(windows) >= 2

    if len(symbols) > 1:
        # Never silently pick one of several mentioned ETFs (audit hardening).
        return {**base, "status": "ambiguous", "category": "multiple_symbols",
                "message": (
                    f"You mentioned {len(symbols)} supported ETFs "
                    f"({', '.join(symbols)}); v1 tests exactly one per run. Material "
                    "fields are never guessed — pick one below."),
                "questions": _questions(True, not windows and not wants_crossover),
                "recognized_fields": _recognized_fields(
                    None, windows, wants_crossover,
                    bool(windows) and (not wants_crossover or len(windows) >= 2))}

    symbol = symbols[0] if symbols else None
    crossover_underspecified = bool(_CROSSOVER.search(text)) and len(windows) < 2
    if symbol is None or crossover_underspecified or (not windows and not wants_crossover):
        # A crossover request missing either window is never silently converted into a
        # different rule shape (audit hardening).
        rule_complete = bool(windows) and not crossover_underspecified
        return {**base, "status": "ambiguous", "category": "underspecified",
                "message": (
                    "This hypothesis doesn't yet pin down a testable rule. Material fields "
                    "are never guessed — answer the questions below and the rule cards "
                    "will update."),
                "questions": _questions(symbol is None,
                                        crossover_underspecified or not windows),
                "recognized_fields": _recognized_fields(
                    symbol, windows, wants_crossover, rule_complete)}

    draft = default_spec(symbol=symbol)
    default_fields = list(DEFAULT_FIELDS)
    windows = sorted(set(windows))
    if wants_crossover and len(windows) >= 2:
        draft["rule"] = {"type": "ma_crossover", "fast_ma_days": windows[0], "ma_days": windows[-1]}
        draft["meta"]["name"] = f"{symbol} · {windows[0]}/{windows[-1]}-day crossover"
        default_fields.remove("rule.ma_days")
    elif windows:
        draft["rule"] = {"type": "price_vs_ma", "fast_ma_days": None, "ma_days": windows[-1]}
        draft["meta"]["name"] = f"{symbol} · {windows[-1]}-day trend"
        default_fields.remove("rule.ma_days")
    # keep the sensitivity grid honest: it must contain the chosen window (LINT_GRID_CONTAINS_CHOSEN)
    grid = draft["validation"]["sensitivity"]["grid"]["ma_days"]
    chosen = draft["rule"]["ma_days"]
    if chosen not in grid:
        draft["validation"]["sensitivity"]["grid"]["ma_days"] = sorted(set(grid + [chosen]))
    return {**base, "status": "draft", "category": "supported", "draft": draft,
            "default_fields": default_fields,
            "message": "Draft rule cards created by the built-in deterministic parser. "
                       "Every default is labeled; nothing runs until you confirm the "
                       "restatement."}
