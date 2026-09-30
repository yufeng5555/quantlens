# Known limitations

- Synthetic samples demonstrate workflow and invariants, not market returns. No real market CSV or provider credential is distributed.
- Legacy v1/v2 use frozen linear cash-friction semantics and are not flagged as verified financial semantics. v3 is release-gated and not activated here.
- v2 is fixed-rule expanding walk-forward; parameter sensitivity is NOT_RUN. A single final evaluation in one local store is not protection against human repeated experimentation elsewhere.
- One symbol per run, daily bars, long/cash, bounded MA rules, and zero cash yield. Taxes, lending, financing, venue microstructure, realistic liquidity, order books and live execution are outside scope.
- CSV import checks declared structure/content/integrity. It does not establish market accuracy, dividends/corporate-action truth or redistribution rights.
- Local-preview identity is not human authentication or a shared-machine boundary. External sign-in, mail, billing and market provider adapters need separate configuration and review; they are not required or activated by the demonstration.
- The natural-language parser and evidence explanation are deterministic local code. AI was used during development; no live LLM is required by this release.
- Hash/contract checks detect supported integrity failures; they do not provide an external signed trust root or certify financial methodology.
- A changed kernel/runtime/source/lock refuses the previous local registration. Cross-platform and multi-worker deployments are not verified by this release.
- The selected suite is a focused public reproduction check, not proof of exhaustive correctness, profitability, production security or universal installability.
