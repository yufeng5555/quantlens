# Methods and version boundaries

## Rule and execution

A study specifies one symbol, one daily range, a price/MA or MA-crossover rule, commission/slippage in basis points, and an allowed benchmark. Indicators use the available prefix. A close-time decision is acted on at the next daily open. Costs and fills are recorded. The benchmark starts at the first tradable decision boundary and uses the same entry cost convention, with aligned dates. There is no leverage, shorting, portfolio allocation, tax model, or live trading.

The reproducible legacy engine uses `linear_execution_friction`: commission and slippage are separately charged cash costs. This is not the corrected `adverse_effective_fill_price` implementation. Its presentation descriptor deliberately says `verified_financial_semantics=false` and `rebuild_required`. A report that passes its integrity checks remains educational legacy evidence, not a certified financial calculation.

Metrics use 252 days/year, zero cash/risk-free yield, sample standard deviation for Sharpe, and an initial-capital anchor so first-fill costs enter the path. Dataset return basis matters; synthetic output does not represent any listed instrument. Uploaded-source accuracy, adjustments and licensing are not independently authenticated.

## Battery v2 (the included example)

A server-owned plan separates the development region from the final holdout. Development uses a fixed rule with expanding training prefixes and contiguous out-of-sample test folds. The training floor is at least 504 bars and twice the strategy lookback; nominal test windows are 126 bars, with a 63-bar minimum short fold. There is **no foldwise parameter search or rule selection**.

Development includes an aligned base estimate and explicitly named cost-stress counterfactuals. Four lagged trend/volatility states summarize supported observations; small samples can be INCONCLUSIVE. Final data is excluded from development explanation/projection. The final holdout has one primary evaluation and no counterfactual evaluations, with a persistent execution audit and retry/recovery protection. This is a software access rule within one local study identity; it cannot prevent a person using another tool or a fresh independent workspace to inspect the same synthetic data.

v2 parameter sensitivity is **NOT_RUN**, with an empty grid. It must not be described as a completed sensitivity sweep or rolling optimization. v1 includes its own historical split/sensitivity behavior and is preserved only for compatibility and selected tests.

## Corrected v3

The source contains corrected financial semantics, continuous walk-forward/ledger machinery, release activation, and external plan/final-access authorities. They have a separate contract and release-admission law. Their presence does not mean the course-project demo has activated them. The local setup registers **v1/v2 only** and creates no active corrected release.

## Traceability

The snapshot records normalized input content; accepted specifications bind to confirmation/preflight receipts. The worker seals canonical artifacts and an index/result hash. Manifests identify data/specification/engine/runtime. Read routes verify the applicable contract and byte bindings before projecting evidence or rendering a report. Unknown identities and tampered evidence are refused. The local SHA-256 runtime identity binds worker source, report templates, lockfiles and host/runtime details; it is not an immutable container-image digest or an external signature.
