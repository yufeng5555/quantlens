# QuantLens

A reproducible course project for evaluating a user-defined, rule-based trading hypothesis on historical daily data. QuantLens turns supported hypotheses into editable rule cards, compares a deterministic backtest with buy-and-hold, runs out-of-sample checks, and produces a report linked to its data, specification, artifacts, and runtime identity.

Licensed under the [MIT License](LICENSE). Third-party dependencies retain their own licenses.

Built for UGBA 117 — AI Tools & Product Innovation, with AI-assisted implementation. This release is a local educational version of a separately deployed project. [Hosted demonstration](https://quantlens-ugba117.fly.dev/). The hosted deployment has its own accounts, data, configuration, and operational history.

## What you can reproduce

- Price versus a moving average and two-moving-average crossover rules; one symbol, daily bars, long or cash.
- Decisions at close *t*, fills at open *t+1*, itemized commission/slippage, and an aligned buy-and-hold baseline.
- Battery v2: fixed-rule **expanding walk-forward**, development cost stress, regime summaries, and a one-time final holdout. The rule is not retuned in each fold. Parameter sensitivity is **NOT_RUN** in v2.
- Content-addressed synthetic input, confirmation-bound specifications, sealed artifact ledgers, and checked HTML/JSON reports.
- A FastAPI API, a local SQLite queue with a separate worker, and a Next.js interface.

The public example uses **synthetic data only**. It is not evidence of returns for a real ETF. v1/v2 retain their frozen historical `linear_execution_friction` semantics and are explicitly marked as legacy, with `verified_financial_semantics=false`. Corrected v3 implementation files are retained for dependency completeness, but v3 admission and its external authorities are **not activated** by this release. See [methods](docs/METHODS.md).

## Install

Tested environment and actual checks are recorded in [reproducibility results](docs/REPRODUCIBILITY.md). Use Python **3.13** and Node **20.9+**; verification was performed with Python 3.13.9 and Node 24.18.0 on macOS arm64. Other platforms have not yet been tested. Requires Bash for the launch scripts.

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-hashes.lock
(cd apps/web && npm ci)
```

The Python and JavaScript dependencies are pinned. No provider keys, broker accounts, cloud login, production database, or LLM service are required.

## Prepare the local runtime

Read [the local trust boundary](docs/LOCAL_RUNTIME.md) first. The historical app deliberately rejects unknown runtime identities. This release adds an **explicit local educational registration** after checking the supplied source hashes and installed dependency versions:

```bash
.venv/bin/python scripts/prepare_local_runtime.py --accept-local-demo
```

This adds only the measured identity for the legacy v1/v2 contracts to this checkout's registry and writes a separate pin/receipt under ignored `var/`. It does not certify financial semantics, change algorithms, import production trust, or authorize v3. Launchers recheck the registration; code/dependency/runtime drift refuses startup. Do not publish your locally prepared registry or `var/` as a release. Publish the reviewed clean snapshot only.

## Run

```bash
bash scripts/run_local.sh
```

Open `http://127.0.0.1:3000`. The API listens on loopback port 8000. State and logs stay in `var/`. The local-preview identity is a convenience for a private demonstration, not human authentication or a shared-machine security boundary. Keep the listeners on loopback.

In Research Studio, use the synthetic sample and try `own QQQ when it's above its 200-day average, otherwise cash`. The parser is deterministic and supports a bounded grammar. No live LLM is called. Inspect/edit the rule, acknowledge the assumptions, and run Battery v2.

## Reproduce the included example

Keep the application running. In another terminal:

```bash
.venv/bin/python scripts/run_example.py --api-origin http://127.0.0.1:8000
```

The script sends the included specification through validation, explicit confirmation, queue execution, and the checked evidence/report endpoints. It saves HTML, evidence, manifest, and ledger JSON under `var/example-report/`. It uses the real loopback API and worker, without a test authentication override or a disabled worker heartbeat. See [sample report](examples/sample-report/report.html) and [example results](examples/sample-report/README.md).

## Verify

```bash
bash scripts/test.sh
(cd apps/web && npm run build)
```

The selected tests cover hand-calculated execution/costs, look-ahead and prefix invariance, aligned benchmarks, partition/final-holdout rules, confirmation/tenant boundaries, unknown-runtime rejection, and tamper refusal. This is a curated suite, not the full private production release validation. [Results and limits](docs/REPRODUCIBILITY.md) include failures from the initial attempt and the final commands actually run.

## Read further

- [Architecture](docs/ARCHITECTURE.md) and [methods](docs/METHODS.md)
- [Limitations](docs/LIMITATIONS.md) and [technical retrospective](docs/POSTMORTEM.md)
- [AI assistance and contribution boundaries](docs/CONTRIBUTIONS.md)
- [Privacy/data/reuse review](docs/PRIVACY_DATA_REVIEW.md), [third-party dependency inventory](docs/THIRD_PARTY.md), and [public file list](docs/PUBLIC_FILES.txt)

QuantLens does not predict future returns, establish profitability, recommend trades, connect to a broker, or execute orders. This release is a course-project portfolio artifact; ongoing feature development and service availability are not promised.

中文说明：这是可在本地复现的课程项目公开版，默认只提供合成数据。v2 使用固定规则的扩展窗口评估，未执行参数敏感性分析；不能据此宣称真实市场盈利、自动交易或具身智能研究。本项目采用 MIT 许可证，第三方依赖适用各自许可证。
