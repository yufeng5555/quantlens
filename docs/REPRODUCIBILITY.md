# Reproducibility checks

## Security maintenance — 2026-11-07

The source repository now pins Next.js 16.4.3, source-map-js 1.2.2 and certifi
2026.10.18. Both dependency locks, the runtime source baseline, the dependency
license inventory and the release manifest have been updated together.

In a fresh checkout of the current remote revision with the reviewed update,
the selected suite passed all **194 tests**, the TypeScript check and the Next.js
production build. A real loopback API/worker synthetic-v2 example passed and all
15 exported artifacts were verified. The current npm lock audit and OSV queries
for all 43 exact Python dependencies reported no known vulnerabilities. The
existing Starlette TestClient deprecation warning remains. Runtime registration
was performed only in the isolated local verification copy; the published
registry and its integrity guards are preserved.

These are source and local verification results. They do not certify the hosted
demo's installed versions or prove that the application has never been attacked.
Production deployment and verification are separate steps. The September
verification record below describes the initial public snapshot and is retained
as historical evidence.

## Initial public snapshot — September 2026

Verification date: 2026-09-28, Asia/Shanghai. Platform: macOS arm64; Python 3.13.9; Node 24.18.0; npm 11.16.0. No production state, provider credentials or existing production environment was used.

## Actual candidate checks

| Check | Actual result |
|---|---|
| Fresh Python venv + hash-locked installation | Passed; final pins subsequently installed and audited |
| npm ci | Passed, including the updated exact web lock |
| `bash scripts/test.sh` | **194 passed**, one Starlette TestClient deprecation warning; TypeScript check passed |
| `npm run build` | Passed; Next.js production bundle/routes built |
| npm audit on final lock | Zero known vulnerabilities reported |
| pip-audit on complete exact Python lock | Zero known vulnerabilities reported |
| Real loopback API + independent heartbeat worker | v2 example published successfully; checked evidence/report/manifest/ledger endpoints returned |
| Repeat of synthetic example | Published; numerical evidence matched; run identity/temporal artifacts and result hashes differed as expected |
| Independent sample verifier | 15 artifact hashes, result/manifest binding, report hash and synthetic files verified |
| Browser checks | Overview/report/data page loaded; synthetic label and legacy-contract restriction visible; no bundled-real-data offer on Data page |

The actual live check used loopback API port 18080 and web port 13000, with isolated local state under `var/demo-session/`. Its request used formal v2 admission because sandbox mode is development-only and permits v1 only. No heartbeat, authentication, activation or integrity assertion was weakened. The included CLI defaults to ports/state used by the normal launcher; overrides must point to the matching local worker state.

Tests retain the selected private project's assertions. API unit/integration tests use the existing explicit TestClient principal override and disable worker-heartbeat admission for in-process worker execution. These fixture settings are confined to tests; the separate HTTP example uses the ordinary loopback identity and actual heartbeat worker. The selected tests include look-ahead/prefix checks, hand-derived execution/cost goldens, benchmark alignment, v2 fold/final access laws, stale-confirmation/tenant refusal, registry-pin/unknown-identity rejection, tamper handling and report templates.

## Initial failures and repairs

The initial untouched candidate check had **56 passes, 7 failures and 2 errors**. Seven failures were the intended unknown-runtime rejection; two startup errors exposed an undefined logger when an optional real-market bundle was absent. The candidate adds logging and handles absent optional bundle data, then uses explicit source-checked local registration for v1/v2. No financial engine algorithm or test assertion was edited.

The first CLI experiment incorrectly requested sandbox mode for v2. Admission returned `SANDBOX_PROFILE_UNSUPPORTED`; the script was corrected to use normal formal v2 admission, rather than relaxing that rule.

The old npm lock reported six affected dependency packages. The old Python audit reported four affected packages (duplicate advisory records were deduplicated in the review). Candidate dependency changes include Next.js 16.2.10→16.3.6, js-yaml 5.2.1→5.4.2, PostCSS 8.5.10→8.5.28, FastAPI 0.115.6→0.141.1, Starlette 0.41.3→1.7.0, Jinja2 3.1.5→3.1.6, cryptography 49.0.0→50.0.0 and pytest 8.3.4→9.0.3. Necessary transitive entries were re-resolved; locks and license inventory capture the exact versions. NumPy/pandas remain unchanged.

## Verification limits

This is a selected public demonstration suite, not the private project's complete production validation. A complete browser automation/accessibility/responsive suite was not rerun. Only this macOS environment has been verified; Linux/Windows, external authentication/email/providers, multi-worker deployment and corrected-v3 activation have not been validated here. The TestClient compatibility warning remains visible and does not cause a failing test.

Run IDs, execution receipts, timestamps and host-dependent runtime identity differ on another checkout. Compare numeric values, specification/data hashes and invariant checks, rather than expecting a byte-identical identity-bearing manifest across hosts. The reference report is static sample evidence; a new run creates its own locally registered evidence. The sample verifier checks internal consistency only.

## Second clean-snapshot reproduction — completed

A separate checkout was copied from the clean publication snapshot, with no `.git`, `.venv`, `node_modules`, runtime state or local registration. A new Python venv and `npm ci` were used. Hash-locked Python installation succeeded. Explicit local registration succeeded without changing any algorithm or admission guard. The selected suite again reported **194 passed**, one TestClient deprecation warning, and the web typecheck passed.

The separate API/worker/web stack used ports 18081/13001 and fresh `var/`. The default example command (with only `--api-origin` changed to the test port) published v2 output and exported all 15 artifacts. Its six numerical evidence sections matched the first fresh run and its ledger result hash was exactly `sha256:8ccb0016b5c450d94077a14a760543fee7b4858b5e53056f28e15b09310c4f59`. The HTML hash differed because execution/report identity fields and timestamps differ. The independent verifier passed on the fresh output; a deliberately modified copy of one reference artifact was rejected for a hash mismatch. A real v3 validation request returned HTTP 422 / `BATTERY_PROFILE_NOT_RELEASED`.

No cross-platform success is inferred from this second checkout on the same host. Temporary servers are stopped after verification. Raw installation/test logs and the unchanged-original proof remain in the private preparation record, outside the publication payload.
