# Technical retrospective

The useful result of this project is a reviewable evaluation workflow: a hypothesis must become a precise rule, costs and data identity must be explicit, out-of-sample evidence must remain separate from development, and a report should be traceable to what was actually run.

A major lesson was the distinction between evidence integrity and numerical/methodological validity. Hashing a report cannot make an assumption correct. The historical v1/v2 presentation contracts consequently preserve their original cost semantics and report that they are legacy; corrected semantics require their own activated contract, rather than relabeling old results.

Runtime provenance also carries an operational cost. The original fingerprint includes host/kernel details. A fresh host can fail registration despite identical algorithm source. This candidate keeps the original identity mechanism and introduces explicit, source-checked local educational registration. It does not redesign production trust or admit v3 under a demo shortcut.

The original README described an earlier local/mock gate while later source supported hosted account/data features. Public documentation now describes the reproducible local subset and separates it from the hosted instance. Removing real market data exposed a startup error: an optional-bundle migration referenced an undefined logger on its exception path. The candidate adds a logger and handles an absent optional bundle without changing strategy arithmetic.

Dependency auditing found issues in the old web and Python pins. The candidate updates only affected framework/template/crypto/test and web dependencies, retains NumPy/pandas pins and every worker algorithm byte, regenerates locks, then reruns the selected assertions and an actual loopback study. The exact outcome is recorded in REPRODUCIBILITY.md; the private deployment was untouched.

Future work would need separately scoped decisions: stable build identity versus host attestation, wider platform testing, externally verifiable releases, and fully validated corrected financial semantics. These are not represented as completed features.
