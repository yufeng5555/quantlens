# Explicit local educational trust

The historical registry admits exact identities. A new host/kernel, Python version, lockfile, or worker-source version changes the measured identity. Registering arbitrary environments invisibly would defeat this boundary. The candidate therefore requires an explicit `--accept-local-demo` setup command; ordinary launch never registers a new identity.

Before adding a registration, setup verifies the static `runtime-baseline.json` file hashes and source file set, checks all installed Python package versions against the lock, then measures the unchanged fingerprint algorithm with the five thread limits set to one. It preserves the supplied registry and appends only two exact legacy v1/v2 rows. The new byte pin and receipt are written under `var/local-runtime/`. No production system is contacted and no corrected v3 identity is added.

Every local launcher runs `--check`. A source/lock mismatch, missing or inconsistent receipt, registry-byte mismatch, or host/runtime drift is an error. Review changes and start from a clean release checkout rather than deleting guards or inventing the original deployment identity.

This is **local trust establishment by the checkout owner**, not an independent release signature, proof of financial correctness, or authorization to serve public users. A person controlling the entire source tree, baseline and environment can replace that local trust state; this limitation is explicit. Synthetic data remains synthetic and legacy evidence retains its unverified financial-semantics descriptor.

The prepared registry differs from the publishable base registry. A locally prepared working directory is therefore not the intended release payload. The private preparation record and clean release snapshot list exactly which bytes are eligible for publication. Do not upload `var/`, virtual environments, node modules, or the private audit directory.
