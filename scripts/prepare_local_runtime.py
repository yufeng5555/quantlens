"""Explicit, source-checked registration for a fresh LOCAL educational checkout.

This does not approve a production build or the corrected v3 financial release.
The original registry pin, exact tuple checks and artifact checks remain enforced.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "services/backtest-worker/quantlens_worker/sealed_build_registrations.json"
BASE_PIN = "sha256:6350a4bf95626794c1ea9afbe6fac0bf8b6305279831fb30979db9d82f690f82"
LOCAL_CONTRACTS = ("legacy-battery-v1-ledger-v0", "legacy-battery-v2-ledger-v0")
THREADS = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
           "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS")


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def check_source() -> None:
    baseline = json.loads((ROOT / "docs/runtime-baseline.json").read_text())
    for relative, digest in baseline["files"].items():
        path = ROOT / relative
        if not path.is_file() or path.is_symlink() or sha(path.read_bytes()) != digest:
            raise RuntimeError(f"Source baseline mismatch: {relative}")
    source_paths = {
        str(p.relative_to(ROOT))
        for prefix in ("services", "packages")
        for p in (ROOT / prefix).rglob("*")
        if p.is_file() and p.suffix in {".py", ".json", ".j2", ".ts"}
        and p != REGISTRY
    }
    if source_paths != {p for p in baseline["files"] if p.startswith(("services/", "packages/"))}:
        raise RuntimeError("Source file set differs from the supplied baseline")
    for line in (ROOT / "requirements-lock.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, expected = line.split("==", 1)
        if importlib.metadata.version(name) != expected:
            raise RuntimeError(f"Installed dependency does not match lock: {name}")


def measure() -> str:
    for name in THREADS:
        os.environ[name] = "1"
    sys.path.insert(0, str(ROOT / "services/backtest-worker"))
    from quantlens_worker.config import image_digest
    return image_digest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept-local-demo", action="store_true",
                        help="Explicitly establish trust for this source-checked local demo only")
    parser.add_argument("--check", action="store_true", help="Verify an existing local registration")
    args = parser.parse_args()
    if not args.accept_local_demo and not args.check:
        parser.error("Read docs/LOCAL_RUNTIME.md, then use --accept-local-demo or --check")
    check_source()
    digest = measure()
    state = ROOT / "var/local-runtime"
    receipt_path = state / "receipt.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        if receipt["image_digest"] != digest or receipt["registry_sha256"] != sha(REGISTRY.read_bytes()):
            raise RuntimeError("Local registration drifted; use a fresh checked checkout and review changes")
        value = json.loads(REGISTRY.read_text())
        for contract in LOCAL_CONTRACTS:
            if {"contract_id": contract, "image_digest": digest} not in value["registrations"]:
                raise RuntimeError("Local registration is incomplete")
        print("Local demo registration verified: " + digest)
        return
    if args.check:
        raise RuntimeError("No local demo registration; preparation has not been accepted")
    if sha(REGISTRY.read_bytes()) != BASE_PIN:
        raise RuntimeError("Refusing to extend a registry that differs from the supplied base pin")
    value = json.loads(REGISTRY.read_text())
    added = []
    for contract in LOCAL_CONTRACTS:
        row = {"contract_id": contract, "image_digest": digest}
        if row not in value["registrations"]:
            value["registrations"].append(row)
            added.append(row)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    state.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY.with_suffix(".json.local-tmp")
    temporary.write_bytes(raw)
    temporary.replace(REGISTRY)
    pin = sha(raw)
    receipt = {"scope": "LOCAL_EDUCATIONAL_DEMO_ONLY", "base_registry_sha256": BASE_PIN,
               "registry_sha256": pin, "image_digest": digest, "added": added,
               "corrected_v3_registered": False, "financial_semantics_verified": False}
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    (state / "env.sh").write_text(
        f"export QL_SEALED_BUILD_REGISTRY_SHA256='{pin}'\n"
        "export QL_CORRECTED_READ_EXPECTATIONS_SHA256='sha256:9eb50321cc31f4132c16ea37e7fd395cb0fd0b6fa3859bc4ac4b3d20fb031b6f'\n"
        "export QL_AUTH_MODE='local-preview'\n")
    print("Explicit local educational registration created for v1/v2 only.")
    print("Registry pin: " + pin)
    print("Runtime identity: " + digest)
    print("No corrected-v3 registration or financial-semantics certification was created.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        raise SystemExit(str(exc)) from None
