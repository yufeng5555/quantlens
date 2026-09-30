"""Independently check the internal byte consistency of a synthetic example.

This is not an external signature or financial-semantics certification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", default="examples/sample-report")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    directory = (root / args.directory).resolve()
    ledger = json.loads((directory / "ledger.json").read_text())
    manifest = json.loads((directory / "manifest.json").read_text())
    checks = json.loads((directory / "checks.json").read_text())
    hashes = []
    for entry in ledger["entries"]:
        leaf = entry["path"]
        if Path(leaf).name != leaf or leaf in {".", ".."}:
            raise RuntimeError("Unsafe artifact filename")
        path = directory / "artifacts" / leaf
        if path.is_symlink():
            raise RuntimeError("Artifact symlinks are not accepted")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise RuntimeError("Artifact hash mismatch: " + leaf)
        wrapper = json.loads(path.read_text())
        if wrapper["kind"] != entry["kind"] or wrapper["producer"] != entry["producer"]:
            raise RuntimeError("Artifact wrapper mismatch: " + leaf)
        hashes.append(digest)
    result = "sha256:" + hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()
    if not result == ledger["result_hash"] == manifest["result_hash"] == checks["result_hash"]:
        raise RuntimeError("Result/manifest/index binding mismatch")
    report_sha = hashlib.sha256((directory / "report.html").read_bytes()).hexdigest()
    if report_sha != checks["report_sha256"]:
        raise RuntimeError("Report byte hash mismatch")
    if manifest["data_label"] != "SYNTHETIC":
        raise RuntimeError("Only this release's synthetic example is accepted")
    snapshot = json.loads((root / "data/synthetic/snapshot.json").read_text())
    if manifest["snapshot_id"] != snapshot["snapshot_id"]:
        raise RuntimeError("Example snapshot differs from the included fixture")
    for leaf, expected in snapshot["files"].items():
        if Path(leaf).name != leaf:
            raise RuntimeError("Unsafe snapshot filename")
        if hashlib.sha256((root / "data/synthetic" / leaf).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Synthetic data hash mismatch: " + leaf)
    print(f"Verified {len(hashes)} artifact bytes, result/manifest binding, report bytes and synthetic files.")
    print("Scope: internal consistency only; no external authenticity or financial-correctness claim.")


if __name__ == "__main__":
    main()
