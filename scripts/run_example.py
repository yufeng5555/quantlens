"""Run the synthetic v2 example through a real loopback API and worker."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import time
import urllib.parse
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-origin", default="http://127.0.0.1:8000")
    parser.add_argument("--output", default="var/example-report")
    parser.add_argument("--state-directory", default="var",
                        help="Local worker state directory, relative to this checkout")
    args = parser.parse_args()
    origin = args.api_origin.rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if (parsed.scheme != "http" or not loopback or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        parser.error("Only a plain loopback http origin is accepted")
    output = (ROOT / args.output).resolve()
    state = (ROOT / args.state_directory).resolve()
    if not output.is_relative_to(ROOT / "var"):
        parser.error("Example output must remain inside this checkout's ignored var directory")
    if not state.is_relative_to(ROOT / "var"):
        parser.error("Worker state must remain inside this checkout's ignored var directory")
    if output.exists() and any(output.iterdir()):
        parser.error("Output directory is not empty; use a fresh --output under var/")

    def request(path: str, payload: dict | None = None, *, html: bool = False):
        raw = None if payload is None else json.dumps(payload).encode()
        headers = {} if raw is None else {"Content-Type": "application/json"}
        try:
            with urllib.request.urlopen(
                urllib.request.Request(origin + path, data=raw, headers=headers), timeout=20
            ) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            error = json.loads(exc.read())
            detail = error.get("detail", {})
            code = detail.get("code", "API_REFUSED") if isinstance(detail, dict) else "API_REFUSED"
            raise RuntimeError(f"API refused {path}: HTTP {exc.code}, {code}") from None
        return body.decode("utf8") if html else json.loads(body)

    health = request("/health")
    if health.get("ok") is not True:
        raise RuntimeError("API is not healthy")
    spec = json.loads((ROOT / "examples/strategy.json").read_text())
    validation = request("/specs/validate", {"spec": spec, "battery_profile": "battery-v2"})
    if not validation.get("valid") or not validation["preflight"]["can_run"]:
        raise RuntimeError("Example validation/preflight refused")
    receipt = {
        "spec": spec, "battery_profile": "battery-v2", "research_mode": "formal",
        "confirmed": True, "restatement_seen": True,
        "confirmed_spec_hash": validation["spec_hash"],
        "confirmed_battery_profile_hash": validation["battery_profile"]["profile_hash"],
        "confirmed_preflight_hash": validation["preflight"]["preflight_hash"],
        "acknowledged_preflight_warning_ids": validation["preflight"]["required_acknowledgement_ids"],
    }
    run_id = request("/runs", receipt)["run_id"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        run = request(f"/runs/{run_id}")
        status = run["status"]
        if status == "published":
            break
        if status.endswith("failed") or status in {"unsupported_contract", "integrity_error"}:
            raise RuntimeError("Example run failed: " + status)
        time.sleep(0.25)
    else:
        raise RuntimeError("Example did not publish within 120 seconds")
    evidence = request(f"/runs/{run_id}/evidence")
    manifest = request(f"/runs/{run_id}/manifest")
    ledger = request(f"/runs/{run_id}/artifacts")
    report = request(f"/runs/{run_id}/report", html=True)
    audit = evidence["final_holdout_execution_audit"]
    assert manifest["data_label"] == "SYNTHETIC"
    assert evidence["evidence_view_version"] == "v2"
    assert audit["primary_evaluation_count"] == 1
    assert audit["counterfactual_evaluation_count"] == 0
    assert evidence["sensitivity"]["grid"] == []
    assert manifest["result_hash"] == ledger["result_hash"]
    assert "SYNTHETIC" in report
    exported_artifacts = {}
    for entry in ledger["entries"]:
        leaf = entry["path"]
        if Path(leaf).name != leaf or leaf in {".", ".."}:
            raise RuntimeError("Unsafe artifact filename")
        path = state / "artifacts" / run_id / leaf
        if path.is_symlink():
            raise RuntimeError("Artifact symlinks are not accepted")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise RuntimeError("Artifact changed after checked API read: " + leaf)
        exported_artifacts[leaf] = raw
    output.mkdir(parents=True, exist_ok=True)
    (output / "artifacts").mkdir()
    for leaf, raw in exported_artifacts.items():
        (output / "artifacts" / leaf).write_bytes(raw)
    for filename, value in {
        "strategy.json": spec, "validation.json": validation, "run.json": run,
        "evidence.json": evidence, "manifest.json": manifest, "ledger.json": ledger,
    }.items():
        (output / filename).write_text(json.dumps(value, indent=2) + "\n")
    (output / "report.html").write_text(report)
    checks = {"status": status, "data_label": manifest["data_label"], "battery_profile": "battery-v2",
              "parameter_sensitivity": "NOT_RUN", "primary_final_evaluations": 1,
              "final_counterfactual_evaluations": 0, "result_hash": ledger["result_hash"],
              "report_sha256": hashlib.sha256(report.encode()).hexdigest()}
    (output / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps(checks, indent=2))
    print("Saved example under " + str(output.relative_to(ROOT)))


if __name__ == "__main__":
    main()
