"""Record an inspectable execution trace of the agent into evidence/<mode>/.

    python record_evidence.py                    # Claude if ANTHROPIC_API_KEY is set, else rules-only
    python record_evidence.py --analyzer rules   # force rules-only

Runs the test suite, the evaluation, and a demo session through the real HTTP API
(webhook + file uploads + feedback), then saves every output for graders to inspect.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], out: Path, env: dict) -> int:
    p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    out.write_text(f"$ {' '.join(cmd)}\n# exit code: {p.returncode}\n\n{p.stdout}{p.stderr}")
    return p.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyzer", choices=["auto", "rules", "claude"], default="auto")
    args = ap.parse_args()
    has_key = any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"))
    mode = args.analyzer if args.analyzer != "auto" else ("claude" if has_key else "rules")
    os.environ["TRIAGE_ANALYZER"] = mode
    env = {**os.environ}

    model = os.environ.get("TRIAGE_MODEL", "claude-opus-5-5")
    # default model -> evidence/claude-mode; another model (e.g. claude-haiku-5-5) -> evidence/claude-haiku-mode
    folder = mode if mode != "claude" or model == "claude-opus-5-5" else "claude-" + model.split("-")[1]
    out = ROOT / "evidence" / f"{folder}-mode"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    var = ROOT / "var"
    for f in ("incidents.db", "outbox.jsonl"):
        (var / f).unlink(missing_ok=True)

    print(f"Recording evidence in {out.relative_to(ROOT)} (analyzer: {mode})")
    run([sys.executable, "-m", "pytest", "-v", "tests"], out / "01_tests.txt", env)
    run([sys.executable, "evaluate.py", "--analyzer", mode, "--show-errors"], out / "02_evaluation.txt", env)
    shutil.copy(var / "last_eval.json", out / "02_evaluation_metrics.json")

    # Demo session through the real FastAPI app (in-process HTTP client)
    from fastapi.testclient import TestClient
    import app as service

    c = TestClient(service.app)
    demo = ROOT / "data"
    steps = []

    def record(name, resp):
        steps.append({"step": name, "status": resp.status_code, "response": resp.json()})

    record("POST /alerts  (webhook, single generic alert)", c.post("/alerts", json={
        "service": "checkout-api", "message": "HTTP 500 error rate above 30% on /checkout",
        "error_details": "NullPointerException in PaymentService.charge", "severity": "error"}))
    record("POST /alerts  (Prometheus Alertmanager envelope)", c.post("/alerts", json={"alerts": [{
        "labels": {"alertname": "KubeNodeNotReady", "service": "k8s", "instance": "worker-3", "severity": "warning"},
        "annotations": {"summary": "Node worker-3 NotReady", "description": "kubelet stopped posting node status"}}]}))
    record("POST /alerts  (vague submitted ticket)", c.post("/alerts", json={
        "ticket_id": "T-DEMO-1", "subject": "Something seems off with the system", "body": "Not sure what, can someone look?"}))
    for fname in ("sample_syslog.log", "sample_alerts.csv"):
        with open(demo / fname, "rb") as fh:
            record(f"POST /upload  ({fname})", c.post("/upload", files={"file": (fname, fh)}))
    record("POST /incidents/1/feedback  (responder confirms decision)",
           c.post("/incidents/1/feedback", json={"outcome": "correct"}))
    nginx = next((i for i in c.get("/incidents").json() if "upstream connect" in i["message"]), None)
    if nginx:  # the ambiguous alert the agent sent to human review; a responder resolves it
        record(f"POST /incidents/{nginx['id']}/feedback  (Triage Desk resolves a human-review item)",
               c.post(f"/incidents/{nginx['id']}/feedback", json={
                   "outcome": "corrected", "correct_category": "application", "correct_team": "Application On-Call",
                   "notes": "Reviewed by Triage Desk: upstream errors came from the app tier"}))

    (out / "03_api_session.json").write_text(json.dumps(steps, indent=1, default=str))
    (out / "04_incident_log.json").write_text(json.dumps(c.get("/incidents").json(), indent=1))
    (out / "05_stats.json").write_text(json.dumps(c.get("/stats").json(), indent=1))
    shutil.copy(var / "outbox.jsonl", out / "06_tool_calls_outbox.jsonl")

    (out / "RUN_INFO.json").write_text(json.dumps({
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "analyzer": service.pipeline.analyzer.name,
        "model": model if mode == "claude" else None,
        "python": sys.version.split()[0],
    }, indent=1))
    print("Done:", ", ".join(sorted(p.name for p in out.iterdir())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
