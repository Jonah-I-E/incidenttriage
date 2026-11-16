import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.analyzer import ClaudeAnalyzer, RulesAnalyzer
from triage.incident_log import IncidentLog
from triage.ingest import deduplicate, normalize, parse_upload
from triage.models import Action
from triage.pipeline import TriagePipeline


def pipe(tmp_path, analyzer=None):
    return TriagePipeline(analyzer=analyzer or RulesAnalyzer(), log=IncidentLog(tmp_path / "t.db"), execute_actions=False)


def test_normalizes_all_formats():
    prom = normalize({"labels": {"alertname": "X", "service": "s", "severity": "critical"},
                      "annotations": {"summary": "down"}, "startsAt": "2026-11-16T09:00:00Z"})
    tic = normalize({"ticket_id": "T1", "subject": "help", "body": "broken"})
    gen = normalize({"service": "a", "message": "m", "severity": "warning"})
    assert (prom.source, prom.service, prom.reported_severity) == ("prometheus", "s", "critical")
    assert (tic.source, tic.message, tic.error_details) == ("ticket", "help", "broken")
    assert gen.message == "m"


def test_dedup_folds_same_shape_messages():
    a = [normalize({"service": "api", "host": "h", "message": f"error rate {n}% on /x",
                    "timestamp": f"2026-11-16T09:0{n % 10}:00Z"}) for n in (21, 22, 23)]
    kept = deduplicate(a)
    assert len(kept) == 1 and kept[0].duplicate_count == 2


def test_log_and_csv_parsing():
    logs = parse_upload("x.log", (ROOT / "data/sample_syslog.log").read_text())
    assert len(logs) == 5  # INFO line skipped
    rows = parse_upload("x.csv", (ROOT / "data/sample_alerts.csv").read_text())
    assert rows[0]["alert_id"] == "C1"


def test_critical_floor_and_routing(tmp_path):
    d = pipe(tmp_path).process(normalize({"service": "endpoint-av", "message": "Ransomware behavior detected on host"}))
    assert d.priority == "critical" and d.team == "Security Operations" and d.action == Action.ROUTE_TO_TEAM


def test_vague_alert_goes_to_human(tmp_path):
    d = pipe(tmp_path).process(normalize({"ticket_id": "T9", "subject": "something seems off", "body": "not sure"}))
    assert d.action == Action.HUMAN_REVIEW and d.team == "Triage Desk"


def test_auto_remediation_only_for_known_low_risk(tmp_path):
    d = pipe(tmp_path).process(normalize({"service": "web-07", "message": "Disk usage at 88% on /var"}))
    assert d.action == Action.AUTO_REMEDIATE and d.runbook == "clear_tmp_and_rotate_logs"
    d2 = pipe(tmp_path).process(normalize({"service": "web-07", "message": "No space left on device, disk usage 100%"}))
    assert d2.action == Action.ROUTE_TO_TEAM  # high priority -> never auto-run


def test_analyzer_failure_falls_back_to_human_review(tmp_path):
    class Broken:
        name = "claude"
        def analyze(self, alert): raise TimeoutError("api down")
    d = pipe(tmp_path, Broken()).process(normalize({"service": "orders-db", "message": "deadlock detected"}))
    assert d.action == Action.HUMAN_REVIEW and "analyzer error" in d.reasons[0]


def test_incident_log_and_feedback(tmp_path):
    p = pipe(tmp_path)
    p.process(normalize({"service": "dns", "message": "NXDOMAIN spike"}))
    row = p.log.list()[0]
    assert p.log.feedback(row["id"], "corrected", correct_team="Network Operations")
    assert p.log.stats()["human_reviewed"] == 1


# ---- Claude path, exercised against a local fake Messages API ---------------------------
class FakeAPI(BaseHTTPRequestHandler):
    last_body = None
    def do_POST(self):
        FakeAPI.last_body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        verdict = {"category": "database", "severity": "high", "confidence": 0.9,
                   "summary": "Deadlocks on orders-db.", "likely_cause": "lock ordering", "analyzer": "x"}
        body = json.dumps({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                           "content": [{"type": "text", "text": json.dumps(verdict)}],
                           "stop_reason": "end_turn", "stop_sequence": None,
                           "usage": {"input_tokens": 10, "output_tokens": 10}}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass


def test_claude_analyzer_request_and_parse(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), FakeAPI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", f"http://127.0.0.1:{srv.server_port}")
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.delenv(k, raising=False)
    d = pipe(tmp_path, ClaudeAnalyzer()).process(
        normalize({"service": "orders-db", "message": "Deadlock detected in transaction"}))
    srv.shutdown()
    req = FakeAPI.last_body
    assert req["model"] == "claude-opus-5-5" and req["output_config"]["effort"] == "low"
    assert req["output_config"]["format"]["type"] == "json_schema" and req["fallbacks"] == "default"
    assert d.analysis.analyzer.startswith("claude") and d.category == "database"
    assert d.team == "Database Team" and d.confidence >= 0.85   # rules + model agree
