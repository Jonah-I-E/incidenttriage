"""Tool integrations. These are mock adapters that write to var/outbox.jsonl so the prototype
runs anywhere; swap each class for a real client (Jira/ServiceNow, PagerDuty/Opsgenie, Slack,
your remediation API) behind the same method signature."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

OUTBOX = Path(__file__).resolve().parent.parent / "var" / "outbox.jsonl"


def _emit(kind: str, **fields) -> dict:
    rec = {"id": f"{kind[:3]}-{uuid.uuid4().hex[:8]}", "kind": kind,
           "at": datetime.now(timezone.utc).isoformat(), **fields}
    OUTBOX.parent.mkdir(parents=True, exist_ok=True)
    with OUTBOX.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


class TicketSystem:
    def create_ticket(self, team: str, priority: str, title: str, body: str) -> dict:
        return _emit("ticket", team=team, priority=priority, title=title, body=body)


class OnCallNotifier:
    # Team directory: who is on call. Replace with a PagerDuty/Opsgenie schedule lookup.
    DIRECTORY = {
        "Network Operations": "netops-oncall", "Database Team": "dba-oncall",
        "Application On-Call": "app-oncall", "SRE": "sre-oncall",
        "Security Operations": "soc-oncall", "Infrastructure / Platform": "platform-oncall",
        "Triage Desk": "triage-desk",
    }

    def page(self, team: str, priority: str, summary: str) -> dict:
        return _emit("page", team=team, target=self.DIRECTORY.get(team, "triage-desk"),
                     priority=priority, summary=summary)


class RemediationRunner:
    """Executes only allow-listed runbooks. Mock: records the request and reports success."""
    def run(self, runbook: str, host: str | None, service: str) -> dict:
        return _emit("remediation", runbook=runbook, host=host, service=service, status="succeeded")
