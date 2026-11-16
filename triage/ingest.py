"""Ingestion + preprocessing: accept many alert formats, normalize, de-duplicate."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .models import Alert


def _ts(value: Any) -> datetime:
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _first(d: dict, *keys, default=None):
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return default


def normalize(raw: dict[str, Any], source_hint: str = "api") -> Alert:
    """Map a raw payload from any supported source onto the Alert schema."""
    # Prometheus Alertmanager: {"labels": {...}, "annotations": {...}, "startsAt": ...}
    if "labels" in raw and "annotations" in raw:
        labels, ann = raw.get("labels", {}), raw.get("annotations", {})
        return Alert(
            alert_id=str(raw.get("fingerprint") or uuid.uuid4().hex[:12]),
            source="prometheus",
            timestamp=_ts(raw.get("startsAt")),
            service=labels.get("service") or labels.get("job") or "unknown",
            host=labels.get("instance"),
            message=ann.get("summary") or labels.get("alertname", ""),
            error_details=ann.get("description"),
            reported_severity=labels.get("severity"),
            context={k: v for k, v in labels.items() if k not in {"service", "job", "instance", "severity"}},
        )
    # Submitted ticket: {"ticket_id", "subject", "body", ...}
    if "ticket_id" in raw or "subject" in raw:
        return Alert(
            alert_id=str(_first(raw, "ticket_id", "id", default=uuid.uuid4().hex[:12])),
            source="ticket",
            timestamp=_ts(_first(raw, "created_at", "timestamp")),
            service=_first(raw, "service", "component", default="unknown"),
            message=_first(raw, "subject", "title", default=""),
            error_details=_first(raw, "body", "description"),
            reported_severity=_first(raw, "priority", "severity"),
            context={"reporter": raw.get("reporter")} if raw.get("reporter") else {},
        )
    # Generic / Datadog-like / CSV row
    known = {"id", "alert_id", "source", "timestamp", "date_happened", "time", "service", "host",
             "message", "title", "text", "error", "error_details", "severity", "priority", "alert_type", "label"}
    return Alert(
        alert_id=str(_first(raw, "alert_id", "id", default=uuid.uuid4().hex[:12])),
        source=str(_first(raw, "source", default=source_hint)),
        timestamp=_ts(_first(raw, "timestamp", "date_happened", "time")),
        service=str(_first(raw, "service", default="unknown")),
        host=_first(raw, "host"),
        message=str(_first(raw, "message", "title", default="")),
        error_details=_first(raw, "error_details", "error", "text"),
        reported_severity=_first(raw, "severity", "priority", "alert_type"),
        context={k: v for k, v in raw.items() if k not in known},
    )


SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?)\s+(?P<host>\S+)\s+(?P<service>[\w\-.\/]+)(\[\d+\])?:\s*"
    r"(?:(?P<level>DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRIT|CRITICAL|FATAL|ALERT)\s*[:\-]?\s*)?(?P<msg>.*)$",
    re.I,
)


def parse_log_text(text: str) -> list[dict]:
    """Parse plain log lines (ISO-timestamp syslog style). Lines below WARN are skipped."""
    rows = []
    for line in text.splitlines():
        m = SYSLOG_RE.match(line.strip())
        if not m:
            continue
        level = (m.group("level") or "").upper()
        if level in {"DEBUG", "INFO", "NOTICE"}:
            continue
        rows.append({"source": "log", "timestamp": m.group("ts"), "host": m.group("host"),
                     "service": m.group("service"), "message": m.group("msg"), "severity": level or None})
    return rows


def parse_upload(filename: str, content: str) -> list[dict]:
    name = filename.lower()
    if name.endswith(".json"):
        data = json.loads(content)
        if isinstance(data, dict) and "alerts" in data:   # Alertmanager webhook envelope
            data = data["alerts"]
        return data if isinstance(data, list) else [data]
    if name.endswith(".jsonl"):
        return [json.loads(l) for l in content.splitlines() if l.strip()]
    if name.endswith(".csv"):
        return [dict(r) for r in csv.DictReader(io.StringIO(content))]
    return parse_log_text(content)


# --- De-duplication --------------------------------------------------------------------
_VOLATILE = re.compile(r"\b(0x[0-9a-f]+|[0-9a-f]{8,}|\d+(\.\d+)?)\b", re.I)


def fingerprint(alert: Alert) -> str:
    """Same service + host + message 'shape' (numbers/ids stripped) => same incident."""
    shape = _VOLATILE.sub("#", alert.message.lower()).strip()
    return hashlib.sha1(f"{alert.service}|{alert.host}|{shape}".encode()).hexdigest()[:16]


def deduplicate(alerts: Iterable[Alert], window: timedelta = timedelta(minutes=15)) -> list[Alert]:
    """Collapse alerts with the same fingerprint seen within `window` of the first occurrence."""
    kept: list[Alert] = []
    first_seen: dict[str, Alert] = {}
    for a in sorted(alerts, key=lambda x: x.timestamp):
        a.fingerprint = fingerprint(a)
        prev = first_seen.get(a.fingerprint)
        if prev and a.timestamp - prev.timestamp <= window:
            prev.duplicate_count += 1
            continue
        first_seen[a.fingerprint] = a
        kept.append(a)
    return kept
