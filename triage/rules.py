"""Deterministic rule layer: categorization hints, severity floors, routing table, runbooks.

Edit this file (or replace it with a YAML loader) to tune the agent without touching code paths.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import SEVERITY_RANK, Alert

# --- Routing: category -> owning team -------------------------------------------------
TEAMS = {
    "network": "Network Operations",
    "database": "Database Team",
    "application": "Application On-Call",
    "performance": "SRE",
    "security": "Security Operations",
    "infrastructure": "Infrastructure / Platform",
    "unknown": "Triage Desk",
}
HUMAN_REVIEW_TEAM = "Triage Desk"

# --- Category keyword rules (pattern, weight) -------------------------------------------
CATEGORY_RULES: dict[str, list[tuple[str, float]]] = {
    "security": [
        (r"brute[- ]?force|failed (ssh |login )?(attempts?|logins?)|unauthori[sz]ed", 3),
        (r"malware|ransomware|intrusion|exfiltrat|suspicious|privilege escalation", 3),
        (r"\bwaf\b|sql injection|xss|blocked request|cve-\d+|certificate (revoked|mismatch)", 2.5),
        (r"\bfirewall\b.*(deny|denied|block)|port scan", 2.5),
    ],
    "database": [
        (r"\b(postgres|postgresql|mysql|mariadb|mongo(db)?|redis|oracle|sql server|rds)\b", 2),
        (r"deadlock|replication (lag|broken|stopped)|too many connections|connection pool exhausted", 3),
        (r"slow quer|query timeout|tablespace|\bwal\b|primary failover|replica", 2),
        (r"primary (db|database)|database (unreachable|down)|failover not triggered", 3),
    ],
    "network": [
        (r"packet loss|latency to|\bbgp\b|\bdns\b|nxdomain|unreachable|link (down|flap)", 3),
        (r"\bvpn\b|switch|router|interface (down|flap)|\bvlan\b|ping fail|tcp reset", 2.5),
        (r"load balancer health|upstream connect error|connection refused", 1.5),
    ],
    "infrastructure": [
        (r"disk (usage|space|full)|filesystem .*(full|\d+%)|no space left|inode", 3),
        (r"\bnode\b.*not ?ready|kubelet|host down|server down|power supply|\braid\b|kernel panic", 3),
        (r"memory usage|\boom\b|out of memory|swap|cpu usage|load average|container restart", 1.5),
        (r"backup (job )?fail|certificate\b.*\bexpir|ntp|clock skew", 2),
    ],
    "performance": [
        (r"p9[59] latency|response time|slow (page|response|endpoint)|latency (spike|increase|above)", 3),
        (r"throughput (drop|degraded)|apdex|queue (depth|backlog)|consumer lag|saturat", 2.5),
        (r"high cpu|cpu usage|memory usage", 1),
    ],
    "application": [
        (r"\b5\d\d\b|http 5|internal server error|exception|stack ?trace|traceback|nullpointer|segfault", 2.5),
        (r"error rate|crash(ed|loop)?|panic:|unhandled|deploy(ment)? fail|failed health ?check", 2),
        (r"\bapi\b|checkout|login page|payment|feature flag", 0.5),
    ],
}
MIN_RULE_SCORE = 2.0  # below this the rule layer abstains

# --- Severity floors: rules that guarantee a minimum priority (critical safety net) -------
SEVERITY_FLOORS: list[tuple[str, str]] = [
    (r"ransomware|exfiltrat|data breach|production (is )?down|total outage|all (users|requests)", "critical"),
    (r"payment|checkout|kernel panic|primary (db|database) (down|unreachable)|replication broken", "high"),
    (r"brute[- ]?force|malware|intrusion|privilege escalation|unauthori[sz]ed access", "high"),
    (r"no space left|disk (usage|space) (at |above )?(9[5-9]|100)%|out of memory", "high"),
]

# --- Severity keyword hints (used by rules-only analyzer) --------------------------------
SEVERITY_HINTS: list[tuple[str, str]] = [
    (r"outage|down\b|unreachable|data loss|breach|ransomware|exfiltrat|crashloop|all users|100% error", "critical"),
    (r"error rate (above|>) ?[1-9]\d%|failing|failed|deadlock|brute|replication|5\d\d|9[0-9]%|timeout|degraded", "high"),
    (r"warning|elevated|latency|slow|lag|8[0-9]%|retry|restart", "medium"),
    (r"info|notice|expiring in \d{2,} days|recovered|resolved|cleared", "low"),
]

# --- Runbooks: known, approved, low-risk automated actions -------------------------------
@dataclass(frozen=True)
class Runbook:
    name: str
    pattern: str
    category: str
    max_priority: str  # never auto-run above this priority
    description: str


RUNBOOKS = [
    Runbook("clear_tmp_and_rotate_logs", r"disk (usage|space)|filesystem .*(8\d|9[0-4])%",
            "infrastructure", "medium", "Rotate logs and clear /tmp on the affected host."),
    Runbook("restart_stuck_worker", r"(worker|consumer|job) (stuck|hung|not processing)|queue backlog",
            "performance", "medium", "Restart the stuck worker process via the orchestration API."),
    Runbook("renew_certificate", r"certificate\b.*\bexpir\w* in \d+ days",
            "infrastructure", "low", "Trigger ACME renewal for the expiring certificate."),
    Runbook("flush_dns_cache", r"stale dns|dns cache", "network", "low", "Flush resolver cache on the host."),
]


@dataclass
class RuleResult:
    category: Optional[str]
    score: float
    severity_floor: Optional[str]
    matched: list[str]


def _text(alert: Alert) -> str:
    return " ".join(filter(None, [alert.service, alert.message, alert.error_details])).lower()


def evaluate_rules(alert: Alert) -> RuleResult:
    text = _text(alert)
    scores: dict[str, float] = {}
    matched: list[str] = []
    for cat, rules in CATEGORY_RULES.items():
        for pattern, weight in rules:
            if re.search(pattern, text):
                scores[cat] = scores.get(cat, 0) + weight
                matched.append(f"{cat}:{pattern[:40]}")
    category, score = (max(scores.items(), key=lambda kv: kv[1]) if scores else (None, 0.0))
    if score < MIN_RULE_SCORE:
        category = None

    floor = None
    for pattern, sev in SEVERITY_FLOORS:
        if re.search(pattern, text) and (floor is None or SEVERITY_RANK[sev] > SEVERITY_RANK[floor]):
            floor = sev
    return RuleResult(category, score, floor, matched)


def keyword_severity(alert: Alert) -> str:
    text = _text(alert)
    for pattern, sev in SEVERITY_HINTS:  # ordered most -> least severe
        if re.search(pattern, text):
            return sev
    rs = (alert.reported_severity or "").lower()
    return {"crit": "critical", "critical": "critical", "error": "high", "high": "high",
            "warn": "medium", "warning": "medium", "info": "low"}.get(rs, "medium")


def find_runbook(alert: Alert, category: str, priority: str) -> Optional[Runbook]:
    text = _text(alert)
    for rb in RUNBOOKS:
        if rb.category == category and re.search(rb.pattern, text) \
                and SEVERITY_RANK[priority] <= SEVERITY_RANK[rb.max_priority]:
            return rb
    return None
