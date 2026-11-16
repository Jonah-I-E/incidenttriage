"""Shared data models for the triage pipeline."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Category = Literal[
    "network", "database", "application", "performance",
    "security", "infrastructure", "unknown",
]
CATEGORIES: list[str] = list(Category.__args__)  # type: ignore[attr-defined]

Severity = Literal["critical", "high", "medium", "low"]
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Action(str, Enum):
    AUTO_REMEDIATE = "auto_remediate"   # known, low-risk issue with an approved runbook
    ROUTE_TO_TEAM = "route_to_team"     # ticket (+ page if critical/high) for the owning team
    HUMAN_REVIEW = "human_review"       # uncertain -> triage desk decides


class Alert(BaseModel):
    """Normalized alert: every input format is converted to this shape."""
    alert_id: str
    source: str                        # e.g. prometheus, datadog, syslog, ticket, csv
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    service: str = "unknown"
    host: Optional[str] = None
    message: str
    error_details: Optional[str] = None
    reported_severity: Optional[str] = None   # what the monitoring tool claimed, if anything
    context: dict[str, Any] = Field(default_factory=dict)
    duplicate_count: int = 0                  # how many duplicates were folded into this alert
    fingerprint: str = ""


class Analysis(BaseModel):
    """Output of an analyzer (Claude or the rules-only fallback). Kept deliberately short (M2.5)."""
    category: Category
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(description="One or two sentences, facts from the alert only.")
    likely_cause: str = Field(description="Short hypothesis, or 'unclear'.")
    analyzer: str = "rules"


class Decision(BaseModel):
    alert: Alert
    rule_category: Optional[str]
    rule_severity_floor: Optional[str]
    analysis: Analysis
    category: str
    priority: Severity
    confidence: float
    action: Action
    team: str
    runbook: Optional[str] = None
    reasons: list[str] = Field(default_factory=list)
    integration_results: list[dict[str, Any]] = Field(default_factory=list)
    processing_ms: float = 0.0
