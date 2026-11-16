"""Prioritization + orchestration: combine rules and model analysis, choose and execute an action."""
from __future__ import annotations

import os
import time
from typing import Iterable, Optional

from .analyzer import RulesAnalyzer, build_analyzer
from .incident_log import IncidentLog
from .ingest import deduplicate, normalize
from .integrations import OnCallNotifier, RemediationRunner, TicketSystem
from .models import SEVERITY_RANK, Action, Alert, Decision
from .rules import HUMAN_REVIEW_TEAM, TEAMS, evaluate_rules, find_runbook

CONFIDENCE_THRESHOLD = float(os.environ.get("TRIAGE_CONFIDENCE_THRESHOLD", "0.6"))
AUTO_REMEDIATE_MIN_CONFIDENCE = float(os.environ.get("TRIAGE_AUTO_MIN_CONFIDENCE", "0.8"))
AUTO_REMEDIATION_ENABLED = os.environ.get("TRIAGE_AUTO_REMEDIATION", "1") == "1"


class TriagePipeline:
    def __init__(self, analyzer=None, log: Optional[IncidentLog] = None, execute_actions: bool = True):
        self.analyzer = analyzer or build_analyzer()
        self.fallback = RulesAnalyzer()
        self.log = log
        self.execute_actions = execute_actions
        self.tickets, self.pager, self.remediation = TicketSystem(), OnCallNotifier(), RemediationRunner()

    # ---- public API -------------------------------------------------------------------
    def ingest(self, raw_alerts: Iterable[dict], source_hint: str = "api") -> list[Decision]:
        alerts = deduplicate([normalize(r, source_hint) for r in raw_alerts])
        return [self.process(a) for a in alerts]

    def process(self, alert: Alert) -> Decision:
        t0 = time.perf_counter()
        reasons: list[str] = []
        rule = evaluate_rules(alert)

        # 1) Analysis (LLM, falling back to rules on any API failure)
        try:
            analysis = self.analyzer.analyze(alert)
        except Exception as e:  # API down, timeout, refusal, bad output...
            analysis = self.fallback.analyze(alert)
            analysis.confidence = min(analysis.confidence, CONFIDENCE_THRESHOLD - 0.01)
            reasons.append(f"analyzer error, used rules fallback and forced review: {type(e).__name__}: {e}"[:200])

        # 2) Categorize: rules + model must agree to be fully trusted
        category, confidence = analysis.category, analysis.confidence
        if rule.category and analysis.analyzer != "rules":
            if rule.category == analysis.category:
                confidence = min(0.99, max(confidence, 0.85))
                reasons.append(f"rules and model agree on '{category}'")
            else:
                reasons.append(f"rules say '{rule.category}', model says '{analysis.category}'")
                if analysis.confidence < 0.8:
                    category = rule.category
                confidence = round(confidence * 0.7, 2)
        elif rule.category:
            reasons.append(f"rule match '{rule.category}' (score {rule.score:g})")
        else:
            reasons.append("no rule matched; relying on analyzer")

        # 3) Prioritize: model severity, but never below a rule-defined floor
        priority = analysis.severity
        if rule.severity_floor and SEVERITY_RANK[rule.severity_floor] > SEVERITY_RANK[priority]:
            reasons.append(f"severity raised {priority} -> {rule.severity_floor} by rule floor")
            priority = rule.severity_floor
        if alert.duplicate_count >= 10 and SEVERITY_RANK[priority] < SEVERITY_RANK["high"]:
            reasons.append(f"{alert.duplicate_count} duplicate alerts: priority raised to high")
            priority = "high"

        # 4) Orchestrate
        runbook = None
        if category == "unknown" or confidence < CONFIDENCE_THRESHOLD:
            action, team = Action.HUMAN_REVIEW, HUMAN_REVIEW_TEAM
            reasons.append(f"confidence {confidence:.2f} below {CONFIDENCE_THRESHOLD} or unknown category")
        else:
            team = TEAMS[category]
            rb = find_runbook(alert, category, priority) if AUTO_REMEDIATION_ENABLED else None
            if rb and confidence >= AUTO_REMEDIATE_MIN_CONFIDENCE:
                action, runbook = Action.AUTO_REMEDIATE, rb.name
                reasons.append(f"known low-risk issue: runbook '{rb.name}'")
            else:
                action = Action.ROUTE_TO_TEAM

        decision = Decision(alert=alert, rule_category=rule.category, rule_severity_floor=rule.severity_floor,
                            analysis=analysis, category=category, priority=priority,
                            confidence=round(confidence, 2), action=action, team=team, runbook=runbook,
                            reasons=reasons)
        if self.execute_actions:
            decision.integration_results = self._execute(decision)
        decision.processing_ms = round((time.perf_counter() - t0) * 1000, 1)
        if self.log:
            self.log.record(decision)
        return decision

    # ---- tool calls ---------------------------------------------------------------------
    def _execute(self, d: Decision) -> list[dict]:
        a, results = d.alert, []
        title = f"[{d.priority.upper()}] {a.service}: {a.message[:80]}"
        body = (f"{d.analysis.summary}\nLikely cause: {d.analysis.likely_cause}\n"
                f"Category: {d.category} (confidence {d.confidence})\nDuplicates folded: {a.duplicate_count}\n"
                f"Why: {'; '.join(d.reasons)}")
        try:
            if d.action == Action.AUTO_REMEDIATE:
                res = self.remediation.run(d.runbook, a.host, a.service)
                results.append(res)
                # FYI ticket so humans can audit automated actions
                results.append(self.tickets.create_ticket(d.team, "low", "[AUTO-RESOLVED] " + title,
                                                          body + f"\nRemediation: {res['status']}"))
                if res.get("status") != "succeeded":  # remediation failed -> escalate
                    results.append(self.pager.page(d.team, d.priority, title))
            else:
                results.append(self.tickets.create_ticket(d.team, d.priority, title, body))
                if d.priority in ("critical", "high"):
                    results.append(self.pager.page(d.team, d.priority, title))
        except Exception as e:  # integration failure must never drop an alert silently
            d.reasons.append(f"integration error: {e}")
            results.append({"kind": "error", "error": str(e)})
        return results
