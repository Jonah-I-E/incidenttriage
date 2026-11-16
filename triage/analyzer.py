"""Analysis component: Claude (when configured) or a rules-only fallback.

Per M2.4/M2.5 the model is asked for a short, structured verdict only - no free-form essays -
which keeps cost and latency down and limits room for fabrication.
"""
from __future__ import annotations

import json
import os
import re

from .models import CATEGORIES, Alert, Analysis
from .rules import evaluate_rules, keyword_severity

MODEL = os.environ.get("TRIAGE_MODEL", "claude-opus-5-5")

SYSTEM_PROMPT = f"""You are an incident triage classifier for an IT operations team.
For the single alert you are given, return:
- category: one of {", ".join(CATEGORIES)}. Use "unknown" if the alert does not give enough evidence.
- severity: critical (outage, data loss, security breach, revenue-impacting), high (major feature
  broken or imminent outage), medium (degraded, needs attention today), low (informational/self-healing).
- confidence: 0-1, how sure you are of the category AND severity. Be calibrated; vague alerts deserve < 0.6.
- summary: at most two sentences, using only facts present in the alert.
- likely_cause: a short hypothesis, or "unclear".
Do not invent hosts, metrics, or events that are not in the alert. Do not propose fixes."""


class RulesAnalyzer:
    """Offline analyzer: keyword rules for category and severity. Always available."""
    name = "rules"

    def analyze(self, alert: Alert) -> Analysis:
        r = evaluate_rules(alert)
        category = r.category or "unknown"
        # crude calibration: stronger/more rule hits => higher confidence
        confidence = 0.4 if r.category is None else min(0.95, 0.55 + 0.1 * r.score)
        msg = alert.message.strip()
        summary = f"{alert.service}: {msg[:160]}" + (f" ({alert.duplicate_count} duplicates folded)" if alert.duplicate_count else "")
        return Analysis(category=category, severity=keyword_severity(alert), confidence=round(confidence, 2),
                        summary=summary, likely_cause="unclear", analyzer=self.name)


class ClaudeAnalyzer:
    """LLM analyzer using the Anthropic SDK with structured (schema-validated) output."""
    name = "claude"

    def __init__(self, model: str = MODEL):
        import anthropic  # imported lazily so offline mode needs no SDK
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(timeout=30.0, max_retries=2)
        self.model = model

    def analyze(self, alert: Alert) -> Analysis:
        payload = alert.model_dump(mode="json", exclude={"fingerprint"})
        resp = self.client.beta.messages.parse(
            model=self.model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            output_config={"effort": "low"},          # classification: low effort is enough & fast
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",                       # if the model declines, server retries on a fallback
            output_format=Analysis,
            messages=[{"role": "user", "content": "Alert:\n" + json.dumps(payload, indent=1)}],
        )
        if resp.stop_reason == "refusal" or resp.parsed_output is None:
            raise RuntimeError(f"model returned no verdict (stop_reason={resp.stop_reason})")
        out = resp.parsed_output
        out.analyzer = f"claude:{resp.model}"
        return out


def build_analyzer():
    """Use Claude when credentials exist (or TRIAGE_ANALYZER=claude), else rules-only."""
    mode = os.environ.get("TRIAGE_ANALYZER", "auto")
    if mode == "rules":
        return RulesAnalyzer()
    has_creds = any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"))
    if mode == "claude" or has_creds:
        return ClaudeAnalyzer()
    return RulesAnalyzer()
