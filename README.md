# Incident Triage Agent — Prototype

Automated incident triage: ingest alerts → normalize & de-duplicate → analyze (Claude + rules) →
prioritize → orchestrate (auto-remediate / route to team / human review) → log everything.

![dashboard](docs/dashboard.png)

## Run it

```bash
pip install -r requirements.txt
python evaluate.py --show-errors        # score against labeled sample alerts (M2.6 criteria)
python -m pytest -q tests               # unit tests
uvicorn app:app --port 8000             # web service + dashboard at http://localhost:8000
```

**Analyzer modes.** If `ANTHROPIC_API_KEY` is set, alerts are analyzed by Claude (`claude-opus-5-5`,
structured JSON output, low effort). Without a key it runs in **rules-only** mode so the demo works offline.
Force a mode with `TRIAGE_ANALYZER=rules|claude`, or `python evaluate.py --analyzer claude`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/alerts` | Webhook/API: one alert, a list, or a Prometheus Alertmanager envelope |
| POST | `/upload` | Upload `.json`, `.jsonl`, `.csv`, or plain log files |
| GET | `/incidents` | Incident log (every decision, action, reason) |
| POST | `/incidents/{id}/feedback` | Responder marks a decision correct / corrected |
| GET | `/stats` | Totals, action mix, avg latency, accuracy on human-reviewed incidents |

## How the code maps to the proposal

| Proposal section | Where |
|---|---|
| M2.2 Ingestion (APIs, webhooks, logs, tickets) | `triage/ingest.py` `normalize`, `parse_upload`, `app.py` |
| M2.2 Preprocessing: standardize + dedup | `triage/ingest.py` `fingerprint`, `deduplicate` (same service/host/message shape within 15 min) |
| M2.2/M2.3 AI analysis (Claude) | `triage/analyzer.py` `ClaudeAnalyzer` |
| M2.3 Rule system for categories & routing | `triage/rules.py` (keyword rules, severity floors, team table, runbooks) |
| M2.1 Prioritization (rules + model) | `triage/pipeline.py`: model severity, never below a rule floor; 10+ duplicates → at least high |
| M2.1 Orchestration | `triage/pipeline.py`: low confidence/unknown → **human review**; known low-risk + runbook + confidence ≥ 0.8 → **auto-remediate** (with FYI ticket); else **ticket + page if critical/high** |
| M2.2 Tool integration | `triage/integrations.py`: mock ticketing, on-call directory/pager, allow-listed remediation (write to `var/outbox.jsonl`; swap for Jira/PagerDuty/etc.) |
| M2.1 Incident log for performance review | `triage/incident_log.py` (SQLite `var/incidents.db`) + feedback endpoint |
| M2.4/M2.5 Risks & mitigations | Model returns only a short schema-validated verdict (no essays, no fixes); told not to invent facts; any API error/refusal → rules fallback **and forced human review**; rules and model must agree for high confidence; disagreement lowers confidence |
| M2.6 Success criteria | `evaluate.py` checks category ≥ 90%, severity ≥ 90%, routing ≥ 95%, < 10 s avg, 0 under-prioritized critical alerts |

## Current results (rules-only mode, 39 synthetic labeled alerts)

| Metric | Result | Target |
|---|---|---|
| Category accuracy | 97.1% | 90% ✅ |
| Severity accuracy | 48.6% | 90% ❌ |
| Routing accuracy | 97.1% | 95% ✅ |
| Avg processing time | < 1 ms | < 10 s ✅ |
| Critical alerts under-prioritized | 0 | 0 ✅ |
| Duplicates folded | 4/4, 0 false folds | — |

Keyword rules route well but estimate severity poorly (97% are within one level, though). That matches
the M2.3 argument for combining the two: rules for routing, the LLM for severity. **Claude mode has not been scored yet:**
run `python evaluate.py --analyzer claude` with an API key. The 39 alerts are synthetic and the rules were
written alongside them. Treat these numbers as a smoke test, and validate on real labeled alerts from your
team before quoting accuracy.

## Tuning knobs (env vars)
`TRIAGE_CONFIDENCE_THRESHOLD` (0.6), `TRIAGE_AUTO_MIN_CONFIDENCE` (0.8), `TRIAGE_AUTO_REMEDIATION` (1/0),
`TRIAGE_MODEL` (claude-opus-5-5). Categories, teams, severity floors and runbooks live in `triage/rules.py`.
