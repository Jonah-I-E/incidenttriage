# Evidence of execution

Recorded runs of the agent, so the results can be inspected without running anything.
Each folder was produced by one command, `python record_evidence.py`, and can be regenerated the same way.

| Folder | Analyzer | Status |
|---|---|---|
| `rules-mode/` | Rules-only (no API key) | Recorded 2026-11-16 |
| `claude-mode/` | Claude (`claude-opus-5-5`) | Not yet recorded: run `python record_evidence.py` with `ANTHROPIC_API_KEY` set |

## What each file shows

| File | Contents |
|---|---|
| `01_tests.txt` | Full `pytest -v` output (9 tests) |
| `02_evaluation.txt` | `evaluate.py` scorecard against the M2.6 targets, with every misclassified alert listed |
| `02_evaluation_metrics.json` | The same metrics as JSON |
| `03_api_session.json` | A demo session through the real HTTP API: a webhook alert, a Prometheus envelope, a vague ticket, a log-file upload, a CSV upload, and two responder feedback calls. Each request is shown with the agent's response (category, priority, action, team, confidence, reasons) |
| `04_incident_log.json` | The incident log after the session: every decision with its reasons, tool calls and processing time |
| `05_stats.json` | Dashboard statistics: actions taken, priorities, average processing time, accuracy on human-reviewed incidents |
| `06_tool_calls_outbox.jsonl` | Every simulated tool call made: tickets created, on-call pages sent, runbooks executed |
| `RUN_INFO.json` | When and how the run was recorded |

## Things worth looking at

- **De-duplication:** in `03_api_session.json`, the two Postgres deadlock log lines become one incident (`duplicates_folded: 1`).
- **Human review:** the vague ticket and the ambiguous nginx error are sent to the Triage Desk instead of being guessed.
- **Auto-remediation guardrails:** the 86% disk alert runs a runbook; the 100% "no space left" alert is critical, so it is routed and paged instead.
- **Feedback loop:** the Triage Desk reassigns the nginx alert, and `05_stats.json` reflects that review.
- **Honest misses:** `02_evaluation.txt` lists every wrong answer, including alert A007 (a primary-database outage routed to Network instead of Database).
