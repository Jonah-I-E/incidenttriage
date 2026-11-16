# Incident Triage Agent — Prototype

Automated incident triage: ingest alerts → normalize & de-duplicate → analyze (Claude + rules) →
prioritize → orchestrate (auto-remediate / route to team / human review) → log everything.

![dashboard](docs/dashboard.png)

**Evidence of execution:** recorded test, evaluation and demo-session output is in [`evidence/`](evidence/README.md).
Regenerate it with `python record_evidence.py`.

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


## Current results (39 synthetic labeled alerts, 35 after de-duplication)

| Metric | Rules-only | Claude Haiku 5.5 | Claude Opus 5.5 | Target |
|---|---|---|---|---|
| Category accuracy | 97.1% | 100.0% | **100.0%** | 90% |
| Severity accuracy | 48.6% ❌ | 68.6% ❌ | **71.4%** ❌ | 90% |
| Severity within one level | 97.1% | 100.0% | **100.0%** | — |
| Routing accuracy | **97.1%** | 94.3% ❌ | 94.3% ❌ | 95% |
| Avg processing time | < 1 ms | 1.7 s (max 3.0 s) | 2.7 s (max 6.0 s) | < 10 s |
| Critical alerts under-prioritized | 0 | 0 | 0 | 0 |
| Duplicates folded | 4/4 | 4/4 | 4/4 | — |

Claude gets every category right and lifts severity accuracy by 20+ points over keyword rules, but
neither model reaches the 90% severity target. Every severity miss is off by exactly one level.
Both models' routing misses are the same two alerts (A017, A030): the model disagreed with the rules
about the category with moderate confidence, so the agent sent them to human review instead of guessing.
That is the intended safety behavior, but it counts as a miss. Full output for all three runs is in
[`evidence/`](evidence/README.md). The 39 alerts are synthetic and the rules were written alongside them,
so treat these numbers as a smoke test and validate on real labeled alerts before quoting accuracy.

## Tuning knobs (env vars)
`TRIAGE_CONFIDENCE_THRESHOLD` (0.6), `TRIAGE_AUTO_MIN_CONFIDENCE` (0.8), `TRIAGE_AUTO_REMEDIATION` (1/0),
`TRIAGE_MODEL` (claude-opus-5-5). Categories, teams, severity floors and runbooks live in `triage/rules.py`.
