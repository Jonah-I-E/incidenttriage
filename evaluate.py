"""Evaluate the agent against labeled alerts and check the M2.6 success criteria.

    python evaluate.py                       # uses Claude if ANTHROPIC_API_KEY is set, else rules-only
    python evaluate.py --analyzer rules      # force offline mode
    python evaluate.py --data my_labels.json --show-errors
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path

TARGETS = {"category": 0.90, "severity": 0.90, "routing": 0.95, "avg_seconds": 10.0}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--data", default=str(Path(__file__).parent / "data" / "labeled_alerts.json"))
    p.add_argument("--analyzer", choices=["auto", "rules", "claude"], default="auto")
    p.add_argument("--show-errors", action="store_true")
    args = p.parse_args()
    os.environ["TRIAGE_ANALYZER"] = args.analyzer

    from triage.pipeline import TriagePipeline  # import after env is set

    rows = json.loads(Path(args.data).read_text())
    labels = {(r.get("alert_id") or r.get("fingerprint") or r.get("ticket_id")): r["label"] for r in rows}

    pipe = TriagePipeline(execute_actions=False)  # don't create tickets/pages during evaluation
    decisions = pipe.ingest(rows, source_hint="eval")

    # De-duplication check
    expected_dups = {k for k, l in labels.items() if l.get("duplicate_of")}
    kept_ids = {d.alert.alert_id for d in decisions}
    dup_folded = len(expected_dups - kept_ids)
    false_folds = [k for k in labels if k not in expected_dups and k not in kept_ids]

    n = cat_ok = sev_ok = route_ok = 0
    sev_off_by_one = critical_missed = 0
    errors = []
    for d in decisions:
        lab = labels.get(d.alert.alert_id)
        if not lab or lab.get("duplicate_of"):
            continue
        n += 1
        c = d.category == lab["category"]
        s = d.priority == lab["severity"]
        r = d.team == lab["team"]
        cat_ok += c; sev_ok += s; route_ok += r
        from triage.models import SEVERITY_RANK as R
        sev_off_by_one += abs(R[d.priority] - R[lab["severity"]]) <= 1
        if lab["severity"] == "critical" and R[d.priority] < R["high"]:
            critical_missed += 1
        if not (c and s and r):
            errors.append((d.alert.alert_id, d.alert.message[:60], lab, d))

    times = [d.processing_ms / 1000 for d in decisions]
    results = {
        "analyzer": decisions[0].analysis.analyzer if decisions else None,
        "alerts_in": len(rows), "after_dedup": len(decisions),
        "duplicates_folded": f"{dup_folded}/{len(expected_dups)}", "wrongly_folded": len(false_folds),
        "category": cat_ok / n, "severity": sev_ok / n, "severity_within_one_level": sev_off_by_one / n,
        "routing": route_ok / n, "critical_underprioritized": critical_missed,
        "avg_seconds": statistics.mean(times), "max_seconds": max(times),
        "actions": {a: sum(d.action.value == a for d in decisions)
                    for a in ("route_to_team", "auto_remediate", "human_review")},
    }

    print(f"\nAnalyzer: {results['analyzer']}   alerts: {results['alerts_in']} -> {results['after_dedup']} after de-dup "
          f"(folded {results['duplicates_folded']} expected duplicates, {results['wrongly_folded']} wrongly folded)\n")
    print(f"{'Metric':<28}{'Result':>10}{'Target':>10}   Pass")
    allpass = True
    for k, label in [("category", "Category accuracy"), ("severity", "Severity accuracy"), ("routing", "Routing accuracy")]:
        ok = results[k] >= TARGETS[k]; allpass &= ok
        print(f"{label:<28}{results[k]:>9.1%}{TARGETS[k]:>9.0%}    {'PASS' if ok else 'FAIL'}")
    ok = results["avg_seconds"] < TARGETS["avg_seconds"]; allpass &= ok
    print(f"{'Avg processing time':<28}{results['avg_seconds']:>9.3f}s{'<10s':>10}    {'PASS' if ok else 'FAIL'}")
    ok = results["critical_underprioritized"] == 0; allpass &= ok
    print(f"{'Critical alerts under-prio':<28}{results['critical_underprioritized']:>10}{'0':>10}    {'PASS' if ok else 'FAIL'}")
    print(f"\nSeverity within one level: {results['severity_within_one_level']:.1%}   max latency: {results['max_seconds']:.3f}s")
    print("Actions:", results["actions"])

    if args.show_errors and errors:
        print("\nMisses (id | message | expected -> got):")
        for aid, msg, lab, d in errors:
            print(f"  {aid} | {msg}\n      expected {lab['category']}/{lab['severity']}/{lab['team']}"
                  f" -> got {d.category}/{d.priority}/{d.team} ({d.action.value}, conf {d.confidence})")
    Path(__file__).with_name("var").mkdir(exist_ok=True)
    Path(__file__).with_name("var").joinpath("last_eval.json").write_text(json.dumps(results, indent=1, default=str))
    return 0 if allpass else 1


if __name__ == "__main__":
    sys.exit(main())
