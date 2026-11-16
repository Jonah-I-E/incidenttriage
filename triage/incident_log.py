"""Incident log: every decision, action and (later) human-confirmed outcome, in SQLite."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from .models import Decision

DEFAULT_DB = Path(__file__).resolve().parent.parent / "var" / "incidents.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  logged_at TEXT DEFAULT CURRENT_TIMESTAMP,
  alert_id TEXT, source TEXT, service TEXT, message TEXT,
  duplicate_count INTEGER, category TEXT, priority TEXT, confidence REAL,
  action TEXT, team TEXT, runbook TEXT, analyzer TEXT, summary TEXT,
  reasons TEXT, integration_results TEXT, processing_ms REAL, decision_json TEXT,
  -- human feedback, filled in by responders to measure agent performance
  outcome TEXT, correct_category TEXT, correct_priority TEXT, correct_team TEXT, reviewer_notes TEXT
);
"""


class IncidentLog:
    def __init__(self, path: Path | str = DEFAULT_DB):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._db.executescript(SCHEMA)

    def record(self, d: Decision) -> int:
        with self._lock:
            cur = self._db.execute(
                """INSERT INTO incidents (alert_id, source, service, message, duplicate_count, category,
                   priority, confidence, action, team, runbook, analyzer, summary, reasons,
                   integration_results, processing_ms, decision_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (d.alert.alert_id, d.alert.source, d.alert.service, d.alert.message, d.alert.duplicate_count,
                 d.category, d.priority, d.confidence, d.action.value, d.team, d.runbook, d.analysis.analyzer,
                 d.analysis.summary, json.dumps(d.reasons), json.dumps(d.integration_results),
                 d.processing_ms, d.model_dump_json()))
            self._db.commit()
            return cur.lastrowid

    def feedback(self, incident_id: int, outcome: str, correct_category: Optional[str] = None,
                 correct_priority: Optional[str] = None, correct_team: Optional[str] = None,
                 notes: Optional[str] = None) -> bool:
        with self._lock:
            cur = self._db.execute(
                """UPDATE incidents SET outcome=?, correct_category=?, correct_priority=?, correct_team=?,
                   reviewer_notes=? WHERE id=?""",
                (outcome, correct_category, correct_priority, correct_team, notes, incident_id))
            self._db.commit()
            return cur.rowcount == 1

    def list(self, limit: int = 200) -> list[dict]:
        rows = self._db.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{k: r[k] for k in r.keys() if k != "decision_json"} for r in rows]

    def stats(self) -> dict:
        q = lambda sql: self._db.execute(sql).fetchall()
        reviewed = q("""SELECT COUNT(*) n,
            SUM(correct_category IS NULL OR correct_category = category) cat_ok,
            SUM(correct_priority IS NULL OR correct_priority = priority) pri_ok,
            SUM(correct_team IS NULL OR correct_team = team) team_ok
            FROM incidents WHERE outcome IS NOT NULL""")[0]
        return {
            "total": q("SELECT COUNT(*) FROM incidents")[0][0],
            "by_action": {r[0]: r[1] for r in q("SELECT action, COUNT(*) FROM incidents GROUP BY action")},
            "by_priority": {r[0]: r[1] for r in q("SELECT priority, COUNT(*) FROM incidents GROUP BY priority")},
            "avg_processing_ms": round(q("SELECT AVG(processing_ms) FROM incidents")[0][0] or 0, 1),
            "human_reviewed": reviewed["n"],
            "reviewed_accuracy": None if not reviewed["n"] else {
                "category": round(reviewed["cat_ok"] / reviewed["n"], 3),
                "priority": round(reviewed["pri_ok"] / reviewed["n"], 3),
                "team": round(reviewed["team_ok"] / reviewed["n"], 3)},
        }
