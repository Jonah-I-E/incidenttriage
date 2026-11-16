"""HTTP service: webhook/API ingestion, file upload, incident log, human feedback, dashboard.

    uvicorn app:app --reload --port 8000
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from triage.incident_log import IncidentLog
from triage.ingest import parse_upload
from triage.pipeline import TriagePipeline

app = FastAPI(title="Incident Triage Agent (prototype)")
log = IncidentLog()
pipeline = TriagePipeline(log=log)


def _brief(decisions):
    return [{"alert_id": d.alert.alert_id, "service": d.alert.service, "category": d.category,
             "priority": d.priority, "confidence": d.confidence, "action": d.action.value, "team": d.team,
             "runbook": d.runbook, "summary": d.analysis.summary, "duplicates_folded": d.alert.duplicate_count,
             "reasons": d.reasons, "processing_ms": d.processing_ms} for d in decisions]


@app.post("/alerts")
def receive_alerts(payload: Any = Body(...)):
    """Webhook/API endpoint. Accepts one alert, a list, or an Alertmanager envelope {"alerts": [...]}."""
    if isinstance(payload, dict) and "alerts" in payload:
        payload = payload["alerts"]
    items = payload if isinstance(payload, list) else [payload]
    if not all(isinstance(i, dict) for i in items):
        raise HTTPException(422, "expected JSON object(s)")
    return {"processed": _brief(pipeline.ingest(items, source_hint="webhook"))}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """Upload .json / .jsonl / .csv alerts or a plain log file."""
    text = (await file.read()).decode("utf-8", errors="replace")
    try:
        rows = parse_upload(file.filename or "upload.log", text)
    except Exception as e:
        raise HTTPException(400, f"could not parse file: {e}")
    return {"parsed": len(rows), "processed": _brief(pipeline.ingest(rows, source_hint="upload"))}


@app.get("/incidents")
def incidents(limit: int = 200):
    return log.list(limit)


@app.get("/stats")
def stats():
    return {**log.stats(), "analyzer": pipeline.analyzer.name}


class Feedback(BaseModel):
    outcome: str                       # e.g. "correct", "corrected", "false_positive"
    correct_category: Optional[str] = None
    correct_priority: Optional[str] = None
    correct_team: Optional[str] = None
    notes: Optional[str] = None


@app.post("/incidents/{incident_id}/feedback")
def feedback(incident_id: int, fb: Feedback):
    if not log.feedback(incident_id, fb.outcome, fb.correct_category, fb.correct_priority, fb.correct_team, fb.notes):
        raise HTTPException(404, "incident not found")
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "static" / "dashboard.html").read_text()
