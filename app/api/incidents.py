from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional
from pydantic import BaseModel
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/incidents", tags=["SOC Incident Tickets"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

class StatusUpdatePayload(BaseModel):
    status: str
    assigned_analyst: Optional[str] = None

class AnalystNotePayload(BaseModel):
    author: str
    note: str

class ExecutePlaybookPayload(BaseModel):
    playbook_name: str
    target: str

@router.get("")
def list_incidents(
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """Lists SOC incident tickets."""
    incidents = pipeline.db.get_incidents(limit=limit, status=status)
    return {"total": len(incidents), "incidents": incidents}

@router.get("/{incident_id}")
def get_incident(incident_id: str, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Retrieves full investigation details for a specific incident ticket."""
    incident = pipeline.db.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/status")
def update_status(incident_id: str, payload: StatusUpdatePayload, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Updates incident status (open, triaged, in_progress, mitigated, closed)."""
    res = pipeline.incident_manager.update_incident_status(
        incident_id=incident_id,
        new_status=payload.status,
        analyst=payload.assigned_analyst
    )
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"message": "Status updated successfully", "incident": res}

@router.post("/{incident_id}/notes")
def add_note(incident_id: str, payload: AnalystNotePayload, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Adds an analyst investigation note to the incident ticket."""
    res = pipeline.incident_manager.add_analyst_note(
        incident_id=incident_id,
        author=payload.author,
        note_text=payload.note
    )
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"message": "Analyst note added", "incident": res}

@router.post("/{incident_id}/playbook")
def execute_manual_playbook(incident_id: str, payload: ExecutePlaybookPayload, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Executes a 1-click SOAR mitigation playbook from the incident view."""
    incident = pipeline.db.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_res = pipeline.soar.execute_playbook(
        playbook_name=payload.playbook_name,
        target=payload.target,
        incident_id=incident_id
    )

    # Append to incident automated actions & timeline
    incident["automated_actions"].append(action_res)
    incident["timeline"].append({
        "timestamp": action_res["timestamp"],
        "event_id": action_res["action_id"],
        "category": "soar",
        "action": payload.playbook_name,
        "status": "MANUAL_PLAYBOOK_EXECUTED",
        "detail": action_res["message"]
    })
    from app.models.incident import Incident
    pipeline.db.update_incident(Incident(**incident))

    return {"message": "Playbook executed successfully", "action": action_res}
