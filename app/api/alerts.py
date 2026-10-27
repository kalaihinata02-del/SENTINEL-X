from fastapi import APIRouter, Query, Depends
from typing import Optional
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/alerts", tags=["Detection Alerts"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

@router.get("")
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """Lists detection alerts with optional severity filtering."""
    alerts = pipeline.db.get_alerts(limit=limit, severity=severity)
    return {"total": len(alerts), "alerts": alerts}
