from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from app.models.log_event import RawLogInput
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/logs", tags=["Logs & Ingestion"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

class BatchLogInput(BaseModel):
    logs: List[RawLogInput]

@router.post("/ingest")
def ingest_log(payload: RawLogInput, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Ingests and normalizes a single raw log, running it through detection and alerting."""
    try:
        result = pipeline.process_raw_log(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log ingestion error: {str(e)}")

@router.post("/ingest-batch")
def ingest_batch(payload: BatchLogInput, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Batch ingestion of multiple raw logs."""
    try:
        result = pipeline.process_batch_logs(payload.logs)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch ingestion error: {str(e)}")

@router.get("")
def list_logs(
    limit: int = Query(50, ge=1, le=500),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """Retrieves normalized logs from the SIEM database."""
    logs = pipeline.db.get_logs(limit=limit, category=category, search=search)
    return {"total": len(logs), "logs": logs}
