from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/soar", tags=["SOAR Automation"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

class TargetPayload(BaseModel):
    target: str

@router.get("/state")
def get_soar_state(pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Returns currently active containment rules and SOAR action history."""
    return pipeline.soar.get_mitigation_state()

@router.post("/unblock-ip")
def unblock_ip(payload: TargetPayload, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Removes an IP from active edge firewall blocklist."""
    success = pipeline.soar.unblock_ip(payload.target)
    return {"success": success, "message": f"IP {payload.target} unblocked from firewall."}

@router.post("/unisolate-host")
def unisolate_host(payload: TargetPayload, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Removes an endpoint from EDR network isolation."""
    success = pipeline.soar.unisolate_host(payload.target)
    return {"success": success, "message": f"Host {payload.target} restored to normal network access."}
