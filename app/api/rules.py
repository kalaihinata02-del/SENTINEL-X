from fastapi import APIRouter, HTTPException, Depends
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/rules", tags=["Detection Rules"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

@router.get("")
def list_rules(pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Lists all detection rules loaded in the engine."""
    rules = [r.model_dump(mode="json") for r in pipeline.detection_engine.rules.values()]
    return {"total": len(rules), "rules": rules}

@router.post("/{rule_id}/toggle")
def toggle_rule(rule_id: str, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Toggles a detection rule between enabled and disabled."""
    rule = pipeline.detection_engine.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    new_status = "disabled" if rule.status == "enabled" else "enabled"
    rule.status = new_status
    return {"rule_id": rule_id, "status": new_status, "message": f"Rule {rule_id} is now {new_status}"}

@router.post("/reload")
def reload_rules(pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Reloads detection rules from disk."""
    count = pipeline.detection_engine.load_rules()
    return {"message": f"Successfully reloaded {count} rules from disk"}
