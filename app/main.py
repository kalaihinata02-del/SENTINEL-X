import os
from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.pipeline.orchestrator import SecurityPipeline
from app.api.logs import router as logs_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.rules import router as rules_router
from app.api.soar import router as soar_router
from app.api.simulation import router as sim_router

# Initialize FastAPI App
app = FastAPI(
    title="Enterprise SOC Detection Engineering & Automation Platform",
    description="Mini SIEM & SOAR detection engineering pipeline: Ingestion -> Normalization -> Detection Rules -> Alerts -> SOAR Playbooks -> Incident Tickets.",
    version="1.0.0"
)

# Enable CORS for local testing/cross-origin if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Pipeline Instance
pipeline = SecurityPipeline(db_path="soc_platform.db", rules_dir="rules")

# Include API Routers
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(rules_router)
app.include_router(soar_router)
app.include_router(sim_router)

# Mount Static directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    """Serves the main SOC Analyst Dashboard."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>SOC Platform is running. index.html not found yet.</h1>")

@app.get("/api/metrics")
def get_metrics():
    """Returns real-time SIEM & SOC health metrics."""
    db_metrics = pipeline.db.get_metrics()
    soar_state = pipeline.soar.get_mitigation_state()
    return {
        "status": "OPERATIONAL",
        "loaded_rules": len(pipeline.detection_engine.rules),
        "total_logs": db_metrics["total_logs"],
        "total_alerts": db_metrics["total_alerts"],
        "open_incidents": db_metrics["open_incidents"],
        "incident_severities": db_metrics["incident_severities"],
        "mitre_tactic_counts": db_metrics["mitre_tactic_counts"],
        "active_blocked_ips": len(soar_state["blocked_ips"]),
        "active_isolated_hosts": len(soar_state["isolated_hosts"]),
        "active_locked_accounts": len(soar_state["locked_accounts"])
    }
