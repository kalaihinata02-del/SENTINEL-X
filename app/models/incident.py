from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid

class IncidentNote(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    author: str
    note: str

class SoarActionLog(BaseModel):
    action_id: str = Field(default_factory=lambda: f"ACT-{str(uuid.uuid4())[:6].upper()}")
    playbook_name: str
    target_entity: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "success"  # success, simulated, failed
    details: str

class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str  # critical, high, medium, low
    status: str = "open"  # open, triaged, in_progress, mitigated, closed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assigned_analyst: str = "Unassigned"
    category: str = "general"
    
    # MITRE ATT&CK
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    summary: str
    primary_ip: Optional[str] = None
    primary_user: Optional[str] = None
    primary_host: Optional[str] = None
    
    alert_ids: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    
    recommended_response: str = ""
    automated_actions: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)
