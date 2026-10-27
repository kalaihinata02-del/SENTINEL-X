from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid

class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{str(uuid.uuid4())[:8].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    rule_title: str
    severity: str  # critical, high, medium, low, info
    category: str  # authentication, endpoint, network, cloud
    mitre_attack: Dict[str, str] = Field(default_factory=dict)
    
    # Aggregated entity indicators
    entities: Dict[str, Any] = Field(default_factory=dict)  # {"src_ip": "...", "user": "...", "host": "..."}
    event_count: int = 1
    evidence_event_ids: List[str] = Field(default_factory=list)
    evidence_events: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Enrichment
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    
    # SOC metadata
    status: str = Field(default="new")  # new, triaged, escalated, resolved
    incident_id: Optional[str] = None
    recommended_response: str = ""
    soar_playbook: Optional[str] = None
