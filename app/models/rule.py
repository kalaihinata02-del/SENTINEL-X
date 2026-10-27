from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class MitreAttack(BaseModel):
    tactic: str = Field(..., description="MITRE ATT&CK Tactic (e.g., Initial Access, Execution)")
    technique_id: str = Field(..., description="MITRE Technique ID (e.g., T1110, T1059.001)")
    technique_name: str = Field(..., description="MITRE Technique Name (e.g., Brute Force)")

class DetectionCondition(BaseModel):
    field: str = Field(..., description="Field in NormalizedEvent to test (e.g., action, process_command_line)")
    operator: str = Field(default="equals", description="equals, not_equals, contains, regex, in_list, exists")
    value: Any = Field(..., description="Value or pattern to match against")

class DetectionLogic(BaseModel):
    conditions: List[DetectionCondition] = Field(default_factory=list)
    condition_logic: str = Field(default="all", description="'all' (AND) or 'any' (OR)")
    threshold: int = Field(default=1, description="Number of matching events required")
    time_window_seconds: int = Field(default=60, description="Time window in seconds for threshold aggregation")
    group_by: List[str] = Field(default_factory=list, description="Fields to group aggregation by (e.g. ['src_ip'])")

class DetectionRule(BaseModel):
    id: str = Field(..., description="Unique rule ID, e.g. AUTH-001, ENDP-001, NETW-001")
    title: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed description of what the rule detects")
    category: str = Field(..., description="authentication, endpoint, network, or cloud")
    severity: str = Field(..., description="critical, high, medium, low, or informational")
    status: str = Field(default="enabled", description="enabled or disabled")
    author: str = Field(default="SOC Detection Engineering Team")
    mitre_attack: MitreAttack
    detection: DetectionLogic
    recommended_response: str = Field(..., description="Step-by-step guidance for the SOC analyst")
    soar_playbook: Optional[str] = Field(None, description="Automated playbook: block_ip, isolate_host, revoke_user, etc.")
    tags: List[str] = Field(default_factory=list)
