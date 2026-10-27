from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid

class RawLogInput(BaseModel):
    """Input payload for raw unparsed logs arriving via API or file."""
    source_type: str = Field(..., description="Type of source: linux_auth, windows_security, network_zeek, web_access, generic_json")
    raw_message: str = Field(..., description="Raw log line, syslog message, or JSON string")
    hostname: Optional[str] = Field(None, description="Optional host where log originated")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom contextual tags")

class NormalizedEvent(BaseModel):
    """
    Unified Open Cybersecurity Schema Framework (OCSF) / Elastic Common Schema (ECS)
    compliant normalized security event.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_source: str = Field(..., description="e.g. linux_auth, windows_security, network_zeek, etc.")
    event_category: str = Field(..., description="authentication, endpoint, network, or cloud")
    action: str = Field(..., description="e.g. logon, logon_failed, process_spawn, network_connection, etc.")
    status: str = Field(default="UNKNOWN", description="SUCCESS, FAILURE, ATTEMPT, or UNKNOWN")
    
    # Identity & Actor
    actor_user: Optional[str] = None
    actor_domain: Optional[str] = None
    actor_privileges: Optional[str] = None
    
    # Network fields
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    network_protocol: Optional[str] = None
    domain: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    
    # Web & HTTP fields
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_status: Optional[int] = None
    user_agent: Optional[str] = None

    # Endpoint & Process fields
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_command_line: Optional[str] = None
    process_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None

    # Metadata & Raw
    raw_log: str = ""
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
