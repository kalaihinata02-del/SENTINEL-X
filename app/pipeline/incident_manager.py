from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid

from app.models.alert import Alert
from app.models.incident import Incident
from app.pipeline.enrichment_engine import EnrichmentEngine
from app.pipeline.soar_engine import SoarEngine
from app.storage.database import SecurityDatabase

class IncidentManager:
    """
    SOC Incident Management & Triage Orchestrator.
    Groups detection alerts into SOC Incident Tickets, triggers automated enrichment,
    builds chronological attack timelines, and executes SOAR playbooks.
    """

    def __init__(self, db: SecurityDatabase, soar: SoarEngine):
        self.db = db
        self.soar = soar

    def process_alert_to_incident(self, alert: Alert) -> Incident:
        """
        Converts an Alert into a full SOC Incident Ticket, executes enrichment,
        and optionally runs automated containment playbooks.
        """
        now = datetime.now(timezone.utc)
        incident_id = f"INC-2026-{str(uuid.uuid4())[:6].upper()}"

        # 1. Automated Context Enrichment
        enrichment_data = EnrichmentEngine.enrich_all(alert.entities)
        alert.enrichment = enrichment_data
        alert.incident_id = incident_id
        self.db.update_alert_status(alert.alert_id, "escalated", incident_id)

        # 2. Extract primary targets and actors
        primary_ip = alert.entities.get("src_ip")
        primary_user = alert.entities.get("user")
        primary_host = alert.entities.get("hostname")

        # 3. Build Timeline
        timeline: List[Dict[str, Any]] = []
        for ev in alert.evidence_events:
            timeline.append({
                "timestamp": ev.get("timestamp"),
                "event_id": ev.get("event_id"),
                "category": ev.get("event_category"),
                "action": ev.get("action"),
                "status": ev.get("status"),
                "detail": f"{ev.get('actor_user') or 'User'} performed {ev.get('action')} on {ev.get('hostname') or 'host'}"
            })

        timeline.append({
            "timestamp": alert.timestamp.isoformat(),
            "event_id": alert.alert_id,
            "category": "detection",
            "action": "alert_triggered",
            "status": "ALERT",
            "detail": f"Detection Rule matched: [{alert.rule_id}] {alert.rule_title}"
        })

        # 4. Automated SOAR Playbook Execution (if configured)
        automated_actions = []
        if alert.soar_playbook:
            target = primary_ip if alert.soar_playbook == "block_ip" else (primary_host or primary_user or "unknown")
            action_res = self.soar.execute_playbook(alert.soar_playbook, target, incident_id)
            automated_actions.append(action_res)
            timeline.append({
                "timestamp": now.isoformat(),
                "event_id": action_res["action_id"],
                "category": "soar",
                "action": alert.soar_playbook,
                "status": "AUTOMATED_RESPONSE",
                "detail": action_res["message"]
            })

        # 5. MITRE Tactic & Technique
        mitre_tactics = [alert.mitre_attack.get("tactic", "Initial Access")] if alert.mitre_attack else []
        mitre_tech = [f"{alert.mitre_attack.get('technique_id')}: {alert.mitre_attack.get('technique_name')}"] if alert.mitre_attack else []

        # 6. Incident Summary
        summary = (
            f"Detected suspicious activity matching rule '{alert.rule_title}'. "
            f"Source IP: {primary_ip or 'N/A'} (Threat: {enrichment_data['ip_intelligence'].get('reputation', 'UNKNOWN')}), "
            f"Target Host: {primary_host or 'N/A'}, Target User: {primary_user or 'N/A'}. "
            f"Total correlated events: {alert.event_count}."
        )

        incident = Incident(
            incident_id=incident_id,
            title=f"[{alert.severity.upper()}] {alert.rule_title} on {primary_host or primary_ip or 'Network'}",
            severity=alert.severity,
            status="open",
            created_at=now,
            updated_at=now,
            assigned_analyst="SOC Level-1 Auto-Triage",
            category=alert.category,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_tech,
            summary=summary,
            primary_ip=primary_ip,
            primary_user=primary_user,
            primary_host=primary_host,
            alert_ids=[alert.alert_id],
            timeline=timeline,
            evidence=alert.evidence_events,
            enrichment=enrichment_data,
            recommended_response=alert.recommended_response,
            automated_actions=automated_actions,
            analyst_notes=[{
                "timestamp": now.isoformat(),
                "author": "SOAR Automation Bot",
                "note": f"Incident auto-created from Alert {alert.alert_id}. Risk Score calculated: {enrichment_data.get('composite_risk_score', 0)}/100."
            }]
        )

        self.db.insert_incident(incident)
        return incident

    def add_analyst_note(self, incident_id: str, author: str, note_text: str) -> Optional[Dict[str, Any]]:
        inc_data = self.db.get_incident_by_id(incident_id)
        if not inc_data:
            return None
        now = datetime.now(timezone.utc).isoformat()
        notes = inc_data.get("analyst_notes", [])
        notes.append({
            "timestamp": now,
            "author": author,
            "note": note_text
        })
        inc_data["analyst_notes"] = notes
        inc_data["updated_at"] = now
        incident = Incident(**inc_data)
        self.db.update_incident(incident)
        return inc_data

    def update_incident_status(self, incident_id: str, new_status: str, analyst: Optional[str] = None) -> Optional[Dict[str, Any]]:
        inc_data = self.db.get_incident_by_id(incident_id)
        if not inc_data:
            return None
        now = datetime.now(timezone.utc).isoformat()
        inc_data["status"] = new_status
        inc_data["updated_at"] = now
        if analyst:
            inc_data["assigned_analyst"] = analyst
        incident = Incident(**inc_data)
        self.db.update_incident(incident)
        return inc_data
