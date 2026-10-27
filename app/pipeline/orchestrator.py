from typing import List, Dict, Any, Optional
from app.models.log_event import RawLogInput, NormalizedEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.pipeline.normalizer import NormalizationEngine
from app.pipeline.detection_engine import DetectionEngine
from app.pipeline.soar_engine import SoarEngine
from app.pipeline.incident_manager import IncidentManager
from app.storage.database import SecurityDatabase

class SecurityPipeline:
    """
    Central End-to-End Orchestrator:
    Raw Log -> Normalization -> Ingestion -> Rule Detection -> Alerting -> Enrichment -> Incident Ticket -> SOAR Mitigation.
    """

    def __init__(self, db_path: str = "soc_platform.db", rules_dir: str = "rules"):
        self.db = SecurityDatabase(db_path=db_path)
        self.soar = SoarEngine()
        self.detection_engine = DetectionEngine(rules_dir=rules_dir)
        self.incident_manager = IncidentManager(self.db, self.soar)

    def process_raw_log(self, raw_input: RawLogInput) -> Dict[str, Any]:
        """
        Executes complete pipeline processing for an incoming raw log:
        1. Normalize
        2. Store Log
        3. Evaluate Rules
        4. Generate Alerts
        5. Generate Incident Tickets & Run SOAR Playbooks
        """
        # 1. Normalize
        normalized_event = NormalizationEngine.normalize(raw_input)

        # 2. Store Normalized Event
        self.db.insert_log(normalized_event)

        # 3. Detection Engine Evaluation
        alerts = self.detection_engine.evaluate_event(normalized_event)

        incidents_created = []
        for alert in alerts:
            # 4. Store Alert
            self.db.insert_alert(alert)

            # 5. Escalate to Incident Ticket and execute enrichment & SOAR
            incident = self.incident_manager.process_alert_to_incident(alert)
            incidents_created.append(incident.model_dump(mode="json"))

        return {
            "status": "processed",
            "event": normalized_event.model_dump(mode="json"),
            "alerts_generated": len(alerts),
            "incidents_created": incidents_created
        }

    def process_batch_logs(self, batch: List[RawLogInput]) -> Dict[str, Any]:
        """Processes multiple raw logs in sequence."""
        total_events = len(batch)
        total_alerts = 0
        all_incidents = []

        for item in batch:
            res = self.process_raw_log(item)
            total_alerts += res["alerts_generated"]
            all_incidents.extend(res["incidents_created"])

        return {
            "total_processed": total_events,
            "total_alerts": total_alerts,
            "total_incidents": len(all_incidents),
            "incidents": all_incidents
        }
