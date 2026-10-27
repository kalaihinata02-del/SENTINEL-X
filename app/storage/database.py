import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.models.log_event import NormalizedEvent
from app.models.alert import Alert
from app.models.incident import Incident

class SecurityDatabase:
    """
    SQLite persistent storage for the SOC platform:
    Logs, Alerts, Incidents, and Audit Trails.
    """

    def __init__(self, db_path: str = "soc_platform.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Normalized Logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    event_source TEXT,
                    event_category TEXT,
                    action TEXT,
                    status TEXT,
                    actor_user TEXT,
                    src_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    hostname TEXT,
                    process_name TEXT,
                    process_command_line TEXT,
                    raw_log TEXT,
                    data_json TEXT
                )
            """)

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    rule_id TEXT,
                    rule_title TEXT,
                    severity TEXT,
                    category TEXT,
                    mitre_tactic TEXT,
                    mitre_technique_id TEXT,
                    mitre_technique_name TEXT,
                    status TEXT,
                    incident_id TEXT,
                    entities_json TEXT,
                    enrichment_json TEXT,
                    data_json TEXT
                )
            """)

            # Incidents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT,
                    severity TEXT,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    assigned_analyst TEXT,
                    category TEXT,
                    primary_ip TEXT,
                    primary_user TEXT,
                    primary_host TEXT,
                    summary TEXT,
                    data_json TEXT
                )
            """)

            conn.commit()

    # Log Operations
    def insert_log(self, event: NormalizedEvent):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO logs (
                    event_id, timestamp, event_source, event_category, action, status,
                    actor_user, src_ip, dest_ip, dest_port, hostname, process_name,
                    process_command_line, raw_log, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.event_source,
                event.event_category,
                event.action,
                event.status,
                event.actor_user,
                event.src_ip,
                event.dest_ip,
                event.dest_port,
                event.hostname,
                event.process_name,
                event.process_command_line,
                event.raw_log,
                event.model_dump_json()
            ))
            conn.commit()

    def get_logs(self, limit: int = 100, category: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT data_json FROM logs WHERE 1=1"
            params = []

            if category and category.lower() != "all":
                query += " AND event_category = ?"
                params.append(category.lower())

            if search:
                query += " AND (actor_user LIKE ? OR src_ip LIKE ? OR hostname LIKE ? OR process_name LIKE ? OR raw_log LIKE ?)"
                term = f"%{search}%"
                params.extend([term, term, term, term, term])

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [json.loads(row["data_json"]) for row in rows]

    # Alert Operations
    def insert_alert(self, alert: Alert):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, rule_id, rule_title, severity, category,
                    mitre_tactic, mitre_technique_id, mitre_technique_name,
                    status, incident_id, entities_json, enrichment_json, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.timestamp.isoformat(),
                alert.rule_id,
                alert.rule_title,
                alert.severity,
                alert.category,
                alert.mitre_attack.get("tactic", ""),
                alert.mitre_attack.get("technique_id", ""),
                alert.mitre_attack.get("technique_name", ""),
                alert.status,
                alert.incident_id,
                json.dumps(alert.entities),
                json.dumps(alert.enrichment),
                alert.model_dump_json()
            ))
            conn.commit()

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT data_json FROM alerts WHERE 1=1"
            params = []
            if severity and severity.lower() != "all":
                query += " AND severity = ?"
                params.append(severity.lower())
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [json.loads(row["data_json"]) for row in cursor.fetchall()]

    def update_alert_status(self, alert_id: str, status: str, incident_id: Optional[str] = None):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM alerts WHERE alert_id = ?", (alert_id,))
            row = cursor.fetchone()
            if row:
                data = json.loads(row["data_json"])
                data["status"] = status
                if incident_id:
                    data["incident_id"] = incident_id
                cursor.execute("""
                    UPDATE alerts SET status = ?, incident_id = ?, data_json = ? WHERE alert_id = ?
                """, (status, incident_id or data.get("incident_id"), json.dumps(data), alert_id))
                conn.commit()

    # Incident Operations
    def insert_incident(self, incident: Incident):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, title, severity, status, created_at, updated_at,
                    assigned_analyst, category, primary_ip, primary_user, primary_host,
                    summary, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.title,
                incident.severity,
                incident.status,
                incident.created_at.isoformat(),
                incident.updated_at.isoformat(),
                incident.assigned_analyst,
                incident.category,
                incident.primary_ip,
                incident.primary_user,
                incident.primary_host,
                incident.summary,
                incident.model_dump_json()
            ))
            conn.commit()

    def get_incidents(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT data_json FROM incidents WHERE 1=1"
            params = []
            if status and status.lower() != "all":
                query += " AND status = ?"
                params.append(status.lower())
            query += " ORDER BY updated_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [json.loads(row["data_json"]) for row in cursor.fetchall()]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["data_json"])
        return None

    def update_incident(self, incident: Incident):
        self.insert_incident(incident)

    def get_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs")
            total_logs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE status != 'closed'")
            open_incidents = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
            incident_severities = dict(cursor.fetchall())

            cursor.execute("SELECT mitre_tactic, COUNT(*) FROM alerts WHERE mitre_tactic != '' GROUP BY mitre_tactic")
            mitre_counts = dict(cursor.fetchall())

            return {
                "total_logs": total_logs,
                "total_alerts": total_alerts,
                "open_incidents": open_incidents,
                "incident_severities": incident_severities,
                "mitre_tactic_counts": mitre_counts
            }
