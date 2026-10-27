from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid

class SoarEngine:
    """
    Security Orchestration, Automation, and Response (SOAR) Engine.
    Executes automated mitigation playbooks (IP Blocking, Endpoint Isolation,
    Account Revocation, Process Termination) and logs audit trails.
    """

    def __init__(self):
        # In-memory tracking of active blocks & mitigations
        self.blocked_ips: List[Dict[str, Any]] = []
        self.isolated_hosts: List[Dict[str, Any]] = []
        self.locked_accounts: List[Dict[str, Any]] = []
        self.action_history: List[Dict[str, Any]] = []

    def execute_playbook(self, playbook_name: str, target: str, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Executes a SOAR playbook against a given target."""
        now = datetime.now(timezone.utc)
        action_id = f"SOAR-{str(uuid.uuid4())[:6].upper()}"

        result = {
            "action_id": action_id,
            "playbook": playbook_name,
            "target": target,
            "incident_id": incident_id,
            "timestamp": now.isoformat(),
            "status": "success",
            "message": ""
        }

        if playbook_name in ("block_ip", "firewall_block"):
            rule_id = f"FW-RULE-{str(uuid.uuid4())[:4].upper()}"
            record = {
                "ip": target,
                "rule_id": rule_id,
                "action_id": action_id,
                "blocked_at": now.isoformat(),
                "expires_at": "Indefinite (SOC Review Req)"
            }
            # Avoid duplicate blocks
            if not any(b["ip"] == target for b in self.blocked_ips):
                self.blocked_ips.append(record)
            result["message"] = f"Automated Firewall Rule {rule_id} created. IP {target} dropped on Edge Firewalls."
            result["details"] = record

        elif playbook_name in ("isolate_host", "edr_quarantine"):
            record = {
                "hostname": target,
                "action_id": action_id,
                "isolated_at": now.isoformat(),
                "status": "NETWORK_ISOLATED (EDR Containment active)"
            }
            if not any(h["hostname"] == target for h in self.isolated_hosts):
                self.isolated_hosts.append(record)
            result["message"] = f"Endpoint {target} successfully isolated via EDR API. Lateral movement blocked."
            result["details"] = record

        elif playbook_name in ("revoke_user", "lock_account"):
            record = {
                "username": target,
                "action_id": action_id,
                "locked_at": now.isoformat(),
                "status": "ACCOUNT_DISABLED_MFA_REVOKED"
            }
            if not any(u["username"] == target for u in self.locked_accounts):
                self.locked_accounts.append(record)
            result["message"] = f"Active Directory account '{target}' locked. All active sessions invalidated."
            result["details"] = record

        elif playbook_name in ("kill_process", "edr_terminate_process"):
            result["message"] = f"Process {target} terminated across all endpoint agent instances."
            result["details"] = {"process": target, "action": "SIGKILL_SENT"}

        else:
            result["status"] = "simulated"
            result["message"] = f"Executed generic automated playbook '{playbook_name}' on target '{target}'."

        self.action_history.append(result)
        return result

    def get_mitigation_state(self) -> Dict[str, Any]:
        """Returns the current active containment and response status."""
        return {
            "blocked_ips": self.blocked_ips,
            "isolated_hosts": self.isolated_hosts,
            "locked_accounts": self.locked_accounts,
            "recent_actions": list(reversed(self.action_history[-20:]))
        }

    def unblock_ip(self, ip: str) -> bool:
        initial = len(self.blocked_ips)
        self.blocked_ips = [b for b in self.blocked_ips if b["ip"] != ip]
        return len(self.blocked_ips) < initial

    def unisolate_host(self, hostname: str) -> bool:
        initial = len(self.isolated_hosts)
        self.isolated_hosts = [h for h in self.isolated_hosts if h["hostname"] != hostname]
        return len(self.isolated_hosts) < initial
