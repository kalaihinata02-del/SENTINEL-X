import re
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from app.models.log_event import RawLogInput, NormalizedEvent

class NormalizationEngine:
    """
    Normalizes heterogeneous raw security logs (Linux auth.log, Windows Event Logs,
    Zeek/Network logs, Web access logs, and JSON payloads) into a standardized
    OCSF/ECS compliant NormalizedEvent schema.
    """

    # Linux auth regexes
    RE_LINUX_SSH_FAILED = re.compile(
        r"Failed\s+(?:password|none)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<src_port>\d+)",
        re.IGNORECASE
    )
    RE_LINUX_SSH_ACCEPTED = re.compile(
        r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<src_port>\d+)",
        re.IGNORECASE
    )
    RE_LINUX_SUDO_CMD = re.compile(
        r"sudo:\s+(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)",
        re.IGNORECASE
    )
    RE_LINUX_SUDO_NOT_IN_SUDOERS = re.compile(
        r"(?P<user>\S+)\s*:\s*user NOT in sudoers\s*;\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)",
        re.IGNORECASE
    )

    # Web Nginx / Apache Combined log
    RE_COMBINED_LOG = re.compile(
        r'(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    @classmethod
    def normalize(cls, raw_input: RawLogInput) -> NormalizedEvent:
        """Entrypoint for normalizing any raw log input."""
        src_type = raw_input.source_type.lower()
        raw = raw_input.raw_message.strip()

        # Try JSON parsing first if it looks like JSON or is marked as generic_json
        if raw.startswith("{") and raw.endswith("}"):
            try:
                data = json.loads(raw)
                return cls._normalize_json(data, raw_input)
            except Exception:
                pass

        if src_type in ("linux_auth", "syslog"):
            return cls._normalize_linux_auth(raw, raw_input)
        elif src_type in ("windows_security", "winevent", "windows"):
            return cls._normalize_windows_text(raw, raw_input)
        elif src_type in ("web_access", "nginx", "apache"):
            return cls._normalize_web_access(raw, raw_input)
        elif src_type in ("network_zeek", "zeek", "suricata", "firewall"):
            return cls._normalize_network_text(raw, raw_input)
        else:
            return cls._normalize_generic_fallback(raw, raw_input)

    @classmethod
    def _normalize_json(cls, data: Dict[str, Any], raw_input: RawLogInput) -> NormalizedEvent:
        """Normalizes structured JSON logs (e.g. from Elastic, Splunk, Zeek JSON, Windows EVTX export)."""
        category = (
            data.get("event_category") or
            data.get("category") or
            cls._infer_category(data) or
            "general"
        )
        action = (
            data.get("action") or
            data.get("event_action") or
            data.get("activity") or
            "unknown_event"
        )
        status = str(data.get("status") or data.get("outcome") or "SUCCESS").upper()

        user = (
            data.get("actor_user") or
            data.get("user") or
            data.get("username") or
            data.get("TargetUserName") or
            data.get("SubjectUserName")
        )

        src_ip = data.get("src_ip") or data.get("source_ip") or data.get("client_ip") or data.get("IpAddress")
        dest_ip = data.get("dest_ip") or data.get("destination_ip") or data.get("server_ip") or data.get("TargetIp")
        
        proc_name = (
            data.get("process_name") or
            data.get("process") or
            data.get("NewProcessName") or
            data.get("Image")
        )
        proc_cmd = (
            data.get("process_command_line") or
            data.get("command_line") or
            data.get("cmd") or
            data.get("CommandLine")
        )
        parent_proc = (
            data.get("parent_process_name") or
            data.get("parent_process") or
            data.get("ParentProcessName")
        )

        return NormalizedEvent(
            timestamp=cls._parse_timestamp(data.get("timestamp")),
            event_source=data.get("event_source") or raw_input.source_type,
            event_category=category,
            action=action,
            status=status,
            actor_user=str(user) if user else None,
            actor_domain=data.get("actor_domain") or data.get("TargetDomainName"),
            src_ip=str(src_ip) if src_ip else None,
            src_port=cls._safe_int(data.get("src_port") or data.get("source_port") or data.get("IpPort")),
            dest_ip=str(dest_ip) if dest_ip else None,
            dest_port=cls._safe_int(data.get("dest_port") or data.get("destination_port")),
            network_protocol=data.get("network_protocol") or data.get("proto") or data.get("protocol"),
            domain=data.get("domain") or data.get("query") or data.get("host"),
            hostname=data.get("hostname") or data.get("host") or raw_input.hostname,
            process_name=cls._clean_proc_name(proc_name),
            process_path=proc_name,
            process_command_line=proc_cmd,
            parent_process_name=cls._clean_proc_name(parent_proc),
            file_path=data.get("file_path") or data.get("TargetFilename"),
            file_hash=data.get("file_hash") or data.get("Hashes"),
            http_method=data.get("http_method") or data.get("method"),
            http_uri=data.get("http_uri") or data.get("uri") or data.get("path"),
            http_status=cls._safe_int(data.get("http_status") or data.get("status_code")),
            raw_log=raw_input.raw_message,
            tags=data.get("tags") or [],
            metadata={**raw_input.metadata, **data}
        )

    @classmethod
    def _normalize_linux_auth(cls, raw: str, raw_input: RawLogInput) -> NormalizedEvent:
        """Parses Linux syslog auth messages (SSHD, SUDO)."""
        # Failed SSH
        m_failed = cls.RE_LINUX_SSH_FAILED.search(raw)
        if m_failed:
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="linux_auth",
                event_category="authentication",
                action="logon_failed",
                status="FAILURE",
                actor_user=m_failed.group("user"),
                src_ip=m_failed.group("src_ip"),
                src_port=int(m_failed.group("src_port")),
                dest_port=22,
                network_protocol="ssh",
                hostname=raw_input.hostname or "linux-server",
                raw_log=raw,
                tags=["linux", "sshd", "auth_failure"]
            )

        # Accepted SSH
        m_acc = cls.RE_LINUX_SSH_ACCEPTED.search(raw)
        if m_acc:
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="linux_auth",
                event_category="authentication",
                action="logon",
                status="SUCCESS",
                actor_user=m_acc.group("user"),
                src_ip=m_acc.group("src_ip"),
                src_port=int(m_acc.group("src_port")),
                dest_port=22,
                network_protocol="ssh",
                hostname=raw_input.hostname or "linux-server",
                raw_log=raw,
                tags=["linux", "sshd", "auth_success"]
            )

        # Sudo unauthorized
        m_sudo_fail = cls.RE_LINUX_SUDO_NOT_IN_SUDOERS.search(raw)
        if m_sudo_fail:
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="linux_auth",
                event_category="endpoint",
                action="privilege_elevation",
                status="FAILURE",
                actor_user=m_sudo_fail.group("user"),
                process_command_line=m_sudo_fail.group("command"),
                process_name=cls._clean_proc_name(m_sudo_fail.group("command").split()[0] if m_sudo_fail.group("command") else "sudo"),
                hostname=raw_input.hostname or "linux-server",
                raw_log=raw,
                tags=["linux", "sudo", "privilege_violation"]
            )

        # Sudo executed
        m_sudo = cls.RE_LINUX_SUDO_CMD.search(raw)
        if m_sudo:
            cmd = m_sudo.group("command")
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="linux_auth",
                event_category="endpoint",
                action="privilege_elevation",
                status="SUCCESS",
                actor_user=m_sudo.group("user"),
                process_command_line=f"sudo {cmd}",
                process_name=cls._clean_proc_name(cmd.split()[0] if cmd else "sudo"),
                hostname=raw_input.hostname or "linux-server",
                raw_log=raw,
                tags=["linux", "sudo", "privilege_elevation"]
            )

        # Fallback linux syslog
        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_source="linux_auth",
            event_category="authentication",
            action="syslog_auth",
            status="UNKNOWN",
            hostname=raw_input.hostname or "linux-server",
            raw_log=raw,
            tags=["linux", "syslog"]
        )

    @classmethod
    def _normalize_windows_text(cls, raw: str, raw_input: RawLogInput) -> NormalizedEvent:
        """Parses Windows Event log text output."""
        event_id = None
        m_id = re.search(r"EventID:\s*(\d+)|Event\s+ID\s*:\s*(\d+)|Event\[(\d+)\]", raw, re.IGNORECASE)
        if m_id:
            event_id = m_id.group(1) or m_id.group(2) or m_id.group(3)

        # Extract common key-values
        user = cls._extract_kv(raw, ["TargetUserName", "Account Name", "User Name", "SubjectUserName"])
        src_ip = cls._extract_kv(raw, ["Source Network Address", "IpAddress", "Client IP"])
        cmd = cls._extract_kv(raw, ["CommandLine", "Process Command Line", "Command"])
        proc = cls._extract_kv(raw, ["NewProcessName", "Process Name", "Image", "Application"])
        parent = cls._extract_kv(raw, ["ParentProcessName", "Parent Process Name"])
        host = cls._extract_kv(raw, ["WorkstationName", "Computer", "ComputerName"]) or raw_input.hostname

        # If no explicit key-value was found, infer command line if string looks like an executable invocation
        if not cmd and any(x in raw.lower() for x in ("powershell", "cmd.exe", ".exe", "vssadmin", "mimikatz", "sudo", "certutil", "net localgroup")):
            cmd = raw
            if not proc:
                first_tok = raw.split()[0].replace("\"", "").replace("'", "")
                proc = first_tok

        if event_id == "4625" or "logon failed" in raw.lower():
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="windows_security",
                event_category="authentication",
                action="logon_failed",
                status="FAILURE",
                actor_user=user,
                src_ip=src_ip,
                hostname=host or "win-workstation",
                raw_log=raw,
                tags=["windows", "event_4625", "logon_failure"],
                metadata={"event_id": "4625"}
            )
        elif event_id == "4624" or "logged on" in raw.lower():
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="windows_security",
                event_category="authentication",
                action="logon",
                status="SUCCESS",
                actor_user=user,
                src_ip=src_ip,
                hostname=host or "win-workstation",
                raw_log=raw,
                tags=["windows", "event_4624", "logon_success"],
                metadata={"event_id": "4624"}
            )
        elif event_id == "4688" or proc or cmd:
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="windows_security",
                event_category="endpoint",
                action="process_spawn",
                status="SUCCESS",
                actor_user=user,
                hostname=host or "win-workstation",
                process_name=cls._clean_proc_name(proc),
                process_path=proc,
                process_command_line=cmd or proc or raw,
                parent_process_name=cls._clean_proc_name(parent),
                raw_log=raw,
                tags=["windows", "event_4688", "process_creation"],
                metadata={"event_id": event_id or "4688"}
            )

        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_source="windows_security",
            event_category="endpoint",
            action="windows_event",
            status="UNKNOWN",
            actor_user=user,
            hostname=host or "win-workstation",
            raw_log=raw,
            tags=["windows"]
        )

    @classmethod
    def _normalize_web_access(cls, raw: str, raw_input: RawLogInput) -> NormalizedEvent:
        """Parses web server access logs (Nginx / Apache Combined)."""
        m = cls.RE_COMBINED_LOG.search(raw)
        if m:
            st = int(m.group("status"))
            status = "SUCCESS" if st < 400 else "FAILURE"
            return NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                event_source="web_access",
                event_category="network",
                action="http_request",
                status=status,
                actor_user=m.group("user") if m.group("user") != "-" else None,
                src_ip=m.group("src_ip"),
                dest_port=80 if st != 443 else 443,
                http_method=m.group("method"),
                http_uri=m.group("uri"),
                http_status=st,
                user_agent=m.group("user_agent"),
                hostname=raw_input.hostname or "web-server",
                raw_log=raw,
                tags=["web", "access_log"]
            )
        return cls._normalize_generic_fallback(raw, raw_input)

    @classmethod
    def _normalize_network_text(cls, raw: str, raw_input: RawLogInput) -> NormalizedEvent:
        """Parses generic network or firewall log lines."""
        # Check IP patterns
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        src_ip = ips[0] if len(ips) > 0 else None
        dest_ip = ips[1] if len(ips) > 1 else None

        ports = re.findall(r"(?:port|pt|dport|sport)[\s:=]+(\d+)", raw, re.IGNORECASE)
        dest_port = int(ports[0]) if ports else None

        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_source=raw_input.source_type,
            event_category="network",
            action="network_connection",
            status="SUCCESS",
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            hostname=raw_input.hostname,
            raw_log=raw,
            tags=["network"]
        )

    @classmethod
    def _normalize_generic_fallback(cls, raw: str, raw_input: RawLogInput) -> NormalizedEvent:
        """Fallback normalizer for unstructured logs."""
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_source=raw_input.source_type,
            event_category="general",
            action="raw_event",
            status="UNKNOWN",
            src_ip=ips[0] if ips else None,
            dest_ip=ips[1] if len(ips) > 1 else None,
            hostname=raw_input.hostname,
            raw_log=raw,
            tags=["unstructured"]
        )

    @staticmethod
    def _infer_category(data: Dict[str, Any]) -> Optional[str]:
        if any(k in data for k in ("process_name", "CommandLine", "NewProcessName", "parent_process")):
            return "endpoint"
        if any(k in data for k in ("actor_user", "TargetUserName", "logon", "auth")):
            return "authentication"
        if any(k in data for k in ("dest_port", "protocol", "domain", "bytes_in")):
            return "network"
        return None

    @staticmethod
    def _extract_kv(text: str, keys: List[str]) -> Optional[str]:
        for k in keys:
            m = re.search(rf"{re.escape(k)}\s*[:=]\s*(.*?)(?=\s+[A-Za-z0-9_]+[:=]|$|[\r\n,;])", text, re.IGNORECASE)
            if m:
                val = m.group(1).strip().strip("'\"")
                if val and val != "-" and val.lower() != "null":
                    return val
        return None

    @staticmethod
    def _clean_proc_name(proc_path: Optional[str]) -> Optional[str]:
        if not proc_path:
            return None
        # Extract filename from path Windows or Unix
        name = proc_path.replace("\\", "/").split("/")[-1].strip()
        return name if name else proc_path

    @staticmethod
    def _safe_int(val: Any) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                pass
        return datetime.now(timezone.utc)
