# SENTINEL-X | Enterprise-Style Detection Engineering & SOC Automation Platform

> **A production-grade, end-to-end Mini SIEM & SOAR platform**: Log Ingestion → OCSF/ECS Normalization → YAML Sigma Detection Rules → Threat Intel Enrichment → SOC Incident Management → Automated Response Playbooks.

[![Python](https://img.shields.io/badge/Python-3.15%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%C2%AE-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Tests](https://img.shields.io/badge/Tests-11%20Passed-10B981?style=for-the-badge)](https://pytest.org)

---

## 📌 Executive Summary & Problem Statement

Modern enterprise Security Operations Centers (SOCs) ingest gigabytes of disparate security logs across Linux, Windows, cloud, and network appliances every hour. Raw logs in disparate formats are hard to correlate manually, leading to alert fatigue and high Mean Time to Detect (MTTD) and Respond (MTTR).

**SENTINEL-X** solves this by implementing an enterprise-style detection engineering pipeline:
1. **Multi-Source Ingestion:** Ingests unparsed syslog (`auth.log`), Windows Security Events (`4624`, `4625`, `4688`), Zeek network streams, and Web access logs.
2. **Unified Normalization (OCSF / ECS Compliant):** Converts heterogeneous raw logs into a standardized schema with strongly typed identity, network, and process fields.
3. **Stateful Detection Engineering Engine:** Evaluates YAML-defined Sigma-style detection rules with sliding time window thresholding and cross-field condition logic.
4. **Automated Threat Intel & CMDB Enrichment:** Automatically augments detections with GeoIP, threat intelligence scores (Tor exit nodes, C2 trackers), CMDB asset criticality (Tier-0 Domain Controller vs Workstation), and identity privilege levels.
5. **SOC-Style Incident Management:** Assembles correlated incident tickets containing severity ratings, visual chronological attack timelines, evidence logs, and recommended analyst playbooks.
6. **SOAR Automated Containment:** Automatically executes mitigation actions (Firewall Edge IP drops, EDR network host isolation, Active Directory account lockout) without human delay.
7. **Interactive SOC Cyber Dashboard:** Sleek dark-mode Operations Center UI with real-time counters, MITRE ATT&CK coverage heatmap, interactive investigation studio, and a **1-Click Attack Simulator** for live demonstration.

---

## 🏗️ Architecture & Pipeline Flow

```
+-----------------------------------------------------------------------------------------+
|                               SENTINEL-X PIPELINE ARCHITECTURE                          |
+-----------------------------------------------------------------------------------------+
       │
       ▼
 [ 1. Log Ingestion ] ──────> Linux auth.log, Windows EVTX 4688/4625, Zeek, Web Access
       │
       ▼
 [ 2. Normalization ] ──────> OCSF / ECS Standard Schema (actor, src_ip, dest_port, process)
       │
       ▼
 [ 3. Detection Engine ] ───> YAML Rules Engine (Thresholds, Regex, Sliding State Windows)
       │
       ▼
 [ 4. Threat Intel & CMDB] ─> GeoIP Lookup, IP Reputation, CMDB Asset Tier, User Privilege
       │
       ▼
 [ 5. SOC Incident Ticket] ─> Ticket ID, MITRE Tag, Correlated Evidence, Visual Timeline
       │
       ▼
 [ 6. SOAR Automation ] ────> 1-Click & Auto Mitigation: Firewall Block, EDR Host Isolation
       │
       ▼
 [ 7. SOC Dashboard UI ] ───> Live Heatmap, Investigation Studio, Real-time Metrics
```

---

## 🛡️ Detection Rules Catalog & MITRE ATT&CK® Mapping

| Rule ID | Rule Title | Category | Severity | MITRE Tactic | Technique ID | Threshold / Window | Automated SOAR Action |
|---|---|---|---|---|---|---|---|
| **AUTH-001** | SSH Brute Force Authentication Attack | Authentication | `HIGH` | Credential Access | **T1110.001** | $\ge$ 5 failures / 60s | `block_ip` (Firewall Drop) |
| **AUTH-002** | Password Spraying Campaign Detected | Authentication | `HIGH` | Credential Access | **T1110.003** | $\ge$ 3 failures / 120s | `block_ip` (Perimeter Block) |
| **ENDP-001** | Obfuscated PowerShell Download Cradle | Endpoint | `CRITICAL` | Execution | **T1059.001** | 1 match (Immediate) | `isolate_host` (EDR Quarantine) |
| **ENDP-002** | LSASS Memory Credential Dumping (Mimikatz) | Endpoint | `CRITICAL` | Credential Access | **T1003.001** | 1 match (Immediate) | `isolate_host` (EDR Quarantine) |
| **ENDP-003** | Unauthorized Local Privilege Escalation | Endpoint | `HIGH` | Privilege Escalation | **T1078.003** | 1 match (Immediate) | `revoke_user` (Account Lock) |
| **ENDP-004** | Shadow Copies Deletion (Ransomware Prep) | Endpoint | `CRITICAL` | Impact / Defense Evasion | **T1490** | 1 match (Immediate) | `isolate_host` (Emergency Isolation) |
| **NETW-001** | Network Port Scanning Reconnaissance | Network | `MEDIUM` | Discovery | **T1046** | $\ge$ 5 ports / 30s | `block_ip` (Edge ACL Block) |
| **NETW-002** | Command & Control (C2) Beaconing Activity | Network | `CRITICAL` | Command & Control | **T1071.001** | 1 match (Immediate) | `block_ip` (Perimeter Drop) |
| **NETW-003** | DNS Tunneling & Covert Data Exfiltration | Network | `HIGH` | Exfiltration | **T1071.004** | 1 match (Immediate) | `block_ip` (DNS Sinkhole) |

---

## 🚀 Quickstart & Setup Guide

### 1. Requirements
- Python 3.10+ (Tested and verified on Python 3.15)
- Standard modern web browser (Chrome, Edge, Firefox, Brave)
- **Zero Node.js/npm dependencies needed!**

### 2. Installation
Open your terminal in the project directory:
```bash
# Install dependencies
python -m pip install -r requirements.txt
```

### 3. Launch Sentinel-X Platform
```bash
# Start the SOC Server
python run.py
```
* **SOC Analyst Dashboard:** [http://localhost:8000](http://localhost:8000)
* **Interactive Swagger REST API:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🎮 How to Demo & Test in Interviews / Reviews

### Option A: 1-Click Interactive Web Simulator (Recommended!)
1. Open [http://localhost:8000](http://localhost:8000) in your browser.
2. Click on the **"Attack Simulator"** tab or the **"Simulate Attack"** button in the top navigation.
3. Click any scenario button:
   - **SSH Brute Force**: Fires 5 failed SSH logons. Watch rule `AUTH-001` trigger, creating an incident and adding IP `185.220.101.5` to the active firewall blocklist in real time.
   - **Obfuscated PowerShell Cradle**: Executes an encoded download cradle. Watch rule `ENDP-001` trigger, creating a `CRITICAL` incident and immediately placing host `win-workstation` into EDR network isolation.
   - **Mimikatz LSASS Dump**: Simulates memory credential harvesting on Tier-0 Domain Controller `dc-prod-01`.
   - **Ransomware Shadow Copies Deletion**: Simulates `vssadmin delete shadows` defense evasion.
   - **Cobalt Strike C2 Beaconing**: Simulates beacon heartbeat communication to external C2 node `103.224.182.245`.
4. Switch to the **"SOC Overview"** tab to see the live metrics counters, MITRE ATT&CK Matrix heatmap update, and severity chart.
5. Click **"Investigate"** on any ticket in the **Incident Queue** to explore the deep-dive investigation modal:
   - Review GeoIP and IP Reputation threat intelligence.
   - Trace the chronological attacker timeline.
   - Inspect raw evidence log entries.
   - Click manual SOAR action buttons (e.g. *Execute Playbook: Block IP*).
   - Add analyst triage notes to the ticket audit trail.

### Option B: Terminal CLI Attack Simulator
Open a second terminal window and run:
```bash
python scripts/simulate_attacks.py
```
Select `9` to run all scenarios sequentially and watch the full pipeline output stream live in your terminal!

### Option C: Automated Unit & Integration Tests
Run the comprehensive test suite:
```bash
python -m pytest tests/ -v
```
All 11 unit and integration tests will run and pass in under 1 second.

---

## 📁 Repository Directory Structure

```
d:\intern nova project\
├── app/
│   ├── main.py                     # FastAPI application & dashboard mount
│   ├── models/                     # Pydantic Schemas
│   │   ├── log_event.py            # Raw & Normalized OCSF Event schemas
│   │   ├── rule.py                 # YAML Detection Rule & MITRE schema
│   │   ├── alert.py                # Alert schema with evidence events
│   │   └── incident.py             # SOC Incident Ticket & Timeline schema
│   ├── pipeline/                   # Core SIEM & SOAR Engine
│   │   ├── normalizer.py           # Multi-source log normalization engine
│   │   ├── detection_engine.py     # YAML rule evaluator + sliding window state
│   │   ├── enrichment_engine.py    # Threat Intel, GeoIP, and CMDB enrichment
│   │   ├── soar_engine.py          # Automated playbooks (Block IP, Isolate host)
│   │   ├── incident_manager.py     # Incident ticket creation & triage orchestrator
│   │   └── orchestrator.py         # End-to-end pipeline coordination
│   ├── storage/
│   │   └── database.py             # SQLite persistence for logs, alerts, tickets
│   ├── api/                        # REST API routers
│   │   ├── logs.py                 # Ingestion & SIEM query API
│   │   ├── alerts.py               # Detection alerts API
│   │   ├── incidents.py            # Incident management & playbook trigger API
│   │   ├── rules.py                # Detection rule catalog & toggle API
│   │   ├── soar.py                 # SOAR containment state & unblock API
│   │   └── simulation.py           # 1-click attack simulation runner API
│   └── static/                     # Dark-Mode Cyber SOC UI
│       ├── index.html              # Single Page Application
│       ├── css/style.css           # Custom animations & styles
│       └── js/app.js               # Frontend controller & Chart.js logic
├── rules/                          # YAML Sigma-style detection rules
│   ├── auth_ssh_bruteforce.yaml
│   ├── auth_password_spray.yaml
│   ├── endp_powershell_obfuscated.yaml
│   ├── endp_lsass_dumping.yaml
│   ├── endp_privilege_escalation.yaml
│   ├── endp_ransomware_indicator.yaml
│   ├── netw_port_scan.yaml
│   ├── netw_c2_beaconing.yaml
│   └── netw_dns_tunneling.yaml
├── data/
│   └── samples/                    # Pre-packaged sample log files
│       ├── auth_attack.log
│       ├── endpoint_attack.log
│       └── network_c2.log
├── scripts/
│   └── simulate_attacks.py         # Interactive CLI attack simulator
├── tests/                          # Automated Pytest suite
│   ├── test_normalizer.py          # Normalizer regex & parser tests
│   ├── test_detection_rules.py     # Threshold & sliding window tests
│   └── test_pipeline.py            # End-to-end integration & SOAR tests
├── requirements.txt                # Python dependencies
├── run.py                          # 1-click startup runner
└── README.md                       # Enterprise project documentation
```

---

## 🎓 Viva & Internship Review Presentation Guide

When presenting this project to your mentor or interviewers, highlight these key engineering decisions:

1. **Why Normalization Matters:** Raw security logs come in endless syntax variations (`/var/log/auth.log` vs Windows EventID `4625`). Without standardizing them into a single unified schema (OCSF/ECS), detection engineers would have to rewrite rules for every log source. Sentinel-X unifies them immediately at ingestion.
2. **Stateful vs Stateless Detections:** Single-event rules (like Mimikatz execution) are stateless. But detecting Brute Force or Port Scanning requires **stateful sliding time windows** ($\ge 5$ events in 60s grouped by `src_ip`). Sentinel-X implements this in-memory sliding window manager with automatic timestamp pruning and alert cooldown suppression to eliminate alert fatigue.
3. **Automated Context Enrichment:** An alert saying *"Failed login from 185.220.101.5 on dc-prod-01"* is 10x more critical than on a test box. Sentinel-X queries the internal CMDB and Threat Intel database to compute a composite Risk Score (0-100) before human analysts even see the ticket.
4. **SOAR Mitigation (Mean Time to Respond):** Attackers compromise domain controllers within minutes. Sentinel-X includes an automated response engine that directly injects perimeter firewall drops and commands EDR host isolation upon alert trigger.

---

**Developed with ❤️ for Advanced Enterprise Cyber Security & SOC Automation.**
