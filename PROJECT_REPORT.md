# INTERNSHIP PROJECT REPORT

---

## 1. Project Title
**SENTINEL-X: Enterprise-Style Detection Engineering & SOC Automation (SIEM/SOAR) Platform**

---

## 2. Why Did You Choose This Project?
In modern enterprise cybersecurity, Security Operations Centers (SOCs) are overwhelmed by millions of raw security logs from heterogeneous systems (Linux, Windows Active Directory, network firewalls, and cloud services). Analyzing these logs manually leads to alert fatigue, missed intrusions, and dangerously high Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR). 

I chose this project to gain end-to-end, hands-on experience in **Detection Engineering, SIEM architecture, and SOAR automation**—the exact core competencies utilized by Tier-1 defense teams (e.g., CrowdStrike Falcon, Splunk Enterprise Security, and Palo Alto Cortex). Building this platform allowed me to bridge the gap between theory and real-world adversary behavior by mapping detection signatures to the **MITRE ATT&CK® framework** and automating incident containment.

---

## 3. Technologies & Tools Used
* **Backend Framework & Language:** Python 3.15, FastAPI (Asynchronous REST API engine)
* **Log Schema & Normalization:** OCSF (Open Cybersecurity Schema Framework) & ECS (Elastic Common Schema)
* **Detection Engineering:** YAML-based Sigma-style detection rules with custom sliding-window correlation
* **Database & Persistence:** SQLite with structured indexing & JSON column attributes
* **Threat Intelligence & Enrichment:** Offline GeoIP, ASN mapping, Tor Exit Node / C2 indicator DB, CMDB Asset Inventory
* **Frontend Operations UI:** Single Page Cyber SOC Dashboard (HTML5, Tailwind CSS, Chart.js, FontAwesome)
* **Testing & Quality Assurance:** Pytest (11 automated unit and integration tests)

---

## 4. How You Completed the Project (Approach & Methodology)
I designed and executed the project following a modular 6-stage engineering lifecycle:

1. **Log Ingestion & Unified Normalization:** Engineered regex and structured parsers capable of consuming Linux `auth.log` (SSH/Sudo), Windows Security Event Logs (`4624`, `4625`, `4688`), Zeek network connection flows, and web access logs. Raw payloads are normalized into a unified `NormalizedEvent` schema with standard fields (`actor_user`, `src_ip`, `hostname`, `process_command_line`).
2. **Rule Authoring & Detection Engine:** Authored 9 multi-domain detection rules across Authentication, Endpoint, and Network vectors. Developed a stateful sliding-window evaluator supporting both single-event immediate triggers and multi-event thresholding ($\ge 5$ attempts within 60 seconds).
3. **Automated Context Enrichment:** Designed an enrichment pipeline that automatically calculates a dynamic composite risk score (0–100) by querying Threat Intelligence reputation and CMDB asset criticality (e.g., Tier-0 Domain Controller vs. standard workstation).
4. **SOC Incident Management:** Structured an automated ticketing engine that groups correlated alerts into `INC-2026-XXXX` tickets with chronological attacker timelines, evidence logs, and MITRE ATT&CK tactic/technique tags.
5. **SOAR Mitigation Playbooks:** Implemented automated containment playbooks (`block_ip` on perimeter firewall, `isolate_host` via simulated EDR, `revoke_user` account lock) with audit logging.
6. **SOC Analyst Dashboard & Simulator:** Created an interactive dark-mode Operations Dashboard featuring a 1-click Attack Simulator that replays real-world attack scenarios (SSH Brute Force, Mimikatz LSASS Dump, PowerShell Download Cradle, Ransomware Defense Evasion, and C2 Beaconing).

---

## 5. What You Learned (Key Technical Skills & Concepts Gained)
* **Detection Engineering Lifecycle:** Developing, testing, and tuning detection logic using Sigma-style YAML definitions.
* **Stateful Stream Correlation:** Implementing in-memory sliding time windows and suppression cooldowns to prevent alert storms and duplicate ticketing.
* **MITRE ATT&CK® Matrix Mapping:** Practical alignment of attack patterns (T1110.001 Brute Force, T1059.001 PowerShell, T1003.001 LSASS Dumping, T1490 Inhibit System Recovery, T1071.001 C2 Web Protocols).
* **SOAR Automation:** Designing closed-loop automated playbooks that reduce response time from hours to milliseconds.
* **REST API & Schema Architecture:** Building modular APIs using FastAPI, Pydantic validation, and SQLite persistence.

---

## 6. Challenges Faced & Solutions
| Challenge Encountered | Root Cause | Solution Implemented |
|---|---|---|
| **Disparate Log Syntaxes** | Windows EVTX, Linux syslog, and Zeek logs use completely different key-value conventions. | Built an intelligent normalization engine with lookahead regexes that dynamically extract entities into a standardized OCSF schema. |
| **Alert Fatigue & Duplication** | High-frequency attack events (e.g., brute force) generated flood warnings for every subsequent failed packet. | Implemented a stateful sliding-window manager with time-window pruning and a 30-second suppression cooldown per entity. |
| **Python 3.15 C-Extension Limitations** | Standard `pyyaml` lacked pre-built binary wheels for Python 3.15 on Windows. | Evaluated and integrated pure-Python `strictyaml`, ensuring zero C++ compiler dependencies and zero-friction portability. |

---

## 7. Final Outcome
The project successfully delivered a fully functional, self-contained **Enterprise SOC & Detection Engineering Platform**:
* **100% Pipeline Automation:** Tested and verified end-to-end: `Raw Log → Normalization → YAML Rule Matching → Threat Intel Enrichment → Incident Ticket → SOAR Containment`.
* **Zero-Setup Web Operations UI:** A modern dark-mode Cyber Operations Dashboard running at `http://localhost:8000` with live metrics, MITRE heatmap, and interactive incident investigation.
* **1-Click Live Attack Simulator:** Built-in attack traces allow mentors and evaluators to trigger real-time attacks and watch the automated pipeline respond instantly.
* **Verified Code Quality:** 11/11 automated unit and integration tests passing in under 1 second.
