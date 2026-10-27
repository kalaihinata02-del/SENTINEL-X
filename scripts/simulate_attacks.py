#!/usr/bin/env python3
"""
Sentinel-X CLI Attack Simulation Script.
Allows demonstrating the full Log -> Detection -> Alert -> Enrichment -> Incident -> SOAR
pipeline from terminal or automated test runners.
"""

import sys
import time
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

SCENARIOS = [
    ("ssh_bruteforce", "SSH Brute Force Credential Attack (AUTH-001)"),
    ("powershell_cradle", "Obfuscated PowerShell Download Cradle (ENDP-001)"),
    ("mimikatz_dump", "LSASS Memory Credential Dumping - Mimikatz (ENDP-002)"),
    ("ransomware_attack", "Ransomware Defense Evasion - Shadow Copies Deletion (ENDP-004)"),
    ("c2_beaconing", "Cobalt Strike C2 Beaconing (NETW-002)"),
    ("port_scan", "TCP Port Scan Sweep Reconnaissance (NETW-001)"),
    ("dns_tunneling", "DNS Tunneling Data Exfiltration (NETW-003)"),
    ("benign_traffic", "Legitimate Corporate User Traffic")
]

def check_server():
    try:
        r = requests.get(f"{BASE_URL}/api/metrics", timeout=3)
        return r.status_code == 200
    except Exception:
        return False

def run_scenario(scenario_key, desc):
    print(f"\n[>>>] Triggering Scenario: {desc}...")
    try:
        r = requests.post(f"{BASE_URL}/api/simulation/run", json={"scenario": scenario_key}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            res = data.get("result", {})
            alerts = res.get("total_alerts", res.get("alerts_generated", 0))
            incidents = res.get("incidents", res.get("incidents_created", []))
            print(f"  [+] Status: SUCCESS")
            print(f"  [+] Description: {data.get('description')}")
            print(f"  [!] Alerts Triggered: {alerts}")
            print(f"  [!] Incidents Created: {len(incidents)}")
            for inc in incidents:
                print(f"      - {inc.get('incident_id')}: {inc.get('title')} ({inc.get('severity').upper()})")
                for act in inc.get("automated_actions", []):
                    print(f"        * [SOAR AUTOMATION] {act.get('message')}")
        else:
            print(f"  [-] Failed with status code {r.status_code}: {r.text}")
    except Exception as e:
        print(f"  [-] Error: {e}")

def main():
    print("=" * 70)
    print("   SENTINEL-X ENTERPRISE DETECTION & SOC AUTOMATION PIPELINE DEMO")
    print("=" * 70)

    if not check_server():
        print(f"\n[!] WARNING: The Sentinel-X server is not responding at {BASE_URL}.")
        print("[!] Please start the server first by running: python run.py")
        sys.exit(1)

    print("\nSelect a simulation option:")
    for idx, (k, desc) in enumerate(SCENARIOS, 1):
        print(f"  {idx}. {desc}")
    print(f"  9. Run ALL Attack Scenarios (Full Demonstration)")
    print(f"  0. Exit")

    choice = input("\nEnter choice [0-9]: ").strip()
    if choice == "0":
        print("Exiting.")
        sys.exit(0)
    elif choice == "9":
        for k, desc in SCENARIOS:
            run_scenario(k, desc)
            time.sleep(1)
    else:
        try:
            val = int(choice)
            if 1 <= val <= len(SCENARIOS):
                k, desc = SCENARIOS[val - 1]
                run_scenario(k, desc)
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid input.")

if __name__ == "__main__":
    main()
