#!/usr/bin/env python3
"""
Sentinel-X Enterprise SOC Detection Engineering & Automation Platform Launcher.
Run with: python run.py
"""

import uvicorn
import os
import sys

def main():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════════╗
  ║    ____ _____ _   _ _____ ___ _   _ _____ _       __  __          ║
  ║   / ___| ____| \ | |_   _|_ _| \ | | ____| |      \ \/ /          ║
  ║   \___ \  _| |  \| | | |  | ||  \| |  _| | |   ____\  /           ║
  ║    ___) | |__| |\  | | |  | || |\  | |___| |__|_____/ \           ║
  ║   |____/|_____|_| \_| |_| |___|_| \_|_____|_____|  /_/\_\         ║
  ║                                                                   ║
  ║   Enterprise SOC Detection Engineering & SOAR Platform           ║
  ║   Log Normalization -> Detection Rules -> SOAR Playbooks          ║
  ╚═══════════════════════════════════════════════════════════════════╝
    """)
    print("[*] Starting Sentinel-X SOC Platform Server...")
    print("[*] Web Dashboard URL: http://localhost:8000")
    print("[*] Interactive Swagger API Docs: http://localhost:8000/docs")
    print("[*] Press Ctrl+C to stop.\n")

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    main()
