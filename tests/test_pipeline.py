import os
import pytest
from app.pipeline.orchestrator import SecurityPipeline
from app.models.log_event import RawLogInput

@pytest.fixture
def pipeline(tmp_path):
    db_file = str(tmp_path / "test_soc.db")
    return SecurityPipeline(db_path=db_file, rules_dir="rules")

def test_end_to_end_critical_incident(pipeline):
    # Ingest ransomware vssadmin deletion log
    raw = RawLogInput(
        source_type="windows_security",
        raw_message="EventID: 4688 Computer: win-workstation CommandLine: vssadmin delete shadows /all /quiet TargetUserName: finance_user",
        hostname="win-workstation"
    )
    result = pipeline.process_raw_log(raw)

    assert result["alerts_generated"] >= 1
    assert len(result["incidents_created"]) >= 1

    inc = result["incidents_created"][0]
    assert inc["severity"] == "critical"
    assert "INC-2026-" in inc["incident_id"]
    assert "vssadmin" in inc["summary"].lower() or "shadow" in inc["title"].lower()

    # Verify SOAR auto-quarantine triggered
    assert len(inc["automated_actions"]) >= 1
    action = inc["automated_actions"][0]
    assert action["playbook"] == "isolate_host"
    assert action["target"] == "win-workstation"

def test_soar_unblock(pipeline):
    ip = "185.220.101.5"
    pipeline.soar.execute_playbook("block_ip", ip)
    assert any(b["ip"] == ip for b in pipeline.soar.blocked_ips)

    # Unblock
    unblocked = pipeline.soar.unblock_ip(ip)
    assert unblocked is True
    assert not any(b["ip"] == ip for b in pipeline.soar.blocked_ips)
