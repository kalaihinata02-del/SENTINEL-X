import pytest
from app.pipeline.detection_engine import DetectionEngine
from app.models.log_event import NormalizedEvent

@pytest.fixture
def engine():
    return DetectionEngine("rules")

def test_rules_loaded(engine):
    assert len(engine.rules) >= 8
    assert "AUTH-001" in engine.rules
    assert "ENDP-001" in engine.rules
    assert "ENDP-002" in engine.rules
    assert "NETW-002" in engine.rules

def test_powershell_cradle_detection(engine):
    event = NormalizedEvent(
        event_source="windows_security",
        event_category="endpoint",
        action="process_spawn",
        process_command_line="powershell.exe -w hidden -enc SQBFAFgA...",
        hostname="win-workstation"
    )
    alerts = engine.evaluate_event(event)
    assert len(alerts) >= 1
    rule_ids = [a.rule_id for a in alerts]
    assert "ENDP-001" in rule_ids
    assert alerts[0].severity == "critical"

def test_mimikatz_detection(engine):
    event = NormalizedEvent(
        event_source="windows_security",
        event_category="endpoint",
        action="process_spawn",
        process_command_line="mimikatz.exe sekurlsa::logonpasswords",
        hostname="dc-prod-01"
    )
    alerts = engine.evaluate_event(event)
    assert len(alerts) >= 1
    assert any(a.rule_id == "ENDP-002" for a in alerts)

def test_ssh_bruteforce_threshold(engine):
    ip = "192.168.100.200"
    alerts = []
    # Ingest 4 failed attempts (should not alert yet)
    for _ in range(4):
        ev = NormalizedEvent(
            event_source="linux_auth",
            event_category="authentication",
            action="logon_failed",
            src_ip=ip
        )
        alerts.extend(engine.evaluate_event(ev))
    assert not any(a.rule_id == "AUTH-001" for a in alerts)

    # 5th attempt (hits threshold)
    ev5 = NormalizedEvent(
        event_source="linux_auth",
        event_category="authentication",
        action="logon_failed",
        src_ip=ip
    )
    alerts_5 = engine.evaluate_event(ev5)
    assert any(a.rule_id == "AUTH-001" for a in alerts_5)
