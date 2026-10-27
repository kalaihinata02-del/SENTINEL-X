import pytest
from app.models.log_event import RawLogInput
from app.pipeline.normalizer import NormalizationEngine

def test_linux_ssh_failed():
    raw = "Failed password for invalid user admin from 192.168.1.105 port 44321 ssh2"
    event = NormalizationEngine.normalize(RawLogInput(source_type="linux_auth", raw_message=raw))
    
    assert event.event_category == "authentication"
    assert event.action == "logon_failed"
    assert event.status == "FAILURE"
    assert event.actor_user == "admin"
    assert event.src_ip == "192.168.1.105"
    assert event.src_port == 44321

def test_linux_ssh_accepted():
    raw = "Accepted publickey for ubuntu from 10.0.0.50 port 55120 ssh2"
    event = NormalizationEngine.normalize(RawLogInput(source_type="linux_auth", raw_message=raw))
    
    assert event.event_category == "authentication"
    assert event.action == "logon"
    assert event.status == "SUCCESS"
    assert event.actor_user == "ubuntu"
    assert event.src_ip == "10.0.0.50"

def test_windows_process_creation():
    raw = "EventID: 4688 Computer: win-workstation CommandLine: powershell.exe -enc SQBFAFgA TargetUserName: finance_user"
    event = NormalizationEngine.normalize(RawLogInput(source_type="windows_security", raw_message=raw))
    
    assert event.event_category == "endpoint"
    assert event.action == "process_spawn"
    assert event.actor_user == "finance_user"
    assert event.hostname == "win-workstation"
    assert "-enc" in event.process_command_line

def test_web_access_log():
    raw = '185.220.101.5 - - [19/Oct/2026:07:00:00 +0000] "POST /api/v1/heartbeat HTTP/1.1" 200 128 "-" "Mozilla/5.0"'
    event = NormalizationEngine.normalize(RawLogInput(source_type="web_access", raw_message=raw))
    
    assert event.event_category == "network"
    assert event.action == "http_request"
    assert event.src_ip == "185.220.101.5"
    assert event.http_uri == "/api/v1/heartbeat"
    assert event.http_status == 200

def test_json_log_normalization():
    json_raw = '{"event_category": "endpoint", "action": "process_spawn", "username": "admin", "process": "mimikatz.exe", "CommandLine": "mimikatz.exe sekurlsa"}'
    event = NormalizationEngine.normalize(RawLogInput(source_type="generic_json", raw_message=json_raw))
    
    assert event.event_category == "endpoint"
    assert event.actor_user == "admin"
    assert event.process_name == "mimikatz.exe"
    assert "sekurlsa" in event.process_command_line
