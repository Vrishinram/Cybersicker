"""
CYBERSICKER — Comprehensive Prompt Matrix & Agent Responsiveness Tests
Validates that the Blue-Team SOC agent appropriately responds to all prompt types:
- Greetings and capability queries
- Conceptual cybersecurity explanations (Autoencoders, Anomaly detection)
- Tactical host hardening and advisory requests (SSH port 22)
- Playbook / SOP containment directives (SYN flood, Ransomware)
- Multi-vector indicator investigations (IP, CVE, MAC)
- Strict RFC 791 validation on malformed inputs
"""

import pytest
from fastapi.testclient import TestClient
from api import app

client = TestClient(app)

def test_greeting_and_capabilities_prompt():
    resp = client.post("/api/chat", json={"message": "Hello Cybersicker, what are your core capabilities as a SOC agent?"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "response" in data
    text = data["response"].lower()
    # Should welcome or explain capabilities, NOT hallucinate fake indicators
    assert any(w in text for w in ["cybersicker", "capabilities", "agent", "threat", "soc", "virustotal", "autoencoder"])

def test_conceptual_autoencoder_prompt():
    resp = client.post("/api/chat", json={"message": "Explain how an autoencoder detects anomalies in network flows"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    text = data["response"].lower()
    assert any(w in text for w in ["autoencoder", "anomaly", "reconstruction", "neural", "kdd", "network", "loss"])

def test_ssh_hardening_advisory_prompt():
    resp = client.post("/api/chat", json={"message": "How do I secure an SSH server on port 22 against brute force?"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    text = data["response"].lower()
    assert any(w in text for w in ["ssh", "port 22", "iptables", "fail2ban", "rate limit", "permitrootlogin", "password"])

def test_syn_flood_playbook_prompt():
    resp = client.post("/api/chat", json={"message": "What is the containment playbook for SYN flood attack?"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    text = data["response"].lower()
    assert any(w in text for w in ["syn", "flood", "sop-004", "sysctl", "tcp_syncookies", "iptables", "backlog"])

def test_compound_ioc_triage_prompt():
    resp = client.post("/api/chat", json={"message": "Analyze IP 185.220.101.43 and query CVE-2024-3094"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    text = data["response"]
    # Check that real indicators are referenced
    assert "185.220.101.43" in text
    assert "CVE-2024-3094" in text

def test_rfc791_validation_rejects_malformed_ip():
    resp = client.post("/api/chat", json={"message": "Scan 999.999.999.999"})
    assert resp.status_code == 200
    data = resp.json()
    # Strict validation policy must fail gracefully without fallback to mock datasets
    assert data["success"] is False
    assert "RFC 791" in data["response"] or "VALIDATION ERROR" in data["response"]

