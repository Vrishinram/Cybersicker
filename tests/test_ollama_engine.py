"""
Tests for Ollama LLM integration and Health Endpoint in Cybersicker
"""

import pytest
from fastapi.testclient import TestClient
from api import app
from agent import build_soc_agent

def test_health_reports_ollama():
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"
    assert data["llm_provider"] == "ollama"
    assert "ollama_model" in data
    assert "ollama_host" in data

def test_build_soc_agent_ollama():
    agent = build_soc_agent(provider="ollama", model="llama3.2")
    assert agent is not None
