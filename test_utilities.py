"""
Testing utilities and base fixtures for CYBERSICKER
Provides test infrastructure and reusable fixtures
"""

import pytest
from typing import Generator, Any, Dict
from unittest.mock import Mock, MagicMock, patch
from fastapi.testclient import TestClient
import json

# Test client configuration
class APITestClient:
    """Wrapper for FastAPI test client with utilities"""
    
    def __init__(self, app):
        self.client = TestClient(app)
        self.base_headers = {"Content-Type": "application/json"}
    
    def set_auth_token(self, token: str):
        """Set JWT token for authenticated requests"""
        self.base_headers["Authorization"] = f"Bearer {token}"
    
    def set_api_key(self, api_key: str):
        """Set API key for authenticated requests"""
        self.base_headers["Authorization"] = f"Bearer {api_key}"
    
    def clear_auth(self):
        """Clear authentication headers"""
        self.base_headers.pop("Authorization", None)
    
    def get(self, path: str, **kwargs) -> Any:
        """GET request wrapper"""
        kwargs.setdefault("headers", self.base_headers)
        return self.client.get(path, **kwargs)
    
    def post(self, path: str, data: Dict = None, **kwargs) -> Any:
        """POST request wrapper"""
        kwargs.setdefault("headers", self.base_headers)
        if data:
            kwargs["json"] = data
        return self.client.post(path, **kwargs)
    
    def put(self, path: str, data: Dict = None, **kwargs) -> Any:
        """PUT request wrapper"""
        kwargs.setdefault("headers", self.base_headers)
        if data:
            kwargs["json"] = data
        return self.client.put(path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> Any:
        """DELETE request wrapper"""
        kwargs.setdefault("headers", self.base_headers)
        return self.client.delete(path, **kwargs)

# Fixtures for common test scenarios
@pytest.fixture
def mock_api_client():
    """Fixture providing mock API client"""
    return APITestClient(None)

@pytest.fixture
def sample_threat_data() -> Dict[str, Any]:
    """Fixture providing sample threat data"""
    return {
        "threat_type": "malware",
        "indicator": "192.168.1.100",
        "severity": "high",
        "context": "Detected in network scan",
        "timestamp": "2026-05-05T12:00:00Z",
    }

@pytest.fixture
def sample_network_scan_data() -> Dict[str, Any]:
    """Fixture providing sample network scan data"""
    return {
        "target": "192.168.1.0/24",
        "scan_type": "basic",
        "timeout": 30,
        "results": {
            "active_hosts": 15,
            "open_ports": [22, 80, 443, 3306],
            "vulnerabilities": 3,
        }
    }

@pytest.fixture
def sample_user_data() -> Dict[str, Any]:
    """Fixture providing sample user data"""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "role": "analyst",
        "department": "SOC",
    }

@pytest.fixture
def mock_external_service():
    """Fixture providing mock external service"""
    return MagicMock()

@pytest.fixture
def mock_database():
    """Fixture providing mock database"""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    return mock_db

class TestBase:
    """Base class for test suites with common utilities"""
    
    @staticmethod
    def assert_response_valid(response: Any, expected_status: int = 200):
        """Assert response is valid JSON and has expected status"""
        assert response.status_code == expected_status, (
            f"Expected status {expected_status}, got {response.status_code}: "
            f"{response.text}"
        )
        assert response.headers.get("content-type") == "application/json"
        return response.json()
    
    @staticmethod
    def assert_error_response(response: Any, expected_status: int = 400):
        """Assert response is an error with expected status"""
        data = TestBase.assert_response_valid(response, expected_status)
        assert "error" in data or "detail" in data
        return data
    
    @staticmethod
    def assert_paginated_response(response: Any):
        """Assert response has pagination structure"""
        data = TestBase.assert_response_valid(response)
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        return data
    
    @staticmethod
    def create_auth_headers(token: str) -> Dict[str, str]:
        """Create authorization headers with token"""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

class MockThreatDetector:
    """Mock threat detector for testing"""
    
    def __init__(self):
        self.detected_threats = []
    
    def detect(self, indicator: str, threat_type: str) -> Dict[str, Any]:
        """Mock threat detection"""
        threat = {
            "indicator": indicator,
            "threat_type": threat_type,
            "severity": "high",
            "confidence": 0.95,
            "timestamp": "2026-05-05T12:00:00Z",
        }
        self.detected_threats.append(threat)
        return threat
    
    def get_all_detected(self) -> list:
        """Get all detected threats"""
        return self.detected_threats
    
    def reset(self):
        """Reset mock state"""
        self.detected_threats = []

class MockNetworkScanner:
    """Mock network scanner for testing"""
    
    def __init__(self):
        self.scan_history = []
    
    def scan(self, target: str, scan_type: str = "basic") -> Dict[str, Any]:
        """Mock network scan"""
        results = {
            "target": target,
            "scan_type": scan_type,
            "status": "completed",
            "active_hosts": 10,
            "open_ports": [22, 80, 443],
            "vulnerabilities": 2,
            "scan_time": 5.23,
        }
        self.scan_history.append(results)
        return results
    
    def get_history(self) -> list:
        """Get scan history"""
        return self.scan_history

# Performance testing utilities
class PerformanceTracker:
    """Track performance metrics during tests"""
    
    def __init__(self):
        self.metrics = {}
    
    def record(self, operation: str, duration_ms: float):
        """Record operation duration"""
        if operation not in self.metrics:
            self.metrics[operation] = []
        self.metrics[operation].append(duration_ms)
    
    def get_stats(self, operation: str) -> Dict[str, float]:
        """Get statistics for operation"""
        if operation not in self.metrics:
            return {}
        
        timings = self.metrics[operation]
        return {
            "count": len(timings),
            "min": min(timings),
            "max": max(timings),
            "avg": sum(timings) / len(timings),
        }
    
    def assert_performance(self, operation: str, max_duration_ms: float):
        """Assert operation duration is within threshold"""
        stats = self.get_stats(operation)
        assert stats.get("max", 0) <= max_duration_ms, (
            f"Operation {operation} exceeded max duration: "
            f"{stats.get('max')}ms > {max_duration_ms}ms"
        )
