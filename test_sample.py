"""
Sample test suite for CYBERSICKER API
Demonstrates testing patterns and best practices
"""

import pytest
from test_utilities import (
    TestBase,
    APITestClient,
    MockThreatDetector,
    MockNetworkScanner,
    PerformanceTracker,
)

class TestThreatAnalysis(TestBase):
    """Test threat analysis endpoints"""
    
    @pytest.fixture
    def threat_detector(self):
        return MockThreatDetector()
    
    def test_detect_malware_threat(self, threat_detector):
        """Test malware threat detection"""
        result = threat_detector.detect("192.168.1.100", "malware")
        
        assert result["threat_type"] == "malware"
        assert result["severity"] == "high"
        assert result["confidence"] == 0.95
        assert len(threat_detector.get_all_detected()) == 1
    
    def test_detect_multiple_threats(self, threat_detector):
        """Test detecting multiple threats"""
        threat_detector.detect("192.168.1.100", "malware")
        threat_detector.detect("example.com", "phishing")
        threat_detector.detect("10.0.0.5", "intrusion")
        
        detected = threat_detector.get_all_detected()
        assert len(detected) == 3
    
    def test_threat_detector_reset(self, threat_detector):
        """Test resetting threat detector state"""
        threat_detector.detect("192.168.1.100", "malware")
        assert len(threat_detector.get_all_detected()) == 1
        
        threat_detector.reset()
        assert len(threat_detector.get_all_detected()) == 0

class TestNetworkScanning(TestBase):
    """Test network scanning functionality"""
    
    @pytest.fixture
    def scanner(self):
        return MockNetworkScanner()
    
    def test_basic_network_scan(self, scanner):
        """Test basic network scan"""
        result = scanner.scan("192.168.1.0/24", "basic")
        
        assert result["target"] == "192.168.1.0/24"
        assert result["status"] == "completed"
        assert result["active_hosts"] > 0
        assert len(result["open_ports"]) > 0
    
    def test_scan_history(self, scanner):
        """Test scan history tracking"""
        scanner.scan("192.168.1.0/24", "basic")
        scanner.scan("10.0.0.0/8", "deep")
        
        history = scanner.get_history()
        assert len(history) == 2
        assert history[0]["target"] == "192.168.1.0/24"
        assert history[1]["target"] == "10.0.0.0/8"
    
    def test_scan_types(self, scanner):
        """Test different scan types"""
        basic_result = scanner.scan("192.168.1.0/24", "basic")
        deep_result = scanner.scan("192.168.1.0/24", "deep")
        
        assert basic_result["scan_type"] == "basic"
        assert deep_result["scan_type"] == "deep"

class TestPerformance(TestBase):
    """Test performance and optimization"""
    
    @pytest.fixture
    def perf_tracker(self):
        return PerformanceTracker()
    
    def test_operation_performance(self, perf_tracker):
        """Test recording operation performance"""
        perf_tracker.record("query_database", 10.5)
        perf_tracker.record("query_database", 12.3)
        perf_tracker.record("query_database", 11.8)
        
        stats = perf_tracker.get_stats("query_database")
        assert stats["count"] == 3
        assert stats["min"] == 10.5
        assert stats["max"] == 12.3
        assert 11 < stats["avg"] < 12
    
    def test_performance_assertion(self, perf_tracker):
        """Test performance assertion"""
        perf_tracker.record("api_call", 5.0)
        perf_tracker.record("api_call", 8.0)
        perf_tracker.record("api_call", 6.5)
        
        # Should pass
        perf_tracker.assert_performance("api_call", 10.0)
        
        # Should fail
        with pytest.raises(AssertionError):
            perf_tracker.assert_performance("api_call", 5.0)

class TestValidation(TestBase):
    """Test input validation"""
    
    def test_valid_threat_data(self):
        """Test validation of valid threat data"""
        threat_data = {
            "threat_type": "malware",
            "indicator": "192.168.1.100",
            "severity": "high",
        }
        # Should not raise
        assert threat_data["threat_type"] == "malware"
    
    def test_invalid_threat_severity(self):
        """Test validation of invalid severity"""
        with pytest.raises(ValueError):
            threat_data = {
                "severity": "invalid_level"
            }
            if threat_data["severity"] not in ["critical", "high", "medium", "low", "info"]:
                raise ValueError("Invalid severity level")

class TestCaching(TestBase):
    """Test caching functionality"""
    
    @pytest.fixture
    def cache_stats(self):
        stats = {"hits": 0, "misses": 0}
        return stats
    
    def test_cache_hit(self, cache_stats):
        """Test cache hit"""
        # Simulate cache hit
        cache_stats["hits"] += 1
        
        assert cache_stats["hits"] == 1
        assert cache_stats["misses"] == 0
    
    def test_cache_miss(self, cache_stats):
        """Test cache miss"""
        # Simulate cache miss
        cache_stats["misses"] += 1
        
        assert cache_stats["hits"] == 0
        assert cache_stats["misses"] == 1
    
    def test_cache_hit_rate(self, cache_stats):
        """Test cache hit rate calculation"""
        cache_stats["hits"] = 80
        cache_stats["misses"] = 20
        
        hit_rate = cache_stats["hits"] / (cache_stats["hits"] + cache_stats["misses"])
        assert hit_rate == 0.8

# Integration test markers
@pytest.mark.slow
class TestIntegration(TestBase):
    """Integration tests for complete workflows"""
    
    def test_threat_detection_workflow(self):
        """Test complete threat detection workflow"""
        detector = MockThreatDetector()
        scanner = MockNetworkScanner()
        
        # Scan network
        scan_result = scanner.scan("192.168.1.0/24", "basic")
        
        # Detect threats
        for ip in ["192.168.1.100", "192.168.1.101"]:
            detector.detect(ip, "malware")
        
        # Verify results
        assert len(scanner.get_history()) == 1
        assert len(detector.get_all_detected()) == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
