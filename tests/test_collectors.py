"""
Unit tests for CTI collectors.

These tests use mocked HTTP responses to test collector logic
without making actual API calls.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Import collectors
from collectors.nvd_collector import NVDCollector
from collectors.intel471_collector import Intel471Collector
from collectors.crowdstrike_collector import CrowdStrikeCollector
from collectors.threatq_collector import ThreatQCollector
from collectors.rapid7_collector import Rapid7Collector
from collectors.registry import collect_all, get_collector, list_available_collectors


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_credentials():
    """Sample credentials for testing."""
    return {
        "nvd_key": "test-nvd-key",
        "intel471_email": "test@example.com",
        "intel471_key": "test-intel471-key",
        "crowdstrike_id": "test-client-id",
        "crowdstrike_secret": "test-client-secret",
        "crowdstrike_base_url": "https://api.crowdstrike.com",
        "threatq_key": "test-threatq-key",
        "threatq_url": "https://threatq.example.com",
        "rapid7_key": "test-rapid7-key",
        "rapid7_region": "us"
    }


@pytest.fixture
def nvd_api_response():
    """Sample NVD API response."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-15T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A critical vulnerability in Example Software"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-5678",
                    "published": "2024-01-16T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A high severity vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH"
                                }
                            }
                        ]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "published": "2024-01-17T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A low severity vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 3.1,
                                    "baseSeverity": "LOW"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }


@pytest.fixture
def intel471_reports_response():
    """Sample Intel471 reports response."""
    return {
        "reports": [
            {
                "uid": "report-123",
                "subject": "Healthcare sector targeted by ransomware group",
                "tags": ["healthcare", "ransomware"],
                "actorHandle": "APT-Healthcare",
                "created": 1705320000000,  # Milliseconds
                "documentType": "Intelligence Report",
                "admiraltyCode": "B1",
                "motivation": ["Financial"],
                "portalReportUrl": "https://portal.intel471.com/report/123"
            }
        ]
    }


@pytest.fixture
def intel471_indicators_response():
    """Sample Intel471 indicators response."""
    return {
        "indicators": [
            {
                "uid": "indicator-456",
                "last_updated": 1705320000000,
                "data": {
                    "indicator_type": "domain",
                    "indicator_data": {"domain": "malicious.example.com"},
                    "confidence": "High",
                    "threat": {
                        "data": {"family": "Ransomware-X"}
                    }
                }
            }
        ]
    }


@pytest.fixture
def crowdstrike_token_response():
    """Sample CrowdStrike OAuth token response."""
    return {"access_token": "test-token-12345"}


@pytest.fixture
def crowdstrike_actors_response():
    """Sample CrowdStrike actors response."""
    return {
        "resources": [
            {
                "name": "FANCY BEAR",
                "origins": [{"value": "Russia"}],
                "motivations": ["Espionage"],
                "kill_chain": ["Reconnaissance", "Weaponization", "Delivery"],
                "target_industries": ["Healthcare", "Technology"],
                "last_modified_date": "2024-01-15T10:00:00Z"
            }
        ]
    }


@pytest.fixture
def rapid7_vulnerabilities_response():
    """Sample Rapid7 vulnerabilities response."""
    return {
        "data": [
            {
                "id": "vuln-123",
                "title": "Critical RCE Vulnerability",
                "severity": "Critical",
                "cves": ["CVE-2024-1234"],
                "cvss": {"v3": {"score": 9.8}},
                "exploits": 2,
                "malwareKits": 1,
                "published": "2024-01-15",
                "modified": "2024-01-16",
                "description": {"text": "Remote code execution vulnerability"},
                "riskScore": 950,
                "categories": ["remote-code-execution"]
            }
        ],
        "metadata": {
            "totalResources": 100
        }
    }


# =============================================================================
# NVD Collector Tests
# =============================================================================

class TestNVDCollector:
    """Tests for NVD collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = NVDCollector(mock_credentials)
        assert collector.source_name == "NVD"

    @pytest.mark.asyncio
    async def test_collect_success(self, mock_credentials, nvd_api_response):
        """Test successful CVE collection."""
        collector = NVDCollector(mock_credentials)

        with patch('collectors.nvd_collector.HTTPClient') as MockHTTPClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=nvd_api_response)
            MockHTTPClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockHTTPClient.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await collector.collect()

            assert result.success is True
            assert result.source == "NVD"
            # Should only include CRITICAL and HIGH (not LOW)
            assert result.record_count == 2
            assert len(result.data) == 2

            # Verify CVE IDs
            cve_ids = [cve["cve_id"] for cve in result.data]
            assert "CVE-2024-1234" in cve_ids
            assert "CVE-2024-5678" in cve_ids
            assert "CVE-2024-9999" not in cve_ids  # LOW severity excluded

    def test_extract_cvss_v31(self, mock_credentials):
        """Test CVSS extraction from v3.1 metrics."""
        collector = NVDCollector(mock_credentials)
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            }
        }
        score, severity = collector._extract_cvss(cve)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_extract_cvss_v2_fallback(self, mock_credentials):
        """Test CVSS extraction falls back to v2."""
        collector = NVDCollector(mock_credentials)
        cve = {
            "metrics": {
                "cvssMetricV2": [
                    {"cvssData": {"baseScore": 9.5}}
                ]
            }
        }
        score, severity = collector._extract_cvss(cve)
        assert score == 9.5
        assert severity == "CRITICAL"  # Derived from score


# =============================================================================
# Intel471 Collector Tests
# =============================================================================

class TestIntel471Collector:
    """Tests for Intel471 collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = Intel471Collector(mock_credentials)
        assert collector.source_name == "Intel471"

    def test_is_relevant_biotech(self, mock_credentials):
        """Test biotech relevance detection."""
        collector = Intel471Collector(mock_credentials)

        # Should be relevant
        assert collector._is_relevant_biotech("Healthcare sector under attack") is True
        assert collector._is_relevant_biotech("Attack on hospital systems") is True
        assert collector._is_relevant_biotech("Generic attack", ["healthcare", "ransomware"]) is True

        # Should not be relevant
        assert collector._is_relevant_biotech("Financial sector attack") is False

    def test_parse_report(self, mock_credentials, intel471_reports_response):
        """Test report parsing."""
        collector = Intel471Collector(mock_credentials)
        report = intel471_reports_response["reports"][0]

        parsed = collector._parse_report(report)

        assert parsed["source"] == "Intel471"
        assert parsed["threat_actor"] == "APT-Healthcare"
        assert parsed["threat_type"] == "Intelligence Report"
        assert parsed["confidence"] == "High"  # B = High
        assert "healthcare" in parsed["tags"]


# =============================================================================
# CrowdStrike Collector Tests
# =============================================================================

class TestCrowdStrikeCollector:
    """Tests for CrowdStrike collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = CrowdStrikeCollector(mock_credentials)
        assert collector.source_name == "CrowdStrike"

    def test_parse_actor(self, mock_credentials, crowdstrike_actors_response):
        """Test actor parsing."""
        collector = CrowdStrikeCollector(mock_credentials)
        actor = crowdstrike_actors_response["resources"][0]

        parsed = collector._parse_actor(actor)

        assert parsed["actor_name"] == "FANCY BEAR"
        assert parsed["country"] == "Russia"
        assert "Espionage" in parsed["motivations"]
        assert "Healthcare" in parsed["target_industries"]


# =============================================================================
# ThreatQ Collector Tests
# =============================================================================

class TestThreatQCollector:
    """Tests for ThreatQ collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = ThreatQCollector(mock_credentials)
        assert collector.source_name == "ThreatQ"

    def test_disabled_without_url(self):
        """Test collector is disabled without URL."""
        credentials = {"threatq_key": "test-key", "threatq_url": ""}
        collector = ThreatQCollector(credentials)
        assert collector.enabled is False

    def test_enabled_with_url(self, mock_credentials):
        """Test collector is enabled with URL."""
        collector = ThreatQCollector(mock_credentials)
        assert collector.enabled is True


# =============================================================================
# Rapid7 Collector Tests
# =============================================================================

class TestRapid7Collector:
    """Tests for Rapid7 collector."""

    def test_source_name(self, mock_credentials):
        """Test source name property."""
        collector = Rapid7Collector(mock_credentials)
        assert collector.source_name == "Rapid7"

    def test_get_count_list(self, mock_credentials):
        """Test count extraction from list."""
        collector = Rapid7Collector(mock_credentials)
        assert collector._get_count([1, 2, 3]) == 3

    def test_get_count_int(self, mock_credentials):
        """Test count extraction from int."""
        collector = Rapid7Collector(mock_credentials)
        assert collector._get_count(5) == 5

    def test_severity_mapping(self, mock_credentials):
        """Test severity normalization."""
        collector = Rapid7Collector(mock_credentials)
        assert collector.SEVERITY_MAP["CRITICAL"] == "Critical"
        assert collector.SEVERITY_MAP["HIGH"] == "Severe"
        assert collector.SEVERITY_MAP["MODERATE"] == "Moderate"


# =============================================================================
# Registry Tests
# =============================================================================

class TestRegistry:
    """Tests for collector registry."""

    def test_list_available_collectors(self):
        """Test listing available collectors."""
        collectors = list_available_collectors()
        assert "nvd" in collectors
        assert "intel471" in collectors
        assert "crowdstrike" in collectors
        assert "threatq" in collectors
        assert "rapid7" in collectors

    def test_get_collector(self, mock_credentials):
        """Test getting collector by name."""
        collector = get_collector("nvd", mock_credentials)
        assert collector is not None
        assert collector.source_name == "NVD"

    def test_get_unknown_collector(self, mock_credentials):
        """Test getting unknown collector returns None."""
        collector = get_collector("unknown", mock_credentials)
        assert collector is None


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
