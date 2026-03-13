"""
Unit tests for function_app.py — exposure merging and orchestration helpers.
"""
import pytest
from function_app import (
    _extract_rapid7_cve_counts,
    _extract_crowdstrike_cve_counts,
    _merge_exposure_into_analysis,
)


# =============================================================================
# _extract_rapid7_cve_counts
# =============================================================================

class TestExtractRapid7CveCounts:
    def test_basic_extraction(self):
        data = [
            {
                "top_vulnerabilities": [
                    {"cve_ids": ["CVE-2024-001"], "asset_count": 5},
                    {"cve_ids": ["CVE-2024-002", "CVE-2024-003"], "asset_count": 12},
                ]
            }
        ]
        counts = _extract_rapid7_cve_counts(data)
        assert counts == {"CVE-2024-001": 5, "CVE-2024-002": 12, "CVE-2024-003": 12}

    def test_empty_data(self):
        assert _extract_rapid7_cve_counts([]) == {}

    def test_non_dict_items_skipped(self):
        assert _extract_rapid7_cve_counts(["not-a-dict", 42]) == {}

    def test_missing_asset_count_skipped(self):
        data = [{"top_vulnerabilities": [{"cve_ids": ["CVE-2024-001"]}]}]
        assert _extract_rapid7_cve_counts(data) == {}

    def test_first_count_wins(self):
        data = [
            {"top_vulnerabilities": [{"cve_ids": ["CVE-2024-001"], "asset_count": 3}]},
            {"top_vulnerabilities": [{"cve_ids": ["CVE-2024-001"], "asset_count": 99}]},
        ]
        counts = _extract_rapid7_cve_counts(data)
        assert counts["CVE-2024-001"] == 3


# =============================================================================
# _extract_crowdstrike_cve_counts
# =============================================================================

class TestExtractCrowdstrikeCveCounts:
    def test_basic_extraction(self):
        data = [
            {"type": "vulnerability", "cve_ids": ["CVE-2024-100"], "device_count": 7},
        ]
        counts = _extract_crowdstrike_cve_counts(data)
        assert counts == {"CVE-2024-100": 7}

    def test_non_vulnerability_type_skipped(self):
        data = [{"type": "actor", "cve_ids": ["CVE-2024-100"], "device_count": 7}]
        assert _extract_crowdstrike_cve_counts(data) == {}

    def test_fallback_count_fields(self):
        data = [
            {"type": "vulnerability", "cve_ids": ["CVE-2024-A"], "asset_count": 4},
            {"type": "vulnerability", "cve_ids": ["CVE-2024-B"], "host_count": 2},
        ]
        counts = _extract_crowdstrike_cve_counts(data)
        assert counts["CVE-2024-A"] == 4
        assert counts["CVE-2024-B"] == 2

    def test_invalid_count_skipped(self):
        data = [{"type": "vulnerability", "cve_ids": ["CVE-2024-X"], "device_count": "not-a-number"}]
        assert _extract_crowdstrike_cve_counts(data) == {}

    def test_empty_data(self):
        assert _extract_crowdstrike_cve_counts([]) == {}


# =============================================================================
# _merge_exposure_into_analysis
# =============================================================================

class TestMergeExposureIntoAnalysis:
    def test_rapid7_takes_precedence(self):
        analysis = {
            "cve_analysis": [{"cve_id": "CVE-2024-001"}]
        }
        rapid7 = [{"top_vulnerabilities": [{"cve_ids": ["CVE-2024-001"], "asset_count": 10}]}]
        cs = [{"type": "vulnerability", "cve_ids": ["CVE-2024-001"], "device_count": 99}]

        _merge_exposure_into_analysis(analysis, rapid7, cs)
        assert analysis["cve_analysis"][0]["server_count"] == 10

    def test_crowdstrike_fallback(self):
        analysis = {
            "cve_analysis": [{"cve_id": "CVE-2024-002"}]
        }
        cs = [{"type": "vulnerability", "cve_ids": ["CVE-2024-002"], "device_count": 5}]

        _merge_exposure_into_analysis(analysis, [], cs)
        assert analysis["cve_analysis"][0]["server_count"] == 5

    def test_no_match_no_change(self):
        analysis = {"cve_analysis": [{"cve_id": "CVE-2024-999"}]}
        _merge_exposure_into_analysis(analysis, [], [])
        assert "server_count" not in analysis["cve_analysis"][0]

    def test_empty_cve_analysis(self):
        analysis = {"cve_analysis": []}
        _merge_exposure_into_analysis(analysis, [], [])  # Should not raise

    def test_missing_cve_analysis_key(self):
        analysis = {}
        _merge_exposure_into_analysis(analysis, [], [])  # Should not raise
