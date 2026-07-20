"""
Unit tests for function_app.py — exposure merging and orchestration helpers.
"""

from function_app import (
    _extract_crowdstrike_cve_counts,
    _merge_exposure_into_analysis,
)

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
    def test_crowdstrike_exposure_merged(self):
        analysis = {"cve_analysis": [{"cve_id": "CVE-2024-002"}]}
        cs = [{"type": "vulnerability", "cve_ids": ["CVE-2024-002"], "device_count": 5}]

        _merge_exposure_into_analysis(analysis, cs)
        assert analysis["cve_analysis"][0]["server_count"] == 5

    def test_no_match_no_change(self):
        analysis = {"cve_analysis": [{"cve_id": "CVE-2024-999"}]}
        _merge_exposure_into_analysis(analysis, [])
        assert "server_count" not in analysis["cve_analysis"][0]

    def test_empty_cve_analysis(self):
        analysis = {"cve_analysis": []}
        _merge_exposure_into_analysis(analysis, [])  # Should not raise

    def test_missing_cve_analysis_key(self):
        analysis = {}
        _merge_exposure_into_analysis(analysis, [])  # Should not raise
