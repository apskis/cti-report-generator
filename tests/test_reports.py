"""
Tests for report generators.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from src.reports.base import BaseReportGenerator, BrandColors, FontSizes
from src.reports.registry import (
    get_report_generator,
    register_report_generator,
    list_report_types,
    REPORT_REGISTRY,
)
from src.reports.weekly_report import WeeklyReportGenerator
from src.reports.quarterly_report import QuarterlyReportGenerator


class TestBrandColors:
    """Tests for brand color constants."""

    def test_orange_primary_value(self):
        assert BrandColors.ORANGE_PRIMARY is not None

    def test_gray_colors_defined(self):
        assert BrandColors.GRAY_DARK is not None
        assert BrandColors.GRAY_MEDIUM is not None

    def test_severity_colors_defined(self):
        assert BrandColors.RED_CRITICAL is not None
        assert BrandColors.ORANGE_HIGH is not None


class TestFontSizes:
    """Tests for font size constants."""

    def test_title_size(self):
        assert FontSizes.TITLE.pt == 18

    def test_body_size(self):
        assert FontSizes.BODY.pt == 10.5

    def test_subtitle_size(self):
        assert FontSizes.SUBTITLE.pt == 9


class TestReportRegistry:
    """Tests for the report registry."""

    def test_weekly_report_registered(self):
        """WeeklyReportGenerator should be auto-registered on import."""
        assert "weekly" in REPORT_REGISTRY
        assert REPORT_REGISTRY["weekly"] == WeeklyReportGenerator

    def test_get_report_generator_weekly(self):
        """get_report_generator should return WeeklyReportGenerator for 'weekly'."""
        generator = get_report_generator("weekly")
        assert generator is not None
        assert isinstance(generator, WeeklyReportGenerator)

    def test_get_report_generator_case_insensitive(self):
        """get_report_generator should be case-insensitive."""
        generator = get_report_generator("WEEKLY")
        assert generator is not None
        assert isinstance(generator, WeeklyReportGenerator)

    def test_get_report_generator_unknown_type(self):
        """get_report_generator should return None for unknown types."""
        generator = get_report_generator("unknown_type")
        assert generator is None

    def test_list_report_types(self):
        """list_report_types should include 'weekly'."""
        types = list_report_types()
        assert "weekly" in types


class TestWeeklyReportGenerator:
    """Tests for the WeeklyReportGenerator."""

    @pytest.fixture
    def generator(self):
        """Create a fresh generator instance."""
        return WeeklyReportGenerator()

    @pytest.fixture
    def sample_analysis_result(self):
        """Sample analysis result for testing."""
        return {
            "executive_summary": "This week we identified 5 new vulnerabilities.",
            "statistics": {
                "total_cves": 10,
                "critical_count": 2,
                "high_count": 3,
                "exploited_count": 1,
                "apt_groups": 2,
                "new_this_week": 5,
                "persistent_count": 3,
                "resolved_count": 2,
            },
            "cve_analysis": [
                {
                    "cve_id": "CVE-2026-1234",
                    "affected_product": "TestApp",
                    "exposure": "Remote code execution",
                    "exploited_by": "APT29",
                    "risk": "CRITICAL",
                    "weeks_detected": 4,
                },
                {
                    "cve_id": "CVE-2026-5678",
                    "affected_product": "TestLib",
                    "exposure": "SQL injection",
                    "exploited_by": "None known",
                    "risk": "HIGH",
                    "weeks_detected": 1,
                },
            ],
            "apt_activity": [
                {
                    "actor": "APT29",
                    "country": "Russia",
                    "motivation": "Espionage",
                    "activity": "Targeting healthcare organizations",
                    "ttps": ["T1566", "T1059", "T1027"],
                    "what_to_monitor": "Phishing emails with healthcare themes",
                },
            ],
            "recommendations": [
                "Patch CVE-2026-1234 immediately",
                "Review access controls for TestApp",
                "Enable MFA for all admin accounts",
            ],
            "exploitation_indicators": [
                "CVE-2026-1234 (TestApp): Unusual outbound connections on port 443",
            ],
        }

    def test_report_type(self, generator):
        """report_type should return 'weekly'."""
        assert generator.report_type == "weekly"

    def test_filename_prefix(self, generator):
        """filename_prefix should return 'CTI_Weekly_Report'."""
        assert generator.filename_prefix == "CTI_Weekly_Report"

    def test_get_filename_format(self, generator):
        """get_filename should return properly formatted filename."""
        filename = generator.get_filename()
        assert filename.startswith("CTI_Weekly_Report_")
        assert filename.endswith(".docx")
        # Should contain date in YYYY-MM-DD format
        date_str = generator.created_at.strftime("%Y-%m-%d")
        assert date_str in filename

    def test_generate_creates_document(self, generator, sample_analysis_result):
        """generate should create a valid Document object."""
        doc = generator.generate(sample_analysis_result)
        assert doc is not None
        assert generator.doc is not None

    def test_generate_with_empty_data(self, generator):
        """generate should handle empty analysis result gracefully."""
        doc = generator.generate({})
        assert doc is not None

    def test_to_bytes_after_generate(self, generator, sample_analysis_result):
        """to_bytes should return bytes after generate is called."""
        generator.generate(sample_analysis_result)
        doc_bytes = generator.to_bytes()
        assert isinstance(doc_bytes, bytes)
        assert len(doc_bytes) > 0
        # DOCX files start with PK (zip signature)
        assert doc_bytes[:2] == b"PK"

    def test_to_bytes_before_generate_raises(self, generator):
        """to_bytes should raise if generate wasn't called."""
        with pytest.raises(ValueError, match="Document not generated"):
            generator.to_bytes()

    def test_week_calculation(self, generator, sample_analysis_result):
        """Week dates should be calculated correctly."""
        generator.generate(sample_analysis_result)
        # week_start should be a Monday
        assert generator.week_start.weekday() == 0
        # week_end should be a Sunday
        assert generator.week_end.weekday() == 6
        # Should be 6 days apart
        delta = generator.week_end - generator.week_start
        assert delta.days == 6

    def test_document_has_paragraphs(self, generator, sample_analysis_result):
        """Generated document should have paragraphs."""
        doc = generator.generate(sample_analysis_result)
        assert len(doc.paragraphs) > 0

    def test_document_has_tables(self, generator, sample_analysis_result):
        """Generated document should have tables (metric cards, CVE table, etc.)."""
        doc = generator.generate(sample_analysis_result)
        assert len(doc.tables) > 0

    def test_document_contains_title(self, generator, sample_analysis_result):
        """Document should contain the report title."""
        doc = generator.generate(sample_analysis_result)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Cyber Threat Intelligence Weekly Report" in text_content

    def test_document_contains_executive_summary(self, generator, sample_analysis_result):
        """Document should contain executive summary section."""
        doc = generator.generate(sample_analysis_result)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Executive Summary" in text_content
        assert "This week we identified 5 new vulnerabilities" in text_content

    def test_document_contains_recommendations(self, generator, sample_analysis_result):
        """Document should contain recommendations."""
        doc = generator.generate(sample_analysis_result)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Recommended Actions" in text_content
        assert "Patch CVE-2026-1234" in text_content


class TestBaseReportGenerator:
    """Tests for BaseReportGenerator utility methods."""

    @pytest.fixture
    def generator(self):
        return WeeklyReportGenerator()

    def test_get_week_number(self, generator):
        """_get_week_number should return valid ISO week number."""
        week = generator._get_week_number()
        assert 1 <= week <= 53

    def test_get_year(self, generator):
        """_get_year should return current year."""
        year = generator._get_year()
        assert year == datetime.now().year

    def test_format_date_range(self, generator):
        """_format_date_range should produce readable date range."""
        date_range = generator._format_date_range()
        assert "to" in date_range
        # Should contain month name
        assert any(month in date_range for month in [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ])


class TestQuarterlyReportGenerator:
    """Tests for the QuarterlyReportGenerator."""

    @pytest.fixture
    def generator(self):
        """Create a fresh generator instance."""
        return QuarterlyReportGenerator()

    @pytest.fixture
    def sample_strategic_analysis(self):
        """Sample strategic analysis result for testing."""
        return {
            "executive_summary": "The threat landscape remained elevated throughout the quarter.",
            "risk_assessment": {
                "nation_state": "HIGH",
                "nation_state_trend": "↑",
                "ransomware": "HIGH",
                "ransomware_trend": "Unchanged",
                "supply_chain": "MEDIUM",
                "supply_chain_trend": "Unchanged",
                "insider": "LOW",
                "insider_trend": "Unchanged"
            },
            "breach_landscape": {
                "total_incidents": 47,
                "prev_total_incidents": 36,
                "total_impact_millions": 127,
                "prev_total_impact": 89,
                "ransomware_count": 18,
                "prev_ransomware": 12,
                "records_exposed_millions": 4.2,
                "prev_records": 2.8
            },
            "incidents_by_type": [
                {"type": "Ransomware", "current_count": 18, "prev_count": 12, "notable_example": "Pharma manufacturer: 12-day production halt, FDA notification"},
                {"type": "Data Theft / Exfiltration", "current_count": 11, "prev_count": 9, "notable_example": "Genomics institute: 2.3M patient samples accessed"},
                {"type": "Manufacturing / OT Disruption", "current_count": 5, "prev_count": 3, "notable_example": "Medical device mfg: assembly line shutdown, 8-day recovery"},
                {"type": "Business Email Compromise", "current_count": 6, "prev_count": 5, "notable_example": "CRO: $3.8M fraudulent wire transfers"},
                {"type": "Third-Party / Vendor", "current_count": 4, "prev_count": 4, "notable_example": "Lab software vendor: credentials exposed for 200+ customers"},
                {"type": "Unauthorized Access", "current_count": 3, "prev_count": 3, "notable_example": "Biotech: former employee accessed IP post-termination"},
            ],
            "common_factors": "Unpatched systems (34%), compromised credentials (28%)",
            "geopolitical_threats": {
                "china": {
                    "strategic_context": "China's strategic interest in biotech",
                    "activity": "APT41 conducted multiple intrusions",
                    "implications": "IP theft risk for proprietary research"
                },
                "russia": {
                    "strategic_context": "Russian ransomware ecosystem",
                    "activity": "Ransomware incidents increased 31%",
                    "implications": "Operational disruption risk"
                },
                "north_korea": {
                    "strategic_context": "NK dual-purpose operations",
                    "activity": "LinkedIn social engineering campaigns",
                    "implications": "Credential compromise risk"
                }
            },
            "looking_ahead": {
                "threat_outlook": "Continued pressure from state-sponsored campaigns",
                "planned_initiatives": "Enhanced detection capabilities",
                "watch_items": "Major industry events and announcements"
            },
            "recommendations": [
                ("Executive Awareness", "Targeted security awareness for executives"),
                ("Vendor Risk Review", "Evaluate vendor security posture"),
            ]
        }

    def test_report_type(self, generator):
        """report_type should return 'quarterly'."""
        assert generator.report_type == "quarterly"

    def test_filename_prefix(self, generator):
        """filename_prefix should return 'CTI_Quarterly_Strategic_Brief'."""
        assert generator.filename_prefix == "CTI_Quarterly_Strategic_Brief"

    def test_get_filename_format(self, generator):
        """get_filename should return properly formatted filename."""
        filename = generator.get_filename()
        assert filename.startswith("CTI_Quarterly_Strategic_Brief_")
        assert filename.endswith(".docx")

    def test_quarterly_registered(self):
        """QuarterlyReportGenerator should be registered."""
        assert "quarterly" in REPORT_REGISTRY
        assert REPORT_REGISTRY["quarterly"] == QuarterlyReportGenerator

    def test_get_report_generator_quarterly(self):
        """get_report_generator should return QuarterlyReportGenerator for 'quarterly'."""
        generator = get_report_generator("quarterly")
        assert generator is not None
        assert isinstance(generator, QuarterlyReportGenerator)

    def test_generate_creates_document(self, generator, sample_strategic_analysis):
        """generate should create a valid Document object."""
        doc = generator.generate(sample_strategic_analysis)
        assert doc is not None
        assert generator.doc is not None

    def test_generate_with_empty_data(self, generator):
        """generate should handle empty analysis result gracefully."""
        doc = generator.generate({})
        assert doc is not None

    def test_to_bytes_after_generate(self, generator, sample_strategic_analysis):
        """to_bytes should return bytes after generate is called."""
        generator.generate(sample_strategic_analysis)
        doc_bytes = generator.to_bytes()
        assert isinstance(doc_bytes, bytes)
        assert len(doc_bytes) > 0
        # DOCX files start with PK (zip signature)
        assert doc_bytes[:2] == b"PK"

    def test_quarter_calculation(self, generator, sample_strategic_analysis):
        """Quarter should be calculated correctly."""
        generator.generate(sample_strategic_analysis)
        # Quarter should be 1-4
        assert 1 <= generator.quarter <= 4
        # Quarter start should be first of month
        assert generator.quarter_start.day == 1
        # Quarter months should be correct
        if generator.quarter == 1:
            assert generator.quarter_start.month == 1
            assert generator.quarter_end.month == 3
        elif generator.quarter == 2:
            assert generator.quarter_start.month == 4
            assert generator.quarter_end.month == 6
        elif generator.quarter == 3:
            assert generator.quarter_start.month == 7
            assert generator.quarter_end.month == 9
        else:  # Q4
            assert generator.quarter_start.month == 10
            assert generator.quarter_end.month == 12

    def test_document_has_paragraphs(self, generator, sample_strategic_analysis):
        """Generated document should have paragraphs."""
        doc = generator.generate(sample_strategic_analysis)
        assert len(doc.paragraphs) > 0

    def test_document_has_tables(self, generator, sample_strategic_analysis):
        """Generated document should have tables (risk cards, breach stats, etc.)."""
        doc = generator.generate(sample_strategic_analysis)
        assert len(doc.tables) > 0

    def test_document_contains_title(self, generator, sample_strategic_analysis):
        """Document should contain the report title."""
        doc = generator.generate(sample_strategic_analysis)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Cyber Threat Intelligence" in text_content
        assert "Quarterly Strategic Brief" in text_content

    def test_document_contains_executive_summary(self, generator, sample_strategic_analysis):
        """Document should contain executive summary section."""
        doc = generator.generate(sample_strategic_analysis)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Executive Summary" in text_content
        assert "elevated" in text_content

    def test_document_contains_geopolitical_section(self, generator, sample_strategic_analysis):
        """Document should contain geopolitical threat landscape."""
        doc = generator.generate(sample_strategic_analysis)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Geopolitical Threat Landscape" in text_content
        # Should have country sections
        assert "China" in text_content
        assert "Russia" in text_content

    def test_document_contains_recommendations(self, generator, sample_strategic_analysis):
        """Document should contain recommendations for leadership."""
        doc = generator.generate(sample_strategic_analysis)
        text_content = "\n".join([p.text for p in doc.paragraphs])
        assert "Recommendations for Leadership" in text_content


class TestReportTypesList:
    """Tests for list_report_types functionality."""

    def test_list_includes_weekly(self):
        """list_report_types should include 'weekly'."""
        types = list_report_types()
        assert "weekly" in types

    def test_list_includes_quarterly(self):
        """list_report_types should include 'quarterly'."""
        types = list_report_types()
        assert "quarterly" in types

    def test_both_types_registered(self):
        """Both weekly and quarterly should be registered."""
        assert len(REPORT_REGISTRY) >= 2
        assert "weekly" in REPORT_REGISTRY
        assert "quarterly" in REPORT_REGISTRY
