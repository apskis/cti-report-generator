"""
Tests for report generators.
"""

from datetime import datetime

import pytest

from src.reports.base import BrandColors, FontSizes
from src.reports.quarterly_report import QuarterlyReportGenerator
from src.reports.registry import (
    REPORT_REGISTRY,
    get_report_generator,
    list_report_types,
)
from src.reports.weekly_report import WeeklyReportGenerator


@pytest.fixture(autouse=True)
def _isolate_quarterly_history(monkeypatch, tmp_path):
    """Keep the quarterly history-file side effect out of the working tree (Q25).

    Quarterly generate() persists risk history; redirect it to a temp dir so tests
    never write data/historical/ into the repo checkout.
    """
    monkeypatch.setenv("QUARTERLY_HISTORY_DIR", str(tmp_path / "quarterly_hist"))


def _get_document_text(doc):
    """Collect all text from document paragraphs and table cells."""
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    parts.append(p.text)
    return "\n".join(parts)


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
        # Weekly reports are named by ISO year and week number, e.g. CTI_Weekly_Report_2026_Week30.docx
        assert "_Week" in filename
        assert str(generator.created_at.isocalendar()[0]) in filename

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
        """Lookback period dates should be calculated correctly."""
        generator.generate(sample_analysis_result)
        assert hasattr(generator, "period_start")
        assert hasattr(generator, "period_end")
        delta = generator.period_end - generator.period_start
        assert delta.days == generator.lookback_days

    def test_document_has_paragraphs(self, generator, sample_analysis_result):
        """Generated document should have paragraphs."""
        doc = generator.generate(sample_analysis_result)
        assert len(doc.paragraphs) > 0

    def test_document_has_tables(self, generator, sample_analysis_result):
        """Generated document should have tables (metric cards, CVE table, etc.)."""
        doc = generator.generate(sample_analysis_result)
        assert len(doc.tables) > 0

    def test_document_contains_title(self, generator, sample_analysis_result):
        """Document should contain the report title (may be in a paragraph or table cell)."""
        doc = generator.generate(sample_analysis_result)
        text_content = _get_document_text(doc)
        assert "Cyber Threat Intelligence Weekly Report" in text_content

    def test_document_contains_executive_summary(self, generator, sample_analysis_result):
        """Document should contain executive summary section."""
        doc = generator.generate(sample_analysis_result)
        text_content = _get_document_text(doc)
        assert "Summary" in text_content
        assert "This week we identified 5 new vulnerabilities" in text_content

    def test_document_contains_recommendations(self, generator, sample_analysis_result):
        """Document should contain recommendations."""
        doc = generator.generate(sample_analysis_result)
        text_content = _get_document_text(doc)
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
        assert any(
            month in date_range
            for month in [
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ]
        )


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
                "insider_trend": "Unchanged",
            },
            "breach_landscape": {
                "total_incidents": 47,
                "prev_total_incidents": 36,
                "total_impact_millions": 127,
                "prev_total_impact": 89,
                "ransomware_count": 18,
                "prev_ransomware": 12,
                "records_exposed_millions": 4.2,
                "prev_records": 2.8,
            },
            "incidents_by_type": [
                {
                    "type": "Ransomware",
                    "current_count": 18,
                    "prev_count": 12,
                    "notable_example": "Pharma manufacturer: 12-day production halt, FDA notification",
                },
                {
                    "type": "Data Theft / Exfiltration",
                    "current_count": 11,
                    "prev_count": 9,
                    "notable_example": "Genomics institute: 2.3M patient samples accessed",
                },
                {
                    "type": "Manufacturing / OT Disruption",
                    "current_count": 5,
                    "prev_count": 3,
                    "notable_example": "Medical device mfg: assembly line shutdown, 8-day recovery",
                },
                {
                    "type": "Business Email Compromise",
                    "current_count": 6,
                    "prev_count": 5,
                    "notable_example": "CRO: $3.8M fraudulent wire transfers",
                },
                {
                    "type": "Third-Party / Vendor",
                    "current_count": 4,
                    "prev_count": 4,
                    "notable_example": "Lab software vendor: credentials exposed for 200+ customers",
                },
                {
                    "type": "Unauthorized Access",
                    "current_count": 3,
                    "prev_count": 3,
                    "notable_example": "Biotech: former employee accessed IP post-termination",
                },
            ],
            "common_factors": "Unpatched systems (34%), compromised credentials (28%)",
            "geopolitical_threats": [
                {
                    "country": "China",
                    "threat_level": "HIGH",
                    "relevance": ["Strategic interest in biotech and genomics IP"],
                    "activity": ["APT41 conducted multiple intrusions"],
                    "risk": ["IP theft risk for proprietary research"],
                },
                {
                    "country": "Russia",
                    "threat_level": "MEDIUM",
                    "relevance": ["Ransomware ecosystem targeting manufacturing"],
                    "activity": ["Ransomware incidents increased 31%"],
                    "risk": ["Operational disruption risk"],
                },
                {
                    "country": "North Korea",
                    "threat_level": "MEDIUM",
                    "relevance": ["Dual-purpose revenue and espionage operations"],
                    "activity": ["LinkedIn social engineering campaigns"],
                    "risk": ["Credential compromise risk"],
                },
            ],
            "looking_ahead": {
                "threat_outlook": "Continued pressure from state-sponsored campaigns",
                "planned_initiatives": "Enhanced detection capabilities",
                "watch_items": [
                    {"subject": "Industry events", "detail": "Major industry events and announcements"},
                    {"subject": "Regulatory shifts", "detail": "New data-protection rules in key markets"},
                ],
            },
            "recommendations": {
                "intro_note": "Priority actions for the coming quarter.",
                "items": [
                    {"title": "Executive Awareness", "body": "Targeted security awareness for executives"},
                    {"title": "Vendor Risk Review", "body": "Evaluate vendor security posture"},
                ],
            },
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
        """Quarter and lookback period should be calculated correctly."""
        generator.generate(sample_strategic_analysis)
        assert 1 <= generator.quarter <= 4
        assert hasattr(generator, "period_start")
        assert hasattr(generator, "period_end")
        delta = generator.period_end - generator.period_start
        assert delta.days == generator.lookback_days

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
        text_content = _get_document_text(doc)
        assert "Geopolitical Threat Landscape" in text_content
        # Should have country sections (rendered as a per-country table)
        assert "China" in text_content
        assert "Russia" in text_content

    def test_document_contains_recommendations(self, generator, sample_strategic_analysis):
        """Document should contain recommendations for leadership."""
        doc = generator.generate(sample_strategic_analysis)
        text_content = _get_document_text(doc)
        assert "Recommendations" in text_content
        assert "Executive Awareness" in text_content


# =============================================================================
# Quarterly robustness (Part 5): malformed AI output must degrade, not crash;
# plus regression tests for the display bugs (Q17 badge, Q18 trend, Q26 cards, Q23).
# =============================================================================


class TestQuarterlyRobustness:
    @pytest.fixture
    def generator(self):
        return QuarterlyReportGenerator()

    # ----- Part 5: malformed strategic analysis degrades without raising -----

    @pytest.mark.parametrize(
        "analysis",
        [
            {"risk_assessment": None},
            {"risk_assessment": {"nation_state": None, "ransomware": None}},
            {"geopolitical_threats": ["China", "Russia"]},
            {"looking_ahead": None},
            {
                "breach_landscape": {
                    "stat_cards": [
                        {"value": 20, "label": "Total", "prior_value": "N/A", "change_pct": "N/A"}
                    ],
                    "incidents_by_type": [
                        {"type": "Ransomware", "current_count": 12, "prev_count": 10, "notable_example": "Acme: hit"}
                    ],
                }
            },
            {"breach_landscape": {"stat_cards": [{"value": 1, "change_pct": "+high%"}]}},
            {"incidents_by_type": [{"type": "X", "current_count": 3, "notable_example": "Y: z"}]},
        ],
    )
    def test_malformed_strategic_analysis_does_not_raise(self, generator, analysis):
        doc = generator.generate(analysis)
        assert doc is not None
        assert len(doc.paragraphs) > 0

    # ----- Q18: risk-card trend arrows map to a direction, not "Unchanged" -----

    def test_trend_arrows_render_direction(self, generator):
        analysis = {
            "risk_assessment": {
                "nation_state": "HIGH",
                "nation_state_trend": "↑",
                "ransomware": "MEDIUM",
                "ransomware_trend": "↓",
                "supply_chain": "LOW",
                "supply_chain_trend": "Unchanged",
                "insider": "LOW",
                "insider_trend": "Unchanged",
            }
        }
        doc = generator.generate(analysis)
        text = _get_document_text(doc)
        assert "Increased" in text
        assert "Decreased" in text

    # ----- Q17: geopolitical badge honors the AI's "level"/"threat_level" -----

    def test_threat_level_badge_reads_level_key(self, generator):
        analysis = {
            "geopolitical_threats": [
                {"name": "China", "level": "CRITICAL", "relevance": ["x"], "activity": ["y"], "risk": ["z"]}
            ]
        }
        doc = generator.generate(analysis)
        text = _get_document_text(doc)
        # The real assessed level must appear, not a hardcoded MEDIUM default.
        assert "CRITICAL" in text

    # ----- Q26: stat cards render for counts other than exactly 4 -----

    @pytest.mark.parametrize("num_cards", [1, 2, 3, 4])
    def test_stat_cards_render_for_varied_counts(self, generator, num_cards):
        cards = [
            {"value": str(i), "label": f"Metric {i}", "prior_value": "N/A", "change_pct": "N/A"}
            for i in range(num_cards)
        ]
        analysis = {"breach_landscape": {"stat_cards": cards, "incidents_by_type": []}}
        doc = generator.generate(analysis)
        text = _get_document_text(doc)
        for i in range(num_cards):
            assert f"Metric {i}" in text

    def test_na_prior_value_does_not_render_fabricated_percent(self, generator):
        cards = [{"value": "20", "label": "Total Incidents", "prior_label": "Q1 2026", "prior_value": "N/A", "change_pct": "N/A"}]
        analysis = {"breach_landscape": {"stat_cards": cards, "incidents_by_type": []}}
        doc = generator.generate(analysis)
        text = _get_document_text(doc)
        assert "Total Incidents" in text
        # No parenthetical percentage when there is no real prior data.
        assert "(N/A)" not in text

    # ----- Q23: inline citations are subscripted document-wide in quarterly -----

    def test_quarterly_citations_are_subscripted(self, generator):
        analysis = {"executive_summary": "Breach at Stadler Rail [1] and follow-up [2] noted."}
        doc = generator.generate(analysis)
        subscript_runs = [r.text for p in doc.paragraphs for r in p.runs if r.font.subscript]
        assert "[1]" in subscript_runs
        assert "[2]" in subscript_runs


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


# =============================================================================
# Inline citation subscript rendering (brackets kept, document-wide)
# =============================================================================


class TestCitationSubscripts:
    def test_split_markers_keeps_brackets(self):
        from src.reports.base import _split_citation_markers

        parts = _split_citation_markers("system [3][4]. Done.")
        assert parts == [("system ", False), ("[3][4]", True), (". Done.", False)]

    def test_no_citations_returns_single_segment(self):
        from src.reports.base import _split_citation_markers

        assert _split_citation_markers("no citations here") == [("no citations here", False)]

    def test_paragraph_citations_become_subscript_with_brackets(self):
        from docx import Document

        from src.reports.base import _subscript_citations_in_paragraph

        doc = Document()
        para = doc.add_paragraph("breach at Stadler Rail [1] this week [2].")
        _subscript_citations_in_paragraph(para)

        subscript_runs = [r.text for r in para.runs if r.font.subscript]
        # Brackets are KEPT and the markers are subscripted.
        assert subscript_runs == ["[1]", "[2]"]
        assert "Stadler Rail" in "".join(r.text for r in para.runs)

    def test_document_wide_pass_covers_table_cells(self):
        from docx import Document

        from src.reports.weekly_report import WeeklyReportGenerator

        gen = WeeklyReportGenerator.__new__(WeeklyReportGenerator)
        gen.doc = Document()
        gen.doc.add_paragraph("Summary cites [1].")
        table = gen.doc.add_table(rows=1, cols=1)
        table.rows[0].cells[0].paragraphs[0].add_run("[3] CrowdStrike")

        gen._subscript_all_citations()

        # Body paragraph citation subscripted...
        body = gen.doc.paragraphs[0]
        assert [r.text for r in body.runs if r.font.subscript] == ["[1]"]
        # ...and the table-cell citation too.
        cell_para = table.rows[0].cells[0].paragraphs[0]
        assert [r.text for r in cell_para.runs if r.font.subscript] == ["[3]"]
        assert "CrowdStrike" in "".join(r.text for r in cell_para.runs)
