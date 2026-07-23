"""
Quarterly Strategic CTI Report Generator.

Generates quarterly strategic threat intelligence briefs for leadership.
"""

import json
import logging
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from src.core.config import customer_profile
from src.reports.base import BaseReportGenerator, BrandColors, FontSizes
from src.reports.registry import register_report_generator

logger = logging.getLogger(__name__)


class RiskLevel:
    """Risk level constants for quarterly assessments."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNCHANGED = "Unchanged"
    INCREASED = "↑"
    DECREASED = "↓"


@register_report_generator("quarterly")
class QuarterlyReportGenerator(BaseReportGenerator):
    """
    Quarterly Strategic CTI Report Generator.

    Generates leadership-focused strategic threat briefs matching
    the CTI_Quarterly_Strategic_Report_Example.docx format.

    Template structure:
    - Report ID header (CTI-QTR-YYYY-QN)
    - Title: "Cyber Threat Intelligence" / "Quarterly Strategic Brief"
    - Quarter date range
    - Executive Summary (strategic overview)
    - Quarterly Risk Assessment (risk metric cards)
    - Industry Breach Landscape (incidents table)
    - Geopolitical Threat Landscape (by nation-state)
    - Looking Ahead (next quarter outlook)
    - Recommendations for Leadership
    - Footer with sources
    """

    @property
    def report_type(self) -> str:
        return "quarterly"

    @property
    def filename_prefix(self) -> str:
        return "CTI_Quarterly_Strategic_Brief"

    def generate(self, analysis_result: dict[str, Any]) -> Document:
        """
        Generate the quarterly strategic report document.

        Args:
            analysis_result: Dictionary containing:
                - executive_summary: str (strategic overview)
                - risk_assessment: dict with risk levels
                - breach_landscape: dict with incident statistics
                - incidents_by_type: list of incident type breakdowns
                - geopolitical_threats: dict by country (china, russia, north_korea, etc.)
                - looking_ahead: dict with outlook, initiatives, watch_items
                - recommendations: list of strategic recommendations

        Returns:
            Document object
        """
        try:
            logger.info("Generating Quarterly Strategic CTI Report")
            self.doc = Document()

            # Set default font to Arial for the entire document
            self._set_default_font("Arial")

            # Print-style: white page with dark body text so the document displays
            # correctly in both light and dark mode (parity with the weekly report).
            self._set_document_background(BrandColors.PAGE_WHITE)
            normal_style = self.doc.styles["Normal"]
            normal_style.font.color.rgb = BrandColors.TEXT_DARK

            # Configure page settings (margins, header/footer distances, paragraph spacing)
            self._configure_page_settings()

            # Calculate quarter info
            self._calculate_quarter_info()

            # Add sections in order
            self._add_header()
            self._add_executive_summary(analysis_result)
            self._add_risk_assessment(analysis_result)
            self._add_geopolitical_landscape(analysis_result)
            self._add_breach_landscape(analysis_result)
            self._add_looking_ahead(analysis_result)
            self._add_recommendations(analysis_result)
            self._add_sources(analysis_result)
            self._add_footer()

            # Document-wide pass: render every inline citation marker ([1], [3][4]) as a
            # subscript, wherever it appears (summary, tables, cards, incidents, etc.).
            self._subscript_all_citations()

            logger.info("Quarterly Strategic CTI Report generated successfully")
            return self.doc

        except Exception as e:
            logger.error(f"Error generating quarterly report: {str(e)}", exc_info=True)
            raise

    def _set_cell_left_border(self, cell, color_hex: str, size: str = "4") -> None:
        """
        Apply a left border to a table cell (used for accent borders on geo cards and stat cards).

        Args:
            cell: The table cell to apply left border to
            color_hex: Border color in hex format (e.g., "E65100" for orange)
            size: Border size as string (e.g., "12" for thicker, "4" for thin)
        """
        tc_pr = cell._element.get_or_add_tcPr()
        tc_borders = tc_pr.find(qn("w:tcBorders"))
        if tc_borders is None:
            tc_borders = OxmlElement("w:tcBorders")
            tc_pr.append(tc_borders)

        left_border = tc_borders.find(qn("w:left"))
        if left_border is None:
            left_border = OxmlElement("w:left")
            tc_borders.append(left_border)

        left_border.set(qn("w:val"), "single")
        left_border.set(qn("w:sz"), size)
        left_border.set(qn("w:space"), "0")
        left_border.set(qn("w:color"), color_hex)

    def _calculate_quarter_info(self) -> None:
        """Calculate the reporting period based on actual quarterly lookback window."""
        from src.core.config import collector_config

        today = self.created_at
        month = today.month

        lookback_days = collector_config.intel471_quarterly_lookback_days
        self.period_end = today
        self.period_start = today - timedelta(days=lookback_days)
        self.lookback_days = lookback_days

        if month <= 3:
            self.quarter = 1
        elif month <= 6:
            self.quarter = 2
        elif month <= 9:
            self.quarter = 3
        else:
            self.quarter = 4

    def _get_historical_file_path(self) -> Path:
        """Get the path to the historical data JSON file."""
        data_dir = Path("data/historical")
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / "quarterly_risk_history.json"

    def _load_historical_data(self) -> dict[str, Any]:
        """Load historical quarterly risk assessment data."""
        file_path = self._get_historical_file_path()
        if not file_path.exists():
            return {}

        try:
            with open(file_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load historical data: {e}")
            return {}

    def _save_historical_data(self, history: dict[str, Any]) -> None:
        """Save historical quarterly risk assessment data."""
        file_path = self._get_historical_file_path()
        try:
            with open(file_path, "w") as f:
                json.dump(history, f, indent=2)
            logger.info(f"Saved historical data to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save historical data: {e}")

    def _get_quarter_key(self, year: int, quarter: int) -> str:
        """Get a string key for a specific quarter."""
        return f"{year}-Q{quarter}"

    def _calculate_previous_quarter(self, year: int, quarter: int) -> tuple:
        """Calculate the previous quarter's year and number."""
        if quarter == 1:
            return (year - 1, 4)
        else:
            return (year, quarter - 1)

    def _save_current_risk_assessment(self, risk_data: dict[str, Any]) -> None:
        """Save the current quarter's risk assessment to history."""
        history = self._load_historical_data()

        year = self._get_year()
        quarter_key = self._get_quarter_key(year, self.quarter)

        # Store the risk assessment for this quarter
        history[quarter_key] = {
            "timestamp": self.created_at.isoformat(),
            "year": year,
            "quarter": self.quarter,
            "nation_state": risk_data.get("nation_state", "MEDIUM"),
            "ransomware": risk_data.get("ransomware", "MEDIUM"),
            "supply_chain": risk_data.get("supply_chain", "MEDIUM"),
            "insider": risk_data.get("insider", "LOW"),
        }

        self._save_historical_data(history)
        logger.info(f"Saved risk assessment for {quarter_key}")

    def _compare_with_previous_quarter(self, current_risk: str, previous_risk: str) -> str:
        """Compare current risk level with previous quarter and return trend indicator."""
        risk_values = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

        current_val = risk_values.get(current_risk.upper(), 2)
        previous_val = risk_values.get(previous_risk.upper(), 2)

        if current_val > previous_val:
            return "↑"
        elif current_val < previous_val:
            return "↓"
        else:
            return "Unchanged"

    def _get_previous_quarter(self) -> str:
        """Get the previous quarter string (e.g., 'Q4 2025')."""
        if self.quarter == 1:
            return f"Q4 {self._get_year() - 1}"
        return f"Q{self.quarter - 1} {self._get_year()}"

    def _add_header(self) -> None:
        """Add report header with banner image, ID, title, and date range."""
        year = self._get_year()

        # Add banner image at the top
        self._add_banner_header()

        # Report ID (e.g., CTI-QTR-2026-Q1) - positioned at top-right
        report_id = f"CTI-QTR-{year}-Q{self.quarter}"
        id_para = self.doc.add_paragraph()
        id_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        id_run = id_para.add_run(report_id)
        id_run.font.name = "Arial"
        id_run.font.size = FontSizes.SUBTITLE
        id_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        # Main title - Quarterly Strategic Brief (styled like Book Title, orange, 20pt, centered)
        title_para = self.doc.add_paragraph()
        title_run = title_para.add_run("Quarterly Strategic Brief")
        title_run.font.name = "Arial"
        title_run.font.size = Pt(20)  # Font size 20pt
        title_run.font.bold = True
        title_run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER  # Center-aligned
        # Reduce spacing after title
        title_para.paragraph_format.space_after = Pt(0)

        # Subtitle - Reporting period based on actual lookback
        date_range = (
            f"{self.lookback_days}-Day Lookback | "
            f"{self.period_start.strftime('%B %d')} to {self.period_end.strftime('%B %d, %Y')}"
        )

        subtitle_para = self.doc.add_paragraph(date_range, style="Subtitle")
        for run in subtitle_para.runs:
            run.font.name = "Arial"
            run.font.color.rgb = BrandColors.GRAY_DARK
        subtitle_para.alignment = WD_ALIGN_PARAGRAPH.CENTER  # Center-aligned
        # Reduce spacing after subtitle
        subtitle_para.paragraph_format.space_after = Pt(0)

        # Spacer after cover page
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

    def _add_executive_summary(self, analysis_result: dict[str, Any]) -> None:
        """Add executive summary section."""
        logger.info("Adding Executive Summary section")

        # Executive Summary heading - Heading 1
        summary_heading = self.doc.add_heading("Executive Summary", level=1)
        for run in summary_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)  # Font size 14pt
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        # Add space after heading
        summary_heading.paragraph_format.space_after = Pt(6)

        # Get summary paragraphs
        summary = analysis_result.get("executive_summary", "")
        if not summary:
            summary = self._generate_default_executive_summary(analysis_result)

        # Split into paragraphs if it's a long string
        paragraphs = summary.split("\n\n") if "\n\n" in summary else [summary]

        for para_text in paragraphs:
            if para_text.strip():
                para = self.doc.add_paragraph(para_text.strip())
                for run in para.runs:
                    run.font.name = "Arial"
                    run.font.size = FontSizes.BODY

        # Spacer after executive summary
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

    def _generate_default_executive_summary(self, analysis_result: dict[str, Any]) -> str:
        """Generate a default executive summary from available data."""
        stats = analysis_result.get("breach_landscape", {})
        total_incidents = stats.get("total_incidents", 0)
        # geopolitical_threats is a list of per-country entries in the current format;
        # tolerate the legacy dict form ({"actors": [...]}) without crashing.
        geo = analysis_result.get("geopolitical_threats", [])
        apt_groups = len(geo) if isinstance(geo, list) else len(geo.get("actors", []))

        return f"""The threat landscape for the genomics, life sciences, and precision manufacturing sectors \
remained elevated throughout Q{self.quarter} {self._get_year()}, with {total_incidents} publicly disclosed \
breaches affecting peer organizations in the industry.

No direct threats to the organization were identified this quarter; however, the threat actors, techniques, \
and vulnerabilities observed are consistent with those historically used against genomics companies. \
{apt_groups} threat actor groups were observed targeting the sector with varying levels of sophistication."""

    def _add_risk_assessment(self, analysis_result: dict[str, Any]) -> None:
        """Add quarterly risk assessment section with risk cards."""
        logger.info("Adding Quarterly Risk Assessment section")

        # Quarterly Risk Assessment heading - Heading 1
        risk_heading = self.doc.add_heading("Quarterly Risk Assessment", level=1)
        for run in risk_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)  # Font size 14pt
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        # Add space before and after heading
        risk_heading.paragraph_format.space_before = Pt(12)
        risk_heading.paragraph_format.space_after = Pt(6)

        # Add explanatory paragraph for risk ratings
        explanation = self.doc.add_paragraph()
        explanation.paragraph_format.space_before = Pt(0)
        explanation.paragraph_format.space_after = Pt(12)
        explanation.paragraph_format.line_spacing = 1.15

        exp_text = (
            "Risk levels are assessed based on observed threat actor activity, peer organization incidents, "
            "and potential business impact. "
        )
        exp_run = explanation.add_run(exp_text)
        exp_run.font.name = "Arial"
        exp_run.font.size = Pt(11)
        exp_run.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add HIGH definition
        high_run = explanation.add_run("HIGH")
        high_run.font.name = "Arial"
        high_run.font.size = Pt(11)
        high_run.font.bold = True
        high_run.font.color.rgb = RGBColor(0xDC, 0x35, 0x45)  # Red

        high_def = explanation.add_run(" indicates active targeting with multiple incidents; ")
        high_def.font.name = "Arial"
        high_def.font.size = Pt(11)
        high_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add MEDIUM definition
        medium_run = explanation.add_run("MEDIUM")
        medium_run.font.name = "Arial"
        medium_run.font.size = Pt(11)
        medium_run.font.bold = True
        medium_run.font.color.rgb = RGBColor(0xFF, 0x8C, 0x00)  # Orange

        medium_def = explanation.add_run(" reflects ongoing activity with moderate incident levels; ")
        medium_def.font.name = "Arial"
        medium_def.font.size = Pt(11)
        medium_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add LOW definition
        low_run = explanation.add_run("LOW")
        low_run.font.name = "Arial"
        low_run.font.size = Pt(11)
        low_run.font.bold = True
        low_run.font.color.rgb = RGBColor(0x28, 0xA7, 0x45)  # Green

        low_def = explanation.add_run(" represents minimal observed activity or limited sector-specific targeting.")
        low_def.font.name = "Arial"
        low_def.font.size = Pt(11)
        low_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # `or {}` guards a present-but-null value (the AI can emit `"risk_assessment": null`,
        # which `.get(k, {})` would NOT protect against).
        risk_data = analysis_result.get("risk_assessment") or {}

        # Load historical data to compare with previous quarter
        history = self._load_historical_data()
        year = self._get_year()
        prev_year, prev_quarter = self._calculate_previous_quarter(year, self.quarter)
        prev_quarter_key = self._get_quarter_key(prev_year, prev_quarter)
        previous_assessment = history.get(prev_quarter_key, {})

        # Get current risk levels. `(x or default)` coerces present-but-null values too.
        current_nation_state = (risk_data.get("nation_state") or RiskLevel.HIGH).upper()
        current_ransomware = (risk_data.get("ransomware") or RiskLevel.HIGH).upper()
        current_supply_chain = (risk_data.get("supply_chain") or RiskLevel.MEDIUM).upper()
        current_insider = (risk_data.get("insider") or RiskLevel.LOW).upper()

        # Get AI's trend assessments from analysis
        ai_nation_state_trend = risk_data.get("nation_state_trend", RiskLevel.UNCHANGED)
        ai_ransomware_trend = risk_data.get("ransomware_trend", RiskLevel.UNCHANGED)
        ai_supply_chain_trend = risk_data.get("supply_chain_trend", RiskLevel.UNCHANGED)
        ai_insider_trend = risk_data.get("insider_trend", RiskLevel.UNCHANGED)

        # Calculate trends by comparing with previous quarter
        # ONLY use historical comparison if we have prior quarter data AND the AI didn't provide trends
        # Otherwise, trust the AI's analysis which considers breach statistics
        if (
            previous_assessment
            and ai_nation_state_trend == RiskLevel.UNCHANGED
            and ai_ransomware_trend == RiskLevel.UNCHANGED
        ):
            # Historical comparison mode - calculate trends from stored risk levels
            nation_state_trend = self._compare_with_previous_quarter(
                current_nation_state, previous_assessment.get("nation_state", "MEDIUM")
            )
            ransomware_trend = self._compare_with_previous_quarter(
                current_ransomware, previous_assessment.get("ransomware", "MEDIUM")
            )
            supply_chain_trend = self._compare_with_previous_quarter(
                current_supply_chain, previous_assessment.get("supply_chain", "MEDIUM")
            )
            insider_trend = self._compare_with_previous_quarter(
                current_insider, previous_assessment.get("insider", "LOW")
            )
            logger.info(
                f"Using historical comparison with {prev_quarter_key}: trends calculated from stored risk levels"
            )
        else:
            # Use AI's trend assessment (which considers breach statistics, not just risk level changes)
            nation_state_trend = ai_nation_state_trend
            ransomware_trend = ai_ransomware_trend
            supply_chain_trend = ai_supply_chain_trend
            insider_trend = ai_insider_trend
            logger.info("Using AI's trend assessment based on breach statistics and threat intelligence")

        # Save current assessment for future comparisons
        self._save_current_risk_assessment(
            {
                "nation_state": current_nation_state,
                "ransomware": current_ransomware,
                "supply_chain": current_supply_chain,
                "insider": current_insider,
            }
        )

        risks = [
            (
                "Nation-State Espionage",
                current_nation_state,
                nation_state_trend,
                None,  # No percentage data available
            ),
            (
                "Ransomware & Extortion",
                current_ransomware,
                ransomware_trend,
                None,  # Could calculate from breach data if available
            ),
            (
                "Supply Chain Compromise",
                current_supply_chain,
                supply_chain_trend,
                None,  # No percentage data available
            ),
            (
                "Insider Threat",
                current_insider,
                insider_trend,
                None,  # No percentage data available
            ),
        ]

        # Create horizontal table (1 row, 4 columns)
        table = self.doc.add_table(rows=1, cols=len(risks))
        table.alignment = WD_TABLE_ALIGNMENT.LEFT  # Left align table like the example

        # Set table width to 100%
        tbl = table._element
        # Get or create tblPr element
        tbl_pr = tbl.find(qn("w:tblPr"))
        if tbl_pr is None:
            tbl_pr = OxmlElement("w:tblPr")
            tbl.insert(0, tbl_pr)  # Insert at the beginning

        tbl_w = tbl_pr.find(qn("w:tblW"))
        if tbl_w is None:
            tbl_w = OxmlElement("w:tblW")
            tbl_pr.append(tbl_w)
        tbl_w.set(qn("w:w"), "5000")  # 5000 = 100% in Word's 50ths of a percent
        tbl_w.set(qn("w:type"), "pct")  # Percentage type

        # Fill table cells with risk data
        for i, (category, level, trend, calculated_pct) in enumerate(risks):
            cell = table.rows[0].cells[i]
            cell.paragraphs[0].clear()

            # Set cell vertical alignment to center for better alignment
            tc_pr = cell._element.get_or_add_tcPr()
            v_align = tc_pr.find(qn("w:vAlign"))
            if v_align is None:
                v_align = OxmlElement("w:vAlign")
                tc_pr.append(v_align)
            v_align.set(qn("w:val"), "center")  # Center vertically

            # Set cell padding: 120 twips all sides
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)

            for margin_type in ["top", "bottom", "left", "right"]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), "120")  # 120 twips
                margin.set(qn("w:type"), "dxa")

            # Determine background and text color based on risk level
            level_upper = level.upper()
            if level_upper == "HIGH":
                bg_color = "FEE2E2"  # Light red
                text_color = RGBColor(0x99, 0x1B, 0x1B)  # Dark red
            elif level_upper == "MEDIUM":
                bg_color = "FEF3C7"  # Light amber
                text_color = RGBColor(0x92, 0x40, 0x0E)  # Dark amber
            elif level_upper == "LOW":
                bg_color = "D1FAE5"  # Light green
                text_color = RGBColor(0x06, 0x5F, 0x46)  # Dark green
            else:
                # Default for unexpected values
                bg_color = "FFFFFF"  # White
                text_color = BrandColors.GRAY_MEDIUM
                logger.warning(f"Unexpected risk level '{level}' - using default styling")

            # Set cell background
            self._set_cell_shading(cell, bg_color)

            # Set cell borders (BORDER_GRAY, size 4)
            self._set_cell_borders(cell, color_hex="CCCCCC", size="4")

            # Category name - centered, single line
            cat_para = cell.paragraphs[0]
            cat_para.paragraph_format.space_before = Pt(0)
            cat_para.paragraph_format.space_after = Pt(0)
            # Replace any newlines with spaces to keep on single line
            category_single_line = category.replace("\n", " ")
            cat_run = cat_para.add_run(category_single_line)
            cat_run.font.name = "Arial"
            cat_run.font.size = Pt(10)
            cat_run.font.bold = True
            cat_run.font.color.rgb = BrandColors.TEXT_DARK
            cat_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Risk level - large, bold, colored
            level_para = cell.add_paragraph()
            level_para.paragraph_format.space_before = Pt(0)
            level_para.paragraph_format.space_after = Pt(0)
            level_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            level_run = level_para.add_run(level)
            level_run.font.name = "Arial"
            level_run.font.size = Pt(20)
            level_run.font.bold = True
            level_run.font.color.rgb = text_color

            # Trend vs previous quarter - format with percentage if available
            prev_quarter_short = f"Q{self.quarter - 1 if self.quarter > 1 else 4}"
            trend_para = cell.add_paragraph()
            trend_para.paragraph_format.space_before = Pt(0)
            trend_para.paragraph_format.space_after = Pt(0)
            trend_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Parse trend to extract percentage or determine display
            trend_text = str(trend).strip()
            trend_display = None

            # Prefer calculated percentage if available
            if calculated_pct:
                trend_display = f"vs {prev_quarter_short}: {calculated_pct}"
            # Check if trend contains percentage
            elif "%" in trend_text:
                trend_display = f"vs {prev_quarter_short}: {trend_text}"
            elif trend_text.upper() == "UNCHANGED":
                trend_display = f"vs {prev_quarter_short}: Unchanged"
            elif trend_text in ["↑", "INCREASED", "INCREASE"]:
                trend_display = f"vs {prev_quarter_short}: Increased"
            elif trend_text in ["↓", "DECREASED", "DECREASE"]:
                trend_display = f"vs {prev_quarter_short}: Decreased"
            else:
                # Try to extract percentage from trend string
                percentage_match = re.search(r"([+-]?\d+(?:\.\d+)?%)", trend_text)
                if percentage_match:
                    percentage = percentage_match.group(1)
                    trend_display = f"vs {prev_quarter_short}: {percentage}"
                else:
                    trend_display = f"vs {prev_quarter_short}: Unchanged"

            trend_run = trend_para.add_run(trend_display)
            trend_run.font.name = "Arial"
            trend_run.font.size = Pt(8)
            trend_run.font.italic = True
            trend_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        # Spacer after risk assessment
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

    def _add_breach_landscape(self, analysis_result: dict[str, Any]) -> None:
        """Add industry breach landscape section."""
        logger.info("Adding Industry Breach Landscape section")

        # COMPONENT 1 — Section heading
        breach_heading = self.doc.add_heading("Industry Breach Landscape", level=1)
        for run in breach_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        breach_heading.paragraph_format.space_before = Pt(12)
        breach_heading.paragraph_format.space_after = Pt(6)

        # Get breach landscape data
        breach_data = analysis_result.get("breach_landscape") or {}

        # If missing, render unavailable message and return
        if not breach_data:
            logger.warning("breach_landscape missing from analysis_result")
            unavailable_para = self.doc.add_paragraph()
            unavailable_run = unavailable_para.add_run("Breach landscape data unavailable for this reporting period.")
            unavailable_run.font.name = "Arial"
            unavailable_run.font.size = Pt(10)
            unavailable_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(6)
            return

        # COMPONENT 2 — Italic scope note
        scope_note = breach_data.get("scope_note", "")
        if scope_note:
            scope_para = self.doc.add_paragraph()
            scope_para.paragraph_format.space_before = Pt(0)
            scope_para.paragraph_format.space_after = Pt(6)
            scope_run = scope_para.add_run(scope_note)
            scope_run.font.name = "Arial"
            scope_run.font.size = Pt(9)
            scope_run.font.italic = True
            scope_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

        # Spacer after scope note
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

        # COMPONENT 3 — Stat cards
        stat_cards = breach_data.get("stat_cards", [])
        if stat_cards and len(stat_cards) == 4:
            # Create single-row table with 4 columns
            table = self.doc.add_table(rows=1, cols=4)
            table.autofit = False
            table.style = None

            # Set column widths
            for col in table.columns:
                col.width = Inches(1.625)

            for i, card in enumerate(stat_cards):
                cell = table.rows[0].cells[i]
                cell.paragraphs[0].clear()

                # Set cell background to light blue-gray (#E8F4F8 or similar light blue)
                self._set_cell_shading(cell, "E8F4F8")

                # Apply thin gray borders on all sides (no accent border)
                tc_pr = cell._element.get_or_add_tcPr()
                tc_borders = tc_pr.find(qn("w:tcBorders"))
                if tc_borders is None:
                    tc_borders = OxmlElement("w:tcBorders")
                    tc_pr.append(tc_borders)

                for border_name in ["top", "left", "right", "bottom"]:
                    border = tc_borders.find(qn(f"w:{border_name}"))
                    if border is None:
                        border = OxmlElement(f"w:{border_name}")
                        tc_borders.append(border)
                    border.set(qn("w:val"), "single")
                    border.set(qn("w:sz"), "4")
                    border.set(qn("w:color"), "D0D0D0")  # Light gray border

                # Paragraph 1 — large display value (black, bold)
                value_para = cell.paragraphs[0]
                value_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                value_para.paragraph_format.space_after = Pt(2)
                value_run = value_para.add_run(str(card.get("value", "")))
                value_run.font.name = "Arial"
                value_run.font.size = Pt(24)
                value_run.font.bold = True
                value_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black

                # Paragraph 2 — label (black, bold)
                label_para = cell.add_paragraph()
                label_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                label_para.paragraph_format.space_after = Pt(4)
                label_run = label_para.add_run(str(card.get("label", "")))
                label_run.font.name = "Arial"
                label_run.font.size = Pt(10)
                label_run.font.bold = True
                label_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black

                # Paragraph 3 — prior quarter comparison (red italic, single line)
                prior_label = card.get("prior_label", "")
                prior_value = card.get("prior_value", "")
                change_pct = card.get("change_pct", "")

                prior_para = cell.add_paragraph()
                prior_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

                # Single run with full comparison text
                comparison_text = f"{prior_label}: {prior_value} ({change_pct})"
                comparison_run = prior_para.add_run(comparison_text)
                comparison_run.font.name = "Arial"
                comparison_run.font.size = Pt(8)
                comparison_run.font.italic = True
                comparison_run.font.bold = False
                comparison_run.font.color.rgb = RGBColor(0xDC, 0x35, 0x45)  # Red color for comparison

        # Spacer after stat cards
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

        # COMPONENT 4 — Incidents by type. Accept it nested under breach_landscape
        # (current AI schema) OR at the top level of the analysis (docstring/tests).
        incidents = breach_data.get("incidents_by_type") or analysis_result.get("incidents_by_type", [])
        current_quarter_label = breach_data.get("current_quarter_label", "Current")
        prior_quarter_label = breach_data.get("prior_quarter_label", "Prior")

        # Subheading
        incidents_heading = self.doc.add_paragraph()
        incidents_heading.paragraph_format.space_before = Pt(10)
        incidents_heading.paragraph_format.space_after = Pt(4)
        heading_run = incidents_heading.add_run("Incidents by Type")
        heading_run.font.name = "Arial"
        heading_run.font.size = Pt(11)
        heading_run.font.bold = True
        heading_run.font.color.rgb = BrandColors.ORANGE_PRIMARY

        if incidents:
            # Create table with header row + data rows
            table = self.doc.add_table(rows=1 + len(incidents), cols=4)
            table.autofit = False
            table.style = None

            # Set column widths
            table.columns[0].width = Inches(1.39)
            table.columns[1].width = Inches(0.83)
            table.columns[2].width = Inches(0.83)
            table.columns[3].width = Inches(3.45)

            # Header row
            headers = ["Incident Type", current_quarter_label, prior_quarter_label, "Notable Example"]
            header_cells = table.rows[0].cells

            for i, header_text in enumerate(headers):
                cell = header_cells[i]
                cell.paragraphs[0].clear()

                # Set background to #E65100 (orange)
                self._set_cell_shading(cell, "E65100")

                # Header text
                header_run = cell.paragraphs[0].add_run(header_text)
                header_run.font.name = "Arial"
                header_run.font.size = Pt(10)
                header_run.font.bold = True
                header_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

                # Cell padding
                tc_pr = cell._element.get_or_add_tcPr()
                tc_mar = tc_pr.find(qn("w:tcMar"))
                if tc_mar is None:
                    tc_mar = OxmlElement("w:tcMar")
                    tc_pr.append(tc_mar)

                for margin_type in ["top", "bottom", "left", "right"]:
                    margin = tc_mar.find(qn(f"w:{margin_type}"))
                    if margin is None:
                        margin = OxmlElement(f"w:{margin_type}")
                        tc_mar.append(margin)
                    if margin_type in ["top", "bottom"]:
                        margin.set(qn("w:w"), "60")
                    else:  # left, right
                        margin.set(qn("w:w"), "80")
                    margin.set(qn("w:type"), "dxa")

            # Data rows
            for row_idx, incident in enumerate(incidents):
                row = table.rows[row_idx + 1]
                cells = row.cells

                # Alternate row backgrounds
                if row_idx % 2 == 0:
                    bg_color = "FFFFFF"  # even rows
                else:
                    bg_color = "F3F4F6"  # odd rows

                for cell in cells:
                    self._set_cell_shading(cell, bg_color)

                # Col 0 — incident type (bold black)
                cells[0].paragraphs[0].clear()
                type_run = cells[0].paragraphs[0].add_run(str(incident.get("type", "")))
                type_run.font.name = "Arial"
                type_run.font.size = Pt(10)
                type_run.font.bold = True
                type_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black
                cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

                # Col 1 — current_count (large bold black)
                cells[1].paragraphs[0].clear()
                current_run = cells[1].paragraphs[0].add_run(str(incident.get("current_count", "0")))
                current_run.font.name = "Arial"
                current_run.font.size = Pt(14)  # Larger size for emphasis
                current_run.font.bold = True
                current_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black
                cells[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

                # Col 2 — prior_count (regular black, not bold). Schema uses `prev_count`;
                # accept `prior_count` too for back-compat, and coerce ints to str.
                cells[2].paragraphs[0].clear()
                prior_run = cells[2].paragraphs[0].add_run(
                    str(incident.get("prev_count", incident.get("prior_count", "0")))
                )
                prior_run.font.name = "Arial"
                prior_run.font.size = Pt(10)
                prior_run.font.bold = False
                prior_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black
                cells[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

                # Col 3 — notable_example (italic gray)
                cells[3].paragraphs[0].clear()
                example_run = cells[3].paragraphs[0].add_run(str(incident.get("notable_example", "")))
                example_run.font.name = "Arial"
                example_run.font.size = Pt(9)
                example_run.font.italic = True
                example_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)  # Gray
                cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT

                # Apply gray borders and padding to all data cells
                for cell in cells:
                    tc_pr = cell._element.get_or_add_tcPr()

                    # Borders
                    tc_borders = tc_pr.find(qn("w:tcBorders"))
                    if tc_borders is None:
                        tc_borders = OxmlElement("w:tcBorders")
                        tc_pr.append(tc_borders)

                    for border_name in ["top", "left", "bottom", "right"]:
                        border = tc_borders.find(qn(f"w:{border_name}"))
                        if border is None:
                            border = OxmlElement(f"w:{border_name}")
                            tc_borders.append(border)
                        border.set(qn("w:val"), "single")
                        border.set(qn("w:sz"), "4")
                        border.set(qn("w:color"), "D1D5DB")

                    # Padding
                    tc_mar = tc_pr.find(qn("w:tcMar"))
                    if tc_mar is None:
                        tc_mar = OxmlElement("w:tcMar")
                        tc_pr.append(tc_mar)

                    for margin_type in ["top", "bottom", "left", "right"]:
                        margin = tc_mar.find(qn(f"w:{margin_type}"))
                        if margin is None:
                            margin = OxmlElement(f"w:{margin_type}")
                            tc_mar.append(margin)
                        if margin_type in ["top", "bottom"]:
                            margin.set(qn("w:w"), "60")
                        else:  # left, right
                            margin.set(qn("w:w"), "80")
                        margin.set(qn("w:type"), "dxa")

        # COMPONENT 5 — Common factors
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

        common_factors = breach_data.get("common_factors", "")
        if common_factors:
            # Subheading
            factors_heading = self.doc.add_paragraph()
            factors_heading.paragraph_format.space_before = Pt(8)
            factors_heading.paragraph_format.space_after = Pt(4)
            factors_heading_run = factors_heading.add_run("Common Factors Across Incidents")
            factors_heading_run.font.name = "Arial"
            factors_heading_run.font.size = Pt(11)
            factors_heading_run.font.bold = True
            factors_heading_run.font.color.rgb = BrandColors.ORANGE_PRIMARY

            # Body paragraph
            factors_para = self.doc.add_paragraph()
            factors_para.paragraph_format.space_after = Pt(6)
            factors_run = factors_para.add_run(common_factors)
            factors_run.font.name = "Arial"
            factors_run.font.size = Pt(10)
            factors_run.font.bold = False
            factors_run.font.color.rgb = RGBColor(0x11, 0x18, 0x27)

        # Spacer after breach landscape
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)
        logger.info("Breach landscape section added")

    def _create_metric_cards(self, metrics: list[tuple]) -> None:
        """Create metric cards for breach landscape."""
        table = self.doc.add_table(rows=1, cols=len(metrics))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        for i, (number, title, subtitle) in enumerate(metrics):
            cell = table.rows[0].cells[i]
            cell.paragraphs[0].clear()

            # Number
            num_para = cell.paragraphs[0]
            num_run = num_para.add_run(number)
            num_run.font.name = "Arial"
            num_run.font.size = Pt(24)
            num_run.font.bold = True
            num_run.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange for emphasis
            num_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Title
            title_para = cell.add_paragraph()
            title_run = title_para.add_run(title)
            title_run.font.name = "Arial"
            title_run.font.size = FontSizes.BODY_SMALL
            title_run.font.bold = True
            title_run.font.color.rgb = BrandColors.GRAY_DARK  # Dark text
            title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Subtitle (previous quarter comparison) - check for percentage increases
            sub_para = cell.add_paragraph()
            # Extract percentage from subtitle if present
            if "+" in subtitle and "%" in subtitle:
                # Has percentage increase - color it green
                sub_run = sub_para.add_run(subtitle)
                sub_run.font.name = "Arial"
                sub_run.font.size = FontSizes.FOOTNOTE
                sub_run.font.color.rgb = BrandColors.GREEN_LOW  # Green for increases
            else:
                sub_run = sub_para.add_run(subtitle)
                sub_run.font.name = "Arial"
                sub_run.font.size = FontSizes.FOOTNOTE
                sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM  # Gray for other text
            sub_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

    def _create_breach_metric_cards(self, metrics: list[tuple], prev_quarter: str) -> None:
        """Create metric cards for breach landscape with dark olive background."""
        # Create horizontal table (1 row, 4 columns) - same structure as risk boxes
        table = self.doc.add_table(rows=1, cols=len(metrics))
        table.alignment = WD_TABLE_ALIGNMENT.LEFT

        # Remove any table style that might override cell shading
        table.style = None

        # Set table width to 100%
        tbl = table._element
        tbl_pr = tbl.find(qn("w:tblPr"))
        if tbl_pr is None:
            tbl_pr = OxmlElement("w:tblPr")
            tbl.insert(0, tbl_pr)

        # Remove any table style reference that might override
        tbl_style = tbl_pr.find(qn("w:tblStyle"))
        if tbl_style is not None:
            tbl_pr.remove(tbl_style)

        tbl_w = tbl_pr.find(qn("w:tblW"))
        if tbl_w is None:
            tbl_w = OxmlElement("w:tblW")
            tbl_pr.append(tbl_w)
        tbl_w.set(qn("w:w"), "5000")  # 5000 = 100% in Word's 50ths of a percent
        tbl_w.set(qn("w:type"), "pct")

        for i, (number, title, prev_value, percentage) in enumerate(metrics):
            cell = table.rows[0].cells[i]
            cell.paragraphs[0].clear()

            # Set cell vertical alignment to center
            tc_pr = cell._element.get_or_add_tcPr()
            v_align = tc_pr.find(qn("w:vAlign"))
            if v_align is None:
                v_align = OxmlElement("w:vAlign")
                tc_pr.append(v_align)
            v_align.set(qn("w:val"), "center")

            # Set cell margins for lean/compact spacing
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)

            for margin_type in ["top", "bottom", "left", "right"]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), "72")  # 72 twips = 0.05 inches
                margin.set(qn("w:type"), "dxa")

            # Set cell background to dark olive (#372E00) with val=clear
            self._set_cell_shading(cell, "372E00")  # Dark olive background

            # Set cell borders (light gray, thinner - 1/2 pt)
            self._set_cell_borders(cell, color_hex="C0C0C0", size="1")

            # Main value (font size 18, bold, white/light gray)
            num_para = cell.paragraphs[0]
            num_para.paragraph_format.space_before = Pt(0)
            num_para.paragraph_format.space_after = Pt(0)
            num_run = num_para.add_run(number)
            num_run.font.name = "Arial"
            num_run.font.size = Pt(18)  # Font size 18 as requested
            num_run.font.bold = True
            num_run.font.color.rgb = RGBColor(0xF0, 0xF0, 0xF0)  # Light gray/white for dark background
            num_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Title/label (font size 8.5)
            title_para = cell.add_paragraph()
            title_para.paragraph_format.space_before = Pt(0)
            title_para.paragraph_format.space_after = Pt(0)
            title_run = title_para.add_run(title)
            title_run.font.name = "Arial"
            title_run.font.size = Pt(8.5)  # Font size 8.5 as requested
            title_run.font.bold = True
            title_run.font.color.rgb = RGBColor(0xF0, 0xF0, 0xF0)  # Light gray/white for dark background
            title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Comparison line (previous quarter with percentage)
            comp_para = cell.add_paragraph()
            comp_para.paragraph_format.space_before = Pt(0)
            comp_para.paragraph_format.space_after = Pt(0)
            comp_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Format: "Q4 2025: 36 +31%" where percentage is orange
            if percentage:
                # Add base text
                base_text = f"{prev_quarter}: {prev_value} "
                comp_run = comp_para.add_run(base_text)
                comp_run.font.name = "Arial"
                comp_run.font.size = Pt(7)  # Font size 7 for base text
                comp_run.font.color.rgb = RGBColor(0xF0, 0xF0, 0xF0)  # Light gray/white

                # Add percentage in orange (font size 7)
                pct_run = comp_para.add_run(percentage)
                pct_run.font.name = "Arial"
                pct_run.font.size = Pt(7)  # Font size 7 as requested
                pct_run.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange for percentage
            else:
                comp_text = f"{prev_quarter}: {prev_value}"
                comp_run = comp_para.add_run(comp_text)
                comp_run.font.name = "Arial"
                comp_run.font.size = Pt(7)  # Font size 7
                comp_run.font.color.rgb = RGBColor(0xF0, 0xF0, 0xF0)  # Light gray/white

    def _add_geopolitical_landscape(self, analysis_result: dict[str, Any]) -> None:
        """Add geopolitical threat landscape section with dynamic card table."""
        logger.info("Adding Geopolitical Threat Landscape section")

        geo_heading = self.doc.add_heading("Geopolitical Threat Landscape", level=1)
        for run in geo_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)  # Font size 14pt
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange color
        # Add space before and after heading
        geo_heading.paragraph_format.space_before = Pt(12)
        geo_heading.paragraph_format.space_after = Pt(6)

        # Subtitle
        subtitle = self.doc.add_paragraph()
        sub_run = subtitle.add_run(
            f"Nation-state activity assessed for direct relevance to {customer_profile.name}'s assets, operations, and competitive position — Q{self.quarter} {self._get_year()}."
        )
        sub_run.font.name = "Arial"
        sub_run.font.size = FontSizes.SUBTITLE
        sub_run.font.italic = True
        sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM
        subtitle.paragraph_format.keep_with_next = True  # Keep with table

        # Add explanatory paragraph for threat levels
        explanation = self.doc.add_paragraph()
        explanation.paragraph_format.space_before = Pt(6)
        explanation.paragraph_format.space_after = Pt(12)
        explanation.paragraph_format.line_spacing = 1.15

        exp_text = (
            "Threat levels reflect the combination of actor capability, demonstrated intent, and targeting frequency. "
        )
        exp_run = explanation.add_run(exp_text)
        exp_run.font.name = "Arial"
        exp_run.font.size = Pt(11)
        exp_run.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add HIGH definition
        high_run = explanation.add_run("HIGH")
        high_run.font.name = "Arial"
        high_run.font.size = Pt(11)
        high_run.font.bold = True
        high_run.font.color.rgb = RGBColor(0xDC, 0x35, 0x45)  # Red

        high_def = explanation.add_run(" indicates systematic sector targeting with confirmed intrusions; ")
        high_def.font.name = "Arial"
        high_def.font.size = Pt(11)
        high_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add MEDIUM definition
        medium_run = explanation.add_run("MEDIUM")
        medium_run.font.name = "Arial"
        medium_run.font.size = Pt(11)
        medium_run.font.bold = True
        medium_run.font.color.rgb = RGBColor(0xFF, 0x8C, 0x00)  # Orange

        medium_def = explanation.add_run(" reflects opportunistic targeting or reconnaissance activity; ")
        medium_def.font.name = "Arial"
        medium_def.font.size = Pt(11)
        medium_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Add LOW definition
        low_run = explanation.add_run("LOW")
        low_run.font.name = "Arial"
        low_run.font.size = Pt(11)
        low_run.font.bold = True
        low_run.font.color.rgb = RGBColor(0x28, 0xA7, 0x45)  # Green

        low_def = explanation.add_run(" represents limited capability or minimal sector-specific interest.")
        low_def.font.name = "Arial"
        low_def.font.size = Pt(11)
        low_def.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

        # Spacer after subtitle
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

        # Get geopolitical threats from AI analysis (should be a list of dicts)
        geopolitical_list = analysis_result.get("geopolitical_threats", [])

        # If it's a dict (old format), skip rendering - log warning
        if isinstance(geopolitical_list, dict):
            logger.warning("geopolitical_threats is a dict (old format), expected list. Skipping geopolitical section.")
            no_data_para = self.doc.add_paragraph()
            no_data_run = no_data_para.add_run(
                "No significant nation-state threat activity identified in this reporting period."
            )
            no_data_run.font.name = "Arial"
            no_data_run.font.size = FontSizes.BODY
            no_data_run.font.italic = True
            no_data_run.font.color.rgb = BrandColors.GRAY_MEDIUM
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(6)
            return

        # Cap at 4 countries max
        if len(geopolitical_list) > 4:
            logger.warning(f"AI returned {len(geopolitical_list)} countries, capping at 4 for readability")
            geopolitical_list = geopolitical_list[:4]

        # Validate and filter geopolitical entries
        valid_entries = []
        for entry in geopolitical_list:
            # Skip non-dict entries (the AI can emit a bare list of country strings) — this
            # is the quarterly analogue of the weekly "'IOC' object has no attribute get" crash.
            if not isinstance(entry, dict):
                logger.warning(f"Skipping non-dict geopolitical entry: {entry!r}")
                continue
            # Extract fields for validation (support both 'name' and 'country' fields)
            name = entry.get("name", "").strip() if entry.get("name") else ""
            country = entry.get("country", "").strip() if entry.get("country") else ""
            display_name = entry.get("display_name", "").strip() if entry.get("display_name") else ""
            level = entry.get("threat_level", "").strip() if entry.get("threat_level") else ""
            if not level:
                level = entry.get("level", "").strip() if entry.get("level") else ""
            relevance = entry.get("relevance", [])
            activity = entry.get("activity", [])
            risk = entry.get("risk", [])

            # Check if we have at least one valid identifier (name, country, or display_name)
            # At least one must be present and not "Unknown"
            has_valid_name = (
                (name and name.upper() != "UNKNOWN")
                or (country and country.upper() != "UNKNOWN")
                or (display_name and display_name.upper() != "UNKNOWN")
            )

            # Check if level is missing or empty
            level_invalid = not level

            # Check if all three bullet lists are empty
            all_bullets_empty = (
                (not relevance or len(relevance) == 0)
                and (not activity or len(activity) == 0)
                and (not risk or len(risk) == 0)
            )

            # Skip if any validation fails
            if not has_valid_name or level_invalid or all_bullets_empty:
                logger.warning(f"Skipping geopolitical entry with insufficient data: {entry}")
                continue

            valid_entries.append(entry)

        # Update list to only valid entries
        geopolitical_list = valid_entries

        # If no valid entries remain after filtering, render insufficient data message
        if not geopolitical_list:
            no_data_para = self.doc.add_paragraph()
            no_data_run = no_data_para.add_run(
                "Insufficient geopolitical threat data returned for this reporting period. Review ThreatAnalystAgent output."
            )
            no_data_run.font.name = "Arial"
            no_data_run.font.size = FontSizes.BODY
            no_data_run.font.italic = True
            no_data_run.font.color.rgb = BrandColors.GRAY_MEDIUM
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(6)
            return

        # Calculate column count and widths dynamically based on valid countries
        num_countries = len(geopolitical_list)

        # Column widths based on count (updated to exact specifications)
        if num_countries == 1:
            col_width = Inches(6.5)  # Full content width
        elif num_countries == 2:
            col_width = Inches(3.25)
        elif num_countries == 3:
            col_width = Inches(2.167)
        else:  # 4 countries
            col_width = Inches(1.625)

        # Define geopolitical card color scheme (local to this section only)
        GEO_HEADER_BG = "1E2D3D"  # dark navy charcoal — header row bg
        GEO_METRICS_BG = "F8FAFC"  # near white — metrics strip bg
        GEO_BULLET_BG_A = "FFFFFF"  # white — relevance and risk rows bg
        GEO_BULLET_BG_B = "F3F4F6"  # light gray — activity row bg
        GEO_LABEL_COLOR = BrandColors.ORANGE_PRIMARY  # orange text for section labels

        # Create table with 5 rows (header, metrics, relevance, activity, risk) and N columns (one per country)
        table = self.doc.add_table(rows=5, cols=num_countries)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.style = None  # Remove any default styling
        table.autofit = False

        # Set table width to content width
        tbl = table._element
        tbl_pr = tbl.find(qn("w:tblPr"))
        if tbl_pr is None:
            tbl_pr = OxmlElement("w:tblPr")
            tbl.insert(0, tbl_pr)

        # Set column widths
        for col in table.columns:
            col.width = col_width

        # Prevent page breaks within card rows
        for row in table.rows:
            tr = row._tr
            tr_pr = tr.find(qn("w:trPr"))
            if tr_pr is None:
                tr_pr = OxmlElement("w:trPr")
                tr.insert(0, tr_pr)
            cant_split = OxmlElement("w:cantSplit")
            cant_split.set(qn("w:val"), "1")
            tr_pr.append(cant_split)

        # Populate each country card (column)
        for col_idx, country_data in enumerate(geopolitical_list):
            if not isinstance(country_data, dict):
                continue
            # Extract country data (support both 'name' and 'country' fields)
            country_name = country_data.get("name", "")
            if not country_name:
                country_name = country_data.get("country", "Unknown")
            display_name = country_data.get("display_name", country_name)

            # Truncate display name if longer than 20 characters
            if len(display_name) > 20:
                truncate_pos = display_name.rfind(" ", 0, 20)
                if truncate_pos > 0:
                    display_name = display_name[:truncate_pos] + "..."
                else:
                    display_name = display_name[:17] + "..."
                logger.debug(f"Geo card name truncated: '{country_name}' -> '{display_name}'")

            # The AI schema emits "level"; older/fallback paths use "threat_level". Accept
            # both (was always falling through to "MEDIUM" because only threat_level was read).
            threat_level = str(country_data.get("threat_level") or country_data.get("level") or "MEDIUM").upper()
            primary_vector = country_data.get("vector", "Multiple vectors")
            exposure = country_data.get("exposure", "MEDIUM").upper()
            relevance_bullets = country_data.get("relevance", [])
            activity_bullets = country_data.get("activity", [])
            risk_bullets = country_data.get("risk", [])

            # ============================================================
            # ROW 1 — HEADER ROW (dark charcoal background, white text)
            # ============================================================
            header_cell = table.rows[0].cells[col_idx]
            header_cell.width = col_width
            header_cell.paragraphs[0].clear()

            # Set background to dark charcoal
            self._set_cell_shading(header_cell, GEO_HEADER_BG)

            # Set all borders to match the header background color (dark charcoal) for seamless look
            tc_pr = header_cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)
            for border_name in ["top", "left", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), GEO_HEADER_BG)  # Match cell background

            # Set cell padding: 100 top/bottom, 100 left, 80 right (twips)
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)
            for margin_type, value in [("top", "100"), ("bottom", "100"), ("left", "100"), ("right", "80")]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), value)
                margin.set(qn("w:type"), "dxa")

            # Country name paragraph
            name_para = header_cell.paragraphs[0]
            name_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            name_para.paragraph_format.space_after = Pt(3)
            name_run = name_para.add_run(display_name)
            name_run.font.name = "Arial"
            name_run.font.size = Pt(10)
            name_run.font.bold = True
            name_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White

            # Threat level paragraph (two runs on same line)
            level_para = header_cell.add_paragraph()
            level_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            level_para.paragraph_format.space_after = Pt(0)

            # Run A: "THREAT LEVEL  " label
            level_label_run = level_para.add_run("THREAT LEVEL  ")
            level_label_run.font.name = "Arial"
            level_label_run.font.size = Pt(7)
            level_label_run.font.bold = False
            level_label_run.font.color.rgb = RGBColor(0x88, 0x99, 0xAA)  # Muted blue-gray

            # Run B: threat level value (colored based on level)
            level_value_run = level_para.add_run(threat_level)
            level_value_run.font.name = "Arial"
            level_value_run.font.size = Pt(9)
            level_value_run.font.bold = True
            if threat_level == "HIGH":
                level_value_run.font.color.rgb = RGBColor(0xFF, 0x6B, 0x6B)  # Soft red
            elif threat_level == "MEDIUM":
                level_value_run.font.color.rgb = RGBColor(0xFF, 0xD1, 0x66)  # Soft amber
            else:  # LOW
                level_value_run.font.color.rgb = RGBColor(0x06, 0xD6, 0xA0)  # Soft green

            # ============================================================
            # ROW 2 — METRICS STRIP (near white background)
            # ============================================================
            metrics_cell = table.rows[1].cells[col_idx]
            metrics_cell.width = col_width
            metrics_cell.paragraphs[0].clear()

            # Set background to near white
            self._set_cell_shading(metrics_cell, GEO_METRICS_BG)

            # Set borders to match cell background for seamless look
            tc_pr = metrics_cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)
            for border_name in ["top", "left", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), GEO_METRICS_BG)  # Match cell background

            # Set cell padding: 60 top/bottom, 100 left, 80 right (twips)
            tc_pr = metrics_cell._element.get_or_add_tcPr()
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)
            for margin_type, value in [("top", "60"), ("bottom", "60"), ("left", "100"), ("right", "80")]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), value)
                margin.set(qn("w:type"), "dxa")

            # Line 1 — Primary vector
            vector_para = metrics_cell.paragraphs[0]
            vector_para.paragraph_format.space_after = Pt(2)
            vector_label_run = vector_para.add_run("Primary vector  ")
            vector_label_run.font.name = "Arial"
            vector_label_run.font.size = Pt(7.5)
            vector_label_run.font.bold = True
            vector_label_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
            vector_value_run = vector_para.add_run(primary_vector)
            vector_value_run.font.name = "Arial"
            vector_value_run.font.size = Pt(7.5)
            vector_value_run.font.bold = False
            vector_value_run.font.color.rgb = RGBColor(0x1A, 0x20, 0x2C)

            # Line 2 — organization exposure
            exposure_para = metrics_cell.add_paragraph()
            exposure_para.paragraph_format.space_after = Pt(0)
            exposure_label_run = exposure_para.add_run(f"{customer_profile.name} exposure  ")
            exposure_label_run.font.name = "Arial"
            exposure_label_run.font.size = Pt(7.5)
            exposure_label_run.font.bold = True
            exposure_label_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
            exposure_value_run = exposure_para.add_run(exposure)
            exposure_value_run.font.name = "Arial"
            exposure_value_run.font.size = Pt(7.5)
            exposure_value_run.font.bold = True
            if exposure == "CRITICAL":
                exposure_value_run.font.color.rgb = RGBColor(0x99, 0x1B, 0x1B)
            elif exposure in ("HIGH", "MEDIUM"):
                exposure_value_run.font.color.rgb = RGBColor(0x92, 0x40, 0x0E)
            else:  # LOW
                exposure_value_run.font.color.rgb = RGBColor(0x06, 0x5F, 0x46)

            # ============================================================
            # ROW 3 — RELEVANCE TO ILLUMINA (white background)
            # ============================================================
            relevance_cell = table.rows[2].cells[col_idx]
            relevance_cell.width = col_width
            relevance_cell.paragraphs[0].clear()

            # Set background to white
            self._set_cell_shading(relevance_cell, GEO_BULLET_BG_A)

            # Set borders to match cell background for seamless look
            tc_pr = relevance_cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)
            for border_name in ["top", "left", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), GEO_BULLET_BG_A)  # Match cell background

            # Set cell padding: 80 top/bottom, 100 left, 80 right (twips)
            tc_pr = relevance_cell._element.get_or_add_tcPr()
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)
            for margin_type, value in [("top", "80"), ("bottom", "80"), ("left", "100"), ("right", "80")]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), value)
                margin.set(qn("w:type"), "dxa")

            # Section label paragraph
            label_para = relevance_cell.paragraphs[0]
            label_para.paragraph_format.space_after = Pt(3)
            label_run = label_para.add_run("RELEVANCE TO ILLUMINA")
            label_run.font.name = "Arial"
            label_run.font.size = Pt(7)
            label_run.font.bold = True
            label_run.font.color.rgb = GEO_LABEL_COLOR

            # Bullets (max 2, truncate at 120 chars)
            bullets_to_render = relevance_bullets[:2]
            if len(relevance_bullets) > 2:
                logger.debug(f"Geo card bullets capped at 2 for section 'RELEVANCE', country '{display_name}'")

            for bullet_text in bullets_to_render:
                # Truncate bullet to 120 characters
                if len(bullet_text) > 120:
                    truncate_pos = bullet_text.rfind(" ", 0, 120)
                    if truncate_pos > 0:
                        bullet_text = bullet_text[:truncate_pos] + "..."
                    else:
                        bullet_text = bullet_text[:117] + "..."
                    logger.debug(f"Geo bullet truncated for '{display_name}': '{bullet_text[:40]}...'")

                # Use bullet character prefix (not List Bullet style)
                bullet_para = relevance_cell.add_paragraph()
                bullet_para.paragraph_format.space_after = Pt(2)
                bullet_run = bullet_para.add_run("\u2022  " + bullet_text)
                bullet_run.font.name = "Arial"
                bullet_run.font.size = Pt(7.5)
                bullet_run.font.color.rgb = RGBColor(0x1A, 0x20, 0x2C)

            # ============================================================
            # ROW 4 — Q2 ACTIVITY (light gray background)
            # ============================================================
            activity_cell = table.rows[3].cells[col_idx]
            activity_cell.width = col_width
            activity_cell.paragraphs[0].clear()

            # Set background to light gray
            self._set_cell_shading(activity_cell, GEO_BULLET_BG_B)

            # Set borders to match cell background for seamless look
            tc_pr = activity_cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)
            for border_name in ["top", "left", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), GEO_BULLET_BG_B)  # Match cell background

            # Set cell padding: 80 top/bottom, 100 left, 80 right (twips)
            tc_pr = activity_cell._element.get_or_add_tcPr()
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)
            for margin_type, value in [("top", "80"), ("bottom", "80"), ("left", "100"), ("right", "80")]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), value)
                margin.set(qn("w:type"), "dxa")

            # Section label paragraph
            label_para = activity_cell.paragraphs[0]
            label_para.paragraph_format.space_after = Pt(3)
            label_run = label_para.add_run(f"Q{self.quarter} ACTIVITY")
            label_run.font.name = "Arial"
            label_run.font.size = Pt(7)
            label_run.font.bold = True
            label_run.font.color.rgb = GEO_LABEL_COLOR

            # Bullets (max 2, truncate at 120 chars)
            bullets_to_render = activity_bullets[:2]
            if len(activity_bullets) > 2:
                logger.debug(f"Geo card bullets capped at 2 for section 'ACTIVITY', country '{display_name}'")

            for bullet_text in bullets_to_render:
                # Truncate bullet to 120 characters
                if len(bullet_text) > 120:
                    truncate_pos = bullet_text.rfind(" ", 0, 120)
                    if truncate_pos > 0:
                        bullet_text = bullet_text[:truncate_pos] + "..."
                    else:
                        bullet_text = bullet_text[:117] + "..."
                    logger.debug(f"Geo bullet truncated for '{display_name}': '{bullet_text[:40]}...'")

                # Use bullet character prefix (not List Bullet style)
                bullet_para = activity_cell.add_paragraph()
                bullet_para.paragraph_format.space_after = Pt(2)
                bullet_run = bullet_para.add_run("\u2022  " + bullet_text)
                bullet_run.font.name = "Arial"
                bullet_run.font.size = Pt(7.5)
                bullet_run.font.color.rgb = RGBColor(0x1A, 0x20, 0x2C)

            # ============================================================
            # ROW 5 — RISK TO ILLUMINA (white background)
            # ============================================================
            risk_cell = table.rows[4].cells[col_idx]
            risk_cell.width = col_width
            risk_cell.paragraphs[0].clear()

            # Set background to white
            self._set_cell_shading(risk_cell, GEO_BULLET_BG_A)

            # Set borders to match cell background for seamless look
            tc_pr = risk_cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)
            for border_name in ["top", "left", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), GEO_BULLET_BG_A)  # Match cell background

            # Set cell padding: 80 top/bottom, 100 left, 80 right (twips)
            tc_pr = risk_cell._element.get_or_add_tcPr()
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)
            for margin_type, value in [("top", "80"), ("bottom", "80"), ("left", "100"), ("right", "80")]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                margin.set(qn("w:w"), value)
                margin.set(qn("w:type"), "dxa")

            # Section label paragraph
            label_para = risk_cell.paragraphs[0]
            label_para.paragraph_format.space_after = Pt(3)
            label_run = label_para.add_run("RISK TO ILLUMINA")
            label_run.font.name = "Arial"
            label_run.font.size = Pt(7)
            label_run.font.bold = True
            label_run.font.color.rgb = GEO_LABEL_COLOR

            # Bullets (max 2, truncate at 120 chars)
            bullets_to_render = risk_bullets[:2]
            if len(risk_bullets) > 2:
                logger.debug(f"Geo card bullets capped at 2 for section 'RISK', country '{display_name}'")

            for bullet_text in bullets_to_render:
                # Truncate bullet to 120 characters
                if len(bullet_text) > 120:
                    truncate_pos = bullet_text.rfind(" ", 0, 120)
                    if truncate_pos > 0:
                        bullet_text = bullet_text[:truncate_pos] + "..."
                    else:
                        bullet_text = bullet_text[:117] + "..."
                    logger.debug(f"Geo bullet truncated for '{display_name}': '{bullet_text[:40]}...'")

                # Use bullet character prefix (not List Bullet style)
                bullet_para = risk_cell.add_paragraph()
                bullet_para.paragraph_format.space_after = Pt(2)
                bullet_run = bullet_para.add_run("\u2022  " + bullet_text)
                bullet_run.font.name = "Arial"
                bullet_run.font.size = Pt(7.5)
                bullet_run.font.color.rgb = RGBColor(0x1A, 0x20, 0x2C)

        # Spacer after geopolitical landscape
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

    # DEPRECATED: Old country section rendering - replaced by dynamic card table in _add_geopolitical_landscape()
    # Keeping these methods for reference but they are no longer called
    #
    # def _add_country_section(self, country: str, data: Dict[str, Any]) -> None:
    #     """Add a country-specific threat section."""
    #     ...
    #
    # def _get_default_strategic_context(self, country: str) -> str:
    #     """Get default strategic context for a country."""
    #     ...
    #
    # def _get_default_activity(self, country: str) -> str:
    #     """Get default activity description for a country."""
    #     ...
    #
    # def _get_default_implications(self, country: str) -> str:
    #     """Get default business implications for a country."""
    #     ...

    def _add_looking_ahead(self, analysis_result: dict[str, Any]) -> None:
        """Add looking ahead section for next quarter."""
        logger.info("Adding Looking Ahead section")

        # Get looking ahead data (`or {}` guards a present-but-null value)
        looking_ahead = analysis_result.get("looking_ahead") or {}

        # If missing or watch_items is empty, render unavailable message
        watch_items = looking_ahead.get("watch_items", [])
        # Defensive: watch_items must be a list of {subject, detail} dicts. Older/
        # malformed analyses sometimes supply a bare string or a list of strings;
        # drop non-dict entries so one bad field cannot crash the whole report.
        if isinstance(watch_items, str) or not isinstance(watch_items, list):
            watch_items = []
        else:
            watch_items = [item for item in watch_items if isinstance(item, dict)]
        if not looking_ahead or not watch_items:
            logger.warning("looking_ahead missing or watch_items empty")

            # Still render heading with fallback quarter calculation
            next_quarter = self.quarter + 1 if self.quarter < 4 else 1
            next_year = self._get_year() if self.quarter < 4 else self._get_year() + 1

            looking_ahead_heading = self.doc.add_heading(f"Looking Ahead: Q{next_quarter} {next_year}", level=1)
            for run in looking_ahead_heading.runs:
                run.font.name = "Arial"
                run.font.size = Pt(14)
                run.font.color.rgb = BrandColors.ORANGE_PRIMARY
            looking_ahead_heading.paragraph_format.space_before = Pt(12)
            looking_ahead_heading.paragraph_format.space_after = Pt(6)

            # Unavailable message
            unavailable_para = self.doc.add_paragraph()
            unavailable_run = unavailable_para.add_run("No specific watch items identified for this reporting period.")
            unavailable_run.font.name = "Arial"
            unavailable_run.font.size = Pt(10)
            unavailable_run.font.italic = True
            unavailable_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(6)
            return

        # Component 1 — Section heading with next_quarter_label
        next_quarter_label = looking_ahead.get("next_quarter_label", "")
        if not next_quarter_label:
            # Fallback calculation if AI didn't provide label
            next_quarter = self.quarter + 1 if self.quarter < 4 else 1
            next_year = self._get_year() if self.quarter < 4 else self._get_year() + 1
            next_quarter_label = f"Q{next_quarter} {next_year}"

        looking_ahead_heading = self.doc.add_heading(f"Looking Ahead: {next_quarter_label}", level=1)
        for run in looking_ahead_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        looking_ahead_heading.paragraph_format.space_before = Pt(12)
        looking_ahead_heading.paragraph_format.space_after = Pt(6)

        # Component 2 — Subheading (black, not orange)
        subheading_para = self.doc.add_paragraph()
        subheading_para.paragraph_format.space_before = Pt(6)
        subheading_para.paragraph_format.space_after = Pt(2)
        subheading_run = subheading_para.add_run("Specific Watch Items")
        subheading_run.font.name = "Arial"
        subheading_run.font.size = Pt(11)
        subheading_run.font.bold = True
        subheading_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black

        # Component 3 — Italic note (gray)
        note_para = self.doc.add_paragraph()
        note_para.paragraph_format.space_before = Pt(0)
        note_para.paragraph_format.space_after = Pt(6)
        note_run = note_para.add_run("Named, specific items — not generic monitoring reminders.")
        note_run.font.name = "Arial"
        note_run.font.size = Pt(9)
        note_run.font.italic = True
        note_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)  # Gray

        # Component 4 — Numbered watch item list
        for i, item in enumerate(watch_items):
            subject = item.get("subject", "")
            detail = item.get("detail", "")

            # Try to use 'List Number' style, fall back to manual numbering
            try:
                item_para = self.doc.add_paragraph(style="List Number")
            except KeyError:
                # 'List Number' style not available, use manual numbering
                item_para = self.doc.add_paragraph()
                # Add manual number prefix
                num_run = item_para.add_run(f"{i + 1}.  ")
                num_run.font.name = "Arial"
                num_run.font.size = Pt(10)
                num_run.font.bold = False
                num_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black

            item_para.paragraph_format.space_after = Pt(4)

            # Run 1 — subject (bold, dark navy)
            subject_run = item_para.add_run(subject)
            subject_run.font.name = "Arial"
            subject_run.font.size = Pt(10)
            subject_run.font.bold = True
            subject_run.font.color.rgb = RGBColor(0x2C, 0x3E, 0x50)  # Dark navy

            # Run 2 — detail (regular, black)
            detail_run = item_para.add_run(f" {detail}")
            detail_run.font.name = "Arial"
            detail_run.font.size = Pt(10)
            detail_run.font.bold = False
            detail_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Black

        # Spacer after looking ahead
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)
        logger.info("Looking ahead section added")

    def _add_recommendations(self, analysis_result: dict[str, Any]) -> None:
        """Add recommendations section."""
        logger.info("Adding Recommendations section")

        # Component 1 — Section heading
        rec_heading = self.doc.add_heading("Recommendations", level=1)
        for run in rec_heading.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)
            run.font.color.rgb = BrandColors.ORANGE_DESIGN  # Orange heading
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY
        rec_heading.paragraph_format.space_before = Pt(12)
        rec_heading.paragraph_format.space_after = Pt(6)

        # Get recommendations data
        recommendations = analysis_result.get("recommendations", {})

        # If missing or items is empty, render unavailable message
        items = recommendations.get("items", []) if isinstance(recommendations, dict) else []
        if not recommendations or not items:
            logger.warning("recommendations missing or items empty")
            unavailable_para = self.doc.add_paragraph()
            unavailable_run = unavailable_para.add_run("No recommendations generated for this reporting period.")
            unavailable_run.font.name = "Arial"
            unavailable_run.font.size = Pt(10)
            unavailable_run.font.italic = True
            unavailable_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(6)
            return

        # Component 2 — Italic intro note
        intro_note = recommendations.get("intro_note", "")
        if intro_note:
            intro_para = self.doc.add_paragraph()
            intro_para.paragraph_format.space_before = Pt(0)
            intro_para.paragraph_format.space_after = Pt(6)
            intro_run = intro_para.add_run(intro_note)
            intro_run.font.name = "Arial"
            intro_run.font.size = Pt(9)
            intro_run.font.italic = True
            intro_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

        # Component 3 — Recommendation boxes
        for index, item in enumerate(items, start=1):
            title = item.get("title", "")
            body = item.get("body", "")

            # Create single-cell table for box
            table = self.doc.add_table(rows=1, cols=1)
            table.autofit = False
            table.style = None

            # Set table width to full content width (6.5 inches)
            table.columns[0].width = Inches(6.5)

            cell = table.rows[0].cells[0]
            cell.paragraphs[0].clear()

            # Set cell background to #FFF3E0 (light orange)
            self._set_cell_shading(cell, "FFF3E0")

            # Apply borders via XML
            tc_pr = cell._element.get_or_add_tcPr()
            tc_borders = tc_pr.find(qn("w:tcBorders"))
            if tc_borders is None:
                tc_borders = OxmlElement("w:tcBorders")
                tc_pr.append(tc_borders)

            # Left border: style SINGLE, size 18, color "E65100" (orange)
            left_border = tc_borders.find(qn("w:left"))
            if left_border is None:
                left_border = OxmlElement("w:left")
                tc_borders.append(left_border)
            left_border.set(qn("w:val"), "single")
            left_border.set(qn("w:sz"), "18")
            left_border.set(qn("w:color"), "E65100")

            # Top, right, bottom borders: style SINGLE, size 4, color "D1D5DB"
            for border_name in ["top", "right", "bottom"]:
                border = tc_borders.find(qn(f"w:{border_name}"))
                if border is None:
                    border = OxmlElement(f"w:{border_name}")
                    tc_borders.append(border)
                border.set(qn("w:val"), "single")
                border.set(qn("w:sz"), "4")
                border.set(qn("w:color"), "D1D5DB")

            # Cell padding via w:tcMar XML: 80 top/bottom, 120 left/right
            tc_mar = tc_pr.find(qn("w:tcMar"))
            if tc_mar is None:
                tc_mar = OxmlElement("w:tcMar")
                tc_pr.append(tc_mar)

            for margin_type in ["top", "bottom", "left", "right"]:
                margin = tc_mar.find(qn(f"w:{margin_type}"))
                if margin is None:
                    margin = OxmlElement(f"w:{margin_type}")
                    tc_mar.append(margin)
                if margin_type in ["top", "bottom"]:
                    margin.set(qn("w:w"), "80")
                else:  # left, right
                    margin.set(qn("w:w"), "120")
                margin.set(qn("w:type"), "dxa")

            # Title paragraph with underline guard
            title_para = cell.paragraphs[0]
            title_para.paragraph_format.space_after = Pt(6)

            # Prefix run: "{index}.  "
            prefix_run = title_para.add_run(f"{index}.  ")
            prefix_run.font.name = "Arial"
            prefix_run.font.size = Pt(11)
            prefix_run.font.bold = True
            prefix_run.font.color.rgb = BrandColors.ORANGE_PRIMARY
            prefix_run.font.underline = False

            # Split title on first space
            if " " in title:
                first_word = title.split(" ", 1)[0]
                remainder = title.split(" ", 1)[1]
            else:
                first_word = title
                remainder = ""

            # Apply underline guard
            if first_word.isalpha():
                # First word is purely alphabetic - underline it
                first_word_run = title_para.add_run(first_word)
                first_word_run.font.name = "Arial"
                first_word_run.font.size = Pt(11)
                first_word_run.font.bold = True
                first_word_run.font.color.rgb = BrandColors.ORANGE_PRIMARY
                first_word_run.font.underline = True

                # Remainder (if exists)
                if remainder:
                    remainder_run = title_para.add_run(f" {remainder}")
                    remainder_run.font.name = "Arial"
                    remainder_run.font.size = Pt(11)
                    remainder_run.font.bold = True
                    remainder_run.font.color.rgb = BrandColors.ORANGE_PRIMARY
                    remainder_run.font.underline = False
            else:
                # First word not purely alphabetic - no underline, render entire title
                logger.debug(f"Rec title underline skipped — first word not purely alphabetic: '{first_word}'")
                full_title_run = title_para.add_run(title)
                full_title_run.font.name = "Arial"
                full_title_run.font.size = Pt(11)
                full_title_run.font.bold = True
                full_title_run.font.color.rgb = BrandColors.ORANGE_PRIMARY
                full_title_run.font.underline = False

            # Body paragraph
            body_para = cell.add_paragraph()
            body_para.paragraph_format.space_after = Pt(0)
            body_run = body_para.add_run(body)
            body_run.font.name = "Arial"
            body_run.font.size = Pt(10)
            body_run.font.bold = False
            body_run.font.color.rgb = RGBColor(0x11, 0x18, 0x27)

            # Add spacer paragraph after box
            spacer = self.doc.add_paragraph()
            spacer.paragraph_format.space_after = Pt(8)

        logger.info("Recommendations section added")

    def _add_sources(self, analysis_result: dict[str, Any]) -> None:
        """Add Resources & Intelligence Sources section with numbered citations."""
        logger.info("Adding Resources & Intelligence Sources section")

        # Heading
        h = self.doc.add_heading("Resources & Intelligence Sources", level=1)
        for run in h.runs:
            run.font.name = "Arial"
            run.font.size = Pt(14)
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY

        # Intro text
        intro = self.doc.add_paragraph()
        intro_run = intro.add_run("This report was compiled using the following intelligence sources:")
        intro_run.font.name = "Arial"
        intro_run.font.size = FontSizes.BODY_SMALL
        intro_run.font.italic = True
        intro_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
        intro.paragraph_format.space_after = Pt(6)

        # Primary intelligence sources (numbered [1]-[4])
        # Only list sources that are actually collected/used
        primary_sources = [
            "NIST National Vulnerability Database (NVD)",
            "CISA Known Exploited Vulnerabilities (KEV) Catalog",
            "Intel471 Titan threat intelligence platform",
            "CrowdStrike Falcon Intelligence",
        ]

        for idx, source in enumerate(primary_sources, start=1):
            para = self.doc.add_paragraph(style="List Bullet")
            # Number in bold
            number_run = para.add_run(f"[{idx}] ")
            number_run.font.name = "Arial"
            number_run.font.size = FontSizes.BODY_SMALL
            number_run.font.bold = True
            # Source name
            name_run = para.add_run(source)
            name_run.font.name = "Arial"
            name_run.font.size = FontSizes.BODY_SMALL

        # OSINT Sources heading
        osint_heading = self.doc.add_paragraph()
        osint_heading.paragraph_format.space_before = Pt(12)
        osint_heading.paragraph_format.space_after = Pt(6)
        osint_run = osint_heading.add_run("Open Source Intelligence (OSINT) Sources:")
        osint_run.font.name = "Arial"
        osint_run.font.size = FontSizes.BODY_SMALL
        osint_run.font.bold = True

        # Get OSINT sources from analysis_result
        osint_sources = analysis_result.get("osint_sources_used", [])

        if osint_sources:
            for idx, osint in enumerate(osint_sources, start=5):
                para = self.doc.add_paragraph(style="List Bullet")

                # Number in bold
                number_run = para.add_run(f"[{idx}] ")
                number_run.font.name = "Arial"
                number_run.font.size = FontSizes.BODY_SMALL
                number_run.font.bold = True

                # Title as hyperlink (blue, underlined)
                title = osint.get("title", "Untitled")
                url = osint.get("url", "")
                description = osint.get("description", "")

                if url:
                    # Add title as blue underlined text (hyperlink styling)
                    title_run = para.add_run(title)
                    title_run.font.name = "Arial"
                    title_run.font.size = FontSizes.BODY_SMALL
                    title_run.font.color.rgb = RGBColor(0x00, 0x5A, 0x9C)  # Blue
                    title_run.font.underline = True

                    # Try to add actual hyperlink functionality
                    try:
                        r = title_run._element
                        hyperlink = OxmlElement("w:hyperlink")
                        hyperlink.set(
                            qn("r:id"),
                            self.doc.part.relate_to(
                                url,
                                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                                is_external=True,
                            ),
                        )
                        # Move the run element into the hyperlink
                        new_r = OxmlElement("w:r")
                        for child in list(r):
                            new_r.append(child)
                        hyperlink.append(new_r)
                        # Replace the run with the hyperlink
                        parent = r.getparent()
                        parent.replace(r, hyperlink)
                    except Exception as e:
                        logger.warning(f"Could not create hyperlink for {title}: {e}")
                        # Hyperlink creation failed, but blue underlined text still shows
                else:
                    # No URL, just show title in regular text
                    title_run = para.add_run(title)
                    title_run.font.name = "Arial"
                    title_run.font.size = FontSizes.BODY_SMALL

                # Description in gray italic
                if description:
                    desc_run = para.add_run(f" - {description}")
                    desc_run.font.name = "Arial"
                    desc_run.font.size = FontSizes.BODY_SMALL
                    desc_run.font.italic = True
                    desc_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
        else:
            # No OSINT sources, show placeholder
            para = self.doc.add_paragraph(style="List Bullet")
            para_run = para.add_run("No OSINT sources were referenced in this report")
            para_run.font.name = "Arial"
            para_run.font.size = FontSizes.BODY_SMALL
            para_run.font.italic = True
            para_run.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

        # Spacer after sources
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

    def _add_footer(self) -> None:
        """Add footer with contact info, sources, TLP classification, and page number."""
        logger.info("Adding footer")

        # Contact info
        contact = self.doc.add_paragraph()
        contact_run = contact.add_run(
            f"Questions or suspicious activity: {customer_profile.security_contact} | ServiceNow"
        )
        contact_run.font.name = "Arial"
        contact_run.font.size = FontSizes.BODY_SMALL
        contact_run.font.bold = True
        contact_run.font.color.rgb = BrandColors.GRAY_DARK  # Dark text
        contact_run.font.underline = False  # No underline
        contact.alignment = WD_ALIGN_PARAGRAPH.LEFT  # Left align

        # Spacer at end
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(6)

        # Data sources - removed, now covered by Sources section

        # Add TLP classification and page number to document footer
        section = self.doc.sections[0]
        footer = section.footer

        # Clear any existing footer content
        if footer.paragraphs:
            footer.paragraphs[0].clear()
        else:
            footer.add_paragraph()

        # Create footer paragraph
        footer_para = footer.paragraphs[0]
        footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # "TLP:" in light gray, italic
        tlp_label = footer_para.add_run("TLP: ")
        tlp_label.font.name = "Arial"
        tlp_label.font.size = FontSizes.FOOTNOTE
        tlp_label.font.italic = True
        tlp_label.font.color.rgb = RGBColor(0x99, 0x99, 0x99)  # Light gray

        # "AMBER+" in orange, italic
        amber = footer_para.add_run("AMBER+")
        amber.font.name = "Arial"
        amber.font.size = FontSizes.FOOTNOTE
        amber.font.italic = True
        amber.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange

        # "STRICT" in orange, italic, no underline
        strict = footer_para.add_run("STRICT")
        strict.font.name = "Arial"
        strict.font.size = FontSizes.FOOTNOTE
        strict.font.italic = True
        strict.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange
        strict.font.underline = False  # No underline

        # Pipe separator in light gray, italic
        pipe = footer_para.add_run(" | ")
        pipe.font.name = "Arial"
        pipe.font.size = FontSizes.FOOTNOTE
        pipe.font.italic = True
        pipe.font.color.rgb = RGBColor(0x99, 0x99, 0x99)  # Light gray

        # Page number in light gray, italic
        # Use simple text for now - user can manually add page number field in Word if needed
        # This avoids XML corruption issues
        page_text = footer_para.add_run("Page 1")
        page_text.font.name = "Arial"
        page_text.font.size = FontSizes.FOOTNOTE
        page_text.font.italic = True
        page_text.font.color.rgb = RGBColor(0x99, 0x99, 0x99)  # Light gray
