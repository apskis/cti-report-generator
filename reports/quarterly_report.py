"""
Quarterly Strategic CTI Report Generator.

Generates quarterly strategic threat intelligence briefs for leadership.
"""
from datetime import datetime, timedelta
import logging
import os
from typing import Dict, Any, List

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from reports.base import BaseReportGenerator, BrandColors, FontSizes
from reports.registry import register_report_generator

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

    def generate(self, analysis_result: Dict[str, Any]) -> Document:
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

            # Calculate quarter info
            self._calculate_quarter_info()

            # Add sections in order
            self._add_header()
            self._add_executive_summary(analysis_result)
            self._add_risk_assessment(analysis_result)
            self._add_breach_landscape(analysis_result)
            self._add_geopolitical_landscape(analysis_result)
            self._add_looking_ahead(analysis_result)
            self._add_leadership_recommendations(analysis_result)
            self._add_footer()

            logger.info("Quarterly Strategic CTI Report generated successfully")
            return self.doc

        except Exception as e:
            logger.error(f"Error generating quarterly report: {str(e)}", exc_info=True)
            raise

    def _calculate_quarter_info(self) -> None:
        """Calculate the quarter's date range and number."""
        today = self.created_at
        # Determine quarter
        month = today.month
        year = today.year

        if month <= 3:
            self.quarter = 1
            self.quarter_start = datetime(year, 1, 1)
            self.quarter_end = datetime(year, 3, 31)
        elif month <= 6:
            self.quarter = 2
            self.quarter_start = datetime(year, 4, 1)
            self.quarter_end = datetime(year, 6, 30)
        elif month <= 9:
            self.quarter = 3
            self.quarter_start = datetime(year, 7, 1)
            self.quarter_end = datetime(year, 9, 30)
        else:
            self.quarter = 4
            self.quarter_start = datetime(year, 10, 1)
            self.quarter_end = datetime(year, 12, 31)

    def _get_previous_quarter(self) -> str:
        """Get the previous quarter string (e.g., 'Q4 2025')."""
        if self.quarter == 1:
            return f"Q4 {self._get_year() - 1}"
        return f"Q{self.quarter - 1} {self._get_year()}"

    def _add_header(self) -> None:
        """Add report header with banner image, ID, title, and date range."""
        year = self._get_year()

        # Add banner image at the top
        # Banner is in the root directory of the project
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        banner_path = os.path.join(root_dir, "illumina_report_banner-EIS.png")
        
        # Also try current working directory (if running from root)
        alt_path = "illumina_report_banner-EIS.png"
        
        if os.path.exists(banner_path):
            self._add_image(banner_path, width=Inches(6.5))
            self.doc.add_paragraph()  # Add spacing after banner
        elif os.path.exists(alt_path):
            self._add_image(alt_path, width=Inches(6.5))
            self.doc.add_paragraph()
        else:
            logger.warning(f"Banner image not found at: {banner_path} or {alt_path}")

        # Report ID (e.g., CTI-QTR-2026-Q1) - appears on banner in example, but we'll add it here too
        report_id = f"CTI-QTR-{year}-Q{self.quarter}"
        id_para = self.doc.add_paragraph()
        id_run = id_para.add_run(report_id)
        id_run.font.size = FontSizes.SUBTITLE
        id_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        # Main title
        title_para = self.doc.add_paragraph()
        title_run = title_para.add_run("Cyber Threat Intelligence")
        title_run.font.size = FontSizes.TITLE
        title_run.font.bold = True
        title_run.font.color.rgb = BrandColors.ORANGE_PRIMARY

        # Subtitle
        subtitle_para = self.doc.add_paragraph()
        subtitle_run = subtitle_para.add_run("Quarterly Strategic Brief")
        subtitle_run.font.size = Pt(16)
        subtitle_run.font.color.rgb = BrandColors.GRAY_DARK

        # Quarter date range
        start_month = self.quarter_start.strftime("%B")
        end_month = self.quarter_end.strftime("%B")
        date_range = f"Q{self.quarter} {year} ({start_month} to {end_month})"

        date_para = self.doc.add_paragraph()
        date_run = date_para.add_run(date_range)
        date_run.font.size = Pt(11)
        date_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        self.doc.add_paragraph()

    def _add_executive_summary(self, analysis_result: Dict[str, Any]) -> None:
        """Add executive summary section."""
        logger.info("Adding Executive Summary section")

        self.doc.add_heading("Executive Summary", level=1)

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
                    run.font.size = FontSizes.BODY

        self.doc.add_paragraph()

    def _generate_default_executive_summary(self, analysis_result: Dict[str, Any]) -> str:
        """Generate a default executive summary from available data."""
        stats = analysis_result.get("breach_landscape", {})
        total_incidents = stats.get("total_incidents", 0)
        apt_groups = len(analysis_result.get("geopolitical_threats", {}).get("actors", []))

        return f"""The threat landscape for the genomics, life sciences, and precision manufacturing sectors \
remained elevated throughout Q{self.quarter} {self._get_year()}, with {total_incidents} publicly disclosed \
breaches affecting peer organizations in the industry.

No direct threats to the organization were identified this quarter; however, the threat actors, techniques, \
and vulnerabilities observed are consistent with those historically used against genomics companies. \
{apt_groups} threat actor groups were observed targeting the sector with varying levels of sophistication."""

    def _add_risk_assessment(self, analysis_result: Dict[str, Any]) -> None:
        """Add quarterly risk assessment section with risk cards."""
        logger.info("Adding Quarterly Risk Assessment section")

        self.doc.add_heading("Quarterly Risk Assessment", level=1)

        risk_data = analysis_result.get("risk_assessment", {})

        # Create risk assessment cards table
        risks = [
            (
                "Nation-State\nEspionage",
                risk_data.get("nation_state", RiskLevel.HIGH),
                risk_data.get("nation_state_trend", RiskLevel.UNCHANGED),
            ),
            (
                "Ransomware &\nExtortion",
                risk_data.get("ransomware", RiskLevel.HIGH),
                risk_data.get("ransomware_trend", RiskLevel.INCREASED),
            ),
            (
                "Supply Chain\nCompromise",
                risk_data.get("supply_chain", RiskLevel.MEDIUM),
                risk_data.get("supply_chain_trend", RiskLevel.UNCHANGED),
            ),
            (
                "Insider Threat",
                risk_data.get("insider", RiskLevel.LOW),
                risk_data.get("insider_trend", RiskLevel.UNCHANGED),
            ),
        ]

        table = self.doc.add_table(rows=1, cols=len(risks))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        for i, (category, level, trend) in enumerate(risks):
            cell = table.rows[0].cells[i]
            cell.paragraphs[0].clear()

            # Category name
            cat_para = cell.paragraphs[0]
            cat_run = cat_para.add_run(category)
            cat_run.font.size = FontSizes.BODY_SMALL
            cat_run.font.bold = True
            cat_run.font.color.rgb = BrandColors.GRAY_DARK  # Dark text for readability
            cat_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Risk level with colored background box
            # Create a nested table cell or use paragraph shading for the colored box
            level_para = cell.add_paragraph()
            level_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            level_run = level_para.add_run(level)
            level_run.font.size = Pt(14)
            level_run.font.bold = True
            
            # Set text color and background based on risk level
            # Use paragraph shading to create the colored box effect
            if level == RiskLevel.HIGH:
                level_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White text
                # Shade the paragraph background (creates colored box)
                pPr = level_para._element.get_or_add_pPr()
                shd = pPr.find(qn("w:shd"))
                if shd is None:
                    shd = OxmlElement("w:shd")
                    pPr.append(shd)
                shd.set(qn("w:fill"), "FF0000")  # Red background
            elif level == RiskLevel.MEDIUM:
                level_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White text
                pPr = level_para._element.get_or_add_pPr()
                shd = pPr.find(qn("w:shd"))
                if shd is None:
                    shd = OxmlElement("w:shd")
                    pPr.append(shd)
                shd.set(qn("w:fill"), "FFA500")  # Orange background
            elif level == RiskLevel.LOW:
                level_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White text
                pPr = level_para._element.get_or_add_pPr()
                shd = pPr.find(qn("w:shd"))
                if shd is None:
                    shd = OxmlElement("w:shd")
                    pPr.append(shd)
                shd.set(qn("w:fill"), "008000")  # Green background
            else:
                # Default styling if level doesn't match
                level_run.font.color.rgb = BrandColors.GRAY_DARK

            # Trend vs previous quarter
            prev_quarter = self._get_previous_quarter()
            trend_para = cell.add_paragraph()
            
            # Format trend with percentage if it's a number
            trend_text = str(trend)
            if isinstance(trend, str) and ("+" in trend or "%" in trend):
                # Trend shows increase/decrease
                trend_display = f"vs {prev_quarter}: {trend}"
                trend_run = trend_para.add_run(trend_display)
                # Color increases green
                if "+" in trend:
                    trend_run.font.color.rgb = BrandColors.GREEN_LOW
                else:
                    trend_run.font.color.rgb = BrandColors.GRAY_MEDIUM  # Gray for unchanged
            else:
                trend_display = f"vs {prev_quarter}: {trend}"
                trend_run = trend_para.add_run(trend_display)
                trend_run.font.color.rgb = BrandColors.GRAY_MEDIUM  # Gray for unchanged
            
            trend_run.font.size = FontSizes.FOOTNOTE
            trend_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        self.doc.add_paragraph()

    def _add_breach_landscape(self, analysis_result: Dict[str, Any]) -> None:
        """Add industry breach landscape section."""
        logger.info("Adding Industry Breach Landscape section")

        self.doc.add_heading("Industry Breach Landscape", level=1)

        # Subtitle
        subtitle = self.doc.add_paragraph()
        sub_run = subtitle.add_run(
            f"Publicly disclosed security incidents affecting life sciences, pharmaceutical, "
            f"biotechnology, healthcare, and advanced manufacturing organizations during "
            f"Q{self.quarter} {self._get_year()}."
        )
        sub_run.font.size = FontSizes.SUBTITLE
        sub_run.font.italic = True
        sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        self.doc.add_paragraph()

        breach_data = analysis_result.get("breach_landscape", {})
        prev_quarter = self._get_previous_quarter()

        # Metric cards
        metrics = [
            (
                str(breach_data.get("total_incidents", 0)),
                "Total Incidents",
                f"{prev_quarter}: {breach_data.get('prev_total_incidents', 'N/A')}"
            ),
            (
                f"${breach_data.get('total_impact_millions', 0)}M",
                "Est. Total Impact",
                f"{prev_quarter}: ${breach_data.get('prev_total_impact', 'N/A')}M"
            ),
            (
                str(breach_data.get("ransomware_count", 0)),
                "Ransomware",
                f"{prev_quarter}: {breach_data.get('prev_ransomware', 'N/A')}"
            ),
            (
                f"{breach_data.get('records_exposed_millions', 0)}M",
                "Records Exposed",
                f"{prev_quarter}: {breach_data.get('prev_records', 'N/A')}M"
            ),
        ]

        self._create_metric_cards(metrics)
        self.doc.add_paragraph()

        # Incidents by Type heading
        self.doc.add_heading("Incidents by Type", level=2)

        incidents = analysis_result.get("incidents_by_type", [])
        if incidents:
            table = self.doc.add_table(rows=1, cols=4)
            table.style = "Table Grid"

            headers = ["Incident Type", f"Q{self.quarter} {self._get_year()}", prev_quarter, "Notable Example"]
            header_cells = table.rows[0].cells
            for i, header in enumerate(headers):
                header_cells[i].text = header
                header_cells[i].paragraphs[0].runs[0].font.bold = True
                header_cells[i].paragraphs[0].runs[0].font.size = FontSizes.SUBTITLE
                header_cells[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White text
                self._set_cell_shading(header_cells[i], BrandColors.ORANGE_TABLE_HEADER)  # Orange background

            for incident in incidents:
                row = table.add_row()
                cells = row.cells
                cells[0].text = incident.get("type", "")
                cells[1].text = str(incident.get("current_count", 0))
                cells[2].text = str(incident.get("prev_count", 0))
                cells[3].text = incident.get("notable_example", "")

                for cell in cells:
                    for para in cell.paragraphs:
                        for run in para.runs:
                            run.font.size = FontSizes.SUBTITLE

        self.doc.add_paragraph()

        # Common factors
        common_factors = analysis_result.get("common_factors", "")
        if common_factors:
            factors_para = self.doc.add_paragraph()
            factors_run = factors_para.add_run(f"Common factors across incidents: {common_factors}")
            factors_run.font.size = FontSizes.BODY_SMALL
            factors_run.font.bold = True

        self.doc.add_paragraph()

    def _create_metric_cards(self, metrics: List[tuple]) -> None:
        """Create metric cards for breach landscape."""
        table = self.doc.add_table(rows=1, cols=len(metrics))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        for i, (number, title, subtitle) in enumerate(metrics):
            cell = table.rows[0].cells[i]
            cell.paragraphs[0].clear()

            # Number
            num_para = cell.paragraphs[0]
            num_run = num_para.add_run(number)
            num_run.font.size = Pt(24)
            num_run.font.bold = True
            num_run.font.color.rgb = BrandColors.ORANGE_PRIMARY  # Orange for emphasis
            num_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Title
            title_para = cell.add_paragraph()
            title_run = title_para.add_run(title)
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
                sub_run.font.size = FontSizes.FOOTNOTE
                sub_run.font.color.rgb = BrandColors.GREEN_LOW  # Green for increases
            else:
                sub_run = sub_para.add_run(subtitle)
                sub_run.font.size = FontSizes.FOOTNOTE
                sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM  # Gray for other text
            sub_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

    def _add_geopolitical_landscape(self, analysis_result: Dict[str, Any]) -> None:
        """Add geopolitical threat landscape section."""
        logger.info("Adding Geopolitical Threat Landscape section")

        self.doc.add_heading("Geopolitical Threat Landscape", level=1)

        # Subtitle
        subtitle = self.doc.add_paragraph()
        sub_run = subtitle.add_run(
            f"Nation-state cyber activity with implications for the life sciences and "
            f"genomics sector during Q{self.quarter} {self._get_year()}."
        )
        sub_run.font.size = FontSizes.SUBTITLE
        sub_run.font.italic = True
        sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        self.doc.add_paragraph()

        geopolitical = analysis_result.get("geopolitical_threats", {})

        # Default countries to cover if not provided
        countries = ["china", "russia", "north_korea", "iran"]

        for country in countries:
            country_data = geopolitical.get(country, {})
            if country_data or country in ["china", "russia", "north_korea"]:
                self._add_country_section(country, country_data)

    def _add_country_section(self, country: str, data: Dict[str, Any]) -> None:
        """Add a country-specific threat section."""
        # Country heading - styled in blue/teal color
        country_names = {
            "china": "China",
            "russia": "Russia",
            "north_korea": "North Korea",
            "iran": "Iran"
        }
        country_heading = self.doc.add_heading(country_names.get(country, country.title()), level=2)
        # Style country headings in blue/teal
        for run in country_heading.runs:
            run.font.color.rgb = RGBColor(0x00, 0xBF, 0xFF)  # Light blue/teal color

        # Strategic Context
        strategic_context = data.get("strategic_context", self._get_default_strategic_context(country))
        context_para = self.doc.add_paragraph()
        context_run = context_para.add_run(f"Strategic Context: {strategic_context}")
        context_run.font.size = FontSizes.BODY
        context_run.font.bold = True

        # Quarter Activity
        activity = data.get("activity", self._get_default_activity(country))
        activity_para = self.doc.add_paragraph()
        activity_run = activity_para.add_run(f"Q{self.quarter} Activity: {activity}")
        activity_run.font.size = FontSizes.BODY
        activity_run.font.bold = True

        # Business Implications
        implications = data.get("implications", self._get_default_implications(country))
        impl_para = self.doc.add_paragraph()
        impl_run = impl_para.add_run(f"Business Implications: {implications}")
        impl_run.font.size = FontSizes.BODY
        impl_run.font.bold = True

        self.doc.add_paragraph()

    def _get_default_strategic_context(self, country: str) -> str:
        """Get default strategic context for a country."""
        defaults = {
            "china": "China's national plans designate biotechnology as a strategic priority, with emphasis on genomics, precision medicine, and biomanufacturing.",
            "russia": "Russian state cyber interests in life sciences remain opportunistic, focusing on healthcare disruption capabilities. Russian-speaking criminal groups pose significant ransomware risk.",
            "north_korea": "North Korean cyber operations serve dual purposes: revenue generation to circumvent sanctions and acquisition of medical/pharmaceutical research for domestic programs.",
            "iran": "Iranian cyber operations target healthcare and pharmaceutical sectors primarily for intelligence gathering and potential disruptive capabilities."
        }
        return defaults.get(country, "Strategic context requires analysis.")

    def _get_default_activity(self, country: str) -> str:
        """Get default activity description for a country."""
        return f"Activity analysis for {country.title()} threat actors pending data collection from Intel471 and CrowdStrike sources."

    def _get_default_implications(self, country: str) -> str:
        """Get default business implications for a country."""
        defaults = {
            "china": "Theft of proprietary research, sequencing technology designs, or manufacturing processes could erode competitive advantage.",
            "russia": "Ransomware incidents in life sciences and manufacturing can result in significant recovery costs and operational disruption.",
            "north_korea": "Credential compromise of research or executive personnel could provide access to sensitive environments and IP repositories.",
            "iran": "Potential for both espionage and disruptive operations targeting pharmaceutical supply chains."
        }
        return defaults.get(country, "Business implications require assessment.")

    def _add_looking_ahead(self, analysis_result: Dict[str, Any]) -> None:
        """Add looking ahead section for next quarter."""
        logger.info("Adding Looking Ahead section")

        next_quarter = self.quarter + 1 if self.quarter < 4 else 1
        next_year = self._get_year() if self.quarter < 4 else self._get_year() + 1

        looking_ahead_heading = self.doc.add_heading(f"Looking Ahead: Q{next_quarter} {next_year}", level=1)
        # Style "Looking Ahead" heading in blue/teal
        for run in looking_ahead_heading.runs:
            run.font.color.rgb = RGBColor(0x00, 0xBF, 0xFF)  # Light blue/teal color

        looking_ahead = analysis_result.get("looking_ahead", {})

        # Threat Outlook
        outlook = looking_ahead.get("threat_outlook",
            "We anticipate continued pressure from state-sponsored espionage campaigns as genomics "
            "research and precision manufacturing technology becomes increasingly valuable.")
        outlook_para = self.doc.add_paragraph()
        outlook_run = outlook_para.add_run(f"Threat Outlook: {outlook}")
        outlook_run.font.size = FontSizes.BODY
        outlook_run.font.bold = True

        # Planned Initiatives
        initiatives = looking_ahead.get("planned_initiatives",
            "Continued monitoring of threat landscape and enhancement of detection capabilities.")
        init_para = self.doc.add_paragraph()
        init_run = init_para.add_run(f"Planned Initiatives: {initiatives}")
        init_run.font.size = FontSizes.BODY
        init_run.font.bold = True

        # Watch Items
        watch_items = looking_ahead.get("watch_items",
            "Potential escalation in state-sponsored activity around major industry events and product announcements.")
        watch_para = self.doc.add_paragraph()
        watch_run = watch_para.add_run(f"Watch Items: {watch_items}")
        watch_run.font.size = FontSizes.BODY
        watch_run.font.bold = True

        self.doc.add_paragraph()

    def _add_leadership_recommendations(self, analysis_result: Dict[str, Any]) -> None:
        """Add recommendations for leadership section."""
        logger.info("Adding Recommendations for Leadership section")

        recommendations_heading = self.doc.add_heading("Recommendations for Leadership", level=1)
        # Style "Recommendations" heading in orange
        for run in recommendations_heading.runs:
            run.font.color.rgb = BrandColors.ORANGE_PRIMARY

        recommendations = analysis_result.get("recommendations", [])

        if not recommendations:
            recommendations = [
                ("Executive Awareness", "Consider targeted security awareness for executives and key research personnel given sustained social engineering campaigns via professional networks."),
                ("Vendor Risk Review", "Evaluate security posture of critical software and laboratory equipment vendors given supply chain compromise activity."),
                ("Manufacturing Environment Security", "Review network segmentation between IT and OT/manufacturing systems. Ensure incident response plans address manufacturing disruption scenarios."),
                ("Incident Response Readiness", "Confirm ransomware response plans address regulatory disclosure timelines, notification requirements, and manufacturing continuity scenarios."),
                ("Board Reporting", "Peer incidents and regulatory enforcement may prompt board inquiries. CTI team available to support sector threat context preparation."),
            ]

        for rec in recommendations:
            if isinstance(rec, tuple):
                title, description = rec
                para = self.doc.add_paragraph(style="List Bullet")
                title_run = para.add_run(f"{title}: ")
                title_run.font.bold = True
                title_run.font.size = FontSizes.BODY
                desc_run = para.add_run(description)
                desc_run.font.size = FontSizes.BODY
            else:
                para = self.doc.add_paragraph(rec, style="List Bullet")
                for run in para.runs:
                    run.font.size = FontSizes.BODY
                    run.font.bold = True

        self.doc.add_paragraph()

    def _add_footer(self) -> None:
        """Add footer with contact info and sources."""
        logger.info("Adding footer")

        # Contact info
        contact = self.doc.add_paragraph()
        contact_run = contact.add_run("Prepared by: Cyber Threat Intelligence  |  cti@illumina.com")
        contact_run.font.size = FontSizes.BODY_SMALL
        contact_run.font.bold = True
        contact_run.font.color.rgb = BrandColors.GRAY_DARK  # Dark text
        contact.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Make email a hyperlink (if possible)
        # Note: python-docx doesn't directly support hyperlinks in runs, 
        # but we can style it to look like one
        for run in contact.runs:
            if "cti@illumina.com" in run.text:
                run.font.underline = True

        self.doc.add_paragraph()

        # Data sources
        sources = self.doc.add_paragraph()
        sources_run = sources.add_run(
            "Sources: CrowdStrike Falcon Intelligence, Intel471 Titan, HHS Breach Portal, "
            "FBI IC3, SEC filings, state attorney general notifications, FDA guidance publications, "
            "and open source intelligence. Breach counts based on public disclosures and may not "
            "reflect total incidents."
        )
        sources_run.font.size = FontSizes.FOOTNOTE
        sources_run.font.bold = True
        sources_run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)  # White text
        sources.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Underline "open source intelligence" if present
        for run in sources.runs:
            if "open source intelligence" in run.text.lower():
                run.font.underline = True
