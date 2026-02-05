"""
Weekly CTI Report Generator.

Generates weekly threat intelligence reports matching the branded template.
"""
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List

from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ROW_HEIGHT_RULE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from src.reports.base import BaseReportGenerator, BrandColors, FontSizes
from src.reports.registry import register_report_generator

logger = logging.getLogger(__name__)


@register_report_generator("weekly")
class WeeklyReportGenerator(BaseReportGenerator):
    """
    Weekly CTI Report Generator.

    Generates reports matching the CTI_Weekly_Report_Template_Example.docx format.

    Template structure:
    - Report ID header (CTI-WK-YYYY-WW)
    - Title: "Cyber Threat Intelligence Weekly Report" (orange, 18pt bold)
    - Date range subtitle
    - Executive Summary
    - This Week at a Glance (metric cards)
    - Vulnerability Exposure (CVE table with weeks tracked)
    - Sector Threat Activity (threat actor table)
    - Exploitation Indicators
    - Recommended Actions
    - Footer with contact info and data sources
    """

    @property
    def report_type(self) -> str:
        return "weekly"

    @property
    def filename_prefix(self) -> str:
        return "CTI_Weekly_Report"

    def generate(self, analysis_result: Dict[str, Any]) -> Document:
        """
        Generate the weekly report document.

        Args:
            analysis_result: Dictionary containing:
                - executive_summary: str
                - statistics: dict with counts
                - cve_analysis: list of CVE dicts
                - apt_activity: list of APT dicts
                - recommendations: list of strings
                - exploitation_indicators: list of strings (optional)

        Returns:
            Document object
        """
        try:
            logger.info("Generating Weekly CTI Report")
            self.doc = Document()

            # Page setup: margins, Letter 8.5x11", header/footer distance, paragraph spacing
            self._configure_page_settings()

            # Dark-mode-friendly: dark page and dark tables so report looks correct in dark mode (no white flash).
            self._set_document_background(BrandColors.METRIC_BOX_DARK)
            normal_style = self.doc.styles["Normal"]
            normal_style.font.color.rgb = BrandColors.TEXT_LIGHT
            normal_style.font.name = "Arial"

            # Calculate date range (Monday to Sunday of current week)
            self._calculate_date_range()

            # Add sections in order
            self._add_header()
            self._add_executive_summary(analysis_result)
            self._add_week_at_glance(analysis_result)
            self._add_vulnerability_exposure(analysis_result)
            self._add_sector_threat_activity(analysis_result)
            self._add_exploitation_indicators(analysis_result)
            self._add_recommended_actions(analysis_result)
            self._add_footer()

            logger.info("Weekly CTI Report generated successfully")
            return self.doc

        except Exception as e:
            logger.error(f"Error generating weekly report: {str(e)}", exc_info=True)
            raise

    def _calculate_date_range(self) -> None:
        """Calculate the week's date range (Monday to Sunday)."""
        today = self.created_at
        # Find Monday of current week
        self.week_start = today - timedelta(days=today.weekday())
        # Find Sunday of current week
        self.week_end = self.week_start + timedelta(days=6)

    def _add_header(self) -> None:
        """Add banner, report code in header bar; then title block on single line."""
        week_num = self._get_week_number()
        year = self._get_year()
        report_id = f"CTI-WK-{year}-{week_num:02d}"
        date_range = f"Week {week_num} | {self.week_start.strftime('%B %d')} to {self.week_end.strftime('%d, %Y')}"

        # Banner in header
        self._add_banner_header()

        # Same horizontal line as bottom of header: report code only (gray monospace), right-aligned
        section = self.doc.sections[0]
        header = section.header
        id_para = header.add_paragraph()
        id_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        id_para.paragraph_format.space_before = Pt(2)
        id_para.paragraph_format.space_after = Pt(0)
        id_run = id_para.add_run(report_id)
        id_run.font.size = FontSizes.FOOTNOTE
        id_run.font.color.rgb = BrandColors.GRAY_LIGHT
        id_run.font.name = "Consolas"

        # Body: main title, 18pt, orange — use Normal style so no line/border under title
        title_para = self.doc.add_paragraph()
        title_para.style = self.doc.styles["Normal"]
        title_para.paragraph_format.space_before = Pt(4)
        title_para.paragraph_format.space_after = Pt(0)
        title_para.paragraph_format.line_spacing = 0.9  # Tighter line height
        title_run = title_para.add_run("Cyber Threat Intelligence Weekly Report")
        title_run.font.size = FontSizes.TITLE  # 18pt
        title_run.font.bold = True
        title_run.font.color.rgb = BrandColors.ORANGE_DESIGN
        title_run.font.name = "Arial"
        title_para.alignment = WD_ALIGN_PARAGRAPH.LEFT
        self._clear_paragraph_borders(title_para)  # No line under the title

        # Subtitle directly below with minimal vertical spacing (dark gray on white)
        date_para = self.doc.add_paragraph()
        date_run = date_para.add_run(date_range)
        date_run.font.size = FontSizes.BODY_SMALL
        date_run.font.color.rgb = BrandColors.GRAY_LIGHT
        date_run.font.name = "Arial"
        date_para.alignment = WD_ALIGN_PARAGRAPH.LEFT
        date_para.paragraph_format.space_before = Pt(2)
        date_para.paragraph_format.space_after = Pt(6)

        # Minimal gap before Executive Summary
        self.doc.add_paragraph()

    def _add_executive_summary(self, analysis_result: Dict[str, Any]) -> None:
        """Add executive summary: bold orange heading, centered white bullet, white body, tight spacing."""
        logger.info("Adding Executive Summary section")

        # Heading 1 style: 14pt, orange
        heading_para = self.doc.add_paragraph()
        heading_para.style = self.doc.styles["Heading 1"]
        heading_para.paragraph_format.space_before = Pt(0)
        heading_para.paragraph_format.space_after = Pt(0)
        heading_run = heading_para.add_run("Executive Summary")
        heading_run.font.bold = True
        heading_run.font.color.rgb = BrandColors.ORANGE_DESIGN
        heading_run.font.size = FontSizes.HEADING_1  # 14pt
        heading_run.font.name = "Arial"

        # Centered bullet (•) on its own line (dark gray so visible on white)
        bullet_para = self.doc.add_paragraph()
        bullet_run = bullet_para.add_run("•")
        bullet_run.font.color.rgb = BrandColors.TEXT_LIGHT
        bullet_run.font.size = FontSizes.BODY
        bullet_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        bullet_para.paragraph_format.space_before = Pt(0)
        bullet_para.paragraph_format.space_after = Pt(0)

        # Body: left-aligned, dark text on white, tight paragraph spacing
        summary = analysis_result.get("executive_summary", "No executive summary available.")
        para = self.doc.add_paragraph(summary)
        para.paragraph_format.space_before = Pt(0)
        para.paragraph_format.space_after = Pt(4)
        para.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
        for run in para.runs:
            run.font.size = FontSizes.BODY
            run.font.color.rgb = BrandColors.TEXT_LIGHT
            run.font.name = "Arial"

    def _add_week_at_glance(self, analysis_result: Dict[str, Any]) -> None:
        """Add 'This Week at a Glance': bold orange heading; space before subtitle."""
        logger.info("Adding This Week at a Glance section")

        # Heading 1 style: "This Week at a Glance", 14pt, orange
        glance_para = self.doc.add_paragraph()
        glance_para.style = self.doc.styles["Heading 1"]
        glance_para.paragraph_format.space_before = Pt(6)
        glance_para.paragraph_format.space_after = Pt(0)
        r1 = glance_para.add_run("This Week ")
        r1.font.bold = True
        r1.font.color.rgb = BrandColors.ORANGE_DESIGN
        r1.font.size = FontSizes.HEADING_1  # 14pt
        r1.font.name = "Arial"
        r2 = glance_para.add_run("at a Glance")
        r2.font.bold = True
        r2.font.underline = False
        r2.font.color.rgb = BrandColors.ORANGE_DESIGN
        r2.font.size = FontSizes.HEADING_1  # 14pt
        r2.font.name = "Arial"

        # Subtitle: italic, light gray, smaller; extra space between title and this paragraph
        subtitle = self.doc.add_paragraph()
        subtitle.paragraph_format.space_before = Pt(10)
        subtitle.paragraph_format.space_after = Pt(4)
        sub_run = subtitle.add_run(
            f"Vulnerability and threat actor metrics from automated collection "
            f"({self.week_start.strftime('%B %d')} to {self.week_end.strftime('%d, %Y')})."
        )
        sub_run.font.size = Pt(9)
        sub_run.font.italic = True
        sub_run.font.color.rgb = BrandColors.GRAY_LIGHT
        sub_run.font.name = "Arial"

        stats = analysis_result.get("statistics", {})

        # All six metrics in 2x3 grid (row1 then row2)
        metrics_row1 = [
            (str(stats.get("new_this_week", stats.get("total_cves", 0))),
             "New This Week",
             "First appearance in Rapid7 scans"),
            (str(stats.get("persistent_count", stats.get("critical_count", 0))),
             "Persistent (3+ Wks)",
             "Unresolved from prior reports"),
            (str(stats.get("resolved_count", 0)),
             "Resolved",
             "Remediated since last week"),
        ]
        metrics_row2 = [
            (str(stats.get("total_exposed", stats.get("total_cves", 0))),
             "Total Exposed",
             "CVEs on assets"),
            (str(stats.get("exploited_count", stats.get("actively_exploited", 0))),
             "Actively Exploited",
             "Confirmed threat actor use"),
            (str(stats.get("apt_groups", 0)),
             "Actor Groups",
             "Targeting biotech sector"),
        ]
        # Two separate tables: 3 boxes, then space, then 3 boxes (per design reference)
        self._create_metric_row(metrics_row1)
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_before = Pt(0)
        spacer.paragraph_format.space_after = Pt(20)  # Vertical gap between the two rows of boxes
        self._create_metric_row(metrics_row2)

        # Minimal gap before next section (no extra padding)
        spacer2 = self.doc.add_paragraph()
        spacer2.paragraph_format.space_before = Pt(0)
        spacer2.paragraph_format.space_after = Pt(6)

    def _create_metric_row(self, metrics: List[tuple]) -> None:
        """Create one row of 3 metric boxes as a single 1x3 table."""
        table = self.doc.add_table(rows=1, cols=3)
        self._clear_table_style(table)  # Prevent Word from overriding cell shading in dark mode
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        for col_idx, (number, title, subtitle) in enumerate(metrics):
            cell = table.rows[0].cells[col_idx]

            # Dark gray background via RGB (same path as accent colors so fill is applied)
            r, g, b = BrandColors.TABLE_CELL_DARK_RGB
            self._set_cell_shading_rgb(cell, r, g, b)
            self._set_cell_borders(cell, BrandColors.BORDER_BOX_LIGHT)

            # Clear default content and build three lines
            cell.paragraphs[0].clear()

            # 1. Colored number: Red (high-risk/Total Exposed), Orange (ongoing), Green (Resolved); 22pt
            num_para = cell.paragraphs[0]
            num_run = num_para.add_run(number)
            num_run.font.size = Pt(22)
            num_run.font.bold = True
            num_run.font.name = "Arial"
            if title == "Resolved":
                num_run.font.color.rgb = BrandColors.GREEN_RESOLVED  # Positive / remediated
            elif title in ("Actively Exploited", "Actor Groups", "Total Exposed"):
                num_run.font.color.rgb = BrandColors.RED_HIGH_RISK  # High-risk / alert / exposure
            else:
                num_run.font.color.rgb = BrandColors.ORANGE_DESIGN  # New This Week, Persistent (ongoing)
            num_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            num_para.paragraph_format.space_after = Pt(2)

            # 2. Bold category title (light text on dark)
            title_para = cell.add_paragraph()
            title_run = title_para.add_run(title)
            title_run.font.size = FontSizes.BODY_SMALL
            title_run.font.bold = True
            title_run.font.color.rgb = BrandColors.TEXT_LIGHT
            title_run.font.name = "Arial"
            title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            title_para.paragraph_format.space_before = Pt(0)
            title_para.paragraph_format.space_after = Pt(2)

            # 3. Smaller light gray subtext; space before box border
            sub_para = cell.add_paragraph()
            sub_run = sub_para.add_run(subtitle)
            sub_run.font.size = FontSizes.FOOTNOTE
            sub_run.font.color.rgb = BrandColors.GRAY_LIGHT
            sub_run.font.name = "Arial"
            sub_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            sub_para.paragraph_format.space_before = Pt(0)
            sub_para.paragraph_format.space_after = Pt(8)  # Spacing between last line and box border

    def _format_exposure_cell(self, cve: Dict[str, Any]) -> str:
        """Format Exposure column as count of servers/databases/endpoints from Rapid7 only. Never use vulnerability description."""
        # Only use fields that represent asset/server/database counts (never description)
        raw = (
            cve.get("exposure")
            or cve.get("exposure_summary")
            or cve.get("asset_count")
            or cve.get("affected_assets")
        )
        if isinstance(raw, str) and raw.strip():
            s = raw.strip()
            # Use only if it looks like a count: "N servers", "N databases", "N endpoints", or "Production"
            lower = s.lower()
            if any(lower.endswith(x) for x in ("servers", "server", "databases", "database", "endpoints", "endpoint")):
                return s[:50]
            if s in ("Production", "N/A", "—", "-"):
                return s
            parts = s.split()
            if len(parts) >= 2 and parts[0].isdigit():
                return s[:50]
        # Build from numeric fields (Rapid7 / pipeline can supply these)
        for key, label in (
            ("server_count", "server"),
            ("servers", "server"),
            ("asset_count", "server"),
            ("host_count", "server"),
            ("hosts", "server"),
            ("database_count", "database"),
            ("databases", "database"),
            ("endpoint_count", "endpoint"),
            ("endpoints", "endpoint"),
            ("affected_asset_count", "server"),
        ):
            val = cve.get(key)
            if val is not None:
                try:
                    n = int(val)
                    return f"{n} {label}{'s' if n != 1 else ''}"
                except (TypeError, ValueError):
                    pass
        return "N/A"

    def _style_heading_1(self, paragraph) -> None:
        """Apply Heading 1 look: orange, 14pt, Arial to all runs in the paragraph."""
        for run in paragraph.runs:
            run.font.color.rgb = BrandColors.ORANGE_DESIGN
            run.font.size = FontSizes.HEADING_1
            run.font.name = "Arial"

    def _add_vulnerability_exposure(self, analysis_result: Dict[str, Any]) -> None:
        """Add Vulnerability Exposure section with table styled per reference image."""
        logger.info("Adding Vulnerability Exposure section")

        h = self.doc.add_heading("Vulnerability Exposure", level=1)
        self._style_heading_1(h)

        cve_analysis = analysis_result.get("cve_analysis", [])

        if cve_analysis:
            table = self.doc.add_table(rows=1, cols=6)
            self._clear_table_style(table)  # Prevent Word from overriding cell shading in dark mode
            headers = ["CVE ID", "Affected Product", "Exposure", "Exploited By", "Risk", "Wks"]
            header_cells = table.rows[0].cells
            table_8pt = Pt(8)
            table_caption_7pt = Pt(7)

            # Header row: #FF5C2E background, white bold centered 8pt, thin light-gray borders
            for i, header in enumerate(headers):
                cell = header_cells[i]
                cell.text = header
                para = cell.paragraphs[0]
                para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run = para.runs[0]
                run.font.bold = True
                run.font.size = table_8pt
                run.font.color.rgb = BrandColors.WHITE
                run.font.name = "Arial"
                hr, hg, hb = BrandColors.TABLE_HEADER_ORANGE_RGB
                self._set_cell_shading_rgb(cell, hr, hg, hb)
                self._set_cell_borders(cell, BrandColors.TABLE_BORDER_GRAY)
                self._set_cell_margins_tight(cell, 2)

            # Compact row heights (header and data)
            header_row = table.rows[0]
            header_row.height_rule = WD_ROW_HEIGHT_RULE.EXACTLY
            header_row.height = Pt(14)

            # Data rows: 8pt, tight padding (2pt), thin borders, compact height
            for cve in cve_analysis:
                row = table.add_row()
                row.height_rule = WD_ROW_HEIGHT_RULE.EXACTLY
                row.height = Pt(14)
                cells = row.cells
                cve_id = cve.get("cve_id", "N/A")
                affected = cve.get("affected_product", cve.get("product", "N/A"))
                # Exposure = count of servers/databases/endpoints from Rapid7 (not vulnerability description)
                exposure = self._format_exposure_cell(cve)
                exploited_by = cve.get("exploited_by", "None known")
                risk = cve.get("risk", cve.get("severity", "N/A"))
                wks_val = cve.get("weeks_detected", cve.get("wks", 1))
                if isinstance(wks_val, str) and wks_val.strip().lower() == "new":
                    wks_str = "New"
                else:
                    try:
                        wks_int = int(wks_val) if not isinstance(wks_val, int) else wks_val
                        wks_str = str(wks_int)
                    except (ValueError, TypeError):
                        wks_str = str(wks_val)

                # Borders and tight padding (2pt) for all cells; CVE ID, Affected Product, Exposure, Wks<3 use dark fill
                for c in cells:
                    self._set_cell_borders(c, BrandColors.TABLE_BORDER_GRAY)
                    self._set_cell_margins_tight(c, 2)

                # CVE ID: dark fill via RGB (no white in dark mode), light text, bold, left
                r, g, b = BrandColors.TABLE_CELL_DARK_RGB
                self._set_cell_shading_rgb(cells[0], r, g, b)
                cells[0].text = cve_id
                p0 = cells[0].paragraphs[0]
                p0.alignment = WD_ALIGN_PARAGRAPH.LEFT
                r0 = p0.runs[0]
                r0.font.size = table_8pt
                r0.font.bold = True
                r0.font.color.rgb = BrandColors.TEXT_LIGHT
                r0.font.name = "Arial"

                # Affected Product: dark fill via RGB, light text, normal, left
                self._set_cell_shading_rgb(cells[1], r, g, b)
                cells[1].text = affected
                p1 = cells[1].paragraphs[0]
                p1.alignment = WD_ALIGN_PARAGRAPH.LEFT
                r1 = p1.runs[0]
                r1.font.size = table_8pt
                r1.font.color.rgb = BrandColors.TEXT_LIGHT
                r1.font.name = "Arial"

                # Exposure: dark fill via RGB, light text, normal, left (count of servers/databases)
                self._set_cell_shading_rgb(cells[2], r, g, b)
                cells[2].text = exposure
                p2 = cells[2].paragraphs[0]
                p2.alignment = WD_ALIGN_PARAGRAPH.LEFT
                r2 = p2.runs[0]
                r2.font.size = table_8pt
                r2.font.color.rgb = BrandColors.TEXT_LIGHT
                r2.font.name = "Arial"

                # Exploited By: conditional background + text color
                cells[3].text = exploited_by
                p3 = cells[3].paragraphs[0]
                p3.alignment = WD_ALIGN_PARAGRAPH.LEFT
                r3 = p3.runs[0]
                r3.font.size = table_8pt
                r3.font.name = "Arial"
                eb_lower = (exploited_by or "").strip().lower()
                if "none" in eb_lower or eb_lower == "none observed":
                    r, g, b = BrandColors.EXPLOITED_BG_GREEN_RGB
                    self._set_cell_shading_rgb(cells[3], r, g, b)
                    r3.font.color.rgb = BrandColors.EXPLOITED_TEXT_GREEN
                elif "poc" in eb_lower or "proof of concept" in eb_lower:
                    r, g, b = BrandColors.EXPLOITED_BG_AMBER_RGB
                    self._set_cell_shading_rgb(cells[3], r, g, b)
                    r3.font.color.rgb = BrandColors.EXPLOITED_TEXT_AMBER
                else:
                    r, g, b = BrandColors.EXPLOITED_BG_RED_RGB
                    self._set_cell_shading_rgb(cells[3], r, g, b)
                    r3.font.color.rgb = BrandColors.EXPLOITED_TEXT_RED

                # Risk: High/Medium/Low with background + bold centered text
                cells[4].text = str(risk)
                p4 = cells[4].paragraphs[0]
                p4.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r4 = p4.runs[0]
                r4.font.size = table_8pt
                r4.font.bold = True
                r4.font.name = "Arial"
                risk_upper = (str(risk) or "").upper()
                if risk_upper in ("HIGH", "CRITICAL", "P1", "P2"):
                    r, g, b = BrandColors.RISK_HIGH_BG_RGB
                    self._set_cell_shading_rgb(cells[4], r, g, b)
                    r4.font.color.rgb = BrandColors.RISK_HIGH_TEXT
                elif risk_upper in ("MEDIUM", "MED"):
                    r, g, b = BrandColors.RISK_MED_BG_RGB
                    self._set_cell_shading_rgb(cells[4], r, g, b)
                    r4.font.color.rgb = BrandColors.RISK_MED_TEXT
                else:
                    r, g, b = BrandColors.RISK_LOW_BG_RGB
                    self._set_cell_shading_rgb(cells[4], r, g, b)
                    r4.font.color.rgb = BrandColors.RISK_LOW_TEXT

                # Wks: New or <3 = dark fill, light text; 3+ = dark brown fill + bold yellow-orange text; centered
                cells[5].text = wks_str
                p5 = cells[5].paragraphs[0]
                p5.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r5 = p5.runs[0]
                r5.font.size = table_8pt
                r5.font.name = "Arial"
                if wks_str.strip().lower() == "new":
                    rd, gd, bd = BrandColors.TABLE_CELL_DARK_RGB
                    self._set_cell_shading_rgb(cells[5], rd, gd, bd)
                    r5.font.color.rgb = BrandColors.TEXT_LIGHT
                else:
                    try:
                        n = int(wks_str)
                        if n >= 3:
                            r, g, b = BrandColors.WKS_HIGHLIGHT_BG_RGB
                            self._set_cell_shading_rgb(cells[5], r, g, b)
                            r5.font.color.rgb = BrandColors.WKS_HIGHLIGHT_TEXT
                            r5.font.bold = True
                        else:
                            rd, gd, bd = BrandColors.TABLE_CELL_DARK_RGB
                            self._set_cell_shading_rgb(cells[5], rd, gd, bd)
                            r5.font.color.rgb = BrandColors.TEXT_LIGHT
                    except ValueError:
                        rd, gd, bd = BrandColors.TABLE_CELL_DARK_RGB
                        self._set_cell_shading_rgb(cells[5], rd, gd, bd)
                        r5.font.color.rgb = BrandColors.TEXT_LIGHT

            # Caption below table: italic gray, 7pt, left-aligned
            caption = self.doc.add_paragraph()
            caption_run = caption.add_run(
                "Wks = consecutive weeks detected. Items at 3+ weeks highlighted. "
                "Source: Rapid7 InsightVM scans."
            )
            caption_run.font.size = table_caption_7pt
            caption_run.font.italic = True
            caption_run.font.color.rgb = BrandColors.GRAY_LIGHT
            caption_run.font.name = "Arial"
            caption.alignment = WD_ALIGN_PARAGRAPH.LEFT
        else:
            self.doc.add_paragraph("No vulnerability data available.")

        self.doc.add_paragraph()

    def _add_sector_threat_activity(self, analysis_result: Dict[str, Any]) -> None:
        """Add sector threat activity section with threat actor table."""
        logger.info("Adding Sector Threat Activity section")

        h = self.doc.add_heading("Sector Threat Activity", level=1)
        self._style_heading_1(h)

        # Intro text
        intro = self.doc.add_paragraph()
        intro_run = intro.add_run(
            "The following threat actors have been observed targeting organizations "
            "in the biotech, pharmaceutical, healthcare, manufacturing, and related sectors this week."
        )
        intro_run.font.size = FontSizes.BODY_SMALL
        intro_run.font.italic = True
        intro_run.font.color.rgb = BrandColors.GRAY_LIGHT

        self.doc.add_paragraph()

        apt_activity = analysis_result.get("apt_activity", [])

        if apt_activity:
            # Create threat actor table
            table = self.doc.add_table(rows=1, cols=3)
            self._clear_table_style(table)  # Prevent Word from overriding cell shading in dark mode

            # Header row
            headers = ["Origin / Motivation", "Activity Observed", "What to Monitor"]
            header_cells = table.rows[0].cells

            hr, hg, hb = BrandColors.TABLE_HEADER_ORANGE_RGB
            for i, header in enumerate(headers):
                header_cells[i].text = header
                para = header_cells[i].paragraphs[0]
                para.runs[0].font.bold = True
                para.runs[0].font.size = FontSizes.SUBTITLE
                para.runs[0].font.color.rgb = BrandColors.WHITE
                self._set_cell_shading_rgb(header_cells[i], hr, hg, hb)

            # Add APT rows (dark cells, light text)
            rd, gd, bd = BrandColors.TABLE_CELL_DARK_RGB
            for apt in apt_activity:
                row = table.add_row()
                cells = row.cells

                # Origin / Motivation
                actor = apt.get("actor", apt.get("name", "Unknown"))
                country = apt.get("country", apt.get("origin", "Unknown"))
                motivation = apt.get("motivation", "Unknown")
                cells[0].text = f"{actor}\n({country})\n{motivation}"

                # Activity Observed
                activity = apt.get("activity", apt.get("description", ""))
                ttps = apt.get("ttps", [])
                if ttps and isinstance(ttps, list):
                    activity += f"\nTTPs: {', '.join(ttps[:3])}"
                cells[1].text = activity

                # What to Monitor
                monitoring = apt.get("what_to_monitor", apt.get("indicators", ""))
                if isinstance(monitoring, list):
                    monitoring = "; ".join(monitoring[:3])
                cells[2].text = monitoring

                # Dark fill and light text for each cell
                for cell in cells:
                    self._set_cell_shading_rgb(cell, rd, gd, bd)
                    for para in cell.paragraphs:
                        for run in para.runs:
                            run.font.size = FontSizes.SUBTITLE
                            run.font.color.rgb = BrandColors.TEXT_LIGHT
        else:
            self.doc.add_paragraph("No threat actor activity data available.")

        self.doc.add_paragraph()

    def _add_exploitation_indicators(self, analysis_result: Dict[str, Any]) -> None:
        """Add exploitation indicators section."""
        logger.info("Adding Exploitation Indicators section")

        h = self.doc.add_heading("Exploitation Indicators for This Week's CVEs", level=1)
        self._style_heading_1(h)

        indicators = analysis_result.get("exploitation_indicators", [])

        # If no explicit indicators, generate from CVE data
        if not indicators:
            cve_analysis = analysis_result.get("cve_analysis", [])
            for cve in cve_analysis[:5]:  # Limit to top 5
                cve_id = cve.get("cve_id", "")
                product = cve.get("affected_product", cve.get("product", "Unknown"))
                description = cve.get("exploitation_indicator", cve.get("description", ""))
                if description:
                    indicators.append(f"{cve_id} ({product}): {description[:150]}")

        if indicators:
            for indicator in indicators:
                para = self.doc.add_paragraph(indicator, style="List Bullet")
                for run in para.runs:
                    run.font.size = FontSizes.BODY_SMALL
                    run.font.bold = True
        else:
            self.doc.add_paragraph("No exploitation indicators available for this week's CVEs.")

        self.doc.add_paragraph()

    def _add_recommended_actions(self, analysis_result: Dict[str, Any]) -> None:
        """Add recommended actions section."""
        logger.info("Adding Recommended Actions section")

        h = self.doc.add_heading("Recommended Actions", level=1)
        self._style_heading_1(h)

        recommendations = analysis_result.get("recommendations", [])

        if recommendations:
            for i, rec in enumerate(recommendations):
                para = self.doc.add_paragraph(rec, style="List Bullet")
                for run in para.runs:
                    run.font.size = FontSizes.BODY_SMALL

                    # Bold important/urgent recommendations
                    lower_rec = rec.lower()
                    if any(word in lower_rec for word in ["urgent", "critical", "immediate", "persistent"]):
                        run.font.bold = True
        else:
            default_recs = [
                "Review scan results for exposed vulnerabilities; validate asset ownership and remediation timelines",
                "Brief development teams on current threat campaigns",
                "Verify endpoint protection has latest behavioral IOAs enabled",
                "Confirm SIEM is receiving logs from affected systems"
            ]
            for rec in default_recs:
                para = self.doc.add_paragraph(rec, style="List Bullet")
                for run in para.runs:
                    run.font.size = FontSizes.BODY_SMALL

        self.doc.add_paragraph()

    def _add_footer(self) -> None:
        """Add footer with contact info and data sources."""
        logger.info("Adding footer")

        # Contact info
        contact = self.doc.add_paragraph()
        contact_run = contact.add_run(
            "Questions or suspicious activity: secops@company.com | ServiceNow | cti@company.com"
        )
        contact_run.font.size = FontSizes.BODY_SMALL
        contact_run.font.bold = True
        contact.alignment = WD_ALIGN_PARAGRAPH.CENTER

        self.doc.add_paragraph()

        # Data sources
        sources = self.doc.add_paragraph()
        sources_run = sources.add_run(
            "Data Sources: Compiled via automated collection from NVD, CrowdStrike Falcon Intelligence, "
            "Intel471, Rapid7 InsightVM, and ThreatQ. Analysis performed by AI-assisted threat analysis."
        )
        sources_run.font.size = FontSizes.FOOTNOTE
        sources_run.font.bold = True
        sources_run.font.color.rgb = BrandColors.GRAY_LIGHT
        sources.alignment = WD_ALIGN_PARAGRAPH.CENTER
