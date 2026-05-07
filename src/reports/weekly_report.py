"""
Weekly CTI Report Generator.

Generates weekly threat intelligence reports matching the branded template.
"""
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
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

            # Print-style: white page so document displays correctly in light and dark mode.
            self._set_document_background(BrandColors.PAGE_WHITE)
            normal_style = self.doc.styles["Normal"]
            normal_style.font.color.rgb = BrandColors.TEXT_DARK
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
            self._add_vulnerability_appendix(analysis_result)
            self._add_ai_disclaimer()
            self._add_footer()

            logger.info("Weekly CTI Report generated successfully")
            return self.doc

        except Exception as e:
            logger.error(f"Error generating weekly report: {str(e)}", exc_info=True)
            raise

    def _calculate_date_range(self) -> None:
        """Calculate the reporting period based on actual data lookback window."""
        from src.core.config import collector_config
        today = self.created_at
        lookback_days = collector_config.nvd_lookback_days
        self.period_end = today
        self.period_start = today - timedelta(days=lookback_days)
        self.lookback_days = lookback_days

    def _add_header(self) -> None:
        """Add banner, report code in header bar; then title block on single line."""
        week_num = self._get_week_number()
        year = self._get_year()
        report_id = f"CTI-WK-{year}-{week_num:02d}"
        date_range = (
            f"{self.lookback_days}-Day Lookback | "
            f"{self.period_start.strftime('%B %d')} to {self.period_end.strftime('%B %d, %Y')}"
        )

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
        bullet_run.font.color.rgb = BrandColors.BULLET_DARK
        bullet_run.font.size = FontSizes.BODY
        bullet_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        bullet_para.paragraph_format.space_before = Pt(0)
        bullet_para.paragraph_format.space_after = Pt(0)

        # Body: left-aligned, dark text on white, tight paragraph spacing
        summary = analysis_result.get("executive_summary", "No executive summary available.")
        para = self.doc.add_paragraph(summary)
        para.paragraph_format.space_before = Pt(0)
        para.paragraph_format.space_after = Pt(4)
        para.paragraph_format.line_spacing = 1.5
        for run in para.runs:
            run.font.size = FontSizes.BODY
            run.font.color.rgb = BrandColors.TEXT_DARK
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
            f"({self.period_start.strftime('%B %d')} to {self.period_end.strftime('%B %d, %Y')})."
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
        self._create_metric_cards(metrics_row1)
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_before = Pt(0)
        spacer.paragraph_format.space_after = Pt(20)  # Vertical gap between the two rows of boxes
        self._create_metric_cards(metrics_row2)

        # Minimal gap before next section (no extra padding)
        spacer2 = self.doc.add_paragraph()
        spacer2.paragraph_format.space_before = Pt(0)
        spacer2.paragraph_format.space_after = Pt(6)

    def _create_metric_cards(self, metrics: List[tuple]) -> None:
        """Create a row of metric cards with light gray backgrounds per spec."""
        table = self.doc.add_table(rows=1, cols=len(metrics))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        for col_idx, (number, title, subtitle) in enumerate(metrics):
            cell = table.rows[0].cells[col_idx]

            # Light gray background per CTI_Weekly_Report_Template_Spec.json (F5F5F5)
            self._set_cell_shading(cell, BrandColors.METRIC_CARD_BG)
            # Add border to make card visible
            self._set_cell_borders(cell, "CCCCCC", "4")

            # Clear and build content
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

            # Title (bold, explicit black color)
            title_para = cell.add_paragraph()
            title_run = title_para.add_run(title)
            title_run.font.size = FontSizes.BODY_SMALL
            title_run.font.bold = True
            title_run.font.color.rgb = RGBColor(0x00, 0x00, 0x00)  # Explicit black
            title_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            title_para.paragraph_format.space_before = Pt(0)
            title_para.paragraph_format.space_after = Pt(2)

            # Subtitle (smaller gray)
            sub_para = cell.add_paragraph()
            sub_run = sub_para.add_run(subtitle)
            sub_run.font.size = FontSizes.FOOTNOTE
            sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM
            sub_run.font.name = "Arial"
            sub_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            sub_para.paragraph_format.space_before = Pt(0)
            sub_para.paragraph_format.space_after = Pt(8)  # Spacing between last line and box border

    def _format_exposure_cell(self, cve: Dict[str, Any]) -> str:
        """Format Exposure column as count of servers/databases/endpoints from Rapid7 only. Never use vulnerability description."""
        # Debug: log what we received for this CVE
        cve_id = cve.get("cve_id", "Unknown")
        
        # Only use fields that represent asset/server/database counts (never description)
        raw = (
            cve.get("exposure")
            or cve.get("exposure_summary")
            or cve.get("asset_count")
            or cve.get("affected_assets")
        )
        
        logger.debug(f"CVE {cve_id} exposure fields - exposure: {cve.get('exposure')}, "
                    f"asset_count: {cve.get('asset_count')}, raw: {raw}")
        
        if isinstance(raw, str) and raw.strip():
            s = raw.strip()
            # Use only if it looks like a count: "N servers", "N databases", "N endpoints", or "Production"
            lower = s.lower()
            if any(lower.endswith(x) for x in ("servers", "server", "databases", "database", "endpoints", "endpoint", "systems", "system", "workstations", "workstation", "cloud servers", "cloud instances")):
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

    @staticmethod
    def _extract_count(exposure_str: str) -> int:
        """Extract numeric count from exposure string like '7 systems'."""
        try:
            return int(str(exposure_str).split()[0])
        except (ValueError, IndexError, AttributeError):
            return 0

    def _group_cves_by_technology(self, cve_analysis: List[Dict[str, Any]]) -> tuple:
        """
        Group CVEs by technology/product family for cleaner reporting.
        
        Returns:
            tuple: (grouped_items, individual_cves, all_cves_for_appendix)
        """
        from collections import defaultdict
        
        # Define grouping patterns
        groups = defaultdict(list)
        individual_cves = []
        
        # Minimum CVEs needed to form a group
        MIN_GROUP_SIZE = 3
        
        for cve in cve_analysis:
            product = cve.get("affected_product", "").strip()
            product_lower = product.lower()
            
            # Group WordPress plugins
            if "wordpress plugin" in product_lower or "wp plugin" in product_lower:
                groups["WordPress Plugins"].append(cve)
            # Group WordPress themes
            elif "wordpress theme" in product_lower or "wp theme" in product_lower:
                groups["WordPress Themes"].append(cve)
            # Group WordPress core
            elif product_lower in ("wordpress", "wordpress core"):
                groups["WordPress Core"].append(cve)
            # Group by vendor for other common products
            elif product.startswith("Microsoft "):
                groups["Microsoft Products"].append(cve)
            elif product.startswith("Apache "):
                groups["Apache Products"].append(cve)
            elif product.startswith("VMware ") or product.startswith("VMWare "):
                groups["VMware Products"].append(cve)
            else:
                # Don't group unique products
                individual_cves.append(cve)
        
        # Convert groups to summary items, only if they meet minimum size
        grouped_items = []
        for group_name, cves in groups.items():
            if len(cves) >= MIN_GROUP_SIZE:
                # Calculate aggregate metrics
                total_systems = sum(self._extract_count(cve.get("exposure", "0")) for cve in cves)
                max_weeks = max((cve.get("weeks_detected", 1) for cve in cves), default=1)
                
                grouped_items.append({
                    "is_group": True,
                    "group_name": group_name,
                    "cve_count": len(cves),
                    "cves": cves,
                    "exposure": f"{total_systems} systems" if total_systems > 0 else "Multiple",
                    "weeks_detected": max_weeks,
                })
            else:
                # If group is too small, treat as individual CVEs
                individual_cves.extend(cves)
        
        # Sort individual CVEs by severity/exposure
        individual_cves.sort(key=lambda x: (
            -self._extract_count(x.get("exposure", "0")),
            -x.get("weeks_detected", 1)
        ))
        
        return grouped_items, individual_cves, cve_analysis

    def _add_vulnerability_exposure(self, analysis_result: Dict[str, Any]) -> None:
        """Add Vulnerability Exposure section with grouped and individual CVEs."""
        logger.info("Adding Vulnerability Exposure section")

        h = self.doc.add_heading("Vulnerability Exposure", level=1)
        self._style_heading_1(h)

        cve_analysis = analysis_result.get("cve_analysis", [])
        
        if not cve_analysis:
            self.doc.add_paragraph("No actively exploited vulnerabilities detected in the environment this week.")
            self.doc.add_paragraph()
            return
        
        # Group CVEs by technology
        grouped_items, individual_cves, all_cves = self._group_cves_by_technology(cve_analysis)
        
        logger.info(f"Grouped: {len(grouped_items)} technology groups, {len(individual_cves)} individual CVEs")

        # Create table
        table = self.doc.add_table(rows=1, cols=4)
        headers = ["Item", "Affected Product/Technology", "Exposure", "Wks"]
        header_cells = table.rows[0].cells
        table_caption_7pt = Pt(7)

        # Header row: orange background, white bold text
        for i, header in enumerate(headers):
            cell = header_cells[i]
            cell.text = header
            para = cell.paragraphs[0]
            para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = para.runs[0]
            run.font.bold = True
            run.font.size = Pt(8)
            run.font.color.rgb = BrandColors.WHITE
            self._set_cell_shading(cell, BrandColors.TABLE_HEADER_BG)
            self._set_cell_borders(cell, "CCCCCC")
            self._set_cell_margins_tight(cell, 2)

        # Add individual CVEs first (most critical/unique)
        for cve in individual_cves:
            row = table.add_row()
            cells = row.cells

            cells[0].text = cve.get("cve_id", "N/A")
            cells[1].text = cve.get("affected_product", cve.get("product", "N/A"))
            cells[2].text = self._format_exposure_cell(cve)

            # Parse weeks for display and 3+ weeks highlighting
            weeks = cve.get("weeks_detected", cve.get("wks", 1))
            if isinstance(weeks, str):
                if weeks.strip().lower() == "new":
                    weeks_num = 0
                    weeks_display = "New"
                else:
                    try:
                        weeks_num = int(weeks)
                        weeks_display = str(weeks_num)
                    except (ValueError, TypeError):
                        weeks_num = 0
                        weeks_display = "New"
            else:
                weeks_num = int(weeks) if weeks is not None else 0
                weeks_display = "New" if weeks_num == 0 or weeks_num == 1 else str(weeks_num)
            cells[3].text = weeks_display

            # Styling for individual CVEs
            for idx in (0, 1, 2):
                self._clear_cell_shading(cells[idx])
                self._set_cell_borders(cells[idx], "CCCCCC")
                for para in cells[idx].paragraphs:
                    for run in para.runs:
                        run.font.size = FontSizes.SUBTITLE
                        run.font.color.rgb = BrandColors.TEXT_DARK

            # Wks: pastel background if 3+
            if weeks_num >= 4:
                self._set_cell_shading(cells[3], BrandColors.WKS_OVERDUE_BG)
            elif weeks_num >= 3:
                self._set_cell_shading(cells[3], BrandColors.WKS_3PLUS_BG)
            else:
                self._clear_cell_shading(cells[3])
            self._set_cell_borders(cells[3], "CCCCCC")
            for para in cells[3].paragraphs:
                para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                for run in para.runs:
                    run.font.size = FontSizes.SUBTITLE
                    run.font.color.rgb = BrandColors.TEXT_DARK

        # Add grouped technology summaries
        for group_item in grouped_items:
            row = table.add_row()
            cells = row.cells

            # Column 0: Group name with count
            cells[0].text = f"{group_item['group_name']}\n({group_item['cve_count']} CVEs)"
            cells[1].text = "Multiple products (see appendix)"
            cells[2].text = group_item.get("exposure", "Multiple")
            
            weeks_num = group_item.get("weeks_detected", 1)
            weeks_display = "New" if weeks_num <= 1 else str(weeks_num)
            cells[3].text = weeks_display

            # Light gray background for grouped items
            for idx in range(4):
                self._set_cell_shading(cells[idx], "F5F5F5")
                self._set_cell_borders(cells[idx], "CCCCCC")
                for para in cells[idx].paragraphs:
                    for run in para.runs:
                        run.font.size = FontSizes.SUBTITLE
                        run.font.color.rgb = BrandColors.TEXT_DARK
                        if idx == 0:  # Make group name bold
                            run.font.bold = True

            # Wks styling for grouped items
            if weeks_num >= 4:
                self._set_cell_shading(cells[3], BrandColors.WKS_OVERDUE_BG)
            elif weeks_num >= 3:
                self._set_cell_shading(cells[3], BrandColors.WKS_3PLUS_BG)
            
            cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Caption below table
        caption = self.doc.add_paragraph()
        caption_run = caption.add_run(
            "Wks = consecutive weeks detected. Items at 3+ weeks (yellow) require escalation, 4+ weeks (red) are overdue. "
            f"Grouped items show {len(grouped_items)} technology families with 3+ CVEs each (full details in appendix). "
            "Individual CVEs shown are unique or critical threats. "
            "Source: Rapid7 InsightVM, CISA KEV, Intel471, CrowdStrike."
        )
        caption_run.font.size = table_caption_7pt
        caption_run.font.italic = True
        caption_run.font.color.rgb = BrandColors.GRAY_MEDIUM
        caption_run.font.name = "Arial"
        caption.alignment = WD_ALIGN_PARAGRAPH.LEFT

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
        intro_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        self.doc.add_paragraph()

        apt_activity = analysis_result.get("apt_activity", [])

        if apt_activity:
            # Create threat actor table per CTI_Weekly_Report_Template_Spec.json
            table = self.doc.add_table(rows=1, cols=3)

            # Header row: orange background, white text
            headers = ["Origin / Motivation", "Activity Observed", "What to Monitor"]
            header_cells = table.rows[0].cells
            for i, header in enumerate(headers):
                header_cells[i].text = header
                para = header_cells[i].paragraphs[0]
                para.runs[0].font.bold = True
                para.runs[0].font.size = FontSizes.SUBTITLE
                para.runs[0].font.color.rgb = BrandColors.WHITE
                self._set_cell_shading(header_cells[i], BrandColors.TABLE_HEADER_BG)
                self._set_cell_borders(header_cells[i], "CCCCCC")

            # Data rows: styled per spec
            for apt in apt_activity:
                row = table.add_row()
                cells = row.cells

                # Column 0: Origin/Motivation - light gray background
                country = apt.get("country", apt.get("origin", "Unknown"))
                motivation = apt.get("motivation", "Unknown")
                cells[0].text = f"{country}\n{motivation}"
                self._set_cell_shading(cells[0], BrandColors.SECTOR_ORIGIN_BG)
                self._set_cell_borders(cells[0], "CCCCCC")

                # Column 1: Activity Observed - no fill (inherit background)
                actor = apt.get("actor", apt.get("name", "Unknown"))
                activity = apt.get("activity", apt.get("description", ""))
                cells[1].text = f"{actor}, {activity}" if activity else actor
                self._clear_cell_shading(cells[1])
                self._set_cell_borders(cells[1], "CCCCCC")

                # Column 2: What to Monitor - light blue background
                monitoring = apt.get("what_to_monitor", apt.get("indicators", ""))
                if isinstance(monitoring, list):
                    monitoring = "; ".join(monitoring[:3])
                cells[2].text = monitoring
                self._set_cell_shading(cells[2], BrandColors.SECTOR_MONITOR_BG)
                self._set_cell_borders(cells[2], "CCCCCC")

                for cell in cells:
                    for para in cell.paragraphs:
                        for run in para.runs:
                            run.font.size = FontSizes.SUBTITLE
                            run.font.color.rgb = BrandColors.TEXT_DARK
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

    def _add_vulnerability_appendix(self, analysis_result: Dict[str, Any]) -> None:
        """Add detailed vulnerability appendix listing all CVEs."""
        logger.info("Adding Vulnerability Appendix section")

        cve_analysis = analysis_result.get("cve_analysis", [])
        
        if not cve_analysis:
            return  # Skip appendix if no CVEs
        
        # Only add appendix if we have enough CVEs to warrant it
        if len(cve_analysis) < 5:
            return

        h = self.doc.add_heading("Appendix: Complete CVE Listing", level=1)
        self._style_heading_1(h)

        # Intro text
        intro = self.doc.add_paragraph()
        intro_run = intro.add_run(
            f"This appendix provides complete details for all {len(cve_analysis)} vulnerabilities detected in the environment. "
            "The summary table in the main report groups common technologies for clarity."
        )
        intro_run.font.size = FontSizes.BODY_SMALL
        intro_run.font.italic = True
        intro_run.font.color.rgb = BrandColors.GRAY_MEDIUM

        self.doc.add_paragraph()

        # Create detailed table
        table = self.doc.add_table(rows=1, cols=4)
        headers = ["CVE ID", "Affected Product", "Exposure", "Wks"]
        header_cells = table.rows[0].cells

        # Header row
        for i, header in enumerate(headers):
            cell = header_cells[i]
            cell.text = header
            para = cell.paragraphs[0]
            para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = para.runs[0]
            run.font.bold = True
            run.font.size = Pt(7)
            run.font.color.rgb = BrandColors.WHITE
            self._set_cell_shading(cell, BrandColors.TABLE_HEADER_BG)
            self._set_cell_borders(cell, "CCCCCC")

        # Add all CVEs
        for cve in cve_analysis:
            row = table.add_row()
            cells = row.cells

            cells[0].text = cve.get("cve_id", "N/A")
            cells[1].text = cve.get("affected_product", cve.get("product", "N/A"))
            cells[2].text = self._format_exposure_cell(cve)

            weeks = cve.get("weeks_detected", 1)
            if isinstance(weeks, str):
                weeks_display = weeks if weeks.lower() != "new" else "1"
            else:
                weeks_num = int(weeks) if weeks is not None else 1
                weeks_display = str(weeks_num)
            cells[3].text = weeks_display

            # Compact styling for appendix
            for idx in range(4):
                self._clear_cell_shading(cells[idx])
                self._set_cell_borders(cells[idx], "CCCCCC")
                for para in cells[idx].paragraphs:
                    for run in para.runs:
                        run.font.size = Pt(7)
                        run.font.color.rgb = BrandColors.TEXT_DARK

            cells[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        self.doc.add_paragraph()

    def _add_ai_disclaimer(self) -> None:
        """Add AI-generated disclaimer box with intelligence sources."""
        logger.info("Adding AI disclaimer box")

        # Add a small gap before the disclaimer
        self.doc.add_paragraph()

        # Create a single-cell table for the box
        table = self.doc.add_table(rows=1, cols=1)
        cell = table.rows[0].cells[0]
        
        # Light blue/gray background for the info box
        self._set_cell_shading(cell, "E8F4F8")  # Light blue-gray
        self._set_cell_borders(cell, "B0D4E3", "8")  # Slightly darker blue border
        
        # Clear default paragraph
        cell.paragraphs[0].clear()
        
        # Title in the box
        title_para = cell.paragraphs[0]
        title_run = title_para.add_run("AI-Generated Intelligence Report")
        title_run.font.size = FontSizes.BODY_SMALL
        title_run.font.bold = True
        title_run.font.color.rgb = BrandColors.TEXT_DARK
        title_run.font.name = "Arial"
        title_para.paragraph_format.space_after = Pt(4)
        
        # Body text
        body_para = cell.add_paragraph()
        body_text = (
            "This report was generated using AI-powered analysis to curate and correlate threat intelligence from the following sources: "
            "NIST National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV) Catalog, "
            "Rapid7 InsightVM, CrowdStrike Falcon Intelligence, Intel471 Titan, ThreatQ, and MITRE ATT&CK. "
            "The analysis identifies threats actively exploited in the wild or targeting the manufacturing, biotech, "
            "medical device, clinical, and genomics industries."
        )
        body_run = body_para.add_run(body_text)
        body_run.font.size = Pt(8)
        body_run.font.color.rgb = BrandColors.GRAY_MEDIUM
        body_run.font.name = "Arial"
        body_para.paragraph_format.space_before = Pt(0)
        body_para.paragraph_format.space_after = Pt(6)
        body_para.paragraph_format.line_spacing = 1.15

        self.doc.add_paragraph()

    def _add_footer(self) -> None:
        """Add footer with contact info."""
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
