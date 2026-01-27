"""
Base report generator class.

Provides common functionality for all report types.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from io import BytesIO
import logging
from typing import Dict, Any

from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn, nsmap
from docx.oxml import OxmlElement

logger = logging.getLogger(__name__)


class BrandColors:
    """Brand color constants matching the template."""

    ORANGE_PRIMARY = RGBColor(0xE6, 0x51, 0x00)  # #E65100 - Main title
    GRAY_DARK = RGBColor(0x55, 0x55, 0x55)  # #555555 - Body text emphasis
    GRAY_MEDIUM = RGBColor(0x66, 0x66, 0x66)  # #666666 - Subtitles, notes
    RED_CRITICAL = RGBColor(0xFF, 0x00, 0x00)  # Red for critical severity
    ORANGE_HIGH = RGBColor(0xFF, 0xA5, 0x00)  # Orange for high severity
    YELLOW_P1 = "FFFF00"  # Yellow highlight for P1


class FontSizes:
    """Font size constants matching the template."""

    TITLE = Pt(18)
    HEADING_1 = Pt(14)
    HEADING_2 = Pt(12)
    BODY = Pt(10.5)
    BODY_SMALL = Pt(10)
    SUBTITLE = Pt(9)
    FOOTNOTE = Pt(8)


class BaseReportGenerator(ABC):
    """
    Abstract base class for report generators.

    Subclasses must implement:
    - report_type: Property returning the report type name
    - generate(): Method to generate the report document
    """

    def __init__(self):
        self.doc: Document | None = None
        self.created_at = datetime.now()

    @property
    @abstractmethod
    def report_type(self) -> str:
        """Return the report type identifier (e.g., 'weekly', 'monthly')."""
        pass

    @property
    @abstractmethod
    def filename_prefix(self) -> str:
        """Return the filename prefix for this report type."""
        pass

    @abstractmethod
    def generate(self, analysis_result: Dict[str, Any]) -> Document:
        """
        Generate the report document.

        Args:
            analysis_result: Dictionary containing analysis results

        Returns:
            Document object (python-docx Document)
        """
        pass

    def get_filename(self) -> str:
        """Generate the filename for this report."""
        date_str = self.created_at.strftime("%Y-%m-%d")
        return f"{self.filename_prefix}_{date_str}.docx"

    def to_bytes(self) -> bytes:
        """Convert the document to bytes for upload."""
        if self.doc is None:
            raise ValueError("Document not generated. Call generate() first.")

        buffer = BytesIO()
        self.doc.save(buffer)
        buffer.seek(0)
        return buffer.getvalue()

    # =========================================================================
    # Common styling utilities
    # =========================================================================

    def _set_cell_shading(self, cell, color_hex: str) -> None:
        """Apply background shading to a table cell."""
        tc_pr = cell._element.get_or_add_tcPr()
        shd = tc_pr.find(qn("w:shd"))
        if shd is None:
            shd = OxmlElement("w:shd")
            tc_pr.append(shd)
        shd.set(qn("w:fill"), color_hex)

    def _apply_severity_color(self, cell, severity: str) -> None:
        """Apply color coding to severity cell text."""
        if not cell.paragraphs[0].runs:
            return

        run = cell.paragraphs[0].runs[0]
        severity_upper = severity.upper()

        if severity_upper == "CRITICAL":
            run.font.color.rgb = BrandColors.RED_CRITICAL
            run.font.bold = True
        elif severity_upper == "HIGH":
            run.font.color.rgb = BrandColors.ORANGE_HIGH
            run.font.bold = True

    def _apply_risk_color(self, cell, risk: str) -> None:
        """Apply color coding to risk level cell."""
        if not cell.paragraphs[0].runs:
            return

        run = cell.paragraphs[0].runs[0]
        risk_upper = risk.upper()

        if risk_upper in ("CRITICAL", "P1"):
            run.font.color.rgb = BrandColors.RED_CRITICAL
            run.font.bold = True
        elif risk_upper in ("HIGH", "P2"):
            run.font.color.rgb = BrandColors.ORANGE_HIGH
            run.font.bold = True

    def _set_paragraph_font(
        self,
        paragraph,
        size: Pt | None = None,
        bold: bool = False,
        italic: bool = False,
        color: RGBColor | None = None
    ) -> None:
        """Set font properties for a paragraph's runs."""
        for run in paragraph.runs:
            if size:
                run.font.size = size
            run.font.bold = bold
            run.font.italic = italic
            if color:
                run.font.color.rgb = color

    def _add_styled_paragraph(
        self,
        text: str,
        size: Pt = FontSizes.BODY,
        bold: bool = False,
        italic: bool = False,
        color: RGBColor | None = None,
        alignment: WD_ALIGN_PARAGRAPH | None = None,
        style: str | None = None
    ):
        """Add a paragraph with custom styling."""
        if style:
            para = self.doc.add_paragraph(text, style=style)
        else:
            para = self.doc.add_paragraph(text)

        if alignment:
            para.alignment = alignment

        for run in para.runs:
            run.font.size = size
            run.font.bold = bold
            run.font.italic = italic
            if color:
                run.font.color.rgb = color

        return para

    def _create_metric_card_table(
        self,
        metrics: list[tuple[str, str, str]]
    ):
        """
        Create a metric card table (like "4 New This Week" cards).

        Args:
            metrics: List of tuples (number, title, subtitle)
        """
        table = self.doc.add_table(rows=1, cols=len(metrics))
        table.autofit = True

        for i, (number, title, subtitle) in enumerate(metrics):
            cell = table.rows[0].cells[i]

            # Clear default paragraph
            cell.paragraphs[0].clear()

            # Add number (large, bold)
            num_para = cell.paragraphs[0]
            num_run = num_para.add_run(number)
            num_run.font.size = Pt(24)
            num_run.font.bold = True
            num_run.font.color.rgb = BrandColors.ORANGE_PRIMARY

            # Add title
            title_para = cell.add_paragraph()
            title_run = title_para.add_run(title)
            title_run.font.size = FontSizes.BODY_SMALL
            title_run.font.bold = True

            # Add subtitle
            sub_para = cell.add_paragraph()
            sub_run = sub_para.add_run(subtitle)
            sub_run.font.size = FontSizes.FOOTNOTE
            sub_run.font.color.rgb = BrandColors.GRAY_MEDIUM
            sub_run.font.italic = True

            # Center align all paragraphs
            for para in cell.paragraphs:
                para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        return table

    def _format_date_range(self, start_date: datetime | None = None, end_date: datetime | None = None) -> str:
        """Format a date range string."""
        if end_date is None:
            end_date = self.created_at
        if start_date is None:
            # Default to 7 days before end_date for weekly
            from datetime import timedelta
            start_date = end_date - timedelta(days=6)

        return f"{start_date.strftime('%B %d')} to {end_date.strftime('%d, %Y')}"

    def _get_week_number(self) -> int:
        """Get ISO week number for the report date."""
        return self.created_at.isocalendar()[1]

    def _get_year(self) -> int:
        """Get year for the report date."""
        return self.created_at.year
