"""HHS OCR "Wall of Shame" collector — U.S. healthcare breach notifications.

The HHS Office for Civil Rights publishes every reported breach of protected health
information affecting 500+ individuals, with the covered entity, state, breach type,
**individuals affected**, and submission date. It is a free, date-accurate,
records-quantified source that is directly relevant to a life-sciences customer's peer
landscape (healthcare + labs + biotech).

Fetched as CSV (URL configurable). Parsed into the common breach-record schema. Best-effort:
a fetch/parse failure logs and returns empty.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any

import aiohttp

from src.collectors.base import BaseCollector
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "cti-report-generator (+https://github.com/apskis/cti-report-generator)"}

# HHS CSV column headers (as exported by the OCR breach portal).
_COL_ENTITY = "Name of Covered Entity"
_COL_INDIVIDUALS = "Individuals Affected"
_COL_DATE = "Breach Submission Date"
_COL_TYPE = "Type of Breach"


def _classify_hhs_type(breach_type: str) -> str:
    """Map HHS 'Type of Breach' text to the report's coarse incident types."""
    t = (breach_type or "").lower()
    if "ransom" in t:
        return "Ransomware"
    if "hacking" in t or "it incident" in t:
        return "Hacking"
    if "unauthorized access" in t or "disclosure" in t:
        return "Unauthorized Access"
    if "theft" in t:
        return "Theft"
    if "loss" in t:
        return "Data Loss"
    if "improper disposal" in t:
        return "Improper Disposal"
    return breach_type.strip() or "Unknown"


def _to_iso_date(value: str) -> str:
    """HHS dates are typically ``MM/DD/YYYY`` — normalize to ``YYYY-MM-DD``."""
    from datetime import datetime

    s = (value or "").strip()
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%m/%d/%y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return ""


def parse_hhs_csv(text: str) -> list[dict[str, Any]]:
    """Parse the HHS OCR breach-report CSV into common breach records."""
    out: list[dict[str, Any]] = []
    if not text or not text.strip():
        return out
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        date_iso = _to_iso_date(row.get(_COL_DATE, ""))
        if not date_iso:
            continue
        raw_records = (row.get(_COL_INDIVIDUALS, "") or "").replace(",", "").strip()
        try:
            records = int(raw_records) if raw_records else None
        except ValueError:
            records = None
        out.append(
            {
                "organization": (row.get(_COL_ENTITY, "") or "").strip() or "Undisclosed entity",
                "date": date_iso,
                "incident_type": _classify_hhs_type(row.get(_COL_TYPE, "")),
                "records_exposed": records,
                "sector": "Healthcare",  # HHS OCR portal is healthcare by definition
                "source": "HHS",
                "summary": (row.get(_COL_TYPE, "") or "").strip(),
                "url": "",
            }
        )
    return out


class HHSBreachCollector(BaseCollector):
    """U.S. HHS OCR healthcare breach notifications (500+ individuals)."""

    @property
    def source_name(self) -> str:
        return "HHS"

    @property
    def enabled(self) -> bool:
        return self.report_type == "quarterly"

    @property
    def lookback_days(self) -> int:
        return 120

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        url = collector_config.hhs_breach_csv_url
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=45), headers=_HEADERS
            ) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.warning(f"HHS: HTTP {resp.status} from {url}; skipping")
                        return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)
                    text = await resp.text()
            records = parse_hhs_csv(text)
            records = filter_records_to_window(records, self.collection_window)
            logger.info(f"HHS: {len(records)} healthcare breach notifications")
            return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
        except Exception as e:
            logger.warning(f"HHS collection failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)
