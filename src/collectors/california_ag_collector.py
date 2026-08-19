"""California AG collector — U.S. cross-sector data-breach notifications.

California law requires any entity that suffers a breach affecting 500+ California residents to
submit a sample notification to the Attorney General, who publishes them in a public list. It is
a free, dated, cross-sector registry — a complement to the healthcare-only HHS source and the
leak-site / SEC feeds. (Chosen as the substitute for the Maine AG registry, which is currently
offline after abuse of its reporting portal.)

The list is an HTML table (no official CSV/JSON export). Parsing is header-indexed via lxml, so a
column reorder does not break it. The fetch paginates the date-sorted list, deduping by
(organization, reported date) and stopping when a page adds nothing new. Best-effort: a
fetch/parse failure logs and returns empty.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import lxml.html

from src.collectors.base import BaseCollector
from src.collectors.dataset_source import fetch_dataset_text
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; cti-report-generator/1.0; "
        "+https://github.com/apskis/cti-report-generator)"
    )
}


def _to_iso(value: str) -> str:
    """Normalize a CA AG date (``MM/DD/YYYY``, sometimes a range) to ``YYYY-MM-DD`` (or ``""``).

    A range like ``"12/01/2025 - 12/15/2025"`` uses the first date; unparseable text -> "".
    """
    s = (value or "").strip()
    if not s:
        return ""
    first = s.split(" - ")[0].strip()  # a range "A - B" uses A; a single date is unchanged
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%m/%d/%y"):
        try:
            return datetime.strptime(first, fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def parse_california_ag(html: str) -> list[dict[str, Any]]:
    """Parse the CA AG breach-list HTML into common breach records (header-indexed)."""
    out: list[dict[str, Any]] = []
    if not html:
        return out
    doc = lxml.html.fromstring(html)
    for table in doc.xpath("//table"):
        header_cells = (
            table.xpath(".//thead//th")
            or table.xpath(".//tr[1]/th")
            or table.xpath(".//tr[1]/td")
        )
        headers = [c.text_content().strip().lower() for c in header_cells]
        if not any("organization" in h for h in headers):
            continue

        def _col(needle: str, _headers: list[str] = headers) -> int | None:
            for i, h in enumerate(_headers):
                if needle in h:
                    return i
            return None

        i_org = _col("organization")
        i_reported = _col("reported")
        i_breach = _col("breach")
        body_rows = table.xpath(".//tbody/tr") or table.xpath(".//tr")[1:]
        for tr in body_rows:
            cells = [td.text_content().strip() for td in tr.xpath("./td")]
            if not cells or i_org is None or i_org >= len(cells):
                continue
            org = cells[i_org]
            if not org:
                continue
            reported = cells[i_reported] if i_reported is not None and i_reported < len(cells) else ""
            breach_dates = cells[i_breach] if i_breach is not None and i_breach < len(cells) else ""
            # The reported date is the reliable, always-present, sortable field; breach dates are
            # often a range or "Unknown". Bucket on the reported date.
            date_iso = _to_iso(reported) or _to_iso(breach_dates)
            out.append(
                {
                    "organization": org,
                    "date": date_iso,
                    "incident_type": "Breach",  # CA list does not classify the incident
                    "records_exposed": None,  # not published in the list
                    "sector": "",  # not published; unknown -> default cost
                    "source": "CaliforniaAG",
                    "country": "US",
                    "summary": f"California AG breach notification (breach dates: {breach_dates or 'n/a'})",
                    "url": "",
                }
            )
    return out


class CaliforniaAGCollector(BaseCollector):
    """California AG cross-sector data-breach notifications."""

    @property
    def source_name(self) -> str:
        return "CaliforniaAG"

    @property
    def enabled(self) -> bool:
        # Peer breach landscape is a quarterly-strategic concern only.
        return self.report_type == "quarterly"

    @property
    def lookback_days(self) -> int:
        return 120

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        base = collector_config.ca_ag_breach_url
        seen: set[tuple[str, str]] = set()
        records: list[dict[str, Any]] = []
        for page in range(max(1, collector_config.ca_ag_max_pages)):
            sep = "&" if "?" in base else "?"
            url = base if page == 0 else f"{base}{sep}page={page}"
            text = await fetch_dataset_text(url, headers=_HEADERS)
            if text is None:
                if page == 0:
                    msg = f"California AG: no data fetched from {base}"
                    logger.warning(msg)
                    return CollectorResult(
                        source=self.source_name, success=False, data=[], error=msg, record_count=0
                    )
                break  # a later page failed; keep what we have
            try:
                page_records = parse_california_ag(text)
            except Exception as e:
                logger.warning(f"California AG parse failed on page {page} (non-critical): {e}")
                break
            new = 0
            for rec in page_records:
                key = (rec["organization"].strip().lower(), rec["date"])
                if key in seen:
                    continue
                seen.add(key)
                records.append(rec)
                new += 1
            # Stop when a page adds nothing new (end of list, or a pager param the site ignores).
            if new == 0:
                break

        records = filter_records_to_window(records, self.collection_window)
        logger.info(f"California AG: {len(records)} cross-sector breach notifications")
        return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
