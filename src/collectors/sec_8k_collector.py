"""SEC 8-K Item 1.05 collector — peer public-company material cyber-incident disclosures.

Since the SEC's cybersecurity disclosure rule, public companies must report a material
cybersecurity incident on Form 8-K under Item 1.05 within four business days. That makes EDGAR a
dated, authoritative stream of *peer public-company* breach disclosures — a strong complement to
the leak-site / notification sources, and directly relevant to a public company like the customer.

Fetched from EDGAR full-text search (keyless; a descriptive User-Agent is required, <=10 req/s).
Parsed into the common breach-record schema (see ``src.core.breach_metrics``). Best-effort: a
fetch/parse failure logs and returns empty.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from src.collectors.base import BaseCollector
from src.collectors.dataset_source import fetch_dataset_text
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config, customer_profile
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

# SEC fair-access policy requires a descriptive User-Agent naming the requester + contact.
_HEADERS = {
    "User-Agent": f"{customer_profile.name} CTI Pipeline {customer_profile.security_contact}",
    "Accept": "application/json",
}


def _company_from_display_name(display: str) -> str:
    """Extract the company name from an EDGAR ``display_names`` entry.

    e.g. ``"ACME CORP  (ACME)  (CIK 0001234567)"`` -> ``"ACME CORP"``.
    """
    return re.split(r"\s*\(", str(display or ""), maxsplit=1)[0].strip()


def _filing_url(source: dict[str, Any], accession: str) -> str:
    """Best-effort filing index URL from the CIK + accession, or ``""``."""
    ciks = source.get("ciks") or []
    cik = str(ciks[0]).lstrip("0") if ciks else ""
    acc_nodash = accession.replace("-", "")
    if cik and acc_nodash:
        return f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc_nodash}/"
    return ""


def parse_sec_8k(payload: Any) -> list[dict[str, Any]]:
    """Parse an EDGAR full-text-search response into common breach records.

    One record per filing (deduplicated by accession, since a filing yields a hit per document),
    each a named public company that disclosed a material cybersecurity incident.
    """
    hits = (((payload or {}).get("hits") or {}).get("hits")) or []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        source = hit.get("_source") or {}
        # _id is "<accession>:<document>"; dedupe multi-document filings to one incident.
        accession = str(hit.get("_id", "")).split(":", 1)[0]
        if accession and accession in seen:
            continue
        if accession:
            seen.add(accession)
        names = source.get("display_names") or []
        org = _company_from_display_name(names[0]) if names else ""
        if not org:
            continue
        date_str = str(source.get("file_date") or "").strip()
        out.append(
            {
                "organization": org,
                "date": date_str,
                "incident_type": "Breach",  # Item 1.05 = material cyber incident (kind unspecified)
                "records_exposed": None,  # not quantified at 8-K filing time
                "sector": "",  # EDGAR FTS does not return SIC/sector; unknown -> default cost
                "source": "SEC8K",
                "country": "US",
                "summary": "Form 8-K Item 1.05 - material cybersecurity incident disclosure",
                "url": _filing_url(source, accession),
            }
        )
    return out


class SEC8KCollector(BaseCollector):
    """Peer public-company material cyber-incident disclosures (SEC 8-K Item 1.05)."""

    @property
    def source_name(self) -> str:
        return "SEC8K"

    @property
    def enabled(self) -> bool:
        # Peer breach landscape is a quarterly-strategic concern only.
        return self.report_type == "quarterly"

    @property
    def lookback_days(self) -> int:
        return 120

    def _build_url(self) -> str:
        params = {"q": collector_config.sec_edgar_fts_query, "forms": "8-K"}
        window = self.collection_window
        if window:
            start, end = window
            start_d = start.date() if isinstance(start, datetime) else start
            end_d = end.date() if isinstance(end, datetime) else end
            params["startdt"] = start_d.isoformat()
            params["enddt"] = end_d.isoformat()
        return f"{collector_config.sec_edgar_fts_url}?{urlencode(params)}"

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        url = self._build_url()
        text = await fetch_dataset_text(url, headers=_HEADERS)
        if text is None:
            msg = "SEC 8-K: no data fetched from EDGAR full-text search"
            logger.warning(msg)
            return CollectorResult(source=self.source_name, success=False, data=[], error=msg, record_count=0)
        try:
            payload = json.loads(text)
            records = parse_sec_8k(payload)
            records = filter_records_to_window(records, self.collection_window)
            logger.info(f"SEC 8-K: {len(records)} Item 1.05 cyber-incident disclosures")
            return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
        except Exception as e:
            logger.warning(f"SEC 8-K parse failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)
