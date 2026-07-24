"""HIBP collector — Have I Been Pwned public breach directory.

HIBP's ``/breaches`` endpoint lists every breach it tracks with a breach date, the number
of accounts exposed (``PwnCount``), the affected domain, and the data classes involved. It
is keyless (the API key is only needed for account-specific lookups) but requires a
descriptive User-Agent. Global coverage with clean dates + records makes it a good
cross-industry complement to VCDB and HHS.

Parsed into the common breach-record schema. Best-effort: a fetch/parse failure logs and
returns empty.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.dataset_source import fetch_dataset_text
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": "cti-report-generator (+https://github.com/apskis/cti-report-generator)",
    "Accept": "application/json",
}

_RANSOM_DATACLASSES = ("ransom",)


def _hibp_incident_type(breach: dict) -> str:
    """Infer a coarse incident type from HIBP data classes / description."""
    classes = [str(c).lower() for c in (breach.get("DataClasses") or [])]
    text = f"{breach.get('Description', '')} {' '.join(classes)}".lower()
    if any(m in text for m in _RANSOM_DATACLASSES):
        return "Ransomware"
    # HIBP breaches are, by definition, data exposures of credentials/PII.
    return "Data Exposure"


def parse_hibp(payload: Any) -> list[dict[str, Any]]:
    """Parse the HIBP ``/breaches`` JSON array into common breach records."""
    breaches = payload if isinstance(payload, list) else (payload or {}).get("breaches", [])
    out: list[dict[str, Any]] = []
    for b in breaches or []:
        if not isinstance(b, dict):
            continue
        date_str = str(b.get("BreachDate", "")).strip()  # already YYYY-MM-DD
        if not date_str:
            continue
        pwn = b.get("PwnCount")
        try:
            records = int(pwn) if pwn is not None else None
        except (ValueError, TypeError):
            records = None
        name = str(b.get("Title") or b.get("Name") or "").strip() or "Undisclosed entity"
        out.append(
            {
                "organization": name,
                "date": date_str,
                "incident_type": _hibp_incident_type(b),
                "records_exposed": records,
                "sector": "Technology",  # HIBP breaches are overwhelmingly online-service/tech
                "source": "HIBP",
                "summary": str(b.get("Description", ""))[:300],
                "url": f"https://{b.get('Domain')}" if b.get("Domain") else "",
            }
        )
    return out


class HIBPBreachCollector(BaseCollector):
    """Have I Been Pwned public breach directory (keyless)."""

    @property
    def source_name(self) -> str:
        return "HIBP"

    @property
    def enabled(self) -> bool:
        # Off by default: HIBP is a global consumer/credential directory, not an industry
        # peer source, and its mega-breaches distort the landscape. Opt in via config.
        return self.report_type == "quarterly" and collector_config.breach_include_hibp

    @property
    def lookback_days(self) -> int:
        return 120

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        url = collector_config.hibp_breaches_url
        text = await fetch_dataset_text(url, headers=_HEADERS)
        if text is None:
            return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)
        try:
            payload = json.loads(text)
            records = parse_hibp(payload)
            records = filter_records_to_window(records, self.collection_window)
            logger.info(f"HIBP: {len(records)} breaches")
            return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
        except Exception as e:
            logger.warning(f"HIBP parse failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)
