"""VCDB collector — Verizon VERIS Community Database (open breach dataset).

VCDB is a public, curated corpus of security incidents encoded in the VERIS schema, each
with a victim, industry (NAICS), disclosure/incident timeline, and — where known — the
number of records affected. It is the richest *free, date-stamped* peer-incident source,
so it is the primary input for grounding the quarterly breach stat cards.

Fetched as a combined JSON array (URL configurable). Parsed into the common breach-record
schema (see ``src.core.breach_metrics``). Best-effort: a fetch/parse failure logs and
returns empty, leaving the report's other values intact.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

from src.collectors.base import BaseCollector
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "cti-report-generator (+https://github.com/apskis/cti-report-generator)"}


def _relevant_industry(naics: Any, prefixes: tuple) -> bool:
    """Whether a VERIS NAICS industry code matches one of the relevant 2-digit prefixes."""
    if not prefixes:
        return True
    code = str(naics or "").strip()
    return any(code.startswith(p) for p in prefixes)


def _veris_incident_type(action: dict) -> str:
    """Map a VERIS ``action`` object to a coarse incident type for the report."""
    if not isinstance(action, dict):
        return "Unknown"
    malware = action.get("malware") or {}
    variety = [str(v).lower() for v in (malware.get("variety") or [])]
    if any("ransom" in v for v in variety):
        return "Ransomware"
    if action.get("hacking"):
        return "Hacking"
    if action.get("error"):
        return "Data Exposure"
    if action.get("misuse"):
        return "Insider Threat"
    if action.get("social"):
        return "Social Engineering"
    if malware:
        return "Malware"
    # Fall back to the first declared action family.
    for key in action:
        if isinstance(action[key], dict):
            return key.capitalize()
    return "Unknown"


def _veris_date(timeline: dict) -> str:
    """Build a ``YYYY-MM-DD`` string from a VERIS ``timeline.incident`` block."""
    inc = (timeline or {}).get("incident") or {}
    year = inc.get("year")
    if not year:
        return ""
    month = inc.get("month") or 1
    day = inc.get("day") or 1
    try:
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
    except (ValueError, TypeError):
        return ""


def _veris_org(victim: dict) -> str:
    vid = (victim or {}).get("victim_id")
    if isinstance(vid, list):
        vid = vid[0] if vid else ""
    return str(vid or "").strip()


def parse_vcdb(payload: Any, naics_prefixes: tuple = ()) -> list[dict[str, Any]]:
    """Parse a combined VCDB JSON array into common breach records, filtered by industry."""
    incidents = payload if isinstance(payload, list) else (payload or {}).get("incidents", [])
    out: list[dict[str, Any]] = []
    for inc in incidents or []:
        if not isinstance(inc, dict):
            continue
        victim = inc.get("victim") or {}
        if not _relevant_industry(victim.get("industry"), naics_prefixes):
            continue
        date_str = _veris_date(inc.get("timeline") or {})
        if not date_str:
            continue
        conf = ((inc.get("attribute") or {}).get("confidentiality")) or {}
        records = conf.get("data_total")
        try:
            records = int(records) if records is not None else None
        except (ValueError, TypeError):
            records = None
        out.append(
            {
                "organization": _veris_org(victim) or "Undisclosed entity",
                "date": date_str,
                "incident_type": _veris_incident_type(inc.get("action") or {}),
                "records_exposed": records,
                "source": "VCDB",
                "summary": str(inc.get("summary", ""))[:300],
                "url": "",
            }
        )
    return out


class VCDBCollector(BaseCollector):
    """Verizon VERIS Community Database breach incidents."""

    @property
    def source_name(self) -> str:
        return "VCDB"

    @property
    def enabled(self) -> bool:
        # Peer breach landscape is a quarterly-strategic concern only.
        return self.report_type == "quarterly"

    @property
    def lookback_days(self) -> int:
        return 120

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        url = collector_config.vcdb_data_url
        prefixes = collector_config.vcdb_relevant_naics_prefixes
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=45), headers=_HEADERS
            ) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.warning(f"VCDB: HTTP {resp.status} from {url}; skipping")
                        return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)
                    text = await resp.text()
            payload = json.loads(text)
            records = parse_vcdb(payload, prefixes)
            records = filter_records_to_window(records, self.collection_window)
            logger.info(f"VCDB: {len(records)} relevant incidents")
            return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
        except Exception as e:
            logger.warning(f"VCDB collection failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)
