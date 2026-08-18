"""ransomware.live collector — public ransomware leak-site victim tracker (keyless).

ransomware.live aggregates named victims posted to ransomware groups' leak sites, each with a
group, discovery date, sector/activity, and country. It is a free, date-stamped, sector-tagged
source that directly grounds the quarterly report's Ransomware stat card and the ransomware
share of the breach landscape.

Parsed into the common breach-record schema (see ``src.core.breach_metrics``). The parser is
version-tolerant: it accepts both the v1 (``post_title``/``group_name``/``activity``) and v2
(``victim``/``group``/``sector``) record shapes, since the public API has changed field names
across releases. Best-effort: a fetch/parse failure logs and returns empty.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.dataset_source import fetch_dataset_text
from src.core.breach_metrics import filter_records_to_window
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "cti-report-generator (+https://github.com/apskis/cti-report-generator)"}

# Free-text "activity"/"sector" -> coarse sector label used by breach_metrics for cost weighting.
# Ordered: the first family whose needle is a substring of the (lowercased) text wins.
_SECTOR_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Pharmaceuticals", ("pharma", "biotech", "life scien")),
    ("Healthcare", ("health", "hospital", "medical", "clinic", "care")),
    ("Manufacturing", ("manufactur", "industrial", "factory", "production")),
    ("Financial", ("financ", "bank", "insurance", "capital", "invest")),
    ("Technology", ("technolog", "software", "it service", "saas", "internet")),
    ("Energy", ("energy", "oil", "gas", "utilit", "petroleum")),
    ("Professional/Scientific", ("legal", "consult", "professional", "scientific", "research", "engineering", "laborator")),
    ("Public", ("government", "public", "education", "university", "municipal")),
)

# Sectors kept for the peer breach landscape (mirrors the VCDB industry scope: healthcare,
# life sciences, manufacturing, professional/scientific). Unknown/other sectors are dropped so
# the ransomware landscape stays peer-relevant rather than a global firehose.
_RELEVANT_SECTORS = {"Healthcare", "Pharmaceuticals", "Manufacturing", "Professional/Scientific"}


def activity_to_sector(text: str) -> str:
    """Map a ransomware.live activity/sector string to a coarse sector label (``""`` if unknown)."""
    t = (text or "").strip().lower()
    if not t:
        return ""
    for label, needles in _SECTOR_FAMILIES:
        if any(n in t for n in needles):
            return label
    return ""


def parse_ransomware_live(payload: Any) -> list[dict[str, Any]]:
    """Parse a ransomware.live victims payload into peer-relevant common breach records.

    Accepts a JSON array of victim objects (or an object wrapping one under ``victims``/``data``).
    Version-tolerant on field names; keeps only victims whose mapped sector is peer-relevant.
    """
    if isinstance(payload, dict):
        victims = payload.get("victims") or payload.get("data") or payload.get("results") or []
    else:
        victims = payload or []
    out: list[dict[str, Any]] = []
    for v in victims:
        if not isinstance(v, dict):
            continue
        name = str(v.get("victim") or v.get("post_title") or v.get("victim_name") or "").strip()
        if not name:
            continue
        # Date: prefer discovery, then attack/published. Values look like "2026-05-14 09:12:33"
        # or "2026-05-14"; keep the date portion (the report parser also tolerates the full form).
        raw_date = str(v.get("discovered") or v.get("attackdate") or v.get("published") or "").strip()
        date_str = re.split(r"[T ]", raw_date, maxsplit=1)[0] if raw_date else ""
        sector = activity_to_sector(str(v.get("sector") or v.get("activity") or v.get("industry") or ""))
        if sector not in _RELEVANT_SECTORS:
            continue
        group = str(v.get("group") or v.get("group_name") or "").strip()
        out.append(
            {
                "organization": name,
                "date": date_str,
                "incident_type": "Ransomware",  # leak-site postings are ransomware by definition
                "records_exposed": None,  # ransomware.live does not report affected-record counts
                "sector": sector,
                "source": "RansomwareLive",
                "threat_actor": group,
                "country": str(v.get("country") or "").strip(),
                "summary": str(v.get("description") or v.get("summary") or "")[:300],
                "url": str(v.get("url") or v.get("website") or "").strip(),
            }
        )
    return out


class RansomwareLiveCollector(BaseCollector):
    """Public ransomware leak-site victim postings (ransomware.live)."""

    @property
    def source_name(self) -> str:
        return "RansomwareLive"

    @property
    def enabled(self) -> bool:
        # Peer breach landscape is a quarterly-strategic concern only.
        return self.report_type == "quarterly"

    @property
    def lookback_days(self) -> int:
        return 120

    async def collect(self, report_type: str = "quarterly") -> CollectorResult:
        url = collector_config.ransomware_live_url
        text = await fetch_dataset_text(url, headers=_HEADERS)
        if text is None:
            # A distinct failure (fetch/host unavailable), not "no ransomware this quarter".
            msg = f"ransomware.live: no data fetched from {url}"
            logger.warning(msg)
            return CollectorResult(source=self.source_name, success=False, data=[], error=msg, record_count=0)
        try:
            payload = json.loads(text)
            records = parse_ransomware_live(payload)
            records = filter_records_to_window(records, self.collection_window)
            logger.info(f"ransomware.live: {len(records)} peer-relevant ransomware victims")
            return CollectorResult(source=self.source_name, success=True, data=records, record_count=len(records))
        except Exception as e:
            logger.warning(f"ransomware.live parse failed (non-critical): {e}")
            return CollectorResult(source=self.source_name, success=False, data=[], error=str(e), record_count=0)
