"""CISA KEV (Known Exploited Vulnerabilities) enrichment for the OT section.

The CISA KEV catalog is a free, keyless JSON feed. Claroty already flags whether a
vulnerability is in KEV (``is_known_exploited``), but it does not carry the catalog's
``knownRansomwareCampaignUse`` marker — the signal that matters most for OT/manufacturing,
where ransomware is the dominant threat. This module fetches the catalog once per run and
lets the report flag which exposed/advisory CVEs are used in ransomware campaigns.

Best-effort: any failure (or a disabled toggle) degrades to an empty map, and annotation
becomes a no-op, so KEV enrichment never blocks report generation.
"""

from __future__ import annotations

import logging
from typing import Any

from src.collectors.http_utils import HTTPClient
from src.core.config import collector_config

logger = logging.getLogger(__name__)


async def fetch_kev_map() -> dict[str, dict[str, Any]]:
    """Fetch the CISA KEV catalog as ``{CVE (upper): {ransomware, due_date, date_added}}``.

    Keyless public feed. Best-effort: returns ``{}`` when disabled or on any failure so KEV
    enrichment never blocks report generation.
    """
    if not collector_config.kev_enrich_enabled:
        return {}
    url = collector_config.kev_feed_url
    try:
        async with HTTPClient(
            timeout=collector_config.kev_timeout_seconds, max_retries=collector_config.kev_max_retries
        ) as client:
            data = await client.get(url)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        out: dict[str, dict[str, Any]] = {}
        for vuln in vulns:
            cve_id = (vuln.get("cveID") or "").upper()
            if not cve_id:
                continue
            out[cve_id] = {
                "ransomware": (vuln.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
                "due_date": vuln.get("dueDate", ""),
                "date_added": vuln.get("dateAdded", ""),
            }
        ransomware_count = sum(1 for v in out.values() if v["ransomware"])
        logger.info(f"CISA KEV: loaded {len(out)} known-exploited CVEs ({ransomware_count} ransomware-linked)")
        return out
    except Exception as e:  # best-effort: a KEV failure never breaks report generation
        logger.warning(f"CISA KEV fetch failed ({type(e).__name__}: {e!r}); ransomware flags unavailable this run")
        return {}


def annotate_records_with_kev(
    records: list[dict[str, Any]], kev_map: dict[str, dict[str, Any]], cve_field: str
) -> None:
    """Set KEV-derived flags on each record in place, based on its CVE list.

    Adds:
      - ``in_cisa_kev``: any of the record's CVEs is in the CISA KEV catalog
      - ``known_ransomware``: any of them is flagged as used in ransomware campaigns
      - ``kev_ransomware_cves``: the specific CVEs driving the ransomware flag (only when present)

    ``cve_field`` is the record key holding the CVE list ("cves" for advisories, "cve_ids" for
    Claroty vulnerabilities). No-op when ``kev_map`` is empty (fetch failed / disabled).
    """
    if not kev_map:
        return
    for rec in records or []:
        cves = rec.get(cve_field) or []
        if isinstance(cves, str):
            cves = [cves]
        upper = [c.upper() for c in cves if isinstance(c, str)]
        in_kev = [c for c in upper if c in kev_map]
        ransomware = [c for c in in_kev if kev_map[c].get("ransomware")]
        rec["in_cisa_kev"] = bool(in_kev)
        rec["known_ransomware"] = bool(ransomware)
        if ransomware:
            rec["kev_ransomware_cves"] = ransomware
