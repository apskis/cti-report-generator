"""CISA KEV (Known Exploited Vulnerabilities) — the single fetch of the catalog.

The CISA KEV catalog is a free, keyless JSON feed. It is the source of truth for two
things in the report:

- **OT tables** (this module's ``annotate_records_with_kev``): Claroty already flags KEV
  membership (``is_known_exploited``) but not the catalog's ``knownRansomwareCampaignUse``
  marker — the signal that matters most for OT/manufacturing, where ransomware dominates.
- **IT Exploited Vulnerabilities section** (``src/agents/exploit_enrichment.py``): recently
  added KEV CVEs, ``exploited_by`` strings, and vendor/product backfill.

Both consumers read the one map returned by :func:`fetch_kev_map`, so the catalog is
downloaded once per run. Each entry carries every field either consumer needs.

Best-effort: any failure (or a disabled toggle) degrades to an empty map, and annotation
becomes a no-op, so KEV enrichment never blocks report generation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from src.collectors.http_utils import HTTPClient
from src.core.config import collector_config

logger = logging.getLogger(__name__)

# Run-scoped memo: the catalog is downloaded once and reused by every consumer (OT tables,
# IT Exploited section, CVE enricher). Only successful fetches are cached, so a transient
# failure is retried on the next call rather than poisoning the whole run.
_kev_cache: dict[str, dict[str, Any]] | None = None
_kev_cache_at: datetime | None = None


def reset_kev_cache() -> None:
    """Clear the memoized catalog. For tests and forced refreshes."""
    global _kev_cache, _kev_cache_at
    _kev_cache = None
    _kev_cache_at = None


async def fetch_kev_map(force_refresh: bool = False) -> dict[str, dict[str, Any]]:
    """Fetch the CISA KEV catalog once as a lookup keyed by upper-cased CVE id.

    Each entry carries every field the report's consumers need::

        {"ransomware": bool, "due_date": str, "date_added": str,
         "vendor": str, "product": str, "name": str, "required_action": str}

    ``ransomware`` is normalized to a bool from ``knownRansomwareCampaignUse``. The result
    is memoized for ``kev_cache_hours`` so repeated calls within a run reuse one download;
    pass ``force_refresh=True`` to bypass the memo. Keyless public feed. Best-effort:
    returns ``{}`` when disabled or on any failure so KEV enrichment never blocks report
    generation (failures are not cached).
    """
    global _kev_cache, _kev_cache_at
    if not collector_config.kev_enrich_enabled:
        return {}
    if (
        not force_refresh
        and _kev_cache is not None
        and _kev_cache_at is not None
        and datetime.now() - _kev_cache_at < timedelta(hours=collector_config.kev_cache_hours)
    ):
        return _kev_cache
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
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "required_action": vuln.get("requiredAction", ""),
            }
        ransomware_count = sum(1 for v in out.values() if v["ransomware"])
        logger.info(f"CISA KEV: loaded {len(out)} known-exploited CVEs ({ransomware_count} ransomware-linked)")
        _kev_cache = out
        _kev_cache_at = datetime.now()
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
