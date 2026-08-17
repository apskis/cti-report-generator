"""Combined exploitation enrichment for the OT section.

Annotates OT advisories and OT-device vulnerabilities with both exploitation signals used by
the report's "Exploited" column — CISA KEV (in the wild) and EPSS (probability) — so the two
lookups happen in one place rather than being duplicated across the pipelines.
"""

from __future__ import annotations

from typing import Any

from src.enrichment.epss import annotate_records_with_epss, fetch_epss_map
from src.enrichment.kev import annotate_records_with_kev, fetch_kev_map


async def annotate_ot_exploitation(
    advisories: list[dict[str, Any]] | None, exposure: list[dict[str, Any]] | None
) -> None:
    """Annotate OT advisories (``cves``) and device vulnerabilities (``cve_ids``) in place.

    Adds CISA KEV flags (in_cisa_kev / known_ransomware / kev_due_date / kev_affected_product)
    and an ``epss`` probability. Best-effort: each lookup degrades to a no-op on failure.
    """
    advisories = advisories or []
    exposure = exposure or []

    kev_map = await fetch_kev_map()
    annotate_records_with_kev(advisories, kev_map, "cves")
    annotate_records_with_kev(exposure, kev_map, "cve_ids")

    cves = [c for a in advisories for c in (a.get("cves") or [])]
    cves += [c for v in exposure for c in (v.get("cve_ids") or [])]
    epss_map = await fetch_epss_map(cves)
    annotate_records_with_epss(advisories, epss_map, "cves")
    annotate_records_with_epss(exposure, epss_map, "cve_ids")
