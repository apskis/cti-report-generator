"""EPSS (Exploit Prediction Scoring System) lookup from FIRST.org.

The EPSS API is a free, keyless public endpoint that returns, for a CVE, the probability it
will be exploited in the wild in the next 30 days. It fills the OT section's exploitation
signal for CVEs that CISA KEV and Claroty do not flag — the "Likely (EPSS xx%)" level.

Best-effort: any failure (or a disabled toggle) yields an empty map, and annotation becomes a
no-op, so EPSS enrichment never blocks report generation.
"""

from __future__ import annotations

import logging
from typing import Any

from src.collectors.http_utils import HTTPClient
from src.core.config import collector_config

logger = logging.getLogger(__name__)

_BATCH = 100  # the EPSS API accepts a comma-separated list; batch to keep URLs sane


async def fetch_epss_map(cve_ids: list[str]) -> dict[str, float]:
    """Return ``{CVE (upper): epss_probability}`` for the given CVEs, via FIRST.org (batched).

    Keyless public API. Best-effort: returns ``{}`` when disabled or on any failure.
    """
    if not collector_config.epss_enrich_enabled:
        return {}
    ids = sorted(
        {c.upper() for c in (cve_ids or []) if isinstance(c, str) and c.upper().startswith("CVE-")}
    )
    if not ids:
        return {}
    out: dict[str, float] = {}
    try:
        async with HTTPClient(
            timeout=collector_config.epss_timeout_seconds, max_retries=collector_config.epss_max_retries
        ) as client:
            for i in range(0, len(ids), _BATCH):
                batch = ids[i : i + _BATCH]
                data = await client.get(collector_config.epss_api_url, params={"cve": ",".join(batch)})
                for entry in (data.get("data", []) if isinstance(data, dict) else []):
                    cve_id = (entry.get("cve") or "").upper()
                    if not cve_id:
                        continue
                    try:
                        out[cve_id] = float(entry.get("epss", 0))
                    except (TypeError, ValueError):
                        continue
        logger.info(f"EPSS: scored {len(out)}/{len(ids)} CVEs from FIRST.org")
    except Exception as e:  # best-effort: an EPSS failure never breaks report generation
        logger.warning(f"EPSS fetch failed ({type(e).__name__}: {e!r}); EPSS scores unavailable this run")
    return out


def annotate_records_with_epss(
    records: list[dict[str, Any]], epss_map: dict[str, float], cve_field: str
) -> None:
    """Set each record's ``epss`` to the highest EPSS across its CVEs, in place.

    Only raises a record's score (keeps a higher value already present, e.g. from Claroty).
    ``cve_field`` is the record key holding the CVE list ("cves" for advisories, "cve_ids" for
    Claroty vulnerabilities). No-op when ``epss_map`` is empty (fetch failed / disabled).
    """
    if not epss_map:
        return
    for rec in records or []:
        cves = rec.get(cve_field) or []
        if isinstance(cves, str):
            cves = [cves]
        scores = [epss_map[c.upper()] for c in cves if isinstance(c, str) and c.upper() in epss_map]
        if not scores:
            continue
        best = max(scores)
        existing = rec.get("epss")
        if existing is None or best > existing:
            rec["epss"] = best
