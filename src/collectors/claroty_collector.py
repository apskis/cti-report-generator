"""
Claroty xDome collector.

Fetches the organization's vulnerabilities that affect **real devices in the
environment** from the Claroty xDome API, so the weekly report's Operational
Technology (OT) section can show which advisories map to assets you actually
have (rather than generic advisories with no environmental context).

The list endpoint ``POST /api/v1/vulnerabilities/`` with the filter
``affected_devices_count > 0`` returns every vulnerability that affects at least
one inventory device; each row carries its CVE ids and affected-device counts.
We collect those into a CVE -> asset-exposure map and match it against the ICS/OT
advisory CVEs (see ``annotate_ot_advisories_with_assets``).

Authentication: HTTP bearer token (``claroty-api-token`` in Key Vault):
    Authorization: Bearer <token>
"""

import logging
import re
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)

# Fields requested from the vulnerabilities endpoint (must be valid field-enum names).
_VULN_FIELDS = [
    "name",
    "cve_ids",
    "cvss_v3_score",
    "is_known_exploited",
    "affected_devices_count",
    "affected_ot_devices_count",
    "affected_confirmed_devices_count",
]

# Device fields requested when product/vendor matching is enabled (site fields drive the
# location breakdown shown under the asset count).
_DEVICE_FIELDS = [
    "manufacturer",
    "model",
    "model_family",
    "product_code",
    "device_type",
    "site_name",
    "site_group_name",
]


class ClarotyCollector(BaseCollector):
    """
    Collector for the Claroty xDome vulnerabilities API.

    Enabled only when a bearer token is present, so the collector self-disables
    gracefully when the secret has not been provisioned.
    """

    VULN_PATH = "/api/v1/vulnerabilities/"

    @property
    def source_name(self) -> str:
        return "Claroty"

    @property
    def enabled(self) -> bool:
        """Only run when a Claroty API token was retrieved from Key Vault."""
        return bool(self.credentials.get("claroty_token"))

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """No-op in the parallel collection phase.

        Claroty matching is done as a *targeted* enrichment (``fetch_and_annotate``) after
        the ICS/OT advisories are known, so it queries only the advisory CVEs and vendors
        instead of pulling the entire environment (which does not scale — a large tenant has
        far more than the page cap of vulnerabilities and devices). The collector stays
        registered only so the ``claroty-api-token`` secret is fetched from Key Vault.
        """
        return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)

    @staticmethod
    def _parse_vuln(row: dict[str, Any]) -> dict[str, Any] | None:
        """Normalize a vulnerability row; keep only ones with usable CVE ids."""
        cve_ids = row.get("cve_ids") or []
        if isinstance(cve_ids, str):
            cve_ids = [c.strip() for c in cve_ids.replace(";", ",").split(",")]
        cve_ids = [c for c in cve_ids if isinstance(c, str) and c.upper().startswith("CVE-")]
        if not cve_ids:
            return None

        def _int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        try:
            cvss = float(row.get("cvss_v3_score")) if row.get("cvss_v3_score") is not None else None
        except (TypeError, ValueError):
            cvss = None

        return {
            "source": "Claroty",
            "record_type": "vulnerability",
            "name": row.get("name", ""),
            "cve_ids": cve_ids,
            "cvss": cvss,
            "affected_devices_count": _int(row.get("affected_devices_count")),
            "affected_ot_devices_count": _int(row.get("affected_ot_devices_count")),
            "affected_confirmed_devices_count": _int(row.get("affected_confirmed_devices_count")),
            "is_known_exploited": bool(row.get("is_known_exploited")),
        }

    @staticmethod
    def _parse_device(row: dict[str, Any]) -> dict[str, Any]:
        """Normalize a device row for product/vendor matching."""
        return {
            "record_type": "device",
            "manufacturer": (row.get("manufacturer") or "").strip(),
            "model": (row.get("model") or "").strip(),
            "model_family": (row.get("model_family") or "").strip(),
            "product_code": (row.get("product_code") or "").strip(),
            "site_name": (row.get("site_name") or "").strip(),
            "site_group_name": (row.get("site_group_name") or "").strip(),
        }


async def _post_paged(
    client: HTTPClient, url: str, headers: dict[str, str], base_body: dict[str, Any], results_key: str
) -> list[dict[str, Any]]:
    """POST the filter body, following pages until exhausted or the page cap is reached."""
    limit = collector_config.claroty_vuln_page_limit
    out: list[dict[str, Any]] = []
    offset = 0
    for _page in range(collector_config.claroty_vuln_max_pages):
        body = {**base_body, "offset": offset, "limit": limit, "include_count": False}
        data = await client.post(url, headers=headers, json_data=body, expected_status=(200,))
        rows = data.get(results_key, []) if isinstance(data, dict) else []
        out.extend(rows)
        if len(rows) < limit:
            break
        offset += limit
    return out


async def _query_vulns_by_cves(
    client: HTTPClient, base_url: str, headers: dict[str, str], cves: list[str]
) -> list[dict[str, Any]]:
    """Vulnerabilities affecting inventory devices whose CVE is one of the advisory CVEs."""
    if not cves:
        return []
    url = f"{base_url}/api/v1/vulnerabilities/"
    body = {
        "filter_by": {
            "operation": "and",
            "operands": [
                {"field": "affected_devices_count", "operation": "greater", "value": 0},
                {"field": "cve_ids", "operation": "in", "value": cves},
            ],
        },
        "fields": _VULN_FIELDS,
    }
    rows = await _post_paged(client, url, headers, body, "vulnerabilities")
    return [v for v in (ClarotyCollector._parse_vuln(r) for r in rows) if v]


async def _query_devices_by_vendors(
    client: HTTPClient, base_url: str, headers: dict[str, str], vendors: list[str]
) -> list[dict[str, Any]]:
    """Inventory devices whose manufacturer is one of the advisory vendors (with sites)."""
    if not vendors:
        return []
    url = f"{base_url}/api/v1/devices/"
    body = {
        "filter_by": {"field": "manufacturer", "operation": "in", "value": vendors},
        "fields": _DEVICE_FIELDS,
    }
    rows = await _post_paged(client, url, headers, body, "devices")
    return [ClarotyCollector._parse_device(r) for r in rows]


async def fetch_and_annotate(
    ot_advisories: list[dict[str, Any]], credentials: dict[str, str]
) -> list[dict[str, Any]]:
    """Query Claroty for just the advisory CVEs/vendors, then annotate asset exposure.

    Targeted (not a full-environment pull), so it is complete and fast at any tenant scale.
    Always calls ``annotate_ot_advisories_with_assets`` so the advisory fields are set even
    when Claroty is unavailable or the token is missing.
    """
    ot_advisories = ot_advisories or []
    token = (credentials or {}).get("claroty_token", "")
    if not token or not ot_advisories:
        return _tag_status(annotate_ot_advisories_with_assets(ot_advisories, []), "disabled")

    base_url = (credentials.get("claroty_base_url") or collector_config.claroty_base_url).rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    cves = sorted({c.upper() for a in ot_advisories for c in (a.get("cves") or []) if isinstance(c, str)})
    vendors = sorted(
        {
            (a.get("vendor") or "").strip()
            for a in ot_advisories
            if (a.get("vendor") or "").strip() and a.get("vendor") != "Unknown"
        }
    )
    logger.info(f"Claroty: querying {len(cves)} advisory CVEs and {len(vendors)} vendors against the environment")

    records: list[dict[str, Any]] = []
    status = "error"
    try:
        # Optional enrichment: short timeout + no retry storm so a slow/failed Claroty call
        # never blocks report generation.
        async with HTTPClient(
            timeout=collector_config.claroty_timeout_seconds, max_retries=collector_config.claroty_max_retries
        ) as client:
            records += await _query_vulns_by_cves(client, base_url, headers, cves)
            if collector_config.claroty_match_products:
                records += await _query_devices_by_vendors(client, base_url, headers, vendors)
        status = "ok"
        logger.info(f"Claroty matched the environment: {len(records)} vulnerability/device records returned")
    except Exception as e:  # best-effort: a Claroty failure never breaks report generation
        # ``repr`` so an empty-message timeout still identifies the exception type.
        logger.warning(
            f"Claroty enrichment failed ({type(e).__name__}: {e!r}); "
            f"OT asset exposure is UNAVAILABLE this run (not necessarily zero)"
        )

    return _tag_status(annotate_ot_advisories_with_assets(ot_advisories, records), status)


def _tag_status(ot_advisories: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    """Record whether the Claroty query ran (ok / error / disabled) on each advisory."""
    for advisory in ot_advisories or []:
        advisory["claroty_status"] = status
    return ot_advisories


async def fetch_environment_exposure(
    credentials: dict[str, str], limit: int | None = None
) -> list[dict[str, Any]]:
    """Return the top environment vulnerabilities by affected device count, from Claroty.

    This is the real OT exposure in the monitored environment, independent of whether any
    ICS advisory covers it — it surfaces what actually affects the most devices. Server-side
    sorted by ``affected_devices_count`` descending, so a single page is the true top N.
    Best-effort: returns [] on missing token or any failure.
    """
    token = (credentials or {}).get("claroty_token", "")
    if not token:
        return []
    limit = limit or collector_config.claroty_env_exposure_limit
    base_url = (credentials.get("claroty_base_url") or collector_config.claroty_base_url).rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = {
        "filter_by": {"field": "affected_devices_count", "operation": "greater", "value": 0},
        "sort_by": [{"field": "affected_devices_count", "order": "desc"}],
        "fields": _VULN_FIELDS,
        "offset": 0,
        "limit": limit,
        "include_count": False,
    }
    url = f"{base_url}/api/v1/vulnerabilities/"
    try:
        async with HTTPClient(
            timeout=collector_config.claroty_timeout_seconds, max_retries=collector_config.claroty_max_retries
        ) as client:
            data = await client.post(url, headers=headers, json_data=body, expected_status=(200,))
        rows = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        out = [v for v in (ClarotyCollector._parse_vuln(r) for r in rows) if v]
        logger.info(f"Claroty environment exposure: top {len(out)} vulnerabilities by affected device count")
        return out
    except Exception as e:
        logger.warning(f"Claroty environment-exposure query failed ({type(e).__name__}: {e!r})")
        return []


def build_cve_asset_map(claroty_data: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Map each CVE (upper-cased) to the largest asset counts seen for it across vuln rows."""
    cve_map: dict[str, dict[str, int]] = {}
    for vuln in claroty_data or []:
        if vuln.get("record_type") == "device":
            continue
        total = vuln.get("affected_devices_count", 0)
        ot = vuln.get("affected_ot_devices_count", 0)
        for cve in vuln.get("cve_ids", []):
            key = cve.upper()
            cur = cve_map.get(key)
            if cur is None:
                cve_map[key] = {"assets": total, "ot_assets": ot}
            else:
                cur["assets"] = max(cur["assets"], total)
                cur["ot_assets"] = max(cur["ot_assets"], ot)
    return cve_map


# Corporate-form suffixes stripped before vendor-name comparison (kept minimal so real
# name words like "Electric"/"Engineering"/"Systems" are NOT dropped).
_CORP_STOPWORDS = {"inc", "corp", "corporation", "llc", "ltd", "co", "gmbh", "ag", "sa",
                   "srl", "plc", "company", "the", "and", "a", "s"}

# Generic industrial words that must NOT, on their own, trigger a vendor match (they appear
# in many unrelated manufacturer names, e.g. "General Electric" vs "Mitsubishi Electric").
_GENERIC_TOKENS = {"electric", "electronics", "electronic", "systems", "system", "technologies",
                   "technology", "automation", "controls", "control", "industrial", "industries",
                   "corporation", "group", "solutions", "solution", "devices", "device", "medical",
                   "energy", "power", "digital", "networks", "network", "communications",
                   "communication", "instruments", "instrument", "software", "international",
                   "global", "products", "product", "services", "service"}


def _name_tokens(text: str) -> set[str]:
    """Normalize a vendor/product string to a set of meaningful (>=4 char) tokens."""
    cleaned = re.sub(r"[^a-z0-9 ]", " ", (text or "").lower())
    return {t for t in cleaned.split() if len(t) >= 4 and t not in _CORP_STOPWORDS}


def _owned_devices(claroty_data: list[dict[str, Any]]) -> list[tuple[set[str], str]]:
    """Return (manufacturer/model tokens, site label) for each inventory device."""
    out: list[tuple[set[str], str]] = []
    for rec in claroty_data or []:
        if rec.get("record_type") != "device":
            continue
        tokens = _name_tokens(rec.get("manufacturer", "")) | _name_tokens(rec.get("model_family", ""))
        if not tokens:
            continue
        site = rec.get("site_name") or rec.get("site_group_name") or "Unspecified site"
        out.append((tokens, site))
    return out


def _match_device_sites(advisory: dict[str, Any], owned: list[tuple[set[str], str]]) -> list[str]:
    """Site label for each owned device whose vendor matches the advisory.

    A device matches only when it shares a NON-generic token with the advisory's
    vendor/product (so "Mitsubishi Electric" does not match "General Electric" on
    "electric" alone). Returns one site label per matched device (for counting + grouping).
    """
    adv_tokens = _name_tokens(advisory.get("vendor", "")) | _name_tokens(advisory.get("product", ""))
    if not adv_tokens:
        return []
    sites: list[str] = []
    for tokens, site in owned:
        if (adv_tokens & tokens) - _GENERIC_TOKENS:
            sites.append(site)
    return sites


def annotate_ot_advisories_with_assets(
    ot_advisories: list[dict[str, Any]], claroty_data: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Annotate each OT advisory with the count of environment assets it touches.

    Two signals are folded into a single ``affected_assets`` count:
      * CVE match  — the advisory's CVE is tracked on real devices in xDome (precise).
      * Product match — you own the advisory's vendor/product, even if the CVE is not yet
        linked to a device (broader, fuzzier vendor-name match).
    The larger of the two counts wins (one asset can carry several CVEs, so summing would
    double-count). Advisories that touch the environment are moved to the front so the
    report leads with what matters. ``match_type`` records which signal drove the count.
    Mutates in place and returns the (re-ordered) list.
    """
    from collections import Counter

    cve_map = build_cve_asset_map(claroty_data)
    owned = _owned_devices(claroty_data)
    for advisory in ot_advisories or []:
        matched = [c for c in (advisory.get("cves") or []) if c.upper() in cve_map]
        cve_assets = max((cve_map[c.upper()]["assets"] for c in matched), default=0)
        cve_ot_assets = max((cve_map[c.upper()]["ot_assets"] for c in matched), default=0)

        # Product match: distinct owned devices of the advisory's vendor, grouped by site.
        matched_sites = _match_device_sites(advisory, owned)
        product_assets = len(matched_sites)
        advisory["sites"] = Counter(matched_sites).most_common(3)  # [(site, count), ...]

        advisory["matched_cves"] = matched
        advisory["affected_assets"] = max(cve_assets, product_assets)
        advisory["affected_ot_assets"] = cve_ot_assets
        advisory["in_environment"] = advisory["affected_assets"] > 0
        if cve_assets and product_assets:
            advisory["match_type"] = "cve+product"
        elif cve_assets:
            advisory["match_type"] = "cve"
        elif product_assets:
            advisory["match_type"] = "product"
        else:
            advisory["match_type"] = "none"

    # Lead with in-environment advisories, highest asset count first.
    ot_advisories.sort(key=lambda a: (a.get("in_environment", False), a.get("affected_assets", 0)), reverse=True)
    return ot_advisories
