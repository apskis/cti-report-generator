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
from src.collectors.http_utils import HTTPClient, NonRetryableHTTPError
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

# Device fields requested when product/vendor matching is enabled.
_DEVICE_FIELDS = ["manufacturer", "model", "model_family", "product_code", "device_type"]


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
        """
        Fetch vulnerabilities that affect devices in the environment.

        Returns:
            CollectorResult with a list of normalized vulnerability dicts, each with
            ``cve_ids`` and affected-device counts. Never raises.
        """
        logger.info("Fetching environment vulnerabilities from Claroty xDome")

        token = self.credentials.get("claroty_token", "")
        if not token:
            logger.warning("Claroty API token not provided, skipping Claroty")
            return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)

        base_url = (self.credentials.get("claroty_base_url") or collector_config.claroty_base_url).rstrip("/")
        url = f"{base_url}{self.VULN_PATH}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        limit = collector_config.claroty_vuln_page_limit
        max_pages = collector_config.claroty_vuln_max_pages

        vulns: list[dict[str, Any]] = []
        try:
            async with HTTPClient() as client:
                offset = 0
                for page in range(max_pages):
                    body = {
                        # Only vulnerabilities that affect a real inventory device.
                        "filter_by": {"field": "affected_devices_count", "operation": "greater", "value": 0},
                        "fields": _VULN_FIELDS,
                        "offset": offset,
                        "limit": limit,
                        "include_count": page == 0,
                    }
                    data = await client.post(url, headers=headers, json_data=body, expected_status=(200,))
                    rows = data.get("vulnerabilities", []) if isinstance(data, dict) else []
                    for row in rows:
                        parsed = self._parse_vuln(row)
                        if parsed:
                            vulns.append(parsed)

                    if len(rows) < limit:
                        break  # last page
                    offset += limit

                logger.info(f"Retrieved {len(vulns)} environment-affecting vulnerabilities from Claroty")

                # Optionally fetch the device inventory for product/vendor matching.
                if collector_config.claroty_match_products:
                    devices = await self._fetch_devices(client, base_url, headers)
                    logger.info(f"Retrieved {len(devices)} device inventory records from Claroty")
                    vulns.extend(devices)

            return CollectorResult(source=self.source_name, success=True, data=vulns, record_count=len(vulns))

        except NonRetryableHTTPError as e:
            logger.error(f"Claroty API error: {e}")
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)
        except Exception as e:
            logger.error(f"Error fetching Claroty vulnerabilities: {e}", exc_info=True)
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)

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

        return {
            "source": "Claroty",
            "record_type": "vulnerability",
            "name": row.get("name", ""),
            "cve_ids": cve_ids,
            "affected_devices_count": _int(row.get("affected_devices_count")),
            "affected_ot_devices_count": _int(row.get("affected_ot_devices_count")),
            "affected_confirmed_devices_count": _int(row.get("affected_confirmed_devices_count")),
            "is_known_exploited": bool(row.get("is_known_exploited")),
        }

    async def _fetch_devices(
        self, client: HTTPClient, base_url: str, headers: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Fetch the (non-retired) device inventory's manufacturer/model for product matching."""
        url = f"{base_url}/api/v1/devices/"
        limit = collector_config.claroty_device_page_limit
        devices: list[dict[str, Any]] = []
        offset = 0
        for page in range(collector_config.claroty_device_max_pages):
            body = {
                "filter_by": {"field": "retired", "operation": "in", "value": [False]},
                "fields": _DEVICE_FIELDS,
                "offset": offset,
                "limit": limit,
                "include_count": page == 0,
            }
            try:
                data = await client.post(url, headers=headers, json_data=body, expected_status=(200,))
            except Exception as e:
                logger.warning(f"Claroty device inventory fetch failed: {e}")
                break
            rows = data.get("devices", []) if isinstance(data, dict) else []
            for row in rows:
                devices.append(
                    {
                        "record_type": "device",
                        "manufacturer": (row.get("manufacturer") or "").strip(),
                        "model": (row.get("model") or "").strip(),
                        "model_family": (row.get("model_family") or "").strip(),
                        "product_code": (row.get("product_code") or "").strip(),
                    }
                )
            if len(rows) < limit:
                break
            offset += limit
        return devices


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


def _name_tokens(text: str) -> set[str]:
    """Normalize a vendor/product string to a set of meaningful (>=4 char) tokens."""
    cleaned = re.sub(r"[^a-z0-9 ]", " ", (text or "").lower())
    return {t for t in cleaned.split() if len(t) >= 4 and t not in _CORP_STOPWORDS}


def _owned_manufacturer_tokens(claroty_data: list[dict[str, Any]]) -> dict[str, int]:
    """Count environment devices per normalized manufacturer/model token."""
    counts: dict[str, int] = {}
    for rec in claroty_data or []:
        if rec.get("record_type") != "device":
            continue
        tokens = _name_tokens(rec.get("manufacturer", "")) | _name_tokens(rec.get("model_family", ""))
        for tok in tokens:
            counts[tok] = counts.get(tok, 0) + 1
    return counts


def _product_match_count(advisory: dict[str, Any], owned_tokens: dict[str, int]) -> int:
    """Devices owned whose manufacturer/model token overlaps the advisory's vendor/product.

    Conservative: returns the max device count among overlapping tokens (not a sum), so
    matching on a vendor with many devices does not inflate unrelated model overlaps.
    """
    if not owned_tokens:
        return 0
    adv_tokens = _name_tokens(advisory.get("vendor", "")) | _name_tokens(advisory.get("product", ""))
    overlap = adv_tokens & set(owned_tokens)
    return max((owned_tokens[t] for t in overlap), default=0)


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
    cve_map = build_cve_asset_map(claroty_data)
    owned_tokens = _owned_manufacturer_tokens(claroty_data)
    for advisory in ot_advisories or []:
        matched = [c for c in (advisory.get("cves") or []) if c.upper() in cve_map]
        cve_assets = max((cve_map[c.upper()]["assets"] for c in matched), default=0)
        cve_ot_assets = max((cve_map[c.upper()]["ot_assets"] for c in matched), default=0)
        product_assets = _product_match_count(advisory, owned_tokens)

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
