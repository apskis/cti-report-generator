"""
ICS/OT advisory collector.

Fetches Industrial Control System (ICS) / Operational Technology (OT) security
advisories from the RapidAPI "ICS[AP] APIs" listing, which republishes the CISA
ICS advisory feed (the ICS Advisory Project dataset).

These advisories feed the weekly report's Operational Technology (OT) section,
covering vulnerabilities in SCADA, PLC, HMI, and other industrial/manufacturing
control systems relevant to organizations with plant-floor or lab-instrument
environments.

Authentication: RapidAPI key via the ``x-rapidapi-key`` header (stored in Key Vault
as ``rapidapi-ics-key``). The ``x-rapidapi-host`` header identifies the API; its value
comes from the optional ``rapidapi-ics-host`` Key Vault secret when present, else the
configured default (so the endpoint can be repointed without a code change).
"""

import logging
from datetime import datetime
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient, NonRetryableHTTPError
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)


class ICSAdvisoryCollector(BaseCollector):
    """
    Collector for ICS/OT security advisories (RapidAPI ICS[AP] APIs).

    The upstream API republishes CISA ICS advisories (ICS Advisory Project). Field
    names in the JSON response mirror the project's CSV columns, but the exact
    spelling can vary by endpoint/version, so parsing is defensive: each normalized
    field is resolved from a list of candidate keys (the same pattern the Intel471
    collector uses for its idiosyncratic field names).

    Enabled only when a RapidAPI key is present in the supplied credentials, so the
    collector self-disables gracefully when the secret has not been provisioned.
    """

    @property
    def source_name(self) -> str:
        return "ICS-Advisory"

    @property
    def enabled(self) -> bool:
        """Only run when a RapidAPI key was retrieved from Key Vault."""
        return bool(self.credentials.get("rapidapi_ics_key"))

    @property
    def lookback_days(self) -> int:
        if self.report_type == "quarterly":
            return collector_config.ics_advisory_quarterly_lookback_days
        return collector_config.ics_advisory_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch recent ICS/OT advisories and normalize them for the OT report section.

        Returns:
            CollectorResult with a list of normalized advisory dictionaries. Never
            raises — collection failures are captured in the result.
        """
        logger.info("Fetching ICS/OT advisories from RapidAPI ICS[AP] API")

        api_key = self.credentials.get("rapidapi_ics_key", "")
        if not api_key:
            logger.warning("RapidAPI ICS key not provided, skipping ICS/OT advisories")
            return CollectorResult(source=self.source_name, success=True, data=[], record_count=0)

        # Host may be supplied as a Key Vault secret (rapidapi-ics-host); otherwise fall
        # back to the configured default. A secret lets the endpoint be rotated/repointed
        # without a code or app-setting change.
        host = self.credentials.get("rapidapi_ics_host") or collector_config.ics_advisory_host
        url = f"https://{host}{collector_config.ics_advisory_latest_path}"
        headers = {
            "x-rapidapi-key": api_key,
            "x-rapidapi-host": host,
            "Accept": "application/json",
        }

        start_date, end_date = self.get_date_range()

        try:
            async with HTTPClient() as client:
                data = await client.get(url, headers=headers)

            records = self._extract_records(data)
            advisories = []
            for raw in records:
                advisory = self._parse_advisory(raw)
                if advisory is None:
                    continue
                if not self._within_window(advisory, start_date, end_date):
                    continue
                advisories.append(advisory)

            # Most recent first, capped to keep the report section readable.
            advisories.sort(key=lambda a: a.get("released") or "", reverse=True)
            advisories = advisories[: collector_config.ics_advisory_max_results]

            logger.info(f"Retrieved {len(advisories)} ICS/OT advisories in the reporting window")
            return CollectorResult(
                source=self.source_name, success=True, data=advisories, record_count=len(advisories)
            )

        except NonRetryableHTTPError as e:
            logger.error(f"ICS advisory API error: {e}")
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)
        except Exception as e:
            logger.error(f"Error fetching ICS/OT advisories: {e}", exc_info=True)
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull the advisory list out of whatever envelope the API returns.

        Accepts a bare JSON array, or an object keyed by ``data`` / ``advisories`` /
        ``results`` / ``items``.
        """
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("data", "advisories", "results", "items"):
                value = data.get(key)
                if isinstance(value, list):
                    return [r for r in value if isinstance(r, dict)]
        return []

    @staticmethod
    def _first(record: dict[str, Any], *keys: str) -> str:
        """Return the first non-empty value among the candidate keys, as a string."""
        for key in keys:
            if key in record and record[key] not in (None, ""):
                return str(record[key]).strip()
        return ""

    def _parse_advisory(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Normalize one raw advisory record into the report's OT schema.

        Field names are resolved defensively against the several spellings seen across
        the ICS Advisory Project dataset and the RapidAPI response.
        """
        advisory_id = self._first(
            record, "ICS-CERT_Number", "ics_cert_number", "advisory_id", "advisoryId", "id", "number"
        )
        title = self._first(
            record, "ICS-CERT_Advisory_Title", "advisory_title", "title", "name"
        )
        if not advisory_id and not title:
            return None

        vendor = self._first(record, "Vendor", "vendor", "vendor_name")
        product = self._first(record, "Product", "product", "product_name")
        products_affected = self._first(
            record, "Products_Affected", "products_affected", "affected_products", "affected"
        )
        severity = self._first(record, "CVSS_Severity", "cvss_severity", "severity").upper()
        released = self._normalize_date(
            self._first(record, "Original_Release_Date", "original_release_date", "release_date", "released", "date")
        )
        updated = self._normalize_date(
            self._first(record, "Last_Updated", "last_updated", "updated", "modified")
        )

        cvss = self._parse_float(
            self._first(record, "Cumulative_CVSS", "cumulative_cvss", "cvss", "cvss_score", "max_cvss")
        )
        cves = self._parse_cves(record)

        url = self._first(record, "Advisory_URL", "advisory_url", "url", "link")
        if not url and advisory_id:
            url = f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id}"

        return {
            "source": self.source_name,
            "advisory_id": advisory_id or "N/A",
            "title": title,
            "vendor": vendor or "Unknown",
            "product": product,
            "products_affected": products_affected,
            "severity": severity,
            "cvss": cvss,
            "cves": cves,
            "released": released,
            "updated": updated,
            "url": url,
        }

    @staticmethod
    def _parse_cves(record: dict[str, Any]) -> list[str]:
        """Extract CVE IDs, handling both list and comma/space-delimited string forms."""
        raw = record.get("CVE") or record.get("cve") or record.get("cves") or record.get("CVEs")
        if raw is None:
            return []
        if isinstance(raw, list):
            values = [str(v).strip() for v in raw]
        else:
            values = [part.strip() for part in str(raw).replace(";", ",").replace(" ", ",").split(",")]
        seen: list[str] = []
        for value in values:
            if value.upper().startswith("CVE-") and value not in seen:
                seen.append(value)
        return seen

    @staticmethod
    def _parse_float(value: str) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_date(value: str) -> str:
        """Best-effort normalize a date string to ISO ``YYYY-MM-DD`` for sorting/display."""
        if not value:
            return ""
        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y/%m/%d", "%B %d, %Y", "%d %B %Y", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value[: len(fmt) + 5], fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue
        # Fall back to the leading YYYY-MM-DD if present, else the raw string.
        return value[:10]

    def _within_window(self, advisory: dict[str, Any], start_date: datetime, end_date: datetime) -> bool:
        """Keep an advisory if its release/update date falls within the reporting window.

        Advisories with an unparseable date are kept (the ``latest`` endpoint already
        returns recent items, and dropping undated records would silently lose data).
        """
        stamp = advisory.get("released") or advisory.get("updated") or ""
        if not stamp:
            return True
        try:
            when = datetime.strptime(stamp[:10], "%Y-%m-%d")
        except ValueError:
            return True
        return start_date.date() <= when.date() <= end_date.date()
