"""
NVD (National Vulnerability Database) collector.

Fetches CVE vulnerability data from the NIST NVD API.
"""

import logging
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient, RetryableHTTPError
from src.core.config import collector_config
from src.core.models import CollectorResult, CVERecord

logger = logging.getLogger(__name__)


class NVDCollector(BaseCollector):
    """
    Collector for the NIST National Vulnerability Database.

    API Documentation: https://nvd.nist.gov/developers/vulnerabilities
    Rate Limits: 5 requests/30sec (without key), 50 requests/30sec (with key)
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @property
    def source_name(self) -> str:
        return "NVD"

    @property
    def lookback_days(self) -> int:
        return collector_config.nvd_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch CVEs from NVD API (CRITICAL and HIGH severity only).
        Falls back to CircleCII API if NVD is blocked by CloudFlare.

        Returns:
            CollectorResult with list of CVE records
        """
        logger.info("Fetching CVEs from NVD API")

        try:
            api_key = self.credentials.get("nvd_key", "")

            # Calculate date range
            start_date, end_date = self.get_date_range()

            # Format dates for NVD API (ISO 8601 format)
            start_date_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
            end_date_str = end_date.strftime("%Y-%m-%dT23:59:59.999")

            params = {
                "pubStartDate": start_date_str,
                "pubEndDate": end_date_str,
                "resultsPerPage": collector_config.nvd_max_results,
            }

            headers = {}
            if api_key:
                headers["apiKey"] = api_key

            async with HTTPClient() as client:
                data = await client.get(self.NVD_API_URL, params=params, headers=headers if headers else None)

                cves = self._parse_cves(data)

                logger.info(f"Retrieved {len(cves)} CRITICAL/HIGH CVEs from NVD")
                return CollectorResult(
                    source=self.source_name, success=True, data=[cve.to_dict() for cve in cves], record_count=len(cves)
                )

        except RetryableHTTPError as e:
            # Check if it's a 503 error (CloudFlare blocking)
            if e.status_code == 503:
                logger.warning("NVD returned 503 (CloudFlare protection), trying CircleCII fallback")
                return await self._fallback_to_circleci()

            logger.error(f"Error fetching NVD CVEs: {e}", exc_info=True)
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)
        except Exception as e:
            error_msg = str(e)
            # Also check string for 503 in case it's wrapped differently
            if "503" in error_msg or "Service Unavailable" in error_msg:
                logger.warning("NVD returned 503 (CloudFlare protection), trying CircleCII fallback")
                return await self._fallback_to_circleci()

            logger.error(f"Error fetching NVD CVEs: {e}", exc_info=True)
            return CollectorResult(source=self.source_name, success=False, error=str(e), record_count=0)

    async def _fallback_to_circleci(self) -> CollectorResult:
        """
        Fallback to CircleCII CVE API when NVD is unavailable.

        CircleCII provides free CVE data without CloudFlare protection.
        API: https://cve.circl.lu/api/
        """
        try:
            logger.info("Using CircleCII CVE API as fallback")

            # Get last N days of CVEs from CircleCII
            lookback = self.lookback_days
            url = f"https://cve.circl.lu/api/last/{lookback}"

            async with HTTPClient() as client:
                data = await client.get(url)

                cves = self._parse_circleci_cves(data)

                logger.info(f"Retrieved {len(cves)} CRITICAL/HIGH CVEs from CircleCII (fallback)")
                return CollectorResult(
                    source=f"{self.source_name} (CircleCII)",
                    success=True,
                    data=[cve.to_dict() for cve in cves],
                    record_count=len(cves),
                )

        except Exception as e:
            logger.error(f"CircleCII fallback also failed: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=f"NVD CloudFlare blocked, CircleCII fallback failed: {str(e)}",
                record_count=0,
            )

    def _parse_circleci_cves(self, data: list[dict[str, Any]]) -> list[CVERecord]:
        """
        Parse CircleCII API response into CVERecord objects.

        Returns ALL CVEs regardless of severity - filtering will happen during enrichment
        when we check CISA KEV and threat intelligence for exploitation evidence.

        Args:
            data: List of CVE objects from CircleCII

        Returns:
            List of CVERecord objects (all severities - exploitation matters more than rating)
        """
        cves = []

        for item in data:
            cve_id = item.get("id", "")

            # Extract CVSS score
            cvss_score = 0.0
            cvss = item.get("cvss", 0)
            if isinstance(cvss, (int, float)):
                cvss_score = float(cvss)

            # Determine severity from CVSS score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Include ALL severities - we'll filter by exploitation activity later
            # A MEDIUM CVE being actively exploited is more important than a CRITICAL CVE sitting idle

            # Extract description
            description = item.get("summary", "")

            # Extract published date
            published = item.get("Published", "")

            # Extract affected product from vulnerable_product list
            affected_product = ""
            vuln_products = item.get("vulnerable_product", [])
            if vuln_products:
                # Parse CPE string from first product
                cpe = vuln_products[0]
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    if vendor and product:
                        affected_product = f"{vendor} {product}"

            cves.append(
                CVERecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=published,
                    exploited=False,
                    source=f"{self.source_name} (CircleCII)",
                    affected_product=affected_product,
                )
            )

        logger.info(f"CircleCII: Parsed {len(cves)} total CVEs (all severities - will filter by exploitation)")
        return cves

    def _parse_cves(self, data: dict[str, Any]) -> list[CVERecord]:
        """
        Parse NVD API response into CVERecord objects.

        Returns ALL CVEs regardless of severity - filtering will happen during enrichment
        when we check CISA KEV and threat intelligence for exploitation evidence.

        Args:
            data: Raw API response

        Returns:
            List of CVERecord objects (all severities - exploitation matters more than rating)
        """
        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract CVSS score and severity
            cvss_score, severity = self._extract_cvss(cve)

            # Include ALL severities - we'll filter by exploitation activity later
            # A MEDIUM CVE being actively exploited is more important than a CRITICAL CVE sitting idle

            # Extract description
            description = self._extract_description(cve)

            # Extract affected product from CPE data
            affected_product = self._extract_product_from_cpe(cve) or ""

            # Get published date
            published = cve.get("published", "")

            cves.append(
                CVERecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=published,
                    exploited=False,
                    source=self.source_name,
                    affected_product=affected_product,
                )
            )

        logger.info(f"NVD: Parsed {len(cves)} total CVEs (all severities - will filter by exploitation)")
        return cves

    def _extract_cvss(self, cve: dict[str, Any]) -> tuple:
        """
        Extract CVSS score and severity from CVE metrics.

        Tries CVSS v3.1 first, then v3.0, then v2.0.

        Args:
            cve: CVE object from API response

        Returns:
            Tuple of (cvss_score, severity)
        """
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "UNKNOWN"

        # Try CVSS v3.1 first
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")

        # Then v3.0
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")

        # Finally v2.0
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0)
            # Convert v2 score to severity (v2 doesn't have severity string)
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        return cvss_score, severity

    def _extract_description(self, cve: dict[str, Any]) -> str:
        """
        Extract English description from CVE.

        Args:
            cve: CVE object from API response

        Returns:
            English description or empty string
        """
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""

    @staticmethod
    def _extract_product_from_cpe(cve: dict[str, Any]) -> str:
        """
        Extract vendor and product name from CPE configuration data.

        CPE URIs follow: cpe:2.3:part:vendor:product:version:...
        Returns "Vendor Product" (title-cased) or empty string.
        """
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        if vendor and product and vendor != "*" and product != "*":
                            return f"{vendor} {product}"
        return ""
