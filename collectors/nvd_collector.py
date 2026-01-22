"""
NVD (National Vulnerability Database) collector.

Fetches CVE vulnerability data from the NIST NVD API.
"""
import logging
from typing import List, Dict, Any

from collectors.base import BaseCollector
from collectors.http_utils import HTTPClient, NonRetryableHTTPError
from config import collector_config
from models import CVERecord, CollectorResult

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

    async def collect(self) -> CollectorResult:
        """
        Fetch CVEs from NVD API (CRITICAL and HIGH severity only).

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
                "resultsPerPage": collector_config.nvd_max_results
            }

            headers = {}
            if api_key:
                headers["apiKey"] = api_key

            async with HTTPClient() as client:
                data = await client.get(
                    self.NVD_API_URL,
                    params=params,
                    headers=headers if headers else None
                )

                cves = self._parse_cves(data)

                logger.info(f"Retrieved {len(cves)} CRITICAL/HIGH CVEs from NVD")
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[cve.to_dict() for cve in cves],
                    record_count=len(cves)
                )

        except NonRetryableHTTPError as e:
            logger.error(f"NVD API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching NVD CVEs: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    def _parse_cves(self, data: Dict[str, Any]) -> List[CVERecord]:
        """
        Parse NVD API response into CVERecord objects.

        Args:
            data: Raw API response

        Returns:
            List of CVERecord objects (CRITICAL and HIGH only)
        """
        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract CVSS score and severity
            cvss_score, severity = self._extract_cvss(cve)

            # Only include CRITICAL and HIGH severity
            if severity not in ["CRITICAL", "HIGH"]:
                continue

            # Extract description
            description = self._extract_description(cve)

            # Get published date
            published = cve.get("published", "")

            cves.append(CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published,
                exploited=False,  # Could cross-reference with CISA KEV
                source=self.source_name
            ))

        return cves

    def _extract_cvss(self, cve: Dict[str, Any]) -> tuple:
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

    def _extract_description(self, cve: Dict[str, Any]) -> str:
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
