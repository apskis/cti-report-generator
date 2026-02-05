"""
Rapid7 collector.

Fetches vulnerability data from Rapid7 InsightVM Cloud API V4.
"""
import logging
from typing import List, Dict, Any

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient, NonRetryableHTTPError
from src.core.config import collector_config
from src.core.models import VulnerabilitySummary, CollectorResult

logger = logging.getLogger(__name__)


class Rapid7Collector(BaseCollector):
    """
    Collector for Rapid7 InsightVM Cloud API V4.

    API Documentation: https://help.rapid7.com/insightvm/en-us/api/integrations.html

    Key implementation notes:
    - Uses POST /vm/v4/integration/vulnerabilities endpoint
    - Region-specific URLs (us, us2, us3, eu, ca, au, ap)
    - API key passed via X-Api-Key header
    """

    # Severity mapping (Rapid7 -> normalized)
    SEVERITY_MAP = {
        "CRITICAL": "Critical",
        "SEVERE": "Severe",
        "HIGH": "Severe",
        "MODERATE": "Moderate",
        "MEDIUM": "Moderate",
        "LOW": "Low"
    }

    @property
    def source_name(self) -> str:
        return "Rapid7"

    @property
    def lookback_days(self) -> int:
        return collector_config.rapid7_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch vulnerability data from Rapid7 InsightVM.

        Returns:
            CollectorResult with vulnerability summary
        """
        api_key = self.credentials.get("rapid7_key", "")
        region = self.credentials.get("rapid7_region", "us")

        if not api_key:
            logger.warning("Rapid7 API key not provided, skipping")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        logger.info(f"Fetching data from Rapid7 InsightVM Cloud API (region: {region})")

        try:
            # Build base URL for the specified region
            base_url = f"https://{region}.api.insight.rapid7.com"

            headers = {
                "X-Api-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            async with HTTPClient() as client:
                summary = await self._fetch_vulnerabilities(client, base_url, headers)

            if summary:
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[summary],
                    record_count=summary.get("critical_severe_count", 0)
                )
            else:
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )

        except NonRetryableHTTPError as e:
            logger.error(f"Rapid7 API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching Rapid7 data: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    async def _fetch_vulnerabilities(
        self,
        client: HTTPClient,
        base_url: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Fetch vulnerabilities from Rapid7.

        Args:
            client: HTTP client
            base_url: Rapid7 API base URL
            headers: Request headers with auth

        Returns:
            Vulnerability summary dictionary
        """
        vuln_url = f"{base_url}/vm/v4/integration/vulnerabilities"

        # Calculate date range
        start_date, _ = self.get_date_range()
        thirty_days_ago = start_date.strftime("%Y-%m-%dT00:00:00Z")

        # Request body with search criteria
        request_body = {
            "vulnerability": f"modified > {thirty_days_ago}"
        }

        # Query parameters for pagination
        params = {
            "size": collector_config.rapid7_max_results,
            "sort": "severity,DESC"
        }

        logger.info(f"Fetching vulnerabilities from: {vuln_url}")
        logger.info(f"Request body: {request_body}")

        try:
            response = await client.post_raw_response(
                vuln_url,
                headers=headers,
                json_data=request_body,
                params=params
            )

            if response.status == 200:
                data = await response.json()
                return self._process_vulnerabilities(data)

            elif response.status == 401:
                logger.error("Rapid7 API authentication failed. Check API key.")
                response_text = await response.text()
                logger.error(f"Rapid7 response: {response_text[:500]}")

            elif response.status == 403:
                logger.error("Rapid7 API access forbidden. Verify API key permissions.")
                response_text = await response.text()
                logger.error(f"Rapid7 response: {response_text[:500]}")

            elif response.status == 400:
                logger.error("Rapid7 API bad request. Check request body format.")
                response_text = await response.text()
                logger.error(f"Rapid7 response: {response_text[:500]}")

            else:
                response_text = await response.text()
                logger.error(f"Rapid7 API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching Rapid7 vulnerabilities: {e}")

        return {}

    def _process_vulnerabilities(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Rapid7 vulnerability data into summary format.

        Args:
            data: Raw API response

        Returns:
            Vulnerability summary dictionary
        """
        vuln_list = data.get("data", [])
        metadata = data.get("metadata", {})

        total_resources = metadata.get("totalResources", 0)
        logger.info(f"Total vulnerabilities available: {total_resources}")
        logger.info(f"Retrieved {len(vuln_list)} vulnerabilities in this page")

        vulnerabilities = []
        all_cve_ids = set()

        for vuln in vuln_list:
            severity = vuln.get("severity", "").upper()
            normalized_severity = self.SEVERITY_MAP.get(severity, severity)

            # Only include Critical and Severe vulnerabilities
            if normalized_severity not in ["Critical", "Severe"]:
                continue

            # Extract CVE IDs
            cve_ids = vuln.get("cves", [])
            all_cve_ids.update(cve_ids)

            # Get CVSS scores
            cvss_v3 = vuln.get("cvss", {}).get("v3", {})
            cvss_v2 = vuln.get("cvss", {}).get("v2", {})
            cvss_score = cvss_v3.get("score", cvss_v2.get("score", 0))

            # Check for exploitability
            exploits_count = self._get_count(vuln.get("exploits", 0))
            malware_kits_count = self._get_count(vuln.get("malwareKits", 0))

            # Extract description
            description = vuln.get("description", {})
            if isinstance(description, dict):
                description_text = description.get("text", "")[:300]
            else:
                description_text = str(description)[:300]

            # Affected asset count (servers/endpoints) for Exposure column in reports
            _raw = vuln.get("affectedAssetCount") or vuln.get("assetCount") or vuln.get("affected_assets")
            try:
                asset_count = int(_raw) if _raw is not None else None
            except (TypeError, ValueError):
                asset_count = None

            vulnerabilities.append({
                "source": self.source_name,
                "vulnerability_id": vuln.get("id", ""),
                "title": vuln.get("title", ""),
                "description": description_text,
                "severity": normalized_severity,
                "cvss_score": cvss_score,
                "cve_ids": cve_ids,
                "exploitable": exploits_count > 0 or malware_kits_count > 0,
                "exploits_count": exploits_count,
                "malware_kits_count": malware_kits_count,
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
                "risk_score": vuln.get("riskScore", 0),
                "categories": vuln.get("categories", []),
                "asset_count": asset_count,
            })

        # Sort by CVSS score descending
        vulnerabilities.sort(
            key=lambda x: (x.get("cvss_score", 0), x.get("exploitable", False)),
            reverse=True
        )

        # Build summary
        summary = {
            "source": self.source_name,
            "total_vulnerabilities_scanned": total_resources,
            "critical_severe_count": len(vulnerabilities),
            "unique_cve_count": len(all_cve_ids),
            "all_cve_ids": list(all_cve_ids),
            "critical_count": sum(1 for v in vulnerabilities if v["severity"] == "Critical"),
            "severe_count": sum(1 for v in vulnerabilities if v["severity"] == "Severe"),
            "exploitable_count": sum(1 for v in vulnerabilities if v.get("exploitable", False)),
            "top_vulnerabilities": vulnerabilities[:25]
        }

        logger.info(f"Processed {len(vulnerabilities)} Critical/Severe vulnerabilities")
        logger.info(f"Found {len(all_cve_ids)} unique CVEs for correlation")

        return summary

    def _get_count(self, value: Any) -> int:
        """
        Get count from a value that could be list or integer.

        Args:
            value: List or integer from API response

        Returns:
            Count as integer
        """
        if isinstance(value, list):
            return len(value)
        elif isinstance(value, int):
            return value
        return 0
