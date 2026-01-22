"""
Intel471 collector.

Fetches threat intelligence reports and indicators from Intel471 Titan API.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any

import aiohttp  # type: ignore

from collectors.base import BaseCollector
from collectors.http_utils import HTTPClient, NonRetryableHTTPError
from config import collector_config, industry_filter_config
from models import ThreatReport, CollectorResult

logger = logging.getLogger(__name__)


# Admiralty code to confidence level mapping
ADMIRALTY_CONFIDENCE_MAP = {
    "A": "Confirmed",
    "B": "High",
    "C": "Medium",
    "D": "Low",
    "E": "Very Low",
    "F": "Cannot be judged"
}


class Intel471Collector(BaseCollector):
    """
    Collector for Intel471 Titan API.

    API Documentation: Intel471 Titan API v1.20.0
    Authentication: Basic Auth (email + API key)

    Key implementation notes:
    - Timestamps must be in MILLISECONDS (multiply by 1000)
    - Alternative: use string format like "7day"
    - Field names differ from typical APIs (subject vs title, etc.)
    """

    BASE_URL = "https://api.intel471.com/v1"
    API_VERSION = "1.20.0"

    @property
    def source_name(self) -> str:
        return "Intel471"

    @property
    def lookback_days(self) -> int:
        return collector_config.intel471_lookback_days

    async def collect(self) -> CollectorResult:
        """
        Fetch threat intelligence from Intel471.

        Collects both reports and indicators, filtered for biotech relevance.

        Returns:
            CollectorResult with list of threat reports and indicators
        """
        logger.info("Fetching data from Intel471 API")

        try:
            email = self.credentials.get("intel471_email", "")
            api_key = self.credentials.get("intel471_key", "")

            if not email or not api_key:
                logger.warning("Intel471 credentials not provided, skipping")
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )

            # Calculate date range
            start_date, end_date = self.get_date_range()

            auth = aiohttp.BasicAuth(email, api_key)
            threats: List[Dict[str, Any]] = []

            async with HTTPClient() as client:
                # Fetch reports
                reports = await self._fetch_reports(client, auth, start_date, end_date)
                threats.extend(reports)

                # Fetch indicators
                indicators = await self._fetch_indicators(client, auth, start_date, end_date)
                threats.extend(indicators)

            logger.info(f"Retrieved {len(threats)} total items from Intel471")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=threats,
                record_count=len(threats)
            )

        except NonRetryableHTTPError as e:
            logger.error(f"Intel471 API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching Intel471 data: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    async def _fetch_reports(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fetch threat reports from Intel471.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of report dictionaries
        """
        reports_url = f"{self.BASE_URL}/reports"

        # CRITICAL: Intel471 uses MILLISECONDS
        params = {
            "from": self.format_date_timestamp_ms(start_date),
            "until": self.format_date_timestamp_ms(end_date),
            "count": collector_config.intel471_reports_limit,
            "v": self.API_VERSION
        }

        threats = []

        try:
            response = await client.get_raw_response(reports_url, auth=auth, params=params)

            if response.status == 200:
                data = await response.json()

                for report in data.get("reports", []):
                    # Check relevance to biotech/healthcare
                    subject = report.get("subject", "").lower()
                    tags = report.get("tags", [])

                    if not self._is_relevant_biotech(subject, tags):
                        continue

                    threat = self._parse_report(report)
                    threats.append(threat)

                logger.info(f"Retrieved {len(threats)} relevant items from Intel471 reports")
            else:
                response_text = await response.text()
                logger.error(f"Intel471 reports API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching Intel471 reports: {e}")

        return threats

    async def _fetch_indicators(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fetch threat indicators from Intel471.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of indicator dictionaries
        """
        indicators_url = f"{self.BASE_URL}/indicators"

        params = {
            "from": self.format_date_timestamp_ms(start_date),
            "until": self.format_date_timestamp_ms(end_date),
            "count": collector_config.intel471_indicators_limit,
            "v": self.API_VERSION
        }

        threats = []

        try:
            response = await client.get_raw_response(indicators_url, auth=auth, params=params)

            if response.status == 200:
                data = await response.json()

                for indicator in data.get("indicators", []):
                    threat = self._parse_indicator(indicator)
                    threats.append(threat)

                logger.info(f"Retrieved {len(threats)} indicators from Intel471")
            else:
                response_text = await response.text()
                logger.error(f"Intel471 indicators API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching Intel471 indicators: {e}")

        return threats

    def _parse_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Intel471 report into standardized format.

        Field mapping (Intel471 -> standard):
        - subject -> summary
        - actorHandle -> threat_actor
        - documentType -> threat_type
        - admiraltyCode -> confidence

        Args:
            report: Raw report from API

        Returns:
            Standardized report dictionary
        """
        # Extract actor handle
        actor_handle = report.get("actorHandle", "Unknown")
        actor_subjects = report.get("actorSubjectOfReport", [])
        if actor_subjects and actor_handle == "Unknown":
            actor_handle = actor_subjects[0].get("handle", "Unknown")

        # Convert timestamp from milliseconds to ISO format
        created_ms = report.get("created", 0)
        created_date = ""
        if created_ms:
            created_date = datetime.fromtimestamp(created_ms / 1000).isoformat()

        # Map admiralty code to confidence level
        admiralty = report.get("admiraltyCode", "")
        confidence = ADMIRALTY_CONFIDENCE_MAP.get(
            admiralty[:1] if admiralty else "",
            "Medium"
        )

        return {
            "source": self.source_name,
            "threat_actor": actor_handle,
            "threat_type": report.get("documentType", "Report"),
            "confidence": confidence,
            "summary": report.get("subject", "")[:500],
            "date": created_date,
            "tags": report.get("tags", []),
            "motivation": report.get("motivation", []),
            "portal_url": report.get("portalReportUrl", ""),
            "uid": report.get("uid", "")
        }

    def _parse_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Intel471 indicator into standardized format.

        Note: Indicators have nested "data" structure.

        Args:
            indicator: Raw indicator from API

        Returns:
            Standardized indicator dictionary
        """
        indicator_data = indicator.get("data", {})
        threat_info = indicator_data.get("threat", {})
        threat_data = threat_info.get("data", {})

        # Get indicator details
        indicator_type = indicator_data.get("indicator_type", "Unknown")
        indicator_values = indicator_data.get("indicator_data", {})

        # Extract the actual indicator value based on type
        value = self._extract_indicator_value(indicator_type, indicator_values)

        # Get last updated timestamp (in milliseconds)
        last_updated_ms = indicator.get("last_updated", 0)
        last_updated_date = ""
        if last_updated_ms:
            last_updated_date = datetime.fromtimestamp(last_updated_ms / 1000).isoformat()

        # Get malware family from threat data
        malware_family = threat_data.get("family", "Unknown")

        return {
            "source": self.source_name,
            "threat_actor": malware_family,
            "threat_type": f"Indicator ({indicator_type})",
            "confidence": indicator_data.get("confidence", "Medium"),
            "summary": f"{indicator_type.upper()}: {value}",
            "date": last_updated_date,
            "mitre_tactics": indicator_data.get("mitre_tactics", ""),
            "indicator_uid": indicator.get("uid", "")
        }

    def _extract_indicator_value(
        self,
        indicator_type: str,
        indicator_values: Dict[str, Any]
    ) -> str:
        """
        Extract indicator value based on type.

        Args:
            indicator_type: Type of indicator (url, file, ipv4, domain, etc.)
            indicator_values: Dictionary containing indicator values

        Returns:
            Extracted indicator value
        """
        type_to_field = {
            "url": "url",
            "file": ["md5", "sha256"],
            "ipv4": "ipv4",
            "domain": "domain"
        }

        field = type_to_field.get(indicator_type)

        if isinstance(field, list):
            # Try multiple fields (e.g., md5 then sha256)
            for f in field:
                if f in indicator_values:
                    return indicator_values[f]
        elif field and field in indicator_values:
            return indicator_values[field]

        # Fallback
        return str(indicator_values)[:100] if indicator_values else ""
