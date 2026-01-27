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
        """Get lookback days based on report type."""
        if self.report_type == "quarterly":
            return collector_config.intel471_quarterly_lookback_days
        return collector_config.intel471_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch threat intelligence from Intel471.

        For quarterly reports: Fetches all report types (BREACH ALERT, SPOT REPORT,
        SITUATION REPORT, MALWARE REPORT) going back 90 days. OpenAI will filter by industry.
        
        For weekly reports: Fetches reports with keyword filtering.

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
                if report_type == "quarterly":
                    # For quarterly: Fetch all report types (breach, spot, situation, malware)
                    # No keyword filtering - let OpenAI filter by industry
                    all_reports = await self._fetch_all_report_types(client, auth, start_date, end_date)
                    threats.extend(all_reports)
                else:
                    # For weekly: Fetch reports with keyword filtering
                    reports = await self._fetch_reports(client, auth, start_date, end_date)
                    threats.extend(reports)

                    # Fetch breach alerts (important even if not biotech-specific)
                    breach_alerts = await self._fetch_breach_alerts(client, auth, start_date, end_date)
                    threats.extend(breach_alerts)

                # Fetch indicators (for both weekly and quarterly)
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
                    # For quarterly reports, include all reports (OpenAI will filter by industry)
                    # For weekly reports, filter by biotech keywords
                    if self.report_type != "quarterly":
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

    async def _fetch_all_report_types(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fetch all report types for quarterly reports: BREACH ALERT, SPOT REPORT,
        SITUATION REPORT, and MALWARE REPORT.

        No keyword filtering - OpenAI will filter by industry/sector.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of all report dictionaries
        """
        reports_url = f"{self.BASE_URL}/reports"

        # Document types to fetch for quarterly reports
        document_types = [
            "BREACH ALERT",
            "SPOT REPORT",
            "SITUATION REPORT",
            "MALWARE REPORT"
        ]

        all_threats = []
        limit = collector_config.intel471_quarterly_reports_limit

        # Fetch each document type
        for doc_type in document_types:
            params = {
                "from": self.format_date_timestamp_ms(start_date),
                "until": self.format_date_timestamp_ms(end_date),
                "count": limit,  # Fetch up to limit per type
                "v": self.API_VERSION,
                "documentType": doc_type
            }

            try:
                response = await client.get_raw_response(reports_url, auth=auth, params=params)

                if response.status == 200:
                    data = await response.json()
                    reports = data.get("reports", [])

                    for report in reports:
                        threat = self._parse_report(report)
                        # Ensure threat_type reflects the document type
                        threat["threat_type"] = doc_type
                        all_threats.append(threat)

                    logger.info(f"Retrieved {len(reports)} {doc_type} reports from Intel471")
                else:
                    # If documentType parameter doesn't work, fetch all and filter client-side
                    logger.info(f"documentType parameter not working for {doc_type}, fetching all and filtering...")
                    all_reports = await self._fetch_all_reports_and_filter(client, auth, start_date, end_date, doc_type)
                    all_threats.extend(all_reports)

            except Exception as e:
                logger.warning(f"Error fetching {doc_type} reports: {e}")
                # Fallback: fetch all and filter client-side
                all_reports = await self._fetch_all_reports_and_filter(client, auth, start_date, end_date, doc_type)
                all_threats.extend(all_reports)

        logger.info(f"Retrieved {len(all_threats)} total reports (all types) from Intel471 for quarterly report")
        return all_threats

    async def _fetch_all_reports_and_filter(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime,
        target_doc_type: str
    ) -> List[Dict[str, Any]]:
        """
        Fallback: Fetch all reports and filter by documentType client-side.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range
            target_doc_type: Document type to filter for

        Returns:
            List of filtered report dictionaries
        """
        reports_url = f"{self.BASE_URL}/reports"

        params = {
            "from": self.format_date_timestamp_ms(start_date),
            "until": self.format_date_timestamp_ms(end_date),
            "count": collector_config.intel471_quarterly_reports_limit * 2,  # Fetch more to account for filtering
            "v": self.API_VERSION
        }

        threats = []

        try:
            response = await client.get_raw_response(reports_url, auth=auth, params=params)

            if response.status == 200:
                data = await response.json()

                for report in data.get("reports", []):
                    document_type = report.get("documentType", "").upper()
                    if document_type == target_doc_type.upper():
                        threat = self._parse_report(report)
                        threat["threat_type"] = target_doc_type
                        threats.append(threat)

                logger.info(f"Retrieved {len(threats)} {target_doc_type} reports (client-side filtered)")
            else:
                response_text = await response.text()
                logger.warning(f"Intel471 reports API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.warning(f"Error fetching and filtering reports: {e}")

        return threats

    async def _fetch_breach_alerts(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fetch breach alerts from Intel471.

        Breach alerts are important for threat intelligence even if they don't
        specifically mention biotech keywords. We include all breach alerts
        targeting relevant industries.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of breach alert dictionaries
        """
        alerts_url = f"{self.BASE_URL}/alerts"

        # CRITICAL: Intel471 uses MILLISECONDS
        params = {
            "from": self.format_date_timestamp_ms(start_date),
            "until": self.format_date_timestamp_ms(end_date),
            "count": collector_config.intel471_breach_alerts_limit,
            "v": self.API_VERSION,
            "documentType": "BREACH ALERT"  # Filter for breach alerts specifically
        }

        threats = []

        try:
            response = await client.get_raw_response(alerts_url, auth=auth, params=params)

            if response.status == 200:
                data = await response.json()

                for alert in data.get("alerts", []):
                    # For breach alerts, we're less restrictive - include if:
                    # 1. It mentions biotech keywords, OR
                    # 2. It targets relevant industries (manufacturing, healthcare, etc.)
                    subject = alert.get("subject", "").lower()
                    tags = alert.get("tags", [])
                    document_type = alert.get("documentType", "").upper()

                    # Always include breach alerts - they're important threat intelligence
                    # even if not directly biotech-related
                    is_breach = "BREACH" in document_type or "breach" in subject

                    if is_breach or self._is_relevant_biotech(subject, tags):
                        threat = self._parse_report(alert)  # Breach alerts use same format as reports
                        threat["threat_type"] = "Breach Alert"  # Mark as breach
                        threats.append(threat)

                logger.info(f"Retrieved {len(threats)} breach alerts from Intel471")
            else:
                response_text = await response.text()
                logger.warning(f"Intel471 alerts API returned status {response.status}: {response_text[:500]}")
                # If alerts endpoint doesn't work, try fetching from reports with documentType filter
                logger.info("Attempting to fetch breach alerts from reports endpoint...")
                return await self._fetch_breach_alerts_from_reports(client, auth, start_date, end_date)

        except Exception as e:
            logger.warning(f"Error fetching Intel471 breach alerts: {e}")
            # Fallback: try fetching from reports endpoint
            logger.info("Attempting to fetch breach alerts from reports endpoint as fallback...")
            return await self._fetch_breach_alerts_from_reports(client, auth, start_date, end_date)

        return threats

    async def _fetch_breach_alerts_from_reports(
        self,
        client: HTTPClient,
        auth: aiohttp.BasicAuth,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fallback method to fetch breach alerts from reports endpoint.

        Some Intel471 API versions may not have a separate alerts endpoint,
        so we query the reports endpoint and filter client-side for breach alerts.

        Args:
            client: HTTP client
            auth: Basic auth credentials
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of breach alert dictionaries
        """
        reports_url = f"{self.BASE_URL}/reports"

        # Try with documentType filter first
        params_with_filter = {
            "from": self.format_date_timestamp_ms(start_date),
            "until": self.format_date_timestamp_ms(end_date),
            "count": collector_config.intel471_breach_alerts_limit,
            "v": self.API_VERSION,
            "documentType": "BREACH ALERT"
        }

        threats = []

        try:
            # First try with documentType filter
            response = await client.get_raw_response(reports_url, auth=auth, params=params_with_filter)

            if response.status == 200:
                data = await response.json()
                reports = data.get("reports", [])
            else:
                # If documentType parameter doesn't work, fetch all reports and filter client-side
                logger.info("documentType parameter not supported, fetching all reports and filtering client-side...")
                params_no_filter = {
                    "from": self.format_date_timestamp_ms(start_date),
                    "until": self.format_date_timestamp_ms(end_date),
                    "count": collector_config.intel471_breach_alerts_limit * 2,  # Fetch more to account for filtering
                    "v": self.API_VERSION
                }
                response = await client.get_raw_response(reports_url, auth=auth, params=params_no_filter)
                if response.status == 200:
                    data = await response.json()
                    reports = data.get("reports", [])
                else:
                    response_text = await response.text()
                    logger.warning(f"Intel471 reports API returned status {response.status}: {response_text[:500]}")
                    return threats

            # Filter for breach alerts
            for report in reports:
                document_type = report.get("documentType", "").upper()
                subject = report.get("subject", "").lower()
                tags = report.get("tags", [])

                # Check if this is a breach alert
                is_breach = (
                    "BREACH" in document_type or
                    "breach" in subject or
                    any("breach" in str(tag).lower() for tag in tags)
                )

                if is_breach:
                    # For breach alerts, include all of them - they're important threat intelligence
                    # even if not biotech-specific
                    threat = self._parse_report(report)
                    threat["threat_type"] = "Breach Alert"
                    threats.append(threat)

            logger.info(f"Retrieved {len(threats)} breach alerts from Intel471 reports endpoint")

        except Exception as e:
            logger.warning(f"Error fetching breach alerts from reports endpoint: {e}")

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
