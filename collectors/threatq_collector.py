"""
ThreatQ collector.

Fetches threat indicators from ThreatQ threat intelligence platform.
"""
import logging
from typing import List, Dict, Any

from collectors.base import BaseCollector
from collectors.http_utils import HTTPClient, NonRetryableHTTPError, validate_url
from config import collector_config
from models import ThreatIndicator, CollectorResult

logger = logging.getLogger(__name__)


class ThreatQCollector(BaseCollector):
    """
    Collector for ThreatQ API.

    Authentication: Bearer token

    Note: ThreatQ is marked as not fully working yet.
    This implementation provides the structure for when it's ready.
    """

    @property
    def source_name(self) -> str:
        return "ThreatQ"

    @property
    def lookback_days(self) -> int:
        return collector_config.threatq_lookback_days

    @property
    def enabled(self) -> bool:
        """ThreatQ is disabled until API access is working."""
        threatq_url = self.credentials.get("threatq_url", "")
        # Only enable if URL is provided
        return bool(threatq_url)

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch indicators from ThreatQ.

        Returns:
            CollectorResult with list of high-score indicators
        """
        threatq_url = self.credentials.get("threatq_url", "")

        if not threatq_url:
            logger.info("ThreatQ URL not provided, skipping ThreatQ data collection")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        logger.info("Fetching data from ThreatQ API")

        try:
            api_key = self.credentials.get("threatq_key", "")

            if not api_key:
                logger.warning("ThreatQ API key not provided, skipping")
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )

            # Validate and sanitize URL
            threatq_url = validate_url(threatq_url)
            api_url = f"{threatq_url}/api"

            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }

            async with HTTPClient() as client:
                indicators = await self._fetch_indicators(client, api_url, headers)

            logger.info(f"Retrieved {len(indicators)} high-priority indicators from ThreatQ")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=indicators,
                record_count=len(indicators)
            )

        except NonRetryableHTTPError as e:
            logger.error(f"ThreatQ API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching ThreatQ data: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    async def _fetch_indicators(
        self,
        client: HTTPClient,
        api_url: str,
        headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Fetch high-priority indicators from ThreatQ.

        Args:
            client: HTTP client
            api_url: ThreatQ API base URL
            headers: Request headers with auth

        Returns:
            List of indicator dictionaries
        """
        indicators_url = f"{api_url}/indicators"
        params = {
            "limit": collector_config.threatq_indicators_limit,
            "status": "Active",
            "sort": "-score"
        }

        indicators = []

        try:
            response = await client.get_raw_response(indicators_url, headers=headers, params=params)

            if response.status == 200:
                data = await response.json()

                for indicator in data.get("data", []):
                    score = indicator.get("score", 0)

                    # Only include high-score indicators
                    if score >= collector_config.threatq_min_score:
                        indicators.append(self._parse_indicator(indicator))

                logger.info(f"Retrieved {len(indicators)} high-priority indicators from ThreatQ")
            else:
                response_text = await response.text()
                logger.error(f"ThreatQ API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching ThreatQ indicators: {e}")

        return indicators

    def _parse_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse ThreatQ indicator into standardized format.

        Args:
            indicator: Raw indicator from API

        Returns:
            Standardized indicator dictionary
        """
        # Extract nested type and status names
        indicator_type = indicator.get("type", {})
        type_name = indicator_type.get("name", "Unknown") if isinstance(indicator_type, dict) else "Unknown"

        status = indicator.get("status", {})
        status_name = status.get("name", "Unknown") if isinstance(status, dict) else "Unknown"

        return {
            "indicator_type": type_name,
            "status": status_name,
            "score": indicator.get("score", 0),
            "value": indicator.get("value", ""),
            "last_seen": indicator.get("updated_at", ""),
            "source": self.source_name
        }
