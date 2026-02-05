"""
ThreatQ collector.

Fetches threat indicators and adversaries from ThreatQ threat intelligence platform.

Authentication: OAuth 2.0 (client credentials flow)
API Documentation: https://helpcenter.threatq.com/Developer_Resources/

Key implementation notes:
    OAuth2 client credentials are generated via kubectl command on ThreatQ server:
        kubectl exec --namespace threatq --stdin --tty deployment/api-schedule-run -- \
        ./artisan threatq:oauth2-client --name="Custom Integration" --user_role="Read Only"
    
    Token endpoint: POST /api/token
    Indicators endpoint: GET /api/indicators
    Adversaries endpoint: GET /api/adversaries
"""
import logging
from typing import List, Dict, Any, Optional, Tuple

from collectors.base import BaseCollector
from collectors.http_utils import HTTPClient, NonRetryableHTTPError, validate_url
from config import collector_config
from models import ThreatIndicator, CollectorResult

logger = logging.getLogger(__name__)


class ThreatQCollector(BaseCollector):
    """
    Collector for ThreatQ API.

    Authentication: OAuth 2.0 (client credentials flow)

    Required credentials:
        threatq_url: ThreatQ instance URL (e.g., https://threatq.company.com)
        threatq_client_id: OAuth2 client ID from ThreatQ
        threatq_client_secret: OAuth2 client secret from ThreatQ

    Note: Client credentials are generated on the ThreatQ server using:
        kubectl exec --namespace threatq --stdin --tty deployment/api-schedule-run -- \
        ./artisan threatq:oauth2-client --name="CTI Integration" --user_role="Read Only"
    """

    @property
    def source_name(self) -> str:
        return "ThreatQ"

    @property
    def lookback_days(self) -> int:
        return collector_config.threatq_lookback_days

    @property
    def enabled(self) -> bool:
        """ThreatQ is enabled when URL and OAuth credentials are provided."""
        threatq_url = self.credentials.get("threatq_url", "")
        client_id = self.credentials.get("threatq_client_id", "")
        client_secret = self.credentials.get("threatq_client_secret", "")
        return bool(threatq_url and client_id and client_secret)

    async def collect(self) -> CollectorResult:
        """
        Fetch indicators and adversaries from ThreatQ.

        Returns:
            CollectorResult with indicators and adversaries for correlation
        """
        threatq_url = self.credentials.get("threatq_url", "")
        client_id = self.credentials.get("threatq_client_id", "")
        client_secret = self.credentials.get("threatq_client_secret", "")

        if not threatq_url:
            logger.info("ThreatQ URL not provided, skipping ThreatQ data collection")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        if not client_id or not client_secret:
            logger.warning("ThreatQ OAuth credentials not provided, skipping")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        logger.info("Fetching data from ThreatQ API")

        try:
            threatq_url = validate_url(threatq_url)

            async with HTTPClient() as client:
                access_token = await self._get_oauth_token(
                    client, threatq_url, client_id, client_secret
                )

                if not access_token:
                    return CollectorResult(
                        source=self.source_name,
                        success=False,
                        error="Failed to obtain OAuth token from ThreatQ",
                        record_count=0
                    )

                # Fetch both indicators and adversaries
                indicators = await self._fetch_indicators(
                    client, threatq_url, access_token
                )
                
                adversaries = await self._fetch_adversaries(
                    client, threatq_url, access_token
                )

            # Combine data with type markers for downstream processing
            all_data = []
            for indicator in indicators:
                indicator["data_type"] = "indicator"
                all_data.append(indicator)
            
            for adversary in adversaries:
                adversary["data_type"] = "adversary"
                all_data.append(adversary)

            logger.info(
                f"Retrieved {len(indicators)} indicators and "
                f"{len(adversaries)} adversaries from ThreatQ"
            )
            
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=all_data,
                record_count=len(all_data)
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

    async def _get_oauth_token(
        self,
        client: HTTPClient,
        base_url: str,
        client_id: str,
        client_secret: str
    ) -> Optional[str]:
        """
        Obtain OAuth2 access token from ThreatQ using client credentials flow.

        ThreatQ OAuth2 token endpoint accepts credentials via query params:
            POST /api/token?grant_type=client_credentials&client_id=X&client_secret=Y

        Args:
            client: HTTP client
            base_url: ThreatQ instance URL
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret

        Returns:
            Access token string or None on failure
        """
        token_url = f"{base_url}/api/token"
        params = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }

        logger.info(f"Requesting OAuth token from ThreatQ: {token_url}")

        try:
            response = await client.post_raw_response(token_url, params=params)

            if response.status in (200, 201):
                token_response = await response.json()
                access_token = token_response.get("access_token")

                if access_token:
                    logger.info("Successfully obtained ThreatQ access token")
                    return access_token
                else:
                    logger.error("ThreatQ token response missing access_token field")
                    logger.debug(f"Token response keys: {list(token_response.keys())}")
            else:
                response_text = await response.text()
                logger.error(
                    f"ThreatQ OAuth token request failed with status {response.status}: "
                    f"{response_text[:500]}"
                )

        except Exception as e:
            logger.error(f"Error obtaining ThreatQ OAuth token: {e}")

        return None

    async def _fetch_indicators(
        self,
        client: HTTPClient,
        base_url: str,
        access_token: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch high priority indicators from ThreatQ.

        API endpoint: GET /api/indicators
        Query parameters:
            limit: Maximum records to retrieve
            sort: Field to sort by (prefix with minus for descending)
            with: Related objects to include

        Args:
            client: HTTP client
            base_url: ThreatQ instance URL
            access_token: OAuth2 access token

        Returns:
            List of indicator dictionaries
        """
        indicators_url = f"{base_url}/api/indicators"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        params = {
            "limit": collector_config.threatq_indicators_limit,
            "sort": "-score",
            "with": "score,status,type,sources"
        }

        indicators: List[Dict[str, Any]] = []

        try:
            response = await client.get_raw_response(
                indicators_url, headers=headers, params=params
            )

            if response.status == 200:
                data = await response.json()
                raw_indicators = data.get("data", [])

                for indicator in raw_indicators:
                    score = self._extract_score(indicator)

                    if score >= collector_config.threatq_min_score:
                        indicators.append(self._parse_indicator(indicator))

                logger.info(
                    f"Retrieved {len(raw_indicators)} total indicators, "
                    f"{len(indicators)} meet minimum score threshold"
                )
            elif response.status == 401:
                logger.error("ThreatQ authentication failed, token may have expired")
            else:
                response_text = await response.text()
                logger.error(
                    f"ThreatQ indicators request failed with status {response.status}: "
                    f"{response_text[:500]}"
                )

        except Exception as e:
            logger.error(f"Error fetching ThreatQ indicators: {e}")

        return indicators

    def _extract_score(self, indicator: Dict[str, Any]) -> int:
        """
        Extract score value from indicator, handling nested structures.

        ThreatQ may return score as:
            Integer: 8
            Dict: {"generated_score": 8, "manual_score": null}

        Args:
            indicator: Raw indicator dictionary

        Returns:
            Integer score value
        """
        score = indicator.get("score", 0)

        if isinstance(score, dict):
            manual = score.get("manual_score")
            generated = score.get("generated_score", 0)
            return manual if manual is not None else (generated or 0)

        return score if isinstance(score, int) else 0

    def _parse_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse ThreatQ indicator into standardized format.

        Args:
            indicator: Raw indicator from API

        Returns:
            Standardized indicator dictionary
        """
        indicator_type = indicator.get("type", {})
        type_name = "Unknown"
        if isinstance(indicator_type, dict):
            type_name = indicator_type.get("name", "Unknown")
        elif isinstance(indicator_type, str):
            type_name = indicator_type

        status = indicator.get("status", {})
        status_name = "Unknown"
        if isinstance(status, dict):
            status_name = status.get("name", "Unknown")
        elif isinstance(status, str):
            status_name = status

        score = self._extract_score(indicator)

        sources = indicator.get("sources", [])
        source_names = []
        if isinstance(sources, list):
            for src in sources:
                if isinstance(src, dict):
                    name = src.get("name", "")
                    if name:
                        source_names.append(name)

        return {
            "id": indicator.get("id"),
            "indicator_type": type_name,
            "status": status_name,
            "score": score,
            "value": indicator.get("value", ""),
            "last_seen": indicator.get("updated_at", ""),
            "created_at": indicator.get("created_at", ""),
            "source": self.source_name,
            "threatq_sources": source_names,
            "class": indicator.get("class", ""),
            "hash": indicator.get("hash", "")
        }

    async def _fetch_adversaries(
        self,
        client: HTTPClient,
        base_url: str,
        access_token: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch adversaries from ThreatQ with their linked indicators.

        API endpoint: GET /api/adversaries
        
        The ?with=indicators parameter returns indicator objects linked
        to each adversary, enabling IOC correlation.

        Args:
            client: HTTP client
            base_url: ThreatQ instance URL
            access_token: OAuth2 access token

        Returns:
            List of adversary dictionaries with indicator_ids for correlation
        """
        adversaries_url = f"{base_url}/api/adversaries"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        params = {
            "limit": 100,
            "with": "indicators,tags"
        }

        adversaries: List[Dict[str, Any]] = []

        try:
            response = await client.get_raw_response(
                adversaries_url, headers=headers, params=params
            )

            if response.status == 200:
                data = await response.json()
                raw_adversaries = data.get("data", [])

                for adversary in raw_adversaries:
                    adversaries.append(self._parse_adversary(adversary))

                logger.info(f"Retrieved {len(adversaries)} adversaries from ThreatQ")
            else:
                response_text = await response.text()
                logger.error(
                    f"ThreatQ adversaries request failed with status {response.status}: "
                    f"{response_text[:500]}"
                )

        except Exception as e:
            logger.error(f"Error fetching ThreatQ adversaries: {e}")

        return adversaries

    def _parse_adversary(self, adversary: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse ThreatQ adversary into standardized format.
        
        Extracts linked indicator IDs for correlation with IOC data.

        Args:
            adversary: Raw adversary from API

        Returns:
            Standardized adversary dictionary with indicator_ids
        """
        tags = adversary.get("tags", [])
        tag_names = []
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict):
                    name = tag.get("name", "")
                    if name:
                        tag_names.append(name)

        # Extract linked indicator IDs for correlation
        indicators = adversary.get("indicators", [])
        indicator_ids = []
        if isinstance(indicators, list):
            for ind in indicators:
                if isinstance(ind, dict):
                    ind_id = ind.get("id")
                    if ind_id:
                        indicator_ids.append(ind_id)
                elif isinstance(ind, (int, str)):
                    indicator_ids.append(ind)

        return {
            "id": adversary.get("id"),
            "name": adversary.get("name", "Unknown"),
            "description": adversary.get("description", ""),
            "tags": tag_names,
            "indicator_ids": indicator_ids,
            "indicator_count": len(indicator_ids),
            "event_count": len(adversary.get("events", [])),
            "updated_at": adversary.get("updated_at", ""),
            "source": self.source_name,
            "data_type": "adversary"
        }

    async def _fetch_events(
        self,
        client: HTTPClient,
        base_url: str,
        access_token: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from ThreatQ.

        API endpoint: GET /api/events

        Args:
            client: HTTP client
            base_url: ThreatQ instance URL
            access_token: OAuth2 access token

        Returns:
            List of event dictionaries
        """
        events_url = f"{base_url}/api/events"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        params = {
            "limit": 50,
            "sort": "-created_at",
            "with": "type,indicators"
        }

        events: List[Dict[str, Any]] = []

        try:
            response = await client.get_raw_response(
                events_url, headers=headers, params=params
            )

            if response.status == 200:
                data = await response.json()
                raw_events = data.get("data", [])

                for event in raw_events:
                    events.append(self._parse_event(event))

                logger.info(f"Retrieved {len(events)} events from ThreatQ")
            else:
                response_text = await response.text()
                logger.error(
                    f"ThreatQ events request failed with status {response.status}: "
                    f"{response_text[:500]}"
                )

        except Exception as e:
            logger.error(f"Error fetching ThreatQ events: {e}")

        return events

    def _parse_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse ThreatQ event into standardized format.

        Args:
            event: Raw event from API

        Returns:
            Standardized event dictionary
        """
        event_type = event.get("type", {})
        type_name = "Unknown"
        if isinstance(event_type, dict):
            type_name = event_type.get("name", "Unknown")
        elif isinstance(event_type, str):
            type_name = event_type

        return {
            "id": event.get("id"),
            "title": event.get("title", ""),
            "description": event.get("description", ""),
            "type": type_name,
            "happened_at": event.get("happened_at", ""),
            "indicator_count": len(event.get("indicators", [])),
            "updated_at": event.get("updated_at", ""),
            "source": self.source_name,
            "data_type": "event"
        }


def separate_threatq_data(
    threatq_data: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Utility function to separate ThreatQ collector data into indicators and adversaries.
    
    The collector returns both types in a single list with data_type markers.
    This function splits them for use with the IOCCorrelator.
    
    Args:
        threatq_data: Combined data from ThreatQ collector
        
    Returns:
        Tuple of (indicators, adversaries)
    """
    indicators = [d for d in threatq_data if d.get("data_type") == "indicator"]
    adversaries = [d for d in threatq_data if d.get("data_type") == "adversary"]
    return indicators, adversaries
