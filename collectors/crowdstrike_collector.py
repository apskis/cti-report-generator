"""
CrowdStrike collector.

Fetches APT intelligence from CrowdStrike Falcon Intelligence API.
"""
import logging
from typing import List, Dict, Any, Optional

from collectors.base import BaseCollector
from collectors.http_utils import HTTPClient, NonRetryableHTTPError, validate_url
from config import collector_config, industry_filter_config
from models import APTActor, CollectorResult

logger = logging.getLogger(__name__)


class CrowdStrikeCollector(BaseCollector):
    """
    Collector for CrowdStrike Falcon Intelligence API.

    Authentication: OAuth2 (client credentials flow)

    Key implementation notes:
    - OAuth token endpoint returns 201 on success (not 200)
    - Base URL varies by region (US, EU, etc.)
    - Token should be cached for multiple requests (within session)
    """

    DEFAULT_BASE_URL = "https://api.crowdstrike.com"

    @property
    def source_name(self) -> str:
        return "CrowdStrike"

    @property
    def lookback_days(self) -> int:
        return collector_config.crowdstrike_lookback_days

    async def collect(self) -> CollectorResult:
        """
        Fetch APT intelligence from CrowdStrike.

        Returns:
            CollectorResult with list of APT actors and indicators
        """
        logger.info("Fetching data from CrowdStrike API")

        try:
            client_id = self.credentials.get("crowdstrike_id", "")
            client_secret = self.credentials.get("crowdstrike_secret", "")
            base_url = self.credentials.get("crowdstrike_base_url", self.DEFAULT_BASE_URL)

            if not client_id or not client_secret:
                logger.warning("CrowdStrike credentials not provided, skipping")
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )

            # Validate and sanitize base URL
            base_url = validate_url(base_url)

            async with HTTPClient() as client:
                # Step 1: Get OAuth2 token
                access_token = await self._get_oauth_token(client, base_url, client_id, client_secret)

                if not access_token:
                    return CollectorResult(
                        source=self.source_name,
                        success=False,
                        error="Failed to obtain OAuth token",
                        record_count=0
                    )

                apt_data: List[Dict[str, Any]] = []

                # Step 2: Fetch actors
                actors = await self._fetch_actors(client, base_url, access_token)
                apt_data.extend(actors)

                # Step 3: Fetch indicators
                indicators = await self._fetch_indicators(client, base_url, access_token)
                apt_data.extend(indicators)

            logger.info(f"Retrieved {len(apt_data)} total items from CrowdStrike")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=apt_data,
                record_count=len(apt_data)
            )

        except NonRetryableHTTPError as e:
            logger.error(f"CrowdStrike API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching CrowdStrike data: {e}", exc_info=True)
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
        Obtain OAuth2 access token from CrowdStrike.

        Note: CrowdStrike returns 201 for successful token requests.

        Args:
            client: HTTP client
            base_url: CrowdStrike API base URL
            client_id: OAuth client ID
            client_secret: OAuth client secret

        Returns:
            Access token string or None on failure
        """
        token_url = f"{base_url}/oauth2/token"
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret
        }

        logger.info(f"Requesting OAuth token from: {token_url}")

        try:
            # CrowdStrike returns 201 on success, but some implementations return 200
            response = await client.post_raw_response(token_url, data=token_data)

            if response.status in (200, 201):
                token_response = await response.json()
                access_token = token_response.get("access_token")

                if access_token:
                    logger.info("Successfully obtained CrowdStrike access token")
                    return access_token
                else:
                    logger.error("Token response missing access_token field")
            else:
                response_text = await response.text()
                logger.error(f"OAuth token request failed with status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error obtaining OAuth token: {e}")

        return None

    async def _fetch_actors(
        self,
        client: HTTPClient,
        base_url: str,
        access_token: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch threat actors from CrowdStrike.

        Args:
            client: HTTP client
            base_url: CrowdStrike API base URL
            access_token: OAuth access token

        Returns:
            List of actor dictionaries
        """
        actors_url = f"{base_url}/intel/combined/actors/v1"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        params = {
            "limit": collector_config.crowdstrike_actors_limit,
            "sort": "last_modified_date.desc"
        }

        apt_data = []

        try:
            logger.info(f"Fetching actors from: {actors_url}")
            response = await client.get_raw_response(actors_url, headers=headers, params=params)

            if response.status == 200:
                actors = await response.json()

                for actor in actors.get("resources", []):
                    target_industries_raw = actor.get("target_industries", [])

                    # Extract industry names - API returns list of dicts like {"slug": "...", "value": "..."}
                    target_industries = self._extract_industry_names(target_industries_raw)

                    # Filter for relevant industries
                    # Include if relevant OR if no industry specified (conservative approach)
                    relevant = self._is_relevant_industry(target_industries)

                    if relevant or not target_industries:
                        apt_data.append(self._parse_actor(actor))

                logger.info(f"Retrieved {len(apt_data)} actors from CrowdStrike")
            else:
                response_text = await response.text()
                logger.error(f"CrowdStrike actors API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching CrowdStrike actors: {e}")

        return apt_data

    async def _fetch_indicators(
        self,
        client: HTTPClient,
        base_url: str,
        access_token: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch threat indicators from CrowdStrike.

        Args:
            client: HTTP client
            base_url: CrowdStrike API base URL
            access_token: OAuth access token

        Returns:
            List of indicator dictionaries
        """
        indicators_url = f"{base_url}/intel/combined/indicators/v1"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        params = {
            "limit": collector_config.crowdstrike_indicators_limit,
            "sort": "_marker.desc"
        }

        indicators_data = []

        try:
            logger.info(f"Fetching indicators from: {indicators_url}")
            response = await client.get_raw_response(indicators_url, headers=headers, params=params)

            if response.status == 200:
                indicators = await response.json()

                # Only include high/medium confidence indicators
                for indicator in indicators.get("resources", [])[:10]:
                    confidence = indicator.get("malicious_confidence", "")
                    if confidence in ("high", "medium"):
                        indicators_data.append(self._parse_indicator(indicator))

                logger.info(f"Retrieved {len(indicators_data)} high-confidence indicators from CrowdStrike")
            else:
                response_text = await response.text()
                logger.error(f"CrowdStrike indicators API returned status {response.status}: {response_text[:500]}")

        except Exception as e:
            logger.error(f"Error fetching CrowdStrike indicators: {e}")

        return indicators_data

    def _extract_industry_names(self, industries_raw: List[Any]) -> List[str]:
        """
        Extract industry names from CrowdStrike's industry format.

        CrowdStrike API returns industries as list of dicts:
        [{"slug": "healthcare", "value": "Healthcare"}, ...]

        Args:
            industries_raw: Raw industries list from API

        Returns:
            List of industry name strings
        """
        names = []
        for item in industries_raw:
            if isinstance(item, dict):
                # Try 'value' first, then 'slug', then 'name'
                name = item.get("value") or item.get("slug") or item.get("name")
                if name:
                    names.append(str(name))
            elif isinstance(item, str):
                names.append(item)
        return names

    def _parse_actor(self, actor: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CrowdStrike actor into standardized format.

        Args:
            actor: Raw actor from API

        Returns:
            Standardized actor dictionary
        """
        # Extract country from origins (list of dicts with 'value' key)
        origins = actor.get("origins", [])
        country = "Unknown"
        if origins:
            first_origin = origins[0]
            if isinstance(first_origin, dict):
                country = first_origin.get("value", "Unknown")
            elif isinstance(first_origin, str):
                country = first_origin

        # Extract motivations (may be list of dicts or strings)
        motivations_raw = actor.get("motivations", [])
        motivations = self._extract_industry_names(motivations_raw)

        # Extract TTPs from kill_chain (may be list of dicts or strings)
        kill_chain_raw = actor.get("kill_chain", [])
        ttps = self._extract_industry_names(kill_chain_raw)[:5]

        # Extract target industries
        industries_raw = actor.get("target_industries", [])
        target_industries = self._extract_industry_names(industries_raw)

        return {
            "actor_name": actor.get("name", "Unknown"),
            "country": country,
            "motivations": motivations,
            "ttps": ttps,
            "target_industries": target_industries,
            "last_activity": actor.get("last_modified_date", ""),
            "source": self.source_name
        }

    def _parse_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CrowdStrike indicator into standardized format.

        Args:
            indicator: Raw indicator from API

        Returns:
            Standardized indicator dictionary
        """
        actors = indicator.get("actors", [])
        actor_name = actors[0] if actors else "Unknown"

        return {
            "actor_name": actor_name,
            "country": "Unknown",
            "motivations": ["Malicious Activity"],
            "ttps": [indicator.get("type", "Unknown")],
            "target_industries": [],
            "indicator": indicator.get("indicator", ""),
            "last_activity": indicator.get("last_updated", ""),
            "source": self.source_name
        }
