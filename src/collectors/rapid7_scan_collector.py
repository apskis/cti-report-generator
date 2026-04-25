"""
Rapid7 Scan Collector - Asset-based vulnerability exposure data.

Fetches actual scan results from Rapid7 InsightVM to determine which assets
are affected by which CVEs. This provides the "Exposure" data (e.g., "12 servers")
for the vulnerability reports.

This collector complements rapid7_collector.py:
- rapid7_collector.py: Vulnerability definitions, enrichment data (exploits, descriptions)
- rapid7_scan_collector.py: Asset exposure data (which servers/endpoints are affected)
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from collections import defaultdict

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient, NonRetryableHTTPError
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)


class Rapid7ScanCollector(BaseCollector):
    """
    Collector for Rapid7 InsightVM asset and vulnerability finding data.
    
    This collector queries actual scan results to determine CVE exposure
    in your environment (how many assets are affected by each CVE).
    
    API Documentation: https://help.rapid7.com/insightvm/en-us/api/integrations.html
    """

    @property
    def source_name(self) -> str:
        return "Rapid7-Scans"

    @property
    def lookback_days(self) -> int:
        return collector_config.rapid7_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch vulnerability exposure data from Rapid7 scan results.

        Returns:
            CollectorResult with CVE exposure mapping
        """
        api_key = self.credentials.get("rapid7_key", "")
        region = self.credentials.get("rapid7_region", "us")

        if not api_key:
            logger.warning("Rapid7 API key not provided, skipping scan data collection")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )

        logger.info(f"Fetching scan-based vulnerability exposure from Rapid7 (region: {region})")

        try:
            base_url = f"https://{region}.api.insight.rapid7.com"

            headers = {
                "X-Api-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            async with HTTPClient() as client:
                # Get CVE exposure mapping from asset vulnerability findings
                exposure_data = await self._fetch_asset_vulnerability_exposure(
                    client, base_url, headers
                )

            if exposure_data:
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[exposure_data],
                    record_count=len(exposure_data.get("cve_exposure_map", {}))
                )
            else:
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )

        except NonRetryableHTTPError as e:
            logger.error(f"Rapid7 Scan API error: {e}")
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )
        except Exception as e:
            logger.error(f"Error fetching Rapid7 scan data: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    async def _fetch_asset_vulnerability_exposure(
        self,
        client: HTTPClient,
        base_url: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Fetch vulnerability exposure by querying assets with their vulnerabilities.
        
        The Rapid7 Integration API v4 has two approaches:
        1. Use asset_search endpoint which can return vulnerability details
        2. Query vulnerabilities directly with asset context
        
        Strategy:
        1. Get assets from the recent scan window
        2. For assets with vulnerabilities, fetch their vulnerability instances
        3. Build CVE -> asset count mapping
        
        Args:
            client: HTTP client
            base_url: Rapid7 API base URL
            headers: Request headers with auth

        Returns:
            Dictionary with CVE exposure mapping
        """
        # Try the vulnerability findings endpoint which gives CVE-to-asset mapping directly
        vuln_url = f"{base_url}/vm/v4/integration/vulnerabilities"
        
        logger.info(f"Fetching vulnerability findings from: {vuln_url}")
        
        try:
            # Calculate date range
            start_date, end_date = self.get_date_range()
            since_date = start_date.strftime("%Y-%m-%dT00:00:00Z")
            
            # Try to get vulnerability instances (findings on assets)
            # According to Rapid7 Integration API v4, we can query for vuln findings
            request_body = {}  # Start with empty filter to see what we get
            
            params = {
                "size": 500,  # Get more results per page
                "page": 0
            }
            
            response = await client.post_raw_response(
                vuln_url,
                headers=headers,
                json_data=request_body,
                params=params
            )
            
            response_text = await response.text()
            
            if response.status == 200:
                data = await response.json()
                vulns = data.get("data", [])
                logger.info(f"Retrieved {len(vulns)} vulnerability instances from /vulnerabilities endpoint")
                
                if len(vulns) > 0:
                    logger.info(f"Sample vuln keys: {list(vulns[0].keys())}")
                    logger.info(f"Sample vuln (first 500 chars): {str(vulns[0])[:500]}...")
                
                    # Build CVE map from vulnerability findings (returns raw map)
                    cve_asset_map = self._build_cve_map_from_vulnerability_findings(vulns)
                    
                    # Enrich with asset hostnames for CVEs with < 3 occurrences
                    await self._enrich_low_count_cves_with_hostnames(
                        client, base_url, headers, cve_asset_map
                    )
                    
                    # Format the enriched data
                    cve_exposure = self._format_cve_exposure_summary(cve_asset_map, len(vulns))
                    
                    return cve_exposure
                else:
                    logger.warning("Vulnerabilities endpoint returned 0 results, falling back to asset-based approach")
                    return await self._fetch_exposure_from_assets(client, base_url, headers)
            elif response.status == 404:
                # Endpoint doesn't exist
                logger.info(f"Vulnerabilities endpoint not found (404), using asset-based approach")
                return await self._fetch_exposure_from_assets(client, base_url, headers)
            else:
                # Fall back to asset-based approach
                logger.warning(f"Vulnerability endpoint returned {response.status}: {response_text[:200]}")
                logger.warning("Falling back to asset-based approach")
                return await self._fetch_exposure_from_assets(client, base_url, headers)
                
        except Exception as e:
            logger.error(f"Error fetching vulnerability exposure: {e}")
            # Fall back to asset-based approach
            return await self._fetch_exposure_from_assets(client, base_url, headers)
    
    async def _fetch_exposure_from_assets(
        self,
        client: HTTPClient,
        base_url: str,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Fallback: Fetch exposure data from assets endpoint.
        """
        assets_url = f"{base_url}/vm/v4/integration/assets"
        logger.info(f"Fetching assets from: {assets_url}")
        
        try:
            # Get assets with vulnerability findings
            assets = await self._fetch_all_assets_with_vulns(client, assets_url, headers)
            
            if not assets:
                logger.warning("No assets returned from Rapid7")
                return {}
            
            logger.info(f"Retrieved {len(assets)} assets with vulnerability data")
            
            # Build CVE exposure map from asset vulnerability findings
            cve_exposure = self._build_cve_map_from_assets(assets)
            
            return cve_exposure
            
        except Exception as e:
            logger.error(f"Error fetching asset vulnerability exposure: {e}")
            return {}

    async def _fetch_all_assets_with_vulns(
        self,
        client: HTTPClient,
        assets_url: str,
        headers: Dict[str, str],
        max_pages: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Fetch all assets with their vulnerability findings.
        
        Args:
            client: HTTP client
            assets_url: Assets endpoint URL
            headers: Request headers
            max_pages: Maximum number of pages to fetch
            
        Returns:
            List of asset dictionaries with vulnerability findings
        """
        all_assets = []
        page = 0
        
        # Calculate date range for recent assets
        start_date, _ = self.get_date_range()
        recent_date = start_date.strftime("%Y-%m-%dT00:00:00Z")
        
        while page < max_pages:
            params = {
                "size": 100,
                "page": page
            }
            
            # Request body - filter for recently scanned assets
            # Include vulnerabilities in the response
            request_body = {
                "asset": f"last-scan-date > {recent_date}",
                "vulnerability": "results > 0"  # Only assets with vulnerability results
            }
            
            try:
                response = await client.post_raw_response(
                    assets_url,
                    headers=headers,
                    json_data=request_body,
                    params=params
                )
                
                if response.status == 200:
                    data = await response.json()
                    assets = data.get("data", [])
                    
                    if not assets:
                        logger.info(f"No more assets on page {page}")
                        break
                    
                    all_assets.extend(assets)
                    logger.info(f"Fetched page {page}: {len(assets)} assets (total: {len(all_assets)})")
                    
                    # Check if there are more pages
                    metadata = data.get("metadata", {})
                    total_pages = metadata.get("totalPages", 1)
                    
                    if page >= total_pages - 1:
                        logger.info(f"Reached last page ({page + 1} of {total_pages})")
                        break
                    
                    page += 1
                    
                elif response.status == 400:
                    # If filtering fails, try without filter
                    logger.warning("Asset filtering failed, trying without date filter")
                    response = await client.post_raw_response(
                        assets_url,
                        headers=headers,
                        json_data={},
                        params=params
                    )
                    
                    if response.status == 200:
                        data = await response.json()
                        assets = data.get("data", [])
                        all_assets.extend(assets)
                        logger.info(f"Fetched {len(assets)} assets without filter")
                    break
                    
                else:
                    response_text = await response.text()
                    logger.error(f"Asset API returned status {response.status}: {response_text[:500]}")
                    break
                    
            except Exception as e:
                logger.error(f"Error fetching assets page {page}: {e}")
                break
        
        return all_assets

    def _build_cve_map_from_vulnerability_findings(
        self,
        vulns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build CVE exposure map from vulnerability findings.
        
        Each vulnerability finding should have CVE IDs. Since the /vulnerabilities endpoint
        returns definitions (not per-asset findings), we track CVEs but won't have hostname
        data unless we make additional queries.
        
        Args:
            vulns: List of vulnerability findings
            
        Returns:
            CVE exposure mapping dictionary
        """
        # First pass: count occurrences of each CVE (each vuln record = 1 occurrence)
        cve_counts = defaultdict(int)
        cve_vuln_ids = defaultdict(list)  # Track vuln IDs for each CVE
        cve_titles = {}  # Track vulnerability title per CVE
        cve_exploit_info = {}  # Track exploit/malware data per CVE
        cve_added_dates = {}  # Track earliest 'added' date per CVE
        
        now = datetime.now(timezone.utc)
        
        logger.info(f"Building CVE exposure map from {len(vulns)} vulnerability findings...")
        
        for idx, vuln in enumerate(vulns):
            if idx < 3:  # Log first 3 for debugging
                logger.info(f"Vuln {idx} keys: {list(vuln.keys())}")
            
            # Get CVE IDs
            cve_ids = vuln.get("cves", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids] if cve_ids else []
            
            # The 'id' field is the vulnerability definition ID (not asset-specific)
            vuln_id = vuln.get("id", "")
            vuln_title = vuln.get("title", "")
            exploits_count = vuln.get("exploits", 0)
            if isinstance(exploits_count, list):
                exploits_count = len(exploits_count)
            malware_kits = vuln.get("malware_kits", 0)
            if isinstance(malware_kits, list):
                malware_kits = len(malware_kits)
            
            # Parse the 'added' date for weeks-detected calculation
            added_str = vuln.get("added", "")
            added_date = None
            if added_str:
                try:
                    added_date = datetime.fromisoformat(added_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
            
            for cve_id in cve_ids:
                if not cve_id:
                    continue
                cve_counts[cve_id] += 1
                cve_vuln_ids[cve_id].append(vuln_id)
                if vuln_title and cve_id not in cve_titles:
                    cve_titles[cve_id] = vuln_title
                if (exploits_count or malware_kits) and cve_id not in cve_exploit_info:
                    cve_exploit_info[cve_id] = {
                        "exploits": exploits_count if isinstance(exploits_count, int) else 0,
                        "malware_kits": malware_kits if isinstance(malware_kits, int) else 0,
                    }
                if added_date and (cve_id not in cve_added_dates or added_date < cve_added_dates[cve_id]):
                    cve_added_dates[cve_id] = added_date
        
        # Build the exposure map
        # Note: Since /vulnerabilities returns definitions without asset context,
        # each unique vulnerability record represents ONE occurrence, but we can't
        # distinguish multiple assets with the same vuln vs one asset with one vuln.
        # The count represents unique vulnerability instances found.
        cve_asset_map = {}
        for cve_id, count in cve_counts.items():
            weeks = 1
            if cve_id in cve_added_dates:
                delta = now - cve_added_dates[cve_id]
                weeks = max(1, delta.days // 7)
            
            cve_asset_map[cve_id] = {
                "asset_count": count,
                "asset_ids": set(),
                "asset_names": set(),
                "asset_types": {"system"},
                "title": cve_titles.get(cve_id, ""),
                "exploit_info": cve_exploit_info.get(cve_id, {}),
                "weeks_detected": weeks,
            }
        
        # Return the raw map (will be formatted by caller after enrichment)
        return cve_asset_map
    
    async def _enrich_low_count_cves_with_hostnames(
        self,
        client: HTTPClient,
        base_url: str,
        headers: Dict[str, str],
        cve_exposure: Dict[str, Any]
    ):
        """
        Enrich CVEs with fewer than 3 occurrences with actual hostnames and asset types.
        
        Strategy for Rapid7 Cloud Integration API v4:
        1. We already have CVE counts from the /vulnerabilities endpoint
        2. For low-count CVEs, we query all assets to find which ones have those CVEs
        3. Extract hostname and asset type from matching assets
        
        NOTE: The Cloud Integration API v4 doesn't support filtering assets by specific CVE ID.
        Instead, we fetch a batch of assets and check each one's vulnerability list.
        
        Args:
            client: HTTP client
            base_url: Rapid7 API base URL
            headers: Request headers
            cve_exposure: The CVE exposure dictionary to enrich (modified in place)
        """
        assets_url = f"{base_url}/vm/v4/integration/assets"
        
        # Find CVEs that need enrichment (count < 3)
        cves_to_enrich = {}  # cve_id -> expected count
        for cve_id, info in cve_exposure.items():
            count = info.get("asset_count", 0)
            if count < 3 and count > 0:
                cves_to_enrich[cve_id] = count
        
        if not cves_to_enrich:
            logger.info("No CVEs need hostname enrichment (all have 0 or 3+ assets)")
            return
        
        logger.info(f"Enriching {len(cves_to_enrich)} CVEs with hostnames and asset types...")
        logger.info(f"Note: Cloud API doesn't support CVE-based asset filtering, using brute-force approach")
        
        # For the Cloud API, we have to query assets and check their vulnerability arrays
        # This is less efficient but it's the only way with the current API
        # We'll query assets with vulnerabilities and check each one
        
        try:
            request_body = {
                "vulnerability": "results > 0"  # Assets with any vulnerabilities
            }
            
            params = {
                "size": 100,  # Get 100 assets at a time
                "page": 0
            }
            
            cve_to_assets = {cve_id: [] for cve_id in cves_to_enrich.keys()}
            max_pages = 5  # Limit to avoid excessive API calls
            
            for page in range(max_pages):
                params["page"] = page
                
                response = await client.post_raw_response(
                    assets_url,
                    headers=headers,
                    json_data=request_body,
                    params=params
                )
                
                if response.status != 200:
                    logger.warning(f"Asset query returned status {response.status}")
                    break
                
                data = await response.json()
                assets = data.get("data", [])
                
                if not assets:
                    logger.info(f"No more assets on page {page}")
                    break
                
                logger.debug(f"Checking {len(assets)} assets from page {page}...")
                
                # Check each asset for our target CVEs
                for asset in assets:
                    hostname = asset.get("host_name") or asset.get("ip", "Unknown")
                    os_family = asset.get("os_family", "")
                    os_name = asset.get("os_name", "")
                    
                    # Check the asset's vulnerability list
                    # Note: According to our previous tests, 'new' arrays were empty
                    # But let's try anyway, and if still empty, we'll document this limitation
                    new_vulns = asset.get("new", [])
                    
                    if not new_vulns:
                        continue  # Skip assets with no vulnerability details
                    
                    # Check each vulnerability on this asset
                    for vuln in new_vulns:
                        vuln_cves = vuln.get("cves", [])
                        if isinstance(vuln_cves, str):
                            vuln_cves = [vuln_cves]
                        
                        # Check if any of our target CVEs are in this vulnerability
                        for cve_id in cves_to_enrich.keys():
                            if cve_id in vuln_cves:
                                asset_info = {
                                    "hostname": hostname,
                                    "os_family": os_family,
                                    "os_name": os_name,
                                    "asset": asset
                                }
                                cve_to_assets[cve_id].append(asset_info)
                
                # Check if we've found all the assets we need
                all_found = all(
                    len(assets) >= cves_to_enrich.get(cve_id, 999)
                    for cve_id, assets in cve_to_assets.items()
                )
                
                if all_found:
                    logger.info(f"Found all target assets after {page + 1} pages")
                    break
            
            # Now enrich the CVE exposure data with the hostnames we found
            enriched_count = 0
            for cve_id, asset_infos in cve_to_assets.items():
                if asset_infos:
                    hostnames = [info["hostname"] for info in asset_infos]
                    
                    # Classify asset types
                    asset_types = set()
                    for info in asset_infos:
                        asset = info["asset"]
                        os_family = asset.get("os_family", "").lower()
                        os_name = asset.get("os_name", "").lower()
                        
                        # Simple classification
                        if "server" in os_family or "server" in os_name or "linux" in os_family:
                            asset_types.add("server")
                        elif "windows" in os_family:
                            asset_types.add("workstation")
                        else:
                            asset_types.add("system")
                    
                    # Update CVE exposure
                    cve_exposure[cve_id]["asset_names"] = set(hostnames)
                    cve_exposure[cve_id]["asset_types"] = asset_types if asset_types else {"system"}
                    cve_exposure[cve_id]["asset_count"] = len(asset_infos)
                    
                    logger.debug(f"Enriched {cve_id}: {len(asset_infos)} assets - {hostnames[:3]}")
                    enriched_count += 1
            
            if enriched_count > 0:
                logger.info(f"Successfully enriched {enriched_count} CVEs with hostnames")
            else:
                logger.warning("Could not enrich any CVEs - asset vulnerability arrays may be empty in Cloud API")
                logger.warning("This is a known limitation of the Rapid7 Cloud Integration API v4")
                
        except Exception as e:
            logger.error(f"Error during hostname enrichment: {e}", exc_info=True)
    
    def _build_cve_map_from_assets(
        self,
        assets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build CVE exposure map from assets with embedded vulnerability findings.
        
        Each asset has 'new', 'same', and 'remediated' vulnerability collections.
        We count unique assets per CVE from 'new' and 'same' (active vulnerabilities).
        
        Args:
            assets: List of assets with vulnerability data
            
        Returns:
            CVE exposure mapping dictionary
        """
        cve_asset_map = defaultdict(lambda: {
            "asset_count": 0,
            "asset_ids": set(),
            "asset_names": set(),
            "asset_types": set(),
        })
        
        logger.info(f"Building CVE exposure map from {len(assets)} assets...")
        
        # Dump first asset structure to understand API response format
        if assets and len(assets) > 0:
            first_asset = assets[0]
            logger.info(f"Sample asset keys: {list(first_asset.keys())}")
            logger.info(f"Sample asset total_vulnerabilities: {first_asset.get('total_vulnerabilities', 0)}")
            logger.info(f"Sample asset critical_vulnerabilities: {first_asset.get('critical_vulnerabilities', 0)}")
            
            # Check what's in the new/remediated fields
            new_vulns = first_asset.get("new", [])
            remediated_vulns = first_asset.get("remediated", [])
            logger.info(f"Sample asset 'new' field type: {type(new_vulns)}, length: {len(new_vulns) if isinstance(new_vulns, list) else 'N/A'}")
            logger.info(f"Sample asset 'remediated' field type: {type(remediated_vulns)}, length: {len(remediated_vulns) if isinstance(remediated_vulns, list) else 'N/A'}")
            
            if isinstance(new_vulns, list) and len(new_vulns) > 0:
                logger.info(f"Sample 'new' vuln structure: {new_vulns[0]}")
            if isinstance(remediated_vulns, list) and len(remediated_vulns) > 0:
                logger.info(f"Sample 'remediated' vuln structure: {remediated_vulns[0]}")
        
        for idx, asset in enumerate(assets):
            asset_id = asset.get("id")
            asset_name = asset.get("host_name") or asset.get("ip", "Unknown")
            asset_type = asset.get("os_family", "server")  # Use OS family as type
            total_vulns = asset.get("total_vulnerabilities", 0)
            
            if not asset_id:
                continue
            
            # Process active vulnerabilities ('new' only - 'same' field doesn't exist in cloud API)
            active_vulns = asset.get("new", [])
            
            # Ensure it's a list
            if not isinstance(active_vulns, list):
                logger.warning(f"Asset {asset_name}: 'new' field is not a list, it's {type(active_vulns)}")
                active_vulns = []
            
            if idx < 5:  # Log first 5 for debugging
                logger.info(f"Asset {asset_name}: {len(active_vulns)} active vulns from 'new' field (total_vulnerabilities={total_vulns})")
                if idx == 0 and len(active_vulns) > 0:
                    logger.info(f"  First vuln keys: {list(active_vulns[0].keys()) if isinstance(active_vulns[0], dict) else type(active_vulns[0])}")
            
            for vuln in active_vulns:
                # Get CVEs for this vulnerability
                cve_ids = vuln.get("cves", [])
                
                # Ensure cve_ids is a list
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids] if cve_ids else []
                
                for cve_id in cve_ids:
                    if not cve_id:
                        continue
                    
                    # Track this asset for this CVE
                    cve_info = cve_asset_map[cve_id]
                    
                    # Only count unique assets
                    if asset_id not in cve_info["asset_ids"]:
                        cve_info["asset_ids"].add(asset_id)
                        cve_info["asset_names"].add(asset_name)
                        
                        # Classify asset type based on OS and other fields
                        os_name = asset.get("os_name", "").lower()
                        os_system_name = asset.get("os_system_name", "").lower()
                        tags = asset.get("tags", [])
                        tag_str = " ".join([str(tag).lower() for tag in tags]) if tags else ""
                        
                        # Check for cloud indicators
                        is_aws = "aws" in asset_name.lower() or "ec2" in asset_name.lower() or "amazon" in tag_str
                        is_azure = "azure" in asset_name.lower() or "azurevm" in asset_name.lower() or "azure" in tag_str
                        
                        # Classify (same logic as enrichment)
                        if "database" in os_name or "sql" in os_name or "mysql" in os_name:
                            cve_info["asset_types"].add("database")
                        elif is_aws or is_azure:
                            if "server" in asset_type.lower() or "linux" in asset_type.lower():
                                cve_info["asset_types"].add("cloud server")
                            else:
                                cve_info["asset_types"].add("cloud instance")
                        elif "server" in asset_type.lower() or "linux" in asset_type.lower() or "unix" in asset_type.lower():
                            cve_info["asset_types"].add("server")
                        elif "windows" in asset_type.lower() and "server" not in asset_type.lower():
                            cve_info["asset_types"].add("workstation")
                        else:
                            cve_info["asset_types"].add("system")
                        
                        cve_info["asset_count"] += 1
        
        # Convert to final format
        return self._format_cve_exposure_summary(cve_asset_map, len(assets))
    
    def _format_cve_exposure_summary(
        self,
        cve_asset_map: Dict[str, Dict[str, Any]],
        total_items: int
    ) -> Dict[str, Any]:
        """
        Format the CVE exposure map into the final summary structure.
        
        Args:
            cve_asset_map: Raw CVE to asset mapping
            total_items: Total number of items processed (assets or vulns)
            
        Returns:
            Formatted CVE exposure summary
        """
        cve_exposure_summary = {}
        
        for cve_id, info in cve_asset_map.items():
            asset_count = info["asset_count"]
            asset_names = list(info["asset_names"])
            
            # Determine predominant asset type
            asset_types = list(info["asset_types"])
            if "database" in asset_types:
                asset_type_singular = "database"
                asset_type_plural = "databases"
            elif "cloud server" in asset_types:
                asset_type_singular = "cloud server"
                asset_type_plural = "cloud servers"
            elif "cloud instance" in asset_types:
                asset_type_singular = "cloud instance"
                asset_type_plural = "cloud instances"
            elif "server" in asset_types:
                asset_type_singular = "server"
                asset_type_plural = "servers"
            elif "workstation" in asset_types:
                asset_type_singular = "workstation"
                asset_type_plural = "workstations"
            elif "endpoint" in asset_types:
                asset_type_singular = "endpoint"
                asset_type_plural = "endpoints"
            else:
                asset_type_singular = "system"
                asset_type_plural = "systems"
            
            # Use proper singular/plural grammar
            asset_type_label = asset_type_singular if asset_count == 1 else asset_type_plural
            exposure_string = f"{asset_count} {asset_type_label}"
            
            # If we have hostnames (from asset-based collection), show them for count < 3
            known_names = [name for name in asset_names if name.lower() != "unknown" and name]
            if known_names and asset_count < 3:
                # Show hostnames if we have them
                exposure_string = ", ".join(known_names[:asset_count])
            
            cve_exposure_summary[cve_id] = {
                "exposure": exposure_string,
                "asset_count": asset_count,
                "asset_type": asset_type_plural,
                "sample_assets": asset_names[:5],
                "title": info.get("title", ""),
                "exploit_info": info.get("exploit_info", {}),
                "weeks_detected": info.get("weeks_detected", 1),
            }
        
        logger.info(f"Built CVE exposure map: {len(cve_exposure_summary)} CVEs found across {total_items} items")
        
        # Log sample
        sample_cves = list(cve_exposure_summary.items())[:5]
        for cve_id, exposure_info in sample_cves:
            logger.info(f"  {cve_id}: {exposure_info['exposure']} (e.g., {list(exposure_info['sample_assets'])[:2]})")
        
        return {
            "source": self.source_name,
            "cve_exposure_map": cve_exposure_summary,
            "total_cves": len(cve_exposure_summary),
            "total_assets_scanned": total_items
        }
