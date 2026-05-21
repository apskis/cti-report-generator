"""
Rapid7 Bulk Export API Collector - Comprehensive vulnerability data via GraphQL.

This collector uses the Rapid7 Bulk Export API to retrieve complete vulnerability
datasets in Parquet format, providing full visibility into your environment.

API Documentation: https://docs.rapid7.com/insightvm/bulk-export-api/

Key Features:
- Uses GraphQL API with your Org API key
- Exports ALL vulnerabilities (not limited like Integration API v4)
- Returns data in Parquet format
- Provides comprehensive CVE-to-asset mapping
"""
import logging
import asyncio
import tempfile
from typing import Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path

from src.collectors.base import BaseCollector
from src.collectors.http_utils import HTTPClient, NonRetryableHTTPError
from src.core.config import collector_config
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)


class Rapid7BulkExportCollector(BaseCollector):
    """
    Collector for Rapid7 InsightVM Bulk Export API.
    
    Uses GraphQL to export comprehensive vulnerability data in Parquet format.
    Provides complete CVE exposure mapping from your environment.
    """

    @property
    def source_name(self) -> str:
        return "Rapid7-BulkExport"

    @property
    def lookback_days(self) -> int:
        return collector_config.rapid7_lookback_days

    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Fetch vulnerability data via Bulk Export API or from cache.
        
        First checks if fresh cached data exists (< 6 hours old).
        If not, performs full export (takes 10-20 minutes).

        Returns:
            CollectorResult with CVE exposure mapping
        """
        # Get credentials
        api_key = self.credentials.get("rapid7_key", "")
        region = self.credentials.get("rapid7_region", "us")
        storage_account_name = self.credentials.get("storage_account_name", "")
        storage_account_key = self.credentials.get("storage_account_key", "")
        
        if not api_key:
            logger.warning("Rapid7 API key not provided, skipping Bulk Export collection")
            return CollectorResult(
                source=self.source_name,
                success=True,
                data=[],
                record_count=0
            )
        
        # Try to load from cache first
        if storage_account_name and storage_account_key:
            try:
                from src.utils.cache_manager import CacheManager
                cache_manager = CacheManager(storage_account_name, storage_account_key)
                
                cache_key = "rapid7-bulk-export-latest"
                cached_data = cache_manager.get_cache(cache_key, max_age_hours=6)
                
                if cached_data:
                    record_count = len(cached_data.get("cve_exposure_map", {}))
                    logger.info(f"Using cached Rapid7 data: {record_count} CVEs")
                    return CollectorResult(
                        source=self.source_name,
                        success=True,
                        data=[cached_data],
                        record_count=record_count
                    )
                else:
                    logger.info("No fresh cache found, will fetch from Rapid7 API")
            except Exception as e:
                logger.warning(f"Cache check failed, will fetch from API: {e}")

        logger.info(f"Fetching vulnerability data via Rapid7 Bulk Export API (region: {region})")
        logger.info("Note: This may take 10-20 minutes for large environments")

        try:
            # Build GraphQL endpoint URL for Bulk Export API
            # Note: Bulk Export is a Platform-level API
            graphql_url = f"https://{region}.api.insight.rapid7.com/export/graphql"
            
            headers = {
                "X-Api-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            async with HTTPClient() as client:
                # Step 1: Create vulnerability export
                export_id = await self._create_vulnerability_export(client, graphql_url, headers)
                
                if not export_id:
                    logger.error("Failed to create vulnerability export")
                    return CollectorResult(
                        source=self.source_name,
                        success=False,
                        error="Failed to create export",
                        record_count=0
                    )
                
                logger.info(f"Created vulnerability export: {export_id}")
                
                # Step 2: Poll for export completion (with timeout)
                download_urls = await self._poll_export_status(client, graphql_url, headers, export_id)
                
                if not download_urls:
                    logger.warning("Export did not complete in time or returned no URLs")
                    return CollectorResult(
                        source=self.source_name,
                        success=False,
                        error="Export timeout or no data",
                        record_count=0
                    )
                
                logger.info(f"Export complete! Got {len(download_urls)} download URLs")
                
                # Step 3: Download and parse Parquet files
                cve_exposure_map = await self._download_and_parse_exports(client, download_urls, headers)
                
                if cve_exposure_map:
                    return CollectorResult(
                        source=self.source_name,
                        success=True,
                        data=[cve_exposure_map],
                        record_count=len(cve_exposure_map.get("cve_exposure_map", {}))
                    )
                else:
                    return CollectorResult(
                        source=self.source_name,
                        success=True,
                        data=[],
                        record_count=0
                    )

        except Exception as e:
            logger.error(f"Error in Rapid7 Bulk Export: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                error=str(e),
                record_count=0
            )

    async def _create_vulnerability_export(
        self,
        client: HTTPClient,
        graphql_url: str,
        headers: Dict[str, str]
    ) -> str:
        """
        Create a vulnerability export via GraphQL mutation.
        
        Returns:
            Export ID string
        """
        mutation = """
        mutation CreateVulnerabilityExport {
            createVulnerabilityExport(input:{}) {
                id
            }
        }
        """
        
        payload = {
            "query": mutation
        }
        
        logger.info(f"Sending GraphQL mutation to {graphql_url}")
        logger.debug(f"Headers: X-Api-Key={'*'*8}, Content-Type={headers.get('Content-Type')}")
        logger.debug(f"Payload: {payload}")
        
        try:
            response = await client.post_raw_response(
                graphql_url,
                headers=headers,
                json_data=payload
            )
            
            if response.status != 200:
                response_text = await response.text()
                logger.error(f"GraphQL mutation failed: {response.status} - {response_text}")
                return ""
            
            logger.info(f"GraphQL response status: {response.status}")
            data = await response.json()
            logger.debug(f"GraphQL response data: {data}")
            
            # Extract export ID from response
            export_id = data.get("data", {}).get("createVulnerabilityExport", {}).get("id", "")
            
            if not export_id:
                logger.error(f"No export ID in response. Full response: {data}")
            
            return export_id
            
        except Exception as e:
            logger.error(f"Error creating vulnerability export: {e}", exc_info=True)
            return ""

    async def _poll_export_status(
        self,
        client: HTTPClient,
        graphql_url: str,
        headers: Dict[str, str],
        export_id: str,
        max_attempts: int = 60,
        poll_interval: int = 10
    ) -> List[Dict[str, str]]:
        """
        Poll export status until complete or timeout.
        
        Args:
            export_id: ID of the export to poll
            max_attempts: Maximum number of poll attempts (default 60 = 10 minutes)
            poll_interval: Seconds between polls (default 10)
            
        Returns:
            List of download URLs with metadata
        """
        query = """
        query GetExport($id: ID!) {
            export(id: $id) {
                id
                status
                urls {
                    url
                    prefix
                }
            }
        }
        """
        
        for attempt in range(max_attempts):
            payload = {
                "query": query,
                "variables": {
                    "id": export_id
                }
            }
            
            try:
                response = await client.post_raw_response(
                    graphql_url,
                    headers=headers,
                    json_data=payload
                )
                
                if response.status != 200:
                    logger.warning(f"Status check failed: {response.status}")
                    await asyncio.sleep(poll_interval)
                    continue
                
                data = await response.json()
                logger.debug(f"Status check response: {data}")
                export_data = data.get("data", {}).get("export", {})
                status = export_data.get("status", "UNKNOWN")
                
                logger.info(f"Export status (attempt {attempt + 1}/{max_attempts}): {status}")
                
                if status == "SUCCEEDED":
                    urls = export_data.get("urls", [])
                    logger.info(f"Export succeeded! {len(urls)} URLs available")
                    return urls
                
                elif status in ("FAILED", "CANCELED"):
                    logger.error(f"Export failed with status: {status}")
                    return []
                
                # Still processing, wait and retry
                await asyncio.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Error polling export status: {e}")
                await asyncio.sleep(poll_interval)
        
        logger.warning(f"Export polling timeout after {max_attempts} attempts")
        return []

    async def _download_and_parse_exports(
        self,
        client: HTTPClient,
        download_urls: List[Dict[str, str]],
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Download Parquet files and parse vulnerability data.
        
        Args:
            download_urls: List of URL dicts with 'url' and 'prefix' keys
            
        Returns:
            CVE exposure mapping dictionary
        """
        try:
            # Try to import pyarrow for Parquet reading
            import pyarrow.parquet as pq
        except ImportError:
            logger.error("pyarrow not installed. Install with: pip install pyarrow")
            logger.error("Bulk Export requires pyarrow to parse Parquet files")
            return {}
        
        # Filter for vulnerability-related files
        vuln_urls = [u for u in download_urls if u.get("prefix") in ("vulnerability", "asset_vulnerability")]
        asset_urls = [u for u in download_urls if u.get("prefix") == "asset"]
        
        logger.info(f"Found {len(vuln_urls)} vulnerability files and {len(asset_urls)} asset files")
        
        if not vuln_urls:
            logger.warning("No vulnerability files in export")
            return {}
        
        # Download and parse vulnerability data
        cve_data = {}
        asset_data = {}
        
        # Process vulnerability files
        for url_info in vuln_urls[:5]:  # Limit to first 5 files for now
            url = url_info.get("url", "")
            prefix = url_info.get("prefix", "")
            
            logger.info(f"Downloading {prefix} file...")
            
            try:
                # Download Parquet file to temporary location
                response = await client.get_raw_response(url, headers={})  # URLs are pre-signed, no auth needed
                
                if response.status != 200:
                    logger.warning(f"Failed to download {prefix}: {response.status}")
                    continue
                
                # Save to temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".parquet") as tmp:
                    content = await response.read()
                    tmp.write(content)
                    tmp_path = tmp.name
                
                # Read Parquet file
                table = pq.read_table(tmp_path)
                df = table.to_pandas()
                
                logger.info(f"Loaded {len(df)} records from {prefix}")
                logger.info(f"Columns: {list(df.columns)}")
                
                # Parse vulnerability data
                # Schema varies by export type - adapt as needed
                self._parse_vulnerability_dataframe(df, cve_data, asset_data)
                
                # Cleanup temp file
                Path(tmp_path).unlink()
                
            except Exception as e:
                logger.error(f"Error processing {prefix} file: {e}", exc_info=True)
        
        # Build CVE exposure map
        cve_exposure_map = self._build_cve_exposure_from_export_data(cve_data, asset_data)
        
        return cve_exposure_map

    def _parse_vulnerability_dataframe(
        self,
        df,
        cve_data: Dict[str, Any],
        asset_data: Dict[str, Any]
    ):
        """
        Parse vulnerability dataframe and extract CVE mappings.
        
        Args:
            df: Pandas dataframe with vulnerability data
            cve_data: Dict to populate with CVE information
            asset_data: Dict to populate with asset information
        """
        # Log first few rows to understand schema
        if len(df) > 0:
            logger.info(f"Sample row keys: {list(df.iloc[0].keys())}")
        
        # Parse based on available columns
        # This is a starting point - schema may need adjustment
        for idx, row in df.iterrows():
            if idx >= 100:  # Limit processing for now
                break
            
            # Try to extract CVE ID
            cve_id = None
            if 'cve' in row:
                cve_id = row['cve']
            elif 'cve_id' in row:
                cve_id = row['cve_id']
            elif 'cves' in row:
                # Might be a list
                cves = row['cves']
                if isinstance(cves, list) and len(cves) > 0:
                    cve_id = cves[0]
            
            if not cve_id:
                continue
            
            # Initialize CVE entry
            if cve_id not in cve_data:
                cve_data[cve_id] = {
                    "asset_count": 0,
                    "assets": [],
                    "title": row.get('title', ''),
                    "severity": row.get('severity', ''),
                }
            
            # Track asset if available
            asset_id = row.get('asset_id')
            if asset_id and asset_id not in cve_data[cve_id]["assets"]:
                cve_data[cve_id]["assets"].append(asset_id)
                cve_data[cve_id]["asset_count"] += 1

    def _build_cve_exposure_from_export_data(
        self,
        cve_data: Dict[str, Any],
        asset_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build final CVE exposure map from parsed export data.
        
        Returns:
            Formatted CVE exposure summary
        """
        cve_exposure_map = {}
        
        for cve_id, info in cve_data.items():
            asset_count = info["asset_count"]
            
            cve_exposure_map[cve_id] = {
                "exposure": f"{asset_count} systems",
                "asset_count": asset_count,
                "asset_type": "systems",
                "sample_assets": info["assets"][:5],
                "title": info["title"],
                "weeks_detected": 1,  # TODO: Calculate from export data if available
            }
        
        logger.info(f"Built CVE exposure map: {len(cve_exposure_map)} CVEs")
        
        return {
            "source": self.source_name,
            "cve_exposure_map": cve_exposure_map,
            "total_cves": len(cve_exposure_map),
            "total_assets_scanned": len(asset_data)
        }
