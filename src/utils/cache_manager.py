"""
Cache Manager for Blob Storage operations.

Handles caching of collector data to Azure Blob Storage with TTL support.
"""

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobServiceClient

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages caching of collector data in Azure Blob Storage.

    Supports TTL-based cache expiration and automatic cache invalidation.
    """

    def __init__(self, storage_account_name: str, storage_account_key: str):
        """
        Initialize cache manager.

        Args:
            storage_account_name: Azure Storage account name
            storage_account_key: Azure Storage account key
        """
        self.account_name = storage_account_name
        self.account_key = storage_account_key
        self.container_name = "cache"

        # Initialize blob service client
        connection_string = (
            f"DefaultEndpointsProtocol=https;"
            f"AccountName={storage_account_name};"
            f"AccountKey={storage_account_key};"
            f"EndpointSuffix=core.windows.net"
        )
        self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)

        # Ensure cache container exists
        self._ensure_container_exists()

    def _ensure_container_exists(self):
        """Create cache container if it doesn't exist."""
        try:
            container_client = self.blob_service_client.get_container_client(self.container_name)
            if not container_client.exists():
                container_client.create_container()
                logger.info(f"Created cache container: {self.container_name}")
        except Exception as e:
            logger.warning(f"Could not verify cache container: {e}")

    def get_cache(self, cache_key: str, max_age_hours: int = 6) -> dict[str, Any] | None:
        """
        Get cached data if it exists and is fresh.

        Args:
            cache_key: Unique identifier for cached data
            max_age_hours: Maximum age of cache in hours (default: 6)

        Returns:
            Cached data dict or None if not found/expired
        """
        blob_name = f"{cache_key}.json"

        try:
            blob_client = self.blob_service_client.get_blob_client(container=self.container_name, blob=blob_name)

            # Check if blob exists
            if not blob_client.exists():
                logger.info(f"Cache miss: {cache_key} not found")
                return None

            # Get blob properties to check last modified time
            properties = blob_client.get_blob_properties()
            last_modified = properties.last_modified

            # Check if cache is expired
            now = datetime.now(UTC)
            age = now - last_modified
            max_age = timedelta(hours=max_age_hours)

            if age > max_age:
                logger.info(f"Cache expired: {cache_key} (age: {age}, max: {max_age})")
                return None

            # Download and parse cached data
            blob_data = blob_client.download_blob()
            cache_content = blob_data.readall()
            cached_data = json.loads(cache_content)

            logger.info(f"Cache hit: {cache_key} (age: {age})")
            return cached_data

        except ResourceNotFoundError:
            logger.info(f"Cache miss: {cache_key} not found")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Cache corrupted: {cache_key} - {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading cache: {cache_key} - {e}")
            return None

    def set_cache(self, cache_key: str, data: dict[str, Any]) -> bool:
        """
        Store data in cache.

        Args:
            cache_key: Unique identifier for cached data
            data: Data to cache (must be JSON serializable)

        Returns:
            True if successful, False otherwise
        """
        blob_name = f"{cache_key}.json"

        try:
            blob_client = self.blob_service_client.get_blob_client(container=self.container_name, blob=blob_name)

            # Serialize data to JSON
            cache_content = json.dumps(data, indent=2, default=str)

            # Upload to blob storage
            blob_client.upload_blob(
                cache_content, overwrite=True, content_settings={"content_type": "application/json"}
            )

            logger.info(f"Cache updated: {cache_key} ({len(cache_content)} bytes)")
            return True

        except Exception as e:
            logger.error(f"Error writing cache: {cache_key} - {e}")
            return False

    def delete_cache(self, cache_key: str) -> bool:
        """
        Delete cached data.

        Args:
            cache_key: Unique identifier for cached data

        Returns:
            True if successful, False otherwise
        """
        blob_name = f"{cache_key}.json"

        try:
            blob_client = self.blob_service_client.get_blob_client(container=self.container_name, blob=blob_name)

            blob_client.delete_blob()
            logger.info(f"Cache deleted: {cache_key}")
            return True

        except ResourceNotFoundError:
            logger.info(f"Cache not found: {cache_key}")
            return False
        except Exception as e:
            logger.error(f"Error deleting cache: {cache_key} - {e}")
            return False

    def list_cache_keys(self, prefix: str = "") -> list[str]:
        """
        List all cache keys with optional prefix filter.

        Args:
            prefix: Optional prefix to filter cache keys

        Returns:
            List of cache keys
        """
        try:
            container_client = self.blob_service_client.get_container_client(self.container_name)
            blobs = container_client.list_blobs(name_starts_with=prefix)

            # Extract keys (remove .json extension)
            cache_keys = [blob.name.replace(".json", "") for blob in blobs]

            logger.info(f"Found {len(cache_keys)} cache entries with prefix '{prefix}'")
            return cache_keys

        except Exception as e:
            logger.error(f"Error listing cache keys: {e}")
            return []

    def cache_collector_data(self, collector_name: str, data: list[dict[str, Any]], ttl_hours: int = 6) -> bool:
        """
        Cache data from any collector with metadata.

        Args:
            collector_name: Name of the collector (e.g., "Intel471", "CrowdStrike")
            data: Data to cache (list of records)
            ttl_hours: Cache time-to-live in hours (for documentation only)

        Returns:
            True if successful, False otherwise
        """
        cache_key = f"collector-{collector_name}-{datetime.now(UTC).strftime('%Y%m%d')}"

        try:
            cache_payload = {
                "collected_at": datetime.now(UTC).isoformat(),
                "source": collector_name,
                "record_count": len(data) if data else 0,
                "ttl_hours": ttl_hours,
                "data": data,
            }

            success = self.set_cache(cache_key, cache_payload)

            if success:
                logger.info(f"Cached {len(data) if data else 0} records from {collector_name} (TTL: {ttl_hours}h)")

            return success

        except Exception as e:
            logger.error(f"Error caching collector data for {collector_name}: {e}")
            return False

    def get_collector_cache(self, collector_name: str, max_age_hours: int = 6) -> list[dict[str, Any]] | None:
        """
        Retrieve cached collector data if fresh.

        Args:
            collector_name: Name of the collector
            max_age_hours: Maximum age of cache in hours

        Returns:
            List of cached records or None if not found/expired
        """
        cache_key = f"collector-{collector_name}-{datetime.now(UTC).strftime('%Y%m%d')}"

        try:
            cached = self.get_cache(cache_key, max_age_hours)

            if cached:
                data = cached.get("data", [])
                record_count = cached.get("record_count", len(data))
                collected_at = cached.get("collected_at", "unknown")

                logger.info(
                    f"Retrieved {record_count} cached records from {collector_name} (collected: {collected_at})"
                )

                return data

            return None

        except Exception as e:
            logger.error(f"Error retrieving collector cache for {collector_name}: {e}")
            return None

    def clear_old_caches(self, days_old: int = 7) -> int:
        """
        Clear cache entries older than specified days.

        Args:
            days_old: Delete caches older than this many days

        Returns:
            Number of caches deleted
        """
        try:
            container_client = self.blob_service_client.get_container_client(self.container_name)
            blobs = container_client.list_blobs()

            cutoff_date = datetime.now(UTC) - timedelta(days=days_old)
            deleted_count = 0

            for blob in blobs:
                if blob.last_modified < cutoff_date:
                    blob_client = self.blob_service_client.get_blob_client(
                        container=self.container_name, blob=blob.name
                    )
                    blob_client.delete_blob()
                    deleted_count += 1
                    logger.debug(f"Deleted old cache: {blob.name}")

            if deleted_count > 0:
                logger.info(f"Cleared {deleted_count} cache entries older than {days_old} days")

            return deleted_count

        except Exception as e:
            logger.error(f"Error clearing old caches: {e}")
            return 0
