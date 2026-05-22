"""
Local File Cache for Rapid7 - Testing/Development Use

This provides a simple file-based cache for Rapid7 data during testing,
so you don't have to wait 20 minutes for exports every time.

Usage:
1. Run a full export once (wait 20 min): python cache_rapid7_local.py --fetch
2. Use cached data for testing: Already automatic!
3. Refresh cache when needed: python cache_rapid7_local.py --fetch
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Cache file location
CACHE_DIR = Path(__file__).parent / ".cache"
CACHE_FILE = CACHE_DIR / "rapid7_local_cache.json"


class LocalCacheManager:
    """Simple file-based cache for local testing."""
    
    def __init__(self):
        """Initialize cache manager."""
        # Ensure cache directory exists
        CACHE_DIR.mkdir(exist_ok=True)
    
    def get_cache(self, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """
        Get cached data if it exists and is fresh.
        
        Args:
            max_age_hours: Maximum age of cache in hours (default: 24)
            
        Returns:
            Cached data dict or None if not found/expired
        """
        if not CACHE_FILE.exists():
            logger.info(f"Local cache not found: {CACHE_FILE}")
            return None
        
        try:
            # Read cache file
            with open(CACHE_FILE, 'r') as f:
                cache_data = json.load(f)
            
            # Check timestamp
            cached_at_str = cache_data.get('cached_at')
            if not cached_at_str:
                logger.warning("Cache missing timestamp")
                return None
            
            cached_at = datetime.fromisoformat(cached_at_str)
            age = datetime.now(timezone.utc) - cached_at
            max_age = timedelta(hours=max_age_hours)
            
            if age > max_age:
                logger.info(f"Local cache expired (age: {age}, max: {max_age})")
                return None
            
            logger.info(f"✓ Using local cache: {cache_data.get('record_count', 0)} CVEs (age: {age})")
            logger.info(f"  Cache file: {CACHE_FILE}")
            
            return cache_data.get('data')
            
        except Exception as e:
            logger.error(f"Error reading local cache: {e}")
            return None
    
    def set_cache(self, data: Dict[str, Any]) -> bool:
        """
        Store data in local cache.
        
        Args:
            data: Data to cache (must be JSON serializable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cache_data = {
                'cached_at': datetime.now(timezone.utc).isoformat(),
                'record_count': len(data.get('cve_exposure_map', {})),
                'data': data
            }
            
            # Write to file
            with open(CACHE_FILE, 'w') as f:
                json.dump(cache_data, f, indent=2, default=str)
            
            logger.info(f"✓ Local cache updated: {cache_data['record_count']} CVEs")
            logger.info(f"  Cache file: {CACHE_FILE}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error writing local cache: {e}")
            return False
    
    def clear_cache(self) -> bool:
        """Delete local cache file."""
        try:
            if CACHE_FILE.exists():
                CACHE_FILE.unlink()
                logger.info(f"✓ Local cache cleared: {CACHE_FILE}")
                return True
            else:
                logger.info("No local cache to clear")
                return False
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False
    
    def cache_info(self) -> Dict[str, Any]:
        """Get information about cache status."""
        if not CACHE_FILE.exists():
            return {
                'exists': False,
                'path': str(CACHE_FILE)
            }
        
        try:
            with open(CACHE_FILE, 'r') as f:
                cache_data = json.load(f)
            
            cached_at = datetime.fromisoformat(cache_data.get('cached_at'))
            age = datetime.now(timezone.utc) - cached_at
            
            return {
                'exists': True,
                'path': str(CACHE_FILE),
                'cached_at': cache_data.get('cached_at'),
                'age_hours': age.total_seconds() / 3600,
                'record_count': cache_data.get('record_count', 0),
                'size_mb': CACHE_FILE.stat().st_size / (1024 * 1024)
            }
        except Exception as e:
            return {
                'exists': True,
                'path': str(CACHE_FILE),
                'error': str(e)
            }


# Global instance for easy import
local_cache = LocalCacheManager()


if __name__ == "__main__":
    import sys
    import argparse
    import asyncio
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Manage local Rapid7 cache for testing')
    parser.add_argument('--fetch', action='store_true', help='Fetch fresh data from Rapid7 API')
    parser.add_argument('--clear', action='store_true', help='Clear local cache')
    parser.add_argument('--info', action='store_true', help='Show cache information')
    
    args = parser.parse_args()
    
    if args.clear:
        local_cache.clear_cache()
        sys.exit(0)
    
    if args.info:
        info = local_cache.cache_info()
        print("\n" + "="*60)
        print("LOCAL CACHE STATUS")
        print("="*60)
        
        if info['exists']:
            print(f"✓ Cache exists: {info['path']}")
            if 'error' not in info:
                print(f"  Cached at: {info['cached_at']}")
                print(f"  Age: {info['age_hours']:.1f} hours")
                print(f"  Records: {info['record_count']} CVEs")
                print(f"  Size: {info['size_mb']:.2f} MB")
            else:
                print(f"  Error: {info['error']}")
        else:
            print(f"✗ No cache found: {info['path']}")
        print()
        sys.exit(0)
    
    if args.fetch:
        print("\n" + "="*60)
        print("FETCHING RAPID7 DATA")
        print("="*60)
        print("\nThis will take 10-20 minutes...")
        print("The data will be cached locally for fast testing.\n")
        
        async def fetch_and_cache():
            from src.collectors.rapid7_bulk_export_collector import Rapid7BulkExportCollector
            from src.core.keyvault import get_credentials
            
            # Get credentials
            credentials = get_credentials(enabled_collectors=['rapid7-bulk-export'])
            
            # Remove storage credentials to force API fetch (no Blob cache)
            credentials_no_cache = credentials.copy()
            credentials_no_cache.pop('storage_account_name', None)
            credentials_no_cache.pop('storage_account_key', None)
            
            # Create collector
            collector = Rapid7BulkExportCollector(credentials_no_cache, report_type='weekly')
            
            # Fetch data
            print("Fetching from Rapid7 API...")
            result = await collector.collect(report_type='weekly')
            
            if result.success and result.record_count > 0:
                # Cache the data
                data = result.data[0] if result.data else {}
                if local_cache.set_cache(data):
                    print(f"\n✓ Success! Cached {result.record_count} CVEs locally")
                    print(f"  Cache file: {CACHE_FILE}")
                    print("\nYou can now run reports instantly using:")
                    print("  python test_local.py weekly --local --real")
                else:
                    print("\n✗ Failed to cache data")
            else:
                print(f"\n✗ Collection failed: {result.error if hasattr(result, 'error') else 'Unknown error'}")
        
        asyncio.run(fetch_and_cache())
        sys.exit(0)
    
    # No args - show usage
    parser.print_help()
