"""
Azure Function: Rapid7 Data Sync Timer

Automatically fetches Rapid7 vulnerability data every 6 hours and caches it
to Blob Storage for instant report generation.

Trigger: Timer (0 */6 * * * - every 6 hours)
"""
import logging
import json
import azure.functions as func
from datetime import datetime, timezone

from src.collectors.rapid7_bulk_export_collector import Rapid7BulkExportCollector
from src.core.keyvault import get_credentials
from src.utils.cache_manager import CacheManager

logger = logging.getLogger(__name__)


async def main(timer: func.TimerRequest) -> None:
    """
    Timer-triggered function to sync Rapid7 data.
    
    Runs every 6 hours to keep vulnerability data fresh in cache.
    """
    utc_timestamp = datetime.now(timezone.utc).isoformat()
    
    if timer.past_due:
        logger.warning('Timer is past due - executing anyway')
    
    logger.info(f'Rapid7 sync function started at {utc_timestamp}')
    
    try:
        # Get credentials from Key Vault
        credentials = get_credentials(enabled_collectors=['rapid7-bulk-export'])
        
        # Initialize cache manager
        storage_account_name = credentials.get('storage_account_name', '')
        storage_account_key = credentials.get('storage_account_key', '')
        cache_manager = CacheManager(storage_account_name, storage_account_key)
        
        # Initialize Rapid7 collector
        collector = Rapid7BulkExportCollector(credentials, report_type='weekly')
        
        # Run collection (this will take 10-20 minutes for large environments)
        logger.info('Starting Rapid7 bulk export collection...')
        result = await collector.collect(report_type='weekly')
        
        if result.success and result.record_count > 0:
            # Extract the CVE exposure map from result data
            if result.data and len(result.data) > 0:
                cve_data = result.data[0]  # First element contains the CVE exposure map
                
                # Cache the data
                cache_key = "rapid7-bulk-export-latest"
                if cache_manager.set_cache(cache_key, cve_data):
                    logger.info(f'Successfully cached {result.record_count} CVEs from Rapid7')
                    logger.info(f'Cache key: {cache_key}')
                else:
                    logger.error('Failed to cache Rapid7 data')
            else:
                logger.warning('No data in collection result')
        else:
            error_msg = result.error if hasattr(result, 'error') else 'Unknown error'
            logger.error(f'Rapid7 collection failed: {error_msg}')
        
        logger.info(f'Rapid7 sync function completed at {datetime.now(timezone.utc).isoformat()}')
        
    except Exception as e:
        logger.error(f'Error in Rapid7 sync function: {e}', exc_info=True)
        raise
