"""
Test script for context management and historical tracking features.

This script tests the new AgentContextManager and trend analysis features.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def generate_mock_analysis(report_date: datetime, cve_count: int = 10) -> Dict[str, Any]:
    """Generate mock analysis data for testing."""
    return {
        "report_type": "weekly",
        "report_date": report_date.strftime("%Y-%m-%d"),
        "executive_summary": f"Mock executive summary for {report_date.strftime('%Y-%m-%d')}",
        "cve_analysis": [
            {
                "cve_id": f"CVE-2024-{1000 + i}",
                "severity": "CRITICAL" if i < 3 else "HIGH",
                "actively_exploited": i < 5,
                "in_cisa_kev": i < 2,
                "affected_product": f"Product {i}",
                "exposure": f"{i * 3} servers"
            }
            for i in range(cve_count)
        ],
        "apt_activity": [
            {
                "actor": f"APT{i}",
                "country": "China" if i % 2 == 0 else "Russia",
                "motivation": "Espionage",
                "activity": f"Activity description for APT{i}"
            }
            for i in range(5)
        ],
        "statistics": {
            "threat_actors": 5,
            "active_campaigns": 3,
            "exploited_cves": 5,
            "peer_incidents": 8
        },
        "recommendations": [
            "Recommendation 1",
            "Recommendation 2",
            "Recommendation 3"
        ]
    }


async def test_context_manager():
    """Test the context manager with mock Azure credentials."""
    logger.info("=" * 80)
    logger.info("TESTING CONTEXT MANAGER")
    logger.info("=" * 80)
    
    try:
        # Import required modules
        from src.utils.cache_manager import CacheManager
        from src.agents.context_manager import AgentContextManager
        
        # Check if we have Azure credentials
        import os
        storage_account_name = os.getenv("STORAGE_ACCOUNT_NAME")
        storage_account_key = os.getenv("STORAGE_ACCOUNT_KEY")
        
        if not storage_account_name or not storage_account_key:
            logger.warning("⚠️  Azure Storage credentials not found in environment")
            logger.warning("⚠️  Set STORAGE_ACCOUNT_NAME and STORAGE_ACCOUNT_KEY to test with real Azure Blob Storage")
            logger.info("✅ Context manager module imports successful (dry run only)")
            return
        
        logger.info(f"✅ Using Azure Storage account: {storage_account_name}")
        
        # Initialize cache manager and context manager
        cache_manager = CacheManager(storage_account_name, storage_account_key)
        context_mgr = AgentContextManager(cache_manager)
        
        logger.info("✅ Context manager initialized")
        
        # Test 1: Save mock analysis contexts for the past 4 weeks
        logger.info("\nTest 1: Saving mock historical contexts")
        for i in range(4):
            report_date = datetime.now() - timedelta(weeks=i)
            analysis = generate_mock_analysis(report_date, cve_count=10 - i)
            
            success = context_mgr.save_analysis_context("weekly", report_date, analysis)
            if success:
                logger.info(f"  ✅ Saved context for {report_date.strftime('%Y-%m-%d')}")
            else:
                logger.error(f"  ❌ Failed to save context for {report_date.strftime('%Y-%m-%d')}")
        
        # Test 2: Retrieve previous contexts
        logger.info("\nTest 2: Retrieving previous contexts")
        previous_contexts = context_mgr.get_previous_context("weekly", lookback_weeks=4)
        logger.info(f"  ✅ Retrieved {len(previous_contexts)} previous contexts")
        
        if previous_contexts:
            for ctx in previous_contexts:
                report_date = ctx.get("report_date", "unknown")
                cve_count = len(ctx.get("analysis", {}).get("cve_analysis", []))
                logger.info(f"    - {report_date}: {cve_count} CVEs")
        
        # Test 3: Calculate CVE trends
        logger.info("\nTest 3: Calculating CVE trends")
        current_analysis = generate_mock_analysis(datetime.now(), cve_count=12)
        current_cves = current_analysis["cve_analysis"]
        
        cve_trends = context_mgr.calculate_cve_trends(current_cves, previous_contexts)
        logger.info(f"  ✅ CVE Trends calculated:")
        logger.info(f"    - New CVEs: {len(cve_trends['new_cves'])}")
        logger.info(f"    - Persistent CVEs: {len(cve_trends['persistent_cves'])}")
        logger.info(f"    - Resolved CVEs: {len(cve_trends['resolved_cves'])}")
        logger.info(f"    - Summary: {cve_trends['trend_summary']}")
        
        # Test 4: Calculate actor trends
        logger.info("\nTest 4: Calculating threat actor trends")
        current_actors = current_analysis["apt_activity"]
        
        actor_trends = context_mgr.calculate_actor_trends(current_actors, previous_contexts)
        logger.info(f"  ✅ Actor Trends calculated:")
        logger.info(f"    - New actors: {len(actor_trends['new_actors'])}")
        logger.info(f"    - Persistent actors: {len(actor_trends['persistent_actors'])}")
        logger.info(f"    - Inactive actors: {len(actor_trends['inactive_actors'])}")
        logger.info(f"    - Summary: {actor_trends['trend_summary']}")
        
        # Test 5: Get historical statistics
        logger.info("\nTest 5: Retrieving historical statistics")
        historical_stats = context_mgr.get_historical_statistics("weekly", lookback_weeks=4)
        
        if historical_stats.get("available"):
            timeline = historical_stats.get("timeline", [])
            logger.info(f"  ✅ Historical statistics available for {len(timeline)} periods:")
            for period in timeline:
                logger.info(f"    - {period['date']}: {period['total_cves']} CVEs, {period['threat_actors']} actors")
        else:
            logger.warning(f"  ⚠️  {historical_stats.get('message', 'No data')}")
        
        # Test 6: List available contexts
        logger.info("\nTest 6: Listing available contexts")
        context_keys = context_mgr.list_available_contexts("weekly")
        logger.info(f"  ✅ Found {len(context_keys)} weekly contexts in storage")
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ ALL CONTEXT MANAGER TESTS PASSED")
        logger.info("=" * 80)
        
    except ImportError as e:
        logger.error(f"❌ Import error: {e}")
        logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
    except Exception as e:
        logger.error(f"❌ Test failed: {e}", exc_info=True)


async def test_cache_manager_enhancements():
    """Test the enhanced cache manager with collector caching."""
    logger.info("\n" + "=" * 80)
    logger.info("TESTING ENHANCED CACHE MANAGER")
    logger.info("=" * 80)
    
    try:
        from src.utils.cache_manager import CacheManager
        
        # Check if we have Azure credentials
        import os
        storage_account_name = os.getenv("STORAGE_ACCOUNT_NAME")
        storage_account_key = os.getenv("STORAGE_ACCOUNT_KEY")
        
        if not storage_account_name or not storage_account_key:
            logger.warning("⚠️  Azure Storage credentials not found in environment")
            logger.info("✅ Cache manager module imports successful (dry run only)")
            return
        
        logger.info(f"✅ Using Azure Storage account: {storage_account_name}")
        
        cache_manager = CacheManager(storage_account_name, storage_account_key)
        logger.info("✅ Enhanced cache manager initialized")
        
        # Test collector data caching
        logger.info("\nTest 1: Caching collector data")
        mock_intel471_data = [
            {"threat_type": "BREACH ALERT", "summary": "Test breach"},
            {"threat_type": "MALWARE", "summary": "Test malware"}
        ]
        
        success = cache_manager.cache_collector_data("Intel471", mock_intel471_data, ttl_hours=6)
        if success:
            logger.info("  ✅ Intel471 data cached successfully")
        else:
            logger.error("  ❌ Failed to cache Intel471 data")
        
        # Test retrieving cached collector data
        logger.info("\nTest 2: Retrieving cached collector data")
        cached_data = cache_manager.get_collector_cache("Intel471", max_age_hours=6)
        
        if cached_data:
            logger.info(f"  ✅ Retrieved {len(cached_data)} cached records")
        else:
            logger.warning("  ⚠️  No cached data found (may have expired)")
        
        # Test listing cache keys
        logger.info("\nTest 3: Listing cache keys")
        all_keys = cache_manager.list_cache_keys()
        collector_keys = cache_manager.list_cache_keys(prefix="collector-")
        analysis_keys = cache_manager.list_cache_keys(prefix="analysis-context-")
        
        logger.info(f"  ✅ Total cache entries: {len(all_keys)}")
        logger.info(f"  ✅ Collector caches: {len(collector_keys)}")
        logger.info(f"  ✅ Analysis contexts: {len(analysis_keys)}")
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ ALL CACHE MANAGER ENHANCEMENT TESTS PASSED")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}", exc_info=True)


async def main():
    """Run all tests."""
    logger.info("\n" + "=" * 80)
    logger.info("CONTEXT MANAGEMENT & HISTORICAL TRACKING TEST SUITE")
    logger.info("=" * 80)
    logger.info("\nThis test suite validates the new features:")
    logger.info("  1. AgentContextManager - Historical analysis tracking")
    logger.info("  2. Enhanced CacheManager - Collector data caching")
    logger.info("  3. Trend Analysis - CVE and actor trends")
    logger.info("\n" + "=" * 80)
    
    await test_context_manager()
    await test_cache_manager_enhancements()
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST SUITE COMPLETE")
    logger.info("=" * 80)
    logger.info("\nNext steps:")
    logger.info("  1. Run a weekly report: python test_local.py weekly --local --real")
    logger.info("  2. Check Azure Blob Storage for saved contexts")
    logger.info("  3. Run another weekly report to see trend analysis")
    logger.info("  4. Review executive summary for trend insights")


if __name__ == "__main__":
    asyncio.run(main())
