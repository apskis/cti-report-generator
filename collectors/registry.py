"""
Collector registry for dynamic collector management.

Provides a central registry for all available collectors,
enabling easy addition/removal of data sources.
"""
import asyncio
import logging
from typing import Dict, Type, List, Any, Optional

from collectors.base import BaseCollector
from collectors.nvd_collector import NVDCollector
from collectors.intel471_collector import Intel471Collector
from collectors.crowdstrike_collector import CrowdStrikeCollector
from collectors.threatq_collector import ThreatQCollector
from collectors.rapid7_collector import Rapid7Collector
from config import get_enabled_collectors
from types import CollectorResult

logger = logging.getLogger(__name__)


# Registry of all available collectors
COLLECTOR_REGISTRY: Dict[str, Type[BaseCollector]] = {
    "nvd": NVDCollector,
    "intel471": Intel471Collector,
    "crowdstrike": CrowdStrikeCollector,
    "threatq": ThreatQCollector,
    "rapid7": Rapid7Collector,
}


def get_collector(name: str, credentials: Dict[str, str]) -> Optional[BaseCollector]:
    """
    Get a collector instance by name.

    Args:
        name: Collector name (lowercase)
        credentials: API credentials dictionary

    Returns:
        Collector instance or None if not found
    """
    collector_class = COLLECTOR_REGISTRY.get(name.lower())
    if collector_class:
        return collector_class(credentials)
    logger.warning(f"Unknown collector: {name}")
    return None


def get_all_collectors(credentials: Dict[str, str]) -> List[BaseCollector]:
    """
    Get instances of all registered collectors.

    Args:
        credentials: API credentials dictionary

    Returns:
        List of collector instances
    """
    return [
        collector_class(credentials)
        for collector_class in COLLECTOR_REGISTRY.values()
    ]


def get_enabled_collector_instances(credentials: Dict[str, str]) -> List[BaseCollector]:
    """
    Get instances of only enabled collectors.

    Uses ENABLED_COLLECTORS environment variable if set,
    otherwise returns all collectors.

    Args:
        credentials: API credentials dictionary

    Returns:
        List of enabled collector instances
    """
    enabled_names = get_enabled_collectors()
    collectors = []

    for name in enabled_names:
        collector = get_collector(name, credentials)
        if collector and collector.enabled:
            collectors.append(collector)
        elif collector and not collector.enabled:
            logger.info(f"Collector {name} is disabled")

    return collectors


async def collect_all(
    credentials: Dict[str, str],
    parallel: bool = True
) -> Dict[str, CollectorResult]:
    """
    Run all enabled collectors and return results.

    Args:
        credentials: API credentials dictionary
        parallel: Whether to run collectors in parallel (default: True)

    Returns:
        Dictionary mapping source name to CollectorResult
    """
    collectors = get_enabled_collector_instances(credentials)
    logger.info(f"Running {len(collectors)} collectors: {[c.source_name for c in collectors]}")

    results: Dict[str, CollectorResult] = {}

    if parallel:
        # Run all collectors in parallel
        tasks = [collector.safe_collect() for collector in collectors]
        collector_results = await asyncio.gather(*tasks)

        for collector, result in zip(collectors, collector_results):
            results[collector.source_name] = result
    else:
        # Run sequentially (useful for debugging)
        for collector in collectors:
            result = await collector.safe_collect()
            results[collector.source_name] = result

    # Log summary
    successful = sum(1 for r in results.values() if r.success)
    total_records = sum(r.record_count for r in results.values())
    logger.info(f"Collection complete: {successful}/{len(results)} sources successful, {total_records} total records")

    return results


def get_data_by_source(results: Dict[str, CollectorResult]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract data from collector results, organized by source.

    Args:
        results: Dictionary of CollectorResults

    Returns:
        Dictionary mapping source name to data list
    """
    return {
        source: result.data
        for source, result in results.items()
        if result.success
    }


def list_available_collectors() -> List[str]:
    """
    List all available collector names.

    Returns:
        List of collector names
    """
    return list(COLLECTOR_REGISTRY.keys())
