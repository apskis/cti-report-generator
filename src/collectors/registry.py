"""
Collector registry for dynamic collector management.

Provides a central registry for all available collectors,
enabling easy addition/removal of data sources.
"""

import asyncio
import logging
from typing import Any

from src.collectors.base import BaseCollector
from src.collectors.claroty_collector import ClarotyCollector
from src.collectors.crowdstrike_collector import CrowdStrikeCollector
from src.collectors.hhs_breach_collector import HHSBreachCollector
from src.collectors.hibp_breach_collector import HIBPBreachCollector
from src.collectors.ics_advisory_collector import ICSAdvisoryCollector
from src.collectors.illumina_osint_collector import IlluminaOSINTCollector
from src.collectors.intel471_collector import Intel471Collector
from src.collectors.news_search_collector import NewsSearchCollector
from src.collectors.nvd_collector import NVDCollector
from src.collectors.osint_collector import OSINTCollector
from src.collectors.ransomware_live_collector import RansomwareLiveCollector
from src.collectors.vcdb_collector import VCDBCollector
from src.core.config import get_enabled_collectors
from src.core.models import CollectorResult

logger = logging.getLogger(__name__)


# Registry of all available collectors
COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "nvd": NVDCollector,
    "intel471": Intel471Collector,
    "crowdstrike": CrowdStrikeCollector,
    "osint": OSINTCollector,
    "ics_advisory": ICSAdvisoryCollector,
    "claroty": ClarotyCollector,
    "illumina_osint": IlluminaOSINTCollector,
    "news_search": NewsSearchCollector,
    "vcdb": VCDBCollector,
    "hhs_breach": HHSBreachCollector,
    "hibp_breach": HIBPBreachCollector,
    "ransomware_live": RansomwareLiveCollector,
}


def get_collector(
    name: str,
    credentials: dict[str, str],
    report_type: str = "weekly",
    collection_window: tuple | None = None,
) -> BaseCollector | None:
    """
    Get a collector instance by name.

    Args:
        name: Collector name (lowercase)
        credentials: API credentials dictionary
        report_type: Report type ("weekly"/"quarterly")
        collection_window: Optional explicit ``(start, end)`` window for historical backfill.

    Returns:
        Collector instance or None if not found
    """
    collector_class = COLLECTOR_REGISTRY.get(name.lower())
    if collector_class:
        return collector_class(credentials, report_type=report_type, collection_window=collection_window)
    logger.warning(f"Unknown collector: {name}")
    return None


def get_enabled_collector_instances(
    credentials: dict[str, str],
    report_type: str = "weekly",
    collection_window: tuple | None = None,
    collector_names: list[str] | None = None,
) -> list[BaseCollector]:
    """
    Get instances of only enabled collectors.

    Uses ENABLED_COLLECTORS environment variable if set,
    otherwise returns all collectors.

    Args:
        credentials: API credentials dictionary
        report_type: Report type ("weekly"/"quarterly")
        collection_window: Optional explicit ``(start, end)`` window for historical backfill.
        collector_names: Explicit collector name list, overriding the configured enabled set
            (used by prior-quarter backfill to force in the ``news_search`` archive source).

    Returns:
        List of enabled collector instances
    """
    enabled_names = collector_names if collector_names is not None else get_enabled_collectors()
    collectors = []

    for name in enabled_names:
        collector = get_collector(name, credentials, report_type=report_type, collection_window=collection_window)
        if collector and collector.enabled:
            collectors.append(collector)
        elif collector and not collector.enabled:
            logger.info(f"Collector {name} is disabled")

    return collectors


async def collect_all(
    credentials: dict[str, str],
    parallel: bool = True,
    report_type: str = "weekly",
    collection_window: tuple | None = None,
    collector_names: list[str] | None = None,
) -> dict[str, CollectorResult]:
    """
    Run all enabled collectors and return results.

    Args:
        credentials: API credentials dictionary
        parallel: Whether to run collectors in parallel (default: True)
        report_type: Report type ("weekly"/"quarterly")
        collection_window: Optional explicit ``(start, end)`` window for historical backfill.
        collector_names: Explicit collector name list, overriding the configured enabled set.

    Returns:
        Dictionary mapping source name to CollectorResult
    """
    collectors = get_enabled_collector_instances(
        credentials, report_type=report_type, collection_window=collection_window, collector_names=collector_names
    )
    logger.info(
        f"Running {len(collectors)} collectors: {[c.source_name for c in collectors]} (report_type: {report_type})"
    )

    results: dict[str, CollectorResult] = {}

    if parallel:
        # Run all collectors in parallel, passing report_type
        tasks = [collector.safe_collect(report_type=report_type) for collector in collectors]
        collector_results = await asyncio.gather(*tasks)

        for collector, result in zip(collectors, collector_results, strict=True):
            results[collector.source_name] = result
    else:
        # Run sequentially (useful for debugging)
        for collector in collectors:
            result = await collector.safe_collect(report_type=report_type)
            results[collector.source_name] = result

    # Log summary
    successful = sum(1 for r in results.values() if r.success)
    total_records = sum(r.record_count for r in results.values())
    logger.info(f"Collection complete: {successful}/{len(results)} sources successful, {total_records} total records")

    return results


def get_data_by_source(results: dict[str, CollectorResult]) -> dict[str, list[dict[str, Any]]]:
    """
    Extract data from collector results, organized by source.

    Args:
        results: Dictionary of CollectorResults

    Returns:
        Dictionary mapping source name to data list
    """
    return {source: result.data for source, result in results.items() if result.success}


def list_available_collectors() -> list[str]:
    """
    List all available collector names.

    Returns:
        List of collector names
    """
    return list(COLLECTOR_REGISTRY.keys())
