"""
Collectors package for CTI Report Generator.

This package provides modular threat intelligence collectors,
each handling a single data source.

Usage:
    from collectors import collect_all, get_collector

    # Collect from all enabled sources
    results = await collect_all(credentials)

    # Get a specific collector
    nvd = get_collector("nvd", credentials)
    result = await nvd.collect()

Available collectors:
    - nvd: NIST National Vulnerability Database
    - intel471: Intel471 Titan API
    - crowdstrike: CrowdStrike Falcon Intelligence
    - threatq: ThreatQ threat intelligence platform
    - rapid7: Rapid7 InsightVM

Configuration:
    Set ENABLED_COLLECTORS environment variable to control which
    collectors are active (comma-separated list).
    Example: ENABLED_COLLECTORS=nvd,crowdstrike,rapid7
"""

from src.collectors.base import BaseCollector
from src.collectors.nvd_collector import NVDCollector
from src.collectors.intel471_collector import Intel471Collector
from src.collectors.crowdstrike_collector import CrowdStrikeCollector
from src.collectors.threatq_collector import ThreatQCollector
from src.collectors.rapid7_collector import Rapid7Collector
from src.collectors.registry import (
    collect_all,
    get_collector,
    get_all_collectors,
    get_enabled_collector_instances,
    get_data_by_source,
    list_available_collectors,
    COLLECTOR_REGISTRY,
)

__all__ = [
    # Base class
    "BaseCollector",
    # Collector implementations
    "NVDCollector",
    "Intel471Collector",
    "CrowdStrikeCollector",
    "ThreatQCollector",
    "Rapid7Collector",
    # Registry functions
    "collect_all",
    "get_collector",
    "get_all_collectors",
    "get_enabled_collector_instances",
    "get_data_by_source",
    "list_available_collectors",
    "COLLECTOR_REGISTRY",
]
