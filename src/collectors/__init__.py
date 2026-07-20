"""
Collectors package for CTI Report Generator.

Provides modular threat intelligence collectors, each handling a single data source.

Available collectors:
    - nvd: NIST National Vulnerability Database
    - intel471: Intel471 Titan API
    - crowdstrike: CrowdStrike Falcon Intelligence
    - osint: Curated public RSS/Atom feeds

Configuration:
    Enable/disable collectors in config/collectors.yaml.
    Environment variable ENABLED_COLLECTORS overrides the YAML if set.
"""

from src.collectors.base import BaseCollector
from src.collectors.crowdstrike_collector import CrowdStrikeCollector
from src.collectors.intel471_collector import Intel471Collector
from src.collectors.nvd_collector import NVDCollector
from src.collectors.osint_collector import OSINTCollector
from src.collectors.registry import (
    COLLECTOR_REGISTRY,
    collect_all,
    get_collector,
    get_data_by_source,
    list_available_collectors,
)

__all__ = [
    # Base class
    "BaseCollector",
    # Collector implementations
    "NVDCollector",
    "Intel471Collector",
    "CrowdStrikeCollector",
    "OSINTCollector",
    # Registry functions
    "collect_all",
    "get_collector",
    "get_data_by_source",
    "list_available_collectors",
    "COLLECTOR_REGISTRY",
]
