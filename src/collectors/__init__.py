"""
Collectors package for CTI Report Generator.

Provides modular threat intelligence collectors, each handling a single data source.

Available collectors:
    - nvd: NIST National Vulnerability Database
    - intel471: Intel471 Titan API
    - crowdstrike: CrowdStrike Falcon Intelligence
    - threatq: ThreatQ threat intelligence platform
    - rapid7: Rapid7 InsightVM (vulnerability definitions & enrichment)
    - rapid7-scans: Rapid7 InsightVM (asset vulnerability exposure data)
    - osint: Curated public RSS/Atom feeds

Configuration:
    Enable/disable collectors in config/collectors.yaml.
    Environment variable ENABLED_COLLECTORS overrides the YAML if set.
"""

from src.collectors.base import BaseCollector
from src.collectors.nvd_collector import NVDCollector
from src.collectors.intel471_collector import Intel471Collector
from src.collectors.crowdstrike_collector import CrowdStrikeCollector
from src.collectors.threatq_collector import ThreatQCollector
from src.collectors.rapid7_collector import Rapid7Collector
from src.collectors.rapid7_scan_collector import Rapid7ScanCollector
from src.collectors.osint_collector import OSINTCollector
from src.collectors.registry import (
    collect_all,
    get_collector,
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
    "Rapid7ScanCollector",
    "OSINTCollector",
    # Registry functions
    "collect_all",
    "get_collector",
    "get_data_by_source",
    "list_available_collectors",
    "COLLECTOR_REGISTRY",
]
