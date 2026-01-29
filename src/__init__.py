"""
CTI Report Generator - Source Package.

This package contains all core functionality for the CTI Report Generator:
- collectors: Data collection from threat intelligence sources
- reports: Report generation (weekly, quarterly, etc.)
- agents: AI-powered threat analysis
- core: Shared configuration, models, and utilities
"""

from src.core.config import (
    collector_config,
    industry_filter_config,
    analysis_config,
    report_config,
    azure_config,
    get_enabled_collectors,
)
from src.core.models import (
    CVERecord,
    ThreatReport,
    APTActor,
    ThreatIndicator,
    VulnerabilitySummary,
    ThreatAnalysisResult,
    CollectorResult,
)

__all__ = [
    # Config
    "collector_config",
    "industry_filter_config",
    "analysis_config",
    "report_config",
    "azure_config",
    "get_enabled_collectors",
    # Models
    "CVERecord",
    "ThreatReport",
    "APTActor",
    "ThreatIndicator",
    "VulnerabilitySummary",
    "ThreatAnalysisResult",
    "CollectorResult",
]
