"""
Core module containing shared configuration, models, and utilities.
"""

from src.core.config import (
    CollectorConfig,
    IndustryFilterConfig,
    EnrichmentConfig,
    AnalysisConfig,
    ReportConfig,
    AzureConfig,
    collector_config,
    industry_filter_config,
    enrichment_config,
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

try:
    from src.core.keyvault import get_secret, get_all_api_keys
except ImportError:
    get_secret = None
    get_all_api_keys = None

__all__ = [
    # Config classes
    "CollectorConfig",
    "IndustryFilterConfig",
    "EnrichmentConfig",
    "AnalysisConfig",
    "ReportConfig",
    "AzureConfig",
    # Config instances
    "collector_config",
    "industry_filter_config",
    "enrichment_config",
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
    # Key Vault
    "get_secret",
    "get_all_api_keys",
]
