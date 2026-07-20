"""
Core module containing shared configuration, models, and utilities.
"""

from src.core.config import (
    AnalysisConfig,
    AzureConfig,
    CollectorConfig,
    EnrichmentConfig,
    IndustryFilterConfig,
    ReportConfig,
    analysis_config,
    azure_config,
    collector_config,
    enrichment_config,
    get_enabled_collectors,
    industry_filter_config,
    report_config,
)
from src.core.models import (
    APTActor,
    CollectorResult,
    CVERecord,
    ThreatAnalysisResult,
    ThreatReport,
)

try:
    from src.core.keyvault import get_all_api_keys, get_secret
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
    "ThreatAnalysisResult",
    "CollectorResult",
    # Key Vault
    "get_secret",
    "get_all_api_keys",
]
