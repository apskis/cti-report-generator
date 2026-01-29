"""
Core module containing shared configuration, models, and utilities.
"""

from src.core.config import (
    CollectorConfig,
    IndustryFilterConfig,
    AnalysisConfig,
    ReportConfig,
    AzureConfig,
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
    ReportResult,
)

# Keyvault imports are optional (require azure-keyvault-secrets)
try:
    from src.core.keyvault import get_secret, get_secrets_batch, get_all_api_keys
    _KEYVAULT_AVAILABLE = True
except ImportError:
    _KEYVAULT_AVAILABLE = False
    get_secret = None
    get_secrets_batch = None
    get_all_api_keys = None

__all__ = [
    # Config classes
    "CollectorConfig",
    "IndustryFilterConfig",
    "AnalysisConfig",
    "ReportConfig",
    "AzureConfig",
    # Config instances
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
    "ReportResult",
    # Key Vault (optional)
    "get_secret",
    "get_secrets_batch",
    "get_all_api_keys",
]
