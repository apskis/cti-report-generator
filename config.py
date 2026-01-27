"""
Configuration settings for CTI Report Generator.

This module contains all configurable application settings.
Sensitive values (API keys, secrets) should be stored in Azure Key Vault.
Infrastructure config (URLs, resource names) should be in environment variables.
Application settings (limits, timeouts, feature flags) are defined here.
"""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class CollectorConfig:
    """Configuration for data collectors."""

    # Lookback periods (days)
    nvd_lookback_days: int = 7
    intel471_lookback_days: int = 7
    crowdstrike_lookback_days: int = 7
    threatq_lookback_days: int = 7
    rapid7_lookback_days: int = 30

    # Result limits per source
    nvd_max_results: int = 100
    intel471_reports_limit: int = 50
    intel471_indicators_limit: int = 20
    crowdstrike_actors_limit: int = 50
    crowdstrike_indicators_limit: int = 50
    threatq_indicators_limit: int = 100
    rapid7_max_results: int = 500

    # Minimum score thresholds
    threatq_min_score: int = 7

    # Retry settings
    max_retries: int = 3
    retry_base_delay_seconds: float = 1.0
    retry_max_delay_seconds: float = 30.0

    # HTTP timeout (seconds)
    http_timeout_seconds: int = 30


@dataclass(frozen=True)
class IndustryFilterConfig:
    """Keywords and industries for filtering relevant threats."""

    # Keywords for biotech/healthcare filtering
    biotech_keywords: tuple = (
        "biotech", "genomics", "healthcare", "hospital", "medical",
        "pharmaceutical", "life sciences", "research", "clinical",
        "patient", "health", "laboratory", "diagnostics", "bioinformatics",
        "genetic", "therapy", "drug", "vaccine", "clinical trial"
    )

    # Target industries for CrowdStrike filtering
    target_industries: tuple = (
        "Technology", "Healthcare", "Pharmaceutical",
        "Life Sciences", "Biotechnology", "Medical Devices",
        "Research", "Education", "Manufacturing"
    )


@dataclass(frozen=True)
class AnalysisConfig:
    """Configuration for threat analysis."""

    # AI model deployment name
    deployment_name: str = "gpt-5.2-cti"

    # Data truncation limits for AI analysis
    max_cves_for_analysis: int = 50
    max_intel471_for_analysis: int = 30
    max_crowdstrike_for_analysis: int = 30
    max_threatq_for_analysis: int = 30
    max_rapid7_for_analysis: int = 20

    # Token limits
    max_completion_tokens: int = 4000


@dataclass(frozen=True)
class ReportConfig:
    """Configuration for report generation."""

    # Blob storage settings
    container_name: str = "reports"
    sas_expiry_days: int = 7

    # Document styling
    table_style: str = "Light Grid Accent 1"


@dataclass(frozen=True)
class AzureConfig:
    """
    Azure infrastructure configuration.

    Only the Key Vault URL is stored in environment variables.
    All secrets (API keys, storage credentials) are stored in Key Vault.
    """

    @staticmethod
    def get_key_vault_url() -> str:
        """
        Get Key Vault URL from environment variable.

        This is the ONLY secret-related config stored in environment.
        All actual secrets are retrieved from Key Vault.
        """
        return os.environ.get("KEY_VAULT_URL", "https://kv-cti-reporting.vault.azure.net/")


# Global configuration instances
collector_config = CollectorConfig()
industry_filter_config = IndustryFilterConfig()
analysis_config = AnalysisConfig()
report_config = ReportConfig()
azure_config = AzureConfig()


def get_enabled_collectors() -> List[str]:
    """
    Get list of enabled collectors.
    Can be configured via ENABLED_COLLECTORS environment variable.
    Default: all collectors enabled.
    """
    enabled = os.environ.get("ENABLED_COLLECTORS", "")
    if enabled:
        return [c.strip().lower() for c in enabled.split(",")]
    # ThreatQ disabled - secrets not configured yet
    return ["nvd", "intel471", "crowdstrike", "rapid7"]
