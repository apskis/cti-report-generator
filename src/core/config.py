"""
Configuration settings for CTI Report Generator.

This module contains all configurable application settings.
Sensitive values (API keys, secrets) should be stored in Azure Key Vault.
Infrastructure config (URLs, resource names) should be in environment variables.
Application settings (limits, timeouts, feature flags) are defined here.
"""
import os
from dataclasses import dataclass
from typing import List
from pathlib import Path

import yaml


@dataclass(frozen=True)
class CollectorConfig:
    """Configuration for data collectors."""

    # Lookback periods (days)
    nvd_lookback_days: int = 7
    intel471_lookback_days: int = 7
    intel471_quarterly_lookback_days: int = 90  # Quarter = 90 days
    crowdstrike_lookback_days: int = 7
    threatq_lookback_days: int = 7
    rapid7_lookback_days: int = 30

    # Result limits per source
    nvd_max_results: int = 100
    intel471_reports_limit: int = 50
    intel471_quarterly_reports_limit: int = 1000  # Higher limit for quarterly (fetching all report types)
    intel471_breach_alerts_limit: int = 100  # Higher limit for breach alerts (many available)
    intel471_indicators_limit: int = 20
    crowdstrike_actors_limit: int = 50
    crowdstrike_indicators_limit: int = 50
    crowdstrike_spotlight_limit: int = 200  # Max vulnerabilities from Spotlight for exposure counts
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
class EnrichmentConfig:
    """Configuration for data enrichment."""
    
    # Enable/disable web search for filling data gaps
    # When enabled, will search the web for missing CVE product information
    # When disabled, uses only CISA KEV catalog and pattern matching
    enable_web_search: bool = True
    
    # Web search settings
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10  # Limit to avoid excessive API calls
    
    # CISA KEV cache duration (hours)
    kev_cache_duration_hours: int = 24


@dataclass(frozen=True)
class AnalysisConfig:
    """Configuration for threat analysis."""

    # AI model deployment name
    deployment_name: str = "gpt-4.1-cti"

    # Data truncation limits for AI analysis
    max_cves_for_analysis: int = 50
    max_intel471_for_analysis: int = 30
    max_crowdstrike_for_analysis: int = 30
    max_threatq_for_analysis: int = 30
    max_rapid7_for_analysis: int = 20



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

    Key Vault URL is required via environment variable.
    All other secrets (API keys, storage, OpenAI endpoint) are retrieved from Key Vault.
    Production defaults are documented for reference.
    """

    @staticmethod
    def get_key_vault_url() -> str:
        """
        Get Key Vault URL from environment variable.

        This is the ONLY secret-related config stored in environment.
        All actual secrets are retrieved from Key Vault.

        Raises:
            EnvironmentError: If KEY_VAULT_URL is not set.
        """
        url = os.environ.get("KEY_VAULT_URL")
        if not url:
            raise EnvironmentError(
                "KEY_VAULT_URL environment variable is not set. "
                "Set it to your Azure Key Vault URL, e.g. 'https://kv-cti-rep-prod.vault.azure.net/'"
            )
        return url


# Global configuration instances
collector_config = CollectorConfig()
industry_filter_config = IndustryFilterConfig()
enrichment_config = EnrichmentConfig()
analysis_config = AnalysisConfig()
report_config = ReportConfig()
azure_config = AzureConfig()


_COLLECTORS_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "collectors.yaml"


def _load_collectors_from_yaml() -> List[str]:
    """Read config/collectors.yaml and return names of enabled collectors."""
    if not _COLLECTORS_YAML.exists():
        raise FileNotFoundError(
            f"Collectors config not found: {_COLLECTORS_YAML}\n"
            "Please create config/collectors.yaml to define your enabled collectors."
        )
    with open(_COLLECTORS_YAML, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    collectors = cfg.get("collectors", [])
    if not collectors:
        raise ValueError(
            f"No collectors defined in {_COLLECTORS_YAML}\n"
            "Add at least one collector with 'enabled: true'."
        )
    return [c["name"] for c in collectors if c.get("enabled", True)]


def get_enabled_collectors() -> List[str]:
    """
    Get list of enabled collectors.

    Priority order:
      1. ENABLED_COLLECTORS environment variable (comma-separated)
      2. config/collectors.yaml (enabled: true/false per collector)
    """
    env = os.environ.get("ENABLED_COLLECTORS", "")
    if env:
        return [c.strip().lower() for c in env.split(",")]
    return _load_collectors_from_yaml()
