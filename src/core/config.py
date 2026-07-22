"""
Configuration settings for CTI Report Generator.

This module contains all configurable application settings.
Sensitive values (API keys, secrets) should be stored in Azure Key Vault.
Infrastructure config (URLs, resource names) should be in environment variables.
Application settings (limits, timeouts, feature flags) are defined here.
"""

import os
from dataclasses import dataclass, field
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

    # Result limits per source
    nvd_max_results: int = 100
    intel471_reports_limit: int = 50
    intel471_quarterly_reports_limit: int = 1000  # Higher limit for quarterly (fetching all report types)
    intel471_breach_alerts_limit: int = 100  # Higher limit for breach alerts (many available)
    intel471_indicators_limit: int = 20
    crowdstrike_actors_limit: int = 50
    crowdstrike_indicators_limit: int = 50
    crowdstrike_spotlight_limit: int = 200  # Max vulnerabilities from Spotlight for exposure counts

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
        "biotech",
        "genomics",
        "healthcare",
        "hospital",
        "medical",
        "pharmaceutical",
        "life sciences",
        "research",
        "clinical",
        "patient",
        "health",
        "laboratory",
        "diagnostics",
        "bioinformatics",
        "genetic",
        "therapy",
        "drug",
        "vaccine",
        "clinical trial",
    )

    # Target industries for CrowdStrike filtering
    target_industries: tuple = (
        "Technology",
        "Healthcare",
        "Pharmaceutical",
        "Life Sciences",
        "Biotechnology",
        "Medical Devices",
        "Research",
        "Education",
        "Manufacturing",
    )


@dataclass(frozen=True)
class EnrichmentConfig:
    """Configuration for data enrichment."""

    # Enable/disable web search for filling data gaps.
    # NOTE: web search is not yet implemented (see cve_enricher), so this defaults
    # to False; enrichment uses only the CISA KEV catalog and pattern matching.
    enable_web_search: bool = os.getenv("ENABLE_WEB_SEARCH", "false").lower() in {"1", "true", "yes"}

    # Web search settings
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10  # Limit to avoid excessive API calls

    # CISA KEV cache duration (hours)
    kev_cache_duration_hours: int = 24

    # OSINT full-text extraction (opt-in). When enabled, each OSINT article URL is
    # fetched and its body extracted with trafilatura (stored as `full_text`) so the
    # AI analyst sees the full article instead of the short RSS summary. Off by
    # default; toggle with ENABLE_OSINT_FULLTEXT. Per-article body is capped
    # (OSINT_FULLTEXT_MAX_CHARS) to keep prompt size and token cost bounded.
    enable_osint_fulltext: bool = os.getenv("ENABLE_OSINT_FULLTEXT", "false").lower() in {"1", "true", "yes"}
    osint_fulltext_max_chars: int = int(os.getenv("OSINT_FULLTEXT_MAX_CHARS", "4000"))
    osint_fulltext_timeout_seconds: int = int(os.getenv("OSINT_FULLTEXT_TIMEOUT", "12"))


_TEMPERATURE_OMIT_TOKENS = {"", "default", "none", "off", "unset", "null"}


def _resolve_temperature() -> float | None:
    """Resolve the sampling temperature from AZURE_OPENAI_TEMPERATURE.

    Returns 0.1 when unset (the historical default). Returns None — meaning "omit the
    temperature parameter entirely and let the model use its own default" — when the
    env var is one of the omit tokens (e.g. "default"). Some newer/reasoning models
    reject any non-default temperature, so this lets you turn it off without code.
    """
    raw = os.environ.get("AZURE_OPENAI_TEMPERATURE")
    if raw is None:
        return 0.1
    if raw.strip().lower() in _TEMPERATURE_OMIT_TOKENS:
        return None
    try:
        return float(raw)
    except ValueError:
        return 0.1


def _resolve_seed() -> int | None:
    """Resolve the sampling seed from AZURE_OPENAI_SEED.

    Returns 789 when unset (the historical default, for reproducibility). Returns
    None — meaning "omit the seed parameter entirely" — when the env var is one of the
    omit tokens (e.g. "default"). Reasoning models that reject a custom temperature
    typically reject seed too, so this lets you turn it off without code.
    """
    raw = os.environ.get("AZURE_OPENAI_SEED")
    if raw is None:
        return 789
    if raw.strip().lower() in _TEMPERATURE_OMIT_TOKENS:
        return None
    try:
        return int(raw)
    except ValueError:
        return 789


@dataclass(frozen=True)
class AnalysisConfig:
    """Configuration for threat analysis."""

    # AI model deployment name. This is the Azure OpenAI *deployment* name (the name
    # you gave the deployment in Foundry), NOT the underlying model id. Override per
    # environment with the AZURE_OPENAI_DEPLOYMENT app setting so switching models is
    # a config change, not a code change.
    deployment_name: str = field(default_factory=lambda: os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1-cti"))

    # Azure OpenAI REST API version. Newer models often require a newer version than
    # the 2024 default; override with AZURE_OPENAI_API_VERSION (use the value shown in
    # the model's "Use this model" code sample in Foundry).
    api_version: str = field(default_factory=lambda: os.environ.get("AZURE_OPENAI_API_VERSION", "2024-06-01"))

    # Sampling temperature, or None to omit the parameter. See _resolve_temperature.
    temperature: float | None = field(default_factory=_resolve_temperature)

    # Sampling seed, or None to omit the parameter. See _resolve_seed.
    seed: int | None = field(default_factory=_resolve_seed)

    # Data truncation limits for AI analysis
    max_cves_for_analysis: int = 50
    max_intel471_for_analysis: int = 30
    max_crowdstrike_for_analysis: int = 30


@dataclass(frozen=True)
class ReportConfig:
    """Configuration for report generation."""

    # Blob storage settings
    container_name: str = "reports"
    sas_expiry_days: int = 7
    # When True, sign SAS URLs with an AAD user-delegation key (revocable, no
    # account key needed) instead of the storage account key. Requires the
    # function's identity to hold a role such as "Storage Blob Data Contributor".
    # Defaults False to preserve the existing account-key behavior.
    use_user_delegation_sas: bool = os.getenv("USE_USER_DELEGATION_SAS", "false").lower() == "true"

    # Document styling
    table_style: str = "Light Grid Accent 1"


@dataclass(frozen=True)
class FeatureConfig:
    """Configuration for feature flags and experimental features."""

    # Gate framework validation pipeline. On by default: the framework is the
    # anti-hallucination guard between collection and publish, so a deployment with
    # no features.yaml still gets gating. Force it off with ENABLE_GATE_FRAMEWORK=0.
    gate_framework_enabled: bool = True

    # Gate framework interactive mode (manual clearance after each gate)
    gate_framework_interactive: bool = False


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
            raise OSError(
                "KEY_VAULT_URL environment variable is not set. "
                "Set it to your Azure Key Vault URL, e.g. 'https://kv-cti-rep-prod.vault.azure.net/'"
            )
        return url


@dataclass(frozen=True)
class CustomerProfile:
    """Organization-specific identity used across reports and analysis.

    Loaded from config/customer_profile.yaml (or the path in CUSTOMER_PROFILE_PATH).
    The defaults below preserve the original single-tenant behavior when no
    profile file is present, so nothing changes for existing deployments.
    """

    name: str = "Illumina"
    brand_color_hex: str = "005DAA"  # hex without leading '#'
    security_contact: str = "secops@illumina.com"
    osint_source_name: str = "Illumina-OSINT"
    # Short industry/sector descriptor used to ground strategic analysis prompts.
    industry: str = "genomics, life sciences, and precision manufacturing"
    # Short phrase naming the org's key products/platforms, used in strategic
    # prompt examples and fallback analysis (e.g. "ICA and BaseSpace").
    products: str = "ICA and BaseSpace"
    # A single flagship product example used in prompt guidance.
    flagship_product: str = "NovaSeq X"
    # Lowercase keywords (company name + product/platform names) used to detect
    # company-specific grounding in geopolitical relevance bullets.
    product_keywords: tuple[str, ...] = (
        "illumina",
        "novaseq",
        "nextseq",
        "iseq",
        "miseq",
        "sequencing platform",
        "ica",
        "basespace",
        "dragen",
    )


# Global configuration instances
collector_config = CollectorConfig()
industry_filter_config = IndustryFilterConfig()
enrichment_config = EnrichmentConfig()
analysis_config = AnalysisConfig()
report_config = ReportConfig()
azure_config = AzureConfig()


_COLLECTORS_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "collectors.yaml"
_FEATURES_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "features.yaml"


def _load_collectors_from_yaml() -> list[str]:
    """Read config/collectors.yaml and return names of enabled collectors."""
    if not _COLLECTORS_YAML.exists():
        raise FileNotFoundError(
            f"Collectors config not found: {_COLLECTORS_YAML}\n"
            "Please create config/collectors.yaml to define your enabled collectors."
        )
    with open(_COLLECTORS_YAML, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    collectors = cfg.get("collectors", [])
    if not collectors:
        raise ValueError(
            f"No collectors defined in {_COLLECTORS_YAML}\nAdd at least one collector with 'enabled: true'."
        )
    return [c["name"] for c in collectors if c.get("enabled", True)]


def get_enabled_collectors() -> list[str]:
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


def _load_features_from_yaml() -> FeatureConfig:
    """Load feature flags from config/features.yaml."""
    if not _FEATURES_YAML.exists():
        # If features.yaml doesn't exist, return defaults
        return FeatureConfig()

    with open(_FEATURES_YAML, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    features = cfg.get("features", {})
    gate_framework = features.get("gate_framework", {})

    return FeatureConfig(
        gate_framework_enabled=gate_framework.get("enabled", True),
        gate_framework_interactive=gate_framework.get("interactive_mode", False),
    )


def get_feature_config() -> FeatureConfig:
    """
    Get feature configuration.

    Priority order:
      1. Environment variable overrides (e.g., ENABLE_GATE_FRAMEWORK=0 to force off)
      2. config/features.yaml settings
      3. Default values (gate framework ON; interactive mode off)
    """
    config = _load_features_from_yaml()

    # Environment variable override for the gate framework (bidirectional):
    # ENABLE_GATE_FRAMEWORK can force it on OR off, taking precedence over YAML.
    env_val = os.environ.get("ENABLE_GATE_FRAMEWORK", "").strip().lower()
    if env_val:
        forced = env_val in {"1", "true", "yes"}
        # Can't mutate a frozen dataclass, so create a new instance.
        return FeatureConfig(
            gate_framework_enabled=forced, gate_framework_interactive=config.gate_framework_interactive
        )

    return config


_CUSTOMER_PROFILE_YAML = Path(__file__).resolve().parent.parent.parent / "config" / "customer_profile.yaml"


def _load_customer_profile() -> CustomerProfile:
    """Load the customer profile from YAML, falling back to defaults if absent."""
    path = Path(os.environ.get("CUSTOMER_PROFILE_PATH", _CUSTOMER_PROFILE_YAML))
    defaults = CustomerProfile()
    if not path.exists():
        return defaults
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    keywords = cfg.get("product_keywords")
    return CustomerProfile(
        name=cfg.get("name", defaults.name),
        brand_color_hex=str(cfg.get("brand_color_hex", defaults.brand_color_hex)),
        security_contact=cfg.get("security_contact", defaults.security_contact),
        osint_source_name=cfg.get("osint_source_name", defaults.osint_source_name),
        industry=cfg.get("industry", defaults.industry),
        products=cfg.get("products", defaults.products),
        flagship_product=cfg.get("flagship_product", defaults.flagship_product),
        product_keywords=tuple(k.lower() for k in keywords) if keywords else defaults.product_keywords,
    )


def get_customer_profile() -> CustomerProfile:
    """Return the active customer profile (config/customer_profile.yaml or defaults)."""
    return _load_customer_profile()


# Eagerly-loaded customer profile singleton.
customer_profile = _load_customer_profile()
