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

    # News-search (GDELT) collector — used mainly for historical/prior-quarter backfill,
    # where RSS feeds can no longer serve articles from a past window.
    news_search_max_records: int = 40
    news_search_query: str = (
        '(biotech OR biotechnology OR genomics OR "life sciences" OR pharmaceutical OR healthcare) '
        "(cyberattack OR cyberattacks OR breach OR ransomware OR hackers OR malware OR databreach OR espionage)"
    )

    # Breach-dataset collectors (date-stamped incidents that ground the breach stat cards).
    # Each source may be a URL *or a local file path* (public dataset endpoints are often
    # unstable — VCDB has no single stable combined-JSON URL, and the HHS portal is a JSF
    # app, not a clean CSV API — so downloading the data once and pinning a local path is
    # the most reliable operation). A local path or file:// URL is read directly from disk.
    # Est. Total Impact is estimated PER INCIDENT (records x $/record explodes on
    # mega-breaches): IBM "Cost of a Data Breach" avg total cost per breach ~$4.88M global,
    # weighted by sector. This is the fallback for incidents of unknown sector.
    breach_cost_per_breach_usd: float = 4_880_000.0
    # HIBP is a global consumer/credential-dump directory, not an industry peer source, so
    # it is EXCLUDED from the counted breach landscape by default. Enable to include it
    # (broader but noisier, and its mega-breaches can dominate the totals).
    breach_include_hibp: bool = False
    # VCDB: Verizon VERIS Community Database — combined JSON array of VERIS incident objects.
    vcdb_data_url: str = "https://raw.githubusercontent.com/vz-risk/VCDB/master/data/joined/vcdb.json"
    # NAICS 2-digit prefixes counted as relevant peers: 31-33 manufacturing, 54 professional/
    # scientific (biotech R&D), 62 health care. Empty tuple = no industry filter.
    vcdb_relevant_naics_prefixes: tuple = ("31", "32", "33", "54", "62")
    # HHS OCR "Wall of Shame" healthcare breaches (>=500 individuals).
    # Leave hhs_breach_csv_url empty to auto-export from the JSF portal (hhs_portal_url);
    # or set it to a direct CSV URL / local file path to bypass the portal scrape.
    hhs_breach_csv_url: str = ""
    hhs_portal_url: str = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
    # Have I Been Pwned public breaches endpoint (keyless; a descriptive User-Agent is required).
    hibp_breaches_url: str = "https://haveibeenpwned.com/api/v3/breaches"

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
    # Durable, threat-relevant attributes of the organization. This is the strategic
    # "hook sheet" the geopolitical/breach analysis must connect intelligence to, so
    # relevance stays grounded even when live scraping is thin or fails. Kept in config
    # (not buried in the prompt) so it is maintainable and single-sourced.
    strategic_profile: str = (
        "- Global leader in DNA sequencing with an estimated ~80% share of the sequencing "
        "instrument market; core platforms include NovaSeq X, NextSeq, MiSeq, and iSeq.\n"
        "- Cloud platforms hold sensitive customer genomic and clinical data: Illumina "
        "Connected Analytics (ICA) and BaseSpace Sequence Hub, with DRAGEN secondary-analysis "
        "pipelines. These are the crown-jewel data assets and primary exfiltration targets.\n"
        "- Custodian of large volumes of human genomic data, making it a high-value target for "
        "nation-state IP theft and espionage against biotechnology and precision medicine.\n"
        "- Material China exposure: significant market/revenue ties and prior placement on "
        "China's 'unreliable entity list', making China-nexus geopolitical activity directly "
        "business-relevant.\n"
        "- Extensive third-party and supply-chain footprint across instruments, reagents, and "
        "laboratory software, creating supply-chain compromise exposure.\n"
        "- Operates in an FDA-regulated clinical environment; US/EU genomic-data-privacy and "
        "foreign-access legislation directly affects the business."
    )
    # Candidate investor-relations press-release RSS/Atom (or JSON) feed URLs, tried in
    # order. A feed is far more stable than scraping the JS-rendered news-center HTML.
    # Pin the one that works for your org (it is logged when it succeeds).
    ir_feed_urls: tuple[str, ...] = (
        "https://investor.illumina.com/rss/news-releases.xml",
        "https://investor.illumina.com/rss/pressreleases.xml",
        "https://investor.illumina.com/news-releases/rss",
        "https://investor.illumina.com/rss/news.xml",
    )
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
        strategic_profile=cfg.get("strategic_profile", defaults.strategic_profile),
        ir_feed_urls=tuple(cfg["ir_feed_urls"]) if cfg.get("ir_feed_urls") else defaults.ir_feed_urls,
        product_keywords=tuple(k.lower() for k in keywords) if keywords else defaults.product_keywords,
    )


def get_customer_profile() -> CustomerProfile:
    """Return the active customer profile (config/customer_profile.yaml or defaults)."""
    return _load_customer_profile()


# Eagerly-loaded customer profile singleton.
customer_profile = _load_customer_profile()
