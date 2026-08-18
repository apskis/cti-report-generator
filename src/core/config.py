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

# Default supply-chain / tech-stack watchlist for the Peer Incidents section. A breach of any
# of these orgs is treated as a peer incident regardless of the victim's sector (see
# CollectorConfig.peer_watch_orgs). Grouped by lens; override wholesale with PEER_WATCH_ORGS.
_DEFAULT_PEER_WATCH_ORGS = [
    # Tech stack — identity, cloud, data, SaaS, security (enterprise IT in use)
    "Okta", "Microsoft", "Amazon Web Services", "AWS", "Google", "Snowflake",
    "Salesforce", "Workday", "ServiceNow", "CrowdStrike", "Zscaler", "Palo Alto Networks",
    # Cloud / compute / infrastructure partners (publicly reported)
    "NVIDIA", "Pure Storage", "Equinix",
    # Genomics informatics / research partners & lab software
    "Broad Institute", "SOPHiA Genetics", "Microba", "Benchling",
    # Diagnostics / pharma partners
    "Bristol Myers Squibb", "Merck", "Myriad Genetics", "Kura Oncology",
]

# Default competitor watchlist for the Peer Incidents section. A breach of a direct
# genomics/sequencing/diagnostics competitor is worth knowing even though the competitor is
# not a supplier or a shared-tech vendor, so competitor hits are kept regardless of confidence
# (see CollectorConfig.peer_competitor_orgs). Override wholesale with PEER_COMPETITOR_ORGS.
_DEFAULT_PEER_COMPETITOR_ORGS = [
    "Thermo Fisher", "Pacific Biosciences", "PacBio", "Oxford Nanopore", "BGI Genomics",
    "MGI Tech", "Complete Genomics", "Qiagen", "Agilent", "10x Genomics", "Bio-Rad",
    "Element Biosciences", "Ultima Genomics", "Singular Genomics", "Twist Bioscience",
    "Guardant Health", "Natera", "Tempus", "Roche",
]

# US + Europe victim countries used to geo-filter sector-peer breach alerts down to the regions
# that matter (the global breach-alert feed is dominated by small international ransomware
# victims). Matched case-insensitively against the breach alert's victim country, in both
# full-name and ISO-2 forms. Competitor / supply-chain watchlist hits bypass this filter.
_US_EUROPE_COUNTRIES = {
    # United States
    "united states", "united states of america", "usa", "us", "u.s.", "u.s.a.",
    # UK & Ireland
    "united kingdom", "uk", "u.k.", "great britain", "england", "scotland", "wales",
    "northern ireland", "gb", "ireland", "ie",
    # Western / Central Europe
    "germany", "de", "france", "fr", "italy", "it", "spain", "es", "portugal", "pt",
    "netherlands", "the netherlands", "nl", "belgium", "be", "luxembourg", "lu",
    "switzerland", "ch", "austria", "at", "liechtenstein", "li", "monaco", "mc",
    # Nordics
    "denmark", "dk", "sweden", "se", "norway", "no", "finland", "fi", "iceland", "is",
    # Southern Europe
    "greece", "gr", "cyprus", "cy", "malta", "mt",
    # Eastern Europe / Baltics / Balkans
    "poland", "pl", "czech republic", "czechia", "cz", "slovakia", "sk", "hungary", "hu",
    "romania", "ro", "bulgaria", "bg", "croatia", "hr", "slovenia", "si", "estonia", "ee",
    "latvia", "lv", "lithuania", "lt", "serbia", "rs", "ukraine", "ua",
}


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
    # Max breach alerts to pull from the /breachAlerts feed. The feed runs ~250-300/week
    # globally; the fetch paginates in batches of 100 (the API's per-request max) up to this
    # limit, so 500 covers a full week's window with headroom before the sector/geo/confidence
    # filters trim it down. Raising this only adds paged requests (capped at 10 pages).
    intel471_breach_alerts_limit: int = 500
    intel471_indicators_limit: int = 20
    # Minimum confidence for a breach alert to appear as a peer incident. Intel471 grades
    # each breach alert's confidence; this drops low-confidence noise. Accepts a word
    # ("low"/"medium"/"high") or an Admiralty letter ("A"-"F"). Defaults to "medium": Intel471
    # grades breach alerts almost entirely "medium" (observed: high=0, medium=21, low=1 in a
    # week), so a "high" floor zeroes the whole feed. Set INTEL471_BREACH_MIN_CONFIDENCE="high"
    # only if you want near-zero breach alerts, or "" to keep all incl. low. Records whose
    # confidence can't be parsed are kept (never silently dropped). Note: the confidence floor
    # does NOT apply to supply-chain / tech-stack / competitor watchlist matches — those are
    # always relevant if the org is hit.
    intel471_breach_min_confidence: str = field(
        default_factory=lambda: os.environ.get("INTEL471_BREACH_MIN_CONFIDENCE", "medium")
    )
    # Supply-chain / tech-stack watchlist for Peer Incidents. Peer incidents come from three
    # relevance lenses: (1) sector peers — healthcare/pharma/biotech orgs, filtered by
    # confidence above; (2) supply chain — our suppliers/partners; (3) tech stack — vendors
    # whose technology we run. Lenses 2 and 3 are named companies: a breach of any org here is
    # kept regardless of its sector or Intel471 confidence, so a supplier/vendor compromise
    # surfaces even though the victim isn't a healthcare company. Matching is whole-word and
    # case-insensitive, so use the distinctive part of the name ("Okta", not "Okta, Inc.").
    # Override the whole list with the PEER_WATCH_ORGS env var (comma-separated); otherwise the
    # curated default below is used. Curated from known IT/tech-stack vendors and publicly
    # reported Illumina partners/suppliers — trim or extend to match reality.
    peer_watch_orgs: list[str] = field(
        default_factory=lambda: (
            [o.strip() for o in os.environ["PEER_WATCH_ORGS"].split(",") if o.strip()]
            if os.environ.get("PEER_WATCH_ORGS")
            else list(_DEFAULT_PEER_WATCH_ORGS)
        )
    )
    # Competitor watchlist — a fourth relevance lens. A breach of a direct competitor is kept
    # regardless of sector or confidence, so a competitor compromise surfaces in Peer Incidents.
    # Whole-word, case-insensitive matching (same as peer_watch_orgs). Override the whole list
    # with the PEER_COMPETITOR_ORGS env var (comma-separated); otherwise the curated default is
    # used. Seeded from known genomics/sequencing/diagnostics competitors — trim or extend.
    peer_competitor_orgs: list[str] = field(
        default_factory=lambda: (
            [o.strip() for o in os.environ["PEER_COMPETITOR_ORGS"].split(",") if o.strip()]
            if os.environ.get("PEER_COMPETITOR_ORGS")
            else list(_DEFAULT_PEER_COMPETITOR_ORGS)
        )
    )
    # Geo-filter sector-peer breach alerts to US + Europe victims (see _US_EUROPE_COUNTRIES).
    # The global breach-alert feed is dominated by small non-US/EU ransomware victims; this cuts
    # that noise. Applies to the SECTOR lens only — competitor / supply-chain hits are kept
    # worldwide. Victims with no country are kept (not silently dropped). Disable with
    # PEER_BREACH_US_EUROPE_ONLY=false.
    intel471_breach_us_europe_only: bool = field(
        default_factory=lambda: os.environ.get("PEER_BREACH_US_EUROPE_ONLY", "true").lower()
        in {"1", "true", "yes"}
    )
    crowdstrike_actors_limit: int = 50
    crowdstrike_indicators_limit: int = 50
    crowdstrike_spotlight_limit: int = 200  # Max vulnerabilities from Spotlight for exposure counts

    # ICS/OT advisories (RapidAPI "ICS[AP] APIs" — republished CISA ICS advisories).
    # Feeds the weekly report's Operational Technology (OT) section. Auth is a RapidAPI
    # key (x-rapidapi-key header) stored in Key Vault; the host is fixed per the RapidAPI
    # listing. Host/path are config (not secrets) so they can be repointed without code.
    ics_advisory_host: str = "ics-ap-apis.p.rapidapi.com"
    # Path of the "Advisories - Latest" endpoint on the RapidAPI listing. Override with
    # ICS_ADVISORY_LATEST_PATH if the listing changes the route.
    ics_advisory_latest_path: str = field(
        default_factory=lambda: os.environ.get("ICS_ADVISORY_LATEST_PATH", "/advisories/latest")
    )
    # Weekly ICS/OT window. Defaults to 45 days (not 7) because the RapidAPI free tier
    # serves advisories ~1 month stale ("Free tier data is one month old"); a 7-day
    # window would filter all of it out and render an empty OT section. 45 gives enough
    # headroom for that lag (which drifts) so the section stays populated. On a PRO
    # subscription that returns current advisories, set ICS_ADVISORY_LOOKBACK_DAYS=7 for
    # a true "this week" view.
    ics_advisory_lookback_days: int = field(
        default_factory=lambda: int(os.environ.get("ICS_ADVISORY_LOOKBACK_DAYS", "45"))
    )
    ics_advisory_quarterly_lookback_days: int = 90
    ics_advisory_max_results: int = 50
    # Per-advisory "Entry" detail endpoint. The list endpoint returns only a summary
    # (id/title/severity/date) on the free tier; the detail endpoint returns the full
    # record (vendor, product, CVEs, CVSS score) even on the free tier. Enrich each
    # advisory with one detail call so the OT table's Vendor/CVSS/CVEs columns fill in.
    # {advisory_id} is substituted with the advisory number. Disable with
    # ICS_ADVISORY_ENRICH=false to save API calls (one call per advisory per run).
    ics_advisory_entry_path: str = field(
        default_factory=lambda: os.environ.get("ICS_ADVISORY_ENTRY_PATH", "/advisories/{advisory_id}")
    )
    ics_advisory_enrich_details: bool = field(
        default_factory=lambda: os.environ.get("ICS_ADVISORY_ENRICH", "true").lower() in {"1", "true", "yes"}
    )
    ics_advisory_enrich_limit: int = 25  # max detail calls per run (guards the request budget)

    # Claroty xDome — matches advisory CVEs to devices actually in the environment, so the
    # OT section can show real asset exposure. Auth is a bearer token (claroty-api-token in
    # Key Vault); the base URL is fixed per the xDome API and overridable via env.
    claroty_base_url: str = field(
        default_factory=lambda: os.environ.get("CLAROTY_BASE_URL", "https://api.claroty.com")
    )
    claroty_vuln_page_limit: int = 500  # page size for /vulnerabilities/ (API max is generous)
    claroty_vuln_max_pages: int = 20  # cap pages fetched per run (rate-limit / safety guard)
    # Product/vendor matching: also fetch the device inventory (manufacturer/model) so an
    # advisory counts as "in environment" when you own the vendor's gear, even if xDome
    # has not yet linked that advisory's CVE to a device. Fuzzier than CVE matching (vendor
    # names differ between CISA advisories and Claroty); disable with CLAROTY_MATCH_PRODUCTS=false.
    claroty_match_products: bool = field(
        default_factory=lambda: os.environ.get("CLAROTY_MATCH_PRODUCTS", "true").lower() in {"1", "true", "yes"}
    )
    claroty_device_page_limit: int = 500
    claroty_device_max_pages: int = 20
    # OT asset matching is an optional enrichment, so it must fail fast rather than block
    # report generation: a single attempt with a short timeout (no long retry storm).
    claroty_timeout_seconds: int = 25
    claroty_max_retries: int = 0
    # "Environment OT Exposure" view: the vulnerabilities on OT devices you operate, straight
    # from Claroty (independent of the ICS advisory feed). Scoped to High/Critical severity and
    # ranked by CVSS so the table is short and meaningful rather than a long device-count dump.
    claroty_env_exposure_limit: int = 10  # safety cap on rows returned
    claroty_env_exposure_min_cvss: float = 7.0  # High (7.0-8.9) and Critical (9.0+) only

    # CISA KEV (Known Exploited Vulnerabilities) — a free, keyless public JSON feed. Claroty
    # already flags KEV membership (is_known_exploited) but not the catalog's ransomware-use
    # marker, so we fetch KEV once per run to add a "known ransomware" flag to the OT tables.
    # Best-effort: any failure degrades to no annotation. Disable with KEV_ENRICH=false.
    kev_enrich_enabled: bool = field(
        default_factory=lambda: os.environ.get("KEV_ENRICH", "true").lower() in {"1", "true", "yes"}
    )
    kev_feed_url: str = field(
        default_factory=lambda: os.environ.get(
            "KEV_FEED_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
    )
    kev_timeout_seconds: int = 15
    kev_max_retries: int = 1

    # EPSS (Exploit Prediction Scoring System, FIRST.org) — keyless public API used to fill the
    # OT section's exploitation signal for CVEs that CISA KEV and Claroty do not flag.
    # Best-effort: any failure degrades to no annotation. Disable with EPSS_ENRICH=false.
    epss_enrich_enabled: bool = field(
        default_factory=lambda: os.environ.get("EPSS_ENRICH", "true").lower() in {"1", "true", "yes"}
    )
    epss_api_url: str = field(
        default_factory=lambda: os.environ.get("EPSS_API_URL", "https://api.first.org/data/v1/epss")
    )
    epss_timeout_seconds: int = 15
    epss_max_retries: int = 1
    # The catalog is fetched once and memoized for the run; every KEV consumer (OT tables,
    # IT Exploited section, CVE enricher) shares that single download. Cache TTL in hours.
    kev_cache_hours: int = 6

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
    # Leave hhs_breach_csv_url empty to auto-export from the JSF portal (hhs_portal_url); or set
    # HHS_BREACH_CSV_URL to a direct CSV URL / local file path to bypass the fragile portal scrape.
    # Pinning this is strongly recommended for a deployed environment (no Chromium, and the JSF
    # auto-export is unreliable) — otherwise HHS can silently contribute zero healthcare breaches.
    hhs_breach_csv_url: str = field(default_factory=lambda: os.environ.get("HHS_BREACH_CSV_URL", ""))
    hhs_portal_url: str = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
    # The portal is JS-rendered, so a headless browser (Playwright) is used to export the
    # CSV. Requires: pip install playwright && playwright install chromium. Set to False to
    # disable the browser path (then only a direct URL / local file in hhs_breach_csv_url works).
    hhs_use_browser: bool = True
    hhs_browser_headless: bool = True
    # Have I Been Pwned public breaches endpoint (keyless; a descriptive User-Agent is required).
    hibp_breaches_url: str = "https://haveibeenpwned.com/api/v3/breaches"
    # ransomware.live — public ransomware leak-site victim tracker (keyless). Grounds the
    # Ransomware stat card and the ransomware share of the breach landscape with date-stamped,
    # sector-tagged victim postings. Defaults to the v2 "recent victims" endpoint; point
    # RANSOMWARE_LIVE_URL at a month/range endpoint for fuller historical coverage. The parser
    # accepts both the v1 (post_title/group_name/activity) and v2 (victim/group/sector) shapes.
    ransomware_live_url: str = field(
        default_factory=lambda: os.environ.get(
            "RANSOMWARE_LIVE_URL", "https://api.ransomware.live/v2/victims/recent"
        )
    )

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
