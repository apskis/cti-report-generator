# Data Enrichment Module

## Overview

The enrichment module fills gaps in threat intelligence data by integrating multiple authoritative sources and enhancing raw CVE and threat actor data with actionable context.

## Features

### 1. CVE Enrichment (`CVEEnricher`)

Automatically enriches CVE records with:

- **Affected Products**: Vendor and product names extracted from:
  - CISA KEV catalog (authoritative source)
  - CPE (Common Platform Enumeration) data
  - CVE description pattern matching
  - Web search fallback (optional)

- **Exploitation Status**: Identifies actively exploited vulnerabilities using:
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - Exploitation attribution (ransomware groups, APT actors, etc.)

- **Additional Context**:
  - Known ransomware campaign usage
  - Required remediation actions (from CISA)
  - Remediation deadlines

### 2. Threat Actor Monitoring Enrichment (`ThreatActorMonitoringEnricher`)

Generates specific monitoring recommendations for observed threat actors:

- **Detection Indicators**: Specific IOCs and behavioral patterns to watch for
- **Known TTPs**: Tactics, techniques, and procedures used by each actor
- **Focus Areas**: Primary targeting motivations and sectors

Currently includes intelligence profiles for:
- CASCADE PANDA (China state-sponsored)
- PLUMP SPIDER (Brazilian criminal)
- ROYAL SPIDER (Russian criminal/ransomware)
- HOOK SPIDER (Criminal/financial)
- MUSTANG PANDA (China state-sponsored)

## Usage

### Basic CVE Enrichment

```python
from src.enrichment import CVEEnricher

enricher = CVEEnricher()

# Enrich a list of CVEs (uses config settings automatically)
enriched_cves = await enricher.enrich_cves(raw_cves)

# Each CVE now has:
# - affected_product: "Vendor Product Name"
# - exploited: true/false
# - exploited_by: "Ransomware groups" or "None known"
# - in_cisa_kev: true/false
# - kev_required_action: "Apply updates per vendor instructions"
```

### Configuration

Web search and other enrichment settings are controlled in `src/core/config.py`:

```python
@dataclass(frozen=True)
class EnrichmentConfig:
    # Enable/disable web search for filling data gaps
    enable_web_search: bool = True
    
    # Web search settings
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10
    
    # CISA KEV cache duration (hours)
    kev_cache_duration_hours: int = 24
```

**To disable web search**, edit `src/core/config.py` and set:

```python
enable_web_search: bool = False
```

### Threat Actor Enrichment

```python
from src.enrichment import ThreatActorMonitoringEnricher

enricher = ThreatActorMonitoringEnricher()

# Enrich threat actors with monitoring guidance
enriched_actors = enricher.enrich_threat_actors(raw_actors)

# Each actor now has:
# - monitoring_guidance: ["Specific detection recommendation 1", ...]
# - known_ttps: ["Spear phishing", "Living-off-the-land", ...]
# - focus_area: "Intellectual property theft in biotech"
```

### Integration in Report Generation

The enrichment is automatically applied in the data collection pipeline:

```python
# In test_local.py or function_app.py
from src.enrichment import CVEEnricher, ThreatActorMonitoringEnricher

# After collecting data
cve_enricher = CVEEnricher()
data_by_source["NVD"] = await cve_enricher.enrich_cves(data_by_source["NVD"])

# Threat actor enrichment happens in AI analysis
# The AI uses the enriched data to generate better recommendations
```

## Data Sources

### CISA KEV Catalog

- **URL**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Update Frequency**: Daily
- **Cache Duration**: 24 hours (in-memory)
- **Coverage**: ~1,100+ actively exploited CVEs
- **Authority**: Official U.S. government source

### Threat Actor Intelligence

Built-in intelligence profiles based on:
- CrowdStrike threat actor taxonomy
- MITRE ATT&CK mappings
- Public threat intelligence reporting

## Configuration

### Web Search Settings

Web search is now controlled by configuration in `src/core/config.py`:

```python
@dataclass(frozen=True)
class EnrichmentConfig:
    # Enable/disable web search for filling data gaps
    enable_web_search: bool = True  # Set to False to disable
    
    # Web search settings
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10
    
    # CISA KEV cache duration (hours)
    kev_cache_duration_hours: int = 24
```

**To disable web search entirely**:
1. Open `src/core/config.py`
2. Find the `EnrichmentConfig` class
3. Change `enable_web_search: bool = True` to `enable_web_search: bool = False`
4. Restart the application

The enricher will now use only CISA KEV catalog and pattern matching, which is faster but may leave more gaps.

### Caching

The CISA KEV catalog is cached for 24 hours (configurable) to reduce API calls:

```python
enricher = CVEEnricher()
# First call: fetches from CISA
enriched1 = await enricher.enrich_cves(cves1)
# Second call within 24 hours: uses cache
enriched2 = await enricher.enrich_cves(cves2)
```

### Add New Threat Actor Profiles

Edit `src/enrichment/cve_enricher.py`:

```python
ACTOR_MONITORING_GUIDANCE = {
    "YOUR ACTOR NAME": {
        "ttps": ["TTP1", "TTP2"],
        "indicators": ["Monitor for X", "Watch for Y"],
        "focus": "Description of targeting focus"
    }
}
```

## Before and After

### Before Enrichment

```json
{
  "cve_id": "CVE-2026-1346",
  "description": "Privilege escalation...",
  "severity": "CRITICAL"
}
```

### After Enrichment

```json
{
  "cve_id": "CVE-2026-1346",
  "description": "Privilege escalation...",
  "severity": "CRITICAL",
  "affected_product": "IBM Verify Identity Access",
  "exploited": true,
  "exploited_by": "Ransomware groups",
  "in_cisa_kev": true,
  "kev_required_action": "Apply mitigations per vendor instructions",
  "known_ransomware": "Known"
}
```

## Report Impact

### Vulnerability Exposure Table

| CVE ID | Affected Product | Exposure | Exploited By | Risk | Wks |
|--------|------------------|----------|--------------|------|-----|
| CVE-2026-1346 | **IBM Verify Identity Access** | N/A | **Ransomware groups** | Critical | New |

*(Before: "N/A" for product and "None known" for exploited by)*

### Sector Threat Activity Table

| Origin / Motivation | Activity Observed | What to Monitor |
|---------------------|-------------------|-----------------|
| China State-Sponsored | CASCADE PANDA | **Monitor for suspicious PowerShell activity; Watch for unusual network connections to Asia-Pacific regions; Scan for signs of credential harvesting** |

*(Before: Empty "What to Monitor" column)*

## Performance

- **CVE enrichment**: ~100ms per CVE (with CISA KEV cache)
- **CISA KEV fetch**: ~2-3 seconds (first call only)
- **Threat actor enrichment**: <1ms per actor (in-memory lookup)
- **Web search** (when enabled): 2-5 seconds per query (optional fallback)

## Future Enhancements

Planned improvements:

1. **Asset Inventory Integration**: Map CVEs to actual deployed products for "Exposure" column
2. **EPSS Scoring**: Integrate Exploit Prediction Scoring System for prioritization
3. **VulnCheck Integration**: Real-time exploitation intelligence
4. **Shodan/Censys**: Identify internet-exposed vulnerable systems
5. **Extended Actor Database**: Add 50+ additional threat actor profiles
6. **Machine Learning**: Auto-extract products from descriptions using NLP

## Troubleshooting

### CISA KEV Fetch Fails

```python
logger.error("Failed to load CISA KEV catalog: Connection timeout")
# Fallback: Uses pattern matching only
# No exploitation data available
```

**Solution**: Check network connectivity, retry will occur on next enrichment call.

### Product Still Shows "N/A"

Possible causes:
1. CVE not in CISA KEV catalog
2. Pattern matching failed to extract from description
3. Web search disabled or failed

**Solution**: Enable web search or manually add product mapping.

## Maintenance

### Update CISA KEV Cache Manually

```python
enricher = CVEEnricher()
enricher._kev_cache = None  # Clear cache
enricher._kev_cache_time = None
enriched = await enricher.enrich_cves(cves)  # Will fetch fresh data
```

### Add Missing Products

For frequently encountered CVEs without product data, add explicit mappings:

```python
# In CVEEnricher class
PRODUCT_OVERRIDES = {
    "CVE-2026-XXXX": "Vendor Product Name"
}
```

## Dependencies

- `src.collectors.http_utils.HTTPClient`: For CISA KEV fetches
- Python `re` module: Pattern matching
- No external dependencies beyond existing project requirements

## License

Same as parent project.
