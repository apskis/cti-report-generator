# Configuration Quick Reference

This document provides quick instructions for common configuration changes.

## Web Search Configuration

### Where to Configure

File: `src/core/config.py`

Look for the `EnrichmentConfig` class (around line 70-80).

### Enable Web Search (Default)

```python
@dataclass(frozen=True)
class EnrichmentConfig:
    enable_web_search: bool = True  # Web search enabled
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10
    kev_cache_duration_hours: int = 24
```

**Behavior**: 
- Uses CISA KEV catalog (always)
- Uses pattern matching from CVE descriptions (always)
- Falls back to web search for gaps (up to 10 searches per run)

**Use when**: You want maximum data completeness and can tolerate slightly longer enrichment times.

### Disable Web Search

```python
@dataclass(frozen=True)
class EnrichmentConfig:
    enable_web_search: bool = False  # Web search disabled
    web_search_timeout_seconds: int = 5
    max_web_searches_per_run: int = 10
    kev_cache_duration_hours: int = 24
```

**Behavior**:
- Uses CISA KEV catalog (always)
- Uses pattern matching from CVE descriptions (always)
- NO web search fallback

**Use when**: You want faster enrichment and are okay with some "N/A" values for products not in CISA KEV.

## Other Common Configurations

### Adjust Web Search Limits

```python
class EnrichmentConfig:
    enable_web_search: bool = True
    web_search_timeout_seconds: int = 10  # Longer timeout per search
    max_web_searches_per_run: int = 20    # More searches allowed
```

### Adjust CISA KEV Cache Duration

```python
class EnrichmentConfig:
    kev_cache_duration_hours: int = 48  # Cache for 2 days instead of 1
```

### Change AI Model

File: `src/core/config.py` → `AnalysisConfig` class

```python
class AnalysisConfig:
    deployment_name: str = "gpt-4.1-cti"  # Change to your deployment name
```

### Change Data Collection Lookback Periods

File: `src/core/config.py` → `CollectorConfig` class

```python
class CollectorConfig:
    nvd_lookback_days: int = 14  # Collect 2 weeks instead of 1
    intel471_lookback_days: int = 14
    crowdstrike_lookback_days: int = 14
```

### Disable Specific Data Collectors

#### Option 1: Environment Variable (Temporary)

```powershell
# PowerShell
$env:ENABLED_COLLECTORS = "nvd,intel471,crowdstrike"  # Excludes rapid7 and threatq

# Bash
export ENABLED_COLLECTORS="nvd,intel471,crowdstrike"
```

#### Option 2: Change Default (Permanent)

File: `src/core/config.py` → `DEFAULT_ENABLED_COLLECTORS`

```python
DEFAULT_ENABLED_COLLECTORS = ["nvd", "intel471", "crowdstrike"]  # Removed rapid7, threatq
```

## How to Apply Configuration Changes

1. **Edit** `src/core/config.py` with your changes
2. **Save** the file
3. **Restart** the application:
   - Local testing: Re-run `python test_local.py`
   - Azure Function: Redeploy or restart the function app

## Validation

After changing configuration, check the logs:

```
INFO:enrichment:Enriching 50 CVEs...
INFO:enrichment:Web search: ENABLED  # or DISABLED
INFO:enrichment:Enrichment complete. 50 CVEs enriched.
INFO:enrichment:Web searches performed: 3/10
```

This confirms your web search settings are active.

## Troubleshooting

### Web search not working

1. Check `enrichment_config.enable_web_search` is `True`
2. Check logs for "Web search: ENABLED"
3. Look for "Web searches performed: X/Y" in logs
4. Current implementation uses pattern matching as fallback (web search integration pending)

### Too many "N/A" values

- Enable web search: `enable_web_search: bool = True`
- Increase search limit: `max_web_searches_per_run: int = 20`
- Check if CVEs are in CISA KEV catalog (most actively exploited CVEs are)

### Enrichment too slow

- Disable web search: `enable_web_search: bool = False`
- Decrease search limit: `max_web_searches_per_run: int = 5`
- Reduce timeout: `web_search_timeout_seconds: int = 3`

## Configuration Precedence

1. **Environment Variables** (highest priority)
   - `ENABLED_COLLECTORS`, `KEY_VAULT_URL`, etc.

2. **config.py Settings** (medium priority)
   - All dataclass configurations

3. **Defaults in Code** (lowest priority)
   - Fallback values if not specified

## See Also

- [Main README](README.md) - Full project documentation
- [Enrichment Module](src/enrichment/README.md) - Detailed enrichment documentation
- [Azure Configuration](README.md#configuration) - Azure-specific settings
