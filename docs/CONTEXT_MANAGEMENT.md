# Historical Context Management & Trend Analysis

## Overview

The CTI Report Generator now includes **historical context management** and **trend analysis** capabilities. This enables week-over-week and quarter-over-quarter tracking of:

- CVE trends (new, persistent, resolved, recurrent vulnerabilities)
- Threat actor activity patterns
- Industry incident trends
- Historical metrics and baselines

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Azure Functions                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  function_app.py                                           │ │
│  │  - Collects threat intelligence data                       │ │
│  │  - Retrieves historical contexts                           │ │
│  │  - Runs context-aware AI analysis                          │ │
│  │  - Saves analysis for next report                          │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│               AgentContextManager                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  - save_analysis_context()                                 │ │
│  │  - get_previous_context()                                  │ │
│  │  - calculate_cve_trends()                                  │ │
│  │  - calculate_actor_trends()                                │ │
│  │  - get_historical_statistics()                             │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    CacheManager                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  - set_cache() / get_cache()                               │ │
│  │  - cache_collector_data()                                  │ │
│  │  - get_collector_cache()                                   │ │
│  │  - list_cache_keys()                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  Azure Blob Storage                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Container: cache                                          │ │
│  │  ├── analysis-context-weekly-2026-06-01.json              │ │
│  │  ├── analysis-context-weekly-2026-05-25.json              │ │
│  │  ├── cve-tracking-weekly-2026-06-01.json                  │ │
│  │  ├── actor-timeline-weekly-2026-06-01.json                │ │
│  │  ├── collector-Intel471-20260601.json                     │ │
│  │  └── collector-CrowdStrike-20260601.json                  │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Week 1:                    Week 2:
┌────────────────┐         ┌────────────────┐
│ Collect Data   │         │ Collect Data   │
└────────┬───────┘         └────────┬───────┘
         │                          │
         ↓                          ↓
┌────────────────┐         ┌────────────────┐
│ AI Analysis    │         │ Get Week 1     │
│ (no context)   │         │ Context        │
└────────┬───────┘         └────────┬───────┘
         │                          │
         ↓                          ↓
┌────────────────┐         ┌────────────────┐
│ Save Context   │         │ Calculate      │
│ to Blob        │         │ Trends         │
└────────────────┘         └────────┬───────┘
                                    │
                                    ↓
                           ┌────────────────┐
                           │ AI Analysis    │
                           │ (with trends)  │
                           └────────┬───────┘
                                    │
                                    ↓
                           ┌────────────────┐
                           │ Save Context   │
                           │ to Blob        │
                           └────────────────┘
```

## Key Features

### 1. Analysis Context Storage

**What it stores:**
- Complete analysis results (CVEs, APT activity, incidents, recommendations)
- CVE tracking data (IDs, severity, exploitation status)
- Threat actor timelines
- Executive summary and statistics

**Storage format:**
```json
{
  "report_type": "weekly",
  "report_date": "2026-06-01",
  "saved_at": "2026-06-01T12:00:00Z",
  "analysis": {
    "executive_summary": "...",
    "cve_analysis": [...],
    "apt_activity": [...],
    "statistics": {...}
  }
}
```

**Cache keys:**
- `analysis-context-weekly-2026-06-01.json` - Full analysis
- `cve-tracking-weekly-2026-06-01.json` - CVE IDs only (fast lookups)
- `actor-timeline-weekly-2026-06-01.json` - Threat actor summary

**TTL:** 30 days (configurable)

### 2. CVE Trend Analysis

Calculates and tracks:

- **New CVEs**: Appearing for the first time
- **Persistent CVEs**: Present in previous report (unresolved)
- **Resolved CVEs**: From last report but not current
- **Recurrent CVEs**: Disappeared and reappeared

**Example output:**
```python
{
  "new_cves": ["CVE-2024-1234", "CVE-2024-5678"],
  "persistent_cves": ["CVE-2024-0001", "CVE-2024-0002"],
  "resolved_cves": ["CVE-2024-0099"],
  "recurrent_cves": [],
  "trend_summary": "2 new CVEs detected; 2 CVEs remain unresolved from last report; 1 CVE resolved since last report",
  "weeks_analyzed": 4
}
```

### 3. Threat Actor Trend Analysis

Tracks actor activity patterns:

- **New actors**: First-time identification
- **Persistent actors**: Active in previous report
- **Inactive actors**: Reduced/no activity

**Example output:**
```python
{
  "new_actors": ["APT99"],
  "persistent_actors": ["APT28", "APT29"],
  "inactive_actors": ["APT10"],
  "trend_summary": "1 new threat actor identified; 2 actors remain active from last report; 1 actor shows reduced activity"
}
```

### 4. Historical Statistics

Provides time-series metrics:

```python
{
  "available": True,
  "timeline": [
    {
      "date": "2026-05-01",
      "total_cves": 15,
      "critical_cves": 5,
      "exploited_cves": 8,
      "threat_actors": 12,
      "peer_incidents": 10
    },
    {
      "date": "2026-05-08",
      "total_cves": 12,
      "critical_cves": 3,
      "exploited_cves": 6,
      "threat_actors": 10,
      "peer_incidents": 8
    }
  ],
  "weeks_analyzed": 4
}
```

### 5. Context-Aware AI Analysis

The `ThreatAnalystAgent` now has two analysis modes:

**Standard Mode** (no context):
```python
analysis = await agent.analyze_threats(
    cve_data, intel471_data, crowdstrike_data,
    threatq_data, rapid7_data, rapid7_scans_data, osint_data
)
```

**Context-Aware Mode** (with trends):
```python
analysis = await agent.analyze_threats_with_context(
    cve_data, intel471_data, crowdstrike_data,
    threatq_data, rapid7_data, rapid7_scans_data, osint_data,
    previous_contexts=previous_contexts,
    cve_trends=cve_trends,
    actor_trends=actor_trends
)
```

The AI receives:
- Historical context from previous 4 weeks
- Pre-calculated trends
- Instructions to highlight trends in executive summary
- Enhanced prompt with trend analysis requirements

### 6. Collector Data Caching

All collector data can now be cached:

```python
# Cache collector data
cache_manager.cache_collector_data("Intel471", intel471_data, ttl_hours=6)

# Retrieve cached data
cached_data = cache_manager.get_collector_cache("Intel471", max_age_hours=6)
```

**Benefits:**
- Faster report generation (read from cache vs. API calls)
- Reduced API costs
- Consistent data across multiple report runs
- Historical data preservation

## Usage

### Weekly Report with Trends

The weekly report function automatically:
1. Retrieves last 4 weeks of context
2. Calculates CVE and actor trends
3. Runs context-aware AI analysis
4. Includes trends in executive summary
5. Saves current analysis for next week

```python
# Automatically handled in function_app.py
# No code changes needed - just run the report
curl -X POST https://your-function-app.azurewebsites.net/api/GenerateWeeklyReport
```

### Quarterly Report with Trends

Similar to weekly, but looks back 1 year (4 quarters):

```python
curl -X POST https://your-function-app.azurewebsites.net/api/GenerateQuarterlyReport
```

### Programmatic Usage

```python
from src.utils.cache_manager import CacheManager
from src.agents.context_manager import AgentContextManager

# Initialize
cache_manager = CacheManager(storage_account_name, storage_account_key)
context_mgr = AgentContextManager(cache_manager)

# Get historical context
previous_contexts = context_mgr.get_previous_context("weekly", lookback_weeks=4)

# Calculate trends
cve_trends = context_mgr.calculate_cve_trends(current_cves, previous_contexts)
actor_trends = context_mgr.calculate_actor_trends(current_actors, previous_contexts)

# Run context-aware analysis
analysis = await agent.analyze_threats_with_context(
    ...,
    previous_contexts=previous_contexts,
    cve_trends=cve_trends,
    actor_trends=actor_trends
)

# Save for next time
context_mgr.save_analysis_context("weekly", datetime.now(), analysis)
```

## Report Output Changes

### Executive Summary Enhancement

The executive summary now includes trend insights:

**Before:**
```
This week's threat landscape shows 15 critical CVEs actively exploited...
```

**After:**
```
Trend Analysis: 2 new CVEs detected; 13 CVEs remain unresolved from last report; 3 CVEs resolved since last report

Actor Trends: 1 new threat actor identified; 5 actors remain active from last report

This week's threat landscape shows 15 critical CVEs actively exploited...
```

### CVE Analysis Enhancement

CVEs now include `weeks_detected` field:

```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "CRITICAL",
  "weeks_detected": 3,  // ← NEW: Indicates persistent issue
  "actively_exploited": true,
  "affected_product": "Microsoft Exchange"
}
```

Reports highlight persistent CVEs (weeks_detected >= 3) as ongoing concerns.

## Configuration

### Cache TTLs

Adjust cache durations in code:

```python
# Analysis context cache: 30 days
context_mgr.get_previous_context("weekly", lookback_weeks=4)
# Uses max_age_hours=24*30

# Collector cache: 6 hours (default)
cache_manager.cache_collector_data("Intel471", data, ttl_hours=6)
```

### Lookback Windows

**Weekly reports**: Default 4 weeks
```python
previous_contexts = context_mgr.get_previous_context("weekly", lookback_weeks=4)
```

**Quarterly reports**: Default 52 weeks (~1 year = 4 quarters)
```python
previous_contexts = context_mgr.get_previous_context("quarterly", lookback_weeks=52)
```

## Testing

### Run the test suite:

```bash
# Set Azure credentials
export STORAGE_ACCOUNT_NAME="your-storage-account"
export STORAGE_ACCOUNT_KEY="your-storage-key"

# Run tests
python test_context_management.py
```

### Expected output:

```
============================================================
TESTING CONTEXT MANAGER
============================================================
✅ Using Azure Storage account: ctireportingstorage
✅ Context manager initialized

Test 1: Saving mock historical contexts
  ✅ Saved context for 2026-06-01
  ✅ Saved context for 2026-05-25
  ✅ Saved context for 2026-05-18
  ✅ Saved context for 2026-05-11

Test 2: Retrieving previous contexts
  ✅ Retrieved 4 previous contexts

Test 3: Calculating CVE trends
  ✅ CVE Trends calculated:
    - New CVEs: 2
    - Persistent CVEs: 8
    - Resolved CVEs: 3
    - Summary: 2 new CVEs detected; 8 CVEs remain...

✅ ALL CONTEXT MANAGER TESTS PASSED
```

### Test with real reports:

```bash
# Week 1: Generate first report (no context)
python test_local.py weekly --local --real

# Week 2: Generate second report (with trends!)
python test_local.py weekly --local --real
```

Check the executive summary in Week 2's report for trend analysis.

## Troubleshooting

### Context not saving

**Symptom**: Trends always show "First report - no historical comparison available"

**Solutions**:
1. Check Azure Storage credentials
2. Verify container "cache" exists
3. Check function logs for errors:
   ```bash
   func azure functionapp logstream your-function-app
   ```

### Trends showing zero changes

**Symptom**: Trends say "0 new CVEs detected; 0 CVEs remain unresolved"

**Possible causes**:
1. CVE data structure changed (cve_id field missing)
2. Date mismatch in context retrieval
3. Cache TTL expired (older than 30 days)

**Fix**: Check context keys in Blob Storage:
```python
context_mgr.list_available_contexts("weekly")
```

### High Azure Storage costs

**Symptom**: Unexpected Blob Storage charges

**Explanation**: Each report saves ~3 blobs (context, CVE tracking, actor timeline)

**Optimization**:
```python
# Clean up old contexts
cache_manager.clear_old_caches(days_old=30)
```

Add to Azure Function as scheduled job.

## Migration Notes

### Existing Deployments

**No breaking changes!** The system gracefully handles missing historical data:
- First report after deployment: No trends (falls back to standard analysis)
- Second report: Trends appear automatically

**Optional**: Seed historical context from old reports:
```python
# If you have old report JSON files
for old_report in old_reports:
    context_mgr.save_analysis_context(
        "weekly",
        old_report["date"],
        old_report["analysis"]
    )
```

## API Changes

### New Methods

**AgentContextManager**:
- `save_analysis_context(report_type, report_date, analysis_result)` → `bool`
- `get_previous_context(report_type, current_date, lookback_weeks)` → `List[Dict]`
- `calculate_cve_trends(current_cves, previous_contexts)` → `Dict`
- `calculate_actor_trends(current_actors, previous_contexts)` → `Dict`
- `get_historical_statistics(report_type, lookback_weeks)` → `Dict`
- `list_available_contexts(report_type)` → `List[str]`

**CacheManager**:
- `cache_collector_data(collector_name, data, ttl_hours)` → `bool`
- `get_collector_cache(collector_name, max_age_hours)` → `Optional[List[Dict]]`
- `clear_old_caches(days_old)` → `int`

**ThreatAnalystAgent**:
- `analyze_threats_with_context(...)` → `Dict` (new method)
- `analyze_threats(...)` → `Dict` (unchanged, still works)

### Backward Compatibility

All new features are **opt-in**:
- If you don't pass `previous_contexts`, it uses standard analysis
- If context save fails, report still generates (logs warning)
- Missing trend data is handled gracefully

## Future Enhancements

Planned improvements:
1. **Trend visualization**: Charts showing metric trends over time
2. **Anomaly detection**: Flag unusual spikes in CVE/actor counts
3. **Predictive analytics**: ML-based threat forecasting
4. **Custom retention policies**: Per-collector cache TTLs
5. **Context compression**: Reduce storage costs for old contexts
6. **Trend dashboard**: Web UI for historical analysis

## Support

For issues or questions:
1. Check logs: `function_app` logs include context manager operations
2. Review Azure Blob Storage: Ensure contexts are being saved
3. Run test suite: `python test_context_management.py`
4. Check this documentation for troubleshooting guidance
