# Rapid7 Bulk Export Background Sync - Implementation Summary

## Problem Solved
Weekly reports took 20+ minutes waiting for Rapid7 to export vulnerability data every single time.

## Solution Implemented
Azure Timer Function that automatically syncs Rapid7 data every 6 hours + intelligent Blob Storage caching.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTOMATED BACKGROUND SYNC                    │
└─────────────────────────────────────────────────────────────────┘

Timer Trigger (Every 6 hours: 12am, 6am, 12pm, 6pm UTC)
    ↓
Rapid7SyncFunction
    ↓
    1. Calls Rapid7 Bulk Export API (GraphQL)
    2. Waits 10-20 min for export to complete
    3. Downloads Parquet files
    4. Parses vulnerability data
    5. Caches to Blob Storage
    ↓
Azure Blob Storage (cache container)
    └── rapid7-bulk-export-latest.json
        ├── CVE exposure mappings
        ├── Asset counts
        └── Timestamp (6-hour TTL)

┌─────────────────────────────────────────────────────────────────┐
│                      WEEKLY REPORT GENERATION                    │
└─────────────────────────────────────────────────────────────────┘

User triggers weekly report
    ↓
Rapid7BulkExportCollector.collect()
    ↓
    ┌─────────────────────────────────────┐
    │ Check cache (< 6 hours old?)        │
    └─────────────────────────────────────┘
           ↓                      ↓
         YES                     NO
           ↓                      ↓
    Load from cache      Fetch from API
    (INSTANT!)           (10-20 minutes)
           ↓                      ↓
           └──────────┬───────────┘
                      ↓
              Report generated
```

---

## Components Created

### 1. Cache Manager (`src/utils/cache_manager.py`)
**Purpose:** Manages Blob Storage caching with TTL support

**Key Methods:**
- `get_cache(key, max_age_hours=6)` - Retrieves cached data if fresh
- `set_cache(key, data)` - Stores data in Blob Storage
- `delete_cache(key)` - Removes cached data
- `list_cache_keys(prefix)` - Lists all cached items

**Features:**
- Automatic TTL checking (default: 6 hours)
- JSON serialization/deserialization
- Error handling with graceful fallbacks
- Creates `cache` container automatically

### 2. Rapid7 Sync Function (`src/functions/rapid7_sync_function.py`)
**Purpose:** Timer-triggered function that keeps Rapid7 data fresh

**Schedule:** `0 */6 * * *` (every 6 hours)

**Process:**
1. Fetches credentials from Key Vault
2. Initializes Rapid7BulkExportCollector
3. Runs full export (10-20 minutes)
4. Caches parsed data to Blob Storage
5. Logs results to Application Insights

**Configuration:** `Rapid7SyncFunction/function.json`
```json
{
  "schedule": "0 */6 * * *",
  "runOnStartup": false,
  "useMonitor": true
}
```

### 3. Updated Collector (`src/collectors/rapid7_bulk_export_collector.py`)
**Purpose:** Enhanced to check cache before fetching from API

**New Logic:**
```python
async def collect():
    # 1. Try cache first
    cached_data = cache_manager.get_cache("rapid7-bulk-export-latest", max_age_hours=6)
    
    if cached_data:
        return instant_result(cached_data)  # INSTANT!
    
    # 2. Fall back to API if cache miss/expired
    result = await fetch_from_rapid7_api()  # 10-20 min
    
    return result
```

### 4. Function Timeout (`host.json`)
**Updated:** Increased timeout from default (5 min) to 30 minutes
```json
{
  "functionTimeout": "00:30:00"
}
```

---

## Benefits

### For Weekly Reports
- **Before:** 20+ minutes every time (waiting for Rapid7)
- **After:** INSTANT (reads from cache)

### Data Freshness
- Data never more than 6 hours old
- Automatic background updates
- No manual intervention required

### Reliability
- Falls back to live API if cache fails
- Retry logic in Timer Function
- Logs to Application Insights for monitoring

### Cost
- **Timer Function:** ~$0.40/month (free tier covers it)
- **Blob Storage:** ~$0.02/month for cache data
- **Total:** Essentially free

---

## Deployment

### Automatic
The timer function will start automatically after deployment:

```bash
func azure functionapp publish your-function-app
```

### Manual Trigger (Optional)
To populate cache immediately without waiting for the timer:

```bash
# Azure Portal
Navigate to: Function App → Functions → Rapid7SyncFunction → Code + Test → Test/Run

# Or via Azure CLI
az rest --method post \
  --url "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}/functions/Rapid7SyncFunction/triggers/default/invoke?api-version=2022-03-01"
```

### Monitoring

**View Timer Logs:**
```bash
func azure functionapp logstream your-function-app --browser
```

**Or in Azure Portal:**
```
Function App → Functions → Rapid7SyncFunction → Monitor
```

**Check Cache Status:**
```bash
az storage blob list \
  --account-name your-storage \
  --container-name cache \
  --prefix rapid7-bulk-export
```

---

## Cache Behavior

### Cache Key
- **Format:** `rapid7-bulk-export-latest.json`
- **Location:** `cache` container in storage account
- **Content:** Complete CVE exposure mapping with asset counts

### TTL (Time To Live)
- **Duration:** 6 hours
- **Check:** Based on Blob Storage `last_modified` timestamp
- **Expiration:** Automatic (no cleanup needed)

### Cache Hit Flow
```
Report Request → Check cache timestamp
  ├─ If < 6 hours old: Load from cache (instant)
  └─ If ≥ 6 hours old: Fetch from API (20 min)
```

### Cache Miss Scenarios
1. **First run:** No cache exists yet → fetch from API
2. **Expired:** Cache > 6 hours old → fetch from API
3. **Corrupted:** Invalid JSON → fetch from API
4. **Storage error:** Can't access Blob → fetch from API

---

## Configuration Options

### Change Cache Duration
Edit in collector or sync function:
```python
cache_manager.get_cache(cache_key, max_age_hours=12)  # 12 hours instead of 6
```

### Change Timer Schedule
Edit `Rapid7SyncFunction/function.json`:
```json
{
  "schedule": "0 */4 * * *"  // Every 4 hours instead of 6
}
```

**Common Schedules:**
- Every 4 hours: `0 */4 * * *`
- Every 12 hours: `0 */12 * * *`
- Daily at 2am: `0 2 * * *`
- Twice daily (6am, 6pm): `0 6,18 * * *`

### Disable Timer (Use Cache Only)
Set `runOnStartup: false` and never manually trigger. Reports will fetch from API when cache expires.

### Disable Cache (Always Fetch Fresh)
Remove cache check from collector (not recommended - defeats the purpose).

---

## Troubleshooting

### Timer Not Running
**Check:**
1. Function deployed successfully: `func azure functionapp list-functions your-app`
2. Timer enabled: Check `function.json` → `runOnStartup: false` is correct
3. Function logs: `func azure functionapp logstream your-app`

### Cache Always Expired
**Check:**
1. Blob Storage timestamp: `az storage blob show --account-name X --container cache --name rapid7-bulk-export-latest.json`
2. Timer execution history: Azure Portal → Function App → Rapid7SyncFunction → Monitor
3. Sync function logs for errors

### Reports Still Slow
**Check:**
1. Cache exists: `az storage blob list --account-name X --container cache`
2. Cache is fresh (< 6 hours): Check blob properties
3. Collector logs: Should say "Using cached Rapid7 data"

### Export Times Out
**Check:**
1. Function timeout set to 30 min: Review `host.json`
2. Rapid7 export status: May need to increase `max_attempts` in collector
3. Consider running during off-hours when Rapid7 is less busy

---

## Future Enhancements

### Possible Improvements
1. **Multiple cache keys:** Separate caches for weekly vs quarterly reports
2. **Compression:** Gzip cache files to reduce storage costs
3. **Delta updates:** Only fetch changed CVEs instead of full export
4. **Cosmos DB:** Upgrade from Blob to Cosmos for faster queries
5. **Notifications:** Alert if sync fails multiple times

### Not Needed Currently
- Database storage (Blob is sufficient for JSON cache)
- Real-time sync (6-hour freshness is plenty for weekly reports)
- Multiple regions (single region is fine)

---

## Summary

**What Changed:**
- Added background timer that syncs Rapid7 data every 6 hours
- Added Blob Storage caching layer
- Reports now instant instead of 20+ minute wait

**What You Need to Do:**
- Deploy updated code: `func azure functionapp publish your-app`
- Verify timer is running: Check Azure Portal
- Run first report to confirm cache works

**What Happens Automatically:**
- Timer fetches Rapid7 data every 6 hours
- Cache is kept fresh automatically
- Reports read from cache (instant!)
- Falls back to API only if needed

**Result:**
✅ Weekly reports now instant
✅ Data always fresh (< 6 hours old)
✅ No manual intervention needed
✅ Cost: essentially free (~$0.40/month)
