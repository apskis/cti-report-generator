# Rapid7 Collector Fallback Behavior

## Overview

The Rapid7 Bulk Export collector is designed to work in **two modes** with automatic fallback:

1. **🚀 Fast Mode (Optimal)**: Uses cached data from timer function - **INSTANT**
2. **🐢 Slow Mode (Fallback)**: Fetches directly from Rapid7 API - **10-20 minutes**

**The collector ALWAYS works**, even if the timer function isn't deployed!

---

## How It Works

```
Report Run Started
    ↓
┌─────────────────────────────────────────┐
│  1. Check if cache exists               │
│     (from timer function)               │
└─────────────────────────────────────────┘
    ↓
    ├─ Cache Found & Fresh (< 6 hours)
    │     ↓
    │  ✓ Use cached data
    │  ✓ Report completes INSTANTLY
    │  ✓ Log: "Using cached Rapid7 data"
    │
    └─ No Cache OR Cache Expired OR Timer Not Deployed
          ↓
       ✓ Fall back to live Rapid7 API
       ✓ Create export (GraphQL)
       ✓ Wait 10-20 minutes
       ✓ Download & parse Parquet files
       ✓ Report completes (slower but works!)
       ✓ Log: "Fetching from Rapid7 Bulk Export API"
```

---

## Scenarios

### Scenario 1: Timer Function Deployed and Working ✅
**What happens:**
- Timer runs every 6 hours automatically
- Cache is always fresh
- Reports complete instantly
- Logs show: `"✓ Using cached Rapid7 data: X CVEs (from timer function)"`

**User experience:** Best - instant reports

---

### Scenario 2: Timer Function Not Yet Deployed ⚠️
**What happens:**
- No cache exists
- Collector automatically uses live API
- Reports take 10-20 minutes
- Logs show: `"Cache not configured, using live Rapid7 API"`

**User experience:** Slower but fully functional

---

### Scenario 3: Timer Function Deployed but Failed ⚠️
**What happens:**
- Cache might be stale or empty
- Collector detects expired/missing cache
- Falls back to live API automatically
- Reports take 10-20 minutes
- Logs show: `"No fresh cache found (timer function hasn't run or cache expired)"`

**User experience:** Slower but fully functional

---

### Scenario 4: Timer Function Deployment Issues (Your Current Situation) ⚠️
**What happens:**
- Timer function deployment stuck (503 or SSL errors)
- Reports still work using live API
- No action required to unblock reports
- Can fix timer deployment later

**User experience:** Reports work immediately, timer is optional optimization

---

## Current State: You're Unblocked! ✅

### What Works RIGHT NOW
- ✅ Rapid7 collector works via live API
- ✅ Weekly reports will complete successfully
- ✅ Data is comprehensive and accurate
- ✅ No deployment blockers

### What's Different
- ⏱️ Reports take 10-20 minutes instead of instant
- 📊 Same data, same quality, just slower
- 🔧 Timer function is an optimization, not a requirement

---

## Testing Fallback Logic

### Quick Test
```bash
python test_rapid7_fallback.py
```

This verifies:
1. Collector checks cache first
2. Falls back to API if no cache
3. Always returns data

### Full Integration Test
```bash
python test_local.py weekly --local --real
```

**Expected behavior:**
- If timer deployed: Report completes in ~2 minutes
- If timer not deployed: Report completes in ~20 minutes
- Either way: Report is generated successfully

---

## Logs to Watch For

### Cache Hit (Fast Mode)
```
INFO - Using cached Rapid7 data: 1234 CVEs (from timer function)
INFO - Cache is fresh and reports will complete instantly
```

### Cache Miss (Fallback Mode)
```
INFO - No fresh cache found (timer function hasn't run or cache expired)
INFO - Falling back to live Rapid7 API (this is normal)
INFO - Fetching vulnerability data via Rapid7 Bulk Export API (region: us2)
INFO - Note: This may take 10-20 minutes for large environments
INFO - TIP: Deploy timer function to make this instant
```

### Cache Unavailable (Timer Not Deployed)
```
WARNING - Cache unavailable (timer function may not be deployed): <error>
INFO - Falling back to live Rapid7 API (this is the backup method)
INFO - Fetching vulnerability data via Rapid7 Bulk Export API
```

---

## When to Deploy Timer Function

### Deploy Timer When:
- ✅ You want instant reports (< 2 minutes)
- ✅ You run reports frequently
- ✅ Azure deployment issues are resolved
- ✅ You want to optimize user experience

### Skip Timer If:
- ✅ You only run reports weekly (once)
- ✅ 10-20 minute wait is acceptable
- ✅ Having deployment issues
- ✅ Want to keep architecture simple

---

## Deployment Timeline

### Immediate (No Blockers)
1. ✅ Push code (already done)
2. ✅ Run reports using live API (works now)
3. ✅ Weekly reports function normally

### When Ready (Optional Optimization)
1. Fix Azure deployment issues (503/SSL errors)
2. Deploy timer function: `func azure functionapp publish func-cti-automation`
3. Wait for first sync (or trigger manually)
4. Future reports will be instant

---

## Configuration

### Current Settings
- **Timeout**: 20 minutes (increased from 10 for safety)
- **Poll interval**: 10 seconds
- **Max attempts**: 120 (20 minutes total)
- **Cache TTL**: 6 hours (when timer is deployed)

### No Changes Needed
The collector automatically adapts to available infrastructure:
- Cache available → use it (fast)
- Cache unavailable → use API (slow but works)

---

## Troubleshooting

### "Reports are slow!"
**Check:** Is timer function deployed and running?
```bash
az functionapp function show \
  --name func-cti-automation \
  --resource-group rg-cti-reporting-prod \
  --function-name Rapid7SyncFunction
```

**If not deployed:** Reports use fallback (expected behavior)
**If deployed but not running:** Check timer logs

### "Cache errors in logs"
**This is OK!** Collector falls back to API automatically.

The warnings just inform you that optimization isn't active:
- `Cache unavailable` → Timer not deployed (expected)
- `No fresh cache found` → Timer hasn't run yet (wait for next scheduled time)
- `Cache check failed` → Transient storage issue (retry next time)

### "Export timeout"
**Rare but possible:** Rapid7 export takes > 20 minutes

**Solutions:**
1. Run during off-hours (less queue time)
2. Increase timeout in collector (change `max_attempts`)
3. Contact Rapid7 support if persistent

---

## Best Practices

### For Weekly Reports
1. **First run of the day:**
   - Will take 10-20 minutes (cache expired or not deployed)
   - Be patient, export is processing

2. **Subsequent runs (if timer deployed):**
   - Will be instant (< 2 minutes)
   - Uses cached data

3. **Weekly cadence:**
   - Timer optimization is less valuable
   - Consider running without timer
   - Save deployment complexity

### For Daily/Frequent Reports
1. **Definitely deploy timer function**
   - Huge time savings (20 min → 2 min)
   - Worth the deployment effort
   - Better user experience

---

## Summary

| Feature | With Timer | Without Timer |
|---------|-----------|---------------|
| **Report Speed** | Instant (~2 min) | Slow (~20 min) |
| **Data Quality** | Same | Same |
| **Reliability** | Same | Same |
| **Deployment** | Complex | Simple |
| **Azure Cost** | +$0.40/month | No change |
| **Recommended For** | Daily reports | Weekly reports |

**Bottom Line:**
- Timer function = nice-to-have optimization
- Live API fallback = must-have reliability
- You can run reports RIGHT NOW without timer
- Deploy timer when convenient, not urgent

---

## Next Steps

### Option A: Run Reports Now (Recommended)
```bash
python test_local.py weekly --local --real
```
Wait 10-20 minutes, report completes successfully.

### Option B: Deploy Timer Later (When Ready)
1. Fix Azure deployment issues
2. Deploy function app
3. Future reports will be instant

### Option C: Skip Timer Entirely
If weekly reports are acceptable at 10-20 minutes, you don't need the timer at all!

---

**You're not blocked!** The collector works perfectly without the timer function.
