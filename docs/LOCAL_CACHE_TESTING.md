# Local Rapid7 Cache - Quick Testing Guide

## Problem
Waiting 10-20 minutes for Rapid7 exports every time you test is painful.

## Solution
Local file cache that stores Rapid7 data for instant testing.

---

## Quick Start

### 1. Fetch Data Once (20 minutes)
```bash
python cache_rapid7_local.py --fetch
```

This will:
- Fetch from Rapid7 API (10-20 min wait)
- Save to `.cache/rapid7_local_cache.json`
- Enable instant testing for next 24 hours

### 2. Test Instantly (2 minutes)
```bash
python test_local.py weekly --local --real
```

Now uses cached data - **reports complete in ~2 minutes!**

---

## Commands

### Check Cache Status
```bash
python cache_rapid7_local.py --info
```

Shows:
- If cache exists
- How old it is
- How many CVEs
- File size

### Refresh Cache
```bash
python cache_rapid7_local.py --fetch
```

Fetches fresh data from Rapid7 and updates cache.

### Clear Cache
```bash
python cache_rapid7_local.py --clear
```

Deletes local cache file.

---

## How It Works

```
Report Run
    ↓
Check Local Cache (.cache/)
    ↓
┌───────────────┐
│ Cache Found?  │
└───────────────┘
   /          \
  YES         NO
   ↓           ↓
Use Cache   Fetch from API
(Instant)   (20 minutes)
   ↓           ↓
   └─────┬─────┘
         ↓
   Generate Report
```

---

## Cache Priority

1. **Local File Cache** (`.cache/rapid7_local_cache.json`)
   - For testing/development
   - 24-hour TTL
   - Instant access

2. **Azure Blob Cache** (from timer function)
   - For production
   - 6-hour TTL
   - When timer deployed

3. **Live API** (fallback)
   - Always works
   - 10-20 minute wait
   - No cache available

---

## Benefits for Testing

### Before
```bash
$ python test_local.py weekly --local --real
[Wait 20 minutes...]
✓ Report generated

$ # Make a small change, test again
$ python test_local.py weekly --local --real
[Wait 20 minutes AGAIN...]
✓ Report generated
```

### After
```bash
$ # First time - fetch data
$ python cache_rapid7_local.py --fetch
[Wait 20 minutes once]
✓ Cached 1234 CVEs

$ # Test instantly
$ python test_local.py weekly --local --real
[2 minutes]
✓ Report generated

$ # Test again - still instant!
$ python test_local.py weekly --local --real
[2 minutes]
✓ Report generated

$ # Test 100 times - all instant!
```

---

## Cache Details

**Location:** `.cache/rapid7_local_cache.json`

**Format:**
```json
{
  "cached_at": "2026-05-22T17:45:00Z",
  "record_count": 1234,
  "data": {
    "cve_exposure_map": { ... },
    "total_cves": 1234,
    ...
  }
}
```

**TTL:** 24 hours

**Auto-refresh:** No - run `--fetch` manually when you want fresh data

---

## When to Refresh Cache

### Refresh When:
- ✅ Testing new gate logic
- ✅ Want fresh vulnerability data
- ✅ Cache is > 24 hours old
- ✅ Major changes in your environment

### Don't Refresh When:
- ✅ Testing report formatting
- ✅ Testing AI prompts
- ✅ Testing document generation
- ✅ Iterating on code changes

---

## Production vs Testing

### Testing (Local Cache)
```bash
# Use local cache - instant testing
python test_local.py weekly --local --real
```

### Production (Azure Function)
```bash
# Uses Azure Blob cache or live API
# Deployed function app handles this automatically
```

---

## Tips

1. **Fetch once per day** during active development
2. **Use cached data** for rapid iteration
3. **Clear cache** if something seems wrong
4. **Check cache info** to see freshness

---

## Troubleshooting

### "No cache found"
**Run:** `python cache_rapid7_local.py --fetch`

### "Cache expired"
**Run:** `python cache_rapid7_local.py --fetch`

### "Cache corrupted"
**Run:** 
```bash
python cache_rapid7_local.py --clear
python cache_rapid7_local.py --fetch
```

### "Still waiting 20 minutes"
**Check:** 
```bash
python cache_rapid7_local.py --info
```

If cache exists but not being used, check logs for why.

---

## Automatic Caching

The collector now **automatically** saves to local cache after successful API fetch:

```
Fetch from Rapid7 API (20 min)
    ↓
Download & Parse Data
    ↓
✓ Saved to local cache for faster future testing
    ↓
Next run uses cache (instant!)
```

So you only need to run `--fetch` manually if:
- You want to force a refresh
- Cache doesn't exist yet
- Something went wrong

---

## Summary

**One-time setup:**
```bash
python cache_rapid7_local.py --fetch
# Wait 20 minutes
```

**Ongoing testing:**
```bash
python test_local.py weekly --local --real
# Takes 2 minutes (uses cache)
# Test as many times as you want!
```

**Refresh when needed:**
```bash
python cache_rapid7_local.py --fetch
# Wait 20 minutes
# Cache refreshed for another 24 hours
```

---

**Result:** Test gate framework and reports instantly without waiting for Rapid7 every time! 🚀
