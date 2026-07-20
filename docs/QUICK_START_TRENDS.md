# Quick Start: Historical Tracking Features

## What's New?

Your CTI Report Generator now tracks history and shows trends! 🎉

### Before
```
Week 1: 15 CVEs found
Week 2: 12 CVEs found
Week 3: 18 CVEs found
```
❌ No context - Are these new? Resolved? Recurring?

### After
```
Week 1: 15 CVEs found
Week 2: 12 CVEs found (3 new, 9 persistent, 6 resolved)
Week 3: 18 CVEs found (10 new, 8 persistent, 2 resolved)
```
✅ Full context - You know exactly what changed!

## How It Works

### Simple 3-Step Flow

```
┌─────────────────────────────────────────────────────────┐
│  Week 1                                                 │
│  ─────────────────────────────────────────────────────  │
│  1. Collect threat data                                 │
│  2. AI analyzes threats                                 │
│  3. Save analysis to Azure Blob Storage ← NEW!          │
│                                                          │
│  Report: "15 CVEs detected this week"                   │
└─────────────────────────────────────────────────────────┘

                         ↓

┌─────────────────────────────────────────────────────────┐
│  Week 2                                                 │
│  ─────────────────────────────────────────────────────  │
│  1. Collect threat data                                 │
│  2. Get Week 1 analysis from Blob Storage ← NEW!        │
│  3. Calculate trends (new, persistent, resolved)        │
│  4. AI analyzes with trend context                      │
│  5. Save Week 2 analysis to Blob Storage                │
│                                                          │
│  Report: "Trend Analysis: 3 new CVEs detected;          │
│           9 CVEs remain unresolved from last week;      │
│           6 CVEs resolved since last week"              │
└─────────────────────────────────────────────────────────┘
```

## What You Get

### 1. Executive Summary Enhancement
**Before:**
> This week shows 15 critical CVEs actively exploited in the wild...

**After:**
> **Trend Analysis:** 3 new CVEs detected; 9 CVEs remain unresolved from last week; 6 CVEs resolved since last week
>
> **Actor Trends:** 2 new threat actors identified; 5 actors remain active from last report
>
> This week shows 15 critical CVEs actively exploited in the wild...

### 2. CVE Persistence Tracking
CVEs now show how long they've been detected:

| CVE ID | Severity | Weeks Detected | Status |
|--------|----------|----------------|--------|
| CVE-2024-1234 | CRITICAL | **3** | ⚠️ Persistent issue |
| CVE-2024-5678 | HIGH | **1** | 🆕 New this week |
| CVE-2024-9999 | CRITICAL | **5** | ⚠️⚠️ Long-term exposure |

### 3. Threat Actor Timeline
Track which actors are new vs. ongoing threats:
- **New Actors**: APT99 (first appearance)
- **Persistent Actors**: APT28, APT29 (active for 3+ weeks)
- **Inactive Actors**: APT10 (no longer detected)

### 4. Historical Metrics
See how your threat landscape is changing over time:

```
Week   | Total CVEs | Exploited | Threat Actors
-------|------------|-----------|---------------
May 01 |     15     |     8     |      12
May 08 |     12     |     6     |      10
May 15 |     18     |    11     |      14
May 22 |     14     |     7     |      11
       |            |           |
Trend  |    ↓ 7%   |   ↓ 13%  |    ↓ 8%
```

## Getting Started

### Option 1: Automatic (Already Works!)
No changes needed. The system automatically:
1. Saves analysis contexts to Azure Blob Storage
2. Retrieves previous contexts on next run
3. Calculates and displays trends

**Just run your weekly report as normal!**

```bash
# Azure Functions
curl -X POST https://your-function-app.azurewebsites.net/api/GenerateWeeklyReport

# Local testing
python test_local.py weekly --local --real
```

### Option 2: Test the Features
Run the test suite to verify everything works:

```bash
# Set your Azure Storage credentials
export STORAGE_ACCOUNT_NAME="your-storage-account"
export STORAGE_ACCOUNT_KEY="your-storage-key"

# Run tests
python test_context_management.py
```

Expected output:
```
✅ Context manager initialized
✅ Saved context for 2026-06-01
✅ Retrieved 4 previous contexts
✅ CVE Trends calculated: 2 new CVEs detected; 8 CVEs remain...
✅ ALL TESTS PASSED
```

## What to Expect

### First Report (Week 1)
- ✅ Report generates normally
- ✅ Analysis saved to Blob Storage
- ❌ No trends shown (no previous data yet)

**This is expected!** You need at least one report before trends can be calculated.

### Second Report (Week 2)
- ✅ Report generates normally
- ✅ Retrieves Week 1 context
- ✅ **Trends appear in executive summary!**
- ✅ Analysis saved for Week 3

### Third Report (Week 3+)
- ✅ Full trend analysis with 3+ weeks of history
- ✅ Persistent CVEs highlighted
- ✅ Week-over-week metrics
- ✅ Actor timeline tracking

## Checking It Works

### 1. Verify Blob Storage
Log into Azure Portal → Storage Account → Containers → `cache`

You should see files like:
```
analysis-context-weekly-2026-06-01.json
cve-tracking-weekly-2026-06-01.json
actor-timeline-weekly-2026-06-01.json
```

### 2. Check Report Output
Open your generated report and look for:
- Executive Summary starts with "Trend Analysis: ..."
- CVE table includes "Weeks Detected" column
- Trend insights throughout the report

### 3. Review Function Logs
```bash
# Azure Functions logs
func azure functionapp logstream your-function-app

# Look for:
"Retrieving historical contexts for trend analysis..."
"CVE Trends: 2 new CVEs detected; 8 CVEs remain..."
"Analysis context saved successfully"
```

## Troubleshooting

### "No trends shown in Week 2+"
**Check:**
1. Azure Blob Storage credentials correct?
2. Container `cache` exists?
3. Previous week's contexts saved?

**Fix:**
```bash
# List saved contexts
python test_context_management.py
```

### "Context save failed" in logs
**Check:**
1. Storage account permissions
2. Network connectivity to Azure
3. Container creation permissions

**Fix:**
Manually create container:
```bash
az storage container create --name cache --account-name YOUR_ACCOUNT
```

### "Trends show 0 changes"
**Check:**
1. CVE data structure consistent week-to-week?
2. Date format matching?

**Fix:**
Re-run test suite to validate data format.

## What's Stored in Blob Storage?

### For Each Weekly Report:
```
📦 cache/ (Azure Blob Container)
│
├── 📄 analysis-context-weekly-2026-06-01.json  (~50KB)
│   └── Complete analysis: CVEs, actors, incidents, summary
│
├── 📄 cve-tracking-weekly-2026-06-01.json      (~10KB)
│   └── CVE IDs + severity (fast trend lookups)
│
└── 📄 actor-timeline-weekly-2026-06-01.json    (~5KB)
    └── Threat actor names + activity summary
```

**Storage Cost:** ~$0.01/month for weekly reports 💰

### Retention:
- **Analysis contexts**: 30 days (automatic)
- **Collector caches**: 6 hours (automatic)
- Old contexts expire automatically

## Need Help?

### Documentation
- **Quick Start**: This file (you're reading it!)
- **Complete Guide**: [CONTEXT_MANAGEMENT.md](CONTEXT_MANAGEMENT.md)
- **Implementation Details**: [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
- **Main Docs**: [README.md](README.md)

### Common Questions

**Q: Do I need to change anything in my code?**
A: No! Everything is automatic.

**Q: Will this break my existing reports?**
A: No! Fully backward compatible.

**Q: How much does Blob Storage cost?**
A: ~$0.01/month for weekly reports.

**Q: Can I disable this feature?**
A: Yes, just don't pass `previous_contexts` to the analyzer. It will fall back to standard analysis.

**Q: What if I delete old contexts?**
A: Reports continue to work. Trends just won't go back as far.

## Summary

🎯 **Goal**: Track threats over time, show trends, provide context

✅ **Status**: Implemented and ready to use

🚀 **Action**: Just run your reports as normal - trends will appear automatically after the first run!

📊 **Benefit**: Better insights, executive context, historical awareness

**You're all set!** Run your next weekly report and watch the trends appear. 📈
