# Report Metrics - Quick Reference

## This Week at a Glance - Explained

### Top Row Metrics

1. **New This Week**
   - CVEs that appeared for the first time in Rapid7 scans
   - Source: Rapid7 InsightVM

2. **Persistent (3+ Wks)**
   - CVEs unresolved from prior reports (tracked for 3+ consecutive weeks)
   - These are highlighted in the Vulnerability Exposure table with yellow/red backgrounds
   - Yellow = 3 weeks, Red = 4+ weeks (long overdue)

3. **Resolved**
   - CVEs remediated since last week
   - Count of vulnerabilities that were present but are now fixed

### Bottom Row Metrics

4. **Total Exposed**
   - Total number of CVEs currently detected on assets
   - Combines new + persistent CVEs

5. **Actively Exploited**
   - CVEs confirmed to be exploited by threat actors
   - Source: CISA KEV catalog + enrichment data

6. **Actor Groups**
   - **FIXED**: Now counts only actual threat actor groups
   - Previously counted all CrowdStrike data (actors + indicators + vulnerabilities)
   - Source: CrowdStrike Falcon Intelligence
   - Filters for actors targeting biotech/healthcare/manufacturing sectors

## Vulnerability Exposure Table

### Columns Explained

| Column | Description |
|--------|-------------|
| **CVE ID** | CVE identifier |
| **Affected Product** | Vendor and product name (from CISA KEV or pattern matching) |
| **Exposure** | Number of affected assets (from Rapid7 scans) |
| **Exploited By** | Who is exploiting this (threat actors, ransomware groups, or "None known") |
| **Risk** | Severity level (Critical, High, Medium) |
| **Wks** | **Consecutive weeks detected** - Shows how long this CVE has been unresolved |

### Wks Column Highlighting

- **No highlight**: New this week (Week 1)
- **Yellow highlight**: 3 weeks - Persistent, needs attention
- **Red highlight**: 4+ weeks - Long overdue, urgent action required

The "7 Persistent (3+ Wks)" metric at the top corresponds to all CVEs with Wks >= 3 in the table.

## Recent Fixes

### Issue #1: Actor Groups Count (FIXED)
- **Problem**: Counted all CrowdStrike data items (actors + indicators + Spotlight vulnerabilities)
- **Impact**: Showed inflated numbers like "49 Actor Groups" when only ~10-15 actual groups were active
- **Fix**: Now filters to count only items with `type == "actor"`
- **Code**: `apt_groups: len([item for item in crowdstrike_data if item.get('type') == 'actor'])`

### Issue #2: Persistent CVEs Not Visible (FIXED)
- **Problem**: "7 Persistent (3+ Wks)" metric shown but no way to identify which CVEs in the table
- **Impact**: Users couldn't prioritize the persistent vulnerabilities
- **Fix**: 
  - Table already had "Wks" column with highlighting (yellow for 3+, red for 4+)
  - Updated AI prompt to populate `weeks_detected` field
  - Enhanced table caption to explain highlighting
  - Now persistent CVEs are clearly visible with color coding

## How Weeks Tracking Works

**Current Implementation:**
- The AI assigns `weeks_detected` values based on CVE age and context
- Default is 1 (new this week)
- Can be set higher based on publish date or recurring nature

**Future Enhancement:**
- Database tracking of historical CVE detections
- Automatic increment of weeks_detected for CVEs seen in previous reports
- True week-over-week persistence tracking

## Testing the Fixes

Run a new report and verify:

1. **Actor Groups count is realistic** (should be 5-20, not 40-50)
   - Check CrowdStrike data includes actors targeting your industries

2. **Persistent CVEs are highlighted**
   - Look for yellow/red highlighted cells in the "Wks" column
   - Match count to "Persistent (3+ Wks)" metric at top

3. **Caption explains the highlighting**
   - Should mention yellow for 3+ weeks, red for 4+ weeks

```powershell
# Run local test
python test_local.py weekly --local --real
```
