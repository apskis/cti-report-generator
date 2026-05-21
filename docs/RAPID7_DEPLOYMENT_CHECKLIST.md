# Rapid7 Background Sync - Deployment Checklist

## Pre-Deployment Verification

- [ ] Code pushed to main branch
- [ ] Azure Function App created
- [ ] Managed Identity enabled
- [ ] Key Vault access granted
- [ ] Storage Account configured

## Deployment Steps

### 1. Deploy Function App
```bash
func azure functionapp publish your-function-app-name
```

**Expected output:**
```
Deployment successful.
Functions in your-function-app-name:
  - Rapid7SyncFunction [timerTrigger]
  - WeeklyReportGenerator [httpTrigger]
```

### 2. Verify Timer Function Deployed
```bash
func azure functionapp list-functions your-function-app-name
```

**Look for:**
- `Rapid7SyncFunction` in the list
- Status: Enabled

### 3. Check Timer Schedule
**Azure Portal:**
1. Navigate to: Function App → Rapid7SyncFunction
2. Click "Integration"
3. Verify schedule: `0 */6 * * *` (every 6 hours)

### 4. Verify Storage Container
```bash
az storage container show \
  --account-name your-storage \
  --name cache
```

**If doesn't exist (first run), it will be created automatically.**

## First Run Test

### Option A: Wait for Timer (Recommended)
The timer will run at the next scheduled time:
- 12:00 AM UTC
- 6:00 AM UTC
- 12:00 PM UTC
- 6:00 PM UTC

### Option B: Manual Trigger (Immediate)

**Azure Portal:**
1. Navigate to: Function App → Rapid7SyncFunction
2. Click "Code + Test"
3. Click "Test/Run"
4. Click "Run"
5. Monitor execution (will take 10-20 minutes)

**Expected logs:**
```
Rapid7 sync function started at 2026-05-21T...
Starting Rapid7 bulk export collection...
Created vulnerability export: <export-id>
Export status: PROCESSING
...
Export succeeded! Got X download URLs
Successfully cached Y CVEs from Rapid7
Rapid7 sync function completed
```

## Post-Deployment Verification

### 1. Check Function Execution History
**Azure Portal:**
```
Function App → Rapid7SyncFunction → Monitor → Invocations
```

**Look for:**
- Status: Success
- Duration: 10-20 minutes
- Log: "Successfully cached X CVEs"

### 2. Verify Cache Created
```bash
az storage blob list \
  --account-name your-storage \
  --container-name cache \
  --prefix rapid7
```

**Expected:**
```
Name: rapid7-bulk-export-latest.json
Last Modified: <recent timestamp>
Size: ~XXX KB
```

### 3. Test Weekly Report
```bash
# Local test
python test_local.py weekly --local --real

# Or trigger Azure Function
curl https://your-function-app.azurewebsites.net/api/weekly-report
```

**Expected logs:**
```
Using cached Rapid7 data: X CVEs
```

**Report should complete in < 2 minutes (not 20+ minutes!)**

## Monitoring Setup

### Enable Application Insights (if not already)
```bash
az functionapp config appsettings set \
  --name your-function-app \
  --resource-group your-rg \
  --settings "APPINSIGHTS_INSTRUMENTATIONKEY=<key>"
```

### Create Alert for Failed Syncs
**Azure Portal:**
1. Navigate to: Application Insights → Alerts
2. Create new alert rule:
   - Signal: Failed requests
   - Resource: Rapid7SyncFunction
   - Condition: Count > 2 in last 24 hours
   - Action: Send email/SMS

## Troubleshooting

### Timer Not Running
```bash
# Check function status
az functionapp function show \
  --name your-function-app \
  --resource-group your-rg \
  --function-name Rapid7SyncFunction
```

**If disabled, enable:**
```bash
az functionapp function enable \
  --name your-function-app \
  --resource-group your-rg \
  --function-name Rapid7SyncFunction
```

### Cache Not Created
**Check logs:**
```bash
func azure functionapp logstream your-function-app --browser
```

**Common issues:**
- Storage account key incorrect
- Container permissions
- Export timeout

**Fix:** Review logs, update Key Vault secrets if needed

### Reports Still Slow
**Verify cache is being used:**
1. Check blob timestamp (< 6 hours old?)
2. Check report logs for "Using cached Rapid7 data"
3. If not found, cache may be expired or corrupted

**Solution:** Manually trigger sync function

## Success Criteria

- [ ] Timer function deployed and enabled
- [ ] First sync completed successfully (10-20 min)
- [ ] Cache blob created in storage
- [ ] Weekly report completes in < 2 minutes
- [ ] Report logs show "Using cached Rapid7 data"
- [ ] Application Insights showing successful executions

## Rollback Plan

If issues occur:

### 1. Disable Timer Function
```bash
az functionapp function disable \
  --name your-function-app \
  --resource-group your-rg \
  --function-name Rapid7SyncFunction
```

### 2. Reports Will Fall Back to Live API
- Reports will take 20+ minutes again
- No cache will be used
- Still functional, just slower

### 3. Fix Issues
- Review logs
- Update configuration
- Test locally

### 4. Re-enable Timer
```bash
az functionapp function enable \
  --name your-function-app \
  --resource-group your-rg \
  --function-name Rapid7SyncFunction
```

## Support

**Documentation:**
- Detailed guide: `docs/RAPID7_BACKGROUND_SYNC.md`
- README: Deployment section updated

**Logs:**
```bash
# Real-time logs
func azure functionapp logstream your-function-app

# Historical logs (Azure Portal)
Function App → Rapid7SyncFunction → Monitor → Logs
```

**Health Check:**
```bash
# Check last sync time
az storage blob show \
  --account-name your-storage \
  --container-name cache \
  --name rapid7-bulk-export-latest.json \
  --query properties.lastModified
```
