# Rapid7 Console API Integration Guide

## Overview

The Rapid7 **Cloud Integration API v4** has severe limitations - it only returns a small subset of your vulnerability data. To get comprehensive CVE exposure data, you need to use the **Console API** (REST API v3) which provides full access to your InsightVM/Nexpose console.

## Current Status

- ✅ Cloud Integration API v4 collectors exist but are LIMITED
- 🚧 Console API collector created but needs CVE extraction logic completed
- ⚠️ You're only seeing 1 CVE because the Cloud API doesn't return your full dataset

## Steps to Use Console API

### 1. Add Console API Credentials to Azure Key Vault

Add these three secrets to your Azure Key Vault:

```
rapid7-console-url      # e.g., https://your-console.rapid7.com
rapid7-console-user     # Your console username
rapid7-console-pass     # Your console password
```

### 2. Register the Console Collector

Edit `src/collectors/registry.py` and add:

```python
from src.collectors.rapid7_console_collector import Rapid7ConsoleCollector

# In the get_all_collectors() function, add:
Rapid7ConsoleCollector,
```

### 3. Enable in Config

Edit `config/collectors.yaml` and add:

```yaml
rapid7_console:
  enabled: true
  description: "Rapid7 InsightVM Console API (full access)"
```

## Console API Endpoints Needed

The Console API provides these key endpoints for comprehensive vulnerability data:

### Get All Vulnerabilities with CVEs
```
GET /api/3/vulnerabilities?size=500&page=0
```
Returns vulnerability definitions including:
- CVE IDs
- Severity
- Description
- Exploit availability

### Get Assets with Vulnerabilities
```
GET /api/3/assets/{assetId}/vulnerabilities
```
Returns vulnerability instances for a specific asset.

### Alternative: Vulnerability Search
```
POST /api/3/vulnerability_instances/search
```
Search for vulnerability instances across all assets with filters.

## Recommended Implementation Approach

**Option A: Use Vulnerability Search (BEST)**
```
POST /api/3/vulnerability_instances/search
```
This single endpoint can return:
- All vulnerability instances
- Asset details
- CVE IDs
- Status (exploited, vulnerable, etc.)

**Option B: Asset + Vulnerability Iteration**
1. Get all assets: `GET /api/3/assets`
2. For each asset: `GET /api/3/assets/{id}/vulnerabilities`
3. For each vulnerability: `GET /api/3/vulnerabilities/{id}` to get CVE

## Next Steps

1. **Add the Console API credentials** to Azure Key Vault
2. **Choose implementation approach** (I recommend Option A - vulnerability search)
3. **Complete the CVE extraction logic** in `rapid7_console_collector.py`
4. **Test with your console** to verify comprehensive data retrieval

## API Documentation

- Console API v3: https://help.rapid7.com/insightvm/en-us/api/index.html
- Vulnerability Instances: https://help.rapid7.com/insightvm/en-us/api/api.html#tag/Vulnerability-Instance
- Vulnerability Search: https://help.rapid7.com/insightvm/en-us/api/api.html#operation/getVulnerabilityInstances

## Why This Matters

**Cloud Integration API v4:**
- Returns: 1 vulnerability
- Limited data access
- Designed for basic integrations

**Console API v3:**
- Returns: ALL your vulnerabilities (you said you have "tons")
- Full access to scan data
- Complete asset and vulnerability correlation
- Proper CVE-to-asset mapping

Once implemented, your weekly reports will accurately reflect your actual vulnerability landscape!
