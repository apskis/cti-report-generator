# CTI Report Generator

An Azure Functions-based Cyber Threat Intelligence (CTI) reporting system that automatically collects threat data from multiple sources, analyzes it with AI, and generates weekly reports.

## Features

- **Multi-source threat intelligence collection** from:
  - NVD (NIST National Vulnerability Database)
  - Intel471 Titan API (underground threat intelligence)
  - CrowdStrike Falcon Intelligence (threat actors, detections)
  - ThreatQ (IOC management)
  - Rapid7 InsightVM (vulnerability enrichment)
  - Rapid7 InsightVM Scans (environmental CVE exposure with asset counts)
  - OSINT (curated public news and research feeds you control)

- **AI-powered analysis** using Azure OpenAI and Semantic Kernel
- **Automatic AI gap-filling** from Rapid7/NVD backup when AI output is incomplete
- **VPN connectivity check** before analysis with interactive continue/stop prompt
- **Automated Word document generation** with executive summaries and recommendations
- **Azure Blob Storage** integration for report hosting with SAS URLs
- **Modular collector architecture** - easily enable/disable sources
- **Reports always saved locally**, even when uploading to Azure

## Prerequisites

- Python 3.11+
- Azure subscription with:
  - Azure Functions
  - Azure Key Vault
  - Azure Storage Account
  - Azure OpenAI Service
- Azure CLI (`az`) for local development
- Azure Functions Core Tools (`func`)

## Project Structure

```
cti-report-generator/
├── config/
│   ├── collectors.yaml              # Enable/disable API collectors (single source of truth)
│   └── osint_sources.yaml          # OSINT feed configuration (user-editable)
├── src/
│   ├── collectors/                  # Modular API collectors
│   │   ├── base.py                 # Base collector class
│   │   ├── http_utils.py           # HTTP client with retry logic
│   │   ├── nvd_collector.py
│   │   ├── intel471_collector.py
│   │   ├── crowdstrike_collector.py
│   │   ├── threatq_collector.py
│   │   ├── rapid7_collector.py
│   │   ├── rapid7_scan_collector.py
│   │   ├── osint_collector.py      # Curated OSINT RSS feeds
│   │   └── registry.py             # Collector registry
│   ├── agents/
│   │   └── threat_analyst.py       # AI analysis engine
│   ├── reports/
│   │   ├── base.py                 # Report base class
│   │   ├── weekly_report.py        # Weekly report generator
│   │   ├── quarterly_report.py     # Quarterly strategic report
│   │   └── blob_storage.py         # Azure Blob upload
│   ├── core/
│   │   ├── config.py               # Application configuration
│   │   ├── models.py               # Data type definitions
│   │   └── keyvault.py             # Key Vault access
│   └── enrichment/
│       └── cve_enricher.py         # CISA KEV + product enrichment
├── tests/                           # Unit tests
├── function_app.py                  # Azure Function entry point
├── test_local.py                    # Local testing CLI
├── requirements.txt
└── local.settings.json.template
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/apskis/cti-report-generator.git
cd cti-report-generator
```

### 2. Create virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development/testing
```

### 4. Configure local settings

```bash
cp local.settings.json.template local.settings.json
```

Edit `local.settings.json` and set your Key Vault URL (production example):
```json
{
    "Values": {
        "KEY_VAULT_URL": "https://kv-cti-rep-prod.vault.azure.net/"
    }
}
```

## Azure Key Vault Setup

All secrets are stored in Azure Key Vault. Add the following secrets:

### Threat Intelligence API Keys

| Secret Name | Description |
|-------------|-------------|
| `nvd-api-key` | NVD API key |
| `intel471-email` | Intel471 account email |
| `intel471-api-key` | Intel471 API key |
| `crowdstrike-client-id` | CrowdStrike OAuth client ID |
| `crowdstrike-client-secret` | CrowdStrike OAuth client secret |
| `crowdstrike-base-url` | CrowdStrike API base URL (e.g., `https://api.crowdstrike.com`) |
| `threatq-api-key` | ThreatQ API key |
| `threatq-url` | ThreatQ instance URL |
| `rapid7-api-key` | Rapid7 InsightVM API key |
| `rapid7-region` | Rapid7 region (e.g., `us`, `eu`, `ap`) |

### Azure OpenAI

| Secret Name | Description |
|-------------|-------------|
| `openai-api-key` | Azure OpenAI API key |
| `openai-endpoint` | Azure OpenAI endpoint URL |

### Azure Storage

| Secret Name | Description |
|-------------|-------------|
| `storage-account-name` | Storage account name for reports |
| `storage-account-key` | Storage account access key |

### Adding secrets via Azure CLI

```bash
KEYVAULT_NAME="kv-cti-rep-prod"

az keyvault secret set --vault-name $KEYVAULT_NAME --name "nvd-api-key" --value "your-value"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "intel471-email" --value "your-value"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "storage-account-name" --value "ctireportingstorage"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "openai-endpoint" --value "https://ids-secops-openai-prd-eastus2.openai.azure.com/"
# ... repeat for all secrets
```

## Local Development

### 1. Login to Azure

```bash
az login
```

### 2. Run tests

```bash
pytest
```

### 3. Start the function locally

```bash
func start
```

### 4. Trigger the function

```bash
curl -X POST http://localhost:7071/api/GenerateCTIReport
```

## Local Testing

### Testing Commands Reference

#### MOCK Data (No API/Azure access needed)

Test report formatting and UI without any external calls:

```bash
# Weekly report with mock data
python test_local.py weekly --local --mock

# Quarterly report with mock data  
python test_local.py quarterly --local --mock

# With custom output directory
python test_local.py weekly --local --mock --output ./test_reports
```

#### REAL Data - Save Locally (Requires Key Vault access)

Pull actual data from Intel471, CrowdStrike, NVD, etc., run AI analysis, save to disk:

```bash
# Weekly report with real API data
python test_local.py weekly --local --real

# Quarterly report with real API data
python test_local.py quarterly --local --real
```

#### REAL Data - Azure Upload (Full production pipeline)

Pull real data, run AI analysis, upload to Azure Blob Storage:

```bash
# Weekly report - full pipeline
python test_local.py weekly --azure

# Quarterly report - full pipeline
python test_local.py quarterly --azure
```

#### Azure Functions (Alternative)

Run the full Azure Functions locally:

```bash
func start
```

Then call:

- `http://localhost:7071/api/GenerateWeeklyReport`
- `http://localhost:7071/api/GenerateQuarterlyReport`

#### Quick Reference Table

| Command | Data Source | Output | Requires |
|---------|-------------|--------|----------|
| `--local --mock` | Hardcoded examples | Local file | Nothing |
| `--local --real` | APIs + AI | Local file | Key Vault |
| `--azure` | APIs + AI | Azure Blob | Key Vault |

## Configuration

### Environment Variables

| Variable | Description | Production |
|----------|-------------|------------|
| `KEY_VAULT_URL` | Azure Key Vault URL | `https://kv-cti-rep-prod.vault.azure.net/` |
| `ENABLED_COLLECTORS` | Override collectors.yaml (comma-separated) | Uses `config/collectors.yaml` |
| `SQL_SERVER` | SQL server hostname (optional) | `sql-cti-automation-ilmn.database.windows.net` |

### Production settings (Key Vault / config)

| Setting | Production value |
|--------|-------------------|
| Key Vault | `https://kv-cti-rep-prod.vault.azure.net/` |
| Storage account | `ctireportingstorage` |
| OpenAI endpoint | `https://ids-secops-openai-prd-eastus2.openai.azure.com/` |
| Deployment name | `gpt-4.1-cti` (in `config.py` AnalysisConfig) |
| SQL server | `sql-cti-automation-ilmn.database.windows.net` |

Storage account name, OpenAI endpoint, and API keys are stored in Key Vault; the deployment name is in `src/core/config.py`.

### Application Settings (config.py)

- **Lookback periods**: How many days back to collect data
- **Result limits**: Maximum records per source
- **Retry settings**: HTTP retry configuration
- **Analysis settings**: AI model deployment name (`gpt-4.1-cti`), token limits
- **Enrichment settings**:
  - `enable_web_search`: Toggle web search for filling CVE product gaps (default: `True`)
  - `web_search_timeout_seconds`: Timeout per search (default: 5)
  - `max_web_searches_per_run`: Limit searches per enrichment run (default: 10)
  - `kev_cache_duration_hours`: CISA KEV catalog cache duration (default: 24)

**To disable web search**, edit `src/core/config.py` and change:
```python
class EnrichmentConfig:
    enable_web_search: bool = False  # Changed from True
```

### Collectors Configuration: `config/collectors.yaml`

This is the **single source of truth** for which API collectors are active. Enable or disable any collector without touching code:

```yaml
collectors:
  - name: nvd
    description: "NIST National Vulnerability Database"
    enabled: true

  - name: rapid7-scans
    description: "Rapid7 InsightVM Scans - CVE-to-asset exposure mapping"
    enabled: true

  - name: threatq
    description: "ThreatQ - IOC management"
    enabled: false    # <-- disabled
```

Set `enabled: false` to skip a collector. The environment variable `ENABLED_COLLECTORS` overrides this file if set.

### Rapid7 Dual-Collector Architecture

The system uses **two Rapid7 collectors** to provide complete vulnerability intelligence:

#### `rapid7` - Vulnerability Enrichment
- **Purpose:** Provides vulnerability metadata and threat intelligence
- **API:** `/vm/v4/integration/vulnerabilities`
- **Data:** CVE details, CVSS scores, exploit availability, malware kits, descriptions

#### `rapid7-scans` - Environmental Exposure
- **Purpose:** Maps CVEs to actual affected assets in your environment
- **API:** `/vm/v4/integration/assets` + `/vm/v4/integration/asset_vulnerabilities`
- **Data:** Asset counts per CVE (e.g., "12 servers", "3 databases"), asset type classification

**How it works:**
1. `rapid7-scans` queries your scanned assets
2. For each asset, fetches its vulnerabilities
3. Builds a CVE → asset count mapping
4. Threat analyst merges this with vulnerability enrichment data
5. Reports show accurate exposure: "CVE-2024-1234 affects **12 servers**"
6. Only CVEs detected in your environment are included in the report

Both collectors use the same API key and are enabled by default.

### OSINT Collector

The OSINT collector pulls articles from public RSS/Atom feeds you control.

#### Configuration: `config/osint_sources.yaml`

```yaml
sources:
  - name: "Krebs on Security"
    url: "https://krebsonsecurity.com/feed/"
    type: rss
    category: "Threat Research"
    enabled: true

lookback_days: 7
max_articles_per_source: 5
max_total_articles: 30
```

#### Managing Sources

**Add a source:**
```yaml
  - name: "My New Source"
    url: "https://example.com/feed/"
    type: rss
    category: "Custom Category"
    enabled: true
```

**Disable a source** without removing it:
```yaml
    enabled: false
```

**Default sources included:**
- CISA Alerts, US-CERT Current Activity
- Krebs on Security, The Hacker News, BleepingComputer, Dark Reading
- Microsoft Threat Intelligence, Google TAG, Mandiant
- Rapid7 Blog

No API key required. The collector automatically extracts CVE mentions from articles and feeds them into the AI analysis.

### VPN / Connectivity Check

When running locally, the script checks if Azure OpenAI is reachable before collecting data. If blocked by VNet:

```
⚠  Azure OpenAI is NOT reachable
Are you connected to the VPN?

[1] Stop - I'll connect to VPN first
[2] Continue without AI (use Rapid7/NVD data directly)
```

Option 2 generates the report using Rapid7 scan data cross-referenced with NVD, without AI analysis.

## Deployment to Azure

### 1. Create Azure Function App

```bash
az functionapp create \
  --name your-function-app \
  --resource-group your-rg \
  --storage-account your-storage \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4
```

### 2. Enable Managed Identity

```bash
az functionapp identity assign --name your-function-app --resource-group your-rg
```

### 3. Grant Key Vault Access

```bash
PRINCIPAL_ID=$(az functionapp identity show --name your-function-app --resource-group your-rg --query principalId -o tsv)

az keyvault set-policy \
  --name your-keyvault \
  --object-id $PRINCIPAL_ID \
  --secret-permissions get list
```

### 4. Configure App Settings

```bash
az functionapp config appsettings set \
  --name your-function-app \
  --resource-group your-rg \
  --settings "KEY_VAULT_URL=https://your-keyvault.vault.azure.net/"
```

### 5. Deploy

```bash
func azure functionapp publish your-function-app
```

## API Response

The function returns JSON with:

```json
{
  "status": "success",
  "message": "CTI report generated successfully",
  "report_url": "https://storage.blob.core.windows.net/reports/CTI_Weekly_Report_2024-01-22.docx?sas=...",
  "filename": "CTI_Weekly_Report_2024-01-22.docx",
  "statistics": {
    "total_cves": 46,
    "critical_count": 12,
    "high_count": 34,
    "apt_groups": 10
  },
  "collection_summary": {
    "NVD": {"success": true, "record_count": 46},
    "CrowdStrike": {"success": true, "record_count": 10}
  }
}
```

## License

Proprietary - Internal use only.
