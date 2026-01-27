# CTI Report Generator

An Azure Functions-based Cyber Threat Intelligence (CTI) reporting system that automatically collects threat data from multiple sources, analyzes it with AI, and generates weekly reports.

## Features

- **Multi-source threat intelligence collection** from:
  - NVD (NIST National Vulnerability Database)
  - Intel471 Titan API
  - CrowdStrike Falcon Intelligence
  - ThreatQ
  - Rapid7 InsightVM

- **AI-powered analysis** using Azure OpenAI and Semantic Kernel
- **Automated Word document generation** with executive summaries and recommendations
- **Azure Blob Storage** integration for report hosting with SAS URLs
- **Modular collector architecture** - easily enable/disable sources

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
├── collectors/                  # Modular API collectors
│   ├── __init__.py
│   ├── base.py                 # Base collector class
│   ├── http_utils.py           # HTTP client with retry logic
│   ├── nvd_collector.py
│   ├── intel471_collector.py
│   ├── crowdstrike_collector.py
│   ├── threatq_collector.py
│   ├── rapid7_collector.py
│   └── registry.py             # Collector registry
├── tests/                       # Unit tests
├── config.py                    # Application configuration
├── models.py                    # Data type definitions
├── function_app.py              # Azure Function entry point
├── keyvault_helper.py           # Key Vault access
├── threat_analyst_agent.py      # AI analysis engine
├── report_generator.py          # Word document generation
├── requirements.txt
├── requirements-dev.txt
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

Edit `local.settings.json` and set your Key Vault URL:
```json
{
    "Values": {
        "KEY_VAULT_URL": "https://your-keyvault-name.vault.azure.net/"
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
KEYVAULT_NAME="your-keyvault-name"

az keyvault secret set --vault-name $KEYVAULT_NAME --name "nvd-api-key" --value "your-value"
az keyvault secret set --vault-name $KEYVAULT_NAME --name "intel471-email" --value "your-value"
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

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KEY_VAULT_URL` | Azure Key Vault URL | `https://kv-cti-reporting.vault.azure.net/` |
| `ENABLED_COLLECTORS` | Comma-separated list of enabled collectors | All enabled |

### Application Settings (config.py)

- **Lookback periods**: How many days back to collect data
- **Result limits**: Maximum records per source
- **Retry settings**: HTTP retry configuration
- **Analysis settings**: AI model deployment name, token limits

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
