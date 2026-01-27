# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.0] - 2026-01-27

### Added
- **Modular report generation architecture**: Support for multiple report types (weekly, monthly, bulletin, etc.)
  - `reports/base.py` - Abstract base class with brand colors, font sizes, and common utilities
  - `reports/registry.py` - Report type registry for dynamic loading
  - `reports/blob_storage.py` - Shared Azure Blob Storage upload functionality
  - `reports/weekly_report.py` - Weekly report generator matching branded template
- `tests/test_reports.py` - Unit tests for report generators (27 tests)
- Brand-consistent styling matching CTI_Weekly_Report_Template_Example.docx:
  - Orange primary color (#E65100)
  - Metric cards for "at a glance" statistics
  - CVE vulnerability table with weeks-tracked highlighting
  - Sector threat activity table
  - Exploitation indicators section

### Changed
- `function_app.py` - Updated to use new modular report generation
- Report generation now uses `report_type` parameter to select generator

### Deprecated
- `report_generator.py` - Still functional but superseded by `reports/` package

## [1.1.0] - 2024-01-27

### Added
- **Modular collector architecture**: Broke out monolithic `api_collectors.py` into individual collector modules
  - `collectors/nvd_collector.py` - NVD CVE collector
  - `collectors/intel471_collector.py` - Intel471 threat reports and indicators
  - `collectors/crowdstrike_collector.py` - CrowdStrike APT intelligence
  - `collectors/threatq_collector.py` - ThreatQ indicators
  - `collectors/rapid7_collector.py` - Rapid7 vulnerability data
- `collectors/base.py` - Abstract base class for all collectors
- `collectors/registry.py` - Collector registry for dynamic loading
- `collectors/http_utils.py` - HTTP client with exponential backoff retry logic
- `config.py` - Centralized application configuration
- `models.py` - Dataclasses for structured data types (CVERecord, ThreatReport, APTActor, etc.)
- `tests/test_collectors.py` - Unit tests for collectors
- `requirements-dev.txt` - Development dependencies
- `pytest.ini` - Pytest configuration
- `local.settings.json.template` - Template for local development settings
- `README.md` - Comprehensive documentation
- `CHANGES.md` - This changelog
- `.env.example` - Environment variable template

### Changed
- **All secrets now stored in Azure Key Vault** including storage account credentials
- `keyvault_helper.py` - Added credential caching and parallel secret fetching
- `function_app.py` - Updated to use modular collector architecture
- `threat_analyst_agent.py` - Moved hardcoded settings to config, removed sensitive logging
- `report_generator.py` - Using Azure SDK properly with account URL instead of connection strings
- Updated type hints to use modern Python 3.10+ `|` syntax instead of `Optional`

### Removed
- `api_collectors.py` - Replaced by modular `collectors/` package
- `test_intel471.py` - Old manual test script (replaced by pytest tests)

### Fixed
- CrowdStrike collector now handles dict-based industry/motivation fields correctly

## [1.0.0] - 2024-01-20

### Added
- Initial release
- Azure Functions HTTP trigger for report generation
- Integration with NVD, Intel471, CrowdStrike, ThreatQ, and Rapid7 APIs
- AI-powered threat analysis using Azure OpenAI and Semantic Kernel
- Word document report generation with python-docx
- Azure Blob Storage upload with SAS URL generation
- Azure Key Vault integration for secrets management
