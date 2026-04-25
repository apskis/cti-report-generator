# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **Collectors YAML Configuration**: New `config/collectors.yaml` for managing enabled collectors
  - Single source of truth for which API collectors are active
  - Enable/disable any collector by setting `enabled: true/false`
  - No hardcoded fallback; missing config file raises a clear error
  - Environment variable `ENABLED_COLLECTORS` still works as override
- **OSINT Collector**: New collector (`osint`) for curated open-source intelligence
  - User-controlled RSS/Atom feed sources defined in `config/osint_sources.yaml`
  - Add, remove, or disable sources without code changes
  - Categorized sources (Government Advisory, Threat Research, Vendor Research, etc.)
  - Automatic CVE mention extraction from article titles and summaries
  - Configurable lookback window, per-source article limits, and total caps
  - 10 vetted sources enabled by default (CISA, Krebs, Hacker News, BleepingComputer, etc.)
  - No API key required; uses public RSS feeds
  - OSINT articles fed into AI prompt for contextual analysis
- **VPN/Connectivity Check**: Pre-flight check for Azure OpenAI reachability
  - Detects VNet 403 errors before data collection starts
  - Interactive prompt: stop to connect VPN, or continue with backup analysis
  - Prevents wasted time collecting data when AI is unreachable
- **AI Gap-Filling**: Automatic patching of incomplete AI analysis
  - Fills missing exposure counts from Rapid7 scan data
  - Fills missing product names from NVD enrichment data
  - Fills missing exploitation attribution from CISA KEV
  - Filters AI output to only include CVEs detected in Rapid7 scans
  - Strategic reports: fills breach counts, risk assessments, geopolitical data from backup
- **Sources Section**: New report section listing all public intelligence sources
  - Added to both weekly and quarterly reports
  - Lists each source with URL or description
  - Removed redundant one-liner from report footer
- **Local Report Saving**: Reports always saved locally even when uploading to Azure
  - `--azure` mode now saves to disk AND uploads (previously upload-only)
  - Removed restriction preventing `--local` and `--azure` together

### Changed
- **Collector Configuration**: Moved enabled collectors from hardcoded list in `config.py` to `config/collectors.yaml`
  - Removed `DEFAULT_ENABLED_COLLECTORS` constant entirely
  - `get_enabled_collectors()` now reads YAML; raises `FileNotFoundError` if missing
- **Report Date Ranges**: Now show actual data lookback period instead of calendar week/quarter
  - Weekly: "7-Day Lookback | April 18 to April 25, 2026" (not "Week 17 | April 21 to 27")
  - Quarterly: "90-Day Lookback | January 25 to April 25, 2026" (not "Q2 April to June")
  - Dates pulled from collector config, always reflect actual data window
  - Run reports any day without seeing future dates
- **CVE Filtering**: Reports now only include CVEs detected in Rapid7 scans
  - Removed N/A exposure entries; every CVE in report has a system count
  - AI instructed to ignore CVEs not found in environment
  - Default/fallback analysis also filters to Rapid7-detected CVEs only
- **Exposure Column**: Fixed recognition of "system/systems" asset type
  - Weekly report formatter now accepts system, workstation, cloud server, cloud instance
- **Default Analysis (AI fallback)**: Complete rewrite for when AI is unavailable
  - Cross-references Rapid7 scan data with NVD for product names and severity
  - Sorts CVEs by priority then exposure count
  - Includes proper executive summary explaining data source
  - Passes Rapid7 scan data to fallback in both weekly and quarterly paths
- **Production Azure Function**: Now passes Rapid7 scan data and OSINT data to analysis

### Fixed
- Quarterly report footer crash from orphaned `sources` variable reference
- Exposure cell formatter not recognizing "system/systems" strings

## [1.3.0] - 2026-04-22

### Added
- **Multi-source intelligence fusion**: AI now automatically correlates data across all threat intelligence sources
  - CVE exposure correlation: Matches CVEs from NVD with asset counts from Rapid7 InsightVM
  - Exploitation intelligence: Correlates Intel471 breach reports with CVE exploitation status
  - Threat actor fusion: Combines CrowdStrike actor profiles with Intel471 underground activity
  - Detection correlation: Links CrowdStrike detections with CVE exploitation patterns
- **CrowdStrike Detections integration**: Added collection of real detections from your environment
  - Fetches detections from `/detects/queries/detects/v1` and `/detects/entities/summaries/GET/v1`
  - Filters for Medium severity and higher
  - Excludes false positives automatically
  - Provides real-world threat context in reports
- **Intel471 underground intelligence correlation**:
  - CVE mention detection in Intel471 reports using regex pattern matching
  - Breach intelligence extraction for industry context
  - Threat actor activity tracking from underground forums
  - Cross-reference with CrowdStrike for complete actor profiles
- **Enhanced AI correlation prompts**:
  - Explicit CVE-to-exposure mapping instructions with device counts
  - Priority guidelines based on environmental presence and exploitation status
  - Intel471 breach context for peer organization compromise intelligence
  - Multi-source validation for high-confidence threat identification
- **Colorized console output**: Clean, readable status updates with color-coding
  - Added `colorama` for cross-platform color support
  - Status icons: ✓ (success), ✗ (error), ⚠ (warning), → (progress), ℹ (info)
  - Color-coded messages: green (success), red (error), yellow (warning), cyan (info), blue (progress)
  - Section headers with visual separators
  - Cleaner output focused on what's happening, not technical logging details

### Changed
- **Vulnerability table "Risk" column renamed to "Priority"**: Better reflects P1/P2/P3 prioritization system
  - Priority field now primary in CVE analysis (falls back to severity for mapping)
  - P1: Address immediately (24-48 hours) - Critical + exploited + in environment
  - P2: Patch within 7-14 days - High severity with exploitation OR in environment
  - P3: Schedule within 30 days - Requires remediation but lower urgency
  - Color coding: P1 (red tint), P2 (yellow tint), P3 (green tint)
  - **Added priority urgency guide under vulnerability table** for clear action timelines
- **P3 redefined as action-required**: Changed from "monitor only" to "scheduled remediation required"
  - All vulnerabilities in report require action, just different timelines
  - Emphasizes proactive security posture
- **Enhanced exposure field handling**: Made exposure field required in AI output
  - Explicit instructions to AI on exposure field format
  - Debug logging for exposure data extraction
  - Better fallback handling when exposure not provided
- **CrowdStrike Falcon Spotlight**: Changed 403 error from WARNING to INFO with helpful message
  - Explains Spotlight requires separate license
  - Notes Rapid7 provides vulnerability exposure as alternative
- **ThreatQ collector**: Added debug logging to troubleshoot OAuth credential issues
  - Logs whether URL, client_id, and client_secret are present (without exposing values)
  - Improved error messages for missing credentials
- **AI analysis prompt**: Significantly enhanced with correlation context
  - Rapid7 CVE exposure map provided to AI with asset counts
  - CrowdStrike Spotlight CVE map (when available) merged with Rapid7
  - Intel471 CVE mentions, breach summaries, and actor activity extracted
  - Priority guidelines updated to consider environmental exposure
  - Exposure field added to CVE analysis JSON schema
  - Intel471 activity field added to APT actor JSON schema
- **Console output**: Completely redesigned for clarity and readability
  - Reduced logging verbosity: WARNING level for most modules
  - Clean status updates instead of technical log messages
  - Emoji icons for visual status indicators
  - Progress tracking with clear section headers
  - Only show what matters: data collection counts, enrichment status, analysis progress

### Fixed
- **AI JSON parsing**: Added control character cleaning for malformed JSON responses
  - Strips control characters (0x00-0x1F, 0x7F) before parsing
  - Retries parsing after cleaning if initial parse fails
  - Prevents report generation failures due to AI formatting issues
- **ThreatQ OAuth authentication**: Enhanced debugging to identify credential format issues
  - Logs OAuth request body structure for troubleshooting
  - Credentials confirmed present but not accepted by ThreatQ API (needs investigation)
- **CrowdStrike Detections 403**: Changed from WARNING to INFO with helpful permission hint
  - Notes which permission is needed: "Detections - Read"

### Documentation
- Created comprehensive intelligence fusion documentation:
  - `CROWDSTRIKE_USAGE.md` - CrowdStrike data sources and permissions
  - `INTEL471_FUSION.md` - Intel471 integration and correlation examples
  - `INTELLIGENCE_FUSION.md` - Complete fusion architecture and data flow
  - `FUSION_SUMMARY.md` - Quick reference for all source correlation
  - `THREATQ_STATUS.md` - ThreatQ status and configuration guide

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
