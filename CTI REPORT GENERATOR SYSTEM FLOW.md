┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           CTI REPORT GENERATOR SYSTEM FLOW                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘

                         ┌─────────────────────────────┐
                         │   HTTP Request Trigger      │
                         │   (Azure Functions)         │
                         └─────────────┬───────────────┘
                                       │
                         ┌─────────────▼───────────────┐
                         │     function_app.py         │
                         │  ┌───────────┬───────────┐  │
                         │  │  Weekly   │ Quarterly │  │
                         │  │  Endpoint │ Endpoint  │  │
                         │  └─────┬─────┴─────┬─────┘  │
                         └────────┼───────────┼────────┘
                                  │           │
┌─────────────────────────────────┼───────────┼────────────────────────────────────────────┐
│ STEP 1: CREDENTIALS             │           │                                            │
│ ─────────────────               ▼           ▼                                            │
│                    ┌────────────────────────────────┐                                    │
│                    │   src/core/keyvault.py         │                                    │
│                    │   get_all_api_keys()           │                                    │
│                    │                                │                                    │
│                    │   Retrieves from Azure KV:     │                                    │
│                    │   • nvd-api-key                │                                    │
│                    │   • intel471-email/key         │                                    │
│                    │   • crowdstrike-id/secret      │                                    │
│                    │   • rapid7-api-key             │                                    │
│                    │   • openai-endpoint/key        │                                    │
│                    │   • storage-account-name/key   │                                    │
│                    └───────────────┬────────────────┘                                    │
└────────────────────────────────────┼─────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: DATA COLLECTION                                                                  │
│ ───────────────────────                                                                  │
│                    ┌────────────────────────────────┐                                    │
│                    │  src/collectors/registry.py    │                                    │
│                    │  collect_all(credentials,      │                                    │
│                    │              report_type)      │                                    │
│                    └───────────────┬────────────────┘                                    │
│                                    │                                                     │
│         ┌──────────────────────────┼──────────────────────────┐                          │
│         │                          │                          │                          │
│         │   PARALLEL COLLECTION    │    (asyncio.gather)      │                          │
│         │                          │                          │                          │
│         ▼                          ▼                          ▼                          │
│  ┌──────────────┐     ┌────────────────────┐     ┌────────────────────┐                  │
│  │ nvd_collector│     │ intel471_collector │     │crowdstrike_collector│                 │
│  │    .py       │     │       .py          │     │        .py          │                 │
│  │              │     │                    │     │                     │                 │
│  │ NVD API      │     │ Intel471 Titan API │     │ CrowdStrike Falcon  │                 │
│  │ CVE data     │     │ Threat reports     │     │ APT intelligence    │                 │
│  │ 7 days back  │     │ Breach alerts      │     │ Actors & TTPs       │                 │
│  └──────┬───────┘     └─────────┬──────────┘     └──────────┬──────────┘                 │
│         │                       │                           │                            │
│         │       ┌───────────────┴──────────────┐            │                            │
│         │       │                              │            │                            │
│         ▼       ▼                              ▼            ▼                            │
│  ┌──────────────────┐                  ┌────────────────────┐                            │
│  │ rapid7_collector │                  │ threatq_collector  │ (disabled)                 │
│  │       .py        │                  │       .py          │                            │
│  │                  │                  │                    │                            │
│  │ Rapid7 InsightVM │                  │ ThreatQ Platform   │                            │
│  │ Vuln scan data   │                  │ Threat indicators  │                            │
│  │ 30 days back     │                  │                    │                            │
│  └────────┬─────────┘                  └────────────────────┘                            │
│           │                                                                              │
│           └─────────────────────┬────────────────────────────────────────────────────────┤
│                                 │                                                        │
│                    ┌────────────▼────────────┐                                           │
│                    │   CollectorResult[]     │                                           │
│                    │   Data by source:       │                                           │
│                    │   • NVD: CVE records    │                                           │
│                    │   • Intel471: Reports   │                                           │
│                    │   • CrowdStrike: Actors │                                           │
│                    │   • Rapid7: Vulns       │                                           │
│                    └────────────┬────────────┘                                           │
└─────────────────────────────────┼────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: AI ANALYSIS (different paths for weekly vs quarterly)                            │
│ ───────────────────                                                                      │
│                    ┌────────────────────────────────┐                                    │
│                    │  src/agents/threat_analyst.py  │                                    │
│                    │  ThreatAnalystAgent            │                                    │
│                    └───────────────┬────────────────┘                                    │
│                                    │                                                     │
│              ┌─────────────────────┴─────────────────────┐                               │
│              │                                           │                               │
│     ┌────────▼────────┐                        ┌─────────▼────────┐                      │
│     │  WEEKLY REPORT  │                        │ QUARTERLY REPORT │                      │
│     │                 │                        │                  │                      │
│     │ analyze_threats()│                       │analyze_strategic()│                     │
│     │                 │                        │                  │                      │
│     │ Uses:           │                        │ Uses:            │                      │
│     │ DEFAULT_SYSTEM_ │                        │ STRATEGIC_SYSTEM_│                      │
│     │ PROMPT (line 23)│                        │ PROMPT (line 38) │                      │
│     │                 │                        │                  │                      │
│     │ Prompt built by:│                        │ Prompt built by: │                      │
│     │ _build_analysis_│                        │ _build_strategic_│                      │
│     │ prompt()        │                        │ prompt()         │                      │
│     │ (line 227)      │                        │ (line 489)       │                      │
│     │                 │                        │                  │                      │
│     │ Input:          │                        │ Input:           │                      │
│     │ • CVE data      │                        │ • Intel471 data  │                      │
│     │ • Intel471 data │                        │ • CrowdStrike    │                      │
│     │ • CrowdStrike   │                        │ • Breach data    │                      │
│     │ • ThreatQ data  │                        │                  │                      │
│     │ • Rapid7 data   │                        │ Focus:           │                      │
│     │                 │                        │ • Geopolitical   │                      │
│     │ Focus:          │                        │ • Industry breach│                      │
│     │ • Tactical CVEs │                        │ • Business risk  │                      │
│     │ • APT activity  │                        │ • Executive view │                      │
│     │ • IOCs          │                        │                  │                      │
│     └────────┬────────┘                        └─────────┬────────┘                      │
│              │                                           │                               │
│              │           ┌───────────────────┐           │                               │
│              └──────────►│  Azure OpenAI     │◄──────────┘                               │
│                          │  (GPT model)      │                                           │
│                          │                   │                                           │
│                          │  Returns JSON     │                                           │
│                          │  analysis result  │                                           │
│                          └─────────┬─────────┘                                           │
│                                    │                                                     │
│                    ┌───────────────▼───────────────┐                                     │
│                    │   _parse_response()           │                                     │
│                    │   Cleans markdown, parses JSON│                                     │
│                    └───────────────┬───────────────┘                                     │
└────────────────────────────────────┼─────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: DOCUMENT GENERATION                                                              │
│ ─────────────────────────                                                                │
│                    ┌────────────────────────────────┐                                    │
│                    │  src/reports/blob_storage.py   │                                    │
│                    │  create_and_upload_report()    │                                    │
│                    └───────────────┬────────────────┘                                    │
│                                    │                                                     │
│                    ┌───────────────▼───────────────┐                                     │
│                    │  src/reports/registry.py      │                                     │
│                    │  get_report_generator(type)   │                                     │
│                    └───────────────┬───────────────┘                                     │
│                                    │                                                     │
│              ┌─────────────────────┴─────────────────────┐                               │
│              │                                           │                               │
│     ┌────────▼────────┐                        ┌─────────▼────────┐                      │
│     │  weekly_report  │                        │ quarterly_report │                      │
│     │      .py        │                        │       .py        │                      │
│     │                 │                        │                  │                      │
│     │ WeeklyReport    │                        │ QuarterlyReport  │                      │
│     │ Generator       │                        │ Generator        │                      │
│     │                 │                        │                  │                      │
│     │ Sections:       │                        │ Sections:        │                      │
│     │ • Exec summary  │                        │ • Exec summary   │                      │
│     │ • CVE table     │                        │ • Risk cards     │                      │
│     │ • APT table     │                        │ • Breach metrics │                      │
│     │ • Indicators    │                        │ • Geopolitical   │                      │
│     │ • Recommendations│                       │ • Looking ahead  │                      │
│     │                 │                        │ • Recommendations│                      │
│     └────────┬────────┘                        └─────────┬────────┘                      │
│              │                                           │                               │
│              │         ┌───────────────────┐             │                               │
│              └────────►│ src/reports/base.py│◄───────────┘                               │
│                        │                   │                                             │
│                        │ BaseReportGenerator│                                            │
│                        │ • BrandColors     │                                             │
│                        │ • FontSizes       │                                             │
│                        │ • _set_cell_shading│                                            │
│                        │ • _add_banner_header│                                           │
│                        │ • _create_metric_card│                                          │
│                        └─────────┬─────────┘                                             │
│                                  │                                                       │
│                    ┌─────────────▼─────────────┐                                         │
│                    │   python-docx Document    │                                         │
│                    │   (Word .docx file)       │                                         │
│                    └─────────────┬─────────────┘                                         │
└──────────────────────────────────┼───────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: UPLOAD & RESPONSE                                                                │
│ ───────────────────────                                                                  │
│                    ┌────────────────────────────────┐                                    │
│                    │  src/reports/blob_storage.py   │                                    │
│                    │  upload_to_blob()              │                                    │
│                    │                                │                                    │
│                    │  • Uploads to Azure Blob       │                                    │
│                    │  • Generates SAS URL           │                                    │
│                    │  • 7-day expiry                │                                    │
│                    └───────────────┬────────────────┘                                    │
│                                    │                                                     │
│                    ┌───────────────▼───────────────┐                                     │
│                    │   HTTP Response (JSON)        │                                     │
│                    │   {                           │                                     │
│                    │     "status": "success",      │                                     │
│                    │     "report_url": "https://..│                                     │
│                    │     "filename": "CTI_Weekly..│                                     │
│                    │     "statistics": {...}       │                                     │
│                    │   }                           │                                     │
│                    └───────────────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘


##File Sequence Summary
#Weekly Report Flow

1. function_app.py:generate_weekly_report()
   │
2. ├─► src/core/keyvault.py:get_all_api_keys()
   │
3. ├─► src/collectors/registry.py:collect_all(report_type="weekly")
   │    ├─► nvd_collector.py        (7 days lookback)
   │    ├─► intel471_collector.py   (7 days lookback)
   │    ├─► crowdstrike_collector.py
   │    └─► rapid7_collector.py     (30 days lookback)
   │
4. ├─► src/agents/threat_analyst.py:analyze_threats()
   │    └─► Uses DEFAULT_SYSTEM_PROMPT + _build_analysis_prompt()
   │
5. └─► src/reports/blob_storage.py:create_and_upload_report("weekly")
        └─► src/reports/weekly_report.py:WeeklyReportGenerator.generate()

#Quarterly Report Flow

1. function_app.py:generate_quarterly_report()
   │
2. ├─► src/core/keyvault.py:get_all_api_keys()
   │
3. ├─► src/collectors/registry.py:collect_all(report_type="quarterly")
   │    ├─► intel471_collector.py   (90 days lookback + breach reports)
   │    └─► crowdstrike_collector.py
   │
4. ├─► src/agents/threat_analyst.py:analyze_strategic()
   │    └─► Uses STRATEGIC_SYSTEM_PROMPT + _build_strategic_prompt()
   │
5. └─► src/reports/blob_storage.py:create_and_upload_report("quarterly")
        └─► src/reports/quarterly_report.py:QuarterlyReportGenerator.generate()

