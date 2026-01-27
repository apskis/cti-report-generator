#!/usr/bin/env python3
"""
Local test script for CTI Report Generation.

Allows testing both weekly and quarterly reports without Azure Functions runtime.
Generates reports locally (saves to disk) or uploads to Azure Blob Storage.

Usage:
    # Generate weekly report with MOCK data (for UI/formatting testing)
    python test_local.py weekly --local --mock

    # Generate quarterly report with MOCK data
    python test_local.py quarterly --local --mock

    # Generate weekly report with REAL API data, save locally
    python test_local.py weekly --local --real

    # Generate quarterly report with REAL API data, save locally
    python test_local.py quarterly --local --real

    # Generate with REAL data and upload to Azure Blob Storage
    python test_local.py weekly --azure

    # Specify output directory for local generation
    python test_local.py weekly --local --mock --output ./reports
"""
import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_mock_weekly_analysis() -> dict:
    """Generate mock data for weekly report testing."""
    return {
        "executive_summary": """This week's threat intelligence collection identified 12 new vulnerabilities \
affecting our environment, with 4 CVEs confirmed to be actively exploited in the wild. \
Three APT groups with known interest in the life sciences sector were observed conducting \
campaigns this week.

No direct threats to the organization were identified; however, the CVEs and threat actors \
observed are consistent with those historically targeting genomics and biotech companies. \
Immediate attention is recommended for CVE-2026-22907 (Grafana) which has public exploit code.""",
        "statistics": {
            "total_cves": 12,
            "critical_count": 4,
            "high_count": 5,
            "exploited_count": 4,
            "apt_groups": 3,
            "new_this_week": 8,
            "persistent_count": 4,
            "resolved_count": 3,
            "total_exposed": 12,
            "p1_count": 2,
            "p2_count": 4,
            "p3_count": 6
        },
        "cve_analysis": [
            {
                "cve_id": "CVE-2026-22907",
                "affected_product": "Grafana",
                "exposure": "LDAP injection via auth",
                "exploited_by": "APT41",
                "risk": "CRITICAL",
                "weeks_detected": 1,
                "exploitation_indicator": "Malformed LDAP queries in auth logs; unexpected LDAP binds"
            },
            {
                "cve_id": "CVE-2026-22908",
                "affected_product": "GLPI",
                "exposure": "SQL injection in search",
                "exploited_by": "None known",
                "risk": "HIGH",
                "weeks_detected": 1,
                "exploitation_indicator": "SQL errors in application logs; UNION SELECT patterns"
            },
            {
                "cve_id": "CVE-2026-0713",
                "affected_product": "Windows Print Spooler",
                "exposure": "Privilege escalation",
                "exploited_by": "Ransomware groups",
                "risk": "CRITICAL",
                "weeks_detected": 2,
                "exploitation_indicator": "Spoolsv.exe spawning cmd/powershell"
            },
            {
                "cve_id": "CVE-2021-47757",
                "affected_product": "Apache Log4j",
                "exposure": "Remote code execution",
                "exploited_by": "Multiple actors",
                "risk": "CRITICAL",
                "weeks_detected": 6,
                "exploitation_indicator": "JNDI lookup patterns in logs"
            },
            {
                "cve_id": "CVE-2025-98213",
                "affected_product": "VMware vCenter",
                "exposure": "Authentication bypass",
                "exploited_by": "APT29",
                "risk": "HIGH",
                "weeks_detected": 4,
                "exploitation_indicator": "Unauthorized API access patterns"
            },
        ],
        "apt_activity": [
            {
                "actor": "APT41",
                "country": "China",
                "motivation": "Espionage / Financial",
                "activity": "Targeting pharmaceutical supply chains via compromised software updates",
                "ttps": ["T1195.002", "T1566.001", "T1059.001"],
                "what_to_monitor": "Software update anomalies; unexpected binary modifications"
            },
            {
                "actor": "Lazarus Group",
                "country": "North Korea",
                "motivation": "Financial / Espionage",
                "activity": "LinkedIn-based social engineering targeting biotech researchers",
                "ttps": ["T1566.003", "T1204.002", "T1547.001"],
                "what_to_monitor": "Suspicious LinkedIn outreach to research staff"
            },
            {
                "actor": "LockBit Affiliates",
                "country": "Russia",
                "motivation": "Financial",
                "activity": "Ransomware campaigns against healthcare and manufacturing",
                "ttps": ["T1486", "T1490", "T1027"],
                "what_to_monitor": "Unusual file encryption activity; VSS deletion"
            },
        ],
        "exploitation_indicators": [
            "CVE-2026-22907 (Grafana): Malformed LDAP queries in auth logs; unexpected LDAP binds from Grafana to AD",
            "CVE-2026-22908 (GLPI): SQL errors in application logs; UNION SELECT or stacked queries from web frontend",
            "CVE-2026-0713 (Print Spooler): Spoolsv.exe spawning cmd/powershell; DLL writes to spool\\drivers directory",
        ],
        "recommendations": [
            "Review Rapid7 scan results for the 12 exposed vulnerabilities; validate asset ownership and remediation timelines",
            "Persistent findings: CVE-2021-47757 (6 wks), CVE-2025-98213 (4 wks) require escalation to system owners",
            "Brief development teams on supply chain compromise campaigns targeting software updates",
            "Review LinkedIn connection requests for research and executive staff given social engineering activity",
            "Verify CrowdStrike has latest behavioral IOAs enabled for ransomware detection",
            "Confirm Splunk is receiving logs from Grafana, GLPI, and affected systems",
        ],
    }


def get_mock_quarterly_analysis() -> dict:
    """Generate mock data for quarterly report testing."""
    return {
        "executive_summary": """The threat landscape for the genomics, life sciences, and precision manufacturing \
sectors remained elevated throughout Q1 2026, with 47 publicly disclosed breaches affecting peer organizations \
in the industry. Estimated aggregate impact exceeded $127M in direct costs and regulatory penalties.

No direct threats to the organization were identified this quarter; however, the threat actors, techniques, \
and vulnerabilities observed are consistent with those historically used against genomics companies. \
Nation-state espionage activity, particularly from China-linked actors, showed increased focus on \
biomanufacturing IP and clinical trial data.""",
        "risk_assessment": {
            "nation_state": "HIGH",
            "nation_state_trend": "↑",
            "ransomware": "HIGH",
            "ransomware_trend": "↑",
            "supply_chain": "MEDIUM",
            "supply_chain_trend": "Unchanged",
            "insider": "LOW",
            "insider_trend": "Unchanged"
        },
        "breach_landscape": {
            "total_incidents": 47,
            "prev_total_incidents": 36,
            "total_impact_millions": 127,
            "prev_total_impact": 89,
            "ransomware_count": 18,
            "prev_ransomware": 12,
            "records_exposed_millions": 4.2,
            "prev_records": 2.8
        },
        "incidents_by_type": [
            {"type": "Ransomware", "current_count": 18, "prev_count": 12, "notable_example": "MedTech Corp - 23 days operational disruption"},
            {"type": "Data Breach", "current_count": 14, "prev_count": 11, "notable_example": "GenomicsLab - 2.1M patient records exposed"},
            {"type": "Supply Chain", "current_count": 8, "prev_count": 7, "notable_example": "LabEquip vendor compromise - 12 customers affected"},
            {"type": "Business Email Compromise", "current_count": 5, "prev_count": 4, "notable_example": "BioPharm Inc - $3.2M wire fraud"},
            {"type": "Insider Threat", "current_count": 2, "prev_count": 2, "notable_example": "ResearchCo - departing employee data theft"},
        ],
        "common_factors": "Exploitation of unpatched internet-facing systems (34%), compromised credentials without MFA (28%), third-party vendor compromise (19%), and social engineering (19%).",
        "geopolitical_threats": {
            "china": {
                "strategic_context": "China's 14th Five-Year Plan designates biotechnology as a strategic priority, with specific emphasis on genomics, precision medicine, and biomanufacturing. The Ministry of State Security (MSS) and affiliated actors continue systematic collection against Western life sciences organizations.",
                "activity": "APT41 and associated clusters conducted multiple intrusions against pharmaceutical and genomics companies via compromised software update mechanisms. GENESIS PANDA conducted spearphishing campaigns targeting clinical research coordinators at 6 biotech firms.",
                "implications": "Theft of proprietary research, sequencing technology designs, or manufacturing processes could erode competitive advantage and represent significant R&D investment loss. Compromised clinical trial data raises regulatory and patient safety concerns."
            },
            "russia": {
                "strategic_context": "Russian state cyber interests in life sciences remain opportunistic, focusing on vaccine research and healthcare disruption capabilities. However, Russian-speaking criminal groups operating with tacit state approval pose the most significant threat through ransomware operations.",
                "activity": "Ransomware incidents affecting healthcare, pharmaceutical, and manufacturing organizations increased 31% quarter-over-quarter. LockBit, ALPHV/BlackCat, and Cl0p affiliates accounted for the majority of incidents.",
                "implications": "Ransomware incidents in life sciences and manufacturing average $4.2M in recovery costs and 23 days of operational disruption. Manufacturing environments face extended recovery timelines due to OT system complexity."
            },
            "north_korea": {
                "strategic_context": "North Korean cyber operations serve dual purposes: revenue generation to circumvent sanctions and acquisition of medical/pharmaceutical research for domestic programs. The regime has demonstrated sustained interest in COVID-19 vaccine research and oncology treatments.",
                "activity": "Lazarus Group, Kimsuky, and VELVET CHOLLIMA conducted social engineering campaigns via LinkedIn and professional networking platforms throughout the quarter. Campaigns used fake recruiter personas targeting research scientists and engineers.",
                "implications": "Credential compromise of research or executive personnel could provide access to sensitive environments, collaboration platforms, and IP repositories. Executive targeting also enables BEC fraud attempts."
            }
        },
        "looking_ahead": {
            "threat_outlook": "We anticipate continued pressure from state-sponsored espionage campaigns as genomics research and precision manufacturing technology becomes increasingly valuable to national biotechnology strategies. Ransomware threat remains elevated with likely targeting of manufacturing operations.",
            "planned_initiatives": "Integration of Microsoft Sentinel for unified security event correlation. Development of automated threat intelligence sharing with industry partners via H-ISAC. Expansion of executive protection monitoring.",
            "watch_items": "Potential escalation in state-sponsored activity around major genomics conferences, product launches, and partnership announcements. Continued evolution of ransomware tactics, particularly double extortion and OT targeting."
        },
        "recommendations": [
            ("Executive Awareness", "Consider targeted security awareness for executives and key research personnel given sustained social engineering campaigns via professional networks. CTI team can provide customized briefings."),
            ("Vendor Risk Review", "Evaluate security posture of critical software and laboratory equipment vendors given Q1 supply chain compromise activity. Prioritize vendors with privileged access to research and manufacturing systems."),
            ("Manufacturing Environment Security", "Review network segmentation between IT and OT/manufacturing systems. Ensure incident response plans address manufacturing disruption scenarios and production recovery."),
            ("Incident Response Readiness", "Confirm ransomware response plans address SEC disclosure timelines (4-day materiality determination), FDA notification requirements, and manufacturing continuity scenarios."),
            ("Board Reporting", "Q1 peer incidents and regulatory enforcement may prompt board inquiries regarding security posture. CTI team available to support preparation of sector threat context and benchmarking."),
        ]
    }


async def generate_report_local(
    report_type: str,
    use_mock: bool = False,
    use_real: bool = False,
    output_dir: str = ".",
    use_azure: bool = False
) -> str:
    """
    Generate a report locally.

    Args:
        report_type: 'weekly' or 'quarterly'
        use_mock: Use mock data instead of collecting from APIs
        use_real: Use real API data (requires Key Vault access)
        output_dir: Directory to save the report
        use_azure: Upload to Azure Blob Storage (implies use_real)

    Returns:
        Path to generated report or Azure URL
    """
    from reports import get_report_generator

    logger.info(f"Generating {report_type} report...")

    # Get the appropriate report generator
    generator = get_report_generator(report_type)
    if generator is None:
        raise ValueError(f"Unknown report type: {report_type}")

    # Determine data source
    if use_mock:
        logger.info("Using MOCK data for report generation (UI/formatting test)")
        if report_type == "weekly":
            analysis = get_mock_weekly_analysis()
        else:
            analysis = get_mock_quarterly_analysis()
    elif use_real or use_azure:
        # Collect real data from APIs
        logger.info("Collecting REAL data from threat intelligence APIs...")
        analysis = await collect_and_analyze(report_type)
    else:
        # Default to mock if nothing specified
        logger.info("Using MOCK data (default - use --real for API data)")
        if report_type == "weekly":
            analysis = get_mock_weekly_analysis()
        else:
            analysis = get_mock_quarterly_analysis()

    # Generate the document
    logger.info("Generating document...")
    doc = generator.generate(analysis)

    # Save or upload
    if use_azure:
        # Upload to Azure
        logger.info("Uploading to Azure Blob Storage...")
        from keyvault_helper import get_all_api_keys
        from reports.blob_storage import upload_to_blob
        from config import azure_config

        credentials = get_all_api_keys(azure_config.get_key_vault_url())
        url = upload_to_blob(
            generator,
            credentials['storage_account_name'],
            credentials['storage_account_key']
        )
        logger.info(f"Report uploaded: {url}")
        return url
    else:
        # Save locally
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename = generator.get_filename()
        filepath = output_path / filename

        doc.save(str(filepath))
        logger.info(f"Report saved to: {filepath}")
        return str(filepath)


async def collect_and_analyze(report_type: str) -> dict:
    """Collect data and run analysis (requires Azure credentials)."""
    from keyvault_helper import get_all_api_keys
    from collectors import collect_all, get_data_by_source
    from threat_analyst_agent import ThreatAnalystAgent
    from config import azure_config, analysis_config

    # Get credentials
    vault_url = azure_config.get_key_vault_url()
    logger.info(f"Retrieving credentials from Key Vault: {vault_url}")
    credentials = get_all_api_keys(vault_url)

    # Collect data
    logger.info(f"Collecting threat intelligence data for {report_type} report...")
    collector_results = await collect_all(credentials, report_type=report_type)
    data_by_source = get_data_by_source(collector_results)

    # Log what we collected
    for source, data in data_by_source.items():
        logger.info(f"  {source}: {len(data)} records")

    # Initialize agent
    agent = ThreatAnalystAgent(
        credentials['openai_endpoint'],
        credentials['openai_key'],
        deployment_name=analysis_config.deployment_name
    )

    if report_type == "weekly":
        # Tactical analysis
        logger.info("Running tactical AI analysis for weekly report...")
        return await agent.analyze_threats(
            data_by_source.get("NVD", []),
            data_by_source.get("Intel471", []),
            data_by_source.get("CrowdStrike", []),
            data_by_source.get("ThreatQ", []),
            data_by_source.get("Rapid7", [])
        )
    else:
        # Strategic analysis
        logger.info("Running strategic AI analysis for quarterly report...")
        
        # Extract breach reports from Intel471 data
        intel471_data = data_by_source.get("Intel471", [])
        breach_data = [
            item for item in intel471_data 
            if item.get("threat_type", "").upper() == "BREACH ALERT"
        ]
        
        # Remove breach reports from intel471_data (they'll be in breach_data)
        intel471_data = [
            item for item in intel471_data 
            if item.get("threat_type", "").upper() != "BREACH ALERT"
        ]
        
        return await agent.analyze_strategic(
            intel471_data=intel471_data,
            crowdstrike_data=data_by_source.get("CrowdStrike", []),
            breach_data=breach_data if breach_data else None
        )


def main():
    parser = argparse.ArgumentParser(
        description="Local test script for CTI Report Generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Data Source Options:
  --mock    Use hardcoded example data (no Azure/API access needed)
  --real    Use real data from APIs (requires Key Vault access)

Examples:
  # MOCK DATA - Test report formatting without any API calls
  python test_local.py weekly --local --mock
  python test_local.py quarterly --local --mock

  # REAL DATA - Pull from actual threat intel APIs, save locally
  python test_local.py weekly --local --real
  python test_local.py quarterly --local --real

  # REAL DATA + AZURE UPLOAD - Full production pipeline
  python test_local.py weekly --azure
  python test_local.py quarterly --azure

  # Custom output directory
  python test_local.py weekly --local --mock --output ./test_reports
        """
    )

    parser.add_argument(
        "report_type",
        choices=["weekly", "quarterly"],
        help="Type of report to generate"
    )

    parser.add_argument(
        "--local",
        action="store_true",
        help="Save report locally (to disk)"
    )

    parser.add_argument(
        "--azure",
        action="store_true",
        help="Upload report to Azure Blob Storage (uses real data)"
    )

    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use MOCK/example data (no API calls, for UI testing)"
    )

    parser.add_argument(
        "--real",
        action="store_true",
        help="Use REAL data from APIs (requires Key Vault access)"
    )

    parser.add_argument(
        "--output", "-o",
        default=".",
        help="Output directory for local generation (default: current directory)"
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.local and not args.azure:
        parser.error("Must specify either --local or --azure")

    if args.local and args.azure:
        parser.error("Cannot use both --local and --azure")

    if args.mock and args.real:
        parser.error("Cannot use both --mock and --real")

    # Default to mock for --local if neither specified
    use_mock = args.mock or (args.local and not args.real)
    use_real = args.real or args.azure

    # Determine data source for display
    if use_mock:
        data_source = "MOCK (example data)"
    else:
        data_source = "REAL (API feeds + AI analysis)"

    # Run the generation
    try:
        print(f"\n{'='*60}")
        print(f"CTI Report Generator")
        print(f"{'='*60}")
        print(f"Report Type: {args.report_type.upper()}")
        print(f"Data Source: {data_source}")
        print(f"Output: {'Azure Blob Storage' if args.azure else f'Local ({args.output})'}")
        print(f"{'='*60}\n")

        result = asyncio.run(generate_report_local(
            report_type=args.report_type,
            use_mock=use_mock,
            use_real=use_real,
            output_dir=args.output,
            use_azure=args.azure
        ))

        print(f"\n{'='*60}")
        print(f"SUCCESS!")
        print(f"{'='*60}")
        print(f"Report Type: {args.report_type.upper()}")
        print(f"Data Source: {data_source}")
        if args.azure:
            print(f"URL: {result}")
        else:
            print(f"File: {result}")
        print(f"{'='*60}\n")

    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
