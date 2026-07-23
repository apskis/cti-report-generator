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
from pathlib import Path

# Allow running this script directly (adds the repo root to sys.path for src/gates imports)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load a local .env file (if present) so vars like AZURE_OPENAI_* persist across
# terminal sessions without exporting them each time. This MUST run before any
# src.core.config import, which snapshots env vars into its config singletons.
# Existing (already-exported) env vars are NOT overridden. .env is gitignored.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Add colorama for colored console output
try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        GREEN = CYAN = YELLOW = RED = MAGENTA = BLUE = WHITE = ""

    class Style:
        BRIGHT = RESET_ALL = ""

    COLORS_ENABLED = False

# Configure logging - will be set based on --debug flag
logger = logging.getLogger(__name__)


def configure_logging(debug_mode: bool = False, log_file: str = "debug.log"):
    """Configure logging based on debug mode.

    In debug mode, verbose logs are written to both the console and ``log_file``
    (overwritten each run) so you can watch the console live and keep the full
    transcript on disk. Pass ``log_file=None`` to disable the file.
    """
    if debug_mode:
        # Debug mode: show detailed logs
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(name)s - %(message)s", force=True)
        logging.getLogger("src.collectors").setLevel(logging.DEBUG)
        logging.getLogger("src.enrichment").setLevel(logging.DEBUG)
        logging.getLogger("src.agents").setLevel(logging.DEBUG)
        logging.getLogger("src.reports").setLevel(logging.DEBUG)
        logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
        logging.getLogger("azure.identity").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("semantic_kernel").setLevel(logging.INFO)
        logging.getLogger("azure").setLevel(logging.WARNING)

        # Also tee the full DEBUG stream to a file (overwrite each run) so the
        # console output is preserved on disk without needing a shell pipe.
        if log_file:
            file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s"))
            logging.getLogger().addHandler(file_handler)
            logger.info(f"Debug logging to file: {os.path.abspath(log_file)}")
    else:
        # Clean mode: only show clean status messages and errors
        logging.basicConfig(level=logging.ERROR, format="%(message)s", force=True)
        logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.ERROR)
        logging.getLogger("azure.identity").setLevel(logging.ERROR)
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("semantic_kernel").setLevel(logging.ERROR)
        logging.getLogger("azure").setLevel(logging.ERROR)
        logging.getLogger("src.collectors").setLevel(logging.ERROR)
        logging.getLogger("src.enrichment").setLevel(logging.ERROR)
        logging.getLogger("src.agents").setLevel(logging.ERROR)
        logging.getLogger("src.reports").setLevel(logging.ERROR)


def print_status(message: str, status: str = "info"):
    """Print a status message with color."""
    icons = {
        "info": "i",
        "success": "✓",
        "error": "x",
        "warning": "!",
        "progress": "→",
    }
    colors = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW,
        "progress": Fore.BLUE,
    }
    icon = icons.get(status, "•")
    color = colors.get(status, "")
    try:
        print(f"{color}{icon} {message}{Style.RESET_ALL}")
    except UnicodeEncodeError:
        # Fallback for terminals that don't support Unicode
        fallback_icons = {"info": "[i]", "success": "[✓]", "error": "[x]", "warning": "[!]", "progress": "[>]"}
        icon_fallback = fallback_icons.get(status, "[*]")
        print(f"{color}{icon_fallback} {message}{Style.RESET_ALL}".encode("ascii", "ignore").decode("ascii"))


def print_header(title: str):
    """Print a section header."""
    try:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 60}")
        print(f"{title}")
        print(f"{'=' * 60}{Style.RESET_ALL}")
    except UnicodeEncodeError:
        # Fallback for terminals that don't support Unicode
        safe_title = title.encode("ascii", "ignore").decode("ascii")
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 60}")
        print(f"{safe_title}")
        print(f"{'=' * 60}{Style.RESET_ALL}")


def print_section(title: str):
    """Print a subsection."""
    try:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    except UnicodeEncodeError:
        # Fallback for terminals that don't support Unicode
        safe_title = title.encode("ascii", "ignore").decode("ascii")
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{safe_title}{Style.RESET_ALL}")


def _gate_framework_enabled() -> bool:
    """Check if the gate framework feature flag is enabled."""
    from src.core.config import get_feature_config

    return get_feature_config().gate_framework_enabled


def _print_gate_summary(session: dict, gate_info: dict, report_type: str) -> None:
    """Print a summary of gate framework execution.

    Args:
        session: Orchestrator session dict mapping gate_id -> GateResult
        gate_info: Info dict returned by run_gate_framework_over_collected_data
        report_type: Report type (weekly/quarterly)
    """
    print()
    try:
        print(f"{Fore.CYAN}{Style.BRIGHT}── Gate Framework Summary {'─' * 30}{Style.RESET_ALL}")
    except UnicodeEncodeError:
        print(f"{Fore.CYAN}{Style.BRIGHT}-- Gate Framework Summary {'-' * 30}{Style.RESET_ALL}")

    # Gate names for display
    gate_names = {
        "1": "Tier 1 Source Inventory",
        "1A": "Statistics Validation",
        "1B": "OSINT Article Triage",
        "1E": "AI Output Quality",
        "1F": "Source Audit",
        "2": "IOC Extraction",
        "3": "Actor Linkage",
        "4": "Structured Assembly",
        "5": "Report Draft",
        "1C": "Technology Coherence",
        "1D": "Source Attribution",
        "6": "Adversarial Review",
    }

    # Gate sequences per report type
    gate_sequences = {
        "weekly": ["1", "1A", "1B", "2", "3", "4", "5", "6"],
        "quarterly": ["1", "1A", "1B", "2", "3", "4", "5", "1F", "1E", "1C", "1D", "6"],
    }
    sequence = gate_sequences.get(report_type.lower(), gate_sequences["weekly"])

    for gate_id in sequence:
        if gate_id in session:
            result = session[gate_id]
            status_display = result.status

            # Color-code the status
            if status_display in {"COMPLETE", "PASS"}:
                color = Fore.GREEN
            elif status_display == "BLOCK":
                color = Fore.RED
            elif status_display in {"HALT", "ESCAPE_DETECTED"}:
                color = Fore.YELLOW
            else:
                color = Fore.WHITE

            gate_name = gate_names.get(gate_id, f"Gate {gate_id}")
            print(f"Gate {gate_id:<3} ({gate_name:<30}): {color}{status_display}{Style.RESET_ALL}")
        else:
            gate_name = gate_names.get(gate_id, f"Gate {gate_id}")
            print(f"Gate {gate_id:<3} ({gate_name:<30}): {Fore.WHITE}NOT RUN{Style.RESET_ALL}")

    # Print Track A/B findings if Gate 6 ran
    if "6" in session:
        track_a = gate_info.get("track_a", [])
        track_b = gate_info.get("track_b", [])
        print(f"\nTrack A findings: {len(track_a)}")
        if track_a:
            for i, finding in enumerate(track_a, 1):
                print(f"  {Fore.RED}[A{i}]{Style.RESET_ALL} {finding}")

        print(f"Track B findings: {len(track_b)}")
        if track_b:
            for i, finding in enumerate(track_b, 1):
                print(f"  {Fore.YELLOW}[B{i}]{Style.RESET_ALL} {finding}")

    print()


def get_mock_weekly_analysis() -> dict:
    """Generate mock data for weekly report testing."""
    return {
        "executive_summary": """This week's threat intelligence collection identified 8 actively exploited vulnerabilities from CISA KEV and underground intelligence sources. Three APT groups with known interest in the life sciences sector were observed conducting campaigns targeting pharmaceutical supply chains.

Industry peer incidents this week include ransomware attacks against BioNTech [1] and Kaiser Permanente [3], plus a data breach at McKesson Corporation [2]. No direct threats to the organization were identified; however, the exploited CVEs and threat actor TTPs are consistent with those historically targeting genomics and biotech companies. Immediate attention is recommended for CVE-2026-22907 (Grafana) which has active exploitation confirmed by Intel471 [3]. CrowdStrike detected APT29 targeting VMware vCenter vulnerabilities [4].""",
        "statistics": {
            "threat_actors": 3,
            "active_campaigns": 2,
            "exploited_cves": 8,
            "peer_incidents": 5,
            # Legacy fallbacks
            "total_cves": 8,
            "critical_count": 4,
        },
        "cve_analysis": [
            {
                "cve_id": "CVE-2026-22907",
                "affected_product": "Grafana",
                "severity": "Critical",
                "description": "Authentication bypass in LDAP authentication module",
                "actively_exploited": True,
                "in_cisa_kev": True,
                "targeted_by_actors": "APT41",
                "exploited_by": "CISA KEV; Underground forums (Intel471)",
                "source_citations": ["NVD", "CISA KEV", "Intel471"],
            },
            {
                "cve_id": "CVE-2026-0713",
                "affected_product": "Windows Print Spooler",
                "severity": "Critical",
                "description": "Remote code execution via crafted print job",
                "actively_exploited": True,
                "in_cisa_kev": True,
                "targeted_by_actors": "Ransomware groups",
                "exploited_by": "CISA KEV; Ransomware campaigns",
            },
            {
                "cve_id": "CVE-2025-98213",
                "affected_product": "VMware vCenter",
                "severity": "High",
                "description": "Authentication bypass in management API",
                "actively_exploited": True,
                "in_cisa_kev": False,
                "targeted_by_actors": "APT29",
                "exploited_by": "APT29 (CrowdStrike)",
                "source_citations": ["NVD", "CrowdStrike"],
            },
            {
                "cve_id": "CVE-2025-12345",
                "affected_product": "Microsoft Exchange",
                "severity": "High",
                "description": "ProxyShell variant allowing remote code execution",
                "actively_exploited": True,
                "in_cisa_kev": True,
                "targeted_by_actors": "",
                "exploited_by": "CISA KEV",
            },
            {
                "cve_id": "CVE-2026-22908",
                "affected_product": "GLPI",
                "severity": "High",
                "description": "SQL injection in asset management module",
                "actively_exploited": True,
                "in_cisa_kev": False,
                "targeted_by_actors": "",
                "exploited_by": "Active exploitation (OSINT)",
            },
            {
                "cve_id": "CVE-2024-5678",
                "affected_product": "Fortinet FortiOS",
                "severity": "Critical",
                "description": "Pre-authentication remote code execution",
                "actively_exploited": True,
                "in_cisa_kev": True,
                "targeted_by_actors": "Multiple APT groups",
                "exploited_by": "CISA KEV; Ransomware groups",
            },
            {
                "cve_id": "CVE-2024-9999",
                "affected_product": "Apache Struts",
                "severity": "High",
                "description": "Remote code execution via OGNL injection",
                "actively_exploited": True,
                "in_cisa_kev": False,
                "targeted_by_actors": "",
                "exploited_by": "Underground exploit sales (Intel471)",
            },
            {
                "cve_id": "CVE-2025-11111",
                "affected_product": "Cisco IOS XE",
                "severity": "Critical",
                "description": "Privilege escalation in web UI",
                "actively_exploited": True,
                "in_cisa_kev": True,
                "targeted_by_actors": "APT41",
                "exploited_by": "CISA KEV",
            },
        ],
        "apt_activity": [
            {
                "actor": "APT41",
                "country": "China",
                "motivation": "Espionage / Financial",
                "activity": "Targeting pharmaceutical supply chains via compromised software updates",
                "ttps": [
                    "Initial Access: Software Supply Chain",
                    "Execution: PowerShell",
                    "Persistence: Registry Modification",
                ],
                "what_to_monitor": "Software update anomalies; unexpected binary modifications; connections to Asia-Pacific IPs",
                "intel471_activity": "Intel471 Report 4a5b6c7d: APT41 selling access to pharmaceutical networks on underground forum",
                "intel471_report_uid": "4a5b6c7d-8e9f-0a1b-2c3d-4e5f6a7b8c9d",
                "crowdstrike_activity": "CrowdStrike detected APT41 targeting FortiOS and Grafana vulnerabilities",
                "source_citations": ["Intel471", "CrowdStrike"],
            },
            {
                "actor": "Lazarus Group",
                "country": "North Korea",
                "motivation": "Financial / Espionage",
                "activity": "LinkedIn-based social engineering targeting biotech researchers",
                "ttps": [
                    "Initial Access: Spearphishing",
                    "Execution: User Execution",
                    "Persistence: Boot/Logon Autostart",
                ],
                "what_to_monitor": "Suspicious LinkedIn outreach to research staff; unusual file downloads from cloud storage",
                "intel471_activity": "",
                "intel471_report_uid": "",
                "crowdstrike_activity": "CrowdStrike observed Lazarus Group phishing campaigns targeting life sciences sector",
                "source_citations": ["CrowdStrike"],
            },
            {
                "actor": "LockBit Affiliates",
                "country": "Russia",
                "motivation": "Financial",
                "activity": "Ransomware campaigns against healthcare and manufacturing",
                "ttps": ["Impact: Data Encrypted", "Impact: Inhibit Recovery", "Defense Evasion: Obfuscation"],
                "what_to_monitor": "Unusual file encryption activity; VSS deletion; lateral movement from DMZ",
                "intel471_activity": "Intel471 Report 9z8y7x6w: LockBit affiliates advertising access to biotech companies",
                "intel471_report_uid": "9z8y7x6w-5v4u-3t2s-1r0q-ponmlkjihgfe",
                "crowdstrike_activity": "",
                "source_citations": ["Intel471"],
            },
        ],
        "active_campaigns": [
            {
                "campaign_name": "Operation PharmaDrain",
                "threat_actors": ["APT41"],
                "objective": "Pharmaceutical IP theft and supply chain compromise",
                "targets": "Pharmaceutical manufacturers and biotech research firms",
                "ttps": ["Software Supply Chain", "Credential Access", "Data Exfiltration"],
                "timeline": "May 2026 - Present",
                "sources": ["Intel471", "CrowdStrike"],
            },
            {
                "campaign_name": "BioSpear Campaign",
                "threat_actors": ["Lazarus Group"],
                "objective": "Social engineering for initial access and credential theft",
                "targets": "Life sciences researchers and executives",
                "ttps": ["Spearphishing", "LinkedIn Social Engineering", "Malware Delivery"],
                "timeline": "April - May 2026",
                "sources": ["CrowdStrike"],
            },
        ],
        "recommendations": [
            "Prioritize patching for the 8 exploited CVEs identified, particularly CVE-2026-22907 (Grafana) and CVE-2026-0713 (Print Spooler)",
            "Review vendor security for software supply chain following APT41 campaigns targeting pharmaceutical vendors",
            "Brief research and executive staff on LinkedIn social engineering campaigns by Lazarus Group",
            "Verify CrowdStrike has latest behavioral IOAs enabled for ransomware and APT detection",
            "Monitor industry peer incidents for emerging attack patterns affecting biotech organizations",
        ],
        "industry_incidents": [
            {
                "organization": "BioNTech SE",
                "incident_type": "Ransomware",
                "date": "2026-05-25",
                "source": "BleepingComputer",
                "osint_citation_number": 1,
            },
            {
                "organization": "McKesson Corporation",
                "incident_type": "Data Exfiltration",
                "date": "2026-05-23",
                "source": "SecurityWeek",
                "osint_citation_number": 2,
            },
            {
                "organization": "Kaiser Permanente",
                "incident_type": "Ransomware",
                "date": "2026-05-22",
                "source": "Healthcare IT News",
                "osint_citation_number": 5,
            },
            {
                "organization": "IQVIA Inc.",
                "incident_type": "Credential Harvesting",
                "date": "2026-05-20",
                "source": "Dark Reading",
                "osint_citation_number": 4,
            },
            {
                "organization": "Medtronic plc",
                "incident_type": "Remote Code Execution",
                "date": "2026-05-19",
                "source": "SecurityWeek",
                "osint_citation_number": 2,
            },
        ],
        "osint_sources_used": [
            {
                "title": "Biotech Firm Suffers Ransomware Attack",
                "url": "https://example.com/biotech-ransomware",
                "source": "BleepingComputer",
                "relevance": "Peer incident showing ransomware targeting of biotech sector",
                "date": "2026-05-25",
                "citation_number": 1,
            },
            {
                "title": "Supply Chain Vendor Data Breach Affects Healthcare",
                "url": "https://example.com/supply-chain-breach",
                "source": "SecurityWeek",
                "relevance": "Third-party breach affecting pharmaceutical supply chain",
                "date": "2026-05-23",
                "citation_number": 2,
            },
            {
                "title": "Grafana Authentication Bypass Exploited in Wild",
                "url": "https://example.com/grafana-exploit",
                "source": "The Hacker News",
                "relevance": "Confirms active exploitation of CVE-2026-22907",
                "date": "2026-05-24",
                "citation_number": 3,
            },
            {
                "title": "APT41 Targets Pharmaceutical Companies",
                "url": "https://example.com/apt41-pharma",
                "source": "Dark Reading",
                "relevance": "Intelligence on APT41 campaigns against pharmaceutical sector",
                "date": "2026-05-26",
                "citation_number": 4,
            },
            {
                "title": "Healthcare Company Hit by LockBit Ransomware",
                "url": "https://example.com/lockbit-healthcare",
                "source": "Healthcare IT News",
                "relevance": "Peer incident showing LockBit targeting of healthcare sector",
                "date": "2026-05-22",
                "citation_number": 5,
            },
        ],
    }


def get_mock_quarterly_analysis() -> dict:
    """Generate mock data for quarterly report testing."""
    return {
        "executive_summary": """The threat landscape for the genomics, life sciences, and precision manufacturing sectors remained elevated throughout Q1 2026, with 47 publicly disclosed breaches affecting peer organizations in the industry. Estimated aggregate impact exceeded $127M in direct costs and regulatory penalties, representing a 43% increase from Q4 2025.

China-linked threat actors showed particularly elevated activity this quarter [5], with systematic targeting of biomanufacturing IP and clinical trial data. APT41 and GENESIS PANDA conducted multiple intrusions via compromised software updates and spearphishing campaigns targeting research coordinators. Russian-speaking ransomware groups maintained high activity levels, with LockBit and ALPHV/BlackCat accounting for the majority of healthcare sector incidents.

Ransomware attacks increased 50% quarter-over-quarter, with notable incidents at Covenant Health (480K patient records) and Memorial Sloan Kettering (2.3M patient samples accessed). Manufacturing disruptions averaged 23 days recovery time due to OT system complexity [6]. Exploitation of unpatched internet-facing systems accounted for 34% of incidents, followed by compromised credentials without MFA at 28%.

No direct threats to the organization were identified this quarter; however, the threat actors, techniques, and vulnerabilities observed are consistent with those historically used against genomics companies [7]. Continued vigilance and proactive defense measures remain essential given the elevated threat environment.""",
        "risk_assessment": {
            "nation_state": "HIGH",
            "nation_state_trend": "↑",
            "ransomware": "HIGH",
            "ransomware_trend": "↑",
            "supply_chain": "MEDIUM",
            "supply_chain_trend": "Unchanged",
            "insider": "LOW",
            "insider_trend": "Unchanged",
        },
        "breach_landscape": {
            "scope_note": "Analysis based on publicly disclosed incidents affecting life sciences, pharmaceutical, and precision manufacturing organizations during Q1 2026.",
            "current_quarter_label": "Q1 2026",
            "prior_quarter_label": "Q4 2025",
            "stat_cards": [
                {
                    "value": "47",
                    "label": "Total Incidents",
                    "prior_label": "Prior Quarter",
                    "prior_value": "36",
                    "change_pct": "+30%",
                },
                {
                    "value": "$127M",
                    "label": "Est. Impact",
                    "prior_label": "Prior Quarter",
                    "prior_value": "$89M",
                    "change_pct": "+43%",
                },
                {
                    "value": "18",
                    "label": "Ransomware",
                    "prior_label": "Prior Quarter",
                    "prior_value": "12",
                    "change_pct": "+50%",
                },
                {
                    "value": "4.2M",
                    "label": "Records Exposed",
                    "prior_label": "Prior Quarter",
                    "prior_value": "2.8M",
                    "change_pct": "+50%",
                },
            ],
            "incidents_by_type": [
                {
                    "type": "Ransomware",
                    "current_count": "18",
                    "prior_count": "12",
                    "notable_example": "Covenant Health: 12-day production halt, FDA notification for 480K patient records",
                },
                {
                    "type": "Data Theft / Exfiltration",
                    "current_count": "11",
                    "prior_count": "9",
                    "notable_example": "Memorial Sloan Kettering: 2.3M patient samples accessed via vendor breach",
                },
                {
                    "type": "Manufacturing / OT Disruption",
                    "current_count": "5",
                    "prior_count": "3",
                    "notable_example": "Medtronic supplier: assembly line shutdown, 8-day recovery period",
                },
                {
                    "type": "Business Email Compromise",
                    "current_count": "6",
                    "prior_count": "5",
                    "notable_example": "Pharmaceutical CRO: $3.8M fraudulent wire transfers over 3-week period",
                },
                {
                    "type": "Third-Party / Vendor",
                    "current_count": "4",
                    "prior_count": "4",
                    "notable_example": "LabCorp vendor: credentials exposed for 200+ clinical laboratory customers",
                },
                {
                    "type": "Unauthorized Access",
                    "current_count": "3",
                    "prior_count": "3",
                    "notable_example": "Regeneron: former employee accessed IP repository post-termination",
                },
            ],
            "common_factors": "Exploitation of unpatched internet-facing systems accounted for 34% of incidents, followed by compromised credentials without MFA (28%). Third-party vendor compromise represented 19% of cases, with social engineering accounting for the remaining 19%. Manufacturing environments faced extended recovery timelines averaging 23 days due to OT system complexity.",
        },
        "geopolitical_threats": [
            {
                "country": "china",
                "display_name": "China",
                "threat_level": "HIGH",
                "activity_level": "HIGH",
                "relevance": [
                    "China's 14th Five-Year Plan designates biotechnology as strategic priority with genomics emphasis.",
                    "MSS-affiliated actors conduct systematic collection against Western life sciences organizations.",
                ],
                "activity": [
                    "APT41 conducted intrusions via compromised software update mechanisms targeting pharma and genomics.",
                    "GENESIS PANDA spearphished clinical research coordinators at 6 biotech firms this quarter.",
                ],
                "risk": [
                    "Theft of sequencing technology designs could erode competitive advantage and R&D investment.",
                    "Compromised clinical trial data raises regulatory and patient safety concerns for ongoing studies.",
                ],
            },
            {
                "country": "russia",
                "display_name": "Russia",
                "threat_level": "HIGH",
                "activity_level": "MEDIUM",
                "relevance": [
                    "Russian-speaking criminal groups operating with tacit state approval pose ransomware threat.",
                    "State cyber interests in life sciences remain opportunistic, focusing on healthcare disruption.",
                ],
                "activity": [
                    "Ransomware incidents affecting healthcare and pharma increased 31% quarter-over-quarter.",
                    "LockBit, ALPHV/BlackCat, and Cl0p affiliates accounted for majority of industry incidents.",
                ],
                "risk": [
                    "Ransomware incidents average $4.2M recovery costs and 23 days operational disruption.",
                    "Manufacturing environments face extended recovery due to OT system complexity and validation.",
                ],
            },
            {
                "country": "north_korea",
                "display_name": "North Korea",
                "threat_level": "MEDIUM",
                "activity_level": "MEDIUM",
                "relevance": [
                    "DPRK cyber operations serve revenue generation and medical research acquisition purposes.",
                    "Sustained interest in vaccine research and oncology treatments for domestic programs.",
                ],
                "activity": [
                    "Lazarus Group and Kimsuky conducted LinkedIn social engineering throughout the quarter.",
                    "Campaigns used fake recruiter personas targeting research scientists and engineers.",
                ],
                "risk": [
                    "Credential compromise provides access to sensitive environments and IP repositories.",
                    "Executive targeting enables BEC fraud attempts and supply chain infiltration vectors.",
                ],
            },
        ],
        "looking_ahead": {
            "next_quarter_label": "Q2 2026",
            "threat_outlook": "We anticipate continued pressure from state-sponsored espionage campaigns as genomics research and precision manufacturing technology becomes increasingly valuable to national biotechnology strategies. Ransomware threat remains elevated with likely targeting of manufacturing operations.",
            "planned_initiatives": "Integration of Microsoft Sentinel for unified security event correlation. Development of automated threat intelligence sharing with industry partners via H-ISAC. Expansion of executive protection monitoring.",
            "watch_items": [
                {
                    "subject": "Major genomics conferences and product launches —",
                    "detail": "Potential escalation in state-sponsored espionage activity targeting intellectual property and partnership announcements during high-profile industry events.",
                },
                {
                    "subject": "Ransomware evolution targeting OT environments —",
                    "detail": "Continued sophistication in double extortion tactics with increased focus on manufacturing and operational technology systems.",
                },
                {
                    "subject": "Supply chain vendor compromises —",
                    "detail": "Ongoing third-party security incidents affecting laboratory equipment vendors and biomanufacturing software providers.",
                },
            ],
        },
        "recommendations": {
            "intro_note": "Based on Q1 threat activity and industry incidents, these actions will strengthen security posture:",
            "items": [
                {
                    "title": "Executive Awareness Briefings",
                    "body": "Consider targeted security awareness for executives and key research personnel given sustained social engineering campaigns via professional networks. CTI team can provide customized briefings on current threat actor tactics.",
                },
                {
                    "title": "Vendor Risk Assessment Review",
                    "body": "Evaluate security posture of critical software and laboratory equipment vendors given Q1 supply chain compromise activity. Prioritize vendors with privileged access to research and manufacturing systems.",
                },
                {
                    "title": "Manufacturing Environment Security",
                    "body": "Review network segmentation between IT and OT/manufacturing systems. Ensure incident response plans address manufacturing disruption scenarios and production recovery timelines.",
                },
            ],
        },
        "osint_sources_used": [
            {
                "title": "FortiClient EMS Flaw",
                "url": "https://example.com/forticlient-vulnerability",
                "description": "Confirmed active exploitation of FortiClient EMS vulnerability impacting device security.",
                "citation_number": 5,
            },
            {
                "title": "GreyVibe AI Attacks",
                "url": "https://example.com/greyvibe-ai-phishing",
                "description": "Highlights emerging use of AI-powered phishing and malware delivery by Russian-linked threat clusters.",
                "citation_number": 6,
            },
            {
                "title": "BTMOB Android Malware",
                "url": "https://example.com/btmob-android-threat",
                "description": "Identifies new Android malware service generating custom phishing payloads, increasing risk to healthcare systems.",
                "citation_number": 7,
            },
        ],
    }


async def generate_report_local(
    report_type: str, use_mock: bool = False, use_real: bool = False, output_dir: str = ".", use_azure: bool = False
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
    from src.reports import get_report_generator

    # Get the appropriate report generator (mark as mock if using mock data)
    generator = get_report_generator(report_type, use_mock_data=use_mock)
    if generator is None:
        raise ValueError(f"Unknown report type: {report_type}")

    # Determine data source
    data_by_source = None  # Will hold raw collected data for gate framework
    credentials = None  # Will hold Azure credentials for gate framework

    if use_mock:
        try:
            print_section("📋 Using Mock Data")
        except UnicodeEncodeError:
            print_section("Using Mock Data")
        if report_type == "weekly":
            analysis = get_mock_weekly_analysis()
        else:
            analysis = get_mock_quarterly_analysis()
        # Mock data: no raw collected data, use empty dicts for gate framework
        data_by_source = {}
    elif use_real or use_azure:
        analysis, data_by_source = await collect_and_analyze(report_type)

        # Get credentials for gate framework (Gate 5 needs Azure OpenAI)
        from src.core.config import azure_config
        from src.core.keyvault import get_all_api_keys

        vault_url = azure_config.get_key_vault_url()
        credentials = get_all_api_keys(vault_url)
    else:
        try:
            print_section("📋 Using Mock Data (default)")
        except UnicodeEncodeError:
            print_section("Using Mock Data (default)")
        if report_type == "weekly":
            analysis = get_mock_weekly_analysis()
        else:
            analysis = get_mock_quarterly_analysis()
        # Mock data: no raw collected data, use empty dicts for gate framework
        data_by_source = {}

    # Optional: gate framework validation pass (feature-flagged)
    if _gate_framework_enabled():
        try:
            print_section("🔒 Gate Framework Validation")
        except UnicodeEncodeError:
            print_section("Gate Framework Validation")
        from src.core.config import get_feature_config
        from src.gates.pipeline_hook import run_gate_framework_over_collected_data

        feature_config = get_feature_config()
        interactive_mode = feature_config.gate_framework_interactive

        if interactive_mode:
            print_status("Interactive mode enabled - you will be prompted after each gate", "info")
            print()

        period_days = 7 if report_type == "weekly" else 90

        # Define interactive callback for prompting user
        def interactive_callback(gate_id, result, session):
            """Called after each gate in interactive mode."""
            # Print gate result
            _print_gate_summary(session, {}, report_type)

            # Prompt user
            print()
            gate_names = {
                "1": "Tier 1 Source Inventory",
                "1A": "Statistics Validation",
                "1B": "OSINT Article Triage",
                "2": "IOC Extraction",
                "3": "Actor Linkage",
                "4": "Structured Assembly",
                "5": "Report Draft",
                "1C": "Technology Coherence",
                "1D": "Source Attribution",
                "6": "Adversarial Review",
            }
            gate_name = gate_names.get(gate_id, f"Gate {gate_id}")
            print(
                f"{Fore.CYAN}Gate {gate_id} ({gate_name}) completed with status: {Fore.GREEN}{result.status}{Style.RESET_ALL}"
            )
            print()

            while True:
                choice = input(f"{Fore.CYAN}Continue to next gate? [Y/n]: {Style.RESET_ALL}").strip().lower()
                if choice in {"", "y", "yes"}:
                    print()
                    return True
                elif choice in {"n", "no"}:
                    print_status("Gate framework aborted by user", "warning")
                    return False
                else:
                    print_status("Please enter 'y' or 'n'", "warning")

        publish_ok, gate_info, session = run_gate_framework_over_collected_data(
            report_type=report_type,
            data_by_source=data_by_source or {},
            osint_articles=data_by_source.get("OSINT", []) if data_by_source else [],
            period_days=period_days,
            interactive_mode=interactive_mode,
            interactive_callback=interactive_callback if interactive_mode else None,
            credentials={
                "openai_endpoint": credentials["openai_endpoint"],
                "openai_key": credentials["openai_key"],
            }
            if credentials
            else None,
        )

        # Print final gate summary (only in non-interactive or after completion)
        if not interactive_mode or publish_ok or not gate_info.get("user_abort"):
            _print_gate_summary(session, gate_info, report_type)

        # Handle blocking conditions
        if not publish_ok:
            # Check for user abort
            if gate_info.get("user_abort"):
                print_status(f"Aborted at Gate {gate_info.get('aborted_at_gate')}", "warning")
                print()
                sys.exit(0)

            # For mock data, treat HALT as warning rather than hard block
            if use_mock and "halt_gate" in gate_info:
                print_status(
                    f"Mock data triggered Gate {gate_info['halt_gate']} HALT (treating as warning in mock mode)",
                    "warning",
                )
                print_status("Continuing with report generation...", "info")
            else:
                # Real data or ESCAPE/BLOCK: stop here
                if "halt_gate" in gate_info:
                    print_status(f"Gate {gate_info['halt_gate']} HALT: {gate_info['halt_reason']}", "error")
                elif "escape_gate" in gate_info:
                    print_status(f"Gate {gate_info['escape_gate']} ESCAPE ({gate_info['escape_type']})", "error")
                elif gate_info.get("gate6_status") == "BLOCK":
                    track_a_count = len(gate_info.get("track_a", []))
                    print_status(f"Gate 6 BLOCK: {track_a_count} Track A findings prevent publication", "error")
                print()
                sys.exit(1)

    # Generate the document
    try:
        print_section("📄 Generating Report")
    except UnicodeEncodeError:
        print_section("Generating Report")
    print_status("Creating document...", "progress")
    doc = generator.generate(analysis)
    print_status("Document created", "success")

    # Always save a local copy
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Get filename with report week start if available
    if hasattr(generator, "_report_week_start"):
        filename = generator.get_filename(report_week_start=generator._report_week_start)
    else:
        filename = generator.get_filename()

    filepath = output_path / filename
    doc.save(str(filepath))
    print_status(f"Saved locally: {filepath}", "success")

    # Upload to Azure if requested
    if use_azure:
        try:
            print_section("☁️  Uploading to Azure")
        except UnicodeEncodeError:
            print_section("Uploading to Azure")
        from src.core.config import azure_config
        from src.core.keyvault import get_all_api_keys
        from src.reports.blob_storage import upload_to_blob

        credentials = get_all_api_keys(azure_config.get_key_vault_url())
        url = upload_to_blob(generator, credentials["storage_account_name"], credentials["storage_account_key"])
        print_status(f"Uploaded: {url}", "success")
        return url

    return str(filepath)


async def check_openai_connectivity(
    endpoint: str, api_key: str = "", deployment: str = "", timeout: float = 8.0
) -> bool:
    """
    Quick connectivity check to Azure OpenAI completions endpoint.
    Sends a minimal authenticated request to detect VNet restrictions.
    Returns True if reachable, False if behind VPN / unreachable.
    """
    import urllib.error
    import urllib.request

    if not api_key:
        return True

    from src.core.config import analysis_config

    deploy = deployment or analysis_config.deployment_name

    url = (
        endpoint.rstrip("/")
        + f"/openai/deployments/{deploy}/chat/completions?api-version={analysis_config.api_version}"
    )
    # No token-cap param: max_tokens is rejected by reasoning models (which want
    # max_completion_tokens), and max_completion_tokens isn't accepted on older api
    # versions — so omit it entirely. This is a tiny connectivity/auth ping.
    body = json.dumps({"messages": [{"role": "user", "content": "ping"}]}).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("api-key", api_key)
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except urllib.error.HTTPError as e:
        resp_body = ""
        try:
            resp_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if e.code == 403 and ("Virtual Network" in resp_body or "VNet" in resp_body or "vnet" in resp_body.lower()):
            return False
        if e.code in (429, 500, 502, 503):
            return True
        if e.code == 404:
            return True
        if e.code == 401:
            return True
        return True
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


async def collect_and_analyze(report_type: str) -> tuple[dict, dict]:
    """Collect data and run analysis (requires Azure credentials).

    Returns:
        (analysis, data_by_source) tuple where analysis is the AI analysis result
        and data_by_source is the raw collected data dict
    """
    from src.agents.threat_analyst import ThreatAnalystAgent
    from src.collectors import collect_all, get_data_by_source
    from src.core.config import analysis_config, azure_config
    from src.core.keyvault import get_all_api_keys

    # Get credentials
    vault_url = azure_config.get_key_vault_url()
    print_status("Connecting to Azure Key Vault...", "progress")
    credentials = get_all_api_keys(vault_url)
    print_status("Credentials retrieved", "success")

    # Check Azure OpenAI connectivity before spending time on data collection
    ai_available = await check_openai_connectivity(
        credentials["openai_endpoint"], api_key=credentials.get("openai_key", "")
    )

    if not ai_available:
        print()
        try:
            print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 60}")
            print("  ⚠  Azure OpenAI is NOT reachable")
            print("  Are you connected to the VPN?")
            print(f"{'=' * 60}{Style.RESET_ALL}")
        except UnicodeEncodeError:
            print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 60}")
            print("  WARNING: Azure OpenAI is NOT reachable")
            print("  Are you connected to the VPN?")
            print(f"{'=' * 60}{Style.RESET_ALL}")
        print()
        print(f"  {Fore.WHITE}[1] Stop - I'll connect to VPN first")
        print(f"  [2] Continue without AI (use NVD data directly){Style.RESET_ALL}")
        print()

        choice = input(f"  {Fore.CYAN}Enter choice (1 or 2): {Style.RESET_ALL}").strip()

        if choice != "2":
            print()
            print_status("Stopped. Connect to VPN and run again.", "warning")
            sys.exit(0)

        print()
        print_status("Continuing without AI analysis (NVD backup mode)...", "warning")
    else:
        print_status("Azure OpenAI is reachable", "success")

    # Collect data
    try:
        print_section("📊 Collecting Threat Intelligence")
    except UnicodeEncodeError:
        print_section("Collecting Threat Intelligence")
    collector_results = await collect_all(credentials, report_type=report_type)
    data_by_source = get_data_by_source(collector_results)

    # Show collection results
    for source, result in collector_results.items():
        if result.success:
            count = result.record_count
            # Check if CircleCII fallback was used
            if "CircleCII" in result.source:
                if count > 0:
                    print_status(f"{source}: {count} records (via CircleCII fallback)", "success")
                else:
                    print_status(f"{source}: CircleCII fallback active (0 CRITICAL/HIGH CVEs found)", "warning")
            else:
                if count > 0:
                    print_status(f"{source}: {count} records", "success")
                else:
                    print_status(f"{source}: No data", "warning")
        else:
            print_status(f"{source}: Failed - {result.error[:50]}", "error")

    # Enrich data
    try:
        print_section("🔍 Enriching CVE Data")
    except UnicodeEncodeError:
        print_section("Enriching CVE Data")
    from src.enrichment import CVEEnricher, ThreatActorMonitoringEnricher

    cve_enricher = CVEEnricher()
    ThreatActorMonitoringEnricher()

    if "NVD" in data_by_source:
        print_status("Checking CISA KEV catalog...", "progress")
        data_by_source["NVD"] = await cve_enricher.enrich_cves(data_by_source["NVD"])
        print_status(f"Enriched {len(data_by_source['NVD'])} CVEs", "success")

    # Initialize agent
    try:
        print_section("🤖 AI-Powered Analysis")
    except UnicodeEncodeError:
        print_section("AI-Powered Analysis")

    if not ai_available:
        print_status("Skipping AI (not reachable) - using backup data", "warning")
        agent = ThreatAnalystAgent(
            credentials["openai_endpoint"], credentials["openai_key"], deployment_name=analysis_config.deployment_name
        )
        if report_type == "weekly":
            result = agent._get_default_analysis(
                data_by_source.get("NVD", []),
                data_by_source.get("Intel471", []),
                data_by_source.get("CrowdStrike", []),
            )
        else:
            intel471_all = data_by_source.get("Intel471", [])
            breach_data = [item for item in intel471_all if item.get("threat_type", "").upper() == "BREACH ALERT"]
            intel471_filtered = [item for item in intel471_all if item.get("threat_type", "").upper() != "BREACH ALERT"]
            result = agent._get_default_strategic_analysis(
                intel471_filtered, data_by_source.get("CrowdStrike", []), breach_data if breach_data else None
            )
        print_status("Backup analysis complete", "success")
        return result, data_by_source

    print_status("Initializing threat analyst agent...", "progress")
    agent = ThreatAnalystAgent(
        credentials["openai_endpoint"], credentials["openai_key"], deployment_name=analysis_config.deployment_name
    )

    if report_type == "weekly":
        print_status("Running tactical analysis...", "progress")
        result = await agent.analyze_threats(
            data_by_source.get("NVD", []),
            data_by_source.get("Intel471", []),
            data_by_source.get("CrowdStrike", []),
            data_by_source.get("OSINT", []),
        )
        print_status("Analysis complete", "success")
        return result, data_by_source
    else:
        print_status("Running strategic analysis...", "progress")

        intel471_data = data_by_source.get("Intel471", [])
        breach_data = [item for item in intel471_data if item.get("threat_type", "").upper() == "BREACH ALERT"]

        intel471_data = [item for item in intel471_data if item.get("threat_type", "").upper() != "BREACH ALERT"]

        # Get Illumina OSINT context for quarterly reports
        illumina_osint = data_by_source.get("Illumina-OSINT", [])
        illumina_context = ""
        if illumina_osint:
            # The Illumina OSINT collector returns a single record with "illumina_context" field
            if len(illumina_osint) > 0 and "illumina_context" in illumina_osint[0]:
                illumina_context = illumina_osint[0]["illumina_context"]
                logger.info(f"Using Illumina OSINT context ({len(illumina_context)} chars)")
            else:
                logger.warning("Illumina-OSINT data found but no illumina_context field present")

        result = await agent.analyze_strategic(
            intel471_data=intel471_data,
            crowdstrike_data=data_by_source.get("CrowdStrike", []),
            breach_data=breach_data if breach_data else None,
            illumina_context=illumina_context,
        )
        print_status("Analysis complete", "success")
        return result, data_by_source


def main():
    parser = argparse.ArgumentParser(
        description="Local test script for CTI Report Generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Data Source Options:
  --mock    Use hardcoded example data (no Azure/API access needed)
  --real    Use real data from APIs (requires Key Vault access)
  --debug   Enable verbose logging output (shows all API calls, data processing, etc.)

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

  # Enable debug mode to see detailed logs
  python test_local.py weekly --local --real --debug
        """,
    )

    parser.add_argument("report_type", choices=["weekly", "quarterly"], help="Type of report to generate")

    parser.add_argument("--local", action="store_true", help="Save report locally (to disk)")

    parser.add_argument("--azure", action="store_true", help="Upload report to Azure Blob Storage (uses real data)")

    parser.add_argument("--mock", action="store_true", help="Use MOCK/example data (no API calls, for UI testing)")

    parser.add_argument("--real", action="store_true", help="Use REAL data from APIs (requires Key Vault access)")

    parser.add_argument(
        "--output", "-o", default=".", help="Output directory for local generation (default: current directory)"
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug mode with verbose logging output")
    parser.add_argument(
        "--log-file",
        default="debug.log",
        help="File to write full debug logs to when --debug is set (default: debug.log). "
        "Use --log-file '' to disable and log to console only.",
    )

    args = parser.parse_args()

    # Configure logging based on debug flag (writes debug.log by default in --debug mode)
    configure_logging(args.debug, log_file=(args.log_file or None))

    # Validate arguments
    if not args.local and not args.azure:
        parser.error("Must specify either --local or --azure")

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
        print_header(f"CTI Report Generator - {args.report_type.upper()}")
        print(f"{Fore.WHITE}Data Source: {data_source}")
        print(f"Output: {'Azure Blob Storage' if args.azure else f'Local ({args.output})'}")
        if args.debug:
            print(f"Debug Mode: {Fore.YELLOW}ENABLED (verbose logging){Style.RESET_ALL}")
        print(f"{Style.RESET_ALL}\n")

        result = asyncio.run(
            generate_report_local(
                report_type=args.report_type,
                use_mock=use_mock,
                use_real=use_real,
                output_dir=args.output,
                use_azure=args.azure,
            )
        )

        try:
            print_header("✓ SUCCESS")
        except UnicodeEncodeError:
            print_header("SUCCESS")
        print(f"{Fore.GREEN}Report Type: {args.report_type.upper()}")
        print(f"Data Source: {data_source}")
        if args.azure:
            print(f"URL: {result}")
        else:
            print(f"File: {result}{Style.RESET_ALL}\n")

    except Exception as e:
        try:
            print_header("✗ ERROR")
        except UnicodeEncodeError:
            print_header("ERROR")
        print(f"{Fore.RED}Failed to generate report: {e}{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
