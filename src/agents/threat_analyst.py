"""
AI-powered threat analyst using Microsoft Semantic Kernel and Azure OpenAI.

Analyzes threat intelligence data and generates actionable reports.
"""
import logging
import json
import re
from typing import Dict, List, Any
from pathlib import Path

from semantic_kernel import Kernel  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatPromptExecutionSettings  # type: ignore
from semantic_kernel.contents import ChatHistory  # type: ignore

from src.core.config import analysis_config, industry_filter_config
from src.core.models import ThreatAnalysisResult
from src.agents.exploit_enrichment import (
    fetch_kev_cves, fetch_epss_scores,
    build_exploited_by, build_affected_product_from_kev,
)

logger = logging.getLogger(__name__)


# System prompt for the analyst - can be loaded from file for easier tuning
DEFAULT_SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence Analyst for a genomics company.
Your role is to analyze threat data from multiple sources, correlate findings across CVEs and threat actors,
prioritize threats based on relevance to the biotech, life sciences, and manufacturing industries, and generate clear,
actionable intelligence reports for technical and executive audiences.

Focus on threats that could impact:
- Research data and intellectual property
- Laboratory equipment and IoT devices
- Healthcare systems and patient data
- Supply chain and vendor security
- Regulatory compliance (HIPAA, FDA, etc.)

Do not use Hyphens."""

# Strategic analysis system prompt for quarterly reports
STRATEGIC_SYSTEM_PROMPT = """You are a Senior Cyber Threat Intelligence Analyst preparing a quarterly strategic brief for executive leadership and the board of directors.

Your role is to analyze threat intelligence data with a STRATEGIC lens, focusing on:
- Geopolitical trends and nation-state threats to the life sciences/genomics sector
- Industry breach landscape and peer organization incidents
- Ransomware and extortion group activity trends
- Supply chain and third-party risk evolution
- Business implications of cyber threats (not just technical details)

Write for a non-technical executive audience. Focus on:
- Business risk and competitive implications
- Regulatory and compliance considerations
- Investment and resource allocation decisions
- Peer organization comparisons and industry benchmarks

Avoid tactical details like specific CVEs or IOCs unless they have strategic significance.

Do not use Hyphens."""


def _sanitize_for_prompt(data: Any, max_chars: int | None = None) -> str:
    """
    Serialize data for safe inclusion in an LLM prompt.
    Strips injection markers, code blocks, and special delimiters; optionally truncates.
    """
    try:
        out = json.dumps(data, default=str)
    except (TypeError, ValueError):
        out = str(data)
    # Remove prompt-injection and formatting markers
    for marker in ("SYSTEM:", "```", "<|", "|>"):
        out = out.replace(marker, "")
    if max_chars is not None and len(out) > max_chars:
        out = out[:max_chars].rstrip() + " [truncated]"
    return out


def load_system_prompt(prompt_file: str = "prompts/analyst_system.txt") -> str:
    """
    Load system prompt from file if available, otherwise use default.

    Args:
        prompt_file: Path to the prompt file

    Returns:
        System prompt string
    """
    prompt_path = Path(prompt_file)
    if prompt_path.exists():
        try:
            return prompt_path.read_text().strip()
        except Exception as e:
            logger.warning(f"Failed to load prompt file: {e}, using default")
    return DEFAULT_SYSTEM_PROMPT


class ThreatAnalystAgent:
    """
    AI-powered threat analyst using Microsoft Semantic Kernel and Azure OpenAI.
    Analyzes threat intelligence data and generates actionable reports.
    """

    def __init__(
        self,
        openai_endpoint: str,
        openai_key: str,
        deployment_name: str = None,
        system_prompt: str = None
    ):
        """
        Initialize the Threat Analyst Agent.

        Args:
            openai_endpoint: Azure OpenAI endpoint URL
            openai_key: Azure OpenAI API key
            deployment_name: Name of the GPT deployment (defaults to config)
            system_prompt: Custom system prompt (defaults to built-in)
        """
        self.deployment_name = deployment_name or analysis_config.deployment_name
        self.openai_endpoint = openai_endpoint
        self.openai_key = openai_key
        self.system_prompt = system_prompt or load_system_prompt()

        logger.info(f"Initializing ThreatAnalystAgent with deployment: {self.deployment_name}")
        logger.info(f"Endpoint configured: {bool(openai_endpoint)}")

        # Initialize Semantic Kernel
        self.kernel = Kernel()

        # Add Azure OpenAI chat service
        self.chat_service = AzureChatCompletion(
            deployment_name=self.deployment_name,
            endpoint=openai_endpoint,
            api_key=openai_key,
            service_id="cti_analyst"
        )

        self.kernel.add_service(self.chat_service)
        logger.info("ThreatAnalystAgent initialized successfully")

    async def analyze_threats(
        self,
        cve_data: List[Dict],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        threatq_data: List[Dict],
        rapid7_data: List[Dict],
        rapid7_scans_data: List[Dict] = None,
        osint_data: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze threat intelligence data from multiple sources.

        Args:
            cve_data: List of CVE records from NVD
            intel471_data: List of threat intelligence from Intel471
            crowdstrike_data: List of APT intelligence from CrowdStrike
            threatq_data: List of indicators from ThreatQ
            rapid7_data: List of vulnerability data from Rapid7
            rapid7_scans_data: List of scan-based exposure data from Rapid7
            osint_data: List of articles from curated OSINT sources

        Returns:
            Dictionary containing analysis results
        """
        try:
            logger.info("Starting threat analysis")
            logger.info(
                f"Data counts - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, "
                f"CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, "
                f"Rapid7: {len(rapid7_data)}, Rapid7-Scans: {len(rapid7_scans_data or [])}, "
                f"OSINT: {len(osint_data or [])}"
            )

            # Fetch public exploit intelligence (CISA KEV + EPSS)
            all_cve_ids = self._collect_all_cve_ids(
                cve_data, rapid7_scans_data or []
            )
            kev_lookup = await fetch_kev_cves()
            epss_lookup = await fetch_epss_scores(list(all_cve_ids))

            # Prepare data for analysis (with smart truncation)
            data_summary = self._prepare_data_for_analysis(
                cve_data, intel471_data, crowdstrike_data, threatq_data, rapid7_data
            )

            # Create analysis prompt
            analysis_prompt = self._build_analysis_prompt(
                data_summary, cve_data, intel471_data, crowdstrike_data,
                threatq_data, rapid7_data, rapid7_scans_data or [],
                osint_data or []
            )

            # Create chat history
            chat_history = ChatHistory()
            chat_history.add_system_message(self.system_prompt)
            chat_history.add_user_message(analysis_prompt)

            # Configure execution settings
            settings = AzureChatPromptExecutionSettings(
                response_format={"type": "json_object"},
                temperature=0.1,  # Slightly higher temperature for more variation in breach selection
                seed=789,  # New seed for different selections
            )

            # Get response from GPT
            logger.info("Sending request to Azure OpenAI")
            response = await self.chat_service.get_chat_message_content(
                chat_history=chat_history,
                settings=settings
            )

            # Parse response
            response_text = str(response)
            logger.info("Received response from Azure OpenAI")

            # Clean up response (remove markdown code blocks if present)
            analysis_result = self._parse_response(response_text)

            if analysis_result:
                logger.info("Successfully parsed analysis results")
                analysis_result = self._fill_gaps_from_backup(
                    analysis_result, cve_data, rapid7_data, rapid7_scans_data,
                    kev_lookup, epss_lookup, intel471_data, crowdstrike_data,
                )
                return analysis_result
            else:
                return self._get_default_analysis(
                    cve_data, intel471_data, crowdstrike_data,
                    threatq_data, rapid7_data, rapid7_scans_data,
                    kev_lookup, epss_lookup,
                )

        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            return self._get_default_analysis(
                cve_data, intel471_data, crowdstrike_data,
                threatq_data, rapid7_data, rapid7_scans_data,
            )

    @staticmethod
    def _collect_all_cve_ids(cve_data: List[Dict], rapid7_scans_data: List) -> set:
        """Gather all unique CVE IDs across data sources for enrichment lookups."""
        ids = set()
        for cve in cve_data:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                ids.add(cve_id)
        if rapid7_scans_data and len(rapid7_scans_data) > 0:
            scan = rapid7_scans_data[0] if isinstance(rapid7_scans_data[0], dict) else {}
            ids.update(scan.get("cve_exposure_map", {}).keys())
        return ids

    def _prepare_data_for_analysis(
        self,
        cve_data: List[Dict],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        threatq_data: List[Dict],
        rapid7_data: List[Dict]
    ) -> Dict[str, List]:
        """
        Prepare and truncate data for analysis based on config limits.

        Args:
            Various data lists from collectors

        Returns:
            Dictionary with truncated data
        """
        return {
            "cve_data": cve_data[:analysis_config.max_cves_for_analysis],
            "intel471_data": intel471_data[:analysis_config.max_intel471_for_analysis],
            "crowdstrike_data": crowdstrike_data[:analysis_config.max_crowdstrike_for_analysis],
            "threatq_data": threatq_data[:analysis_config.max_threatq_for_analysis],
            "rapid7_data": rapid7_data[:analysis_config.max_rapid7_for_analysis]
        }

    def _build_analysis_prompt(
        self,
        data_summary: Dict[str, List],
        cve_data: List,
        intel471_data: List,
        crowdstrike_data: List,
        threatq_data: List,
        rapid7_data: List,
        rapid7_scans_data: List = None,
        osint_data: List = None
    ) -> str:
        """Build the analysis prompt with data."""
        rapid7_scans_data = rapid7_scans_data or []
        osint_data = osint_data or []
        
        # Extract Rapid7 CVE correlation data from BOTH sources
        rapid7_cve_map = {}
        
        # OPTION 1: Scan-based data (NEW - more accurate asset counts)
        if rapid7_scans_data and len(rapid7_scans_data) > 0:
            scan_summary = rapid7_scans_data[0] if isinstance(rapid7_scans_data[0], dict) else {}
            logger.info(f"Rapid7 scan data keys: {list(scan_summary.keys())}")
            
            cve_exposure_map = scan_summary.get("cve_exposure_map", {})
            logger.info(f"Rapid7 scans CVE exposure map: {len(cve_exposure_map)} CVEs")
            
            # Extract exposure data in the format: {"CVE-2024-1234": {"exposure": "12 servers", "asset_count": 12, ...}}
            for cve_id, exposure_info in cve_exposure_map.items():
                if isinstance(exposure_info, dict):
                    # Use the pre-formatted exposure string (e.g., "12 servers")
                    rapid7_cve_map[cve_id] = exposure_info.get("exposure", f"{exposure_info.get('asset_count', 0)} systems")
                    logger.debug(f"Mapped {cve_id} -> {rapid7_cve_map[cve_id]}")
        
        # OPTION 2: Fallback to vulnerability definitions (original source)
        if not rapid7_cve_map and rapid7_data and len(rapid7_data) > 0:
            logger.info("No scan data available, checking vulnerability definitions...")
            rapid7_summary = rapid7_data[0] if isinstance(rapid7_data[0], dict) else {}
            logger.info(f"Rapid7 summary keys: {list(rapid7_summary.keys())}")
            
            top_vulns = rapid7_summary.get("top_vulnerabilities", [])
            logger.info(f"Rapid7 top_vulnerabilities count: {len(top_vulns)}")
            
            if top_vulns:
                logger.info(f"Sample vulnerability structure: {top_vulns[0].keys() if top_vulns else 'empty'}")
            
            # Build a map of CVE ID -> asset count from Rapid7 top vulnerabilities
            for idx, vuln in enumerate(top_vulns):
                cve_ids = vuln.get("cve_ids", [])
                # Fix: Ensure cve_ids is a list, not a string
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids] if cve_ids else []
                
                asset_count = vuln.get("asset_count")
                
                if idx < 3:  # Log first 3 for debugging
                    logger.info(f"Vuln {idx}: CVEs={cve_ids}, asset_count={asset_count} (type: {type(asset_count)})")
                
                for cve_id in cve_ids:
                    if cve_id not in rapid7_cve_map:
                        if asset_count is not None and asset_count > 0:
                            rapid7_cve_map[cve_id] = f"{asset_count} servers"
                            logger.info(f"Mapped {cve_id} -> {asset_count} assets")
                        elif idx < 3:  # Log why first 3 weren't mapped
                            logger.info(f"Skipped {cve_id}: asset_count={asset_count}")
        
        logger.info(f"Rapid7 CVE exposure map: {len(rapid7_cve_map)} CVEs with exposure data")
        if rapid7_cve_map:
            logger.info(f"Sample Rapid7 exposures: {dict(list(rapid7_cve_map.items())[:5])}")
        
        # Extract CrowdStrike Spotlight CVE correlation data
        crowdstrike_cve_map = {}
        if crowdstrike_data:
            for item in crowdstrike_data:
                if item.get("type") == "vulnerability" and item.get("device_count"):
                    for cve_id in item.get("cve_ids", []):
                        if cve_id not in crowdstrike_cve_map:
                            crowdstrike_cve_map[cve_id] = item["device_count"]
        
        if crowdstrike_cve_map:
            logger.info(f"CrowdStrike CVE exposure map: {len(crowdstrike_cve_map)} CVEs")
        
        # Merge both sources - prefer CrowdStrike if both exist (more real-time)
        combined_cve_map = {**rapid7_cve_map, **crowdstrike_cve_map}
        
        logger.info(f"Combined exposure map: {len(combined_cve_map)} CVEs total")
        if combined_cve_map:
            logger.info(f"Exposure map content: {combined_cve_map}")
        
        # Extract Intel471 breach/exploitation context
        intel471_cve_mentions = {}
        intel471_actor_activity = []
        intel471_breach_summary = []
        
        if intel471_data:
            for item in intel471_data:
                threat_type = item.get("threat_type", "").upper()
                summary = item.get("summary", "")
                
                # Look for CVE mentions in Intel471 reports
                import re
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                cves_mentioned = re.findall(cve_pattern, summary)
                for cve_id in cves_mentioned:
                    if cve_id not in intel471_cve_mentions:
                        intel471_cve_mentions[cve_id] = {
                            "mentioned_in": threat_type,
                            "context": summary[:200]
                        }
                
                # Collect actor activity
                actor = item.get("threat_actor", "")
                if actor and actor != "Unknown":
                    intel471_actor_activity.append({
                        "actor": actor,
                        "type": threat_type,
                        "summary": summary[:150]
                    })
                
                # Collect breach information
                if "BREACH" in threat_type:
                    intel471_breach_summary.append({
                        "summary": summary[:200],
                        "date": item.get("date", "")
                    })
        
        # Merge both sources - prefer CrowdStrike if both exist (more real-time)
        combined_cve_map = {**rapid7_cve_map, **crowdstrike_cve_map}
        
        exposure_correlation_note = ""
        if combined_cve_map:
            # Create explicit examples for the AI
            example_mappings = []
            for cve_id, exposure_value in list(combined_cve_map.items())[:5]:
                # The exposure_value is already formatted (e.g., "1 system", "7 systems")
                example_mappings.append(f'  - {cve_id}: {exposure_value} → set "exposure": "{exposure_value}"')
            
            exposure_correlation_note = f"""
CRITICAL - VULNERABILITY EXPOSURE CORRELATION:
The following CVEs have been detected in our environment by security scans:
{json.dumps(combined_cve_map, indent=2)}

Source: {"CrowdStrike Spotlight" if crowdstrike_cve_map else ""} {"and Rapid7 InsightVM" if rapid7_cve_map else "Rapid7 InsightVM"}

INSTRUCTIONS - ANALYZE ONLY DETECTED CVEs:
- **ONLY analyze CVEs that appear in the exposure map above**
- **IGNORE any CVEs from NVD/Intel471/other sources that are NOT in this exposure map**
- We only care about vulnerabilities actually detected in our environment
- Set "exposure" field to the EXACT string from the map (already formatted, e.g., "1 server", "7 systems", "3 endpoints")
- DO NOT modify or append anything to these values - use them exactly as provided
- Examples from the data above:
{chr(10).join(example_mappings)}

FILTERING REQUIREMENT:
If a CVE is not in the exposure map above, DO NOT include it in your cve_analysis array.
Your report should ONLY contain CVEs that are actually in our environment.
"""
        
        # Add Intel471 correlation context
        intel471_context = ""
        if intel471_cve_mentions or intel471_breach_summary:
            intel471_context = f"""
INTEL471 UNDERGROUND INTELLIGENCE CORRELATION:
"""
            if intel471_cve_mentions:
                intel471_context += f"""
CVEs Mentioned in Intel471 Underground/Breach Reports:
{json.dumps(intel471_cve_mentions, indent=2)}

If a CVE appears here, it means:
- It's being discussed in underground forums OR
- It was used in an actual breach (high confidence of active exploitation)
- Set "exploited_by" to reflect Intel471 source (e.g., "Ransomware groups (Intel471 breach report)")
- Increase priority - these are actively weaponized vulnerabilities
"""
            
            if intel471_breach_summary:
                intel471_context += f"""
Recent Breach Intelligence from Intel471 (peer organizations):
{json.dumps(intel471_breach_summary[:5], indent=2)}

Use this to provide context in the executive summary about:
- What attack vectors are working against similar organizations
- Industry breach trends
- Common compromise methods
"""
            
            if intel471_actor_activity:
                intel471_context += f"""
Threat Actor Activity from Intel471 Underground:
{json.dumps(intel471_actor_activity[:10], indent=2)}

Cross-reference with CrowdStrike actors when possible to provide:
- Combined actor profiles (CrowdStrike TTPs + Intel471 underground activity)
- Specific targeting information
"""
        
        # Build OSINT context if we have articles
        osint_context = ""
        if osint_data:
            osint_articles = []
            for article in osint_data[:15]:
                entry = {
                    "title": article.get('title', 'No title'),
                    "source": article.get('source', 'Unknown'),
                    "url": article.get('url', ''),
                    "summary": article.get('summary', '')[:150]
                }
                if article.get("cves_mentioned"):
                    entry["cves_mentioned"] = article['cves_mentioned']
                osint_articles.append(entry)

            osint_context = f"""
OSINT - CURATED PUBLIC INTELLIGENCE ({len(osint_data)} articles from vetted sources):
{json.dumps(osint_articles, indent=2)}

Use these OSINT articles to:
1. INDUSTRY INCIDENTS (PRIMARY USE): Extract company breaches from article titles
   - Look for patterns like "Company X breach", "Organization Y hacked", "Ransomware hits Z"
   - Be generous with extraction - even partial company names are valuable
   - Example: "GitHub confirms data breach" → organization: "GitHub", incident_type: "Breach"
   - These go in industry_incidents array with osint_citation_number
2. Provide additional context for CVEs or threat actors mentioned
3. Identify emerging threats not yet in commercial feeds
4. Track peer incidents (company breaches) for Industry Incidents section
5. ONLY include articles in osint_sources_used if you actually reference them in your analysis
6. Do NOT list all 30 articles - be selective and only cite those that add value
"""

        return f"""Analyze this threat intelligence data and provide a comprehensive report.

REPORT FOCUS - THREAT INTELLIGENCE (NO ENVIRONMENT DATA):
You are analyzing threat intelligence for a biotechnology/genomics/manufacturing organization.
This is a THREAT INTELLIGENCE report, NOT a vulnerability management report.

KEY PRINCIPLES:
- Focus on threat intelligence collected in the past 7 days
- Report on currently exploited vulnerabilities and active threat actors
- Include CVEs in CISA KEV catalog (shows ongoing exploitation relevance)
- Include CVEs mentioned in Intel471/CrowdStrike/OSINT data from this week
- DO NOT require Rapid7 exposure data - this is threat intelligence, not vulnerability management
- ALWAYS mention peer incidents in executive summary - leadership cares about real-world breaches
- Extract and highlight company breaches from OSINT - these show the active threat landscape
- This report helps leadership understand current threats in the wild

DATA SUMMARY (7-DAY COLLECTION WINDOW):
- CVEs: {len(cve_data)} records (from NVD - published in past 7 days)
- Intel471 Threats: {len(intel471_data)} records (underground intelligence, breach reports from past 7 days)
- CrowdStrike APT Activity: {len(crowdstrike_data)} records (threat actor activity from past 7 days)
- ThreatQ Indicators: {len(threatq_data)} records
- OSINT Articles: {len(osint_data)} records (public breach news from past 7 days)
{intel471_context}
{osint_context}

RAW DATA:
{json.dumps(data_summary, indent=2)}

Please provide your analysis in the following JSON format:
{{
  "executive_summary": "2-3 paragraph summary highlighting the most critical threats from intelligence sources. 
  
  MUST INCLUDE:
  (1) Threat actors targeting our sector from Intel471/CrowdStrike
  (2) Exploited vulnerabilities from CISA KEV / threat intelligence
  (3) Industry peer incidents - ALWAYS mention key breaches from the industry_incidents array by company name (e.g., 'This week saw major breaches at Carnival Corporation (6M records) and Charter Communications (13M records), demonstrating ongoing targeting of large enterprises.')
  
  If referencing OSINT intelligence, add inline citations like [1], [2] matching the osint_sources_used array. DO NOT reference source names directly - use citations. Make peer incidents prominent - they show real-world impact and active threat landscape.",
  "top_threats": [
    {{
      "threat": "Description of threat (from intelligence sources)",
      "priority": "P1/P2/P3",
      "justification": "Why this is prioritized (threat actor activity, exploitation evidence, peer incidents)"
    }}
  ],
  "cve_analysis": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "severity": "Critical/High/Medium/Low",
      "description": "Brief technical description of the vulnerability",
      "impact": "Potential impact on genomics/biotech/manufacturing operations",
      "affected_product": "Vendor Product Name (e.g., 'WordPress Plugin: contact-form-7', 'Microsoft Exchange Server', 'Fortinet FortiOS')",
      "actively_exploited": true/false,
      "in_cisa_kev": true/false,
      "targeted_by_actors": "REQUIRED if actively exploited: List specific threat actors exploiting this CVE from Intel471 or CrowdStrike data (e.g., 'APT28', 'Lazarus Group', 'FIN7'). Leave empty string if no actor targeting is known.",
      "exploited_by": "Source of exploitation evidence (e.g., 'CISA KEV', 'Ransomware groups (Intel471)', 'Active exploitation (CrowdStrike)', 'Unknown')",
      "source_citations": ["CISA KEV", "Intel471", "CrowdStrike", "NVD"] // Array listing which APIs provided intelligence for this CVE. Used to build References section.
    }}
  ],
  "apt_activity": [
    {{
      "actor": "Threat actor name",
      "country": "Country of origin",
      "motivation": "Primary motivation",
      "ttps": ["Generic kill chain phase or technique description - NOTE: Neither Intel471 nor CrowdStrike provide MITRE ATT&CK technique IDs"],
      "relevance": "Why this matters to genomics/biotech/manufacturing",
      "what_to_monitor": "Specific indicators and detection recommendations (e.g., 'Monitor for PowerShell activity; Watch for connections to Asia-Pacific regions; Scan for credential harvesting')",
      "intel471_activity": "If Intel471 provided underground activity for this actor, include it here with REPORT UID (e.g., 'Intel471 Report abc123: Actor selling access to biotech networks on underground forum')",
      "intel471_report_uid": "REQUIRED if intel471_activity is provided: The exact UID from Intel471 data (e.g., 'abc123-def456-ghi789')",
      "crowdstrike_activity": "If CrowdStrike provided detection or targeting data for this actor, include it here",
      "source_citations": ["Intel471", "CrowdStrike"] // Array listing which APIs provided intelligence for this actor. Used to build References section.
    }}
  ],
  "recommendations": [
    "Specific, actionable recommendation 1",
    "Specific, actionable recommendation 2",
    "Specific, actionable recommendation 3",
    "Specific, actionable recommendation 4",
    "Specific, actionable recommendation 5"
  ],
  "industry_incidents": [
    {{
      "organization": "REQUIRED: EXACT victim company/organization name. MUST be specific like 'Morrison & Foerster LLP', 'City Hospital', 'Acme Manufacturing'. 
                      FORBIDDEN: Generic terms like 'Healthcare Sector', 'US Law Firms', 'Life sciences companies', 'Biotech firms', 'Multiple organizations'.
                      FORBIDDEN: Breach aggregation sites like 'Databreach+' or descriptions like 'site operated by X'.
                      If the Intel471 or OSINT source does NOT name the specific victim, do NOT include this incident.",
      "incident_type": "Ransomware/Breach/Data Leak/DDoS/Supply Chain",
      "date": "YYYY-MM-DD from Intel471 breach alert publish date or OSINT article date",
      "source": "Intel471 or Publication name (e.g., 'BleepingComputer')",
      "osint_citation_number": 1  // Only for OSINT incidents - match to osint_sources_used array. Omit for Intel471.
    }}
  ],
  "osint_sources_used": [
    {{
      "title": "Full article title for peer incident tracking",
      "url": "https://example.com/article",
      "source": "Publication name (e.g., 'BleepingComputer', 'SecurityWeek')",
      "relevance": "Brief note on why this source was relevant (1 sentence)",
      "date": "Article publish date if available",
      "citation_number": 1
    }}
  ]
}}

CRITICAL - OSINT Source Selection and Usage:
- ONLY include articles in osint_sources_used if you ACTUALLY REFERENCE them in your analysis
- DO NOT include all 30 articles - be highly selective (aim for 5-10 max)
- Each article must be ACTIVELY USED for one of these purposes:
  1. Industry incident extraction (company breach mentioned in executive summary or incidents table)
  2. CVE context (article discusses exploitation of a specific CVE you're analyzing)
  3. Threat actor context (article provides intelligence about an APT group you're profiling)
- If you list an OSINT source, it MUST appear as a citation [1], [2] in:
  * Executive summary text (inline citations)
  * Industry incidents table (osint_citation_number column)
  * CVE description or context (if article discusses that CVE)
- WRONG: Listing 7 OSINT sources but none are cited anywhere in the report
- RIGHT: Listing 5 OSINT sources, all cited in executive summary or incidents table
- If an article provides no unique value or you don't reference it, DO NOT include it in osint_sources_used

CRITICAL - Industry Incidents (Peer Breaches):
- BE COMPREHENSIVE: Extract ALL breaches you can find - aim for 10-20 incidents per week
- Include ALL breach incidents from Intel471 breach alerts (even if not biotech-specific)
- Intel471 breach alerts show real victim organizations under attack - these are HIGH VALUE for peer context
- Also include EVERY specific company breach from OSINT articles (must name actual victim organization)
- Review ALL OSINT articles carefully - breach news is spread across multiple sources
- For Intel471 breaches: set source="Intel471", omit osint_citation_number
- For OSINT breaches: set source="Publication name", include osint_citation_number
- DO NOT include generic threats like "Healthcare Sector" or "US Law Firms" - must be named victims
- If NO specific victim organizations are named in Intel471 or OSINT this week, return EMPTY array: []
- DO NOT create placeholder entries like "No organizations reported" - just use empty array
- Typical weekly report should have 10-20 peer incidents total from Intel471 + OSINT
- CONSISTENCY: Extract the same incidents every time - don't randomly skip some breaches

HOW TO EXTRACT BREACH VICTIMS FROM OSINT:
- Look for company/organization names in article titles and URLs
- Common patterns: "Company X suffers breach", "Ransomware hits Organization Y", "Hackers breach Company Z"
- Extract the organization name from the title - be generous, even partial names are valuable
- REAL EXAMPLES from May 2026 OSINT (these ARE in your data):
  * "Carnival Cruise confirms data breach affecting nearly 6 million people" → organization: "Carnival Corporation", incident_type: "Breach", date: "2026-05-28"
  * "Charter confirms data breach after ShinyHunters extortion threat" → organization: "Charter Communications", incident_type: "Breach", date: "2026-05-26"
  * "GitHub Breach 2026: Poisoned VS Code Extension Stole 3,800 Internal Repositories" → organization: "GitHub", incident_type: "Breach", date: "2026-05-20"
  * "Qilin Hit Covenant Health Hospitals for 480K Records" → organization: "Covenant Health", incident_type: "Ransomware", date: "2026-05-26"
- If you can identify ANY company/organization name from the article title, include it
- Don't be overly strict - extract the company name even if you don't have all details
- Better to include a breach than skip it - peer incident awareness is CRITICAL VALUE

FILTERING RULES FOR CVE_ANALYSIS:
- Include CVEs that have current exploitation relevance:
  * Currently in CISA KEV catalog (regardless of when added)
  * Mentioned in Intel471 reports collected in the past 7 days
  * Associated with threat actors active in CrowdStrike data from the past 7 days
  * Discussed as actively exploited in OSINT articles from the past 7 days
  * High severity (Critical/High) with public exploit code available
- Prioritize CVEs with multiple exploitation indicators (KEV + actor targeting, KEV + OSINT, etc.)
- Focus on CVEs that pose current risk, even if exploitation evidence is not brand new
- Limit to top 15-20 most critical CVEs based on severity, exploitation status, and threat actor interest
- Include CVEs published in the past 7 days if they show early exploitation signals

IMPORTANT: Do NOT include a "statistics" field - statistics are calculated deterministically from the CVE data after your analysis.

OSINT Citation Rules:
- Use SHORT reference titles (2-4 words max), not full article titles
- Example: "GitHub Breach" not "GitHub Confirms Breach, 4K Internal Repos Stolen"
- When you reference OSINT in the executive_summary, add [1], [2] inline citations
- Assign citation_number sequentially starting from 1
- Only mention specific OSINT articles by name if you're citing them (list them in osint_sources_used)
- The Resources section will automatically list all data sources - you don't need to reference them

CRITICAL - AVOID VAGUE SOURCE REFERENCES:
- DO NOT write "Refer to Rapid7 for remediation guidance" or "Refer to OSINT sources"
- DO NOT write "as highlighted by OSINT and Microsoft Threat Intelligence" in the executive summary
- Be specific: Instead of "Refer to X", say exactly what to do (e.g., "Patch systems immediately", "Review firewall rules", "Enable MFA")

IMPORTANT CVE Analysis Guidelines:
- Include ALL CVEs from the exposure map above - they are all detected in the environment
- Focus on accurate severity assessment and impact analysis
- The report will automatically group similar technologies (e.g., WordPress plugins) for readability
- Priority scoring is no longer used - focus on clear severity and impact descriptions
- Do NOT filter CVEs - include everything from the exposure map

Exposure Field Guidelines:
- Use the EXACT exposure string from the exposure map (e.g., "1 system", "7 systems")
- DO NOT modify or reformat these values - copy them exactly as shown
- All CVEs in your analysis must have exposure data

Weeks Detected Guidelines:
- Set weeks_detected to 1 for all CVEs by default (new this week)
- If a CVE appears to be older or recurring based on publish date or context, use a higher value
- The report will highlight CVEs with weeks_detected >= 3 as persistent issues

Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks.

Do not use Hyphens."""

    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """
        Robustly parse the AI response into a dictionary, handling control
        characters, truncated JSON, missing delimiters, and other common
        issues from large language model output.
        """
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        # Attempt 1: direct parse
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Attempt 2: strip control characters (except newline/tab used in formatting)
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', response_text)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Attempt 3: fix unescaped newlines/tabs inside JSON string values
        # Replace literal newlines inside strings with \\n
        fixed = self._escape_strings_in_json(cleaned)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        # Attempt 4: fix missing commas between } and { or } and "
        fixed2 = re.sub(r'\}\s*\{', '},{', fixed)
        fixed2 = re.sub(r'\}\s*"', '},"', fixed2)
        fixed2 = re.sub(r'"\s*\{', '",{', fixed2)
        # Missing comma between "value" and "key"
        fixed2 = re.sub(r'"\s*\n\s*"', '","', fixed2)
        try:
            return json.loads(fixed2)
        except json.JSONDecodeError:
            pass

        # Attempt 5: truncated JSON -- try to close open structures
        repaired = self._repair_truncated_json(fixed2)
        if repaired:
            try:
                return json.loads(repaired)
            except json.JSONDecodeError:
                pass

        # Attempt 6: extract the largest parseable JSON object from the text
        result = self._extract_json_object(cleaned)
        if result is not None:
            return result

        logger.error("All JSON parse attempts failed")
        logger.error(f"Response text (first 500 chars): {response_text[:500]}")
        return None

    @staticmethod
    def _escape_strings_in_json(text: str) -> str:
        """Escape literal newlines and tabs that appear inside JSON string values."""
        result = []
        in_string = False
        escape_next = False
        for ch in text:
            if escape_next:
                result.append(ch)
                escape_next = False
                continue
            if ch == '\\' and in_string:
                result.append(ch)
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                result.append(ch)
                continue
            if in_string:
                if ch == '\n':
                    result.append('\\n')
                    continue
                if ch == '\r':
                    result.append('\\r')
                    continue
                if ch == '\t':
                    result.append('\\t')
                    continue
            result.append(ch)
        return ''.join(result)

    @staticmethod
    def _repair_truncated_json(text: str) -> str | None:
        """
        If the AI output was cut off mid-JSON, close any open braces/brackets
        and truncate the last incomplete value.
        """
        if not text or text[-1] in ('}', ']'):
            return None

        # Strip trailing partial value (after last complete comma-separated item)
        truncated = text
        for end_marker in ['},', '"],', '",', 'null,', 'true,', 'false,']:
            idx = truncated.rfind(end_marker)
            if idx != -1:
                candidate = truncated[:idx + len(end_marker) - 1]  # drop trailing comma
                # Count open/close braces and brackets
                open_braces = candidate.count('{') - candidate.count('}')
                open_brackets = candidate.count('[') - candidate.count(']')
                if open_braces >= 0 and open_brackets >= 0:
                    candidate += ']' * open_brackets + '}' * open_braces
                    return candidate

        return None

    @staticmethod
    def _extract_json_object(text: str) -> dict | None:
        """
        Find the first top-level { and attempt to parse progressively
        larger substrings until we get the largest valid JSON object.
        """
        start = text.find('{')
        if start == -1:
            return None

        best = None
        depth = 0
        in_string = False
        escape_next = False

        for i in range(start, len(text)):
            ch = text[i]
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            best = parsed
                    except json.JSONDecodeError:
                        pass
                    # Keep going in case there's a larger enclosing object
                    # but typically the first complete match is it
                    if best is not None:
                        return best

        return best

    def _fill_gaps_from_backup(
        self,
        analysis_result: Dict[str, Any],
        cve_data: List[Dict],
        rapid7_data: List[Dict],
        rapid7_scans_data: List[Dict] = None,
        kev_lookup: Dict[str, dict] = None,
        epss_lookup: Dict[str, dict] = None,
        intel471_data: List[Dict] = None,
        crowdstrike_data: List[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Patch AI analysis results with Rapid7/NVD/KEV/EPSS backup data where
        the AI left gaps (N/A exposure, missing product names, etc.).
        """
        rapid7_scans_data = rapid7_scans_data or []
        kev_lookup = kev_lookup or {}
        epss_lookup = epss_lookup or {}
        rapid7_cve_map = {}
        rapid7_scan_lookup = {}
        if rapid7_scans_data and len(rapid7_scans_data) > 0:
            scan_summary = rapid7_scans_data[0] if isinstance(rapid7_scans_data[0], dict) else {}
            for cve_id, info in scan_summary.get("cve_exposure_map", {}).items():
                if isinstance(info, dict):
                    rapid7_cve_map[cve_id] = info.get("exposure", f"{info.get('asset_count', 0)} systems")
                    rapid7_scan_lookup[cve_id] = info

        # Build NVD lookup
        nvd_lookup = {}
        for cve in cve_data:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                nvd_lookup[cve_id] = cve

        # Build Rapid7 vuln definitions lookup
        rapid7_vuln_lookup = {}
        if rapid7_data and len(rapid7_data) > 0:
            r7_summary = rapid7_data[0] if isinstance(rapid7_data[0], dict) else {}
            for vuln in r7_summary.get("top_vulnerabilities", []):
                for cve_id in vuln.get("cve_ids", []):
                    rapid7_vuln_lookup[cve_id] = vuln

        if not rapid7_cve_map and not nvd_lookup:
            return analysis_result

        gaps_filled = 0
        cve_analysis = analysis_result.get("cve_analysis", [])

        for cve_entry in cve_analysis:
            cve_id = cve_entry.get("cve_id", "")
            if not cve_id:
                continue

            nvd = nvd_lookup.get(cve_id, {})
            r7_vuln = rapid7_vuln_lookup.get(cve_id, {})
            r7_scan = rapid7_scan_lookup.get(cve_id, {})

            # Fill exposure if AI left it blank or N/A
            exposure = cve_entry.get("exposure", "N/A")
            if exposure in ("N/A", "", None, "Unknown", "unknown"):
                backup_exposure = rapid7_cve_map.get(cve_id)
                if backup_exposure:
                    cve_entry["exposure"] = backup_exposure
                    gaps_filled += 1

            # Fill affected_product if AI left it blank
            product = cve_entry.get("affected_product", "N/A")
            product_lower = (product or "").lower()
            needs_product = (
                product in ("N/A", "", None)
                or product_lower.startswith("unknown")
                or "vendor product" in product_lower
                or "see asset" in product_lower
            )
            if needs_product:
                backup_product = (
                    build_affected_product_from_kev(cve_id, kev_lookup)
                    or nvd.get("affected_product")
                    or self._clean_rapid7_title(r7_scan.get("title", ""))
                    or r7_vuln.get("title", "")
                    or self._extract_product_from_description(
                        nvd.get("description", "") or r7_vuln.get("description", "")
                    )
                )
                if backup_product and backup_product not in ("N/A", ""):
                    cve_entry["affected_product"] = backup_product
                    gaps_filled += 1

            # Fill exploited_by from KEV/EPSS/Rapid7/NVD (in priority order)
            exploited_by = cve_entry.get("exploited_by", "")
            exploited_lower = (exploited_by or "").lower()
            needs_exploit = (
                exploited_by in ("", None)
                or exploited_lower in ("unknown", "none known", "n/a", "none", "no")
                or exploited_lower.startswith("none")
                or exploited_lower.startswith("unknown")
                or exploited_lower.startswith("no known")
            )
            if needs_exploit:
                # First try KEV/EPSS
                kev_epss_result = build_exploited_by(cve_id, kev_lookup, epss_lookup)
                if kev_epss_result:
                    cve_entry["exploited_by"] = kev_epss_result
                    if "CISA KEV" in kev_epss_result:
                        cve_entry["exploited"] = True
                        cve_entry["in_cisa_kev"] = True
                    gaps_filled += 1
                # Then try Rapid7
                elif r7_vuln.get("exploitable"):
                    kits = r7_vuln.get("malware_kits_count", 0)
                    exploits = r7_vuln.get("exploits_count", 0)
                    if kits:
                        cve_entry["exploited_by"] = f"Malware kits ({kits} known)"
                    elif exploits:
                        cve_entry["exploited_by"] = f"Public exploits ({exploits} known)"
                    else:
                        cve_entry["exploited_by"] = "Exploit available"
                    gaps_filled += 1
                # Finally check NVD data for enrichment fields
                elif nvd.get("exploited") or nvd.get("in_cisa_kev"):
                    cve_entry["exploited"] = nvd.get("exploited", False)
                    cve_entry["in_cisa_kev"] = nvd.get("in_cisa_kev", False)
                    cve_entry["exploited_by"] = nvd.get("exploited_by", "Unknown")
                    if nvd.get("known_ransomware"):
                        cve_entry["known_ransomware"] = nvd.get("known_ransomware")
                    gaps_filled += 1
            else:
                # Even if exploited_by exists, ensure boolean flags are set
                if "CISA KEV" in exploited_by:
                    cve_entry["exploited"] = True
                    cve_entry["in_cisa_kev"] = True

            # Fill weeks_detected from Rapid7 scan 'added' date
            weeks = cve_entry.get("weeks_detected", 1)
            if weeks in (1, "1", "New", "new", None):
                scan_weeks = r7_scan.get("weeks_detected")
                if scan_weeks and scan_weeks > 1:
                    cve_entry["weeks_detected"] = scan_weeks
                    gaps_filled += 1

        # Recompute priority using weighted scoring
        apt_cve_map = self._build_apt_cve_map(
            intel471_data or [], crowdstrike_data or [],
        )
        for cve_entry in cve_analysis:
            label, num_score, justification = self.compute_priority(
                cve_entry, kev_lookup or {}, epss_lookup or {}, apt_cve_map,
            )
            cve_entry["priority"] = label
            cve_entry["priority_score"] = num_score
            cve_entry["priority_justification"] = justification

        priority_order = {"P1": 0, "P2": 1, "P3": 2}
        cve_analysis.sort(key=lambda x: (
            priority_order.get(x.get("priority", "P3"), 3),
            -x.get("priority_score", 0),
            -self._extract_count(x.get("exposure", "0")),
        ))

        # Recount after re-scoring
        stats = analysis_result.get("statistics", {})
        if stats:
            stats["p1_count"] = sum(1 for c in cve_analysis if c.get("priority") == "P1")
            stats["p2_count"] = sum(1 for c in cve_analysis if c.get("priority") == "P2")
            stats["p3_count"] = sum(1 for c in cve_analysis if c.get("priority") == "P3")

        # Filter: only keep CVEs that exist in Rapid7 scans
        if rapid7_cve_map:
            original_count = len(cve_analysis)
            cve_analysis = [c for c in cve_analysis if c.get("cve_id") in rapid7_cve_map]
            filtered = original_count - len(cve_analysis)
            if filtered > 0:
                logger.info(f"Filtered out {filtered} CVEs not detected in Rapid7 scans")
            analysis_result["cve_analysis"] = cve_analysis

        if gaps_filled > 0:
            logger.info(f"Filled {gaps_filled} gaps in AI analysis from Rapid7/NVD backup data")

        return analysis_result

    def _get_default_analysis(
        self,
        cve_data: List[Dict],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        threatq_data: List[Dict],
        rapid7_data: List[Dict],
        rapid7_scans_data: List[Dict] = None,
        kev_lookup: Dict[str, dict] = None,
        epss_lookup: Dict[str, dict] = None,
    ) -> Dict[str, Any]:
        """
        Generate a default analysis structure when AI analysis fails.
        Uses Rapid7 scan data to filter to only detected CVEs and 
        cross-references with NVD data for product names and severity.
        """
        rapid7_scans_data = rapid7_scans_data or []
        kev_lookup = kev_lookup or {}
        epss_lookup = epss_lookup or {}
        
        # Build exposure map and scan enrichment from Rapid7 scans
        rapid7_cve_map = {}
        rapid7_scan_lookup = {}
        if rapid7_scans_data and len(rapid7_scans_data) > 0:
            scan_summary = rapid7_scans_data[0] if isinstance(rapid7_scans_data[0], dict) else {}
            cve_exposure_map = scan_summary.get("cve_exposure_map", {})
            for cve_id, exposure_info in cve_exposure_map.items():
                if isinstance(exposure_info, dict):
                    rapid7_cve_map[cve_id] = exposure_info.get("exposure", f"{exposure_info.get('asset_count', 0)} systems")
                    rapid7_scan_lookup[cve_id] = exposure_info
        
        logger.info(f"Default analysis: {len(rapid7_cve_map)} CVEs from Rapid7 scans")
        
        # Build NVD lookup for product names, severity, descriptions
        nvd_lookup = {}
        for cve in cve_data:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                nvd_lookup[cve_id] = cve
        
        logger.info(f"Default analysis: {len(nvd_lookup)} CVEs in NVD data for enrichment")
        
        # Build Rapid7 vulnerability definitions lookup for extra product info
        rapid7_vuln_lookup = {}
        if rapid7_data and len(rapid7_data) > 0:
            rapid7_summary = rapid7_data[0] if isinstance(rapid7_data[0], dict) else {}
            for vuln in rapid7_summary.get("top_vulnerabilities", []):
                for cve_id in vuln.get("cve_ids", []):
                    rapid7_vuln_lookup[cve_id] = vuln
        
        # Build CVE analysis from Rapid7-detected CVEs only
        cve_analysis = []
        if rapid7_cve_map:
            for cve_id, exposure_string in rapid7_cve_map.items():
                nvd_info = nvd_lookup.get(cve_id, {})
                rapid7_vuln = rapid7_vuln_lookup.get(cve_id, {})
                r7_scan = rapid7_scan_lookup.get(cve_id, {})
                
                # Get affected product from KEV, NVD CPE, scan title, or Rapid7 vuln title
                affected_product = (
                    build_affected_product_from_kev(cve_id, kev_lookup)
                    or nvd_info.get("affected_product")
                    or self._clean_rapid7_title(r7_scan.get("title", ""))
                    or rapid7_vuln.get("title", "")
                    or self._extract_product_from_description(
                        nvd_info.get("description", "") or rapid7_vuln.get("description", "")
                    )
                    or "Unknown"
                )
                if affected_product == "N/A":
                    affected_product = "Unknown"
                
                severity = nvd_info.get("severity", rapid7_vuln.get("severity", "HIGH"))
                exploited = nvd_info.get("exploited", rapid7_vuln.get("exploitable", False))
                description = nvd_info.get("description", rapid7_vuln.get("description", ""))[:200]

                # Derive exploited_by from KEV/EPSS first, then Rapid7
                kev_epss_result = build_exploited_by(cve_id, kev_lookup, epss_lookup)
                if kev_epss_result:
                    exploited_by = kev_epss_result
                    if "CISA KEV" in kev_epss_result:
                        exploited = True
                elif rapid7_vuln.get("exploitable"):
                    kits = rapid7_vuln.get("malware_kits_count", 0)
                    exploits = rapid7_vuln.get("exploits_count", 0)
                    if kits:
                        exploited_by = f"Malware kits ({kits} known)"
                    elif exploits:
                        exploited_by = f"Public exploits ({exploits} known)"
                    else:
                        exploited_by = "Exploit available"
                else:
                    exploited_by = "None known"
                
                cve_analysis.append({
                    "cve_id": cve_id,
                    "priority": "P3",
                    "severity": severity,
                    "exploited": exploited,
                    "description": description,
                    "impact": "Detected in environment - requires assessment",
                    "affected_product": affected_product,
                    "exploited_by": exploited_by,
                    "exposure": exposure_string,
                    "weeks_detected": r7_scan.get("weeks_detected", 1),
                })
            
            # Weighted priority scoring
            apt_cve_map = self._build_apt_cve_map(intel471_data, crowdstrike_data)
            for cve_entry in cve_analysis:
                label, num_score, justification = self.compute_priority(
                    cve_entry, kev_lookup, epss_lookup, apt_cve_map,
                )
                cve_entry["priority"] = label
                cve_entry["priority_score"] = num_score
                cve_entry["priority_justification"] = justification

            priority_order = {"P1": 0, "P2": 1, "P3": 2}
            cve_analysis.sort(key=lambda x: (
                priority_order.get(x.get("priority", "P3"), 3),
                -x.get("priority_score", 0),
                -self._extract_count(x.get("exposure", "0")),
            ))
        
        total_cves = len(cve_analysis)
        p1_count = sum(1 for c in cve_analysis if c.get("priority") == "P1")
        p2_count = sum(1 for c in cve_analysis if c.get("priority") == "P2")
        p3_count = sum(1 for c in cve_analysis if c.get("priority") == "P3")
        critical_count = sum(1 for c in cve_analysis if c.get("severity") in ("CRITICAL", "Critical"))
        high_count = sum(1 for c in cve_analysis if c.get("severity") in ("HIGH", "High", "Severe"))
        exploited_count = sum(1 for c in cve_analysis if c.get("exploited"))
        
        if total_cves == 0:
            executive_summary = """No vulnerabilities were detected in our environment during this reporting period.
Continue monitoring for emerging threats and ensure all security controls remain active."""
        else:
            executive_summary = f"""This week's threat intelligence analysis identified {total_cves} vulnerabilities \
detected in our environment through Rapid7 InsightVM scans. Of these, {p1_count} are rated P1 (critical/actively exploited), \
{p2_count} are P2, and {p3_count} are P3. Immediate attention is recommended for any P1 items.

Note: AI-powered analysis was unavailable for this report. The vulnerability data below is sourced directly from \
Rapid7 scan results cross-referenced with NVD severity ratings. Only CVEs detected in our environment are included."""

        return {
            "executive_summary": executive_summary,
            "top_threats": [
                {
                    "threat": f"{total_cves} vulnerabilities detected in environment via Rapid7 scans",
                    "priority": "P1" if p1_count > 0 else "P2",
                    "justification": f"{p1_count} critical, {exploited_count} actively exploited"
                }
            ],
            "cve_analysis": cve_analysis,
            "apt_activity": [
                {
                    "actor": actor.get("actor_name", "Unknown Actor"),
                    "country": actor.get("country", "Unknown"),
                    "motivation": (
                        actor.get("motivations", ["Unknown"])[0]
                        if isinstance(actor.get("motivations"), list) and actor.get("motivations")
                        else "Unknown"
                    ),
                    "ttps": actor.get("ttps", [])[:5],
                    "relevance": "Requires manual assessment"
                }
                for actor in crowdstrike_data[:5]
            ] if crowdstrike_data else [],
            "recommendations": [
                "Review P1 vulnerabilities immediately and initiate patching within 24-48 hours",
                "Validate Rapid7 scan coverage to ensure all critical assets are being assessed",
                "Cross-reference detected CVEs with CISA KEV catalog for exploitation status",
                "Prioritize remediation based on exposure count (higher count = more risk)",
                "Schedule follow-up analysis once AI analysis is available for deeper threat correlation"
            ],
            "statistics": {
                "total_cves": total_cves,
                "critical_count": critical_count,
                "high_count": high_count,
                "exploited_count": exploited_count,
                "apt_groups": len([item for item in crowdstrike_data if item.get("type") == "actor"]),
                "p1_count": p1_count,
                "p2_count": p2_count,
                "p3_count": p3_count
            }
        }

    @staticmethod
    def _extract_count(exposure_str: str) -> int:
        """Extract numeric count from exposure string like '7 systems'."""
        try:
            return int(exposure_str.split()[0])
        except (ValueError, IndexError):
            return 0

    @staticmethod
    def compute_priority(
        cve_entry: Dict[str, Any],
        kev_lookup: Dict[str, dict],
        epss_lookup: Dict[str, dict],
        apt_cve_map: Dict[str, str],
    ) -> tuple:
        """
        Deterministic weighted priority scoring (0-100 scale).

        Weights:
            CVSS severity   0-30
            EPSS score       0-30
            CISA KEV         0-20
            Threat actor     0-15
            Exposure         0-5

        Returns (priority_label, numeric_score, justification_string).
        """
        cve_id = cve_entry.get("cve_id", "")
        score = 0
        factors = []

        # --- CVSS severity (0-30) ---
        severity = (cve_entry.get("severity") or "").upper()
        cvss_raw = cve_entry.get("cvss_score")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (TypeError, ValueError):
            cvss = None

        if cvss is not None:
            if cvss >= 9.0:
                score += 30
                factors.append(f"CVSS {cvss}")
            elif cvss >= 7.0:
                score += 20
                factors.append(f"CVSS {cvss}")
            elif cvss >= 4.0:
                score += 10
                factors.append(f"CVSS {cvss}")
            else:
                score += 5
                factors.append(f"CVSS {cvss}")
        else:
            if severity in ("CRITICAL",):
                score += 30
                factors.append("Critical severity")
            elif severity in ("HIGH", "SEVERE"):
                score += 20
                factors.append("High severity")
            elif severity in ("MEDIUM", "MODERATE"):
                score += 10
                factors.append("Medium severity")
            else:
                score += 5
                factors.append(severity or "Unknown severity")

        # --- EPSS (0-30) ---
        epss_entry = epss_lookup.get(cve_id)
        if epss_entry:
            epss_score = epss_entry["epss"]
            if epss_score >= 0.6:
                score += 30
                factors.append(f"EPSS {epss_score:.0%}")
            elif epss_score >= 0.2:
                score += 20
                factors.append(f"EPSS {epss_score:.0%}")
            elif epss_score >= 0.04:
                score += 10
                factors.append(f"EPSS {epss_score:.1%}")
            else:
                score += 3
                factors.append(f"EPSS {epss_score:.2%}")

        # --- CISA KEV (0-20) ---
        kev = kev_lookup.get(cve_id)
        if kev:
            score += 20
            factors.append("CISA KEV")

        # --- Threat actor relevance (0-15) ---
        actor_label = apt_cve_map.get(cve_id)
        if actor_label:
            if "crowdstrike" in actor_label.lower() or "apt" in actor_label.lower():
                score += 15
                factors.append(f"Actor: {actor_label}")
            else:
                score += 10
                factors.append(f"Intel471: {actor_label}")

        # --- Exposure (0-5) ---
        exposure_str = cve_entry.get("exposure", "0")
        try:
            asset_count = int(str(exposure_str).split()[0])
        except (ValueError, IndexError):
            asset_count = 0
        if asset_count >= 5:
            score += 5
            factors.append(f"{asset_count} assets")
        elif asset_count >= 1:
            score += 2
            factors.append(f"{asset_count} asset{'s' if asset_count > 1 else ''}")

        # --- Thresholds ---
        if score >= 60:
            label = "P1"
        elif score >= 30:
            label = "P2"
        else:
            label = "P3"

        justification = "; ".join(factors) + f" [score {score}]"
        return label, score, justification

    @staticmethod
    def _build_apt_cve_map(
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
    ) -> Dict[str, str]:
        """
        Build CVE-ID -> actor-label mapping from Intel471 reports and
        CrowdStrike actor data so the priority scorer can give credit for
        threat-actor association.
        """
        apt_cve_map: Dict[str, str] = {}
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')

        for item in (intel471_data or []):
            actor = item.get("threat_actor", "")
            if not actor or actor == "Unknown":
                actor = item.get("threat_type", "Intel471 report")
            text = item.get("summary", "") + " " + item.get("description", "")
            for cve_id in cve_pattern.findall(text):
                if cve_id not in apt_cve_map:
                    apt_cve_map[cve_id] = actor

        for actor in (crowdstrike_data or []):
            actor_name = actor.get("actor_name", actor.get("name", ""))
            if not actor_name:
                continue
            for field in ("description", "summary", "rich_text_description"):
                text = actor.get(field, "")
                if isinstance(text, str):
                    for cve_id in cve_pattern.findall(text):
                        apt_cve_map[cve_id] = f"{actor_name} (CrowdStrike)"

        return apt_cve_map

    @staticmethod
    def _extract_product_from_description(description: str) -> str:
        """Try to extract product name from CVE description text."""
        if not description:
            return ""
        import re
        patterns = [
            r'^([\w\s]+(?:Server|Client|Browser|Framework|Library|Engine|Platform))',
            r'(?:in|affecting|vulnerability in)\s+([\w\s\.]+?)(?:\s+(?:before|prior|through|allows|via|could))',
        ]
        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                product = match.group(1).strip()
                if len(product) > 3 and len(product) < 50:
                    return product
        return ""

    @staticmethod
    def _clean_rapid7_title(title: str) -> str:
        """
        Clean a Rapid7 vulnerability title into a short product name.

        Rapid7 titles look like:
          "WordPress Plugin: access-demo-importer: CVE-2021-39317: Unrestricted Upload..."
          "7-Zip: CVE-2016-2334: Buffer Overflow"
          "Adobe Acrobat: CVE-2016-0931: Use After Free"

        Returns just the product portion, e.g. "WordPress Plugin: access-demo-importer".
        """
        if not title:
            return ""
        import re
        # Strip the CVE-XXXX-XXXX: portion and everything after it
        cleaned = re.split(r'\s*:\s*CVE-\d{4}-\d+', title)[0].strip()
        if cleaned and len(cleaned) > 2:
            return cleaned
        return title.split(":")[0].strip() if ":" in title else title

    async def analyze_strategic(
        self,
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        breach_data: List[Dict] | None = None,
        illumina_context: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze threat intelligence data for quarterly strategic reports.

        Focuses on geopolitical threats, industry breach landscape, and
        business implications rather than tactical CVE details.

        Args:
            intel471_data: List of threat intelligence from Intel471
            crowdstrike_data: List of APT intelligence from CrowdStrike
            breach_data: Optional list of industry breach incidents
            illumina_context: Current Illumina company context from public sources

        Returns:
            Dictionary containing strategic analysis results
        """
        try:
            logger.info("Starting strategic threat analysis for quarterly report")
            logger.info(
                f"Data counts - Intel471: {len(intel471_data)}, "
                f"CrowdStrike: {len(crowdstrike_data)}, "
                f"Breaches: {len(breach_data) if breach_data else 0}"
            )

            # Build strategic analysis prompt
            strategic_prompt = self._build_strategic_prompt(
                intel471_data, crowdstrike_data, breach_data, illumina_context
            )

            # Create chat history with strategic system prompt
            chat_history = ChatHistory()
            chat_history.add_system_message(STRATEGIC_SYSTEM_PROMPT)
            chat_history.add_user_message(strategic_prompt)

            # Configure execution settings
            settings = AzureChatPromptExecutionSettings(
                response_format={"type": "json_object"},
                temperature=0.1,  # Slightly higher temperature for more variation in breach selection
                seed=789,  # New seed for different selections
            )

            # Get response from GPT
            logger.info("Sending strategic analysis request to Azure OpenAI")
            response = await self.chat_service.get_chat_message_content(
                chat_history=chat_history,
                settings=settings
            )

            # Parse response
            response_text = str(response)
            logger.info("Received strategic analysis response from Azure OpenAI")

            analysis_result = self._parse_response(response_text)

            if analysis_result:
                logger.info("Successfully parsed strategic analysis results")
                
                # Debug: Log if osint_sources_used is present
                osint_sources = analysis_result.get("osint_sources_used", [])
                logger.info(f"AI returned {len(osint_sources)} OSINT sources")
                if osint_sources:
                    logger.info(f"OSINT sources: {osint_sources}")
                else:
                    logger.warning("AI did not return any osint_sources_used - may need prompt adjustment")
                
                # Validate AI output quality
                from src.validation import QuarterlyReportValidator
                validator = QuarterlyReportValidator()
                is_valid = validator.validate(analysis_result, illumina_context)
                
                if not is_valid:
                    logger.error("AI output failed validation checks")
                    logger.error(f"Validation summary: {validator.get_summary()}")
                    # Continue anyway but log the issues
                
                analysis_result = self._fill_strategic_gaps(
                    analysis_result, intel471_data, crowdstrike_data, breach_data
                )
                return analysis_result
            else:
                return self._get_default_strategic_analysis(
                    intel471_data, crowdstrike_data, breach_data
                )

        except Exception as e:
            logger.error(f"Error during strategic analysis: {e}", exc_info=True)
            return self._get_default_strategic_analysis(
                intel471_data, crowdstrike_data, breach_data
            )

    def _fill_strategic_gaps(
        self,
        analysis_result: Dict[str, Any],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        breach_data: List[Dict] | None
    ) -> Dict[str, Any]:
        """
        Patch AI strategic analysis with backup data where the AI left gaps.
        Ensures breach counts, actor counts, and risk assessments are populated.
        """
        breach_data = breach_data or []
        gaps_filled = 0

        # Fill breach_landscape if AI left zeros or missing fields
        bl = analysis_result.get("breach_landscape", {})
        if bl:
            # Check if using old schema (has total_incidents but missing stat_cards)
            if "stat_cards" not in bl and "total_incidents" in bl:
                logger.warning("breach_landscape is old schema, converting to new format")
                # Convert old schema to new schema
                total_incidents = bl.get("total_incidents", 0)
                prev_total = bl.get("prev_total_incidents", 0)
                total_impact = bl.get("total_impact_millions", 0)
                prev_impact = bl.get("prev_total_impact", 0)
                ransomware_count = bl.get("ransomware_count", 0)
                prev_ransomware = bl.get("prev_ransomware", 0)
                records_exposed = bl.get("records_exposed_millions", 0)
                prev_records = bl.get("prev_records", 0)
                
                def calc_pct_change(current, prior):
                    if not prior or prior == 0:
                        return "+0%"
                    try:
                        curr = float(current)
                        prev = float(prior)
                        if prev == 0:
                            return "+0%"
                        change = ((curr - prev) / prev) * 100
                        if change > 0:
                            return f"+{int(change)}%"
                        elif change < 0:
                            return f"{int(change)}%"
                        else:
                            return "0%"
                    except (ValueError, TypeError):
                        return "0%"
                
                # Determine quarter labels
                from datetime import datetime
                today = datetime.now()
                current_q = (today.month - 1) // 3 + 1
                current_year = today.year
                prior_q = current_q - 1 if current_q > 1 else 4
                prior_year = current_year if current_q > 1 else current_year - 1
                
                analysis_result["breach_landscape"] = {
                    "scope_note": f"Publicly disclosed incidents affecting life sciences, pharmaceutical, biotechnology, healthcare, and advanced manufacturing organizations during Q{current_q} {current_year}.",
                    "stat_cards": [
                        {
                            "value": str(total_incidents),
                            "label": "Total Incidents",
                            "prior_label": f"Q{prior_q} {prior_year}",
                            "prior_value": str(prev_total),
                            "change_pct": calc_pct_change(total_incidents, prev_total)
                        },
                        {
                            "value": f"${total_impact}M",
                            "label": "Est. Total Impact",
                            "prior_label": f"Q{prior_q} {prior_year}",
                            "prior_value": f"${prev_impact}M",
                            "change_pct": calc_pct_change(total_impact, prev_impact)
                        },
                        {
                            "value": str(ransomware_count),
                            "label": "Ransomware",
                            "prior_label": f"Q{prior_q} {prior_year}",
                            "prior_value": str(prev_ransomware),
                            "change_pct": calc_pct_change(ransomware_count, prev_ransomware)
                        },
                        {
                            "value": f"{records_exposed}M",
                            "label": "Records Exposed",
                            "prior_label": f"Q{prior_q} {prior_year}",
                            "prior_value": f"{prev_records}M",
                            "change_pct": calc_pct_change(records_exposed, prev_records)
                        }
                    ],
                    "incidents_by_type": analysis_result.get("incidents_by_type", []),
                    "current_quarter_label": f"Q{current_q} {current_year}",
                    "prior_quarter_label": f"Q{prior_q} {prior_year}",
                    "common_factors": analysis_result.get("common_factors", "Analysis pending - manual review of threat data recommended")
                }
                gaps_filled += 1
        elif breach_data:
            # No breach_landscape at all, create minimal one
            from datetime import datetime
            today = datetime.now()
            current_q = (today.month - 1) // 3 + 1
            current_year = today.year
            prior_q = current_q - 1 if current_q > 1 else 4
            prior_year = current_year if current_q > 1 else current_year - 1
            
            analysis_result["breach_landscape"] = {
                "scope_note": f"Publicly disclosed incidents affecting life sciences, pharmaceutical, biotechnology, healthcare, and advanced manufacturing organizations during Q{current_q} {current_year}.",
                "stat_cards": [
                    {"value": "0", "label": "Total Incidents", "prior_label": f"Q{prior_q} {prior_year}", "prior_value": "0", "change_pct": "0%"},
                    {"value": "$0M", "label": "Est. Total Impact", "prior_label": f"Q{prior_q} {prior_year}", "prior_value": "$0M", "change_pct": "0%"},
                    {"value": "0", "label": "Ransomware", "prior_label": f"Q{prior_q} {prior_year}", "prior_value": "0", "change_pct": "0%"},
                    {"value": "0M", "label": "Records Exposed", "prior_label": f"Q{prior_q} {prior_year}", "prior_value": "0M", "change_pct": "0%"}
                ],
                "incidents_by_type": [],
                "current_quarter_label": f"Q{current_q} {current_year}",
                "prior_quarter_label": f"Q{prior_q} {prior_year}",
                "common_factors": "Analysis pending - manual review of threat data recommended"
            }
            gaps_filled += 1

        # Fill risk_assessment if completely missing
        if not analysis_result.get("risk_assessment"):
            analysis_result["risk_assessment"] = {
                "nation_state": "HIGH",
                "nation_state_trend": "Unchanged",
                "ransomware": "HIGH",
                "ransomware_trend": "Unchanged",
                "supply_chain": "MEDIUM",
                "supply_chain_trend": "Unchanged",
                "insider": "LOW",
                "insider_trend": "Unchanged"
            }
            gaps_filled += 1

        # Fill geopolitical_threats if missing or empty
        geo = analysis_result.get("geopolitical_threats", [])
        
        # Handle both old dict format and new list format
        if isinstance(geo, dict):
            # Old format - convert to new format or skip
            logger.warning("geopolitical_threats is old dict format, converting to list")
            china_count = len([a for a in crowdstrike_data if self._is_china_related(a)])
            russia_count = len([a for a in crowdstrike_data if self._is_russia_related(a)])
            nk_count = len([a for a in crowdstrike_data if self._is_nk_related(a)])
            
            # Convert old dict to new list format
            converted_list = []
            if geo.get("china"):
                converted_list.append({
                    "name": "China",
                    "level": "HIGH",
                    "vector": "Espionage — IP theft",
                    "exposure": "CRITICAL",
                    "relevance": [geo["china"].get("strategic_context", "")],
                    "activity": [geo["china"].get("activity", "")],
                    "risk": [geo["china"].get("implications", "")]
                })
            if geo.get("russia"):
                converted_list.append({
                    "name": "Russia",
                    "level": "HIGH",
                    "vector": "Ransomware — Disruption",
                    "exposure": "HIGH",
                    "relevance": [geo["russia"].get("strategic_context", "")],
                    "activity": [geo["russia"].get("activity", "")],
                    "risk": [geo["russia"].get("implications", "")]
                })
            if geo.get("north_korea"):
                converted_list.append({
                    "name": "North Korea",
                    "level": "MEDIUM",
                    "vector": "Financial theft — Dual-use IP",
                    "exposure": "MEDIUM",
                    "relevance": [geo["north_korea"].get("strategic_context", "")],
                    "activity": [geo["north_korea"].get("activity", "")],
                    "risk": [geo["north_korea"].get("implications", "")]
                })
            
            analysis_result["geopolitical_threats"] = converted_list
            gaps_filled += 1
        elif not geo:
            # Empty list - provide defaults
            china_count = len([a for a in crowdstrike_data if self._is_china_related(a)])
            russia_count = len([a for a in crowdstrike_data if self._is_russia_related(a)])
            nk_count = len([a for a in crowdstrike_data if self._is_nk_related(a)])
            analysis_result["geopolitical_threats"] = [
                {
                    "name": "China",
                    "level": "HIGH",
                    "vector": "Espionage — IP theft",
                    "exposure": "CRITICAL",
                    "relevance": ["China designates biotechnology as a strategic priority."],
                    "activity": [f"Observed {china_count} China-linked actor groups this quarter."],
                    "risk": ["Potential IP theft risk for proprietary research."]
                },
                {
                    "name": "Russia",
                    "level": "HIGH",
                    "vector": "Ransomware — Disruption",
                    "exposure": "HIGH",
                    "relevance": ["Russian criminal groups pose significant ransomware risk."],
                    "activity": [f"Observed {russia_count} Russia-linked actor groups this quarter."],
                    "risk": ["Ransomware incidents can cause major operational disruption."]
                },
                {
                    "name": "North Korea",
                    "level": "MEDIUM",
                    "vector": "Financial theft — Dual-use IP",
                    "exposure": "MEDIUM",
                    "relevance": ["NK cyber operations target pharmaceutical and healthcare sectors."],
                    "activity": [f"Observed {nk_count} North Korea-linked actor groups this quarter."],
                    "risk": ["Social engineering risk for research personnel."]
                }
            ]
            gaps_filled += 1

        # Fill looking_ahead if missing or using old format
        looking_ahead = analysis_result.get("looking_ahead", {})
        if looking_ahead:
            # Check if using old format (has threat_outlook/planned_initiatives/watch_items as strings)
            if isinstance(looking_ahead.get("watch_items"), str):
                logger.warning("looking_ahead is old format (watch_items is string), converting to new format")
                from datetime import datetime
                today = datetime.now()
                next_q = (today.month - 1) // 3 + 2
                next_year = today.year
                if next_q > 4:
                    next_q = 1
                    next_year += 1
                
                # Convert old string-based format to new list format
                analysis_result["looking_ahead"] = {
                    "next_quarter_label": f"Q{next_q} {next_year}",
                    "watch_items": [
                        {
                            "subject": "Threat landscape monitoring",
                            "detail": "continues to be essential as adversary capabilities evolve and targeting patterns shift."
                        }
                    ]
                }
                gaps_filled += 1
        else:
            # No looking_ahead at all, create minimal one
            from datetime import datetime
            today = datetime.now()
            next_q = (today.month - 1) // 3 + 2
            next_year = today.year
            if next_q > 4:
                next_q = 1
                next_year += 1
            
            analysis_result["looking_ahead"] = {
                "next_quarter_label": f"Q{next_q} {next_year}",
                "watch_items": []
            }
            gaps_filled += 1

        # Fill recommendations if missing or using old tuple format
        recommendations = analysis_result.get("recommendations", [])
        if recommendations:
            # Check if using old tuple/list format
            if isinstance(recommendations, list) and len(recommendations) > 0:
                if isinstance(recommendations[0], (tuple, list)):
                    logger.warning("recommendations is old tuple/list format, converting to new format")
                    # Convert old tuple format to new dict format
                    new_items = []
                    for rec in recommendations[:3]:  # Take first 3
                        if isinstance(rec, (tuple, list)) and len(rec) >= 2:
                            new_items.append({
                                "title": rec[0],
                                "body": rec[1]
                            })
                    
                    analysis_result["recommendations"] = {
                        "intro_note": "Three prioritized actions informed by quarterly intelligence findings.",
                        "items": new_items
                    }
                    gaps_filled += 1
        else:
            # No recommendations at all, create minimal one
            analysis_result["recommendations"] = {
                "intro_note": "Recommendations pending - manual review of threat data recommended.",
                "items": []
            }
            gaps_filled += 1

        if gaps_filled > 0:
            logger.info(f"Filled {gaps_filled} gaps in AI strategic analysis from backup data")

        return analysis_result

    def _build_strategic_prompt(
        self,
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        breach_data: List[Dict] | None,
        illumina_context: str = ""
    ) -> str:
        """Build the strategic analysis prompt for quarterly reports."""
        breach_data = breach_data or []

        # Group APT data by country/region
        china_actors = [a for a in crowdstrike_data if self._is_china_related(a)]
        russia_actors = [a for a in crowdstrike_data if self._is_russia_related(a)]
        nk_actors = [a for a in crowdstrike_data if self._is_nk_related(a)]

        # Get target industries from config
        target_industries = ", ".join(industry_filter_config.target_industries)
        
        # Build Illumina context section if available
        illumina_context_section = ""
        if illumina_context:
            logger.info(f"Including Illumina context in prompt ({len(illumina_context)} chars)")
            logger.debug(f"Illumina context: {illumina_context[:200]}...")
            
            # Pre-flight checklist
            logger.info("=" * 60)
            logger.info("PRE-FLIGHT CHECKLIST - AI Should:")
            logger.info("  ✓ Use Illumina context for geopolitical relevance bullets")
            logger.info("  ✓ Cite Illumina sources with [5], [6], [7] in relevance bullets")
            logger.info("  ✓ Add inline citations in executive summary")
            logger.info("  ✓ Include actual company names in notable_example fields")
            logger.info("  ✓ List cited sources in osint_sources_used array")
            logger.info("=" * 60)
            
            illumina_context_section = f"""
## Current Illumina Company Context (sourced from public disclosures this quarter)

{illumina_context}

IMPORTANT: Use the above Illumina context to ground your geopolitical_threats "relevance" bullets.
Reference specific Illumina products, platforms, market position, or regulatory situations that are
directly relevant to why each threat actor poses a risk to Illumina. Draw on current, public facts.

CRITICAL: If you reference any Illumina articles from the context above in your analysis, you MUST include them in osint_sources_used with proper citation."""
        else:
            logger.warning("No Illumina context available - AI will use generic life sciences context")
            illumina_context_section = """
## Current Illumina Company Context

No current context available from public sources. Fall back to general life sciences sector exposure
when writing "relevance" bullets, and note this limitation."""
        
        return f"""Analyze this threat intelligence data and provide a QUARTERLY STRATEGIC BRIEF for executive leadership.

IMPORTANT: 
- ALL breach reports (BREACH ALERT) should be included regardless of industry - they are critical for the breach landscape analysis.
- Filter other Intel471 reports (SPOT REPORT, SITUATION REPORT, MALWARE REPORT) by relevance to these industries/sectors: {target_industries}
- Focus on reports that mention or target these sectors: {target_industries}

{illumina_context_section}

DATA SUMMARY:
- Intel471 Threat Reports: {len(intel471_data)} records (filtered for relevance to: {target_industries})
- CrowdStrike APT Activity: {len(crowdstrike_data)} records
  - China-linked actors: {len(china_actors)}
  - Russia-linked actors: {len(russia_actors)}
  - North Korea-linked actors: {len(nk_actors)}
- Industry Breach Incidents: {len(breach_data)} records

RAW DATA:
Intel471 Data (sample - filter by industry relevance):
{json.dumps(intel471_data[:50], indent=2)}

CrowdStrike APT Data:
{json.dumps(crowdstrike_data[:30], indent=2)}

Industry Breaches:
{json.dumps(breach_data[:20], indent=2) if breach_data else "No breach data provided"}

Please provide your STRATEGIC analysis in the following JSON format:
{{
  "executive_summary": "3-4 paragraph executive summary that serves as a complete standalone brief. If executives read ONLY this section, they should understand:
  
  PARAGRAPH 1 — Overall threat landscape: Summarize the quarter's threat environment, mention the number of industry breaches and estimated impact, and note key risk assessment changes (e.g., 'Nation-state espionage remains HIGH with increased activity...')
  
  PARAGRAPH 2 — Geopolitical threats: Highlight the top 2-3 geopolitical threats identified this quarter, including which countries/actors and what they're targeting (e.g., 'China-linked actors showed elevated focus on biomanufacturing IP...')
  
  PARAGRAPH 3 — Industry breach landscape: Provide specific examples of peer breaches by company name where relevant, common attack vectors, and what incident types dominated (e.g., 'Ransomware attacks increased 50%, with notable incidents at [Company A] and [Company B]...')
  
  PARAGRAPH 4 (OPTIONAL) — Direct organizational impact: Note whether any direct threats were identified, and briefly mention 1-2 key watch items for next quarter or critical recommendations.
  
  CRITICAL - INLINE CITATIONS: If you reference ANY OSINT sources (including Illumina articles) in the executive summary, you MUST add inline citations using the citation_number from osint_sources_used. Format: [5], [6], [7], etc. Example: 'Illumina announced new precision medicine partnerships [5], which may increase...'
  
  Write in clear, business-focused language. Avoid technical jargon. This is for board members and executives who need the full picture quickly.",
  "risk_assessment": {{
    "nation_state": "HIGH/MEDIUM/LOW",
    "nation_state_trend": "↑/↓/Unchanged",
    "ransomware": "HIGH/MEDIUM/LOW",
    "ransomware_trend": "↑/↓/Unchanged",
    "supply_chain": "HIGH/MEDIUM/LOW",
    "supply_chain_trend": "↑/↓/Unchanged",
    "insider": "HIGH/MEDIUM/LOW",
    "insider_trend": "↑/↓/Unchanged"
  }},
  "breach_landscape": {{
    "scope_note": "One sentence describing what the data covers and the time period. Example: 'Publicly disclosed incidents affecting life sciences, pharmaceutical, biotechnology, healthcare, and advanced manufacturing organizations during Q2 2026.'",
    "stat_cards": [
      {{
        "value": "20",
        "label": "Total Incidents",
        "prior_label": "Q1 2026",
        "prior_value": "16",
        "change_pct": "+25%"
      }},
      {{
        "value": "$120M",
        "label": "Est. Total Impact",
        "prior_label": "Q1 2026",
        "prior_value": "$90M",
        "change_pct": "+33%"
      }},
      {{
        "value": "12",
        "label": "Ransomware",
        "prior_label": "Q1 2026",
        "prior_value": "10",
        "change_pct": "+20%"
      }},
      {{
        "value": "8M",
        "label": "Records Exposed",
        "prior_label": "Q1 2026",
        "prior_value": "5M",
        "change_pct": "+60%"
      }}
    ],
    "incidents_by_type": [
      {{
        "type": "Ransomware",
        "current_count": "12",
        "prior_count": "10",
        "notable_example": "Covenant Health: ransomware attack disrupted hospital operations for 3 weeks, 480K patient records"
      }},
      {{
        "type": "Supply Chain",
        "current_count": "5",
        "prior_count": "3",
        "notable_example": "LabCorp vendor: credentials exposed affecting 200+ clinical laboratories"
      }},
      {{
        "type": "Data Exposure",
        "current_count": "3",
        "prior_count": "3",
        "notable_example": "Genomics research institute: 2.3M patient samples accessed via misconfigured database"
      }}
    ],
    "current_quarter_label": "Q2 2026",
    "prior_quarter_label": "Q1 2026",
    "common_factors": "One paragraph of prose describing common factors across incidents. Include specific percentages where possible, e.g., 'Exploitation of unpatched systems accounted for 34% of incidents, followed by compromised credentials at 28%.'"
  }},
  "geopolitical_threats": [
    {{
      "name": "Country or geopolitical region name ONLY",
      "level": "HIGH/MEDIUM/LOW",
      "vector": "Primary attack method (concise phrase, e.g., 'Espionage — IP theft', 'Ransomware — Disruption')",
      "exposure": "CRITICAL/HIGH/MEDIUM",
      "relevance": [
        "Bullet 1: Illumina-specific relevance drawn from the Illumina context above (reference specific products, markets, or regulatory situations)",
        "Bullet 2: Another Illumina-specific relevance point",
        "Bullet 3: Third relevance point (max 3 bullets)"
      ],
      "activity": [
        "Bullet 1: What this actor did this quarter (from Intel471/CrowdStrike data)",
        "Bullet 2: Additional activity this quarter",
        "Bullet 3: Third activity point (max 3 bullets)"
      ],
      "risk": [
        "Bullet 1: Specific business risk to Illumina from this actor",
        "Bullet 2: Additional risk",
        "Bullet 3: Third risk (max 3 bullets)"
      ]
    }}
  ],

CRITICAL - geopolitical_threats "name" field formatting rule:

The "name" field must contain ONLY the country or geopolitical region name. Never include actor group names, threat actor codenames, or parenthetical lists in this field.

  BAD:  "name": "China (CASCADE PANDA, VAULT PANDA, OVERCAST PANDA)"
  BAD:  "name": "Russian Federation — APT28, APT29"
  GOOD: "name": "China"
  GOOD: "name": "Russian Federation"
  GOOD: "name": "Iran"
  GOOD: "name": "North Korea"

The "name" field must always contain a real country or geopolitical region name based on the intelligence reviewed. Do not return "Unknown", "N/A", or placeholder values under any circumstances. If you cannot identify a specific country from the intelligence data, do not include that entry in the list at all. It is better to return fewer entries than to return entries with missing or fabricated data. Every field in every entry must be populated with real intelligence-based content before it is included in the output.

Actor group names belong in the "activity" bullets, referenced naturally within the text:
  
  CORRECT activity bullet example:
    "CASCADE PANDA targeted pharmaceutical organizations with credential harvesting campaigns focused on executive accounts with access to clinical trial data."
  
If multiple actor groups are active, dedicate separate activity bullets to each OR combine them naturally in prose:
  
  "VAULT PANDA and OVERCAST PANDA both conducted espionage operations targeting life sciences research institutions, focusing on genomics and proteomics data."


  "looking_ahead": {{
    "next_quarter_label": "Q3 2026",
    "watch_items": [
      {{
        "subject": "ALPHV/BlackCat successor groups",
        "detail": "are actively rebuilding targeting infrastructure and re-engaging life sciences organizations. Expect elevated ransomware incident volume against sector peers in Q3. Illumina should validate that M365 playbooks reflect current RaaS TTPs."
      }},
      {{
        "subject": "CISA KEV entries from Q2",
        "detail": "affecting network management and VPN gateway software used in laboratory environments remain unpatched across a significant portion of the sector. Confirm patch status for all affected Illumina systems before Q3 close."
      }},
      {{
        "subject": "Pending genomics data security legislation",
        "detail": "in the United States and European Union — including provisions restricting foreign access to human genomic datasets — is expected to advance in Q3. Monitor for provisions relevant to ICA and BaseSpace customer data and Illumina's ongoing China market activity."
      }}
    ]
  }},
  "recommendations": {{
    "intro_note": "Three prioritized actions informed by Q2 intelligence findings.",
    "items": [
      {{
        "title": "Verify MFA Coverage Across Research and Manufacturing Environments",
        "body": "Twelve percent of sector breaches this quarter involved absent MFA on critical systems. An MFA coverage audit across Illumina's sequencing systems, manufacturing network, and ICA/BaseSpace administrative interfaces should be completed before Q3 close, with any gaps remediated on an accelerated timeline."
      }},
      {{
        "title": "Conduct ICA and BaseSpace Threat Model Review",
        "body": "Nation-state targeting of cloud-hosted genomic data is the intelligence trend with the highest potential business impact for Illumina identified this quarter. A threat model review scoped to ICA and BaseSpace — covering data access controls, customer data segregation, and detection capabilities for unauthorized access scenarios — should be initiated this quarter and completed before the Q3 board cycle."
      }},
      {{
        "title": "Prioritize Security Attestation for Critical Vendor Tier",
        "body": "Eighteen percent of sector breaches originated from third-party and vendor compromise. Illumina should accelerate contractual security requirements and attestation reviews for vendors with access to instrument firmware, ICA infrastructure, or clinical data systems."
      }}
    ]
  }},
  "osint_sources_used": [
    {{
      "title": "Article title (shortened for citation, 2-5 words max)",
      "url": "https://example.com/article",
      "description": "One sentence describing what intelligence this source provided (e.g., 'Confirmed active exploitation of FortiClient EMS vulnerability impacting device security.')",
      "citation_number": 5
    }}
  ]
}}

CRITICAL - osint_sources_used Instructions:

1. **Purpose**: List ONLY the OSINT articles that you ACTUALLY REFERENCE in your analysis. These should be articles that:
   - Provide specific intelligence about Illumina (company news, SEC filings, regulatory updates, incidents)
   - Offer peer breach intelligence with named victim organizations
   - Discuss specific threat actors, vulnerabilities, or incidents relevant to the quarterly analysis
   
2. **Illumina-Specific OSINT**: If the "Current Illumina Company Context" section above contains articles,
   you MUST review them for relevance. If you use ANY of that Illumina context in your:
   - Geopolitical threat "relevance" bullets (mentioning specific Illumina products, markets, or situations)
   - Executive summary (referencing Illumina's business context)
   - Risk assessment considerations
   THEN you MUST include those Illumina articles in osint_sources_used with:
   - Short title (2-5 words)
   - Original URL from the context
   - Description of what intelligence it provided (1 sentence)
   - Citation number starting from 5 (after the 4 primary intelligence sources)
   
3. **Citation numbering**: Start from 5 (sources [1]-[4] are reserved for NVD, CISA KEV, Intel471, CrowdStrike)

4. **Quality over quantity**: It's better to have 0-3 highly relevant OSINT sources than to list 10+ that weren't actually used

5. **When to include zero OSINT**: ONLY if no OSINT articles (including Illumina articles) added unique value beyond what Intel471/CrowdStrike provided.
   However, if Illumina context was provided and you referenced it, you MUST cite those sources.

CRITICAL - risk_assessment Instructions:

Use the following criteria to determine risk levels. Each rating must be defensible based on the threat intelligence data.

**Nation-State Espionage:**
- HIGH: 3+ APT groups actively targeting sector this quarter, OR direct targeting of genomics/sequencing technology, OR confirmed IP theft incidents from peer organizations
- MEDIUM: 1-2 APT groups with sector interest, OR general life sciences targeting without genomics-specific focus
- LOW: Minimal observed activity, OR actors focused on other sectors

**Ransomware & Extortion:**
- HIGH: 10+ peer incidents this quarter, OR increase >30% from prior quarter, OR targeting of manufacturing/OT environments, OR average impact >$5M
- MEDIUM: 5-9 peer incidents, OR stable activity levels, OR primarily IT-focused attacks
- LOW: <5 peer incidents, OR declining activity, OR no sector-specific campaigns

**Supply Chain Compromise:**
- HIGH: 5+ vendor/third-party incidents this quarter, OR targeting of critical suppliers (lab equipment, software, sequencing reagents), OR confirmed compromise of widely-used platforms
- MEDIUM: 2-4 vendor incidents, OR general third-party risk observations, OR targeting of non-critical vendors
- LOW: <2 vendor incidents, OR no sector-specific supply chain activity

**Insider Threat:**
- HIGH: 3+ confirmed insider incidents in peer organizations, OR insider-as-a-service activity targeting sector, OR recruitment campaigns against industry employees
- MEDIUM: 1-2 insider incidents, OR general insider risk indicators, OR social engineering campaigns
- LOW: No observed insider incidents, OR minimal social engineering activity

**When assigning ratings:**
1. Review the actual Intel471, CrowdStrike, and breach data provided above
2. Count relevant incidents, actor groups, and campaigns
3. Compare to prior quarter if historical data available
4. Err on the side of caution - if uncertain between two levels, choose the higher risk level
5. Ensure the executive summary and breach landscape data support your chosen risk levels

CRITICAL - geopolitical_threats Instructions:

1. **Identify relevant nation-state actors**: Review all Intel471 and CrowdStrike data from the 90-day lookback period.
   Identify every country or state-affiliated threat actor with meaningful activity targeting life sciences, pharmaceutical,
   biotechnology, genomics, or advanced manufacturing sectors.

2. **Rank by threat relevance**: Order actors by threat relevance to Illumina specifically (not just the sector in general).
   Consider: direct targeting of genomics companies, IP theft capabilities, ransomware/disruption risk, and overlap with
   Illumina's specific products/markets/regulatory environment.

3. **Return up to 4 actors**: Include only actors with meaningful activity this quarter. If fewer than 4 have meaningful
   activity, return only those that do. DO NOT pad the list with irrelevant actors just to reach 4.

4. **Threat Level Criteria** - Use these criteria to assign threat_level (HIGH/MEDIUM/LOW):

   **HIGH**:
   - 5+ actor groups from this country actively targeting the sector this quarter, OR
   - Direct confirmed intrusions into genomics/life sciences companies, OR
   - Systematic IP theft campaigns targeting biotech/pharma, OR
   - Confirmed targeting of sequencing technology or genomics platforms

   **MEDIUM**:
   - 2-4 actor groups with sector interest, OR
   - Opportunistic targeting without sustained campaigns, OR
   - General healthcare/pharma targeting without genomics-specific focus, OR
   - Ransomware activity targeting sector but not genomics-specific

   **LOW**:
   - 1 or fewer actor groups observed, OR
   - Minimal sector-specific activity, OR
   - Primarily focused on other sectors with occasional healthcare targeting

5. **For relevance bullets specifically**: Draw on the Illumina context provided above. Reference specific Illumina products
   (e.g., NovaSeq X, sequencing platforms), market positions (e.g., "~80% global sequencing market share"), regulatory
   situations (e.g., recent SEC filings, FDA approvals), or partnerships mentioned in the context. If the context is empty
   or unparseable, fall back to general life sciences sector exposure and note the limitation in your analysis.
   
   **CRITICAL - INLINE CITATIONS IN RELEVANCE BULLETS**: If you reference specific Illumina information from the "Current Illumina Company Context"
   section in your relevance bullets, you MUST add an inline citation using the source's citation_number from osint_sources_used.
   Format: "Illumina's focus on precision medicine platforms [5] increases..." or "Recent partnerships in oncology [6] create..."
   This allows readers to trace Illumina-specific claims back to their sources.

5. **Keep bullets concise**: Each bullet should be one short sentence. Max 3 bullets per section (relevance, activity, risk).

CRITICAL - breach_landscape Instructions:

**BEFORE YOU BEGIN: COMPANY NAME REQUIREMENT**

You MUST verify EVERY breach has a specific company/organization name BEFORE including it.
If the source data shows:
- "Pharma manufacturer" → SKIP THIS BREACH, find another
- "Genomics institute" → SKIP THIS BREACH, find another  
- "Genomics research institute" → SKIP THIS BREACH, find another
- "Research institute" → SKIP THIS BREACH, find another
- "Biotech company" → SKIP THIS BREACH, find another
- ANY generic term → SKIP THIS BREACH, find another

ONLY include breaches where the victim has an actual name like:
✓ "Covenant Health" ✓ "Memorial Sloan Kettering" ✓ "Medtronic" ✓ "LabCorp" ✓ "Regeneron"

**CRITICAL DECISION POINT:**
If you review ALL breaches for "Data Exposure" and find ONLY breaches with generic terms like "Genomics research institute",
then DO NOT INCLUDE "Data Exposure" as an incident type at all. Skip it completely.

If you cannot find enough named breaches to fill 5-6 incident types, that's FINE.
Return only 3-4 incident types with NAMED examples. Quality over quantity.

1. **scope_note**: Generate one sentence describing the data coverage and time period. Use the current quarter from the context.

2. **stat_cards**: Always return exactly 4 cards in this exact order:
   - Card 1: Total Incidents
   - Card 2: Est. Total Impact (in millions, e.g., "$120M")
   - Card 3: Ransomware (count of ransomware incidents)
   - Card 4: Records Exposed (in millions, e.g., "8M")

3. **change_pct calculation**: For each stat card, calculate the percentage change from prior quarter to current quarter.
   ALWAYS include the sign explicitly:
   - Use "+" prefix for increases (e.g., "+25%")
   - Use "-" prefix for decreases (e.g., "-12%")
   - Use "0%" for no change
   The sign is REQUIRED - the renderer uses it to determine color (red for +, green for -, gray for 0%).

4. **Quarter labels**: Set current_quarter_label and prior_quarter_label to the actual quarter identifiers (e.g., "Q2 2026", "Q1 2026").

5. **incidents_by_type**: Return a dynamic list of incident types observed in the breach data. Common types include:
   Ransomware, Supply Chain, Data Exposure, Insider Threat, DDoS, Business Email Compromise, Manufacturing/OT Disruption, Third-Party/Vendor, Unauthorized Access, etc.
   DO NOT hardcode exactly 3 types - return however many distinct types you observe in the data (typically 4-7).
   For each type, provide current_count, prior_count, and a notable_example.

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   CRITICAL - notable_example MUST USE ACTUAL COMPANY NAMES
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   THIS IS MANDATORY - NOT OPTIONAL:

   ✓ CORRECT - Use actual company/organization names:
     • "Covenant Health: ransomware attack disrupted operations for 3 weeks"
     • "Memorial Sloan Kettering: 2.3M patient samples accessed via vendor breach"
     • "Medtronic: assembly line shutdown for 8 days following OT compromise"
     • "LabCorp: third-party credentials exposed affecting 200+ customers"
     • "Regeneron: former employee accessed IP repository post-termination"
     • "Broad Institute: genomics database misconfiguration exposed research data"

   ✗ WRONG - Generic terms are STRICTLY FORBIDDEN:
     • "Pharma manufacturer" ← NO - find the actual company name in the breach data
     • "Genomics institute" ← NO - use "Broad Institute", "Sanger Institute", etc.
     • "Research institute" ← NO - use the actual organization name
     • "Genomics research institute" ← NO - use the specific institution name
     • "Biotech company" ← NO - use "Genentech", "Amgen", "Illumina", etc.
     • "Medical device mfg" ← NO - use "Medtronic", "Boston Scientific", etc.
     • "Lab software vendor" ← NO - use "LabCorp", "Quest Diagnostics", etc.
     • "Healthcare provider" ← NO - use "Kaiser Permanente", "Mayo Clinic", etc.
     • "Life sciences company" ← NO - use the specific company name
     • "Clinical research org" ← NO - use the actual CRO name

   INSTRUCTIONS:
   1. Review the Industry Breaches data provided above - look for breaches with SPECIFIC victim names
   2. **FILTER OUT breaches with generic descriptions** - if a breach record says "pharma manufacturer", 
      "genomics institute", "biotech company", or any generic term, SKIP IT and find a different breach
   3. For EACH notable_example, you MUST find a breach record that has:
      - An actual company name (e.g., "Covenant Health", "Medtronic", "LabCorp")
      - NOT a generic description (e.g., "pharma manufacturer", "genomics institute")
   4. If multiple breaches exist for an incident type, choose the one with the MOST SPECIFIC company name
   5. Format MUST be: "ActualCompanyName: what happened"
   6. The validation system WILL REJECT generic terms - this is your FINAL warning before rejection
   
   **IF YOU CANNOT FIND A BREACH WITH A SPECIFIC COMPANY NAME:**
   - Do NOT use a generic placeholder
   - Do NOT copy generic descriptions from the source data
   - Skip that incident type entirely and only include types where you have named examples
   - It is better to have 4 incident types with named companies than 6 types with generic placeholders

   Only use "Multiple organizations" if the breach data literally shows multiple unnamed victims,
   but this should be EXTREMELY rare because breach data includes victim names.

6. **common_factors**: Write one paragraph analyzing common factors across the incidents. Include specific percentages
   where possible (e.g., "Exploitation of unpatched systems accounted for 34% of incidents").

CRITICAL - looking_ahead Instructions:

1. **next_quarter_label**: Calculate the next quarter from the current reporting period. Format as "Q{{N}} YYYY" (e.g., "Q3 2026").

2. **watch_items**: Return a list of 2-4 specific, named watch items. Each item must have:
   - **subject**: A concise named entity (threat actor, CVE, policy, or specific technology). Examples: "ALPHV/BlackCat successor groups", "CISA KEV entries from Q2", "Pending genomics data security legislation"
   - **detail**: The rest of the sentence explaining why this item matters and what to watch for. Should flow naturally after the subject.

3. **Quality standards for watch items**:
   - Must be SPECIFIC and NAMED - not generic (e.g., "CVE-2024-1234" not "unpatched vulnerabilities")
   - Must be ACTIONABLE - give concrete next steps or monitoring guidance
   - Must be RELEVANT to Illumina's specific business, products, or threat profile
   - Avoid generic monitoring reminders like "Continue monitoring threat landscape"

CRITICAL - recommendations Instructions:

1. **intro_note**: Write one sentence describing the recommendations. Examples: "Three prioritized actions informed by Q2 intelligence findings.", "Four strategic initiatives to address identified risks."

2. **items**: Return a list of 2-4 recommendations. Each must have:
   - **title**: Full recommendation title. The first word will be underlined if it's purely alphabetic. Examples: "Verify MFA Coverage Across Research and Manufacturing Environments", "Conduct ICA and BaseSpace Threat Model Review"
   - **body**: 2-4 sentences explaining the justification (what intelligence finding drove this) and the specific action to take

3. **Quality standards for recommendations**:
   - Must be SPECIFIC and ACTIONABLE - not vague (e.g., "Verify MFA coverage across research environments" not "Improve security posture")
   - Must include CONTEXT from the quarter's intelligence findings (reference specific percentages, threat actors, or incidents)
   - Must include CLEAR SCOPE and NEXT STEPS (what to review, when to complete, what outcome to achieve)
   - No owners, no dates, no "leadership to decide" framing - these are direct technical recommendations

Focus on STRATEGIC insights for leadership, not tactical details.
When analyzing Intel471 data, prioritize reports relevant to: {target_industries}
Include breach alerts, spot reports, situation reports, and malware reports that target or mention these sectors.
Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks.

Do not use Hyphens.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL - INLINE CITATION REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Whenever you reference information from an OSINT source (including Illumina articles from the "Current Illumina Company Context" section):

1. **Add inline citation numbers**: Use square brackets with the citation_number from osint_sources_used
   - Format: [5], [6], [7], etc.
   - Example: "Illumina's recent precision medicine partnerships [5] increase exposure to..."
   - Example: "Q2 saw increased targeting of genomics data [6] by nation-state actors..."

2. **Where to include citations**:
   - Executive summary paragraphs (when referencing OSINT-sourced information)
   - Geopolitical threat "relevance" bullets (when using Illumina-specific context)
   - Any other section where you reference an OSINT article

3. **Citation consistency**: Every source listed in osint_sources_used MUST be cited at least once in the report content.
   If you list a source but never cite it, remove it from osint_sources_used.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT LENGTH AND CONCISENESS RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY:
- Maximum 3 sentences total
- Each sentence must be one standalone thought (no multi-sentence compound clauses)
- No paragraph breaks — the entire summary is one short paragraph
- If you generate more than 3 sentences, consolidate before returning

GEOPOLITICAL BULLETS (relevance, activity, risk):
- Maximum 2 bullets per section per country
- Each bullet must be a maximum of 20 words
- Bullets must be statements of fact or assessed risk — not explanatory prose
- No bullet should begin with "Illumina" — vary the sentence openings

WATCH ITEMS (looking_ahead):
- Maximum 3 items
- Each item's "detail" field must be a maximum of 40 words

RECOMMENDATIONS:
- Maximum 3 items
- Each item's "body" field must be a maximum of 50 words

BREACH LANDSCAPE COMMON FACTORS:
- Maximum 4 sentences
- Include percentages where available

These are HARD LIMITS. Exceeding them will cause display overflow and formatting issues.
Review your output before returning and trim to meet these constraints.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINAL VERIFICATION CHECKLIST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Before returning your JSON, verify each item:

☐ Every source in osint_sources_used is cited with [N] in executive summary or relevance bullets
☐ Every notable_example includes an ACTUAL COMPANY NAME - verify no generic terms like "Pharma manufacturer", "Genomics institute", "Research institute", "Biotech company", "Medical device mfg", or "Lab software vendor"
☐ If Illumina context was provided above, it's referenced in relevance bullets with inline citations [N]
☐ Executive summary is 3-4 paragraphs covering: threat landscape, geopolitical threats, breach landscape, organizational impact
☐ Citation numbers start from 5 and are sequential (5, 6, 7, ...)
☐ Each incident type has current_count, prior_count, and a specific notable_example with NAMED company (check the Industry Breaches data above for actual victim names)
☐ Geopolitical relevance bullets mention specific Illumina products/platforms/situations when context provided

If any item is unchecked, fix it before returning.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    def _is_china_related(self, actor: Dict) -> bool:
        """Check if an actor is China-related."""
        country = str(actor.get("country", "")).lower()
        name = str(actor.get("actor_name", actor.get("name", ""))).lower()
        return "china" in country or "panda" in name or "apt41" in name or "apt40" in name

    def _is_russia_related(self, actor: Dict) -> bool:
        """Check if an actor is Russia-related."""
        country = str(actor.get("country", "")).lower()
        name = str(actor.get("actor_name", actor.get("name", ""))).lower()
        return "russia" in country or "bear" in name or "apt29" in name or "apt28" in name

    def _is_nk_related(self, actor: Dict) -> bool:
        """Check if an actor is North Korea-related."""
        country = str(actor.get("country", "")).lower()
        name = str(actor.get("actor_name", actor.get("name", ""))).lower()
        return "korea" in country or "lazarus" in name or "kimsuky" in name or "chollima" in name

    def _get_default_strategic_analysis(
        self,
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        breach_data: List[Dict] | None
    ) -> Dict[str, Any]:
        """Generate default strategic analysis when AI analysis fails."""
        breach_data = breach_data or []
        
        # Determine current and prior quarter labels
        from datetime import datetime
        today = datetime.now()
        current_q = (today.month - 1) // 3 + 1
        current_year = today.year
        prior_q = current_q - 1 if current_q > 1 else 4
        prior_year = current_year if current_q > 1 else current_year - 1

        return {
            "executive_summary": f"""The threat landscape for the genomics, life sciences, and precision manufacturing sectors \
requires continued vigilance. This quarter's analysis identified {len(crowdstrike_data)} threat actor groups and \
{len(intel471_data)} threat intelligence reports relevant to our sector.

While no direct threats to the organization were identified, the threat actors and techniques observed are consistent \
with those historically targeting genomics and life sciences companies. Strategic monitoring and proactive defense \
measures remain essential.""",
            "risk_assessment": {
                "nation_state": "HIGH",
                "nation_state_trend": "Unchanged",
                "ransomware": "HIGH",
                "ransomware_trend": "↑",
                "supply_chain": "MEDIUM",
                "supply_chain_trend": "Unchanged",
                "insider": "LOW",
                "insider_trend": "Unchanged"
            },
            "breach_landscape": {
                "scope_note": f"Publicly disclosed incidents affecting life sciences, pharmaceutical, biotechnology, healthcare, and advanced manufacturing organizations during Q{current_q} {current_year}.",
                "stat_cards": [
                    {
                        "value": str(len(breach_data)),
                        "label": "Total Incidents",
                        "prior_label": f"Q{prior_q} {prior_year}",
                        "prior_value": "N/A",
                        "change_pct": "0%"
                    },
                    {
                        "value": "$0M",
                        "label": "Est. Total Impact",
                        "prior_label": f"Q{prior_q} {prior_year}",
                        "prior_value": "N/A",
                        "change_pct": "0%"
                    },
                    {
                        "value": "0",
                        "label": "Ransomware",
                        "prior_label": f"Q{prior_q} {prior_year}",
                        "prior_value": "N/A",
                        "change_pct": "0%"
                    },
                    {
                        "value": "0M",
                        "label": "Records Exposed",
                        "prior_label": f"Q{prior_q} {prior_year}",
                        "prior_value": "N/A",
                        "change_pct": "0%"
                    }
                ],
                "incidents_by_type": [],
                "current_quarter_label": f"Q{current_q} {current_year}",
                "prior_quarter_label": f"Q{prior_q} {prior_year}",
                "common_factors": "Analysis pending - manual review of threat data recommended"
            },
            "geopolitical_threats": [
                {
                    "name": "China",
                    "level": "HIGH",
                    "vector": "Espionage — IP theft",
                    "exposure": "CRITICAL",
                    "relevance": ["China's national plans designate biotechnology as a strategic priority."],
                    "activity": [f"Observed {len([a for a in crowdstrike_data if self._is_china_related(a)])} China-linked actor groups."],
                    "risk": ["Potential IP theft risk for proprietary research and manufacturing processes."]
                },
                {
                    "name": "Russia",
                    "level": "HIGH",
                    "vector": "Ransomware — Disruption",
                    "exposure": "HIGH",
                    "relevance": ["Russian-speaking criminal groups pose significant ransomware risk to healthcare and life sciences."],
                    "activity": [f"Observed {len([a for a in crowdstrike_data if self._is_russia_related(a)])} Russia-linked actor groups."],
                    "risk": ["Ransomware incidents can result in significant operational disruption and recovery costs."]
                },
                {
                    "name": "North Korea",
                    "level": "MEDIUM",
                    "vector": "Financial theft — Dual-use IP",
                    "exposure": "MEDIUM",
                    "relevance": ["North Korean cyber operations target pharmaceutical and healthcare sectors."],
                    "activity": [f"Observed {len([a for a in crowdstrike_data if self._is_nk_related(a)])} North Korea-linked actor groups."],
                    "risk": ["Social engineering risk for research and executive personnel."]
                }
            ],
            "looking_ahead": {
                "next_quarter_label": f"Q{(current_q % 4) + 1} {current_year if current_q < 4 else current_year + 1}",
                "watch_items": [
                    {
                        "subject": "Threat landscape evolution",
                        "detail": "continues to require monitoring as adversary capabilities and targeting patterns shift."
                    }
                ]
            },
            "recommendations": {
                "intro_note": "Three prioritized actions based on quarterly intelligence findings.",
                "items": [
                    {
                        "title": "Executive Awareness",
                        "body": "Consider targeted security awareness for executives and key research personnel given sustained social engineering campaigns via professional networks."
                    },
                    {
                        "title": "Vendor Risk Review",
                        "body": "Evaluate security posture of critical software and laboratory equipment vendors given supply chain compromise activity observed this quarter."
                    },
                    {
                        "title": "Manufacturing Security",
                        "body": "Review network segmentation between IT and OT/manufacturing systems. Ensure incident response plans address manufacturing disruption scenarios."
                    }
                ]
            }
        }
