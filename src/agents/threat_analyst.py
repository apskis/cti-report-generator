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
                temperature=0.3,
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
                    analysis_result, cve_data, rapid7_data, rapid7_scans_data
                )
                return analysis_result
            else:
                return self._get_default_analysis(
                    cve_data, intel471_data, crowdstrike_data,
                    threatq_data, rapid7_data, rapid7_scans_data
                )

        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            return self._get_default_analysis(
                cve_data, intel471_data, crowdstrike_data,
                threatq_data, rapid7_data, rapid7_scans_data
            )

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
                entry = f"- [{article.get('source', 'Unknown')}] {article.get('title', 'No title')}"
                if article.get("cves_mentioned"):
                    entry += f" (CVEs: {', '.join(article['cves_mentioned'])})"
                if article.get("summary"):
                    entry += f"\n  {article['summary'][:150]}"
                osint_articles.append(entry)

            osint_context = f"""
OSINT - CURATED PUBLIC INTELLIGENCE ({len(osint_data)} articles from vetted sources):
{chr(10).join(osint_articles)}

Use these OSINT articles to:
- Provide additional context for CVEs or threat actors mentioned
- Identify emerging threats not yet in commercial feeds
- Reference specific articles in the executive summary or recommendations where relevant
"""

        return f"""Analyze this threat intelligence data and provide a comprehensive report.

DATA SUMMARY:
- CVEs: {len(cve_data)} records
- Intel471 Threats: {len(intel471_data)} records
- CrowdStrike APT Activity: {len(crowdstrike_data)} records
- ThreatQ Indicators: {len(threatq_data)} records
- Rapid7 Vulnerabilities: {len(rapid7_data)} records
- OSINT Articles: {len(osint_data)} records
{exposure_correlation_note}
{intel471_context}
{osint_context}

RAW DATA:
{json.dumps(data_summary, indent=2)}

Please provide your analysis in the following JSON format:
{{
  "executive_summary": "2-3 paragraph summary highlighting the most critical threats and their potential impact on genomics/biotech/manufacturing operations",
  "top_threats": [
    {{
      "threat": "Description of threat",
      "priority": "P1/P2/P3",
      "justification": "Why this is prioritized this way"
    }}
  ],
  "cve_analysis": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "priority": "P1/P2/P3",
      "severity": "Critical/High/Medium",
      "exploited": true/false,
      "description": "Brief description",
      "impact": "Potential impact on biotech/manufacturing operations",
      "affected_product": "Vendor Product Name (e.g., 'Microsoft Exchange Server', 'Fortinet FortiOS')",
      "exploited_by": "Who is exploiting it (e.g., 'Ransomware groups', 'APT28', 'None known')",
      "exposure": "REQUIRED: Asset count from exposure map (e.g., '12 servers', '3 databases', '28 devices') or 'N/A' if not in environment",
      "weeks_detected": 1
    }}
  ],
  "apt_activity": [
    {{
      "actor": "Threat actor name",
      "country": "Country of origin",
      "motivation": "Primary motivation",
      "ttps": ["TTP1", "TTP2"],
      "relevance": "Why this matters to genomics/biotech/manufacturing",
      "what_to_monitor": "Specific indicators and detection recommendations (e.g., 'Monitor for PowerShell activity; Watch for connections to Asia-Pacific regions; Scan for credential harvesting')",
      "intel471_activity": "If Intel471 provided underground activity for this actor, include it here (e.g., 'Intel471: Actor selling access to biotech networks on underground forum')"
    }}
  ],
  "recommendations": [
    "Specific, actionable recommendation 1 (mention source if relevant: 'Based on Intel471 breach reports...')",
    "Specific, actionable recommendation 2",
    "Specific, actionable recommendation 3 (e.g., 'Monitor for IOCs from Intel471 underground intelligence')",
    "Specific, actionable recommendation 4",
    "Specific, actionable recommendation 5"
  ],
  "statistics": {{
    "total_cves": {len(cve_data)},
    "critical_count": 0,
    "high_count": 0,
    "exploited_count": 0,
    "apt_groups": {len([item for item in crowdstrike_data if item.get('type') == 'actor'])},
    "p1_count": 0,
    "p2_count": 0,
    "p3_count": 0
  }}
}}

Priority Guidelines (for CVEs detected in our environment):
- P1: Critical vulnerabilities being actively exploited AND detected in our environment
  - Action required: Address immediately (24-48 hours)
  - These pose imminent risk to operations
- P2: High-severity vulnerabilities with active exploitation OR wide exposure (5+ systems)
  - Action required: Patch within 7-14 days
  - Significant risk requiring prompt attention
- P3: Vulnerabilities detected in our environment but lower severity/urgency
  - Action required: Schedule within 30 days
  - Lower exposure (1-4 systems) AND no active exploitation

Exposure Field Guidelines:
- Use the EXACT exposure string from the exposure map (e.g., "1 server", "7 systems", "12 endpoints")
- DO NOT modify or reformat these values - copy them exactly as shown
- All CVEs in your analysis will have exposure data (since we're only analyzing detected CVEs)

Weeks Detected Guidelines:
- Set weeks_detected to 1 for all CVEs by default (new this week)
- If a CVE appears to be older or recurring based on publish date or context, use a higher value
- The report will highlight CVEs with weeks_detected >= 3 as "Persistent (3+ Wks)"

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
        rapid7_scans_data: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Patch AI analysis results with Rapid7/NVD backup data where the AI
        left gaps (N/A exposure, missing product names, etc.).
        """
        rapid7_scans_data = rapid7_scans_data or []

        # Build exposure map and scan-level enrichment from Rapid7 scans
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
            if product in ("N/A", "", None, "Unknown", "unknown") or "vendor product" in product.lower():
                backup_product = (
                    nvd.get("affected_product")
                    or self._clean_rapid7_title(r7_scan.get("title", ""))
                    or r7_vuln.get("title", "")
                    or self._extract_product_from_description(
                        nvd.get("description", "") or r7_vuln.get("description", "")
                    )
                )
                if backup_product and backup_product not in ("N/A", ""):
                    cve_entry["affected_product"] = backup_product
                    gaps_filled += 1

            # Fill exploited_by if AI left it blank
            exploited_by = cve_entry.get("exploited_by", "")
            if exploited_by in ("", None, "Unknown", "unknown", "None known", "N/A"):
                exploit_info = r7_scan.get("exploit_info", {})
                if exploit_info:
                    kits = exploit_info.get("malware_kits", 0)
                    exploits = exploit_info.get("exploits", 0)
                    if kits:
                        cve_entry["exploited_by"] = f"Malware kits ({kits} known)"
                        gaps_filled += 1
                    elif exploits:
                        cve_entry["exploited_by"] = f"Public exploits ({exploits} known)"
                        gaps_filled += 1
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
                else:
                    backup_exploited_by = nvd.get("exploited_by", "")
                    if backup_exploited_by and backup_exploited_by not in ("N/A", ""):
                        cve_entry["exploited_by"] = backup_exploited_by
                        gaps_filled += 1

            # Fill weeks_detected from Rapid7 scan 'added' date
            weeks = cve_entry.get("weeks_detected", 1)
            if weeks in (1, "1", "New", "new", None):
                scan_weeks = r7_scan.get("weeks_detected")
                if scan_weeks and scan_weeks > 1:
                    cve_entry["weeks_detected"] = scan_weeks
                    gaps_filled += 1

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
        rapid7_scans_data: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate a default analysis structure when AI analysis fails.
        Uses Rapid7 scan data to filter to only detected CVEs and 
        cross-references with NVD data for product names and severity.
        """
        rapid7_scans_data = rapid7_scans_data or []
        
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
                
                # Get affected product from NVD CPE, scan title, or Rapid7 vuln title
                affected_product = (
                    nvd_info.get("affected_product")
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

                exploited_by = "None known"
                exploit_info = r7_scan.get("exploit_info", {})
                if exploit_info:
                    kits = exploit_info.get("malware_kits", 0)
                    exploits = exploit_info.get("exploits", 0)
                    if kits:
                        exploited_by = f"Malware kits ({kits} known)"
                    elif exploits:
                        exploited_by = f"Public exploits ({exploits} known)"
                elif rapid7_vuln.get("exploitable"):
                    kits = rapid7_vuln.get("malware_kits_count", 0)
                    exploits = rapid7_vuln.get("exploits_count", 0)
                    if kits:
                        exploited_by = f"Malware kits ({kits} known)"
                    elif exploits:
                        exploited_by = f"Public exploits ({exploits} known)"
                    else:
                        exploited_by = "Exploit available"
                
                # Determine priority based on severity and exploitation
                if exploited and severity in ("CRITICAL", "Critical"):
                    priority = "P1"
                elif exploited or severity in ("CRITICAL", "Critical"):
                    priority = "P2"
                elif severity in ("HIGH", "Severe", "High"):
                    priority = "P2"
                else:
                    priority = "P3"
                
                cve_analysis.append({
                    "cve_id": cve_id,
                    "priority": priority,
                    "severity": severity,
                    "exploited": exploited,
                    "description": description,
                    "impact": "Detected in environment - requires assessment",
                    "affected_product": affected_product,
                    "exploited_by": exploited_by,
                    "exposure": exposure_string,
                    "weeks_detected": r7_scan.get("weeks_detected", 1),
                })
            
            # Sort by priority (P1 first), then by exposure count descending
            priority_order = {"P1": 0, "P2": 1, "P3": 2}
            cve_analysis.sort(key=lambda x: (
                priority_order.get(x.get("priority", "P3"), 3),
                -self._extract_count(x.get("exposure", "0"))
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
        breach_data: List[Dict] | None = None
    ) -> Dict[str, Any]:
        """
        Analyze threat intelligence data for quarterly strategic reports.

        Focuses on geopolitical threats, industry breach landscape, and
        business implications rather than tactical CVE details.

        Args:
            intel471_data: List of threat intelligence from Intel471
            crowdstrike_data: List of APT intelligence from CrowdStrike
            breach_data: Optional list of industry breach incidents

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
                intel471_data, crowdstrike_data, breach_data
            )

            # Create chat history with strategic system prompt
            chat_history = ChatHistory()
            chat_history.add_system_message(STRATEGIC_SYSTEM_PROMPT)
            chat_history.add_user_message(strategic_prompt)

            # Configure execution settings
            settings = AzureChatPromptExecutionSettings(
                response_format={"type": "json_object"},
                temperature=0.3,
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
        if bl and bl.get("total_incidents") in (0, None, "N/A") and breach_data:
            bl["total_incidents"] = len(breach_data)
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

        # Fill geopolitical_threats if missing
        geo = analysis_result.get("geopolitical_threats", {})
        if not geo:
            china_count = len([a for a in crowdstrike_data if self._is_china_related(a)])
            russia_count = len([a for a in crowdstrike_data if self._is_russia_related(a)])
            nk_count = len([a for a in crowdstrike_data if self._is_nk_related(a)])
            analysis_result["geopolitical_threats"] = {
                "china": {
                    "strategic_context": "China designates biotechnology as a strategic priority.",
                    "activity": f"Observed {china_count} China-linked actor groups this quarter.",
                    "implications": "Potential IP theft risk for proprietary research."
                },
                "russia": {
                    "strategic_context": "Russian criminal groups pose significant ransomware risk.",
                    "activity": f"Observed {russia_count} Russia-linked actor groups this quarter.",
                    "implications": "Ransomware incidents can cause major operational disruption."
                },
                "north_korea": {
                    "strategic_context": "NK cyber operations target pharmaceutical and healthcare sectors.",
                    "activity": f"Observed {nk_count} North Korea-linked actor groups this quarter.",
                    "implications": "Social engineering risk for research personnel."
                }
            }
            gaps_filled += 1

        if gaps_filled > 0:
            logger.info(f"Filled {gaps_filled} gaps in AI strategic analysis from backup data")

        return analysis_result

    def _build_strategic_prompt(
        self,
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        breach_data: List[Dict] | None
    ) -> str:
        """Build the strategic analysis prompt for quarterly reports."""
        breach_data = breach_data or []

        # Group APT data by country/region
        china_actors = [a for a in crowdstrike_data if self._is_china_related(a)]
        russia_actors = [a for a in crowdstrike_data if self._is_russia_related(a)]
        nk_actors = [a for a in crowdstrike_data if self._is_nk_related(a)]

        # Get target industries from config
        target_industries = ", ".join(industry_filter_config.target_industries)
        
        return f"""Analyze this threat intelligence data and provide a QUARTERLY STRATEGIC BRIEF for executive leadership.

IMPORTANT: 
- ALL breach reports (BREACH ALERT) should be included regardless of industry - they are critical for the breach landscape analysis.
- Filter other Intel471 reports (SPOT REPORT, SITUATION REPORT, MALWARE REPORT) by relevance to these industries/sectors: {target_industries}
- Focus on reports that mention or target these sectors: {target_industries}

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
  "executive_summary": "2-3 paragraph strategic overview for board/executives. Focus on business risk, not technical details.",
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
    "total_incidents": 0,
    "prev_total_incidents": 0,
    "total_impact_millions": 0,
    "prev_total_impact": 0,
    "ransomware_count": 0,
    "prev_ransomware": 0,
    "records_exposed_millions": 0,
    "prev_records": 0
  }},
  "incidents_by_type": [
    {{
      "type": "Ransomware",
      "current_count": 0,
      "prev_count": 0,
      "notable_example": "Brief description of notable incident"
    }}
  ],
  "common_factors": "Common factors across incidents (percentages): e.g., 'Exploitation of unpatched systems (34%), compromised credentials (28%)'",
  "geopolitical_threats": {{
    "china": {{
      "strategic_context": "China's strategic interest in biotech/genomics sector",
      "activity": "Observed activity this quarter from China-linked actors",
      "implications": "Business implications of China threat activity"
    }},
    "russia": {{
      "strategic_context": "Russia's interests and ransomware ecosystem",
      "activity": "Observed activity this quarter",
      "implications": "Business implications"
    }},
    "north_korea": {{
      "strategic_context": "NK's dual-purpose cyber operations",
      "activity": "Observed activity this quarter",
      "implications": "Business implications"
    }}
  }},
  "looking_ahead": {{
    "threat_outlook": "What we anticipate next quarter",
    "planned_initiatives": "Security initiatives to recommend",
    "watch_items": "Specific items to monitor"
  }},
  "recommendations": [
    ["Executive Awareness", "Recommendation for executive security awareness"],
    ["Vendor Risk Review", "Recommendation for third-party risk"],
    ["Manufacturing Security", "Recommendation for OT/manufacturing security"],
    ["Incident Response", "Recommendation for IR readiness"],
    ["Board Reporting", "Support available for board communications"]
  ]
}}

Focus on STRATEGIC insights for leadership, not tactical details.
When analyzing Intel471 data, prioritize reports relevant to: {target_industries}
Include breach alerts, spot reports, situation reports, and malware reports that target or mention these sectors.
Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks.

Do not use Hyphens."""

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
                "total_incidents": len(breach_data),
                "prev_total_incidents": "N/A",
                "total_impact_millions": 0,
                "prev_total_impact": "N/A",
                "ransomware_count": 0,
                "prev_ransomware": "N/A",
                "records_exposed_millions": 0,
                "prev_records": "N/A"
            },
            "incidents_by_type": [],
            "common_factors": "Analysis pending - manual review of threat data recommended",
            "geopolitical_threats": {
                "china": {
                    "strategic_context": "China's national plans designate biotechnology as a strategic priority.",
                    "activity": f"Observed {len([a for a in crowdstrike_data if self._is_china_related(a)])} China-linked actor groups.",
                    "implications": "Potential IP theft risk for proprietary research and manufacturing processes."
                },
                "russia": {
                    "strategic_context": "Russian-speaking criminal groups pose significant ransomware risk to healthcare and life sciences.",
                    "activity": f"Observed {len([a for a in crowdstrike_data if self._is_russia_related(a)])} Russia-linked actor groups.",
                    "implications": "Ransomware incidents can result in significant operational disruption and recovery costs."
                },
                "north_korea": {
                    "strategic_context": "North Korean cyber operations target pharmaceutical and healthcare sectors.",
                    "activity": f"Observed {len([a for a in crowdstrike_data if self._is_nk_related(a)])} North Korea-linked actor groups.",
                    "implications": "Social engineering risk for research and executive personnel."
                }
            },
            "looking_ahead": {
                "threat_outlook": "Continued pressure from state-sponsored espionage campaigns anticipated.",
                "planned_initiatives": "Enhanced monitoring and detection capabilities recommended.",
                "watch_items": "Major industry events, product launches, and partnership announcements."
            },
            "recommendations": [
                ("Executive Awareness", "Consider targeted security awareness for executives given social engineering campaigns."),
                ("Vendor Risk Review", "Evaluate security posture of critical software and equipment vendors."),
                ("Manufacturing Security", "Review network segmentation between IT and OT systems."),
                ("Incident Response", "Confirm response plans address regulatory disclosure requirements."),
                ("Board Reporting", "CTI team available to support board communication preparation.")
            ]
        }
