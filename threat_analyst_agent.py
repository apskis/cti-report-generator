"""
AI-powered threat analyst using Microsoft Semantic Kernel and Azure OpenAI.

Analyzes threat intelligence data and generates actionable reports.
"""
import logging
import json
from typing import Dict, List, Any
from pathlib import Path

from semantic_kernel import Kernel  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatPromptExecutionSettings  # type: ignore
from semantic_kernel.contents import ChatHistory  # type: ignore

from config import analysis_config
from models import ThreatAnalysisResult

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
- Regulatory compliance (HIPAA, FDA, etc.)"""

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

Avoid tactical details like specific CVEs or IOCs unless they have strategic significance."""


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
        rapid7_data: List[Dict]
    ) -> Dict[str, Any]:
        """
        Analyze threat intelligence data from multiple sources.

        Args:
            cve_data: List of CVE records from NVD
            intel471_data: List of threat intelligence from Intel471
            crowdstrike_data: List of APT intelligence from CrowdStrike
            threatq_data: List of indicators from ThreatQ
            rapid7_data: List of vulnerability data from Rapid7

        Returns:
            Dictionary containing analysis results
        """
        try:
            logger.info("Starting threat analysis")
            logger.info(
                f"Data counts - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, "
                f"CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, "
                f"Rapid7: {len(rapid7_data)}"
            )

            # Prepare data for analysis (with smart truncation)
            data_summary = self._prepare_data_for_analysis(
                cve_data, intel471_data, crowdstrike_data, threatq_data, rapid7_data
            )

            # Create analysis prompt
            analysis_prompt = self._build_analysis_prompt(
                data_summary, cve_data, intel471_data, crowdstrike_data,
                threatq_data, rapid7_data
            )

            # Create chat history
            chat_history = ChatHistory()
            chat_history.add_system_message(self.system_prompt)
            chat_history.add_user_message(analysis_prompt)

            # Configure execution settings
            settings = AzureChatPromptExecutionSettings(
                max_completion_tokens=analysis_config.max_completion_tokens,
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
                return analysis_result
            else:
                # Return default analysis if parsing fails
                return self._get_default_analysis(
                    cve_data, intel471_data, crowdstrike_data,
                    threatq_data, rapid7_data
                )

        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            return self._get_default_analysis(
                cve_data, intel471_data, crowdstrike_data,
                threatq_data, rapid7_data
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
        rapid7_data: List
    ) -> str:
        """Build the analysis prompt with data."""
        return f"""Analyze this threat intelligence data and provide a comprehensive report.

DATA SUMMARY:
- CVEs: {len(cve_data)} records
- Intel471 Threats: {len(intel471_data)} records
- CrowdStrike APT Activity: {len(crowdstrike_data)} records
- ThreatQ Indicators: {len(threatq_data)} records
- Rapid7 Vulnerabilities: {len(rapid7_data)} records

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
      "impact": "Potential impact on biotech/manufacturing operations"
    }}
  ],
  "apt_activity": [
    {{
      "actor": "Threat actor name",
      "country": "Country of origin",
      "motivation": "Primary motivation",
      "ttps": ["TTP1", "TTP2"],
      "relevance": "Why this matters to genomics/biotech/manufacturing"
    }}
  ],
  "recommendations": [
    "Specific, actionable recommendation 1",
    "Specific, actionable recommendation 2",
    "Specific, actionable recommendation 3",
    "Specific, actionable recommendation 4",
    "Specific, actionable recommendation 5"
  ],
  "statistics": {{
    "total_cves": {len(cve_data)},
    "critical_count": 0,
    "high_count": 0,
    "exploited_count": 0,
    "apt_groups": {len(crowdstrike_data)},
    "p1_count": 0,
    "p2_count": 0,
    "p3_count": 0
  }}
}}

Priority Guidelines:
- P1: Critical vulnerabilities being actively exploited or affecting core systems
- P2: High-severity vulnerabilities or significant APT activity targeting our sector
- P3: Important but lower-urgency threats requiring monitoring

Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."""

    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse the AI response into a dictionary.

        Args:
            response_text: Raw response from AI

        Returns:
            Parsed dictionary or None if parsing fails
        """
        # Clean up response (remove markdown code blocks if present)
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.error(f"Response text: {response_text[:500]}")
            return None

    def _get_default_analysis(
        self,
        cve_data: List[Dict],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        threatq_data: List[Dict],
        rapid7_data: List[Dict]
    ) -> Dict[str, Any]:
        """
        Generate a default analysis structure when AI analysis fails.

        Args:
            Various data lists from collectors

        Returns:
            Default analysis dictionary
        """
        total_threats = (
            len(cve_data) + len(intel471_data) + len(crowdstrike_data) +
            len(threatq_data) + len(rapid7_data)
        )

        if total_threats == 0:
            executive_summary = """No significant threat intelligence data was collected during this reporting period.
This may indicate either a quiet threat landscape or potential issues with data collection from threat intelligence sources.
We recommend verifying that all threat intelligence feeds are properly configured and operational. Continue monitoring
for emerging threats and ensure all security controls remain active."""
        else:
            executive_summary = f"""This week's threat intelligence analysis identified {total_threats} potential security
concerns across multiple data sources. While automated analysis encountered technical issues, manual review of the collected
data should be performed to identify critical threats. Priority should be given to any CVEs with active exploitation,
APT groups targeting the healthcare, biotech, or manufacturing sectors, and indicators showing signs of compromise in our threat feeds."""

        return {
            "executive_summary": executive_summary,
            "top_threats": [
                {
                    "threat": "Manual review required for collected threat data",
                    "priority": "P2",
                    "justification": "Automated analysis unavailable, manual triage needed"
                }
            ],
            "cve_analysis": [
                {
                    "cve_id": cve.get("cve_id", "Unknown"),
                    "priority": "P2",
                    "severity": cve.get("severity", "Unknown"),
                    "exploited": cve.get("exploited", False),
                    "description": cve.get("description", "No description")[:200],
                    "impact": "Requires manual assessment"
                }
                for cve in cve_data[:10]
            ] if cve_data else [],
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
                "Review threat intelligence data sources to ensure proper configuration",
                "Manually triage collected CVEs and prioritize based on organizational risk",
                "Monitor for any APT activity targeting the biotech, healthcare, and manufacturing sectors",
                "Ensure all security monitoring and alerting systems are operational",
                "Schedule follow-up analysis once data collection issues are resolved"
            ],
            "statistics": {
                "total_cves": len(cve_data),
                "critical_count": sum(1 for cve in cve_data if cve.get("severity") == "CRITICAL"),
                "high_count": sum(1 for cve in cve_data if cve.get("severity") == "HIGH"),
                "exploited_count": sum(1 for cve in cve_data if cve.get("exploited", False)),
                "apt_groups": len(crowdstrike_data),
                "p1_count": 0,
                "p2_count": 1,
                "p3_count": 0
            }
        }

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
                max_completion_tokens=analysis_config.max_completion_tokens,
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
        from config import industry_filter_config
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
Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks."""

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
