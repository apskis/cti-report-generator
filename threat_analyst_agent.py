import logging
import json
from typing import Dict, List, Any
from semantic_kernel import Kernel  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion  # type: ignore
from semantic_kernel.connectors.ai.open_ai import AzureChatPromptExecutionSettings  # type: ignore
from semantic_kernel.contents import ChatHistory  # type: ignore

logger = logging.getLogger(__name__)


class ThreatAnalystAgent:
    """
    AI-powered threat analyst using Microsoft Semantic Kernel and Azure OpenAI.
    Analyzes threat intelligence data and generates actionable reports.
    """
    
    def __init__(self, openai_endpoint: str, openai_key: str, deployment_name: str = "gpt-5.2-cti"):
        """
        Initialize the Threat Analyst Agent.
        
        Args:
            openai_endpoint: Azure OpenAI endpoint URL
            openai_key: Azure OpenAI API key
            deployment_name: Name of the GPT deployment
        """
        logger.info(f"Initializing ThreatAnalystAgent with deployment: {deployment_name}")
        logger.info(f"Endpoint received: {openai_endpoint}")
        logger.info(f"Key length: {len(openai_key) if openai_key else 0}")
        
        self.deployment_name = deployment_name
        self.openai_endpoint = openai_endpoint
        self.openai_key = openai_key
        
        # Initialize Semantic Kernel
        self.kernel = Kernel()
        
        # Add Azure OpenAI chat service
        self.chat_service = AzureChatCompletion(
            deployment_name=deployment_name,
            endpoint=openai_endpoint,
            api_key=openai_key,
            service_id="cti_analyst"
        )
        
        self.kernel.add_service(self.chat_service)
        
        # System prompt for the analyst
        self.system_prompt = """You are a Senior Cyber Threat Intelligence Analyst for a genomics company. 
Your role is to analyze threat data from multiple sources, correlate findings across CVEs and threat actors, 
prioritize threats based on relevance to the biotech and life sciences industry, and generate clear, 
actionable intelligence reports for technical and executive audiences.

Focus on threats that could impact:
- Research data and intellectual property
- Laboratory equipment and IoT devices
- Healthcare systems and patient data
- Supply chain and vendor security
- Regulatory compliance (HIPAA, FDA, etc.)"""
        
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
            Dictionary containing analysis results with structure:
            {
                "executive_summary": str,
                "top_threats": List[Dict],
                "cve_analysis": List[Dict],
                "apt_activity": List[Dict],
                "recommendations": List[str],
                "statistics": Dict
            }
        """
        try:
            logger.info("Starting threat analysis")
            logger.info(f"Data counts - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, "
                       f"CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, "
                       f"Rapid7: {len(rapid7_data)}")
            
            # Prepare data for analysis
            data_summary = {
                "cve_data": cve_data[:50],  # Limit to top 50 CVEs
                "intel471_data": intel471_data[:30],
                "crowdstrike_data": crowdstrike_data[:30],
                "threatq_data": threatq_data[:30],
                "rapid7_data": rapid7_data[:20]
            }
            
            # Create analysis prompt
            analysis_prompt = f"""Analyze this threat intelligence data and provide a comprehensive report.

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
  "executive_summary": "2-3 paragraph summary highlighting the most critical threats and their potential impact on genomics/biotech operations",
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
      "impact": "Potential impact on biotech operations"
    }}
  ],
  "apt_activity": [
    {{
      "actor": "Threat actor name",
      "country": "Country of origin",
      "motivation": "Primary motivation",
      "ttps": ["TTP1", "TTP2"],
      "relevance": "Why this matters to genomics/biotech"
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

            # Create chat history
            chat_history = ChatHistory()
            chat_history.add_system_message(self.system_prompt)
            chat_history.add_user_message(analysis_prompt)
            
            # Configure execution settings
            settings = AzureChatPromptExecutionSettings(
                max_completion_tokens=4000,
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
            response_text = response_text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            # Parse JSON
            try:
                analysis_result = json.loads(response_text)
                logger.info("Successfully parsed analysis results")
                return analysis_result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                logger.error(f"Response text: {response_text[:500]}")
                
                # Return a default structure if parsing fails
                return self._get_default_analysis(cve_data, intel471_data, crowdstrike_data, 
                                                  threatq_data, rapid7_data)
                
        except Exception as e:
            logger.error(f"Error during threat analysis: {e}", exc_info=True)
            # Return default analysis on error
            return self._get_default_analysis(cve_data, intel471_data, crowdstrike_data,
                                             threatq_data, rapid7_data)
    
    def _get_default_analysis(
        self,
        cve_data: List[Dict],
        intel471_data: List[Dict],
        crowdstrike_data: List[Dict],
        threatq_data: List[Dict],
        rapid7_data: List[Dict]
    ) -> Dict[str, Any]:
        """
        Generate a default analysis structure when AI analysis fails or returns no data.
        """
        total_threats = len(cve_data) + len(intel471_data) + len(crowdstrike_data) + len(threatq_data) + len(rapid7_data)
        
        if total_threats == 0:
            executive_summary = """No significant threat intelligence data was collected during this reporting period. 
This may indicate either a quiet threat landscape or potential issues with data collection from threat intelligence sources. 
We recommend verifying that all threat intelligence feeds are properly configured and operational. Continue monitoring 
for emerging threats and ensure all security controls remain active."""
        else:
            executive_summary = f"""This week's threat intelligence analysis identified {total_threats} potential security 
concerns across multiple data sources. While automated analysis encountered technical issues, manual review of the collected 
data should be performed to identify critical threats. Priority should be given to any CVEs with active exploitation, 
APT groups targeting the healthcare or biotech sectors, and indicators showing signs of compromise in our threat feeds."""
        
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
                    "motivation": actor.get("motivations", ["Unknown"])[0] if isinstance(actor.get("motivations"), list) else "Unknown",
                    "ttps": actor.get("ttps", [])[:5],
                    "relevance": "Requires manual assessment"
                }
                for actor in crowdstrike_data[:5]
            ] if crowdstrike_data else [],
            "recommendations": [
                "Review threat intelligence data sources to ensure proper configuration",
                "Manually triage collected CVEs and prioritize based on organizational risk",
                "Monitor for any APT activity targeting the biotech and healthcare sectors",
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