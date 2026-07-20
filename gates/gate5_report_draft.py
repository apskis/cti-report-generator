"""Gate 5: AI-powered threat analysis.

Invokes ThreatAnalystAgent to analyze the collected threat intelligence data.
This is the AI analysis gate - it takes raw data from collectors and prior gates,
runs it through the AI analyst, and produces the structured analysis that will
become the report.

For weekly reports: Tactical analysis with CVE focus
For quarterly reports: Strategic analysis with geopolitical context

Gate 6 validates the output of this analysis.
"""

from __future__ import annotations

import logging

from .escape_handler import detect_gate_bleed
from .models import GateInput, GateResult

logger = logging.getLogger(__name__)


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """Execute Gate 5 - AI Threat Analysis.

    This gate invokes ThreatAnalystAgent to analyze the collected data.
    The AI agent produces the structured analysis (cve_analysis, apt_activity,
    statistics, etc.) that Gate 6 will validate and the report generator will format.

    Args:
        input: GateInput with tier1_data, osint_articles, and prior gate results
        llm_client: LLM client (not used - we instantiate ThreatAnalystAgent directly)
        report_type: "WEEKLY" or "QUARTERLY"

    Returns:
        GateResult with the AI's analysis in payload["report"]
    """
    logger.info(f"Running Gate 5: AI Threat Analysis ({report_type})")

    # Get prior gate results for context
    g1 = input.prior_results.get("1")
    g1b = input.prior_results.get("1B")
    g2 = input.prior_results.get("2")
    input.prior_results.get("4")

    if not all((g1, g1b, g2)):
        raise RuntimeError("Gate 5 requires Gates 1, 1B, 2 in input.prior_results")

    # Extract data from prior gates
    g1.payload.get("tier1_sources", [])
    osint_articles = g1b.payload.get("osint_articles", [])

    # Prepare data for AI analyst
    cve_data = input.tier1_data.get("NVD", [])
    intel471_data = input.tier1_data.get("Intel471", [])
    crowdstrike_data = input.tier1_data.get("CrowdStrike", [])
    threatq_data = input.tier1_data.get("ThreatQ", [])

    # Rapid7 is disabled for threat intelligence reports, but method signature requires it
    rapid7_data = []
    rapid7_scans_data = []

    # Convert OSINT articles to the format the AI expects
    osint_data = [
        {
            "title": article.title,
            "url": article.url,
            "source": article.source_name,
            "published_date": article.published_date,
        }
        for article in osint_articles
    ]

    logger.info(
        f"AI analysis input: {len(cve_data)} CVEs, {len(intel471_data)} Intel471 records, "
        f"{len(crowdstrike_data)} CrowdStrike records, {len(osint_data)} OSINT articles"
    )

    # Import ThreatAnalystAgent here to avoid circular dependencies
    try:
        from src.agents.threat_analyst import ThreatAnalystAgent
        from src.core.config import analysis_config
    except ImportError as e:
        logger.error(f"Failed to import ThreatAnalystAgent: {e}")
        raise RuntimeError("Gate 5 requires ThreatAnalystAgent. Ensure src.agents.threat_analyst is available.") from e

    # Get Azure OpenAI credentials from gate input or environment
    # The credentials should be passed through the orchestrator from the caller
    openai_endpoint = None
    openai_key = None

    # Try to get from prior_results (passed by pipeline_hook.py)
    credentials = input.prior_results.get("credentials")
    if isinstance(credentials, dict):
        openai_endpoint = credentials.get("openai_endpoint")
        openai_key = credentials.get("openai_key")

    # Fallback to environment variables
    if not openai_endpoint or not openai_key:
        import os

        openai_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        openai_key = os.environ.get("AZURE_OPENAI_KEY")

    if not openai_endpoint or not openai_key:
        raise RuntimeError(
            "Gate 5 requires Azure OpenAI credentials. "
            "Pass them via prior_results['credentials'] or set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY environment variables."
        )

    # Initialize AI agent
    deployment_name = analysis_config.deployment_name
    agent = ThreatAnalystAgent(openai_endpoint, openai_key, deployment_name=deployment_name)

    # Run appropriate analysis based on report type
    is_quarterly = report_type.upper() == "QUARTERLY"

    try:
        import asyncio

        # Check if we're in an async context
        try:
            asyncio.get_running_loop()
            # We're in async context - need to use nest_asyncio or run_in_executor
            # Simpler: just use asyncio.run_coroutine_threadsafe
            import concurrent.futures

            if is_quarterly:
                logger.info("Running strategic analysis for quarterly report")

                breach_data = [item for item in intel471_data if item.get("threat_type", "").upper() == "BREACH ALERT"]
                intel471_filtered = [
                    item for item in intel471_data if item.get("threat_type", "").upper() != "BREACH ALERT"
                ]

                # Run in a new thread with its own event loop
                def run_async():
                    return asyncio.run(
                        agent.analyze_strategic(
                            intel471_data=intel471_filtered,
                            crowdstrike_data=crowdstrike_data,
                            breach_data=breach_data if breach_data else None,
                        )
                    )

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_async)
                    analysis_result = future.result()
            else:
                logger.info("Running tactical analysis for weekly report")

                # Run in a new thread with its own event loop
                def run_async():
                    return asyncio.run(
                        agent.analyze_threats(
                            cve_data=cve_data,
                            intel471_data=intel471_data,
                            crowdstrike_data=crowdstrike_data,
                            threatq_data=threatq_data,
                            rapid7_data=rapid7_data,
                            rapid7_scans_data=rapid7_scans_data,
                            osint_data=osint_data,
                        )
                    )

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_async)
                    analysis_result = future.result()

        except RuntimeError:
            # No running loop - we can safely use asyncio.run
            if is_quarterly:
                logger.info("Running strategic analysis for quarterly report")

                breach_data = [item for item in intel471_data if item.get("threat_type", "").upper() == "BREACH ALERT"]
                intel471_filtered = [
                    item for item in intel471_data if item.get("threat_type", "").upper() != "BREACH ALERT"
                ]

                analysis_result = asyncio.run(
                    agent.analyze_strategic(
                        intel471_data=intel471_filtered,
                        crowdstrike_data=crowdstrike_data,
                        breach_data=breach_data if breach_data else None,
                    )
                )
            else:
                logger.info("Running tactical analysis for weekly report")

                analysis_result = asyncio.run(
                    agent.analyze_threats(
                        cve_data=cve_data,
                        intel471_data=intel471_data,
                        crowdstrike_data=crowdstrike_data,
                        threatq_data=threatq_data,
                        rapid7_data=rapid7_data,
                        rapid7_scans_data=rapid7_scans_data,
                        osint_data=osint_data,
                    )
                )
    except Exception as e:
        logger.error(f"AI analysis failed: {e}", exc_info=True)
        raise RuntimeError(f"Gate 5 AI analysis failed: {str(e)}") from e

    logger.info(
        f"AI analysis complete: {len(analysis_result.get('cve_analysis', []))} CVEs analyzed, "
        f"{len(analysis_result.get('apt_activity', []))} threat actors identified"
    )

    # Detect any gate bleed in the AI's response
    # (Check if AI is trying to escape gate boundaries)
    analysis_text = str(analysis_result)
    try:
        detect_gate_bleed(analysis_text, expected_gate_id="5")
    except Exception as e:
        logger.warning(f"Gate bleed detection raised: {e}")
        # Don't fail the gate on this, just log it

    return GateResult(
        gate_id="5",
        status="COMPLETE",
        payload={
            "report": analysis_result,  # This is what Gate 6 will validate
            "draft_text": "",  # Not used for weekly/quarterly - AI produces structured data
            "analysis_type": "strategic" if is_quarterly else "tactical",
        },
        awaiting_clearance=True,
    )
