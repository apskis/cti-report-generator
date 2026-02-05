"""
IOC Correlation Integration Example.

Shows how to integrate the IOCCorrelator into your existing
CTI report generation pipeline in function_app.py.

This replaces the raw data handling with enriched, correlated IOCs
that have threat actor attribution.
"""
import logging
from typing import Dict, Any, List

# Existing imports from your codebase
from collectors import collect_all, get_data_by_source
from threatq_collector import separate_threatq_data
from ioc_correlator import IOCCorrelator, CorrelationResult

logger = logging.getLogger(__name__)


def separate_crowdstrike_data(
    crowdstrike_data: List[Dict[str, Any]]
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Separate CrowdStrike data into actors and indicators.
    
    CrowdStrike collector returns both types together.
    We identify them by checking for actor specific fields.
    """
    actors = []
    indicators = []
    
    for item in crowdstrike_data:
        # Actors have target_industries, indicators have indicator field
        if "target_industries" in item and "indicator" not in item:
            actors.append(item)
        else:
            indicators.append(item)
    
    return actors, indicators


async def collect_and_correlate(credentials: Dict[str, str]) -> Dict[str, Any]:
    """
    Collect threat intel from all sources and correlate IOCs.
    
    This function replaces the data collection portion of your
    existing generate_cti_report function.
    
    Args:
        credentials: API credentials from Key Vault
        
    Returns:
        Dictionary containing:
            - correlation_result: Enriched IOCs with attribution
            - cve_data: CVE data (unchanged)
            - intel471_data: Intel471 reports (unchanged)
            - rapid7_data: Vulnerability data (unchanged)
            - collection_stats: Statistics from collectors
    """
    # Step 1: Collect from all sources (existing code)
    logger.info("Collecting threat intelligence data from enabled sources...")
    collector_results = await collect_all(credentials)
    
    # Step 2: Extract data by source
    data_by_source = get_data_by_source(collector_results)
    
    cve_data = data_by_source.get("NVD", [])
    intel471_data = data_by_source.get("Intel471", [])
    crowdstrike_data = data_by_source.get("CrowdStrike", [])
    threatq_data = data_by_source.get("ThreatQ", [])
    rapid7_data = data_by_source.get("Rapid7", [])
    
    # Step 3: Separate data types for correlation
    threatq_indicators, threatq_adversaries = separate_threatq_data(threatq_data)
    crowdstrike_actors, crowdstrike_indicators = separate_crowdstrike_data(crowdstrike_data)
    
    logger.info(
        f"Data collected: CVEs={len(cve_data)}, Intel471={len(intel471_data)}, "
        f"CS Actors={len(crowdstrike_actors)}, CS IOCs={len(crowdstrike_indicators)}, "
        f"TQ IOCs={len(threatq_indicators)}, TQ Adversaries={len(threatq_adversaries)}, "
        f"Rapid7={len(rapid7_data)}"
    )
    
    # Step 4: Correlate IOCs across sources
    logger.info("Correlating IOCs across threat intelligence sources...")
    correlator = IOCCorrelator(
        target_industries=[
            "Healthcare", "Pharmaceutical", "Biotechnology",
            "Life Sciences", "Medical Devices", "Research",
            "Technology"
        ]
    )
    
    correlation_result = correlator.correlate(
        threatq_indicators=threatq_indicators,
        threatq_adversaries=threatq_adversaries,
        crowdstrike_actors=crowdstrike_actors,
        crowdstrike_indicators=crowdstrike_indicators
    )
    
    logger.info(
        f"Correlation complete: {correlation_result.attributed_count} attributed IOCs, "
        f"{correlation_result.unattributed_count} unattributed, "
        f"{len(correlation_result.actors_identified)} unique threat actors"
    )
    
    # Step 5: Get high priority IOCs for reporting
    high_priority_iocs = correlator.get_high_priority_iocs(
        correlation_result,
        min_relevance=50,
        max_count=20
    )
    
    # Step 6: Get actor summary for reporting
    actor_summary = correlator.get_actor_summary(correlation_result)
    
    return {
        "correlation_result": correlation_result,
        "high_priority_iocs": high_priority_iocs,
        "actor_summary": actor_summary,
        "cve_data": cve_data,
        "intel471_data": intel471_data,
        "rapid7_data": rapid7_data,
        "crowdstrike_actors": crowdstrike_actors,
        "collection_stats": {
            source: {
                "success": result.success,
                "record_count": result.record_count,
                "error": result.error
            }
            for source, result in collector_results.items()
        }
    }


def prepare_analysis_input(correlated_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare correlated data for the ThreatAnalystAgent.
    
    Transforms the correlation results into the format expected
    by your existing AI analysis prompt.
    
    Args:
        correlated_data: Output from collect_and_correlate()
        
    Returns:
        Dictionary ready for threat analysis
    """
    high_priority_iocs = correlated_data["high_priority_iocs"]
    actor_summary = correlated_data["actor_summary"]
    
    # Format IOCs for AI analysis
    ioc_analysis_data = []
    for ioc in high_priority_iocs:
        ioc_analysis_data.append({
            "value": ioc.value,
            "type": ioc.indicator_type,
            "score": ioc.score,
            "attributed_to": ioc.attributed_actors,
            "actor_countries": ioc.actor_countries,
            "target_industries": ioc.target_industries,
            "ttps": ioc.ttps,
            "relevance": ioc.relevance_score,
            "relevance_reason": ioc.relevance_reason,
            "confidence": ioc.confidence
        })
    
    # Format actors for AI analysis  
    actor_analysis_data = []
    for actor in actor_summary:
        if actor["relevant_to_org"]:
            actor_analysis_data.append({
                "name": actor["actor_name"],
                "country": actor["country"],
                "motivations": actor["motivations"],
                "targets": actor["target_industries"],
                "ttps": actor["ttps"],
                "ioc_count": actor["ioc_count"],
                "relevance": actor["relevance_note"]
            })
    
    return {
        "correlated_iocs": ioc_analysis_data,
        "relevant_actors": actor_analysis_data,
        "cve_data": correlated_data["cve_data"],
        "intel471_data": correlated_data["intel471_data"],
        "rapid7_data": correlated_data["rapid7_data"],
        "statistics": {
            "total_iocs_analyzed": correlated_data["correlation_result"].correlation_stats["total_iocs"],
            "attributed_iocs": correlated_data["correlation_result"].attributed_count,
            "unattributed_iocs": correlated_data["correlation_result"].unattributed_count,
            "high_relevance_iocs": correlated_data["correlation_result"].correlation_stats["high_relevance"],
            "threat_actors_identified": len(correlated_data["correlation_result"].actors_identified),
            "actors_targeting_our_sector": len(actor_analysis_data)
        }
    }


# =============================================================================
# Example: Updated function_app.py generate_cti_report handler
# =============================================================================

"""
Replace your existing generate_cti_report function with this updated version
that includes IOC correlation.

async def generate_cti_report(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('CTI Report Generation function triggered')

    try:
        # Step 1: Get credentials
        vault_url = azure_config.get_key_vault_url()
        credentials = get_all_api_keys(vault_url)

        # Step 2: Collect and correlate (NEW)
        correlated_data = await collect_and_correlate(credentials)
        
        # Step 3: Prepare for AI analysis (NEW)
        analysis_input = prepare_analysis_input(correlated_data)

        # Step 4: Analyze with AI (updated to use correlated data)
        agent = ThreatAnalystAgent(
            credentials['openai_endpoint'],
            credentials['openai_key'],
            deployment_name=analysis_config.deployment_name
        )

        # Pass correlated IOCs and actor data to analysis
        analysis = await agent.analyze_threats_with_correlation(
            cve_data=analysis_input["cve_data"],
            intel471_data=analysis_input["intel471_data"],
            correlated_iocs=analysis_input["correlated_iocs"],
            relevant_actors=analysis_input["relevant_actors"],
            rapid7_data=analysis_input["rapid7_data"],
            correlation_stats=analysis_input["statistics"]
        )

        # Step 5: Generate report (unchanged)
        report_result = create_and_upload_report(
            analysis,
            credentials['storage_account_name'],
            credentials['storage_account_key']
        )

        # Return response with correlation stats
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'message': 'CTI report generated successfully',
                'report_url': report_result['url'],
                'filename': report_result['filename'],
                'correlation_stats': analysis_input["statistics"],
                'collection_summary': correlated_data["collection_stats"]
            }, indent=2),
            mimetype='application/json',
            status_code=200
        )

    except Exception as e:
        logging.error(f'Error generating CTI report: {str(e)}', exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'status': 'error',
                'message': f'Failed to generate report: {str(e)}'
            }, indent=2),
            mimetype='application/json',
            status_code=500
        )
"""


# =============================================================================
# Example: Updated AI Prompt for Correlated Data
# =============================================================================

CORRELATED_ANALYSIS_PROMPT = """
You are analyzing correlated threat intelligence for a biotech/genomics company.

## Correlated IOC Intelligence

The following IOCs have been enriched with threat actor attribution:

{correlated_iocs_json}

## Threat Actors Targeting Our Sector

These actors specifically target healthcare, biotech, or related industries:

{relevant_actors_json}

## Correlation Statistics
- Total IOCs analyzed: {total_iocs}
- IOCs with actor attribution: {attributed_count}
- IOCs without attribution: {unattributed_count}  
- High relevance IOCs (targeting our sector): {high_relevance}
- Threat actors identified: {actors_identified}

## Analysis Instructions

1. **Priority Assessment**: Focus on IOCs that are:
   - Attributed to actors targeting healthcare/biotech
   - High relevance score (>=70)
   - Critical severity (score >=9)

2. **Actor Profiling**: For each relevant threat actor:
   - Summarize their TTPs and targeting patterns
   - Assess likelihood of targeting our organization
   - Recommend defensive measures

3. **IOC Recommendations**:
   - Which IOCs should be added to blocklists immediately?
   - Which require further investigation?
   - Which are low priority?

4. **Output Format**: Return JSON with:
   - executive_summary
   - priority_iocs (list with justification)
   - actor_assessments (list with relevance to org)
   - recommendations (actionable items)
   - statistics (counts and trends)
"""
