"""
Azure Functions entry point for CTI Report Generator.

HTTP-triggered functions for generating weekly tactical and quarterly strategic
threat intelligence reports.
"""

import asyncio
import json
import logging
import uuid
from datetime import date

import azure.functions as func  # type: ignore

from gates.pipeline_hook import run_gate_framework_over_collected_data
from src.agents.context_manager import AgentContextManager
from src.agents.threat_analyst import ThreatAnalystAgent
from src.collectors import collect_all, get_data_by_source
from src.core.config import analysis_config, azure_config, customer_profile
from src.core.keyvault import get_all_api_keys
from src.reports.blob_storage import create_and_upload_report
from src.utils.cache_manager import CacheManager

logger = logging.getLogger(__name__)


def _gate_framework_enabled() -> bool:
    from src.core.config import get_feature_config

    return get_feature_config().gate_framework_enabled


def _extract_rapid7_cve_counts(rapid7_data: list) -> dict:
    """Extract CVE-to-asset-count mapping from Rapid7 vulnerability summaries."""
    cve_to_count = {}
    for summary in rapid7_data:
        if not isinstance(summary, dict):
            continue
        for vuln in summary.get("top_vulnerabilities") or []:
            count = vuln.get("asset_count")
            if count is None:
                continue
            for cve_id in vuln.get("cve_ids") or []:
                if cve_id and cve_id not in cve_to_count:
                    cve_to_count[cve_id] = count
    return cve_to_count


def _extract_crowdstrike_cve_counts(crowdstrike_data: list) -> dict:
    """Extract CVE-to-device-count mapping from CrowdStrike Spotlight data."""
    cve_to_count = {}
    for item in crowdstrike_data:
        if not isinstance(item, dict) or item.get("type") != "vulnerability":
            continue
        count = item.get("device_count") or item.get("asset_count") or item.get("host_count")
        cve_ids = item.get("cve_ids") or []
        if count is None or not cve_ids:
            continue
        try:
            n = int(count)
        except (TypeError, ValueError):
            continue
        for cve_id in cve_ids:
            if cve_id and cve_id not in cve_to_count:
                cve_to_count[cve_id] = n
    return cve_to_count


def _merge_exposure_into_analysis(analysis: dict, rapid7_data: list, crowdstrike_data: list) -> None:
    """Merge Rapid7 and CrowdStrike asset/device counts into cve_analysis for the Exposure column.

    Rapid7 counts take precedence; CrowdStrike counts are used as a fallback.
    """
    cve_analysis = analysis.get("cve_analysis") or []
    if not cve_analysis:
        return

    # Rapid7 takes precedence, CrowdStrike fills gaps
    rapid7_counts = _extract_rapid7_cve_counts(rapid7_data) if rapid7_data else {}
    cs_counts = _extract_crowdstrike_cve_counts(crowdstrike_data) if crowdstrike_data else {}

    for cve in cve_analysis:
        cve_id = cve.get("cve_id")
        if not cve_id:
            continue
        if cve_id in rapid7_counts:
            cve["server_count"] = rapid7_counts[cve_id]
        elif cve_id in cs_counts:
            cve["server_count"] = cs_counts[cve_id]


app = func.FunctionApp()


@app.function_name(name="GenerateWeeklyReport")
@app.route(route="GenerateWeeklyReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_weekly_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate a weekly tactical CTI report.

    Pipeline:
    1. Retrieve credentials from Key Vault
    2. Collect threat data from all enabled sources (parallel)
    3. Analyze threats with AI (tactical analysis)
    4. Generate Word document
    5. Upload to Azure Blob Storage
    6. Return download URL

    Returns:
        HTTP response with report URL and statistics
    """
    logger.info("Weekly CTI Report Generation triggered")

    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = azure_config.get_key_vault_url()
        logger.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = await asyncio.to_thread(get_all_api_keys, vault_url)

        # Step 2: Collect threat intelligence data from all sources in parallel
        logger.info("Collecting threat intelligence data from enabled sources...")
        collector_results = await collect_all(credentials, report_type="weekly")

        # Extract data from results
        data_by_source = get_data_by_source(collector_results)

        # Get data for each source (with fallback to empty list)
        cve_data = data_by_source.get("NVD", [])
        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])
        threatq_data = data_by_source.get("ThreatQ", [])
        rapid7_data = data_by_source.get("Rapid7", [])
        rapid7_scans_data = data_by_source.get("Rapid7-Scans", [])
        osint_data = data_by_source.get("OSINT", [])

        # Log collection statistics
        logger.info(
            f"Data collected - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, "
            f"CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, "
            f"Rapid7: {len(rapid7_data)}, Rapid7-Scans: {len(rapid7_scans_data)}, "
            f"OSINT: {len(osint_data)}"
        )

        # Log any collection failures
        for source, result in collector_results.items():
            if not result.success:
                logger.warning(f"Collection failed for {source}: {result.error}")

        # Step 3: Analyze threats with AI agent (tactical mode) + historical context
        deployment_name = analysis_config.deployment_name
        logger.info(f"Analyzing threat data with {deployment_name} (tactical mode with context)...")

        agent = ThreatAnalystAgent(
            credentials["openai_endpoint"], credentials["openai_key"], deployment_name=deployment_name
        )

        # Initialize context manager for historical tracking
        storage_account_name = credentials["storage_account_name"]
        storage_account_key = credentials["storage_account_key"]

        cache_manager = CacheManager(storage_account_name, storage_account_key)
        context_mgr = AgentContextManager(cache_manager)

        # Get previous 4 weeks of context for trend analysis
        logger.info("Retrieving historical contexts for trend analysis...")
        previous_contexts = await asyncio.to_thread(context_mgr.get_previous_context, "weekly", lookback_weeks=4)

        # Calculate CVE trends
        current_cve_data = cve_data + rapid7_scans_data  # Combined CVE sources
        cve_trends = context_mgr.calculate_cve_trends(current_cve_data, previous_contexts)
        logger.info(f"CVE Trends: {cve_trends.get('trend_summary', 'N/A')}")

        # Calculate threat actor trends
        # Note: We'll extract actors from the analysis, so pass empty list for now
        actor_trends = None  # Will be calculated after initial analysis

        # Run context-aware analysis
        analysis = await agent.analyze_threats_with_context(
            cve_data,
            intel471_data,
            crowdstrike_data,
            threatq_data,
            rapid7_data,
            rapid7_scans_data,
            osint_data,
            previous_contexts=previous_contexts,
            cve_trends=cve_trends,
            actor_trends=actor_trends,
        )

        # Merge Rapid7 and CrowdStrike (Spotlight) asset/device counts into CVE analysis for Exposure column
        _merge_exposure_into_analysis(analysis, rapid7_data, crowdstrike_data)

        # Save analysis context for next week's report
        logger.info("Saving analysis context for historical tracking...")
        context_save_success = await asyncio.to_thread(
            context_mgr.save_analysis_context, "weekly", date.today(), analysis
        )
        if context_save_success:
            logger.info("Analysis context saved successfully")
        else:
            logger.warning("Failed to save analysis context - future reports will lack trend data")

        # Optional: gate framework validation pass (feature-flagged)
        if _gate_framework_enabled():
            logger.info("Running gate framework validation over collected data...")
            publish_ok, gate_info, session = await asyncio.to_thread(
                run_gate_framework_over_collected_data,
                report_type="weekly",
                data_by_source=data_by_source,
                osint_articles=osint_data,
                period_days=7,
                credentials={
                    "openai_endpoint": credentials["openai_endpoint"],
                    "openai_key": credentials["openai_key"],
                },
            )
            if not publish_ok:
                return func.HttpResponse(
                    json.dumps(
                        {
                            "status": "blocked",
                            "report_type": "weekly",
                            "message": "Gate framework blocked report publication",
                            "gate_info": gate_info,
                        },
                        indent=2,
                    ),
                    mimetype="application/json",
                    status_code=409,
                )

        # Step 4: Generate Word document and upload to blob storage
        logger.info("Generating Weekly Word document and uploading to Azure Blob Storage...")
        storage_account_name = credentials["storage_account_name"]
        storage_account_key = credentials["storage_account_key"]

        if not storage_account_name or not storage_account_key:
            raise ValueError("Storage account credentials not found in Key Vault")

        report_result = await asyncio.to_thread(
            create_and_upload_report,
            report_type="weekly",
            analysis_result=analysis,
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key,
        )

        if not report_result.get("success", False):
            raise Exception(f"Report generation failed: {report_result.get('error', 'Unknown error')}")

        # Step 5: Return success response with download URL
        logger.info(f"Weekly report generated successfully: {report_result['filename']}")
        return func.HttpResponse(
            json.dumps(
                {
                    "status": "success",
                    "report_type": "weekly",
                    "message": "Weekly CTI report generated successfully",
                    "report_url": report_result["url"],
                    "filename": report_result["filename"],
                    "statistics": analysis.get("statistics", {}),
                    "collection_summary": {
                        source: {"success": result.success, "record_count": result.record_count, "error": result.error}
                        for source, result in collector_results.items()
                    },
                },
                indent=2,
            ),
            mimetype="application/json",
            status_code=200,
        )

    except Exception as e:
        correlation_id = str(uuid.uuid4())
        logger.error(f"Error generating weekly report [correlation_id={correlation_id}]: {str(e)}", exc_info=True)
        return func.HttpResponse(
            json.dumps(
                {
                    "status": "error",
                    "report_type": "weekly",
                    "message": "Failed to generate weekly report. Check server logs for details.",
                    "correlation_id": correlation_id,
                },
                indent=2,
            ),
            mimetype="application/json",
            status_code=500,
        )


@app.function_name(name="GenerateQuarterlyReport")
@app.route(route="GenerateQuarterlyReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_quarterly_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate a quarterly strategic CTI report.

    Pipeline:
    1. Retrieve credentials from Key Vault
    2. Collect threat data (focused on Intel471 and CrowdStrike for strategic analysis)
    3. Analyze threats with AI (strategic analysis mode)
    4. Generate Word document
    5. Upload to Azure Blob Storage
    6. Return download URL

    Returns:
        HTTP response with report URL and statistics
    """
    logger.info("Quarterly Strategic CTI Report Generation triggered")

    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = azure_config.get_key_vault_url()
        logger.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = await asyncio.to_thread(get_all_api_keys, vault_url)

        # Step 2: Collect threat intelligence data
        # For quarterly reports, we focus on Intel471 and CrowdStrike
        logger.info("Collecting strategic threat intelligence data...")
        collector_results = await collect_all(credentials, report_type="quarterly")

        # Extract data from results
        data_by_source = get_data_by_source(collector_results)

        # Primary sources for strategic analysis
        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])

        # Extract company context from the company-OSINT collector
        illumina_osint_data = data_by_source.get(customer_profile.osint_source_name, [])
        illumina_context = ""
        if illumina_osint_data and len(illumina_osint_data) > 0:
            illumina_context = illumina_osint_data[0].get("illumina_context", "")

        if not illumina_context:
            logger.warning("Illumina OSINT context is empty - AI will use fallback context")

        # Log collection statistics
        logger.info(
            f"Strategic data collected - Intel471: {len(intel471_data)}, "
            f"CrowdStrike: {len(crowdstrike_data)}, "
            f"Illumina OSINT: {len(illumina_context)} chars"
        )

        # Log any collection failures
        for source, result in collector_results.items():
            if not result.success:
                logger.warning(f"Collection failed for {source}: {result.error}")

        # Step 3: Analyze threats with AI agent (strategic mode) + historical context
        deployment_name = analysis_config.deployment_name
        logger.info(f"Analyzing threat data with {deployment_name} (strategic mode with context)...")

        agent = ThreatAnalystAgent(
            credentials["openai_endpoint"], credentials["openai_key"], deployment_name=deployment_name
        )

        # Initialize context manager for historical tracking
        storage_account_name = credentials["storage_account_name"]
        storage_account_key = credentials["storage_account_key"]

        cache_manager = CacheManager(storage_account_name, storage_account_key)
        context_mgr = AgentContextManager(cache_manager)

        # Get previous quarters for trend analysis (look back 1 year = 4 quarters)
        logger.info("Retrieving historical quarterly contexts for trend analysis...")
        await asyncio.to_thread(context_mgr.get_previous_context, "quarterly", lookback_weeks=52)  # ~1 year

        # Note: Quarterly reports focus on strategic trends, not individual CVEs
        # So CVE trends are less relevant, but we can still track high-level metrics

        # Use strategic analysis for quarterly reports
        # Extract breach reports from Intel471 data
        breach_data = [item for item in intel471_data if item.get("threat_type", "").upper() == "BREACH ALERT"]

        # Remove breach reports from intel471_data (they'll be in breach_data)
        intel471_data = [item for item in intel471_data if item.get("threat_type", "").upper() != "BREACH ALERT"]

        analysis = await agent.analyze_strategic(
            intel471_data=intel471_data,
            crowdstrike_data=crowdstrike_data,
            breach_data=breach_data if breach_data else None,
            illumina_context=illumina_context,
        )

        # Save analysis context for next quarter's report
        logger.info("Saving quarterly analysis context for historical tracking...")
        context_save_success = await asyncio.to_thread(
            context_mgr.save_analysis_context, "quarterly", date.today(), analysis
        )
        if context_save_success:
            logger.info("Quarterly analysis context saved successfully")
        else:
            logger.warning("Failed to save quarterly analysis context - future reports will lack trend data")

        # Optional: gate framework validation pass (feature-flagged)
        if _gate_framework_enabled():
            logger.info("Running gate framework validation over collected data (quarterly)...")
            publish_ok, gate_info, session = await asyncio.to_thread(
                run_gate_framework_over_collected_data,
                report_type="quarterly",
                data_by_source=data_by_source,
                osint_articles=data_by_source.get("OSINT", []),
                period_days=90,
                credentials={
                    "openai_endpoint": credentials["openai_endpoint"],
                    "openai_key": credentials["openai_key"],
                },
            )
            if not publish_ok:
                return func.HttpResponse(
                    json.dumps(
                        {
                            "status": "blocked",
                            "report_type": "quarterly",
                            "message": "Gate framework blocked report publication",
                            "gate_info": gate_info,
                        },
                        indent=2,
                    ),
                    mimetype="application/json",
                    status_code=409,
                )

        # Step 4: Generate Word document and upload to blob storage
        logger.info("Generating Quarterly Word document and uploading to Azure Blob Storage...")
        storage_account_name = credentials["storage_account_name"]
        storage_account_key = credentials["storage_account_key"]

        if not storage_account_name or not storage_account_key:
            raise ValueError("Storage account credentials not found in Key Vault")

        report_result = await asyncio.to_thread(
            create_and_upload_report,
            report_type="quarterly",
            analysis_result=analysis,
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key,
        )

        if not report_result.get("success", False):
            raise Exception(f"Report generation failed: {report_result.get('error', 'Unknown error')}")

        # Step 5: Return success response with download URL
        logger.info(f"Quarterly report generated successfully: {report_result['filename']}")
        return func.HttpResponse(
            json.dumps(
                {
                    "status": "success",
                    "report_type": "quarterly",
                    "message": "Quarterly strategic CTI report generated successfully",
                    "report_url": report_result["url"],
                    "filename": report_result["filename"],
                    "risk_assessment": analysis.get("risk_assessment", {}),
                    "collection_summary": {
                        source: {"success": result.success, "record_count": result.record_count, "error": result.error}
                        for source, result in collector_results.items()
                    },
                },
                indent=2,
            ),
            mimetype="application/json",
            status_code=200,
        )

    except Exception as e:
        correlation_id = str(uuid.uuid4())
        logger.error(f"Error generating quarterly report [correlation_id={correlation_id}]: {str(e)}", exc_info=True)
        return func.HttpResponse(
            json.dumps(
                {
                    "status": "error",
                    "report_type": "quarterly",
                    "message": "Failed to generate quarterly report. Check server logs for details.",
                    "correlation_id": correlation_id,
                },
                indent=2,
            ),
            mimetype="application/json",
            status_code=500,
        )


# Legacy endpoint - redirect to weekly for backwards compatibility
@app.function_name(name="GenerateCTIReport")
@app.route(route="GenerateCTIReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_cti_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Legacy endpoint - generates weekly report for backwards compatibility.

    Deprecated: Use GenerateWeeklyReport or GenerateQuarterlyReport instead.
    """
    logger.warning("Legacy GenerateCTIReport endpoint called - redirecting to GenerateWeeklyReport")
    return await generate_weekly_report(req)
