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

from src.agents.context_manager import AgentContextManager
from src.agents.threat_analyst import ThreatAnalystAgent
from src.collectors import collect_all, get_data_by_source
from src.core.config import analysis_config, azure_config, customer_profile
from src.core.keyvault import get_all_api_keys
from src.gates.pipeline_hook import run_gate_framework_over_collected_data
from src.reports.blob_storage import create_and_upload_report
from src.utils.cache_manager import CacheManager

logger = logging.getLogger(__name__)


def _gate_framework_enabled() -> bool:
    from src.core.config import get_feature_config

    return get_feature_config().gate_framework_enabled


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


def _merge_exposure_into_analysis(analysis: dict, crowdstrike_data: list) -> None:
    """Merge CrowdStrike (Spotlight) device counts into cve_analysis for the Exposure column."""
    cve_analysis = analysis.get("cve_analysis") or []
    if not cve_analysis:
        return

    cs_counts = _extract_crowdstrike_cve_counts(crowdstrike_data) if crowdstrike_data else {}

    for cve in cve_analysis:
        cve_id = cve.get("cve_id")
        if not cve_id:
            continue
        if cve_id in cs_counts:
            cve["server_count"] = cs_counts[cve_id]


async def _fetch_credentials_and_collect(report_type: str):
    """Shared pipeline prefix: Key Vault credentials + parallel collection."""
    vault_url = azure_config.get_key_vault_url()
    logger.info(f"Retrieving credentials from Key Vault: {vault_url}")
    credentials = await asyncio.to_thread(get_all_api_keys, vault_url)

    logger.info(f"Collecting threat intelligence data for {report_type} report...")
    collector_results = await collect_all(credentials, report_type=report_type)
    data_by_source = get_data_by_source(collector_results)

    for source, result in collector_results.items():
        if not result.success:
            logger.warning(f"Collection failed for {source}: {result.error}")

    return credentials, collector_results, data_by_source


async def _run_gate_pass(report_type, data_by_source, osint_articles, period_days, credentials, analysis):
    """Run the (feature-flagged) gate framework. Returns (publish_ok, gate_info)."""
    if not _gate_framework_enabled():
        return True, None
    logger.info(f"Running gate framework validation over collected data ({report_type})...")
    publish_ok, gate_info, _session = await asyncio.to_thread(
        run_gate_framework_over_collected_data,
        report_type=report_type,
        data_by_source=data_by_source,
        osint_articles=osint_articles,
        period_days=period_days,
        credentials={"openai_endpoint": credentials["openai_endpoint"], "openai_key": credentials["openai_key"]},
        analysis=analysis,
    )
    return publish_ok, gate_info


async def _upload_report(report_type: str, analysis: dict, credentials: dict) -> dict:
    """Render the .docx and upload it to blob storage; raise on failure."""
    storage_account_name = credentials["storage_account_name"]
    storage_account_key = credentials["storage_account_key"]
    if not storage_account_name or not storage_account_key:
        raise ValueError("Storage account credentials not found in Key Vault")

    report_result = await asyncio.to_thread(
        create_and_upload_report,
        report_type=report_type,
        analysis_result=analysis,
        storage_account_name=storage_account_name,
        storage_account_key=storage_account_key,
    )
    if not report_result.get("success", False):
        raise RuntimeError(f"Report generation failed: {report_result.get('error', 'Unknown error')}")
    return report_result


def _json_response(body: dict, status_code: int) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(body, indent=2), mimetype="application/json", status_code=status_code)


def _blocked_response(report_type: str, gate_info: dict) -> func.HttpResponse:
    return _json_response(
        {
            "status": "blocked",
            "report_type": report_type,
            "message": "Gate framework blocked report publication",
            "gate_info": gate_info,
        },
        409,
    )


def _success_response(report_type, message, report_result, collector_results, extra) -> func.HttpResponse:
    body = {
        "status": "success",
        "report_type": report_type,
        "message": message,
        "report_url": report_result["url"],
        "filename": report_result["filename"],
        "collection_summary": {
            source: {"success": r.success, "record_count": r.record_count, "error": r.error}
            for source, r in collector_results.items()
        },
    }
    body.update(extra)
    return _json_response(body, 200)


def _error_response(report_type: str, e: Exception) -> func.HttpResponse:
    correlation_id = str(uuid.uuid4())
    logger.error(f"Error generating {report_type} report [correlation_id={correlation_id}]: {str(e)}", exc_info=True)
    return _json_response(
        {
            "status": "error",
            "report_type": report_type,
            "message": f"Failed to generate {report_type} report. Check server logs for details.",
            "correlation_id": correlation_id,
        },
        500,
    )


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
        credentials, collector_results, data_by_source = await _fetch_credentials_and_collect("weekly")

        cve_data = data_by_source.get("NVD", [])
        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])
        osint_data = data_by_source.get("OSINT", [])
        logger.info(
            f"Data collected - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, "
            f"CrowdStrike: {len(crowdstrike_data)}, OSINT: {len(osint_data)}"
        )

        # Analyze threats (tactical mode) + historical context
        deployment_name = analysis_config.deployment_name
        logger.info(f"Analyzing threat data with {deployment_name} (tactical mode with context)...")
        agent = ThreatAnalystAgent(
            credentials["openai_endpoint"], credentials["openai_key"], deployment_name=deployment_name
        )
        context_mgr = AgentContextManager(
            CacheManager(credentials["storage_account_name"], credentials["storage_account_key"])
        )

        logger.info("Retrieving historical contexts for trend analysis...")
        previous_contexts = await asyncio.to_thread(context_mgr.get_previous_context, "weekly", lookback_weeks=4)
        cve_trends = context_mgr.calculate_cve_trends(cve_data, previous_contexts)
        logger.info(f"CVE Trends: {cve_trends.get('trend_summary', 'N/A')}")

        analysis = await agent.analyze_threats_with_context(
            cve_data,
            intel471_data,
            crowdstrike_data,
            osint_data,
            previous_contexts=previous_contexts,
            cve_trends=cve_trends,
            actor_trends=None,  # actors are extracted from the analysis afterward
        )
        # Merge CrowdStrike (Spotlight) device counts into CVE analysis for Exposure column
        _merge_exposure_into_analysis(analysis, crowdstrike_data)

        logger.info("Saving analysis context for historical tracking...")
        if not await asyncio.to_thread(context_mgr.save_analysis_context, "weekly", date.today(), analysis):
            logger.warning("Failed to save analysis context - future reports will lack trend data")

        publish_ok, gate_info = await _run_gate_pass("weekly", data_by_source, osint_data, 7, credentials, analysis)
        if not publish_ok:
            return _blocked_response("weekly", gate_info)

        logger.info("Generating Weekly Word document and uploading to Azure Blob Storage...")
        report_result = await _upload_report("weekly", analysis, credentials)

        logger.info(f"Weekly report generated successfully: {report_result['filename']}")
        return _success_response(
            "weekly",
            "Weekly CTI report generated successfully",
            report_result,
            collector_results,
            {"statistics": analysis.get("statistics", {})},
        )

    except Exception as e:
        return _error_response("weekly", e)


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
        credentials, collector_results, data_by_source = await _fetch_credentials_and_collect("quarterly")

        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])

        # Extract company context from the company-OSINT collector
        company_osint_data = data_by_source.get(customer_profile.osint_source_name, [])
        illumina_context = company_osint_data[0].get("illumina_context", "") if company_osint_data else ""
        if not illumina_context:
            logger.warning(f"{customer_profile.name} OSINT context is empty - AI will use fallback context")
        logger.info(
            f"Strategic data collected - Intel471: {len(intel471_data)}, "
            f"CrowdStrike: {len(crowdstrike_data)}, company OSINT: {len(illumina_context)} chars"
        )

        # Analyze threats (strategic mode) + historical context
        deployment_name = analysis_config.deployment_name
        logger.info(f"Analyzing threat data with {deployment_name} (strategic mode with context)...")
        agent = ThreatAnalystAgent(
            credentials["openai_endpoint"], credentials["openai_key"], deployment_name=deployment_name
        )
        context_mgr = AgentContextManager(
            CacheManager(credentials["storage_account_name"], credentials["storage_account_key"])
        )
        logger.info("Retrieving historical quarterly contexts for trend analysis...")
        await asyncio.to_thread(context_mgr.get_previous_context, "quarterly", lookback_weeks=52)  # ~1 year

        # Split breach alerts out of the Intel471 stream
        breach_data = [item for item in intel471_data if item.get("threat_type", "").upper() == "BREACH ALERT"]
        intel471_data = [item for item in intel471_data if item.get("threat_type", "").upper() != "BREACH ALERT"]

        analysis = await agent.analyze_strategic(
            intel471_data=intel471_data,
            crowdstrike_data=crowdstrike_data,
            breach_data=breach_data if breach_data else None,
            illumina_context=illumina_context,
        )

        logger.info("Saving quarterly analysis context for historical tracking...")
        if not await asyncio.to_thread(context_mgr.save_analysis_context, "quarterly", date.today(), analysis):
            logger.warning("Failed to save quarterly analysis context - future reports will lack trend data")

        publish_ok, gate_info = await _run_gate_pass(
            "quarterly", data_by_source, data_by_source.get("OSINT", []), 90, credentials, analysis
        )
        if not publish_ok:
            return _blocked_response("quarterly", gate_info)

        logger.info("Generating Quarterly Word document and uploading to Azure Blob Storage...")
        report_result = await _upload_report("quarterly", analysis, credentials)

        logger.info(f"Quarterly report generated successfully: {report_result['filename']}")
        return _success_response(
            "quarterly",
            "Quarterly strategic CTI report generated successfully",
            report_result,
            collector_results,
            {"risk_assessment": analysis.get("risk_assessment", {})},
        )

    except Exception as e:
        return _error_response("quarterly", e)


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
