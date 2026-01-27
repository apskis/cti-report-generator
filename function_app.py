"""
Azure Functions entry point for CTI Report Generator.

HTTP-triggered functions for generating weekly tactical and quarterly strategic
threat intelligence reports.
"""
import azure.functions as func  # type: ignore
import logging
import json

from keyvault_helper import get_all_api_keys
from collectors import collect_all, get_data_by_source
from threat_analyst_agent import ThreatAnalystAgent
from reports.blob_storage import create_and_upload_report
from config import azure_config, analysis_config

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
    logging.info('Weekly CTI Report Generation triggered')

    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = azure_config.get_key_vault_url()
        logging.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = get_all_api_keys(vault_url)

        # Step 2: Collect threat intelligence data from all sources in parallel
        logging.info('Collecting threat intelligence data from enabled sources...')
        collector_results = await collect_all(credentials, report_type="weekly")

        # Extract data from results
        data_by_source = get_data_by_source(collector_results)

        # Get data for each source (with fallback to empty list)
        cve_data = data_by_source.get("NVD", [])
        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])
        threatq_data = data_by_source.get("ThreatQ", [])
        rapid7_data = data_by_source.get("Rapid7", [])

        # Log collection statistics
        logging.info(
            f'Data collected - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, '
            f'CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, '
            f'Rapid7: {len(rapid7_data)}'
        )

        # Log any collection failures
        for source, result in collector_results.items():
            if not result.success:
                logging.warning(f"Collection failed for {source}: {result.error}")

        # Step 3: Analyze threats with AI agent (tactical mode)
        deployment_name = analysis_config.deployment_name
        logging.info(f'Analyzing threat data with {deployment_name} (tactical mode)...')

        agent = ThreatAnalystAgent(
            credentials['openai_endpoint'],
            credentials['openai_key'],
            deployment_name=deployment_name
        )

        analysis = await agent.analyze_threats(
            cve_data,
            intel471_data,
            crowdstrike_data,
            threatq_data,
            rapid7_data
        )

        # Step 4: Generate Word document and upload to blob storage
        logging.info('Generating Weekly Word document and uploading to Azure Blob Storage...')
        storage_account_name = credentials['storage_account_name']
        storage_account_key = credentials['storage_account_key']

        if not storage_account_name or not storage_account_key:
            raise ValueError("Storage account credentials not found in Key Vault")

        report_result = create_and_upload_report(
            report_type="weekly",
            analysis_result=analysis,
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key
        )

        if not report_result.get("success", False):
            raise Exception(f"Report generation failed: {report_result.get('error', 'Unknown error')}")

        # Step 5: Return success response with download URL
        logging.info(f'Weekly report generated successfully: {report_result["filename"]}')
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'report_type': 'weekly',
                'message': 'Weekly CTI report generated successfully',
                'report_url': report_result['url'],
                'filename': report_result['filename'],
                'statistics': analysis.get('statistics', {}),
                'collection_summary': {
                    source: {
                        'success': result.success,
                        'record_count': result.record_count,
                        'error': result.error
                    }
                    for source, result in collector_results.items()
                }
            }, indent=2),
            mimetype='application/json',
            status_code=200
        )

    except Exception as e:
        logging.error(f'Error generating weekly report: {str(e)}', exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'status': 'error',
                'report_type': 'weekly',
                'message': f'Failed to generate weekly report: {str(e)}'
            }, indent=2),
            mimetype='application/json',
            status_code=500
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
    logging.info('Quarterly Strategic CTI Report Generation triggered')

    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = azure_config.get_key_vault_url()
        logging.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = get_all_api_keys(vault_url)

        # Step 2: Collect threat intelligence data
        # For quarterly reports, we focus on Intel471 and CrowdStrike
        logging.info('Collecting strategic threat intelligence data...')
        collector_results = await collect_all(credentials, report_type="quarterly")

        # Extract data from results
        data_by_source = get_data_by_source(collector_results)

        # Primary sources for strategic analysis
        intel471_data = data_by_source.get("Intel471", [])
        crowdstrike_data = data_by_source.get("CrowdStrike", [])

        # Log collection statistics
        logging.info(
            f'Strategic data collected - Intel471: {len(intel471_data)}, '
            f'CrowdStrike: {len(crowdstrike_data)}'
        )

        # Log any collection failures
        for source, result in collector_results.items():
            if not result.success:
                logging.warning(f"Collection failed for {source}: {result.error}")

        # Step 3: Analyze threats with AI agent (strategic mode)
        deployment_name = analysis_config.deployment_name
        logging.info(f'Analyzing threat data with {deployment_name} (strategic mode)...')

        agent = ThreatAnalystAgent(
            credentials['openai_endpoint'],
            credentials['openai_key'],
            deployment_name=deployment_name
        )

        # Use strategic analysis for quarterly reports
        analysis = await agent.analyze_strategic(
            intel471_data=intel471_data,
            crowdstrike_data=crowdstrike_data,
            breach_data=None  # Can be populated from external breach feed
        )

        # Step 4: Generate Word document and upload to blob storage
        logging.info('Generating Quarterly Word document and uploading to Azure Blob Storage...')
        storage_account_name = credentials['storage_account_name']
        storage_account_key = credentials['storage_account_key']

        if not storage_account_name or not storage_account_key:
            raise ValueError("Storage account credentials not found in Key Vault")

        report_result = create_and_upload_report(
            report_type="quarterly",
            analysis_result=analysis,
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key
        )

        if not report_result.get("success", False):
            raise Exception(f"Report generation failed: {report_result.get('error', 'Unknown error')}")

        # Step 5: Return success response with download URL
        logging.info(f'Quarterly report generated successfully: {report_result["filename"]}')
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'report_type': 'quarterly',
                'message': 'Quarterly strategic CTI report generated successfully',
                'report_url': report_result['url'],
                'filename': report_result['filename'],
                'risk_assessment': analysis.get('risk_assessment', {}),
                'collection_summary': {
                    'Intel471': {
                        'success': collector_results.get('Intel471', {}).success if hasattr(collector_results.get('Intel471', {}), 'success') else False,
                        'record_count': len(intel471_data)
                    },
                    'CrowdStrike': {
                        'success': collector_results.get('CrowdStrike', {}).success if hasattr(collector_results.get('CrowdStrike', {}), 'success') else False,
                        'record_count': len(crowdstrike_data)
                    }
                }
            }, indent=2),
            mimetype='application/json',
            status_code=200
        )

    except Exception as e:
        logging.error(f'Error generating quarterly report: {str(e)}', exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'status': 'error',
                'report_type': 'quarterly',
                'message': f'Failed to generate quarterly report: {str(e)}'
            }, indent=2),
            mimetype='application/json',
            status_code=500
        )


# Legacy endpoint - redirect to weekly for backwards compatibility
@app.function_name(name="GenerateCTIReport")
@app.route(route="GenerateCTIReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_cti_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Legacy endpoint - generates weekly report for backwards compatibility.

    Deprecated: Use GenerateWeeklyReport or GenerateQuarterlyReport instead.
    """
    logging.warning('Legacy GenerateCTIReport endpoint called - redirecting to GenerateWeeklyReport')
    return await generate_weekly_report(req)
