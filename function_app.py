"""
Azure Functions entry point for CTI Report Generator.

HTTP-triggered function that orchestrates the threat intelligence
collection, analysis, and report generation pipeline.
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


@app.function_name(name="GenerateCTIReport")
@app.route(route="GenerateCTIReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_cti_report(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate a weekly CTI report.

    Pipeline:
    1. Retrieve credentials from Key Vault
    2. Collect threat data from all enabled sources (parallel)
    3. Analyze threats with AI
    4. Generate Word document
    5. Upload to Azure Blob Storage
    6. Return download URL

    Returns:
        HTTP response with report URL and statistics
    """
    logging.info('CTI Report Generation function triggered')

    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = azure_config.get_key_vault_url()
        logging.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = get_all_api_keys(vault_url)

        # Step 2: Collect threat intelligence data from all sources in parallel
        logging.info('Collecting threat intelligence data from enabled sources...')
        collector_results = await collect_all(credentials)

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

        # Step 3: Analyze threats with AI agent
        deployment_name = analysis_config.deployment_name
        logging.info(f'Analyzing threat data with {deployment_name}...')

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
        # Storage credentials come from Key Vault (same as other secrets)
        logging.info('Generating Word document and uploading to Azure Blob Storage...')
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
        logging.info(f'Report generated successfully: {report_result["filename"]}')
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'message': 'CTI report generated successfully',
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
        logging.error(f'Error generating CTI report: {str(e)}', exc_info=True)
        return func.HttpResponse(
            json.dumps({
                'status': 'error',
                'message': f'Failed to generate report: {str(e)}'
            }, indent=2),
            mimetype='application/json',
            status_code=500
        )
