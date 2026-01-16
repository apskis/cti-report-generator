import azure.functions as func  # type: ignore
import logging
import asyncio
import json
import os

from keyvault_helper import get_all_api_keys
from api_collectors import get_nvd_cves, get_intel471_data, get_crowdstrike_data, get_threatq_data, get_rapid7_data
from threat_analyst_agent import ThreatAnalystAgent
from report_generator import create_and_upload_report

app = func.FunctionApp()

@app.function_name(name="GenerateCTIReport")
@app.route(route="GenerateCTIReport", auth_level=func.AuthLevel.FUNCTION)
async def generate_cti_report(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('CTI Report Generation function triggered')
    
    try:
        # Step 1: Get API credentials from Key Vault
        vault_url = "https://kv-cti-reporting.vault.azure.net/"
        logging.info(f"Retrieving credentials from Key Vault: {vault_url}")
        credentials = get_all_api_keys(vault_url)
        
        # Step 2: Collect threat intelligence data from all sources in parallel
        logging.info('Collecting threat intelligence data from 5 sources...')
        results = await asyncio.gather(
            get_nvd_cves(credentials['nvd_key']),
            get_intel471_data(credentials['intel471_email'], credentials['intel471_key']),
            get_crowdstrike_data(credentials['crowdstrike_id'], credentials['crowdstrike_secret'], credentials['crowdstrike_base_url']),
            get_threatq_data(credentials['threatq_key'], credentials['threatq_url']),
            get_rapid7_data(credentials['rapid7_key'], credentials['rapid7_region']),
            return_exceptions=True
        )
        
        cve_data, intel471_data, crowdstrike_data, threatq_data, rapid7_data = results
        
        # Handle exceptions in results
        cve_data = cve_data if not isinstance(cve_data, Exception) else []
        intel471_data = intel471_data if not isinstance(intel471_data, Exception) else []
        crowdstrike_data = crowdstrike_data if not isinstance(crowdstrike_data, Exception) else []
        threatq_data = threatq_data if not isinstance(threatq_data, Exception) else []
        rapid7_data = rapid7_data if not isinstance(rapid7_data, Exception) else []
        
        logging.info(f'Data collected - CVEs: {len(cve_data)}, Intel471: {len(intel471_data)}, CrowdStrike: {len(crowdstrike_data)}, ThreatQ: {len(threatq_data)}, Rapid7: {len(rapid7_data)}')
        
        # Step 3: Analyze threats with AI agent
        logging.info('Analyzing threat data with GPT-5.2...')
        agent = ThreatAnalystAgent(
            credentials['openai_endpoint'],
            credentials['openai_key'],
            deployment_name='gpt-5.2-cti'
        )
        
        analysis = await agent.analyze_threats(
            cve_data, 
            intel471_data, 
            crowdstrike_data, 
            threatq_data, 
            rapid7_data
        )
        
        # Step 4: Generate Word document and upload to blob storage
        logging.info('Generating Word document and uploading to Azure Blob Storage...')
        storage_account_name = os.environ['STORAGE_ACCOUNT_NAME']
        storage_account_key = os.environ['STORAGE_ACCOUNT_KEY']
        
        report_result = create_and_upload_report(
            analysis,
            storage_account_name,
            storage_account_key
        )
        
        # Step 5: Return success response with download URL
        logging.info(f'Report generated successfully: {report_result["filename"]}')
        return func.HttpResponse(
            json.dumps({
                'status': 'success',
                'message': 'CTI report generated successfully',
                'report_url': report_result['url'],
                'filename': report_result['filename'],
                'statistics': analysis.get('statistics', {})
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