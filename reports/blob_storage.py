"""
Azure Blob Storage utilities for report upload.

Shared functionality for uploading reports to Azure Blob Storage.
"""
from datetime import datetime, timedelta
import logging
from typing import Dict, Any

from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.core.credentials import AzureNamedKeyCredential

from config import report_config
from reports.base import BaseReportGenerator

logger = logging.getLogger(__name__)


def upload_to_blob(
    report: BaseReportGenerator,
    storage_account_name: str,
    storage_account_key: str,
    container_name: str | None = None
) -> str:
    """
    Upload a report document to Azure Blob Storage.

    Args:
        report: Report generator instance (must have called generate() first)
        storage_account_name: Azure Storage account name
        storage_account_key: Azure Storage account key
        container_name: Blob container name (default from config)

    Returns:
        Public SAS URL string
    """
    container_name = container_name or report_config.container_name

    try:
        filename = report.get_filename()
        logger.info(f"Uploading {filename} to Azure Blob Storage: {storage_account_name}/{container_name}")

        # Get document bytes
        doc_bytes = report.to_bytes()

        # Create BlobServiceClient using account URL
        account_url = f"https://{storage_account_name}.blob.core.windows.net"
        credential = AzureNamedKeyCredential(storage_account_name, storage_account_key)
        blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)

        # Get container client (create if doesn't exist)
        container_client = blob_service_client.get_container_client(container_name)
        try:
            container_client.create_container()
            logger.info(f"Created container: {container_name}")
        except Exception:
            # Container likely already exists
            pass

        # Upload blob
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=filename)
        blob_client.upload_blob(doc_bytes, overwrite=True)
        logger.info(f"Uploaded blob: {filename}")

        # Generate SAS URL
        sas_url = generate_sas_url(
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key,
            container_name=container_name,
            blob_name=filename
        )

        return sas_url

    except Exception as e:
        logger.error(f"Error uploading to blob storage: {str(e)}", exc_info=True)
        raise


def generate_sas_url(
    storage_account_name: str,
    storage_account_key: str,
    container_name: str,
    blob_name: str,
    expiry_days: int | None = None
) -> str:
    """
    Generate a SAS URL for a blob.

    Args:
        storage_account_name: Azure Storage account name
        storage_account_key: Azure Storage account key
        container_name: Blob container name
        blob_name: Blob name
        expiry_days: SAS token expiry in days (default from config)

    Returns:
        SAS URL string
    """
    expiry_days = expiry_days or report_config.sas_expiry_days

    sas_token = generate_blob_sas(
        account_name=storage_account_name,
        container_name=container_name,
        blob_name=blob_name,
        account_key=storage_account_key,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(days=expiry_days)
    )

    account_url = f"https://{storage_account_name}.blob.core.windows.net"
    sas_url = f"{account_url}/{container_name}/{blob_name}?{sas_token}"

    logger.info(f"Generated SAS URL (valid for {expiry_days} days)")
    return sas_url


def create_and_upload_report(
    report_type: str,
    analysis_result: Dict[str, Any],
    storage_account_name: str,
    storage_account_key: str
) -> Dict[str, Any]:
    """
    Generate a report and upload it to Azure Blob Storage.

    Args:
        report_type: Type of report to generate (e.g., "weekly")
        analysis_result: Dictionary containing analysis results
        storage_account_name: Azure Storage account name
        storage_account_key: Azure Storage account key

    Returns:
        Dictionary with keys: filename, url, success, error (if failed)
    """
    from reports.registry import get_report_generator

    try:
        logger.info(f"Creating and uploading {report_type} report")

        # Get report generator
        generator = get_report_generator(report_type)
        if generator is None:
            return {
                "filename": None,
                "url": None,
                "success": False,
                "error": f"Unknown report type: {report_type}"
            }

        # Generate report
        generator.generate(analysis_result)
        filename = generator.get_filename()

        # Upload to blob storage
        url = upload_to_blob(generator, storage_account_name, storage_account_key)

        logger.info(f"Report created and uploaded successfully: {filename}")

        return {
            "filename": filename,
            "url": url,
            "success": True
        }

    except Exception as e:
        logger.error(f"Error creating and uploading report: {str(e)}", exc_info=True)
        return {
            "filename": None,
            "url": None,
            "success": False,
            "error": str(e)
        }
