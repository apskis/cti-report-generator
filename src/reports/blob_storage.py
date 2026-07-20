"""
Azure Blob Storage utilities for report upload.

Shared functionality for uploading reports to Azure Blob Storage.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from azure.core.credentials import AzureNamedKeyCredential
from azure.core.exceptions import AzureError, ResourceExistsError
from azure.storage.blob import BlobSasPermissions, BlobServiceClient, generate_blob_sas

from src.core.config import report_config
from src.reports.base import BaseReportGenerator

logger = logging.getLogger(__name__)


def _generate_user_delegation_sas_url(
    blob_service_client: BlobServiceClient,
    storage_account_name: str,
    container_name: str,
    blob_name: str,
    expiry_days: int,
) -> str:
    """Generate a SAS URL signed with an AAD user-delegation key.

    Unlike an account-key SAS, a user-delegation SAS is backed by Azure AD and can
    be revoked (by revoking the delegation key or the identity's role) without
    rotating the storage account key. Requires the caller's identity to hold a data
    role such as "Storage Blob Data Contributor" on the account.
    """
    start_time = datetime.now(UTC)
    expiry_time = start_time + timedelta(days=expiry_days)
    user_delegation_key = blob_service_client.get_user_delegation_key(
        key_start_time=start_time, key_expiry_time=expiry_time
    )
    sas_token = generate_blob_sas(
        account_name=storage_account_name,
        container_name=container_name,
        blob_name=blob_name,
        user_delegation_key=user_delegation_key,
        permission=BlobSasPermissions(read=True),
        start=start_time,
        expiry=expiry_time,
    )
    account_url = f"https://{storage_account_name}.blob.core.windows.net"
    sas_url = f"{account_url}/{container_name}/{blob_name}?{sas_token}"
    logger.info(f"Generated user-delegation SAS URL (valid for {expiry_days} days)")
    return sas_url


def upload_to_blob(
    report: BaseReportGenerator, storage_account_name: str, storage_account_key: str, container_name: str | None = None
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
        # Get document bytes
        doc_bytes = report.to_bytes()

        # Get filename with report week start if available
        if hasattr(report, "_report_week_start"):
            filename = report.get_filename(report_week_start=report._report_week_start)
        else:
            filename = report.get_filename()

        logger.info(f"Uploading {filename} to Azure Blob Storage: {storage_account_name}/{container_name}")

        account_url = f"https://{storage_account_name}.blob.core.windows.net"
        use_delegation = report_config.use_user_delegation_sas

        # Create BlobServiceClient. For user-delegation SAS we must authenticate with
        # Azure AD (DefaultAzureCredential); otherwise use the storage account key.
        if use_delegation:
            from azure.identity import DefaultAzureCredential

            blob_service_client = BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())
        else:
            credential = AzureNamedKeyCredential(storage_account_name, storage_account_key)
            blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)

        # Get container client (create if doesn't exist)
        container_client = blob_service_client.get_container_client(container_name)
        try:
            container_client.create_container()
            logger.info(f"Created container: {container_name}")
        except ResourceExistsError:
            pass  # Container already exists

        # Upload blob
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=filename)
        blob_client.upload_blob(doc_bytes, overwrite=True)
        logger.info(f"Uploaded blob: {filename}")

        # Generate SAS URL. Prefer a revocable user-delegation SAS when enabled;
        # fall back to account-key signing so report delivery is not lost on a
        # transient AAD/RBAC misconfiguration (the fallback is logged loudly).
        if use_delegation:
            try:
                return _generate_user_delegation_sas_url(
                    blob_service_client=blob_service_client,
                    storage_account_name=storage_account_name,
                    container_name=container_name,
                    blob_name=filename,
                    expiry_days=report_config.sas_expiry_days,
                )
            except AzureError as e:
                logger.error(
                    "User-delegation SAS generation failed; falling back to account-key SAS. "
                    f"Check the function identity's Storage Blob Data role. Error: {e}",
                    exc_info=True,
                )

        return generate_sas_url(
            storage_account_name=storage_account_name,
            storage_account_key=storage_account_key,
            container_name=container_name,
            blob_name=filename,
        )

    except AzureError as e:
        logger.error(f"Azure storage error uploading report: {e}", exc_info=True)
        raise
    except (ValueError, OSError) as e:
        logger.error(f"Error preparing report for upload: {e}", exc_info=True)
        raise


def generate_sas_url(
    storage_account_name: str,
    storage_account_key: str,
    container_name: str,
    blob_name: str,
    expiry_days: int | None = None,
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
        expiry=datetime.now(UTC) + timedelta(days=expiry_days),
    )

    account_url = f"https://{storage_account_name}.blob.core.windows.net"
    sas_url = f"{account_url}/{container_name}/{blob_name}?{sas_token}"

    logger.info(f"Generated SAS URL (valid for {expiry_days} days)")
    return sas_url


def create_and_upload_report(
    report_type: str, analysis_result: dict[str, Any], storage_account_name: str, storage_account_key: str
) -> dict[str, Any]:
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
    from src.reports.registry import get_report_generator

    try:
        logger.info(f"Creating and uploading {report_type} report")

        # Get report generator
        generator = get_report_generator(report_type)
        if generator is None:
            return {"filename": None, "url": None, "success": False, "error": f"Unknown report type: {report_type}"}

        # Generate report
        generator.generate(analysis_result)

        # Get filename with report week start if available
        if hasattr(generator, "_report_week_start"):
            filename = generator.get_filename(report_week_start=generator._report_week_start)
        else:
            filename = generator.get_filename()

        # Upload to blob storage
        url = upload_to_blob(generator, storage_account_name, storage_account_key)

        logger.info(f"Report created and uploaded successfully: {filename}")

        return {"filename": filename, "url": url, "success": True}

    except (AzureError, ValueError, OSError) as e:
        logger.error(f"Error creating and uploading report: {e}", exc_info=True)
        return {"filename": None, "url": None, "success": False, "error": str(e)}
