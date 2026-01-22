"""
Azure Key Vault helper for credential management.

Provides secure access to API keys and secrets stored in Azure Key Vault.
Uses Azure Managed Identity in production, supports local development
via Azure CLI authentication.
"""
import asyncio
import logging
from typing import Dict, Optional
from concurrent.futures import ThreadPoolExecutor

from azure.identity import DefaultAzureCredential  # type: ignore
from azure.keyvault.secrets import SecretClient  # type: ignore
from azure.core.exceptions import ResourceNotFoundError  # type: ignore

from config import azure_config
from models import APICredentials

logger = logging.getLogger(__name__)


# Module-level credential instance for reuse
# DefaultAzureCredential is thread-safe and should be reused
_credential: Optional[DefaultAzureCredential] = None
_client_cache: Dict[str, SecretClient] = {}


def _get_credential() -> DefaultAzureCredential:
    """
    Get or create the Azure credential instance.

    Returns:
        DefaultAzureCredential instance (reused across calls)
    """
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_client(vault_url: str) -> SecretClient:
    """
    Get or create a SecretClient for the given vault.

    Args:
        vault_url: URL of the Azure Key Vault

    Returns:
        SecretClient instance (cached per vault URL)
    """
    if vault_url not in _client_cache:
        credential = _get_credential()
        _client_cache[vault_url] = SecretClient(vault_url=vault_url, credential=credential)
    return _client_cache[vault_url]


def get_secret(vault_url: str, secret_name: str) -> str:
    """
    Retrieve a secret from Azure Key Vault using managed identity.

    Args:
        vault_url: URL of the Azure Key Vault
        secret_name: Name of the secret to retrieve

    Returns:
        The secret value as a string

    Raises:
        ResourceNotFoundError: If secret doesn't exist
        Exception: For other Key Vault errors
    """
    try:
        client = _get_client(vault_url)
        secret = client.get_secret(secret_name)
        logger.debug(f"Retrieved secret: {secret_name}")
        return secret.value.strip() if secret.value else ""

    except ResourceNotFoundError:
        logger.error(f"Secret '{secret_name}' not found in vault '{vault_url}'")
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve secret '{secret_name}' from vault '{vault_url}': {e}")
        raise


def get_all_api_keys(vault_url: Optional[str] = None) -> Dict[str, str]:
    """
    Retrieve all API keys needed for threat intelligence collection.

    Uses parallel fetching for improved performance.

    Args:
        vault_url: URL of the Azure Key Vault (defaults to config)

    Returns:
        Dictionary containing all API keys
    """
    vault_url = vault_url or azure_config.get_key_vault_url()
    logger.info(f"Retrieving all API keys from vault: {vault_url}")

    # Define all secrets to retrieve
    # All credentials stored in Key Vault for security
    secrets_map = {
        # Threat Intelligence API credentials
        'nvd_key': 'nvd-api-key',
        'threatq_key': 'threatq-api-key',
        'threatq_url': 'threatq-url',
        'intel471_email': 'intel471-email',
        'intel471_key': 'intel471-api-key',
        'crowdstrike_id': 'crowdstrike-client-id',
        'crowdstrike_secret': 'crowdstrike-client-secret',
        'crowdstrike_base_url': 'crowdstrike-base-url',
        'rapid7_key': 'rapid7-api-key',
        'rapid7_region': 'rapid7-region',
        # Azure OpenAI credentials
        'openai_key': 'openai-api-key',
        'openai_endpoint': 'openai-endpoint',
        # Azure Storage credentials
        'storage_account_name': 'storage-account-name',
        'storage_account_key': 'storage-account-key'
    }

    api_keys = {}

    # Fetch secrets in parallel using ThreadPoolExecutor
    # (Key Vault SDK is synchronous, so we use threads)
    def fetch_secret(item):
        key_name, secret_name = item
        try:
            return key_name, get_secret(vault_url, secret_name)
        except Exception as e:
            logger.error(f"Failed to retrieve API key '{key_name}' (secret: '{secret_name}'): {e}")
            raise Exception(f"Failed to retrieve required API key '{key_name}': {e}")

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(fetch_secret, secrets_map.items()))

    for key_name, value in results:
        api_keys[key_name] = value

    logger.info("Successfully retrieved all API keys")
    return api_keys


async def get_all_api_keys_async(vault_url: Optional[str] = None) -> Dict[str, str]:
    """
    Async wrapper for get_all_api_keys.

    Runs the synchronous Key Vault calls in a thread pool.

    Args:
        vault_url: URL of the Azure Key Vault (defaults to config)

    Returns:
        Dictionary containing all API keys
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_all_api_keys, vault_url)


def get_api_credentials(vault_url: Optional[str] = None) -> APICredentials:
    """
    Retrieve all API credentials as a typed dataclass.

    Args:
        vault_url: URL of the Azure Key Vault (defaults to config)

    Returns:
        APICredentials dataclass with all credentials
    """
    api_keys = get_all_api_keys(vault_url)
    return APICredentials(**api_keys)


async def get_api_credentials_async(vault_url: Optional[str] = None) -> APICredentials:
    """
    Async version of get_api_credentials.

    Args:
        vault_url: URL of the Azure Key Vault (defaults to config)

    Returns:
        APICredentials dataclass with all credentials
    """
    api_keys = await get_all_api_keys_async(vault_url)
    return APICredentials(**api_keys)


def clear_cache():
    """
    Clear the credential and client cache.

    Useful for testing or when credentials need to be refreshed.
    """
    global _credential, _client_cache
    _credential = None
    _client_cache = {}
    logger.info("Cleared Key Vault credential cache")
