import logging
from azure.identity import DefaultAzureCredential  # type: ignore
from azure.keyvault.secrets import SecretClient  # type: ignore
from azure.core.exceptions import ResourceNotFoundError  # type: ignore

logger = logging.getLogger(__name__)


def get_secret(vault_url: str, secret_name: str) -> str:
    """
    Retrieve a secret from Azure Key Vault using managed identity.
    
    Args:
        vault_url: URL of the Azure Key Vault
        secret_name: Name of the secret to retrieve
        
    Returns:
        The secret value as a string
    """
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        
        secret = client.get_secret(secret_name)
        logger.info(f"Retrieved secret: {secret_name}")
        return secret.value.strip() if secret.value else ""
        
    except ResourceNotFoundError:
        logger.error(f"Secret '{secret_name}' not found in vault '{vault_url}'")
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve secret '{secret_name}' from vault '{vault_url}': {e}")
        raise


def get_all_api_keys(vault_url: str) -> dict:
    """
    Retrieve all API keys needed for threat intelligence collection.
    
    Args:
        vault_url: URL of the Azure Key Vault
        
    Returns:
        Dictionary containing all API keys
    """
    logger.info(f"Retrieving all API keys from vault: {vault_url}")
    
    api_keys = {}
    
    # Define all secrets to retrieve
    secrets_map = {
        'nvd_key': 'nvd-api-key',
        'threatq_key': 'threatq-api-key',
        'threatq_url': 'threatq-url',
        'intel471_email': 'intel471-email',
        'intel471_key': 'intel471-api-key',
        'crowdstrike_id': 'crowdstrike-client-id',
        'crowdstrike_secret': 'crowdstrike-client-secret',
        'crowdstrike_base_url': 'crowdstrike-base-url',  # NEW LINE
        'rapid7_key': 'rapid7-api-key',
        'rapid7_region': 'rapid7-region',
        'openai_key': 'openai-api-key',
        'openai_endpoint': 'openai-endpoint'
    }
    
    # Retrieve each secret
    for key_name, secret_name in secrets_map.items():
        try:
            api_keys[key_name] = get_secret(vault_url, secret_name)
        except Exception as e:
            logger.error(f"Failed to retrieve API key '{key_name}' (secret: '{secret_name}'): {e}")
            raise Exception(f"Failed to retrieve required API key '{key_name}': {e}")
    
    logger.info("Successfully retrieved all API keys")
    return api_keys