"""
Unit tests for src/core/keyvault.py — Key Vault credential retrieval.
"""
import pytest
from unittest.mock import patch, MagicMock

from azure.core.exceptions import ResourceNotFoundError

from src.core.keyvault import get_secret, get_all_api_keys, clear_cache


@pytest.fixture(autouse=True)
def _clear_keyvault_cache():
    """Clear module-level caches between tests."""
    clear_cache()
    yield
    clear_cache()


VAULT_URL = "https://kv-test.vault.azure.net/"


class TestGetSecret:
    @patch("src.core.keyvault._get_client")
    def test_retrieves_and_strips_secret(self, mock_get_client):
        mock_client = MagicMock()
        mock_secret = MagicMock()
        mock_secret.value = "  my-secret-value  "
        mock_client.get_secret.return_value = mock_secret
        mock_get_client.return_value = mock_client

        result = get_secret(VAULT_URL, "test-secret")
        assert result == "my-secret-value"
        mock_client.get_secret.assert_called_once_with("test-secret")

    @patch("src.core.keyvault._get_client")
    def test_returns_empty_for_none_value(self, mock_get_client):
        mock_client = MagicMock()
        mock_secret = MagicMock()
        mock_secret.value = None
        mock_client.get_secret.return_value = mock_secret
        mock_get_client.return_value = mock_client

        result = get_secret(VAULT_URL, "empty-secret")
        assert result == ""

    @patch("src.core.keyvault._get_client")
    def test_raises_on_not_found(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.get_secret.side_effect = ResourceNotFoundError("not found")
        mock_get_client.return_value = mock_client

        with pytest.raises(ResourceNotFoundError):
            get_secret(VAULT_URL, "missing-secret")


class TestGetAllApiKeys:
    @patch("src.core.keyvault.get_secret")
    @patch("src.core.config.AzureConfig.get_key_vault_url", return_value=VAULT_URL)
    def test_fetches_all_enabled_collector_secrets(self, mock_vault_url, mock_get_secret):
        mock_get_secret.return_value = "test-value"
        keys = get_all_api_keys(VAULT_URL)

        # Should include required keys (openai, storage) and enabled collector keys
        assert "openai_key" in keys
        assert "openai_endpoint" in keys
        assert "storage_account_name" in keys
        assert "nvd_key" in keys

    @patch("src.core.keyvault.get_secret")
    @patch("src.core.config.AzureConfig.get_key_vault_url", return_value=VAULT_URL)
    def test_optional_threatq_missing_returns_empty_string(self, mock_vault_url, mock_get_secret):
        def side_effect(vault_url, secret_name):
            if "threatq" in secret_name:
                raise ResourceNotFoundError("not found")
            return "test-value"

        mock_get_secret.side_effect = side_effect

        # Enable ThreatQ for this test
        with patch("src.core.config.get_enabled_collectors", return_value=["nvd", "threatq"]):
            keys = get_all_api_keys(VAULT_URL)

        assert keys.get("threatq_key") == ""

    @patch("src.core.keyvault.get_secret")
    @patch("src.core.config.AzureConfig.get_key_vault_url", return_value=VAULT_URL)
    def test_required_secret_missing_raises(self, mock_vault_url, mock_get_secret):
        def side_effect(vault_url, secret_name):
            if secret_name == "openai-api-key":
                raise ResourceNotFoundError("not found")
            return "test-value"

        mock_get_secret.side_effect = side_effect

        with pytest.raises(RuntimeError, match="Failed to retrieve required API key"):
            get_all_api_keys(VAULT_URL)
