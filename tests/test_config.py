"""
Unit tests for src/core/config.py.
"""
import os
import pytest
from unittest.mock import patch

from src.core.config import AzureConfig, get_enabled_collectors, DEFAULT_ENABLED_COLLECTORS


class TestAzureConfig:
    def test_raises_when_key_vault_url_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            # Ensure KEY_VAULT_URL is not in env
            os.environ.pop("KEY_VAULT_URL", None)
            with pytest.raises(EnvironmentError, match="KEY_VAULT_URL"):
                AzureConfig.get_key_vault_url()

    def test_returns_url_when_set(self):
        with patch.dict(os.environ, {"KEY_VAULT_URL": "https://my-vault.vault.azure.net/"}):
            assert AzureConfig.get_key_vault_url() == "https://my-vault.vault.azure.net/"


class TestGetEnabledCollectors:
    def test_default_collectors(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ENABLED_COLLECTORS", None)
            result = get_enabled_collectors()
            assert result == DEFAULT_ENABLED_COLLECTORS
            assert "threatq" not in result

    def test_custom_collectors_from_env(self):
        with patch.dict(os.environ, {"ENABLED_COLLECTORS": "nvd, threatq"}):
            result = get_enabled_collectors()
            assert result == ["nvd", "threatq"]

    def test_returns_new_list_each_call(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ENABLED_COLLECTORS", None)
            a = get_enabled_collectors()
            b = get_enabled_collectors()
            assert a == b
            assert a is not b  # Should be independent lists
