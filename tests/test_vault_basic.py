#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the basic vault functionality.

Author: ansible-age-vault
License: MIT
"""
import os
from unittest.mock import Mock, patch

import pytest

from ansible_age_vault.vault import AgeVaultPlugin
from ansible_age_vault.exceptions import AgeVaultError

# Test file paths - defined here since imports from fixtures are failing
TEST_KEY_PATH = os.path.join(os.path.dirname(__file__), '.age-key.txt')
AGE_RECIPIENTS_PATH = os.path.join(os.path.dirname(__file__), '.age-recipients')


class TestAgeVaultPlugin:
    """Test cases for AgeVaultPlugin."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = AgeVaultPlugin()

    def test_vault_id(self):
        """Test vault_id property."""
        assert self.plugin.vault_id == "age"

    def test_get_recipients_from_vault_id_params(self):
        """Test _get_recipients with vault-id parameters."""
        # Test comma-separated recipients
        recipients = self.plugin._get_recipients("age1abc123,age1def456")
        assert recipients == ["age1abc123", "age1def456"]

        # Test single recipient
        recipients = self.plugin._get_recipients("age1single")
        assert recipients == ["age1single"]

        # Test recipients with spaces
        recipients = self.plugin._get_recipients("age1abc123, age1def456 ,age1ghi789")
        assert recipients == ["age1abc123", "age1def456", "age1ghi789"]

    def test_get_recipients_from_file(self):
        """Test _get_recipients from file."""
        recipients = self.plugin._get_recipients(AGE_RECIPIENTS_PATH)
        assert len(recipients) == 1  # Based on our test file content
        assert all(recipient.startswith("age1") for recipient in recipients)

    def test_get_recipients_colon_format(self):
        """Test _get_recipients with colon format (identity:recipients)."""
        recipients = self.plugin._get_recipients("key.txt:age1abc123,age1def456")
        assert recipients == ["age1abc123", "age1def456"]

    @patch.dict(os.environ, {'AGE_RECIPIENTS': 'age1env123,age1env456'})
    def test_get_recipients_from_env(self):
        """Test _get_recipients from environment variable."""
        recipients = self.plugin._get_recipients()
        assert recipients == ["age1env123", "age1env456"]

    def test_get_recipients_empty(self):
        """Test _get_recipients with no recipients found."""
        recipients = self.plugin._get_recipients()
        assert recipients == []

    def test_read_recipients_file_invalid(self):
        """Test _read_recipients_file with invalid file."""
        with pytest.raises(AgeVaultError):
            self.plugin._read_recipients_file("/nonexistent/file")

    def test_get_identity_file_vault_id_override(self):
        """Test _get_identity_file with vault-id override."""
        identity = self.plugin._get_identity_file(vault_id_params="test@" + TEST_KEY_PATH)
        assert identity == TEST_KEY_PATH

    def test_get_identity_file_colon_format(self):
        """Test _get_identity_file with colon format."""
        identity = self.plugin._get_identity_file(vault_id_params=TEST_KEY_PATH + ":recipients")
        assert identity == TEST_KEY_PATH

    @patch.dict(os.environ, {'AGE_IDENTITY_FILE': TEST_KEY_PATH})
    @patch('os.path.exists')
    def test_get_identity_file_from_env(self, mock_exists):
        """Test _get_identity_file from environment variable."""
        mock_exists.return_value = True
        identity = self.plugin._get_identity_file()
        assert identity == TEST_KEY_PATH

    def test_get_identity_file_none(self):
        """Test _get_identity_file when no identity found."""
        identity = self.plugin._get_identity_file()
        assert identity is None

    @patch('ansible_age_vault.vault.AgeVaultPlugin._get_recipients')
    @patch('ansible_age_vault.age_utils.AgeUtils.encrypt')
    def test_encrypt_success(self, mock_encrypt, mock_get_recipients):
        """Test successful encryption."""
        mock_get_recipients.return_value = ["age1abc123"]
        mock_encrypt.return_value = b"encrypted_data"

        result = self.plugin.encrypt(b"test_data")

        assert result == b"encrypted_data"
        mock_get_recipients.assert_called_once_with(vault_id_params=None)
        mock_encrypt.assert_called_once_with(b"test_data", ["age1abc123"])

    @patch('ansible_age_vault.vault.AgeVaultPlugin._get_recipients')
    def test_encrypt_no_recipients(self, mock_get_recipients):
        """Test encryption with no recipients."""
        mock_get_recipients.return_value = []

        with pytest.raises(AgeVaultError, match="No recipients found"):
            self.plugin.encrypt(b"test_data")

    @patch('ansible_age_vault.vault.AgeVaultPlugin._get_identity_file')
    @patch('ansible_age_vault.age_utils.AgeUtils.decrypt')
    def test_decrypt_success(self, mock_decrypt, mock_get_identity_file):
        """Test successful decryption."""
        mock_get_identity_file.return_value = "/path/to/key.txt"
        mock_decrypt.return_value = b"decrypted_data"

        result = self.plugin.decrypt(b"encrypted_data")

        assert result == b"decrypted_data"
        mock_get_identity_file.assert_called_once_with(vault_id_params=None)
        mock_decrypt.assert_called_once_with(b"encrypted_data", "/path/to/key.txt")

    @patch('ansible_age_vault.age_utils.AgeUtils.encrypt')
    def test_encrypt_with_exception(self, mock_encrypt):
        """Test encryption with exception."""
        mock_encrypt.side_effect = Exception("Age failed")

        with pytest.raises(AgeVaultError, match="Age encryption failed"):
            self.plugin.encrypt(b"test_data", "age1abc123")

    @patch('ansible_age_vault.age_utils.AgeUtils.decrypt')
    def test_decrypt_with_exception(self, mock_decrypt):
        """Test decryption with exception."""
        mock_decrypt.side_effect = Exception("Age failed")

        with pytest.raises(AgeVaultError, match="Age decryption failed"):
            self.plugin.decrypt(b"encrypted_data")


class TestConfigMethods:
    """Test configuration-related methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = AgeVaultPlugin()

    def test_get_config_value_no_config(self):
        """Test _get_config_value with no config file."""
        value = self.plugin._get_config_value('age_recipients')
        assert value is None

    @patch('configparser.ConfigParser')
    @patch('os.path.exists')
    def test_get_config_value_with_config(self, mock_exists, mock_configparser):
        """Test _get_config_value with config file."""
        mock_exists.return_value = True
        mock_config = Mock()
        mock_config.has_section.return_value = True
        mock_config.has_option.return_value = True
        mock_config.get.return_value = "  test_value  "
        mock_configparser.return_value = mock_config

        value = self.plugin._get_config_value('age_recipients')
        assert value == "test_value"
