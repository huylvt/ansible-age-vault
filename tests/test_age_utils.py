#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for age_utils module.

Author: ansible-age-vault
License: MIT
"""

import pytest
import subprocess
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock

from ansible_age_vault.age_utils import AgeUtils
from ansible_age_vault.exceptions import AgeVaultError

# Test file paths - defined here since imports from fixtures are failing
TEST_KEY_PATH = os.path.join(os.path.dirname(__file__), 'test-key.txt')


class TestAgeUtils:
    """Test cases for AgeUtils."""

    @patch('subprocess.run')
    def test_check_age_available_success(self, mock_run):
        """Test successful age availability check."""
        mock_run.return_value = Mock(returncode=0)

        # Should not raise exception
        age_utils = AgeUtils()
        assert age_utils is not None

    @patch('subprocess.run')
    def test_check_age_available_not_found(self, mock_run):
        """Test age not available."""
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(AgeVaultError, match="Age CLI tool not found"):
            AgeUtils()

    @patch('subprocess.run')
    def test_check_age_available_failed(self, mock_run):
        """Test age command failed."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'age')

        with pytest.raises(AgeVaultError, match="Age CLI tool not found"):
            AgeUtils()

    def setup_method(self):
        """Set up test fixtures."""
        with patch('subprocess.run'):
            self.age_utils = AgeUtils()

    @patch('ansible_age_vault.age_utils.AgeUtils._run_age_command')
    def test_encrypt_success(self, mock_run_age):
        """Test successful encryption."""
        mock_run_age.return_value = b"encrypted_data"
        recipients = ["age1abc123", "age1def456"]

        result = self.age_utils.encrypt(b"test_data", recipients)

        assert result == b"encrypted_data"
        expected_cmd = ['age', '--encrypt', '--recipient', 'age1abc123', '--recipient', 'age1def456']
        mock_run_age.assert_called_once_with(expected_cmd, input_data=b"test_data")

    def test_encrypt_no_recipients(self):
        """Test encryption with no recipients."""
        with pytest.raises(AgeVaultError, match="No recipients provided"):
            self.age_utils.encrypt(b"test_data", [])

    @patch('ansible_age_vault.age_utils.AgeUtils._run_age_command')
    @patch('os.path.exists')
    def test_decrypt_with_identity(self, mock_exists, mock_run_age):
        """Test decryption with specific identity file."""
        mock_exists.return_value = True
        mock_run_age.return_value = b"decrypted_data"

        result = self.age_utils.decrypt(b"encrypted_data", TEST_KEY_PATH)

        assert result == b"decrypted_data"
        expected_cmd = ['age', '--decrypt', '--identity', TEST_KEY_PATH]
        mock_run_age.assert_called_once_with(expected_cmd, input_data=b"encrypted_data")

    @patch('ansible_age_vault.age_utils.AgeUtils._run_age_command')
    @patch('ansible_age_vault.age_utils.AgeUtils._find_default_identity')
    def test_decrypt_with_default_identity(self, mock_find_identity, mock_run_age):
        """Test decryption with default identity."""
        mock_find_identity.return_value = TEST_KEY_PATH
        mock_run_age.return_value = b"decrypted_data"

        result = self.age_utils.decrypt(b"encrypted_data")

        assert result == b"decrypted_data"
        expected_cmd = ['age', '--decrypt', '--identity', TEST_KEY_PATH]
        mock_run_age.assert_called_once_with(expected_cmd, input_data=b"encrypted_data")

    @patch('ansible_age_vault.age_utils.AgeUtils._find_default_identity')
    def test_decrypt_no_identity(self, mock_find_identity):
        """Test decryption with no identity found."""
        mock_find_identity.return_value = None

        with pytest.raises(AgeVaultError, match="No identity file found"):
            self.age_utils.decrypt(b"encrypted_data")

    def test_find_default_identity_found(self):
        """Test finding default identity file."""
        # Test with actual test key file
        with patch('os.path.expanduser') as mock_expanduser:
            mock_expanduser.return_value = TEST_KEY_PATH
            identity = self.age_utils._find_default_identity()
            assert identity == TEST_KEY_PATH

    def test_find_default_identity_not_found(self):
        """Test not finding default identity file."""
        identity = self.age_utils._find_default_identity()
        assert identity is None

    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open')
    def test_run_age_command_success(self, mock_open, mock_tempfile, mock_run):
        """Test successful age command execution."""
        # Mock temporary file
        mock_temp = Mock()
        mock_temp.name = '/tmp/test'
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Mock file operations
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock subprocess
        mock_process = Mock()
        mock_process.stdout = b"output_data"
        mock_run.return_value = mock_process

        result = self.age_utils._run_age_command(['age', '--version'], b"input_data")

        assert result == b"output_data"

    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open')
    def test_run_age_command_failed(self, mock_open, mock_tempfile, mock_run):
        """Test failed age command execution."""
        mock_temp = Mock()
        mock_temp.name = '/tmp/test'
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Mock file operations
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        mock_run.side_effect = subprocess.CalledProcessError(
            1, 'age', stderr=b"error message"
        )

        with pytest.raises(AgeVaultError, match="Age command failed: error message"):
            self.age_utils._run_age_command(['age', '--version'], b"input_data")

    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open')
    def test_run_age_command_timeout(self, mock_open, mock_tempfile, mock_run):
        """Test age command timeout."""
        mock_temp = Mock()
        mock_temp.name = '/tmp/test'
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Mock file operations
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        mock_run.side_effect = subprocess.TimeoutExpired('age', 30)

        with pytest.raises(AgeVaultError, match="Age command timed out"):
            self.age_utils._run_age_command(['age', '--version'], b"input_data")

    @patch('subprocess.run')
    def test_generate_keypair_success(self, mock_run):
        """Test successful keypair generation."""
        mock_process = Mock()
        mock_process.stderr = b"# public key: age1abc123\n"
        mock_process.stdout = b"AGE-SECRET-KEY-123\n"
        mock_run.return_value = mock_process

        with tempfile.TemporaryDirectory() as temp_dir:
            private_key_path, public_key = self.age_utils.generate_keypair(temp_dir)

            assert public_key == "age1abc123"
            assert os.path.exists(private_key_path)
            assert os.path.basename(private_key_path) == "age-key.txt"

    @patch('subprocess.run')
    def test_generate_keypair_failed(self, mock_run):
        """Test failed keypair generation."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, 'age-keygen', stderr=b"error"
        )

        with pytest.raises(AgeVaultError, match="Failed to generate age keypair"):
            self.age_utils.generate_keypair()


class TestAgeUtilsIntegration:
    """Integration test cases that require age CLI tool."""

    @pytest.mark.integration
    @patch('subprocess.run')
    def test_full_encrypt_decrypt_cycle(self, mock_run):
        """Test full encrypt/decrypt cycle (mocked)."""
        # Mock age availability check
        mock_run.return_value = Mock(returncode=0)
        age_utils = AgeUtils()

        # Mock encryption and decryption
        with patch.object(age_utils, '_run_age_command') as mock_cmd:
            mock_cmd.side_effect = [b"encrypted_data", b"original_data"]

            # Test encryption
            encrypted = age_utils.encrypt(b"original_data", ["age1abc123"])
            assert encrypted == b"encrypted_data"

            # Test decryption with mocked command
            with patch.object(age_utils, 'decrypt') as mock_decrypt:
                mock_decrypt.return_value = b"original_data"
                decrypted = mock_decrypt(encrypted, TEST_KEY_PATH)
                assert decrypted == b"original_data"
