#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ansible Vault Plugin for Age Encryption
==========================================

This module provides the main vault plugin implementation for age encryption.

Requirements:
- age CLI tool (https://github.com/FiloSottile/age)
- Python 3.8+
- Ansible Core 2.15+

Usage:
    ansible-vault encrypt secrets.yml --vault-id age@prompt
    ansible-vault decrypt secrets.yml --vault-id age@prompt
"""

import os
from typing import Optional, List

from ansible.utils.display import Display

from .age_utils import AgeUtils
from .exceptions import AgeVaultError

display = Display()


class AgeVaultPlugin():
    """
    Ansible Vault Plugin for Age Encryption.

    This plugin allows Ansible to encrypt and decrypt vault files using
    the age encryption tool instead of the default AES256 encryption.

    Features:
    - Public/private key encryption with age
    - Multi-recipient support
    - Vault-id parameter override
    - Configuration file integration
    - Environment variable support
    """

    def __init__(self):
        """Initialize the Age vault plugin."""
        super().__init__()
        self.age_utils = AgeUtils()

    @property
    def vault_id(self) -> str:
        """Return the vault ID for this plugin."""
        return "age"

    def encrypt(self, data: bytes, secret: Optional[str] = None) -> bytes:
        """
        Encrypt data using age encryption.

        Args:
            data: Raw bytes to encrypt
            secret: Vault-id parameters or unused for age (uses public key encryption)

        Returns:
            Encrypted bytes

        Raises:
            AgeVaultError: If encryption fails
        """
        try:
            # Load recipients for encryption, supporting vault-id override
            recipients = self._get_recipients(vault_id_params=secret)
            if not recipients:
                raise AgeVaultError("No recipients found for age encryption")

            # Use age_utils for encryption
            result = self.age_utils.encrypt(data, recipients)

            display.vvv(f"Age encryption successful with {len(recipients)} recipients")
            return result

        except Exception as e:
            raise AgeVaultError(f"Age encryption failed: {str(e)}") from e

    def decrypt(self, data: bytes, secret: Optional[str] = None) -> bytes:
        """
        Decrypt data using age decryption.

        Args:
            data: Encrypted bytes to decrypt
            secret: Vault-id parameters for identity resolution

        Returns:
            Decrypted bytes

        Raises:
            AgeVaultError: If decryption fails
        """
        try:
            # Parse vault-id parameters for specific identity
            identity_file = self._get_identity_file(vault_id_params=secret)

            # Use age_utils for decryption
            result = self.age_utils.decrypt(data, identity_file)

            display.vvv(f"Age decryption successful with identity: {identity_file or 'default'}")
            return result

        except Exception as e:
            raise AgeVaultError(f"Age decryption failed: {str(e)}") from e

    def _get_recipients(self, vault_id_params: Optional[str] = None) -> List[str]:
        """
        Get recipients for encryption with support for vault-id overrides.

        Args:
            vault_id_params: Optional vault-id parameters for recipients override

        Returns:
            List of recipient public keys

        Raises:
            AgeVaultError: If no recipients found or invalid format
        """
        recipients = []

        # Priority 1: Vault-ID parameters override
        if vault_id_params:
            # Parse format: recipients or identity_file:recipients
            if ':' in vault_id_params:
                parts = vault_id_params.split(':', 1)
                recipients_part = parts[1] if len(parts) > 1 else parts[0]
            else:
                recipients_part = vault_id_params

            # Check if it's a file path or direct recipients
            if os.path.exists(recipients_part):
                recipients = self._read_recipients_file(recipients_part)
            else:
                # Assume comma-separated recipients
                recipients = [r.strip() for r in recipients_part.split(',') if r.strip()]

            if recipients:
                display.vvv(f"Using vault-id recipients override: {len(recipients)} recipients")
                return recipients

        # Priority 2: Configuration from ansible.cfg
        recipients_from_config = self._get_config_value('age_recipients')
        if recipients_from_config:
            if os.path.exists(recipients_from_config):
                recipients = self._read_recipients_file(recipients_from_config)
                if recipients:
                    display.vvv(f"Using recipients from config: {recipients_from_config}")
                    return recipients

        # Priority 3: .age-recipients file in current directory
        default_recipients_files = ['.age-recipients', 'age-recipients.txt']
        for recipients_file in default_recipients_files:
            if os.path.exists(recipients_file):
                recipients = self._read_recipients_file(recipients_file)
                if recipients:
                    display.vvv(f"Using default recipients file: {recipients_file}")
                    return recipients

        # Priority 4: Environment variable
        env_recipients = os.environ.get('AGE_RECIPIENTS')
        if env_recipients:
            recipients = [r.strip() for r in env_recipients.split(',') if r.strip()]
            if recipients:
                display.vvv("Using recipients from AGE_RECIPIENTS environment variable")
                return recipients

        return []

    def _get_identity_file(self, vault_id_params: Optional[str] = None) -> Optional[str]:
        """
        Get private key identity file path with support for vault-id overrides.

        Args:
            vault_id_params: Optional vault-id parameters for identity override

        Returns:
            Path to identity file or None if not found

        Raises:
            AgeVaultError: If specified identity file doesn't exist
        """
        # Priority 1: Vault-ID parameters override
        if vault_id_params:
            # Parse format: vault_name@identity_file, identity_file:recipients, or identity_file
            identity_part = vault_id_params

            # Handle vault_name@identity_file format
            if '@' in vault_id_params:
                identity_part = vault_id_params.split('@', 1)[1]
            # Handle identity_file:recipients format
            elif ':' in vault_id_params:
                identity_part = vault_id_params.split(':')[0]

            if identity_part and os.path.exists(identity_part):
                display.vvv(f"Using vault-id identity override: {identity_part}")
                return identity_part

        # Priority 2: Configuration from ansible.cfg
        identity_from_config = self._get_config_value('age_identity')
        if identity_from_config and os.path.exists(identity_from_config):
            display.vvv(f"Using identity from ansible.cfg: {identity_from_config}")
            return identity_from_config

        # Priority 3: Environment variable
        env_identity = os.environ.get('AGE_IDENTITY_FILE')
        if env_identity and os.path.exists(env_identity):
            display.vvv(f"Using identity from AGE_IDENTITY_FILE: {env_identity}")
            return env_identity

        # Priority 4: Default locations
        default_locations = [
            os.path.expanduser('~/.age/key.txt'),
            os.path.expanduser('~/.config/age/key.txt'),
            'age-key.txt'
        ]

        for location in default_locations:
            if os.path.exists(location):
                display.vvv(f"Using default identity: {location}")
                return location

        return None

    def _read_recipients_file(self, file_path: str) -> List[str]:
        """
        Read recipients from a file.

        Args:
            file_path: Path to recipients file

        Returns:
            List of recipient public keys

        Raises:
            AgeVaultError: If file cannot be read
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            recipients = []
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Support comma-separated recipients on single line
                    for recipient in line.split(','):
                        recipient = recipient.strip()
                        if recipient:
                            recipients.append(recipient)

            return recipients
        except Exception as e:
            raise AgeVaultError(f"Failed to read recipients file {file_path}: {str(e)}") from e

    def _get_config_value(self, setting_name: str) -> Optional[str]:
        """
        Get configuration value from ansible.cfg.

        Args:
            setting_name: Name of the configuration setting

        Returns:
            Configuration value or None if not found
        """
        try:
            # Try to get setting from ansible configuration
            # First check for age-specific settings in defaults section
            config_paths = [
                './ansible.cfg',
                os.path.expanduser('~/.ansible.cfg'),
                '/etc/ansible/ansible.cfg'
            ]

            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        import configparser
                        config = configparser.ConfigParser()
                        config.read(config_path)

                        # Check defaults section for age settings
                        if config.has_section('defaults') and config.has_option('defaults', setting_name):
                            value = config.get('defaults', setting_name)
                            if value:
                                return value.strip()
                    except (configparser.Error, OSError, ValueError):
                        continue

            return None
        except (OSError, ImportError, AttributeError):
            return None
