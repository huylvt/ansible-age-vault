#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Age Utilities for Encryption/Decryption
========================================

This module provides utilities for interacting with the age CLI tool.
"""

import os
import subprocess
import tempfile
from typing import List, Optional

from .exceptions import AgeVaultError


class AgeUtils:
    """Utility class for age encryption/decryption operations."""

    def __init__(self):
        """Initialize AgeUtils."""
        self._check_age_available()

    def _check_age_available(self) -> None:
        """
        Check if age CLI tool is available.

        Raises:
            AgeVaultError: If age tool is not found
        """
        try:
            subprocess.run(['age', '--version'],
                         capture_output=True, check=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise AgeVaultError(
                "Age CLI tool not found. Please install it from: "
                "https://github.com/FiloSottile/age"
            ) from e

    def encrypt(self, data: bytes, recipients: List[str]) -> bytes:
        """
        Encrypt data using age with multiple recipients.

        Args:
            data: Raw bytes to encrypt
            recipients: List of recipient public keys

        Returns:
            Encrypted bytes

        Raises:
            AgeVaultError: If encryption fails
        """
        if not recipients:
            raise AgeVaultError("No recipients provided for encryption")

        # Prepare age command
        cmd = ['age', '--encrypt']
        for recipient in recipients:
            cmd.extend(['--recipient', recipient])

        return self._run_age_command(cmd, input_data=data)

    def decrypt(self, data: bytes, identity_file: Optional[str] = None) -> bytes:
        """
        Decrypt data using age.

        Args:
            data: Encrypted bytes to decrypt
            identity_file: Path to identity file (private key)

        Returns:
            Decrypted bytes

        Raises:
            AgeVaultError: If decryption fails
        """
        # Prepare age command
        cmd = ['age', '--decrypt']

        if identity_file and os.path.exists(identity_file):
            cmd.extend(['--identity', identity_file])
        else:
            # Try to find default identity
            default_identity = self._find_default_identity()
            if default_identity:
                cmd.extend(['--identity', default_identity])
            else:
                raise AgeVaultError(
                    "No identity file found for decryption. "
                    "Expected locations: ~/.age/key.txt, ~/.config/age/key.txt, age-key.txt"
                )

        return self._run_age_command(cmd, input_data=data)

    def _run_age_command(self, cmd: List[str], input_data: bytes) -> bytes:
        """
        Execute age command with input data.

        Args:
            cmd: Command to execute
            input_data: Input data to pass to command

        Returns:
            Command output bytes

        Raises:
            AgeVaultError: If command execution fails
        """
        try:
            # Use temporary file for Windows compatibility
            with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                temp_input.write(input_data)
                temp_input.flush()

                try:
                    # Run age command with input from file
                    with open(temp_input.name, 'rb') as input_file:
                        result = subprocess.run(
                            cmd,
                            stdin=input_file,
                            capture_output=True,
                            check=True,
                            timeout=30
                        )

                    return result.stdout

                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(temp_input.name)
                    except OSError:
                        pass

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode('utf-8', errors='replace') if e.stderr else 'Unknown error'
            raise AgeVaultError(f"Age command failed: {error_msg}") from e
        except subprocess.TimeoutExpired as e:
            raise AgeVaultError("Age command timed out") from e
        except Exception as e:
            raise AgeVaultError(f"Failed to execute age command: {str(e)}") from e

    def _find_default_identity(self) -> Optional[str]:
        """
        Find default identity file.

        Returns:
            Path to default identity file or None if not found
        """
        default_locations = [
            os.path.expanduser('~/.age/key.txt'),
            os.path.expanduser('~/.config/age/key.txt'),
            'age-key.txt'
        ]

        for location in default_locations:
            if os.path.exists(location):
                return location

        return None

    def generate_keypair(self, output_dir: str = '.') -> tuple[str, str]:
        """
        Generate age keypair.

        Args:
            output_dir: Directory to save keys

        Returns:
            Tuple of (private_key_path, public_key)

        Raises:
            AgeVaultError: If key generation fails
        """
        try:
            # Generate keypair
            result = subprocess.run(
                ['age-keygen'],
                capture_output=True,
                check=True,
                timeout=10
            )

            output = result.stderr.decode('utf-8')

            # Parse output to extract public key
            public_key = None
            private_key_content = result.stdout.decode('utf-8')

            for line in output.split('\n'):
                if line.startswith('# public key:'):
                    public_key = line.replace('# public key:', '').strip()
                    break

            if not public_key:
                raise AgeVaultError("Failed to extract public key from age-keygen output")

            # Save private key
            private_key_path = os.path.join(output_dir, 'age-key.txt')
            with open(private_key_path, 'w', encoding='utf-8') as f:
                f.write(private_key_content)

            # Set secure permissions
            os.chmod(private_key_path, 0o600)

            return private_key_path, public_key

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode('utf-8', errors='replace') if e.stderr else 'Unknown error'
            raise AgeVaultError(f"Failed to generate age keypair: {error_msg}") from e
        except Exception as e:
            raise AgeVaultError(f"Key generation failed: {str(e)}") from e
