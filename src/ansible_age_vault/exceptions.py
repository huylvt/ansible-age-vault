#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom Exceptions for Age Vault Plugin
======================================

This module defines custom exceptions used in the Age Vault Plugin
"""
from ansible.errors import AnsibleError


class AgeVaultError(AnsibleError):
    """
    Base exception for Age Vault Plugin errors.
    """

    def __init__(self, message: str, orig_exc: Exception = None):
        """
        Initialize AgeVaultError.

        Args:
            message: Error message
            orig_exc: Original exception that caused this error
        """
        super().__init__(message, orig_exc)
        self.orig_exc = orig_exc
