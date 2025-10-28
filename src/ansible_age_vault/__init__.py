#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ansible Age Vault Plugin Package
=================================

This package provides an Ansible Vault plugin that integrates with the age
 encryption tool.

Author: Huy Le Viet
License: MIT
"""

__version__ = "0.1.0"
__author__ = "Huy Le Viet"
__email__ = "huylvt.vn@gmail.com"
__license__ = "MIT"

from .vault import AgeVaultPlugin

__all__ = ["AgeVaultPlugin"]
