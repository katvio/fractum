#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fractum - A secure file encryption and secret sharing tool
"""

import sys

# Strict Python version check
REQUIRED_PYTHON_VERSION = (3, 12, 10)
if sys.version_info[:3] != REQUIRED_PYTHON_VERSION:
    sys.exit(f"Error: This application requires exactly Python {'.'.join(map(str, REQUIRED_PYTHON_VERSION))}. "
             f"Current version: {'.'.join(map(str, sys.version_info[:3]))}")

VERSION = "1.0.0"

# Import core functionality
from .core import ShareManager, ShareMetadata, FileEncryptor, ShareArchiver
from .utils import SecureMemory, get_enhanced_random_bytes
from .cli import encrypt, decrypt, verify, interactive_mode, cli

__all__ = [
    'VERSION',
    'encrypt',
    'decrypt',
    'verify',
    'ShareManager',
    'FileEncryptor',
    'ShareArchiver',
    'SecureMemory',
    'get_enhanced_random_bytes',
    'cli'
]

if __name__ == '__main__':
    cli() 