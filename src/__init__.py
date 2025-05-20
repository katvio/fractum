#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import click

# Strict Python version check
REQUIRED_PYTHON_VERSION = (3, 12, 10)
if sys.version_info[:3] != REQUIRED_PYTHON_VERSION:
    sys.exit(f"Error: This application requires exactly Python {'.'.join(map(str, REQUIRED_PYTHON_VERSION))}. "
             f"Current version: {'.'.join(map(str, sys.version_info[:3]))}")

VERSION = "1.0.0"

# Import public components
from src.crypto.memory import SecureMemory, SecureContext
from src.crypto.encryption import FileEncryptor
from src.shares.metadata import ShareMetadata
from src.shares.manager import ShareManager
from src.shares.archiver import ShareArchiver
from src.utils.integrity import calculate_tool_integrity, get_enhanced_random_bytes

# Import CLI entry point
from src.cli import cli

# Make the CLI available at the package level
if __name__ == '__main__':
    cli() 