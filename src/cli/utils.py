#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from pathlib import Path
from .. import VERSION

def calculate_tool_integrity():
    """Calculates integrity hashes of the tool and its dependencies."""
    integrity = {
        'tool_hash': '',
        'packages_hash': {},
        'shares_tool_version': VERSION
    }
    
    # Hash of __init__.py file
    init_path = Path(__file__).parent.parent / "__init__.py"
    if init_path.exists():
        with open(init_path, 'rb') as f:
            integrity['tool_hash'] = hashlib.sha256(f.read()).hexdigest()
    
    # Hash of packages
    packages_dir = Path('packages')
    if packages_dir.exists():
        for whl in packages_dir.glob('*.whl'):
            with open(whl, 'rb') as f:
                integrity['packages_hash'][whl.name] = hashlib.sha256(f.read()).hexdigest()
    
    return integrity 