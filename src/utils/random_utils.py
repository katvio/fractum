#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import hashlib
from Crypto.Random import get_random_bytes

def get_enhanced_random_bytes(length: int = 32) -> bytes:
    """Combines multiple entropy sources for enhanced randomness.
    
    Args:
        length (int): Length of random bytes to generate
        
    Returns:
        bytes: Cryptographically secure random bytes from mixed sources
    """
    # Collect entropy from multiple sources
    sources = [
        get_random_bytes(length),    # PyCryptodome source
        os.urandom(length),          # OS entropy pool
        str(time.time_ns()).encode(),  # High-precision timing information
        str(os.getpid()).encode(),   # Process ID
        str(id(object())).encode()   # Memory address (adds some randomness)
    ]
    
    # Add some environmental entropy if available
    try:
        if hasattr(os, 'getloadavg'):
            sources.append(str(os.getloadavg()).encode())
        if hasattr(os, 'times'):
            sources.append(str(os.times()).encode())
    except (OSError, AttributeError):
        pass
    
    # Mix sources using a hash function
    combined = b"".join(sources)
    result = hashlib.sha256(combined).digest()
    
    # If we need more than 32 bytes, use SHAKE256 (extendable output function)
    if length > 32:
        result = hashlib.shake_256(combined).digest(length)
    else:
        result = result[:length]
        
    return result 