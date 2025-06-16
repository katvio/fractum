import hashlib
import os
import time
from pathlib import Path
from typing import Any, Dict

from src.config import VERSION


def get_enhanced_random_bytes(length: int = 32) -> bytes:
    """Combines multiple entropy sources for enhanced randomness.

    Args:
        length (int): Length of random bytes to generate

    Returns:
        bytes: Cryptographically secure random bytes from mixed sources
    """
    # Using PyCryptodome (not deprecated PyCrypto) for cryptographically secure random generation
    from Crypto.Random import get_random_bytes

    # Collect entropy from multiple sources
    sources = [
        get_random_bytes(length),  # PyCryptodome source
        os.urandom(length),  # OS entropy pool
        str(time.time_ns()).encode(),  # High-precision timing information
        str(os.getpid()).encode(),  # Process ID
        str(id(object())).encode(),  # Memory address (adds some randomness)
    ]

    # Add some environmental entropy if available
    try:
        if hasattr(os, "getloadavg"):
            sources.append(str(os.getloadavg()).encode())
        if hasattr(os, "times"):
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


def calculate_tool_integrity() -> Dict[str, Any]:
    """Calculates integrity hashes of the tool and its dependencies."""

    integrity: Dict[str, Any] = {
        "tool_hash": "",
        "packages_hash": {},
        "shares_tool_version": VERSION,
    }

    # Hash of the package files
    init_path = Path(__file__).parent.parent / "__init__.py"
    if init_path.exists():
        with open(init_path, "rb") as f:
            integrity["tool_hash"] = hashlib.sha256(f.read()).hexdigest()

    # Hash of packages
    packages_dir = Path("packages")
    if packages_dir.exists():
        for whl in packages_dir.glob("*.whl"):
            with open(whl, "rb") as f:
                integrity["packages_hash"][whl.name] = hashlib.sha256(
                    f.read()
                ).hexdigest()

    return integrity
