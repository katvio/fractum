import hashlib
import os
from pathlib import Path
from typing import Any, Dict

from src.config import VERSION


def get_enhanced_random_bytes(length: int = 32) -> bytes:
    """Returns cryptographically secure random bytes from the OS entropy pool."""
    return os.urandom(length)


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
