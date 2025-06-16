import sys

from src.cli import cli
from src.config import REQUIRED_PYTHON_VERSION

# Strict Python version check
if sys.version_info[:3] != REQUIRED_PYTHON_VERSION:
    sys.exit(
        f"Error: This application requires exactly Python {'.'.join(map(str, REQUIRED_PYTHON_VERSION))}. "
        f"Current version: {'.'.join(map(str, sys.version_info[:3]))}"
    )

if __name__ == "__main__":
    cli()
