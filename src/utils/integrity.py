import hashlib
import os
from pathlib import Path
from typing import Any, Dict

from src.config import VERSION


def get_enhanced_random_bytes(length: int = 32) -> bytes:
    """Returns cryptographically secure random bytes from the OS entropy pool.

    Le nom vient d'une epoque ou cette fonction melangeait sa propre entropie a
    celle du systeme. Elle ne le fait plus, et c'est voulu : melanger l'horloge
    et des identifiants de processus au CSPRNG du systeme n'ajoute rien, et si
    l'on ne peut pas faire confiance a ce CSPRNG le probleme est ailleurs. Le
    nom est conserve pour ne pas toucher aux cinquante appels de la suite de
    tests a la veille d'une release ; il n'y a rien d'« enhanced » ici.
    """
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
