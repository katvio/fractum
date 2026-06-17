import sys
from collections import namedtuple
from unittest.mock import MagicMock, patch

# On CI runners that have Python < 3.12.11 (e.g. macOS arm64 with 3.12.10),
# the CLI refuses to run because of its runtime version guard.
# We patch the sys reference inside src.cli.commands so functional tests pass.
# The guard itself is covered by test_encrypt_fails_on_old_python_version,
# which applies its own patch and is unaffected by this one.
_REQUIRED = (3, 12, 11)

if sys.version_info[:3] < _REQUIRED:
    import src.cli.commands as _cli

    _mock_sys = MagicMock(wraps=sys)
    _VI = namedtuple("version_info", ["major", "minor", "micro", "releaselevel", "serial"])
    _mock_sys.version_info = _VI(*_REQUIRED, "final", 0)
    patch("src.cli.commands.sys", _mock_sys).start()
