#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared Python-version shim for the test suite.

Fractum's CLI refuses to run when the interpreter is older than the pinned
3.12.11 (src/cli/commands.py runtime guard). CI runners frequently ship a
slightly older 3.12 patch (e.g. macOS arm64 with 3.12.10), which would make
every functional CLI test fail on the guard rather than on the behaviour under
test.

Both test entry points must apply the same shim, or the suite behaves
differently depending on how it is launched:
  * pytest        → loads conftest.py, which calls apply()
  * run_tests.py  → the project's real runner (also the Docker ENTRYPOINT),
                    which calls apply() directly

apply() patches only the `sys` reference seen inside src.cli.commands, leaving
the real interpreter untouched. It is idempotent and a no-op on a compliant
interpreter, so the dedicated guard test (which installs its own patch to force
an *old* version) is unaffected.
"""

import atexit
import sys
from collections import namedtuple
from unittest.mock import MagicMock, patch

_REQUIRED = (3, 12, 11)
_applied = False


def apply() -> None:
    """Patch src.cli.commands.sys so the runtime version guard passes on
    slightly-old 3.12 patch releases. No-op if already applied or unneeded."""
    global _applied
    if _applied or sys.version_info[:3] >= _REQUIRED:
        return
    import src.cli.commands  # noqa: F401  (ensure module exists before patching)

    version_info = namedtuple(
        "version_info", ["major", "minor", "micro", "releaselevel", "serial"])
    mock_sys = MagicMock(wraps=sys)
    mock_sys.version_info = version_info(*_REQUIRED, "final", 0)
    patcher = patch("src.cli.commands.sys", mock_sys)
    patcher.start()
    atexit.register(patcher.stop)
    _applied = True
