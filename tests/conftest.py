# pytest-only entry point. The project's real runner is run_tests.py (also the
# Docker ENTRYPOINT), which applies the same shim itself — see _pyversion_shim.
# Keeping both paths on one shim ensures the suite behaves identically however
# it is launched.
from _pyversion_shim import apply

apply()
