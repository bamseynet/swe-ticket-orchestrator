"""Re-exports the D5-06 container tests, because CI's integration job only collects this directory.

The tests live (and are documented) in ``tests/workspace/test_local_docker.py``; they carry the
``integration`` marker, and fail rather than skip when CI has no Docker. Loaded by name so the
module is not type-checked twice under two names.
"""

from __future__ import annotations

import importlib

_source = importlib.import_module("workspace.test_local_docker")
_FIXTURES = ("docker_provider", "live", "hostile")
for _name in dir(_source):
    if _name.startswith("test_docker_") or _name in _FIXTURES:
        globals()[_name] = getattr(_source, _name)
