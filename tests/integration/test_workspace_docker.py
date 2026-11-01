"""Re-exports the D5-06 container tests, because CI's integration job only collects this directory.

The tests live (and are documented) in ``tests/workspace/test_local_docker.py``; they carry the
``integration`` marker and skip when Docker is absent. Loaded by name so the module is not
type-checked twice under two names.
"""

from __future__ import annotations

import importlib

_source = importlib.import_module("workspace.test_local_docker")
for _name in (
    "docker_provider",
    "live",
    "test_docker_container_has_no_host_credentials",
    "test_docker_container_has_no_network",
    "test_docker_lost_session_recovers_from_the_branch",
    "test_docker_output_is_capped",
    "test_docker_runs_commands_in_the_snapshot",
    "test_docker_sessions_are_isolated_from_each_other",
    "test_docker_timeout_kills_the_command",
):
    globals()[_name] = getattr(_source, _name)
