"""Test-tier plugin (``-p tier_guard``), D0-08.

* Registers the six tier markers: ``unit``, ``contract``, ``gate``, ``integration``,
  ``ui_browser`` and ``live``. A test with no tier marker counts as ``unit``.
* ``integration``, ``ui_browser`` and ``live`` tests are deselected unless ``-m`` is given, so
  local runs stay hermetic. CI jobs select them with ``-m``.
* Docker use (launching ``docker``, or connecting to ``docker.sock``) without the
  ``integration`` marker fails, and so does launching a browser without ``ui_browser``.

This sits beside ``hermetic_guard`` and does not change its network and AWS guards.
"""

from __future__ import annotations

import os
import socket
import subprocess
from typing import Any

import pytest

TIERS = {
    "unit": "hermetic, in-process; the default tier for an unmarked test",
    "contract": "adapters and stores against in-process fakes; hermetic",
    "gate": "gate-integrity scenarios on the in-memory store; hermetic",
    "integration": "needs Docker (DynamoDB Local, containers); CI only",
    "ui_browser": "needs a browser (Playwright); CI only",
    "live": "needs real GitHub or AWS; tagged, on demand",
}
HEAVY = ("integration", "ui_browser", "live")
DOCKER_PROGRAMS = {"docker", "docker-compose", "podman"}
BROWSER_HINTS = ("chrome", "chromium", "firefox", "webkit", "playwright", "msedge")


class TierViolationError(RuntimeError):
    """A test used Docker or a browser without the marker for that tier."""


def pytest_configure(config: pytest.Config) -> None:
    for name, text in TIERS.items():
        config.addinivalue_line("markers", f"{name}: {text}")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if not any(item.get_closest_marker(t) for t in TIERS):
            item.add_marker(pytest.mark.unit)
    if config.getoption("markexpr", default=""):
        return  # an explicit -m selects the tier itself
    kept: list[pytest.Item] = []
    dropped: list[pytest.Item] = []
    for item in items:
        (dropped if any(item.get_closest_marker(t) for t in HEAVY) else kept).append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = kept


def _argv_text(args: Any) -> list[str]:
    if isinstance(args, (str, bytes, os.PathLike)):
        args = [args]
    try:
        return [os.fsdecode(a) for a in args]
    except TypeError:
        return []


def _program_kind(args: Any) -> str | None:
    argv = _argv_text(args)
    if not argv:
        return None
    program = os.path.basename(argv[0]).lower()
    if program in DOCKER_PROGRAMS:
        return "docker"
    if any(hint in program for hint in BROWSER_HINTS):
        return "browser"
    return None


@pytest.fixture(autouse=True)
def _tier_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    node = request.node
    docker_ok = node.get_closest_marker("integration") is not None
    browser_ok = node.get_closest_marker("ui_browser") is not None
    original_init = subprocess.Popen.__init__
    original_connect = socket.socket.connect

    def guarded_init(self: Any, args: Any, *a: Any, **kw: Any) -> None:
        kind = _program_kind(args)
        if kind == "docker" and not docker_ok:
            raise TierViolationError(
                "this test uses Docker without @pytest.mark.integration; "
                "Docker tests run in CI only"
            )
        if kind == "browser" and not browser_ok:
            raise TierViolationError(
                "this test launches a browser without @pytest.mark.ui_browser; "
                "browser tests run in CI only"
            )
        original_init(self, args, *a, **kw)

    def guarded_connect(self: Any, address: Any) -> Any:
        if not docker_ok and "docker.sock" in os.fsdecode(
            address if isinstance(address, (str, bytes)) else b""
        ):
            raise TierViolationError(
                "this test connects to the Docker socket without @pytest.mark.integration"
            )
        return original_connect(self, address)

    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_init)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
