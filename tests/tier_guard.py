"""Test-tier plugin (``-p tier_guard``), D0-08.

* Registers the six tier markers: ``unit``, ``contract``, ``gate``, ``integration``,
  ``ui_browser`` and ``live``. A test with no tier marker counts as ``unit``.
* ``integration``, ``ui_browser`` and ``live`` tests are deselected unless ``-m`` is given, so
  local runs stay hermetic. CI jobs select them with ``-m``.
* Docker use without the ``integration`` marker fails, and so does launching a browser without
  ``ui_browser``. Every word of a command is inspected (``sh -c``, ``env docker`` and
  ``shell=True`` strings included), across ``Popen``, ``os.system``, ``os.posix_spawn[p]`` and
  ``connect``/``connect_ex`` on ``docker.sock``. A test under a ``gate(s)/`` or ``contract(s)/``
  directory is in that tier even without the marker.

This sits beside ``hermetic_guard`` and does not change its network and AWS guards.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
from pathlib import Path
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
BROWSER_HINTS = (
    "chrome",
    "chromium",
    "firefox",
    "webkit",
    "playwright",
    "msedge",
    "headless_shell",
)
TIER_DIRS = {"gate": "gate", "gates": "gate", "contract": "contract", "contracts": "contract"}


class TierViolationError(RuntimeError):
    """A test used Docker or a browser without the marker for that tier."""


def pytest_configure(config: pytest.Config) -> None:
    for name, text in TIERS.items():
        config.addinivalue_line("markers", f"{name}: {text}")


def _tier_from_directory(item: pytest.Item, root: Path) -> str:
    try:
        parts = Path(str(item.path)).resolve().relative_to(root).parts[:-1]
    except ValueError:
        parts = Path(str(item.path)).parts[:-1]
    for part in parts:
        if part in TIER_DIRS:
            return TIER_DIRS[part]
    return "unit"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    root = Path(str(config.rootpath)).resolve()
    for item in items:
        if not any(item.get_closest_marker(t) for t in TIERS):
            item.add_marker(getattr(pytest.mark, _tier_from_directory(item, root)))
    if config.getoption("markexpr", default=""):
        return  # an explicit -m selects the tier itself
    kept: list[pytest.Item] = []
    dropped: list[pytest.Item] = []
    for item in items:
        (dropped if any(item.get_closest_marker(t) for t in HEAVY) else kept).append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = kept


def _words(args: Any) -> list[str]:
    """Every word in a command: all argv items, each also split like a shell would."""
    if isinstance(args, (str, bytes, os.PathLike)):
        args = [args]
    try:
        items = [os.fsdecode(a) for a in args]
    except TypeError:
        return []
    words: list[str] = []
    for item in items:
        words.append(item)
        try:
            words.extend(shlex.split(item, posix=True))
        except ValueError:
            words.extend(item.split())
        words.extend(w for w in re.split(r"[\s;&|()<>`$]+", item) if w)
    return words


def _program_kind(args: Any) -> str | None:
    """'docker' or 'browser' when any word of the command launches one, else None.

    Looks at every word, not only argv[0], so ``sh -c "docker ..."``, ``env docker`` and
    ``shell=True`` strings are caught. Playwright is matched anywhere in a path, because its
    driver is a ``node`` binary living under a ``playwright`` directory.
    """
    for word in _words(args):
        base = os.path.basename(word).lower()
        if base in DOCKER_PROGRAMS:
            return "docker"
        if any(hint in base for hint in BROWSER_HINTS) or "/playwright/" in word.lower():
            return "browser"
    return None


def _is_docker_socket(address: Any) -> bool:
    if isinstance(address, (str, bytes, os.PathLike)):
        return "docker.sock" in os.fsdecode(address)
    return False


@pytest.fixture(autouse=True)
def _tier_guard(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    node = request.node
    docker_ok = node.get_closest_marker("integration") is not None
    browser_ok = node.get_closest_marker("ui_browser") is not None

    def check(command: Any) -> None:
        kind = _program_kind(command)
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

    original_init = subprocess.Popen.__init__
    original_system = os.system
    original_spawn = os.posix_spawn
    original_spawnp = os.posix_spawnp
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_init(self: Any, args: Any, *a: Any, **kw: Any) -> None:
        check(args)
        original_init(self, args, *a, **kw)

    def guarded_system(command: Any) -> int:
        check(command)
        return original_system(command)

    def guarded_spawn(path: Any, argv: Any, *a: Any, **kw: Any) -> int:
        check([path, *argv])
        return original_spawn(path, argv, *a, **kw)

    def guarded_spawnp(file: Any, argv: Any, *a: Any, **kw: Any) -> int:
        check([file, *argv])
        return original_spawnp(file, argv, *a, **kw)

    def guard_socket(address: Any) -> None:
        if not docker_ok and _is_docker_socket(address):
            raise TierViolationError(
                "this test connects to the Docker socket without @pytest.mark.integration"
            )

    def guarded_connect(self: Any, address: Any) -> Any:
        guard_socket(address)
        return original_connect(self, address)

    def guarded_connect_ex(self: Any, address: Any) -> Any:
        guard_socket(address)
        return original_connect_ex(self, address)

    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_init)
    monkeypatch.setattr(os, "system", guarded_system)
    monkeypatch.setattr(os, "posix_spawn", guarded_spawn)
    monkeypatch.setattr(os, "posix_spawnp", guarded_spawnp)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
