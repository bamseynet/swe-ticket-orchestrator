"""Test-tier plugin (``-p tier_guard``), D0-08.

* Registers the six tier markers: ``unit``, ``contract``, ``gate``, ``integration``,
  ``ui_browser`` and ``live``. A test with no tier marker counts as ``unit``.
* ``integration``, ``ui_browser`` and ``live`` tests are deselected unless ``-m`` is given, so
  local runs stay hermetic. CI jobs select them with ``-m``.
* Docker use without the ``integration`` marker fails, and so does launching a browser without
  ``ui_browser``. Every word of a command is inspected (``sh -c``, ``env docker`` and
  ``shell=True`` strings, ``xargs``, backtick and ``$(...)`` substitutions and
  ``Popen(executable=...)`` included), across ``Popen``, ``os.system``, ``os.posix_spawn[p]`` and
  ``connect``/``connect_ex`` on ``docker.sock``. A test under a ``gate(s)/`` or ``contract(s)/``
  directory is in that tier even without the marker.

This sits beside ``hermetic_guard`` and does not change its network and AWS guards.
"""

from __future__ import annotations

import os
import pty
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


SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
WRAPPERS = {"env", "sudo", "nice", "nohup", "command", "exec", "time", "timeout", "stdbuf"}
XARGS_VALUE_OPTIONS = {"-I", "-i", "-n", "-P", "-L", "-l", "-s", "-d", "-E", "-e", "-a", "-R", "-S"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _as_argv(command: Any) -> list[str]:
    if isinstance(command, (str, bytes, os.PathLike)):
        command = [command]
    try:
        return [os.fsdecode(a) for a in command]
    except TypeError:
        return []


def _shell_segments(text: str) -> list[list[str]]:
    """Split a shell string into simple commands at ; & | and newlines (quotes respected)."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()\n")
    lexer.whitespace_split = True
    segments: list[list[str]] = [[]]
    try:
        for token in lexer:
            if token and set(token) <= set(";&|()\n"):
                segments.append([])
            else:
                segments[-1].append(token)
    except ValueError:  # unbalanced quotes: fall back to plain words
        return [text.split()]
    return [seg for seg in segments if seg]


def _substitutions(text: str) -> list[str]:
    """Bodies of backtick and ``$(...)`` command substitutions (not inside single quotes)."""
    found: list[str] = []
    i, n, single = 0, len(text), False
    while i < n:
        ch = text[i]
        if ch == "\\" and not single:
            i += 2
            continue
        if ch == "'":
            single = not single
        elif not single and ch == "`":
            end = text.find("`", i + 1)
            end = n if end < 0 else end
            found.append(text[i + 1 : end])
            i = end
        elif not single and text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            found.append(text[i + 2 : j - 1 if depth == 0 else j])
            i = j - 1
        i += 1
    return found


def _xargs_command(rest: list[str]) -> list[str]:
    """The command ``xargs`` runs: ``rest`` without xargs's own options."""
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 2 if rest[i] in XARGS_VALUE_OPTIONS else 1
    return rest[i:]


def _programs(argv: list[str], *, shell_string: bool = False) -> list[str]:
    """The programs a command actually runs: argv[0], through env-like wrappers and ``sh -c``."""
    if shell_string:
        text = " ".join(argv)
        found = [p for seg in _shell_segments(text) for p in _programs(seg)]
        for body in _substitutions(text):
            found.extend(_programs([body], shell_string=True))
        return found
    while argv and _ASSIGNMENT.match(argv[0]):
        argv = argv[1:]
    if not argv:
        return []
    base = os.path.basename(argv[0]).lower()
    rest = argv[1:]
    if base == "xargs":
        return [argv[0], *_programs(_xargs_command(rest))]
    if base in WRAPPERS:
        # Skip options and VAR=value words; the next word is the wrapped program.
        i = 0
        while i < len(rest) and (rest[i].startswith("-") or _ASSIGNMENT.match(rest[i])):
            i += 1
        return [argv[0], *_programs(rest[i:])]
    if base in SHELLS:
        for i, word in enumerate(rest):
            if word.startswith("-") and not word.startswith("--") and "c" in word:
                if i + 1 < len(rest):
                    return [argv[0], *_programs([rest[i + 1]], shell_string=True)]
                break
        return [argv[0]]
    return [argv[0]]


def _kind(program: str) -> str | None:
    base = os.path.basename(program).lower()
    if base in DOCKER_PROGRAMS:
        return "docker"
    # Playwright's driver is a ``node`` binary under a ``playwright`` directory.
    if any(hint in base for hint in BROWSER_HINTS) or "/playwright/" in program.lower():
        return "browser"
    return None


def _program_kind(command: Any, *, shell_string: bool = False) -> str | None:
    """'docker' or 'browser' when the command launches one, else None.

    Only the program that is actually run counts (argv[0], the word after ``env``, the first word
    of an ``sh -c`` or ``shell=True`` string), so ``grep docker`` and ``echo firefox`` pass.
    """
    for program in _programs(_as_argv(command), shell_string=shell_string):
        kind = _kind(program)
        if kind:
            return kind
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

    def check(command: Any, *, shell_string: bool = False) -> None:
        kind = _program_kind(command, shell_string=shell_string)
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
        shell = bool(kw.get("shell")) or (len(a) > 7 and bool(a[7]))
        executable = kw.get("executable", a[1] if len(a) > 1 else None)
        if executable is not None and not shell:
            check([executable, *_as_argv(args)[1:]])  # executable replaces argv[0] as the program
        check(args, shell_string=shell)
        original_init(self, args, *a, **kw)

    def guarded_system(command: Any) -> int:
        check(command, shell_string=True)
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

    def wrap_exec(original: Any, *, has_mode: bool) -> Any:
        def guarded(*a: Any, **kw: Any) -> Any:
            args = list(a[1:] if has_mode else a)
            path, rest = (args[0], args[1:]) if args else ("", [])
            listed = next((r for r in rest if isinstance(r, (list, tuple))), None)
            words = list(listed) if listed is not None else [r for r in rest if isinstance(r, str)]
            check([path, *words[1:]])
            return original(*a, **kw)

        return guarded

    for name in dir(os):
        if re.fullmatch(r"exec(l|v)p?e?", name) or re.fullmatch(r"spawn(l|v)p?e?", name):
            monkeypatch.setattr(os, name, wrap_exec(getattr(os, name), has_mode=name[0] == "s"))

    original_pty_spawn = pty.spawn

    def guarded_pty_spawn(argv: Any, *a: Any, **kw: Any) -> Any:
        check(argv)
        return original_pty_spawn(argv, *a, **kw)

    monkeypatch.setattr(pty, "spawn", guarded_pty_spawn)
    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_init)
    monkeypatch.setattr(os, "system", guarded_system)
    monkeypatch.setattr(os, "posix_spawn", guarded_spawn)
    monkeypatch.setattr(os, "posix_spawnp", guarded_spawnp)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
