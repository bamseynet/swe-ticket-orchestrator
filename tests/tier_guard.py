"""Test-tier plugin (``-p tier_guard``), D0-08 and D0-09a.

* Registers the seven tier markers: ``unit``, ``contract``, ``gate``, ``integration``,
  ``ui_browser``, ``e2e`` and ``live``. A test with no tier marker counts as ``unit``.
* ``integration``, ``ui_browser``, ``e2e`` and ``live`` tests are deselected unless ``-m`` is
  given, so local runs stay hermetic. CI jobs select them with ``-m``.
* Docker use without the ``integration`` marker fails, and so does launching a browser without
  ``ui_browser``. The program of every simple command is inspected (``sh -c``, ``env docker`` and
  ``shell=True`` strings, ``xargs``, backtick and ``$(...)`` substitutions and
  ``Popen(executable=...)`` included), across ``Popen``, ``os.system``, ``os.posix_spawn[p]`` and
  ``connect``/``connect_ex`` on ``docker.sock``. A test under a ``gate(s)/``,
  ``contract(s)/`` or ``e2e/`` directory is in that tier even without the marker; under ``e2e/``
  it is e2e even with another tier marker.

This is a best-effort guard against accidents, not a security boundary. Known limits, left open
on purpose: shell keywords as the first word (``if docker ps; then``), ``command -v docker``
(flagged although it only looks), ``&>file`` redirections glued to a word, and
``Popen(["docker"], executable="/bin/echo")`` (flagged although it runs echo),
``echo $(x)#b; docker ps`` and ``echo a\\ #b; docker ps`` (``#`` wrongly read as a comment), heredoc
bodies (read as commands), and an unquoted ``|`` or ``(`` in ``case`` patterns, array
assignments and ``[[ =~ ]]`` (read as a command separator). Odd input fails
closed: nesting deeper than ``MAX_DEPTH`` raises ``TierViolationError``.

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
    "e2e": "whole local stack up (Docker); CI only",
    "live": "needs real GitHub or AWS; tagged, on demand",
}
HEAVY = ("integration", "ui_browser", "e2e", "live")
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
TIER_DIRS = {
    "gate": "gate",
    "gates": "gate",
    "contract": "contract",
    "contracts": "contract",
    "e2e": "e2e",
}


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
        tier = _tier_from_directory(item, root)
        if tier == "e2e":
            # Under tests/e2e/ a test is always e2e, whatever else it is marked (e.g. integration).
            if not item.get_closest_marker("e2e"):
                item.add_marker(pytest.mark.e2e)
        elif not any(item.get_closest_marker(t) for t in TIERS):
            item.add_marker(getattr(pytest.mark, tier))
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
XARGS_SHORT_VALUE = set("InPLsdEaRS")  # the value is the rest of the word, or the next word
XARGS_SHORT_ATTACHED = set("ile")  # GNU: the value, if any, must be attached
XARGS_LONG_VALUE = {
    "--max-args",
    "--max-procs",
    "--max-chars",
    "--delimiter",
    "--arg-file",
    "--process-slot-var",
}
MAX_DEPTH = 16
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _as_argv(command: Any) -> list[str]:
    if isinstance(command, (str, bytes, os.PathLike)):
        command = [command]
    try:
        return [os.fsdecode(a) for a in command]
    except TypeError:
        return []


def _is_comment_start(text: str, i: int) -> bool:
    return text[i] == "#" and (i == 0 or text[i - 1] in " \t\n;&|()")


def _shell_segments(text: str) -> list[list[str]]:
    """Split a shell string into simple commands at unquoted ; & | ( ) and newlines.

    Quotes and backslashes are respected, and ``#`` comments are dropped.
    """
    parts: list[str] = [""]
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote != "'" and text.startswith("\n", i + 1):
            i += 2  # a line continuation joins lines and leaves no trace
            continue
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"' and i + 1 < len(text):
                parts[-1] += ch
                i += 1
                ch = text[i]
            parts[-1] += ch
        elif ch == "\\" and i + 1 < len(text):
            parts[-1] += text[i : i + 2]
            i += 1
        elif ch in "'\"":
            quote = ch
            parts[-1] += ch
        elif _is_comment_start(text, i):
            while i < len(text) and text[i] != "\n":
                i += 1
            parts.append("")
        elif ch in ";&|()\n":
            parts.append("")
        else:
            parts[-1] += ch
        i += 1
    segments: list[list[str]] = []
    for part in parts:
        try:
            words = shlex.split(part)
        except ValueError:  # unbalanced quotes: fall back to plain words
            words = part.split()
        if words:
            segments.append(words)
    return segments


def _substitutions(text: str) -> list[str]:
    """Bodies of backtick and ``$(...)`` command substitutions (not inside single quotes)."""
    found: list[str] = []
    i, n = 0, len(text)
    single = double = False
    while i < n:
        ch = text[i]
        if ch == "\\" and not single:
            i += 2
            continue
        if not single and not double and _is_comment_start(text, i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "'" and not double:
            single = not single
        elif ch == '"' and not single:
            double = not double
        elif not single and ch == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            found.append(re.sub(r"\\([`$\\])", r"\1", text[i + 1 : j]))
            i = j
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
    while i < len(rest) and rest[i].startswith("-") and rest[i] != "--":
        word = rest[i]
        i += 1
        if word.startswith("--"):
            if word in XARGS_LONG_VALUE:
                i += 1
            continue
        for pos, flag in enumerate(word[1:], start=2):
            if flag in XARGS_SHORT_ATTACHED:
                break
            if flag in XARGS_SHORT_VALUE:
                if pos == len(word):  # nothing attached: the value is the next word
                    i += 1
                break
    if i < len(rest) and rest[i] == "--":
        i += 1
    return rest[i:]


def _programs(argv: list[str], *, shell_string: bool = False, depth: int = 0) -> list[str]:
    """The programs a command actually runs: argv[0], through env-like wrappers and ``sh -c``."""
    if depth > MAX_DEPTH:  # fail closed rather than recurse without limit
        raise TierViolationError("command nests too deeply for the tier guard to inspect")
    if shell_string:
        text = " ".join(argv)
        found = [p for seg in _shell_segments(text) for p in _programs(seg, depth=depth + 1)]
        for body in _substitutions(text):
            found.extend(_programs([body], shell_string=True, depth=depth + 1))
        return found
    while argv and _ASSIGNMENT.match(argv[0]):
        argv = argv[1:]
    if not argv:
        return []
    base = os.path.basename(argv[0]).lower()
    rest = argv[1:]
    if base == "xargs":
        return [argv[0], *_programs(_xargs_command(rest), depth=depth + 1)]
    if base in WRAPPERS:
        # Skip options and VAR=value words; the next word is the wrapped program.
        i = 0
        while i < len(rest) and (rest[i].startswith("-") or _ASSIGNMENT.match(rest[i])):
            i += 1
        return [argv[0], *_programs(rest[i:], depth=depth + 1)]
    if base in SHELLS:
        for i, word in enumerate(rest):
            if word.startswith("-") and not word.startswith("--") and "c" in word:
                if i + 1 < len(rest):
                    inner = _programs([rest[i + 1]], shell_string=True, depth=depth + 1)
                    return [argv[0], *inner]
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
        if executable is not None:
            # executable replaces argv[0] (or /bin/sh when shell=True) as the program run
            check([executable] if shell else [executable, *_as_argv(args)[1:]])
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
