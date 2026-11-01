"""The workspace port: where an agent's commands run (PLAN 8.4, ADR-0012).

It mirrors the AgentCore command model (``InvokeAgentRuntimeCommand``): a command string, a
timeout, capped output, and an exit code. So a test against the fake, or against local Docker,
stays meaningful for the AWS sandbox.

* The sandbox gets **no credentials and no network**. State comes in as a snapshot tarball (the
  branch at a pinned SHA, fetched by the control plane) and goes out as a patch (D5-07).
* A session can die at any time. The branch is the source of truth, so ``ensure_session`` rebuilds
  a lost session from a fresh snapshot of the branch. Work not yet pushed or checkpointed is lost.

``FakeWorkspaceProvider`` gives local tests the same port with no Docker.
"""

from __future__ import annotations

import io
import re
import tarfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError

MAX_COMMAND_BYTES = 64 * 1024  # AgentCore's per-command limit (ADR-0012)
DEFAULT_TIMEOUT_S = 120.0
MAX_TIMEOUT_S = 3600.0  # AgentCore's one-hour ceiling
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024  # per stream
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class WorkspaceError(PermanentError):
    """A bad request to a provider, or a session that does not exist or could not be made."""


class SnapshotError(WorkspaceError):
    """A snapshot tarball with an unsafe or unreadable member."""


@dataclass(frozen=True)
class ExecResult:
    """The outcome of one command. ``exit_code`` is ``None`` when the command timed out."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool  # either stream hit ``max_output_bytes``; the text is a prefix


@runtime_checkable
class WorkspaceProvider(Protocol):
    def start(self, session_id: str, snapshot: bytes) -> None:
        """Create a session whose ``/workspace`` holds the snapshot tarball. Raises if live."""
        ...

    def exec(
        self,
        session_id: str,
        command: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ExecResult:
        """Run ``command`` in the workspace. A timeout or oversize output is a result."""
        ...

    def is_alive(self, session_id: str) -> bool: ...

    def stop(self, session_id: str) -> None:
        """Destroy the session. Idempotent."""
        ...


def check_session_id(session_id: str) -> str:
    if not _SESSION_ID.fullmatch(session_id):
        raise WorkspaceError("session id must be 1-64 characters of [A-Za-z0-9_.-], no leading -")
    return session_id


def check_exec_args(command: str, timeout_s: float, max_output_bytes: int) -> None:
    if not command or len(command.encode()) > MAX_COMMAND_BYTES:
        raise WorkspaceError(f"command must be 1 to {MAX_COMMAND_BYTES} bytes")
    if not 0 < timeout_s <= MAX_TIMEOUT_S:
        raise WorkspaceError(f"timeout_s must be in (0, {MAX_TIMEOUT_S:g}]")
    if max_output_bytes < 1:
        raise WorkspaceError("max_output_bytes must be positive")


def cap_text(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode a prefix of at most ``limit`` bytes. Returns the text and whether data was cut."""
    cut = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), cut


# ---------------------------------------------------------------- snapshots


def _safe_member(name: str) -> str:
    parts = name.split("/")
    if not name or name.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise SnapshotError(f"unsafe snapshot path: {name!r}")
    return name


def pack_snapshot(files: Mapping[str, bytes]) -> bytes:
    """Build a snapshot tarball from relative paths to contents."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in files.items():
            info = tarfile.TarInfo(_safe_member(name))
            info.size = len(body)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def unpack_snapshot(data: bytes) -> dict[str, bytes]:
    """Read a snapshot into memory. Only regular files with relative paths are accepted."""
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("snapshot too large")
    out: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf:
                if member.isdir():
                    continue
                if not member.isreg():
                    raise SnapshotError(f"snapshot member {member.name!r} is not a regular file")
                handle = tf.extractfile(member)
                assert handle is not None
                out[_safe_member(member.name.removeprefix("./"))] = handle.read()
    except tarfile.TarError as exc:
        raise SnapshotError("snapshot is not a readable tar archive") from exc
    return out


# ---------------------------------------------------------------- recovery

SnapshotSource = Callable[[str], bytes]  # branch name -> snapshot tarball


def ensure_session(
    provider: WorkspaceProvider, session_id: str, branch: str, source: SnapshotSource
) -> bool:
    """Make sure ``session_id`` is live, rebuilding it from ``branch`` if it is missing or dead.

    Returns True if a session was (re)created. Anything that was only in the dead session's
    filesystem is gone, which is the design: the branch and checkpoints are the state.
    """
    if provider.is_alive(session_id):
        return False
    provider.stop(session_id)  # clear a dead leftover so the name is free
    provider.start(session_id, source(branch))
    return True


# ---------------------------------------------------------------- fake provider


@dataclass(frozen=True)
class FakeOutcome:
    """A scripted command result. ``duration_s`` past the timeout makes the command time out."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_s: float = 0.0
    writes: Mapping[str, bytes] = field(default_factory=dict)


class FakeWorkspaceProvider:
    """In-memory ``WorkspaceProvider``. Commands are scripted by exact string; ``cat PATH``,
    ``true`` and ``false`` work without a script. It applies the same checks and caps as the
    real providers, so a test of the port's behaviour does not need Docker.
    """

    def __init__(self) -> None:
        self._files: dict[str, dict[str, bytes]] = {}
        self._scripts: dict[str, FakeOutcome] = {}
        self.history: list[tuple[str, str]] = []  # (session_id, command)

    def script(self, command: str, outcome: FakeOutcome) -> None:
        self._scripts[command] = outcome

    def kill(self, session_id: str) -> None:
        """Simulate a lost session."""
        self._files.pop(session_id, None)

    def start(self, session_id: str, snapshot: bytes) -> None:
        check_session_id(session_id)
        if session_id in self._files:
            raise WorkspaceError("session already exists")
        self._files[session_id] = unpack_snapshot(snapshot)

    def is_alive(self, session_id: str) -> bool:
        return check_session_id(session_id) in self._files

    def stop(self, session_id: str) -> None:
        self._files.pop(check_session_id(session_id), None)

    def exec(
        self,
        session_id: str,
        command: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ExecResult:
        check_session_id(session_id)
        check_exec_args(command, timeout_s, max_output_bytes)
        files = self._files.get(session_id)
        if files is None:
            raise WorkspaceError("no such session")
        self.history.append((session_id, command))
        outcome = self._outcome(command, files)
        if outcome.duration_s > timeout_s:
            return ExecResult(None, "", "", timed_out=True, truncated=False)
        files.update(outcome.writes)
        out, out_cut = cap_text(outcome.stdout.encode(), max_output_bytes)
        err, err_cut = cap_text(outcome.stderr.encode(), max_output_bytes)
        return ExecResult(
            outcome.exit_code, out, err, timed_out=False, truncated=out_cut or err_cut
        )

    def _outcome(self, command: str, files: Mapping[str, bytes]) -> FakeOutcome:
        if command in self._scripts:
            return self._scripts[command]
        if command == "true":
            return FakeOutcome()
        if command == "false":
            return FakeOutcome(exit_code=1)
        if command.startswith("cat "):
            path = command[4:].strip()
            if path in files:
                return FakeOutcome(stdout=files[path].decode("utf-8", errors="replace"))
            return FakeOutcome(stderr=f"cat: {path}: No such file or directory", exit_code=1)
        return FakeOutcome(stderr=f"{command}: command not found", exit_code=127)
