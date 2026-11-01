"""The workspace port: where an agent's commands run (PLAN 8.4, ADR-0012).

It mirrors the AgentCore command model (``InvokeAgentRuntimeCommand``): a command string, a
timeout, capped output, and an exit code. So a test against the fake, or against local Docker,
stays meaningful for the AWS sandbox.

* The sandbox gets **no credentials and no network**. State comes in as a snapshot tarball (the
  branch at a pinned SHA, fetched by the control plane) and goes out as a patch (D5-07).
* A session can die at any time. The branch is the source of truth, so ``ensure_session`` rebuilds
  a lost session from a fresh snapshot of the branch. Work not yet pushed or checkpointed is lost.

Result semantics every provider must keep (the conformance suite runs them against the fake and
against Docker):

* ``exit_code`` is the command's own exit status, or ``None`` when the command did not exit by
  itself: it timed out, or it was killed at the output cap. Never a signal number. A command that
  fails to start (126, 127) with the daemon up is an ordinary exit code, not an error.
* **Timeout:** ``timed_out`` is True. Output produced so far is kept (capped).
* **Output cap:** each stream is capped at ``max_output_bytes`` of what the caller receives. When a
  stream goes over, the command is killed, ``truncated`` is True and ``exit_code`` is ``None``.
  A command that exits by itself with text that merely decodes past the cap (invalid UTF-8)
  keeps its real ``exit_code``; ``truncated`` is still True and nothing is killed.
* **After a timeout or cap, nothing the command started is still running** (children that ignore
  SIGTERM or call ``setsid`` included), and the provider has verified it **from outside the
  sandbox**, not by asking code in it. If it cannot verify that, it destroys the session and sets
  ``session_destroyed`` so the caller recovers from the branch. A command that exits by itself is
  never swept: a caller that needs a quiet workspace (patch capture) must check for itself.
* **One command at a time per session.** ``exec`` calls on one session are serialized by the
  provider *instance* (the lock is not shared between instances or processes): a second call
  waits until the first has finished and been cleaned up, so one command's cleanup can never kill
  another command.
* ``timed_out`` is set only when the time really elapsed. A command that exits with 124 or 137 on
  its own reports that exit code.
* A runner that reports a negative status (the Docker client itself killed by a signal) is a
  killed command: it is swept and reported with ``exit_code`` ``None``, never a signal number.
* Infrastructure failures are never command results: a daemon that does not answer raises
  ``WorkspaceUnavailableError`` (transient), a missing session raises ``SessionLostError``.

Snapshot format: a tar archive, plain or gzip, of regular files, directories and symbolic links
(real repositories have them). Hard links, devices, absolute or ``..`` paths and members that sit
behind a symbolic link are refused. The fake never follows a link out of its snapshot; in a real
container a link is the container's own filesystem, and the sandbox is the boundary.

``FakeWorkspaceProvider`` gives local tests the same port with no Docker.
"""

from __future__ import annotations

import gzip
import io
import posixpath
import re
import tarfile
import threading
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError, TransientError

MAX_COMMAND_BYTES = 64 * 1024  # AgentCore's per-command limit (ADR-0012)
DEFAULT_TIMEOUT_S = 120.0
MAX_TIMEOUT_S = 3600.0  # AgentCore's one-hour ceiling
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024  # per stream
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024  # unpacked, so a gzip bomb is refused too

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class WorkspaceError(PermanentError):
    """A bad request to a provider, or a session that could not be made."""


class SnapshotError(WorkspaceError):
    """A snapshot with an unsafe, unreadable or oversize member."""


class SessionExistsError(WorkspaceError):
    """``start`` found a live (or half-made) session with this id."""


class SessionLostError(WorkspaceError):
    """The session does not exist (any more). Recover it from the branch with ``ensure_session``."""


class WorkspaceUnavailableError(TransientError):
    """The backend (Docker daemon) did not answer. Nothing is known about the session. Retry."""


@dataclass(frozen=True)
class ExecResult:
    """The outcome of one command. See the module docstring for the exact semantics."""

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool  # a stream hit ``max_output_bytes``; the text is a prefix
    session_destroyed: bool = False  # cleanup could not be verified, so the session was removed


@runtime_checkable
class WorkspaceProvider(Protocol):
    def start(self, session_id: str, snapshot: bytes) -> None:
        """Create a session whose ``/workspace`` holds the snapshot. Raises if one exists."""
        ...

    def exec(
        self,
        session_id: str,
        command: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ExecResult:
        """Run ``command`` in the workspace. A timeout or cap is a result, not an error."""
        ...

    def is_alive(self, session_id: str) -> bool:
        """True if the session is running and ready (its snapshot fully unpacked). A half-made
        session is not alive. Raises ``WorkspaceUnavailableError`` if that cannot be told."""
        ...

    def stop(self, session_id: str) -> None:
        """Destroy the session. Idempotent. Raises unless the session is really gone."""
        ...


def check_session_id(session_id: str) -> str:
    if not _SESSION_ID.fullmatch(session_id):
        raise WorkspaceError("session id must be 1-64 characters of [A-Za-z0-9_.-], no leading -")
    return session_id


def check_exec_args(command: str, timeout_s: float, max_output_bytes: int) -> None:
    if not command or len(command.encode()) > MAX_COMMAND_BYTES:
        raise WorkspaceError(f"command must be 1 to {MAX_COMMAND_BYTES} bytes")
    if "\0" in command:
        raise WorkspaceError("command must not contain a NUL byte")
    if not 0 < timeout_s <= MAX_TIMEOUT_S:
        raise WorkspaceError(f"timeout_s must be in (0, {MAX_TIMEOUT_S:g}]")
    if max_output_bytes < 1:
        raise WorkspaceError("max_output_bytes must be positive")


def cap_text(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode ``data`` into text whose UTF-8 form is at most ``limit`` bytes.

    Returns the text and whether anything was cut. Invalid bytes become U+FFFD (3 bytes each), so
    the decoded text is cut again if it grew past the limit: callers receive at most ``limit``.
    """
    cut = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    encoded = text.encode()
    if len(encoded) > limit:
        text = encoded[:limit].decode("utf-8", errors="ignore")
        cut = True
    return text, cut


# ---------------------------------------------------------------- snapshots


@dataclass(frozen=True)
class ParsedSnapshot:
    files: dict[str, bytes]
    links: dict[str, str]  # path -> link target, as written in the archive


def _safe_member(name: str) -> str:
    name = name.removeprefix("./")
    parts = name.split("/")
    if not name or name.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise SnapshotError(f"unsafe snapshot path: {name!r}")
    return name


def pack_snapshot(
    files: Mapping[str, bytes],
    *,
    links: Mapping[str, str] | None = None,
    compress: bool = False,
) -> bytes:
    """Build a snapshot from relative paths to contents, plus optional symbolic links."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in files.items():
            info = tarfile.TarInfo(_safe_member(name))
            info.size = len(body)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(body))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(_safe_member(name))
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    data = buf.getvalue()
    return gzip.compress(data) if compress else data


def _plain_tar(data: bytes) -> bytes:
    if data[:2] != b"\x1f\x8b":
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise SnapshotError("snapshot too large")
        return data
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            out = gz.read(MAX_SNAPSHOT_BYTES + 1)  # bounded: a gzip bomb stops here
    except (OSError, EOFError, zlib.error) as exc:
        raise SnapshotError("snapshot is not a readable gzip stream") from exc
    if len(out) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("snapshot too large once unpacked")
    return out


def read_snapshot(data: bytes) -> ParsedSnapshot:
    """Validate a snapshot (plain or gzip tar) and read it into memory. Nothing is extracted."""
    return _parse(_plain_tar(data))


def _parse(plain: bytes) -> ParsedSnapshot:
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    dirs: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tf:
            for member in tf:
                if member.name in (".", "./"):
                    continue
                name = _safe_member(member.name.rstrip("/"))
                if member.isdir():
                    dirs.add(name)
                elif member.issym():
                    if not member.linkname:
                        raise SnapshotError(f"empty link target for {name!r}")
                    links[name] = member.linkname
                elif member.isreg():
                    total += member.size
                    if total > MAX_SNAPSHOT_BYTES:
                        raise SnapshotError("snapshot too large once unpacked")
                    handle = tf.extractfile(member)
                    if handle is None:  # pragma: no cover - isreg() members always have data
                        raise SnapshotError(f"unreadable member {name!r}")
                    files[name] = handle.read()
                else:
                    raise SnapshotError(f"snapshot member {name!r} is not a file, dir or symlink")
    except tarfile.TarError as exc:
        raise SnapshotError("snapshot is not a readable tar archive") from exc
    for name in (*files, *links, *dirs):
        parent = posixpath.dirname(name)
        while parent:
            if parent in links:
                raise SnapshotError(f"{name!r} is behind the symbolic link {parent!r}")
            parent = posixpath.dirname(parent)
    return ParsedSnapshot(files, links)


def normalize_snapshot(data: bytes) -> bytes:
    """Validate a snapshot and return it as a plain tar, ready to stream into a sandbox."""
    plain = _plain_tar(data)  # decompressed once
    _parse(plain)
    return plain


def unpack_snapshot(data: bytes) -> dict[str, bytes]:
    """The regular files of a snapshot, by path."""
    return read_snapshot(data).files


# ---------------------------------------------------------------- recovery

SnapshotSource = Callable[[str], bytes]  # branch name -> snapshot tarball


def ensure_session(
    provider: WorkspaceProvider, session_id: str, branch: str, source: SnapshotSource
) -> bool:
    """Make sure ``session_id`` is live, rebuilding it from ``branch`` if it is missing or dead.

    Returns True if this call created the session. Anything that was only in the dead session's
    filesystem is gone, which is the design: the branch and checkpoints are the state.

    It never destroys anything: if ``is_alive`` cannot tell (``WorkspaceUnavailableError``) that
    error propagates, because a session that may be alive must not be replaced. A concurrent
    caller that wins the race to create the session is not an error; if that caller has not
    finished unpacking, the result is a retryable ``WorkspaceUnavailableError``.
    """
    if provider.is_alive(session_id):
        return False
    try:
        provider.start(session_id, source(branch))
    except SessionExistsError as exc:
        if provider.is_alive(session_id):
            return False
        # A peer's start is still unpacking (or a crashed one left a stub): not ready yet, so
        # this is a retry, never a permanent failure.
        raise WorkspaceUnavailableError("another start of this session is not finished") from exc
    return True


# ---------------------------------------------------------------- fake provider


def _raw(value: str | bytes) -> bytes:
    return value.encode() if isinstance(value, str) else value


@dataclass(frozen=True)
class FakeOutcome:
    """A scripted command result. ``duration_s`` past the timeout makes the command time out;
    ``unkillable`` makes the cleanup after a timeout or a cap fail, so the session is destroyed."""

    stdout: str | bytes = ""
    stderr: str | bytes = ""
    exit_code: int = 0
    duration_s: float = 0.0
    writes: Mapping[str, bytes] = field(default_factory=dict)
    unkillable: bool = False


class FakeWorkspaceProvider:
    """In-memory ``WorkspaceProvider``. Commands are scripted by exact string; ``cat PATH``,
    ``true`` and ``false`` work without a script. It applies the same checks, caps and result
    semantics as the real providers, so a test of the port does not need Docker. ``cat`` follows
    a symbolic link only while it stays inside the snapshot.
    """

    def __init__(self) -> None:
        self._fs: dict[str, ParsedSnapshot] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._scripts: dict[str, FakeOutcome] = {}
        self.history: list[tuple[str, str]] = []  # (session_id, command)

    def script(self, command: str, outcome: FakeOutcome) -> None:
        self._scripts[command] = outcome

    def kill(self, session_id: str) -> None:
        """Simulate a lost session."""
        self._fs.pop(session_id, None)

    def start(self, session_id: str, snapshot: bytes) -> None:
        check_session_id(session_id)
        parsed = read_snapshot(snapshot)
        if session_id in self._fs:
            raise SessionExistsError("session already exists")
        self._fs[session_id] = parsed

    def is_alive(self, session_id: str) -> bool:
        return check_session_id(session_id) in self._fs

    def stop(self, session_id: str) -> None:
        self._fs.pop(check_session_id(session_id), None)

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
        with self._guard:
            lock = self._locks.setdefault(session_id, threading.Lock())
        with lock:  # one command at a time per session
            return self._exec_locked(session_id, command, timeout_s, max_output_bytes)

    def _exec_locked(
        self, session_id: str, command: str, timeout_s: float, max_output_bytes: int
    ) -> ExecResult:
        snap = self._fs.get(session_id)
        if snap is None:
            raise SessionLostError("no such session")
        self.history.append((session_id, command))
        outcome = self._outcome(command, snap)
        snap.files.update(outcome.writes)
        raw_out, raw_err = _raw(outcome.stdout), _raw(outcome.stderr)
        out, out_cut = cap_text(raw_out, max_output_bytes)
        err, err_cut = cap_text(raw_err, max_output_bytes)
        timed_out = outcome.duration_s > timeout_s
        killed_at_cap = not timed_out and (
            len(raw_out) > max_output_bytes or len(raw_err) > max_output_bytes
        )
        destroyed = outcome.unkillable and (timed_out or killed_at_cap)
        if destroyed:
            self._fs.pop(session_id, None)
        exit_code = None if (timed_out or killed_at_cap) else outcome.exit_code
        return ExecResult(
            exit_code,
            out,
            err,
            timed_out=timed_out,
            truncated=out_cut or err_cut,
            session_destroyed=destroyed,
        )

    def _outcome(self, command: str, snap: ParsedSnapshot) -> FakeOutcome:
        if command in self._scripts:
            return self._scripts[command]
        if command == "true":
            return FakeOutcome()
        if command == "false":
            return FakeOutcome(exit_code=1)
        if command.startswith("cat "):
            path = command[4:].strip()
            body = self._read(snap, path)
            if body is not None:
                return FakeOutcome(stdout=body)
            return FakeOutcome(stderr=f"cat: {path}: No such file or directory", exit_code=1)
        return FakeOutcome(stderr=f"{command}: command not found", exit_code=127)

    @staticmethod
    def _read(snap: ParsedSnapshot, path: str) -> bytes | None:
        current = posixpath.normpath(path)
        for _ in range(20):  # a loop of links ends here
            if current.startswith(("/", "..")):
                return None  # absolute, or out of the workspace
            if current in snap.links:
                current = posixpath.normpath(
                    posixpath.join(posixpath.dirname(current), snap.links[current])
                )
                continue
            return snap.files.get(current)
        return None
