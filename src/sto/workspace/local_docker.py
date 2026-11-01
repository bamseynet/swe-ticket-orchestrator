"""Local Docker workspace provider: dev and tests only (PLAN 8.4, ADR-0012).

One container per session, driven through the ``docker`` CLI. The container is the stand-in for the
AWS sandbox, so it is built to hold what that sandbox holds:

* **No network** (``--network none``): only a loopback interface, so no package registry, no DNS,
  no host services.
* **No credentials**: no ``-e NAME`` that would copy a host variable, no env files, no bind mounts,
  no Docker socket. The snapshot is streamed in over stdin and unpacked as an unprivileged user.
* **Least privilege**: non-root, all capabilities dropped, ``no-new-privileges``, read-only root
  filesystem, tmpfs for ``/workspace`` and ``/tmp``, and limits on memory, CPUs and processes.
* **Bounded commands**: ``timeout`` runs inside the container; the host side has its own deadline
  and a cap on each output stream. After a timeout or cap a sweep kills every process in the
  container except PID 1 and the keeper, and verifies it (see ``SWEEP_BODY``). If that cannot be
  verified the session is destroyed and the result says so.

The ``docker`` calls go through a ``runner`` so the argv this module builds can be tested without
Docker. Tests that need a real container carry the ``integration`` marker and run in CI.

A clean report from code inside the container is never trusted, because it runs as the same user
as the hostile command. After a sweep, the host reads the container's task count from its cgroup
(``docker stats``) and requires exactly PID 1 and the keeper, several times in a row; anything
else, or any sweep failure, destroys the session.

Stated limits (this provider is for development and tests, not for hostile production code):

* Where Yama ``ptrace_scope`` is 0, code in the container can ptrace the sweep or inject into the
  keeper, and the task count cannot see that. CI logs ``ptrace_scope`` so we know what it proved.
  There is no seccomp profile here.
* A hostile process can keep itself alive only by outrunning the sweep, and the repeated count
  below makes that unlikely, not impossible.

What is not classified: a command's own stderr. Whether a session still exists is asked of Docker
(``docker ps``), never read out of what the command printed.
"""

from __future__ import annotations

import contextlib
import os
import re
import selectors
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from .ports import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    ExecResult,
    SessionExistsError,
    SessionLostError,
    WorkspaceError,
    WorkspaceUnavailableError,
    cap_text,
    check_exec_args,
    check_session_id,
    normalize_snapshot,
)

# Host environment variables a child process may see. Everything else, tokens included, is dropped.
ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "XDG_RUNTIME_DIR",
)

Runner = Callable[..., ExecResult]  # (argv, *, timeout_s, max_output_bytes, stdin=None)

_CHUNK = 64 * 1024
_KILL_GRACE_S = 2  # `timeout -k`: seconds between TERM and KILL inside the container
_HOST_GRACE_S = 10  # host deadline sits this far above the in-container timeout
_ADMIN_TIMEOUT_S = 60.0
_PULL_TIMEOUT_S = 600.0
_SWEEP_TIMEOUT_S = 30.0
_READY = "/tmp/.sto-ready"  # noqa: S108 - written inside the container after the snapshot is unpacked
_BASELINE_TASKS = 2  # PID 1 (init) and the keeper
_QUIET_SAMPLES = 3  # consecutive host-side counts that must equal the baseline
_MAX_SAMPLES = 15
_SAMPLE_PAUSE_S = 0.2
_STALE_START_S = 300.0  # an unfinished start older than this is a crashed one and is taken over
_EXIT_TIMEOUT = 124  # `timeout` when the command timed out
_EXIT_KILLED = 137  # 128 + SIGKILL, when `-k` had to escalate
_WORKSPACE = "/workspace"
_UID = "1000:1000"
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}")
_MEMORY = re.compile(r"[1-9][0-9]*[kmg]?")
_CPUS = re.compile(r"[0-9]+(\.[0-9]+)?")
_TMPFS_OPTS = "rw,exec,nosuid,nodev,uid=1000,gid=1000"

# The sweep runs inside the container as `sh -c PRELUDE+BODY`. The prelude names the /proc root,
# the kill command and the pause between rounds, so a test can run the real body against a fake
# /proc tree with stubs. It does not read process state: a zombie leader with live threads, or a
# comm that imitates a stat line, must not be believed. It kills until only PID 1, the keeper and
# this shell remain; orphaned zombies are reaped by the init, so the loop is bounded by time
# (400 rounds of ~20 ms), not by a small count. Its report is only a hint: the host verifies.
SWEEP_PRELUDE = 'PROC=/proc\nsto_kill() { kill "$@" 2>/dev/null; }\nsto_wait() { sleep 0.02; }\n'
# Keeper = the lowest PID above 1 (PID 1 is the init from `--init`; the keeper is `sleep infinity`,
# started first). Stopping before killing means a fork loop cannot outrun the kill. No subshell:
# the sweep never sees or kills itself.
SWEEP_BODY = r"""
keeper=
for d in "$PROC"/[0-9]*; do
  p=${d#"$PROC"/}
  if [ "$p" -gt 1 ] && { [ -z "$keeper" ] || [ "$p" -lt "$keeper" ]; }; then keeper=$p; fi
done
i=0
while [ "$i" -lt 400 ]; do
  pids=
  for d in "$PROC"/[0-9]*; do
    p=${d#"$PROC"/}
    [ "$p" -gt 1 ] || continue
    [ "$p" = "$keeper" ] && continue
    [ "$p" = "$$" ] && continue
    pids="$pids $p"
  done
  if [ -z "$pids" ]; then echo clean; exit 0; fi
  for p in $pids; do sto_kill -STOP "$p"; done
  for p in $pids; do sto_kill -KILL "$p"; done
  i=$((i + 1))
  sto_wait
done
echo "survivors:$pids"
exit 1
"""
SWEEP_SCRIPT = SWEEP_PRELUDE + SWEEP_BODY


def run_capped(
    argv: Sequence[str],
    *,
    timeout_s: float,
    max_output_bytes: int,
    stdin: bytes | None = None,
) -> ExecResult:
    """Run ``argv`` on the host with a deadline and a cap on each output stream.

    The child gets a minimal environment and its own process group. On timeout, or as soon as
    either stream passes ``max_output_bytes``, the whole group is killed and ``exit_code`` is
    ``None``. Output is never buffered beyond the cap, so an endless writer cannot grow memory.
    """
    env = {k: v for k in ENV_ALLOWLIST if (v := os.environ.get(k)) is not None}
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        raise WorkspaceError(f"cannot run {argv[0]!r}: {exc.strerror}") from exc
    assert proc.stdout is not None
    assert proc.stderr is not None
    deadline = time.monotonic() + timeout_s
    buffers: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    truncated = timed_out = False
    pending = memoryview(stdin) if stdin is not None else None

    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, "out")
    sel.register(proc.stderr, selectors.EVENT_READ, "err")
    if pending is not None and proc.stdin is not None:
        os.set_blocking(proc.stdin.fileno(), False)
        sel.register(proc.stdin, selectors.EVENT_WRITE, "in")
    elif proc.stdin is not None:
        proc.stdin.close()

    def kill_group() -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)

    exited_at: float | None = None
    try:
        while sel.get_map():
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if proc.poll() is not None:
                exited_at = exited_at or now
                if now - exited_at > 0.5:  # a grandchild may still hold a pipe open; stop waiting
                    break
            for key, _ in sel.select(timeout=min(0.1, deadline - now)):
                if key.data == "in":
                    assert pending is not None
                    assert proc.stdin is not None
                    try:
                        sent = os.write(proc.stdin.fileno(), pending[:_CHUNK])
                        pending = pending[sent:]
                        done = not len(pending)
                    except BlockingIOError:
                        done = False
                    except BrokenPipeError:
                        done = True  # the child stopped reading; its exit status tells the story
                    if done:
                        sel.unregister(proc.stdin)
                        proc.stdin.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), _CHUNK)  # type: ignore[union-attr]
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                buf = buffers[key.data]
                room = max_output_bytes - len(buf)
                buf += chunk[:room]
                if len(chunk) > room:
                    truncated = True
            if truncated:
                break
    finally:
        sel.close()
        if timed_out or truncated or proc.poll() is None:
            kill_group()
        with contextlib.suppress(OSError):
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        for stream in (proc.stdout, proc.stderr):
            stream.close()
        returncode = proc.wait()

    out, out_cut = cap_text(bytes(buffers["out"]), max_output_bytes)
    err, err_cut = cap_text(bytes(buffers["err"]), max_output_bytes)
    return ExecResult(
        exit_code=None if (timed_out or truncated) else returncode,
        stdout=out,
        stderr=err,
        timed_out=timed_out,
        truncated=truncated or out_cut or err_cut,
    )


class LocalDockerProvider:
    """``WorkspaceProvider`` backed by one local container per session."""

    def __init__(
        self,
        image: str = "python:3.12-slim",
        *,
        runner: Runner = run_capped,
        docker: str = "docker",
        memory: str = "2g",
        cpus: str = "2",
        pids_limit: int = 512,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        stale_start_s: float = _STALE_START_S,
    ) -> None:
        if not _IMAGE.fullmatch(image):
            raise WorkspaceError("image must be a plain image reference (no leading '-')")
        if not _MEMORY.fullmatch(memory):
            raise WorkspaceError("memory must look like 512m or 2g")
        if not _CPUS.fullmatch(cpus):
            raise WorkspaceError("cpus must be a number")
        if not 1 <= pids_limit <= 65536:
            raise WorkspaceError("pids_limit must be between 1 and 65536")
        self._image = image
        self._run = runner
        self._docker = docker
        self._memory = memory
        self._cpus = cpus
        self._pids = pids_limit
        self._clock = clock
        self._wall = wall
        self._sleep = sleep
        self._stale = stale_start_s
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    @staticmethod
    def container_name(session_id: str) -> str:
        return f"sto-ws-{check_session_id(session_id)}"

    def _call(
        self, *args: str, timeout_s: float = _ADMIN_TIMEOUT_S, stdin: bytes | None = None
    ) -> ExecResult:
        return self._run(
            [self._docker, *args],
            timeout_s=timeout_s,
            max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
            stdin=stdin,
        )

    def _state(self, session_id: str) -> str:
        """The container state from `docker ps`, or ``absent``. Raises if Docker is silent."""
        name = self.container_name(session_id)
        pattern = f"^/{re.escape(name)}$"  # ids may contain '.', which must not match anything
        res = self._call(
            "ps", "-a", "--no-trunc", "--filter", f"name={pattern}", "--format", "{{.State}}"
        )
        if res.exit_code != 0 or res.timed_out:
            raise WorkspaceUnavailableError("the Docker daemon did not answer")
        states = res.stdout.split()
        return states[0] if states else "absent"

    def _ready(self, name: str, session_id: str) -> bool:
        """The readiness marker, written only after the snapshot is fully unpacked."""
        res = self._call("exec", name, "test", "-e", _READY)
        if res.exit_code == 0 and not res.timed_out:
            return True
        if res.exit_code == 1 and not res.timed_out:
            self._state(session_id)  # raises if the daemon is the reason
            return False
        raise WorkspaceUnavailableError("could not check the workspace marker")

    def is_alive(self, session_id: str) -> bool:
        """Running and fully unpacked. A half-made session is not alive."""
        if self._state(session_id) != "running":
            return False
        return self._ready(self.container_name(session_id), session_id)

    def _remove(self, target: str, *, force: bool) -> bool:
        res = self._call("rm", *(["-f"] if force else []), "-v", target)
        return res.exit_code == 0 and not res.timed_out

    def stop(self, session_id: str) -> None:
        name = self.container_name(session_id)
        if self._remove(name, force=True):
            return
        if self._state(session_id) != "absent":  # raises if Docker is not answering
            raise WorkspaceUnavailableError("the container could not be removed")

    def _fail(self, message: str) -> WorkspaceError | WorkspaceUnavailableError:
        """A failed admin call is transient if the daemon is down, permanent if it is up."""
        probe = self._call("version", "--format", "{{.Server.Version}}")
        if probe.exit_code != 0 or probe.timed_out:
            return WorkspaceUnavailableError("the Docker daemon did not answer")
        return WorkspaceError(message)

    def _age_s(self, name: str) -> tuple[str, float]:
        """The container id and its age, from `docker inspect`. Unparseable counts as brand new."""
        res = self._call("inspect", "--type", "container", "-f", "{{.Id}} {{.Created}}", name)
        if res.exit_code != 0:
            raise WorkspaceUnavailableError("the Docker daemon did not answer")
        cid, _, created = res.stdout.strip().partition(" ")
        try:
            when = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", created))
            return cid, self._wall() - when.astimezone(UTC).timestamp()
        except ValueError:
            return cid, 0.0

    def _clear_leftover(self, session_id: str, name: str, state: str) -> None:
        """Make the name free, or say why not. Never touches a start that is still in progress."""
        if state in ("exited", "dead"):
            # A dead leftover. No `-f`: if it is not dead any more, someone else owns the name.
            if not self._remove(name, force=False) and self._state(session_id) != "absent":
                raise SessionExistsError("session already exists")
            return
        if state == "running" and self._ready(name, session_id):
            raise SessionExistsError("session already exists")
        # created / running but not unpacked / paused: a peer's start, or a crashed one.
        cid, age = self._age_s(name)
        if age < self._stale:
            raise WorkspaceUnavailableError(f"a start of this session is in progress ({state})")
        if not self._remove(cid, force=True):
            raise WorkspaceUnavailableError("a crashed start could not be taken over")

    def start(self, session_id: str, snapshot: bytes) -> None:
        name = self.container_name(session_id)
        plain = normalize_snapshot(snapshot)  # refuses anything unsafe before Docker is touched
        state = self._state(session_id)
        if state != "absent":
            self._clear_leftover(session_id, name, state)
        created = self._call(*self._create_args(name), timeout_s=_PULL_TIMEOUT_S)
        cid = created.stdout.strip()
        if created.exit_code != 0 or not _CONTAINER_ID.fullmatch(cid):
            # Nothing of ours exists, so nothing is removed. If the name appeared since we looked,
            # a peer won the race: that is "exists", which callers expect, not a failure.
            if self._state(session_id) != "absent":
                raise SessionExistsError("session was created by another caller")
            raise self._fail(f"could not create the workspace container: {created.stderr[:500]}")
        try:
            started = self._call("start", cid)
            if started.exit_code != 0:
                raise self._fail(f"could not start the workspace container: {started.stderr[:500]}")
            extracted = self._call(
                *self._extract_args(cid), timeout_s=_ADMIN_TIMEOUT_S * 5, stdin=plain
            )
            if extracted.exit_code != 0:
                raise self._fail(f"could not unpack the snapshot: {extracted.stderr[:500]}")
            marked = self._call("exec", cid, "touch", _READY)
            if marked.exit_code != 0:
                raise self._fail(f"could not mark the workspace ready: {marked.stderr[:500]}")
        except BaseException:
            # Only this call's own container, by id.
            with contextlib.suppress(WorkspaceError, WorkspaceUnavailableError):
                self._remove(cid, force=True)
            raise

    def _create_args(self, name: str) -> list[str]:
        return [
            "create",
            "--init",
            "--name",
            name,
            "--label",
            "sto.workspace=1",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--user",
            _UID,
            "--pids-limit",
            str(self._pids),
            "--memory",
            self._memory,
            "--memory-swap",
            self._memory,
            "--cpus",
            self._cpus,
            "--tmpfs",
            f"{_WORKSPACE}:{_TMPFS_OPTS},size=1g",
            "--tmpfs",
            f"/tmp:{_TMPFS_OPTS},size=256m",  # noqa: S108 - a path inside the container
            "-e",
            "HOME=/tmp",
            "-w",
            _WORKSPACE,
            self._image,
            "sleep",
            "infinity",
        ]

    @staticmethod
    def _extract_args(cid: str) -> list[str]:
        return [
            "exec", "-i", "-w", _WORKSPACE, cid, "tar", "-x", "-f", "-", "--no-same-owner",
        ]  # fmt: skip

    def exec(
        self,
        session_id: str,
        command: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> ExecResult:
        name = self.container_name(session_id)
        check_exec_args(command, timeout_s, max_output_bytes)
        with self._guard:
            lock = self._locks.setdefault(session_id, threading.Lock())
        with lock:  # one command at a time: a sweep must never kill a neighbour
            return self._exec_locked(session_id, name, command, timeout_s, max_output_bytes)

    def _exec_locked(
        self, session_id: str, name: str, command: str, timeout_s: float, max_output_bytes: int
    ) -> ExecResult:
        started = self._clock()
        res = self._run(
            [
                self._docker,
                "exec",
                "-w",
                _WORKSPACE,
                name,
                "timeout",
                "-k",
                str(_KILL_GRACE_S),
                f"{timeout_s:g}",
                "sh",
                "-c",
                command,
            ],
            timeout_s=timeout_s + _KILL_GRACE_S + _HOST_GRACE_S,
            max_output_bytes=max_output_bytes,
        )
        elapsed = self._clock() - started
        if res.timed_out:
            # The docker client hung past the in-container timeout: nothing can be verified.
            self.stop(session_id)
            return ExecResult(
                None, res.stdout, res.stderr, timed_out=True, truncated=res.truncated,
                session_destroyed=True,
            )  # fmt: skip
        # `timeout` reports 124 (or 137 after -k); only the clock tells that from a command that
        # exits with those codes itself, or is killed by the OOM killer.
        killed_at_cap = res.truncated and res.exit_code is None  # else: finished, text re-capped
        hit_timeout = (
            not killed_at_cap
            and res.exit_code in (_EXIT_TIMEOUT, _EXIT_KILLED)
            and elapsed >= timeout_s
        )
        if killed_at_cap or hit_timeout:
            destroyed = not self._sweep(session_id)
            return ExecResult(
                None, res.stdout, res.stderr, timed_out=hit_timeout, truncated=res.truncated,
                session_destroyed=destroyed,
            )  # fmt: skip
        if res.exit_code != 0:
            # A failed command, or a failed docker. Ask Docker; never read the command's stderr.
            state = self._state(session_id)
            if state != "running":
                raise SessionLostError(f"session is {state}")
        return res

    def _sweep(self, session_id: str) -> bool:
        """Kill everything the command left behind, then verify from the host.

        True only if the sweep says clean AND the host sees just PID 1 and the keeper, several
        times in a row. Anything else destroys the session and returns False.
        """
        name = self.container_name(session_id)
        res = self._call("exec", name, "sh", "-c", SWEEP_SCRIPT, timeout_s=_SWEEP_TIMEOUT_S)
        said_clean = res.exit_code == 0 and not res.timed_out and res.stdout.strip() == "clean"
        if said_clean and self._host_sees_quiet(name):
            return True
        self.stop(session_id)
        return False

    def _tasks(self, name: str) -> int | None:
        """Tasks in the container cgroup (threads and zombies included), counted by the host."""
        res = self._call("stats", "--no-stream", "--format", "{{.PIDs}}", name)
        text = res.stdout.strip()
        return int(text) if res.exit_code == 0 and text.isdigit() else None

    def _host_sees_quiet(self, name: str) -> bool:
        streak = 0
        for _ in range(_MAX_SAMPLES):
            streak = streak + 1 if self._tasks(name) == _BASELINE_TASKS else 0
            if streak >= _QUIET_SAMPLES:
                return True
            self._sleep(_SAMPLE_PAUSE_S)
        return False
