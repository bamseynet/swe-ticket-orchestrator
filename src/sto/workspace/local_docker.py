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
import time
from collections.abc import Callable, Sequence

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
_EXIT_TIMEOUT = 124  # `timeout` when the command timed out
_EXIT_KILLED = 137  # 128 + SIGKILL, when `-k` had to escalate
_WORKSPACE = "/workspace"
_UID = "1000:1000"
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_IMAGE = re.compile(r"[a-z0-9][A-Za-z0-9._/:@-]{0,254}")
_MEMORY = re.compile(r"[1-9][0-9]*[kmg]?")
_CPUS = re.compile(r"[0-9]+(\.[0-9]+)?")
_TMPFS_OPTS = "rw,exec,nosuid,nodev,uid=1000,gid=1000"

# The sweep runs inside the container as `sh -c PRELUDE+BODY`. The prelude names the /proc root and
# the kill command, so a test can run the real body against a fake /proc tree with a stub `kill`.
SWEEP_PRELUDE = 'PROC=/proc\nsto_kill() { kill "$@" 2>/dev/null; }\n'
# Keeper = the lowest PID above 1 (PID 1 is the init from `--init`; the keeper is `sleep infinity`,
# started first and never exiting). Everything else, except this shell and zombies, is stopped and
# then killed, round after round, until a scan finds nothing. Stopping first means a fork loop
# cannot outrun the kill. Builtins only: no subshell, so the sweep never sees or kills itself.
SWEEP_BODY = r"""
keeper=
for d in "$PROC"/[0-9]*; do
  p=${d#"$PROC"/}
  if [ "$p" -gt 1 ] && { [ -z "$keeper" ] || [ "$p" -lt "$keeper" ]; }; then keeper=$p; fi
done
scan() {
  pids=
  for d in "$PROC"/[0-9]*; do
    p=${d#"$PROC"/}
    [ "$p" -gt 1 ] || continue
    [ "$p" = "$keeper" ] && continue
    [ "$p" = "$$" ] && continue
    line=
    read -r line 2>/dev/null < "$d/stat" || continue
    state=${line##*\) }
    state=${state%% *}
    [ "$state" = Z ] && continue
    pids="$pids $p"
  done
}
i=0
while [ "$i" -lt 100 ]; do
  scan
  if [ -z "$pids" ]; then echo clean; exit 0; fi
  for p in $pids; do sto_kill -STOP "$p"; done
  for p in $pids; do sto_kill -KILL "$p"; done
  i=$((i + 1))
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
        res = self._call(
            "ps", "-a", "--no-trunc", "--filter", f"name=^/{name}$", "--format", "{{.State}}"
        )
        if res.exit_code != 0 or res.timed_out:
            raise WorkspaceUnavailableError("the Docker daemon did not answer")
        states = res.stdout.split()
        return states[0] if states else "absent"

    def is_alive(self, session_id: str) -> bool:
        return self._state(session_id) == "running"

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

    def start(self, session_id: str, snapshot: bytes) -> None:
        name = self.container_name(session_id)
        plain = normalize_snapshot(snapshot)  # refuses anything unsafe before Docker is touched
        state = self._state(session_id)
        if state in ("exited", "dead"):
            # A dead leftover. No `-f`: if it is not dead any more, someone else owns the name.
            if not self._remove(name, force=False) and self._state(session_id) != "absent":
                raise SessionExistsError("session already exists")
        elif state != "absent":
            raise SessionExistsError(f"session already exists ({state}); stop() it first")
        created = self._call(*self._create_args(name), timeout_s=_PULL_TIMEOUT_S)
        cid = created.stdout.strip()
        if created.exit_code != 0 or not _CONTAINER_ID.fullmatch(cid):
            # Nothing of ours exists, so nothing is removed: a name conflict means a peer won.
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
        hit_timeout = (
            not res.truncated
            and res.exit_code in (_EXIT_TIMEOUT, _EXIT_KILLED)
            and elapsed >= timeout_s
        )
        if res.truncated or hit_timeout:
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
        """Kill everything the command left behind. True if verified; else the session is gone."""
        name = self.container_name(session_id)
        res = self._call("exec", name, "sh", "-c", SWEEP_SCRIPT, timeout_s=_SWEEP_TIMEOUT_S)
        if res.exit_code == 0 and not res.timed_out and res.stdout.strip() == "clean":
            return True
        self.stop(session_id)
        return False
