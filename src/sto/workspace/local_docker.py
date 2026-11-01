"""Local Docker workspace provider: dev and tests only (PLAN 8.4, ADR-0012).

One container per session, driven through the ``docker`` CLI. The container is the stand-in for the
AWS sandbox, so it is built to hold what that sandbox holds:

* **No network** (``--network none``): only a loopback interface, so no package registry, no DNS,
  no host services.
* **No credentials**: no ``-e NAME`` that would copy a host variable, no env files, no bind mounts,
  no Docker socket. The snapshot is streamed in over stdin and unpacked as an unprivileged user.
* **Least privilege**: non-root, all capabilities dropped, ``no-new-privileges``, read-only root
  filesystem, tmpfs for ``/workspace`` and ``/tmp``, and limits on memory, CPUs and processes.
* **Bounded commands**: ``timeout`` runs inside the container and kills the command's process
  group; the host side has its own deadline and a cap on each output stream, so a command that
  spews output or hangs cannot stall or flood the caller.

The ``docker`` calls go through a ``runner`` so the argv this module builds can be tested without
Docker. Tests that need a real container carry the ``integration`` marker and run in CI.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Sequence

from .ports import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    MAX_SNAPSHOT_BYTES,
    ExecResult,
    WorkspaceError,
    cap_text,
    check_exec_args,
    check_session_id,
)

# Host environment variables a child process may see. Everything else, tokens included, is dropped.
ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "XDG_RUNTIME_DIR",
)

Runner = Callable[..., ExecResult]  # (argv, *, timeout_s, max_output_bytes, stdin=None)

_CHUNK = 64 * 1024
_KILL_GRACE_S = 2  # `timeout -k`: seconds between TERM and KILL inside the container
_HOST_GRACE_S = 10  # host deadline sits this far above the in-container timeout
_ADMIN_TIMEOUT_S = 60.0
_PULL_TIMEOUT_S = 600.0
_EXIT_TIMEOUT = 124  # `timeout` when the command timed out
_EXIT_KILLED = 137  # 128 + SIGKILL, when `-k` had to escalate
_WORKSPACE = "/workspace"
_UID = "1000:1000"


def run_capped(
    argv: Sequence[str],
    *,
    timeout_s: float,
    max_output_bytes: int,
    stdin: bytes | None = None,
) -> ExecResult:
    """Run ``argv`` on the host with a deadline and a cap on each output stream.

    The child gets a minimal environment and its own process group. On timeout, or as soon as
    either stream passes ``max_output_bytes``, the whole group is killed. Output is never
    buffered beyond the cap, so an endless writer cannot grow memory.
    """
    env = {k: v for k in ENV_ALLOWLIST if (v := os.environ.get(k)) is not None}
    proc = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
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

    out, _ = cap_text(bytes(buffers["out"]), max_output_bytes)
    err, _ = cap_text(bytes(buffers["err"]), max_output_bytes)
    return ExecResult(
        exit_code=None if timed_out else returncode,
        stdout=out,
        stderr=err,
        timed_out=timed_out,
        truncated=truncated,
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
    ) -> None:
        self._image = image
        self._run = runner
        self._docker = docker
        self._memory = memory
        self._cpus = cpus
        self._pids = pids_limit

    @staticmethod
    def container_name(session_id: str) -> str:
        return f"sto-ws-{check_session_id(session_id)}"

    def _admin(self, *args: str, timeout_s: float = _ADMIN_TIMEOUT_S) -> ExecResult:
        return self._run(
            [self._docker, *args], timeout_s=timeout_s, max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES
        )

    def is_alive(self, session_id: str) -> bool:
        name = self.container_name(session_id)
        res = self._admin("inspect", "-f", "{{.State.Running}}", name)
        return res.exit_code == 0 and res.stdout.strip() == "true"

    def stop(self, session_id: str) -> None:
        # `rm -f` of a missing container is not an error worth surfacing: stop is idempotent.
        self._admin("rm", "-f", self.container_name(session_id))

    def start(self, session_id: str, snapshot: bytes) -> None:
        name = self.container_name(session_id)
        if len(snapshot) > MAX_SNAPSHOT_BYTES:
            raise WorkspaceError("snapshot too large")
        if self.is_alive(session_id):
            raise WorkspaceError("session already exists")
        self.stop(session_id)  # a dead container still owns the name
        created = self._admin(*self._run_args(name), timeout_s=_PULL_TIMEOUT_S)
        if created.exit_code != 0:
            self.stop(session_id)
            raise WorkspaceError(f"could not start the workspace container: {created.stderr[:500]}")
        extracted = self._run(
            [
                self._docker,
                "exec",
                "-i",
                "-w",
                _WORKSPACE,
                name,
                "tar",
                "-x",
                "-f",
                "-",
                "--no-same-owner",
            ],
            timeout_s=_ADMIN_TIMEOUT_S * 5,
            max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
            stdin=snapshot,
        )
        if extracted.exit_code != 0:
            self.stop(session_id)
            raise WorkspaceError(f"could not unpack the snapshot: {extracted.stderr[:500]}")

    def _run_args(self, name: str) -> list[str]:
        tmpfs = "rw,exec,nosuid,nodev,uid=1000,gid=1000"
        return [
            "run",
            "-d",
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
            "--cpus",
            self._cpus,
            "--tmpfs",
            f"{_WORKSPACE}:{tmpfs},size=1g",
            "--tmpfs",
            f"/tmp:{tmpfs},size=256m",  # noqa: S108 - a path inside the container
            "-e",
            "HOME=/tmp",
            "-w",
            _WORKSPACE,
            self._image,
            "sleep",
            "infinity",
        ]

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
        if res.timed_out:
            # The docker client hung past the in-container timeout; the container is suspect.
            self.stop(session_id)
            return res
        if res.exit_code == 1 and res.stderr.startswith(
            ("Error response from daemon", "Error: No such")
        ):
            raise WorkspaceError("no such session")
        if res.exit_code in (_EXIT_TIMEOUT, _EXIT_KILLED):
            return ExecResult(None, res.stdout, res.stderr, timed_out=True, truncated=res.truncated)
        return res
