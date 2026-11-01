"""D5-06: the workspace port, the fake provider and the local Docker provider.

Layers, each with its own job:

* Hermetic tests (run everywhere): the snapshot format, the fake, the host-side runner
  (``run_capped``) against real host subprocesses, the in-container sweep script against a fake
  ``/proc``, and the ``LocalDockerProvider`` logic against ``FakeDocker``, a scripted stand-in for
  the ``docker`` CLI. They prove the controls are *requested* and the results are *classified*
  correctly.
* One conformance suite (``CHECKS``) runs against the fake here and against a real container in CI
  (``test_docker_conformance``), so the two cannot drift apart.
* ``integration`` tests (``test_docker_*``, CI only; they fail, not skip, when CI has no Docker):
  the controls against a real container. They prove the controls *hold*. ``tests/integration``
  re-exports them because CI's integration job only collects that directory.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sto.workspace.local_docker import (
    ENV_ALLOWLIST,
    SWEEP_BODY,
    SWEEP_SCRIPT,
    LocalDockerProvider,
    run_capped,
)
from sto.workspace.ports import (
    MAX_COMMAND_BYTES,
    ExecResult,
    FakeOutcome,
    FakeWorkspaceProvider,
    SessionExistsError,
    SessionLostError,
    SnapshotError,
    WorkspaceError,
    WorkspaceProvider,
    WorkspaceUnavailableError,
    cap_text,
    ensure_session,
    normalize_snapshot,
    pack_snapshot,
    read_snapshot,
    unpack_snapshot,
)

IMAGE = "python:3.12-slim"
SID = "s1"
NAME = "sto-ws-s1"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def ok(stdout: str = "", stderr: str = "") -> ExecResult:
    return ExecResult(0, stdout, stderr, timed_out=False, truncated=False)


def failed(code: int = 1, stderr: str = "") -> ExecResult:
    return ExecResult(code, "", stderr, timed_out=False, truncated=False)


# ======================================== snapshots


def test_snapshot_round_trip() -> None:
    files = {"a.txt": b"one", "dir/b.txt": b"two"}
    assert unpack_snapshot(pack_snapshot(files)) == files


def test_snapshots_accept_gzip_and_symlinks() -> None:
    snap = pack_snapshot(
        {"a.txt": b"one"}, links={"b.txt": "a.txt", "up": "../elsewhere"}, compress=True
    )
    assert snap[:2] == b"\x1f\x8b"
    parsed = read_snapshot(snap)
    assert parsed.files == {"a.txt": b"one"}
    assert parsed.links == {"b.txt": "a.txt", "up": "../elsewhere"}
    assert normalize_snapshot(snap)[:2] != b"\x1f\x8b"  # providers get a plain tar
    assert read_snapshot(normalize_snapshot(snap)) == parsed


@pytest.mark.parametrize("name", ["../escape", "/abs", "a/../../b", ""])
def test_pack_refuses_unsafe_paths(name: str) -> None:
    with pytest.raises(SnapshotError):
        pack_snapshot({name: b"x"})


def _tar_with(*members: tuple[str, str, bytes, str]) -> bytes:
    import io
    import tarfile

    kinds = {
        "file": tarfile.REGTYPE,
        "sym": tarfile.SYMTYPE,
        "hard": tarfile.LNKTYPE,
        "fifo": tarfile.FIFOTYPE,
        "dir": tarfile.DIRTYPE,
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, body, link in members:
            info = tarfile.TarInfo(name)
            info.type = kinds[kind]
            info.linkname = link
            info.size = len(body) if kind == "file" else 0
            tf.addfile(info, io.BytesIO(body) if kind == "file" else None)
    return buf.getvalue()


@pytest.mark.parametrize(
    "members",
    [
        pytest.param([("../evil", "file", b"x", "")], id="dotdot"),
        pytest.param([("/evil", "file", b"x", "")], id="absolute"),
        pytest.param([("h", "hard", b"", "other")], id="hardlink"),
        pytest.param([("f", "fifo", b"", "")], id="fifo"),
        pytest.param([("l", "sym", b"", "")], id="empty-link"),
        pytest.param([("l", "sym", b"", "/etc"), ("l/passwd", "file", b"x", "")], id="behind-link"),
    ],
)
def test_unsafe_snapshots_are_refused(members: list[tuple[str, str, bytes, str]]) -> None:
    with pytest.raises(SnapshotError):
        read_snapshot(_tar_with(*members))


def test_unreadable_and_oversize_snapshots_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SnapshotError):
        read_snapshot(b"not a tar")
    with pytest.raises(SnapshotError):
        read_snapshot(b"\x1f\x8bnot gzip")
    monkeypatch.setattr("sto.workspace.ports.MAX_SNAPSHOT_BYTES", 2000)
    with pytest.raises(SnapshotError):
        read_snapshot(pack_snapshot({"big": b"0" * 5000}))
    bomb = pack_snapshot({"big": b"0" * 5000}, compress=True)
    assert len(bomb) < 2000  # small on the wire, large once unpacked
    with pytest.raises(SnapshotError):
        read_snapshot(bomb)


def test_cap_text_keeps_a_prefix_and_flags_truncation() -> None:
    assert cap_text(b"abcdef", 4) == ("abcd", True)
    assert cap_text(b"abcd", 4) == ("abcd", False)
    assert cap_text(b"", 4) == ("", False)


def test_cap_text_caps_what_the_caller_receives_even_for_invalid_utf8() -> None:
    text, cut = cap_text(b"\xff" * 1000, 1000)  # each bad byte decodes to 3 bytes
    assert len(text.encode()) <= 1000
    assert cut
    text, cut = cap_text("é".encode() * 3, 5)  # never ends in half a character
    assert text == "éé"
    assert cut


# ======================================== the fake on its own


@pytest.fixture
def fake() -> FakeWorkspaceProvider:
    return FakeWorkspaceProvider()


def test_both_providers_satisfy_the_port(fake: FakeWorkspaceProvider) -> None:
    assert isinstance(fake, WorkspaceProvider)
    assert isinstance(LocalDockerProvider(runner=FakeDocker()), WorkspaceProvider)
    assert not isinstance(object(), WorkspaceProvider)


@pytest.mark.parametrize("bad", ["", "-x", "a b", "a/b", "a;b", "x" * 65])
def test_session_ids_are_validated(fake: FakeWorkspaceProvider, bad: str) -> None:
    with pytest.raises(WorkspaceError):
        fake.start(bad, pack_snapshot({}))


@pytest.mark.parametrize("timeout_s", [0, -1, 3601])
def test_timeout_must_be_in_range(fake: FakeWorkspaceProvider, timeout_s: float) -> None:
    fake.start(SID, pack_snapshot({}))
    with pytest.raises(WorkspaceError):
        fake.exec(SID, "true", timeout_s=timeout_s)


def test_a_command_over_the_agentcore_limit_is_refused(fake: FakeWorkspaceProvider) -> None:
    fake.start(SID, pack_snapshot({}))
    with pytest.raises(WorkspaceError):
        fake.exec(SID, "x" * (MAX_COMMAND_BYTES + 1))


def test_the_fake_never_follows_a_symlink_out_of_its_root(fake: FakeWorkspaceProvider) -> None:
    links = {"abs": "/etc/passwd", "up": "../../etc/passwd", "loop": "loop", "ok": "a.txt"}
    fake.start(SID, pack_snapshot({"a.txt": b"A"}, links=links))
    for name in ("abs", "up", "loop"):
        assert fake.exec(SID, f"cat {name}").exit_code == 1, name
    assert fake.exec(SID, "cat ok").stdout == "A"
    assert fake.exec(SID, "cat ../a.txt").exit_code == 1


def test_a_fake_session_that_cannot_be_cleaned_up_is_destroyed(fake: FakeWorkspaceProvider) -> None:
    fake.script("stuck", FakeOutcome(duration_s=99, unkillable=True))
    fake.start(SID, pack_snapshot({}))
    res = fake.exec(SID, "stuck", timeout_s=1)
    assert res.timed_out
    assert res.session_destroyed
    assert not fake.is_alive(SID)


def test_a_fake_command_killed_at_the_cap_that_cannot_be_cleaned_up_destroys_the_session(
    fake: FakeWorkspaceProvider,
) -> None:
    fake.script("noisy", FakeOutcome(stdout="x" * 500, unkillable=True))
    fake.start(SID, pack_snapshot({}))
    res = fake.exec(SID, "noisy", max_output_bytes=100)
    assert (res.exit_code, res.truncated, res.session_destroyed) == (None, True, True)
    assert not fake.is_alive(SID)


def test_a_fake_command_that_finishes_with_invalid_utf8_at_the_cap_keeps_its_exit_status(
    fake: FakeWorkspaceProvider,
) -> None:
    fake.script("bad", FakeOutcome(stdout=b"\xff" * 1000, exit_code=3))
    fake.start(SID, pack_snapshot({}))
    res = fake.exec(SID, "bad", max_output_bytes=1000)  # exactly the cap: nothing is killed
    assert res.exit_code == 3
    assert res.truncated  # the decoded text had to be cut
    assert len(res.stdout.encode()) <= 1000


def test_normalize_snapshot_decompresses_once(monkeypatch: pytest.MonkeyPatch) -> None:
    import sto.workspace.ports as ports

    calls: list[int] = []
    real = ports._plain_tar  # noqa: SLF001

    def counting(data: bytes) -> bytes:
        calls.append(1)
        return real(data)

    monkeypatch.setattr(ports, "_plain_tar", counting)
    normalize_snapshot(pack_snapshot({"a": b"1"}, compress=True))
    assert len(calls) == 1


# ======================================== recovery from the branch


def test_a_lost_session_recovers_from_the_branch_and_loses_unpushed_work(
    fake: FakeWorkspaceProvider,
) -> None:
    fetched: list[str] = []

    def source(branch: str) -> bytes:
        fetched.append(branch)
        return pack_snapshot({"src/app.py": b"print('pushed')"})

    fake.script("echo scratch > scratch.txt", FakeOutcome(writes={"scratch.txt": b"scratch\n"}))
    assert ensure_session(fake, SID, "sto/run-1", source) is True
    fake.exec(SID, "echo scratch > scratch.txt")
    assert fake.exec(SID, "cat scratch.txt").stdout == "scratch\n"
    assert ensure_session(fake, SID, "sto/run-1", source) is False
    assert len(fetched) == 1

    fake.kill(SID)
    assert ensure_session(fake, SID, "sto/run-1", source) is True
    assert fake.exec(SID, "cat src/app.py").stdout == "print('pushed')"
    assert fake.exec(SID, "cat scratch.txt").exit_code != 0


class FlakyProvider(FakeWorkspaceProvider):
    """is_alive cannot tell (daemon slow); every other call is recorded."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def is_alive(self, session_id: str) -> bool:
        raise WorkspaceUnavailableError("inspect timed out")

    def start(self, session_id: str, snapshot: bytes) -> None:
        self.calls.append("start")
        super().start(session_id, snapshot)

    def stop(self, session_id: str) -> None:
        self.calls.append("stop")
        super().stop(session_id)


def test_ensure_session_never_replaces_a_session_it_cannot_inspect() -> None:
    flaky = FlakyProvider()
    with pytest.raises(WorkspaceUnavailableError):
        ensure_session(flaky, SID, "b", lambda _b: pack_snapshot({}))
    assert flaky.calls == []  # no start, and above all no stop


def test_ensure_session_only_starts_a_dead_session_and_never_stops_it_first() -> None:
    class Recording(FakeWorkspaceProvider):
        def __init__(self) -> None:
            super().__init__()
            self.calls: list[str] = []

        def start(self, session_id: str, snapshot: bytes) -> None:
            self.calls.append("start")
            super().start(session_id, snapshot)

        def stop(self, session_id: str) -> None:
            self.calls.append("stop")
            super().stop(session_id)

    rec = Recording()
    assert ensure_session(rec, SID, "b", lambda _b: pack_snapshot({})) is True
    assert rec.calls == ["start"]


def test_ensure_session_accepts_losing_a_creation_race() -> None:
    class Raced(FakeWorkspaceProvider):
        def __init__(self) -> None:
            super().__init__()
            self.asked = 0

        def is_alive(self, session_id: str) -> bool:
            self.asked += 1
            return self.asked > 1  # dead at first, alive once the peer has started it

        def start(self, session_id: str, snapshot: bytes) -> None:
            raise SessionExistsError("peer won")

    assert ensure_session(Raced(), SID, "b", lambda _b: pack_snapshot({})) is False


# ======================================== host-side runner (real subprocesses)

RUN_DEADLINE_S = 20  # every host subprocess in these tests is bounded; a hang fails, not blocks


def test_run_capped_returns_output_and_exit_code() -> None:
    res = run_capped(
        ["sh", "-c", "printf out; printf err >&2; exit 3"], timeout_s=10, max_output_bytes=100
    )
    assert (res.exit_code, res.stdout, res.stderr) == (3, "out", "err")
    assert not res.timed_out
    assert not res.truncated


def test_run_capped_feeds_stdin() -> None:
    res = run_capped(["cat"], timeout_s=10, max_output_bytes=100, stdin=b"piped")
    assert res.stdout == "piped"


def test_run_capped_timeout_kills_the_command_and_returns_promptly() -> None:
    start = time.monotonic()
    res = run_capped(["sh", "-c", "sleep 60"], timeout_s=1, max_output_bytes=100)
    assert res.timed_out
    assert res.exit_code is None
    assert time.monotonic() - start < RUN_DEADLINE_S


def test_run_capped_timeout_kills_the_whole_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "survivor"
    res = run_capped(
        ["sh", "-c", f"(sleep 3; touch {marker}) & wait"], timeout_s=1, max_output_bytes=100
    )
    assert res.timed_out
    time.sleep(4)
    assert not marker.exists(), "a grandchild outlived the timeout"


def test_run_capped_timeout_holds_when_a_grandchild_keeps_the_pipe_open() -> None:
    start = time.monotonic()
    res = run_capped(["sh", "-c", "sleep 60 & wait"], timeout_s=1, max_output_bytes=100)
    assert res.timed_out
    assert time.monotonic() - start < RUN_DEADLINE_S


def test_run_capped_output_cap_truncates_and_stops_an_endless_writer() -> None:
    start = time.monotonic()
    res = run_capped(["yes", "0123456789"], timeout_s=30, max_output_bytes=1000)
    assert res.truncated
    assert res.exit_code is None  # killed at the cap: no signal number leaks out
    assert len(res.stdout.encode()) <= 1000
    assert res.stdout.startswith("0123456789\n")
    assert not res.timed_out, "the cap must stop the writer; the timeout is not the control"
    assert time.monotonic() - start < RUN_DEADLINE_S


def test_run_capped_caps_stderr_separately() -> None:
    res = run_capped(["sh", "-c", "yes e >&2"], timeout_s=30, max_output_bytes=500)
    assert res.truncated
    assert len(res.stderr.encode()) <= 500
    assert res.stdout == ""


def test_run_capped_caps_what_the_caller_receives_for_invalid_utf8() -> None:
    res = run_capped(
        ["sh", "-c", "head -c 1000 /dev/zero | tr '\\000' '\\377'"],
        timeout_s=10,
        max_output_bytes=1000,
    )
    assert len(res.stdout.encode()) <= 1000
    assert res.truncated  # bytes were lost to the cap on the decoded text


def test_run_capped_missing_binary_is_a_workspace_error() -> None:
    with pytest.raises(WorkspaceError):
        run_capped(["/nonexistent/dkr", "ps"], timeout_s=5, max_output_bytes=100)


def test_run_capped_runs_with_an_empty_environment_apart_from_the_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_canary_not_for_children")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "canary")
    res = run_capped(["sh", "-c", "env"], timeout_s=10, max_output_bytes=10_000)
    names = {line.split("=", 1)[0] for line in res.stdout.splitlines() if "=" in line}
    assert "GITHUB_TOKEN" not in names
    assert "AWS_SECRET_ACCESS_KEY" not in names
    assert names - {"PWD", "SHLVL", "_", "OLDPWD"} <= set(ENV_ALLOWLIST)


def test_the_allowlist_keeps_remote_docker_tls_settings() -> None:
    assert {"DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_HOST"} <= set(ENV_ALLOWLIST)


# ======================================== the in-container sweep

DASH = shutil.which("dash") or "sh"


def test_the_sweep_script_parses() -> None:
    parsed = subprocess.run(
        [DASH, "-n", "-c", SWEEP_SCRIPT], capture_output=True, timeout=20, check=False
    )
    assert parsed.returncode == 0, parsed.stderr


def _fake_proc(tmp_path: Path, procs: dict[int, str]) -> Path:
    root = tmp_path / "proc"
    for pid, stat in procs.items():
        (root / str(pid)).mkdir(parents=True)
        (root / str(pid) / "stat").write_text(stat)
    (root / "self").mkdir()
    return root


def _run_sweep(root: Path, log: Path, *, kills: bool) -> subprocess.CompletedProcess[str]:
    # The real body against a fake /proc. `sto_kill` is a stub that records the call and, when
    # `kills`, removes the victim's entry; the shell registers its own pid in the tree first, so
    # the test can see whether the sweep spares itself. Nothing on this host is signalled.
    die = 'if [ "$1" = -KILL ]; then rm -rf "$PROC/$2"; fi; ' if kills else ""
    prelude = (
        f'PROC={root}\nmkdir "$PROC/$$"\necho "$$" > {log}.self\n'
        f'sto_kill() {{ echo "$@" >> {log}; {die}}}\nsto_wait() {{ :; }}\n'
    )
    return subprocess.run(
        [DASH, "-c", prelude + SWEEP_BODY], capture_output=True, text=True, timeout=30, check=False
    )


def test_the_sweep_kills_everything_but_pid_1_the_keeper_and_itself(tmp_path: Path) -> None:
    root = _fake_proc(
        tmp_path,
        {
            1: "1 (tini) S 0 1 1\n",
            9: "9 (sleep) S 1 9 9\n",  # offender
            2: "2 (sleep) S 1 2 2\n",  # keeper: lowest PID above 1, whatever order /proc lists
            7: "7 (zl) Z 1 7 7\n",  # a zombie leader whose threads are still running
            12: "12 (a) Z \nb) S 1 12 12\n",  # a comm that imitates a stat line
        },
    )
    log = tmp_path / "kills"
    res = _run_sweep(root, log, kills=True)
    assert (res.returncode, res.stdout.strip()) == (0, "clean"), res.stderr
    killed = log.read_text().split("\n")
    own = (tmp_path / "kills.self").read_text().strip()
    assert "-STOP 9" in killed
    for victim in ("9", "7", "12"):  # state is never believed: a "Z" is killed like any other
        assert f"-KILL {victim}" in killed, victim
    for spared in ("1", "2", own):
        assert not any(line.endswith(f" {spared}") for line in killed), spared


def test_the_sweep_fails_loudly_when_a_process_will_not_die(tmp_path: Path) -> None:
    root = _fake_proc(tmp_path, {1: "1 (tini) S 0\n", 2: "2 (sleep) S 1\n", 5: "5 (stuck) S 1\n"})
    res = _run_sweep(root, tmp_path / "kills", kills=False)
    assert res.returncode == 1
    assert res.stdout.strip() == "survivors: 5"


# ======================================== docker logic against FakeDocker

WALL = 1_700_000_000.0


@dataclass
class Box:
    cid: str
    state: str
    created: float = WALL
    ready: bool = False


class FakeDocker:
    """A scripted stand-in for the ``docker`` CLI: a tiny daemon with containers and failures."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.stdins: list[bytes | None] = []
        self.containers: dict[str, Box] = {}
        self.down = False
        self.down_on: str | None = None  # the daemon dies as this verb is called
        self.fail: set[str] = set()  # create, start, extract, touch, rm, sweep, version, ps, stats
        self.exec_script: dict[str, tuple[ExecResult, float]] = {}  # command -> (result, seconds)
        self.hooks: dict[str, Callable[[], None]] = {}  # command -> run while it "executes"
        self.sweep_result: ExecResult | None = None  # what the in-container sweep reports
        self.task_counts: list[int] = [
            2
        ]  # what `docker stats` reports, one per call (last repeats)
        self.create_output: str | None = None  # override the id `create` prints
        self.now = 0.0
        self.wall_time = WALL
        self.created = 0

    def clock(self) -> float:
        return self.now

    def wall(self) -> float:
        return self.wall_time

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]

    def sweeps(self) -> list[list[str]]:
        return [c for c in self.calls if SWEEP_SCRIPT in c]

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        max_output_bytes: int,
        stdin: bytes | None = None,
    ) -> ExecResult:
        args = list(argv)
        self.calls.append(args)
        self.stdins.append(stdin)
        verb = args[1]
        if verb == self.down_on:
            self.down = True
        if self.down:
            return failed(1, "Cannot connect to the Docker daemon")
        if verb in self.fail and verb in ("version", "ps", "stats"):
            return failed(1, f"{verb} failed")
        handler = getattr(self, f"_{verb}")
        result: ExecResult = handler(args)
        return result

    def _version(self, args: list[str]) -> ExecResult:
        return ok("27.0\n")

    def _ps(self, args: list[str]) -> ExecResult:
        pattern = args[args.index("--filter") + 1].removeprefix("name=")
        for name, box in self.containers.items():
            if re.search(pattern, "/" + name):  # the filter is a regex, as in Docker
                return ok(f"{box.state}\n")
        return ok("")

    def _inspect(self, args: list[str]) -> ExecResult:
        box = self.containers.get(args[-1])
        if box is None:
            return failed(1, "No such container")
        created = datetime.fromtimestamp(box.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        return ok(f"{box.cid} {created}\n")

    def _stats(self, args: list[str]) -> ExecResult:
        count = self.task_counts.pop(0) if len(self.task_counts) > 1 else self.task_counts[0]
        return ok(f"{count}\n")

    def _create(self, args: list[str]) -> ExecResult:
        name = args[args.index("--name") + 1]
        if "create" in self.fail:
            return failed(1, "pull access denied")
        if name in self.containers:
            return failed(125, f"Conflict. The container name /{name} is already in use")
        self.created += 1
        cid = f"{self.created:064x}"
        self.containers[name] = Box(cid, "created", self.wall_time)
        return ok((self.create_output or cid) + "\n")

    def _find(self, target: str) -> str | None:
        for name, box in self.containers.items():
            if target in (name, box.cid):
                return name
        return None

    def _start(self, args: list[str]) -> ExecResult:
        name = self._find(args[2])
        if "start" in self.fail or name is None:
            return failed(1, "cannot start")
        self.containers[name].state = "running"
        return ok(args[2] + "\n")

    def _rm(self, args: list[str]) -> ExecResult:
        force = "-f" in args
        name = self._find(args[-1])
        if "rm" in self.fail:
            return failed(1, "rm failed")
        if name is None:
            return ok() if force else failed(1, "No such container")
        if self.containers[name].state == "running" and not force:
            return failed(1, "cannot remove a running container")
        del self.containers[name]
        return ok()

    def _exec(self, args: list[str]) -> ExecResult:
        rest = args[2:]
        while rest and rest[0] in ("-i", "-w"):
            rest = rest[2:] if rest[0] == "-w" else rest[1:]
        name = self._find(rest[0])
        if name is None or self.containers[name].state != "running":
            return failed(1, "Error response from daemon: No such container")
        box = self.containers[name]
        if rest[1] == "tar":
            return failed(2, "tar: a: Cannot open") if "extract" in self.fail else ok()
        if rest[1] == "touch":
            if "touch" in self.fail:
                return failed(1, "touch failed")
            box.ready = True
            return ok()
        if rest[1] == "test":
            return ok() if box.ready else failed(1)
        if rest[1:3] == ["sh", "-c"] and rest[3] == SWEEP_SCRIPT:
            if "sweep" in self.fail:
                return ExecResult(1, "survivors: 5\n", "", timed_out=False, truncated=False)
            return self.sweep_result or ok("clean\n")
        command = rest[-1]
        if command in self.hooks:
            self.hooks[command]()
        result, seconds = self.exec_script.get(command, (ok(), 0.0))
        self.now += seconds
        return result


def make_provider(docker: FakeDocker) -> LocalDockerProvider:
    return LocalDockerProvider(
        image=IMAGE,
        runner=docker,
        docker="docker",
        clock=docker.clock,
        wall=docker.wall,
        sleep=lambda _s: None,
    )


@pytest.fixture
def docker() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def provider(docker: FakeDocker) -> LocalDockerProvider:
    return make_provider(docker)


@pytest.fixture
def live_provider(provider: LocalDockerProvider) -> LocalDockerProvider:
    provider.start(SID, pack_snapshot({}))
    return provider


EXPECTED_CREATE = [
    "docker", "create", "--init", "--name", NAME, "--label", "sto.workspace=1",
    "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--read-only", "--user", "1000:1000", "--pids-limit", "512",
    "--memory", "2g", "--memory-swap", "2g", "--cpus", "2",
    "--tmpfs", "/workspace:rw,exec,nosuid,nodev,uid=1000,gid=1000,size=1g",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev,uid=1000,gid=1000,size=256m",
    "-e", "HOME=/tmp", "-w", "/workspace", IMAGE, "sleep", "infinity",
]  # fmt: skip


def test_the_container_is_created_with_exactly_these_flags(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    provider.start(SID, pack_snapshot({}))
    create = next(c for c in docker.calls if c[1] == "create")
    # An exact match, so a flag added (--cap-add, --pid host, --device, -v, --privileged) or lost
    # (--cpus, nosuid, --init, --user) changes this list and fails here.
    assert create == EXPECTED_CREATE


CID = f"{1:064x}"
OTHER = f"{5:064x}"


def test_start_extracts_a_plain_tar_through_stdin_then_marks_the_workspace_ready(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    gz = pack_snapshot({"a": b"1"}, links={"b": "a"}, compress=True)
    provider.start(SID, gz)
    assert docker.verbs() == ["ps", "create", "start", "exec", "exec"]
    assert docker.calls[2] == ["docker", "start", CID]
    assert docker.calls[3] == [
        "docker", "exec", "-i", "-w", "/workspace", CID, "tar", "-x", "-f", "-", "--no-same-owner",
    ]  # fmt: skip
    assert docker.stdins[3] == normalize_snapshot(gz)
    assert read_snapshot(docker.stdins[3] or b"").links == {"b": "a"}
    assert docker.calls[4] == [
        "docker",
        "exec",
        CID,
        "touch",
        "/tmp/.sto-ready",
    ]  # after the unpack


@pytest.mark.parametrize("step", ["create", "start", "extract", "touch"])
def test_a_start_that_fails_part_way_removes_only_its_own_container_by_id(
    provider: LocalDockerProvider, docker: FakeDocker, step: str
) -> None:
    docker.fail.add(step)
    with pytest.raises(WorkspaceError):
        provider.start(SID, pack_snapshot({}))
    rms = [c for c in docker.calls if c[1] == "rm"]
    if step == "create":
        assert rms == []  # nothing of ours exists
    else:
        assert rms == [["docker", "rm", "-f", "-v", CID]]
        failing_call = max(i for i, c in enumerate(docker.calls) if c[1] in ("start", "exec"))
        assert docker.calls.index(rms[0]) > failing_call  # cleanup runs after the failure
        assert NAME not in docker.containers  # and nothing is left behind


def test_a_container_id_that_is_not_an_id_is_refused_without_starting_anything(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.create_output = "Error: something printed on stdout"
    with pytest.raises(WorkspaceError):
        provider.start(SID, pack_snapshot({}))
    assert "start" not in docker.verbs()
    assert "rm" not in docker.verbs()


def test_a_start_never_removes_a_running_winners_container(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    provider.start(SID, pack_snapshot({}))
    docker.calls.clear()
    with pytest.raises(SessionExistsError):
        provider.start(SID, pack_snapshot({}))
    assert "rm" not in docker.verbs()
    assert docker.containers[NAME].state == "running"


def test_losing_the_create_race_is_session_exists_so_ensure_session_does_not_block_the_run(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    # The peer's container appears between our `ps` and our `create`. Docker answers with a real
    # conflict message; the provider must call that "exists", which ensure_session understands.
    peer = Box(OTHER, "running", ready=True)
    seen = {"ps": 0}
    original = docker._ps  # noqa: SLF001

    def ps_before_the_peer(args: list[str]) -> ExecResult:
        seen["ps"] += 1
        if seen["ps"] == 1:
            return ok("")
        docker.containers[NAME] = peer
        return original(args)

    docker._ps = ps_before_the_peer  # type: ignore[method-assign]  # noqa: SLF001
    docker.containers[NAME] = peer  # created by the peer after the first ps ...
    del docker.containers[NAME]
    original_create = docker._create  # noqa: SLF001

    def create_after_peer(args: list[str]) -> ExecResult:
        docker.containers[NAME] = peer  # ... and before our create
        return original_create(args)

    docker._create = create_after_peer  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(SessionExistsError):
        provider.start(SID, pack_snapshot({}))
    assert "rm" not in docker.verbs()
    assert docker.containers[NAME] is peer

    docker.calls.clear()
    seen["ps"] = 0
    docker.containers.pop(NAME)
    docker._ps = original  # type: ignore[method-assign]  # noqa: SLF001
    docker._create = create_after_peer  # type: ignore[method-assign]  # noqa: SLF001
    assert ensure_session(provider, SID, "b", lambda _b: pack_snapshot({})) is False


def test_a_young_unfinished_start_is_transient_and_is_left_alone(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    for state, ready in (("created", False), ("running", False)):  # between create and ready
        docker.containers[NAME] = Box(OTHER, state, created=docker.wall_time - 5, ready=ready)
        with pytest.raises(WorkspaceUnavailableError) as raised:
            provider.start(SID, pack_snapshot({}))
        assert raised.value.retryable
        assert "rm" not in docker.verbs()


def test_ensure_session_does_not_call_a_half_unpacked_session_alive(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.containers[NAME] = Box(OTHER, "running", created=docker.wall_time - 5, ready=False)
    assert not provider.is_alive(SID)  # running, but the marker is not there yet
    with pytest.raises(WorkspaceUnavailableError):
        ensure_session(provider, SID, "b", lambda _b: pack_snapshot({}))
    docker.containers[NAME].ready = True
    assert provider.is_alive(SID)
    assert ensure_session(provider, SID, "b", lambda _b: pack_snapshot({})) is False


@pytest.mark.parametrize("state", ["created", "running", "paused"])
def test_a_crashed_start_is_taken_over_once_it_is_old_enough(
    provider: LocalDockerProvider, docker: FakeDocker, state: str
) -> None:
    docker.containers[NAME] = Box(OTHER, state, created=docker.wall_time - 3600, ready=False)
    provider.start(SID, pack_snapshot({}))
    assert ["docker", "rm", "-f", "-v", OTHER] in docker.calls  # by the id we inspected
    assert docker.containers[NAME].cid == CID
    assert provider.is_alive(SID)


def test_a_ready_running_session_is_never_taken_over_however_old(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.containers[NAME] = Box(OTHER, "running", created=docker.wall_time - 99999, ready=True)
    with pytest.raises(SessionExistsError):
        provider.start(SID, pack_snapshot({}))
    assert "rm" not in docker.verbs()


@pytest.mark.parametrize("state", ["exited", "dead"])
def test_a_dead_leftover_is_removed_without_force(
    provider: LocalDockerProvider, docker: FakeDocker, state: str
) -> None:
    docker.containers[NAME] = Box(OTHER, state)
    provider.start(SID, pack_snapshot({}))
    rm = next(c for c in docker.calls if c[1] == "rm")
    assert rm == ["docker", "rm", "-v", NAME]  # no -f: a live container would be refused
    assert docker.containers[NAME].cid == CID


def test_a_leftover_that_came_alive_is_not_removed(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.containers[NAME] = Box(OTHER, "exited")
    original = docker._rm  # noqa: SLF001

    def revived(args: list[str]) -> ExecResult:
        docker.containers[NAME].state = "running"  # the peer restarted it just now
        return original(args)

    docker._rm = revived  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(SessionExistsError):
        provider.start(SID, pack_snapshot({}))
    assert docker.containers[NAME].cid == OTHER


def test_the_name_filter_matches_only_this_session(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.containers["sto-ws-axb"] = Box(OTHER, "running", ready=True)  # '.' is a regex wildcard
    assert not provider.is_alive("a.b")
    docker.containers["sto-ws-a.b"] = Box(CID, "running", ready=True)
    assert provider.is_alive("a.b")
    assert docker.calls[0][docker.calls[0].index("--filter") + 1] == r"name=^/sto\-ws\-a\.b$"


def test_a_snapshot_that_is_unsafe_is_refused_before_docker_is_touched(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    with pytest.raises(SnapshotError):
        provider.start(SID, _tar_with(("../x", "file", b"1", "")))
    assert docker.calls == []


# ---- infrastructure failures are not command results


def test_a_daemon_that_is_down_is_transient_everywhere(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.down = True
    for call in (
        lambda: live_provider.exec(SID, "pytest"),
        lambda: live_provider.is_alive(SID),
        lambda: live_provider.stop(SID),
        lambda: live_provider.start("s2", pack_snapshot({})),
    ):
        with pytest.raises(WorkspaceUnavailableError) as raised:
            call()
        assert raised.value.retryable


@pytest.mark.parametrize("verb", ["create", "start", "exec"])
def test_a_daemon_that_dies_during_start_is_transient_so_the_run_retries(
    provider: LocalDockerProvider, docker: FakeDocker, verb: str
) -> None:
    docker.down_on = verb
    with pytest.raises(WorkspaceUnavailableError) as raised:
        provider.start(SID, pack_snapshot({}))
    assert raised.value.retryable


def test_a_start_that_fails_with_the_daemon_up_is_permanent(
    provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.fail.add("create")
    with pytest.raises(WorkspaceError) as raised:
        provider.start(SID, pack_snapshot({}))
    assert not isinstance(raised.value, WorkspaceUnavailableError)


def test_stop_raises_unless_the_container_is_really_gone(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.fail.add("rm")
    with pytest.raises(WorkspaceUnavailableError):
        live_provider.stop(SID)  # rm failed and the container is still there
    del docker.containers[NAME]
    live_provider.stop(SID)  # rm failed but it is gone: idempotent
    docker.fail.discard("rm")
    live_provider.stop(SID)


def test_stop_removes_volumes_too(live_provider: LocalDockerProvider, docker: FakeDocker) -> None:
    live_provider.stop(SID)
    assert docker.calls[-1] == ["docker", "rm", "-f", "-v", NAME]


def test_is_alive_only_for_a_running_container(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    assert live_provider.is_alive(SID)
    for state in ("exited", "created", "paused"):
        docker.containers[NAME].state = state
        assert not live_provider.is_alive(SID)
    docker.containers[NAME].state = "running"
    docker.containers[NAME].ready = False  # running, but not (or no longer) fully unpacked
    assert not live_provider.is_alive(SID)
    del docker.containers[NAME]
    assert not live_provider.is_alive(SID)


# ---- exec result classification


def test_exec_runs_under_an_in_container_timeout_with_the_exact_argv(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    live_provider.exec(SID, "make test", timeout_s=7, max_output_bytes=123)
    assert docker.calls[-1] == [
        "docker", "exec", "-w", "/workspace", NAME,
        "timeout", "-k", "2", "7", "sh", "-c", "make test",
    ]  # fmt: skip


def test_a_failing_command_is_returned_not_raised_and_stderr_is_never_classified(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    for text in (
        "Error: No such file or directory: foo.txt",
        "Error response from daemon: x",
        "Error: No such container: sto-ws-s1",
    ):
        docker.exec_script["cmd"] = (failed(1, text), 0.0)
        res = live_provider.exec(SID, "cmd")
        assert (res.exit_code, res.stderr) == (1, text)
        assert not res.session_destroyed


def test_a_failure_with_the_container_gone_is_a_lost_session(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    del docker.containers[NAME]
    with pytest.raises(SessionLostError):
        live_provider.exec(SID, "true")


def test_a_failure_with_an_unanswering_daemon_is_transient_not_a_test_failure(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.exec_script["cmd"] = (failed(1, "whatever"), 0.0)
    docker.fail.add("ps")
    with pytest.raises(WorkspaceUnavailableError):
        live_provider.exec(SID, "cmd")


@pytest.mark.parametrize("status", [124, 137])
def test_a_command_that_exits_124_or_137_by_itself_reports_its_exit_code(
    live_provider: LocalDockerProvider, docker: FakeDocker, status: int
) -> None:
    docker.exec_script["cmd"] = (failed(status), 0.0)  # e.g. `kill -9 $$`, OOM, a nested timeout
    res = live_provider.exec(SID, "cmd", timeout_s=30)
    assert res.exit_code == status
    assert not res.timed_out
    assert not any(SWEEP_SCRIPT in call for call in docker.calls)  # nothing to clean up


@pytest.mark.parametrize("status", [124, 137])
def test_a_command_that_ran_out_its_time_is_timed_out_and_swept(
    live_provider: LocalDockerProvider, docker: FakeDocker, status: int
) -> None:
    docker.exec_script["cmd"] = (failed(status), 30.0)
    res = live_provider.exec(SID, "cmd", timeout_s=30)
    assert res.timed_out
    assert res.exit_code is None
    assert not res.session_destroyed
    assert docker.sweeps() == [["docker", "exec", NAME, "sh", "-c", SWEEP_SCRIPT]]
    assert docker.verbs()[-3:] == ["stats", "stats", "stats"]  # then the host checks it itself


def test_a_cap_kills_the_command_and_sweeps_before_returning(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.exec_script["noisy"] = (
        ExecResult(None, "x" * 10, "", timed_out=False, truncated=True),
        0.5,
    )
    res = live_provider.exec(SID, "noisy", max_output_bytes=10)
    assert (res.exit_code, res.truncated, res.timed_out, res.session_destroyed) == (
        None,
        True,
        False,
        False,
    )
    assert len(docker.sweeps()) == 1


@pytest.mark.parametrize("case", ["timeout", "cap"])
def test_a_sweep_that_cannot_be_verified_destroys_the_session_and_says_so(
    live_provider: LocalDockerProvider, docker: FakeDocker, case: str
) -> None:
    if case == "timeout":
        docker.exec_script["cmd"] = (failed(124), 5.0)
    else:
        docker.exec_script["cmd"] = (ExecResult(None, "x", "", False, True), 0.0)
    docker.fail.add("sweep")
    res = live_provider.exec(SID, "cmd", timeout_s=5)
    assert res.session_destroyed
    assert NAME not in docker.containers
    assert docker.calls[-1] == ["docker", "rm", "-f", "-v", NAME]


def test_a_docker_client_that_hangs_past_the_deadline_destroys_the_session(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.exec_script["hang"] = (ExecResult(None, "", "", timed_out=True, truncated=False), 0.0)
    res = live_provider.exec(SID, "hang", timeout_s=1)
    assert res.timed_out
    assert res.session_destroyed
    assert NAME not in docker.containers


def test_a_normal_result_is_passed_through_untouched(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.exec_script["cmd"] = (ok("out\n", "err\n"), 1.0)
    assert live_provider.exec(SID, "cmd") == ok("out\n", "err\n")
    assert not any(SWEEP_SCRIPT in call for call in docker.calls)


def test_a_command_that_finished_with_text_over_the_cap_keeps_its_exit_status_and_is_not_swept(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    # exit status known, text only cut by the decoded-size cap: nothing was killed
    cut = ExecResult(3, "x" * 10, "", timed_out=False, truncated=True)
    docker.exec_script["cmd"] = (cut, 0.0)
    res = live_provider.exec(SID, "cmd", max_output_bytes=10)
    assert (res.exit_code, res.truncated, res.session_destroyed) == (3, True, False)
    assert docker.sweeps() == []


# ---- the sweep's own report is never enough


def _swept(live_provider: LocalDockerProvider, docker: FakeDocker) -> ExecResult:
    docker.exec_script["cmd"] = (failed(124), 5.0)
    return live_provider.exec(SID, "cmd", timeout_s=5)


@pytest.mark.parametrize(
    "report",
    [
        pytest.param(ExecResult(1, "clean\n", "", False, False), id="clean-but-exit-1"),
        pytest.param(ExecResult(0, "survivors: 7\n", "", False, False), id="exit-0-not-clean"),
        pytest.param(ExecResult(0, "", "", False, False), id="exit-0-silent"),
        pytest.param(ExecResult(None, "clean\n", "", True, False), id="stopped-and-timed-out"),
        pytest.param(ExecResult(0, "clean\n", "", True, False), id="timed-out-yet-exit-0"),
    ],
)
def test_a_sweep_report_that_is_not_exactly_clean_with_exit_0_destroys_the_session(
    live_provider: LocalDockerProvider, docker: FakeDocker, report: ExecResult
) -> None:
    docker.sweep_result = report
    res = _swept(live_provider, docker)
    assert res.session_destroyed
    assert NAME not in docker.containers
    assert "stats" not in docker.verbs()[-3:]  # it never got as far as being believed


@pytest.mark.parametrize("tasks", [[3], [5], [2, 2, 3], [2, 2, 3] * 10, [0]])
def test_a_clean_report_is_not_believed_when_the_host_still_counts_extra_tasks(
    live_provider: LocalDockerProvider, docker: FakeDocker, tasks: list[int]
) -> None:
    # The sweep says clean (it runs as the same user as the hostile code), but the cgroup disagrees:
    # a zombie leader with live threads, a process the sweep could not see, a hop in progress.
    docker.task_counts = tasks
    res = _swept(live_provider, docker)
    assert res.session_destroyed
    assert NAME not in docker.containers


def test_a_host_that_cannot_count_tasks_destroys_the_session(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    docker.fail.add("stats")
    assert _swept(live_provider, docker).session_destroyed


@pytest.mark.parametrize("tasks", [[2], [4, 3, 2], [2, 3, 2, 2, 2], [2, 2, 3, 2, 2, 2]])
def test_a_session_that_settles_to_pid_1_and_the_keeper_is_kept(
    live_provider: LocalDockerProvider, docker: FakeDocker, tasks: list[int]
) -> None:
    docker.task_counts = tasks  # three equal counts in a row are required, so one 2 is not enough
    res = _swept(live_provider, docker)
    assert not res.session_destroyed
    assert docker.containers[NAME].state == "running"


# ---- one command at a time per session


def test_exec_calls_on_one_session_are_serialized_so_a_sweep_never_kills_a_neighbour(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    started, release = threading.Event(), threading.Event()

    def hold() -> None:
        started.set()
        assert release.wait(30)

    docker.hooks["slow"] = hold
    docker.exec_script["doomed"] = (failed(124), 5.0)  # will time out, and so be swept
    results: dict[str, ExecResult] = {}

    def run(key: str, command: str, timeout_s: float) -> None:
        results[key] = live_provider.exec(SID, command, timeout_s=timeout_s)

    first = threading.Thread(target=run, args=("a", "slow", 60))
    first.start()
    assert started.wait(10)
    second = threading.Thread(target=run, args=("b", "doomed", 5))
    second.start()
    time.sleep(0.4)
    assert not any("doomed" in call for call in docker.calls), "ran while another command was live"
    assert docker.sweeps() == []
    release.set()
    first.join(30)
    second.join(30)
    assert results["a"].exit_code == 0
    assert results["b"].timed_out
    assert not results["a"].session_destroyed


def test_the_lock_is_per_session_so_other_sessions_keep_running(
    live_provider: LocalDockerProvider, docker: FakeDocker
) -> None:
    live_provider.start("s2", pack_snapshot({}))
    started, release = threading.Event(), threading.Event()

    def hold() -> None:
        started.set()
        release.wait(30)

    docker.hooks["slow"] = hold
    holder = threading.Thread(target=lambda: live_provider.exec(SID, "slow", timeout_s=60))
    holder.start()
    assert started.wait(10)
    other: dict[str, ExecResult] = {}
    side = threading.Thread(target=lambda: other.setdefault("r", live_provider.exec("s2", "true")))
    side.start()
    side.join(10)
    assert "r" in other, "a different session was blocked"
    release.set()
    holder.join(30)


def test_image_references_may_start_with_an_uppercase_letter() -> None:
    LocalDockerProvider(image="Registry.example/Team/Image:1", runner=FakeDocker())


def test_exec_refuses_oversize_nul_and_flag_like_input(live_provider: LocalDockerProvider) -> None:
    with pytest.raises(WorkspaceError):
        live_provider.exec(SID, "x" * (MAX_COMMAND_BYTES + 1))
    with pytest.raises(WorkspaceError):
        live_provider.exec(SID, "echo a\0b")
    with pytest.raises(WorkspaceError):
        live_provider.exec("--privileged", "true")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"image": "--network=host"},
        {"image": "-v"},
        {"image": ""},
        {"image": "a b"},
        {"memory": "--privileged"},
        {"memory": "0"},
        {"cpus": "--pid=host"},
        {"cpus": "two"},
        {"pids_limit": 0},
    ],
)
def test_provider_settings_that_could_become_flags_are_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(WorkspaceError):
        LocalDockerProvider(runner=FakeDocker(), **kwargs)  # type: ignore[arg-type]


def test_a_missing_docker_binary_is_a_clear_error_not_a_raw_oserror() -> None:
    missing = LocalDockerProvider(docker="/nonexistent/dkr")
    with pytest.raises(WorkspaceError):
        missing.is_alive(SID)


# ======================================== conformance: fake here, Docker in CI

SNAP = pack_snapshot({"hello.txt": b"hi\n"}, links={"link.txt": "hello.txt"}, compress=True)
BYTES_2000 = "head -c 2000 /dev/zero | tr '\\000' '\\377'"
BYTES_1000_EXIT_3 = "head -c 1000 /dev/zero | tr '\\000' '\\377'; exit 3"


def script_fake(fake: FakeWorkspaceProvider) -> FakeWorkspaceProvider:
    """Give the fake the shell's behaviour for exactly the commands the checks use."""
    fake.script("exit 3", FakeOutcome(exit_code=3))
    fake.script("echo out; echo err >&2", FakeOutcome(stdout="out\n", stderr="err\n"))
    fake.script("yes 0123456789", FakeOutcome(stdout="0123456789\n" * 500))
    fake.script("echo partial; sleep 100", FakeOutcome(stdout="partial\n", duration_s=100))
    fake.script(BYTES_2000, FakeOutcome(stdout=b"\xff" * 2000))
    fake.script(BYTES_1000_EXIT_3, FakeOutcome(stdout=b"\xff" * 1000, exit_code=3))
    fake.script("sleep 3; echo done-A", FakeOutcome(stdout="done-A\n"))
    fake.script("sleep 100", FakeOutcome(duration_s=100))
    return fake


def check_results(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)  # gzip, with a symbolic link: accepted by every provider
    assert p.is_alive("conf")
    assert p.exec("conf", "cat hello.txt") == ok("hi\n")
    assert p.exec("conf", "cat link.txt").stdout == "hi\n"
    res = p.exec("conf", "exit 3")
    assert (res.exit_code, res.timed_out, res.truncated, res.session_destroyed) == (
        3,
        False,
        False,
        False,
    )
    both = p.exec("conf", "echo out; echo err >&2")
    assert (both.stdout, both.stderr, both.exit_code) == ("out\n", "err\n", 0)


def check_cap(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)
    res = p.exec("conf", "yes 0123456789", timeout_s=60, max_output_bytes=1000)
    assert res.truncated
    assert res.exit_code is None
    assert not res.timed_out
    assert not res.session_destroyed
    assert len(res.stdout.encode()) <= 1000
    assert res.stdout.startswith("0123456789\n")
    assert p.exec("conf", "cat hello.txt").stdout == "hi\n"  # the session is still usable


def check_timeout(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)
    res = p.exec("conf", "echo partial; sleep 100", timeout_s=2)
    assert res.timed_out
    assert res.exit_code is None
    assert res.stdout == "partial\n"  # what the command had written is kept
    assert not res.session_destroyed
    assert p.exec("conf", "cat hello.txt").stdout == "hi\n"


def check_invalid_utf8(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)
    res = p.exec("conf", BYTES_2000, max_output_bytes=1000)
    assert len(res.stdout.encode()) <= 1000
    assert res.truncated


def check_finished_command_keeps_its_status_when_only_the_text_is_cut(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)
    res = p.exec("conf", BYTES_1000_EXIT_3, max_output_bytes=1000)
    assert res.exit_code == 3  # it exited by itself: not killed, not swept, status kept
    assert res.truncated
    assert not res.timed_out
    assert not res.session_destroyed
    assert len(res.stdout.encode()) <= 1000


def check_one_command_at_a_time(p: WorkspaceProvider) -> None:
    """A sweep after one command's timeout must never kill another command in the session."""
    p.start("conf", SNAP)
    first: dict[str, ExecResult] = {}

    def slow() -> None:
        first["r"] = p.exec("conf", "sleep 3; echo done-A", timeout_s=60)

    worker = threading.Thread(target=slow)
    worker.start()
    time.sleep(0.8)  # let the first command get going
    doomed = p.exec("conf", "sleep 100", timeout_s=1)
    worker.join(60)
    assert doomed.timed_out
    assert first["r"].exit_code == 0, first["r"]  # not killed by the other command's cleanup
    assert first["r"].stdout == "done-A\n"
    assert not first["r"].session_destroyed
    assert not doomed.session_destroyed


def check_errors(p: WorkspaceProvider) -> None:
    p.start("conf", SNAP)
    with pytest.raises(SessionExistsError):
        p.start("conf", SNAP)
    with pytest.raises(WorkspaceError):
        p.exec("conf", "echo a\0b")
    with pytest.raises(SessionLostError):
        p.exec("conf-missing", "true")
    p.stop("conf")
    assert not p.is_alive("conf")
    p.stop("conf")  # idempotent
    with pytest.raises(SnapshotError):
        p.start("conf", _tar_with(("h", "hard", b"", "x")))
    assert not p.is_alive("conf")


CHECKS: list[Callable[[WorkspaceProvider], None]] = [
    check_results,
    check_cap,
    check_timeout,
    check_invalid_utf8,
    check_finished_command_keeps_its_status_when_only_the_text_is_cut,
    check_one_command_at_a_time,
    check_errors,
]


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.__name__)
def test_fake_conformance(check: Callable[[WorkspaceProvider], None]) -> None:
    check(script_fake(FakeWorkspaceProvider()))


# ======================================== real container (CI integration job)

SESSIONS = ["itest-main", "itest-a", "itest-b", "conf", "conf-missing"]


@pytest.fixture
def docker_provider() -> Iterator[LocalDockerProvider]:
    if not docker_available():
        if os.environ.get("CI"):
            pytest.fail("Docker is required in CI: the isolation proofs must not be skipped there")
        pytest.skip("Docker is not available here")
    real = LocalDockerProvider(image=IMAGE)
    for sid in SESSIONS:
        real.stop(sid)
    try:
        yield real
    finally:
        for sid in SESSIONS:
            real.stop(sid)


@pytest.fixture
def live(docker_provider: LocalDockerProvider) -> LocalDockerProvider:
    docker_provider.start(
        "itest-main",
        pack_snapshot({"hello.txt": b"hi from the branch\n", "control.txt": b"CANARY-8f3a91c2\n"}),
    )
    return docker_provider


def stable(p: LocalDockerProvider, path: str) -> tuple[str, str]:
    """A marker file's content, then again after a pause: equal means its writer is gone."""
    first = p.exec("itest-main", f"cat {path}").stdout
    time.sleep(1.5)
    return first, p.exec("itest-main", f"cat {path}").stdout


@pytest.mark.integration
@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.__name__)
def test_docker_conformance(
    docker_provider: LocalDockerProvider, check: Callable[[WorkspaceProvider], None]
) -> None:
    check(docker_provider)


@pytest.mark.integration
def test_docker_runs_commands_in_the_snapshot(live: LocalDockerProvider) -> None:
    res = live.exec("itest-main", "cat hello.txt && id -u")
    assert res.exit_code == 0, res
    assert res.stdout.splitlines() == ["hi from the branch", "1000"]
    live.exec("itest-main", "echo kept > note.txt")
    assert live.exec("itest-main", "cat note.txt").stdout == "kept\n"  # the session persists
    # a command whose own stderr looks like an infrastructure error is still just a failed command
    noisy = live.exec("itest-main", "echo 'Error: No such file or directory: foo.txt' >&2; exit 1")
    assert (noisy.exit_code, noisy.session_destroyed) == (1, False)
    assert live.is_alive("itest-main")


@pytest.mark.integration
def test_docker_exit_124_and_137_by_themselves_are_not_timeouts(live: LocalDockerProvider) -> None:
    for command, code in (("exit 124", 124), ("exit 137", 137), ("kill -9 $$", 137)):
        res = live.exec("itest-main", command, timeout_s=30)
        assert (res.exit_code, res.timed_out) == (code, False), command


@pytest.mark.integration
def test_docker_container_has_no_network(live: LocalDockerProvider) -> None:
    def py(body: str) -> ExecResult:
        return live.exec("itest-main", f"python - <<'EOF'\n{body}\nEOF", timeout_s=60)

    # Positive control first: the probe works, and loopback is up, so a failure below is the
    # network being absent, not python or sockets being broken.
    control = py(
        "import socket\n"
        "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen()\n"
        "socket.create_connection(s.getsockname(), timeout=3)\n"
        "print('loopback-ok')"
    )
    assert control.stdout.strip() == "loopback-ok", control
    external = py(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=5)\n"
        "    print('CONNECTED')\n"
        "except OSError as e:\n"
        "    print(type(e).__name__, e)"
    )
    assert "Network is unreachable" in external.stdout, external
    dns = py(
        "import socket\n"
        "try:\n"
        "    socket.gethostbyname('example.com')\n"
        "    print('RESOLVED')\n"
        "except OSError as e:\n"
        "    print(type(e).__name__, e)"
    )
    assert dns.stdout.startswith("gaierror"), dns
    assert live.exec("itest-main", "ls /sys/class/net").stdout.split() == ["lo"]


@pytest.mark.integration
def test_docker_container_has_no_host_credentials(
    docker_provider: LocalDockerProvider, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canaries = {
        "AWS_ACCESS_KEY_ID": "AKIACANARYCANARY0000",
        "AWS_SECRET_ACCESS_KEY": "canary-secret-canary-secret",
        "AWS_SESSION_TOKEN": "canary-session-token",
        "GITHUB_TOKEN": "ghp_canarycanarycanarycanarycanary000000",
        "GH_TOKEN": "ghp_canarycanarycanarycanarycanary000001",
        "ANTHROPIC_API_KEY": "sk-ant-canary",
        "SSH_AUTH_SOCK": "/tmp/canary-agent.sock",
    }
    for name, value in canaries.items():
        monkeypatch.setenv(name, value)
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text("[default]\naws_access_key_id=CANARY-8f3a91c2\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / ".aws" / "credentials"))

    # control.txt holds the same canary inside the workspace: the search below must find exactly it.
    docker_provider.start("itest-main", pack_snapshot({"control.txt": b"CANARY-8f3a91c2\n"}))
    env = docker_provider.exec("itest-main", "env")
    assert env.exit_code == 0, env
    assert "HOME=/tmp" in env.stdout.splitlines()  # the env listing really worked
    for name, value in canaries.items():
        assert name not in env.stdout, f"{name} leaked into the container"
        assert value not in env.stdout, f"{name} value leaked into the container"
    found = docker_provider.exec(
        "itest-main",
        "grep -rIl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev "
        "CANARY-8f3a91c2 / 2>/dev/null",
    )
    assert found.stdout == "/workspace/control.txt\n", found  # the host's copy is nowhere
    sock = docker_provider.exec("itest-main", "ls /var/run/docker.sock /run/docker.sock 2>&1")
    assert sock.exit_code != 0
    assert "No such file" in sock.stdout
    mounts = docker_provider.exec("itest-main", "cat /proc/self/mountinfo")
    assert mounts.exit_code == 0
    assert "overlay" in mounts.stdout  # the listing is real
    assert str(tmp_path) not in mounts.stdout
    assert "docker.sock" not in mounts.stdout
    assert docker_provider.exec("itest-main", "id -u").stdout.strip() == "1000"
    assert docker_provider.exec("itest-main", "touch /etc/not-writable").exit_code != 0


@pytest.mark.integration
def test_docker_timeout_leaves_nothing_running(live: LocalDockerProvider) -> None:
    command = (
        "(trap '' TERM; while :; do date +%s%N > /workspace/m_term; sleep 0.1; done) & "
        "setsid sh -c 'while :; do date +%s%N > /workspace/m_setsid; sleep 0.1; done' & "
        "sleep 100"
    )
    start = time.monotonic()
    res = live.exec("itest-main", command, timeout_s=2)
    assert res.timed_out
    assert not res.session_destroyed, res
    assert time.monotonic() - start < 60
    for marker in ("m_term", "m_setsid"):
        before, after = stable(live, f"/workspace/{marker}")
        assert before != "", f"{marker}: the child never ran, so the test proves nothing"
        assert before == after, f"{marker} is still being written: a child survived the timeout"
    assert live.exec("itest-main", "echo usable").stdout == "usable\n"


@pytest.mark.integration
def test_docker_output_cap_leaves_nothing_running(live: LocalDockerProvider) -> None:
    command = "(while :; do date +%s%N > /workspace/m_cap; sleep 0.1; done) & yes 0123456789"
    res = live.exec("itest-main", command, timeout_s=60, max_output_bytes=2000)
    assert res.truncated
    assert res.exit_code is None
    assert not res.timed_out
    assert not res.session_destroyed, res
    before, after = stable(live, "/workspace/m_cap")
    assert before != ""
    assert before == after, "a background writer survived the output cap"
    # nothing writes into /workspace while the next command (or a patch capture) runs
    assert live.exec("itest-main", "ls /workspace").stdout.split() == [
        "control.txt", "hello.txt", "m_cap",
    ]  # fmt: skip


HOSTILE = {
    # The main thread exits (a zombie leader) while a worker thread keeps writing.
    "zleader.py": b"""import ctypes, os, sys, threading, time
m = sys.argv[1]
def work():
    end = time.time() + float(sys.argv[2])
    while time.time() < end:
        open(m, "w").write(str(time.time())); time.sleep(0.05)
    os._exit(0)
threading.Thread(target=work, daemon=True).start()
time.sleep(0.2)
ctypes.CDLL(None).pthread_exit(None)
""",
    # A comm that imitates a stat line, so anything parsing /proc/PID/stat is fooled.
    "comm.py": b"""import sys, time
open("/proc/self/comm", "wb").write(b"a) Z \nb")
end = time.time() + float(sys.argv[2])
while time.time() < end:
    open(sys.argv[1], "w").write(str(time.time())); time.sleep(0.05)
""",
    # Every generation writes, forks its successor and exits: the PID keeps changing.
    "hop.py": b"""import os, sys, time
while True:
    open(sys.argv[1], "w").write(str(time.time()))
    if os.fork():
        os._exit(0)
    time.sleep(0.02)
""",
    # Freezes any process whose command line looks like the sweep.
    "stopper.py": b"""import os, signal, time
me = os.getpid()
while True:
    for name in os.listdir("/proc"):
        if name.isdigit() and int(name) != me:
            try:
                data = open(f"/proc/{name}/cmdline", "rb").read()
                if b"keeper=" in data:
                    os.kill(int(name), signal.SIGSTOP)
            except OSError:
                pass
    time.sleep(0.001)
""",
}
WRITER = "(while :; do date +%s%N > /workspace/{m}; sleep 0.05; done) &"


@pytest.fixture
def hostile(docker_provider: LocalDockerProvider) -> LocalDockerProvider:
    docker_provider.start("itest-main", pack_snapshot(HOSTILE))
    return docker_provider


def contained(p: LocalDockerProvider, command: str, marker: str) -> str:
    """Run hostile code to a timeout. Either its marker stops changing, or the session is gone."""
    try:
        res = p.exec("itest-main", command, timeout_s=2)
    except SessionLostError:
        assert not p.is_alive("itest-main")
        return "lost"
    if res.session_destroyed:
        assert p._state("itest-main") == "absent"  # noqa: SLF001
        return "destroyed"
    assert res.timed_out, res
    before, after = stable(p, f"/workspace/{marker}")
    assert before != "", f"{marker}: the hostile code never ran, so this proves nothing"
    assert before == after, f"{marker} is still changing after a sweep that reported clean"
    return "swept"


@pytest.mark.integration
def test_docker_a_zombie_leader_with_live_threads_does_not_survive(
    hostile: LocalDockerProvider,
) -> None:
    contained(hostile, "python zleader.py /workspace/m_zl 600 & sleep 100", "m_zl")


@pytest.mark.integration
def test_docker_a_comm_that_imitates_a_stat_line_does_not_fool_the_sweep(
    hostile: LocalDockerProvider,
) -> None:
    contained(hostile, "python comm.py /workspace/m_comm 600 & sleep 100", "m_comm")


@pytest.mark.integration
def test_docker_a_process_that_changes_its_pid_every_few_milliseconds_does_not_survive(
    hostile: LocalDockerProvider,
) -> None:
    contained(hostile, "python hop.py /workspace/m_hop & sleep 100", "m_hop")


@pytest.mark.integration
def test_docker_a_process_that_freezes_the_sweep_gets_the_session_destroyed_or_loses(
    hostile: LocalDockerProvider,
) -> None:
    command = "python stopper.py & " + WRITER.format(m="m_stop") + " sleep 100"
    contained(hostile, command, "m_stop")


@pytest.mark.integration
def test_docker_a_killed_keeper_ends_the_session_instead_of_hiding_in_it(
    hostile: LocalDockerProvider,
) -> None:
    keeper = (
        'k=; for d in /proc/[0-9]*; do p=${d#/proc/}; [ "$p" -gt 1 ] || continue; '
        '[ -z "$k" ] || [ "$p" -lt "$k" ] && k=$p; done; kill -9 "$k"; '
    )
    # A killed keeper stops the container: the command's exec fails (lost) or the sweep cannot
    # verify (destroyed). Reaching "swept" would mean the marker stopped, which is also contained.
    contained(hostile, keeper + WRITER.format(m="m_keep") + " sleep 100", "m_keep")


@pytest.mark.integration
def test_docker_environment_report(
    docker_provider: LocalDockerProvider, request: pytest.FixtureRequest
) -> None:
    """Prints into the CI log what the isolation proofs ran on, and which tests ran."""
    ptrace = Path("/proc/sys/kernel/yama/ptrace_scope")
    scope = ptrace.read_text().strip() if ptrace.exists() else "absent"
    server = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}} cgroup={{.Server.CgroupVersion}}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    ).stdout.strip()
    names = [i.nodeid for i in request.session.items if i.get_closest_marker("integration")]
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    lines = [f"docker server: {server}", f"yama ptrace_scope (host): {scope}", "integration tests:"]
    lines += [f"  {name}" for name in names]
    if reporter is not None:
        reporter.write_line("")
        for line in lines:
            reporter.write_line(line)
    assert server
    assert names


@pytest.mark.integration
def test_docker_orphans_are_reaped_because_the_container_has_an_init(
    live: LocalDockerProvider,
) -> None:
    res = live.exec(
        "itest-main",
        "(sh -c 'exit 0' &); sleep 1; grep -lE '^State:[[:space:]]+Z' /proc/[0-9]*/status | wc -l",
    )
    assert res.stdout.strip() == "0", f"zombies were left unreaped: {res}"


@pytest.mark.integration
def test_docker_a_snapshot_tar_cannot_unpack_leaves_no_container(
    docker_provider: LocalDockerProvider,
) -> None:
    bad = pack_snapshot({"a": b"x", "a/b": b"y"})  # valid archive, but `a` is a file then a dir
    with pytest.raises(WorkspaceError):
        docker_provider.start("itest-a", bad)
    assert not docker_provider.is_alive("itest-a")
    assert docker_provider._state("itest-a") == "absent"  # noqa: SLF001
    docker_provider.start("itest-a", pack_snapshot({"ok": b"1"}))  # and the name is reusable
    assert docker_provider.is_alive("itest-a")


@pytest.mark.integration
def test_docker_lost_session_recovers_from_the_branch(docker_provider: LocalDockerProvider) -> None:
    branch = pack_snapshot({"src/app.py": b"print('pushed')"})
    assert ensure_session(docker_provider, "itest-a", "sto/run-1", lambda _b: branch)
    docker_provider.exec("itest-a", "echo unpushed > scratch.txt")
    subprocess.run(
        ["docker", "kill", "sto-ws-itest-a"], check=True, capture_output=True, timeout=60
    )
    assert not docker_provider.is_alive("itest-a")
    assert ensure_session(docker_provider, "itest-a", "sto/run-1", lambda _b: branch)
    assert docker_provider.exec("itest-a", "cat src/app.py").stdout == "print('pushed')"
    assert docker_provider.exec("itest-a", "cat scratch.txt").exit_code != 0


@pytest.mark.integration
def test_docker_sessions_are_isolated_from_each_other(docker_provider: LocalDockerProvider) -> None:
    docker_provider.start("itest-a", pack_snapshot({"who": b"a"}))
    docker_provider.start("itest-b", pack_snapshot({"who": b"b"}))
    docker_provider.exec("itest-a", "echo only-a > private.txt")
    assert docker_provider.exec("itest-b", "cat who").stdout == "b"
    assert docker_provider.exec("itest-b", "cat private.txt").exit_code != 0
