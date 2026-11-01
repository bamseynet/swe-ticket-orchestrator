"""D5-06: the workspace port, the fake provider and the local Docker provider.

Three layers, each with its own job:

* Hermetic tests (run everywhere): the port contract on the fake, the host-side runner
  (``run_capped``) against real host subprocesses, and the ``docker`` argv the provider builds,
  checked through a recording runner. They prove the controls are *requested*.
* ``integration`` tests (``test_docker_*``, CI only, skipped without Docker): the same controls
  against a real container. They prove the controls *hold*. ``tests/integration`` re-exports them
  because CI's integration job only collects that directory.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from sto.workspace.local_docker import (
    ENV_ALLOWLIST,
    LocalDockerProvider,
    run_capped,
)
from sto.workspace.ports import (
    MAX_COMMAND_BYTES,
    ExecResult,
    FakeOutcome,
    FakeWorkspaceProvider,
    SnapshotError,
    WorkspaceError,
    WorkspaceProvider,
    cap_text,
    ensure_session,
    pack_snapshot,
    unpack_snapshot,
)

IMAGE = "python:3.12-slim"


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


# ---------------------------------------------------------------- snapshot helpers


def test_snapshot_round_trip() -> None:
    files = {"a.txt": b"one", "dir/b.txt": b"two"}
    assert unpack_snapshot(pack_snapshot(files)) == files


@pytest.mark.parametrize("name", ["../escape", "/abs", "a/../../b", ""])
def test_pack_refuses_unsafe_paths(name: str) -> None:
    with pytest.raises(SnapshotError):
        pack_snapshot({name: b"x"})


def test_unpack_refuses_unsafe_and_non_regular_members() -> None:
    import io
    import tarfile

    def tar_with(info: tarfile.TarInfo, body: bytes = b"") -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            tf.addfile(info, io.BytesIO(body))
        return buf.getvalue()

    evil = tarfile.TarInfo("../evil")
    evil.size = 1
    with pytest.raises(SnapshotError):
        unpack_snapshot(tar_with(evil, b"x"))
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    with pytest.raises(SnapshotError):
        unpack_snapshot(tar_with(link))
    with pytest.raises(SnapshotError):
        unpack_snapshot(b"not a tar")


def test_cap_text_keeps_a_prefix_and_flags_truncation() -> None:
    assert cap_text(b"abcdef", 4) == ("abcd", True)
    assert cap_text(b"abcd", 4) == ("abcd", False)
    assert cap_text(b"", 4) == ("", False)
    text, _ = cap_text(b"ok\xff\xfe", 100)
    assert text.startswith("ok")  # invalid UTF-8 is replaced, never raised


# ---------------------------------------------------------------- port contract on the fake


@pytest.fixture
def fake() -> FakeWorkspaceProvider:
    return FakeWorkspaceProvider()


def test_fake_satisfies_the_port(fake: FakeWorkspaceProvider) -> None:
    provider: WorkspaceProvider = fake
    provider.start("s1", pack_snapshot({"hello.txt": b"hi"}))
    assert provider.is_alive("s1")
    res = provider.exec("s1", "cat hello.txt")
    assert (res.exit_code, res.stdout, res.timed_out, res.truncated) == (0, "hi", False, False)
    assert provider.exec("s1", "false").exit_code == 1
    provider.stop("s1")
    assert not provider.is_alive("s1")
    provider.stop("s1")  # idempotent


def test_exec_on_an_unknown_session_raises(fake: FakeWorkspaceProvider) -> None:
    with pytest.raises(WorkspaceError):
        fake.exec("nope", "true")


def test_starting_a_live_session_twice_raises(fake: FakeWorkspaceProvider) -> None:
    fake.start("s1", pack_snapshot({}))
    with pytest.raises(WorkspaceError):
        fake.start("s1", pack_snapshot({}))


def test_a_command_over_the_agentcore_limit_is_refused(fake: FakeWorkspaceProvider) -> None:
    fake.start("s1", pack_snapshot({}))
    with pytest.raises(WorkspaceError):
        fake.exec("s1", "x" * (MAX_COMMAND_BYTES + 1))


@pytest.mark.parametrize("bad", ["", "-x", "a b", "a/b", "a;b", "x" * 65])
def test_session_ids_are_validated(fake: FakeWorkspaceProvider, bad: str) -> None:
    with pytest.raises(WorkspaceError):
        fake.start(bad, pack_snapshot({}))


@pytest.mark.parametrize("timeout_s", [0, -1, 3601])
def test_timeout_must_be_in_range(fake: FakeWorkspaceProvider, timeout_s: float) -> None:
    fake.start("s1", pack_snapshot({}))
    with pytest.raises(WorkspaceError):
        fake.exec("s1", "true", timeout_s=timeout_s)


def test_fake_enforces_timeout_and_output_caps(fake: FakeWorkspaceProvider) -> None:
    fake.script("slow", FakeOutcome(stdout="partial", duration_s=50))
    fake.script("loud", FakeOutcome(stdout="x" * 500, stderr="y" * 500))
    fake.start("s1", pack_snapshot({}))
    slow = fake.exec("s1", "slow", timeout_s=5)
    assert slow.timed_out
    assert slow.exit_code is None
    loud = fake.exec("s1", "loud", max_output_bytes=100)
    assert loud.truncated
    assert len(loud.stdout) == 100
    assert len(loud.stderr) == 100


# ---------------------------------------------------------------- recovery from the branch


def test_a_lost_session_recovers_from_the_branch_and_loses_unpushed_work(
    fake: FakeWorkspaceProvider,
) -> None:
    branch_files = {"src/app.py": b"print('pushed')"}
    fetched: list[str] = []

    def source(branch: str) -> bytes:
        fetched.append(branch)
        return pack_snapshot(branch_files)

    fake.script("echo scratch > scratch.txt", FakeOutcome(writes={"scratch.txt": b"scratch\n"}))
    assert ensure_session(fake, "s1", "sto/run-1", source) is True  # first start
    fake.exec("s1", "echo scratch > scratch.txt")
    assert fake.exec("s1", "cat scratch.txt").stdout == "scratch\n"
    assert ensure_session(fake, "s1", "sto/run-1", source) is False  # alive: nothing to do
    assert len(fetched) == 1

    fake.kill("s1")  # the session is lost
    assert not fake.is_alive("s1")
    assert ensure_session(fake, "s1", "sto/run-1", source) is True
    assert fetched == ["sto/run-1", "sto/run-1"]
    assert fake.exec("s1", "cat src/app.py").stdout == "print('pushed')"
    assert fake.exec("s1", "cat scratch.txt").exit_code != 0  # only the branch survives


# ------------------------------------------------------- host-side runner (real subprocesses)

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
    script = f"(sleep 3; touch {marker}) & wait"
    res = run_capped(["sh", "-c", script], timeout_s=1, max_output_bytes=100)
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
    assert len(res.stdout.encode()) <= 1000
    assert res.stdout.startswith("0123456789\n")
    assert not res.timed_out, "the cap must stop the writer; the timeout is not the control"
    assert time.monotonic() - start < RUN_DEADLINE_S


def test_run_capped_caps_stderr_separately() -> None:
    res = run_capped(
        ["sh", "-c", "yes e >&2"],
        timeout_s=30,
        max_output_bytes=500,
    )
    assert res.truncated
    assert len(res.stderr.encode()) <= 500
    assert res.stdout == ""


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


# ---------------------------------------------------------------- docker argv (recording runner)


class Recorder:
    """A runner that records every argv and answers from a script."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.next: list[ExecResult] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        max_output_bytes: int,
        stdin: bytes | None = None,
    ) -> ExecResult:
        self.calls.append(
            (
                list(argv),
                {"timeout_s": timeout_s, "max_output_bytes": max_output_bytes, "stdin": stdin},
            )
        )
        if self.next:
            return self.next.pop(0)
        return ExecResult(exit_code=0, stdout="", stderr="", timed_out=False, truncated=False)

    def verb(self, name: str) -> list[str]:
        return next(a for a, _ in self.calls if name in a[:3])


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def provider(recorder: Recorder) -> LocalDockerProvider:
    return LocalDockerProvider(image=IMAGE, runner=recorder, docker="docker")


def flag_values(argv: Sequence[str], flag: str) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def test_start_creates_a_container_with_no_network_and_dropped_privileges(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    provider.start("s1", pack_snapshot({"a": b"1"}))
    run = recorder.verb("run")
    assert flag_values(run, "--network") == ["none"]
    assert flag_values(run, "--cap-drop") == ["ALL"]
    assert "no-new-privileges" in flag_values(run, "--security-opt")
    assert "--read-only" in run
    assert flag_values(run, "--user")
    assert flag_values(run, "--user")[0] != "0:0"
    assert "--privileged" not in run
    assert flag_values(run, "--pids-limit")
    assert flag_values(run, "--memory")


def test_start_passes_no_host_environment_files_or_mounts(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    provider.start("s1", pack_snapshot({}))
    for argv, _ in recorder.calls:
        for banned in ("--env-file", "-v", "--volume", "--mount", "--volumes-from"):
            assert banned not in argv, banned
        assert not any(a.startswith(("--volume=", "--mount=", "--env-file=")) for a in argv)
        for value in flag_values(argv, "-e") + flag_values(argv, "--env"):
            name, sep, _ = value.partition("=")  # NAME alone would copy the host's value
            assert sep == "=", f"-e {value} forwards a host variable"
            assert name in {"HOME", "PATH", "LANG"}
        assert not any("docker.sock" in a for a in argv)


def test_the_snapshot_is_streamed_in_not_bind_mounted(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    snapshot = pack_snapshot({"a": b"1"})
    provider.start("s1", snapshot)
    extract = next((a, o) for a, o in recorder.calls if "tar" in a and o["stdin"] is not None)
    assert extract[1]["stdin"] == snapshot
    assert "exec" in extract[0]
    assert "/workspace" in extract[0]


def test_start_failure_removes_the_half_made_container(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    ok = ExecResult(exit_code=0, stdout="", stderr="", timed_out=False, truncated=False)
    bad = ExecResult(exit_code=1, stdout="", stderr="boom", timed_out=False, truncated=False)
    recorder.next = [ok, bad]  # inspect/ls says none, run fails
    # the exact order of calls is an implementation detail; any failure must end in `rm -f`
    recorder.next = [bad] * 5
    with pytest.raises(WorkspaceError):
        provider.start("s1", pack_snapshot({}))
    assert any("rm" in a[:3] and "-f" in a for a, _ in recorder.calls)


def test_exec_wraps_the_command_in_an_in_container_timeout(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    provider.exec("s1", "make test", timeout_s=7, max_output_bytes=123)
    argv, opts = recorder.calls[-1]
    assert "exec" in argv[:3]
    assert "-w" in argv
    assert "/workspace" in argv
    i = argv.index("timeout")
    assert argv[i + 1 :][-3:] == ["sh", "-c", "make test"]
    assert "7" in " ".join(argv[i + 1 : i + 5]) or "7.0" in " ".join(argv[i + 1 : i + 5])
    assert opts["max_output_bytes"] == 123
    assert (
        float(str(opts["timeout_s"])) > 7
    )  # host-side backstop sits above the in-container timeout


def test_exec_maps_the_timeout_exit_status_to_timed_out(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    for status in (124, 137):
        recorder.next = [
            ExecResult(exit_code=status, stdout="", stderr="", timed_out=False, truncated=False)
        ]
        res = provider.exec("s1", "sleep 99", timeout_s=1)
        assert res.timed_out
        assert res.exit_code is None


def test_a_host_side_backstop_timeout_kills_the_container(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    recorder.next = [
        ExecResult(exit_code=None, stdout="", stderr="", timed_out=True, truncated=False)
    ]
    res = provider.exec("s1", "hang", timeout_s=1)
    assert res.timed_out
    assert any(("kill" in a[:3] or "rm" in a[:3]) for a, _ in recorder.calls[1:])


def test_exec_on_a_missing_container_raises_workspace_error(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    recorder.next = [
        ExecResult(
            exit_code=1,
            stdout="",
            stderr="Error response from daemon: No such container: sto-ws-s1",
            timed_out=False,
            truncated=False,
        )
    ]
    with pytest.raises(WorkspaceError):
        provider.exec("s1", "true")


def test_exec_refuses_oversize_commands_and_bad_ids(provider: LocalDockerProvider) -> None:
    with pytest.raises(WorkspaceError):
        provider.exec("s1", "x" * (MAX_COMMAND_BYTES + 1))
    with pytest.raises(WorkspaceError):
        provider.exec("--privileged", "true")


def test_stop_and_is_alive_use_the_container_name(
    provider: LocalDockerProvider, recorder: Recorder
) -> None:
    provider.stop("s1")
    assert recorder.calls[-1][0][-1].startswith("sto-ws-")
    recorder.next = [
        ExecResult(exit_code=0, stdout="true\n", stderr="", timed_out=False, truncated=False)
    ]
    assert provider.is_alive("s1")
    recorder.next = [
        ExecResult(exit_code=1, stdout="", stderr="no such", timed_out=False, truncated=False)
    ]
    assert not provider.is_alive("s1")
    recorder.next = [
        ExecResult(exit_code=0, stdout="false\n", stderr="", timed_out=False, truncated=False)
    ]
    assert not provider.is_alive("s1")


# ------------------------------------------------------- real container (CI integration job)

needs_docker = pytest.mark.skipif(not docker_available(), reason="Docker is not available here")


@pytest.fixture
def docker_provider() -> Iterator[LocalDockerProvider]:
    real = LocalDockerProvider(image=IMAGE)
    sessions = ["itest-main", "itest-a", "itest-b"]
    for sid in sessions:
        real.stop(sid)
    try:
        yield real
    finally:
        for sid in sessions:
            real.stop(sid)


@pytest.fixture
def live(docker_provider: LocalDockerProvider) -> LocalDockerProvider:
    docker_provider.start("itest-main", pack_snapshot({"hello.txt": b"hi from the branch\n"}))
    return docker_provider


@pytest.mark.integration
@needs_docker
def test_docker_runs_commands_in_the_snapshot(live: LocalDockerProvider) -> None:
    res = live.exec("itest-main", "cat hello.txt && id -u")
    assert res.exit_code == 0, res
    assert res.stdout.splitlines() == ["hi from the branch", "1000"]
    assert live.exec("itest-main", "exit 5").exit_code == 5
    live.exec("itest-main", "echo kept > note.txt")
    assert live.exec("itest-main", "cat note.txt").stdout == "kept\n"  # the session persists


@pytest.mark.integration
@needs_docker
def test_docker_container_has_no_network(live: LocalDockerProvider) -> None:
    ifaces = live.exec("itest-main", "ls /sys/class/net")
    assert ifaces.stdout.split() == ["lo"], ifaces
    probe = live.exec(
        "itest-main",
        "python -c \"import socket; socket.create_connection(('1.1.1.1', 53), timeout=5)\"",
        timeout_s=30,
    )
    assert probe.exit_code not in (0, None), "the container reached the internet"
    dns = live.exec(
        "itest-main",
        "python -c \"import socket; socket.gethostbyname('example.com')\"",
        timeout_s=30,
    )
    assert dns.exit_code not in (0, None), "the container resolved a public name"


@pytest.mark.integration
@needs_docker
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
    (tmp_path / ".aws" / "credentials").write_text("[default]\naws_access_key_id=CANARYFILE\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / ".aws" / "credentials"))

    docker_provider.start("itest-main", pack_snapshot({}))
    env = docker_provider.exec("itest-main", "env").stdout
    for name, value in canaries.items():
        assert name not in env, f"{name} leaked into the container"
        assert value not in env, f"{name} value leaked into the container"
    assert (
        "CANARYFILE"
        not in docker_provider.exec("itest-main", "grep -rIl CANARYFILE / 2>/dev/null; true").stdout
    )
    sock = docker_provider.exec(
        "itest-main", "test -e /var/run/docker.sock -o -e /run/docker.sock && echo EXPOSED"
    )
    assert "EXPOSED" not in sock.stdout
    mounts = docker_provider.exec("itest-main", "cat /proc/mounts").stdout
    assert str(tmp_path) not in mounts
    assert "/home/" not in mounts
    assert docker_provider.exec("itest-main", "id -u").stdout.strip() == "1000"
    root_write = docker_provider.exec("itest-main", "touch /etc/not-writable")
    assert root_write.exit_code != 0, "the root filesystem must be read-only"


@pytest.mark.integration
@needs_docker
def test_docker_timeout_kills_the_command(live: LocalDockerProvider) -> None:
    start = time.monotonic()
    res = live.exec("itest-main", "sleep 120", timeout_s=2)
    assert res.timed_out
    assert time.monotonic() - start < 30
    # The kill reached the process group, not just the docker client: a backgrounded child dies too.
    live.exec("itest-main", "(sleep 4; touch late) & wait", timeout_s=1)
    time.sleep(6)
    assert live.exec("itest-main", "test -e late").exit_code == 1, "a child outlived the timeout"
    assert live.exec("itest-main", "echo still-usable").stdout == "still-usable\n"


@pytest.mark.integration
@needs_docker
def test_docker_output_is_capped(live: LocalDockerProvider) -> None:
    start = time.monotonic()
    res = live.exec("itest-main", "yes 0123456789", timeout_s=60, max_output_bytes=2000)
    assert res.truncated
    assert 0 < len(res.stdout.encode()) <= 2000
    assert not res.timed_out
    assert time.monotonic() - start < 30
    assert live.exec("itest-main", "echo ok").stdout == "ok\n"


@pytest.mark.integration
@needs_docker
def test_docker_lost_session_recovers_from_the_branch(
    docker_provider: LocalDockerProvider,
) -> None:
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
@needs_docker
def test_docker_sessions_are_isolated_from_each_other(
    docker_provider: LocalDockerProvider,
) -> None:
    docker_provider.start("itest-a", pack_snapshot({"who": b"a"}))
    docker_provider.start("itest-b", pack_snapshot({"who": b"b"}))
    docker_provider.exec("itest-a", "echo only-a > private.txt")
    assert docker_provider.exec("itest-b", "cat who").stdout == "b"
    assert docker_provider.exec("itest-b", "cat private.txt").exit_code != 0
