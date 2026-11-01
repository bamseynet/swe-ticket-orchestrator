"""Tests for ``scripts/doctor.py``. All probes are injected, so nothing touches the host."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "doctor.py"
_spec = importlib.util.spec_from_file_location("doctor", _PATH)
assert _spec is not None
assert _spec.loader is not None
doctor = importlib.util.module_from_spec(_spec)
sys.modules["doctor"] = doctor
_spec.loader.exec_module(doctor)


class FakeHost:
    def __init__(
        self,
        tools: dict[str, str] | None = None,
        taken: set[int] | None = None,
        python: tuple[int, int] = (3, 12),
    ) -> None:
        self.tools = {"uv": "uv 0.8.0", "node": "v24.1.0", "docker": "Docker 27"}
        self.tools.update(tools or {})
        self.taken = taken or set()
        self.python = python

    def version(self, tool: str) -> str | None:
        return self.tools.get(tool)

    def port_free(self, port: int) -> bool:
        return port not in self.taken

    def python_version(self) -> tuple[int, int]:
        return self.python


def run(
    host: FakeHost, env: dict[str, str] | None = None, argv: list[str] | None = None
) -> list[Any]:
    results: list[Any] = doctor.run_checks(host, env or {}, argv or [])
    return results


def by_name(results: list[Any], name: str) -> Any:
    return next(r for r in results if r.name == name)


def test_all_good_exits_zero() -> None:
    results = run(FakeHost())
    assert doctor.exit_code(results) == 0
    assert all(r.ok for r in results)


@pytest.mark.parametrize(
    ("host", "name", "fix_word"),
    [
        (FakeHost(python=(3, 11)), "python", "uv python install"),
        (FakeHost(tools={"uv": ""}), "uv", "astral.sh/uv"),
        (FakeHost(tools={"node": ""}), "node", "nvm install"),
        (FakeHost(tools={"node": "v22.1.0"}), "node", "nvm install"),
    ],
)
def test_missing_prerequisite_prints_a_fix(host: FakeHost, name: str, fix_word: str) -> None:
    host.tools = {k: v for k, v in host.tools.items() if v}
    results = run(host)
    result = by_name(results, name)
    assert not result.ok
    assert fix_word in result.fix
    assert doctor.exit_code(results) == 1
    assert fix_word in doctor.render(results)


def test_missing_docker_is_not_an_error() -> None:
    host = FakeHost()
    del host.tools["docker"]
    results = run(host)
    docker = by_name(results, "docker")
    assert docker.optional
    assert not docker.ok
    assert doctor.exit_code(results) == 0
    assert "optional" in doctor.render(results)


def test_default_ports() -> None:
    results = run(FakeHost())
    assert by_name(results, "port 8710 (api)").ok
    assert by_name(results, "port 5710 (web)").ok


def test_ports_overridable_by_env_and_flag() -> None:
    results = run(FakeHost(), {"STO_API_PORT": "9001"}, ["--web-port", "9002"])
    names = {r.name for r in results}
    assert "port 9001 (api)" in names
    assert "port 9002 (web)" in names
    assert "port 8710 (api)" not in names


def test_flag_beats_env() -> None:
    results = run(FakeHost(), {"STO_API_PORT": "9001"}, ["--api-port", "9003"])
    assert "port 9003 (api)" in {r.name for r in results}


def test_taken_port_gives_clear_message() -> None:
    results = run(FakeHost(taken={8710}))
    result = by_name(results, "port 8710 (api)")
    assert not result.ok
    assert "already in use" in result.detail
    assert "STO_API_PORT" in result.fix
    assert "--api-port" in result.fix
    assert doctor.exit_code(results) == 1


def test_invalid_port_is_rejected() -> None:
    with pytest.raises(SystemExit):
        run(FakeHost(), {"STO_API_PORT": "banana"})


def test_invalid_port_message_names_the_source(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        run(FakeHost(), {"STO_API_PORT": "banana"})
    assert "STO_API_PORT" in str(exc.value)
    assert "banana" in str(exc.value)


@pytest.mark.parametrize("value", ["0", "80", "1023", "65536", "-5"])
def test_ports_outside_unprivileged_range_are_rejected(value: str) -> None:
    with pytest.raises(SystemExit) as exc:
        run(FakeHost(), argv=["--web-port", value])
    assert "1024" in str(exc.value)


def test_same_port_for_api_and_web_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        run(FakeHost(), {"STO_API_PORT": "9001", "STO_WEB_PORT": "9001"})
    assert "different" in str(exc.value)


# --- RealHost and the entrypoint -------------------------------------------------------------
# The hermetic guard blocks all internet sockets, so these tests put the real socket classes
# back for loopback only, inside the test.


@pytest.fixture
def real_sockets() -> Iterator[None]:
    import _socket
    import socket

    import hermetic_guard

    guarded = (socket.__dict__.copy(), _socket.__dict__.copy())
    socket.__dict__.update(hermetic_guard.saved["sockets"][0])
    _socket.__dict__.update(hermetic_guard.saved["sockets"][1])
    try:
        yield
    finally:
        socket.__dict__.update(guarded[0])
        _socket.__dict__.update(guarded[1])


def _listen(family: int, host: str) -> tuple[Any, int]:
    import socket

    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, 0))
    except OSError:
        sock.close()
        pytest.skip(f"{host} is unavailable")
    sock.listen()
    return sock, int(sock.getsockname()[1])


@pytest.mark.usefixtures("real_sockets")
def test_real_port_free_for_unused_port() -> None:
    import socket

    sock, port = _listen(socket.AF_INET, "127.0.0.1")
    sock.close()
    assert doctor.RealHost().port_free(port)


@pytest.mark.usefixtures("real_sockets")
def test_real_port_taken_on_ipv4_loopback() -> None:
    import socket

    sock, port = _listen(socket.AF_INET, "127.0.0.1")
    try:
        assert not doctor.RealHost().port_free(port)
    finally:
        sock.close()


@pytest.mark.usefixtures("real_sockets")
def test_real_port_taken_on_ipv6_loopback() -> None:
    import socket

    sock, port = _listen(socket.AF_INET6, "::1")
    try:
        assert not doctor.RealHost().port_free(port)
    finally:
        sock.close()


def _script(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def test_version_requires_zero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _script(tmp_path, "broken", "echo 'v24.0.0 but broken'; exit 1")
    _script(tmp_path, "fine", "echo 'fine 1.2.3'")
    monkeypatch.setenv("PATH", str(tmp_path))
    host = doctor.RealHost()
    assert host.version("broken") is None
    assert host.version("fine") == "fine 1.2.3"
    assert host.version("absent") is None


def test_python_version_falls_back_to_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _script(tmp_path, "py312", "echo 'Python 3.12.4'")
    _script(tmp_path, "uv", f"echo {tmp_path}/py312")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))
    assert doctor.RealHost().python_version() == (3, 12)


def test_python_version_without_uv_reports_running_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(sys, "version_info", (3, 10, 0, "final", 0))
    assert doctor.RealHost().python_version() == (3, 10)


@pytest.mark.usefixtures("real_sockets")
def test_entrypoint_without_uv_on_path_prints_fix(tmp_path: Path) -> None:
    import subprocess

    env = {"PATH": str(tmp_path), "HOME": str(tmp_path)}  # no uv, node or docker
    proc = subprocess.run(
        [sys.executable, str(_PATH)], env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 1
    assert "[FAIL] uv" in proc.stdout
    assert "astral.sh/uv" in proc.stdout
    assert "Traceback" not in proc.stderr


def test_make_doctor_does_not_need_uv() -> None:
    import subprocess

    out = subprocess.run(
        ["make", "-n", "doctor"],
        cwd=_PATH.parents[1],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "python3 scripts/doctor.py" in out
    assert "uv run" not in out
