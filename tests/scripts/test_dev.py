"""``scripts/dev.py``: the demo seeding decision and the web command, with the API faked."""

from __future__ import annotations

import importlib.util
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "dev.py"
_spec = importlib.util.spec_from_file_location("dev_script", _PATH)
assert _spec is not None
assert _spec.loader is not None
dev: Any = importlib.util.module_from_spec(_spec)
sys.modules["dev_script"] = dev
_spec.loader.exec_module(dev)


def fake_api(
    monkeypatch: pytest.MonkeyPatch, runs: list[object], post_status: int = 202
) -> list[Any]:
    calls: list[Any] = []

    def request(port: int, method: str, path: str, token: str, body: object = None) -> Any:
        calls.append((method, path, body))
        if method == "GET":
            return 200, {"runs": runs, "cursor": None}
        return post_status, {}

    monkeypatch.setattr(dev, "request", request)
    return calls


def test_seeds_one_demo_run_when_there_are_none(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_api(monkeypatch, [])
    assert "started" in dev.seed_demo(1, "t")
    assert ("POST", "/runs", {"ticket": dev.DEMO_TICKET}) in calls


def test_does_not_seed_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_api(monkeypatch, [{"id": "r"}])
    assert "already exist" in dev.seed_demo(1, "t")
    assert all(c[0] == "GET" for c in calls)


def test_a_refused_seed_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_api(monkeypatch, [], post_status=503)
    assert "refused" in dev.seed_demo(1, "t")


def test_web_command_is_the_pinned_vite_on_the_advertised_address() -> None:
    assert dev.web_command() == ["npx", "--no-install", "vite", "--host", "127.0.0.1"]
    assert dev.npm_env({"A": "1"})["npm_config_engine_strict"] == "false"


def sleeper() -> subprocess.Popen[bytes]:
    """A stand-in child in its own session, like the API and vite."""
    return subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_stop_ends_the_childs_whole_group() -> None:
    child = sleeper()
    dev.stop(child)
    assert child.poll() is not None
    assert not alive(child.pid)


@pytest.fixture
def stubbed_stack(monkeypatch: pytest.MonkeyPatch) -> list[subprocess.Popen[bytes]]:
    children: list[subprocess.Popen[bytes]] = []

    def start_api(env: Any, port: int) -> subprocess.Popen[bytes]:
        children.append(sleeper())
        return children[-1]

    monkeypatch.setattr(dev, "start_api", start_api)
    monkeypatch.setattr(dev, "wait_for_api", lambda *a, **k: True)
    monkeypatch.setattr(dev, "port_answers", lambda port: False)
    return children


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP, signal.SIGINT])
def test_a_stop_signal_stops_the_children_and_exits_cleanly(
    stubbed_stack: list[subprocess.Popen[bytes]], sig: signal.Signals
) -> None:
    timer = threading.Timer(0.5, os.kill, [os.getpid(), sig])
    timer.start()
    try:
        assert dev.main(["--no-web", "--no-seed"]) == 0
    finally:
        timer.cancel()
        for c in stubbed_stack:  # never leave a sleeper behind if the test fails
            dev.stop(c)
    assert stubbed_stack
    assert not any(alive(c.pid) for c in stubbed_stack)


def test_a_second_signal_during_cleanup_does_not_leave_children(
    stubbed_stack: list[subprocess.Popen[bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_stop = dev.stop

    def slow_stop(proc: subprocess.Popen[bytes]) -> None:
        os.kill(os.getpid(), signal.SIGTERM)  # a second signal while cleaning up
        time.sleep(0.1)
        real_stop(proc)

    monkeypatch.setattr(dev, "stop", slow_stop)
    timer = threading.Timer(0.5, os.kill, [os.getpid(), signal.SIGTERM])
    timer.start()
    try:
        assert dev.main(["--no-web", "--no-seed"]) == 0
    finally:
        timer.cancel()
        for c in stubbed_stack:
            real_stop(c)
    assert not any(alive(c.pid) for c in stubbed_stack)


def test_signal_handlers_are_restored_afterwards(
    stubbed_stack: list[subprocess.Popen[bytes]],
) -> None:
    before = {s: signal.getsignal(s) for s in dev.STOP_SIGNALS}
    threading.Timer(0.3, os.kill, [os.getpid(), signal.SIGTERM]).start()
    dev.main(["--no-web", "--no-seed"])
    assert {s: signal.getsignal(s) for s in dev.STOP_SIGNALS} == before


def test_refuses_to_start_when_the_port_already_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    started: list[object] = []
    monkeypatch.setattr(dev, "port_answers", lambda port: True)
    monkeypatch.setattr(dev, "start_api", lambda *a: started.append(a))
    assert dev.main(["--no-web", "--no-seed"]) == 1
    assert not started
    assert "already in use" in capsys.readouterr().err


def test_port_answers_sees_a_listener(allow_loopback: None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert dev.port_answers(port)
    assert not dev.port_answers(port)


def test_the_dev_token_is_forwarded_to_the_ui(
    monkeypatch: pytest.MonkeyPatch, stubbed_stack: list[subprocess.Popen[bytes]]
) -> None:
    seen: dict[str, str] = {}
    monkeypatch.setenv("STO_DEV_TOKEN", "custom")
    monkeypatch.setattr(dev, "ensure_web_deps", lambda env: None)
    monkeypatch.setattr(dev.shutil, "which", lambda name: "/usr/bin/npx")

    def start_web(env: Any) -> subprocess.Popen[bytes]:
        seen.update(env)
        stubbed_stack.append(sleeper())
        raise KeyboardInterrupt  # stop right after the UI is started

    monkeypatch.setattr(dev, "start_web", start_web)
    monkeypatch.setattr(dev, "seed_demo", lambda port, token: "seeded")
    dev.main([])
    for c in stubbed_stack:
        dev.stop(c)
    assert seen["VITE_DEV_TOKEN"] == "custom"


def test_a_half_installed_node_modules_does_not_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dev, "WEB", tmp_path)
    (tmp_path / "node_modules").mkdir()
    assert not dev.deps_installed()
    (tmp_path / "node_modules" / ".package-lock.json").write_text("{}")
    assert dev.deps_installed()
