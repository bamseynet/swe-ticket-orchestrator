"""Tests for ``scripts/doctor.py``. All probes are injected, so nothing touches the host."""

from __future__ import annotations

import importlib.util
import sys
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
