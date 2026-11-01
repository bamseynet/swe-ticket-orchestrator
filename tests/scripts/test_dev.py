"""``scripts/dev.py``: the demo seeding decision and the web command, with the API faked."""

from __future__ import annotations

import importlib.util
import sys
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


def test_web_command_is_the_vite_dev_server() -> None:
    assert dev.web_command() == ["npx", "vite"]
    assert dev.npm_env({"A": "1"})["npm_config_engine_strict"] == "false"
