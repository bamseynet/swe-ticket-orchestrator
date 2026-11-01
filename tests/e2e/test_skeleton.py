"""The walking skeleton end to end (D1-10): the ``make dev`` stack, driven through both gates.

``scripts/dev.py --no-web`` runs the API exactly as ``make dev`` does (SQLite file, fake SCM,
simulated steps and merge queue) in a subprocess; this test talks to it over HTTP on loopback with
the dev token. No Docker, no credentials, no network beyond loopback. The browser journey is
``tests/ui/test_ui_v0.py``.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "dev-token"  # noqa: S105 - the documented local default
WAIT = 30.0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        size, _, data = data.partition(b"\r\n")
        n = int(size.split(b";")[0], 16)
        if n == 0:
            break
        out, data = out + data[:n], data[n + 2 :]
    return out


class Api:
    def __init__(self, port: int) -> None:
        self.port = port

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        # A raw loopback socket: name lookup (http.client) is blocked by the test guard.
        payload = json.dumps(body).encode() if body is not None else b""
        head = (
            f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode()
        chunks: list[bytes] = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.settimeout(10)
            conn.connect(("127.0.0.1", self.port))
            conn.sendall(head + payload)
            while chunk := conn.recv(65536):
                chunks.append(chunk)
        raw_head, _, raw_body = b"".join(chunks).partition(b"\r\n\r\n")
        status = int(raw_head.split(b" ", 2)[1])
        if b"transfer-encoding: chunked" in raw_head.lower():
            raw_body = _dechunk(raw_body)
        return status, (json.loads(raw_body) if raw_body else None)

    def until(self, what: str, probe: Callable[[], Any]) -> Any:
        deadline = time.monotonic() + WAIT
        while time.monotonic() < deadline:
            found = probe()
            if found:
                return found
            time.sleep(0.1)
        raise AssertionError(f"timed out waiting for {what}")

    def gate(self, run: str, name: str, round_: int) -> dict[str, Any]:
        def probe() -> dict[str, Any] | None:
            _, body = self.call("GET", f"/runs/{run}/gates")
            for g in body["gates"]:
                if g["name"] == name and g["round"] == round_:
                    return g  # type: ignore[no-any-return]
            return None

        return self.until(f"{name} round {round_}", probe)  # type: ignore[no-any-return]

    def decide(self, run: str, gate: dict[str, Any], kind: str, comment: str = "") -> None:
        status, body = self.call(
            "POST",
            f"/runs/{run}/gates/{gate['name']}/{gate['round']}/decisions",
            {"kind": kind, "subject_digest": gate["subject_digest"], "comment": comment},
        )
        assert status == 202, body

    def run_status(self, run: str) -> str:
        return str(self.call("GET", f"/runs/{run}")[1]["status"])

    def start(self) -> str:
        status, body = self.call("POST", "/runs", {"ticket": "DEMO-1"})
        assert status == 202, body
        return str(body["id"])

    def closed_as(self, run: str, gate: dict[str, Any]) -> str:
        def probe() -> str | None:
            g = self.gate(run, gate["name"], gate["round"])
            return f"{g['status']} by {g['closed_by']}" if g["closed_by"] else None

        return str(self.until("the gate to close", probe))


def children_of(pid: int) -> list[int]:
    """Direct children of a process (Linux ``/proc``)."""
    found: list[int] = []
    for task in Path(f"/proc/{pid}/task").iterdir():
        found += [int(c) for c in (task / "children").read_text().split()]
    return found


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def launch(tmp: Path, *flags: str) -> Iterator[Api]:
    """``scripts/dev.py --no-web`` as a subprocess. On exit it is sent SIGTERM (only it, not its
    group) and every process it started must be gone: a leaked API keeps its port."""
    env = {**os.environ, "STO_DB": str(tmp / "dev.db"), "STO_POLL_INTERVAL": "0.2"}
    log = (tmp / "dev.log").open("w")
    port = free_port()
    env["STO_API_PORT"] = str(port)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, str(ROOT / "scripts" / "dev.py"), "--no-web", *flags],
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    kids: list[int] = []
    try:
        client = Api(port)

        def up() -> bool:
            if proc.poll() is not None:
                raise AssertionError(f"dev.py exited early:\n{(tmp / 'dev.log').read_text()}")
            try:
                return client.call("GET", "/healthz")[0] == 200
            except OSError:
                return False

        client.until("the API to answer /healthz", up)
        kids = children_of(proc.pid)
        assert kids, "dev.py has no child: where is the API?"
        yield client
    finally:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(30)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass
        leaked = [pid for pid in kids if alive(pid)]
        with contextlib.suppress(ProcessLookupError):  # the backstop, after the check
            os.killpg(proc.pid, signal.SIGKILL)
        log.close()
        assert not leaked, f"dev.py left processes behind after SIGTERM: {leaked}"


@pytest.fixture
def api(tmp_path: Path, allow_loopback: None) -> Iterator[Api]:
    yield from launch(tmp_path, "--no-seed")


@pytest.fixture
def seeded_api(tmp_path: Path, allow_loopback: None) -> Iterator[Api]:
    yield from launch(tmp_path)  # as `make dev` does: with the demo run


@pytest.mark.e2e
def test_approve_then_approve_finishes_the_run(api: Api) -> None:
    run = api.start()
    review = api.gate(run, "review_gate", 1)
    api.decide(run, review, "approve", "ok")
    assert api.closed_as(run, review) == "APPROVED by dev"
    qa = api.gate(run, "qa_gate", 1)
    api.decide(run, qa, "approve", "ok")
    assert api.closed_as(run, qa) == "APPROVED by dev"
    api.until("the run to be DONE", lambda: api.run_status(run) == "DONE")


@pytest.mark.e2e
def test_reject_at_the_first_gate_ends_the_run(api: Api) -> None:
    run = api.start()
    review = api.gate(run, "review_gate", 1)
    status, body = api.call(
        "POST",
        f"/runs/{run}/gates/review_gate/1/decisions",
        {"kind": "reject", "comment": ""},
    )
    assert status == 422  # a veto says why
    assert body["error"]["code"] == "comment_required"
    api.decide(run, review, "reject", "not this")
    assert api.closed_as(run, review) == "REJECTED by dev"
    api.until("the run to end", lambda: api.run_status(run) == "REJECTED")
    assert api.call("GET", f"/runs/{run}/gates")[1]["gates"][-1]["name"] == "review_gate"


@pytest.mark.e2e
def test_reject_at_the_second_gate_ends_the_run(api: Api) -> None:
    run = api.start()
    review = api.gate(run, "review_gate", 1)
    api.decide(run, review, "approve", "ok")
    qa = api.gate(run, "qa_gate", 1)
    api.decide(run, qa, "reject", "qa says no")
    assert api.closed_as(run, qa) == "REJECTED by dev"
    api.until("the run to end", lambda: api.run_status(run) == "REJECTED")


@pytest.mark.e2e
def test_make_dev_seeds_one_demo_run_waiting_at_the_first_gate(seeded_api: Api) -> None:
    # /healthz answers before dev.py has seeded, so wait for the run to appear.
    body = seeded_api.until(
        "the demo run", lambda: seeded_api.call("GET", "/runs")[1]["runs"] or None
    )
    assert [r["ticket"] for r in body] == ["DEMO-1"]
    run = body[0]["id"]
    assert seeded_api.gate(run, "review_gate", 1)["status"] == "OPEN"
