#!/usr/bin/env python3
"""``make dev``: the whole local stack, with no Docker and no credentials.

Starts the API (``python -m sto.api.app``: SQLite file, fake SCM, simulated steps) and the web UI
(``vite``, which forwards ``/api`` to the API), waits until the API answers, then starts one demo
run if there are none, so ``/runs`` has a ticket waiting at its first gate. Ctrl-C stops both.

Ports: ``STO_API_PORT`` (8710) and ``STO_WEB_PORT`` (5710). ``--no-web`` runs only the API (the
e2e test does); ``--no-seed`` skips the demo run. Dev auth only runs in local mode, so this sets
``STO_MODE=local`` itself.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
DEFAULT_TOKEN = "dev-token"  # noqa: S105 - the documented local default, loopback only
DEMO_TICKET = "DEMO-1"


def request(
    port: int, method: str, path: str, token: str, body: object = None
) -> tuple[int, object]:
    """One HTTP call to the API on loopback."""
    payload = json.dumps(body).encode() if body is not None else b""
    head = (
        f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n\r\n"
    ).encode()
    chunks: list[bytes] = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(("127.0.0.1", port))
        conn.sendall(head + payload)
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    raw_head, _, raw_body = b"".join(chunks).partition(b"\r\n\r\n")
    status = int(raw_head.split(b" ", 2)[1])
    if b"transfer-encoding: chunked" in raw_head.lower():
        out, rest = b"", raw_body
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            n = int(size.split(b";")[0], 16)
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2 :]
        raw_body = out
    return status, (json.loads(raw_body) if raw_body else None)


def wait_for_api(port: int, timeout: float, alive: object = None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if callable(alive) and not alive():
            return False
        try:
            if request(port, "GET", "/healthz", "")[0] == 200:
                return True
        except (OSError, ValueError, IndexError):
            pass
        time.sleep(0.2)
    return False


def seed_demo(port: int, token: str) -> str:
    """Start the demo run when there is none yet. Returns what it did, for the log."""
    status, body = request(port, "GET", "/runs?limit=1", token)
    if status != 200 or not isinstance(body, dict):
        return f"could not list runs (HTTP {status}); no demo run started"
    if body.get("runs"):
        return "runs already exist; no demo run started"
    status, _ = request(port, "POST", "/runs", token, {"ticket": DEMO_TICKET})
    return (
        f"started demo run for {DEMO_TICKET}"
        if status == 202
        else f"demo run refused (HTTP {status})"
    )


def web_command() -> list[str]:
    # --no-install: never fetch an unpinned vite. 127.0.0.1: the address this script advertises
    # (plain "localhost" can resolve to ::1 first).
    return ["npx", "--no-install", "vite", "--host", "127.0.0.1"]


def npm_env(env: Mapping[str, str]) -> dict[str, str]:
    return {**env, "npm_config_engine_strict": "false"}


def deps_installed() -> bool:
    # npm writes this file last, so a half-finished `npm ci` does not count as installed.
    return (WEB / "node_modules" / ".package-lock.json").exists()


def ensure_web_deps(env: Mapping[str, str]) -> None:
    if deps_installed():
        return
    print("dev: installing web dependencies (npm ci)", flush=True)
    subprocess.run(  # noqa: S603 - fixed argv
        ["npm", "ci", "--no-audit", "--no-fund"], cwd=WEB, env=npm_env(env), check=True, timeout=600
    )


def port_answers(port: int) -> bool:
    """True if something already listens on the loopback port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def start_api(env: Mapping[str, str], port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "sto.api.app", "--port", str(port)],
        cwd=ROOT,
        env=dict(env),
        start_new_session=True,
    )


def start_web(env: Mapping[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv
        web_command(), cwd=WEB, env=npm_env(env), start_new_session=True
    )


def stop(proc: subprocess.Popen[bytes]) -> None:
    """Stop the child's whole process group (it runs in its own session): SIGTERM, then SIGKILL."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(10)
            return
        except subprocess.TimeoutExpired:
            continue


STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def _leave(signum: int, frame: object) -> None:
    raise KeyboardInterrupt  # one exit path for Ctrl-C, kill and a closed terminal


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local stack: API, web UI, demo ticket.")
    parser.add_argument("--no-web", action="store_true", help="run only the API")
    parser.add_argument("--no-seed", action="store_true", help="do not start a demo run")
    args = parser.parse_args(argv)

    api_port = int(os.environ.get("STO_API_PORT", "8710"))
    web_port = int(os.environ.get("STO_WEB_PORT", "5710"))
    token = os.environ.get("STO_DEV_TOKEN", DEFAULT_TOKEN)
    env = {
        **os.environ,
        "STO_MODE": "local",
        "STO_API_PORT": str(api_port),
        "VITE_DEV_TOKEN": token,  # the UI sends the same token the API expects
    }

    wanted = [("API", api_port)] + ([] if args.no_web else [("web", web_port)])
    for name, port in wanted:
        if port_answers(port):
            print(
                f"dev: port {port} ({name}) is already in use, perhaps by another `make dev`; "
                "stop it first, or set STO_API_PORT / STO_WEB_PORT",
                file=sys.stderr,
            )
            return 1

    if not args.no_web:
        if shutil.which("npx") is None:
            print(
                "dev: Node 24 (npx) not found; run `make doctor`, or use --no-web", file=sys.stderr
            )
            return 2
        ensure_web_deps(env)

    previous = {sig: signal.signal(sig, _leave) for sig in STOP_SIGNALS}
    procs: list[subprocess.Popen[bytes]] = []
    code = 1
    try:
        api = start_api(env, api_port)
        procs.append(api)
        if not wait_for_api(api_port, 60, lambda: api.poll() is None):
            print("dev: the API did not come up; see its output above", file=sys.stderr)
            return 1
        if not args.no_seed:
            print(f"dev: {seed_demo(api_port, token)}", flush=True)
        if not args.no_web:
            procs.append(start_web(env))
            print(
                f"dev: UI http://127.0.0.1:{web_port}/  API http://127.0.0.1:{api_port}/docs",
                flush=True,
            )
        else:
            print(f"dev: API http://127.0.0.1:{api_port}/docs", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        print("dev: a process exited; stopping the rest", file=sys.stderr)
    except KeyboardInterrupt:
        code = 0
    finally:
        for sig in STOP_SIGNALS:  # a second Ctrl-C must not interrupt the cleanup
            signal.signal(sig, signal.SIG_IGN)
        for p in procs:
            stop(p)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
