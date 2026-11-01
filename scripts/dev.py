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
    return ["npx", "vite"]


def npm_env(env: Mapping[str, str]) -> dict[str, str]:
    return {**env, "npm_config_engine_strict": "false"}


def ensure_web_deps(env: Mapping[str, str]) -> None:
    if (WEB / "node_modules").exists():
        return
    print("dev: installing web dependencies (npm ci)", flush=True)
    subprocess.run(  # noqa: S603 - fixed argv
        ["npm", "ci", "--no-audit", "--no-fund"], cwd=WEB, env=npm_env(env), check=True, timeout=600
    )


def stop(proc: subprocess.Popen[bytes]) -> None:
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local stack: API, web UI, demo ticket.")
    parser.add_argument("--no-web", action="store_true", help="run only the API")
    parser.add_argument("--no-seed", action="store_true", help="do not start a demo run")
    args = parser.parse_args(argv)

    api_port = int(os.environ.get("STO_API_PORT", "8710"))
    web_port = int(os.environ.get("STO_WEB_PORT", "5710"))
    token = os.environ.get("STO_DEV_TOKEN", DEFAULT_TOKEN)
    env = {**os.environ, "STO_MODE": "local", "STO_API_PORT": str(api_port)}

    if not args.no_web:
        if shutil.which("npx") is None:
            print(
                "dev: Node 24 (npx) not found; run `make doctor`, or use --no-web", file=sys.stderr
            )
            return 2
        ensure_web_deps(env)

    procs: list[subprocess.Popen[bytes]] = []
    try:
        api = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "sto.api.app", "--port", str(api_port)],
            cwd=ROOT,
            env=env,
            start_new_session=True,
        )
        procs.append(api)
        if not wait_for_api(api_port, 60, lambda: api.poll() is None):
            print("dev: the API did not come up; see its output above", file=sys.stderr)
            return 1
        if not args.no_seed:
            print(f"dev: {seed_demo(api_port, token)}", flush=True)
        if not args.no_web:
            web = subprocess.Popen(  # noqa: S603 - fixed argv
                web_command(),
                cwd=WEB,
                env=npm_env(env),
                start_new_session=True,
            )
            procs.append(web)
            print(
                f"dev: UI http://127.0.0.1:{web_port}/  API http://127.0.0.1:{api_port}/docs",
                flush=True,
            )
        else:
            print(f"dev: API http://127.0.0.1:{api_port}/docs", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        print("dev: a process exited; stopping the rest", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for p in procs:
            stop(p)


if __name__ == "__main__":
    raise SystemExit(main())
