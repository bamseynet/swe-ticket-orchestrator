#!/usr/bin/env python3
"""``make doctor``: check local prerequisites and ports, printing a fix for each problem.

Python 3.12+, uv, Node 24 (``.nvmrc``) and the dev ports are required. Docker is optional.
Ports default to 8710 (API) and 5710 (web), and can be overridden with ``STO_API_PORT`` /
``STO_WEB_PORT`` or ``--api-port`` / ``--web-port`` (flags win).
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

DEFAULT_API_PORT = 8710
DEFAULT_WEB_PORT = 5710
MIN_PYTHON = (3, 12)
NODE_MAJOR = 24


@dataclass(frozen=True)
class Result:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    optional: bool = False


class Host(Protocol):
    def version(self, tool: str) -> str | None: ...
    def port_free(self, port: int) -> bool: ...
    def python_version(self) -> tuple[int, int]: ...


class RealHost:
    def version(self, tool: str) -> str | None:
        if shutil.which(tool) is None:
            return None
        try:
            proc = subprocess.run(
                [tool, "--version"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return (proc.stdout or proc.stderr).strip() or None

    def port_free(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    def python_version(self) -> tuple[int, int]:
        return sys.version_info[0], sys.version_info[1]


def _port(value: str, source: str) -> int:
    try:
        port = int(value)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise SystemExit(f"doctor: {source} must be a port number 1-65535, got {value!r}")
    return port


def _check_python(host: Host) -> Result:
    major, minor = host.python_version()
    if (major, minor) >= MIN_PYTHON:
        return Result("python", True, f"Python {major}.{minor}")
    return Result(
        "python",
        False,
        f"Python {major}.{minor} is older than {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
        f"uv python install {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
    )


def _check_uv(host: Host) -> Result:
    found = host.version("uv")
    if found:
        return Result("uv", True, found)
    return Result(
        "uv",
        False,
        "uv not found",
        "curl -LsSf https://astral.sh/uv/install.sh | sh  (see https://docs.astral.sh/uv/)",
    )


def _check_node(host: Host) -> Result:
    fix = f"nvm install {NODE_MAJOR} && nvm use  (the repo's .nvmrc pins {NODE_MAJOR})"
    found = host.version("node")
    if not found:
        return Result("node", False, "node not found", fix)
    digits = found.lstrip("v").split(".")[0]
    if digits.isdigit() and int(digits) == NODE_MAJOR:
        return Result("node", True, found)
    return Result("node", False, f"{found} found, Node {NODE_MAJOR} required", fix)


def _check_docker(host: Host) -> Result:
    found = host.version("docker")
    if found:
        return Result("docker", True, found, optional=True)
    return Result(
        "docker",
        False,
        "docker not found; only needed for CI-tier integration work",
        "optional: install Docker Engine from https://docs.docker.com/engine/install/",
        optional=True,
    )


def _check_port(host: Host, port: int, label: str, env_var: str, flag: str) -> Result:
    name = f"port {port} ({label})"
    if host.port_free(port):
        return Result(name, True, "free")
    return Result(
        name,
        False,
        f"port {port} is already in use by another process",
        f"stop that process (e.g. `ss -ltnp | grep :{port}`), or pick another port with "
        f"{env_var}=<port> or {flag} <port>",
    )


def run_checks(host: Host, env: Mapping[str, str], argv: Sequence[str]) -> list[Result]:
    parser = argparse.ArgumentParser(prog="doctor", description=__doc__)
    parser.add_argument("--api-port", type=str, help=f"API port (default {DEFAULT_API_PORT})")
    parser.add_argument("--web-port", type=str, help=f"web port (default {DEFAULT_WEB_PORT})")
    args = parser.parse_args(list(argv))

    def pick(flag: str | None, var: str, default: int) -> int:
        if flag is not None:
            return _port(flag, f"--{var.removeprefix('STO_').removesuffix('_PORT').lower()}-port")
        if var in env:
            return _port(env[var], var)
        return default

    api = pick(args.api_port, "STO_API_PORT", DEFAULT_API_PORT)
    web = pick(args.web_port, "STO_WEB_PORT", DEFAULT_WEB_PORT)
    return [
        _check_python(host),
        _check_uv(host),
        _check_node(host),
        _check_docker(host),
        _check_port(host, api, "api", "STO_API_PORT", "--api-port"),
        _check_port(host, web, "web", "STO_WEB_PORT", "--web-port"),
    ]


def exit_code(results: Sequence[Result]) -> int:
    return 0 if all(r.ok or r.optional for r in results) else 1


def render(results: Sequence[Result]) -> str:
    lines: list[str] = []
    for r in results:
        mark = "ok  " if r.ok else ("skip" if r.optional else "FAIL")
        suffix = " (optional)" if r.optional else ""
        lines.append(f"[{mark}] {r.name}{suffix}: {r.detail}")
        if not r.ok and r.fix:
            lines.append(f"       fix: {r.fix}")
    lines.append(
        "doctor: all required checks passed"
        if exit_code(results) == 0
        else "doctor: fix the FAIL items above"
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    results = run_checks(RealHost(), os.environ, sys.argv[1:] if argv is None else argv)
    print(render(results))
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
