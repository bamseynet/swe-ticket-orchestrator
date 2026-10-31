"""Hermetic-test guards, active for every test.

* Network sockets are blocked: opening an internet-family socket or resolving a name raises
  ``SocketBlockedError``. Unix-domain sockets stay allowed (asyncio uses ``socketpair``).
* Host AWS configuration is invisible: ``AWS_*`` variables are removed and the config and
  credential files point at nothing, so a test can never reach a real account.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

import pytest


class SocketBlockedError(RuntimeError):
    """Raised when a test tries to use the network."""


def _blocked(*_args: Any, **_kwargs: Any) -> Any:
    raise SocketBlockedError("network sockets are blocked in tests; use an in-process fake")


class _GuardedSocket(socket.socket):
    def __init__(
        self,
        family: int = -1,
        type: int = -1,  # noqa: A002 - mirrors socket.socket
        proto: int = -1,
        fileno: int | None = None,
    ) -> None:
        if fileno is None and family != socket.AF_UNIX:
            _blocked()
        super().__init__(family, type, proto, fileno)


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "socket", _GuardedSocket)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, _blocked)


@pytest.fixture(autouse=True)
def _hide_host_aws(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in [n for n in os.environ if n.startswith("AWS_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
