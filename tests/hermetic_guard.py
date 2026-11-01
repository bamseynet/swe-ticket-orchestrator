"""Hermetic-test guards, a pytest plugin active for the whole process (``-p hermetic_guard``).

It is a plugin rather than ``conftest.py`` so pytest imports it exactly once, whichever paths
are collected.

They are installed in ``pytest_configure``, so imports, collection and session or module
fixtures are covered, not just test bodies. The autouse fixture is a per-test backstop.

* Network is blocked: creating an internet-family socket or resolving a name raises
  ``SocketBlockedError``. Unix-domain sockets stay allowed (asyncio uses ``socketpair``).
  Python subprocesses are guarded too, through a ``sitecustomize`` on ``PYTHONPATH``
  (not ``python -I``, and not non-Python programs).
* Host AWS configuration is invisible: ``AWS_*`` variables are removed, and ``HOME``,
  ``BOTO_CONFIG`` and the AWS config and credential files point into a temporary directory,
  so ``~/.aws`` (profiles, SSO and CLI caches) and boto configs are unreachable.
"""

from __future__ import annotations

import _socket
import contextlib
import inspect
import os
import shutil
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest


class SocketBlockedError(RuntimeError):
    """Raised when a test tries to use the network."""


def _install_network_guard() -> None:
    # Self-contained: its source is also written to the subprocess ``sitecustomize``.
    import os

    # ``allow_loopback_bind`` flips this; subprocesses inherit it through the environment.
    # Guards can nest (a child pytest on top of the sitecustomize guard), so layers share one state.
    state = _socket.__dict__.setdefault(
        "_sto_guard_state", {"loopback": os.environ.get("STO_TEST_ALLOW_LOOPBACK") == "1"}
    )
    loopback_hosts = ("127.0.0.1", "::1")

    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise SocketBlockedError("network sockets are blocked in tests; use an in-process fake")

    def check_address(family: int, address: Any) -> None:
        if family == socket.AF_UNIX:
            return
        if not (state["loopback"] and isinstance(address, tuple) and address[0] in loopback_hosts):
            blocked()

    def guard(base: type) -> type:
        class Guarded(base):  # type: ignore[misc]
            def __init__(self, family: int = -1, *args: Any, **kwargs: Any) -> None:
                fileno = kwargs.get("fileno", args[2] if len(args) > 2 else None)
                loopback_family = state["loopback"] and family in (socket.AF_INET, socket.AF_INET6)
                if fileno is None and family != socket.AF_UNIX and not loopback_family:
                    blocked()
                # Not super(): socket.socket.__init__ calls _socket.socket.__init__(self, ...).
                base.__init__(self, family, *args, **kwargs)  # type: ignore[misc]

            def bind(self, address: Any) -> Any:
                check_address(self.family, address)
                return super().bind(address)

            def connect(self, address: Any) -> Any:
                check_address(self.family, address)
                return super().connect(address)

            def connect_ex(self, address: Any) -> Any:
                check_address(self.family, address)
                return super().connect_ex(address)

            def sendto(self, data: Any, *args: Any) -> Any:
                # sendto(data, address) or sendto(data, flags, address)
                check_address(self.family, args[-1] if args else None)
                return super().sendto(data, *args)

            def sendmsg(self, buffers: Any, *args: Any) -> Any:
                # sendmsg(buffers[, ancdata[, flags[, address]]]); no address means connected
                if len(args) > 2 and args[2] is not None:
                    check_address(self.family, args[2])
                return super().sendmsg(buffers, *args)

        return Guarded

    for module in (_socket, socket):
        module.__dict__["socket"] = guard(module.socket)
    for module in (socket, _socket):
        for name in (
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostbyaddr",
            "getnameinfo",
        ):
            setattr(module, name, blocked)


_SITECUSTOMIZE = (
    "from __future__ import annotations\n"
    "import socket\nimport _socket\nfrom typing import Any\n\n\n"
    + inspect.getsource(SocketBlockedError)
    + "\n\n"
    + inspect.getsource(_install_network_guard)
    + "\n\n_install_network_guard()\n"
)


@contextlib.contextmanager
def allow_loopback_bind() -> Iterator[None]:
    """Permit bind, listen and connect on 127.0.0.1 and ::1 only, for the ``with`` body.

    Name lookups and every other address stay blocked, including in Python subprocesses started
    inside the block (they inherit it through ``STO_TEST_ALLOW_LOOPBACK``).
    """
    state = _socket.__dict__["_sto_guard_state"]
    previous = (state["loopback"], os.environ.get("STO_TEST_ALLOW_LOOPBACK"))
    state["loopback"] = True
    os.environ["STO_TEST_ALLOW_LOOPBACK"] = "1"
    try:
        yield
    finally:
        state["loopback"] = previous[0]
        if previous[1] is None:
            os.environ.pop("STO_TEST_ALLOW_LOOPBACK", None)
        else:
            os.environ["STO_TEST_ALLOW_LOOPBACK"] = previous[1]


@pytest.fixture
def allow_loopback() -> Iterator[None]:
    """Fixture form of ``allow_loopback_bind`` for tests that need real loopback listeners."""
    with allow_loopback_bind():
        yield


def _sandbox_env(root: Path) -> dict[str, str]:
    return {
        "HOME": str(root / "home"),
        "BOTO_CONFIG": str(root / "no-boto-config"),
        "AWS_CONFIG_FILE": str(root / "no-aws-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(root / "no-aws-credentials"),
        "AWS_EC2_METADATA_DISABLED": "true",
        "UV_OFFLINE": "1",
        "PYTHONPATH": os.pathsep.join(
            p for p in (str(root / "site"), os.environ.get("PYTHONPATH")) if p
        ),
    }


saved: dict[str, Any] = {}
configure_calls = 0


def pytest_configure(config: pytest.Config) -> None:
    global configure_calls  # noqa: PLW0603
    configure_calls += 1
    # An exported variable must not open loopback for the whole session, including through an
    # outer sitecustomize guard; only ``allow_loopback_bind`` may.
    os.environ.pop("STO_TEST_ALLOW_LOOPBACK", None)
    root = Path(tempfile.mkdtemp(prefix="sto-hermetic-"))
    (root / "home").mkdir()
    (root / "site").mkdir()
    (root / "site" / "sitecustomize.py").write_text(_SITECUSTOMIZE)
    saved.update(
        root=root,
        env=dict(os.environ),
        sockets=(socket.__dict__.copy(), _socket.__dict__.copy()),
    )
    _install_network_guard()
    _socket.__dict__["_sto_guard_state"]["loopback"] = False
    for name in [n for n in os.environ if n.startswith("AWS_")]:
        del os.environ[name]
    os.environ.update(_sandbox_env(root))


def pytest_unconfigure(config: pytest.Config) -> None:
    if not saved:
        return
    for module, original in zip((socket, _socket), saved["sockets"], strict=True):
        module.__dict__.update(original)
    os.environ.clear()
    os.environ.update(saved["env"])
    shutil.rmtree(saved["root"], ignore_errors=True)
    saved.clear()


@pytest.fixture(autouse=True)
def _guards_backstop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-test backstop: re-applies the sandbox if a test or plugin restored host values."""
    sandbox = _sandbox_env(saved["root"])
    for name in [n for n in os.environ if n.startswith("AWS_") and n not in sandbox]:
        monkeypatch.delenv(name)
    for key, value in sandbox.items():
        monkeypatch.setenv(key, value)
