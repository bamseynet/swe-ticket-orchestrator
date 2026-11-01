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
import inspect
import os
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Any

import pytest


class SocketBlockedError(RuntimeError):
    """Raised when a test tries to use the network."""


def _install_network_guard() -> None:
    # Self-contained: its source is also written to the subprocess ``sitecustomize``.
    def blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise SocketBlockedError("network sockets are blocked in tests; use an in-process fake")

    def guard(base: type) -> type:
        class Guarded(base):  # type: ignore[misc]
            def __init__(self, family: int = -1, *args: Any, **kwargs: Any) -> None:
                fileno = kwargs.get("fileno", args[2] if len(args) > 2 else None)
                if fileno is None and family != socket.AF_UNIX:
                    blocked()
                # Not super(): socket.socket.__init__ calls _socket.socket.__init__(self, ...).
                base.__init__(self, family, *args, **kwargs)  # type: ignore[misc]

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
