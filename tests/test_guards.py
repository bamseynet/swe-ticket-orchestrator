"""Tests for the hermetic-test guards in ``conftest.py``.

Inner test files run in a child pytest (``pytester``) with a copy of the real conftest, so the
guards are exercised exactly as every other test sees them, including the failing case.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

CONFTEST = Path(__file__).with_name("conftest.py")


@pytest.fixture
def guarded(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(CONFTEST.read_text())
    return pytester


def test_socket_open_fails_with_clear_reason(guarded: pytest.Pytester) -> None:
    guarded.makepyfile(
        """
        import socket

        def test_opens_socket():
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """
    )
    result = guarded.runpytest_subprocess()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*SocketBlockedError*network sockets are blocked*"])


def test_connect_helper_fails(guarded: pytest.Pytester) -> None:
    guarded.makepyfile(
        """
        import socket

        def test_connects():
            socket.create_connection(("127.0.0.1", 9))
        """
    )
    result = guarded.runpytest_subprocess()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*SocketBlockedError*"])


def test_dns_lookup_fails(guarded: pytest.Pytester) -> None:
    guarded.makepyfile(
        """
        import socket

        def test_resolves():
            socket.getaddrinfo("example.com", 443)
        """
    )
    result = guarded.runpytest_subprocess()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*SocketBlockedError*"])


def test_unix_socketpair_still_works() -> None:
    # asyncio's event loop needs socketpair(); local IPC is not network access.
    a, b = socket.socketpair()
    a.close()
    b.close()


def test_aws_environment_is_hidden(
    guarded: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_PROFILE", "prod")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAHOSTKEY")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/host/.aws/config")
    guarded.makepyfile(
        """
        import os

        def test_hidden():
            assert "AWS_PROFILE" not in os.environ
            assert "AWS_ACCESS_KEY_ID" not in os.environ
            assert "AWS_DEFAULT_REGION" not in os.environ
            assert "/host" not in os.environ["AWS_CONFIG_FILE"]
            assert not os.path.exists(os.environ["AWS_CONFIG_FILE"])
            assert not os.path.exists(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
            assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true"
        """
    )
    guarded.runpytest_subprocess().assert_outcomes(passed=1)


def test_aws_profile_is_unset_in_tests() -> None:
    assert "AWS_PROFILE" not in os.environ
