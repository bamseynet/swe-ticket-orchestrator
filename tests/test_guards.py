"""Tests for the hermetic-test guards in ``hermetic_guard.py``.

Inner test files run in a child pytest (``pytester``) with a copy of the real plugin, so the
guards are exercised exactly as every other test sees them, including the failing case.
"""

from __future__ import annotations

import _socket
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

PLUGIN = Path(__file__).with_name("hermetic_guard.py")


@pytest.fixture
def guarded(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makepyfile(hermetic_guard=PLUGIN.read_text())
    pytester.makeconftest('pytest_plugins = ["hermetic_guard"]')
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


def test_session_fixture_and_import_time_are_guarded(
    guarded: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_PROFILE", "prod")
    guarded.makepyfile(
        """
        import os
        import socket

        import pytest

        @pytest.fixture(scope="session")
        def session_probe():
            assert "AWS_PROFILE" not in os.environ
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def test_uses_session_fixture(session_probe):
            pass
        """
    )
    result = guarded.runpytest_subprocess()
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*SocketBlockedError*"])


def test_import_time_socket_and_aws_are_guarded(
    guarded: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_PROFILE", "prod")
    guarded.makepyfile(
        """
        import os
        import socket

        assert "AWS_PROFILE" not in os.environ
        socket.create_connection(("127.0.0.1", 9))

        def test_never_collected():
            pass
        """
    )
    result = guarded.runpytest_subprocess()
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*SocketBlockedError*"])


def test_home_and_boto_config_are_unreachable(
    guarded: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", "/host/home")
    monkeypatch.setenv("BOTO_CONFIG", "/host/home/.boto")
    guarded.makepyfile(
        """
        import os
        from pathlib import Path

        def test_hidden():
            assert "/host" not in os.environ["HOME"]
            assert "/host" not in str(Path.home())
            assert "/host" not in os.environ["BOTO_CONFIG"]
            assert not Path(os.environ["BOTO_CONFIG"]).exists()
            assert not (Path.home() / ".aws").exists()
        """
    )
    guarded.runpytest_subprocess().assert_outcomes(passed=1)


def test_getnameinfo_is_blocked() -> None:
    with pytest.raises(Exception, match="network sockets are blocked"):
        socket.getnameinfo(("127.0.0.1", 80), 0)


def test_low_level_socket_is_blocked() -> None:
    with pytest.raises(Exception, match="network sockets are blocked"):
        _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)


def test_subprocesses_are_guarded() -> None:
    code = "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert proc.returncode != 0
    assert "network sockets are blocked" in proc.stderr


def test_guards_cover_tests_outside_tests_dir(tmp_path: Path) -> None:
    # e.g. ``pytest tools/...``: the repo's pytest config must load the guards itself.
    repo = PLUGIN.parent.parent
    probe = tmp_path / "test_probe.py"
    probe.write_text("import socket\n\ndef test_probe():\n    socket.socket(socket.AF_INET)\n")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-c", str(repo / "pyproject.toml"),
         "--rootdir", str(repo), "-p", "no:cacheprovider", str(probe)],
        capture_output=True, text=True, check=False, cwd=tmp_path,
    )  # fmt: skip
    assert proc.returncode == 1, proc.stdout
    assert "network sockets are blocked" in proc.stdout


def test_guard_plugin_configures_once_and_shares_its_error_class() -> None:
    import hermetic_guard

    assert hermetic_guard.configure_calls == 1
    # The snapshot taken for restoring must be the host env, not the sandboxed one.
    assert hermetic_guard.saved["env"].get("HOME") != os.environ["HOME"]
    assert os.environ["UV_OFFLINE"] == "1"
    with pytest.raises(hermetic_guard.SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
