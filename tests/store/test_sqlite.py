"""The SQLite store passes the shared contract suite and keeps committed state (D1-12)."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from store_contract import StoreContract, race_claims

from sto.store.ports import PLATFORM, Absent, Key, Put, Store, TeamScope
from sto.store.sqlite import SqliteStore

T = TeamScope("team-a")


class TestSqliteStore(StoreContract):
    @pytest.fixture
    def store(self, tmp_path: Path) -> Iterator[Store]:
        s = SqliteStore(tmp_path / "sto.db")
        yield s
        s.close()


def test_claims_stay_exclusive(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "sto.db")
    try:
        assert race_claims(store, rounds=5) == [1] * 5
    finally:
        store.close()


def test_state_survives_reopening_the_file(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    first = SqliteStore(path)
    first.put(T, Key("RUN#1", "META"), {"n": 1})
    first.put(PLATFORM, Key("ORG", "META"), {"o": 1})
    first.close()
    second = SqliteStore(path)
    try:
        item = second.get(T, Key("RUN#1", "META"))
        assert item is not None
        assert (item.data, item.version) == ({"n": 1}, 1)
        assert second.get(PLATFORM, Key("ORG", "META")) is not None
    finally:
        second.close()


def test_a_second_connection_sees_committed_writes(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    a, b = SqliteStore(path), SqliteStore(path)
    try:
        a.put(T, Key("RUN#1", "META"), {"n": 1})
        assert b.get(T, Key("RUN#1", "META")) is not None
    finally:
        a.close()
        b.close()


_WRITER = textwrap.dedent(
    """
    import os, sys
    from sto.store.ports import Key, Put, TeamScope
    from sto.store.sqlite import SqliteStore

    store = SqliteStore(sys.argv[1])
    team = TeamScope("team-a")
    store.put(team, Key("RUN#1", "META"), {"status": "waiting"})
    store.put(team, Key("RUN#1", "GATE#g#1"), {"status": "open"})
    print("committed", flush=True)
    # A transaction left open when the process dies must not be applied.
    store._conn.execute("BEGIN IMMEDIATE")
    store._conn.execute(
        "UPDATE items SET data = '{\\"status\\": \\"torn\\"}' WHERE pk = 'RUN#1' AND sk = 'META'"
    )
    print("uncommitted", flush=True)
    os.kill(os.getpid(), 9)
    """
)


def test_a_killed_process_keeps_committed_state_and_drops_uncommitted(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    proc = subprocess.Popen(
        [sys.executable, "-c", _WRITER, str(path)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "committed"
    assert proc.stdout.readline().strip() == "uncommitted"
    assert proc.wait(timeout=30) == -9  # SIGKILL: no close(), no cleanup, no atexit
    proc.stdout.close()

    store = SqliteStore(path)  # a restart
    try:
        meta = store.get(T, Key("RUN#1", "META"))
        gate = store.get(T, Key("RUN#1", "GATE#g#1"))
        assert meta is not None
        assert gate is not None
        assert meta.data == {"status": "waiting"}  # the torn update is gone
        assert gate.data == {"status": "open"}  # the waiting gate is still waiting
        store.put(T, Key("RUN#1", "NEXT"), {"n": 1}, when=Absent())  # and the file is writable
        store.transact(T, [Put(Key("RUN#1", "NEXT"), {"n": 2})])
    finally:
        store.close()


def test_a_closed_store_refuses_use(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "sto.db")
    store.close()
    store.close()  # idempotent
    with pytest.raises(RuntimeError, match="closed"):
        store.get(T, Key("RUN#1", "META"))
