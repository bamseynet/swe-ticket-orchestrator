"""The SQLite store passes the shared contract suite and keeps committed state (D1-12).

What the kill test proves: SQLite's commit protocol is atomic across a process kill (SIGKILL
mid-transaction through ``transact``, no ``close()``, no cleanup). What it does not prove:
power-loss durability. SIGKILL leaves the OS page cache intact, so ``synchronous=FULL`` is
checked separately, as a pragma assertion (``test_the_durability_pragmas_are_set``).
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from store_contract import StoreContract, race_claims

from sto.store.memory import MemoryStore
from sto.store.ports import (
    PLATFORM,
    Absent,
    ConditionFailedError,
    Key,
    Put,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)
from sto.store.sqlite import SqliteStore

T = TeamScope("team-a")
META = Key("RUN#1", "META")
GATE = Key("RUN#1", "GATE#g#1")


class TestSqliteStore(StoreContract):
    @pytest.fixture
    def store(self, tmp_path: Path) -> Iterator[Store]:
        s = SqliteStore(tmp_path / "sto.db")
        yield s
        s.close()


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SqliteStore]:
    s = SqliteStore(tmp_path / "sto.db")
    yield s
    s.close()


class Proxy:
    """Stands in for the store's connection and runs ``hook(sql)`` before each statement, so a
    test can inject a failure (or a SIGKILL) at an exact point inside ``transact``."""

    def __init__(self, conn: Any, hook: Any) -> None:
        self._conn = conn
        self._hook = hook

    def execute(self, sql: str, *args: Any) -> Any:
        self._hook(self._conn, sql)
        return self._conn.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def inject(store: SqliteStore, hook: Any) -> None:
    store._conn = Proxy(store._conn, hook)  # type: ignore[assignment]


# --- the contract under contention and restarts -------------------------------------------


def test_claims_stay_exclusive(store: SqliteStore) -> None:
    assert race_claims(store, rounds=5) == [1] * 5


def test_separate_connections_to_one_file_race_with_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    threads, rounds = 6, 15
    stores = [SqliteStore(path) for _ in range(threads)]
    try:
        for r in range(rounds):
            key = Key("RACE", f"R{r}")
            stores[0].put(T, key, {"owner": None})
            barrier = threading.Barrier(threads)
            outcomes: list[str] = []

            def claim(
                n: int,
                key: Key = key,
                barrier: threading.Barrier = barrier,
                outcomes: list[str] = outcomes,
            ) -> None:
                barrier.wait()
                try:
                    stores[n].transact(T, [Put(key, {"owner": n}, when=VersionIs(1))])
                    outcomes.append("won")
                except ConditionFailedError:
                    outcomes.append("lost")
                except TransactionConflictError:  # BEGIN IMMEDIATE must wait, not fail
                    outcomes.append("conflict")

            pool = [threading.Thread(target=claim, args=(n,)) for n in range(threads)]
            for t in pool:
                t.start()
            for t in pool:
                t.join()
            assert sorted(outcomes) == ["lost"] * (threads - 1) + ["won"]
    finally:
        for s in stores:
            s.close()


def test_state_survives_reopening_the_file(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    first = SqliteStore(path)
    first.put(T, META, {"n": 1})
    first.put(PLATFORM, Key("ORG", "META"), {"o": 1})
    first.close()
    second = SqliteStore(path)
    try:
        item = second.get(T, META)
        assert item is not None
        assert (item.data, item.version) == ({"n": 1}, 1)
        assert second.get(PLATFORM, Key("ORG", "META")) is not None
    finally:
        second.close()


def test_a_second_connection_sees_committed_writes(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    a, b = SqliteStore(path), SqliteStore(path)
    try:
        a.put(T, META, {"n": 1})
        assert b.get(T, META) is not None
    finally:
        a.close()
        b.close()


def test_a_closed_store_refuses_use(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "sto.db")
    store.close()
    store.close()  # idempotent
    with pytest.raises(RuntimeError, match="closed"):
        store.get(T, META)


# --- durability settings and the transaction protocol -------------------------------------


def test_the_durability_pragmas_are_set(store: SqliteStore, tmp_path: Path) -> None:
    assert store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    raw = sqlite3.connect(str(tmp_path / "sto.db"))
    try:
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        raw.close()


def test_every_transaction_takes_the_write_lock_first_and_commits(store: SqliteStore) -> None:
    seen: list[str] = []
    store._conn.set_trace_callback(seen.append)
    store.put(T, META, {"n": 1})
    store._conn.set_trace_callback(None)
    assert seen[0] == "BEGIN IMMEDIATE"
    assert seen[-1] == "COMMIT"


def test_a_failure_inside_a_transaction_commits_nothing(store: SqliteStore, tmp_path: Path) -> None:
    inserts = []

    def hook(_conn: Any, sql: str) -> None:
        if sql.lstrip().startswith("INSERT"):
            inserts.append(sql)
            if len(inserts) == 3:
                raise sqlite3.OperationalError("boom")

    inject(store, hook)
    with pytest.raises(sqlite3.OperationalError, match="boom"):
        store.transact(T, [Put(Key("R", f"K{i}"), {"i": i}) for i in range(5)])
    assert len(inserts) == 3  # two writes had been made when it failed
    other = SqliteStore(tmp_path / "sto.db")  # a fresh connection sees only committed state
    try:
        assert other.query(T, "R").items == ()
    finally:
        other.close()
    assert store.query(T, "R").items == ()
    store.put(T, Key("R", "K0"), {"i": 0}, when=Absent())  # and the store is still usable


def test_a_failing_commit_leaves_no_open_transaction(store: SqliteStore) -> None:
    def hook(_conn: Any, sql: str) -> None:
        if sql == "COMMIT":
            raise sqlite3.OperationalError("disk I/O error")

    inject(store, hook)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store.put(T, META, {"n": 1})
    assert not store._conn.in_transaction
    assert store.get(T, META) is None  # the aborted item is not visible
    store._conn = store._conn._conn  # type: ignore[attr-defined]  # remove the fault
    store.put(T, META, {"n": 2}, when=Absent())


def test_a_rollback_by_sqlite_does_not_hide_the_real_error(store: SqliteStore) -> None:
    """On a full disk SQLite rolls back by itself; a second ROLLBACK would raise 'cannot
    rollback' and bury the cause."""

    def hook(conn: Any, sql: str) -> None:
        if sql.lstrip().startswith("INSERT"):
            conn.execute("ROLLBACK")
            raise sqlite3.OperationalError("database or disk is full")

    inject(store, hook)
    with pytest.raises(sqlite3.OperationalError, match="disk is full"):
        store.put(T, META, {"n": 1})


# --- busy file ------------------------------------------------------------------------------


def test_a_busy_file_raises_a_retryable_conflict_not_a_raw_sqlite_error(tmp_path: Path) -> None:
    path = tmp_path / "sto.db"
    holder = SqliteStore(path)
    waiter = SqliteStore(path, timeout=0.05)
    try:
        holder._conn.execute("BEGIN IMMEDIATE")  # another writer holds the file
        with pytest.raises(TransactionConflictError):
            waiter.put(T, META, {"n": 1})
        holder._conn.execute("ROLLBACK")
        waiter.put(T, META, {"n": 1})  # retry works once the writer is done
    finally:
        holder.close()
        waiter.close()


def test_many_connections_can_open_a_fresh_file_at_once(tmp_path: Path) -> None:
    for round_ in range(20):
        path = tmp_path / f"fresh{round_}.db"
        barrier = threading.Barrier(6)
        errors: list[BaseException] = []

        def open_it(
            path: Path = path,
            barrier: threading.Barrier = barrier,
            errors: list[BaseException] = errors,
        ) -> None:
            barrier.wait()
            try:
                SqliteStore(path).close()
            except BaseException as exc:
                errors.append(exc)

        pool = [threading.Thread(target=open_it) for _ in range(6)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        assert errors == []


def test_a_file_that_cannot_use_wal_is_refused_and_the_connection_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made: list[sqlite3.Connection] = []
    real = sqlite3.connect

    def spy(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn: sqlite3.Connection = real(*args, **kwargs)
        made.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", spy)
    with pytest.raises(RuntimeError, match="WAL"):
        SqliteStore(":memory:")  # an in-memory database silently ignores journal_mode=WAL
    with pytest.raises(sqlite3.ProgrammingError):
        made[0].execute("SELECT 1")


# --- parity with the in-memory store on odd keys ---------------------------------------------


def test_a_prefix_with_a_nul_character_is_literal(store: SqliteStore) -> None:
    memory = MemoryStore()
    for s in (store, memory):
        for sk in ("a\x00b", "a\x00", "a", "ab", "a\x01"):
            s.put(T, Key("P", sk), {"sk": sk})
    for prefix in ("a\x00", "a", "a\x00b", "\x00"):
        got = [i.key.sk for i in store.query(T, "P", sk_prefix=prefix).items]
        assert got == [i.key.sk for i in memory.query(T, "P", sk_prefix=prefix).items]
    assert [i.key.sk for i in store.query(T, "P", sk_prefix="a\x00").items] == ["a\x00", "a\x00b"]


def test_keys_with_surrogates_behave_like_the_memory_store(store: SqliteStore) -> None:
    memory = MemoryStore()
    key = Key("RUN#1", "S\udc00")
    root = Key("ORG", "S\udc00")
    for s in (store, memory):
        assert s.get(T, key) is None
        s.delete(T, key)
        assert s.get(PLATFORM, root) is None
        assert s.query(T, "RUN#1", sk_prefix="\ud800").items == ()
        assert s.query(T, "RUN#1", limit=2**63 - 1).items == ()
    store.put(T, Key("RUN#1", "x"), {"n": 1})
    memory.put(T, Key("RUN#1", "x"), {"n": 1})
    assert (
        store.query(T, "RUN#1", limit=2**63 - 1).items
        == memory.query(T, "RUN#1", limit=2**63 - 1).items
    )


# --- a killed process --------------------------------------------------------------------------

_WRITER = textwrap.dedent(
    """
    import os, signal, sys
    from sto.store.ports import Key, Put, TeamScope
    from sto.store.sqlite import SqliteStore

    class KillOnSecondInsert:
        def __init__(self, conn):
            self._conn, self._inserts = conn, 0
        def execute(self, sql, *args):
            if sql.lstrip().startswith("INSERT"):
                self._inserts += 1
                if self._inserts == 2:  # one write is in the open transaction, not committed
                    os.kill(os.getpid(), signal.SIGKILL)
            return self._conn.execute(sql, *args)
        def __getattr__(self, name):
            return getattr(self._conn, name)

    store = SqliteStore(sys.argv[1])
    team = TeamScope("team-a")
    store.put(team, Key("RUN#1", "META"), {"status": "waiting"})
    store.put(team, Key("RUN#1", "GATE#g#1"), {"status": "open"})
    print("committed", flush=True)
    store._conn = KillOnSecondInsert(store._conn)
    store.transact(team, [
        Put(Key("RUN#1", "META"), {"status": "torn"}),
        Put(Key("RUN#1", "GATE#g#1"), {"status": "torn"}),
    ])
    print("unreachable", flush=True)
    """
)


def test_a_killed_process_keeps_committed_state_and_drops_the_open_transaction(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sto.db"
    proc = subprocess.Popen(
        [sys.executable, "-c", _WRITER, str(path)], stdout=subprocess.PIPE, text=True
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "committed"
        assert proc.wait(timeout=30) == -9  # SIGKILL mid-transact: no close(), no atexit
        assert proc.stdout.read() == ""  # it never got past the kill
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()

    store = SqliteStore(path)  # a restart
    try:
        meta = store.get(T, META)
        gate = store.get(T, GATE)
        assert meta is not None
        assert gate is not None
        assert (meta.data, meta.version) == ({"status": "waiting"}, 1)  # not half-applied
        assert (gate.data, gate.version) == ({"status": "open"}, 1)  # a waiting gate stays waiting
        store.put(T, META, {"status": "next"}, when=VersionIs(1))  # the file is writable again
    finally:
        store.close()
