"""SQLite store (D1-12): the port on a local file, so ``make dev`` needs no Docker and a waiting
gate survives a process restart.

**Local, single-writer use only.** One process owns the file at a time. Several connections
(even several processes) stay *correct*, because each transaction takes SQLite's write lock up
front (``BEGIN IMMEDIATE``), but writers queue behind one another, so this is not a shared or
production store: use DynamoDB for that (D3-09). Never put the file on a network filesystem.

Durability: WAL with ``synchronous=FULL``, so a committed transaction survives ``kill -9`` (and
power loss); an uncommitted one is rolled back on the next open.

Semantics match ``MemoryStore`` and are proved by the same contract suite. Items are stored as
canonical JSON text; the version counter is a column.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

# One definition of the condition rules, shared with MemoryStore (private to the store package).
from .memory import _holds
from .ports import (
    MAIN,
    Addr,
    Condition,
    ConditionFailedError,
    Delete,
    Item,
    Key,
    Op,
    Page,
    Prepared,
    Put,
    Scope,
    TransactionConflictError,
    check_query_args,
    decode_cursor,
    encode_cursor,
    require_key,
    require_scope,
    resolve,
    validate_ops,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    partition TEXT NOT NULL,
    tbl       TEXT NOT NULL,
    pk        BLOB NOT NULL,
    sk        BLOB NOT NULL,
    data      TEXT NOT NULL,
    version   INTEGER NOT NULL,
    PRIMARY KEY (partition, tbl, pk, sk)
) WITHOUT ROWID
"""

_BUSY_TIMEOUT_S = 30.0


_SQLITE_BUSY, _SQLITE_LOCKED = 5, 6


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        return bool(code & 0xFF in (_SQLITE_BUSY, _SQLITE_LOCKED))
    return "locked" in str(exc) or "busy" in str(exc)


def _b(text: str) -> bytes:
    # Keys are stored as UTF-8 bytes (surrogates allowed) rather than TEXT: SQLite TEXT cannot
    # hold a lone surrogate, and stops at NUL in substr(). Byte order equals code point order.
    return text.encode("utf-8", "surrogatepass")


def _s(blob: bytes) -> str:
    return blob.decode("utf-8", "surrogatepass")


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, separators=(",", ":"))  # ASCII only: safe for any string content


class SqliteStore:
    def __init__(self, path: str | Path, *, timeout: float = _BUSY_TIMEOUT_S) -> None:
        self._lock = threading.RLock()
        self._closed = False
        # isolation_level=None: we issue BEGIN/COMMIT ourselves. One connection guarded by a lock
        # serves all threads; the file lock covers other connections and processes.
        self._conn = sqlite3.connect(
            str(path), timeout=timeout, isolation_level=None, check_same_thread=False
        )
        try:
            self._init(timeout)
        except BaseException:
            self._conn.close()
            raise

    def _init(self, timeout: float) -> None:
        # Switching to WAL on a fresh file needs a lock that the busy timeout does not always
        # cover when several processes open it together, so retry until the deadline.
        deadline = time.monotonic() + timeout
        while True:
            try:
                mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                self._conn.execute("PRAGMA synchronous=FULL")
                if str(mode).lower() != "wal":
                    raise RuntimeError(f"cannot use WAL journaling here (got {mode!r})")
                self._conn.execute(_SCHEMA)
                return
            except sqlite3.OperationalError as exc:
                if not _is_busy(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._conn.close()

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("store is closed")

    def _read(self, addr: Addr) -> Item | None:
        row = self._conn.execute(
            "SELECT data, version FROM items WHERE partition=? AND tbl=? AND pk=? AND sk=?",
            (addr.partition, addr.table, _b(addr.pk), _b(addr.sk)),
        ).fetchone()
        return (
            None if row is None else Item(Key(addr.pk or "-", addr.sk), json.loads(row[0]), row[1])
        )

    def get(self, scope: Scope, key: Key) -> Item | None:
        addr = resolve(require_scope(scope), require_key(key))
        with self._lock:
            self._check_open()
            found = self._read(addr)
        # Rebuild with the caller's key (it may be the TEAM_ROOT pseudo pk, stored as "").
        return None if found is None else Item(key, found.data, found.version)

    def query(
        self,
        scope: Scope,
        pk: str,
        *,
        table: str = MAIN,
        sk_prefix: str = "",
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page:
        require_scope(scope)
        check_query_args(pk, limit, table, sk_prefix)
        root = resolve(scope, Key(pk, "-", table))
        after = (
            None if cursor is None else decode_cursor(cursor, root.partition, table, pk, sk_prefix)
        )
        sql = "SELECT sk, data, version FROM items WHERE partition=? AND tbl=? AND pk=?"
        args: list[Any] = [root.partition, table, _b(root.pk)]
        if sk_prefix:  # a byte-wise substr, not LIKE: the prefix is literal, NUL included
            prefix = _b(sk_prefix)
            sql += " AND substr(sk, 1, ?) = ?"
            args += [len(prefix), prefix]
        if after is not None:
            sql += " AND sk > ?"
            args.append(_b(after))
        sql += " ORDER BY sk"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(min(limit, 2**62) + 1)  # SQLite integers are 64-bit
        with self._lock:
            self._check_open()
            rows = self._conn.execute(sql, args).fetchall()
        more = limit is not None and len(rows) > limit
        if limit is not None:
            rows = rows[:limit]
        items = tuple(Item(Key(pk, _s(sk), table), json.loads(d), v) for sk, d, v in rows)
        return Page(
            items,
            encode_cursor(root.partition, table, pk, sk_prefix, items[-1].key.sk) if more else None,
        )

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        require_scope(scope)
        prepared = validate_ops(scope, tuple(ops))
        with self._lock:
            self._check_open()
            try:
                self._conn.execute("BEGIN IMMEDIATE")  # take the write lock before reading
            except sqlite3.OperationalError as exc:
                if _is_busy(exc):
                    raise TransactionConflictError(f"store file is busy: {exc}") from exc
                raise
            try:
                self._apply(prepared)
                self._conn.execute("COMMIT")
            except BaseException:
                # SQLite may already have rolled back by itself (full disk); only undo what is
                # still open, and never let a rollback error hide the real one.
                if self._conn.in_transaction:
                    with contextlib.suppress(sqlite3.Error):
                        self._conn.execute("ROLLBACK")
                raise

    def _apply(self, prepared: tuple[Prepared, ...]) -> None:
        current = {p.addr: self._read(p.addr) for p in prepared}
        failed = [i for i, p in enumerate(prepared) if not _holds(p.op.when, current[p.addr])]
        if failed:
            raise ConditionFailedError(failed)
        for p in prepared:
            a = p.addr
            match p:
                case Prepared(op=Put(), data=d) if d is not None:
                    old = current[a]
                    self._conn.execute(
                        "INSERT OR REPLACE INTO items (partition, tbl, pk, sk, data, version)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            a.partition,
                            a.table,
                            _b(a.pk),
                            _b(a.sk),
                            _json(d),
                            1 if old is None else old.version + 1,
                        ),
                    )
                case Prepared(op=Delete()):
                    self._conn.execute(
                        "DELETE FROM items WHERE partition=? AND tbl=? AND pk=? AND sk=?",
                        (a.partition, a.table, _b(a.pk), _b(a.sk)),
                    )

    def put(
        self,
        scope: Scope,
        key: Key,
        data: Mapping[str, Any],
        *,
        when: Condition | None = None,
    ) -> None:
        self.transact(scope, [Put(key, dict(data), when)])

    def delete(self, scope: Scope, key: Key, *, when: Condition | None = None) -> None:
        self.transact(scope, [Delete(key, when)])
