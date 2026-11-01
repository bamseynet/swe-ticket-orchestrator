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

import json
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .ports import (
    MAIN,
    Absent,
    Addr,
    Condition,
    ConditionFailedError,
    Delete,
    Exists,
    FieldEquals,
    Item,
    Key,
    Op,
    Page,
    Prepared,
    Put,
    Scope,
    VersionIs,
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
    pk        TEXT NOT NULL,
    sk        TEXT NOT NULL,
    data      TEXT NOT NULL,
    version   INTEGER NOT NULL,
    PRIMARY KEY (partition, tbl, pk, sk)
) WITHOUT ROWID
"""

_BUSY_TIMEOUT_S = 30.0


def _holds(condition: Condition | None, current: Item | None) -> bool:
    match condition:
        case None:
            return True
        case Absent():
            return current is None
        case Exists():
            return current is not None
        case VersionIs(version=v):
            return current is not None and current.version == v
        case FieldEquals(field=f, value=v):
            if current is None or f not in current.data:
                return False
            actual = current.data[f]
            return type(actual) is type(v) and actual == v  # 1 is not True, as in DynamoDB
    raise TypeError(f"unknown condition {condition!r}")


def _row_to_item(sk_key: Key, data: str, version: int) -> Item:
    return Item(sk_key, json.loads(data), version)


class SqliteStore:
    def __init__(self, path: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        # isolation_level=None: we issue BEGIN/COMMIT ourselves. One connection guarded by a lock
        # serves all threads; the file lock covers other connections and processes.
        self._conn = sqlite3.connect(
            str(path), timeout=_BUSY_TIMEOUT_S, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(_SCHEMA)

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
            (addr.partition, addr.table, addr.pk, addr.sk),
        ).fetchone()
        return None if row is None else _row_to_item(Key(addr.pk or "-", addr.sk), *row)

    def get(self, scope: Scope, key: Key) -> Item | None:
        addr = resolve(require_scope(scope), require_key(key))
        with self._lock:
            self._check_open()
            row = self._read(addr)
        # Rebuild with the caller's key (it may be the TEAM_ROOT pseudo pk, stored as "").
        return None if row is None else Item(key, row.data, row.version)

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
        args: list[Any] = [root.partition, table, root.pk]
        if sk_prefix:  # substr, not LIKE: the prefix is literal
            sql += " AND substr(sk, 1, ?) = ?"
            args += [len(sk_prefix), sk_prefix]
        if after is not None:
            sql += " AND sk > ?"
            args.append(after)
        sql += " ORDER BY sk"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit + 1)
        with self._lock:
            self._check_open()
            rows = self._conn.execute(sql, args).fetchall()
        more = limit is not None and len(rows) > limit
        if limit is not None:
            rows = rows[:limit]
        items = tuple(Item(Key(pk, sk, table), json.loads(data), v) for sk, data, v in rows)
        return Page(
            items,
            encode_cursor(root.partition, table, pk, sk_prefix, items[-1].key.sk) if more else None,
        )

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        require_scope(scope)
        prepared = validate_ops(scope, tuple(ops))
        with self._lock:
            self._check_open()
            self._conn.execute("BEGIN IMMEDIATE")  # take the write lock before reading
            try:
                self._apply(prepared)
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

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
                            a.pk,
                            a.sk,
                            json.dumps(d, separators=(",", ":"), ensure_ascii=False),
                            1 if old is None else old.version + 1,
                        ),
                    )
                case Prepared(op=Delete()):
                    self._conn.execute(
                        "DELETE FROM items WHERE partition=? AND tbl=? AND pk=? AND sk=?",
                        (a.partition, a.table, a.pk, a.sk),
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
