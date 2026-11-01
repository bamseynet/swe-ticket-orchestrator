"""In-memory store (D1-01): the reference implementation of the port's semantics.

Thread-safe: one lock makes each transaction atomic. Data is copied in and out, so callers never
share state with the store (a store must behave like a remote database).
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from .ports import (
    MAIN,
    Absent,
    Addr,
    Check,
    Condition,
    ConditionFailedError,
    Delete,
    Exists,
    FieldEquals,
    Item,
    Key,
    Op,
    Page,
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


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[Addr, Item] = {}

    def get(self, scope: Scope, key: Key) -> Item | None:
        addr = resolve(require_scope(scope), require_key(key))
        with self._lock:
            return self._copy(self._items.get(addr))

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
        check_query_args(pk, limit, table)
        after = None if cursor is None else decode_cursor(cursor)
        partition = resolve(scope, Key(pk, "-", table)).partition
        with self._lock:
            matching = sorted(
                (
                    item
                    for addr, item in self._items.items()
                    if (addr.partition, addr.table, addr.pk) == (partition, table, pk)
                    and addr.sk.startswith(sk_prefix)
                    and (after is None or addr.sk > after)
                ),
                key=lambda i: i.key.sk,
            )
            more = limit is not None and len(matching) > limit
            if limit is not None:
                matching = matching[:limit]
            items = tuple(c for i in matching if (c := self._copy(i)) is not None)
        return Page(items, encode_cursor(items[-1].key.sk) if more else None)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        require_scope(scope)
        ops = tuple(ops)
        addrs = validate_ops(scope, ops)
        with self._lock:
            failed = [
                i
                for i, (op, addr) in enumerate(zip(ops, addrs, strict=True))
                if not _holds(op.when, self._items.get(addr))
            ]
            if failed:
                raise ConditionFailedError(failed)
            # Build every write first and only then apply, so nothing can fail half way.
            writes: dict[Addr, Item | None] = {}
            for op, addr in zip(ops, addrs, strict=True):
                match op:
                    case Put(key=k, data=d):
                        old = self._items.get(addr)
                        writes[addr] = Item(
                            k, copy.deepcopy(d), 1 if old is None else old.version + 1
                        )
                    case Delete():
                        writes[addr] = None
                    case Check():
                        pass
            for addr, new in writes.items():
                if new is None:
                    self._items.pop(addr, None)
                else:
                    self._items[addr] = new

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

    @staticmethod
    def _copy(item: Item | None) -> Item | None:
        return None if item is None else Item(item.key, copy.deepcopy(item.data), item.version)
