"""In-memory store (D1-01): the reference implementation of the port's semantics.

Thread-safe: one lock makes each transaction atomic. Data is deep-copied in and out, so callers
never share state with the store (a store must behave like a remote database).
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from .ports import (
    Absent,
    Check,
    Condition,
    ConditionFailedError,
    Delete,
    Exists,
    FieldEquals,
    Item,
    Key,
    Op,
    Put,
    TeamScope,
    VersionIs,
    check_query_args,
    require_scope,
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
        self._teams: dict[str, dict[Key, Item]] = {}

    def get(self, scope: TeamScope, key: Key) -> Item | None:
        team = require_scope(scope).team
        with self._lock:
            return self._copy(self._teams.get(team, {}).get(key))

    def query(
        self, scope: TeamScope, pk: str, *, sk_prefix: str = "", limit: int | None = None
    ) -> tuple[Item, ...]:
        team = require_scope(scope).team
        check_query_args(limit)
        with self._lock:
            items = sorted(
                (
                    i
                    for k, i in self._teams.get(team, {}).items()
                    if k.pk == pk and k.sk.startswith(sk_prefix)
                ),
                key=lambda i: i.key.sk,
            )
            if limit is not None:
                items = items[:limit]
            return tuple(c for i in items if (c := self._copy(i)) is not None)

    def transact(self, scope: TeamScope, ops: Sequence[Op]) -> None:
        team = require_scope(scope).team
        ops = tuple(ops)
        validate_ops(ops)
        with self._lock:
            items = self._teams.setdefault(team, {})
            failed = [i for i, op in enumerate(ops) if not _holds(op.when, items.get(op.key))]
            if failed:
                raise ConditionFailedError(failed)
            for op in ops:  # all conditions held: nothing below can fail
                match op:
                    case Put(key=k, data=d):
                        old = items.get(k)
                        items[k] = Item(k, copy.deepcopy(d), 1 if old is None else old.version + 1)
                    case Delete(key=k):
                        items.pop(k, None)
                    case Check():
                        pass

    def put(
        self,
        scope: TeamScope,
        key: Key,
        data: Mapping[str, Any],
        *,
        when: Condition | None = None,
    ) -> None:
        self.transact(scope, [Put(key, dict(data), when)])

    def delete(self, scope: TeamScope, key: Key, *, when: Condition | None = None) -> None:
        self.transact(scope, [Delete(key, when)])

    @staticmethod
    def _copy(item: Item | None) -> Item | None:
        return None if item is None else Item(item.key, copy.deepcopy(item.data), item.version)
