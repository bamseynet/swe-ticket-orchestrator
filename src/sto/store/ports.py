"""Store port (D1-01): conditional writes and multi-item transactions, always inside a team.

The semantics here are what DynamoDB must match later (PLAN 11): ``TransactWriteItems`` with
conditions on the version counter or a status field. One contract suite
(``tests/store/store_contract.py``) proves them on every store.

* Items are plain-JSON dicts, normally ``to_wire(record)`` of a domain model; ``from_wire``
  rebuilds the record. A DynamoDB store normalizes its own key attributes and numbers.
* Every item has a ``version``: 1 on creation, +1 on each write. ``VersionIs`` turns it into
  optimistic locking.
* **Every function takes a ``TeamScope`` as its first argument,** and a store addresses items
  only inside that team, so no query can be written without one and none can cross teams.
* A transaction is all or nothing. Any failed condition raises ``ConditionFailedError`` and
  nothing is applied.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from sto.domain.errors import PermanentError, TransientError

MAX_TRANSACTION_OPS = 100  # DynamoDB's TransactWriteItems limit


class ConditionFailedError(PermanentError):
    """A condition did not hold, so the whole transaction was aborted. ``failed`` lists the
    indexes of the operations whose conditions failed. Callers re-read and decide whether to
    retry (a lost version race) or report (a gate that is already closed)."""

    def __init__(self, failed: Sequence[int]) -> None:
        self.failed = tuple(failed)
        super().__init__(f"condition failed for operation(s) {list(self.failed)}")


class TransactionConflictError(TransientError):
    """The backend could not serialize concurrent transactions (DynamoDB
    ``TransactionCanceled`` for a conflict, not for a failed condition). Retry with backoff.
    The in-memory and SQLite stores never raise it; a DynamoDB store does."""


@dataclass(frozen=True)
class TeamScope:
    """The team a call acts for. Built by auth middleware from a verified identity."""

    team: str

    def __post_init__(self) -> None:
        if not isinstance(self.team, str):
            raise TypeError(f"team must be a str, not {type(self.team).__name__}")
        if not self.team.strip():
            raise ValueError("team must not be blank")


def require_scope(scope: object) -> TeamScope:
    """Stores call this first, so a missing or wrong scope fails before any data is touched."""
    if not isinstance(scope, TeamScope):
        raise TypeError(f"a TeamScope is required, not {type(scope).__name__}")
    return scope


@dataclass(frozen=True, order=True)
class Key:
    """Partition key and sort key within a team (PLAN 11, e.g. ``RUN#r`` / ``GATE#g#1``)."""

    pk: str
    sk: str

    def __post_init__(self) -> None:
        for label, part in (("pk", self.pk), ("sk", self.sk)):
            if not isinstance(part, str):
                raise TypeError(f"key {label} must be a str, not {type(part).__name__}")
            if not part:
                raise ValueError(f"key {label} must not be empty")


@dataclass(frozen=True)
class Item:
    key: Key
    data: dict[str, Any]
    version: int


# --- conditions -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Absent:
    """The item does not exist (a conditional create)."""


@dataclass(frozen=True)
class Exists:
    """The item exists."""


@dataclass(frozen=True)
class VersionIs:
    """The item exists at exactly this version (optimistic locking)."""

    version: int

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be an int of at least 1")


@dataclass(frozen=True)
class FieldEquals:
    """The item exists and its top-level ``field`` equals ``value`` (e.g. a gate's status)."""

    field: str
    value: str | int | bool | None

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field:
            raise ValueError("field must be a non-empty str")
        if not (self.value is None or isinstance(self.value, str | int | bool)):
            raise TypeError("value must be a str, int, bool or None")


Condition = Absent | Exists | VersionIs | FieldEquals


def _check_condition(condition: object, *, required: bool) -> None:
    if condition is None and not required:
        return
    if not isinstance(condition, Absent | Exists | VersionIs | FieldEquals):
        raise TypeError(f"not a condition: {condition!r}")


# --- operations -------------------------------------------------------------------------------


def _check_json_object(data: object) -> None:
    if not isinstance(data, dict):
        raise TypeError(f"data must be a JSON object (dict), not {type(data).__name__}")
    try:
        json.dumps(data, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"data must be plain JSON: {exc}") from exc
    if any(not isinstance(k, str) for k in data):
        raise TypeError("data must be plain JSON: object keys must be strings")


@dataclass(frozen=True)
class Put:
    """Create or replace an item. Bumps its version."""

    key: Key
    data: dict[str, Any]
    when: Condition | None = None

    def __post_init__(self) -> None:
        _check_json_object(self.data)
        _check_condition(self.when, required=False)


@dataclass(frozen=True)
class Delete:
    """Remove an item. Deleting a missing item without a condition is a no-op."""

    key: Key
    when: Condition | None = None

    def __post_init__(self) -> None:
        _check_condition(self.when, required=False)


@dataclass(frozen=True)
class Check:
    """Assert a condition on an item without writing it (DynamoDB ``ConditionCheck``)."""

    key: Key
    when: Condition

    def __post_init__(self) -> None:
        _check_condition(self.when, required=True)


Op = Put | Delete | Check


def validate_ops(ops: Sequence[Op]) -> None:
    """Shape rules every store shares: DynamoDB refuses these, so the fast stores must too."""
    if not ops:
        raise ValueError("a transaction needs at least one operation")
    if len(ops) > MAX_TRANSACTION_OPS:
        raise ValueError(f"a transaction takes at most {MAX_TRANSACTION_OPS} operations")
    seen: set[Key] = set()
    for op in ops:
        if not isinstance(op, Put | Delete | Check):
            raise TypeError(f"not an operation: {op!r}")
        if op.key in seen:
            raise ValueError(f"item {op.key} appears more than once in a transaction")
        seen.add(op.key)


def check_query_args(limit: int | None) -> None:
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("limit must be a positive int")


# --- the port ---------------------------------------------------------------------------------


@runtime_checkable
class Store(Protocol):
    """Synchronous repository port. Reads are strongly consistent."""

    def get(self, scope: TeamScope, key: Key) -> Item | None: ...

    def query(
        self, scope: TeamScope, pk: str, *, sk_prefix: str = "", limit: int | None = None
    ) -> tuple[Item, ...]:
        """Items of one partition in ascending sort-key order. ``sk_prefix`` is literal."""
        ...

    def transact(self, scope: TeamScope, ops: Sequence[Op]) -> None:
        """Apply all ``ops`` or none. Raises ``ConditionFailedError`` if any condition fails."""
        ...

    def put(
        self,
        scope: TeamScope,
        key: Key,
        data: Mapping[str, Any],
        *,
        when: Condition | None = None,
    ) -> None: ...

    def delete(self, scope: TeamScope, key: Key, *, when: Condition | None = None) -> None: ...
