"""Store port (D1-01): conditional writes and multi-item transactions, always inside a scope.

The semantics here are what DynamoDB must match later (PLAN 11, D3-09): ``TransactWriteItems``
with conditions on the version counter or a status field. One contract suite
(``tests/store/store_contract.py``) proves them on every store.

* Items are plain-JSON dicts, normally ``to_wire(record)`` of a domain model; ``from_wire``
  rebuilds the record. Data is canonicalized on construction (see ``canonical_data``), so every
  store holds and compares exactly the same values.
* ``Item.version`` is the *store's* write counter: 1 on creation, +1 on each write, and it
  restarts at 1 after a delete (so a stale ``VersionIs(1)`` matches a deleted-and-recreated
  item: the ABA case; use ``Absent`` to create, never delete-then-recreate under a version
  guard). It is separate from ``Run.version`` and other counters inside the data.
* **Every function takes a scope as its first argument.** Team data needs a ``TeamScope``; the
  few partitions that belong to no team (ORG, REPO#r, MANIFEST#digest, HOOK#surface#id) need the
  explicit ``PlatformScope``, so reaching one is visible and grep-able at the call site. A store
  addresses items only inside the scope's partition, so no call can cross teams.
* Items live in a ``table`` (``MAIN`` or ``AUDIT``; ADR-0017), so a decision, its audit event
  and the outbox entry can commit in one transaction (PLAN 4.3 rule 6). The audit table is
  append-only: only ``Put`` with ``Absent()`` (and ``Check``) are allowed on it.
* A transaction is all or nothing. Any failed condition raises ``ConditionFailedError`` and
  nothing is applied.
"""

from __future__ import annotations

import base64
import binascii
import json
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NamedTuple, Protocol, runtime_checkable

from sto.domain.errors import PermanentError, TransientError

# DynamoDB limits. Serialized JSON size only approximates DynamoDB's own item accounting
# (attribute names, number encodings), so a real store may still refuse a borderline item.
MAX_TRANSACTION_OPS = 100
MAX_ITEM_BYTES = 400 * 1024
MAX_TRANSACTION_BYTES = 4 * 1024 * 1024
MAX_PK_BYTES = 2048
MAX_SK_BYTES = 1024
_MAX_NUMBER = 10**38
# DynamoDB allows 32 levels of nesting.
_MAX_DEPTH = 32
# DynamoDB's smallest non-zero magnitude (1E-130). Memory and SQLite could hold less, so every
# store refuses it: a run that works locally must not fail in production.
_MIN_NUMBER = 1e-130

# The team's own bare partition (PLAN 11: Team META and switches, CONFIG, WF#, BUD#, SLOT#, CONN#,
# IMAGE# live under exactly ``TEAM#<t>``). ``Key(TEAM_ROOT, "META")`` addresses it, so every caller
# reaches the same item. The pk string is reserved: it never names an ordinary partition.
TEAM_ROOT = "TEAM"

MAIN = "main"
AUDIT = "audit"
TABLES = (MAIN, AUDIT)


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
    A DynamoDB store raises it, and so does the SQLite store when its busy wait expires. The
    in-memory store never does."""


class TransactionOutcomeUnknownError(TransactionConflictError):
    """A write may or may not have been applied: the request was sent but the answer was lost
    (a read timeout, a closed connection, a 5xx). It is a ``TransactionConflictError``, so
    existing retry loops still work, but a caller that cares must re-read and reconcile before it
    retries: a retry of a version- or status-guarded write can lose to its own earlier success
    and report a lost condition. ``TransactionConflictError`` itself means nothing was applied by
    that call (a conflict or throttling); a *read* that fails to connect raises it too, as a
    read has nothing to reconcile. Reads never raise this subclass."""


# --- scopes -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class TeamScope:
    """The team a call acts for. Built by auth middleware from a verified identity."""

    team: str

    def __post_init__(self) -> None:
        if not isinstance(self.team, str):
            raise TypeError(f"team must be a str, not {type(self.team).__name__}")
        if not self.team.strip():
            raise ValueError("team must not be blank")
        if self.team != self.team.strip():
            raise ValueError("team must not have surrounding whitespace")
        if any(unicodedata.category(c).startswith("C") for c in self.team):
            raise ValueError("team must not contain control characters")
        if "#" in self.team:
            # PLAN 11 keys are TEAM#t#pk: a '#' in t would let team "a" with pk "b#x" read
            # the items of team "a#b".
            raise ValueError("team must not contain '#'")


@dataclass(frozen=True)
class PlatformScope:
    """Partitions that belong to no team: ORG, USER#u, MANIFEST#digest, REPO#r and HOOK#...
    (``PLATFORM_PREFIXES``). Using it is a deliberate, visible choice, and a key outside that
    list is refused, so team data cannot go through it. Restricting who may write these from a
    team's transaction is the auth layer's job (D3)."""


PLATFORM = PlatformScope()
PLATFORM_PREFIXES = ("ORG", "USER#", "MANIFEST#", "REPO#", "HOOK#")
Scope = TeamScope | PlatformScope


def require_scope(scope: object) -> Scope:
    """Stores call this first, so a missing or wrong scope fails before any data is touched."""
    if not isinstance(scope, TeamScope | PlatformScope):
        raise TypeError(f"a TeamScope or PlatformScope is required, not {type(scope).__name__}")
    return scope


# --- keys -------------------------------------------------------------------------------------


def _check_part(label: str, part: object, max_bytes: int) -> None:
    if not isinstance(part, str):
        raise TypeError(f"key {label} must be a str, not {type(part).__name__}")
    if not part:
        raise ValueError(f"key {label} must not be empty")
    if len(part.encode("utf-8", "surrogatepass")) > max_bytes:
        raise ValueError(f"key {label} is longer than {max_bytes} bytes")


@dataclass(frozen=True, order=True)
class Key:
    """Partition key and sort key within a scope and table (PLAN 11, e.g. ``RUN#r`` / ``GATE#g#1``).

    The team prefix is added by the store, and is not counted in the byte limits here.
    """

    pk: str
    sk: str
    table: str = MAIN

    def __post_init__(self) -> None:
        _check_part("pk", self.pk, MAX_PK_BYTES)
        _check_part("sk", self.sk, MAX_SK_BYTES)
        if self.table not in TABLES:
            raise ValueError(f"unknown table {self.table!r}; use one of {TABLES}")


@dataclass(frozen=True)
class Item:
    key: Key
    data: dict[str, Any]
    version: int


@dataclass(frozen=True)
class Page:
    """One page of a query. ``cursor`` is opaque; pass it back to continue. ``None`` means no
    more. A store may return a cursor on the last page, followed by an empty page."""

    items: tuple[Item, ...]
    cursor: str | None = None


@dataclass(frozen=True)
class Addr:
    """A fully resolved item address: what a store actually keys on. ``partition`` is
    ``TEAM#<team>`` or ``PLATFORM``. A DynamoDB store writes a team's pk as ``TEAM#<team>#<pk>``,
    or as exactly ``TEAM#<team>`` when ``pk`` is empty (the ``TEAM_ROOT`` partition)."""

    partition: str
    table: str
    pk: str
    sk: str


def resolve(scope: Scope, key: Key, override: PlatformScope | None = None) -> Addr:
    """Address of ``key`` for a call made with ``scope``; ``override`` redirects one operation
    of a transaction to the platform partition."""
    if override is not None:
        scope = require_scope(override)
    if isinstance(scope, TeamScope):
        # A shared table stores the pk as TEAM#<team>#<pk>, so the prefix counts against the limit.
        if len(f"TEAM#{scope.team}#".encode()) + len(key.pk.encode()) > MAX_PK_BYTES:
            raise ValueError(
                f"key pk is longer than {MAX_PK_BYTES} bytes once prefixed with the team"
            )
        return Addr(f"TEAM#{scope.team}", key.table, "" if key.pk == TEAM_ROOT else key.pk, key.sk)
    if not any(
        key.pk == p or key.pk.startswith(p if p.endswith("#") else p + "#")
        for p in PLATFORM_PREFIXES
    ):
        raise ValueError(
            f"platform key must start with one of {PLATFORM_PREFIXES}; team data needs a TeamScope"
        )
    return Addr("PLATFORM", key.table, key.pk, key.sk)


def require_key(key: object) -> Key:
    if not isinstance(key, Key):
        raise TypeError(f"a Key is required, not {type(key).__name__}")
    return key


def encode_cursor(partition: str, table: str, pk: str, sk_prefix: str, last_sk: str) -> str:
    """Opaque cursor bound to the query that made it (partition, table, pk, prefix)."""
    raw = json.dumps([partition, table, pk, sk_prefix, last_sk], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: object, partition: str, table: str, pk: str, sk_prefix: str) -> str:
    """The sort key to continue after. Refuses anything malformed, and any cursor made by a
    different query or team, instead of silently restarting or skipping."""
    try:
        if not isinstance(cursor, str):
            raise TypeError
        raw = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
        parts = json.loads(raw.decode("utf-8"))
        ok = isinstance(parts, list) and len(parts) == 5 and all(isinstance(p, str) for p in parts)
    except (TypeError, ValueError, binascii.Error, RecursionError):  # JSON, Unicode, deep nesting
        raise ValueError("invalid cursor") from None
    if not ok:
        raise ValueError("invalid cursor")
    if parts[:4] != [partition, table, pk, sk_prefix]:
        raise ValueError("cursor belongs to a different query")
    return str(parts[4])


# --- data -------------------------------------------------------------------------------------


def _validate(value: object, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:  # also stops a self-referencing dict before it hits RecursionError
        raise TypeError("data must be plain JSON: nested too deeply (or cyclic)")
    if value is None or isinstance(value, str | bool):
        return
    if isinstance(value, int):
        if abs(value) >= _MAX_NUMBER:
            raise TypeError("data must be plain JSON: number out of range")
    elif isinstance(value, float):
        if value != value or abs(value) >= _MAX_NUMBER:  # NaN, inf, out of range
            raise TypeError("data must be plain JSON: number out of range")
        if value != 0 and abs(value) < _MIN_NUMBER:
            raise TypeError("data must be plain JSON: number out of range (below 1e-130)")
    elif isinstance(value, list | tuple):
        for v in value:
            _validate(v, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("data must be plain JSON: object keys must be strings")
            if not k:
                raise TypeError("data must be plain JSON: object keys must not be empty")
            _validate(v, depth + 1)
    else:
        raise TypeError(f"data must be plain JSON, not {type(value).__name__}")


def _numbers(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)  # DynamoDB has one number type: 1.0 and 1 are the same value
    if isinstance(value, list):
        return [_numbers(v) for v in value]
    if isinstance(value, dict):
        return {k: _numbers(v) for k, v in value.items()}
    return value


def canonical_data(data: object) -> dict[str, Any]:
    """The one stored form of ``data``: a fresh dict of plain JSON. Tuples become lists, str and
    int subclasses (enums) become their plain value, integral floats become ints. Anything else
    raises ``TypeError``. Stores compare conditions against this form."""
    if not isinstance(data, dict):
        raise TypeError(f"data must be a JSON object (dict), not {type(data).__name__}")
    _validate(data)
    result = _numbers(json.loads(json.dumps(data, allow_nan=False)))
    assert isinstance(result, dict)
    return result


def _item_size(key: Key, data: dict[str, Any]) -> int:
    size = len(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    size += len(key.pk.encode()) + len(key.sk.encode())
    if size > MAX_ITEM_BYTES:
        raise ValueError(f"item is {size} bytes; the limit is {MAX_ITEM_BYTES}")
    return size


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
    """The item exists and its top-level ``field`` equals ``value`` (e.g. a gate's status).

    ``value`` is normalized like stored data, so a ``StrEnum`` matches its wire string and
    ``1.0`` matches ``1``. Types are otherwise strict: ``1`` never equals ``True``.
    """

    field: str
    value: str | int | bool | None

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field:
            raise ValueError("field must be a non-empty str")
        value: Any = self.value.value if isinstance(self.value, Enum) else self.value
        if not (value is None or isinstance(value, str | int | float)):  # bool is an int
            raise TypeError("value must be a str, int, bool or None")
        _validate(value)
        object.__setattr__(self, "value", _numbers(json.loads(json.dumps(value))))


Condition = Absent | Exists | VersionIs | FieldEquals


def _check_condition(condition: object, *, required: bool) -> None:
    if condition is None and not required:
        return
    if not isinstance(condition, Absent | Exists | VersionIs | FieldEquals):
        raise TypeError(f"not a condition: {condition!r}")


# --- operations -------------------------------------------------------------------------------
# ``scope`` on an operation redirects that one operation to the platform partition, so a
# transaction can mix a team's items with ORG or REPO items and audit-table items.


@dataclass(frozen=True)
class Put:
    """Create or replace an item. Bumps its version."""

    key: Key
    data: dict[str, Any]
    when: Condition | None = None
    scope: PlatformScope | None = None
    size: int = field(init=False, default=0, compare=False, repr=False)

    def __post_init__(self) -> None:
        require_key(self.key)
        _check_condition(self.when, required=False)
        _check_op_scope(self.scope)
        data = canonical_data(self.data)  # a private copy: later caller mutation cannot reach it
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "size", _item_size(self.key, data))


@dataclass(frozen=True)
class Delete:
    """Remove an item. Deleting a missing item without a condition is a no-op."""

    key: Key
    when: Condition | None = None
    scope: PlatformScope | None = None

    def __post_init__(self) -> None:
        require_key(self.key)
        _check_condition(self.when, required=False)
        _check_op_scope(self.scope)


@dataclass(frozen=True)
class Check:
    """Assert a condition on an item without writing it (DynamoDB ``ConditionCheck``)."""

    key: Key
    when: Condition
    scope: PlatformScope | None = None

    def __post_init__(self) -> None:
        require_key(self.key)
        _check_condition(self.when, required=True)
        _check_op_scope(self.scope)


Op = Put | Delete | Check


def _check_op_scope(scope: object) -> None:
    if scope is not None and not isinstance(scope, PlatformScope):
        raise TypeError("an operation's scope may only be a PlatformScope")


class Prepared(NamedTuple):
    """One validated operation: its resolved address, and for a ``Put`` a fresh canonical copy of
    the data taken now (so mutation of ``op.data`` after construction cannot slip through)."""

    op: Op
    addr: Addr
    data: dict[str, Any] | None


def validate_ops(scope: Scope, ops: Sequence[Op]) -> tuple[Prepared, ...]:
    """Shape rules every store shares (DynamoDB refuses these, so the fast stores must too).
    Raises before anything is applied."""
    if not ops:
        raise ValueError("a transaction needs at least one operation")
    if len(ops) > MAX_TRANSACTION_OPS:
        raise ValueError(f"a transaction takes at most {MAX_TRANSACTION_OPS} operations")
    seen: set[Addr] = set()
    total = 0
    prepared: list[Prepared] = []
    for op in ops:
        if not isinstance(op, Put | Delete | Check):
            raise TypeError(f"not an operation: {op!r}")
        addr = resolve(scope, op.key, op.scope)
        if addr in seen:
            raise ValueError(f"item {op.key} appears more than once in a transaction")
        seen.add(addr)
        if op.key.table == AUDIT and (
            isinstance(op, Delete) or (isinstance(op, Put) and op.when != Absent())
        ):
            raise ValueError("the audit table is append-only: only Put with Absent() is allowed")
        data = None
        if isinstance(op, Put):
            data = canonical_data(op.data)
            total += _item_size(op.key, data)
        prepared.append(Prepared(op, addr, data))
    if total > MAX_TRANSACTION_BYTES:
        raise ValueError(f"transaction is {total} bytes; the limit is {MAX_TRANSACTION_BYTES}")
    return tuple(prepared)


def check_query_args(pk: object, limit: int | None, table: str, sk_prefix: object) -> None:
    _check_part("pk", pk, MAX_PK_BYTES)
    if not isinstance(sk_prefix, str):
        raise TypeError(f"sk_prefix must be a str, not {type(sk_prefix).__name__}")
    if len(sk_prefix.encode("utf-8", "surrogatepass")) > MAX_SK_BYTES:
        raise ValueError(f"sk_prefix is longer than {MAX_SK_BYTES} bytes")
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("limit must be a positive int")
    if table not in TABLES:
        raise ValueError(f"unknown table {table!r}; use one of {TABLES}")


# --- the port ---------------------------------------------------------------------------------


@runtime_checkable
class Store(Protocol):
    """Synchronous repository port. Reads are strongly consistent."""

    def get(self, scope: Scope, key: Key) -> Item | None: ...

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
        """Items of one partition in ascending sort-key order. ``sk_prefix`` is literal.
        Without ``limit`` everything is returned; with it, at most ``limit`` items and a
        ``cursor`` to continue. Paging by cursor neither skips nor repeats items that existed
        throughout."""
        ...

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        """Apply all ``ops`` or none. Raises ``ConditionFailedError`` if any condition fails."""
        ...

    def put(
        self,
        scope: Scope,
        key: Key,
        data: Mapping[str, Any],
        *,
        when: Condition | None = None,
    ) -> None: ...

    def delete(self, scope: Scope, key: Key, *, when: Condition | None = None) -> None: ...
