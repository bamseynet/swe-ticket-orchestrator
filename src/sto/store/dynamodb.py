"""DynamoDB store (D3-09): the port on two DynamoDB tables (PLAN 11, ADR-0017).

Table design. Both tables (main and audit) have a string hash key ``pk`` and a string range key
``sk``. An item is ``{pk, sk, v, d}``: ``v`` is the store's version counter and ``d`` the
caller's data as one native map (so a condition can read ``d.status`` and no data field can
collide with a key attribute or a reserved word).

Tenancy lives in the key. A team's ``pk`` is ``TEAM#<team>#<pk>`` (exactly ``TEAM#<team>`` for the
``TEAM_ROOT`` partition) and a team name cannot contain ``#``, so no team's keys can be written as
another's. Platform partitions keep their own pk (``ORG``, ``REPO#r``, ...), which no team pk can
equal because team pks always start ``TEAM#``. Every call goes through ``resolve`` first.

Atomicity is ``TransactWriteItems``: a ``Put`` is an ``Update`` that sets ``v = v + 1`` and
replaces ``d`` under the operation's condition, a ``Check`` is a ``ConditionCheck``. Every
expression uses ``ExpressionAttributeNames`` for names and values, so reserved words and odd
characters in data are never parsed.

Errors speak the port's types, on reads as well as writes:

* A lost condition is ``ConditionFailedError`` (``failed`` = the cancelled items whose condition
  failed); a ``DynamoConditionFailedError`` also carries every item's reason.
* Throttling, a transaction conflict, a server error or a dropped connection is
  ``TransactionConflictError``: the one type callers retry with backoff. ``get`` and ``query``
  raise it too. botocore's own retries run first; this is what is left after them.
* ``TransactionCanceledException`` is mapped per item from ``CancellationReasons``, in this order:
  a validation failure (``ValueError``), a lost condition, another permanent reason
  (``DynamoTransactionError``), then retryable ones. When reasons mix, the most definite one wins
  and ``.reasons`` still lists all of them.
* Anything else (a missing table, no permission) is raised unchanged: retrying cannot fix it.

Reads are strongly consistent (``ConsistentRead=True`` on every ``GetItem`` and every ``Query``
page), which the port promises. Queries follow ``LastEvaluatedKey`` (DynamoDB cuts a page at
1 MB) until ``limit`` is met or the partition ends.

Limits the in-memory stores cannot show are checked before anything is sent: 100 operations, one
per item, 4 MB per transaction, 400 KB per item (by DynamoDB's own accounting, not JSON size),
numbers within DynamoDB's range, UTF-8 text, and no empty object keys. The server is still the
authority: its size and validation refusals are mapped to ``ValueError`` too.

``create_tables`` is for tests and local setups; real tables come from the infrastructure stack.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from sto.domain.errors import PermanentError

from .ports import (
    AUDIT,
    MAIN,
    MAX_ITEM_BYTES,
    MAX_TRANSACTION_BYTES,
    MAX_TRANSACTION_OPS,
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
    Prepared,
    Put,
    Scope,
    TransactionConflictError,
    VersionIs,
    check_query_args,
    decode_cursor,
    encode_cursor,
    require_key,
    require_scope,
    resolve,
    validate_ops,
)

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

__all__ = [
    "MAX_TRANSACTION_OPS",
    "CancellationReason",
    "DynamoConditionFailedError",
    "DynamoDbStore",
    "DynamoTransactionError",
    "create_tables",
    "estimate_item_bytes",
]

_PLATFORM = "PLATFORM"
_MAX_QUERY_LIMIT = 2**31 - 1
# DynamoDB numbers: 38 digits, magnitude from 1E-130 to 9.99...E+125. The port already refuses
# magnitudes of 1E+38 and over; nothing here is that large, but tiny floats get through the port.
_MIN_MAGNITUDE = Decimal("1E-130")

_RETRYABLE_CODES = frozenset(
    {
        "ThrottlingException",
        "Throttling",
        "ProvisionedThroughputExceededException",
        "RequestLimitExceeded",
        "InternalServerError",
        "ServiceUnavailable",
        "TransactionConflictException",
        "TransactionInProgressException",
    }
)
_RETRYABLE_REASONS = frozenset(
    {"TransactionConflict", "ThrottlingError", "ProvisionedThroughputExceeded"}
)
_CONNECTION_ERRORS = (
    EndpointConnectionError,
    ConnectTimeoutError,
    ReadTimeoutError,
    ConnectionClosedError,
)

_SER = TypeSerializer()
_DESER = TypeDeserializer()


# --- errors ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class CancellationReason:
    """One entry of ``CancellationReasons``: operation ``index`` (same order as the ops), its
    ``code`` (``None`` when that operation was fine) and DynamoDB's message."""

    index: int
    code: str
    message: str = ""


def _describe(reasons: Sequence[CancellationReason]) -> str:
    return ", ".join(
        f"#{r.index}={r.code}" + (f" ({r.message})" if r.message and r.code != "None" else "")
        for r in reasons
    )


class DynamoConditionFailedError(ConditionFailedError):
    """``ConditionFailedError`` that keeps what DynamoDB said about every operation."""

    def __init__(self, failed: Sequence[int], reasons: Sequence[CancellationReason]) -> None:
        super().__init__(failed)
        self.reasons = tuple(reasons)
        self.args = (f"{self.args[0]}; reasons: {_describe(self.reasons)}",)


class DynamoTransactionError(PermanentError):
    """A cancellation for a reason retrying cannot fix and that is not a lost condition."""

    def __init__(self, reasons: Sequence[CancellationReason]) -> None:
        self.reasons = tuple(reasons)
        super().__init__(f"DynamoDB cancelled the transaction: {_describe(self.reasons)}")


class _Conflict(TransactionConflictError):
    """Retryable; ``reasons`` is empty unless it came from a cancelled transaction."""

    def __init__(self, message: str, reasons: Sequence[CancellationReason] = ()) -> None:
        super().__init__(message)
        self.reasons = tuple(reasons)


def _translate(exc: BaseException) -> BaseException:
    """The port's error for a failed call, or ``exc`` itself when nothing maps."""
    if isinstance(exc, _CONNECTION_ERRORS):
        return _Conflict(f"DynamoDB was unreachable: {exc}")
    if not isinstance(exc, ClientError):
        return exc
    code = str(exc.response.get("Error", {}).get("Code", ""))
    message = str(exc.response.get("Error", {}).get("Message", ""))
    if code in _RETRYABLE_CODES:
        return _Conflict(f"{code}: {message}")
    if code == "ValidationException":
        return ValueError(message)
    if code == "TransactionCanceledException":
        return _translate_cancellation(exc, message)
    return exc


def _translate_cancellation(exc: ClientError, message: str) -> BaseException:
    raw = exc.response.get("CancellationReasons")
    if not raw:  # cannot tell what failed, so it must not be reported as a lost condition
        return _Conflict(f"transaction cancelled without reasons: {message}")
    reasons = [
        CancellationReason(i, str(r.get("Code", "None")), str(r.get("Message", "")))
        for i, r in enumerate(raw)
    ]
    for r in reasons:
        if r.code == "ValidationError":
            return ValueError(f"operation {r.index}: {r.message or 'DynamoDB refused the item'}")
    lost = [r.index for r in reasons if r.code == "ConditionalCheckFailed"]
    if lost:
        return DynamoConditionFailedError(lost, reasons)
    other = [r for r in reasons if r.code != "None" and r.code not in _RETRYABLE_REASONS]
    if other:
        return DynamoTransactionError(reasons)
    return _Conflict(f"transaction cancelled, retry: {_describe(reasons)}", reasons)


# --- values ----------------------------------------------------------------------------------


def _utf8(text: str, what: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{what} must be valid UTF-8 text (it has a lone surrogate)") from None


def _number(value: float | int) -> Decimal:
    number = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
    if number != 0 and abs(number) < _MIN_MAGNITUDE:
        raise ValueError(f"number {value!r} is outside DynamoDB's range (smallest is 1E-130)")
    return number


def _to_wire(value: Any) -> Any:
    """Plain JSON to what the boto3 serializer takes: floats as Decimal, text checked."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        _utf8(value, "text")
        return value
    if isinstance(value, int | float):
        return _number(value)
    if isinstance(value, list):
        return [_to_wire(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not k:
                raise ValueError("DynamoDB cannot hold an empty object key")
            _utf8(k, "object key")
            out[k] = _to_wire(v)
        return out
    raise TypeError(f"not plain JSON: {type(value).__name__}")


def _from_wire(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, list):
        return [_from_wire(v) for v in value]
    if isinstance(value, dict):
        return {k: _from_wire(v) for k, v in value.items()}
    return value


def _attr(value: Any) -> dict[str, Any]:
    return dict(_SER.serialize(_to_wire(value)))


def _size(value: Any) -> int:
    """DynamoDB's accounting (documented in "Item sizes"): text is its UTF-8 length, a number about
    one byte per two significant digits plus one, null and boolean one byte, and a list or map 3
    bytes plus one per element plus the elements (a map element also counts its name)."""
    if value is None or isinstance(value, bool):
        return 1
    if isinstance(value, str):
        return len(value.encode("utf-8", "surrogatepass"))
    if isinstance(value, int | float):
        digits = len(
            Decimal(repr(value) if isinstance(value, float) else value)
            .normalize()
            .as_tuple()
            .digits
        )
        return math.ceil(digits / 2) + 1
    if isinstance(value, list):
        return 3 + sum(_size(v) + 1 for v in value)
    if isinstance(value, dict):
        return 3 + sum(
            len(k.encode("utf-8", "surrogatepass")) + _size(v) + 1 for k, v in value.items()
        )
    raise TypeError(f"not plain JSON: {type(value).__name__}")


def estimate_item_bytes(data: dict[str, Any], *, pk: str = "", sk: str = "") -> int:
    """Size of the stored item ``{pk, sk, v, d}`` by DynamoDB's rules. ``pk`` is the full stored
    partition key (with its ``TEAM#<team>#`` prefix)."""
    names = len(b"pk") + len(b"sk") + len(b"v") + len(b"d")
    keys = len(pk.encode("utf-8", "surrogatepass")) + len(sk.encode("utf-8", "surrogatepass"))
    return names + keys + 21 + _size(data)  # a version number is at most 21 bytes


# --- addressing ------------------------------------------------------------------------------


def _pk(addr: Addr) -> str:
    if addr.partition == _PLATFORM:
        return addr.pk
    return f"{addr.partition}#{addr.pk}" if addr.pk else addr.partition


def _table_key(addr: Addr) -> dict[str, Any]:
    pk, sk = _pk(addr), addr.sk
    _utf8(pk, "key")
    _utf8(sk, "key")
    return {"pk": {"S": pk}, "sk": {"S": sk}}


def _condition(
    condition: Condition | None, names: dict[str, str], values: dict[str, Any]
) -> str | None:
    match condition:
        case None:
            return None
        case Absent():
            names["#pk"] = "pk"
            return "attribute_not_exists(#pk)"
        case Exists():
            names["#pk"] = "pk"
            return "attribute_exists(#pk)"
        case VersionIs(version=n):
            names["#v"] = "v"
            values[":ver"] = {"N": str(n)}
            return "#v = :ver"
        case FieldEquals(field=f, value=v):
            _utf8(f, "field name")
            names["#d"] = "d"
            names["#f"] = f
            values[":fv"] = _attr(v)
            # The type test is explicit so 1 never equals True, whatever the backend's comparison.
            values[":ft"] = {"S": next(iter(values[":fv"]))}
            return "attribute_type(#d.#f, :ft) AND #d.#f = :fv"
    raise TypeError(f"unknown condition {condition!r}")


def _with(spec: dict[str, Any], names: dict[str, str], values: dict[str, Any]) -> dict[str, Any]:
    if names:
        spec["ExpressionAttributeNames"] = names
    if values:
        spec["ExpressionAttributeValues"] = values
    return spec


# --- the store -------------------------------------------------------------------------------


class DynamoDbStore:
    """Store port on DynamoDB. ``client`` is a boto3 ``dynamodb`` client (thread-safe). Pass one
    with retries configured; this class does not add its own."""

    def __init__(self, client: DynamoDBClient, *, main_table: str, audit_table: str) -> None:
        for name in (main_table, audit_table):
            if not isinstance(name, str) or not name:
                raise ValueError("a table name must be a non-empty str")
        if main_table == audit_table:
            raise ValueError("the main and audit tables must differ")
        self._client = client
        self._tables = {MAIN: main_table, AUDIT: audit_table}

    # -- reads

    def get(self, scope: Scope, key: Key) -> Item | None:
        addr = resolve(require_scope(scope), require_key(key))
        wire_key = _table_key(addr)
        try:
            response = self._client.get_item(
                TableName=self._tables[addr.table], Key=wire_key, ConsistentRead=True
            )
        except (ClientError, *_CONNECTION_ERRORS) as exc:
            raise _translate(exc) from exc
        found = response.get("Item")
        return None if found is None else _to_item(key, found)

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
        _utf8(pk, "key")
        _utf8(sk_prefix, "sk_prefix")
        after = (
            None if cursor is None else decode_cursor(cursor, root.partition, table, pk, sk_prefix)
        )
        names = {"#pk": "pk"}
        values: dict[str, Any] = {":pk": {"S": _pk(root)}}
        expression = "#pk = :pk"
        if sk_prefix:
            names["#sk"] = "sk"
            values[":prefix"] = {"S": sk_prefix}
            expression += " AND begins_with(#sk, :prefix)"
        want = None if limit is None else limit + 1  # one extra tells us whether there is more
        found: list[dict[str, Any]] = []
        start: dict[str, Any] | None = (
            None if after is None else _table_key(Addr(root.partition, table, root.pk, after))
        )
        while True:
            args: dict[str, Any] = {
                "TableName": self._tables[table],
                "KeyConditionExpression": expression,
                "ExpressionAttributeNames": names,
                "ExpressionAttributeValues": values,
                "ConsistentRead": True,
            }
            if want is not None:
                args["Limit"] = min(want - len(found), _MAX_QUERY_LIMIT)
            if start is not None:
                args["ExclusiveStartKey"] = start
            try:
                response = self._client.query(**args)
            except (ClientError, *_CONNECTION_ERRORS) as exc:
                raise _translate(exc) from exc
            found += response["Items"]
            start = response.get("LastEvaluatedKey")  # a page ends at 1 MB or at Limit
            if not start or (want is not None and len(found) >= want):
                break
        more = limit is not None and len(found) > limit
        if limit is not None:
            found = found[:limit]
        items = tuple(_to_item(Key(pk, f["sk"]["S"], table), f) for f in found)
        return Page(
            items,
            encode_cursor(root.partition, table, pk, sk_prefix, items[-1].key.sk) if more else None,
        )

    # -- writes

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        require_scope(scope)
        prepared = validate_ops(scope, tuple(ops))
        wire: list[dict[str, Any]] = []
        total = 0
        for p in prepared:
            spec, size = self._operation(p)
            wire.append(spec)
            total += size
        if total > MAX_TRANSACTION_BYTES:
            raise ValueError(f"transaction is {total} bytes; the limit is {MAX_TRANSACTION_BYTES}")
        try:
            self._client.transact_write_items(TransactItems=wire)  # type: ignore[arg-type]
        except (ClientError, *_CONNECTION_ERRORS) as exc:
            raise _translate(exc) from exc

    def _operation(self, p: Prepared) -> tuple[dict[str, Any], int]:
        table = self._tables[p.addr.table]
        key = _table_key(p.addr)
        names: dict[str, str] = {}
        values: dict[str, Any] = {}
        match p:
            case Prepared(op=Put(when=when), data=data) if data is not None:
                size = estimate_item_bytes(data, pk=key["pk"]["S"], sk=p.addr.sk)
                if size > MAX_ITEM_BYTES:
                    raise ValueError(f"item is {size} bytes; the limit is {MAX_ITEM_BYTES}")
                condition = _condition(when, names, values)
                names |= {"#v": "v", "#d": "d"}
                values |= {":zero": {"N": "0"}, ":one": {"N": "1"}, ":data": _attr(data)}
                update: dict[str, Any] = {
                    "TableName": table,
                    "Key": key,
                    "UpdateExpression": "SET #v = if_not_exists(#v, :zero) + :one, #d = :data",
                }
                if condition:
                    update["ConditionExpression"] = condition
                return {"Update": _with(update, names, values)}, size
            case Prepared(op=Delete(when=when)):
                delete: dict[str, Any] = {"TableName": table, "Key": key}
                if (condition := _condition(when, names, values)) is not None:
                    delete["ConditionExpression"] = condition
                return {"Delete": _with(delete, names, values)}, 0
            case Prepared(op=Check(when=when)):
                check: dict[str, Any] = {
                    "TableName": table,
                    "Key": key,
                    "ConditionExpression": _condition(when, names, values),
                }
                return {"ConditionCheck": _with(check, names, values)}, 0
        raise TypeError(f"not an operation: {p.op!r}")

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


def _to_item(key: Key, raw: Mapping[str, Any]) -> Item:
    data = _from_wire(_DESER.deserialize(raw["d"]))
    return Item(key, data, int(raw["v"]["N"]))


# --- tables ----------------------------------------------------------------------------------


def create_tables(client: DynamoDBClient, *, main_table: str, audit_table: str) -> None:
    """Create the two tables if they are missing (on-demand billing, ``pk``/``sk`` strings). For
    tests and local setups; the real tables, with indexes, TTL and backups, come from CDK."""
    for name in (main_table, audit_table):
        try:
            client.create_table(
                TableName=name,
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise
        client.get_waiter("table_exists").wait(TableName=name)
