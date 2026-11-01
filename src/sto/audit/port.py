"""The audit port: read only, plus the best-effort path for refused attempts.

There is no update, delete or write here. Entries are appended only by an ``AuditWriter`` inside
the transaction of the change they record, and the store refuses anything but ``Put`` under
``Absent`` in the audit table (``validate_ops``). ``StoreAuditLog`` holds a read-only view of the
store, so the object itself cannot write.
"""

from __future__ import annotations

import contextlib
import json
import secrets
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from itertools import islice
from typing import Any, Protocol

from sto.audit.errors import AuditVerificationError
from sto.audit.redact import redact, redact_text
from sto.domain import RunId
from sto.domain.errors import InvalidIdError
from sto.gates.hooks import CHAIN_SK, ReadOnly, audit_pk, run_pk
from sto.store.ports import AUDIT, Absent, Key, Put, Scope, Store

DEFAULT_PAGE = 500
REFUSED_METRIC = "audit.refused_write_failed"
MAX_FIELD_CHARS = 1_024  # actor, action, reason, after redaction
MAX_TEXT_SLICE = 4_096  # what redaction reads of a text field
MAX_DATA_BYTES = 64 * 1_024  # of the serialised data, well under the item limit
UNATTRIBUTED = "unattributed"


@dataclass(frozen=True)
class ChainHead:
    seq: int
    hash: str


class AuditLog(Protocol):
    def entries(self, scope: Scope, run_id: RunId) -> Iterator[Mapping[str, Any]]:
        """A run's entries in ``seq`` order."""
        ...

    def head(self, scope: Scope, run_id: RunId) -> ChainHead | None: ...


class StoreAuditLog:
    __slots__ = ("_page_size", "_view")

    def __init__(self, store: Store, *, page_size: int = DEFAULT_PAGE) -> None:
        self._view = ReadOnly(store)
        self._page_size = page_size

    def entries(self, scope: Scope, run_id: RunId) -> Iterator[Mapping[str, Any]]:
        cursor: str | None = None
        while True:
            page = self._view.query(
                scope, audit_pk(run_id), table=AUDIT, limit=self._page_size, cursor=cursor
            )
            for item in page.items:
                yield item.data
            cursor = page.cursor
            if cursor is None:
                return

    def has_entry(self, scope: Scope, run_id: RunId, seq: int) -> bool:
        return self._view.get(scope, Key(audit_pk(run_id), f"{seq:012d}", AUDIT)) is not None

    def head(self, scope: Scope, run_id: RunId) -> ChainHead | None:
        item = self._view.get(scope, Key(run_pk(run_id), CHAIN_SK))
        if item is None:
            return None
        seq, digest = item.data.get("seq"), item.data.get("hash")
        if type(seq) is not int or seq < 1 or not isinstance(digest, str):
            raise AuditVerificationError(f"the chain head of run {run_id} is malformed")
        return ChainHead(seq, digest)


def _plain(value: object) -> str:
    """Text the store can hold: a lone surrogate (which cannot be encoded) becomes ``?``."""
    return str(value).encode("utf-8", "replace").decode("utf-8")


def _field(value: object) -> str:
    """A bounded, redacted text field. Redaction runs on a bounded slice with its last word
    removed, so a secret cut by the bound is never kept in part; only then is the (already
    redacted) result clipped."""
    text, cut = _plain(value), False
    if len(text) > MAX_TEXT_SLICE:
        words = text[:MAX_TEXT_SLICE].rsplit(None, 1)
        text, cut = (words[0] if len(words) == 2 else ""), True
    out = redact_text(text)
    if cut or len(out) > MAX_FIELD_CHARS:
        out = out[:MAX_FIELD_CHARS] + "...[truncated]"
    return out


_MAX_NODES = 5_000
_MAX_DEPTH = 20  # the store allows 32 for the whole item
_MAX_NUMBER = 10**15


def _storable(value: Any, depth: int, budget: list[int]) -> Any:
    """JSON the store accepts, from anything: deep, cyclic, oversized or odd values become short
    markers (bytes and unknown objects are never printed, they may hold secrets)."""
    budget[0] -= 1
    if budget[0] < 0 or depth > _MAX_DEPTH:
        return "[too large]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _plain(value)
    if isinstance(value, int | float):
        ok = value == value and abs(value) < _MAX_NUMBER
        return value if ok else "[number out of range]"
    if isinstance(value, Mapping):
        return {
            _plain(k)[:200]: _storable(v, depth + 1, budget)
            for k, v in islice(value.items(), _MAX_NODES)
        }
    if isinstance(value, list | tuple):
        return [_storable(v, depth + 1, budget) for v in islice(value, _MAX_NODES)]
    if isinstance(value, bytes | bytearray):
        return f"[{len(value)} bytes]"
    return f"[unstorable {type(value).__name__}]"


class RefusedAttempts:
    """A refused attempt cannot be written in the transaction that failed (PLAN 4.9), so it goes
    here: its own write, outside any run's chain, that never raises. If the write fails the
    caller's refusal still stands and ``counter`` gets ``audit.refused_write_failed``.

    Whatever is passed in, the record is kept: text is made storable and bounded, odd data becomes
    markers, oversized data is replaced by its size (no preview: a preview of a secret is a
    secret), and if the store still refuses, a second write keeps only the bounded text fields."""

    def __init__(self, store: Store, counter: Callable[[str], None]) -> None:
        self._store = store
        self._counter = counter

    def record(
        self,
        scope: Scope,
        run_id: RunId | str,
        *,
        actor: str,
        action: str,
        reason: str,
        data: Mapping[str, Any],
        at: int,
    ) -> None:
        try:
            try:
                partition, claimed = str(RunId.parse(_plain(run_id))), None
            except (ValueError, InvalidIdError):
                partition, claimed = UNATTRIBUTED, _field(run_id)
            body: dict[str, Any] = {
                "run": partition,
                "at": at if type(at) is int and abs(at) < _MAX_NUMBER else 0,
                "actor": _field(actor),
                "action": _field(action),
                "reason": _field(reason),
            }
            if claimed is not None:
                body["claimed_run"] = claimed
            key = Key(f"REFUSED#{partition}", f"{body['at']:016d}#{secrets.token_hex(6)}", AUDIT)
            try:
                self._store.transact(
                    scope, [Put(key, {**body, "data": self._bounded(data)}, Absent())]
                )
            except Exception:
                marker = {**body, "data": {"unstorable": True}}
                self._store.transact(scope, [Put(key, marker, Absent())])
        except Exception:
            with contextlib.suppress(Exception):  # best effort all the way down
                self._counter(REFUSED_METRIC)

    @staticmethod
    def _bounded(data: object) -> dict[str, Any]:
        if not isinstance(data, Mapping):
            return {"unstorable": True}
        clean = _storable(data, 0, [_MAX_NODES])
        size = len(json.dumps(clean))
        if size <= MAX_DATA_BYTES:
            out: dict[str, Any] = redact(clean)
            if len(json.dumps(out)) <= MAX_DATA_BYTES:
                return out
        return {"truncated": True, "bytes": size}
