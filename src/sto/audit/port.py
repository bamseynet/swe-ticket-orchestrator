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
from sto.store.ports import AUDIT, Absent, ConditionFailedError, Key, Put, Scope, Store

DEFAULT_PAGE = 500
REFUSED_METRIC = "audit.refused_write_failed"
REFUSED_DEGRADED_METRIC = "audit.refused_write_degraded"
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

    def head(self, scope: Scope, run_id: RunId) -> ChainHead | None:
        item = self._view.get(scope, Key(run_pk(run_id), CHAIN_SK))
        if item is None:
            return None
        seq, digest = item.data.get("seq"), item.data.get("hash")
        if type(seq) is not int or seq < 1 or not isinstance(digest, str):
            raise AuditVerificationError(f"the chain head of run {run_id} is malformed")
        return ChainHead(seq, digest)


def _plain(value: object) -> str:
    """Text the store can hold: a lone surrogate (which cannot be encoded) becomes ``?``, and a
    value whose ``str`` raises (or a 5,000-digit int) becomes a marker."""
    try:
        return str(value).encode("utf-8", "replace").decode("utf-8")
    except Exception:
        return f"[unprintable {type(value).__name__}]"


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


MAX_KEY_CHARS = 200
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
        mapped: dict[str, Any] = {}
        for k, v in islice(value.items(), _MAX_NODES):
            if budget[0] < 0:
                break  # stop pulling items once the budget is spent
            mapped[_plain(k)] = _storable(v, depth + 1, budget)  # whole key: redacted, then clipped
        return mapped
    if isinstance(value, list | tuple):
        items: list[Any] = []
        for v in islice(value, _MAX_NODES):
            if budget[0] < 0:
                break
            items.append(_storable(v, depth + 1, budget))
        return items
    if isinstance(value, bytes | bytearray):
        return f"[{len(value)} bytes]"
    return f"[unstorable {type(value).__name__}]"


def _clip_keys(value: Any) -> Any:
    """Bound dict keys after redaction, so a secret in a long key is never cut first. Keys that
    collide once clipped get a counter."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            new_k = k if len(k) <= MAX_KEY_CHARS else k[:MAX_KEY_CHARS] + "...[truncated]"
            n = 0
            base = new_k
            while new_k in out:
                n += 1
                new_k = f"{base}#{n}"
            out[new_k] = _clip_keys(v)
        return out
    if isinstance(value, list):
        return [_clip_keys(v) for v in value]
    return value


class RefusedAttempts:
    """A refused attempt cannot be written in the transaction that failed (PLAN 4.9), so it goes
    here: its own write, outside any run's chain, that never raises. If the write fails the
    caller's refusal still stands and ``counter`` gets ``audit.refused_write_failed``; a record
    that had to be degraded to a marker counts ``audit.refused_write_degraded``.

    ``actor`` is redacted here, unlike in the chain: in a refused attempt it is whatever the
    caller sent (the identity was never verified), so it is free text and may hold a secret. In
    the chain the actor is a verified identity and stays readable.

    Whatever is passed in, the record is kept: text is made storable and bounded, odd data
    becomes markers, oversized data is replaced by its size (no preview: a preview of a secret is
    a secret), and if the store refuses the record as invalid, a second write keeps only the
    bounded text fields. A transient failure is retried with the same record instead."""

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
            self._write(scope, key, body, data)
        except Exception:
            with contextlib.suppress(Exception):  # best effort all the way down
                self._counter(REFUSED_METRIC)

    def _write(self, scope: Scope, key: Key, body: dict[str, Any], data: object) -> None:
        """One write. A store that refuses the record (a validation error) gets a second write of
        the bounded text with ``{"unstorable": true}``, counted as degraded. Anything else (a
        throttle, a timeout) is retried once with the same record; a retry that finds the item
        already there succeeded the first time."""
        full = {**body, "data": self._bounded(data)}
        try:
            self._store.transact(scope, [Put(key, full, Absent())])
        except (ValueError, TypeError):
            with contextlib.suppress(Exception):
                self._counter(REFUSED_DEGRADED_METRIC)
            self._store.transact(
                scope, [Put(key, {**body, "data": {"unstorable": True}}, Absent())]
            )
        except Exception:
            try:
                self._store.transact(scope, [Put(key, full, Absent())])
            except ConditionFailedError:
                return  # the first attempt did commit
            # anything else propagates to record(), which counts it

    @staticmethod
    def _bounded(data: object) -> dict[str, Any]:
        if not isinstance(data, Mapping):
            return {"unstorable": True}
        clean = _storable(data, 0, [_MAX_NODES])
        size = len(json.dumps(clean))
        if size <= MAX_DATA_BYTES:
            out: dict[str, Any] = _clip_keys(redact(clean))
            if len(json.dumps(out)) <= MAX_DATA_BYTES:
                return out
        return {"truncated": True, "bytes": size}
