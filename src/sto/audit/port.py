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
from typing import Any, Protocol

from sto.audit.errors import AuditVerificationError
from sto.audit.redact import redact, redact_text
from sto.domain import RunId
from sto.domain.errors import InvalidIdError
from sto.gates.hooks import CHAIN_SK, ReadOnly, audit_pk, run_pk
from sto.store.ports import AUDIT, Absent, Key, Put, Scope, Store

DEFAULT_PAGE = 500
REFUSED_METRIC = "audit.refused_write_failed"
MAX_FIELD_CHARS = 1_024  # actor, action, reason
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


def _clip(text: object) -> str:
    s = str(text)
    return s if len(s) <= MAX_FIELD_CHARS else s[:MAX_FIELD_CHARS] + "...[truncated]"


class RefusedAttempts:
    """A refused attempt cannot be written in the transaction that failed (PLAN 4.9), so it goes
    here: its own write, outside any run's chain, that never raises. If the write fails the
    caller's refusal still stands and ``counter`` gets ``audit.refused_write_failed``.

    Every field is bounded before anything else runs on it, so padding an attempt cannot make the
    write fail and erase the record: oversized data is replaced by a size and a short preview."""

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
                partition = str(RunId.parse(str(run_id)))
                claimed = None
            except (ValueError, InvalidIdError):
                partition, claimed = UNATTRIBUTED, _clip(run_id)
            body: dict[str, Any] = {
                "run": partition,
                "at": at,
                "actor": _clip(actor),
                "action": redact_text(_clip(action)),
                "reason": redact_text(_clip(reason)),
                "data": self._bounded(data),
            }
            if claimed is not None:
                body["claimed_run"] = redact_text(claimed)
            key = Key(f"REFUSED#{partition}", f"{at:016d}#{secrets.token_hex(6)}", AUDIT)
            self._store.transact(scope, [Put(key, body, Absent())])
        except Exception:
            with contextlib.suppress(Exception):  # best effort all the way down
                self._counter(REFUSED_METRIC)

    @staticmethod
    def _bounded(data: Mapping[str, Any]) -> dict[str, Any]:
        blob = json.dumps(data, default=str, sort_keys=True)
        if len(blob) > MAX_DATA_BYTES:
            return {
                "truncated": True,
                "bytes": len(blob),
                "preview": redact_text(blob[:MAX_FIELD_CHARS]),
            }
        return redact(dict(data))  # type: ignore[no-any-return]
