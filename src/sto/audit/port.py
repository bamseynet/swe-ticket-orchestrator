"""The audit port: read only, plus the best-effort path for refused attempts.

There is no update, delete or write here. Entries are appended only by an ``AuditWriter`` inside
the transaction of the change they record, and the store refuses anything but ``Put`` under
``Absent`` in the audit table (``validate_ops``).
"""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sto.audit.redact import redact, redact_text
from sto.domain import RunId
from sto.gates.hooks import CHAIN_SK, audit_pk, run_pk
from sto.store.ports import AUDIT, Absent, Key, Put, Scope, Store

DEFAULT_PAGE = 500
REFUSED_METRIC = "audit.refused_write_failed"


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
    __slots__ = ("_page_size", "_store")

    def __init__(self, store: Store, *, page_size: int = DEFAULT_PAGE) -> None:
        self._store = store
        self._page_size = page_size

    def entries(self, scope: Scope, run_id: RunId) -> Iterator[Mapping[str, Any]]:
        cursor: str | None = None
        while True:
            page = self._store.query(
                scope, audit_pk(run_id), table=AUDIT, limit=self._page_size, cursor=cursor
            )
            for item in page.items:
                yield item.data
            cursor = page.cursor
            if cursor is None:
                return

    def head(self, scope: Scope, run_id: RunId) -> ChainHead | None:
        item = self._store.get(scope, Key(run_pk(run_id), CHAIN_SK))
        return None if item is None else ChainHead(int(item.data["seq"]), str(item.data["hash"]))


class RefusedAttempts:
    """A refused attempt cannot be written in the transaction that failed (PLAN 4.9), so it goes
    here: its own write, outside any run's chain, that never raises. If the write fails the
    caller's refusal still stands and ``counter`` gets ``audit.refused_write_failed``."""

    def __init__(self, store: Store, counter: Callable[[str], None]) -> None:
        self._store = store
        self._counter = counter

    def record(
        self,
        scope: Scope,
        run_id: RunId,
        *,
        actor: str,
        action: str,
        reason: str,
        data: Mapping[str, Any],
        at: int,
    ) -> None:
        try:
            body = {
                "run": str(run_id),
                "at": at,
                "actor": redact_text(actor),
                "action": action,
                "reason": redact_text(reason),
                "data": redact(dict(data)),
            }
            key = Key(f"REFUSED#{run_id}", f"{at:016d}#{secrets.token_hex(6)}", AUDIT)
            self._store.transact(scope, [Put(key, body, Absent())])
        except Exception:
            with contextlib.suppress(Exception):  # best effort all the way down
                self._counter(REFUSED_METRIC)
