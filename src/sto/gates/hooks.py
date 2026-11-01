"""Seams of the gate service (D1-06): the ``AuditWriter`` and the gate-open and decide hooks.

Later gate rules (eligibility, quorum, separation of duties, notifications) plug in here as
new files, so ``service.py`` stays closed. Everything a seam produces is a list of store ops
that the service adds to the **same transaction** as the gate change, so a hook's writes commit
or roll back with the decision (PLAN 4.3 rule 6, ADR-0005 #3).

* A hook cannot write on its own: it sees a ``Reader`` and returns ops. To refuse, raise a
  ``StoError``; nothing has been written yet.
* A hook may run more than once for one call (the service retries a lost version race and
  runs the hooks again on fresh state), so it must have no side effects outside the ops it
  returns. It never runs for a replayed ``open_gate`` that finds the gate already open.
* Ops must not name an item the service itself writes; the store refuses a duplicate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from sto.audit.redact import redact, redact_text
from sto.domain import Decision, Gate, RunId
from sto.store.ports import (
    AUDIT,
    MAIN,
    Absent,
    Item,
    Key,
    Op,
    Page,
    Put,
    Scope,
    Store,
    TeamScope,
    VersionIs,
    canonical_data,
)

GENESIS_HASH = "0" * 64
CHAIN_SK = "CHAIN"


def run_pk(run_id: RunId) -> str:
    """Partition of everything that belongs to one run: ``RUN#r`` (PLAN 11)."""
    return f"RUN#{run_id}"


def audit_pk(run_id: RunId) -> str:
    """Partition of a run's audit entries in the audit table."""
    return run_pk(run_id)


class Reader(Protocol):
    """The read half of a store. Hooks and the audit writer get this and nothing more."""

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
    ) -> Page: ...


class ReadOnly:
    """Wraps a store so only reads are reachable (no ``transact``, ``put`` or ``delete``)."""

    __slots__ = ("_store",)

    def __init__(self, store: Store) -> None:
        self._store = store

    def get(self, scope: Scope, key: Key) -> Item | None:
        return self._store.get(scope, key)

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
        return self._store.query(
            scope, pk, table=table, sk_prefix=sk_prefix, limit=limit, cursor=cursor
        )


# --- audit ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    """One audit event. ``at`` is epoch milliseconds from the service's clock."""

    run_id: RunId
    action: str
    actor: str
    data: dict[str, Any]
    at: int


class AuditWriter(Protocol):
    """Turns an entry into ops for the caller's transaction. It never writes by itself, so an
    audit record cannot exist without its decision, or the reverse.

    Every writer must move ``RUN#r/CHAIN`` in the same transaction as the gate open or decision it
    records: the effect claim (``effects/core.py``) checks that item to notice a gate round that
    skips numbers, which no per-key check can see."""

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]: ...


def entry_hash(body: dict[str, Any]) -> str:
    """Hash of the *stored* form: 1.0 is stored as 1 and tuples as lists, so hash that, or a
    verifier reading the item back computes a different value."""
    blob = json.dumps(
        canonical_data(body), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(blob.encode()).hexdigest()


class ChainedAuditWriter:
    """Append-only hash chain per run (PLAN 11 ``CHAIN`` head and audit table ``seq``).

    Each entry is a ``Put`` with ``Absent()`` in the audit table, and the chain head moves under
    a version condition, so two writers cannot both take the same ``seq``: one loses and retries.

    Secrets are redacted here, before the hash is taken (PLAN 4.9), so no unredacted writer exists
    and the stored form is what the verifier hashes.
    """

    def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> Sequence[Op]:
        head_key = Key(run_pk(entry.run_id), CHAIN_SK)
        head = reader.get(scope, head_key)
        seq = 1 if head is None else int(head.data["seq"]) + 1
        prev = GENESIS_HASH if head is None else str(head.data["hash"])
        body = {
            # run and team are in the hash, so a valid chain cannot be moved to another run
            "run": str(entry.run_id),
            "team": scope.team if isinstance(scope, TeamScope) else "",
            "seq": seq,
            "at": entry.at,
            "action": redact_text(entry.action),
            "actor": entry.actor,  # identities stay readable; they are verified, not free text
            "data": redact(entry.data),
            "prev": prev,
        }
        digest = entry_hash(body)
        return [
            Put(
                Key(audit_pk(entry.run_id), f"{seq:012d}", AUDIT),
                {**body, "hash": digest},
                Absent(),
            ),
            Put(
                head_key,
                {"seq": seq, "hash": digest},
                Absent() if head is None else VersionIs(head.version),
            ),
        ]


# --- hooks ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenContext:
    reader: Reader
    scope: Scope
    gate: Gate


@dataclass(frozen=True)
class DecideContext:
    """``before`` is the open gate that was read, ``after`` what this decision closes it to."""

    reader: Reader
    scope: Scope
    before: Gate
    after: Gate
    decision: Decision

    @property
    def gate(self) -> Gate:
        return self.after


OpenHook = Callable[[OpenContext], Sequence[Op]]
DecideHook = Callable[[DecideContext], Sequence[Op]]


@dataclass
class GateHooks:
    """Registered hooks run in registration order."""

    _open: list[OpenHook] = field(default_factory=list)
    _decide: list[DecideHook] = field(default_factory=list)

    def on_open(self, hook: OpenHook) -> OpenHook:
        self._open.append(hook)
        return hook

    def on_decide(self, hook: DecideHook) -> DecideHook:
        self._decide.append(hook)
        return hook

    def open_ops(self, ctx: OpenContext) -> list[Op]:
        return [op for hook in self._open for op in hook(ctx)]

    def decide_ops(self, ctx: DecideContext) -> list[Op]:
        return [op for hook in self._decide for op in hook(ctx)]
