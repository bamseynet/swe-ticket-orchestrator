"""Shared fixtures for the audit tests: a recorded gate flow and a way to forge a store."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sto.domain import DecisionKind, GateType, RunId, Subject, Surface
from sto.engine.commands import OpenGate
from sto.gates.hooks import audit_pk, run_pk
from sto.gates.service import GateService
from sto.signing.local import LocalSigner
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, Absent, Key, Op, Put, Scope, TeamScope

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
RUN2 = RunId.parse("01J00000000000000000000002")
SECRET = b"audit-checkpoint-key-material-0123456789"


def signer(key_id: str = "audit-cp-1", secret: bytes = SECRET) -> LocalSigner:
    return LocalSigner(key_id=key_id, secret=secret)


def subject(tag: str = "a") -> Subject:
    return Subject(
        patch_id=f"patch-{tag}",
        ticket_revision=f"rev-{tag}",
        head_sha=f"sha-{tag}",
        evidence_digest=f"ev-{tag}",
        attention_digest=f"att-{tag}",
    )


@dataclass
class Recorder:
    """A store that remembers every transaction that committed, in order."""

    inner: MemoryStore = field(default_factory=MemoryStore)
    committed: list[tuple[Scope, tuple[Op, ...]]] = field(default_factory=list)

    def get(self, scope: Scope, key: Key) -> Any:
        return self.inner.get(scope, key)

    def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
        return self.inner.query(scope, pk, **kw)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        self.inner.transact(scope, ops)
        self.committed.append((scope, tuple(ops)))

    def put(self, scope: Scope, key: Key, data: Any, *, when: Any = None) -> None:
        self.transact(scope, [Put(key, dict(data), when)])

    def delete(self, scope: Scope, key: Key, *, when: Any = None) -> None:
        raise AssertionError("the helper store does not delete")


def template_run(service: GateService, run: RunId = RUN, *, comment: str = "fine") -> int:
    """Drive one run through the gates a template has: review (changes requested, then an
    approval), then QA (approval), then a later rejection that voids an earlier approval.
    Returns how many state changes it made."""
    n = 0

    def open_(name: str, kind: GateType, rnd: int, tag: str) -> None:
        nonlocal n
        service.open_gate(TEAM, OpenGate(run, name, kind, rnd, subject(tag)))
        n += 1

    def decide(name: str, rnd: int, kind: DecisionKind, tag: str, who: str) -> None:
        nonlocal n
        service.decide(
            TEAM,
            run_id=run,
            gate=name,
            round=rnd,
            kind=kind,
            actor=who,
            surface=Surface.UI,
            subject_digest=subject(tag).digest(),
            comment=comment,
        )
        n += 1

    open_("review", GateType.REVIEW, 1, "a")
    decide("review", 1, DecisionKind.REQUEST_CHANGES, "a", "alice")
    open_("review", GateType.REVIEW, 2, "b")
    decide("review", 2, DecisionKind.APPROVE, "b", "bob")
    open_("qa", GateType.QA, 1, "b")
    decide("qa", 1, DecisionKind.APPROVE, "b", "carol")
    open_("review", GateType.REVIEW, 3, "c")
    decide("review", 3, DecisionKind.REJECT, "c", "dave")  # voids the approved round 2
    return n


def audit_items(store: MemoryStore, run: RunId = RUN, scope: Scope = TEAM) -> list[dict[str, Any]]:
    return [dict(i.data) for i in store.query(scope, audit_pk(run), table=AUDIT).items]


def head_of(store: MemoryStore, run: RunId = RUN, scope: Scope = TEAM) -> dict[str, Any] | None:
    item = store.get(scope, Key(run_pk(run), "CHAIN"))
    return None if item is None else dict(item.data)


def forged_copy(
    source: MemoryStore,
    runs: Sequence[RunId],
    edit: Callable[[RunId, list[dict[str, Any]]], list[dict[str, Any]]],
    *,
    scope: Scope = TEAM,
    fix_head: bool = True,
) -> MemoryStore:
    """What a writer with full access to the tables could produce: a fresh store holding each
    run's entries after ``edit`` (which may change, reorder or drop them). With ``fix_head`` the
    chain head is rewritten to match the new last entry, so only a checkpoint can tell."""
    out = MemoryStore()
    for run in runs:
        entries = edit(run, audit_items(source, run, scope))
        for pos, e in enumerate(entries, start=1):  # stored by position, so a swap is physical
            out.transact(scope, [Put(Key(audit_pk(run), f"{pos:012d}", AUDIT), e, Absent())])
        if entries and fix_head:
            last = entries[-1]
            out.transact(
                scope,
                [Put(Key(run_pk(run), "CHAIN"), {"seq": last["seq"], "hash": last["hash"]}, None)],
            )
    return out


def rechain(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recompute seq, links and hashes so the forged chain is internally consistent."""
    from sto.gates.hooks import GENESIS_HASH, entry_hash

    out, prev = [], GENESIS_HASH
    for n, e in enumerate(entries, start=1):
        body = {k: v for k, v in e.items() if k != "hash"}
        body["seq"], body["prev"] = n, prev
        digest = entry_hash(body)
        out.append({**body, "hash": digest})
        prev = digest
    return out
