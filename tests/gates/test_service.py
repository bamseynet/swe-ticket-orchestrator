"""Gate service v0 (D1-06): open idempotently, decide through one function, close once.

The races here are built to fail on a broken service: a store that injects a competing commit
between the service's read and its write, and many threads released together.
"""

from __future__ import annotations

import random
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import Any

import pytest

from sto.domain import (
    DecisionId,
    DecisionKind,
    Gate,
    GateId,
    GateStatus,
    GateType,
    PermanentError,
    RunId,
    Subject,
    Surface,
    from_wire,
    to_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.hooks import (
    AuditEntry,
    ChainedAuditWriter,
    DecideContext,
    GateHooks,
    OpenContext,
    Reader,
    ReadOnly,
    audit_pk,
)
from sto.gates.service import (
    MAX_ROUNDS_PER_GATE,
    DecisionNotAllowedError,
    GateClosedError,
    GateConflictError,
    GateNotFoundError,
    GateRoundLimitError,
    GateService,
    StaleRoundError,
    StaleSubjectError,
    verify_audit_chain,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    AUDIT,
    Absent,
    Check,
    ConditionFailedError,
    Exists,
    Item,
    Key,
    Op,
    Put,
    Scope,
    TeamScope,
)

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")


def head_subject(tag: str = "a") -> Subject:
    return Subject(
        patch_id=f"patch-{tag}",
        ticket_revision=f"rev-{tag}",
        head_sha=f"sha-{tag}",
        evidence_digest=f"ev-{tag}",
        attention_digest=f"att-{tag}",
    )


def open_cmd(
    name: str = "review", round: int = 1, gate_type: GateType = GateType.REVIEW, tag: str = "a"
) -> OpenGate:
    return OpenGate(RUN, name, gate_type, round, head_subject(tag))


def gate_item(store: MemoryStore, name: str = "review", round: int = 1) -> Item:
    item = store.get(TEAM, Key(f"RUN#{RUN}", f"GATE#{name}#{round}"))
    assert item is not None
    return item


def gate_of(store: MemoryStore, name: str = "review", round: int = 1) -> Gate:
    return from_wire(Gate, gate_item(store, name, round).data)


def ledger(store: MemoryStore) -> list[Item]:
    return list(store.query(TEAM, f"RUN#{RUN}", sk_prefix="DEC#").items)


def outbox(store: MemoryStore) -> list[Item]:
    return list(store.query(TEAM, f"RUN#{RUN}", sk_prefix="OUT#").items)


def audit(store: MemoryStore) -> list[Item]:
    return list(store.query(TEAM, f"RUN#{RUN}", table=AUDIT).items)


@pytest.fixture
def store() -> MemoryStore:
    """The one place a store is chosen, so another implementation (SQLite, D1-12) can be
    parametrized in here. Tests that subclass a store to inject races stay on MemoryStore."""
    return MemoryStore()


@pytest.fixture
def svc(store: MemoryStore) -> GateService:
    return GateService(store)


def decide(
    svc: GateService,
    kind: DecisionKind,
    *,
    gate: Gate,
    actor: str = "alice",
    digest: str | None = None,
    comment: str = "",
) -> Any:
    if digest is None:
        digest = gate.subject.digest()
    return svc.decide(
        TEAM,
        run_id=RUN,
        gate=gate.name,
        round=gate.round,
        kind=kind,
        actor=actor,
        surface=Surface.UI,
        subject_digest=digest,
        comment=comment,
    )


# --- open -----------------------------------------------------------------------------------


def test_open_creates_an_open_gate_at_its_triple(store: MemoryStore, svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    assert gate.status is GateStatus.OPEN
    assert (gate.run_id, gate.name, gate.round) == (RUN, "review", 1)
    assert gate_of(store) == gate


def test_open_is_idempotent_on_run_name_round(store: MemoryStore, svc: GateService) -> None:
    first = svc.open_gate(TEAM, open_cmd())
    again = svc.open_gate(TEAM, open_cmd())
    assert again == first  # same gate id: a replayed command opens nothing new
    assert len(store.query(TEAM, f"RUN#{RUN}", sk_prefix="GATE#").items) == 1
    assert len([a for a in audit(store) if a.data["action"] == "gate.opened"]) == 1


def test_replayed_open_returns_the_closed_gate_and_does_not_reopen_it(
    store: MemoryStore, svc: GateService
) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, DecisionKind.APPROVE, gate=gate)
    again = svc.open_gate(TEAM, open_cmd())
    assert again.status is GateStatus.APPROVED
    assert again.id == gate.id


def test_concurrent_opens_of_one_triple_yield_one_gate(store: MemoryStore) -> None:
    barrier = threading.Barrier(8)
    ids: list[GateId] = []
    lock = threading.Lock()

    def go() -> None:
        barrier.wait()
        g = GateService(store).open_gate(TEAM, open_cmd())
        with lock:
            ids.append(g.id)

    with _fast_switching():
        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert len(set(ids)) == 1
    assert len(ids) == 8
    assert len(store.query(TEAM, f"RUN#{RUN}", sk_prefix="GATE#").items) == 1
    assert len([a for a in audit(store) if a.data["action"] == "gate.opened"]) == 1


def test_open_with_a_different_subject_for_the_same_triple_is_refused(
    svc: GateService,
) -> None:
    svc.open_gate(TEAM, open_cmd(tag="a"))
    with pytest.raises(GateConflictError):
        svc.open_gate(TEAM, open_cmd(tag="b"))


def test_new_round_is_a_new_gate_once_the_earlier_round_is_closed(
    store: MemoryStore, svc: GateService
) -> None:
    g1 = svc.open_gate(TEAM, open_cmd(round=1))
    decide(svc, DecisionKind.REQUEST_CHANGES, gate=g1, comment="again")
    g2 = svc.open_gate(TEAM, open_cmd(round=2, tag="b"))
    assert g1.id != g2.id
    assert gate_of(store, round=2).is_open


def test_a_new_round_is_refused_while_a_lower_round_is_open(
    store: MemoryStore, svc: GateService
) -> None:
    svc.open_gate(TEAM, open_cmd(round=1))
    with pytest.raises(GateConflictError, match="round 1"):
        svc.open_gate(TEAM, open_cmd(round=2, tag="b"))
    assert len(store.query(TEAM, f"RUN#{RUN}", sk_prefix="GATE#").items) == 1


def test_replaying_an_earlier_round_open_still_works_after_a_later_round_exists(
    svc: GateService,
) -> None:
    g1 = svc.open_gate(TEAM, open_cmd(round=1))
    decide(svc, DecisionKind.REJECT, gate=g1, comment="no")
    svc.open_gate(TEAM, open_cmd(round=2, tag="b"))
    assert svc.open_gate(TEAM, open_cmd(round=1)).id == g1.id


def _plant(store: MemoryStore, name: str, round: int, status: str, tag: str = "a") -> Gate:
    """Write a gate straight into the store, as an older version or a bug might have left it."""
    gate = Gate(
        GateId.new(), RUN, name, GateType.REVIEW, round, head_subject(tag), GateStatus(status)
    )
    data = to_wire(gate)
    if gate.status is not GateStatus.OPEN:
        data["closed_by"] = "planted"
    store.put(TEAM, Key(f"RUN#{RUN}", f"GATE#{name}#{round}"), data)
    return from_wire(Gate, data)


def test_an_older_round_cannot_be_decided_after_a_newer_one_exists(
    store: MemoryStore, svc: GateService
) -> None:
    """ADR-0005 #8: an older approval must not close after a later veto."""
    old = _plant(store, "review", 1, "OPEN")
    _plant(store, "review", 2, "CHANGES_REQUESTED", tag="b")
    for kind in (DecisionKind.APPROVE, DecisionKind.REJECT):
        with pytest.raises(StaleRoundError) as err:
            decide(svc, kind, gate=old, comment="x")
        assert err.value.code == "stale_round"
    assert gate_of(store, round=1).is_open
    assert ledger(store) == []


def test_closing_an_older_round_never_invalidates_a_newer_one(
    store: MemoryStore, svc: GateService
) -> None:
    """Only EARLIER rounds are voided. (A newer round cannot exist beside an open older one
    through the service, so this is planted to pin the < comparison.)"""
    _plant(store, "review", 2, "APPROVED", tag="b")
    older = _plant(store, "review", 1, "OPEN")
    with pytest.raises(StaleRoundError):
        decide(svc, DecisionKind.REJECT, gate=older, comment="x")
    assert gate_of(store, round=2).status is GateStatus.APPROVED


class _FlipBetweenReads(MemoryStore):
    """On the third ``GATE#`` query (the confirming re-read), approve round 1 behind the
    service's back: the state changed after its first look, before it commits."""

    def __init__(self) -> None:
        super().__init__()
        self.queries = 0
        self.armed = False

    def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
        if self.armed and kw.get("sk_prefix", "").startswith("GATE#"):
            self.queries += 1
            if self.queries == 3:
                item = gate_item(self, round=1)
                MemoryStore.put(self, TEAM, item.key, {**item.data, "status": "APPROVED"})
        return super().query(scope, pk, **kw)


def test_invalidation_set_is_confirmed_after_the_audit_chain_head_is_read() -> None:
    store = _FlipBetweenReads()
    service = GateService(store)
    _plant(store, "review", 1, "OPEN")  # planted: round 2 beside an open round 1
    g2 = _plant(store, "review", 2, "OPEN", tag="b")
    store.armed = True
    decide(service, DecisionKind.REJECT, gate=g2, comment="no")
    assert gate_of(store, round=1).status is GateStatus.INVALIDATED
    assert gate_of(store, round=2).status is GateStatus.REJECTED


def test_round_limit_keeps_a_veto_inside_the_transaction_cap() -> None:
    """ADR-0017: transactions cap at 100 ops. Closing a round voids every earlier approved
    round in the same transaction, so rounds per gate are bounded to keep a veto possible."""
    store = MemoryStore()
    service = GateService(store)
    for r in range(1, MAX_ROUNDS_PER_GATE):
        g = service.open_gate(TEAM, open_cmd(round=r, tag=str(r)))
        decide(service, DecisionKind.APPROVE, gate=g)
    last = service.open_gate(TEAM, open_cmd(round=MAX_ROUNDS_PER_GATE, tag="last"))
    with pytest.raises(GateRoundLimitError, match="rounds"):
        service.open_gate(TEAM, open_cmd(round=MAX_ROUNDS_PER_GATE + 1, tag="over"))
    # the worst case still commits: a veto that voids every earlier approval
    decide(service, DecisionKind.REJECT, gate=last, comment="no")
    assert gate_of(store, round=1).status is GateStatus.INVALIDATED
    assert gate_of(store, round=MAX_ROUNDS_PER_GATE - 1).status is GateStatus.INVALIDATED
    assert gate_of(store, round=MAX_ROUNDS_PER_GATE).status is GateStatus.REJECTED


def test_too_many_ops_fails_clearly_not_with_a_store_value_error() -> None:
    """Hooks add ops too; if the total would pass the cap the decision is refused by name."""
    hooks = GateHooks()
    hooks.on_decide(lambda ctx: [Put(Key(f"RUN#{RUN}", f"BULK#{i}"), {}) for i in range(100)])
    service = GateService(MemoryStore(), hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(GateRoundLimitError, match="operations"):
        decide(service, DecisionKind.APPROVE, gate=gate)


# --- decide: the three outcomes ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "status", "comment"),
    [
        (DecisionKind.APPROVE, GateStatus.APPROVED, ""),
        (DecisionKind.REQUEST_CHANGES, GateStatus.CHANGES_REQUESTED, "fix the null check"),
        (DecisionKind.REJECT, GateStatus.REJECTED, "wrong approach"),
    ],
)
def test_decision_closes_the_gate_with_ledger_audit_and_outbox(
    store: MemoryStore, svc: GateService, kind: DecisionKind, status: GateStatus, comment: str
) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    result = decide(svc, kind, gate=gate, comment=comment)

    assert result.gate.status is status
    assert result.gate.closed_by == "alice"
    assert gate_of(store).status is status
    assert gate_of(store).closed_by == "alice"

    (entry,) = ledger(store)
    assert entry.data["kind"] == kind.value
    assert entry.data["actor"] == "alice"
    assert entry.data["id"] == str(result.decision.id)

    (out,) = outbox(store)
    assert out.data["kind"] == "gate.closed"
    assert out.data["gate"] == "review"
    assert out.data["round"] == 1
    assert out.data["decision"] == kind.value
    assert out.data["decision_id"] == str(result.decision.id)

    actions = [a.data["action"] for a in audit(store)]
    assert actions == ["gate.opened", "gate.decided"]
    decided = audit(store)[1].data
    assert decided["data"]["surface"] == "ui"  # PLAN 4.9: surface reaches the locked audit log
    assert decided["data"]["decision"] == kind.value


def test_approval_outbox_carries_the_approved_subject(store: MemoryStore, svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, DecisionKind.APPROVE, gate=gate)
    (out,) = outbox(store)
    assert from_wire(Subject, out.data["subject"]) == gate.subject


def test_retest_only_closes_a_qa_gate(svc: GateService) -> None:
    review = svc.open_gate(TEAM, open_cmd(name="review", gate_type=GateType.REVIEW))
    with pytest.raises(DecisionNotAllowedError):
        decide(svc, DecisionKind.RETEST, gate=review, comment="again")
    qa = svc.open_gate(TEAM, open_cmd(name="qa", gate_type=GateType.QA))
    assert decide(svc, DecisionKind.RETEST, gate=qa, comment="flaky").gate.status is (
        GateStatus.RETEST
    )


def test_waive_is_not_available_in_v0(svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    with pytest.raises(DecisionNotAllowedError):
        decide(svc, DecisionKind.WAIVE, gate=gate, comment="ok")


def test_negative_decision_needs_a_comment(store: MemoryStore, svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    with pytest.raises(ValueError, match="comment"):
        decide(svc, DecisionKind.REJECT, gate=gate, comment="  ")
    assert gate_of(store).is_open
    assert ledger(store) == []


def test_deciding_a_gate_that_does_not_exist(svc: GateService) -> None:
    ghost = Gate(
        GateId.parse("01J00000000000000000000009"),
        RUN,
        "review",
        GateType.REVIEW,
        1,
        head_subject(),
    )
    with pytest.raises(GateNotFoundError):
        decide(svc, DecisionKind.APPROVE, gate=ghost)


# --- single close ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "second", [DecisionKind.APPROVE, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES]
)
def test_second_close_gets_gate_closed_naming_who_and_how(
    store: MemoryStore, svc: GateService, second: DecisionKind
) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, DecisionKind.APPROVE, gate=gate, actor="alice")
    with pytest.raises(GateClosedError) as err:
        decide(svc, second, gate=gate, actor="bob", comment="too late")
    assert err.value.code == "gate_closed"
    assert err.value.closed_by == "alice"
    assert err.value.status is GateStatus.APPROVED
    # nothing from the refused attempt was written
    assert len(ledger(store)) == 1
    assert len(outbox(store)) == 1
    assert len(audit(store)) == 2
    assert gate_of(store).status is GateStatus.APPROVED


def test_gate_closed_is_a_permanent_error(svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, DecisionKind.REJECT, gate=gate, comment="no")
    with pytest.raises(PermanentError):
        decide(svc, DecisionKind.REJECT, gate=gate, comment="no again")


class InterleavingStore(MemoryStore):
    """Runs ``before`` once, just before the first ``transact`` whose ops satisfy ``when``.
    That is the exact moment between a service's read and its conditional write."""

    def __init__(self, when: Callable[[Sequence[Op]], bool], before: Callable[[], None]) -> None:
        super().__init__()
        self._when = when
        self._before = before
        self._fired = False

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        if not self._fired and self._when(tuple(ops)):
            self._fired = True
            self._before()
        super().transact(scope, ops)


def _closes_gate(sk: str = "GATE#review#1") -> Callable[[Sequence[Op]], bool]:
    """Matches the transaction that closes the gate stored at ``sk``."""

    def match(ops: Sequence[Op]) -> bool:
        return any(
            isinstance(o, Put) and o.key.sk == sk and o.data.get("status") != "OPEN" for o in ops
        )

    return match


def test_close_is_a_conditional_write_not_a_blind_overwrite() -> None:
    """Approver reads an open gate; before it writes, the gate record alone is closed by a
    rival (no ledger, audit or chain change, so only the gate's own condition can notice).
    The approver must lose. A service that writes the gate unconditionally would flip
    REJECTED to APPROVED."""

    def rival_closes_the_record() -> None:
        item = gate_item(racing)
        closed = {**item.data, "status": "REJECTED", "closed_by": "rival"}
        MemoryStore.put(racing, TEAM, item.key, closed)

    racing = InterleavingStore(_closes_gate(), rival_closes_the_record)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())

    with pytest.raises(GateClosedError) as err:
        decide(service, DecisionKind.APPROVE, gate=gate, actor="alice")

    assert err.value.closed_by == "rival"
    assert err.value.status is GateStatus.REJECTED
    assert gate_of(racing).status is GateStatus.REJECTED
    assert ledger(racing) == []


def test_a_veto_that_loses_the_commit_race_gets_gate_closed() -> None:
    """Rule 3/5: order is decided by commit. If the approval commits first, the late reject is
    refused (and points at Stop), not merged into the result."""

    def rival_approves() -> None:
        rival = GateService(_Bypass(racing))
        decide(rival, DecisionKind.APPROVE, gate=gate_of(racing), actor="rival")

    racing = InterleavingStore(_closes_gate(), rival_approves)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(GateClosedError) as err:
        decide(service, DecisionKind.REJECT, gate=gate, actor="bob", comment="late veto")
    assert err.value.status is GateStatus.APPROVED
    assert err.value.closed_by == "rival"
    assert gate_of(racing).status is GateStatus.APPROVED
    assert [e.data["kind"] for e in ledger(racing)] == ["approve"]


def test_a_rival_full_decision_between_read_and_write_also_wins() -> None:
    def rival_rejects() -> None:
        rival = GateService(_Bypass(racing))
        decide(rival, DecisionKind.REJECT, gate=gate_of(racing), actor="rival", comment="veto")

    racing = InterleavingStore(_closes_gate(), rival_rejects)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(GateClosedError) as err:
        decide(service, DecisionKind.APPROVE, gate=gate, actor="alice")
    assert err.value.closed_by == "rival"
    assert [e.data["actor"] for e in ledger(racing)] == ["rival"]
    assert len(outbox(racing)) == 1


class _Bypass(MemoryStore):
    """A second client of an ``InterleavingStore``: it shares the data but skips the hook."""

    def __init__(self, inner: InterleavingStore) -> None:
        super().__init__()
        self._inner = inner

    def get(self, scope: Scope, key: Key) -> Item | None:
        return self._inner.get(scope, key)

    def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
        return self._inner.query(scope, pk, **kw)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        MemoryStore.transact(self._inner, scope, ops)


def test_write_conflict_while_still_open_is_retried_not_reported() -> None:
    """Something else bumps the gate's version while it is still open (e.g. a timer extension).
    That is not a closed gate: the decision must be retried and then commit."""

    def bump_version() -> None:
        item = gate_item(racing)
        MemoryStore.put(racing, TEAM, item.key, item.data)  # same data, version + 1

    racing = InterleavingStore(_closes_gate(), bump_version)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())
    result = decide(service, DecisionKind.APPROVE, gate=gate)
    assert result.gate.status is GateStatus.APPROVED
    assert len(ledger(racing)) == 1


def test_audit_chain_conflict_is_retried_not_reported() -> None:
    """Another writer appends to the run's audit chain between read and write."""

    def append_elsewhere() -> None:
        rival = GateService(_Bypass(racing))
        rival.open_gate(TEAM, open_cmd(name="qa", gate_type=GateType.QA))

    racing = InterleavingStore(_closes_gate(), append_elsewhere)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())
    decide(service, DecisionKind.APPROVE, gate=gate)
    assert gate_of(racing).status is GateStatus.APPROVED
    assert verify_audit_chain(racing, TEAM, RUN) == 3


class _fast_switching:
    def __enter__(self) -> None:
        self.old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)

    def __exit__(self, *exc: object) -> None:
        sys.setswitchinterval(self.old)


def _race(
    store: MemoryStore,
    gate: Gate,
    jobs: Sequence[tuple[DecisionKind, str, str | None]],
) -> list[tuple[DecisionKind, str, str]]:
    """Release all jobs together. Returns (kind, actor, outcome) per job where outcome is
    ``won``, ``gate_closed``, ``stale_subject``."""
    barrier = threading.Barrier(len(jobs))
    out: list[tuple[DecisionKind, str, str]] = []
    lock = threading.Lock()

    def run(kind: DecisionKind, actor: str, digest: str | None) -> None:
        service = GateService(store)
        barrier.wait()
        try:
            decide(
                service,
                kind,
                gate=gate,
                actor=actor,
                digest=digest,
                comment="" if kind is DecisionKind.APPROVE else "no",
            )
            outcome = "won"
        except GateClosedError:
            outcome = "gate_closed"
        except StaleSubjectError:
            outcome = "stale_subject"
        with lock:
            out.append((kind, actor, outcome))

    with _fast_switching():
        threads = [threading.Thread(target=run, args=j) for j in jobs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    return out


def test_racing_approve_and_reject_close_exactly_once() -> None:
    rng = random.Random(7)
    for _ in range(40):
        store = MemoryStore()
        gate = GateService(store).open_gate(TEAM, open_cmd())
        jobs: list[tuple[DecisionKind, str, str | None]] = [
            *((DecisionKind.APPROVE, f"a{i}", None) for i in range(4)),
            *((DecisionKind.REJECT, f"r{i}", None) for i in range(4)),
        ]
        rng.shuffle(jobs)  # the thread that starts first is random, so either kind can win
        results = _race(store, gate, jobs)
        winners = [r for r in results if r[2] == "won"]
        assert len(winners) == 1
        assert all(r[2] == "gate_closed" for r in results if r not in winners)
        kind, actor, _ = winners[0]
        closed = gate_of(store)
        assert closed.closed_by == actor
        assert closed.status is (
            GateStatus.APPROVED if kind is DecisionKind.APPROVE else GateStatus.REJECTED
        )
        assert [e.data["actor"] for e in ledger(store)] == [actor]
        assert len(outbox(store)) == 1
        decided = [a for a in audit(store) if a.data["action"] == "gate.decided"]
        assert len(decided) == 1
        assert verify_audit_chain(store, TEAM, RUN) == 2


# --- digest ---------------------------------------------------------------------------------


@pytest.mark.parametrize("digest", ["0" * 64, "sha256-of-something-else"])
def test_stale_approval_digest_is_refused_and_nothing_is_written(
    store: MemoryStore, svc: GateService, digest: str
) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    with pytest.raises(StaleSubjectError) as err:
        decide(svc, DecisionKind.APPROVE, gate=gate, digest=digest)
    assert err.value.code == "stale_subject"
    assert gate_of(store).is_open
    assert ledger(store) == []
    assert outbox(store) == []
    assert [a.data["action"] for a in audit(store)] == ["gate.opened"]


def test_approval_without_a_digest_is_invalid_input(store: MemoryStore, svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    with pytest.raises(ValueError, match="subject_digest"):
        decide(svc, DecisionKind.APPROVE, gate=gate, digest=" ")
    assert gate_of(store).is_open


def test_the_right_digest_of_another_gate_is_stale(svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd(tag="a"))
    other = head_subject("b").digest()
    with pytest.raises(StaleSubjectError):
        decide(svc, DecisionKind.APPROVE, gate=gate, digest=other)


@pytest.mark.parametrize("kind", [DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES])
@pytest.mark.parametrize("digest", ["", "0" * 64])
def test_negative_decision_is_not_refused_for_a_stale_digest(
    store: MemoryStore, svc: GateService, kind: DecisionKind, digest: str
) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    result = decide(svc, kind, gate=gate, digest=digest, comment="veto")
    assert result.gate.status in (GateStatus.REJECTED, GateStatus.CHANGES_REQUESTED)
    (entry,) = ledger(store)
    assert entry.data["subject_digest"] != gate.subject.digest()


def test_stale_approvals_cannot_beat_a_racing_veto() -> None:
    """Many stale approvals and one reject, released together: the reject always closes the
    gate. If the digest check were skipped, a stale approval could win some of these runs; if
    the veto needed a matching digest, the reject would be refused."""
    rng = random.Random(11)
    for _ in range(25):
        store = MemoryStore()
        gate = GateService(store).open_gate(TEAM, open_cmd())
        jobs: list[tuple[DecisionKind, str, str | None]] = [
            *((DecisionKind.APPROVE, f"a{i}", "stale") for i in range(6)),
            (DecisionKind.REJECT, "veto", "stale"),
        ]
        rng.shuffle(jobs)
        results = _race(store, gate, jobs)
        assert [r for r in results if r[2] == "won"] == [(DecisionKind.REJECT, "veto", "won")]
        assert gate_of(store).status is GateStatus.REJECTED
        assert all(r[2] == "stale_subject" for r in results if r[1] != "veto")


def test_subject_moving_between_read_and_write_is_caught() -> None:
    """The gate's subject changes after the approver read it but before the approver's write.
    The approval was for the old subject, so it must not close the gate."""

    def move_subject() -> None:
        item = gate_item(racing)
        data = dict(item.data)
        data["subject"] = {**data["subject"], "head_sha": "sha-moved"}
        MemoryStore.put(racing, TEAM, item.key, data)

    racing = InterleavingStore(_closes_gate(), move_subject)
    service = GateService(racing)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(StaleSubjectError):
        decide(service, DecisionKind.APPROVE, gate=gate)
    assert gate_of(racing).is_open


# --- earlier approvals --------------------------------------------------------------------------


def test_non_approved_close_invalidates_earlier_approvals_of_that_gate(
    store: MemoryStore, svc: GateService
) -> None:
    g1 = svc.open_gate(TEAM, open_cmd(round=1))
    decide(svc, DecisionKind.APPROVE, gate=g1)
    other = svc.open_gate(TEAM, open_cmd(name="qa", gate_type=GateType.QA))
    decide(svc, DecisionKind.APPROVE, gate=other)
    g2 = svc.open_gate(TEAM, open_cmd(round=2, tag="b"))

    decide(svc, DecisionKind.REQUEST_CHANGES, gate=g2, comment="again")

    assert gate_of(store, round=1).status is GateStatus.INVALIDATED
    assert gate_of(store, "qa", 1).status is GateStatus.APPROVED  # a different gate is untouched
    assert gate_of(store, round=2).status is GateStatus.CHANGES_REQUESTED


def test_an_approval_does_not_invalidate_earlier_ones(store: MemoryStore, svc: GateService) -> None:
    g1 = svc.open_gate(TEAM, open_cmd(round=1))
    decide(svc, DecisionKind.APPROVE, gate=g1)
    g2 = svc.open_gate(TEAM, open_cmd(round=2, tag="b"))
    decide(svc, DecisionKind.APPROVE, gate=g2)
    assert gate_of(store, round=1).status is GateStatus.APPROVED


def test_name_prefix_does_not_leak_between_gates(store: MemoryStore, svc: GateService) -> None:
    short = svc.open_gate(TEAM, open_cmd(name="qa", round=1, gate_type=GateType.QA))
    decide(svc, DecisionKind.APPROVE, gate=short)
    longer = svc.open_gate(TEAM, open_cmd(name="qa2", round=1, gate_type=GateType.QA))
    decide(svc, DecisionKind.REJECT, gate=longer, comment="no")
    assert gate_of(store, "qa", 1).status is GateStatus.APPROVED


def test_invalidation_does_not_clobber_a_concurrent_edit_of_the_earlier_gate() -> None:
    """Between the service's read and its write, someone else updates the earlier round's
    approved gate (here: closed_by). A blind overwrite would revert that edit."""

    def edit_round_one() -> None:
        item = gate_item(racing, round=1)
        MemoryStore.put(racing, TEAM, item.key, {**item.data, "closed_by": "admin"})

    racing = InterleavingStore(_closes_gate("GATE#review#2"), edit_round_one)
    service = GateService(racing)
    g1 = service.open_gate(TEAM, open_cmd(round=1))
    decide(service, DecisionKind.APPROVE, gate=g1)
    g2 = service.open_gate(TEAM, open_cmd(round=2, tag="b"))
    decide(service, DecisionKind.REJECT, gate=g2, comment="no")

    first = gate_of(racing, round=1)
    assert first.status is GateStatus.INVALIDATED
    assert first.closed_by == "admin"
    assert gate_of(racing, round=2).status is GateStatus.REJECTED


# --- atomicity --------------------------------------------------------------------------------


class CountingStore(MemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.transactions: list[tuple[Op, ...]] = []

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        super().transact(scope, ops)
        self.transactions.append(tuple(ops))

    def put(self, *a: Any, **k: Any) -> None:  # pragma: no cover - the service must not use it
        raise AssertionError("the service wrote outside a transaction")

    def delete(self, *a: Any, **k: Any) -> None:  # pragma: no cover
        raise AssertionError("the service wrote outside a transaction")


def test_decision_ledger_audit_outbox_and_gate_commit_in_one_transaction() -> None:
    store = CountingStore()
    service = GateService(store)
    gate = service.open_gate(TEAM, open_cmd())
    before = len(store.transactions)
    decide(service, DecisionKind.APPROVE, gate=gate)
    (tx,) = store.transactions[before:]
    sks = sorted(o.key.sk.split("#")[0] for o in tx)
    tables = {o.key.table for o in tx}
    assert {"GATE", "DEC", "OUT"} <= set(sks)
    assert AUDIT in tables
    assert any(o.key.table == AUDIT for o in tx)


def test_failed_audit_append_aborts_the_decision(store: MemoryStore) -> None:
    """The audit record is part of the decision: if it cannot be written, there is no
    decision (the PoC bug where a failed audit write let an old approval stand)."""
    service = GateService(store)
    gate = service.open_gate(TEAM, open_cmd())
    # Occupy the next audit slot (without moving the chain head), so this decision's audit
    # Put(Absent) can never succeed, however often the service retries.
    store.transact(TEAM, [Put(Key(audit_pk(RUN), f"{2:012d}", AUDIT), {"x": 1}, Absent())])
    with pytest.raises(ConditionFailedError):
        decide(service, DecisionKind.APPROVE, gate=gate)
    assert gate_of(store).is_open
    assert ledger(store) == []
    assert outbox(store) == []


def test_audit_is_a_hash_chain_in_the_audit_table(store: MemoryStore, svc: GateService) -> None:
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, DecisionKind.APPROVE, gate=gate)
    entries = audit(store)
    assert [e.data["seq"] for e in entries] == [1, 2]
    assert entries[1].data["prev"] == entries[0].data["hash"]
    assert verify_audit_chain(store, TEAM, RUN) == 2
    # tampering with an entry is detected (a copy, since the audit table refuses rewrites)
    broken = MemoryStore()
    for item in store.query(TEAM, f"RUN#{RUN}").items:
        broken.put(TEAM, item.key, item.data)
    for n, item in enumerate(entries):
        data = {**item.data, "actor": "mallory"} if n == 0 else item.data
        broken.transact(TEAM, [Put(item.key, data, Absent())])
    with pytest.raises(ValueError, match="audit chain"):
        verify_audit_chain(broken, TEAM, RUN)


def test_audit_table_refuses_overwrite_and_delete(store: MemoryStore, svc: GateService) -> None:
    svc.open_gate(TEAM, open_cmd())
    (entry,) = audit(store)
    with pytest.raises(ValueError, match="append-only"):
        store.put(TEAM, entry.key, {"forged": True})
    with pytest.raises(ValueError, match="append-only"):
        store.delete(TEAM, entry.key)


# --- hooks ------------------------------------------------------------------------------------


def test_hook_ops_commit_in_the_same_transaction_as_the_decision() -> None:
    store = CountingStore()
    hooks = GateHooks()
    seen: list[DecideContext] = []

    @hooks.on_decide
    def mark(ctx: DecideContext) -> Sequence[Op]:
        seen.append(ctx)
        return [Put(Key(f"RUN#{ctx.gate.run_id}", f"HOOK#{ctx.decision.id}"), {"ok": True})]

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    before = len(store.transactions)
    decide(service, DecisionKind.APPROVE, gate=gate)
    (tx,) = store.transactions[before:]
    assert any(o.key.sk.startswith("HOOK#") for o in tx)
    assert any(o.key.sk.startswith("GATE#") for o in tx)
    ctx = seen[-1]
    assert ctx.before.status is GateStatus.OPEN
    assert ctx.after.status is GateStatus.APPROVED
    assert ctx.decision.kind is DecisionKind.APPROVE


def test_failing_hook_condition_rolls_back_the_decision(store: MemoryStore) -> None:
    hooks = GateHooks()

    @hooks.on_decide
    def never_holds(ctx: DecideContext) -> Sequence[Op]:
        return [Check(Key("NOPE", "NOPE"), Exists())]

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(ConditionFailedError):
        decide(service, DecisionKind.APPROVE, gate=gate)
    assert gate_of(store).is_open
    assert ledger(store) == []
    assert outbox(store) == []
    assert [a.data["action"] for a in audit(store)] == ["gate.opened"]


def test_hook_that_raises_refuses_the_decision_and_writes_nothing(store: MemoryStore) -> None:
    hooks = GateHooks()

    class Refused(PermanentError):
        pass

    @hooks.on_decide
    def refuse(ctx: DecideContext) -> Sequence[Op]:
        raise Refused("not eligible")

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    with pytest.raises(Refused):
        decide(service, DecisionKind.APPROVE, gate=gate)
    assert gate_of(store).is_open
    assert ledger(store) == []


def test_open_hook_ops_commit_with_the_gate_and_roll_back_with_it(store: MemoryStore) -> None:
    hooks = GateHooks()
    contexts: list[OpenContext] = []

    @hooks.on_open
    def stamp(ctx: OpenContext) -> Sequence[Op]:
        contexts.append(ctx)
        return [Put(Key(f"RUN#{ctx.gate.run_id}", "OPENED"), {"gate": ctx.gate.name})]

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    assert contexts[-1].gate == gate
    opened = store.get(TEAM, Key(f"RUN#{RUN}", "OPENED"))
    assert opened is not None
    assert opened.data == {"gate": "review"}

    failing = GateHooks()
    failing.on_open(lambda ctx: [Check(Key("NOPE", "NOPE"), Exists())])
    bad = GateService(MemoryStore(), hooks=failing)
    with pytest.raises(ConditionFailedError):
        bad.open_gate(TEAM, open_cmd())


def test_open_hook_does_not_run_its_ops_on_a_replayed_open(store: MemoryStore) -> None:
    hooks = GateHooks()
    calls: list[int] = []

    @hooks.on_open
    def count(ctx: OpenContext) -> Sequence[Op]:
        calls.append(1)
        return [Put(Key(f"RUN#{ctx.gate.run_id}", f"STAMP#{len(calls)}"), {})]

    service = GateService(store, hooks=hooks)
    service.open_gate(TEAM, open_cmd())
    service.open_gate(TEAM, open_cmd())
    stamps = store.query(TEAM, f"RUN#{RUN}", sk_prefix="STAMP#").items
    assert len(stamps) == 1


def test_hooks_read_through_a_reader_that_cannot_write(store: MemoryStore) -> None:
    hooks = GateHooks()
    readers: list[Reader] = []

    @hooks.on_decide
    def grab(ctx: DecideContext) -> Sequence[Op]:
        readers.append(ctx.reader)
        assert ctx.reader.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1")) is not None
        return []

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    decide(service, DecisionKind.APPROVE, gate=gate)
    (reader,) = readers
    assert not hasattr(reader, "transact")
    assert not hasattr(reader, "put")


def test_hooks_run_in_registration_order_and_cannot_touch_the_same_item_twice(
    store: MemoryStore,
) -> None:
    hooks = GateHooks()
    order: list[str] = []

    @hooks.on_decide
    def one(ctx: DecideContext) -> Sequence[Op]:
        order.append("one")
        return []

    @hooks.on_decide
    def two(ctx: DecideContext) -> Sequence[Op]:
        order.append("two")
        return []

    service = GateService(store, hooks=hooks)
    gate = service.open_gate(TEAM, open_cmd())
    decide(service, DecisionKind.APPROVE, gate=gate)
    assert order == ["one", "two"]

    clash = GateHooks()
    clash.on_decide(lambda ctx: [Put(Key(f"RUN#{RUN}", "GATE#review#1"), {"evil": True})])
    bad = GateService(MemoryStore(), hooks=clash)
    g = bad.open_gate(TEAM, open_cmd())
    with pytest.raises(ValueError, match="more than once"):
        decide(bad, DecisionKind.APPROVE, gate=g)


# --- scope ------------------------------------------------------------------------------------


def test_gates_are_isolated_per_team(store: MemoryStore, svc: GateService) -> None:
    svc.open_gate(TEAM, open_cmd())
    other = TeamScope("t2")
    with pytest.raises(GateNotFoundError):
        svc.decide(
            other,
            run_id=RUN,
            gate="review",
            round=1,
            kind=DecisionKind.REJECT,
            actor="eve",
            surface=Surface.UI,
            subject_digest="",
            comment="x",
        )
    assert gate_of(store).is_open


def test_service_needs_a_scope(svc: GateService) -> None:
    with pytest.raises(TypeError):
        svc.open_gate(None, open_cmd())  # type: ignore[arg-type]


def test_audit_entry_and_ids_are_plain_values() -> None:
    entry = AuditEntry(RUN, "x", "alice", {"k": 1}, 5)
    assert entry.action == "x"
    assert DecisionId.new() != DecisionId.new()
    assert replace(entry, at=6).at == 6


def test_audit_hash_survives_values_the_store_canonicalizes() -> None:
    """1.0 is stored as 1; the hash must be over the canonical form or verification fails."""
    store = MemoryStore()
    service = GateService(store)
    service.open_gate(TEAM, open_cmd())
    writer = ChainedAuditWriter()
    entry = AuditEntry(RUN, "x", "alice", {"ratio": 1.0, "t": (1, 2)}, 5)
    store.transact(TEAM, list(writer.ops(ReadOnly(store), TEAM, entry)))
    assert verify_audit_chain(store, TEAM, RUN) == 2


def test_audit_chain_is_bound_to_its_run_and_team() -> None:
    store = MemoryStore()
    GateService(store).open_gate(TEAM, open_cmd())
    # copy the whole chain to another run, and to another team
    other_run = RunId.parse("01J00000000000000000000002")
    other_team = TeamScope("t2")
    for scope, run in ((TEAM, other_run), (other_team, RUN)):
        moved = MemoryStore()
        for item in store.query(TEAM, f"RUN#{RUN}", table=AUDIT).items:
            moved.transact(scope, [Put(Key(f"RUN#{run}", item.key.sk, AUDIT), item.data, Absent())])
        for item in store.query(TEAM, f"RUN#{RUN}", sk_prefix="CHAIN").items:
            moved.put(scope, Key(f"RUN#{run}", "CHAIN"), item.data)
        with pytest.raises(ValueError, match="audit chain"):
            verify_audit_chain(moved, scope, run)
