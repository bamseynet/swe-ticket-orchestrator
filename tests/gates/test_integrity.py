"""Gate suite v1 (D1-11): the integrity invariants G1, G4, G10 and the single-approver cases of G3
and G5 (PLAN section 15.3), proved through the real ``GateService``, ``EffectExecutor``,
``LocalDriver`` and ``FakeScm``. Nothing here stubs them.

Every test name carries its invariant ID, so a failure says which promise broke. Quorum cases
(G3 and G5 with two approvers) come with D3-06.

How the tests are built to fail on a broken service, not only to pass on a good one:

* Each refusal test has a positive control (the same setup, minus the one thing that should
  refuse, does write), so "the writer was not called" can never be vacuous.
* A crash inside the code under test is turned into an assertion that names the invariant
  (``calls_cleanly``), so a mutant that raises is still caught by a message, not a bare traceback.
* Races are deterministic where they can be (a store that runs a callback just before or after the
  next transaction) and threaded, with a deadline, where only real interleaving shows the bug.
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import sys
import threading
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Any

import pytest

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, PrRef, PrSpec, RepoRef
from sto.domain import (
    DecisionKind,
    Effect,
    EffectClass,
    EffectStatus,
    Gate,
    GateStatus,
    GateType,
    Receipt,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    Surface,
    from_wire,
    to_wire,
)
from sto.effects.core import EffectExecutor, ExecResult
from sto.effects.ports import CallHandler, EffectHandler, MergeHandler
from sto.engine.commands import OpenGate, RunStep
from sto.engine.drivers.local import EffectsExecutor, LocalDriver
from sto.engine.drivers.ports import Done, Outcome
from sto.engine.handlers.core import CancelCompleted, GateClosed, StepSucceeded
from sto.engine.reducer import LINEAR_V0, RunState
from sto.gates.service import (
    Decided,
    GateClosedError,
    GateService,
    StaleSubjectError,
    verify_audit_chain,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    MAIN,
    Condition,
    Item,
    Key,
    Op,
    Page,
    Put,
    Scope,
    Store,
    TeamScope,
)

SCOPE = TeamScope("acme")
REPO = RepoRef("acme", "app")
SUBJECT = Subject(
    patch_id="p1", ticket_revision="r1", head_sha="h1", evidence_digest="e1", attention_digest="a1"
)
# The same patch after the head moved: an approval of SUBJECT says nothing about this.
MOVED = dataclasses.replace(SUBJECT, head_sha="h2")
DEADLINE = 30.0


def calls_cleanly[T](invariant: str, fn: Callable[[], T]) -> T:
    """Run ``fn``. If the code under test raises, fail with an assertion that names the invariant
    that broke, so a mutant that crashes is caught by a message that says what it broke."""
    try:
        return fn()
    except Exception as exc:
        raise AssertionError(f"{invariant}, but it raised {exc!r}") from None


def refused_as_closed(invariant: str, fn: Callable[[], object]) -> GateClosedError:
    """Run a decision that must get 409 ``gate_closed``. Anything else (accepted, or another
    error) fails with a message that names the invariant."""
    try:
        fn()
    except GateClosedError as err:
        return err
    except Exception as exc:
        raise AssertionError(f"{invariant}: expected 409 gate_closed, got {exc!r}") from None
    raise AssertionError(f"{invariant}: expected 409 gate_closed, but the decision was accepted")


class HookStore:
    """Delegates to a store and runs queued callbacks just before or just after the next
    transaction, so "Stop commits between the read and the claim" is a line of code."""

    def __init__(self, inner: Store) -> None:
        self.inner = inner
        self.before: list[Callable[[], object]] = []
        self.after: list[Callable[[], object]] = []

    def get(self, scope: Scope, key: Key) -> Item | None:
        return self.inner.get(scope, key)

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
        return self.inner.query(
            scope, pk, table=table, sk_prefix=sk_prefix, limit=limit, cursor=cursor
        )

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        if self.before:
            self.before.pop(0)()
        self.inner.transact(scope, ops)
        if self.after:
            self.after.pop(0)()

    def put(self, scope: Scope, key: Key, data: Any, *, when: Condition | None = None) -> None:
        self.transact(scope, [Put(key, dict(data), when=when)])

    def delete(self, scope: Scope, key: Key, *, when: Condition | None = None) -> None:
        self.inner.delete(scope, key, when=when)


class fast_switching:
    """Switch threads every microsecond so a race window is hit, not just possible."""

    def __enter__(self) -> None:
        self.old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)

    def __exit__(self, *exc: object) -> None:
        sys.setswitchinterval(self.old)


def race(jobs: Sequence[Callable[[], object]]) -> list[object]:
    """Release every job at once; return each one's result or exception, in order. A job that
    does not finish in ``DEADLINE`` seconds fails the test instead of hanging CI."""
    barrier = threading.Barrier(len(jobs))
    out: list[object] = [None] * len(jobs)

    def go(i: int, job: Callable[[], object]) -> None:
        barrier.wait()
        try:
            out[i] = job()
        except Exception as exc:
            out[i] = exc

    with fast_switching():
        threads = [
            threading.Thread(target=go, args=(i, j), daemon=True) for i, j in enumerate(jobs)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(DEADLINE)
    assert not any(t.is_alive() for t in threads), "a racing job did not finish: the code hangs"
    return out


@dataclass
class World:
    """One run with a real gate service and effect executor over one store. ``writes`` is the
    spy writer: the idempotency key of every call that reached the outside world."""

    store: HookStore
    svc: GateService
    fx: EffectExecutor
    run: Run
    writes: list[str] = field(default_factory=list)

    def open(self, name: str = "review", round: int = 1, subject: Subject = SUBJECT) -> Gate:
        return self.svc.open_gate(
            SCOPE, OpenGate(self.run.id, name, GateType.REVIEW, round, subject)
        )

    def decide(
        self,
        gate: Gate,
        kind: DecisionKind,
        *,
        actor: str = "alice",
        digest: str | None = None,
    ) -> Decided:
        return self.svc.decide(
            SCOPE,
            run_id=self.run.id,
            gate=gate.name,
            round=gate.round,
            kind=kind,
            actor=actor,
            surface=Surface.UI,
            subject_digest=gate.subject.digest() if digest is None else digest,
            comment="" if kind is DecisionKind.APPROVE else "no",
        )

    def gate(self, name: str = "review", round: int = 1) -> Gate:
        item = self.store.get(SCOPE, Key(f"RUN#{self.run.id}", f"GATE#{name}#{round}"))
        assert item is not None
        return from_wire(Gate, item.data)

    def plan(self, gates: tuple[str, ...] = ("review",), subject: Subject = SUBJECT) -> Effect:
        return self.fx.plan(
            self.run.id,
            "pr.mark_ready",
            "merge",
            1,
            EffectClass.GATED,
            subject.digest(),
            requires_gates=gates,
            subject=subject,
        )

    def handler(self) -> CallHandler:
        def write(key: str) -> Receipt:
            self.writes.append(key)
            return Receipt("x-1", "", read_back_verified=True)

        return CallHandler(write)

    def go(self, effect: Effect, live: Subject | None = SUBJECT) -> ExecResult:
        return self.fx.execute(self.run.id, effect.idempotency_key, self.handler(), live=live)

    def status(self, effect: Effect) -> EffectStatus:
        return self.fx.get(self.run.id, effect.idempotency_key).status

    def count(self, prefix: str) -> int:
        return len(self.store.query(SCOPE, f"RUN#{self.run.id}", sk_prefix=prefix).items)


@pytest.fixture
def world() -> World:
    store = HookStore(MemoryStore())
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
    store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
    return World(store, GateService(store), EffectExecutor(store, SCOPE), run)


# --- G1: the writer is not called before approval -----------------------------------------------


def test_G1_control_an_approved_gate_lets_the_writer_run_once(world: World) -> None:
    gate = world.open()
    world.decide(gate, DecisionKind.APPROVE)
    result = calls_cleanly("G1: an approved gated effect runs", lambda: world.go(world.plan()))
    assert result.effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G1_gated_effect_with_no_gate_never_calls_the_writer(world: World) -> None:
    effect = world.plan()
    result = calls_cleanly("G1: no gate means refused", lambda: world.go(effect))
    assert world.writes == [], "G1: the writer ran with no gate at all"
    assert result.effect.status is not EffectStatus.CONFIRMED


@pytest.mark.parametrize(
    "close",
    [None, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES],
    ids=["open", "rejected", "changes_requested"],
)
def test_G1_gated_effect_behind_a_gate_that_is_not_approved_never_calls_the_writer(
    world: World, close: DecisionKind | None
) -> None:
    gate = world.open()
    if close is not None:
        world.decide(gate, close)
    effect = world.plan()
    calls_cleanly("G1: a gate that is not approved refuses", lambda: world.go(effect))
    assert world.writes == [], f"G1: the writer ran behind a gate that is {world.gate().status}"
    assert world.status(effect) is not EffectStatus.CONFIRMED


def test_G1_an_approving_decision_does_not_release_a_gate_that_is_not_approved(
    world: World,
) -> None:
    """Defence in depth: a stored gate that reads REJECTED must refuse the writer even if an
    approving decision is still in the ledger (a stale or corrupt read must not release a write)."""
    gate = world.open()
    world.decide(gate, DecisionKind.APPROVE)
    effect = world.plan()
    key = Key(f"RUN#{world.run.id}", "GATE#review#1")
    world.store.put(
        SCOPE, key, to_wire(dataclasses.replace(world.gate(), status=GateStatus.REJECTED))
    )
    calls_cleanly("G1: a gate that is not APPROVED refuses", lambda: world.go(effect))
    assert world.writes == [], "G1: the writer ran behind a gate whose status is not APPROVED"


def test_G1_every_required_gate_must_approve_before_the_writer_runs(world: World) -> None:
    review, qa = world.open("review"), world.open("qa")
    effect = world.plan(gates=("review", "qa"))
    world.decide(review, DecisionKind.APPROVE)
    calls_cleanly("G1: one of two gates open refuses", lambda: world.go(effect))
    assert world.writes == [], "G1: the writer ran with the qa gate still open"
    assert world.status(effect) is EffectStatus.VOIDED  # a refusal on a gate is final
    world.decide(qa, DecisionKind.APPROVE)  # control: the same two gates, both approved, do write
    again = world.fx.plan(
        world.run.id, "pr.mark_ready", "merge", 2, EffectClass.GATED, SUBJECT.digest(),
        requires_gates=("review", "qa"), subject=SUBJECT,
    )  # fmt: skip
    assert world.go(again).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G1_a_replayed_refusal_still_never_calls_the_writer(world: World) -> None:
    effect = world.plan()
    for _ in range(3):
        calls_cleanly("G1: a retried call is refused again", lambda: world.go(effect))
    assert world.writes == []


def test_G1_a_later_round_that_is_open_blocks_the_writer(world: World) -> None:
    """The latest round decides: an old approval does not carry over to a reopened gate."""
    first = world.open()
    world.decide(first, DecisionKind.APPROVE)
    world.open(round=2)
    calls_cleanly("G1: an open later round refuses", lambda: world.go(world.plan()))
    assert world.writes == [], "G1: the writer ran on the strength of a superseded round"


# G1 through the driver, on every branch of the real linear workflow.


class DriverWorld:
    """The real reducer, driver, gate service, effect executor and ``FakeScm``. Gates are opened
    through the service and left open; the test decides them, like a person would."""

    def __init__(self) -> None:
        self.store = MemoryStore()
        self.svc = GateService(self.store)
        self.scm = FakeScm()
        self.scm.seed_branch(REPO, "main", "b0")
        self.scm.seed_branch(REPO, "sto/x", "h1", parent="b0")
        self.pr = PrRef.of(
            REPO, self.scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k")
        )
        self.scm.mark_ready(self.pr, "k2")
        self.scm.spy.clear()
        self.rid = RunId.new()
        self.opened: dict[str, OpenGate] = {}
        self.driver: LocalDriver
        world = self

        class Others:
            async def execute(self, key: str, command: object) -> Outcome:
                if isinstance(command, RunStep):
                    key_ = StepKey(command.run_id, command.stage, command.visit)
                    return Done([StepSucceeded(key_, SUBJECT)])
                if isinstance(command, OpenGate):
                    world.svc.open_gate(SCOPE, command)
                    world.opened[command.name] = command
                    return Done()  # left open: only a person closes it
                if type(command).__name__ == "StopRun":
                    return Done([CancelCompleted(command.run_id)])  # type: ignore[attr-defined]
                return Done()

        async def sleep(_: float) -> None:
            for handle in self.scm.merges():  # the merge queue lands what it was asked to
                if not self.scm.poll_merge(handle).merge_sha:
                    self.scm.complete_merge(handle, "m1")

        handler: EffectHandler = MergeHandler(self.scm, self.pr, "h1", MergeMethod.SQUASH, SUBJECT)
        adapter = EffectsExecutor(
            EffectExecutor(self.store, SCOPE),
            {"pr.merge": handler},
            lambda cmd: SUBJECT,
            lambda rid: self.driver.state(rid).run.status,
            others=Others(),
            poll_interval=0.0,
        )
        ids = itertools.count()
        self.driver = LocalDriver(
            self.store,
            SCOPE,
            LINEAR_V0,
            adapter,
            owner="g1",
            clock=lambda: 1000.0,
            new_id=lambda: str(next(ids)),
            lease_seconds=60.0,
            sleep=sleep,
        )

    def run_(self, coro: Coroutine[Any, Any, RunState]) -> RunState:
        return asyncio.run(asyncio.wait_for(coro, DEADLINE))

    def start(self) -> RunState:
        async def go() -> RunState:
            await self.driver.start(Run(id=self.rid, team="acme"))
            return await self.driver.run_until_idle(self.rid)

        return self.run_(go())

    def decide(self, name: str, kind: DecisionKind) -> RunState:
        cmd = self.opened[name]
        decided = self.svc.decide(
            SCOPE,
            run_id=self.rid,
            gate=name,
            round=cmd.round,
            kind=kind,
            actor="alice",
            surface=Surface.UI,
            subject_digest=cmd.subject.digest(),
            comment="" if kind is DecisionKind.APPROVE else "no",
        )
        event = GateClosed(
            self.rid,
            name,
            cmd.round,
            kind,
            "alice",
            decided.decision.id,
            cmd.subject if kind is DecisionKind.APPROVE else None,
        )

        async def go() -> RunState:
            await self.driver.submit(self.rid, event)
            return await self.driver.run_until_idle(self.rid)

        return self.run_(go())

    def merges_requested(self) -> int:
        return len(self.scm.spy.applied("request_merge"))


def test_G1_driver_requests_no_merge_until_both_gates_approve() -> None:
    w = DriverWorld()
    w.start()
    assert w.merges_requested() == 0, "G1: a merge was requested with no gate decided"
    w.decide("review_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 0, "G1: a merge was requested with the qa gate still open"
    final = w.decide("qa_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 1, "G1: control: both gates approved, so the merge goes out"
    assert final.run.status is RunStatus.DONE


@pytest.mark.parametrize("kind", [DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES])
@pytest.mark.parametrize("at", ["review_gate", "qa_gate"])
def test_G1_driver_requests_no_merge_after_a_negative_decision(at: str, kind: DecisionKind) -> None:
    w = DriverWorld()
    w.start()
    if at == "qa_gate":
        w.decide("review_gate", DecisionKind.APPROVE)
    state = w.decide(at, kind)
    assert w.merges_requested() == 0, f"G1: a merge was requested after {kind.value} at {at}"
    assert state.run.status is not RunStatus.DONE


# --- G4: approval is bound to the subject -------------------------------------------------------


def test_G4_approve_with_a_stale_digest_is_refused_and_changes_nothing(world: World) -> None:
    gate = world.open()
    before = (
        world.count("DEC#"),
        world.count("OUT#"),
        verify_audit_chain(world.store, SCOPE, world.run.id),
    )
    with pytest.raises(StaleSubjectError):
        world.decide(gate, DecisionKind.APPROVE, digest=MOVED.digest())
    assert world.gate().status is GateStatus.OPEN, "G4: a stale approval closed the gate"
    after = (
        world.count("DEC#"),
        world.count("OUT#"),
        verify_audit_chain(world.store, SCOPE, world.run.id),
    )
    assert after == before, "G4: a refused approval still left a decision, outbox or audit entry"


def test_G4_a_refused_stale_approval_leaves_the_gate_open_for_the_right_one(world: World) -> None:
    gate = world.open()
    with pytest.raises(StaleSubjectError):
        world.decide(gate, DecisionKind.APPROVE, digest="not-the-digest")
    decided = calls_cleanly(
        "G4: the current digest still approves", lambda: world.decide(gate, DecisionKind.APPROVE)
    )
    assert decided.gate.status is GateStatus.APPROVED


@pytest.mark.parametrize("kind", [DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES])
def test_G4_a_negative_decision_with_a_stale_digest_is_accepted(
    world: World, kind: DecisionKind
) -> None:
    gate = world.open()
    decided = calls_cleanly(
        "G4: a veto is never delayed by a stale digest",
        lambda: world.decide(gate, kind, digest=MOVED.digest()),
    )
    assert decided.gate.status in (GateStatus.REJECTED, GateStatus.CHANGES_REQUESTED)
    assert world.gate().status is decided.gate.status


def test_G4_approval_of_an_old_round_digest_is_refused_on_the_new_round(world: World) -> None:
    first = world.open()
    world.decide(first, DecisionKind.REQUEST_CHANGES)
    second = world.open(round=2, subject=MOVED)
    with pytest.raises(StaleSubjectError):
        world.decide(second, DecisionKind.APPROVE, digest=first.subject.digest())
    assert world.gate(round=2).status is GateStatus.OPEN


@pytest.mark.parametrize(
    "moved",
    [MOVED, dataclasses.replace(SUBJECT, ticket_revision="r2")],
    ids=["head_moved", "ticket_edited"],
)
def test_G4_an_approval_does_not_let_the_writer_run_once_the_subject_has_moved(
    world: World, moved: Subject
) -> None:
    world.decide(world.open(), DecisionKind.APPROVE)
    effect = world.plan()
    calls_cleanly("G4: the effect is refused", lambda: world.go(effect, live=moved))
    assert world.writes == [], "G4: the writer ran on an approval of a different subject"
    assert world.status(effect) is EffectStatus.VOIDED
    # control: a fresh effect (another visit) for the same approved gate does write at the same head
    fresh = world.fx.plan(
        world.run.id, "pr.mark_ready", "merge", 2, EffectClass.GATED, SUBJECT.digest(),
        requires_gates=("review",), subject=SUBJECT,
    )  # fmt: skip
    assert world.go(fresh, live=SUBJECT).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G4_a_gate_whose_subject_is_not_the_planned_head_does_not_release_the_effect(
    world: World,
) -> None:
    """The gate was opened and approved for another head than the one the effect merges."""
    world.decide(world.open(subject=MOVED), DecisionKind.APPROVE)
    effect = world.plan()
    calls_cleanly("G4: an approval of another head is refused", lambda: world.go(effect))
    assert world.writes == [], "G4: an approval of head h2 released a write for head h1"


# --- G10: Stop beats approval -------------------------------------------------------------------


def approved_and_planned(world: World) -> Effect:
    world.decide(world.open(), DecisionKind.APPROVE)
    return world.plan()


def test_G10_stop_after_approval_voids_the_effect_and_the_writer_never_runs(world: World) -> None:
    effect = approved_and_planned(world)
    report = world.fx.void_planned(world.run.id)
    assert [e.id for e in report.voided] == [effect.id], "G10: Stop did not void the effect"
    assert world.status(effect) is EffectStatus.VOIDED
    calls_cleanly("G10: a voided effect is refused", lambda: world.go(effect))
    assert world.writes == [], "G10: the writer ran after Stop voided the effect"
    assert world.status(effect) is EffectStatus.VOIDED


def test_G10_stop_committing_between_the_read_and_the_claim_wins(world: World) -> None:
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.fx.void_planned(world.run.id))  # just before the claim
    calls_cleanly("G10: a claim that lost to Stop backs off", lambda: world.go(effect))
    assert world.writes == [], "G10: the claim won over a Stop that committed first"
    assert world.status(effect) is EffectStatus.VOIDED


def test_G10_the_claim_committing_before_stop_wins_and_stop_reports_it_may_have_landed(
    world: World,
) -> None:
    effect = approved_and_planned(world)
    reports: list[Any] = []
    world.store.after.append(lambda: reports.append(world.fx.void_planned(world.run.id)))
    result = calls_cleanly("G10: the claim that won writes", lambda: world.go(effect))
    (report,) = reports
    assert report.voided == (), "G10: Stop voided an effect whose claim had already committed"
    assert [e.id for e in report.in_flight] == [effect.id], (
        "G10: Stop did not report the claimed effect as possibly landed"
    )
    assert len(world.writes) == 1
    assert result.effect.status is EffectStatus.CONFIRMED


def test_G10_concurrent_claim_and_stop_have_exactly_one_winner() -> None:
    claim_won = stop_won = 0
    for _ in range(40):
        store = HookStore(MemoryStore())
        run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
        store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
        w = World(store, GateService(store), EffectExecutor(store, SCOPE), run)
        effect = approved_and_planned(w)
        claimed, stopped = race([partial(w.go, effect), partial(w.fx.void_planned, w.run.id)])
        assert not isinstance(claimed, Exception), f"G10: the claim crashed: {claimed!r}"
        assert not isinstance(stopped, Exception), f"G10: Stop crashed: {stopped!r}"
        if w.writes:
            claim_won += 1
            assert len(w.writes) == 1
            assert stopped.voided == (), "G10: the claim wrote and Stop also says it voided it"  # type: ignore[attr-defined]
            assert w.status(effect) is EffectStatus.CONFIRMED
        else:
            stop_won += 1
            assert [e.id for e in stopped.voided] == [effect.id], (  # type: ignore[attr-defined]
                "G10: nothing was written but Stop did not void the effect"
            )
            assert w.status(effect) is EffectStatus.VOIDED
    assert claim_won + stop_won == 40


def test_G10_stop_on_the_run_blocks_a_claim_even_if_the_effect_was_never_voided(
    world: World,
) -> None:
    """Stop marks the run CANCELLING first. An effect nobody voided yet is still refused."""
    effect = approved_and_planned(world)
    cancelling = dataclasses.replace(
        world.run, status=RunStatus.CANCELLING, version=world.run.version + 1
    )
    world.store.put(SCOPE, Key(f"RUN#{world.run.id}", "META"), to_wire(cancelling))
    calls_cleanly("G10: a stopping run refuses the claim", lambda: world.go(effect))
    assert world.writes == [], "G10: the writer ran on a run that was being stopped"


# --- G3 (single approver): reject beats approve while the gate is open -------------------------


def test_G3_a_reject_committed_first_beats_a_later_approve(world: World) -> None:
    gate = world.open()
    world.decide(gate, DecisionKind.REJECT, actor="bob")
    late = refused_as_closed("G3", lambda: world.decide(gate, DecisionKind.APPROVE, actor="alice"))
    assert late.closed_by == "bob", "G3: the 409 does not say who closed the gate"
    assert world.gate().status is GateStatus.REJECTED, "G3: a late approve reopened a rejection"
    effect = world.plan()
    calls_cleanly("G3: a rejected gate refuses the effect", lambda: world.go(effect))
    assert world.writes == [], "G3: the writer ran after a reject"


def test_G3_a_reject_after_the_deciding_approval_gets_409_and_stop_voids_the_effect(
    world: World,
) -> None:
    gate = world.open()
    world.decide(gate, DecisionKind.APPROVE, actor="alice")
    effect = world.plan()
    late = refused_as_closed("G3", lambda: world.decide(gate, DecisionKind.REJECT, actor="bob"))
    assert late.closed_by == "alice"
    assert world.gate().status is GateStatus.APPROVED, "G3: a late reject rewrote the approval"
    report = world.fx.void_planned(world.run.id)  # the Stop option the 409 offers
    assert [e.id for e in report.voided] == [effect.id]
    calls_cleanly("G3: Stop then voids the effect", lambda: world.go(effect))
    assert world.writes == [], "G3: the writer ran after the late reject was followed by Stop"


def test_G3_concurrent_approve_and_reject_close_the_gate_once_and_a_reject_wins_cleanly() -> None:
    saw_reject_win = saw_approve_win = False
    for _ in range(40):
        store = HookStore(MemoryStore())
        run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
        store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
        w = World(store, GateService(store), EffectExecutor(store, SCOPE), run)
        gate = w.open()
        results = race(
            [
                partial(w.decide, gate, DecisionKind.APPROVE, actor="alice"),
                partial(w.decide, gate, DecisionKind.REJECT, actor="bob"),
            ]
        )
        winners = [r for r in results if isinstance(r, Decided)]
        losers = [r for r in results if not isinstance(r, Decided)]
        assert len(winners) == 1, f"G3: {len(winners)} decisions closed the gate: {results!r}"
        assert all(isinstance(r, GateClosedError) for r in losers), f"G3: wrong refusal {losers!r}"
        assert w.gate().status is winners[0].gate.status
        effect = w.plan()
        w.go(effect)
        if winners[0].decision.kind is DecisionKind.REJECT:
            saw_reject_win = True
            assert w.writes == [], "G3: the writer ran although the reject closed the gate"
        else:
            saw_approve_win = True
            assert len(w.writes) == 1
    assert saw_reject_win or saw_approve_win


# --- G5 (single approver): exactly one close ----------------------------------------------------


@pytest.mark.parametrize("n", [2, 50])
def test_G5_concurrent_decisions_close_the_gate_exactly_once(world: World, n: int) -> None:
    gate = world.open()
    kinds = itertools.cycle(
        [DecisionKind.APPROVE, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES]
    )
    jobs = [
        (lambda k=k, i=i: world.decide(gate, k, actor=f"user{i}"))
        for i, k in zip(range(n), kinds, strict=False)
    ]
    results = race(jobs)
    winners = [r for r in results if isinstance(r, Decided)]
    assert len(winners) == 1, f"G5: {len(winners)} decisions closed one gate"
    losers = [r for r in results if not isinstance(r, Decided)]
    assert len(losers) == n - 1
    assert all(isinstance(r, GateClosedError) for r in losers), (
        f"G5: a loser was refused for any reason but a closed gate: "
        f"{[r for r in losers if not isinstance(r, GateClosedError)][:3]!r}"
    )
    won = winners[0]
    assert world.gate().status is won.gate.status
    assert world.gate().closed_by == won.decision.actor
    assert world.count("DEC#") == 1, "G5: more than one decision was recorded"
    assert world.count("OUT#") == 1, "G5: more than one gate.closed outbox entry"
    # opened + decided: exactly one close in the audit trail, and the chain still verifies
    assert verify_audit_chain(world.store, SCOPE, world.run.id) == 2


def test_G5_a_closed_gate_answers_409_to_every_later_decision(world: World) -> None:
    gate = world.open()
    world.decide(gate, DecisionKind.APPROVE, actor="alice")
    for kind in (DecisionKind.APPROVE, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES):
        err = refused_as_closed("G5", lambda k=kind: world.decide(gate, k, actor="bob"))  # type: ignore[misc]
        assert err.status is GateStatus.APPROVED
        assert err.closed_by == "alice"
    assert world.count("DEC#") == 1
    assert verify_audit_chain(world.store, SCOPE, world.run.id) == 2


def test_G5_a_gate_that_is_still_open_never_answers_409(world: World) -> None:
    """A lost race on a gate that is still open is retried, not reported as closed (the 409 is for
    a truly closed gate). A competing write to the gate's version between the service's read and
    its write must not turn into ``gate_closed`` or into a lost decision."""
    gate = world.open()
    gate_key = Key(f"RUN#{world.run.id}", "GATE#review#1")

    def touch() -> None:  # a no-op rewrite: bumps the version, leaves the gate open
        item = world.store.get(SCOPE, gate_key)
        assert item is not None
        world.store.inner.put(SCOPE, gate_key, dict(item.data))

    world.store.before.append(touch)
    decided = calls_cleanly(
        "G5: a version bump on an open gate is retried",
        lambda: world.decide(gate, DecisionKind.APPROVE),
    )
    assert decided.gate.status is GateStatus.APPROVED
    assert world.count("DEC#") == 1
