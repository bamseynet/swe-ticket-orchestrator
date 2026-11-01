"""Gate suite v1 (D1-11): the integrity invariants G1, G4, G10 and the single-approver cases of G3
and G5 (PLAN section 15.3), proved through the real ``GateService``, ``EffectExecutor``,
``LocalDriver`` and ``FakeScm``. The code under test is never replaced by a stub. The only
in-test double on the driver path is a small executor for the commands that are not a gated
effect (run a step, open a gate, stop the run's sessions); it stands where the agent harness and
the notifier will be.

Every test name carries its invariant ID, so a failure says which promise broke. Quorum cases
(G3 and G5 with two approvers) come with D3-06.

How the tests are built to fail on a broken service, not only to pass on a good one:

* "The writer was not called" is never left to stand alone. The controls are:
  ``test_G1_control_an_approved_gate_lets_the_writer_run_once`` (the plain approved path writes),
  a fresh approved effect in the two-gate, moved-subject and post-merge tests (the same setup
  minus the one broken thing does write), and the driver tests, which end with a merge that goes
  out. A refusal test also asserts the *reason* the executor gives, so a refusal for the wrong
  reason fails it.
* A crash or a wrong answer from the code under test is turned into an assertion that names the
  invariant (``calls_cleanly``, ``refused_as_closed``, ``refused_as_stale``, ``DriverWorld``), so a
  mutant that raises or accepts is caught by a message, not a bare traceback or "DID NOT RAISE".
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
    Decision,
    DecisionId,
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
    TransientError,
    from_wire,
    to_wire,
)
from sto.effects.core import EffectExecutor, ExecResult
from sto.effects.ports import CallHandler, EffectHandler, MergeHandler, Pending, Written
from sto.engine.commands import OpenGate, RunStep, StopRun
from sto.engine.drivers.local import EffectsExecutor, LocalDriver
from sto.engine.drivers.ports import Done, Outcome
from sto.engine.handlers.core import CancelCompleted, CancelRequested, GateClosed, StepSucceeded
from sto.engine.reducer import LINEAR_V0, RunState
from sto.gates.hooks import AuditEntry, Reader
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
    TransactionConflictError,
)

SCOPE = TeamScope("acme")
REPO = RepoRef("acme", "app")
SUBJECT = Subject(
    patch_id="p1", ticket_revision="r1", head_sha="h1", evidence_digest="e1", attention_digest="a1"
)
# The same patch after the head moved: an approval of SUBJECT says nothing about this.
MOVED = dataclasses.replace(SUBJECT, head_sha="h2")
DEADLINE = 30.0
# One variant of SUBJECT per field the digest covers. An approval is bound to every one of them.
DIGEST_FIELDS = (
    "head_sha",
    "patch_id",
    "evidence_digest",
    "attention_digest",
    "ticket_revision",
)
PRE_PUSH = Subject.pre_push(base_sha="b0", patch_id="p1", ticket_revision="r1")  # base, no head
VARIANTS = {f: dataclasses.replace(SUBJECT, **{f: f"other-{f}"}) for f in DIGEST_FIELDS}
VARIANTS["base_sha"] = PRE_PUSH
EACH_FIELD = pytest.mark.parametrize("moved", list(VARIANTS.values()), ids=list(VARIANTS))


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


def refused_as_stale(invariant: str, fn: Callable[[], object]) -> None:
    """Run an approval that must be refused as ``stale_subject``."""
    try:
        fn()
    except StaleSubjectError:
        return
    except Exception as exc:
        raise AssertionError(f"{invariant}: expected stale_subject, got {exc!r}") from None
    raise AssertionError(f"{invariant}: expected stale_subject, but the approval was accepted")


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

    def open(
        self,
        name: str = "review",
        round: int = 1,
        subject: Subject = SUBJECT,
        gate_type: GateType = GateType.REVIEW,
    ) -> Gate:
        return self.svc.open_gate(SCOPE, OpenGate(self.run.id, name, gate_type, round, subject))

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

    def set_run(self, status: RunStatus) -> None:
        """Move the run to ``status`` (as the engine does on Stop, or when a run waits or blocks).
        Written under the hook store, so it never consumes a queued hook."""
        key = Key(f"RUN#{self.run.id}", "META")
        item = self.store.get(SCOPE, key)
        assert item is not None
        run = from_wire(Run, item.data)
        reason = "kill_switch" if status is RunStatus.BLOCKED else None
        moved = dataclasses.replace(
            run, status=status, version=run.version + 1, blocked_reason=reason
        )
        self.store.inner.put(SCOPE, key, to_wire(moved))

    def refused(
        self,
        invariant: str,
        effect: Effect,
        *,
        reason: str = "gate_invalid",
        live: Subject | None = SUBJECT,
    ) -> ExecResult:
        """Execute ``effect`` and require that nothing was written *and* that the executor says why
        it refused, so a refusal for the wrong reason fails too."""
        result = calls_cleanly(
            f"{invariant}: the effect is refused", lambda: self.go(effect, live=live)
        )
        assert self.writes == [], f"{invariant}: the writer ran"
        assert result.reason == reason, (
            f"{invariant}: refused for {result.reason!r}, expected {reason!r}"
        )
        return result

    def visit(self, n: int, gates: tuple[str, ...] = ("review",)) -> Effect:
        """A fresh gated effect (another visit), the control after a refusal."""
        return self.fx.plan(
            self.run.id, "pr.mark_ready", "merge", n, EffectClass.GATED, SUBJECT.digest(),
            requires_gates=gates, subject=SUBJECT,
        )  # fmt: skip

    def plant_approved_gate(
        self,
        *,
        decision: DecisionKind | None = DecisionKind.APPROVE,
        digest: str | None = None,
        of_gate: bool = True,
    ) -> Gate:
        """A gate stored as APPROVED that the service did not produce, with (or without) one
        decision in the ledger. Defence in depth: the executor must read the ledger itself."""
        gate = self.open()
        approved = dataclasses.replace(gate, status=GateStatus.APPROVED, closed_by="planted")
        key = Key(f"RUN#{self.run.id}", "GATE#review#1")
        self.store.inner.put(SCOPE, key, to_wire(approved))
        if decision is not None:
            from sto.domain import GateId

            planted = Decision(
                DecisionId.new(),
                gate.id if of_gate else GateId.new(),
                1,
                "mallory",
                Surface.UI,
                decision,
                gate.subject.digest() if digest is None else digest,
                "planted",
            )
            dkey = Key(f"RUN#{self.run.id}", f"DEC#review#1#{planted.id}")
            self.store.inner.put(SCOPE, dkey, to_wire(planted))
        return approved


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
    result = world.refused("G1", effect)
    assert result.effect.status is EffectStatus.VOIDED


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
    world.refused("G1", effect)
    assert world.status(effect) is EffectStatus.VOIDED


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
    world.refused("G1", effect)


def test_G1_every_required_gate_must_approve_before_the_writer_runs(world: World) -> None:
    review, qa = world.open("review"), world.open("qa")
    effect = world.plan(gates=("review", "qa"))
    world.decide(review, DecisionKind.APPROVE)
    world.refused("G1", effect)
    assert world.status(effect) is EffectStatus.VOIDED  # a refusal on a gate is final
    world.decide(qa, DecisionKind.APPROVE)  # control: the same two gates, both approved, do write
    again = world.visit(2, gates=("review", "qa"))
    assert world.go(again).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G1_a_replayed_refusal_still_never_calls_the_writer(world: World) -> None:
    effect = world.plan()
    for _ in range(3):
        result = calls_cleanly("G1: a retried call is refused again", lambda: world.go(effect))
        assert result.effect.status is EffectStatus.VOIDED
    assert world.writes == []


def test_G1_a_later_round_that_is_open_blocks_the_writer(world: World) -> None:
    """The latest round decides: an old approval does not carry over to a reopened gate."""
    first = world.open()
    world.decide(first, DecisionKind.APPROVE)
    world.open(round=2)
    world.refused("G1", world.plan())


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
        self.stopped: list[RunId] = []
        self.live = SUBJECT  # what the adapter reads afresh from the ticket and the SCM
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
                if isinstance(command, StopRun):
                    world.stopped.append(command.run_id)
                    return Done([CancelCompleted(command.run_id)])
                return Done()

        async def sleep(_: float) -> None:
            for handle in self.scm.merges():  # the merge queue lands what it was asked to
                if not self.scm.poll_merge(handle).merge_sha:
                    self.scm.complete_merge(handle, "m1")

        handler: EffectHandler = MergeHandler(self.scm, self.pr, "h1", MergeMethod.SQUASH, SUBJECT)
        adapter = EffectsExecutor(
            EffectExecutor(self.store, SCOPE),
            {"pr.merge": handler},
            lambda cmd: self.live,
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
        """Drive to idle with a deadline. A driver that raises or hangs fails with a message that
        says the run broke, not with a bare traceback."""
        try:
            return asyncio.run(asyncio.wait_for(coro, DEADLINE))
        except Exception as exc:
            raise AssertionError(f"G1: the driver stopped with {exc!r}") from None

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

    def event(self, name: str, decision_id: DecisionId | None = None) -> GateClosed:
        """The approval event for the open gate ``name``. With no ``decision_id`` it is a forged
        one: the gate service never decided anything."""
        cmd = self.opened[name]
        return GateClosed(
            self.rid,
            name,
            cmd.round,
            DecisionKind.APPROVE,
            "mallory",
            decision_id or DecisionId.new(),
            cmd.subject,
        )

    def submit(self, *events: object) -> RunState:
        async def go() -> RunState:
            for event in events:
                await self.driver.submit(self.rid, event)
            return await self.driver.run_until_idle(self.rid)

        return self.run_(go())

    def decide_only(self, name: str) -> GateClosed:
        """Approve through the gate service but do not tell the driver yet."""
        cmd = self.opened[name]
        decided = self.svc.decide(
            SCOPE,
            run_id=self.rid,
            gate=name,
            round=cmd.round,
            kind=DecisionKind.APPROVE,
            actor="alice",
            surface=Surface.UI,
            subject_digest=cmd.subject.digest(),
        )
        return self.event(name, decided.decision.id)

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


def test_G1_driver_requests_no_merge_when_the_subject_moved_after_the_approvals() -> None:
    """The adapter must read the live subject afresh (PLAN 4.3 rule 2): the head moved after the
    reviewer saw it, so the approvals no longer cover what would be merged."""
    w = DriverWorld()
    w.start()
    w.decide("review_gate", DecisionKind.APPROVE)
    w.live = MOVED
    state = w.decide("qa_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 0, "G1: a merge was requested although the live subject moved"
    assert state.run.status is RunStatus.BLOCKED, f"G1: the run ended {state.run.status.value}"


def test_G1_driver_requests_no_merge_for_an_approval_event_the_gate_service_never_made() -> None:
    """The event says the qa gate was approved, but the service holds it open: the effect check
    reads the gate and the ledger itself and refuses."""
    w = DriverWorld()
    w.start()
    w.decide("review_gate", DecisionKind.APPROVE)
    state = w.submit(w.event("qa_gate"))  # no svc.decide behind it
    assert w.merges_requested() == 0, "G1: a merge went out on an approval nobody decided"
    assert state.run.status is RunStatus.BLOCKED, f"G1: the run ended {state.run.status.value}"


def test_G1_driver_requests_no_merge_for_a_forged_approval_of_the_first_gate_either() -> None:
    w = DriverWorld()
    w.start()
    w.submit(w.event("review_gate"))
    state = w.decide("qa_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 0, "G1: a merge went out with the review gate never decided"
    assert state.run.status is RunStatus.BLOCKED, f"G1: the run ended {state.run.status.value}"


@pytest.mark.parametrize("at", ["review_gate", "qa_gate"])
def test_G1_driver_requests_no_merge_after_a_reject(at: str) -> None:
    w = DriverWorld()
    w.start()
    if at == "qa_gate":
        w.decide("review_gate", DecisionKind.APPROVE)
    state = w.decide(at, DecisionKind.REJECT)
    assert w.merges_requested() == 0, f"G1: a merge was requested after a reject at {at}"
    assert state.run.status is RunStatus.REJECTED, f"G1: a reject ended {state.run.status.value}"


@pytest.mark.parametrize("at", ["review_gate", "qa_gate"])
def test_G1_driver_requests_no_merge_after_request_changes_and_waits_at_a_new_review_round(
    at: str,
) -> None:
    w = DriverWorld()
    w.start()
    if at == "qa_gate":
        w.decide("review_gate", DecisionKind.APPROVE)
    state = w.decide(at, DecisionKind.REQUEST_CHANGES)
    assert w.merges_requested() == 0, f"G1: a merge was requested after changes at {at}"
    assert state.run.status is RunStatus.WAITING_HUMAN, f"G1: ended {state.run.status.value}"
    assert w.opened["review_gate"].round == 2, "G1: changes did not send the run back to review"


def test_G1_driver_a_retest_reopens_qa_and_only_a_new_approval_merges() -> None:
    w = DriverWorld()
    w.start()
    w.decide("review_gate", DecisionKind.APPROVE)
    state = w.decide("qa_gate", DecisionKind.RETEST)
    assert w.merges_requested() == 0, "G1: a merge was requested after a retest"
    assert state.run.status is RunStatus.WAITING_HUMAN, f"G1: ended {state.run.status.value}"
    assert w.opened["qa_gate"].round == 2, "G1: a retest did not reopen the qa gate"
    assert [a.gate for a in w.driver.state(w.rid).approvals] == ["review_gate"], (
        "G1: a retest keeps the review approval of the same head"
    )
    final = w.decide("qa_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 1, "G1: control: the new qa approval releases the merge"
    assert final.run.status is RunStatus.DONE


def test_G1_driver_changes_requested_at_qa_voids_earlier_approvals() -> None:
    w = DriverWorld()
    w.start()
    w.decide("review_gate", DecisionKind.APPROVE)
    w.decide("qa_gate", DecisionKind.REQUEST_CHANGES)
    assert w.opened["review_gate"].round == 2
    assert w.driver.state(w.rid).approvals == (), "G1: changes requested kept earlier approvals"
    w.decide("review_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 0, "G1: round 1 approvals carried over into the second pass"
    assert w.opened["qa_gate"].round == 2, "G1: the qa gate did not open a new round"
    final = w.decide("qa_gate", DecisionKind.APPROVE)
    assert w.merges_requested() == 1, "G1: control: after a full second pass the merge goes out"
    assert final.run.status is RunStatus.DONE


# G10 through the driver: a Stop queued with the final approval.


def test_G10_driver_stop_queued_with_the_final_approval_requests_no_merge() -> None:
    """The last approval and the Stop are both waiting when the driver runs. Stop wins: no merge is
    requested, the run ends CANCELLED, and the driver told the executor to stop the run's work.
    (A real Stop service, and a Stop that races a merge already in the queue, are D2-11's.)"""
    w = DriverWorld()
    w.start()
    w.decide("review_gate", DecisionKind.APPROVE)
    final = w.decide_only("qa_gate")
    state = w.submit(final, CancelRequested(w.rid))
    assert w.merges_requested() == 0, "G10: a merge went out although Stop was queued with it"
    assert state.run.status is RunStatus.CANCELLED, f"G10: the run ended {state.run.status.value}"
    assert w.stopped == [w.rid], "G10: nothing told the run's work to stop"


# --- G4: approval is bound to the subject -------------------------------------------------------


@EACH_FIELD
def test_G4_approve_with_a_stale_digest_is_refused_and_changes_nothing(
    world: World, moved: Subject
) -> None:
    gate = world.open()
    before = (
        world.count("DEC#"),
        world.count("OUT#"),
        verify_audit_chain(world.store, SCOPE, world.run.id),
    )
    refused_as_stale("G4", lambda: world.decide(gate, DecisionKind.APPROVE, digest=moved.digest()))
    assert world.gate().status is GateStatus.OPEN, "G4: a stale approval closed the gate"
    after = (
        world.count("DEC#"),
        world.count("OUT#"),
        verify_audit_chain(world.store, SCOPE, world.run.id),
    )
    assert after == before, "G4: a refused approval still left a decision, outbox or audit entry"


def test_G4_a_refused_stale_approval_leaves_the_gate_open_for_the_right_one(world: World) -> None:
    gate = world.open()
    refused_as_stale(
        "G4", lambda: world.decide(gate, DecisionKind.APPROVE, digest="not-the-digest")
    )
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
    assert decided.decision.subject_digest == MOVED.digest(), (
        "G4: the ledger must keep the digest the person saw, not the gate's current one"
    )


def test_G4_approval_of_an_old_round_digest_is_refused_on_the_new_round(world: World) -> None:
    first = world.open()
    world.decide(first, DecisionKind.REQUEST_CHANGES)
    second = world.open(round=2, subject=MOVED)
    refused_as_stale(
        "G4", lambda: world.decide(second, DecisionKind.APPROVE, digest=first.subject.digest())
    )
    assert world.gate(round=2).status is GateStatus.OPEN


@EACH_FIELD
def test_G4_an_approval_does_not_let_the_writer_run_once_the_subject_has_moved(
    world: World, moved: Subject
) -> None:
    world.decide(world.open(), DecisionKind.APPROVE)
    effect = world.plan()
    world.refused("G4", effect, live=moved)
    assert world.status(effect) is EffectStatus.VOIDED
    # control: a fresh effect (another visit) for the same approved gate does write at the same head
    assert world.go(world.visit(2), live=SUBJECT).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G4_a_gate_whose_subject_is_not_the_planned_head_does_not_release_the_effect(
    world: World,
) -> None:
    """The gate was opened and approved for another head than the one the effect merges."""
    world.decide(world.open(subject=MOVED), DecisionKind.APPROVE)
    effect = world.plan()
    world.refused("G4", effect)


# --- G10: Stop beats approval -------------------------------------------------------------------


def assert_two_audit_entries(world: World) -> None:
    """Opened plus exactly one close, and the hash chain still verifies."""
    try:
        n = verify_audit_chain(world.store, SCOPE, world.run.id)
    except ValueError as exc:
        raise AssertionError(f"G5: the audit chain is broken: {exc}") from None
    assert n == 2, f"G5: expected the open and one close in the audit trail, found {n} entries"


def approved_and_planned(world: World) -> Effect:
    world.decide(world.open(), DecisionKind.APPROVE)
    return world.plan()


class PendingHandler:
    """An async write: the request is accepted and its handle kept (a merge queue)."""

    def execute(self, effect: Effect) -> Pending:
        return Pending("handle-1")

    def poll(self, effect: Effect) -> Pending:
        return Pending("handle-1")

    stop = reconcile = poll


class DownHandler:
    """The service is down: every attempt fails in a way worth retrying."""

    def execute(self, effect: Effect) -> Pending:
        raise TransientError("scm is down")

    poll = stop = reconcile = execute


def test_G10_stop_after_approval_voids_the_effect_and_the_writer_never_runs(world: World) -> None:
    effect = approved_and_planned(world)
    report = world.fx.void_planned(world.run.id)
    assert [e.id for e in report.voided] == [effect.id], "G10: Stop did not void the effect"
    assert world.status(effect) is EffectStatus.VOIDED, "G10: the effect is not VOIDED after Stop"
    result = calls_cleanly("G10: a voided effect is refused", lambda: world.go(effect))
    assert world.writes == [], "G10: the writer ran after Stop voided the effect"
    assert result.effect.status is EffectStatus.VOIDED
    assert result.reason == "cancelled", f"G10: refused for {result.reason!r}, not as cancelled"


def test_G10_stop_committing_between_the_read_and_the_claim_wins(world: World) -> None:
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.fx.void_planned(world.run.id))  # just before the claim
    result = calls_cleanly("G10: a claim that lost to Stop backs off", lambda: world.go(effect))
    assert world.writes == [], "G10: the claim won over a Stop that committed first"
    assert world.status(effect) is EffectStatus.VOIDED
    assert result.reason == "cancelled"


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


def test_G10_a_claim_and_write_that_finish_before_the_void_saves_are_not_voided(
    world: World,
) -> None:
    """Deterministic: the whole claim and write commit between Stop's read and its save. Stop's
    void is conditional on the version it read, so it loses and must not overwrite CONFIRMED."""
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.go(effect))  # runs just before Stop's save
    report = calls_cleanly(
        "G10: Stop that lost the race", lambda: world.fx.void_planned(world.run.id)
    )
    assert len(world.writes) == 1, "G10: control: the claim ran once"
    assert report.voided == (), "G10: Stop reports a void for an effect that was written"
    assert world.status(effect) is EffectStatus.CONFIRMED, (
        "G10: Stop overwrote a CONFIRMED effect with VOIDED"
    )


@pytest.mark.parametrize("how", ["accepted", "retrying", "attempting"])
def test_G10_stop_reports_every_tried_effect_as_possibly_landed_and_never_voids_it(
    world: World, how: str
) -> None:
    effect = approved_and_planned(world)
    if how == "accepted":
        world.fx.execute(world.run.id, effect.idempotency_key, PendingHandler(), live=SUBJECT)
        want = EffectStatus.ACCEPTED
    elif how == "retrying":
        world.fx.execute(world.run.id, effect.idempotency_key, DownHandler(), live=SUBJECT)
        want = EffectStatus.RETRYING
    else:
        reports: list[Any] = []
        world.store.after.append(lambda: reports.append(world.fx.void_planned(world.run.id)))
        world.go(effect)
        assert reports[0].voided == ()
        assert [e.id for e in reports[0].in_flight] == [effect.id]
        return
    assert world.status(effect) is want, f"G10: control: the effect should be {want.value}"
    report = world.fx.void_planned(world.run.id)
    assert report.voided == (), f"G10: Stop voided a {want.value} effect that may have landed"
    assert [e.id for e in report.in_flight] == [effect.id], (
        f"G10: Stop did not report the {want.value} effect as possibly landed"
    )
    assert world.status(effect) is want


def test_G10_concurrent_claim_and_stop_never_both_win() -> None:
    """Real interleaving: whichever wins, never both. (Which one wins is not fixed, so the
    deterministic tests above carry each outcome; this one only has to find a bad interleaving.)"""
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
            assert len(w.writes) == 1
            assert stopped.voided == (), "G10: the claim wrote and Stop also says it voided it"  # type: ignore[attr-defined]
            assert w.status(effect) is EffectStatus.CONFIRMED
        else:
            assert [e.id for e in stopped.voided] == [effect.id], (  # type: ignore[attr-defined]
                "G10: nothing was written but Stop did not void the effect"
            )
            assert w.status(effect) is EffectStatus.VOIDED


@pytest.mark.parametrize(
    "status", [RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.REJECTED, RunStatus.DONE]
)
def test_G10_a_run_that_is_stopping_or_over_voids_the_effect_unwritten(
    world: World, status: RunStatus
) -> None:
    """Stop marks the run CANCELLING first. An effect nobody voided yet is refused and VOIDED."""
    effect = approved_and_planned(world)
    world.set_run(status)
    result = world.refused("G10", effect, reason="run_not_active")
    assert result.effect.status is EffectStatus.VOIDED, f"G10: effect on a {status.value} run"


@pytest.mark.parametrize("status", [RunStatus.BLOCKED, RunStatus.WAITING_HUMAN])
def test_G10_a_run_that_is_not_active_holds_the_effect_and_writes_nothing(
    world: World, status: RunStatus
) -> None:
    effect = approved_and_planned(world)
    world.set_run(status)
    result = world.refused("G10", effect, reason="held")
    assert result.effect.status is EffectStatus.PLANNED, "G10: a held effect must stay PLANNED"
    world.set_run(RunStatus.RUNNING)  # control: the run comes back, and the same effect writes
    assert world.go(effect).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


def test_G10_the_run_stopping_between_the_read_and_the_claim_wins(world: World) -> None:
    """PLAN 4.3 rule 1: the claim holds a check on the run, so a Stop that commits after the claim
    read the run (and before the claim commits) makes the claim lose."""
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.set_run(RunStatus.CANCELLING))
    result = calls_cleanly("G10: a claim that lost to the run stopping", lambda: world.go(effect))
    assert world.writes == [], "G10: the claim won over a run that went to CANCELLING first"
    assert result.effect.status is EffectStatus.VOIDED
    assert result.reason == "run_not_active"


# --- the atomic checks of the claim (PLAN 4.3 rule 1) -------------------------------------------


def test_G1_a_gate_that_stops_being_approved_between_the_read_and_the_claim_wins(
    world: World,
) -> None:
    effect = approved_and_planned(world)
    rejected = dataclasses.replace(world.gate(), status=GateStatus.REJECTED)
    key = Key(f"RUN#{world.run.id}", "GATE#review#1")
    world.store.before.append(lambda: world.store.inner.put(SCOPE, key, to_wire(rejected)))
    result = calls_cleanly("G1: a claim that lost to a gate change", lambda: world.go(effect))
    assert world.writes == [], "G1: the claim won over a gate that changed before it committed"
    assert result.reason == "gate_invalid"


def test_G1_a_later_round_opening_between_the_read_and_the_claim_wins(world: World) -> None:
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.open(round=2))
    result = calls_cleanly("G1: a claim that lost to a new round", lambda: world.go(effect))
    assert world.writes == [], "G1: the claim won over a round that opened before it committed"
    assert result.reason == "gate_invalid"


def test_G1_a_round_that_skips_a_number_between_the_read_and_the_claim_wins(world: World) -> None:
    """Round 3 opens while round 2 never did: the next-round check (round 2 absent) cannot see it,
    only the audit chain head can (the AuditWriter port's stated requirement)."""
    effect = approved_and_planned(world)
    world.store.before.append(lambda: world.open(round=3))
    result = calls_cleanly("G1: a claim that lost to a skipped round", lambda: world.go(effect))
    assert world.writes == [], "G1: the claim won over a gate round that skipped a number"
    assert result.reason == "gate_invalid"


def test_G1_the_next_round_check_holds_even_if_the_audit_writer_does_not_move_the_chain() -> None:
    """Defence in depth: with a writer that records nothing (so the chain head never moves), the
    claim's own check that round N+1 is absent still stops a claim racing a new round."""

    class NoAudit:
        def ops(self, reader: Reader, scope: Scope, entry: AuditEntry) -> list[Op]:
            return []

    store = HookStore(MemoryStore())
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
    store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
    w = World(store, GateService(store, audit=NoAudit()), EffectExecutor(store, SCOPE), run)
    effect = approved_and_planned(w)
    store.before.append(lambda: w.open(round=2))
    result = calls_cleanly("G1: a claim that lost to a new round", lambda: w.go(effect))
    assert w.writes == [], "G1: the claim won over a round that opened before it committed"
    assert result.reason == "gate_invalid"


# --- the ledger half of the approval check ------------------------------------------------------


def test_G1_control_a_planted_approving_decision_for_this_gate_and_digest_releases(
    world: World,
) -> None:
    world.plant_approved_gate()
    assert world.go(world.plan()).effect.status is EffectStatus.CONFIRMED
    assert len(world.writes) == 1


@pytest.mark.parametrize(
    "plant",
    [
        {"decision": None},
        {"decision": DecisionKind.REJECT},
        {"decision": DecisionKind.REQUEST_CHANGES},
        {"digest": MOVED.digest()},
        {"of_gate": False},
    ],
    ids=["no_decision", "reject", "request_changes", "other_digest", "other_gate"],
)
def test_G1_an_approved_gate_without_a_matching_approving_decision_releases_nothing(
    world: World, plant: dict[str, Any]
) -> None:
    """The executor does not trust the gate row alone: it needs an approving decision on this
    gate's own id, bound to this gate's own subject digest (PLAN 4.3 rule 2, ADR-0005 #1)."""
    world.plant_approved_gate(**plant)
    world.refused("G1", world.plan())


# --- after a merge: the frozen subject (PLAN 4.3 rule 2) ----------------------------------------


class MergedHandler:
    """A merge that landed: ``Written`` with the subject frozen at the merge commit."""

    def __init__(self, world: World) -> None:
        self.world = world

    def execute(self, effect: Effect) -> Written:
        self.world.writes.append(effect.idempotency_key)
        frozen = dataclasses.replace(SUBJECT, merge_sha="m1")
        return Written(Receipt("m-1", "", read_back_verified=True), frozen)

    poll = stop = reconcile = execute


def merged_world(world: World) -> None:
    """Approve the review gate, then confirm a merge, so later effects compare with the merge."""
    world.decide(world.open(), DecisionKind.APPROVE)
    merge = world.fx.plan(
        world.run.id, "pr.merge", "merge", 1, EffectClass.GATED, SUBJECT.digest(),
        requires_gates=("review",), subject=SUBJECT,
    )  # fmt: skip
    done = world.fx.execute(world.run.id, merge.idempotency_key, MergedHandler(world), live=SUBJECT)
    assert done.effect.status is EffectStatus.CONFIRMED, "G1: control: the merge confirms"
    world.writes.clear()


def after_merge(world: World, subject: Subject = SUBJECT, visit: int = 2) -> Effect:
    return world.fx.plan(
        world.run.id, "pr.mark_ready", "after", visit, EffectClass.GATED, subject.digest(),
        requires_gates=("review",), subject=subject,
    )  # fmt: skip


def test_G1_after_a_merge_a_later_gated_effect_for_the_merged_head_writes_even_if_live_moved(
    world: World,
) -> None:
    """Control for the frozen path: once merged, the live subject is the base branch and is not
    compared; the planned head and the gate are compared with the merged head."""
    merged_world(world)
    result = world.go(after_merge(world), live=MOVED)
    assert result.effect.status is EffectStatus.CONFIRMED, f"G1: refused for {result.reason!r}"
    assert len(world.writes) == 1


def test_G1_after_a_merge_an_effect_planned_for_another_head_never_writes(world: World) -> None:
    merged_world(world)
    world.refused("G1", after_merge(world, subject=MOVED), live=None)


def test_G1_after_a_merge_a_gate_approved_at_another_head_never_releases_a_write(
    world: World,
) -> None:
    merged_world(world)
    # a second gate, approved for a different head than the one that was merged
    other = world.open("extra", subject=MOVED)
    world.decide(other, DecisionKind.APPROVE)
    effect = world.fx.plan(
        world.run.id, "pr.mark_ready", "after", 2, EffectClass.GATED, SUBJECT.digest(),
        requires_gates=("extra",), subject=SUBJECT,
    )  # fmt: skip
    world.refused("G1", effect, live=None)


def test_G1_a_subject_with_no_head_never_releases_a_write(world: World) -> None:
    """A pre-push subject has no head. None equals None, which must not pass as a match."""
    bare = PRE_PUSH
    world.decide(world.open(subject=bare, gate_type=GateType.PRE_PUSH), DecisionKind.APPROVE)
    world.refused("G1", world.plan(subject=bare), live=bare)


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


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        (DecisionKind.APPROVE, GateStatus.APPROVED),
        (DecisionKind.REJECT, GateStatus.REJECTED),
        (DecisionKind.REQUEST_CHANGES, GateStatus.CHANGES_REQUESTED),
        (DecisionKind.RETEST, GateStatus.RETEST),
    ],
)
def test_G3_each_decision_closes_the_gate_with_its_own_status(
    world: World, kind: DecisionKind, status: GateStatus
) -> None:
    """Only an approval closes a gate as APPROVED. A retest or a request for changes that closed
    it as APPROVED (or a reject as anything else) would release or lose a veto."""
    gate = world.open("qa", gate_type=GateType.QA)
    decided = world.decide(gate, kind)
    assert decided.gate.status is status, (
        f"G3: {kind.value} closed the gate as {decided.gate.status}"
    )
    assert world.gate("qa").status is status
    effect = world.plan(gates=("qa",))
    if status is GateStatus.APPROVED:
        assert world.go(effect).effect.status is EffectStatus.CONFIRMED
    else:
        world.refused("G3", effect)


def test_G1_a_negative_decision_in_a_later_round_invalidates_the_earlier_approval(
    world: World,
) -> None:
    first = world.open()
    world.decide(first, DecisionKind.APPROVE)
    second = world.open(round=2)
    world.decide(second, DecisionKind.REJECT)
    assert world.gate(round=1).status is GateStatus.INVALIDATED, (
        "G1: an earlier approval stayed usable after a later round was refused"
    )


def test_G3_concurrent_approve_and_reject_close_the_gate_once_whoever_wins() -> None:
    """Real interleaving: exactly one decision closes the gate, and if the reject won the writer
    never runs. (Each commit order is also pinned, deterministically, by the two tests above.)"""
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
        calls_cleanly("G3: the effect after the close", lambda w=w, e=effect: w.go(e))  # type: ignore[misc]
        if winners[0].decision.kind is DecisionKind.REJECT:
            assert w.writes == [], "G3: the writer ran although the reject closed the gate"
        else:
            assert len(w.writes) == 1, "G3: control: the approval won, so the writer ran once"


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
    assert_two_audit_entries(world)


def test_G5_a_closed_gate_answers_409_to_every_later_decision(world: World) -> None:
    gate = world.open()
    world.decide(gate, DecisionKind.APPROVE, actor="alice")
    for kind in (DecisionKind.APPROVE, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES):
        err = refused_as_closed("G5", lambda k=kind: world.decide(gate, k, actor="bob"))  # type: ignore[misc]
        assert err.status is GateStatus.APPROVED
        assert err.closed_by == "alice"
    assert world.count("DEC#") == 1, "G5: a refused decision left a decision in the ledger"
    assert_two_audit_entries(world)


def test_G5_a_store_conflict_is_retried_and_the_decision_lands_exactly_once(
    world: World,
) -> None:
    gate = world.open()

    def conflict() -> None:
        raise TransactionConflictError("another transaction won")

    world.store.before.append(conflict)
    decided = calls_cleanly(
        "G5: a transient store conflict is retried",
        lambda: world.decide(gate, DecisionKind.APPROVE),
    )
    assert decided.gate.status is GateStatus.APPROVED
    assert world.count("DEC#") == 1
    assert_two_audit_entries(world)


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
