"""D1-07: effects are claimed atomically, gated ones need a live approval, and status comes only
from a receipt (PLAN 4.3 rules 1, 2 and 5, 6.3, ADR-0011).

Every test runs on the in-memory and the SQLite store. Races are deterministic: ``HookStore``
runs a callback just before the next transaction, so "Stop commits between the read and the
claim" is a line of code, not a timing hope.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import (
    MergeHandle,
    MergeMethod,
    MergeReason,
    MergeResult,
    MergeState,
    PrRef,
    PrSpec,
    RepoRef,
)
from sto.domain import (
    Decision,
    DecisionId,
    DecisionKind,
    Effect,
    EffectClass,
    EffectStatus,
    Gate,
    GateId,
    GateStatus,
    GateType,
    PermanentError,
    Receipt,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    Surface,
    TransientError,
    to_wire,
)
from sto.effects.core import EffectExecutor, ExecResult, StopReport, set_switch
from sto.effects.ports import (
    CallHandler,
    EffectHandler,
    Failed,
    MergeHandler,
    Pending,
    Written,
    effect_item_key,
)
from sto.engine.commands import OpenGate, RunEffect
from sto.engine.handlers.core import GateClosed, RunStarted, StepSucceeded
from sto.engine.reducer import LINEAR_V0, RunState, load_handlers, next
from sto.gates.service import Decided, GateService
from sto.store.memory import MemoryStore
from sto.store.ports import (
    MAIN,
    PLATFORM,
    TEAM_ROOT,
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
from sto.store.sqlite import SqliteStore

SCOPE = TeamScope("acme")
REPO = RepoRef("acme", "app")
SUBJECT = Subject(
    patch_id="p1",
    ticket_revision="r1",
    head_sha="h1",
    evidence_digest="e1",
    attention_digest="a1",
)
DIGEST = SUBJECT.digest()
TEAM_META = Key(TEAM_ROOT, "META")
FLEET = Key("ORG", "SWITCHES")


class HookStore:
    """A store that delegates, can cap page size, and runs queued hooks before transactions."""

    def __init__(self, inner: Store, page_limit: int | None = None) -> None:
        self.inner, self.page_limit = inner, page_limit
        self.hooks: list[Callable[[Sequence[Op]], object]] = []
        self.after_hooks: list[Callable[[], object]] = []

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
        if self.page_limit:
            limit = min(limit or self.page_limit, self.page_limit)
        return self.inner.query(
            scope, pk, table=table, sk_prefix=sk_prefix, limit=limit, cursor=cursor
        )

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        if self.hooks:
            self.hooks.pop(0)(ops)
        self.inner.transact(scope, ops)
        if self.after_hooks:
            self.after_hooks.pop(0)()

    def put(
        self, scope: Scope, key: Key, data: Mapping[str, Any], *, when: Condition | None = None
    ) -> None:
        self.transact(scope, [Put(key, dict(data), when=when)])

    def delete(self, scope: Scope, key: Key, *, when: Condition | None = None) -> None:
        self.inner.delete(scope, key, when=when)

    def before_next_transaction(self, hook: Callable[[], object]) -> None:
        self.hooks.append(lambda _ops: hook())

    def after_next_transaction(self, hook: Callable[[], object]) -> None:
        """Runs once the next transaction has committed (so: just after a claim)."""
        self.after_hooks.append(hook)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# The store contract suite (tests/store/store_contract.py) proves the stores equivalent, so most
# tests here run on memory only. The races, the demo merge and one lifecycle also run on SQLite.
both_stores = pytest.mark.parametrize("inner", ["memory", "sqlite"], indirect=True)


@pytest.fixture
def inner(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Store]:
    if getattr(request, "param", "memory") == "memory":
        yield MemoryStore()
    else:
        sqlite = SqliteStore(tmp_path / "fx.db")
        yield sqlite
        sqlite.close()


@dataclass
class World:
    store: HookStore
    fx: EffectExecutor
    scm: FakeScm
    run: Run
    pr: PrRef
    clock: Clock
    svc: GateService

    def run_key(self) -> Key:
        return Key(f"RUN#{self.run.id}", "META")

    def set_run(self, status: RunStatus) -> None:
        self.run = dataclasses.replace(
            self.run,
            status=status,
            blocked_reason="kill_switch" if status is RunStatus.BLOCKED else None,
            version=self.run.version + 1,
        )
        self.store.put(SCOPE, self.run_key(), to_wire(self.run))

    def gate(
        self,
        name: str = "review",
        round: int = 1,
        subject: Subject = SUBJECT,
        close: DecisionKind | None = None,
        gate_type: GateType = GateType.REVIEW,
    ) -> Gate:
        """Open a gate through the real ``GateService`` (and close it with ``close``, if given),
        so the keys, the decision ledger and the audit chain are what #273 really writes."""
        opened = self.svc.open_gate(SCOPE, OpenGate(self.run.id, name, gate_type, round, subject))
        if close is None:
            return opened
        return self.close(opened, close).gate

    def close(self, gate: Gate, kind: DecisionKind) -> Decided:
        return self.svc.decide(
            SCOPE,
            run_id=self.run.id,
            gate=gate.name,
            round=gate.round,
            kind=kind,
            actor="alice",
            surface=Surface.UI,
            subject_digest=gate.subject.digest(),
            comment="" if kind is DecisionKind.APPROVE else "no",
        )

    def approve(self, **kw: Any) -> tuple[Gate, Decision]:
        decided = self.close(self.gate(**kw), DecisionKind.APPROVE)
        return decided.gate, decided.decision

    def raw_gate(self, status: GateStatus, subject: Subject = SUBJECT) -> Gate:
        """A gate the service cannot produce (defence in depth against bad data)."""
        gate = Gate(GateId.new(), self.run.id, "review", GateType.REVIEW, 1, subject, status)
        self.store.put(SCOPE, Key(f"RUN#{self.run.id}", "GATE#review#1"), to_wire(gate))
        return gate

    def raw_decision(
        self,
        gate: Gate,
        kind: DecisionKind,
        digest: str,
        id_: DecisionId | None = None,
        gate_id: GateId | None = None,
    ) -> Decision:
        d = Decision(
            id_ or DecisionId.new(),
            gate_id or gate.id,
            gate.round,
            "alice",
            Surface.UI,
            kind,
            digest,
            "ok",
        )
        key = Key(f"RUN#{self.run.id}", f"DEC#{gate.name}#{gate.round}#{d.id}")
        self.store.put(SCOPE, key, to_wire(d))
        return d

    def plan(self, type_: str = "pr.mark_ready", klass: EffectClass = EffectClass.GATED) -> Effect:
        gates = ("review",) if klass is EffectClass.GATED else ()
        return self.fx.plan(
            self.run.id,
            type_,
            "merge",
            1,
            klass,
            DIGEST,
            requires_gates=gates,
            subject=SUBJECT if klass is EffectClass.GATED else None,
        )

    def effect(self, e: Effect) -> Effect:
        return self.fx.get(self.run.id, e.idempotency_key)

    def go(
        self,
        e: Effect,
        handler: EffectHandler | None = None,
        live: Subject | None = SUBJECT,
    ) -> ExecResult:
        return self.fx.execute(self.run.id, e.idempotency_key, handler or self.ready(), live=live)

    def ready(self) -> CallHandler:
        return CallHandler(lambda key: self.scm.mark_ready(self.pr, key))

    def merger(self, subject: Subject = SUBJECT, sha: str = "h1") -> MergeHandler:
        return MergeHandler(self.scm, self.pr, sha, MergeMethod.SQUASH, subject)

    def force(self, e: Effect, **changes: Any) -> Effect:
        """Write a record in a state the executor would only reach by crashing."""
        meta = changes.pop("meta", {})
        forced = dataclasses.replace(self.effect(e), **changes)
        key = effect_item_key(self.run.id, e.idempotency_key)
        self.store.put(SCOPE, key, {"effect": to_wire(forced), "meta": meta})
        return forced


@pytest.fixture
def world(inner: Store) -> World:
    store = HookStore(inner)
    clock = Clock()
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
    scm = FakeScm()
    scm.seed_branch(REPO, "main", "b0")
    scm.seed_branch(REPO, "sto/x", "h1", parent="b0")
    receipt = scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k-pr")
    fx = EffectExecutor(store, SCOPE, clock=clock)
    w = World(store, fx, scm, run, PrRef.of(REPO, receipt), clock, GateService(store))
    store.put(SCOPE, w.run_key(), to_wire(run))
    scm.spy.clear()
    return w


def calls_cleanly[T](what: str, fn: Callable[[], T]) -> T:
    """Run ``fn``; if it crashes, fail with an assertion that names the behaviour that broke. A
    mutant that breaks an invariant by raising is then caught by an assertion, and the failure
    shows ``what`` (not a bare traceback)."""
    try:
        return fn()
    except Exception as exc:
        raise AssertionError(f"{what}, but it raised {exc!r}") from None


def _receipt(writes: list[str], key: str) -> Receipt:
    writes.append(key)
    return Receipt("x-1", "", read_back_verified=True)


# --- AC1: a gated effect with no approval never calls the writer ---------------------------


def test_gated_effect_with_no_gate_never_calls_writer(world: World) -> None:
    e = world.plan()
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED
    assert result.reason == "gate_invalid"
    assert world.scm.pr_state(world.pr) == "draft"


@pytest.mark.parametrize("close", [None, DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES])
def test_gated_effect_with_gate_not_approved_never_calls_writer(
    world: World, close: DecisionKind | None
) -> None:
    world.gate(close=close)
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


def test_a_veto_in_a_newer_round_voids_the_earlier_approval(world: World) -> None:
    """PLAN 4.3.3: the service invalidates round 1 when round 2 closes negative."""
    first, _ = world.approve()
    world.close(world.gate(round=2), DecisionKind.REJECT)
    item = world.store.get(SCOPE, Key(f"RUN#{world.run.id}", "GATE#review#1"))
    assert item is not None
    assert item.data["status"] == GateStatus.INVALIDATED.value  # the service did the voiding
    assert first.status is GateStatus.APPROVED
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_approval_of_another_head_does_not_count(world: World) -> None:
    other = dataclasses.replace(SUBJECT, head_sha="h2")
    world.approve(subject=other)
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


def test_a_decision_bound_to_another_digest_does_not_count(world: World) -> None:
    gate = world.raw_gate(GateStatus.APPROVED)  # the service refuses such a decision
    world.raw_decision(gate, DecisionKind.APPROVE, "not-this-subject")
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_approved_gate_without_an_approving_decision_does_not_count(world: World) -> None:
    gate = world.raw_gate(GateStatus.APPROVED)  # the service cannot approve without one
    world.raw_decision(gate, DecisionKind.REJECT, gate.subject.digest())
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_only_the_latest_gate_instance_counts(world: World) -> None:
    world.approve()
    world.gate(round=2)  # a newer round re-opened the gate
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_round_ten_is_later_than_round_nine(world: World) -> None:
    world.approve(round=9)
    world.gate(round=10)
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_gated_effect_with_live_approval_runs_and_records_the_decisions(world: World) -> None:
    _, decision = world.approve()
    e = world.plan()
    result = world.go(e)
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert result.edge == "done"
    assert done.decision_ids == (decision.id,)
    assert done.subject_digest == DIGEST
    assert len(world.scm.spy.applied("mark_ready")) == 1
    assert world.scm.pr_state(world.pr) == "ready"


def test_a_gated_effect_must_name_its_gates(world: World) -> None:
    with pytest.raises(ValueError, match="requires_gates"):
        world.fx.plan(
            world.run.id, "pr.merge", "merge", 1, EffectClass.GATED, DIGEST, subject=SUBJECT
        )


@pytest.mark.parametrize("klass", [EffectClass.INTERNAL, EffectClass.EXPOSING])
def test_v0_plans_only_scoped_and_gated_effects(world: World, klass: EffectClass) -> None:
    with pytest.raises(ValueError, match="scoped or gated"):
        world.fx.plan(world.run.id, "x", "merge", 1, klass, DIGEST)


def test_a_gated_effect_cannot_run_without_the_live_subject(world: World) -> None:
    world.approve()
    e = world.plan()
    with pytest.raises(ValueError, match="live subject"):
        world.go(e, live=None)
    assert world.scm.spy.calls == ()


# --- PLAN 4.3.2: the merge needs both gates, each at its own digest, at the same head ------------


@dataclass
class Demo:
    fx: EffectExecutor
    rid: RunId
    e: Effect
    merger: MergeHandler
    cmd: RunEffect
    scm: FakeScm
    approvals: dict[str, Decided]


def _demo(inner: Store) -> Demo:
    """The reducer decides the commands and the real ``GateService`` carries them out. The ticket
    is edited between the review gate and QA, which PLAN 272 says the QA gate simply shows."""
    load_handlers()
    rid = RunId.new()
    review = dataclasses.replace(SUBJECT, evidence_digest="review-evidence")
    qa = dataclasses.replace(SUBJECT, evidence_digest="qa-evidence", ticket_revision="r2")
    assert review.digest() != qa.digest()
    store = HookStore(inner)
    store.put(
        SCOPE,
        Key(f"RUN#{rid}", "META"),
        to_wire(Run(rid, "acme", RunStatus.RUNNING, version=1, stage="merge")),
    )
    svc = GateService(store)
    state = RunState(Run(id=rid, team="acme"))
    approvals: dict[str, Decided] = {}

    def feed(event: Any) -> tuple[object, ...]:
        nonlocal state
        t = next(state, event, LINEAR_V0)
        state = t.state
        return t.commands

    def approve(cmd: OpenGate) -> GateClosed:
        svc.open_gate(SCOPE, cmd)
        d = svc.decide(
            SCOPE,
            run_id=rid,
            gate=cmd.name,
            round=cmd.round,
            kind=DecisionKind.APPROVE,
            actor="alice",
            surface=Surface.UI,
            subject_digest=cmd.subject.digest(),
        )
        approvals[cmd.name] = d
        return GateClosed(
            rid, cmd.name, cmd.round, DecisionKind.APPROVE, "alice", d.decision.id, cmd.subject
        )

    feed(RunStarted(rid))
    (open_review,) = feed(StepSucceeded(StepKey(rid, "implement", 1, 1), review))
    assert isinstance(open_review, OpenGate)
    feed(approve(open_review))
    (open_qa,) = feed(StepSucceeded(StepKey(rid, "qa", 1, 1), qa))
    assert isinstance(open_qa, OpenGate)
    (cmd,) = feed(approve(open_qa))
    assert isinstance(cmd, RunEffect)
    assert cmd.subject_digest == qa.digest()
    assert cmd.decision_ids == (
        approvals["review_gate"].decision.id,
        approvals["qa_gate"].decision.id,
    )

    scm = FakeScm()
    scm.seed_branch(REPO, "main", "b0")
    assert cmd.subject.head_sha is not None
    scm.seed_branch(REPO, "sto/x", cmd.subject.head_sha, parent="b0")
    pr = PrRef.of(REPO, scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k"))
    scm.mark_ready(pr, "k2")
    fx = EffectExecutor(store, SCOPE)
    e = fx.plan(
        rid,
        cmd.type,
        cmd.stage,
        cmd.visit,
        EffectClass.GATED,
        cmd.subject_digest,
        requires_gates=cmd.requires_gates,
        subject=cmd.subject,
    )
    merger = MergeHandler(scm, pr, cmd.subject.head_sha, MergeMethod.SQUASH, cmd.subject)
    return Demo(fx, rid, e, merger, cmd, scm, approvals)


@both_stores
def test_the_real_reducers_merge_runs_with_approvals_from_both_gates(inner: Store) -> None:
    d = _demo(inner)
    fresh = dataclasses.replace(d.cmd.subject)  # re-read now: same ticket, same head
    first = d.fx.execute(d.rid, d.e.idempotency_key, d.merger, live=fresh)
    assert first.effect.status is EffectStatus.ACCEPTED
    assert first.effect.decision_ids == d.cmd.decision_ids
    d.scm.complete_merge(d.scm.merges()[-1], "m1")
    done = d.fx.poll(d.rid, d.e.idempotency_key, d.merger)
    assert done.effect.status is EffectStatus.CONFIRMED


@both_stores
def test_the_real_reducers_merge_is_refused_when_a_fresh_read_shows_a_ticket_edit(
    inner: Store,
) -> None:
    d = _demo(inner)
    fresh = dataclasses.replace(d.cmd.subject, ticket_revision="r3")  # edited after QA approval
    result = d.fx.execute(d.rid, d.e.idempotency_key, d.merger, live=fresh)
    assert result.reason == "gate_invalid"
    assert d.scm.merges() == []


def test_one_gate_approved_at_another_head_voids_the_merge(world: World) -> None:
    world.approve(name="review")
    world.approve(name="qa", subject=dataclasses.replace(SUBJECT, head_sha="h0"))
    e = world.fx.plan(
        world.run.id,
        "pr.merge",
        "merge",
        1,
        EffectClass.GATED,
        DIGEST,
        requires_gates=("review", "qa"),
        subject=SUBJECT,
    )
    world.go(e, world.merger())
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


# --- the claim checks the run and the switches ---------------------------------------------


@pytest.mark.parametrize("status", [RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE])
def test_a_run_that_is_stopping_voids_a_gated_effect_unwritten(
    world: World, status: RunStatus
) -> None:
    world.approve()
    e = world.plan()
    world.set_run(status)
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"
    assert world.effect(e).status is EffectStatus.VOIDED


@pytest.mark.parametrize("status", [RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE])
def test_a_scoped_effect_still_runs_on_a_stopped_run(world: World, status: RunStatus) -> None:
    """PLAN 6.2: the revert PR after Stop, ``pr.close`` on reject, check runs."""
    e = world.plan("pr.open_revert", EffectClass.SCOPED)
    world.set_run(status)
    result = world.go(e)
    assert result.edge == "done"
    assert world.effect(e).status is EffectStatus.CONFIRMED
    assert len(world.scm.spy.calls_for("mark_ready")) == 1


def test_a_run_that_is_waiting_holds_a_gated_effect(world: World) -> None:
    world.approve()
    e = world.plan()
    world.set_run(RunStatus.WAITING_HUMAN)
    result = world.go(e)
    assert result.reason == "held"
    assert world.effect(e).status is EffectStatus.PLANNED


def test_a_missing_run_voids_the_effect(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.store.delete(SCOPE, world.run_key())
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"


def test_no_switch_written_means_not_off(world: World) -> None:
    world.approve()
    e = world.plan("pr.merge")  # no team or fleet item exists at all
    assert world.go(e).edge == "done"


@pytest.mark.parametrize("value", [False, "off", 0, None, "true"])
@pytest.mark.parametrize("fleet", [False, True])
def test_a_switch_that_is_not_exactly_true_is_off(world: World, fleet: bool, value: object) -> None:
    world.approve()
    e = world.plan("pr.merge")
    scope = PLATFORM if fleet else SCOPE
    world.store.put(scope, FLEET if fleet else TEAM_META, {"switch_merge": value})
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "held"
    assert world.effect(e).status is EffectStatus.PLANNED


def test_a_switch_that_is_true_is_on_and_an_unrelated_one_is_ignored(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.store.put(SCOPE, TEAM_META, {"switch_effects": True, "switch_merge": False})
    assert world.go(e).edge == "done"  # pr.update_branch has no merge switch


@pytest.mark.parametrize(
    ("effect_type", "switch"), [("pr.update_branch", "effects"), ("release.trigger", "release")]
)
@pytest.mark.parametrize("fleet", [False, True])
def test_each_effect_checks_its_own_switches(
    world: World, effect_type: str, switch: str, fleet: bool
) -> None:
    world.approve()
    klass = EffectClass.GATED if effect_type == "release.trigger" else EffectClass.SCOPED
    e = world.plan(effect_type, klass)
    set_switch(world.store, SCOPE, switch, False, fleet=fleet)
    assert world.go(e).reason == "held"
    assert world.scm.spy.calls == ()
    set_switch(world.store, SCOPE, switch, True, fleet=fleet)  # released: it re-runs its guards
    assert world.go(e).edge == "done"


@pytest.mark.parametrize("fleet", [False, True])
@both_stores
def test_a_switch_turned_off_between_the_read_and_the_claim_aborts_the_claim(
    world: World, fleet: bool
) -> None:
    world.approve()
    e = world.plan("pr.merge")
    set_switch(world.store, SCOPE, "effects", True, fleet=fleet)  # the item exists when read
    world.store.before_next_transaction(
        lambda: set_switch(world.store, SCOPE, "merge", False, fleet=fleet)
    )
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "held"
    assert world.effect(e).status is EffectStatus.PLANNED


@pytest.mark.parametrize("fleet", [False, True])
@both_stores
def test_a_switch_item_created_between_the_read_and_the_claim_aborts_the_claim(
    world: World, fleet: bool
) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)  # no switch item when read
    world.store.before_next_transaction(
        lambda: set_switch(world.store, SCOPE, "effects", False, fleet=fleet)
    )
    assert world.go(e).reason == "held"
    assert world.scm.spy.calls == ()


@both_stores
def test_set_switch_keeps_a_concurrent_change(world: World) -> None:
    set_switch(world.store, SCOPE, "merge", True)
    world.store.before_next_transaction(lambda: set_switch(world.store, SCOPE, "effects", False))
    set_switch(world.store, SCOPE, "release", True)  # read before the change, written after it
    item = world.store.get(SCOPE, TEAM_META)
    assert item is not None
    assert item.data == {"switch_merge": True, "switch_effects": False, "switch_release": True}


# --- AC2 and AC3: cancel -----------------------------------------------------------------------


def test_cancel_voids_a_planned_effect(world: World) -> None:
    world.approve()
    e = world.plan()
    report = world.fx.void_planned(world.run.id)
    assert [x.id for x in report.voided] == [e.id]
    assert report.in_flight == ()
    assert world.effect(e).status is EffectStatus.VOIDED
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.effect.status is EffectStatus.VOIDED
    assert result.reason == "cancelled"


def test_cancel_voids_every_planned_effect_across_pages(world: World) -> None:
    world.store.page_limit = 1
    planned = [
        world.fx.plan(world.run.id, f"t{i}", "s", 1, EffectClass.SCOPED, DIGEST) for i in range(3)
    ]
    report = world.fx.void_planned(world.run.id)
    assert len(report.voided) == 3
    assert all(world.effect(e).status is EffectStatus.VOIDED for e in planned)


def test_cancel_reports_a_retrying_effect_instead_of_voiding_it(world: World) -> None:
    """A lost response may have landed, so VOIDED would be a false statement (PLAN 14.3)."""
    world.approve()
    e = world.plan()
    world.scm.lose_response_next("mark_ready")
    world.go(e)
    report = world.fx.void_planned(world.run.id)
    assert report.voided == ()
    assert [x.id for x in report.in_flight] == [e.id]
    assert world.effect(e).status is EffectStatus.RETRYING


def test_cancel_reports_an_attempting_effect_as_possibly_landed(world: World) -> None:
    world.approve()
    e = world.plan()
    seen: list[StopReport] = []

    def write(key: str) -> Receipt:
        seen.append(world.fx.void_planned(world.run.id))  # Stop arrives mid-write
        return world.scm.mark_ready(world.pr, key)

    world.go(e, CallHandler(write))
    assert seen[0].voided == ()
    assert [x.id for x in seen[0].in_flight] == [e.id]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_void_leaves_finished_effects_alone(world: World) -> None:
    world.approve()
    e = world.plan()
    world.go(e)
    report = world.fx.void_planned(world.run.id)
    assert report.voided == ()
    assert report.in_flight == ()
    assert world.effect(e).status is EffectStatus.CONFIRMED


@both_stores
def test_stop_committing_before_the_claim_wins_and_nothing_is_written(world: World) -> None:
    """Deterministic: the void commits between the claim's read and its transaction."""
    e = world.fx.plan(world.run.id, "pr.update_branch", "s", 1, EffectClass.SCOPED, DIGEST)
    reports: list[StopReport] = []
    world.store.before_next_transaction(lambda: reports.append(world.fx.void_planned(world.run.id)))
    result = world.go(e)
    assert [x.id for x in reports[0].voided] == [e.id]
    assert world.scm.spy.calls == ()
    assert result.effect.status is EffectStatus.VOIDED


@both_stores
def test_the_claim_committing_before_stop_wins_and_stop_voids_nothing(world: World) -> None:
    """Deterministic: the claim commits between the void's read and its transaction."""
    e = world.fx.plan(world.run.id, "pr.update_branch", "s", 1, EffectClass.SCOPED, DIGEST)
    writes: list[str] = []

    def claim() -> None:
        world.go(e, CallHandler(lambda k: _receipt(writes, k)))

    world.store.before_next_transaction(claim)
    report = world.fx.void_planned(world.run.id)
    assert report.voided == ()  # the void lost: it neither overwrote the claim nor reports a void
    assert writes == [e.idempotency_key]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def _race_once(inner: Store) -> tuple[Effect, StopReport, list[str]]:
    store = HookStore(inner)
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="s")
    store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
    fx = EffectExecutor(store, SCOPE)
    e = fx.plan(run.id, "pr.update_branch", "s", 1, EffectClass.SCOPED, DIGEST)
    writes: list[str] = []
    reports: list[StopReport] = []
    start = threading.Barrier(2)

    def claimer() -> None:
        start.wait()
        fx.execute(run.id, e.idempotency_key, CallHandler(lambda k: _receipt(writes, k)))

    def canceller() -> None:
        start.wait()
        reports.append(fx.void_planned(run.id))

    threads = [threading.Thread(target=claimer), threading.Thread(target=canceller)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return fx.get(run.id, e.idempotency_key), reports[0], writes


@both_stores
def test_concurrent_cancel_and_claim_have_exactly_one_winner(inner: Store) -> None:
    """Real threads, as a smoke test of the deterministic tests above."""
    for _ in range(20):
        final, report, writes = _race_once(inner)
        if final.status is EffectStatus.VOIDED:
            assert writes == []
            assert len(report.voided) == 1
        else:
            assert final.status is EffectStatus.CONFIRMED
            assert len(writes) == 1
            assert report.voided == ()


@both_stores
def test_stop_between_the_read_and_the_claim_aborts_a_gated_claim(world: World) -> None:
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(lambda: world.set_run(RunStatus.CANCELLING))
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"


@both_stores
def test_a_gate_invalidated_between_the_read_and_the_claim_aborts_the_claim(world: World) -> None:
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(
        lambda: world.close(world.gate(round=2), DecisionKind.REJECT)  # invalidates round 1
    )
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "gate_invalid"


@both_stores
def test_a_gate_item_changed_without_moving_the_chain_still_aborts_the_claim(
    world: World,
) -> None:
    """Defence in depth: the service always moves the chain, but the claim also holds the gate
    item's own version, so a write that bypasses the service is caught too."""
    gate, _ = world.approve()
    e = world.plan()
    invalid = gate.advance(GateStatus.INVALIDATED)
    world.store.before_next_transaction(
        lambda: world.store.put(
            SCOPE, Key(f"RUN#{world.run.id}", "GATE#review#1"), to_wire(invalid)
        )
    )
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "gate_invalid"


class NoChainAudit:
    """An ``AuditWriter`` that records nothing and so never moves ``RUN#r/CHAIN``. It shows the
    claim's second line of defence (the next round's key) works without the chain."""

    def ops(self, reader: object, scope: object, entry: object) -> list[Op]:
        return []


@pytest.mark.parametrize("round", [2, 3])  # the next round, and a skipped number
@both_stores
def test_a_newer_gate_round_opened_before_the_claim_aborts_it(world: World, round: int) -> None:
    """PLAN 4.3.2: the latest instance counts. The real service opens the round, and its
    ``ChainedAuditWriter`` moves ``CHAIN``, which the claim checks (this alone covers skipped
    numbers)."""
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(lambda: world.gate(round=round))
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "gate_invalid"


@both_stores
def test_the_next_round_is_checked_even_if_the_audit_writer_never_moves_the_chain(
    world: World,
) -> None:
    world.svc = GateService(world.store, audit=NoChainAudit())
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(lambda: world.gate(round=2))
    result = world.go(e)
    assert world.scm.spy.calls == ()
    assert result.reason == "gate_invalid"


@both_stores
def test_other_gate_activity_moves_the_chain_and_the_claim_simply_retries(world: World) -> None:
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(lambda: world.gate(name="qa"))  # moves CHAIN
    world.go(e)
    # the first claim aborted, then the loop re-read and the approval still held
    assert world.effect(e).status is EffectStatus.CONFIRMED


# --- AC4: status comes only from a receipt -----------------------------------------------------


def test_a_receipt_without_read_back_is_not_confirmed_and_a_retry_confirms(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.read_back_verified = False
    first = world.go(e)
    mid = world.effect(e)
    assert first.effect.status is EffectStatus.RETRYING
    assert mid.receipt is None
    assert world.scm.pr_state(world.pr) == "draft"  # accepted, but nothing was written
    world.scm.read_back_verified = True
    second = world.go(e)
    done = world.effect(e)
    assert second.edge == "done"
    assert done.status is EffectStatus.CONFIRMED
    assert done.receipt is not None
    assert done.receipt.read_back_verified
    assert done.attempts == 2
    keys = {c.key for c in world.scm.spy.calls_for("mark_ready")}
    assert keys == {e.idempotency_key}  # a retry keeps its key


def test_read_back_that_never_verifies_blocks_instead_of_failing(world: World) -> None:
    """The write may have landed, so FAILED would be a guess (ADR-0011)."""
    world.approve()
    e = world.plan()
    world.scm.read_back_verified = False
    results = [world.go(e) for _ in range(3)]
    final = world.effect(e)
    assert results[-1].blocked
    assert results[-1].reason == "attempts_exhausted"
    assert final.status is EffectStatus.RETRYING
    assert final.receipt is None
    assert final.attempts == 3
    again = world.go(e)  # blocked: no fourth write
    assert again.blocked
    assert len(world.scm.spy.calls_for("mark_ready")) == 3


def test_a_confirmed_effect_is_not_written_again(world: World) -> None:
    world.approve()
    e = world.plan()
    world.go(e)
    again = world.go(e)
    assert again.effect.status is EffectStatus.CONFIRMED
    assert again.edge == "done"  # the edge replays, so a crashed driver can still route
    assert len(world.scm.spy.calls_for("mark_ready")) == 1


@both_stores
def test_a_lost_response_is_written_exactly_once(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.lose_response_next("mark_ready")
    first = world.go(e)
    assert first.effect.status is EffectStatus.RETRYING
    assert world.scm.pr_state(world.pr) == "ready"  # the write did happen
    second = world.go(e)
    assert second.effect.status is EffectStatus.CONFIRMED
    calls = world.scm.spy.calls_for("mark_ready")
    assert len(calls) == 2
    assert {c.key for c in calls} == {e.idempotency_key}
    assert len(world.scm.spy.applied("mark_ready")) == 1
    assert calls[1].replayed


def test_a_transient_failure_retries_with_the_same_key(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    assert world.go(e).effect.status is EffectStatus.RETRYING
    world.go(e)
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert done.attempts == 2


def test_transient_failures_block_after_max_attempts(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready", times=5)
    results = [world.go(e) for _ in range(4)]
    assert results[2].blocked
    assert results[3].blocked
    assert world.effect(e).status is EffectStatus.RETRYING
    assert len(world.scm.spy.calls_for("mark_ready")) == 3


def test_a_retry_checks_the_approval_again(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.go(e)
    world.close(world.gate(round=2), DecisionKind.REJECT)  # invalidates the round-1 approval
    result = world.go(e)
    assert len(world.scm.spy.calls_for("mark_ready")) == 1
    # it was tried once, so it may have landed: blocked for a person, never VOIDED
    assert result.blocked
    assert result.reason == "unreconciled:gate_invalid"
    assert world.effect(e).status is EffectStatus.RETRYING


def test_execute_hands_the_writer_the_effects_key(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    seen: list[str] = []
    world.go(e, CallHandler(lambda k: _receipt(seen, k)))
    assert seen == [e.idempotency_key]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_a_permanent_error_fails_the_effect_with_no_edge_and_replays(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.stale_next("mark_ready")  # StaleHeadError, but mark_ready has no stale edge
    result = world.go(e)
    assert result.effect.status is EffectStatus.FAILED
    assert result.edge is None
    assert result.reason == "StaleHeadError"
    assert world.go(e).reason == "StaleHeadError"


def test_a_permanent_error_from_the_writer_is_a_failure(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)

    def refuse(key: str) -> Receipt:
        raise PermanentError("no")

    assert world.go(e, CallHandler(refuse)).effect.status is EffectStatus.FAILED


# --- the lease: a live worker is never taken over; a late one never overwrites -----------------


def test_a_live_attempt_is_not_taken_over(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    writes: list[str] = []
    seen: list[ExecResult] = []

    def write(key: str) -> Receipt:
        seen.append(world.go(e, CallHandler(lambda k: _receipt(writes, k))))  # a second worker
        return _receipt(writes, key)

    world.go(e, CallHandler(write))
    assert seen[0].reason == "in_flight"
    assert writes == [e.idempotency_key]  # written once
    assert world.effect(e).status is EffectStatus.CONFIRMED


@pytest.mark.parametrize("late", ["receipt", "transient", "permanent"])
@both_stores
def test_a_worker_whose_lease_lapsed_cannot_overwrite_the_newer_result(
    world: World, late: str
) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    writes: list[str] = []
    second: list[ExecResult] = []

    def stalled(key: str) -> Receipt:
        world.clock.now += 61  # the lease lapses while this worker is stuck
        second.append(world.go(e, CallHandler(lambda k: _receipt(writes, k))))
        if late == "transient":
            raise TransientError("late")
        if late == "permanent":
            raise PermanentError("late")
        return Receipt("late", "", read_back_verified=True)

    first = world.go(e, CallHandler(stalled))
    assert second[0].effect.status is EffectStatus.CONFIRMED
    assert first.reason == "lease_lost"
    final = world.effect(e)
    assert final.status is EffectStatus.CONFIRMED
    assert final.receipt is not None
    assert final.receipt.external_id == "x-1"  # the second worker's receipt, not the late one
    assert writes == [e.idempotency_key]


@both_stores
def test_a_settle_that_loses_a_race_does_not_overwrite_the_newer_state(world: World) -> None:
    """Deterministic: another worker confirms between our read and our settle transaction."""
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    receipt = Receipt("other", "", read_back_verified=True)

    def other_worker_confirms() -> None:
        world.force(
            e,
            status=EffectStatus.CONFIRMED,
            attempts=2,
            receipt=receipt,
            meta={"edge": "done", "reason": None},
        )

    world.store.before_next_transaction(lambda: None)  # the claim
    world.store.before_next_transaction(other_worker_confirms)  # the settle

    def refuse(key: str) -> Receipt:
        raise PermanentError("late")

    result = world.go(e, CallHandler(refuse))
    assert result.reason == "lease_lost"
    final = world.effect(e)
    assert final.status is EffectStatus.CONFIRMED
    assert final.receipt == receipt


def test_a_lapsed_lease_is_retried_with_the_same_key(world: World) -> None:
    world.approve()
    e = world.plan()
    world.force(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=1,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
        meta={"lease_owner": "dead", "lease_until": world.clock.now - 1},
    )
    world.go(e)
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert done.attempts == 2
    assert {c.key for c in world.scm.spy.calls_for("mark_ready")} == {e.idempotency_key}


def test_crash_recovery_does_not_bypass_max_attempts(world: World) -> None:
    world.approve()
    e = world.plan()
    world.force(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=3,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
    )
    result = world.go(e)
    assert result.blocked
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.RETRYING


def test_a_crashed_merge_under_stop_is_never_voided(world: World) -> None:
    """The worker died after the SCM accepted the merge. Stop must find it, not void it."""
    world.approve()
    world.scm.mark_ready(world.pr, "k-ready")
    e = world.plan("pr.merge")
    world.scm.request_merge(world.pr, "h1", MergeMethod.SQUASH, e.idempotency_key)
    world.force(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=1,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
        meta={"lease_owner": "dead", "lease_until": 0},
    )
    world.set_run(RunStatus.CANCELLING)
    result = world.go(e, world.merger())
    assert result.blocked
    assert result.reason == "unreconciled:run_not_active"
    assert world.effect(e).status is EffectStatus.RETRYING
    assert world.scm.poll_merge(world.scm.merges()[-1]).state is MergeState.PENDING
    report = world.fx.void_planned(world.run.id)
    assert report.voided == ()
    assert [x.id for x in report.in_flight] == [e.id]


# --- plan --------------------------------------------------------------------------------------


def test_planning_twice_returns_the_same_record(world: World) -> None:
    first, second = world.plan(), world.plan()
    assert first == second


def test_a_new_subject_gets_a_new_record(world: World) -> None:
    first = world.plan()
    moved = dataclasses.replace(SUBJECT, head_sha="h2")
    other = world.fx.plan(
        world.run.id,
        "pr.mark_ready",
        "merge",
        1,
        EffectClass.GATED,
        moved.digest(),
        requires_gates=("review",),
        subject=moved,
    )
    assert other.idempotency_key != first.idempotency_key


def test_an_explicit_key_scope_is_used_as_given(world: World) -> None:
    e = world.fx.plan(
        world.run.id, "pr.ensure_draft", "open", 1, EffectClass.SCOPED, DIGEST, key="run:branch"
    )
    assert e.idempotency_key == "run:branch"
    assert world.effect(e) == e


def test_replanning_a_key_for_another_effect_is_refused(world: World) -> None:
    world.fx.plan(world.run.id, "a", "s", 1, EffectClass.SCOPED, DIGEST, key="k")
    with pytest.raises(ValueError, match="already"):
        world.fx.plan(world.run.id, "b", "s", 1, EffectClass.SCOPED, DIGEST, key="k")


def test_replanning_with_different_gates_is_refused(world: World) -> None:
    world.fx.plan(
        world.run.id,
        "a",
        "s",
        1,
        EffectClass.GATED,
        DIGEST,
        requires_gates=("review",),
        key="k",
        subject=SUBJECT,
    )
    with pytest.raises(ValueError, match="already"):
        world.fx.plan(
            world.run.id,
            "a",
            "s",
            1,
            EffectClass.GATED,
            DIGEST,
            requires_gates=("qa",),
            key="k",
            subject=SUBJECT,
        )


def test_get_of_an_unknown_effect_is_a_key_error(world: World) -> None:
    with pytest.raises(KeyError):
        world.fx.get(world.run.id, "nope")


# --- the live subject: ticket edits and the frozen subject -------------------------------------


def test_a_ticket_edited_after_the_final_approval_voids_the_merge(world: World) -> None:
    world.approve()
    world.scm.mark_ready(world.pr, "k-ready")
    world.scm.spy.clear()
    e = world.plan("pr.merge")
    edited = dataclasses.replace(SUBJECT, ticket_revision="r2")
    result = world.go(e, world.merger(), live=edited)
    assert result.reason == "gate_invalid"
    assert world.effect(e).status is EffectStatus.VOIDED
    assert world.scm.spy.calls == ()


def test_evidence_that_changed_since_approval_voids_the_merge(world: World) -> None:
    """Same code and ticket, but the subject the effect was planned for is not the live one."""
    world.approve()
    e = world.plan("pr.merge")
    changed = dataclasses.replace(SUBJECT, evidence_digest="e2")
    assert world.go(e, world.merger(), live=changed).reason == "gate_invalid"
    assert world.scm.spy.calls == ()


def test_a_head_that_moved_since_approval_voids_the_merge(world: World) -> None:
    world.approve()
    e = world.plan("pr.merge")
    moved = dataclasses.replace(SUBJECT, head_sha="h2")
    assert world.go(e, world.merger(), live=moved).reason == "gate_invalid"


def _noop() -> CallHandler:
    return CallHandler(lambda key: Receipt("release-1", "", read_back_verified=True))


def _merged(world: World) -> Effect:
    world.approve()
    world.scm.mark_ready(world.pr, "k-ready")
    merge = world.plan("pr.merge")
    world.go(merge, world.merger())
    world.scm.complete_merge(world.scm.merges()[-1], "m1")
    done = world.fx.poll(world.run.id, merge.idempotency_key, world.merger())
    assert done.effect.frozen_subject is not None
    return merge


def test_after_a_merge_later_gated_effects_check_the_frozen_subject(world: World) -> None:
    """PLAN 293: a ticket edit after the merge cannot strand the run."""
    _merged(world)
    release = world.plan("release.trigger")
    edited = dataclasses.replace(SUBJECT, ticket_revision="r2")
    result = world.go(release, _noop(), live=edited)
    assert result.edge == "done"
    assert world.effect(release).status is EffectStatus.CONFIRMED


def _release(world: World, subject: Subject = SUBJECT, name: str = "release") -> Effect:
    return world.fx.plan(
        world.run.id,
        "release.trigger",
        "r",
        1,
        EffectClass.GATED,
        subject.digest(),
        requires_gates=(name,),
        subject=subject,
    )


def test_after_a_merge_a_gate_approved_at_another_head_is_still_refused(world: World) -> None:
    _merged(world)
    world.approve(name="release", subject=dataclasses.replace(SUBJECT, head_sha="h9"))
    assert world.go(_release(world), _noop(), live=SUBJECT).reason == "gate_invalid"


def test_after_a_merge_an_effect_planned_for_other_code_cannot_ride_the_old_approval(
    world: World,
) -> None:
    """h1 was merged; an effect planned at h9 holding only the h1 approval must not run."""
    _merged(world)
    world.approve(name="release")  # approved at h1 (the merged head)
    other = _release(world, dataclasses.replace(SUBJECT, head_sha="h9"))
    result = world.go(other, _noop(), live=SUBJECT)
    assert result.reason == "gate_invalid"
    assert world.effect(other).status is EffectStatus.VOIDED


def test_after_a_merge_a_gate_approved_at_another_ticket_text_still_runs(world: World) -> None:
    """PLAN 293: only the head matters after a merge, so a ticket edit cannot strand the run."""
    _merged(world)
    world.approve(name="release", subject=dataclasses.replace(SUBJECT, ticket_revision="r9"))
    release = _release(world)
    assert world.go(release, _noop(), live=SUBJECT).edge == "done"


def test_the_frozen_subject_is_found_across_pages(world: World) -> None:
    world.store.page_limit = 1
    for i in range(3):
        world.fx.plan(world.run.id, f"noise{i}", "s", 1, EffectClass.SCOPED, DIGEST)
    _merged(world)
    release = world.plan("release.trigger")
    edited = dataclasses.replace(SUBJECT, ticket_revision="r2")
    assert world.go(release, _noop(), live=edited).edge == "done"


# --- paging ------------------------------------------------------------------------------------


def test_a_stale_gate_round_is_not_missed_when_pages_hold_one_item(world: World) -> None:
    world.store.page_limit = 1
    world.approve()
    world.approve(round=2)
    world.gate(round=3)
    e = world.plan()
    world.go(e)
    assert world.scm.spy.calls == ()


def test_an_approval_on_a_later_page_is_found(world: World) -> None:
    world.store.page_limit = 1
    gate = world.gate()
    for n in (1, 2):  # ledger noise that sorts before the real decision
        world.raw_decision(gate, DecisionKind.REJECT, "x", DecisionId.from_parts(n, bytes(10)))
    approve = world.close(gate, DecisionKind.APPROVE).decision
    e = world.plan()
    world.go(e)
    assert world.effect(e).decision_ids == (approve.id,)


# --- pr.merge: async, stale and conflict edges, and Stop -----------------------------------------


def _merge(world: World) -> Effect:
    world.approve()
    world.scm.mark_ready(world.pr, "k-ready")
    return world.plan("pr.merge")


def test_a_merge_stays_accepted_until_read_back(world: World) -> None:
    e = _merge(world)
    first = world.go(e, world.merger())
    accepted = world.effect(e)
    assert first.effect.status is EffectStatus.ACCEPTED
    assert first.edge is None
    assert accepted.intent is not None
    assert accepted.receipt is None
    pending = world.fx.poll(world.run.id, e.idempotency_key, world.merger())
    assert pending.effect.status is EffectStatus.ACCEPTED
    world.scm.complete_merge(MergeHandle(accepted.intent, world.pr), "m1")
    done = world.fx.poll(world.run.id, e.idempotency_key, world.merger())
    final = world.effect(e)
    assert done.edge == "done"
    assert final.status is EffectStatus.CONFIRMED
    assert final.receipt is not None
    assert final.receipt.read_back_verified
    assert final.frozen_subject == dataclasses.replace(SUBJECT, merge_sha="m1")


@pytest.mark.parametrize("merge_sha", [None, ""])
def test_a_merge_reported_without_a_sha_is_not_confirmed(
    world: World, monkeypatch: pytest.MonkeyPatch, merge_sha: str | None
) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    receipt = Receipt("pr-1", "", read_back_verified=True)
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, merge_sha, receipt)
    )
    polled = calls_cleanly(
        "a merge that cannot be confirmed must stay ACCEPTED",
        lambda: world.fx.poll(world.run.id, e.idempotency_key, world.merger()),
    )
    assert polled.effect.status is EffectStatus.ACCEPTED
    assert polled.reason == "unconfirmed"


def test_a_merge_reported_without_a_receipt_is_not_confirmed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, "m1", None)
    )
    polled = calls_cleanly(
        "a merge that cannot be confirmed must stay ACCEPTED",
        lambda: world.fx.poll(world.run.id, e.idempotency_key, world.merger()),
    )
    assert polled.effect.status is EffectStatus.ACCEPTED
    assert world.effect(e).frozen_subject is None


def test_a_merge_with_a_receipt_that_failed_read_back_is_not_confirmed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    unverified = Receipt("pr-1", "", read_back_verified=False)
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, "m1", unverified)
    )
    polled = calls_cleanly(
        "a merge that cannot be confirmed must stay ACCEPTED",
        lambda: world.fx.poll(world.run.id, e.idempotency_key, world.merger()),
    )
    assert polled.effect.status is EffectStatus.ACCEPTED


def test_a_merge_the_service_never_applied_is_not_confirmed(world: World) -> None:
    e = _merge(world)
    world.scm.read_back_verified = False
    world.go(e, world.merger())
    polled = world.fx.poll(world.run.id, e.idempotency_key, world.merger())
    assert polled.effect.status is EffectStatus.ACCEPTED
    assert polled.reason == "unconfirmed"
    assert world.effect(e).frozen_subject is None


def test_a_handler_built_for_another_head_cannot_merge_under_this_approval(world: World) -> None:
    e = _merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")
    other = dataclasses.replace(SUBJECT, head_sha="h2")
    result = world.go(e, world.merger(subject=other, sha="h2"))
    assert result.effect.status is EffectStatus.FAILED
    assert result.reason == "subject_mismatch"
    assert world.scm.merges() == []


def test_a_handler_whose_expected_sha_differs_from_its_subject_cannot_merge(world: World) -> None:
    e = _merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")
    result = world.go(e, world.merger(sha="h2"))  # subject says h1, the request would say h2
    assert result.reason == "head_mismatch"
    assert world.scm.merges() == []


def test_a_stale_head_at_merge_takes_the_stale_edge_and_replays_it(world: World) -> None:
    e = _merge(world)
    world.scm.stale_next("request_merge")
    result = world.go(e, world.merger())
    assert result.edge == "stale"
    assert result.effect.status is EffectStatus.FAILED
    replay = world.go(e, world.merger())  # a crashed driver asks again
    assert replay.edge == "stale"
    assert replay.reason == "stale_head"


def test_the_head_moving_before_the_merge_takes_the_stale_edge(world: World) -> None:
    e = _merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")
    result = world.go(e, world.merger())
    assert result.edge == "stale"
    assert world.scm.merges() == []


@pytest.mark.parametrize(
    ("reason", "edge"),
    [
        (MergeReason.STALE, "stale"),
        (MergeReason.CONFLICT, "conflict"),
        (MergeReason.REJECTED, None),
    ],
)
def test_poll_maps_each_failure_reason_and_it_replays(
    world: World, reason: MergeReason, edge: str | None
) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    world.scm.fail_merge(world.scm.merges()[-1], reason)
    result = world.fx.poll(world.run.id, e.idempotency_key, world.merger())
    assert result.edge == edge
    assert result.effect.status is EffectStatus.FAILED
    replay = world.go(e, world.merger())
    assert replay.edge == edge
    assert replay.reason == f"merge_{reason.value}"


def test_stop_dequeues_an_accepted_merge_and_keeps_its_handle(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    handle = world.effect(e).intent
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.VOIDED
    assert result.reason == "dequeued"
    assert world.effect(e).intent == handle  # the void reason is not written over the handle
    assert world.scm.pr_state(world.pr) == "ready"  # nothing merged
    assert world.go(e, world.merger()).reason == "dequeued"


def test_stop_after_the_merge_landed_reconciles_to_confirmed(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    world.scm.complete_merge(world.scm.merges()[-1], "m1")  # dequeue now raises RefusedError
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.CONFIRMED  # reported, never BLOCKED
    assert result.effect.frozen_subject is not None


def test_stop_with_a_moved_head_polls_instead_of_blocking(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    world.scm.stale_next("dequeue")
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.ACCEPTED  # still pending: reported, not dead
    assert result.reason == "unconfirmed"


def test_stop_of_a_failed_merge_settles_it(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    world.scm.fail_merge(world.scm.merges()[-1], MergeReason.STALE)
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.FAILED
    assert result.edge == "stale"


def test_a_slow_poller_cannot_overwrite_a_confirmed_merge(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    handle = world.scm.merges()[-1]
    inner_merger = world.merger()

    class Slow:
        """Its poll starts first, but another poller confirms the merge before it answers."""

        def execute(self, effect: Effect) -> Any:
            return inner_merger.execute(effect)

        def stop(self, effect: Effect) -> Any:
            return inner_merger.stop(effect)

        def reconcile(self, effect: Effect) -> Any:
            return inner_merger.reconcile(effect)

        def poll(self, effect: Effect) -> Any:
            world.scm.complete_merge(handle, "m1")
            world.fx.poll(world.run.id, e.idempotency_key, inner_merger)
            return Failed("stale", "merge_stale")

    result = calls_cleanly(
        "a poll that lost to a confirmation must report 'superseded'",
        lambda: world.fx.poll(world.run.id, e.idempotency_key, Slow()),
    )
    assert result.reason == "superseded"
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_poll_and_stop_need_an_accepted_effect(world: World) -> None:
    e = _merge(world)
    with pytest.raises(ValueError, match="ACCEPTED"):
        world.fx.poll(world.run.id, e.idempotency_key, world.merger())
    with pytest.raises(ValueError, match="ACCEPTED"):
        world.fx.stop(world.run.id, e.idempotency_key, world.merger())


# --- declared scoped effects need a live run; only engine-implicit ones run on a stopped one ----


@pytest.mark.parametrize("effect_type", ["pr.update_branch", "pr.ensure_draft"])
@pytest.mark.parametrize("status", [RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE])
def test_a_declared_scoped_effect_is_voided_on_a_stopped_run(
    world: World, effect_type: str, status: RunStatus
) -> None:
    e = world.plan(effect_type, EffectClass.SCOPED)
    world.set_run(status)
    result = world.go(e)
    assert result.reason == "run_not_active"
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


@pytest.mark.parametrize("effect_type", ["pr.update_branch", "pr.ensure_draft"])
def test_a_declared_scoped_effect_planned_after_the_void_does_not_run(
    world: World, effect_type: str
) -> None:
    world.set_run(RunStatus.CANCELLED)
    e = world.plan(effect_type, EffectClass.SCOPED)  # planned after Stop voided the rest
    assert world.go(e).reason == "run_not_active"
    assert world.scm.spy.calls == ()


@pytest.mark.parametrize("effect_type", ["pr.update_branch", "pr.ensure_draft"])
@pytest.mark.parametrize("status", [RunStatus.BLOCKED, RunStatus.WAITING_HUMAN, RunStatus.QUEUED])
def test_a_declared_scoped_effect_is_held_while_the_run_waits(
    world: World, effect_type: str, status: RunStatus
) -> None:
    e = world.plan(effect_type, EffectClass.SCOPED)
    world.set_run(status)
    assert world.go(e).reason == "held"
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.PLANNED


def test_a_declared_scoped_claim_checks_the_run_in_the_transaction(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.store.before_next_transaction(lambda: world.set_run(RunStatus.CANCELLING))
    assert world.go(e).reason == "run_not_active"
    assert world.scm.spy.calls == ()


@pytest.mark.parametrize(
    "effect_type", ["check.publish", "gate.notify", "pr.close", "pr.open_revert"]
)
@pytest.mark.parametrize("status", [RunStatus.CANCELLED, RunStatus.REJECTED, RunStatus.BLOCKED])
def test_an_engine_implicit_effect_runs_whatever_the_run_status(
    world: World, effect_type: str, status: RunStatus
) -> None:
    e = world.plan(effect_type, EffectClass.SCOPED)
    world.set_run(status)
    assert world.go(e).edge == "done"


# --- the lease and the fences (second worker, late worker) --------------------------------------


@both_stores
def test_a_worker_cannot_settle_while_a_second_worker_holds_the_lease(world: World) -> None:
    """A stalls past its lease; B takes over and is mid-write when A finally answers."""
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    a_in, b_in, a_go, b_go = (threading.Event() for _ in range(4))
    out: dict[str, ExecResult] = {}

    def a_write(key: str) -> Receipt:
        a_in.set()
        assert a_go.wait(10)
        raise TransientError("A answers late")

    def b_write(key: str) -> Receipt:
        b_in.set()
        assert b_go.wait(10)
        return Receipt("from-b", "", read_back_verified=True)

    def run(name: str, write: Callable[[str], Receipt]) -> None:
        out[name] = world.go(e, CallHandler(write))

    ta = threading.Thread(target=run, args=("a", a_write))
    ta.start()
    assert a_in.wait(10)
    world.clock.now += 61  # A's lease lapses
    tb = threading.Thread(target=run, args=("b", b_write))
    tb.start()
    assert b_in.wait(10)  # B holds the lease and has not answered
    a_go.set()
    ta.join(10)
    assert out["a"].reason == "lease_lost"
    held = world.effect(e)
    assert held.status is EffectStatus.ATTEMPTING  # A did not move B's record
    b_go.set()
    tb.join(10)
    assert out["b"].edge == "done"
    final = world.effect(e)
    assert final.status is EffectStatus.CONFIRMED
    assert final.receipt is not None
    assert final.receipt.external_id == "from-b"


@both_stores
def test_a_worker_whose_claim_was_taken_over_before_it_wrote_never_writes(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    first_calls: list[str] = []
    writes: list[str] = []

    def takeover() -> None:  # right after A's claim commits: the lease lapses and B finishes
        world.clock.now += 61
        world.go(e, CallHandler(lambda k: _receipt(writes, k)))

    world.store.after_next_transaction(takeover)
    result = world.go(e, CallHandler(lambda k: _receipt(first_calls, k)))
    assert first_calls == []  # A never called its writer
    assert result.reason == "lease_lost"
    assert writes == [e.idempotency_key]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_a_block_survives_a_later_approval_until_a_person_retries(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.go(e)
    world.close(world.gate(round=2), DecisionKind.REJECT)
    assert world.go(e).reason == "unreconciled:gate_invalid"
    world.approve(round=3)  # a new approval at the same head would satisfy every guard
    again = world.go(e)
    assert again.blocked
    assert world.effect(e).status is EffectStatus.RETRYING
    assert len(world.scm.spy.calls_for("mark_ready")) == 1  # no second write


def test_a_decision_of_another_gate_instance_is_not_an_approval(world: World) -> None:
    gate = world.raw_gate(GateStatus.APPROVED)
    world.raw_decision(gate, DecisionKind.APPROVE, gate.subject.digest(), gate_id=GateId.new())
    e = world.plan()
    assert world.go(e).reason == "gate_invalid"
    assert world.scm.spy.calls == ()


def test_a_pre_push_gate_never_satisfies_an_effect(world: World) -> None:
    """A pre-push subject has no head; None == None must not pass (PLAN 4: pre_push is checked
    only by the branch.push claim)."""
    evil = Subject.pre_push(base_sha="b0", patch_id="EVIL", ticket_revision="r1")
    planned = Subject.pre_push(base_sha="b0", patch_id="p1", ticket_revision="r1")
    world.close(world.gate(subject=evil, gate_type=GateType.PRE_PUSH), DecisionKind.APPROVE)
    e = world.fx.plan(
        world.run.id,
        "pr.mark_ready",
        "merge",
        1,
        EffectClass.GATED,
        planned.digest(),
        requires_gates=("review",),
        subject=planned,
    )
    result = world.go(e, live=planned)
    assert result.reason == "gate_invalid"
    assert world.scm.spy.calls == ()


def test_gates_are_compared_by_head_only(world: World) -> None:
    """PLAN 4.3.2: a gate that saw other evidence, patch id or ticket text still counts."""
    other = dataclasses.replace(
        SUBJECT, patch_id="p0", ticket_revision="r0", evidence_digest="other"
    )
    world.approve(subject=other)
    e = world.plan()
    assert world.go(e).edge == "done"


# --- handler-level: a merge is only reported done with a receipt and a sha ---------------------


def _accepted_merge(world: World) -> Effect:
    return dataclasses.replace(_merge(world), intent="merge-1")


@pytest.mark.parametrize("merge_sha", [None, ""])
def test_the_merge_handler_does_not_report_a_merge_without_a_sha(
    world: World, monkeypatch: pytest.MonkeyPatch, merge_sha: str | None
) -> None:
    effect = _accepted_merge(world)
    receipt = Receipt("pr-1", "", read_back_verified=True)
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, merge_sha, receipt)
    )
    out = calls_cleanly(
        "a merge without a sha must be Pending", lambda: world.merger().poll(effect)
    )
    assert isinstance(out, Pending)


def test_the_merge_handler_does_not_report_a_merge_without_a_receipt(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    effect = _accepted_merge(world)
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, "m1", None)
    )
    out = calls_cleanly(
        "a merge without a receipt must be Pending", lambda: world.merger().poll(effect)
    )
    assert isinstance(out, Pending)


def test_the_merge_handler_reports_a_merge_with_a_receipt_and_a_sha(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    effect = _accepted_merge(world)
    receipt = Receipt("pr-1", "", read_back_verified=True)
    monkeypatch.setattr(
        world.scm, "poll_merge", lambda h: MergeResult(MergeState.MERGED, "m1", receipt)
    )
    out = world.merger().poll(effect)
    assert isinstance(out, Written)
    assert out.frozen_subject == dataclasses.replace(SUBJECT, merge_sha="m1")


# --- reconcile: Stop's route for a lost attempt ----------------------------------------------


def test_reconcile_dequeues_a_merge_whose_request_answer_was_lost(world: World) -> None:
    e = _merge(world)
    world.scm.lose_response_next("request_merge")  # the merge is pending at the SCM
    assert world.go(e, world.merger()).effect.status is EffectStatus.RETRYING
    requests = len(world.scm.spy.calls_for("request_merge"))
    world.set_run(RunStatus.CANCELLING)
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.VOIDED
    assert result.reason == "dequeued"
    assert world.scm.poll_merge(world.scm.merges()[-1]).state is MergeState.DEQUEUED
    assert len(world.scm.spy.calls_for("request_merge")) == requests  # reconcile never requests
    assert len(world.scm.merges()) == 1


def test_reconcile_of_a_merge_that_landed_blocks_for_a_person(world: World) -> None:
    """Dequeue is refused (nothing pending), and "no merge visible" is not proof of anything."""
    e = _merge(world)
    world.scm.lose_response_next("request_merge")
    world.go(e, world.merger())
    world.scm.complete_merge(world.scm.merges()[-1], "m1")
    world.set_run(RunStatus.CANCELLING)
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.blocked
    assert result.reason == "unreconciled:RefusedError"
    assert world.effect(e).status is EffectStatus.RETRYING


class InstantScm(FakeScm):
    """An SCM whose merge queue is empty: every accepted request merges at once."""

    def request_merge(self, pr: PrRef, expected_sha: str, method: MergeMethod, key: str) -> Any:
        before = len(self.merges())
        try:
            handle = super().request_merge(pr, expected_sha, method, key)
        except TransientError:
            if len(self.merges()) > before:  # accepted, then the answer was lost: it merged
                self.complete_merge(self.merges()[-1], "m-instant")
            raise
        self.complete_merge(handle, "m-instant")
        return handle


def _instant(world: World) -> None:
    scm = InstantScm()
    scm.seed_branch(REPO, "main", "b0")
    scm.seed_branch(REPO, "sto/x", "h1", parent="b0")
    world.pr = PrRef.of(REPO, scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k-pr"))
    world.scm = scm


@pytest.mark.parametrize("lost", ["never_requested", "answer_lost"])
@both_stores
def test_a_stop_never_causes_a_merge_even_on_an_instant_merge_queue(
    world: World, lost: str
) -> None:
    _instant(world)
    e = _merge(world)
    if lost == "never_requested":
        world.scm.fail_next("request_merge")
    else:
        world.scm.lose_response_next("request_merge")
    world.go(e, world.merger())
    requests = len(world.scm.spy.calls_for("request_merge"))
    set_switch(world.store, SCOPE, "merge", False, fleet=True)
    world.set_run(RunStatus.CANCELLING)
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert len(world.scm.spy.calls_for("request_merge")) == requests  # none during reconcile
    if lost == "never_requested":
        assert world.scm.pr_state(world.pr) == "ready"  # nothing merged by Stop
        assert world.scm.merges() == []
        assert result.blocked
    else:
        assert world.scm.pr_state(world.pr) == "merged"  # it landed before Stop: reported
        assert result.blocked
    assert world.effect(e).status is EffectStatus.RETRYING


def test_reconcile_of_a_lapsed_attempt_after_a_crash(world: World) -> None:
    e = _merge(world)
    world.scm.request_merge(world.pr, "h1", MergeMethod.SQUASH, e.idempotency_key)
    world.force(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=1,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
        meta={
            "lease_owner": "dead",
            "lease_until": world.clock.now - 1,
            "subject": to_wire(SUBJECT),
        },
    )
    requests = len(world.scm.spy.calls_for("request_merge"))
    world.set_run(RunStatus.CANCELLING)
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.VOIDED
    assert world.scm.poll_merge(world.scm.merges()[-1]).state is MergeState.DEQUEUED
    assert len(world.scm.spy.calls_for("request_merge")) == requests


def _crashed_merge(world: World) -> Effect:
    e = _merge(world)
    world.force(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=1,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
        meta={
            "lease_owner": "dead",
            "lease_until": world.clock.now - 1,
            "subject": to_wire(SUBJECT),
        },
    )
    return e


@both_stores
def test_a_block_set_by_reconcile_survives_the_next_execute(world: World) -> None:
    e = _crashed_merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")  # the head moved: reconcile cannot tell
    assert world.fx.reconcile(world.run.id, e.idempotency_key, world.merger()).blocked
    again = world.go(e, world.merger())
    assert again.blocked
    assert again.reason == "unreconciled:StaleHeadError"
    assert world.effect(e).status is EffectStatus.ATTEMPTING  # not moved to RETRYING and re-run
    assert world.scm.spy.calls_for("request_merge") == ()


def test_a_block_survives_a_retry_outcome_from_reconcile(world: World) -> None:
    e = _crashed_merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")
    world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    unverified = Receipt("x", "", read_back_verified=False)

    class Unsure:
        def execute(self, effect: Effect) -> Any: ...
        def poll(self, effect: Effect) -> Any: ...
        def stop(self, effect: Effect) -> Any: ...
        def reconcile(self, effect: Effect) -> Any:
            return Written(unverified)

    result = world.fx.reconcile(world.run.id, e.idempotency_key, Unsure())
    assert result.effect.status is EffectStatus.RETRYING
    assert result.blocked
    assert world.go(e, world.merger()).blocked


def test_reconcile_leaves_a_live_attempt_alone(world: World) -> None:
    e = _merge(world)
    seen: list[ExecResult] = []

    class Probe:
        def execute(self, effect: Effect) -> Any:
            seen.append(world.fx.reconcile(world.run.id, e.idempotency_key, world.merger()))
            return Written(Receipt("x", "", read_back_verified=True))

        def poll(self, effect: Effect) -> Any: ...
        def stop(self, effect: Effect) -> Any: ...
        def reconcile(self, effect: Effect) -> Any: ...

    world.go(e, Probe())
    assert seen[0].reason == "in_flight"
    assert world.scm.merges() == []


def test_reconcile_of_a_merge_that_cannot_be_found_stays_blocked(world: World) -> None:
    e = _merge(world)
    world.scm.fail_next("request_merge")  # it never reached the SCM
    world.go(e, world.merger())
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")  # the head moved
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.blocked
    assert result.reason == "unreconciled:StaleHeadError"
    assert world.effect(e).status is EffectStatus.RETRYING


def test_reconcile_of_a_merge_nobody_requested_blocks_rather_than_deciding(world: World) -> None:
    e = _merge(world)
    world.scm.fail_next("request_merge")
    world.go(e, world.merger())
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.blocked
    assert result.reason == "unreconciled:RefusedError"  # nothing pending: could mean anything


def test_reconcile_of_an_accepted_merge_stops_it(world: World) -> None:
    e = _merge(world)
    world.go(e, world.merger())
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())
    assert result.effect.status is EffectStatus.VOIDED


def test_reconcile_needs_something_that_was_tried(world: World) -> None:
    e = _merge(world)
    with pytest.raises(ValueError, match="nothing to reconcile"):
        world.fx.reconcile(world.run.id, e.idempotency_key, world.merger())


def test_a_synchronous_effect_blocks_instead_of_raising_on_reconcile(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.go(e)
    result = world.fx.reconcile(world.run.id, e.idempotency_key, world.ready())
    assert result.blocked
    assert result.reason == "unreconciled:CannotReconcile"
    assert world.effect(e).status is EffectStatus.RETRYING


# --- a person's Retry --------------------------------------------------------------------------


def test_retry_blocked_allows_another_full_round_of_attempts(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready", times=3)
    results = [world.go(e) for _ in range(3)]
    assert results[-1].blocked
    world.fx.retry_blocked(world.run.id, e.idempotency_key)
    assert world.go(e).edge == "done"
    assert len(world.scm.spy.calls_for("mark_ready")) == 4
    assert world.effect(e).attempts == 4


def test_retry_blocked_is_capped_again_after_max_more_attempts(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready", times=20)
    for _ in range(3):
        world.go(e)
    world.fx.retry_blocked(world.run.id, e.idempotency_key)
    results = [world.go(e) for _ in range(4)]
    assert [r.blocked for r in results] == [False, False, True, True]
    assert len(world.scm.spy.calls_for("mark_ready")) == 6
    assert world.effect(e).attempts == 6


def test_retry_blocked_keeps_the_planned_subject(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready", times=3)
    for _ in range(3):
        world.go(e)
    world.fx.retry_blocked(world.run.id, e.idempotency_key)
    item = world.store.get(SCOPE, effect_item_key(world.run.id, e.idempotency_key))
    assert item is not None
    assert item.data["meta"]["subject"] == to_wire(SUBJECT)


def test_retry_blocked_needs_a_blocked_effect(world: World) -> None:
    e = world.plan()
    with pytest.raises(ValueError, match="blocked"):
        world.fx.retry_blocked(world.run.id, e.idempotency_key)


def test_a_retried_unreconciled_effect_runs_its_guards_again(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.go(e)
    world.close(world.gate(round=2), DecisionKind.REJECT)
    assert world.go(e).blocked
    world.fx.retry_blocked(world.run.id, e.idempotency_key)
    assert world.go(e).blocked  # still no live approval: blocked again, no write
    world.approve(round=3)
    world.fx.retry_blocked(world.run.id, e.idempotency_key)
    assert world.go(e).edge == "done"


# --- the claim relies on the audit chain; transaction conflicts are retried ---------------------


@both_stores
def test_pinned_a_writer_that_never_moves_the_chain_lets_a_skipped_round_through(
    world: World,
) -> None:
    """The dependency, pinned: with an ``AuditWriter`` that does not move ``RUN#r/CHAIN``, a round
    that skips a number is invisible to the claim and the stale approval is used (PLAN 4.3.2
    broken). Every AuditWriter must move the chain; see the note at ``EffectExecutor._approval``."""
    world.svc = GateService(world.store, audit=NoChainAudit())
    world.approve()
    e = world.plan()
    world.store.before_next_transaction(lambda: world.gate(round=3))  # not round 2
    world.go(e)
    assert len(world.scm.spy.applied("mark_ready")) == 1  # the stale approval won


@both_stores
def test_a_transaction_conflict_while_settling_is_retried(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)

    def conflict() -> None:
        raise TransactionConflictError("busy")

    world.store.before_next_transaction(lambda: None)  # the claim
    world.store.before_next_transaction(conflict)  # the settle, after the write landed
    result = calls_cleanly("a settle conflict must be retried", lambda: world.go(e))
    assert result.edge == "done"
    assert len(world.scm.spy.calls_for("mark_ready")) == 1
    assert world.effect(e).status is EffectStatus.CONFIRMED


@both_stores
def test_a_transaction_conflict_at_the_claim_is_retried(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)

    def conflict() -> None:
        raise TransactionConflictError("busy")

    world.store.before_next_transaction(conflict)
    assert calls_cleanly("a claim conflict must be retried", lambda: world.go(e)).edge == "done"


# --- the frozen subject is the latest merge -------------------------------------------------------


@pytest.mark.parametrize("i", range(6))
def test_the_frozen_subject_is_the_latest_merge_whatever_the_key_order(
    world: World, i: int
) -> None:
    old = dataclasses.replace(SUBJECT, head_sha="h0", merge_sha="m0")
    new = dataclasses.replace(SUBJECT, head_sha="h1", merge_sha="m1")
    receipt = Receipt("pr", "", read_back_verified=True)
    for name, frozen in ((f"m{i}-old", old), (f"m{i}-new", new)):  # the older one is planned first
        time.sleep(0.003)  # ULIDs sort by millisecond
        e = world.fx.plan(world.run.id, name, "s", 1, EffectClass.SCOPED, DIGEST)
        world.force(
            e,
            status=EffectStatus.CONFIRMED,
            receipt=receipt,
            frozen_subject=frozen,
            meta={"edge": "done"},
        )
    world.approve(name="release")  # approved at h1
    assert world.go(_release(world), _noop(), live=SUBJECT).edge == "done"


def test_reconcile_confirms_a_write_that_a_handler_can_read_back(world: World) -> None:
    """A handler with a read-only lookup (D2-11) can report a lost write as landed."""
    world.approve()
    e = world.plan()
    world.scm.lose_response_next("mark_ready")
    assert world.go(e).effect.status is EffectStatus.RETRYING
    landed = Receipt("pr-1", "", read_back_verified=True)

    class Lookup:
        def execute(self, effect: Effect) -> Any: ...
        def poll(self, effect: Effect) -> Any: ...
        def stop(self, effect: Effect) -> Any: ...
        def reconcile(self, effect: Effect) -> Any:
            return Written(landed)

    result = calls_cleanly(
        "a RETRYING write that read back as landed must be CONFIRMED",
        lambda: world.fx.reconcile(world.run.id, e.idempotency_key, Lookup()),
    )
    assert result.effect.status is EffectStatus.CONFIRMED
    assert result.effect.receipt == landed
