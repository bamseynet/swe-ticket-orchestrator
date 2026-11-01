"""D1-07: effects are claimed atomically, gated ones need a live approval, and status comes only
from a receipt (PLAN 4.3 rules 1 and 5, 6.3, ADR-0011)."""

from __future__ import annotations

import dataclasses
import threading
from dataclasses import dataclass

import pytest

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import (
    MergeHandle,
    MergeMethod,
    MergeReason,
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
    Receipt,
    Run,
    RunId,
    RunStatus,
    Subject,
    Surface,
    to_wire,
)
from sto.effects.core import EffectExecutor, StopReport, enable_switches
from sto.effects.ports import CallHandler, MergeHandler
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, TEAM_ROOT, Key, TeamScope

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


@dataclass
class World:
    store: MemoryStore
    fx: EffectExecutor
    scm: FakeScm
    run: Run
    pr: PrRef

    def run_key(self) -> Key:
        return Key(f"RUN#{self.run.id}", "META")

    def set_run(self, status: RunStatus) -> None:
        self.run = dataclasses.replace(
            self.run, status=status, blocked_reason=None, version=self.run.version + 1
        )
        self.store.put(SCOPE, self.run_key(), to_wire(self.run))

    def put_gate(self, status: GateStatus, *, subject: Subject = SUBJECT, round: int = 1) -> Gate:
        gate = Gate(GateId.new(), self.run.id, "review", GateType.REVIEW, round, subject, status)
        self.store.put(SCOPE, Key(f"RUN#{self.run.id}", f"GATE#review#{round}"), to_wire(gate))
        return gate

    def put_decision(self, gate: Gate, kind: DecisionKind, digest: str = DIGEST) -> Decision:
        d = Decision(DecisionId.new(), gate.id, gate.round, "alice", Surface.UI, kind, digest, "ok")
        key = Key(f"RUN#{self.run.id}", f"DEC#review#{gate.round}#{d.id}")
        self.store.put(SCOPE, key, to_wire(d))
        return d

    def approve(self) -> Gate:
        gate = self.put_gate(GateStatus.APPROVED)
        self.put_decision(gate, DecisionKind.APPROVE)
        return gate

    def plan(self, type_: str = "pr.mark_ready", klass: EffectClass = EffectClass.GATED) -> Effect:
        gates = ("review",) if klass is EffectClass.GATED else ()
        return self.fx.plan(self.run.id, type_, "merge", 1, klass, DIGEST, requires_gates=gates)

    def effect(self, e: Effect) -> Effect:
        return self.fx.get(self.run.id, e.idempotency_key)

    def ready_handler(self) -> CallHandler:
        return CallHandler(lambda key: self.scm.mark_ready(self.pr, key))

    def merge_handler(self) -> MergeHandler:
        return MergeHandler(self.scm, self.pr, "h1", MergeMethod.SQUASH, SUBJECT)


@pytest.fixture
def world() -> World:
    store = MemoryStore()
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="merge")
    scm = FakeScm()
    scm.seed_branch(REPO, "main", "b0")
    scm.seed_branch(REPO, "sto/x", "h1", parent="b0")
    receipt = scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k-pr")
    w = World(store, EffectExecutor(store, SCOPE), scm, run, PrRef.of(REPO, receipt))
    store.put(SCOPE, w.run_key(), to_wire(run))
    enable_switches(store, SCOPE, "effects", "merge")
    scm.spy.clear()
    return w


# --- AC1: a gated effect with no approval never calls the writer ---------------------------


def test_gated_effect_with_no_gate_never_calls_writer(world: World) -> None:
    e = world.plan()
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED
    assert result.reason == "gate_invalid"
    assert world.scm.pr_state(world.pr) == "draft"


@pytest.mark.parametrize(
    "status",
    [GateStatus.OPEN, GateStatus.REJECTED, GateStatus.CHANGES_REQUESTED, GateStatus.INVALIDATED],
)
def test_gated_effect_with_gate_not_approved_never_calls_writer(
    world: World, status: GateStatus
) -> None:
    world.put_gate(status)
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


def test_approval_of_another_subject_does_not_count(world: World) -> None:
    other = dataclasses.replace(SUBJECT, head_sha="h2")
    gate = world.put_gate(GateStatus.APPROVED, subject=other)
    world.put_decision(gate, DecisionKind.APPROVE, other.digest())
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert world.effect(e).status is EffectStatus.VOIDED


def test_approved_gate_without_an_approving_decision_does_not_count(world: World) -> None:
    gate = world.put_gate(GateStatus.APPROVED)
    world.put_decision(gate, DecisionKind.REJECT)
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()


def test_only_the_latest_gate_instance_counts(world: World) -> None:
    gate = world.approve()
    world.put_gate(GateStatus.OPEN, round=2)  # a newer round re-opened the gate
    assert gate.round == 1
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()


def test_round_ten_is_later_than_round_nine(world: World) -> None:
    world.put_gate(GateStatus.APPROVED, round=9)
    world.put_gate(GateStatus.OPEN, round=10)
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()


def test_gated_effect_with_live_approval_runs_and_records_the_decisions(world: World) -> None:
    world.approve()
    e = world.plan()
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert result.edge == "done"
    assert len(done.decision_ids) == 1
    assert done.subject_digest == DIGEST
    assert len(world.scm.spy.applied("mark_ready")) == 1
    assert world.scm.pr_state(world.pr) == "ready"


def test_a_gated_effect_must_name_its_gates(world: World) -> None:
    with pytest.raises(ValueError, match="requires_gates"):
        world.fx.plan(world.run.id, "pr.merge", "merge", 1, EffectClass.GATED, DIGEST)


@pytest.mark.parametrize("klass", [EffectClass.INTERNAL, EffectClass.EXPOSING])
def test_v0_plans_only_scoped_and_gated_effects(world: World, klass: EffectClass) -> None:
    with pytest.raises(ValueError, match="scoped or gated"):
        world.fx.plan(world.run.id, "x", "merge", 1, klass, DIGEST)


# --- the claim checks the run and the switches ---------------------------------------------


@pytest.mark.parametrize("status", [RunStatus.CANCELLING, RunStatus.CANCELLED, RunStatus.DONE])
def test_a_run_that_is_stopping_voids_the_effect_unwritten(world: World, status: RunStatus) -> None:
    world.approve()
    e = world.plan()
    world.set_run(status)
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"
    assert world.effect(e).status is EffectStatus.VOIDED


def test_a_scoped_effect_also_needs_an_active_run(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.set_run(RunStatus.CANCELLING)
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()


def test_a_missing_run_voids_the_effect(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.store.delete(SCOPE, world.run_key())
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"


def test_a_switch_that_is_off_holds_the_effect_without_a_state_change(world: World) -> None:
    world.approve()
    e = world.plan("pr.merge")
    world.store.put(SCOPE, Key(TEAM_ROOT, "META"), {"switch_effects": True, "switch_merge": False})
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.reason == "held"
    assert world.effect(e).status is EffectStatus.PLANNED
    enable_switches(world.store, SCOPE, "effects", "merge")  # released: it re-runs its guards
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_the_fleet_switch_holds_every_team(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    world.store.put(PLATFORM, Key("ORG", "SWITCHES"), {"switch_effects": False})
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert result.reason == "held"
    assert world.scm.spy.calls == ()


def test_switch_state_that_was_never_written_holds(world: World) -> None:
    store = MemoryStore()
    store.put(SCOPE, world.run_key(), to_wire(world.run))
    fx = EffectExecutor(store, SCOPE)
    e = fx.plan(world.run.id, "pr.update_branch", "merge", 1, EffectClass.SCOPED, DIGEST)
    assert fx.execute(world.run.id, e.idempotency_key, world.ready_handler()).reason == "held"


# --- AC2 and AC3: cancel ---------------------------------------------------------------------


def test_cancel_voids_a_planned_effect(world: World) -> None:
    world.approve()
    e = world.plan()
    report = world.fx.void_planned(world.run.id)
    assert [x.id for x in report.voided] == [e.id]
    assert report.in_flight == ()
    assert world.effect(e).status is EffectStatus.VOIDED
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.effect.status is EffectStatus.VOIDED


def test_cancel_voids_a_retrying_effect(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.effect(e).status is EffectStatus.RETRYING
    world.fx.void_planned(world.run.id)
    assert world.effect(e).status is EffectStatus.VOIDED


def test_cancel_reports_an_attempting_effect_as_possibly_landed(world: World) -> None:
    world.approve()
    e = world.plan()
    seen: list[StopReport] = []

    def write(key: str) -> Receipt:
        seen.append(world.fx.void_planned(world.run.id))  # Stop arrives mid-write
        return world.scm.mark_ready(world.pr, key)

    world.fx.execute(world.run.id, e.idempotency_key, CallHandler(write))
    report = seen[0]
    assert report.voided == ()
    assert [x.id for x in report.in_flight] == [e.id]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_void_leaves_finished_effects_alone(world: World) -> None:
    world.approve()
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    report = world.fx.void_planned(world.run.id)
    assert report.voided == ()
    assert report.in_flight == ()
    assert world.effect(e).status is EffectStatus.CONFIRMED


def _race_once() -> tuple[Effect, StopReport, list[str]]:
    store = MemoryStore()
    run = Run(RunId.new(), "acme", RunStatus.RUNNING, version=1, stage="s")
    store.put(SCOPE, Key(f"RUN#{run.id}", "META"), to_wire(run))
    enable_switches(store, SCOPE, "effects")
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


def test_concurrent_cancel_and_claim_have_exactly_one_winner() -> None:
    claim_wins = cancel_wins = 0
    for _ in range(40):
        final, report, writes = _race_once()
        if final.status is EffectStatus.VOIDED:
            cancel_wins += 1
            assert writes == []
            assert len(report.voided) == 1
        else:
            claim_wins += 1
            assert final.status is EffectStatus.CONFIRMED
            assert len(writes) == 1
            assert report.voided == ()
    assert claim_wins + cancel_wins == 40


def _receipt(writes: list[str], key: str) -> Receipt:
    writes.append(key)
    return Receipt("x-1", "", read_back_verified=True)


def test_stop_between_the_read_and_the_claim_aborts_the_claim(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stop commits after the claim read the run but before the claim transaction."""
    world.approve()
    e = world.plan()
    real = world.store.transact
    fired: list[bool] = []

    def racing(scope: TeamScope, ops: object) -> None:
        if not fired:
            fired.append(True)
            world.set_run(RunStatus.CANCELLING)
        real(scope, ops)  # type: ignore[arg-type]

    monkeypatch.setattr(world.store, "transact", racing)
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.reason == "run_not_active"


def test_a_gate_invalidated_between_the_read_and_the_claim_aborts_the_claim(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = world.approve()
    e = world.plan()
    real = world.store.transact
    fired: list[bool] = []

    def racing(scope: TeamScope, ops: object) -> None:
        if not fired:
            fired.append(True)
            invalid = gate.advance(GateStatus.INVALIDATED)
            world.store.put(SCOPE, Key(f"RUN#{world.run.id}", "GATE#review#1"), to_wire(invalid))
        real(scope, ops)  # type: ignore[arg-type]

    monkeypatch.setattr(world.store, "transact", racing)
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.scm.spy.calls == ()
    assert result.reason == "gate_invalid"


# --- AC4: status comes only from a receipt -----------------------------------------------------


def test_a_receipt_without_read_back_is_not_confirmed_and_a_retry_confirms(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.read_back_verified = False
    first = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    mid = world.effect(e)
    assert first.effect.status is EffectStatus.RETRYING
    assert mid.receipt is None
    assert world.scm.pr_state(world.pr) == "draft"  # accepted, but nothing was written
    world.scm.read_back_verified = True
    second = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    done = world.effect(e)
    assert second.edge == "done"
    assert done.status is EffectStatus.CONFIRMED
    assert done.receipt is not None
    assert done.receipt.read_back_verified
    assert done.attempts == 2
    keys = {c.key for c in world.scm.spy.calls_for("mark_ready")}
    assert len(keys) == 1
    assert keys == {e.idempotency_key}


def test_read_back_that_never_verifies_ends_failed(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.read_back_verified = False
    for _ in range(3):
        world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    final = world.effect(e)
    assert final.status is EffectStatus.FAILED
    assert final.receipt is None
    assert final.attempts == 3


def test_a_confirmed_effect_is_not_written_again(world: World) -> None:
    world.approve()
    e = world.plan()
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    again = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert again.effect.status is EffectStatus.CONFIRMED
    assert len(world.scm.spy.calls_for("mark_ready")) == 1


def test_a_lost_response_is_written_exactly_once(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.lose_response_next("mark_ready")
    first = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert first.effect.status is EffectStatus.RETRYING
    assert world.scm.pr_state(world.pr) == "ready"  # the write did happen
    second = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
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
    assert (
        world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler()).effect.status
        is EffectStatus.RETRYING
    )
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert done.attempts == 2


def test_transient_failures_end_failed_after_max_attempts(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready", times=5)
    for _ in range(3):
        world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert world.effect(e).status is EffectStatus.FAILED


def test_a_retry_checks_the_approval_again(world: World) -> None:
    gate = world.approve()
    e = world.plan()
    world.scm.fail_next("mark_ready")
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    world.store.put(
        SCOPE,
        Key(f"RUN#{world.run.id}", "GATE#review#1"),
        to_wire(gate.advance(GateStatus.INVALIDATED)),
    )
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert result.reason == "gate_invalid"
    assert world.effect(e).status is EffectStatus.VOIDED
    assert len(world.scm.spy.calls_for("mark_ready")) == 1


def test_an_attempt_left_by_a_crashed_worker_is_retried_with_its_key(world: World) -> None:
    world.approve()
    e = world.plan()
    key = Key(f"RUN#{world.run.id}", f"FX#{e.idempotency_key}")
    item = world.store.get(SCOPE, key)
    assert item is not None
    crashed = dataclasses.replace(
        e,
        status=EffectStatus.ATTEMPTING,
        attempts=1,
        decision_ids=(DecisionId.new(),),
        subject_digest=DIGEST,
    )
    world.store.put(SCOPE, key, to_wire(crashed))
    world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    done = world.effect(e)
    assert done.status is EffectStatus.CONFIRMED
    assert done.attempts == 2


# --- plan --------------------------------------------------------------------------------------


def test_planning_twice_returns_the_same_record(world: World) -> None:
    first, second = world.plan(), world.plan()
    assert first == second
    assert first.idempotency_key == second.idempotency_key


def test_a_new_subject_gets_a_new_record(world: World) -> None:
    first = world.plan()
    other = world.fx.plan(
        world.run.id,
        "pr.mark_ready",
        "merge",
        1,
        EffectClass.GATED,
        "d2",
        requires_gates=("review",),
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


def test_get_of_an_unknown_effect_is_a_key_error(world: World) -> None:
    with pytest.raises(KeyError):
        world.fx.get(world.run.id, "nope")


def test_execute_hands_the_writer_the_effects_key(world: World) -> None:
    e = world.plan("pr.update_branch", EffectClass.SCOPED)
    seen: list[str] = []
    world.fx.execute(world.run.id, e.idempotency_key, CallHandler(lambda k: _receipt(seen, k)))
    assert seen == [e.idempotency_key]
    assert world.effect(e).status is EffectStatus.CONFIRMED


def test_a_permanent_error_fails_the_effect_with_no_edge(world: World) -> None:
    world.approve()
    e = world.plan()
    world.scm.stale_next("mark_ready")  # StaleHeadError, but mark_ready has no stale edge
    result = world.fx.execute(world.run.id, e.idempotency_key, world.ready_handler())
    assert result.effect.status is EffectStatus.FAILED
    assert result.edge is None
    assert result.reason == "StaleHeadError"


# --- pr.merge: async, stale and conflict edges, and Stop -----------------------------------------


def _merge(world: World) -> Effect:
    world.approve()
    world.scm.mark_ready(world.pr, "k-ready")
    return world.plan("pr.merge")


def test_a_merge_stays_accepted_until_read_back(world: World) -> None:
    e = _merge(world)
    first = world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    accepted = world.effect(e)
    assert first.effect.status is EffectStatus.ACCEPTED
    assert first.edge is None
    assert accepted.intent is not None
    assert accepted.receipt is None
    pending = world.fx.poll(world.run.id, e.idempotency_key, world.merge_handler())
    assert pending.effect.status is EffectStatus.ACCEPTED
    handle = MergeHandle(accepted.intent, world.pr)
    world.scm.complete_merge(handle, "m1")
    done = world.fx.poll(world.run.id, e.idempotency_key, world.merge_handler())
    final = world.effect(e)
    assert done.edge == "done"
    assert final.status is EffectStatus.CONFIRMED
    assert final.receipt is not None
    assert final.receipt.read_back_verified
    assert final.frozen_subject == dataclasses.replace(SUBJECT, merge_sha="m1")


def test_a_merge_the_service_never_applied_is_not_confirmed(world: World) -> None:
    e = _merge(world)
    world.scm.read_back_verified = False
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    polled = world.fx.poll(world.run.id, e.idempotency_key, world.merge_handler())
    assert polled.effect.status is EffectStatus.ACCEPTED
    assert polled.reason == "unconfirmed"
    assert world.effect(e).frozen_subject is None


def test_a_stale_head_at_merge_takes_the_stale_edge(world: World) -> None:
    e = _merge(world)
    world.scm.stale_next("request_merge")
    result = world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.edge == "stale"
    assert result.effect.status is EffectStatus.FAILED


def test_the_head_moving_before_the_merge_takes_the_stale_edge(world: World) -> None:
    e = _merge(world)
    world.scm.seed_branch(REPO, "sto/x", "h2", parent="h1")
    result = world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
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
def test_poll_maps_each_failure_reason(world: World, reason: MergeReason, edge: str | None) -> None:
    e = _merge(world)
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    world.scm.fail_merge(world.scm.merges()[-1], reason)
    result = world.fx.poll(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.edge == edge
    assert result.effect.status is EffectStatus.FAILED


def test_stop_dequeues_an_accepted_merge_and_voids_it(world: World) -> None:
    e = _merge(world)
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.effect.status is EffectStatus.VOIDED
    assert world.scm.pr_state(world.pr) == "ready"  # nothing merged


def test_stop_after_the_merge_landed_reconciles_to_confirmed(world: World) -> None:
    e = _merge(world)
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    world.scm.complete_merge(world.scm.merges()[-1], "m1")  # dequeue now raises RefusedError
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.effect.status is EffectStatus.CONFIRMED  # reported, never BLOCKED
    assert result.effect.frozen_subject is not None


def test_stop_with_a_moved_head_polls_instead_of_blocking(world: World) -> None:
    e = _merge(world)
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    world.scm.stale_next("dequeue")
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.effect.status is EffectStatus.ACCEPTED  # still pending: reported, not dead
    assert result.reason == "unconfirmed"


def test_stop_of_a_failed_merge_settles_it(world: World) -> None:
    e = _merge(world)
    world.fx.execute(world.run.id, e.idempotency_key, world.merge_handler())
    world.scm.fail_merge(world.scm.merges()[-1], MergeReason.STALE)
    result = world.fx.stop(world.run.id, e.idempotency_key, world.merge_handler())
    assert result.effect.status is EffectStatus.FAILED


def test_poll_and_stop_need_an_accepted_effect(world: World) -> None:
    e = _merge(world)
    with pytest.raises(ValueError, match="ACCEPTED"):
        world.fx.poll(world.run.id, e.idempotency_key, world.merge_handler())
    with pytest.raises(ValueError, match="ACCEPTED"):
        world.fx.stop(world.run.id, e.idempotency_key, world.merge_handler())
