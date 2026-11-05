"""D2-11: Cancel v1. Fixtures are synthetic (fake SCM, memory store, fake clock).

Parts: ``void_planned`` reports what it found (a landed merge, a contended effect) instead of
staying silent; ``find_merge`` tells a stop whether a merge landed; the reducer-side events
record what happened while the run was stopping; the executor of ``StopRun`` voids, reconciles
and closes; the driver lets a Stop win every race.
"""

from __future__ import annotations

import asyncio
import importlib.util
import itertools
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from pathlib import Path
from typing import Any

import pytest

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import (
    MergeMethod,
    MergeResult,
    MergeState,
    PrRef,
    PrSpec,
    RefusedError,
    RepoRef,
)
from sto.domain import (
    DecisionKind,
    Effect,
    EffectClass,
    EffectStatus,
    FailureClass,
    Gate,
    GateStatus,
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
from sto.effects.core import EffectExecutor
from sto.effects.ports import CallHandler, MergeHandler
from sto.engine.commands import OpenGate, OpenRevert, RunStep, StopRun
from sto.engine.drivers.local import EffectsExecutor, LocalDriver, RunWedgedError
from sto.engine.drivers.ports import Done, Outcome
from sto.engine.handlers.cancel import (
    CancelService,
    EffectLandedDuringStop,
    EffectUnresolvedDuringStop,
    GateEligibleStop,
    ScmReadTimeoutError,
    StopExecutor,
    StopNotAllowedError,
    StopSettings,
    StopWatch,
    StoreGateCloser,
    bounded_read,
    cancel_key,
)
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    EffectFailed,
    GateClosed,
    StepFailed,
)
from sto.engine.handlers.failures import RetryRequested
from sto.engine.handlers.stages import StageReported
from sto.engine.reducer import MalformedEventError, OutOfOrderEventError, RunState, next
from sto.gates.service import GateClosedError, GateService
from sto.store.memory import MemoryStore
from sto.store.ports import (
    Key,
    Op,
    Scope,
    Store,
    TeamScope,
    TransactionConflictError,
)

SCOPE = TeamScope("t1")
RID = RunId.from_parts(1, bytes(10))
SUBJECT = Subject(
    patch_id="p1",
    ticket_revision="r1",
    head_sha="h1",
    evidence_digest="e1",
    attention_digest="a1",
)
DIGEST = SUBJECT.digest()


class FlakyStore:
    """Delegates to a store; ``conflicts`` transactions in a row that touch an effect fail with
    ``TransactionConflictError`` (a contended item), then they go through."""

    def __init__(self, inner: Store, conflicts: int = 0) -> None:
        self.inner, self.conflicts = inner, conflicts

    def get(self, scope: Scope, key: Key) -> Any:
        return self.inner.get(scope, key)

    def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
        return self.inner.query(scope, pk, **kw)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        touches_effect = any(getattr(op, "key", None) and "FX#" in op.key.sk for op in ops)
        if touches_effect and self.conflicts > 0:
            self.conflicts -= 1
            raise TransactionConflictError("contended")
        self.inner.transact(scope, ops)

    def put(self, scope: Scope, key: Key, data: Any, *, when: Any = None) -> None:
        self.inner.put(scope, key, data, when=when)

    def delete(self, scope: Scope, key: Key, *, when: Any = None) -> None:
        self.inner.delete(scope, key, when=when)


def make_effects(
    status: RunStatus = RunStatus.CANCELLING,
    conflicts: int = 0,
    sleeps: list[float] | None = None,
) -> tuple[EffectExecutor, FlakyStore]:
    store = FlakyStore(MemoryStore())
    run = Run(RID, "t1", status, version=1, stage="merge")
    store.inner.put(SCOPE, Key(f"RUN#{RID}", "META"), to_wire(run))
    log = sleeps if sleeps is not None else []
    fx = EffectExecutor(store, SCOPE, sleep=log.append)
    store.conflicts = conflicts
    return fx, store


def plan(fx: EffectExecutor, type: str = "pr.update_branch", stage: str = "s") -> str:
    return fx.plan(RID, type, stage, 1, EffectClass.SCOPED, DIGEST).idempotency_key


# --- void_planned reports, it does not stay silent ---


def test_void_planned_reports_a_confirmed_effect_as_landed() -> None:
    fx, _ = make_effects(RunStatus.RUNNING)
    key = plan(fx)
    fx.execute(RID, key, CallHandler(lambda k: _receipt(k)))
    assert fx.get(RID, key).status is EffectStatus.CONFIRMED
    report = fx.void_planned(RID)
    assert report.voided == ()
    assert [e.idempotency_key for e in report.landed] == [key]


def test_void_planned_does_not_list_a_voided_or_failed_effect_as_landed() -> None:
    fx, _ = make_effects()
    key = plan(fx)
    assert [e.idempotency_key for e in fx.void_planned(RID).voided] == [key]
    again = fx.void_planned(RID)  # a repeated Stop: the void is not a landing
    assert again.voided == ()
    assert again.landed == ()


def test_void_planned_backs_off_on_conflicts_then_succeeds() -> None:
    sleeps: list[float] = []
    fx, store = make_effects(sleeps=sleeps)
    key = plan(fx)
    store.conflicts = 3
    report = fx.void_planned(RID)
    assert [e.idempotency_key for e in report.voided] == [key]
    assert len(sleeps) == 3
    assert sleeps == sorted(sleeps)
    assert sleeps[0] < sleeps[-1]  # it backs off, it does not spin
    assert all(0 < s <= 1.0 for s in sleeps)


def test_void_planned_does_not_stay_silent_when_conflicts_never_clear() -> None:
    sleeps: list[float] = []
    fx, store = make_effects(sleeps=sleeps)
    plan(fx)
    store.conflicts = 10_000
    with pytest.raises(TransientError, match="kept changing"):
        fx.void_planned(RID)  # not an empty StopReport: that would read as "nothing to stop"
    assert len(sleeps) >= 7


def _receipt(key: str) -> Any:

    return Receipt(f"x-{key}", "fake://x", True, simulated=True)


# === the driver, end to end ====================================================================


def _reducer_fixtures() -> Any:
    name = "_sto_reducer_v1_fixtures"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, Path(__file__).with_name("test_reducer_v1.py")
        )
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


_fx = _reducer_fixtures()
W: Any = _fx.W
S1: Subject = _fx.S1
REPO = RepoRef("acme", "app")
_IDS = itertools.count()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Alarms:
    def __init__(self) -> None:
        self.calls: list[tuple[RunId, str, str]] = []

    def raise_alarm(self, run_id: RunId, name: str, detail: str) -> None:
        self.calls.append((run_id, name, detail))

    def names(self) -> list[str]:
        return [n for _, n, _ in self.calls]


class Steps:
    def __init__(self) -> None:
        self.stopped: list[tuple[str, int, int]] = []

    def stop_step(self, run_id: RunId, stage: str, visit: int, attempt: int) -> None:
        self.stopped.append((stage, visit, attempt))


class BrokenGates:
    def close_open_gates(self, run_id: RunId) -> int:
        raise TransientError("the gate store is down")


class World:
    """The graph workflow on the real gate service, effects service and fake SCM, driven by the
    local driver. Steps and gates are scripted; effects and the Stop are the real code."""

    def __init__(self, **kw: Any) -> None:
        self.store: Store = MemoryStore()
        self.clock, self.alarms, self.steps = Clock(), Alarms(), Steps()
        self.svc = GateService(self.store)
        self.fx = EffectExecutor(self.store, SCOPE, sleep=lambda s: None)
        self.scm = FakeScm()
        self.scm.seed_branch(REPO, "main", "b0")
        self.scm.seed_branch(REPO, "sto/x", "abc", parent="b0")
        self.pr = PrRef.of(
            REPO, self.scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "t", "b"), "k")
        )
        self.scm.mark_ready(self.pr, "k2")
        self.auto_gates = {"review_gate"}
        self.on_gate: Callable[[], Awaitable[None]] | None = None
        self.fail_step: str | None = None
        self.executed: list[tuple[str, RunStatus]] = []
        self.hook: Callable[[str], Awaitable[None]] | None = None
        self.sleeps: list[float] = []
        self.on_sleep: Callable[[], Awaitable[None]] | None = None
        self.driver: LocalDriver
        handlers = {"pr.merge": MergeHandler(self.scm, self.pr, "abc", MergeMethod.SQUASH, S1)}
        self.stop = StopExecutor(
            store=self.store,
            scope=SCOPE,
            effects=self.fx,
            handlers=handlers,  # type: ignore[arg-type]
            load=lambda rid: self.driver.state(rid),
            clock=self.clock,
            alarm=self.alarms,
            lookup=kw.pop("lookup", lambda e: self.scm.find_merge(self.pr)),
            revert=lambda rid, sha, key: self.scm.open_revert_pr(REPO, sha, key),
            steps=self.steps,
            gates=kw.pop("gates", StoreGateCloser(self.store, SCOPE)),
            settings=kw.pop("settings", StopSettings(stop_timeout=60.0, retry_after=1.0)),
        )
        world = self

        class Router:
            async def execute(self, key: str, command: object) -> Outcome:
                if isinstance(command, RunStep):
                    return await world.script_step(command)
                if isinstance(command, OpenGate):
                    return await world.script_gate(command)
                return await world.stop.execute(key, command)

        class Tap:
            def __init__(self, inner: EffectsExecutor) -> None:
                self.inner = inner

            async def execute(self, key: str, command: object) -> Outcome:
                state = world.driver.state(RID)
                world.executed.append((type(command).__name__, state.run.status))
                if world.hook:
                    await world.hook("inside_before")
                out = await self.inner.execute(key, command)
                if world.hook:
                    await world.hook("inside_after")
                return out

        adapter = EffectsExecutor(
            self.fx,
            {"pr.merge": handlers["pr.merge"]},
            lambda cmd: S1,
            lambda rid: self.driver.state(rid).run.status,
            others=Router(),
            poll_interval=0.5,
        )

        async def sleep(s: float) -> None:
            self.sleeps.append(s)
            self.clock.now += s
            if self.on_sleep is not None:
                await self.on_sleep()

        self.driver = LocalDriver(
            self.store,
            SCOPE,
            W,
            Tap(adapter),
            owner="me",
            new_id=lambda: str(next_id()),
            clock=self.clock,
            lease_seconds=3600.0,
            sleep=sleep,
            **kw,
        )

    async def script_step(self, cmd: RunStep) -> Outcome:
        if self.fail_step == cmd.stage:
            return Done([StepFailed(StepKey(cmd.run_id, cmd.stage, cmd.visit, cmd.attempt),
                                    FailureClass.PERMANENT)])  # fmt: skip
        outcome, subject = {
            "implement": ("ready", None),
            "panel": ("clean", S1),
            "qa_agent": ("pass", None),
        }[cmd.stage]
        key = StepKey(cmd.run_id, cmd.stage, cmd.visit, cmd.attempt)
        return Done([StageReported(key, outcome, subject)])

    async def script_gate(self, cmd: OpenGate) -> Outcome:
        self.svc.open_gate(SCOPE, cmd)
        if self.on_gate is not None:
            await self.on_gate()
        if cmd.name not in self.auto_gates:
            return Done()
        d = self.svc.decide(
            SCOPE,
            run_id=cmd.run_id,
            gate=cmd.name,
            round=cmd.round,
            kind=DecisionKind.APPROVE,
            actor="alice",
            surface=Surface.UI,
            subject_digest=cmd.subject.digest(),
        )
        closed = GateClosed(
            cmd.run_id,
            cmd.name,
            cmd.round,
            DecisionKind.APPROVE,
            "alice",
            d.decision.id,
            cmd.subject,
        )
        return Done([closed])

    # --- reading the outcome ----------------------------------------------------------------

    def effects(self) -> list[Effect]:
        page = self.store.query(SCOPE, f"RUN#{RID}", sk_prefix="FX#")
        return [from_wire(Effect, i.data["effect"]) for i in page.items]

    def timeline_types(self) -> list[tuple[str, str]]:
        return [(e["type"], e["outcome"]) for e in self.driver.timeline(RID)]

    def landed(self) -> bool:
        found = self.scm.find_merge(self.pr)
        return found is not None and found.state is MergeState.MERGED

    def land_pending(self) -> bool:
        """The queue lets a pending merge in; False if there was none (or it was dequeued)."""
        for handle in self.scm.merges():
            try:
                self.scm.complete_merge(handle, f"m-{handle.id}")
            except RefusedError:
                continue
            return True
        return False

    async def start(self) -> RunState:
        await self.driver.start(Run(RID, "t1"))
        return await self.driver.run_until_idle(RID)


def next_id() -> int:
    return _IDS.__next__()


def run[T](coro: Coroutine[Any, Any, T], timeout: float = 30) -> T:
    return asyncio.run(asyncio.wait_for(coro, timeout))


# --- G10: Stop beats an approved but unexecuted effect ---


async def to_the_merge(w: World) -> None:
    """Drive step by step until the approval has been applied and the merge is the next command,
    planned and not yet sent."""
    await w.driver.start(Run(RID, "t1"))
    for _ in range(40):
        rec = w.driver._load(RID)  # noqa: SLF001 - a test reads the stored record
        if not rec.inbox and rec.pending and rec.pending[0]["cmd"]["type"] == "run_effect":
            return
        await w.driver.step(RID)
    raise AssertionError("the run never reached the merge")


def test_stop_beats_an_approved_but_unexecuted_effect() -> None:
    w = World()

    async def go() -> RunState:
        await to_the_merge(w)
        assert w.driver.state(RID).run.stage == "merge"
        assert w.effects() == []  # approved, planned in the command, not executed
        return await w.driver.cancel(RID)

    rs = run(go())
    assert (rs.run.status, rs.run.incident) == (RunStatus.CANCELLED, False)
    (merge,) = w.effects()
    assert merge.status is EffectStatus.VOIDED
    assert w.scm.merges() == []  # the writer was never called
    assert w.scm.spy.applied("request_merge") == ()
    types = w.timeline_types()
    assert ("gate.closed", "applied") in types
    assert types.index(("gate.closed", "applied")) < types.index(("cancel.requested", "applied"))
    assert w.driver.rejected(RID) == []


# --- Stop after a merge: a revert, an incident, never plain CANCELLED ---


def _land_after_response_lost(w: World) -> None:
    """The merge is requested, the answer is lost, and the merge then lands behind the driver."""
    w.scm.lose_response_next("request_merge")


def test_stop_after_a_merge_that_landed_unseen_plans_a_revert_and_is_an_incident() -> None:
    w = World()
    _land_after_response_lost(w)

    async def land_then_stop() -> None:
        w.on_sleep = None
        w.scm.complete_merge(w.scm.merges()[-1], "m-landed")
        await w.driver.submit(RID, CancelRequested(RID))

    w.on_sleep = land_then_stop
    rs = run(w.start())
    assert rs.run.status is RunStatus.CANCELLED
    assert rs.run.incident is True  # done_with_incident, never plain CANCELLED
    assert [m.sha for m in rs.merges] == ["m-landed"]
    assert len(w.scm.spy.applied("open_revert_pr")) == 1
    assert ("cancel.effect_landed", "applied") in w.timeline_types()
    assert "done_with_incident" in w.alarms.names()
    assert w.driver.rejected(RID) == []


def test_a_merge_confirmed_while_the_stop_is_applied_is_recorded_not_refused() -> None:
    """The effect was sent while RUNNING; its confirmation is heard after CANCELLING."""
    w = World()

    async def stop_then_land() -> None:
        w.on_sleep = None
        await w.driver.submit(RID, CancelRequested(RID))
        w.scm.complete_merge(w.scm.merges()[-1], "m-late")

    w.on_sleep = stop_then_land
    rs = run(w.start())
    assert (rs.run.status, rs.run.incident) == (RunStatus.CANCELLED, True)
    assert [m.sha for m in rs.merges] == ["m-late"]
    assert len(w.scm.spy.applied("open_revert_pr")) == 1
    types = w.timeline_types()
    assert ("cancel.effect_landed", "applied") in types
    assert ("effect.confirmed", "out_of_order") not in types  # never silently dropped


def test_a_stop_before_any_merge_ends_plain_cancelled() -> None:
    w = World()
    w.auto_gates = set()  # the run waits at the review gate

    rs = run(w.start())
    assert rs.run.status is RunStatus.WAITING_HUMAN

    async def stop() -> RunState:
        return await w.driver.cancel(RID)

    final = run(stop())
    assert (final.run.status, final.run.incident) == (RunStatus.CANCELLED, False)
    assert w.scm.spy.applied("open_revert_pr") == ()


def test_the_stop_reports_a_confirmed_merge_the_run_never_heard_about() -> None:
    """``void_planned`` after CONFIRMED reports the landed merge: the Stop turns it into the
    record that plans the revert, instead of ending plain CANCELLED."""
    w = World()

    async def go() -> list[object]:
        await to_the_merge(w)
        cmd = w.driver._load(RID).pending[0]  # noqa: SLF001
        key = cmd["key"]
        await w.driver._executor.execute(key, from_wire_command(cmd))  # noqa: SLF001
        (merge,) = w.effects()
        w.scm.complete_merge(w.scm.merges()[-1], "m-heard-nowhere")
        w.fx.poll(RID, merge.idempotency_key, w.stop._handlers["pr.merge"])  # noqa: SLF001
        assert w.effects()[0].status is EffectStatus.CONFIRMED
        # the run is CANCELLING by now, and the confirmation event was lost
        await w.driver.submit(RID, CancelRequested(RID))
        await w.driver.step(RID)
        done = await w.stop.execute("k", StopRun(RID))
        assert isinstance(done, Done)
        return list(done.events)

    events = run(go())
    landed = [e for e in events if isinstance(e, EffectLandedDuringStop)]
    assert [(e.effect, e.merge_sha) for e in landed] == [("pr.merge", "m-heard-nowhere")]
    assert landed[0].head_sha == "abc"


def from_wire_command(cmd: dict[str, Any]) -> object:
    from sto.engine.drivers.local import decode

    return decode(cmd["cmd"], "command")


# --- unresolved effects are shown, not refused ---


def test_a_blocked_effect_on_a_stopped_run_shows_plainly() -> None:
    w = World()
    w.auto_gates = set()
    run(w.start())

    async def go() -> RunState:
        await w.driver.submit(RID, CancelRequested(RID))
        await w.driver.submit(RID, EffectFailed(RID, "pr.merge", 1, "blocked"))
        return await w.driver.run_until_idle(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.CANCELLED
    types = w.timeline_types()
    assert ("cancel.effect_unresolved", "applied") in types
    assert w.driver.rejected(RID) == []  # not "a refused event": the only trace used to be there


def test_a_blocked_merge_with_no_lookup_keeps_the_stop_open_and_alarms() -> None:
    """Without a way to ask the SCM whether it landed, the Stop does not guess."""
    w = World(lookup=None)
    _land_after_response_lost(w)

    class Enough(Exception):
        pass

    async def land_then_stop() -> None:
        if len(w.sleeps) == 1:
            w.scm.complete_merge(w.scm.merges()[-1], "m-x")
            await w.driver.submit(RID, CancelRequested(RID))
        if len(w.sleeps) > 70:
            raise Enough

    w.on_sleep = land_then_stop
    with pytest.raises(Enough):
        run(w.start())
    assert w.driver.state(RID).run.status is RunStatus.CANCELLING  # never CANCELLED unseen
    assert "stuck_stop" in w.alarms.names()
    assert w.alarms.names().count("stuck_stop") == 1  # once, not on every retry


# --- C3: Stop during each state ends CANCELLED, no leaks ---


def _ticks_in_a_full_run() -> int:
    w = World()
    w.auto_gates = {"review_gate"}

    async def go() -> int:
        await w.driver.start(Run(RID, "t1"))
        n = 0
        while await w.driver.step(RID) != "idle":
            n += 1
            w.land_pending()
            assert n < 200
        return n

    return run(go())


FULL_RUN_TICKS = _ticks_in_a_full_run()


@pytest.mark.parametrize("tick", range(FULL_RUN_TICKS + 1))
def test_c3_a_stop_at_every_point_of_the_run_ends_cancelled_with_nothing_left(tick: int) -> None:
    w = World()

    async def go() -> RunState:
        await w.driver.start(Run(RID, "t1"))
        for _ in range(tick):
            if await w.driver.step(RID) == "idle":
                break
            w.land_pending()
        return await w.driver.cancel(RID)

    rs = run(go())
    assert rs.run.status in (RunStatus.CANCELLED, RunStatus.WAITING_HUMAN) or rs.run.incident
    assert rs.run.status is RunStatus.CANCELLED
    assert rs.run.incident is w.landed()  # an incident exactly when a merge landed
    assert w.driver.pending_events(RID) == 0
    assert w.driver._load(RID).pending == ()  # noqa: SLF001 - nothing queued: no leak
    assert RID not in run(_active(w))
    for e in w.effects():
        assert e.status in (EffectStatus.VOIDED, EffectStatus.CONFIRMED), e.status
    assert not any(
        name in ("RunStep", "OpenGate") and status is RunStatus.CANCELLING
        for name, status in w.executed
    ), "a stopping run dispatched a new step or gate"
    if w.landed():
        assert len(w.scm.spy.applied("open_revert_pr")) == 1
    items = w.store.query(SCOPE, f"RUN#{RID}", sk_prefix="GATE#").items
    gates = [from_wire(Gate, i.data) for i in items]
    assert all(not g.is_open for g in gates), "a gate was left open"


async def _active(w: World) -> list[RunId]:
    return await w.driver.active_runs()


# --- C4: a connection closing changes nothing ---


def test_c4_dropping_the_client_does_not_stop_or_change_the_run() -> None:
    w = World()
    w.auto_gates = set()

    async def go() -> tuple[RunState, RunState]:
        await w.driver.start(Run(RID, "t1"))
        client = asyncio.ensure_future(w.driver.run_until_idle(RID))
        await asyncio.sleep(0)
        client.cancel()  # the browser closed: the request task is cancelled
        await asyncio.gather(client, return_exceptions=True)
        before = w.driver.state(RID)
        assert before.run.status is not RunStatus.CANCELLING
        after = await w.driver.run_until_idle(RID)  # a fresh request carries on
        return before, after

    before, after = run(go())
    assert after.run.status is RunStatus.WAITING_HUMAN
    assert ("cancel.requested", "applied") not in w.timeline_types()
    assert w.driver.pending_events(RID) == 0


# --- the driver: a stopping run starts nothing new ---


def test_a_step_queued_before_the_stop_is_dropped_not_run_after_it() -> None:
    w = World()

    async def go() -> RunState:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.step(RID)  # apply RunStarted: RunStep(implement) is pending
        assert w.driver._load(RID).pending[0]["cmd"]["type"] == "run_step"  # noqa: SLF001
        await w.driver.submit(RID, CancelRequested(RID))
        return await w.driver.run_until_idle(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.CANCELLED
    assert [n for n, _ in w.executed if n == "RunStep"] == []  # the step never started


# --- the stuck-stop alarm ---


def test_a_stop_that_keeps_failing_raises_the_alarm_once_and_never_gives_up() -> None:
    w = World(gates=BrokenGates())
    w.auto_gates = set()

    class Enough(Exception):
        pass

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)  # waits at the gate
        await w.driver.submit(RID, CancelRequested(RID))

        async def enough() -> None:
            if len(w.sleeps) > 60:
                raise Enough

        w.on_sleep = enough
        await w.driver.run_until_idle(RID)

    with pytest.raises(Enough):
        run(go())
    assert w.driver.state(RID).run.status is RunStatus.CANCELLING  # still trying, not dropped
    assert w.alarms.names().count("stuck_stop") == 1
    assert "gate store is down" in [d for _, n, d in w.alarms.calls if n == "stuck_stop"][0]
    note = w.store.get(SCOPE, cancel_key(RID))
    assert note is not None
    assert note.data["alarmed"] is True
    assert note.data["attempts"] >= 5
    assert "TransientError" in note.data["last_error"]


def test_a_fast_stop_that_fails_a_few_times_raises_no_alarm() -> None:
    w = World()
    broken = {"n": 2}

    class Flaky:
        def close_open_gates(self, run_id: RunId) -> int:
            if broken["n"] > 0:
                broken["n"] -= 1
                raise TransientError("blip")
            return 0

    w = World(gates=Flaky())
    w.auto_gates = set()

    async def go() -> RunState:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        return await w.driver.cancel(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.CANCELLED
    assert w.alarms.names() == []


def test_the_watch_finds_a_dead_run_whose_stop_nobody_is_driving() -> None:
    w = World()
    w.auto_gates = set()
    alarms = w.alarms

    async def go() -> list[RunId]:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        service = _service(w)
        await service.stop(RID, "alice", "wrong ticket")
        # no driver ever runs: the process died. Time passes.
        watch = StopWatch(
            store=w.store,
            scope=SCOPE,
            active_runs=w.driver.active_runs,
            load=w.driver.state,
            clock=w.clock,
            alarm=alarms,
            timeout=60.0,
        )
        assert await watch.sweep() == []  # not yet
        w.clock.now += 61
        first = await watch.sweep()
        assert await watch.sweep() == []  # raised once, not on every sweep
        return first

    assert run(go()) == [RID]
    assert alarms.names() == ["stuck_stop"]


# --- who may Stop, and the audited service ---


class Audit:
    def __init__(self) -> None:
        self.rows: list[tuple[RunId, str, str, dict[str, object]]] = []

    def record(self, run_id: RunId, action: str, actor: str, data: dict[str, object]) -> None:
        self.rows.append((run_id, action, actor, data))


def _service(
    w: World, eligible: set[str] | None = None, audit: Audit | None = None
) -> CancelService:
    return CancelService(
        policy=GateEligibleStop(lambda rid: eligible if eligible is not None else {"alice"}),
        audit=audit or Audit(),
        store=w.store,
        scope=SCOPE,
        clock=w.clock,
        submit=w.driver.submit,
        load=w.driver.state,
        quiesce=w.driver.stop_background,
    )


def test_people_eligible_for_a_gate_can_stop_and_others_cannot() -> None:
    w = World()
    w.auto_gates = set()
    audit = Audit()

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        service = _service(w, {"alice", "bob"}, audit)
        with pytest.raises(StopNotAllowedError):
            await service.stop(RID, "mallory", "because")
        assert w.driver.pending_events(RID) == 0  # nothing was queued for a refused Stop
        assert audit.rows == []
        with pytest.raises(MalformedEventError):
            await service.stop(RID, "bob", "  ")
        event = await service.stop(RID, "bob", "wrong ticket")
        assert event == CancelRequested(RID)
        rs = await w.driver.run_until_idle(RID)
        assert rs.run.status is RunStatus.CANCELLED

    run(go())
    assert [(a, actor, d["reason"]) for _, a, actor, d in audit.rows] == [
        ("run.cancel", "bob", "wrong ticket")
    ]


def test_a_second_stop_is_harmless_and_a_stop_of_a_finished_run_is_refused() -> None:
    w = World()
    w.auto_gates = set()
    audit = Audit()

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        service = _service(w, audit=audit)
        await service.stop(RID, "alice", "one")
        await service.stop(RID, "alice", "two")  # a second person's click: audited, and refused
        rs = await w.driver.run_until_idle(RID)
        assert rs.run.status is RunStatus.CANCELLED
        with pytest.raises(OutOfOrderEventError):
            await service.stop(RID, "alice", "three")

    run(go())
    assert len(audit.rows) == 2  # each click is a person's act
    types = w.timeline_types()
    assert types.count(("cancel.requested", "applied")) == 1  # the run takes one
    assert types.count(("cancel.requested", "out_of_order")) == 1
    requested = w.store.get(SCOPE, cancel_key(RID))
    assert requested is not None
    assert requested.data["requested_at"] == 1000.0  # the first request's time stands


# --- gates ---


def test_stop_closes_an_open_gate_so_a_late_decision_is_refused() -> None:
    w = World()
    w.auto_gates = set()

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        rs = await w.driver.run_until_idle(RID)
        assert rs.run.status is RunStatus.WAITING_HUMAN
        await w.driver.cancel(RID)

    run(go())
    (item,) = w.store.query(SCOPE, f"RUN#{RID}", sk_prefix="GATE#").items
    gate = from_wire(Gate, item.data)
    assert gate.status is GateStatus.CANCELLED
    with pytest.raises(GateClosedError):
        w.svc.decide(
            SCOPE,
            run_id=RID,
            gate="review_gate",
            round=1,
            kind=DecisionKind.APPROVE,
            actor="alice",
            surface=Surface.UI,
            subject_digest=gate.subject.digest(),
        )
    assert StoreGateCloser(w.store, SCOPE).close_open_gates(RID) == 0  # idempotent


# --- the live step's attempt ---


def test_stop_ends_the_live_steps_attempt_and_nothing_after_it() -> None:
    w = World()

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.step(RID)  # RunStarted
        await w.driver.step(RID)  # RunStep(implement) executed -> StageReported queued
        await w.driver.cancel(RID)

    run(go())
    # the stage reported while RUNNING; the stopped visit/attempt is the live one at CANCELLING
    assert w.steps.stopped
    assert all(isinstance(v, int) and v >= 1 for _, v, _ in w.steps.stopped)
    assert w.steps.stopped[-1][0] in ("implement", "panel")


# --- SCM reads are bounded ---


def test_a_hung_scm_read_times_out_on_its_own_pool_not_the_default_one() -> None:
    from concurrent.futures import ThreadPoolExecutor

    release = threading.Event()
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sto-scm-test")
    started = time.monotonic()
    names: list[str] = []

    def hang() -> MergeResult:
        names.append(threading.current_thread().name)
        release.wait(10)
        return MergeResult(MergeState.MERGED, "x")

    try:
        with pytest.raises(ScmReadTimeoutError):
            bounded_read(hang, timeout=0.2, pool=pool)
        assert time.monotonic() - started < 5
        assert names[0].startswith("sto-scm-test")
        assert isinstance(ScmReadTimeoutError("x"), TransientError)  # retried, never "no merge"
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_a_timed_out_merge_lookup_keeps_the_stop_open() -> None:
    w = World(
        lookup=lambda e: (_ for _ in ()).throw(ScmReadTimeoutError("slow")),
        settings=StopSettings(stop_timeout=60, retry_after=1.0),
    )
    _land_after_response_lost(w)

    class Enough(Exception):
        pass

    async def land_then_stop() -> None:
        if len(w.sleeps) == 1:
            w.scm.complete_merge(w.scm.merges()[-1], "m-y")
            await w.driver.submit(RID, CancelRequested(RID))
        if len(w.sleeps) > 8:
            raise Enough

    w.on_sleep = land_then_stop
    with pytest.raises(Enough):
        run(w.start())
    assert w.driver.state(RID).run.status is RunStatus.CANCELLING  # a failed read is not "empty"


# --- the queued merge keeps the Stop open ---


def test_a_merge_still_queued_after_a_failed_dequeue_keeps_the_stop_open() -> None:
    """``find_merge`` says PENDING: it may still land, so CancelCompleted waits."""
    pending = MergeResult(MergeState.PENDING)
    w = World(lookup=lambda e: pending)
    _land_after_response_lost(w)
    w.scm.lose_response_next("dequeue", 100)  # the dequeue cannot be confirmed

    class Enough(Exception):
        pass

    async def stop_now() -> None:
        if len(w.sleeps) == 1:
            await w.driver.submit(RID, CancelRequested(RID))
        if len(w.sleeps) > 8:
            raise Enough

    w.on_sleep = stop_now
    with pytest.raises((Enough, RuntimeError)):
        run(w.start())
    assert w.driver.state(RID).run.status is RunStatus.CANCELLING


# --- driver changes: heartbeat, WAITING_EXTERNAL, background re-drive ---


def test_waiting_external_is_idle_allowed_not_wedged() -> None:
    w = World()
    w.auto_gates = set()

    async def go() -> RunState:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        # a handler enters WAITING_EXTERNAL; model it by moving the stored run there
        rec = w.driver._load(RID)  # noqa: SLF001
        import dataclasses as dc

        run_ = dc.replace(rec.state.run, status=RunStatus.WAITING_EXTERNAL)
        rec2 = dc.replace(rec, state=dc.replace(rec.state, run=run_))
        await w.driver._write(dc.replace(rec2, version=rec.version))  # noqa: SLF001
        return await w.driver.run_until_idle(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.WAITING_EXTERNAL  # not RunWedgedError


def test_wedged_still_raises_for_a_running_run_with_nothing_queued() -> None:
    assert RunWedgedError is not None  # the guard stays for every non-idle-allowed status


def test_the_lease_heartbeat_has_its_own_thread_and_survives_a_first_load_error() -> None:
    w = World()
    seen: list[str] = []
    real_get = w.store.get
    state = {"fail_once": True, "beat": False}

    def get(scope: Scope, key: Key) -> Any:
        name = threading.current_thread().name
        if state["beat"] and name.startswith("sto-lease"):
            seen.append(name)
            if state["fail_once"]:
                state["fail_once"] = False
                raise TransientError("store blip on the heartbeat's first load")
        return real_get(scope, key)

    w.store.get = get  # type: ignore[method-assign]
    w.driver._ttl = 0.3  # noqa: SLF001 - a short lease so the beat fires within the test
    inner = w.driver._executor  # noqa: SLF001

    class Slow:
        async def execute(self, key: str, command: object) -> Outcome:
            await asyncio.sleep(0.5)  # longer than the lease: only the heartbeat keeps the run
            return await inner.execute(key, command)

    w.driver._executor = Slow()  # noqa: SLF001

    async def go() -> RunState:
        await w.driver.start(Run(RID, "t1"))
        state["beat"] = True
        return await w.driver.run_until_idle(RID)

    w.auto_gates = set()
    rs = run(go())
    assert rs.run.status is RunStatus.WAITING_HUMAN  # the slow steps finished: no LeaseLostError
    assert seen, "the heartbeat never used its own thread"
    assert state["fail_once"] is False  # the first load failed and the command still finished


# === every interleaving: Stop wins every race ===================================================

PHASES = ("before", "inside_before", "inside_after")


class Plan:
    """When the Stop (C) is submitted and when the merge lands in the queue (M), as a position in
    the driver's ticks. A tick is one ``driver.step``; ``inside_*`` fire around the executor call
    of that tick, i.e. while an effect is in flight. An action fires at the first point at or after
    its position that really occurs, so every position is exercised."""

    def __init__(self, w: World, c: tuple[int, int], m: tuple[int, int] | None, order: str) -> None:
        self.w, self.c, self.m, self.order = w, c, m, order
        self.tick = 0
        self.c_done = self.m_done = False

    async def fire(self, phase: str) -> None:
        here = (self.tick, PHASES.index(phase))
        for which in self.order:
            if which == "c" and not self.c_done and here >= self.c:
                self.c_done = True
                await self.w.driver.submit(RID, CancelRequested(RID))
            if which == "m" and self.m is not None and not self.m_done and here >= self.m:
                self.m_done = self.w.land_pending()


def _check_stop_won(w: World, plan: Plan, final: RunState) -> None:
    landed = w.landed()
    assert final.run.status is RunStatus.CANCELLED
    assert final.run.incident is landed, "an incident exactly when a merge landed"
    assert len(w.scm.spy.applied("open_revert_pr")) == (1 if landed else 0)
    if landed:
        types = {t for t, o in w.timeline_types() if o == "applied"}
        assert types & {"effect.confirmed", "cancel.effect_landed"}, "a landed merge was dropped"
        assert final.merges, "a landed merge is not recorded on the run"
    found = w.scm.find_merge(w.pr)
    assert found is None or found.state is MergeState.MERGED, "a merge is still queued"
    assert w.land_pending() is False, "a merge landed after the Stop finished"
    assert not any(
        name in ("RunStep", "OpenGate") and status is RunStatus.CANCELLING
        for name, status in w.executed
    )
    for e in w.effects():
        assert e.status in (EffectStatus.VOIDED, EffectStatus.CONFIRMED), e.status
    refused = [r for r in w.driver.rejected(RID) if r["type"].startswith("effect.")]
    assert refused == [], f"an effect event was refused: {refused}"
    assert w.driver._load(RID).pending == ()  # noqa: SLF001
    assert plan.c_done


def test_stop_wins_every_interleaving_with_an_in_flight_merge() -> None:
    ticks = 4
    points = [(t, p) for t in range(ticks) for p in range(len(PHASES))] + [(ticks, 0)]
    cases = [
        (c, m, order)
        for c in points
        for m in [*points, None]
        for order in (("cm", "mc") if m is not None else ("cm",))
    ]
    assert len(cases) == len(points) * (2 * len(points) + 1)
    failures: list[str] = []
    outcomes: list[bool] = []  # per case: did a merge land

    async def one(c: tuple[int, int], m: tuple[int, int] | None, order: str) -> None:
        w = World()
        await to_the_merge(w)
        plan = Plan(w, c, m, order)
        w.hook = plan.fire
        for tick in range(ticks):
            plan.tick = tick
            await plan.fire("before")
            await w.driver.step(RID)
        plan.tick = ticks
        await plan.fire("before")
        if not plan.c_done:  # a position after the last tick: the Stop still arrives
            plan.c_done = True
            await w.driver.submit(RID, CancelRequested(RID))
        w.hook = None
        final = await w.driver.run_until_idle(RID)
        _check_stop_won(w, plan, final)
        outcomes.append(w.landed())

    async def guarded(c: tuple[int, int], m: tuple[int, int] | None, order: str) -> None:
        try:
            await one(c, m, order)
        except Exception as exc:  # noqa: BLE001 - collect every failing interleaving
            failures.append(f"C@{c} M@{m} {order}: {type(exc).__name__}: {exc}")

    async def all_cases() -> None:
        # Independent worlds: run them side by side so the store's thread hops overlap.
        for i in range(0, len(cases), 24):
            await asyncio.gather(*(guarded(*case) for case in cases[i : i + 24]))

    run(all_cases(), timeout=300)
    # the enumeration reaches both worlds: merges that landed before the Stop could dequeue them,
    # and merges the Stop dequeued or never let start
    assert any(outcomes), "no interleaving let the merge land: the race is not exercised"
    assert not all(outcomes), "every interleaving landed the merge: the dequeue is not exercised"
    assert len(outcomes) == len(cases) - len(failures)
    assert failures == [], f"{len(failures)} of {len(cases)} interleavings:\n" + "\n".join(
        failures[:10]
    )


def test_stop_wins_every_interleaving_with_a_retry() -> None:
    ticks = 4
    cases = [(r, c, order) for r in range(ticks) for c in range(ticks) for order in ("rc", "cr")]
    cases = [x for x in cases if x[0] != x[1] or True]
    failures: list[str] = []

    async def one(r_at: int, c_at: int, order: str) -> None:
        w = World()
        w.fail_step = "implement"
        await w.driver.start(Run(RID, "t1"))
        blocked = await w.driver.run_until_idle(RID)
        assert blocked.run.status is RunStatus.BLOCKED
        w.fail_step = None  # a retry would now succeed: it must still lose to the Stop
        retry = RetryRequested(
            RID, "bob", "again", "implement", blocked.visit, blocked.attempt, blocked.run.version
        )
        sent = {"r": False, "c": False}
        before = len(w.executed)
        for tick in range(ticks):
            for which in order:
                if which == "r" and not sent["r"] and tick >= r_at:
                    sent["r"] = True
                    await w.driver.submit(RID, retry)
                if which == "c" and not sent["c"] and tick >= c_at:
                    sent["c"] = True
                    await w.driver.submit(RID, CancelRequested(RID))
            await w.driver.step(RID)
        final = await w.driver.run_until_idle(RID)
        assert (final.run.status, final.run.incident) == (RunStatus.CANCELLED, False)
        late = [n for n, s in w.executed[before:] if s is RunStatus.CANCELLING]
        assert late == [] or set(late) <= {"StopRun"}, late
        assert [n for n, _ in w.executed[before:]].count("RunStep") <= 1
        assert w.driver._load(RID).pending == ()  # noqa: SLF001

    async def all_cases() -> None:
        for r_at, c_at, order in cases:
            try:
                await one(r_at, c_at, order)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"R@{r_at} C@{c_at} {order}: {type(exc).__name__}: {exc}")

    run(all_cases(), timeout=120)
    assert failures == [], "\n".join(failures[:10])


def test_stop_ends_the_background_redrive_of_the_run() -> None:
    w = World(redrive=None)  # replaced below: a driver that has a Redriver

    class Dead:
        async def execute(self, key: str, command: object) -> Outcome:
            raise TransientError("lease still held by a dead driver")

    from sto.engine.handlers.failures import RetryPolicy

    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)
        await asyncio.sleep(10)  # a long backoff: the re-drive is parked in it

    async def go() -> None:
        d = LocalDriver(
            w.store, SCOPE, W, Dead(), owner="me", new_id=lambda: str(next_id()), clock=w.clock,
            lease_seconds=3600.0, sleep=sleep,
            redrive=RetryPolicy(max_attempts=5, base_delay=5, max_delay=60, total_budget=1000),
        )  # fmt: skip
        w.driver = d
        await d.start(Run(RID, "t1"))
        assert d.redriver is not None
        task = d.redriver.spawn(RID)
        await asyncio.sleep(0.05)
        assert not task.done()
        await d.stop_background(RID)
        assert task.cancelled()
        assert RID not in d.redriver._tasks  # noqa: SLF001 - nothing left to re-drive behind a Stop
        await d.aclose()

    run(go())


# === the reducer side: what a stopping run records ==============================================


def _stopping() -> RunState:
    return next(_fx.at_merge(), CancelRequested(RID), W).state


def test_a_landed_merge_is_recorded_once_and_gets_a_revert_and_an_incident() -> None:
    rs = _stopping()
    event = EffectLandedDuringStop(RID, "pr.merge", 1, "m1", "abc")
    t = next(rs, event, W)
    assert [(m.sha, m.head_sha) for m in t.state.merges] == [("m1", "abc")]
    assert t.state.run.version == rs.run.version + 1
    assert t.commands == ()
    again = next(t.state, event, W).state  # a replay or a second report adds nothing
    assert again.merges == t.state.merges
    ended = next(again, CancelCompleted(RID), W)
    assert ended.state.run.status is RunStatus.CANCELLED
    assert ended.state.run.incident is True
    assert [type(c).__name__ for c in ended.commands] == ["OpenRevert", "Finish"]


def test_a_landed_effect_that_is_not_a_merge_is_only_recorded() -> None:
    rs = _stopping()
    t = next(rs, EffectLandedDuringStop(RID, "pr.update_branch", 1), W)
    assert t.state.merges == ()
    assert t.state.run.version == rs.run.version + 1


def test_a_landed_merge_must_say_which_merge() -> None:
    with pytest.raises(MalformedEventError):
        next(_stopping(), EffectLandedDuringStop(RID, "pr.merge", 1, "  ", "abc"), W)


@pytest.mark.parametrize(
    "event",
    [
        EffectLandedDuringStop(RID, "pr.merge", 1, "m1", "abc"),
        EffectUnresolvedDuringStop(RID, "pr.merge", 1),
    ],
)
def test_the_stop_records_are_refused_unless_the_run_is_stopping(event: Any) -> None:
    with pytest.raises(OutOfOrderEventError, match="not CANCELLING"):
        next(_fx.at_merge(), event, W)


def test_an_unresolved_effect_is_an_applied_record_with_no_other_change() -> None:
    rs = _stopping()
    t = next(rs, EffectUnresolvedDuringStop(RID, "pr.merge", 1, "blocked"), W)
    assert t.state.run.status is RunStatus.CANCELLING
    assert t.state.run.version == rs.run.version + 1
    assert (t.state.merges, t.commands) == ((), ())


def test_the_linear_registry_records_them_too() -> None:
    from sto.engine.reducer import LINEAR_V0

    rs = RunState(Run(RID, "t", RunStatus.CANCELLING, stage="merge"))
    t = next(rs, EffectLandedDuringStop(RID, "pr.merge", 1, "m1", "abc"), LINEAR_V0)
    assert [m.sha for m in t.state.merges] == ["m1"]


def test_only_a_named_person_in_the_set_may_stop() -> None:
    policy = GateEligibleStop(lambda rid: {"alice"})
    assert policy.may_stop("alice", RID)
    assert not policy.may_stop("bob", RID)
    assert not policy.may_stop("", RID)
    assert not GateEligibleStop(lambda rid: {""}).may_stop("", RID)


# === the Stop executor on its own =============================================================


def test_stop_run_replayed_reports_the_same_and_does_nothing_twice() -> None:
    w = World()
    w.auto_gates = set()

    async def go() -> tuple[Done, Done]:
        await w.driver.start(Run(RID, "t1"))
        await w.driver.run_until_idle(RID)
        await w.driver.submit(RID, CancelRequested(RID))
        await w.driver.step(RID)
        first = await w.stop.execute("k", StopRun(RID))
        second = await w.stop.execute("k", StopRun(RID))
        assert isinstance(first, Done)
        assert isinstance(second, Done)
        return first, second

    first, second = run(go())
    assert [type(e).__name__ for e in first.events] == ["CancelCompleted"]
    assert [type(e).__name__ for e in second.events] == ["CancelCompleted"]


def test_open_revert_is_idempotent_on_the_merge_and_a_blocked_one_alarms() -> None:
    w = World()
    cmd = OpenRevert(RID, "m1")

    async def go() -> None:
        await w.driver.start(Run(RID, "t1"))
        handle = w.scm.request_merge(w.pr, "abc", MergeMethod.SQUASH, "mk")
        w.scm.complete_merge(handle, "m1")
        for _ in range(3):
            out = await w.stop.execute("k", cmd)
            assert isinstance(out, Done)
        assert len(w.scm.spy.applied("open_revert_pr")) == 1

    run(go())
    assert w.alarms.names() == []


def test_a_finish_with_an_incident_alarms_and_a_plain_one_does_not() -> None:
    from sto.engine.commands import Finish

    w = World()

    async def go() -> None:
        await w.stop.execute("k", Finish(RID, RunStatus.CANCELLED, False))
        assert w.alarms.names() == []
        await w.stop.execute("k", Finish(RID, RunStatus.CANCELLED, True))

    run(go())
    assert w.alarms.names() == ["done_with_incident"]


def test_the_executor_refuses_a_command_it_does_not_own() -> None:
    w = World()
    with pytest.raises(TypeError):
        run(w.stop.execute("k", object()))
