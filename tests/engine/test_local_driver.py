"""Local driver (D1-03): durable apply-and-feed-back loop, recovery from stored state only.

The kill tests run the driver in a child process on a real SQLite file and SIGKILL it at each
commit (just before it applies, and just after), then restart a fresh process that knows no run
ID and calls ``resume_all``. A ledger records every piece of *work* actually performed and a
separate call log records every ``execute`` call, so duplicated work and repeated calls both
show up. The finished state and timeline must equal an uninterrupted run's.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import itertools
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, MergeState, PrRef, PrSpec, RepoRef, UnknownRefError
from sto.domain import (
    DecisionId,
    DecisionKind,
    Effect,
    EffectStatus,
    FailureClass,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    Surface,
    from_wire,
)
from sto.domain.errors import TransientError
from sto.effects.core import EffectExecutor, set_switch
from sto.effects.ports import EffectHandler, Failed, MergeHandler, Pending
from sto.engine.commands import Finish, OpenGate, RunEffect, RunStep, StopRun
from sto.engine.drivers.local import (
    EffectsExecutor,
    LeaseHeldError,
    LeaseLostError,
    LocalDriver,
    RunWedgedError,
    decode,
    encode,
)
from sto.engine.drivers.ports import Done, Held, Outcome, StillRunning, command_key
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    EffectConfirmed,
    GateClosed,
    StepFailed,
    StepSucceeded,
)
from sto.engine.reducer import (
    LINEAR_V0,
    HandlerRegistry,
    NoHandlerError,
    OutOfOrderEventError,
    RunState,
)
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import (
    Key,
    Store,
    TeamScope,
    TransactionConflictError,
)
from sto.store.sqlite import SqliteStore

RID = RunId.from_parts(1, bytes(10))
RID2 = RunId.from_parts(2, bytes(10))
SCOPE = TeamScope("t1")
SUBJECT = Subject(
    patch_id="p1",
    ticket_revision="r1",
    head_sha="abc",
    evidence_digest="e1",
    attention_digest="a1",
)
THIS = Path(__file__).resolve()
Override = Callable[[str, object], Outcome | None]


def run[T](coro: Coroutine[Any, Any, T], timeout: float = 30) -> T:
    """``asyncio.run`` with a deadline: a driver that loops forever fails the test, not CI."""
    return asyncio.run(asyncio.wait_for(coro, timeout))


def new_run(rid: RunId = RID) -> Run:
    return Run(id=rid, team="t1")


def fixed_clock() -> float:
    return 1000.0


def approve(cmd: OpenGate, subject: Subject | None = None) -> GateClosed:
    return GateClosed(
        cmd.run_id,
        cmd.name,
        cmd.round,
        DecisionKind.APPROVE,
        "alice",
        DecisionId.from_parts(cmd.round, bytes(10)),
        subject if subject is not None else cmd.subject,
    )


class Worker:
    """Executor with a durable ledger (work performed, once per key, as the port requires) and a
    separate call log (every ``execute`` call), so a driver that calls twice is visible even
    though the worker deduplicates. ``override`` may answer a call instead."""

    def __init__(
        self, ledger: Path, *, auto_approve: bool = True, override: Override | None = None
    ) -> None:
        self.ledger = ledger
        self.calls_file = ledger.with_name(ledger.name + ".calls")
        self.auto_approve, self.override = auto_approve, override

    @staticmethod
    def _lines(path: Path) -> list[str]:
        return path.read_text().split() if path.exists() else []

    def done(self) -> list[str]:
        return self._lines(self.ledger)

    def calls(self) -> list[str]:
        return self._lines(self.calls_file)

    @staticmethod
    def _append(path: Path, key: str) -> None:
        with path.open("a") as f:
            f.write(key + "\n")
            f.flush()
            os.fsync(f.fileno())

    async def execute(self, key: str, command: object) -> Outcome:
        self._append(self.calls_file, key)
        if self.override is not None and (answer := self.override(key, command)) is not None:
            return answer
        if key not in self.done():
            self._append(self.ledger, key)
        if isinstance(command, RunStep):
            step = StepSucceeded(StepKey(command.run_id, command.stage, command.visit), SUBJECT)
            return Done([step])
        if isinstance(command, OpenGate):
            return Done([approve(command)] if self.auto_approve else [])
        if isinstance(command, RunEffect):
            return Done([EffectConfirmed(command.run_id, command.type, command.visit, "merge1")])
        if isinstance(command, StopRun):
            return Done([CancelCompleted(command.run_id)])
        return Done()


class CountingStore:
    """Delegates to a store; ``hook(n, phase)`` runs around the n-th transaction (0-based).
    Records the threads that touch the store."""

    def __init__(self, inner: Store, hook: Callable[[int, str], None] | None = None) -> None:
        self.inner, self.hook, self.commits = inner, hook, 0
        self.threads: set[int] = set()

    def get(self, scope: Any, key: Key) -> Any:
        self.threads.add(threading.get_ident())
        return self.inner.get(scope, key)

    def query(self, scope: Any, pk: str, **kw: Any) -> Any:
        self.threads.add(threading.get_ident())
        return self.inner.query(scope, pk, **kw)

    def transact(self, scope: Any, ops: Any) -> None:
        self.threads.add(threading.get_ident())
        n, self.commits = self.commits, self.commits + 1
        if self.hook:
            self.hook(n, "before")
        self.inner.transact(scope, ops)
        if self.hook:
            self.hook(n, "after")

    def put(self, scope: Any, key: Key, data: Any, *, when: Any = None) -> None:
        raise AssertionError("the driver must commit through transact")

    def delete(self, scope: Any, key: Key, *, when: Any = None) -> None:
        raise AssertionError("the driver must commit through transact")


_IDS = itertools.count()


def make(store: Store, worker: object, **kw: Any) -> LocalDriver:
    kw.setdefault("owner", "me")
    kw.setdefault("new_id", lambda: str(next(_IDS)))
    kw.setdefault("clock", fixed_clock)
    kw.setdefault("lease_seconds", 60.0)
    return LocalDriver(store, SCOPE, LINEAR_V0, worker, **kw)  # type: ignore[arg-type]


def drive(store: Store, worker: Worker, *, start: bool = True, **kw: Any) -> RunState:
    d = make(store, worker, **kw)

    async def go() -> RunState:
        if start:
            await d.start(new_run())
        return await d.run_until_idle(RID)

    return run(go())


# --- the happy path ---------------------------------------------------------------------------


def test_runs_linear_workflow_to_done(tmp_path: Path) -> None:
    w = Worker(tmp_path / "ledger")
    rs = drive(MemoryStore(), w)
    assert rs.run.status is RunStatus.DONE
    assert len(w.done()) == len(set(w.done())) == 6  # 2 steps, 2 gates, 1 effect, finish
    assert w.calls() == w.done()  # each command executed exactly once when nothing crashes


def test_state_is_persisted_in_the_store(tmp_path: Path) -> None:
    store = MemoryStore()
    rs = drive(store, Worker(tmp_path / "ledger"))
    item = store.get(SCOPE, Key(f"RUN#{RID}", "META"))
    assert item is not None
    assert from_wire(Run, item.data) == rs.run
    assert make(store, Worker(tmp_path / "ledger")).state(RID) == rs


def test_start_is_idempotent(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger")
    drive(store, w)
    before = w.done()
    assert drive(store, w, owner="other").run.status is RunStatus.DONE  # start again, then idle
    assert w.done() == before


def test_timeline_records_every_event_in_order(tmp_path: Path) -> None:
    store = MemoryStore()
    drive(store, Worker(tmp_path / "ledger"))
    tl = make(store, object()).timeline(RID)
    assert [e["seq"] for e in tl] == list(range(len(tl)))
    assert [e["type"] for e in tl] == [
        "run.started",
        "step.succeeded",
        "gate.closed",
        "step.succeeded",
        "gate.closed",
        "effect.confirmed",
    ]
    assert {e["outcome"] for e in tl} == {"applied"}
    assert tl[-1]["status"] == RunStatus.DONE.value
    assert decode({"type": tl[1]["type"], "data": tl[1]["data"]}, "event").key.stage == "implement"


# --- a waiting gate stays waiting -------------------------------------------------------------


def test_waiting_gate_stays_waiting_and_is_not_reopened(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    first = drive(store, w)
    assert first.run.status is RunStatus.WAITING_HUMAN
    assert first.run.stage == "review_gate"
    for i in range(3):  # restarts and idle polls change nothing
        assert drive(store, w, start=False, owner=f"p{i}") == first
    assert [k for k in w.done() if k.startswith("gate:")] == [f"gate:{RID}:review_gate:1"]
    assert w.calls() == w.done()


def _gate_cmd(name: str = "review_gate", rnd: int = 1) -> OpenGate:
    return OpenGate(RID, name, LINEAR_V0.node(name).gate_type, rnd, SUBJECT)  # type: ignore[arg-type]


def test_gate_decision_resumes_a_waiting_run(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    drive(store, w)
    d = make(store, w, owner="p2")

    async def go() -> RunState:
        await d.submit(RID, approve(_gate_cmd()))
        return await d.run_until_idle(RID)

    rs = run(go())
    assert rs.run.stage == "qa_gate"
    assert rs.run.status is RunStatus.WAITING_HUMAN


def test_open_gate_key_is_run_name_round() -> None:
    a = command_key(_gate_cmd(), 7)
    assert a == command_key(_gate_cmd(), 99)
    assert a != command_key(_gate_cmd(rnd=2), 7)


# --- refused, malformed and unknown events ----------------------------------------------------


def test_late_event_is_discarded_and_recorded(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    waiting = drive(store, w)
    d = make(store, w, owner="p2")
    late = StepSucceeded(StepKey(RID, "implement", 1, 1), SUBJECT)

    async def go() -> RunState:
        await d.submit(RID, late)
        return await d.run_until_idle(RID)

    assert run(go()) == waiting
    assert [r["reason"] for r in d.rejected(RID)] == ["out_of_order"]
    assert d.timeline(RID)[-1]["outcome"] == "out_of_order"


def test_malformed_event_is_quarantined_and_does_not_block_the_queue(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    drive(store, w)
    d = make(store, w, owner="p2")
    cmd = _gate_cmd()
    no_subject = dataclasses.replace(approve(cmd), subject=None)  # approve needs the subject

    async def go() -> RunState:
        await d.submit(RID, no_subject)
        await d.submit(RID, approve(cmd))
        return await d.run_until_idle(RID)

    try:
        rs = run(go())
    except Exception as e:  # a bad event must be quarantined, not stop the driver
        pytest.fail(f"a malformed event blocked the queue: {e!r}")
    assert rs.run.stage == "qa_gate"  # the good decision behind the bad one was applied
    assert [r["reason"] for r in d.rejected(RID)] == ["malformed"]
    outcomes = [e["outcome"] for e in d.timeline(RID)]
    assert outcomes.count("malformed") == 1
    assert outcomes[outcomes.index("malformed") + 1] == "applied"


def test_no_handler_is_not_discarded_as_late(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    drive(store, w)
    # an empty registry has no handler for anything: the event must stay queued, not vanish
    d = make(store, w, owner="p2", registry=HandlerRegistry())

    async def go() -> None:
        await d.submit(RID, StepFailed(StepKey(RID, "x", 1), FailureClass.PERMANENT))
        await d.run_until_idle(RID)

    with pytest.raises(NoHandlerError):
        run(go())
    assert d.rejected(RID) == []
    assert d.pending_events(RID) == 1


def test_out_of_order_is_not_a_no_handler() -> None:
    assert not issubclass(NoHandlerError, OutOfOrderEventError)


# --- a run that is idle but not waiting is stuck ----------------------------------------------


def _wrong_sha_on_qa(key: str, command: object) -> Outcome | None:
    if isinstance(command, RunStep) and command.stage == "qa":
        other = dataclasses.replace(SUBJECT, head_sha="different")
        return Done([StepSucceeded(StepKey(command.run_id, "qa", command.visit), other)])
    return None


def _no_subject(key: str, command: object) -> Outcome | None:
    if isinstance(command, RunStep) and command.stage == "implement":
        return Done([StepSucceeded(StepKey(command.run_id, "implement", command.visit), None)])
    return None


def _empty_replay(key: str, command: object) -> Outcome | None:
    return Done() if isinstance(command, RunStep) and command.stage == "implement" else None


@pytest.mark.parametrize(
    ("override", "why"),
    [(_wrong_sha_on_qa, "out_of_order"), (_no_subject, "malformed"), (_empty_replay, "")],
    ids=["qa-reports-different-sha", "implement-reports-no-subject", "empty-replay"],
)
def test_idle_run_that_still_needs_work_is_reported_not_returned(
    tmp_path: Path, override: Override, why: str
) -> None:
    w = Worker(tmp_path / "ledger", override=override)
    with pytest.raises(RunWedgedError) as e:
        drive(MemoryStore(), w)
    assert "RUNNING" in str(e.value)
    assert why in str(e.value)


# --- a command that is not finished -----------------------------------------------------------


def test_still_running_keeps_the_head_and_is_called_again_with_the_same_key(
    tmp_path: Path,
) -> None:
    seen = {"n": 0}

    def twice_busy(key: str, command: object) -> Outcome | None:
        if isinstance(command, RunStep) and command.stage == "implement" and seen["n"] < 2:
            seen["n"] += 1
            return StillRunning(2.5, "in_flight")
        return None

    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    w = Worker(tmp_path / "ledger", override=twice_busy)
    rs = drive(MemoryStore(), w, sleep=fake_sleep)
    assert rs.run.status is RunStatus.DONE
    assert sleeps == [2.5, 2.5]
    first = w.calls()[0]
    assert w.calls().count(first) == 3
    assert w.done().count(first) == 1


def test_stop_runs_ahead_of_a_command_that_is_not_finished(tmp_path: Path) -> None:
    """A queued Stop is applied between polls, and its command runs before the stuck head."""
    store = MemoryStore()
    box: dict[str, Any] = {"order": []}

    def busy_until_stopped(key: str, command: object) -> Outcome | None:
        box["order"].append(type(command).__name__)
        # Cap the polls: a driver that never gets to the Stop fails here, on an assertion that
        # shows the order, not only on the deadline.
        assert len(box["order"]) < 8, f"the Stop was not seen after {box['order']}"
        if isinstance(command, RunStep):
            return Done() if "StopRun" in box["order"] else StillRunning(1.0)
        return None

    async def stop_during_first_wait(_: float) -> None:
        if not box.get("sent"):
            box["sent"] = True
            await box["driver"].submit(RID, CancelRequested(RID))

    w = Worker(tmp_path / "ledger", override=busy_until_stopped)
    d = box["driver"] = make(store, w, sleep=stop_during_first_wait)

    async def go() -> RunState:
        await d.start(new_run())
        return await d.run_until_idle(RID)

    rs = run(go())
    # The Stop jumped the stuck head. The head RunStep is then called again after the StopRun
    # (the run is CANCELLED by then): that is D2-11's to stop (it owns what a Stop does to an
    # unfinished command), so it changes this line knowingly.
    assert box["order"][:3] == ["RunStep", "StopRun", "RunStep"]
    assert rs.run.status is RunStatus.CANCELLED


def test_held_command_returns_instead_of_spinning_and_retries_when_released(
    tmp_path: Path,
) -> None:
    store = MemoryStore()
    released = {"on": False}

    def held_until_released(key: str, command: object) -> Outcome | None:
        if isinstance(command, RunStep) and command.stage == "implement" and not released["on"]:
            return Held("held")
        return None

    w = Worker(tmp_path / "ledger", override=held_until_released)
    d = make(store, w)

    async def first() -> RunState:
        await d.start(new_run())
        return await d.run_until_idle(RID)

    rs = run(first(), timeout=5)
    assert rs.run.status is RunStatus.RUNNING  # not wedged, not done: held
    assert d.held(RID) == "held"
    assert len(w.calls()) == 1  # asked once, not polled
    released["on"] = True
    assert run(d.run_until_idle(RID)).run.status is RunStatus.DONE
    assert d.held(RID) is None


def test_still_running_rejects_bad_delays() -> None:
    for bad in (-1.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="retry_after"):
            StillRunning(bad)


# --- store conflicts and lost races -----------------------------------------------------------


def test_transaction_conflicts_are_retried_with_backoff(tmp_path: Path) -> None:
    sleeps: list[float] = []
    failures = {"left": 3}

    def flaky(n: int, phase: str) -> None:
        if phase == "before" and failures["left"] > 0 and n >= 2:
            failures["left"] -= 1
            raise TransactionConflictError("busy")

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    w = Worker(tmp_path / "ledger")
    rs = drive(CountingStore(MemoryStore(), flaky), w, sleep=fake_sleep)
    assert rs.run.status is RunStatus.DONE
    assert len(sleeps) == 3
    assert sleeps == sorted(sleeps)
    assert sleeps[0] < sleeps[-1]
    assert w.calls() == w.done()


def test_persistent_conflict_gives_up(tmp_path: Path) -> None:
    def always(n: int, phase: str) -> None:
        if phase == "before" and n >= 1:
            raise TransactionConflictError("busy")

    async def no_sleep(_: float) -> None:
        return None

    with pytest.raises(TransactionConflictError):
        drive(CountingStore(MemoryStore(), always), Worker(tmp_path / "l"), sleep=no_sleep)


def test_lost_version_race_reloads_retries_and_backs_off(tmp_path: Path) -> None:
    """Another writer queues a Stop between our read and our write. We must not overwrite it,
    must reload and retry, and must back off before retrying."""
    inner = MemoryStore()
    other = make(inner, object(), owner="api")
    sleeps: list[float] = []

    def api_writes_first(n: int, phase: str) -> None:
        if n == 2 and phase == "before":  # our first event commit
            run(other.submit(RID, CancelRequested(RID)))

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    w = Worker(tmp_path / "ledger")
    try:
        rs = drive(CountingStore(inner, api_writes_first), w, sleep=fake_sleep)
    except Exception as e:  # a lost race must be retried, not surfaced
        pytest.fail(f"lost race was not retried: {e!r}")
    assert rs.run.status is RunStatus.CANCELLED  # the Stop was not lost
    assert len(sleeps) == 1


def test_done_is_recorded_once_even_if_someone_else_recorded_it(tmp_path: Path) -> None:
    """A former owner popped the head and queued its events before our commit: we must not
    append them again."""
    inner = MemoryStore()
    helper = make(inner, object(), owner="ghost")
    w = Worker(tmp_path / "ledger")

    def ghost_records_the_command(n: int, phase: str) -> None:
        if n == 3 and phase == "before":  # our commit of the first command
            rec = helper._load(RID)
            step = StepSucceeded(StepKey(RID, "implement", 1), SUBJECT)
            theirs = dataclasses.replace(rec, pending=(), inbox=(encode(step, "event"),))
            run(helper._write(theirs))

    store = CountingStore(inner, ghost_records_the_command)
    rs = drive(store, w)
    assert rs.run.status is RunStatus.DONE
    assert make(inner, w).rejected(RID) == []  # no duplicate StepSucceeded was refused later


def test_apply_with_an_empty_inbox_is_a_no_op() -> None:
    d = make(MemoryStore(), object())
    run(d.start(new_run()))
    rec = d._load(RID)
    emptied = dataclasses.replace(rec, inbox=())
    assert d._apply(emptied) == (emptied, ())


def test_store_calls_do_not_run_on_the_event_loop_thread(tmp_path: Path) -> None:
    store = CountingStore(MemoryStore())
    loop_thread: list[int] = []

    async def go() -> None:
        loop_thread.append(threading.get_ident())
        d = make(store, Worker(tmp_path / "ledger"))
        await d.start(new_run())
        await d.run_until_idle(RID)

    run(go())
    assert store.threads
    assert loop_thread[0] not in store.threads


def test_a_non_suspending_executor_does_not_starve_other_tasks(tmp_path: Path) -> None:
    ticks: list[int] = []

    async def ticker(stop: asyncio.Event) -> None:
        while not stop.is_set():
            ticks.append(1)
            await asyncio.sleep(0)

    async def go() -> None:
        stop = asyncio.Event()
        t = asyncio.create_task(ticker(stop))
        d = make(MemoryStore(), Worker(tmp_path / "ledger"))
        await d.start(new_run())
        await d.run_until_idle(RID)
        stop.set()
        await t

    run(go())
    assert len(ticks) > 12  # at least one tick per durable step


# --- one driver per run -----------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_second_driver_cannot_run_a_leased_run_and_never_calls_execute(tmp_path: Path) -> None:
    store, clock = MemoryStore(), Clock()
    wa, wb = Worker(tmp_path / "a"), Worker(tmp_path / "b")
    a = make(store, wa, owner="a", clock=clock, lease_seconds=10)
    b = make(store, wb, owner="b", clock=clock, lease_seconds=10)

    async def go() -> None:
        await a.start(new_run())
        assert await a.step(RID) == "worked"  # a now holds the lease
        with pytest.raises(LeaseHeldError):
            await b.run_until_idle(RID)

    run(go())
    assert wb.calls() == []


def test_resume_all_reports_a_leased_run_without_stopping(tmp_path: Path) -> None:
    store, clock = MemoryStore(), Clock()
    a = make(store, Worker(tmp_path / "a"), owner="a", clock=clock, lease_seconds=10)
    b = make(store, Worker(tmp_path / "b"), owner="b", clock=clock, lease_seconds=10, resume_wait=0)

    async def go() -> dict[RunId, Any]:
        await a.start(new_run())
        await a.start(new_run(RID2))
        await a.step(RID)  # a holds only the first run
        return await b.resume_all()

    out = run(go())
    assert isinstance(out[RID], LeaseHeldError)
    assert isinstance(out[RID2], RunState)
    assert out[RID2].run.status is RunStatus.DONE


def test_expired_lease_is_taken_over_and_the_old_owner_stops_writing(tmp_path: Path) -> None:
    store, clock = MemoryStore(), Clock()
    wb = Worker(tmp_path / "b")
    b = make(store, wb, owner="b", clock=clock, lease_seconds=10)

    class SlowWorker(Worker):
        """Its lease runs out while it works, and b takes the run over before it commits."""

        async def execute(self, key: str, command: object) -> Outcome:
            outcome = await super().execute(key, command)
            clock.now += 11
            await b._claim(RID)
            return outcome

    wa = SlowWorker(tmp_path / "a")
    a = make(store, wa, owner="a", clock=clock, lease_seconds=10)

    async def go() -> RunState:
        await a.start(new_run())
        await a.step(RID)  # applies RunStarted
        with pytest.raises(LeaseLostError):
            await a.step(RID)  # executes RunStep; the lease is b's when it tries to commit
        return await b.run_until_idle(RID)

    assert run(go()).run.status is RunStatus.DONE
    assert len(wa.calls()) == 1
    assert wb.calls()[0] == wa.calls()[0]  # the new owner replays a's unfinished command


def test_lease_wait_sleeps_until_expiry_then_takes_over(tmp_path: Path) -> None:
    store, clock = MemoryStore(), Clock()
    naps: list[float] = []

    async def advancing_sleep(s: float) -> None:
        naps.append(s)
        clock.now += s

    a = make(store, Worker(tmp_path / "a"), owner="a", clock=clock, lease_seconds=10)
    b = make(
        store,
        Worker(tmp_path / "b"),
        owner="b",
        clock=clock,
        lease_seconds=10,
        lease_wait=20,
        sleep=advancing_sleep,
    )

    async def go() -> RunState:
        await a.start(new_run())
        await a.step(RID)
        return await b.run_until_idle(RID)

    assert run(go()).run.status is RunStatus.DONE
    assert naps
    assert sum(naps) == pytest.approx(10)


# --- finding unfinished runs without knowing their IDs ----------------------------------------


def test_active_runs_lists_unfinished_runs_and_resume_all_drives_them(tmp_path: Path) -> None:
    store = MemoryStore()
    w = Worker(tmp_path / "ledger", auto_approve=False)
    d = make(store, w)

    async def go() -> tuple[list[RunId], dict[RunId, Any]]:
        await d.start(new_run())
        await d.start(new_run(RID2))
        before = await d.active_runs()
        await d.run_until_idle(RID)
        await d.run_until_idle(RID2)
        return before, await make(store, w, owner="p2").resume_all()

    before, resumed = run(go())
    assert before == [RID, RID2]
    assert set(resumed) == {RID, RID2}
    assert all(s.run.status is RunStatus.WAITING_HUMAN for s in resumed.values())


def test_finished_run_leaves_the_index(tmp_path: Path) -> None:
    store = MemoryStore()
    d = make(store, Worker(tmp_path / "ledger"))

    async def go() -> list[RunId]:
        await d.start(new_run())
        assert await d.active_runs() == [RID]
        await d.run_until_idle(RID)
        return await d.active_runs()

    assert run(go()) == []


# --- owners, heartbeat, concurrent resume -----------------------------------------------------


def test_a_reused_owner_label_does_not_share_a_lease(tmp_path: Path) -> None:
    store = MemoryStore()
    a = make(store, Worker(tmp_path / "a"), owner="same")
    b = make(store, Worker(tmp_path / "b"), owner="same")

    async def go() -> None:
        await a.start(new_run())
        await a.step(RID)
        with pytest.raises(LeaseHeldError):
            await b.run_until_idle(RID)

    run(go())


def test_the_lease_is_renewed_while_a_long_command_executes(tmp_path: Path) -> None:
    """A 1 s command under a 0.3 s lease: a second driver must still be turned away."""
    store = MemoryStore()

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                await asyncio.sleep(1.0)
            return await super().execute(key, command)

    wa, wb = Slow(tmp_path / "a"), Worker(tmp_path / "b")
    a = make(store, wa, owner="a", clock=time.time, lease_seconds=0.3)
    b = make(store, wb, owner="b", clock=time.time, lease_seconds=0.3)

    async def go() -> RunState:
        await a.start(new_run())
        first = asyncio.ensure_future(a.run_until_idle(RID))
        await asyncio.sleep(0.6)  # twice the lease into the command
        with pytest.raises(LeaseHeldError):
            await b.run_until_idle(RID)
        return await first

    assert run(go(), timeout=20).run.status is RunStatus.DONE
    assert wb.calls() == []
    assert len(wa.calls()) == len(set(wa.calls()))


def _rid(n: int) -> RunId:
    return RunId.from_parts(n, bytes(10))


def test_resume_all_runs_runs_concurrently_and_isolates_faults(tmp_path: Path) -> None:
    store = MemoryStore()
    r1, r2, r3 = _rid(11), _rid(12), _rid(13)
    box = {"polls": 0, "r2_finished": False}

    def override(key: str, command: object) -> Outcome | None:
        if isinstance(command, Finish) and command.run_id == r2:
            box["r2_finished"] = True
        if isinstance(command, RunStep) and command.run_id == r1 and not box["r2_finished"]:
            box["polls"] += 1
            assert box["polls"] < 30, "run 1 starved run 2: it polled 30 times first"
            return StillRunning(0.0)
        if isinstance(command, RunStep) and command.run_id == r3:
            raise RuntimeError("executor fault")
        return None

    w = Worker(tmp_path / "ledger", override=override)
    d = make(store, w)

    async def go() -> dict[RunId, Any]:
        for r in (r1, r2, r3):
            await d.start(new_run(r))
        return await make(store, w, owner="restart").resume_all()

    out = run(go())
    assert not isinstance(out[r1], Exception), out[r1]
    assert not isinstance(out[r2], Exception), out[r2]
    assert out[r1].run.status is RunStatus.DONE
    assert out[r2].run.status is RunStatus.DONE
    assert isinstance(out[r3], RuntimeError)  # reported, and the others still finished


def test_resume_waits_for_a_dead_drivers_lease_to_expire(tmp_path: Path) -> None:
    store, clock = MemoryStore(), Clock()
    naps: list[float] = []

    async def advancing_sleep(s: float) -> None:
        naps.append(s)
        clock.now += s

    dead = make(store, Worker(tmp_path / "a"), owner="a", clock=clock, lease_seconds=10)
    b = make(
        store,
        Worker(tmp_path / "b"),
        owner="b",
        clock=clock,
        lease_seconds=10,
        sleep=advancing_sleep,
    )

    async def go() -> dict[RunId, Any]:
        await dead.start(new_run())
        await dead.step(RID)  # holds the lease, then "dies"
        return await b.resume_all()

    out = run(go())
    assert out[RID].run.status is RunStatus.DONE
    assert sum(naps) == pytest.approx(10)


def test_wedge_check_does_not_misfire_on_a_queue_filled_just_now(tmp_path: Path) -> None:
    store = MemoryStore()
    api = make(store, object(), owner="api")

    class Racy(LocalDriver):
        sent = False

        async def step(self, run_id: RunId) -> Any:
            result = await super().step(run_id)
            if result == "idle" and not self.sent:
                self.sent = True  # another writer queues the missing event right after "idle"
                await api.submit(RID, StepSucceeded(StepKey(RID, "implement", 1), SUBJECT))
            return result

    w = Worker(tmp_path / "ledger", override=_empty_replay)
    d = Racy(
        store,
        SCOPE,
        LINEAR_V0,
        w,
        owner="me",
        clock=fixed_clock,
        new_id=lambda: "r",
    )

    async def go() -> RunState:
        await d.start(new_run())
        return await d.run_until_idle(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.DONE


class PagedStore(CountingStore):
    """Returns at most two items per query, so a caller that ignores the cursor sees too few."""

    def query(self, scope: Any, pk: str, **kw: Any) -> Any:
        kw["limit"] = 2
        return super().query(scope, pk, **kw)


def test_timeline_and_active_runs_follow_the_cursor(tmp_path: Path) -> None:
    store = PagedStore(MemoryStore())
    d = make(store, Worker(tmp_path / "ledger"))

    async def go() -> list[RunId]:
        for n in (21, 22, 23, 24, 25):
            await d.start(new_run(_rid(n)))
        await d.run_until_idle(_rid(21))  # finishes: six events, three pages of two
        return await d.active_runs()

    # the finished run left the index; four runs span two pages of two
    assert run(go()) == [_rid(22), _rid(23), _rid(24), _rid(25)]
    assert len(d.timeline(_rid(21))) == 6


# --- the effects adapter against the real effects service and the fakes -----------------------


class Delegate:
    """An ``EffectHandler`` that forwards to whatever handler the test has put on the world."""

    def __init__(self, world: RealWorld) -> None:
        self.world = world

    def execute(self, effect: Effect) -> Any:
        return self.world.handler.execute(effect)

    def poll(self, effect: Effect) -> Any:
        return self.world.handler.poll(effect)

    def stop(self, effect: Effect) -> Any:
        return self.world.handler.stop(effect)

    def reconcile(self, effect: Effect) -> Any:
        return self.world.handler.reconcile(effect)


class RealWorld:
    """Real ``GateService`` and ``EffectExecutor`` over one store, with the fake SCM: the driver
    runs the real reducer's merge from the review gate to the end."""

    def __init__(self, tmp_path: Path, **fx_args: Any) -> None:
        self.store = MemoryStore()
        self.svc = GateService(self.store)
        self.fx = EffectExecutor(self.store, SCOPE, **fx_args)
        self.scm = FakeScm()
        repo = RepoRef("acme", "app")
        self.scm.seed_branch(repo, "main", "b0")
        self.scm.seed_branch(repo, "sto/x", "abc", parent="b0")
        self.pr = PrRef.of(
            repo, self.scm.ensure_draft_pr(PrSpec(repo, "sto/x", "main", "t", "b"), "k")
        )
        self.scm.mark_ready(self.pr, "k2")
        self.handler: EffectHandler = MergeHandler(
            self.scm, self.pr, "abc", MergeMethod.SQUASH, SUBJECT
        )
        self.live_subject = SUBJECT
        self.sleeps: list[float] = []
        self.on_sleep: Callable[[], Any] | None = None
        self.driver: LocalDriver

        steps = self

        class Others:
            async def execute(self, key: str, command: object) -> Outcome:
                if isinstance(command, RunStep):
                    ev = StepSucceeded(
                        StepKey(command.run_id, command.stage, command.visit), SUBJECT
                    )
                    return Done([ev])
                if isinstance(command, OpenGate):
                    steps.svc.open_gate(SCOPE, command)
                    d = steps.svc.decide(
                        SCOPE,
                        run_id=command.run_id,
                        gate=command.name,
                        round=command.round,
                        kind=DecisionKind.APPROVE,
                        actor="alice",
                        surface=Surface.UI,
                        subject_digest=command.subject.digest(),
                    )
                    return Done([approve_with(command, d.decision.id)])
                if isinstance(command, StopRun):
                    return Done([CancelCompleted(command.run_id)])
                return Done()

        async def sleep(s: float) -> None:
            self.sleeps.append(s)
            assert len(self.sleeps) < 8, "the driver is spinning on a command that cannot finish"
            if self.on_sleep is not None:
                await self.on_sleep()

        adapter = EffectsExecutor(
            self.fx,
            {"pr.merge": Delegate(self)},
            lambda cmd: self.live_subject,
            lambda rid: self.driver.state(rid).run.status,
            others=Others(),
            poll_interval=0.5,
        )
        self.driver = make(self.store, adapter, sleep=sleep)

    async def start(self) -> RunState:
        await self.driver.start(new_run())
        return await self.driver.run_until_idle(RID)

    def effect(self) -> Any:
        (item,) = [i for i in self.store.query(SCOPE, f"RUN#{RID}", sk_prefix="FX#").items]
        return from_wire(Effect, item.data["effect"])


def approve_with(cmd: OpenGate, decision_id: DecisionId) -> GateClosed:
    return GateClosed(
        cmd.run_id, cmd.name, cmd.round, DecisionKind.APPROVE, "alice", decision_id, cmd.subject
    )


def test_adapter_polls_an_accepted_merge_until_it_lands(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)

    async def land() -> None:
        w.on_sleep = None
        w.scm.complete_merge(w.scm.merges()[-1], "m1")

    w.on_sleep = land
    rs = run(w.start())
    assert rs.run.status is RunStatus.DONE
    assert w.effect().status is EffectStatus.CONFIRMED
    assert w.sleeps == [0.5]
    assert [e["type"] for e in w.driver.timeline(RID)][-1] == "effect.confirmed"


def test_a_stop_between_polls_reaches_the_handler_and_dequeues_the_merge(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)

    async def stop() -> None:
        w.on_sleep = None
        await w.driver.submit(RID, CancelRequested(RID))

    w.on_sleep = stop
    rs = run(w.start())
    assert rs.run.status is RunStatus.CANCELLED
    assert w.effect().status is EffectStatus.VOIDED  # handler.stop dequeued it before the Stop ran
    assert "effect.confirmed" not in [e["type"] for e in w.driver.timeline(RID)]
    assert w.driver.rejected(RID) == []  # a voided effect on a dead run reports nothing
    assert w.scm.merges()  # a merge was requested, and then dequeued by the handler's stop


def test_a_blocked_effect_ends_the_run_blocked_not_spinning(tmp_path: Path) -> None:
    w = RealWorld(tmp_path, max_attempts=2)

    class Flaky:
        def execute(self, effect: Effect) -> Any:
            raise TransientError("scm is down")

        poll = stop = reconcile = execute

    w.handler = Flaky()
    rs = run(w.start())
    assert rs.run.status is RunStatus.BLOCKED
    assert w.sleeps == [0.5]  # one retry, then blocked: EffectFailed, not another poll
    assert w.effect().status is EffectStatus.RETRYING


def test_a_failed_effect_without_an_edge_blocks_the_run(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)

    class Refuses:
        def execute(self, effect: Effect) -> Any:
            return Failed(None, "boom")

    w.handler = Refuses()  # type: ignore[assignment]
    rs = run(w.start())
    assert rs.run.status is RunStatus.BLOCKED
    assert w.effect().status is EffectStatus.FAILED


def test_a_voided_effect_on_an_active_run_blocks_it(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    w.live_subject = dataclasses.replace(SUBJECT, ticket_revision="edited")  # gate_invalid
    rs = run(w.start())
    assert rs.run.status is RunStatus.BLOCKED
    assert w.effect().status is EffectStatus.VOIDED


def test_a_held_merge_returns_held_and_resumes_when_released(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    set_switch(w.store, SCOPE, "effects", True)
    set_switch(w.store, SCOPE, "merge", False)
    rs = run(w.start())
    assert rs.run.status is RunStatus.RUNNING
    assert w.driver.held(RID) == "held"
    assert w.sleeps == []  # not polled
    set_switch(w.store, SCOPE, "merge", True)

    async def land() -> None:
        w.on_sleep = None
        w.scm.complete_merge(w.scm.merges()[-1], "m1")

    w.on_sleep = land
    assert run(w.driver.run_until_idle(RID)).run.status is RunStatus.DONE
    assert w.driver.held(RID) is None


# --- Stop and the merge queue, transient errors, one drive per run ----------------------------


class Crash(BaseException):
    """A process death in the middle of a handler call."""


class Flaky:
    """Forwards to a real handler; the named method raises ``TransientError`` the first time."""

    def __init__(self, inner: Any, method: str) -> None:
        self.inner, self.method, self.left = inner, method, 1

    def __getattr__(self, name: str) -> Any:
        fn = getattr(self.inner, name)
        if name != self.method:
            return fn

        def wrapped(effect: Effect) -> Any:
            if self.left:
                self.left -= 1
                raise TransientError(f"scm blip in {name}")
            return fn(effect)

        return wrapped


class Spy:
    """Forwards to a real handler and records which methods were called."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        fn = getattr(self.inner, name)

        def call(effect: Effect) -> Any:
            self.calls.append(name)
            return fn(effect)

        return call


def _stop_on_first_sleep(w: RealWorld) -> None:
    async def stop() -> None:
        w.on_sleep = None
        await w.driver.submit(RID, CancelRequested(RID))

    w.on_sleep = stop


def test_a_transient_poll_is_retried_not_a_fault(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    w.handler = Flaky(w.handler, "poll")

    async def land() -> None:
        w.on_sleep = None
        w.scm.complete_merge(w.scm.merges()[-1], "m1")

    w.on_sleep = land
    try:
        rs = run(w.start())
    except TransientError as e:
        pytest.fail(f"a transient error ended the drive: {e!r}")
    assert rs.run.status is RunStatus.DONE


def test_a_transient_stop_still_dequeues_the_merge(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    w.handler = Flaky(w.handler, "stop")
    _stop_on_first_sleep(w)
    try:
        rs = run(w.start())
    except TransientError as e:
        pytest.fail(f"a transient error ended the drive: {e!r}")
    assert rs.run.status is RunStatus.CANCELLED
    assert w.scm.poll_merge(w.scm.merges()[-1]).state is MergeState.DEQUEUED
    assert w.driver._probed == set()  # nothing is remembered once the drive ends


def test_a_stop_after_a_crash_in_flight_reconciles_the_queued_merge(tmp_path: Path) -> None:
    """Crash after request_merge, before settling; restart; Stop. The effect is still ATTEMPTING
    inside its lease, then the lease lapses: the handler must be asked to reconcile (dequeue)."""
    clock = Clock()
    w = RealWorld(tmp_path, clock=clock, lease_seconds=60.0)
    real = w.handler

    class CrashAfterRequest:
        def execute(self, effect: Effect) -> Any:
            real.execute(effect)
            raise Crash()

    w.handler = CrashAfterRequest()  # type: ignore[assignment]
    with pytest.raises(Crash):
        run(w.start())
    assert w.effect().status is EffectStatus.ATTEMPTING
    spy = w.handler = Spy(real)

    async def lease_lapses() -> None:
        clock.now += 30

    w.on_sleep = lease_lapses

    async def go() -> RunState:
        await w.driver.submit(RID, CancelRequested(RID))
        return await w.driver.run_until_idle(RID)

    rs = run(go())
    assert rs.run.status is RunStatus.CANCELLED
    assert "reconcile" in spy.calls
    assert w.scm.poll_merge(w.scm.merges()[-1]).state is MergeState.DEQUEUED


def test_the_stop_probe_is_made_once_and_does_not_starve_the_stop(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)

    class SlowToStop:
        calls = 0

        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def execute(self, effect: Effect) -> Any:
            return self.inner.execute(effect)

        def poll(self, effect: Effect) -> Any:
            return self.inner.poll(effect)

        def reconcile(self, effect: Effect) -> Any:
            return self.inner.reconcile(effect)

        def stop(self, effect: Effect) -> Any:
            SlowToStop.calls += 1
            assert SlowToStop.calls < 8, "the probe is repeated, so the StopRun never runs"
            # The merge only gives way once the run has actually been stopped.
            if w.driver.state(RID).run.status is not RunStatus.CANCELLED:
                return Pending(effect.intent or "h")
            return self.inner.stop(effect)

    w.handler = SlowToStop(w.handler)
    _stop_on_first_sleep(w)
    rs = run(w.start())
    assert rs.run.status is RunStatus.CANCELLED
    assert SlowToStop.calls == 2  # the probe while CANCELLING, then one once CANCELLED
    assert w.scm.poll_merge(w.scm.merges()[-1]).state is MergeState.DEQUEUED


def test_a_replay_of_a_finished_effect_does_not_need_the_live_subject(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    adapter = w.driver._executor
    seen: dict[str, Any] = {}

    class Record:
        async def execute(self, key: str, cmd: object) -> Outcome:
            out = await adapter.execute(key, cmd)
            if isinstance(cmd, RunEffect):
                seen.update(key=key, cmd=cmd, out=out)
            return out

    w.driver._executor = Record()

    async def land() -> None:
        w.on_sleep = None
        w.scm.complete_merge(w.scm.merges()[-1], "m1")

    w.on_sleep = land
    assert run(w.start()).run.status is RunStatus.DONE

    def gone(cmd: RunEffect) -> Subject:
        raise TransientError("the SCM is down")

    adapter._live = gone  # type: ignore[attr-defined]
    assert run(adapter.execute(seen["key"], seen["cmd"])) == seen["out"]


def test_a_stop_against_a_held_effect_does_not_need_the_live_subject(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    set_switch(w.store, SCOPE, "effects", True)
    set_switch(w.store, SCOPE, "merge", False)
    run(w.start())
    assert w.driver.held(RID) == "held"

    def gone(cmd: RunEffect) -> Subject:
        raise TransientError("the SCM is down")

    w.driver._executor._live = gone  # type: ignore[attr-defined]

    async def go() -> RunState:
        await w.driver.submit(RID, CancelRequested(RID))
        return await w.driver.run_until_idle(RID)

    assert run(go()).run.status is RunStatus.CANCELLED


@pytest.mark.parametrize("error", ["plan_conflict", "moved"])
def test_other_adapter_hiccups_are_retried_not_faults(tmp_path: Path, error: str) -> None:
    w = RealWorld(tmp_path)
    raised = {"n": 0}
    if error == "plan_conflict":
        real_plan = w.fx.plan

        def plan(*a: Any, **kw: Any) -> Effect:
            if raised["n"] == 0:
                raised["n"] += 1
                raise TransactionConflictError("busy")
            return real_plan(*a, **kw)

        w.fx.plan = plan  # type: ignore[method-assign]
    else:
        real_poll = w.fx.poll

        def poll(*a: Any, **kw: Any) -> Any:
            if raised["n"] == 0:
                raised["n"] += 1
                # Another driver's poll wins: the record really moves to CONFIRMED, then ours
                # finds it is no longer ACCEPTED.
                if w.scm.poll_merge(w.scm.merges()[-1]).state is MergeState.PENDING:
                    w.scm.complete_merge(w.scm.merges()[-1], "m1")
                real_poll(*a, **kw)
                raise ValueError("only an ACCEPTED effect can be polled")
            return real_poll(*a, **kw)

        w.fx.poll = poll  # type: ignore[method-assign]

    async def land() -> None:
        merges = w.scm.merges()
        if merges and w.scm.poll_merge(merges[-1]).state is MergeState.PENDING:
            w.on_sleep = None
            w.scm.complete_merge(merges[-1], "m1")

    w.on_sleep = land
    assert run(w.start()).run.status is RunStatus.DONE
    assert raised["n"] == 1


def test_retries_back_off(tmp_path: Path) -> None:
    w = RealWorld(tmp_path, max_attempts=3)

    class Down:
        def execute(self, effect: Effect) -> Any:
            raise TransientError("scm is down")

    w.handler = Down()  # type: ignore[assignment]
    assert run(w.start()).run.status is RunStatus.BLOCKED
    assert w.sleeps == [0.5, 1.0]  # doubling, not a fixed interval


def test_two_drives_of_one_run_on_one_driver_execute_once(tmp_path: Path) -> None:
    store = MemoryStore()

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                await asyncio.sleep(0.2)
            return await super().execute(key, command)

    w = Slow(tmp_path / "l")
    d = make(store, w)

    async def go() -> tuple[Any, Any]:
        await d.start(new_run())
        a, b = await asyncio.gather(
            d.run_until_idle(RID), d.run_until_idle(RID), return_exceptions=True
        )
        return a, b

    first, second = run(go())
    assert not isinstance(first, Exception), first
    assert not isinstance(second, Exception), second
    assert first == second  # the second joined the first
    assert w.calls() == w.done()
    assert len(w.calls()) == len(set(w.calls()))


def test_resume_all_joins_a_drive_already_running_on_this_driver(tmp_path: Path) -> None:
    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                await asyncio.sleep(0.2)
            return await super().execute(key, command)

    w = Slow(tmp_path / "l")
    d = make(MemoryStore(), w)

    async def go() -> tuple[dict[RunId, Any], Any]:
        await d.start(new_run())
        live = asyncio.ensure_future(d.run_until_idle(RID))
        await asyncio.sleep(0.05)
        resumed = await d.resume_all()
        return resumed, await live

    resumed, rs = run(go())
    assert resumed[RID] == rs
    assert w.calls() == w.done()


def test_wedge_check_decides_from_a_read_after_the_release(tmp_path: Path) -> None:
    """A submit that lands just ahead of the release commit must not be reported as a wedge."""
    inner = MemoryStore()
    api = make(inner, object(), owner="api")
    box = {"fired": False, "ready": False}

    def hook(n: int, phase: str) -> None:
        if phase != "before" or box["fired"] or not box["ready"]:
            return
        rec = api._load(RID)
        if not rec.inbox and not rec.pending and rec.state.run.status is RunStatus.RUNNING:
            box["fired"] = True  # this is the release commit: a submit gets in just ahead of it
            run(api.submit(RID, StepSucceeded(StepKey(RID, "implement", 1), SUBJECT)))

    d = make(CountingStore(inner, hook), Worker(tmp_path / "l", override=_empty_replay))

    async def go() -> RunState:
        await d.start(new_run())
        box["ready"] = True
        return await d.run_until_idle(RID)

    try:
        rs = run(go())
    except RunWedgedError as e:
        pytest.fail(f"a false wedge with an event queued: {e}")
    assert box["fired"]
    assert rs.run.status is RunStatus.DONE


def test_the_wedge_report_reads_the_store_off_the_loop(tmp_path: Path) -> None:
    store = CountingStore(MemoryStore())
    loop_thread: list[int] = []

    async def go() -> None:
        loop_thread.append(threading.get_ident())
        d = make(store, Worker(tmp_path / "l", override=_empty_replay))
        await d.start(new_run())
        with pytest.raises(RunWedgedError):
            await d.run_until_idle(RID)

    run(go())
    assert loop_thread[0] not in store.threads


def test_lease_lost_during_a_command_cancels_the_work_and_surfaces(tmp_path: Path) -> None:
    store = MemoryStore()
    box: dict[str, Any] = {}

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                box["started"] = True
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    box["cancelled"] = True
                    raise
            return await super().execute(key, command)

    a = make(store, Slow(tmp_path / "a"), owner="a", clock=time.time, lease_seconds=0.3)
    thief = make(store, Worker(tmp_path / "b"), owner="b", clock=time.time, lease_seconds=0.3)

    def steal(rec: Any) -> Any:
        return dataclasses.replace(rec, lease={"owner": "thief", "expires": time.time() + 5}), ()

    async def go() -> None:
        await a.start(new_run())
        drive_task = asyncio.ensure_future(a.run_until_idle(RID))
        while "started" not in box:
            await asyncio.sleep(0.01)
        await thief._commit(RID, steal, owner=False)
        with pytest.raises(LeaseLostError):
            await drive_task

    run(go())
    assert box.get("cancelled")  # the work stopped; it did not run on without the lease


def test_a_store_hiccup_during_a_heartbeat_does_not_abort_the_command(tmp_path: Path) -> None:
    inner = MemoryStore()
    box = {"arm": False}

    class Hiccup(CountingStore):
        def transact(self, scope: Any, ops: Any) -> None:
            if box["arm"]:
                box["arm"] = False
                raise TransientError("store hiccup")
            super().transact(scope, ops)

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                box["arm"] = True
                await asyncio.sleep(1.0)
            return await super().execute(key, command)

    d = make(Hiccup(inner), Slow(tmp_path / "a"), clock=time.time, lease_seconds=0.6)

    async def go() -> RunState:
        await d.start(new_run())
        return await d.run_until_idle(RID)

    try:
        rs = run(go())
    except TransientError as e:
        pytest.fail(f"one store hiccup aborted a live command: {e!r}")
    assert rs.run.status is RunStatus.DONE


def test_lease_seconds_must_be_positive() -> None:
    for bad in (0, -1):
        with pytest.raises(ValueError, match="lease_seconds"):
            make(MemoryStore(), object(), lease_seconds=bad)


def test_held_is_forgotten_once_the_run_is_finished(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    set_switch(w.store, SCOPE, "effects", True)
    set_switch(w.store, SCOPE, "merge", False)
    run(w.start())
    assert w.driver.held(RID) == "held"
    _stop_on_first_sleep(w)

    async def go() -> RunState:
        await w.driver.submit(RID, CancelRequested(RID))
        return await w.driver.run_until_idle(RID)

    assert run(go()).run.status is RunStatus.CANCELLED
    assert w.driver.held(RID) is None


def _crashing_adapter(w: RealWorld, store: Store, clock: Clock, holder: dict[str, Any]) -> Any:
    fx = EffectExecutor(store, SCOPE, clock=clock)
    return EffectsExecutor(
        fx,
        {"pr.merge": Delegate(w)},
        lambda c: w.live_subject,
        lambda rid: holder["d"].state(rid).run.status,
        others=w.driver._executor._others,  # type: ignore[attr-defined]
        poll_interval=0.5,
    )


@pytest.mark.parametrize("variant", ["finish", "stop"])
@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("kill", range(14))
def test_crash_at_every_commit_around_the_merge(
    tmp_path: Path, kill: int, phase: str, variant: str
) -> None:
    """The merge is requested, the process dies at each commit, a fresh driver and adapter resume
    (and, for ``stop``, a Stop arrives): the run ends DONE with one landed merge, or CANCELLED
    with no merge left queued, and no second merge request is ever made."""
    clock = Clock()
    w = RealWorld(tmp_path, clock=clock)
    first = make(w.store, w.driver._executor, clock=clock, lease_seconds=10, owner="p1")
    w.driver = first
    set_switch(w.store, SCOPE, "effects", True)
    set_switch(w.store, SCOPE, "merge", False)

    async def stand_at_the_merge() -> RunState:
        await first.start(new_run())
        return await first.run_until_idle(RID)

    assert run(stand_at_the_merge()).run.stage == "merge"
    set_switch(w.store, SCOPE, "merge", True)

    def hook(n: int, ph: str) -> None:
        if n == kill and ph == phase:
            raise Crash()

    crashing = CountingStore(w.store, hook)
    holder: dict[str, Any] = {}
    polls = {"n": 0}

    def land_if_pending() -> None:
        merges = w.scm.merges()
        if (
            merges
            and variant == "finish"
            and w.scm.poll_merge(merges[-1]).state is MergeState.PENDING
        ):
            w.scm.complete_merge(merges[-1], "m1")

    async def die_after_a_while(_: float) -> None:
        polls["n"] += 1
        if polls["n"] > 20:
            raise Crash()  # the first process must not poll forever
        land_if_pending()

    holder["d"] = make(
        crashing,
        _crashing_adapter(w, crashing, clock, holder),
        clock=clock,
        lease_seconds=10,
        owner="p1",
        sleep=die_after_a_while,
    )
    with contextlib.suppress(Crash):
        run(holder["d"].run_until_idle(RID))

    resumed: dict[str, Any] = {}
    sleeps = {"n": 0}

    async def advance(seconds: float) -> None:
        sleeps["n"] += 1
        assert sleeps["n"] < 2000, "the resumed driver is spinning"
        clock.now += max(seconds, 0.5)
        land_if_pending()

    second = resumed["d"] = make(
        w.store,
        _crashing_adapter(w, w.store, clock, resumed),
        clock=clock,
        lease_seconds=10,
        owner="p2",
        sleep=advance,
    )

    async def restart() -> dict[RunId, Any]:
        if variant == "stop":
            await second.submit(RID, CancelRequested(RID))
        return await second.resume_all()

    out = run(restart(), timeout=25)
    rs = out[RID] if out else second.state(RID)
    assert not isinstance(rs, Exception), repr(rs)
    states = [w.scm.poll_merge(m).state for m in w.scm.merges()]
    assert len(states) <= 1, "a second merge was requested"
    if variant == "finish":
        assert rs.run.status is RunStatus.DONE
        assert w.effect().status is EffectStatus.CONFIRMED
        assert states == [MergeState.MERGED]
    else:
        assert rs.run.status in (RunStatus.CANCELLED, RunStatus.DONE)
        assert MergeState.PENDING not in states, "the merge is still queued after the run ended"
    assert second.pending_events(RID) == 0
    assert run(second.active_runs()) == []


# --- pass 4 -----------------------------------------------------------------------------------


def test_a_joiner_does_not_trust_a_drive_that_had_already_read(tmp_path: Path) -> None:
    """A decision is submitted after the first drive's final (empty) read; a second call joins it.
    Nobody must be left holding the queued decision."""
    inner = MemoryStore()
    read, go_on = threading.Event(), threading.Event()
    box = {"armed": False}

    class Late(CountingStore):
        def transact(self, scope: Any, ops: Any) -> None:
            super().transact(scope, ops)
            item = inner.get(SCOPE, Key(f"RUN#{RID}", "DRIVER"))
            if (
                item
                and item.data["lease"] is None
                and item.data["state"]["run"]["status"] == ("WAITING_HUMAN")
            ):
                box["armed"] = True  # the release just committed

        def get(self, scope: Any, key: Key) -> Any:
            out = super().get(scope, key)
            if box["armed"] and key.sk == "DRIVER":
                box["armed"] = False
                read.set()  # the first drive has its final (empty) read in hand...
                go_on.wait(10)  # ...and is scheduled late
            return out

    d = make(Late(inner), Worker(tmp_path / "l", auto_approve=False))

    async def go() -> None:
        await d.start(new_run())
        first = asyncio.ensure_future(d.run_until_idle(RID))
        await asyncio.to_thread(read.wait, 10)
        await d.submit(RID, approve(_gate_cmd()))
        second = asyncio.ensure_future(d.run_until_idle(RID))  # joins the first
        await asyncio.sleep(0.01)
        go_on.set()
        await asyncio.gather(first, second)

    run(go())
    assert d.pending_events(RID) == 0, "the decision is queued and nobody is driving"
    assert d.state(RID).run.stage == "qa_gate"


def test_a_stop_submitted_while_a_held_call_returns_is_not_stranded(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    set_switch(w.store, SCOPE, "effects", True)
    set_switch(w.store, SCOPE, "merge", False)
    inner = w.driver._executor
    box: dict[str, Any] = {}

    class Wrap:
        async def execute(self, key: str, cmd: object) -> Outcome:
            out = await inner.execute(key, cmd)
            if isinstance(cmd, RunEffect) and isinstance(out, Held) and "joined" not in box:
                await w.driver.submit(RID, CancelRequested(RID))
                box["joined"] = asyncio.ensure_future(w.driver.run_until_idle(RID))
                await asyncio.sleep(0)
            return out

    w.driver._executor = Wrap()

    async def go() -> RunState:
        await w.start()
        rs: RunState = await box["joined"]
        return rs

    assert run(go()).run.status is RunStatus.CANCELLED
    assert w.driver.pending_events(RID) == 0


def test_a_joiner_receives_the_first_drives_exception(tmp_path: Path) -> None:
    class Faulty(Worker):
        failed = False

        async def execute(self, key: str, command: object) -> Outcome:
            await asyncio.sleep(0.05)
            if not Faulty.failed:  # only the first call fails: a joiner that ran its own
                Faulty.failed = True  # drive would succeed, so it must have been handed this
                raise RuntimeError("fault")
            return await super().execute(key, command)

    d = make(MemoryStore(), Faulty(tmp_path / "l"))

    async def go() -> list[Any]:
        await d.start(new_run())
        return list(
            await asyncio.gather(
                d.run_until_idle(RID), d.run_until_idle(RID), return_exceptions=True
            )
        )

    out = run(go())
    assert all(isinstance(o, RuntimeError) for o in out), out
    assert not d._driving


def test_cancelling_a_joiner_leaves_the_drive_running(tmp_path: Path) -> None:
    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            await asyncio.sleep(0.02)
            return await super().execute(key, command)

    d = make(MemoryStore(), Slow(tmp_path / "l"))

    async def go() -> RunState:
        await d.start(new_run())
        first = asyncio.ensure_future(d.run_until_idle(RID))
        await asyncio.sleep(0.01)
        joiner = asyncio.ensure_future(d.run_until_idle(RID))
        await asyncio.sleep(0.01)
        joiner.cancel()
        return await first

    assert run(go()).run.status is RunStatus.DONE


def test_cancelling_the_first_caller_does_not_cancel_resume_all(tmp_path: Path) -> None:
    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.run_id == RID:
                await asyncio.sleep(0.05)
            return await super().execute(key, command)

    d = make(MemoryStore(), Slow(tmp_path / "l"))

    async def go() -> Any:
        await d.start(new_run())
        await d.start(new_run(RID2))
        first = asyncio.ensure_future(d.run_until_idle(RID))
        await asyncio.sleep(0.01)
        resumed = asyncio.ensure_future(d.resume_all())
        await asyncio.sleep(0.01)
        first.cancel()  # e.g. a request timeout around the first caller
        return (await asyncio.gather(resumed, return_exceptions=True))[0]

    out = run(go())
    assert isinstance(out, dict), f"resume_all lost every result: {out!r}"
    assert out[RID2].run.status is RunStatus.DONE


@pytest.mark.parametrize("what", ["raises", "returns_garbage"])
def test_a_permanent_value_error_is_not_polled_forever(tmp_path: Path, what: str) -> None:
    w = RealWorld(tmp_path)
    real = w.handler

    class Buggy:
        def execute(self, e: Effect) -> Any:
            return real.execute(e)

        def poll(self, e: Effect) -> Any:
            if what == "raises":
                raise ValueError("a bug: bad JSON from the SCM")
            return "not an outcome"

        stop = reconcile = poll

    w.handler = Buggy()
    with pytest.raises(ValueError, match=".+"):  # not "spinning": the fault surfaces
        run(w.start())


class _StopFails:
    """A handler that can no longer stop or reconcile its effect (the PR is gone)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def execute(self, e: Effect) -> Any:
        return self.inner.execute(e)

    def poll(self, e: Effect) -> Any:
        return self.inner.poll(e)

    def stop(self, e: Effect) -> Any:
        raise UnknownRefError("PR is gone")

    reconcile = stop


def _count_stop_runs(w: RealWorld) -> dict[str, int]:
    seen = {"n": 0}
    others = w.driver._executor._others  # type: ignore[attr-defined]

    class Count:
        async def execute(self, k: str, c: object) -> Outcome:
            if isinstance(c, StopRun):
                seen["n"] += 1
            out: Outcome = await others.execute(k, c)
            return out

    w.driver._executor._others = Count()  # type: ignore[attr-defined]
    return seen


def test_a_permanent_stop_error_does_not_hold_the_stoprun_back(tmp_path: Path) -> None:
    w = RealWorld(tmp_path)
    w.handler = _StopFails(w.handler)
    stops = _count_stop_runs(w)
    _stop_on_first_sleep(w)
    with pytest.raises(UnknownRefError):  # the fault still surfaces, from the effect itself
        run(w.start())
    assert stops["n"] == 1
    assert w.driver.state(RID).run.status is RunStatus.CANCELLED
    with pytest.raises(UnknownRefError):  # and on every later call, not hidden
        run(w.driver.run_until_idle(RID))
    assert stops["n"] == 1


def test_a_permanent_reconcile_error_does_not_hold_the_stoprun_back(tmp_path: Path) -> None:
    clock = Clock()
    w = RealWorld(tmp_path, clock=clock, lease_seconds=60.0)
    real = w.handler

    class CrashAfterRequest:
        def execute(self, effect: Effect) -> Any:
            real.execute(effect)
            raise Crash()

    w.handler = CrashAfterRequest()  # type: ignore[assignment]
    with pytest.raises(Crash):
        run(w.start())
    w.handler = _StopFails(real)
    stops = _count_stop_runs(w)

    async def lease_lapses() -> None:
        clock.now += 30

    w.on_sleep = lease_lapses

    async def go() -> None:
        await w.driver.submit(RID, CancelRequested(RID))
        await w.driver.run_until_idle(RID)

    with pytest.raises(UnknownRefError):
        run(go())
    assert stops["n"] == 1
    assert w.driver.state(RID).run.status is RunStatus.CANCELLED


def test_a_persistent_transient_stop_error_cannot_hold_the_stoprun_back(tmp_path: Path) -> None:
    """Known limit: the retries themselves are unbounded (D2-10). The Stop still runs."""
    w = RealWorld(tmp_path)
    real = w.handler

    class Down:
        def execute(self, e: Effect) -> Any:
            return real.execute(e)

        def poll(self, e: Effect) -> Any:
            return real.poll(e)

        def stop(self, e: Effect) -> Any:
            raise TransientError("scm down")

        reconcile = stop

    w.handler = Down()
    _stop_on_first_sleep(w)
    with pytest.raises(AssertionError, match="spinning"):
        run(w.start())
    assert w.driver.state(RID).run.status is RunStatus.CANCELLED


def test_the_heartbeat_gives_up_when_the_lease_has_run_out(tmp_path: Path) -> None:
    """Retries are bounded by the lease's own expiry, not by a clock that starts at the first
    failure: with a 2 s lease the command is aborted about when the lease runs out."""
    inner = MemoryStore()
    box: dict[str, Any] = {"fail": False}

    class Busy(CountingStore):
        def transact(self, scope: Any, ops: Any) -> None:
            if box["fail"]:
                raise TransactionConflictError("busy")
            super().transact(scope, ops)

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                box["t_exec"] = time.time()
                box["fail"] = True
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    box["t_abort"] = time.time()
                    raise
            return await super().execute(key, command)

    a = make(Busy(inner), Slow(tmp_path / "a"), owner="a", clock=time.time, lease_seconds=2.0)

    async def go() -> float:
        await a.start(new_run())
        await a.step(RID)  # claim and apply: the lease is stamped now
        await asyncio.sleep(0.9)  # older than nothing, younger than ttl/2: no renewal yet
        expires = float(a._load(RID).lease["expires"])  # type: ignore[index]
        with pytest.raises(TransactionConflictError):
            await a.step(RID)
        return expires

    expires = run(go(), timeout=30)
    assert box["t_abort"] <= expires + 0.5, f"aborted {box['t_abort'] - expires:.2f}s late"


def test_the_heartbeat_gives_up_after_its_attempts_even_if_the_lease_has_time(
    tmp_path: Path,
) -> None:
    box: dict[str, Any] = {"fail": False, "n": 0}

    class Down(CountingStore):
        def transact(self, scope: Any, ops: Any) -> None:
            if box["fail"]:
                box["n"] += 1
                assert box["n"] < 20, "the heartbeat keeps retrying past its attempt limit"
                raise TransientError("store down")
            super().transact(scope, ops)

    class Slow(Worker):
        async def execute(self, key: str, command: object) -> Outcome:
            if isinstance(command, RunStep) and command.stage == "implement":
                box["fail"] = True
                await asyncio.sleep(10)
            return await super().execute(key, command)

    # a frozen clock: the lease never runs out, so only the attempt limit can end the retries
    d = make(Down(MemoryStore()), Slow(tmp_path / "a"), lease_seconds=0.3)

    async def go() -> None:
        await d.start(new_run())
        with pytest.raises(TransientError):
            await d.run_until_idle(RID)

    run(go())
    assert box["n"] == 8


def test_dead_statuses_match_the_effects_core() -> None:
    from sto.effects.core import _DEAD as CORE_DEAD
    from sto.engine.drivers.local import _DEAD

    assert _DEAD == CORE_DEAD


# --- real process kill on SQLite --------------------------------------------------------------


def _child_driver(db: str, ledger: str, auto: bool, hook: Any = None) -> LocalDriver:
    return LocalDriver(
        CountingStore(SqliteStore(db), hook),
        SCOPE,
        LINEAR_V0,
        Worker(Path(ledger), auto_approve=auto),
        owner="child",
        clock=time.time,
        new_id=lambda: f"{os.getpid()}-{time.time_ns()}",
        lease_seconds=0.4,
        lease_wait=10,
    )


def _child_run(db: str, ledger: str, kill_at: int, phase: str, auto: bool) -> None:
    """A fresh process: register the run and drive it, killing itself at the given commit."""

    def hook(n: int, ph: str) -> None:
        if n == kill_at and ph == phase:
            os.kill(os.getpid(), signal.SIGKILL)

    d = _child_driver(db, ledger, auto, hook)

    async def go() -> RunState:
        await d.start(new_run())
        return await d.run_until_idle(RID)

    rs = run(go())
    print(json.dumps({"status": rs.run.status.value, "stage": rs.run.stage}), flush=True)
    if not auto:
        os.kill(os.getpid(), signal.SIGKILL)  # die while the gate waits


def _child_resume(db: str, ledger: str, auto: bool) -> None:
    """A fresh process that knows no run ID: it finds unfinished runs in the store."""
    out = run(_child_driver(db, ledger, auto).resume_all())
    print(json.dumps({str(k): [v.run.status.value, v.run.stage] for k, v in out.items()}))  # type: ignore[union-attr]


def _spawn(*args: object) -> Any:
    return subprocess.run(
        [sys.executable, str(THIS), "child", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )


# start, claim of the lease, 6 events applied, 6 commands done, release of the lease.
# test_reference_run pins the count.
COMMITS = 15
Reference = tuple[int, list[str], RunState, list[dict[str, Any]]]


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> Reference:
    store = CountingStore(MemoryStore())
    w = Worker(tmp_path_factory.mktemp("ref") / "ledger")
    rs = drive(store, w)
    return store.commits, w.done(), rs, make(store.inner, w).timeline(RID)


def test_reference_run(reference: Reference) -> None:
    commits, work, rs, timeline = reference
    assert rs.run.status is RunStatus.DONE
    assert commits == COMMITS  # a new commit must be added to the kill sweep, not slip past it
    assert len(work) == 6
    assert len(timeline) == 6


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("kill_at", range(COMMITS))
def test_kill_at_every_commit_finishes_with_no_duplicated_work(
    tmp_path: Path, kill_at: int, phase: str, reference: Reference
) -> None:
    _, work, final, timeline = reference
    db, ledger = tmp_path / "s.db", tmp_path / "ledger"
    killed = _spawn("run", db, ledger, kill_at, phase, True)
    assert killed.returncode == -signal.SIGKILL, killed.stderr  # the kill really happened
    resumed = _spawn("resume", db, ledger, True)  # knows no run ID
    assert resumed.returncode == 0, resumed.stderr
    if json.loads(resumed.stdout) == {}:  # nothing unfinished in the store
        if (kill_at, phase) == (0, "before"):  # the run was never stored: start it again
            again = _spawn("run", db, ledger, -1, phase, True)
            assert again.returncode == 0, again.stderr
        else:  # the run had finished (Finish done); at most the lease release was lost
            assert (kill_at, phase) in {
                (COMMITS - 2, "after"),
                (COMMITS - 1, "before"),
                (COMMITS - 1, "after"),
            }
    else:
        assert json.loads(resumed.stdout) == {str(RID): [RunStatus.DONE.value, final.run.stage]}
    done = ledger.read_text().split()
    assert sorted(done) == sorted(set(done)), "a piece of work ran twice"
    assert sorted(done) == sorted(work)
    calls = Worker(ledger).calls()
    assert len(calls) - len(set(calls)) <= 1, "more than the one replay a kill can cause"
    d = make(SqliteStore(db), Worker(ledger))
    assert d.state(RID) == final
    assert d.timeline(RID) == timeline  # every event once, in order, none lost
    assert run(d.active_runs()) == []


def test_restart_with_no_run_id_known_finishes_the_run(tmp_path: Path) -> None:
    db, ledger = tmp_path / "s.db", tmp_path / "ledger"
    assert _spawn("run", db, ledger, 7, "after", True).returncode == -signal.SIGKILL
    resumed = _spawn("resume", db, ledger, True)  # no RID, no start: stored state only
    assert resumed.returncode == 0, resumed.stderr
    assert list(json.loads(resumed.stdout).values()) == [[RunStatus.DONE.value, "merge"]]


def test_kill_while_gate_waits_then_restart_still_waits(tmp_path: Path) -> None:
    db, ledger = tmp_path / "s.db", tmp_path / "ledger"
    died = _spawn("run", db, ledger, -1, "before", False)
    assert died.returncode == -signal.SIGKILL
    assert json.loads(died.stdout)["stage"] == "review_gate"
    again = _spawn("resume", db, ledger, False)  # fresh process, stored state only
    assert again.returncode == 0, again.stderr
    waiting = [RunStatus.WAITING_HUMAN.value, "review_gate"]
    assert json.loads(again.stdout) == {str(RID): waiting}
    opened = [k for k in ledger.read_text().split() if k.startswith("gate:")]
    assert opened == [f"gate:{RID}:review_gate:1"]


def test_driver_loads_handlers_itself() -> None:
    """In a fresh interpreter nothing has called ``load_handlers``: building the driver must,
    or ``next`` refuses with ``HandlersNotLoadedError`` on the first event."""
    code = textwrap.dedent(
        """
        import asyncio
        from sto.domain import Run, RunId
        from sto.engine.drivers.local import LocalDriver
        from sto.engine.reducer import LINEAR_V0
        from sto.store.memory import MemoryStore
        from sto.store.ports import TeamScope

        class Idle:
            async def execute(self, key, command):
                from sto.engine.drivers.ports import Done
                return Done()

        rid = RunId.from_parts(1, bytes(10))
        d = LocalDriver(MemoryStore(), TeamScope("t"), LINEAR_V0, Idle(), owner="x",
                        clock=lambda: 1.0, new_id=lambda: "1")

        async def go():
            await d.start(Run(id=rid, team="t"))
            await d.step(rid)  # claims the lease
            await d.step(rid)  # applies RunStarted: next() needs the handlers loaded
            return d.state(rid)

        print(asyncio.run(go()).run.stage)
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "implement"


def test_wire_roundtrip_of_commands() -> None:
    cmds = [RunStep(RID, "implement", 1, 1), _gate_cmd(), Finish(RID, RunStatus.DONE)]
    for c in cmds:
        assert decode(json.loads(json.dumps(encode(c, "command"))), "command") == c


if __name__ == "__main__" and sys.argv[1:2] == ["child"]:
    if sys.argv[2] == "run":
        db_, ledger_, kill_, phase_, auto_ = sys.argv[3:8]
        _child_run(db_, ledger_, int(kill_), phase_, auto_ == "True")
    else:
        db_, ledger_, auto_ = sys.argv[3:6]
        _child_resume(db_, ledger_, auto_ == "True")
