"""G6 for the outbox relay (D3-11): a crash after each write recovers and applies once.

The gate service commits the decision and its outbox entry in one transaction; the relay delivers
the entry to the driver and then deletes it. ``CrashingStore`` lets a chosen commit land and then
raises, so every commit of the whole path is a crash point (the answer is lost, the write is not).
Recovery is a fresh service and relay over the same store. The sink models the driver: it applies
an event once per decision id, as the reducer does with a late duplicate.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from sto.domain import DecisionKind, GateType, RunId, Subject, Surface, TransientError, Ulid
from sto.effects.relay import (
    AlreadyClosedError,
    OutboxEntry,
    OutboxRelay,
    TokenNotStoredError,
)
from sto.engine.commands import OpenGate
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import Condition, Key, Op, Scope, TeamScope

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
OTHER = RunId.parse("01J00000000000000000000002")
SUBJECT = Subject(
    patch_id="p", ticket_revision="r", head_sha="s", evidence_digest="e", attention_digest="a"
)


class Crash(BaseException):
    """The process died after the write landed."""


class CrashingStore(MemoryStore):
    """Counts commits (transact, put, delete). Commit number ``crash_at`` lands, then raises."""

    def __init__(self, crash_at: int | None = None) -> None:
        super().__init__()
        self.commits = 0
        self.crash_at = crash_at

    def _tick(self) -> None:
        self.commits += 1
        if self.commits == self.crash_at:
            raise Crash

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        super().transact(scope, ops)
        self._tick()

    def put(
        self, scope: Scope, key: Key, data: Mapping[str, Any], *, when: Condition | None = None
    ) -> None:
        super().put(scope, key, data, when=when)
        self._tick()

    def delete(self, scope: Scope, key: Key, *, when: Condition | None = None) -> None:
        super().delete(scope, key, when=when)
        self._tick()


class Driver:
    """The run's side. ``applied`` holds each decision once however often it is delivered."""

    def __init__(self) -> None:
        self.applied: dict[str, dict[str, Any]] = {}
        self.deliveries: list[str] = []
        self.token_stored = True
        self.closed_runs: set[str] = set()
        self.down: Exception | None = None

    def deliver(self, entry: OutboxEntry) -> None:
        if self.down is not None:
            raise self.down
        if not self.token_stored:
            raise TokenNotStoredError("no task token yet")
        if entry.data["run_id"] in self.closed_runs:
            raise AlreadyClosedError("task timed out")
        self.deliveries.append(entry.data["decision_id"])
        self.applied.setdefault(entry.data["decision_id"], entry.data)

    def reconcile(self, entry: OutboxEntry) -> bool:
        return entry.data["decision_id"] in self.applied


class Metrics:
    def __init__(self) -> None:
        self.gauges: dict[str, float] = {}

    def gauge(self, name: str, value: float) -> None:
        self.gauges[name] = value


class Clock:
    def __init__(self) -> None:
        self.ms = 1_000_000_000_000

    def __call__(self) -> float:
        return self.ms / 1000


def open_gate(svc: GateService, run: RunId = RUN, name: str = "review", round: int = 1) -> Any:
    return svc.open_gate(TEAM, OpenGate(run, name, GateType.REVIEW, round, SUBJECT))


def approve(svc: GateService, run: RunId = RUN, name: str = "review", round: int = 1) -> Any:
    return svc.decide(
        TEAM,
        run_id=run,
        gate=name,
        round=round,
        kind=DecisionKind.APPROVE,
        actor="alice",
        surface=Surface.UI,
        subject_digest=SUBJECT.digest(),
        comment="",
    )


def entries(store: MemoryStore, run: RunId = RUN) -> list[Any]:
    return list(store.query(TEAM, f"RUN#{run}", sk_prefix="OUT#").items)


def relay_for(
    store: MemoryStore, driver: Driver, metrics: Metrics | None = None, clock: Clock | None = None
) -> OutboxRelay:
    return OutboxRelay(
        store, TEAM, driver, metrics=metrics or Metrics(), clock=clock or Clock(), stuck_after=60.0
    )


def decide_and_deliver(store: MemoryStore, driver: Driver) -> None:
    svc = GateService(store)
    open_gate(svc)
    approve(svc)
    relay_for(store, driver).drain(RUN)


def count_commits() -> int:
    store = CrashingStore()
    decide_and_deliver(store, Driver())
    return store.commits


def test_the_clean_path_has_the_commits_the_crash_sweep_covers() -> None:
    # open gate (2 commits), decide (one transaction), delete the delivered entry. If this number
    # changes, a write was added or removed and the sweep below must still reach it.
    assert count_commits() == 4


@pytest.mark.parametrize("crash_at", range(1, 5))
def test_a_crash_after_each_write_recovers_and_applies_once(crash_at: int) -> None:
    store = CrashingStore(crash_at)
    driver = Driver()
    with pytest.raises(Crash):
        decide_and_deliver(store, driver)
    store.crash_at = None
    # recovery: a fresh service, the same store. The caller retries the decision if it never
    # landed (crash 1 is the open itself), and a relay sweep finishes whatever was committed.
    svc = GateService(store)
    open_gate(svc)
    if not entries(store) and not driver.applied:
        approve(svc)
    relay_for(store, driver).drain(RUN)
    relay_for(store, driver).drain(RUN)
    assert len(driver.applied) == 1
    assert entries(store) == []


def test_a_crash_between_delivery_and_delete_redelivers_and_the_run_applies_it_once() -> None:
    store = CrashingStore()
    driver = Driver()
    svc = GateService(store)
    open_gate(svc)
    approve(svc)
    inner = driver.deliver

    def deliver_then_die(entry: OutboxEntry) -> None:
        inner(entry)
        raise Crash  # the signal went out; the process died before the delete

    driver.deliver = deliver_then_die  # type: ignore[method-assign]
    with pytest.raises(Crash):
        relay_for(store, driver).drain(RUN)
    driver.deliver = inner  # type: ignore[method-assign]
    assert len(entries(store)) == 1
    assert len(driver.applied) == 1
    relay_for(store, driver).drain(RUN)
    assert driver.deliveries
    assert len(driver.applied) == 1
    assert entries(store) == []


def test_a_decision_committing_before_the_task_token_is_stored_still_wakes_the_run() -> None:
    store = MemoryStore()
    driver = Driver()
    driver.token_stored = False
    svc = GateService(store)
    open_gate(svc)
    approve(svc)
    relay = relay_for(store, driver)
    report = relay.drain(RUN)
    assert report.delivered == 0
    assert report.waiting == 1
    assert len(entries(store)) == 1  # kept, not dropped
    driver.token_stored = True
    # the step that stores the token reads the gate and signals at once: that is a drain
    relay.drain(RUN)
    assert len(driver.applied) == 1
    assert entries(store) == []


def test_already_closed_is_success_only_after_a_reconcile_confirms_it() -> None:
    store = MemoryStore()
    driver = Driver()
    svc = GateService(store)
    open_gate(svc)
    decided = approve(svc)
    driver.closed_runs.add(str(RUN))
    # the run is closed and never heard the decision: not a success, the entry stays
    report = relay_for(store, driver).drain(RUN)
    assert report.delivered == 0
    assert report.failed == 1
    assert len(entries(store)) == 1
    # the run closed after hearing it: reconcile finds the decision applied
    driver.applied[str(decided.decision.id)] = {}
    report = relay_for(store, driver).drain(RUN)
    assert report.delivered == 1
    assert entries(store) == []


def test_delivery_is_in_order_per_run_and_a_failure_blocks_only_its_own_run() -> None:
    store = MemoryStore()
    driver = Driver()
    svc = GateService(store)
    for run in (RUN, OTHER):
        for round in (1, 2):
            open_gate(svc, run, "review", round)
            approve(svc, run, "review", round)
    order: list[tuple[str, int]] = []
    inner = driver.deliver

    def deliver(entry: OutboxEntry) -> None:
        if entry.data["run_id"] == str(RUN) and entry.data["round"] == 1:
            raise TransientError("down")
        order.append((entry.data["run_id"], entry.data["round"]))
        inner(entry)

    driver.deliver = deliver  # type: ignore[method-assign]
    report = relay_for(store, driver).sweep([RUN, OTHER])
    # RUN's round 1 failed, so its round 2 must not overtake it; OTHER is unaffected
    assert order == [(str(OTHER), 1), (str(OTHER), 2)]
    assert report.delivered == 2
    assert report.failed == 1
    assert len(entries(store, RUN)) == 2
    assert entries(store, OTHER) == []


def test_a_stuck_entry_raises_the_alarm_metric() -> None:
    store = MemoryStore()
    driver = Driver()
    driver.down = TransientError("down")
    svc = GateService(store)
    open_gate(svc)
    approve(svc)
    metrics, clock = Metrics(), Clock()
    clock.ms = Ulid.parse(entries(store)[0].key.sk[len("OUT#") :]).value >> 80
    relay = relay_for(store, driver, metrics, clock)
    relay.sweep([RUN])
    assert metrics.gauges["outbox_stuck"] == 0
    clock.ms += 61_000
    report = relay.sweep([RUN])
    assert metrics.gauges["outbox_stuck"] == 1
    assert metrics.gauges["outbox_oldest_age_seconds"] == pytest.approx(61.0)
    assert report.stuck == 1
    driver.down = None
    relay.sweep([RUN])
    assert metrics.gauges["outbox_stuck"] == 0
    assert metrics.gauges["outbox_oldest_age_seconds"] == 0
