"""Timers (D2-12): the timer port, a local implementation, and the handler that fires them.

A timer is a one-shot schedule that carries no authority. When it fires, the handler re-reads the
run and the gate and acts only on what it finds, so a late, early, repeated or reordered timer is
harmless (PLAN 4.4). The only change a timer can make to a gate is to close it ``EXPIRED``, and
this module has no way to write an approval (G12, ADR-0005): it never touches a decision.

* ``REMIND`` and ``ESCALATE`` write one notification each to the outbox. Their key is the timer's
  ID, so firing twice writes once. Escalation names a role; it grants that role nothing.
* ``EXPIRE`` closes one open gate ``EXPIRED``, by a conditional write on the version it read, in
  one transaction with the audit entry and the outbox entry.
* ``MAX_RUN_AGE`` is wall-clock time and always holds: it ignores a pause, and expires every
  open gate of the run, then asks the engine (through the outbox) to end the run.
* Gate timers do nothing while the run is paused (``BLOCKED``): they return ``PAUSED`` and stay
  scheduled. ``LocalTimers.resume`` gives back the business time that was left when the run
  paused, so the pause is not spent.

Not done here: nothing calls ``LocalTimers.pause`` and ``resume`` yet. The driver must wire them
to the run's pause and resume, or the paused time is spent and the timers come due early on
resume. The team and org pause switch (PLAN section 9) is not considered either: only a run in
``BLOCKED`` counts as paused. A run being ``CANCELLING`` makes gate timers do nothing.
"""

from __future__ import annotations

import datetime as dt
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from sto.config.schema import Timeouts, duration_seconds
from sto.domain import Gate, GateStatus, Run, RunId, RunStatus, from_wire, to_wire
from sto.domain.errors import PermanentError
from sto.gates.calendar import BusinessCalendar
from sto.gates.hooks import Reader, ReadOnly, run_pk
from sto.store.ports import (
    Absent,
    Check,
    ConditionFailedError,
    Key,
    Op,
    Put,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)

TIMER_ACTOR = "system:timer"
MAX_ATTEMPTS = 10
DEFAULT_REMIND_AFTER = "1d"  # PLAN 4.4: one business day, unless the gate says otherwise
DEFAULT_ESCALATE_AFTER = "2d"  # PLAN 4.4: two business days


class TimerConfigError(PermanentError):
    """A gate's timeouts cannot be scheduled as written."""


class TimerKind(StrEnum):
    REMIND = "remind"
    ESCALATE = "escalate"
    EXPIRE = "expire"
    MAX_RUN_AGE = "max_run_age"

    @property
    def wall_clock(self) -> bool:
        """Counted in wall-clock time, and never paused."""
        return self is TimerKind.MAX_RUN_AGE


class FireOutcome(StrEnum):
    DONE = "done"  # the timer acted
    NOOP = "noop"  # the run or gate it is about is gone, finished or no longer open
    DUPLICATE = "duplicate"  # it already acted
    EARLY = "early"  # not due yet
    PAUSED = "paused"  # the run is paused; the timer stays scheduled


@dataclass(frozen=True)
class Timer:
    team: str
    run_id: RunId
    kind: TimerKind
    due_at: dt.datetime
    gate: str | None = None
    round: int | None = None
    escalate_to: str | None = None
    # When the timer started counting. A pause that began earlier is not charged to it.
    scheduled_at: dt.datetime | None = None

    def __post_init__(self) -> None:
        _aware(self.due_at, "a timer's due time")
        if self.scheduled_at is not None:
            _aware(self.scheduled_at, "a timer's scheduled time")
        object.__setattr__(self, "kind", TimerKind(self.kind))
        if self.kind.wall_clock:
            if self.gate is not None or self.round is not None:
                raise ValueError("a run-age timer belongs to the run, not a gate")
        elif not self.gate or self.round is None:
            raise ValueError(f"a {self.kind.value} timer needs its gate and round")

    @property
    def id(self) -> str:
        """Stable identity: scheduling the same timer again, or firing it twice, is one timer."""
        return f"{self.run_id}:{self.kind.value}:{self.gate or '-'}:{self.round or 0}"


class TimerPort(Protocol):
    """Where timers wait. A hosted implementation fires them from a durable scheduler (D3)."""

    def schedule(self, timer: Timer) -> None: ...
    def due(self, now: dt.datetime) -> list[Timer]: ...
    def done(self, timer: Timer) -> None: ...
    def pause(self, run_id: RunId, now: dt.datetime) -> None: ...
    def resume(self, run_id: RunId, now: dt.datetime) -> None: ...


@dataclass
class LocalTimers:
    """In-process timers on a business calendar. Thread-safe."""

    calendar: BusinessCalendar
    _timers: dict[str, Timer] = field(default_factory=dict)
    _paused: dict[RunId, dt.datetime] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def schedule(self, timer: Timer) -> None:
        with self._lock:
            self._timers.setdefault(timer.id, timer)

    def done(self, timer: Timer) -> None:
        with self._lock:
            self._timers.pop(timer.id, None)

    def due(self, now: dt.datetime) -> list[Timer]:
        with self._lock:
            ready = [
                t
                for t in self._timers.values()
                if t.due_at <= now and (t.kind.wall_clock or t.run_id not in self._paused)
            ]
        return sorted(ready, key=lambda t: (t.due_at, t.id))

    def pause(self, run_id: RunId, now: dt.datetime) -> None:
        _aware(now, "the pause time")
        with self._lock:
            self._paused.setdefault(run_id, now)  # a second pause keeps the first

    def resume(self, run_id: RunId, now: dt.datetime) -> None:
        _aware(now, "the resume time")
        with self._lock:
            since = self._paused.pop(run_id, None)
            if since is None:
                return
            for tid, t in list(self._timers.items()):
                if t.run_id != run_id or t.kind.wall_clock:
                    continue
                # Only the pause that overlaps the timer's own life: one scheduled during the
                # pause was not running before it was scheduled.
                began = since if t.scheduled_at is None else max(since, t.scheduled_at)
                left = self.calendar.business_seconds_between(began, t.due_at)
                self._timers[tid] = replace(t, due_at=self.calendar.add(now, left))


def schedule_gate_timers(
    timers: TimerPort,
    team: str,
    run_id: RunId,
    gate: str,
    round: int,
    opened_at: dt.datetime,
    timeouts: Timeouts | None,
    calendar: BusinessCalendar | None = None,
) -> None:
    """Schedule a gate's reminder, escalation and expiry in business time.

    A gate with no ``remind_after`` is reminded after a business day, and one with an
    ``escalate_to`` role escalates after two unless ``escalate_after`` says otherwise (PLAN 4.4).
    ``escalate_after`` without ``escalate_to`` is a config error, never dropped silently. Expiry
    needs an ``expire_after``; without it the gate never expires."""
    cal = calendar if calendar is not None else _calendar_of(timers)
    t = timeouts if timeouts is not None else Timeouts()
    if t.escalate_after and not t.escalate_to:
        raise TimerConfigError(
            f"gate {gate!r} sets escalate_after but no escalate_to: there is nobody to tell"
        )
    escalate_after = t.escalate_after or (DEFAULT_ESCALATE_AFTER if t.escalate_to else None)

    def make(kind: TimerKind, duration: str, **more: str) -> Timer:
        return Timer(
            team,
            run_id,
            kind,
            cal.add_duration(opened_at, duration),
            gate=gate,
            round=round,
            scheduled_at=opened_at,
            **more,
        )

    timers.schedule(make(TimerKind.REMIND, t.remind_after or DEFAULT_REMIND_AFTER))
    if escalate_after and t.escalate_to:
        timers.schedule(make(TimerKind.ESCALATE, escalate_after, escalate_to=t.escalate_to))
    if t.expire_after:
        timers.schedule(make(TimerKind.EXPIRE, t.expire_after))


def schedule_run_age(
    timers: TimerPort, team: str, run_id: RunId, started_at: dt.datetime, max_run_age: str
) -> None:
    """``max_run_age`` is wall-clock: no calendar, no pause."""
    _aware(started_at, "the run's start time")
    # Add to the UTC instant: on a ZoneInfo value, timedelta adds local wall time, so across a
    # DST change "1d" would be 23 or 25 real hours.
    due = started_at.astimezone(dt.UTC) + dt.timedelta(seconds=duration_seconds(max_run_age))
    timers.schedule(Timer(team, run_id, TimerKind.MAX_RUN_AGE, due))


def _aware(value: dt.datetime, what: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{what} needs a timezone")


def _calendar_of(timers: TimerPort) -> BusinessCalendar:
    cal = getattr(timers, "calendar", None)
    if not isinstance(cal, BusinessCalendar):
        raise ValueError("pass a calendar: this timer port has none")
    return cal


class AuditOps(Protocol):
    """Builds the ops that record a timer's action in the run's audit chain.

    It is injected, not imported: only the gate service and the effect executor may use the audit
    seam (``tests/audit/test_writer_conformance.py``), so the driver passes in a function that
    wraps its ``AuditWriter``. The ops go into the same transaction as the change they record."""

    def __call__(
        self,
        reader: Reader,
        scope: TeamScope,
        run_id: RunId,
        action: str,
        actor: str,
        data: dict[str, Any],
        at_ms: int,
    ) -> Sequence[Op]: ...


class TimerHandler:
    """Fires one timer against the store. See the module doc for what each kind does."""

    def __init__(self, store: Store, *, audit_ops: AuditOps) -> None:
        self._store = store
        self._reader = ReadOnly(store)
        self._audit_ops_for = audit_ops

    def fire(self, scope: TeamScope, timer: Timer, now: dt.datetime) -> FireOutcome:
        if timer.team != scope.team:
            raise ValueError(f"timer is for team {timer.team}, not {scope.team}")
        _aware(now, "the time a timer fires at")
        if now < timer.due_at:
            return FireOutcome.EARLY
        run = self._run(scope, timer.run_id)
        if run is None or run.status.is_terminal:
            return FireOutcome.NOOP
        if timer.kind is TimerKind.MAX_RUN_AGE:
            return self._max_age(scope, timer, now)
        if run.status is RunStatus.CANCELLING:
            return FireOutcome.NOOP
        if run.status is RunStatus.BLOCKED:
            return FireOutcome.PAUSED
        assert timer.gate is not None
        assert timer.round is not None
        key = Key(run_pk(timer.run_id), f"GATE#{timer.gate}#{timer.round}")
        last: Exception | None = None
        for _ in range(MAX_ATTEMPTS):
            item = self._store.get(scope, key)
            if item is None:
                return FireOutcome.NOOP
            gate = from_wire(Gate, item.data)
            if not gate.is_open:
                return FireOutcome.NOOP
            if timer.kind is TimerKind.EXPIRE:
                ops = self._expire_ops(scope, timer, item.version, gate, now)
            else:
                ops = self._notify_ops(scope, timer, item.version, gate, now)
            try:
                self._store.transact(scope, ops)
            except ConditionFailedError as err:
                if self._store.get(scope, _outbox_key(timer)) is not None:
                    return FireOutcome.DUPLICATE
                last = err  # the gate moved under us: look again
            except TransactionConflictError as err:
                last = err
                time.sleep(0.001)
            else:
                return FireOutcome.DONE
        raise last if last is not None else RuntimeError("timer kept conflicting")

    # --- per kind ---------------------------------------------------------------------------

    def _notify_ops(
        self, scope: TeamScope, timer: Timer, version: int, gate: Gate, now: dt.datetime
    ) -> list[Op]:
        kind = "gate.reminder" if timer.kind is TimerKind.REMIND else "gate.escalation"
        body = {
            "kind": kind,
            "run_id": str(timer.run_id),
            "gate": gate.name,
            "round": gate.round,
            "timer": timer.id,
        }
        if timer.escalate_to:
            body["escalate_to"] = timer.escalate_to
        return [
            Check(Key(run_pk(timer.run_id), f"GATE#{gate.name}#{gate.round}"), VersionIs(version)),
            Put(_outbox_key(timer), body, Absent()),
            *self._audit_ops(scope, timer, kind, {"gate": gate.name, "round": gate.round}, now),
        ]

    def _expire_ops(
        self, scope: TeamScope, timer: Timer, version: int, gate: Gate, now: dt.datetime
    ) -> list[Op]:
        closed = gate.advance(GateStatus.EXPIRED, closed_by=TIMER_ACTOR)
        outbox = {
            "kind": "gate.closed",
            "run_id": str(timer.run_id),
            "gate": gate.name,
            "round": gate.round,
            "status": closed.status.value,
            "decision": None,
            "decision_id": None,
            "actor": TIMER_ACTOR,
            "subject": None,
            "timer": timer.id,
        }
        return [
            Put(
                Key(run_pk(timer.run_id), f"GATE#{gate.name}#{gate.round}"),
                to_wire(closed),
                VersionIs(version),
            ),
            Put(_outbox_key(timer), outbox, Absent()),
            *self._audit_ops(
                scope, timer, "gate.expired", {"gate": gate.name, "round": gate.round}, now
            ),
        ]

    def _max_age(self, scope: TeamScope, timer: Timer, now: dt.datetime) -> FireOutcome:
        """Expire every open gate, then record the run's age-out. Repeating it after a crash
        finishes whatever was left, and repeating it after success writes nothing."""
        pk = run_pk(timer.run_id)
        conflicts = 0
        while True:  # each pass closes one gate; only lost races count against the bound
            open_gates = [
                (i, g)
                for i, g in (
                    (i, from_wire(Gate, i.data))
                    for i in self._store.query(scope, pk, sk_prefix="GATE#").items
                )
                if g.is_open
            ]
            if not open_gates:
                break
            item, gate = open_gates[0]
            sub = replace(timer, kind=TimerKind.EXPIRE, gate=gate.name, round=gate.round)
            try:
                self._store.transact(scope, self._expire_ops(scope, sub, item.version, gate, now))
            except (ConditionFailedError, TransactionConflictError):
                conflicts += 1
                if conflicts >= MAX_ATTEMPTS:
                    raise RuntimeError("gates kept changing while the run aged out") from None
        for _ in range(MAX_ATTEMPTS):
            ops: list[Op] = [
                Put(
                    _outbox_key(timer),
                    {
                        "kind": "run.max_age_exceeded",
                        "run_id": str(timer.run_id),
                        "timer": timer.id,
                    },
                    Absent(),
                ),
                *self._audit_ops(scope, timer, "run.max_age_exceeded", {}, now),
            ]
            try:
                self._store.transact(scope, ops)
            except ConditionFailedError:
                # The outbox key says "already done"; a moved audit chain head says "try again".
                if self._store.get(scope, _outbox_key(timer)) is not None:
                    return FireOutcome.DUPLICATE
            except TransactionConflictError:
                pass
            else:
                return FireOutcome.DONE
        raise RuntimeError("the audit chain kept moving while the run aged out")

    # --- helpers ----------------------------------------------------------------------------

    def _audit_ops(
        self, scope: TeamScope, timer: Timer, action: str, data: dict[str, Any], now: dt.datetime
    ) -> list[Op]:
        return list(
            self._audit_ops_for(
                self._reader,
                scope,
                timer.run_id,
                action,
                TIMER_ACTOR,
                {**data, "timer": timer.id},
                int(now.timestamp() * 1000),
            )
        )

    def _run(self, scope: TeamScope, run_id: RunId) -> Run | None:
        item = self._store.get(scope, Key(run_pk(run_id), "META"))
        return None if item is None else from_wire(Run, item.data)


def _outbox_key(timer: Timer) -> Key:
    """One outbox entry per timer: its ID is the key, so a repeat finds it and writes nothing."""
    return Key(run_pk(timer.run_id), f"OUT#timer#{timer.id}")
