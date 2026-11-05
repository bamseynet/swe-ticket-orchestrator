"""Timers and the business calendar (D2-12).

G12 here is exercised by firing every timer of a run in every order, early, late and repeated,
against a store that holds an OPEN gate, and asserting nothing ever approves.
"""

from __future__ import annotations

import datetime as dt
import itertools
from pathlib import Path
from typing import Any

import pytest

from sto.config.schema import Calendar, Timeouts, Weekday
from sto.domain import (
    DecisionKind,
    Gate,
    GateStatus,
    GateType,
    Run,
    RunId,
    RunStatus,
    Subject,
    Surface,
    from_wire,
    to_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.calendar import BusinessCalendar
from sto.gates.service import GateClosedError, GateService, verify_audit_chain
from sto.gates.timers import (
    FireOutcome,
    LocalTimers,
    Timer,
    TimerHandler,
    TimerKind,
    schedule_gate_timers,
    schedule_run_age,
)
from sto.store.memory import MemoryStore
from sto.store.ports import Key, TeamScope

pytestmark = pytest.mark.unit

UTC = dt.UTC
TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
WEEKDAYS: tuple[Weekday, ...] = ("mon", "tue", "wed", "thu", "fri")


def cal(
    tz: str = "Europe/London",
    days: tuple[Weekday, ...] = WEEKDAYS,
    hours: str = "09:00-17:30",
    holidays: tuple[dt.date, ...] = (),
) -> BusinessCalendar:
    return BusinessCalendar.from_config(
        Calendar(timezone=tz, workdays=days, hours=hours), holidays=holidays
    )


def utc(y: int, mo: int, d: int, h: int = 0, mi: int = 0, s: int = 0) -> dt.datetime:
    return dt.datetime(y, mo, d, h, mi, s, tzinfo=UTC)


# --- business calendar ------------------------------------------------------------------------


class TestBusinessTime:
    def test_stays_inside_the_working_day(self) -> None:
        assert cal().add(utc(2025, 1, 6, 10, 0), 3600) == utc(2025, 1, 6, 11, 0)

    def test_overflow_rolls_to_the_next_morning(self) -> None:
        # Mon 16:45 + 1h: 45 minutes left today, 15 minutes on Tuesday.
        assert cal().add(utc(2025, 1, 6, 16, 45), 3600) == utc(2025, 1, 7, 9, 15)

    def test_before_opening_starts_at_opening(self) -> None:
        assert cal().add(utc(2025, 1, 6, 6, 0), 60) == utc(2025, 1, 6, 9, 1)

    def test_weekend_is_skipped(self) -> None:
        assert cal().add(utc(2025, 1, 10, 17, 0), 3600) == utc(2025, 1, 13, 9, 30)

    def test_holiday_is_skipped(self) -> None:
        c = cal(holidays=(dt.date(2025, 1, 7),))
        assert c.add(utc(2025, 1, 6, 16, 45), 3600) == utc(2025, 1, 8, 9, 15)

    def test_holiday_run_of_days_and_a_weekend(self) -> None:
        c = cal(holidays=(dt.date(2025, 1, 13), dt.date(2025, 1, 14)))
        assert c.add(utc(2025, 1, 10, 17, 0), 3600) == utc(2025, 1, 15, 9, 30)

    def test_starting_on_a_holiday(self) -> None:
        c = cal(holidays=(dt.date(2025, 1, 6),))
        assert c.add(utc(2025, 1, 6, 12, 0), 60) == utc(2025, 1, 7, 9, 1)

    def test_zero_is_the_start(self) -> None:
        assert cal().add(utc(2025, 1, 6, 12, 0), 0) == utc(2025, 1, 6, 12, 0)

    def test_negative_is_refused(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            cal().add(utc(2025, 1, 6, 12, 0), -1)

    def test_naive_datetimes_are_refused(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            cal().add(dt.datetime(2025, 1, 6, 12, 0), 60)

    def test_time_zone_moves_the_window(self) -> None:
        # 09:00 Tokyo is 00:00 UTC; 17:30 is 08:30 UTC.
        tokyo = cal("Asia/Tokyo")
        assert tokyo.add(utc(2025, 1, 6, 8, 0), 3600) == utc(2025, 1, 7, 0, 30)
        assert cal("America/New_York").add(utc(2025, 1, 6, 21, 0), 7200) == utc(2025, 1, 7, 14, 30)

    def test_workday_follows_the_local_date_not_the_utc_date(self) -> None:
        # Sunday 23:30 UTC is already Monday 08:30 in Tokyo: the day is a workday there.
        tokyo = cal("Asia/Tokyo")
        assert tokyo.add(utc(2025, 1, 5, 23, 30), 1800) == utc(2025, 1, 6, 0, 30)

    def test_spring_forward_does_not_shift_the_local_day(self) -> None:
        # London goes to BST on Sun 2025-03-30. Fri 17:00 GMT + 1h lands on Mon 09:30 BST (08:30Z).
        assert cal().add(utc(2025, 3, 28, 17, 0), 3600) == utc(2025, 3, 31, 8, 30)

    def test_autumn_back_does_not_shift_the_local_day(self) -> None:
        # BST ends Sun 2025-10-26. Fri 17:00 BST (16:00Z) + 1h lands on Mon 09:30 GMT (09:30Z).
        assert cal().add(utc(2025, 10, 24, 16, 0), 3600) == utc(2025, 10, 27, 9, 30)

    def test_a_window_that_spans_the_spring_gap_is_an_hour_shorter(self) -> None:
        # New York 01:00-05:00 on Sun 2025-03-09: 02:00 never happens, so the day has 3 hours.
        ny = cal("America/New_York", days=("sat", "sun", "mon"), hours="01:00-05:00")
        start = utc(2025, 3, 9, 6, 0)  # 01:00 EST
        assert ny.business_seconds_between(start, utc(2025, 3, 9, 9, 0)) == 3 * 3600
        # 4 business hours: 3 on Sunday, the 4th is Monday 01:00-02:00 EDT (05:00Z-06:00Z).
        assert ny.add(start, 4 * 3600) == utc(2025, 3, 10, 6, 0)

    def test_a_window_that_spans_the_autumn_repeat_is_an_hour_longer(self) -> None:
        # Sun 2025-11-02: 01:00 happens twice, so 01:00-05:00 has 5 hours.
        ny = cal("America/New_York", days=("sat", "sun"), hours="01:00-05:00")
        start = utc(2025, 11, 2, 5, 0)  # first 01:00 (EDT)
        assert ny.add(start, 5 * 3600) == utc(2025, 11, 2, 10, 0)  # 05:00 EST
        assert ny.add(start, 5 * 3600 + 1) == utc(2025, 11, 8, 6, 0, 1)  # next Saturday

    def test_between_is_the_inverse_of_add(self) -> None:
        c = cal(holidays=(dt.date(2025, 3, 31),))
        start = utc(2025, 3, 27, 13, 20)
        for secs in (0, 1, 3600, 8 * 3600, 30 * 3600, 100 * 3600 + 17):
            assert c.business_seconds_between(start, c.add(start, secs)) == secs

    def test_between_counts_nothing_out_of_hours(self) -> None:
        assert cal().business_seconds_between(utc(2025, 1, 4, 0, 0), utc(2025, 1, 6, 0, 0)) == 0
        assert cal().business_seconds_between(utc(2025, 1, 6, 12, 0), utc(2025, 1, 6, 11, 0)) == 0

    def test_durations_use_business_units(self) -> None:
        c = cal()  # a business day is 8.5 hours
        start = utc(2025, 1, 6, 9, 0)
        assert c.add_duration(start, "90m") == utc(2025, 1, 6, 10, 30)
        assert c.add_duration(start, "1d") == utc(2025, 1, 6, 17, 30)
        assert c.add_duration(start, "2d") == utc(2025, 1, 7, 17, 30)
        assert c.add_duration(start, "1w") == utc(2025, 1, 10, 17, 30)

    def test_a_calendar_with_no_working_time_is_refused(self) -> None:
        c = cal(
            days=("mon",),
            holidays=tuple(dt.date(2025, 1, 6) + dt.timedelta(7 * i) for i in range(600)),
        )
        with pytest.raises(ValueError, match="no business time"):
            c.add(utc(2025, 1, 6, 12, 0), 60)


# --- timers -----------------------------------------------------------------------------------


def open_gate_with_run(store: MemoryStore, status: RunStatus = RunStatus.WAITING_HUMAN) -> Gate:
    reason = "paused" if status is RunStatus.BLOCKED else None
    store.put(
        TEAM, Key(f"RUN#{RUN}", "META"), to_wire(Run(RUN, "t1", status, blocked_reason=reason))
    )
    subject = head_subject()
    return GateService(store).open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))


def set_run(store: MemoryStore, status: RunStatus) -> None:
    reason = "paused" if status is RunStatus.BLOCKED else None
    store.put(
        TEAM, Key(f"RUN#{RUN}", "META"), to_wire(Run(RUN, "t1", status, blocked_reason=reason))
    )


def gate_status(store: MemoryStore, round: int = 1) -> GateStatus:
    item = store.get(TEAM, Key(f"RUN#{RUN}", f"GATE#review#{round}"))
    assert item is not None
    return from_wire(Gate, item.data).status


def outbox(store: MemoryStore) -> list[dict[str, Any]]:
    return [i.data for i in store.query(TEAM, f"RUN#{RUN}", sk_prefix="OUT#").items]


def kinds(store: MemoryStore) -> list[str]:
    return [o["kind"] for o in outbox(store)]


T0 = utc(2025, 1, 6, 9, 0)


def head_subject(tag: str = "a") -> Subject:
    return Subject(
        patch_id=f"patch-{tag}",
        ticket_revision=f"rev-{tag}",
        head_sha=f"sha-{tag}",
        evidence_digest=f"ev-{tag}",
        attention_digest=f"att-{tag}",
    )


def timer(kind: TimerKind, due: dt.datetime = T0) -> Timer:
    gate = None if kind is TimerKind.MAX_RUN_AGE else "review"
    return Timer(TEAM.team, RUN, kind, due, gate=gate, round=1 if gate else None)


class TestFiring:
    def test_a_reminder_notifies_once_however_often_it_fires(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        h = TimerHandler(store)
        t = timer(TimerKind.REMIND)
        assert h.fire(TEAM, t, T0) is FireOutcome.DONE
        assert h.fire(TEAM, t, T0 + dt.timedelta(days=3)) is FireOutcome.DUPLICATE
        assert kinds(store) == ["gate.reminder"]
        assert gate_status(store) is GateStatus.OPEN
        assert verify_audit_chain(store, TEAM, RUN) == 2  # opened + reminder

    def test_escalation_names_the_role_and_grants_nothing(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        t = Timer(
            TEAM.team, RUN, TimerKind.ESCALATE, T0, gate="review", round=1, escalate_to="lead"
        )
        assert TimerHandler(store).fire(TEAM, t, T0) is FireOutcome.DONE
        (entry,) = outbox(store)
        assert entry["kind"] == "gate.escalation"
        assert entry["escalate_to"] == "lead"
        assert "eligible" not in entry
        assert gate_status(store) is GateStatus.OPEN

    def test_expiry_closes_the_gate_expired_and_it_cannot_be_decided_after(self) -> None:
        store = MemoryStore()
        gate = open_gate_with_run(store)
        assert TimerHandler(store).fire(TEAM, timer(TimerKind.EXPIRE), T0) is FireOutcome.DONE
        assert gate_status(store) is GateStatus.EXPIRED
        (entry,) = outbox(store)
        assert entry["kind"] == "gate.closed"
        assert entry["status"] == "EXPIRED"
        assert entry["decision"] is None
        assert entry["subject"] is None
        with pytest.raises(GateClosedError):
            GateService(store).decide(
                TEAM,
                run_id=RUN,
                gate="review",
                round=1,
                kind=DecisionKind.APPROVE,
                actor="alice",
                surface=Surface.UI,
                subject_digest=gate.subject.digest(),
            )
        assert verify_audit_chain(store, TEAM, RUN) == 2

    def test_a_late_timer_on_a_decided_gate_changes_nothing(self) -> None:
        store = MemoryStore()
        gate = open_gate_with_run(store)
        GateService(store).decide(
            TEAM,
            run_id=RUN,
            gate="review",
            round=1,
            kind=DecisionKind.APPROVE,
            actor="alice",
            surface=Surface.UI,
            subject_digest=gate.subject.digest(),
        )
        before = outbox(store)
        h = TimerHandler(store)
        for kind in (TimerKind.REMIND, TimerKind.ESCALATE, TimerKind.EXPIRE):
            assert h.fire(TEAM, timer(kind), T0) is FireOutcome.NOOP
        assert gate_status(store) is GateStatus.APPROVED
        assert outbox(store) == before

    def test_an_early_timer_does_nothing(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        h = TimerHandler(store)
        assert (
            h.fire(TEAM, timer(TimerKind.EXPIRE, T0 + dt.timedelta(hours=1)), T0)
            is FireOutcome.EARLY
        )
        assert gate_status(store) is GateStatus.OPEN
        assert outbox(store) == []

    def test_a_timer_for_a_missing_gate_or_run_is_a_noop(self) -> None:
        store = MemoryStore()
        h = TimerHandler(store)
        assert h.fire(TEAM, timer(TimerKind.REMIND), T0) is FireOutcome.NOOP
        open_gate_with_run(store)
        missing = Timer(TEAM.team, RUN, TimerKind.EXPIRE, T0, gate="review", round=7)
        assert h.fire(TEAM, missing, T0) is FireOutcome.NOOP

    def test_a_timer_for_a_finished_run_is_a_noop(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        set_run(store, RunStatus.CLOSED)
        assert TimerHandler(store).fire(TEAM, timer(TimerKind.EXPIRE), T0) is FireOutcome.NOOP
        assert gate_status(store) is GateStatus.OPEN

    def test_a_timer_of_another_team_is_refused(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        other = Timer("t2", RUN, TimerKind.EXPIRE, T0, gate="review", round=1)
        with pytest.raises(ValueError, match="team"):
            TimerHandler(store).fire(TEAM, other, T0)

    @pytest.mark.parametrize("round_", [1, 2])
    def test_only_the_timers_round_is_touched(self, round_: int) -> None:
        store = MemoryStore()
        gate = open_gate_with_run(store)
        svc = GateService(store)
        svc.decide(
            TEAM,
            run_id=RUN,
            gate="review",
            round=1,
            kind=DecisionKind.REQUEST_CHANGES,
            actor="alice",
            surface=Surface.UI,
            subject_digest=gate.subject.digest(),
            comment="needs work",
        )
        svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 2, head_subject("2")))
        t = Timer(TEAM.team, RUN, TimerKind.EXPIRE, T0, gate="review", round=round_)
        TimerHandler(store).fire(TEAM, t, T0)
        assert gate_status(store, 1) is GateStatus.CHANGES_REQUESTED
        assert gate_status(store, 2) is (GateStatus.EXPIRED if round_ == 2 else GateStatus.OPEN)


class TestG12:
    """Fire every timer in any order, late and repeated: never approved."""

    ALL = (TimerKind.REMIND, TimerKind.ESCALATE, TimerKind.EXPIRE, TimerKind.MAX_RUN_AGE)

    @pytest.mark.parametrize("order", list(itertools.permutations(ALL)))
    @pytest.mark.parametrize("offsets", [(0, 0), (-1, 5), (400, 400)])
    def test_no_order_approves(
        self, order: tuple[TimerKind, ...], offsets: tuple[int, int]
    ) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        h = TimerHandler(store)
        for off in offsets:
            for kind in order * 2:  # repeated
                t = timer(kind, T0 + dt.timedelta(days=off if off < 0 else 0))
                h.fire(TEAM, t, T0 + dt.timedelta(days=off))
        assert gate_status(store) in (GateStatus.OPEN, GateStatus.EXPIRED)
        for entry in outbox(store):
            assert entry.get("decision") is None
            assert entry.get("status") != "APPROVED"
        assert verify_audit_chain(store, TEAM, RUN) >= 1

    def test_no_firing_adds_a_decision_record(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        h = TimerHandler(store)
        for kind in self.ALL:
            h.fire(TEAM, timer(kind), T0 + dt.timedelta(days=500))
        assert list(store.query(TEAM, f"RUN#{RUN}", sk_prefix="DEC#").items) == []

    def test_the_timer_module_has_no_path_to_approval(self) -> None:
        import sto.gates.timers as mod

        src = Path(mod.__file__).read_text()
        assert "APPROVED" not in src
        assert "DecisionKind" not in src


# --- pause ------------------------------------------------------------------------------------


class TestPause:
    def test_a_reminder_does_nothing_while_the_run_is_paused(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store, RunStatus.BLOCKED)
        h = TimerHandler(store)
        for kind in (TimerKind.REMIND, TimerKind.ESCALATE, TimerKind.EXPIRE):
            assert h.fire(TEAM, timer(kind), T0 + dt.timedelta(days=9)) is FireOutcome.PAUSED
        assert gate_status(store) is GateStatus.OPEN
        assert outbox(store) == []

    def test_the_same_timer_fires_once_the_run_resumes(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store, RunStatus.BLOCKED)
        h = TimerHandler(store)
        t = timer(TimerKind.REMIND)
        assert h.fire(TEAM, t, T0) is FireOutcome.PAUSED
        set_run(store, RunStatus.WAITING_HUMAN)
        assert h.fire(TEAM, t, T0) is FireOutcome.DONE

    def test_resume_gives_back_only_the_business_time_that_was_left(self) -> None:
        c = cal()
        timers = LocalTimers(c)
        t = timer(TimerKind.REMIND, utc(2025, 1, 6, 15, 0))  # Mon, 2h left at 13:00
        timers.schedule(t)
        timers.pause(RUN, utc(2025, 1, 6, 13, 0))
        timers.resume(RUN, utc(2025, 1, 8, 10, 0))  # Wed 10:00
        (moved,) = timers.due(utc(2025, 1, 9, 0, 0))
        assert moved.due_at == utc(2025, 1, 8, 12, 0)
        assert timers.due(utc(2025, 1, 8, 11, 59)) == []

    def test_a_paused_timer_is_not_due(self) -> None:
        timers = LocalTimers(cal())
        timers.schedule(timer(TimerKind.REMIND))
        timers.pause(RUN, T0)
        assert timers.due(T0 + dt.timedelta(days=30)) == []

    def test_pausing_twice_or_resuming_twice_is_harmless(self) -> None:
        timers = LocalTimers(cal())
        timers.schedule(timer(TimerKind.REMIND, utc(2025, 1, 6, 15, 0)))
        timers.pause(RUN, utc(2025, 1, 6, 13, 0))
        timers.pause(RUN, utc(2025, 1, 6, 14, 0))  # keeps the first pause
        timers.resume(RUN, utc(2025, 1, 7, 9, 0))
        timers.resume(RUN, utc(2025, 1, 8, 9, 0))
        (moved,) = timers.due(utc(2025, 1, 31))
        assert moved.due_at == utc(2025, 1, 7, 11, 0)

    def test_pause_does_not_touch_other_runs(self) -> None:
        timers = LocalTimers(cal())
        other = Timer(
            TEAM.team,
            RunId.parse("01J00000000000000000000002"),
            TimerKind.REMIND,
            T0,
            gate="review",
            round=1,
        )
        timers.schedule(other)
        timers.pause(RUN, T0)
        assert timers.due(T0) == [other]


class TestMaxRunAge:
    def test_it_counts_wall_clock_across_weekends_and_holidays(self) -> None:
        timers = LocalTimers(cal(holidays=(dt.date(2025, 1, 7),)))
        started = utc(2025, 1, 3, 17, 0)  # Fri evening
        schedule_run_age(timers, TEAM.team, RUN, started, "30d")
        (t,) = timers.due(utc(2026, 1, 1))
        assert t.kind is TimerKind.MAX_RUN_AGE
        assert t.due_at == started + dt.timedelta(days=30)

    def test_it_does_not_pause_with_the_run(self) -> None:
        timers = LocalTimers(cal())
        schedule_run_age(timers, TEAM.team, RUN, T0, "2d")
        timers.pause(RUN, T0)
        timers.resume(RUN, T0 + dt.timedelta(days=1))
        (t,) = timers.due(T0 + dt.timedelta(days=2))
        assert t.due_at == T0 + dt.timedelta(days=2)

    def test_it_fires_while_the_run_is_paused_and_expires_open_gates(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store, RunStatus.BLOCKED)
        t = timer(TimerKind.MAX_RUN_AGE)
        h = TimerHandler(store)
        assert h.fire(TEAM, t, T0) is FireOutcome.DONE
        assert gate_status(store) is GateStatus.EXPIRED
        assert "run.max_age_exceeded" in kinds(store)
        assert h.fire(TEAM, t, T0 + dt.timedelta(days=1)) is FireOutcome.DUPLICATE
        assert verify_audit_chain(store, TEAM, RUN) >= 2

    def test_it_holds_even_if_every_gate_timer_was_never_scheduled(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        timers = LocalTimers(cal())
        schedule_run_age(timers, TEAM.team, RUN, T0, "1d")
        (t,) = timers.due(T0 + dt.timedelta(days=1))
        assert TimerHandler(store).fire(TEAM, t, T0 + dt.timedelta(days=1)) is FireOutcome.DONE

    def test_early_firing_does_nothing(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        t = timer(TimerKind.MAX_RUN_AGE, T0 + dt.timedelta(days=5))
        assert TimerHandler(store).fire(TEAM, t, T0) is FireOutcome.EARLY
        assert gate_status(store) is GateStatus.OPEN

    def test_a_finished_run_ignores_it(self) -> None:
        store = MemoryStore()
        open_gate_with_run(store)
        set_run(store, RunStatus.DONE)
        assert TimerHandler(store).fire(TEAM, timer(TimerKind.MAX_RUN_AGE), T0) is FireOutcome.NOOP


# --- scheduling -------------------------------------------------------------------------------


class TestScheduling:
    def test_timers_are_scheduled_in_business_time(self) -> None:
        timers = LocalTimers(cal())
        opened = utc(2025, 1, 10, 16, 0)  # Fri 16:00
        schedule_gate_timers(
            timers,
            TEAM.team,
            RUN,
            "review",
            1,
            opened,
            Timeouts(remind_after="1d", escalate_after="2d", escalate_to="lead", expire_after="3d"),
        )
        got = {t.kind: t for t in timers.due(utc(2026, 1, 1))}
        assert got[TimerKind.REMIND].due_at == utc(2025, 1, 13, 16, 0)  # Fri 1.5h + Mon 7h
        assert got[TimerKind.ESCALATE].escalate_to == "lead"
        assert (
            got[TimerKind.EXPIRE].due_at
            > got[TimerKind.ESCALATE].due_at
            > got[TimerKind.REMIND].due_at
        )

    def test_scheduling_twice_keeps_one_timer(self) -> None:
        timers = LocalTimers(cal())
        t = timer(TimerKind.REMIND)
        timers.schedule(t)
        timers.schedule(t)
        assert timers.due(T0) == [t]

    def test_defaults_remind_after_one_day_and_nothing_expires(self) -> None:
        timers = LocalTimers(cal())
        schedule_gate_timers(timers, TEAM.team, RUN, "review", 1, T0, None)
        (t,) = timers.due(utc(2026, 1, 1))
        assert t.kind is TimerKind.REMIND
        assert t.due_at == utc(2025, 1, 6, 17, 30)

    def test_escalation_needs_a_role(self) -> None:
        timers = LocalTimers(cal())
        schedule_gate_timers(timers, TEAM.team, RUN, "review", 1, T0, Timeouts(escalate_after="2d"))
        assert {t.kind for t in timers.due(utc(2026, 1, 1))} == {TimerKind.REMIND}

    def test_a_fired_timer_is_removed(self) -> None:
        timers = LocalTimers(cal())
        t = timer(TimerKind.REMIND)
        timers.schedule(t)
        timers.done(t)
        assert timers.due(T0) == []

    def test_due_is_ordered_and_excludes_the_future(self) -> None:
        timers = LocalTimers(cal())
        a, b = timer(TimerKind.EXPIRE, T0 + dt.timedelta(hours=2)), timer(TimerKind.REMIND, T0)
        timers.schedule(a)
        timers.schedule(b)
        assert timers.due(T0 + dt.timedelta(hours=1)) == [b]
        assert timers.due(T0 + dt.timedelta(hours=3)) == [b, a]

    def test_naive_due_time_is_refused(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            Timer(TEAM.team, RUN, TimerKind.REMIND, dt.datetime(2025, 1, 6), gate="review", round=1)

    def test_a_gate_timer_needs_its_gate(self) -> None:
        with pytest.raises(ValueError, match="gate"):
            Timer(TEAM.team, RUN, TimerKind.REMIND, T0)
