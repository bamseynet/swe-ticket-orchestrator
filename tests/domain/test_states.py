"""Edge tables are pinned to PLAN 4.7 (gate), 6.2 (run), 6.3 (effect), written out independently."""

from __future__ import annotations

from enum import Enum
from typing import Any

import pytest

from sto.domain import (
    EffectStatus,
    GateStatus,
    InvalidTransitionError,
    RunStatus,
    StepStatus,
    can_transition,
    transition,
)

R, G, E, S = RunStatus, GateStatus, EffectStatus, StepStatus

RUN_EDGES = {
    (R.QUEUED, R.RUNNING),
    (R.RUNNING, R.WAITING_HUMAN),
    (R.WAITING_HUMAN, R.RUNNING),
    (R.RUNNING, R.WAITING_EXTERNAL),
    (R.WAITING_EXTERNAL, R.RUNNING),
    (R.RUNNING, R.BLOCKED),
    (R.WAITING_EXTERNAL, R.BLOCKED),
    (R.BLOCKED, R.RUNNING),
    (R.BLOCKED, R.WAITING_HUMAN),
    (R.WAITING_HUMAN, R.BLOCKED),
    (R.QUEUED, R.CANCELLING),
    (R.RUNNING, R.CANCELLING),
    (R.WAITING_HUMAN, R.CANCELLING),
    (R.WAITING_EXTERNAL, R.CANCELLING),
    (R.BLOCKED, R.CANCELLING),
    (R.CANCELLING, R.CANCELLED),
    (R.RUNNING, R.DONE),
    (R.RUNNING, R.REJECTED),
    (R.RUNNING, R.CLOSED),
    (R.RUNNING, R.EXPIRED),
}
GATE_EDGES = {
    (G.OPEN, G.OPEN),
    (G.OPEN, G.APPROVED),
    (G.OPEN, G.CHANGES_REQUESTED),
    (G.OPEN, G.RETEST),
    (G.OPEN, G.REJECTED),
    (G.OPEN, G.EXPIRED),
    (G.OPEN, G.SUPERSEDED),
    (G.OPEN, G.CANCELLED),
    (G.APPROVED, G.INVALIDATED),
}
EFFECT_EDGES = {
    (E.PLANNED, E.ATTEMPTING),
    (E.ATTEMPTING, E.CONFIRMED),
    (E.ATTEMPTING, E.RETRYING),
    (E.RETRYING, E.ATTEMPTING),
    (E.ATTEMPTING, E.FAILED),
    (E.ATTEMPTING, E.ACCEPTED),
    (E.ACCEPTED, E.CONFIRMED),
    (E.ACCEPTED, E.FAILED),
    (E.ACCEPTED, E.VOIDED),
    (E.PLANNED, E.VOIDED),
    (E.RETRYING, E.VOIDED),
}
# Not drawn in PLAN: a step's own life, kept minimal. Retries are new attempts (STEP#n#a).
STEP_EDGES = {
    (S.PENDING, S.RUNNING),
    (S.PENDING, S.CANCELLED),
    (S.RUNNING, S.SUCCEEDED),
    (S.RUNNING, S.FAILED),
    (S.RUNNING, S.CANCELLED),
}

TABLES: list[tuple[type[Enum], set[tuple[Any, Any]]]] = [
    (R, RUN_EDGES),
    (G, GATE_EDGES),
    (E, EFFECT_EDGES),
    (S, STEP_EDGES),
]


@pytest.mark.parametrize(("enum", "edges"), TABLES, ids=lambda x: getattr(x, "__name__", ""))
def test_table_is_exactly_the_plan(enum: type[Enum], edges: set[tuple[Any, Any]]) -> None:
    for a in enum:
        for b in enum:
            assert can_transition(a, b) == ((a, b) in edges), (a, b)
            if (a, b) in edges:
                assert transition(a, b) is b
            else:
                with pytest.raises(InvalidTransitionError):
                    transition(a, b)


def test_terminal_flags() -> None:
    assert {s for s in R if s.is_terminal} == {R.DONE, R.REJECTED, R.CLOSED, R.EXPIRED, R.CANCELLED}
    assert {s for s in G if s.is_terminal} == set(G) - {G.OPEN, G.APPROVED}
    assert {s for s in E if s.is_terminal} == {E.CONFIRMED, E.FAILED, E.VOIDED}


def test_only_open_gate_is_open() -> None:
    # PLAN 4.7: decisions are collected only in OPEN; APPROVED is not terminal (it can still be
    # INVALIDATED) but no longer takes decisions.
    assert {s for s in G if s.is_open} == {G.OPEN}
    assert not G.APPROVED.is_terminal


@pytest.mark.parametrize(
    "closed",
    [
        G.RETEST,
        G.SUPERSEDED,
        G.CANCELLED,
        G.REJECTED,
        G.EXPIRED,
        G.CHANGES_REQUESTED,
        G.INVALIDATED,
    ],
)
def test_closed_gate_never_reopens_or_approves(closed: GateStatus) -> None:
    assert all(not can_transition(closed, t) for t in G)


def test_every_live_run_state_can_be_stopped() -> None:
    live = {R.QUEUED, R.RUNNING, R.WAITING_HUMAN, R.WAITING_EXTERNAL, R.BLOCKED}
    assert all(can_transition(s, R.CANCELLING) for s in live)


def test_same_valued_members_of_different_enums_do_not_collide() -> None:
    # StrEnum members hash as their strings; REJECTED exists in both run and gate.
    assert str(R.REJECTED) == str(G.REJECTED)  # same string, the trap
    assert can_transition(R.RUNNING, R.REJECTED)
    assert not can_transition(G.OPEN, R.REJECTED)
    assert not can_transition(R.RUNNING, G.REJECTED)
    assert can_transition(G.OPEN, G.REJECTED)


def test_plain_strings_and_cross_enum_are_rejected() -> None:
    assert not can_transition("QUEUED", "RUNNING")  # type: ignore[arg-type]
    assert not can_transition(R.QUEUED, "RUNNING")  # type: ignore[arg-type]
    with pytest.raises(InvalidTransitionError):
        transition(R.QUEUED, G.OPEN)
