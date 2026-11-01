"""State enums and their legal edges (PLAN 4.7, 6.2, 6.3).

``transition`` (and ``advance`` on the models) is the *checked* way to change a status: it
consults the edge table and raises ``InvalidTransitionError``. It is not the only way:
``dataclasses.replace(run, status=...)`` still builds any status, so code must use ``advance``.
Tables are per enum, because ``StrEnum`` members hash as plain strings (``REJECTED`` exists in
the run and gate enums) and one shared table would collide.
"""

from __future__ import annotations

from enum import Enum, StrEnum

from .errors import InvalidTransitionError


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING_HUMAN = "WAITING_HUMAN"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    BLOCKED = "BLOCKED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    DONE = "DONE"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"

    @property
    def is_terminal(self) -> bool:
        return not _EDGES[RunStatus][self]


class GateStatus(StrEnum):
    OPEN = "OPEN"
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    RETEST = "RETEST"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    CANCELLED = "CANCELLED"
    INVALIDATED = "INVALIDATED"

    @property
    def is_terminal(self) -> bool:
        return not _EDGES[GateStatus][self]

    @property
    def is_open(self) -> bool:
        """Only OPEN collects decisions. APPROVED is not terminal (it can be INVALIDATED)."""
        return self is GateStatus.OPEN


class EffectStatus(StrEnum):
    PLANNED = "PLANNED"
    ATTEMPTING = "ATTEMPTING"
    RETRYING = "RETRYING"
    ACCEPTED = "ACCEPTED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    VOIDED = "VOIDED"

    @property
    def is_terminal(self) -> bool:
        return not _EDGES[EffectStatus][self]


class StepStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return not _EDGES[StepStatus][self]


R, G, E, S = RunStatus, GateStatus, EffectStatus, StepStatus

_EDGES: dict[type[Enum], dict[Enum, frozenset[Enum]]] = {
    RunStatus: {
        R.QUEUED: frozenset({R.RUNNING, R.CANCELLING}),
        R.RUNNING: frozenset(
            {
                R.WAITING_HUMAN,
                R.WAITING_EXTERNAL,
                R.BLOCKED,
                R.CANCELLING,
                R.DONE,
                R.REJECTED,
                R.CLOSED,
                R.EXPIRED,
            }
        ),
        R.WAITING_HUMAN: frozenset({R.RUNNING, R.BLOCKED, R.CANCELLING}),
        R.WAITING_EXTERNAL: frozenset({R.RUNNING, R.BLOCKED, R.CANCELLING}),
        R.BLOCKED: frozenset({R.RUNNING, R.WAITING_HUMAN, R.CANCELLING}),
        R.CANCELLING: frozenset({R.CANCELLED}),
        R.CANCELLED: frozenset(),
        R.DONE: frozenset(),
        R.REJECTED: frozenset(),
        R.CLOSED: frozenset(),
        R.EXPIRED: frozenset(),
    },
    GateStatus: {
        G.OPEN: frozenset(
            {
                G.OPEN,
                G.APPROVED,
                G.CHANGES_REQUESTED,
                G.RETEST,
                G.REJECTED,
                G.EXPIRED,
                G.SUPERSEDED,
                G.CANCELLED,
            }
        ),
        G.APPROVED: frozenset({G.INVALIDATED}),
        G.CHANGES_REQUESTED: frozenset(),
        G.RETEST: frozenset(),
        G.REJECTED: frozenset(),
        G.EXPIRED: frozenset(),
        G.SUPERSEDED: frozenset(),
        G.CANCELLED: frozenset(),
        G.INVALIDATED: frozenset(),
    },
    EffectStatus: {
        E.PLANNED: frozenset({E.ATTEMPTING, E.VOIDED}),
        E.ATTEMPTING: frozenset({E.CONFIRMED, E.RETRYING, E.FAILED, E.ACCEPTED}),
        E.RETRYING: frozenset({E.ATTEMPTING, E.VOIDED}),
        E.ACCEPTED: frozenset({E.CONFIRMED, E.FAILED, E.VOIDED}),
        E.CONFIRMED: frozenset(),
        E.FAILED: frozenset(),
        E.VOIDED: frozenset(),
    },
    StepStatus: {
        S.PENDING: frozenset({S.RUNNING, S.CANCELLED}),
        S.RUNNING: frozenset({S.SUCCEEDED, S.FAILED, S.CANCELLED}),
        S.SUCCEEDED: frozenset(),
        S.FAILED: frozenset(),
        S.CANCELLED: frozenset(),
    },
}


def can_transition(current: Enum, target: Enum) -> bool:
    if not isinstance(current, Enum) or type(current) is not type(target):
        return False
    return target in _EDGES.get(type(current), {}).get(current, frozenset())


def transition[T: Enum](current: T, target: T) -> T:
    """Return ``target`` if the edge is legal, else raise ``InvalidTransitionError``."""
    if not can_transition(current, target):
        raise InvalidTransitionError(f"illegal transition {current!r} -> {target!r}")
    return target
