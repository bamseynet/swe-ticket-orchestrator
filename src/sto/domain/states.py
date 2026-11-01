"""State enums and their legal edges (PLAN 4.7, 6.2, 6.3).

Illegal moves are unrepresentable as a *value*: the only way to change a status is
``transition``, which consults the table below and raises ``InvalidTransitionError``.
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
        return not _EDGES[self]


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
        return not _EDGES[self]


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
        return not _EDGES[self]


R, G, E = RunStatus, GateStatus, EffectStatus
_STOPPABLE = (R.QUEUED, R.RUNNING, R.WAITING_HUMAN, R.WAITING_EXTERNAL, R.BLOCKED)

_EDGES: dict[Enum, frozenset[Enum]] = {
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
    E.PLANNED: frozenset({E.ATTEMPTING, E.VOIDED}),
    E.ATTEMPTING: frozenset({E.CONFIRMED, E.RETRYING, E.FAILED, E.ACCEPTED}),
    E.RETRYING: frozenset({E.ATTEMPTING, E.VOIDED}),
    E.ACCEPTED: frozenset({E.CONFIRMED, E.FAILED, E.VOIDED}),
    E.CONFIRMED: frozenset(),
    E.FAILED: frozenset(),
    E.VOIDED: frozenset(),
}


def can_transition(current: Enum, target: Enum) -> bool:
    return type(current) is type(target) and target in _EDGES.get(current, frozenset())


def transition[S: Enum](current: S, target: S) -> S:
    """Return ``target`` if the edge is legal, else raise ``InvalidTransitionError``."""
    if not can_transition(current, target):
        raise InvalidTransitionError(f"illegal transition {current!r} -> {target!r}")
    return target
