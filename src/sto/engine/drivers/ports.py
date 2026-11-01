"""Ports of the local driver (D1-03): what it needs from the code that performs commands.

The driver depends on commands, events and this port only, so the gate service and effects
(which perform ``OpenGate`` and ``RunEffect``) plug in without the driver changing.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from sto.engine.commands import OpenGate


def command_key(command: object, seq: int) -> str:
    """The idempotency key a command is executed under.

    ``seq`` is the command's position in the run's persisted command log, so a re-run after a
    crash gets the same key. ``OpenGate`` is keyed by ``(run, name, round)`` (the gate's own key,
    see ``sto.engine.commands``) so opening a gate is idempotent whatever ``seq`` it had.
    """
    if isinstance(command, OpenGate):
        return f"gate:{command.run_id}:{command.name}:{command.round}"
    return f"cmd:{getattr(command, 'run_id', '?')}:{seq}:{type(command).__name__}"


@dataclass(frozen=True)
class Done:
    """The command finished; ``events`` are what the run should hear about it. No events is
    normal when the outcome arrives later from outside (a gate waiting for a person)."""

    events: Sequence[object] = ()


@dataclass(frozen=True)
class StillRunning:
    """The command is not finished (an effect that is ``in_flight``, ``held``, ``RETRYING`` or
    ``ACCEPTED`` and waiting for a poll). The driver keeps it at the head of the queue, applies
    any queued event first (so a Stop is not stuck behind it), waits ``retry_after`` seconds and
    calls again with the same key."""

    retry_after: float
    reason: str = ""

    def __post_init__(self) -> None:
        if not (math.isfinite(self.retry_after) and self.retry_after >= 0):
            raise ValueError("retry_after must be a finite, non-negative number of seconds")


@dataclass(frozen=True)
class Held:
    """The command cannot proceed until something outside the run changes (a kill switch, a
    freeze). The driver does not poll: ``run_until_idle`` returns, the command stays at the head
    of the queue, and ``LocalDriver.held(run_id)`` reports ``reason``. Calling ``run_until_idle``
    or ``resume_all`` again retries it."""

    reason: str = "held"


Outcome = Done | StillRunning | Held


class CommandExecutor(Protocol):
    """Performs one command.

    **Must be idempotent on ``key``, and a replay must return the original ``Done`` events.**
    The driver commits "command done" only after ``execute`` returns, so a crash in between
    makes it call again with the same key. The work must not happen twice, and the second call
    must report the same events as the first: an empty answer on replay would leave the run
    RUNNING with nothing queued, which the driver reports as ``RunWedgedError``.

    **Mapping the effects service's ``ExecResult`` (D1-08 owns the adapter).** Check ``blocked``
    first, because a blocked effect also has status ``RETRYING``:

    * ``blocked=True`` (outcome unknown, a person must decide): ``Done([EffectFailed(...)])``.
      Returning ``StillRunning`` here would spin forever.
    * finished (``done``/``stale``/``conflict`` edge, or a replay of one): ``Done`` with the
      original ``EffectConfirmed`` or ``EffectFailed``.
    * ``reason == "held"``: ``Held("held")``.
    * ``in_flight``, ``RETRYING`` (not blocked), or ``unconfirmed``: ``StillRunning(n)``.
    * ``ACCEPTED``: ``execute`` of the effects service only replays, so the adapter must call
      its ``poll`` (and ``stop`` instead while the run is CANCELLING), then map the result as
      above, ``StillRunning`` while it is still unconfirmed.

    The driver runs a queued ``StopRun`` ahead of a command that is not finished, and applies
    queued events before every call, so none of these can hold a Stop behind a pending merge.

    Do not poll or sleep inside ``execute``: return ``StillRunning`` instead, so queued events
    (Stop) can be applied between calls. Raising ends the driver loop; it is for faults.
    """

    async def execute(self, key: str, command: object) -> Outcome: ...
