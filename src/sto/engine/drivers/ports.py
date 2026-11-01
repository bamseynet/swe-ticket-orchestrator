"""Ports of the local driver (D1-03): what it needs from the code that performs commands.

The driver depends on commands, events and this port only, so the gate service and effects
(which perform ``OpenGate`` and ``RunEffect``) plug in later without the driver changing.
"""

from __future__ import annotations

from collections.abc import Sequence
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


class CommandExecutor(Protocol):
    """Performs one command and reports what happened as events.

    **Must be idempotent on ``key``.** The driver commits "command done" only after ``execute``
    returns, so a crash in between makes it call again with the same key. Performing the work
    twice for one key is a bug in the executor, not something the driver can undo. Returning
    no events is normal for a command whose outcome arrives later (an open gate).
    """

    async def execute(self, key: str, command: object) -> Sequence[object]: ...
