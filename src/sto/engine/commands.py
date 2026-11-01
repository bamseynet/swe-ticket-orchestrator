"""Commands the reducer emits (PLAN 6.1). The reducer never performs them: a driver does.

Each command registers itself in ``sto.domain.COMMANDS``. Later modules register their own
commands from their own files, so adding one never edits this file.
"""

from __future__ import annotations

from dataclasses import dataclass

from sto.domain import COMMANDS, GateType, RunId, RunStatus, Subject


@COMMANDS.register("run_step")
@dataclass(frozen=True)
class RunStep:
    run_id: RunId
    stage: str
    visit: int
    attempt: int


@COMMANDS.register("open_gate")
@dataclass(frozen=True)
class OpenGate:
    """The gate service mints the gate ID; the reducer has no randomness to do it with."""

    run_id: RunId
    name: str
    type: GateType
    round: int
    subject: Subject


@COMMANDS.register("stop_run")
@dataclass(frozen=True)
class StopRun:
    """Stop every session of the run; the driver reports back with ``CancelCompleted``."""

    run_id: RunId


@COMMANDS.register("finish")
@dataclass(frozen=True)
class Finish:
    run_id: RunId
    status: RunStatus
