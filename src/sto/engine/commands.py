"""Commands the reducer emits (PLAN 6.1). The reducer never performs them: a driver does.

Each command registers itself in ``sto.domain.COMMANDS``. Later modules register their own
commands from their own files, so adding one never edits this file.

``OpenGate`` carries no gate ID, because the reducer has no randomness. It is identified by
``(run_id, name, round)`` (the ``GATE#g#round`` key). D1-06 must make opening a gate
idempotent on that triple, not mint an ID and insert, or a replayed command opens it twice.
"""

from __future__ import annotations

from dataclasses import dataclass

from sto.domain import COMMANDS, DecisionId, GateType, RunId, RunStatus, Subject


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
    """Always a head subject: every gate here binds evidence via ``head_sha``."""

    run_id: RunId
    name: str
    type: GateType
    round: int
    subject: Subject


@COMMANDS.register("run_effect")
@dataclass(frozen=True)
class RunEffect:
    """Plan a gated effect. Carries what its idempotency key (PLAN 6.3) and claim need:
    stage, visit, type, the approved subject and the decisions that approved it."""

    run_id: RunId
    type: str
    stage: str
    visit: int
    subject: Subject
    subject_digest: str
    requires_gates: tuple[str, ...]
    decision_ids: tuple[DecisionId, ...]


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
