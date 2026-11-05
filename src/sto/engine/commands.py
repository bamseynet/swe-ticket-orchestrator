"""Commands the reducer emits (PLAN 6.1). The reducer never performs them: a driver does.

Each command registers itself in ``sto.domain.COMMANDS``. Later modules register their own
commands from their own files, so adding one never edits this file.

``OpenGate`` carries no gate ID, because the reducer has no randomness. It is identified by
``(run_id, name, round)`` (the ``GATE#g#round`` key). D1-06 must make opening a gate
idempotent on that triple, not mint an ID and insert, or a replayed command opens it twice.

``OpenGate.subject`` is a head subject for every gate type but ``pre_push``, whose gate closes
before any commit exists and so takes the short pre-push subject (the ``Gate`` invariant).
``OpenRevert`` is the engine's implicit scoped effect for a merge that ended without a QA
approval (PLAN 6.2); like ``pr.open_revert`` it is keyed by ``(run, merge_sha)`` (PLAN 6.3), so a
replay or a declared revert opens one PR.
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
    """A head subject, or the pre-push subject for a ``pre_push`` gate (see the module doc)."""

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


@COMMANDS.register("open_revert")
@dataclass(frozen=True)
class OpenRevert:
    run_id: RunId
    merge_sha: str


@COMMANDS.register("finish")
@dataclass(frozen=True)
class Finish:
    """``incident`` is the ``done_with_incident`` flag of PLAN 6.2: the run merged code and
    ended without a QA approval of it, so the driver alerts."""

    run_id: RunId
    status: RunStatus
    incident: bool = False
