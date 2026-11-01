"""Core events, blocked reasons and handlers for the linear workflow (D1-02).

``Run`` carries no visit, round or attempt counter (domain is frozen), so the reducer trusts
the visit, round and attempt on the event and cannot tell a stale one from a live one: the
driver and store fence that (version CAS). It does check run, stage, gate name and status.

Run positions: ``Run.stage`` names the current node. A step node is current while the run is
RUNNING; a gate node is current while it is WAITING_HUMAN. A step's ``visit`` counts its
reruns and doubles as the round of the gate that follows it.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from sto.domain import (
    BLOCKED_REASONS,
    EVENTS,
    DecisionKind,
    FailureClass,
    GateType,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
)
from sto.engine.commands import Finish, OpenGate, RunStep, StopRun
from sto.engine.reducer import OutOfOrderEventError, Transition, Workflow, handles


@BLOCKED_REASONS.register("attempts_exhausted")
class AttemptsExhausted:
    pass


@BLOCKED_REASONS.register("permanent_failure")
class PermanentFailure:
    pass


@BLOCKED_REASONS.register("degraded")
class Degraded:
    pass


@EVENTS.register("run.started")
@dataclass(frozen=True)
class RunStarted:
    run_id: RunId


@EVENTS.register("step.succeeded")
@dataclass(frozen=True)
class StepSucceeded:
    """``subject`` is what the next gate will approve; required when a gate follows."""

    key: StepKey
    subject: Subject | None = None

    @property
    def run_id(self) -> RunId:
        return self.key.run_id


@EVENTS.register("step.failed")
@dataclass(frozen=True)
class StepFailed:
    key: StepKey
    failure_class: FailureClass

    def __post_init__(self) -> None:
        object.__setattr__(self, "failure_class", FailureClass(self.failure_class))

    @property
    def run_id(self) -> RunId:
        return self.key.run_id


@EVENTS.register("gate.closed")
@dataclass(frozen=True)
class GateClosed:
    run_id: RunId
    gate: str
    round: int
    kind: DecisionKind
    actor: str


@EVENTS.register("cancel.requested")
@dataclass(frozen=True)
class CancelRequested:
    run_id: RunId


@EVENTS.register("cancel.completed")
@dataclass(frozen=True)
class CancelCompleted:
    run_id: RunId


def _bump(run: Run, **changes: object) -> Run:
    return dataclasses.replace(run, version=run.version + 1, **changes)  # type: ignore[arg-type]


def _reject(what: str) -> OutOfOrderEventError:
    return OutOfOrderEventError(what)


def _enter(run: Run, wf: Workflow, index: int, visit: int, subject: Subject | None) -> Transition:
    """Move the run onto node ``index`` (or finish if the list is exhausted)."""
    if index >= len(wf.nodes):
        done = _bump(run.advance(RunStatus.DONE), stage=run.stage)
        return Transition(done, (Finish(run.id, RunStatus.DONE),))
    node = wf.nodes[index]
    if node.kind == "step":
        return Transition(
            _bump(run, stage=node.name), (RunStep(run.id, node.name, visit=visit, attempt=1),)
        )
    if subject is None:
        raise _reject(f"gate {node.name!r} needs a subject from the preceding step")
    gate_type = GateType.QA if node.name == "qa" else GateType.REVIEW
    waiting = _bump(run.advance(RunStatus.WAITING_HUMAN), stage=node.name)
    return Transition(waiting, (OpenGate(run.id, node.name, gate_type, visit, subject),))


def _current_step(run: Run, wf: Workflow, key: StepKey) -> int:
    if run.status is not RunStatus.RUNNING:
        raise _reject(f"step event while run is {run.status.value}")
    index = wf.index(key.stage)
    if index is None or wf.nodes[index].kind != "step" or key.stage != run.stage:
        raise _reject(f"step {key.stage!r} is not the current stage ({run.stage!r})")
    return index


@handles(RunStarted)
def on_run_started(run: Run, event: RunStarted, wf: Workflow) -> Transition:
    if run.status is not RunStatus.QUEUED:
        raise _reject(f"run already started ({run.status.value})")
    first = wf.nodes[0]
    started = _bump(run.advance(RunStatus.RUNNING), stage=first.name, workflow_version=wf.version)
    return Transition(started, (RunStep(run.id, first.name, visit=1, attempt=1),))


@handles(StepSucceeded)
def on_step_succeeded(run: Run, event: StepSucceeded, wf: Workflow) -> Transition:
    index = _current_step(run, wf, event.key)
    return _enter(run, wf, index + 1, event.key.visit, event.subject)


@handles(StepFailed)
def on_step_failed(run: Run, event: StepFailed, wf: Workflow) -> Transition:
    _current_step(run, wf, event.key)
    key = event.key
    if event.failure_class is FailureClass.TRANSIENT:
        if key.attempt < wf.max_attempts:
            retry = RunStep(run.id, key.stage, visit=key.visit, attempt=key.attempt + 1)
            return Transition(_bump(run), (retry,))
        reason = "attempts_exhausted"
    elif event.failure_class is FailureClass.PERMANENT:
        reason = "permanent_failure"
    else:
        reason = "degraded"
    return Transition(_bump(run.advance(RunStatus.BLOCKED, blocked_reason=reason)))


@handles(GateClosed)
def on_gate_closed(run: Run, event: GateClosed, wf: Workflow) -> Transition:
    if run.status is not RunStatus.WAITING_HUMAN:
        raise _reject(f"gate closed while run is {run.status.value}")
    index = wf.index(event.gate)
    if index is None or wf.nodes[index].kind != "gate" or event.gate != run.stage:
        raise _reject(f"gate {event.gate!r} is not the open gate ({run.stage!r})")
    if event.kind in (DecisionKind.APPROVE, DecisionKind.WAIVE):
        resumed = run.advance(RunStatus.RUNNING)
        return _enter(resumed, wf, index + 1, 1, None)
    if event.kind is DecisionKind.REJECT:
        # WAITING_HUMAN has no edge to REJECTED, so the run resumes first, then ends.
        rejected = _bump(run.advance(RunStatus.RUNNING).advance(RunStatus.REJECTED))
        return Transition(rejected, (Finish(run.id, RunStatus.REJECTED),))
    # request_changes or retest: rerun the stage before the gate as its next visit.
    previous = wf.nodes[index - 1]
    visit = event.round + 1
    rerun = _bump(run.advance(RunStatus.RUNNING), stage=previous.name)
    return Transition(rerun, (RunStep(run.id, previous.name, visit=visit, attempt=1),))


@handles(CancelRequested)
def on_cancel_requested(run: Run, event: CancelRequested, wf: Workflow) -> Transition:
    if run.status.is_terminal or run.status is RunStatus.CANCELLING:
        raise _reject(f"cancel while run is {run.status.value}")
    return Transition(_bump(run.advance(RunStatus.CANCELLING)), (StopRun(run.id),))


@handles(CancelCompleted)
def on_cancel_completed(run: Run, event: CancelCompleted, wf: Workflow) -> Transition:
    if run.status is not RunStatus.CANCELLING:
        raise _reject(f"cancel completed while run is {run.status.value}")
    return Transition(
        _bump(run.advance(RunStatus.CANCELLED)), (Finish(run.id, RunStatus.CANCELLED),)
    )
