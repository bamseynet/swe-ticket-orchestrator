"""Core events, blocked reasons and handlers for the linear workflow (D1-02).

Position: ``Run.stage`` names the current node. A step or effect node is current while the run
is RUNNING; a gate node while it is WAITING_HUMAN. ``RunState`` holds the visit, attempt, round
and subject the domain ``Run`` lacks, and every event must match them.

Deferred (not v0): loop caps (D2-06), degraded fail-closed flags (D2-10), closing an open gate
on cancel (D2-11).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from sto.domain import (
    BLOCKED_REASONS,
    EVENTS,
    DecisionId,
    DecisionKind,
    FailureClass,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
)
from sto.engine.commands import Finish, OpenGate, RunEffect, RunStep, StopRun
from sto.engine.reducer import (
    Approval,
    MalformedEventError,
    Node,
    OutOfOrderEventError,
    RunState,
    Transition,
    Workflow,
    handles,
)


@BLOCKED_REASONS.register("attempts_exhausted")
class AttemptsExhausted:
    pass


@BLOCKED_REASONS.register("permanent_failure")
class PermanentFailure:
    pass


@BLOCKED_REASONS.register("effect_failed")
class EffectFailedReason:
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
    """What the decision was made on; ``round`` is the key (a gate has no visit of its own).
    ``subject`` is required for approve and waive (negative
    decisions are exempt from the digest match, PLAN 4 / ADR-0005) and must be the live one."""

    run_id: RunId
    gate: str
    round: int
    kind: DecisionKind
    actor: str
    decision_id: DecisionId
    subject: Subject | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", DecisionKind(self.kind))


@EVENTS.register("effect.confirmed")
@dataclass(frozen=True)
class EffectConfirmed:
    """``visit`` is the effect node's own visit (the ``RunEffect.visit``). ``pr.merge`` must
    report ``merge_sha``. D2-11: this is refused while the run is CANCELLING, so a merge that
    lands during Stop needs handling there (PLAN 6.2 done_with_incident)."""

    run_id: RunId
    effect: str
    visit: int
    merge_sha: str | None = None


@EVENTS.register("effect.failed")
@dataclass(frozen=True)
class EffectFailed:
    """A permanent effect failure: the run BLOCKS (PLAN 6.2). Re-entry on ``gate_invalid`` is D2."""

    run_id: RunId
    effect: str
    visit: int


@EVENTS.register("cancel.requested")
@dataclass(frozen=True)
class CancelRequested:
    run_id: RunId


@EVENTS.register("cancel.completed")
@dataclass(frozen=True)
class CancelCompleted:
    run_id: RunId


def _out(what: str) -> OutOfOrderEventError:
    return OutOfOrderEventError(what)


def _with(rs: RunState, run: Run, **changes: object) -> RunState:
    """New state with the run's version bumped: one accepted event, one version."""
    bumped = dataclasses.replace(run, version=run.version + 1)
    return dataclasses.replace(rs, run=bumped, **changes)  # type: ignore[arg-type]


def _enter(rs: RunState, wf: Workflow, node: Node, subject: Subject | None) -> Transition:
    """Put a RUNNING run on ``node`` and emit its command."""
    run = rs.run
    count = rs.count(node.name) + 1
    visits = tuple(sorted({**dict(rs.visits), node.name: count}.items()))
    if node.kind == "step":
        nxt = _with(
            rs, dataclasses.replace(run, stage=node.name), visit=count, attempt=1, round=0,
            visits=visits,
        )  # fmt: skip
        return Transition(nxt, (RunStep(run.id, node.name, visit=count, attempt=1),))
    if node.kind == "gate":
        if subject is None or subject.head_sha is None or node.gate_type is None:
            raise MalformedEventError(f"gate {node.name!r} needs a head subject")
        waiting = run.advance(RunStatus.WAITING_HUMAN)
        nxt = _with(
            rs, dataclasses.replace(waiting, stage=node.name), round=count, subject=subject,
            visits=visits,
        )  # fmt: skip
        return Transition(nxt, (OpenGate(run.id, node.name, node.gate_type, count, subject),))
    # effect: a gated effect that needs every required gate's live approval.
    assert node.effect is not None
    if rs.subject is None:
        raise _out(f"effect {node.name!r} has no approved subject")
    by_gate = {a.gate: a for a in rs.approvals}
    missing = [g for g in node.requires_gates if g not in by_gate]
    if missing:
        raise _out(f"effect {node.name!r} lacks approval from {missing}")
    digest = rs.subject.digest()
    # D1-07: ``subject_digest`` is QA's subject, so it differs from the review approval's
    # digest (``Approval.subject_digest``); compare approvals by head SHA (PLAN 4.3.2).
    cmd = RunEffect(
        run.id,
        node.effect,
        node.name,
        count,
        rs.subject,
        digest,
        node.requires_gates,
        tuple(by_gate[g].decision_id for g in node.requires_gates),
    )
    nxt = _with(rs, dataclasses.replace(run, stage=node.name), round=0, visits=visits)
    return Transition(nxt, (cmd,))


def _current_step(rs: RunState, wf: Workflow, key: StepKey) -> Node:
    run = rs.run
    if run.status is not RunStatus.RUNNING:
        raise _out(f"step event while run is {run.status.value}")
    node = wf.node(run.stage)
    if node.kind != "step" or key.stage != node.name:
        raise _out(f"step {key.stage!r} is not the current stage ({run.stage!r})")
    if key.visit != rs.visit or key.attempt != rs.attempt:
        raise _out(
            f"stale step event: visit {key.visit} attempt {key.attempt}, "
            f"live is visit {rs.visit} attempt {rs.attempt}"
        )
    return node


@handles(RunStarted)
def on_run_started(rs: RunState, event: RunStarted, wf: Workflow) -> Transition:
    if rs.run.status is not RunStatus.QUEUED:
        raise _out(f"run already started ({rs.run.status.value})")
    running = dataclasses.replace(rs.run.advance(RunStatus.RUNNING), workflow_version=wf.version)
    return _enter(dataclasses.replace(rs, run=running), wf, wf.nodes[0], None)


@handles(StepSucceeded)
def on_step_succeeded(rs: RunState, event: StepSucceeded, wf: Workflow) -> Transition:
    node = _current_step(rs, wf, event.key)
    subject = event.subject
    following = wf.after(node.name)
    if following is None:
        raise _out(f"nothing follows {node.name!r}")
    if following.kind == "gate" and (subject is None or subject.head_sha is None):
        raise MalformedEventError(f"step {node.name!r} must report a head subject for its gate")
    if (
        not node.produces_code
        and subject is not None
        and rs.subject is not None
        and (subject.head_sha, subject.patch_id) != (rs.subject.head_sha, rs.subject.patch_id)
    ):
        raise _out(f"step {node.name!r} reported a different SHA or patch than the reviewed one")
    return _enter(rs, wf, following, subject)


@handles(StepFailed)
def on_step_failed(rs: RunState, event: StepFailed, wf: Workflow) -> Transition:
    _current_step(rs, wf, event.key)
    key = event.key
    if event.failure_class is FailureClass.TRANSIENT:
        if key.attempt < wf.max_attempts:
            retry = RunStep(rs.run.id, key.stage, visit=key.visit, attempt=key.attempt + 1)
            return Transition(_with(rs, rs.run, attempt=key.attempt + 1), (retry,))
        reason = "attempts_exhausted"
    elif event.failure_class is FailureClass.PERMANENT:
        reason = "permanent_failure"
    else:
        reason = "degraded"
    return Transition(_with(rs, rs.run.advance(RunStatus.BLOCKED, blocked_reason=reason)))


@handles(GateClosed)
def on_gate_closed(rs: RunState, event: GateClosed, wf: Workflow) -> Transition:
    run = rs.run
    if run.status is not RunStatus.WAITING_HUMAN:
        raise _out(f"gate closed while run is {run.status.value}")
    node = wf.node(run.stage)
    if node.kind != "gate" or event.gate != node.name:
        raise _out(f"gate {event.gate!r} is not the open gate ({run.stage!r})")
    if event.round != rs.round:
        raise _out(f"stale gate event: round {event.round}, live is round {rs.round}")
    if event.kind not in node.decisions:
        raise MalformedEventError(f"{event.kind.value} is not allowed at {node.name!r}")
    resumed = run.advance(RunStatus.RUNNING)
    if event.kind in (DecisionKind.APPROVE, DecisionKind.WAIVE):
        if event.subject is None:
            raise MalformedEventError(f"{event.kind.value} needs the approved subject")
        if event.subject != rs.subject:
            raise _out("stale approval: the subject is not the live one")
        approval = Approval(node.name, event.round, event.decision_id, event.subject.digest())
        kept = tuple(a for a in rs.approvals if a.gate != node.name) + (approval,)
        following = wf.after(node.name)
        if following is None:
            raise _out(f"nothing follows {node.name!r}")
        return _enter(dataclasses.replace(rs, run=resumed, approvals=kept), wf, following, None)
    if event.kind is DecisionKind.REJECT:
        rejected = resumed.advance(RunStatus.REJECTED)
        return Transition(_with(rs, rejected), (Finish(run.id, RunStatus.REJECTED),))
    if event.kind is DecisionKind.REQUEST_CHANGES:
        # The code will change, so every earlier approval is void and the gates run again.
        cleared = dataclasses.replace(rs, run=resumed, approvals=(), subject=None)
        return _enter(cleared, wf, wf.node(node.on_changes), None)
    # retest: same SHA, so the approvals and subject stay; back to the QA stage.
    return _enter(dataclasses.replace(rs, run=resumed), wf, wf.node(node.on_retest), None)


@handles(EffectConfirmed)
def on_effect_confirmed(rs: RunState, event: EffectConfirmed, wf: Workflow) -> Transition:
    run = rs.run
    if run.status is not RunStatus.RUNNING:
        raise _out(f"effect confirmed while run is {run.status.value}")
    node = wf.node(run.stage)
    if node.kind != "effect" or node.effect != event.effect:
        raise _out(f"effect {event.effect!r} is not the current one")
    if event.visit != rs.count(node.name):
        raise _out("stale effect event")
    if node.effect == "pr.merge" and not (event.merge_sha or "").strip():
        raise MalformedEventError("a pr.merge confirmation must report merge_sha")
    return Transition(_with(rs, run.advance(RunStatus.DONE)), (Finish(run.id, RunStatus.DONE),))


@handles(EffectFailed)
def on_effect_failed(rs: RunState, event: EffectFailed, wf: Workflow) -> Transition:
    run = rs.run
    if run.status is not RunStatus.RUNNING:
        raise _out(f"effect failed while run is {run.status.value}")
    node = wf.node(run.stage)
    if node.kind != "effect" or node.effect != event.effect:
        raise _out(f"effect {event.effect!r} is not the current one")
    if event.visit != rs.count(node.name):
        raise _out("stale effect event")
    return Transition(_with(rs, run.advance(RunStatus.BLOCKED, blocked_reason="effect_failed")))


@handles(CancelRequested)
def on_cancel_requested(rs: RunState, event: CancelRequested, wf: Workflow) -> Transition:
    status = rs.run.status
    if status.is_terminal or status is RunStatus.CANCELLING:
        raise _out(f"cancel while run is {status.value}")
    return Transition(_with(rs, rs.run.advance(RunStatus.CANCELLING)), (StopRun(rs.run.id),))


@handles(CancelCompleted)
def on_cancel_completed(rs: RunState, event: CancelCompleted, wf: Workflow) -> Transition:
    if rs.run.status is not RunStatus.CANCELLING:
        raise _out(f"cancel completed while run is {rs.run.status.value}")
    cancelled = rs.run.advance(RunStatus.CANCELLED)
    return Transition(_with(rs, cancelled), (Finish(rs.run.id, RunStatus.CANCELLED),))
