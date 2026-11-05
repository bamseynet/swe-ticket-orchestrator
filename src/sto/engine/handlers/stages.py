"""Reducer v1 (D2-06): handlers that run a validated graph ``Workflow`` (PLAN 6.1, 7.2).

The structural validator (D2-03) has already proved that every reference resolves, that each
stage has the edges its kind produces, that every cycle names a declared loop, and that an
effect's gates are listed. This module relies on that and does not re-check it. What it still
refuses is a *run-time* fault: an event that does not fit the live position
(``OutOfOrderEventError``), one that is not well formed for the stage it targets
(``MalformedEventError``), and a position the run cannot safely enter, which BLOCKS the run
instead of raising, because a refused event is dropped by the driver and the run would hang:

* ``loop_exhausted``: the edge's named loop is at its cap (PLAN 6.2); an undeclared loop counts as
  exhausted, so a workflow the validator never saw cannot loop free.
* ``max_steps_exceeded``: the entry would exceed ``limits.max_steps_per_run``.
* ``stage_unsupported``: ``route`` stages arrive in D2-23. They are not skipped. (``wait`` and
  ``checks`` are D2-13: ``waits.py`` registers them in ``STAGE_ENTRY``.)
* ``gate_invalid``: a gated effect whose required gate (``requires_gates``, plus every gate in
  ``RunState.routed_gates``, PLAN 4.3 rule 2) has no live approval.
* ``subject_missing``: a gate or an effect with no live subject (of the right shape) to plan
  against. Only a ``StageReported`` or ``StepSucceeded`` that must carry a subject and omits it is
  Malformed; a failure, a request for changes or a confirmed ``pr.update_branch`` can lead to a
  gate with none, and that blocks.

A BLOCKED run stays on the stage it was leaving, and no counter moves for the refused entry. (A
gate close that then blocks has already changed the approvals and subject, as the close does.)

Position, as in core: ``Run.stage`` names the current stage; an agent, panel or effect stage is
current while the run is RUNNING and a gate while it is WAITING_HUMAN. ``RunStarted`` and the
other core events keep their types; their graph handlers are registered here, so ``core.py`` and
the linear path are untouched. Three events are new, because core's carry no outcome:
``StageReported`` (an agent or review panel outcome, with the head subject a later gate will
approve), ``GateExpired`` and ``EffectRefused`` (a merge or branch update that came back
``conflict`` or ``stale``). A plain ``StepSucceeded`` still works on a stage with exactly one
edge. A gate decision maps to an outcome: approve and waive to ``approved``, request_changes to
``changes_requested``, reject to ``rejected``, retest to ``retest``.

Approvals follow PLAN 4.3: a close that is not an approval drops that gate's approvals; a request
for changes drops them all (the code will change); a report of a different head SHA drops them
all, so an approval is never reused on code it did not see; a confirmed ``pr.update_branch`` moves
the head, so it drops them and the subject too, and the new SHA passes a gate again. Each approval
records its ``head_sha``. A merge records the head it merged, and a merge is covered only by a QA
approval (a waive counts) of that head. A run with an uncovered merge ends with ``incident`` set
whichever terminal it reaches, plans one ``OpenRevert`` per uncovered merge SHA, and says so in
``Finish`` (PLAN 6.2). Merged code is immutable: once a merge is recorded a report of any other head
is Malformed. ``workflow_version`` is the workflow's name until D2-07 pins the digest.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sto.config.schema import (
    AgentStage,
    Edge,
    EffectStage,
    GateStage,
    ReviewPanelStage,
    TerminalStage,
)
from sto.config.schema import Workflow as Graph
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
from sto.engine.commands import Finish, OpenGate, OpenRevert, RunEffect, RunStep
from sto.engine.handlers import core
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    EffectConfirmed,
    EffectFailed,
    GateClosed,
    RunStarted,
    StepFailed,
    StepSucceeded,
)
from sto.engine.reducer import (
    Approval,
    MalformedEventError,
    Merge,
    OutOfOrderEventError,
    RunState,
    Transition,
    handles_graph,
)

DEFAULT_MAX_ATTEMPTS = 2  # PLAN 6.2: a stage's ``max_attempts`` defaults to 2

_TERMINAL = {
    "done": RunStatus.DONE,
    "rejected": RunStatus.REJECTED,
    "closed": RunStatus.CLOSED,
    "expired": RunStatus.EXPIRED,
    "done_with_incident": RunStatus.DONE,
}
_DECISION_OUTCOME = {
    DecisionKind.APPROVE: "approved",
    DecisionKind.WAIVE: "approved",
    DecisionKind.REQUEST_CHANGES: "changes_requested",
    DecisionKind.REJECT: "rejected",
    DecisionKind.RETEST: "retest",
}
_REFUSALS = frozenset({"conflict", "stale"})
_MOVES_HEAD = frozenset({"pr.update_branch"})  # a confirmed effect that leaves a new head SHA


@BLOCKED_REASONS.register("loop_exhausted")
class LoopExhausted:
    pass


@BLOCKED_REASONS.register("max_steps_exceeded")
class MaxStepsExceeded:
    pass


@BLOCKED_REASONS.register("stage_unsupported")
class StageUnsupported:
    pass


@BLOCKED_REASONS.register("gate_invalid")
class GateInvalid:
    pass


@BLOCKED_REASONS.register("subject_missing")
class SubjectMissing:
    pass


@EVENTS.register("stage.reported")
@dataclass(frozen=True)
class StageReported:
    """An agent or review panel finished with ``outcome`` (an edge of the stage).

    ``subject`` is the head subject a later gate will approve: required when the stage's edge
    leads to a gate that has none yet, and a different head SHA voids every earlier approval."""

    key: StepKey
    outcome: str
    subject: Subject | None = None

    @property
    def run_id(self) -> RunId:
        return self.key.run_id


@EVENTS.register("gate.expired")
@dataclass(frozen=True)
class GateExpired:
    """The gate's ``expire_after`` passed. It never approves: it follows the ``expired`` edge."""

    run_id: RunId
    gate: str
    round: int


@EVENTS.register("effect.refused")
@dataclass(frozen=True)
class EffectRefused:
    """The effect did not happen and its outcome is ``conflict`` or ``stale`` (PLAN 6.4).
    ``visit`` is the effect stage's own visit, as for ``EffectConfirmed``."""

    run_id: RunId
    effect: str
    visit: int
    outcome: str


def _out(what: str) -> OutOfOrderEventError:
    return OutOfOrderEventError(what)


def _with(rs: RunState, run: Run, **changes: object) -> RunState:
    """New state with the run's version bumped: one accepted event, one version."""
    bumped = dataclasses.replace(run, version=run.version + 1)
    return dataclasses.replace(rs, run=bumped, **changes)  # type: ignore[arg-type]


def _block(rs: RunState, reason: str) -> Transition:
    """BLOCK a RUNNING run where it stands: no command, and no counter moves."""
    return Transition(_with(rs, rs.run.advance(RunStatus.BLOCKED, blocked_reason=reason)))


def _target(edge: str | Edge) -> tuple[str, str | None]:
    return (edge, None) if isinstance(edge, str) else (edge.to, edge.loop)


def _inc(pairs: tuple[tuple[str, int], ...], key: str) -> tuple[tuple[str, int], ...]:
    counts = dict(pairs)
    counts[key] = counts.get(key, 0) + 1
    return tuple(sorted(counts.items()))


_SUPPORTED = (AgentStage, ReviewPanelStage, GateStage, EffectStage, TerminalStage)


@dataclass(frozen=True)
class StageEntry:
    """How a stage kind defined in another handler module is entered (D2-13 wait and checks).

    ``refuse`` runs with the other entry checks, before any counter moves, and returns a blocked
    reason or ``None``. ``enter`` runs once the visit is counted and returns the transition."""

    refuse: Callable[[RunState, Any], str | None]
    enter: Callable[[RunState, Run, str, Any, int], Transition]


STAGE_ENTRY: dict[type, StageEntry] = {}


# --- entering a stage and ending the run ---------------------------------------------------


def _goto(rs: RunState, wf: Graph, name: str, loop: str | None = None) -> Transition:
    """Move a RUNNING run onto stage ``name``, over ``loop`` if the edge names one.

    Every refusal is decided before any counter moves, so a BLOCKED run is exactly as it was."""
    stage = wf.stages[name]
    entry = STAGE_ENTRY.get(type(stage))
    if entry is None and not isinstance(stage, _SUPPORTED):
        return _block(rs, "stage_unsupported")
    if loop is not None and rs.loop_count(loop) >= wf.limits.loops.get(loop, 0):
        return _block(rs, "loop_exhausted")
    if isinstance(stage, TerminalStage):  # reaching the end is not a step
        counted = dataclasses.replace(rs, loops=_inc(rs.loops, loop)) if loop else rs
        run = dataclasses.replace(counted.run, stage=name)
        return _end(dataclasses.replace(counted, run=run), wf, _TERMINAL[stage.result],
                    flagged=stage.result == "done_with_incident")  # fmt: skip
    if rs.steps >= wf.limits.max_steps_per_run:
        return _block(rs, "max_steps_exceeded")
    if entry is not None and (why := entry.refuse(rs, stage)) is not None:
        return _block(rs, why)
    approvals: dict[str, Approval] = {}
    needed: tuple[str, ...] = ()
    if isinstance(stage, GateStage) and not _fits(stage, rs.subject):
        return _block(rs, "subject_missing")
    if isinstance(stage, EffectStage):
        if rs.subject is None:
            return _block(rs, "subject_missing")
        gates = tuple(stage.requires_gates or ())
        # A gated effect also needs every gate a ticket-field route reached (PLAN 4.3 rule 2).
        needed = (*gates, *(g for g in rs.routed_gates if gates and g not in gates))
        approvals = {a.gate: a for a in rs.approvals}
        if any(g not in approvals for g in needed):
            return _block(rs, "gate_invalid")
    rs = dataclasses.replace(
        rs,
        steps=rs.steps + 1,
        visits=_inc(rs.visits, name),
        loops=_inc(rs.loops, loop) if loop else rs.loops,
    )
    count = rs.count(name)
    run = dataclasses.replace(rs.run, stage=name)
    if entry is not None:
        return entry.enter(rs, run, name, stage, count)
    if isinstance(stage, GateStage):
        return _open_gate(rs, run, name, stage, count)
    if isinstance(stage, EffectStage):
        assert rs.subject is not None
        # The claim re-checks every gate the command names, so it names the routed ones too.
        cmd = RunEffect(
            run.id,
            stage.effect,
            name,
            count,
            rs.subject,
            rs.subject.digest(),
            needed,
            tuple(approvals[g].decision_id for g in needed),
        )
        return Transition(_with(rs, run, round=0), (cmd,))
    nxt = _with(rs, run, visit=count, attempt=1, round=0)
    return Transition(nxt, (RunStep(run.id, name, visit=count, attempt=1),))


def _fits(stage: GateStage, subject: Subject | None) -> bool:
    """A gate takes a head subject, except ``pre_push``, which takes the pre-push one."""
    if subject is None:
        return False
    return (GateType(stage.gate.type) is GateType.PRE_PUSH) == (subject.head_sha is None)


def _open_gate(rs: RunState, run: Run, name: str, stage: GateStage, count: int) -> Transition:
    assert rs.subject is not None  # _goto checked it before any counter moved
    waiting = run.advance(RunStatus.WAITING_HUMAN)
    return Transition(
        _with(rs, waiting, round=count),
        (OpenGate(run.id, name, GateType(stage.gate.type), count, rs.subject),),
    )


def _uncovered(rs: RunState, wf: Graph) -> tuple[Merge, ...]:
    """The merges no standing QA approval covers: a QA gate's approval (a waive records one) of the
    merged head. An approval of any other head does not qualify code it never saw."""
    qa_heads = {
        a.head_sha
        for a in rs.approvals
        if isinstance(stage := wf.stages.get(a.gate), GateStage) and stage.gate.type == "qa"
    }
    return tuple(m for m in rs.merges if m.head_sha is None or m.head_sha not in qa_heads)


def _end(rs: RunState, wf: Graph, status: RunStatus, *, flagged: bool = False) -> Transition:
    """End the run. Merged code no QA approval covers makes it an incident whichever terminal it
    reaches, Stop included, and plans one revert per such merge SHA (PLAN 6.2, 6.3)."""
    uncovered = _uncovered(rs, wf)
    incident = flagged or bool(uncovered)
    run = rs.run.advance(status, incident=incident)
    shas = tuple(dict.fromkeys(m.sha for m in uncovered))
    reverts = tuple(OpenRevert(rs.run.id, sha) for sha in shas)
    return Transition(_with(rs, run), (*reverts, Finish(rs.run.id, status, incident)))


def _close(
    rs: RunState,
    wf: Graph,
    name: str,
    outcome: str,
    approval: Approval | None = None,
) -> Transition:
    """Close the WAITING_HUMAN gate ``name`` with ``outcome`` and follow the edge.

    Only an approval keeps this gate's approval (a new one replaces it); any other close drops
    it (PLAN 4.3 rule 3). A request for changes drops them all, because the code will change."""
    stage = wf.stages[name]
    assert isinstance(stage, GateStage)
    kept = tuple(a for a in rs.approvals if a.gate != name)
    if approval is not None:
        kept = (*kept, approval)
    state = dataclasses.replace(rs, run=rs.run.advance(RunStatus.RUNNING), approvals=kept)
    if outcome == "changes_requested":
        state = dataclasses.replace(state, approvals=(), subject=None)
    to, loop = _target(stage.next[outcome])
    return _goto(state, wf, to, loop)


# --- handlers ------------------------------------------------------------------------------


def _step_stage(rs: RunState, wf: Graph, key: StepKey) -> AgentStage | ReviewPanelStage:
    run = rs.run
    if run.status is not RunStatus.RUNNING:
        raise _out(f"step event while run is {run.status.value}")
    stage = wf.stages.get(run.stage or "")
    if not isinstance(stage, AgentStage | ReviewPanelStage) or key.stage != run.stage:
        raise _out(f"step {key.stage!r} is not the current stage ({run.stage!r})")
    if key.visit != rs.visit or key.attempt != rs.attempt:
        raise _out(
            f"stale step event: visit {key.visit} attempt {key.attempt}, "
            f"live is visit {rs.visit} attempt {rs.attempt}"
        )
    return stage


def _report(
    rs: RunState,
    wf: Graph,
    stage: AgentStage | ReviewPanelStage,
    outcome: str,
    subject: Subject | None,
    *,
    strict: bool = True,
) -> Transition:
    """Follow ``outcome``. ``strict`` (a reporter's own event) makes a missing subject for the
    next gate Malformed; a failure has no subject to give, and blocks at gate entry instead."""
    if outcome not in stage.next:
        raise MalformedEventError(
            f"stage {rs.run.stage!r} has no {outcome!r} outcome; it has: {', '.join(stage.next)}"
        )
    if isinstance(stage, ReviewPanelStage) and outcome == "degraded" and stage.fail_closed:
        return _block(rs, "degraded")
    if subject is not None:
        live = rs.subject
        if rs.merges and subject.head_sha not in {m.head_sha for m in rs.merges}:
            raise MalformedEventError("merged code cannot change: report the merged head")
        moved = live is not None and live.head_sha is not None and live.head_sha != subject.head_sha
        rs = dataclasses.replace(rs, subject=subject, approvals=() if moved else rs.approvals)
    to, loop = _target(stage.next[outcome])
    nxt = wf.stages[to]
    if strict and isinstance(nxt, GateStage) and not _fits(nxt, rs.subject):
        want = "a pre-push" if GateType(nxt.gate.type) is GateType.PRE_PUSH else "a head"
        raise MalformedEventError(f"stage {rs.run.stage!r} must report {want} subject for {to!r}")
    return _goto(rs, wf, to, loop)


@handles_graph(RunStarted)
def on_run_started(rs: RunState, event: RunStarted, wf: Graph) -> Transition:
    if rs.run.status is not RunStatus.QUEUED:
        raise _out(f"run already started ({rs.run.status.value})")
    running = dataclasses.replace(
        rs.run.advance(RunStatus.RUNNING), workflow_version=wf.metadata.name
    )
    return _goto(dataclasses.replace(rs, run=running), wf, wf.start)


@handles_graph(StageReported)
def on_stage_reported(rs: RunState, event: StageReported, wf: Graph) -> Transition:
    stage = _step_stage(rs, wf, event.key)
    return _report(rs, wf, stage, event.outcome, event.subject)


@handles_graph(StepSucceeded)
def on_step_succeeded(rs: RunState, event: StepSucceeded, wf: Graph) -> Transition:
    stage = _step_stage(rs, wf, event.key)
    if len(stage.next) != 1:
        raise MalformedEventError(
            f"stage {event.key.stage!r} has {len(stage.next)} outcomes: "
            "report one with StageReported"
        )
    return _report(rs, wf, stage, next(iter(stage.next)), event.subject)


@handles_graph(StepFailed)
def on_step_failed(rs: RunState, event: StepFailed, wf: Graph) -> Transition:
    stage = _step_stage(rs, wf, event.key)
    key = event.key
    if event.failure_class is FailureClass.TRANSIENT:
        limit = getattr(stage, "max_attempts", None) or DEFAULT_MAX_ATTEMPTS
        if key.attempt < limit:
            retry = RunStep(rs.run.id, key.stage, visit=key.visit, attempt=key.attempt + 1)
            return Transition(_with(rs, rs.run, attempt=key.attempt + 1), (retry,))
        return _block(rs, "attempts_exhausted")
    if event.failure_class is FailureClass.PERMANENT:
        return _block(rs, "permanent_failure")
    # degraded: a review panel opens its gate with the flag, unless it fails closed (PLAN 6.2)
    if isinstance(stage, ReviewPanelStage) and not stage.fail_closed and "degraded" in stage.next:
        return _report(rs, wf, stage, "degraded", None, strict=False)
    return _block(rs, "degraded")


def _open_gate_stage(rs: RunState, wf: Graph, gate: str, round_: int) -> GateStage:
    run = rs.run
    if run.status is not RunStatus.WAITING_HUMAN:
        raise _out(f"gate closed while run is {run.status.value}")
    stage = wf.stages.get(run.stage or "")
    if not isinstance(stage, GateStage) or gate != run.stage:
        raise _out(f"gate {gate!r} is not the open gate ({run.stage!r})")
    if round_ != rs.round:
        raise _out(f"stale gate event: round {round_}, live is round {rs.round}")
    return stage


@handles_graph(GateClosed)
def on_gate_closed(rs: RunState, event: GateClosed, wf: Graph) -> Transition:
    stage = _open_gate_stage(rs, wf, event.gate, event.round)
    kind, outcome = event.kind, _DECISION_OUTCOME[event.kind]
    if kind.value not in stage.gate.decisions or outcome not in stage.next:
        raise MalformedEventError(f"{kind.value} is not allowed at {event.gate!r}")
    approval = None
    if kind in (DecisionKind.APPROVE, DecisionKind.WAIVE):
        if event.subject is None:
            raise MalformedEventError(f"{kind.value} needs the approved subject")
        if event.subject != rs.subject:
            raise _out("stale approval: the subject is not the live one")
        approval = Approval(
            event.gate,
            event.round,
            event.decision_id,
            event.subject.digest(),
            event.subject.head_sha,
        )
    return _close(rs, wf, event.gate, outcome, approval)


@handles_graph(GateExpired)
def on_gate_expired(rs: RunState, event: GateExpired, wf: Graph) -> Transition:
    stage = _open_gate_stage(rs, wf, event.gate, event.round)
    if "expired" not in stage.next:
        raise MalformedEventError(f"gate {event.gate!r} has no expired edge, so it cannot expire")
    return _close(rs, wf, event.gate, "expired")


def _effect_stage(rs: RunState, wf: Graph, effect: str, visit: int) -> EffectStage:
    run = rs.run
    if run.status is not RunStatus.RUNNING:
        raise _out(f"effect event while run is {run.status.value}")
    stage = wf.stages.get(run.stage or "")
    if not isinstance(stage, EffectStage) or stage.effect != effect:
        raise _out(f"effect {effect!r} is not the current one")
    if visit != rs.count(run.stage or ""):
        raise _out("stale effect event")
    return stage


def _follow(rs: RunState, wf: Graph, stage: EffectStage, outcome: str) -> Transition:
    if outcome not in stage.next:
        raise MalformedEventError(f"effect {stage.effect!r} has no {outcome!r} outcome")
    to, loop = _target(stage.next[outcome])
    return _goto(rs, wf, to, loop)


@handles_graph(EffectConfirmed)
def on_effect_confirmed(rs: RunState, event: EffectConfirmed, wf: Graph) -> Transition:
    stage = _effect_stage(rs, wf, event.effect, event.visit)
    if stage.effect == "pr.merge":
        sha = (event.merge_sha or "").strip()
        if not sha:
            raise MalformedEventError("a pr.merge confirmation must report merge_sha")
        head = rs.subject.head_sha if rs.subject else None
        rs = dataclasses.replace(rs, merges=(*rs.merges, Merge(sha, head)))
    if stage.effect in _MOVES_HEAD:
        # The new SHA was never approved: it passes through the gates again (PLAN 4.3 rule 2).
        rs = dataclasses.replace(rs, approvals=(), subject=None)
    return _follow(rs, wf, stage, "done")


@handles_graph(EffectRefused)
def on_effect_refused(rs: RunState, event: EffectRefused, wf: Graph) -> Transition:
    stage = _effect_stage(rs, wf, event.effect, event.visit)
    if event.outcome not in _REFUSALS:
        raise MalformedEventError(f"{event.outcome!r} is not a refusal; use conflict or stale")
    return _follow(rs, wf, stage, event.outcome)


@handles_graph(EffectFailed)
def on_effect_failed(rs: RunState, event: EffectFailed, wf: Graph) -> Transition:
    _effect_stage(rs, wf, event.effect, event.visit)
    return _block(rs, "effect_failed")


handles_graph(CancelRequested)(core.on_cancel_requested)  # it never reads the workflow


@handles_graph(CancelCompleted)
def on_cancel_completed(rs: RunState, event: CancelCompleted, wf: Graph) -> Transition:
    if rs.run.status is not RunStatus.CANCELLING:
        raise _out(f"cancel completed while run is {rs.run.status.value}")
    return _end(rs, wf, RunStatus.CANCELLED)
