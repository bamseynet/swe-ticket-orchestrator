"""Wait and checks stages (D2-13): reducer v1 handlers for ``wait`` and ``checks`` (PLAN 6.2, 7.2).

Entering one parks the run and plans one command, ``AwaitWait`` or ``AwaitChecks``, and that is
all: no step, session or compute runs while it waits. A human-answer wait is ``WAITING_HUMAN``;
an environment wait and a checks stage are ``WAITING_EXTERNAL``. The reducer has no clock, so the
command carries the timeout in seconds and the timer (D2-12) reports ``StageTimedOut``.

Three events end or advance the wait, all tied to the stage's own visit:

* ``WaitResumed``: an answer or a ready environment. A wait follows ``resumed``.
* ``StageTimedOut``: a wait follows ``timeout``. A checks stage has only green and red, and a
  timeout is neither, so it BLOCKS ``checks_timed_out`` (PLAN 6.2: WAITING_EXTERNAL to BLOCKED)
  instead of spending a fix loop on an outage. A ``team_default`` that never resolved blocks
  ``checks_unresolved``.
* ``CheckResults``: a snapshot of the results for the head SHA (the driver reads them from the
  SCM port). Any required check ``failed`` is ``red``; every required check ``passed`` is
  ``green``. Anything else, ``pending`` or not yet reported, is a wait and not a failure: the
  event changes nothing, so no step, loop or version is spent on it. A snapshot is idempotent,
  so a repeat of one that decided nothing is the same no-op.

An event that does not fit the live position is refused with ``OutOfOrderEventError`` and changes
nothing (PLAN 6.1 R4): a run that is not waiting (ended, stopping, BLOCKED), another stage, an
earlier visit, or another head SHA. A decided stage has left its position, so a duplicate or late
result is refused the same way. Results are never trusted for a SHA the run no longer holds, and
a checks stage cannot be entered without a head SHA (``subject_missing``).

``required: team_default`` is resolved by the driver from the team's config, which the pure
reducer does not hold. The command says ``team_default`` and the results carry ``team_required``.
If that is empty the run BLOCKS ``checks_unresolved`` (V13), where it stays on the stage. A stage
with named checks ignores ``team_required``.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from sto.config.schema import ChecksStage, WaitStage, duration_seconds
from sto.config.schema import Workflow as Graph
from sto.domain import BLOCKED_REASONS, COMMANDS, EVENTS, Run, RunId, RunStatus
from sto.engine.handlers.stages import STAGE_ENTRY, StageEntry, _block, _goto, _out, _target, _with
from sto.engine.reducer import MalformedEventError, RunState, Transition, handles_graph

_PASSING = frozenset({"passed", "neutral"})  # neutral counts as passing (PLAN, [S59])
_STATUSES = _PASSING | {"failed", "pending"}


@BLOCKED_REASONS.register("checks_unresolved")
class ChecksUnresolved:
    pass


@BLOCKED_REASONS.register("checks_timed_out")
class ChecksTimedOut:
    pass


@COMMANDS.register("await_wait")
@dataclass(frozen=True)
class AwaitWait:
    """Wait for ``wait_for``; ``timeout_s`` after this the timer reports ``StageTimedOut``."""

    run_id: RunId
    stage: str
    visit: int
    wait_for: str
    timeout_s: int


@COMMANDS.register("await_checks")
@dataclass(frozen=True)
class AwaitChecks:
    """Collect ``source`` results for ``sha``. ``required`` is empty and ``team_default`` true when
    the driver must resolve the team's list."""

    run_id: RunId
    stage: str
    visit: int
    source: str
    sha: str
    required: tuple[str, ...]
    team_default: bool
    timeout_s: int


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # passed | failed | pending


@EVENTS.register("wait.resumed")
@dataclass(frozen=True)
class WaitResumed:
    """An answer arrived or the environment is ready. It carries no responder: who answered is
    authenticated before the event is built, and the reducer takes it as given."""

    run_id: RunId
    stage: str
    visit: int


@EVENTS.register("stage.timed_out")
@dataclass(frozen=True)
class StageTimedOut:
    """The stage's timeout passed. ``team_required`` is, for a ``team_default`` checks stage, the
    list the driver resolved (empty if it never did); it picks the blocked reason."""

    run_id: RunId
    stage: str
    visit: int
    team_required: tuple[str, ...] = ()


@EVENTS.register("check.results")
@dataclass(frozen=True)
class CheckResults:
    """A snapshot of check results for ``sha``. The driver's contract:

    * one entry per check name, the latest run only (re-runs would repeat a name, and the reducer
      refuses a name reported with two statuses);
    * statuses are ``passed``, ``failed``, ``pending`` or ``neutral`` (counts as passing); the
      driver maps GitHub's other conclusions, ``skipped`` included, before sending;
    * ``team_required`` (used only for ``team_default``) is the resolved list and must be the
      same on every snapshot of a visit. RunState has no field to pin the first list, so the
      reducer reads it fresh on each event: a shorter later list could turn green on fewer checks.
    """

    run_id: RunId
    stage: str
    visit: int
    sha: str
    results: tuple[CheckResult, ...]
    team_required: tuple[str, ...] = ()


# --- entering ------------------------------------------------------------------------------


def _refuse(rs: RunState, stage: object) -> str | None:
    if isinstance(stage, ChecksStage) and (rs.subject is None or rs.subject.head_sha is None):
        return "subject_missing"  # checks are tied to a head SHA
    return None


def _enter(rs: RunState, run: Run, name: str, stage: object, count: int) -> Transition:
    if isinstance(stage, WaitStage):
        status = (
            RunStatus.WAITING_HUMAN
            if stage.wait_for == "human_answer"
            else RunStatus.WAITING_EXTERNAL
        )
        cmd: object = AwaitWait(
            run.id, name, count, stage.wait_for, duration_seconds(stage.timeout)
        )
    else:
        assert isinstance(stage, ChecksStage)
        assert rs.subject is not None  # _refuse checked it
        assert rs.subject.head_sha is not None
        named = () if stage.required == "team_default" else tuple(stage.required)
        cmd = AwaitChecks(
            run.id,
            name,
            count,
            stage.source,
            rs.subject.head_sha,
            named,
            stage.required == "team_default",
            duration_seconds(stage.timeout),
        )
        status = RunStatus.WAITING_EXTERNAL
    return Transition(_with(rs, run.advance(status), visit=count, attempt=1, round=0), (cmd,))


STAGE_ENTRY[WaitStage] = StageEntry(_refuse, _enter)
STAGE_ENTRY[ChecksStage] = StageEntry(_refuse, _enter)


# --- the live position ---------------------------------------------------------------------


def _waiting(rs: RunState, wf: Graph, name: str, visit: int) -> WaitStage | ChecksStage:
    run = rs.run
    if run.status not in (RunStatus.WAITING_HUMAN, RunStatus.WAITING_EXTERNAL):
        raise _out(f"wait event while run is {run.status.value}")
    stage = wf.stages.get(run.stage or "")
    if not isinstance(stage, WaitStage | ChecksStage) or name != run.stage:
        raise _out(f"{name!r} is not the stage being waited on ({run.stage!r})")
    if visit != rs.count(name):
        raise _out(f"stale wait event: visit {visit}, live is visit {rs.count(name)}")
    return stage


def _leave(rs: RunState, wf: Graph, stage: WaitStage | ChecksStage, outcome: str) -> Transition:
    if outcome not in stage.next:
        raise MalformedEventError(f"stage {rs.run.stage!r} has no {outcome!r} edge")
    to, loop = _target(stage.next[outcome])
    running = dataclasses.replace(rs, run=rs.run.advance(RunStatus.RUNNING))
    return _goto(running, wf, to, loop)


# --- handlers ------------------------------------------------------------------------------


@handles_graph(WaitResumed)
def on_wait_resumed(rs: RunState, event: WaitResumed, wf: Graph) -> Transition:
    stage = _waiting(rs, wf, event.stage, event.visit)
    if not isinstance(stage, WaitStage):
        raise _out(f"{event.stage!r} is a checks stage: it ends on results or a timeout")
    return _leave(rs, wf, stage, "resumed")


@handles_graph(StageTimedOut)
def on_stage_timed_out(rs: RunState, event: StageTimedOut, wf: Graph) -> Transition:
    stage = _waiting(rs, wf, event.stage, event.visit)
    if isinstance(stage, WaitStage):
        return _leave(rs, wf, stage, "timeout")
    # Checks have only green and red (PLAN 7.2), and a timeout is neither: the run BLOCKS (PLAN 6.2)
    # rather than spend a fix loop on an outage.
    if stage.required == "team_default" and not event.team_required:
        return _block(rs, "checks_unresolved")
    return _block(rs, "checks_timed_out")


@handles_graph(CheckResults)
def on_check_results(rs: RunState, event: CheckResults, wf: Graph) -> Transition:
    stage = _waiting(rs, wf, event.stage, event.visit)
    if not isinstance(stage, ChecksStage):
        raise _out(f"{event.stage!r} is a wait stage: it takes no check results")
    live = rs.subject.head_sha if rs.subject else None
    if event.sha != live:
        raise _out("stale check results: they are not for the live head SHA")
    seen: dict[str, str] = {}
    for r in event.results:
        if r.status not in _STATUSES:
            raise MalformedEventError(f"check {r.name!r} has unknown status {r.status!r}")
        if seen.setdefault(r.name, r.status) != r.status:
            raise MalformedEventError(f"check {r.name!r} is reported with two statuses")
    required = event.team_required if stage.required == "team_default" else tuple(stage.required)
    if not required:
        return _block(rs, "checks_unresolved")
    states = [seen.get(name, "pending") for name in required]
    if "failed" in states:
        return _leave(rs, wf, stage, "red")
    if all(s in _PASSING for s in states):
        return _leave(rs, wf, stage, "green")
    return Transition(rs)  # pending is a wait: nothing moves and nothing is spent
