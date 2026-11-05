"""D2-13: ``wait`` and ``checks`` stages as reducer v1 handlers.

Fixtures are synthetic. The workflow is checked against the D2-03 validator, because the reducer
relies on a validated workflow and must not be tested on an invalid one.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from sto.config.manifest import load_manifest
from sto.config.schema import OrgPolicy, load_document
from sto.config.schema import Workflow as Graph
from sto.config.validate_structure import validate_structure
from sto.domain import (
    BLOCKED_REASONS,
    COMMANDS,
    EVENTS,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    from_wire,
    to_wire,
)
from sto.engine.commands import RunStep
from sto.engine.handlers.core import CancelCompleted, CancelRequested, RunStarted
from sto.engine.handlers.stages import StageReported
from sto.engine.handlers.waits import (
    AwaitChecks,
    AwaitWait,
    CheckResult,
    CheckResults,
    StageTimedOut,
    WaitResumed,
)
from sto.engine.reducer import (
    MalformedEventError,
    OutOfOrderEventError,
    RunState,
    load_handlers,
    next,
)

load_handlers()

RID = RunId.from_parts(1, bytes(10))
SHA, SHA2 = "abc", "def"


def subj(sha: str = SHA) -> Subject:
    return Subject(
        patch_id="p1",
        ticket_revision="r1",
        head_sha=sha,
        evidence_digest="e1",
        attention_digest="a1",
    )


DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "wait-flow", "team": "ledger"},
    "limits": {"loops": {"info": 1, "fix": 1}, "max_steps_per_run": 30, "max_run_age": "30d"},
    "start": "implement",
    "stages": {
        "implement": {
            "kind": "agent",
            "agent": "implementer",
            "next": {"ready": "ci", "blocked": "ask"},
        },
        "ask": {
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "2d",
            "next": {"resumed": {"to": "implement", "loop": "info"}, "timeout": "closed"},
        },
        "ci": {
            "kind": "checks",
            "source": "ci",
            "required": ["unit", "lint"],
            "timeout": "45m",
            "next": {"green": "done", "red": {"to": "implement", "loop": "fix"}},
        },
        "done": {"kind": "terminal", "result": "done"},
        "closed": {"kind": "terminal", "result": "closed"},
    },
}

ORG: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "waive_allowed": True,
        "mandatory_gate_roles": {"pre_push": ["reviewer"], "review": ["reviewer"], "qa": ["qa"]},
        "decision_surfaces": {"review": ["ui"], "qa": ["ui"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    },
    "ceilings": {
        "max_steps_per_run": 200,
        "max_run_age": "60d",
        "max_loop": 5,
        "max_stage_duration": "14d",
        "max_run_usd": 50,
    },
}


def wf(mutate: Callable[[dict[str, Any]], None] | None = None, *, valid: bool = True) -> Graph:
    data = copy.deepcopy(DOC)
    if mutate:
        mutate(data)
    doc = load_document(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False))
    assert isinstance(doc, Graph)
    if valid:
        policy = load_document(yaml.safe_dump(ORG, sort_keys=False))
        assert isinstance(policy, OrgPolicy)
        assert validate_structure(doc, manifest=load_manifest(), policy=policy) == []
    return doc


W = wf()


def team_default(d: dict[str, Any]) -> None:
    d["stages"]["ci"]["required"] = "team_default"


def started(w: Graph = W) -> RunState:
    return next(RunState(Run(id=RID, team="t")), RunStarted(RID), w).state


def report(rs: RunState, outcome: str, subject: Subject | None = None, w: Graph = W) -> RunState:
    key = StepKey(RID, rs.run.stage or "", rs.visit, rs.attempt)
    return next(rs, StageReported(key, outcome, subject), w).state


def at_ci(w: Graph = W) -> RunState:
    return report(started(w), "ready", subj(), w)


def at_ask() -> RunState:
    return report(started(), "blocked")


def results(rs: RunState, *pairs: tuple[str, str], sha: str = SHA, **kw: Any) -> CheckResults:
    return CheckResults(
        RID,
        rs.run.stage or "",
        rs.visit,
        sha,
        tuple(CheckResult(n, s) for n, s in pairs),
        **kw,
    )


# --- entering the stages: no compute is held -------------------------------------------------


def test_a_wait_stage_parks_the_run_and_plans_one_wait_with_its_timeout() -> None:
    t = next(started(), StageReported(StepKey(RID, "implement", 1, 1), "blocked"), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.WAITING_HUMAN, "ask")
    assert t.commands == (AwaitWait(RID, "ask", 1, "human_answer", 2 * 86400),)
    assert t.state.steps == 2


def test_an_environment_wait_parks_the_run_as_waiting_external() -> None:
    w = wf(lambda d: d["stages"]["ask"].update(wait_for="environment_ready"))
    rs = report(started(w), "blocked", w=w)
    assert rs.run.status is RunStatus.WAITING_EXTERNAL


def test_a_checks_stage_parks_the_run_and_plans_the_wait_for_the_head_sha() -> None:
    t = next(started(), StageReported(StepKey(RID, "implement", 1, 1), "ready", subj()), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.WAITING_EXTERNAL, "ci")
    assert t.commands == (AwaitChecks(RID, "ci", 1, "ci", SHA, ("unit", "lint"), False, 45 * 60),)


def test_team_default_checks_are_planned_unresolved_for_the_driver_to_resolve() -> None:
    cmd = next(
        started(wf(team_default)),
        StageReported(StepKey(RID, "implement", 1, 1), "ready", subj()),
        wf(team_default),
    ).commands[0]
    assert (cmd.required, cmd.team_default) == ((), True)  # type: ignore[attr-defined]


def test_checks_without_a_head_subject_block_before_any_counter_moves() -> None:
    rs = started()
    t = next(rs, StageReported(StepKey(RID, "implement", 1, 1), "ready"), W)
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "subject_missing",
    )
    assert t.state.run.stage == "implement"
    assert (t.state.steps, t.commands) == (rs.steps, ())


def test_a_wait_after_an_exhausted_loop_blocks_instead_of_waiting() -> None:
    resumed = next(at_ask(), WaitResumed(RID, "ask", 1), W).state  # uses the one `info` loop
    assert resumed.run.stage == "implement"
    again = report(resumed, "blocked")
    assert again.run.status is RunStatus.WAITING_HUMAN
    # a second return would need `info` again
    t = next(again, WaitResumed(RID, "ask", 2), W)
    assert (t.state.run.status, t.state.run.blocked_reason) == (RunStatus.BLOCKED, "loop_exhausted")
    assert t.state.run.stage == "ask"


# --- wait: resume and timeout ----------------------------------------------------------------


def test_an_answer_resumes_along_the_resumed_edge_and_uses_its_loop() -> None:
    t = next(at_ask(), WaitResumed(RID, "ask", 1), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.RUNNING, "implement")
    assert t.state.loop_count("info") == 1
    assert t.commands == (RunStep(RID, "implement", visit=2, attempt=1),)


def test_a_wait_timeout_follows_the_timeout_edge() -> None:
    t = next(at_ask(), StageTimedOut(RID, "ask", 1), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.CLOSED, "closed")


def test_a_duplicate_or_late_answer_changes_nothing() -> None:
    answered = next(at_ask(), WaitResumed(RID, "ask", 1), W).state
    for late in (WaitResumed(RID, "ask", 1), StageTimedOut(RID, "ask", 1)):
        with pytest.raises(OutOfOrderEventError):
            next(answered, late, W)


def test_an_answer_for_an_earlier_visit_is_refused_and_leaves_the_state_alone() -> None:
    rs = at_ask()
    resumed = next(rs, WaitResumed(RID, "ask", 1), W).state
    second = report(resumed, "blocked")  # visit 2 of ask
    before = second
    with pytest.raises(OutOfOrderEventError):
        next(second, WaitResumed(RID, "ask", 1), W)
    assert second == before


def test_a_timeout_cannot_resume_a_wait_it_did_not_target() -> None:
    with pytest.raises(OutOfOrderEventError):
        next(at_ask(), StageTimedOut(RID, "ci", 1), W)


# --- checks: results -------------------------------------------------------------------------


def test_all_required_green_follows_the_green_edge() -> None:
    rs = at_ci()
    t = next(rs, results(rs, ("unit", "passed"), ("lint", "passed"), ("extra", "failed")), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.DONE, "done")


def test_a_failed_required_check_follows_the_red_edge_and_uses_its_loop() -> None:
    rs = at_ci()
    t = next(rs, results(rs, ("unit", "failed"), ("lint", "pending")), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.RUNNING, "implement")
    assert t.state.loop_count("fix") == 1


def test_a_pending_check_is_a_wait_not_a_failure() -> None:
    rs = at_ci()
    for res in (
        results(rs, ("unit", "passed"), ("lint", "pending")),
        results(rs, ("unit", "passed")),  # lint not reported yet
        results(rs),
    ):
        t = next(rs, res, W)
        assert t.state == rs  # nothing moves: no version, no loop, no step
        assert t.commands == ()
        assert t.state.run.status is RunStatus.WAITING_EXTERNAL
        assert t.state.loops == ()


def test_results_arriving_in_pieces_decide_once_every_required_check_is_in() -> None:
    rs = at_ci()
    rs = next(rs, results(rs, ("unit", "passed")), W).state
    t = next(rs, results(rs, ("unit", "passed"), ("lint", "passed")), W)
    assert t.state.run.status is RunStatus.DONE


def test_a_duplicate_result_changes_nothing_before_and_after_the_decision() -> None:
    rs = at_ci()
    partial = results(rs, ("unit", "passed"))
    assert next(rs, partial, W).state == rs
    assert next(next(rs, partial, W).state, partial, W).state == rs
    final = results(rs, ("unit", "passed"), ("lint", "passed"))
    decided = next(rs, final, W).state
    with pytest.raises(OutOfOrderEventError):
        next(decided, final, W)


def test_a_late_result_from_an_earlier_visit_changes_nothing() -> None:
    rs = at_ci()
    red = next(rs, results(rs, ("unit", "failed"), ("lint", "passed")), W).state
    second = report(red, "ready", subj(SHA2))  # ci visit 2, new head
    with pytest.raises(OutOfOrderEventError):
        next(second, results(rs, ("unit", "passed"), ("lint", "passed")), W)
    assert second.run.status is RunStatus.WAITING_EXTERNAL


def test_results_for_another_sha_are_refused() -> None:
    rs = at_ci()
    with pytest.raises(OutOfOrderEventError):
        next(rs, results(rs, ("unit", "passed"), ("lint", "passed"), sha=SHA2), W)


def test_a_result_for_a_stage_that_is_not_checks_is_refused() -> None:
    rs = at_ask()
    with pytest.raises(OutOfOrderEventError):
        next(rs, CheckResults(RID, "ask", 1, SHA, ()), W)


def test_an_unknown_status_or_a_contradicting_pair_is_malformed() -> None:
    rs = at_ci()
    with pytest.raises(MalformedEventError):
        next(rs, results(rs, ("unit", "ok")), W)
    with pytest.raises(MalformedEventError):
        next(rs, results(rs, ("unit", "passed"), ("unit", "failed")), W)


def test_a_checks_timeout_is_not_green_and_follows_the_red_edge() -> None:
    rs = at_ci()
    t = next(rs, StageTimedOut(RID, "ci", 1), W)
    assert (t.state.run.status, t.state.run.stage) == (RunStatus.RUNNING, "implement")
    assert t.state.loop_count("fix") == 1


def test_a_timeout_after_the_checks_decided_changes_nothing() -> None:
    rs = at_ci()
    decided = next(rs, results(rs, ("unit", "passed"), ("lint", "passed")), W).state
    with pytest.raises(OutOfOrderEventError):
        next(decided, StageTimedOut(RID, "ci", 1), W)


# --- team_default ----------------------------------------------------------------------------


def test_team_default_uses_the_checks_the_driver_resolved() -> None:
    w = wf(team_default)
    rs = at_ci(w)
    pending = results(rs, ("smoke", "passed"), team_required=("smoke", "unit"))
    assert next(rs, pending, w).state == rs
    done = results(rs, ("smoke", "passed"), ("unit", "passed"), team_required=("smoke", "unit"))
    assert next(rs, done, w).state.run.status is RunStatus.DONE


def test_team_default_that_resolves_to_no_checks_blocks_with_a_reason() -> None:
    w = wf(team_default)
    rs = at_ci(w)
    t = next(rs, results(rs, ("unit", "passed"), team_required=()), w)
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "checks_unresolved",
    )
    assert t.state.run.stage == "ci"  # it stays on the stage it was waiting at
    assert t.commands == ()


def test_a_stage_with_named_checks_ignores_what_the_event_claims_is_required() -> None:
    rs = at_ci()
    t = next(rs, results(rs, ("unit", "passed"), team_required=("unit",)), W)
    assert t.state == rs  # lint is still required and not in


# --- a closed run ignores results ------------------------------------------------------------


@pytest.mark.parametrize("event", ["result", "timeout", "resume"])
def test_a_run_that_ended_ignores_every_wait_event(event: str) -> None:
    rs = at_ci()
    ended = next(rs, StageTimedOut(RID, "ci", 1), W).state
    ended = next(ended, CancelRequested(RID), W).state
    ended = next(ended, CancelCompleted(RID), W).state
    assert ended.run.status.is_terminal
    ev: Any = {
        "result": results(rs, ("unit", "passed"), ("lint", "passed")),
        "timeout": StageTimedOut(RID, "ci", 1),
        "resume": WaitResumed(RID, "ask", 1),
    }[event]
    with pytest.raises(OutOfOrderEventError):
        next(ended, ev, W)


def test_a_stopping_run_ignores_results_and_timeouts() -> None:
    rs = at_ci()
    stopping = next(rs, CancelRequested(RID), W).state
    for ev in (results(rs, ("unit", "passed"), ("lint", "passed")), StageTimedOut(RID, "ci", 1)):
        with pytest.raises(OutOfOrderEventError):
            next(stopping, ev, W)


def test_a_blocked_run_ignores_results() -> None:
    w = wf(team_default)
    rs = at_ci(w)
    blocked = next(rs, results(rs, team_required=()), w).state
    with pytest.raises(OutOfOrderEventError):
        next(blocked, results(rs, ("unit", "passed"), team_required=("unit",)), w)


# --- purity and registration -----------------------------------------------------------------


def test_next_is_pure_for_the_new_events() -> None:
    rs = at_ci()
    ev = results(rs, ("unit", "passed"), ("lint", "passed"))
    before = copy.deepcopy(rs)
    assert next(rs, ev, W) == next(rs, ev, W)
    assert rs == before


def test_events_commands_and_reasons_are_registered_and_survive_the_wire() -> None:
    for name in ("check.results", "wait.resumed", "stage.timed_out"):
        assert EVENTS.get(name) is not None
    for name in ("await_wait", "await_checks"):
        assert COMMANDS.get(name) is not None
    assert BLOCKED_REASONS.get("checks_unresolved") is not None
    ev = CheckResults(RID, "ci", 1, SHA, (CheckResult("unit", "passed"),), ("unit",))
    cmd = AwaitChecks(RID, "ci", 1, "ci", SHA, ("unit",), False, 60)
    assert from_wire(CheckResults, to_wire(ev)) == ev
    assert from_wire(AwaitChecks, to_wire(cmd)) == cmd


# --- mutation-pass additions -----------------------------------------------------------------


def test_an_event_naming_another_stage_is_refused_even_when_its_visit_number_matches() -> None:
    # `ask` and `ci` both have visit 1 here, so only the stage name tells them apart.
    resumed = next(at_ask(), WaitResumed(RID, "ask", 1), W).state
    rs = report(resumed, "ready", subj())  # ci, after one visit to ask
    assert (rs.run.stage, rs.count("ask"), rs.count("ci")) == ("ci", 1, 1)
    with pytest.raises(OutOfOrderEventError):
        next(rs, StageTimedOut(RID, "ask", 1), W)
    with pytest.raises(OutOfOrderEventError):
        next(rs, WaitResumed(RID, "ask", 1), W)


def test_checks_cannot_be_entered_on_a_subject_with_no_head_sha() -> None:
    pre = Subject(patch_id="p1", ticket_revision="r1", base_sha="base")
    rs = dataclasses.replace(started(), subject=pre)
    t = next(rs, StageReported(StepKey(RID, "implement", 1, 1), "ready"), W)
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "subject_missing",
    )


def test_an_event_of_the_wrong_kind_for_the_stage_is_refused_not_applied() -> None:
    ci = at_ci()
    with pytest.raises(OutOfOrderEventError):
        next(ci, WaitResumed(RID, "ci", 1), W)  # checks end on results or a timeout
    ask = dataclasses.replace(at_ask(), subject=subj())  # a live head, so only the kind differs
    with pytest.raises(OutOfOrderEventError):
        next(ask, CheckResults(RID, "ask", 1, SHA, (CheckResult("unit", "passed"),)), W)


def test_a_workflow_missing_the_edge_an_event_needs_is_malformed_not_a_crash() -> None:
    def drop(d: dict[str, Any]) -> None:
        del d["stages"]["ask"]["next"]["timeout"]

    w = wf(
        drop, valid=False
    )  # the validator would refuse this; the handler still must not raise a KeyError
    rs = report(started(w), "blocked", w=w)
    with pytest.raises(MalformedEventError):
        next(rs, StageTimedOut(RID, "ask", 1), w)
