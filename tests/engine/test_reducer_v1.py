"""D2-06: reducer v1 runs a validated ``Workflow`` (the D2-01 graph model) for agent,
review_panel, gate, effect and terminal stages, with named loops, the step limit and the
visited-gates rule. route is D2-23: entering one blocks the run. wait and checks are D2-13
(tests/engine/test_waits.py).

Fixtures are synthetic. The base workflow is a Kanban-shaped one (merge before QA) so that the
incident rule has something to bite on; it is checked against the D2-03 validator below, because
the reducer relies on a validated workflow and must not be tested on an invalid one.
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
    DecisionId,
    DecisionKind,
    FailureClass,
    GateType,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
)
from sto.engine.commands import Finish, OpenGate, OpenRevert, RunEffect, RunStep, StopRun
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
from sto.engine.handlers.stages import EffectRefused, GateExpired, StageReported
from sto.engine.reducer import (
    GRAPH_HANDLERS,
    LINEAR_V0,
    Approval,
    HandlerRegistry,
    MalformedEventError,
    Merge,
    NoHandlerError,
    OutOfOrderEventError,
    RunState,
    WorkflowMismatchError,
    load_handlers,
    next,
)

load_handlers()

RID = RunId.from_parts(1, bytes(10))
OTHER = RunId.from_parts(2, bytes(10))
K = DecisionKind


def subj(sha: str = "abc", ev: str = "e1") -> Subject:
    return Subject(
        patch_id="p1",
        ticket_revision="r1",
        head_sha=sha,
        evidence_digest=ev,
        attention_digest="a1",
    )


S1, S2 = subj("abc"), subj("def", "e2")
PRE = Subject(patch_id="p1", ticket_revision="r1", base_sha="base")
_ids = iter(range(1, 10_000))


def did() -> DecisionId:
    return DecisionId.from_parts(_ids.__next__(), bytes(10))


def _gate(gtype: str, roles: list[str], nxt: dict[str, Any], **extra: Any) -> dict[str, Any]:
    gate = {
        "type": gtype,
        "eligible_roles": roles,
        "decisions": ["approve", "request_changes", "reject"],
        "decision_surfaces": ["ui"],
        **extra,
    }
    return {"kind": "gate", "gate": gate, "next": nxt}


DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "kanban-flow", "team": "ledger"},
    "limits": {
        "loops": {"fix": 2, "review_loop": 2, "retest": 2, "stale": 1},
        "max_steps_per_run": 50,
        "max_run_age": "30d",
    },
    "start": "implement",
    "stages": {
        "implement": {
            "kind": "agent",
            "agent": "implementer",
            "next": {"ready": "panel", "blocked": "closed"},
        },
        "panel": {
            "kind": "review_panel",
            "reviewers": ["correctness_reviewer"],
            "required": ["correctness_reviewer"],
            "block_on": "high",
            "next": {
                "clean": "review_gate",
                "findings": {"to": "implement", "loop": "fix"},
                "degraded": "review_gate",
            },
        },
        "review_gate": _gate(
            "review",
            ["reviewer"],
            {
                "approved": "merge",
                "changes_requested": {"to": "implement", "loop": "review_loop"},
                "rejected": "rejected_end",
            },
        ),
        "merge": {
            "kind": "effect",
            "effect": "pr.merge",
            "requires_gates": ["review_gate"],
            "next": {
                "done": "qa_agent",
                "conflict": {"to": "implement", "loop": "fix"},
                "stale": {"to": "update", "loop": "stale"},
            },
        },
        "update": {
            "kind": "effect",
            "effect": "pr.update_branch",
            "next": {"done": "panel", "conflict": {"to": "implement", "loop": "fix"}},
        },
        "qa_agent": {
            "kind": "agent",
            "agent": "qa_agent",
            "next": {"pass": "qa_gate", "fail": "qa_gate", "inconclusive": "qa_gate"},
        },
        "qa_gate": _gate(
            "qa",
            ["qa"],
            {
                "approved": "done",
                "changes_requested": {"to": "implement", "loop": "review_loop"},
                "retest": {"to": "qa_agent", "loop": "retest"},
                "rejected": "rejected_end",
                "expired": "expired_end",
            },
            decisions=["approve", "request_changes", "reject", "retest", "waive"],
            timeouts={"expire_after": "3d"},
        ),
        "done": {"kind": "terminal", "result": "done"},
        "closed": {"kind": "terminal", "result": "closed"},
        "rejected_end": {"kind": "terminal", "result": "rejected"},
        "expired_end": {"kind": "terminal", "result": "expired"},
    },
}

ORG: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "waive_allowed": True,
        "mandatory_gate_roles": {
            "pre_push": ["reviewer"],
            "review": ["reviewer"],
            "qa": ["qa", "reviewer"],
        },
        "decision_surfaces": {"review": ["ui", "slack", "github"], "qa": ["ui", "slack"]},
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


def new() -> RunState:
    return RunState(Run(id=RID, team="t"))


def step(rs: RunState, event: Any, w: Graph = W) -> RunState:
    return next(rs, event, w).state


def cmds(rs: RunState, event: Any, w: Graph = W) -> tuple[object, ...]:
    return next(rs, event, w).commands


def started(w: Graph = W) -> RunState:
    return step(new(), RunStarted(RID), w)


def report(
    rs: RunState,
    outcome: str,
    subject: Subject | None = None,
    w: Graph = W,
    *,
    attempt: int | None = None,
) -> RunState:
    key = StepKey(RID, rs.run.stage or "", rs.visit, attempt or rs.attempt)
    return step(rs, StageReported(key, outcome, subject), w)


def close(
    rs: RunState, kind: DecisionKind, subject: Subject | None = None, w: Graph = W
) -> RunState:
    if subject is None and not kind.is_negative and kind is not K.RETEST:
        subject = rs.subject
    return step(rs, GateClosed(RID, rs.run.stage or "", rs.round, kind, "alice", did(), subject), w)


def at_review_gate(w: Graph = W) -> RunState:
    rs = report(started(w), "ready", w=w)  # implement -> panel
    return report(rs, "clean", S1, w)  # panel -> review_gate


def at_merge() -> RunState:
    return close(at_review_gate(), K.APPROVE)


def merged(sha: str = "m1") -> RunState:
    rs = at_merge()
    return step(rs, EffectConfirmed(RID, "pr.merge", rs.count("merge"), sha))  # -> qa_agent


def at_qa_gate() -> RunState:
    return report(merged(), "pass")


def status(rs: RunState) -> tuple[RunStatus, str | None]:
    return rs.run.status, rs.run.stage


# --- the fixture itself --------------------------------------------------------------------


def test_the_base_workflow_passes_the_structural_validator() -> None:
    assert isinstance(W, Graph)  # wf() asserted validate_structure == [] on construction


# --- start, agent, review_panel ------------------------------------------------------------


def test_run_started_enters_the_start_stage_and_pins_the_workflow() -> None:
    t = next(new(), RunStarted(RID), W)
    assert status(t.state) == (RunStatus.RUNNING, "implement")
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=1),)
    assert t.state.run.workflow_version == "kanban-flow"
    assert t.state.run.version == 1  # one accepted event, one version


def test_run_started_twice_is_refused() -> None:
    with pytest.raises(OutOfOrderEventError):
        step(started(), RunStarted(RID))


@pytest.mark.parametrize(
    ("outcome", "stage"),
    [("ready", "panel"), ("blocked", "closed")],
)
def test_each_agent_outcome_follows_its_edge(outcome: str, stage: str) -> None:
    rs = report(started(), outcome)
    assert rs.run.stage == stage


def test_an_agent_outcome_with_no_edge_is_malformed() -> None:
    with pytest.raises(MalformedEventError, match="pass"):
        report(started(), "pass")


def test_an_agent_with_one_edge_accepts_a_plain_step_succeeded() -> None:
    one = wf(
        lambda d: d["stages"].update(
            implement={"kind": "agent", "agent": "notifier", "next": {"done": "done"}}
        ),
        valid=False,  # the rest of the graph is unreachable, which V1 refuses
    )
    t = next(started(one), StepSucceeded(StepKey(RID, "implement", 1, 1)), one)
    assert t.state.run.status is RunStatus.DONE
    assert t.commands == (Finish(RID, RunStatus.DONE),)


def test_a_plain_step_succeeded_is_malformed_when_the_outcome_is_ambiguous() -> None:
    with pytest.raises(MalformedEventError, match="outcome"):
        step(started(), StepSucceeded(StepKey(RID, "implement", 1, 1)))


@pytest.mark.parametrize(
    ("outcome", "stage"),
    [("clean", "review_gate"), ("degraded", "review_gate"), ("findings", "implement")],
)
def test_each_review_panel_outcome_follows_its_edge(outcome: str, stage: str) -> None:
    rs = report(started(), "ready")
    assert report(rs, outcome, S1).run.stage == stage


def test_a_findings_edge_counts_its_named_loop() -> None:
    rs = report(report(started(), "ready"), "findings", S1)
    assert dict(rs.loops) == {"fix": 1}
    assert rs.count("implement") == 2


def test_a_degraded_failure_takes_the_panel_degraded_edge() -> None:
    rs = report(started(), "ready", S1)
    key = StepKey(RID, "panel", 1, 1)
    out = step(rs, StepFailed(key, FailureClass.DEGRADED))
    assert out.run.stage == "review_gate"
    assert out.run.status is RunStatus.WAITING_HUMAN


def test_a_degraded_failure_blocks_a_fail_closed_panel() -> None:
    w = wf(lambda d: d["stages"]["panel"].update(fail_closed=True))
    rs = report(started(w), "ready", w=w)
    out = step(rs, StepFailed(StepKey(RID, "panel", 1, 1), FailureClass.DEGRADED), w)
    assert status(out) == (RunStatus.BLOCKED, "panel")
    assert out.run.blocked_reason == "degraded"
    out = report(rs, "degraded", S1, w)
    assert out.run.blocked_reason == "degraded"


def test_a_degraded_failure_blocks_an_agent_stage() -> None:
    out = step(started(), StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.DEGRADED))
    assert out.run.blocked_reason == "degraded"


def test_a_transient_failure_retries_to_the_attempt_limit_then_blocks() -> None:
    rs = started()
    t = next(rs, StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.TRANSIENT), W)
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=2),)
    assert t.state.attempt == 2
    out = step(t.state, StepFailed(StepKey(RID, "implement", 1, 2), FailureClass.TRANSIENT))
    assert out.run.status is RunStatus.BLOCKED
    assert out.run.blocked_reason == "attempts_exhausted"


def test_a_stage_max_attempts_overrides_the_default() -> None:
    w = wf(lambda d: d["stages"]["implement"].update(max_attempts=3))
    rs = started(w)
    for attempt in (1, 2):
        rs = step(rs, StepFailed(StepKey(RID, "implement", 1, attempt), FailureClass.TRANSIENT), w)
        assert rs.run.status is RunStatus.RUNNING
        assert rs.attempt == attempt + 1
    rs = step(rs, StepFailed(StepKey(RID, "implement", 1, 3), FailureClass.TRANSIENT), w)
    assert rs.run.blocked_reason == "attempts_exhausted"


def test_a_permanent_failure_blocks_at_once() -> None:
    out = step(started(), StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.PERMANENT))
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "permanent_failure")
    assert out.run.stage == "implement"


def test_a_stale_step_event_is_refused_and_changes_nothing() -> None:
    rs = report(started(), "ready")
    with pytest.raises(OutOfOrderEventError):
        step(rs, StageReported(StepKey(RID, "implement", 1, 1), "ready"))  # the old stage
    with pytest.raises(OutOfOrderEventError):
        step(rs, StageReported(StepKey(RID, "panel", 2, 1), "clean", S1))  # wrong visit


def test_a_gate_that_follows_needs_a_head_subject() -> None:
    rs = report(started(), "ready")
    with pytest.raises(MalformedEventError, match="subject"):
        report(rs, "clean")


def test_a_new_head_voids_every_earlier_approval() -> None:
    twin = _twin()  # review gate, then a QA agent, then the QA gate, then the merge
    rs = report(started(twin), "ready", S1, twin)
    rs = close(rs, K.APPROVE, w=twin)  # -> qa
    assert rs.approvals
    out = report(rs, "pass", S2, twin)  # QA reports a different head than the approved one
    assert out.approvals == ()
    assert out.subject == S2


def test_merged_code_cannot_change_so_a_report_of_another_head_is_refused() -> None:
    # P1: QA reports head def after abc was merged, then approves def. Refused at the report.
    with pytest.raises(MalformedEventError, match="merged"):
        report(merged("m1"), "pass", S2)
    assert report(merged("m1"), "pass", S1).run.stage == "qa_gate"  # the merged head is fine


def test_a_qa_approval_of_another_head_does_not_qualify_the_merge() -> None:
    # The same hole, reached with a forged state: the merge was of abc and QA approved def.
    rs = dataclasses.replace(at_qa_gate(), subject=S2)
    t = next(rs, GateClosed(RID, "qa_gate", 1, K.APPROVE, "q", did(), S2), W)
    assert (t.state.run.status, t.state.run.incident) == (RunStatus.DONE, True)
    assert t.commands == (OpenRevert(RID, "m1"), Finish(RID, RunStatus.DONE, incident=True))


def test_only_the_merges_no_qa_approval_covers_get_a_revert() -> None:
    covered = Merge("m2", S2.head_sha)
    rs = dataclasses.replace(at_qa_gate(), subject=S2, merges=(Merge("m1", "abc"), covered))
    t = next(rs, GateClosed(RID, "qa_gate", 1, K.APPROVE, "q", did(), S2), W)
    assert [c for c in t.commands if isinstance(c, OpenRevert)] == [OpenRevert(RID, "m1")]
    assert t.state.run.incident is True


# --- gates ---------------------------------------------------------------------------------


def test_entering_a_gate_waits_for_a_human_and_opens_it() -> None:
    rs = report(started(), "ready")
    t = next(rs, StageReported(StepKey(RID, "panel", 1, 1), "clean", S1), W)
    assert status(t.state) == (RunStatus.WAITING_HUMAN, "review_gate")
    assert t.commands == (OpenGate(RID, "review_gate", GateType.REVIEW, 1, S1),)
    assert t.state.round == 1


@pytest.mark.parametrize(
    ("kind", "stage", "status_"),
    [
        (K.APPROVE, "merge", RunStatus.RUNNING),
        (K.REQUEST_CHANGES, "implement", RunStatus.RUNNING),
        (K.REJECT, "rejected_end", RunStatus.REJECTED),
    ],
)
def test_each_review_gate_decision_follows_its_edge(
    kind: DecisionKind, stage: str, status_: RunStatus
) -> None:
    out = close(at_review_gate(), kind)
    assert out.run.status is status_
    assert out.run.stage == stage


def test_a_gated_effect_command_carries_the_approvals_it_needs() -> None:
    rs = at_review_gate()
    closed = GateClosed(RID, "review_gate", 1, K.APPROVE, "alice", (d := did()), S1)
    t = next(rs, closed, W)
    assert t.commands == (
        RunEffect(RID, "pr.merge", "merge", 1, S1, S1.digest(), ("review_gate",), (d,)),
    )


@pytest.mark.parametrize(
    ("kind", "stage"),
    [
        (K.APPROVE, "done"),
        (K.WAIVE, "done"),
        (K.REQUEST_CHANGES, "implement"),
        (K.RETEST, "qa_agent"),
        (K.REJECT, "rejected_end"),
    ],
)
def test_each_qa_gate_decision_follows_its_edge(kind: DecisionKind, stage: str) -> None:
    out = close(at_qa_gate(), kind)
    assert out.run.stage == stage


def test_an_expired_gate_follows_its_expired_edge() -> None:
    rs = at_qa_gate()
    out = step(rs, GateExpired(RID, "qa_gate", rs.round))
    assert status(out) == (RunStatus.EXPIRED, "expired_end")


def test_expiry_without_an_expired_edge_is_malformed() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError, match="expired"):
        step(rs, GateExpired(RID, "review_gate", rs.round))


def test_a_decision_the_gate_does_not_offer_is_malformed() -> None:
    with pytest.raises(MalformedEventError):
        close(at_review_gate(), K.RETEST)  # the review gate offers no retest
    with pytest.raises(MalformedEventError):
        close(at_review_gate(), K.WAIVE)


def test_an_approval_needs_the_live_subject() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError):
        step(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), None))
    with pytest.raises(OutOfOrderEventError):
        step(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S2))


def test_a_stale_or_misaddressed_gate_event_is_refused() -> None:
    rs = at_review_gate()
    with pytest.raises(OutOfOrderEventError):
        step(rs, GateClosed(RID, "review_gate", 2, K.REJECT, "a", did()))
    with pytest.raises(OutOfOrderEventError):
        step(rs, GateClosed(RID, "qa_gate", 1, K.REJECT, "a", did()))
    with pytest.raises(OutOfOrderEventError):
        step(started(), GateClosed(RID, "review_gate", 1, K.REJECT, "a", did()))


def test_a_gate_round_is_its_own_visit_count() -> None:
    rs = close(at_review_gate(), K.REQUEST_CHANGES)  # -> implement (loop review_loop)
    rs = report(report(rs, "ready"), "clean", S2)
    assert (rs.run.stage, rs.round) == ("review_gate", 2)


def test_request_changes_voids_all_approvals_and_the_subject() -> None:
    rs = close(at_qa_gate(), K.REQUEST_CHANGES)
    assert rs.approvals == ()
    assert rs.subject is None


def test_a_rejected_close_drops_that_gates_approval_only() -> None:
    rs = close(at_qa_gate(), K.RETEST)  # same SHA: the review approval stays
    assert [a.gate for a in rs.approvals] == ["review_gate"]


def test_a_pre_push_gate_takes_a_pre_push_subject_and_a_review_gate_refuses_one() -> None:
    def pre(d: dict[str, Any]) -> None:
        d["stages"]["pre_push_gate"] = _gate(
            "pre_push",
            ["reviewer"],
            {
                "approved": "implement",
                "changes_requested": {"to": "implement", "loop": "fix"},
                "rejected": "rejected_end",
            },
        )
        d["stages"]["implement"]["next"]["ready"] = "pre_push_gate"

    w = wf(pre, valid=False)  # the panel is now unreachable
    t = next(started(w), StageReported(StepKey(RID, "implement", 1, 1), "ready", PRE), w)
    assert t.commands == (OpenGate(RID, "pre_push_gate", GateType.PRE_PUSH, 1, PRE),)
    with pytest.raises(MalformedEventError):  # a head subject for a pre_push gate
        next(started(w), StageReported(StepKey(RID, "implement", 1, 1), "ready", S1), w)
    with pytest.raises(MalformedEventError):  # a pre-push subject for a review gate
        report(report(started(), "ready"), "clean", PRE)


# --- effects -------------------------------------------------------------------------------


def test_effect_done_follows_the_done_edge_and_records_the_merge() -> None:
    rs = merged("m1")
    assert status(rs) == (RunStatus.RUNNING, "qa_agent")
    assert rs.merges == (Merge("m1", S1.head_sha),)


@pytest.mark.parametrize(
    ("outcome", "stage", "loop"),
    [("conflict", "implement", "fix"), ("stale", "update", "stale")],
)
def test_effect_refusals_follow_their_edges_and_count_their_loops(
    outcome: str, stage: str, loop: str
) -> None:
    rs = at_merge()
    out = step(rs, EffectRefused(RID, "pr.merge", rs.count("merge"), outcome))
    assert out.run.stage == stage
    assert dict(out.loops) == {loop: 1}
    assert out.merges == ()


def test_pr_update_branch_has_a_conflict_outcome() -> None:
    rs = at_merge()
    rs = step(rs, EffectRefused(RID, "pr.merge", 1, "stale"))  # -> update (no gates needed)
    t = next(rs, EffectRefused(RID, "pr.update_branch", 1, "conflict"), W)
    assert t.state.run.stage == "implement"
    assert dict(t.state.loops) == {"stale": 1, "fix": 1}
    back = step(rs, EffectConfirmed(RID, "pr.update_branch", 1))
    assert back.run.stage == "panel"


def test_an_effect_outcome_the_stage_has_no_edge_for_is_malformed() -> None:
    rs = at_merge()
    with pytest.raises(MalformedEventError):
        step(rs, EffectRefused(RID, "pr.merge", 1, "nonsense"))
    rs = step(rs, EffectRefused(RID, "pr.merge", 1, "stale"))
    with pytest.raises(MalformedEventError):
        step(rs, EffectRefused(RID, "pr.update_branch", 1, "stale"))  # update has no stale edge


def test_a_merge_confirmation_must_report_the_merge_sha() -> None:
    rs = at_merge()
    with pytest.raises(MalformedEventError, match="merge_sha"):
        step(rs, EffectConfirmed(RID, "pr.merge", 1, None))


def test_a_stale_effect_event_is_refused() -> None:
    rs = at_merge()
    with pytest.raises(OutOfOrderEventError):
        step(rs, EffectConfirmed(RID, "pr.merge", 2, "m"))
    with pytest.raises(OutOfOrderEventError):
        step(rs, EffectConfirmed(RID, "pr.update_branch", 1))
    with pytest.raises(OutOfOrderEventError):
        step(started(), EffectConfirmed(RID, "pr.merge", 1, "m"))


def test_an_effect_failure_blocks_with_effect_failed() -> None:
    rs = at_merge()
    out = step(rs, EffectFailed(RID, "pr.merge", 1))
    assert status(out) == (RunStatus.BLOCKED, "merge")
    assert out.run.blocked_reason == "effect_failed"


def test_the_visited_gates_rule_requires_a_routed_gate_to_be_approved_for_a_gated_effect() -> None:
    # PLAN 6.4 rule 2: a gate reached by a ticket-field route stays required once visited. D2-23
    # adds the route stage that sets ``routed_gates``; the reducer enforces it from now on.
    rs = dataclasses.replace(at_review_gate(), routed_gates=("qa_gate",))
    out = close(rs, K.APPROVE)  # the merge needs review_gate (approved) and qa_gate (not)
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "gate_invalid")
    assert out.run.stage == "review_gate"


def test_a_routed_gate_that_is_approved_lets_the_effect_run() -> None:
    rs = dataclasses.replace(at_review_gate(), routed_gates=("review_gate",))
    t = next(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S1), W)
    assert t.state.run.stage == "merge"
    assert isinstance(t.commands[0], RunEffect)
    assert t.commands[0].requires_gates == ("review_gate",)


def test_a_scoped_effect_needs_no_approval_but_needs_a_subject() -> None:
    rs = step(at_merge(), EffectRefused(RID, "pr.merge", 1, "stale"))
    assert rs.run.stage == "update"
    # ... entered with no live subject at all, it blocks rather than invent one:
    bare = dataclasses.replace(at_merge(), subject=None, approvals=())
    out = step(bare, EffectRefused(RID, "pr.merge", 1, "stale"))
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "subject_missing")


def test_a_confirmed_branch_update_voids_the_approvals_and_the_subject() -> None:
    # P3: the updated branch has a new SHA nobody approved.
    rs = step(at_merge(), EffectRefused(RID, "pr.merge", 1, "stale"))  # -> update
    out = step(rs, EffectConfirmed(RID, "pr.update_branch", 1))
    assert out.run.stage == "panel"
    assert out.approvals == ()
    assert out.subject is None
    with pytest.raises(MalformedEventError, match="subject"):
        report(out, "clean")  # the panel must report the new head before a gate can open
    assert report(out, "clean", S2).run.stage == "review_gate"


def test_an_update_branch_edge_straight_to_the_merge_cannot_merge_the_old_approval() -> None:
    # P3b: the validator accepts update.done -> merge; the merge must not carry the old approval.
    w = wf(lambda d: d["stages"]["update"]["next"].update(done="merge"))
    rs = close(at_review_gate(w), K.APPROVE, w=w)
    rs = step(rs, EffectRefused(RID, "pr.merge", 1, "stale"), w)
    t = next(rs, EffectConfirmed(RID, "pr.update_branch", 1), w)
    assert not any(isinstance(c, RunEffect) for c in t.commands)
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "subject_missing",
    )


def test_the_effect_command_names_the_routed_gates_and_their_decision_ids() -> None:
    qa = Approval("qa_gate", 1, did(), S1.digest(), S1.head_sha)
    rs = dataclasses.replace(at_review_gate(), routed_gates=("qa_gate",), approvals=(qa,))
    d = did()
    t = next(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", d, S1), W)
    (cmd,) = t.commands
    assert isinstance(cmd, RunEffect)
    assert cmd.requires_gates == ("review_gate", "qa_gate")
    assert cmd.decision_ids == (d, qa.decision_id)


def test_a_confirmation_that_is_not_a_refusal_outcome_is_malformed() -> None:
    rs = at_merge()
    with pytest.raises(MalformedEventError, match="not a refusal"):
        step(rs, EffectRefused(RID, "pr.merge", 1, "done"))  # done has an edge, but is no refusal


def test_effect_events_are_refused_while_the_run_is_stopping() -> None:
    rs = step(at_merge(), CancelRequested(RID))
    for event in (
        EffectConfirmed(RID, "pr.merge", 1, "m1"),
        EffectRefused(RID, "pr.merge", 1, "stale"),
        EffectFailed(RID, "pr.merge", 1),
    ):
        with pytest.raises(OutOfOrderEventError):
            step(rs, event)


def test_a_late_event_from_an_older_attempt_is_refused() -> None:
    rs = step(started(), StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.TRANSIENT))
    assert rs.attempt == 2
    with pytest.raises(OutOfOrderEventError, match="attempt"):
        step(rs, StageReported(StepKey(RID, "implement", 1, 1), "ready"))
    with pytest.raises(OutOfOrderEventError, match="attempt"):
        step(rs, StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.PERMANENT))
    assert report(rs, "ready").run.stage == "panel"


def test_a_failure_that_leads_to_a_gate_with_no_subject_blocks_instead_of_hanging() -> None:
    # P2/P9: a degraded panel failure carries no subject, and implement reported none.
    rs = report(started(), "ready")
    out = step(rs, StepFailed(StepKey(RID, "panel", 1, 1), FailureClass.DEGRADED))
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "subject_missing")
    assert out.run.stage == "panel"
    assert out.steps == rs.steps  # the refused gate entry took no step
    assert out.round == rs.round


def test_a_changes_requested_edge_into_a_gate_blocks_because_the_subject_was_voided() -> None:
    # P10: request_changes clears the subject, and this edge goes straight to another gate.
    w = wf(
        lambda d: d["stages"]["review_gate"]["next"].update(
            changes_requested={"to": "qa_gate", "loop": "review_loop"}
        ),
        valid=False,  # the loop now bypasses implement, which other rules refuse
    )
    out = close(at_review_gate(w), K.REQUEST_CHANGES, w=w)
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "subject_missing")
    assert out.approvals == ()


def test_a_stale_qa_approval_does_not_qualify_a_run_whose_qa_gate_then_rejects() -> None:
    # PLAN 4.3 rule 3: a non-approving close drops that gate's approvals.
    stale = Approval("qa_gate", 1, did(), S1.digest(), S1.head_sha)
    rs = dataclasses.replace(at_qa_gate(), approvals=(*at_qa_gate().approvals, stale))
    out = next(rs, GateClosed(RID, "qa_gate", 1, K.REJECT, "q", did()), W)
    assert all(a.gate != "qa_gate" for a in out.state.approvals)
    assert out.state.run.incident is True
    assert OpenRevert(RID, "m1") in out.commands


def test_a_duplicate_merge_sha_plans_one_revert() -> None:
    rs = dataclasses.replace(at_qa_gate(), merges=(Merge("m1", "abc"), Merge("m1", "abc")))
    t = next(rs, GateClosed(RID, "qa_gate", 1, K.REJECT, "q", did()), W)
    assert [c for c in t.commands if isinstance(c, OpenRevert)] == [OpenRevert(RID, "m1")]


# --- loops ---------------------------------------------------------------------------------


def _loop_to_implement(rs: RunState) -> RunState:
    rs = report(rs, "ready")
    return report(rs, "findings", S1)  # panel -> implement via loop "fix"


def test_an_exhausted_loop_blocks_with_loop_exhausted_and_stays_put() -> None:
    rs = started()
    rs = _loop_to_implement(rs)  # fix = 1
    rs = _loop_to_implement(rs)  # fix = 2 (the limit)
    assert dict(rs.loops) == {"fix": 2}
    rs = report(rs, "ready")
    t = next(rs, StageReported(StepKey(RID, "panel", rs.visit, rs.attempt), "findings", S1), W)
    out = t.state
    assert (out.run.status, out.run.blocked_reason) == (RunStatus.BLOCKED, "loop_exhausted")
    assert out.run.stage == "panel"
    assert t.commands == ()
    assert dict(out.loops) == {"fix": 2}  # the refused round is not counted


def test_loops_count_separately_by_name() -> None:
    rs = _loop_to_implement(started())  # fix
    rs = close(report(report(rs, "ready"), "clean", S1), K.REQUEST_CHANGES)  # review_loop
    assert dict(rs.loops) == {"fix": 1, "review_loop": 1}


def test_a_loop_edge_into_a_terminal_still_counts_the_loop() -> None:
    w = wf(
        lambda d: d["stages"]["implement"]["next"].update(blocked={"to": "closed", "loop": "fix"})
    )
    out = report(started(w), "blocked", w=w)
    assert out.run.status is RunStatus.CLOSED
    assert dict(out.loops) == {"fix": 1}


def test_an_edge_without_a_loop_counts_nothing() -> None:
    assert report(started(), "ready").loops == ()


def test_the_exhausted_reason_is_registered() -> None:
    assert BLOCKED_REASONS.get("loop_exhausted") is not None


def test_an_undeclared_loop_fails_closed() -> None:
    # V3 makes this impossible for a validated workflow; the reducer must still not run it free.
    w = wf(lambda d: d["limits"]["loops"].pop("fix"), valid=False)
    rs = report(started(w), "ready", w=w)
    out = report(rs, "findings", S1, w)
    assert out.run.blocked_reason == "loop_exhausted"


# --- max_steps_per_run ---------------------------------------------------------------------


def test_max_steps_per_run_blocks_the_entry_that_would_exceed_it() -> None:
    w = wf(lambda d: d["limits"].update(max_steps_per_run=3))
    rs = started(w)  # entry 1: implement
    rs = report(rs, "ready", w=w)  # entry 2: panel
    rs = report(rs, "clean", S1, w)  # entry 3: review_gate (the limit)
    assert rs.steps == 3
    assert rs.run.status is RunStatus.WAITING_HUMAN
    t = next(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S1), w)  # entry 4
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "max_steps_exceeded",
    )
    assert t.state.run.stage == "review_gate"
    assert t.commands == ()


def test_a_terminal_at_the_limit_is_not_a_step() -> None:
    w = wf(lambda d: d["limits"].update(max_steps_per_run=1))
    out = report(started(w), "blocked", w=w)  # implement (1) -> closed (terminal)
    assert out.run.status is RunStatus.CLOSED


def test_a_loop_that_would_spin_forever_is_stopped_by_the_step_limit() -> None:
    def limits(d: dict[str, Any]) -> None:
        d["limits"].update(max_steps_per_run=6)
        d["limits"]["loops"].update(fix=5)

    w = wf(limits)
    rs = started(w)
    for _ in range(10):
        if rs.run.status is not RunStatus.RUNNING:
            break
        rs = (
            report(rs, "ready", w=w)
            if rs.run.stage == "implement"
            else report(rs, "findings", S1, w)
        )
    assert (rs.run.status, rs.run.blocked_reason) == (RunStatus.BLOCKED, "max_steps_exceeded")
    assert rs.steps == 6


# --- terminals and the incident rule -------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ("done", RunStatus.DONE),
        ("rejected", RunStatus.REJECTED),
        ("closed", RunStatus.CLOSED),
        ("expired", RunStatus.EXPIRED),
        ("done_with_incident", RunStatus.DONE),
    ],
)
def test_each_terminal_result_ends_the_run(result: str, expected: RunStatus) -> None:
    w = wf(lambda d: d["stages"]["closed"].update(result=result))
    t = next(started(w), StageReported(StepKey(RID, "implement", 1, 1), "blocked"), w)
    assert t.state.run.status is expected
    assert t.state.run.incident is (result == "done_with_incident")
    assert t.commands[-1] == Finish(RID, expected, incident=result == "done_with_incident")


def test_a_merged_run_with_a_qa_approval_ends_done_without_an_incident() -> None:
    t = next(at_qa_gate(), GateClosed(RID, "qa_gate", 1, K.APPROVE, "q", did(), S1), W)
    assert t.state.run.status is RunStatus.DONE
    assert t.state.run.incident is False
    assert t.commands == (Finish(RID, RunStatus.DONE),)


def test_a_waived_qa_gate_counts_as_a_qa_approval() -> None:
    out = close(at_qa_gate(), K.WAIVE)
    assert (out.run.status, out.run.incident) == (RunStatus.DONE, False)


def test_a_merged_run_without_a_qa_approval_ends_done_with_incident_and_plans_a_revert() -> None:
    # Kanban: the merge landed; QA then expires. Whichever terminal it reaches, the code stays.
    rs = at_qa_gate()
    w = wf(lambda d: d["stages"]["expired_end"].update(result="done"))
    t = next(rs, GateExpired(RID, "qa_gate", rs.round), w)
    assert t.state.run.status is RunStatus.DONE
    assert t.state.run.incident is True
    assert t.commands == (
        OpenRevert(RID, "m1"),
        Finish(RID, RunStatus.DONE, incident=True),
    )


def test_the_incident_flag_rides_any_terminal() -> None:
    rs = at_qa_gate()
    t = next(rs, GateClosed(RID, "qa_gate", 1, K.REJECT, "q", did()), W)
    assert t.state.run.status is RunStatus.REJECTED
    assert t.state.run.incident is True
    assert t.commands == (OpenRevert(RID, "m1"), Finish(RID, RunStatus.REJECTED, incident=True))


def test_one_revert_is_planned_for_each_unqualified_merge() -> None:
    rs = merged("m1")
    rs = dataclasses.replace(rs, merges=(Merge("m0", "old"), *rs.merges))
    t = next(report(rs, "pass"), GateClosed(RID, "qa_gate", 1, K.REJECT, "q", did()), W)
    assert [c for c in t.commands if isinstance(c, OpenRevert)] == [
        OpenRevert(RID, "m0"),
        OpenRevert(RID, "m1"),
    ]


def test_a_run_that_never_merged_ends_without_an_incident() -> None:
    t = next(at_review_gate(), GateClosed(RID, "review_gate", 1, K.REJECT, "a", did()), W)
    assert (t.state.run.status, t.state.run.incident) == (RunStatus.REJECTED, False)
    assert t.commands == (Finish(RID, RunStatus.REJECTED),)


def test_a_stopped_run_that_merged_unqualified_stays_cancelled_with_the_incident_flag() -> None:
    rs = merged()
    stopping = next(rs, CancelRequested(RID), W)
    assert stopping.commands == (StopRun(RID),)
    t = next(stopping.state, CancelCompleted(RID), W)
    assert t.state.run.status is RunStatus.CANCELLED
    assert t.state.run.incident is True
    assert t.commands == (OpenRevert(RID, "m1"), Finish(RID, RunStatus.CANCELLED, incident=True))


def test_a_stopped_run_that_never_merged_is_cancelled_cleanly() -> None:
    stopping = step(started(), CancelRequested(RID))
    t = next(stopping, CancelCompleted(RID), W)
    assert (t.state.run.status, t.state.run.incident) == (RunStatus.CANCELLED, False)
    assert t.commands == (Finish(RID, RunStatus.CANCELLED),)


def test_an_event_after_the_run_ended_is_refused() -> None:
    done = close(at_qa_gate(), K.APPROVE)
    with pytest.raises(OutOfOrderEventError):
        step(done, StageReported(StepKey(RID, "implement", 1, 1), "ready"))


# --- stage kinds that come later -----------------------------------------------------------


@pytest.mark.parametrize(
    "stage",
    [
        {"kind": "route", "field": "risk", "next": {"default": "panel"}},
    ],
)
def test_a_stage_kind_that_is_not_implemented_yet_blocks_instead_of_being_skipped(
    stage: dict[str, Any],
) -> None:
    def add(d: dict[str, Any]) -> None:
        d["stages"]["later"] = stage
        d["stages"]["implement"]["next"]["ready"] = "later"

    w = wf(add, valid=False)
    t = next(started(w), StageReported(StepKey(RID, "implement", 1, 1), "ready"), w)
    assert (t.state.run.status, t.state.run.blocked_reason) == (
        RunStatus.BLOCKED,
        "stage_unsupported",
    )
    assert t.state.run.stage == "implement"
    assert t.commands == ()
    assert t.state.steps == 1  # the unsupported stage was not entered


# --- the engine contract -------------------------------------------------------------------


def test_next_is_pure_and_does_not_mutate_its_inputs() -> None:
    rs = at_review_gate()
    event = GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S1)
    before = copy.deepcopy(rs)
    a, b = next(rs, event, W), next(rs, event, W)
    assert a == b
    assert rs == before


def test_a_run_pinned_to_another_workflow_is_refused() -> None:
    other = wf(lambda d: d["metadata"].update(name="other-flow"))
    with pytest.raises(WorkflowMismatchError):
        step(started(), StageReported(StepKey(RID, "implement", 1, 1), "ready"), other)


def test_an_event_for_another_run_is_refused() -> None:
    with pytest.raises(OutOfOrderEventError):
        step(started(), StageReported(StepKey(OTHER, "implement", 1, 1), "ready"))


def test_the_new_events_commands_and_reasons_are_registered() -> None:
    for name in ("stage.reported", "gate.expired", "effect.refused"):
        assert EVENTS.get(name) is not None
    assert COMMANDS.get("open_revert") is not None
    for reason in (
        "loop_exhausted",
        "max_steps_exceeded",
        "stage_unsupported",
        "gate_invalid",
        "subject_missing",
    ):
        assert BLOCKED_REASONS.get(reason) is not None


def test_graph_handlers_are_a_separate_registry_from_the_linear_ones() -> None:
    assert GRAPH_HANDLERS.get(StageReported) is not None
    from sto.engine.reducer import HANDLERS

    assert HANDLERS.get(StageReported) is None
    assert HANDLERS.get(StepSucceeded) is not None  # the linear path is untouched


def test_an_event_with_no_graph_handler_is_a_no_handler_error() -> None:
    empty = HandlerRegistry()
    with pytest.raises(NoHandlerError):
        next(new(), RunStarted(RID), W, graph_registry=empty)


# --- no behaviour change: the standard linear flow and its graph twin ----------------------

TWIN: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "linear-v0", "team": "ledger"},
    "limits": {
        "loops": {"human_review": 3, "qa_fix": 3, "retest": 3},
        "max_steps_per_run": 100,
        "max_run_age": "30d",
    },
    "start": "implement",
    "stages": {
        "implement": {
            "kind": "agent",
            "agent": "implementer",
            "next": {"ready": "review_gate", "blocked": "stopped"},
        },
        "review_gate": _gate(
            "review",
            ["reviewer"],
            {
                "approved": "qa",
                "changes_requested": {"to": "implement", "loop": "human_review"},
                "rejected": "stopped",
            },
        ),
        "qa": {
            "kind": "agent",
            "agent": "qa_agent",
            "next": {"pass": "qa_gate", "fail": "qa_gate", "inconclusive": "qa_gate"},
        },
        "qa_gate": _gate(
            "qa",
            ["qa"],
            {
                "approved": "merge",
                "changes_requested": {"to": "implement", "loop": "qa_fix"},
                "retest": {"to": "qa", "loop": "retest"},
                "rejected": "stopped",
            },
            decisions=["approve", "request_changes", "reject", "retest", "waive"],
        ),
        "merge": {
            "kind": "effect",
            "effect": "pr.merge",
            "requires_gates": ["review_gate", "qa_gate"],
            "next": {"done": "done", "conflict": "stopped", "stale": "stopped"},
        },
        "done": {"kind": "terminal", "result": "done"},
        "stopped": {"kind": "terminal", "result": "rejected"},
    },
}


def _twin() -> Graph:
    doc = load_document(yaml.safe_dump(TWIN, sort_keys=False))
    assert isinstance(doc, Graph)
    return doc


def _at(sha: str, ev: str = "e") -> Subject:
    return subj(sha, ev)


# ('step', subject) is the agent step reporting; ('gate', kind) closes the open gate on the live
# subject (negative decisions carry none); ('effect',) confirms the merge; ('fail', class) fails
# the current step; ('effect_fail',) fails the effect; ('cancel',) and ('stopped',) are Stop;
# ('stale',) sends a step event for a visit that is not live and expects both to refuse it.
SEQUENCES: dict[str, list[tuple[Any, ...]]] = {
    "happy": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.APPROVE),
        ("effect",),
    ],
    "review_changes": [
        ("step", _at("a", "rev")),
        ("gate", K.REQUEST_CHANGES),
        ("step", _at("b", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("b", "qa")),
        ("gate", K.APPROVE),
        ("effect",),
    ],
    "qa_retest": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.RETEST),
        ("step", _at("a", "qa2")),
        ("gate", K.APPROVE),
        ("effect",),
    ],
    "qa_waive": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.WAIVE),
        ("effect",),
    ],
    "qa_changes": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.REQUEST_CHANGES),
        ("step", _at("c", "rev")),
        ("gate", K.APPROVE),
    ],
    "review_reject": [("step", _at("a", "rev")), ("gate", K.REJECT)],
    "qa_reject": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.REJECT),
    ],
    "transient_then_ok": [
        ("fail", FailureClass.TRANSIENT),
        ("step", _at("a", "rev")),
        ("gate", K.REJECT),
    ],
    "transient_exhausted": [("fail", FailureClass.TRANSIENT), ("fail", FailureClass.TRANSIENT)],
    "permanent": [("fail", FailureClass.PERMANENT)],
    "degraded": [("fail", FailureClass.DEGRADED)],
    "qa_step_fails": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("fail", FailureClass.PERMANENT),
    ],
    "effect_fails": [
        ("step", _at("a", "rev")),
        ("gate", K.APPROVE),
        ("step", _at("a", "qa")),
        ("gate", K.APPROVE),
        ("effect_fail",),
    ],
    "stop_while_running": [("cancel",), ("stopped",)],
    "stop_at_a_gate": [("step", _at("a", "rev")), ("cancel",), ("stopped",)],
    "stale_events": [("stale",), ("step", _at("a", "rev")), ("stale",)],
}


def _approvals(rs: RunState) -> list[tuple[Any, ...]]:
    """What both paths record. ``head_sha`` is the graph path's own addition (finding 1)."""
    return [(a.gate, a.round, a.decision_id, a.subject_digest) for a in rs.approvals]


@pytest.mark.parametrize("name", list(SEQUENCES))
def test_the_graph_twin_of_linear_v0_emits_the_same_commands_and_statuses(name: str) -> None:
    twin = _twin()
    g = next(new(), RunStarted(RID), twin)
    lin = next(new(), RunStarted(RID), LINEAR_V0)
    assert g.commands == lin.commands
    for item in SEQUENCES[name]:
        ls = lin.state
        stage = ls.run.stage or ""
        key = StepKey(RID, stage, ls.visit, ls.attempt)
        g_event: Any
        l_event: Any
        match item[0]:
            case "step":
                g_event = StageReported(key, "ready" if stage == "implement" else "pass", item[1])
                l_event = StepSucceeded(key, item[1])
            case "gate":
                kind = item[1]
                live = None if kind.is_negative or kind is K.RETEST else ls.subject
                g_event = l_event = GateClosed(RID, stage, ls.round, kind, "alice", did(), live)
            case "effect":
                g_event = l_event = EffectConfirmed(RID, "pr.merge", ls.count("merge"), "m1")
            case "fail":
                g_event = l_event = StepFailed(key, item[1])
            case "effect_fail":
                g_event = l_event = EffectFailed(RID, "pr.merge", ls.count("merge"))
            case "cancel":
                g_event = l_event = CancelRequested(RID)
            case "stopped":
                g_event = l_event = CancelCompleted(RID)
            case "stale":
                late = StepKey(RID, stage, ls.visit + 7, ls.attempt)
                g_event, l_event = StageReported(late, "ready"), StepSucceeded(late)
                with pytest.raises(OutOfOrderEventError):
                    next(g.state, g_event, twin)
                with pytest.raises(OutOfOrderEventError):
                    next(ls, l_event, LINEAR_V0)
                continue
            case other:
                raise AssertionError(other)
        g, lin = next(g.state, g_event, twin), next(ls, l_event, LINEAR_V0)
        assert g.commands == lin.commands
        assert g.state.run.status == lin.state.run.status
        assert g.state.run.blocked_reason == lin.state.run.blocked_reason
        assert g.state.attempt == lin.state.attempt
        assert _approvals(g.state) == _approvals(lin.state)
        assert g.state.subject == lin.state.subject
        assert g.state.visits == lin.state.visits
        if not lin.state.run.status.is_terminal:
            assert g.state.run.stage == lin.state.run.stage


def _apply(rs: RunState, event: Any, w: Any) -> RunState:
    return next(rs, event, w).state


# --- where the graph path legitimately differs from the linear one -------------------------


def test_difference_a_qa_agent_that_changes_the_head_is_refused_by_linear_and_voids_on_graph() -> (
    None
):
    # Linear: a non-code step may not report another SHA (the run is stuck, PLAN 4.3 rule 2 by
    # refusal). Graph: any stage may produce code, so the report is taken and every earlier
    # approval is voided, which is the same rule enforced by loss instead of by refusal.
    twin = _twin()
    other = subj("zzz", "qa")

    def to_qa(w: Any) -> RunState:
        rs = _apply(new(), RunStarted(RID), w)
        rs = _apply(
            rs,
            StepSucceeded(StepKey(RID, "implement", 1, 1), S1)
            if w is LINEAR_V0
            else StageReported(StepKey(RID, "implement", 1, 1), "ready", S1),
            w,
        )
        return _apply(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S1), w)

    qa_key = StepKey(RID, "qa", 1, 1)
    with pytest.raises(OutOfOrderEventError):
        _apply(to_qa(LINEAR_V0), StepSucceeded(qa_key, other), LINEAR_V0)
    out = _apply(to_qa(twin), StageReported(qa_key, "pass", other), twin)
    assert out.approvals == ()  # the review approval of abc cannot reach the merge of zzz
    assert out.subject == other


def test_difference_a_retest_drops_the_qa_gates_own_earlier_approval_on_graph_only() -> None:
    # PLAN 4.3 rule 3: any non-approving close drops that gate's approvals. Linear keeps them
    # (its next approval replaces them anyway); the graph path drops them at the close.
    twin = _twin()
    stale = Approval("qa_gate", 1, did(), S1.digest(), S1.head_sha)

    def at_gate(w: Any) -> RunState:
        rs = _apply(new(), RunStarted(RID), w)
        ok = StepSucceeded(StepKey(RID, "implement", 1, 1), S1)
        ok_g = StageReported(StepKey(RID, "implement", 1, 1), "ready", S1)
        rs = _apply(rs, ok if w is LINEAR_V0 else ok_g, w)
        rs = _apply(rs, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), S1), w)
        qa = StepKey(RID, "qa", 1, 1)
        rs = _apply(
            rs, StepSucceeded(qa, S1) if w is LINEAR_V0 else StageReported(qa, "pass", S1), w
        )
        return dataclasses.replace(rs, approvals=(*rs.approvals, stale))

    retest = GateClosed(RID, "qa_gate", 1, K.RETEST, "q", did())
    assert "qa_gate" in [a.gate for a in _apply(at_gate(LINEAR_V0), retest, LINEAR_V0).approvals]
    assert "qa_gate" not in [a.gate for a in _apply(at_gate(twin), retest, twin).approvals]
