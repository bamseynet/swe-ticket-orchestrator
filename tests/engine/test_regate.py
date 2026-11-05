"""D2-28: an effect voided with ``gate_invalid`` returns the run to the first invalid gate.

Reuses the D2-06 workflow fixture (loaded by path, as in ``test_failures.py``), with a second
review gate in front of the merge so that "first" has something to decide.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sto.domain import DecisionKind, RunStatus, Subject
from sto.engine.commands import OpenGate, RunEffect
from sto.engine.handlers.core import EffectConfirmed, EffectFailed, GateClosed
from sto.engine.handlers.failures import describe_retry
from sto.engine.handlers.regate import (
    REGATE_BLOCK,
    EffectDisposed,
    on_effect_disposed,
)
from sto.engine.reducer import (
    GRAPH_HANDLERS,
    Approval,
    HandlerRegistry,
    NoHandlerError,
    OutOfOrderEventError,
    RunState,
    next,
)


def _fixtures() -> Any:
    name = "_sto_reducer_v1_fixtures"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, Path(__file__).with_name("test_reducer_v1.py")
        )
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


_fx = _fixtures()
RID: Any = _fx.RID
S1: Any = _fx.S1
PRE: Any = _fx.PRE
DOC: Any = _fx.DOC
K = DecisionKind
step: Callable[..., RunState] = _fx.step
status: Callable[[RunState], tuple[RunStatus, str | None]] = _fx.status
report: Callable[..., RunState] = _fx.report
close: Callable[..., RunState] = _fx.close
started: Callable[..., RunState] = _fx.started
did: Callable[[], Any] = _fx.did


def _two_gates(d: dict[str, Any]) -> None:
    """implement, panel, review_gate, sec_gate, merge. The merge lists its gates in reverse."""
    stages = d["stages"]
    stages["review_gate"]["next"]["approved"] = "sec_gate"
    stages["sec_gate"] = _fx._gate(
        "review",
        ["reviewer"],
        {
            "approved": "merge",
            "changes_requested": {"to": "implement", "loop": "review_loop"},
            "rejected": "rejected_end",
        },
    )
    stages["merge"]["requires_gates"] = ["sec_gate", "review_gate"]


W: Any = _fx.wf(_two_gates)


def edited(subject: Subject = S1) -> Subject:
    """The same head after the ticket was edited: only the ticket revision moves."""
    return dataclasses.replace(subject, ticket_revision="r2")


def at_merge2() -> RunState:
    rs = report(started(W), "ready", w=W)
    rs = report(rs, "clean", S1, W)  # -> review_gate
    rs = close(rs, K.APPROVE, w=W)  # -> sec_gate
    assert rs.run.stage == "sec_gate"
    rs = close(rs, K.APPROVE, w=W)  # -> merge
    assert status(rs) == (RunStatus.RUNNING, "merge")
    return rs


def void(rs: RunState, **over: Any) -> EffectDisposed:
    base: dict[str, Any] = {
        "run_id": RID,
        "effect": "pr.merge",
        "visit": rs.count("merge"),
        "reason": "gate_invalid",
        "subject": edited(),
        "run_version": rs.run.version,
    }
    return EffectDisposed(**{**base, **over})


def regate(rs: RunState, **over: Any) -> Any:
    return next(rs, void(rs, **over), W)


# --- the return -----------------------------------------------------------------------------


def test_a_voided_effect_returns_to_the_first_gate_whose_approval_no_longer_holds() -> None:
    rs = at_merge2()
    t = regate(rs)
    assert status(t.state) == (RunStatus.WAITING_HUMAN, "review_gate")  # not sec_gate, not merge
    (cmd,) = t.commands
    assert cmd == OpenGate(RID, "review_gate", cmd.type, 2, edited())
    assert t.state.subject == edited()
    assert t.state.round == 2


def test_first_means_workflow_order_not_requires_gates_order_or_approval_order() -> None:
    rs = at_merge2()
    assert [a.gate for a in rs.approvals] == ["review_gate", "sec_gate"]
    reordered = dataclasses.replace(rs, approvals=tuple(reversed(rs.approvals)))
    t = regate(reordered)
    assert t.state.run.stage == "review_gate"  # the merge lists sec_gate first


def test_a_gate_whose_approval_still_holds_is_not_reopened() -> None:
    rs = at_merge2()
    now = edited()
    keep = dataclasses.replace(rs.approvals[0], subject_digest=now.digest())
    only_sec_stale = dataclasses.replace(rs, approvals=(keep, rs.approvals[1]))
    t = regate(only_sec_stale)
    assert status(t.state) == (RunStatus.WAITING_HUMAN, "sec_gate")
    assert [a.gate for a in t.state.approvals] == ["review_gate"]  # kept: it still holds


def test_a_missing_approval_is_an_approval_that_does_not_hold() -> None:
    rs = at_merge2()
    now = edited()
    held = dataclasses.replace(rs.approvals[0], subject_digest=now.digest())
    t = regate(dataclasses.replace(rs, approvals=(held,)))  # sec_gate has none
    assert t.state.run.stage == "sec_gate"


def test_an_approval_of_another_head_does_not_hold_even_with_the_right_digest() -> None:
    rs = at_merge2()
    now = edited()
    a0, a1 = rs.approvals
    held = dataclasses.replace(a0, subject_digest=now.digest(), head_sha=now.head_sha)
    wrong = dataclasses.replace(a1, subject_digest=now.digest(), head_sha="elsewhere")
    t = regate(dataclasses.replace(rs, approvals=(held, wrong)))
    assert t.state.run.stage == "sec_gate"


def test_a_routed_gate_is_judged_too() -> None:
    rs = at_merge2()
    now = edited()
    both = tuple(dataclasses.replace(a, subject_digest=now.digest()) for a in rs.approvals)
    routed = dataclasses.replace(rs, approvals=both, routed_gates=("qa_gate",))
    t = regate(routed)
    assert status(t.state) == (RunStatus.WAITING_HUMAN, "qa_gate")


def test_the_gate_is_found_from_state_alone_the_event_names_none() -> None:
    names = {f.name for f in dataclasses.fields(EffectDisposed)}
    assert names == {"run_id", "effect", "visit", "reason", "subject", "run_version"}


def test_a_new_head_voids_every_approval_so_the_first_gate_is_the_first() -> None:
    rs = at_merge2()
    t = regate(rs, subject=_fx.subj("def", "e2"))
    assert t.state.run.stage == "review_gate"
    assert t.state.approvals == ()


def test_the_effect_stage_is_left_with_an_unchanged_visit_and_the_gate_gets_a_new_round() -> None:
    rs = at_merge2()
    t = regate(rs)
    assert t.state.count("review_gate") == 2
    assert t.state.count("merge") == rs.count("merge")
    assert t.state.run.version == rs.run.version + 1


def test_after_the_new_round_the_run_goes_forward_through_the_graph_again() -> None:
    rs = regate(at_merge2()).state
    rs = close(rs, K.APPROVE, w=W)  # review_gate round 2
    assert rs.run.stage == "sec_gate"  # the stale sec_gate approval was dropped, so it asks again
    rs = close(rs, K.APPROVE, w=W)
    assert status(rs) == (RunStatus.RUNNING, "merge")
    out = next(rs, EffectConfirmed(RID, "pr.merge", rs.count("merge"), "m1"), W)
    assert out.state.run.stage == "qa_agent"


def test_the_next_merge_is_planned_with_the_new_subject_and_a_new_visit() -> None:
    rs = regate(at_merge2()).state
    rs = close(rs, K.APPROVE, w=W)
    t = next(
        rs,
        GateClosed(RID, "sec_gate", rs.round, K.APPROVE, "alice", did(), rs.subject),
        W,
    )
    (cmd,) = t.commands
    assert isinstance(cmd, RunEffect)
    assert cmd.subject == edited()
    assert cmd.visit == 2


# --- no counter moves, max_steps ------------------------------------------------------------


def test_no_loop_counter_moves() -> None:
    rs = at_merge2()
    spent = dataclasses.replace(rs, loops=(("fix", 2), ("review_loop", 1)))
    t = regate(spent)
    assert t.state.loops == spent.loops
    assert t.state.merges == spent.merges


def test_a_spent_loop_does_not_stop_the_return() -> None:
    rs = at_merge2()
    spent = dataclasses.replace(
        rs, loops=(("fix", 2), ("review_loop", 2), ("retest", 2), ("stale", 1))
    )
    assert status(regate(spent).state) == (RunStatus.WAITING_HUMAN, "review_gate")


def test_the_return_counts_one_step() -> None:
    rs = at_merge2()
    assert regate(rs).state.steps == rs.steps + 1


def test_max_steps_is_respected_and_the_run_blocks_where_it_stands() -> None:
    rs = at_merge2()
    full = dataclasses.replace(rs, steps=50)
    t = regate(full)
    assert status(t.state) == (RunStatus.BLOCKED, "merge")
    assert t.state.run.blocked_reason == "max_steps_exceeded"
    assert t.commands == ()
    assert t.state.steps == 50
    assert t.state.visits == full.visits


def test_one_step_under_the_cap_still_returns() -> None:
    rs = at_merge2()
    t = regate(dataclasses.replace(rs, steps=49))
    assert t.state.run.status is RunStatus.WAITING_HUMAN
    assert t.state.steps == 50


# --- what stays blocked ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "blocked"),
    [
        ("blocked", "effect_failed"),
        ("failed", "effect_failed_permanently"),
        ("voided", "effect_voided"),
    ],
)
def test_a_permanent_failure_stays_blocked_with_its_reason(reason: str, blocked: str) -> None:
    rs = at_merge2()
    t = regate(rs, reason=reason)
    assert status(t.state) == (RunStatus.BLOCKED, "merge")
    assert t.state.run.blocked_reason == blocked
    assert t.commands == ()
    assert t.state.steps == rs.steps
    assert t.state.visits == rs.visits
    assert t.state.approvals == rs.approvals


@pytest.mark.parametrize("reason", ["blocked", "failed", "voided"])
def test_the_blocks_agree_with_the_existing_effect_failed_handler(reason: str) -> None:
    rs = at_merge2()
    old = next(rs, EffectFailed(RID, "pr.merge", rs.count("merge"), reason), W)
    new = regate(rs, reason=reason)
    assert old.state.run.blocked_reason == new.state.run.blocked_reason


def test_the_reason_map_has_every_effect_failure_reason() -> None:
    assert set(REGATE_BLOCK) == {"blocked", "failed", "voided"}


def test_when_every_approval_holds_no_gate_is_first_invalid_so_the_run_blocks() -> None:
    rs = at_merge2()
    t = regate(rs, subject=S1)  # nothing moved: the claim's refusal cannot be explained
    assert status(t.state) == (RunStatus.BLOCKED, "merge")
    assert t.state.run.blocked_reason == "regate_unresolved"
    assert t.commands == ()
    assert t.state.steps == rs.steps


def test_two_invalid_gates_the_workflow_cannot_order_block() -> None:
    def twins(d: dict[str, Any]) -> None:
        s = d["stages"]
        s["panel"]["next"]["clean"] = "review_gate"
        s["review_gate"]["next"]["approved"] = "sec_gate"  # 3 by this way, 2 by triage
        s["triage"] = {"kind": "agent", "agent": "implementer", "next": {"ok": "sec_gate"}}
        # triage is listed first, so a depth-first walk would reach sec_gate the long way round
        s["implement"]["next"] = {"blocked": "triage", "ready": "panel"}
        s["sec_gate"] = _fx._gate(
            "review",
            ["reviewer"],
            {"approved": "merge", "rejected": "rejected_end"},
        )
        s["merge"]["requires_gates"] = ["review_gate", "sec_gate"]

    w = _fx.wf(twins, valid=False)
    rs = report(started(w), "ready", w=w)
    rs = close(report(rs, "clean", S1, w), K.APPROVE, w=w)
    running = dataclasses.replace(
        rs.run, status=RunStatus.RUNNING, stage="merge", blocked_reason=None
    )
    twin = dataclasses.replace(
        rs,
        run=running,
        visits=(*rs.visits, ("merge", 1)),
        approvals=(*rs.approvals, Approval("sec_gate", 1, did(), S1.digest(), S1.head_sha)),
    )
    t = next(twin, void(twin), w)
    assert t.state.run.blocked_reason == "regate_unresolved"
    assert t.commands == ()


def test_a_gate_the_workflow_does_not_have_blocks() -> None:
    rs = at_merge2()
    t = regate(dataclasses.replace(rs, routed_gates=("nowhere",)))
    assert t.state.run.blocked_reason == "regate_unresolved"


def test_an_approval_the_run_has_no_subject_to_judge_blocks() -> None:
    rs = at_merge2()
    t = regate(dataclasses.replace(rs, subject=None), subject=None)
    assert t.state.run.blocked_reason == "subject_missing"
    assert t.commands == ()


def test_without_an_event_subject_the_live_one_is_judged() -> None:
    rs = at_merge2()
    gone = dataclasses.replace(rs, approvals=rs.approvals[:1])
    t = regate(gone, subject=None)
    assert t.state.run.stage == "sec_gate"
    assert t.state.subject == S1


def test_merged_code_cannot_change_so_another_head_blocks() -> None:
    rs = dataclasses.replace(at_merge2(), merges=(_fx.Merge("m1", "abc"),))
    t = regate(rs, subject=_fx.subj("zzz"))
    assert t.state.run.blocked_reason == "head_moved"
    assert t.commands == ()
    assert t.state.subject == S1
    assert t.state.approvals == rs.approvals


def test_a_subject_of_the_wrong_shape_for_the_gate_blocks_instead_of_raising() -> None:
    rs = at_merge2()
    t = regate(rs, subject=PRE)
    assert t.state.run.blocked_reason == "subject_missing"
    assert t.commands == ()
    assert t.state.steps == rs.steps


def test_a_regate_block_cannot_be_retried() -> None:
    blocked = regate(at_merge2(), subject=S1).state
    with pytest.raises(OutOfOrderEventError, match="regate_unresolved"):
        describe_retry(blocked, W)


# --- replays and stale events ---------------------------------------------------------------


def test_a_replay_is_refused_after_the_return() -> None:
    rs = at_merge2()
    ev = void(rs)
    after = next(rs, ev, W).state
    with pytest.raises(OutOfOrderEventError):
        next(after, ev, W)


def test_a_replay_is_refused_after_a_block() -> None:
    rs = at_merge2()
    ev = void(rs, reason="failed")
    after = next(rs, ev, W).state
    with pytest.raises(OutOfOrderEventError):
        next(after, ev, W)


def test_a_replay_is_refused_when_the_run_comes_back_to_the_same_effect_visit() -> None:
    rs = at_merge2()
    ev = void(rs)
    same_place = dataclasses.replace(
        rs, run=dataclasses.replace(rs.run, version=rs.run.version + 5)
    )
    with pytest.raises(OutOfOrderEventError, match="version"):
        next(same_place, ev, W)


@pytest.mark.parametrize(
    "over",
    [{"visit": 9}, {"effect": "pr.update_branch"}, {"run_version": 0}],
)
def test_a_stale_or_misaddressed_event_is_refused(over: dict[str, Any]) -> None:
    rs = at_merge2()
    with pytest.raises(OutOfOrderEventError):
        regate(rs, **over)


def test_an_event_for_another_stage_than_an_effect_is_refused() -> None:
    rs = report(started(W), "ready", w=W)
    with pytest.raises(OutOfOrderEventError):
        next(rs, EffectDisposed(RID, "pr.merge", 1, "gate_invalid", None, rs.run.version), W)


def test_an_event_while_the_run_waits_for_a_human_is_refused() -> None:
    rs = report(report(started(W), "ready", w=W), "clean", S1, W)
    assert rs.run.status is RunStatus.WAITING_HUMAN
    with pytest.raises(OutOfOrderEventError):
        next(rs, EffectDisposed(RID, "pr.merge", 0, "gate_invalid", None, rs.run.version), W)


def test_a_terminal_run_absorbs_the_event() -> None:
    rs = at_merge2()
    done = dataclasses.replace(rs, run=rs.run.advance(RunStatus.CANCELLING))
    with pytest.raises(OutOfOrderEventError):
        regate(done)


# --- well-formedness ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"reason": "nope"},
        {"reason": "gate_invalidish"},
        {"visit": -1},
        {"visit": True},
        {"run_version": -1},
        {"run_version": True},
        {"effect": ""},
        {"effect": 3},
        {"subject": "S1"},
    ],
)
def test_a_malformed_event_cannot_be_built(over: dict[str, Any]) -> None:
    with pytest.raises((TypeError, ValueError)):
        EffectDisposed(
            **{
                "run_id": RID,
                "effect": "pr.merge",
                "visit": 1,
                "reason": "gate_invalid",
                "subject": None,
                "run_version": 0,
                **over,
            }
        )


# --- registration, purity -------------------------------------------------------------------


def test_the_handler_is_registered_by_load_handlers() -> None:
    assert GRAPH_HANDLERS.get(EffectDisposed) is on_effect_disposed


def test_a_registry_without_it_has_no_handler() -> None:
    rs = at_merge2()
    with pytest.raises(NoHandlerError):
        next(rs, void(rs), W, graph_registry=HandlerRegistry())


def test_it_is_pure_and_deterministic() -> None:
    rs = at_merge2()
    before = dataclasses.replace(rs)
    a, b = regate(rs), regate(rs)
    assert a == b
    assert rs == before


def test_the_module_reads_no_clock_randomness_or_context() -> None:
    src = Path(__file__).parents[2] / "src/sto/engine/handlers/regate.py"
    tree = ast.parse(src.read_text())
    banned = {"time", "datetime", "random", "uuid", "secrets", "contextvars", "os", "asyncio"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & banned


def _running_at(rs: RunState, stage: str, **over: Any) -> RunState:
    run = dataclasses.replace(rs.run, status=RunStatus.RUNNING, stage=stage, blocked_reason=None)
    return dataclasses.replace(rs, run=run, **over)


def test_a_routed_stage_that_is_not_a_gate_cannot_be_the_first_invalid_one() -> None:
    rs = at_merge2()
    now = edited()
    both = tuple(dataclasses.replace(a, subject_digest=now.digest()) for a in rs.approvals)
    t = regate(dataclasses.replace(rs, approvals=both, routed_gates=("merge",)))
    assert t.state.run.blocked_reason == "regate_unresolved"
    assert t.commands == ()


def test_an_invalid_gate_the_start_cannot_reach_blocks() -> None:
    def orphan(d: dict[str, Any]) -> None:
        _two_gates(d)
        d["stages"]["lonely"] = _fx._gate(
            "review", ["reviewer"], {"approved": "merge", "rejected": "rejected_end"}
        )

    w = _fx.wf(orphan, valid=False)
    rs = at_merge2()
    now = edited()
    both = tuple(dataclasses.replace(a, subject_digest=now.digest()) for a in rs.approvals)
    t = next(dataclasses.replace(rs, approvals=both, routed_gates=("lonely",)), void(rs), w)
    assert t.state.run.blocked_reason == "regate_unresolved"


def test_routed_gates_alone_do_not_make_an_ungated_effect_gated() -> None:
    rs = at_merge2()
    at_update = _running_at(rs, "update", visits=(*rs.visits, ("update", 1)))
    ev = EffectDisposed(RID, "pr.update_branch", 1, "gate_invalid", edited(), rs.run.version)
    routed = dataclasses.replace(at_update, routed_gates=("review_gate",))
    t = next(routed, ev, W)  # like _goto: routed gates count only on an effect that has gates
    assert t.state.run.blocked_reason == "regate_unresolved"


def test_workflow_order_holds_when_requires_gates_is_already_in_that_order() -> None:
    def forward(d: dict[str, Any]) -> None:
        _two_gates(d)
        d["stages"]["merge"]["requires_gates"] = ["review_gate", "sec_gate"]

    w = _fx.wf(forward)
    rs = at_merge2()
    t = next(rs, void(rs), w)
    assert t.state.run.stage == "review_gate"
