"""D2-25: loop grants and route-to-gate.

Fixtures are synthetic. The graph is the D2-06 reducer test's Kanban workflow (loop ``fix`` has a
cap of 2; the review panel's ``clean`` edge leads to ``review_gate``), loaded by path as
``test_failures.py`` does, so it is shared and not copied.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sto.config.schema import Workflow as Graph
from sto.domain import BLOCKED_REASONS, COMMANDS, EVENTS, RunStatus, TransientError
from sto.domain.models import BlockedEdge
from sto.engine.commands import OpenGate, RunStep
from sto.engine.handlers.grants import (
    MAX_GRANT_ROUNDS_FACTOR,
    AddToAttention,
    BarFromRound,
    GrantService,
    LoopGrant,
    LoopGranted,
    RouteService,
    RouteToGateRequested,
    grant_refusal,
    route_refusal,
)
from sto.engine.reducer import MalformedEventError, OutOfOrderEventError, RunState, next
from sto.gates.sod import AdminAction
from sto.gates.subject import AttentionItems, attention_digest


def _reducer_fixtures() -> Any:
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


_fx = _reducer_fixtures()
RID: Any = _fx.RID
OTHER: Any = _fx.OTHER
S1: Any = _fx.S1
W: Any = _fx.W
wf: Callable[..., Graph] = _fx.wf
new: Callable[[], RunState] = _fx.new
report: Callable[..., RunState] = _fx.report
started: Callable[..., RunState] = _fx.started
step: Callable[..., RunState] = _fx.step

ADMIN = "idp|team-admin-1"
NOW = 1_000.0


def spent_at_panel(subject: Any = S1) -> RunState:
    """Two uses of ``fix`` (cap 2), then a third ``findings``: BLOCKED(loop_exhausted) at the
    panel, with the head subject reported."""
    rs = started()
    for _ in range(2):
        rs = report(rs, "ready")
        rs = report(rs, "findings")
    rs = report(rs, "ready")
    rs = report(rs, "findings", subject)
    assert (rs.run.status, rs.run.blocked_reason) == (RunStatus.BLOCKED, "loop_exhausted")
    assert rs.run.stage == "panel"
    return rs


def grant(rs: RunState, **over: Any) -> LoopGrant:
    base: dict[str, Any] = {
        "run_id": RID,
        "stage": "panel",
        "outcome": "findings",
        "loop": "fix",
        "rounds": 1,
        "actor": ADMIN,
        "reason": "reviewer keeps flagging a documented pattern",
        "issued_at": NOW,
        "expires_at": NOW + 600,
    }
    return LoopGrant(**{**base, **over})


def granted(rs: RunState, g: LoopGrant | None = None, **over: Any) -> LoopGranted:
    base: dict[str, Any] = {
        "run_id": RID,
        "grant": g if g is not None else grant(rs),
        "run_version": rs.run.version,
        "applied_at": NOW + 1,
    }
    return LoopGranted(**{**base, **over})


def unchanged(rs: RunState, event: Any, w: Graph = W) -> None:
    out = next(rs, event, w)
    assert out.state == rs
    assert out.commands == ()


# --- loop grants ---------------------------------------------------------------------------


def test_a_grant_buys_exactly_the_rounds_it_names_and_no_more() -> None:
    rs = spent_at_panel()
    out = next(rs, granted(rs), W)
    assert out.state.run.status is RunStatus.RUNNING
    assert out.state.run.stage == "implement"
    assert out.commands == (RunStep(RID, "implement", visit=out.state.visit, attempt=1),)
    again = report(out.state, "ready")
    blocked = report(again, "findings", S1)  # the one extra round is used up
    assert (blocked.run.status, blocked.run.blocked_reason) == (RunStatus.BLOCKED, "loop_exhausted")


def test_a_grant_of_two_rounds_allows_two_more_iterations() -> None:
    rs = spent_at_panel()
    rs = step(rs, granted(rs, grant(rs, rounds=2)))
    for _ in range(1):
        rs = report(rs, "ready")
        rs = report(rs, "findings", S1)
    assert rs.run.status is RunStatus.RUNNING  # second extra round entered
    rs = report(rs, "ready")
    rs = report(rs, "findings", S1)
    assert rs.run.blocked_reason == "loop_exhausted"


def test_a_grant_is_one_version_and_touches_no_other_counter() -> None:
    rs = spent_at_panel()
    out = step(rs, granted(rs))
    assert out.run.version == rs.run.version + 1
    assert out.steps == rs.steps + 1  # the entered stage is one step, as for any entry
    assert out.approvals == rs.approvals
    assert out.merges == rs.merges
    assert out.routed_gates == rs.routed_gates


def test_the_grant_total_is_kept_so_a_second_grant_is_capped() -> None:
    rs = spent_at_panel()
    cap = W.limits.loops["fix"]
    rs = step(rs, granted(rs, grant(rs, rounds=cap)))  # the whole allowance at once
    for _ in range(cap):
        rs = report(rs, "ready")
        rs = report(rs, "findings", S1)
    assert rs.run.blocked_reason == "loop_exhausted"
    assert grant_refusal(rs, W, grant(rs), applied_at=NOW + 1) == "over_cap"
    unchanged(rs, granted(rs))


def test_a_grant_larger_than_the_cap_allows_is_refused() -> None:
    rs = spent_at_panel()
    cap = W.limits.loops["fix"]
    assert MAX_GRANT_ROUNDS_FACTOR == 1
    over = grant(rs, rounds=cap + 1)
    assert grant_refusal(rs, W, over, applied_at=NOW + 1) == "over_cap"
    unchanged(rs, granted(rs, over))


@pytest.mark.parametrize("rounds", [0, -1])
def test_a_grant_of_no_rounds_is_malformed(rounds: int) -> None:
    rs = spent_at_panel()
    with pytest.raises(ValueError, match="rounds"):
        grant(rs, rounds=rounds)


def test_a_missing_grant_gives_no_extra_iteration() -> None:
    rs = spent_at_panel()
    unchanged(rs, LoopGranted(RID, None, rs.run.version, NOW))
    assert grant_refusal(rs, W, None, applied_at=NOW) == "missing"


@pytest.mark.parametrize(
    ("over", "applied_at", "why"),
    [
        ({"expires_at": NOW + 1}, NOW + 1, "expired"),  # the expiry instant itself is expired
        ({"expires_at": NOW + 1}, NOW + 2, "expired"),
        ({}, NOW - 1, "not_yet_valid"),  # applied before it was issued: a bad clock
        ({"run_id": OTHER}, NOW + 1, "other_run"),
        ({"stage": "review_gate"}, NOW + 1, "other_stage"),
        ({"loop": "review_loop"}, NOW + 1, "other_loop"),
        ({"outcome": "degraded"}, NOW + 1, "other_loop"),  # that edge is not a looping edge
        ({"outcome": "nonexistent"}, NOW + 1, "other_loop"),
        ({"expires_at": NOW}, NOW + 1, "expired"),
        ({"expires_at": NOW - 5}, NOW + 1, "expired"),
    ],
)
def test_a_grant_that_does_not_fit_gives_no_extra_iteration(
    over: dict[str, Any], applied_at: float, why: str
) -> None:
    rs = spent_at_panel()
    g = grant(rs, **over)
    assert grant_refusal(rs, W, g, applied_at=applied_at) == why
    unchanged(rs, granted(rs, g, applied_at=applied_at))


def test_a_grant_with_a_non_finite_time_is_not_valid() -> None:
    rs = spent_at_panel()
    for bad in (float("nan"), float("inf")):
        g = grant(rs, expires_at=bad)
        assert grant_refusal(rs, W, g, applied_at=NOW + 1) is not None
        assert grant_refusal(rs, W, grant(rs), applied_at=bad) is not None


def test_a_grant_for_a_loop_that_is_not_spent_is_refused() -> None:
    rs = spent_at_panel()
    # Same state but the loop has room (a stale reading of a different block).
    room = dataclasses.replace(rs, loops=(("fix", 1),))
    assert grant_refusal(room, W, grant(room), applied_at=NOW + 1) == "not_spent"
    unchanged(room, granted(room))


def test_an_undeclared_loop_cannot_be_granted() -> None:
    rs = spent_at_panel()
    g = grant(rs, loop="ghost")
    assert grant_refusal(rs, W, g, applied_at=NOW + 1) == "other_loop"


def test_a_grant_is_only_for_a_run_blocked_on_a_spent_loop() -> None:
    rs = spent_at_panel()
    running = started()
    with pytest.raises(OutOfOrderEventError):
        next(running, granted(running), W)
    other_block = dataclasses.replace(
        rs, run=dataclasses.replace(rs.run, blocked_reason="max_steps_exceeded")
    )
    with pytest.raises(OutOfOrderEventError):
        next(other_block, granted(other_block), W)


def test_a_stale_or_repeated_grant_is_refused() -> None:
    rs = spent_at_panel()
    ev = granted(rs)
    after = step(rs, ev)
    with pytest.raises(OutOfOrderEventError):
        next(after, ev, W)  # the same event again: the run has moved
    with pytest.raises(OutOfOrderEventError):
        next(rs, granted(rs, run_version=rs.run.version - 1), W)


def test_a_grant_for_a_run_blocked_by_max_steps_after_the_grant_blocks_again() -> None:
    small = wf(lambda d: d["limits"].update(max_steps_per_run=6))
    rs = started(small)
    for _ in range(2):
        rs = report(rs, "ready", None, small)
        rs = report(rs, "findings", None, small)
    rs = report(rs, "ready", None, small)
    rs = report(rs, "findings", S1, small)
    assert rs.run.blocked_reason == "loop_exhausted"
    out = next(rs, granted(rs), small).state
    assert out.run.blocked_reason == "max_steps_exceeded"
    assert out.loop_count("fix") == rs.loop_count("fix")  # the refused entry moved no counter


def test_the_grant_handler_is_pure() -> None:
    rs = spent_at_panel()
    ev = granted(rs)
    assert next(rs, ev, W) == next(rs, ev, W)
    assert rs == spent_at_panel()


def test_a_grant_of_a_gate_edge_resumes_the_gate_edge() -> None:
    """A spent loop on a gate's request_changes edge is granted the same way."""
    rs = started()
    rs = report(rs, "ready")
    rs = report(rs, "clean", S1)
    for _ in range(2):  # review_loop cap 2
        rs = _fx.close(rs, _fx.K.REQUEST_CHANGES)
        rs = report(rs, "ready")
        rs = report(rs, "clean", S1)
    rs = _fx.close(rs, _fx.K.REQUEST_CHANGES)
    assert rs.run.blocked_reason == "loop_exhausted"
    assert rs.run.stage == "review_gate"
    g = grant(rs, stage="review_gate", outcome="changes_requested", loop="review_loop")
    out = next(rs, granted(rs, g), W)
    assert out.state.run.stage == "implement"
    assert out.state.run.status is RunStatus.RUNNING


# --- route-to-gate -------------------------------------------------------------------------


def route(rs: RunState, **over: Any) -> RouteToGateRequested:
    base: dict[str, Any] = {
        "run_id": RID,
        "actor": ADMIN,
        "reason": "the panel flags a documented pattern every round",
        "stage": rs.run.stage,
        "run_version": rs.run.version,
        "policy_allowed": True,
        "patch_blocked": False,
        "attention": AttentionItems(blocking_findings=("F-1",), failed_reviewers=()),
    }
    return RouteToGateRequested(**{**base, **over})


def test_route_to_gate_opens_the_next_gate_through_the_existing_gate_path() -> None:
    rs = spent_at_panel()
    out = next(rs, route(rs), W)
    assert out.state.run.status is RunStatus.WAITING_HUMAN
    assert out.state.run.stage == "review_gate"
    opens = [c for c in out.commands if isinstance(c, OpenGate)]
    assert len(opens) == 1
    assert opens[0].name == "review_gate"
    assert opens[0].round == out.state.round == 1
    assert opens[0].subject == S1


def test_route_to_gate_puts_the_item_on_the_attention_list() -> None:
    rs = spent_at_panel()
    ev = route(rs)
    out = next(rs, ev, W)
    adds = [c for c in out.commands if isinstance(c, AddToAttention)]
    assert len(adds) == 1
    add = adds[0]
    assert (add.run_id, add.stage, add.gate, add.round) == (RID, "panel", "review_gate", 1)
    assert add.actor == ADMIN
    assert add.reason == ev.reason
    assert add.items == ev.attention
    assert add.digest == attention_digest(ev.attention)


def test_route_to_gate_makes_the_actor_ineligible_for_that_round() -> None:
    rs = spent_at_panel()
    out = next(rs, route(rs), W)
    bars = [c for c in out.commands if isinstance(c, BarFromRound)]
    assert bars == [BarFromRound(RID, ADMIN, "review_gate", 1)]
    action = bars[0].as_admin_action()
    assert isinstance(action, AdminAction)
    assert action.actor == ADMIN
    assert action.kind == "extend_eligibility"  # SoD's admin_self_service bars the actor
    assert (action.gate, action.round) == ("review_gate", 1)


def test_the_bar_is_for_the_round_that_opens_not_an_earlier_one() -> None:
    rs = spent_at_panel()
    again = dataclasses.replace(rs, visits=(*rs.visits, ("review_gate", 2)))
    out = next(again, route(again), W)
    bars = [c for c in out.commands if isinstance(c, BarFromRound)]
    assert bars[0].round == 3
    assert [c for c in out.commands if isinstance(c, OpenGate)][0].round == 3


def test_route_to_gate_moves_no_loop_counter() -> None:
    rs = spent_at_panel()
    out = step(rs, route(rs))
    assert out.loops == rs.loops
    assert out.run.version == rs.run.version + 1
    assert out.steps == rs.steps + 1


def test_route_to_gate_is_refused_by_default() -> None:
    rs = spent_at_panel()
    ev = route(rs, policy_allowed=False)
    assert route_refusal(rs, W, ev) == "not_allowed"
    unchanged(rs, ev)
    default = RouteToGateRequested(RID, ADMIN, "why", "panel", rs.run.version)
    assert default.policy_allowed is False
    unchanged(rs, default)


def test_route_to_gate_is_refused_from_a_stage_that_is_not_a_review_panel() -> None:
    rs = spent_at_panel()
    for stage in ("review_gate", "implement", "merge"):
        # a block at a gate (spent loop on its request_changes edge) is not a panel false positive
        moved = dataclasses.replace(rs, run=dataclasses.replace(rs.run, stage=stage))
        ev = route(moved, stage=stage)
        assert route_refusal(moved, W, ev) == "not_review_stage"
        unchanged(moved, ev)


def test_route_to_gate_is_refused_for_a_policy_blocked_patch() -> None:
    rs = spent_at_panel()
    ev = route(rs, patch_blocked=True)
    assert route_refusal(rs, W, ev) == "patch_blocked"
    unchanged(rs, ev)


def test_an_unknown_patch_status_fails_closed() -> None:
    rs = spent_at_panel()
    ev = route(rs, patch_blocked=None)
    assert route_refusal(rs, W, ev) == "patch_blocked"
    unchanged(rs, ev)


def test_policy_block_wins_over_everything_else_that_would_allow() -> None:
    rs = spent_at_panel()
    assert route_refusal(rs, W, route(rs, patch_blocked=True, policy_allowed=True)) == (
        "patch_blocked"
    )


def test_route_to_gate_never_skips_a_stage_between_the_panel_and_the_gate() -> None:
    def via_effect(d: dict[str, Any]) -> None:
        d["stages"]["push_step"] = {
            "kind": "effect",
            "effect": "branch.push",
            "next": {"done": "review_gate"},
        }
        d["stages"]["panel"]["next"]["clean"] = "push_step"

    graph = wf(via_effect, valid=False)
    rs = started(graph)
    for _ in range(2):
        rs = report(rs, "ready", None, graph)
        rs = report(rs, "findings", None, graph)
    rs = report(rs, "ready", None, graph)
    rs = report(rs, "findings", S1, graph)
    ev = route(rs)
    assert route_refusal(rs, graph, ev) == "no_next_gate"
    unchanged(rs, ev, graph)


def test_route_to_gate_refuses_when_the_gate_would_not_open() -> None:
    rs = spent_at_panel(None)  # no head subject to approve
    ev = route(rs)
    assert route_refusal(rs, W, ev) == "gate_would_not_open"
    unchanged(rs, ev)


def test_route_to_gate_needs_a_run_blocked_on_a_spent_loop() -> None:
    running = started()
    with pytest.raises(OutOfOrderEventError):
        next(running, route(running, stage="implement"), W)
    rs = spent_at_panel()
    with pytest.raises(OutOfOrderEventError):
        next(rs, route(rs, run_version=rs.run.version + 1), W)
    other = dataclasses.replace(rs, run=dataclasses.replace(rs.run, blocked_reason="degraded"))
    with pytest.raises(OutOfOrderEventError):
        next(other, route(other), W)


def test_a_second_route_for_the_same_block_is_refused() -> None:
    rs = spent_at_panel()
    ev = route(rs)
    after = step(rs, ev)
    with pytest.raises(OutOfOrderEventError):
        next(after, ev, W)


@pytest.mark.parametrize("over", [{"actor": ""}, {"actor": "  "}, {"reason": ""}, {"reason": " "}])
def test_route_to_gate_names_who_and_why(over: dict[str, Any]) -> None:
    rs = spent_at_panel()
    with pytest.raises(MalformedEventError):
        next(rs, route(rs, **over), W)


def test_an_actor_that_sod_would_not_recognise_is_malformed() -> None:
    rs = spent_at_panel()
    with pytest.raises(MalformedEventError):
        next(rs, route(rs, actor="alice"), W)  # not 'issuer|subject': would bar nobody


def test_the_route_handler_is_pure() -> None:
    rs = spent_at_panel()
    ev = route(rs)
    assert next(rs, ev, W) == next(rs, ev, W)


def test_events_and_commands_register_by_name() -> None:
    assert EVENTS.get("loop.granted") is LoopGranted
    assert EVENTS.get("route_to_gate.requested") is RouteToGateRequested
    assert COMMANDS.get("add_to_attention") is AddToAttention
    assert COMMANDS.get("bar_from_round") is BarFromRound
    assert BLOCKED_REASONS is not None


# --- the audited services ------------------------------------------------------------------


class Journal:
    def __init__(self) -> None:
        self.log: list[tuple[Any, ...]] = []


class FakeAudit:
    def __init__(self, j: Journal, fail: bool = False) -> None:
        self.j, self.fail = j, fail

    def record(self, run_id: Any, action: str, actor: str, data: dict[str, Any]) -> None:
        if self.fail:
            raise TransientError("audit store down")
        self.j.log.append(("audit", action, actor, data))


class Admins:
    def __init__(self, who: set[str]) -> None:
        self.who = who

    def is_team_admin(self, team: str, actor: str) -> bool:
        return actor in self.who


class Policy:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed

    def route_to_gate_allowed(self, team: str) -> bool:
        return self.allowed


class Patches:
    def __init__(self, blocked: bool | None) -> None:
        self.blocked = blocked

    def patch_blocked(self, run_id: Any) -> bool | None:
        return self.blocked


class Attention:
    def __init__(self, items: AttentionItems) -> None:
        self.items = items
        self.asked: list[str] = []

    def items_for(self, run_id: Any, stage: str) -> AttentionItems:
        self.asked.append(stage)
        return self.items


class Ceilings:
    def __init__(self, max_loop: int | None = None) -> None:
        self.max_loop_value = max_loop

    def max_loop(self, team: str) -> int | None:
        return self.max_loop_value


class Clock:
    def __init__(self, t: float = NOW) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def make(
    rs: RunState,
    j: Journal,
    *,
    admins: set[str] | None = None,
    allowed: bool = True,
    blocked: bool | None = False,
    clock: Clock | None = None,
    audit_fails: bool = False,
    submit_fails: int = 0,
    max_loop: int | None = None,
    graph: Graph = W,
) -> tuple[GrantService, RouteService, list[object]]:
    sent: list[object] = []
    failures = [submit_fails]

    async def submit(run_id: Any, event: object) -> None:
        j.log.append(("submit", type(event).__name__))
        if failures[0] > 0:
            failures[0] -= 1
            raise TransientError("store blip")
        sent.append(event)

    common: dict[str, Any] = {
        "audit": FakeAudit(j, audit_fails),
        "submit": submit,
        "load": lambda run_id: (rs, graph),
        "admins": Admins({ADMIN} if admins is None else admins),
    }
    attention = Attention(AttentionItems(blocking_findings=("F-1",)))
    grants = GrantService(clock=clock or Clock(), ceilings=Ceilings(max_loop), **common)
    routes = RouteService(
        policy=Policy(allowed),
        patches=Patches(blocked),
        attention=attention,
        **common,
    )
    return grants, routes, sent


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_a_grant_is_audited_before_the_run_hears_of_it() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j)
    ev = run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert [e[0] for e in j.log] == ["audit", "submit"]
    action, actor, data = j.log[0][1:]
    assert (action, actor) == ("loop.grant", ADMIN)
    assert data["loop"] == "fix"
    assert data["rounds"] == 1
    assert data["reason"] == "why"
    assert sent == [ev]
    assert isinstance(ev, LoopGranted)
    assert ev.run_version == rs.run.version
    assert ev.grant is not None
    assert ev.grant.expires_at > NOW


def test_the_service_stamps_the_grant_and_the_event_from_its_injected_clock() -> None:
    rs, j = spent_at_panel(), Journal()
    clock = Clock(NOW)
    grants, _, sent = make(rs, j, clock=clock)
    g = run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why", ttl=60)).grant
    assert g is not None
    assert (g.issued_at, g.expires_at) == (NOW, NOW + 60)
    # The event carries the service's time so the pure handler can compare numbers. A grant is not
    # revoked by the passing of time inside the reducer (it cannot read a clock): ``run_version``
    # is the guard against a late grant, and the handler tests below pin that.
    assert sent[0].applied_at == NOW  # type: ignore[attr-defined]


def test_a_grant_from_someone_who_is_not_a_team_admin_is_refused_and_audited() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j, admins=set())
    with pytest.raises(PermissionError):
        run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert sent == []
    assert [e[:2] for e in j.log] == [("audit", "loop.grant_refused")]
    assert j.log[0][3]["why"] == "not_team_admin"


def test_a_grant_that_would_do_nothing_is_refused_and_audited() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j)
    with pytest.raises(PermissionError):
        run(grants.grant(RID, ADMIN, "panel", "findings", "ghost", 1, "why"))
    assert sent == []
    assert j.log[0][1] == "loop.grant_refused"
    assert j.log[0][3]["why"] == "other_loop"


def test_a_failed_audit_stops_the_grant() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j, audit_fails=True)
    with pytest.raises(TransientError):
        run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert sent == []
    assert j.log == []


def test_a_grant_service_check_agrees_with_what_the_reducer_does() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j)
    ev = run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    out = next(rs, ev, W).state
    assert out.run.stage == "implement"


def test_route_is_audited_before_the_run_hears_of_it() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j)
    ev = run(routes.route(RID, ADMIN, "false positive"))
    assert [e[0] for e in j.log] == ["audit", "submit"]
    action, actor, data = j.log[0][1:]
    assert (action, actor) == ("run.route_to_gate", ADMIN)
    assert data["gate"] == "review_gate"
    assert data["reason"] == "false positive"
    assert sent == [ev]
    assert isinstance(ev, RouteToGateRequested)
    assert ev.policy_allowed is True
    assert ev.patch_blocked is False


def test_route_reads_the_org_policy_at_decision_time_and_refuses_by_default() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j, allowed=False)
    with pytest.raises(PermissionError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []
    assert j.log[0][1:3] == ("run.route_to_gate_refused", ADMIN)
    assert j.log[0][3]["why"] == "not_allowed"


def test_route_for_a_policy_blocked_patch_is_refused_and_audited() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j, blocked=True)
    with pytest.raises(PermissionError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []
    assert j.log[0][3]["why"] == "patch_blocked"


def test_route_with_an_unknown_patch_status_is_refused() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j, blocked=None)
    with pytest.raises(PermissionError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []


def test_route_from_someone_who_is_not_a_team_admin_is_refused() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j, admins=set())
    with pytest.raises(PermissionError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []
    assert j.log[0][3]["why"] == "not_team_admin"


def test_route_from_a_non_review_stage_is_refused_and_audited() -> None:
    rs = spent_at_panel()
    moved = dataclasses.replace(rs, run=dataclasses.replace(rs.run, stage="review_gate"))
    j = Journal()
    _, routes, sent = make(moved, j)
    with pytest.raises(PermissionError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []
    assert j.log[0][3]["why"] == "not_review_stage"


def test_a_failed_route_audit_stops_the_route() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, sent = make(rs, j, audit_fails=True)
    with pytest.raises(TransientError):
        run(routes.route(RID, ADMIN, "why"))
    assert sent == []


def test_the_services_never_read_a_wall_clock() -> None:
    import inspect

    import sto.engine.handlers.grants as mod

    src = inspect.getsource(mod)
    for banned in ("time.time", "datetime.now", "datetime.utcnow", "time.monotonic", "random"):
        assert banned not in src


def test_route_asks_for_the_attention_items_of_the_blocked_panel() -> None:
    rs, j = spent_at_panel(), Journal()
    _, routes, _ = make(rs, j)
    run(routes.route(RID, ADMIN, "why"))
    assert routes._attention.asked == ["panel"]  # type: ignore[attr-defined]


def test_a_grant_without_a_reason_is_refused_and_audited() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j)
    for blank in ("", "  "):
        with pytest.raises(PermissionError):
            run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, blank))
    assert sent == []
    assert [e[3]["why"] for e in j.log] == ["no_reason", "no_reason"]


def test_a_panel_with_no_clean_edge_has_no_next_gate() -> None:
    def no_clean(d: dict[str, Any]) -> None:
        del d["stages"]["panel"]["next"]["clean"]

    graph = wf(no_clean, valid=False)
    rs = started(graph)
    for _ in range(2):
        rs = report(rs, "ready", None, graph)
        rs = report(rs, "findings", None, graph)
    rs = report(rs, "ready", None, graph)
    rs = report(rs, "findings", S1, graph)
    assert route_refusal(rs, graph, route(rs)) == "no_next_gate"


def test_a_counter_above_the_cap_is_brought_back_to_the_cap_before_the_grant() -> None:
    rs = spent_at_panel()
    over = dataclasses.replace(rs, loops=(("fix", 5),))
    out = next(over, granted(over), W).state
    assert out.loop_count("fix") == W.limits.loops["fix"]  # (cap - 1) + 1 for the re-entry


# --- review fixes (pass 1) -----------------------------------------------------------------


def blocked_at(
    rs: RunState,
    stage: str,
    loops: tuple[tuple[str, int], ...],
    edge: BlockedEdge | None = None,
) -> RunState:
    """A hand-built BLOCKED(loop_exhausted) run, with the edge the reducer would have recorded."""
    run = dataclasses.replace(
        rs.run, stage=stage, status=RunStatus.BLOCKED, blocked_reason="loop_exhausted"
    )
    return dataclasses.replace(rs, run=run, loops=loops, blocked_edge=edge)


QA_CHANGES = BlockedEdge("qa_gate", "implement", "review_loop")
QA_RETEST = BlockedEdge("qa_gate", "qa_agent", "retest")


def qa_blocked_with_both_loops_spent(edge: BlockedEdge | None) -> RunState:
    rs = started()
    rs = report(rs, "ready")
    rs = report(rs, "clean", S1)
    return blocked_at(rs, "qa_gate", (("review_loop", 2), ("retest", 2)), edge)


def test_a_grant_cannot_turn_request_changes_into_a_retest() -> None:
    """P1: both QA loops are spent. The recorded edge says which one blocked, so the grant for the
    other is refused and the grant for the blocked one is not ambiguous."""
    rs = qa_blocked_with_both_loops_spent(QA_CHANGES)
    other = grant(rs, stage="qa_gate", outcome="retest", loop="retest")
    assert grant_refusal(rs, W, other, applied_at=NOW + 1) == "other_edge"
    unchanged(rs, granted(rs, other))
    ok = grant(rs, stage="qa_gate", outcome="changes_requested", loop="review_loop")
    assert grant_refusal(rs, W, ok, applied_at=NOW + 1) is None


def test_the_recorded_edge_decides_even_when_both_edges_look_spent() -> None:
    """The edge is read, not derived: it names the retest, so only the retest is granted."""
    rs = qa_blocked_with_both_loops_spent(QA_RETEST)
    ok = grant(rs, stage="qa_gate", outcome="retest", loop="retest")
    assert grant_refusal(rs, W, ok, applied_at=NOW + 1) is None
    assert next(rs, granted(rs, ok), W).state.run.stage == "qa_agent"
    other = grant(rs, stage="qa_gate", outcome="changes_requested", loop="review_loop")
    assert grant_refusal(rs, W, other, applied_at=NOW + 1) == "other_edge"


def test_a_run_saved_without_the_edge_takes_no_grant() -> None:
    """A run saved before the field existed is blocked on a loop with no edge: it fails closed
    rather than guessing, even when only one edge looks spent."""
    rs = blocked_at(started(), "merge", (("fix", 1), ("stale", 1)), None)
    g = grant(rs, stage="merge", outcome="stale", loop="stale")
    assert grant_refusal(rs, W, g, applied_at=NOW + 1) == "edge_unknown"
    unchanged(rs, granted(rs, g))


def test_a_merge_with_both_conflict_and_stale_spent_follows_the_recorded_edge() -> None:
    edge = BlockedEdge("merge", "update", "stale")
    rs = blocked_at(started(), "merge", (("fix", 2), ("stale", 1)), edge)
    stale = grant(rs, stage="merge", outcome="stale", loop="stale")
    assert grant_refusal(rs, W, stale, applied_at=NOW + 1) is None
    conflict = grant(rs, stage="merge", outcome="conflict", loop="fix")
    assert grant_refusal(rs, W, conflict, applied_at=NOW + 1) == "other_edge"
    unchanged(rs, granted(rs, conflict))


def test_a_grant_for_a_loop_that_is_not_spent_is_not_spent_even_with_an_edge() -> None:
    edge = BlockedEdge("merge", "update", "stale")
    rs = blocked_at(started(), "merge", (("fix", 1), ("stale", 1)), edge)
    other = grant(rs, stage="merge", outcome="conflict", loop="fix")
    assert grant_refusal(rs, W, other, applied_at=NOW + 1) == "not_spent"
    unchanged(rs, granted(rs, other))


def test_a_stale_edge_for_another_stage_takes_no_grant() -> None:
    edge = BlockedEdge("panel", "implement", "fix")
    rs = blocked_at(started(), "merge", (("fix", 2), ("stale", 1)), edge)
    g = grant(rs, stage="merge", outcome="stale", loop="stale")
    assert grant_refusal(rs, W, g, applied_at=NOW + 1) == "edge_unknown"


def test_the_standard_template_qa_gate_follows_the_recorded_edge() -> None:
    from sto.config.schema import load_document

    path = Path(__file__).parents[2] / "templates" / "standard" / "workflow.yaml"
    graph = load_document(path.read_text())
    assert isinstance(graph, Graph)
    edges = graph.stages["qa_gate"].next  # type: ignore[union-attr]
    looped = {
        o: BlockedEdge("qa_gate", e.to, e.loop)
        for o, e in edges.items()
        if not isinstance(e, str) and e.loop
    }
    assert {e.loop for e in looped.values()} == {"qa_fix", "retest"}
    spent = tuple((e.loop, graph.limits.loops[e.loop]) for e in looped.values())
    for blocked_outcome, edge in looped.items():
        rs = blocked_at(started(graph), "qa_gate", spent, edge)
        for outcome, e in looped.items():
            g = grant(rs, stage="qa_gate", outcome=outcome, loop=e.loop)
            want = None if outcome == blocked_outcome else "other_edge"
            assert grant_refusal(rs, graph, g, applied_at=NOW + 1) == want


# --- the reducer records the blocked edge (D2-34) -------------------------------------------


def test_the_reducer_records_the_edge_it_blocked_on() -> None:
    rs = spent_at_panel()
    assert rs.blocked_edge == BlockedEdge("panel", "implement", "fix")


def test_the_edge_is_cleared_when_the_run_is_no_longer_blocked_on_a_loop() -> None:
    rs = spent_at_panel()
    out = next(rs, granted(rs), W).state
    assert out.run.status is RunStatus.RUNNING
    assert out.blocked_edge is None


def test_a_recorded_edge_does_not_survive_a_different_block() -> None:
    """A grant that another guard re-blocks (step limit) leaves a run that is not blocked on the
    loop, so no edge is kept."""
    rs = spent_at_panel()
    tight = dataclasses.replace(rs, steps=W.limits.max_steps_per_run)
    out = next(tight, granted(tight), W).state
    assert out.run.blocked_reason == "max_steps_exceeded"
    assert out.blocked_edge is None


def test_the_edge_survives_the_wire_and_an_old_run_without_it_still_loads() -> None:
    from sto.domain import from_wire, to_wire

    rs = spent_at_panel()
    wire = to_wire(rs)
    assert from_wire(RunState, wire) == rs
    old = {k: v for k, v in wire.items() if k != "blocked_edge"}  # saved before the field
    loaded = from_wire(RunState, old)
    assert loaded.blocked_edge is None
    assert loaded.run.blocked_reason == "loop_exhausted"


def test_the_edge_is_recorded_when_a_gate_edge_blocks() -> None:
    """A gate leaves by the decision's outcome: QA's retest edge, with its own loop spent."""
    rs = started()
    rs = report(rs, "ready")
    rs = report(rs, "clean", S1)  # panel -> review_gate
    rs = _fx.close(rs, _fx.K.APPROVE)  # review_gate -> merge
    rs = dataclasses.replace(rs, run=dataclasses.replace(rs.run, stage="qa_gate"), round=1)
    rs = dataclasses.replace(
        rs, run=rs.run.advance(RunStatus.WAITING_HUMAN), loops=(("retest", 2),)
    )
    out = _fx.close(rs, _fx.K.RETEST)
    assert out.run.blocked_reason == "loop_exhausted"
    assert out.blocked_edge == QA_RETEST


def test_a_route_needs_the_recorded_edge_to_be_at_the_panel() -> None:
    rs = spent_at_panel()
    assert route_refusal(rs, W, route(rs)) is None
    for edge in (
        None,
        BlockedEdge("merge", "update", "stale"),
        BlockedEdge("panel", "review_gate", "x"),
    ):
        bad = dataclasses.replace(rs, blocked_edge=edge)
        assert route_refusal(bad, W, route(bad)) == "no_next_gate"


def test_route_emits_the_bar_before_the_gate_opens() -> None:
    rs = spent_at_panel()
    out = next(rs, route(rs), W)
    assert [type(c) for c in out.commands] == [BarFromRound, OpenGate, AddToAttention]


def test_the_total_never_passes_the_org_ceiling() -> None:
    """P3: loop cap 5, org max_loop 5: a grant of 5 used to run the loop ten times."""
    w5 = wf(lambda d: d["limits"]["loops"].update({"fix": 5}))
    rs = started(w5)
    for _ in range(5):
        rs = report(rs, "ready", None, w5)
        rs = report(rs, "findings", None, w5)
    rs = report(rs, "ready", None, w5)
    rs = report(rs, "findings", S1, w5)
    g = grant(rs, rounds=5)
    assert grant_refusal(rs, w5, g, applied_at=NOW + 1, loop_ceiling=5) == "over_cap"
    unchanged(rs, granted(rs, g, loop_ceiling=5), w5)


def test_a_grant_may_use_the_room_between_the_cap_and_the_ceiling() -> None:
    rs = spent_at_panel()  # cap 2
    assert grant_refusal(rs, W, grant(rs, rounds=1), applied_at=NOW + 1, loop_ceiling=3) is None
    assert grant_refusal(rs, W, grant(rs, rounds=2), applied_at=NOW + 1, loop_ceiling=3) == (
        "over_cap"
    )
    assert grant_refusal(rs, W, grant(rs, rounds=1), applied_at=NOW + 1, loop_ceiling=1) == (
        "over_cap"
    )  # a ceiling tightened below the cap leaves no room


@pytest.mark.parametrize("bad", [0, -1, True, "5", 2.5])
def test_a_mistyped_ceiling_fails_closed(bad: Any) -> None:
    rs = spent_at_panel()
    assert grant_refusal(rs, W, grant(rs), applied_at=NOW + 1, loop_ceiling=bad) == "bad_ceiling"


@pytest.mark.parametrize(
    "over",
    [
        {"stage": ["panel"]},
        {"outcome": ["findings"]},
        {"loop": {"a": 1}},
        {"actor": 5},
        {"reason": None},
        {"run_id": "r1"},
        {"issued_at": "now"},
        {"expires_at": None},
        {"issued_at": True},
    ],
)
def test_a_mistyped_grant_is_refused_at_construction_not_with_a_type_error(
    over: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="grant"):
        grant(spent_at_panel(), **over)


def test_a_mistyped_decoded_grant_is_refused_on_decode() -> None:
    from sto.domain.serialize import from_wire, to_wire

    rs = spent_at_panel()
    wire = to_wire(granted(rs))
    wire["grant"] = {**wire["grant"], "outcome": ["findings"]}
    with pytest.raises(ValueError, match="grant"):
        from_wire(LoopGranted, wire)


def test_the_service_passes_the_org_ceiling_and_refuses_the_excess() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, sent = make(rs, j, max_loop=3)
    with pytest.raises(PermissionError):
        run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 2, "why"))
    assert sent == []
    assert j.log[0][3]["why"] == "over_cap"
    ev = run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert ev.loop_ceiling == 3


def test_the_audit_records_the_real_result_when_another_guard_blocks_the_grant() -> None:
    small = wf(lambda d: d["limits"].update(max_steps_per_run=6))
    rs = started(small)
    for _ in range(2):
        rs = report(rs, "ready", None, small)
        rs = report(rs, "findings", None, small)
    rs = report(rs, "ready", None, small)
    rs = report(rs, "findings", S1, small)
    j = Journal()
    grants, _, _ = make(rs, j, graph=small)
    run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert j.log[0][3]["result"] == "blocked:max_steps_exceeded"


def test_the_audit_records_a_resumed_run() -> None:
    rs, j = spent_at_panel(), Journal()
    grants, _, _ = make(rs, j)
    run(grants.grant(RID, ADMIN, "panel", "findings", "fix", 1, "why"))
    assert j.log[0][3]["result"] == "resumed"
