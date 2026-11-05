"""D3-13: moving ticket and PR (PLAN 4.5, invariant G11).

``react`` is pure: one test per row of the PLAN 4.5 table, each with an allowed twin, so a rule
that fires on everything (or nothing) fails. The store tests run the plan against a real
``GateService`` to show that a superseded gate cannot be approved and an old approval never
counts for a moved subject.
"""

# ruff: noqa: PT018  (compound asserts keep each row of PLAN 4.5 on one line)
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from sto.domain import (
    DecisionKind,
    Gate,
    GateStatus,
    GateType,
    PermanentError,
    RunId,
    RunStatus,
    Subject,
    Surface,
    from_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.hooks import audit_pk
from sto.gates.moving import (
    AcknowledgementRequiredError,
    Action,
    CommitPushed,
    MoveState,
    MovingEventError,
    MovingFacts,
    PrClosed,
    StaleMovingEventError,
    TicketClosed,
    TicketClosedError,
    TicketEdited,
    apply_reaction,
    check_decision,
    load_state,
    react,
)
from sto.gates.service import GateClosedError, GateService
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, Key, TeamScope

pytestmark = pytest.mark.unit

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
APP = "sto-app[bot]"


def facts(**over: Any) -> MovingFacts:
    base: dict[str, Any] = {
        "run_version": 7,
        "status": RunStatus.WAITING_HUMAN,
        "stage": "qa",
        "head_sha": "h1",
        "ticket_revision": "rev1",
        "has_open_gate": True,
        "merged": False,
        "our_heads": frozenset({"h1"}),
        "our_merges": frozenset(),
        "push_attempting": False,
        "return_stage": "ci",
        "external_commits": 0,
        "external_commit_cap": 3,
        "app_login": APP,
    }
    return MovingFacts(**{**base, **over})


def commit(sha: str = "x9", **over: Any) -> CommitPushed:
    return CommitPushed(**{"run_version": 7, "sha": sha, **over})


def edit(revision: str = "rev2", **over: Any) -> TicketEdited:
    return TicketEdited(
        **{
            "run_version": 7,
            "revision": revision,
            "editor": "alice",
            "editor_is_member": True,
            **over,
        }
    )


# --- new commit -------------------------------------------------------------------------------


def test_commit_during_qa_returns_to_ci_under_the_external_commit_cap() -> None:
    r = react(facts(stage="qa"), commit())
    assert r.action is Action.RETURN_TO_STAGE
    assert (r.stage, r.loop) == ("ci", "external_commit")
    assert r.supersede_gates is True
    assert r.audit_action == "moving.external_commit"
    assert r.audit_data["sha"] == "x9"


def test_commit_at_the_cap_blocks_instead_of_looping() -> None:
    r = react(facts(external_commits=2), commit())
    assert r.action is Action.RETURN_TO_STAGE  # the third use is still allowed
    r = react(facts(external_commits=3), commit())
    assert r.action is Action.BLOCK
    assert r.reason == "loop_exhausted"
    assert r.supersede_gates is True


def test_commit_without_a_target_stage_blocks() -> None:
    r = react(facts(return_stage=None), commit())
    assert (r.action, r.reason) == (Action.BLOCK, "external_commit_unroutable")
    assert r.supersede_gates is True


@pytest.mark.parametrize("sha", ["h1", "h0"])
def test_commit_we_know_changes_nothing(sha: str) -> None:
    r = react(facts(our_heads=frozenset({"h0", "h1"})), commit(sha))
    assert r.action is Action.NONE and not r.supersede_gates


def test_commit_while_our_push_is_attempting_waits() -> None:
    r = react(facts(push_attempting=True), commit())
    assert r.action is Action.DEFER and not r.supersede_gates
    # ... but our own commit is recognised even then
    assert react(facts(push_attempting=True), commit("h1")).action is Action.NONE


def test_commit_after_merge_or_on_an_ended_run_is_only_audited() -> None:
    merged = react(facts(merged=True), commit())
    assert merged.action is Action.NONE and merged.audit_action == "moving.commit_after_merge"
    done = react(facts(status=RunStatus.DONE), commit())
    assert done.action is Action.NONE and not done.supersede_gates


# --- ticket edited ----------------------------------------------------------------------------


def test_edit_with_a_gate_open_drops_votes_and_needs_acknowledgement() -> None:
    r = react(facts(), edit())
    assert r.action is Action.NONE and not r.supersede_gates
    assert r.drop_votes is True
    assert r.require_ack == "rev2"
    assert r.record_revision == "rev2"
    assert r.audit_data["from"] == "rev1" and r.audit_data["to"] == "rev2"


def test_edit_with_no_gate_open_only_records_the_revision() -> None:
    r = react(facts(has_open_gate=False), edit())
    assert r.record_revision == "rev2"
    assert not r.drop_votes and r.require_ack is None


def test_edit_to_the_same_revision_is_a_no_op() -> None:
    r = react(facts(), edit("rev1"))
    assert r.action is Action.NONE and r.record_revision is None and not r.drop_votes


@pytest.mark.parametrize(
    "over", [{"editor_is_member": False}, {"editor": None, "editor_is_member": None}]
)
def test_edit_by_a_non_member_or_unknown_editor_pauses_the_run(over: dict[str, Any]) -> None:
    r = react(facts(), edit(**over))
    assert (r.action, r.reason) == (Action.BLOCK, "ticket_edit_unconfirmed")
    assert r.drop_votes is True and r.require_ack == "rev2"


def test_edit_after_merge_is_recorded_but_cannot_strand_the_run() -> None:
    r = react(facts(merged=True), edit(editor_is_member=False))
    assert r.action is Action.NONE and not r.drop_votes and r.require_ack is None


# --- ticket closed ----------------------------------------------------------------------------


def test_closed_ticket_cancels_and_supersedes() -> None:
    r = react(facts(), TicketClosed(run_version=7))
    assert (r.action, r.reason) == (Action.CANCEL, "ticket_closed")
    assert r.supersede_gates and r.ticket_closed


def test_deleted_ticket_says_so() -> None:
    assert react(facts(), TicketClosed(run_version=7, deleted=True)).reason == "ticket_deleted"


def test_closed_ticket_after_merge_ends_done_with_incident() -> None:
    r = react(facts(merged=True), TicketClosed(run_version=7))
    assert r.action is Action.FINISH_WITH_INCIDENT and r.supersede_gates and r.ticket_closed


def test_closed_ticket_on_an_ended_run_changes_nothing_but_the_flag() -> None:
    r = react(facts(status=RunStatus.DONE), TicketClosed(run_version=7))
    assert r.action is Action.NONE and r.ticket_closed


# --- PR closed or merged ----------------------------------------------------------------------


def test_pr_closed_by_a_person_cancels() -> None:
    r = react(facts(), PrClosed(run_version=7, merged=False))
    assert (r.action, r.reason) == (Action.CANCEL, "pr_closed")
    assert r.supersede_gates


def merge(**over: Any) -> PrClosed:
    return PrClosed(
        **{"run_version": 7, "merged": True, "merge_sha": "m1", "merged_by": APP, **over}
    )


def test_our_merge_is_recognised_by_receipt_and_author() -> None:
    r = react(facts(our_merges=frozenset({"m1"}), merged=True), merge())
    assert r.action is Action.NONE and not r.supersede_gates and r.audit_action is None


@pytest.mark.parametrize(
    "over",
    [
        {"merge_sha": "zz"},  # no receipt for this merge
        {"merged_by": "mallory"},  # a receipt, but not our author
        {"merged_by": None},  # unknown author fails closed
        {"merge_sha": None},
    ],
)
def test_outside_merge_blocks_and_is_flagged(over: dict[str, Any]) -> None:
    r = react(facts(our_merges=frozenset({"m1"})), merge(**over))
    assert (r.action, r.reason) == (Action.BLOCK, "outside_merge")
    assert r.supersede_gates is True
    assert r.audit_action == "moving.outside_merge"
    assert r.audit_data["flagged"] is True


# --- refusing events --------------------------------------------------------------------------


def test_a_stale_event_is_refused_by_run_version() -> None:
    with pytest.raises(StaleMovingEventError):
        react(facts(run_version=8), commit())
    with pytest.raises(PermanentError):
        react(facts(run_version=8), TicketClosed(run_version=7))


@pytest.mark.parametrize(
    "event",
    [
        lambda: commit(" "),
        lambda: edit(""),
        lambda: TicketEdited(run_version=7, revision="r", editor="a", editor_is_member="yes"),  # type: ignore[arg-type]
        lambda: PrClosed(run_version=7, merged="no"),  # type: ignore[arg-type]
        lambda: CommitPushed(run_version=-1, sha="x"),
        lambda: TicketClosed(run_version=7, deleted=1),  # type: ignore[arg-type]
    ],
)
def test_a_malformed_event_is_refused(event: Any) -> None:
    with pytest.raises(MovingEventError):
        event()


def test_react_refuses_an_event_it_does_not_know() -> None:
    with pytest.raises(MovingEventError):
        react(facts(), object())  # type: ignore[arg-type]


# --- the decision-time check ------------------------------------------------------------------


def test_a_closed_ticket_cannot_be_approved() -> None:
    with pytest.raises(TicketClosedError):
        check_decision(MoveState(ticket_closed=True), DecisionKind.APPROVE, acknowledged=None)
    # a veto is never delayed, and an open ticket is fine
    check_decision(MoveState(ticket_closed=True), DecisionKind.REJECT, acknowledged=None)
    check_decision(MoveState(), DecisionKind.APPROVE, acknowledged=None)


def test_an_approval_after_an_edit_needs_the_matching_acknowledgement() -> None:
    state = MoveState(pending_revision="rev2")
    for wrong in (None, "rev1", ""):
        with pytest.raises(AcknowledgementRequiredError):
            check_decision(state, DecisionKind.APPROVE, acknowledged=wrong)
    check_decision(state, DecisionKind.APPROVE, acknowledged="rev2")
    check_decision(state, DecisionKind.REQUEST_CHANGES, acknowledged=None)


# --- against the store ------------------------------------------------------------------------


def head_subject(tag: str = "a") -> Subject:
    return Subject(
        patch_id=f"patch-{tag}",
        ticket_revision=f"rev-{tag}",
        head_sha=f"sha-{tag}",
        evidence_digest=f"ev-{tag}",
        attention_digest=f"att-{tag}",
    )


class OneRoleAll:
    """A quorum of two ``reviewer`` approvals so that one vote leaves the gate open."""

    def quorum(self, scope: Any, gate: Gate) -> list[Any]:
        from sto.gates.service import QuorumRule

        return [QuorumRule("reviewer", 2)]

    def roles(self, scope: Any, gate: Gate, actor: str) -> list[str]:
        return ["reviewer"]

    def refusals(self, scope: Any, gate: Gate, actor: str, *, negative: bool) -> list[str]:
        return []


def open_with_vote(store: MemoryStore) -> tuple[GateService, Subject]:
    svc = GateService(store, policy=OneRoleAll())
    subject = head_subject()
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    svc.decide(
        TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE, actor="alice",
        surface=Surface.UI, subject_digest=subject.digest(),
    )  # fmt: skip
    return svc, subject


def stored_gate(store: MemoryStore) -> Gate:
    item = store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1"))
    assert item is not None
    return from_wire(Gate, item.data)


def votes(store: MemoryStore) -> int:
    return len(store.query(TEAM, f"RUN#{RUN}", sk_prefix="VOTE#").items)


def audit_actions(store: MemoryStore) -> list[str]:
    return [i.data["action"] for i in store.query(TEAM, audit_pk(RUN), table=AUDIT).items]


def run_reaction(store: MemoryStore, reaction: Any) -> None:
    ops = apply_reaction(store, TEAM, RUN, reaction, actor="system", at=1)
    store.transact(TEAM, ops)


def test_an_external_commit_supersedes_the_gate_and_an_old_approval_cannot_land() -> None:
    store = MemoryStore()
    svc, subject = open_with_vote(store)
    run_reaction(store, react(facts(), commit()))
    assert stored_gate(store).status is GateStatus.SUPERSEDED
    assert "moving.external_commit" in audit_actions(store)
    with pytest.raises(GateClosedError):
        svc.decide(
            TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE, actor="bob",
            surface=Surface.UI, subject_digest=subject.digest(),
        )  # fmt: skip


def test_an_edit_drops_votes_and_leaves_the_gate_open_with_a_pending_revision() -> None:
    store = MemoryStore()
    open_with_vote(store)
    assert votes(store) == 1
    run_reaction(store, react(facts(), edit()))
    assert votes(store) == 0
    assert stored_gate(store).is_open
    state = load_state(store, TEAM, RUN)
    assert state.pending_revision == "rev2" and not state.ticket_closed
    with pytest.raises(AcknowledgementRequiredError):
        check_decision(state, DecisionKind.APPROVE, acknowledged=None)


def test_a_closed_ticket_supersedes_open_gates_and_is_remembered() -> None:
    store = MemoryStore()
    open_with_vote(store)
    run_reaction(store, react(facts(), TicketClosed(run_version=7)))
    assert stored_gate(store).status is GateStatus.SUPERSEDED
    state = load_state(store, TEAM, RUN)
    assert state.ticket_closed
    with pytest.raises(TicketClosedError):
        check_decision(state, DecisionKind.APPROVE, acknowledged=None)


def test_an_outside_merge_is_flagged_in_the_audit_chain() -> None:
    store = MemoryStore()
    open_with_vote(store)
    run_reaction(store, react(facts(), merge()))
    item = [
        i for i in store.query(TEAM, audit_pk(RUN), table=AUDIT).items
        if i.data["action"] == "moving.outside_merge"
    ]  # fmt: skip
    assert len(item) == 1 and item[0].data["data"]["flagged"] is True


def test_closed_gates_are_left_alone() -> None:
    store = MemoryStore()
    svc = GateService(store)
    subject = head_subject()
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    svc.decide(
        TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE, actor="alice",
        surface=Surface.UI, subject_digest=subject.digest(),
    )  # fmt: skip
    run_reaction(store, react(facts(), commit()))
    assert stored_gate(store).status is GateStatus.APPROVED


def test_a_no_op_reaction_writes_nothing() -> None:
    store = MemoryStore()
    open_with_vote(store)
    assert (
        apply_reaction(store, TEAM, RUN, react(facts(), commit("h1")), actor="system", at=1) == []
    )


def test_facts_are_immutable_and_checked() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts().stage = "x"  # type: ignore[misc]
    with pytest.raises(MovingEventError):
        facts(external_commit_cap=-1)
