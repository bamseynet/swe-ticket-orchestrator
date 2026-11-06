"""D3-13: moving ticket and PR (PLAN 4.5, invariant G11).

``react`` is pure: one test per row of the PLAN 4.5 table, each with an allowed twin, so a rule
that fires on everything (or nothing) fails. The store tests run the plan against a real
``GateService`` to show that a superseded gate cannot be approved and an old approval never
counts for a moved subject.
"""

# ruff: noqa: PT018  (compound asserts keep each row of PLAN 4.5 on one line)
from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path
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
from sto.gates.hooks import GateHooks, OpenContext, ReadOnly, audit_pk
from sto.gates.moving import (
    AcknowledgementRequiredError,
    Action,
    CommitPushed,
    MoveState,
    MovingEventError,
    MovingFacts,
    MovingTooLargeError,
    PrClosed,
    Reaction,
    StaleMovingEventError,
    TicketClosed,
    TicketClosedError,
    TicketEdited,
    acknowledge_ops,
    apply_reaction,
    check_decision,
    load_state,
    react,
    refuse_closed_ticket,
    refuse_moved_subject,
)
from sto.gates.retry import Backoff
from sto.gates.service import GateClosedError, GateService, GuardContext
from sto.store.memory import MemoryStore
from sto.store.ports import (
    AUDIT,
    MAX_TRANSACTION_OPS,
    ConditionFailedError,
    Key,
    Op,
    Store,
    TeamScope,
)
from sto.store.sqlite import SqliteStore

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
        "unadopted_heads": frozenset(),
        "our_merges": frozenset(),
        "push_attempting": False,
        "return_stage": "ci",
        "external_commits": 0,
        "external_commit_cap": 3,
        "app_login": APP,
        "merge_in_progress": False,
        "seen_revision": None,
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


@pytest.mark.parametrize("sha", ["h1", "h2"])
def test_commit_we_know_changes_nothing(sha: str) -> None:
    # h1 is the head we hold; h2 is a receipt head the run has not adopted yet
    r = react(facts(unadopted_heads=frozenset({"h2"})), commit(sha))
    assert r.action is Action.NONE and not r.supersede_gates


def test_commit_while_our_push_is_attempting_waits() -> None:
    r = react(facts(push_attempting=True), commit())
    assert r.action is Action.DEFER and not r.supersede_gates
    # ... but our own commit is recognised even then
    own = facts(push_attempting=True, unadopted_heads=frozenset({"h2"}))
    assert react(own, commit("h2")).action is Action.NONE


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


def open_with_vote(store: Store) -> tuple[GateService, Subject]:
    svc = GateService(store, policy=OneRoleAll())
    subject = head_subject()
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    svc.decide(
        TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE, actor="alice",
        surface=Surface.UI, subject_digest=subject.digest(),
    )  # fmt: skip
    return svc, subject


def stored_gate(store: Store) -> Gate:
    item = store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1"))
    assert item is not None
    return from_wire(Gate, item.data)


def votes(store: Store) -> int:
    return len(store.query(TEAM, f"RUN#{RUN}", sk_prefix="VOTE#").items)


def audit_actions(store: Store) -> list[str]:
    return [i.data["action"] for i in store.query(TEAM, audit_pk(RUN), table=AUDIT).items]


def run_reaction(store: Store, reaction: Any) -> None:
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
    svc = GateService.unpoliced_for_tests(store)
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


# --- review fixes (pass 1) --------------------------------------------------------------------


def test_force_push_back_to_an_older_own_head_is_external() -> None:
    # We pushed h1 then h2 (the run holds h2). A person force-pushes back to h1: not ours any more.
    r = react(facts(head_sha="h2"), commit("h1"))
    assert r.action is Action.RETURN_TO_STAGE
    assert r.supersede_gates


def test_a_redelivered_member_edit_changes_nothing() -> None:
    seen = facts(seen_revision="rev2")  # rev2 was recorded (and maybe acknowledged) already
    r = react(seen, edit("rev2"))
    assert r.action is Action.NONE
    assert not r.drop_votes
    assert r.require_ack is None


def test_a_redelivered_non_member_edit_does_not_block_again() -> None:
    seen = facts(seen_revision="rev2")
    assert react(seen, edit("rev2", editor_is_member=False)).action is Action.NONE


def test_an_edit_back_to_the_run_revision_still_counts_as_an_edit() -> None:
    r = react(facts(seen_revision="rev2"), edit("rev1"))
    assert r.drop_votes is True
    assert r.audit_data["from"] == "rev2"


def test_our_merge_webhook_before_its_receipt_defers() -> None:
    r = react(facts(merge_in_progress=True), merge())
    assert r.action is Action.DEFER
    assert not r.supersede_gates
    assert r.audit_action is None
    # a recognised merge is still recognised, and with no merge in progress it is outside
    assert (
        react(facts(merge_in_progress=True, our_merges=frozenset({"m1"})), merge()).action
        is Action.NONE
    )
    assert react(facts(), merge()).action is Action.BLOCK


def test_pr_closed_unmerged_does_nothing_to_an_ended_or_merged_run() -> None:
    closed = PrClosed(run_version=7, merged=False)
    assert react(facts(status=RunStatus.DONE), closed).action is Action.NONE
    assert react(facts(merged=True), closed).action is Action.NONE
    assert react(facts(status=RunStatus.DONE, merged=True), closed).action is Action.NONE
    assert react(facts(), closed).action is Action.CANCEL


@pytest.mark.parametrize("extra", [{"merge_sha": "m1"}, {"merged_by": APP}])
def test_unmerged_pr_with_half_a_merge_is_malformed(extra: dict[str, Any]) -> None:
    with pytest.raises(MovingEventError):
        PrClosed(run_version=7, merged=False, **extra)


@pytest.mark.parametrize("bad", [True, "3", 3.0, None])
def test_run_version_must_be_an_int(bad: Any) -> None:
    for build in (
        lambda: CommitPushed(run_version=bad, sha="x"),
        lambda: TicketClosed(run_version=bad),
        lambda: PrClosed(run_version=bad, merged=False),
    ):
        with pytest.raises(MovingEventError):
            build()
    with pytest.raises(MovingEventError):
        facts(run_version=bad)


def test_ticket_close_on_a_cancelling_run_supersedes_gates_without_a_second_cancel() -> None:
    r = react(facts(status=RunStatus.CANCELLING), TicketClosed(run_version=7))
    assert r.action is Action.NONE
    assert r.supersede_gates
    assert r.ticket_closed
    done = react(facts(status=RunStatus.DONE), TicketClosed(run_version=7))
    assert not done.supersede_gates


def test_the_state_remembers_the_last_revision_seen() -> None:
    store = MemoryStore()
    open_with_vote(store)
    run_reaction(store, react(facts(), edit()))
    assert load_state(store, TEAM, RUN).last_revision == "rev2"


def test_acknowledging_clears_the_pending_revision() -> None:
    store = MemoryStore()
    open_with_vote(store)
    run_reaction(store, react(facts(), edit()))
    assert acknowledge_ops(store, TEAM, RUN, "rev1") == []  # the wrong revision clears nothing
    store.transact(TEAM, acknowledge_ops(store, TEAM, RUN, "rev2"))
    state = load_state(store, TEAM, RUN)
    assert state.pending_revision is None
    assert state.last_revision == "rev2"
    check_decision(state, DecisionKind.APPROVE, acknowledged=None)


def test_a_later_member_edit_never_clears_an_untrusted_pending_revision() -> None:
    store = MemoryStore()
    run_reaction(store, react(facts(has_open_gate=False), edit("rev2", editor_is_member=False)))
    assert load_state(store, TEAM, RUN).pending_revision == "rev2"
    later = facts(has_open_gate=False, seen_revision="rev2")
    run_reaction(store, react(later, edit("rev3")))
    state = load_state(store, TEAM, RUN)
    assert state.pending_revision == "rev2"
    assert state.last_revision == "rev3"


def test_a_closed_ticket_refuses_a_new_gate_atomically() -> None:
    store = MemoryStore()
    hooks = GateHooks()
    hooks.on_open(refuse_closed_ticket)
    svc = GateService.unpoliced_for_tests(store, hooks=hooks)
    cmd = OpenGate(RUN, "review", GateType.REVIEW, 1, head_subject())
    run_reaction(store, react(facts(has_open_gate=False), TicketClosed(run_version=7)))
    with pytest.raises(TicketClosedError):
        svc.open_gate(TEAM, cmd)
    assert store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1")) is None


def test_an_open_ticket_still_opens_gates_and_the_hook_checks_the_state_version() -> None:
    store = MemoryStore()
    hooks = GateHooks()
    hooks.on_open(refuse_closed_ticket)
    svc = GateService.unpoliced_for_tests(store, hooks=hooks)
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, head_subject()))
    assert stored_gate(store).is_open
    # the hook returns a Check on MOVE#state, so a close that commits between the read and the
    # write fails the open's transaction
    gate = stored_gate(store)
    ops = refuse_closed_ticket(OpenContext(ReadOnly(store), TEAM, gate))
    run_reaction(store, react(facts(), TicketClosed(run_version=7)))
    with pytest.raises(ConditionFailedError):
        store.transact(TEAM, ops)


def test_a_reaction_that_does_not_fit_one_transaction_is_refused() -> None:
    store = MemoryStore()
    svc = GateService.unpoliced_for_tests(store)
    for n in range(MAX_TRANSACTION_OPS):
        svc.open_gate(TEAM, OpenGate(RUN, f"g{n}", GateType.REVIEW, 1, head_subject()))
    with pytest.raises(MovingTooLargeError):
        apply_reaction(store, TEAM, RUN, react(facts(), commit()), actor="system", at=1)


# --- the decide transaction pins MOVE#state (D3-26) -------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def any_store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Store]:
    if request.param == "memory":
        yield MemoryStore()
        return
    sqlite = SqliteStore(tmp_path / "sto.db")
    yield sqlite
    sqlite.close()


def raced_service(store: Store, *, quorum: bool, race: Any, fired: list[int]) -> GateService:
    """A service whose guard is the real one, followed by ``race`` once: the ticket edit commits
    after the guard has read ``MOVE#state`` and before the decision is written."""

    def guard(ctx: GuardContext) -> list[Op]:
        ops = refuse_moved_subject(ctx)
        if not fired:
            fired.append(1)
            race()
        return ops

    retry = Backoff(attempts=5, sleep=lambda _: None)
    if quorum:
        return GateService(store, policy=OneRoleAll(), guards=(guard,), retry=retry)
    return GateService.unpoliced_for_tests(store, guards=(guard,), retry=retry)


def approve(svc: GateService, subject: Subject, actor: str) -> Any:
    return svc.decide(
        TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.APPROVE, actor=actor,
        surface=Surface.UI, subject_digest=subject.digest(),
    )  # fmt: skip


def test_a_sub_quorum_vote_after_a_ticket_edit_never_lands(any_store: Store) -> None:
    store = any_store
    subject = head_subject()
    setup = GateService(store, policy=OneRoleAll())
    setup.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    approve(setup, subject, "alice")  # the first of two votes, before the edit
    fired: list[int] = []
    svc = raced_service(
        store, quorum=True, fired=fired, race=lambda: run_reaction(store, react(facts(), edit()))
    )
    with pytest.raises(AcknowledgementRequiredError):
        approve(svc, subject, "bob")
    assert fired == [1]
    assert votes(store) == 0  # alice's vote was dropped by the edit, bob's never landed
    assert stored_gate(store).is_open
    assert load_state(store, TEAM, RUN).pending_revision == "rev2"


def test_a_closing_vote_after_a_ticket_edit_never_lands(any_store: Store) -> None:
    store = any_store
    subject = head_subject()
    plain = GateService.unpoliced_for_tests(store)
    plain.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    fired: list[int] = []
    svc = raced_service(
        store, quorum=False, fired=fired, race=lambda: run_reaction(store, react(facts(), edit()))
    )
    with pytest.raises(AcknowledgementRequiredError):
        approve(svc, subject, "alice")
    assert fired == [1]
    gate = stored_gate(store)
    assert gate.is_open and gate.status is GateStatus.OPEN
    assert not store.query(TEAM, f"RUN#{RUN}", sk_prefix="DEC#").items
    assert not store.query(TEAM, f"RUN#{RUN}", sk_prefix="OUT#").items  # no gate.closed outbox


def test_a_ticket_close_between_guard_and_decide_never_lets_the_approval_land(
    any_store: Store,
) -> None:
    store = any_store
    subject = head_subject()
    GateService.unpoliced_for_tests(store).open_gate(
        TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject)
    )
    # a close that does not supersede the gate, so only the MOVE#state check can stop the vote
    closing = Reaction(ticket_closed=True, audit_action="moving.ticket_closed")
    svc = raced_service(store, quorum=False, fired=[], race=lambda: run_reaction(store, closing))
    with pytest.raises(TicketClosedError):
        approve(svc, subject, "alice")
    assert stored_gate(store).is_open


def test_an_edit_after_the_guard_is_not_reported_as_success_even_when_acknowledged_later(
    any_store: Store,
) -> None:
    """After the refusal the person acknowledges the new revision; the next approval lands."""
    store = any_store
    subject = head_subject()
    GateService.unpoliced_for_tests(store).open_gate(
        TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject)
    )
    svc = raced_service(
        store, quorum=False, fired=[], race=lambda: run_reaction(store, react(facts(), edit()))
    )
    with pytest.raises(AcknowledgementRequiredError):
        approve(svc, subject, "alice")
    store.transact(TEAM, acknowledge_ops(store, TEAM, RUN, "rev2"))
    assert approve(svc, subject, "alice").closed
    assert stored_gate(store).status is GateStatus.APPROVED


def test_a_veto_is_never_held_back_by_a_moved_ticket(any_store: Store) -> None:
    store = any_store
    subject = head_subject()
    GateService.unpoliced_for_tests(store).open_gate(
        TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject)
    )
    run_reaction(store, react(facts(), edit()))
    run_reaction(store, Reaction(ticket_closed=True, audit_action="moving.ticket_closed"))
    svc = raced_service(store, quorum=False, fired=[1], race=lambda: None)
    decided = svc.decide(
        TEAM, run_id=RUN, gate="review", round=1, kind=DecisionKind.REJECT, actor="alice",
        surface=Surface.UI, subject_digest=subject.digest(), comment="no",
    )  # fmt: skip
    assert decided.closed and stored_gate(store).status is GateStatus.REJECTED


def test_an_unmoved_ticket_lets_a_vote_land_and_pins_the_state_version(any_store: Store) -> None:
    store = any_store
    subject = head_subject()
    svc = raced_service(store, quorum=False, fired=[1], race=lambda: None)
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    ctx = GuardContext(ReadOnly(store), TEAM, stored_gate(store), DecisionKind.APPROVE, "alice")
    checks = refuse_moved_subject(ctx)
    assert len(checks) == 1  # Check(MOVE#state, Absent) while nothing was ever recorded
    assert approve(svc, subject, "alice").closed


def test_the_app_builder_wires_both_moving_rules(any_store: Store) -> None:
    from sto.api.app import moving_aware_gates

    store = any_store
    svc = moving_aware_gates(store, OneRoleAll())
    subject = head_subject()
    svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, subject))
    run_reaction(store, react(facts(), edit()))
    with pytest.raises(AcknowledgementRequiredError):  # the guard is registered
        approve(svc, subject, "alice")
    run_reaction(store, react(facts(seen_revision="rev2"), TicketClosed(run_version=7)))
    with pytest.raises(TicketClosedError):  # on_open is registered
        svc.open_gate(TEAM, OpenGate(RUN, "qa", GateType.QA, 1, subject))
