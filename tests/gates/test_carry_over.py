"""D2-09: carry-over and invalidation (PLAN 4.6, invariant G13).

Every G13 case is a named ``test_G13_*``. A refusal test names the *reason* it expects, and the
baseline (``World().decide()``) carries, so a refusal for the wrong reason, or an evaluator that
refuses everything, fails. Fixtures are synthetic.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

import pytest

from sto.config.schema import Quorum
from sto.domain import (
    DecisionKind,
    Gate,
    GateId,
    GateStatus,
    GateType,
    RunId,
    Subject,
)
from sto.gates.carry_over import (
    BaseRange,
    CarryOverDecision,
    Citation,
    GateInstance,
    Vote,
    evaluate_carry_over,
    invalidated_by_close,
    invalidated_by_patch,
)
from sto.gates.subject import RoundRecord, evidence_digest, plan_round

pytestmark = pytest.mark.unit

ISS = "https://idp.example.test"
NAME = "review"
B1, B2 = "b" * 40, "c" * 40
EMPTY_EVIDENCE = evidence_digest(())


def actor(sub: str) -> str:
    return f"{ISS}|{sub}"


ALICE, BOB = actor("alice"), actor("bob")


def subject(head: str, patch: str = "P1", ticket: str = "T1", attention: str = "A1") -> Subject:
    return Subject(
        patch_id=patch,
        ticket_revision=ticket,
        head_sha=head,
        evidence_digest=EMPTY_EVIDENCE,
        attention_digest=attention,
    )


def vote(
    who: str = ALICE, role: str = "reviewer", kind: DecisionKind = DecisionKind.APPROVE
) -> Vote:
    return Vote(who, role, kind)


def allow_all(_actor: str, _role: str, _gate: Gate) -> bool:
    return True


class World:
    """A run's history for one gate, built round by round, and the re-entry that follows it."""

    def __init__(self, gate_type: GateType = GateType.REVIEW) -> None:
        self.run_id = RunId.new()
        self.gate_type = gate_type
        self.history: list[GateInstance] = []
        self.asked: list[str] = []

    def add(
        self,
        status: GateStatus,
        patch: str = "P1",
        *,
        votes: tuple[Vote, ...] | None = None,
        ticket: str = "T1",
        attention: str = "A1",
        merge_base: str = B1,
        carried_from: Gate | None = None,
        head: str | None = None,
    ) -> Gate:
        rnd = len(self.history) + 1
        if votes is None:
            votes = () if carried_from is not None else (vote(),)
        gate = Gate(
            GateId.new(),
            self.run_id,
            NAME,
            self.gate_type,
            rnd,
            subject(head or f"{rnd:040x}", patch, ticket, attention),
            status,
            closed_by=None if status is GateStatus.OPEN else ALICE,
        )
        self.history.append(
            GateInstance(
                gate,
                merge_base=merge_base,
                votes=votes,
                carried_from=None if carried_from is None else carried_from.id,
            )
        )
        return gate

    def decide(
        self,
        *,
        patch: str = "P1",
        ticket: str = "T1",
        attention: str = "A1",
        carry_over: str = "patch_id",
        quorum: tuple[Quorum, ...] | None = None,
        merge_base: str = B1,
        patch_files: frozenset[str] = frozenset({"app.py"}),
        base_range: BaseRange | None = None,
        recheck: Callable[[str, str, Gate], bool] | None = None,
        patch_ids_since: tuple[str, ...] | None = None,
        previous_gate_id: GateId | None = None,
        round_: int | None = None,
        history: list[GateInstance] | None = None,
    ) -> CarryOverDecision:
        latest = max(self.history, key=lambda i: i.gate.round).gate if self.history else None
        history = self.history if history is None else history
        rnd = round_ if round_ is not None else (latest.round + 1 if latest else 1)
        sub = subject(f"{900 + rnd:040x}", patch, ticket, attention)
        previous = None if latest is None else RoundRecord.from_gate(latest, "diff-prev")
        # plan_round only reads the type to hold a qa gate to V14 (evidence it must judge) and a
        # pre_push gate to a pre-push subject; neither is under test here, so plan as a review.
        plan = plan_round(
            name=NAME,
            gate_type=GateType.REVIEW,
            previous=previous,
            subject=sub,
            diff_ref="diff-now",
            evidence={},
            expected_stages=(),
        )
        if previous_gate_id is not None:
            plan = dataclasses.replace(plan, previous_gate_id=previous_gate_id)
        if round_ is not None:
            plan = dataclasses.replace(plan, round=round_)
        gate = Gate(GateId.new(), self.run_id, NAME, self.gate_type, rnd, sub)

        def port(who: str, role: str, g: Gate) -> bool:
            self.asked.append(who)
            return (recheck or allow_all)(who, role, g)

        return evaluate_carry_over(
            gate=gate,
            plan=plan,
            carry_over=carry_over,  # type: ignore[arg-type]
            history=tuple(history),
            quorum=quorum,
            merge_base=merge_base,
            patch_files=patch_files,
            base_range=base_range,
            patch_ids_since=(patch,) if patch_ids_since is None else patch_ids_since,
            recheck=port,
        )


def refused(result: CarryOverDecision, reason: str) -> None:
    assert not result.carried
    assert result.citation is None
    assert any(r == reason or r.startswith(reason + ":") for r in result.reasons), result.reasons


def approved_world() -> tuple[World, Gate]:
    w = World()
    g = w.add(GateStatus.APPROVED)
    return w, g


A, X = GateStatus.APPROVED, GateStatus


# --- the baseline -------------------------------------------------------------------------------


def test_G13_same_patch_with_carry_over_patch_id_closes_with_a_citation() -> None:
    w, r1 = approved_world()
    result = w.decide()
    assert result.carried
    assert result.reasons == ()
    c = result.citation
    assert c is not None
    assert (c.gate_id, c.round, c.origin_gate_id, c.origin_round) == (r1.id, 1, r1.id, 1)
    assert c.patch_id == "P1"
    assert c.approvers == (ALICE,)


def test_G13_carry_over_none_requires_a_new_decision() -> None:
    w, _ = approved_world()
    refused(w.decide(carry_over="none"), "carry_over_none")


def test_G13_an_unknown_carry_over_setting_fails_closed() -> None:
    w, _ = approved_world()
    refused(w.decide(carry_over="patch-id"), "carry_over_none")


def test_G13_a_first_round_has_nothing_to_carry() -> None:
    refused(World().decide(), "no_previous_instance")


def test_G13_a_whitespace_only_change_is_a_different_patch() -> None:
    # the patch ids differ (D2-08 proves a whitespace change moves the id); here that means no carry
    w, _ = approved_world()
    refused(w.decide(patch="P1-reindented"), "patch_changed")


# --- condition 1: the most recent closed instance approved, not invalidated -------------------


def test_G13_P1_P2_P1_asks_again() -> None:
    w = World()
    w.add(A, "P1")
    w.add(A, "P2")  # a person approved the changed patch
    refused(w.decide(patch="P1"), "patch_changed")


def test_G13_P1_P2_P1_asks_again_when_the_p2_round_was_not_approved() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.CHANGES_REQUESTED, "P2")
    refused(w.decide(patch="P1"), "latest_not_approved")


def test_G13_P1_P2_P1_asks_again_even_if_the_old_round_still_reads_approved() -> None:
    # nothing advanced round 1 to INVALIDATED: the walk itself must see round 2 in between
    w = World()
    w.add(A, "P1")
    w.add(A, "P2", merge_base=B1)
    result = w.decide(patch="P1")
    assert not result.carried


def test_G13_approve_request_changes_same_patch_asks_again() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.CHANGES_REQUESTED, "P1")
    refused(w.decide(patch="P1"), "latest_not_approved")


def test_G13_approve_request_changes_same_patch_asks_again_after_invalidation() -> None:
    w = World()
    w.add(X.INVALIDATED, "P1")  # what the gate service leaves behind
    w.add(X.CHANGES_REQUESTED, "P1")
    refused(w.decide(patch="P1"), "latest_not_approved")


def test_G13_approve_superseded_same_patch_asks_again() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.SUPERSEDED, "P1")
    refused(w.decide(patch="P1"), "latest_not_approved")


@pytest.mark.parametrize(
    "status",
    [
        X.CHANGES_REQUESTED,
        X.RETEST,
        X.REJECTED,
        X.EXPIRED,
        X.SUPERSEDED,
        X.CANCELLED,
        X.INVALIDATED,
    ],
)
def test_G13_any_non_approved_close_after_an_approval_blocks_carry_over(status: GateStatus) -> None:
    w = World()
    w.add(A, "P1")
    w.add(status, "P1")
    refused(w.decide(), "latest_not_approved")


def test_G13_an_expired_close_blocks_even_though_timers_do_not_invalidate_earlier_rounds() -> None:
    # gates/timers.py closes EXPIRED and leaves round 1 APPROVED. carry_over must not rely on it.
    w = World()
    r1 = w.add(A, "P1")
    w.add(X.EXPIRED, "P1")
    result = w.decide()
    refused(result, "latest_not_approved")
    assert w.history[0].gate.status is X.APPROVED  # still reads approved: the walk is what refuses
    closing = w.history[1].gate
    assert invalidated_by_close(tuple(w.history[:1]), closing) == (r1.id,)


def test_G13_an_approval_that_followed_a_veto_is_a_fresh_decision_and_can_be_cited() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.CHANGES_REQUESTED, "P1")
    r3 = w.add(A, "P1", votes=(vote(BOB),))  # a person approved again after the veto
    result = w.decide()
    assert result.carried
    assert result.citation is not None
    assert result.citation.gate_id == r3.id
    assert result.citation.approvers == (BOB,)


def test_G13_an_open_earlier_instance_never_carries() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.OPEN, "P1")
    refused(w.decide(), "latest_not_approved")


# --- only the most recent closed instance can be cited ------------------------------------------


def test_G13_only_the_most_recent_closed_instance_can_be_cited() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(X.CHANGES_REQUESTED, "P1")
    # the plan links the new round to round 1, skipping the veto
    refused(w.decide(previous_gate_id=r1.id), "not_most_recent")


def test_G13_a_plan_linked_to_nothing_cannot_cite() -> None:
    w, _ = approved_world()
    refused(w.decide(round_=2, previous_gate_id=GateId.new()), "not_most_recent")


def test_G13_a_round_that_skips_the_most_recent_cannot_cite() -> None:
    w, _ = approved_world()
    refused(w.decide(round_=3), "inconsistent_history")


def test_G13_history_of_another_gate_is_refused() -> None:
    w, _ = approved_world()
    other = dataclasses.replace(w.history[0].gate, name="qa")
    bad = [dataclasses.replace(w.history[0], gate=other)]
    refused(w.decide(history=bad), "inconsistent_history")


def test_G13_history_of_another_run_is_refused() -> None:
    w, _ = approved_world()
    other = dataclasses.replace(w.history[0].gate, run_id=RunId.new())
    bad = [dataclasses.replace(w.history[0], gate=other)]
    refused(w.decide(history=bad), "inconsistent_history")


def test_G13_two_instances_of_one_round_are_refused() -> None:
    w, _ = approved_world()
    refused(w.decide(history=[w.history[0], w.history[0]]), "inconsistent_history")


def test_G13_a_current_round_not_after_the_history_is_refused() -> None:
    w, _ = approved_world()
    refused(w.decide(round_=1), "inconsistent_history")


# --- a chain of carry-overs ---------------------------------------------------------------------


def test_G13_a_carried_round_can_itself_be_carried_and_cites_the_original_decision() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(A, "P1", carried_from=r1, merge_base=B2)
    result = w.decide(merge_base=B2, base_range=BaseRange(B1, B2, frozenset({"README.md"})))
    assert result.carried
    c = result.citation
    assert c is not None
    assert (c.gate_id, c.round, c.origin_gate_id, c.origin_round) == (r2.id, 2, r1.id, 1)
    assert c.approvers == (ALICE,)
    assert w.asked == [ALICE]


def test_G13_a_chain_is_measured_from_the_original_base_not_the_last_hop() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(A, "P1", carried_from=r1, merge_base=B2)
    # B2 -> B2 alone is empty, but the range from the human's base B1 is what counts
    refused(
        w.decide(merge_base=B2, base_range=BaseRange(B2, B2, frozenset())), "base_range_unknown"
    )


def test_G13_a_chain_that_crosses_a_retest_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(X.RETEST, "P1")
    w.add(A, "P1", carried_from=r1)  # forged: skips round 2, which should have stopped this
    refused(w.decide(), "broken_chain")


def test_G13_a_chain_through_a_retest_round_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(X.RETEST, "P1", carried_from=r1)
    w.add(A, "P1", carried_from=r2)
    refused(w.decide(), "non_approved_close_since:2:RETEST")


def test_G13_a_chain_that_crosses_a_patch_change_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(A, "P2", carried_from=r1)
    w.add(A, "P1", carried_from=r2)
    refused(w.decide(), "patch_changed")


def test_G13_a_carried_round_whose_origin_is_missing_does_not_carry() -> None:
    w = World()
    ghost = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 1, subject("f" * 40), A)
    w.add(A, "P1", carried_from=ghost)
    refused(w.decide(), "broken_chain")


def test_G13_a_carried_round_that_cites_itself_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1")
    inst = dataclasses.replace(w.history[0], carried_from=r1.id)
    refused(w.decide(history=[inst]), "broken_chain")


def test_G13_a_carried_round_that_cites_a_later_round_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(A, "P1", carried_from=r1)
    first = dataclasses.replace(w.history[0], carried_from=r2.id)
    refused(w.decide(history=[first, w.history[1]]), "broken_chain")


# --- partial votes and quorum -------------------------------------------------------------------


def test_G13_partial_votes_on_a_superseded_gate_never_carry() -> None:
    w = World()
    w.add(X.SUPERSEDED, "P1", votes=(vote(ALICE),))
    refused(w.decide(quorum=(Quorum(role="reviewer", count=2),)), "latest_not_approved")


def test_G13_partial_votes_on_a_gate_marked_approved_do_not_carry() -> None:
    w, _ = approved_world()  # one vote
    refused(w.decide(quorum=(Quorum(role="reviewer", count=2),)), "quorum_not_met")


def test_G13_full_quorum_carries() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE), vote(BOB)))
    result = w.decide(quorum=(Quorum(role="reviewer", count=2),))
    assert result.carried
    assert result.citation is not None
    assert result.citation.approvers == (ALICE, BOB)
    assert w.asked == [ALICE, BOB]


def test_G13_one_person_voting_twice_counts_once() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE), vote(ALICE)))
    refused(w.decide(quorum=(Quorum(role="reviewer", count=2),)), "quorum_not_met")


def test_G13_quorum_is_counted_per_role() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE, "dev"), vote(BOB, "dev")))
    quorum = (Quorum(role="dev", count=1), Quorum(role="qa", count=1))
    refused(w.decide(quorum=quorum), "quorum_not_met")


def test_G13_two_quorum_entries_for_one_role_add_up() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE),))
    quorum = (Quorum(role="reviewer", count=1), Quorum(role="reviewer", count=1))
    refused(w.decide(quorum=quorum), "quorum_not_met")


def test_G13_the_current_stricter_quorum_applies() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE),))
    assert w.decide(quorum=None).carried
    refused(w.decide(quorum=(Quorum(role="reviewer", count=2),)), "quorum_not_met")


def test_G13_an_approved_gate_with_no_votes_does_not_carry() -> None:
    w = World()
    w.add(A, "P1", votes=())
    refused(w.decide(), "quorum_not_met")


def test_G13_waived_approvals_are_not_carried() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(kind=DecisionKind.WAIVE),))
    refused(w.decide(), "waiver_not_carried")


def test_G13_a_vote_must_be_an_approval() -> None:
    with pytest.raises(ValueError, match="approve or waive"):
        Vote(ALICE, "reviewer", DecisionKind.REJECT)


# --- condition 3: approvers re-checked through the port -----------------------------------------


def test_G13_an_approver_who_is_no_longer_eligible_blocks_carry_over() -> None:
    w, _ = approved_world()
    refused(w.decide(recheck=lambda who, _r, _g: False), f"approver_ineligible:{ALICE}")


def test_G13_one_ineligible_approver_among_several_blocks_carry_over() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE), vote(BOB)))
    result = w.decide(recheck=lambda who, _r, _g: who != BOB)
    refused(result, f"approver_ineligible:{BOB}")
    assert f"approver_ineligible:{ALICE}" not in result.reasons


def test_G13_the_port_must_answer_true_exactly() -> None:
    w, _ = approved_world()
    refused(w.decide(recheck=lambda who, _r, _g: 1), f"approver_ineligible:{ALICE}")  # type: ignore[arg-type,return-value]
    refused(w.decide(recheck=lambda who, _r, _g: None), f"approver_ineligible:{ALICE}")  # type: ignore[arg-type,return-value]


def test_G13_the_port_is_asked_about_the_new_round() -> None:
    w, _ = approved_world()
    seen: list[Gate] = []

    def port(_who: str, _role: str, gate: Gate) -> bool:
        seen.append(gate)
        return True

    assert w.decide(recheck=port).carried
    assert [(g.name, g.round, g.status) for g in seen] == [(NAME, 2, GateStatus.OPEN)]


def test_G13_a_failing_port_is_a_fault_not_a_verdict() -> None:
    w, _ = approved_world()

    def broken(_who: str, _role: str, _g: Gate) -> bool:
        raise RuntimeError("identity store down")

    with pytest.raises(RuntimeError, match="identity store down"):
        w.decide(recheck=broken)


def test_G13_the_port_is_not_asked_when_another_condition_already_refuses() -> None:
    w, _ = approved_world()
    refused(w.decide(patch="P2"), "patch_changed")
    assert w.asked == []


# --- condition 4: ticket revision ---------------------------------------------------------------


def test_G13_an_edited_ticket_never_carries() -> None:
    w, _ = approved_world()
    refused(w.decide(ticket="T2"), "ticket_revision_changed")


def test_G13_a_ticket_edited_and_restored_between_chain_links_does_not_carry() -> None:
    w = World()
    r1 = w.add(A, "P1", ticket="T1")
    w.add(A, "P1", ticket="T2", carried_from=r1)
    refused(w.decide(ticket="T1"), "ticket_revision_changed")


# --- condition 5: attention digest --------------------------------------------------------------


def test_G13_a_new_attention_item_never_carries() -> None:
    w, _ = approved_world()
    refused(w.decide(attention="A2"), "attention_changed")


def test_G13_an_unchanged_attention_digest_carries_whatever_the_free_text() -> None:
    # free text has no field in the digest (D2-08), so a re-run reviewer leaves it equal
    w, _ = approved_world()
    assert w.decide(attention="A1").carried


# --- condition 6: the base range ----------------------------------------------------------------


def test_G13_a_base_range_that_touches_the_patch_files_never_carries() -> None:
    w, _ = approved_world()
    rng = BaseRange(B1, B2, frozenset({"docs/x.md", "app.py"}))
    result = w.decide(merge_base=B2, base_range=rng)
    refused(result, "base_range_touches_patch")
    assert "base_range_touches_patch:app.py" in result.reasons


def test_G13_a_base_range_that_touches_other_files_carries() -> None:
    w, _ = approved_world()
    assert w.decide(merge_base=B2, base_range=BaseRange(B1, B2, frozenset({"docs/x.md"}))).carried


def test_G13_a_base_range_that_touches_a_parent_directory_of_a_patch_file_never_carries() -> None:
    w, _ = approved_world()
    w.history[0] = w.history[0]  # unchanged: the files below are the patch's
    result = w.decide(
        merge_base=B2,
        patch_files=frozenset({"src/pkg/mod.py"}),
        base_range=BaseRange(B1, B2, frozenset({"src/pkg"})),  # a file became a directory
    )
    refused(result, "base_range_touches_patch")


def test_G13_a_base_range_that_touches_a_child_of_a_patch_path_never_carries() -> None:
    w, _ = approved_world()
    result = w.decide(
        merge_base=B2,
        patch_files=frozenset({"src/pkg"}),
        base_range=BaseRange(B1, B2, frozenset({"src/pkg/mod.py"})),
    )
    refused(result, "base_range_touches_patch")


def test_G13_a_path_that_differs_only_by_case_counts_as_touched() -> None:
    w, _ = approved_world()
    result = w.decide(
        merge_base=B2,
        patch_files=frozenset({"App.py"}),
        base_range=BaseRange(B1, B2, frozenset({"app.py"})),
    )
    refused(result, "base_range_touches_patch")


def test_G13_a_path_that_differs_only_by_unicode_form_counts_as_touched() -> None:
    w, _ = approved_world()
    result = w.decide(
        merge_base=B2,
        patch_files=frozenset({"café.py"}),  # precomposed
        base_range=BaseRange(B1, B2, frozenset({"café.py"})),  # decomposed
    )
    refused(result, "base_range_touches_patch")


def test_G13_a_moved_base_with_no_range_given_does_not_carry() -> None:
    w, _ = approved_world()
    refused(w.decide(merge_base=B2, base_range=None), "base_range_unknown")


def test_G13_a_range_for_other_commits_does_not_carry() -> None:
    w, _ = approved_world()
    refused(
        w.decide(merge_base=B2, base_range=BaseRange("d" * 40, B2, frozenset())),
        "base_range_unknown",
    )
    refused(
        w.decide(merge_base=B2, base_range=BaseRange(B1, "d" * 40, frozenset())),
        "base_range_unknown",
    )


def test_G13_an_unchanged_base_needs_no_range() -> None:
    w, _ = approved_world()
    assert w.decide(merge_base=B1, base_range=None).carried


def test_G13_an_unchanged_base_with_a_touching_range_still_refuses() -> None:
    w, _ = approved_world()
    refused(
        w.decide(merge_base=B1, base_range=BaseRange(B1, B1, frozenset({"app.py"}))),
        "base_range_touches_patch",
    )


def test_G13_a_patch_with_no_known_files_does_not_carry() -> None:
    w, _ = approved_world()
    refused(w.decide(patch_files=frozenset()), "patch_files_unknown")


def test_G13_a_blank_path_is_refused() -> None:
    with pytest.raises(ValueError, match="path"):
        BaseRange(B1, B2, frozenset({" "}))
    w, _ = approved_world()
    with pytest.raises(ValueError, match="path"):
        w.decide(patch_files=frozenset({""}))


# --- carry-over never crosses a retest ----------------------------------------------------------


def test_G13_carry_over_never_crosses_a_retest() -> None:
    w = World(GateType.QA)
    w.add(A, "P1")
    w.add(X.RETEST, "P1")  # same SHA, QA reran
    refused(w.decide(), "latest_not_approved")


def test_G13_carry_over_resumes_after_a_retest_is_decided_by_a_person() -> None:
    w = World(GateType.QA)
    w.add(A, "P1")
    w.add(X.RETEST, "P1")
    w.add(A, "P1", votes=(vote(BOB),))
    result = w.decide()
    assert result.carried
    assert result.citation is not None
    assert result.citation.round == 3


# --- pre-push gates -----------------------------------------------------------------------------


def test_G13_a_pre_push_gate_carries_on_the_same_terms() -> None:
    w = World(GateType.PRE_PUSH)
    gate = Gate(
        GateId.new(),
        w.run_id,
        NAME,
        GateType.PRE_PUSH,
        1,
        Subject.pre_push(base_sha=B1, patch_id="P1", ticket_revision="T1"),
        A,
        closed_by=ALICE,
    )
    w.history.append(GateInstance(gate, merge_base=B1, votes=(vote(),)))
    result = _decide_pre_push(w)
    assert result.carried
    refused(_decide_pre_push(w, ticket="T2"), "ticket_revision_changed")
    refused(_decide_pre_push(w, patch="P2"), "patch_changed")


def _decide_pre_push(w: World, *, patch: str = "P1", ticket: str = "T1") -> CarryOverDecision:
    sub = Subject.pre_push(base_sha=B1, patch_id=patch, ticket_revision=ticket)
    plan = plan_round(
        name=NAME,
        gate_type=GateType.PRE_PUSH,
        previous=RoundRecord.from_gate(w.history[0].gate, "d1"),
        subject=sub,
        diff_ref="d2",
        evidence={},
        expected_stages=(),
    )
    gate = Gate(GateId.new(), w.run_id, NAME, GateType.PRE_PUSH, 2, sub)
    return evaluate_carry_over(
        gate=gate,
        plan=plan,
        carry_over="patch_id",
        history=tuple(w.history),
        quorum=None,
        merge_base=B1,
        patch_files=frozenset({"app.py"}),
        base_range=None,
        patch_ids_since=(patch,),
        recheck=allow_all,
    )


# --- several refusals at once -------------------------------------------------------------------


def test_G13_every_failing_condition_is_reported() -> None:
    w, _ = approved_world()
    result = w.decide(patch="P2", ticket="T2", attention="A2", patch_files=frozenset())
    for reason in (
        "patch_changed",
        "ticket_revision_changed",
        "attention_changed",
        "patch_files_unknown",
    ):
        assert reason in result.reasons


def test_G13_the_decision_cannot_be_built_inconsistently() -> None:
    with pytest.raises(ValueError, match="citation and no reasons"):
        CarryOverDecision(carried=True, reasons=("patch_changed",), citation=None)
    with pytest.raises(ValueError, match="needs a reason"):
        CarryOverDecision(carried=False, reasons=(), citation=None)


# --- invalidation -------------------------------------------------------------------------------


def test_G13_a_non_approved_close_invalidates_every_earlier_approved_round() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(A, "P1", carried_from=r1)
    w.add(X.INVALIDATED, "P1")  # already voided: not listed again
    w.add(X.REJECTED, "P0")  # not approved: not listed
    closing = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 5, subject("a" * 40), X.RETEST)
    assert invalidated_by_close(tuple(w.history), closing) == (r1.id, r2.id)


@pytest.mark.parametrize(
    "status",
    [X.CHANGES_REQUESTED, X.RETEST, X.REJECTED, X.EXPIRED, X.SUPERSEDED, X.CANCELLED],
)
def test_G13_each_non_approved_close_invalidates(status: GateStatus) -> None:
    w, r1 = approved_world()
    closing = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 2, subject("a" * 40), status)
    assert invalidated_by_close(tuple(w.history), closing) == (r1.id,)


def test_G13_an_approval_invalidates_nothing() -> None:
    w, _ = approved_world()
    closing = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 2, subject("a" * 40), A)
    assert invalidated_by_close(tuple(w.history), closing) == ()


def test_G13_a_close_leaves_later_rounds_and_other_gates_alone() -> None:
    w, r1 = approved_world()
    later = w.add(A, "P1", votes=(vote(BOB),))
    other = dataclasses.replace(w.history[0].gate, name="qa", id=GateId.new())
    history = (*w.history, dataclasses.replace(w.history[0], gate=other))
    closing = dataclasses.replace(w.history[1].gate, status=X.REJECTED, round=2)
    # round 2 closes REJECTED: only round 1 is earlier. The qa gate and round 2 itself stay.
    assert invalidated_by_close(history, closing) == (r1.id,)
    assert later.id not in invalidated_by_close(history, closing)


def test_G13_a_close_that_is_still_open_invalidates_nothing() -> None:
    w, _ = approved_world()
    still_open = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 2, subject("a" * 40))
    assert invalidated_by_close(tuple(w.history), still_open) == ()


def test_G13_a_patch_change_invalidates_approved_rounds_of_the_old_patch() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(A, "P2")
    r3 = w.add(A, "P1", carried_from=r1)
    assert invalidated_by_patch(tuple(w.history), "P2", gate=w.history[-1].gate) == (r1.id, r3.id)
    assert invalidated_by_patch(tuple(w.history), "P1", gate=w.history[-1].gate) == (
        w.history[1].gate.id,
    )


def test_G13_a_patch_change_leaves_closed_non_approved_rounds_alone() -> None:
    w = World()
    w.add(X.REJECTED, "P1")
    assert invalidated_by_patch(tuple(w.history), "P2", gate=w.history[-1].gate) == ()


def test_G13_a_patch_invalidated_round_is_not_revived_by_returning_to_the_patch() -> None:
    w = World()
    r1 = w.add(X.INVALIDATED, "P1")  # the patch moved to P2 and its round was voided
    w.add(X.SUPERSEDED, "P2")
    refused(w.decide(patch="P1"), "latest_not_approved")
    assert r1.status is X.INVALIDATED


# --- inputs are checked, and a plan that does not fit the gate is refused ----------


@pytest.mark.parametrize(
    "bad",
    ["alice", f"{ISS}|", "|alice", f" {ISS}|alice", f"{ISS}|alice ", f"{ISS}|ali\nce", "", " "],
)
def test_G13_a_vote_actor_must_be_issuer_bar_subject(bad: str) -> None:
    with pytest.raises(ValueError, match="vote actor"):
        Vote(bad, "reviewer")


def test_G13_a_vote_actor_must_be_a_string_and_the_role_not_blank() -> None:
    with pytest.raises(TypeError, match="vote actor"):
        Vote(None, "reviewer")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="vote role"):
        Vote(ALICE, " ")


def test_G13_instance_inputs_are_checked() -> None:
    w, _ = approved_world()
    gate = w.history[0].gate
    with pytest.raises(TypeError, match="gate"):
        GateInstance("g", B1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="merge_base"):
        GateInstance(gate, " ")
    with pytest.raises(TypeError, match="votes"):
        GateInstance(gate, B1, votes="alice")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="votes"):
        GateInstance(gate, B1, votes=(ALICE,))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="carried_from"):
        GateInstance(gate, B1, carried_from="x")  # type: ignore[arg-type]
    assert GateInstance(gate, B1, votes=[vote()]).votes == (vote(),)  # type: ignore[arg-type]


def test_G13_a_list_of_paths_is_not_a_string() -> None:
    with pytest.raises(TypeError, match="path"):
        BaseRange(B1, B2, "app.py")  # type: ignore[arg-type]
    w, _ = approved_world()
    with pytest.raises(TypeError, match="path"):
        w.decide(patch_files="app.py")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="from_base"):
        BaseRange(" ", B2, frozenset())
    with pytest.raises(ValueError, match="to_base"):
        BaseRange(B1, " ", frozenset())


def test_G13_evaluate_checks_its_inputs() -> None:
    w, _ = approved_world()
    with pytest.raises(ValueError, match="merge_base"):
        w.decide(merge_base=" ")
    with pytest.raises(TypeError, match="base_range"):
        w.decide(base_range="x")  # type: ignore[arg-type]


def test_G13_a_gate_that_is_not_open_is_refused() -> None:
    w, r1 = approved_world()
    sub = subject("9" * 40)
    plan = plan_round(
        name=NAME,
        gate_type=GateType.REVIEW,
        previous=RoundRecord.from_gate(r1, "d1"),
        subject=sub,
        diff_ref="d2",
        evidence={},
        expected_stages=(),
    )
    closed = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 2, sub, X.CANCELLED)
    common = {
        "carry_over": "patch_id",
        "history": tuple(w.history),
        "quorum": None,
        "merge_base": B1,
        "patch_files": frozenset({"app.py"}),
        "base_range": None,
        "patch_ids_since": ("P1",),
        "recheck": allow_all,
    }
    refused(evaluate_carry_over(gate=closed, plan=plan, **common), "plan_mismatch")  # type: ignore[arg-type]
    # twin: the same plan and an open gate carries
    ok = dataclasses.replace(closed, status=X.OPEN)
    assert evaluate_carry_over(gate=ok, plan=plan, **common).carried  # type: ignore[arg-type]
    # a plan for another subject, name or round does not fit the gate
    other = dataclasses.replace(plan, subject=subject("8" * 40))
    refused(evaluate_carry_over(gate=ok, plan=other, **common), "plan_mismatch")  # type: ignore[arg-type]
    named = dataclasses.replace(plan, name="qa")
    refused(evaluate_carry_over(gate=ok, plan=named, **common), "plan_mismatch")  # type: ignore[arg-type]
    rounded = dataclasses.replace(plan, round=3)
    refused(evaluate_carry_over(gate=ok, plan=rounded, **common), "plan_mismatch")  # type: ignore[arg-type]


def test_G13_evaluate_wants_a_gate_and_a_plan() -> None:
    w, r1 = approved_world()
    with pytest.raises(TypeError, match="RoundPlan"):
        evaluate_carry_over(
            gate=r1,
            plan="plan",  # type: ignore[arg-type]
            carry_over="patch_id",
            history=(),
            quorum=None,
            merge_base=B1,
            patch_files=frozenset({"a"}),
            base_range=None,
            patch_ids_since=("P1",),
            recheck=allow_all,
        )


def test_G13_the_blocking_round_is_named_in_the_reason() -> None:
    w = World()
    r1 = w.add(A, "P1")
    r2 = w.add(X.RETEST, "P1", carried_from=r1)
    w.add(A, "P1", carried_from=r2)
    result = w.decide()
    assert "non_approved_close_since:2:RETEST" in result.reasons


def test_G13_invalidation_by_patch_needs_a_patch_id() -> None:
    w, _ = approved_world()
    with pytest.raises(ValueError, match="patch_id"):
        invalidated_by_patch(tuple(w.history), " ", gate=w.history[0].gate)


@pytest.mark.parametrize("cls", [Vote, GateInstance, BaseRange, CarryOverDecision, Citation])
def test_G13_records_are_frozen(cls: type) -> None:
    w, _ = approved_world()
    samples = {
        Vote: vote(),
        GateInstance: w.history[0],
        BaseRange: BaseRange(B1, B2, frozenset()),
        CarryOverDecision: w.decide(),
        Citation: w.decide().citation,
    }
    with pytest.raises(dataclasses.FrozenInstanceError):
        samples[cls].extra = 1  # type: ignore[attr-defined]


def test_G13_a_base_range_stores_its_files_as_a_set() -> None:
    assert BaseRange(B1, B2, ["a.py", "a.py"]).files == frozenset({"a.py"})  # type: ignore[arg-type]


# --- pass 1 review: fail-open inputs ----------------------------------------------------


def test_G13_P1_P2_P1_asks_again_when_P2_never_reached_this_gate() -> None:
    w, _ = approved_world()  # round 1 approved P1; the run then pushed P2 and back to P1
    refused(w.decide(patch="P1", patch_ids_since=("P2", "P1")), "patch_changed_since")
    assert w.decide(patch="P1", patch_ids_since=("P1", "P1")).carried  # twin: nothing moved


def test_G13_patch_ids_since_is_required_and_must_not_be_empty() -> None:
    w, _ = approved_world()
    refused(w.decide(patch_ids_since=()), "patch_history_unknown")
    with pytest.raises(TypeError, match="patch_ids_since"):
        w.decide(patch_ids_since="P1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="patch id"):
        w.decide(patch_ids_since=(" ",))


def test_G13_patch_ids_since_is_measured_from_the_human_decision_not_the_last_hop() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(A, "P1", carried_from=r1)
    refused(w.decide(patch_ids_since=("P1", "P2", "P1")), "patch_changed_since")


def test_G13_a_history_with_a_missing_round_does_not_carry() -> None:
    w = World()
    w.add(A, "P1")
    w.add(X.CHANGES_REQUESTED, "P1")
    w.add(A, "P1", votes=(vote(BOB),))
    gap = [w.history[0], w.history[2]]  # round 2, the veto, is not in the list
    refused(w.decide(history=gap), "inconsistent_history")
    assert w.decide().carried  # twin: the whole history carries from round 3


def test_G13_a_history_that_starts_after_round_one_does_not_carry() -> None:
    w = World()
    w.add(A, "P1")
    w.add(A, "P1", votes=(vote(BOB),))
    refused(w.decide(history=[w.history[1]]), "inconsistent_history")


def test_G13_a_carried_round_must_cite_the_round_immediately_before() -> None:
    w = World()
    r1 = w.add(A, "P1")
    w.add(A, "P1", votes=(vote(BOB),))  # round 2, decided by a person
    w.add(A, "P1", carried_from=r1)  # skips round 2
    refused(w.decide(), "broken_chain")


def test_G13_the_port_confirms_the_role_a_person_voted_as() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE, "qa"), vote(BOB, "dev")))
    asked: list[tuple[str, str]] = []

    def port(who: str, role: str, _g: Gate) -> bool:
        asked.append((who, role))
        return True

    assert w.decide(recheck=port, quorum=(Quorum(role="qa", count=1),)).carried
    assert asked == [(ALICE, "qa"), (BOB, "dev")]


def test_G13_someone_who_lost_the_role_they_voted_as_does_not_count_for_it() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE, "qa"),))
    # alice kept another eligible role, but no longer holds qa
    result = w.decide(
        recheck=lambda who, role, _g: role != "qa",
        quorum=(Quorum(role="qa", count=1),),
    )
    refused(result, f"approver_ineligible:{ALICE}")
    assert "quorum_not_met" in result.reasons


def test_G13_only_confirmed_pairs_count_toward_the_quorum() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE, "qa"), vote(BOB, "dev")))
    quorum = (Quorum(role="qa", count=1), Quorum(role="dev", count=1))
    refused(w.decide(quorum=quorum, recheck=lambda who, _r, _g: who == ALICE), "quorum_not_met")


# --- pass 1 review: pins ----------------------------------------------------------------


def test_G13_an_empty_base_range_on_a_moved_base_is_unknown_unless_complete() -> None:
    w, _ = approved_world()
    refused(
        w.decide(merge_base=B2, base_range=BaseRange(B1, B2, frozenset())), "base_range_unknown"
    )
    assert w.decide(merge_base=B2, base_range=BaseRange(B1, B2, frozenset(), complete=True)).carried


def test_G13_an_empty_complete_range_still_refuses_for_other_commits() -> None:
    w, _ = approved_world()
    rng = BaseRange(B2, B2, frozenset(), complete=True)
    refused(w.decide(merge_base=B2, base_range=rng), "base_range_unknown")


def test_G13_a_base_range_complete_flag_is_a_bool() -> None:
    with pytest.raises(TypeError, match="complete"):
        BaseRange(B1, B2, frozenset(), complete="yes")  # type: ignore[arg-type]


def test_G13_a_base_move_in_a_chain_is_measured_from_the_human_decision() -> None:
    w = World()
    r1 = w.add(A, "P1", merge_base=B1)
    w.add(A, "P1", carried_from=r1, merge_base=B2)
    refused(w.decide(merge_base=B2, base_range=None), "base_range_unknown")


def test_G13_a_carry_from_a_retest_origin_refuses() -> None:
    w = World()
    r1 = w.add(X.RETEST, "P1")
    w.add(A, "P1", carried_from=r1)
    refused(w.decide(), "non_approved_close_since:1:RETEST")


def test_G13_history_of_another_gate_type_is_refused() -> None:
    w, _ = approved_world()
    other = dataclasses.replace(w.history[0].gate, type=GateType.QA)
    refused(
        w.decide(history=[dataclasses.replace(w.history[0], gate=other)]), "inconsistent_history"
    )


def test_G13_dot_segments_in_a_path_are_normalised() -> None:
    w, _ = approved_world()
    result = w.decide(
        merge_base=B2,
        patch_files=frozenset({"src/./app.py"}),
        base_range=BaseRange(B1, B2, frozenset({"src/app.py"})),
    )
    refused(result, "base_range_touches_patch")
    assert w.decide(
        merge_base=B2,
        patch_files=frozenset({"src/./app.py"}),
        base_range=BaseRange(B1, B2, frozenset({"src/other.py"})),
    ).carried


def test_G13_a_person_counts_once_in_their_first_role() -> None:
    w = World()
    w.add(A, "P1", votes=(vote(ALICE, "qa"), vote(ALICE, "dev")))
    assert w.decide(quorum=(Quorum(role="qa", count=1),)).carried
    refused(w.decide(quorum=(Quorum(role="dev", count=1),)), "quorum_not_met")


def test_G13_an_empty_quorum_is_never_met() -> None:
    w, _ = approved_world()
    refused(w.decide(quorum=()), "quorum_not_met")


def test_G13_invalidated_by_close_ignores_another_run() -> None:
    w, r1 = approved_world()
    foreign = dataclasses.replace(w.history[0].gate, run_id=RunId.new(), id=GateId.new())
    history = (w.history[0], dataclasses.replace(w.history[0], gate=foreign))
    closing = Gate(GateId.new(), w.run_id, NAME, GateType.REVIEW, 2, subject("a" * 40), X.REJECTED)
    assert invalidated_by_close(history, closing) == (r1.id,)


def test_G13_invalidated_by_patch_filters_by_gate_name_and_run() -> None:
    w, r1 = approved_world()
    other_name = dataclasses.replace(w.history[0].gate, name="qa", id=GateId.new())
    other_run = dataclasses.replace(w.history[0].gate, run_id=RunId.new(), id=GateId.new())
    history = (
        w.history[0],
        dataclasses.replace(w.history[0], gate=other_name),
        dataclasses.replace(w.history[0], gate=other_run),
    )
    assert invalidated_by_patch(history, "P2", gate=r1) == (r1.id,)
