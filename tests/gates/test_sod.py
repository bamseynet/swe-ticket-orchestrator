"""D3-05: separation of duties (PLAN 9.4), invariant G7 and threat T8.

Every test builds one decision and asks :func:`sto.gates.sod.evaluate`. A refusal test names the
*reason* it expects, and each has an allowed twin (``base`` allows the candidate), so a refusal for
the wrong reason, or an evaluator that refuses everything, fails.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from sto.config.schema import Floors, SeparationOfDuties
from sto.domain import Gate, GateId, GateType, RunId, Subject
from sto.gates.sod import (
    AdminAction,
    Approval,
    Commit,
    Exclusion,
    Pusher,
    Resolution,
    RunFacts,
    SodVerdict,
    evaluate,
)
from sto.identity.mapping import ServiceIdentity, UserIdentity

TEAM = "ledger"
ISS = "https://idp.example.test"


def actor(sub: str) -> str:
    return f"{ISS}|{sub}"


def user(sub: str, *roles: str) -> UserIdentity:
    return UserIdentity(sub, ISS, frozenset((TEAM, r) for r in roles or ("reviewer",)))


def make_floors(**over: Any) -> Floors:
    doc: dict[str, Any] = {
        "mandatory_gate_roles": {"review": ["reviewer"], "qa": ["qa"], "pre_push": ["reviewer"]},
        "decision_surfaces": {"review": ["ui"], "qa": ["ui"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
        **over,
    }
    return Floors.model_validate(doc)


def make_gate(kind: GateType = GateType.REVIEW, name: str = "review_gate", rnd: int = 1) -> Gate:
    if kind is GateType.PRE_PUSH:
        subject = Subject.pre_push(base_sha="a" * 40, patch_id="p1", ticket_revision="r1")
    else:
        subject = Subject(
            head_sha="b" * 40,
            patch_id="p1",
            ticket_revision="r1",
            evidence_digest="e1",
            attention_digest="t1",
        )
    return Gate(GateId.new(), RunId.new(), name, kind, rnd, subject)


PLATFORM_COMMIT = Commit(sha="c" * 40, in_receipts=True)


def base_facts(**over: Any) -> RunFacts:
    facts = RunFacts(
        requester=actor("rita"),
        commits=(PLATFORM_COMMIT,),
        assignees=frozenset({actor("amy")}),
    )
    return dataclasses.replace(facts, **over)


def check(
    who: UserIdentity | ServiceIdentity | None = None,
    *,
    gate: Gate | None = None,
    facts: RunFacts | None = None,
    sod: SeparationOfDuties | None = None,
    floors: Floors | None = None,
    linked: bool = True,
    opened_with: frozenset[str] | None | str = "default",
    eligible_roles: frozenset[str] = frozenset({"reviewer", "qa"}),
    negative: bool = False,
) -> SodVerdict:
    who = who or user("bob")
    if opened_with == "default":
        opened_with = frozenset({actor(who.subject)})
    return evaluate(
        who=who,
        linked=linked,
        team=TEAM,
        gate=gate or make_gate(),
        eligible_roles=eligible_roles,
        opened_with=opened_with,  # type: ignore[arg-type]
        sod=sod,
        floors=floors or make_floors(),
        facts=facts or base_facts(),
        negative=negative,
    )


def sod_not(*terms: Any) -> SeparationOfDuties:
    return SeparationOfDuties.model_validate({"not": list(terms)})


def refused(verdict: Any, reason: str) -> None:
    assert not verdict.allowed, f"expected a refusal for {reason}, got allowed"
    assert reason in verdict.reasons, verdict.reasons


# --- control -----------------------------------------------------------------------------------


def test_control_an_unrelated_eligible_human_is_allowed() -> None:
    verdict = check()
    assert verdict.allowed
    assert verdict.reasons == ()


# --- eligibility: linked human, role, then and now -----------------------------------------------


def test_G7_service_identity_is_never_eligible() -> None:
    svc = ServiceIdentity("client1", ISS, "client1")
    refused(check(svc), "service_identity")
    # whatever else is true of the record, a service stays refused, even on a negative decision
    refused(check(svc, negative=True), "service_identity")


def test_G7_unlinked_account_is_refused() -> None:
    refused(check(linked=False), "unlinked")


def test_G7_no_gate_role_is_refused() -> None:
    refused(check(user("bob", "developer")), "role")


def test_G7_admin_rights_alone_are_not_eligibility() -> None:
    refused(check(user("bob", "team_admin")), "role")


def test_G7_admin_who_also_holds_reviewer_can_decide() -> None:
    assert check(user("bob", "team_admin", "reviewer")).allowed


def test_G7_revoked_mapping_is_refused_even_if_eligible_when_opened() -> None:
    # eligible at open (in the snapshot) but the current mapping no longer gives a gate role
    refused(check(user("bob", "developer"), opened_with=frozenset({actor("bob")})), "role")


def test_G7_newly_mapped_after_open_is_refused() -> None:
    # holds the role now but was not eligible when the gate opened: "then and now"
    refused(check(opened_with=frozenset({actor("someone-else")})), "not_eligible_at_open")


def test_G7_a_gate_with_no_eligibility_snapshot_fails_closed() -> None:
    refused(check(opened_with=None), "not_eligible_at_open")


# --- floor: committer ---------------------------------------------------------------------------


def test_G7_attributed_committer_is_excluded() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("bob"), attributed_by=actor("tess")
    )
    refused(check(facts=base_facts(commits=(PLATFORM_COMMIT, commit))), "committer")


def test_G7_committer_floor_applies_when_the_gate_names_no_sod() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("bob"), attributed_by=actor("tess")
    )
    facts = base_facts(commits=(commit,))
    refused(check(facts=facts, sod=None), "committer")


def test_T8_narrowing_sod_cannot_drop_the_committer_floor() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("bob"), attributed_by=actor("tess")
    )
    facts = base_facts(commits=(commit,))
    # a gate that only lists author, or only requester, still excludes the committer
    refused(check(facts=facts, sod=sod_not("author")), "committer")
    refused(check(facts=facts, sod=sod_not("requester")), "committer")
    refused(check(facts=facts, sod=sod_not({"approver_of": "other"})), "committer")


def test_T8_omitting_sod_cannot_drop_the_requester_floor() -> None:
    facts = base_facts()
    refused(check(user("rita"), facts=facts, sod=None), "requester")
    refused(check(user("rita"), facts=facts, sod=sod_not("author")), "requester")


def test_G7_co_author_trailer_excludes() -> None:
    co = Exclusion(actor("bob"), source="co-authored-by")
    commit = Commit(sha="d" * 40, in_receipts=True, coauthors=(co,))
    refused(check(facts=base_facts(commits=(commit,))), "committer")


def test_G7_a_person_cannot_clear_their_own_exclusion() -> None:
    co = Exclusion(actor("bob"), source="co-authored-by", cleared_by=actor("bob"))
    commit = Commit(sha="d" * 40, in_receipts=True, coauthors=(co,))
    refused(check(facts=base_facts(commits=(commit,))), "committer")


def test_G7_another_admin_can_clear_a_false_exclusion() -> None:
    co = Exclusion(actor("bob"), source="co-authored-by", cleared_by=actor("tess"))
    commit = Commit(sha="d" * 40, in_receipts=True, coauthors=(co,))
    facts = base_facts(commits=(commit,))
    assert check(facts=facts).allowed


def test_G7_admin_who_cleared_an_exclusion_is_ineligible_for_that_round() -> None:
    co = Exclusion(actor("bob"), source="co-authored-by", cleared_by=actor("tess"))
    commit = Commit(sha="d" * 40, in_receipts=True, coauthors=(co,))
    facts = base_facts(commits=(commit,))
    refused(check(user("tess"), facts=facts), "admin_self_service")
    assert check(user("tess"), facts=base_facts()).allowed  # twin: she did nothing here


def test_G7_admin_who_attributed_a_commit_is_ineligible() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("amy"), attributed_by=actor("tess")
    )
    facts = base_facts(commits=(commit,))
    refused(check(user("tess"), facts=facts), "admin_self_service")
    assert check(user("bob"), facts=facts).allowed


def test_G7_pusher_from_a_webhook_adds_an_exclusion() -> None:
    commit = Commit(sha="d" * 40, in_receipts=True, pushers=(Pusher(actor("bob")),))
    refused(check(facts=base_facts(commits=(commit,))), "committer")


# --- push receipts: forged and platform commits -------------------------------------------------


def test_G7_forged_bot_author_on_a_pushed_commit_blocks() -> None:
    forged = Commit(sha="e" * 40, in_receipts=False, git_author="sto[bot] <bot@platform.test>")
    verdict = check(facts=base_facts(commits=(PLATFORM_COMMIT, forged)))
    refused(verdict, f"unattributed_commit:{forged.sha}")
    assert verdict.blocked  # the gate is blocked for everyone until an admin attributes it


def test_G7_unattributed_commit_blocks_everyone_not_one_person() -> None:
    commit = Commit(sha="e" * 40, in_receipts=False)
    facts = base_facts(commits=(commit,))
    for sub in ("bob", "carol", "dave"):
        assert check(user(sub), facts=facts).blocked


def test_G7_attribution_lifts_the_block() -> None:
    commit = Commit(
        sha="e" * 40, in_receipts=False, attributed_to=actor("amy"), attributed_by=actor("tess")
    )
    assert check(facts=base_facts(commits=(commit,))).allowed


def test_G7_a_git_author_field_is_never_trusted_on_a_receipt_commit() -> None:
    # a receipt commit whose author field names a human excludes no one: only receipts decide
    commit = Commit(sha="c" * 40, in_receipts=True, git_author="Bob <bob@example.test>")
    assert check(facts=base_facts(commits=(commit,))).allowed


def test_G7_platform_commits_do_not_block() -> None:
    many = tuple(Commit(sha=f"{i:040d}", in_receipts=True) for i in range(1, 4))
    verdict = check(facts=base_facts(commits=many))
    assert verdict.allowed
    assert not verdict.blocked


def test_G7_a_run_with_no_commits_is_not_blocked() -> None:
    assert check(facts=base_facts(commits=())).allowed


def test_G7_negative_decisions_are_accepted_despite_an_unattributed_commit() -> None:
    commit = Commit(sha="e" * 40, in_receipts=False)
    verdict = check(facts=base_facts(commits=(commit,)), negative=True)
    assert verdict.allowed


# --- requester ---------------------------------------------------------------------------------


def test_G7_requester_cannot_approve_review() -> None:
    refused(check(user("rita")), "requester")


def test_G7_requester_cannot_approve_pre_push() -> None:
    gate = make_gate(GateType.PRE_PUSH, "pre_push")
    refused(check(user("rita"), gate=gate), "requester")


def test_G7_requester_may_approve_qa_by_default() -> None:
    gate = make_gate(GateType.QA, "qa_gate")
    assert check(user("rita", "qa"), gate=gate).allowed


def test_G7_requester_floor_follows_the_org_list() -> None:
    gate = make_gate(GateType.QA, "qa_gate")
    floors = make_floors(requester_excluded_from=["review", "pre_push", "qa"])
    refused(check(user("rita", "qa"), gate=gate, floors=floors), "requester")


def test_G7_gate_can_add_requester_term_for_a_type_the_floor_skips() -> None:
    gate = make_gate(GateType.QA, "qa_gate")
    refused(check(user("rita", "qa"), gate=gate, sod=sod_not("requester")), "requester")


def test_G7_jira_requester_with_no_linked_identity_fails_closed() -> None:
    verdict = check(facts=base_facts(requester=None))
    refused(verdict, "unresolved_term:requester")
    assert verdict.blocked


def test_G7_unresolved_intake_actor_fails_closed_for_everyone() -> None:
    for sub in ("bob", "carol"):
        assert check(user(sub), facts=base_facts(requester=None)).blocked


def test_G7_unresolved_requester_only_matters_when_the_term_applies() -> None:
    gate = make_gate(GateType.QA, "qa_gate")
    assert check(user("bob", "qa"), gate=gate, facts=base_facts(requester=None)).allowed


def test_G7_admin_resolving_a_term_makes_that_actor_ineligible_and_lifts_the_block() -> None:
    res = Resolution("requester", frozenset({actor("rita")}), resolved_by=actor("tess"))
    facts = base_facts(requester=None, resolutions=(res,))
    assert check(user("bob"), facts=facts).allowed
    refused(check(user("rita"), facts=facts), "requester")


def test_G7_negative_decision_accepted_while_a_term_is_unresolved() -> None:
    assert check(facts=base_facts(requester=None), negative=True).allowed


def test_G7_explicit_unresolved_author_term_fails_closed() -> None:
    facts = base_facts(unresolved=frozenset({"author"}))
    refused(check(facts=facts, sod=sod_not("author")), "unresolved_term:author")
    # not listed, so not applied
    assert check(facts=facts, sod=None).allowed


# --- author: the frozen union -----------------------------------------------------------------


def test_G7_assignee_is_excluded_when_the_gate_lists_author() -> None:
    refused(check(user("amy"), sod=sod_not("author")), "author")
    assert check(user("amy"), sod=None).allowed  # author is a team term, not a floor


def test_G7_assignee_changed_before_approving_still_excluded() -> None:
    # the union has grown to include amy and ben; reassigning to carol cannot free them
    facts = base_facts(assignees=frozenset({actor("amy"), actor("ben"), actor("carol")}))
    for sub in ("amy", "ben", "carol"):
        refused(check(user(sub), facts=facts, sod=sod_not("author")), "author")
    assert check(user("dave"), facts=facts, sod=sod_not("author")).allowed


# --- approver_of and the two-human floor ------------------------------------------------------


def test_G7_prior_approver_of_a_named_gate_is_excluded() -> None:
    facts = base_facts(approvals=(Approval("review_gate", GateType.REVIEW, actor("bob")),))
    gate = make_gate(GateType.CUSTOM, "release")
    sod = sod_not({"approver_of": "review_gate"})
    refused(check(facts=facts, gate=gate, sod=sod), "approver_of:review_gate")
    assert check(user("carol"), facts=facts, gate=gate, sod=sod).allowed


def test_G7_same_person_cannot_approve_review_and_qa() -> None:
    qa = make_gate(GateType.QA, "qa_gate")
    facts = base_facts(approvals=(Approval("review_gate", GateType.REVIEW, actor("bob")),))
    refused(check(user("bob", "qa"), gate=qa, facts=facts), "review_and_qa")
    assert check(user("carol", "qa"), gate=qa, facts=facts).allowed


def test_G7_review_and_qa_floor_holds_in_the_other_order() -> None:
    facts = base_facts(approvals=(Approval("qa_gate", GateType.QA, actor("bob")),))
    refused(check(user("bob"), facts=facts), "review_and_qa")


def test_G7_single_human_allowed_lifts_the_review_and_qa_floor() -> None:
    qa = make_gate(GateType.QA, "qa_gate")
    facts = base_facts(approvals=(Approval("review_gate", GateType.REVIEW, actor("bob")),))
    floors = make_floors(single_human_allowed=True)
    assert check(user("bob", "qa"), gate=qa, facts=facts, floors=floors).allowed


# --- admin self-service ------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["mapping", "eligible_roles", "attribute", "clear_exclusion"])
def test_T8_admin_who_self_granted_is_ineligible_for_the_affected_round(kind: str) -> None:
    action = AdminAction(actor("tess"), kind)  # type: ignore[arg-type]
    facts = base_facts(admin_actions=(action,))
    refused(check(user("tess"), facts=facts), "admin_self_service")
    assert check(user("bob"), facts=facts).allowed


def test_T8_self_grant_covers_its_round_and_every_later_round_of_the_gate() -> None:
    # a gate snapshots eligibility at open, so a grant only ever helps a LATER round
    action = AdminAction(actor("tess"), "mapping", gate="review_gate", round=2)
    facts = base_facts(admin_actions=(action,))
    for rnd in (2, 3, 9):
        refused(check(user("tess"), facts=facts, gate=make_gate(rnd=rnd)), "admin_self_service")
    # an earlier round was already open before the action, and another gate is unaffected
    assert check(user("tess"), facts=facts, gate=make_gate(rnd=1)).allowed
    other = make_gate(GateType.QA, "qa_gate", rnd=3)
    assert check(user("tess", "qa"), facts=facts, gate=other).allowed


def test_T8_eligible_roles_self_grant_covers_later_rounds_too() -> None:
    action = AdminAction(actor("tess"), "eligible_roles", gate="review_gate", round=1)
    refused(
        check(user("tess"), facts=base_facts(admin_actions=(action,)), gate=make_gate(rnd=4)),
        "admin_self_service",
    )


def test_T8_admin_action_not_scoped_covers_every_gate() -> None:
    facts = base_facts(admin_actions=(AdminAction(actor("tess"), "eligible_roles"),))
    refused(check(user("tess"), facts=facts, gate=make_gate(rnd=7)), "admin_self_service")


# --- eligibility extension (D3-16 uses these) --------------------------------------------------


def test_G7_extender_cannot_vote_in_the_round() -> None:
    action = AdminAction(actor("olga"), "extend_eligibility", gate="review_gate", round=1)
    facts = base_facts(admin_actions=(action,))
    refused(check(user("olga"), facts=facts), "admin_self_service")


def test_G7_added_person_must_pass_sod() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("bob"), attributed_by=actor("tess")
    )
    facts = base_facts(commits=(commit,))
    # bob was added to the snapshot by an extension, yet is still a committer
    refused(check(user("bob"), facts=facts, opened_with=frozenset({actor("bob")})), "committer")


# --- result shape ------------------------------------------------------------------------------


def test_reasons_collect_every_cause_not_just_the_first() -> None:
    commit = Commit(
        sha="d" * 40, in_receipts=False, attributed_to=actor("rita"), attributed_by=actor("tess")
    )
    verdict = check(user("rita"), facts=base_facts(commits=(commit,)))
    assert {"committer", "requester"} <= set(verdict.reasons)


def test_G7_extension_covers_exactly_its_round() -> None:
    action = AdminAction(actor("olga"), "extend_eligibility", gate="review_gate", round=2)
    facts = base_facts(admin_actions=(action,))
    refused(check(user("olga"), facts=facts, gate=make_gate(rnd=2)), "admin_self_service")
    assert check(user("olga"), facts=facts, gate=make_gate(rnd=3)).allowed


# --- term resolution ---------------------------------------------------------------------------


def test_G7_the_admin_who_resolves_a_term_is_ineligible() -> None:
    res = Resolution("requester", frozenset({actor("rita")}), resolved_by=actor("tess"))
    facts = base_facts(requester=None, resolutions=(res,))
    refused(check(user("tess"), facts=facts), "admin_self_service")
    assert check(user("bob"), facts=facts).allowed


def test_G7_the_resolver_stays_ineligible_in_later_rounds() -> None:
    res = Resolution("requester", frozenset({actor("rita")}), resolved_by=actor("tess"), round=1)
    facts = base_facts(requester=None, resolutions=(res,))
    refused(check(user("tess"), facts=facts, gate=make_gate(rnd=3)), "admin_self_service")


def test_G7_a_resolution_naming_nobody_resolves_nothing() -> None:
    res = Resolution("requester", frozenset(), resolved_by=actor("tess"))
    facts = base_facts(requester=None, resolutions=(res,))
    refused(check(user("bob"), facts=facts), "unresolved_term:requester")


def test_G7_resolving_the_author_term_excludes_the_named_actor() -> None:
    res = Resolution("author", frozenset({actor("jo")}), resolved_by=actor("tess"))
    facts = base_facts(unresolved=frozenset({"author"}), resolutions=(res,))
    assert check(user("bob"), facts=facts, sod=sod_not("author")).allowed
    refused(check(user("jo"), facts=facts, sod=sod_not("author")), "author")


# --- pushers, store-shaped records, actor format ------------------------------------------------


def test_G7_a_pusher_exclusion_cannot_be_cleared() -> None:
    assert not hasattr(Pusher(actor("bob")), "cleared_by")
    with pytest.raises(TypeError):
        Pusher(actor("bob"), cleared_by=actor("tess"))  # type: ignore[call-arg]
    commit = Commit(sha="d" * 40, in_receipts=True, pushers=(Pusher(actor("bob")),))
    refused(check(user("bob"), facts=base_facts(commits=(commit,))), "committer")


def test_G7_gate_type_read_back_as_a_string_still_enforces_review_and_qa() -> None:
    qa = make_gate(GateType.QA, "qa_gate")
    facts = base_facts(approvals=(Approval("review_gate", "review", actor("bob")),))  # type: ignore[arg-type]
    refused(check(user("bob", "qa"), gate=qa, facts=facts), "review_and_qa")


def test_G7_an_unknown_approval_gate_type_is_refused() -> None:
    with pytest.raises(ValueError, match="GateType"):
        Approval("g", "nonsense", actor("bob"))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["bob", "bob@example.test", "|bob", "https://idp.test|", ""])
def test_G7_an_actor_not_in_issuer_subject_form_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Commit(sha="d" * 40, in_receipts=False, attributed_to=bad, attributed_by=actor("tess"))
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Commit(sha="d" * 40, in_receipts=False, attributed_to=actor("a"), attributed_by=bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Exclusion(bad, source="co-authored-by")
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Exclusion(actor("a"), source="co-authored-by", cleared_by=bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Pusher(bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Approval("g", GateType.REVIEW, bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        AdminAction(bad, "mapping")
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Resolution("requester", frozenset({bad}), resolved_by=actor("tess"))
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        Resolution("requester", frozenset({actor("a")}), resolved_by=bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        base_facts(requester=bad)
    with pytest.raises(ValueError, match=r"issuer\|subject"):
        base_facts(assignees=frozenset({bad}))


def test_G7_a_subject_containing_a_bar_is_still_a_valid_actor() -> None:
    assert Approval("g", GateType.REVIEW, f"{ISS}|auth0|123").actor.endswith("auth0|123")


# --- a veto: what still applies and what does not ----------------------------------------------


def test_G7_an_excluded_person_cannot_reject_either() -> None:
    commit = Commit(sha="d" * 40, in_receipts=True, pushers=(Pusher(actor("bob")),))
    facts = base_facts(commits=(commit,))
    refused(check(user("bob"), facts=facts, negative=True), "committer")
    refused(check(user("rita"), negative=True), "requester")


def test_T8_a_self_granting_admin_cannot_reject_either() -> None:
    facts = base_facts(admin_actions=(AdminAction(actor("tess"), "mapping"),))
    refused(check(user("tess"), facts=facts, negative=True), "admin_self_service")
    commit = Commit(
        sha="e" * 40, in_receipts=False, attributed_to=actor("amy"), attributed_by=actor("tess")
    )
    refused(
        check(user("tess"), facts=base_facts(commits=(commit,)), negative=True),
        "admin_self_service",
    )


def test_G7_the_review_approver_may_reject_at_qa() -> None:
    qa = make_gate(GateType.QA, "qa_gate")
    facts = base_facts(approvals=(Approval("review_gate", GateType.REVIEW, actor("bob")),))
    assert check(user("bob", "qa"), gate=qa, facts=facts, negative=True).allowed
    refused(check(user("bob", "qa"), gate=qa, facts=facts), "review_and_qa")  # twin


def test_G7_approver_of_applies_to_approvals_only() -> None:
    facts = base_facts(approvals=(Approval("review_gate", GateType.REVIEW, actor("bob")),))
    gate = make_gate(GateType.CUSTOM, "release")
    sod = sod_not({"approver_of": "review_gate"})
    assert check(facts=facts, gate=gate, sod=sod, negative=True).allowed
    refused(check(facts=facts, gate=gate, sod=sod), "approver_of:review_gate")


# --- records that must not be half-read --------------------------------------------------------


def test_G7_a_half_attributed_commit_still_blocks() -> None:
    only_to = Commit(sha="e" * 40, in_receipts=False, attributed_to=actor("amy"))
    refused(check(facts=base_facts(commits=(only_to,))), f"unattributed_commit:{only_to.sha}")
    only_by = Commit(sha="f" * 40, in_receipts=False, attributed_by=actor("tess"))
    refused(check(facts=base_facts(commits=(only_by,))), f"unattributed_commit:{only_by.sha}")


def test_G7_only_the_named_gate_excludes_a_prior_approver() -> None:
    approvals = (
        Approval("other_gate", GateType.CUSTOM, actor("bob")),
        Approval("review_gate", GateType.REVIEW, actor("carol")),
    )
    facts = base_facts(approvals=approvals)
    gate = make_gate(GateType.CUSTOM, "release")
    sod = sod_not({"approver_of": "review_gate"})
    assert check(user("bob"), facts=facts, gate=gate, sod=sod).allowed
    refused(check(user("carol"), facts=facts, gate=gate, sod=sod), "approver_of:review_gate")


def test_G7_clearing_your_own_exclusion_is_not_admin_self_service() -> None:
    co = Exclusion(actor("bob"), source="co-authored-by", cleared_by=actor("bob"))
    commit = Commit(sha="d" * 40, in_receipts=True, coauthors=(co,))
    verdict = check(user("bob"), facts=base_facts(commits=(commit,)))
    refused(verdict, "committer")
    assert "admin_self_service" not in verdict.reasons
