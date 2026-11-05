"""Quorum and veto (D3-06): the decision path of ``GateService`` with a ``DecisionPolicy``.

Covers per-role quorum, one vote per person, veto by any negative decision, the digest rule
(a veto is exempt, a moved subject drops earlier votes), required comments, refused quorum
configs and contention. G3 is proved by enumerating every commit order of a decision set
against an independent oracle, not by sampling.
"""

from __future__ import annotations

import itertools
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

import pytest

from sto.domain import (
    Decision,
    DecisionKind,
    Gate,
    GateStatus,
    GateType,
    RunId,
    Subject,
    Surface,
    TransientError,
    from_wire,
    to_wire,
)
from sto.engine.commands import OpenGate
from sto.gates.service import (
    CommentRequiredError,
    DecisionNotAllowedError,
    DuplicateVoteError,
    GateClosedError,
    GateContentionError,
    GateService,
    QuorumConfigError,
    QuorumRule,
    StaleSubjectError,
    verify_audit_chain,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    AUDIT,
    ConditionFailedError,
    Item,
    Key,
    Op,
    Put,
    Scope,
    Store,
    TeamScope,
    TransactionConflictError,
)

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
A, B, C, D = "iss|alice", "iss|bob", "iss|carol", "iss|dave"


class Recording(MemoryStore):
    """A memory store that remembers every transaction it committed."""

    def __init__(self) -> None:
        super().__init__()
        self.transactions: list[tuple[Op, ...]] = []

    def transact(self, scope: Scope, ops: Iterable[Op]) -> None:
        ops = tuple(ops)
        super().transact(scope, ops)
        self.transactions.append(ops)


@dataclass
class Policy:
    """A scripted ``DecisionPolicy``: a quorum, each person's roles and their refusals."""

    rules: Sequence[QuorumRule] = ()
    roles_of: Mapping[str, Collection[str]] = field(default_factory=dict)
    refused: dict[str, tuple[str, ...]] = field(default_factory=dict)
    approve_refused: dict[str, tuple[str, ...]] = field(default_factory=dict)  # like approver_of

    def quorum(self, scope: Scope, gate: Gate) -> Sequence[QuorumRule]:
        return self.rules

    def roles(self, scope: Scope, gate: Gate, actor: str) -> Collection[str]:
        return self.roles_of.get(actor, ())

    def refusals(self, scope: Scope, gate: Gate, actor: str, *, negative: bool) -> Sequence[str]:
        if negative:
            return self.refused.get(actor, ())
        return (*self.refused.get(actor, ()), *self.approve_refused.get(actor, ()))


REVIEWERS = {A: {"reviewer"}, B: {"reviewer"}, C: {"reviewer"}, D: {"reviewer"}}


def subject(tag: str = "a") -> Subject:
    return Subject(
        patch_id=f"patch-{tag}",
        ticket_revision=f"rev-{tag}",
        head_sha=f"sha-{tag}",
        evidence_digest=f"ev-{tag}",
        attention_digest=f"att-{tag}",
    )


def open_cmd(name: str = "review", round: int = 1, tag: str = "a") -> OpenGate:
    return OpenGate(RUN, name, GateType.REVIEW, round, subject(tag))


def pk() -> str:
    return f"RUN#{RUN}"


def gate_of(store: Store, name: str = "review", round: int = 1) -> Gate:
    item = store.get(TEAM, Key(pk(), f"GATE#{name}#{round}"))
    assert item is not None
    return from_wire(Gate, item.data)


def items(store: Store, prefix: str) -> list[Item]:
    return list(store.query(TEAM, pk(), sk_prefix=prefix).items)


def audit_actions(store: Store) -> list[str]:
    return [i.data["action"] for i in store.query(TEAM, pk(), table=AUDIT).items]


def decide(
    svc: GateService,
    kind: DecisionKind,
    actor: str,
    *,
    gate: Gate | None = None,
    name: str = "review",
    round: int = 1,
    digest: str | None = None,
    comment: str | None = None,
    surface: Surface = Surface.UI,
) -> Any:
    if digest is None:
        digest = gate.subject.digest() if gate else subject().digest()
    if comment is None:
        comment = "" if kind is DecisionKind.APPROVE else "because"
    return svc.decide(
        TEAM,
        run_id=RUN,
        gate=name,
        round=round,
        kind=kind,
        actor=actor,
        surface=surface,
        subject_digest=digest,
        comment=comment,
    )


def quorum_service(
    store: Store, rules: Sequence[QuorumRule] = (QuorumRule("reviewer", 2),), **kw: Any
) -> tuple[GateService, Gate, Policy]:
    policy = Policy(rules, kw.pop("roles_of", REVIEWERS), **kw)
    svc = GateService(store, policy=policy)
    return svc, svc.open_gate(TEAM, open_cmd()), policy


APPROVE, REJECT = DecisionKind.APPROVE, DecisionKind.REJECT


# --- quorum -----------------------------------------------------------------------------------


def test_a_sub_quorum_approval_commits_and_leaves_the_gate_open() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    first = decide(svc, APPROVE, A, gate=gate)
    assert first.gate.is_open
    assert not first.closed
    assert gate_of(store).is_open
    assert gate_of(store).closed_by is None
    assert [o.data["kind"] for o in items(store, "OUT#")] == []  # nothing closed, nothing queued
    assert audit_actions(store) == ["gate.opened", "gate.voted"]
    assert len(items(store, "VOTE#")) == 1


def test_the_quorum_closes_the_gate_approved_exactly_once() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    done = decide(svc, APPROVE, B, gate=gate)
    assert done.closed
    assert gate_of(store).status is GateStatus.APPROVED
    assert gate_of(store).closed_by == B
    assert [o.data["kind"] for o in items(store, "OUT#")] == ["gate.closed"]
    assert audit_actions(store) == ["gate.opened", "gate.voted", "gate.decided"]
    with pytest.raises(GateClosedError):
        decide(svc, APPROVE, C, gate=gate)
    assert verify_audit_chain(store, TEAM, RUN) == 3


def test_the_closing_outbox_entry_and_audit_name_every_approval_that_counted() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    first = decide(svc, APPROVE, A, gate=gate)
    last = decide(svc, APPROVE, B, gate=gate)
    (out,) = items(store, "OUT#")
    assert sorted(out.data["decision_ids"]) == sorted(
        [str(first.decision.id), str(last.decision.id)]
    )
    (dec,) = items(store, "DEC#")  # the ledger the effects read keeps one closing decision
    assert from_wire(Decision, dec.data).id == last.decision.id


def test_one_person_has_one_vote_whatever_the_surface() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    for surface in (Surface.UI, Surface.SLACK, Surface.GITHUB):
        with pytest.raises(DuplicateVoteError) as err:
            decide(svc, APPROVE, A, gate=gate, surface=surface)
        assert err.value.code == "already_voted"
    assert gate_of(store).is_open  # the same person twice is not a quorum of two
    assert len(items(store, "VOTE#")) == 1


def test_a_per_role_quorum_needs_each_role() -> None:
    store = Recording()
    rules = (QuorumRule("reviewer", 1), QuorumRule("qa", 1))
    roles = {A: {"reviewer"}, B: {"reviewer"}, C: {"qa"}}
    svc, gate, _ = quorum_service(store, rules, roles_of=roles)
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, APPROVE, B, gate=gate)  # two reviewers do not make a qa
    assert gate_of(store).is_open
    done = decide(svc, APPROVE, C, gate=gate)
    assert done.closed
    assert gate_of(store).status is GateStatus.APPROVED


def test_one_person_holding_both_roles_fills_only_one_of_them() -> None:
    store = Recording()
    rules = (QuorumRule("reviewer", 1), QuorumRule("qa", 1))
    roles = {A: {"reviewer", "qa"}, B: {"qa"}}
    svc, gate, _ = quorum_service(store, rules, roles_of=roles)
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).is_open
    decide(svc, APPROVE, B, gate=gate)  # A is the reviewer, B the qa
    assert gate_of(store).status is GateStatus.APPROVED


def test_a_dual_role_voter_is_reassigned_so_the_order_of_votes_does_not_matter() -> None:
    """A holds both roles and votes first; B (qa only) then C (reviewer only) must still make
    the quorum: A takes whichever role is left."""
    store = Recording()
    rules = (QuorumRule("reviewer", 1), QuorumRule("qa", 1))
    roles = {A: {"reviewer", "qa"}, B: {"qa"}}
    svc, gate, _ = quorum_service(store, rules, roles_of=roles)
    decide(svc, APPROVE, B, gate=gate)
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).status is GateStatus.APPROVED


@pytest.mark.parametrize("dual_first", [True, False], ids=["dual-first", "dual-last"])
@pytest.mark.parametrize("qa_first", [True, False], ids=["qa-listed-first", "qa-listed-last"])
def test_dual_role_voters_are_matched_in_every_vote_and_rule_order(
    dual_first: bool, qa_first: bool
) -> None:
    rules = [QuorumRule("qa", 1), QuorumRule("reviewer", 1)]
    if not qa_first:
        rules.reverse()
    store = Recording()
    svc, gate, _ = quorum_service(
        store, rules, roles_of={A: {"reviewer", "qa"}, B: {"qa"}, C: {"reviewer"}}
    )
    for who in [A, B] if dual_first else [B, A]:
        decide(svc, APPROVE, who, gate=gate)
    assert gate_of(store).status is GateStatus.APPROVED


def test_a_close_that_lands_between_the_count_and_the_vote_wins() -> None:
    """The vote checks the gate's version itself, so it holds even for an audit writer that does
    not move the chain head."""

    class NoAudit:
        def ops(self, reader: Any, scope: Scope, entry: Any) -> list[Op]:
            return []

    class Racing(Recording):
        fired = False

        def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
            page = super().query(scope, pk, **kw)
            if kw.get("sk_prefix", "").startswith("VOTE#") and not self.fired:
                self.fired = True  # B rejects after the service counted, before it writes
                item = self.get(TEAM, Key(pk, "GATE#review#1"))
                assert item is not None
                closed = from_wire(Gate, item.data).advance(GateStatus.REJECTED, closed_by=B)
                super().transact(TEAM, [Put(item.key, to_wire(closed))])
            return page

    store = Racing()
    svc = GateService(
        store, policy=Policy((QuorumRule("reviewer", 2),), REVIEWERS), audit=NoAudit()
    )
    gate = svc.open_gate(TEAM, open_cmd())
    with pytest.raises(GateClosedError):
        decide(svc, APPROVE, A, gate=gate)
    assert items(store, "VOTE#") == []


def test_the_policy_is_told_whether_the_decision_is_negative() -> None:
    """`approver_of` bars approving only: the same person may still veto."""
    store = Recording()
    svc, gate, _ = quorum_service(store, approve_refused={A: ("approver_of:review",)})
    with pytest.raises(DecisionNotAllowedError, match="approver_of"):
        decide(svc, APPROVE, A, gate=gate)
    decide(svc, REJECT, A, gate=gate)
    assert gate_of(store).status is GateStatus.REJECTED


def test_an_approval_from_nobody_in_the_quorum_is_refused_and_writes_nothing() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, roles_of={**REVIEWERS, "iss|eve": {"visitor"}})
    before = len(store.transactions)
    with pytest.raises(DecisionNotAllowedError):
        decide(svc, APPROVE, "iss|eve", gate=gate)
    assert len(store.transactions) == before
    assert items(store, "VOTE#") == []


def test_a_policy_refusal_names_its_reasons_and_writes_nothing() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, refused={A: ("committer", "role")})
    with pytest.raises(DecisionNotAllowedError, match="committer"):
        decide(svc, APPROVE, A, gate=gate)
    assert items(store, "VOTE#") == []
    assert gate_of(store).is_open


def test_a_voter_who_stops_being_eligible_before_the_close_does_not_count() -> None:
    """PLAN 4.1: each person is eligible when the gate closes."""
    store = Recording()
    svc, gate, policy = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    policy.refused[A] = ("admin_self_service",)
    decide(svc, APPROVE, B, gate=gate)
    assert gate_of(store).is_open  # A no longer counts, so B is one of two
    decide(svc, APPROVE, C, gate=gate)
    assert gate_of(store).status is GateStatus.APPROVED


def test_without_a_policy_one_approval_closes_the_gate() -> None:
    store = Recording()
    svc = GateService(store)
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).status is GateStatus.APPROVED
    assert items(store, "VOTE#") == []
    assert items(store, "QUO#") == []


def test_a_policy_with_no_quorum_means_one_approval_from_any_eligible_person() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, rules=())
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).status is GateStatus.APPROVED


def test_the_quorum_is_frozen_when_the_gate_opens() -> None:
    store = Recording()
    svc, gate, policy = quorum_service(store, (QuorumRule("reviewer", 2),))
    policy.rules = (QuorumRule("reviewer", 1),)  # a later config change
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).is_open


def test_the_gate_record_keeps_its_shape() -> None:
    """D3-22 reads gate records for Stop: quorum state lives beside the gate, not in it."""
    store = Recording()
    svc, gate, _ = quorum_service(store)
    item = store.get(TEAM, Key(pk(), "GATE#review#1"))
    assert item is not None
    assert item.data == to_wire(gate)
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, APPROVE, B, gate=gate)
    closed = store.get(TEAM, Key(pk(), "GATE#review#1"))
    assert closed is not None
    assert set(closed.data) == set(item.data)
    assert closed.data == to_wire(replace(gate, status=GateStatus.APPROVED, closed_by=B))


# --- veto -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        (DecisionKind.REJECT, GateStatus.REJECTED),
        (DecisionKind.REQUEST_CHANGES, GateStatus.CHANGES_REQUESTED),
    ],
)
def test_any_negative_decision_closes_a_quorum_gate_whatever_the_votes(
    kind: DecisionKind, status: GateStatus
) -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, (QuorumRule("reviewer", 3),))
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, APPROVE, B, gate=gate)
    decide(svc, kind, C, gate=gate)
    assert gate_of(store).status is status
    assert gate_of(store).closed_by == C
    with pytest.raises(GateClosedError):
        decide(svc, APPROVE, D, gate=gate)


def test_a_person_who_approved_may_veto_their_own_approval() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, REJECT, A, gate=gate)
    assert gate_of(store).status is GateStatus.REJECTED


def test_a_veto_is_exempt_from_the_digest_and_from_the_quorum_roles() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, roles_of={**REVIEWERS, "iss|eve": {"visitor"}})
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, REJECT, "iss|eve", gate=gate, digest="what-i-saw-before-it-moved")
    assert gate_of(store).status is GateStatus.REJECTED


def test_an_excluded_person_cannot_veto_either() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, refused={A: ("service_identity",)})
    with pytest.raises(DecisionNotAllowedError):
        decide(svc, REJECT, A, gate=gate)
    assert gate_of(store).is_open


def test_a_veto_voids_earlier_approved_rounds() -> None:
    store = Recording()
    svc, round1, _ = quorum_service(store, (QuorumRule("reviewer", 1),))
    decide(svc, APPROVE, A, gate=round1)
    round2 = svc.open_gate(TEAM, open_cmd(round=2, tag="b"))
    decide(svc, REJECT, B, gate=round2, round=2)
    assert gate_of(store, round=1).status is GateStatus.INVALIDATED


# --- moved subject ----------------------------------------------------------------------------


def _move_subject(store: Store, tag: str) -> Gate:
    """The open gate's subject moves under it (a ticket edit reaching the round)."""
    item = store.get(TEAM, Key(pk(), "GATE#review#1"))
    assert item is not None
    moved = replace(from_wire(Gate, item.data), subject=subject(tag))
    store.transact(TEAM, [Put(item.key, to_wire(moved))])
    return moved


def test_votes_for_a_moved_subject_do_not_count() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    moved = _move_subject(store, "b")
    decide(svc, APPROVE, B, gate=moved)
    assert gate_of(store).is_open  # A's vote was for the old subject: B is one of two
    decide(svc, APPROVE, A, gate=moved)  # and A may vote again, on the new one
    assert gate_of(store).status is GateStatus.APPROVED


def test_an_approval_for_the_old_subject_is_refused_after_the_move() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    moved = _move_subject(store, "b")
    with pytest.raises(StaleSubjectError):
        decide(svc, APPROVE, A, gate=gate)  # the digest it saw
    assert gate_of(store) == moved
    assert items(store, "VOTE#") == []


def test_a_ticket_edit_opens_a_new_round_that_starts_with_no_votes() -> None:
    store = Recording()
    svc, round1, _ = quorum_service(store, (QuorumRule("reviewer", 2),))
    decide(svc, APPROVE, A, gate=round1)
    decide(svc, DecisionKind.REQUEST_CHANGES, B, gate=round1)
    round2 = svc.open_gate(TEAM, open_cmd(round=2, tag="b"))  # new ticket revision
    decide(svc, APPROVE, A, gate=round2, round=2)  # A's round 1 vote is not carried
    assert gate_of(store, round=2).is_open
    decide(svc, APPROVE, C, gate=round2, round=2)
    assert gate_of(store, round=2).status is GateStatus.APPROVED


def test_a_vote_for_a_moved_subject_is_replaced_not_duplicated() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    moved = _move_subject(store, "b")
    decide(svc, APPROVE, A, gate=moved)
    assert len(items(store, "VOTE#")) == 1


# --- comments ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind", [DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES, DecisionKind.RETEST]
)
@pytest.mark.parametrize("comment", ["", "   ", "\n\t"])
def test_a_negative_decision_without_a_comment_is_refused_and_writes_nothing(
    kind: DecisionKind, comment: str
) -> None:
    store = Recording()
    policy = Policy((), REVIEWERS)
    svc = GateService(store, policy=policy)
    gate = svc.open_gate(TEAM, replace(open_cmd(), type=GateType.QA, subject=subject()))
    before = len(store.transactions)
    with pytest.raises(CommentRequiredError) as err:
        decide(svc, kind, A, gate=gate, comment=comment)
    assert err.value.code == "comment_required"
    assert len(store.transactions) == before
    assert gate_of(store).is_open


def test_an_approval_needs_no_comment() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store, (QuorumRule("reviewer", 1),))
    decide(svc, APPROVE, A, gate=gate, comment="")
    assert gate_of(store).status is GateStatus.APPROVED


# --- refused quorum configs -------------------------------------------------------------------


@pytest.mark.parametrize(
    "rules",
    [
        (QuorumRule("reviewer", 1), QuorumRule("reviewer", 1)),
        (QuorumRule("reviewer", 2), QuorumRule("qa", 1), QuorumRule("reviewer", 1)),
        (QuorumRule("reviewer", 0),),
        (QuorumRule("reviewer", -1),),
        (QuorumRule("  ", 1),),
        (QuorumRule("reviewer", True),),
    ],
)
def test_a_bad_quorum_is_refused_at_open_and_nothing_is_written(
    rules: Sequence[QuorumRule],
) -> None:
    store = Recording()
    svc = GateService(store, policy=Policy(rules, REVIEWERS))
    with pytest.raises(QuorumConfigError) as err:
        svc.open_gate(TEAM, open_cmd())
    assert err.value.code == "quorum_invalid"
    assert store.transactions == []


def test_a_quorum_may_be_given_by_the_config_schema_objects() -> None:
    from sto.config.schema import Quorum

    store = Recording()
    rules = [Quorum(role="reviewer", count=2)]
    svc = GateService(store, policy=Policy(rules, REVIEWERS))  # type: ignore[arg-type]
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, APPROVE, A, gate=gate)
    assert gate_of(store).is_open


# --- contention -------------------------------------------------------------------------------


class Losing(Recording):
    """Every transaction loses a race, forever."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error, self.armed = error, False

    def transact(self, scope: Scope, ops: Iterable[Op]) -> None:
        if self.armed:
            raise self.error
        super().transact(scope, ops)


@pytest.mark.parametrize(
    "error", [ConditionFailedError([0]), TransactionConflictError("busy")], ids=["cond", "txn"]
)
def test_open_gate_contention_is_a_gate_contention_error(error: Exception) -> None:
    store = Losing(error)
    store.armed = True
    with pytest.raises(GateContentionError) as err:
        GateService(store).open_gate(TEAM, open_cmd())
    assert isinstance(err.value, TransientError)
    assert not isinstance(err.value, ConditionFailedError)
    assert err.value.__cause__ is error


@pytest.mark.parametrize(
    "error", [ConditionFailedError([0]), TransactionConflictError("busy")], ids=["cond", "txn"]
)
def test_decide_contention_is_a_gate_contention_error(error: Exception) -> None:
    store = Losing(error)
    svc = GateService(store)
    gate = svc.open_gate(TEAM, open_cmd())
    store.armed = True
    with pytest.raises(GateContentionError) as err:
        decide(svc, APPROVE, A, gate=gate)
    assert err.value.__cause__ is error
    store.armed = False
    assert gate_of(store).is_open


# --- G3 by every commit order -----------------------------------------------------------------


@dataclass(frozen=True)
class Move:
    actor: str
    kind: DecisionKind

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.actor.split('|')[1]}"


def oracle(order: Sequence[Move], satisfied: Any) -> tuple[GateStatus, list[bool]]:
    """What must happen, written without the service: walk the commits in order. The first
    negative decision closes the gate negative; the approvals close it when they satisfy the
    quorum; whatever commits after the close is refused as closed."""
    status, approvers, accepted = GateStatus.OPEN, [], []
    for move in order:
        if status is not GateStatus.OPEN:
            accepted.append(False)
            continue
        accepted.append(True)
        if move.kind.is_negative:
            status = GateStatus.REJECTED if move.kind is REJECT else GateStatus.CHANGES_REQUESTED
        else:
            approvers.append(move.actor)
            if satisfied(approvers):
                status = GateStatus.APPROVED
    return status, accepted


def _run_order(
    order: Sequence[Move], rules: Sequence[QuorumRule], roles: Mapping[str, Collection[str]]
) -> tuple[Store, list[bool]]:
    store = Recording()
    svc = GateService(store, policy=Policy(rules, roles))
    gate = svc.open_gate(TEAM, open_cmd())
    accepted = []
    for move in order:
        try:
            decide(svc, move.kind, move.actor, gate=gate)
        except GateClosedError:
            accepted.append(False)
        else:
            accepted.append(True)
    return store, accepted


G3_CASES = {
    "two reviewers, one veto": (
        [QuorumRule("reviewer", 2)],
        REVIEWERS,
        [Move(A, APPROVE), Move(B, APPROVE), Move(C, REJECT)],
        lambda who: len(set(who)) >= 2,
    ),
    "three reviewers, a request for changes, a spare approval": (
        [QuorumRule("reviewer", 3)],
        REVIEWERS,
        [
            Move(A, APPROVE),
            Move(B, APPROVE),
            Move(C, APPROVE),
            Move(D, DecisionKind.REQUEST_CHANGES),
        ],
        lambda who: len(set(who)) >= 3,
    ),
    "reviewer plus qa, the vetoer already approved": (
        [QuorumRule("reviewer", 1), QuorumRule("qa", 1)],
        {A: {"reviewer"}, B: {"qa"}, C: {"reviewer"}},
        [Move(A, APPROVE), Move(B, APPROVE), Move(A, REJECT), Move(C, APPROVE)],
        lambda who: "iss|bob" in who and bool({"iss|alice", "iss|carol"} & set(who)),
    ),
}


@pytest.mark.parametrize("case", list(G3_CASES))
def test_G3_holds_in_every_commit_order(case: str) -> None:
    rules, roles, moves, satisfied = G3_CASES[case]
    orders = list(itertools.permutations(moves))
    assert len(orders) >= 6
    closed_each_way = set()
    for order in orders:
        want_status, want_accepted = oracle(order, satisfied)
        # a person's second decision is refused as a duplicate vote only if it is an approval;
        # these cases give nobody two approvals, so the oracle needs no such rule.
        store, accepted = _run_order(order, rules, roles)
        label = " -> ".join(str(m) for m in order)
        gate = gate_of(store)
        assert gate.status is want_status, f"G3 {label}: closed {gate.status}, want {want_status}"
        assert accepted == want_accepted, f"G3 {label}: accepted {accepted}, want {want_accepted}"
        # exactly one close: one outbox entry, one gate.decided audit entry
        assert [o.data["kind"] for o in items(store, "OUT#")] == ["gate.closed"], label
        assert audit_actions(store).count("gate.decided") == 1, label
        # a decision that committed after the close would have changed the record
        assert gate.closed_by is not None
        closing = [m for m, ok in zip(order, accepted, strict=True) if ok][-1]
        assert gate.closed_by == closing.actor, label
        # reject beats approve: if any negative decision committed while open, it closed negative
        first_negative = next(
            (m for m, ok in zip(order, accepted, strict=True) if ok and m.kind.is_negative), None
        )
        if first_negative is not None:
            assert gate.status is not GateStatus.APPROVED, f"G3 {label}: approved over a veto"
        assert verify_audit_chain(store, TEAM, RUN) >= 2
        closed_each_way.add(gate.status)
    assert GateStatus.APPROVED in closed_each_way, "a case must also reach an approval"
    assert closed_each_way - {GateStatus.APPROVED}, "a case must also reach a negative close"


def test_G3_the_enumeration_reaches_both_outcomes_and_every_position_of_the_veto() -> None:
    rules, roles, moves, satisfied = G3_CASES["two reviewers, one veto"]
    outcomes: dict[int, set[GateStatus]] = {}
    for order in itertools.permutations(moves):
        store, _ = _run_order(order, rules, roles)
        position = [i for i, m in enumerate(order) if m.kind is REJECT][0]
        outcomes.setdefault(position, set()).add(gate_of(store).status)
    assert outcomes == {
        0: {GateStatus.REJECTED},
        1: {GateStatus.REJECTED},
        2: {GateStatus.APPROVED},  # only a veto after the deciding approval loses, and gets 409
    }


def test_G3_a_late_veto_gets_gate_closed_and_leaves_the_approval_standing() -> None:
    store = Recording()
    svc, gate, _ = quorum_service(store)
    decide(svc, APPROVE, A, gate=gate)
    decide(svc, APPROVE, B, gate=gate)
    with pytest.raises(GateClosedError) as err:
        decide(svc, REJECT, C, gate=gate)
    assert err.value.status is GateStatus.APPROVED
    assert err.value.closed_by == B
    assert gate_of(store).status is GateStatus.APPROVED
