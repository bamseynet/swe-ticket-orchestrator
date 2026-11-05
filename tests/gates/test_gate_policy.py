"""D3-24: the gate service decides with separation of duties and the gate's quorum.

``GatePolicy`` is built from the real pieces (the published workflow's gate config, the real
``sod.evaluate``, the attribution records, the service's own decision records) and handed to a real
``GateService`` over memory and SQLite. The last tests go through the real HTTP app, the
authorization middleware and a real run, so a barred approver is refused where a person meets it.
Everything is synthetic and offline.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from bundled_templates import policy as org_policy
from bundled_templates import template

from sto.adapters.fake.scm import FakeScm
from sto.adapters.ports import MergeMethod, PrRef, PrSpec, RepoRef
from sto.api import app as app_module
from sto.api.app import DevDirectory, SimulatedSteps, create_app, gate_policy
from sto.api.auth import Authorization
from sto.api.routers.attribution import commit_key, read_records
from sto.api.runtime import API_INDEX, Runtime, default_gate_roles, scm_merge_factory
from sto.config.org_policy import ORG_ADMIN, Principal
from sto.config.schema import Gate as GateConfig
from sto.config.schema import Workflow as GraphWorkflow
from sto.domain import DecisionKind, Gate, GateId, GateType, RunId, Subject, Surface
from sto.effects.core import EffectExecutor
from sto.engine.commands import OpenGate
from sto.engine.reducer import LINEAR_V0
from sto.gates import policy as policy_module
from sto.gates.hooks import run_pk
from sto.gates.policy import (
    GatePolicy,
    LinearGates,
    StoreRecords,
    WorkflowGates,
    check_quorum,
)
from sto.gates.service import (
    Decided,
    DecisionNotAllowedError,
    GateService,
    QuorumConfigError,
    QuorumRule,
)
from sto.gates.sod import RunFacts
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.mapping import RoleMapping, ServiceIdentity, UserIdentity
from sto.identity.oidc import OidcConfig, OidcValidator, StaticJwks
from sto.store.memory import MemoryStore
from sto.store.ports import Absent, Key, Scope, Store, TeamScope
from sto.store.sqlite import SqliteStore

TEAM = "ledger"
SCOPE = TeamScope(TEAM)
ISS = "https://idp.example.test"
RUN = RunId.parse("01J00000000000000000000001")
SUBJECT = Subject(
    patch_id="p", ticket_revision="r", head_sha="h", evidence_digest="e", attention_digest="a"
)
DIGEST = SUBJECT.digest()


def actor(sub: str) -> str:
    return f"{ISS}|{sub}"


def person(sub: str, *roles: str) -> UserIdentity:
    return UserIdentity(sub, ISS, frozenset((TEAM, r) for r in roles or ("reviewer",)))


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Store]:
    s: Store = MemoryStore() if request.param == "memory" else SqliteStore(tmp_path / "t.db")
    yield s
    close = getattr(s, "close", None)
    if close:
        close()


# --- the pieces, as one rig ---------------------------------------------------------------------


def workflow_with(
    *, quorum: Sequence[dict[str, Any]] | None = None, sod: Sequence[Any] | None = None
) -> GraphWorkflow:
    """The standard template with a quorum and separation of duties on its review gate."""
    body = template().model_dump(mode="json", by_alias=True, exclude_none=True)
    gate = body["stages"]["review_gate"]["gate"]
    if quorum is not None:
        gate["quorum"] = list(quorum)
    if sod is not None:
        gate["separation_of_duties"] = {"not": list(sod)}
    return GraphWorkflow.model_validate(copy.deepcopy(body))


class People:
    """The directory: who each actor key is, and which accounts are linked."""

    def __init__(self) -> None:
        self.found: dict[str, UserIdentity | ServiceIdentity] = {}
        self.unlinked: set[str] = set()

    def add(self, who: UserIdentity | ServiceIdentity) -> str:
        key = f"{who.issuer}|{who.subject}"
        self.found[key] = who
        return key

    def who(self, scope: Scope, key: str) -> UserIdentity | ServiceIdentity | None:
        return self.found.get(key)

    def linked(self, scope: Scope, key: str) -> bool:
        return key not in self.unlinked


class Rig:
    def __init__(
        self,
        store: Store,
        *,
        rules: Any = None,
        quorum: Sequence[dict[str, Any]] | None = ({"role": "reviewer", "count": 2},),
        sod: Sequence[Any] | None = None,
        quorum_floor: Callable[[str, str], int] = lambda team, gate_type: 1,
    ) -> None:
        self.store = store
        self.people = People()
        self.requester: dict[RunId, str | None] = {RUN: actor("starter")}
        self.snapshot: set[str] = set()
        self.rules = rules or WorkflowGates(workflow_with(quorum=quorum, sod=sod))
        self.facts_error: Exception | None = None
        records = StoreRecords(
            store,
            read=read_records,
            requester_of=self._requester,
            snapshot=lambda scope, gate: frozenset(self.snapshot),
        )
        self.records = records
        self.policy = GatePolicy(
            rules=self.rules,
            directory=self.people,
            records=records,
            floors=org_policy().floors,
            quorum_floor=quorum_floor,
        )
        self.service = GateService(store, policy=self.policy)

    def _requester(self, scope: Scope, run_id: RunId) -> str | None:
        if self.facts_error is not None:
            raise self.facts_error
        return self.requester.get(run_id)

    def join(self, sub: str, *roles: str) -> str:
        key = self.people.add(person(sub, *roles))
        self.snapshot.add(key)  # eligible when the gate opened
        return key

    def open(
        self, name: str = "review_gate", type_: GateType = GateType.REVIEW, round: int = 1
    ) -> Gate:
        return self.service.open_gate(SCOPE, OpenGate(RUN, name, type_, round, SUBJECT))

    def decide(
        self,
        who: str,
        kind: DecisionKind = DecisionKind.APPROVE,
        *,
        gate: str = "review_gate",
        round: int = 1,
    ) -> Decided:
        return self.service.decide(
            SCOPE,
            run_id=RUN,
            gate=gate,
            round=round,
            kind=kind,
            actor=who,
            surface=Surface.UI,
            subject_digest=DIGEST,
            comment="" if kind is DecisionKind.APPROVE else "because",
        )

    def votes(self) -> list[str]:
        return [i.key.sk for i in self.store.query(SCOPE, run_pk(RUN), sk_prefix="VOTE#").items]

    def stored_gate(self, name: str = "review_gate", round: int = 1) -> Any:
        return self.store.get(SCOPE, Key(run_pk(RUN), f"GATE#{name}#{round}"))

    def coauthor(self, who: str, *, sha: str = "abc1234") -> None:
        """Ingest saw a ``Co-authored-by`` trailer naming ``who`` on a commit of the PR."""
        self.store.put(
            SCOPE,
            commit_key(RUN, sha),
            {
                "sha": sha,
                "in_receipts": True,
                "coauthors": [{"actor": who, "source": "trailer"}],
            },
            when=Absent(),
        )


def refused(rig: Rig, who: str, kind: DecisionKind = DecisionKind.APPROVE, **kw: Any) -> str:
    with pytest.raises(DecisionNotAllowedError) as err:
        rig.decide(who, kind, **kw)
    return str(err.value)


# --- the gate's quorum --------------------------------------------------------------------------


def test_a_gate_opened_from_a_workflow_with_a_quorum_writes_its_quorum_record(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    rig.open()
    record = store.get(SCOPE, Key(run_pk(RUN), "QUO#review_gate#1"))
    assert record is not None
    assert record.data == {"rules": [{"role": "reviewer", "count": 2}]}


def test_a_gate_whose_config_has_no_quorum_writes_none_and_one_approval_closes_it(
    store: Store,
) -> None:
    rig = Rig(store, quorum=None)
    a = rig.join("alice")
    rig.open()
    assert store.get(SCOPE, Key(run_pk(RUN), "QUO#review_gate#1")) is None
    assert rig.decide(a).closed


def test_a_sub_quorum_vote_never_advances_the_run(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    a, b = rig.join("alice"), rig.join("bob")
    rig.open()
    first = rig.decide(a)
    assert not first.closed
    assert first.gate.is_open
    assert rig.stored_gate().data["status"] == "OPEN"  # the store agrees: nothing closed
    assert len(rig.votes()) == 1
    second = rig.decide(b)
    assert second.closed
    assert second.gate.status.value == "APPROVED"


def test_the_quorum_names_roles_and_a_person_without_that_role_cannot_fill_it(
    store: Store,
) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 1}])
    qa = rig.join("quinn", "qa")  # holds a role, but not one this gate's eligible_roles names
    both = rig.join("rita", "reviewer", "qa")
    gate = rig.open()
    assert rig.policy.roles(SCOPE, gate, qa) == frozenset()
    assert rig.policy.roles(SCOPE, gate, both) == frozenset({"reviewer"})  # only the gate's own
    assert "role" in rig.policy.refusals(SCOPE, gate, qa, negative=False)
    assert "role" in rig.policy.refusals(
        SCOPE, gate, qa, negative=True
    )  # a veto needs the role too
    assert "role" in refused(rig, qa)
    assert "role" in refused(rig, qa, DecisionKind.REJECT)
    assert rig.stored_gate().data["status"] == "OPEN"


def test_roles_are_empty_for_a_service_an_unknown_person_and_an_unknown_gate(store: Store) -> None:
    rig = Rig(store)
    svc = rig.people.add(ServiceIdentity("bot", ISS, "bot"))
    a = rig.join("alice")
    gate = rig.open()
    assert rig.policy.roles(SCOPE, gate, svc) == frozenset()
    assert rig.policy.roles(SCOPE, gate, actor("nobody")) == frozenset()
    other = rig.open("mystery", GateType.CUSTOM)
    assert rig.policy.roles(SCOPE, other, a) == frozenset()


# --- separation of duties refuses the vote ------------------------------------------------------


def test_a_committer_named_by_a_trailer_is_refused_and_leaves_no_vote(store: Store) -> None:
    rig = Rig(store)
    a, b = rig.join("alice"), rig.join("bob")
    rig.open()
    rig.coauthor(b)
    assert "committer" in refused(rig, b)
    assert rig.votes() == []  # a refusal writes nothing
    assert rig.stored_gate().data["status"] == "OPEN"
    assert not rig.decide(a).closed  # the allowed twin: someone else may vote


def test_the_requester_is_refused_on_a_review_gate_by_the_org_floor(store: Store) -> None:
    rig = Rig(store)
    a, b = rig.join("alice"), rig.join("bob")
    rig.requester[RUN] = b
    rig.open()
    assert "requester" in refused(rig, b)
    assert rig.votes() == []
    assert not rig.decide(a).closed


def test_an_approver_of_another_gate_is_refused_where_the_gate_says_so(store: Store) -> None:
    """``approver_of`` and ``review_and_qa`` read the run's approvals from the service's own
    records, so a person who approved review cannot approve QA."""
    rig = Rig(store, quorum=None)
    a, b = rig.join("alice", "reviewer", "qa"), rig.join("bob", "reviewer", "qa")
    rig.open()
    assert rig.decide(a).closed
    qa = rig.service.open_gate(SCOPE, OpenGate(RUN, "qa_gate", GateType.QA, 1, SUBJECT))
    assert qa.name == "qa_gate"
    assert "review_and_qa" in refused(rig, a, gate="qa_gate")
    assert rig.decide(b, gate="qa_gate").closed  # the allowed twin


def test_a_sub_quorum_vote_on_review_still_bars_the_same_person_from_qa(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    a = rig.join("alice", "reviewer", "qa")
    rig.join("bob", "reviewer", "qa")
    rig.open()
    assert not rig.decide(a).closed  # a vote, not a close: it is in the VOTE# records
    rig.service.open_gate(SCOPE, OpenGate(RUN, "qa_gate", GateType.QA, 1, SUBJECT))
    assert "review_and_qa" in refused(rig, a, gate="qa_gate")


def test_a_rejection_of_review_does_not_bar_the_person_from_qa(store: Store) -> None:
    rig = Rig(store, quorum=None)
    a = rig.join("alice", "reviewer", "qa")
    rig.open()
    assert rig.decide(a, DecisionKind.REJECT).closed  # only an approval counts for the floor
    rig.service.open_gate(SCOPE, OpenGate(RUN, "qa_gate", GateType.QA, 1, SUBJECT))
    assert rig.decide(a, gate="qa_gate").closed


def test_an_earlier_voter_who_became_barred_no_longer_counts_at_the_close(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    a, b, c = rig.join("alice"), rig.join("bob"), rig.join("carol")
    rig.open()
    rig.decide(a)
    rig.coauthor(a)  # alice is later found to be a co-author
    assert not rig.decide(b).closed  # bob is the 2nd vote, but alice's no longer stands
    done = rig.decide(c)
    assert done.closed
    stored = store.query(SCOPE, run_pk(RUN), sk_prefix="OUT#").items
    assert len(stored[0].data["decision_ids"]) == 2  # bob and carol, not alice


def test_a_barred_person_cannot_veto_either(store: Store) -> None:
    rig = Rig(store)
    a, b = rig.join("alice"), rig.join("bob")
    rig.open()
    rig.coauthor(b)
    assert "committer" in refused(rig, b, DecisionKind.REJECT)
    assert rig.stored_gate().data["status"] == "OPEN"
    assert rig.decide(a, DecisionKind.REJECT).closed  # the allowed twin


def test_a_block_stops_every_approval_but_not_a_veto(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.open()
    rig.store.put(
        SCOPE,
        commit_key(RUN, "dead123"),
        {"sha": "dead123", "in_receipts": False},  # a human commit nobody attributed
        when=Absent(),
    )
    assert "unattributed_commit:dead123" in refused(rig, a)
    assert rig.decide(a, DecisionKind.REJECT).closed


def test_a_gates_own_separation_of_duties_terms_are_applied(store: Store) -> None:
    rig = Rig(store, quorum=None, sod=[{"approver_of": "qa_gate"}])
    a = rig.join("alice", "reviewer", "qa")
    b = rig.join("bob", "reviewer", "qa")
    rig.open("qa_gate", GateType.QA)
    assert rig.decide(a, gate="qa_gate").closed
    rig.open()
    assert "approver_of:qa_gate" in refused(rig, a)  # the gate's term, not only the org floors
    assert rig.decide(b).closed


def test_an_admin_resolution_of_the_requester_lifts_the_block_and_excludes_who_it_names(
    store: Store,
) -> None:
    rig = Rig(store, quorum=None)
    a, b = rig.join("alice"), rig.join("bob")
    rig.requester[RUN] = None  # nobody can say who started the run
    rig.open()
    assert "unresolved_term:requester" in refused(rig, a)
    store.put(
        SCOPE,
        Key(run_pk(RUN), "SODRES#requester#r1"),
        {"term": "requester", "actors": [b], "resolved_by": actor("admin")},
        when=Absent(),
    )
    assert "requester" in refused(rig, b)  # the resolution names bob as the requester
    assert rig.decide(a).closed  # and alice is no longer blocked


# --- fail closed --------------------------------------------------------------------------------


def test_an_unknown_gate_counts_no_decision_not_even_a_veto(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    gate = rig.open("mystery", GateType.CUSTOM)  # no stage of that name in the workflow
    assert store.get(SCOPE, Key(run_pk(RUN), "QUO#mystery#1")) is None
    assert rig.policy.roles(SCOPE, gate, a) == frozenset()
    assert "unknown_gate" in refused(rig, a, gate="mystery")
    assert "unknown_gate" in refused(rig, a, DecisionKind.REJECT, gate="mystery")
    assert rig.stored_gate("mystery").data["status"] == "OPEN"


def test_an_unknown_identity_is_refused(store: Store) -> None:
    rig = Rig(store)
    rig.open()
    assert "unknown_identity" in refused(rig, actor("nobody"))


def test_a_service_identity_never_decides(store: Store) -> None:
    rig = Rig(store)
    svc = rig.people.add(ServiceIdentity("bot", ISS, "bot"))
    rig.snapshot.add(svc)
    rig.open()
    assert "service_identity" in refused(rig, svc)
    assert "service_identity" in refused(rig, svc, DecisionKind.REJECT)


def test_an_unlinked_account_is_refused(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.people.unlinked.add(a)
    rig.open()
    assert "unlinked" in refused(rig, a)


def test_a_person_who_was_not_eligible_when_the_gate_opened_is_refused(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.snapshot.clear()  # no snapshot of who was eligible: then-and-now fails closed
    rig.open()
    assert "not_eligible_at_open" in refused(rig, a)


def test_an_error_reading_the_records_refuses_the_decision(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.open()
    rig.facts_error = RuntimeError("the store is down")
    assert "sod_error:RuntimeError" in refused(rig, a)
    assert "sod_error:RuntimeError" in refused(rig, a, DecisionKind.REJECT)
    assert rig.stored_gate().data["status"] == "OPEN"


def test_an_error_inside_the_evaluator_refuses_the_decision(
    store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.open()

    def boom(**kw: Any) -> Any:
        raise ValueError("a record the evaluator cannot use")

    monkeypatch.setattr(policy_module, "evaluate", boom)
    assert "sod_error:ValueError" in refused(rig, a)
    assert rig.votes() == []


def test_a_corrupt_commit_record_refuses_the_decision(store: Store) -> None:
    rig = Rig(store)
    a = rig.join("alice")
    rig.open()
    rig.store.put(SCOPE, commit_key(RUN, "bad1234"), {"sha": "bad1234"}, when=Absent())
    assert "sod_error:KeyError" in refused(rig, a)


def test_a_service_with_no_policy_cannot_count_a_quorum_gate(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    a = rig.join("alice")
    rig.open()
    bare = GateService(store)  # the same store, no policy
    with pytest.raises(QuorumConfigError):
        bare.decide(
            SCOPE,
            run_id=RUN,
            gate="review_gate",
            round=1,
            kind=DecisionKind.APPROVE,
            actor=a,
            surface=Surface.UI,
            subject_digest=DIGEST,
        )


def test_a_policy_for_a_non_team_scope_refuses(store: Store) -> None:
    from sto.store.ports import PLATFORM

    rig = Rig(store)
    gate = rig.open()
    assert rig.policy.refusals(PLATFORM, gate, actor("alice"), negative=False) == ["no_team"]


# --- a quorum the validator would refuse never reaches open_gate -------------------------------


@pytest.mark.parametrize(
    ("quorum", "floor", "why"),
    [
        ([{"role": "qa", "count": 1}], 1, "not an eligible role"),
        ([{"role": "reviewer", "count": 1}, {"role": "reviewer", "count": 1}], 1, "listed twice"),
        ([{"role": "reviewer", "count": 1}], 2, "needs 2 approvals by org policy"),
        (None, 2, "needs 2 approvals by org policy"),
    ],
)
def test_a_quorum_the_validator_would_refuse_never_opens_a_gate(
    store: Store, quorum: Sequence[dict[str, Any]] | None, floor: int, why: str
) -> None:
    # the schema accepts these shapes; V7 and the org min_quorum are what refuse them
    rig = Rig(store, quorum=quorum, quorum_floor=lambda team, gate_type: floor)
    rig.rules = WorkflowGates(workflow_with(quorum=quorum))
    rig.policy = GatePolicy(
        rules=rig.rules,
        directory=rig.people,
        records=rig.records,
        floors=org_policy().floors,
        quorum_floor=lambda team, gate_type: floor,
    )
    rig.service = GateService(store, policy=rig.policy)
    with pytest.raises(QuorumConfigError, match=why):
        rig.open()
    assert rig.stored_gate() is None  # nothing was written


def test_a_role_listed_twice_is_refused_by_the_policy_itself() -> None:
    cfg = GateConfig.model_construct(
        type="review",
        eligible_roles=("reviewer",),
        quorum=(
            type("Q", (), {"role": "reviewer", "count": 1})(),
            type("Q", (), {"role": "reviewer", "count": 1})(),
        ),
    )
    with pytest.raises(QuorumConfigError, match="listed twice"):
        check_quorum(cfg)


def test_a_count_below_one_is_refused() -> None:
    cfg = GateConfig.model_construct(
        type="review",
        eligible_roles=("reviewer",),
        quorum=(type("Q", (), {"role": "reviewer", "count": 0})(),),
    )
    with pytest.raises(QuorumConfigError, match="at least 1"):
        check_quorum(cfg)


def test_a_valid_quorum_is_returned_as_rules() -> None:
    cfg = workflow_with(quorum=[{"role": "reviewer", "count": 3}]).stages["review_gate"].gate  # type: ignore[union-attr]
    assert check_quorum(cfg, floor=3) == [QuorumRule("reviewer", 3)]


# --- the linear v0 workflow ---------------------------------------------------------------------


def test_the_linear_workflow_gives_each_gate_its_roles_and_a_named_quorum() -> None:
    rules = LinearGates(LINEAR_V0, default_gate_roles, {"review_gate": [QuorumRule("reviewer", 2)]})

    def gate(name: str, type_: GateType) -> Gate:
        return Gate(GateId.new(), RUN, name, type_, 1, SUBJECT)

    review = rules.gate(SCOPE, gate("review_gate", GateType.REVIEW))
    assert review is not None
    assert review.eligible_roles == ("reviewer",)
    assert [(q.role, q.count) for q in review.quorum or ()] == [("reviewer", 2)]
    qa = rules.gate(SCOPE, gate("qa_gate", GateType.QA))
    assert qa is not None
    assert qa.quorum is None
    assert qa.eligible_roles == ("qa",)
    assert rules.gate(SCOPE, gate("nope", GateType.REVIEW)) is None  # not a node
    assert rules.gate(SCOPE, gate("custom_gate", GateType.CUSTOM)) is None


def test_a_linear_node_that_is_not_a_gate_has_no_config() -> None:
    rules = LinearGates(LINEAR_V0, default_gate_roles)
    step = Gate(GateId.new(), RUN, "implement", GateType.REVIEW, 1, SUBJECT)  # a step, not a gate
    assert rules.gate(SCOPE, step) is None


def test_a_linear_gate_that_names_nobody_has_no_config() -> None:
    rules = LinearGates(LINEAR_V0, lambda gate: None)
    assert (
        rules.gate(SCOPE, Gate(GateId.new(), RUN, "review_gate", GateType.REVIEW, 1, SUBJECT))
        is None
    )


# --- the records --------------------------------------------------------------------------------


def test_the_records_skip_an_approval_by_an_actor_that_is_not_issuer_pipe_subject(
    store: Store,
) -> None:
    rig = Rig(store, quorum=None)
    gate = rig.open()
    # the dev token's actor is the bare string "dev": it can never equal an evaluated actor
    GateService(store).decide(
        SCOPE,
        run_id=RUN,
        gate="review_gate",
        round=1,
        kind=DecisionKind.APPROVE,
        actor="dev",
        surface=Surface.UI,
        subject_digest=DIGEST,
    )
    facts = rig.records.facts(SCOPE, gate)
    assert isinstance(facts, RunFacts)
    assert facts.approvals == ()


def test_the_records_need_a_team_scope(store: Store) -> None:
    from sto.store.ports import PLATFORM

    rig = Rig(store)
    gate = rig.open()
    with pytest.raises(ValueError, match="team scope"):
        rig.records.facts(PLATFORM, gate)


# --- the app builds the service with the policy -------------------------------------------------


def test_the_local_app_builds_its_gate_service_with_a_policy(tmp_path: Path) -> None:
    app = app_module.build_local({"STO_MODE": "local", "STO_DB": str(tmp_path / "d.db")})
    service = app.state.runtime._gates
    assert isinstance(service._policy, GatePolicy)  # never GateService(store) with none


def test_the_local_policy_lets_the_dev_actor_decide_and_refuses_everyone_else(
    store: Store,
) -> None:
    directory = DevDirectory(TEAM)
    service = GateService(store, policy=gate_policy(store, directory))
    service.open_gate(SCOPE, OpenGate(RUN, "review_gate", GateType.REVIEW, 1, SUBJECT))

    def decide(who: str) -> Decided:
        return service.decide(
            SCOPE,
            run_id=RUN,
            gate="review_gate",
            round=1,
            kind=DecisionKind.APPROVE,
            actor=who,
            surface=Surface.UI,
            subject_digest=DIGEST,
        )

    with pytest.raises(DecisionNotAllowedError, match="unknown_identity"):
        decide("intruder")
    assert decide("dev").closed


# --- end to end through the API -----------------------------------------------------------------

NOW = 1_800_000_000.0
CLIENT = "sto-client"
ROOT = Principal("root", frozenset({ORG_ADMIN}))
REPO = RepoRef("acme", "app")


class Api:
    """The real app, middleware and runtime, with a review gate that needs two reviewers."""

    def __init__(self, store: Store, quorum: Sequence[QuorumRule]) -> None:
        self.issuer = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
        cfg = OidcConfig(
            issuer=ISS, audience=CLIENT, audience_claim="client_id", token_use="access"
        )
        validator = OidcValidator(cfg, StaticJwks(self.issuer.jwks()), clock=lambda: NOW)
        self.mapping = RoleMapping(MemoryStore(), issuers=[ISS], clock=lambda: NOW)
        for role in ("reviewer", "qa"):
            self.mapping.set_mapping(ROOT, idp=ISS, group=f"{TEAM}-{role}", team=TEAM, role=role)
        self.store = store
        self.people = People()
        self.snapshot: set[str] = set()
        records = StoreRecords(
            store,
            read=read_records,
            requester_of=self._requester,
            snapshot=lambda scope, gate: frozenset(self.snapshot),
        )
        scm = FakeScm()
        scm.seed_branch(REPO, "main", "b0")
        scm.seed_branch(REPO, "sto/x", "abc", parent="b0")
        pr = PrRef.of(REPO, scm.ensure_draft_pr(PrSpec(REPO, "sto/x", "main", "T", "b"), "k"))
        scm.mark_ready(pr, "ready")
        subject = Subject(
            patch_id="p1",
            ticket_revision="r1",
            head_sha=scm.pr_head(pr),
            evidence_digest="e1",
            attention_digest="a1",
        )
        self.policy = GatePolicy(
            rules=LinearGates(LINEAR_V0, default_gate_roles, {"review_gate": quorum}),
            directory=self.people,
            records=records,
            floors=org_policy().floors,
        )
        self.runtime = Runtime(
            store,
            SCOPE,
            gates=GateService(store, policy=self.policy),
            effects=EffectExecutor(store, SCOPE),
            steps=SimulatedSteps(lambda run_id: subject),
            merges=scm_merge_factory(scm, store, SCOPE, lambda run_id: pr, MergeMethod.SQUASH),
            live=lambda cmd: cmd.subject,
            poll_interval=0.01,
        )
        self.app = create_app(
            self.runtime,
            token="",
            mode="prod",
            authorization=Authorization(validator, self.mapping),
        )
        self.validator = validator

    def _requester(self, scope: Scope, run_id: RunId) -> str | None:
        item = self.store.get(scope, Key(API_INDEX, str(run_id)))
        found = item.data.get("started_by") if item else None
        return found if isinstance(found, str) else None

    def user(self, sub: str, role: str = "reviewer") -> tuple[str, str]:
        """A token for a person who holds ``role`` (and is eligible when the gate opens)."""
        token = self.issuer.issue(
            sub=sub,
            audience=CLIENT,
            groups=[f"{TEAM}-{role}"],
            extra={"client_id": CLIENT, "token_use": "access"},
        )
        who = self.mapping.resolve(self.validator.validate(token))
        assert isinstance(who, UserIdentity)
        key = self.people.add(who)
        self.snapshot.add(key)
        return token, key


async def _until(pred: Callable[[], Any], what: str) -> Any:
    for _ in range(500):
        found = pred()
        if asyncio.iscoroutine(found):
            found = await found
        if found:
            return found
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def _drive(store: Store, body: Callable[[Api, httpx.AsyncClient], Any]) -> None:
    async def go() -> None:
        api = Api(store, [QuorumRule("reviewer", 2)])
        await api.runtime.start()
        try:
            transport = httpx.ASGITransport(app=api.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                await body(api, client)
        finally:
            await api.runtime.close()

    asyncio.run(asyncio.wait_for(go(), 30))


def _post(client: httpx.AsyncClient, token: str, run: str, digest: str) -> Any:
    return client.post(
        f"/runs/{run}/gates/review_gate/1/decisions",
        headers={"Authorization": f"Bearer {token}"},
        json={"kind": "approve", "subject_digest": digest},
    )


def test_through_the_api_a_barred_approver_is_refused_and_the_quorum_is_honoured(
    store: Store,
) -> None:
    async def body(api: Api, client: httpx.AsyncClient) -> None:
        starter_token, starter = api.user("starter")
        alice_token, _ = api.user("alice")
        bob_token, bob = api.user("bob")
        carol_token, _ = api.user("carol")
        run = await api.runtime.create_run(None, started_by=starter)
        rid = str(run.id)
        gates = await _until(lambda: api.runtime.gates(run.id), "the review gate to open")
        gate = next(g for g in gates if g.name == "review_gate")
        digest = gate.subject.digest()
        # the quorum record was written when the gate opened from the workflow's config
        assert store.get(SCOPE, Key(run_pk(run.id), "QUO#review_gate#1")) is not None
        api.store.put(
            SCOPE,
            commit_key(run.id, "abc1234"),
            {"sha": "abc1234", "in_receipts": True, "coauthors": [{"actor": bob, "source": "t"}]},
            when=Absent(),
        )

        # the requester (who started the run) and a named co-author are refused through the API
        for token in (starter_token, bob_token):
            r = await _post(client, token, rid, digest)
            assert (r.status_code, r.json()["error"]["code"]) == (422, "decision_not_allowed"), (
                r.text
            )
        assert store.query(SCOPE, run_pk(run.id), sk_prefix="VOTE#").items == ()

        # one eligible vote is below quorum: accepted, the gate is still open, the run waits
        r = await _post(client, alice_token, rid, digest)
        assert r.status_code == 202
        assert r.json()["gate"]["status"] == "OPEN"
        again = await _post(client, alice_token, rid, digest)
        assert (again.status_code, again.json()["error"]["code"]) == (409, "already_voted")
        state = api.runtime.state(run.id)
        assert state.run.stage == "review_gate"  # one vote of two never advanced the run

        # the second distinct eligible reviewer closes it and the run moves on
        r = await _post(client, carol_token, rid, digest)
        assert r.status_code == 202
        assert r.json()["gate"]["status"] == "APPROVED"
        await _until(
            lambda: api.runtime.state(run.id).run.stage != "review_gate", "the run to move on"
        )

    _drive(store, body)


def test_through_the_api_a_person_with_no_role_for_the_gate_is_refused(store: Store) -> None:
    async def body(api: Api, client: httpx.AsyncClient) -> None:
        starter_token, starter = api.user("starter")
        qa_token, _ = api.user("quinn", "qa")
        run = await api.runtime.create_run(None, started_by=starter)
        gates = await _until(lambda: api.runtime.gates(run.id), "the review gate to open")
        digest = next(g for g in gates if g.name == "review_gate").subject.digest()
        r = await _post(client, qa_token, str(run.id), digest)
        assert r.status_code in (403, 422), r.text  # the middleware or the policy, never a vote
        assert store.query(SCOPE, run_pk(run.id), sk_prefix="VOTE#").items == ()

    _drive(store, body)


def test_the_local_dev_actor_may_approve_review_and_then_qa(store: Store) -> None:
    """One developer plays every part on the local stack, so the local floors allow it."""
    service = GateService(store, policy=gate_policy(store, DevDirectory(TEAM)))
    for name, type_ in (("review_gate", GateType.REVIEW), ("qa_gate", GateType.QA)):
        service.open_gate(SCOPE, OpenGate(RUN, name, type_, 1, SUBJECT))
        done = service.decide(
            SCOPE,
            run_id=RUN,
            gate=name,
            round=1,
            kind=DecisionKind.APPROVE,
            actor="dev",
            surface=Surface.UI,
            subject_digest=DIGEST,
        )
        assert done.closed


def test_the_local_dev_directory_knows_one_person_who_is_linked() -> None:
    directory = DevDirectory(TEAM)
    assert directory.who(SCOPE, "dev") is not None
    assert directory.who(SCOPE, "local|dev") is None  # only the dev token's own actor string
    assert directory.linked(SCOPE, "dev")
    assert not directory.linked(SCOPE, "intruder")


def test_the_local_policy_gives_each_linear_gate_only_its_own_role(store: Store) -> None:
    policy = gate_policy(store, DevDirectory(TEAM))
    review = Gate(GateId.new(), RUN, "review_gate", GateType.REVIEW, 1, SUBJECT)
    qa = Gate(GateId.new(), RUN, "qa_gate", GateType.QA, 1, SUBJECT)
    assert policy.roles(SCOPE, review, "dev") == frozenset({"reviewer"})
    assert policy.roles(SCOPE, qa, "dev") == frozenset({"qa"})


# --- review pass 1: bindings, frozen quorum, paging ---------------------------------------------


def test_a_gate_opened_without_a_quorum_cannot_be_closed_by_a_quorum_that_appears_later(
    store: Store,
) -> None:
    rig = Rig(store, quorum=None)  # the gate opens with no quorum record
    a = rig.join("alice")
    rig.open()
    later = Rig(store, quorum=[{"role": "reviewer", "count": 2}])  # the config gains a quorum
    later.people, later.snapshot = rig.people, rig.snapshot
    later.policy = GatePolicy(
        rules=later.rules,
        directory=rig.people,
        records=rig.records,
        floors=org_policy().floors,
    )
    later.service = GateService(store, policy=later.policy)
    assert "quorum_not_frozen" in refused(later, a)
    assert "quorum_not_frozen" in refused(later, a, DecisionKind.REJECT)
    assert rig.stored_gate().data["status"] == "OPEN"
    assert rig.decide(a).closed  # the policy the gate opened under still decides it


def test_a_gate_with_its_quorum_frozen_is_not_refused_for_it(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 2}])
    a = rig.join("alice")
    rig.open()
    assert "quorum_not_frozen" not in rig.policy.refusals(SCOPE, rig.open(), a, negative=False)


def test_an_identity_whose_key_is_not_the_decisions_actor_is_refused(store: Store) -> None:
    rig = Rig(store, quorum=None)
    rig.join("alice")
    rig.open()
    liar = actor("mallory")
    rig.people.found[liar] = person("alice")  # the directory answers with someone else
    assert "actor_mismatch" in refused(rig, liar)
    assert "actor_mismatch" in refused(rig, liar, DecisionKind.REJECT)


def test_a_gate_whose_config_type_differs_from_the_gates_type_is_refused(store: Store) -> None:
    class WrongType(WorkflowGates):
        def gate(self, scope: Scope, gate: Gate) -> GateConfig | None:
            return super().gate(scope, Gate(gate.id, gate.run_id, "qa_gate", gate.type, 1, SUBJECT))

    rig = Rig(store, rules=WrongType(workflow_with()))
    a = rig.join("alice", "reviewer", "qa")
    gate = rig.open()  # a REVIEW gate that the config calls a qa gate
    assert "gate_type_mismatch" in rig.policy.refusals(SCOPE, gate, a, negative=False)
    assert "gate_type_mismatch" in rig.policy.refusals(SCOPE, gate, a, negative=True)


def test_the_dev_identity_is_issuer_local_subject_dev() -> None:
    me = DevDirectory(TEAM).who(SCOPE, "dev")
    assert isinstance(me, UserIdentity)
    assert (me.issuer, me.subject) == ("local", "dev")


def test_the_org_quorum_floor_is_asked_with_the_team_and_the_gate_type(store: Store) -> None:
    asked: list[tuple[str, str]] = []

    def floor(team: str, gate_type: str) -> int:
        asked.append((team, gate_type))
        return 1

    rig = Rig(store, quorum_floor=floor)
    rig.open()
    assert asked == [(TEAM, "review")]


class PagingStore:
    """A store that answers every prefix query one item at a time, with a cursor."""

    def __init__(self, inner: Store) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
        from sto.store.ports import Page

        cursor = kw.pop("cursor", None)
        kw.pop("limit", None)
        everything = self._inner.query(scope, pk, **kw).items
        i = int(cursor or 0)
        more = i + 1 < len(everything)
        return Page(everything[i : i + 1], str(i + 1) if more else None)


def test_the_records_follow_the_paging_cursor_to_every_approval(store: Store) -> None:
    rig = Rig(store, quorum=[{"role": "reviewer", "count": 3}])
    people = [rig.join(n) for n in ("alice", "bob", "carol")]
    gate = rig.open()
    for p in people:
        rig.decide(p)
    paged = StoreRecords(
        PagingStore(store),
        read=lambda s, sc, run: ((), ()),
        requester_of=lambda sc, run: None,
    )
    facts = paged.facts(SCOPE, gate)
    assert sorted(a.actor for a in facts.approvals) == sorted(people)  # two votes and the close
