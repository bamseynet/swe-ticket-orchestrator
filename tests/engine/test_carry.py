"""D2-31: carry-over in the engine (G13).

First slice: the git readers. File lists come from ``git diff --name-only -z --no-renames``; the
output must end in its final NUL, paths decode with surrogateescape, and ``complete`` is set only
after a full read, measured from the merge base of the subject head.
"""

from __future__ import annotations

import asyncio
import dataclasses
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_reducer_v1 import RID as REDUCER_RID
from test_reducer_v1 import W, at_review_gate
from test_reducer_v1 import wf as build_workflow

from sto.api.runtime import Runtime
from sto.config.schema import Floors
from sto.domain import (
    Decision,
    DecisionId,
    DecisionKind,
    Gate,
    GateId,
    GateStatus,
    GateType,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
    Surface,
    from_wire,
)
from sto.effects.core import EffectExecutor
from sto.engine.commands import OpenGate
from sto.engine.drivers.ports import Done
from sto.engine.handlers.carry import (
    CarryEngine,
    CarryRefused,
    SodRecheck,
    parse_name_only_z,
    record_head,
)
from sto.engine.handlers.core import GateClosed, StepSucceeded, check_carried
from sto.engine.handlers.stages import StageReported
from sto.engine.reducer import MalformedEventError
from sto.engine.reducer import next as reduce
from sto.gates.carry_over import Citation
from sto.gates.hooks import run_pk
from sto.gates.policy import WorkflowGates
from sto.gates.service import (
    CARRY_ACTOR,
    CarryStaleError,
    DecisionNotAllowedError,
    GateService,
    cite_key,
    gate_key,
)
from sto.gates.sod import RunFacts
from sto.identity.mapping import ServiceIdentity, UserIdentity
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, Key, TeamScope
from sto.workspace.git_reader import GitReader


def test_a_full_read_parses_every_path_and_is_complete() -> None:
    files = parse_name_only_z(b"a.py\x00dir/b.py\x00")
    assert files == frozenset({"a.py", "dir/b.py"})


def test_an_empty_read_is_an_empty_set_only_when_it_is_really_empty() -> None:
    assert parse_name_only_z(b"") == frozenset()


@pytest.mark.parametrize("raw", [b"a.py", b"a.py\x00b.py", b"\x00a.py\x00"])
def test_a_read_without_its_trailing_nul_or_with_an_empty_name_is_refused(raw: bytes) -> None:
    with pytest.raises(CarryRefused):
        parse_name_only_z(raw)


def test_a_path_that_is_not_utf8_is_kept_with_surrogateescape_not_dropped() -> None:
    files = parse_name_only_z(b"caf\xe9.txt\x00")
    assert files == frozenset({"caf\udce9.txt"})


# --- the git reader -----------------------------------------------------------------------------


_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PATH": "/usr/bin:/bin",
}  # fmt: skip


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=True, env=_ENV, text=True
    )
    return done.stdout.strip()


def _commit(repo: Path, name: str, text: str) -> str:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"edit {name}")
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _commit(tmp_path, "base.txt", "base\n")
    return tmp_path


def test_files_come_from_the_merge_base_of_the_subject_head(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "feature")
    head = _commit(repo, "feature.txt", "f\n")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, "main-only.txt", "m\n")  # main moved after the branch point
    reader = GitReader(repo, "main")
    base = reader.merge_base(head)
    assert base == _git(repo, "merge-base", "main", head)
    assert reader.files(base, head) == frozenset({"feature.txt"})  # not main-only.txt


def test_a_rename_lists_both_sides(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "feature")
    _git(repo, "mv", "base.txt", "moved.txt")
    _git(repo, "commit", "-qm", "rename")
    head = _git(repo, "rev-parse", "HEAD")
    reader = GitReader(repo, "main")
    assert reader.files(reader.merge_base(head), head) == frozenset({"base.txt", "moved.txt"})


def test_a_git_failure_is_a_refusal_not_an_empty_list(repo: Path) -> None:
    reader = GitReader(repo, "main")
    with pytest.raises(CarryRefused):
        reader.files("0" * 40, "1" * 40)
    with pytest.raises(CarryRefused):
        reader.merge_base("1" * 40)


def test_the_diff_is_the_canonical_patch_diff(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "feature")
    head = _commit(repo, "feature.txt", "f\n")
    reader = GitReader(repo, "main")
    diff = reader.diff(reader.merge_base(head), head)
    assert b"feature.txt" in diff
    assert diff.startswith(b"diff --git")


# --- the carried close (GateService.close_carried) ---------------------------------------------


SCOPE = TeamScope("t1")
RID = RunId.from_parts(1, bytes(10))
SUBJ = Subject(
    patch_id="p1", ticket_revision="r1", head_sha="abc", evidence_digest="e1", attention_digest="a1"
)


def _stored_gate(store: MemoryStore, name: str, round_: int) -> Gate:
    item = store.get(SCOPE, gate_key(RID, name, round_))
    assert item is not None
    return from_wire(Gate, item.data)


def _chain(service: GateService) -> int | None:
    return service.audit_version(SCOPE, RID)


def _open(service: GateService, round_: int) -> Gate:
    return service.open_gate(SCOPE, OpenGate(RID, "review", GateType.REVIEW, round_, SUBJ))


def _citation(gate: Gate, origin: Gate) -> Citation:
    return Citation(origin.id, origin.round, origin.id, origin.round, "p1", ("iss|alice",))


def _approved_round_one(service: GateService) -> Gate:
    _open(service, 1)
    service.decide(
        SCOPE, run_id=RID, gate="review", round=1, kind=DecisionKind.APPROVE,
        actor="iss|alice", surface=Surface.UI, subject_digest=SUBJ.digest(),
    )  # fmt: skip
    return _stored_gate(service._store, "review", 1)  # type: ignore[arg-type]


def test_a_carried_close_approves_under_the_service_identity_and_cites_in_audit() -> None:
    service = GateService.unpoliced_for_tests(MemoryStore())
    origin = _approved_round_one(service)
    g2 = _open(service, 2)
    cite = _citation(origin, origin)
    done = service.close_carried(SCOPE, gate=g2, citation=cite, chain=_chain(service))
    assert done.gate.status is GateStatus.APPROVED
    assert done.gate.closed_by == CARRY_ACTOR
    assert done.decision.actor == CARRY_ACTOR
    assert done.decision.kind is DecisionKind.APPROVE
    stored = service._store.get(SCOPE, Key(run_pk(RID), "CITE#review#2"))
    assert stored is not None
    assert stored.data["origin_gate_id"] == str(origin.id)
    audit = [i.data for i in service._store.query(SCOPE, run_pk(RID), table=AUDIT).items]
    carried = [a for a in audit if a.get("action") == "gate.decided" and a["actor"] == CARRY_ACTOR]
    assert carried
    assert carried[0]["data"]["citation"]["origin_gate_id"] == str(origin.id)


def test_nothing_new_since_the_read_is_a_condition_of_the_close() -> None:
    service = GateService.unpoliced_for_tests(MemoryStore())
    origin = _approved_round_one(service)
    g2 = _open(service, 2)
    stale = service._head_version(SCOPE, RID)
    # something lands after the engine read: a decision on another gate moves the chain head
    service.open_gate(SCOPE, OpenGate(RID, "qa", GateType.QA, 1, SUBJ))
    with pytest.raises(CarryStaleError):
        service.close_carried(SCOPE, gate=g2, citation=_citation(origin, origin), chain=stale)
    still = _stored_gate(service._store, "review", 2)  # type: ignore[arg-type]
    assert still.is_open


def test_a_closed_gate_or_another_subject_cannot_be_carried_closed() -> None:
    service = GateService.unpoliced_for_tests(MemoryStore())
    origin = _approved_round_one(service)
    g2 = _open(service, 2)
    edited = dataclasses.replace(g2.subject, ticket_revision="r2")
    other = dataclasses.replace(g2, subject=edited)
    with pytest.raises(CarryStaleError):
        service.close_carried(
            SCOPE, gate=other, citation=_citation(origin, origin), chain=_chain(service)
        )
    service.close_carried(SCOPE, gate=g2, citation=_citation(origin, origin), chain=_chain(service))
    with pytest.raises(CarryStaleError):
        service.close_carried(
            SCOPE, gate=g2, citation=_citation(origin, origin), chain=_chain(service)
        )


def test_the_service_identity_cannot_decide_through_the_ordinary_path() -> None:
    service = GateService.unpoliced_for_tests(MemoryStore())
    _open(service, 1)
    with pytest.raises(DecisionNotAllowedError):
        service.decide(
            SCOPE, run_id=RID, gate="review", round=1, kind=DecisionKind.APPROVE,
            actor=CARRY_ACTOR, surface=Surface.UI, subject_digest=SUBJ.digest(),
        )  # fmt: skip


# --- the engine ---------------------------------------------------------------------------------


class FakeGit:
    """Synthetic git: the merge base of a head, and the files between two commits."""

    def __init__(self) -> None:
        self.bases: dict[str, str] = {}
        self.changed: dict[tuple[str, str], frozenset[str]] = {}
        self.broken = False

    def merge_base(self, head: str) -> str:
        if self.broken:
            raise CarryRefused("git down")
        return self.bases.get(head, "base0")

    def files(self, a: str, b: str) -> frozenset[str]:
        if self.broken:
            raise CarryRefused("git down")
        return self.changed.get((a, b), frozenset({"src/x.py"}))


def _subj(head: str, patch: str, ticket: str = "r1") -> Subject:
    return Subject(
        patch_id=patch, ticket_revision=ticket, head_sha=head, evidence_digest="e1",
        attention_digest="a1",
    )  # fmt: skip


class Rig:
    def __init__(self, *, carry: str = "patch_id", allowed: frozenset[str] | None = None) -> None:
        self.store = MemoryStore()
        self.service = GateService.unpoliced_for_tests(self.store)
        self.git = FakeGit()
        self.rechecked: list[tuple[str, str]] = []
        self.ok = True
        self.engine = CarryEngine(
            self.store,
            self.service,
            self.git,
            carry_of=lambda run, name: carry,  # type: ignore[arg-type,return-value]
            allowed=lambda team: allowed,
            recheck=self._recheck,
            roles_of=lambda scope, gate, actor: {"reviewer"},
        )

    def _recheck(self, actor: str, role: str, gate: Gate, /) -> bool:
        self.rechecked.append((actor, role))
        return self.ok

    def push(self, sha: str, patch: str | None) -> None:
        record_head(self.store, SCOPE, RID, sha, patch)

    def open(self, round_: int, subject: Subject) -> Gate:
        return self.service.open_gate(
            SCOPE, OpenGate(RID, "review", GateType.REVIEW, round_, subject)
        )

    def approve(self, round_: int, subject: Subject, actor: str = "iss|alice") -> None:
        self.service.decide(
            SCOPE, run_id=RID, gate="review", round=round_, kind=DecisionKind.APPROVE,
            actor=actor, surface=Surface.UI, subject_digest=subject.digest(),
        )  # fmt: skip

    def reenter(self, round_: int, subject: Subject) -> GateClosed | None:
        gate = self.open(round_, subject)
        return self.engine.on_open(SCOPE, gate)

    def status(self, round_: int) -> GateStatus:
        item = self.store.get(SCOPE, gate_key(RID, "review", round_))
        assert item is not None
        return from_wire(Gate, item.data).status


P1, P2 = _subj("h1", "patch1"), _subj("h2", "patch2")
P1B = _subj("h3", "patch1")  # a new head with the first patch again


def _first_round(rig: Rig) -> None:
    rig.push("h1", "patch1")
    g1 = rig.open(1, P1)
    assert rig.engine.on_open(SCOPE, g1) is None  # round one has nothing to carry
    rig.approve(1, P1)


def test_same_patch_on_a_new_head_closes_by_carry_over_with_a_citation() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")  # a push with the same patch
    event = rig.reenter(2, P1B)
    assert event is not None
    assert rig.status(2) is GateStatus.APPROVED
    assert event.kind is DecisionKind.APPROVE
    assert event.actor == CARRY_ACTOR
    assert event.subject == P1B
    assert event.citation is not None
    assert event.citation.origin_round == 1
    assert event.citation.approvers == ("iss|alice",)
    assert rig.rechecked == [("iss|alice", "reviewer")]


def test_p1_p2_p1_asks_again_even_when_p2_never_reached_the_gate() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h2", "patch2")  # P2 opened no gate round
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is None
    assert rig.status(2) is GateStatus.OPEN
    assert rig.rechecked == []


def test_a_head_whose_patch_id_cannot_be_computed_refuses() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h2", None)  # the producer could not compute it
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is None
    assert rig.status(2) is GateStatus.OPEN


def test_an_origin_head_the_log_never_saw_refuses() -> None:
    rig = Rig()
    rig.open(1, P1)  # no push recorded for h1
    rig.approve(1, P1)
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is None


def test_a_log_that_does_not_end_at_the_subject_head_refuses() -> None:
    rig = Rig()
    _first_round(rig)  # the log ends at h1; the subject is h3
    assert rig.reenter(2, P1B) is None


def test_carry_over_none_or_not_allowed_by_the_org_asks_a_person() -> None:
    for rig in (Rig(carry="none"), Rig(allowed=frozenset({"none"}))):
        _first_round(rig)
        rig.push("h3", "patch1")
        assert rig.reenter(2, P1B) is None
        assert rig.status(2) is GateStatus.OPEN


def test_an_approver_who_no_longer_passes_sod_refuses() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    rig.ok = False
    assert rig.reenter(2, P1B) is None
    assert rig.status(2) is GateStatus.OPEN


def test_a_moved_base_that_touched_the_patch_refuses() -> None:
    rig = Rig()
    rig.git.bases = {"h1": "m1", "h3": "m2"}
    rig.git.changed = {("m1", "m2"): frozenset({"src/x.py"}), ("m2", "h3"): frozenset({"src/x.py"})}
    _first_round(rig)
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is None


def test_a_moved_base_that_left_the_patch_alone_still_carries() -> None:
    rig = Rig()
    rig.git.bases = {"h1": "m1", "h3": "m2"}
    rig.git.changed = {
        ("m1", "m2"): frozenset({"docs/a.md"}),
        ("m2", "h3"): frozenset({"src/x.py"}),
    }
    _first_round(rig)
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is not None


def test_a_git_failure_never_carries_and_does_not_raise() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    rig.git.broken = True
    assert rig.reenter(2, P1B) is None


def test_every_round_persists_merge_base_and_carried_from() -> None:
    rig = Rig()
    rig.git.bases = {"h1": "m1", "h3": "m2"}
    rig.git.changed = {("m1", "m2"): frozenset({"docs/a.md"})}
    _first_round(rig)
    rig.push("h3", "patch1")
    rig.reenter(2, P1B)
    r1 = rig.store.get(SCOPE, Key(run_pk(RID), "CARRY#review#1"))
    r2 = rig.store.get(SCOPE, Key(run_pk(RID), "CARRY#review#2"))
    assert r1 is not None
    assert r1.data == {"merge_base": "m1", "carried_from": None, "head_seq": 1}
    g1 = _stored_gate(rig.store, "review", 1)
    assert r2 is not None
    assert r2.data == {"merge_base": "m2", "carried_from": str(g1.id), "head_seq": 2}


def test_a_replay_of_the_open_returns_the_same_close_and_writes_nothing_more() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    first = rig.reenter(2, P1B)
    again = rig.engine.on_open(SCOPE, rig.open(2, P1B))
    assert again == first
    assert first is not None


def test_a_head_moving_after_the_read_stops_the_close() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    gate = rig.open(2, P1B)
    real = rig.engine._read_facts  # noqa: SLF001

    def moved(*a: Any, **k: Any) -> Any:
        facts = real(*a, **k)
        rig.push("h4", "patch9")  # a push lands between the read and the write
        return facts

    rig.engine._read_facts = moved  # type: ignore[method-assign]
    assert rig.engine.on_open(SCOPE, gate) is None
    assert rig.status(2) is GateStatus.OPEN


def test_a_round_one_gate_never_carries_and_a_missing_round_record_refuses() -> None:
    rig = Rig()
    rig.push("h1", "patch1")
    rig.open(1, P1)
    rig.approve(1, P1)  # no on_open: round 1 has no CARRY# record
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is None


def test_the_service_close_cannot_be_forged_with_a_citation_for_another_patch() -> None:
    rig = Rig()
    _first_round(rig)
    g2 = rig.open(2, P2)
    cite = dataclasses.replace(_citation(g2, g2), patch_id="patch1")
    with pytest.raises(CarryStaleError):
        rig.service.close_carried(SCOPE, gate=g2, citation=cite, chain=_chain(rig.service))


# --- the reducer refuses a service approval without a citation -----------------------------------


def _closed(rs: object, **kw: Any) -> GateClosed:
    base: dict[str, Any] = dict(  # noqa: C408
        run_id=REDUCER_RID, gate="review_gate", round=1, kind=DecisionKind.APPROVE,
        actor=CARRY_ACTOR, decision_id=DecisionId.new(), subject=rs.subject,  # type: ignore[attr-defined]
    )  # fmt: skip
    return GateClosed(**{**base, **kw})


def _cite_for(rs: object, patch: str | None = None) -> Citation:
    g = GateId.new()
    return Citation(g, 1, g, 1, patch or rs.subject.patch_id, ("iss|a",))  # type: ignore[attr-defined]


def test_the_reducer_refuses_a_service_approval_without_a_citation() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError):
        reduce(rs, _closed(rs), W)


def test_the_reducer_accepts_a_service_approval_that_cites_this_patch() -> None:
    rs = at_review_gate()
    t = reduce(rs, _closed(rs, citation=_cite_for(rs)), W)
    assert t.state.approvals
    assert t.state.approvals[0].gate == "review_gate"


def test_the_reducer_refuses_a_citation_for_another_patch() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError):
        reduce(rs, _closed(rs, citation=_cite_for(rs, "other")), W)


def test_a_person_cannot_attach_a_citation_to_their_own_approval() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError):
        reduce(rs, _closed(rs, actor="iss|alice", citation=_cite_for(rs)), W)


def test_a_service_actor_may_not_close_a_gate_with_anything_but_an_approval() -> None:
    rs = at_review_gate()
    with pytest.raises(MalformedEventError):
        reduce(rs, _closed(rs, kind=DecisionKind.REJECT, subject=None), W)


def test_guard_2_mirrors_the_service_identity_and_citation_key() -> None:
    from sto.effects import core as fx

    g = Gate(GateId.new(), RID, "review", GateType.REVIEW, 2, SUBJ)
    assert fx.CARRY_ACTOR == CARRY_ACTOR
    assert fx.cite_key(g) == Key(run_pk(RID), "CITE#review#2") == cite_key(g)


# --- G13 end to end on the local driver ---------------------------------------------------------


def _flow(carry: str = "patch_id") -> Any:
    def mutate(d: dict[str, Any]) -> None:
        gate = d["stages"]["review_gate"]["gate"]
        gate["carry_over"] = carry
        d["stages"]["review_gate"]["next"]["approved"] = "qa_agent"  # no merge in this flow

    return build_workflow(mutate, valid=False)  # no merge in this flow: it is left unreachable


def _head(sha: str, patch: str, ticket: str = "r1") -> Subject:
    return _subj(sha, patch, ticket)


class Script:
    """The agent steps of one run: ``implement`` reports the subjects in order, the panel is clean
    unless told otherwise, and QA passes."""

    def __init__(self, heads: list[Subject], panel: list[str] | None = None) -> None:
        self.heads, self.panel = list(heads), list(panel or [])
        self.seen: list[str] = []

    async def execute(self, key: str, command: object) -> Done:
        from sto.engine.commands import RunStep

        assert isinstance(command, RunStep)
        k = StepKey(command.run_id, command.stage, command.visit, command.attempt)
        self.seen.append(command.stage)
        if command.stage == "implement":
            return Done([StepSucceeded(k, self.heads.pop(0))])
        if command.stage == "panel":
            return Done([StageReported(k, self.panel.pop(0) if self.panel else "clean")])
        return Done([StepSucceeded(k, None)])


class E2E:
    def __init__(self, script: Script, *, carry: str = "patch_id", ok: bool = True,
                 allowed: frozenset[str] | None = None) -> None:  # fmt: skip
        self.store = MemoryStore()
        self.script = script
        self.rechecked: list[tuple[str, str]] = []
        self.ok = ok
        gates = GateService.unpoliced_for_tests(self.store)

        def recheck(actor: str, role: str, gate: Gate, /) -> bool:
            self.rechecked.append((actor, role))
            return self.ok

        self.runtime = Runtime(
            self.store, SCOPE,
            gates=gates,
            effects=EffectExecutor(self.store, SCOPE),
            steps=script,
            merges=lambda *a, **k: None,  # type: ignore[arg-type]
            live=lambda cmd: cmd.subject,
            workflow=_flow(carry),
            carry=lambda carry_of: self._engine(
                CarryEngine(
                self.store, gates, FakeGit(), carry_of=carry_of,
                allowed=lambda team: allowed, recheck=recheck,
                roles_of=lambda scope, gate, actor: {"reviewer"},
                )
            ),
        )  # fmt: skip
        self.run: Run | None = None

    def _engine(self, engine: CarryEngine) -> CarryEngine:
        self.engine = engine
        return engine

    async def start(self) -> Run:
        self.run = await self.runtime.create_run(None)
        await self.runtime.driver.run_until_idle(self.run.id)
        return self.run

    def state(self) -> Any:
        assert self.run is not None
        return self.runtime.state(self.run.id)

    async def decide(
        self, gate: str, round_: int, kind: DecisionKind, who: str = "iss|alice"
    ) -> None:
        assert self.run is not None
        subject = self.state().subject
        await self.runtime.decide(
            self.run.id, gate, round_, kind, actor=who, surface=Surface.UI,
            subject_digest=subject.digest() if subject else "", comment="x",
        )  # fmt: skip
        await self.runtime.driver.run_until_idle(self.run.id)

    def gate_status(self, name: str, round_: int) -> GateStatus:
        assert self.run is not None
        item = self.store.get(SCOPE, gate_key(self.run.id, name, round_))
        assert item is not None
        return from_wire(Gate, item.data).status


async def _to_second_review(e: E2E) -> None:
    await e.start()
    await e.decide("review_gate", 1, DecisionKind.APPROVE)  # a person approves P1
    assert e.state().run.stage == "qa_gate"
    await e.decide("qa_gate", 1, DecisionKind.REQUEST_CHANGES)  # back to implement


def test_g13_p1_then_the_same_patch_on_a_new_head_closes_by_carry_over() -> None:
    async def go() -> None:
        e = E2E(Script([_head("h1", "patch1"), _head("h3", "patch1")]))
        await _to_second_review(e)
        st = e.state()
        assert e.gate_status("review_gate", 2) is GateStatus.APPROVED  # no person decided round 2
        assert st.run.stage == "qa_gate"
        assert st.run.status is RunStatus.WAITING_HUMAN
        assert [a.gate for a in st.approvals] == ["review_gate"]
        assert e.rechecked == [("iss|alice", "reviewer")]
        item = e.store.get(SCOPE, Key(run_pk(e.run.id), "CITE#review_gate#2"))  # type: ignore[union-attr]
        assert item is not None
        assert item.data["patch_id"] == "patch1"

    asyncio.run(asyncio.wait_for(go(), 30))


def test_g13_p1_p2_p1_with_p2_never_reaching_the_gate_asks_again() -> None:
    async def go() -> None:
        e = E2E(
            Script(
                [_head("h1", "patch1"), _head("h2", "patch2"), _head("h3", "patch1")],
                panel=["clean", "findings"],  # P2 goes back to implement, never to the gate
            )
        )
        await _to_second_review(e)
        st = e.state()
        assert e.gate_status("review_gate", 2) is GateStatus.OPEN  # a person must decide again
        assert st.run.stage == "review_gate"
        assert st.run.status is RunStatus.WAITING_HUMAN
        assert e.rechecked == []

    asyncio.run(asyncio.wait_for(go(), 30))


def test_g13_an_org_that_does_not_allow_patch_id_asks_again() -> None:
    async def go() -> None:
        e = E2E(Script([_head("h1", "patch1"), _head("h3", "patch1")]), allowed=frozenset({"none"}))
        await _to_second_review(e)
        assert e.gate_status("review_gate", 2) is GateStatus.OPEN

    asyncio.run(asyncio.wait_for(go(), 30))


def test_g13_an_approver_who_fails_sod_now_asks_again() -> None:
    async def go() -> None:
        e = E2E(Script([_head("h1", "patch1"), _head("h3", "patch1")]), ok=False)
        await _to_second_review(e)
        assert e.gate_status("review_gate", 2) is GateStatus.OPEN

    asyncio.run(asyncio.wait_for(go(), 30))


# --- the approver port: sod.evaluate per voted role ---------------------------------------------


ISS = "https://idp.example.test"
ALICE = f"{ISS}|alice"
FLOORS = Floors(
    waive_allowed=True,
    mandatory_gate_roles={
        "review": ("reviewer",),
        "qa": ("qa", "reviewer"),
        "pre_push": ("reviewer",),
    },
    decision_surfaces={"review": ("ui",), "qa": ("ui",)},
    hold_after_approval_min="10m",
    identity_max_age="8h",
)  # fmt: skip


HOLDS_REVIEWER = UserIdentity("alice", ISS, frozenset({("t1", "reviewer")}))


class _Directory:
    def __init__(self, who: UserIdentity | ServiceIdentity | None, linked: bool = True) -> None:
        self.found, self.is_linked = who, linked

    def who(self, scope: object, actor: str) -> UserIdentity | ServiceIdentity | None:
        return self.found

    def linked(self, scope: object, actor: str) -> bool:
        return self.is_linked


class _Records:
    def __init__(self, opened: frozenset[str] | None, facts: RunFacts) -> None:
        self.opened, self.run_facts = opened, facts

    def opened_with(self, scope: object, gate: Gate) -> frozenset[str] | None:
        return self.opened

    def quorum_frozen(self, scope: object, gate: Gate) -> bool:
        return True

    def facts(self, scope: object, gate: Gate) -> RunFacts:
        return self.run_facts


def _recheck(
    who: UserIdentity | ServiceIdentity | None = HOLDS_REVIEWER,
    *, linked: bool = True, opened: frozenset[str] | None = frozenset({ALICE}),
    facts: RunFacts | None = None, workflow: Any = None,
) -> SodRecheck:  # fmt: skip
    from bundled_templates import template

    return SodRecheck(
        SCOPE,
        rules=WorkflowGates(workflow or template()),
        directory=_Directory(who, linked),
        records=_Records(opened, facts or RunFacts(requester="someone|else")),
        floors=FLOORS,
    )


def _gate_for_recheck() -> Gate:
    return Gate(GateId.new(), RID, "review_gate", GateType.REVIEW, 2, SUBJ)


def test_the_recheck_passes_a_person_who_still_holds_the_role_and_is_not_barred() -> None:
    assert _recheck()(ALICE, "reviewer", _gate_for_recheck()) is True


@pytest.mark.parametrize(
    "case",
    ["unknown", "service", "unlinked", "lost_role", "not_open_snapshot", "other_actor"],
)
def test_the_recheck_refuses_on_any_change_in_identity_or_membership(case: str) -> None:
    gate = _gate_for_recheck()
    holds = UserIdentity("alice", ISS, frozenset({("t1", "reviewer")}))
    rc = {
        "unknown": lambda: _recheck(None),
        "service": lambda: _recheck(ServiceIdentity("alice", ISS, "alice")),
        "unlinked": lambda: _recheck(linked=False),
        "lost_role": lambda: _recheck(UserIdentity("alice", ISS, frozenset({("t1", "qa")}))),
        "not_open_snapshot": lambda: _recheck(opened=None),
        "other_actor": lambda: _recheck(UserIdentity("mallory", ISS, holds.memberships)),
    }[case]()
    assert rc(ALICE, "reviewer", gate) is False


def test_the_recheck_asks_for_the_role_that_was_voted_not_any_role() -> None:
    gate = _gate_for_recheck()
    both = UserIdentity("alice", ISS, frozenset({("t1", "reviewer")}))
    assert _recheck(both)(ALICE, "qa", gate) is False  # holds reviewer, voted as qa


def test_the_recheck_refuses_a_blocked_gate_even_if_the_person_is_allowed() -> None:
    from sto.gates.sod import Commit

    unattributed = RunFacts(requester="someone|else", commits=(Commit("deadbeef", False),))
    assert _recheck(facts=unattributed)(ALICE, "reviewer", _gate_for_recheck()) is False


# --- review pass 1 (PR #410) ---------------------------------------------------------------------


def test_the_same_sha_returning_after_p2_asks_again() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h2", "patch2")  # P2, never at the gate
    rig.push("h1", "patch1")  # force-pushed back to the very first commit
    assert rig.reenter(2, P1) is None
    assert rig.status(2) is GateStatus.OPEN


def test_the_same_sha_returning_after_p2_asks_again_end_to_end() -> None:
    async def go() -> None:
        e = E2E(
            Script(
                [_head("h1", "patch1"), _head("h2", "patch2"), _head("h1", "patch1")],
                panel=["clean", "findings"],
            )
        )
        await _to_second_review(e)
        assert e.gate_status("review_gate", 2) is GateStatus.OPEN

    asyncio.run(asyncio.wait_for(go(), 30))


def test_an_origin_whose_head_was_not_the_log_tip_when_it_opened_cannot_be_carried_from() -> None:
    rig = Rig()
    rig.push("h1", "patch1")
    rig.push("h9", "patch9")  # the log moved on before round 1 opened on h1
    rig.open(1, P1)
    rig.engine.on_open(SCOPE, _stored_gate(rig.store, "review", 1))
    rig.approve(1, P1)
    rig.push("h1", "patch1")
    assert rig.reenter(2, P1) is None


def test_a_made_up_citation_closes_nothing() -> None:
    rig = Rig()
    g1 = rig.open(1, P1)
    fake = Citation(GateId.new(), 0, GateId.new(), 0, "patch1", ())
    with pytest.raises(CarryStaleError):
        rig.service.close_carried(SCOPE, gate=g1, citation=fake, chain=_chain(rig.service))
    assert rig.status(1) is GateStatus.OPEN


def test_a_citation_naming_a_real_but_wrong_round_closes_nothing() -> None:
    rig = Rig()
    _first_round(rig)
    g1 = _stored_gate(rig.store, "review", 1)
    g2 = rig.open(2, _subj("h3", "patch1"))
    wrong_round = Citation(g1.id, 2, g1.id, 1, "patch1", ("iss|alice",))
    wrong_gate = Citation(GateId.new(), 1, g1.id, 1, "patch1", ("iss|alice",))
    wrong_origin = Citation(g1.id, 1, GateId.new(), 1, "patch1", ("iss|alice",))
    for bad in (wrong_round, wrong_gate, wrong_origin):
        with pytest.raises(CarryStaleError):
            rig.service.close_carried(SCOPE, gate=g2, citation=bad, chain=_chain(rig.service))
    assert rig.status(2) is GateStatus.OPEN


def test_an_absent_chain_head_read_is_still_a_condition() -> None:
    rig = Rig()
    _first_round(rig)
    g1 = _stored_gate(rig.store, "review", 1)
    g2 = rig.open(2, _subj("h3", "patch1"))
    cite = Citation(g1.id, 1, g1.id, 1, "patch1", ("iss|alice",))
    with pytest.raises(CarryStaleError):
        rig.service.close_carried(SCOPE, gate=g2, citation=cite, chain=None)


def test_a_redelivered_carried_close_keeps_its_citation() -> None:
    from sto.api.runtime import _closed_event

    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    first = rig.reenter(2, P1B)
    assert first is not None
    gate = _stored_gate(rig.store, "review", 2)
    page = rig.store.query(SCOPE, f"RUN#{RID}", sk_prefix="DEC#review#2#")
    again = _closed_event(gate, from_wire(Decision, page.items[0].data))
    assert again.citation == first.citation
    check_carried(again, gate.subject)


def test_a_carried_decision_with_a_mangled_comment_redelivers_without_a_citation() -> None:
    from sto.api.runtime import _closed_event

    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    assert rig.reenter(2, P1B) is not None
    gate = _stored_gate(rig.store, "review", 2)
    page = rig.store.query(SCOPE, f"RUN#{RID}", sk_prefix="DEC#review#2#")
    decision = dataclasses.replace(
        from_wire(Decision, page.items[0].data), comment="carried-over:{"
    )
    with pytest.raises(MalformedEventError):
        check_carried(_closed_event(gate, decision), gate.subject)


def test_a_round_whose_merge_base_changed_on_replay_refuses() -> None:
    rig = Rig()
    _first_round(rig)
    rig.push("h3", "patch1")
    gate = rig.open(2, P1B)
    rig.engine._persist_round(SCOPE, gate, "m1")  # noqa: SLF001 - the round was recorded on m1
    rig.git.bases["h3"] = "m2"  # the replay now reads another merge base
    assert rig.engine.on_open(SCOPE, gate) is None
    assert rig.status(2) is GateStatus.OPEN


def test_note_head_refusing_does_not_escape_the_step() -> None:
    async def go() -> None:
        e = E2E(Script([_head("h1", "patch1")]))

        def boom(*a: Any, **k: Any) -> None:
            raise CarryRefused("log busy")

        e.engine.note_head = boom  # type: ignore[method-assign]
        await e.start()
        assert e.state().run.stage == "review_gate"  # the step still completed

    asyncio.run(asyncio.wait_for(go(), 30))


def test_carry_over_is_read_from_the_pinned_workflow_not_the_default() -> None:
    from sto.engine.reducer import RunState, pin_version

    e = E2E(Script([]), carry="none")  # the runtime's default workflow says none
    pin = pin_version("kanban-flow", 1, "sha256:" + "a" * 64)
    e.runtime._load_pin = lambda version: _flow("patch_id")  # type: ignore[method-assign]
    pinned = RunState(Run(id=RID, team="t1", workflow_version=pin))
    unpinned = RunState(Run(id=RID, team="t1", workflow_version="kanban-flow"))
    e.runtime.driver.state = lambda run_id: pinned  # type: ignore[method-assign]
    assert e.runtime.carry_over_of(RID, "review_gate") == "patch_id"
    e.runtime.driver.state = lambda run_id: unpinned  # type: ignore[method-assign]
    assert e.runtime.carry_over_of(RID, "review_gate") == "none"


def test_a_pin_that_will_not_load_means_no_carry_over() -> None:
    from sto.engine.reducer import PinUnavailableError, RunState, pin_version

    e = E2E(Script([]))
    pin = pin_version("kanban-flow", 1, "sha256:" + "a" * 64)

    def gone(version: str) -> Any:
        raise PinUnavailableError("gone")

    e.runtime._load_pin = gone  # type: ignore[method-assign]
    e.runtime.driver.state = lambda run_id: RunState(  # type: ignore[method-assign]
        Run(id=RID, team="t1", workflow_version=pin)
    )
    assert e.runtime.carry_over_of(RID, "review_gate") is None


def test_the_diff_does_not_depend_on_the_repositorys_own_config(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "feature")
    (repo / "base.txt").write_text("l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\n")
    _git(repo, "commit", "-qam", "more")
    _git(repo, "mv", "base.txt", "moved.txt")
    head = _commit(repo, "extra.txt", "x\n")
    reader = GitReader(repo, "main")
    base = reader.merge_base(head)
    plain = reader.diff(base, head)
    for key, value in (
        ("diff.renames", "true"),
        ("diff.context", "9"),
        ("diff.noprefix", "true"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.algorithm", "patience"),
    ):
        _git(repo, "config", key, value)
    assert reader.diff(base, head) == plain
    assert b"rename from" not in plain
    assert b"\n--- a/" in plain or b"--- /dev/null" in plain
