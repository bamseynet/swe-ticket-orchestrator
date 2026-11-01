"""from_wire is the inverse of to_wire; constructors reject wrong-typed IDs and records."""

from __future__ import annotations

import dataclasses
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sto.domain import (
    Decision,
    DecisionId,
    DecisionKind,
    Effect,
    EffectClass,
    EffectId,
    EffectStatus,
    Gate,
    GateId,
    GateStatus,
    GateType,
    InvalidIdError,
    Receipt,
    Run,
    RunId,
    RunStatus,
    Step,
    StepKey,
    StepStatus,
    Subject,
    Surface,
    from_wire,
    to_wire,
)

ms = st.integers(min_value=0, max_value=2**48 - 1)
rand = st.binary(min_size=10, max_size=10)
ns = st.from_regex(r"[a-z0-9]{1,8}", fullmatch=True)
run_ids = st.builds(RunId.from_parts, ms, rand)
gate_ids = st.builds(GateId.from_parts, ms, rand)
dec_ids = st.builds(DecisionId.from_parts, ms, rand)
eff_ids = st.builds(EffectId.from_parts, ms, rand)
pos = st.integers(1, 50)
nonneg = st.integers(0, 50)


@st.composite
def head_subjects(draw: st.DrawFn) -> Subject:
    return Subject(
        head_sha=draw(ns),
        patch_id=draw(ns),
        evidence_digest=draw(ns),
        attention_digest=draw(ns),
        ticket_revision=draw(ns),
        merge_sha=draw(st.none() | ns),
    )


pre_push_subjects = st.builds(
    lambda b, p, t: Subject.pre_push(base_sha=b, patch_id=p, ticket_revision=t), ns, ns, ns
)
subjects = head_subjects() | pre_push_subjects
merged_subjects = head_subjects().map(lambda s: dataclasses.replace(s, merge_sha="m"))
receipts = st.builds(Receipt, ns, ns, st.booleans(), st.booleans())


@st.composite
def decisions(draw: st.DrawFn) -> Decision:
    return Decision(
        id=draw(dec_ids),
        gate_id=draw(gate_ids),
        round=draw(pos),
        actor=draw(ns),
        surface=draw(st.sampled_from(Surface)),
        kind=draw(st.sampled_from(DecisionKind)),
        subject_digest=draw(ns),
        comment=draw(ns),
    )


@st.composite
def minimal_decisions(draw: st.DrawFn) -> Decision:
    """Empty comment / digest wherever the rules allow them."""
    kind = draw(st.sampled_from(DecisionKind))
    return Decision(
        id=draw(dec_ids),
        gate_id=draw(gate_ids),
        round=draw(pos),
        actor=draw(ns),
        surface=draw(st.sampled_from(Surface)),
        kind=kind,
        subject_digest="" if kind.is_negative else draw(ns),
        comment=draw(ns) if kind is not DecisionKind.APPROVE else "",
    )


@st.composite
def gates(draw: st.DrawFn) -> Gate:
    typ = draw(st.sampled_from(GateType))
    subject = draw(pre_push_subjects if typ is GateType.PRE_PUSH else head_subjects())
    g = Gate(
        id=draw(gate_ids),
        run_id=draw(run_ids),
        name=draw(ns),
        type=typ,
        round=draw(pos),
        subject=subject,
    )
    status = draw(st.sampled_from([s for s in GateStatus if s is not GateStatus.OPEN]))
    return (
        g
        if draw(st.booleans())
        else Gate(**{**g.__dict__, "status": status, "closed_by": draw(ns)})
    )


@st.composite
def runs(draw: st.DrawFn) -> Run:
    status = draw(st.sampled_from(RunStatus))
    return Run(
        id=draw(run_ids),
        team=draw(ns),
        status=status,
        version=draw(nonneg),
        stage=draw(st.none() | ns),
        workflow_version=draw(st.none() | ns),
        blocked_reason=draw(ns) if status is RunStatus.BLOCKED else None,
        incident=draw(st.booleans()) if status.is_terminal else False,
    )


@st.composite
def effects(draw: st.DrawFn) -> Effect:
    klass = draw(st.sampled_from(EffectClass))
    status = draw(st.sampled_from(EffectStatus))
    gated = klass is EffectClass.GATED
    return Effect(
        id=draw(eff_ids),
        run_id=draw(run_ids),
        type=draw(ns),
        stage=draw(ns),
        visit=draw(pos),
        klass=klass,
        idempotency_key=draw(ns),
        status=status,
        requires_gates=tuple(draw(st.lists(ns, min_size=1, max_size=3))) if gated else (),
        decision_ids=tuple(draw(st.lists(dec_ids, min_size=1, max_size=3))) if gated else (),
        subject_digest=draw(ns) if gated else draw(st.none() | ns),
        receipt=draw(
            st.builds(Receipt, ns, ns, st.just(True), st.booleans())
            if status is EffectStatus.CONFIRMED
            else (st.none() | receipts)
            if status in (EffectStatus.ACCEPTED, EffectStatus.FAILED, EffectStatus.VOIDED)
            else st.none()
        ),
        attempts=draw(nonneg),
        intent=draw(st.none() | ns),
        frozen_subject=draw(st.none() | merged_subjects),
    )


steps = st.builds(
    Step,
    key=st.builds(StepKey, run_ids, ns, pos, pos),
    fence=nonneg,
    session_id=st.none() | ns,
    status=st.sampled_from(StepStatus),
    usage=st.lists(st.tuples(ns, nonneg), max_size=3).map(tuple),
    artifact_refs=st.lists(ns, max_size=3).map(tuple),
)


@pytest.mark.parametrize(
    ("cls", "strategy"),
    [
        (Subject, subjects),
        (Decision, decisions()),
        (Decision, minimal_decisions()),
        (Gate, gates()),
        (Run, runs()),
        (Effect, effects()),
        (Step, steps),
        (Receipt, receipts),
        (StepKey, steps.map(lambda s: s.key)),
    ],
    ids=lambda x: getattr(x, "__name__", ""),
)
def test_from_wire_inverts_to_wire(cls: type, strategy: st.SearchStrategy[object]) -> None:
    @given(strategy)
    def check(x: object) -> None:
        assert from_wire(cls, to_wire(x)) == x
        assert from_wire(cls, json.loads(json.dumps(to_wire(x)))) == x  # through real JSON

    check()


def test_gate_from_wire_holds_a_real_subject() -> None:
    g = Gate(
        id=GateId.new(),
        run_id=RunId.new(),
        name="g",
        type=GateType.QA,
        round=1,
        subject=Subject(
            head_sha="a",
            patch_id="p",
            evidence_digest="e",
            attention_digest="x",
            ticket_revision="t",
        ),
    )
    back = from_wire(Gate, to_wire(g))
    assert isinstance(back.subject, Subject)
    assert back.subject.digest() == g.subject.digest()


def test_from_wire_rejects_junk() -> None:
    w = to_wire(Run(id=RunId.new(), team="t"))
    with pytest.raises(ValueError, match="unexpected"):
        from_wire(Run, {**w, "bogus": 1})
    with pytest.raises(InvalidIdError):
        from_wire(Run, {**w, "id": "junk"})
    with pytest.raises(ValueError, match="RUNNIN"):
        from_wire(Run, {**w, "status": "RUNNIN"})
    with pytest.raises(TypeError):
        from_wire(Run, {**w, "id": 5})


def test_constructors_reject_wrong_typed_ids_and_records() -> None:
    with pytest.raises(TypeError, match="id"):
        Run(id="junk", team="t")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="id"):
        Run(id=GateId.new(), team="t")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="subject"):
        Gate(
            id=GateId.new(),
            run_id=RunId.new(),
            name="g",
            type=GateType.QA,
            round=1,
            subject={"head_sha": "a"},  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="decision_ids"):
        Effect(
            id=EffectId.new(),
            run_id=RunId.new(),
            type="t",
            stage="s",
            visit=1,
            klass=EffectClass.GATED,
            idempotency_key="k",
            requires_gates=("g",),
            decision_ids=["nope"],  # type: ignore[arg-type]
            subject_digest="d",
        )
    with pytest.raises(TypeError, match="receipt"):
        Effect(
            id=EffectId.new(),
            run_id=RunId.new(),
            type="t",
            stage="s",
            visit=1,
            klass=EffectClass.SCOPED,
            idempotency_key="k",
            receipt={"x": 1},  # type: ignore[arg-type]
        )
