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
    InvalidTransitionError,
    Receipt,
    Run,
    RunId,
    RunStatus,
    Step,
    StepKey,
    StepStatus,
    Subject,
    Surface,
    effect_key,
    to_wire,
)

RID = RunId.from_parts(1, bytes(10))
GID = GateId.from_parts(2, bytes(10))


def head(**kw: object) -> Subject:
    base: dict[str, object] = dict(
        head_sha="a", patch_id="p", evidence_digest="e", attention_digest="x", ticket_revision="t"
    )
    return Subject(**{**base, **kw})  # type: ignore[arg-type]


def gate(**kw: object) -> Gate:
    base: dict[str, object] = dict(
        id=GID, run_id=RID, name="review", type=GateType.REVIEW, round=1, subject=head()
    )
    return Gate(**{**base, **kw})  # type: ignore[arg-type]


def effect(**kw: object) -> Effect:
    base: dict[str, object] = dict(
        id=EffectId.from_parts(3, bytes(10)),
        run_id=RID,
        type="pr.merge",
        stage="merge",
        visit=1,
        klass=EffectClass.GATED,
        idempotency_key="k",
        requires_gates=("review_gate",),
    )
    return Effect(**{**base, **kw})  # type: ignore[arg-type]


# Subject -----------------------------------------------------------------------------------


def test_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        head().head_sha = "b"  # type: ignore[misc]


def test_digest_golden_pin() -> None:
    # If this changes, every stored approval is invalidated. Bump the payload version instead.
    assert head().digest() == "53203f7935648cd52da56e9cf1401bba9aeaa4e899ba2e16f8e208e9da22c5a6"
    pp = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t")
    assert pp.digest() == "c30439639cce6a2bf7582ec718adff247db246fb5ee29567b6d913cf4e80a36b"


def test_merge_sha_does_not_change_digest() -> None:
    assert dataclasses.replace(head(), merge_sha="m").digest() == head().digest()


def test_digest_changes_with_every_bound_field() -> None:
    for f in ("head_sha", "patch_id", "evidence_digest", "attention_digest", "ticket_revision"):
        assert dataclasses.replace(head(), **{f: "zz"}).digest() != head().digest()


def test_pre_push_shape() -> None:
    s = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t")
    assert s.head_sha is None
    assert s.digest() != Subject.pre_push(base_sha="c", patch_id="p", ticket_revision="t").digest()


@pytest.mark.parametrize(
    "kw",
    [
        {"head_sha": ""},
        {"patch_id": ""},
        {"ticket_revision": ""},
        {"evidence_digest": None},
        {"attention_digest": None},
        {"evidence_digest": ""},
        {"base_sha": "b"},  # both head and base
        {"head_sha": None},  # neither
    ],
)
def test_head_subject_rejects(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="subject"):
        head(**kw)


@pytest.mark.parametrize(
    "extra", [{"evidence_digest": "e"}, {"attention_digest": "x"}, {"merge_sha": "m"}]
)
def test_pre_push_rejects_head_only_fields(extra: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="subject"):
        Subject(patch_id="p", ticket_revision="t", base_sha="b", **extra)


# Decision ----------------------------------------------------------------------------------


def test_negative_set_is_explicit_and_every_member_covered() -> None:
    expected = {
        DecisionKind.APPROVE: False,
        DecisionKind.WAIVE: False,
        DecisionKind.REQUEST_CHANGES: True,
        DecisionKind.REJECT: True,
        DecisionKind.RETEST: True,
    }
    assert set(DecisionKind) == set(expected)
    for kind, neg in expected.items():
        assert kind.is_negative is neg


def decision(**kw: object) -> Decision:
    base: dict[str, object] = dict(
        id=DecisionId.from_parts(4, bytes(10)),
        gate_id=GID,
        round=1,
        actor="alice",
        surface=Surface.UI,
        kind=DecisionKind.APPROVE,
        subject_digest="d",
    )
    return Decision(**{**base, **kw})  # type: ignore[arg-type]


def test_decision_rules() -> None:
    assert decision().kind is DecisionKind.APPROVE
    for k in (
        DecisionKind.REJECT,
        DecisionKind.REQUEST_CHANGES,
        DecisionKind.RETEST,
        DecisionKind.WAIVE,
    ):
        with pytest.raises(ValueError, match="comment"):
            decision(kind=k, comment="  ")
        decision(kind=k, comment="because")
    for k in (DecisionKind.APPROVE, DecisionKind.WAIVE):
        with pytest.raises(ValueError, match="subject_digest"):
            decision(kind=k, subject_digest="", comment="why")
    decision(kind=DecisionKind.REJECT, comment="no", subject_digest="")  # veto needs no digest
    with pytest.raises(ValueError, match="round"):
        decision(round=0)
    with pytest.raises(ValueError, match="actor"):
        decision(actor="")


def test_decision_coerces_enums_from_the_store() -> None:
    d = decision(surface="slack", kind="approve")
    assert d.surface is Surface.SLACK
    assert d.kind is DecisionKind.APPROVE
    with pytest.raises(ValueError, match="carrier"):
        decision(surface="carrier pigeon")


# Run / Gate / Effect / Step ------------------------------------------------------------------


def test_run_advance_goes_through_transition() -> None:
    run = Run(id=RID, team="t", stage="implement", workflow_version="v1")
    running = run.advance(RunStatus.RUNNING)
    assert running.status is RunStatus.RUNNING
    with pytest.raises(InvalidTransitionError):
        run.advance(RunStatus.DONE)
    blocked = running.advance(RunStatus.BLOCKED, blocked_reason="loop_exhausted")
    assert blocked.blocked_reason == "loop_exhausted"
    assert blocked.advance(RunStatus.RUNNING).blocked_reason is None
    with pytest.raises(ValueError, match="blocked_reason"):
        running.advance(RunStatus.BLOCKED)
    done = running.advance(RunStatus.DONE, incident=True)
    assert done.incident


def test_run_rules() -> None:
    with pytest.raises(ValueError, match="version"):
        Run(id=RID, team="t", version=-1)
    with pytest.raises(ValueError, match="incident"):
        Run(id=RID, team="t", incident=True)  # only a DONE run can be done_with_incident
    with pytest.raises(ValueError, match="blocked_reason"):
        Run(id=RID, team="t", blocked_reason="x")
    assert Run(id=RID, team="t", status="RUNNING").status is RunStatus.RUNNING  # type: ignore[arg-type]


def test_replace_can_still_bypass_advance() -> None:
    # Documented limit: the types do not stop dataclasses.replace; advance() is the checked path.
    run = Run(id=RID, team="t")
    assert dataclasses.replace(run, status=RunStatus.DONE).status is RunStatus.DONE


def test_gate_rules_and_advance() -> None:
    g = gate()
    assert g.is_open
    closed = g.advance(GateStatus.APPROVED, closed_by="alice")
    assert not closed.is_open
    assert closed.closed_by == "alice"
    assert closed.advance(GateStatus.INVALIDATED).status is GateStatus.INVALIDATED
    with pytest.raises(InvalidTransitionError):
        closed.advance(GateStatus.REJECTED)
    for bad in ({"round": 0}, {"name": ""}, {"closed_by": "x"}):
        with pytest.raises(ValueError, match="gate"):
            gate(**bad)
    assert gate(type="qa").type is GateType.QA
    assert {t.value for t in GateType} == {"review", "qa", "custom", "pre_push"}


def test_effect_gated_requires_gates_and_coerces() -> None:
    with pytest.raises(ValueError, match="requires_gates"):
        effect(requires_gates=())
    with pytest.raises(ValueError, match="requires_gates"):
        effect(klass="gated", requires_gates=())
    with pytest.raises(ValueError, match="blank"):
        effect(requires_gates=[""])
    with pytest.raises(ValueError, match="requires_gates"):
        effect(klass=EffectClass.SCOPED, requires_gates=("g",))
    with pytest.raises(TypeError):
        effect(requires_gates="review_gate")
    e = effect(klass="gated", requires_gates=["a", "b"], status="PLANNED")
    assert e.klass is EffectClass.GATED
    assert e.requires_gates == ("a", "b")
    assert e.status is EffectStatus.PLANNED
    hash(e)  # hashable after coercion
    assert effect(klass="scoped", requires_gates=()).klass is EffectClass.SCOPED


def test_effect_adr0011_fields_and_receipt() -> None:
    e = effect(decision_ids=[DecisionId.from_parts(9, bytes(10))], subject_digest="d")
    assert len(e.decision_ids) == 1
    assert (e.stage, e.visit) == ("merge", 1)
    a = e.advance(EffectStatus.ATTEMPTING)
    with pytest.raises(ValueError, match="receipt"):
        a.advance(EffectStatus.CONFIRMED)  # no receipt
    with pytest.raises(ValueError, match="read-back"):
        a.advance(
            EffectStatus.CONFIRMED, receipt=Receipt("42", "https://x", read_back_verified=False)
        )
    ok = a.advance(
        EffectStatus.CONFIRMED, receipt=Receipt("42", "https://x", read_back_verified=True)
    )
    assert ok.receipt is not None
    assert ok.receipt.external_id == "42"
    with pytest.raises(InvalidTransitionError):
        ok.advance(EffectStatus.ATTEMPTING)
    with pytest.raises(ValueError, match="receipt"):
        effect(receipt=Receipt("1", "u", True))  # PLANNED cannot already hold a receipt
    with pytest.raises(ValueError, match="visit"):
        effect(visit=0)


def test_step() -> None:
    key = StepKey(run_id=RID, stage="implement", visit=1, attempt=2)
    s = Step(key=key, fence=3, session_id="sess", artifact_refs=("a",))
    assert s.status is StepStatus.PENDING
    assert s.artifact_refs == ("a",)
    r = s.advance(StepStatus.RUNNING).advance(StepStatus.SUCCEEDED)
    assert r.status is StepStatus.SUCCEEDED
    with pytest.raises(InvalidTransitionError):
        r.advance(StepStatus.RUNNING)
    with pytest.raises(ValueError, match="fence"):
        Step(key=key, fence=-1)
    with pytest.raises(ValueError, match="step"):
        StepKey(run_id=RID, stage="", visit=1)


# effect_key ---------------------------------------------------------------------------------


def test_effect_key_no_delimiter_collision() -> None:
    assert effect_key(RID, "a|1", 2, "x", "d") != effect_key(RID, "a", 1, "2|x", "d")


@given(st.text(), st.integers(1, 5), st.text(), st.text())
def test_effect_key_deterministic_and_sensitive(stage: str, visit: int, typ: str, dig: str) -> None:
    k = effect_key(RID, stage, visit, typ, dig)
    assert k == effect_key(RID, stage, visit, typ, dig)
    assert k != effect_key(RID, stage, visit + 1, typ, dig)


# wire ---------------------------------------------------------------------------------------


def test_models_serialize_ids_as_ulid_strings() -> None:
    wire = to_wire(Run(id=RID, team="t"))
    assert wire["id"] == str(RID)
    assert wire["status"] == "QUEUED"
    json.dumps(wire)
    w = to_wire(effect())
    assert w["requires_gates"] == ["review_gate"]


# pass 2 -------------------------------------------------------------------------------------


def test_pre_push_gate_type() -> None:
    assert GateType.PRE_PUSH.value == "pre_push"
    pp = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t")
    g = gate(type="pre_push", subject=pp)
    assert g.type is GateType.PRE_PUSH
    with pytest.raises(ValueError, match="pre_push"):
        gate(type=GateType.PRE_PUSH)  # head subject on a pre_push gate


@pytest.mark.parametrize("gtype", list(GateType))
@pytest.mark.parametrize("short", [True, False], ids=["pre_push_subject", "head_subject"])
def test_gate_type_and_subject_shape_agree(gtype: GateType, short: bool) -> None:
    subject = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t") if short else head()
    if (gtype is GateType.PRE_PUSH) == short:
        assert gate(type=gtype, subject=subject).type is gtype
    else:
        with pytest.raises(ValueError, match="pre_push"):
            gate(type=gtype, subject=subject)


@pytest.mark.parametrize("terminal", [s for s in RunStatus if s.is_terminal])
def test_incident_on_any_terminal_status(terminal: RunStatus) -> None:
    assert Run(id=RID, team="t", status=terminal, incident=True).incident


def test_incident_on_stop_path() -> None:
    # PLAN 6.2 (the "whichever terminal it reaches, including Stop" paragraph) is wider than its
    # next sentence ("DONE with an incident flag"); we follow the wider one. No new edge.
    run = Run(id=RID, team="t", status=RunStatus.RUNNING)
    stopped = run.advance(RunStatus.CANCELLING).advance(RunStatus.CANCELLED, incident=True)
    assert stopped.incident
    assert stopped.status is RunStatus.CANCELLED
    with pytest.raises(InvalidTransitionError):
        run.advance(RunStatus.CANCELLING).advance(RunStatus.DONE)
    with pytest.raises(ValueError, match="incident"):
        Run(id=RID, team="t", status=RunStatus.RUNNING, incident=True)


@pytest.mark.parametrize(
    "status", [s for s in EffectStatus if s not in (EffectStatus.PLANNED, EffectStatus.VOIDED)]
)
def test_gated_effect_past_claim_needs_decision_and_digest(status: EffectStatus) -> None:
    rcpt = Receipt("1", "u", True)
    kw: dict[str, object] = {
        "status": status,
        "receipt": rcpt if status is EffectStatus.CONFIRMED else None,
    }
    with pytest.raises(ValueError, match="decision_ids"):
        effect(subject_digest="d", **kw)
    with pytest.raises(ValueError, match="subject_digest"):
        effect(decision_ids=(DecisionId.from_parts(9, bytes(10)),), **kw)
    effect(decision_ids=(DecisionId.from_parts(9, bytes(10)),), subject_digest="d", **kw)


@pytest.mark.parametrize("status", [EffectStatus.PLANNED, EffectStatus.VOIDED])
def test_planned_and_voided_gated_effects_are_exempt(status: EffectStatus) -> None:
    assert effect(status=status).decision_ids == ()


def test_scoped_effect_needs_no_decision() -> None:
    effect(klass=EffectClass.SCOPED, requires_gates=(), status=EffectStatus.ATTEMPTING)


def test_effect_attempts_intent_frozen_subject() -> None:
    e = effect(attempts=2, intent="abc123", frozen_subject=head(merge_sha="m"))
    assert (e.attempts, e.intent) == (2, "abc123")
    assert e.frozen_subject is not None
    assert e.frozen_subject.merge_sha == "m"
    with pytest.raises(ValueError, match="attempts"):
        effect(attempts=-1)
    with pytest.raises(TypeError, match="frozen_subject"):
        effect(frozen_subject={"x": 1})
    with pytest.raises(ValueError, match="intent"):
        effect(intent=" ")


def test_step_can_fail_before_running() -> None:
    s = Step(key=StepKey(run_id=RID, stage="s", visit=1))
    assert s.advance(StepStatus.FAILED).status is StepStatus.FAILED


def test_receipt_flag_must_be_a_real_bool() -> None:
    with pytest.raises(TypeError, match="read_back_verified"):
        Receipt("1", "u", "false")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="simulated"):
        Receipt("1", "u", True, simulated=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="external_id"):
        Receipt("  ", "u", True)


def test_whitespace_only_required_strings_rejected() -> None:
    with pytest.raises(ValueError, match="actor"):
        decision(actor="  ")
    with pytest.raises(ValueError, match="subject_digest"):
        decision(subject_digest=" ")
    with pytest.raises(TypeError, match="comment"):
        decision(comment=None)
    for f in ("patch_id", "ticket_revision", "head_sha", "evidence_digest"):
        with pytest.raises(ValueError, match="subject"):
            head(**{f: " "})
    with pytest.raises(ValueError, match="closed_by"):
        gate(status=GateStatus.APPROVED, closed_by=" ")
    with pytest.raises(ValueError, match="team"):
        Run(id=RID, team=" ")
    with pytest.raises(ValueError, match="stage"):
        effect(stage=" ")


def test_step_usage_cannot_be_negative() -> None:
    with pytest.raises(ValueError, match="usage"):
        Step(key=StepKey(run_id=RID, stage="s", visit=1), usage=(("tokens", -1),))


def test_numeric_fields_reject_bool_and_non_int() -> None:
    with pytest.raises(TypeError, match="version"):
        Run(id=RID, team="t", version=True)
    with pytest.raises(TypeError, match="round"):
        gate(round="1")


def test_full_gated_claim_through_advance_only() -> None:
    dec = DecisionId.from_parts(9, bytes(10))
    planned = effect()
    assert planned.attempts == 0
    claimed = planned.advance(
        EffectStatus.ATTEMPTING, decision_ids=(dec,), subject_digest="d", intent="abc123"
    )
    assert (claimed.attempts, claimed.intent, claimed.decision_ids) == (1, "abc123", (dec,))
    retry = claimed.advance(EffectStatus.RETRYING)
    assert retry.attempts == 1  # RETRYING itself is not an attempt
    again = retry.advance(EffectStatus.ATTEMPTING)
    assert again.attempts == 2  # PLAN 6.3: RETRYING -> ATTEMPTING is another attempt
    accepted = again.advance(EffectStatus.ACCEPTED)
    done = accepted.advance(
        EffectStatus.CONFIRMED,
        receipt=Receipt("42", "u", True),
        frozen_subject=head(merge_sha="m"),
    )
    assert done.status is EffectStatus.CONFIRMED
    assert done.frozen_subject is not None
    assert done.attempts == 2
    with pytest.raises(ValueError, match="decision_ids"):
        planned.advance(EffectStatus.ATTEMPTING)  # a gated claim without a decision


def test_frozen_subject_is_a_merged_head_subject() -> None:
    effect(frozen_subject=head(merge_sha="m"))
    with pytest.raises(ValueError, match="frozen_subject"):
        effect(frozen_subject=head())  # no merge_sha
    with pytest.raises(ValueError, match="frozen_subject"):
        effect(frozen_subject=Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t"))


def test_unordered_collections_rejected() -> None:
    with pytest.raises(TypeError, match="requires_gates"):
        effect(requires_gates={"a", "b"})
    with pytest.raises(TypeError, match="decision_ids"):
        effect(decision_ids={DecisionId.from_parts(1, bytes(10))}, subject_digest="d")
