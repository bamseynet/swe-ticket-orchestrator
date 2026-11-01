"""D0-07: domain types. Frozen, no I/O, extensible without edits to ``sto.domain``."""

from __future__ import annotations

import dataclasses

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sto.domain import (
    DecisionKind,
    DegradedError,
    EffectClass,
    EffectStatus,
    FailureClass,
    GateId,
    GateStatus,
    InvalidIdError,
    InvalidTransitionError,
    PermanentError,
    Registry,
    RunId,
    RunStatus,
    StoError,
    Subject,
    TransientError,
    Ulid,
    can_transition,
    transition,
)

ms = st.integers(min_value=0, max_value=2**48 - 1)
rand = st.binary(min_size=10, max_size=10)


@given(ms, rand)
def test_ulid_roundtrip(t: int, r: bytes) -> None:
    u = Ulid.from_parts(t, r)
    assert len(str(u)) == 26
    assert Ulid.parse(str(u)) == u
    assert u.timestamp_ms == t


@given(ms, ms, rand)
def test_ulid_sorts_by_time(a: int, b: int, r: bytes) -> None:
    ua, ub = Ulid.from_parts(a, r), Ulid.from_parts(b, r)
    assert (a < b) == (str(ua) < str(ub)) or a == b


@pytest.mark.parametrize("bad", ["", "abc", "U" * 26, "8" * 26, "0" * 25])
def test_ulid_rejects_invalid(bad: str) -> None:
    with pytest.raises(InvalidIdError):
        Ulid.parse(bad)


def test_ids_are_distinct_types() -> None:
    v = Ulid.from_parts(1, bytes(10)).value
    assert RunId(v) != GateId(v)  # type: ignore[comparison-overlap]  # mypy forbids it too
    assert RunId(v) == RunId(v)
    assert hash(RunId(v)) == hash(RunId(v))


def test_new_ids_unique() -> None:
    assert RunId.new() != RunId.new()


def test_models_are_frozen() -> None:
    s = Subject(
        head_sha="a", patch_id="p", evidence_digest="e", attention_digest="x", ticket_revision="t"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.head_sha = "b"  # type: ignore[misc]


def test_subject_digest_changes_with_any_field() -> None:
    base = Subject(
        head_sha="a", patch_id="p", evidence_digest="e", attention_digest="x", ticket_revision="t"
    )
    for f in ("head_sha", "patch_id", "evidence_digest", "attention_digest", "ticket_revision"):
        assert dataclasses.replace(base, **{f: "zz"}).digest() != base.digest()
    assert base.digest() == dataclasses.replace(base).digest()


def test_pre_push_subject_has_no_head_sha() -> None:
    s = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="t")
    assert s.head_sha is None
    assert s.base_sha == "b"
    assert s.digest() != Subject.pre_push(base_sha="c", patch_id="p", ticket_revision="t").digest()


def test_negative_decisions() -> None:
    assert not DecisionKind.APPROVE.is_negative
    for k in (DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES):
        assert k.is_negative


def test_failure_classes() -> None:
    assert {c.value for c in FailureClass} == {"transient", "permanent", "degraded"}
    assert TransientError("x").failure_class is FailureClass.TRANSIENT
    assert PermanentError("x").failure_class is FailureClass.PERMANENT
    assert DegradedError("x").failure_class is FailureClass.DEGRADED
    assert issubclass(TransientError, StoError)


def test_stoerror_cannot_be_unclassified() -> None:
    with pytest.raises(TypeError):
        StoError("x")

    class Sub(StoError):
        pass

    with pytest.raises(TypeError):
        Sub("x")


def test_permanent_is_never_retryable() -> None:
    assert TransientError("x").retryable
    assert not PermanentError("x").retryable
    assert not DegradedError("x").retryable


# transitions -------------------------------------------------------------------------------


def test_terminal_run_states_have_no_exits() -> None:
    for s in (
        RunStatus.DONE,
        RunStatus.REJECTED,
        RunStatus.CLOSED,
        RunStatus.EXPIRED,
        RunStatus.CANCELLED,
    ):
        assert s.is_terminal
        assert all(not can_transition(s, t) for t in RunStatus)


def test_run_known_edges() -> None:
    assert can_transition(RunStatus.QUEUED, RunStatus.RUNNING)
    assert can_transition(RunStatus.BLOCKED, RunStatus.RUNNING)
    assert can_transition(RunStatus.CANCELLING, RunStatus.CANCELLED)
    assert not can_transition(RunStatus.QUEUED, RunStatus.DONE)
    assert not can_transition(RunStatus.WAITING_HUMAN, RunStatus.DONE)
    assert not can_transition(RunStatus.DONE, RunStatus.RUNNING)


@given(st.sampled_from(RunStatus), st.sampled_from(RunStatus))
def test_run_transition_matches_predicate(a: RunStatus, b: RunStatus) -> None:
    if can_transition(a, b):
        assert transition(a, b) is b
    else:
        with pytest.raises(InvalidTransitionError):
            transition(a, b)


@given(st.sampled_from(RunStatus))
def test_every_nonterminal_run_state_can_be_stopped(s: RunStatus) -> None:
    if not s.is_terminal and s is not RunStatus.CANCELLING:
        assert can_transition(s, RunStatus.CANCELLING)


def test_gate_closes_exactly_once() -> None:
    assert can_transition(GateStatus.OPEN, GateStatus.APPROVED)
    assert can_transition(GateStatus.OPEN, GateStatus.OPEN)
    assert can_transition(GateStatus.APPROVED, GateStatus.INVALIDATED)
    for closed in (
        GateStatus.REJECTED,
        GateStatus.EXPIRED,
        GateStatus.CHANGES_REQUESTED,
        GateStatus.INVALIDATED,
    ):
        assert all(not can_transition(closed, t) for t in GateStatus)
    assert not can_transition(GateStatus.REJECTED, GateStatus.APPROVED)


def test_effect_edges() -> None:
    assert can_transition(EffectStatus.PLANNED, EffectStatus.ATTEMPTING)
    assert can_transition(EffectStatus.ACCEPTED, EffectStatus.CONFIRMED)
    assert not can_transition(EffectStatus.PLANNED, EffectStatus.CONFIRMED)
    assert not can_transition(EffectStatus.CONFIRMED, EffectStatus.ATTEMPTING)


def test_cross_enum_transition_rejected() -> None:
    with pytest.raises(InvalidTransitionError):
        transition(RunStatus.QUEUED, GateStatus.OPEN)


def test_effect_classes() -> None:
    assert {c.value for c in EffectClass} == {"internal", "scoped", "gated", "exposing"}


# registry ----------------------------------------------------------------------------------


def test_registry_registers_from_other_modules() -> None:
    events: Registry[object] = Registry("event")

    @events.register("step_succeeded")
    class StepSucceeded:
        pass

    assert events.get("step_succeeded") is StepSucceeded
    assert "step_succeeded" in events
    assert events.names() == ("step_succeeded",)


def test_registry_rejects_duplicates_and_unknown() -> None:
    reg: Registry[object] = Registry("blocked_reason")
    reg.register("loop_exhausted")(int)
    with pytest.raises(ValueError, match="already registered"):
        reg.register("loop_exhausted")(str)
    with pytest.raises(KeyError, match="blocked_reason"):
        reg.get("nope")
    with pytest.raises(ValueError, match="non-empty"):
        reg.register("")(int)


def test_registry_same_class_reregistration_is_idempotent() -> None:
    reg: Registry[object] = Registry("command")
    reg.register("x")(int)
    reg.register("x")(int)
    assert reg.names() == ("x",)


def test_runid_str_roundtrip() -> None:
    r = RunId.new()
    assert RunId.parse(str(r)) == r
