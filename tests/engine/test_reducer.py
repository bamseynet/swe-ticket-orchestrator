"""Reducer v0: purity, ordering, every outcome of the linear two-gate workflow, and the
registries (a new handler, event or command is added from outside reducer.py/commands.py)."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sto.domain import (
    BLOCKED_REASONS,
    COMMANDS,
    EVENTS,
    DecisionKind,
    FailureClass,
    GateType,
    PermanentError,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
)
from sto.engine.commands import Finish, OpenGate, RunStep, StopRun
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    GateClosed,
    RunStarted,
    StepFailed,
    StepSucceeded,
)
from sto.engine.reducer import (
    LINEAR_V0,
    HandlerRegistry,
    OutOfOrderEventError,
    Transition,
    Workflow,
    handles,
    next,
)

RID = RunId.from_parts(1, bytes(10))
OTHER = RunId.from_parts(2, bytes(10))
HEAD = Subject(
    patch_id="p1",
    ticket_revision="r1",
    head_sha="abc",
    evidence_digest="e1",
    attention_digest="a1",
)
PRE = Subject.pre_push(base_sha="base", patch_id="p1", ticket_revision="r1")


def run(**kw: object) -> Run:
    return Run(id=RID, team="t", **kw)  # type: ignore[arg-type]


def key(stage: str, visit: int = 1, attempt: int = 1, rid: RunId = RID) -> StepKey:
    return StepKey(run_id=rid, stage=stage, visit=visit, attempt=attempt)


def started() -> Run:
    return next(run(), RunStarted(RID), LINEAR_V0).state


def at_gate(name: str) -> Run:
    """Drive through the workflow to the open gate ``name``."""
    state = started()
    for event in _events_until(name):
        state = next(state, event, LINEAR_V0).state
    return state


def _events_until(gate: str) -> list[Any]:
    out: list[Any] = [StepSucceeded(key("analyse"), subject=PRE)]
    if gate == "review":
        return out
    out += [
        GateClosed(RID, "review", 1, DecisionKind.APPROVE, "alice"),
        StepSucceeded(key("implement"), subject=HEAD),
    ]
    return out


def test_workflow_is_linear_with_two_gates() -> None:
    assert [(n.name, n.kind) for n in LINEAR_V0.nodes] == [
        ("analyse", "step"),
        ("review", "gate"),
        ("implement", "step"),
        ("qa", "gate"),
    ]


def test_start_runs_first_stage() -> None:
    t = next(run(), RunStarted(RID), LINEAR_V0)
    assert t.state.status is RunStatus.RUNNING
    assert t.state.stage == "analyse"
    assert t.state.workflow_version == LINEAR_V0.version
    assert t.state.version == 1
    assert t.commands == (RunStep(RID, "analyse", visit=1, attempt=1),)


def test_step_success_opens_gate() -> None:
    t = next(started(), StepSucceeded(key("analyse"), subject=PRE), LINEAR_V0)
    assert t.state.status is RunStatus.WAITING_HUMAN
    assert t.state.stage == "review"
    assert t.commands == (OpenGate(RID, "review", GateType.REVIEW, round=1, subject=PRE),)


def test_step_success_before_gate_needs_a_subject() -> None:
    with pytest.raises(OutOfOrderEventError, match="subject"):
        next(started(), StepSucceeded(key("analyse")), LINEAR_V0)


def test_approve_moves_to_next_stage() -> None:
    t = next(at_gate("review"), GateClosed(RID, "review", 1, DecisionKind.APPROVE, "a"), LINEAR_V0)
    assert t.state.status is RunStatus.RUNNING
    assert t.state.stage == "implement"
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=1),)


def test_waive_is_an_approval() -> None:
    t = next(at_gate("review"), GateClosed(RID, "review", 1, DecisionKind.WAIVE, "a"), LINEAR_V0)
    assert t.state.stage == "implement"


@pytest.mark.parametrize("kind", [DecisionKind.REQUEST_CHANGES, DecisionKind.RETEST])
def test_changes_requested_reruns_previous_stage_next_visit(kind: DecisionKind) -> None:
    t = next(at_gate("review"), GateClosed(RID, "review", 1, kind, "a"), LINEAR_V0)
    assert t.state.status is RunStatus.RUNNING
    assert t.state.stage == "analyse"
    assert t.commands == (RunStep(RID, "analyse", visit=2, attempt=1),)


def test_second_round_gate_uses_the_visit_as_round() -> None:
    state = next(
        at_gate("review"),
        GateClosed(RID, "review", 1, DecisionKind.REQUEST_CHANGES, "a"),
        LINEAR_V0,
    ).state
    t = next(state, StepSucceeded(key("analyse", visit=2), subject=PRE), LINEAR_V0)
    assert t.commands == (OpenGate(RID, "review", GateType.REVIEW, round=2, subject=PRE),)


def test_reject_ends_rejected() -> None:
    t = next(at_gate("review"), GateClosed(RID, "review", 1, DecisionKind.REJECT, "a"), LINEAR_V0)
    assert t.state.status is RunStatus.REJECTED
    assert t.commands == (Finish(RID, RunStatus.REJECTED),)


def test_implement_opens_qa_gate_with_head_subject() -> None:
    state = at_gate("qa")
    assert state.stage == "qa"
    assert state.status is RunStatus.WAITING_HUMAN
    t = next(
        next(at_gate("review"), _events_until("qa")[1], LINEAR_V0).state,
        _events_until("qa")[2],
        LINEAR_V0,
    )
    assert t.commands == (OpenGate(RID, "qa", GateType.QA, round=1, subject=HEAD),)


def test_qa_approval_finishes_done() -> None:
    t = next(at_gate("qa"), GateClosed(RID, "qa", 1, DecisionKind.APPROVE, "a"), LINEAR_V0)
    assert t.state.status is RunStatus.DONE
    assert t.commands == (Finish(RID, RunStatus.DONE),)


def test_qa_changes_requested_reruns_implement() -> None:
    t = next(at_gate("qa"), GateClosed(RID, "qa", 1, DecisionKind.REQUEST_CHANGES, "a"), LINEAR_V0)
    assert t.state.stage == "implement"
    assert t.commands == (RunStep(RID, "implement", visit=2, attempt=1),)


def test_transient_failure_retries_with_next_attempt() -> None:
    t = next(started(), StepFailed(key("analyse"), FailureClass.TRANSIENT), LINEAR_V0)
    assert t.state.status is RunStatus.RUNNING
    assert t.commands == (RunStep(RID, "analyse", visit=1, attempt=2),)


def test_transient_failure_blocks_when_attempts_exhausted() -> None:
    t = next(
        started(),
        StepFailed(key("analyse", attempt=LINEAR_V0.max_attempts), FailureClass.TRANSIENT),
        LINEAR_V0,
    )
    assert t.state.status is RunStatus.BLOCKED
    assert t.state.blocked_reason == "attempts_exhausted"
    assert t.commands == ()


def test_permanent_failure_blocks_without_retry() -> None:
    t = next(started(), StepFailed(key("analyse"), FailureClass.PERMANENT), LINEAR_V0)
    assert t.state.status is RunStatus.BLOCKED
    assert t.state.blocked_reason == "permanent_failure"
    assert t.commands == ()


def test_degraded_failure_blocks() -> None:
    t = next(started(), StepFailed(key("analyse"), FailureClass.DEGRADED), LINEAR_V0)
    assert t.state.blocked_reason == "degraded"


@pytest.mark.parametrize("setup", ["queued", "running", "gate"])
def test_cancel_stops_the_run(setup: str) -> None:
    state = {"queued": run(), "running": started(), "gate": at_gate("review")}[setup]
    t = next(state, CancelRequested(RID), LINEAR_V0)
    assert t.state.status is RunStatus.CANCELLING
    assert t.commands == (StopRun(RID),)
    done = next(t.state, CancelCompleted(RID), LINEAR_V0)
    assert done.state.status is RunStatus.CANCELLED
    assert done.commands == (Finish(RID, RunStatus.CANCELLED),)


def test_cancel_while_cancelling_is_rejected() -> None:
    state = next(started(), CancelRequested(RID), LINEAR_V0).state
    with pytest.raises(OutOfOrderEventError):
        next(state, CancelRequested(RID), LINEAR_V0)


# --- out-of-order rejection -------------------------------------------------------------------


def test_cancel_completed_without_cancelling_is_rejected() -> None:
    with pytest.raises(OutOfOrderEventError):
        next(started(), CancelCompleted(RID), LINEAR_V0)


OUT_OF_ORDER: list[tuple[str, Run, Any]] = [
    ("step before start", run(), StepSucceeded(key("analyse"), subject=PRE)),
    ("start twice", started(), RunStarted(RID)),
    ("wrong stage", started(), StepSucceeded(key("implement"), subject=HEAD)),
    ("unknown stage", started(), StepSucceeded(key("nope"), subject=HEAD)),
    ("gate name as step", started(), StepSucceeded(key("review"), subject=PRE)),
    (
        "gate closed while running",
        started(),
        GateClosed(RID, "review", 1, DecisionKind.APPROVE, "a"),
    ),
    ("step done while at gate", at_gate("review"), StepSucceeded(key("analyse"), subject=PRE)),
    ("wrong gate", at_gate("review"), GateClosed(RID, "qa", 1, DecisionKind.APPROVE, "a")),
    ("other run", started(), StepSucceeded(key("analyse", rid=OTHER), subject=PRE)),
    (
        "other run gate",
        at_gate("review"),
        GateClosed(OTHER, "review", 1, DecisionKind.APPROVE, "a"),
    ),
    ("failure at gate", at_gate("review"), StepFailed(key("analyse"), FailureClass.PERMANENT)),
]


@pytest.mark.parametrize(
    ("label", "state", "event"), OUT_OF_ORDER, ids=[o[0] for o in OUT_OF_ORDER]
)
def test_out_of_order_event_is_rejected(label: str, state: Run, event: Any) -> None:
    before = dataclasses.replace(state)
    with pytest.raises(OutOfOrderEventError):
        next(state, event, LINEAR_V0)
    assert state == before


def test_everything_is_rejected_after_a_terminal_status() -> None:
    state = next(
        at_gate("review"), GateClosed(RID, "review", 1, DecisionKind.REJECT, "a"), LINEAR_V0
    ).state
    for event in (
        RunStarted(RID),
        CancelRequested(RID),
        StepSucceeded(key("analyse"), subject=PRE),
        GateClosed(RID, "review", 1, DecisionKind.APPROVE, "a"),
    ):
        with pytest.raises(OutOfOrderEventError):
            next(state, event, LINEAR_V0)


def test_blocked_run_rejects_progress_events() -> None:
    state = next(started(), StepFailed(key("analyse"), FailureClass.PERMANENT), LINEAR_V0).state
    with pytest.raises(OutOfOrderEventError):
        next(state, StepSucceeded(key("analyse"), subject=PRE), LINEAR_V0)


def test_out_of_order_is_a_permanent_error() -> None:
    assert issubclass(OutOfOrderEventError, PermanentError)


def test_unregistered_event_type_is_rejected() -> None:
    @dataclass(frozen=True)
    class Stray:
        run_id: RunId

    with pytest.raises(OutOfOrderEventError, match="no handler"):
        next(started(), Stray(RID), LINEAR_V0)


# --- determinism ------------------------------------------------------------------------------


def test_same_input_gives_same_output() -> None:
    state, event = started(), StepSucceeded(key("analyse"), subject=PRE)
    first = next(state, event, LINEAR_V0)
    for _ in range(5):
        assert next(state, event, LINEAR_V0) == first
    assert state == started()  # input untouched


def _all_events() -> list[Any]:
    return [
        RunStarted(RID),
        StepSucceeded(key("analyse"), subject=PRE),
        StepSucceeded(key("implement"), subject=HEAD),
        StepFailed(key("analyse"), FailureClass.TRANSIENT),
        StepFailed(key("analyse"), FailureClass.PERMANENT),
        GateClosed(RID, "review", 1, DecisionKind.APPROVE, "a"),
        GateClosed(RID, "review", 1, DecisionKind.REQUEST_CHANGES, "a"),
        GateClosed(RID, "qa", 1, DecisionKind.APPROVE, "a"),
        CancelRequested(RID),
        CancelCompleted(RID),
    ]


def _replay(events: list[Any]) -> list[tuple[Run, tuple[object, ...]] | str]:
    state = run()
    out: list[tuple[Run, tuple[object, ...]] | str] = []
    for e in events:
        try:
            t = next(state, e, LINEAR_V0)
        except OutOfOrderEventError as exc:
            out.append(str(exc))
            continue
        state = t.state
        out.append((t.state, t.commands))
    return out


@given(st.lists(st.sampled_from(_all_events()), max_size=12))
def test_replay_is_deterministic_and_state_stays_valid(events: list[Any]) -> None:
    assert _replay(events) == _replay(events)
    state = run()
    for e in events:
        try:
            state = next(state, e, LINEAR_V0).state
        except OutOfOrderEventError:
            continue
        assert state.version >= 0
        assert state.status is not RunStatus.QUEUED


def test_version_counts_accepted_events_only() -> None:
    state = started()
    assert state.version == 1
    with pytest.raises(OutOfOrderEventError):
        next(state, RunStarted(RID), LINEAR_V0)
    state = next(state, StepSucceeded(key("analyse"), subject=PRE), LINEAR_V0).state
    assert state.version == 2


def test_reducer_module_is_pure() -> None:
    import sto.engine.handlers.core as core
    import sto.engine.reducer as reducer

    for mod in (reducer, core):
        src = Path(mod.__file__ or "").read_text()
        for banned in ("import time", "import random", "import os", "datetime", "Ulid.new", "uuid"):
            assert banned not in src, f"{mod.__name__} uses {banned}"


# --- registries -------------------------------------------------------------------------------


def test_core_names_are_registered() -> None:
    for name in (
        "run.started", "step.succeeded", "step.failed", "gate.closed",
        "cancel.requested", "cancel.completed",
    ):  # fmt: skip
        assert name in EVENTS
    for name in ("run_step", "open_gate", "stop_run", "finish"):
        assert name in COMMANDS
    for name in ("attempts_exhausted", "permanent_failure", "degraded"):
        assert name in BLOCKED_REASONS


def test_new_event_handler_and_command_register_from_outside() -> None:
    """A later module adds an event, a command, a blocked reason and a handler on its own."""
    reg = HandlerRegistry()

    @COMMANDS.register("test.reducer_ping")
    @dataclass(frozen=True)
    class Ping:
        run_id: RunId

    @EVENTS.register("test.reducer_pinged")
    @dataclass(frozen=True)
    class Pinged:
        run_id: RunId

    @handles(Pinged, registry=reg)
    def on_pinged(state: Run, event: Pinged, workflow: Workflow) -> Transition:
        return Transition(state, (Ping(event.run_id),))

    state = started()
    assert next(state, Pinged(RID), LINEAR_V0, registry=reg) == Transition(state, (Ping(RID),))
    with pytest.raises(OutOfOrderEventError):  # the default registry never saw it
        next(state, Pinged(RID), LINEAR_V0)


def test_registry_refuses_a_second_handler_for_one_event() -> None:
    reg = HandlerRegistry()

    @dataclass(frozen=True)
    class E:
        run_id: RunId

    @handles(E, registry=reg)
    def one(state: Run, event: E, workflow: Workflow) -> Transition:
        return Transition(state, ())

    with pytest.raises(ValueError, match="already"):

        @handles(E, registry=reg)
        def two(state: Run, event: E, workflow: Workflow) -> Transition:
            return Transition(state, ())


def test_handler_modules_are_discovered(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """A new file under engine/handlers/ is loaded without editing reducer.py."""
    import importlib
    import pkgutil

    import sto.engine.handlers as pkg

    names = {m.name for m in pkgutil.iter_modules(pkg.__path__)}
    assert "core" in names
    assert importlib.import_module("sto.engine.handlers.core")


def test_failure_class_is_coerced_from_its_wire_value() -> None:
    assert StepFailed(key("analyse"), "transient").failure_class is FailureClass.TRANSIENT  # type: ignore[arg-type]
