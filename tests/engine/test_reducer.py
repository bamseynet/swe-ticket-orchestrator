"""Reducer v0: purity, ordering, every outcome of the linear workflow, and the registries (a
new handler, event or command is added from outside reducer.py/commands.py)."""

from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
import textwrap
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
    DecisionId,
    DecisionKind,
    FailureClass,
    Gate,
    GateId,
    GateType,
    PermanentError,
    Run,
    RunId,
    RunStatus,
    StepKey,
    Subject,
)
from sto.engine.commands import Finish, OpenGate, RunEffect, RunStep, StopRun
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    EffectConfirmed,
    EffectFailed,
    GateClosed,
    RunStarted,
    StepFailed,
    StepSucceeded,
)
from sto.engine.reducer import (
    HANDLERS,
    LINEAR_V0,
    HandlerRegistry,
    HandlersNotLoadedError,
    MalformedEventError,
    Node,
    NoHandlerError,
    OutOfOrderEventError,
    RunState,
    Transition,
    Workflow,
    WorkflowMismatchError,
    handles,
    load_handlers,
    next,
)

load_handlers()  # startup step; next() refuses the default registry until this has run

RID = RunId.from_parts(1, bytes(10))
OTHER = RunId.from_parts(2, bytes(10))
WF = LINEAR_V0
K = DecisionKind


def subj(sha: str = "abc", ev: str = "e1") -> Subject:
    return Subject(
        patch_id="p1",
        ticket_revision="r1",
        head_sha=sha,
        evidence_digest=ev,
        attention_digest="a1",
    )


REV = subj("abc", "review-evidence")
QAS = subj("abc", "qa-evidence")
NEW = subj("def", "new-evidence")
_ids = iter(range(1, 10_000))


def did() -> DecisionId:
    return DecisionId.from_parts(_ids.__next__(), bytes(10))


def key(stage: str, visit: int = 1, attempt: int = 1, rid: RunId = RID) -> StepKey:
    return StepKey(run_id=rid, stage=stage, visit=visit, attempt=attempt)


def new() -> RunState:
    return RunState(Run(id=RID, team="t"))


def step(rs: RunState, event: Any) -> RunState:
    return next(rs, event, WF).state


def play(*events: Any) -> RunState:
    rs = new()
    for e in events:
        rs = step(rs, e)
    return rs


def close(
    gate: str,
    kind: DecisionKind = K.APPROVE,
    *,
    round: int = 1,
    subject: Subject | None = None,
    rid: RunId = RID,
) -> GateClosed:
    if subject is None and not kind.is_negative:
        subject = REV if gate == "review_gate" else QAS
    return GateClosed(rid, gate, round, kind, "alice", did(), subject)


START = RunStarted(RID)
IMPL = StepSucceeded(key("implement"), REV)
AT_REVIEW = (START, IMPL)
REVIEW_OK = close("review_gate")
QA_OK = StepSucceeded(key("qa"), QAS)
AT_QA_STEP = (*AT_REVIEW, REVIEW_OK)
AT_QA_GATE = (*AT_QA_STEP, QA_OK)


def test_workflow_order_and_gate_types() -> None:
    assert [(n.name, n.kind) for n in WF.nodes] == [
        ("implement", "step"),
        ("review_gate", "gate"),
        ("qa", "step"),
        ("qa_gate", "gate"),
        ("merge", "effect"),
    ]
    assert [n.gate_type for n in WF.nodes if n.kind == "gate"] == [GateType.REVIEW, GateType.QA]


def test_workflow_rejects_dangling_reentry_and_bad_nodes() -> None:
    with pytest.raises(ValueError, match="unknown node"):
        Workflow("x", (Node("a", "step"), Node("g", "gate", gate_type=GateType.QA, on_changes="z")))
    with pytest.raises(ValueError, match="must be a step"):
        Workflow(
            "x",
            (
                Node("g", "gate", gate_type=GateType.QA, on_changes="g"),
                Node("e", "effect", effect="x"),
            ),
        )
    with pytest.raises(ValueError, match="unique"):
        Workflow("x", (Node("a", "step"), Node("a", "step")))
    with pytest.raises(ValueError, match="gate_type"):
        Node("g", "gate")
    with pytest.raises(ValueError, match="on_changes"):
        Node("g", "gate", gate_type=GateType.QA, decisions=frozenset({K.REQUEST_CHANGES}))
    with pytest.raises(ValueError, match="on_retest"):
        Node("g", "gate", gate_type=GateType.QA, decisions=frozenset({K.RETEST}))
    with pytest.raises(ValueError, match="effect"):
        Node("e", "effect")


def test_start_runs_first_stage() -> None:
    t = next(new(), START, WF)
    run = t.state.run
    assert (run.status, run.stage, run.workflow_version, run.version) == (
        RunStatus.RUNNING,
        "implement",
        WF.version,
        1,
    )
    assert (t.state.visit, t.state.attempt) == (1, 1)
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=1),)


def test_implement_opens_review_gate_with_head_subject() -> None:
    t = next(play(START), IMPL, WF)
    assert t.state.run.status is RunStatus.WAITING_HUMAN
    assert t.state.run.stage == "review_gate"
    assert t.state.subject == REV
    assert t.state.round == 1
    assert t.commands == (OpenGate(RID, "review_gate", GateType.REVIEW, 1, REV),)


def test_every_opened_gate_builds_a_real_domain_gate() -> None:
    for events, name in ((AT_REVIEW, "review_gate"), (AT_QA_GATE, "qa_gate")):
        rs = new()
        cmd: Any = None
        for e in events:
            t = next(rs, e, WF)
            rs, cmd = t.state, (t.commands[0] if t.commands else cmd)
        assert isinstance(cmd, OpenGate)
        assert cmd.name == name
        gate = Gate(
            id=GateId.from_parts(1, bytes(10)),
            run_id=cmd.run_id,
            name=cmd.name,
            type=cmd.type,
            round=cmd.round,
            subject=cmd.subject,
        )
        assert gate.is_open


def test_step_must_report_a_head_subject_for_its_gate() -> None:
    with pytest.raises(MalformedEventError):
        next(play(START), StepSucceeded(key("implement")), WF)
    pre = Subject.pre_push(base_sha="b", patch_id="p", ticket_revision="r")
    with pytest.raises(MalformedEventError):
        next(play(START), StepSucceeded(key("implement"), pre), WF)


def test_review_approve_goes_to_qa_and_records_the_approval() -> None:
    event = close("review_gate")
    t = next(play(*AT_REVIEW), event, WF)
    assert t.state.run.status is RunStatus.RUNNING
    assert t.state.run.stage == "qa"
    assert t.commands == (RunStep(RID, "qa", visit=1, attempt=1),)
    (approval,) = t.state.approvals
    assert (approval.gate, approval.round, approval.decision_id) == (
        "review_gate",
        1,
        event.decision_id,
    )
    assert approval.subject_digest == REV.digest()


def test_review_gate_refuses_waive() -> None:
    with pytest.raises(MalformedEventError, match="waive"):
        next(play(*AT_REVIEW), close("review_gate", K.WAIVE), WF)


def test_review_request_changes_reruns_implement_and_voids_approvals() -> None:
    t = next(play(*AT_REVIEW), close("review_gate", K.REQUEST_CHANGES), WF)
    assert t.state.run.stage == "implement"
    assert t.state.run.status is RunStatus.RUNNING
    assert t.commands == (RunStep(RID, "implement", visit=2, attempt=1),)
    assert t.state.approvals == ()
    assert t.state.subject is None


def test_review_reject_ends_rejected() -> None:
    t = next(play(*AT_REVIEW), close("review_gate", K.REJECT), WF)
    assert t.state.run.status is RunStatus.REJECTED
    assert t.commands == (Finish(RID, RunStatus.REJECTED),)


def test_review_gate_refuses_retest() -> None:
    with pytest.raises(MalformedEventError, match="retest"):
        next(play(*AT_REVIEW), close("review_gate", K.RETEST), WF)


def test_qa_step_opens_qa_gate() -> None:
    t = next(play(*AT_QA_STEP), QA_OK, WF)
    assert t.state.run.status is RunStatus.WAITING_HUMAN
    assert t.state.run.stage == "qa_gate"
    assert t.commands == (OpenGate(RID, "qa_gate", GateType.QA, 1, QAS),)


def test_qa_step_cannot_report_a_different_sha() -> None:
    with pytest.raises(OutOfOrderEventError, match="different SHA or patch"):
        next(play(*AT_QA_STEP), StepSucceeded(key("qa"), NEW), WF)


@pytest.mark.parametrize("kind", [K.APPROVE, K.WAIVE])  # waive is QA-only
def test_qa_approval_plans_the_gated_merge(kind: DecisionKind) -> None:
    event = close("qa_gate", kind)
    t = next(play(*AT_QA_GATE), event, WF)
    review_id = play(*AT_QA_GATE).approvals[0].decision_id
    assert t.state.run.status is RunStatus.RUNNING
    assert t.state.run.stage == "merge"
    assert t.commands == (
        RunEffect(
            RID,
            "pr.merge",
            "merge",
            1,
            QAS,
            QAS.digest(),
            ("review_gate", "qa_gate"),
            (review_id, event.decision_id),
        ),
    )


def test_qa_reject_ends_rejected() -> None:
    t = next(play(*AT_QA_GATE), close("qa_gate", K.REJECT), WF)
    assert t.state.run.status is RunStatus.REJECTED
    assert t.commands == (Finish(RID, RunStatus.REJECTED),)


def test_qa_request_changes_reruns_implement_then_the_review_gate() -> None:
    t = next(play(*AT_QA_GATE), close("qa_gate", K.REQUEST_CHANGES), WF)
    assert t.state.run.stage == "implement"
    assert t.commands == (RunStep(RID, "implement", visit=2, attempt=1),)
    assert t.state.approvals == ()
    again = next(t.state, StepSucceeded(key("implement", 2), NEW), WF)
    assert again.commands == (OpenGate(RID, "review_gate", GateType.REVIEW, 2, NEW),)


def test_qa_retest_reruns_qa_on_the_same_sha_with_a_new_gate() -> None:
    t = next(play(*AT_QA_GATE), close("qa_gate", K.RETEST), WF)
    assert t.state.run.stage == "qa"
    assert t.state.run.status is RunStatus.RUNNING
    assert t.commands == (RunStep(RID, "qa", visit=2, attempt=1),)
    assert [a.gate for a in t.state.approvals] == ["review_gate"]  # review approval still stands
    with pytest.raises(OutOfOrderEventError):  # same SHA only
        next(t.state, StepSucceeded(key("qa", 2), NEW), WF)
    g2 = next(t.state, StepSucceeded(key("qa", 2), subj("abc", "qa-2")), WF)
    assert g2.commands[0].round == 2  # type: ignore[attr-defined]
    done = next(g2.state, close("qa_gate", round=2, subject=subj("abc", "qa-2")), WF)
    assert done.state.run.stage == "merge"


def test_merge_confirmation_finishes_the_run() -> None:
    rs = play(*AT_QA_GATE, close("qa_gate"))
    t = next(rs, EffectConfirmed(RID, "pr.merge", 1, "m1"), WF)
    assert t.state.run.status is RunStatus.DONE
    assert t.commands == (Finish(RID, RunStatus.DONE),)


def test_transient_failure_retries_with_next_attempt() -> None:
    t = next(play(START), StepFailed(key("implement"), FailureClass.TRANSIENT), WF)
    assert t.state.run.status is RunStatus.RUNNING
    assert t.state.attempt == 2
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=2),)


def test_transient_failures_exhaust_attempts() -> None:
    rs = play(START)
    for attempt in range(1, WF.max_attempts):
        rs = step(rs, StepFailed(key("implement", attempt=attempt), FailureClass.TRANSIENT))
    t = next(rs, StepFailed(key("implement", attempt=WF.max_attempts), FailureClass.TRANSIENT), WF)
    assert t.state.run.status is RunStatus.BLOCKED
    assert t.state.run.blocked_reason == "attempts_exhausted"
    assert t.commands == ()


@pytest.mark.parametrize(
    ("fc", "reason"),
    [(FailureClass.PERMANENT, "permanent_failure"), (FailureClass.DEGRADED, "degraded")],
)
def test_permanent_and_degraded_failures_block(fc: FailureClass, reason: str) -> None:
    t = next(play(START), StepFailed(key("implement"), fc), WF)
    assert (t.state.run.status, t.state.run.blocked_reason) == (RunStatus.BLOCKED, reason)
    assert t.commands == ()


def test_failure_class_is_coerced_from_its_wire_value() -> None:
    event = StepFailed(key("implement"), "transient")  # type: ignore[arg-type]
    assert event.failure_class is FailureClass.TRANSIENT


CANCELLABLE = {
    "queued": (),
    "running": (START,),
    "gate": AT_REVIEW,
    "blocked": (START, StepFailed(key("implement"), FailureClass.PERMANENT)),
}


@pytest.mark.parametrize("where", list(CANCELLABLE))
def test_cancel_stops_the_run(where: str) -> None:
    t = next(play(*CANCELLABLE[where]), CancelRequested(RID), WF)
    assert t.state.run.status is RunStatus.CANCELLING
    assert t.commands == (StopRun(RID),)
    done = next(t.state, CancelCompleted(RID), WF)
    assert done.state.run.status is RunStatus.CANCELLED
    assert done.commands == (Finish(RID, RunStatus.CANCELLED),)


# --- out-of-order rejection -------------------------------------------------------------------

RUNNING = play(START)
GATE1 = play(*AT_REVIEW)
GATE_R2 = play(
    *AT_REVIEW, close("review_gate", K.REQUEST_CHANGES), StepSucceeded(key("implement", 2), NEW)
)
STEP_V2 = play(*AT_REVIEW, close("review_gate", K.REQUEST_CHANGES))
RETRIED = play(START, StepFailed(key("implement"), FailureClass.TRANSIENT))
TERMINAL = play(*AT_REVIEW, close("review_gate", K.REJECT))
BLOCKED = play(START, StepFailed(key("implement"), FailureClass.PERMANENT))
MERGING = play(*AT_QA_GATE, close("qa_gate"))

OUT_OF_ORDER: list[tuple[str, RunState, Any]] = [
    ("step before start", new(), IMPL),
    ("start twice", RUNNING, START),
    ("wrong stage", RUNNING, StepSucceeded(key("qa"), QAS)),
    ("unknown stage", RUNNING, StepSucceeded(key("nope"), REV)),
    ("gate name as step", RUNNING, StepSucceeded(key("review_gate"), REV)),
    ("gate closed while running", RUNNING, close("review_gate")),
    ("step done while at gate", GATE1, IMPL),
    ("wrong gate", GATE1, close("qa_gate")),
    ("other run step", RUNNING, StepSucceeded(key("implement", rid=OTHER), REV)),
    ("other run gate", GATE1, close("review_gate", rid=OTHER)),
    ("failure at gate", GATE1, StepFailed(key("implement"), FailureClass.PERMANENT)),
    # the late and duplicate cases a store CAS cannot catch
    ("late visit-1 success during visit 2", STEP_V2, StepSucceeded(key("implement", 1), REV)),
    ("visit 99", RUNNING, StepSucceeded(key("implement", 99), REV)),
    (
        "round-1 approve on round-2 gate",
        GATE_R2,
        close("review_gate", round=1, subject=NEW),
    ),
    ("round 99", GATE1, close("review_gate", round=99)),
    (
        "duplicate failure after retry",
        RETRIED,
        StepFailed(key("implement", attempt=1), FailureClass.TRANSIENT),
    ),
    (
        "late attempt-1 success during attempt 2",
        RETRIED,
        StepSucceeded(key("implement", attempt=1), REV),
    ),
    ("attempt 99", RUNNING, StepFailed(key("implement", attempt=99), FailureClass.TRANSIENT)),
    ("stale approval subject", GATE1, close("review_gate", subject=NEW)),
    ("round-1 approve after the gate already moved", MERGING, close("review_gate")),
    ("effect before its time", RUNNING, EffectConfirmed(RID, "pr.merge", 1, "m1")),
    ("wrong effect", MERGING, EffectConfirmed(RID, "pr.other", 1, "m1")),
    ("stale effect visit", MERGING, EffectConfirmed(RID, "pr.merge", 2, "m1")),
    ("cancel completed without cancelling", RUNNING, CancelCompleted(RID)),
    ("cancel twice", step(RUNNING, CancelRequested(RID)), CancelRequested(RID)),
    ("step on blocked run", BLOCKED, IMPL),
    *[
        (f"{type(e).__name__} after terminal", TERMINAL, e)
        for e in (START, CancelRequested(RID), IMPL, close("review_gate"))
    ],
]


@pytest.mark.parametrize(
    ("label", "state", "event"), OUT_OF_ORDER, ids=[o[0] for o in OUT_OF_ORDER]
)
def test_out_of_order_event_is_rejected(label: str, state: RunState, event: Any) -> None:
    before = dataclasses.replace(state)
    with pytest.raises(OutOfOrderEventError):
        next(state, event, WF)
    assert state == before


def test_malformed_events_are_not_out_of_order() -> None:
    for error in (MalformedEventError, OutOfOrderEventError, WorkflowMismatchError):
        assert issubclass(error, PermanentError)
    assert not issubclass(MalformedEventError, OutOfOrderEventError)
    with pytest.raises(MalformedEventError, match="subject"):
        next(GATE1, GateClosed(RID, "review_gate", 1, K.APPROVE, "a", did(), None), WF)


def test_workflow_version_must_match() -> None:
    other = Workflow("other", WF.nodes)
    with pytest.raises(WorkflowMismatchError):
        next(RUNNING, StepSucceeded(key("implement"), REV), other)


def test_unregistered_event_type_is_rejected() -> None:
    @dataclass(frozen=True)
    class Stray:
        run_id: RunId

    with pytest.raises(NoHandlerError, match="no handler"):
        next(RUNNING, Stray(RID), WF)


# --- determinism ------------------------------------------------------------------------------


def test_same_input_gives_same_output() -> None:
    first = next(RUNNING, IMPL, WF)
    for _ in range(5):
        assert next(RUNNING, IMPL, WF) == first
    assert play(START) == RUNNING  # input untouched


def test_version_counts_accepted_events_only() -> None:
    assert RUNNING.run.version == 1
    with pytest.raises(OutOfOrderEventError):
        next(RUNNING, START, WF)
    assert step(RUNNING, IMPL).run.version == 2


_EVENTS: list[Any] = [
    START,
    IMPL,
    QA_OK,
    StepFailed(key("implement"), FailureClass.TRANSIENT),
    StepFailed(key("implement"), FailureClass.PERMANENT),
    REVIEW_OK,
    close("review_gate", K.REQUEST_CHANGES),
    close("qa_gate"),
    close("qa_gate", K.RETEST),
    EffectConfirmed(RID, "pr.merge", 1, "m1"),
    CancelRequested(RID),
    CancelCompleted(RID),
]


def _replay(events: list[Any]) -> list[Any]:
    rs = new()
    out: list[Any] = []
    for e in events:
        try:
            t = next(rs, e, WF)
        except (OutOfOrderEventError, MalformedEventError) as exc:
            out.append(str(exc))
            continue
        rs = t.state
        out.append((t.state, t.commands))
    return out


@given(st.lists(st.sampled_from(_EVENTS), max_size=14))
def test_replay_is_deterministic_and_never_corrupts_state(events: list[Any]) -> None:
    assert _replay(events) == _replay(events)
    rs = new()
    for e in events:
        try:
            rs = next(rs, e, WF).state
        except (OutOfOrderEventError, MalformedEventError):
            continue
        assert rs.run.status is not RunStatus.QUEUED
        assert rs.run.stage in {None, *(n.name for n in WF.nodes)}


ENGINE = Path(__file__).resolve().parents[2] / "src" / "sto" / "engine"
IMPURE_MODULES = {"time", "random", "os", "datetime", "uuid", "secrets", "socket", "subprocess"}
IMPURE_CALLS = {"now", "utcnow", "urandom", "uuid4", "getenv", "time", "random"}


@pytest.mark.parametrize("path", sorted(ENGINE.rglob("*.py")), ids=lambda p: p.name)
def test_engine_modules_are_pure(path: Path) -> None:
    """No clock, randomness or environment; ``Ulid.new`` is the impure ID constructor."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            mods = {(node.module or "").split(".")[0]}
        else:
            mods = set()
        assert not mods & IMPURE_MODULES, f"{path.name} imports {mods & IMPURE_MODULES}"
        if isinstance(node, ast.Attribute):
            assert node.attr not in IMPURE_CALLS, f"{path.name} uses .{node.attr}"
            if node.attr == "new" and isinstance(node.value, ast.Name):
                assert node.value.id != "Ulid", f"{path.name} calls Ulid.new"


def test_next_does_no_import_io() -> None:
    tree = ast.parse((ENGINE / "reducer.py").read_text())
    (fn,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "next"]
    calls = {
        c.func.attr
        for c in ast.walk(fn)
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
    }
    assert not calls & {"import_module", "iter_modules"}


# --- registries -------------------------------------------------------------------------------


def test_core_names_are_registered() -> None:
    for name in (
        "run.started", "step.succeeded", "step.failed", "gate.closed", "effect.confirmed",
        "cancel.requested", "cancel.completed",
    ):  # fmt: skip
        assert name in EVENTS
    for name in ("run_step", "open_gate", "run_effect", "stop_run", "finish"):
        assert name in COMMANDS
    for name in ("attempts_exhausted", "permanent_failure", "degraded"):
        assert name in BLOCKED_REASONS


def test_new_event_handler_and_command_register_from_outside() -> None:
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
    def on_pinged(state: RunState, event: Pinged, workflow: Workflow) -> Transition:
        return Transition(state, (Ping(event.run_id),))

    assert next(RUNNING, Pinged(RID), WF, registry=reg) == Transition(RUNNING, (Ping(RID),))
    with pytest.raises(NoHandlerError):  # the default registry never saw it
        next(RUNNING, Pinged(RID), WF)


def test_registry_refuses_a_second_handler_for_one_event() -> None:
    reg = HandlerRegistry()

    @dataclass(frozen=True)
    class E:
        run_id: RunId

    @handles(E, registry=reg)
    def one(state: RunState, event: E, workflow: Workflow) -> Transition:
        return Transition(state, ())

    with pytest.raises(ValueError, match="already"):

        @handles(E, registry=reg)
        def two(state: RunState, event: E, workflow: Workflow) -> Transition:
            return Transition(state, ())


def test_load_handlers_loads_a_new_file_without_editing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg = tmp_path / "newhandlers"
    pkg.mkdir()
    (pkg / "extra.py").write_text(
        textwrap.dedent(
            """
            from dataclasses import dataclass
            from sto.engine.reducer import Transition, handles

            @dataclass(frozen=True)
            class Extra:
                run_id: object

            @handles(Extra)
            def on_extra(state, event, workflow):
                return Transition(state, ())
            """
        )
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    load_handlers("newhandlers")
    extra = sys.modules["newhandlers.extra"]
    assert HANDLERS.get(extra.Extra) is extra.on_extra
    load_handlers("newhandlers")  # idempotent: a second call does not re-register


def test_next_refuses_until_handlers_are_loaded_in_a_fresh_interpreter() -> None:
    """Importing core by hand must not make next() work: loading is an explicit startup step."""
    code = textwrap.dedent(
        """
        from sto.domain import Run, RunId
        from sto.engine.handlers.core import RunStarted
        from sto.engine.reducer import (
            LINEAR_V0, HANDLERS, HandlersNotLoadedError, RunState, load_handlers, next,
        )
        rid = RunId.from_parts(1, bytes(10))
        state = RunState(Run(id=rid, team="t"))
        try:
            next(state, RunStarted(rid), LINEAR_V0)
        except HandlersNotLoadedError:
            pass
        else:
            raise SystemExit("next() ran before load_handlers()")
        load_handlers()
        assert next(state, RunStarted(rid), LINEAR_V0).state.run.stage == "implement"
        """
    )
    env = {"PYTHONPATH": str(ENGINE.parents[1])}
    subprocess.run([sys.executable, "-c", code], check=True, env=env)


def test_an_unhandled_event_is_not_an_out_of_order_one() -> None:
    assert not issubclass(NoHandlerError, OutOfOrderEventError)
    assert not issubclass(HandlersNotLoadedError, OutOfOrderEventError)
    assert HANDLERS.get(RunStarted) is not None


# --- review pass 2 ----------------------------------------------------------------------------


def test_failed_merge_blocks_the_run() -> None:
    t = next(MERGING, EffectFailed(RID, "pr.merge", 1), WF)
    assert t.state.run.status is RunStatus.BLOCKED
    assert t.state.run.blocked_reason == "effect_failed"
    assert t.commands == ()


@pytest.mark.parametrize(
    "event",
    [EffectFailed(RID, "pr.other", 1), EffectFailed(RID, "pr.merge", 2)],
    ids=["wrong effect", "stale visit"],
)
def test_effect_failure_must_match_the_live_effect(event: EffectFailed) -> None:
    with pytest.raises(OutOfOrderEventError):
        next(MERGING, event, WF)
    with pytest.raises(OutOfOrderEventError):
        next(RUNNING, EffectFailed(RID, "pr.merge", 1), WF)


def test_merge_confirmation_must_report_the_merge_sha() -> None:
    with pytest.raises(MalformedEventError, match="merge_sha"):
        next(MERGING, EffectConfirmed(RID, "pr.merge", 1), WF)


def test_effect_visit_is_the_merge_nodes_own_not_qas() -> None:
    """After a retest QA is on visit 2 but merge is on its first visit (PLAN 6.3 effect key)."""
    rs = play(*AT_QA_GATE, close("qa_gate", K.RETEST))
    qa2 = subj("abc", "qa-2")
    rs = step(rs, StepSucceeded(key("qa", 2), qa2))
    t = next(rs, close("qa_gate", round=2, subject=qa2), WF)
    (cmd,) = t.commands
    assert isinstance(cmd, RunEffect)
    assert (cmd.stage, cmd.visit) == ("merge", 1)
    assert t.state.visit == 2  # QA's visit is untouched
    with pytest.raises(OutOfOrderEventError):
        next(t.state, EffectConfirmed(RID, "pr.merge", 2, "m1"), WF)
    done = next(t.state, EffectConfirmed(RID, "pr.merge", 1, "m1"), WF)
    assert done.state.run.status is RunStatus.DONE


def test_attempt_resets_on_reentry() -> None:
    rs = play(START, StepFailed(key("implement"), FailureClass.TRANSIENT))
    assert rs.attempt == 2
    rs = step(rs, StepSucceeded(key("implement", attempt=2), REV))
    t = next(rs, close("review_gate", K.REQUEST_CHANGES), WF)
    assert t.state.attempt == 1
    assert t.commands == (RunStep(RID, "implement", visit=2, attempt=1),)


def test_qa_step_must_keep_the_reviewed_patch_id() -> None:
    other_patch = dataclasses.replace(QAS, patch_id="p2")
    with pytest.raises(OutOfOrderEventError, match="different SHA or patch"):
        next(play(*AT_QA_STEP), StepSucceeded(key("qa"), other_patch), WF)


def test_a_gate_with_nothing_after_it_is_a_workflow_error() -> None:
    wf = _one(
        Node("a", "step"),
        Node("g", "gate", gate_type=GateType.QA, decisions=frozenset({K.APPROVE})),
    )
    rs = next(next(new(), START, wf).state, StepSucceeded(key("a"), REV), wf).state
    with pytest.raises(WorkflowMismatchError, match="nothing follows"):
        next(rs, close("g", subject=REV), wf)


@given(st.lists(st.sampled_from(_EVENTS), max_size=16))
def test_a_merge_command_always_has_both_approvals(events: list[Any]) -> None:
    rs = new()
    for e in events:
        try:
            t = next(rs, e, WF)
        except (OutOfOrderEventError, MalformedEventError):
            continue
        rs = t.state
        for cmd in t.commands:
            if isinstance(cmd, RunEffect):
                assert cmd.requires_gates == ("review_gate", "qa_gate")
                assert len(set(cmd.decision_ids)) == 2
                assert {a.gate for a in rs.approvals} >= set(cmd.requires_gates)


# --- workflow shapes the default one never exercises --------------------------------------------


def _one(*nodes: Node) -> Workflow:
    return Workflow("shape", nodes)


def test_a_workflow_that_ends_on_a_step_has_nothing_to_follow() -> None:
    wf = _one(Node("a", "step"))
    rs = next(new(), START, wf).state
    with pytest.raises(OutOfOrderEventError, match="nothing follows"):
        next(rs, StepSucceeded(key("a")), wf)


def test_an_effect_with_no_approved_subject_is_refused() -> None:
    wf = _one(Node("a", "step"), Node("e", "effect", effect="x"))
    rs = next(new(), START, wf).state
    with pytest.raises(OutOfOrderEventError, match="no approved subject"):
        next(rs, StepSucceeded(key("a")), wf)


def test_an_effect_lacking_a_required_approval_is_refused() -> None:
    wf = _one(
        Node("a", "step"),
        Node("g", "gate", gate_type=GateType.QA, decisions=frozenset({K.APPROVE})),
        Node("e", "effect", effect="x", requires_gates=("a",)),
    )
    rs = next(new(), START, wf).state
    rs = next(rs, StepSucceeded(key("a"), REV), wf).state
    with pytest.raises(OutOfOrderEventError, match="lacks approval"):
        next(rs, close("g", subject=REV), wf)


def test_a_gate_cannot_be_entered_without_a_subject() -> None:
    wf = _one(Node("g", "gate", gate_type=GateType.QA))
    with pytest.raises(MalformedEventError, match="head subject"):
        next(new(), START, wf)


def test_unknown_node_is_out_of_order() -> None:
    with pytest.raises(OutOfOrderEventError, match="unknown node"):
        WF.node("ghost")


def test_effect_failure_on_a_blocked_run_is_refused() -> None:
    with pytest.raises(OutOfOrderEventError, match="BLOCKED"):
        next(BLOCKED, EffectFailed(RID, "pr.merge", 1), WF)


def test_next_refuses_the_default_registry_before_loading(monkeypatch: pytest.MonkeyPatch) -> None:
    import sto.engine.reducer as reducer

    monkeypatch.setattr(reducer, "_loaded", set())
    with pytest.raises(HandlersNotLoadedError):
        next(new(), START, WF)
