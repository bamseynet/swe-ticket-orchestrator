"""D2-26: the graph reducer is what the runtime and the local driver run by default.

* ``LINEAR_V0_GRAPH`` is the graph twin of ``LINEAR_V0``: the same stages, gates and re-entries,
  and the same commands for the same events (a parity walk through every path of PLAN 3).
* ``Runtime`` and ``LocalDriver`` default to it.
* ``OpenRevert`` is executed by ``StopExecutor`` (D2-11), once per ``(run, merge_sha)``, wired into
  the runtime's command executor.

The gate suite (tests/gates) is not edited: it runs against the same gate names on both reducers.
Fixtures are synthetic.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

import pytest

from sto.config.schema import Workflow as Graph
from sto.domain import DecisionId, DecisionKind, Receipt, Run, RunId, RunStatus, StepKey, Subject
from sto.engine.commands import Finish, OpenGate, OpenRevert, RunEffect, RunStep
from sto.engine.drivers.local import LINEAR_V0_GRAPH, LocalDriver
from sto.engine.drivers.ports import Done
from sto.engine.handlers.core import (
    EffectConfirmed,
    GateClosed,
    RunStarted,
    StepSucceeded,
)
from sto.engine.reducer import LINEAR_V0, RunState, load_handlers, next

load_handlers()

RID = RunId.from_parts(1, bytes(10))
K = DecisionKind
SUBJ = Subject(
    patch_id="p1", ticket_revision="r1", head_sha="abc", evidence_digest="e1", attention_digest="a1"
)


def _did(n: int) -> DecisionId:
    return DecisionId.from_parts(n, bytes(10))


def test_the_twin_is_a_graph_workflow_with_the_linear_stages() -> None:
    assert isinstance(LINEAR_V0_GRAPH, Graph)
    assert list(LINEAR_V0_GRAPH.stages) == [n.name for n in LINEAR_V0.nodes] + [
        "done",
        "rejected",
    ]
    assert LINEAR_V0_GRAPH.start == "implement"


def test_the_twin_is_structurally_sound() -> None:
    from sto.config.manifest import load_manifest
    from sto.config.schema import OrgPolicy, load_document
    from sto.config.validate_structure import validate_structure

    org = load_document(
        "apiVersion: sto/v1\nkind: OrgPolicy\n"
        "floors:\n  waive_allowed: true\n"
        "  mandatory_gate_roles: {pre_push: [reviewer], review: [reviewer], qa: [qa]}\n"
        "  decision_surfaces: {review: [ui], qa: [ui]}\n"
        "  hold_after_approval_min: 10m\n  identity_max_age: 8h\n"
        "ceilings: {max_steps_per_run: 200, max_run_age: 60d, max_loop: 50,"
        " max_stage_duration: 14d, max_run_usd: 50}\n"
    )
    assert isinstance(org, OrgPolicy)
    issues = validate_structure(LINEAR_V0_GRAPH, manifest=load_manifest(), policy=org)
    assert issues == []


def _as_graph_reports(event: Any) -> Any:
    """What the runtime does for a graph stage with several edges (``Runtime``'s ``_reported``)."""
    from sto.engine.handlers.stages import StageReported

    if isinstance(event, StepSucceeded):
        edges = list(getattr(LINEAR_V0_GRAPH.stages[event.key.stage], "next", {}))
        if len(edges) > 1:
            return StageReported(event.key, edges[0], event.subject)
    return event


class Pair:
    """The linear workflow and its twin, fed the same events."""

    def __init__(self) -> None:
        self.lin = RunState(Run(id=RID, team="t"))
        self.gr = RunState(Run(id=RID, team="t"))

    def feed(self, event: Any) -> tuple[tuple[object, ...], tuple[object, ...]]:
        a = next(self.lin, event, LINEAR_V0)
        b = next(self.gr, _as_graph_reports(event), LINEAR_V0_GRAPH)
        self.lin, self.gr = a.state, b.state
        return a.commands, b.commands

    def same_position(self) -> None:
        assert self.lin.run.status is self.gr.run.status
        if self.lin.run.status.is_terminal:
            return  # linear stays on its last node; the graph moves to its terminal stage
        assert (self.lin.run.status, self.lin.run.stage, self.lin.visit, self.lin.round) == (
            self.gr.run.status,
            self.gr.run.stage,
            self.gr.visit,
            self.gr.round,
        )


def _step(pair: Pair) -> StepSucceeded:
    return StepSucceeded(
        StepKey(RID, pair.lin.run.stage or "", pair.lin.visit, pair.lin.attempt), SUBJ
    )


def _close(pair: Pair, kind: DecisionKind, n: int) -> GateClosed:
    return GateClosed(RID, pair.lin.run.stage or "", pair.lin.round, kind, "alice", _did(n), SUBJ)


def _walk(pair: Pair, script: list[Any]) -> None:
    for n, item in enumerate(script, 1):
        event: Any
        if isinstance(item, DecisionKind):
            event = _close(pair, item, n)
        elif item == "step":
            event = _step(pair)
        elif item == "merged":
            event = EffectConfirmed(RID, "pr.merge", 1, "m1")  # merge is entered once on every path
        else:
            event = item
        a, b = pair.feed(event)
        assert [type(c) for c in a] == [type(c) for c in b], (item, a, b)
        for x, y in zip(a, b, strict=True):
            if isinstance(x, OpenGate):
                assert (x.name, x.type, x.round) == (y.name, y.type, y.round)  # type: ignore[attr-defined]
            if isinstance(x, RunStep):
                assert (x.stage, x.visit, x.attempt) == (y.stage, y.visit, y.attempt)  # type: ignore[attr-defined]
            if isinstance(x, RunEffect):
                assert (x.type, x.stage, x.requires_gates) == (y.type, y.stage, y.requires_gates)  # type: ignore[attr-defined]
            if isinstance(x, Finish):
                assert x == y
        pair.same_position()


PATHS = {
    "happy": ["step", K.APPROVE, "step", K.APPROVE, "merged"],
    "waive": ["step", K.APPROVE, "step", K.WAIVE, "merged"],
    "review_changes": ["step", K.REQUEST_CHANGES, "step", K.APPROVE, "step", K.APPROVE, "merged"],
    "qa_changes": [
        "step",
        K.APPROVE,
        "step",
        K.REQUEST_CHANGES,
        "step",
        K.APPROVE,
        "step",
        K.APPROVE,
    ],
    "retest": ["step", K.APPROVE, "step", K.RETEST, "step", K.APPROVE, "merged"],
    "review_reject": ["step", K.REJECT],
    "qa_reject": ["step", K.APPROVE, "step", K.REJECT],
}


@pytest.mark.parametrize("path", PATHS)
def test_the_twin_walks_every_linear_path_the_same_way(path: str) -> None:
    pair = Pair()
    _walk(pair, [RunStarted(RID), *PATHS[path]])
    assert pair.gr.run.status is pair.lin.run.status


def test_the_happy_path_ends_done_on_both() -> None:
    pair = Pair()
    _walk(pair, [RunStarted(RID), *PATHS["happy"]])
    assert pair.gr.run.status is RunStatus.DONE


# --- the defaults -----------------------------------------------------------------------------


def test_the_local_driver_defaults_to_the_graph_reducer() -> None:
    from sto.store.memory import MemoryStore
    from sto.store.ports import TeamScope

    class Idle:
        async def execute(self, key: str, command: object) -> Done:
            return Done()

    d = LocalDriver(
        MemoryStore(),
        TeamScope("t"),
        None,
        Idle(),
        owner="x",
        clock=lambda: 0.0,
        new_id=lambda: "1",
    )
    assert d._wf is LINEAR_V0_GRAPH


def test_the_runtime_defaults_to_the_graph_reducer() -> None:
    import inspect

    from sto.api.runtime import Runtime

    assert inspect.signature(Runtime.__init__).parameters["workflow"].default is LINEAR_V0_GRAPH


# --- OpenRevert -------------------------------------------------------------------------------


class _Alarms:
    def __init__(self) -> None:
        self.calls: list[tuple[RunId, str, str]] = []

    def raise_alarm(self, run_id: RunId, name: str, detail: str) -> None:
        self.calls.append((run_id, name, detail))


def _runtime(**kw: Any) -> Any:
    from sto.api.runtime import Runtime
    from sto.effects.core import EffectExecutor
    from sto.gates.service import GateService
    from sto.store.memory import MemoryStore
    from sto.store.ports import TeamScope

    store, scope = MemoryStore(), TeamScope("t1")

    class NoSteps:
        async def execute(self, key: str, command: object) -> Done:
            return Done()

    return Runtime(
        store,
        scope,
        gates=GateService(store, policy=None),
        effects=EffectExecutor(store, scope),
        steps=NoSteps(),
        merges=lambda *a, **k: None,  # type: ignore[arg-type]
        live=lambda cmd: cmd.subject,
        **kw,
    )


def test_the_runtime_opens_a_revert_once_per_run_and_merge_sha() -> None:
    opened: list[tuple[str, str]] = []

    def revert(run_id: RunId, sha: str, key: str) -> Receipt:
        opened.append((str(run_id), sha))
        return Receipt(f"pr-for-{sha}", f"https://example.invalid/{sha}", True)

    alarms = _Alarms()
    rt = _runtime(revert=revert, alarm=alarms)
    execute = rt.driver._executor.execute

    async def go() -> list[object]:
        await rt.driver.start(Run(RID, "t1"))
        return [
            await execute("k1", OpenRevert(RID, "m1")),
            await execute("k1", OpenRevert(RID, "m1")),  # a replay after a crash: the same key
            await execute("k2", OpenRevert(RID, "m1")),  # the same merge asked again
            await execute("k3", OpenRevert(RID, "m2")),  # another merge is another revert
        ]

    outcomes = asyncio.run(go())
    assert all(isinstance(o, Done) for o in outcomes)
    assert opened == [(str(RID), "m1"), (str(RID), "m2")]
    assert alarms.calls == []


def test_an_unnameable_merge_needs_a_person_not_a_guess() -> None:
    alarms = _Alarms()
    rt = _runtime(revert=lambda *a: pytest.fail("nothing to revert"), alarm=alarms)
    out = asyncio.run(rt.driver._executor.execute("k", OpenRevert(RID, "unknown")))
    assert isinstance(out, Done)
    assert [n for _, n, _ in alarms.calls] == ["revert_needs_person"]


# --- pins on the twin ---------------------------------------------------------------------------


def test_the_twin_offers_each_gate_the_decisions_of_the_linear_node() -> None:
    from sto.config.schema import GateStage

    for node in LINEAR_V0.nodes:
        if node.kind == "gate":
            stage = LINEAR_V0_GRAPH.stages[node.name]
            assert isinstance(stage, GateStage)
            assert {DecisionKind(d) for d in stage.gate.decisions} == node.decisions, node.name
            assert stage.gate.type == node.gate_type


def test_the_twin_names_its_loops_and_caps_them() -> None:
    assert dict(LINEAR_V0_GRAPH.limits.loops) == {
        "review_changes": 20,
        "qa_changes": 20,
        "retest": 20,
    }
    assert LINEAR_V0_GRAPH.limits.max_steps_per_run == 200


def test_the_twin_has_its_own_name() -> None:
    assert LINEAR_V0_GRAPH.metadata.name != LINEAR_V0.version


# --- G1: a QA step that moves the head is refused, on both reducers ------------------------------


def _for(workflow: Any, event: Any) -> Any:
    return event if workflow is LINEAR_V0 else _as_graph_reports(event)


def _at_qa(workflow: Any) -> RunState:
    pair = Pair()
    for event in (RunStarted(RID),):
        pair.lin = next(pair.lin, event, LINEAR_V0).state
        pair.gr = next(pair.gr, event, LINEAR_V0_GRAPH).state
    _walk_to_qa(pair)
    return pair.lin if workflow is LINEAR_V0 else pair.gr


def _walk_to_qa(pair: Pair) -> None:
    pair.feed(_step(pair))
    pair.feed(_close(pair, K.APPROVE, 1))


@pytest.mark.parametrize("workflow", [LINEAR_V0, LINEAR_V0_GRAPH], ids=["linear", "twin"])
def test_a_qa_step_that_changes_the_head_is_refused(workflow: Any) -> None:
    from sto.engine.reducer import OutOfOrderEventError

    rs = _at_qa(workflow)
    assert rs.run.stage == "qa"
    moved = dataclasses.replace(SUBJ, head_sha="other")
    key = StepKey(RID, "qa", rs.visit, rs.attempt)
    with pytest.raises(OutOfOrderEventError):
        next(rs, _for(workflow, StepSucceeded(key, moved)), workflow)
    ok = next(
        rs, _for(workflow, StepSucceeded(key, SUBJ)), workflow
    )  # the reviewed head goes on to the gate
    assert ok.state.run.stage == "qa_gate"


# --- a run stored under the linear reducer ------------------------------------------------------


def _linear_run_at_merge() -> RunState:
    pair = Pair()
    for event in (RunStarted(RID),):
        pair.lin = next(pair.lin, event, LINEAR_V0).state
    rs = pair.lin
    for n, kind in enumerate((None, K.APPROVE, None, K.APPROVE), 1):
        if kind is None:
            ev: Any = StepSucceeded(StepKey(RID, rs.run.stage or "", rs.visit, rs.attempt), SUBJ)
        else:
            ev = GateClosed(RID, rs.run.stage or "", rs.round, kind, "alice", _did(n), SUBJ)
        rs = next(rs, ev, LINEAR_V0).state
    assert rs.run.stage == "merge"
    return rs


def test_a_linear_run_is_refused_by_the_twin_not_misjudged() -> None:
    from sto.engine.reducer import WorkflowMismatchError

    rs = _linear_run_at_merge()
    with pytest.raises(WorkflowMismatchError):
        next(rs, EffectConfirmed(RID, "pr.merge", 1, "m1"), LINEAR_V0_GRAPH)


def test_a_linear_run_that_resumes_on_the_default_driver_stays_linear_and_is_not_reverted() -> None:
    from sto.store.memory import MemoryStore
    from sto.store.ports import TeamScope

    class Idle:
        async def execute(self, key: str, command: object) -> Done:
            return Done()

    d = LocalDriver(
        MemoryStore(),
        TeamScope("t"),
        None,
        Idle(),
        owner="x",
        clock=lambda: 0.0,
        new_id=lambda: "1",
    )
    old = _linear_run_at_merge()
    assert d._workflow_for(old) is LINEAR_V0
    assert d._workflow_for(RunState(Run(id=RID, team="t"))) is LINEAR_V0_GRAPH  # a new run
    t = next(old, EffectConfirmed(RID, "pr.merge", 1, "m1"), d._workflow_for(old))
    assert t.state.run.status is RunStatus.DONE
    assert not any(isinstance(c, OpenRevert) for c in t.commands)
    assert t.state.run.incident is False


# --- the runtime ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("stage", "gate", "expected"),
    [
        ("review_gate", "review_gate", True),  # still at the gate
        ("merge", "review_gate", True),  # the merge that needs it (the post-approval hold)
        ("merge", "qa_gate", True),
        ("qa", "review_gate", False),  # a step does not need a gate
        ("implement", "qa_gate", False),
        (None, "review_gate", False),
    ],
)
def test_a_late_reject_is_still_wanted_while_the_gated_merge_waits(
    stage: str | None, gate: str, expected: bool
) -> None:
    from types import SimpleNamespace

    from sto.api.runtime import Runtime

    stub = SimpleNamespace(_wf=LINEAR_V0_GRAPH)
    assert Runtime._waiting_on(stub, stage, gate) is expected  # type: ignore[arg-type]


def _commands(version: str | None) -> Any:
    from sto.api.runtime import _Commands

    return _Commands(
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        None,  # type: ignore[arg-type]
        lambda run_id: RunStatus.RUNNING,
        0.0,
        None,  # type: ignore[arg-type]
        LINEAR_V0_GRAPH,
        lambda run_id: version,
    )


def test_a_step_that_succeeds_takes_the_first_edge_of_a_graph_stage() -> None:
    from sto.engine.handlers.stages import StageReported

    qa, impl = StepKey(RID, "qa", 1, 1), StepKey(RID, "implement", 1, 1)
    out = asyncio.run(
        _commands(LINEAR_V0_GRAPH.metadata.name)._reported(
            RID, Done([StepSucceeded(qa, SUBJ), StepSucceeded(impl, SUBJ)])
        )
    )
    assert list(out.events) == [StageReported(qa, "pass", SUBJ), StageReported(impl, "ready", SUBJ)]


def test_a_run_still_on_the_linear_reducer_keeps_its_plain_success() -> None:
    done = Done([StepSucceeded(StepKey(RID, "qa", 1, 1), SUBJ)])
    out = asyncio.run(_commands("linear-v0")._reported(RID, done))
    assert out is done
