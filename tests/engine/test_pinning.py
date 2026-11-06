"""D2-30: a run pins the published digest, and nothing published later changes that run.

* The pin is ``name@version#digest`` in ``Run.workflow_version``; ``workflow_version()`` returns it
  and the reducer checks the workflow's name against it.
* A runtime with a ``Publisher`` pins ``Publisher.latest`` when it creates a run, and the driver and
  the command executor load the workflow through ``load_pinned`` for every later step.
* A publish during a run (a changed outcome, prompt or stage edge) changes nothing for that run.
* A run whose pinned manifest no longer loads BLOCKS with ``pin_unavailable`` and nothing raises.
* The built-ins (``linear-v0``, the unpublished twin ``linear-v0-graph``) are pinned by name, as
  before.

Fixtures are synthetic; the store is in memory.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

import pytest
from bundled_templates import SANDBOX_IMAGES, TEAM, TEMPLATE_REF, TEMPLATES, template

from sto.api.runtime import NoPublishedWorkflowError, Runtime, load_pin
from sto.config.manifest import Manifest, load_manifest
from sto.config.org_policy import ORG_ADMIN, OrgPolicyStore, Principal
from sto.config.publish import Pin, Publisher, load_pinned
from sto.config.schema import Metadata
from sto.config.schema import Workflow as Graph
from sto.config.team_config import TEAM_ADMIN
from sto.domain import Run, RunId, RunStatus, StepKey, Subject
from sto.effects.core import EffectExecutor
from sto.engine.commands import RunStep, StopRun
from sto.engine.drivers.local import LINEAR_V0_GRAPH
from sto.engine.drivers.ports import Done
from sto.engine.handlers.cancel import EffectLandedDuringStop
from sto.engine.handlers.core import (
    CancelCompleted,
    CancelRequested,
    EffectConfirmed,
    RunStarted,
    StepSucceeded,
)
from sto.engine.handlers.stages import StageReported
from sto.engine.reducer import (
    LINEAR_V0,
    MalformedEventError,
    OutOfOrderEventError,
    PinUnavailableError,
    RunState,
    UnavailablePin,
    WorkflowMismatchError,
    block_unavailable_pin,
    load_handlers,
    next,
    parse_pin,
    pin_version,
    workflow_version,
)
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key, TeamScope

load_handlers()

SCOPE = TeamScope(TEAM["kanban"])
ADMIN = Principal("alice", frozenset({TEAM_ADMIN}), team=SCOPE.team)
OVERLAY_TEXT = (TEMPLATES / "kanban" / "overlay.yaml").read_text(encoding="utf-8")
PROMPTS = {"planner": "You plan.", "implementer": "You implement."}
RID = RunId.from_parts(1, bytes(10))
DIGEST = "sha256:" + "a" * 64
SUBJ = Subject(
    patch_id="p1", ticket_revision="r1", head_sha="abc", evidence_digest="e1", attention_digest="a1"
)


# --- the pin string -----------------------------------------------------------------------------


def test_a_pin_round_trips() -> None:
    text = pin_version("platform-kanban", 3, DIGEST)
    assert text == f"platform-kanban@3#{DIGEST}"
    assert parse_pin(text) == ("platform-kanban", 3, DIGEST)


@pytest.mark.parametrize(
    "text",
    [None, "", "linear-v0", "linear-v0-graph", "a@b#c", "a@1", "a@1#", "@1#x", "a@#x", "a@-1#x"],
)
def test_a_built_in_version_or_a_malformed_pin_is_not_a_pin(text: str | None) -> None:
    assert parse_pin(text) is None


def test_workflow_version_returns_the_pin_for_the_workflow_it_names() -> None:
    wf = template()
    pin = pin_version(wf.metadata.name, 2, DIGEST)
    assert workflow_version(wf, pin) == pin


def test_workflow_version_is_the_name_without_a_pin_for_it() -> None:
    wf = template()
    assert workflow_version(wf) == wf.metadata.name
    assert workflow_version(wf, None) == wf.metadata.name
    assert workflow_version(wf, pin_version("another", 1, DIGEST)) == wf.metadata.name
    assert workflow_version(wf, "linear-v0") == wf.metadata.name
    assert workflow_version(LINEAR_V0, pin_version("linear-v0", 1, DIGEST)) == "linear-v0"
    assert workflow_version(LINEAR_V0_GRAPH) == "linear-v0-graph"


def test_the_reducer_refuses_a_run_pinned_to_another_workflow() -> None:
    wf = template()
    run = Run(id=RID, team="t", workflow_version=pin_version("another", 1, DIGEST))
    with pytest.raises(WorkflowMismatchError):
        next(RunState(run), RunStarted(RID), wf)


def test_run_started_keeps_the_pin_it_finds_and_sets_a_built_in_name() -> None:
    wf = template()
    pin = pin_version(wf.metadata.name, 4, DIGEST)
    pinned = next(RunState(Run(id=RID, team="t", workflow_version=pin)), RunStarted(RID), wf)
    assert pinned.state.run.workflow_version == pin
    assert pinned.state.run.status is RunStatus.RUNNING
    plain = next(RunState(Run(id=RID, team="t")), RunStarted(RID), LINEAR_V0_GRAPH)
    assert plain.state.run.workflow_version == "linear-v0-graph"


def test_a_pinned_run_goes_on_under_its_pin_and_a_late_event_for_a_rename_is_refused() -> None:
    wf = template()
    pin = pin_version(wf.metadata.name, 4, DIGEST)
    started = next(RunState(Run(id=RID, team="t", workflow_version=pin)), RunStarted(RID), wf)
    key = StepKey(RID, wf.start, 1, 1)
    again = next(started.state, StageReported(key, "ready", SUBJ), wf)  # the same pin: accepted
    assert again.state.run.workflow_version == pin
    renamed = wf.model_copy(update={"metadata": wf.metadata.model_copy(update={"name": "other"})})
    with pytest.raises(WorkflowMismatchError):
        next(started.state, StageReported(key, "ready", SUBJ), renamed)


def test_next_given_an_unavailable_pin_blocks_instead_of_raising() -> None:
    from sto.config.schema import Metadata

    pin = pin_version("x", 1, DIGEST)
    running = Run(id=RID, team="t", workflow_version=pin).advance(RunStatus.RUNNING)
    stand_in = UnavailablePin.model_construct(metadata=Metadata(name="x", team="t"), reason="gone")
    out = next(RunState(running), StepSucceeded(StepKey(RID, "s", 1, 1), SUBJ), stand_in)
    assert (out.state.run.status, out.state.run.blocked_reason, out.commands) == (
        RunStatus.BLOCKED,
        "pin_unavailable",
        (),
    )
    other = RunId.from_parts(2, bytes(10))
    with pytest.raises(OutOfOrderEventError):
        next(RunState(running), StepSucceeded(StepKey(other, "s", 1, 1), SUBJ), stand_in)


def test_block_unavailable_pin_blocks_with_a_reason_and_queues_nothing() -> None:
    load_handlers()
    running = Run(id=RID, team="t", workflow_version=pin_version("x", 1, DIGEST)).advance(
        RunStatus.RUNNING
    )
    out = block_unavailable_pin(RunState(running))
    assert out.state.run.status is RunStatus.BLOCKED
    assert out.state.run.blocked_reason == "pin_unavailable"
    assert out.commands == ()
    again = block_unavailable_pin(out.state)  # already blocked: left as it is
    assert again.state == out.state
    done = RunState(running.advance(RunStatus.DONE))
    assert block_unavailable_pin(done).state == done


# --- the runtime pins what is published ----------------------------------------------------------


class Steps:
    """A step executor that reports success, and can publish in the middle of a step."""

    def __init__(self) -> None:
        self.stages: list[str] = []
        self.during: dict[str, Any] = {}

    async def execute(self, key: str, command: object) -> Done:
        assert isinstance(command, RunStep)
        self.stages.append(command.stage)
        hook = self.during.pop(command.stage, None)
        if hook is not None:
            hook()
        return Done([StepSucceeded(StepKey(command.run_id, command.stage, 1, 1), SUBJ)])


def _resolve(ref: str) -> tuple[str, Graph]:
    assert ref == TEMPLATE_REF
    return TEMPLATE_REF, template()


class World:
    def __init__(self) -> None:
        self.store = MemoryStore()
        OrgPolicyStore(self.store).write(
            Principal("root", frozenset({ORG_ADMIN})),
            (TEMPLATES / "org-policy.yaml").read_text(encoding="utf-8"),
            expected_version=None,
        )
        self.publisher = Publisher(
            self.store, resolve_template=_resolve, sandbox_images=SANDBOX_IMAGES
        )
        self.steps = Steps()
        self.runtime = Runtime(
            self.store,
            SCOPE,
            gates=GateService(self.store, policy=None),
            effects=EffectExecutor(self.store, SCOPE),
            steps=self.steps,
            merges=lambda *a, **k: None,  # type: ignore[arg-type]
            live=lambda cmd: cmd.subject,
            publisher=self.publisher,
            workflow_name="platform-kanban",
        )

    def publish(
        self, *, manifest: Manifest | None = None, text: str = OVERLAY_TEXT, **p: str
    ) -> Pin:
        got = self.publisher.publish(
            SCOPE,
            who=ADMIN,
            text=text,
            manifest=manifest or load_manifest(),
            prompts={**PROMPTS, **p},
        )
        return got.pin

    async def drive(self, run: Run) -> RunState:
        return await self.runtime.driver.run_until_idle(run.id)


def _with_outcome(manifest: Manifest, profile: str, extra: str) -> Manifest:
    doc = manifest.model_dump(mode="json", by_alias=True)
    for spec in doc["effects"].values():
        spec["hold"] = f"{spec['hold']}s"
    doc["profiles"][profile]["outcomes"] = sorted([*doc["profiles"][profile]["outcomes"], extra])
    return Manifest.model_validate(doc)


def _text(pin: Pin) -> str:
    return pin_version(pin.name, pin.version, pin.digest)


def test_a_new_run_records_the_latest_published_pin() -> None:
    w = World()
    v1 = w.publish()
    v2 = w.publish(implementer="You implement, differently.")
    assert (v2.version, v1.digest != v2.digest) == (2, True)

    async def go() -> Run:
        return await w.runtime.create_run("T-1")

    run = asyncio.run(go())
    assert run.workflow_version == _text(v2)
    assert run.team == SCOPE.team
    assert w.runtime.state(run.id).run.workflow_version == _text(v2)


def test_a_run_before_the_first_publish_is_refused_not_started_on_something_else() -> None:
    w = World()
    with pytest.raises(NoPublishedWorkflowError, match="has not published"):
        asyncio.run(w.runtime.create_run("T-1"))


def test_a_runtime_takes_a_publisher_and_a_name_together() -> None:
    w = World()
    with pytest.raises(ValueError, match="together"):
        Runtime(
            w.store,
            SCOPE,
            gates=GateService(w.store, policy=None),
            effects=EffectExecutor(w.store, SCOPE),
            steps=w.steps,
            merges=lambda *a, **k: None,  # type: ignore[arg-type]
            live=lambda cmd: cmd.subject,
            publisher=w.publisher,
        )


def test_a_publish_during_a_run_changes_nothing_for_that_run() -> None:
    w = World()
    v1 = w.publish()
    changed = _with_outcome(load_manifest(), "planner", "zzz_new_outcome")
    # during triage: a new version with a changed profile outcome and a changed prompt
    published: list[Pin] = []
    w.steps.during["triage"] = lambda: published.append(
        w.publish(manifest=changed, implementer="Ignore the ticket.")
    )

    async def go() -> tuple[Run, RunState]:
        run = await w.runtime.create_run("T-1")
        return run, await w.drive(run)

    run, state = asyncio.run(go())
    (v2,) = published
    assert v2.version == 2
    assert v2.digest != v1.digest
    assert w.publisher.latest(SCOPE, "platform-kanban") == v2
    # the run did what version 1 says: triage reported 'ready', so it went on to implement
    assert w.steps.stages[:2] == ["triage", "implement"]
    assert state.run.workflow_version == _text(v1)
    assert load_pin(w.store, SCOPE, state.run.workflow_version or "").metadata.name == v1.name
    # a run started after the publish pins the new version
    later = asyncio.run(w.runtime.create_run("T-2"))
    assert later.workflow_version == _text(v2)


def test_every_later_step_loads_the_manifest_through_load_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    w = World()
    v1 = w.publish()
    seen: list[Pin] = []
    real = load_pinned

    def spy(store: Any, scope: Any, pin: Pin) -> Any:
        seen.append(pin)
        return real(store, scope, pin)

    monkeypatch.setattr("sto.api.runtime.load_pinned", spy)

    async def go() -> None:
        run = await w.runtime.create_run("T-1")
        await w.drive(run)

    asyncio.run(go())
    assert set(seen) == {v1}
    assert len(w.steps.stages) >= 2
    assert len(seen) >= len(w.steps.stages)  # at least one load per step


def test_a_run_whose_pinned_manifest_is_gone_blocks_with_a_reason() -> None:
    w = World()
    v1 = w.publish()
    w.steps.during["triage"] = lambda: w.store.delete(
        PLATFORM, Key(f"MANIFEST#{v1.digest}", "META")
    )

    async def go() -> RunState:
        run = await w.runtime.create_run("T-1")
        return await w.drive(run)

    state = asyncio.run(go())  # nothing raises
    assert state.run.status is RunStatus.BLOCKED
    assert state.run.blocked_reason == "pin_unavailable"
    assert state.run.workflow_version == _text(v1)
    assert w.steps.stages == ["triage"]  # nothing ran after the manifest went


def test_load_pin_refuses_what_is_not_a_pin_or_not_there() -> None:
    w = World()
    with pytest.raises(PinUnavailableError):
        load_pin(w.store, SCOPE, "linear-v0")
    with pytest.raises(PinUnavailableError, match="not published"):
        load_pin(w.store, SCOPE, pin_version("platform-kanban", 9, DIGEST))
    v1 = w.publish()
    with pytest.raises(PinUnavailableError):  # a digest that is not the stored one
        load_pin(w.store, SCOPE, pin_version(v1.name, v1.version, DIGEST))
    assert load_pin(w.store, SCOPE, _text(v1)).metadata.name == "platform-kanban"


# --- the built-ins are pinned by name, as before -------------------------------------------------


def test_the_built_in_twin_still_runs_without_a_publisher() -> None:
    store = MemoryStore()
    scope = TeamScope("t1")
    steps = Steps()
    rt = Runtime(
        store,
        scope,
        gates=GateService(store, policy=None),
        effects=EffectExecutor(store, scope),
        steps=steps,
        merges=lambda *a, **k: None,  # type: ignore[arg-type]
        live=lambda cmd: cmd.subject,
    )

    async def go() -> RunState:
        run = await rt.create_run("T-1")
        assert run.workflow_version is None
        return await rt.driver.run_until_idle(run.id)

    state = asyncio.run(go())
    assert state.run.workflow_version == "linear-v0-graph"
    assert steps.stages[0] == "implement"


# --- Stop and in-flight events while the pin does not load -----------------------------------


def _blocked_world() -> tuple[World, Key, dict[str, Any]]:
    w = World()
    v1 = w.publish()
    key = Key(f"MANIFEST#{v1.digest}", "META")
    saved: dict[str, Any] = {}

    def gone() -> None:
        item = w.store.get(PLATFORM, key)
        assert item is not None
        saved["data"] = item.data
        w.store.delete(PLATFORM, key)

    w.steps.during["triage"] = gone
    return w, key, saved


def test_stop_on_a_pin_unavailable_run_is_not_lost() -> None:
    """ASSERTS: a Stop sent to a run BLOCKED on pin_unavailable either stops it or stays queued.
    Bug: block_unavailable_pin returns the state unchanged and the driver logs the CancelRequested
    as 'applied' and drops it: the Stop is silently lost and the run stays BLOCKED."""
    w, _, _ = _blocked_world()

    async def go() -> tuple[RunState, int]:
        run = await w.runtime.create_run("T-1")
        st = await w.drive(run)
        assert (st.run.status, st.run.blocked_reason) == (RunStatus.BLOCKED, "pin_unavailable")
        await w.runtime.cancel(run.id)
        st = await w.drive(run)
        return st, w.runtime.driver.pending_events(run.id)

    st, pending = asyncio.run(go())
    assert st.run.status in (RunStatus.CANCELLING, RunStatus.CANCELLED) or pending > 0, (
        f"Stop lost: status={st.run.status}, inbox={pending}"
    )


def test_a_stop_sent_during_the_outage_takes_effect_once_the_manifest_is_restored() -> None:
    """ASSERTS: restore the manifest after a Stop sent during the outage, drive, and the run ends
    stopped without a second Stop. Bug: the first Stop was consumed; the run stays BLOCKED."""
    w, key, saved = _blocked_world()

    async def go() -> RunState:
        run = await w.runtime.create_run("T-1")
        await w.drive(run)
        await w.runtime.cancel(run.id)
        await w.drive(run)
        w.store.put(PLATFORM, key, saved["data"])
        return await w.drive(run)

    st = asyncio.run(go())
    assert st.run.status in (RunStatus.CANCELLING, RunStatus.CANCELLED), st.run.status


def _cancelling() -> RunState:
    pin = pin_version("x", 1, DIGEST)
    run = Run(id=RID, team=SCOPE.team, workflow_version=pin).advance(RunStatus.RUNNING)
    return RunState(run.advance(RunStatus.CANCELLING))


def _stand_in_for_stop() -> UnavailablePin:
    return UnavailablePin.model_construct(
        metadata=Metadata(name="x", team=SCOPE.team), reason="gone"
    )


def test_a_stop_in_progress_is_not_frozen_by_a_lost_pin() -> None:
    """ASSERTS: CancelCompleted for a CANCELLING run whose pin is gone is not silently consumed:
    next() must either finish the Stop or raise (so LocalDriver._apply keeps it queued).
    Bug: CANCELLING -> BLOCKED is not a legal transition, so the event was consumed unchanged and
    the run stayed CANCELLING forever."""
    rs = _cancelling()
    try:
        out = next(rs, CancelCompleted(RID), _stand_in_for_stop())
    except Exception:
        return  # kept queued: acceptable
    assert out.state != rs, "CancelCompleted consumed with no effect: the Stop never completes"


def test_a_merge_landed_during_stop_is_not_dropped_by_a_lost_pin() -> None:
    """ASSERTS: a merge that landed during a Stop (EffectLandedDuringStop, which plans the revert,
    PLAN 6.2) is not silently consumed when the pin is gone. Bug: dropped, so no revert and no
    incident is ever recorded for an uncovered merge."""
    rs = _cancelling()
    ev = EffectLandedDuringStop(RID, "pr.merge", 1, merge_sha="m" * 40, head_sha="h" * 40)
    try:
        out = next(rs, ev, _stand_in_for_stop())
    except Exception:
        return
    assert out.state != rs or out.commands, "landed merge dropped: no revert, no incident"


def test_a_confirmed_merge_is_not_dropped_by_a_lost_pin() -> None:
    """ASSERTS: an EffectConfirmed for pr.merge arriving while the pin is gone is not consumed
    without recording the merge (Run.merges / uncovered-merge accounting, PLAN 6.2).
    Bug: the run goes BLOCKED with merges=() and the confirmation is dropped for ever."""
    pin = pin_version("x", 1, DIGEST)
    run = Run(id=RID, team=SCOPE.team, workflow_version=pin).advance(RunStatus.RUNNING)
    rs = RunState(run.advance(RunStatus.WAITING_EXTERNAL))
    ev = EffectConfirmed(RID, "pr.merge", 1, merge_sha="m" * 40)
    try:
        out = next(rs, ev, _stand_in_for_stop())
    except Exception:
        return
    assert out.state.merges, f"merge confirmation dropped; run now {out.state.run.status}"


def test_control_a_fresh_stop_after_restore_works() -> None:
    """CONTROL (passes today): once the manifest is restored a NEW Stop does stop the run."""
    w, key, saved = _blocked_world()

    async def go() -> RunState:
        run = await w.runtime.create_run("T-1")
        await w.drive(run)
        w.store.put(PLATFORM, key, saved["data"])
        await w.runtime.cancel(run.id)
        return await w.drive(run)

    st = asyncio.run(go())
    assert st.run.status in (RunStatus.CANCELLING, RunStatus.CANCELLED), st.run.status


# --- a publish that changes the graph ---------------------------------------------------------


V2_TEXT = (
    OVERLAY_TEXT.replace("  refine: null\n", "")
    .replace("  plan: null\n", "")
    .replace(
        "triage: { model_tier: fast, next: { ready: implement } }", "triage: { model_tier: fast }"
    )
)


def test_a_publish_that_reroutes_triage_does_not_reroute_a_running_run() -> None:
    assert V2_TEXT != OVERLAY_TEXT
    w = World()
    v1 = w.publish()
    out = []
    w.steps.during["triage"] = lambda: out.append(w.publish(text=V2_TEXT))

    async def go() -> None:
        run = await w.runtime.create_run("T-1")
        await w.drive(run)

    asyncio.run(go())
    (v2,) = out
    assert v2.version == 2
    assert v2.digest != v1.digest
    assert w.steps.stages[:2] == ["triage", "implement"], w.steps.stages

    w.steps.stages.clear()

    async def go2() -> None:
        run = await w.runtime.create_run("T-2")
        await w.drive(run)

    asyncio.run(go2())
    assert w.steps.stages[:2] == ["triage", "refine"], w.steps.stages


def test_a_stop_ends_fail_closed_with_a_revert_per_recorded_merge() -> None:
    from sto.engine.commands import Finish, OpenRevert
    from sto.engine.handlers.cancel import CancelCompletedUnresolved
    from sto.engine.reducer import Merge

    rs = dataclasses.replace(
        _cancelling(), merges=(Merge("m1", "h"), Merge("m1", "h"), Merge("m2", None))
    )
    out = next(rs, CancelCompleted(RID), _stand_in_for_stop())
    assert out.state.run.status is RunStatus.CANCELLED
    assert out.state.run.incident is True
    assert out.state.run.version == rs.run.version + 1
    assert out.commands == (
        OpenRevert(RID, "m1"),
        OpenRevert(RID, "m2"),
        Finish(RID, RunStatus.CANCELLED, True),
    )
    clean = next(_cancelling(), CancelCompleted(RID), _stand_in_for_stop())
    assert (clean.state.run.incident, clean.commands) == (
        False,
        (Finish(RID, RunStatus.CANCELLED, False),),
    )
    flagged = next(_cancelling(), CancelCompletedUnresolved(RID), _stand_in_for_stop())
    assert flagged.state.run.incident is True


def test_a_landed_merge_while_stopping_is_recorded_not_dropped() -> None:
    ev = EffectLandedDuringStop(RID, "pr.merge", 1, merge_sha="m" * 40, head_sha="h" * 40)
    out = next(_cancelling(), ev, _stand_in_for_stop())
    assert [m.sha for m in out.state.merges] == ["m" * 40]


def test_stop_and_landed_events_outside_a_stop_block_or_are_refused_not_applied() -> None:
    running = RunState(
        Run(id=RID, team=SCOPE.team, workflow_version=pin_version("x", 1, DIGEST)).advance(
            RunStatus.RUNNING
        )
    )
    landed = EffectLandedDuringStop(RID, "pr.merge", 1, merge_sha="m" * 40)
    out = next(running, landed, _stand_in_for_stop())  # not stopping: the pin block
    assert (out.state.run.status, out.state.merges) == (RunStatus.BLOCKED, ())
    stop = next(running, CancelRequested(RID), _stand_in_for_stop())
    assert stop.state.run.status is RunStatus.CANCELLING
    assert stop.commands == (StopRun(RID),)
    blocked = next(running, StepSucceeded(StepKey(RID, "s", 1, 1), SUBJ), _stand_in_for_stop())
    assert next(blocked.state, CancelRequested(RID), _stand_in_for_stop()).state.run.status is (
        RunStatus.CANCELLING
    )


def test_a_confirmed_merge_without_a_sha_is_malformed_even_without_the_workflow() -> None:
    run = Run(id=RID, team=SCOPE.team, workflow_version=pin_version("x", 1, DIGEST))
    rs = RunState(run.advance(RunStatus.RUNNING))
    with pytest.raises(MalformedEventError):
        next(rs, EffectConfirmed(RID, "pr.merge", 1, merge_sha=" "), _stand_in_for_stop())


def test_a_confirmed_merge_records_the_live_head_and_blocks() -> None:
    run = Run(id=RID, team=SCOPE.team, workflow_version=pin_version("x", 1, DIGEST))
    rs = RunState(run.advance(RunStatus.RUNNING), subject=SUBJ)
    out = next(rs, EffectConfirmed(RID, "pr.merge", 1, merge_sha="m1"), _stand_in_for_stop())
    assert [(m.sha, m.head_sha) for m in out.state.merges] == [("m1", SUBJ.head_sha)]
    assert out.state.run.status is RunStatus.BLOCKED
    assert out.state.run.version == rs.run.version + 1
    # a run that cannot block from where it is (finished) still keeps the record
    done = RunState(run.advance(RunStatus.RUNNING).advance(RunStatus.DONE))
    kept = next(done, EffectConfirmed(RID, "pr.merge", 1, merge_sha="m2"), _stand_in_for_stop())
    assert [m.sha for m in kept.state.merges] == ["m2"]
    assert kept.state.run.status is RunStatus.DONE
    assert kept.state.run.version == done.run.version + 1


def test_blocking_bumps_the_run_version_once() -> None:
    running = Run(id=RID, team="t").advance(RunStatus.RUNNING)
    out = block_unavailable_pin(RunState(running))
    assert out.state.run.version == running.version + 1


# --- the runtime on a pinned run --------------------------------------------------------------


def test_the_runtime_finds_a_pinned_runs_workflow_and_not_the_default() -> None:
    w = World()
    v1 = w.publish()
    run = Run(id=RID, team=SCOPE.team, workflow_version=_text(v1))
    wf = w.runtime._workflow_of(RunState(run))
    assert isinstance(wf, Graph)
    assert wf.metadata.name == "platform-kanban"
    builtin = RunState(Run(id=RID, team=SCOPE.team, workflow_version="linear-v0-graph"))
    assert w.runtime._workflow_of(builtin) is LINEAR_V0_GRAPH
    w.store.delete(PLATFORM, Key(f"MANIFEST#{v1.digest}", "META"))
    assert w.runtime._workflow_of(RunState(run)) is None


def test_stop_gate_roles_uses_the_pinned_workflow() -> None:
    """``mark_ready`` waits on ``review_gate`` in the pinned workflow; the built-in twin has no
    such stage, so a runtime that used its own workflow would offer nobody."""
    from sto.domain import DecisionId, Gate, GateId, GateStatus, GateType
    from sto.engine.reducer import Approval

    w = World()
    v1 = w.publish()
    run = Run(id=RID, team=SCOPE.team, workflow_version=_text(v1), stage="mark_ready")
    approval = Approval("review_gate", 1, DecisionId.from_parts(1, bytes(10)), "d", "abc")
    state = RunState(run.advance(RunStatus.RUNNING), approvals=(approval,))
    gate = Gate(
        GateId.from_parts(1, bytes(10)),
        RID,
        "review_gate",
        GateType.REVIEW,
        1,
        SUBJ,
        status=GateStatus.APPROVED,
        closed_by="bob",
    )

    async def astate(run_id: RunId) -> RunState:
        return state

    async def gates(run_id: RunId) -> list[Gate]:
        return [gate]

    w.runtime._astate = astate  # type: ignore[method-assign]
    w.runtime._read_gates = gates  # type: ignore[method-assign]
    assert asyncio.run(w.runtime.stop_gate_roles(RID)) == {"reviewer"}
    w.store.delete(PLATFORM, Key(f"MANIFEST#{v1.digest}", "META"))  # the pin is gone: not waiting
    assert asyncio.run(w.runtime.stop_gate_roles(RID)) == frozenset()


def test_waiting_on_follows_the_workflow_it_is_given() -> None:
    w = World()
    v1 = w.publish()
    wf = load_pin(w.store, SCOPE, _text(v1))
    assert w.runtime._waiting_on("mark_ready", "review_gate", wf) is True
    assert w.runtime._waiting_on("triage", "review_gate", wf) is False
    assert w.runtime._waiting_on("review_gate", "review_gate", wf) is True
    assert w.runtime._waiting_on("mark_ready", "review_gate") is False  # the default twin
    assert w.runtime._waiting_on(None, "review_gate", wf) is False
    assert w.runtime._waiting_on("nowhere", "review_gate", wf) is False


def test_a_latest_version_that_does_not_load_is_refused_at_create_run() -> None:
    w = World()
    v1 = w.publish()
    w.store.delete(PLATFORM, Key(f"MANIFEST#{v1.digest}", "META"))
    with pytest.raises(NoPublishedWorkflowError, match="cannot be loaded"):
        asyncio.run(w.runtime.create_run("T-1"))


def test_parse_pin_refuses_a_version_that_is_digits_only_to_unicode() -> None:
    assert parse_pin(f"a@²#{DIGEST}") is None
    assert parse_pin(f"a@٣#{DIGEST}") is None
    assert parse_pin(f"a@2#{DIGEST}") == ("a", 2, DIGEST)
