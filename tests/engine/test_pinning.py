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
from typing import Any

import pytest
from bundled_templates import SANDBOX_IMAGES, TEAM, TEMPLATE_REF, TEMPLATES, template

from sto.api.runtime import NoPublishedWorkflowError, Runtime, load_pin
from sto.config.manifest import Manifest, load_manifest
from sto.config.org_policy import ORG_ADMIN, OrgPolicyStore, Principal
from sto.config.publish import Pin, Publisher, load_pinned
from sto.config.schema import Workflow as Graph
from sto.config.team_config import TEAM_ADMIN
from sto.domain import Run, RunId, RunStatus, StepKey, Subject
from sto.effects.core import EffectExecutor
from sto.engine.commands import RunStep
from sto.engine.drivers.local import LINEAR_V0_GRAPH
from sto.engine.drivers.ports import Done
from sto.engine.handlers.core import RunStarted, StepSucceeded
from sto.engine.handlers.stages import StageReported, block_unavailable_pin
from sto.engine.reducer import (
    LINEAR_V0,
    PinUnavailableError,
    RunState,
    WorkflowMismatchError,
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
