"""Runtime decide path (D3-06): a vote below quorum is not a close.

``Runtime.decide`` is called on a stand-in ``self`` that has only what it uses, over a real
``GateService`` and store, so the test needs no run, driver or app.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any, cast

from sto.api.runtime import Runtime
from sto.domain import DecisionKind, GateType, RunId, Subject, Surface
from sto.engine.commands import OpenGate
from sto.gates.service import GateService, QuorumRule
from sto.store.memory import MemoryStore
from sto.store.ports import TeamScope

SCOPE = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
SUBJECT = Subject(
    patch_id="p",
    ticket_revision="r",
    head_sha="h",
    evidence_digest="e",
    attention_digest="a",
)


class Policy:
    def quorum(self, scope: Any, gate: Any) -> Sequence[QuorumRule]:
        return [QuorumRule("reviewer", 2)]

    def roles(self, scope: Any, gate: Any, actor: str) -> set[str]:
        return {"reviewer"}

    def refusals(self, scope: Any, gate: Any, actor: str, *, negative: bool) -> list[str]:
        return []


def _runtime() -> tuple[Runtime, list[object]]:
    store = MemoryStore()
    gates = GateService(store, policy=Policy())
    gates.open_gate(SCOPE, OpenGate(RUN, "review", GateType.REVIEW, 1, SUBJECT))
    sent: list[object] = []

    async def submit(run_id: RunId, event: object) -> None:
        sent.append(event)

    async def astate(run_id: RunId) -> None:
        return None

    stub = SimpleNamespace(
        scope=SCOPE,
        _gates=gates,
        _astate=astate,
        _lock=lambda run_id: asyncio.Lock(),
        submit=submit,
    )
    return cast(Runtime, stub), sent


async def _decide(rt: Runtime, actor: str) -> Any:
    return await Runtime.decide(
        rt,
        RUN,
        "review",
        1,
        DecisionKind.APPROVE,
        actor=actor,
        surface=Surface.UI,
        subject_digest=SUBJECT.digest(),
        comment="",
    )


def test_a_vote_below_quorum_tells_the_run_nothing_and_the_closing_vote_tells_it_once() -> None:
    async def body() -> None:
        rt, sent = _runtime()
        vote = await _decide(rt, "iss|a")
        assert not vote.closed
        assert sent == []  # one of two: an event now would advance the run on one vote
        done = await _decide(rt, "iss|b")
        assert done.closed
        assert len(sent) == 1  # and the close is delivered exactly once

    asyncio.run(body())
