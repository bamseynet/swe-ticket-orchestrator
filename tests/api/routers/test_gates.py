"""Decision route (D3-06): what each refusal of the gate service looks like over HTTP.

The route function is called directly with a stand-in runtime that runs a real ``GateService``,
so the test needs no app, run or driver.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any, cast

import pytest
from starlette.requests import Request

from sto.api.routers.gates import _REFUSALS, DecisionIn, decide
from sto.api.routers.runs import ApiError
from sto.api.runtime import Runtime
from sto.domain import DecisionKind, GateType, RunId, Subject
from sto.engine.commands import OpenGate
from sto.gates.hooks import GateHooks
from sto.gates.service import (
    CommentRequiredError,
    DuplicateVoteError,
    GateService,
    QuorumConfigError,
    QuorumRule,
)
from sto.store.memory import MemoryStore
from sto.store.ports import Check, Exists, Key, Op, TeamScope

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


def _runtime(service: GateService) -> Runtime:
    """A runtime whose ``decide`` is the service's, as the dev token's one actor "dev"."""

    async def decide_(run_id: RunId, gate: str, round: int, kind: DecisionKind, **kw: Any) -> Any:
        return service.decide(SCOPE, run_id=run_id, gate=gate, round=round, kind=kind, **kw)

    return cast(Runtime, SimpleNamespace(decide=decide_))


async def _post(rt: Runtime, kind: str, comment: str = "x") -> Any:
    request = Request({"type": "http", "headers": [], "state": {}})
    body = DecisionIn(kind=DecisionKind(kind), subject_digest=SUBJECT.digest(), comment=comment)
    return await decide(str(RUN), "review", 1, body, rt, request)


def _opened(service: GateService) -> None:
    service.open_gate(SCOPE, OpenGate(RUN, "review", GateType.REVIEW, 1, SUBJECT))


def _refused(rt: Runtime, kind: str, comment: str = "x") -> ApiError:
    with pytest.raises(ApiError) as err:
        asyncio.run(_post(rt, kind, comment))
    return err.value


def test_the_refusal_table_maps_each_decision_error_to_one_status() -> None:
    table = dict(_REFUSALS)
    assert table[DuplicateVoteError] == 409  # the state conflicts: this person already voted
    assert table[CommentRequiredError] == 422  # the request is incomplete
    assert table[QuorumConfigError] == 422
    assert len(table) == len(_REFUSALS)  # no error is listed twice


def test_a_second_vote_from_the_same_person_is_a_409_already_voted() -> None:
    service = GateService(MemoryStore(), policy=Policy())
    _opened(service)
    rt = _runtime(service)
    first = asyncio.run(_post(rt, "approve", ""))
    assert first["gate"]["status"] == "OPEN"  # one of two
    err = _refused(rt, "approve", "")
    assert (err.http_status, err.code) == (409, "already_voted")


def test_a_gate_whose_quorum_the_service_cannot_read_is_a_422_quorum_invalid() -> None:
    store = MemoryStore()
    _opened(GateService(store, policy=Policy()))
    err = _refused(
        _runtime(GateService.unpoliced_for_tests(store)), "approve", ""
    )  # the same store, no policy
    assert (err.http_status, err.code) == (422, "quorum_invalid")


def test_a_hook_op_that_loses_a_race_is_a_retryable_503_not_a_500() -> None:
    """A real hook, a real service: the hook's ``Check`` fails, the service re-raises the store's
    ``ConditionFailedError`` (retrying cannot help a hook), and the route calls it contention."""
    hooks = GateHooks()

    @hooks.on_decide
    def never_holds(ctx: object) -> Sequence[Op]:
        return [Check(Key("NOPE", "NOPE"), Exists())]

    service = GateService.unpoliced_for_tests(MemoryStore(), hooks=hooks)
    _opened(service)
    err = _refused(_runtime(service), "approve", "")
    assert (err.http_status, err.code) == (503, "gate_contention")
    assert err.headers["Retry-After"]
