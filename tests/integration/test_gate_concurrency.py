"""Gate concurrency on DynamoDB Local (D3-17). CI only (``integration`` marker, Docker).

The races ``tests/gates/test_retry.py`` runs on memory and SQLite, on a real DynamoDB engine:
quorum 50 with 50 concurrent approvals (G5: every sub-quorum approval commits and exactly one
closes) and two concurrent approvals of a quorum of two (G3: they always close).
"""

from __future__ import annotations

import random
import threading
from collections.abc import Collection, Sequence
from typing import Any

import pytest
from test_dynamodb import Env
from test_dynamodb_local import env as _env

from sto.domain import DecisionKind, Gate, GateStatus, GateType, RunId, Subject, Surface, from_wire
from sto.engine.commands import OpenGate
from sto.gates.retry import Backoff
from sto.gates.service import GateService, QuorumRule
from sto.store.ports import Key, Scope, TeamScope

env = _env  # the DynamoDB Local fixture (it skips outside the integration job)

TEAM = TeamScope("t1")
RUN = RunId.parse("01J00000000000000000000001")
SUBJECT = Subject(
    patch_id="patch-a",
    ticket_revision="rev-a",
    head_sha="sha-a",
    evidence_digest="ev-a",
    attention_digest="att-a",
)


class _Everyone:
    def __init__(self, quorum: int) -> None:
        self._rules = [QuorumRule("reviewer", quorum)]

    def quorum(self, scope: Scope, gate: Gate) -> Sequence[QuorumRule]:
        return self._rules

    def roles(self, scope: Scope, gate: Gate, actor: str) -> Collection[str]:
        return {"reviewer"}

    def refusals(self, scope: Scope, gate: Gate, actor: str, *, negative: bool) -> Sequence[str]:
        return ()


def _race(env: Env, people: int, quorum: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    svc = GateService(env.store, policy=_Everyone(quorum), retry=Backoff(rng=rng.random))
    gate = svc.open_gate(TEAM, OpenGate(RUN, "review", GateType.REVIEW, 1, SUBJECT))
    results: dict[str, Any] = {}
    barrier = threading.Barrier(people)

    def go(name: str) -> None:
        barrier.wait()
        try:
            results[name] = svc.decide(
                TEAM,
                run_id=RUN,
                gate="review",
                round=1,
                kind=DecisionKind.APPROVE,
                actor=name,
                surface=Surface.UI,
                subject_digest=gate.subject.digest(),
            )
        except Exception as err:
            results[name] = err

    pool = [threading.Thread(target=go, args=(f"iss|p{i}",)) for i in range(people)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(timeout=300)
    return results


def _gate(env: Env) -> Gate:
    item = env.store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1"))
    assert item is not None
    return from_wire(Gate, item.data)


@pytest.mark.integration
def test_G5_fifty_concurrent_approvals_of_a_quorum_of_fifty_all_commit(env: Env) -> None:
    results = _race(env, people=50, quorum=50, seed=1)
    errors = [r for r in results.values() if isinstance(r, Exception)]
    assert errors == [], {type(e).__name__ for e in errors}
    assert len(results) == 50
    assert _gate(env).status is GateStatus.APPROVED
    assert sum(1 for r in results.values() if r.closed) == 1
    votes = env.store.query(TEAM, f"RUN#{RUN}", sk_prefix="VOTE#").items
    assert len(votes) == 49  # every sub-quorum approval committed


@pytest.mark.integration
def test_G3_two_concurrent_approvals_of_a_quorum_of_two_always_close(env: Env) -> None:
    results = _race(env, people=2, quorum=2, seed=2)
    assert not [r for r in results.values() if isinstance(r, Exception)], results
    assert _gate(env).status is GateStatus.APPROVED
