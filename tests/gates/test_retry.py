"""Write conflicts and concurrency (D3-17): backoff with jitter and a high-quorum contention test.

The fast stores (memory, SQLite) run here. DynamoDB Local runs the same race in
``tests/integration/test_gate_concurrency.py`` (CI only). Backoff is pure: the sleep and the RNG
are injected, so the schedule is checked without a clock.
"""

from __future__ import annotations

import itertools
import random
import threading
from collections.abc import Callable, Sequence
from typing import Any

import pytest
from test_decisions import (
    APPROVE,
    EVENTS,
    REVIEWERS,
    RUN,
    TEAM,
    A,
    B,
    Policy,
    Recording,
    Windowed,
    _assert_one_close,
    _event,
    _snapshot,
    audit_actions,
    decide,
    gate_of,
    items,
    open_cmd,
)
from test_decisions import (
    make_store as _make_store,
)

from sto.domain import GateStatus
from sto.gates.retry import Backoff
from sto.gates.service import GateService, QuorumRule, verify_audit_chain
from sto.store.ports import Scope, Store, TransactionOutcomeUnknownError

make_store = _make_store  # the parametrized (memory, sqlite) store fixture


def test_backoff_delay_is_full_jitter_under_a_capped_exponential() -> None:
    slept: list[float] = []
    b = Backoff(base=0.01, cap=0.1, rng=lambda: 1.0, sleep=slept.append)
    for attempt in range(8):
        b.wait(attempt)
    assert slept == [0.01, 0.02, 0.04, 0.08, 0.1, 0.1, 0.1, 0.1]  # doubles, then the cap


def test_backoff_jitter_scales_the_delay_and_zero_is_allowed() -> None:
    b = Backoff(base=0.01, cap=1.0, rng=lambda: 0.5, sleep=lambda _: None)
    assert b.delay(3) == pytest.approx(0.04)
    assert Backoff(rng=lambda: 0.0, sleep=lambda _: None).delay(9) == 0.0


def test_backoff_never_sleeps_beyond_the_cap_for_a_huge_attempt_number() -> None:
    b = Backoff(base=0.01, cap=0.1, rng=lambda: 1.0, sleep=lambda _: None)
    assert b.delay(10_000) == 0.1


def test_backoff_rejects_nonsense_settings() -> None:
    for bad in (
        {"base": 0},
        {"base": -1},
        {"cap": 0.0001, "base": 0.01},
        {"attempts": 0},
    ):
        with pytest.raises(ValueError, match="must"):
            Backoff(**bad)


def _service(store: Store, quorum: int, people: list[str], backoff: Backoff) -> GateService:
    roles = {n: {"reviewer"} for n in people}
    return GateService(store, policy=Policy([QuorumRule("reviewer", quorum)], roles), retry=backoff)


def _contend(
    make: Callable[[], Store], people: int, quorum: int, seed: int
) -> tuple[Store, dict[str, Any]]:
    store = make()
    names = [f"iss|p{i}" for i in range(people)]
    rng = random.Random(seed)
    svc = _service(store, quorum, names, Backoff(rng=rng.random))
    gate = svc.open_gate(TEAM, open_cmd())
    results: dict[str, Any] = {}
    barrier = threading.Barrier(people)

    def go(i: int) -> None:
        barrier.wait()
        try:
            results[names[i]] = (APPROVE, decide(svc, APPROVE, names[i], gate=gate))
        except Exception as err:
            results[names[i]] = (APPROVE, err)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(people)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return store, results


def test_G5_fifty_concurrent_approvals_of_a_quorum_of_fifty_all_commit(
    make_store: Callable[[], Store],
) -> None:
    """The D3-06 pass-2 finding: with quorum 50 every approval is sub-quorum but the last, so each
    must commit; 59/250 (memory) and 76/250 (SQLite) used to fail with GateContentionError."""
    for seed in range(2):
        store, results = _contend(make_store, people=50, quorum=50, seed=seed)
        errors = [r for _, r in results.values() if isinstance(r, Exception)]
        assert errors == [], {type(e).__name__ for e in errors}
        _assert_one_close(store, results, 50)
        assert gate_of(store).status is GateStatus.APPROVED
        assert len(items(store, "VOTE#")) == 49
        assert audit_actions(store).count("gate.voted") == 49


def test_G5_a_quorum_just_above_the_approvers_stays_open_and_every_vote_commits(
    make_store: Callable[[], Store],
) -> None:
    store, results = _contend(make_store, people=40, quorum=41, seed=7)
    assert [r for _, r in results.values() if isinstance(r, Exception)] == []
    assert gate_of(store).is_open
    assert len(items(store, "VOTE#")) == 40


def test_a_lost_race_waits_before_it_reads_again() -> None:
    """The head-moved ``continue`` and the ConditionFailed retry both back off now."""
    slept: list[float] = []
    store = Recording()
    names = ["iss|a", "iss|b"]
    svc = _service(store, 2, names, Backoff(rng=lambda: 1.0, sleep=slept.append))
    gate = svc.open_gate(TEAM, open_cmd())
    real = store.transact
    fired: list[int] = []

    def racing(scope: Any, ops: Any) -> None:
        if not fired:
            fired.append(1)
            other = _service(store, 2, names, Backoff(sleep=lambda _: None))
            decide(other, APPROVE, "iss|b", gate=gate)  # commits inside a's window
        real(scope, ops)

    store.transact = racing  # type: ignore[method-assign]
    result = decide(svc, APPROVE, "iss|a", gate=gate)
    assert result.closed
    assert slept, "the retry after a lost race must back off"


# --- the injection enumeration, from the state "A already voted" --------------------------------


def _start(store: Store) -> tuple[GateService, Any]:
    svc = GateService(store, policy=Policy([QuorumRule("reviewer", 2)], REVIEWERS))
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, APPROVE, A, gate=gate)  # A has voted; the gate is one approval short
    return svc, gate


def _voted_model(order: Sequence[str]) -> tuple[Any, ...]:
    store = Recording()
    svc, gate = _start(store)
    return _snapshot(store, {name: _event(name, store, svc, gate) for name in order})


def _voted_injected(
    make: Callable[[], Store], x: str, y: str, at: int
) -> tuple[bool, tuple[Any, ...]]:
    inner = make()
    store = Windowed(inner)
    _, gate = _start(inner)
    svc = GateService(store, policy=Policy([QuorumRule("reviewer", 2)], REVIEWERS))
    bare = GateService(inner, policy=Policy([QuorumRule("reviewer", 2)], REVIEWERS))
    outcomes: dict[str, str] = {}

    def inject() -> None:
        outcomes[y] = _event(y, inner, bare, gate)

    store.at, store.fire, store.armed = at, inject, True
    outcomes[x] = _event(x, store, svc, gate)
    store.armed = False
    if not store.fired:
        outcomes[y] = _event(y, inner, bare, gate)
    return store.fired, _snapshot(inner, outcomes)


def test_G3_every_decision_pair_is_serialisable_when_A_has_already_voted(
    make_store: Callable[[], Store],
) -> None:
    """The same enumeration as ``test_decisions``, started from "A voted": approving again is a
    ``DuplicateVoteError``, B's approval now closes, and a close races the veto, the subject move
    and the expiry. The close path runs inside every window."""
    checked, closes = 0, 0
    for x, y in itertools.permutations(EVENTS, 2):
        for at in range(1, 16):
            fired, got = _voted_injected(make_store, x, y, at)
            if not fired:
                break
            # A repeat approval has two legal orders: it is refused on the state it read, so it
            # gets DuplicateVoteError before B's close and GateClosedError after it.
            allowed = [_voted_model((y, x))]
            if x == "approve A":
                allowed.append(_voted_model((x, y)))
            assert got in allowed, f"{y} injected at call {at} of {x}"
            checked += 1
            closes += got[0] is GateStatus.APPROVED
        else:
            raise AssertionError("an event made more than 15 store calls: raise the bound")
        fired, got = _voted_injected(make_store, x, y, 99)
        assert not fired
        assert got == _voted_model((x, y)), f"{x} then {y}"
    assert checked >= 80
    assert closes > 0  # the enumeration reaches an approved close, not only votes


# --- an answer lost after the write landed --------------------------------------------------------


class LosesTheAnswer(Recording):
    """Commits the n-th transaction, then raises ``TransactionOutcomeUnknownError`` (or raises
    before committing when ``lands`` is false)."""

    def __init__(self, lands: bool) -> None:
        super().__init__()
        self.lands, self.armed = lands, False

    def transact(self, scope: Scope, ops: Any) -> None:
        if not self.armed:
            return super().transact(scope, ops)
        self.armed = False
        if self.lands:
            super().transact(scope, ops)
        raise TransactionOutcomeUnknownError("the answer was lost")


@pytest.mark.parametrize("lands", [True, False])
@pytest.mark.parametrize("closing", [False, True])
def test_a_decision_whose_write_landed_does_not_return_409_for_the_persons_own_vote(
    lands: bool, closing: bool
) -> None:
    store = LosesTheAnswer(lands)
    names = [A, B]
    svc = _service(store, 2, names, Backoff(sleep=lambda _: None))
    gate = svc.open_gate(TEAM, open_cmd())
    if closing:
        decide(svc, APPROVE, A, gate=gate)
    store.armed = True
    who = B if closing else A
    result = decide(svc, APPROVE, who, gate=gate)  # no DuplicateVoteError, no GateClosedError
    assert result.closed is closing
    assert gate_of(store).status is (GateStatus.APPROVED if closing else GateStatus.OPEN)
    assert len(items(store, "VOTE#")) == 1
    assert audit_actions(store).count("gate.decided") == (1 if closing else 0)
    assert audit_actions(store).count("gate.voted") == 1  # A's vote once, never twice
    assert verify_audit_chain(store, TEAM, RUN) >= 2
