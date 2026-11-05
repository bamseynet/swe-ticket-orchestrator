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

from sto.domain import DecisionKind, GateStatus
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
    snapshot = _snapshot(inner, outcomes)
    close = getattr(inner, "close", None)
    if close is not None:
        close()  # ~100 open SQLite/WAL stores can exhaust memory ("disk I/O error")
    return store.fired, snapshot


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


# --- a write that lands late, and the waits on every retry path ---------------------------------


class LandsLate(Recording):
    """The armed transaction times out ("may or may not have landed") and really commits later,
    when the service sleeps (as a DynamoDB request still in flight does)."""

    def __init__(self) -> None:
        super().__init__()
        self.armed = False
        self.pending: tuple[Scope, tuple[Any, ...]] | None = None

    def transact(self, scope: Scope, ops: Any) -> None:
        if self.armed:
            self.armed = False
            self.pending = (scope, tuple(ops))
            raise TransactionOutcomeUnknownError("timed out; still in flight")
        super().transact(scope, ops)

    def land(self, _delay: float) -> None:  # the injected sleep
        if self.pending is not None:
            scope, ops = self.pending
            self.pending = None
            super().transact(scope, ops)


@pytest.mark.parametrize("closing", [False, True])
def test_a_write_that_lands_after_the_reconcile_read_is_still_the_persons_own(
    closing: bool,
) -> None:
    store = LandsLate()
    svc = _service(store, 2, [A, B], Backoff(sleep=store.land))
    gate = svc.open_gate(TEAM, open_cmd())
    if closing:
        decide(svc, APPROVE, A, gate=gate)
    store.armed = True
    who = B if closing else A
    result = decide(svc, APPROVE, who, gate=gate)  # not DuplicateVoteError / GateClosedError
    assert result.decision.actor == who
    assert result.closed is closing
    assert gate_of(store).status is (GateStatus.APPROVED if closing else GateStatus.OPEN)
    assert len(items(store, "VOTE#")) == 1
    assert audit_actions(store).count("gate.voted") == 1
    assert audit_actions(store).count("gate.decided") == (1 if closing else 0)
    assert verify_audit_chain(store, TEAM, RUN) >= 2


def test_an_unknown_outcome_that_did_not_land_is_not_success_over_an_older_stale_vote() -> None:
    """A already holds a vote for a subject that has since moved. A's new approval times out and
    does NOT land: the stale vote has another decision id, so it is not A's new decision."""
    from dataclasses import replace

    from sto.domain import Gate, from_wire, to_wire
    from sto.store.ports import Key, Put, VersionIs

    store = LandsLate()
    svc = _service(store, 3, [A, B, "iss|c"], Backoff(sleep=lambda _: None))
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, APPROVE, A, gate=gate)
    item = store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1"))
    assert item is not None
    from test_decisions import subject

    moved = replace(from_wire(Gate, item.data), subject=subject("b"))
    store.transact(TEAM, [Put(item.key, to_wire(moved), VersionIs(item.version))])
    store.armed = True  # A's second approval: outcome unknown, nothing lands
    result = decide(svc, APPROVE, A, digest=moved.subject.digest(), gate=moved)
    assert result.decision.subject_digest == moved.subject.digest()
    assert not result.closed
    votes = items(store, "VOTE#")
    assert len(votes) == 1  # the retry committed the replacement vote exactly once
    assert audit_actions(store).count("gate.voted") == 2


def _recording_service(
    store: Store, quorum: int, people: list[str]
) -> tuple[GateService, list[float]]:
    slept: list[float] = []
    return _service(store, quorum, people, Backoff(rng=lambda: 1.0, sleep=slept.append)), slept


def test_a_head_moved_recount_waits_before_it_reads_again() -> None:
    """A decision commits while A counts: the head-moved ``continue`` backs off."""

    class Inject(Recording):
        hook: Callable[[], None] | None = None

        def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
            page = super().query(scope, pk, **kw)
            if kw.get("sk_prefix", "").startswith("VOTE#") and self.hook:
                hook, self.hook = self.hook, None
                hook()
            return page

    store = Inject()
    names = [A, B, "iss|c"]
    svc, slept = _recording_service(store, 3, names)
    gate = svc.open_gate(TEAM, open_cmd())
    other = _service(store, 3, names, Backoff(sleep=lambda _: None))
    store.hook = lambda: decide(other, APPROVE, B, gate=gate)
    result = decide(svc, APPROVE, A, gate=gate)
    assert not result.closed
    assert len(items(store, "VOTE#")) == 2
    assert slept == [0.002]  # exactly the one wait, after the head moved


def _bump_gate_version(store: Store) -> None:
    """A timer's write to the open gate: same content, new version (the close loses its check)."""
    from sto.store.ports import Key, Put, VersionIs

    item = store.get(TEAM, Key(f"RUN#{RUN}", "GATE#review#1"))
    assert item is not None
    store.transact(TEAM, [Put(item.key, item.data, VersionIs(item.version))])


def test_a_close_that_loses_its_condition_waits_before_it_reads_again() -> None:
    store = Recording()
    svc, slept = _recording_service(store, 2, [A, B])
    gate = svc.open_gate(TEAM, open_cmd())
    decide(svc, APPROVE, A, gate=gate)
    real = store.transact
    fired: list[int] = []

    def racing(scope: Any, ops: Any) -> None:
        if not fired:
            fired.append(1)
            _bump_gate_version(store)
        real(scope, ops)

    store.transact = racing  # type: ignore[method-assign]
    assert decide(svc, APPROVE, B, gate=gate).closed
    assert slept == [0.002]


def test_a_close_that_finds_the_rounds_it_voids_changed_waits() -> None:
    from dataclasses import replace

    class Flip(Recording):
        """The confirming re-read of the earlier rounds shows an approved round 1 that the first
        read did not (as if it were approved meanwhile)."""

        armed = False
        reads = 0

        def query(self, scope: Scope, pk: str, **kw: Any) -> Any:
            page = super().query(scope, pk, **kw)
            if not (self.armed and kw.get("sk_prefix", "").startswith("GATE#")):
                return page
            self.reads += 1
            if self.reads != 3:  # attempt 0: stale-round check, first read, confirming re-read
                return page
            template = page.items[0]
            data = {**template.data, "round": 1, "status": "APPROVED"}
            return replace(page, items=(*page.items, replace(template, data=data)))

    store = Flip()
    svc, slept = _recording_service(store, 1, [A])
    gate = svc.open_gate(TEAM, open_cmd(round=2))
    store.armed = True
    decide(svc, DecisionKind.REJECT, A, gate=gate, round=2)
    assert slept == [0.002]


def test_no_sleep_follows_the_final_attempt() -> None:
    slept: list[float] = []
    b = Backoff(attempts=3, sleep=slept.append, rng=lambda: 1.0)
    for attempt in range(3):
        b.wait(attempt)
    assert len(slept) == 2  # nothing to wait for after the last try
