"""Concurrency leases (D10-05): a limit holds, a crashed holder's lease expires, a queued run
starts when a slot frees. Run on the memory and SQLite stores through the port, with the clock
injected and the interleavings of racing acquirers enumerated, not sampled."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Sequence
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from sto.budget.concurrency import (
    MAX_LIMIT,
    ORG_KEY,
    TEAM_KEY,
    ConcurrencyLeases,
    ConcurrencyLimits,
    Denied,
    Lease,
    admit_queued,
    run_bounded,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    PLATFORM,
    Condition,
    ConditionFailedError,
    Item,
    Key,
    Op,
    Page,
    Scope,
    Store,
    TeamScope,
)
from sto.store.sqlite import SqliteStore

TTL = 100.0


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Store]:
    if request.param == "memory":
        yield MemoryStore()
    else:
        s = SqliteStore(tmp_path / "c.db")
        yield s
        s.close()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make(store: Store, clock: FakeClock, **kw: Any) -> ConcurrencyLeases:
    counter = iter(range(10_000))
    return ConcurrencyLeases(
        store, clock=clock, ttl_s=TTL, new_token=lambda: f"tok{next(counter)}", **kw
    )


def lease_of(result: Lease | Denied) -> Lease:
    assert isinstance(result, Lease), result
    return result


# --- limits -----------------------------------------------------------------------------------


def test_team_limit_holds_and_denies_the_next(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=2, org=10)
    lease_of(leases.acquire("a", "r1", lim))
    lease_of(leases.acquire("a", "r2", lim))
    assert leases.acquire("a", "r3", lim) == Denied("team_limit")
    assert leases.active("a") == 2


def test_org_limit_spans_teams(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=5, org=2)
    lease_of(leases.acquire("a", "r1", lim))
    lease_of(leases.acquire("b", "r2", lim))
    assert leases.acquire("c", "r3", lim) == Denied("org_limit")
    assert leases.active("c") == 0
    assert leases.active_org() == 2


def test_a_denial_takes_nothing_from_the_other_level(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lease_of(leases.acquire("a", "r1", ConcurrencyLimits(team=1, org=5)))
    assert leases.acquire("a", "r2", ConcurrencyLimits(team=1, org=5)) == Denied("team_limit")
    assert leases.active_org() == 1


def test_limit_zero_admits_nothing(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    assert leases.acquire("a", "r1", ConcurrencyLimits(team=0, org=5)) == Denied("team_limit")
    assert leases.acquire("a", "r1", ConcurrencyLimits(team=5, org=0)) == Denied("org_limit")


def test_lowering_a_limit_denies_until_holders_drain(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    held = [lease_of(leases.acquire("a", f"r{i}", ConcurrencyLimits(3, 9))) for i in range(3)]
    low = ConcurrencyLimits(team=1, org=9)
    assert leases.acquire("a", "new", low) == Denied("team_limit")
    leases.release(held[0])
    leases.release(held[1])
    assert leases.acquire("a", "new", low) == Denied("team_limit")
    leases.release(held[2])
    lease_of(leases.acquire("a", "new", low))


@pytest.mark.parametrize(
    ("team", "org"), [(-1, 1), (1, -1), (MAX_LIMIT + 1, 1), (1, MAX_LIMIT + 1)]
)
def test_limits_out_of_range_are_refused(team: int, org: int) -> None:
    with pytest.raises(ValueError, match="."):
        ConcurrencyLimits(team=team, org=org)


def test_limits_must_be_real_ints() -> None:
    with pytest.raises(ValueError, match="."):
        ConcurrencyLimits(team=True, org=1)  # bool is an int
    with pytest.raises(ValueError, match="."):
        ConcurrencyLimits(team=1.5, org=1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("team", "run"), [("", "r"), (" ", "r"), ("a", ""), ("a", " "), ("a#b", "r")]
)
def test_blank_identities_are_refused(store: Store, clock: FakeClock, team: str, run: str) -> None:
    with pytest.raises(ValueError, match="."):
        make(store, clock).acquire(team, run, ConcurrencyLimits(1, 1))


# --- idempotence ------------------------------------------------------------------------------


def test_reacquiring_a_held_run_returns_the_same_lease(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    first = lease_of(leases.acquire("a", "r1", lim))
    assert leases.acquire("a", "r1", lim) == first  # redelivery does not take a second slot
    assert leases.active("a") == 1


def test_release_is_idempotent(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    lease = lease_of(leases.acquire("a", "r1", lim))
    assert leases.release(lease) is True
    assert leases.release(lease) is False
    assert leases.active("a") == 0
    assert leases.active_org() == 0
    lease_of(leases.acquire("a", "r2", lim))


# --- expiry -----------------------------------------------------------------------------------


def test_crashed_holders_lease_expires(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    lease_of(leases.acquire("a", "crashed", lim))
    assert leases.acquire("a", "next", lim) == Denied("team_limit")
    clock.now += TTL - 1
    assert leases.acquire("a", "next", lim) == Denied("team_limit")
    clock.now += 1  # exactly at expiry: the slot is free
    lease_of(leases.acquire("a", "next", lim))
    assert leases.active("a") == 1


def test_extend_keeps_a_live_lease_alive(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    lease = lease_of(leases.acquire("a", "r1", lim))
    clock.now += TTL - 1
    lease = leases.extend(lease)  # type: ignore[assignment]
    assert lease is not None
    assert lease.expires_at == clock.now + TTL
    clock.now += TTL - 1
    assert leases.acquire("a", "r2", lim) == Denied("team_limit")


def test_expired_holder_cannot_extend(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    old = lease_of(leases.acquire("a", "r1", lim))
    clock.now += TTL
    assert leases.extend(old) is None  # even though nobody took the slot yet
    assert leases.active("a") == 0


def test_expired_holder_cannot_extend_or_release_a_successors_lease(
    store: Store, clock: FakeClock
) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    old = lease_of(leases.acquire("a", "r1", lim))
    clock.now += TTL
    new = lease_of(leases.acquire("a", "r2", lim))
    assert leases.extend(old) is None
    assert leases.release(old) is False
    assert leases.active("a") == 1
    assert leases.acquire("a", "r3", lim) == Denied("team_limit")
    assert leases.release(new) is True


def test_same_run_after_expiry_gets_a_new_token_and_the_old_one_is_dead(
    store: Store, clock: FakeClock
) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    old = lease_of(leases.acquire("a", "r1", lim))
    clock.now += TTL
    new = lease_of(leases.acquire("a", "r1", lim))
    assert new.token != old.token
    assert leases.release(old) is False
    assert leases.extend(old) is None
    assert leases.active("a") == 1


def test_forged_lease_cannot_release_or_extend(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=1, org=1)
    real = lease_of(leases.acquire("a", "r1", lim))
    forged = Lease(team="a", run_id="r1", token="guess", expires_at=real.expires_at)
    assert leases.release(forged) is False
    assert leases.extend(forged) is None
    assert leases.active("a") == 1


def test_expiry_frees_the_org_slot_too(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=5, org=1)
    lease_of(leases.acquire("a", "r1", lim))
    clock.now += TTL
    lease_of(leases.acquire("b", "r2", lim))


# --- store failures and contention fail closed ------------------------------------------------


class ConflictingStore:
    """Every transaction loses its race."""

    def __init__(self, inner: Store) -> None:
        self.inner = inner
        self.transacts = 0

    def get(self, scope: Scope, key: Key) -> Item | None:
        return self.inner.get(scope, key)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        self.transacts += 1
        raise ConditionFailedError([0])

    def query(self, *a: Any, **k: Any) -> Page:  # pragma: no cover
        return self.inner.query(*a, **k)

    def put(self, *a: Any, **k: Any) -> None:  # pragma: no cover
        raise AssertionError("every write goes through transact")

    def delete(self, *a: Any, **k: Any) -> None:  # pragma: no cover
        raise AssertionError("every write goes through transact")


def test_persistent_contention_denies_after_bounded_retries(store: Store, clock: FakeClock) -> None:
    flaky = ConflictingStore(store)
    leases = make(flaky, clock, max_attempts=3)
    assert leases.acquire("a", "r1", ConcurrencyLimits(5, 5)) == Denied("contended")
    assert flaky.transacts == 3


def test_a_dead_store_propagates_rather_than_admitting(clock: FakeClock) -> None:
    class Down(ConflictingStore):
        def get(self, scope: Scope, key: Key) -> Item | None:
            raise ConnectionError("store down")

    leases = make(Down(MemoryStore()), clock)
    with pytest.raises(ConnectionError):
        leases.acquire("a", "r1", ConcurrencyLimits(5, 5))


def test_writes_use_conditional_transactions_only(store: Store, clock: FakeClock) -> None:
    seen: list[Sequence[Op]] = []

    class Spy(ConflictingStore):
        def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
            seen.append(ops)
            self.inner.transact(scope, ops)

    leases = make(Spy(store), clock)
    lease = lease_of(leases.acquire("a", "r1", ConcurrencyLimits(5, 5)))
    leases.extend(lease)
    leases.release(lease)
    assert seen
    for ops in seen:
        assert {type(o).__name__ for o in ops} == {"Put"}
        conds: list[Condition | None] = [o.when for o in ops]
        assert all(c is not None for c in conds)
    # the org row is written in the same transaction as the team row
    assert all(len(ops) == 2 for ops in seen)


# --- queue and bounded drives -----------------------------------------------------------------


def test_queued_runs_start_in_order_when_a_slot_frees(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    lim = ConcurrencyLimits(team=2, org=9)
    queue = ["q1", "q2", "q3"]
    started, waiting = admit_queued(leases, "a", queue, lim)
    assert [lease.run_id for lease in started] == ["q1", "q2"]
    assert waiting == ["q3"]  # stays queued, not failed
    again, waiting = admit_queued(leases, "a", waiting, lim)
    assert again == []
    assert waiting == ["q3"]
    leases.release(started[0])
    started3, waiting = admit_queued(leases, "a", waiting, lim)
    assert [lease.run_id for lease in started3] == ["q3"]
    assert waiting == []


def test_admit_queued_does_not_skip_the_head_of_the_queue(store: Store, clock: FakeClock) -> None:
    leases = make(store, clock)
    # org is full, so nothing from any later entry may jump ahead of the first denied one
    lease_of(leases.acquire("z", "other", ConcurrencyLimits(5, 1)))
    started, waiting = admit_queued(leases, "a", ["q1", "q2"], ConcurrencyLimits(5, 1))
    assert started == []
    assert waiting == ["q1", "q2"]


def test_run_bounded_never_exceeds_the_bound() -> None:
    lock = threading.Lock()
    live = peak = 0
    gate = threading.Barrier(3, timeout=5)

    def work(item: int) -> int:
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        if item < 3:
            gate.wait()  # the first three must overlap, proving real parallelism
        with lock:
            live -= 1
        return item * 2

    results = run_bounded(range(8), work, max_concurrency=3)
    assert peak == 3
    assert results == [i * 2 for i in range(8)]


def test_run_bounded_one_failure_does_not_stop_the_rest() -> None:
    def work(item: int) -> int:
        if item == 1:
            raise RuntimeError("boom")
        return item

    results = run_bounded([0, 1, 2], work, max_concurrency=2)
    assert results[0] == 0
    assert results[2] == 2
    assert isinstance(results[1], RuntimeError)


def test_run_bounded_rejects_a_bad_bound() -> None:
    with pytest.raises(ValueError, match="."):
        run_bounded([1], lambda x: x, max_concurrency=0)


# --- the invariant under enumerated interleavings ---------------------------------------------


class Scheduler:
    """Runs actors in threads but lets only one store call proceed at a time, in an order the
    test chooses. ``explore`` replays the scenario for every order of those steps (depth-first),
    so the check covers all interleavings, not the ones a thread scheduler happens to give."""

    def __init__(self, script: list[int]) -> None:
        self.script = script
        self.trace: list[int] = []  # branching factor at each decision
        self.cv = threading.Condition()
        self.waiting: set[int] = set()
        self.granted: int | None = None
        self.done: set[int] = set()

    def step(self, actor: int) -> None:
        with self.cv:
            self.waiting.add(actor)
            self.cv.notify_all()
            while self.granted != actor:
                self.cv.wait(timeout=10)
            self.granted = None
            self.waiting.discard(actor)

    def finish(self, actor: int) -> None:
        with self.cv:
            self.done.add(actor)
            self.cv.notify_all()

    def run(self, actors: list[Callable[[], object]], observe: Callable[[], None]) -> None:
        def body(i: int) -> None:
            try:
                actors[i]()
            finally:
                self.finish(i)

        threads = [threading.Thread(target=body, args=(i,)) for i in range(len(actors))]
        for t in threads:
            t.start()
        n = len(actors)
        pos = 0
        while True:
            with self.cv:
                # quiescent: every actor is blocked at a store call or finished
                while len(self.waiting) + len(self.done) < n:
                    assert self.cv.wait(timeout=10), "scheduler stalled"
                if not self.waiting:
                    break
                choices = sorted(self.waiting)
                pick = self.script[pos] if pos < len(self.script) else 0
                self.trace.append(len(choices))
                pos += 1
                self.granted = choices[pick]
                self.cv.notify_all()
                while self.granted is not None:
                    self.cv.wait(timeout=10)
            # the granted actor now runs its store call; wait for it to block again or finish
            with self.cv:
                while len(self.waiting) + len(self.done) < n:
                    assert self.cv.wait(timeout=10), "scheduler stalled"
            observe()
        for t in threads:
            t.join(timeout=10)


class SteppedStore:
    def __init__(self, inner: Store, sched: Scheduler, actor: int) -> None:
        self.inner, self.sched, self.actor = inner, sched, actor

    def get(self, scope: Scope, key: Key) -> Item | None:
        self.sched.step(self.actor)
        return self.inner.get(scope, key)

    def transact(self, scope: Scope, ops: Sequence[Op]) -> None:
        self.sched.step(self.actor)
        self.inner.transact(scope, ops)


def explore(
    fresh_store: Callable[[], Store],
    scenario: Callable[[Store, Callable[[int], Store]], list[Callable[[], object]]],
    observe: Callable[[Store], None],
    final: Callable[[], None],
) -> int:
    """Replay ``scenario`` once per interleaving of store calls; return how many were run.
    ``observe`` runs after every store call, ``final`` after each replay finishes."""
    runs = 0
    stack: list[list[int]] = [[]]
    while stack:
        script = stack.pop()
        inner = fresh_store()
        sched = Scheduler(script)
        actors = scenario(inner, partial(_stepped, inner, sched))
        sched.run(actors, partial(observe, inner))
        observe(inner)
        final()
        runs += 1
        assert runs < 20_000, "interleaving tree larger than expected"
        # expand: for each decision beyond the script, queue its alternatives
        for pos in range(len(script), len(sched.trace)):
            for alt in range(1, sched.trace[pos]):
                stack.append([*script, *([0] * (pos - len(script))), alt])
    return runs


def _stepped(inner: Store, sched: Scheduler, actor: int) -> Store:
    return SteppedStore(inner, sched, actor)  # type: ignore[return-value]


def active_counts(inner: Store, clock: FakeClock, teams: Sequence[str]) -> tuple[int, int]:
    leases = ConcurrencyLeases(inner, clock=clock, ttl_s=TTL)
    return sum(leases.active(t) for t in teams), leases.active_org()


@pytest.fixture(params=["memory", "sqlite"])
def fresh_store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Callable[[], Store]]:
    # One SQLite file for the whole enumeration, emptied between replays through the port:
    # creating a file per schedule would dominate the run time.
    db = SqliteStore(tmp_path / "enum.db") if request.param == "sqlite" else None
    if db is not None:
        # Durability is not what is under test and an fsync per commit makes ~1,700 replays take
        # minutes; the conditional-write semantics are the same.
        with db._lock:
            db._conn.execute("PRAGMA synchronous=OFF")

    def make_store() -> Store:
        if db is None:
            return MemoryStore()
        # delete only rows that exist: a commit is the expensive part on SQLite
        for scope, key in (
            (TeamScope("a"), TEAM_KEY),
            (TeamScope("b"), TEAM_KEY),
            (PLATFORM, ORG_KEY),
        ):
            if db.get(scope, key) is not None:
                db.delete(scope, key)
        return db

    yield make_store
    if db is not None:
        db.close()


def test_limit_holds_over_every_interleaving_of_two_acquirers(
    fresh_store: Callable[[], Store],
) -> None:
    clock = FakeClock()
    lim = ConcurrencyLimits(team=1, org=1)
    results: dict[int, Lease | Denied] = {}

    def scenario(inner: Store, view: Callable[[int], Store]) -> list[Callable[[], object]]:
        results.clear()

        def actor(i: int) -> Callable[[], None]:
            leases = ConcurrencyLeases(view(i), clock=clock, ttl_s=TTL, max_attempts=3)

            def go() -> None:
                results[i] = leases.acquire("a", f"r{i}", lim)

            return go

        return [actor(0), actor(1)]

    def observe(inner: Store) -> None:
        team, org = active_counts(inner, clock, ["a"])
        assert team <= 1
        assert org <= 1

    def final() -> None:
        # a lost update would overwrite the row and hide a second winner from the row counts
        assert sum(isinstance(r, Lease) for r in results.values()) <= 1

    runs = explore(fresh_store, scenario, observe, final)
    assert runs > 10  # a real tree, not one lucky order


def test_limit_holds_over_every_interleaving_with_three_acquirers_across_two_teams(
    fresh_store: Callable[[], Store],
) -> None:
    clock = FakeClock()
    lim = ConcurrencyLimits(team=1, org=2)
    winners: list[int] = []

    def scenario(inner: Store, view: Callable[[int], Store]) -> list[Callable[[], object]]:
        winners.clear()
        teams = ["a", "a", "b"]

        def actor(i: int) -> Callable[[], None]:
            leases = ConcurrencyLeases(view(i), clock=clock, ttl_s=TTL, max_attempts=1)

            def go() -> None:
                if isinstance(leases.acquire(teams[i], f"r{i}", lim), Lease):
                    winners.append(i)

            return go

        return [actor(0), actor(1), actor(2)]

    def observe(inner: Store) -> None:
        leases = ConcurrencyLeases(inner, clock=clock, ttl_s=TTL)
        assert leases.active("a") <= 1
        assert leases.active("b") <= 1
        assert leases.active_org() <= 2

    def final() -> None:
        assert len([w for w in winners if w in (0, 1)]) <= 1  # team a has one slot
        assert len(winners) <= 2  # the org has two

    runs = explore(fresh_store, scenario, observe, final)
    assert runs > 50


def test_release_racing_acquire_never_overadmits(fresh_store: Callable[[], Store]) -> None:
    clock = FakeClock()
    lim = ConcurrencyLimits(team=1, org=1)
    holder_box: list[Lease] = []
    taken: dict[str, Lease | Denied] = {}

    def scenario(inner: Store, view: Callable[[int], Store]) -> list[Callable[[], object]]:
        holder_box.clear()
        taken.clear()
        holder_box.append(
            lease_of(ConcurrencyLeases(inner, clock=clock, ttl_s=TTL).acquire("a", "h", lim))
        )
        rel = ConcurrencyLeases(view(0), clock=clock, ttl_s=TTL, max_attempts=1)
        acq1 = ConcurrencyLeases(view(1), clock=clock, ttl_s=TTL, max_attempts=1)
        acq2 = ConcurrencyLeases(view(2), clock=clock, ttl_s=TTL, max_attempts=1)
        return [
            partial(rel.release, holder_box[0]),
            lambda: taken.update(x=acq1.acquire("a", "x", lim)),
            lambda: taken.update(y=acq2.acquire("a", "y", lim)),
        ]

    def observe(inner: Store) -> None:
        team, org = active_counts(inner, clock, ["a"])
        assert team <= 1
        assert org <= 1

    def final() -> None:
        assert sum(isinstance(r, Lease) for r in taken.values()) <= 1

    assert explore(fresh_store, scenario, observe, final) > 50


def test_real_threads_cannot_overadmit(store: Store, clock: FakeClock) -> None:
    lim = ConcurrencyLimits(team=3, org=3)
    barrier = threading.Barrier(12, timeout=10)
    won: list[str] = []
    lock = threading.Lock()

    def go(i: int) -> None:
        leases = ConcurrencyLeases(store, clock=clock, ttl_s=TTL, max_attempts=50)
        barrier.wait()
        if isinstance(leases.acquire("a", f"r{i}", lim), Lease):
            with lock:
                won.append(f"r{i}")

    threads = [threading.Thread(target=go, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(won) <= 3
    assert ConcurrencyLeases(store, clock=clock, ttl_s=TTL).active("a") == len(won)


def test_rows_are_where_the_spec_says(store: Store, clock: FakeClock) -> None:
    make(store, clock).acquire("a", "r1", ConcurrencyLimits(1, 1))
    assert store.get(TeamScope("a"), Key("TEAM", "CONC")) is not None
    assert store.get(PLATFORM, Key("ORG", "CONC")) is not None
