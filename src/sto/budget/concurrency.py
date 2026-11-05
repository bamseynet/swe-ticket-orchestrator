"""Concurrency leases (D10-05): a lease semaphore per team and per org, used at dispatch.

Lambda reserved concurrency is not used for this. A run takes one slot at the team level and one at
the org level, in one transaction, so both limits hold together or neither is taken.

Storage (through the store port only, so memory, SQLite and DynamoDB agree): one row per level,
``TEAM#t / TEAM:CONC`` for the team and ``ORG / CONC`` for the org, each holding
``{"holders": {run_id: {"token": ..., "exp": ...}}}``. Every write is a conditional ``Put``
(``Absent`` to create, ``VersionIs`` after that), so two racing acquirers cannot both read
"one slot free" and both write: the second write fails its condition, re-reads and retries.

Rules:

* **Fail closed.** At the limit, ``acquire`` returns ``Denied`` and writes nothing. Running out of
  retries under contention is also ``Denied("contended")``, never an admission. A failing store
  propagates; nothing is swallowed.
* **Expiry from an injected clock.** A lease lives ``ttl_s`` seconds from the moment it was taken
  or last extended, and is dead at ``expires_at`` exactly. Nothing here reads the wall clock
  except the default argument. A crashed holder never releases, so its slot comes back at expiry
  and the next write prunes the row.
* **Ownership by token.** A lease carries a random token. ``extend`` and ``release`` act only on
  the row entry with that token, so a holder whose lease expired (and whose slot was reissued, even
  to the same run) can neither extend nor release the new holder's lease. An expired lease cannot
  be extended, even if nobody has taken the slot yet.
* **Idempotent.** Acquiring again for a run that holds a live lease returns that lease (a redelivery
  takes no second slot). Releasing twice is a no-op that returns ``False``.

Queued runs: ``admit_queued`` starts runs from the head of a queue while slots are free and stops at
the first denial (no queue-jumping), so a run that was queued starts when a slot frees. Wiring it to
the dispatcher is the dispatcher's job. ``run_bounded`` bounds how many drives (and startup
redeliveries, which are sequential today) run at once.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Final, Literal

from sto.store.ports import (
    PLATFORM,
    Absent,
    Condition,
    ConditionFailedError,
    Item,
    Key,
    Put,
    Store,
    TeamScope,
    VersionIs,
)

# A row holds one entry per holder, about 100 bytes each, and rows are pruned on every write, so
# this keeps a row far below the item size limit.
MAX_LIMIT: Final = 1000
DEFAULT_TTL_S: Final = 900.0
DEFAULT_ATTEMPTS: Final = 8

TEAM_KEY: Final = Key("TEAM", "CONC")
ORG_KEY: Final = Key("ORG", "CONC")


def _check_limit(name: str, value: object) -> None:
    if type(value) is not int or not 0 <= value <= MAX_LIMIT:
        raise ValueError(f"{name} limit must be an int from 0 to {MAX_LIMIT}")


@dataclass(frozen=True)
class ConcurrencyLimits:
    team: int
    org: int

    def __post_init__(self) -> None:
        _check_limit("team", self.team)
        _check_limit("org", self.org)


@dataclass(frozen=True)
class Lease:
    team: str
    run_id: str
    token: str
    expires_at: float


@dataclass(frozen=True)
class Denied:
    """No slot. An expected result, not an error: the run stays queued."""

    reason: Literal["team_limit", "org_limit", "contended"]


def _check_name(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-blank string without surrounding whitespace")
    return value


@dataclass
class _Row:
    """One level's row as read: the live holders at ``now`` and the version to condition on."""

    holders: dict[str, dict[str, Any]]
    version: int | None


def _read(store: Store, scope: Any, key: Key, now: float) -> _Row:
    item: Item | None = store.get(scope, key)
    if item is None:
        return _Row({}, None)
    raw = item.data.get("holders", {})
    live = {r: dict(h) for r, h in raw.items() if h["exp"] > now}
    return _Row(live, item.version)


class ConcurrencyLeases:
    def __init__(
        self,
        store: Store,
        *,
        clock: Callable[[], float] = time.time,
        ttl_s: float = DEFAULT_TTL_S,
        new_token: Callable[[], str] = lambda: secrets.token_hex(16),
        max_attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        if not ttl_s > 0:
            raise ValueError("ttl_s must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._store = store
        self._clock = clock
        self._ttl = float(ttl_s)
        self._new_token = new_token
        self._attempts = max_attempts

    # --- reads --------------------------------------------------------------------------------

    def active(self, team: str) -> int:
        """Live leases of a team right now."""
        return len(
            _read(
                self._store, TeamScope(_check_name("team", team)), TEAM_KEY, self._clock()
            ).holders
        )

    def active_org(self) -> int:
        return len(_read(self._store, PLATFORM, ORG_KEY, self._clock()).holders)

    # --- writes -------------------------------------------------------------------------------

    def _commit(self, team: str, team_row: _Row, org_row: _Row) -> None:
        """Write both rows in one transaction, each conditioned on the version that was read."""

        def put(key: Key, row: _Row, platform: bool) -> Put:
            when: Condition = Absent() if row.version is None else VersionIs(row.version)
            return Put(
                key, {"holders": row.holders}, when=when, scope=PLATFORM if platform else None
            )

        self._store.transact(
            TeamScope(team), [put(TEAM_KEY, team_row, False), put(ORG_KEY, org_row, True)]
        )

    def _read_both(self, team: str, now: float) -> tuple[_Row, _Row]:
        return (
            _read(self._store, TeamScope(team), TEAM_KEY, now),
            _read(self._store, PLATFORM, ORG_KEY, now),
        )

    def acquire(self, team: str, run_id: str, limits: ConcurrencyLimits) -> Lease | Denied:
        _check_name("team", team)
        _check_name("run_id", run_id)
        TeamScope(team)  # refuses a '#' or control characters
        for _ in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(team, now)
            mine, theirs = team_row.holders.get(run_id), org_row.holders.get(f"{team}#{run_id}")
            if mine is not None and theirs is not None and mine["token"] == theirs["token"]:
                return Lease(team, run_id, mine["token"], mine["exp"])
            # A half-held run (one level lost, say to a crash between versions of this code) is
            # treated as not held: its remains do not count against the limits.
            team_row.holders.pop(run_id, None)
            org_row.holders.pop(f"{team}#{run_id}", None)
            if len(team_row.holders) >= limits.team:
                return Denied("team_limit")
            if len(org_row.holders) >= limits.org:
                return Denied("org_limit")
            token, exp = self._new_token(), now + self._ttl
            entry = {"token": token, "exp": exp}
            team_row.holders[run_id] = entry
            org_row.holders[f"{team}#{run_id}"] = dict(entry)
            try:
                self._commit(team, team_row, org_row)
            except ConditionFailedError:
                continue  # someone else wrote first: re-read and decide again
            return Lease(team, run_id, token, exp)
        return Denied("contended")

    def extend(self, lease: Lease) -> Lease | None:
        """Push the expiry out. ``None`` means the lease is lost (expired, released or not ours)."""
        _check_name("team", lease.team)
        for _ in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(lease.team, now)
            org_id = f"{lease.team}#{lease.run_id}"
            mine, theirs = team_row.holders.get(lease.run_id), org_row.holders.get(org_id)
            if mine is None or theirs is None:
                return None
            if mine["token"] != lease.token or theirs["token"] != lease.token:
                return None
            exp = now + self._ttl
            mine["exp"] = theirs["exp"] = exp
            try:
                self._commit(lease.team, team_row, org_row)
            except ConditionFailedError:
                continue
            return Lease(lease.team, lease.run_id, lease.token, exp)
        return None  # could not confirm: the caller must treat the lease as lost

    def release(self, lease: Lease) -> bool:
        """Give the slot back. ``True`` if this call freed it, ``False`` if there was nothing of
        this lease to free (already released, expired and reissued, or a wrong token)."""
        _check_name("team", lease.team)
        for _ in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(lease.team, now)
            org_id = f"{lease.team}#{lease.run_id}"
            freed = False
            held = team_row.holders.get(lease.run_id)
            if held is not None and held["token"] == lease.token:
                del team_row.holders[lease.run_id]
                freed = True
            held = org_row.holders.get(org_id)
            if held is not None and held["token"] == lease.token:
                del org_row.holders[org_id]
                freed = True
            if not freed:
                return False
            try:
                self._commit(lease.team, team_row, org_row)
            except ConditionFailedError:
                continue
            return True
        raise ConditionFailedError([0])  # contention outlasted the retries: surface, do not guess


def admit_queued(
    leases: ConcurrencyLeases, team: str, queued: Sequence[str], limits: ConcurrencyLimits
) -> tuple[list[Lease], list[str]]:
    """Start queued runs, oldest first, while slots are free. Returns the leases taken and the
    runs still waiting. It stops at the first denial, so a later run never starts before an
    earlier one. A denied run stays queued, not failed."""
    started: list[Lease] = []
    for i, run_id in enumerate(queued):
        got = leases.acquire(team, run_id, limits)
        if isinstance(got, Denied):
            return started, list(queued[i:])
        started.append(got)
    return started, []


def run_bounded[T, R](
    items: Iterable[T], fn: Callable[[T], R], *, max_concurrency: int
) -> list[R | Exception]:
    """Call ``fn`` on every item with at most ``max_concurrency`` running at once, for the drives
    and the startup redelivery. Results keep the item order; an exception from one item is
    returned in its place and does not stop the others."""
    if type(max_concurrency) is not int or max_concurrency < 1:
        raise ValueError("max_concurrency must be an int of at least 1")
    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        futures = [pool.submit(fn, item) for item in items]
        out: list[R | Exception] = []
        for f in futures:
            err = f.exception()
            out.append(err if isinstance(err, Exception) else f.result())
        return out
