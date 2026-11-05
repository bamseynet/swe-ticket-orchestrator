"""Concurrency leases (D10-05): a lease semaphore per team and per org, used at dispatch.

Lambda reserved concurrency is not used for this. A run takes one slot at the team level and one at
the org level, in one transaction, so both limits hold together or neither is taken.

Storage (through the store port only, so memory, SQLite and DynamoDB agree): one row per level,
pk ``TEAM#t`` / sk ``CONC`` for the team and pk ``ORG`` / sk ``CONC`` for the org, each holding
``{"holders": {key: {"token": ..., "exp": ...}}}`` (key = run id in the team row, ``team#run`` in
the org row). Every write is a conditional ``Put`` (``Absent`` to create, ``VersionIs`` after
that), so two racing acquirers cannot both read "one slot free" and both write: the second write
fails its condition, re-reads and retries.

**Deviation from PLAN (section 11).** PLAN has one ``TEAM#t`` / ``SLOT#ulid`` item per lease, with a
TTL. Here a whole level is one row. Why: the limit check and the claim must be one atomic decision
over a count, and a single conditional write on one row gives that on every store with no scan, no
counter drift and no reliance on TTL deletion (DynamoDB TTL runs late, up to days; expiry here is
decided by the injected clock at read time). Cost: every write at a level rewrites the whole row.
Measured with ``estimate_item_bytes`` at the cap (``MAX_LIMIT`` = 1,000 holders): with a 16-char
team and ULID run ids the org row is 96 KB, which is 96 write units, doubled to 192 in a
transaction; with the longest ids allowed it is 277 KB (a test pins it under the 400 KB item
limit). One DynamoDB partition takes about 1,000 write units a second, so an org at the cap gets
about 5 lease writes a second (under 2 with the longest ids), shared by acquire, extend and
release; the cost falls in proportion to the number of holders. The conflict retries below absorb
bursts, but a fleet that heartbeats often should use a long ``ttl_s``.
A D12 follow-up should tune this or move to per-slot items.

Rules:

* **Fail closed.** At the limit, ``acquire`` returns ``Denied`` and writes nothing. Running out of
  retries under contention is also ``Denied("contended")``, never an admission. A failing store
  propagates; nothing is swallowed.
* **Expiry from an injected clock.** A lease lives ``ttl_s`` seconds from the moment it was taken
  or last extended, and is dead at ``expires_at`` exactly. Nothing here reads the wall clock
  except the default argument. A crashed holder never releases, so its slot comes back at expiry
  and the next write prunes the row. **Clock skew:** hosts compare ``expires_at`` against their own
  clocks, so a host whose clock runs ahead by more than a lease has left reclaims a live lease and
  the limit is exceeded for that time. Heartbeat (``extend``) with a margin well above the worst
  skew, for example every ``ttl_s / 3`` with ``ttl_s`` several times the skew bound.
* **Ownership by token.** A lease carries a random token. ``extend`` and ``release`` act only on
  the row entry with that token, so a holder whose lease expired (and whose slot was reissued, even
  to the same run) can neither extend nor release the new holder's lease. The token is not a
  monotonic fencing token: it protects the lease row only, and does not stop a stale holder from
  doing work elsewhere. A holder that cannot extend must stop. An expired lease cannot be
  extended, even if nobody has taken the slot yet.
* **Idempotent.** Acquiring again for a run that holds a live lease returns that lease (a redelivery
  takes no second slot). Releasing twice is a no-op that returns ``False``.
* **Transient conflicts retry.** A ``TransactionConflictError`` (DynamoDB cancels concurrent writes
  to the one row) is retried with jittered exponential backoff, from an injected ``sleep`` and
  ``rng``, as a lost condition is. If a write's outcome was unknown, the retry re-reads: an
  ``acquire`` that landed returns the lease it wrote, and a ``release`` that landed returns
  ``True``.
* **Exhausted retries.** ``acquire`` returns ``Denied("contended")``. ``release`` raises
  ``LeaseContentionError`` (the slot is still held until expiry). ``extend`` returns ``None``, which
  therefore means "lost *or could not be confirmed*": the lease may still be held, but the caller
  cannot rely on it and should stop and let it expire.

Queued runs: ``admit_queued`` starts runs from the head of a queue while slots are free and stops at
the first denial (no queue-jumping), so a run that was queued starts when a slot frees. Wiring it to
the dispatcher is the dispatcher's job. ``run_bounded`` bounds how many drives (and startup
redeliveries, which are sequential today) run at once.
"""

from __future__ import annotations

import math
import random
import secrets
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Final, Literal

from sto.domain.errors import TransientError
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
    TransactionConflictError,
    TransactionOutcomeUnknownError,
    VersionIs,
)

# Rows are pruned on every write and hold one entry per live holder. With these bounds an org row
# at the cap is 277 KB by DynamoDB's accounting (see the module docstring), under the 400 KB limit.
MAX_LIMIT: Final = 1000
MAX_ID_BYTES: Final = 128
MAX_TEAM_BYTES: Final = 100
DEFAULT_TTL_S: Final = 900.0
DEFAULT_ATTEMPTS: Final = 8
BACKOFF_BASE_S: Final = 0.005
BACKOFF_CAP_S: Final = 0.25

TEAM_KEY: Final = Key("TEAM", "CONC")
ORG_KEY: Final = Key("ORG", "CONC")


class LeaseContentionError(TransientError):
    """Retries ran out before a release could be confirmed. The slot is still held until it
    expires; the caller may try again."""


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


def _check_name(label: str, value: object, max_bytes: int) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-blank string without surrounding whitespace")
    if len(value.encode("utf-8", "surrogatepass")) > max_bytes:
        raise ValueError(f"{label} must be at most {max_bytes} bytes")
    return value


def _check_ids(team: str, run_id: str) -> None:
    _check_name("team", team, MAX_TEAM_BYTES)
    _check_name("run_id", run_id, MAX_ID_BYTES)
    TeamScope(team)  # refuses a '#' or control characters


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
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        if not (math.isfinite(ttl_s) and ttl_s > 0):
            raise ValueError("ttl_s must be a finite positive number")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._store = store
        self._clock = clock
        self._ttl = float(ttl_s)
        self._new_token = new_token
        self._attempts = max_attempts
        self._sleep = sleep
        self._rng = rng

    # --- reads --------------------------------------------------------------------------------

    def active(self, team: str) -> int:
        """Live leases of a team right now."""
        _check_name("team", team, MAX_TEAM_BYTES)
        row = _read(self._store, TeamScope(team), TEAM_KEY, self._clock())
        return len(row.holders)

    def active_org(self) -> int:
        return len(_read(self._store, PLATFORM, ORG_KEY, self._clock()).holders)

    def held(self, team: str, run_id: str) -> Lease | None:
        """The live lease this run holds at both levels, if any."""
        _check_ids(team, run_id)
        return self._held(*self._read_both(team, self._clock()), team, run_id)

    # --- internals ----------------------------------------------------------------------------

    @staticmethod
    def _held(team_row: _Row, org_row: _Row, team: str, run_id: str) -> Lease | None:
        mine, theirs = team_row.holders.get(run_id), org_row.holders.get(f"{team}#{run_id}")
        if mine is not None and theirs is not None and mine["token"] == theirs["token"]:
            return Lease(team, run_id, mine["token"], mine["exp"])
        return None

    def _pause(self, attempt: int) -> None:
        """Jittered exponential backoff after a transient conflict."""
        ceiling = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2**attempt)
        self._sleep(ceiling * (0.5 + self._rng() / 2))

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

    def _try_commit(self, team: str, team_row: _Row, org_row: _Row, attempt: int) -> str:
        """``"ok"`` if the write landed, ``"lost"`` if a condition failed, ``"conflict"`` after a
        transient conflict (already backed off), ``"unknown"`` if it may or may not have landed."""
        try:
            self._commit(team, team_row, org_row)
        except ConditionFailedError:
            return "lost"
        except TransactionOutcomeUnknownError:
            self._pause(attempt)
            return "unknown"
        except TransactionConflictError:
            self._pause(attempt)
            return "conflict"
        return "ok"

    # --- writes -------------------------------------------------------------------------------

    def acquire(self, team: str, run_id: str, limits: ConcurrencyLimits) -> Lease | Denied:
        got = self._acquire(team, run_id, limits)
        return got[0]

    def _acquire(
        self, team: str, run_id: str, limits: ConcurrencyLimits
    ) -> tuple[Lease | Denied, bool]:
        """The result and whether the run already held this lease before the call."""
        _check_ids(team, run_id)
        org_id = f"{team}#{run_id}"
        wrote = False  # a write of ours may have landed (outcome unknown)
        for attempt in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(team, now)
            existing = self._held(team_row, org_row, team, run_id)
            if existing is not None:
                return existing, not wrote
            # A half-held run (one level lost) is treated as not held: its remains do not count.
            team_row.holders.pop(run_id, None)
            org_row.holders.pop(org_id, None)
            if len(team_row.holders) >= limits.team:
                return Denied("team_limit"), False
            if len(org_row.holders) >= limits.org:
                return Denied("org_limit"), False
            token, exp = self._new_token(), now + self._ttl
            entry = {"token": token, "exp": exp}
            team_row.holders[run_id] = entry
            org_row.holders[org_id] = dict(entry)
            outcome = self._try_commit(team, team_row, org_row, attempt)
            if outcome == "ok":
                return Lease(team, run_id, token, exp), False
            wrote = wrote or outcome == "unknown"
        return Denied("contended"), False

    def extend(self, lease: Lease) -> Lease | None:
        """Push the expiry out. ``None`` means the caller must treat the lease as lost: it
        expired, was released, is not ours, or retries ran out before the write could be
        confirmed (then it may in fact still be held, until it expires)."""
        _check_ids(lease.team, lease.run_id)
        org_id = f"{lease.team}#{lease.run_id}"
        for attempt in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(lease.team, now)
            mine, theirs = team_row.holders.get(lease.run_id), org_row.holders.get(org_id)
            if mine is None or theirs is None:
                return None
            if mine["token"] != lease.token or theirs["token"] != lease.token:
                return None
            exp = now + self._ttl
            mine["exp"] = theirs["exp"] = exp
            if self._try_commit(lease.team, team_row, org_row, attempt) == "ok":
                return Lease(lease.team, lease.run_id, lease.token, exp)
        return None

    def release(self, lease: Lease) -> bool:
        """Give the slot back. ``True`` if the slot is freed by this lease's release, ``False`` if
        there was nothing of this lease to free (already released, expired and reissued, or a wrong
        token). Raises ``LeaseContentionError`` if retries ran out before it could be confirmed."""
        _check_ids(lease.team, lease.run_id)
        org_id = f"{lease.team}#{lease.run_id}"
        maybe_landed = False
        for attempt in range(self._attempts):
            now = self._clock()
            team_row, org_row = self._read_both(lease.team, now)
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
                # Nothing of ours is left. After an unknown outcome that is our own write landing.
                return maybe_landed
            outcome = self._try_commit(lease.team, team_row, org_row, attempt)
            if outcome == "ok":
                return True
            maybe_landed = maybe_landed or outcome == "unknown"
        raise LeaseContentionError(
            f"could not confirm the release of {lease.team}/{lease.run_id}; "
            "it is held until it expires"
        )


@dataclass(frozen=True)
class Admission:
    started: list[Lease]  # leases taken by this call: drive these runs
    already_held: list[Lease]  # runs that were already running: do not drive them again
    waiting: list[str]  # still queued, in order


def admit_queued(
    leases: ConcurrencyLeases, team: str, queued: Sequence[str], limits: ConcurrencyLimits
) -> Admission:
    """Start queued runs, oldest first, while slots are free. It stops at the first denial, so a
    later run never starts before an earlier one; a denied run stays queued, not failed. A run
    named twice counts once, and a run that already holds a slot is reported in ``already_held``,
    not as started."""
    started: list[Lease] = []
    already_held: list[Lease] = []
    unique = list(dict.fromkeys(queued))
    for i, run_id in enumerate(unique):
        got, was_held = leases._acquire(team, run_id, limits)  # noqa: SLF001
        if isinstance(got, Denied):
            return Admission(started, already_held, unique[i:])
        (already_held if was_held else started).append(got)
    return Admission(started, already_held, [])


@dataclass(frozen=True)
class Done[R]:
    value: R


@dataclass(frozen=True)
class Failed:
    error: Exception


def run_bounded[T, R](
    items: Iterable[T], fn: Callable[[T], R], *, max_concurrency: int
) -> list[Done[R] | Failed]:
    """Call ``fn`` on every item with at most ``max_concurrency`` running at once, for the drives
    and the startup redelivery. Results keep the item order: ``Done(value)`` or, when ``fn``
    raised an ``Exception``, ``Failed(error)``, which does not stop the others. A ``BaseException``
    (Ctrl-C, ``SystemExit``) cancels the items that have not started and propagates."""
    if type(max_concurrency) is not int or max_concurrency < 1:
        raise ValueError("max_concurrency must be an int of at least 1")
    pool = ThreadPoolExecutor(max_workers=max_concurrency)
    try:
        futures = [pool.submit(fn, item) for item in items]
        out: list[Done[R] | Failed] = []
        for f in futures:
            err = f.exception()
            if err is None:
                out.append(Done(f.result()))
            elif isinstance(err, Exception):
                out.append(Failed(err))
            else:
                raise err
        return out
    except BaseException:
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    finally:
        pool.shutdown(wait=True)
