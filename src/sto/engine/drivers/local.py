"""The local asyncio driver (D1-03): applies commands, feeds events back, persists every step.

Everything the driver knows lives in one store item per run (``RUN#r`` / ``DRIVER``): the
``RunState`` that goes to ``next()``, an inbox of events not yet applied, a log of commands not
yet done, events refused as late, and the lease that says which driver owns the run. Every
step is one conditional transaction on that item. The same transaction writes the run's
``META``, the active-runs index entry, and, when an event is applied, its timeline entry
``EVT#<seq>``. A kill at any point leaves a state that a fresh process resumes from, using the
store alone (``resume_all`` finds the unfinished runs; no run ID has to be known):

* applying an event: pop it from the inbox, store the new state, append its commands;
* executing a command: call the executor with the command's key, then pop it and append the
  events it reported. A crash between the call and the commit repeats the call with the *same
  key*, which the executor must treat as already done (``CommandExecutor``).

A gate waiting for a person is a state with an empty inbox and no pending commands: the driver
goes idle and a restart finds the same thing, without opening the gate again. A run that is
idle in any other non-final status is stuck, and ``run_until_idle`` raises ``RunWedgedError``.

One driver owns a run at a time, through a lease with an expiry (``owner``, ``clock`` and
``lease_seconds`` are the caller's: the engine reads no clock of its own). A second driver
waits up to ``lease_wait`` seconds, then raises ``LeaseHeldError``; a driver that finds the
lease taken mid-step raises ``LeaseLostError`` and writes nothing. ``submit`` is how other
writers (the API) queue an event; it never touches the lease. A lost version race reloads and
retries, and both that and ``TransactionConflictError`` back off. Store calls run in threads so
a busy store does not freeze the event loop.

The active-runs index is ``RUNS_ACTIVE`` / ``<run id>`` in the team's partition. PLAN 11 has
no such item: it lists runs through ``GSI2`` (by team, status and time). That index is the
DynamoDB answer; the store port has no secondary indexes, so the local driver keeps its own
list, written in the same transaction so it can never disagree with the run.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from sto.domain import (
    COMMANDS,
    EVENTS,
    PermanentError,
    Run,
    RunId,
    RunStatus,
    TransientError,
    from_wire,
    to_wire,
)
from sto.engine.drivers.ports import (
    CommandExecutor,
    Done,
    StillRunning,
    command_key,
)
from sto.engine.handlers.core import RunStarted
from sto.engine.reducer import (
    HandlerRegistry,
    MalformedEventError,
    OutOfOrderEventError,
    RunState,
    Workflow,
    load_handlers,
    next,
)
from sto.store.ports import (
    Absent,
    ConditionFailedError,
    Delete,
    Key,
    Op,
    Put,
    Scope,
    Store,
    TransactionConflictError,
    VersionIs,
)

Kind = Literal["command", "event"]
_REGISTRIES = {"command": COMMANDS, "event": EVENTS}
_RETRIES = 8
ACTIVE_PK = "RUNS_ACTIVE"
# A run idle in one of these is not stuck: a person decides, or it is over.
_IDLE_OK = frozenset({RunStatus.WAITING_HUMAN, RunStatus.BLOCKED})


class RunWedgedError(PermanentError):
    """The run is idle (nothing to apply or execute) yet still in a status that needs the driver:
    a refused or replayed-empty result left it with nothing queued."""


class LeaseHeldError(TransientError):
    """Another live driver owns the run."""

    def __init__(self, owner: str, remaining: float) -> None:
        self.owner, self.remaining = owner, remaining
        super().__init__(f"run is leased to {owner!r} for another {remaining:.2f}s")


class LeaseLostError(PermanentError):
    """The lease is no longer ours, so this driver must stop without writing."""


@dataclass(frozen=True)
class Waiting:
    """``step`` result: the head command is still running; call again after ``retry_after``."""

    retry_after: float


StepResult = Literal["worked", "idle"] | Waiting


def encode(obj: object, kind: Kind) -> dict[str, Any]:
    return {"type": _REGISTRIES[kind].name_of(type(obj)), "data": to_wire(obj)}


def decode(wire: dict[str, Any], kind: Kind) -> Any:
    return from_wire(_REGISTRIES[kind].get(wire["type"]), wire["data"])


@dataclass(frozen=True)
class _Rec:
    """The stored driver record, as read. ``version`` is the item's, for the next write."""

    state: RunState
    inbox: tuple[dict[str, Any], ...]
    pending: tuple[dict[str, Any], ...]
    next_seq: int
    next_evt: int
    rejected: tuple[dict[str, Any], ...]
    lease: dict[str, Any] | None
    version: int

    def wire(self) -> dict[str, Any]:
        return {
            "state": to_wire(self.state),
            "inbox": list(self.inbox),
            "pending": list(self.pending),
            "next_seq": self.next_seq,
            "next_evt": self.next_evt,
            "rejected": list(self.rejected),
            "lease": self.lease,
        }


_Change = Callable[[_Rec], tuple[_Rec, tuple[Put, ...]]]


class LocalDriver:
    def __init__(
        self,
        store: Store,
        scope: Scope,
        workflow: Workflow,
        executor: CommandExecutor,
        *,
        owner: str,
        clock: Callable[[], float],
        lease_seconds: float = 30.0,
        lease_wait: float = 0.0,
        registry: HandlerRegistry | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = 0.01,
    ) -> None:
        load_handlers()  # before any stored event is decoded (decoding needs the registries)
        self._store, self._scope, self._wf = store, scope, workflow
        self._executor, self._registry = executor, registry
        self._owner, self._clock = owner, clock
        self._ttl, self._lease_wait = lease_seconds, lease_wait
        self._sleep, self._backoff = sleep, backoff

    # --- storage ------------------------------------------------------------------------------

    @staticmethod
    def _key(run_id: RunId) -> Key:
        return Key(f"RUN#{run_id}", "DRIVER")

    def _load(self, run_id: RunId) -> _Rec:
        item = self._store.get(self._scope, self._key(run_id))
        if item is None:
            raise KeyError(f"no driver record for run {run_id}")
        d = item.data
        return _Rec(
            from_wire(RunState, d["state"]),
            tuple(d["inbox"]),
            tuple(d["pending"]),
            d["next_seq"],
            d["next_evt"],
            tuple(d["rejected"]),
            d["lease"],
            item.version,
        )

    async def _aload(self, run_id: RunId) -> _Rec:
        return await asyncio.to_thread(self._load, run_id)

    async def _write(self, rec: _Rec, extra: tuple[Put, ...] = (), *, create: bool = False) -> None:
        run = rec.state.run
        index = Key(ACTIVE_PK, str(run.id))
        finished = run.status.is_terminal and not rec.pending and not rec.inbox
        ops: list[Op] = [
            Put(self._key(run.id), rec.wire(), when=Absent() if create else VersionIs(rec.version)),
            Put(Key(f"RUN#{run.id}", "META"), to_wire(run)),
            # Listed until finished: a terminal run may still have its last command (Finish) to do.
            Delete(index) if finished else Put(index, {"run_id": str(run.id)}),
            *extra,
        ]
        await asyncio.to_thread(self._store.transact, self._scope, ops)

    async def _backoff_sleep(self, delay: float) -> float:
        await self._sleep(delay)
        return delay * 2

    async def _commit(self, run_id: RunId, change: _Change, *, owner: bool = True) -> None:
        """Load, apply ``change`` (pure), write. Reload and retry, with backoff, on a lost
        race or a conflict. ``owner`` commits require our lease and renew it."""
        delay = self._backoff
        for attempt in range(_RETRIES):
            try:
                rec = await self._aload(run_id)
                if owner and (rec.lease is None or rec.lease["owner"] != self._owner):
                    raise LeaseLostError(f"run {run_id} is no longer leased to {self._owner!r}")
                new, extra = change(rec)
                if new is rec and not extra:
                    return
                if owner:
                    new = dataclasses.replace(new, lease=self._stamp())
                await self._write(new, extra)
                return
            except (ConditionFailedError, TransactionConflictError):
                if attempt == _RETRIES - 1:
                    raise
                delay = await self._backoff_sleep(delay)

    def _stamp(self) -> dict[str, Any]:
        return {"owner": self._owner, "expires": self._clock() + self._ttl}

    # --- lease --------------------------------------------------------------------------------

    def _holds(self, rec: _Rec) -> bool:
        """Ours, with more than half its time left (so a long step renews it in good time)."""
        lease = rec.lease
        return (
            lease is not None
            and lease["owner"] == self._owner
            and lease["expires"] - self._clock() > self._ttl / 2
        )

    def _take(self, rec: _Rec) -> tuple[_Rec, tuple[Put, ...]]:
        lease = rec.lease
        if lease is not None and lease["owner"] != self._owner:
            remaining = lease["expires"] - self._clock()
            if remaining > 0:
                raise LeaseHeldError(lease["owner"], remaining)
        return dataclasses.replace(rec, lease=self._stamp()), ()

    async def _claim(self, run_id: RunId) -> None:
        waited = 0.0
        while True:
            try:
                await self._commit(run_id, self._take, owner=False)
                return
            except LeaseHeldError as held:
                if waited >= self._lease_wait:
                    raise
                nap = min(held.remaining, self._lease_wait - waited)
                await self._sleep(nap)
                waited += nap

    async def _release(self, run_id: RunId) -> None:
        """Give the run up when idle, so another process need not wait for the lease to expire."""

        def let_go(rec: _Rec) -> tuple[_Rec, tuple[Put, ...]]:
            if rec.lease is None or rec.lease["owner"] != self._owner:
                return rec, ()
            return dataclasses.replace(rec, lease=None), ()

        await self._commit(run_id, let_go, owner=False)

    # --- public -------------------------------------------------------------------------------

    async def start(self, run: Run) -> None:
        """Register a QUEUED run; calling it again for a known run does nothing."""
        rec = _Rec(RunState(run), (encode(RunStarted(run.id), "event"),), (), 0, 0, (), None, 0)
        delay = self._backoff
        for attempt in range(_RETRIES):
            try:
                await self._write(rec, create=True)
                return
            except ConditionFailedError:
                return
            except TransactionConflictError:
                if attempt == _RETRIES - 1:
                    raise
                delay = await self._backoff_sleep(delay)

    async def submit(self, run_id: RunId, event: object) -> None:
        """Queue an event from outside (a gate decision, a cancel). Durable once it returns.
        Does not touch the lease, so any process may call it."""
        wire = encode(event, "event")
        await self._commit(
            run_id, lambda r: (dataclasses.replace(r, inbox=(*r.inbox, wire)), ()), owner=False
        )

    def state(self, run_id: RunId) -> RunState:
        return self._load(run_id).state

    def rejected(self, run_id: RunId) -> list[dict[str, Any]]:
        return list(self._load(run_id).rejected)

    def pending_events(self, run_id: RunId) -> int:
        return len(self._load(run_id).inbox)

    def timeline(self, run_id: RunId) -> list[dict[str, Any]]:
        """The run's ``EVT#`` entries in order."""
        page = self._store.query(self._scope, f"RUN#{run_id}", sk_prefix="EVT#")
        return [i.data for i in page.items]

    def _active_runs(self) -> list[RunId]:
        ids: list[RunId] = []
        cursor: str | None = None
        while True:
            page = self._store.query(self._scope, ACTIVE_PK, cursor=cursor)
            ids += [RunId.parse(i.key.sk) for i in page.items]
            cursor = page.cursor
            if cursor is None:
                return sorted(ids)

    async def active_runs(self) -> list[RunId]:
        """Every unfinished run of this team, from the store alone."""
        return await asyncio.to_thread(self._active_runs)

    async def step(self, run_id: RunId) -> StepResult:
        """One durable unit of work. Queued events come before the next command."""
        rec = await self._aload(run_id)
        if not rec.inbox and not rec.pending:
            return "idle"  # nothing to do, so no need to own the run
        if not self._holds(rec):
            await self._claim(run_id)
            rec = await self._aload(run_id)
        if rec.inbox:
            await self._commit(run_id, self._apply)
            return "worked"
        if not rec.pending:  # another writer finished the work while we claimed
            return "idle"
        head = rec.pending[0]
        outcome = await self._executor.execute(head["key"], decode(head["cmd"], "command"))
        if isinstance(outcome, StillRunning):
            return Waiting(outcome.retry_after)
        assert isinstance(outcome, Done)
        wires = tuple(encode(e, "event") for e in outcome.events)
        await self._commit(run_id, lambda r: self._done(r, head["key"], wires))
        return "worked"

    async def run_until_idle(self, run_id: RunId) -> RunState:
        """Drive until there is nothing to do. Returns with the run waiting for a person,
        BLOCKED or finished; raises ``RunWedgedError`` if it is idle in any other status."""
        while True:
            result = await self.step(run_id)
            if result == "worked":
                await asyncio.sleep(0)  # an executor that never suspends must not starve the loop
            elif isinstance(result, Waiting):
                await self._sleep(result.retry_after)
            else:
                break
        rec = await self._aload(run_id)
        await self._release(run_id)
        rs = rec.state
        status = rs.run.status
        if status not in _IDLE_OK and not status.is_terminal:
            refused = [r["reason"] for r in rec.rejected]
            raise RunWedgedError(
                f"run {run_id} is idle in {status.value} at {rs.run.stage!r} with nothing queued"
                f" (refused events: {refused})"
            )
        return rs

    async def resume_all(self) -> dict[RunId, RunState | RunWedgedError | LeaseHeldError]:
        """After a restart: drive every unfinished run found in the store. A run that is
        wedged or leased to a live driver is reported, not allowed to stop the others."""
        out: dict[RunId, RunState | RunWedgedError | LeaseHeldError] = {}
        for run_id in await self.active_runs():
            try:
                out[run_id] = await self.run_until_idle(run_id)
            except (RunWedgedError, LeaseHeldError) as e:
                out[run_id] = e
        return out

    # --- one event ----------------------------------------------------------------------------

    def _apply(self, rec: _Rec) -> tuple[_Rec, tuple[Put, ...]]:
        if not rec.inbox:  # another writer got there first: nothing to do
            return rec, ()
        wire, rest = rec.inbox[0], rec.inbox[1:]
        event = decode(wire, "event")
        run_id = rec.state.run.id

        def entry(outcome: str, state: RunState, detail: str = "") -> tuple[Put, ...]:
            data = {
                "seq": rec.next_evt,
                "outcome": outcome,
                "type": wire["type"],
                "data": wire["data"],
                "status": state.run.status.value,
                "stage": state.run.stage,
                "detail": detail,
            }
            key = Key(f"RUN#{run_id}", f"EVT#{rec.next_evt:08d}")
            return (Put(key, data, when=Absent()),)

        try:
            tr = next(rec.state, event, self._wf, registry=self._registry)
        except (OutOfOrderEventError, MalformedEventError) as e:
            # Late or duplicate (out of order), or never valid (malformed): recorded and dropped,
            # so a bad event cannot block the queue. Anything else (NoHandlerError,
            # HandlersNotLoadedError, WorkflowMismatchError) is a fault of this deployment, not
            # a stale event: it propagates and the event stays queued.
            reason = "out_of_order" if isinstance(e, OutOfOrderEventError) else "malformed"
            refused = {**wire, "reason": reason, "detail": str(e)}
            nxt = dataclasses.replace(
                rec,
                inbox=rest,
                rejected=(*rec.rejected, refused),
                next_evt=rec.next_evt + 1,
            )
            return nxt, entry(reason, rec.state, str(e))
        seq = rec.next_seq
        cmds = tuple(
            {"key": command_key(c, seq + i), "cmd": encode(c, "command")}
            for i, c in enumerate(tr.commands)
        )
        nxt = dataclasses.replace(
            rec,
            state=tr.state,
            inbox=rest,
            pending=(*rec.pending, *cmds),
            next_seq=seq + len(cmds),
            next_evt=rec.next_evt + 1,
        )
        return nxt, entry("applied", tr.state)

    @staticmethod
    def _done(
        rec: _Rec, key: str, events: tuple[dict[str, Any], ...]
    ) -> tuple[_Rec, tuple[Put, ...]]:
        if not rec.pending or rec.pending[0]["key"] != key:
            return rec, ()  # someone else already recorded it
        nxt = dataclasses.replace(rec, pending=rec.pending[1:], inbox=(*rec.inbox, *events))
        return nxt, ()
