"""The local asyncio driver (D1-03): applies commands, feeds events back, persists every step.

Everything the driver knows lives in one store item per run (``RUN#r`` / ``DRIVER``): the
``RunState`` that goes to ``next()``, an inbox of events not yet applied, a log of commands not
yet done, and the lease that says which driver owns the run. Every
step is one conditional transaction on that item. The same transaction writes the run's
``META``, the active-runs index entry, and, when an event is applied, its timeline entry
``EVT#<seq>`` (events refused as late or malformed are those entries whose outcome is not
``applied``; there is no second copy). A kill at any point leaves a state that a fresh process
resumes from, using the store alone (``resume_all`` finds the unfinished runs; no run ID has
to be known):

* applying an event: pop it from the inbox, store the new state, append its commands;
* executing a command: call the executor with the command's key, then pop it and append the
  events it reported. A crash between the call and the commit repeats the call with the *same
  key*, which the executor must treat as already done (``CommandExecutor``).

A gate waiting for a person is a state with an empty inbox and no pending commands: the driver
goes idle and a restart finds the same thing, without opening the gate again. A run that is
idle in any other non-final status is stuck, and ``run_until_idle`` raises ``RunWedgedError``.

One driver owns a run at a time, through a lease with an expiry (``clock``, ``new_id`` and
``lease_seconds`` are the caller's: the engine reads no clock or randomness of its own, and
``new_id`` makes every driver instance's owner unique, so a reused label cannot share a lease).
The lease is renewed while a command executes. A second driver waits up to ``lease_wait``
seconds, then raises ``LeaseHeldError``; a driver that finds the lease taken mid-step raises
``LeaseLostError`` and writes nothing. ``resume_all`` runs one task per run and, for a run still
leased by a dead driver, waits for the lease to expire (up to ``resume_wait``).
``submit`` is how other
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
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from sto.domain import (
    COMMANDS,
    EVENTS,
    EffectClass,
    EffectStatus,
    PermanentError,
    Run,
    RunId,
    RunStatus,
    Subject,
    TransientError,
    from_wire,
    to_wire,
)
from sto.effects.core import EffectExecutor, ExecResult
from sto.effects.ports import EffectHandler
from sto.engine.commands import RunEffect
from sto.engine.drivers.ports import (
    CommandExecutor,
    Done,
    Held,
    Outcome,
    StillRunning,
    command_key,
)
from sto.engine.handlers.core import EffectConfirmed, EffectFailed, RunStarted
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


StepResult = Literal["worked", "idle"] | Waiting | Held


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
    lease: dict[str, Any] | None
    version: int

    def wire(self) -> dict[str, Any]:
        return {
            "state": to_wire(self.state),
            "inbox": list(self.inbox),
            "pending": list(self.pending),
            "next_seq": self.next_seq,
            "next_evt": self.next_evt,
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
        new_id: Callable[[], str],
        lease_seconds: float = 30.0,
        lease_wait: float = 0.0,
        resume_wait: float | None = None,
        registry: HandlerRegistry | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = 0.01,
    ) -> None:
        if not lease_seconds > 0:
            raise ValueError("lease_seconds must be positive")
        load_handlers()  # before any stored event is decoded (decoding needs the registries)
        self._store, self._scope, self._wf = store, scope, workflow
        self._executor, self._registry = executor, registry
        self._owner, self._clock = f"{owner}/{new_id()}", clock
        self._resume_wait = lease_seconds if resume_wait is None else resume_wait
        self._probed: set[tuple[RunId, str]] = set()
        self._ttl, self._lease_wait = lease_seconds, lease_wait
        self._sleep, self._backoff = sleep, backoff
        self._held: dict[RunId, str] = {}
        self._driving: dict[RunId, asyncio.Future[RunState]] = {}

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

    async def _commit(
        self, run_id: RunId, change: _Change, *, owner: bool = True, attempts: int = _RETRIES
    ) -> None:
        """Load, apply ``change`` (pure), write. Reload and retry, with backoff, on a lost
        race or a conflict. ``owner`` commits require our lease and renew it."""
        delay = self._backoff
        for attempt in range(attempts):
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
                if attempt == attempts - 1:
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
        rec = _Rec(RunState(run), (encode(RunStarted(run.id), "event"),), (), 0, 0, None, 0)
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
        """Events refused as late or malformed: the timeline entries whose outcome is not
        ``applied``, each with a ``reason`` (its outcome)."""
        return [
            {**e, "reason": e["outcome"]}
            for e in self.timeline(run_id)
            if e["outcome"] != "applied"
        ]

    def pending_events(self, run_id: RunId) -> int:
        return len(self._load(run_id).inbox)

    def timeline(self, run_id: RunId) -> list[dict[str, Any]]:
        """The run's ``EVT#`` entries in order."""
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page = self._store.query(self._scope, f"RUN#{run_id}", sk_prefix="EVT#", cursor=cursor)
            out += [i.data for i in page.items]
            cursor = page.cursor
            if cursor is None:
                return out

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

    def _choose(self, rec: _Rec) -> tuple[dict[str, Any], bool]:
        """The command to run next, and whether this call is a probe.

        A Stop must not wait behind a command that is not finished, so a queued ``StopRun`` goes
        first. But while the run is CANCELLING, an effect that was already tried is called once
        before the ``StopRun``, so its handler can stop or reconcile it (a merge in flight must
        be dequeued, not left to land). D2-11 owns the rest of that race."""
        run_id = rec.state.run.id
        if rec.state.run.status is RunStatus.CANCELLING:
            for c in rec.pending:
                if c["cmd"]["type"] == "run_effect" and (run_id, c["key"]) not in self._probed:
                    self._probed.add((run_id, c["key"]))
                    return c, True
        stops = [c for c in rec.pending if c["cmd"]["type"] == "stop_run"]
        return (stops[0] if stops else rec.pending[0]), False

    async def _heartbeat(self, run_id: RunId) -> None:
        """Renew the lease while a command executes, so a long one does not lose the run. A
        store error that is not a lost lease is retried until the lease would run out; losing the
        lease for real ends the heartbeat (and so the command)."""
        lease = (await self._aload(run_id)).lease
        expires = lease["expires"] if lease else self._clock()
        while True:
            await asyncio.sleep(self._ttl / 3)
            for attempt in range(_RETRIES):
                started = self._clock()
                try:
                    await self._commit(
                        run_id, lambda r: (dataclasses.replace(r), ()), attempts=1
                    )  # one try: the retries below are bounded by the lease, not by backoff
                    expires = started + self._ttl  # the stamp is at least this late
                    break
                except LeaseLostError:
                    raise
                except Exception:
                    if attempt == _RETRIES - 1 or self._clock() >= expires:
                        raise
                    await asyncio.sleep(self._ttl / 10)

    async def _execute(self, run_id: RunId, head: dict[str, Any]) -> Outcome:
        work = asyncio.ensure_future(
            self._executor.execute(head["key"], decode(head["cmd"], "command"))
        )
        beat = asyncio.ensure_future(self._heartbeat(run_id))
        try:
            await asyncio.wait({work, beat}, return_when=asyncio.FIRST_COMPLETED)
            if work.done():
                return work.result()
            beat.result()  # the heartbeat only ends by failing, e.g. LeaseLostError
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            for t in (work, beat):
                t.cancel()
            await asyncio.gather(work, beat, return_exceptions=True)

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
        head, probe = self._choose(rec)
        if probe:
            try:
                outcome = await self._execute(run_id, head)
            except LeaseLostError:
                raise
            except Exception:
                # The probe's one call failed for good (the handler cannot stop this effect).
                # That must not hold the StopRun back; the effect, still at the head, raises the
                # same fault again on its next call, so it is not hidden.
                return "worked"
        else:
            outcome = await self._execute(run_id, head)
        if isinstance(outcome, StillRunning | Held):
            if probe:
                return "worked"  # the probe has had its one call; go on to the StopRun
            return Waiting(outcome.retry_after) if isinstance(outcome, StillRunning) else outcome
        wires = tuple(encode(e, "event") for e in outcome.events)
        await self._commit(run_id, lambda r: self._done(r, head["key"], wires))
        return "worked"

    async def run_until_idle(self, run_id: RunId) -> RunState:
        """Drive until there is nothing to do. Returns with the run waiting for a person,
        BLOCKED, finished or held (see ``held``); raises ``RunWedgedError`` if it is idle in
        any other status.

        One drive per run per driver instance: while this instance is already driving the run, a
        second call (or ``resume_all``) executes nothing in the meantime. It waits for the first
        drive to end without inheriting its cancellation, re-raises that drive's exception if it
        had one, and otherwise runs its own drive (an idle drive costs nothing), so an event
        queued after the first drive's last read is not left with nobody driving it. The lease
        cannot tell two tasks of one instance apart, so this guard does."""
        while (running := self._driving.get(run_id)) is not None:
            await asyncio.wait({running})
            if self._driving.get(run_id) is running:
                del self._driving[run_id]  # do not wait for the done callback to clear it
            if not running.cancelled() and (error := running.exception()) is not None:
                raise error
        task = asyncio.ensure_future(self._drive(run_id))
        self._driving[run_id] = task
        task.add_done_callback(lambda t: self._forget(run_id, t))
        return await task

    def _forget(self, run_id: RunId, task: asyncio.Future[RunState]) -> None:
        if self._driving.get(run_id) is task:
            del self._driving[run_id]

    async def _drive(self, run_id: RunId) -> RunState:
        self._held.pop(run_id, None)
        try:
            while True:
                while True:
                    result = await self.step(run_id)
                    if isinstance(result, Held):
                        self._held[run_id] = result.reason
                        break
                    if result == "worked":
                        await asyncio.sleep(0)  # a non-suspending executor must not starve others
                    elif isinstance(result, Waiting):
                        await self._sleep(result.retry_after)
                    else:
                        break
                await self._release(run_id)
                rec = await self._aload(run_id)  # read at or after the release: it decides
                if (rec.inbox or rec.pending) and run_id not in self._held:
                    continue  # another writer queued work meanwhile: not idle after all
                break
            rs = rec.state
            status = rs.run.status
            if run_id not in self._held and status not in _IDLE_OK and not status.is_terminal:
                refused = [r["reason"] for r in await asyncio.to_thread(self.rejected, run_id)]
                raise RunWedgedError(
                    f"run {run_id} is idle in {status.value} at {rs.run.stage!r} with nothing"
                    f" queued (refused events: {refused})"
                )
            if status.is_terminal:
                self._held.pop(run_id, None)
            return rs
        finally:
            self._probed = {p for p in self._probed if p[0] != run_id}

    def held(self, run_id: RunId) -> str | None:
        """Why the last ``run_until_idle`` of this run stopped on a held command, if it did."""
        return self._held.get(run_id)

    async def _resume(self, run_id: RunId) -> RunState:
        waited = 0.0
        while True:
            try:
                return await self.run_until_idle(run_id)
            except LeaseHeldError as held:
                if waited + held.remaining > self._resume_wait:
                    raise
                await self._sleep(held.remaining)  # a dead driver's lease runs out
                waited += held.remaining

    async def resume_all(self) -> dict[RunId, RunState | Exception]:
        """After a restart: drive every unfinished run found in the store, one task per run so
        a run that polls cannot starve another. A run that fails (wedged, leased to a live
        driver, lease lost, an executor fault) is reported in the result, and the others go on."""
        ids = await self.active_runs()
        results = await asyncio.gather(*(self._resume(r) for r in ids), return_exceptions=True)
        out: dict[RunId, RunState | Exception] = {}
        for run_id, result in zip(ids, results, strict=True):
            if isinstance(result, BaseException) and not isinstance(result, Exception):
                raise result  # cancellation is not a run's failure
            out[run_id] = result
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
            nxt = dataclasses.replace(rec, inbox=rest, next_evt=rec.next_evt + 1)
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
        if all(c["key"] != key for c in rec.pending):
            return rec, ()  # someone else already recorded it
        rest = tuple(c for c in rec.pending if c["key"] != key)
        nxt = dataclasses.replace(rec, pending=rest, inbox=(*rec.inbox, *events))
        return nxt, ()


# A run in one of these will never act again (the same set the effects service calls dead).
_DEAD = frozenset(
    {
        RunStatus.CANCELLING,
        RunStatus.CANCELLED,
        RunStatus.DONE,
        RunStatus.REJECTED,
        RunStatus.CLOSED,
        RunStatus.EXPIRED,
    }
)


class EffectsExecutor:
    """The ``CommandExecutor`` for ``RunEffect``: plans the effect (idempotent), runs it through
    the effects service and maps the result to what the driver understands. Any other command goes
    to ``others``.

    * ``live`` reads the subject afresh from the ticket and the SCM (the effects service refuses
      to trust the command's own subject).
    * ``status_of`` is the run's current status: while CANCELLING an ACCEPTED effect is stopped
      instead of polled, and an in-flight one is reconciled; a failed or voided effect on a dead
      run is not reported (nothing is waiting for it).

    Mapping (``blocked`` is checked first, because a blocked effect also has status RETRYING):
    blocked -> ``EffectFailed``; CONFIRMED -> ``EffectConfirmed`` (with the merge SHA); FAILED or
    VOIDED -> ``EffectFailed`` while the run is active, ``Done()`` once it is dead; ``held`` ->
    ``Held``; anything else (in flight, RETRYING, ACCEPTED and unconfirmed, lease lost) ->
    ``StillRunning``. The effects service runs in a thread, so a slow SCM call does not freeze
    the loop.
    """

    def __init__(
        self,
        effects: EffectExecutor,
        handlers: Mapping[str, EffectHandler],
        live: Callable[[RunEffect], Subject],
        status_of: Callable[[RunId], RunStatus],
        *,
        others: CommandExecutor | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self._fx, self._handlers, self._live = effects, handlers, live
        self._status_of, self._others, self._poll = status_of, others, poll_interval
        self._streak: dict[str, int] = {}

    async def execute(self, key: str, command: object) -> Outcome:
        if not isinstance(command, RunEffect):
            if self._others is None:
                raise TypeError(f"no executor for {type(command).__name__}")
            return await self._others.execute(key, command)
        try:
            outcome = await asyncio.to_thread(self._run_effect, command, key)
        except TransientError as e:
            # An SCM blip, or the effect kept changing under the claim: try again later.
            return self._again(key, f"transient:{type(e).__name__}", retrying=True)
        if isinstance(outcome, Done):
            self._streak.pop(key, None)
        return outcome

    def _again(self, key: str, reason: str, *, retrying: bool) -> StillRunning:
        """``StillRunning``. Retries back off (doubling, capped), so attempts do not all go
        within seconds of one blip; plain polls of an accepted effect keep the fixed interval."""
        n = self._streak.get(key, 0) if retrying else 0
        self._streak[key] = n + 1 if retrying else 0
        return StillRunning(min(self._poll * 2 ** min(n, 6), 60 * self._poll), reason)

    def _run_effect(self, cmd: RunEffect, key: str) -> Outcome:
        fx, run_id = self._fx, cmd.run_id
        planned = fx.plan(
            run_id,
            cmd.type,
            cmd.stage,
            cmd.visit,
            EffectClass.GATED,
            cmd.subject_digest,
            requires_gates=cmd.requires_gates,
            subject=cmd.subject,
        )
        handler, ikey = self._handlers[cmd.type], planned.idempotency_key
        # Once the run is dead (CANCELLING included) an effect that was tried is stopped or
        # reconciled, not polled or written: a merge must not land after the Stop.
        dying = self._status_of(run_id) in _DEAD
        status = fx.get(run_id, ikey).status
        try:
            if status is EffectStatus.ACCEPTED:
                result = fx.stop(run_id, ikey, handler) if dying else fx.poll(run_id, ikey, handler)
            elif dying and status in (EffectStatus.ATTEMPTING, EffectStatus.RETRYING):
                result = fx.reconcile(run_id, ikey, handler)
            else:
                # The live subject is only needed to claim a write; a dead run or a finished
                # effect is refused or replayed before it is looked at.
                needs_live = not dying and not status.is_terminal
                result = fx.execute(
                    run_id, ikey, handler, live=self._live(cmd) if needs_live else None
                )
        except ValueError:
            # A ValueError is a fault (a handler bug, a non-outcome return) unless the record
            # really moved between get and poll/stop/reconcile (ACCEPTED -> CONFIRMED, ...):
            # then look again on the next call.
            if fx.get(run_id, ikey).status is status:
                raise
            return self._again(key, "moved", retrying=False)
        return self._map(cmd, result, key)

    def _map(self, cmd: RunEffect, result: ExecResult, key: str) -> Outcome:
        effect = result.effect
        failed = EffectFailed(cmd.run_id, cmd.type, cmd.visit)
        # Blocked means the outcome is unknown and a person must decide. It is reported even on a
        # dead run: the run refuses it, which leaves the only trace of it in the timeline (D2-11
        # decides what a blocked effect on a stopped run shows).
        if result.blocked:
            return Done([failed])
        if effect.status is EffectStatus.CONFIRMED:
            merged = effect.frozen_subject.merge_sha if effect.frozen_subject else None
            return Done([EffectConfirmed(cmd.run_id, cmd.type, cmd.visit, merged)])
        if effect.status in (EffectStatus.FAILED, EffectStatus.VOIDED):
            dead = self._status_of(cmd.run_id) in _DEAD
            return Done() if dead else Done([failed])
        if result.reason == "held":
            return Held("held")
        retrying = effect.status is EffectStatus.RETRYING
        return self._again(key, result.reason or effect.status.value.lower(), retrying=retrying)
