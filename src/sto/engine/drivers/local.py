"""The local asyncio driver (D1-03): applies commands, feeds events back, persists every step.

Everything the driver knows lives in one store item per run (``RUN#r`` / ``DRIVER``): the
``RunState`` that goes to ``next()``, an inbox of events not yet applied, a log of commands not
yet done, and events refused as late. Every step is one conditional transaction on that item
(plus the run's ``META`` record), so a kill at any point leaves a state that a fresh process
resumes from, using the store alone:

* applying an event: pop it from the inbox, store the new state, append its commands;
* executing a command: call the executor with the command's key, then pop it and append the
  events it reported. A crash between the call and the commit repeats the call with the *same
  key*, which the executor must treat as already done (``CommandExecutor``).

A gate waiting for a person is just a state with an empty inbox and no pending commands: the
driver goes idle and a restart finds the same thing, without opening the gate again.

Single driver per run (a local, single-writer tool); a lost version race is reloaded and
retried, and a ``TransactionConflictError`` is retried with backoff.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from sto.domain import COMMANDS, EVENTS, Run, RunId, from_wire, to_wire
from sto.engine.drivers.ports import CommandExecutor, command_key
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
    Key,
    Put,
    Scope,
    Store,
    TransactionConflictError,
    VersionIs,
)

Kind = Literal["command", "event"]
_REGISTRIES = {"command": COMMANDS, "event": EVENTS}
_RETRIES = 8


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
    rejected: tuple[dict[str, Any], ...]
    version: int

    def wire(self) -> dict[str, Any]:
        return {
            "state": to_wire(self.state),
            "inbox": list(self.inbox),
            "pending": list(self.pending),
            "next_seq": self.next_seq,
            "rejected": list(self.rejected),
        }


class LocalDriver:
    def __init__(
        self,
        store: Store,
        scope: Scope,
        workflow: Workflow,
        executor: CommandExecutor,
        *,
        registry: HandlerRegistry | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = 0.01,
    ) -> None:
        load_handlers()  # before any stored event is decoded (decoding needs the registries)
        self._store, self._scope, self._wf = store, scope, workflow
        self._executor, self._registry = executor, registry
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
            tuple(d["rejected"]),
            item.version,
        )

    def _write(self, rec: _Rec, *, create: bool = False) -> None:
        run = rec.state.run
        self._store.transact(
            self._scope,
            [
                Put(
                    self._key(run.id),
                    rec.wire(),
                    when=Absent() if create else VersionIs(rec.version),
                ),
                Put(Key(f"RUN#{run.id}", "META"), to_wire(run)),
            ],
        )

    async def _commit(self, run_id: RunId, change: Callable[[_Rec], _Rec]) -> None:
        """Load, apply ``change`` (pure), write. Reload on a lost race, back off on a conflict."""
        delay = self._backoff
        for attempt in range(_RETRIES):
            try:
                self._write(change(self._load(run_id)))
                return
            except ConditionFailedError:
                if attempt == _RETRIES - 1:
                    raise
            except TransactionConflictError:
                if attempt == _RETRIES - 1:
                    raise
                await self._sleep(delay)
                delay *= 2

    # --- public -------------------------------------------------------------------------------

    async def start(self, run: Run) -> None:
        """Register a QUEUED run; calling it again for a known run does nothing."""
        rec = _Rec(RunState(run), (encode(RunStarted(run.id), "event"),), (), 0, (), 0)
        delay = self._backoff
        for attempt in range(_RETRIES):
            try:
                self._write(rec, create=True)
                return
            except ConditionFailedError:
                return
            except TransactionConflictError:
                if attempt == _RETRIES - 1:
                    raise
                await self._sleep(delay)
                delay *= 2

    async def submit(self, run_id: RunId, event: object) -> None:
        """Queue an event from outside (a gate decision, a cancel). Durable once it returns."""
        wire = encode(event, "event")
        await self._commit(run_id, lambda r: _replace(r, inbox=(*r.inbox, wire)))

    def state(self, run_id: RunId) -> RunState:
        return self._load(run_id).state

    def rejected(self, run_id: RunId) -> list[dict[str, Any]]:
        return list(self._load(run_id).rejected)

    def pending_events(self, run_id: RunId) -> int:
        return len(self._load(run_id).inbox)

    async def step(self, run_id: RunId) -> bool:
        """Do one durable unit of work; False when there is nothing to do (idle or waiting)."""
        rec = self._load(run_id)
        if rec.inbox:
            await self._commit(run_id, self._apply)
            return True
        if rec.pending:
            head = rec.pending[0]
            events = await self._executor.execute(head["key"], decode(head["cmd"], "command"))
            wires = tuple(encode(e, "event") for e in events)
            await self._commit(run_id, lambda r: _done(r, head["key"], wires))
            return True
        return False

    async def run_until_idle(self, run_id: RunId) -> RunState:
        while await self.step(run_id):
            pass
        return self.state(run_id)

    # --- one event ----------------------------------------------------------------------------

    def _apply(self, rec: _Rec) -> _Rec:
        wire, rest = rec.inbox[0], rec.inbox[1:]
        event = decode(wire, "event")
        try:
            tr = next(rec.state, event, self._wf, registry=self._registry)
        except OutOfOrderEventError as e:  # late or duplicate: refused, recorded, dropped
            return _replace(
                rec, inbox=rest, rejected=(*rec.rejected, _why(wire, "out_of_order", e))
            )
        except MalformedEventError as e:  # can never succeed, so it must not block the queue
            return _replace(rec, inbox=rest, rejected=(*rec.rejected, _why(wire, "malformed", e)))
        # Anything else (NoHandlerError, HandlersNotLoadedError, WorkflowMismatchError) is a
        # fault of this deployment, not a stale event: it propagates and the event stays queued.
        seq = rec.next_seq
        cmds = tuple(
            {"key": command_key(c, seq + i), "cmd": encode(c, "command")}
            for i, c in enumerate(tr.commands)
        )
        return _Rec(
            tr.state, rest, (*rec.pending, *cmds), seq + len(cmds), rec.rejected, rec.version
        )


def _replace(rec: _Rec, **changes: Any) -> _Rec:
    import dataclasses

    return dataclasses.replace(rec, **changes)


def _done(rec: _Rec, key: str, events: tuple[dict[str, Any], ...]) -> _Rec:
    if not rec.pending or rec.pending[0]["key"] != key:
        return rec  # someone else already recorded it
    return _replace(rec, pending=rec.pending[1:], inbox=(*rec.inbox, *events))


def _why(wire: dict[str, Any], reason: str, error: Exception) -> dict[str, Any]:
    return {**wire, "reason": reason, "detail": str(error)}
