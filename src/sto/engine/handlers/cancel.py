"""Cancel v1 (D2-11, PLAN 14.3): the Stop path, from the request to ``CANCELLED``.

``CancelRequested`` (core.py) commits ``CANCELLING`` and emits ``StopRun``. The reducer stays pure;
everything below is what a driver does around it.

Events (reducer side, registered for both workflow kinds). A run that is stopping refuses
``effect.confirmed`` and ``effect.failed``, so an effect that was already sent would vanish. The
driver (``LocalDriver._apply``) turns those into:

* ``EffectLandedDuringStop``: the write happened. A ``pr.merge`` is recorded in ``RunState.merges``,
  so ending the run plans the revert and sets the incident flag (a stopped run that merged is never
  plain ``CANCELLED``). Recording the same merge twice changes nothing.
* ``EffectUnresolvedDuringStop``: the outcome is unknown (a blocked effect on a stopped run). It is
  an *applied* timeline entry, so it shows plainly instead of as a refused event.

``StopExecutor`` performs ``StopRun`` (and ``OpenRevert``, ``Finish``) for the driver, in PLAN
14.3's order:

* void ``PLANNED`` effects (a confirmed one is reported as landed, a contended one raises);
* reconcile what was tried and, when the handler cannot tell, look the merge up with the read-only
  ``ScmProvider.find_merge`` (a queued merge keeps the Stop open; "none" is only believed when the
  read succeeded);
* stop the live step's attempt, close open gates, then report ``CancelCompleted``.

It never gives up: a Stop that keeps failing answers ``StillRunning`` and raises the stuck-stop
alarm once ``stop_timeout`` has passed. SCM reads run on their own pool with a deadline, so a hung
read cannot hold the API's thread pool.

``CancelService`` is the audited API path: who may Stop (``StopPolicy``; people eligible for a gate
of the run), the audit entry, the durable request time (which the alarm counts from, so a dead run
is found by ``StopWatch`` even though no driver is alive), the background re-drive stopped, and the
event submitted. A browser closing is not an input anywhere here: a run does not live on a
connection (C4).

Not here: stopping model calls mid-step and sessions (D10-06 fills ``StepStopper``), closing a gate
through the gate service's audit chain (``GateCloser`` is store-level until that exists), and the
linear v0 workflow's ``CancelCompleted`` (D2-26). The attempt directory still accepts a later
``register`` after ``end``; closing that needs a change in ``budget/broker.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
from collections.abc import Awaitable, Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Protocol

from sto.adapters.ports import MergeResult, MergeState
from sto.domain import (
    EVENTS,
    Effect,
    EffectClass,
    EffectStatus,
    Gate,
    GateStatus,
    PermanentError,
    Receipt,
    RunId,
    RunStatus,
    TransientError,
    from_wire,
    to_wire,
)
from sto.effects.core import EffectExecutor, ExecResult
from sto.effects.ports import CallHandler, EffectHandler
from sto.engine.commands import Finish, OpenRevert, StopRun
from sto.engine.drivers.ports import Done, Outcome, StillRunning
from sto.engine.handlers.core import CancelCompleted, CancelRequested
from sto.engine.reducer import (
    MalformedEventError,
    Merge,
    OutOfOrderEventError,
    RunState,
    Transition,
    handles,
    handles_graph,
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

# --- events -------------------------------------------------------------------------------------


@EVENTS.register("cancel.effect_landed")
@dataclass(frozen=True)
class EffectLandedDuringStop:
    """An effect sent before the Stop took hold did land. ``merge_sha`` and ``head_sha`` are set
    for a ``pr.merge`` (the head it merged is what a QA approval must have covered)."""

    run_id: RunId
    effect: str
    visit: int
    merge_sha: str | None = None
    head_sha: str | None = None


@EVENTS.register("cancel.effect_unresolved")
@dataclass(frozen=True)
class EffectUnresolvedDuringStop:
    """An effect sent before the Stop whose outcome is unknown. A person reconciles it."""

    run_id: RunId
    effect: str
    visit: int
    reason: str = "blocked"


def _stopping(rs: RunState, what: str) -> None:
    if rs.run.status is not RunStatus.CANCELLING:
        raise OutOfOrderEventError(f"{what} while run is {rs.run.status.value}, not CANCELLING")


def _bump(rs: RunState, **changes: object) -> RunState:
    run = dataclasses.replace(rs.run, version=rs.run.version + 1)
    return dataclasses.replace(rs, run=run, **changes)  # type: ignore[arg-type]


def on_effect_landed(rs: RunState, event: EffectLandedDuringStop, wf: Any) -> Transition:
    _stopping(rs, "an effect landed")
    if event.effect != "pr.merge":
        return Transition(_bump(rs))
    sha = (event.merge_sha or "").strip()
    if not sha:
        raise MalformedEventError("a landed pr.merge must report merge_sha")
    if any(m.sha == sha for m in rs.merges):
        return Transition(_bump(rs))  # already recorded: the report adds nothing
    return Transition(_bump(rs, merges=(*rs.merges, Merge(sha, event.head_sha))))


def on_effect_unresolved(rs: RunState, event: EffectUnresolvedDuringStop, wf: Any) -> Transition:
    _stopping(rs, "an effect is unresolved")
    return Transition(_bump(rs))


for _register in (handles_graph, handles):
    _register(EffectLandedDuringStop)(on_effect_landed)
    _register(EffectUnresolvedDuringStop)(on_effect_unresolved)
del _register


# --- ports --------------------------------------------------------------------------------------


class Alarm(Protocol):
    def raise_alarm(self, run_id: RunId, name: str, detail: str) -> None: ...


class StepStopper(Protocol):
    """Ends the live step's attempt (and, with D10-06, its session). Called once per Stop try."""

    def stop_step(self, run_id: RunId, stage: str, visit: int, attempt: int) -> None: ...


class GateCloser(Protocol):
    def close_open_gates(self, run_id: RunId) -> int:
        """Close every open gate of the run as cancelled; returns how many. Idempotent."""
        ...


class StopPolicy(Protocol):
    def may_stop(self, actor: str, run_id: RunId) -> bool: ...


class StopNotAllowedError(PermanentError):
    """The actor may not stop this run."""


class ScmReadTimeoutError(TransientError):
    """An SCM read did not answer in time. The Stop tries again; it is never read as "no merge"."""


class GateEligibleStop:
    """Anyone eligible to decide a gate of the run may Stop it. ``eligible(run_id)`` returns the
    people the run's gates name (from the workflow and team config)."""

    def __init__(self, eligible: Callable[[RunId], Iterable[str]]) -> None:
        self._eligible = eligible

    def may_stop(self, actor: str, run_id: RunId) -> bool:
        return bool(actor) and actor in set(self._eligible(run_id))


def cancel_key(run_id: RunId) -> Key:
    return Key(f"RUN#{run_id}", "CANCEL")


def bounded_read[T](read: Callable[[], T], *, timeout: float, pool: ThreadPoolExecutor) -> T:
    """Run an SCM read on ``pool`` with a deadline. A read that hangs ends in
    ``ScmReadTimeoutError`` (transient) and holds one of the pool's own threads, not the API's."""
    future = pool.submit(read)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout:
        future.cancel()
        raise ScmReadTimeoutError(f"the SCM read did not answer within {timeout}s") from None


MergeLookup = Callable[[Effect], MergeResult | None]
RevertWriter = Callable[[RunId, str, str], Receipt]  # run, merge sha, idempotency key


# --- the executor of StopRun ----------------------------------------------------------------------


@dataclass(frozen=True)
class StopSettings:
    stop_timeout: float = 60.0  # PLAN 14.3: all sessions stopped within 60 seconds
    retry_after: float = 1.0
    max_retry_after: float = 30.0
    read_timeout: float = 10.0


class StopExecutor:
    """The ``CommandExecutor`` for ``StopRun``, ``OpenRevert`` and ``Finish``. Idempotent on the
    run: a repeated or replayed ``StopRun`` finds nothing left to stop and reports the same
    ``CancelCompleted``."""

    def __init__(
        self,
        *,
        store: Store,
        scope: Scope,
        effects: EffectExecutor,
        handlers: dict[str, EffectHandler],
        load: Callable[[RunId], RunState],
        clock: Callable[[], float],
        alarm: Alarm,
        lookup: MergeLookup | None = None,
        revert: RevertWriter | None = None,
        steps: StepStopper | None = None,
        gates: GateCloser | None = None,
        settings: StopSettings | None = None,
        read_pool: ThreadPoolExecutor | None = None,
    ) -> None:
        self._store, self._scope, self._fx, self._handlers = store, scope, effects, handlers
        self._load, self._clock, self._alarm = load, clock, alarm
        self._lookup, self._revert, self._steps, self._gates = lookup, revert, steps, gates
        self._s = settings or StopSettings()
        self._pool = read_pool or ThreadPoolExecutor(max_workers=2, thread_name_prefix="sto-scm")
        self._own_pool = read_pool is None
        self._streak: dict[RunId, int] = {}

    def close(self) -> None:
        if self._own_pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    async def execute(self, key: str, command: object) -> Outcome:
        if isinstance(command, StopRun):
            return await self._stop(command.run_id)
        if isinstance(command, OpenRevert):
            return await self._open_revert(command)
        if isinstance(command, Finish):
            if command.incident:
                self._alarm.raise_alarm(
                    command.run_id, "done_with_incident", f"ended {command.status.value}"
                )
            return Done()
        raise TypeError(f"no executor for {type(command).__name__}")

    # --- the Stop ---------------------------------------------------------------------------

    async def _stop(self, run_id: RunId) -> Outcome:
        try:
            events = await asyncio.to_thread(self._stop_once, run_id)
        except Exception as exc:  # noqa: BLE001 - a Stop that fails is retried, never dropped
            return self._failing(run_id, exc)
        if isinstance(events, StillRunning):
            self._check_alarm(run_id, events.reason)
            return events
        self._streak.pop(run_id, None)
        return Done([*events, CancelCompleted(run_id)])

    def _failing(self, run_id: RunId, exc: Exception) -> StillRunning:
        n = self._streak.get(run_id, 0)
        self._streak[run_id] = n + 1
        reason = (
            f"stop_failing:{type(exc).__name__}"  # not "transient:": the budget never ends a Stop
        )
        self._note(run_id, error=f"{type(exc).__name__}: {exc}")
        self._check_alarm(run_id, reason, detail=str(exc))
        delay = min(self._s.retry_after * 2 ** min(n, 6), self._s.max_retry_after)
        return StillRunning(delay, reason)

    def _stop_once(self, run_id: RunId) -> list[object] | StillRunning:
        rs = self._load(run_id)
        report = self._fx.void_planned(run_id)
        events: list[object] = [self._landed(e, rs) for e in report.landed]
        unsettled: list[str] = []
        for effect in report.in_flight:
            outcome = self._reconcile(effect, rs)
            if isinstance(outcome, str):
                unsettled.append(outcome)
            else:
                events.extend(outcome)
        if unsettled:
            self._note(run_id, error="; ".join(unsettled))
            return StillRunning(self._s.retry_after, "stop_pending:" + ",".join(unsettled))
        if self._steps is not None and rs.run.stage is not None and rs.visit > 0:
            self._steps.stop_step(run_id, rs.run.stage, rs.visit, rs.attempt)
        if self._gates is not None:
            self._gates.close_open_gates(run_id)
        return events

    @staticmethod
    def _landed(effect: Effect, rs: RunState) -> object:
        frozen = effect.frozen_subject
        sha = frozen.merge_sha if frozen else None
        head = frozen.head_sha if frozen else None
        if effect.type == "pr.merge" and head is None and rs.subject is not None:
            head = rs.subject.head_sha
        return EffectLandedDuringStop(effect.run_id, effect.type, effect.visit, sha, head)

    def _reconcile(self, effect: Effect, rs: RunState) -> list[object] | str:
        """Events for a tried effect, or a reason it is not settled yet (the Stop stays open)."""
        run_id, key = effect.run_id, effect.idempotency_key
        handler = self._handlers[effect.type]
        try:
            result = self._fx.reconcile(run_id, key, handler)
        except ValueError:
            # The record moved under us (ACCEPTED -> CONFIRMED ...): look at it again next time.
            return f"{effect.type}:moved"
        return self._after_reconcile(effect, result, rs)

    def _after_reconcile(
        self, effect: Effect, result: ExecResult, rs: RunState
    ) -> list[object] | str:
        status = result.effect.status
        if status is EffectStatus.CONFIRMED:
            return [self._landed(result.effect, rs)]
        if status in (EffectStatus.VOIDED, EffectStatus.FAILED):
            return []  # cancelled or refused: it did not land
        if result.reason == "in_flight":
            return f"{effect.type}:in_flight"  # a live attempt: wait for it, never over it
        if not result.blocked:
            return f"{effect.type}:{status.value.lower()}"
        # The handler could not tell (moved head, nothing to dequeue). "No merge visible" is false
        # while one is queued or has landed, so ask the SCM read-only.
        if effect.type != "pr.merge":
            return [EffectUnresolvedDuringStop(effect.run_id, effect.type, effect.visit)]
        if self._lookup is None:
            return f"{effect.type}:no_merge_lookup"  # a merge may have landed: never guess
        found = bounded_read(
            lambda: self._lookup(effect) if self._lookup else None,
            timeout=self._s.read_timeout,
            pool=self._pool,
        )
        if found is not None and found.state is MergeState.MERGED:
            return [
                EffectLandedDuringStop(
                    effect.run_id,
                    effect.type,
                    effect.visit,
                    found.merge_sha,
                    effect.frozen_subject.head_sha
                    if effect.frozen_subject
                    else rs.subject.head_sha
                    if rs.subject
                    else None,
                )
            ]
        if found is not None and found.state is MergeState.PENDING:
            return f"{effect.type}:merge_queued"  # it may still land: the Stop stays open
        return []  # the read succeeded and no merge landed or could

    # --- the alarm and the durable note ---------------------------------------------------------

    def _note(self, run_id: RunId, *, error: str) -> None:
        for _ in range(3):
            item = self._store.get(self._scope, cancel_key(run_id))
            data: dict[str, Any] = dict(item.data) if item else {"requested_at": self._clock()}
            data["attempts"] = int(data.get("attempts", 0)) + 1
            data["last_error"] = error
            when = VersionIs(item.version) if item else Absent()
            try:
                self._store.transact(self._scope, [Put(cancel_key(run_id), data, when=when)])
                return
            except (ConditionFailedError, TransactionConflictError):
                continue

    def _check_alarm(self, run_id: RunId, reason: str, *, detail: str = "") -> None:
        raise_stuck_stop_alarm(
            self._store, self._scope, run_id, self._clock(), self._s.stop_timeout, self._alarm,
            detail or reason,
        )  # fmt: skip

    # --- the revert ---------------------------------------------------------------------

    async def _open_revert(self, cmd: OpenRevert) -> Outcome:
        if self._revert is None:
            raise TypeError("no revert writer configured")
        revert = self._revert
        digest = hashlib.sha256(cmd.merge_sha.encode()).hexdigest()
        fx = self._fx

        def run() -> Outcome:
            planned = fx.plan(
                cmd.run_id,
                "pr.open_revert",
                f"revert:{cmd.merge_sha}",
                1,
                EffectClass.SCOPED,
                digest,
            )
            handler = CallHandler(lambda k: revert(cmd.run_id, cmd.merge_sha, k))
            result = fx.execute(cmd.run_id, planned.idempotency_key, handler)
            status = result.effect.status
            if result.blocked:
                self._alarm.raise_alarm(
                    cmd.run_id, "revert_blocked", f"revert of {cmd.merge_sha} needs a person"
                )
                return Done()
            if status in (EffectStatus.CONFIRMED, EffectStatus.FAILED, EffectStatus.VOIDED):
                return Done()
            return StillRunning(self._s.retry_after, f"revert:{status.value.lower()}")

        return await asyncio.to_thread(run)


# --- the alarm ----------------------------------------------------------------------------------


def raise_stuck_stop_alarm(
    store: Store,
    scope: Scope,
    run_id: RunId,
    now: float,
    timeout: float,
    alarm: Alarm,
    detail: str,
) -> bool:
    """Raise ``stuck_stop`` once if the Stop was requested more than ``timeout`` ago. The request
    time and the raised flag live in the store, so a restart does not forget or repeat it."""
    for _ in range(3):
        item = store.get(scope, cancel_key(run_id))
        if item is None:
            return False
        data = dict(item.data)
        requested = float(data.get("requested_at", now))
        if data.get("alarmed") or now - requested < timeout:
            return False
        data["alarmed"] = True
        try:
            store.transact(scope, [Put(cancel_key(run_id), data, when=VersionIs(item.version))])
        except (ConditionFailedError, TransactionConflictError):
            continue
        alarm.raise_alarm(
            run_id,
            "stuck_stop",
            f"stopping for {now - requested:.0f}s (limit {timeout:.0f}s): {detail}",
        )
        return True
    return False


class StopWatch:
    """The alarm for a Stop nobody is driving (a dead run): sweep the active runs and raise
    ``stuck_stop`` for each whose Stop was requested more than ``timeout`` ago and has not
    finished. The request note decides, not the run's status: with no driver alive the request is
    still in the inbox and the run has not yet reached CANCELLING."""

    def __init__(
        self,
        *,
        store: Store,
        scope: Scope,
        active_runs: Callable[[], Awaitable[list[RunId]]],
        load: Callable[[RunId], RunState],
        clock: Callable[[], float],
        alarm: Alarm,
        timeout: float = 60.0,
    ) -> None:
        self._store, self._scope, self._active, self._load = store, scope, active_runs, load
        self._clock, self._alarm, self._timeout = clock, alarm, timeout

    async def sweep(self) -> list[RunId]:
        raised: list[RunId] = []
        for run_id in await self._active():
            if self._load(run_id).run.status.is_terminal:
                continue  # over: nothing is stuck (the request note decides for the rest)
            if await asyncio.to_thread(
                raise_stuck_stop_alarm, self._store, self._scope, run_id, self._clock(),
                self._timeout, self._alarm, "no driver finished the Stop",
            ):  # fmt: skip
                raised.append(run_id)
        return raised


# --- closing gates ------------------------------------------------------------------------------


class StoreGateCloser:
    """Closes a run's open gates as CANCELLED straight in the store, conditional on each gate's
    version, so a decision racing the Stop wins or loses cleanly. A gate closed this way is no
    longer ``OPEN``, so ``GateService.decide`` refuses a later decision on it. It writes no
    audit-chain entry (the gate service owns the chain: a ``GateService.cancel_open`` is the
    follow-up that adds one)."""

    def __init__(self, store: Store, scope: Scope) -> None:
        self._store, self._scope = store, scope

    def close_open_gates(self, run_id: RunId) -> int:
        closed, cursor = 0, None
        while True:
            page = self._store.query(self._scope, f"RUN#{run_id}", sk_prefix="GATE#", cursor=cursor)
            for item in page.items:
                gate = from_wire(Gate, item.data)
                if not gate.is_open:
                    continue
                done = gate.advance(GateStatus.CANCELLED, closed_by="system:cancel")
                try:
                    self._store.transact(
                        self._scope, [Put(item.key, to_wire(done), when=VersionIs(item.version))]
                    )
                    closed += 1
                except (ConditionFailedError, TransactionConflictError):
                    # a decision won the race for this gate: look again, once
                    fresh = self._store.get(self._scope, item.key)
                    if fresh is not None and from_wire(Gate, fresh.data).is_open:
                        raise TransientError(f"gate {gate.name!r} kept changing") from None
            cursor = page.cursor
            if cursor is None:
                return closed


# --- the audited service ------------------------------------------------------------------------


class CancelAudit(Protocol):
    def record(self, run_id: RunId, action: str, actor: str, data: dict[str, object]) -> None: ...


class CancelService:
    """A person's Stop. Order: check who, audit, note the request time, quiet the background
    re-drive, submit the event. ``quiesce`` ends the driver's background re-drives for the run
    (``LocalDriver.stop_background``); ``submit`` queues the event (``LocalDriver.submit``)."""

    def __init__(
        self,
        *,
        policy: StopPolicy,
        audit: CancelAudit,
        store: Store,
        scope: Scope,
        clock: Callable[[], float],
        submit: Callable[[RunId, object], Awaitable[None]],
        load: Callable[[RunId], RunState],
        quiesce: Callable[[RunId], Awaitable[None]] | None = None,
    ) -> None:
        self._policy, self._audit, self._store, self._scope = policy, audit, store, scope
        self._clock, self._submit, self._load, self._quiesce = clock, submit, load, quiesce

    async def stop(self, run_id: RunId, actor: str, reason: str) -> CancelRequested:
        if not isinstance(actor, str) or not actor.strip():
            raise MalformedEventError("a stop names the person who asked for it")
        if not isinstance(reason, str) or not reason.strip():
            raise MalformedEventError("a stop gives a reason")
        if not self._policy.may_stop(actor, run_id):
            raise StopNotAllowedError(f"{actor!r} may not stop run {run_id}")
        status = self._load(run_id).run.status
        if status.is_terminal:
            raise OutOfOrderEventError(f"run {run_id} already ended ({status.value})")
        event = CancelRequested(run_id)
        if status is not RunStatus.CANCELLING:
            self._audit.record(run_id, "run.cancel", actor, {"reason": reason})
        self._note_request(run_id)
        if self._quiesce is not None:
            await self._quiesce(run_id)
        await self._submit(run_id, event)  # a second Stop is refused by the run, harmlessly
        return event

    def _note_request(self, run_id: RunId) -> None:
        first = {"requested_at": self._clock(), "attempts": 0}
        with contextlib.suppress(ConditionFailedError):  # the first request's time stands
            self._store.transact(self._scope, [Put(cancel_key(run_id), first, Absent())])


__all__ = [
    "Alarm",
    "CancelAudit",
    "CancelService",
    "EffectLandedDuringStop",
    "EffectUnresolvedDuringStop",
    "GateCloser",
    "GateEligibleStop",
    "ScmReadTimeoutError",
    "StepStopper",
    "StopExecutor",
    "StopNotAllowedError",
    "StopPolicy",
    "StopSettings",
    "StopWatch",
    "StoreGateCloser",
    "bounded_read",
    "cancel_key",
    "raise_stuck_stop_alarm",
]
