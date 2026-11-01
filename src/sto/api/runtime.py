"""What the API runs on (D1-08): the local driver, driven in the background, and the one place
that turns a gate decision into an event for the run.

**No request holds work open.** A request records something durable (a run, a decision, a cancel)
and returns; ``kick`` then drives the run in a background task. Every submit is followed by a
``kick``, because ``submit`` has no wake-up of its own. At most one task drives a run, and a kick
that arrives while it is busy makes it drive once more when it ends (``run_until_idle`` on a run
this instance is already driving waits and then drives again, so an event queued after the last
read is never stranded). Only ``run_until_idle`` is used, never the public ``step``, which skips
the per-run guard. Every task is referenced until it ends, and an exception is logged and kept
(``driver_error``), never dropped.

**A Stop does not wait out a backoff.** The driver sleeps between polls of a command that is not
finished (``StillRunning``), and a RETRYING effect backs off for up to a minute. The driver's
sleep is replaced by one that a submit for *that run* cuts short, so the Stop is applied at once.
Other runs' submits do not wake it (that would call the effect again before its time).

**A gate decision is two commits** (the gate service's, then the run's inbox), until the outbox
relay delivers them (D3-11). A crash in between would leave the gate closed and the run waiting
for ever, so the decision is *redelivered*: at startup for every active run, and whenever a
decision hits a closed gate. A run that is WAITING_HUMAN at a gate that is closed in the store
and has nothing queued is missing exactly that event. Delivery and redelivery of one run are
serialised, so the event is queued once.

Single process, single team (local mode). The locks and wake-ups are in memory.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator, Mapping
from typing import Any, Literal

from sto.adapters.ports import MergeMethod, PrRef, ScmProvider
from sto.domain import Decision as DecisionRecord
from sto.domain import (
    DecisionKind,
    Effect,
    Gate,
    GateType,
    PermanentError,
    Run,
    RunId,
    RunStatus,
    Subject,
    TransientError,
    from_wire,
)
from sto.effects.core import EffectExecutor
from sto.effects.ports import EffectHandler, Failed, MergeHandler, Outcome, Voided
from sto.engine.commands import Finish, OpenGate, RunEffect, RunStep, StopRun
from sto.engine.drivers.local import EffectsExecutor, LeaseHeldError, LocalDriver
from sto.engine.drivers.ports import CommandExecutor, Done, StillRunning
from sto.engine.drivers.ports import Outcome as CommandOutcome
from sto.engine.handlers.core import CancelCompleted, CancelRequested, GateClosed
from sto.engine.reducer import LINEAR_V0, RunState, Workflow, load_handlers
from sto.gates.service import Decided, GateService
from sto.store.ports import (
    Absent,
    ConditionFailedError,
    Item,
    Key,
    Store,
    TeamScope,
    TransactionConflictError,
)

log = logging.getLogger("sto.api")

API_INDEX = "RUNS_API"  # the API's own list of runs: the driver's index drops finished ones
_STORE_ATTEMPTS = 8
_DRIVE_ATTEMPTS = 6
_COOLDOWN_CAP = 30.0
_RUN: contextvars.ContextVar[RunId | None] = contextvars.ContextVar("sto_api_run", default=None)

MergeFactory = Callable[[Effect], EffectHandler]
LiveSubject = Callable[[RunEffect], Subject]


class StoreConflictError(TransientError):
    """The store kept conflicting until the retries ran out. Nothing was written. Retry."""


class DeliveryFailedError(TransientError):
    """The decision is recorded (the gate is closed) but could not be queued for the run. A
    retry of the decision hits the closed gate and queues it then; so does a restart."""

    def __init__(self, cause: BaseException) -> None:
        # The client gets a fixed message; what went wrong is logged where it happened.
        self.decision_recorded = True
        self.__cause__ = cause
        super().__init__("the decision was recorded but could not be delivered to the run yet")


class BadCursorError(PermanentError):
    pass


class RunNotFoundError(PermanentError):
    pass


class RunFinishedError(PermanentError):
    pass


# --- the dispatcher: one executor for every command --------------------------------------------


class _ByEffect:
    """An ``EffectHandler`` that builds the real handler *from the effect* on every call. The
    effects service picks a handler by effect type, but a merge handler is built per PR, so it
    cannot be built before the effect is known."""

    def __init__(self, build: MergeFactory) -> None:
        self._build = build

    def execute(self, effect: Effect) -> Outcome:
        return self._build(effect).execute(effect)

    def poll(self, effect: Effect) -> Outcome:
        return self._build(effect).poll(effect)

    def stop(self, effect: Effect) -> Outcome:
        return self._build(effect).stop(effect)

    def reconcile(self, effect: Effect) -> Outcome:
        return self._build(effect).reconcile(effect)


class _Handlers(Mapping[str, EffectHandler]):
    def __init__(self, merges: MergeFactory) -> None:
        self._by_type: dict[str, EffectHandler] = {"pr.merge": _ByEffect(merges)}

    def __getitem__(self, effect_type: str) -> EffectHandler:
        return self._by_type[effect_type]

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_type)

    def __len__(self) -> int:
        return len(self._by_type)


class _Refusing:
    """The handler for an effect whose approved subject cannot be found: it writes nothing."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def execute(self, effect: Effect) -> Outcome:
        return Failed(None, self._reason)

    def poll(self, effect: Effect) -> Outcome:
        return Failed(None, self._reason)

    def stop(self, effect: Effect) -> Outcome:
        return Voided(self._reason)

    def reconcile(self, effect: Effect) -> Outcome:
        return Voided(self._reason)


def scm_merge_factory(
    scm: ScmProvider,
    store: Store,
    scope: TeamScope,
    pr_for: Callable[[RunId], PrRef],
    method: MergeMethod,
) -> MergeFactory:
    """Build the ``pr.merge`` handler for an effect: the PR is the run's, and the subject and head
    are those the gates approved (the gate whose subject has the effect's digest)."""

    def build(effect: Effect) -> EffectHandler:
        subject = _approved_subject(store, scope, effect)
        if subject is None or subject.head_sha is None:
            return _Refusing("subject_unknown")
        return MergeHandler(scm, pr_for(effect.run_id), subject.head_sha, method, subject)

    return build


def _approved_subject(store: Store, scope: TeamScope, effect: Effect) -> Subject | None:
    cursor: str | None = None
    while True:
        page = store.query(scope, f"RUN#{effect.run_id}", sk_prefix="GATE#", cursor=cursor)
        for item in page.items:
            subject = from_wire(Gate, item.data).subject
            if subject.digest() == effect.subject_digest:
                return subject
        cursor = page.cursor
        if cursor is None:
            return None


class _Commands:
    """Everything the driver can ask for: gates are opened here, effects go to the effects
    service, steps to the step executor, and Stop and Finish need nothing outside the run."""

    def __init__(
        self,
        gates: GateService,
        scope: TeamScope,
        steps: CommandExecutor,
        status_of: Callable[[RunId], RunStatus],
        wait: float,
    ):
        self._gates, self._scope, self._steps = gates, scope, steps
        self._status_of, self._wait = status_of, wait

    async def execute(self, key: str, command: object) -> CommandOutcome:
        if isinstance(command, OpenGate):
            try:
                await asyncio.to_thread(self._gates.open_gate, self._scope, command)
            except TransientError as e:  # contention, a store conflict: try again shortly
                return StillRunning(self._wait, f"transient:{type(e).__name__}")
            return Done()  # a person decides; the decision arrives as an event
        if isinstance(command, StopRun):
            return Done([CancelCompleted(command.run_id)])
        if isinstance(command, Finish):
            return Done()
        if isinstance(command, RunStep):
            status = await asyncio.to_thread(self._status_of, command.run_id)
            if status.is_terminal or status is RunStatus.CANCELLING:
                return Done()  # the run was stopped while this step waited: do not start it
            return await self._steps.execute(key, command)
        raise TypeError(f"no executor for {type(command).__name__}")


class _TaggedDriver(LocalDriver):
    """Tells the sleep which run it is sleeping for, however the drive was started (a kick, or
    a start-up kick, which calls ``run_until_idle`` per run)."""

    async def run_until_idle(self, run_id: RunId) -> RunState:
        token = _RUN.set(run_id)
        try:
            return await super().run_until_idle(run_id)
        finally:
            _RUN.reset(token)


# --- the runtime --------------------------------------------------------------------------------


class Runtime:
    def __init__(
        self,
        store: Store,
        scope: TeamScope,
        *,
        gates: GateService,
        effects: EffectExecutor,
        steps: CommandExecutor,
        merges: MergeFactory,
        live: LiveSubject,
        workflow: Workflow = LINEAR_V0,
        clock: Callable[[], float] = time.time,
        new_id: Callable[[], str] = lambda: uuid.uuid4().hex,
        owner: str = "api",
        poll_interval: float = 1.0,
        lease_seconds: float = 30.0,
        backoff: float = 0.01,
        api_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        cooldown: float = 1.0,
        mono: Callable[[], float] = time.monotonic,
    ) -> None:
        load_handlers()  # before anything stored is decoded (the driver needs the registries)
        self.store, self.scope, self._wf = store, scope, workflow
        self._gates = gates
        self._api_sleep, self._backoff = api_sleep, backoff
        self._cooldown, self._mono = cooldown, mono
        self._wake: dict[RunId, asyncio.Event] = {}
        self._tasks: dict[RunId, asyncio.Task[None]] = {}
        self._again: set[RunId] = set()
        self._errors: dict[RunId, str] = {}
        self._locks: dict[RunId, asyncio.Lock] = {}
        self._delivery_errors: dict[RunId, str] = {}
        self._redeliveries: dict[RunId, asyncio.Task[None]] = {}
        self._startup_failed = False
        self._startup_task: asyncio.Task[None] | None = None
        self._cool: dict[RunId, tuple[float, float]] = {}
        self._lease_wait = lease_seconds
        self._started = False

        def status_of(run_id: RunId) -> RunStatus:
            return self.driver.state(run_id).run.status

        adapter = EffectsExecutor(
            effects,
            _Handlers(merges),
            live,
            status_of,
            others=_Commands(gates, scope, steps, status_of, poll_interval),
            poll_interval=poll_interval,
        )
        self.driver = _TaggedDriver(
            store,
            scope,
            workflow,
            adapter,
            owner=owner,
            clock=clock,
            new_id=new_id,
            lease_seconds=lease_seconds,
            resume_wait=lease_seconds,
            sleep=self._sleep,
            backoff=backoff,
        )

    # --- life cycle ---------------------------------------------------------------------------

    async def start(self) -> None:
        """Bring the runs back from the store alone: for every unfinished run, redeliver a
        decision that was recorded but never queued (retried in the background until it works,
        and shown on the run meanwhile), then drive it. Each run is driven on its own, so a run
        that polls cannot hide another's failure, which is reported as soon as that run ends.
        If the runs cannot be listed, that is retried in the background (and shown as
        ``degraded``) until it works; nothing resumes before then."""
        if self._started:
            return
        self._started = True
        load_handlers()
        try:
            await self._list_and_resume()
        except asyncio.CancelledError:
            raise
        except Exception as e:  # not listing the runs is not fatal: keep trying in the background
            log.error("listing the unfinished runs failed: %r", e, exc_info=e)
            self._startup_task = asyncio.get_running_loop().create_task(
                self._retry_until_done(self._list_and_resume, "listing the runs"), name="startup"
            )

    async def _list_and_resume(self) -> None:
        try:
            run_ids = await self.driver.active_runs()
        except asyncio.CancelledError:
            raise
        except Exception:
            self._startup_failed = True  # logged by the caller, once per failure
            raise
        self._startup_failed = False
        for run_id in run_ids:
            try:
                await self.redeliver(run_id)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # one bad run must not stop the API from starting
                self._delivery_failed(run_id, e)
            self.kick(run_id)  # the lease of a dead driver is waited for (see _drive_with_retries)

    def _delivery_failed(self, run_id: RunId, error: BaseException) -> None:
        """Keep the error on the run and retry the redelivery until it works."""
        self._delivery_errors[run_id] = f"{type(error).__name__}: {error}"
        log.error("redelivering the decision of run %s failed: %r", run_id, error, exc_info=error)
        if run_id not in self._redeliveries:
            task = asyncio.get_running_loop().create_task(
                self._retry_until_done(
                    lambda: self.redeliver(run_id), f"redelivery for run {run_id}"
                ),
                name=f"redeliver:{run_id}",
            )
            self._redeliveries[run_id] = task
            task.add_done_callback(lambda _t: self._redeliveries.pop(run_id, None))

    async def _retry_until_done(self, attempt: Callable[[], Awaitable[object]], what: str) -> None:
        """Try again, doubling the wait up to a cap, until it works (shared by the start-up
        listing and by redelivery)."""
        delay = self._backoff
        while True:
            await self._api_sleep(delay)
            try:
                await attempt()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("%s failed again: %r", what, e)  # no traceback: the first has one
                delay = min(delay * 2, 5.0)
            else:
                return

    async def close(self) -> None:
        tasks = [*self._tasks.values(), *self._redeliveries.values()]
        if self._startup_task is not None:
            tasks.append(self._startup_task)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        self._redeliveries.clear()
        # Give the runs up, so the next process need not wait for the leases to run out. The
        # driver has no public release yet (a D1-03 follow-up); it ignores a lease that is not ours.
        try:
            for run_id in await self.driver.active_runs():
                try:
                    await self.driver._release(run_id)
                except Exception as e:
                    log.warning("could not release the lease of run %s: %r", run_id, e)
        except Exception as e:
            log.warning("could not list the runs to release their leases: %r", e)

    def background_tasks(self) -> list[asyncio.Task[None]]:
        """Every task still running for the API (drives, and redelivery retries)."""
        tasks = [*self._tasks.values(), *self._redeliveries.values()]
        if self._startup_task is not None:
            tasks.append(self._startup_task)
        return [t for t in tasks if not t.done()]

    # --- driving ------------------------------------------------------------------------------

    def kick(self, run_id: RunId) -> None:
        """Drive the run in the background; call it after every submit. If a task is already
        driving the run it drives once more when it ends, so nothing queued meanwhile waits."""
        self._again.add(run_id)
        if run_id in self._tasks:
            return
        task = asyncio.get_running_loop().create_task(self._loop(run_id), name=f"drive:{run_id}")
        self._tasks[run_id] = task  # held here until the loop ends; not just by the event loop

    async def _loop(self, run_id: RunId) -> None:
        try:
            while run_id in self._again:
                self._again.discard(run_id)
                try:
                    await self._drive_with_retries(run_id)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self._report(run_id, e)
                    self._cool_down(run_id)
                else:
                    self._errors.pop(run_id, None)
                    if self.driver.held(run_id) is None:
                        self._cool.pop(run_id, None)
                    else:
                        self._cool_down(run_id)  # a held command is retried after the cool-down
        finally:
            # No await between the loop test and here, so a kick cannot slip in unseen.
            self._tasks.pop(run_id, None)

    async def _drive_with_retries(self, run_id: RunId) -> None:
        """A transient error (a store that kept conflicting, or a version race lost eight times)
        ends one drive, not the run: retry with backoff before giving up. A run still leased by a
        dead driver is waited for, up to one lease. Anything else is a fault and surfaces
        at once."""
        delay, waited = self._backoff, 0.0
        for attempt in range(_DRIVE_ATTEMPTS):
            while True:
                try:
                    await self.driver.run_until_idle(run_id)
                    return
                except LeaseHeldError as held:
                    if waited + held.remaining > self._lease_wait:
                        raise
                    await self._api_sleep(held.remaining)  # the dead driver's lease runs out
                    waited += held.remaining
                except (TransientError, ConditionFailedError) as e:
                    if attempt == _DRIVE_ATTEMPTS - 1:
                        raise
                    log.warning("driving run %s hit %r; retrying", run_id, e)
                    await self._api_sleep(delay)
                    delay = min(delay * 2, 1.0)
                    break

    def _cool_down(self, run_id: RunId) -> None:
        """After a failed drive, requests that would only *re-drive* wait: the first for one
        cool-down, then twice as long each time, up to ``_COOLDOWN_CAP``; a success resets it.
        Without this, a client polling a failing run would re-execute its step on every poll."""
        if self._cooldown <= 0:
            return
        previous = self._cool.get(run_id, (0.0, self._cooldown / 2))[1]
        delay = min(previous * 2, _COOLDOWN_CAP)
        self._cool[run_id] = (self._mono() + delay, delay)

    async def _ensure_driven(self, run_id: RunId, *, force: bool = False) -> None:
        """Drive the run if it has work and nobody is driving it. Called by every per-run
        request, so a run whose drive died is picked up again by whoever asks about it, subject
        to the cool-down (``force`` skips it: a Stop must always get through). Never raises: a
        read must not fail because this could not tell."""

        def may_drive() -> bool:
            cooling = self._cool.get(run_id)
            return run_id not in self._tasks and (
                force or cooling is None or self._mono() >= cooling[0]
            )

        if not may_drive():
            return
        try:
            busy = await self._store(self._has_work, run_id)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("could not tell whether run %s has work: %r", run_id, e)
            return
        # Looked again after the read: many requests at once all pass the first check, and only
        # the first may start a drive (a kick on a live drive would make it run twice more).
        if busy and may_drive():
            self.kick(run_id)

    def _has_work(self, run_id: RunId) -> bool:
        """Is something queued (an event not applied, a command not done)? The driver has no
        public accessor for the command log, so this reads its record (a D1-03 follow-up)."""
        try:
            rec = self.driver._load(run_id)
        except KeyError:
            return False
        return bool(rec.inbox or rec.pending)

    def _report(self, run_id: RunId, error: BaseException) -> None:
        self._errors[run_id] = f"{type(error).__name__}: {error}"
        log.error("driving run %s failed: %r", run_id, error, exc_info=error)

    def errors(self) -> int:
        """How many runs have an error on them (a drive that failed, or a redelivery that did)."""
        return len(self._errors.keys() | self._delivery_errors.keys())

    def degraded(self) -> bool:
        """Something needs a person: a run with an error, or start-up could not list the runs."""
        return self._startup_failed or self.errors() > 0

    def driver_error(self, run_id: RunId) -> str | None:
        """What is wrong with this run, if anything: a decision that could not be delivered
        (until it is), else the exception that ended its last drive. A run's error clears only
        when that run's own later drive (or redelivery) succeeds."""
        return self._delivery_errors.get(run_id) or self._errors.get(run_id)

    async def _sleep(self, seconds: float) -> None:
        """The driver's sleep: cut short by a submit for the run it is sleeping for."""
        run_id = _RUN.get()
        if run_id is None:
            await asyncio.sleep(seconds)
            return
        event = self._wake.setdefault(run_id, asyncio.Event())
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(event.wait(), seconds)
        event.clear()

    async def submit(self, run_id: RunId, event: object) -> None:
        """Queue an event (durable once this returns), wake the run's sleep and drive it."""
        try:
            await self.driver.submit(run_id, event)
        except (TransactionConflictError, ConditionFailedError) as e:
            raise StoreConflictError("the store kept conflicting; try again") from e
        self._wake.setdefault(run_id, asyncio.Event()).set()
        self.kick(run_id)

    # --- store access with retries ------------------------------------------------------------

    async def _store[T](self, fn: Callable[..., T], *args: Any) -> T:
        delay = self._backoff
        for attempt in range(_STORE_ATTEMPTS):
            try:
                return await asyncio.to_thread(fn, *args)
            except TransactionConflictError as e:
                if attempt == _STORE_ATTEMPTS - 1:
                    raise StoreConflictError("the store kept conflicting; try again") from e
                await self._api_sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")  # pragma: no cover

    # --- runs ---------------------------------------------------------------------------------

    async def create_run(self, ticket: str | None) -> Run:
        run = Run(id=RunId.new(), team=self.scope.team)
        await self._store(
            lambda: self.store.put(
                self.scope, Key(API_INDEX, str(run.id)), {"ticket": ticket}, when=Absent()
            )
        )
        try:
            await self.driver.start(run)
        except TransactionConflictError as e:
            raise StoreConflictError("the store kept conflicting; try again") from e
        self.kick(run.id)
        return run

    def state(self, run_id: RunId) -> RunState:
        try:
            return self.driver.state(run_id)
        except KeyError:
            raise RunNotFoundError(f"no run {run_id}") from None

    def _view(self, run_id: RunId, item: Item | None) -> dict[str, Any] | None:
        try:
            run = self.driver.state(run_id).run
        except KeyError:
            return None  # indexed, but the process died before it was started
        return {
            "id": str(run.id),
            "status": run.status.value,
            "stage": run.stage,
            "blocked_reason": run.blocked_reason,
            "ticket": item.data.get("ticket") if item else None,
            "held": self.driver.held(run_id),
            "driver_error": self.driver_error(run_id),
        }

    async def get_run(self, run_id: RunId) -> dict[str, Any]:
        await self._ensure_driven(run_id)

        def read() -> dict[str, Any] | None:
            return self._view(run_id, self.store.get(self.scope, Key(API_INDEX, str(run_id))))

        view = await self._store(read)
        if view is None:
            raise RunNotFoundError(f"no run {run_id}")
        return view

    async def list_runs(self, limit: int, cursor: str | None) -> tuple[list[dict[str, Any]], Any]:
        def read() -> tuple[list[dict[str, Any]], str | None]:
            try:
                page = self.store.query(self.scope, API_INDEX, limit=limit, cursor=cursor)
            except ValueError as e:  # only the query refuses a cursor; reading a run is not that
                raise BadCursorError("that cursor is not valid") from e
            views = [self._view(RunId.parse(i.key.sk), i) for i in page.items]
            return [v for v in views if v is not None], page.cursor

        return await self._store(read)

    async def _astate(self, run_id: RunId) -> RunState:
        return await self._store(self.state, run_id)

    async def events(self, run_id: RunId, after: int, limit: int) -> list[dict[str, Any]]:
        """Timeline entries with ``seq`` above ``after``, oldest first."""
        await self._astate(run_id)  # 404 for an unknown run
        await self._ensure_driven(run_id)
        everything = await self._store(self.driver.timeline, run_id)
        return [e for e in everything if e["seq"] > after][:limit]

    async def can_stop(self, run_id: RunId) -> bool:
        """Is there anything left to stop? (A finished or already stopping run offers no Stop.)"""
        try:
            status = (await self._astate(run_id)).run.status
        except RunNotFoundError:
            return False
        return not (status.is_terminal or status is RunStatus.CANCELLING)

    async def cancel(self, run_id: RunId) -> None:
        status = (await self._astate(run_id)).run.status
        if status.is_terminal or status is RunStatus.CANCELLING:
            # A Stop whose drive died leaves the run CANCELLING with the StopRun queued: the
            # repeat is refused, but it still gets the run driven again.
            await self._ensure_driven(run_id, force=True)  # a Stop always gets through
            raise RunFinishedError(f"run {run_id} is already {status.value}")
        await self.submit(run_id, CancelRequested(run_id))

    # --- gates --------------------------------------------------------------------------------

    def _lock(self, run_id: RunId) -> asyncio.Lock:
        return self._locks.setdefault(run_id, asyncio.Lock())

    async def gates(self, run_id: RunId) -> list[Gate]:
        await self._astate(run_id)
        await self._ensure_driven(run_id)

        def read() -> list[Gate]:
            found: list[Gate] = []
            cursor: str | None = None
            while True:
                page = self.store.query(
                    self.scope, f"RUN#{run_id}", sk_prefix="GATE#", cursor=cursor
                )
                found += [from_wire(Gate, i.data) for i in page.items]
                cursor = page.cursor
                if cursor is None:
                    return sorted(found, key=lambda g: str(g.id))

        return await self._store(read)

    async def decide(
        self,
        run_id: RunId,
        gate: str,
        round: int,
        kind: DecisionKind,
        *,
        actor: str,
        surface: Any,
        subject_digest: str,
        comment: str,
    ) -> Decided:
        """Close the gate (the one decision function), then queue the decision for the run. The
        gate is closed for good once ``decide`` returns; if queueing it fails, ``DeliveryFailed``
        says so and a retry or a restart finishes the delivery."""
        await self._astate(run_id)  # no lock (and no memory) for a run that does not exist
        async with self._lock(run_id):
            try:
                decided = await asyncio.to_thread(
                    lambda: self._gates.decide(
                        self.scope,
                        run_id=run_id,
                        gate=gate,
                        round=round,
                        kind=kind,
                        actor=actor,
                        surface=surface,
                        subject_digest=subject_digest,
                        comment=comment,
                    )
                )
            except PermanentError as e:
                if getattr(e, "code", None) == "gate_closed":
                    # Someone closed it. If their delivery never happened, do it now.
                    try:
                        await self._redeliver_locked(run_id)
                    except (ValueError, TypeError):
                        raise  # stored data the domain refuses: a server fault, not a retry
                    except Exception as d:  # the delivery is what failed, not the decision
                        log.error("redelivery for run %s failed: %r", run_id, d)
                        raise DeliveryFailedError(d) from d
                # Whatever is queued for this run must not wait for a drive that died.
                await self._ensure_driven(run_id)
                raise
            event = _closed_event(decided.gate, decided.decision)
            try:
                await self.submit(run_id, event)
            except (ValueError, TypeError):
                raise
            except Exception as e:
                log.error("decision for run %s recorded but not delivered: %r", run_id, e)
                raise DeliveryFailedError(e) from e
            return decided

    async def redeliver(self, run_id: RunId) -> bool:
        """Queue the decision of a closed gate the run never heard about. True if one was."""
        async with self._lock(run_id):
            delivered = await self._redeliver_locked(run_id)
        self._delivery_errors.pop(run_id, None)
        return delivered

    async def _redeliver_locked(self, run_id: RunId) -> bool:
        def missing() -> GateClosed | Literal["queued"] | None:
            try:
                rs = self.driver.state(run_id)
            except KeyError:
                return None
            if rs.run.status is not RunStatus.WAITING_HUMAN or rs.run.stage is None:
                return None
            if self.driver.pending_events(run_id):
                return "queued"  # it will be applied first
            item = self.store.get(
                self.scope, Key(f"RUN#{run_id}", f"GATE#{rs.run.stage}#{rs.round}")
            )
            if item is None:
                return None
            gate = from_wire(Gate, item.data)
            if gate.is_open or gate.type is GateType.PRE_PUSH:
                return None
            page = self.store.query(
                self.scope, f"RUN#{run_id}", sk_prefix=f"DEC#{gate.name}#{gate.round}#"
            )
            if not page.items:
                return None
            return _closed_event(gate, from_wire(DecisionRecord, page.items[0].data))

        event = await self._store(missing)
        if event == "queued":
            await self._ensure_driven(run_id)  # queued work must not wait for a dead drive
            return False
        if event is None:
            return False
        await self.submit(run_id, event)
        return True


def _closed_event(gate: Gate, decision: DecisionRecord) -> GateClosed:
    approving = decision.kind in (DecisionKind.APPROVE, DecisionKind.WAIVE)
    return GateClosed(
        gate.run_id,
        gate.name,
        gate.round,
        decision.kind,
        decision.actor,
        decision.id,
        gate.subject if approving else None,
    )


__all__ = [
    "API_INDEX",
    "CancelRequested",
    "DeliveryFailedError",
    "LiveSubject",
    "MergeFactory",
    "RunFinishedError",
    "RunNotFoundError",
    "Runtime",
    "StoreConflictError",
    "scm_merge_factory",
]
