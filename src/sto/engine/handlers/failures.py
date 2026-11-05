"""Failure classes and retry (D2-10, PLAN 6.2).

Four parts. The engine reads no clock (a purity test enforces it), so the clock is injected;
the service and re-driver take their other collaborators the same way:

* ``classify``: an error is exactly one ``FailureClass``. It fails closed: an unknown error is
  permanent, a retryable HTTP status never promotes a ``PermanentError``, and a ``TransientError``
  that carries a permanent status (401, 403, 422, ...) is permanent. D1-03 carried this over:
  permanent errors do arrive as transient.
* ``call_with_retry`` / ``acall_with_retry``: the one retry layer around an external call (PLAN
  6.2). Doubling backoff, each delay capped, and a cap on *total* time, so a persistent transient
  error ends in ``RetryBudgetExceededError`` (permanent) instead of backing off for ever. A
  permanent error is called once. Inner clients must use ``total_max_attempts=1``.
* ``RetryRequested`` and its graph handler: a person's Retry of a BLOCKED run. It re-runs the
  blocked step at a new attempt (same visit), or re-plans the blocked effect (same visit, so the
  same idempotency key). It touches no counter: visits, loops, steps and merges are as they were,
  so a spent loop stays spent, and it only accepts blocks that are failures of a step or effect.
  ``loop_exhausted``, ``max_steps_exceeded``, ``gate_invalid``, ``subject_missing``,
  ``stage_unsupported`` and ``head_moved`` are refused, because retrying would step past the
  guard that raised them (PLAN 6.2: Retry only re-runs a step). Like the other graph handlers it is
  pure and deterministic; a stale, duplicate or terminal-run Retry is refused.
* ``RetryService``: the audited path. It checks the Retry would apply, writes the audit record,
  stops the earlier attempt, clears an effect's block with ``EffectExecutor.retry_blocked`` and only
  then submits the event. An unaudited Retry never runs.
* ``Redriver``: a drive that gave up on a transient error is driven again in the background, with
  the same capped backoff. A BLOCKED run is returned as it is and never driven again (R1).

One click buys one step attempt: it is numbered past the stage's ``max_attempts``, and
``handlers/stages.py`` compares ``attempt < max_attempts``, so a transient failure of it blocks
again at once. One click on an effect buys one executor call, which has its own retry layer
(``retry_blocked`` allows ``max_attempts`` more). Both match PLAN 6.2.

Only a *blocked* effect (unknown outcome) is retryable. A FAILED or VOIDED effect shows as its own
block (``effect_failed_permanently``, ``effect_voided``, ``gate_invalid``; ``EffectFailed.reason``)
and a Retry is refused with the reason in ``NOT_RETRYABLE_WHY``, because the executor would replay
the record. PLAN 6.3's return to the first invalid gate is a follow-up, not part of this issue.

Notes for callers: the stopper port is filled by D10-06; who may Retry (PLAN's role table) is the
API route's job; the linear v0 path in ``core.py`` is D2-26's. A ``head_moved`` block on a run with
an uncovered merge gets its revert only on Cancel, so it must be on the attention list.
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from sto.config.schema import AgentStage, EffectStage, ReviewPanelStage
from sto.config.schema import Workflow as Graph
from sto.domain import (
    EVENTS,
    Effect,
    EffectStatus,
    FailureClass,
    PermanentError,
    RunId,
    RunStatus,
    StepKey,
    StoError,
    effect_key,
)
from sto.engine.commands import RunEffect, RunStep
from sto.engine.handlers.core import StepFailed
from sto.engine.reducer import (
    MalformedEventError,
    OutOfOrderEventError,
    RunState,
    Transition,
    handles_graph,
)

# --- classification ------------------------------------------------------------------------

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
# A block whose cause is a failure of a step or an effect. Every other block is a guard (a cap, a
# missing approval, a moved head) that a re-run must not step past.
RETRYABLE_BLOCKS = frozenset(
    {"permanent_failure", "attempts_exhausted", "degraded", "effect_failed"}
)


# What a UI shows when a Retry is refused for a block that is not a step or effect failure.
NOT_RETRYABLE_WHY = {
    "effect_failed_permanently": "permanent failure: Cancel the run (a retry would re-spend)",
    "effect_voided": "the effect was voided: Cancel the run",
    "gate_invalid": "approval no longer holds: it needs a new approval, not a retry",
    "head_moved": "the merged head changed: Cancel the run (an uncovered merge is reverted then)",
}


class RetryBudgetExceededError(PermanentError):
    """A transient error outlasted the retry cap. The cause is chained. It blocks the run: nothing
    retries it again until a person does."""


def _status(exc: BaseException) -> int | None:
    for name in ("status", "status_code"):
        value = getattr(exc, name, None)
        if type(value) is int:
            return value
    return None


def classify(exc: BaseException) -> FailureClass:
    """The class of ``exc``. Fails closed: only a known-transient error is ever retried."""
    status = _status(exc)
    if isinstance(exc, StoError):
        declared = exc.failure_class
        if declared is FailureClass.TRANSIENT and status is not None:
            return FailureClass.TRANSIENT if status in RETRYABLE_STATUS else FailureClass.PERMANENT
        return declared
    if status is not None:
        return FailureClass.TRANSIENT if status in RETRYABLE_STATUS else FailureClass.PERMANENT
    if isinstance(exc, TimeoutError | ConnectionError):
        return FailureClass.TRANSIENT
    return FailureClass.PERMANENT


def step_failed(key: StepKey, exc: BaseException) -> StepFailed:
    return StepFailed(key, classify(exc))


# --- one retry layer, capped in total time -------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """``max_attempts`` calls in all, doubling from ``base_delay`` up to ``max_delay``, and never
    more than ``total_budget`` seconds from the first call to the last sleep's end."""

    max_attempts: int = 2
    base_delay: float = 0.5
    max_delay: float = 30.0
    total_budget: float = 120.0

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise ValueError("max_attempts must be an int of at least 1")
        for name in ("base_delay", "max_delay", "total_budget"):
            value = getattr(self, name)
            if not (isinstance(value, int | float) and math.isfinite(value)):
                raise ValueError(f"{name} must be a finite number")
        if self.base_delay < 0:
            raise ValueError("base_delay must not be negative")
        if self.max_delay <= 0 or self.total_budget <= 0:
            raise ValueError("max_delay and total_budget must be positive")

    def delay(self, attempt: int) -> float:
        """The sleep after failed call number ``attempt`` (1 for the first)."""
        return float(min(self.base_delay * 2 ** (attempt - 1), self.max_delay))


class _Loop:
    """Decides, after a failure, whether to sleep and for how long (shared by sync and async)."""

    def __init__(self, policy: RetryPolicy, clock: Callable[[], float]) -> None:
        self._policy, self._clock = policy, clock
        self._start = clock()
        self._calls = 0

    def after(self, exc: Exception) -> float:
        """The delay before the next call; raises ``exc`` itself if it must not be retried, or
        ``RetryBudgetExceededError`` if the cap ended the retries."""
        self._calls += 1
        p = self._policy
        if classify(exc) is not FailureClass.TRANSIENT:
            raise exc
        if self._calls >= p.max_attempts:
            # Not the raw transient error: an outer layer would classify it as retryable and
            # retry again, which is a second retry layer (R2).
            raise RetryBudgetExceededError(
                f"gave up after {self._calls} calls: max_attempts ({p.max_attempts}) is spent"
            ) from exc
        delay = p.delay(self._calls)
        if (self._clock() - self._start) + delay > p.total_budget:
            raise RetryBudgetExceededError(
                f"gave up after {self._calls} calls: the {p.total_budget}s retry budget is spent"
            ) from exc
        return delay


def call_with_retry[T](
    call: Callable[[], T],
    policy: RetryPolicy,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> T:
    loop = _Loop(policy, clock)
    while True:
        try:
            return call()
        except Exception as exc:
            sleep(loop.after(exc))


async def acall_with_retry[T](
    call: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    loop = _Loop(policy, clock)
    while True:
        try:
            return await call()
        except Exception as exc:
            await sleep(loop.after(exc))


# --- the person's Retry --------------------------------------------------------------------


@EVENTS.register("retry.requested")
@dataclass(frozen=True)
class RetryRequested:
    """A person's Retry of a BLOCKED run. ``stage``, ``visit`` and ``attempt`` are the position the
    person saw blocked (``attempt`` is 0 for an effect, which has none), so a late or repeated
    click is refused. ``run_version`` is the run's version the person saw: the position can come
    back to the same stage, visit and attempt (an effect blocks again at the same visit), so it is
    the position's identity and a replayed event is refused. ``actor`` and ``reason`` are the
    audit record's."""

    run_id: RunId
    actor: str
    reason: str
    stage: str
    visit: int
    attempt: int = 0
    run_version: int = 0

    def __post_init__(self) -> None:
        for name in ("actor", "reason", "stage"):
            if type(getattr(self, name)) is not str:
                raise TypeError(f"{name} must be a str")
        for name in ("visit", "attempt", "run_version"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:  # a bool is not an int here
                raise TypeError(f"{name} must be a non-negative int")


@dataclass(frozen=True)
class RetryTarget:
    stage: str
    visit: int
    attempt: int  # the live attempt of a step; 0 for an effect
    blocked_reason: str
    is_effect: bool


def describe_retry(rs: RunState, wf: Graph) -> RetryTarget:
    """What a Retry would re-run, or ``OutOfOrderEventError`` if it may not."""
    run = rs.run
    if run.status is not RunStatus.BLOCKED:
        raise OutOfOrderEventError(f"retry while run is {run.status.value}, not BLOCKED")
    reason = run.blocked_reason or ""
    if reason not in RETRYABLE_BLOCKS:
        why = NOT_RETRYABLE_WHY.get(reason)
        raise OutOfOrderEventError(
            f"retry cannot clear a {reason!r} block: {why}"
            if why
            else f"retry cannot clear a {reason!r} block: it would step past that guard"
        )
    name = run.stage or ""
    stage = wf.stages.get(name)
    if isinstance(stage, AgentStage | ReviewPanelStage):
        return RetryTarget(name, rs.visit, rs.attempt, reason, False)
    if isinstance(stage, EffectStage):
        return RetryTarget(name, rs.count(name), 0, reason, True)
    raise OutOfOrderEventError(f"stage {name!r} has no step or effect to retry")


def _check_actor(actor: str, reason: str) -> None:
    if not isinstance(actor, str) or not actor.strip():
        raise MalformedEventError("a retry names the person who asked for it")
    if not isinstance(reason, str) or not reason.strip():
        raise MalformedEventError("a retry gives a reason")


def _effect_command(rs: RunState, wf: Graph, target: RetryTarget) -> RunEffect:
    stage = wf.stages[target.stage]
    assert isinstance(stage, EffectStage)
    subject = rs.subject
    if subject is None:
        raise OutOfOrderEventError("retry of an effect with no live subject")
    gates = tuple(stage.requires_gates or ())
    needed = (*gates, *(g for g in rs.routed_gates if gates and g not in gates))
    by_gate = {a.gate: a for a in rs.approvals}
    for gate in needed:
        approval = by_gate.get(gate)
        if approval is None or approval.head_sha != subject.head_sha:
            raise OutOfOrderEventError(f"retry: the approval of {gate!r} no longer holds")
    return RunEffect(
        rs.run.id,
        stage.effect,
        target.stage,
        target.visit,
        subject,
        subject.digest(),
        needed,
        tuple(by_gate[g].decision_id for g in needed),
    )


@handles_graph(RetryRequested)
def on_retry_requested(rs: RunState, event: RetryRequested, wf: Graph) -> Transition:
    _check_actor(event.actor, event.reason)
    target = describe_retry(rs, wf)
    if event.run_version != rs.run.version:
        raise OutOfOrderEventError(
            f"stale retry: it was asked at run version {event.run_version}, live is "
            f"{rs.run.version}"
        )
    if (event.stage, event.visit, event.attempt) != (target.stage, target.visit, target.attempt):
        raise OutOfOrderEventError(
            f"stale retry for {event.stage!r} visit {event.visit} attempt {event.attempt}; "
            f"blocked at {target.stage!r} visit {target.visit} attempt {target.attempt}"
        )
    run = rs.run.advance(RunStatus.RUNNING)
    run = dataclasses.replace(run, version=run.version + 1)
    if target.is_effect:
        cmd = _effect_command(rs, wf, target)
        return Transition(dataclasses.replace(rs, run=run), (cmd,))
    attempt = target.attempt + 1
    nxt = dataclasses.replace(rs, run=run, attempt=attempt)
    return Transition(nxt, (RunStep(run.id, target.stage, visit=target.visit, attempt=attempt),))


# --- the audited service -------------------------------------------------------------------


class RetryAudit(Protocol):
    """Appends one audit entry, or raises. Wired to the audit chain by the caller: only the gate
    service and the effect executor may use the audit seam directly."""

    def record(self, run_id: RunId, action: str, actor: str, data: dict[str, object]) -> None: ...


class AttemptStopper(Protocol):
    """Stops the earlier attempt's session before the next starts (PLAN 14.3); D10-06 fills it."""

    def stop_attempt(self, run_id: RunId, stage: str, visit: int, attempt: int) -> None: ...


class BlockedEffects(Protocol):
    """``EffectExecutor``'s two calls this service needs."""

    def retry_blocked(self, run_id: RunId, idempotency_key: str) -> object: ...

    def get(self, run_id: RunId, idempotency_key: str) -> Effect: ...


class RetryService:
    """``load`` returns the run's live state and workflow; ``submit`` queues an event for it."""

    def __init__(
        self,
        *,
        audit: RetryAudit,
        stopper: AttemptStopper,
        effects: BlockedEffects,
        submit: Callable[[RunId, object], Awaitable[None]],
        load: Callable[[RunId], tuple[RunState, Graph]],
    ) -> None:
        self._audit, self._stopper, self._effects = audit, stopper, effects
        self._submit, self._load = submit, load

    async def retry(self, run_id: RunId, actor: str, reason: str) -> RetryRequested:
        """Retry a blocked run. Order: check, audit, stop (a step) or clear the block (an effect),
        submit. The event is only ever sent after the audit entry exists. A failure after the block
        is cleared leaves the run BLOCKED with the effect already cleared, and the next click
        carries on from there: clearing is idempotent (``_clear``). The effect's key is derived
        from the run's state, never supplied, so a Retry cannot clear another effect."""
        _check_actor(actor, reason)
        rs, wf = self._load(run_id)
        target = describe_retry(rs, wf)
        key = None
        if target.is_effect:
            cmd = _effect_command(rs, wf, target)  # also proves every approval still holds
            key = effect_key(run_id, cmd.stage, cmd.visit, cmd.type, cmd.subject_digest)
        event = RetryRequested(
            run_id, actor, reason, target.stage, target.visit, target.attempt, rs.run.version
        )
        self._audit.record(
            run_id,
            "run.retry",
            actor,
            {
                "reason": reason,
                "stage": target.stage,
                "visit": target.visit,
                "attempt": target.attempt,
                "blocked_reason": target.blocked_reason,
            },
        )
        if key is not None:
            # A delayed click: the run may have moved since it was read (the first Retry ran and
            # the effect blocked again). Clearing now would clear a new block nobody looked at.
            if self._load(run_id)[0].run.version != rs.run.version:
                raise OutOfOrderEventError("the run changed while this retry was being made")
            self._clear(run_id, key)
        else:
            self._stopper.stop_attempt(run_id, target.stage, target.visit, target.attempt)
        await self._submit(run_id, event)
        return event

    def _clear(self, run_id: RunId, key: str) -> None:
        """``retry_blocked``, unless an earlier click already did it (the executor then refuses
        with ``ValueError``): an effect that is PLANNED or RETRYING is cleared, so go on."""
        try:
            self._effects.retry_blocked(run_id, key)
        except ValueError as e:
            if "only a blocked effect" not in str(e) or self._effects.get(
                run_id, key
            ).status not in (
                EffectStatus.PLANNED,
                EffectStatus.RETRYING,
            ):
                raise


# --- the background re-drive ---------------------------------------------------------------


class Drive(Protocol):
    async def run_until_idle(self, run_id: RunId) -> RunState: ...


class Redriver:
    """Drives a run again, in the background, when a drive gave up on a transient error (a lease
    held by a dead driver, a store blip), so it does not wait for the next person to ask about it.

    Only transient errors are driven again, under the same capped backoff as any retry. A permanent
    error is raised (and, from ``spawn``, kept in ``failures``), and a run that came back BLOCKED is
    returned as it is: no restart, redrive or reconciliation retries a permanent failure (R1)."""

    def __init__(
        self,
        driver: Drive,
        policy: RetryPolicy,
        *,
        clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._driver, self._policy, self._clock, self._sleep = driver, policy, clock, sleep
        self._tasks: dict[RunId, asyncio.Task[RunState]] = {}
        self.failures: dict[RunId, BaseException] = {}

    async def drive(self, run_id: RunId) -> RunState:
        return await acall_with_retry(
            lambda: self._driver.run_until_idle(run_id),
            self._policy,
            clock=self._clock,
            sleep=self._sleep,
        )

    def spawn(self, run_id: RunId) -> asyncio.Task[RunState]:
        """One background drive per run: asking again while it runs returns the same task."""
        live = self._tasks.get(run_id)
        if live is not None and not live.done():
            return live
        self.failures.pop(run_id, None)
        task = asyncio.ensure_future(self.drive(run_id))
        self._tasks[run_id] = task
        task.add_done_callback(lambda t: self._settle(run_id, t))
        return task

    async def aclose(self) -> None:
        """Cancel the background drives and wait for them to end."""
        tasks = [t for t in self._tasks.values() if not t.done()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def _settle(self, run_id: RunId, task: asyncio.Task[RunState]) -> None:
        if self._tasks.get(run_id) is task:
            del self._tasks[run_id]
        if not task.cancelled() and (error := task.exception()) is not None:
            self.failures[run_id] = error


__all__ = [
    "RETRYABLE_BLOCKS",
    "AttemptStopper",
    "BlockedEffects",
    "Redriver",
    "RetryAudit",
    "RetryBudgetExceededError",
    "RetryPolicy",
    "RetryRequested",
    "RetryService",
    "RetryTarget",
    "acall_with_retry",
    "call_with_retry",
    "classify",
    "describe_retry",
    "on_retry_requested",
    "step_failed",
]
