"""D2-10: failure classes, one retry layer, the audited human Retry and the background re-drive.

Fixtures are synthetic. The graph is the D2-06 reducer test's Kanban workflow (merge before QA),
which is validated by the D2-03 validator there; this file reuses it rather than copying it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.util
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from sto.domain import (
    EffectStatus,
    FailureClass,
    PermanentError,
    Run,
    RunStatus,
    StepKey,
    TransientError,
    effect_key,
)
from sto.engine.commands import RunEffect, RunStep
from sto.engine.handlers.core import EffectFailed, StepFailed
from sto.engine.handlers.failures import (
    RETRYABLE_BLOCKS,
    Redriver,
    RetryBudgetExceededError,
    RetryPolicy,
    RetryRequested,
    RetryService,
    acall_with_retry,
    call_with_retry,
    classify,
    describe_retry,
    step_failed,
)
from sto.engine.handlers.stages import StageReported
from sto.engine.reducer import MalformedEventError, OutOfOrderEventError, RunState, next


def _reducer_fixtures() -> Any:
    """The D2-06 test module's validated workflow and helpers, loaded once by path (the tests
    directory is not a package) so the fixture is shared, not copied."""
    name = "_sto_reducer_v1_fixtures"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, Path(__file__).with_name("test_reducer_v1.py")
        )
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


_fx = _reducer_fixtures()
RID: Any = _fx.RID
S1: Any = _fx.S1
S2: Any = _fx.S2
W: Any = _fx.W
at_merge: Callable[[], RunState] = _fx.at_merge
at_review_gate: Callable[[], RunState] = _fx.at_review_gate
merged: Callable[[str], RunState] = _fx.merged
new: Callable[[], RunState] = _fx.new
report: Callable[..., RunState] = _fx.report
started: Callable[[], RunState] = _fx.started
status: Callable[[RunState], tuple[RunStatus, str | None]] = _fx.status
step: Callable[..., RunState] = _fx.step


class HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"http {status}")
        self.status = status


class StatusTransient(TransientError):
    def __init__(self, status: int) -> None:
        super().__init__(f"http {status}")
        self.status = status


# --- classification ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "want"),
    [
        (TransientError("x"), FailureClass.TRANSIENT),
        (PermanentError("x"), FailureClass.PERMANENT),
        (TimeoutError(), FailureClass.TRANSIENT),
        (ConnectionResetError(), FailureClass.TRANSIENT),
        (HttpError(429), FailureClass.TRANSIENT),
        (HttpError(503), FailureClass.TRANSIENT),
        (HttpError(401), FailureClass.PERMANENT),
        (HttpError(403), FailureClass.PERMANENT),
        (HttpError(422), FailureClass.PERMANENT),
        (HttpError(501), FailureClass.PERMANENT),
        (ValueError("bad"), FailureClass.PERMANENT),
        (KeyError("k"), FailureClass.PERMANENT),
        (MemoryError(), FailureClass.PERMANENT),
        (RuntimeError("who knows"), FailureClass.PERMANENT),  # an unknown error is never retried
    ],
)
def test_classify(exc: BaseException, want: FailureClass) -> None:
    assert classify(exc) is want


@pytest.mark.parametrize("code", [400, 401, 403, 404, 410, 422])
def test_a_permanent_error_that_arrives_as_transient_is_permanent(code: int) -> None:
    assert classify(StatusTransient(code)) is FailureClass.PERMANENT


def test_a_retryable_status_never_promotes_a_permanent_error() -> None:
    class P(PermanentError):
        status = 503

    assert classify(P("x")) is FailureClass.PERMANENT


def test_a_degraded_error_stays_degraded() -> None:
    from sto.domain import DegradedError

    assert classify(DegradedError("one reviewer failed")) is FailureClass.DEGRADED


def test_step_failed_carries_the_class_of_the_error() -> None:
    key = StepKey(RID, "implement", 1, 1)
    assert step_failed(key, HttpError(403)) == StepFailed(key, FailureClass.PERMANENT)
    assert step_failed(key, TimeoutError()) == StepFailed(key, FailureClass.TRANSIENT)


# --- one retry layer, capped in total time -------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0  # not 0, so a budget measured from the first call is not hidden
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s

    async def asleep(self, s: float) -> None:
        self.sleep(s)


class Stub:
    """Counts calls at the boundary: R2 is asserted here, not on the retry code's own counter."""

    def __init__(self, *errors: BaseException) -> None:
        self.calls = 0
        self._errors = list(errors)

    def __call__(self) -> str:
        self.calls += 1
        if self._errors:
            raise self._errors.pop(0)
        return "ok"


POLICY = RetryPolicy(max_attempts=3, base_delay=1.0, max_delay=4.0, total_budget=10.0)


def test_r2_a_persistent_transient_error_is_called_exactly_max_attempts_times() -> None:
    stub, clock = Stub(*[TransientError("t")] * 9), Clock()
    with pytest.raises(RetryBudgetExceededError) as e:
        call_with_retry(stub, POLICY, clock=clock, sleep=clock.sleep)
    assert stub.calls == 3
    assert clock.slept == [1.0, 2.0]  # doubling backoff between the three calls
    assert isinstance(e.value.__cause__, TransientError)
    # P4: an outer layer must see a permanent error, or it would retry again (a second layer)
    assert classify(e.value) is FailureClass.PERMANENT


def test_a_transient_error_that_then_succeeds_returns() -> None:
    stub, clock = Stub(TransientError("t")), Clock()
    assert call_with_retry(stub, POLICY, clock=clock, sleep=clock.sleep) == "ok"
    assert stub.calls == 2


def test_r1_a_permanent_error_is_called_once_and_never_slept_on() -> None:
    stub, clock = Stub(HttpError(403)), Clock()
    with pytest.raises(HttpError):
        call_with_retry(stub, POLICY, clock=clock, sleep=clock.sleep)
    assert stub.calls == 1
    assert clock.slept == []


def test_a_permanent_error_that_arrives_as_transient_is_not_retried() -> None:
    stub, clock = Stub(StatusTransient(401)), Clock()
    with pytest.raises(StatusTransient):
        call_with_retry(stub, POLICY, clock=clock, sleep=clock.sleep)
    assert stub.calls == 1


def test_the_backoff_is_capped_per_delay() -> None:
    p = RetryPolicy(max_attempts=9, base_delay=1.0, max_delay=4.0, total_budget=1000.0)
    assert [p.delay(n) for n in range(1, 6)] == [1.0, 2.0, 4.0, 4.0, 4.0]


def test_total_time_is_capped_so_a_persistent_transient_error_stops() -> None:
    p = RetryPolicy(max_attempts=100, base_delay=4.0, max_delay=4.0, total_budget=10.0)
    stub, clock = Stub(*[TransientError("t")] * 100), Clock()
    with pytest.raises(RetryBudgetExceededError) as e:
        call_with_retry(stub, p, clock=clock, sleep=clock.sleep)
    assert clock.now - 1000.0 <= 10.0  # never sleeps past the budget
    assert stub.calls == 3  # t=0, 4, 8; a sleep to 12 would overrun
    assert classify(e.value) is FailureClass.PERMANENT  # it blocks; it is not retried again
    assert isinstance(e.value.__cause__, TransientError)


def test_a_slow_call_counts_against_the_budget() -> None:
    clock = Clock()
    calls = 0

    def slow() -> str:
        nonlocal calls
        calls += 1
        clock.now += 9.5
        raise TransientError("t")

    with pytest.raises(RetryBudgetExceededError):
        call_with_retry(slow, POLICY, clock=clock, sleep=clock.sleep)
    assert calls == 1


def test_async_retry_matches_sync() -> None:
    stub, clock = Stub(*[TransientError("t")] * 9), Clock()

    async def go() -> str:
        async def call() -> str:
            return stub()

        return await acall_with_retry(call, POLICY, clock=clock, sleep=clock.asleep)

    with pytest.raises(RetryBudgetExceededError):
        asyncio.run(go())
    assert stub.calls == 3
    assert clock.slept == [1.0, 2.0]


@pytest.mark.parametrize(
    "kw",
    [
        {"max_attempts": 0},
        {"base_delay": -1.0},
        {"base_delay": float("nan")},
        {"max_delay": 0.0},
        {"total_budget": float("inf")},
        {"total_budget": 0.0},
    ],
)
def test_a_bad_policy_is_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must"):
        RetryPolicy(**kw)


# --- the Retry event on the reducer --------------------------------------------------------


def retry_event(rs: RunState, **over: Any) -> RetryRequested:
    base: dict[str, Any] = {
        "run_id": RID,
        "actor": "alice",
        "reason": "flaky sandbox",
        "stage": rs.run.stage,
        "visit": rs.visit,
        "attempt": rs.attempt,
        "run_version": rs.run.version,
    }
    return RetryRequested(**{**base, **over})


def blocked_at_step(failure: FailureClass = FailureClass.PERMANENT) -> RunState:
    rs = started()
    return step(rs, StepFailed(StepKey(RID, "implement", rs.visit, rs.attempt), failure))


def test_retry_reruns_the_blocked_step_at_a_new_attempt() -> None:
    rs = blocked_at_step()
    assert status(rs) == (RunStatus.BLOCKED, "implement")
    t = next(rs, retry_event(rs), W)
    assert status(t.state) == (RunStatus.RUNNING, "implement")
    assert t.commands == (RunStep(RID, "implement", visit=1, attempt=2),)
    assert t.state.attempt == 2
    assert t.state.run.blocked_reason is None
    assert t.state.run.version == rs.run.version + 1


def test_retry_resets_no_counter() -> None:
    rs = blocked_at_step()
    out = next(rs, retry_event(rs), W).state
    for field in ("visits", "loops", "steps", "visit", "merges", "approvals", "subject"):
        assert getattr(out, field) == getattr(rs, field), field


def test_retry_does_not_reset_a_spent_loop() -> None:
    # Use the "fix" loop (cap 2) twice, then fail permanently and retry: the loop stays spent.
    rs = started()
    for _ in range(2):
        rs = report(rs, "ready")  # implement -> panel
        rs = report(rs, "findings")  # panel -> implement over "fix"
    assert rs.loop_count("fix") == 2
    rs = step(
        rs, StepFailed(StepKey(RID, "implement", rs.visit, rs.attempt), FailureClass.PERMANENT)
    )
    out = next(rs, retry_event(rs), W).state
    assert out.loop_count("fix") == 2
    rs2 = report(out, "ready")
    blocked = report(rs2, "findings")  # a third use of "fix" is still refused
    assert blocked.run.blocked_reason == "loop_exhausted"


def test_retry_after_attempts_exhausted_is_allowed() -> None:
    rs = started()
    rs = step(rs, StepFailed(StepKey(RID, "implement", 1, 1), FailureClass.TRANSIENT))
    assert rs.run.status is RunStatus.RUNNING
    assert rs.attempt == 2
    rs = step(rs, StepFailed(StepKey(RID, "implement", 1, 2), FailureClass.TRANSIENT))
    assert rs.run.blocked_reason == "attempts_exhausted"
    assert next(rs, retry_event(rs), W).state.run.status is RunStatus.RUNNING


def test_retry_after_a_degraded_block_is_allowed() -> None:
    rs = blocked_at_step(FailureClass.DEGRADED)
    assert rs.run.blocked_reason == "degraded"
    assert next(rs, retry_event(rs), W).state.run.status is RunStatus.RUNNING


def test_the_retryable_block_reasons_are_exactly_the_failure_ones() -> None:
    assert {
        "permanent_failure",
        "attempts_exhausted",
        "degraded",
        "effect_failed",
    } == RETRYABLE_BLOCKS


@pytest.mark.parametrize(
    "reason",
    ["loop_exhausted", "max_steps_exceeded", "stage_unsupported", "gate_invalid",
     "subject_missing", "head_moved"],
)  # fmt: skip
def test_retry_never_steps_past_a_block_on_that_is_not_a_step_failure(reason: str) -> None:
    rs = blocked_at_step()
    rs = dataclasses.replace(rs, run=dataclasses.replace(rs.run, blocked_reason=reason))
    with pytest.raises(OutOfOrderEventError, match=reason):
        next(rs, retry_event(rs), W)


def test_retry_of_a_run_that_is_not_blocked_is_refused() -> None:
    rs = started()
    with pytest.raises(OutOfOrderEventError, match="RUNNING"):
        next(rs, retry_event(rs), W)


def test_a_second_retry_for_the_same_block_is_refused() -> None:
    rs = blocked_at_step()
    ev = retry_event(rs)
    again = next(rs, ev, W).state
    with pytest.raises(OutOfOrderEventError):
        next(again, ev, W)


@pytest.mark.parametrize("over", [{"visit": 9}, {"attempt": 9}, {"stage": "panel"}])
def test_a_stale_retry_is_refused(over: dict[str, Any]) -> None:
    rs = blocked_at_step()
    with pytest.raises(OutOfOrderEventError):
        next(rs, retry_event(rs, **over), W)


@pytest.mark.parametrize("over", [{"actor": ""}, {"actor": "  "}, {"reason": ""}])
def test_a_retry_with_no_actor_or_reason_is_malformed(over: dict[str, Any]) -> None:
    rs = blocked_at_step()
    with pytest.raises(MalformedEventError):
        next(rs, retry_event(rs, **over), W)


@pytest.mark.parametrize("terminal", [RunStatus.DONE, RunStatus.CANCELLED, RunStatus.REJECTED])
def test_terminal_runs_absorb_a_retry(terminal: RunStatus) -> None:
    rs = blocked_at_step()
    rs = dataclasses.replace(
        rs, run=dataclasses.replace(rs.run, status=terminal, blocked_reason=None)
    )
    with pytest.raises(OutOfOrderEventError):
        next(rs, retry_event(rs), W)


def blocked_at_merge() -> RunState:
    rs = at_merge()
    return step(rs, EffectFailed(RID, "pr.merge", rs.count("merge")))


def effect_retry(rs: RunState, **over: Any) -> RetryRequested:
    return retry_event(rs, stage="merge", visit=rs.count("merge"), attempt=0, **over)


def test_retry_of_a_blocked_effect_replans_it_at_the_same_visit() -> None:
    rs = blocked_at_merge()
    assert rs.run.blocked_reason == "effect_failed"
    t = next(rs, effect_retry(rs), W)
    assert status(t.state) == (RunStatus.RUNNING, "merge")
    (cmd,) = t.commands
    assert isinstance(cmd, RunEffect)
    assert (cmd.type, cmd.stage, cmd.visit) == ("pr.merge", "merge", 1)  # same idempotency scope
    assert cmd.subject == rs.subject
    assert cmd.requires_gates == ("review_gate",)
    assert t.state.visits == rs.visits
    assert t.state.steps == rs.steps


def test_retry_of_an_effect_is_refused_when_its_approval_no_longer_holds() -> None:
    rs = blocked_at_merge()
    gone = dataclasses.replace(rs, approvals=())
    with pytest.raises(OutOfOrderEventError, match="approval"):
        next(gone, effect_retry(gone), W)


def test_retry_of_an_effect_is_refused_when_an_approval_is_for_another_head() -> None:
    rs = blocked_at_merge()
    stale = tuple(dataclasses.replace(a, head_sha="other") for a in rs.approvals)
    moved = dataclasses.replace(rs, approvals=stale)
    with pytest.raises(OutOfOrderEventError, match="approval"):
        next(moved, effect_retry(moved), W)


def test_retry_of_an_effect_needs_the_routed_gates_too() -> None:
    rs = blocked_at_merge()
    routed = dataclasses.replace(rs, routed_gates=("extra_gate",))
    with pytest.raises(OutOfOrderEventError, match="extra_gate"):
        next(routed, effect_retry(routed), W)


def test_retry_is_not_defined_at_a_gate() -> None:
    rs = at_review_gate()
    blocked = dataclasses.replace(
        rs,
        run=dataclasses.replace(
            rs.run, status=RunStatus.BLOCKED, blocked_reason="permanent_failure"
        ),
    )
    with pytest.raises(OutOfOrderEventError):
        next(blocked, retry_event(blocked, stage="review_gate"), W)


def test_the_handler_is_pure_and_deterministic() -> None:
    rs = blocked_at_step()
    ev = retry_event(rs)
    assert next(rs, ev, W) == next(rs, ev, W)


# --- a head that moves during QA blocks the run --------------------------------------------


def test_a_head_that_moves_during_the_qa_step_blocks_instead_of_raising() -> None:
    rs = merged("m1")  # the merge of S1 is recorded; the QA step is current
    t = next(rs, StageReported(StepKey(RID, "qa_agent", rs.visit, rs.attempt), "pass", S2), W)
    assert t.state.run.status is RunStatus.BLOCKED
    assert t.state.run.blocked_reason == "head_moved"
    assert t.state.run.stage == "qa_agent"
    assert t.commands == ()
    assert t.state.merges == rs.merges  # the merged head is not rewritten
    assert t.state.subject == rs.subject  # and neither is the live subject


def test_the_merged_head_still_passes_qa() -> None:
    assert report(merged("m1"), "pass", S1).run.stage == "qa_gate"


def test_a_head_moved_block_cannot_be_retried_into_the_new_head() -> None:
    rs = merged("m1")
    rs = next(
        rs, StageReported(StepKey(RID, "qa_agent", rs.visit, rs.attempt), "pass", S2), W
    ).state
    with pytest.raises(OutOfOrderEventError, match="head_moved"):
        next(rs, retry_event(rs), W)


# --- the audited Retry service -------------------------------------------------------------


class Journal:
    """One ordered log shared by every collaborator, so the order of effects is asserted."""

    def __init__(self) -> None:
        self.log: list[tuple[Any, ...]] = []


class FakeAudit:
    def __init__(self, j: Journal, fail: bool = False) -> None:
        self.j, self.fail = j, fail

    def record(self, run_id: Any, action: str, actor: str, data: dict[str, Any]) -> None:
        if self.fail:
            raise TransientError("audit store down")
        self.j.log.append(("audit", action, actor, data))


class FakeStopper:
    def __init__(self, j: Journal) -> None:
        self.j = j

    def stop_attempt(self, run_id: Any, stage: str, visit: int, attempt: int) -> None:
        self.j.log.append(("stop", stage, visit, attempt))


class FakeEffect:
    def __init__(self, status: EffectStatus) -> None:
        self.status = status


class FakeEffects:
    """Models the executor's rule: ``retry_blocked`` clears a block once, and refuses with
    ``ValueError`` when nothing is blocked. ``get`` reports the record's status."""

    def __init__(self, j: Journal, key: str | None = None) -> None:
        self.j = j
        self.blocked = {key} if key else set()
        self.status = EffectStatus.ATTEMPTING

    def retry_blocked(self, run_id: Any, idempotency_key: str) -> object:
        self.j.log.append(("retry_blocked", idempotency_key))
        if idempotency_key not in self.blocked:
            raise ValueError("only a blocked effect can be retried")
        self.blocked.discard(idempotency_key)
        self.status = EffectStatus.PLANNED
        return object()

    def get(self, run_id: Any, idempotency_key: str) -> Any:
        return FakeEffect(self.status)


def merge_key(rs: RunState) -> str:
    if rs.subject is None:
        return "no-effect-here"
    return effect_key(RID, "merge", rs.count("merge"), "pr.merge", rs.subject.digest())


def service(
    rs: RunState,
    j: Journal,
    *,
    audit_fails: bool = False,
    effects: FakeEffects | None = None,
    submit_fails: int = 0,
) -> tuple[RetryService, list[object]]:
    sent: list[object] = []
    failures = [submit_fails]

    async def submit(run_id: Any, event: object) -> None:
        j.log.append(("submit", type(event).__name__))
        if failures[0] > 0:
            failures[0] -= 1
            raise TransientError("store blip")
        sent.append(event)

    svc = RetryService(
        audit=FakeAudit(j, audit_fails),
        stopper=FakeStopper(j),
        effects=effects if effects is not None else FakeEffects(j, merge_key(rs)),
        submit=submit,
        load=lambda run_id: (rs, W),
    )
    return svc, sent


def test_a_step_retry_audits_then_stops_the_old_attempt_then_submits() -> None:
    rs, j = blocked_at_step(), Journal()
    svc, sent = service(rs, j)
    ev = asyncio.run(svc.retry(RID, "alice", "flaky sandbox"))
    assert [e[0] for e in j.log] == ["audit", "stop", "submit"]
    assert j.log[0][1:3] == ("run.retry", "alice")
    assert j.log[0][3] == {
        "reason": "flaky sandbox",
        "stage": "implement",
        "visit": 1,
        "attempt": 1,
        "blocked_reason": "permanent_failure",
    }
    assert j.log[1] == ("stop", "implement", 1, 1)
    assert sent == [ev]
    assert ev.actor == "alice"


def test_an_effect_retry_clears_the_block_before_the_run_hears_of_it() -> None:
    rs, j = blocked_at_merge(), Journal()
    svc, _ = service(rs, j)
    asyncio.run(svc.retry(RID, "bob", "scm outage over"))
    assert [e[0] for e in j.log] == ["audit", "retry_blocked", "submit"]
    assert j.log[1] == ("retry_blocked", merge_key(rs))  # no earlier attempt session to stop


def test_p3_the_effect_key_is_derived_from_the_run_not_supplied() -> None:
    import inspect

    assert "effect_key" not in inspect.signature(RetryService.retry).parameters
    rs, j = blocked_at_merge(), Journal()
    other = FakeEffects(j, "some-other-effects-key")  # blocked, but not this run's effect
    svc, sent = service(rs, j, effects=other)
    with pytest.raises(ValueError, match="only a blocked effect"):
        asyncio.run(svc.retry(RID, "bob", "x"))  # the other effect was never touched
    assert other.blocked == {"some-other-effects-key"}
    assert sent == []


def test_p2_a_failed_submit_then_a_second_click_goes_through() -> None:
    rs, j = blocked_at_merge(), Journal()
    svc, sent = service(rs, j, submit_fails=1)
    with pytest.raises(TransientError):
        asyncio.run(svc.retry(RID, "bob", "scm outage over"))  # cleared, then submit failed
    assert sent == []
    ev = asyncio.run(svc.retry(RID, "bob", "scm outage over"))  # the block is already cleared
    assert sent == [ev]
    assert [e[0] for e in j.log].count("submit") == 2


def test_a_second_click_on_an_effect_that_is_not_cleared_nor_blocked_is_refused() -> None:
    rs, j = blocked_at_merge(), Journal()
    fx = FakeEffects(j)  # nothing blocked ...
    fx.status = EffectStatus.FAILED  # ... and the record is final: a retry would replay it
    svc, sent = service(rs, j, effects=fx)
    with pytest.raises(ValueError, match="only a blocked effect"):
        asyncio.run(svc.retry(RID, "bob", "x"))
    assert sent == []


def test_nothing_happens_when_the_audit_write_fails() -> None:
    rs, j = blocked_at_step(), Journal()
    svc, sent = service(rs, j, audit_fails=True)
    with pytest.raises(TransientError):
        asyncio.run(svc.retry(RID, "alice", "again"))
    assert j.log == []
    assert sent == []


def test_a_retry_that_cannot_apply_audits_nothing_and_changes_nothing() -> None:
    rs, j = started(), Journal()
    svc, sent = service(rs, j)
    with pytest.raises(OutOfOrderEventError):
        asyncio.run(svc.retry(RID, "alice", "again"))
    assert j.log == []
    assert sent == []


def test_an_anonymous_retry_is_refused_before_anything_is_written() -> None:
    rs, j = blocked_at_step(), Journal()
    svc, _ = service(rs, j)
    with pytest.raises(MalformedEventError):
        asyncio.run(svc.retry(RID, "", "why"))
    assert j.log == []


def test_retry_state_equals_what_the_event_does_to_the_reducer() -> None:
    rs, j = blocked_at_step(), Journal()
    svc, sent = service(rs, j)
    asyncio.run(svc.retry(RID, "alice", "x"))
    (ev,) = sent
    assert isinstance(ev, RetryRequested)
    assert next(rs, ev, W).state.attempt == 2


# --- the background re-drive ---------------------------------------------------------------


class FakeDriver:
    def __init__(self, *script: BaseException | RunState) -> None:
        self.script = list(script)
        self.calls = 0

    async def run_until_idle(self, run_id: Any) -> RunState:
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def redriver(driver: FakeDriver, clock: Clock, **kw: Any) -> Redriver:
    pol = kw.pop(
        "policy", RetryPolicy(max_attempts=4, base_delay=1.0, max_delay=4.0, total_budget=30.0)
    )
    return Redriver(driver, pol, clock=clock, sleep=clock.asleep, **kw)


def test_a_drive_that_gave_up_on_a_transient_error_is_driven_again() -> None:
    done = dataclasses.replace(new(), run=Run(id=RID, team="t", status=RunStatus.RUNNING))
    d, clock = FakeDriver(TransientError("lease"), TransientError("store"), done), Clock()
    out = asyncio.run(redriver(d, clock).drive(RID))
    assert out is done
    assert d.calls == 3
    assert clock.slept == [1.0, 2.0]


def test_a_blocked_run_is_returned_and_never_driven_again() -> None:
    blocked = blocked_at_step()
    d, clock = FakeDriver(blocked), Clock()
    assert asyncio.run(redriver(d, clock).drive(RID)) is blocked
    assert d.calls == 1  # R1: a restart or redrive does not retry a permanent failure


def test_a_permanent_drive_error_is_raised_not_redriven() -> None:
    d, clock = FakeDriver(PermanentError("wedged")), Clock()
    with pytest.raises(PermanentError):
        asyncio.run(redriver(d, clock).drive(RID))
    assert d.calls == 1


def test_a_drive_that_keeps_failing_gives_up_within_the_budget() -> None:
    tight = RetryPolicy(max_attempts=50, base_delay=1.0, max_delay=4.0, total_budget=5.0)
    d, clock = FakeDriver(*[TransientError("t")] * 50), Clock()
    with pytest.raises(RetryBudgetExceededError):
        asyncio.run(redriver(d, clock, policy=tight).drive(RID))
    assert d.calls == 3  # t=0, 1, 3; the next sleep (4s) would end at 7
    assert clock.now - 1000.0 <= 5.0


def test_spawn_redrives_in_the_background_without_anyone_asking() -> None:
    done = new()
    d, clock = FakeDriver(TransientError("t"), done), Clock()

    async def go() -> RunState:
        rd = redriver(d, clock)
        task = rd.spawn(RID)
        assert rd.spawn(RID) is task  # one background drive per run
        return await task

    assert asyncio.run(go()) is done
    assert d.calls == 2


def test_a_failed_background_drive_is_recorded_not_lost() -> None:
    d, clock = FakeDriver(PermanentError("wedged")), Clock()

    async def go() -> Redriver:
        rd = redriver(d, clock)
        await asyncio.gather(rd.spawn(RID), return_exceptions=True)
        return rd

    rd = asyncio.run(go())
    assert isinstance(rd.failures[RID], PermanentError)


def test_a_later_spawn_after_a_failure_starts_a_fresh_drive() -> None:
    done = new()
    d, clock = FakeDriver(PermanentError("wedged"), done), Clock()

    async def go() -> RunState:
        rd = redriver(d, clock)
        await asyncio.gather(rd.spawn(RID), return_exceptions=True)
        out = await rd.spawn(RID)
        assert RID not in rd.failures
        return out

    assert asyncio.run(go()) is done


Submit = Callable[[Any, object], Awaitable[None]]


def test_retry_requested_is_registered_and_survives_the_wire() -> None:
    from sto.domain import EVENTS, from_wire, to_wire

    ev = RetryRequested(RID, "alice", "why", "implement", 1, 1, 4)
    assert EVENTS.name_of(RetryRequested) == "retry.requested"
    assert from_wire(RetryRequested, to_wire(ev)) == ev


@pytest.mark.parametrize("code", [408, 425, 429, 500, 502, 503, 504])
def test_each_retryable_status_is_transient(code: int) -> None:
    assert classify(HttpError(code)) is FailureClass.TRANSIENT
    assert classify(StatusTransient(code)) is FailureClass.TRANSIENT


@pytest.mark.parametrize("code", [407, 426, 499, 501, 505, 511])
def test_a_neighbouring_status_is_permanent(code: int) -> None:
    assert classify(HttpError(code)) is FailureClass.PERMANENT


def test_the_default_policy_is_the_plan_default() -> None:
    p = RetryPolicy()
    assert (p.max_attempts, p.base_delay, p.max_delay, p.total_budget) == (2, 0.5, 30.0, 120.0)


def test_policy_edges_that_are_allowed() -> None:
    RetryPolicy(max_attempts=1, base_delay=0, max_delay=0.5, total_budget=0.5)
    stub, clock = Stub(TransientError("t")), Clock()
    with pytest.raises(RetryBudgetExceededError):
        call_with_retry(stub, RetryPolicy(max_attempts=1), clock=clock, sleep=clock.sleep)
    assert stub.calls == 1  # one attempt means no retry at all


def test_events_and_targets_are_immutable() -> None:
    ev = RetryRequested(RID, "alice", "why", "implement", 1)
    assert ev.attempt == 0  # an effect has no attempt
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.actor = "mallory"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        RetryPolicy().max_attempts = 9  # type: ignore[misc]
    target = describe_retry(blocked_at_step(), W)
    with pytest.raises(dataclasses.FrozenInstanceError):
        target.attempt = 9  # type: ignore[misc]


def test_retry_of_an_effect_with_no_live_subject_is_refused() -> None:
    rs = blocked_at_merge()
    bare = dataclasses.replace(rs, subject=None)
    with pytest.raises(OutOfOrderEventError, match="subject"):
        next(bare, effect_retry(bare), W)


def test_routed_gates_are_not_required_of_an_ungated_effect() -> None:
    rs = blocked_at_merge()
    run = dataclasses.replace(rs.run, stage="update")
    at_update = dataclasses.replace(
        rs, run=run, visits=(("update", 1),), routed_gates=("extra_gate",)
    )
    ev = retry_event(at_update, stage="update", visit=1, attempt=0)
    (cmd,) = next(at_update, ev, W).commands
    assert isinstance(cmd, RunEffect)
    assert cmd.requires_gates == ()
    assert cmd.decision_ids == ()


# --- review pass 1 ---------------------------------------------------------------------------


def test_p1_a_replayed_effect_retry_is_refused_after_the_effect_blocks_again() -> None:
    rs = blocked_at_merge()
    ev = effect_retry(rs)
    again = next(rs, ev, W).state
    reblocked = step(again, EffectFailed(RID, "pr.merge", again.count("merge")))
    assert reblocked.run.blocked_reason == "effect_failed"
    # same stage, same visit, same attempt (0): only the run version tells the click apart
    with pytest.raises(OutOfOrderEventError, match="stale retry"):
        next(reblocked, ev, W)


def test_a_replayed_step_retry_is_refused_by_the_run_version_too() -> None:
    rs = blocked_at_step()
    ev = retry_event(rs)
    with pytest.raises(OutOfOrderEventError, match="run version"):
        next(rs, dataclasses.replace(ev, run_version=ev.run_version - 1), W)


def test_the_effect_retry_command_carries_the_decision_ids_of_the_approvals() -> None:
    rs = blocked_at_merge()
    (cmd,) = next(rs, effect_retry(rs), W).commands
    assert isinstance(cmd, RunEffect)
    assert cmd.decision_ids == tuple(a.decision_id for a in rs.approvals if a.gate == "review_gate")
    assert cmd.decision_ids
    assert cmd.subject_digest == rs.subject.digest()  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("reason", "blocked", "why"),
    [
        ("blocked", "effect_failed", None),
        ("failed", "effect_failed_permanently", "permanent failure"),
        ("voided", "effect_voided", "voided"),
        ("gate_invalid", "gate_invalid", "approval no longer holds"),
    ],
)
def test_an_effect_failure_blocks_with_its_own_reason_and_only_a_blocked_one_retries(
    reason: str, blocked: str, why: str | None
) -> None:
    at = at_merge()
    rs = step(at, EffectFailed(RID, "pr.merge", at.count("merge"), reason))
    assert rs.run.blocked_reason == blocked
    if why is None:
        assert next(rs, effect_retry(rs), W).state.run.status is RunStatus.RUNNING
        return
    with pytest.raises(OutOfOrderEventError, match=why):
        next(rs, effect_retry(rs), W)


def test_an_effect_failure_reason_is_validated() -> None:
    with pytest.raises(ValueError, match="reason"):
        EffectFailed(RID, "pr.merge", 1, "whatever")
    assert EffectFailed(RID, "pr.merge", 1).reason == "blocked"  # the default is unchanged


def test_the_service_refuses_a_failed_effect_before_writing_anything() -> None:
    at = at_merge()
    rs = step(at, EffectFailed(RID, "pr.merge", at.count("merge"), "failed"))
    j = Journal()
    svc, sent = service(rs, j)
    with pytest.raises(OutOfOrderEventError, match="permanent failure"):
        asyncio.run(svc.retry(RID, "bob", "x"))
    assert j.log == []
    assert sent == []


def test_the_service_stamps_the_run_version_the_person_saw() -> None:
    rs, j = blocked_at_step(), Journal()
    svc, _ = service(rs, j)
    ev = asyncio.run(svc.retry(RID, "alice", "x"))
    assert ev.run_version == rs.run.version


def test_exactly_at_the_budget_is_still_allowed() -> None:
    p = RetryPolicy(max_attempts=5, base_delay=5.0, max_delay=5.0, total_budget=10.0)
    stub, clock = Stub(TransientError("t"), TransientError("t")), Clock()
    assert call_with_retry(stub, p, clock=clock, sleep=clock.sleep) == "ok"
    assert clock.now - 1000.0 == 10.0  # slept 5 + 5: the second sleep ends exactly at the budget


def test_a_bool_status_is_not_an_http_status() -> None:
    class Odd(TransientError):
        status = True  # == 1, but not an int status

    assert classify(Odd("x")) is FailureClass.TRANSIENT


@pytest.mark.parametrize(
    "over",
    [
        {"attempt": True},
        {"visit": True},
        {"run_version": True},
        {"visit": -1},
        {"run_version": 1.0},
        {"actor": 5},
        {"stage": None},
    ],
)
def test_retry_requested_field_types_are_validated(over: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "run_id": RID,
        "actor": "a",
        "reason": "r",
        "stage": "implement",
        "visit": 1,
        "attempt": 1,
        "run_version": 1,
    }
    with pytest.raises(TypeError):
        RetryRequested(**{**base, **over})


# --- review pass 2 ---------------------------------------------------------------------------


def test_n2_a_delayed_second_click_cannot_clear_a_new_block() -> None:
    rs, j = blocked_at_merge(), Journal()
    moved = dataclasses.replace(rs, run=dataclasses.replace(rs.run, version=rs.run.version + 2))
    loads = iter([rs, moved])  # read at the start, then the run has moved before the clear
    sent: list[object] = []

    async def submit(run_id: Any, event: object) -> None:
        sent.append(event)

    fx = FakeEffects(j, merge_key(rs))
    svc = RetryService(
        audit=FakeAudit(j),
        stopper=FakeStopper(j),
        effects=fx,
        submit=submit,
        load=lambda run_id: (loads.__next__(), W),
    )
    with pytest.raises(OutOfOrderEventError, match="changed"):
        asyncio.run(svc.retry(RID, "bob", "again"))
    assert fx.blocked == {merge_key(rs)}  # the new block was not cleared
    assert sent == []
    assert "retry_blocked" not in [e[0] for e in j.log]


def test_a_value_error_that_is_not_the_not_blocked_refusal_is_not_swallowed() -> None:
    rs, j = blocked_at_merge(), Journal()

    class Broken(FakeEffects):
        def retry_blocked(self, run_id: Any, idempotency_key: str) -> object:
            raise ValueError("the store returned garbage")

    fx = Broken(j)
    fx.status = EffectStatus.PLANNED  # a status that would otherwise count as cleared
    svc, sent = service(rs, j, effects=fx)
    with pytest.raises(ValueError, match="garbage"):
        asyncio.run(svc.retry(RID, "bob", "x"))
    assert sent == []


def test_redriver_aclose_cancels_and_awaits_the_background_drives() -> None:
    started = asyncio.Event()

    class Hangs:
        async def run_until_idle(self, run_id: Any) -> RunState:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    async def go() -> tuple[bool, dict[Any, BaseException]]:
        rd = Redriver(Hangs(), RetryPolicy(), clock=Clock(), sleep=Clock().asleep)
        task = rd.spawn(RID)
        await started.wait()
        await rd.aclose()
        return task.cancelled(), rd.failures

    cancelled, failures = asyncio.run(go())
    assert cancelled
    assert failures == {}  # a cancelled drive is not a failure
