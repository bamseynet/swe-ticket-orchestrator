"""Effect ports (D1-07): where effect records live, what a writer returns, and the handlers.

Layout (PLAN 11), all inside a team scope and the ``MAIN`` table:

* effect  ``RUN#r`` / ``FX#<idempotency key>``
* run     ``RUN#r`` / ``META``
* gate    ``RUN#r`` / ``GATE#<name>#<round>``
* decision ``RUN#r`` / ``DEC#<name>#<round>#<ulid>``
* team switches ``TEAM`` / ``META``, fields ``switch_<name>``; fleet switches
  ``ORG`` / ``SWITCHES`` (platform scope)

A *handler* does one effect's outside write. It returns an outcome and never decides a status:
the executor does, from the receipt (ADR-0011: "status comes only from a receipt with
read-back").
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from sto.adapters.ports import (
    MergeHandle,
    MergeMethod,
    MergeReason,
    MergeState,
    PrRef,
    RefusedError,
    ScmProvider,
    StaleHeadError,
)
from sto.domain import Effect, Receipt, RunId, Subject
from sto.store.ports import TEAM_ROOT, Key

# Only these two effects have a ``stale`` edge (PLAN 859); anywhere else StaleHeadError is a
# permanent failure like any other.
STALE_EDGE_TYPES = frozenset({"pr.merge", "release.trigger"})

# Every effect needs ``effects`` (the kill switch's "planned effects held", PLAN 14.4). The
# merge and release effects also need their own switch (PLAN 6.4 guard 1).
ALL_EFFECTS_SWITCH = "effects"
EXTRA_SWITCHES = {"pr.merge": ("merge",), "release.trigger": ("release",)}


def switches_for(effect_type: str) -> tuple[str, ...]:
    return (ALL_EFFECTS_SWITCH, *EXTRA_SWITCHES.get(effect_type, ()))


def switch_field(name: str) -> str:
    return f"switch_{name}"


TEAM_SWITCHES = Key(TEAM_ROOT, "META")
FLEET_SWITCHES = Key("ORG", "SWITCHES")


def run_pk(run_id: RunId) -> str:
    return f"RUN#{run_id}"


def run_key(run_id: RunId) -> Key:
    return Key(run_pk(run_id), "META")


def effect_item_key(run_id: RunId, idempotency_key: str) -> Key:
    return Key(run_pk(run_id), f"FX#{idempotency_key}")


def gate_prefix(name: str) -> str:
    return f"GATE#{name}#"


def decision_prefix(name: str, round: int) -> str:
    return f"DEC#{name}#{round}#"


# --- outcomes ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Written:
    """The write happened. It counts only if ``receipt.read_back_verified``."""

    receipt: Receipt
    frozen_subject: Subject | None = None


@dataclass(frozen=True)
class Pending:
    """Accepted but not done (an async merge). ``intent`` is what later polling needs."""

    intent: str
    receipt: Receipt | None = None


@dataclass(frozen=True)
class Failed:
    """Refused for good. ``edge`` is the workflow edge it takes, if it has one."""

    edge: str | None
    reason: str


@dataclass(frozen=True)
class Voided:
    """Cancelled before it landed (a dequeued merge)."""

    reason: str


Outcome = Written | Pending | Failed | Voided


class EffectHandler(Protocol):
    def execute(self, effect: Effect) -> Outcome:
        """The write. Retries get the same ``effect.idempotency_key``."""
        ...

    def poll(self, effect: Effect) -> Outcome:
        """Resolve an ACCEPTED effect."""
        ...

    def stop(self, effect: Effect) -> Outcome:
        """Cancel an ACCEPTED effect if possible, then report where it stands."""
        ...


class CallHandler:
    """A synchronous write: ``write(idempotency_key)`` returns the adapter's receipt."""

    def __init__(self, write: Callable[[str], Receipt]) -> None:
        self._write = write

    def execute(self, effect: Effect) -> Outcome:
        return Written(self._write(effect.idempotency_key))

    def poll(self, effect: Effect) -> Outcome:
        raise ValueError("a synchronous effect is never ACCEPTED, so there is nothing to poll")

    def stop(self, effect: Effect) -> Outcome:
        raise ValueError("a synchronous effect is never ACCEPTED, so there is nothing to stop")


class MergeHandler:
    """``pr.merge`` through the async merge API (PLAN 6.4): request, poll, read back."""

    def __init__(
        self,
        scm: ScmProvider,
        pr: PrRef,
        expected_sha: str,
        method: MergeMethod,
        subject: Subject,
    ) -> None:
        self._scm, self._pr, self._sha = scm, pr, expected_sha
        self._method, self._subject = method, subject

    def execute(self, effect: Effect) -> Outcome:
        handle = self._scm.request_merge(self._pr, self._sha, self._method, effect.idempotency_key)
        return Pending(handle.id)

    def poll(self, effect: Effect) -> Outcome:
        if effect.intent is None:
            raise ValueError("an ACCEPTED merge records its handle as intent")
        result = self._scm.poll_merge(MergeHandle(effect.intent, self._pr))
        match result.state:
            case MergeState.MERGED if result.receipt is not None and result.merge_sha:
                frozen = dataclasses.replace(self._subject, merge_sha=result.merge_sha)
                return Written(result.receipt, frozen)
            case MergeState.FAILED:
                edges = {MergeReason.STALE: "stale", MergeReason.CONFLICT: "conflict"}
                reason = result.reason or MergeReason.REJECTED
                return Failed(edges.get(reason), f"merge_{reason.value}")
            case MergeState.DEQUEUED:
                return Voided("dequeued")
            case _:  # pending, or merged without a receipt to confirm it
                return Pending(effect.intent)

    def stop(self, effect: Effect) -> Outcome:
        """Dequeue if possible. A moved head (``StaleHeadError``) or a merge that already
        landed (``RefusedError``) means that merge is already dead or done: poll and reconcile
        instead of blocking (PLAN 14.3)."""
        with contextlib.suppress(StaleHeadError, RefusedError):
            self._scm.dequeue(self._pr, self._sha)
        return self.poll(effect)
