"""Effect ports (D1-07): where effect records live, what a writer returns, and the handlers.

Layout (PLAN 11), all inside a team scope and the ``MAIN`` table:

* effect  ``RUN#r`` / ``FX#<idempotency key>``
* run     ``RUN#r`` / ``META``
* gate    ``RUN#r`` / ``GATE#<name>#<round>``
* decision ``RUN#r`` / ``DEC#<name>#<round>#<ulid>``
* run audit chain head ``RUN#r`` / ``CHAIN`` (moved by every gate open and decision)
* team switches ``TEAM`` / ``META``, fields ``switch_<name>``; fleet switches
  ``ORG`` / ``SWITCHES`` (platform scope)
* the effect item holds an envelope: ``{"effect": <domain wire form>, "meta": {...}}``, where
  ``meta`` keeps what the frozen domain record has no field for (void reason, edge, edge reason,
  the lease, a blocked marker)

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
from sto.domain import Effect, PermanentError, Receipt, RunId, Subject
from sto.store.ports import TEAM_ROOT, Key

# Only these two effects have a ``stale`` edge (PLAN 859); anywhere else StaleHeadError is a
# permanent failure like any other.
STALE_EDGE_TYPES = frozenset({"pr.merge", "release.trigger"})

# Switches are off flags (PLAN 14.4): absent means not off, and a present value counts as on only
# if it is exactly ``True``. Every effect checks ``effects`` (the kill switch's "planned effects
# held"); the merge and release effects also check their own (PLAN 6.4 guard 1).
ALL_EFFECTS_SWITCH = "effects"
EXTRA_SWITCHES = {"pr.merge": ("merge",), "release.trigger": ("release",)}


# Engine-implicit scoped effects (PLAN 6.3: check runs, gate notifications, ``pr.close`` on reject,
# the revert PR) run on a stopped or finished run: that is when they are needed (PLAN 6.2, 14.3).
# Every other scoped effect is declared in the workflow and needs a live run like a gated one.
IMPLICIT_TYPES = frozenset({"check.publish", "gate.notify", "pr.close", "pr.open_revert"})


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


def chain_key(run_id: RunId) -> Key:
    """The run's audit chain head. The gate service moves it, through its ``AuditWriter``, in the
    same transaction as every gate open and decision (PLAN 4.3 rule 6), so a claim that checks its
    version sees them. This is a requirement on every ``AuditWriter`` (see ``EffectExecutor``)."""
    return Key(run_pk(run_id), "CHAIN")


def gate_key(run_id: RunId, name: str, round: int) -> Key:
    return Key(run_pk(run_id), f"{gate_prefix(name)}{round}")


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

    def reconcile(self, effect: Effect) -> Outcome:
        """Stop's route for an attempt whose answer was lost (RETRYING, or ATTEMPTING with a lapsed
        lease): cancel it if it is still pending. It must never write anything new. Return
        ``Voided`` if the cancel succeeded; raise ``StaleHeadError``, ``RefusedError`` or
        ``CannotReconcile`` if it cannot tell, and the executor blocks the effect for a person."""
        ...


class CannotReconcile(PermanentError):
    """A handler has no safe way to find out what a lost attempt became."""


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

    def reconcile(self, effect: Effect) -> Outcome:
        raise CannotReconcile("a synchronous effect has no handle to reconcile: a person decides")


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
        # The approval covers exactly this subject and head (PLAN 4.3 rule 2): a handler built for
        # another commit must not merge it under this effect's approval.
        if self._subject.digest() != effect.subject_digest:
            return Failed(None, "subject_mismatch")
        if self._subject.head_sha != self._sha:
            return Failed(None, "head_mismatch")
        handle = self._scm.request_merge(self._pr, self._sha, self._method, effect.idempotency_key)
        return Pending(handle.id)

    def poll(self, effect: Effect) -> Outcome:
        if effect.intent is None:
            raise ValueError("an ACCEPTED merge records its handle as intent")
        return self._read_back(MergeHandle(effect.intent, self._pr))

    def _read_back(self, handle: MergeHandle) -> Outcome:
        result = self._scm.poll_merge(handle)
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
                return Pending(handle.id)

    def stop(self, effect: Effect) -> Outcome:
        """Dequeue if possible. A moved head (``StaleHeadError``) or a merge that already
        landed (``RefusedError``) means that merge is already dead or done: poll and reconcile
        instead of blocking (PLAN 14.3)."""
        with contextlib.suppress(StaleHeadError, RefusedError):
            self._scm.dequeue(self._pr, self._sha)
        return self.poll(effect)

    def reconcile(self, effect: Effect) -> Outcome:
        """Only dequeues; it never requests a merge, so a Stop cannot cause one. A successful
        dequeue means a merge was pending and is now cancelled (``Voided``). ``StaleHeadError``
        (the head moved) or ``RefusedError`` (nothing pending, or the PR is closed) mean the
        outcome is unknown: it may have landed, or never been requested, and "no merge visible"
        is false while one is queued. Those propagate and block the effect for a person. Finding
        a merge that already landed needs a read-only lookup by key (D2-11)."""
        self._scm.dequeue(self._pr, self._sha)
        return Voided("dequeued")
