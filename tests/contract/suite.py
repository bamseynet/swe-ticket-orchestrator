"""Shared adapter conformance suite (D4-01, PLAN 10.2, ADR-0009, threat T6).

Written once. Every adapter in every later stage runs it, against whichever server a setting
selects: its in-process fake (the default) or the real API (``STO_CONFORMANCE_TARGET=live``).
When the real API disagrees with the fake, that is a bug in the fake.

How to use it: in a ``test_*.py`` file, subclass ``AdapterConformance`` as a ``Test*`` class and
provide a ``target`` fixture that returns a ``Target`` (see ``select_target``). This module is not
collected itself, and the base class is not either, because neither name starts with ``Test``.

A ``Target`` is the thin harness between the suite and one server. It exposes the port's canonical
idempotent write, and the **controls** the suite needs to provoke each failure: forging a
delivery, losing a response, rate limiting, revoking auth. A target declares which controls it
has. A test that needs a control the target lacks FAILS with ``MissingControl``; it is never
skipped, because a skip would read as a pass. A fake that is known to lack a control says so with
``@pending_controls(...)``, which turns that failure into a strict xfail. Adding the control then
fails the xfail until the marker is removed, so the gap cannot be forgotten.

What is covered (the criteria of D4-01):

* signature rejection (T6): forged, tampered, re-serialised, unsigned; nothing is enqueued, and a
  rejected delivery does not use up its delivery ID
* duplicates: a redelivery of one delivery ID is dropped, a new ID for similar content is not
* out-of-order delivery: a delivery is a nudge that names what changed, never the new state, so
  any order gives the same nudges and the same state on re-read
* crash after write: a lost response and a refused attempt both retry under one key to exactly
  one effect; a reused key with other arguments is refused
* rate limits: a limited call is transient, applies nothing, and succeeds on retry
* auth failure: permanent (never retried), applies nothing, and recovers once auth is restored

It runs in process with no Docker and no network when the target is a fake.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any, ClassVar

import pytest

from sto.adapters.ports import (
    ExternalChange,
    IdempotencyKeyReuseError,
    RawWebhook,
)
from sto.domain.errors import PermanentError, TransientError
from sto.domain.models import Receipt

TARGET_ENV = "STO_CONFORMANCE_TARGET"
DEFAULT_TARGET = "fake"
RETRIES = 5  # attempts the suite's stand-in for the effect layer's retry loop makes


class Control(StrEnum):
    SIGNATURE = "signature"  # sign / forge / tamper a delivery, and a verifier that rejects it
    DUPLICATE = "duplicate"  # dedupe by delivery ID
    ORDERING = "ordering"  # emit changes and read state back
    CRASH = "crash"  # lose a response / fail a call, then count real effects
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"


class MissingControl(AssertionError):
    """The target cannot provoke the failure this test needs (see the module docstring)."""


class Target:
    """One server under test. Subclasses override what they support and list it in ``controls``.

    ``write`` is the port's canonical idempotent write (a comment, a check, a message). ``variant``
    changes its arguments, so the same ``key`` with another ``variant`` is a key-derivation bug.
    ``effects`` counts the real state changes made so far, as the server saw them.
    """

    name: ClassVar[str] = "target"
    controls: ClassVar[frozenset[Control]] = frozenset()

    # --- the port's write ---
    def write(self, key: str, variant: str = "a") -> Receipt:
        raise NotImplementedError

    def effects(self) -> int:
        raise NotImplementedError

    # --- CRASH ---
    def lose_response_next(self) -> None:
        """The next write is applied, then the caller gets a transient error."""
        raise NotImplementedError

    def fail_next(self) -> None:
        """The next write applies nothing and raises a transient error."""
        raise NotImplementedError

    # --- RATE_LIMIT / AUTH ---
    def rate_limit_next(self, times: int) -> None:
        """The next ``times`` writes are rejected as rate limited (transient, nothing applied)."""
        raise NotImplementedError

    def revoke_auth(self) -> None:
        raise NotImplementedError

    def restore_auth(self) -> None:
        raise NotImplementedError

    # --- SIGNATURE / DUPLICATE / ORDERING: webhook side ---
    def signed(self, revision: int, delivery_id: str) -> RawWebhook:
        """A genuine delivery that says the watched object changed, to ``revision``. The server
        state moves to at least ``revision``."""
        raise NotImplementedError

    def forged(self, revision: int, delivery_id: str) -> RawWebhook:
        """A delivery signed with the wrong secret."""
        raise NotImplementedError

    def deliver(self, raw: RawWebhook) -> list[ExternalChange]:
        """Verify on the raw body, drop a repeated delivery ID, enqueue, and return the nudges
        this delivery adds. A bad signature raises ``PermanentError`` and enqueues nothing."""
        raise NotImplementedError

    def queued(self) -> int:
        """Nudges enqueued so far."""
        raise NotImplementedError

    def read_revision(self) -> int:
        """The watched object's revision, read from the server now (a re-read, not a body)."""
        raise NotImplementedError

    # --- helpers the suite relies on ---
    def require(self, *needed: Control) -> None:
        missing = sorted(c for c in needed if c not in self.controls)
        if missing:
            raise MissingControl(f"{self.name} has no control for: {', '.join(missing)}")


def select_target(factories: Mapping[str, Callable[[], Target]]) -> Target:
    """The target a setting selects: ``STO_CONFORMANCE_TARGET`` is ``fake`` (default) or ``live``.

    An adapter registers a factory per name. A name with no factory is an error, not a fallback to
    the fake: a run that was meant to prove the real API must not quietly prove the fake.
    """
    name = os.environ.get(TARGET_ENV, DEFAULT_TARGET)
    if name not in factories:
        raise pytest.UsageError(
            f"{TARGET_ENV}={name!r} but only {sorted(factories)} are registered for this adapter"
        )
    return factories[name]()


def needs(*controls: Control) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Tag a suite test with the controls it needs, so ``pending_controls`` can find it."""

    def tag(fn: Callable[..., None]) -> Callable[..., None]:
        fn._needs = frozenset(controls)  # type: ignore[attr-defined]
        return fn

    return tag


def pending_controls(*missing: Control) -> Callable[[type[Any]], type[Any]]:
    """Class decorator for a fake that is known not to have these controls yet.

    Each test needing one becomes a strict xfail on ``MissingControl``. It XPASSes, and so fails,
    as soon as the control exists, which is the signal to delete the marker.
    """
    gone = frozenset(missing)

    def apply(cls: type[Any]) -> type[Any]:
        for attr in dir(cls):
            fn = getattr(cls, attr)
            tags: frozenset[Control] = getattr(fn, "_needs", frozenset())
            if tags & gone:
                reason = f"known gap: no {', '.join(sorted(tags & gone))} control yet"
                mark = pytest.mark.xfail(strict=True, raises=MissingControl, reason=reason)
                own = functools.wraps(fn)(
                    lambda *a, _fn=fn, **k: _fn(*a, **k)
                )  # not the shared one
                own.__dict__.pop("pytestmark", None)
                setattr(cls, attr, mark(own))
        return cls

    return apply


def retrying[T](call: Callable[[], T], attempts: int = RETRIES) -> T:
    """The effect layer's rule in miniature: retry a transient failure, never a permanent one."""
    for attempt in range(attempts):
        try:
            return call()
        except TransientError:
            if attempt == attempts - 1:
                raise
    raise AssertionError("unreachable")


def _nudge_key(change: ExternalChange) -> Any:
    return (change.kind, change.ticket, change.repo, change.pr, change.sha, change.branch)


class AdapterConformance:
    """The tests. Provide a ``target`` fixture; every test starts from a fresh one."""

    @pytest.fixture
    def target(self) -> Target:  # pragma: no cover - overridden by every subclass
        raise NotImplementedError("subclass AdapterConformance and provide a `target` fixture")

    # ---- signature rejection (T6) -------------------------------------------------------

    @needs(Control.SIGNATURE)
    def test_t6_genuine_delivery_is_accepted(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        nudges = target.deliver(target.signed(1, "d-1"))
        assert nudges, "a correctly signed delivery must yield its nudge"
        assert target.queued() == len(nudges)

    @needs(Control.SIGNATURE)
    def test_t6_forged_signature_is_rejected_and_enqueues_nothing(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        with pytest.raises(PermanentError):
            target.deliver(target.forged(1, "d-1"))
        assert target.queued() == 0

    @needs(Control.SIGNATURE)
    def test_t6_tampered_body_is_rejected(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        genuine = target.signed(1, "d-1")
        tampered = RawWebhook(genuine.headers, genuine.body.replace(b"1", b"9"))
        assert tampered.body != genuine.body
        with pytest.raises(PermanentError):
            target.deliver(tampered)
        assert target.queued() == 0

    @needs(Control.SIGNATURE)
    def test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one(
        self, target: Target
    ) -> None:
        """Same JSON, different bytes: a verifier that parses first would let this through."""
        import json

        target.require(Control.SIGNATURE)
        genuine = target.signed(1, "d-1")
        reserialised = json.dumps(json.loads(genuine.body), indent=2).encode()
        assert reserialised != genuine.body
        with pytest.raises(PermanentError):
            target.deliver(RawWebhook(genuine.headers, reserialised))
        assert target.queued() == 0

    @needs(Control.SIGNATURE)
    def test_t6_unsigned_delivery_is_rejected(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        genuine = target.signed(1, "d-1")
        with pytest.raises(PermanentError):
            target.deliver(RawWebhook({}, genuine.body))
        assert target.queued() == 0

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_rejected_delivery_does_not_use_up_its_delivery_id(self, target: Target) -> None:
        """Else a forger who guesses the next delivery ID could block the genuine one."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        with pytest.raises(PermanentError):
            target.deliver(target.forged(1, "d-1"))
        assert target.deliver(target.signed(1, "d-1")), "the genuine d-1 must still be accepted"

    # ---- duplicates ---------------------------------------------------------------------

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_redelivery_of_the_same_delivery_id_is_dropped(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        raw = target.signed(1, "d-1")
        first = target.deliver(raw)
        assert first
        assert target.deliver(raw) == []
        assert target.queued() == len(first)

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_a_new_delivery_id_is_not_a_duplicate(self, target: Target) -> None:
        """Dedupe is by delivery ID, not by content: two real changes are both delivered."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        first = target.deliver(target.signed(1, "d-1"))
        second = target.deliver(target.signed(1, "d-2"))
        assert first
        assert second
        assert target.queued() == len(first) + len(second)

    # ---- out-of-order delivery ----------------------------------------------------------

    @needs(Control.SIGNATURE, Control.ORDERING)
    def test_delivery_order_does_not_change_the_nudges_or_the_state_read(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.ORDERING)
        deliveries = [target.signed(rev, f"d-{rev}") for rev in (1, 2, 3)]
        assert target.read_revision() == 3
        got = [target.deliver(raw) for raw in reversed(deliveries)]  # 3, 2, 1
        assert all(len(nudges) == 1 for nudges in got)
        assert len({_nudge_key(nudges[0]) for nudges in got}) == 1, "one object, one nudge target"
        assert target.read_revision() == 3, "a late, older delivery must not rewind state"

    # ---- crash after write --------------------------------------------------------------

    @needs(Control.CRASH)
    def test_lost_response_then_retry_with_the_same_key_writes_once(self, target: Target) -> None:
        target.require(Control.CRASH)
        target.lose_response_next()
        with pytest.raises(TransientError):
            target.write("k1")
        assert target.effects() == 1, "the write happened; only the answer was lost"
        receipt = target.write("k1")
        assert target.effects() == 1, "the retry must not write again"
        assert receipt.external_id

    @needs(Control.CRASH)
    def test_replaying_a_key_returns_the_first_receipt(self, target: Target) -> None:
        target.require(Control.CRASH)
        first = target.write("k1")
        again = target.write("k1")
        assert again.external_id == first.external_id
        assert target.effects() == 1

    @needs(Control.CRASH)
    def test_failure_before_the_write_applies_nothing_and_the_retry_applies_once(
        self, target: Target
    ) -> None:
        target.require(Control.CRASH)
        target.fail_next()
        with pytest.raises(TransientError):
            target.write("k1")
        assert target.effects() == 0
        retrying(lambda: target.write("k1"))
        assert target.effects() == 1

    @needs(Control.CRASH)
    def test_a_new_key_is_a_new_write(self, target: Target) -> None:
        target.require(Control.CRASH)
        target.write("k1", "a")
        target.write("k2", "b")
        assert target.effects() == 2

    @needs(Control.CRASH)
    def test_a_key_reused_with_other_arguments_is_refused(self, target: Target) -> None:
        target.require(Control.CRASH)
        target.write("k1", "a")
        with pytest.raises(IdempotencyKeyReuseError):
            target.write("k1", "b")
        assert target.effects() == 1

    # ---- rate limits --------------------------------------------------------------------

    @needs(Control.RATE_LIMIT)
    def test_rate_limited_calls_are_transient_apply_nothing_and_succeed_on_retry(
        self, target: Target
    ) -> None:
        target.require(Control.RATE_LIMIT)
        target.rate_limit_next(2)
        for _ in range(2):
            with pytest.raises(TransientError):
                target.write("k1")
            assert target.effects() == 0
        retrying(lambda: target.write("k1"))
        assert target.effects() == 1

    @needs(Control.RATE_LIMIT)
    def test_a_rate_limit_is_not_permanent(self, target: Target) -> None:
        """Else one burst of traffic would block a run for a person to retry."""
        target.require(Control.RATE_LIMIT)
        target.rate_limit_next(1)
        with pytest.raises(TransientError) as caught:
            target.write("k1")
        assert not isinstance(caught.value, PermanentError)
        assert caught.value.retryable

    # ---- auth failure -------------------------------------------------------------------

    @needs(Control.AUTH)
    def test_auth_failure_is_permanent_and_applies_nothing(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError) as caught:
            target.write("k1")
        assert not caught.value.retryable
        assert target.effects() == 0

    @needs(Control.AUTH)
    def test_auth_failure_is_not_retried_by_the_retry_rule(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        calls = 0

        def call() -> Receipt:
            nonlocal calls
            calls += 1
            return target.write("k1")

        with pytest.raises(PermanentError):
            retrying(call)
        assert calls == 1

    @needs(Control.AUTH)
    def test_the_write_succeeds_once_auth_is_restored(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError):
            target.write("k1")
        target.restore_auth()
        target.write("k1")
        assert target.effects() == 1
