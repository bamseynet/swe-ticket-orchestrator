"""Shared adapter conformance suite (D4-01, PLAN 10.2, ADR-0009, threat T6).

Written once. Every adapter in every later stage runs it, against whichever server a setting
selects: its in-process fake server (the default) or the real API (``STO_CONFORMANCE_TARGET=live``).
When the real API disagrees with the fake, that is a bug in the fake.

Reusing it
----------
In a ``test_*.py`` file next to ``suite.py``::

    import pytest

    pytest.register_assert_rewrite("suite")  # before the import, for readable failures
    from suite import AdapterConformance, Target  # noqa: E402

    class TestMyAdapter(AdapterConformance):
        registry = {"fake": MyFakeTarget, "live": MyLiveTarget}

``tests/`` is on ``pythonpath``, so a test in ANOTHER directory (``tests/adapters/github/``) cannot
``import suite`` (pytest only adds the test file's own directory). It imports ``contract.suite``
(a namespace package) with ``register_assert_rewrite("contract.suite")``. mypy then sees the file
under two names; the first consumer (D4-16) must resolve that, with a ``tests/contract/__init__.py``
or ``explicit_package_bases``, which are outside this issue's files.

The class name must start with ``Test`` or pytest collects nothing; ``__init_subclass__`` refuses
other names, and ``uncollected`` lets a test prove no subclass collected zero tests. The suite
owns target selection: the inherited ``target`` fixture reads ``STO_CONFORMANCE_TARGET`` (``fake``
by default), refuses a name that has no registered target, and never falls back to the fake. Note
for D4-15: a typo in the *name* of that variable runs the fake, and is not detectable here, so the
live CI job must set it and assert it from the run's ``conformance_target`` property.

What it is, and is not
----------------------
The harness (``Target``) is a thin pass-through. The truth lives in the **server** under it:
stored objects, signature secret, clock, 429/401/5xx/timeouts. Controls act at the server, and the
suite asserts what the SERVER saw (objects stored, calls made), never what the adapter says about
itself. Security and failure-mapping code (signature check, dedupe, replay window, error classes,
look-up-first) must live in the adapter under test, reached through ``target.verifier`` and
``target.deliver``, not in the harness. ``run_suite`` runs the suite against any target, which is
how a known-bad adapter proves the suite can catch it.

This section covers **Receipt-returning, keyed writes** only (comment, check, message). The SCM
section (``MergeHandle``, ``UpdateResult``, keyless ``move_ref``, ``dequeue``, update-branch)
belongs to D4-19. A delivery's result is whatever the port returns (nudges, or a ``Notifier``'s
``DecisionRequest | None``), so a target maps it to an ``Outcome``; the suite invents no nudge.

Covered: signature rejection (T6: forged, tampered, re-serialised, unsigned, forged with a seen
ID, forged not wiping dedupe memory, replay window, then re-read), duplicates, out-of-order
delivery, crash after write at each step of a write with a restart, look-up-first (paging, errors,
foreign markers), read-back, rate limits (429 and GitHub's 403 secondary shape), auth failure.

A test needing a control the target lacks FAILS with ``MissingControl``; it is never skipped.
``pending_controls`` can mark a *fake* as lacking a non-security control; it is refused for the
security controls, without a reason, and under a live run.
"""

from __future__ import annotations

import functools
import json
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Protocol

import pytest

from sto.adapters.ports import IdempotencyKeyReuseError, RawWebhook, UnknownRefError
from sto.domain.errors import PermanentError, TransientError
from sto.domain.models import Receipt

TARGET_ENV = "STO_CONFORMANCE_TARGET"
DEFAULT_TARGET = "fake"
LIVE_TARGET = "live"
RETRIES = 5


class Control(StrEnum):
    SIGNATURE = "signature"  # forge / tamper / re-serialise a delivery
    UNSIGNED = "unsigned"  # drop only the signature
    DUPLICATE = "duplicate"  # dedupe by delivery ID
    REPLAY_WINDOW = "replay_window"  # a clock, and a signed timestamp
    ORDERING = "ordering"  # emit changes at the server, read them back
    CRASH = "crash"  # fault at each step of a write
    RESTART = "restart"  # a fresh adapter over the same server
    LOOKUP = "lookup"  # look-up-first inspection: other objects, foreign markers
    READ_BACK = "read_back"  # a write the server accepts but does not apply
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"


# Opting out of these would hide a hole an attacker or a crash walks through.
SECURITY_CONTROLS = frozenset(
    {
        Control.SIGNATURE,
        Control.UNSIGNED,
        Control.DUPLICATE,
        Control.REPLAY_WINDOW,
        Control.CRASH,
        Control.RESTART,
    }
)


class CrashPoint(StrEnum):
    """Steps of a write: look up, post, answer (PLAN 10.2 and 6.3)."""

    LOOKUP_FAILS = "lookup_fails"  # the look-up itself errors (5xx)
    REJECTED_BEFORE_APPLY = "rejected_before_apply"  # the post fails and nothing is stored
    RESPONSE_LOST_AFTER_APPLY = "response_lost_after_apply"  # stored, caller sees a timeout


class RateShape(StrEnum):
    PRIMARY_429 = "primary_429"
    SECONDARY_403 = "secondary_403"  # GitHub: 403 with a retry-after, not a 429


class MissingControl(AssertionError):
    """The target cannot provoke the failure this test needs."""


@dataclass(frozen=True)
class Outcome:
    """What a delivery did, in the suite's terms. ``names`` identifies the object(s) the nudge or
    decision is about, as the target reads it from the port's own return type."""

    accepted: bool  # False: dropped as a duplicate
    names: tuple[str, ...] = ()


class Verifier(Protocol):
    """The shape the suite needs from an adapter's production verifier (D4-03 owns the real port).

    Returns the delivery ID. A rejection raises ``PermanentError``.
    """

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str: ...


class Target:
    """One server under test plus the adapter over it. Override what you support."""

    name: ClassVar[str] = "target"
    controls: ClassVar[frozenset[Control]] = frozenset()
    signature_header: ClassVar[str] = "X-Signature"
    replay_window: ClassVar[float] = 300.0
    watched: str = ""  # the name a nudge for the watched object must carry
    retry_after_hint: ClassVar[float] = 0.0
    selected: str = DEFAULT_TARGET  # set by the fixture: which target ran
    verifier: Verifier

    # --- adapter calls ---
    def write(self, key: str, variant: str = "a") -> Receipt:
        raise NotImplementedError

    def restart(self) -> None:
        """A fresh adapter (no in-process memory) over the same server."""
        raise NotImplementedError

    def deliver(self, raw: RawWebhook) -> Outcome:
        raise NotImplementedError

    def queued(self) -> int:
        raise NotImplementedError

    def reported_revision(self) -> int:
        """What the adapter says the watched object's revision is, a re-read it must make."""
        raise NotImplementedError

    # --- the server's view ---
    def stored_ids(self) -> list[str]:
        """IDs of the objects our principal has stored, oldest first."""
        raise NotImplementedError

    def stored_id_for(self, key: str) -> str | None:
        raise NotImplementedError

    def calls(self, op: str) -> int:
        """Requests the server received: ``lookup``, ``write``, ``read``, ``unauthorized``,
        ``limited``."""
        raise NotImplementedError

    def server_revision(self) -> int:
        raise NotImplementedError

    # --- controls, acting at the server ---
    def crash(self, point: CrashPoint) -> None:
        raise NotImplementedError

    def seed_others(self, n: int) -> None:
        """``n`` objects by other authors, newer than everything stored so far."""
        raise NotImplementedError

    def plant_foreign_marker(self, key: str) -> None:
        """Another author stores an object carrying this adapter's marker for ``key``."""
        raise NotImplementedError

    def swallow_next_write(self) -> None:
        """The next write is answered success but not applied."""
        raise NotImplementedError

    def rate_limit_next(self, times: int, shape: RateShape) -> None:
        raise NotImplementedError

    def revoke_auth(self) -> None:
        raise NotImplementedError

    def restore_auth(self) -> None:
        raise NotImplementedError

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        """The vendor changes the watched object to ``revision`` and sends a genuine delivery."""
        raise NotImplementedError

    def forge(self, revision: int, delivery_id: str) -> RawWebhook:
        """A delivery signed with the wrong secret. It changes nothing at the server."""
        raise NotImplementedError

    def advance_clock(self, seconds: float) -> None:
        raise NotImplementedError

    def require(self, *needed: Control) -> None:
        missing = sorted(c for c in needed if c not in self.controls)
        if missing:
            raise MissingControl(f"{self.name} has no control for: {', '.join(missing)}")


# --- selection ------------------------------------------------------------------------------


def resolve(registry: Mapping[str, Callable[[], Target]]) -> tuple[str, Target]:
    """The target ``STO_CONFORMANCE_TARGET`` selects. An unregistered name is an error, never the
    fake: a run meant to prove the real API must not quietly prove the fake."""
    name = os.environ.get(TARGET_ENV, DEFAULT_TARGET)
    if name not in registry:
        raise pytest.UsageError(
            f"{TARGET_ENV}={name!r} but only {sorted(registry)} are registered for this adapter"
        )
    target = registry[name]()
    target.selected = name
    return name, target


def check_not_simulated(target: Target, receipt: Receipt) -> None:
    """A live run must have talked to the real service: a simulated receipt proves a fake."""
    if target.selected == LIVE_TARGET and receipt.simulated:
        pytest.fail(f"{LIVE_TARGET} target returned a simulated receipt: this run proved a fake")


def _write(target: Target, key: str, variant: str = "a") -> Receipt:
    receipt = target.write(key, variant)
    check_not_simulated(target, receipt)
    return receipt


# --- known gaps (fakes only) ----------------------------------------------------------------


def needs(*controls: Control) -> Callable[[Callable[..., None]], Callable[..., None]]:
    def tag(fn: Callable[..., None]) -> Callable[..., None]:
        fn._needs = frozenset(controls)  # type: ignore[attr-defined]
        return fn

    return tag


def pending_controls(*missing: Control, reason: str) -> Callable[[type[Any]], type[Any]]:
    """Class decorator for a FAKE known to lack non-security controls.

    Each test needing one becomes a strict xfail on ``MissingControl``. Refused for the security
    controls, without a reason, and when the live target is selected (a live run proves the real
    API, so nothing may be waived).
    """
    if not reason.strip():
        raise ValueError("pending_controls needs a reason")
    banned = sorted(set(missing) & SECURITY_CONTROLS)
    if banned:
        raise ValueError(f"pending_controls cannot waive security controls: {', '.join(banned)}")
    gone = frozenset(missing)

    def apply(cls: type[Any]) -> type[Any]:
        for attr in dir(cls):
            fn = getattr(cls, attr)
            tags: frozenset[Control] = getattr(fn, "_needs", frozenset())
            if not tags & gone:
                continue
            mark = pytest.mark.xfail(strict=True, raises=MissingControl, reason=reason)

            def guarded(*a: Any, _fn: Callable[..., None] = fn, **k: Any) -> None:
                if os.environ.get(TARGET_ENV, DEFAULT_TARGET) == LIVE_TARGET:
                    pytest.fail("pending_controls is not allowed under a live run")
                _fn(*a, **k)

            own = functools.wraps(fn)(guarded)  # a copy: marking `fn` would mark every class
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


SUBCLASSES: list[type] = []


def uncollected(classes: Iterable[type], items: Iterable[Any]) -> list[str]:
    """Conformance subclasses in a ``test_*.py`` module that collected no test."""
    collected = {getattr(item, "cls", None) for item in items}
    out = []
    for cls in classes:
        module_file = getattr(__import__(cls.__module__, fromlist=["x"]), "__file__", "") or ""
        if os.path.basename(module_file).startswith("test_") and cls not in collected:
            out.append(f"{cls.__module__}.{cls.__name__}")
    return out


class AdapterConformance:
    """The tests. Set ``registry``; the inherited ``target`` fixture does the selecting."""

    registry: ClassVar[Mapping[str, Callable[[], Target]]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.__name__.startswith("Test"):
            raise TypeError(
                f"{cls.__name__}: a conformance subclass must be named Test*, else pytest "
                "collects none of its tests"
            )
        if not hasattr(cls, "registry"):
            raise TypeError(f"{cls.__name__} must set `registry`")
        SUBCLASSES.append(cls)

    @pytest.fixture
    def target(self, request: pytest.FixtureRequest) -> Target:
        name, target = resolve(self.registry)
        request.node.user_properties.append(("conformance_target", name))
        return target

    # ---- signature rejection (T6) -------------------------------------------------------

    @needs(Control.SIGNATURE)
    def test_t6_the_production_verifier_accepts_a_genuine_delivery(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        raw = target.emit(1, "d-1")
        assert target.verifier.verify(raw.headers, raw.body) == "d-1"

    @needs(Control.SIGNATURE)
    def test_t6_the_production_verifier_rejects_a_forged_delivery(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        raw = target.forge(1, "d-1")
        with pytest.raises(PermanentError):
            target.verifier.verify(raw.headers, raw.body)

    @needs(Control.SIGNATURE)
    def test_t6_genuine_delivery_is_accepted(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        outcome = target.deliver(target.emit(1, "d-1"))
        assert outcome.accepted
        assert outcome.names == (target.watched,)
        assert target.queued() == 1

    @needs(Control.SIGNATURE)
    def test_t6_forged_signature_is_rejected_and_enqueues_nothing(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))
        assert target.queued() == 0

    @needs(Control.SIGNATURE)
    def test_t6_tampered_body_is_rejected(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        genuine = target.emit(1, "d-1")
        tampered = RawWebhook(genuine.headers, genuine.body.replace(b"1", b"9", 1))
        assert tampered.body != genuine.body
        with pytest.raises(PermanentError):
            target.deliver(tampered)
        assert target.queued() == 0

    @needs(Control.SIGNATURE)
    def test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one(
        self, target: Target
    ) -> None:
        """Same JSON, different bytes: a verifier that parses first would let this through."""
        target.require(Control.SIGNATURE)
        genuine = target.emit(1, "d-1")
        reserialised = json.dumps(json.loads(genuine.body), indent=2).encode()
        assert reserialised != genuine.body
        with pytest.raises(PermanentError):
            target.deliver(RawWebhook(genuine.headers, reserialised))
        assert target.queued() == 0

    @needs(Control.UNSIGNED)
    def test_t6_a_delivery_with_only_the_signature_removed_is_rejected(
        self, target: Target
    ) -> None:
        """Everything else is intact (delivery ID, timestamp), so only the missing signature can
        be the reason for the rejection."""
        target.require(Control.UNSIGNED)
        genuine = target.emit(1, "d-1")
        keep = target.signature_header.lower()
        stripped = {k: v for k, v in genuine.headers.items() if k.lower() != keep}
        assert len(stripped) == len(genuine.headers) - 1, "the signature header was not present"
        with pytest.raises(PermanentError):
            target.deliver(RawWebhook(stripped, genuine.body))
        assert target.queued() == 0

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_rejected_delivery_does_not_use_up_its_delivery_id(self, target: Target) -> None:
        """Else a forger who guesses the next delivery ID could block the genuine one."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))
        assert target.deliver(target.emit(1, "d-1")).accepted

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_forged_delivery_with_a_seen_id_is_rejected_not_dropped(
        self, target: Target
    ) -> None:
        """Answering "duplicate" is a silent 2xx for a forgery."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        assert target.deliver(target.emit(1, "d-1")).accepted
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_forged_delivery_does_not_wipe_the_dedupe_memory(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        genuine = target.emit(1, "d-1")
        assert target.deliver(genuine).accepted
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))
        assert not target.deliver(genuine).accepted, "the genuine redelivery must still be a dup"
        assert target.queued() == 1

    @needs(Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_genuine_delivery_outside_the_replay_window_is_rejected(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        target.advance_clock(target.replay_window + 1)
        with pytest.raises(PermanentError):
            target.deliver(raw)
        assert target.queued() == 0

    @needs(Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_genuine_delivery_inside_the_replay_window_is_accepted(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        target.advance_clock(target.replay_window - 1)
        assert target.deliver(raw).accepted

    # ---- duplicates ---------------------------------------------------------------------

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_redelivery_of_the_same_delivery_id_is_dropped(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        assert not target.deliver(raw).accepted
        assert target.queued() == 1

    @needs(Control.SIGNATURE, Control.DUPLICATE)
    def test_a_new_delivery_id_is_not_a_duplicate(self, target: Target) -> None:
        """Dedupe is by delivery ID, not by content: two real changes are both delivered."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        assert target.deliver(target.emit(1, "d-1")).accepted
        assert target.deliver(target.emit(1, "d-2")).accepted
        assert target.queued() == 2

    # ---- out-of-order delivery, and webhooks as nudges ----------------------------------

    @needs(Control.SIGNATURE, Control.ORDERING)
    def test_delivery_order_does_not_change_what_the_adapter_reports(self, target: Target) -> None:
        """Deliveries 3, 2, 1 arrive after the server is at 3. The adapter must report what the
        SERVER says, so a cache fed from delivery bodies shows up as 1."""
        target.require(Control.SIGNATURE, Control.ORDERING)
        deliveries = [target.emit(rev, f"d-{rev}") for rev in (1, 2, 3)]
        assert target.server_revision() == 3
        outcomes = [target.deliver(raw) for raw in reversed(deliveries)]
        assert all(o.accepted for o in outcomes)
        assert target.reported_revision() == target.server_revision() == 3

    @needs(Control.SIGNATURE, Control.ORDERING)
    def test_every_nudge_names_the_object_that_changed(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.ORDERING)
        outcomes = [target.deliver(target.emit(rev, f"d-{rev}")) for rev in (2, 1)]
        assert [o.names for o in outcomes] == [(target.watched,)] * 2

    @needs(Control.SIGNATURE, Control.ORDERING)
    def test_after_a_delivery_state_is_re_read_from_the_server(self, target: Target) -> None:
        """ "Then re-read state" (T6): the answer must cost a request, not come from a cache."""
        target.require(Control.SIGNATURE, Control.ORDERING)
        target.deliver(target.emit(1, "d-1"))
        before = target.calls("read")
        target.reported_revision()
        assert target.calls("read") == before + 1

    # ---- crash after write, at each step ------------------------------------------------

    def _crash_then_retry(self, target: Target, point: CrashPoint, applied: bool) -> None:
        target.require(Control.CRASH, Control.RESTART)
        target.crash(point)
        with pytest.raises(TransientError):
            _write(target, "k1")
        assert len(target.stored_ids()) == (1 if applied else 0), "the server's view of the crash"
        target.restart()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id], "exactly one, and the one it names"
        assert target.stored_id_for("k1") == receipt.external_id

    @needs(Control.CRASH, Control.RESTART)
    def test_crash_when_the_lookup_fails_then_a_restart_writes_once(self, target: Target) -> None:
        self._crash_then_retry(target, CrashPoint.LOOKUP_FAILS, applied=False)

    @needs(Control.CRASH, Control.RESTART)
    def test_crash_when_the_post_is_rejected_then_a_restart_writes_once(
        self, target: Target
    ) -> None:
        self._crash_then_retry(target, CrashPoint.REJECTED_BEFORE_APPLY, applied=False)

    @needs(Control.CRASH, Control.RESTART)
    def test_crash_after_the_write_applied_then_a_restart_does_not_write_again(
        self, target: Target
    ) -> None:
        self._crash_then_retry(target, CrashPoint.RESPONSE_LOST_AFTER_APPLY, applied=True)

    @needs(Control.RESTART)
    def test_a_fresh_adapter_replaying_a_key_returns_the_servers_object(
        self, target: Target
    ) -> None:
        target.require(Control.RESTART)
        first = _write(target, "k1")
        target.restart()
        again = _write(target, "k1")
        assert again.external_id == first.external_id == target.stored_id_for("k1")
        assert target.stored_ids() == [first.external_id]

    @needs(Control.CRASH)
    def test_a_new_key_is_a_new_write(self, target: Target) -> None:
        target.require(Control.CRASH)
        a, b = _write(target, "k1", "a"), _write(target, "k2", "b")
        assert a.external_id != b.external_id
        assert target.stored_ids() == [a.external_id, b.external_id]

    @needs(Control.CRASH, Control.RESTART)
    def test_a_key_reused_with_other_arguments_is_refused_even_after_a_restart(
        self, target: Target
    ) -> None:
        target.require(Control.CRASH, Control.RESTART)
        _write(target, "k1", "a")
        with pytest.raises(IdempotencyKeyReuseError):
            target.write("k1", "b")
        target.restart()
        with pytest.raises(IdempotencyKeyReuseError):
            target.write("k1", "b")
        assert len(target.stored_ids()) == 1

    # ---- look-up-first (PLAN 6.3) -------------------------------------------------------

    @needs(Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_lookup_reads_past_the_first_page(self, target: Target) -> None:
        """35 newer objects push our marker onto page 2: reading only page 1 writes twice."""
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        target.crash(CrashPoint.RESPONSE_LOST_AFTER_APPLY)
        with pytest.raises(TransientError):
            target.write("k1")
        target.seed_others(35)
        target.restart()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]

    @needs(Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_a_server_error_on_lookup_is_not_taken_for_not_found(self, target: Target) -> None:
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        first = _write(target, "k1")
        target.restart()
        target.crash(CrashPoint.LOOKUP_FAILS)
        with pytest.raises(TransientError):
            target.write("k1")
        assert target.stored_ids() == [first.external_id], "a failed look-up must not write"
        assert _write(target, "k1").external_id == first.external_id

    @needs(Control.LOOKUP)
    def test_a_marker_planted_by_another_author_is_not_trusted(self, target: Target) -> None:
        """G9: anyone who can comment could otherwise suppress our real comment."""
        target.require(Control.LOOKUP)
        target.plant_foreign_marker("k1")
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]
        assert target.stored_id_for("k1") == receipt.external_id

    # ---- read-back (PLAN 6.3, G8) -------------------------------------------------------

    @needs(Control.READ_BACK)
    def test_an_applied_write_is_reported_read_back_verified(self, target: Target) -> None:
        target.require(Control.READ_BACK)
        assert _write(target, "k1").read_back_verified

    @needs(Control.READ_BACK)
    def test_a_write_accepted_but_not_applied_is_never_reported_verified(
        self, target: Target
    ) -> None:
        target.require(Control.READ_BACK)
        target.swallow_next_write()
        try:
            receipt = target.write("k1")
        except TransientError:
            pass  # refusing is also honest
        else:
            assert not receipt.read_back_verified
        assert target.stored_ids() == [], "the server really did not apply it"

    # ---- rate limits --------------------------------------------------------------------

    def _rate_limited(self, target: Target, shape: RateShape) -> None:
        target.require(Control.RATE_LIMIT)
        target.rate_limit_next(2, shape)
        for attempt in (1, 2):
            with pytest.raises(TransientError) as caught:
                target.write("k1")
            assert target.calls("limited") == attempt, "one request per attempt: no hammering"
            hint = getattr(caught.value, "retry_after", None)
            if hint is not None:  # the port has no field for it; honoured where an adapter sets it
                assert hint >= target.retry_after_hint
            assert target.stored_ids() == []
        receipt = retrying(lambda: _write(target, "k1"))
        assert target.stored_ids() == [receipt.external_id]

    @needs(Control.RATE_LIMIT)
    def test_a_429_is_transient_applies_nothing_and_is_not_hammered(self, target: Target) -> None:
        self._rate_limited(target, RateShape.PRIMARY_429)

    @needs(Control.RATE_LIMIT)
    def test_githubs_403_secondary_limit_is_transient_not_a_permission_error(
        self, target: Target
    ) -> None:
        self._rate_limited(target, RateShape.SECONDARY_403)

    # ---- auth failure -------------------------------------------------------------------

    @needs(Control.AUTH)
    def test_a_401_is_permanent_applies_nothing_and_is_asked_once(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError) as caught:
            retrying(lambda: target.write("k1"))
        assert not isinstance(caught.value, UnknownRefError), "auth is not 'not found'"
        assert target.calls("unauthorized") == 1, "a permanent failure must not be retried"
        assert target.stored_ids() == []

    @needs(Control.AUTH)
    def test_the_write_succeeds_once_auth_is_restored(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError):
            target.write("k1")
        target.restore_auth()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]


def run_suite(factory: Callable[[], Target]) -> dict[str, BaseException | None]:
    """Run every test against fresh targets from ``factory``: name -> the failure, or None.

    A known-bad adapter must come back with failures: that is how the suite proves it can catch it.
    """
    out: dict[str, BaseException | None] = {}
    for name in dir(AdapterConformance):
        if not name.startswith("test_"):
            continue
        try:
            getattr(AdapterConformance.__new__(AdapterConformance), name)(factory())
            out[name] = None
        except (Exception, pytest.fail.Exception) as exc:
            out[name] = exc
    return out
