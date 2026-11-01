"""Shared adapter conformance suite (D4-01, PLAN 10.2, ADR-0009, threat T6).

Written once. Every adapter in every later stage runs it, against whichever server a setting
selects: its in-process fake server (the default) or the real API (``STO_CONFORMANCE_TARGET``).
When the real API disagrees with the fake, that is a bug in the fake.

Reusing it
----------
Import it as ``contract.suite`` from any test directory (``tests/`` is on ``pythonpath`` and
``tests/contract`` is a package)::

    import pytest

    pytest.register_assert_rewrite("contract.suite")  # before the import, for readable failures
    from contract.suite import AdapterConformance, Port, Target  # noqa: E402

    class TestMyAdapter(AdapterConformance):
        port = Port.TICKET_SOURCE
        registry = {"fake": MyFakeTarget, "live": MyLiveTarget}

Outside ``tests/contract`` also load the guards, in that directory's ``conftest.py``::

    pytest_plugins = ["contract.conftest"]

The guards (``check_collection`` and ``enforce_outcome``) fail the run if a subclass collected no
test (under ``-m`` too), if a suite test was replaced, and if a suite test is skipped or xfailed
by anything but ``pending_controls``. A subclass cannot override a ``test_*`` method, the
``target`` fixture, ``pytestmark`` or ``__test__``; it must be named ``Test*``.

Sections, ports and capabilities
--------------------------------
Which sections a target must pass comes from the PORT the adapter implements (``PORT_SECTIONS``),
never from the adapter's choice. A webhook-only target (``Port.WEBHOOK``) is not asked to survive
a crash. A target declares typed ``Capabilities`` (signed timestamp, the rate-limit shapes its
vendor uses, auth refresh). A capability never removes a control: it selects which assertion a
mandatory test makes. Signature, dedupe, auth and idempotency cannot be declared out.

What the harness is
-------------------
``Target`` is a thin pass-through. The truth lives in the **server** under it: stored objects,
signature secret, clock, 429/403/401/404/5xx/timeouts. Controls act at the server, and the suite
asserts what the SERVER saw, never what the adapter says about itself. Security and
failure-mapping code (signature check, dedupe, replay window, error classes, look-up-first) must
live in the adapter under test, reached through ``target.verifier`` and ``target.deliver``. The
suite never parses a delivery body: the target forges, tampers and re-serialises it, so a
form-encoded vendor works. ``run_suite`` runs the suite against any target, which is how a
known-bad adapter proves the suite can catch it; ``HarnessError`` marks a broken harness, as
opposed to an adapter failing the contract.

This section covers **Receipt-returning, keyed writes** only (comment, check, message). The SCM
section (``MergeHandle``, ``UpdateResult``, keyless ``move_ref``, ``dequeue``, update-branch)
belongs to D4-19. A delivery's result is whatever the port returns (nudges, or a ``Notifier``'s
``DecisionRequest | None``); a target maps it to an ``Outcome``. The suite invents no nudge.

Not testable black-box: constant-time comparison (T4). D4-04 owns it as a static check.

A test needing a control the target lacks FAILS with ``MissingControl``; it is never skipped.
``pending_controls`` lets a FAKE (a class under ``sto.adapters.fake``) lack the one waivable
control, with a reason; it cannot be used on anything that is not a fake.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Protocol

import pytest

from sto.adapters.ports import (
    IdempotencyKeyReuseError,
    MalformedWebhookError,
    RawWebhook,
    UnknownRefError,
)
from sto.domain.errors import PermanentError, TransientError
from sto.domain.models import Receipt

TARGET_ENV = "STO_CONFORMANCE_TARGET"
DEFAULT_TARGET = "fake"  # the only name whose receipts may be simulated
MAX_REPLAY_WINDOW = 300.0  # seconds; set here, a target cannot raise it
PAGE_SIZE = 100  # GitHub's maximum; the server pages at this size
RETRIES = 5
FAKE_MODULE = "sto.adapters.fake"
PORT_ERROR_MODULES = frozenset({"sto.adapters.ports", "sto.domain.errors"})


class Section(StrEnum):
    WEBHOOK = "webhook"  # signature, dedupe, replay window, nudges
    ORDERING = "ordering"  # needs a state read
    IDEMPOTENCY = "idempotency"  # crash at each step, restart, keys
    LOOKUP = "lookup"  # look-up-first (PLAN 6.3)
    READ_BACK = "read_back"  # needs a read after the write
    RATE = "rate"
    AUTH = "auth"


class Port(StrEnum):
    TICKET_SOURCE = "ticket_source"
    SCM = "scm"
    NOTIFIER = "notifier"  # no read: no ordering or read-back sections
    WEBHOOK = "webhook"  # ingest only (D4-03, D4-04)
    AUTH_WEBHOOK = "auth_webhook"  # a fake server's auth and webhooks (D4-16)


_ALL = frozenset(Section)
PORT_SECTIONS: Mapping[Port, frozenset[Section]] = {
    Port.TICKET_SOURCE: _ALL,
    Port.SCM: _ALL,
    Port.NOTIFIER: _ALL - {Section.ORDERING, Section.READ_BACK},
    Port.WEBHOOK: frozenset({Section.WEBHOOK}),
    Port.AUTH_WEBHOOK: frozenset({Section.WEBHOOK, Section.ORDERING, Section.RATE, Section.AUTH}),
}


class Control(StrEnum):
    SIGNATURE = "signature"
    UNSIGNED = "unsigned"
    DUPLICATE = "duplicate"
    REPLAY_WINDOW = "replay_window"
    ORDERING = "ordering"
    CRASH = "crash"
    RESTART = "restart"
    LOOKUP = "lookup"
    READ_BACK = "read_back"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    HTTP_ERRORS = "http_errors"  # a plain 403 and 404 from the server


# The only control a fake may lack. Everything else is a hole an attacker or a crash walks through.
WAIVABLE = frozenset({Control.HTTP_ERRORS})
SECURITY_CONTROLS = frozenset(Control) - WAIVABLE


class CrashPoint(StrEnum):
    """Steps of a write: look up, post, answer (PLAN 10.2 and 6.3)."""

    LOOKUP_FAILS = "lookup_fails"
    REJECTED_BEFORE_APPLY = "rejected_before_apply"
    RESPONSE_LOST_AFTER_APPLY = "response_lost_after_apply"


class RateShape(StrEnum):
    PRIMARY_429 = "primary_429"  # 429 with Retry-After
    PRIMARY_429_NO_HEADER = "primary_429_no_header"
    SECONDARY_403 = "secondary_403"  # GitHub: 403 with Retry-After
    PRIMARY_403_REMAINING_ZERO = "primary_403_remaining_zero"  # 403, x-ratelimit-remaining: 0


class AuthRefresh(StrEnum):
    NONE = "none"
    ONCE = "once"  # a 401 gets exactly one refresh and one retry (Jira 3LO, D6-02)


class ForgeKind(StrEnum):
    WRONG_SECRET = "wrong_secret"
    TRUNCATED_MAC = "truncated_mac"
    EMPTY_MAC = "empty_mac"
    EMPTY_KEY = "empty_key"  # a MAC made with an empty secret


@dataclass(frozen=True)
class Capabilities:
    signed_timestamp: bool = True  # False: GitHub; the adapter may use no time header for replay
    rate_shapes: frozenset[RateShape] = field(default=frozenset({RateShape.PRIMARY_429}))
    auth_refresh: AuthRefresh = AuthRefresh.NONE

    def __post_init__(self) -> None:
        if not self.rate_shapes:
            raise ValueError("declare at least one rate-limit shape the vendor uses")


class MissingControl(AssertionError):
    """The target cannot provoke the failure this test needs."""


class HarnessError(Exception):
    """The harness is broken or inconsistent: not an adapter failing the contract."""


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


def _unset(what: str) -> HarnessError:
    return HarnessError(f"the target does not implement {what}")


class Target:
    """One server under test plus the adapter over it. Override what you support."""

    name: ClassVar[str] = "target"
    controls: ClassVar[frozenset[Control]] = frozenset()
    capabilities: Capabilities = Capabilities()
    signature_header: ClassVar[str] = "X-Signature"
    replay_window: float = MAX_REPLAY_WINDOW
    watched: str = ""  # the name a nudge for the watched object must carry
    selected: str = DEFAULT_TARGET  # set by the fixture: which target ran
    verifier: Verifier

    # --- adapter calls ---
    def write(self, key: str, variant: str = "a") -> Receipt:
        raise _unset("write")

    def restart(self) -> None:
        """A fresh adapter (no in-process memory) over the same server and the same durable
        stores (the dedupe table, the queue)."""
        raise _unset("restart")

    def deliver(self, raw: RawWebhook) -> Outcome:
        raise _unset("deliver")

    def queued(self) -> int:
        raise _unset("queued")

    def reported_revision(self) -> int:
        """What the adapter says the watched object's revision is: a read it must make."""
        raise _unset("reported_revision")

    # --- the server's view ---
    def stored_ids(self) -> list[str]:
        """IDs of the objects our principal has stored, oldest first."""
        raise _unset("stored_ids")

    def stored_id_for(self, key: str) -> str | None:
        raise _unset("stored_id_for")

    def calls(self, op: str) -> int:
        """Requests the server received: ``lookup``, ``write``, ``read``, ``refresh``,
        ``unauthorized``, ``limited``."""
        raise _unset("calls")

    def server_revision(self) -> int:
        raise _unset("server_revision")

    def retry_after_hint(self, shape: RateShape) -> float | None:
        """The seconds the server's answer for this shape asks for, or None if it names none."""
        raise _unset("retry_after_hint")

    # --- controls, acting at the server ---
    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        """The next ``op`` request (``lookup``, ``write``, ``read``), after skipping ``after`` of
        them and only for ``page`` if given, suffers ``mode``: ``5xx`` (nothing applied),
        ``timeout`` (nothing applied) or ``lose`` (a write applied, the caller sees a timeout)."""
        raise _unset("fault_next")

    def respond_next(self, op: str, status: int) -> None:
        """The next ``op`` request is answered with a plain ``status`` (403 or 404)."""
        raise _unset("respond_next")

    def seed_others(self, n: int, newer: bool = True) -> None:
        """``n`` objects by other authors, stored after (``newer``) or before everything so far."""
        raise _unset("seed_others")

    def set_list_order(self, order: str) -> None:
        """``newest_first`` or ``oldest_first``: how the server lists objects."""
        raise _unset("set_list_order")

    def plant_foreign_marker(self, key: str, variant: str = "a", author: str = "mallory") -> None:
        """Another author stores an object carrying this adapter's marker for ``key``."""
        raise _unset("plant_foreign_marker")

    def swallow_next_write(self) -> None:
        """The next write is answered success but not applied."""
        raise _unset("swallow_next_write")

    def rate_limit_next(self, times: int, shape: RateShape, op: str | None = None) -> None:
        """The next ``times`` requests (of ``op``, or of any) get this shape of rate limit."""
        raise _unset("rate_limit_next")

    def revoke_auth(self, op: str | None = None) -> None:
        """Reject every request (or just ``op``) with a 401, even after a refresh."""
        raise _unset("revoke_auth")

    def restore_auth(self) -> None:
        raise _unset("restore_auth")

    def expire_token(self) -> None:
        """The credential the adapter holds stops working; a refresh yields one that works."""
        raise _unset("expire_token")

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        """The vendor changes the watched object to ``revision`` and sends a genuine delivery."""
        raise _unset("emit")

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        """Like ``emit`` in every byte and header but the signature. It changes nothing at the
        server."""
        raise _unset("forge")

    def emit_without_id(self, revision: int) -> RawWebhook:
        """A genuinely signed delivery that carries no delivery ID."""
        raise _unset("emit_without_id")

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        """A genuinely signed delivery whose body cannot be understood."""
        raise _unset("emit_malformed")

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        """A genuine delivery stamped ``ahead`` seconds in the future."""
        raise _unset("future_dated")

    def bump_timestamp(self, raw: RawWebhook) -> RawWebhook:
        """The same delivery with its timestamp header set to the server's time now."""
        raise _unset("bump_timestamp")

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        """The same signature over a body with one byte changed."""
        raise _unset("tamper")

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        """The same content in different bytes (the body is not parsed by the suite)."""
        raise _unset("reserialise")

    def strip_signature(self, raw: RawWebhook) -> RawWebhook:
        """The same delivery with only the signature header removed."""
        keep = self.signature_header.lower()
        headers = {k: v for k, v in raw.headers.items() if k.lower() != keep}
        if len(headers) != len(raw.headers) - 1:
            raise HarnessError(f"no {self.signature_header} header to remove")
        return RawWebhook(headers, raw.body)

    def advance_clock(self, seconds: float) -> None:
        raise _unset("advance_clock")

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
    """Only the fake may return simulated receipts. Any other name (live, staging, ...) is meant
    to talk to a real service, so a simulated receipt there proves a fake."""
    if target.selected != DEFAULT_TARGET and receipt.simulated:
        pytest.fail(f"{target.selected!r} returned a simulated receipt: this run proved a fake")


def _write(target: Target, key: str, variant: str = "a") -> Receipt:
    receipt = target.write(key, variant)
    check_not_simulated(target, receipt)
    return receipt


def _crash(target: Target, point: CrashPoint) -> None:
    op, mode = {
        CrashPoint.LOOKUP_FAILS: ("lookup", "5xx"),
        CrashPoint.REJECTED_BEFORE_APPLY: ("write", "5xx"),
        CrashPoint.RESPONSE_LOST_AFTER_APPLY: ("write", "lose"),
    }[point]
    target.fault_next(op, mode)


def is_auth_error(exc: BaseException) -> bool:
    """A permanent error that means "your credentials or permissions are no good", not "not
    found", "stale", "refused" or any other port error."""
    if not isinstance(exc, PermanentError):
        return False
    return type(exc) is PermanentError or type(exc).__module__ not in PORT_ERROR_MODULES


# --- known gaps (fakes only) ----------------------------------------------------------------

_SUITE_TESTS: dict[str, Callable[..., None]] = {}
_WAIVER = object()


def covers(
    section: Section, *controls: Control
) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Tag a suite test with its section and the controls it needs."""

    def tag(fn: Callable[..., None]) -> Callable[..., None]:
        fn._section = section  # type: ignore[attr-defined]
        fn._needs = frozenset(controls)  # type: ignore[attr-defined]
        _SUITE_TESTS[fn.__name__] = fn
        return fn

    return tag


def pending_controls(
    *missing: Control, reason: str, fake: type[Any]
) -> Callable[[type[Any]], type[Any]]:
    """Class decorator for a FAKE (``fake`` must be defined under ``sto.adapters.fake``) that
    lacks a waivable control. Each test needing one becomes a strict xfail on ``MissingControl``.

    Refused unless ``fake`` is a fake, without a reason, for any non-waivable control, and when the
    target that runs is not the default ``fake`` (checked at run time, in every mode).
    """
    if not reason.strip():
        raise ValueError("pending_controls needs a reason")
    if not fake.__module__.startswith(FAKE_MODULE):
        raise ValueError(
            f"pending_controls is for fakes under {FAKE_MODULE}, not {fake.__module__}"
        )
    banned = sorted(set(missing) - WAIVABLE)
    if banned:
        raise ValueError(f"pending_controls cannot waive security controls: {', '.join(banned)}")
    gone = frozenset(missing)

    def apply(cls: type[Any]) -> type[Any]:
        for attr in dir(cls):
            fn = getattr(cls, attr)
            if attr not in _SUITE_TESTS or not getattr(fn, "_needs", frozenset()) & gone:
                continue
            mark = pytest.mark.xfail(strict=True, raises=MissingControl, reason=reason)

            def guarded(*a: Any, _fn: Callable[..., None] = fn, **k: Any) -> None:
                target = a[1] if len(a) > 1 else k.get("target")
                if getattr(target, "selected", DEFAULT_TARGET) != DEFAULT_TARGET:
                    pytest.fail("pending_controls is only for the fake target")
                _fn(*a, **k)

            own = functools.wraps(fn)(guarded)  # a copy: marking `fn` would mark every class
            own.__dict__.pop("pytestmark", None)
            own._waiver = _WAIVER  # type: ignore[attr-defined]
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


# --- guards -----------------------------------------------------------------------------------

SUBCLASSES: list[type] = []
_FORBIDDEN = ("target", "pytestmark", "__test__")


def applicable(port: Port) -> list[str]:
    return sorted(
        n
        for n, fn in _SUITE_TESTS.items()
        if fn._section in PORT_SECTIONS[port]  # type: ignore[attr-defined]
    )


def _module_file(cls: type) -> Path | None:
    module = __import__(cls.__module__, fromlist=["_"])
    file = getattr(module, "__file__", None)
    return Path(file).resolve() if file else None


def check_collection(items: Iterable[Any], args: Iterable[str]) -> list[str]:
    """Problems with the suite subclasses in this session. Call it with the FULL list of
    collected items (before ``-m`` and ``-k`` deselect), as ``tests/contract/conftest.py`` does.

    A subclass in scope (a test file under the session's arguments) must have collected, for
    every test its port requires, the suite's own function. A run narrowed to node IDs only
    checks that what it did collect is genuine.
    """
    items = list(items)
    args = [str(a) for a in args]
    partial = any("::" in a for a in args)
    scope = [Path(a.split("::")[0]).resolve() for a in args]
    by_cls: dict[type, dict[str, Any]] = {}
    for item in items:
        cls = getattr(item, "cls", None)
        if cls in SUBCLASSES:
            by_cls.setdefault(cls, {})[item.originalname] = item
    problems = []
    for cls, found in by_cls.items():
        for name, item in found.items():
            if name not in _SUITE_TESTS:
                continue
            fn = item.function
            genuine = _SUITE_TESTS[name]
            waived = getattr(fn, "_waiver", None) is _WAIVER and fn.__wrapped__ is genuine
            if fn is not genuine and not waived:
                problems.append(f"{cls.__name__}.{name} is not the suite's own test")
    if partial:
        return problems
    for cls in SUBCLASSES:
        file = _module_file(cls)
        in_scope = file is not None and any(file == s or s in file.parents for s in scope)
        if not in_scope:
            continue
        if cls not in by_cls:
            problems.append(f"{cls.__module__}.{cls.__name__} collected no test")
            continue
        for name in applicable(cls.port):  # type: ignore[attr-defined]
            if name not in by_cls[cls]:
                problems.append(f"{cls.__name__}.{name} was not collected")
    return problems


def enforce_outcome(item: Any, report: Any) -> None:
    """Turn a skip or xfail of a suite test into a failure, unless ``pending_controls`` made it."""
    cls = getattr(item, "cls", None)
    name = getattr(item, "originalname", "")
    if cls not in SUBCLASSES or name not in _SUITE_TESTS:
        return
    if getattr(item.function, "_waiver", None) is _WAIVER:
        return
    if report.outcome == "skipped" or hasattr(report, "wasxfail"):
        report.outcome = "failed"
        report.longrepr = f"{name}: a conformance test may not be skipped or xfailed"
        if hasattr(report, "wasxfail"):
            del report.wasxfail


class AdapterConformance:
    """The tests. Set ``port`` and ``registry``; the inherited ``target`` fixture selects."""

    port: ClassVar[Port]
    registry: ClassVar[Mapping[str, Callable[[], Target]]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not cls.__name__.startswith("Test"):
            raise TypeError(
                f"{cls.__name__}: a conformance subclass must be named Test*, else pytest "
                "collects none of its tests"
            )
        for name in cls.__dict__:
            if name in _FORBIDDEN or name in _SUITE_TESTS:
                raise TypeError(
                    f"{cls.__name__} may not define {name!r}: it would change the suite"
                )
        for attr in ("port", "registry"):
            if not hasattr(cls, attr):
                raise TypeError(f"{cls.__name__} must set `{attr}`")
        keep = set(applicable(cls.port))
        for name in _SUITE_TESTS:
            if name not in keep:
                setattr(cls, name, None)  # not required of this port; pytest collects no None
        SUBCLASSES.append(cls)

    @pytest.fixture
    def target(self, request: pytest.FixtureRequest) -> Target:
        name, target = resolve(self.registry)
        request.node.user_properties.append(("conformance_target", name))
        return target

    # ==== WEBHOOK: signature rejection (T6) ================================================

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_the_production_verifier_accepts_a_genuine_delivery(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        raw = target.emit(1, "d-1")
        assert target.verifier.verify(raw.headers, raw.body) == "d-1"

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_the_production_verifier_rejects_every_kind_of_forgery(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        for i, how in enumerate(ForgeKind):
            raw = target.forge(1, f"d-{i}", how)
            with pytest.raises(PermanentError):
                target.verifier.verify(raw.headers, raw.body)

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_a_forged_delivery_differs_from_a_genuine_one_only_in_its_signature(
        self, target: Target
    ) -> None:
        """The harness check: else a rejection could be for some other reason."""
        target.require(Control.SIGNATURE)
        genuine, forged = target.emit(1, "d-1"), target.forge(1, "d-1")
        sig = target.signature_header.lower()
        same = {k: v for k, v in genuine.headers.items() if k.lower() != sig}
        if genuine.body != forged.body or same != {
            k: v for k, v in forged.headers.items() if k.lower() != sig
        }:
            raise HarnessError("forge() changed something besides the signature")
        assert genuine.headers[target.signature_header] != forged.headers[target.signature_header]

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_genuine_delivery_is_accepted(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        outcome = target.deliver(target.emit(1, "d-1"))
        assert outcome.accepted
        assert outcome.names == (target.watched,)
        assert target.queued() == 1

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE)
        for i, how in enumerate(ForgeKind):
            with pytest.raises(PermanentError):
                target.deliver(target.forge(1, f"d-{i}", how))
        assert target.queued() == 0

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_tampered_body_is_rejected(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        genuine = target.emit(1, "d-1")
        tampered = target.tamper(genuine)
        if tampered.body == genuine.body:
            raise HarnessError("tamper() did not change the body")
        with pytest.raises(PermanentError):
            target.deliver(tampered)
        assert target.queued() == 0

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one(
        self, target: Target
    ) -> None:
        """Same content, different bytes: a verifier that parses first would let this through."""
        target.require(Control.SIGNATURE)
        genuine = target.emit(1, "d-1")
        other = target.reserialise(genuine)
        if other.body == genuine.body:
            raise HarnessError("reserialise() did not change the bytes")
        with pytest.raises(PermanentError):
            target.deliver(other)
        assert target.queued() == 0

    @covers(Section.WEBHOOK, Control.UNSIGNED)
    def test_t6_a_delivery_with_only_the_signature_removed_is_rejected(
        self, target: Target
    ) -> None:
        """Everything else is intact (delivery ID, timestamp), so only the missing signature can
        be the reason for the rejection."""
        target.require(Control.UNSIGNED)
        stripped = target.strip_signature(target.emit(1, "d-1"))
        with pytest.raises(PermanentError):
            target.deliver(stripped)
        assert target.queued() == 0

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_rejected_delivery_does_not_use_up_its_delivery_id(self, target: Target) -> None:
        """Else a forger who guesses the next delivery ID could block the genuine one."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))
        assert target.deliver(target.emit(1, "d-1")).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_forged_delivery_with_a_seen_id_is_rejected_not_dropped(
        self, target: Target
    ) -> None:
        """Answering "duplicate" is a silent 2xx for a forgery."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        assert target.deliver(target.emit(1, "d-1")).accepted
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_t6_a_forged_delivery_does_not_wipe_the_dedupe_memory(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        genuine = target.emit(1, "d-1")
        assert target.deliver(genuine).accepted
        with pytest.raises(PermanentError):
            target.deliver(target.forge(1, "d-1"))
        assert not target.deliver(genuine).accepted, "the genuine redelivery must still be a dup"
        assert target.queued() == 1

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_a_delivery_with_no_id_is_refused_not_given_one(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        with pytest.raises(PermanentError):
            target.deliver(target.emit_without_id(1))
        assert target.queued() == 0

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_a_verified_but_malformed_body_is_refused_and_does_not_burn_its_id(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        with pytest.raises(MalformedWebhookError):
            target.deliver(target.emit_malformed("d-1"))
        assert target.queued() == 0
        assert target.deliver(target.emit(1, "d-1")).accepted

    # ---- replay window: what it means depends on whether the vendor signs the timestamp ----

    @covers(Section.WEBHOOK, Control.REPLAY_WINDOW)
    def test_t6_the_replay_window_is_no_wider_than_the_suite_allows(self, target: Target) -> None:
        target.require(Control.REPLAY_WINDOW)
        assert 0 < target.replay_window <= MAX_REPLAY_WINDOW

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_genuine_delivery_older_than_the_window(self, target: Target) -> None:
        """Signed timestamp: rejected. Unsigned timestamp (GitHub): a redelivery of an unseen ID
        is accepted, because no time header may be trusted for replay."""
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        target.advance_clock(min(target.replay_window, MAX_REPLAY_WINDOW) + 1)
        if target.capabilities.signed_timestamp:
            with pytest.raises(PermanentError):
                target.deliver(raw)
            assert target.queued() == 0
        else:
            assert target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_genuine_delivery_inside_the_replay_window_is_accepted(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        target.advance_clock(min(target.replay_window, MAX_REPLAY_WINDOW) - 1)
        assert target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW, Control.DUPLICATE)
    def test_t6_a_bumped_timestamp_cannot_revive_an_old_delivery(self, target: Target) -> None:
        """Signed timestamp: the bump breaks the signature. Unsigned: the bump changes nothing,
        and the seen ID still drops it."""
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW, Control.DUPLICATE)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        target.advance_clock(100_000)
        bumped = target.bump_timestamp(raw)
        if target.capabilities.signed_timestamp:
            with pytest.raises(PermanentError):
                target.deliver(bumped)
        else:
            assert not target.deliver(bumped).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_delivery_dated_in_the_future(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        ahead = min(target.replay_window, MAX_REPLAY_WINDOW) + 1
        raw = target.future_dated(1, "d-1", ahead)
        if target.capabilities.signed_timestamp:
            with pytest.raises(PermanentError):
                target.deliver(raw)
        else:
            assert target.deliver(raw).accepted

    # ---- duplicates ---------------------------------------------------------------------

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_redelivery_of_the_same_delivery_id_is_dropped(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        assert not target.deliver(raw).accepted
        assert target.queued() == 1

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_a_new_delivery_id_is_not_a_duplicate(self, target: Target) -> None:
        """Dedupe is by delivery ID, not by content: two real changes are both delivered."""
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        assert target.deliver(target.emit(1, "d-1")).accepted
        assert target.deliver(target.emit(1, "d-2")).accepted
        assert target.queued() == 2

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE)
    def test_dedupe_remembers_every_id_not_just_the_last(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE)
        first, second = target.emit(1, "d-1"), target.emit(2, "d-2")
        assert target.deliver(first).accepted
        assert target.deliver(second).accepted
        assert not target.deliver(first).accepted
        assert target.queued() == 2

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE, Control.REPLAY_WINDOW)
    def test_dedupe_does_not_expire_while_the_delivery_can_still_be_replayed(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.DUPLICATE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        wait = min(target.replay_window, MAX_REPLAY_WINDOW) - 1
        target.advance_clock(wait if target.capabilities.signed_timestamp else 100_000)
        assert not target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.DUPLICATE, Control.RESTART)
    def test_dedupe_survives_a_restart(self, target: Target) -> None:
        """The seen-ID table is durable (PLAN): a redelivery after a deploy is still a duplicate."""
        target.require(Control.SIGNATURE, Control.DUPLICATE, Control.RESTART)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        target.restart()
        assert not target.deliver(raw).accepted
        assert target.queued() == 1

    @covers(Section.WEBHOOK, Control.SIGNATURE)
    def test_every_nudge_names_the_object_that_changed(self, target: Target) -> None:
        target.require(Control.SIGNATURE)
        outcomes = [target.deliver(target.emit(rev, f"d-{rev}")) for rev in (2, 1)]
        assert [o.names for o in outcomes] == [(target.watched,)] * 2

    # ==== ORDERING: webhooks are nudges, state is re-read ===================================

    @covers(Section.ORDERING, Control.SIGNATURE, Control.ORDERING)
    def test_delivery_order_does_not_change_what_the_adapter_reports(self, target: Target) -> None:
        """Deliveries 3, 2, 1 arrive after the server is at 3. The adapter must report what the
        SERVER says, so a cache fed from delivery bodies shows up as 1."""
        target.require(Control.SIGNATURE, Control.ORDERING)
        deliveries = [target.emit(rev, f"d-{rev}") for rev in (1, 2, 3)]
        assert target.server_revision() == 3
        outcomes = [target.deliver(raw) for raw in reversed(deliveries)]
        assert all(o.accepted for o in outcomes)
        assert target.reported_revision() == target.server_revision() == 3

    @covers(Section.ORDERING, Control.SIGNATURE, Control.ORDERING)
    def test_after_a_delivery_state_is_re_read_from_the_server(self, target: Target) -> None:
        """ "Then re-read state" (T6): every answer costs a request, and sees what changed between
        two reads, so a value remembered from the first read cannot pass."""
        target.require(Control.SIGNATURE, Control.ORDERING)
        target.deliver(target.emit(1, "d-1"))
        before = target.calls("read")
        assert target.reported_revision() == 1
        assert target.calls("read") == before + 1
        target.emit(2, "d-2")  # the server changes; no delivery reaches the adapter
        assert target.reported_revision() == 2
        assert target.calls("read") == before + 2

    @covers(Section.ORDERING, Control.ORDERING)
    def test_a_failing_read_is_an_error_not_a_zero(self, target: Target) -> None:
        target.require(Control.ORDERING)
        target.emit(5, "d-5")
        for mode in ("5xx", "timeout"):
            target.fault_next("read", mode)
            with pytest.raises(TransientError):
                target.reported_revision()
        assert target.reported_revision() == 5

    @covers(Section.ORDERING, Control.ORDERING, Control.AUTH)
    def test_a_read_refused_for_credentials_is_an_auth_error_not_a_missing_object(
        self, target: Target
    ) -> None:
        target.require(Control.ORDERING, Control.AUTH)
        target.revoke_auth("read")
        with pytest.raises(PermanentError) as caught:
            target.reported_revision()
        assert is_auth_error(caught.value)

    # ==== IDEMPOTENCY: crash after write, at each step ======================================

    def _crash_then_retry(self, target: Target, point: CrashPoint, applied: bool) -> None:
        target.require(Control.CRASH, Control.RESTART)
        _crash(target, point)
        with pytest.raises(TransientError):
            _write(target, "k1")
        assert len(target.stored_ids()) == (1 if applied else 0), "the server's view of the crash"
        target.restart()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id], "exactly one, and the one it names"
        assert target.stored_id_for("k1") == receipt.external_id

    @covers(Section.IDEMPOTENCY, Control.CRASH, Control.RESTART)
    def test_crash_when_the_lookup_fails_then_a_restart_writes_once(self, target: Target) -> None:
        self._crash_then_retry(target, CrashPoint.LOOKUP_FAILS, applied=False)

    @covers(Section.IDEMPOTENCY, Control.CRASH, Control.RESTART)
    def test_crash_when_the_post_is_rejected_then_a_restart_writes_once(
        self, target: Target
    ) -> None:
        self._crash_then_retry(target, CrashPoint.REJECTED_BEFORE_APPLY, applied=False)

    @covers(Section.IDEMPOTENCY, Control.CRASH, Control.RESTART)
    def test_crash_after_the_write_applied_then_a_restart_does_not_write_again(
        self, target: Target
    ) -> None:
        self._crash_then_retry(target, CrashPoint.RESPONSE_LOST_AFTER_APPLY, applied=True)

    @covers(Section.IDEMPOTENCY, Control.RESTART)
    def test_a_fresh_adapter_replaying_a_key_returns_the_servers_object(
        self, target: Target
    ) -> None:
        target.require(Control.RESTART)
        first = _write(target, "k1")
        target.restart()
        again = _write(target, "k1")
        assert again.external_id == first.external_id == target.stored_id_for("k1")
        assert target.stored_ids() == [first.external_id]

    @covers(Section.IDEMPOTENCY, Control.CRASH)
    def test_a_new_key_is_a_new_write(self, target: Target) -> None:
        target.require(Control.CRASH)
        a, b = _write(target, "k1", "a"), _write(target, "k2", "b")
        assert a.external_id != b.external_id
        assert target.stored_ids() == [a.external_id, b.external_id]

    @covers(Section.IDEMPOTENCY, Control.CRASH, Control.RESTART)
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

    # ==== LOOKUP: look-up-first (PLAN 6.3) ==================================================

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_lookup_reads_every_page_in_either_order(self, target: Target) -> None:
        """250 objects before and 250 after the marker, at a page size of 100, on a server that
        lists newest first and on one that lists oldest first."""
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        for i, order in enumerate(("newest_first", "oldest_first")):
            target.set_list_order(order)
            key = f"k{i}"
            target.seed_others(250, newer=False)
            _crash(target, CrashPoint.RESPONSE_LOST_AFTER_APPLY)
            with pytest.raises(TransientError):
                target.write(key)
            target.seed_others(250, newer=True)
            target.restart()
            before = target.calls("lookup")
            receipt = _write(target, key)
            assert target.calls("lookup") - before >= 3, "the marker is on a later page"
            assert target.stored_id_for(key) == receipt.external_id
        assert len(target.stored_ids()) == 2

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_an_error_on_a_later_page_is_not_the_end_of_the_list(self, target: Target) -> None:
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        target.set_list_order("newest_first")
        first = _write(target, "k1")
        target.seed_others(250, newer=True)
        target.restart()
        target.fault_next("lookup", "5xx", page=1)
        with pytest.raises(TransientError):
            target.write("k1")
        assert target.stored_ids() == [first.external_id], "a failed look-up must not write"

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_a_server_error_on_lookup_is_not_taken_for_not_found(self, target: Target) -> None:
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        first = _write(target, "k1")
        target.restart()
        _crash(target, CrashPoint.LOOKUP_FAILS)
        with pytest.raises(TransientError):
            target.write("k1")
        assert target.stored_ids() == [first.external_id], "a failed look-up must not write"
        assert _write(target, "k1").external_id == first.external_id

    @covers(Section.LOOKUP, Control.LOOKUP)
    def test_a_marker_planted_by_another_author_is_not_trusted(self, target: Target) -> None:
        """G9: anyone who can comment could otherwise suppress our real comment."""
        target.require(Control.LOOKUP)
        target.plant_foreign_marker("k1")
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]
        assert target.stored_id_for("k1") == receipt.external_id

    @covers(Section.LOOKUP, Control.LOOKUP)
    def test_another_authors_marker_with_other_arguments_does_not_block_our_write(
        self, target: Target
    ) -> None:
        target.require(Control.LOOKUP)
        target.plant_foreign_marker("k1", variant="zzz")
        receipt = _write(target, "k1", "a")
        assert target.stored_ids() == [receipt.external_id]

    @covers(Section.LOOKUP, Control.LOOKUP)
    def test_an_author_whose_name_merely_starts_like_ours_is_not_us(self, target: Target) -> None:
        target.require(Control.LOOKUP)
        target.plant_foreign_marker("k1", author="sto-bot-evil")
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]

    @covers(Section.LOOKUP, Control.LOOKUP)
    def test_a_key_that_is_a_prefix_of_another_key_is_a_different_key(self, target: Target) -> None:
        target.require(Control.LOOKUP)
        a = _write(target, "k10")
        b = _write(target, "k1")
        assert a.external_id != b.external_id
        assert target.stored_ids() == [a.external_id, b.external_id]

    # ==== READ_BACK (PLAN 6.3, G8) ==========================================================

    @covers(Section.READ_BACK, Control.READ_BACK)
    def test_an_applied_write_is_reported_read_back_verified(self, target: Target) -> None:
        target.require(Control.READ_BACK)
        assert _write(target, "k1").read_back_verified

    @covers(Section.READ_BACK, Control.READ_BACK)
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

    @covers(Section.READ_BACK, Control.READ_BACK, Control.LOOKUP)
    def test_a_read_back_that_fails_is_unknown_never_verified(self, target: Target) -> None:
        target.require(Control.READ_BACK, Control.LOOKUP)
        target.swallow_next_write()
        target.fault_next("lookup", "5xx", after=1)  # the look-up before the write passes
        try:
            receipt = target.write("k1")
        except TransientError:
            return
        assert not receipt.read_back_verified

    @covers(Section.READ_BACK, Control.READ_BACK, Control.LOOKUP)
    def test_read_back_does_not_accept_another_authors_object(self, target: Target) -> None:
        target.require(Control.READ_BACK, Control.LOOKUP)
        target.plant_foreign_marker("k1")
        target.swallow_next_write()
        try:
            receipt = target.write("k1")
        except TransientError:
            return
        assert not receipt.read_back_verified

    # ==== RATE: per the shapes the vendor uses ==============================================

    @covers(Section.RATE, Control.RATE_LIMIT)
    def test_every_rate_limit_shape_is_transient_applies_nothing_and_is_not_hammered(
        self, target: Target
    ) -> None:
        target.require(Control.RATE_LIMIT)
        for i, shape in enumerate(sorted(target.capabilities.rate_shapes)):
            for op in (None, "write"):  # the first request of a write, and its post alone
                key = f"k-{i}-{op}"
                target.rate_limit_next(2, shape, op)
                hint = target.retry_after_hint(shape)
                for _ in (1, 2):
                    limited = target.calls("limited")
                    with pytest.raises(TransientError) as caught:
                        target.write(key)
                    assert target.calls("limited") == limited + 1, "one limited request, no more"
                    retry_after = getattr(caught.value, "retry_after", None)
                    if hint is not None:  # a shape that carries Retry-After must pass it on
                        assert retry_after is not None
                        assert retry_after >= hint
                    assert target.stored_id_for(key) is None
                receipt = retrying(functools.partial(_write, target, key))
                assert target.stored_id_for(key) == receipt.external_id

    # ==== AUTH ===============================================================================

    @covers(Section.AUTH, Control.AUTH)
    def test_a_401_is_an_auth_error_applies_nothing_and_is_asked_per_the_refresh_rule(
        self, target: Target
    ) -> None:
        """No refresh: asked exactly once. Refresh once: exactly one refresh and one retry."""
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError) as caught:
            retrying(lambda: target.write("k1"))
        assert is_auth_error(caught.value)
        once = target.capabilities.auth_refresh is AuthRefresh.ONCE
        assert target.calls("unauthorized") == (2 if once else 1)
        assert target.calls("refresh") == (1 if once else 0)
        assert target.stored_ids() == []

    @covers(Section.AUTH, Control.AUTH)
    def test_an_expired_token_is_refreshed_only_if_the_vendor_allows_it(
        self, target: Target
    ) -> None:
        target.require(Control.AUTH)
        target.expire_token()
        if target.capabilities.auth_refresh is AuthRefresh.ONCE:
            receipt = _write(target, "k1")
            assert target.calls("refresh") == 1
            assert target.stored_ids() == [receipt.external_id]
        else:
            with pytest.raises(PermanentError) as caught:
                target.write("k1")
            assert is_auth_error(caught.value)
            assert target.calls("refresh") == 0

    @covers(Section.AUTH, Control.AUTH)
    def test_a_401_at_any_step_of_a_write_is_an_auth_error(self, target: Target) -> None:
        target.require(Control.AUTH)
        for op in ("lookup", "write"):
            target.revoke_auth(op)
            with pytest.raises(PermanentError) as caught:
                target.write(f"k-{op}")
            assert is_auth_error(caught.value), f"a 401 on {op}"
            target.restore_auth()
        assert target.stored_ids() == []

    @covers(Section.AUTH, Control.AUTH)
    def test_the_write_succeeds_once_auth_is_restored(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError):
            target.write("k1")
        target.restore_auth()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]

    @covers(Section.AUTH, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_plain_403_is_a_permission_error_not_a_rate_limit_or_a_missing_object(
        self, target: Target
    ) -> None:
        """A 403 that names no rate limit means "forbidden"."""
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        for op in ("lookup", "write"):
            target.respond_next(op, 403)
            with pytest.raises(PermanentError) as caught:
                target.write(f"k-{op}")
            assert is_auth_error(caught.value), f"a 403 on {op}"
        assert target.stored_ids() == []

    @covers(Section.AUTH, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_404_is_an_unknown_object_not_a_credential_error(self, target: Target) -> None:
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        target.respond_next("lookup", 404)
        with pytest.raises(UnknownRefError):
            target.write("k1")
        assert target.stored_ids() == []


def run_suite(
    factory: Callable[[], Target], port: Port = Port.TICKET_SOURCE
) -> dict[str, BaseException | None]:
    """Run the tests ``port`` requires against fresh targets from ``factory``: name -> the
    failure, or None. A skip counts as a failure. A known-bad adapter must come back with
    failures of the right kind: that is how the suite proves it can catch it."""
    out: dict[str, BaseException | None] = {}
    for name in applicable(port):
        try:
            getattr(AdapterConformance.__new__(AdapterConformance), name)(factory())
            out[name] = None
        except (Exception, pytest.fail.Exception, pytest.skip.Exception) as exc:
            out[name] = exc
    return out
