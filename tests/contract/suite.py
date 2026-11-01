"""Shared adapter conformance suite (D4-01, PLAN 10.2, ADR-0009, threat T6).

Written once. Every adapter in every later stage runs it, against whichever server a setting
selects: its in-process fake server (the default) or the real API (``STO_CONFORMANCE_TARGET``).
When the real API disagrees with the fake, that is a bug in the fake.

Reusing it
----------
Import it as ``contract.suite`` from any test directory (``tests/`` is on ``pythonpath`` and
``tests/contract`` is a package)::

    import pytest

    from contract.suite import AdapterConformance, Port, Target, Vendor

    class TestMyAdapter(AdapterConformance):
        port = Port.TICKET_SOURCE
        registry = {"fake": MyFakeTarget, "live": MyLiveTarget}

The package ``contract`` is a pytest plugin, loaded for EVERY session through ``addopts`` in
``pyproject.toml`` (``-p contract``), as ``hermetic_guard`` is; it forwards to this module once a
test module has imported it, and imports nothing from ``sto`` itself (else coverage skips ``sto``).
Its hooks fail the
run if a subclass collected no test (under ``-m`` too), if a suite test was replaced, if an
in-process subclass carries a marker that deselects or skips it, and if a suite test is skipped
or xfailed by anything but ``pending_controls``. A subclass must be named ``Test*`` and may define
only ``port``, ``registry`` and Python's own class attributes (an allow-list, in itself and in any
mixin): no helper, hook, fixture, mark or ``test_*`` method. The checks run at class creation AND
again at collection, over every real subclass of ``AdapterConformance`` (so a registry edit or a
swallowed ``__init_subclass__`` does not hide one).

Known limits, deliberate routes the suite does not stop:

* Forging the private waiver token, and setting ``__module__`` plus ``setattr`` into
  ``contract.test_suite`` to pass as a reference adapter.
* The port, vendor and waiver checks trust ``target.adapter``: a target can name a different real
  class under ``sto.`` (the class must be really defined there, and match the declared vendor's
  module path, but the suite cannot tell it from the class the test means to exercise).
* Header names are matched case-sensitively (fails closed).
* Nothing requires a real adapter to HAVE a conformance subclass.
* A silent page cap above 50 pages is not seen: the marker is 5,100 objects (51 pages) from each
  end, and the absent-key walk is about 200 pages including the read-back walk. A cap of 34 pages
  or more, up to 50, fails.
* A ``::`` argument narrows the completeness check to the classes it names.

What a fake server must provide for the suite to be meaningful: it must page at 100 items (the
page size the suite assumes), and a rate-limit answer must ask for at least ``SHAPE_RETRY_AFTER``
(30 seconds for a ``Retry-After`` shape, 45 for ``x-ratelimit-reset`` shape), since the suite
requires an adapter to pass on at least that wait.

For a vendor with no signed timestamp the dedupe record is the only bound on a replay, so it never
expires; a TTL on the seen-ID table applies only to vendors with a signed timestamp.

Ports, vendors and sections
---------------------------
Which sections a target must pass comes from the PORT the adapter implements (``PORT_SECTIONS``),
and the port is VERIFIED: an adapter that implements ``TicketSource``, ``ScmProvider`` or
``Notifier`` (checked with ``isinstance``) cannot claim a narrower port. Only adapters defined in
``contract.test_suite``, the reference and its known-bad variants, implement no real port and are
exempt. A target names a ``Vendor``; the suite owns that vendor's ``Capabilities`` (signed
timestamp, rate-limit shapes, auth refresh) and there is no default. A vendor never removes a
control: it selects which assertion a mandatory test makes.

What the harness is
-------------------
``Target`` is a thin pass-through. The truth lives in the **server** under it: stored objects,
signature secret, clock, 429/403/401/404/5xx/timeouts. Controls act at the server, and the suite
asserts what the SERVER saw, never what the adapter says about itself. Security and
failure-mapping code (signature check, dedupe, replay window, error classes, look-up-first) must
live in the adapter under test, reached through ``target.verifier`` and ``target.deliver``. The
suite never parses a delivery body: the target forges, tampers and re-serialises it, so a
form-encoded vendor works. Authentication and rate-limit tests go through ``target.probe`` (an
authenticated request that writes nothing), so a server with no write surface (D4-16) can run
them. ``run_suite`` runs the suite against any target, which is how a known-bad adapter proves the
suite can catch it; ``HarnessError`` marks a broken harness, as opposed to an adapter failing the
contract.

This section covers **Receipt-returning, keyed writes** only (comment, check, message). The SCM
section (``MergeHandle``, ``UpdateResult``, keyless ``move_ref``, ``dequeue``, update-branch)
belongs to D4-19. A delivery's result is whatever the port returns (nudges, or a ``Notifier``'s
``DecisionRequest | None``); a target maps it to an ``Outcome``. The suite invents no nudge.

Not testable black-box: constant-time comparison (T4). D4-04 owns it as a static check.

A test needing a control the target lacks FAILS with ``MissingControl``; it is never skipped.
``pending_controls`` lets a FAKE (an adapter class really defined under ``sto.adapters.fake``)
lack the one waivable control, with a reason; it cannot be used on anything else.
"""

from __future__ import annotations

import contextlib
import functools
import importlib.util
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Protocol

import pytest

from sto.adapters.ports import (
    IdempotencyKeyReuseError,
    MalformedWebhookError,
    Notifier,
    RawWebhook,
    RefusedError,
    ScmProvider,
    StaleHeadError,
    TicketSource,
    UnknownRefError,
)
from sto.domain.errors import (
    InvalidIdError,
    InvalidTransitionError,
    PermanentError,
    TransientError,
)
from sto.domain.models import Receipt

TARGET_ENV = "STO_CONFORMANCE_TARGET"
DEFAULT_TARGET = "fake"  # the only name whose receipts may be simulated
MAX_REPLAY_WINDOW = 300.0  # seconds; set here, a target cannot raise it
FAR_FUTURE = 10.0**10  # seconds; longer than any finite window an adapter could sensibly use
PAGE_SIZE = 100  # GitHub's maximum; the server pages at this size
DEEP = 5100  # objects on each side of a marker: past any page cap up to 50 pages
RETRIES = 5
FAKE_MODULE = "sto.adapters.fake"
STO_MODULE = "sto"
REFERENCE_MODULE = "contract.test_suite"
PORT_ERRORS = (
    IdempotencyKeyReuseError,
    InvalidIdError,
    InvalidTransitionError,
    MalformedWebhookError,
    RefusedError,
    StaleHeadError,
    UnknownRefError,
)
# Markers that would deselect, skip or fail-soft an in-process conformance class.
ESCAPE_MARKERS = frozenset({"live", "integration", "e2e", "ui_browser", "skip", "skipif", "xfail"})


class Section(StrEnum):
    WEBHOOK = "webhook"  # signature, dedupe, replay window, nudges
    ORDERING = "ordering"  # needs a state read
    IDEMPOTENCY = "idempotency"  # crash at each step, restart, keys
    LOOKUP = "lookup"  # look-up-first (PLAN 6.3)
    READ_BACK = "read_back"  # a write returns a Receipt with read_back_verified (G8)
    RATE = "rate"  # through target.probe
    AUTH = "auth"  # through target.probe
    WRITE_FAILURES = "write_failures"  # rate limits, auth and HTTP errors at each step of a write


class Port(StrEnum):
    TICKET_SOURCE = "ticket_source"
    SCM = "scm"
    NOTIFIER = "notifier"  # no state read: no ordering section
    WEBHOOK = "webhook"  # ingest only (D4-03, D4-04)
    AUTH_WEBHOOK = "auth_webhook"  # a fake server's auth, reads and webhooks (D4-16)


_ALL = frozenset(Section)
PORT_SECTIONS: Mapping[Port, frozenset[Section]] = {
    Port.TICKET_SOURCE: _ALL,
    Port.SCM: _ALL,
    Port.NOTIFIER: _ALL - {Section.ORDERING},
    Port.WEBHOOK: frozenset({Section.WEBHOOK}),
    Port.AUTH_WEBHOOK: frozenset({Section.WEBHOOK, Section.ORDERING, Section.RATE, Section.AUTH}),
}
_REAL_PORTS: tuple[tuple[Port, type], ...] = (
    (Port.TICKET_SOURCE, TicketSource),
    (Port.SCM, ScmProvider),
    (Port.NOTIFIER, Notifier),
)
# The methods of the three ports that only read or parse. Every other public method writes, so an
# adapter that implements no port must not expose one: it would be a write the suite never sees.
PORT_READ_METHODS = frozenset(
    {"get", "search", "parse_event", "current_sprint", "snapshot", "poll_merge", "ci_trust"}
    | {"checks", "parse_action"}
)
PORT_WRITE_METHODS = (
    frozenset(
        name
        for _, protocol in _REAL_PORTS
        for name, value in vars(protocol).items()
        if callable(value) and not name.startswith("_")
    )
    - PORT_READ_METHODS
)


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
    SECONDARY_403_NO_HEADER = "secondary_403_no_header"  # GitHub: 403, only the message says so
    PRIMARY_403_REMAINING_ZERO = "primary_403_remaining_zero"  # 403, x-ratelimit-remaining: 0


# What the server's answer for a shape asks the caller to wait (seconds), or None if it names none.
SHAPE_RETRY_AFTER: Mapping[RateShape, float | None] = {
    RateShape.PRIMARY_429: 30.0,
    RateShape.PRIMARY_429_NO_HEADER: None,
    RateShape.SECONDARY_403: 30.0,
    RateShape.SECONDARY_403_NO_HEADER: None,
    RateShape.PRIMARY_403_REMAINING_ZERO: 45.0,
}


class AuthRefresh(StrEnum):
    NONE = "none"
    ONCE = "once"  # a 401 gets exactly one refresh and one retry (Jira 3LO, D6-02)


class ForgeKind(StrEnum):
    WRONG_SECRET = "wrong_secret"
    TRUNCATED_MAC = "truncated_mac"
    EMPTY_MAC = "empty_mac"
    EMPTY_KEY = "empty_key"  # a MAC made with an empty secret
    BLANK_HEADER = "blank_header"  # the signature header is present and empty


@dataclass(frozen=True)
class Capabilities:
    signed_timestamp: bool  # False: GitHub, Jira; the adapter may use no time header for replay
    rate_shapes: frozenset[RateShape]
    auth_refresh: AuthRefresh

    def __post_init__(self) -> None:
        if not self.rate_shapes:
            raise ValueError("declare at least one rate-limit shape the vendor uses")


class Vendor(StrEnum):
    GITHUB = "github"
    SLACK = "slack"
    JIRA = "jira"
    STUB = "stub"  # the reference and its known-bad variants only


CAPABILITIES: Mapping[Vendor, Capabilities] = {
    Vendor.GITHUB: Capabilities(
        False,
        frozenset(
            {
                RateShape.PRIMARY_429,
                RateShape.PRIMARY_403_REMAINING_ZERO,
                RateShape.SECONDARY_403,
                RateShape.SECONDARY_403_NO_HEADER,
            }
        ),
        AuthRefresh.NONE,
    ),
    Vendor.SLACK: Capabilities(True, frozenset({RateShape.PRIMARY_429}), AuthRefresh.NONE),
    Vendor.JIRA: Capabilities(False, frozenset({RateShape.PRIMARY_429}), AuthRefresh.ONCE),
    Vendor.STUB: Capabilities(True, frozenset(RateShape), AuthRefresh.NONE),
}


class MissingControl(AssertionError):
    """The target cannot provoke the failure this test needs."""


class PortClaimError(AssertionError):
    """The target claims a port or a vendor it does not have."""


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
    vendor: Vendor  # required: the suite owns the vendor's capabilities, there is no default
    signature_header: ClassVar[str] = "X-Signature"
    replay_window: float = MAX_REPLAY_WINDOW
    watched: str = ""  # the name a nudge for the watched object must carry
    selected: str = DEFAULT_TARGET  # set by the fixture: which target ran
    adapter: object  # the adapter under test, so the suite can verify the port it claims
    verifier: Verifier

    @property
    def capabilities(self) -> Capabilities:
        return CAPABILITIES[self.vendor]

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

    def probe(self) -> None:
        """An authenticated request that writes nothing (a read, ``auth.test``). Rate-limit and
        auth behaviour is asserted through it."""
        raise _unset("probe")

    # --- the server's view ---
    def stored_ids(self) -> list[str]:
        """IDs of the objects our principal has stored, oldest first."""
        raise _unset("stored_ids")

    def stored_id_for(self, key: str) -> str | None:
        raise _unset("stored_id_for")

    def listed(self) -> int:
        """How many objects the server lists in all, whoever stored them."""
        raise _unset("listed")

    def calls(self, op: str) -> int:
        """Requests the server received: ``lookup``, ``write``, ``read``, ``refresh``,
        ``unauthorized``, ``limited``."""
        raise _unset("calls")

    def server_revision(self) -> int:
        raise _unset("server_revision")

    def clock(self) -> float:
        raise _unset("clock")

    # --- controls, acting at the server ---
    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        """The next ``op`` request (``lookup``, ``write``, ``read``), after skipping ``after`` of
        them and only for ``page`` if given, suffers ``mode``: ``5xx`` or ``timeout`` (nothing
        applied), ``429`` or ``401`` (answered so), ``lose`` (a write applied, the caller sees a
        timeout)."""
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

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        """The same delivery with its timestamp header set to ``value``, or removed if None."""
        raise _unset("set_timestamp")

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


# --- what a target may claim ------------------------------------------------------------------


def _defined_under(cls: type, dotted: str, directories: Iterable[Path]) -> bool:
    """``cls`` is REALLY defined in a module of package ``dotted`` (with a dot boundary): the
    module is loaded under that name, holds this very class, and lives in one of ``directories``.
    A ``__module__`` set by hand fails the last two."""
    name = cls.__module__
    if name != dotted and not name.startswith(dotted + "."):
        return False
    module = sys.modules.get(name)
    if module is None or getattr(module, cls.__name__, None) is not cls:
        return False
    file = getattr(module, "__file__", None)
    if not file:
        return False
    return any(Path(str(file)).resolve().is_relative_to(d) for d in directories)


def _fake_directories() -> list[Path]:
    spec = importlib.util.find_spec(FAKE_MODULE)
    return [Path(p).resolve() for p in (spec.submodule_search_locations or [])] if spec else []


def _sto_directories() -> list[Path]:
    spec = importlib.util.find_spec(STO_MODULE)
    return [Path(p).resolve() for p in (spec.submodule_search_locations or [])] if spec else []


def is_sto_class(cls: type) -> bool:
    """``cls`` is REALLY defined under ``sto.``: not merely named so."""
    return _defined_under(cls, STO_MODULE, _sto_directories())


def is_fake(cls: type) -> bool:
    return _defined_under(cls, FAKE_MODULE, _fake_directories())


def is_reference(cls: type) -> bool:
    return _defined_under(cls, REFERENCE_MODULE, [Path(__file__).resolve().parent])


def implemented_ports(adapter: object) -> list[Port]:
    return [port for port, protocol in _REAL_PORTS if isinstance(adapter, protocol)]


def _caps(target: Target) -> Capabilities:
    """The vendor's capabilities, as the suite owns them: never the target's own claim."""
    return CAPABILITIES[target.vendor]


def _vendor_matches(cls: type, vendor: Vendor) -> bool:
    """The vendor is a whole segment of the adapter's module path (``sto.adapters.github.x``)."""
    return vendor.value in cls.__module__.split(".")


def validate_target(target: Target, port: Port) -> None:
    """The target is what it says: a known vendor, a port its adapter really implements, and no
    capabilities of its own."""
    import inspect

    try:
        own = inspect.getattr_static(target, "capabilities")
    except AttributeError:
        own = Target.__dict__["capabilities"]
    if own is not Target.__dict__["capabilities"]:
        raise PortClaimError("capabilities belong to the vendor: a target cannot override them")
    vendor = getattr(target, "vendor", None)
    if not isinstance(vendor, Vendor):
        raise HarnessError("the target must name a Vendor; the suite owns its capabilities")
    adapter = getattr(target, "adapter", None)
    if adapter is None:
        raise HarnessError("the target must expose the adapter under test as `adapter`")
    reference = is_reference(type(adapter))
    if vendor is Vendor.STUB and not reference:
        raise PortClaimError("Vendor.STUB is for the reference adapters only")
    if port is Port.NOTIFIER and not CAPABILITIES[vendor].signed_timestamp:
        raise PortClaimError(
            "an unsigned-timestamp vendor needs the re-read of an ordering section"
        )
    if reference:
        return
    if not is_sto_class(type(adapter)):
        raise PortClaimError(
            f"{type(adapter).__qualname__} must be a class really defined under sto."
        )
    if not _vendor_matches(type(adapter), vendor):
        raise PortClaimError(
            f"vendor {vendor} does not match the adapter's module path {type(adapter).__module__}"
        )
    implemented = implemented_ports(adapter)
    if not implemented:
        if port not in (Port.WEBHOOK, Port.AUTH_WEBHOOK):
            raise PortClaimError(f"the adapter implements no {port} port")
        exposed = sorted(n for n in PORT_WRITE_METHODS if callable(getattr(adapter, n, None)))
        if exposed:
            raise PortClaimError(f"an adapter with no port exposes write methods: {exposed}")
        return
    needed: set[Section] = set().union(*(PORT_SECTIONS[p] for p in implemented))
    if not needed <= PORT_SECTIONS[port]:
        raise PortClaimError(f"the adapter implements {implemented}; {port} is narrower")


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
    """A permanent error that means "your credentials or permissions are no good": not "not
    found", "stale", "refused" or any other port error, and not a subclass of one."""
    return isinstance(exc, PermanentError) and not isinstance(exc, PORT_ERRORS)


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


def pending_controls(*missing: Control, reason: str) -> Callable[[type[Any]], type[Any]]:
    """Class decorator for a FAKE that lacks a waivable control. Each test needing one becomes a
    strict xfail on ``MissingControl``.

    Refused without a reason and for any non-waivable control. When the test RUNS, it fails unless
    the target is the default ``fake`` and the adapter under test is a class really defined under
    ``sto.adapters.fake`` (dot boundary, loaded module, source location), whatever it is called.
    """
    if not reason.strip():
        raise ValueError("pending_controls needs a reason")
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
                adapter = getattr(target, "adapter", None)
                if getattr(target, "selected", None) != DEFAULT_TARGET or adapter is None:
                    pytest.fail("pending_controls is only for the fake target")
                if not is_fake(type(adapter)):
                    pytest.fail(f"pending_controls is only for a fake under {FAKE_MODULE}")
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


# --- guards: class checks, collection checks, outcome checks ----------------------------------

SUBCLASSES: list[type] = []
# Everything a subclass (or a mixin of one) may define: the port, the registry, and the
# machinery Python adds to every class. Any other name (a helper, a hook, a fixture, a mark) could
# change what the suite does, so it is refused. The suite's own tests may only be None or a waiver.
_ALLOWED = frozenset(
    {
        "port",
        "registry",
        "__module__",
        "__qualname__",
        "__doc__",
        "__dict__",
        "__weakref__",
        "__annotations__",
        "__annotate__",
        "__annotate_func__",
        "__annotations_cache__",
        "__firstlineno__",
        "__static_attributes__",
        "__orig_bases__",
        "__parameters__",
    }
)


def applicable(port: Port) -> list[str]:
    return sorted(
        n
        for n, fn in _SUITE_TESTS.items()
        if fn._section in PORT_SECTIONS[port]  # type: ignore[attr-defined]
    )


def check_class(cls: type) -> list[str]:
    """Why ``cls`` is not a faithful conformance subclass, looking through its whole MRO (mixins
    too). A test may be absent (``None``: the port does not require it) or the waiver copy that
    ``pending_controls`` made; nothing else."""
    problems = []
    if not cls.__name__.startswith("Test"):
        problems.append(f"{cls.__name__} must be named Test*: pytest collects none of its tests")
    for klass in cls.__mro__:
        if klass is AdapterConformance or klass is object:
            continue
        for name, value in vars(klass).items():
            if name in _SUITE_TESTS:
                genuine = _SUITE_TESTS[name]
                waived = getattr(value, "_waiver", None) is _WAIVER and (
                    getattr(value, "__wrapped__", None) is genuine
                )
                if value is not None and not waived:
                    problems.append(f"{cls.__name__} ({klass.__name__}) overrides {name}")
            elif name not in _ALLOWED:
                problems.append(f"{cls.__name__} ({klass.__name__}) defines {name!r}")
    if "target" in dir(cls) and not _has_suite_fixture(cls):
        problems.append(f"{cls.__name__} replaces the target fixture")
    for attr in ("port", "registry"):
        if not hasattr(cls, attr):
            problems.append(f"{cls.__name__} must set `{attr}`")
    return problems


def _has_suite_fixture(cls: type) -> bool:
    import inspect

    return inspect.getattr_static(cls, "target") is inspect.getattr_static(
        AdapterConformance, "target"
    )


def _all_subclasses(base: type) -> list[type]:
    out: list[type] = []
    for sub in base.__subclasses__():  # type: ignore[var-annotated]
        out.append(sub)
        out += _all_subclasses(sub)
    return out


def _file_of(cls: type) -> Path | None:
    module = sys.modules.get(cls.__module__)
    file = getattr(module, "__file__", None)
    return Path(str(file)).resolve() if file else None


def _scope(args: Iterable[str]) -> tuple[list[Path], dict[Path, set[str]]]:
    """Directories and files the session was pointed at, and the classes a ``::`` argument names
    (a class named there narrows the completeness check to itself)."""
    paths: list[Path] = []
    named: dict[Path, set[str]] = {}
    for arg in args:
        file, _, rest = str(arg).partition("::")
        path = Path(file).resolve()
        paths.append(path)
        if rest:
            named.setdefault(path, set()).add(rest.split("::")[0])
    return paths, named


def check_collection(items: Iterable[Any], args: Iterable[str]) -> list[str]:
    """Problems with the suite subclasses in this session. Call it with the FULL list of
    collected items (before ``-m`` and ``-k`` deselect), as the plugin hook does.

    Every class collected is re-checked (mixins and ``__init_subclass__`` included). A class in
    scope (a test file under the session's arguments) must have collected every test its port
    requires, as the suite's own function. An in-process class (one with a ``fake`` target) must
    carry no marker that would deselect or skip it. A ``::`` argument names the classes it
    selects: only those are checked for completeness, and the rest are out of the selection.
    """
    items = list(items)
    args = [str(a) for a in args]
    paths, named = _scope(args)
    by_cls: dict[type, dict[str, Any]] = {}
    problems = []
    for item in items:
        cls = getattr(item, "cls", None)
        if cls is None or not (isinstance(cls, type) and issubclass(cls, AdapterConformance)):
            continue
        if cls not in SUBCLASSES:
            problems.append(f"{cls.__name__} is a conformance subclass that was never registered")
            continue
        by_cls.setdefault(cls, {})[item.originalname] = item
    for cls, found in by_cls.items():
        problems += check_class(cls)
        for name, item in found.items():
            genuine = _SUITE_TESTS.get(name)
            fn = item.function
            waived = getattr(fn, "_waiver", None) is _WAIVER and fn.__wrapped__ is genuine
            if genuine is not None and fn is not genuine and not waived:
                problems.append(f"{cls.__name__}.{name} is not the suite's own test")
            if "fake" in getattr(cls, "registry", {}):
                marks = {m.name for m in item.iter_markers()} & ESCAPE_MARKERS
                marks -= {"xfail"} if waived else set()
                if marks:
                    problems.append(f"{cls.__name__}.{name} carries {sorted(marks)}")
    for cls in _all_subclasses(AdapterConformance):
        if "<locals>" in cls.__qualname__:
            continue  # defined inside a function: pytest cannot collect it, so nothing runs
        file = _file_of(cls)
        if file is None or not any(file == p or p in file.parents or p == file for p in paths):
            continue
        selected = [c for p, c in named.items() if p == file]
        if selected and cls.__name__ not in set().union(*selected):
            continue
        if cls not in SUBCLASSES:
            problems.append(f"{cls.__name__} is a conformance subclass that was never registered")
            continue
        problems += [p for p in check_class(cls) if p not in problems]
        if cls not in by_cls:
            problems.append(f"{cls.__module__}.{cls.__name__} collected no test")
            continue
        if selected and any(a.count("::") > 1 for a in args):
            continue  # a single test was named
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


def guard_collection(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Called by the ``contract`` plugin hook with the full item list, before deselection."""
    problems = check_collection(items, config.args)
    if problems:
        raise pytest.UsageError("conformance suite: " + "; ".join(problems))


class AdapterConformance:
    """The tests. Set ``port`` and ``registry``; the inherited ``target`` fixture selects."""

    port: ClassVar[Port]
    registry: ClassVar[Mapping[str, Callable[[], Target]]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        problems = check_class(cls)
        if problems:
            raise TypeError("; ".join(problems))
        keep = set(applicable(cls.port))
        for name in _SUITE_TESTS:
            if name not in keep:
                setattr(cls, name, None)  # not required of this port; pytest collects no None
        SUBCLASSES.append(cls)

    @pytest.fixture
    def target(self, request: pytest.FixtureRequest) -> Target:
        name, target = resolve(self.registry)
        validate_target(target, self.port)
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
        """The harness check, for EVERY kind of forgery: else a rejection could be for some other
        reason, or one kind could quietly stand in for another (a ``forge()`` returning the wrong
        secret for all of them would let a prefix-compare or empty-key verifier pass)."""
        target.require(Control.SIGNATURE)
        header = target.signature_header
        genuine = target.emit(1, "d-1")
        same = {k: v for k, v in genuine.headers.items() if k.lower() != header.lower()}
        real = genuine.headers[header]
        seen: dict[ForgeKind, str] = {}
        for how in ForgeKind:
            forged = target.forge(1, "d-1", how)
            others = {k: v for k, v in forged.headers.items() if k.lower() != header.lower()}
            if genuine.body != forged.body or same != others:
                raise HarnessError(f"forge({how}) changed something besides the signature")
            if header not in forged.headers:
                raise HarnessError(f"forge({how}) removed the {header} header")
            seen[how] = forged.headers[header]
        for how, value in seen.items():
            if value == real:
                raise HarnessError(f"forge({how}) produced the genuine signature")
        if len(set(seen.values())) != len(seen):
            raise HarnessError("forge() gave two kinds of forgery the same signature")
        if seen[ForgeKind.BLANK_HEADER] != "":
            raise HarnessError("forge(BLANK_HEADER) must leave the header present and empty")
        truncated = seen[ForgeKind.TRUNCATED_MAC]
        if not (real.startswith(truncated) and len(truncated) < len(real)):
            raise HarnessError("forge(TRUNCATED_MAC) must be a proper prefix of the genuine one")
        if len(seen[ForgeKind.EMPTY_MAC]) > len(truncated):
            raise HarnessError("forge(EMPTY_MAC) must carry less than the truncated MAC")

    @covers(Section.WEBHOOK, Control.RESTART)
    def test_the_harness_restart_gives_a_fresh_adapter_over_the_same_durable_stores(
        self, target: Target
    ) -> None:
        """The harness check: a ``restart()`` that does nothing makes every restart test vacuous,
        and one that loses the durable tables makes them pass for the wrong reason."""
        target.require(Control.RESTART)
        target.deliver(target.emit(1, "d-1"))
        adapter, verifier, queued = target.adapter, target.verifier, target.queued()
        target.restart()
        if target.adapter is adapter or target.verifier is verifier:
            raise HarnessError("restart() left the same adapter in place")
        if target.queued() != queued:
            raise HarnessError("restart() lost the durable queue")

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
        """Signed timestamp: rejected. Unsigned timestamp (GitHub, Jira): a delivery of an unseen
        ID is accepted however old, because no time header may be trusted for replay."""
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        if _caps(target).signed_timestamp:
            target.advance_clock(min(target.replay_window, MAX_REPLAY_WINDOW) + 1)
            with pytest.raises(PermanentError):
                target.deliver(raw)
            assert target.queued() == 0
        else:
            target.advance_clock(FAR_FUTURE)
            assert target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_genuine_delivery_inside_the_replay_window_is_accepted(
        self, target: Target
    ) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        target.advance_clock(min(target.replay_window, MAX_REPLAY_WINDOW) - 1)
        assert target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_missing_or_garbage_time_header(self, target: Target) -> None:
        """Signed timestamp: both are refused. Unsigned: both are accepted (header ignored)."""
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        for i, value in enumerate((None, "not-a-time")):
            raw = target.set_timestamp(target.emit(1, f"d-{i}"), value)
            if _caps(target).signed_timestamp:
                with pytest.raises(PermanentError):
                    target.deliver(raw)
            else:
                assert target.deliver(raw).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW, Control.DUPLICATE)
    def test_t6_a_bumped_timestamp_cannot_revive_an_old_delivery(self, target: Target) -> None:
        """Signed timestamp: the bump breaks the signature. Unsigned: the bump changes nothing,
        and the seen ID still drops it."""
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW, Control.DUPLICATE)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        target.advance_clock(FAR_FUTURE)
        bumped = target.set_timestamp(raw, str(target.clock()))
        if _caps(target).signed_timestamp:
            with pytest.raises(PermanentError):
                target.deliver(bumped)
        else:
            assert not target.deliver(bumped).accepted

    @covers(Section.WEBHOOK, Control.SIGNATURE, Control.REPLAY_WINDOW)
    def test_t6_a_delivery_dated_in_the_future(self, target: Target) -> None:
        target.require(Control.SIGNATURE, Control.REPLAY_WINDOW)
        ahead = min(target.replay_window, MAX_REPLAY_WINDOW) + 1
        raw = target.future_dated(1, "d-1", ahead)
        if _caps(target).signed_timestamp:
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
        """Signed timestamp: for the whole window. Unsigned: for good (no window bounds it)."""
        target.require(Control.SIGNATURE, Control.DUPLICATE, Control.REPLAY_WINDOW)
        raw = target.emit(1, "d-1")
        assert target.deliver(raw).accepted
        wait = min(target.replay_window, MAX_REPLAY_WINDOW) - 1
        target.advance_clock(wait if _caps(target).signed_timestamp else FAR_FUTURE)
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
        assert target.calls("read") > before
        mid = target.calls("read")
        target.emit(2, "d-2")  # the server changes; no delivery reaches the adapter
        assert target.reported_revision() == 2
        assert target.calls("read") > mid

    @covers(Section.ORDERING, Control.ORDERING)
    def test_a_failing_read_is_an_error_not_a_zero(self, target: Target) -> None:
        target.require(Control.ORDERING)
        target.emit(5, "d-5")
        for mode in ("5xx", "timeout", "429"):
            target.fault_next("read", mode)
            with pytest.raises(TransientError):
                target.reported_revision()
        assert target.reported_revision() == 5

    @covers(Section.ORDERING, Control.ORDERING, Control.AUTH)
    def test_a_read_refused_for_credentials_is_an_auth_error_never_a_revision(
        self, target: Target
    ) -> None:
        """Through `reported_revision`, not the probe: a probe that is a separate call would let
        an adapter answer 0 to a permanent failure of the read the ordering test relies on."""
        target.require(Control.ORDERING, Control.AUTH)
        target.revoke_auth("read")
        with pytest.raises(PermanentError) as caught:
            target.reported_revision()
        assert is_auth_error(caught.value)

    @covers(Section.ORDERING, Control.ORDERING, Control.HTTP_ERRORS)
    def test_a_plain_403_or_404_on_a_read_is_an_error_never_a_revision(
        self, target: Target
    ) -> None:
        target.require(Control.ORDERING, Control.HTTP_ERRORS)
        target.respond_next("read", 403)
        with pytest.raises(PermanentError) as caught:
            target.reported_revision()
        assert is_auth_error(caught.value)
        target.respond_next("read", 404)
        with pytest.raises(UnknownRefError):
            target.reported_revision()

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

    @covers(Section.LOOKUP, Control.LOOKUP)
    def test_the_harness_seeds_and_plants_objects_the_server_lists(self, target: Target) -> None:
        """The harness check: a ``seed_others`` or ``plant_foreign_marker`` that does nothing
        makes the look-up and read-back tests pass vacuously, and a plant under our own name is
        not a foreign one."""
        target.require(Control.LOOKUP)
        for newer in (True, False):
            before = target.listed()
            target.seed_others(3, newer=newer)
            if target.listed() != before + 3:
                raise HarnessError("seed_others() did not add the objects it was asked to")
        before, ours = target.listed(), target.stored_ids()
        target.plant_foreign_marker("k-plant")
        if target.listed() != before + 1:
            raise HarnessError("plant_foreign_marker() added no object to the server")
        if target.stored_ids() != ours or target.stored_id_for("k-plant") is not None:
            raise HarnessError("plant_foreign_marker() planted an object by our own principal")

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk(
        self, target: Target
    ) -> None:
        """The marker sits 1100 objects from each end, at a page size of 100, on a server that
        lists newest first and on one that lists oldest first: an adapter that reads only the
        head, only the tail, or stops at a page cap writes twice. An absent key is a full walk."""
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        for i, order in enumerate(("newest_first", "oldest_first")):
            target.set_list_order(order)
            key = f"k{i}"
            target.seed_others(DEEP, newer=False)
            _crash(target, CrashPoint.RESPONSE_LOST_AFTER_APPLY)
            with pytest.raises(TransientError):
                target.write(key)
            target.seed_others(DEEP, newer=True)
            target.restart()
            before = target.calls("lookup")
            receipt = _write(target, key)
            assert target.calls("lookup") - before >= DEEP // PAGE_SIZE + 1, "a later page"
            assert target.stored_id_for(key) == receipt.external_id
        assert len(target.stored_ids()) == 2
        before = target.calls("lookup")
        _write(target, "absent")
        assert target.calls("lookup") - before >= 4 * DEEP // PAGE_SIZE, "an absent key: all pages"

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_an_error_on_a_later_page_is_not_the_end_of_the_list(self, target: Target) -> None:
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        target.set_list_order("newest_first")
        first = _write(target, "k1")
        target.seed_others(250, newer=True)
        for mode in ("5xx", "timeout", "429"):
            target.restart()
            target.fault_next("lookup", mode, page=1)
            with pytest.raises(TransientError):
                target.write("k1")
            assert target.stored_ids() == [first.external_id], f"{mode}: must not write"
        # A 401 on a later page: a refresh-once vendor may recover and answer, so assert on what
        # the server stored (nothing new), not on whether it raised.
        target.restart()
        target.fault_next("lookup", "401", page=1)
        with contextlib.suppress(TransientError, PermanentError):
            target.write("k1")
        assert target.stored_ids() == [first.external_id], "a 401 on page 1: must not write"

    @covers(Section.LOOKUP, Control.CRASH, Control.RESTART, Control.LOOKUP)
    def test_a_failed_lookup_of_any_kind_is_not_taken_for_not_found(self, target: Target) -> None:
        target.require(Control.CRASH, Control.RESTART, Control.LOOKUP)
        first = _write(target, "k1")
        for mode in ("5xx", "timeout", "429"):
            target.restart()
            target.fault_next("lookup", mode)
            with pytest.raises(TransientError):
                target.write("k1")
            assert target.stored_ids() == [first.external_id], f"{mode}: must not write"
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
    def test_a_read_back_that_fails_in_any_way_is_unknown_never_verified(
        self, target: Target
    ) -> None:
        target.require(Control.READ_BACK, Control.LOOKUP)
        for i, mode in enumerate(("5xx", "timeout", "429", "401")):
            target.swallow_next_write()
            target.fault_next("lookup", mode, after=1)  # the look-up before the post passes
            try:
                receipt = target.write(f"k{i}")
            except (TransientError, PermanentError):
                continue
            assert not receipt.read_back_verified, mode

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

    # ==== RATE: per the shapes the vendor uses, through the probe ===========================

    @covers(Section.RATE, Control.RATE_LIMIT)
    def test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered(
        self, target: Target
    ) -> None:
        target.require(Control.RATE_LIMIT)
        for shape in sorted(_caps(target).rate_shapes):
            target.rate_limit_next(2, shape)
            hint = SHAPE_RETRY_AFTER[shape]
            for _ in (1, 2):
                limited = target.calls("limited")
                with pytest.raises(TransientError) as caught:
                    target.probe()
                assert target.calls("limited") == limited + 1, f"{shape}: one request, no more"
                retry_after = getattr(caught.value, "retry_after", None)
                if hint is not None:  # a shape that carries a wait must pass it on
                    assert retry_after is not None, shape
                    assert retry_after >= hint, shape
            retrying(target.probe)

    # ==== AUTH: through the probe ===========================================================

    @covers(Section.AUTH, Control.AUTH)
    def test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule(self, target: Target) -> None:
        """No refresh: asked exactly once. Refresh once: exactly one refresh and one retry."""
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError) as caught:
            retrying(target.probe)
        assert is_auth_error(caught.value)
        once = _caps(target).auth_refresh is AuthRefresh.ONCE
        assert target.calls("unauthorized") == (2 if once else 1)
        assert target.calls("refresh") == (1 if once else 0)

    @covers(Section.AUTH, Control.AUTH)
    def test_an_expired_token_is_refreshed_only_if_the_vendor_allows_it(
        self, target: Target
    ) -> None:
        target.require(Control.AUTH)
        target.expire_token()
        if _caps(target).auth_refresh is AuthRefresh.ONCE:
            target.probe()
            assert target.calls("refresh") == 1
        else:
            with pytest.raises(PermanentError) as caught:
                target.probe()
            assert is_auth_error(caught.value)
            assert target.calls("refresh") == 0

    @covers(Section.AUTH, Control.AUTH)
    def test_the_probe_succeeds_once_auth_is_restored_and_nothing_latches(
        self, target: Target
    ) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError):
            target.probe()
        target.restore_auth()
        target.probe()

    @covers(Section.AUTH, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_plain_403_on_a_read_is_a_permission_error(self, target: Target) -> None:
        """A 403 that names no rate limit means "forbidden"."""
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        target.respond_next("read", 403)
        with pytest.raises(PermanentError) as caught:
            target.probe()
        assert is_auth_error(caught.value)

    @covers(Section.AUTH, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_404_on_a_read_is_an_unknown_object_not_a_credential_error(
        self, target: Target
    ) -> None:
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        target.respond_next("read", 404)
        with pytest.raises(UnknownRefError):
            target.probe()

    # ==== WRITE_FAILURES: rate limits, auth and HTTP errors at each step of a write =========

    @covers(Section.WRITE_FAILURES, Control.RATE_LIMIT)
    def test_a_rate_limited_post_is_transient_and_applies_nothing(self, target: Target) -> None:
        target.require(Control.RATE_LIMIT)
        for i, shape in enumerate(sorted(_caps(target).rate_shapes)):
            key = f"k-{i}"
            target.rate_limit_next(1, shape, "write")  # the look-up passes, the post is limited
            limited = target.calls("limited")
            with pytest.raises(TransientError):
                target.write(key)
            assert target.calls("limited") == limited + 1
            assert target.stored_id_for(key) is None, shape
            receipt = retrying(functools.partial(_write, target, key))
            assert target.stored_id_for(key) == receipt.external_id

    @covers(Section.WRITE_FAILURES, Control.AUTH)
    def test_a_401_at_any_step_of_a_write_is_an_auth_error(self, target: Target) -> None:
        target.require(Control.AUTH)
        for op in ("lookup", "write"):
            target.revoke_auth(op)
            with pytest.raises(PermanentError) as caught:
                target.write(f"k-{op}")
            assert is_auth_error(caught.value), f"a 401 on {op}"
            target.restore_auth()
        assert target.stored_ids() == []

    @covers(Section.WRITE_FAILURES, Control.AUTH)
    def test_the_write_succeeds_once_auth_is_restored(self, target: Target) -> None:
        target.require(Control.AUTH)
        target.revoke_auth()
        with pytest.raises(PermanentError):
            target.write("k1")
        target.restore_auth()
        receipt = _write(target, "k1")
        assert target.stored_ids() == [receipt.external_id]

    @covers(Section.WRITE_FAILURES, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_plain_403_at_any_step_of_a_write_is_a_permission_error(self, target: Target) -> None:
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        for op in ("lookup", "write"):
            target.respond_next(op, 403)
            with pytest.raises(PermanentError) as caught:
                target.write(f"k-{op}")
            assert is_auth_error(caught.value), f"a 403 on {op}"
        assert target.stored_ids() == []

    @covers(Section.WRITE_FAILURES, Control.AUTH, Control.HTTP_ERRORS)
    def test_a_404_at_any_step_of_a_write_is_an_unknown_object(self, target: Target) -> None:
        target.require(Control.AUTH, Control.HTTP_ERRORS)
        for op in ("lookup", "write"):
            target.respond_next(op, 404)
            with pytest.raises(UnknownRefError):
                target.write(f"k-{op}")
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
            target = factory()
            validate_target(target, port)
            getattr(AdapterConformance.__new__(AdapterConformance), name)(target)
            out[name] = None
        except (Exception, pytest.fail.Exception, pytest.skip.Exception) as exc:
            out[name] = exc
    return out
