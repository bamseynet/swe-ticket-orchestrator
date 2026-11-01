"""D4-01: the conformance suite runs in process against the merged fakes and a reference adapter.

* ``ReferenceTarget`` is the trivial fake adapter: it passes every section.
* The merged fakes (D1-04) pass the crash section, and are known to lack signature, duplicate,
  ordering, rate limit and auth controls. That is a finding for the stage that owns each fake
  (D4-16 and the Jira and Slack fakes), recorded here as strict xfails.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import ClassVar

import pytest
from suite import (
    AdapterConformance,
    Control,
    MissingControl,
    Target,
    needs,
    pending_controls,
    select_target,
)

from sto.adapters.fake.notifier import FakeNotifier
from sto.adapters.fake.scm import FakeScm
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.fake.tickets import FakeTicketSource
from sto.adapters.ports import (
    CheckSpec,
    ExternalChange,
    GateMessage,
    RawWebhook,
    RepoRef,
    Ticket,
    TicketRef,
)
from sto.domain.errors import PermanentError, TransientError
from sto.domain.models import Receipt

REPO = RepoRef("acme", "app")
TREF = TicketRef("fake", "T-1")
SECRET = b"synthetic-secret"
ALL = frozenset(Control)


def _mac(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


class ReferenceTarget(Target):
    """A trivial fake adapter over ``FakeTicketSource``: HMAC over the raw body, dedupe by
    delivery ID, a rate limiter and revocable auth, which the fake itself does not model."""

    name = "reference"
    controls = ALL

    def __init__(self) -> None:
        self.spy = SpyWriter()
        self.fake = FakeTicketSource(self.spy)
        self.fake.add_ticket(Ticket(TREF, "t", "b", "open"))
        self._seen: set[str] = set()
        self._queue: list[ExternalChange] = []
        self._revision = 0
        self._limited = 0
        self._auth = True

    def _guard(self) -> None:
        if not self._auth:
            raise PermanentError("401 bad credentials")
        if self._limited:
            self._limited -= 1
            raise TransientError("429 rate limited")

    def write(self, key: str, variant: str = "a") -> Receipt:
        self._guard()
        return self.fake.comment(TREF, f"body-{variant}", key)

    def effects(self) -> int:
        return len(self.spy.applied("comment"))

    def lose_response_next(self) -> None:
        self.fake.lose_response_next("comment")

    def fail_next(self) -> None:
        self.fake.fail_next("comment")

    def rate_limit_next(self, times: int) -> None:
        self._limited = times

    def revoke_auth(self) -> None:
        self._auth = False

    def restore_auth(self) -> None:
        self._auth = True

    def _delivery(self, revision: int, delivery_id: str, secret: bytes) -> RawWebhook:
        self._revision = max(self._revision, revision)
        body = json.dumps({"changes": [{"kind": "ticket", "ticket": TREF.key}]}).encode()
        # the revision rides in the header, not the body: a delivery never carries state
        headers = {
            "X-Delivery": delivery_id,
            "X-Revision": str(revision),
            "X-Sig": _mac(secret, body),
        }
        return RawWebhook(headers, body)

    def signed(self, revision: int, delivery_id: str) -> RawWebhook:
        return self._delivery(revision, delivery_id, SECRET)

    def forged(self, revision: int, delivery_id: str) -> RawWebhook:
        return self._delivery(revision, delivery_id, b"not-the-secret")

    def deliver(self, raw: RawWebhook) -> list[ExternalChange]:
        if not hmac.compare_digest(raw.headers.get("X-Sig", ""), _mac(SECRET, raw.body)):
            raise PermanentError("401 bad signature")
        delivery_id = raw.headers["X-Delivery"]
        if delivery_id in self._seen:
            return []
        self._seen.add(delivery_id)
        changes = self.fake.parse_event(raw)
        self._queue.extend(changes)
        return changes

    def queued(self) -> int:
        return len(self._queue)

    def read_revision(self) -> int:
        return self._revision


class FakeTicketsTarget(Target):
    name = "FakeTicketSource"
    controls = frozenset({Control.CRASH})

    def __init__(self) -> None:
        self.spy = SpyWriter()
        self.fake = FakeTicketSource(self.spy)
        self.fake.add_ticket(Ticket(TREF, "t", "b", "open"))

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.fake.comment(TREF, f"body-{variant}", key)

    def effects(self) -> int:
        return len(self.spy.applied("comment"))

    def lose_response_next(self) -> None:
        self.fake.lose_response_next("comment")

    def fail_next(self) -> None:
        self.fake.fail_next("comment")


class FakeScmTarget(Target):
    name = "FakeScm"
    controls = frozenset({Control.CRASH})

    def __init__(self) -> None:
        self.spy = SpyWriter()
        self.fake = FakeScm(self.spy)
        self.fake.seed_branch(REPO, "main", "sha0")

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.fake.publish_check(CheckSpec(REPO, "sha0", f"check-{variant}", "success"), key)

    def effects(self) -> int:
        return len(self.spy.applied("publish_check"))

    def lose_response_next(self) -> None:
        self.fake.lose_response_next("publish_check")

    def fail_next(self) -> None:
        self.fake.fail_next("publish_check")


class FakeNotifierTarget(Target):
    name = "FakeNotifier"
    controls = frozenset({Control.CRASH})

    def __init__(self) -> None:
        self.spy = SpyWriter()
        self.fake = FakeNotifier(self.spy)

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.fake.send(GateMessage(f"gate-{variant}", "s", "digest"), key)

    def effects(self) -> int:
        return len(self.spy.applied("send"))

    def lose_response_next(self) -> None:
        self.fake.lose_response_next("send")

    def fail_next(self) -> None:
        self.fake.fail_next("send")


class TestReferenceAdapter(AdapterConformance):
    """A trivial fake adapter passes every section."""

    @pytest.fixture
    def target(self) -> Target:
        return select_target({"fake": ReferenceTarget})


_GAPS = (
    Control.SIGNATURE,
    Control.DUPLICATE,
    Control.ORDERING,
    Control.RATE_LIMIT,
    Control.AUTH,
)


@pending_controls(*_GAPS)
class TestMergedFakeTicketSource(AdapterConformance):
    @pytest.fixture
    def target(self) -> Target:
        return select_target({"fake": FakeTicketsTarget})


@pending_controls(*_GAPS)
class TestMergedFakeScm(AdapterConformance):
    @pytest.fixture
    def target(self) -> Target:
        return select_target({"fake": FakeScmTarget})


@pending_controls(*_GAPS)
class TestMergedFakeNotifier(AdapterConformance):
    @pytest.fixture
    def target(self) -> Target:
        return select_target({"fake": FakeNotifierTarget})


# --- the suite's own plumbing ---------------------------------------------------------------


def test_a_missing_control_fails_rather_than_skips() -> None:
    with pytest.raises(MissingControl, match="rate_limit"):
        FakeTicketsTarget().require(Control.RATE_LIMIT)


def test_select_target_defaults_to_the_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STO_CONFORMANCE_TARGET", raising=False)
    assert isinstance(select_target({"fake": ReferenceTarget}), ReferenceTarget)


def test_select_target_never_falls_back_to_the_fake_for_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "live")
    with pytest.raises(pytest.UsageError, match="live"):
        select_target({"fake": ReferenceTarget})


def test_select_target_picks_live_when_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    class Live(ReferenceTarget):
        name: ClassVar[str] = "live"

    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "live")
    assert select_target({"fake": ReferenceTarget, "live": Live}).name == "live"


def test_pending_controls_only_marks_tests_that_need_a_gap() -> None:
    @pending_controls(Control.AUTH)
    class Probe:
        @needs(Control.AUTH)
        def test_a(self) -> None: ...

        @needs(Control.CRASH)
        def test_b(self) -> None: ...

    assert hasattr(Probe.test_a, "pytestmark")
    assert not hasattr(Probe.test_b, "pytestmark")
