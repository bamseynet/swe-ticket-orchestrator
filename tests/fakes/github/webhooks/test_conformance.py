"""D4-16: the conformance suite's auth and webhook sections, aimed at the fake GitHub.

The fake is a SERVER. It has no adapter of its own and verifies nothing: the adapter and the
verifier are the suite's reference ones (``GitHubHeadersAdapter``, which adds only GitHub's header
names), and the suite asserts what the SERVER saw. So this proves the fake behaves like a vendor
server the suite can target, not that any adapter is right.

Selection follows ``STO_CONFORMANCE_TARGET``: only ``fake`` is registered here. The live GitHub
target arrives with D12.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import ClassVar

import pytest

from contract.suite import (
    AdapterConformance,
    Control,
    ForgeKind,
    Outcome,
    Port,
    RateShape,
    Section,
    Target,
    Vendor,
    applicable,
    run_suite,
)
from contract.test_suite import GitHubHeadersAdapter, Store
from fakes.github.auth import INSTALLATION_ID, FakeGitHubAuth
from fakes.github.webhooks import FakeWebhooks
from sto.adapters.ports import DecisionRequest, RawWebhook

pytestmark = pytest.mark.contract

WATCHED = "T-1"


def _body(revision: int, delivery_id: str) -> bytes:
    """The one body shape the reference adapter reads; the fake sends whatever it is given."""
    return json.dumps(
        {"changes": [{"kind": "ticket", "ticket": WATCHED}], "revision": revision}
    ).encode()


class FakeGitHubTarget(Target):
    """The harness: a thin pass-through to the fake's auth server and webhook sender."""

    name = "fake-github"
    vendor = Vendor.GITHUB
    signature_header = "X-Hub-Signature-256"
    watched = WATCHED
    controls = frozenset(
        {
            Control.SIGNATURE,
            Control.UNSIGNED,
            Control.DUPLICATE,
            Control.REPLAY_WINDOW,
            Control.RESTART,
            Control.ORDERING,
            Control.RATE_LIMIT,
            Control.AUTH,
            Control.HTTP_ERRORS,
        }
    )

    def __init__(self) -> None:
        self.server = FakeGitHubAuth()
        self.hooks = FakeWebhooks(lambda: self.server.now, body=_body)
        self.store = Store(set(), [])
        self.token = self._mint()
        self.adapter: GitHubHeadersAdapter = self._fresh()
        self.verifier = self.adapter.verifier

    def _mint(self) -> str:
        response = self.server.create_installation_token(self.server.app_jwt(), INSTALLATION_ID)
        return str(response.body["token"])

    def _fresh(self) -> GitHubHeadersAdapter:
        adapter = GitHubHeadersAdapter(self.server, self.store)  # type: ignore[arg-type]
        adapter.token = self.token
        return adapter

    # --- adapter calls ---
    def restart(self) -> None:
        self.adapter = self._fresh()
        self.verifier = self.adapter.verifier

    def deliver(self, raw: RawWebhook) -> Outcome:
        result = self.adapter.receive(raw)
        if result is None:
            return Outcome(False)
        assert not isinstance(result, DecisionRequest)
        return Outcome(True, tuple(c.ticket.key for c in result if c.ticket))

    def queued(self) -> int:
        return len(self.store.queue)

    def reported_revision(self) -> int:
        return self.adapter.read_revision()

    def probe(self) -> None:
        self.adapter.probe()

    # --- the server's view ---
    def calls(self, op: str) -> int:
        return self.server.counts[op]

    def server_revision(self) -> int:
        return self.server.revision

    def clock(self) -> float:
        return self.server.now

    def advance_clock(self, seconds: float) -> None:
        self.server.now += seconds

    # --- controls, acting at the server ---
    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        self.server.fault_next(op, mode, page, after)

    def respond_next(self, op: str, status: int) -> None:
        self.server.respond_next(op, status)

    def rate_limit_next(self, times: int, shape: RateShape, op: str | None = None) -> None:
        self.server.rate_limit_next(times, shape, op)

    def revoke_auth(self, op: str | None = None) -> None:
        self.server.revoke_auth(op)

    def restore_auth(self) -> None:
        self.server.restore_auth()

    def expire_token(self) -> None:
        self.server.expire_token(self.token)

    # --- the vendor sending webhooks ---
    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        self.server.revision = revision
        return self.hooks.delivery(revision, delivery_id)

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        return self.hooks.forge(revision, delivery_id, how)

    def emit_without_id(self, revision: int) -> RawWebhook:
        return self.hooks.without_id(revision)

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        return self.hooks.malformed(delivery_id)

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        return self.hooks.delivery(revision, delivery_id)  # GitHub signs and sends no time

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        headers = {k: v for k, v in raw.headers.items() if k != "X-Timestamp"}
        if value is not None:
            headers["X-Timestamp"] = value  # GitHub sends none: a forger may add one
        return RawWebhook(headers, raw.body)

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        return self.hooks.tamper(raw)

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        return self.hooks.reserialise(raw)


def fake_github() -> Target:
    return FakeGitHubTarget()


class TestFakeGitHubAuthAndWebhooks(AdapterConformance):
    """The auth, reads, rate limits and webhooks of the fake GitHub, with no write surface."""

    port = Port.AUTH_WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": fake_github}


def test_the_fake_passes_every_test_its_port_requires() -> None:
    failed = {n: e for n, e in run_suite(fake_github, Port.AUTH_WEBHOOK).items() if e is not None}
    assert failed == {}


def test_the_sections_it_is_held_to_are_the_webhook_ordering_rate_and_auth_ones() -> None:
    names = applicable(Port.AUTH_WEBHOOK)
    assert names
    assert not [n for n in names if "write" in n or "lookup" in n]
    assert {Section.WEBHOOK, Section.ORDERING, Section.RATE, Section.AUTH} >= {
        getattr(AdapterConformance, n)._section for n in names
    }


def test_the_fake_has_no_adapter_of_its_own() -> None:
    import fakes.github.auth.server as auth
    import fakes.github.webhooks.sender as sender

    for module in (auth, sender):
        classes = {n for n in vars(module) if n.endswith(("Adapter", "Verifier"))}
        assert classes == set(), (module.__name__, classes)
    assert not hasattr(FakeGitHubAuth, "verify")
    assert not hasattr(FakeWebhooks, "verify")
