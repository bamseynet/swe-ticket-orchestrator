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
from contract.test_suite import (
    PRINCIPAL,
    GitHubHeadersAdapter,
    LinkFollowingAdapter,
    Store,
    SwallowingLinkFollowingAdapter,
)
from fakes.github.auth import INSTALLATION_ID, FakeGitHubAuth
from fakes.github.webhooks import FakeWebhooks
from sto.adapters.ports import DecisionRequest, RawWebhook
from sto.domain.models import Receipt

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
    adapter_cls: type[GitHubHeadersAdapter] = GitHubHeadersAdapter
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
        adapter = self.adapter_cls(self.server, self.store)  # type: ignore[arg-type]
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
        # The suite counts pages from zero; this server counts from one.
        self.server.fault_next(op, mode, None if page is None else page + 1, after)

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


# --- the same fake, paged by link, held to the look-up and write sections too ---------------------


class PagedFakeGitHubTarget(FakeGitHubTarget):
    """Every control, through the fake's list and its stand-in write. The page base is translated
    in ``fault_next`` (the suite's page 1 is the second page; the server's is the first)."""

    name = "paged-fake-github"
    adapter_cls: type[GitHubHeadersAdapter] = LinkFollowingAdapter
    controls = frozenset(Control)

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.adapter.write(key, variant)

    def stored_ids(self) -> list[str]:
        return [i.id for i in self.server.items if i.author == PRINCIPAL]

    def stored_id_for(self, key: str) -> str | None:
        for i in self.server.items:
            if i.author == PRINCIPAL and f"<!-- sto:{key}:" in i.body:
                return i.id
        return None

    def listed(self) -> int:
        return len(self.server.items)

    def foreign_marked(self, key: str) -> bool:
        return any(
            i.author != PRINCIPAL and f"<!-- sto:{key}:" in i.body for i in self.server.items
        )

    def seed_others(self, n: int, newer: bool = True) -> None:
        self.server.seed(n, "alice", older=not newer)

    def set_list_order(self, order: str) -> None:
        self.server.order = order

    def plant_foreign_marker(self, key: str, variant: str = "a", author: str = "mallory") -> None:
        self.server.add(author, self.adapter.marker(key, variant) + " planted")

    def swallow_next_write(self) -> None:
        self.server.swallow += 1


class UntranslatedPagedTarget(PagedFakeGitHubTarget):
    """The mistake the page base guards against: the suite's page number sent to a one-based
    server as it is, so "a later page" is the FIRST page."""

    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        self.server.fault_next(op, mode, page, after)


def paged_fake_github() -> Target:
    return PagedFakeGitHubTarget()


class TestPagedFakeGitHub(AdapterConformance):
    """All eight sections against the fake's paged list and stand-in write, through an adapter
    that follows the ``link`` header."""

    port = Port.SCM
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": paged_fake_github}


LATER_PAGE = "test_an_error_on_a_later_page_is_not_the_end_of_the_list"


def _paged(adapter: type[GitHubHeadersAdapter], base: type[PagedFakeGitHubTarget]) -> Target:
    target = base()
    target.adapter_cls = adapter
    target.adapter = target._fresh()
    target.verifier = target.adapter.verifier
    return target


def test_the_paged_fake_passes_every_section_through_a_link_following_adapter() -> None:
    failed = {n: e for n, e in run_suite(paged_fake_github, Port.SCM).items() if e is not None}
    assert failed == {}


def test_an_adapter_that_swallows_a_later_page_error_fails_on_the_paged_fake() -> None:
    results = run_suite(
        lambda: _paged(SwallowingLinkFollowingAdapter, PagedFakeGitHubTarget), Port.SCM
    )
    assert type(results[LATER_PAGE]) is pytest.fail.Exception  # DID NOT RAISE
    assert [n for n, e in results.items() if e is not None] == [LATER_PAGE]


def test_without_the_page_translation_the_same_adapter_slips_through() -> None:
    """Why the suite fixes the page base: on a one-based server, page 1 is the first page, and a
    fault there is not a LATER page."""
    results = run_suite(
        lambda: _paged(SwallowingLinkFollowingAdapter, UntranslatedPagedTarget), Port.SCM
    )
    assert results[LATER_PAGE] is None
