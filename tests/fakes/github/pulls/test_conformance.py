"""D4-19: the conformance suite's SCM section, aimed at the fake GitHub's real routes.

The fake is a SERVER with no adapter of its own. The suite's reference adapter
(``LinkFollowingAdapter``) speaks the suite's three stand-in ops (``lookup``, ``write``, ``read``);
``RoutedOps`` below is the whole of the translation, and it turns each into the real GitHub
request an adapter makes: ``GET .../issues/1/comments`` (paged by the ``link`` header),
``POST .../issues/1/comments`` and ``GET .../pulls/1``. It adds no logic. So this proves the fake
behaves like a vendor server the suite can target, not that any adapter is right.

Selection follows ``STO_CONFORMANCE_TARGET``: only ``fake`` is registered here. The live GitHub
target arrives with D4-15.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, ClassVar

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
from fakes.github.auth import INSTALLATION_ID, Response
from fakes.github.pulls import REPO, FakeGitHubPulls
from fakes.github.webhooks import FakeWebhooks
from sto.adapters.ports import DecisionRequest, RawWebhook
from sto.domain.models import Receipt

pytestmark = pytest.mark.contract

WATCHED = "T-1"
PR = 1
BASE = f"/repos/{REPO}"


def _body(revision: int, delivery_id: str) -> bytes:
    return json.dumps(
        {"changes": [{"kind": "ticket", "ticket": WATCHED}], "revision": revision}
    ).encode()


class RoutedOps:
    """The suite's stand-in ops, as the real requests they stand for. Nothing else."""

    def __init__(self, server: FakeGitHubPulls) -> None:
        self.server = server

    @property
    def now(self) -> float:
        return self.server.now

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        if op == "lookup":
            query = {k: str(v) for k, v in kw.items()}
            r = self.server.request("GET", f"{BASE}/issues/{PR}/comments", token, query=query)
            if r.status != 200:
                return r
            items = [
                {"id": str(c["id"]), "author": c["user"]["login"], "body": c["body"]}
                for c in r.body
            ]
            return Response(200, r.headers, {"items": items})
        if op == "write":
            r = self.server.request(
                "POST", f"{BASE}/issues/{PR}/comments", token, json={"body": kw["body"]}
            )
            return r if r.status != 201 else Response(201, r.headers, {"id": str(r.body["id"])})
        if op == "read":
            r = self.server.request("GET", f"{BASE}/pulls/{PR}", token)
            if r.status != 200:
                return r
            return Response(200, r.headers, {"revision": int(r.body["title"].split()[-1])})
        raise AssertionError(f"unknown op {op!r}")


class FakeGitHubPullsTarget(Target):
    """The harness: a thin pass-through to the fake's routes and its test controls."""

    name = "fake-github-pulls"
    adapter_cls: type[GitHubHeadersAdapter] = LinkFollowingAdapter
    vendor = Vendor.GITHUB
    signature_header = "X-Hub-Signature-256"
    watched = WATCHED
    controls = frozenset(Control)

    def __init__(self) -> None:
        self.server = FakeGitHubPulls()
        self.server.push(REPO, "feat", {"feat.txt": "x"})
        token = self.server.mint()
        opened = self.server.request(
            "POST",
            f"{BASE}/pulls",
            token,
            json={"title": "revision 0", "head": "feat", "base": "main"},
        )
        assert opened.status == 201
        assert opened.body["number"] == PR
        self.ops = RoutedOps(self.server)
        self.hooks = FakeWebhooks(lambda: self.server.now, body=_body)
        self.store = Store(set(), [])
        self.token = self._mint()
        self.adapter: GitHubHeadersAdapter = self._fresh()
        self.verifier = self.adapter.verifier

    def _mint(self) -> str:
        response = self.server.create_installation_token(self.server.app_jwt(), INSTALLATION_ID)
        return str(response.body["token"])

    def _fresh(self) -> GitHubHeadersAdapter:
        adapter = self.adapter_cls(self.ops, self.store)  # type: ignore[arg-type]
        adapter.token = self.token
        return adapter

    # --- adapter calls ---
    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.adapter.write(key, variant)

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
    def _comments(self) -> list[Any]:
        return [c for c in self.server.repos[REPO].comments if c.number == PR]

    def stored_ids(self) -> list[str]:
        return [str(c.id) for c in self._comments() if c.author == PRINCIPAL]

    def stored_id_for(self, key: str) -> str | None:
        for c in self._comments():
            if c.author == PRINCIPAL and f"<!-- sto:{key}:" in c.body:
                return str(c.id)
        return None

    def foreign_marked(self, key: str) -> bool:
        return any(c.author != PRINCIPAL and f"<!-- sto:{key}:" in c.body for c in self._comments())

    def listed(self) -> int:
        return len(self._comments())

    def calls(self, op: str) -> int:
        return self.server.counts[op]

    def server_revision(self) -> int:
        return int(self.server.pulls(REPO)[PR - 1].title.split()[-1])

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

    def seed_others(self, n: int, newer: bool = True) -> None:
        for i in range(n):
            self.server.add_comment(PR, "alice", f"unrelated {i}", older=not newer)

    def set_list_order(self, order: str) -> None:
        self.server.order = order

    def plant_foreign_marker(self, key: str, variant: str = "a", author: str = "mallory") -> None:
        self.server.add_comment(PR, author, self.adapter.marker(key, variant) + " planted")

    def swallow_next_write(self) -> None:
        self.server.swallow += 1

    # --- the vendor sending webhooks ---
    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        self.server.edit_pull(PR, title=f"revision {revision}")
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


class UntranslatedTarget(FakeGitHubPullsTarget):
    """The mistake the page base guards against: the suite's page number sent to a one-based
    server as it is, so "a later page" is the FIRST page."""

    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        self.server.fault_next(op, mode, page, after)


def fake_github_pulls() -> Target:
    return FakeGitHubPullsTarget()


class TestFakeGitHubPulls(AdapterConformance):
    """All eight sections of the SCM port's suite, against the fake's PR comment routes."""

    port = Port.SCM
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": fake_github_pulls}


LATER_PAGE = "test_an_error_on_a_later_page_is_not_the_end_of_the_list"


def _with(adapter: type[GitHubHeadersAdapter], base: type[FakeGitHubPullsTarget]) -> Target:
    target = base()
    target.adapter_cls = adapter
    target.adapter = target._fresh()
    target.verifier = target.adapter.verifier
    return target


def test_the_fake_passes_every_section_the_scm_port_requires() -> None:
    results = run_suite(fake_github_pulls, Port.SCM)
    assert {n: e for n, e in results.items() if e is not None} == {}
    assert set(results) == set(applicable(Port.SCM))
    assert {getattr(AdapterConformance, n)._section for n in results} == set(Section)


def test_the_suite_reaches_the_server_only_through_the_real_routes() -> None:
    target = FakeGitHubPullsTarget()
    target.write("k1")
    target.probe()
    assert target.reported_revision() == 0
    seen = {(m, p) for m, p in target.server.log if "/git/" not in p}
    assert ("POST", f"{BASE}/issues/1/comments") in seen
    assert ("GET", f"{BASE}/issues/1/comments") in seen
    assert ("GET", f"{BASE}/pulls/1") in seen
    with pytest.raises(AssertionError, match="real routes"):
        target.server.handle("write", target.token, body="x")


def test_an_adapter_that_swallows_a_later_page_error_fails_here_too() -> None:
    results = run_suite(
        lambda: _with(SwallowingLinkFollowingAdapter, FakeGitHubPullsTarget), Port.SCM
    )
    assert type(results[LATER_PAGE]) is pytest.fail.Exception  # DID NOT RAISE
    assert [n for n, e in results.items() if e is not None] == [LATER_PAGE]


def test_without_the_page_translation_the_same_adapter_slips_through() -> None:
    results = run_suite(lambda: _with(SwallowingLinkFollowingAdapter, UntranslatedTarget), Port.SCM)
    assert results[LATER_PAGE] is None


def test_the_fake_has_no_adapter_of_its_own() -> None:
    import fakes.github.pulls.server as server

    classes = {n for n in vars(server) if n.endswith(("Adapter", "Verifier"))}
    assert classes == set()
