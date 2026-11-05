"""Account linking (D3-04): proof by the vendor's OAuth flow, single-use short-lived tokens,
no email matching, an unlinked account never resolves, and unlink is audited.

Everything is offline: the vendors are fakes, and the client secrets, codes and tokens are
synthetic. The router tests run the real authorization middleware with the ``ROUTES`` lines the
PR body asks for, so the declared permission is what is tested.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sto.api.auth import (
    ROUTES,
    Authorization,
    Permission,
    RouteRule,
    install_authorization,
    routes_of,
    undeclared_routes,
)
from sto.api.routers.links import LINK_ROUTES, make_router
from sto.api.routers.runs import ApiError
from sto.config.org_policy import ORG_ADMIN, Principal
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.linking import (
    AccountClaimedError,
    AccountLinking,
    LinkContentionError,
    LinkStateError,
    LinkTokenExpiredError,
    LinkTokenInvalidError,
    LinkTokenMismatchError,
    NotLinkedError,
    UnknownVendorError,
    VendorAccount,
    VendorExchangeError,
)
from sto.identity.mapping import RoleMapping, UserIdentity
from sto.identity.oidc import OidcConfig, OidcValidator, StaticJwks
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, ConditionFailedError, Key, TeamScope

ISS = "https://idp.example.test"
CLIENT = "sto-client"
NOW = 1_800_000_000.0
ANN = UserIdentity("ann-sub", ISS, frozenset({("alpha", "developer")}))
BOB = UserIdentity("bob-sub", ISS, frozenset({("alpha", "reviewer")}))
SESSION, OTHER_SESSION = "sess-ann-1", "sess-ann-2"
JIRA_ID = "712020:synthetic-jira-account-0001"
SECRET = "synthetic-client-secret-do-not-use"  # a fixture, like every value here


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeVendor:
    """A vendor's OAuth: ``code -> account``. Codes are single-use, as a real vendor's are."""

    name: str
    accounts: dict[str, VendorAccount] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)
    states: list[str] = field(default_factory=list)

    def authorize_url(self, state: str) -> str:
        self.states.append(state)
        return f"https://{self.name}.example.test/oauth/authorize?client_id=synthetic&state={state}"

    def exchange(self, code: str) -> VendorAccount:
        if code in self.used or code not in self.accounts:
            raise VendorExchangeError("the vendor refused the code")
        self.used.add(code)
        return self.accounts[code]


def make_vendors() -> dict[str, FakeVendor]:
    return {
        "jira": FakeVendor("jira", {"jira-code-ann": VendorAccount(JIRA_ID, "ann@example.test")}),
        "github": FakeVendor("github", {"gh-code-ann": VendorAccount("ann-octo", None)}),
        "slack": FakeVendor("slack", {"sl-code-ann": VendorAccount("U0SYNTH01", None)}),
    }


@dataclass
class Rig:
    store: MemoryStore
    clock: Clock
    vendors: dict[str, FakeVendor]
    links: AccountLinking


@pytest.fixture
def rig() -> Rig:
    store, clock, vendors = MemoryStore(), Clock(), make_vendors()
    links = AccountLinking(store, vendors=vendors, clock=clock)
    return Rig(store, clock, vendors, links)


def link_jira(rig: Rig, who: UserIdentity = ANN, code: str = "jira-code-ann") -> None:
    started = rig.links.start(who, SESSION, "jira")
    rig.links.complete(who, SESSION, "jira", started.token, code)


def audit_entries(store: MemoryStore, who: UserIdentity) -> list[dict[str, Any]]:
    pk = f"USER#{who.issuer}|{who.subject}"
    return [i.data for i in store.query(PLATFORM, pk, sk_prefix="LINKLOG#").items]


# --- AC 2: a Jira account ID resolves to an SSO identity ---------------------------------------


def test_a_jira_account_id_resolves_to_the_sso_identity(rig: Rig) -> None:
    link_jira(rig)
    found = rig.links.resolve("jira", JIRA_ID)
    assert found is not None
    assert (found.issuer, found.subject) == (ISS, "ann-sub")
    assert found.actor == f"{ISS}|ann-sub"


@pytest.mark.parametrize("vendor", ["slack", "github", "jira"])
def test_each_vendor_links_and_resolves(rig: Rig, vendor: str) -> None:
    code = {"slack": "sl-code-ann", "github": "gh-code-ann", "jira": "jira-code-ann"}[vendor]
    started = rig.links.start(ANN, SESSION, vendor)
    link = rig.links.complete(ANN, SESSION, vendor, started.token, code)
    resolved = rig.links.resolve(vendor, link.account_id)
    assert resolved is not None
    assert resolved.subject == "ann-sub"


def test_the_same_id_at_another_vendor_is_another_account(rig: Rig) -> None:
    link_jira(rig)
    assert rig.links.resolve("github", JIRA_ID) is None
    assert rig.links.resolve("slack", JIRA_ID) is None


def test_the_authorize_url_carries_the_token_as_state(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    assert started.authorize_url.endswith(f"state={started.token}")
    assert rig.vendors["jira"].states == [started.token]


# --- email matching alone is refused -----------------------------------------------------------


def test_matching_email_alone_does_not_link(rig: Rig) -> None:
    # the vendor reports ann's email for this account, but no link was completed
    assert rig.vendors["jira"].accounts["jira-code-ann"].email == "ann@example.test"
    assert rig.links.resolve("jira", JIRA_ID) is None
    with pytest.raises(NotLinkedError):
        rig.links.require_linked("jira", JIRA_ID)


def test_the_vendors_email_is_never_stored_or_used(rig: Rig) -> None:
    link_jira(rig)
    dumped = repr(rig.store.query(PLATFORM, f"USER#{ISS}|ann-sub").items)
    dumped += repr(rig.store.query(PLATFORM, "ORG").items)
    assert "ann@example.test" not in dumped


def test_there_is_no_way_to_link_by_email(rig: Rig) -> None:
    assert not hasattr(rig.links, "link_by_email")
    with pytest.raises(TypeError):
        rig.links.complete(ANN, SESSION, "jira", "t", "c", email="ann@example.test")  # type: ignore[call-arg]


def test_a_token_is_required_even_with_a_valid_code(rig: Rig) -> None:
    with pytest.raises(LinkTokenInvalidError):
        rig.links.complete(ANN, SESSION, "jira", "never-issued", "jira-code-ann")
    assert rig.links.resolve("jira", JIRA_ID) is None


# --- AC 1: replayed and expired link tokens are refused ----------------------------------------


def test_a_replayed_token_is_refused(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    rig.vendors["jira"].accounts["jira-code-2"] = VendorAccount("712020:other", None)
    with pytest.raises(LinkTokenInvalidError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-2")
    assert rig.links.resolve("jira", "712020:other") is None


def test_a_replayed_token_is_refused_after_unlink_too(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    rig.links.unlink(ANN, "jira", JIRA_ID)
    rig.vendors["jira"].accounts["again"] = VendorAccount(JIRA_ID, None)
    with pytest.raises(LinkTokenInvalidError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "again")
    assert rig.links.resolve("jira", JIRA_ID) is None


def test_an_expired_token_is_refused(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    rig.clock.now = started.expires_at  # expiry is exclusive of the last instant
    with pytest.raises(LinkTokenExpiredError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    assert rig.links.resolve("jira", JIRA_ID) is None


def test_a_token_just_before_expiry_still_works(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    rig.clock.now = started.expires_at - 0.001
    link = rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    assert link.account_id == JIRA_ID


def test_tokens_are_short_lived_by_default(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    assert 0 < started.expires_at - NOW <= 900


def test_the_token_lifetime_is_capped(rig: Rig) -> None:
    with pytest.raises(ValueError, match="token_ttl"):
        AccountLinking(MemoryStore(), vendors={}, clock=rig.clock, token_ttl=3600)
    with pytest.raises(ValueError, match="token_ttl"):
        AccountLinking(MemoryStore(), vendors={}, clock=rig.clock, token_ttl=0)


def test_the_token_is_not_stored_in_the_clear(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    link_jira(rig)
    dumped = repr(rig.store.query(PLATFORM, "ORG").items) + repr(
        rig.store.query(PLATFORM, f"USER#{ISS}|ann-sub").items
    )
    assert started.token not in dumped
    assert SESSION not in dumped


def test_each_token_is_unique_and_unguessable(rig: Rig) -> None:
    tokens = {rig.links.start(ANN, SESSION, "jira").token for _ in range(20)}
    assert len(tokens) == 20
    assert all(len(t) >= 32 for t in tokens)


def test_a_failed_vendor_exchange_leaves_nothing_linked(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(VendorExchangeError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "wrong-code")
    assert rig.links.links_of(ANN) == []
    # the token is still ours and still bound: a right code now completes it
    assert rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")


# --- bound to the SSO user, the SSO session and the vendor --------------------------------------


def test_another_user_cannot_complete_my_token(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(LinkTokenMismatchError):
        rig.links.complete(BOB, SESSION, "jira", started.token, "jira-code-ann")
    assert rig.links.resolve("jira", JIRA_ID) is None
    # a refused stranger did not use the token up
    assert rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")


def test_another_sso_session_cannot_complete_my_token(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(LinkTokenMismatchError):
        rig.links.complete(ANN, OTHER_SESSION, "jira", started.token, "jira-code-ann")
    assert rig.links.resolve("jira", JIRA_ID) is None


def test_a_token_is_for_one_vendor(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(LinkTokenMismatchError):
        rig.links.complete(ANN, SESSION, "github", started.token, "gh-code-ann")
    assert rig.links.resolve("github", "ann-octo") is None


def test_the_same_subject_from_another_issuer_is_another_user(rig: Rig) -> None:
    impostor = UserIdentity("ann-sub", "https://evil.example.test", frozenset({("alpha", "qa")}))
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(LinkTokenMismatchError):
        rig.links.complete(impostor, SESSION, "jira", started.token, "jira-code-ann")


def test_a_session_is_required(rig: Rig) -> None:
    for bad in ("", None):
        with pytest.raises(ValueError, match="session"):
            rig.links.start(ANN, bad, "jira")  # type: ignore[arg-type]


def test_an_unknown_vendor_is_refused(rig: Rig) -> None:
    with pytest.raises(UnknownVendorError):
        rig.links.start(ANN, SESSION, "gitlab")
    with pytest.raises(UnknownVendorError):
        rig.links.resolve("gitlab", "x")


# --- one account, one person --------------------------------------------------------------------


def test_an_account_linked_to_someone_else_is_refused(rig: Rig) -> None:
    link_jira(rig)
    rig.vendors["jira"].accounts["jira-code-bob"] = VendorAccount(JIRA_ID, None)
    started = rig.links.start(BOB, "sess-bob", "jira")
    with pytest.raises(AccountClaimedError):
        rig.links.complete(BOB, "sess-bob", "jira", started.token, "jira-code-bob")
    found = rig.links.resolve("jira", JIRA_ID)
    assert found is not None
    assert found.subject == "ann-sub"


def test_relinking_the_same_account_refreshes_the_expiry(rig: Rig) -> None:
    link_jira(rig)
    first = rig.links.links_of(ANN)[0]
    rig.clock.now += 1000
    rig.vendors["jira"].accounts["again"] = VendorAccount(JIRA_ID, None)
    started = rig.links.start(ANN, SESSION, "jira")
    rig.links.complete(ANN, SESSION, "jira", started.token, "again")
    (second,) = rig.links.links_of(ANN)
    assert second.expires_at > first.expires_at


def test_an_expired_claim_can_be_taken_over_by_proof(rig: Rig) -> None:
    link_jira(rig)
    rig.clock.now += rig.links.link_ttl + 1
    rig.vendors["jira"].accounts["jira-code-bob"] = VendorAccount(JIRA_ID, None)
    started = rig.links.start(BOB, "sess-bob", "jira")
    rig.links.complete(BOB, "sess-bob", "jira", started.token, "jira-code-bob")
    found = rig.links.resolve("jira", JIRA_ID)
    assert found is not None
    assert found.subject == "bob-sub"
    assert rig.links.links_of(ANN) == []


def test_a_hostile_account_id_is_refused(rig: Rig) -> None:
    for bad in ("", " x", "a\nb", "x" * 500):
        rig.vendors["jira"].accounts["c"] = VendorAccount(bad, None)
        rig.vendors["jira"].used.discard("c")
        started = rig.links.start(ANN, SESSION, "jira")
        with pytest.raises(VendorExchangeError):
            rig.links.complete(ANN, SESSION, "jira", started.token, "c")
    assert rig.links.links_of(ANN) == []


# --- links expire; an unlinked account can never decide -----------------------------------------


def test_a_link_expires(rig: Rig) -> None:
    link_jira(rig)
    (link,) = rig.links.links_of(ANN)
    rig.clock.now = link.expires_at
    assert rig.links.resolve("jira", JIRA_ID) is None
    with pytest.raises(NotLinkedError):
        rig.links.require_linked("jira", JIRA_ID)
    assert rig.links.links_of(ANN) == []


def test_require_linked_gives_the_actor_of_a_live_link(rig: Rig) -> None:
    link_jira(rig)
    assert rig.links.require_linked("jira", JIRA_ID).actor == f"{ISS}|ann-sub"


def test_an_unknown_account_never_resolves(rig: Rig) -> None:
    assert rig.links.resolve("jira", "712020:nobody") is None
    with pytest.raises(NotLinkedError):
        rig.links.require_linked("jira", "712020:nobody")


def test_a_hand_written_malformed_reverse_item_fails_closed(rig: Rig) -> None:
    rig.store.put(PLATFORM, Key("ORG", f"LINKED#jira#{JIRA_ID}"), {"user": 5, "expires_at": "x"})
    assert rig.links.resolve("jira", JIRA_ID) is None


# --- AC 3: unlink works and is audited ----------------------------------------------------------


def test_unlink_removes_the_link_and_the_resolution(rig: Rig) -> None:
    link_jira(rig)
    rig.links.unlink(ANN, "jira", JIRA_ID)
    assert rig.links.resolve("jira", JIRA_ID) is None
    assert rig.links.links_of(ANN) == []
    with pytest.raises(NotLinkedError):
        rig.links.require_linked("jira", JIRA_ID)


def test_unlink_is_audited(rig: Rig) -> None:
    link_jira(rig)
    rig.clock.now += 5
    rig.links.unlink(ANN, "jira", JIRA_ID)
    entries = audit_entries(rig.store, ANN)
    assert [e["action"] for e in entries] == ["link.created", "link.removed"]
    removed = entries[-1]
    assert removed["actor"] == f"{ISS}|ann-sub"
    assert removed["data"] == {"vendor": "jira", "account_id": JIRA_ID, "owner": f"{ISS}|ann-sub"}
    assert removed["at"] == int((NOW + 5) * 1000)


def test_creating_a_link_is_audited_without_the_token(rig: Rig) -> None:
    started = rig.links.start(ANN, SESSION, "jira")
    rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    created = audit_entries(rig.store, ANN)[0]
    assert created["action"] == "link.created"
    assert started.token not in repr(created)
    assert SESSION not in repr(created)


def test_audit_entries_are_append_only_even_for_two_in_one_instant(rig: Rig) -> None:
    link_jira(rig)
    rig.links.unlink(ANN, "jira", JIRA_ID)
    rig.vendors["jira"].accounts["jira-code-3"] = VendorAccount(JIRA_ID, None)
    started = rig.links.start(ANN, SESSION, "jira")
    rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-3")
    rig.links.unlink(ANN, "jira", JIRA_ID)  # same clock reading as before: keys must not collide
    assert [e["action"] for e in audit_entries(rig.store, ANN)] == [
        "link.created",
        "link.removed",
        "link.created",
        "link.removed",
    ]


def test_unlinking_someone_elses_account_is_refused_and_writes_nothing(rig: Rig) -> None:
    link_jira(rig)
    before = audit_entries(rig.store, ANN)
    with pytest.raises(NotLinkedError):
        rig.links.unlink(BOB, "jira", JIRA_ID)
    assert rig.links.resolve("jira", JIRA_ID) is not None
    assert audit_entries(rig.store, ANN) == before
    assert audit_entries(rig.store, BOB) == []


def test_unlinking_what_is_not_linked_is_refused(rig: Rig) -> None:
    with pytest.raises(NotLinkedError):
        rig.links.unlink(ANN, "jira", JIRA_ID)
    assert audit_entries(rig.store, ANN) == []


def test_unlink_twice_is_refused_the_second_time(rig: Rig) -> None:
    link_jira(rig)
    rig.links.unlink(ANN, "jira", JIRA_ID)
    with pytest.raises(NotLinkedError):
        rig.links.unlink(ANN, "jira", JIRA_ID)
    assert [e["action"] for e in audit_entries(rig.store, ANN)] == ["link.created", "link.removed"]


def test_an_expired_link_can_still_be_removed(rig: Rig) -> None:
    link_jira(rig)
    rig.clock.now += rig.links.link_ttl + 1
    rig.links.unlink(ANN, "jira", JIRA_ID)
    assert [e["action"] for e in audit_entries(rig.store, ANN)][-1] == "link.removed"


# --- every write is conditional ----------------------------------------------------------------


class _Spy(MemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.transactions: list[list[Any]] = []

    def transact(self, scope: Any, ops: Any) -> None:
        self.transactions.append(list(ops))
        super().transact(scope, ops)


def test_every_write_is_one_conditional_transaction() -> None:
    store, clock = _Spy(), Clock()
    links = AccountLinking(store, vendors=make_vendors(), clock=clock)
    started = links.start(ANN, SESSION, "jira")
    links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    links.unlink(ANN, "jira", JIRA_ID)
    assert len(store.transactions) == 3
    for ops in store.transactions:
        for op in ops:
            assert getattr(op, "when", None) is not None, op


def test_the_store_port_is_never_written_unconditionally(rig: Rig) -> None:
    class Strict(MemoryStore):
        def put(self, scope: Any, key: Any, data: Any, *, when: Any = None, **kw: Any) -> Any:
            assert when is not None, f"unconditional put {key}"
            return super().put(scope, key, data, when=when, **kw)

        def delete(self, scope: Any, key: Any, *, when: Any = None) -> None:
            assert when is not None, f"unconditional delete {key}"
            super().delete(scope, key, when=when)

    links = AccountLinking(Strict(), vendors=make_vendors(), clock=Clock())
    started = links.start(ANN, SESSION, "jira")
    links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    links.unlink(ANN, "jira", JIRA_ID)


def test_two_completions_racing_for_one_token_link_once() -> None:
    """Both read the token before either consumed it; the store lets one transaction win."""
    store, clock, vendors = MemoryStore(), Clock(), make_vendors()
    links = AccountLinking(store, vendors=vendors, clock=clock)
    started = links.start(ANN, SESSION, "jira")
    vendors["jira"].accounts["second"] = VendorAccount(JIRA_ID, None)
    original = vendors["jira"].exchange
    raced: list[bool] = []

    def exchange(code: str) -> VendorAccount:
        account = original(code)
        if not raced:  # between the first completion's read and its write, the second finishes
            raced.append(True)
            links.complete(ANN, SESSION, "jira", started.token, "second")
        return account

    vendors["jira"].exchange = exchange  # type: ignore[method-assign]
    with pytest.raises(LinkTokenInvalidError):
        links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    assert len(links.links_of(ANN)) == 1
    assert [e["action"] for e in audit_entries(store, ANN)] == ["link.created"]


# --- the router --------------------------------------------------------------------------------


def _routes() -> dict[tuple[str, str], RouteRule]:
    return {**ROUTES, **LINK_ROUTES}


class _Http:
    def __init__(self) -> None:
        self.issuer = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
        cfg = OidcConfig(
            issuer=ISS, audience=CLIENT, audience_claim="client_id", token_use="access"
        )
        validator = OidcValidator(cfg, StaticJwks(self.issuer.jwks()), clock=lambda: NOW)
        root = Principal("root", frozenset({ORG_ADMIN}))
        mapping = RoleMapping(MemoryStore(), issuers=[ISS], clock=lambda: NOW)
        for role in ("developer", "reviewer", "auditor"):
            mapping.set_mapping(root, idp=ISS, group=f"g-{role}", team="alpha", role=role)
        self.store, self.clock, self.vendors = MemoryStore(), Clock(), make_vendors()
        self.links = AccountLinking(self.store, vendors=self.vendors, clock=self.clock)
        self.app = FastAPI()

        @self.app.exception_handler(ApiError)
        async def api_error(request: Request, exc: ApiError) -> JSONResponse:
            body = {"code": exc.code, "message": exc.message}
            return JSONResponse({"error": body}, status_code=exc.http_status)

        self.app.include_router(make_router(self.links, session_of=_session))
        authz = Authorization(validator, mapping, routes=_routes(), team_of=lambda conn: "alpha")
        self.authz = Authorization(validator, mapping, team_of=lambda conn: "alpha")
        install_authorization(self.app, authz)

    def token(self, sub: str, role: str = "developer") -> str:
        return self.issuer.issue(
            sub=sub,
            audience=CLIENT,
            groups=[f"g-{role}"],
            extra={"client_id": CLIENT, "token_use": "access"},
        )

    def call(
        self, method: str, path: str, token: str | None, body: Any = None, session: str = SESSION
    ) -> httpx.Response:
        headers = {"x-sso-session": session}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"

        async def go() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                return await c.request(method, path, headers=headers, json=body)

        return asyncio.run(asyncio.wait_for(go(), 20))


def _session(request: Request) -> str | None:
    return request.headers.get("x-sso-session")


@pytest.fixture
def http() -> _Http:
    return _Http()


def test_the_proposed_routes_are_declared_and_no_others_are_missing(http: _Http) -> None:
    assert undeclared_routes(http.app, _routes()) == []
    assert undeclared_routes(http.app, ROUTES) == []  # auth.py declares them (D3-04)
    assert all(isinstance(r.permission, Permission) for r in LINK_ROUTES.values())


def test_link_over_http_end_to_end(http: _Http) -> None:
    ann = http.token("ann-sub")
    started = http.call("POST", "/links/jira:start", ann)
    assert started.status_code == 200
    state = started.json()["state"]
    done = http.call("POST", "/links/jira:complete", ann, {"state": state, "code": "jira-code-ann"})
    assert done.status_code == 200, done.text
    assert done.json()["account_id"] == JIRA_ID
    assert http.links.resolve("jira", JIRA_ID) is not None
    assert [link["account_id"] for link in http.call("GET", "/links", ann).json()["links"]] == [
        JIRA_ID
    ]


def test_replay_and_expiry_over_http(http: _Http) -> None:
    ann = http.token("ann-sub")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    body = {"state": state, "code": "jira-code-ann"}
    assert http.call("POST", "/links/jira:complete", ann, body).status_code == 200
    replay = http.call("POST", "/links/jira:complete", ann, body)
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "link_token_invalid"
    state = http.call("POST", "/links/github:start", ann).json()["state"]
    http.clock.now += 10_000
    late = http.call("POST", "/links/github:complete", ann, {"state": state, "code": "gh-code-ann"})
    assert late.status_code == 410
    assert late.json()["error"]["code"] == "link_token_expired"


def test_a_different_session_or_user_is_refused_over_http(http: _Http) -> None:
    ann, bob = http.token("ann-sub"), http.token("bob-sub", "reviewer")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    body = {"state": state, "code": "jira-code-ann"}
    other_session = http.call("POST", "/links/jira:complete", ann, body, session="elsewhere")
    assert other_session.status_code == 403
    assert other_session.json()["error"]["code"] == "link_token_mismatch"
    other_user = http.call("POST", "/links/jira:complete", bob, body)
    assert other_user.status_code == 403
    assert http.links.resolve("jira", JIRA_ID) is None


def test_no_sso_session_means_no_link_over_http(http: _Http) -> None:
    ann = http.token("ann-sub")
    assert http.call("POST", "/links/jira:start", ann, session="").status_code == 401


def test_email_in_the_body_is_refused_over_http(http: _Http) -> None:
    ann = http.token("ann-sub")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    body = {"state": state, "code": "jira-code-ann", "email": "ann@example.test"}
    assert http.call("POST", "/links/jira:complete", ann, body).status_code == 422
    assert (
        http.call("POST", "/links/jira:complete", ann, {"email": "ann@example.test"}).status_code
        == 422
    )
    assert http.links.resolve("jira", JIRA_ID) is None


def test_unlink_over_http_is_audited_and_only_for_the_owner(http: _Http) -> None:
    ann, bob = http.token("ann-sub"), http.token("bob-sub", "reviewer")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    http.call("POST", "/links/jira:complete", ann, {"state": state, "code": "jira-code-ann"})
    path = f"/links/jira/{JIRA_ID}"
    assert http.call("DELETE", path, bob).status_code == 404
    assert http.links.resolve("jira", JIRA_ID) is not None
    assert http.call("DELETE", path, ann).status_code == 204
    assert http.links.resolve("jira", JIRA_ID) is None
    assert [e["action"] for e in audit_entries(http.store, ANN)] == ["link.created", "link.removed"]
    assert http.call("DELETE", path, ann).status_code == 404


def test_the_links_listing_is_only_my_own(http: _Http) -> None:
    ann, bob = http.token("ann-sub"), http.token("bob-sub", "reviewer")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    http.call("POST", "/links/jira:complete", ann, {"state": state, "code": "jira-code-ann"})
    assert http.call("GET", "/links", bob).json()["links"] == []


def test_the_routes_need_a_signed_in_person(http: _Http) -> None:
    assert http.call("GET", "/links", None).status_code == 401
    assert http.call("POST", "/links/jira:start", None).status_code == 401
    assert http.call("POST", "/links/gitlab:start", http.token("ann-sub")).status_code == 404


# --- review round 1 -----------------------------------------------------------------------------


def log_of(store: MemoryStore, who: UserIdentity) -> list[dict[str, Any]]:
    return audit_entries(store, who)


def test_takeover_of_an_expired_claim_is_logged_under_the_old_owner(rig: Rig) -> None:
    link_jira(rig)
    rig.clock.now += rig.links.link_ttl + 1
    rig.vendors["jira"].accounts["jira-code-bob"] = VendorAccount(JIRA_ID, None)
    started = rig.links.start(BOB, "sess-bob", "jira")
    rig.links.complete(BOB, "sess-bob", "jira", started.token, "jira-code-bob")
    old = log_of(rig.store, ANN)
    assert [e["action"] for e in old] == ["link.created", "link.removed"]
    assert old[-1]["data"]["reason"] == "replaced"
    assert old[-1]["actor"] == f"{ISS}|bob-sub"
    assert old[-1]["data"]["owner"] == f"{ISS}|ann-sub"
    assert [e["action"] for e in log_of(rig.store, BOB)] == ["link.created"]


@pytest.mark.parametrize("bad", [{"seq": "x"}, {}, {"seq": -1}, {"seq": True}, {"seq": 1.5}])
def test_a_malformed_counter_is_a_typed_refusal(rig: Rig, bad: dict[str, Any]) -> None:
    rig.store.put(PLATFORM, Key(f"USER#{ISS}|ann-sub", "LINKSEQ"), bad, when=None)
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(LinkStateError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    assert rig.links.resolve("jira", JIRA_ID) is None


class _AlwaysLosing(MemoryStore):
    """Every transaction after ``armed`` fails its condition, as under endless contention."""

    armed = False

    def transact(self, scope: Any, ops: Any) -> None:
        if self.armed:
            raise ConditionFailedError([0])
        super().transact(scope, ops)


def test_complete_gives_up_with_contention_not_a_bare_store_error() -> None:
    store = _AlwaysLosing()
    links = AccountLinking(store, vendors=make_vendors(), clock=Clock())
    started = links.start(ANN, SESSION, "jira")
    store.armed = True
    with pytest.raises(LinkContentionError):
        links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")


def test_unlink_gives_up_with_contention_not_a_bare_store_error() -> None:
    store = _AlwaysLosing()
    links = AccountLinking(store, vendors=make_vendors(), clock=Clock())
    started = links.start(ANN, SESSION, "jira")
    links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")
    store.armed = True
    with pytest.raises(LinkContentionError):
        links.unlink(ANN, "jira", JIRA_ID)
    store.armed = False
    assert links.resolve("jira", JIRA_ID) is not None


def test_contention_is_not_reported_as_a_used_token() -> None:
    assert not issubclass(LinkContentionError, LinkTokenInvalidError)


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), float("-inf"), 0, -1, 1e12])
def test_link_ttl_must_be_finite_and_bounded(ttl: float) -> None:
    with pytest.raises(ValueError, match="link_ttl"):
        AccountLinking(MemoryStore(), vendors={}, link_ttl=ttl)


def test_a_non_finite_or_boolean_time_is_not_a_time() -> None:
    from sto.identity.linking import _number

    assert _number(float("nan")) is None
    assert _number(float("inf")) is None
    assert _number(True) is None
    assert _number(5) == 5.0


def test_an_unreadable_claim_blocks_a_new_link(rig: Rig) -> None:
    rig.store.put(PLATFORM, Key("ORG", f"LINKED#jira#{JIRA_ID}"), {"issuer": 5}, when=None)
    started = rig.links.start(ANN, SESSION, "jira")
    with pytest.raises(AccountClaimedError):
        rig.links.complete(ANN, SESSION, "jira", started.token, "jira-code-ann")


@pytest.mark.parametrize(("issuer", "subject"), [("", "ann-sub"), (ISS, "")])
def test_an_empty_issuer_or_subject_never_resolves(rig: Rig, issuer: str, subject: str) -> None:
    data = {"issuer": issuer, "subject": subject, "expires_at": NOW + 1e6}
    rig.store.put(PLATFORM, Key("ORG", f"LINKED#jira#{JIRA_ID}"), data, when=None)
    assert rig.links.resolve("jira", JIRA_ID) is None


def test_a_stale_link_item_does_not_let_another_user_unlink(rig: Rig) -> None:
    link_jira(rig)
    stale = {"vendor": "jira", "account_id": JIRA_ID, "linked_at": NOW, "expires_at": NOW + 1e6}
    rig.store.put(PLATFORM, Key(f"USER#{ISS}|bob-sub", f"LINK#jira#{JIRA_ID}"), stale, when=None)
    with pytest.raises(NotLinkedError):
        rig.links.unlink(BOB, "jira", JIRA_ID)
    found = rig.links.resolve("jira", JIRA_ID)
    assert found is not None
    assert found.subject == "ann-sub"
    assert audit_entries(rig.store, BOB) == []


def test_account_claimed_and_vendor_refused_over_http(http: _Http) -> None:
    ann, bob = http.token("ann-sub"), http.token("bob-sub", "reviewer")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    http.call("POST", "/links/jira:complete", ann, {"state": state, "code": "jira-code-ann"})
    http.vendors["jira"].accounts["bobs"] = VendorAccount(JIRA_ID, None)
    state = http.call("POST", "/links/jira:start", bob, session="s-bob").json()["state"]
    claimed = http.call(
        "POST", "/links/jira:complete", bob, {"state": state, "code": "bobs"}, session="s-bob"
    )
    assert claimed.status_code == 409
    assert claimed.json()["error"]["code"] == "account_already_linked"
    refused = http.call(
        "POST", "/links/jira:complete", bob, {"state": state, "code": "nope"}, session="s-bob"
    )
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "vendor_refused"


def test_contention_and_corrupt_state_map_to_503_and_500(http: _Http) -> None:
    from sto.api.routers.links import _refusal

    assert _refusal(LinkContentionError("busy")).http_status == 503
    assert _refusal(LinkStateError("bad")).http_status == 500


def test_the_vendor_in_the_log_line_is_not_injectable(http: _Http, caplog: Any) -> None:
    ann = http.token("ann-sub")
    state = http.call("POST", "/links/jira:start", ann).json()["state"]
    caplog.set_level("INFO", logger="sto.api")
    http.vendors["jira"].accounts["x"] = VendorAccount(JIRA_ID, None)
    http.call("POST", "/links/jira:complete", ann, {"state": state, "code": "bad"})
    evil = "gitlab%0AINJECTED%20line"
    http.call("POST", f"/links/{evil}:complete", ann, {"state": state, "code": "c"})
    assert not any("\nINJECTED" in r.getMessage() for r in caplog.records)


def test_create_app_mounts_links_only_when_given_with_a_session_reader() -> None:
    from sto.api.app import create_app
    from sto.api.runtime import Runtime
    from sto.effects.core import EffectExecutor
    from sto.gates.service import GateService

    class NoSteps:
        async def execute(self, key: str, command: object) -> Any:
            raise AssertionError("no step runs here")

    class World:  # the smallest runtime create_app accepts
        def __init__(self) -> None:
            store, scope = MemoryStore(), TeamScope("alpha")
            self.runtime = Runtime(
                store,
                scope,
                gates=GateService(store),
                gate_roles=lambda gate: None,
                effects=EffectExecutor(store, scope),
                steps=NoSteps(),
                merges=lambda effect: (_ for _ in ()).throw(AssertionError("no merge")),
                live=lambda cmd: cmd.subject,
            )
            self.authz = _Http().authz

    world = World()
    links = AccountLinking(MemoryStore(), vendors=make_vendors(), clock=Clock())
    plain = create_app(world.runtime, token="", mode="prod", authorization=world.authz)
    assert not any(path.startswith("/links") for _, path in routes_of(plain))
    with pytest.raises(ValueError, match="session_of"):
        create_app(world.runtime, token="", mode="prod", authorization=world.authz, links=links)
    app = create_app(
        world.runtime,
        token="",
        mode="prod",
        authorization=world.authz,
        links=links,
        session_of=_session,
    )
    assert undeclared_routes(app) == []
    assert ("GET", "/links") in routes_of(app)
    with pytest.raises(ValueError, match="links"):
        create_app(
            world.runtime, token="", mode="prod", authorization=world.authz, session_of=_session
        )


def test_auth_declares_exactly_the_link_routes() -> None:
    for key, rule in LINK_ROUTES.items():
        assert ROUTES[key] == rule
