"""Authorization middleware (D3-03): the permission matrix, tenancy and service denial.

Every test drives the real v0 app (``create_app``) over ASGI with tokens from the fake issuer.
The matrix cases are generated from the one table in ``sto.api.auth`` (``MATRIX`` and ``ROUTES``),
and every cell of PLAN.md section 9.3 is also written out by hand below (``EXPECTED``), so a wrong
table cannot pass by agreeing with itself. Nothing here opens a real socket.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import APIRouter, FastAPI, Request, WebSocket
from starlette.endpoints import HTTPEndpoint
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Route
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sto.api.app import create_app
from sto.api.auth import (
    DOCS,
    MATRIX,
    PUBLIC,
    ROLES,
    ROUTES,
    Authorization,
    Authorized,
    Permission,
    RouteRule,
    RouteTableError,
    check_table,
    grants,
    routes_of,
    undeclared_routes,
)
from sto.api.runtime import Runtime, default_gate_roles
from sto.config.org_policy import ORG_ADMIN, Principal
from sto.domain import Gate, GateType, RunId, Subject
from sto.effects.core import EffectExecutor
from sto.engine.commands import OpenGate
from sto.gates.service import GateService
from sto.identity.fake_issuer import FakeIssuer
from sto.identity.mapping import RoleMapping
from sto.identity.oidc import OidcConfig, OidcValidator, StaticJwks
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key, TeamScope
from sto.store.sqlite import SqliteStore

ISS = "https://idp.example.test"
CLIENT = "sto-client"
NOW = 1_800_000_000.0
ALPHA, BETA = "alpha", "beta"
CUSTOM = "security_officer"
ROOT = Principal("root", frozenset({ORG_ADMIN}))
CANCEL = ("POST", "/runs/{run_id}/cancel")
TEAM_ROLES = ("developer", "reviewer", "qa", "team_admin", "auditor", CUSTOM)
REPO_ROOT = Path(__file__).resolve().parents[2]


# --- a world: issuer, validator, mapping, app ---------------------------------------------------


class _NoSteps:
    async def execute(self, key: str, command: object) -> Any:
        raise AssertionError("no step runs in a tenancy test")


def gate_roles(gate: Gate) -> frozenset[str] | None:
    """The template defaults, plus a team's own role for its custom gates."""
    return frozenset({CUSTOM}) if gate.type is GateType.CUSTOM else default_gate_roles(gate)


class World:
    def __init__(self) -> None:
        self.issuer = FakeIssuer(issuer=ISS, key_id="k1", clock=lambda: NOW)
        cfg = OidcConfig(
            issuer=ISS, audience=CLIENT, audience_claim="client_id", token_use="access"
        )
        self.validator = OidcValidator(cfg, StaticJwks(self.issuer.jwks()), clock=lambda: NOW)
        self.mapping = RoleMapping(MemoryStore(), issuers=[ISS], clock=lambda: NOW)
        for team in (ALPHA, BETA):
            self.mapping.declare_roles(ROOT, team=team, roles=[CUSTOM])
            for role in TEAM_ROLES:
                self.mapping.set_mapping(
                    ROOT, idp=ISS, group=f"{team}-{role}", team=team, role=role
                )
        self.mapping.set_mapping(ROOT, idp=ISS, group="org-admins", team=None, role=ORG_ADMIN)
        store = MemoryStore()
        self.scope = TeamScope(ALPHA)
        self.runtime = Runtime(
            store,
            self.scope,
            gates=GateService(store),
            gate_roles=gate_roles,
            effects=EffectExecutor(store, self.scope),
            steps=_NoSteps(),
            merges=lambda effect: (_ for _ in ()).throw(AssertionError("no merge")),
            live=lambda cmd: cmd.subject,
        )

    def token(
        self, sub: str, groups: list[str] | None, *, client: str = CLIENT, **extra: Any
    ) -> str:
        return self.issuer.issue(
            sub=sub,
            audience=CLIENT,
            groups=groups,
            extra={"client_id": client, "token_use": "access", **extra},
        )

    def user(self, team: str, role: str) -> str:
        return self.token(f"{team}-{role}-user", [f"{team}-{role}"])

    def authz(self, routes: dict[tuple[str, str], RouteRule] | None = None) -> Authorization:
        return Authorization(self.validator, self.mapping, routes=routes or ROUTES)

    def app(
        self, routes: dict[tuple[str, str], RouteRule] | None = None, mode: str = "prod"
    ) -> FastAPI:
        return create_app(self.runtime, token="", mode=mode, authorization=self.authz(routes))


@pytest.fixture(scope="module")
def world() -> World:
    return World()


@pytest.fixture(scope="module")
def app(world: World) -> FastAPI:
    return world.app()


def send_raw(app: FastAPI, method: str, path: str, header: str | None) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers = {} if header is None else {"Authorization": header}
            return await c.request(
                method, path, headers=headers, json={} if method == "POST" else None
            )

    return asyncio.run(asyncio.wait_for(go(), 20))


def send(app: FastAPI, method: str, path: str, token: str | None = None) -> httpx.Response:
    return send_raw(app, method, path, None if token is None else f"Bearer {token}")


def code(r: httpx.Response) -> str:
    try:
        return str(r.json()["error"]["code"])
    except (ValueError, KeyError, TypeError):
        return f"HTTP {r.status_code}: {r.text[:80]}"


def refused(r: httpx.Response, status: int, why: str, ctx: object = None) -> None:
    assert (r.status_code, code(r)) == (status, why), ctx


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


DECLARED = sorted(ROUTES.items())
ROUTE_IDS = [f"{m} {p}" for (m, p), _ in DECLARED]


# --- one table ----------------------------------------------------------------------------------


def test_every_route_of_the_real_app_declares_a_permission(world: World, app: FastAPI) -> None:
    assert undeclared_routes(app) == []
    seen = set(routes_of(app))
    assert set(ROUTES) <= seen, f"stale entries in ROUTES: {set(ROUTES) - seen}"
    assert set(ROUTES) | PUBLIC == seen  # no interactive docs outside local mode
    local = world.app(mode="local")
    assert set(ROUTES) | PUBLIC | DOCS == set(routes_of(local))
    assert undeclared_routes(local) == []


def test_a_new_route_with_no_declared_permission_is_found_and_refused(world: World) -> None:
    app = world.app()

    @app.get("/brand-new")
    async def brand_new() -> dict[str, bool]:  # pragma: no cover - never reached
        return {"reached": True}

    assert undeclared_routes(app) == [("GET", "/brand-new")]
    for who in (world.user(ALPHA, "team_admin"), world.token("org", ["org-admins"]), None):
        r = send(app, "GET", "/brand-new", who)
        refused(r, 403, "no_permission_declared", None)


def test_every_matrix_row_names_known_roles_only() -> None:
    for perm, grant in MATRIX.items():
        assert grant.anyone | grant.own <= set(ROLES), perm
        assert not grant.anyone & grant.own, f"{perm}: a role is both any and own"


# PLAN.md 9.3, every cell: developer, reviewer, qa, team_admin, org_admin, auditor.
# "any" is a plain yes, "own" is a yes for the user's own runs only, None is a no.
_ANY, _OWN, _NO = "any", "own", None
COLUMNS = ("developer", "reviewer", "qa", "team_admin", "org_admin", "auditor")
EXPECTED: dict[Permission, tuple[str | None, ...]] = {
    Permission.VIEW_RUNS: (_ANY, _ANY, _ANY, _ANY, _ANY, _ANY),
    Permission.START_RUN: (_ANY, _ANY, _ANY, _ANY, _ANY, _NO),
    Permission.CANCEL_RUN: (_OWN, _OWN, _OWN, _ANY, _ANY, _NO),
    Permission.STOP_AT_GATE: (_NO, _ANY, _ANY, _ANY, _ANY, _NO),
    Permission.DECIDE_GATE: (_ANY, _ANY, _ANY, _ANY, _ANY, _NO),
    Permission.PUBLISH_WORKFLOW: (_NO, _NO, _NO, _ANY, _ANY, _NO),
    Permission.RETRY_RUN: (_OWN, _OWN, _OWN, _ANY, _ANY, _NO),
    Permission.ATTRIBUTE_COMMIT: (_NO, _NO, _NO, _ANY, _ANY, _NO),
    Permission.EXTEND_ELIGIBILITY: (_NO, _NO, _NO, _NO, _ANY, _NO),
    Permission.SET_FLOORS: (_NO, _NO, _NO, _NO, _ANY, _NO),
    Permission.READ_AUDIT: (_NO, _NO, _NO, _ANY, _ANY, _ANY),
}
# A team's own gate role (security_officer...) is not a PLAN column: it may view, stop at a gate
# and decide, which is what gate work needs, and administer nothing.
CUSTOM_EXPECTED: dict[Permission, str | None] = {
    p: (
        _ANY
        if p in (Permission.VIEW_RUNS, Permission.STOP_AT_GATE, Permission.DECIDE_GATE)
        else _NO
    )
    for p in Permission
}


def expected(perm: Permission, role: str) -> str | None:
    if role in COLUMNS:
        return EXPECTED[perm][COLUMNS.index(role)]
    return CUSTOM_EXPECTED[perm]


def expect_in(rule: RouteRule, role: str) -> bool:
    """Whether ``role`` gets past the middleware on a route, from the hand-written table alone."""
    for perm in (rule.permission, *rule.also):
        how = expected(perm, role)
        if how is None:
            continue
        if perm is Permission.STOP_AT_GATE:
            if rule.checks_gate:
                return True
        elif how == _OWN:
            if rule.checks_own:
                return True
        else:
            return True
    return False


def test_the_hand_written_table_covers_every_permission_and_role() -> None:
    assert set(EXPECTED) == set(Permission) == set(MATRIX)
    assert set(COLUMNS) == set(ROLES)


@pytest.mark.parametrize("perm", list(Permission))
@pytest.mark.parametrize("role", [*COLUMNS, CUSTOM])
def test_every_cell_of_the_matrix_matches_the_plan(perm: Permission, role: str) -> None:
    assert grants(perm, role) == expected(perm, role), (perm, role)


def test_a_name_that_is_no_role_holds_nothing() -> None:
    for perm in Permission:
        assert grants(perm, "") is None


@pytest.mark.parametrize(("key", "rule"), DECLARED, ids=ROUTE_IDS)
@pytest.mark.parametrize("role", [*TEAM_ROLES, ORG_ADMIN])
def test_matrix_per_route_and_role(
    world: World, app: FastAPI, key: tuple[str, str], rule: RouteRule, role: str
) -> None:
    method, path = key
    token = world.token("org", ["org-admins"]) if role == ORG_ADMIN else world.user(ALPHA, role)
    r = send(app, method, concrete(path), token)
    if expect_in(rule, role):
        assert r.status_code not in (401, 403), f"{role} on {key}: {code(r)}"
    else:
        refused(r, 403, "forbidden", f"{role} on {key}: {code(r)}")


# --- cross-team ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("key", "rule"), DECLARED, ids=ROUTE_IDS)
@pytest.mark.parametrize("role", TEAM_ROLES)
def test_cross_team_access_is_refused_on_every_route(
    world: World, app: FastAPI, key: tuple[str, str], rule: RouteRule, role: str
) -> None:
    method, path = key
    r = send(app, method, concrete(path), world.user(BETA, role))  # the app serves team alpha
    refused(r, 403, "forbidden", f"{role}@beta on {key}: {code(r)}")


def test_roles_do_not_add_up_across_teams(world: World, app: FastAPI) -> None:
    """A developer in alpha who is team_admin in beta has only developer rights in alpha."""
    both = world.token("mixed", [f"{ALPHA}-developer", f"{BETA}-team_admin"])
    publish = next(k for k, v in ROUTES.items() if v.permission is Permission.START_RUN)
    assert send(app, publish[0], concrete(publish[1]), both).status_code not in (401, 403)
    # Whatever beta's admin may do, alpha only sees a developer.
    for (method, path), rule in ROUTES.items():
        ok = expect_in(rule, "developer")
        r = send(app, method, concrete(path), both)
        assert (r.status_code not in (401, 403)) is ok, (method, path, code(r))


def test_org_admin_is_org_wide_by_the_matrix(world: World, app: FastAPI) -> None:
    token = world.token("org", ["org-admins"])
    for (method, path), rule in ROUTES.items():
        ok = expect_in(rule, ORG_ADMIN)
        assert (send(app, method, concrete(path), token).status_code not in (401, 403)) is ok


def test_a_team_group_cannot_carry_org_admin_so_no_team_user_is_org_wide(world: World) -> None:
    from sto.identity.mapping import InvalidMappingError

    with pytest.raises(InvalidMappingError):
        world.mapping.set_mapping(ROOT, idp=ISS, group="sneaky", team=ALPHA, role=ORG_ADMIN)


# --- authentication and resolution on every request --------------------------------------------


def test_no_token_or_a_bad_token_is_401_with_no_detail(world: World, app: FastAPI) -> None:
    expired = world.issuer.issue(
        sub="u", audience=CLIENT, groups=[f"{ALPHA}-developer"], expires_in=-3600,
        extra={"client_id": CLIENT, "token_use": "access"},
    )  # fmt: skip
    wrong_aud = world.issuer.issue(
        sub="u", audience="someone-else", groups=[f"{ALPHA}-developer"],
        extra={"client_id": "someone-else", "token_use": "access"},
    )  # fmt: skip
    for key in ROUTES:
        for bad in (None, "", "garbage", "a.b.c", expired, wrong_aud):
            r = send(app, key[0], concrete(key[1]), bad)
            refused(r, 401, "unauthorized", (key, bad))
            assert r.headers["www-authenticate"] == "Bearer"
            assert "signature" not in r.text
            assert "expired" not in r.text


def test_the_authorization_header_must_be_exactly_a_bearer_token(
    world: World, app: FastAPI
) -> None:
    tok = world.user(ALPHA, "developer")
    for scheme in ("Bearer", "bearer", "BEARER", "bEaReR"):  # RFC 7235: the scheme is case-blind
        assert send_raw(app, "GET", "/runs", f"{scheme} {tok}").status_code == 200, scheme
    for bad in (
        "Basic Zm9vOmJhcg==",
        f"Bearerx {tok}",
        f"xBearer {tok}",
        f"Bearer {tok} extra",
        f"Bearer {tok}\tx",
        f"Bearer  {tok}",
        f" Bearer {tok}",
        f"Bearer {tok} ",
        "Bearer",
        tok,
    ):
        refused(send_raw(app, "GET", "/runs", bad), 401, "unauthorized", bad[:20])


def test_an_unmapped_user_has_no_access(world: World, app: FastAPI) -> None:
    for groups in ([], ["random-group"], None):
        r = send(app, "GET", "/runs", world.token("nobody", groups))
        refused(r, 403, "no_access", None)


def test_a_changed_mapping_and_a_disable_apply_on_the_next_request(world: World) -> None:
    app = world.app()
    m = world.mapping
    m.set_mapping(ROOT, idp=ISS, group="temp", team=ALPHA, role="developer")
    token = world.token("temp-user", ["temp"])
    assert send(app, "GET", "/runs", token).status_code == 200
    m.set_mapping(ROOT, idp=ISS, group="temp", team=BETA, role="developer")  # moved to beta
    assert code(send(app, "GET", "/runs", token)) == "forbidden"
    m.set_mapping(ROOT, idp=ISS, group="temp", team=ALPHA, role="auditor")  # back, as auditor
    assert send(app, "GET", "/runs", token).status_code == 200
    assert code(send(app, "POST", "/runs", token)) == "forbidden"
    m.remove_mapping(ROOT, idp=ISS, group="temp", team=ALPHA)
    assert code(send(app, "GET", "/runs", token)) == "no_access"
    m.set_mapping(ROOT, idp=ISS, group="temp", team=ALPHA, role="developer")
    m.disable_user(ROOT, idp=ISS, subject="temp-user")  # unexpired token, refused at once
    assert code(send(app, "GET", "/runs", token)) == "user_disabled"
    m.enable_user(ROOT, idp=ISS, subject="temp-user")
    assert send(app, "GET", "/runs", token).status_code == 200


# --- services ----------------------------------------------------------------------------------


def service_token(world: World, **kw: Any) -> str:
    return world.issuer.issue(
        sub=CLIENT, audience=CLIENT, groups=kw.pop("groups", []),
        extra={"client_id": CLIENT, "token_use": "access"},
    )  # fmt: skip


@pytest.mark.parametrize(("key", "rule"), DECLARED, ids=ROUTE_IDS)
def test_a_service_is_denied_on_every_route_unless_it_declares_one(
    world: World, app: FastAPI, key: tuple[str, str], rule: RouteRule
) -> None:
    assert not rule.service, "no v0 route declares a service permission"
    for groups in ([], [f"{ALPHA}-team_admin"], ["org-admins"]):  # groups never turn it into a user
        r = send(app, key[0], concrete(key[1]), service_token(world, groups=groups))
        refused(r, 403, "service_not_permitted", (key, groups))


def test_a_route_that_declares_a_service_permission_admits_it_with_platform_scope(
    world: World,
) -> None:
    routes = {
        **ROUTES,
        ("GET", "/who"): RouteRule(Permission.VIEW_RUNS, service=True),
        ("GET", "/who-user"): RouteRule(Permission.VIEW_RUNS),
    }
    app = world.app(routes)
    seen: dict[str, Authorized] = {}

    for path in ("/who", "/who-user"):

        async def who(request: Request, _p: str = path) -> dict[str, str]:
            auth: Authorized = request.state.auth
            seen[_p] = auth
            return {"scope": repr(auth.scope)}

        app.add_api_route(path, who, methods=["GET"])
    svc = service_token(world)
    assert send(app, "GET", "/who", svc).status_code == 200
    assert seen["/who"].scope is PLATFORM
    assert seen["/who"].identity.eligible_for_gate is False
    assert code(send(app, "GET", "/who-user", svc)) == "service_not_permitted"
    # a service reaching a route that is declared for it is still no user: a disabled one is refused
    world.mapping.disable_user(ROOT, idp=ISS, subject=CLIENT)
    try:
        assert code(send(app, "GET", "/who", svc)) == "user_disabled"
    finally:
        world.mapping.enable_user(ROOT, idp=ISS, subject=CLIENT)


# --- what a handler sees ------------------------------------------------------------------------


def with_handlers(
    world: World, routes: dict[tuple[str, str], RouteRule]
) -> tuple[FastAPI, list[Authorized]]:
    """An app whose extra routes record what the middleware handed them."""
    app = world.app({**ROUTES, **routes})
    seen: list[Authorized] = []

    async def record(request: Request) -> dict[str, bool]:
        seen.append(request.state.auth)
        return {"ok": True}

    for method, path in routes:
        app.add_api_route(path, record, methods=[method])
    return app, seen


def test_the_handler_gets_a_team_scope_and_the_user(world: World) -> None:
    app, seen = with_handlers(world, {("GET", "/me"): RouteRule(Permission.VIEW_RUNS)})
    assert send(app, "GET", "/me", world.user(ALPHA, "auditor")).status_code == 200
    (auth,) = seen
    assert auth.scope == TeamScope(ALPHA)
    assert (auth.own_only, auth.gate_only) == (False, False)
    assert auth.identity.subject == f"{ALPHA}-auditor-user"


OWN = ("POST", "/own")
GATE = ("POST", "/gate")
BOTH = ("POST", "/both")
CONDITIONAL = {
    OWN: RouteRule(Permission.CANCEL_RUN, checks_own=True),
    GATE: RouteRule(Permission.CANCEL_RUN, also=(Permission.STOP_AT_GATE,), checks_gate=True),
    BOTH: RouteRule(
        Permission.CANCEL_RUN,
        also=(Permission.STOP_AT_GATE,),
        checks_own=True,
        checks_gate=True,
    ),
}


def flags(world: World, route: tuple[str, str], *groups: str) -> tuple[int, tuple[bool, bool]]:
    app, seen = with_handlers(world, CONDITIONAL)
    r = send(app, *route, world.token("multi", list(groups)))
    return r.status_code, ((seen[0].own_only, seen[0].gate_only) if seen else (False, False))


def test_an_own_grant_admits_only_where_the_route_checks_ownership(world: World) -> None:
    """A developer may cancel their own run: that needs a handler that checks, so a route that
    declares no check refuses them, and one that declares it flags them. (The real cancel route
    declares it now: see the D3-22 tests below.)"""
    for role in ("developer", "reviewer", "qa"):
        assert flags(world, OWN, f"{ALPHA}-{role}") == (200, (True, False)), role
    undeclared = {**ROUTES, CANCEL: replace(ROUTES[CANCEL], checks_own=False, checks_gate=False)}
    refused(
        send(world.app(undeclared), "POST", "/runs/x/cancel", world.user(ALPHA, "developer")),
        403,
        "forbidden",
    )
    assert flags(world, OWN, f"{ALPHA}-auditor")[0] == 403
    assert flags(world, OWN, f"{ALPHA}-{CUSTOM}")[0] == 403  # no cancel grant at all


def test_a_stop_at_gate_grant_admits_only_where_the_route_checks_the_gate(world: World) -> None:
    """Custom gate roles stop a run only while eligible for its gate: refused on the real
    cancel route until a handler checks that, flagged where one declares it."""
    for role in ("reviewer", "qa", CUSTOM):
        assert flags(world, GATE, f"{ALPHA}-{role}") == (200, (False, True)), role
        undeclared = {
            **ROUTES,
            CANCEL: replace(ROUTES[CANCEL], checks_own=False, checks_gate=False),
        }
        real = send(world.app(undeclared), "POST", "/runs/x/cancel", world.user(ALPHA, role))
        refused(real, 403, "forbidden", role)
    # a plain developer holds only the own grant, which this route does not check
    assert flags(world, GATE, f"{ALPHA}-developer")[0] == 403
    assert flags(world, GATE, f"{ALPHA}-auditor")[0] == 403


def test_the_cancel_route_takes_cancel_or_stop_at_gate(world: World) -> None:
    """The real cancel route names both permissions: with only the gate check declared (a copy
    of the table) a gate role gets in and a plain developer does not."""
    key = ("POST", "/runs/{run_id}/cancel")
    assert ROUTES[key].also == (Permission.STOP_AT_GATE,)
    app = world.app({**ROUTES, key: replace(ROUTES[key], checks_own=False, checks_gate=True)})
    for role in ("reviewer", "qa", CUSTOM):
        assert send(app, "POST", "/runs/x/cancel", world.user(ALPHA, role)).status_code not in (
            401,
            403,
        ), role
    refused(send(app, "POST", "/runs/x/cancel", world.user(ALPHA, "developer")), 403, "forbidden")


def test_a_route_that_checks_both_flags_whichever_way_the_role_got_in(world: World) -> None:
    assert flags(world, BOTH, f"{ALPHA}-developer") == (200, (True, False))
    assert flags(world, BOTH, f"{ALPHA}-qa") == (200, (True, True))  # own, and the gate grant


def test_a_role_that_holds_the_permission_outright_is_not_flagged(world: World) -> None:
    """Admin, or any role plus an admin one, gets no flags (a user's best grant wins)."""
    for route in (OWN, GATE, BOTH):
        assert flags(world, route, f"{ALPHA}-team_admin") == (200, (False, False))
        assert flags(world, route, f"{ALPHA}-developer", f"{ALPHA}-team_admin") == (
            200,
            (False, False),
        )
        assert flags(world, route, f"{ALPHA}-team_admin", f"{ALPHA}-developer") == (
            200,
            (False, False),
        )
    # the real cancel route lets an admin through, and only an admin
    real = send(world.app(), "POST", "/runs/x/cancel", world.user(ALPHA, "team_admin"))
    assert real.status_code not in (401, 403)


def test_public_routes_need_no_token(world: World, app: FastAPI) -> None:
    for method, path in PUBLIC:
        assert send(app, method, path, None).status_code == 200, path
    local = world.app(mode="local")
    for method, path in DOCS:
        assert send(local, method, path, None).status_code == 200, path


def test_a_root_path_is_stripped_before_matching(world: World, app: FastAPI) -> None:
    async def get(path: str, token: str | None = None) -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, root_path="/api")
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers = {} if token is None else {"Authorization": f"Bearer {token}"}
            return await c.get(path, headers=headers)

    assert asyncio.run(get("/api/healthz")).status_code == 200
    assert asyncio.run(get("/api/runs")).status_code == 401
    assert asyncio.run(get("/api/runs", world.user(ALPHA, "auditor"))).status_code == 200
    assert asyncio.run(get("/api/nope")).status_code == 403


def test_the_interactive_docs_exist_only_in_local_mode(world: World) -> None:
    prod = world.app(mode="prod")
    for method, path in DOCS:
        refused(send(prod, method, path, None), 403, "no_permission_declared", path)
        refused(
            send(prod, method, path, world.user(ALPHA, "team_admin")), 403, "no_permission_declared"
        )
    assert not set(DOCS) & set(routes_of(prod))
    assert (prod.openapi_url, prod.docs_url, prod.redoc_url) == (None, None, None)


def test_the_dev_bearer_dependency_is_not_built_when_authorization_is_on(world: World) -> None:
    schema = world.app(mode="local").openapi()
    assert "securitySchemes" not in schema.get("components", {})
    for item in schema["paths"].values():
        for op in item.values():
            assert "security" not in op
    # ...and without authorization the dev token is still what it was
    dev = create_app(world.runtime, token="dev-token", mode="local")
    assert "HTTPBearer" in dev.openapi()["components"]["securitySchemes"]


def test_unknown_paths_and_methods_are_refused_alike_so_routes_cannot_be_listed(
    world: World, app: FastAPI
) -> None:
    for token in (None, world.user(ALPHA, "team_admin")):
        for method, path in (
            ("GET", "/nope"),
            ("DELETE", "/runs"),
            ("GET", "/runs/"),
            ("GET", "/runs//gates"),
            ("HEAD", "/runs"),
            ("OPTIONS", "/runs"),
            ("GET", "/RUNS"),
        ):
            r = send(app, method, path, token)
            assert r.status_code == 403, (method, path)
            if method != "HEAD":  # a HEAD response has no body
                assert code(r) == "no_permission_declared", (method, path)


# --- templates that overlap, and routes the walker must see -------------------------------------


def test_overlapping_templates_are_refused_when_the_table_is_built(world: World) -> None:
    """The router serves the first registered of two that match; the middleware cannot tell
    which, so it refuses a table where two could (a developer reached a floors handler this way)."""
    view, floors = RouteRule(Permission.VIEW_RUNS), RouteRule(Permission.SET_FLOORS)
    bad: list[dict[tuple[str, str], RouteRule]] = [
        {("POST", "/org/floors/{name}"): floors, ("POST", "/org/floors/summary"): view},
        {("GET", "/a/{x}"): view, ("GET", "/a/{y}"): view},
        {("GET", "/{a}/b"): view, ("GET", "/c/{d}"): view},
    ]
    for routes in bad:
        with pytest.raises(RouteTableError):
            world.authz(routes)
    for method_differs in (
        {("POST", "/org/floors/{name}"): floors, ("GET", "/org/floors/summary"): view},
        {("GET", "/runs/{id}"): view, ("GET", "/runs/{id}/x"): view},
    ):
        world.authz(method_differs)  # fine
    with pytest.raises(RouteTableError):  # a public route may not overlap a declared one either
        Authorization(world.validator, world.mapping, routes={("GET", "/{x}"): view}, public=PUBLIC)
    # a parameter that is only part of a segment cannot be compared for overlap, so it is refused
    partial: list[tuple[str, str]] = [
        ("/a/b{y}", "/a/bz"),
        ("/f/{name}.json", "/f/summary.json"),
        ("/g/{a}-{b}", "/g/x-y"),
        ("/org/{name}.json", "/org/floors.json"),
    ]
    for one, other in partial:
        with pytest.raises(RouteTableError):
            world.authz({("GET", one): view, ("GET", other): floors})
        with pytest.raises(RouteTableError):
            world.authz({("GET", one): view})
    for template in ("/files/{p:path}", "/x/{id:int}", "runs", "/a/{b", "/a/b}", "/a/{}"):
        with pytest.raises(RouteTableError):
            world.authz({("GET", template): view})
    check_table(ROUTES, PUBLIC | DOCS)  # the real table passes


def listed(app: FastAPI) -> list[tuple[str, str]]:
    return undeclared_routes(app)


def test_the_table_is_copied_so_a_later_change_cannot_skip_the_overlap_check(
    world: World,
) -> None:
    view = RouteRule(Permission.VIEW_RUNS)
    table = {**ROUTES, ("GET", "/x/{a}"): view}
    authz = world.authz(table)
    table[("GET", "/x/fixed")] = RouteRule(Permission.SET_FLOORS)  # would overlap
    assert ("GET", "/x/fixed") not in authz.routes
    with pytest.raises(TypeError):
        authz.routes[("GET", "/x/fixed")] = view  # type: ignore[index]
    loose: Any = {("GET", "/healthz")}  # a plain set, as a caller might pass
    assert isinstance(Authorization(world.validator, world.mapping, public=loose).public, frozenset)


def test_the_walker_lists_a_route_hidden_from_the_schema(world: World) -> None:
    app = world.app()
    router = APIRouter()

    @router.get("/hidden", include_in_schema=False)
    async def hidden() -> dict[str, bool]:
        return {}

    app.include_router(router, prefix="/pre")
    assert listed(app) == [("GET", "/pre/hidden")]
    refused(
        send(app, "GET", "/pre/hidden", world.user(ALPHA, "team_admin")),
        403,
        "no_permission_declared",
    )


def test_the_walker_lists_mounts_and_their_routes(world: World) -> None:
    app = world.app()
    sub = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @sub.get("/secret")
    async def secret() -> dict[str, int]:
        return {"x": 1}

    async def plain(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover
        raise AssertionError("never served")

    app.mount("/admin", sub)
    app.mount("/raw", plain)
    assert listed(app) == [("GET", "/admin/secret"), ("MOUNT", "/raw/*")]
    refused(
        send(app, "GET", "/admin/secret", world.user(ALPHA, "team_admin")),
        403,
        "no_permission_declared",
    )


def test_an_included_routers_websocket_is_listed(world: World) -> None:
    app = world.app()
    router = APIRouter()

    @router.websocket("/ws/{x}")
    async def sock(ws: WebSocket, x: str) -> None:  # pragma: no cover
        await ws.close()

    app.include_router(router, prefix="/pre")
    assert listed(app) == [("WEBSOCKET", "/pre/ws/{x}")]


def test_a_route_with_no_method_list_is_listed_as_any(world: World) -> None:
    class Endpoint(HTTPEndpoint):  # answers every method
        async def get(self, request: Request) -> JSONResponse:  # pragma: no cover
            return JSONResponse({})

    app = world.app()
    app.router.routes.append(Route("/endpoint", Endpoint))
    assert listed(app) == [("ANY", "/endpoint")]
    for method in ("GET", "POST", "DELETE"):
        r = send(app, method, "/endpoint", world.user(ALPHA, "team_admin"))
        refused(r, 403, "no_permission_declared", method)


def test_an_app_level_frontend_is_listed(world: World, tmp_path: Path) -> None:
    """``app.frontend()`` registers its routes as low priority, matched after the rest."""
    (tmp_path / "index.html").write_text("<p>hi</p>")
    app = world.app()
    app.frontend("/ui", directory=str(tmp_path))
    assert listed(app) != []
    r = send(app, "GET", "/ui/index.html", world.user(ALPHA, "team_admin"))
    refused(r, 403, "no_permission_declared")


def test_a_path_converter_is_listed_once_in_its_declared_form(world: World) -> None:
    app = world.app()

    @app.get("/files/{p:path}")
    async def files(p: str) -> dict[str, str]:  # pragma: no cover
        return {}

    assert listed(app) == [("GET", "/files/{p:path}")]
    assert routes_of(app).count(("GET", "/files/{p:path}")) == 1


def test_a_route_type_the_walker_does_not_know_is_listed_so_it_fails_a_test(world: World) -> None:
    class Odd(BaseRoute):
        def matches(self, scope: Any) -> Any:  # pragma: no cover
            raise AssertionError

        async def handle(self, scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover
            raise AssertionError

        def url_path_for(self, name: str, /, **path_params: Any) -> Any:  # pragma: no cover
            raise AssertionError

    app = world.app()
    app.router.routes.append(Odd())
    assert listed(app) == [("UNKNOWN", "Odd")]


# --- websockets ---------------------------------------------------------------------------------


def ws_app(world: World) -> FastAPI:
    routes = {("WEBSOCKET", "/live/{run_id}"): RouteRule(Permission.VIEW_RUNS)}
    app = world.app({**ROUTES, **routes})

    async def live(ws: WebSocket, run_id: str) -> None:
        await ws.accept()
        await ws.send_text(f"alpha data for {run_id}")
        await ws.close()

    app.add_api_websocket_route("/live/{run_id}", live)
    app.add_api_websocket_route("/undeclared/{run_id}", live)
    return app


def ws_attempt(app: FastAPI, path: str, token: str | None) -> str:
    """What a websocket client got: the first text, or ``closed <code>``. A server that neither
    accepts nor closes would hang the client, so it runs under a deadline and fails by name."""
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}

    def attempt() -> str:
        try:
            with TestClient(app).websocket_connect(path, headers=headers) as ws:
                return ws.receive_text()
        except WebSocketDisconnect as e:
            return f"closed {e.code}"

    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(attempt).result(timeout=10)
    except TimeoutError:
        raise AssertionError(f"websocket {path} was neither accepted nor closed") from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def test_websockets_are_listed_and_an_undeclared_one_is_refused(world: World) -> None:
    app = ws_app(world)
    assert ("WEBSOCKET", "/live/{run_id}") in routes_of(app)
    assert undeclared_routes(
        app, {**ROUTES, ("WEBSOCKET", "/live/{run_id}"): ROUTES[("GET", "/runs")]}
    ) == [("WEBSOCKET", "/undeclared/{run_id}")]
    for tok in (None, world.user(ALPHA, "team_admin")):
        assert ws_attempt(app, "/undeclared/x", tok) == "closed 1008"


def test_a_declared_websocket_is_authorised_like_a_request(world: World) -> None:
    app = ws_app(world)
    assert ws_attempt(app, "/live/x", world.user(ALPHA, "auditor")) == "alpha data for x"
    assert ws_attempt(app, "/live/x", None) == "closed 1008"
    assert ws_attempt(app, "/live/x", "garbage") == "closed 1008"
    assert ws_attempt(app, "/live/x", world.user(BETA, "developer")) == "closed 1008"  # other team
    assert ws_attempt(app, "/live/x", world.token("nobody", [])) == "closed 1008"
    assert (
        ws_attempt(app, "/live/x", service_token(world)) == "closed 1008"
    )  # a service, by default


# --- T9: the store side of the boundary ---------------------------------------------------------


@pytest.mark.parametrize("kind", ["mem", "sqlite"])
def test_t9_a_team_cannot_read_another_teams_rows(kind: str, tmp_path: Path) -> None:
    store = MemoryStore() if kind == "mem" else SqliteStore(tmp_path / "t.db")
    a, b = TeamScope(ALPHA), TeamScope(BETA)
    store.put(a, Key("RUN#1", "META"), {"secret": 1})
    assert store.get(b, Key("RUN#1", "META")) is None
    assert tuple(store.query(b, "RUN#1").items) == ()
    assert store.get(a, Key("RUN#1", "META")) is not None
    with pytest.raises((TypeError, AttributeError, ValueError)):
        store.get("alpha", Key("RUN#1", "META"))  # type: ignore[arg-type]  # a bare string is not a scope


# --- import boundary ----------------------------------------------------------------------------

FAKE_ISSUER = REPO_ROOT / "src/sto/identity/fake_issuer.py"


def python_files_outside_tests() -> list[Path]:
    """Every Python file of the repo (deploy/, web/, scripts/, tools/... as well as src/) that is
    not a test: what git tracks, or a walk of the tree when this is not a checkout."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.py"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        files = [REPO_ROOT / name for name in out]
    except (OSError, subprocess.CalledProcessError):
        skip = {".git", ".venv", "node_modules", "__pycache__", "cdk.out"}
        files = [
            p for p in REPO_ROOT.rglob("*.py") if not skip & set(p.relative_to(REPO_ROOT).parts)
        ]
    return [p for p in files if p.exists() and "tests" not in p.relative_to(REPO_ROOT).parts]


def test_the_scan_sees_the_whole_repository() -> None:
    names = {p.relative_to(REPO_ROOT).as_posix() for p in python_files_outside_tests()}
    assert "src/sto/api/auth.py" in names
    assert "src/sto/identity/fake_issuer.py" in names
    assert not any(n.startswith("tests/") for n in names)
    assert {n.split("/")[0] for n in names} > {"src"}


def test_nothing_outside_tests_mentions_the_fake_issuer() -> None:
    """Any name or string containing ``fake_issuer`` (an import, an importlib call, a string that
    is built later) in a non-test file other than the module itself fails."""
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in python_files_outside_tests()
        if p != FAKE_ISSUER and "fake_issuer" in p.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"only tests may use the fake issuer: {offenders}"


def test_importing_every_module_never_loads_the_fake_issuer() -> None:
    """The runtime check for what a text scan cannot see (names built from pieces)."""
    src = REPO_ROOT / "src"
    program = f"""
import importlib, pkgutil, sys
sys.path.insert(0, {str(src)!r})  # -I ignores PYTHONPATH: this checkout, explicitly
import sto
assert sto.__file__.startswith({str(src)!r}), sto.__file__
failed = []
for m in pkgutil.walk_packages(sto.__path__, "sto.", onerror=lambda n: failed.append(n)):
    if m.name == "sto.identity.fake_issuer":
        continue
    try:
        importlib.import_module(m.name)
    except ImportError as e:  # an optional dependency that is not installed
        failed.append(f"{{m.name}}: {{e}}")
assert "sto.identity.fake_issuer" not in sys.modules, "the fake issuer was imported"
assert "sto.api.auth" in sys.modules and "sto.api.app" in sys.modules, failed
"""
    done = subprocess.run(
        [sys.executable, "-I", "-c", program], capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stderr[-800:]


# --- D3-22: the cancel and decide handlers enforce the conditional grants ----------

SOD_ACTOR = f"{ISS}|"  # the actor key is issuer|subject (sto.gates.sod)


def actor_of(team: str, role: str) -> str:
    return f"{SOD_ACTOR}{team}-{role}-user"


def seed_run(world: World, *, started_by: str | None, gate: GateType | None = None) -> RunId:
    """A real run in the world's runtime, started by ``started_by``, optionally at an open gate."""
    run = asyncio.run(world.runtime.create_run("T-1", started_by=started_by))
    if gate is not None:
        subject = Subject(
            head_sha="b" * 40,
            patch_id="p1",
            ticket_revision="r1",
            evidence_digest="e1",
            attention_digest="t1",
        )
        world.runtime._gates.open_gate(world.scope, OpenGate(run.id, "g", gate, 1, subject))
    return run.id


def digest_of(world: World, run_id: RunId) -> str:
    (g,) = asyncio.run(world.runtime.gates(run_id))
    return g.subject.digest()


def post(app: FastAPI, path: str, token: str, body: dict[str, Any]) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.post(path, headers={"Authorization": f"Bearer {token}"}, json=body)

    return asyncio.run(asyncio.wait_for(go(), 20))


def test_the_real_cancel_route_declares_both_checks() -> None:
    rule = ROUTES[CANCEL]
    assert (rule.checks_own, rule.checks_gate) == (True, True)
    assert rule.also == (Permission.STOP_AT_GATE,)


def test_an_own_holder_cancels_only_a_run_they_started(world: World) -> None:
    app = world.app()
    mine = seed_run(world, started_by=actor_of(ALPHA, "developer"))
    theirs = seed_run(world, started_by=actor_of(ALPHA, "qa"))
    nobody = seed_run(world, started_by=None)
    dev = world.user(ALPHA, "developer")
    assert send(app, "POST", f"/runs/{mine}/cancel", dev).status_code == 202
    refused(send(app, "POST", f"/runs/{theirs}/cancel", dev), 403, "forbidden")
    refused(send(app, "POST", f"/runs/{nobody}/cancel", dev), 403, "forbidden")


def test_ownership_is_issuer_and_subject_not_the_subject_alone(world: World) -> None:
    app = world.app()
    other_issuer = seed_run(world, started_by="https://other.example.test|alpha-developer-user")
    refused(
        send(app, "POST", f"/runs/{other_issuer}/cancel", world.user(ALPHA, "developer")),
        403,
        "forbidden",
    )


def test_an_admin_cancels_any_run(world: World) -> None:
    run_id = seed_run(world, started_by=actor_of(ALPHA, "developer"))
    r = send(world.app(), "POST", f"/runs/{run_id}/cancel", world.user(ALPHA, "team_admin"))
    assert r.status_code == 202


def test_a_stop_at_gate_holder_cancels_only_a_run_waiting_at_a_gate_their_role_may_decide(
    world: World,
) -> None:
    app = world.app()
    at_review = seed_run(world, started_by=None, gate=GateType.REVIEW)
    at_custom = seed_run(world, started_by=None, gate=GateType.CUSTOM)
    no_gate = seed_run(world, started_by=None)
    reviewer, qa = world.user(ALPHA, "reviewer"), world.user(ALPHA, "qa")
    officer = world.user(ALPHA, CUSTOM)
    assert send(app, "POST", f"/runs/{at_review}/cancel", reviewer).status_code == 202
    assert send(app, "POST", f"/runs/{at_custom}/cancel", officer).status_code == 202
    for who, kind in (
        (qa, GateType.REVIEW),
        (reviewer, GateType.CUSTOM),
        (officer, GateType.REVIEW),
    ):
        other = seed_run(world, started_by=None, gate=kind)
        refused(send(app, "POST", f"/runs/{other}/cancel", who), 403, "forbidden")
    refused(send(app, "POST", f"/runs/{no_gate}/cancel", reviewer), 403, "forbidden")
    refused(send(app, "POST", f"/runs/{no_gate}/cancel", officer), 403, "forbidden")


def test_a_closed_gate_no_longer_lets_its_role_stop_the_run(world: World) -> None:
    app = world.app()
    run_id = seed_run(world, started_by=None, gate=GateType.REVIEW)
    d = post(
        app,
        f"/runs/{run_id}/gates/g/1/decisions",
        world.user(ALPHA, "reviewer"),
        {"kind": "approve", "subject_digest": digest_of(world, run_id)},
    )
    assert d.status_code == 202, d.text
    refused(
        send(app, "POST", f"/runs/{run_id}/cancel", world.user(ALPHA, "reviewer")), 403, "forbidden"
    )


def test_an_unknown_run_is_404_for_a_holder_the_middleware_admitted(world: World) -> None:
    r = send(world.app(), "POST", f"/runs/{RunId.new()}/cancel", world.user(ALPHA, "developer"))
    refused(r, 404, "run_not_found")


def test_a_user_holding_both_grants_may_stop_through_either(world: World) -> None:
    """A qa user holds own and stop-at-gate: their own run, or one at a gate qa may decide."""
    app = world.app()
    own = seed_run(world, started_by=actor_of(ALPHA, "qa"))
    at_qa = seed_run(world, started_by=None, gate=GateType.QA)
    neither = seed_run(world, started_by=None)
    qa = world.user(ALPHA, "qa")
    assert send(app, "POST", f"/runs/{own}/cancel", qa).status_code == 202
    assert send(app, "POST", f"/runs/{at_qa}/cancel", qa).status_code == 202
    refused(send(app, "POST", f"/runs/{neither}/cancel", qa), 403, "forbidden")


def test_decide_records_the_authenticated_actor_never_a_constant(world: World) -> None:
    app = world.app()
    for role in ("reviewer", "team_admin"):
        run_id = seed_run(world, started_by=None, gate=GateType.REVIEW)
        r = post(
            app,
            f"/runs/{run_id}/gates/g/1/decisions",
            world.user(ALPHA, role),
            {"kind": "approve", "subject_digest": digest_of(world, run_id)},
        )
        assert r.status_code == 202, r.text
        assert r.json()["gate"]["closed_by"] == actor_of(ALPHA, role)
    org = seed_run(world, started_by=None, gate=GateType.REVIEW)
    r = post(
        app,
        f"/runs/{org}/gates/g/1/decisions",
        world.token("root-user", ["org-admins"]),
        {"kind": "approve", "subject_digest": digest_of(world, org)},
    )
    assert r.json()["gate"]["closed_by"] == f"{ISS}|root-user"


def decide_twice(world: World, run_id: RunId, token: str) -> httpx.Response:
    """The second decision on a closed gate: a 409 that may offer the stop link."""
    return post(
        world.app(),
        f"/runs/{run_id}/gates/g/1/decisions",
        token,
        {"kind": "reject", "comment": "no"},
    )


def test_the_409_stop_link_is_offered_only_to_roles_that_can_use_it(world: World) -> None:
    app = world.app()
    owner_actor = actor_of(ALPHA, "developer")
    run_id = seed_run(world, started_by=owner_actor, gate=GateType.REVIEW)
    first = post(
        app,
        f"/runs/{run_id}/gates/g/1/decisions",
        world.user(ALPHA, "team_admin"),
        {"kind": "approve", "subject_digest": digest_of(world, run_id)},
    )
    assert first.status_code == 202, first.text
    # a second gate stays open for a custom gate role, so that role is offered the link too
    subject = Subject(
        head_sha="b" * 40,
        patch_id="p2",
        ticket_revision="r1",
        evidence_digest="e1",
        attention_digest="t1",
    )
    world.runtime._gates.open_gate(
        world.scope, OpenGate(run_id, "sec", GateType.CUSTOM, 1, subject)
    )
    link = {"method": "POST", "href": f"/runs/{run_id}/cancel"}
    offered = {
        "developer": link,  # the owner
        "team_admin": link,
        "qa": None,  # not the owner, and no open gate qa may decide
        "reviewer": None,
        CUSTOM: link,
    }
    for role, want in offered.items():
        r = decide_twice(world, run_id, world.user(ALPHA, role))
        assert (r.status_code, code(r)) == (409, "gate_closed"), (role, r.text)
        assert r.json()["error"].get("stop") == want, role
    # the link works for every role it was offered to (checked on separate runs: a Stop is final)
    for role, want in offered.items():
        if want is None:
            continue
        fresh = seed_run(world, started_by=actor_of(ALPHA, role), gate=GateType.REVIEW)
        post(
            app,
            f"/runs/{fresh}/gates/g/1/decisions",
            world.user(ALPHA, "team_admin"),
            {"kind": "approve", "subject_digest": digest_of(world, fresh)},
        )
        world.runtime._gates.open_gate(
            world.scope, OpenGate(fresh, "sec", GateType.CUSTOM, 1, subject)
        )
        r = decide_twice(world, fresh, world.user(ALPHA, role))
        href = r.json()["error"]["stop"]["href"]
        assert send(app, "POST", href, world.user(ALPHA, role)).status_code == 202, role
