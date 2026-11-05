"""Authorization middleware (D3-03): the permission matrix, tenancy and service denial.

Every test drives the real v0 app (``create_app``) over ASGI with tokens from the fake issuer.
The matrix cases are generated from the one table in ``sto.api.auth`` (``MATRIX`` and ``ROUTES``),
and a few cells are also written out by hand from PLAN.md section 9.3, so a wrong table cannot
pass by agreeing with itself. Nothing here opens a socket.
"""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request

from sto.api.app import create_app
from sto.api.auth import (
    MATRIX,
    PUBLIC,
    ROLES,
    ROUTES,
    Authorization,
    Authorized,
    Permission,
    RouteRule,
    grants,
    routes_of,
    undeclared_routes,
)
from sto.api.runtime import Runtime
from sto.config.org_policy import ORG_ADMIN, Principal
from sto.effects.core import EffectExecutor
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
TEAM_ROLES = ("developer", "reviewer", "qa", "team_admin", "auditor", CUSTOM)
REPO_ROOT = Path(__file__).resolve().parents[2]


# --- a world: issuer, validator, mapping, app ---------------------------------------------------


class _NoSteps:
    async def execute(self, key: str, command: object) -> Any:
        raise AssertionError("no step runs in a tenancy test")


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

    def app(self, routes: dict[tuple[str, str], RouteRule] | None = None) -> FastAPI:
        authz = Authorization(self.validator, self.mapping, routes=routes or ROUTES)
        return create_app(self.runtime, token="", mode="prod", authorization=authz)


@pytest.fixture(scope="module")
def world() -> World:
    return World()


@pytest.fixture(scope="module")
def app(world: World) -> FastAPI:
    return world.app()


def send(app: FastAPI, method: str, path: str, token: str | None = None) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
            return await c.request(
                method, path, headers=headers, json={} if method == "POST" else None
            )

    return asyncio.run(asyncio.wait_for(go(), 20))


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


def test_every_route_of_the_real_app_declares_a_permission(app: FastAPI) -> None:
    assert undeclared_routes(app) == []
    seen = set(routes_of(app))
    assert set(ROUTES) <= seen, f"stale entries in ROUTES: {set(ROUTES) - seen}"
    assert set(ROUTES) | PUBLIC == seen


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


@pytest.mark.parametrize(("key", "rule"), DECLARED, ids=ROUTE_IDS)
@pytest.mark.parametrize("role", [*TEAM_ROLES, ORG_ADMIN])
def test_matrix_per_route_and_role(
    world: World, app: FastAPI, key: tuple[str, str], rule: RouteRule, role: str
) -> None:
    method, path = key
    token = world.token("org", ["org-admins"]) if role == ORG_ADMIN else world.user(ALPHA, role)
    r = send(app, method, concrete(path), token)
    if grants(rule.permission, role) is not None:
        assert r.status_code not in (401, 403), f"{role} on {key}: {code(r)}"
    else:
        refused(r, 403, "forbidden", f"{role} on {key}: {code(r)}")


# Written out by hand from PLAN.md 9.3 (the table above is not trusted to check itself).
@pytest.mark.parametrize(
    ("perm", "role", "ok"),
    [
        (Permission.VIEW_RUNS, "auditor", True),
        (Permission.START_RUN, "auditor", False),
        (Permission.START_RUN, "developer", True),
        (Permission.CANCEL_RUN, "developer", True),  # own only, flagged separately
        (Permission.CANCEL_RUN, "auditor", False),
        (Permission.PUBLISH_WORKFLOW, "developer", False),
        (Permission.PUBLISH_WORKFLOW, "team_admin", True),
        (Permission.EXTEND_ELIGIBILITY, "team_admin", False),
        (Permission.EXTEND_ELIGIBILITY, "org_admin", True),
        (Permission.SET_FLOORS, "team_admin", False),
        (Permission.SET_FLOORS, "org_admin", True),
        (Permission.DECIDE_GATE, "auditor", False),
        (Permission.DECIDE_GATE, "reviewer", True),
        (Permission.STOP_AT_GATE, "developer", False),
        (Permission.STOP_AT_GATE, "qa", True),
        (Permission.READ_AUDIT, "auditor", True),
        (Permission.READ_AUDIT, "developer", False),
    ],
)
def test_matrix_cells_from_the_plan(perm: Permission, role: str, ok: bool) -> None:
    assert (grants(perm, role) is not None) is ok


def test_custom_gate_roles_may_view_and_decide_but_not_administer() -> None:
    assert grants(Permission.DECIDE_GATE, CUSTOM) == "any"
    assert grants(Permission.VIEW_RUNS, CUSTOM) == "any"
    assert grants(Permission.PUBLISH_WORKFLOW, CUSTOM) is None
    assert grants(Permission.START_RUN, CUSTOM) is None
    assert grants(Permission.DECIDE_GATE, "") is None


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
        ok = grants(rule.permission, "developer") is not None
        r = send(app, method, concrete(path), both)
        assert (r.status_code not in (401, 403)) is ok, (method, path, code(r))


def test_org_admin_is_org_wide_by_the_matrix(world: World, app: FastAPI) -> None:
    token = world.token("org", ["org-admins"])
    for (method, path), rule in ROUTES.items():
        ok = grants(rule.permission, ORG_ADMIN) is not None
        assert (send(app, method, concrete(path), token).status_code not in (401, 403)) is ok


def test_a_team_group_cannot_carry_org_admin_so_no_team_user_is_org_wide(world: World) -> None:
    from sto.config.org_policy import PermissionDeniedError  # noqa: F401
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


def test_a_non_bearer_scheme_is_401(app: FastAPI) -> None:
    async def go() -> int:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (
                await c.get("/runs", headers={"Authorization": "Basic Zm9vOmJhcg=="})
            ).status_code

    assert asyncio.run(go()) == 401


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


def test_the_handler_gets_a_team_scope_and_the_own_only_flag(world: World) -> None:
    routes = {
        **ROUTES,
        ("GET", "/me"): RouteRule(Permission.CANCEL_RUN),
    }
    app = world.app(routes)
    seen: list[Authorized] = []

    async def me(request: Request) -> dict[str, bool]:
        seen.append(request.state.auth)
        return {"ok": True}

    app.add_api_route("/me", me, methods=["GET"])
    assert send(app, "GET", "/me", world.user(ALPHA, "developer")).status_code == 200
    assert send(app, "GET", "/me", world.user(ALPHA, "team_admin")).status_code == 200
    assert send(app, "GET", "/me", world.user(ALPHA, "auditor")).status_code == 403
    dev, admin = seen
    assert (dev.scope, dev.own_only) == (TeamScope(ALPHA), True)
    assert (admin.scope, admin.own_only) == (TeamScope(ALPHA), False)
    assert dev.identity.subject == f"{ALPHA}-developer-user"


def test_public_routes_need_no_token(app: FastAPI) -> None:
    for method, path in PUBLIC:
        assert send(app, method, path, None).status_code == 200, path


def test_unknown_paths_and_methods_are_refused_alike_so_routes_cannot_be_listed(
    world: World, app: FastAPI
) -> None:
    for token in (None, world.user(ALPHA, "team_admin")):
        for method, path in (
            ("GET", "/nope"),
            ("DELETE", "/runs"),
            ("GET", "/runs/"),
            ("GET", "/runs//gates"),
        ):
            r = send(app, method, path, token)
            refused(r, 403, "no_permission_declared", (method, path))


def test_a_fixed_path_beats_a_captured_one(world: World) -> None:
    routes = {
        **ROUTES,
        ("GET", "/runs/export"): RouteRule(Permission.READ_AUDIT),
    }
    app = world.app(routes)

    async def export() -> dict[str, bool]:
        return {"ok": True}

    app.add_api_route("/runs/export", export, methods=["GET"])
    assert send(app, "GET", "/runs/export", world.user(ALPHA, "developer")).status_code == 403
    # (the auditor passes: the 404 is FastAPI serving the earlier "/runs/{run_id}" route)
    assert send(app, "GET", "/runs/export", world.user(ALPHA, "auditor")).status_code not in (
        401,
        403,
    )
    assert send(app, "GET", "/runs/other", world.user(ALPHA, "developer")).status_code != 403


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


def _imports_fake_issuer(tree: ast.AST) -> bool:
    target = "sto.identity.fake_issuer"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name == target for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == target:
                return True
            if mod == "sto.identity" and any(a.name == "fake_issuer" for a in node.names):
                return True
            if node.level and (
                mod.endswith("fake_issuer") or any(a.name == "fake_issuer" for a in node.names)
            ):
                return True
        if isinstance(node, ast.Constant) and node.value == target:  # importlib.import_module(...)
            return True
    return False


def test_the_boundary_check_itself_catches_each_way_in() -> None:
    for src in (
        "import sto.identity.fake_issuer",
        "from sto.identity.fake_issuer import FakeIssuer",
        "from sto.identity import fake_issuer",
        "from .fake_issuer import FakeIssuer",
        "from . import fake_issuer",
        "import importlib; importlib.import_module('sto.identity.fake_issuer')",
    ):
        assert _imports_fake_issuer(ast.parse(src)), src
    assert not _imports_fake_issuer(ast.parse("from sto.identity.oidc import OidcValidator"))


def test_nothing_outside_tests_imports_the_fake_issuer() -> None:
    offenders: list[str] = []
    for base in ("src", "scripts", "tools", "infra"):
        for path in (REPO_ROOT / base).rglob("*.py") if (REPO_ROOT / base).exists() else []:
            if path == REPO_ROOT / "src/sto/identity/fake_issuer.py":
                continue
            if _imports_fake_issuer(ast.parse(path.read_text(encoding="utf-8"))):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == [], f"only tests may import the fake issuer: {offenders}"
