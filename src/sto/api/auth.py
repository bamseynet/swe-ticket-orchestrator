"""Authorization middleware (PLAN 9.2 and 9.3, D3-03).

One ASGI middleware turns a bearer token into an identity, the identity into a
:class:`~sto.store.ports.TeamScope`, and enforces the permission matrix. Everything it decides
comes from two tables in this module, so the tests can generate their cases from them:

* :data:`MATRIX` is PLAN.md section 9.3: a :class:`Permission` per row, and for each the roles
  that may do it outright (``anyone``) or only on a run of their own (``own``).
* :data:`ROUTES` maps ``(METHOD, path template)`` to a :class:`RouteRule` (its permission, and
  whether a service identity may call it). :data:`PUBLIC` lists the routes that need no token.

**A route with no entry fails closed.** A request for a route that is in neither table is refused
with ``403 no_permission_declared`` before any token is read, and :func:`undeclared_routes` lists
the app's routes that are in neither (from the top-level routes and the OpenAPI paths, so a route
hidden from the schema inside an included router is only caught by the runtime refusal) so a test
fails when a route is added without a permission.

Per request, in this order: match the request against the declared path templates (this module
does its own matching, so it does not depend on how FastAPI nests included routers; a path that
matches no declared or public template, whether a missing path, a wrong method or a route nobody
declared, is refused the same way, so the middleware cannot be used to list routes); let a public
route through; read the bearer token (``401``
``unauthorized`` for a missing, malformed, expired or otherwise invalid one, and the reason is
never sent back); resolve the identity from the store *now* (D3-02: a changed mapping or a
disable applies at once; ``403`` ``no_access`` or ``user_disabled``); then

* a **service identity** is refused (``403 service_not_permitted``) unless the route declares
  ``service=True``; where it does, the scope is ``PLATFORM``, never a team's, and the handler
  must not read team data. No v0 route declares it.
* a **user** needs a role in the request's team (``team_of``; the v0 app serves one team, the
  runtime's) that the matrix grants for the route's permission. Roles are the user's in *that*
  team only, so they never add up across teams. ``org_admin`` is org-level and holds that role in
  every team (the matrix's column). Anything else is ``403 forbidden``, the same answer for
  another team's user and for a role the matrix does not grant, so it does not say which.

Custom gate roles (``security_officer``...) are declared per team (D3-02). They are admitted to
the rows that gate work needs (view runs, stop at a gate, decide a gate); whether they may decide
*this* gate is the gate's ``eligible_roles`` and separation of duties (D3-05), not this module.

A handler reads the result from ``request.state.auth`` (:class:`Authorized`): the identity, the
scope, and ``own_only``, true when the role only qualifies for the user's *own* runs (the
matrix's "Own"). The middleware cannot know a run's owner, so the handler must apply that.

Not wired into ``create_app`` here (its dev-token check is D1-08 and stays until the real app is
assembled): :func:`install_authorization` adds the middleware to any app. Unverified until D12:
the middleware against a real Cognito token and a real group list.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from sto.config.org_policy import ORG_ADMIN
from sto.identity.mapping import (
    NoAccessError,
    RoleMapping,
    ServiceIdentity,
    UserDisabledError,
    UserIdentity,
)
from sto.identity.oidc import InvalidTokenError, OidcValidator
from sto.store.ports import PLATFORM, PlatformScope, TeamScope

__all__ = [
    "MATRIX",
    "PUBLIC",
    "ROLES",
    "ROUTES",
    "Authorization",
    "Authorized",
    "Grant",
    "Permission",
    "RouteRule",
    "grants",
    "install_authorization",
    "routes_of",
    "undeclared_routes",
]

log = logging.getLogger("sto.api.auth")

ROLES = ("developer", "reviewer", "qa", "team_admin", ORG_ADMIN, "auditor")
_BUILTIN = frozenset(ROLES)
_HUMANS = frozenset({"developer", "reviewer", "qa"})
_ADMINS = frozenset({"team_admin", ORG_ADMIN})


class Permission(StrEnum):
    """The rows of PLAN.md section 9.3."""

    VIEW_RUNS = "view_runs"
    START_RUN = "start_run"  # start and answer; cancelling is its own row
    CANCEL_RUN = "cancel_run"  # own run, or any run for an admin
    STOP_AT_GATE = "stop_at_gate"  # stop a run while eligible for its open or just-approved gate
    DECIDE_GATE = "decide_gate"  # the gate's eligible_roles is the real authority (D3-05)
    PUBLISH_WORKFLOW = "publish_workflow"  # also: map team groups, set a team budget
    RETRY_RUN = "retry_run"  # retry a blocked run, raise a run budget
    ATTRIBUTE_COMMIT = "attribute_commit"  # also: resolve a SoD term
    EXTEND_ELIGIBILITY = "extend_eligibility"
    SET_FLOORS = "set_floors"  # also: org budgets, kill switch
    READ_AUDIT = "read_audit"  # the export scope (team, org) is the handler's


@dataclass(frozen=True)
class Grant:
    """Who may do a permission. ``own`` roles only on a run of their own. ``custom`` admits a
    role the team declared itself (not one of :data:`ROLES`)."""

    anyone: frozenset[str]
    own: frozenset[str] = frozenset()
    custom: bool = False


MATRIX: dict[Permission, Grant] = {
    Permission.VIEW_RUNS: Grant(frozenset(ROLES), custom=True),
    Permission.START_RUN: Grant(_HUMANS | _ADMINS),
    Permission.CANCEL_RUN: Grant(_ADMINS, own=_HUMANS),
    Permission.STOP_AT_GATE: Grant(frozenset({"reviewer", "qa"}) | _ADMINS, custom=True),
    Permission.DECIDE_GATE: Grant(_HUMANS | _ADMINS, custom=True),
    Permission.PUBLISH_WORKFLOW: Grant(_ADMINS),
    Permission.RETRY_RUN: Grant(_ADMINS, own=_HUMANS),
    Permission.ATTRIBUTE_COMMIT: Grant(_ADMINS),
    Permission.EXTEND_ELIGIBILITY: Grant(frozenset({ORG_ADMIN})),
    Permission.SET_FLOORS: Grant(frozenset({ORG_ADMIN})),
    Permission.READ_AUDIT: Grant(frozenset({"team_admin", ORG_ADMIN, "auditor"})),
}


def grants(permission: Permission, role: str) -> Literal["any", "own"] | None:
    """How ``role`` holds ``permission``: ``"any"``, ``"own"`` (own runs only) or ``None``."""
    grant = MATRIX[permission]
    if role in grant.anyone:
        return "any"
    if role in grant.own:
        return "own"
    if grant.custom and role and role not in _BUILTIN:
        return "any"
    return None


@dataclass(frozen=True)
class RouteRule:
    permission: Permission
    service: bool = False  # a service identity may call it (denied unless declared)


ROUTES: dict[tuple[str, str], RouteRule] = {
    ("GET", "/runs"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs"): RouteRule(Permission.START_RUN),
    ("GET", "/runs/{run_id}"): RouteRule(Permission.VIEW_RUNS),
    ("GET", "/runs/{run_id}/events"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs/{run_id}/cancel"): RouteRule(Permission.CANCEL_RUN),
    ("GET", "/runs/{run_id}/gates"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs/{run_id}/gates/{name}/{round}/decisions"): RouteRule(Permission.DECIDE_GATE),
}

PUBLIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/healthz"),
        ("GET", "/openapi.json"),
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/redoc"),
    }
)


@dataclass(frozen=True)
class Authorized:
    """What a handler gets in ``request.state.auth``."""

    identity: UserIdentity | ServiceIdentity
    scope: TeamScope | PlatformScope  # ``PLATFORM`` for a service
    own_only: bool = False


TeamOf = Callable[[Request], str | None]


def runtime_team(request: Request) -> str | None:
    """The v0 app serves one team: the runtime's."""
    runtime = getattr(request.app.state, "runtime", None)
    scope = getattr(runtime, "scope", None)
    team = getattr(scope, "team", None)
    return team if isinstance(team, str) and team else None


@dataclass(frozen=True)
class Authorization:
    validator: OidcValidator
    mapping: RoleMapping
    routes: Mapping[tuple[str, str], RouteRule] = field(default_factory=lambda: ROUTES)
    public: frozenset[tuple[str, str]] = PUBLIC
    team_of: TeamOf = runtime_team


def routes_of(app: FastAPI) -> list[tuple[str, str]]:
    """Every ``(method, path template)`` the app serves: its top-level routes plus the OpenAPI
    paths (which see through included routers)."""
    found: set[tuple[str, str]] = set()
    for r in app.routes:
        if isinstance(r, APIRoute | Route):
            found |= {(m, r.path) for m in (r.methods or ()) if m != "HEAD"}
    app.openapi_schema = None  # never a stale schema: a route may have been added since
    for path, item in app.openapi().get("paths", {}).items():
        found |= {(m.upper(), path) for m in item if m.upper() in _HTTP_METHODS}
    return sorted(found)


def undeclared_routes(
    app: FastAPI,
    routes: Mapping[tuple[str, str], RouteRule] = ROUTES,
    public: frozenset[tuple[str, str]] = PUBLIC,
) -> list[tuple[str, str]]:
    """Every ``(method, path)`` of the app that is neither declared nor public."""
    return [k for k in routes_of(app) if k not in routes and k not in public]


_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"})
_BEARER = re.compile(r"Bearer ([^\s]+)", re.ASCII)


@functools.cache
def _compile(template: str) -> re.Pattern[str]:
    """``/runs/{run_id}`` becomes a pattern with one named, non-empty, slash-free group."""
    out = ""
    for part in re.split(r"(\{[A-Za-z_][A-Za-z0-9_]*\})", template):
        out += f"(?P<{part[1:-1]}>[^/]+)" if part.startswith("{") else re.escape(part)
    return re.compile(out)


def _refuse(status: int, code: str, message: str, *, www: bool = False) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if www else None
    body = {"error": {"code": code, "message": message}}
    return JSONResponse(body, status_code=status, headers=headers)


class AuthorizationMiddleware:
    def __init__(self, app: ASGIApp, authorization: Authorization) -> None:
        self.app, self.authz = app, authorization

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response = await self._check(scope)
        if response is not None:
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _match(self, scope: Scope) -> tuple[tuple[str, str], dict[str, str]] | None:
        """The declared ``(method, template)`` this request is for, and its path parameters.
        The most specific template wins (fewest parameters): a fixed path beats a captured one."""
        path = scope["path"]
        root = scope.get("root_path") or ""
        if root and path.startswith(root):
            path = path[len(root) :]
        method = scope["method"]
        best: tuple[int, tuple[str, str], dict[str, str]] | None = None
        for m, template in (*self.authz.routes, *self.authz.public):
            if m != method:
                continue
            found = _compile(template).fullmatch(path)
            if found is None:
                continue
            rank = template.count("{")
            if best is None or rank < best[0]:
                best = (rank, (m, template), found.groupdict())
        return None if best is None else (best[1], best[2])

    async def _check(self, scope: Scope) -> JSONResponse | None:
        matched = self._match(scope)
        if matched is None:
            return _refuse(403, "no_permission_declared", "this route has no declared permission")
        key, params = matched
        if key in self.authz.public:
            return None
        rule = self.authz.routes[key]
        request = Request({**scope, "path_params": params})
        header = request.headers.get("authorization", "")
        found = _BEARER.fullmatch(header)
        if found is None:
            return _refuse(401, "unauthorized", "a bearer token is required", www=True)
        try:
            token = await asyncio.to_thread(self.authz.validator.validate, found.group(1))
        except InvalidTokenError as e:
            log.info("token refused on %s %s: %s", *key, e.reason)
            return _refuse(401, "unauthorized", "the token is not valid", www=True)
        try:
            identity = await asyncio.to_thread(self.authz.mapping.resolve, token)
        except UserDisabledError:
            return _refuse(403, "user_disabled", "this identity is disabled")
        except NoAccessError:
            return _refuse(403, "no_access", "this identity has no access")
        if isinstance(identity, ServiceIdentity):
            if not rule.service:
                return _refuse(403, "service_not_permitted", "services may not call this route")
            self._set(scope, Authorized(identity, PLATFORM))
            return None
        team = self.authz.team_of(request)
        if team is None:
            return _refuse(403, "forbidden", "this request is not allowed")
        roles = set(identity.roles_in(team))
        if (None, ORG_ADMIN) in identity.memberships:
            roles.add(ORG_ADMIN)
        held = {grants(rule.permission, r) for r in roles} - {None}
        if not held:
            return _refuse(403, "forbidden", "this request is not allowed")
        self._set(scope, Authorized(identity, TeamScope(team), own_only="any" not in held))
        return None

    @staticmethod
    def _set(scope: Scope, auth: Authorized) -> None:
        state: dict[str, Any] = scope.setdefault("state", {})
        state["auth"] = auth


def install_authorization(app: FastAPI, authorization: Authorization) -> None:
    """Add the middleware. Call before the app starts."""
    app.add_middleware(AuthorizationMiddleware, authorization=authorization)
