"""Authorization middleware (PLAN 9.2 and 9.3, D3-03).

One ASGI middleware turns a bearer token into an identity, the identity into a
:class:`~sto.store.ports.TeamScope`, and enforces the permission matrix. Everything it decides
comes from two tables in this module, so the tests can generate their cases from them:

* :data:`MATRIX` is PLAN.md section 9.3: a :class:`Permission` per row, and for each the roles
  that may do it outright (``anyone``) or only on a run of their own (``own``).
* :data:`ROUTES` maps ``(METHOD, path template)`` to a :class:`RouteRule` (its permissions, and
  whether a service identity may call it). Websockets use the method ``WEBSOCKET``.
  :data:`PUBLIC` lists the routes that need no token (``/healthz``); :data:`DOCS` the interactive
  documentation, public only in local mode (``create_app`` disables it otherwise).

**A route with no entry fails closed.** A request (or websocket) for a route that is in neither
table is refused (``403 no_permission_declared``; a websocket is closed with code 1008) before
any token is read. :func:`undeclared_routes` walks the app's router tree (included routers,
mounts, websocket routes, hidden routes) and lists what is in neither table, so a test fails when
a route is added without a permission. A route type it does not understand is listed as
``("UNKNOWN", type)``, so it fails too.

Templates are matched by this module, not the router, so no pair of declared templates may
overlap for one method (``/org/{name}`` and ``/org/summary``): the router serves whichever was
registered first and the two could disagree on the permission. :class:`Authorization` refuses
such a table when it is built, and a template whose parameter is not a whole segment
(``/f/{name}.json``) or has a converter (``{p:path}``), which the overlap check cannot compare.
The table is copied and frozen at that point. A route with no method list (an ``HTTPEndpoint``)
is listed as ``ANY``, which cannot be declared, so it is always refused.

Per request, in this order: match the request against the declared templates (a path that
matches none, whether a missing path, a wrong method or a route nobody declared, is refused the
same way, so the middleware cannot be used to list routes); let a public route through; read the
bearer token (``401 unauthorized`` for a missing, malformed, expired or otherwise invalid one,
and the reason is never sent back); resolve the identity from the store *now* (D3-02: a changed
mapping or a disable applies at once; ``403`` ``no_access`` or ``user_disabled``); then

* a **service identity** is refused (``403 service_not_permitted``) unless the route declares
  ``service=True``; where it does, the scope is ``PLATFORM``, never a team's, and the handler
  must not read team data. No v0 route declares it.
* a **user** needs a role in the request's team (``team_of``; the v0 app serves one team, the
  runtime's) that the matrix grants for one of the route's permissions. Roles are the user's in
  *that* team only, so they never add up across teams. ``org_admin`` is org-level and holds that
  role in every team (the matrix's column). Anything else is ``403 forbidden``, the same answer
  for another team's user and for a role the matrix does not grant, so it does not say which.

**Conditional grants fail closed.** Two kinds of grant depend on something only a handler can
see. An "own" grant (a developer cancelling *their own* run) and a ``STOP_AT_GATE`` grant (stop
a run while eligible for its open gate) admit a request only on a route whose rule declares
``checks_own`` or ``checks_gate``: a promise that the handler checks it, which the handler
reads as ``own_only`` and ``gate_only`` on :class:`Authorized`. Only the cancel route declares
them (D3-22), and its handler applies :func:`may_stop`; the decide handler records
:func:`actor_key` (``issuer|subject``, as separation of duties keys actors), and offers the 409's
stop link only to a caller who passes the same check.

Custom gate roles (``security_officer``...) are declared per team (D3-02). They are admitted to
the rows that gate work needs (view runs, stop at a gate, decide a gate); whether they may decide
*this* gate is the gate's ``eligible_roles`` and separation of duties (D3-05), not this module.

A handler reads the result from ``request.state.auth`` (:class:`Authorized`).
``create_app(..., authorization=...)`` installs this middleware in place of the dev token.
Unverified until D12: the middleware against a real Cognito token and a real group list.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal

from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
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
    "DOCS",
    "PUBLIC",
    "ROLES",
    "ROUTES",
    "Authorization",
    "Authorized",
    "Grant",
    "Permission",
    "RouteRule",
    "RouteTableError",
    "actor_key",
    "grants",
    "install_authorization",
    "may_stop",
    "routes_of",
    "stop_flags",
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
    """What a route needs. A role qualifies through ``permission`` or any of ``also``.

    ``checks_own`` and ``checks_gate`` are promises that the handler applies the condition behind
    an "own" or a ``STOP_AT_GATE`` grant (see the module docstring); without them those grants
    do not admit.
    """

    permission: Permission
    also: tuple[Permission, ...] = ()
    service: bool = False  # a service identity may call it (denied unless declared)
    checks_own: bool = False
    checks_gate: bool = False


WEBSOCKET = "WEBSOCKET"
STOP_ROUTE = ("POST", "/runs/{run_id}/cancel")

ROUTES: dict[tuple[str, str], RouteRule] = {
    ("GET", "/runs"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs"): RouteRule(Permission.START_RUN),
    ("GET", "/runs/{run_id}"): RouteRule(Permission.VIEW_RUNS),
    ("GET", "/runs/{run_id}/events"): RouteRule(Permission.VIEW_RUNS),
    # Stop: a run's own owner (own) or someone eligible for its gate (STOP_AT_GATE) may stop it.
    # The handler checks both with ``may_stop`` (D3-22); an admin holds the permission outright.
    STOP_ROUTE: RouteRule(
        Permission.CANCEL_RUN,
        also=(Permission.STOP_AT_GATE,),
        checks_own=True,
        checks_gate=True,
    ),
    ("GET", "/runs/{run_id}/gates"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs/{run_id}/gates/{name}/{round}/decisions"): RouteRule(Permission.DECIDE_GATE),
    # D3-19: only team and org admins attribute a commit or resolve a SoD term (PLAN 9.3);
    # anyone who can view the run may read what blocks it and who can clear it.
    ("GET", "/runs/{run_id}/sod-blocks"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/runs/{run_id}/commits/{sha}:attribute"): RouteRule(Permission.ATTRIBUTE_COMMIT),
    ("POST", "/runs/{run_id}/sod-terms:resolve"): RouteRule(Permission.ATTRIBUTE_COMMIT),
}

PUBLIC: frozenset[tuple[str, str]] = frozenset({("GET", "/healthz")})
DOCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/openapi.json"),
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/redoc"),
    }
)


@dataclass(frozen=True)
class Authorized:
    """What a handler gets in ``request.state.auth``.

    ``own_only``: the role qualifies only for the user's own runs, so the handler must check the
    run is theirs. ``gate_only``: only while eligible for the run's open gate. Both are false
    when a role holds the permission outright. Set only on a route that declared ``checks_own``
    or ``checks_gate``.
    """

    identity: UserIdentity | ServiceIdentity
    scope: TeamScope | PlatformScope  # ``PLATFORM`` for a service
    own_only: bool = False
    gate_only: bool = False


def actor_key(identity: UserIdentity | ServiceIdentity) -> str:
    """``issuer|subject``: the actor key of separation of duties (``sto.gates.sod``)."""
    return f"{identity.issuer}|{identity.subject}"


def may_stop(
    auth: Authorized,
    flags: tuple[bool, bool] | None,
    *,
    started_by: str | None,
    gate_roles: frozenset[str],
) -> bool:
    """Whether the caller may Stop a run, given how the cancel route admits them.

    ``flags`` is ``(own_only, gate_only)`` from the cancel rule *in force* (the middleware's
    :class:`Authorized` on the cancel route itself, :func:`stop_flags` anywhere else), or ``None``
    if that rule does not admit them at all. No flag means the caller holds the permission
    outright. Otherwise an "own" holder may Stop a run they started, and a stop-at-gate holder
    one where a role they hold that carries ``STOP_AT_GATE`` is among ``gate_roles`` (the roles
    of the gates that may still be stopped at). A holder of both needs either. A service, an
    unknown starter and a rule that checks nothing admit nobody.
    """
    identity = auth.identity
    if flags is None or not isinstance(identity, UserIdentity):
        return False
    own_only, gate_only = flags
    if not (own_only or gate_only):
        return True
    if own_only and started_by is not None and started_by == actor_key(identity):
        return True
    if not (gate_only and isinstance(auth.scope, TeamScope)):
        return False
    roles = _roles_of(identity, auth.scope.team)
    return any(r in gate_roles and grants(Permission.STOP_AT_GATE, r) is not None for r in roles)


def _roles_of(identity: UserIdentity, team: str) -> set[str]:
    roles = set(identity.roles_in(team))
    if (None, ORG_ADMIN) in identity.memberships:
        roles.add(ORG_ADMIN)
    return roles


TeamOf = Callable[[HTTPConnection], str | None]


def runtime_team(conn: HTTPConnection) -> str | None:
    """The v0 app serves one team: the runtime's."""
    runtime = getattr(conn.app.state, "runtime", None)
    scope = getattr(runtime, "scope", None)
    team = getattr(scope, "team", None)
    return team if isinstance(team, str) and team else None


class RouteTableError(ValueError):
    """The declared routes cannot be matched safely."""


_PARAM = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_SUFFIXED = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}(:[A-Za-z][A-Za-z0-9-]*)")


def _segments(template: str) -> list[str]:
    """The segments of a template. A parameter must be a whole segment (``/runs/{run_id}``),
    optionally followed by a literal colon suffix (``/commits/{sha}:attribute``, the custom-method
    style of the API): any other partial one (``/f/{name}.json``, ``/g/{a}-{b}``) or a converter
    (``{p:path}``) is refused, so the overlap check only has to compare those two shapes."""
    segments = template.split("/")[1:]
    ok = template.startswith("/") and all(
        _PARAM.fullmatch(seg) or _SUFFIXED.fullmatch(seg) or ("{" not in seg and "}" not in seg)
        for seg in segments
    )
    if not ok:
        raise RouteTableError(
            f"unsupported path template {template!r} (whole-segment parameters only, "
            "optionally with a ':name' suffix)"
        )
    return segments


def _shape(segment: str) -> tuple[bool, str]:
    """``(has a parameter, literal suffix)``: ``{id}`` is (True, ''), ``{id}:go`` (True, ':go')
    and ``plain`` (False, 'plain')."""
    found = _SUFFIXED.fullmatch(segment)
    if found:
        return True, found.group(1)
    return (True, "") if _PARAM.fullmatch(segment) else (False, segment)


def _segments_overlap(a: str, b: str) -> bool:
    """Could one non-empty segment value match both templates' segments?"""
    (pa, sa), (pb, sb) = _shape(a), _shape(b)
    if not pa and not pb:
        return sa == sb
    if pa and pb:
        return sa.endswith(sb) or sb.endswith(sa)
    literal, suffix = (sb, sa) if pa else (sa, sb)
    return literal.endswith(suffix) and len(literal) > len(suffix)


def _overlap(a: list[str], b: list[str]) -> bool:
    return len(a) == len(b) and all(_segments_overlap(x, y) for x, y in zip(a, b, strict=True))


def check_table(*tables: Iterable[tuple[str, str]]) -> None:
    """Refuse a malformed template, or two that could match one request, for one method."""
    keys = [k for t in tables for k in t]
    parsed = [(m, tpl, _segments(tpl)) for m, tpl in keys]
    for i, (m1, t1, s1) in enumerate(parsed):
        for m2, t2, s2 in parsed[i + 1 :]:
            if m1 == m2 and _overlap(s1, s2):
                raise RouteTableError(f"{m1} {t1} and {t2} can match the same path")


@dataclass(frozen=True)
class Authorization:
    validator: OidcValidator
    mapping: RoleMapping
    routes: Mapping[tuple[str, str], RouteRule] = field(default_factory=lambda: ROUTES)
    public: frozenset[tuple[str, str]] = PUBLIC
    team_of: TeamOf = runtime_team

    def __post_init__(self) -> None:
        # Copied and frozen first, so a later change to the caller's dict cannot skip the check.
        object.__setattr__(self, "routes", MappingProxyType(dict(self.routes)))
        object.__setattr__(self, "public", frozenset(self.public))
        check_table(self.routes, self.public)


def stop_flags(authorization: Authorization, auth: Authorized) -> tuple[bool, bool] | None:
    """How the cancel route *of this installed table* admits the caller: ``(own_only,
    gate_only)``, or ``None`` if it does not. For a handler that offers the Stop link from another
    route; the cancel route's own handler reads the flags the middleware set."""
    rule = authorization.routes.get(STOP_ROUTE)
    identity = auth.identity
    if rule is None or not isinstance(identity, UserIdentity):
        return None
    if not isinstance(auth.scope, TeamScope):
        return None
    return _admission(rule, _roles_of(identity, auth.scope.team))


def _methods(methods: Iterable[str] | None, path: str) -> Iterator[tuple[str, str]]:
    """A route with no method list (an ``HTTPEndpoint``) answers every method: ``ANY``, which no
    declared route can be, so it is always listed as undeclared and refused."""
    found = sorted(m for m in methods or () if m != "HEAD")
    yield from ((m, path) for m in found) if found else iter([("ANY", path)])


def _walk(routes: Iterable[Any], prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every ``(method, path template)`` below ``routes``, through included routers and mounts."""
    for r in routes:
        if hasattr(r, "effective_candidates"):  # FastAPI's wrapper for an included router
            yield from _walk(r.effective_candidates(), prefix)
            yield from _walk(r.effective_low_priority_routes(), prefix)
            continue
        original = getattr(r, "original_route", None)  # an included route, with its full path
        if original is not None:
            if isinstance(original, Mount):
                yield ("MOUNT", f"{getattr(r, 'frontend_prefix', '')}{original.path}/*")
            elif isinstance(original, WebSocketRoute):
                starlette = getattr(r, "starlette_route", None)
                yield (WEBSOCKET, getattr(starlette, "path", None) or original.path)
            elif isinstance(original, APIRoute | Route):
                yield from _methods(r.methods, r.path)
            else:
                yield ("UNKNOWN", type(original).__name__)
        elif isinstance(r, Mount):
            sub = getattr(r.app, "routes", None)
            if sub is None:
                yield ("MOUNT", f"{prefix}{r.path}/*")
            else:
                yield from _walk(sub, prefix + r.path)
        elif isinstance(r, WebSocketRoute):
            yield (WEBSOCKET, prefix + r.path)
        elif isinstance(r, APIRoute | Route):
            yield from _methods(r.methods, prefix + r.path)
        else:
            yield ("UNKNOWN", type(r).__name__)


def routes_of(app: FastAPI) -> list[tuple[str, str]]:
    """Every ``(method, path template)`` the app serves, from its router tree (so including
    included routers, mounts, websockets and routes hidden from the schema)."""
    router = app.router
    # ``_low_priority_routes`` holds what an app-level ``frontend()`` registers: matched last.
    low = getattr(router, "_low_priority_routes", ())
    return sorted(set(_walk([*router.routes, *low])))


def undeclared_routes(
    app: FastAPI,
    routes: Mapping[tuple[str, str], RouteRule] = ROUTES,
    public: frozenset[tuple[str, str]] = PUBLIC | DOCS,
) -> list[tuple[str, str]]:
    """Every ``(method, path template)`` of the app that is neither declared nor public."""
    return [k for k in routes_of(app) if k not in routes and k not in public]


@functools.cache
def _compile(template: str) -> re.Pattern[str]:
    """``/runs/{run_id}`` becomes a pattern with one named, non-empty, slash-free group."""
    out = ""
    for part in re.split(f"({_PARAM.pattern})", template):
        out += f"(?P<{part[1:-1]}>[^/]+)" if _PARAM.fullmatch(part) else re.escape(part)
    return re.compile(out)


_BEARER = re.compile(r"(?i:bearer) ([^\s]+)", re.ASCII)


@dataclass(frozen=True)
class _Refusal:
    status: int
    code: str
    message: str
    www: bool = False

    def response(self) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if self.www else None
        body = {"error": {"code": self.code, "message": self.message}}
        return JSONResponse(body, status_code=self.status, headers=headers)


_UNDECLARED = _Refusal(403, "no_permission_declared", "this route has no declared permission")
_FORBIDDEN = _Refusal(403, "forbidden", "this request is not allowed")


def _admission(rule: RouteRule, roles: Iterable[str]) -> tuple[bool, bool] | None:
    """``(own_only, gate_only)`` for the best way in, or ``None`` if no role gets in."""
    own = gate = False
    for role in roles:
        for permission in (rule.permission, *rule.also):
            how = grants(permission, role)
            if how is None:
                continue
            if permission is Permission.STOP_AT_GATE:  # conditional on the run's gate, always
                gate = gate or rule.checks_gate
            elif how == "own":
                own = own or rule.checks_own
            else:
                return (False, False)
    return (own, gate) if own or gate else None


class AuthorizationMiddleware:
    def __init__(self, app: ASGIApp, authorization: Authorization) -> None:
        self.app, self.authz = app, authorization

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)  # lifespan
            return
        refusal = await self._check(scope)
        if refusal is None:
            await self.app(scope, receive, send)
        elif scope["type"] == "http":
            await refusal.response()(scope, receive, send)
        else:
            await receive()  # the connect message; then refuse it before accepting
            await send({"type": "websocket.close", "code": 1008, "reason": refusal.code})

    def _match(self, scope: Scope) -> tuple[tuple[str, str], dict[str, str]] | None:
        """The declared ``(method, template)`` this request is for, and its path parameters.
        Templates never overlap (``check_table``), so at most one matches."""
        path = scope["path"]
        root = scope.get("root_path") or ""
        if root and path.startswith(root):
            path = path[len(root) :]
        method = WEBSOCKET if scope["type"] == "websocket" else scope["method"]
        for m, template in (*self.authz.routes, *self.authz.public):
            if m == method and (found := _compile(template).fullmatch(path)) is not None:
                return (m, template), found.groupdict()
        return None

    async def _check(self, scope: Scope) -> _Refusal | None:
        matched = self._match(scope)
        if matched is None:
            return _UNDECLARED
        key, params = matched
        if key in self.authz.public:
            return None
        rule = self.authz.routes[key]
        conn = HTTPConnection({**scope, "path_params": params})
        found = _BEARER.fullmatch(conn.headers.get("authorization", ""))
        if found is None:
            return _Refusal(401, "unauthorized", "a bearer token is required", www=True)
        try:
            token = await asyncio.to_thread(self.authz.validator.validate, found.group(1))
        except InvalidTokenError as e:
            log.info("token refused on %s %s: %s", *key, e.reason)
            return _Refusal(401, "unauthorized", "the token is not valid", www=True)
        try:
            identity = await asyncio.to_thread(self.authz.mapping.resolve, token)
        except UserDisabledError:
            return _Refusal(403, "user_disabled", "this identity is disabled")
        except NoAccessError:
            return _Refusal(403, "no_access", "this identity has no access")
        if isinstance(identity, ServiceIdentity):
            if not rule.service:
                return _Refusal(403, "service_not_permitted", "services may not call this route")
            self._set(scope, Authorized(identity, PLATFORM))
            return None
        team = self.authz.team_of(conn)
        if team is None:
            return _FORBIDDEN
        admitted = _admission(rule, _roles_of(identity, team))
        if admitted is None:
            return _FORBIDDEN
        self._set(scope, Authorized(identity, TeamScope(team), *admitted))
        return None

    @staticmethod
    def _set(scope: Scope, auth: Authorized) -> None:
        state: dict[str, Any] = scope.setdefault("state", {})
        state["auth"] = auth


def install_authorization(app: FastAPI, authorization: Authorization) -> None:
    """Add the middleware. Call before the app starts. The table in force is kept on
    ``app.state.authorization`` for handlers that must judge another route's rule."""
    app.state.authorization = authorization
    app.add_middleware(AuthorizationMiddleware, authorization=authorization)
