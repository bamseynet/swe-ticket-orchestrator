"""Account linking routes (PLAN 9.2, D3-04).

A signed-in person proves control of a Slack, GitHub or Jira account through that vendor's OAuth
flow (``sto.identity.linking`` holds every rule; this is the HTTP shape of it):

* ``POST /links/{vendor}:start`` returns the vendor's authorize URL and the link ``state`` token.
* ``POST /links/{vendor}:complete`` takes ``{state, code}`` from the vendor redirect. The token
  must be the caller's, from the caller's SSO session, for this vendor, unused and unexpired.
* ``GET /links`` lists the caller's own live links; ``DELETE /links/{vendor}/{account_id}``
  removes one of the caller's own (audited).

Nobody else's links are readable or removable here, and an email address is accepted nowhere
(request bodies refuse unknown fields). The SSO session comes from ``session_of`` (the caller of
:func:`make_router` decides how a request names its session; ``None`` or empty is ``401``).

The router is a factory because the linking service is built from vendor clients and the store.
It is not yet included by ``create_app`` and its routes are not yet in ``sto.api.auth.ROUTES``;
:data:`LINK_ROUTES` is the exact set of lines to declare. Every role may link its own account,
so they use ``VIEW_RUNS`` (which every built-in and custom role holds) until a dedicated
permission row is decided.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from sto.api.auth import Permission, RouteRule
from sto.api.routers.runs import ApiError, ErrorResponse, authorization_of
from sto.identity.linking import (
    AccountClaimedError,
    AccountLinking,
    LinkContentionError,
    LinkRefusedError,
    LinkStateError,
    LinkTokenExpiredError,
    LinkTokenInvalidError,
    LinkTokenMismatchError,
    NotLinkedError,
    UnknownVendorError,
    VendorExchangeError,
)
from sto.identity.mapping import UserIdentity

__all__ = ["LINK_ROUTES", "make_router"]

log = logging.getLogger("sto.api")

LINK_ROUTES: dict[tuple[str, str], RouteRule] = {
    ("GET", "/links"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/links/{vendor}:start"): RouteRule(Permission.VIEW_RUNS),
    ("POST", "/links/{vendor}:complete"): RouteRule(Permission.VIEW_RUNS),
    ("DELETE", "/links/{vendor}/{account_id}"): RouteRule(Permission.VIEW_RUNS),
}

_STATUS: tuple[tuple[type[LinkRefusedError], int, str], ...] = (
    (LinkTokenExpiredError, 410, "link_token_expired"),
    (LinkTokenInvalidError, 409, "link_token_invalid"),
    (LinkTokenMismatchError, 403, "link_token_mismatch"),
    (AccountClaimedError, 409, "account_already_linked"),
    (NotLinkedError, 404, "link_not_found"),
    (UnknownVendorError, 404, "unknown_vendor"),
    (VendorExchangeError, 422, "vendor_refused"),
    (LinkStateError, 500, "link_state_unreadable"),
)


class StartOut(BaseModel):
    state: str
    authorize_url: str
    expires_at: float


class CompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str = Field(min_length=1, max_length=512)
    code: str = Field(min_length=1, max_length=2_048)


class LinkOut(BaseModel):
    vendor: str
    account_id: str
    linked_at: float
    expires_at: float


class LinkList(BaseModel):
    links: list[LinkOut]


def _refusal(error: LinkRefusedError | LinkContentionError) -> ApiError:
    if isinstance(error, LinkContentionError):
        return ApiError(503, "link_busy", str(error), headers={"Retry-After": "1"})
    for kind, status, code in _STATUS:
        if isinstance(error, kind):
            return ApiError(status, code, str(error))
    return ApiError(400, "link_refused", str(error))  # pragma: no cover


def make_router(links: AccountLinking, *, session_of: Callable[[Request], str | None]) -> APIRouter:
    router = APIRouter(tags=["links"])
    refused: dict[int | str, dict[str, Any]] = {
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        410: {"model": ErrorResponse},
    }

    def person(request: Request) -> UserIdentity:
        auth = authorization_of(request)
        if auth is None or not isinstance(auth.identity, UserIdentity):
            raise ApiError(403, "identity_required", "this needs a signed-in person")
        return auth.identity

    def session(request: Request) -> str:
        found = session_of(request)
        if not found:
            raise ApiError(401, "session_required", "sign in again to link an account")
        return found

    @router.get("/links", response_model=LinkList, summary="My linked accounts")
    async def list_links(request: Request) -> dict[str, Any]:
        mine = await asyncio.to_thread(links.links_of, person(request))
        return {"links": [vars(link) for link in mine]}

    @router.post(
        "/links/{vendor}:start",
        response_model=StartOut,
        responses=refused,
        summary="Begin linking: the vendor's authorize URL and the state token",
    )
    async def start(vendor: str, request: Request) -> dict[str, Any]:
        who, sso = person(request), session(request)
        try:
            began = await asyncio.to_thread(links.start, who, sso, vendor)
        except (LinkRefusedError, LinkContentionError) as e:
            raise _refusal(e) from e
        return {
            "state": began.token,
            "authorize_url": began.authorize_url,
            "expires_at": began.expires_at,
        }

    @router.post(
        "/links/{vendor}:complete",
        response_model=LinkOut,
        responses=refused,
        summary="Finish linking with the code the vendor's redirect carried",
    )
    async def complete(vendor: str, body: CompleteIn, request: Request) -> dict[str, Any]:
        who, sso = person(request), session(request)
        try:
            link = await asyncio.to_thread(links.complete, who, sso, vendor, body.state, body.code)
        except (LinkRefusedError, LinkContentionError) as e:
            log.info("link refused for %r: %s", vendor, type(e).__name__)
            raise _refusal(e) from e
        return vars(link)

    @router.delete(
        "/links/{vendor}/{account_id}",
        status_code=204,
        responses=refused,
        summary="Unlink one of my accounts (audited)",
    )
    async def unlink(
        vendor: str, account_id: Annotated[str, Path(max_length=400)], request: Request
    ) -> Response:
        who = person(request)
        try:
            await asyncio.to_thread(links.unlink, who, vendor, account_id)
        except (LinkRefusedError, LinkContentionError) as e:
            raise _refusal(e) from e
        return Response(status_code=204)

    return router
