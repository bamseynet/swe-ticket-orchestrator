"""An in-process fake of GitHub's App authentication, rate limits, pagination and errors (D4-16).

This is a SERVER, not an adapter. It has no port, writes no verifier and holds no real credential:
every ID, key and token is synthetic. An adapter under test talks to ``FakeGitHubAuth.handle`` as
it would talk to the API. Each behaviour below names the page that documents it; the live suite
(D12) later proves the fake against the real service, and when they disagree the fake is wrong.

Known departures, each deliberate:

* GitHub signs App JWTs with RS256. The fake checks an HMAC-SHA256 under a synthetic key
  instead (``APP_KEY``), so the tests need no RSA key and no crypto dependency. The claims it
  checks, and the 401 for a bad one, are GitHub's.
* The state read (``read``) returns a ``revision`` counter and the list (``lookup``) returns
  objects with an ID, an author and a body. GitHub has no such endpoints; they stand in for "read
  the object a webhook was about" and "list comments", which D4-19 and later issues replace with
  the real routes.
* The list takes a zero-based ``page`` and answers ``next`` in the body as well as in the
  ``link`` header (one-based, as GitHub's). ``per_page`` defaults to 100, not GitHub's 30,
  because the conformance suite assumes the server pages at 100.
* There is no write surface (``handle("write", ...)`` raises): writes belong to D4-19 and later.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from contract.suite import RateShape

APP_ID = "100001"  # synthetic
INSTALLATION_ID = 200002  # synthetic
APP_KEY = b"synthetic-app-key"  # stands in for the App's RSA private key; see the module docstring
PAGE_SIZE = 100  # the maximum per_page
# https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
JWT_MAX_TTL = 600.0  # seconds
# https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
TOKEN_TTL = 3600.0  # seconds
# https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
RATE_WINDOW = 3600.0  # seconds
DEFAULT_BUDGET = 5000
# https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
HOST = "https://api.github.test"  # a reserved TLD: never a real host


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: Any


@dataclass(frozen=True)
class Item:
    id: str
    author: str
    body: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _iso(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def _unauthorized(message: str) -> Response:
    # https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api#401-unauthorized
    return Response(401, {}, {"message": message})


class FakeGitHubAuth:
    """App authentication, installation tokens, a rate-limited and paged read surface, and
    controls to provoke every failure."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self.revision = 0
        self.order = "newest_first"
        self.budget = DEFAULT_BUDGET
        self.counts: Counter[str] = Counter()
        self.items: list[Item] = []
        self._seq = 0
        self._tokens: dict[str, float] = {}  # token -> expiry
        self._issued = 0
        self._used, self._window_end = 0, 0.0
        self._faults: defaultdict[str, list[list[Any]]] = defaultdict(list)
        self._plain: defaultdict[str, list[int]] = defaultdict(list)
        self._limited, self._shape = 0, RateShape.PRIMARY_429
        self._limit_op: str | None = None
        self._auth_ok, self._deny_ops = True, set[str]()

    # --- App authentication ---------------------------------------------------------------

    def app_jwt(
        self,
        *,
        iat_offset: float = -60.0,
        ttl: float = 540.0,
        key: bytes = APP_KEY,
        app_id: str = APP_ID,
    ) -> str:
        """A JSON Web Token as the App would sign one: ``iat`` a minute back for clock drift,
        ``exp`` within ten minutes."""
        header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = {"iat": int(self.now + iat_offset), "exp": int(self.now + ttl), "iss": app_id}
        payload = _b64(json.dumps(claims).encode())
        sig = hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        return f"{header}.{payload}.{_b64(sig)}"

    def _jwt_claims(self, jwt: str) -> dict[str, Any] | str:
        """The claims, or the reason GitHub gives for refusing the token."""
        undecodable = "A JSON web token could not be decoded"
        parts = jwt.split(".")
        if len(parts) != 3:
            return undecodable
        try:
            claims = json.loads(_unb64(parts[1]))
            json.loads(_unb64(parts[0]))
            sent = _unb64(parts[2])
        except (ValueError, TypeError):
            return undecodable
        want = hmac.new(APP_KEY, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if not isinstance(claims, dict) or not hmac.compare_digest(sent, want):
            return undecodable
        return claims

    def create_installation_token(self, jwt: str, installation_id: int) -> Response:
        """``POST /app/installations/{id}/access_tokens``, authenticated by the App's JWT.

        * ``exp`` is at most ten minutes ahead, ``iat`` is not in the future, and the JWT is not
          expired; anything else is a 401 (generating-a-json-web-token-jwt-for-a-github-app).
        * The token it returns lasts one hour (create-an-installation-access-token-for-an-app).
        * An installation that is not this App's is a 404.
        """
        self.counts["installation_token"] += 1
        claims = self._jwt_claims(jwt)
        if isinstance(claims, str):
            return _unauthorized(claims)
        iat, exp, iss = claims.get("iat"), claims.get("exp"), claims.get("iss")
        if not isinstance(iat, int) or iat > self.now:
            return _unauthorized(
                "'Issued at' claim ('iat') must be an Integer representing the time that the "
                "assertion was issued"
            )
        if not isinstance(exp, int) or exp <= self.now or exp > self.now + JWT_MAX_TTL:
            return _unauthorized(
                "'Expiration time' claim ('exp') must be a numeric value representing the "
                "future time at which the assertion expires"
            )
        if iss != APP_ID:
            return _unauthorized("A JSON web token could not be decoded")
        if installation_id != INSTALLATION_ID:
            return Response(404, {}, {"message": "Not Found"})
        self._issued += 1
        token = f"ghs_fake_{self._issued}"
        self._tokens[token] = self.now + TOKEN_TTL
        return Response(
            201, {}, {"token": token, "expires_at": _iso(self.now + TOKEN_TTL), "permissions": {}}
        )

    # --- controls -------------------------------------------------------------------------

    def revoke(self, token: str) -> None:
        """``DELETE /installation/token``: this token stops working at once."""
        self._tokens.pop(token, None)

    def expire_token(self, token: str) -> None:
        self._tokens[token] = self.now

    def revoke_auth(self, op: str | None = None) -> None:
        """Reject every request (or just ``op``) with a 401."""
        if op is None:
            self._auth_ok = False
        else:
            self._deny_ops.add(op)

    def restore_auth(self) -> None:
        self._auth_ok = True
        self._deny_ops.clear()

    def rate_limit_next(self, times: int, shape: RateShape, op: str | None = None) -> None:
        self._limited, self._shape, self._limit_op = times, shape, op

    def respond_next(self, op: str, status: int) -> None:
        """The next ``op`` request is answered with a plain ``status`` (403 or 404)."""
        self._plain[op].append(status)

    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        """The next ``op`` request (after skipping ``after``, and only for ``page``) suffers
        ``5xx``, ``timeout``, ``429`` or ``401``."""
        self._faults[op].append([mode, page, after])

    def add(self, author: str, body: str, *, older: bool = False) -> Item:
        self._seq += 1
        item = Item(f"c-{self._seq}", author, body)
        if older:
            self.items.insert(0, item)
        else:
            self.items.append(item)
        return item

    def seed(self, n: int, author: str, *, older: bool = False) -> None:
        for i in range(n):
            self.add(author, f"unrelated {i}", older=older)

    # --- the API ---------------------------------------------------------------------------

    def _limit_response(self, shape: RateShape) -> Response:
        """The five ways GitHub says "slow down".

        https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
        https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
        """
        if shape is RateShape.PRIMARY_429:
            return Response(429, {"retry-after": "30", "x-ratelimit-remaining": "0"}, {})
        if shape is RateShape.PRIMARY_429_NO_HEADER:
            return Response(429, {}, {})
        if shape is RateShape.SECONDARY_403:
            return Response(403, {"retry-after": "30"}, {"message": "secondary rate limit"})
        if shape is RateShape.SECONDARY_403_NO_HEADER:
            return Response(403, {}, {"message": "You have exceeded a secondary rate limit."})
        reset = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(self.now) + 45)}
        return Response(403, reset, {"message": "API rate limit exceeded"})

    def _fault(self, op: str, page: int | None) -> str:
        for entry in self._faults[op]:
            mode, want_page, after = entry
            if want_page is not None and want_page != page:
                continue
            if after > 0:
                entry[2] -= 1
                return ""
            self._faults[op].remove(entry)
            return str(mode)
        return ""

    def _quota(self) -> dict[str, str]:
        if self.now >= self._window_end:
            self._used, self._window_end = 0, self.now + RATE_WINDOW
        return {
            "x-ratelimit-limit": str(self.budget),
            "x-ratelimit-remaining": str(max(0, self.budget - self._used)),
            "x-ratelimit-used": str(self._used),
            "x-ratelimit-reset": str(int(self._window_end)),
            "x-ratelimit-resource": "core",
        }

    def _authenticated(self, op: str, token: str) -> Response | None:
        if not token:
            return _unauthorized("Requires authentication")
        expiry = self._tokens.get(token)
        if expiry is None or expiry <= self.now or not self._auth_ok or op in self._deny_ops:
            return _unauthorized("Bad credentials")
        return None

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        """One authenticated request: ``read`` or ``lookup`` (with ``page``, ``per_page``)."""
        if op not in ("read", "lookup"):
            raise AssertionError(f"unknown op {op!r}: this fake has no write surface")
        self.counts[op] += 1
        refused = self._authenticated(op, token)
        if refused is not None:
            self.counts["unauthorized"] += 1
            return refused
        quota = self._quota()
        if self._limited > 0 and self._limit_op in (None, op):
            self._limited -= 1
            self.counts["limited"] += 1
            return self._limit_response(self._shape)
        if self._used >= self.budget:
            self.counts["limited"] += 1
            return Response(
                403,
                quota,
                {"message": f"API rate limit exceeded for installation ID {INSTALLATION_ID}."},
            )
        self._used += 1
        quota = self._quota()
        page = int(kw["page"]) if op == "lookup" else None
        if self._plain[op]:
            return Response(self._plain[op].pop(0), quota, {"message": "plain error"})
        fault = self._fault(op, page)
        if fault == "5xx":
            return Response(503, quota, {})
        if fault == "429":
            return Response(429, {**quota, "retry-after": "30"}, {})
        if fault == "401":
            return _unauthorized("Bad credentials")
        if fault == "timeout":
            raise TimeoutError("timed out")
        if op == "read":
            return Response(200, quota, {"revision": self.revision})
        return self._list(quota, page or 0, int(kw.get("per_page", PAGE_SIZE)))

    def _list(self, quota: dict[str, str], page: int, per_page: int) -> Response:
        """A page of the list.

        ``per_page`` is capped at 100 and the ``link`` header names the next, previous, first and
        last pages, one-based. https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
        """
        per_page = max(1, min(per_page, PAGE_SIZE))
        listing = list(reversed(self.items)) if self.order == "newest_first" else self.items
        chunk = listing[page * per_page : (page + 1) * per_page]
        more = len(listing) > (page + 1) * per_page
        last = max(0, (len(listing) - 1) // per_page)

        def url(number: int, rel: str) -> str:
            return f'<{HOST}/items?page={number + 1}&per_page={per_page}>; rel="{rel}"'

        links = ([url(page - 1, "prev"), url(0, "first")] if page > 0 and chunk else []) + (
            [url(page + 1, "next"), url(last, "last")] if more else []
        )
        headers = {**quota, **({"link": ", ".join(links)} if links else {})}
        items = [{"id": c.id, "author": c.author, "body": c.body} for c in chunk]
        return Response(200, headers, {"items": items, "next": page + 1 if more else None})
