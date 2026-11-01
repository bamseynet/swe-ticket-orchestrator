"""An in-process fake of GitHub's App authentication, rate limits, pagination and errors (D4-16).

This is a SERVER, not an adapter. It has no port, writes no verifier and holds no real credential:
every ID, key and token is synthetic. An adapter under test talks to ``FakeGitHubAuth.handle`` as
it would talk to the API. Each behaviour below names the page that documents it, or says
"unsourced" where no page does; the live suite (D12) later proves all of it against the real
service, and when they disagree the fake is wrong.

Known departures, each deliberate:

* GitHub signs App JWTs with RS256. The fake checks that the header says ``alg: RS256`` and then
  an HMAC-SHA256 under a synthetic key (``APP_KEY``), so the tests need no RSA key and no crypto
  dependency. The claims it checks are GitHub's.
* The state read (``read``) returns a ``revision`` counter and the list (``lookup``) returns
  ``{"items": [...]}`` of objects with an ID, an author and a body. GitHub has no such endpoints;
  they stand in for "read the object a webhook was about" and "list comments", which D4-19 and
  later issues replace with the real routes. Paging is GitHub's: one-based ``page`` (default 1),
  ``per_page`` (default 30, at most 100), and the ``link`` header alone says where the rest is.
* The only write is a stand-in ``write`` (store one object under ``PRINCIPAL``), so that the
  look-up sections can target the paged list. The real routes arrive with D4-19 and later.
* The HMAC stand-in means a real RS256 signer gets a 401 here: D4-02 has to work around that (sign
  with ``APP_KEY`` under ``alg: RS256``, or inject a signer).
* Bad paging values follow GitHub as observed with read-only calls: ``page`` below 1 or not an
  integer means page 1, and ``per_page`` below 1 or not an integer means the default of 30. Not
  modelled, as known limits: a page far past the end (GitHub answers 422; the fake an empty 200)
  and the ``link`` header GitHub sends on a page past the end (the fake sends none).
* ``permissions={}`` on the mint grants nothing (untested, unsourced). A token narrowed to some
  repositories and used with no repository named gets a 200: nothing is there to refuse.
* A token for no narrower set reaches only the installation's repositories: ``repo`` outside them
  is a 404, inferred and not tried live.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from contract.suite import RateShape

APP_ID = "100001"  # synthetic
CLIENT_ID = "Iv1.synthetic0001"  # synthetic; the docs accept the client ID or the App ID as `iss`
INSTALLATION_ID = 200002  # synthetic
APP_KEY = b"synthetic-app-key"  # stands in for the App's RSA private key; see the module docstring
INSTALLATION_OWNER = "acme"  # synthetic
# The repositories this installation can reach, as BARE names: the docs call `repositories` a
# "List of repository names" (example "Hello-World"), so owner/name is refused at the mint. This
# was read from the docs and NOT tried on real GitHub: prove it live (D12).
INSTALLATION_REPOS = ("app", "lib")
PRINCIPAL = "sto-bot"  # the login the stand-in write route stores objects under
INSTALLATION_PERMISSIONS: Mapping[str, str] = {
    "checks": "write",
    "contents": "write",
    "issues": "write",
    "metadata": "read",
    "pull_requests": "write",
}
_LEVELS = {"read": 1, "write": 2, "admin": 3}
PAGE_SIZE = 100  # the maximum per_page
DEFAULT_PER_PAGE = 30
# https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
JWT_MAX_TTL = 600.0  # seconds
# https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
# (alg RS256; iss; exp at most ten minutes ahead; iat a minute back for drift. The page lists no
# error behaviour: the 401 and its messages below are unsourced, observed behaviour to prove live.)
TOKEN_TTL = 3600.0  # seconds
# https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
# (an hour; `repositories` and `permissions` narrow it; omitted, it gets all of the installation's.
# The 404 for an unknown installation and the 422 for an outside repository or permission are
# unsourced, observed behaviour to prove live.)
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


@dataclass
class Grant:
    """What an installation token may do: its expiry, repositories (None: all) and permissions."""

    expires: float
    repositories: tuple[str, ...] | None
    permissions: Mapping[str, str]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _iso(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def _page_number(raw: object) -> int:
    """A page below 1, or not an integer, is page 1 (as GitHub answers, observed read-only)."""
    try:
        number = int(str(raw))
    except ValueError:
        return 1
    return number if number >= 1 else 1


def _per_page(raw: object) -> int:
    """Below 1 or not an integer: the default of 30. Above 100: 100."""
    try:
        number = int(str(raw))
    except ValueError:
        return DEFAULT_PER_PAGE
    return DEFAULT_PER_PAGE if number < 1 else min(number, PAGE_SIZE)


def _unauthorized(message: str) -> Response:
    # unsourced, observed behaviour to prove live: a 401 with this message
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
        self._tokens: dict[str, Grant] = {}
        self._issued = 0
        self._used, self._window_end = 0, 0.0
        self._faults: defaultdict[str, list[list[Any]]] = defaultdict(list)
        self._plain: defaultdict[str, list[int]] = defaultdict(list)
        self._limited, self._shape = 0, RateShape.PRIMARY_429
        self._limit_op: str | None = None
        self._auth_ok, self._deny_ops = True, set[str]()
        self._lose = False
        self.swallow = 0

    # --- App authentication ---------------------------------------------------------------

    def app_jwt(
        self,
        *,
        iat_offset: float = -60.0,
        ttl: float = 540.0,
        key: bytes = APP_KEY,
        app_id: str | int = APP_ID,
        alg: str = "RS256",
    ) -> str:
        """A JSON Web Token as the App would sign one: ``iat`` a minute back for clock drift,
        ``exp`` within ten minutes."""
        header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
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
            header = json.loads(_unb64(parts[0]))
            sent = _unb64(parts[2])
        except (ValueError, TypeError):
            return undecodable
        want = hmac.new(APP_KEY, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if not isinstance(claims, dict) or not isinstance(header, dict):
            return undecodable
        if header.get("alg") != "RS256" or not hmac.compare_digest(sent, want):
            return undecodable
        return claims

    def _jwt_refusal(self, jwt: str) -> Response | None:
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
        if str(iss) not in (APP_ID, CLIENT_ID):
            return _unauthorized("A JSON web token could not be decoded")
        return None

    def create_installation_token(
        self,
        jwt: str,
        installation_id: int,
        repositories: Sequence[str] | None = None,
        permissions: Mapping[str, str] | None = None,
    ) -> Response:
        """``POST /app/installations/{id}/access_tokens``, authenticated by the App's JWT.

        * ``exp`` at most ten minutes ahead, ``iat`` not in the future, ``alg`` RS256, not expired:
          anything else is a 401 (generating-a-json-web-token-jwt-for-a-github-app).
        * The token lasts one hour. ``repositories`` and ``permissions`` narrow it; left out, it
          gets all the installation's, and the answer says what was granted
          (create-an-installation-access-token-for-an-app).
        * ``repositories`` are bare names ("app"), per the docs; ``owner/name`` is a 422. An
          installation that is not this App's is a 404; a repository or a permission beyond the
          installation's is a 422 (unsourced, observed behaviour to prove live).
        * The same faults, limits and 401s as any request apply to ``installation_token``.
        """
        op = "installation_token"
        refused = self._jwt_refusal(jwt)
        early = self._preflight(op, refused, None, metered=False)
        if early is not None:
            return early[0]
        if installation_id != INSTALLATION_ID:
            return Response(404, {}, {"message": "Not Found"})
        outside = [r for r in repositories or () if r not in INSTALLATION_REPOS]
        if outside:
            return Response(
                422,
                {},
                {
                    "message": "There is at least one repository that does not exist or is not "
                    "accessible to the parent installation."
                },
            )
        asked = dict(permissions) if permissions is not None else dict(INSTALLATION_PERMISSIONS)
        too_much = [
            name
            for name, level in asked.items()
            if _LEVELS.get(level, 99) > _LEVELS.get(INSTALLATION_PERMISSIONS.get(name, ""), 0)
        ]
        if too_much:
            return Response(
                422,
                {},
                {"message": "The permissions requested are not granted to this installation."},
            )
        self._issued += 1
        token = f"ghs_fake_{self._issued}"
        repos = tuple(repositories) if repositories is not None else None
        self._tokens[token] = Grant(self.now + TOKEN_TTL, repos, asked)
        granted: dict[str, Any] = {
            "token": token,
            "expires_at": _iso(self.now + TOKEN_TTL),
            "permissions": asked,
            "repository_selection": "selected" if repos is not None else "all",
        }
        if repos is not None:
            granted["repositories"] = [
                {"name": r, "full_name": f"{INSTALLATION_OWNER}/{r}"} for r in repos
            ]
        return Response(201, {}, granted)

    def grant(self, token: str) -> Grant | None:
        """What this token was granted (the fake's own view; an adapter has no such call)."""
        return self._tokens.get(token)

    # --- controls -------------------------------------------------------------------------

    def revoke(self, token: str) -> None:
        """``DELETE /installation/token``: this token stops working at once.
        https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token"""
        self._tokens.pop(token, None)

    def expire_token(self, token: str) -> None:
        grant = self._tokens.get(token)
        if grant is not None:
            grant.expires = self.now

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
        """The next ``op`` request is answered with a plain ``status`` (403 or 404): unsourced,
        observed behaviour to prove live."""
        self._plain[op].append(status)

    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        """The next ``op`` request (after skipping ``after``, and only for ``page``, one-based)
        suffers ``5xx``, ``timeout``, ``429`` or ``401``; a write also ``lose``."""
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

    def _preflight(
        self, op: str, refused: Response | None, page: int | None, *, metered: bool
    ) -> tuple[Response, dict[str, str]] | None:
        """What every request meets before its own work: counted, authenticated, limited, then
        the planted plain answer or fault. ``None`` means "carry on", with the quota headers
        left in ``self._quota()``. ``refused`` is the credential check the caller already made."""
        self.counts[op] += 1
        if refused is None and (not self._auth_ok or op in self._deny_ops):
            refused = _unauthorized("Bad credentials")
        if refused is not None:
            self.counts["unauthorized"] += 1
            return refused, {}
        quota = self._quota() if metered else {}
        if self._limited > 0 and self._limit_op in (None, op):
            self._limited -= 1
            self.counts["limited"] += 1
            return self._limit_response(self._shape), quota
        if metered:
            if self._used >= self.budget:
                self.counts["limited"] += 1
                message = f"API rate limit exceeded for installation ID {INSTALLATION_ID}."
                return Response(403, quota, {"message": message}), quota
            self._used += 1
            quota = self._quota()
        if self._plain[op]:
            return Response(self._plain[op].pop(0), quota, {"message": "plain error"}), quota
        fault = self._fault(op, page)
        if fault == "5xx":
            return Response(503, quota, {}), quota
        if fault == "429":
            return Response(429, {**quota, "retry-after": "30"}, {}), quota
        if fault == "401":
            return _unauthorized("Bad credentials"), quota
        if fault == "timeout":
            raise TimeoutError("timed out")
        self._lose = fault == "lose"  # a write applied, the caller sees a timeout
        return None

    def _token_refusal(self, token: str) -> Response | None:
        if not token:
            return _unauthorized("Requires authentication")
        grant = self._tokens.get(token)
        if grant is None or grant.expires <= self.now:
            return _unauthorized("Bad credentials")
        return None

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        """One authenticated request: ``read``, ``lookup`` (with ``page``, ``per_page``) or the
        stand-in ``write`` (with ``body``), and optionally ``repo`` (``owner/name``), which a token
        narrowed to other repositories, or outside the installation, cannot reach (404)."""
        if op not in ("read", "lookup", "write"):
            raise AssertionError(f"unknown op {op!r}")
        page = _page_number(kw.get("page", 1)) if op == "lookup" else None
        early = self._preflight(op, self._token_refusal(token), page, metered=True)
        if early is not None:
            return early[0]
        quota = self._quota()
        grant = self._tokens[token]
        repo = kw.get("repo")
        if repo is not None and not self._reaches(grant, str(repo)):
            return Response(404, quota, {"message": "Not Found"})
        if op == "read":
            return Response(200, quota, {"revision": self.revision})
        if op == "write" and self.swallow > 0:
            self.swallow -= 1
            return Response(201, quota, {"id": "c-swallowed"})
        if op == "write":
            self._seq += 1
            item = Item(f"c-{self._seq}", PRINCIPAL, str(kw["body"]))
            self.items.append(item)
            if self._lose:
                raise TimeoutError("response lost")
            return Response(201, quota, {"id": item.id})
        return self._list(
            quota, page if page is not None else 1, _per_page(kw.get("per_page", DEFAULT_PER_PAGE))
        )

    @staticmethod
    def _reaches(grant: Grant, repo: str) -> bool:
        """``owner/name`` is inside the installation, and inside the token's narrowing if any."""
        owner, _, name = repo.partition("/")
        if owner != INSTALLATION_OWNER or name not in INSTALLATION_REPOS:
            return False  # inferred 404, not tried live
        return grant.repositories is None or name in grant.repositories

    def _list(self, quota: dict[str, str], page: int, per_page: int) -> Response:
        """A page of the list.

        ``page`` is one-based and ``per_page`` defaults to 30 and is capped at 100; the ``link``
        header names the next, previous, first and last pages and is the only way to find them.
        https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
        """
        listing = list(reversed(self.items)) if self.order == "newest_first" else self.items
        chunk = listing[(page - 1) * per_page : page * per_page]
        more = len(listing) > page * per_page
        last = max(1, -(-len(listing) // per_page))

        def url(number: int, rel: str) -> str:
            return f'<{HOST}/items?page={number}&per_page={per_page}>; rel="{rel}"'

        links = ([url(page - 1, "prev"), url(1, "first")] if page > 1 and chunk else []) + (
            [url(page + 1, "next"), url(last, "last")] if more else []
        )
        headers = {**quota, **({"link": ", ".join(links)} if links else {})}
        items = [{"id": c.id, "author": c.author, "body": c.body} for c in chunk]
        return Response(200, headers, {"items": items})
