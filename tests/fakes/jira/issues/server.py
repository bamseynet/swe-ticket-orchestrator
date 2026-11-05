"""An in-process fake of Jira Cloud's issue REST API (v3): issues, JQL search, comments, ADF,
paging, rate limits and errors (D6-01).

This is a SERVER, not an adapter. It has no port and holds no real credential: every site,
account, email and token is synthetic. An adapter under test talks to ``FakeJiraIssues.request``
as it would talk to ``https://<site>/rest/api/3``. Each behaviour names the page that documents it
(``SOURCES`` maps each operation to its page) or the v3 OpenAPI schema it follows, or says
"unsourced" where neither does; the live suite (D12) later proves all of it against the real
service, and when they disagree the fake is wrong. Transitions and workflows are D6-09's.

Sources (all under https://developer.atlassian.com/cloud/jira/platform/):
* issues: rest/v3/api-group-issues/ (create, get, edit; ``issueIdOrKey`` is an ID or a key)
* search: rest/v3/api-group-issue-search/ (``POST /search/jql``)
* comments: rest/v3/api-group-issue-comments/
* ADF: apis/document/structure/ (see ``adf.py``); JQL: jira-query-language/ (see ``jql.py``)
* limits: rate-limiting/ (429, ``Retry-After``, ``RateLimit-Reason``)
* auth: basic-auth-for-rest-apis/ (email plus API token) and oauth-2-3lo-apps/ (bearer)
* the OpenAPI document, https://dac-static.atlassian.com/cloud/jira/platform/swagger-v3.v3.json,
  cited below as "spec": ``SearchAndReconcileRequestBean`` (additionalProperties false; keys
  jql, maxResults default 50, nextPageToken, fields default ``id``, and five more),
  ``SearchAndReconcileResults`` (the token "will expire in 7 days"), ``IssueUpdateDetails``
  ("fields included in here cannot be included in update"), the comment ``orderBy`` enum
  (created, -created, +created) and comment ``maxResults`` default 100.

Known departures, each deliberate:

* Error bodies are Jira's ``{"errorMessages": [...], "errors": {...}}`` (documented). Texts
  quoted from Jira, not the docs, are unsourced, observed behaviour to prove live: the 400 texts
  for unknown fields, labels with spaces, invalid priority, issue type or user, summary length,
  unknown JQL operators, unbounded JQL, bad page tokens and bad comment bodies; the 404 text for
  a missing comment. A JQL value that does not exist is a 400 here and may not be in Jira (see
  ``jql.py``: the v3 spec has no ``validateQuery`` on ``/search/jql``): unsourced, for D12.
* The 401 body is ``{"message": ...}`` with no ``WWW-Authenticate`` header: unsourced, and
  different in shape from the errorMessages body.
* The site is ``HOST``. 3LO calls go to ``api.atlassian.com/ex/jira/{cloudId}/rest/api/3``
  instead; that base URL is not modelled and D6-02 adds it.
* Search with the default ``fields`` returns ``{"id": ...}`` only (spec: default ``id``). With
  any other field it returns id, key, self and ``fields``. The last page omits ``nextPageToken``
  (the spec says null; omission and null both read as absent). ``maxResults`` is capped at 100
  here (the spec allows far more, and says fewer may be returned). The default order is issue ID
  ascending, and equal issues stay in ID ascending order whatever the direction (unsourced).
* Paging is a keyset: the token holds the sort position of the last issue returned, and the next
  page is every matching issue that sorts strictly after that position, whether or not the last
  issue still matches. So nothing already returned is repeated, and an issue that sorts after the
  position (created mid-paging under ``ORDER BY created ASC``) is returned; one that sorts
  before it (created mid-paging under ``DESC``) is not. Real tokens are opaque (unsourced); the
  fake's search is immediately consistent (the real one is eventually consistent, unsourced).
* The comment ``maxResults`` cap of 100 is unsourced (the spec names none).
* Unsourced limits of the fake: issue keys in the path are case-sensitive (``syn-1`` is a 404);
  on create, project and issue type take an exact key/name or a string ID (a lowercase project
  key or an integer ID is a 400), and assignee takes ``accountId`` only (``{"id": ...}`` is a
  400); JQL ``summary ~`` is a substring match.
* A denied project (``deny_project``) is a 404 on direct access and absent from search.
* The rate budget is a count per sixty seconds of fake time (``budget``, unlimited by default);
  Jira publishes no numbers. Only the 429-with-``Retry-After`` shape is modelled, as in the
  contract suite's ``CAPABILITIES``.
* Refused as "not modelled" (400), never answered wrongly: ``expand``, ``properties``,
  ``fieldsByKeys``, ``includeArchivedProjects`` and ``reconcileIssues`` on search; ``expand`` and
  ``properties`` on get; ``transition`` and ``properties`` on edit; comment ``visibility`` and
  ``properties``; edit operations other than add/remove/set on labels and set elsewhere; fields
  beyond summary, description, labels, assignee and priority (and project and issuetype on
  create): standard Jira fields get a "not modelled" message and the rest Jira's "unknown" text;
  ``expand`` on edit and on comment create and update; ``updateHistory`` on create; issue
  deletion, attachments, worklogs, GET search. ``returnIssue=true`` on edit is modelled (200
  with the issue, spec).
* The fake does not sanitise ADF: links, mentions and media are stored verbatim.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json as jsonlib
import math
import time
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any

from contract.suite import RateShape
from fakes.jira.issues.adf import adf_error
from fakes.jira.issues.jql import (
    FIELDS,
    STANDARD_FIELDS,
    JqlError,
    Resolver,
    compare,
    parse,
    sort_key,
)

HOST = "https://synthetic-site.atlassian.test"  # a reserved TLD: never a real host
ACCOUNT_ID = "5bsynthetic0001"  # the account the credentials act as
OTHER_ACCOUNT_ID = "5bsynthetic0002"  # a second account that exists
EMAIL = "bot@example.test"
API_TOKEN = "synthetic-api-token"
BASIC = "Basic " + base64.b64encode(f"{EMAIL}:{API_TOKEN}".encode()).decode()
BEARER = "Bearer synthetic-oauth-1"
PROJECTS: Mapping[str, str] = {"SYN": "10000", "OTH": "10100"}  # key -> ID
ISSUE_TYPES: Mapping[str, str] = {"Task": "10001", "Bug": "10002", "Story": "10003"}  # name -> ID
PRIORITIES: Mapping[str, str] = {
    "Highest": "1",
    "High": "2",
    "Medium": "3",
    "Low": "4",
    "Lowest": "5",
}
DEFAULT_STATUSES: Mapping[str, str] = {"To Do": "10000", "In Progress": "3", "Done": "10001"}
DEFAULT_SEARCH_PAGE = 50  # spec: SearchAndReconcileRequestBean.maxResults default
DEFAULT_COMMENT_PAGE = 100  # spec: comment maxResults default
MAX_RESULTS = 100
RATE_WINDOW = 60.0  # seconds of fake time
PAGE_TOKEN_TTL = 7 * 24 * 3600.0  # spec: "This token will expire in 7 days."
EPOCH = 1_767_225_600.0  # 2026-01-01T00:00:00Z

_BASE = "https://developer.atlassian.com/cloud/jira/platform"
_CMT = f"{_BASE}/rest/v3/api-group-issue-comments/#api-rest-api-3-issue-issueidorkey-comment"
SOURCES: Mapping[str, str] = {
    "create_issue": f"{_BASE}/rest/v3/api-group-issues/#api-rest-api-3-issue-post",
    "get_issue": f"{_BASE}/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-get",
    "edit_issue": f"{_BASE}/rest/v3/api-group-issues/#api-rest-api-3-issue-issueidorkey-put",
    "search": f"{_BASE}/rest/v3/api-group-issue-search/#api-rest-api-3-search-jql-post",
    "list_comments": f"{_CMT}-get",
    "add_comment": f"{_CMT}-post",
    "get_comment": f"{_CMT}-id-get",
    "update_comment": f"{_CMT}-id-put",
    "adf": f"{_BASE}/apis/document/structure/",
    "jql": f"{_BASE}/jira-query-language/",
    "rate_limits": f"{_BASE}/rate-limiting/",
    "auth_basic": f"{_BASE}/basic-auth-for-rest-apis/",
    "auth_oauth": f"{_BASE}/oauth-2-3lo-apps/",
}
_STATUS_CATEGORY = {"to do": "new", "in progress": "indeterminate", "done": "done"}
_NOT_FOUND = "Issue does not exist or you do not have permission to see it."
_SEARCH_KEYS = frozenset({"jql", "maxResults", "nextPageToken", "fields"})
_SEARCH_UNMODELLED = frozenset(
    {"expand", "fieldsByKeys", "includeArchivedProjects", "properties", "reconcileIssues"}
)
_ORDER_BY = ("created", "-created", "+created")
_UNKNOWN_FIELD = "Field '{}' cannot be set. It is not on the appropriate screen, or unknown."
_UNMODELLED_FIELD = "Field '{}' is a standard Jira field that the fake Jira does not model."


def _field_problem(name: str) -> str:
    """Why ``name`` cannot be set: standard fields are not modelled, the rest are unknown."""
    if name.casefold() in STANDARD_FIELDS | {"reporter", "project", "issuetype"}:
        return _UNMODELLED_FIELD.format(name)
    return _UNKNOWN_FIELD.format(name)


_ADF_BAD = "Operation value must be an Atlassian Document"


class Headers(Mapping[str, str]):
    """Response headers, looked up case-insensitively (HTTP header names are)."""

    def __init__(self, items: Mapping[str, str] | None = None) -> None:
        self._items = {k.casefold(): (k, v) for k, v in (items or {}).items()}

    def __getitem__(self, name: str) -> str:
        return self._items[name.casefold()][1]

    def __iter__(self) -> Iterator[str]:
        return (k for k, _ in self._items.values())

    def __len__(self) -> int:
        return len(self._items)


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: Any


def _err(status: int, *messages: str, **errors: str) -> Response:
    return Response(status, Headers(), {"errorMessages": list(messages), "errors": errors})


def _errors(status: int, errors: Mapping[str, str]) -> Response:
    return Response(status, Headers(), {"errorMessages": [], "errors": dict(errors)})


def _iso(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(seconds))) + ".000+0000"


def _int(raw: Any, default: int) -> int | None:
    """``raw`` as an integer, ``default`` when absent, None when it is not an integer."""
    if raw is None:
        return default
    if isinstance(raw, bool | float):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _flag(raw: Any) -> bool | None:
    """A boolean query parameter: false when absent, None when it is not true or false."""
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    return {"true": True, "false": False}.get(str(raw).casefold())


def _not_modelled(what: str) -> Response:
    return _err(400, f"Not modelled by the fake Jira: {what}.")


class FakeJiraIssues(Resolver):
    """Issues, search, comments and ADF behind a REST-shaped ``request``, with controls to seed
    state and to provoke every failure."""

    def __init__(self) -> None:
        self.now = EPOCH
        self.budget: int | None = None
        self.counts: Counter[str] = Counter()
        self._issues: dict[str, dict[str, Any]] = {}
        self._by_id: dict[str, dict[str, Any]] = {}
        self._comments: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._next_id, self._next_comment = 10_000, 20_000
        self._project_seq: Counter[str] = Counter()
        self._statuses = {name.casefold(): ident for name, ident in DEFAULT_STATUSES.items()}
        self._priorities = dict(PRIORITIES)
        self._accounts = {ACCOUNT_ID, OTHER_ACCOUNT_ID}
        self._denied: set[str] = set()
        self._bearers = {"synthetic-oauth-1"}
        self._bearer_n = 1
        self._auth_ok = True
        self._page_epoch = 0
        self._used, self._window_end = 0, 0.0
        self._limited = 0
        self._limit_op: str | None = None
        self._plain: defaultdict[str, list[int]] = defaultdict(list)
        self._faults: defaultdict[str, list[list[Any]]] = defaultdict(list)
        self._lose = False

    # --- seeding and controls -------------------------------------------------------------

    def add_issue(
        self,
        *,
        summary: str,
        project: str = "SYN",
        status: str = "To Do",
        labels: list[str] | None = None,
        assignee: str | None = ACCOUNT_ID,
        issuetype: str = "Task",
        priority: str = "Medium",
        description: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Seed an issue directly (no validation: this is the test's own state)."""
        self._project_seq[project] += 1
        self._next_id += 1
        key = f"{project}-{self._project_seq[project]}"
        stamp = _iso(self.now)
        self.add_status(status)
        if priority not in self._priorities:
            self.add_priority(priority)
        if assignee:
            self._accounts.add(assignee)
        issue: dict[str, Any] = {
            "id": str(self._next_id),
            "key": key,
            "self": f"{HOST}/rest/api/3/issue/{self._next_id}",
            "fields": {
                "summary": summary,
                "description": description,
                "project": {"key": project, "id": PROJECTS.get(project, "10999")},
                "status": {
                    "name": status,
                    "id": self._statuses[status.casefold()],
                    "statusCategory": {"key": _STATUS_CATEGORY.get(status.casefold(), "new")},
                },
                "issuetype": {"name": issuetype, "id": ISSUE_TYPES.get(issuetype, "10999")},
                "priority": {"name": priority, "id": self._priorities[priority]},
                "labels": list(labels or []),
                "assignee": {"accountId": assignee} if assignee else None,
                "reporter": {"accountId": ACCOUNT_ID},
                "created": stamp,
                "updated": stamp,
            },
        }
        self._issues[key] = issue
        self._by_id[issue["id"]] = issue
        self.now += 1  # every issue gets its own created time, so ORDER BY created is total
        return issue

    def add_status(self, name: str, ident: str | None = None) -> None:
        """Register a status (so JQL may name it) without creating an issue in it."""
        ident = ident or str(10_100 + len(self._statuses))
        self._statuses.setdefault(name.casefold(), ident)

    def add_priority(self, name: str, ident: str | None = None) -> None:
        """Register a priority; it sorts below Lowest under ORDER BY priority."""
        self._priorities.setdefault(name, ident or str(10 + len(self._priorities)))

    def add_account(self, account_id: str) -> None:
        """Register an account (assignable, and usable in JQL) without an issue."""
        self._accounts.add(account_id)

    def deny_project(self, project: str) -> None:
        self._denied.add(project)

    def new_bearer(self) -> str:
        """A fresh OAuth access token (what a 3LO refresh returns), as an Authorization value."""
        self._bearer_n += 1
        self._bearers.add(f"synthetic-oauth-{self._bearer_n}")
        return f"Bearer synthetic-oauth-{self._bearer_n}"

    def expire_bearer(self) -> None:
        self._bearers.clear()

    def revoke_auth(self) -> None:
        self._auth_ok = False

    def restore_auth(self) -> None:
        self._auth_ok = True

    def expire_page_tokens(self) -> None:
        self._page_epoch += 1

    def rate_limit_next(self, times: int, shape: RateShape, op: str | None = None) -> None:
        if shape is not RateShape.PRIMARY_429:
            raise ValueError("Jira is modelled with the 429 plus Retry-After shape only")
        self._limited, self._limit_op = times, op

    def respond_next(self, op: str, status: int) -> None:
        """The next ``op`` is answered with a plain ``status`` (unsourced body)."""
        self._plain[op].append(status)

    def fault_next(self, op: str, mode: str, page: int | None = None) -> None:
        """The next ``op`` (for search, only page ``page``, one-based) suffers ``5xx``,
        ``timeout``, ``401`` or, for a write, ``lose`` (applied, caller sees a timeout)."""
        self._faults[op].append([mode, page])

    # --- JQL values (Resolver) --------------------------------------------------------------

    def resolve(self, field: str, raw: str) -> str | None:
        folded = raw.casefold()
        if field == "project":
            for key, ident in PROJECTS.items():
                if folded in (key.casefold(), ident):
                    return key.casefold()
        elif field == "issuetype":
            for name, ident in ISSUE_TYPES.items():
                if folded in (name.casefold(), ident):
                    return name.casefold()
        elif field == "priority":
            for name, ident in self._priorities.items():
                if folded in (name.casefold(), ident):
                    return name.casefold()
        elif field == "status":
            for name, ident in self._statuses.items():
                if folded in (name, ident):
                    return name
        elif field in ("assignee", "reporter"):
            return folded if raw in self._accounts else None
        return None

    # --- the API --------------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        auth: str | None = None,
        params: Mapping[str, Any] | None = None,
        json: Any = None,  # noqa: A002 - the HTTP client's own name; any JSON value
    ) -> Response:
        params, body = params or {}, ({} if json is None else json)
        route = self._route(method.upper(), path)
        if route is None:
            if not self._check_auth(auth):  # authentication comes before routing
                self.counts["unauthorized"] += 1
                return self._unauthorized()
            return _err(404, "Not Found")
        op, args = route
        sent = body.get("nextPageToken") if isinstance(body, Mapping) else None
        early = self._preflight(op, auth, self._token_page(sent))
        if early is not None:
            return early
        if not isinstance(body, Mapping):  # the API takes a JSON object
            result: Response = _err(400, "Request body must be a JSON object.")
        else:
            result = getattr(self, f"_{op}")(*args, params=params, body=body)
        lose, self._lose = self._lose, False  # a planted loss applies to this request only
        if lose and result.status < 300:
            raise TimeoutError("response lost")
        return result

    @staticmethod
    def _route(method: str, path: str) -> tuple[str, tuple[str, ...]] | None:
        prefix = "/rest/api/3/"
        if not path.startswith(prefix):
            return None
        parts = path.removeprefix(prefix).strip("/").split("/")
        if parts == ["search", "jql"]:
            return ("search", ()) if method == "POST" else None
        if parts[0] != "issue":
            return None
        shapes: dict[tuple[str, tuple[str, ...]], str] = {
            ("POST", ()): "create_issue",
            ("GET", ("ref",)): "get_issue",
            ("PUT", ("ref",)): "edit_issue",
            ("GET", ("ref", "comment")): "list_comments",
            ("POST", ("ref", "comment")): "add_comment",
            ("GET", ("ref", "comment", "id")): "get_comment",
            ("PUT", ("ref", "comment", "id")): "update_comment",
        }
        rest = parts[1:]
        shape = tuple(name for name, part in zip(("ref", "comment", "id"), rest, strict=False))
        if len(rest) >= 2 and rest[1] != "comment":
            return None
        op = shapes.get((method, shape))
        if op is None or len(rest) > 3:
            return None
        return op, tuple(rest[0:1] + rest[2:3])

    def _check_auth(self, auth: str | None) -> bool:
        if not self._auth_ok or not auth:
            return False
        scheme, _, credential = auth.partition(" ")
        if scheme.casefold() == "basic":
            return credential == BASIC.partition(" ")[2]
        return scheme.casefold() == "bearer" and credential in self._bearers

    def _preflight(self, op: str, auth: str | None, page: int) -> Response | None:
        self.counts[op] += 1
        if not self._check_auth(auth):
            self.counts["unauthorized"] += 1
            return self._unauthorized()
        if self._limited > 0 and self._limit_op in (None, op):
            self._limited -= 1
            return self._limit(30)
        if self.budget is not None:
            if self.now >= self._window_end:
                self._used, self._window_end = 0, self.now + RATE_WINDOW
            if self._used >= self.budget:
                return self._limit(max(1, int(self._window_end - self.now)))
            self._used += 1
        if self._plain[op]:
            return _err(self._plain[op].pop(0), "plain error")
        mode = self._take_fault(op, page)
        if mode == "5xx":
            return _err(503, "Service Unavailable")
        if mode == "401":
            return self._unauthorized()
        if mode == "timeout":
            raise TimeoutError("timed out")
        self._lose = mode == "lose"
        return None

    def _take_fault(self, op: str, page: int) -> str:
        for entry in self._faults[op]:
            if entry[1] is not None and entry[1] != page:
                continue
            self._faults[op].remove(entry)
            return str(entry[0])
        return ""

    @staticmethod
    def _unauthorized() -> Response:
        # unsourced, observed behaviour to prove live (see the departures)
        message = "Client must be authenticated to access this resource."
        return Response(401, Headers(), {"message": message})

    def _limit(self, seconds: int) -> Response:
        """https://developer.atlassian.com/cloud/jira/platform/rate-limiting/ : a 429 with
        ``Retry-After`` (seconds) and ``RateLimit-Reason`` naming which limit tripped."""
        self.counts["limited"] += 1
        headers = Headers({"Retry-After": str(seconds), "RateLimit-Reason": "jira-burst-based"})
        return Response(429, headers, {"errorMessages": ["Rate limit exceeded."], "errors": {}})

    # --- issues ---------------------------------------------------------------------------

    def _visible(self, ref: str) -> dict[str, Any] | None:
        """``issueIdOrKey`` (spec): a numeric ID or a key."""
        issue = self._by_id.get(ref) if ref.isdigit() else self._issues.get(ref)
        if issue is None or issue["fields"]["project"]["key"] in self._denied:
            return None
        return issue

    @staticmethod
    def _field_list(raw: Any) -> list[str] | None:
        if raw is None:
            return None
        if isinstance(raw, str):
            return [f.strip() for f in raw.split(",") if f.strip()]
        return [str(f) for f in raw]

    @staticmethod
    def _select(fields: dict[str, Any], wanted: list[str] | None) -> dict[str, Any]:
        """The ``fields`` parameter: names, ``*all``/``*navigable``, and ``-name`` to exclude."""
        if wanted is None:
            return dict(fields)
        names = [w for w in wanted if w != "id"]
        excluded = {w[1:] for w in names if w.startswith("-")}
        included = [w for w in names if not w.startswith("-")]
        everything = "*all" in included or "*navigable" in included or (not included and excluded)
        return {
            k: v for k, v in fields.items() if (everything or k in included) and k not in excluded
        }

    def _get_issue(self, ref: str, *, params: Mapping[str, Any], body: Any) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, _NOT_FOUND)
        for name in ("expand", "properties"):
            if name in params:
                return _not_modelled(f"'{name}' on get issue")
        if params.get("fieldsByKeys") not in (None, False, "false"):
            return _not_modelled("'fieldsByKeys' on get issue")
        wanted = self._field_list(params.get("fields"))
        return Response(200, Headers(), {**issue, "fields": self._select(issue["fields"], wanted)})

    def _check_fields(
        self, fields: Mapping[str, Any], *, creating: bool
    ) -> tuple[dict[str, str], dict[str, Any]]:
        """Validate ``fields`` and resolve them: (errors by field, resolved values by field).
        Unknown fields, blank summaries, labels with spaces, unknown priorities, issue types,
        projects and users are errors."""
        errors: dict[str, str] = {}
        values: dict[str, Any] = {}
        settable = {"summary", "description", "labels", "assignee", "priority"}
        if creating:
            settable |= {"project", "issuetype"}
        for name in fields:
            if name not in settable:
                errors[name] = _field_problem(name)
        if creating:
            self._check_project(fields, errors, values)
            self._check_issuetype(fields, errors, values)
        if "summary" in fields or creating:
            summary = fields.get("summary")
            if not isinstance(summary, str) or not summary.strip():
                errors["summary"] = "You must specify a summary of the issue."
            elif len(summary) > 255:
                errors["summary"] = "Summary must be less than 255 characters."
            else:
                values["summary"] = summary
        if "description" in fields:
            desc = fields["description"]
            if desc is not None and adf_error(desc, require_content=False):
                errors["description"] = _ADF_BAD
            else:
                values["description"] = desc
        if "labels" in fields:
            self._check_labels(fields["labels"], errors, values)
        if "assignee" in fields:
            self._check_assignee(fields["assignee"], errors, values)
        if "priority" in fields:
            self._check_priority(fields["priority"], errors, values)
        return errors, values

    @staticmethod
    def _check_project(
        fields: Mapping[str, Any], errors: dict[str, str], values: dict[str, Any]
    ) -> None:
        ref = fields.get("project")
        ref = ref if isinstance(ref, dict) else {}
        for key, ident in PROJECTS.items():
            if ref.get("key") == key or ref.get("id") == ident:
                values["project"] = key
                return
        errors["project"] = "valid project is required"

    @staticmethod
    def _check_issuetype(
        fields: Mapping[str, Any], errors: dict[str, str], values: dict[str, Any]
    ) -> None:
        ref = fields.get("issuetype")
        ref = ref if isinstance(ref, dict) else {}
        for name, ident in ISSUE_TYPES.items():
            if ref.get("name") == name or ref.get("id") == ident:
                values["issuetype"] = name
                return
        errors["issuetype"] = "valid issue type is required"

    @staticmethod
    def _check_labels(raw: Any, errors: dict[str, str], values: dict[str, Any]) -> None:
        if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
            errors["labels"] = "Operation value must be an array of non-empty strings"
            return
        spaced = next((x for x in raw if any(c.isspace() for c in x)), None)
        if spaced is not None:
            errors["labels"] = f"The label '{spaced}' contains spaces."
            return
        values["labels"] = list(dict.fromkeys(raw))

    def _check_assignee(self, raw: Any, errors: dict[str, str], values: dict[str, Any]) -> None:
        if raw is None:
            values["assignee"] = None
        elif not isinstance(raw, dict) or not isinstance(raw.get("accountId"), str):
            errors["assignee"] = "Operation value must be a user object with an accountId"
        elif raw["accountId"] not in self._accounts:
            errors["assignee"] = f"User '{raw['accountId']}' does not exist."
        else:
            values["assignee"] = raw["accountId"]

    def _check_priority(self, raw: Any, errors: dict[str, str], values: dict[str, Any]) -> None:
        priorities = self._priorities
        ref = raw if isinstance(raw, dict) else {}
        for name, ident in priorities.items():
            if ref.get("name") == name or ref.get("id") == ident:
                values["priority"] = name
                return
        errors["priority"] = "The priority selected is invalid."

    def _create_issue(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        fields = body.get("fields")
        if not isinstance(fields, dict):
            return _err(400, "Request body must contain 'fields'.")
        if "updateHistory" in params:
            return _not_modelled("'updateHistory' on create")
        if body.get("transition") is not None or body.get("properties") is not None:
            return _not_modelled("'transition' and 'properties' on create")
        errors, values = self._check_fields(fields, creating=True)
        if errors:
            return _errors(400, errors)
        issue = self.add_issue(
            summary=values["summary"],
            project=values["project"],
            issuetype=values["issuetype"],
            labels=values.get("labels"),
            assignee=values.get("assignee"),
            priority=values.get("priority", "Medium"),
            description=values.get("description"),
        )
        shown = {"id": issue["id"], "key": issue["key"], "self": issue["self"]}
        return Response(201, Headers(), shown)

    def _edit_issue(
        self, ref: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, _NOT_FOUND)
        if "expand" in params:
            return _not_modelled("'expand' on edit")
        return_issue = _flag(params.get("returnIssue"))
        if return_issue is None:
            return _err(400, "'returnIssue' must be true or false.")
        if body.get("transition") is not None or body.get("properties") is not None:
            return _not_modelled("'transition' and 'properties' on edit")
        fields, update = body.get("fields") or {}, body.get("update") or {}
        if not isinstance(fields, dict) or not isinstance(update, dict):
            return _err(400, "'fields' and 'update' must be objects.")
        both = {
            name: f"Field '{name}' cannot be in both 'fields' and 'update'."
            for name in fields.keys() & update.keys()
        }  # spec: IssueUpdateDetails, "fields included in here cannot be included in update"
        if both:
            return _errors(400, both)
        changes, errors = dict(fields), {}
        for name, operations in update.items():
            problem = self._apply_operations(name, operations, issue, changes)
            if problem:
                errors[name] = problem
        checked, values = self._check_fields(changes, creating=False)
        errors = {**errors, **checked}
        if errors:  # nothing is applied unless everything is valid
            return _errors(400, errors)
        target = issue["fields"]
        for name, value in values.items():
            if name == "assignee":
                target[name] = {"accountId": value} if value else None
            elif name == "priority":
                target[name] = {"name": value, "id": self._priorities[value]}
            else:
                target[name] = value
        self._touch(issue)
        if return_issue:  # spec: returnIssue gives the edited issue, in the Get issue format
            return Response(200, Headers(), issue)
        return Response(204, Headers(), None)

    @staticmethod
    def _apply_operations(
        name: str, operations: Any, issue: dict[str, Any], changes: dict[str, Any]
    ) -> str | None:
        """Fold ``update[name]`` (a list of ``{op: value}``) into ``changes``; an error text or
        None. Labels take add, remove and set; summary, description, assignee and priority set."""
        if name not in {"summary", "description", "labels", "assignee", "priority"}:
            return _field_problem(name)
        if not isinstance(operations, list) or not all(
            isinstance(o, dict) and len(o) == 1 for o in operations
        ):
            return "Operation value must be an array of single-operation objects"
        allowed = {"add", "remove", "set"} if name == "labels" else {"set"}
        current = list(changes.get("labels", issue["fields"]["labels"]))
        for operation in operations:
            ((verb, value),) = operation.items()
            if verb not in allowed:
                return f"Not modelled by the fake Jira: operation '{verb}' on '{name}'"
            if name != "labels":
                changes[name] = value
            elif verb == "set":
                if not isinstance(value, list):
                    return "Operation value must be an array of labels"
                current = list(value)
            elif verb == "add":
                current += [value] if value not in current else []
            else:
                current = [x for x in current if x != value]
            if name == "labels":
                changes["labels"] = current
        return None

    def _touch(self, issue: dict[str, Any]) -> None:
        self.now += 1
        issue["fields"]["updated"] = _iso(self.now)

    # --- search ---------------------------------------------------------------------------

    def _decode(self, token: Any) -> dict[str, Any] | None:
        """A page token's contents, or None when it is not one this fake issued (or not valid)."""
        if not isinstance(token, str):
            return None
        try:
            data = jsonlib.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        except (ValueError, TypeError, binascii.Error):
            return None
        if not isinstance(data, dict):
            return None
        page, issued = data.get("p"), data.get("t")
        good = (
            isinstance(data.get("q"), str)
            and isinstance(data.get("e"), int)
            and not isinstance(data.get("e"), bool)
            and isinstance(page, int)
            and not isinstance(page, bool)
            and page >= 1
            and isinstance(issued, int | float)
            and math.isfinite(issued)
            and isinstance(data.get("k"), list)
        )
        return data if good else None

    def _token_page(self, token: Any) -> int:
        """The page a token leads to, for fault matching; 1 for none or an invalid one."""
        decoded = self._decode(token)
        return int(decoded["p"]) + 1 if decoded else 1

    def _search(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        bad = self._search_body_problem(body)
        if bad is not None:
            return bad
        jql = str(body.get("jql", ""))
        try:
            query = parse(jql, self)
        except JqlError as exc:
            return _err(400, str(exc))
        if not query.bounded:
            return _err(
                400,
                "Unbounded JQL queries are not allowed here. "
                "Please add a search restriction to your query.",
            )
        size = min(_int(body.get("maxResults"), DEFAULT_SEARCH_PAGE) or 1, MAX_RESULTS)
        digest = hashlib.sha256(jql.encode()).hexdigest()[:12]
        position, page = None, 1
        if body.get("nextPageToken") is not None:
            tok = self._decode(body["nextPageToken"])
            expired = tok is not None and self.now - tok["t"] > PAGE_TOKEN_TTL
            if tok is None or tok["q"] != digest or tok["e"] != self._page_epoch or expired:
                return _err(400, "Invalid request payload. Refer to the REST API documentation.")
            position, page = tok["k"], tok["p"] + 1
            last = position[-1] if position else None
            well_formed = isinstance(last, int) and not isinstance(last, bool)
            if len(position) != len(query.order) + 1 or not well_formed:
                return _err(400, "Invalid request payload. Refer to the REST API documentation.")
        rows = [
            i
            for i in self._issues.values()
            if i["fields"]["project"]["key"] not in self._denied and query.matches(i)
        ]
        order = query.order
        rows.sort(
            key=cmp_to_key(lambda a, b: compare(sort_key(a, order), sort_key(b, order), order))
        )
        if position is not None:  # continue after the last position, match or not
            try:
                rows = [r for r in rows if compare(sort_key(r, order), position, order) > 0]
            except (IndexError, TypeError):  # a forged position of the wrong shape
                return _err(400, "Invalid request payload. Refer to the REST API documentation.")
        chunk, more = rows[:size], len(rows) > size
        wanted = self._field_list(body.get("fields")) or ["id"]
        out: dict[str, Any] = {"issues": [self._search_issue(i, wanted) for i in chunk]}
        out["isLast"] = not more
        if more:
            token = {
                "q": digest,
                "e": self._page_epoch,
                "p": page,
                "t": self.now,
                "k": sort_key(chunk[-1], order),
            }
            raw = jsonlib.dumps(token).encode()
            out["nextPageToken"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return Response(200, Headers(), out)

    def _search_issue(self, issue: dict[str, Any], wanted: list[str]) -> dict[str, Any]:
        """Spec: ``fields`` defaults to ``id``, which returns only issue IDs."""
        if set(wanted) <= {"id"}:
            return {"id": issue["id"]}
        shown = self._select(issue["fields"], [w for w in wanted if w != "id"])
        return {"id": issue["id"], "key": issue["key"], "self": issue["self"], "fields": shown}

    def _search_body_problem(self, body: Mapping[str, Any]) -> Response | None:
        """Spec: SearchAndReconcileRequestBean has additionalProperties false."""
        unknown = sorted(set(body) - _SEARCH_KEYS - _SEARCH_UNMODELLED)
        if unknown:
            return _err(400, f"Unrecognized field '{unknown[0]}' in the search request.")
        unmodelled = sorted(set(body) & _SEARCH_UNMODELLED)
        if unmodelled:
            return _not_modelled(f"'{unmodelled[0]}' on search")
        if "jql" in body and not isinstance(body["jql"], str):
            return _err(400, "'jql' must be a string.")
        size = _int(body.get("maxResults"), DEFAULT_SEARCH_PAGE)
        if size is None or size < 1:
            return _err(400, "The 'maxResults' parameter must be a positive integer.")
        if "nextPageToken" in body and not isinstance(body["nextPageToken"], str | None):
            return _err(400, "'nextPageToken' must be a string.")
        fields = body.get("fields")
        if fields is not None and not (
            isinstance(fields, str)
            or (isinstance(fields, list) and all(isinstance(f, str) for f in fields))
        ):
            return _err(400, "'fields' must be an array of strings.")
        return None

    # --- comments -------------------------------------------------------------------------

    @staticmethod
    def _comment_body_problem(body: Mapping[str, Any]) -> Response | None:
        for name in ("visibility", "properties"):
            if body.get(name) is not None:
                return _not_modelled(f"'{name}' on a comment")
        if adf_error(body.get("body"), require_content=True):
            return _err(400, "Comment body is not valid!")
        return None

    def _list_comments(self, ref: str, *, params: Mapping[str, Any], body: Any) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, _NOT_FOUND)
        if "expand" in params:
            return _not_modelled("'expand' on comments")
        start = _int(params.get("startAt"), 0)
        size = _int(params.get("maxResults"), DEFAULT_COMMENT_PAGE)
        if start is None or start < 0 or size is None or size < 1:
            return _err(400, "startAt must be 0 or more and maxResults 1 or more.")
        order = str(params.get("orderBy", "created"))
        if order not in _ORDER_BY:  # spec: enum created, -created, +created
            return _err(400, f"'orderBy' must be one of {', '.join(_ORDER_BY)}.")
        size = min(size, MAX_RESULTS)
        ordered = list(self._comments[issue["key"]])
        if order == "-created":
            ordered.reverse()
        shown = {
            "startAt": start,
            "maxResults": size,
            "total": len(ordered),
            "comments": ordered[start : start + size],
        }
        return Response(200, Headers(), shown)

    def _add_comment(
        self, ref: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, _NOT_FOUND)
        if "expand" in params:
            return _not_modelled("'expand' on comment create")
        problem = self._comment_body_problem(body)
        if problem is not None:
            return problem
        self._next_comment += 1
        self.now += 1
        stamp = _iso(self.now)
        who = {"accountId": ACCOUNT_ID, "displayName": "Synthetic Bot"}
        comment = {
            "id": str(self._next_comment),
            "self": f"{HOST}/rest/api/3/issue/{issue['id']}/comment/{self._next_comment}",
            "author": who,
            "updateAuthor": who,
            "body": body["body"],
            "created": stamp,
            "updated": stamp,
        }
        self._comments[issue["key"]].append(comment)
        issue["fields"]["updated"] = stamp  # a comment is activity on the issue
        return Response(201, Headers(), comment)

    def _find_comment(self, ref: str, cid: str) -> dict[str, Any] | None:
        issue = self._visible(ref)
        if issue is None:
            return None
        return next((c for c in self._comments[issue["key"]] if c["id"] == cid), None)

    def _get_comment(self, ref: str, cid: str, *, params: Mapping[str, Any], body: Any) -> Response:
        comment = self._find_comment(ref, cid)
        if comment is None:
            return _err(404, "Can not find comment with id " + cid)
        return Response(200, Headers(), comment)

    def _update_comment(
        self, ref: str, cid: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        comment = self._find_comment(ref, cid)
        if comment is None:
            return _err(404, "Can not find comment with id " + cid)
        if "expand" in params:
            return _not_modelled("'expand' on comment update")
        problem = self._comment_body_problem(body)
        if problem is not None:
            return problem
        self.now += 1
        comment["body"], comment["updated"] = body["body"], _iso(self.now)
        issue = self._visible(ref)
        if issue is not None:
            issue["fields"]["updated"] = comment["updated"]
        return Response(200, Headers(), comment)


__all__ = ["FIELDS", "FakeJiraIssues", "Headers", "RateShape", "Response"]
