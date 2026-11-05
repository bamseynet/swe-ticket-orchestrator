"""An in-process fake of Jira Cloud's issue REST API (v3): issues, JQL search, comments, ADF,
paging, rate limits and errors (D6-01).

This is a SERVER, not an adapter. It has no port and holds no real credential: every site,
account, email and token is synthetic. An adapter under test talks to ``FakeJiraIssues.request``
as it would talk to ``https://<site>/rest/api/3``. Each behaviour names the page that documents it
(``SOURCES`` maps each operation to its page), or says "unsourced" where no page does; the live
suite (D12) later proves all of it against the real service, and when they disagree the fake is
wrong. Transitions and workflows are D6-09's, not here.

Sources (all under https://developer.atlassian.com/cloud/jira/platform/):
* issues: rest/v3/api-group-issues/ (create, get, edit)
* search: rest/v3/api-group-issue-search/ (``POST /search/jql``: ``nextPageToken``, ``isLast``,
  no ``total``, ``fields`` defaulting to ``id`` alone)
* comments: rest/v3/api-group-issue-comments/ (``startAt``/``maxResults``/``total``, ``orderBy``)
* ADF: apis/document/structure/ (see ``adf.py``)
* limits: rate-limiting/ (429, ``Retry-After``, ``RateLimit-Reason``)
* auth: basic-auth-for-rest-apis/ (email plus API token) and oauth-2-3lo-apps/ (bearer)

Known departures, each deliberate:

* Errors use Jira's body, ``{"errorMessages": [...], "errors": {...}}`` (documented). The exact
  texts are copied from Jira where the docs or community answers quote them, and are otherwise
  unsourced, observed behaviour to prove live: the 401 text, the unbounded-JQL text, the page
  token 400 text and the comment-body 400 text.
* Page-token paging is a keyset: the token holds the last issue returned, so an issue created
  mid-paging is neither skipped nor repeated. Real tokens are opaque and may behave differently
  under concurrent change; the fake's search is also immediately consistent (the real one is
  eventually consistent, unsourced).
* ``maxResults`` is capped at 100 and defaults to 50 on both surfaces (the 100 cap is unsourced;
  the 50 default is documented). Comment paging past the end is an empty 200 (unsourced).
* A denied project (``deny_project``) is a 404 on direct access and absent from search, as Jira
  hides what you may not see (documented in the 404 text).
* The rate budget is a count per sixty seconds of fake time (``budget``, unlimited by default);
  Jira publishes no numbers. Only the 429-with-``Retry-After`` shape is modelled, as in the
  contract suite's ``CAPABILITIES``.
* Not modelled: the ``expand`` parameter, ``properties``, attachments, worklogs, visibility
  restrictions on comments, issue deletion, and GET search (only ``POST /search/jql``).
* The fake does not sanitise ADF: links, mentions and media are stored verbatim.
"""

from __future__ import annotations

import base64
import hashlib
import json as jsonlib
import time
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from contract.suite import RateShape
from fakes.jira.issues.adf import adf_error
from fakes.jira.issues.jql import FIELDS, JqlError, field_values, parse

HOST = "https://synthetic-site.atlassian.test"  # a reserved TLD: never a real host
ACCOUNT_ID = "5bsynthetic0001"  # the account the credentials act as
EMAIL = "bot@example.test"
API_TOKEN = "synthetic-api-token"
BASIC = "Basic " + base64.b64encode(f"{EMAIL}:{API_TOKEN}".encode()).decode()
BEARER = "Bearer synthetic-oauth-1"
PROJECTS = ("SYN", "OTH")  # the projects that exist
DEFAULT_MAX = 50
MAX_RESULTS = 100
RATE_WINDOW = 60.0  # seconds of fake time
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
    "rate_limits": f"{_BASE}/rate-limiting/",
    "auth_basic": f"{_BASE}/basic-auth-for-rest-apis/",
    "auth_oauth": f"{_BASE}/oauth-2-3lo-apps/",
}
_STATUS_CATEGORY = {"to do": "new", "in progress": "indeterminate", "done": "done"}
_NOT_FOUND = "Issue does not exist or you do not have permission to see it."


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: Any


def _err(status: int, *messages: str, **errors: str) -> Response:
    return Response(status, {}, {"errorMessages": list(messages), "errors": errors})


def _iso(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(seconds))) + ".000+0000"


def _int(raw: Any, default: int) -> int | None:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default if raw is None else None


class FakeJiraIssues:
    """Issues, search, comments and ADF behind a REST-shaped ``request``, with controls to seed
    state and to provoke every failure."""

    def __init__(self) -> None:
        self.now = EPOCH
        self.budget: int | None = None
        self.counts: Counter[str] = Counter()
        self._issues: dict[str, dict[str, Any]] = {}
        self._comments: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._next_id, self._next_comment, self._project_seq = 10_000, 20_000, Counter[str]()
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
        self._project_seq[project] += 1
        self._next_id += 1
        key = f"{project}-{self._project_seq[project]}"
        stamp = _iso(self.now)
        issue = {
            "id": str(self._next_id),
            "key": key,
            "self": f"{HOST}/rest/api/3/issue/{self._next_id}",
            "fields": {
                "summary": summary,
                "description": description,
                "project": {"key": project, "name": f"Synthetic {project}"},
                "status": {
                    "name": status,
                    "statusCategory": {"key": _STATUS_CATEGORY.get(status.casefold(), "new")},
                },
                "issuetype": {"name": issuetype},
                "priority": {"name": priority},
                "labels": list(labels or []),
                "assignee": {"accountId": assignee} if assignee else None,
                "reporter": {"accountId": ACCOUNT_ID},
                "created": stamp,
                "updated": stamp,
            },
        }
        self._issues[key] = issue
        self.now += 1  # every issue gets its own created time, so ORDER BY created is total
        return issue

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

    # --- the API --------------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        auth: str | None = None,
        params: Mapping[str, Any] | None = None,
        json: Mapping[str, Any] | None = None,  # noqa: A002 - the HTTP client's own name
    ) -> Response:
        params, body = params or {}, json or {}
        route = self._route(method.upper(), path)
        if route is None:
            return _err(404, "Not Found")
        op, args = route
        page = 1
        if op == "search":
            page = 1 + self._token_page(body.get("nextPageToken"))
        early = self._preflight(op, auth, page)
        if early is not None:
            return early
        handler = getattr(self, f"_{op}")
        result: Response = handler(*args, params=params, body=body)
        if self._lose and result.status < 300:
            self._lose = False
            raise TimeoutError("response lost")
        return result

    @staticmethod
    def _route(method: str, path: str) -> tuple[str, tuple[str, ...]] | None:
        if not path.startswith("/rest/api/3/"):
            return None
        parts = path.removeprefix("/rest/api/3/").strip("/").split("/")
        table: dict[tuple[str, int, str], str] = {
            ("POST", 1, "issue"): "create_issue",
            ("GET", 2, "issue"): "get_issue",
            ("PUT", 2, "issue"): "edit_issue",
            ("POST", 2, "search"): "search",
            ("GET", 3, "comment"): "list_comments",
            ("POST", 3, "comment"): "add_comment",
            ("GET", 4, "comment"): "get_comment",
            ("PUT", 4, "comment"): "update_comment",
        }
        if parts[0] == "search" and parts[1:] == ["jql"]:
            return ("search", ()) if method == "POST" else None
        if parts[0] != "issue":
            return None
        shape = 4 if len(parts) == 4 else len(parts)
        marker = parts[2] if len(parts) >= 3 else "issue"
        op = table.get((method, shape, marker if shape >= 3 else "issue"))
        if op is None:
            return None
        return op, tuple(parts[1:2] + parts[3:4])

    def _check_auth(self, auth: str | None) -> bool:
        if not self._auth_ok or not auth:
            return False
        if auth == BASIC:
            return True
        return auth.startswith("Bearer ") and auth.removeprefix("Bearer ") in self._bearers

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
            return Response(503, {}, {"errorMessages": ["Service Unavailable"], "errors": {}})
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
        # unsourced, observed behaviour to prove live
        return Response(
            401, {}, {"message": "Client must be authenticated to access this resource."}
        )

    def _limit(self, seconds: int) -> Response:
        """https://developer.atlassian.com/cloud/jira/platform/rate-limiting/ : a 429 with
        ``Retry-After`` (seconds) and ``RateLimit-Reason`` naming which limit tripped."""
        self.counts["limited"] += 1
        headers = {"retry-after": str(seconds), "ratelimit-reason": "jira-burst-based"}
        return Response(429, headers, {"errorMessages": ["Rate limit exceeded."], "errors": {}})

    # --- issues ---------------------------------------------------------------------------

    def _visible(self, key: str) -> dict[str, Any] | None:
        issue = self._issues.get(key)
        if issue is None or issue["fields"]["project"]["key"] in self._denied:
            return None
        return issue

    @staticmethod
    def _shape(issue: dict[str, Any], wanted: list[str] | None) -> dict[str, Any]:
        shown = dict(issue)
        fields = issue["fields"]
        if wanted is None or "*all" in wanted or "*navigable" in wanted:
            return shown
        shown["fields"] = {k: v for k, v in fields.items() if k in wanted}
        return shown

    @staticmethod
    def _field_list(raw: Any) -> list[str] | None:
        if raw is None:
            return None
        if isinstance(raw, str):
            return [f for f in raw.split(",") if f]
        return [str(f) for f in raw]

    def _get_issue(self, key: str, *, params: Mapping[str, Any], body: Any) -> Response:
        issue = self._visible(key)
        if issue is None:
            return _err(404, _NOT_FOUND)
        return Response(200, {}, self._shape(issue, self._field_list(params.get("fields"))))

    def _fields_problem(self, fields: Mapping[str, Any], *, creating: bool) -> Response | None:
        if creating:
            project = (fields.get("project") or {}).get("key")
            if project not in PROJECTS:
                return _err(400, project="valid project is required")
            if not fields.get("summary"):
                return _err(400, summary="You must specify a summary of the issue.")
            if not (fields.get("issuetype") or {}).get("name"):
                return _err(400, issuetype="Specify an issue type")
        desc = fields.get("description")
        if desc is not None and adf_error(desc, require_content=False):
            return _err(400, description="Operation value must be an Atlassian Document")
        return None

    def _create_issue(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        fields = body.get("fields") or {}
        problem = self._fields_problem(fields, creating=True)
        if problem is not None:
            return problem
        assignee = (fields.get("assignee") or {}).get("accountId")
        issue = self.add_issue(
            summary=fields["summary"],
            project=fields["project"]["key"],
            labels=list(fields.get("labels") or []),
            assignee=assignee,
            issuetype=fields["issuetype"]["name"],
            priority=(fields.get("priority") or {}).get("name", "Medium"),
            description=fields.get("description"),
        )
        return Response(201, {}, {"id": issue["id"], "key": issue["key"], "self": issue["self"]})

    def _edit_issue(
        self, key: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        issue = self._visible(key)
        if issue is None:
            return _err(404, _NOT_FOUND)
        fields = body.get("fields") or {}
        problem = self._fields_problem(fields, creating=False)
        if problem is not None:
            return problem
        target = issue["fields"]
        for name in ("summary", "description", "labels"):
            if name in fields:
                target[name] = fields[name]
        if "assignee" in fields:
            who = (fields["assignee"] or {}).get("accountId")
            target["assignee"] = {"accountId": who} if who else None
        if "priority" in fields:
            target["priority"] = {"name": fields["priority"]["name"]}
        for op in (body.get("update") or {}).get("labels", []):
            if "add" in op and op["add"] not in target["labels"]:
                target["labels"].append(op["add"])
            if "remove" in op and op["remove"] in target["labels"]:
                target["labels"].remove(op["remove"])
        self.now += 1
        target["updated"] = _iso(self.now)
        return Response(204, {}, None)

    # --- search ---------------------------------------------------------------------------

    def _token_page(self, token: Any) -> int:
        decoded = self._decode(token)
        return int(decoded["p"]) if decoded else 0

    def _decode(self, token: Any) -> dict[str, Any] | None:
        if not isinstance(token, str):
            return None
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            data = jsonlib.loads(raw)
            return data if isinstance(data, dict) and {"a", "q", "e", "p"} <= set(data) else None
        except (ValueError, TypeError):
            return None

    def _search(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        jql = str(body.get("jql", ""))
        try:
            query = parse(jql)
        except JqlError as exc:
            return _err(400, str(exc))
        if not query.bounded:
            return _err(
                400,
                "Unbounded JQL queries are not allowed here. "
                "Please add a search restriction to your query.",
            )
        size = _int(body.get("maxResults"), DEFAULT_MAX)
        if size is None or size < 1:
            return _err(400, "The 'maxResults' parameter must be a positive integer.")
        size = min(size, MAX_RESULTS)
        digest = hashlib.sha256(jql.encode()).hexdigest()[:12]
        after, page = None, 1
        if body.get("nextPageToken") is not None:
            tok = self._decode(body["nextPageToken"])
            if tok is None or tok["q"] != digest or tok["e"] != self._page_epoch:
                return _err(400, "Invalid request payload. Refer to the REST API documentation.")
            after, page = tok["a"], int(tok["p"]) + 1
        rows = [
            i for i in self._issues.values() if i["fields"]["project"]["key"] not in self._denied
        ]
        rows = [i for i in rows if query.matches(i)]
        rows.sort(key=lambda i: int(i["id"]))
        for field, desc in reversed(query.order):
            rows.sort(key=lambda i, f=field: _sort_value(i, f), reverse=desc)  # type: ignore[misc]
        if after is not None:
            ids = [i["id"] for i in rows]
            rows = rows[ids.index(after) + 1 :] if after in ids else rows
        chunk, more = rows[:size], len(rows) > size
        wanted = self._field_list(body.get("fields")) or ["id"]
        issues = [self._shape(i, [w for w in wanted if w != "id"]) for i in chunk]
        out: dict[str, Any] = {"issues": issues, "isLast": not more}
        if more:
            token = {"a": chunk[-1]["id"], "q": digest, "e": self._page_epoch, "p": page}
            out["nextPageToken"] = (
                base64.urlsafe_b64encode(jsonlib.dumps(token).encode()).rstrip(b"=").decode()
            )
        return Response(200, {}, out)

    # --- comments -------------------------------------------------------------------------

    def _comment_body_problem(self, body: Mapping[str, Any]) -> Response | None:
        if adf_error(body.get("body"), require_content=True):
            return _err(400, "Comment body is not valid!")
        return None

    def _list_comments(self, key: str, *, params: Mapping[str, Any], body: Any) -> Response:
        if self._visible(key) is None:
            return _err(404, _NOT_FOUND)
        start, size = _int(params.get("startAt"), 0), _int(params.get("maxResults"), DEFAULT_MAX)
        if start is None or start < 0 or size is None or size < 1:
            return _err(400, "startAt and maxResults must be non-negative integers.")
        size = min(size, MAX_RESULTS)
        ordered = list(self._comments[key])
        if str(params.get("orderBy", "created")).lstrip("+") == "-created":
            ordered.reverse()
        page = ordered[start : start + size]
        return Response(
            200,
            {},
            {"startAt": start, "maxResults": size, "total": len(ordered), "comments": page},
        )

    def _add_comment(
        self, key: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        if self._visible(key) is None:
            return _err(404, _NOT_FOUND)
        problem = self._comment_body_problem(body)
        if problem is not None:
            return problem
        self._next_comment += 1
        stamp = _iso(self.now)
        who = {"accountId": ACCOUNT_ID, "displayName": "Synthetic Bot"}
        comment = {
            "id": str(self._next_comment),
            "self": f"{HOST}/rest/api/3/issue/{key}/comment/{self._next_comment}",
            "author": who,
            "updateAuthor": who,
            "body": body["body"],
            "created": stamp,
            "updated": stamp,
        }
        self._comments[key].append(comment)
        return Response(201, {}, comment)

    def _find_comment(self, key: str, cid: str) -> dict[str, Any] | None:
        return next((c for c in self._comments[key] if c["id"] == cid), None)

    def _get_comment(self, key: str, cid: str, *, params: Mapping[str, Any], body: Any) -> Response:
        comment = self._find_comment(key, cid) if self._visible(key) else None
        if comment is None:
            return _err(404, "Can not find comment with id " + cid)
        return Response(200, {}, comment)

    def _update_comment(
        self, key: str, cid: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        comment = self._find_comment(key, cid) if self._visible(key) else None
        if comment is None:
            return _err(404, "Can not find comment with id " + cid)
        problem = self._comment_body_problem(body)
        if problem is not None:
            return problem
        self.now += 1
        comment["body"], comment["updated"] = body["body"], _iso(self.now)
        return Response(200, {}, comment)


def _sort_value(issue: dict[str, Any], field: str) -> str:
    if field == "key":
        return str(issue["id"]).zfill(12)
    values = field_values(issue, field)
    return values[0] if values else ""


__all__ = ["FIELDS", "FakeJiraIssues", "RateShape", "Response"]
