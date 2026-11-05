"""The fake Jira's workflow features (D6-09): transitions and screens, Jira Software boards and
sprints, and webhook registration, on top of the issues fake (D6-01, ``FakeJiraIssues``), which
supplies auth, rate limits, faults, issues and JQL. Read its docstring first; its standards hold
here: at least as strict as Jira where a wrong adapter would pass, never stricter on a correct
adapter's path, and every behaviour sourced or listed below as unsourced. The live suite (D12-11)
proves all of it against the real service; when they disagree the fake is wrong. Deliveries
(signatures, retries) are ``webhooks.py``; the workflow data is ``model.py`` (read its departures).

Sources (https://developer.atlassian.com/cloud/jira/platform/):
* transitions: rest/v3/api-group-issues/ (Get transitions, Transition issue). Documented: a
  transition that does not exist or cannot be performed gives an EMPTY list (200); 404 for a
  missing issue; 400 when no transition is given, or a field not on the transition screen is in
  ``fields`` or ``update``; ``fields`` and ``update`` may not name the same field (spec).
* webhooks: rest/v3/api-group-webhooks/ and webhooks/ (30 day expiry, refresh by another 30
  days, 5 per OAuth 2.0 app and user on a tenant, expired ones kept for up to 3 months,
  Connect and OAuth 2.0 apps only, unknown IDs on refresh ignored).
* boards and sprints: rest/agile/1.0 (Jira Software Cloud REST), reached at
  https://developer.atlassian.com/cloud/jira/software/rest/api-group-board/ and
  .../api-group-sprint/. Documented: board ``type`` is scrum, kanban or simple; a board that
  does not support sprints answers the sprint list with 400; ``state`` is active, future or
  closed (comma separated); issues can be moved only into an open or active sprint, at most 50
  per call; the issue resource carries ``sprint`` and ``closedSprints``.

Unsourced departures, observed behaviour to prove in D12:

* Error TEXTS for: a missing required screen field ("<Name> is required."), a transition not valid
  for the issue, an unknown board or sprint, a closed sprint, a webhook limit, an unsupported
  JQL filter and a non-app caller (403). The status codes are documented unless said here.
* A team-managed ("simple") board supports sprints only when ``sprints=True`` (the sprints
  feature). A kanban board never does. One active sprint per board unless ``parallel_sprints``.
* A sprint's state moves future to active to closed only; starting needs no dates here (Jira
  asks for them) and the fake fills them in. Closing leaves issues pointing at nothing (Jira asks
  where unfinished work goes). An issue is in at most one open sprint. The board filter is not
  modelled: any issue can go in any sprint. The sprint list has no ``total``.
* Registered webhook IDs count against the limit of 5 until deleted, expired or not. Event names
  are not validated against Jira's list. ``fieldIdsFilter`` and ``issuePropertyKeysFilter`` are
  refused as not modelled. Webhook registration, refresh and delete need a bearer (OAuth) token:
  a basic-auth API token is a 403 (documented as app-only; the status is the spec's).
* Boards are one per project at most per call of ``add_board``; paging is ``startAt`` and
  ``maxResults`` (cap 50); a transition "looped" flag and sorting options are not modelled.
* Refused as "not modelled" (400): ``skipRemoteOnlyCondition`` and ``sortByOpsBarAndStatus`` on
  Get transitions, ``historyMetadata`` and ``properties`` on Transition issue, PUT on a sprint.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from fakes.jira.issues.server import (
    _UNKNOWN_FIELD,
    HOST,
    FakeJiraIssues,
    Headers,
    Response,
    _err,
    _errors,
    _flag,
    _int,
    _iso,
    _not_modelled,
)
from fakes.jira.issues.server import (
    SOURCES as ISSUE_SOURCES,
)
from fakes.jira.workflow.model import (
    CATEGORIES,
    SERVICE,
    SOFTWARE,
    ScreenField,
    Transition,
    Workflow,
    filter_matches,
    parse_filter,
)

_API = "https://developer.atlassian.com/cloud/jira/platform/rest/v3"
_TR = "#api-rest-api-3-issue-issueidorkey-transitions"
SOURCES: Mapping[str, str] = {
    **ISSUE_SOURCES,
    "get_transitions": f"{_API}/api-group-issues/{_TR}-get",
    "do_transition": f"{_API}/api-group-issues/{_TR}-post",
    "webhooks": f"{_API}/api-group-webhooks/",
    "webhook_guide": "https://developer.atlassian.com/cloud/jira/platform/webhooks/",
    "boards": "https://developer.atlassian.com/cloud/jira/software/rest/api-group-board/",
    "sprints": "https://developer.atlassian.com/cloud/jira/software/rest/api-group-sprint/",
}
DAY = 86_400.0
WEBHOOK_LIFE = (
    30 * DAY
)  # webhooks guide: "30 days from the time the webhook was created or refreshed"
WEBHOOK_KEPT = 90 * DAY  # webhooks guide: expired webhooks stay "up to 3 months"
WEBHOOK_LIMIT = 5  # webhooks guide: OAuth 2.0 apps, per app and user on a tenant
MAX_MOVE = 50  # sprint API: issues moved per call
PAGE_CAP = 50
BOARD_TYPES = ("scrum", "kanban", "simple")
SPRINT_STATES = ("future", "active", "closed")
_ORDER = {"future": 0, "active": 1, "closed": 2}
AGILE = "/rest/agile/1.0/"
_NOT_VALID = "Transition id '{}' is not valid for this issue."


def _app_only() -> Response:
    return _err(403, "Only Connect and OAuth 2.0 apps can use this operation.")


def _paged(items: list[Any], params: Mapping[str, Any], *, total: bool) -> Response:
    start, size = _int(params.get("startAt"), 0), _int(params.get("maxResults"), PAGE_CAP)
    if start is None or size is None or start < 0 or size < 0:
        return _err(400, "'startAt' and 'maxResults' must be non-negative integers.")
    size = min(size, PAGE_CAP)
    page = items[start : start + size]
    body: dict[str, Any] = {
        "maxResults": size,
        "startAt": start,
        "isLast": start + size >= len(items),
        "values": page,
    }
    if total:
        body["total"] = len(items)
    return Response(200, Headers(), body)


class FakeJiraWorkflow(FakeJiraIssues):
    """``FakeJiraIssues`` plus transitions, boards, sprints and webhook registration. Project SYN
    uses ``SOFTWARE`` and OTH uses ``SERVICE``; ``assign_workflow`` changes that."""

    def __init__(self, *, parallel_sprints: bool = False) -> None:
        super().__init__()
        self.parallel_sprints = parallel_sprints
        self._workflows: dict[str, Workflow] = {}
        self._boards: dict[int, dict[str, Any]] = {}
        self._sprints: dict[int, dict[str, Any]] = {}
        self._in_sprint: dict[str, int] = {}
        self._closed_sprints: dict[str, list[int]] = {}
        self._next_board, self._next_sprint = 1, 101
        self._hooks: dict[int, dict[str, Any]] = {}
        self._next_hook = 1000
        self._auth_header: str | None = None
        self.assign_workflow("SYN", SOFTWARE)
        self.assign_workflow("OTH", SERVICE)

    # --- seeding and controls -------------------------------------------------------------

    def assign_workflow(self, project: str, workflow: Workflow) -> None:
        self._workflows[project] = workflow
        for name in workflow.statuses:
            self.add_status(name)

    def force_status(self, key: str, status: str) -> None:
        """A person moved the issue in the Jira UI (no transition check)."""
        issue = self._issues[key]
        self._set_status(issue, status)
        self._touch(issue)

    def add_board(
        self, name: str, board_type: str = "scrum", project: str = "SYN", *, sprints: bool = True
    ) -> int:
        if board_type not in BOARD_TYPES:
            raise ValueError(f"board type must be one of {BOARD_TYPES}")
        ident, self._next_board = self._next_board, self._next_board + 1
        self._boards[ident] = {
            "id": ident,
            "self": f"{HOST}/rest/agile/1.0/board/{ident}",
            "name": name,
            "type": board_type,
            "location": {"projectKey": project, "projectId": 10000 + ident},
            "_sprints": board_type == "scrum" or (board_type == "simple" and sprints),
        }
        return ident

    def add_sprint(self, board: int, name: str, state: str = "future") -> int:
        ident, self._next_sprint = self._next_sprint, self._next_sprint + 1
        sprint: dict[str, Any] = {
            "id": ident,
            "self": f"{HOST}/rest/agile/1.0/sprint/{ident}",
            "state": "future",
            "name": name,
            "originBoardId": board,
        }
        self._sprints[ident] = sprint
        if state != "future":
            self._start(sprint)
        if state == "closed":
            self._finish(sprint)
        return ident

    def webhook_expiry(self, ident: int) -> float:
        return float(self._hooks[ident]["expires"])

    def webhook_expired(self, ident: int) -> bool:
        self._purge_hooks()
        return ident not in self._hooks or self.now >= self._hooks[ident]["expires"]

    def clear_webhooks(self) -> None:
        self._hooks.clear()

    def live_webhooks(self, event: str, key: str) -> dict[str, list[int]]:
        """Unexpired registrations that fire for ``event`` on issue ``key``, as url -> IDs."""
        self._purge_hooks()
        issue = self._issues[key]
        found: dict[str, list[int]] = {}
        for ident, hook in self._hooks.items():
            if (
                self.now < hook["expires"]
                and event in hook["events"]
                and filter_matches(hook["clauses"], issue)
            ):
                found.setdefault(hook["url"], []).append(ident)
        return found

    def issue_snapshot(self, key: str) -> dict[str, Any]:
        return copy.deepcopy(self._issues[key])

    # --- routing --------------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        auth: str | None = None,
        params: Mapping[str, Any] | None = None,
        json: Any = None,  # noqa: A002 - the HTTP client's own name
    ) -> Response:
        self._auth_header = auth
        return super().request(method, path, auth=auth, params=params, json=json)

    @staticmethod
    def _route(method: str, path: str) -> tuple[str, tuple[str, ...]] | None:
        api = "/rest/api/3/"
        if path.startswith(api):
            parts = path.removeprefix(api).strip("/").split("/")
            if parts[0] == "webhook":
                table = {
                    ("POST", ("webhook",)): "register_webhooks",
                    ("GET", ("webhook",)): "list_webhooks",
                    ("DELETE", ("webhook",)): "delete_webhooks",
                    ("PUT", ("webhook", "refresh")): "refresh_webhooks",
                }
                op = table.get((method, tuple(parts)))
                return (op, ()) if op else None
            if len(parts) == 3 and parts[0] == "issue" and parts[2] == "transitions":
                op = {"GET": "get_transitions", "POST": "do_transition"}.get(method)
                return (op, (parts[1],)) if op else None
        elif path.startswith(AGILE):
            parts = path.removeprefix(AGILE).strip("/").split("/")
            shape = tuple(p if i % 2 == 0 else "id" for i, p in enumerate(parts))
            table = {
                ("GET", ("board",)): "list_boards",
                ("GET", ("board", "id")): "get_board",
                ("GET", ("board", "id", "sprint")): "board_sprints",
                ("GET", ("sprint", "id")): "get_sprint",
                ("POST", ("sprint", "id")): "update_sprint",
                ("GET", ("sprint", "id", "issue")): "sprint_issues",
                ("POST", ("sprint", "id", "issue")): "move_to_sprint",
                ("GET", ("issue", "id")): "agile_issue",
            }
            op = table.get((method, shape))
            return (op, tuple(parts[1::2])) if op else None
        else:
            return FakeJiraIssues._route(method, path)
        return FakeJiraIssues._route(method, path) if path.startswith(api) else None

    # --- transitions ----------------------------------------------------------------------

    def _category(self, issue: dict[str, Any], status: str) -> str:
        workflow = self._workflows.get(issue["fields"]["project"]["key"])
        if workflow and status in workflow.statuses:
            return workflow.statuses[status]
        return {"to do": "new", "in progress": "indeterminate", "done": "done"}.get(
            status.casefold(), "new"
        )

    def _set_status(self, issue: dict[str, Any], status: str) -> None:
        self.add_status(status)
        key = self._category(issue, status)
        ident, name = CATEGORIES[key]
        issue["fields"]["status"] = {
            "name": status,
            "id": self._statuses[status.casefold()],
            "statusCategory": {"key": key, "id": ident, "name": name},
        }

    def _offered(self, issue: dict[str, Any]) -> list[tuple[Transition, bool]]:
        """Transitions from the issue's status, each with whether its conditions pass."""
        fields = issue["fields"]
        workflow = self._workflows.get(fields["project"]["key"])
        if workflow is None:
            return []
        found = workflow.from_status(fields["status"]["name"])
        return [(t, t.condition is None or t.condition(fields)) for t in found]

    def _describe(
        self, issue: dict[str, Any], t: Transition, ok: bool, screen: bool
    ) -> dict[str, Any]:
        workflow = self._workflows[issue["fields"]["project"]["key"]]
        key = workflow.statuses[t.to]
        ident, name = CATEGORIES[key]
        item: dict[str, Any] = {
            "id": t.id,
            "name": t.name,
            "to": {
                "self": f"{HOST}/rest/api/3/status/{self._statuses[t.to.casefold()]}",
                "name": t.to,
                "id": self._statuses[t.to.casefold()],
                "statusCategory": {"id": ident, "key": key, "name": name},
            },
            "hasScreen": bool(t.screen),
            "isGlobal": t.is_global,
            "isInitial": False,
            "isAvailable": ok,
            "isConditional": t.condition is not None,
        }
        if screen:
            item["fields"] = {f.key: self._screen_field(f) for f in t.screen}
        return item

    @staticmethod
    def _screen_field(f: ScreenField) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": "option" if f.kind == "option" else "string"}
        schema["system" if f.system else "custom"] = f.key if f.system else "synthetic:textfield"
        out: dict[str, Any] = {
            "required": f.required,
            "name": f.name,
            "key": f.key,
            "schema": schema,
            "operations": ["set"],
            "hasDefaultValue": False,
        }
        if f.options:
            out["allowedValues"] = [
                {"id": i, "name": n, "self": f"{HOST}/rest/api/3/{f.key}/{i}"}
                for n, i in f.options.items()
            ]
        return out

    def _get_transitions(self, ref: str, *, params: Mapping[str, Any], body: Any) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, "Issue does not exist or you do not have permission to see it.")
        for name in ("skipRemoteOnlyCondition", "sortByOpsBarAndStatus"):
            if name in params:
                return _not_modelled(f"'{name}' on get transitions")
        expand = params.get("expand")
        if expand not in (None, "transitions.fields"):
            return _not_modelled("'expand' other than 'transitions.fields' on get transitions")
        unavailable = _flag(params.get("includeUnavailableTransitions"))
        if unavailable is None:
            return _err(400, "'includeUnavailableTransitions' must be true or false.")
        wanted = params.get("transitionId")
        shown = [
            self._describe(issue, t, ok, expand is not None)
            for t, ok in self._offered(issue)
            if (ok or unavailable) and wanted in (None, t.id)
        ]
        out: dict[str, Any] = {"transitions": shown}
        if expand:
            out["expand"] = "transitions"
        return Response(200, Headers(), out)

    def _do_transition(
        self, ref: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, "Issue does not exist or you do not have permission to see it.")
        if body.get("historyMetadata") is not None or body.get("properties") is not None:
            return _not_modelled("'historyMetadata' and 'properties' on transition issue")
        wanted = body.get("transition")
        ident = wanted.get("id") if isinstance(wanted, Mapping) else None
        if not isinstance(ident, str) or not ident:
            return _err(400, "No transition specified.")
        chosen = next((t for t, ok in self._offered(issue) if ok and t.id == ident), None)
        if chosen is None:
            return _err(400, _NOT_VALID.format(ident))
        fields, update = body.get("fields") or {}, body.get("update") or {}
        if not isinstance(fields, dict) or not isinstance(update, dict):
            return _err(400, "'fields' and 'update' must be objects.")
        errors = {
            n: f"Field '{n}' cannot be in both 'fields' and 'update'."
            for n in fields.keys() & update.keys()
        }
        values: dict[str, Any] = dict(fields)
        for name, operations in update.items():
            if name in errors:
                continue
            if (
                not isinstance(operations, list)
                or len(operations) != 1
                or not isinstance(operations[0], dict)
                or set(operations[0]) != {"set"}
            ):
                errors[name] = "Operation value must be a single 'set' operation"
            else:
                values[name] = operations[0]["set"]
        screen = {f.key: f for f in chosen.screen}
        for name in values:
            if name not in screen and name not in errors:
                errors[name] = _UNKNOWN_FIELD.format(name)
        stored: dict[str, Any] = {}
        for f in chosen.screen:
            if f.key in errors:
                continue
            problem = self._check_screen_value(f, values.get(f.key), f.key in values, stored)
            if problem:
                errors[f.key] = problem
        if errors:  # nothing is applied unless everything is valid
            return _errors(400, errors)
        issue["fields"].update(stored)
        self._set_status(issue, chosen.to)
        self._touch(issue)
        return Response(204, Headers(), None)

    @staticmethod
    def _check_screen_value(
        f: ScreenField, value: Any, given: bool, out: dict[str, Any]
    ) -> str | None:
        """An error text, or None with the accepted value stored in ``out``."""
        blank = value is None or (isinstance(value, str) and not value.strip()) or value in ({}, [])
        if not given or (blank and value is None):
            return f"{f.name} is required." if f.required else None
        if f.kind == "option":
            options = f.options or {}
            if isinstance(value, Mapping) and len(value) == 1:
                ((how, wanted),) = value.items()
                for name, ident in options.items():
                    if (how == "name" and wanted == name) or (how == "id" and wanted == ident):
                        out[f.key] = {"name": name, "id": ident}
                        return None
            return "Specified value is invalid."
        if isinstance(value, str):
            if blank:
                return f"{f.name} is required." if f.required else None
            out[f.key] = value
            return None
        return "Specified value is invalid."

    # --- boards and sprints ---------------------------------------------------------------

    def _board(self, raw: str) -> dict[str, Any] | None:
        return self._boards.get(int(raw)) if raw.isdigit() else None

    def _sprint(self, raw: str) -> dict[str, Any] | None:
        return self._sprints.get(int(raw)) if raw.isdigit() else None

    @staticmethod
    def _public(entry: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in entry.items() if not k.startswith("_")}

    def _list_boards(self, *, params: Mapping[str, Any], body: Any) -> Response:
        kind, project = params.get("type"), params.get("projectKeyOrId")
        if kind is not None and kind not in BOARD_TYPES:
            return _err(400, f"Invalid board type '{kind}'.")
        found = [
            self._public(b)
            for b in self._boards.values()
            if kind in (None, b["type"])
            and project in (None, b["location"]["projectKey"], str(b["location"]["projectId"]))
        ]
        return _paged(found, params, total=True)

    def _get_board(self, raw: str, *, params: Mapping[str, Any], body: Any) -> Response:
        board = self._board(raw)
        if board is None:
            return _err(404, "Board does not exist or you do not have permission to see it.")
        return Response(200, Headers(), self._public(board))

    def _board_sprints(self, raw: str, *, params: Mapping[str, Any], body: Any) -> Response:
        board = self._board(raw)
        if board is None:
            return _err(404, "Board does not exist or you do not have permission to see it.")
        if not board["_sprints"]:
            return _err(400, "The board does not support sprints")
        states = str(params.get("state") or ",".join(SPRINT_STATES)).split(",")
        if any(s.strip() not in SPRINT_STATES for s in states):
            return _err(400, f"Invalid sprint state in '{params.get('state')}'.")
        found = [
            dict(s)
            for s in self._sprints.values()
            if s["originBoardId"] == board["id"] and s["state"] in {x.strip() for x in states}
        ]
        return _paged(found, params, total=False)

    def _get_sprint(self, raw: str, *, params: Mapping[str, Any], body: Any) -> Response:
        sprint = self._sprint(raw)
        if sprint is None:
            return _err(404, "Sprint does not exist or you do not have permission to view it.")
        return Response(200, Headers(), dict(sprint))

    def _start(self, sprint: dict[str, Any]) -> None:
        sprint["state"] = "active"
        sprint["startDate"] = _iso(self.now)
        sprint["endDate"] = _iso(self.now + 14 * DAY)

    def _finish(self, sprint: dict[str, Any]) -> None:
        sprint["state"] = "closed"
        sprint["completeDate"] = _iso(self.now)
        for key, ident in list(self._in_sprint.items()):
            if ident == sprint["id"]:
                del self._in_sprint[key]
                self._closed_sprints.setdefault(key, []).append(ident)

    def _update_sprint(
        self, raw: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        sprint = self._sprint(raw)
        if sprint is None:
            return _err(404, "Sprint does not exist or you do not have permission to view it.")
        extra = set(body) - {"state", "name"}
        if extra:
            return _not_modelled(f"{sorted(extra)} on sprint update")
        state = body.get("state", sprint["state"])
        if state not in SPRINT_STATES or _ORDER[state] < _ORDER[sprint["state"]]:
            return _err(400, f"The sprint cannot move from '{sprint['state']}' to '{state}'.")
        if (
            state == "active"
            and sprint["state"] != "active"
            and not self.parallel_sprints
            and any(
                s["state"] == "active" and s["originBoardId"] == sprint["originBoardId"]
                for s in self._sprints.values()
            )
        ):
            return _err(400, "Only one active sprint is allowed on this board.")
        if "name" in body:
            if not isinstance(body["name"], str) or not body["name"].strip():
                return _err(400, "The sprint name must not be empty.")
            sprint["name"] = body["name"]
        if state != sprint["state"]:
            if sprint["state"] == "future" and state == "closed":
                self._start(sprint)
            (self._start if state == "active" else self._finish)(sprint)
        return Response(200, Headers(), dict(sprint))

    def _agile_issue_body(self, issue: dict[str, Any]) -> dict[str, Any]:
        key, now = issue["key"], self._in_sprint.get(issue["key"])
        shown = copy.deepcopy(issue)
        shown["fields"]["sprint"] = dict(self._sprints[now]) if now else None
        shown["fields"]["closedSprints"] = [
            dict(self._sprints[i]) for i in self._closed_sprints.get(key, [])
        ]
        return shown

    def _agile_issue(self, ref: str, *, params: Mapping[str, Any], body: Any) -> Response:
        issue = self._visible(ref)
        if issue is None:
            return _err(404, "Issue does not exist or you do not have permission to see it.")
        return Response(200, Headers(), self._agile_issue_body(issue))

    def _sprint_issues(self, raw: str, *, params: Mapping[str, Any], body: Any) -> Response:
        sprint = self._sprint(raw)
        if sprint is None:
            return _err(404, "Sprint does not exist or you do not have permission to view it.")
        found = [
            self._agile_issue_body(self._issues[k])
            for k, i in self._in_sprint.items()
            if i == sprint["id"] and self._visible(k) is not None
        ]
        page = _paged(found, params, total=True)
        if page.status != 200:
            return page
        got = page.body
        return Response(
            200,
            Headers(),
            {
                "startAt": got["startAt"],
                "maxResults": got["maxResults"],
                "total": got["total"],
                "issues": got["values"],
            },
        )

    def _move_to_sprint(
        self, raw: str, *, params: Mapping[str, Any], body: Mapping[str, Any]
    ) -> Response:
        sprint = self._sprint(raw)
        if sprint is None:
            return _err(404, "Sprint does not exist or you do not have permission to view it.")
        keys = body.get("issues")
        if not isinstance(keys, list) or not keys or not all(isinstance(k, str) for k in keys):
            return _err(400, "'issues' must be a non-empty list of issue keys or IDs.")
        if len(keys) > MAX_MOVE:
            return _err(400, f"At most {MAX_MOVE} issues can be moved in one call.")
        if sprint["state"] == "closed":
            return _err(400, "Issues can only be moved to an open or active sprint.")
        found = [self._visible(k) for k in keys]
        if any(i is None for i in found):
            return _err(400, "One or more issues do not exist or cannot be seen.")
        for issue in found:
            assert issue is not None
            self._in_sprint[issue["key"]] = sprint["id"]
        return Response(204, Headers(), None)

    # --- webhook registration -------------------------------------------------------------

    def _purge_hooks(self) -> None:
        for ident in [i for i, h in self._hooks.items() if self.now >= h["expires"] + WEBHOOK_KEPT]:
            del self._hooks[ident]

    def _is_app(self) -> bool:
        scheme, _, token = (self._auth_header or "").partition(" ")
        return scheme.casefold() == "bearer" and bool(token)

    def _register_webhooks(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        if not self._is_app():
            return _app_only()
        url, hooks = body.get("url"), body.get("webhooks")
        if not (
            isinstance(url, str)
            and url
            and isinstance(hooks, list)
            and hooks
            and all(
                isinstance(h, Mapping)
                and isinstance(h.get("events"), list)
                and h["events"]
                and isinstance(h.get("jqlFilter"), str)
                for h in hooks
            )
        ):
            return _err(
                400, "'url' and a non-empty 'webhooks' list of events and jqlFilter are required."
            )
        self._purge_hooks()
        results: list[dict[str, Any]] = []
        for hook in hooks:
            clauses, why = parse_filter(hook["jqlFilter"])
            if hook.get("fieldIdsFilter") or hook.get("issuePropertyKeysFilter"):
                why = "Not modelled by the fake Jira: field and property filters."
            elif why is None and len(self._hooks) >= WEBHOOK_LIMIT:
                why = "The maximum number of webhooks for this app and user has been reached."
            if why is not None:
                results.append({"errors": [why]})
                continue
            ident, self._next_hook = self._next_hook, self._next_hook + 1
            self._hooks[ident] = {
                "url": url,
                "events": list(hook["events"]),
                "jqlFilter": hook["jqlFilter"],
                "clauses": clauses,
                "expires": self.now + WEBHOOK_LIFE,
            }
            results.append({"createdWebhookId": ident})
        return Response(200, Headers(), {"webhookRegistrationResult": results})

    def _list_webhooks(self, *, params: Mapping[str, Any], body: Any) -> Response:
        if not self._is_app():
            return _app_only()
        self._purge_hooks()
        listed = [
            {
                "id": i,
                "jqlFilter": h["jqlFilter"],
                "events": h["events"],
                "expirationDate": int(h["expires"] * 1000),
            }
            for i, h in self._hooks.items()
        ]
        return _paged(listed, params, total=True)

    def _ids(self, body: Mapping[str, Any]) -> list[int] | None:
        ids = body.get("webhookIds")
        if (
            isinstance(ids, list)
            and ids
            and all(isinstance(i, int) and not isinstance(i, bool) for i in ids)
        ):
            return list(ids)
        return None

    def _refresh_webhooks(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        if not self._is_app():
            return _app_only()
        ids = self._ids(body)
        if ids is None:
            return _err(400, "'webhookIds' must be a non-empty list of webhook IDs.")
        self._purge_hooks()
        for ident in ids:  # spec: unrecognised IDs are ignored
            if ident in self._hooks:
                self._hooks[ident]["expires"] = self.now + WEBHOOK_LIFE
        return Response(200, Headers(), {"expirationDate": int((self.now + WEBHOOK_LIFE) * 1000)})

    def _delete_webhooks(self, *, params: Mapping[str, Any], body: Mapping[str, Any]) -> Response:
        if not self._is_app():
            return _app_only()
        ids = self._ids(body)
        if ids is None:
            return _err(400, "'webhookIds' must be a non-empty list of webhook IDs.")
        for ident in ids:
            self._hooks.pop(ident, None)
        return Response(202, Headers(), None)
