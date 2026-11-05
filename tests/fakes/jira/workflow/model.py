"""Workflows, transitions, screens and the webhook JQL subset for the fake Jira (D6-09).

Sources (https://developer.atlassian.com/cloud/jira/platform/):
* rest/v3/api-group-issues/ ``Get transitions`` and ``Transition issue``; the v3 OpenAPI schemas
  ``IssueTransition`` (``id`` is a string; ``hasScreen``, ``isGlobal``, ``isInitial``,
  ``isAvailable``, ``isConditional``, ``fields``), ``FieldMetadata`` (``required``, ``name``,
  ``key``, ``schema``, ``operations``, ``allowedValues``, ``hasDefaultValue``) and
  ``StatusCategory``.
* webhooks/: the supported JQL clauses for dynamic webhooks.

Departures, each deliberate:

* Transition IDs are unique within a workflow, and the two bundled workflows reuse the same ID
  for different targets (``11`` is In Progress in one and Done in the other), as Jira's
  per-workflow IDs allow. That choice is the fake's, to catch a hard-coded ID.
* The status category IDs (2 new, 4 indeterminate, 3 done) are the ones Jira Cloud uses; this is
  observed behaviour, unsourced, for D12.
* Screens model two field kinds: ``option`` (a value ``{"name": ...}`` or ``{"id": ...}`` from
  ``allowedValues``) and ``string``. Rich text, users and arrays on a screen are not modelled.
* The webhook JQL subset is ``issueKey``, ``project``, ``issuetype``, ``status``, ``priority``,
  ``assignee`` and ``reporter`` with ``=``, ``!=``, ``IN`` and ``NOT IN``, joined by ``AND``.
  The page also lists ``issue.property`` and ``cf[id]`` (Epic field only); neither is modelled
  and both are refused, which is stricter than Jira for an adapter that uses them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

# category key -> (id, name); the IDs are Jira Cloud's (unsourced, see above)
CATEGORIES: Mapping[str, tuple[int, str]] = {
    "new": (2, "To Do"),
    "indeterminate": (4, "In Progress"),
    "done": (3, "Done"),
}


@dataclass(frozen=True)
class ScreenField:
    """A field on a transition screen (``FieldMetadata``)."""

    key: str
    name: str
    required: bool = False
    kind: str = "string"  # "string" or "option"
    options: Mapping[str, str] | None = None  # option name -> ID, for kind "option"
    system: bool = False


@dataclass(frozen=True)
class Transition:
    id: str
    name: str
    to: str
    sources: tuple[str, ...] = ()  # empty: global, from any status
    screen: tuple[ScreenField, ...] = ()
    condition: Callable[[dict[str, Any]], bool] | None = None  # takes the issue's fields

    @property
    def is_global(self) -> bool:
        return not self.sources


@dataclass(frozen=True)
class Workflow:
    name: str
    statuses: Mapping[str, str]  # status name -> category key
    transitions: tuple[Transition, ...]

    def from_status(self, status: str) -> list[Transition]:
        return [t for t in self.transitions if t.is_global or status in t.sources]


def _has_assignee(fields: dict[str, Any]) -> bool:
    return bool(fields.get("assignee"))


RESOLUTION = ScreenField(
    "resolution",
    "Resolution",
    required=True,
    kind="option",
    options={"Done": "10000", "Won't Do": "10001"},
    system=True,
)
ROOT_CAUSE = ScreenField("customfield_10050", "Root cause", required=True)

SOFTWARE = Workflow(
    "software simplified",
    {"To Do": "new", "In Progress": "indeterminate", "Done": "done"},
    (
        Transition("11", "Start progress", "In Progress", ("To Do",)),
        Transition("21", "Done", "Done", ("In Progress",), screen=(RESOLUTION,)),
        Transition("31", "Stop progress", "To Do", ("In Progress",)),
        Transition("41", "Reopen", "To Do", ("Done",)),
    ),
)
SERVICE = Workflow(
    "service review",
    {"To Do": "new", "In Review": "indeterminate", "Done": "done"},
    (
        Transition("11", "Resolve", "Done", ("To Do",), screen=(ROOT_CAUSE,)),
        Transition("21", "Start review", "In Review", ("To Do",), condition=_has_assignee),
        Transition("31", "Approve", "Done", ("In Review",)),
        Transition("51", "Back to To Do", "To Do"),
    ),
)

_FILTER_FIELDS = {"issuekey", "project", "issuetype", "status", "priority", "assignee", "reporter"}
_VALUE = r'(?:"[^"]*"|[^\s,()"]+)'
_CLAUSE = re.compile(
    rf"^(?P<field>[A-Za-z.]+|cf\[\d+\])\s*(?P<op>!=|=|NOT\s+IN|IN)\s*"
    rf"(?P<value>{_VALUE}|\(\s*{_VALUE}(?:\s*,\s*{_VALUE})*\s*\))$",
    re.IGNORECASE,
)
Clause = tuple[str, bool, frozenset[str]]  # field, negated, casefolded values


def parse_filter(jql: str) -> tuple[list[Clause], None] | tuple[None, str]:
    """The clauses of a webhook JQL filter, or None and why it is not supported."""
    clauses: list[Clause] = []
    for part in re.split(r"\s+AND\s+", jql.strip(), flags=re.IGNORECASE):
        m = _CLAUSE.match(part.strip())
        if m is None:
            return None, f"Unsupported JQL in the webhook filter: '{part.strip()}'."
        field, op, raw = m["field"].casefold(), re.sub(r"\s+", " ", m["op"].upper()), m["value"]
        if field not in _FILTER_FIELDS:
            return None, f"The JQL field '{m['field']}' is not supported in webhook filters."
        is_list = raw.startswith("(")
        if is_list != op.endswith("IN"):
            return None, f"Unsupported JQL in the webhook filter: '{part.strip()}'."
        values = re.findall(_VALUE, raw[1:-1] if is_list else raw)
        clauses.append(
            (
                field,
                op.startswith("NOT") or op == "!=",
                frozenset(v.strip('"').casefold() for v in values),
            )
        )
    return clauses, None


def filter_matches(clauses: list[Clause], issue: Mapping[str, Any]) -> bool:
    fields = issue["fields"]

    def have(field: str) -> set[str]:
        if field == "issuekey":
            return {str(issue["key"]).casefold(), str(issue["id"])}
        if field in ("assignee", "reporter"):
            person = fields.get(field)
            return {str(person["accountId"]).casefold()} if person else set()
        thing = fields["project" if field == "project" else field]
        return {str(thing["name" if "name" in thing else "key"]).casefold(), str(thing["id"])} | (
            {str(thing["key"]).casefold()} if "key" in thing else set()
        )

    return all(bool(have(f) & values) != negated for f, negated, values in clauses)
