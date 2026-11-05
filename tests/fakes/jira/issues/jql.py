"""A small JQL evaluator for the fake Jira (D6-01).

Sources: https://developer.atlassian.com/cloud/jira/platform/jira-query-language/ (fields,
operators, ORDER BY, and the date formats), and the v3 OpenAPI spec for ``POST /search/jql``.
Modelled, per field:

* ``project``, ``status``, ``issuetype``, ``priority``, ``assignee``, ``reporter``, ``labels``:
  ``=``, ``!=``, ``in``, ``not in``, ``is [not] EMPTY|NULL``. ``!=`` and ``not in`` do NOT match an
  issue whose field is empty (Atlassian: they match only issues with some other value).
* ``key``: the same, plus ``<``, ``<=``, ``>``, ``>=`` within one project, by issue NUMBER.
* ``summary``: ``~`` and ``!~`` (a case-insensitive substring; Jira matches on words, a
  departure) and ``is [not] EMPTY``.
* ``created``, ``updated``: ``<``, ``<=``, ``>``, ``>=`` against ``yyyy/MM/dd``, ``yyyy-MM-dd``
  and either with `` HH:mm`` (UTC), and ``is [not] EMPTY``.
* ``AND``, ``OR``, parentheses; ``ORDER BY f [ASC|DESC], ...``. Names and values compare
  case-insensitively (assumed, not tried live). Values for project, status, issuetype, priority
  and assignee must exist, else a 400 as Jira gives; ``project`` and ``issuetype`` also take IDs.

Everything else is REFUSED with a 400 and "not modelled", never answered wrongly: functions
(``currentUser()``, ``startOfDay()``), relative dates (``-1d``), ``NOT``, ``was``/``changed``,
operators a field does not support in Jira, and a date compared with ``=``, ``!=``, ``in``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

FIELDS = frozenset(
    {
        "project",
        "status",
        "labels",
        "assignee",
        "reporter",
        "issuetype",
        "priority",
        "key",
        "summary",
        "created",
        "updated",
    }
)
_EQUALITY = frozenset({"=", "!=", "in", "not in", "is", "is not"})
_RELATIONAL = frozenset({"<", "<=", ">", ">="})
OPERATORS: Mapping[str, frozenset[str]] = {
    **{f: _EQUALITY for f in ("project", "status", "issuetype", "priority", "assignee")},
    "reporter": _EQUALITY,
    "labels": _EQUALITY,
    "key": _EQUALITY | _RELATIONAL,
    "summary": frozenset({"~", "!~", "is", "is not"}),
    "created": _RELATIONAL | _EQUALITY,
    "updated": _RELATIONAL | _EQUALITY,
}
_DATE_UNMODELLED = frozenset({"=", "!=", "in", "not in"})
_DATE_FORMATS = ("%Y/%m/%d %H:%M", "%Y-%m-%d %H:%M", "%Y/%m/%d", "%Y-%m-%d")
_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)-([0-9]+)$")
_TOKEN = re.compile(
    r"""\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
    r"""|(?P<op>!=|!~|>=|<=|=|~|>|<|\(|\)|,)|(?P<word>[^\s=!~<>(),"']+))"""
)
PRIORITY_RANK = {"highest": 1, "high": 2, "medium": 3, "low": 4, "lowest": 5}

Match = Callable[[dict[str, Any]], bool]


class JqlError(ValueError):
    """The query is not valid JQL (as the fake understands it); the text is Jira-style."""


class Resolver:
    """What the query's values are checked against: the server's projects, statuses and so on.
    ``resolve`` returns the canonical (casefolded) value, or None when it does not exist."""

    def resolve(self, field: str, raw: str) -> str | None:
        raise NotImplementedError


@dataclass(frozen=True)
class Query:
    matches: Match
    order: tuple[tuple[str, bool], ...]  # (field, descending)
    bounded: bool


def _not_modelled(what: str) -> JqlError:
    return JqlError(f"Not modelled by the fake Jira: {what}.")


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    while text[pos:].strip():
        m = _TOKEN.match(text, pos)
        if m is None:
            raise JqlError(f"Error in the JQL Query: unexpected character at {pos}.")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("str", re.sub(r"\\(.)", r"\1", m.group("str")[1:-1])))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            out.append(("word", m.group("word")))
    return out


def parse_date(raw: str, field: str) -> datetime:
    """A JQL date value, or a JqlError: relative periods are not modelled."""
    for form in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, form).replace(tzinfo=UTC)
        except ValueError:
            continue
    if re.match(r"^[+-]?\d+[a-zA-Z]", raw):
        raise _not_modelled(f"the relative date '{raw}'")
    raise JqlError(
        f"Date value '{raw}' for field '{field}' is invalid. Valid formats include: "
        "'yyyy/MM/dd HH:mm', 'yyyy-MM-dd HH:mm', 'yyyy/MM/dd', 'yyyy-MM-dd', or a period "
        "format e.g. '-5d', '4w 2d'."
    )


def issue_date(issue: dict[str, Any], field: str) -> datetime:
    return datetime.strptime(issue["fields"][field], "%Y-%m-%dT%H:%M:%S.000+0000").replace(
        tzinfo=UTC
    )


def field_values(issue: dict[str, Any], field: str) -> list[str]:
    """The issue's canonical (casefolded) value(s) for ``field``; empty when it has none."""
    f = issue["fields"]
    if field == "key":
        return [issue["key"].casefold()]
    if field == "project":
        return [f["project"]["key"].casefold()]
    if field in ("status", "issuetype", "priority"):
        node = f.get(field)
        return [str(node["name"]).casefold()] if node else []
    if field in ("assignee", "reporter"):
        node = f.get(field)
        return [str(node["accountId"]).casefold()] if node else []
    if field == "labels":
        return [str(x).casefold() for x in f.get("labels", [])]
    if field in ("created", "updated"):
        return [f[field]]
    value = f.get(field)
    return [str(value).casefold()] if value else []


def sort_value(issue: dict[str, Any], field: str) -> Any:
    """A JSON-able, comparable value to ORDER BY ``field`` (same type for every issue)."""
    if field == "key":
        project, _, number = issue["key"].rpartition("-")
        return [project.casefold(), int(number)]
    if field == "priority":
        return PRIORITY_RANK.get(field_values(issue, "priority")[0], 99)
    values = field_values(issue, field)
    return values[0] if values else ""


def sort_key(issue: dict[str, Any], order: tuple[tuple[str, bool], ...]) -> list[Any]:
    """The position of an issue in this ordering: one value per ORDER BY field, then its ID
    (ascending, whatever the direction: the default order of equal issues)."""
    return [*(sort_value(issue, f) for f, _ in order), int(issue["id"])]


def compare(a: list[Any], b: list[Any], order: tuple[tuple[str, bool], ...]) -> int:
    """Negative when ``a`` sorts before ``b`` in this ordering."""
    for n, (_, desc) in enumerate(order):
        if a[n] != b[n]:
            return (-1 if a[n] < b[n] else 1) * (-1 if desc else 1)
    return int(a[-1] > b[-1]) - int(a[-1] < b[-1])


def _either(a: Match, b: Match) -> Match:
    return lambda issue: a(issue) or b(issue)


def _both(a: Match, b: Match) -> Match:
    return lambda issue: a(issue) and b(issue)


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], resolver: Resolver) -> None:
        self.t, self.i, self.resolver = tokens, 0, resolver
        self.bounded = False

    def peek(self, ahead: int = 0) -> tuple[str, str] | None:
        return self.t[self.i + ahead] if self.i + ahead < len(self.t) else None

    def word(self, *names: str) -> str | None:
        tok = self.peek()
        if tok and tok[0] == "word" and tok[1].casefold() in names:
            self.i += 1
            return tok[1].casefold()
        return None

    def op(self, *names: str) -> str | None:
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in names:
            self.i += 1
            return tok[1]
        return None

    def raw_value(self) -> str:
        tok = self.peek()
        if tok is None or tok[0] == "op":
            raise JqlError("Error in the JQL Query: expecting a value but got end of query.")
        self.i += 1
        nxt = self.peek()
        if tok[0] == "word" and nxt == ("op", "("):
            raise _not_modelled(f"the function '{tok[1]}()'")
        return tok[1]

    def expr(self) -> Match:
        left = self.term()
        while self.word("or"):
            left = _either(left, self.term())
        return left

    def term(self) -> Match:
        left = self.factor()
        while self.word("and"):
            left = _both(left, self.factor())
        return left

    def factor(self) -> Match:
        if self.word("not"):
            raise _not_modelled("NOT")
        if self.op("("):
            inner = self.expr()
            if not self.op(")"):
                raise JqlError("Error in the JQL Query: expecting ')'.")
            return inner
        return self.clause()

    def operator(self, field: str) -> str:
        if self.word("is"):
            op = "is not" if self.word("not") else "is"
        elif self.word("not"):
            if not self.word("in"):
                raise JqlError("Error in the JQL Query: expecting 'in'.")
            op = "not in"
        elif self.word("in"):
            op = "in"
        elif sym := self.op("=", "!=", "~", "!~", ">=", "<=", ">", "<"):
            op = sym
        else:
            raise JqlError("Error in the JQL Query: expecting an operator.")
        if op not in OPERATORS[field]:
            raise JqlError(f"The operator '{op}' is not supported by the '{field}' field.")
        if field in ("created", "updated") and op in _DATE_UNMODELLED:
            raise _not_modelled(f"the operator '{op}' on '{field}'")
        return op

    def clause(self) -> Match:
        tok = self.peek()
        if tok is None or tok[0] == "op":
            raise JqlError("Error in the JQL Query: expecting a field name.")
        self.i += 1
        field = tok[1].casefold()
        if field not in FIELDS:
            raise JqlError(
                f"Field '{tok[1]}' does not exist or you do not have permission to view it."
            )
        self.bounded = True
        op = self.operator(field)
        if op in ("is", "is not"):
            if not self.word("empty", "null"):
                raise JqlError("Error in the JQL Query: expecting EMPTY or NULL.")
            return lambda i: bool(field_values(i, field)) == (op == "is not")
        if op in ("in", "not in"):
            return self.membership(field, op)
        if field in ("created", "updated"):
            cut = parse_date(self.raw_value(), field)
            return lambda i: self.date_test(issue_date(i, field), op, cut)
        want = self.value(field)
        if op in _RELATIONAL:
            return lambda i: self.key_test(i, op, want)
        return lambda i: self.compare(field_values(i, field), op, want)

    def value(self, field: str) -> str:
        raw = self.raw_value()
        if field in ("summary", "labels"):
            return raw.casefold()
        if field == "key":
            if _KEY.match(raw) is None:
                raise JqlError(f"The issue key '{raw}' for field 'key' is invalid.")
            return raw.casefold()
        found = self.resolver.resolve(field, raw)
        if found is None:
            raise JqlError(f"The value '{raw}' does not exist for the field '{field}'.")
        return found

    def membership(self, field: str, op: str) -> Match:
        if not self.op("("):
            raise JqlError("Error in the JQL Query: expecting '('.")
        wanted = {self.value(field)}
        while self.op(","):
            wanted.add(self.value(field))
        if not self.op(")"):
            raise JqlError("Error in the JQL Query: expecting ')'.")
        if op == "in":
            return lambda i: bool(wanted & set(field_values(i, field)))
        return lambda i: bool(field_values(i, field)) and not wanted & set(field_values(i, field))

    @staticmethod
    def date_test(have: datetime, op: str, cut: datetime) -> bool:
        return {">=": have >= cut, "<=": have <= cut, ">": have > cut, "<": have < cut}[op]

    @staticmethod
    def key_test(issue: dict[str, Any], op: str, want: str) -> bool:
        """``key`` against a key of the same project, by issue number (SYN-2 < SYN-10)."""
        project, _, number = issue["key"].casefold().rpartition("-")
        want_project, _, want_number = want.rpartition("-")
        if project != want_project:
            return False
        have, cut = int(number), int(want_number)
        return {">=": have >= cut, "<=": have <= cut, ">": have > cut, "<": have < cut}[op]

    @staticmethod
    def compare(have: list[str], op: str, want: str) -> bool:
        if op == "=":
            return want in have
        if op == "!=":
            return bool(have) and want not in have
        if op == "~":
            return any(want in h for h in have)
        return bool(have) and not any(want in h for h in have)  # "!~"


def parse(text: str, resolver: Resolver) -> Query:
    parser = _Parser(_tokens(text), resolver)
    matches: Match = lambda _issue: True  # noqa: E731
    if parser.peek() is not None and not _at_order(parser):
        matches = parser.expr()
    order: tuple[tuple[str, bool], ...] = ()
    if parser.peek() is not None:
        if not _at_order(parser):
            raise JqlError("Error in the JQL Query: unexpected input after the query.")
        order = _order(parser)
    return Query(matches, order, parser.bounded)


def _at_order(parser: _Parser) -> bool:
    first, second = parser.peek(), parser.peek(1)
    return bool(
        first
        and second
        and first[0] == "word"
        and first[1].casefold() == "order"
        and second[0] == "word"
        and second[1].casefold() == "by"
    )


def _order(parser: _Parser) -> tuple[tuple[str, bool], ...]:
    parser.i += 2
    out: list[tuple[str, bool]] = []
    while True:
        tok = parser.peek()
        if tok is None or tok[0] == "op":
            raise JqlError("Error in the JQL Query: expecting a field after 'order by'.")
        parser.i += 1
        field = tok[1].casefold()
        if field not in FIELDS:
            raise JqlError(
                f"Field '{tok[1]}' does not exist or you do not have permission to view it."
            )
        if field == "labels":
            raise JqlError("The field 'labels' does not support sorting.")
        desc = parser.word("asc", "desc") == "desc"
        out.append((field, desc))
        if not parser.op(","):
            break
    if parser.peek() is not None:
        raise JqlError("Error in the JQL Query: unexpected input after 'order by'.")
    return tuple(out)
