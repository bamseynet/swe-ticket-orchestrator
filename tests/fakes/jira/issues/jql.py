"""A small JQL evaluator for the fake Jira (D6-01).

Source: https://developer.atlassian.com/cloud/jira/platform/jql-fields/ and
https://support.atlassian.com/jira-software-cloud/docs/jql-operators/ (fields, operators, ORDER BY).
Modelled: ``=``, ``!=``, ``~``, ``>=``/``<=``/``>``/``<`` (on ISO dates and times), ``in``,
``not in``, ``is [not] EMPTY|NULL``, ``AND``, ``OR``, parentheses and ``ORDER BY f [ASC|DESC]``.
Not modelled: ``NOT``, functions (``currentUser()``), relative dates, ``was``/``changed``.
Names and values compare case-insensitively (assumed, not tried live).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
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
_TOKEN = re.compile(
    r"""\s*(?:(?P<str>"[^"]*"|'[^']*')|(?P<op>!=|>=|<=|=|~|>|<|\(|\)|,)|(?P<word>[^\s=!~<>(),"']+))"""
)


class JqlError(ValueError):
    """The query is not valid JQL (as the fake understands it); the text is Jira-style."""


@dataclass(frozen=True)
class Query:
    matches: Callable[[dict[str, Any]], bool]
    order: tuple[tuple[str, bool], ...]  # (field, descending)
    bounded: bool


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        if not text[pos:].strip():
            break
        m = _TOKEN.match(text, pos)
        if m is None:
            raise JqlError(f"Error in the JQL Query: unexpected character at {pos}.")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("str", m.group("str")[1:-1]))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            out.append(("word", m.group("word")))
    return out


def field_values(issue: dict[str, Any], field: str) -> list[str]:
    """The issue's value(s) for ``field``, casefolded; empty when it has none."""
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
    value = f.get(field)
    return [str(value).casefold()] if value else []


Match = Callable[[dict[str, Any]], bool]


def _either(a: Match, b: Match) -> Match:
    return lambda issue: a(issue) or b(issue)


def _both(a: Match, b: Match) -> Match:
    return lambda issue: a(issue) and b(issue)


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.t, self.i = tokens, 0
        self.bounded = False

    def peek(self) -> tuple[str, str] | None:
        return self.t[self.i] if self.i < len(self.t) else None

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

    def expect_value(self) -> str:
        tok = self.peek()
        if tok is None or tok[0] == "op":
            raise JqlError("Error in the JQL Query: expecting a value but got end of query.")
        self.i += 1
        return tok[1].casefold()

    def expr(self) -> Callable[[dict[str, Any]], bool]:
        left = self.term()
        while self.word("or"):
            left = _either(left, self.term())
        return left

    def term(self) -> Callable[[dict[str, Any]], bool]:
        left = self.factor()
        while self.word("and"):
            left = _both(left, self.factor())
        return left

    def factor(self) -> Callable[[dict[str, Any]], bool]:
        if self.op("("):
            inner = self.expr()
            if not self.op(")"):
                raise JqlError("Error in the JQL Query: expecting ')'.")
            return inner
        return self.clause()

    def clause(self) -> Callable[[dict[str, Any]], bool]:
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
        if self.word("is"):
            negate = bool(self.word("not"))
            if not self.word("empty", "null"):
                raise JqlError("Error in the JQL Query: expecting EMPTY or NULL.")
            return lambda i: bool(field_values(i, field)) == negate
        negate = False
        if self.word("not"):
            negate = True
            if not self.word("in"):
                raise JqlError("Error in the JQL Query: expecting 'in'.")
            return self.membership(field, negate)
        if self.word("in"):
            return self.membership(field, negate)
        op = self.op("=", "!=", "~", ">=", "<=", ">", "<")
        if op is None:
            raise JqlError("Error in the JQL Query: expecting an operator.")
        want = self.expect_value()
        return lambda i: self.compare(field_values(i, field), op, want)

    def membership(self, field: str, negate: bool) -> Callable[[dict[str, Any]], bool]:
        if not self.op("("):
            raise JqlError("Error in the JQL Query: expecting '('.")
        wanted = {self.expect_value()}
        while self.op(","):
            wanted.add(self.expect_value())
        if not self.op(")"):
            raise JqlError("Error in the JQL Query: expecting ')'.")
        return lambda i: bool(wanted & set(field_values(i, field))) != negate

    @staticmethod
    def compare(have: list[str], op: str, want: str) -> bool:
        if op == "=":
            return want in have
        if op == "!=":
            return want not in have
        if op == "~":
            return any(want in h for h in have)
        if not have:
            return False
        h = have[0]
        return {">=": h >= want, "<=": h <= want, ">": h > want, "<": h < want}[op]


def parse(text: str) -> Query:
    tokens = _tokens(text)
    split = next(
        (n for n, (k, v) in enumerate(tokens) if k == "word" and v.casefold() == "order"), None
    )
    order_tokens: list[tuple[str, str]] = []
    if split is not None:
        if split + 1 >= len(tokens) or tokens[split + 1][1].casefold() != "by":
            raise JqlError("Error in the JQL Query: expecting 'by' after 'order'.")
        order_tokens, tokens = tokens[split + 2 :], tokens[:split]
    parser = _Parser(tokens)
    if tokens:
        matches = parser.expr()
        if parser.peek() is not None:
            raise JqlError("Error in the JQL Query: unexpected input after the query.")
    else:
        matches = lambda _i: True  # noqa: E731
    return Query(matches, _order(order_tokens, split is not None), parser.bounded)


def _order(tokens: list[tuple[str, str]], present: bool) -> tuple[tuple[str, bool], ...]:
    if present and not tokens:
        raise JqlError("Error in the JQL Query: expecting a field after 'order by'.")
    out: list[tuple[str, bool]] = []
    i = 0
    while i < len(tokens):
        field = tokens[i][1].casefold()
        if field not in FIELDS:
            raise JqlError(
                f"Field '{tokens[i][1]}' does not exist or you do not have permission to view it."
            )
        i += 1
        desc = False
        if i < len(tokens) and tokens[i][1].casefold() in ("asc", "desc"):
            desc = tokens[i][1].casefold() == "desc"
            i += 1
        out.append((field, desc))
        if i < len(tokens):
            if tokens[i] != ("op", ","):
                raise JqlError("Error in the JQL Query: expecting ',' in 'order by'.")
            i += 1
    return tuple(out)
