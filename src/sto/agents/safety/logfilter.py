"""A ``logging.Filter`` that keeps secrets and raw untrusted text out of logs (D5-04).

For every record it:

* replaces an ``Untrusted`` value, or the plain dict ``dataclasses.asdict`` makes from one, by a
  description with no text in it. This is done on the message object, on every argument, and on
  every ``extra`` value, to any depth up to ``MAX_DEPTH``; a container nested deeper than that is
  replaced by a fixed placeholder, never left raw;
* screens the formatted message and every ``extra`` value (strings, bytes, exceptions and any
  other object become a screened string; containers are rebuilt with screened members);
* replaces ``exc_info``, ``exc_text`` and ``stack_info`` by ``redact_error`` text;
* fails closed: if screening fails, the record is rewritten to a fixed message and every
  non-standard attribute is deleted. It never logs the original.

Limit: a plain string that holds raw ticket text (for example ``json.dumps(asdict(u))`` or
``u.text``) is only screened for secrets; the filter cannot know it is untrusted text.

Attach it to a handler, not a logger, so that it covers records from every logger. Wiring it into
the application is a later issue.
"""

from __future__ import annotations

import dataclasses
import itertools
import logging
import re
from collections.abc import Collection, Mapping
from typing import Any

from sto.agents.prompts.render import Untrusted
from sto.agents.safety.redact import redact_error
from sto.agents.safety.scanner import screen

MAX_DEPTH = 3
MAX_ITEMS = 1000
MAX_RECORD_CHARS = 1_000_000  # screened per record; a record over it is withheld, not slow
WITHHELD = "[log record withheld: screening failed]"
TOO_DEEP = "[nested value withheld]"
_STANDARD = frozenset(logging.LogRecord("n", 0, "p", 0, "m", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}
_SCALARS = (int, float, bool, type(None))


def _untrusted_text(value: dict[Any, Any]) -> str:
    return f"Untrusted(source={str(value['source'])[:64]!r}, chars={len(str(value['text']))})"


_SOURCE_LABEL = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_SCALAR_TYPES = (int, float, bool, type(None))
_LEAF_TYPES = (str, bytes, bytearray)
_UNTRUSTED_FIELDS = ("text", "source")
_ABORT = (KeyboardInterrupt, SystemExit, GeneratorExit)


def _is_scalar(value: Any) -> bool:
    return type(value) in _SCALAR_TYPES  # exact: an int subclass may bring its own __str__


def _as_pairs(value: Any) -> dict[Any, Any] | None:
    try:
        if value and all(isinstance(v, tuple | list) and len(v) == 2 for v in value):
            return {v[0]: v[1] for v in value}
    except TypeError:
        return None
    return None


def _is_untrusted_tuple(value: Any) -> bool:
    """``astuple(Untrusted(...))``: a pair of strings, the second a source label."""
    return (
        isinstance(value, tuple | list)
        and len(value) == 2
        and all(isinstance(v, str) for v in value)
        and _SOURCE_LABEL.fullmatch(value[1]) is not None
    )


def _key(value: Any, depth: int) -> Any:
    described = _describe(value, depth)
    return described if _is_scalar(described) or isinstance(described, str) else repr(described)


def _describe(value: Any, depth: int = 0) -> Any:
    """Return ``value`` with ``Untrusted`` and its ``asdict``/``astuple`` forms made safe.

    Mappings and every non-string iterable are walked; an exception becomes ``redact_error`` text;
    an iterator is not consumed and an unknown object is named, never ``repr``-ed.
    """
    if isinstance(value, Untrusted):
        return repr(value)
    if _is_scalar(value) or isinstance(value, _LEAF_TYPES):
        return value
    if isinstance(value, BaseException):
        return redact_error(value)
    if isinstance(value, Mapping):
        if all(f in value for f in _UNTRUSTED_FIELDS):
            return _untrusted_text(dict(value))
        if depth >= MAX_DEPTH:
            return TOO_DEEP
        return {_key(k, depth + 1): _describe(v, depth + 1) for k, v in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if depth >= MAX_DEPTH:
            return TOO_DEEP
        fields = {f.name: getattr(value, f.name, None) for f in dataclasses.fields(value)}
        return {"type": type(value).__name__, **_describe(fields, depth)}
    if isinstance(value, Collection):  # a lazy paginator or generator is not walked
        if depth >= MAX_DEPTH:
            return TOO_DEEP
        items = list(itertools.islice(value, MAX_ITEMS))
        if _is_untrusted_tuple(items):  # dict.values(), astuple(u)
            return f"Untrusted(source={items[1]!r}, chars={len(items[0])})"
        pairs = _as_pairs(items)
        if pairs is not None and all(f in pairs for f in _UNTRUSTED_FIELDS):
            return _untrusted_text(pairs)  # list(asdict(u).items())
        return [_describe(v, depth + 1) for v in items]
    return f"[object: {type(value).__name__}]"


class _OverBudget(Exception):  # noqa: N818
    pass


class _Budget:
    """Characters the filter will screen for one record; one big extra cannot stall a handler."""

    def __init__(self, limit: int) -> None:
        self.left = limit

    def screen(self, text: str) -> str:
        self.left -= len(text)
        if self.left < 0:
            raise _OverBudget
        return screen(text).text


def _screened(value: Any, budget: _Budget) -> Any:
    """A value safe to keep on a record: scalars as they are, everything else screened text."""
    if _is_scalar(value):
        return value
    if isinstance(value, str):
        return budget.screen(value)
    if isinstance(value, dict):
        return {str(_screened(k, budget)): _screened(v, budget) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_screened(v, budget) for v in value]
    if isinstance(value, bytes | bytearray):
        return budget.screen(repr(bytes(value)))
    return budget.screen(repr(value))  # already described: a string, or a placeholder


def _fail_closed(record: logging.LogRecord) -> None:
    for key in [k for k in record.__dict__ if k not in _STANDARD]:
        del record.__dict__[key]
    record.msg, record.args = WITHHELD, None
    record.exc_info, record.exc_text, record.stack_info = None, None, None


class SecretScreeningFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.__dict__.pop("message", None)  # a cached, formatted copy from another handler
            record.msg = _describe(record.msg)
            if isinstance(record.args, dict):
                record.args = _describe(record.args)
            elif record.args:
                record.args = tuple(_describe(a) for a in record.args)
            budget = _Budget(MAX_RECORD_CHARS)
            record.msg = budget.screen(record.getMessage())
            record.args = None
            if record.exc_info:
                exc = record.exc_info[1]
                record.exc_text = redact_error(exc) if exc is not None else None
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = redact_error(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_error(record.stack_info)
            for key in [k for k in record.__dict__ if k not in _STANDARD]:
                record.__dict__[key] = _screened(_describe(record.__dict__[key]), budget)
        except _ABORT:
            raise
        except BaseException:
            _fail_closed(record)
        return True
