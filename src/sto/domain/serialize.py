"""Canonical wire form: IDs are their ULID string, enums their value, tuples lists.

``from_wire(cls, data)`` is the inverse of ``to_wire`` for the dataclasses in ``models``.
"""

from __future__ import annotations

import dataclasses
import types
import typing
from enum import Enum
from typing import Any

from .ids import Ulid


def to_wire(obj: Any) -> Any:
    """JSON-ready form: an ID is its ULID string, not the ``{"value": n}`` of ``asdict``."""
    if isinstance(obj, Ulid):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_wire(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {str(k): to_wire(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_wire(v) for v in obj]
    return obj


def _decode(tp: Any, value: Any) -> Any:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin in (typing.Union, types.UnionType):
        if value is None and type(None) in args:
            return None
        (inner,) = [a for a in args if a is not type(None)]
        return _decode(inner, value)
    if origin is tuple:
        if not isinstance(value, list | tuple):
            raise TypeError(f"expected a list, got {type(value).__name__}")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], v) for v in value)
        if len(args) != len(value):
            raise ValueError(f"expected {len(args)} items, got {len(value)}")
        return tuple(_decode(a, v) for a, v in zip(args, value, strict=True))
    if isinstance(tp, type):
        if issubclass(tp, Ulid):
            if not isinstance(value, str):
                raise TypeError(f"{tp.__name__} must be a string on the wire")
            return tp.parse(value)
        if issubclass(tp, Enum):
            return tp(value)
        if dataclasses.is_dataclass(tp):
            return from_wire(tp, value)
    return value  # str, int, bool: the model's own validation checks the type


def from_wire[T](cls: type[T], data: Any) -> T:
    """Rebuild a model from ``to_wire`` output, parsing IDs, enums and nested records.

    The input must be plain JSON types. A DynamoDB store must normalize first (``Decimal``
    numbers to ints, PK/SK and other key attributes dropped) in its own module.
    """
    if not isinstance(data, dict):
        raise TypeError(f"{cls.__name__} wire form must be an object, not {type(data).__name__}")
    hints = typing.get_type_hints(cls)
    names = {f.name for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    extra = set(data) - names
    if extra:
        raise ValueError(f"unexpected fields for {cls.__name__}: {sorted(extra)}")
    return cls(**{k: _decode(hints[k], v) for k, v in data.items()})
