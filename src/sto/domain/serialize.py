"""Canonical wire form: IDs are their ULID string, enums their value, tuples lists."""

from __future__ import annotations

import dataclasses
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
    if isinstance(obj, (list, tuple)):
        return [to_wire(v) for v in obj]
    return obj
