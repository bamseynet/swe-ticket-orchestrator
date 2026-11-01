"""Spy writer: records every write attempt made through a fake, for assertions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpyCall:
    port: str
    method: str
    args: dict[str, Any]
    key: str | None = None
    replayed: bool = False  # key already seen: the first result was returned
    error: str | None = None  # class name of the error raised; None if it applied


class SpyWriter:
    def __init__(self) -> None:
        self._calls: list[SpyCall] = []

    @property
    def calls(self) -> tuple[SpyCall, ...]:
        return tuple(self._calls)

    def calls_for(self, method: str) -> tuple[SpyCall, ...]:
        return tuple(c for c in self._calls if c.method == method)

    def applied(self, method: str | None = None) -> tuple[SpyCall, ...]:
        """Calls that changed state: not refused and not an idempotent replay."""
        return tuple(
            c
            for c in self._calls
            if c.error is None and not c.replayed and (method is None or c.method == method)
        )

    def clear(self) -> None:
        self._calls.clear()

    def record(self, call: SpyCall) -> None:
        self._calls.append(call)
