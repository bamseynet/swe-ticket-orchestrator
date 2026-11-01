"""Spy writer: records every write made through a fake, for assertions."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sto.domain.models import Receipt


@dataclass(frozen=True)
class SpyCall:
    port: str
    method: str
    args: dict[str, Any]
    key: str | None = None
    replayed: bool = False  # the idempotency key had been seen, so the fake did not write again


class SpyWriter:
    def __init__(self) -> None:
        self._calls: list[SpyCall] = []
        self._by_key: dict[tuple[str, str, str], Receipt] = {}
        self._seq = 0

    @property
    def calls(self) -> tuple[SpyCall, ...]:
        return tuple(self._calls)

    def calls_for(self, method: str) -> tuple[SpyCall, ...]:
        return tuple(c for c in self._calls if c.method == method)

    def clear(self) -> None:
        self._calls.clear()

    def next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq}"

    def record(self, port: str, method: str, args: dict[str, Any], key: str | None = None) -> None:
        self._calls.append(SpyCall(port, method, args, key))

    def write(
        self,
        port: str,
        method: str,
        args: dict[str, Any],
        key: str | None,
        apply: Callable[[], Receipt],
    ) -> Receipt:
        """Record the call, then apply it once per ``(port, method, key)``; replays get the
        first receipt back."""
        if key is not None and (port, method, key) in self._by_key:
            self._calls.append(SpyCall(port, method, args, key, replayed=True))
            return self._by_key[(port, method, key)]
        self._calls.append(SpyCall(port, method, args, key))
        receipt = apply()
        if key is not None:
            self._by_key[(port, method, key)] = receipt
        return receipt

    def receipt(self, prefix: str, url: str = "") -> Receipt:
        """Every fake result is marked ``simulated`` (PLAN 6.3) and says it was read back."""
        return Receipt(self.next_id(prefix), url, read_back_verified=True, simulated=True)

    @staticmethod
    def receipt_for(external_id: str, url: str = "") -> Receipt:
        """Same as ``receipt`` but with a stable ID, for finds-or-creates and state changes."""
        return Receipt(external_id, url, read_back_verified=True, simulated=True)
