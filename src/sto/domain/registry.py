"""Name registries. Events, commands and BLOCKED reasons register from the modules that use
them, so adding one never edits ``sto.domain`` (PLAN 6.1, STAGES D0-07)."""

from __future__ import annotations

from collections.abc import Callable


class Registry[T]:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._items: dict[str, type[T]] = {}

    def register(self, name: str) -> Callable[[type[T]], type[T]]:
        if not name:
            raise ValueError(f"{self.kind} name must be non-empty")

        def deco(cls: type[T]) -> type[T]:
            existing = self._items.get(name)
            if existing is not None and existing is not cls:
                raise ValueError(f"{self.kind} {name!r} already registered")
            self._items[name] = cls
            return cls

        return deco

    def get(self, name: str) -> type[T]:
        try:
            return self._items[name]
        except KeyError:
            raise KeyError(f"unknown {self.kind} {name!r}") from None

    def __contains__(self, name: object) -> bool:
        return name in self._items

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


# Shared registries. Other modules import these and decorate their own types.
EVENTS: Registry[object] = Registry("event")
COMMANDS: Registry[object] = Registry("command")
BLOCKED_REASONS: Registry[object] = Registry("blocked_reason")
