"""The pure reducer: ``next(state, event, workflow) -> Transition`` (PLAN 6.1).

No I/O, clock or randomness. It emits commands and does nothing itself. The reducer only
dispatches: behaviour lives in handlers registered in ``HANDLERS``, found by importing every
module under ``sto.engine.handlers``, so a later issue adds a file and edits none of this.
An event with no handler, or one that does not fit the run's current state, raises
``OutOfOrderEventError`` and changes nothing.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from sto.domain import PermanentError, Run, RunId


class OutOfOrderEventError(PermanentError):
    """The event is not valid for the run's current state, so it is refused."""


@dataclass(frozen=True)
class Node:
    name: str
    kind: Literal["step", "gate"]


@dataclass(frozen=True)
class Workflow:
    """A linear list of nodes. Workflows are data (PLAN 6.1)."""

    version: str
    nodes: tuple[Node, ...]
    max_attempts: int = 2

    def index(self, name: str) -> int | None:
        for i, n in enumerate(self.nodes):
            if n.name == name:
                return i
        return None


# Hard-coded for D1: analyse, a review gate, implement, a QA gate.
LINEAR_V0 = Workflow(
    version="linear-v0",
    nodes=(
        Node("analyse", "step"),
        Node("review", "gate"),
        Node("implement", "step"),
        Node("qa", "gate"),
    ),
)


@dataclass(frozen=True)
class Transition:
    state: Run
    commands: tuple[object, ...] = ()


class Event(Protocol):
    @property
    def run_id(self) -> RunId: ...


Handler = Callable[[Run, Any, Workflow], Transition]


class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: dict[type, Handler] = {}

    def register(self, event_type: type, fn: Handler) -> None:
        if event_type in self._handlers:
            raise ValueError(f"a handler for {event_type.__name__} is already registered")
        self._handlers[event_type] = fn

    def get(self, event_type: type) -> Handler | None:
        return self._handlers.get(event_type)


HANDLERS = HandlerRegistry()


def handles(
    event_type: type, *, registry: HandlerRegistry = HANDLERS
) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        registry.register(event_type, fn)
        return fn

    return deco


_loaded = False


def load_handlers() -> None:
    """Import every module in ``sto.engine.handlers``, in name order. Idempotent."""
    global _loaded
    if _loaded:
        return
    pkg = importlib.import_module("sto.engine.handlers")
    for mod in sorted(m.name for m in pkgutil.iter_modules(pkg.__path__)):
        importlib.import_module(f"{pkg.__name__}.{mod}")
    _loaded = True


def next(  # noqa: A001 - the name is the contract (PLAN 6.1)
    state: Run,
    event: Event,
    workflow: Workflow,
    *,
    registry: HandlerRegistry | None = None,
) -> Transition:
    if registry is None:
        load_handlers()
        registry = HANDLERS
    handler = registry.get(type(event))
    if handler is None:
        raise OutOfOrderEventError(f"no handler for {type(event).__name__}")
    if event.run_id != state.id:
        raise OutOfOrderEventError(f"{type(event).__name__} is for another run")
    return handler(state, event, workflow)
