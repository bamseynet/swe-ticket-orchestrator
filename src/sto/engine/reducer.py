"""The pure reducer: ``next(state, event, workflow) -> Transition`` (PLAN 6.1).

No I/O, clock or randomness. It emits commands and does nothing itself. The reducer only
dispatches: behaviour lives in handlers in ``HANDLERS``. Call ``load_handlers()`` once at
startup (see there); ``next`` does no import I/O.

``RunState`` is the engine's state: the domain ``Run`` plus the position counters the domain
leaves out (visit, attempt, round, the live subject, approvals). An event whose run, status,
stage, visit, attempt, round or subject differs from the live state is refused with
``OutOfOrderEventError`` and changes nothing, so a late or duplicate event cannot act.
A malformed event (missing subject, decision not allowed at the gate) raises
``MalformedEventError`` instead.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from sto.domain import (
    DecisionId,
    DecisionKind,
    GateType,
    PermanentError,
    Run,
    RunId,
    Subject,
)


class OutOfOrderEventError(PermanentError):
    """The event is not valid for the run's current state, so it is refused."""


class MalformedEventError(PermanentError):
    """The event is not well formed for the node it targets, whatever the state."""


class WorkflowMismatchError(PermanentError):
    """The run was started on a different workflow version."""


@dataclass(frozen=True)
class Node:
    """One node of a linear workflow. Re-entry targets are explicit, never positional."""

    name: str
    kind: Literal["step", "gate", "effect"]
    gate_type: GateType | None = None
    decisions: frozenset[DecisionKind] = frozenset()
    on_changes: str | None = None  # re-entry after request_changes
    on_retest: str | None = None  # re-entry after retest
    produces_code: bool = False  # a step that may change the head SHA
    effect: str | None = None
    requires_gates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (self.kind == "gate") != (self.gate_type is not None):
            raise ValueError(f"{self.name}: gate_type is set exactly on gate nodes")
        if (self.kind == "effect") != (self.effect is not None):
            raise ValueError(f"{self.name}: effect is set exactly on effect nodes")
        if DecisionKind.REQUEST_CHANGES in self.decisions and self.on_changes is None:
            raise ValueError(f"{self.name}: request_changes needs on_changes")
        if DecisionKind.RETEST in self.decisions and self.on_retest is None:
            raise ValueError(f"{self.name}: retest needs on_retest")


@dataclass(frozen=True)
class Workflow:
    """A linear list of nodes. Workflows are data (PLAN 6.1)."""

    version: str
    nodes: tuple[Node, ...]
    max_attempts: int = 2

    def __post_init__(self) -> None:
        names = [n.name for n in self.nodes]
        if not names or len(set(names)) != len(names):
            raise ValueError("workflow needs unique, non-empty node names")
        for n in self.nodes:
            for ref in (n.on_changes, n.on_retest, *n.requires_gates):
                if ref is not None and ref not in names:
                    raise ValueError(f"{n.name}: unknown node {ref!r}")
            for ref in (n.on_changes, n.on_retest):
                if ref is not None and self.node(ref).kind != "step":
                    raise ValueError(f"{n.name}: re-entry {ref!r} must be a step")

    def node(self, name: str | None) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise OutOfOrderEventError(f"unknown node {name!r}")

    def after(self, name: str) -> Node | None:
        names = [n.name for n in self.nodes]
        i = names.index(name) + 1
        return self.nodes[i] if i < len(self.nodes) else None


_REVIEW = frozenset(
    {
        DecisionKind.APPROVE,
        DecisionKind.WAIVE,
        DecisionKind.REQUEST_CHANGES,
        DecisionKind.REJECT,
    }
)

# PLAN 3 default order: implement, review gate, QA, QA gate, then the merge. Request changes
# at either gate goes back to implement, so the review gate runs again (PLAN 4.2); retest
# returns to the QA stage on the same SHA (PLAN 4.2). Only QA offers retest (PLAN 4.1, 4.7).
LINEAR_V0 = Workflow(
    version="linear-v0",
    nodes=(
        Node("implement", "step", produces_code=True),
        Node(
            "review_gate",
            "gate",
            gate_type=GateType.REVIEW,
            decisions=_REVIEW,
            on_changes="implement",
        ),
        Node("qa", "step"),
        Node(
            "qa_gate",
            "gate",
            gate_type=GateType.QA,
            decisions=_REVIEW | {DecisionKind.RETEST},
            on_changes="implement",
            on_retest="qa",
        ),
        Node("merge", "effect", effect="pr.merge", requires_gates=("review_gate", "qa_gate")),
    ),
)


@dataclass(frozen=True)
class Approval:
    gate: str
    round: int
    decision_id: DecisionId
    subject_digest: str


@dataclass(frozen=True)
class RunState:
    """``visit``/``attempt`` are those of the live step; ``round`` is the live gate's (0 when
    none). ``visits`` counts entries per node, so a gate's round is its own count."""

    run: Run
    visit: int = 0
    attempt: int = 0
    round: int = 0
    subject: Subject | None = None
    approvals: tuple[Approval, ...] = ()
    visits: tuple[tuple[str, int], ...] = ()

    def count(self, node: str) -> int:
        return dict(self.visits).get(node, 0)


@dataclass(frozen=True)
class Transition:
    state: RunState
    commands: tuple[object, ...] = ()


class Event(Protocol):
    @property
    def run_id(self) -> RunId: ...


Handler = Callable[[RunState, Any, Workflow], Transition]


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


_loaded: set[str] = set()


def load_handlers(package: str = "sto.engine.handlers") -> None:
    """Import every module of ``package`` so its handlers, events and commands register.

    Call once at startup. D1-03 must call it before decoding stored events, because decoding
    looks names up in the ``sto.domain`` registries that these modules fill. ``next`` never
    imports. Modules load in name order; calling again is a no-op.
    """
    if package in _loaded:
        return
    pkg = importlib.import_module(package)
    for mod in sorted(m.name for m in pkgutil.iter_modules(pkg.__path__)):
        importlib.import_module(f"{package}.{mod}")
    _loaded.add(package)


def next(  # noqa: A001 - the name is the contract (PLAN 6.1)
    state: RunState,
    event: Event,
    workflow: Workflow,
    *,
    registry: HandlerRegistry = HANDLERS,
) -> Transition:
    handler = registry.get(type(event))
    if handler is None:
        raise OutOfOrderEventError(f"no handler for {type(event).__name__}")
    if event.run_id != state.run.id:
        raise OutOfOrderEventError(f"{type(event).__name__} is for another run")
    if state.run.workflow_version not in (None, workflow.version):
        raise WorkflowMismatchError(
            f"run is on {state.run.workflow_version!r}, not {workflow.version!r}"
        )
    return handler(state, event, workflow)
