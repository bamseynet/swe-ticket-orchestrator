"""Return to the first invalid gate (D2-28, PLAN 6.3).

A gated effect whose approval no longer holds is voided with ``gate_invalid``, and PLAN 6.3 says
the engine "returns the run to the stage of the first gate whose approval no longer holds". Until
now ``EffectFailed(reason="gate_invalid")`` only BLOCKED the run, and a Retry of it is refused, so
the run could only be cancelled. ``EffectDisposed`` is the event that does the return. The driver
sends it where it sent ``EffectFailed`` for a voided effect (see the PR for the wiring);
``stages.py`` and ``reducer.py`` are not touched, and ``EffectFailed`` still blocks as it did.

``EffectDisposed`` carries the effect, its visit, why it ended (``reason``, the vocabulary of
``EffectFailed``), the run version the driver saw and the *current* subject (a ticket edited after
the final approval has a new ``ticket_revision``; the live subject is the one recorded before).
It names no gate. Which gate is first is decided here from recorded state:

* The candidates are the gates the effect needs, exactly as its claim checks them: its
  ``requires_gates``, plus every routed gate (PLAN 4.3 rule 2).
* A candidate is judged as the claim (``effects/core.py``, ``_approval``) judges it. That check
  reads the store, so this is a pure mirror of it, not a call: a gate holds when it has an
  approval at the current head (``head_sha``). Only the head is compared across gates, because
  gates see different evidence and a ticket edit between two gates is shown to the next one
  (PLAN 4.3). The claim's other void, a live subject that moved since the effect was planned,
  invalidates the gates that approved the subject the run last recorded: their approval is of
  what was edited. A gate that approved an earlier subject at the same head is not made invalid
  by an edit it was never asked about. If the subject has not moved and every gate holds, nothing
  explains the refusal.
* The subject may change, but the head may not. A new head BLOCKS ``head_moved``: it has to go
  through the agent stages and the review panel (``StageReported``) like any other new code, and
  a return straight to a gate would approve a head nobody reviewed. So only ticket or attention
  changes return.
* "First" is decided by the graph, and fails closed. An invalid gate is first only if it lies on
  every path from ``start`` to every other invalid gate (it dominates them). Fewest edges is not
  enough: the order a run visited gates in need not be the order of their depth. If no invalid
  gate dominates the rest (a tie, a branch), or one is not a reachable gate of this workflow, or
  none is invalid, the order is unknown and the run BLOCKS ``regate_unresolved``.

Returning goes through the existing gate path: ``stages._goto`` onto the gate stage with no loop,
so the gate's visit count is its next round (``round + 1``) and ``OpenGate`` is emitted for it.
The gate service links it to the last round with ``plan_round`` (D2-08), and the reopened gate
may close without a person through D2-09 carry-over, as for any re-entered gate. An old round is
never reopened. A step is counted against ``max_steps_per_run`` and no loop counter moves, so the
only bound on repeated returns is that step limit (accepted): each return and the stages after it
spend steps, and the run BLOCKS ``max_steps_exceeded`` when they are spent. The approvals of the
needed gates that do not hold are dropped, so the gates that follow ask again; the ones that
hold, and every approval of a gate the effect does not need, are kept as they were.

Every other ``reason`` (a permanent failure, an unknown outcome, a plain void) BLOCKS with the
reason ``EffectFailed`` gives it. Like every graph handler this is pure and deterministic, reads
no clock and keeps no state. A well-formed but unsafe event BLOCKS and never raises. A stale or
repeated event is refused (``OutOfOrderEventError``): ``run_version`` is the position's identity,
and the return itself moves the run off the effect stage.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass

from sto.config.schema import EffectStage, GateStage
from sto.config.schema import Workflow as Graph
from sto.domain import BLOCKED_REASONS, EVENTS, RunId, Subject
from sto.engine.handlers.core import EFFECT_FAILURE_REASONS
from sto.engine.handlers.stages import (
    _block,
    _effect_stage,
    _goto,
    _out,
    _target,
)
from sto.engine.reducer import Approval, RunState, Transition, handles_graph

GATE_INVALID = "gate_invalid"

# What each non-return reason blocks as: the reasons ``stages.on_effect_failed`` gives them.
REGATE_BLOCK = {
    "blocked": "effect_failed",
    "failed": "effect_failed_permanently",
    "voided": "effect_voided",
}


@BLOCKED_REASONS.register("regate_unresolved")
class RegateUnresolved:
    """The run could not be sent back: no gate is provably the first invalid one."""


@EVENTS.register("effect.disposed")
@dataclass(frozen=True)
class EffectDisposed:
    """The effect ``effect`` at ``visit`` ended with ``reason`` (``EffectFailed``'s vocabulary).

    ``subject`` is the current subject, or ``None`` for the live one. ``run_version`` is the run
    version the driver saw, so a repeated or late event is refused."""

    run_id: RunId
    effect: str
    visit: int
    reason: str
    subject: Subject | None = None
    run_version: int = 0

    def __post_init__(self) -> None:
        if type(self.effect) is not str or not self.effect.strip():
            raise TypeError("effect must be a non-empty str")
        for name in ("visit", "run_version"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:  # a bool is not an int here
                raise TypeError(f"{name} must be a non-negative int")
        if self.reason not in EFFECT_FAILURE_REASONS:
            raise ValueError(f"reason must be one of {EFFECT_FAILURE_REASONS}")
        if self.subject is not None and not isinstance(self.subject, Subject):
            raise TypeError("subject must be a Subject or None")


def _reachable(wf: Graph, avoiding: str | None = None) -> set[str]:
    """The stages reachable from ``start`` without passing through ``avoiding``."""
    if wf.start == avoiding:
        return set()
    seen = {wf.start}
    queue = deque([wf.start])
    while queue:
        edges = getattr(wf.stages.get(queue.popleft()), "next", None) or {}
        for edge in edges.values():
            to, _ = _target(edge)
            if to in wf.stages and to != avoiding and to not in seen:
                seen.add(to)
                queue.append(to)
    return seen


def _holds(approval: Approval | None, subject: Subject, edited: str | None) -> bool:
    """Does the gate's approval hold, as the effect claim sees it? It must be at the current head,
    and must not be of the subject (digest ``edited``) that has since moved."""
    return (
        approval is not None
        and approval.head_sha == subject.head_sha
        and approval.subject_digest != edited
    )


def _needed(rs: RunState, stage: EffectStage) -> tuple[str, ...]:
    """The gates the effect's claim checks: as ``stages._goto`` names them."""
    gates = tuple(stage.requires_gates or ())
    return (*gates, *(g for g in rs.routed_gates if gates and g not in gates))


def _first(wf: Graph, invalid: list[str]) -> str | None:
    """The invalid gate that lies on every path from ``start`` to each other one, if any."""
    anywhere = _reachable(wf)
    if not invalid or any(
        g not in anywhere or not isinstance(wf.stages.get(g), GateStage) for g in invalid
    ):
        return None
    for g in invalid:
        past = _reachable(wf, avoiding=g)
        if not any(h in past for h in invalid if h != g):
            return g
    return None


@handles_graph(EffectDisposed)
def on_effect_disposed(rs: RunState, event: EffectDisposed, wf: Graph) -> Transition:
    stage = _effect_stage(rs, wf, event.effect, event.visit)
    if event.run_version != rs.run.version:
        raise _out(
            f"stale effect event: it was sent at run version {event.run_version}, "
            f"live is {rs.run.version}"
        )
    if event.reason != GATE_INVALID:
        return _block(rs, REGATE_BLOCK[event.reason])
    live = rs.subject
    if live is None:
        return _block(rs, "subject_missing")
    subject = event.subject if event.subject is not None else live
    if subject.head_sha != live.head_sha:
        return _block(rs, "head_moved")  # new code goes through the panel, not straight to a gate
    edited = live.digest() if subject.digest() != live.digest() else None
    needed = _needed(rs, stage)
    by_gate = {a.gate: a for a in rs.approvals}
    invalid = [g for g in dict.fromkeys(needed) if not _holds(by_gate.get(g), subject, edited)]
    first = _first(wf, invalid)
    if first is None:
        return _block(rs, "regate_unresolved")
    kept = tuple(a for a in rs.approvals if a.gate not in invalid)
    return _goto(dataclasses.replace(rs, subject=subject, approvals=kept), wf, first)


__all__ = ["REGATE_BLOCK", "EffectDisposed", "RegateUnresolved", "on_effect_disposed"]
