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

* the candidates are the gates the effect needs, exactly as its claim checks them: its
  ``requires_gates``, plus every routed gate (PLAN 4.3 rule 2);
* a candidate holds when it has an approval whose subject digest equals the current subject's and
  whose ``head_sha`` is the current head, so an approval is tied to a head SHA and never reused on
  code or a ticket it did not see;
* "first" is workflow order: a stage's depth is its fewest edges from ``start``. The earliest
  invalid gate wins. If two invalid gates are equally deep, or one cannot be placed (it is not a
  gate of this workflow, or unreachable), the order is unknown and the run BLOCKS
  ``regate_unresolved``. So does a refusal nothing explains (every approval holds). It fails
  closed.

Returning goes through the existing gate path: ``stages._goto`` onto the gate stage with no loop,
so the gate's visit count is its next round (``round + 1``), ``OpenGate`` is emitted for it (the
gate service links it to the last round with ``plan_round``, D2-08, and decides carry-over,
D2-09), a step is counted against ``max_steps_per_run`` and no loop counter moves. The old round
is never reopened. The approvals that do not hold are dropped, so the gates that follow ask
again (a new head changes the digest, so it drops them all, as ``stages._report`` does).

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


def _depths(wf: Graph) -> dict[str, int]:
    """Fewest edges from ``start`` to each reachable stage."""
    depth = {wf.start: 0}
    queue = deque([wf.start])
    while queue:
        name = queue.popleft()
        edges = getattr(wf.stages.get(name), "next", None) or {}
        for edge in edges.values():
            to, _ = _target(edge)
            if to in wf.stages and to not in depth:
                depth[to] = depth[name] + 1
                queue.append(to)
    return depth


def _holds(approval: Approval | None, subject: Subject) -> bool:
    return (
        approval is not None
        and approval.subject_digest == subject.digest()
        and approval.head_sha == subject.head_sha
    )


def _needed(rs: RunState, stage: EffectStage) -> tuple[str, ...]:
    """The gates the effect's claim checks: as ``stages._goto`` names them."""
    gates = tuple(stage.requires_gates or ())
    return (*gates, *(g for g in rs.routed_gates if gates and g not in gates))


def _first_invalid(
    wf: Graph, needed: tuple[str, ...], approvals: dict[str, Approval], subject: Subject
) -> str | None:
    invalid = [g for g in dict.fromkeys(needed) if not _holds(approvals.get(g), subject)]
    if not invalid:
        return None
    depth = _depths(wf)
    if any(g not in depth or not isinstance(wf.stages.get(g), GateStage) for g in invalid):
        return None
    ranked = sorted(depth[g] for g in invalid)
    if len(ranked) > 1 and ranked[0] == ranked[1]:
        return None  # the workflow does not say which comes first
    return min(invalid, key=lambda g: depth[g])


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
    subject = event.subject if event.subject is not None else rs.subject
    if subject is None:
        return _block(rs, "subject_missing")
    if rs.merges and subject.head_sha not in {m.head_sha for m in rs.merges}:
        return _block(rs, "head_moved")  # merged code cannot change
    approvals = rs.approvals
    by_gate = {a.gate: a for a in approvals}
    first = _first_invalid(wf, _needed(rs, stage), by_gate, subject)
    if first is None:
        return _block(rs, "regate_unresolved")
    needed = set(_needed(rs, stage))
    kept = tuple(a for a in approvals if a.gate not in needed or _holds(a, subject))
    return _goto(dataclasses.replace(rs, subject=subject, approvals=kept), wf, first)


__all__ = ["REGATE_BLOCK", "EffectDisposed", "RegateUnresolved", "on_effect_disposed"]
