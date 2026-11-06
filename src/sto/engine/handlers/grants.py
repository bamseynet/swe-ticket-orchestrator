"""Loop grants and route-to-gate (D2-25, PLAN 6.2).

Two human actions on a BLOCKED run, both limited to what the graph allows, both audited, and both
refused by default. The reducer stays pure: no clock and no context variable. Time arrives on the
event, stamped by the service from an injected clock, and the handlers only compare numbers.

**Loop grant.** A run whose loop edge hit its cap is ``BLOCKED(loop_exhausted)`` and stays on the
stage it was leaving. A team admin can grant it extra rounds of that loop. The grant names the
stage, the outcome (the looping edge) and the loop, and is bounded and fails closed. It gives no
extra iteration when it is missing, is for another run, stage or loop edge, is not yet valid or has
expired (``applied_at`` is outside ``[issued_at, expires_at)``, or a time is not finite), the loop
is not actually spent, the grant does not name the edge the run was blocked on (``other_edge``: the
reducer records it in ``RunState.blocked_edge`` and a grant reads it, so a QA stage blocked on
request-changes is never granted into a retest, as PLAN 6.2 requires), the run has no recorded edge
for this stage (``edge_unknown``: a run saved before the field existed, which fails closed rather
than guessing), or the rounds would take the run's total
grants for that loop past the loop's own cap (``MAX_GRANT_ROUNDS_FACTOR`` times it) or past the org
ceiling ``max_loop`` (``LoopGranted.loop_ceiling``, read by the service; none set means the platform
cap), so the loop never runs more often than the org allows.

Expiry is the service's: the reducer reads no clock, so ``applied_at`` is stamped on the event by
the service and only compared. A grant is not revoked by time inside the reducer. The real guard
against a late or replayed grant is ``run_version``: it must equal the run's version, and any
accepted event bumps it. Such an event is *not* an error and not
a new block: it returns the state as it was, because the run is already BLOCKED and a raise would
drop the event. A stale or repeated event (wrong run version) and a run that is not blocked on a
spent loop raise ``OutOfOrderEventError``, as ``RetryRequested`` does.

An accepted grant gives the rounds back by lowering that loop's counter, then takes the edge again
through ``stages._goto``, so every other guard (``max_steps_per_run``, a gate's subject) still
applies; if one of them blocks, the counters are as they were. The running total of rounds granted
is kept in ``RunState.loops`` under ``"<loop>#granted"`` (identifiers cannot contain ``#``, so it
cannot collide with a loop). A grant that resumes the run clears ``blocked_edge``.

**Route-to-gate.** For a persistent false positive of a ``review_panel`` (its ``findings`` edge is a
spent loop), a team admin sends the run to the gate its ``clean`` edge leads to, under the org floor
``route_to_gate_allowed``. It opens that gate through the normal ``OpenGate`` command, puts the
item on the attention list (``AddToAttention``, with the ``attention_digest``) and bars the actor
from that gate round (``BarFromRound``, which is an SoD ``AdminAction``, so ``admin_self_service``
excludes them). The commands come in the order ``BarFromRound``, ``OpenGate``, ``AddToAttention``,
so the router is barred before the gate exists. Refused (state unchanged) when: the patch is not
*known* not to be blocked by path policy or a secret scan (G20: ``patch_blocked`` must be exactly
``False``), the floor is off (the default), the run is not at a review panel, the panel's ``clean``
edge does not lead straight to a gate (so the route never skips a stage, and never goes past
``branch.push``), or the gate would not open (no head subject, step limit). No loop counter moves.

``GrantService`` and ``RouteService`` are the audited paths: check (role, floor, the same refusal
the reducer would give, a dry run of the reducer), write the audit record (a refusal is audited
too), then submit. An unaudited action never runs. Who may call them (``team_admin``) is checked
here by the injected ``admins``; the API route is D3's.

Wiring, not done here: ``load_handlers()`` imports this module, so its handlers register. It
needs no line in ``handlers/stages.py``. A driver that executes commands must handle
``AddToAttention`` and ``BarFromRound``: the first writes the attention list entry, the second a
``AdminAction`` (``as_admin_action()``) to the run's records that SoD reads.
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from sto.config.schema import PLATFORM_MAX_STEPS, Edge, GateStage, ReviewPanelStage
from sto.config.schema import Workflow as Graph
from sto.domain import COMMANDS, EVENTS, RunId, RunStatus
from sto.domain.models import BlockedEdge
from sto.engine.handlers.stages import _goto, _target
from sto.engine.reducer import (
    MalformedEventError,
    OutOfOrderEventError,
    RunState,
    Transition,
    handles_graph,
)
from sto.gates.sod import AdminAction
from sto.gates.subject import AttentionItems, attention_digest

MAX_GRANT_ROUNDS_FACTOR = 1  # total rounds granted for a loop <= this times the loop's own cap
# A loop never runs more than the org ceiling ``max_loop`` allows, grants included. With no ceiling
# set the platform cap holds (``Ceilings`` docs).
DEFAULT_GRANT_TTL = 900.0  # seconds a grant stays valid after it is issued
GRANTED_SUFFIX = "#granted"


def _granted_key(loop: str) -> str:
    return loop + GRANTED_SUFFIX


def _finite(*values: object) -> bool:
    return all(
        isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v) for v in values
    )


# --- loop grants ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoopGrant:
    """Extra ``rounds`` of ``loop``, for the edge ``stage`` -> ``outcome``, valid from
    ``issued_at`` until (not including) ``expires_at``. Times are seconds from the service's
    injected clock. A time that is not finite is refused at use, not at construction."""

    run_id: RunId
    stage: str
    outcome: str
    loop: str
    rounds: int
    actor: str
    reason: str
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        # A decoded event can carry any JSON, so every field is checked: a mistyped grant is
        # refused here (ValueError, on decode) and never reaches the reducer as a TypeError.
        if not isinstance(self.run_id, RunId):
            raise ValueError(f"grant run_id must be a RunId, not {self.run_id!r}")
        for name in ("stage", "outcome", "loop", "actor", "reason"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"grant {name} must be a non-blank string, not {value!r}")
        if type(self.rounds) is not int or self.rounds < 1:
            raise ValueError(f"grant rounds must be a positive integer, not {self.rounds!r}")
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError(f"grant {name} must be a number, not {value!r}")


@EVENTS.register("loop.granted")
@dataclass(frozen=True)
class LoopGranted:
    """A team admin's grant (or ``None``: no grant, which changes nothing), applied at
    ``applied_at`` on the service's clock, against the run at ``run_version``. ``loop_ceiling`` is
    the org's ``max_loop`` read by the service (``None``: none set, so the platform cap holds)."""

    run_id: RunId
    grant: LoopGrant | None
    run_version: int
    applied_at: float
    loop_ceiling: int | None = None


def _blocked_on_loop(rs: RunState) -> bool:
    return rs.run.status is RunStatus.BLOCKED and rs.run.blocked_reason == "loop_exhausted"


def _blocked_edge(rs: RunState) -> BlockedEdge | None:
    """The recorded edge, if it is for the stage the run is blocked on."""
    edge = rs.blocked_edge
    return edge if edge is not None and edge.stage == rs.run.stage else None


def _edges(wf: Graph, stage: str | None) -> Mapping[str, str | Edge] | None:
    found = wf.stages.get(stage or "")
    edges = getattr(found, "next", None)
    return edges if edges else None


def grant_refusal(
    rs: RunState,
    wf: Graph,
    grant: LoopGrant | None,
    *,
    applied_at: float,
    loop_ceiling: int | None = None,
) -> str | None:
    """Why ``grant`` gives no extra iteration, or ``None`` when it does. Pure.

    The blocked edge is read from ``RunState.blocked_edge``, never derived from the workflow or
    the counts, which can change after the block. PLAN 6.2 says a grant never changes an outcome,
    so it must name that edge (``other_edge``). With no recorded edge it fails closed
    (``edge_unknown``)."""
    if grant is None:
        return "missing"
    if grant.run_id != rs.run.id:
        return "other_run"
    if not _finite(grant.issued_at, grant.expires_at, applied_at):
        return "bad_time"
    if applied_at < grant.issued_at:
        return "not_yet_valid"
    if applied_at >= grant.expires_at:
        return "expired"
    if grant.stage != rs.run.stage:
        return "other_stage"
    edges = _edges(wf, grant.stage)
    if edges is None or grant.outcome not in edges:
        return "other_loop"
    edge_to, edge_loop = _target(edges[grant.outcome])
    cap = wf.limits.loops.get(grant.loop)
    if edge_loop != grant.loop or cap is None:
        return "other_loop"
    if rs.loop_count(grant.loop) < cap:
        return "not_spent"
    blocked = _blocked_edge(rs)
    if blocked is None:
        return "edge_unknown"
    if (blocked.to, blocked.loop) != (edge_to, edge_loop):
        return "other_edge"
    ceiling = PLATFORM_MAX_STEPS if loop_ceiling is None else loop_ceiling
    if isinstance(ceiling, bool) or not isinstance(ceiling, int) or ceiling < 1:
        return "bad_ceiling"
    room = min(cap * MAX_GRANT_ROUNDS_FACTOR, ceiling - cap)  # the loop never passes the ceiling
    if rs.loop_count(_granted_key(grant.loop)) + grant.rounds > room:
        return "over_cap"
    return None


def _with_count(
    pairs: tuple[tuple[str, int], ...], key: str, value: int
) -> tuple[tuple[str, int], ...]:
    counts = dict(pairs)
    counts[key] = value
    return tuple(sorted(counts.items()))


@handles_graph(LoopGranted)
def on_loop_granted(rs: RunState, event: LoopGranted, wf: Graph) -> Transition:
    if event.run_version != rs.run.version:
        raise OutOfOrderEventError(
            f"stale grant: it was made at run version {event.run_version}, live is {rs.run.version}"
        )
    if not _blocked_on_loop(rs):
        raise OutOfOrderEventError("a loop grant needs a run blocked on a spent loop")
    grant, edges = event.grant, _edges(wf, event.grant.stage if event.grant else None)
    why = grant_refusal(rs, wf, grant, applied_at=event.applied_at, loop_ceiling=event.loop_ceiling)
    if why is not None or grant is None or edges is None:
        return Transition(rs)  # no extra iteration, and nothing moved
    to, loop = _target(edges[grant.outcome])
    if loop != grant.loop:  # grant_refusal proved this; kept explicit, not as an assert
        return Transition(rs)
    cap = wf.limits.loops[grant.loop]
    loops = _with_count(rs.loops, grant.loop, min(rs.loop_count(grant.loop), cap) - grant.rounds)
    loops = _with_count(
        loops, _granted_key(grant.loop), rs.loop_count(_granted_key(grant.loop)) + grant.rounds
    )
    resumed = dataclasses.replace(
        rs, run=rs.run.advance(RunStatus.RUNNING), loops=loops, blocked_edge=None
    )
    out = _goto(resumed, wf, to, loop)
    if out.state.run.status is RunStatus.BLOCKED:
        # Another guard refused the entry (step limit, a gate's subject): the rounds are not spent.
        return Transition(
            dataclasses.replace(out.state, loops=rs.loops, blocked_edge=None), out.commands
        )
    return out


# --- route-to-gate -------------------------------------------------------------------------


@COMMANDS.register("add_to_attention")
@dataclass(frozen=True)
class AddToAttention:
    """Put the routed item on the attention list: the panel ``stage`` it was routed past, the
    ``gate`` round it goes to, who did it and why, and the items (with their digest)."""

    run_id: RunId
    stage: str
    gate: str
    round: int
    actor: str
    reason: str
    items: AttentionItems
    digest: str


@COMMANDS.register("bar_from_round")
@dataclass(frozen=True)
class BarFromRound:
    """``actor`` may not decide ``gate`` round ``round``: they sent the run here."""

    run_id: RunId
    actor: str
    gate: str
    round: int

    def as_admin_action(self) -> AdminAction:
        """The SoD record. ``extend_eligibility`` covers exactly one gate round, which is the
        scope wanted; ``admin_self_service`` then bars the actor from it."""
        return AdminAction(self.actor, "extend_eligibility", self.gate, self.round)


@EVENTS.register("route_to_gate.requested")
@dataclass(frozen=True)
class RouteToGateRequested:
    """A team admin sends a run blocked at a review panel to its next gate.

    ``policy_allowed`` is the org floor ``route_to_gate_allowed`` and ``patch_blocked`` whether the
    patch is blocked by path policy or a secret scan; both are read by the service when it asks.
    Both default to refusal: the floor to off, and ``patch_blocked=None`` (unknown) to blocked."""

    run_id: RunId
    actor: str
    reason: str
    stage: str | None
    run_version: int
    policy_allowed: bool = False
    patch_blocked: bool | None = None
    attention: AttentionItems = AttentionItems()


def _route_target(rs: RunState, wf: Graph) -> str | None:
    stage = wf.stages.get(rs.run.stage or "")
    if not isinstance(stage, ReviewPanelStage) or "clean" not in stage.next:
        return None
    blocked = _blocked_edge(rs)
    if blocked is None or not any(
        o != "clean" and _target(e) == (blocked.to, blocked.loop) for o, e in stage.next.items()
    ):
        return None  # no recorded loop edge of this panel: nothing was spent here
    to, loop = _target(stage.next["clean"])
    if loop is not None or not isinstance(wf.stages.get(to), GateStage):
        return None
    return to


def _route(rs: RunState, wf: Graph, target: str) -> Transition:
    return _goto(dataclasses.replace(rs, run=rs.run.advance(RunStatus.RUNNING)), wf, target)


def route_refusal(rs: RunState, wf: Graph, event: RouteToGateRequested) -> str | None:
    """Why the route is refused, or ``None``. Pure. Most serious first."""
    if event.patch_blocked is not False:  # blocked, or not known not to be (G20)
        return "patch_blocked"
    if event.policy_allowed is not True:
        return "not_allowed"
    if not isinstance(wf.stages.get(rs.run.stage or ""), ReviewPanelStage):
        return "not_review_stage"
    target = _route_target(rs, wf)
    if target is None:
        return "no_next_gate"
    out = _route(rs, wf, target)
    if out.state.run.status is not RunStatus.WAITING_HUMAN:
        return "gate_would_not_open"
    return None


def _check_route_event(event: RouteToGateRequested) -> None:
    for label, value in (("actor", event.actor), ("reason", event.reason)):
        if not isinstance(value, str) or not value.strip():
            raise MalformedEventError(f"a route-to-gate names its {label}")
    try:
        AdminAction(event.actor, "extend_eligibility", "gate", 1)
    except ValueError as e:  # an actor SoD would not recognise would bar nobody
        raise MalformedEventError(str(e)) from None


@handles_graph(RouteToGateRequested)
def on_route_to_gate(rs: RunState, event: RouteToGateRequested, wf: Graph) -> Transition:
    _check_route_event(event)
    if event.run_version != rs.run.version:
        raise OutOfOrderEventError(
            f"stale route: it was asked at run version {event.run_version}, live is "
            f"{rs.run.version}"
        )
    if event.stage != rs.run.stage or not _blocked_on_loop(rs):
        raise OutOfOrderEventError("a route-to-gate needs a run blocked on a spent loop here")
    if route_refusal(rs, wf, event) is not None:
        return Transition(rs)
    target = _route_target(rs, wf)
    if target is None or rs.run.stage is None:  # route_refusal proved both
        return Transition(rs)
    out = _route(rs, wf, target)
    round_ = out.state.round
    add = AddToAttention(
        rs.run.id,
        rs.run.stage,
        target,
        round_,
        event.actor,
        event.reason,
        event.attention,
        attention_digest(event.attention),
    )
    bar = BarFromRound(rs.run.id, event.actor, target, round_)
    # The bar comes first, so the router is barred before the gate exists to be decided.
    return Transition(out.state, (bar, *out.commands, add))


# --- the audited services ------------------------------------------------------------------


class Audit(Protocol):
    """Appends one audit entry, or raises. Wired to the audit chain by the caller."""

    def record(self, run_id: RunId, action: str, actor: str, data: dict[str, object]) -> None: ...


class TeamAdmins(Protocol):
    def is_team_admin(self, team: str, actor: str) -> bool: ...


class RoutePolicy(Protocol):
    """The org floor ``route_to_gate_allowed``, read now (D2-24's typed read API)."""

    def route_to_gate_allowed(self, team: str) -> bool: ...


class PatchFacts(Protocol):
    """Whether the run's patch was blocked by path policy or a secret scan. ``None`` = unknown."""

    def patch_blocked(self, run_id: RunId) -> bool | None: ...


class AttentionSource(Protocol):
    def items_for(self, run_id: RunId, stage: str) -> AttentionItems: ...


class OrgCeilings(Protocol):
    """The org's ``ceilings.max_loop``, read now (``None``: none set). D2-24's reader fills it."""

    def max_loop(self, team: str) -> int | None: ...


class RefusedError(PermissionError):
    """The action was refused; ``why`` is the stable reason that was audited."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


Load = Callable[[RunId], tuple[RunState, Graph]]
Submit = Callable[[RunId, object], Awaitable[None]]


class GrantService:
    def __init__(
        self,
        *,
        audit: Audit,
        admins: TeamAdmins,
        ceilings: OrgCeilings,
        clock: Callable[[], float],
        submit: Submit,
        load: Load,
    ) -> None:
        self._audit, self._admins, self._clock = audit, admins, clock
        self._ceilings = ceilings
        self._submit, self._load = submit, load

    async def grant(
        self,
        run_id: RunId,
        actor: str,
        stage: str,
        outcome: str,
        loop: str,
        rounds: int,
        reason: str,
        *,
        ttl: float = DEFAULT_GRANT_TTL,
    ) -> LoopGranted:
        """Grant ``rounds`` more of ``loop`` at the blocked ``stage``/``outcome``. Order: check,
        audit, submit. A refusal is audited and raises ``RefusedError``."""
        rs, wf = self._load(run_id)
        data: dict[str, object] = {
            "stage": stage,
            "outcome": outcome,
            "loop": loop,
            "rounds": rounds,
            "reason": reason,
        }
        if not self._admins.is_team_admin(rs.run.team, actor):
            self._refuse(run_id, actor, data, "not_team_admin")
        if not isinstance(reason, str) or not reason.strip():
            self._refuse(run_id, actor, data, "no_reason")
        now = self._clock()
        grant = LoopGrant(run_id, stage, outcome, loop, rounds, actor, reason, now, now + ttl)
        ceiling = self._ceilings.max_loop(rs.run.team)
        event = LoopGranted(run_id, grant, rs.run.version, now, ceiling)
        why = grant_refusal(rs, wf, grant, applied_at=now, loop_ceiling=ceiling)
        if why is not None:
            self._refuse(run_id, actor, data, why)
        after = on_loop_granted(rs, event, wf).state  # raises if stale or not blocked on a loop
        if after == rs:
            self._refuse(run_id, actor, data, "no_effect")
        # The real result: another guard (step limit, a gate's subject) may still block the run.
        result = "resumed"
        if after.run.status is RunStatus.BLOCKED:
            result = f"blocked:{after.run.blocked_reason}"
        self._audit.record(
            run_id,
            "loop.grant",
            actor,
            {**data, "expires_at": grant.expires_at, "issued_at": now, "result": result},
        )
        await self._submit(run_id, event)
        return event

    def _refuse(self, run_id: RunId, actor: str, data: dict[str, object], why: str) -> None:
        self._audit.record(run_id, "loop.grant_refused", actor, {**data, "why": why})
        raise RefusedError(why)


class RouteService:
    def __init__(
        self,
        *,
        audit: Audit,
        admins: TeamAdmins,
        policy: RoutePolicy,
        patches: PatchFacts,
        attention: AttentionSource,
        submit: Submit,
        load: Load,
    ) -> None:
        self._audit, self._admins, self._policy = audit, admins, policy
        self._patches, self._attention = patches, attention
        self._submit, self._load = submit, load

    async def route(self, run_id: RunId, actor: str, reason: str) -> RouteToGateRequested:
        """Send the blocked run to its next gate. Order: check, audit, submit. The floor and the
        patch facts are read now, not remembered. A refusal is audited and raises."""
        rs, wf = self._load(run_id)
        stage = rs.run.stage
        data: dict[str, object] = {"stage": stage, "reason": reason}
        if not self._admins.is_team_admin(rs.run.team, actor):
            self._refuse(run_id, actor, data, "not_team_admin")
        items = self._attention.items_for(run_id, stage or "")
        event = RouteToGateRequested(
            run_id,
            actor,
            reason,
            stage,
            rs.run.version,
            policy_allowed=self._policy.route_to_gate_allowed(rs.run.team) is True,
            patch_blocked=self._patches.patch_blocked(run_id),
            attention=items,
        )
        _check_route_event(event)
        why = route_refusal(rs, wf, event)
        if why is not None:
            self._refuse(run_id, actor, data, why)
        out = on_route_to_gate(rs, event, wf)  # raises if stale or not blocked on a loop
        self._audit.record(
            run_id,
            "run.route_to_gate",
            actor,
            {
                **data,
                "gate": out.state.run.stage,
                "round": out.state.round,
                "attention_digest": attention_digest(items),
            },
        )
        await self._submit(run_id, event)
        return event

    def _refuse(self, run_id: RunId, actor: str, data: dict[str, object], why: str) -> None:
        self._audit.record(run_id, "run.route_to_gate_refused", actor, {**data, "why": why})
        raise RefusedError(why)


__all__ = [
    "DEFAULT_GRANT_TTL",
    "MAX_GRANT_ROUNDS_FACTOR",
    "OrgCeilings",
    "AddToAttention",
    "BarFromRound",
    "GrantService",
    "LoopGrant",
    "LoopGranted",
    "RefusedError",
    "RouteService",
    "RouteToGateRequested",
    "grant_refusal",
    "route_refusal",
]
