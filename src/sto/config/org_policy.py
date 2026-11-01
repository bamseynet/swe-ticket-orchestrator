"""Stored, live ``OrgPolicy``, its typed read API, and V17 (D2-24).

``OrgPolicy`` is read at decision and effect time, never cached into a run: a run pins its
workflow but not the floors (PLAN 7.4), so tightening a floor changes the next read of a run in
flight. Only an org admin writes it, checked at the role seam (``Principal``); D3 supplies real
principals from verified identities, and until then this is the one place the rule lives.

Every question the read API answers fails closed. What the policy does not name is nothing
permitted: a gate type missing from ``decision_surfaces`` has no surface, a gate type that is not
mandatory has no mandatory roles, and an absent quorum counts as one approval, never as zero.

V17 (PLAN 7.3): for the workflow's team, each ``required_gates`` entry exists as a gate with its
role and lies on every path to a successful end (for an entry with ``when``, on every path that
takes that route value), every gate meets ``min_quorum`` for its type, and every gate's
``carry_over`` is in ``allowed_carry_over``. It is a pure function of a flattened workflow and
a policy, so publish, migrate and the live re-check all call the same code.

``FLOOR_TRACKING`` lists every floor in the schema with the issue that enforces it. A test pins
it to the schema fields, so a new floor must be named here, and ``open_floor_report`` says which
issue each unenforced floor waits for.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from sto.config.schema import (
    Edge,
    GateStage,
    Issue,
    OrgPolicy,
    RequiredGate,
    RouteStage,
    SchemaError,
    TerminalStage,
    Workflow,
    load_document,
)
from sto.domain.errors import PermanentError
from sto.store.ports import PLATFORM, Absent, Key, Store, VersionIs

__all__ = [
    "FLOOR_TRACKING",
    "ORG_ADMIN",
    "POLICY_KEY",
    "FloorStatus",
    "OrgPolicy",
    "OrgPolicyStore",
    "PermissionDeniedError",
    "PolicyMissingError",
    "Principal",
    "allowed_carry_over",
    "check_org_required_gates",
    "mandatory_roles",
    "open_floor_report",
    "open_floors",
    "permitted_surfaces",
    "quorum_floor",
    "surface_permitted",
]

ORG_ADMIN = "org_admin"
POLICY_KEY = Key("ORG", "POLICY")


class PermissionDeniedError(PermanentError):
    """The principal lacks the role the write needs."""


class PolicyMissingError(PermanentError):
    """No ``OrgPolicy`` has been written, so there are no floors to read."""


@dataclass(frozen=True)
class Principal:
    """The role seam: who is acting and the roles they hold, in ``team`` (``None`` for none).

    Roles are exact strings. Built by auth from a verified identity (D3); never from a request."""

    actor: str
    roles: frozenset[str] = field(default_factory=frozenset)
    team: str | None = None

    def has(self, role: str) -> bool:
        return role in self.roles


class OrgPolicyStore:
    def __init__(self, store: Store) -> None:
        self._store = store

    def write(self, who: Principal, text: str) -> OrgPolicy:
        """Store ``text`` as the current policy. Org admins only; the text must load."""
        if not who.has(ORG_ADMIN):
            raise PermissionDeniedError(
                f"{who.actor} may not write OrgPolicy: it needs {ORG_ADMIN}"
            )
        doc = load_document(text, source="OrgPolicy")
        if not isinstance(doc, OrgPolicy):
            raise SchemaError([Issue(1, "kind", "kind must be OrgPolicy")])
        current = self._store.get(PLATFORM, POLICY_KEY)
        self._store.put(
            PLATFORM,
            POLICY_KEY,
            {"text": text},
            when=Absent() if current is None else VersionIs(current.version),
        )
        return doc

    def read(self) -> OrgPolicy | None:
        item = self._store.get(PLATFORM, POLICY_KEY)
        if item is None:
            return None
        doc = load_document(str(item.data["text"]), source="OrgPolicy")
        if not isinstance(doc, OrgPolicy):
            raise SchemaError([Issue(1, "kind", "the stored document is not an OrgPolicy")])
        return doc

    def require(self) -> OrgPolicy:
        policy = self.read()
        if policy is None:
            raise PolicyMissingError("no OrgPolicy has been written")
        return policy


# --- typed reads, failing closed -----------------------------------------------------------


def permitted_surfaces(policy: OrgPolicy, gate_type: str) -> frozenset[str]:
    """Surfaces a decision on this gate type may come from. A type the policy does not name
    permits none."""
    by_type: Mapping[Any, tuple[str, ...]] = policy.floors.decision_surfaces
    return frozenset(by_type.get(gate_type, ()))


def surface_permitted(policy: OrgPolicy, gate_type: str, surface: str) -> bool:
    return surface in permitted_surfaces(policy, gate_type)


def mandatory_roles(policy: OrgPolicy, gate_type: str) -> frozenset[str]:
    """Roles that may decide a mandatory gate; empty (nobody) for any other type."""
    by_type: Mapping[Any, tuple[str, ...]] = policy.floors.mandatory_gate_roles
    return frozenset(by_type.get(gate_type, ()))


def quorum_floor(policy: OrgPolicy, team: str, gate_type: str) -> int:
    """Approvals a gate of this type must need for ``team``; never below one."""
    team_policy = policy.teams.get(team)
    if team_policy is None:
        return 1
    by_type: Mapping[Any, int] = team_policy.min_quorum
    return max(1, by_type.get(gate_type, 1))


def allowed_carry_over(policy: OrgPolicy, team: str) -> frozenset[str] | None:
    """Carry-over settings ``team`` may use, or ``None`` when the policy sets no limit."""
    team_policy = policy.teams.get(team)
    if team_policy is None or team_policy.allowed_carry_over is None:
        return None
    return frozenset(team_policy.allowed_carry_over)


# --- V17 -----------------------------------------------------------------------------------

_SUCCESS = frozenset({"done", "done_with_incident"})


def _targets(edges: Mapping[str, str | Edge]) -> Iterable[tuple[str, str]]:
    for outcome, edge in edges.items():
        yield outcome, edge if isinstance(edge, str) else edge.to


def _success_reachable_without(wf: Workflow, gate_id: str, when: tuple[str, str] | None) -> bool:
    """Can a successful terminal be reached from ``start`` with ``gate_id`` removed? With
    ``when`` = (field, value), a route on that field takes only the edge for that value (its
    ``default`` if none is named); every other edge is possible (PLAN 7.3: all edges count)."""
    seen: set[str] = set()
    queue: deque[str] = deque([wf.start])
    while queue:
        sid = queue.popleft()
        if sid in seen or sid == gate_id or sid not in wf.stages:
            continue
        seen.add(sid)
        stage = wf.stages[sid]
        if isinstance(stage, TerminalStage):
            if stage.result in _SUCCESS:
                return True
            continue
        edges = dict(_targets(stage.next))
        if isinstance(stage, RouteStage) and when is not None and stage.field == when[0]:
            taken = edges.get(when[1], edges.get("default"))
            queue.extend([taken] if taken else [])
        else:
            queue.extend(edges.values())
    return False


def _required(wf: Workflow, entry: RequiredGate) -> list[Issue]:
    stage = wf.stages.get(entry.id)
    where = f"stages.{entry.id}"
    cond = f" when {entry.when.field} is {entry.when.value}" if entry.when else ""
    if not isinstance(stage, GateStage):
        return [
            Issue(
                None,
                where,
                f"org policy requires a gate {entry.id} with role {entry.role}{cond}; "
                f"add a gate stage named {entry.id}",
            )
        ]
    if entry.role not in stage.gate.eligible_roles:
        return [
            Issue(
                None,
                f"{where}.gate.eligible_roles",
                f"org policy requires role {entry.role} on gate {entry.id}; "
                "add it to eligible_roles",
            )
        ]
    when = (entry.when.field, entry.when.value) if entry.when else None
    if _success_reachable_without(wf, entry.id, when):
        return [
            Issue(
                None,
                where,
                f"org policy requires gate {entry.id}{cond}, but a path reaches a successful end "
                f"without it; route every such path through {entry.id}",
            )
        ]
    return []


def check_org_required_gates(wf: Workflow, policy: OrgPolicy) -> list[Issue]:
    """V17 for the workflow's team. Empty when the workflow meets the policy."""
    team = wf.metadata.team
    team_policy = policy.teams.get(team)
    if team_policy is None:
        return []
    issues: list[Issue] = []
    for entry in team_policy.required_gates:
        issues.extend(_required(wf, entry))
    carry = allowed_carry_over(policy, team)
    for sid, stage in wf.stages.items():
        if not isinstance(stage, GateStage):
            continue
        gate = stage.gate
        floor = quorum_floor(policy, team, gate.type)
        have = sum(q.count for q in gate.quorum) if gate.quorum else 1
        if have < floor:
            issues.append(
                Issue(
                    None,
                    f"stages.{sid}.gate.quorum",
                    f"org policy needs {floor} approvals on a {gate.type} gate for team {team}, "
                    f"this one needs {have}; raise the quorum to at least {floor}",
                )
            )
        if carry is not None and gate.carry_over not in carry:
            issues.append(
                Issue(
                    None,
                    f"stages.{sid}.gate.carry_over",
                    f"org policy for team {team} does not allow carry_over {gate.carry_over}; "
                    f"use one of: {', '.join(sorted(carry))}",
                )
            )
    return issues


# --- tracking ------------------------------------------------------------------------------


@dataclass(frozen=True)
class FloorStatus:
    """``issue`` enforces the floor. ``done`` once it does, with ``evidence`` a test
    ``path::name`` that proves it."""

    issue: str
    done: bool = False
    evidence: str = ""


_V17_TESTS = "tests/config/test_policy.py"
FLOOR_TRACKING: Mapping[str, FloorStatus] = {
    "floors.single_human_allowed": FloorStatus("D3-05"),
    "floors.requester_excluded_from": FloorStatus("D3-05"),
    "floors.mandatory_gate_roles": FloorStatus("D2-03"),
    "floors.decision_surfaces": FloorStatus("D3-16"),
    "floors.waive_allowed": FloorStatus("D2-03"),
    "floors.hold_after_approval_min": FloorStatus("D4-11"),
    "floors.require_up_to_date": FloorStatus("D4-11"),
    "floors.require_up_to_date_waived_for": FloorStatus("D4-11"),
    "floors.identity_max_age": FloorStatus("D3-15"),
    "floors.public_repo_intake": FloorStatus("D2-17"),
    "floors.ci_without_secrets_waived_for": FloorStatus("D4-26"),
    "floors.route_to_gate_allowed": FloorStatus("D2-25"),
    "teams.*.required_gates": FloorStatus(
        "D2-24", True, f"{_V17_TESTS}::test_v17_refuses_a_missing_required_gate"
    ),
    "teams.*.min_quorum": FloorStatus(
        "D2-24",
        True,
        f"{_V17_TESTS}::test_v17_refuses_quorum_below_the_floor_for_every_gate_of_that_type",
    ),
    "teams.*.allowed_carry_over": FloorStatus(
        "D2-24", True, f"{_V17_TESTS}::test_v17_refuses_carry_over_outside_the_allowed_set"
    ),
}


def open_floors(tracking: Mapping[str, FloorStatus] = FLOOR_TRACKING) -> dict[str, str]:
    """Floor -> the issue that will enforce it, for every floor not yet enforced."""
    return {k: v.issue for k, v in tracking.items() if not v.done}


def open_floor_report(tracking: Mapping[str, FloorStatus] = FLOOR_TRACKING) -> str:
    return "\n".join(f"{k}: {i}" for k, i in open_floors(tracking).items())
