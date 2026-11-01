"""Stored, live ``OrgPolicy``, its typed read API, and V17 (D2-24).

``OrgPolicy`` is read at decision and effect time, never cached into a run: a run pins its
workflow but not the floors (PLAN 7.4), so tightening a floor changes the next read of a run in
flight. Only an org admin writes it, checked at the role seam (``Principal``); D3 supplies real
principals from verified identities, and until then this is the one place the rule lives.

Every question the read API answers fails closed. What the policy does not name is nothing
permitted: a gate type missing from ``decision_surfaces`` has no surface, a gate type that is not
mandatory has no mandatory roles, and an absent quorum counts as one approval, never as zero.

V17 (PLAN 7.3): for the scope's team, each ``required_gates`` entry exists as a gate whose
decider really is its role, and every path to a successful end passes its approval (for an entry
with ``when``, every path that takes that route value); every gate meets ``min_quorum`` for its
type, and every gate's ``carry_over`` is in ``allowed_carry_over``. The team is the caller's
scope, never the file's ``metadata.team``: a file that names another team is itself refused. It is
a pure function of a flattened workflow and a policy, so publish, migrate and the live re-check
all call the same code.

A path ends successfully at a ``done`` or ``done_with_incident`` terminal, or at any terminal once
``pr.merge`` or ``release.trigger`` has succeeded: a merged change is shipped whatever the
terminal is called. The search starts at ``start`` and at ``on_external_commit`` (every ``ci``
checks stage when it is unset), because a commit by someone else re-enters the run there. Only a
gate's ``approved`` edge passes it; its other outcomes are followed, so a rejection that goes
on to ``done`` is a bypass, while one that loops back to an earlier stage is not.

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
    ChecksStage,
    Edge,
    EffectStage,
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
    "MAX_DOCUMENT_BYTES",
    "ORG_ADMIN",
    "POLICY_KEY",
    "FloorStatus",
    "OrgPolicy",
    "OrgPolicyStore",
    "PermissionDeniedError",
    "PolicyMissingError",
    "Principal",
    "Versioned",
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

    Roles are exact strings. Built by auth from a verified identity (D3); never from a request.
    ``org_admin`` is an org-level role: held inside a team it grants nothing."""

    actor: str
    roles: frozenset[str] = field(default_factory=frozenset)
    team: str | None = None

    def has(self, role: str) -> bool:
        return role in self.roles

    @property
    def is_org_admin(self) -> bool:
        return self.team is None and self.has(ORG_ADMIN)


MAX_DOCUMENT_BYTES = 128 * 1024  # well under the store's item limit, which is not a SchemaError


@dataclass(frozen=True)
class Versioned[T]:
    """A document with the store version it was read at, to pass back as ``expected_version``."""

    document: T
    version: int


def checked_text(text: object, what: str) -> str:
    """The text of a document to store, or a ``SchemaError``: a str within the size limit."""
    if not isinstance(text, str):
        raise SchemaError(
            [Issue(None, "", f"{what} must be given as text, not {type(text).__name__}")]
        )
    size = len(text.encode("utf-8", "surrogatepass"))
    if size > MAX_DOCUMENT_BYTES:
        raise SchemaError(
            [Issue(None, "", f"{what} is {size} bytes; the limit is {MAX_DOCUMENT_BYTES} bytes")]
        )
    return text


def stored_text(data: Mapping[str, Any], what: str) -> str:
    """The text of a stored record, or a ``SchemaError`` when the record has none."""
    text = data.get("text")
    if not isinstance(text, str):
        raise SchemaError([Issue(None, "", f"the stored {what} has no text")])
    return text


class OrgPolicyStore:
    def __init__(self, store: Store) -> None:
        self._store = store

    def write(self, who: Principal, text: str, *, expected_version: int | None) -> OrgPolicy:
        """Store ``text`` as the current policy. Org admins only; the text must load.

        ``expected_version`` is the version from ``read_versioned`` that this edit was made on
        (``None`` to create the first policy). If anyone has written since, the store refuses
        with ``ConditionFailedError``, so a stale copy cannot undo a tightened floor."""
        if not who.is_org_admin:
            raise PermissionDeniedError(
                f"{who.actor} may not write OrgPolicy: it needs {ORG_ADMIN}"
            )
        doc = load_document(checked_text(text, "OrgPolicy"), source="OrgPolicy")
        if not isinstance(doc, OrgPolicy):
            raise SchemaError([Issue(1, "kind", "kind must be OrgPolicy")])
        self._store.put(
            PLATFORM,
            POLICY_KEY,
            {"text": text},
            when=Absent() if expected_version is None else VersionIs(expected_version),
        )
        return doc

    def read_versioned(self) -> Versioned[OrgPolicy] | None:
        item = self._store.get(PLATFORM, POLICY_KEY)
        if item is None:
            return None
        doc = load_document(stored_text(item.data, "OrgPolicy"), source="OrgPolicy")
        if not isinstance(doc, OrgPolicy):
            raise SchemaError([Issue(1, "kind", "the stored document is not an OrgPolicy")])
        return Versioned(doc, item.version)

    def read(self) -> OrgPolicy | None:
        current = self.read_versioned()
        return None if current is None else current.document

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
    """Roles that may decide a mandatory gate. The schema never allows a mandatory gate an empty
    list, so an empty result always means "not a mandatory gate type", never "nobody": it is
    for the caller to treat a type with no mandatory roles as unconstrained by this floor."""
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
_SHIPPING_EFFECTS = frozenset({"pr.merge", "release.trigger"})
_State = tuple[str, bool, bool]  # (stage, a merge or release succeeded, the gate was reached)


def _targets(edges: Mapping[str, str | Edge]) -> Iterable[tuple[str, str]]:
    for outcome, edge in edges.items():
        yield outcome, edge if isinstance(edge, str) else edge.to


def _entry_points(wf: Workflow) -> list[str]:
    if wf.on_external_commit is not None:
        return [wf.start, wf.on_external_commit]
    ci = [sid for sid, st in wf.stages.items() if isinstance(st, ChecksStage) and st.source == "ci"]
    return [wf.start, *ci]


def _success_reachable_without(wf: Workflow, gate_id: str, when: tuple[str, str] | None) -> bool:
    """Can a successful end be reached with ``gate_id`` never approved? With ``when`` =
    (field, value), a route on that field takes only the edge for that value (its ``default`` if
    none is named); every other edge is possible (PLAN 7.3: all edges count)."""
    seen: set[_State] = set()
    queue: deque[_State] = deque((sid, False, False) for sid in _entry_points(wf))
    while queue:
        state = queue.popleft()
        sid, shipped, reached = state
        if state in seen or sid not in wf.stages:
            continue
        seen.add(state)
        stage = wf.stages[sid]
        if isinstance(stage, TerminalStage):
            # After the gate has been reached, a merged change ending in a rejection is the gate
            # doing its work (Kanban puts gates after the merge); only done still counts.
            if stage.result in _SUCCESS or (shipped and not reached):
                return True
            continue
        edges = dict(_targets(stage.next))
        if sid == gate_id:
            edges.pop("approved", None)  # approval is what passes it; everything else goes on
            reached = True
        if isinstance(stage, RouteStage) and when is not None and stage.field == when[0]:
            taken = edges.get(when[1], edges.get("default"))
            edges = {} if taken is None else {"taken": taken}
        for outcome, target in edges.items():
            ships = isinstance(stage, EffectStage) and stage.effect in _SHIPPING_EFFECTS
            queue.append((target, shipped or (ships and outcome == "done"), reached))
    return False


def _decided_by(stage: GateStage, role: str) -> bool:
    gate = stage.gate
    if gate.quorum:
        return any(q.role == role for q in gate.quorum)
    return tuple(gate.eligible_roles) == (role,)


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
    if not _decided_by(stage, entry.role):
        if stage.gate.quorum:
            path, fix = f"{where}.gate.quorum", f"add a quorum entry for {entry.role}"
        else:
            path = f"{where}.gate.eligible_roles"
            fix = f"make {entry.role} the only eligible role, or give a quorum that names it"
        return [
            Issue(
                None,
                path,
                f"org policy requires gate {entry.id} to be decided by {entry.role}, but another "
                f"role can pass it; {fix}",
            )
        ]
    when = (entry.when.field, entry.when.value) if entry.when else None
    if _success_reachable_without(wf, entry.id, when):
        return [
            Issue(
                None,
                where,
                f"org policy requires gate {entry.id}{cond}, but a path reaches a successful end "
                f"without its approval; route every such path through {entry.id}",
            )
        ]
    return []


def check_org_required_gates(wf: Workflow, policy: OrgPolicy, *, team: str) -> list[Issue]:
    """V17 for ``team``, the team of the caller's scope. Empty when the workflow meets the policy.

    A workflow whose ``metadata.team`` names another team is refused, and still checked against
    ``team``, so a file cannot choose which team's requirements apply to it."""
    issues: list[Issue] = []
    if wf.metadata.team != team:
        issues.append(
            Issue(
                None,
                "metadata.team",
                f"this workflow is for team {team}, but the file says {wf.metadata.team}; "
                f"set metadata.team to {team}",
            )
        )
    team_policy = policy.teams.get(team)
    if team_policy is None:
        return issues
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
    """``issues`` enforce the floor, all of them needed. ``done`` once they do, with
    ``evidence`` a test ``path::name`` that proves it."""

    issues: tuple[str, ...]
    done: bool = False
    evidence: str = ""


def _one(issue: str) -> FloorStatus:
    return FloorStatus((issue,))


# V17 is proved here as a pure function, but PLAN 7.3 has it checked at publish, on migrate and
# live, and no caller exists yet: D2-07 publishes, D2-19 migrates, D3-16 checks at decision time.
_V17_WIRING = FloorStatus(("D2-07", "D2-19", "D3-16"))
FLOOR_TRACKING: Mapping[str, FloorStatus] = {
    "floors.single_human_allowed": _one("D3-05"),
    "floors.requester_excluded_from": _one("D3-05"),
    "floors.mandatory_gate_roles": _one("D2-03"),
    "floors.decision_surfaces": _one("D3-16"),
    "floors.waive_allowed": _one("D2-03"),
    "floors.hold_after_approval_min": _one("D4-11"),
    "floors.require_up_to_date": _one("D4-11"),
    "floors.require_up_to_date_waived_for": _one("D4-11"),
    "floors.identity_max_age": _one("D3-15"),
    "floors.public_repo_intake": _one("D2-17"),
    "floors.ci_without_secrets_waived_for": _one("D4-26"),
    "floors.route_to_gate_allowed": _one("D2-25"),
    "teams.*.required_gates": _V17_WIRING,
    "teams.*.min_quorum": _V17_WIRING,
    "teams.*.allowed_carry_over": _V17_WIRING,
}


def open_floors(
    tracking: Mapping[str, FloorStatus] = FLOOR_TRACKING,
) -> dict[str, tuple[str, ...]]:
    """Floor -> the issues that will enforce it, for every floor not yet enforced."""
    return {k: v.issues for k, v in tracking.items() if not v.done}


def open_floor_report(tracking: Mapping[str, FloorStatus] = FLOOR_TRACKING) -> str:
    return "\n".join(f"{k}: {', '.join(i)}" for k, i in open_floors(tracking).items())
