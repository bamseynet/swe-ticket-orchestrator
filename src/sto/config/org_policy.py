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

The search starts at ``start`` and at ``on_external_commit`` (every ``ci`` checks stage when it
is unset), because a commit by someone else re-enters the run there. Only a gate's ``approved``
edge passes it; its other outcomes are followed. It assumes the structural rules (V1: every edge
names a stage) already hold, and skips an edge to an unknown stage rather than guessing.

What counts as getting round a required gate, with its approval removed:

* A gate that is not QA (V6, ADR-0005 item 12 allow only QA to follow a merge): any ``done`` or
  ``done_with_incident`` terminal, or any successful ``pr.merge`` or ``release.trigger``,
  whatever terminal follows it. A non-QA gate may not sit behind a merge.
* A QA gate after a merge: ``done`` always. After the merge, ``closed`` or
  ``done_with_incident`` counts too, unless the gate has answered something other than approval
  since the last merge or release (another merge or release clears that), and the run then
  opened a revert (``pr.open_revert``). A rejection that ends in ``rejected`` or ``expired`` is
  fine. Wait timeouts are ignored once merged, as in V6. A merge that ends in a terminal with no
  QA gate on that path is tolerated, as V6 tolerates it.
* For an entry without ``when``, every merge or release downstream of the gate's approval lists
  the gate in ``requires_gates``, so the gate cannot approve before there is code (V4 and V5 do
  the rest). The walk from the approval stops at the first merge or release that lists the gate.
  An entry with ``when`` relies on the ratchet of PLAN 4.3 instead, and every route on its field
  must carry an ``order`` that contains the value, so the value cannot be missed.

``FLOOR_TRACKING`` lists every floor in the schema with the issues that enforce it. A test pins
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
    WaitStage,
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

_SHIPPING_EFFECTS = frozenset({"pr.merge", "release.trigger"})

# Where a path is, for a QA gate that follows a merge.
_NOT_SHIPPED = 0  # nothing merged yet
_SHIPPED = 1  # merged (or released), and the gate has not answered since
_ANSWERED = 2  # the gate answered something other than approval since the last merge
_REVERTING = 3  # and a revert has been opened


def _targets(edges: Mapping[str, str | Edge]) -> Iterable[tuple[str, str]]:
    for outcome, edge in edges.items():
        yield outcome, edge if isinstance(edge, str) else edge.to


def _entry_points(wf: Workflow) -> list[str]:
    if wf.on_external_commit is not None:
        return [wf.start, wf.on_external_commit]
    ci = [sid for sid, st in wf.stages.items() if isinstance(st, ChecksStage) and st.source == "ci"]
    return [wf.start, *ci]


def _success_reachable_without(wf: Workflow, gate_id: str, when: tuple[str, str] | None) -> bool:
    """Can the run get round ``gate_id`` with its approval removed? See the module docstring for
    what counts. With ``when`` = (field, value), a route on that field takes only the edge for
    that value (its ``default`` if none is named, and none at all if it has neither); every other
    edge is possible (PLAN 7.3: all edges count)."""
    gate = wf.stages[gate_id]
    qa = isinstance(gate, GateStage) and gate.gate.type == "qa"
    seen: set[tuple[str, int]] = set()
    queue: deque[tuple[str, int]] = deque((sid, _NOT_SHIPPED) for sid in _entry_points(wf))
    while queue:
        state = queue.popleft()
        sid, phase = state
        if state in seen or sid not in wf.stages:  # V1 has run: an unknown stage is not ours
            continue
        seen.add(state)
        stage = wf.stages[sid]
        if isinstance(stage, TerminalStage):
            result = stage.result
            if result == "done":
                return True
            if phase == _NOT_SHIPPED and result == "done_with_incident":
                return True
            if phase in (_SHIPPED, _ANSWERED) and result in ("done_with_incident", "closed"):
                return True
            continue
        edges = dict(_targets(stage.next))
        if sid == gate_id:
            edges.pop("approved", None)  # approval is what passes it; everything else goes on
            if phase >= _SHIPPED:
                phase = _ANSWERED
        if isinstance(stage, RouteStage) and when is not None and stage.field == when[0]:
            taken = edges.get(when[1], edges.get("default"))
            edges = {} if taken is None else {"taken": taken}
        if phase >= _SHIPPED and isinstance(stage, WaitStage):
            edges.pop("timeout", None)  # as V6: a timeout is not a way out once merged
        if isinstance(stage, EffectStage) and stage.effect == "pr.open_revert":
            phase = _REVERTING if phase == _ANSWERED else phase
        ships = isinstance(stage, EffectStage) and stage.effect in _SHIPPING_EFFECTS
        for outcome, target in edges.items():
            onward = phase
            if ships and outcome == "done":
                if not qa:
                    return True  # only a QA gate may follow a merge
                onward = _SHIPPED  # a new merge or release clears what the gate answered
            queue.append((target, onward))
    return False


def _shipping_effects_after(wf: Workflow, gate: GateStage, gate_id: str) -> list[str]:
    """Merge and release stages that follow the gate's approval without requiring it.

    The walk goes on past a merge or release only when it lists the gate. One that lists it is
    the effect the approval is for, and what follows it (Kanban sends a stale release back round
    through QA and the implementer to another merge) is judged by that effect's own claim."""
    first = dict(_targets(gate.next)).get("approved")
    seen: set[str] = set()
    queue = deque([first] if first else [])
    found: list[str] = []
    while queue:
        sid = queue.popleft()
        if sid in seen or sid not in wf.stages:
            continue
        seen.add(sid)
        stage = wf.stages[sid]
        if isinstance(stage, TerminalStage):
            continue
        if isinstance(stage, EffectStage) and stage.effect in _SHIPPING_EFFECTS:
            if gate_id not in (stage.requires_gates or ()):
                found.append(sid)
            continue
        queue.extend(t for _, t in _targets(stage.next))
    return sorted(found)


def _routes_missing_value(wf: Workflow, field_name: str, value: str) -> list[str]:
    """Routes on ``field_name`` whose ``order`` is absent or does not contain ``value``."""
    return [
        rid
        for rid, st in wf.stages.items()
        if isinstance(st, RouteStage)
        and st.field == field_name
        and (st.order is None or value not in st.order)
    ]


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
    issues: list[Issue] = []
    if entry.when is not None:
        for rid in _routes_missing_value(wf, entry.when.field, entry.when.value):
            issues.append(
                Issue(
                    None,
                    f"stages.{rid}.order",
                    f"org policy requires gate {entry.id}{cond}, so route {rid} needs an order "
                    f"that contains {entry.when.value}; without it a value outside the order "
                    "takes the default and skips the gate",
                )
            )
    if _success_reachable_without(wf, entry.id, when):
        issues.append(
            Issue(
                None,
                where,
                f"org policy requires gate {entry.id}{cond}, but a path gets round its approval "
                f"(to a successful end, or through a merge or release); route every such path "
                f"through {entry.id}, and put any non-QA gate before the merge",
            )
        )
    if entry.when is None:
        for eid in _shipping_effects_after(wf, stage, entry.id):
            issues.append(
                Issue(
                    None,
                    f"stages.{eid}.requires_gates",
                    f"org policy requires gate {entry.id}, and {eid} comes after its approval; "
                    f"add {entry.id} to requires_gates",
                )
            )
    return issues


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
    "floors.decision_surfaces": FloorStatus(("D2-03", "D3-16")),
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
