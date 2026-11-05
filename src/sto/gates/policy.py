"""The gate service's decision policy (D3-24): each gate's quorum and the SoD verdict, wired.

:class:`GatePolicy` is the :class:`~sto.gates.service.DecisionPolicy` the app gives the service.
It owns no rules. It joins four sources and fails closed when any of them cannot answer:

* :class:`GateRules` says what the published config says about a gate (its eligible roles, quorum
  and ``separation_of_duties``). :class:`WorkflowGates` reads a validated graph workflow by stage
  name; :class:`LinearGates` reads the linear v0 workflow the local stack runs.
* :class:`Directory` turns the actor string a decision carries (``issuer|subject``) into the
  resolved identity, and says whether the account is linked.
* :class:`Records` gives the run's own facts (:class:`~sto.gates.sod.RunFacts`) and the
  eligibility snapshot taken when the gate opened. :class:`StoreRecords` reads them from the store.
* ``floors`` are the org floors :func:`sto.gates.sod.evaluate` applies whatever the gate says.

What fails closed, and how:

* **Unknown gate** (no config for its name): ``refusals`` bars every decision, a veto too, and
  ``roles`` is empty, so nothing counts. The gate still opens (with no quorum record) so the
  state is visible, instead of a run that cannot open its gate and says nothing.
* **Unknown identity, a service identity, an unlinked account, no snapshot**: ``evaluate`` or the
  directory refuses (``unknown_identity``, ``service_identity``, ``unlinked``,
  ``not_eligible_at_open``).
* **Binding**: the identity the directory returns must be the decision's actor
  (``actor_mismatch``), the config's gate type must be the gate's (``gate_type_mismatch``), and a
  config that has a quorum needs the quorum record frozen when the gate opened
  (``quorum_not_frozen``), so a config that gains a quorum later cannot close an old gate on one
  approval.
* **Any error** while resolving the identity, reading the records or evaluating: the decision is
  refused with ``sod_error:<ExceptionType>``. Nothing is swallowed into an allow.
* **No policy at all** is the service's own refusal (``QuorumConfigError`` for a gate with a
  quorum). Nothing here makes a service without a policy refuse a gate that has none to read: a
  production builder must refuse to build one without a policy.

A quorum the config validator would refuse (V7: a role that is not eligible, listed twice, a count
below 1; and the org's ``min_quorum`` for the gate type) is refused at ``quorum``, which is read by
``open_gate`` before anything is written, so it never reaches a stored gate.

Not done here, and why (see the PR): the vote and close transactions do not ``Check`` the versions
of the role and mapping items this policy read (that is a ``service.py`` change, #65 and #66);
``RunFacts.assignees`` and ``admin_actions`` have no stored source yet, so :class:`StoreRecords`
leaves them empty; the eligibility snapshot (D3-08a) has no store yet, so it is a port.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from typing import Any, Protocol

from sto.config.schema import Floors, GateStage
from sto.config.schema import Gate as GateConfig
from sto.config.schema import Workflow as GraphWorkflow
from sto.domain import Decision, DecisionKind, Gate, GateId, RunId, from_wire
from sto.engine.reducer import Workflow as LinearWorkflow
from sto.gates.hooks import run_pk
from sto.gates.service import QuorumConfigError, QuorumRule
from sto.gates.sod import Approval, Commit, Resolution, RunFacts, evaluate
from sto.identity.mapping import ServiceIdentity, UserIdentity
from sto.store.ports import Key, Scope, Store, TeamScope

__all__ = [
    "Directory",
    "GatePolicy",
    "GateRules",
    "LinearGates",
    "Records",
    "StoreRecords",
    "WorkflowGates",
    "check_quorum",
]

log = logging.getLogger("sto.gates")

Who = UserIdentity | ServiceIdentity


class GateRules(Protocol):
    def gate(self, scope: Scope, gate: Gate) -> GateConfig | None:
        """The config of ``gate`` (by name), or ``None`` if there is none: nothing counts."""
        ...


class Directory(Protocol):
    def who(self, scope: Scope, actor: str) -> Who | None:
        """The identity behind an actor key, resolved now; ``None`` if nobody."""
        ...

    def linked(self, scope: Scope, actor: str) -> bool:
        """Is this account linked to its SSO identity (D3-04)?"""
        ...


class Records(Protocol):
    def facts(self, scope: Scope, gate: Gate) -> RunFacts:
        """The run's own records, read fresh. May raise: the policy then refuses."""
        ...

    def opened_with(self, scope: Scope, gate: Gate) -> frozenset[str] | None:
        """Who was eligible when the gate opened; ``None`` when there is no snapshot."""
        ...

    def quorum_frozen(self, scope: Scope, gate: Gate) -> bool:
        """Was a quorum record written when the gate opened?"""
        ...


class WorkflowGates:
    """Gate config of a validated graph workflow, by stage name (the name ``OpenGate`` carries)."""

    def __init__(self, workflow: GraphWorkflow) -> None:
        self._gates = {
            name: stage.gate
            for name, stage in workflow.stages.items()
            if isinstance(stage, GateStage)
        }

    def gate(self, scope: Scope, gate: Gate) -> GateConfig | None:
        return self._gates.get(gate.name)


class LinearGates:
    """Gate config for the linear v0 workflow, which has no quorum or SoD terms of its own: the
    eligible roles of each gate (``roles_of``, None for a gate that names nobody, which then has no
    config) and one approval, or the ``quorums`` given by gate name."""

    def __init__(
        self,
        workflow: LinearWorkflow,
        roles_of: Callable[[Gate], frozenset[str] | None],
        quorums: Mapping[str, Sequence[QuorumRule]] | None = None,
    ) -> None:
        self._workflow = workflow
        self._roles_of = roles_of
        self._quorums = quorums or {}

    def gate(self, scope: Scope, gate: Gate) -> GateConfig | None:
        node = next((n for n in self._workflow.nodes if n.name == gate.name), None)
        roles = self._roles_of(gate)
        if node is None or node.gate_type is None or not roles:
            return None
        body: dict[str, Any] = {
            "type": node.gate_type.value,
            "eligible_roles": sorted(roles),
            "decisions": sorted(d.value for d in node.decisions) or ["approve"],
            "decision_surfaces": ["ui"],
        }
        if gate.name in self._quorums:
            body["quorum"] = [{"role": q.role, "count": q.count} for q in self._quorums[gate.name]]
        return GateConfig.model_validate(body)


def check_quorum(cfg: GateConfig, *, floor: int = 1) -> list[QuorumRule]:
    """The quorum of ``cfg`` as rules, or :class:`QuorumConfigError` for what the validator (V7 and
    the org ``min_quorum``) refuses. No quorum is one approval, so it must meet ``floor`` too."""
    seen: set[str] = set()
    rules: list[QuorumRule] = []
    for entry in cfg.quorum or ():
        if entry.role in seen:
            raise QuorumConfigError(f"quorum role {entry.role!r} is listed twice")
        seen.add(entry.role)
        if entry.role not in cfg.eligible_roles:
            raise QuorumConfigError(f"quorum role {entry.role!r} is not an eligible role")
        if entry.count < 1:
            raise QuorumConfigError(f"quorum role {entry.role!r} needs a count of at least 1")
        rules.append(QuorumRule(entry.role, entry.count))
    needed = sum(r.count for r in rules) if rules else 1
    if needed < floor:
        raise QuorumConfigError(
            f"a {cfg.type} gate needs {floor} approvals by org policy; this one needs {needed}"
        )
    return rules


class GatePolicy:
    def __init__(
        self,
        *,
        rules: GateRules,
        directory: Directory,
        records: Records,
        floors: Floors,
        quorum_floor: Callable[[str, str], int] = lambda team, gate_type: 1,
        actor_key: Callable[[Who], str] = lambda who: f"{who.issuer}|{who.subject}",
    ) -> None:
        self._actor_key = actor_key
        self._rules, self._directory, self._records = rules, directory, records
        self._floors, self._quorum_floor = floors, quorum_floor

    def quorum(self, scope: Scope, gate: Gate) -> Sequence[QuorumRule]:
        cfg = self._rules.gate(scope, gate)
        if cfg is None:
            return []  # nothing to enforce; refusals() bars every decision on this gate
        team = scope.team if isinstance(scope, TeamScope) else ""
        return check_quorum(cfg, floor=self._quorum_floor(team, gate.type.value))

    def roles(self, scope: Scope, gate: Gate, actor: str) -> Collection[str]:
        cfg = self._rules.gate(scope, gate)
        who = self._directory.who(scope, actor)
        if cfg is None or not isinstance(who, UserIdentity) or not isinstance(scope, TeamScope):
            return frozenset()
        return who.roles_in(scope.team) & frozenset(cfg.eligible_roles)

    def refusals(self, scope: Scope, gate: Gate, actor: str, *, negative: bool) -> Sequence[str]:
        try:
            return self._refusals(scope, gate, actor, negative=negative)
        except Exception as e:  # an SoD error is a refusal, never an allow
            log.error("separation of duties failed for gate %s: %r", gate.name, e, exc_info=e)
            return [f"sod_error:{type(e).__name__}"]

    def _refusals(self, scope: Scope, gate: Gate, actor: str, *, negative: bool) -> list[str]:
        cfg = self._rules.gate(scope, gate)
        if cfg is None:
            return ["unknown_gate"]
        if not isinstance(scope, TeamScope):
            return ["no_team"]
        if cfg.type != gate.type.value:
            return ["gate_type_mismatch"]
        if check_quorum(cfg) and not self._records.quorum_frozen(scope, gate):
            return ["quorum_not_frozen"]
        who = self._directory.who(scope, actor)
        if who is None:
            return ["unknown_identity"]
        if self._actor_key(who) != actor:
            return ["actor_mismatch"]
        verdict = evaluate(
            who=who,
            linked=self._directory.linked(scope, actor),
            team=scope.team,
            gate=gate,
            eligible_roles=frozenset(cfg.eligible_roles),
            opened_with=self._records.opened_with(scope, gate),
            sod=cfg.separation_of_duties,
            floors=self._floors,
            facts=self._records.facts(scope, gate),
            negative=negative,
        )
        return [] if verdict.allowed else list(verdict.reasons)


class StoreRecords:
    """:class:`Records` over the store: the run's commits and resolutions through ``read`` (the
    attribution records, D3-19), its starter through ``requester_of``, and its approvals from the
    gate service's own decision and vote records. ``snapshot`` gives the eligibility snapshot.

    Every approval on the run counts, a vote below quorum included and a voided round included:
    that can only bar more people, never fewer. An approval by an actor that is not in
    ``issuer|subject`` form is skipped: ``evaluate`` only ever asks about actors in that form, so it
    could never match."""

    def __init__(
        self,
        store: Store,
        *,
        read: Callable[
            [Store, TeamScope, RunId], tuple[tuple[Commit, ...], tuple[Resolution, ...]]
        ],
        requester_of: Callable[[Scope, RunId], str | None],
        snapshot: Callable[[Scope, Gate], frozenset[str] | None] = lambda scope, gate: None,
    ) -> None:
        self._store, self._read = store, read
        self._requester_of, self._snapshot = requester_of, snapshot

    def opened_with(self, scope: Scope, gate: Gate) -> frozenset[str] | None:
        return self._snapshot(scope, gate)

    def quorum_frozen(self, scope: Scope, gate: Gate) -> bool:
        key = Key(run_pk(gate.run_id), f"QUO#{gate.name}#{gate.round}")
        return self._store.get(scope, key) is not None

    def facts(self, scope: Scope, gate: Gate) -> RunFacts:
        if not isinstance(scope, TeamScope):
            raise ValueError("run facts need a team scope")
        commits, resolutions = self._read(self._store, scope, gate.run_id)
        return RunFacts(
            requester=self._requester_of(scope, gate.run_id),
            commits=commits,
            resolutions=resolutions,
            approvals=self._approvals(scope, gate.run_id),
        )

    def _scan(self, scope: Scope, run_id: RunId, prefix: str) -> Iterator[dict[str, Any]]:
        cursor: str | None = None
        while True:
            page = self._store.query(scope, run_pk(run_id), sk_prefix=prefix, cursor=cursor)
            for item in page.items:
                yield item.data
            cursor = page.cursor
            if cursor is None:
                return

    def _approvals(self, scope: Scope, run_id: RunId) -> tuple[Approval, ...]:
        gates = {g.id: g for g in (from_wire(Gate, d) for d in self._scan(scope, run_id, "GATE#"))}
        decisions = [from_wire(Decision, d) for d in self._scan(scope, run_id, "DEC#")]
        decisions += [
            from_wire(Decision, d["decision"]) for d in self._scan(scope, run_id, "VOTE#")
        ]
        found: list[Approval] = []
        for d in decisions:
            gid: GateId = d.gate_id
            gate = gates.get(gid)
            if d.kind is not DecisionKind.APPROVE or gate is None or "|" not in d.actor:
                continue
            found.append(Approval(gate.name, gate.type, d.actor))
        return tuple(found)
