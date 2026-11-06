"""Carry-over in the engine (D2-31, PLAN 4.3 rule 3 and 4.6; invariant G13).

``gates/carry_over.py`` decides; this module feeds it true history and emits the close safely.
Every doubt is a refusal (:class:`CarryRefused` or a refused decision), and a refusal only means
the gate stays open for a person.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast

from sto.config.schema import CarryOver, Floors, Quorum
from sto.domain import (
    Decision,
    DecisionKind,
    Gate,
    GateId,
    GateStatus,
    GateType,
    PermanentError,
    RunId,
    Subject,
    from_wire,
)
from sto.engine.handlers.core import GateClosed
from sto.gates.carry_over import (
    ApproverRecheck,
    BaseRange,
    Citation,
    GateInstance,
    PatchHistory,
    Vote,
    evaluate_carry_over,
)
from sto.gates.evidence import EvidenceCheck
from sto.gates.hooks import run_pk
from sto.gates.policy import Directory, GateRules, Records
from sto.gates.service import CARRY_ACTOR, GateService, QuorumRule, cite_key
from sto.gates.sod import evaluate
from sto.gates.subject import PatchIdError, RoundPlan, patch_id
from sto.store.ports import (
    Absent,
    Check,
    ConditionFailedError,
    Item,
    Key,
    Op,
    Put,
    Scope,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)

__all__ = [
    "CarryEngine",
    "CarryRefused",
    "GitSource",
    "SodRecheck",
    "parse_name_only_z",
    "record_head",
    "record_head_from_git",
]

if TYPE_CHECKING:
    from sto.workspace.git_reader import GitReader

log = logging.getLogger(__name__)


class CarryRefused(Exception):
    """Carry-over cannot be decided safely (an unreadable fact). The gate opens normally."""


def parse_name_only_z(raw: bytes) -> frozenset[str]:
    """The paths of ``git diff --name-only -z --no-renames`` output.

    The output must end in its final NUL: a missing one is a truncated read, which is refused and
    never read as a shorter list. Paths decode with ``surrogateescape`` so a name that is not
    UTF-8 stays distinct instead of being dropped or replaced. An empty name is refused."""
    if not isinstance(raw, bytes):
        raise TypeError("git output must be bytes")
    if not raw:
        return frozenset()
    if not raw.endswith(b"\x00"):
        raise CarryRefused("git diff output does not end in its final NUL: truncated read")
    names = raw[:-1].split(b"\x00")
    if any(not n for n in names):
        raise CarryRefused("git diff output holds an empty path")
    return frozenset(n.decode("utf-8", "surrogateescape") for n in names)


class GitSource(Protocol):
    """What the engine reads from git (``GitReader`` is the production one)."""

    def merge_base(self, head: str) -> str: ...
    def files(self, from_commit: str, to_commit: str) -> frozenset[str]: ...


class SodRecheck:
    """The approver port (``ApproverRecheck``) over ``sod.evaluate``, asked per ``(actor, role)``
    with the role they voted as. Everything is read fresh on each call: the person's identity and
    team membership (``directory``), the re-entered gate's eligibility snapshot and the run's
    facts (``records``), the gate's current rules and the org floors.

    True only when the verdict is ``allowed`` and the gate is not ``blocked``, the role is one the
    gate still accepts and the identity is the person asked about. Any doubt is False. A lookup
    that raises propagates: that is a fault, never a verdict."""

    def __init__(
        self,
        scope: TeamScope,
        *,
        rules: GateRules,
        directory: Directory,
        records: Records,
        floors: Floors,
    ) -> None:
        self._scope, self._rules, self._directory = scope, rules, directory
        self._records, self._floors = records, floors

    def __call__(self, actor: str, role: str, gate: Gate, /) -> bool:
        cfg = self._rules.gate(self._scope, gate)
        if cfg is None or cfg.type != gate.type.value or role not in cfg.eligible_roles:
            return False
        who = self._directory.who(self._scope, actor)
        if who is None or f"{who.issuer}|{who.subject}" != actor:
            return False
        verdict = evaluate(
            who=who,
            linked=self._directory.linked(self._scope, actor),
            team=self._scope.team,
            gate=gate,
            eligible_roles=frozenset({role}),
            opened_with=self._records.opened_with(self._scope, gate),
            sod=cfg.separation_of_duties,
            floors=self._floors,
            facts=self._records.facts(self._scope, gate),
            negative=False,
        )
        return verdict.allowed and not verdict.blocked


# --- what the run remembers: heads and rounds ---------------------------------------------------
#
# ``HEAD#<seq>``   every head the run has had, in order: {sha, patch_id}. ``patch_id`` is None
#                  when it could not be computed, which refuses any carry-over spanning it.
# ``CARRY#n#r``    one per gate round: {merge_base, carried_from}.
# ``CITE#n#r``     written by the carried close itself (``GateService.close_carried``).


def _items(store: Store, scope: Scope, pk: str, prefix: str) -> list[Item]:
    """Every item under ``prefix``, following the cursor to the end, with no filter: a page
    boundary or a status must never hide a round or a head."""
    found: list[Item] = []
    cursor: str | None = None
    while True:
        page = store.query(scope, pk, sk_prefix=prefix, cursor=cursor)
        found += list(page.items)
        cursor = page.cursor
        if cursor is None:
            return found


def _head_key(run_id: RunId, seq: int) -> Key:
    return Key(run_pk(run_id), f"HEAD#{seq:010d}")


def _round_key(gate: Gate) -> Key:
    return Key(run_pk(gate.run_id), f"CARRY#{gate.name}#{gate.round}")


def record_head(store: Store, scope: Scope, run_id: RunId, sha: str, patch: str | None) -> None:
    """Append a head to the run's log (each push and each PR synchronize calls this). A repeat of
    the latest head is a no-op; a new one takes the next sequence number under ``Absent``, so two
    writers cannot both take it (the loser reads again). ``patch`` is None when the patch id
    could not be computed."""
    if not isinstance(sha, str) or not sha.strip():
        raise ValueError("a head needs a sha")
    for _ in range(8):
        items = _items(store, scope, run_pk(run_id), "HEAD#")
        if items and items[-1].data["sha"] == sha:
            return
        try:
            store.transact(
                scope,
                [Put(_head_key(run_id, len(items) + 1), {"sha": sha, "patch_id": patch}, Absent())],
            )
        except (ConditionFailedError, TransactionConflictError):
            continue
        return
    raise CarryRefused("the head log kept changing")


def record_head_from_git(
    store: Store, scope: Scope, run_id: RunId, sha: str, git: GitReader
) -> None:
    """Record ``sha`` with the patch id of its diff against its merge base, or with None when git
    or ``patch_id`` cannot produce one."""
    try:
        patch: str | None = patch_id(git.diff(git.merge_base(sha), sha))
    except (CarryRefused, PatchIdError):
        patch = None
    record_head(store, scope, run_id, sha, patch)


@dataclass(frozen=True)
class _Read:
    """What one attempt read, and the versions its close is conditioned on."""

    history: list[GateInstance]
    patch_history: PatchHistory
    patch_files: frozenset[str]
    base_range: BaseRange | None
    chain: int | None
    heads: int  # how many heads were logged when read
    round_item: Item


class CarryEngine:
    """Decides a re-entered gate's carry-over and, if it holds, closes it (G13).

    ``carry_of(run_id, gate_name)`` is the gate's ``carry_over`` read from the run's *pinned*
    workflow (None when it cannot be read); ``allowed(team)`` is the org's ``allowed_carry_over``
    (None: the org states no limit). ``recheck`` is the approver port (``sod.evaluate`` per voted
    role, fresh identity and membership) and ``roles_of`` the roles a person holds now on the
    gate. Anything that cannot be read is a refusal and the gate stays open."""

    def __init__(
        self,
        store: Store,
        gates: GateService,
        git: GitSource,
        *,
        carry_of: Callable[[RunId, str], CarryOver | None],
        allowed: Callable[[str], Collection[str] | None],
        recheck: ApproverRecheck,
        roles_of: Callable[[Scope, Gate, str], Collection[str]],
    ) -> None:
        self._store, self._gates, self._git = store, gates, git
        self._carry_of, self._allowed = carry_of, allowed
        self._recheck, self._roles_of = recheck, roles_of

    # --- the head log ---

    def note_head(self, scope: Scope, run_id: RunId, subject: Subject | None) -> None:
        """Record a head the run reported (a push by an agent stage): its sha and the patch id the
        subject carries."""
        if subject is not None and subject.head_sha is not None:
            record_head(self._store, scope, run_id, subject.head_sha, subject.patch_id)

    # --- entry point ---

    def on_open(self, scope: Scope, gate: Gate) -> GateClosed | None:
        """Called after the gate is opened (and again on a replay). Returns the ``GateClosed``
        event of a carried close, or None when a person must decide."""
        if gate.type is GateType.PRE_PUSH or gate.subject.head_sha is None:
            return None
        cited = self._store.get(scope, cite_key(gate))
        if cited is not None:
            return self._replayed(scope, gate, cited)
        if not gate.is_open:
            return None
        try:
            base = self._git.merge_base(gate.subject.head_sha)
            self._persist_round(scope, gate, base)
            if not self._enabled(scope, gate):
                return None
            return self._carry(scope, gate, base)
        except (CarryRefused, PermanentError) as why:
            log.info("carry-over refused for %s round %s: %s", gate.name, gate.round, why)
            return None
        except (ValueError, TypeError) as why:  # malformed facts: refuse, and say so loudly
            log.warning(
                "carry-over refused for %s round %s on malformed input",
                gate.name, gate.round, exc_info=why,
            )  # fmt: skip
            return None

    # --- configuration ---

    def _enabled(self, scope: Scope, gate: Gate) -> bool:
        if self._carry_of(gate.run_id, gate.name) != "patch_id":
            return False
        limit = self._allowed(scope.team if isinstance(scope, TeamScope) else "")
        return limit is None or "patch_id" in limit

    # --- the round record ---

    def _persist_round(self, scope: Scope, gate: Gate, base: str) -> None:
        key = _round_key(gate)
        found = self._store.get(scope, key)
        if found is not None:
            if found.data["merge_base"] != base:
                raise CarryRefused("the round's merge base changed since it was recorded")
            return
        data = {"merge_base": base, "carried_from": None}
        try:
            self._store.transact(scope, [Put(key, data, Absent())])
        except (ConditionFailedError, TransactionConflictError) as err:
            raise CarryRefused("the round record was written concurrently") from err

    # --- reading the facts ---

    def _rounds(self, scope: Scope, gate: Gate) -> list[tuple[Gate, Item]]:
        """Every round of this gate name in the run, from the store, unfiltered."""
        prefix = f"GATE#{gate.name}#"
        rows = [
            (from_wire(Gate, i.data), i)
            for i in _items(self._store, scope, run_pk(gate.run_id), prefix)
        ]
        return [(g, i) for g, i in rows if g.name == gate.name]

    def _instance(self, scope: Scope, earlier: Gate) -> GateInstance:
        rec = self._store.get(scope, _round_key(earlier))
        if rec is None:
            raise CarryRefused(f"round {earlier.round} has no merge base on record")
        raw = rec.data.get("carried_from")
        carried = None if raw is None else GateId.parse(str(raw))
        votes = () if carried is not None else self._votes(scope, earlier)
        return GateInstance(earlier, str(rec.data["merge_base"]), votes, carried)

    def _votes(self, scope: Scope, earlier: Gate) -> tuple[Vote, ...]:
        """The approvals that stand for a human-decided round: its closing decision and every vote
        bound to the subject it closed on. A voter who was not counted at the close is included, so
        the recheck can only be stricter. Each is given the quorum role they can fill now."""
        pk, digest = run_pk(earlier.run_id), earlier.subject.digest()
        decisions: dict[str, Decision] = {}
        for item in _items(self._store, scope, pk, f"DEC#{earlier.name}#{earlier.round}#"):
            d = from_wire(Decision, item.data)
            if d.gate_id == earlier.id and d.kind is DecisionKind.APPROVE:
                decisions[d.actor] = d
        for item in _items(self._store, scope, pk, f"VOTE#{earlier.name}#{earlier.round}#"):
            d = from_wire(Decision, item.data["decision"])
            if d.gate_id == earlier.id and d.kind is DecisionKind.APPROVE:
                decisions.setdefault(d.actor, d)
        voters = [a for a, d in decisions.items() if d.subject_digest == digest]
        return self._assign_roles(scope, earlier, voters)

    def _assign_roles(self, scope: Scope, earlier: Gate, voters: list[str]) -> tuple[Vote, ...]:
        """One role per voter, found by matching against the round's frozen quorum with the roles
        each holds now. A voter who fills no slot gets one of their other roles (so they are still
        rechecked) or, holding none, is dropped, which can only break the quorum."""
        rules = self._quorum(scope, earlier)
        held = {a: sorted(self._roles_of(scope, earlier, a)) for a in voters}
        if not rules:
            return tuple(Vote(a, r[0]) for a, r in held.items() if r)
        slots = [r.role for r in rules for _ in range(r.count)]
        owner: dict[str, int] = {}  # voter -> slot index

        def place(slot: int, seen: set[str]) -> bool:
            for a, roles in held.items():
                if slots[slot] in roles and a not in seen:
                    seen.add(a)
                    if a not in owner or place(owner[a], seen):
                        owner[a] = slot
                        return True
            return False

        for slot in range(len(slots)):
            place(slot, set())
        out = []
        for a, roles in held.items():
            if a in owner:
                out.append(Vote(a, slots[owner[a]]))
            elif roles:
                out.append(Vote(a, roles[0]))
        return tuple(out)

    def _quorum(self, scope: Scope, gate: Gate) -> list[QuorumRule] | None:
        item = self._store.get(scope, Key(run_pk(gate.run_id), f"QUO#{gate.name}#{gate.round}"))
        if item is None:
            return None
        return [QuorumRule(r["role"], r["count"]) for r in item.data["rules"]]

    def _patch_history(
        self, scope: Scope, run_id: RunId, origin: GateInstance, subject: Subject
    ) -> tuple[PatchHistory, int]:
        """The patch id of every head from the origin decision's head to the current one."""
        log_items = _items(self._store, scope, run_pk(run_id), "HEAD#")
        shas = [i.data["sha"] for i in log_items]
        origin_head = origin.gate.subject.head_sha
        if origin_head not in shas:
            raise CarryRefused("the head log never saw the origin decision's head")
        start = len(shas) - 1 - shas[::-1].index(origin_head)
        span = log_items[start:]
        if span[-1].data["sha"] != subject.head_sha:
            raise CarryRefused("the head log does not end at the subject's head")
        ids = [i.data["patch_id"] for i in span]
        if any(not isinstance(p, str) or not p.strip() for p in ids):
            raise CarryRefused("a head's patch id could not be computed")
        return PatchHistory(origin.gate.id, tuple(ids)), len(log_items)

    def _read(self, scope: Scope, gate: Gate, base: str) -> tuple[_Read, GateInstance]:
        chain = self._gates.audit_version(scope, gate.run_id)  # via the service's audit writer
        rounds = self._rounds(scope, gate)
        history = [self._instance(scope, g) for g, _ in rounds if g.round < gate.round]
        by_id = {i.gate.id: i for i in history}
        if not history:
            raise CarryRefused("no earlier round")
        origin = max(history, key=lambda i: i.gate.round)
        seen = {origin.gate.id}
        while origin.carried_from is not None:
            nxt = by_id.get(origin.carried_from)
            if nxt is None or nxt.gate.id in seen:
                raise CarryRefused("broken carry-over chain")
            seen.add(nxt.gate.id)
            origin = nxt
        patch_history, heads = self._patch_history(scope, gate.run_id, origin, gate.subject)
        head = gate.subject.head_sha
        assert head is not None
        files = self._git.files(base, head)  # measured from the merge base of the subject head
        moved = origin.merge_base != base
        base_range = (
            BaseRange(origin.merge_base, base, self._git.files(origin.merge_base, base), True)
            if moved
            else None
        )
        round_item = self._store.get(scope, _round_key(gate))
        if round_item is None:
            raise CarryRefused("this round has no record")
        read = _Read(
            history,
            patch_history,
            files,
            base_range,
            chain,
            heads,
            round_item,
        )
        return read, origin

    # --- deciding and closing ---

    def _carry(self, scope: Scope, gate: Gate, base: str) -> GateClosed | None:
        read, _ = self._read_facts(scope, gate, base)
        previous = max(read.history, key=lambda i: i.gate.round).gate
        plan = RoundPlan(
            name=gate.name,
            round=gate.round,
            previous_gate_id=previous.id,
            subject=gate.subject,
            diff_ref="",  # not read by the decision
            check=EvidenceCheck(()),
            interdiff=None,
        )
        decision = evaluate_carry_over(
            gate=gate,
            plan=plan,
            carry_over="patch_id",
            history=read.history,
            quorum=cast(Sequence[Quorum] | None, self._quorum(scope, gate)),  # reads role, count
            merge_base=base,
            patch_files=read.patch_files,
            base_range=read.base_range,
            patch_history=read.patch_history,
            recheck=self._recheck,
        )
        if not decision.carried or decision.citation is None:
            log.info(
                "carry-over of %s round %s refused: %s", gate.name, gate.round, decision.reasons
            )
            return None
        conditions: list[Op] = [
            Check(_head_key(gate.run_id, read.heads + 1), Absent()),  # no push since the read
            Put(
                read.round_item.key,
                {"merge_base": base, "carried_from": str(previous.id)},
                VersionIs(read.round_item.version),
            ),
        ]
        closed = self._gates.close_carried(
            scope, gate=gate, citation=decision.citation, chain=read.chain, extra=conditions
        )
        return self._event(closed.gate, closed.decision.id, decision.citation)

    def _read_facts(self, scope: Scope, gate: Gate, base: str) -> tuple[_Read, GateInstance]:
        return self._read(scope, gate, base)

    def _event(self, gate: Gate, decision_id: Any, citation: Citation) -> GateClosed:
        return GateClosed(
            gate.run_id,
            gate.name,
            gate.round,
            DecisionKind.APPROVE,
            CARRY_ACTOR,
            decision_id,
            gate.subject,
            citation,
        )

    def _replayed(self, scope: Scope, gate: Gate, cited: Item) -> GateClosed | None:
        """The close was committed on an earlier call: report the same event."""
        c = cited.data
        if gate.status is not GateStatus.APPROVED or gate.closed_by != CARRY_ACTOR:
            return None
        citation = Citation(
            GateId.parse(c["gate_id"]),
            int(c["round"]),
            GateId.parse(c["origin_gate_id"]),
            int(c["origin_round"]),
            str(c["patch_id"]),
            tuple(c["approvers"]),
        )
        from sto.domain import DecisionId

        return self._event(gate, DecisionId.parse(c["decision_id"]), citation)
