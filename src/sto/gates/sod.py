"""Separation of duties at decision time (PLAN 9.4, D3-05; invariant G7, threat T8).

:func:`evaluate` answers one question: may this person decide this gate round, as far as
separation of duties goes? It is a pure function of the candidate, the gate, the org floors and
the run's records (:class:`RunFacts`), so a decision path reads the records fresh and calls it
inside the decision. It never reads a token, a git author field or a webhook for trust.

Eligibility first, because SoD is only meaningful for a person who could decide at all:

* a :class:`~sto.identity.mapping.ServiceIdentity` is never eligible (``service_identity``);
* the account must be linked (``unlinked``);
* the person holds a gate role in ``eligible_roles`` now (``role``; ``team_admin`` alone is not
  one) **and** was eligible when the gate opened (``not_eligible_at_open``, fail closed when the
  gate has no snapshot): "then and now".

Exclusions. The floors apply whatever the gate says, so a gate that narrows or omits
``separation_of_duties`` cannot drop them (T8; the loader's ``FLOORS`` only covers an explicit
``null``):

* ``committer``: anyone attributed to a human commit, named by a ``Co-authored-by`` trailer or
  seen as a pusher. The floor.
* ``requester``: for the gate types in ``floors.requester_excluded_from``, or any gate that
  lists it.
* ``review_and_qa``: nobody approves both a review and a QA gate, unless
  ``floors.single_human_allowed``. With the requester floor this gives two distinct humans.
* the gate's own terms: ``author`` (the frozen union of assignees) and ``approver_of: <gate>``.

Commit authorship rests on the run's own records. A commit in the push receipts was made by the
platform and has no human author, whatever its author field says. Any other commit is human and
unattributed, and it **blocks every approval** until an admin attributes it (``unattributed_commit:
<sha>``). So a forged bot author on a pushed commit blocks, and platform commits never do.

Fail closed. A requester that cannot be resolved (``requester`` is ``None``) or a term in
``RunFacts.unresolved`` blocks every approval (``unresolved_term:<term>``) until an admin resolves
it, which adds the actors they name to that term's exclusions. A **negative** decision is still
accepted while blocked, but not while excluded.

Admin self-service is closed off. An actor who changed a mapping, published ``eligible_roles``,
attributed a commit, cleared an exclusion or extended eligibility is ineligible for the rounds that
action affects (``admin_self_service``). Attributing and clearing are read from the commit records;
the other kinds arrive as :class:`AdminAction`. Because any gate that opens later snapshots a
grant, every kind but an extension is run-wide (see :class:`AdminAction`); an extension covers
exactly its round. An admin who resolves a term (:class:`Resolution`) is ineligible the same way,
and a resolution naming nobody resolves nothing. A person cannot clear their own exclusion.

Records carry a gate's **name** (``Gate.name``), never its id.

Not here: writing these records (the attribute, clear and resolve endpoints), the audit entries
for them, and wiring ``evaluate`` into ``GateService.decide`` (D3-06 owns that path).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal, get_args

from sto.config.schema import ApproverOf, Floors, SeparationOfDuties
from sto.domain import Gate, GateType
from sto.identity.mapping import ServiceIdentity, UserIdentity

__all__ = [
    "AdminAction",
    "Approval",
    "Commit",
    "Exclusion",
    "Pusher",
    "Resolution",
    "RunFacts",
    "SodVerdict",
    "evaluate",
]

AdminKind = Literal[
    "mapping",
    "eligible_roles",
    "attribute",
    "clear_exclusion",
    "extend_eligibility",
    "resolve_term",
]


_TERMS = ("requester", "author")


def _actor(label: str, value: object) -> str:
    """An actor is ``issuer|subject``, as :func:`evaluate` builds it. Any other spelling (a login,
    an email) would silently exclude nobody, so a record carrying one is refused."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an 'issuer|subject' string")
    issuer, bar, subject = value.partition("|")
    if not (issuer and bar and subject):
        raise ValueError(f"{label} {value!r} must be in 'issuer|subject' form")
    for part in (issuer, subject):
        # a stray space or newline would make the key differ from the one evaluate() builds, so
        # the record would silently exclude nobody
        if part != part.strip() or any(unicodedata.category(c).startswith("C") for c in part):
            raise ValueError(
                f"{label} {value!r}: issuer|subject must have no surrounding whitespace "
                "or control characters"
            )
    return value


def _opt_actor(label: str, value: object) -> str | None:
    return None if value is None else _actor(label, value)


@dataclass(frozen=True)
class Exclusion:
    """A person a ``Co-authored-by`` trailer names. ``cleared_by`` is the admin who called the
    trailer false; a person cannot clear their own, so that does not count."""

    actor: str
    source: str
    cleared_by: str | None = None

    def __post_init__(self) -> None:
        _actor("exclusion actor", self.actor)
        _opt_actor("exclusion cleared_by", self.cleared_by)

    @property
    def active(self) -> bool:
        return self.cleared_by is None or self.cleared_by == self.actor


@dataclass(frozen=True)
class Pusher:
    """Pusher data from a webhook. It adds an exclusion and **cannot be cleared**: PLAN 9.4 lets an
    admin clear only a false trailer."""

    actor: str

    def __post_init__(self) -> None:
        _actor("pusher actor", self.actor)


@dataclass(frozen=True)
class Commit:
    """One commit of the PR. ``in_receipts`` means it is in the run's push receipts.

    ``git_author`` is free text and is never read for a decision; it exists so a record can carry
    what git said. ``attributed_to`` counts only with ``attributed_by``, the admin who did it."""

    sha: str
    in_receipts: bool
    attributed_to: str | None = None
    attributed_by: str | None = None
    git_author: str = ""
    coauthors: tuple[Exclusion, ...] = ()
    pushers: tuple[Pusher, ...] = ()

    def __post_init__(self) -> None:
        _name("commit sha", self.sha)
        if not isinstance(self.in_receipts, bool):
            raise ValueError("commit in_receipts must be a bool")
        _opt_actor("commit attributed_to", self.attributed_to)
        _opt_actor("commit attributed_by", self.attributed_by)


@dataclass(frozen=True)
class Approval:
    gate_name: str
    gate_type: GateType
    actor: str

    def __post_init__(self) -> None:
        _name("approval gate_name", self.gate_name)
        _actor("approval actor", self.actor)
        # a plain string from a store is coerced; an unknown one raises ValueError
        object.__setattr__(self, "gate_type", GateType(self.gate_type))


def _name(label: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _round(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"round must be a positive integer or None, not {value!r}")
    return value


@dataclass(frozen=True)
class AdminAction:
    """Something an admin did. ``round`` is the round of ``gate`` the action **happened in**, not
    the round it takes effect in.

    Coverage. ``extend_eligibility`` covers exactly its ``gate`` and ``round`` (both required).
    Every other kind (``mapping``, ``eligible_roles``, ``attribute``, ``clear_exclusion``,
    ``resolve_term``) is run-wide, because any gate that opens later snapshots the grant too: it
    covers every gate and round of the run, whatever ``gate`` and ``round`` say, so a wrongly
    recorded round cannot un-bar the actor. ``gate`` is a gate name, not an id. A ``round`` without
    a ``gate`` is refused."""

    actor: str
    kind: AdminKind
    gate: str | None = None
    round: int | None = None

    def __post_init__(self) -> None:
        _actor("admin action actor", self.actor)
        if self.kind not in get_args(AdminKind):
            raise ValueError(f"unknown admin action kind {self.kind!r}")
        if self.gate is not None:
            _name("admin action gate", self.gate)
        _round(self.round)
        if self.round is not None and self.gate is None:
            raise ValueError("an admin action with a round must name its gate")
        if self.kind == "extend_eligibility" and (self.gate is None or self.round is None):
            raise ValueError("an extension covers one round, so it needs a gate and a round")

    def covers(self, gate: Gate) -> bool:
        if self.kind == "extend_eligibility":
            return self.gate == gate.name and self.round == gate.round
        # run-wide: any gate that opens later snapshots the grant, so ``gate`` and ``round`` are
        # kept for the record but never narrow the coverage
        return True


@dataclass(frozen=True)
class Resolution:
    """An admin's resolution of a term that could not be resolved. It names who becomes excluded
    (``actors``); naming nobody resolves nothing. It lifts the block on every gate of the run (the
    term is run-level), so the resolver is ineligible everywhere, as a run-wide ``resolve_term``
    action; ``gate`` and ``round`` are where it happened, as for :class:`AdminAction`."""

    term: Literal["requester", "author"]
    actors: frozenset[str]
    resolved_by: str
    gate: str | None = None
    round: int | None = None

    def __post_init__(self) -> None:
        if self.term not in _TERMS:
            raise ValueError(f"cannot resolve term {self.term!r}: only requester or author")
        if isinstance(self.actors, str) or not isinstance(self.actors, Collection):
            raise ValueError("resolution actors must be a collection of actors, not a string")
        object.__setattr__(self, "actors", frozenset(self.actors))
        _actor("resolution resolved_by", self.resolved_by)
        for a in self.actors:
            _actor("resolution actor", a)
        self.as_action()  # validates gate and round

    @property
    def resolves(self) -> bool:
        return bool(self.actors)

    def as_action(self) -> AdminAction:
        return AdminAction(self.resolved_by, "resolve_term", self.gate, self.round)


@dataclass(frozen=True)
class RunFacts:
    """What the run's own records say. Built fresh at each decision, never cached on a gate."""

    requester: str | None
    commits: tuple[Commit, ...] = ()
    assignees: frozenset[str] = frozenset()  # frozen union of every assignee seen in the run
    approvals: tuple[Approval, ...] = ()
    unresolved: frozenset[str] = frozenset()
    resolutions: tuple[Resolution, ...] = ()
    admin_actions: tuple[AdminAction, ...] = ()

    def __post_init__(self) -> None:
        _opt_actor("requester", self.requester)
        for a in self.assignees:
            _actor("assignee", a)
        if isinstance(self.unresolved, str) or not isinstance(self.unresolved, Collection):
            raise ValueError("unresolved must be a collection of term names, not a string")
        bad = [t for t in self.unresolved if t not in _TERMS]
        if bad:
            raise ValueError(f"unresolved names unknown terms {bad!r}: only requester or author")
        object.__setattr__(self, "unresolved", frozenset(self.unresolved))


@dataclass(frozen=True)
class SodVerdict:
    """``blocked`` means the gate refuses every approval, whoever asks. ``reasons`` lists every
    cause, so a person can be told all of them at once."""

    allowed: bool
    reasons: tuple[str, ...]
    blocked: bool


def _excluded_terms(
    actor: str,
    gate: Gate,
    sod: SeparationOfDuties | None,
    floors: Floors,
    facts: RunFacts,
    *,
    negative: bool,
) -> tuple[list[str], list[str]]:
    """Return (exclusion reasons, blocking reasons).

    ``approver_of`` bars *approving*, so it is skipped for a negative decision."""
    terms: set[str] = {"committer"}
    approver_of: list[str] = []
    for term in sod.not_ if sod else ():
        if isinstance(term, ApproverOf):
            approver_of.append(term.approver_of)
        else:
            terms.add(term)
    if gate.type.value in floors.requester_excluded_from:
        terms.add("requester")

    excluded: list[str] = []
    blocking: list[str] = []
    for commit in facts.commits:
        if any(e.actor == actor and e.active for e in commit.coauthors) or any(
            p.actor == actor for p in commit.pushers
        ):
            excluded.append("committer")
        if commit.in_receipts:
            continue
        if commit.attributed_to is None or commit.attributed_by is None:
            blocking.append(f"unattributed_commit:{commit.sha}")
        elif commit.attributed_to == actor:
            excluded.append("committer")
    if "requester" in terms and facts.requester == actor:
        excluded.append("requester")
    if "author" in terms and actor in facts.assignees:
        excluded.append("author")
    for term in ("requester", "author"):
        if term not in terms:
            continue
        resolved = [r for r in facts.resolutions if r.term == term and r.resolves]
        if any(actor in r.actors for r in resolved):
            excluded.append(term)
        unresolved = term in facts.unresolved or (term == "requester" and facts.requester is None)
        if unresolved and not resolved:
            blocking.append(f"unresolved_term:{term}")
    for name in () if negative else approver_of:
        if any(a.gate_name == name and a.actor == actor for a in facts.approvals):
            excluded.append(f"approver_of:{name}")
    return excluded, blocking


_PAIR = (GateType.REVIEW, GateType.QA)


def _admin_self_service(actor: str, gate: Gate, facts: RunFacts) -> bool:
    actions = [*facts.admin_actions, *(r.as_action() for r in facts.resolutions)]
    if any(a.actor == actor and a.covers(gate) for a in actions):
        return True
    for commit in facts.commits:
        if commit.attributed_by == actor:
            return True
        for e in commit.coauthors:
            # clearing your own exclusion is not a clearance (see Exclusion.active)
            if e.cleared_by == actor and e.cleared_by != e.actor:
                return True
    return False


def evaluate(
    *,
    who: UserIdentity | ServiceIdentity,
    linked: bool,
    team: str,
    gate: Gate,
    eligible_roles: frozenset[str],
    opened_with: frozenset[str] | None,
    sod: SeparationOfDuties | None,
    floors: Floors,
    facts: RunFacts,
    negative: bool = False,
) -> SodVerdict:
    """May ``who`` decide ``gate``? ``opened_with`` is the eligibility snapshot taken at open."""
    if isinstance(who, ServiceIdentity):
        return SodVerdict(False, ("service_identity",), False)
    actor = f"{who.issuer}|{who.subject}"
    reasons: list[str] = []
    if not linked:
        reasons.append("unlinked")
    if not who.roles_in(team) & eligible_roles:
        reasons.append("role")
    if opened_with is None or actor not in opened_with:
        reasons.append("not_eligible_at_open")

    excluded, blocking = _excluded_terms(actor, gate, sod, floors, facts, negative=negative)
    reasons.extend(excluded)
    # the floor bars *approving* both, so a prior approver may still reject or ask for changes
    if not negative and not floors.single_human_allowed and gate.type in _PAIR:
        other = GateType.QA if gate.type is GateType.REVIEW else GateType.REVIEW
        if any(a.actor == actor and a.gate_type == other for a in facts.approvals):
            reasons.append("review_and_qa")
    if _admin_self_service(actor, gate, facts):
        reasons.append("admin_self_service")

    blocked = bool(blocking)
    if not negative:  # a veto is accepted while approvals are blocked
        reasons.extend(blocking)
    unique = tuple(dict.fromkeys(reasons))
    return SodVerdict(not unique, unique, blocked)
