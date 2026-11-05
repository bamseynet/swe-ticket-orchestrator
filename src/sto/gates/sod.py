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
the other kinds arrive as :class:`AdminAction` with the gate and round they touch (``None`` for
all). A person cannot clear their own exclusion.

Not here: writing these records (the attribute, clear and resolve endpoints), the audit entries
for them, and wiring ``evaluate`` into ``GateService.decide`` (D3-06 owns that path).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from sto.config.schema import ApproverOf, Floors, SeparationOfDuties
from sto.domain import Gate, GateType
from sto.identity.mapping import ServiceIdentity, UserIdentity

__all__ = [
    "AdminAction",
    "Approval",
    "Commit",
    "Exclusion",
    "RunFacts",
    "SodVerdict",
    "evaluate",
]

AdminKind = Literal[
    "mapping", "eligible_roles", "attribute", "clear_exclusion", "extend_eligibility"
]


@dataclass(frozen=True)
class Exclusion:
    """A person a trailer or webhook names. ``cleared_by`` is the admin who called it false."""

    actor: str
    source: str
    cleared_by: str | None = None

    @property
    def active(self) -> bool:
        # a person cannot clear their own exclusion
        return self.cleared_by is None or self.cleared_by == self.actor


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
    pushers: tuple[Exclusion, ...] = ()


@dataclass(frozen=True)
class Approval:
    gate_name: str
    gate_type: GateType
    actor: str


@dataclass(frozen=True)
class AdminAction:
    actor: str
    kind: AdminKind
    gate: str | None = None
    round: int | None = None

    def covers(self, gate: Gate) -> bool:
        return (self.gate is None or self.gate == gate.name) and (
            self.round is None or self.round == gate.round
        )


@dataclass(frozen=True)
class RunFacts:
    """What the run's own records say. Built fresh at each decision, never cached on a gate."""

    requester: str | None
    commits: tuple[Commit, ...] = ()
    assignees: frozenset[str] = frozenset()  # frozen union of every assignee seen in the run
    approvals: tuple[Approval, ...] = ()
    unresolved: frozenset[str] = frozenset()
    resolutions: Mapping[str, frozenset[str]] = field(default_factory=dict)
    admin_actions: tuple[AdminAction, ...] = ()


@dataclass(frozen=True)
class SodVerdict:
    """``blocked`` means the gate refuses every approval, whoever asks. ``reasons`` lists every
    cause, so a person can be told all of them at once."""

    allowed: bool
    reasons: tuple[str, ...]
    blocked: bool


def _excluded_terms(
    actor: str, gate: Gate, sod: SeparationOfDuties | None, floors: Floors, facts: RunFacts
) -> tuple[list[str], list[str], set[str]]:
    """Return (exclusion reasons, blocking reasons, the terms that apply)."""
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
        humans = [*commit.coauthors, *commit.pushers]
        if any(e.actor == actor and e.active for e in humans):
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
        if actor in facts.resolutions.get(term, frozenset()):
            excluded.append(term)
        unresolved = term in facts.unresolved or (term == "requester" and facts.requester is None)
        if unresolved and term not in facts.resolutions:
            blocking.append(f"unresolved_term:{term}")
    for name in approver_of:
        if any(a.gate_name == name and a.actor == actor for a in facts.approvals):
            excluded.append(f"approver_of:{name}")
    return excluded, blocking, terms


def _admin_self_service(actor: str, gate: Gate, facts: RunFacts) -> bool:
    if any(a.actor == actor and a.covers(gate) for a in facts.admin_actions):
        return True
    for commit in facts.commits:
        if commit.attributed_by == actor:
            return True
        for e in (*commit.coauthors, *commit.pushers):
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

    excluded, blocking, _terms = _excluded_terms(actor, gate, sod, floors, facts)
    reasons.extend(excluded)
    if not floors.single_human_allowed and gate.type in (GateType.REVIEW, GateType.QA):
        other = GateType.QA if gate.type is GateType.REVIEW else GateType.REVIEW
        if any(a.actor == actor and a.gate_type is other for a in facts.approvals):
            reasons.append("review_and_qa")
    if _admin_self_service(actor, gate, facts):
        reasons.append("admin_self_service")

    blocked = bool(blocking)
    if not negative:  # a veto is accepted while approvals are blocked
        reasons.extend(blocking)
    unique = tuple(dict.fromkeys(reasons))
    return SodVerdict(not unique, unique, blocked)
