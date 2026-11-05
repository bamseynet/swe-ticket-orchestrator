"""Carry-over and invalidation (D2-09, PLAN 4.3 rule 3 and 4.6; invariant G13).

When a gate is re-entered with ``carry_over: patch_id``, :func:`evaluate_carry_over` says whether
it may close ``approved`` with no human, citing the earlier decision. It is pure: the caller reads
the run's records and passes them in, and acts on the answer (opening the gate, closing it, the
audit entry). Any doubt is a refusal, and a refusal only means the gate opens normally.

The six conditions of PLAN 4.6, each with the reason it refuses with. Every condition is
evaluated and every failing one is reported, except that a history that cannot be read
(``no_previous_instance``, ``inconsistent_history``, ``plan_mismatch``, ``not_most_recent``) stops
at once, since the rest would rest on it.

1. The **most recent closed instance** closed ``APPROVED`` with full quorum
   (``latest_not_approved``, ``quorum_not_met``, ``waiver_not_carried``) and nothing between the
   decision and now closed any other way (``non_approved_close_since``). Only that instance can be
   cited: the plan from :func:`~sto.gates.subject.plan_round` must link to it
   (``not_most_recent``). Any other close, including ``RETEST`` (carry-over never crosses a
   retest) and ``EXPIRED``, ends the line; a person decides again. This does not rely on an
   earlier round having been advanced to ``INVALIDATED``: ``gates/timers.py`` closes ``EXPIRED``
   and leaves earlier rounds ``APPROVED``, so the walk reads the instances themselves.
   Waived approvals never carry (a waiver is recorded per criterion, with a reason, and is not
   extended silently).
2. Its ``patch_id`` equals the current one, and so does that of every instance since the decision
   (``patch_changed``), and so does every head the *run* has had since (:class:`PatchHistory`,
   required, ``patch_changed_since``). The list is every head, not every subject: a push that
   opens no gate still counts, so P1, P2, P1 asks again whether or not P2 opened a round. It is
   anchored to the origin decision's gate id and must end at the current patch, else
   ``patch_history_mismatch``: passing only the current patch cannot satisfy it.
3. Every approver it cites passes the **approver port** (``ApproverRecheck``), which D3-05's
   ``sod.evaluate`` fills, asked per ``(actor, role)`` with the role they voted as: they still hold
   that role, were eligible when the gate opened, and separation of duties holds against the
   current commits (``approver_ineligible:<actor>``). The answer must be exactly ``True``, and
   only confirmed pairs count toward the quorum again.
   The port is asked only when every other condition holds, so a refusal costs no lookups. A port
   that raises propagates: it is a fault, never a verdict.
4. The ticket revision is unchanged (``ticket_revision_changed``).
5. The attention digest is unchanged (``attention_changed``).
6. The base range changed no file in the patch (``base_range_touches_patch:<path>``). The range
   runs from the merge base the *human* decision was made on (the origin of a chain of
   carry-overs) to the current one, and is refused when it is for other commits or missing while
   the base moved (``base_range_unknown``), and so is an empty range on a moved base unless its
   producer marks it ``complete`` (an empty list is also what a failed read looks like). A patch
   with no known files refuses
   (``patch_files_unknown``). Paths are compared after NFC and case folding, and a path that
   contains or is contained by another counts as touched, so a file that became a directory, or
   the reverse, and a case-insensitive checkout do not slip through.
   A path that could be read two ways is a ``ValueError``, not normalised: a ``..`` segment, NUL,
   a newline, a backslash, or leading or trailing whitespace. Only ``.`` and empty segments are
   dropped when comparing.

The history must be exactly rounds 1 to ``gate.round - 1`` of this run, gate name and type, or it
is ``inconsistent_history``: a missing round could hide a close.

A carried instance has no votes of its own. It names the instance it carried from
(``GateInstance.carried_from``), which must be the round immediately before it, and the walk
follows that to the original human decision, whose votes are the ones cited. A broken chain
(missing, cyclic, skipping a round) refuses (``broken_chain``).

A retest (or any close) on a *different* gate does not block carry-over here: PLAN's "never
crosses a QA retest" is read as the retest of this gate's own line, which is what the walk sees.

Invalidation. :func:`invalidated_by_close` lists the earlier approved rounds a non-approved close
voids (PLAN 4.3 rule 3), and :func:`invalidated_by_patch` those approved on another patch (a patch
change invalidates permanently). Carry-over does not depend on either being called. They agree
with the gate service's ``_earlier_approvals`` and with the reducer, which drops a gate's
approvals on any non-approved close.

Not here: opening or closing the gate (``GateService``), the audit entry, reading commits and
diffs (``git diff --name-only`` for the patch and for the base range), or the eligibility lookup
itself (D3-05).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Protocol

from sto.config.schema import CarryOver, Quorum
from sto.domain import DecisionKind, Gate, GateId, GateStatus
from sto.gates.subject import RoundPlan

__all__ = [
    "ApproverRecheck",
    "BaseRange",
    "CarryOverDecision",
    "Citation",
    "GateInstance",
    "PatchHistory",
    "Vote",
    "evaluate_carry_over",
    "invalidated_by_close",
    "invalidated_by_patch",
]


def _nonblank(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string, not {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _actor(label: str, value: object) -> str:
    """``issuer|subject``, as ``sod`` keys people; any other spelling would match nobody."""
    text = _nonblank(label, value)
    issuer, bar, subject = text.partition("|")
    if not (issuer and bar and subject):
        raise ValueError(f"{label} {text!r} must be in 'issuer|subject' form")
    for part in (issuer, subject):
        if part != part.strip() or any(unicodedata.category(c).startswith("C") for c in part):
            raise ValueError(f"{label} {text!r} has surrounding whitespace or control characters")
    return text


@dataclass(frozen=True)
class Vote:
    """One approving decision on a gate instance: who, as which quorum role, and how."""

    actor: str
    role: str
    kind: DecisionKind = DecisionKind.APPROVE

    def __post_init__(self) -> None:
        _actor("vote actor", self.actor)
        _nonblank("vote role", self.role)
        kind = DecisionKind(self.kind)
        if kind not in (DecisionKind.APPROVE, DecisionKind.WAIVE):
            raise ValueError(f"a vote is an approve or waive decision, not {kind.value}")
        object.__setattr__(self, "kind", kind)


@dataclass(frozen=True)
class GateInstance:
    """A stored round of a gate as this module reads it.

    ``merge_base`` is the commit the round's diff was taken against. ``votes`` are the approving
    decisions of a human-decided round. A round closed by carry-over has none and names the round
    it carried from in ``carried_from``.
    """

    gate: Gate
    merge_base: str
    votes: tuple[Vote, ...] = ()
    carried_from: GateId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.gate, Gate):
            raise TypeError("instance gate must be a Gate")
        _nonblank("instance merge_base", self.merge_base)
        if isinstance(self.votes, str) or not isinstance(self.votes, Sequence):
            raise TypeError("instance votes must be a sequence of Vote")
        object.__setattr__(self, "votes", tuple(self.votes))
        if not all(isinstance(v, Vote) for v in self.votes):
            raise TypeError("instance votes must be a sequence of Vote")
        if self.carried_from is not None and not isinstance(self.carried_from, GateId):
            raise TypeError("instance carried_from must be a GateId")


def _path(label: str, value: object) -> str:
    """A repository path as git prints it. Refused outright, not normalised, when it could be read
    two ways: a ``..`` segment, NUL, a newline, a backslash, or surrounding whitespace."""
    text = _nonblank(label, value)
    if text != text.strip() or any(c in text for c in ("\x00", "\n", "\\")):
        raise ValueError(f"{label} {text!r} has whitespace, NUL, a newline or a backslash")
    if ".." in text.split("/"):
        raise ValueError(f"{label} {text!r} has a '..' segment")
    return text


def _paths(label: str, paths: Collection[str]) -> frozenset[str]:
    if isinstance(paths, str) or not isinstance(paths, Collection):
        raise TypeError(f"{label}s must be a collection of strings, not a string")
    return frozenset(_path(label, p) for p in paths)


@dataclass(frozen=True)
class PatchHistory:
    """Every head the run has had from the origin decision up to now, as patch ids in order.

    ``anchor`` is the origin decision's **gate id**: the first instance of the line, the one a
    person decided. ``patch_ids`` runs from that decision's head to the current head, inclusive. It
    lists *heads*, not subjects: a push or PR synchronize that opened no gate is still a head.
    Heads whose patch id cannot be computed are the producer's to refuse, not to skip.
    """

    anchor: GateId
    patch_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.anchor, GateId):
            raise TypeError("patch history anchor must be a GateId")
        if isinstance(self.patch_ids, str) or not isinstance(self.patch_ids, Sequence):
            raise TypeError("patch history patch_ids must be a sequence of patch ids")
        ids = tuple(_nonblank("patch id", p) for p in self.patch_ids)
        if not ids:
            raise ValueError("patch history needs at least the current patch id")
        object.__setattr__(self, "patch_ids", ids)


@dataclass(frozen=True)
class BaseRange:
    """The files the base changed between two merge bases (``git diff --name-only -z`` with
    renames turned off, so both sides of a rename appear).

    ``complete`` is the producer's statement that the list is whole: the output ended in its
    final NUL and nothing was dropped. An empty list on a moved base is believed only when it is
    set, because an empty list is also what a truncated or failed read looks like."""

    from_base: str
    to_base: str
    files: frozenset[str]
    complete: bool = False  # the caller vouches the list is whole (see the module docstring)

    def __post_init__(self) -> None:
        if type(self.complete) is not bool:
            raise TypeError("base range complete must be a bool")
        _nonblank("base range from_base", self.from_base)
        _nonblank("base range to_base", self.to_base)
        object.__setattr__(self, "files", _paths("base range path", self.files))


class ApproverRecheck(Protocol):
    """The approver port (D3-05 fills it with ``sod.evaluate`` and the current mapping): does
    ``actor`` (``issuer|subject``) still hold ``role``, the quorum role they voted as, and may they
    still decide ``gate``, the re-entered round, as far as separation of duties goes? ``True`` or
    no. Only a confirmed ``(actor, role)`` pair counts toward the quorum."""

    def __call__(self, actor: str, role: str, gate: Gate, /) -> bool: ...


@dataclass(frozen=True)
class Citation:
    """What the audit entry of a carried close cites. ``gate_id``/``round`` are the most recent
    instance; ``origin_*`` the human decision at the end of any chain of carry-overs."""

    gate_id: GateId
    round: int
    origin_gate_id: GateId
    origin_round: int
    patch_id: str
    approvers: tuple[str, ...]


@dataclass(frozen=True)
class CarryOverDecision:
    """``carried`` with a citation and no reasons, or not carried with the reasons."""

    carried: bool
    reasons: tuple[str, ...]
    citation: Citation | None

    def __post_init__(self) -> None:
        if self.carried != (self.citation is not None and not self.reasons):
            raise ValueError("a carried decision has a citation and no reasons; a refusal neither")
        if not self.carried and not self.reasons:
            raise ValueError("a refusal needs a reason")


def _refuse(*reasons: str) -> CarryOverDecision:
    return CarryOverDecision(False, tuple(dict.fromkeys(reasons)), None)


def _key(path: str) -> tuple[str, ...]:
    folded = unicodedata.normalize("NFC", path).casefold()
    return tuple(p for p in folded.split("/") if p not in ("", "."))


def _related(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    n = min(len(a), len(b))
    return a[:n] == b[:n]


def _actors(votes: Sequence[Vote]) -> frozenset[str]:
    return frozenset(v.actor for v in votes)


def _quorum_met(votes: Sequence[Vote], quorum: Sequence[Quorum] | None) -> bool:
    """Distinct people per role. A person who voted more than once counts once, in the role of
    their first vote."""
    first: dict[str, str] = {}
    for v in votes:
        first.setdefault(v.actor, v.role)
    if quorum is None:
        return bool(first)
    needed: dict[str, int] = {}
    for q in quorum:
        needed[q.role] = needed.get(q.role, 0) + q.count
    have: dict[str, int] = {}
    for role in first.values():
        have[role] = have.get(role, 0) + 1
    return bool(needed) and all(have.get(role, 0) >= n for role, n in needed.items())


def evaluate_carry_over(
    *,
    gate: Gate,
    plan: RoundPlan,
    carry_over: CarryOver,
    history: Sequence[GateInstance],
    quorum: Sequence[Quorum] | None,
    merge_base: str,
    patch_files: Collection[str],
    base_range: BaseRange | None,
    patch_history: PatchHistory,
    recheck: ApproverRecheck,
) -> CarryOverDecision:
    """May the re-entered ``gate`` (open, round ``plan.round``) close approved by carry-over?

    ``history`` is every earlier instance of this gate in the run. ``quorum`` is the gate's
    current quorum (``None`` means one approval), ``merge_base`` the commit the current diff is
    against and ``patch_files`` the paths the patch touches. ``patch_history`` is every head the
    **run** has had since the human decision, not only those a round of this gate saw (required).
    See the module docstring.
    """
    if not isinstance(gate, Gate) or not isinstance(plan, RoundPlan):
        raise TypeError("gate must be a Gate and plan a RoundPlan")
    _nonblank("merge_base", merge_base)
    files = _paths("patch file path", patch_files)
    if not isinstance(patch_history, PatchHistory):
        raise TypeError("patch_history must be a PatchHistory")
    if base_range is not None and not isinstance(base_range, BaseRange):
        raise TypeError("base_range must be a BaseRange or None")
    if carry_over != "patch_id":
        return _refuse("carry_over_none")  # none, and anything unknown, asks a person

    if not gate.is_open or (plan.name, plan.round, plan.subject) != (
        gate.name,
        gate.round,
        gate.subject,
    ):
        return _refuse("plan_mismatch")
    by_id: dict[GateId, GateInstance] = {}
    rounds: set[int] = set()
    for inst in history:
        g = inst.gate
        if (g.name, g.run_id, g.type) != (gate.name, gate.run_id, gate.type):
            return _refuse("inconsistent_history")
        if g.round in rounds or g.round >= gate.round or g.id in by_id:
            return _refuse("inconsistent_history")
        rounds.add(g.round)
        by_id[g.id] = inst
    if not by_id:
        return _refuse("no_previous_instance" if gate.round == 1 else "inconsistent_history")
    if rounds != set(range(1, gate.round)):
        return _refuse("inconsistent_history")  # a missing round hides what closed in it
    latest = max(by_id.values(), key=lambda i: i.gate.round)
    if plan.previous_gate_id != latest.gate.id or gate.round != latest.gate.round + 1:
        return _refuse("not_most_recent")

    reasons: list[str] = []

    # --- the chain back to the human decision ---
    origin = latest
    seen = {latest.gate.id}
    while origin.carried_from is not None:
        nxt = by_id.get(origin.carried_from)
        if nxt is None or nxt.gate.id in seen or nxt.gate.round != origin.gate.round - 1:
            return _refuse("broken_chain")
        seen.add(nxt.gate.id)
        origin = nxt

    # --- 1: approved, nothing else closed since ---
    if latest.gate.status is not GateStatus.APPROVED:
        reasons.append("latest_not_approved")
    span = [i for i in by_id.values() if i.gate.round >= origin.gate.round]
    for inst in sorted(span, key=lambda i: i.gate.round):
        if inst is not latest and inst.gate.status is not GateStatus.APPROVED:
            reasons.append(f"non_approved_close_since:{inst.gate.round}:{inst.gate.status.value}")
    if any(v.kind is DecisionKind.WAIVE for v in origin.votes):
        reasons.append("waiver_not_carried")
    if not _quorum_met(origin.votes, quorum):
        reasons.append("quorum_not_met")

    # --- 2, 4, 5: the subject is what the human saw ---
    subject = gate.subject
    if any(i.gate.subject.patch_id != subject.patch_id for i in span):
        reasons.append("patch_changed")
    if patch_history.anchor != origin.gate.id or patch_history.patch_ids[-1] != subject.patch_id:
        reasons.append("patch_history_mismatch")
    elif any(p != origin.gate.subject.patch_id for p in patch_history.patch_ids):
        reasons.append("patch_changed_since")
    if any(i.gate.subject.ticket_revision != subject.ticket_revision for i in span):
        reasons.append("ticket_revision_changed")
    if any(i.gate.subject.attention_digest != subject.attention_digest for i in span):
        reasons.append("attention_changed")

    # --- 6: the base range left the patch's files alone ---
    if not files:
        reasons.append("patch_files_unknown")
    moved = origin.merge_base != merge_base
    if base_range is None:
        if moved:
            reasons.append("base_range_unknown")
    elif (base_range.from_base, base_range.to_base) != (origin.merge_base, merge_base):
        reasons.append("base_range_unknown")
    else:
        if moved and not base_range.files and not base_range.complete:
            reasons.append("base_range_unknown")
        patch_keys = [_key(f) for f in files]
        reasons.extend(
            f"base_range_touches_patch:{path}"
            for path in sorted(base_range.files)
            if any(_related(_key(path), k) for k in patch_keys)
        )

    # --- 3: the approvers, last: it is a lookup, so ask only when the rest allows ---
    # One (actor, role) pair per person, the role of their first vote: the port confirms that role,
    # and only confirmed pairs count toward the quorum again.
    pairs: dict[str, str] = {}
    for v in origin.votes:
        pairs.setdefault(v.actor, v.role)
    approvers = tuple(pairs)
    if not reasons:
        confirmed = [
            Vote(who, role) for who, role in pairs.items() if recheck(who, role, gate) is True
        ]
        reasons.extend(
            f"approver_ineligible:{who}" for who in approvers if who not in _actors(confirmed)
        )
        if not _quorum_met(confirmed, quorum):
            reasons.append("quorum_not_met")
    if reasons:
        return _refuse(*reasons)
    return CarryOverDecision(
        True,
        (),
        Citation(
            gate_id=latest.gate.id,
            round=latest.gate.round,
            origin_gate_id=origin.gate.id,
            origin_round=origin.gate.round,
            patch_id=subject.patch_id,
            approvers=approvers,
        ),
    )


def invalidated_by_close(history: Sequence[GateInstance], closing: Gate) -> tuple[GateId, ...]:
    """The earlier ``APPROVED`` rounds of ``closing``'s gate that its close voids, by round.

    Any close that is not an approval voids them (PLAN 4.3 rule 3), ``EXPIRED``, ``SUPERSEDED``
    and ``CANCELLED`` included. An approval, and a gate still open, void nothing.
    """
    if closing.status in (GateStatus.OPEN, GateStatus.APPROVED, GateStatus.INVALIDATED):
        return ()
    earlier = [
        i.gate
        for i in history
        if (i.gate.name, i.gate.run_id) == (closing.name, closing.run_id)
        and i.gate.round < closing.round
        and i.gate.status is GateStatus.APPROVED
    ]
    return tuple(g.id for g in sorted(earlier, key=lambda g: g.round))


def invalidated_by_patch(
    history: Sequence[GateInstance], patch_id: str, *, gate: Gate
) -> tuple[GateId, ...]:
    """The ``APPROVED`` rounds of ``gate``'s name and run that were approved on a patch other than
    ``patch_id``: a patch change voids an approval for good.

    Carry-over does not depend on anyone calling this. A push that no round of the gate saw leaves
    the stored row ``APPROVED``, so :func:`evaluate_carry_over` takes the run's
    :class:`PatchHistory` and refuses on any difference (``patch_changed_since``). Calling this
    just keeps the stored status honest.
    """
    _nonblank("patch_id", patch_id)
    stale = [
        i.gate
        for i in history
        if (i.gate.name, i.gate.run_id) == (gate.name, gate.run_id)
        and i.gate.status is GateStatus.APPROVED
        and i.gate.subject.patch_id != patch_id
    ]
    return tuple(g.id for g in sorted(stale, key=lambda g: g.round))
