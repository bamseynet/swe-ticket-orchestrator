"""Intake (D2-17, PLAN 4, 7.1, 7.3 and T11): what starts a run, and what holds one.

Everything here is a pure function of its inputs, or goes through the store port, so the memory,
SQLite and DynamoDB stores agree. Clocks are passed in (``now`` must carry a time zone); nothing
here reads one, and the reducer is not touched.

* **Closed selectors.** ``Intake`` is source, project, label and optional issue types. Two
  selectors *overlap* when one ticket could match both; ``check_publish`` refuses that (V12).
  ``extra_filter`` is opaque and can only narrow, so it never separates two selectors, and a
  ticket carries the adapter's verdict on it (``extra_filter_matched``).
* **Decide.** ``decide`` returns one workflow to start, or a reason to start nothing: no match, a
  ticket matching two workflows, a ticket outside the active sprint, a public repo without the org
  opt-in, or an intake actor that is unknown or not a member of the team. Applying the trigger
  label is a command (T11), so the actor is checked through ``MemberLookup`` and a skip fails
  closed. A skip is returned to the caller with its reason; nothing is written for it, because a
  record per hostile trigger would let an outsider fill the store.
* **Start and WIP.** ``open_run`` creates the run ``QUEUED`` and claims its ticket in one
  transaction (``queries.start_run``), so a duplicate active run starts nothing. Under a WIP limit
  every run is written *held* (``admitted: false``) and then goes through ``admit_queued``, which
  releases the oldest held runs into free slots; ``open_run`` reports ``started`` if its own run
  was among them. So there is one admission path, oldest first, and a newcomer cannot pass an
  older run. A release is one transaction that claims a WIP slot (``WIP/SLOT#k``, k below the
  limit: created with ``Absent()``, or a version-guarded takeover of a slot whose holder run is
  terminal, with a check that the holder still has that status) and flips ``admitted``, guarded
  by the run's version, so a run is released once however many callers race and the slots never
  exceed the limit. Nothing has to release a slot when a run ends. ``active_count`` is the number
  of slots with a live holder in any status; an admitted run that is still ``QUEUED`` counts.
  The queue is read with ``admit_queued`` listing the status index again before each release;
  between that read and the write a still-older run could appear, which is a window of one index
  read, and on DynamoDB the index is eventually consistent, so "oldest first" is as strict as
  the index allows and not a serialised guarantee. Another caller's ``admit_queued`` can release
  *your* run: a caller starts its own run if ``admitted`` and every id in
  ``IntakeOutcome.released``, and starting must be idempotent.
  Without a limit nothing is claimed and every run is admitted, so runs admitted while unlimited
  do not count once a limit is set. Lowering a limit never evicts a run: slots at or above the
  new limit keep their holders and stop being counted, so the team can briefly exceed a lowered
  limit.
* **Record.** The run keeps the intake actor, the ``ticket_revision`` and the frozen route inputs,
  computed by ``sto.gates.subject`` (which refuses keys that collide after normalising).
* **Windows.** ``merge_window`` says whether merge may happen now. A deny window, a closed
  ``allow_only`` cron, or the sprint's merge freeze holds the run in ``WAITING_EXTERNAL`` until
  the returned ``until``; the caller re-evaluates then.
* **T11.** ``review_edit`` pauses a run (``WAITING_HUMAN``) when a ticket edit that changes the
  revision comes from a non-member or an editor that cannot be identified; ``confirm_edit`` lets a
  member confirm it. Membership comes through the narrow ``MemberLookup`` port below, because the
  identity code has no member lookup yet.

Not here (owned elsewhere, described in the PR): calling these from the runtime or a driver,
telling the team about a skipped ticket, and applying the merge hold inside the merge effect.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from sto.config.schema import Intake
from sto.domain.errors import PermanentError
from sto.domain.states import RunStatus
from sto.gates.subject import TicketFields, ticket_revision
from sto.gates.windows import Instant, MergeWindow, merge_window, utc_text
from sto.store import queries
from sto.store.ports import (
    Absent,
    Check,
    ConditionFailedError,
    FieldEquals,
    IndexedStore,
    Item,
    Key,
    Op,
    Put,
    TeamScope,
    VersionIs,
)

__all__ = [
    "Decision",
    "EditVerdict",
    "IntakeOutcome",
    "IntakeRecord",
    "IntakeTicket",
    "MemberLookup",
    "MergeWindow",
    "NotAMemberError",
    "OverlappingIntakeError",
    "StaleConfirmationError",
    "active_count",
    "admit_queued",
    "check_publish",
    "confirm_edit",
    "decide",
    "find_overlaps",
    "matches",
    "merge_window",
    "open_run",
    "record",
    "review_edit",
    "selectors_overlap",
]

WorkflowRef = tuple[str, str]  # (team, workflow name)

# --- V12: closed selectors ---------------------------------------------------------------------


def _norm(value: str) -> str:
    return unicodedata.normalize("NFC", value).strip().casefold()


def _types(s: Intake) -> frozenset[str] | None:
    return None if s.issue_types is None else frozenset(_norm(t) for t in s.issue_types)


def selectors_overlap(a: Intake, b: Intake) -> bool:
    """Could one ticket match both? Source, project and label are compared case-insensitively
    and after NFC (more overlaps refused, never fewer); no issue types means every type. The
    sprint mode and ``extra_filter`` can only narrow, so they never make two selectors disjoint."""
    if (a.source, _norm(a.project), _norm(a.label)) != (b.source, _norm(b.project), _norm(b.label)):
        return False
    ta, tb = _types(a), _types(b)
    return ta is None or tb is None or bool(ta & tb)


class OverlappingIntakeError(PermanentError):
    """A workflow's intake overlaps another published workflow's (V12)."""

    def __init__(self, workflow: WorkflowRef, workflows: tuple[WorkflowRef, ...]) -> None:
        self.workflow, self.workflows = workflow, workflows
        names = ", ".join(f"{t}/{n}" for t, n in workflows)
        super().__init__(
            f"intake of {workflow[0]}/{workflow[1]} overlaps {names}: "
            "change the project, label or issue types so no ticket matches two workflows"
        )


def find_overlaps(intakes: Mapping[WorkflowRef, Intake]) -> list[tuple[WorkflowRef, WorkflowRef]]:
    """Every overlapping pair, each once, in sorted order."""
    keys = sorted(intakes)
    return [
        (a, b)
        for i, a in enumerate(keys)
        for b in keys[i + 1 :]
        if selectors_overlap(intakes[a], intakes[b])
    ]


def check_publish(
    workflow: WorkflowRef, intake: Intake, published: Mapping[WorkflowRef, Intake]
) -> None:
    """V12's overlap clause, for publish: raise ``OverlappingIntakeError`` if ``intake`` overlaps
    any *other* published workflow. The workflow's own earlier version is not another workflow."""
    clash = tuple(
        sorted(
            ref
            for ref, other in published.items()
            if ref != workflow and selectors_overlap(intake, other)
        )
    )
    if clash:
        raise OverlappingIntakeError(workflow, clash)


# --- the ticket, matching and the decision -----------------------------------------------------


@dataclass(frozen=True)
class IntakeTicket:
    """What intake knows of a ticket, from the adapter. ``None`` means "could not be told" and is
    read the safe way: not in the active sprint, a public repo, an unknown actor.

    ``repo_public`` is the adapter's to set. A source with no notion of repo visibility (Jira)
    passes ``False`` once the adapter knows the project is private to the org, and ``None``
    otherwise, which intake treats as public and refuses unless the org opted in."""

    source: str
    ref: str
    project: str
    labels: tuple[str, ...]
    issue_type: str | None
    in_active_sprint: bool | None
    repo_public: bool | None
    fields: TicketFields
    actor: str | None  # issuer|subject of whoever added the label or issued the command
    extra_filter_matched: bool = True  # the adapter's verdict on ``Intake.extra_filter``


def matches(intake: Intake, ticket: IntakeTicket) -> bool:
    """Does the ticket fit the closed selector (and its filter, which can only narrow)?"""
    if ticket.source != intake.source or _norm(ticket.project) != _norm(intake.project):
        return False
    if _norm(intake.label) not in {_norm(label) for label in ticket.labels}:
        return False
    if intake.issue_types is not None and (
        ticket.issue_type is None or _norm(ticket.issue_type) not in _types(intake)  # type: ignore[operator]
    ):
        return False
    return intake.extra_filter is None or ticket.extra_filter_matched


def _is_actor(value: object) -> bool:
    """``issuer|subject``, both non-empty and unpadded (the spelling ``sto.gates.sod`` uses)."""
    if not isinstance(value, str):
        return False
    issuer, bar, subject = value.partition("|")
    return bool(bar) and all(p and p == p.strip() for p in (issuer, subject))


@dataclass(frozen=True)
class Decision:
    start: bool
    workflow: str | None = None
    reason: str | None = None
    workflows: tuple[str, ...] = ()  # the workflows an ambiguous ticket matched


def decide(
    *,
    workflows: Mapping[str, Intake],
    ticket: IntakeTicket,
    public_repo_intake: bool,
    members: MemberLookup,
    team: str,
) -> Decision:
    """Which workflow, if any, a ticket starts. Starts nothing on any doubt."""
    hit = tuple(sorted(n for n, s in workflows.items() if matches(s, ticket)))
    if not hit:
        return Decision(False, reason="no_match")
    if len(hit) > 1:
        return Decision(False, reason="ambiguous", workflows=hit)
    name = hit[0]
    if not _is_actor(ticket.actor):
        return Decision(False, name, "unknown_actor")
    if not _member(members, team, ticket.actor):
        return Decision(False, name, "actor_not_member")
    if ticket.repo_public is not False and not public_repo_intake:
        return Decision(False, name, "public_repo_not_opted_in")
    sprint = workflows[name].sprint
    if sprint is not None and sprint.mode == "active_only" and ticket.in_active_sprint is not True:
        return Decision(False, name, "outside_active_sprint")
    return Decision(True, name)


# --- the record --------------------------------------------------------------------------------


@dataclass(frozen=True)
class IntakeRecord:
    """Stored on the run: who started it, at which ticket revision, and the route inputs as they
    were then (later edits follow the ratchet of D2-23 and never rewrite these)."""

    actor: str
    workflow: str
    source: str
    ref: str
    ticket_revision: str
    route_inputs: Mapping[str, str]
    started_at: str

    def to_data(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "workflow": self.workflow,
            "source": self.source,
            "ref": self.ref,
            "ticket_revision": self.ticket_revision,
            "route_inputs": dict(self.route_inputs),
            "started_at": self.started_at,
        }

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> IntakeRecord:
        try:
            texts = {
                k: data[k]
                for k in ("actor", "workflow", "source", "ref", "ticket_revision", "started_at")
            }
            inputs = data["route_inputs"]
        except KeyError as exc:
            raise ValueError(f"stored intake record lacks {exc.args[0]}") from None
        if not all(isinstance(v, str) and v for v in texts.values()):
            raise ValueError("stored intake record has a field that is not text")
        if not isinstance(inputs, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in inputs.items()
        ):
            raise ValueError("stored intake record has malformed route inputs")
        return cls(route_inputs=dict(inputs), **texts)


def record(ticket: IntakeTicket, workflow: str, now: Instant) -> IntakeRecord:
    """The intake record for ``ticket``. The revision and the normalised route inputs come from
    ``sto.gates.subject``; a ticket whose keys collide after normalising never gets this far."""
    if not _is_actor(ticket.actor):
        raise ValueError("an intake record needs an issuer|subject actor")
    assert ticket.actor is not None
    return IntakeRecord(
        actor=ticket.actor,
        workflow=workflow,
        source=ticket.source,
        ref=ticket.ref,
        ticket_revision=ticket_revision(ticket.fields),
        route_inputs=dict(ticket.fields.route_inputs),
        started_at=utc_text(now),
    )


# --- start, WIP --------------------------------------------------------------------------------

_PAGE = 100
WIP_PK = "WIP"
_TERMINAL = frozenset(s.value for s in RunStatus if s.is_terminal)


def _slot_key(k: int) -> Key:
    return Key(WIP_PK, f"SLOT#{k:06d}")


def _limit(wip_limit: int | None) -> int | None:
    if wip_limit is not None and (type(wip_limit) is not int or wip_limit < 0):
        raise ValueError("wip_limit must be None or an int of at least 0")
    return wip_limit


def _queued(store: IndexedStore, scope: TeamScope, size: int) -> list[Item]:
    """Every QUEUED run, oldest first (the status index lists newest first)."""
    items: list[Item] = []
    cursor: str | None = None
    while True:
        page = queries.list_runs(store, scope, RunStatus.QUEUED, limit=size, cursor=cursor)
        items.extend(page.items)
        if page.cursor is None:
            return items[::-1]
        cursor = page.cursor


def _is_held(item: Item) -> bool:
    return item.data.get("admitted") is False


def _slots(store: IndexedStore, scope: TeamScope) -> dict[str, Item]:
    found: dict[str, Item] = {}
    cursor: str | None = None
    while True:
        page = store.query(scope, WIP_PK, sk_prefix="SLOT#", limit=_PAGE, cursor=cursor)
        found.update({i.key.sk: i for i in page.items})
        if page.cursor is None:
            return found
        cursor = page.cursor


def _ended_holder(store: IndexedStore, scope: TeamScope, slot: Item) -> tuple[Key, str] | None:
    """The slot holder's run key and terminal status, or ``None`` if it cannot be shown to have
    ended: a holder whose run is missing, or whose status is not terminal, is live and is never
    displaced. Terminal statuses never change, so a takeover that also checks the status read
    cannot displace a run that is still going.

    A run item that is deleted (say by a retention job) reads as live here, so a retention job
    must free the run's slot in the same transaction that deletes the run."""
    pk, sk = slot.data.get("run_pk"), slot.data.get("run_sk")
    if not isinstance(pk, str) or not isinstance(sk, str) or not pk or not sk:
        return None
    run = store.get(scope, Key(pk, sk))
    status = None if run is None else run.data.get("status")
    if isinstance(status, str) and status in _TERMINAL:
        return Key(pk, sk), status
    return None


def _claim_ops(
    store: IndexedStore, scope: TeamScope, limit: int, run_id: str, run_key: Key
) -> list[Op] | None:
    """The write that gives ``run_id`` the lowest free slot below ``limit``: a create of an empty
    slot, or a version-guarded overwrite of one whose holder ended (plus a check that the holder
    still has the terminal status that was read, as ``queries.start_run`` does for a ticket).
    ``None`` if all are held. It commits only if the slots are still as read, so of any number of
    racing claims one wins."""
    slots = _slots(store, scope)
    mine = {"run_id": run_id, "run_pk": run_key.pk, "run_sk": run_key.sk}
    for k in range(limit):
        key = _slot_key(k)
        held = slots.get(key.sk)
        if held is None:
            return [Put(key, mine, when=Absent())]
        ended = _ended_holder(store, scope, held)
        if ended is not None:
            return [
                Put(key, mine, when=VersionIs(held.version)),
                Check(ended[0], FieldEquals("status", ended[1])),
            ]
    return None


def active_count(store: IndexedStore, scope: TeamScope, *, wip_limit: int) -> int:
    """Admitted runs holding one of the ``wip_limit`` slots, in any non-terminal status (an
    admitted run that is still ``QUEUED`` counts; a held one does not)."""
    limit = _limit(wip_limit)
    assert limit is not None
    slots = _slots(store, scope)
    return sum(
        1
        for k in range(limit)
        if (held := slots.get(_slot_key(k).sk)) is not None
        and _ended_holder(store, scope, held) is None
    )


def _held_runs(store: IndexedStore, scope: TeamScope, size: int) -> list[Item]:
    return [i for i in _queued(store, scope, size) if _is_held(i)]


def admit_queued(
    store: IndexedStore, scope: TeamScope, *, wip_limit: int | None, page_size: int = _PAGE
) -> list[str]:
    """Release the oldest held runs into free slots; return their ids, oldest first.

    Each release is one transaction that claims a slot and flips the run's ``admitted`` flag,
    guarded by the run's version, so a run is released once however many callers race: the loser
    re-reads, finds it admitted, and moves on. The queue is listed again before every release,
    so a run that appears while we work (an older one included) is seen; the run is re-read
    first and must still be ``QUEUED`` and held, so one cancelled after it was listed is not
    given a slot. Stops at the first run that finds every slot taken, so a younger run never
    passes an older one. The caller moves each released run on (``QUEUED`` to ``RUNNING``)."""
    limit = _limit(wip_limit)
    released: list[str] = []
    budget = 4 + 2 * len(_held_runs(store, scope, page_size))  # each pass makes progress or loses
    while budget > 0:
        budget -= 1
        held = _held_runs(store, scope, page_size)
        if not held:
            return released
        head = held[0]
        item = store.get(scope, head.key)
        run_id = None if item is None else item.data.get("id")
        if (
            item is None
            or not _is_held(item)
            or item.data.get("status") != RunStatus.QUEUED.value
            or not isinstance(run_id, str)
            or not run_id
        ):
            continue  # released, ended or gone since it was listed: list again
        ops: list[Op] = []
        if limit is not None:
            claim = _claim_ops(store, scope, limit, run_id, head.key)
            if claim is None:
                return released  # every slot is taken
            ops = claim
        run = Put(
            head.key,
            dict(item.data) | {"admitted": True},
            when=VersionIs(item.version),
            attrs=item.attrs,
        )
        try:
            store.transact(scope, [*ops, run])
        except ConditionFailedError:
            continue  # lost the run or a slot to another caller: list again
        released.append(run_id)
    return released


def _is_admitted(store: IndexedStore, scope: TeamScope, key: Key) -> bool:
    item = store.get(scope, key)
    return item is not None and item.data.get("admitted") is True


@dataclass(frozen=True)
class IntakeOutcome:
    """``admitted`` is whether this call's own run holds a slot when the call returns, whoever
    released it. ``released`` lists every run this call released into a slot: the caller starts
    all of them too, because another caller's run may be among them (that caller may already
    have returned ``queued``). A run can therefore be started by its own caller and by the one
    that released it, so starting a run (``QUEUED`` to ``RUNNING``) must be idempotent, which
    the reducer's transition table gives: a second start of a running run is refused."""

    status: Literal["started", "queued", "skipped"]
    admitted: bool
    reason: str | None = None
    run_id: str | None = None  # the run that holds the ticket, for a duplicate
    workflows: tuple[str, ...] = ()
    released: tuple[str, ...] = ()


def open_run(
    store: IndexedStore,
    scope: TeamScope,
    *,
    workflows: Mapping[str, Intake],
    ticket: IntakeTicket,
    public_repo_intake: bool,
    members: MemberLookup,
    wip_limit: int | None,
    run_id: str,
    now: Instant,
) -> IntakeOutcome:
    """Decide, then create the run ``QUEUED`` and claim its ticket in one transaction. Under a
    limit the run is written held and released through ``admit_queued`` (oldest first).

    ``started`` means this run holds a slot and may go ahead (the caller moves it to
    ``RUNNING``, along with every id in ``released``); ``queued`` means WIP, or an older run,
    keeps it waiting for ``admit_queued``. ``skipped`` wrote nothing: it carries the reason, and
    for a duplicate the run that holds the ticket."""
    limit = _limit(wip_limit)
    verdict = decide(
        workflows=workflows,
        ticket=ticket,
        public_repo_intake=public_repo_intake,
        members=members,
        team=scope.team,
    )
    if not verdict.start or verdict.workflow is None:
        return IntakeOutcome("skipped", False, verdict.reason, workflows=verdict.workflows)
    rec = record(ticket, verdict.workflow, now)
    stamp = utc_text(now)
    key = Key(f"RUN#{run_id}", "META")
    try:
        queries.ticket_attrs(ticket.source, ticket.ref, stamp, key)  # the key parts are valid
    except ValueError:
        return IntakeOutcome("skipped", False, "invalid_ticket_key")
    data = {
        "id": run_id,
        "team": scope.team,
        "status": RunStatus.QUEUED.value,
        "workflow": verdict.workflow,
        "intake": rec.to_data(),
        "admitted": limit is None,
    }
    try:
        queries.start_run(
            store,
            scope,
            key,
            data,
            run_id=run_id,
            status=RunStatus.QUEUED,
            updated_at=stamp,
            ticket=(ticket.source, ticket.ref),
        )
    except queries.ActiveRunExistsError as exc:
        return IntakeOutcome("skipped", False, "duplicate_active", run_id=exc.run_id)
    if limit is None:
        return IntakeOutcome("started", True, released=(run_id,))
    released = tuple(admit_queued(store, scope, wip_limit=limit)) if limit > 0 else ()
    if run_id in released or _is_admitted(store, scope, key):
        return IntakeOutcome("started", True, released=released)
    return IntakeOutcome("queued", False, "wip_limit", released=released)


# --- T11: edits --------------------------------------------------------------------------------


class MemberLookup(Protocol):
    """Is ``actor`` (``issuer|subject``) a member of ``team``? The identity code (D3-02, D3-05)
    has no such lookup yet; this is the narrowest port intake needs."""

    def is_member(self, team: str, actor: str) -> bool: ...


class NotAMemberError(PermanentError):
    pass


class StaleConfirmationError(PermanentError):
    pass


@dataclass(frozen=True)
class EditVerdict:
    action: Literal["unchanged", "accepted", "pause"]
    revision: str
    status: RunStatus | None = None  # WAITING_HUMAN when the run pauses
    reason: str | None = None


def _member(members: MemberLookup, team: str, actor: str | None) -> bool:
    """A malformed or missing actor is never looked up and is never a member."""
    return _is_actor(actor) and members.is_member(team, actor)  # type: ignore[arg-type]


def review_edit(
    *,
    team: str,
    confirmed_revision: str,
    pending_revision: str | None,
    fields: TicketFields,
    editor: str | None,
    members: MemberLookup,
) -> EditVerdict:
    """What to do with the ticket as it is now. ``pending_revision`` is the revision of an edit
    that paused the run and is not yet confirmed, or ``None``.

    A revision equal to the confirmed one changes nothing (our own comments never reach it, and
    reverting an edit clears it). Otherwise, while an unconfirmed edit is outstanding the run
    stays paused whoever writes next: the snapshot holds the earlier edit too, so a member's
    follow-up must not launder it. With nothing outstanding, a member's edit is accepted and any
    other edit pauses the run until a member confirms it."""
    revision = ticket_revision(fields)
    if revision == confirmed_revision:
        return EditVerdict("unchanged", revision)
    if pending_revision is not None:
        return EditVerdict(
            "pause",
            revision,
            RunStatus.WAITING_HUMAN,
            "an earlier ticket edit is still unconfirmed; a member must confirm the latest",
        )
    if _member(members, team, editor):
        return EditVerdict("accepted", revision)
    return EditVerdict(
        "pause",
        revision,
        RunStatus.WAITING_HUMAN,
        "ticket edited by a non-member or unknown editor; a member must confirm",
    )


def confirm_edit(
    *,
    team: str,
    pending_revision: str,
    current_revision: str,
    confirmer: str | None,
    members: MemberLookup,
) -> str:
    """A member confirms the pending revision, which becomes the confirmed one. Refused for a
    non-member, and when the ticket moved again since the pause (confirm what was reviewed)."""
    if not _member(members, team, confirmer):
        raise NotAMemberError("only a team member can confirm a ticket edit")
    if pending_revision != current_revision:
        raise StaleConfirmationError("the ticket changed again; review the latest revision")
    return pending_revision
