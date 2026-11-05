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
  opt-in, or an intake actor that cannot be identified.
* **Start.** ``open_run`` creates the run ``QUEUED`` and claims its ticket in one transaction
  (``queries.start_run``), so a duplicate active run starts nothing. WIP is counted from the status
  index; a run over the limit stays ``QUEUED`` (``admitted`` is false) and ``admit_queued`` names
  the oldest to release when slots free up.
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
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from sto.config.schema import Intake
from sto.domain.errors import PermanentError
from sto.domain.states import RunStatus
from sto.gates.subject import TicketFields, ticket_revision
from sto.gates.windows import Instant, MergeWindow, merge_window, utc_text
from sto.store import queries
from sto.store.ports import IndexedStore, Key, TeamScope

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
    read the safe way: not in the active sprint, a public repo, an unknown actor."""

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
    *, workflows: Mapping[str, Intake], ticket: IntakeTicket, public_repo_intake: bool
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
    route_inputs: Mapping[str, str] = field(default_factory=dict)
    started_at: str = ""

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

_ACTIVE = (
    RunStatus.RUNNING,
    RunStatus.WAITING_HUMAN,
    RunStatus.WAITING_EXTERNAL,
    RunStatus.BLOCKED,
)
_PAGE = 100


def _walk(store: IndexedStore, scope: TeamScope, status: RunStatus, page_size: int) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    while True:
        page = queries.list_runs(store, scope, status, limit=page_size, cursor=cursor)
        items.extend(page.items)
        if page.cursor is None:
            return items
        cursor = page.cursor


def active_count(store: IndexedStore, scope: TeamScope, *, page_size: int = _PAGE) -> int:
    """Runs using a WIP slot: running, waiting or blocked. Queued runs and runs winding down or
    ended do not. Read from the status index (eventually consistent on DynamoDB), so a count that
    is a little stale holds a run back or lets one extra through, and never loses a ticket."""
    return sum(len(_walk(store, scope, s, page_size)) for s in _ACTIVE)


def admit_queued(
    store: IndexedStore, scope: TeamScope, *, wip_limit: int | None, page_size: int = _PAGE
) -> list[str]:
    """Ids of the queued runs to release now, oldest first, up to the free slots."""
    queued = _walk(store, scope, RunStatus.QUEUED, page_size)[::-1]  # the index is newest first
    free = len(queued) if wip_limit is None else max(0, wip_limit - active_count(store, scope))
    ids: list[str] = []
    for item in queued[:free]:
        run_id = item.data.get("id")
        if isinstance(run_id, str) and run_id:
            ids.append(run_id)
    return ids


@dataclass(frozen=True)
class IntakeOutcome:
    status: Literal["started", "queued", "skipped"]
    admitted: bool
    reason: str | None = None
    run_id: str | None = None  # the run that holds the ticket, for a duplicate
    workflows: tuple[str, ...] = ()


def open_run(
    store: IndexedStore,
    scope: TeamScope,
    *,
    workflows: Mapping[str, Intake],
    ticket: IntakeTicket,
    public_repo_intake: bool,
    wip_limit: int | None,
    run_id: str,
    now: Instant,
) -> IntakeOutcome:
    """Decide, then create the run ``QUEUED`` and claim the ticket in one transaction.

    ``started`` means the run may go ahead (the caller moves it to ``RUNNING``); ``queued`` means
    WIP holds it, and ``admit_queued`` releases it later. ``skipped`` wrote nothing."""
    verdict = decide(workflows=workflows, ticket=ticket, public_repo_intake=public_repo_intake)
    if not verdict.start or verdict.workflow is None:
        return IntakeOutcome("skipped", False, verdict.reason, workflows=verdict.workflows)
    rec = record(ticket, verdict.workflow, now)
    stamp = utc_text(now)
    key = Key(f"RUN#{run_id}", "META")
    data = {
        "id": run_id,
        "team": scope.team,
        "status": RunStatus.QUEUED.value,
        "workflow": verdict.workflow,
        "intake": rec.to_data(),
    }
    held = wip_limit is not None and active_count(store, scope) >= wip_limit
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
    if held:
        return IntakeOutcome("queued", False, "wip_limit")
    return IntakeOutcome("started", True)


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
    fields: TicketFields,
    editor: str | None,
    members: MemberLookup,
) -> EditVerdict:
    """What to do with the ticket as it is now. A revision equal to the confirmed one changes
    nothing (our own comments never reach it); a member's edit is accepted; any other edit pauses
    the run until a member confirms it."""
    revision = ticket_revision(fields)
    if revision == confirmed_revision:
        return EditVerdict("unchanged", revision)
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
