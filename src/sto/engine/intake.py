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

import datetime as dt
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from zoneinfo import ZoneInfo

from sto.config.schema import Intake, TeamConfig, duration_seconds
from sto.domain.errors import PermanentError
from sto.domain.states import RunStatus
from sto.gates.subject import TicketFields, ticket_revision
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


def _aware(now: dt.datetime) -> dt.datetime:
    if now.tzinfo is None:
        raise ValueError("the clock needs a timezone")
    return now.astimezone(dt.UTC)


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


def record(ticket: IntakeTicket, workflow: str, now: dt.datetime) -> IntakeRecord:
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
        started_at=_aware(now).isoformat(),
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
    now: dt.datetime,
) -> IntakeOutcome:
    """Decide, then create the run ``QUEUED`` and claim the ticket in one transaction.

    ``started`` means the run may go ahead (the caller moves it to ``RUNNING``); ``queued`` means
    WIP holds it, and ``admit_queued`` releases it later. ``skipped`` wrote nothing."""
    verdict = decide(workflows=workflows, ticket=ticket, public_repo_intake=public_repo_intake)
    if not verdict.start or verdict.workflow is None:
        return IntakeOutcome("skipped", False, verdict.reason, workflows=verdict.workflows)
    rec = record(ticket, verdict.workflow, now)
    stamp = _aware(now).isoformat()
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


# --- windows -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class MergeWindow:
    open: bool
    status: RunStatus  # RUNNING if merge may go ahead, else WAITING_EXTERNAL
    reason: str | None = None
    until: dt.datetime | None = None  # when to look again; None if not known


_OPEN = MergeWindow(True, RunStatus.RUNNING)


def _held(reason: str, until: dt.datetime | None) -> MergeWindow:
    return MergeWindow(False, RunStatus.WAITING_EXTERNAL, reason, until)


class CronError(ValueError):
    pass


_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def _field(text: str, lo: int, hi: int) -> frozenset[int]:
    out: set[int] = set()
    for part in text.split(","):
        base, slash, step_text = part.partition("/")
        if slash and not step_text.isdigit():
            raise CronError(f"bad step in {part!r}")
        step = int(step_text) if slash else 1
        if step < 1:
            raise CronError(f"step must be at least 1 in {part!r}")
        if base == "*":
            a, b = lo, hi
        elif "-" in base:
            x, _, y = base.partition("-")
            if not (x.isdigit() and y.isdigit()):
                raise CronError(f"bad range {part!r}")
            a, b = int(x), int(y)
        elif base.isdigit():
            a = int(base)
            b = hi if slash else a
        else:
            raise CronError(f"bad value {part!r}")
        if not (lo <= a <= b <= hi):
            raise CronError(f"{part!r} is outside {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return frozenset(out)


@dataclass(frozen=True)
class _Cron:
    minute: frozenset[int]
    hour: frozenset[int]
    dom: frozenset[int]
    month: frozenset[int]
    dow: frozenset[int]  # 0 = Sunday
    dom_star: bool
    dow_star: bool

    def matches(self, t: dt.datetime) -> bool:
        if t.minute not in self.minute or t.hour not in self.hour or t.month not in self.month:
            return False
        in_dom, in_dow = t.day in self.dom, (t.isoweekday() % 7) in self.dow
        if self.dom_star or self.dow_star:
            return in_dom and in_dow
        return in_dom or in_dow  # both restricted: either, as cron does


def _parse_cron(text: str) -> _Cron:
    parts = text.split()
    if len(parts) != 5:
        raise CronError("a cron has five fields: minute hour day month weekday")
    f = [_field(p, lo, hi) for p, (lo, hi) in zip(parts, _RANGES, strict=True)]
    return _Cron(
        f[0], f[1], f[2], f[3], frozenset(d % 7 for d in f[4]), parts[2] == "*", parts[4] == "*"
    )


_CRON_SCAN_MINUTES = 8 * 24 * 60


def _local(t: dt.datetime, tz: ZoneInfo | dt.tzinfo) -> dt.datetime:
    return t.astimezone(tz)


def _cron_window(text: str, now: dt.datetime, tz: ZoneInfo | dt.tzinfo) -> MergeWindow | None:
    try:
        cron = _parse_cron(text)
    except CronError as exc:
        return _held(f"change_windows.allow_only is not a valid cron ({exc}); merge is held", None)
    base = now.replace(second=0, microsecond=0)
    if cron.matches(_local(base, tz)):
        return None
    for i in range(1, _CRON_SCAN_MINUTES):
        t = base + dt.timedelta(minutes=i)
        if cron.matches(_local(t, tz)):
            return _held("outside change_windows.allow_only", t)
    return _held("outside change_windows.allow_only", None)


def _sprint_window(
    cfg: TeamConfig, now: dt.datetime, tz: ZoneInfo | dt.tzinfo
) -> MergeWindow | None:
    sprint = cfg.sprint
    if sprint is None or sprint.merge_freeze_before_end is None:
        return None
    length = dt.timedelta(weeks=int(sprint.cadence[0]))
    start = dt.datetime.combine(sprint.anchor, dt.time(), tzinfo=tz)
    if now < start:
        return None
    end = start + length * ((now - start) // length + 1)
    freeze = dt.timedelta(seconds=duration_seconds(sprint.merge_freeze_before_end))
    if now >= end - freeze:
        return _held("sprint merge freeze", end)
    return None


def merge_window(cfg: TeamConfig, now: dt.datetime) -> MergeWindow:
    """May merge happen at ``now``? Deny windows, ``allow_only`` and the sprint freeze each hold
    it; the answer with the latest known reopening wins, and an unknown reopening wins over all.
    Local time (the cron, the sprint's day boundaries) is in the team calendar's zone, or UTC."""
    now = _aware(now)
    tz: ZoneInfo | dt.tzinfo = ZoneInfo(cfg.calendar.timezone) if cfg.calendar else dt.UTC
    holds: list[MergeWindow] = []
    windows = cfg.change_windows
    if windows is not None:
        for deny in windows.deny:
            if deny.from_ <= now < deny.to:
                holds.append(_held(f"change window: {deny.reason}", deny.to))
        if windows.allow_only is not None and (w := _cron_window(windows.allow_only, now, tz)):
            holds.append(w)
    if w := _sprint_window(cfg, now, tz):
        holds.append(w)
    if not holds:
        return _OPEN
    unknown = [h for h in holds if h.until is None]
    pick = unknown[0] if unknown else max(holds, key=lambda h: h.until or now)
    reasons = "; ".join(dict.fromkeys(h.reason or "" for h in holds))
    return _held(reasons, pick.until)


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
