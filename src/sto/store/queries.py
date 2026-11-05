"""Indexed queries (D3-10): "my approvals", run lists, ticket lookup, PR lookup and a team's
resources, all through the five GSIs of PLAN 11 and never by reading a partition and filtering.

Writers build the promoted attributes with the ``*_attrs`` helpers and pass them as ``Put(...,
attrs=...)``; readers use the query functions. The index layout (the team prefix is added by the
store, so these keys are the same for every team):

=========  ===========================  ===========================  =========================
index      pk                           sk                           use
=========  ===========================  ===========================  =========================
``gsi1``   ``GATE#OPEN#<role>``          ``<opened_at>``              my approvals (open gates)
``gsi2``   ``RUNS#<status>``             ``<updated_at>``             run lists, newest first
``gsi3``   ``TICKET#<source>#<ref>``     ``<updated_at>``             ticket lookup (active runs)
``gsi4``   ``PR#<repo>#<n>``             ``<updated_at>``             PR lookup, webhook routing
``gsi5``   ``ORG#TEAM#<team>``           ``<kind>#<id>``              a team's resources
=========  ===========================  ===========================  =========================

Timestamps are ISO 8601 strings in UTC, so text order is time order.

**Index sort keys are unique by construction.** Where entries of one index partition can share a
timestamp (``gsi1``-``gsi4``), the sort key is ``<stamp>#<item pk>#<item sk>`` (the stamp has no
``#``). DynamoDB does not document the order of equal sort keys, and a page that resumes from an
``ExclusiveStartKey`` inside such a tie could skip entries; with distinct keys there is no tie.
``gsi5`` is ``<kind>#<id>``, already one per ORG item.

**A Put replaces the item, attributes included.** An item that is rewritten must be written with
its ``*_attrs`` again, or it leaves the indexes (which is what closing a gate does on purpose).

Reads of a GSI are eventually consistent on DynamoDB, so a result says "look here", not "decide
from this": a caller that acts on a gate or run re-reads the item with ``get``.

**One active run per ticket.** An index cannot be unique, so ``start_run`` makes the claim an item
of its own, ``TICKET#<source>#<ref>`` / ``ACTIVE``, created with ``Absent()`` in the same
transaction as the run. Of any number of concurrent starts exactly one commits; the others get
``ActiveRunExistsError`` and write nothing. Ending a run releases the claim with
``release_ticket_ops`` in the transaction that moves it to a terminal status. A release succeeds
whether the claim is held by this run or missing (a run that never had one can still end), and is
refused when another run holds it. If a run ended without releasing, the next ``start_run`` takes
the claim over, in one transaction: a ``Check`` that the holder's run is still in the terminal
status that was read, a versioned overwrite of the claim, and the new run.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sto.domain.errors import PermanentError
from sto.domain.states import RunStatus

from .ports import (
    PLATFORM,
    Absent,
    Check,
    ConditionFailedError,
    Delete,
    FieldEquals,
    IndexedStore,
    Item,
    Key,
    Op,
    Page,
    Put,
    TeamScope,
    VersionIs,
    encode_index_cursor,
)

GATE_QUEUE = "gsi1"
RUN_LIST = "gsi2"
TICKET_LOOKUP = "gsi3"
PR_LOOKUP = "gsi4"
RESOURCE_LOOKUP = "gsi5"

CLAIM_SK = "ACTIVE"


class ActiveRunExistsError(PermanentError):
    """The ticket already has an active run. ``run_id`` is that run (``None`` if the claim
    vanished before it could be read)."""

    def __init__(self, source: str, ref: str, run_id: str | None) -> None:
        self.source, self.ref, self.run_id = source, ref, run_id
        super().__init__(f"ticket {source}:{ref} already has an active run ({run_id})")


# --- key parts ---------------------------------------------------------------------------------


def _part(label: str, value: object, *, allow_hash: bool = False) -> str:
    """A key part: non-empty text, and no ``#`` (it is the separator, so ``a#b`` + ``c`` would
    collide with ``a`` + ``b#c``) unless it is the last part."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be non-empty text without surrounding whitespace")
    if "#" in value and not allow_hash:
        raise ValueError(f"{label} must not contain '#'")
    return value


def _stamp(label: str, value: object) -> str:
    return _part(label, value, allow_hash=True)


def ttl_attrs(expires_at: datetime) -> dict[str, str | int]:
    """The ``ttl`` attribute (epoch seconds) for a row that expires at ``expires_at``: task
    tokens, concurrency leases, and webhook dedupe rows of vendors with a signed timestamp."""
    if expires_at.tzinfo is None:
        raise ValueError("expires_at needs a timezone")
    return {"ttl": int(expires_at.timestamp())}


def _unique_sk(label: str, stamp: str, key: Key) -> str:
    """``<stamp>#<pk>#<sk>``: sorts by time, and no two items of one index share it."""
    return f"{_part(label, stamp)}#{key.pk}#{key.sk}"


def gate_queue_attrs(role: str, opened_at: str, key: Key) -> dict[str, str | int]:
    """Index entry of an OPEN gate item ``key`` that ``role`` can decide. Leave it out when the
    gate closes."""
    return {
        "gsi1pk": f"GATE#OPEN#{_part('role', role)}",
        "gsi1sk": _unique_sk("opened_at", opened_at, key),
    }


def run_attrs(
    status: RunStatus,
    updated_at: str,
    key: Key,
    *,
    ticket: tuple[str, str] | None = None,
    pr: tuple[str, int] | None = None,
) -> dict[str, str | int]:
    """Index entries of a run's META item: the run list by status always, the ticket lookup while
    the run is active (a terminal run leaves it, so the lookup finds active runs only), and the PR
    lookup when it has a PR."""
    attrs: dict[str, str | int] = {
        "gsi2pk": f"RUNS#{_part('status', RunStatus(status).value)}",
        "gsi2sk": _unique_sk("updated_at", updated_at, key),
    }
    if ticket is not None and not RunStatus(status).is_terminal:
        attrs |= ticket_attrs(*ticket, updated_at, key)
    if pr is not None:
        attrs |= pr_attrs(pr[0], pr[1], updated_at, key)
    return attrs


def _ticket_pk(source: str, ref: str) -> str:
    return f"TICKET#{_part('source', source)}#{_stamp('ref', ref)}"


def ticket_attrs(source: str, ref: str, updated_at: str, key: Key) -> dict[str, str | int]:
    return {"gsi3pk": _ticket_pk(source, ref), "gsi3sk": _unique_sk("updated_at", updated_at, key)}


def _pr_pk(repo: str, number: int) -> str:
    if type(number) is not int or number < 1:
        raise ValueError("a PR number is an int of at least 1")
    return f"PR#{_part('repo', repo)}#{number}"


def pr_attrs(repo: str, number: int, updated_at: str, key: Key) -> dict[str, str | int]:
    return {"gsi4pk": _pr_pk(repo, number), "gsi4sk": _unique_sk("updated_at", updated_at, key)}


def resource_attrs(team: str, kind: str, resource_id: str) -> dict[str, str | int]:
    """Reverse index of a resource binding (an ORG item, written with ``scope=PLATFORM``)."""
    return {
        "gsi5pk": f"ORG#TEAM#{_part('team', team)}",
        "gsi5sk": f"{_part('kind', kind)}#{_stamp('resource id', resource_id)}",
    }


# --- queries -----------------------------------------------------------------------------------


def open_gates(
    store: IndexedStore,
    scope: TeamScope,
    role: str,
    *,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    """Open gates one role can decide, oldest first."""
    return store.query_index(
        scope, GATE_QUEUE, f"GATE#OPEN#{_part('role', role)}", limit=limit, cursor=cursor
    )


def my_approvals(
    store: IndexedStore,
    scope: TeamScope,
    roles: Sequence[str],
    *,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    """Open gates any of ``roles`` can decide, oldest first (ties by item key), as a merge of one
    index query per role. The cursor remembers where each role stopped, so paging is stable and
    bound to the role set; it is not valid for another set of roles."""
    names = sorted({_part("role", r) for r in roles})
    state = _decode_approvals_cursor(cursor, scope, names)
    fetched: dict[str, Page] = {}
    candidates: list[tuple[tuple[str, str, str], str, Item]] = []
    for role in names:
        if state.get(role, _START) is _DONE:
            continue
        mark = state.get(role, _START)
        page = store.query_index(
            scope,
            GATE_QUEUE,
            f"GATE#OPEN#{role}",
            limit=limit,
            cursor=None if mark is _START else _role_cursor(scope, role, mark),
        )
        fetched[role] = page
        for item in page.items:
            candidates.append(
                ((str(item.attrs["gsi1sk"]), _addr_pk(item), item.key.sk), role, item)
            )
    candidates.sort(key=lambda c: c[0])
    taken = candidates if limit is None else candidates[:limit]
    marks: dict[str, Any] = {r: state.get(r, _START) for r in names}
    for role, page in fetched.items():
        mine = [c for c in taken if c[1] == role]
        if len(mine) == len(page.items) and page.cursor is None:
            marks[role] = _DONE  # everything it had is on this page or an earlier one
        elif mine:
            marks[role] = mine[-1][0]
    items = tuple(c[2] for c in taken)
    if all(m is _DONE for m in marks.values()):
        return Page(items, None)
    return Page(items, _encode_approvals_cursor(scope, names, marks))


def list_runs(
    store: IndexedStore,
    scope: TeamScope,
    status: RunStatus,
    *,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    """A team's runs in one status, most recently updated first."""
    return store.query_index(
        scope,
        RUN_LIST,
        f"RUNS#{_part('status', RunStatus(status).value)}",
        limit=limit,
        cursor=cursor,
        descending=True,
    )


def runs_for_ticket(store: IndexedStore, scope: TeamScope, source: str, ref: str) -> Page:
    """The active run(s) of a ticket: at most one, since ``start_run`` claims the ticket."""
    return store.query_index(scope, TICKET_LOOKUP, _ticket_pk(source, ref))


def runs_for_pr(
    store: IndexedStore,
    scope: TeamScope,
    repo: str,
    number: int,
    *,
    limit: int | None = None,
    cursor: str | None = None,
) -> Page:
    """Items carrying a PR's index entry, to route a webhook."""
    return store.query_index(scope, PR_LOOKUP, _pr_pk(repo, number), limit=limit, cursor=cursor)


def resources_of_team(
    store: IndexedStore, team: str, *, limit: int | None = None, cursor: str | None = None
) -> Page:
    """The resource bindings an org admin gave one team (ORG items, so the platform scope)."""
    return store.query_index(
        PLATFORM, RESOURCE_LOOKUP, f"ORG#TEAM#{_part('team', team)}", limit=limit, cursor=cursor
    )


# --- one active run per ticket -----------------------------------------------------------------


def _claim_key(source: str, ref: str) -> Key:
    return Key(_ticket_pk(source, ref), CLAIM_SK)


class ClaimHeldByAnotherRunError(PermanentError):
    """A run tried to release a ticket claim that another run holds."""

    def __init__(self, source: str, ref: str, holder: str | None) -> None:
        self.source, self.ref, self.holder = source, ref, holder
        super().__init__(f"ticket {source}:{ref} is claimed by another run ({holder})")


def release_ticket_ops(
    store: IndexedStore, scope: TeamScope, source: str, ref: str, *, run_id: str
) -> list[Op]:
    """Operations that release ``run_id``'s claim on a ticket; add them to the transaction that
    moves the run to a terminal status. They commit only if the claim is still as read:

    * held by this run: a ``Delete`` guarded by the claim's version;
    * missing (the run never had one, or it was released): a ``Check`` that it is still absent,
      so a run without a claim can still end;
    * held by another run: ``ClaimHeldByAnotherRunError``, and nothing is released.
    """
    claim = _claim_key(source, ref)
    held = store.get(scope, claim)
    if held is None:
        return [Check(claim, Absent())]
    holder = held.data.get("run_id")
    if holder != _part("run_id", run_id):
        raise ClaimHeldByAnotherRunError(source, ref, None if holder is None else str(holder))
    return [Delete(claim, when=VersionIs(held.version))]


_TERMINAL = frozenset(s.value for s in RunStatus if s.is_terminal)


def _claim_data(run_id: str, updated_at: str, run_key: Key) -> dict[str, Any]:
    return {
        "run_id": _part("run_id", run_id),
        "since": _stamp("updated_at", updated_at),
        "run_pk": run_key.pk,
        "run_sk": run_key.sk,
    }


def start_run(
    store: IndexedStore,
    scope: TeamScope,
    run_key: Key,
    run_data: dict[str, Any],
    *,
    run_id: str,
    status: RunStatus,
    updated_at: str,
    ticket: tuple[str, str],
    pr: tuple[str, int] | None = None,
    extra_ops: Sequence[Op] = (),
) -> None:
    """Create a run and claim its ticket in one transaction. Raises ``ActiveRunExistsError`` if
    the ticket has an active run, and writes nothing. Other errors (for example the run item
    already existing) are ``ConditionFailedError`` as usual.

    If the claim is held by a run whose item shows a terminal status (``data["status"]``), that
    run ended without releasing: the claim is taken over in the same transaction, guarded by the
    claim's version and by that run still having the status that was read (terminal statuses
    never change). A holder whose run item is missing or not terminal is never displaced."""
    source, ref = ticket
    claim = _claim_key(source, ref)
    mine = _claim_data(run_id, updated_at, run_key)
    new_run = [
        Put(
            run_key,
            run_data,
            when=Absent(),
            attrs=run_attrs(status, updated_at, run_key, ticket=ticket, pr=pr),
        ),
        *extra_ops,
    ]
    try:
        store.transact(scope, [Put(claim, mine, when=Absent()), *new_run])
        return
    except ConditionFailedError as exc:
        if 0 not in exc.failed:
            raise
    held = store.get(scope, claim)
    ended = _ended_holder(store, scope, held)
    if held is None or ended is None:
        raise ActiveRunExistsError(
            source, ref, None if held is None else str(held.data.get("run_id"))
        )
    holder_key, holder_status = ended
    try:
        store.transact(
            scope,
            [
                Put(claim, mine, when=VersionIs(held.version)),
                Check(holder_key, FieldEquals("status", holder_status)),
                *new_run,
            ],
        )
    except ConditionFailedError as exc:
        if exc.failed and min(exc.failed) <= 1:  # the claim or the holder moved: someone else won
            now = store.get(scope, claim)
            raise ActiveRunExistsError(
                source, ref, None if now is None else str(now.data.get("run_id"))
            ) from exc
        raise


def _ended_holder(
    store: IndexedStore, scope: TeamScope, claim: Item | None
) -> tuple[Key, str] | None:
    """The claim holder's run key and terminal status, or ``None`` if it cannot be shown to have
    ended."""
    if claim is None:
        return None
    pk, sk = claim.data.get("run_pk"), claim.data.get("run_sk")
    if not isinstance(pk, str) or not isinstance(sk, str) or not pk or not sk:
        return None
    run = store.get(scope, Key(pk, sk))
    status = None if run is None else run.data.get("status")
    if isinstance(status, str) and status in _TERMINAL:
        return Key(pk, sk), status
    return None


# --- merged cursor of my_approvals -------------------------------------------------------------


def _addr_pk(item: Item) -> str:
    return "" if item.key.pk == "TEAM" else item.key.pk


_START: Any = object()  # a role not read yet
_DONE: Any = object()  # a role with nothing left


def _role_cursor(scope: TeamScope, role: str, mark: tuple[str, str, str]) -> str:
    return encode_index_cursor(
        f"TEAM#{scope.team}", GATE_QUEUE, f"GATE#OPEN#{role}", "", False, mark
    )


def _encode_approvals_cursor(scope: TeamScope, roles: list[str], marks: dict[str, Any]) -> str:
    wire = [
        "start" if marks[r] is _START else "done" if marks[r] is _DONE else [*marks[r]]
        for r in roles
    ]
    raw = json.dumps(["approvals", scope.team, roles, wire])
    return base64.urlsafe_b64encode(raw.encode()).decode("ascii")


def _decode_approvals_cursor(
    cursor: str | None, scope: TeamScope, roles: list[str]
) -> dict[str, Any]:
    if cursor is None:
        return {}
    try:
        parts = json.loads(base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True))
        ok = (
            isinstance(parts, list)
            and len(parts) == 4
            and parts[0] == "approvals"
            and isinstance(parts[2], list)
            and isinstance(parts[3], list)
            and len(parts[2]) == len(parts[3])
        )
    except (TypeError, ValueError, binascii.Error, RecursionError):
        raise ValueError("invalid cursor") from None
    if not ok:
        raise ValueError("invalid cursor")
    if parts[1] != scope.team or parts[2] != roles:
        raise ValueError("cursor belongs to a different query")
    state: dict[str, Any] = {}
    for role, mark in zip(parts[2], parts[3], strict=True):
        if mark == "start":
            state[role] = _START
        elif mark == "done":
            state[role] = _DONE
        elif isinstance(mark, list) and len(mark) == 3 and all(isinstance(m, str) for m in mark):
            state[role] = (mark[0], mark[1], mark[2])
        else:
            raise ValueError("invalid cursor")
    return state
