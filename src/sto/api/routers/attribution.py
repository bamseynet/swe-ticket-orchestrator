"""Commit attribution and term resolution (PLAN 9.4, D3-19).

Separation of duties (``sto.gates.sod``) blocks every approval while a commit of the PR is human
and unattributed, or while the requester or author cannot be resolved. These routes let a team
admin clear that, so one stray commit never leaves a run stuck for ever:

* ``POST /runs/{id}/commits/{sha}:attribute`` either **attributes** the commit to a person
  (``attributed_to``) or **clears a false exclusion**: a ``Co-authored-by`` trailer that named
  someone who did not write it (``clear_exclusion``). Exactly one of the two.
* ``POST /runs/{id}/sod-terms:resolve`` names who the ``requester`` or ``author`` term excludes.
* ``GET /runs/{id}/sod-blocks`` is what the gate reports: every block that stops approvals, and
  the roles that can clear it (:data:`CLEARING_ROLES`).

Only ``team_admin`` and ``org_admin`` hold ``ATTRIBUTE_COMMIT`` (PLAN 9.3), enforced by the
middleware for both POST routes. People are named as actor keys, ``issuer|subject``, the form
``sto.gates.sod`` compares; the caller is recorded as the authenticated actor, never a name from
the body. A person cannot clear their own exclusion (the evaluator ignores it as well).

Every change is one transaction: the record, and its chained audit entry (built by
``sto.gates.hooks.record_with_audit``), so neither exists without the other. A lost race on the
audit chain re-reads and tries again. A refusal writes nothing.

Records live in the run's partition, next to its gates: ``COMMIT#<sha>`` (what ingest observed,
plus who attributed it) and ``SODRES#<term>#<id>`` (one per resolution). Ingest of commits is
D4's; this module only reads a commit that is already recorded (404 otherwise), and
:func:`read_records` hands both kinds back as :mod:`sto.gates.sod` values for the decision path.
Which authors are unresolved is ingest's to record too, so ``sod-blocks`` reports an unresolved
requester (a run with no known starter) and unattributed commits, and an unresolved author only
once ingest says so (the ``unresolved`` argument of :func:`blockers`).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field

from sto.api.auth import actor_key
from sto.api.routers.runs import (
    NOT_FOUND,
    ApiError,
    ErrorResponse,
    RuntimeDep,
    _busy,
    authorization_of,
    parse_run_id,
)
from sto.api.runtime import RunNotFoundError, Runtime, StoreConflictError
from sto.config.org_policy import ORG_ADMIN
from sto.config.schema import Floors, SeparationOfDuties
from sto.domain import Gate, RunId
from sto.gates.hooks import ReadOnly, record_with_audit, run_pk
from sto.gates.sod import Commit, Exclusion, Pusher, Resolution, RunFacts, evaluate
from sto.identity.mapping import UserIdentity
from sto.store.ports import (
    Absent,
    ConditionFailedError,
    Key,
    Op,
    Put,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)

log = logging.getLogger("sto.api")
router = APIRouter(tags=["attribution"])

CLEARING_ROLES = ("team_admin", ORG_ADMIN)
"""Who can clear a block: the roles that hold ``ATTRIBUTE_COMMIT``."""
_ATTEMPTS = 8
_SHA = re.compile(r"[0-9a-f]{7,64}")
_COMMIT = "COMMIT#"
_RESOLUTION = "SODRES#"
Term = Literal["requester", "author"]


def _now_ms() -> int:
    return int(time.time() * 1000)


# --- records ------------------------------------------------------------------------------------


def commit_key(run_id: RunId, sha: str) -> Key:
    return Key(run_pk(run_id), f"{_COMMIT}{sha}")


def _commit_from(data: dict[str, Any]) -> Commit:
    return Commit(
        sha=data["sha"],
        in_receipts=data["in_receipts"],
        attributed_to=data.get("attributed_to"),
        attributed_by=data.get("attributed_by"),
        git_author=data.get("git_author", ""),
        coauthors=tuple(
            Exclusion(e["actor"], e["source"], e.get("cleared_by"))
            for e in data.get("coauthors", ())
        ),
        pushers=tuple(Pusher(a) for a in data.get("pushers", ())),
    )


def _pages(store: Store, scope: TeamScope, run_id: RunId, prefix: str) -> Iterable[dict[str, Any]]:
    cursor: str | None = None
    while True:
        page = store.query(scope, run_pk(run_id), sk_prefix=prefix, cursor=cursor)
        for item in page.items:
            yield item.data
        cursor = page.cursor
        if cursor is None:
            return


def read_records(
    store: Store, scope: TeamScope, run_id: RunId
) -> tuple[tuple[Commit, ...], tuple[Resolution, ...]]:
    """The run's commits and term resolutions, as ``sto.gates.sod`` values, read fresh. A record
    the evaluator refuses raises ``ValueError`` (a corrupt record is a fault, never ignored)."""
    commits = tuple(_commit_from(d) for d in _pages(store, scope, run_id, _COMMIT))
    resolutions = tuple(
        Resolution(d["term"], frozenset(d["actors"]), d["resolved_by"])
        for d in _pages(store, scope, run_id, _RESOLUTION)
    )
    return commits, resolutions


@dataclass(frozen=True)
class Blocker:
    """One thing that stops every approval of one gate, and who can clear it."""

    reason: (
        str  # ``unattributed_commit:<sha>`` or ``unresolved_term:<term>``, as the evaluator says
    )
    clear_with: str  # the route that clears it
    gate: str
    round: int
    who_can_clear: tuple[str, ...] = CLEARING_ROLES


_PROBE = UserIdentity("probe", "probe", frozenset())
# What the runtime knows of org policy until config is wired in: the schema's defaults (the
# requester floor covers review and pre_push). ``model_construct`` skips the required fields the
# evaluator never reads here.
DEFAULT_FLOORS = Floors.model_construct()
_BLOCKING = ("unattributed_commit:", "unresolved_term:")


def blockers(
    commits: Iterable[Commit],
    resolutions: Iterable[Resolution],
    *,
    gates: Iterable[Gate],
    requester: str | None,
    unresolved: Collection[str] = (),
    floors: Floors = DEFAULT_FLOORS,
    sod_of: Callable[[Gate], SeparationOfDuties | None] = lambda gate: None,
) -> list[Blocker]:
    """What blocks approvals of each of ``gates`` now. Which terms a gate has (the requester floor,
    its own ``separation_of_duties``) is ``sto.gates.sod``'s table: this asks ``evaluate`` itself
    with a probe who holds no role, and keeps only its blocking reasons, so the report can never
    say "blocked" where ``evaluate`` allows. A commit blocks every gate; the requester only the
    gates whose terms include it. ``sod_of`` gives a gate's own SoD terms (none until the
    published config is wired in)."""
    facts = RunFacts(
        requester=requester,
        commits=tuple(commits),
        unresolved=frozenset(unresolved),
        resolutions=tuple(resolutions),
    )
    found: list[Blocker] = []
    for gate in gates:
        verdict = evaluate(
            who=_PROBE,
            linked=False,
            team="",
            gate=gate,
            eligible_roles=frozenset(),
            opened_with=None,
            sod=sod_of(gate),
            floors=floors,
            facts=facts,
        )
        for reason in verdict.reasons:
            if reason.startswith(_BLOCKING):
                clear_with = (
                    f"POST /runs/{{run_id}}/commits/{reason.partition(':')[2]}:attribute"
                    if reason.startswith(_BLOCKING[0])
                    else "POST /runs/{run_id}/sod-terms:resolve"
                )
                found.append(Blocker(reason, clear_with, gate.name, gate.round))
    return found


# --- the shape of requests and answers ----------------------------------------------------------


class BlockOut(BaseModel):
    reason: str
    clear_with: str
    gate: str
    round: int
    who_can_clear: list[str]


class BlockList(BaseModel):
    blocked: bool
    blocks: list[BlockOut]


class AttributeIn(BaseModel):
    attributed_to: str | None = Field(
        default=None,
        max_length=1_000,
        description="Who made the commit: an actor, `issuer|subject`. Email alone is not accepted.",
    )
    clear_exclusion: str | None = Field(
        default=None,
        max_length=1_000,
        description="An actor a `Co-authored-by` trailer named wrongly (`issuer|subject`). "
        "You cannot clear your own.",
    )


class ResolveIn(BaseModel):
    term: Term
    actors: list[Annotated[str, Field(max_length=1_000)]] = Field(
        min_length=1, max_length=50, description="Who the term excludes (`issuer|subject`)."
    )


class Changed(BaseModel):
    audited: bool = True
    blocked: bool
    blocks: list[BlockOut]


def _out(found: list[Blocker]) -> list[dict[str, Any]]:
    return [
        {
            "reason": b.reason,
            "clear_with": b.clear_with,
            "gate": b.gate,
            "round": b.round,
            "who_can_clear": list(b.who_can_clear),
        }
        for b in found
    ]


# --- shared plumbing ----------------------------------------------------------------------------


def _admin(request: Request) -> str:
    """The authenticated actor. With no sign-in there is no one to attribute the change to."""
    auth = authorization_of(request)
    if auth is None or not isinstance(auth.identity, UserIdentity):
        raise ApiError(403, "identity_required", "this needs a signed-in person")
    return actor_key(auth.identity)


def _valid_sha(sha: str) -> str:
    if _SHA.fullmatch(sha) is None:
        raise ApiError(404, "commit_not_found", "no such commit on this run")
    return sha


def _actor(label: str, value: str) -> str:
    """Validate an actor with the evaluator's own rule (a bad spelling would exclude nobody)."""
    try:
        Exclusion(value, label)
    except ValueError as e:
        raise ApiError(422, "invalid_actor", str(e)) from None
    return value


async def _commit_with_retry(rt: Runtime, attempt: Any) -> Any:
    """Run ``attempt`` (a sync function reading fresh and writing one transaction) in a thread,
    again when the audit chain or the record moved underneath it."""
    for n in range(_ATTEMPTS):
        try:
            return await asyncio.to_thread(attempt)
        except (ConditionFailedError, TransactionConflictError) as e:
            if n == _ATTEMPTS - 1:
                raise StoreConflictError("the store kept conflicting; try again") from e
            await asyncio.sleep(0.005 * 2**n)
    raise AssertionError("unreachable")  # pragma: no cover


def _commit(
    rt: Runtime, run_id: RunId, action: str, who: str, data: dict[str, Any], write: Op
) -> None:
    """One transaction: ``write`` and the audit entry for it (a lost chain race raises)."""
    ops = record_with_audit(
        ReadOnly(rt.store),
        rt.scope,
        run_id,
        action=action,
        actor=who,
        data=data,
        at=_now_ms(),
        writes=[write],
    )
    rt.store.transact(rt.scope, ops)


async def _requester(rt: Runtime, run_id: RunId) -> str | None:
    return await rt.started_by(run_id)


async def _blocks_now(rt: Runtime, run_id: RunId) -> list[dict[str, Any]]:
    gates = [g for g in _latest(await rt.gates(run_id)) if g.is_open]
    commits, resolutions = await asyncio.to_thread(read_records, rt.store, rt.scope, run_id)
    requester = await _requester(rt, run_id)
    return _out(blockers(commits, resolutions, gates=gates, requester=requester))


def _latest(gates: Iterable[Gate]) -> list[Gate]:
    """The latest round of each gate (an earlier round no longer waits for anyone)."""
    best: dict[str, Gate] = {}
    for g in gates:
        if g.name not in best or g.round > best[g.name].round:
            best[g.name] = g
    return list(best.values())


# --- routes -------------------------------------------------------------------------------------


@router.get(
    "/runs/{run_id}/sod-blocks",
    response_model=BlockList,
    responses=NOT_FOUND,
    summary="What blocks approvals, and who can clear it",
)
async def sod_blocks(run_id: str, rt: RuntimeDep) -> dict[str, Any]:
    rid = parse_run_id(run_id)
    try:
        blocks = await _blocks_now(rt, rid)
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    except (ValueError, KeyError, TypeError) as e:
        log.error("attribution on run %s hit data it cannot use: %r", run_id, e, exc_info=e)
        raise ApiError(500, "internal_error", "the server could not process this request") from e
    return {"blocked": bool(blocks), "blocks": blocks}


@router.post(
    "/runs/{run_id}/commits/{sha}:attribute",
    response_model=Changed,
    responses={**NOT_FOUND, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
    summary="Attribute a commit, or clear a false co-author exclusion",
)
async def attribute(
    run_id: str,
    sha: Annotated[str, Path(max_length=64)],
    body: AttributeIn,
    rt: RuntimeDep,
    request: Request,
) -> dict[str, Any]:
    admin = _admin(request)
    rid, sha = parse_run_id(run_id), _valid_sha(sha)
    if (body.attributed_to is None) == (body.clear_exclusion is None):
        raise ApiError(
            422, "one_action_required", "send exactly one of attributed_to and clear_exclusion"
        )
    target = _actor(
        "attributed_to" if body.attributed_to else "clear_exclusion",
        body.attributed_to or body.clear_exclusion or "",
    )
    clearing = body.clear_exclusion is not None
    if clearing and target == admin:
        raise ApiError(
            403, "cannot_clear_own_exclusion", "a person cannot clear their own exclusion"
        )
    try:
        await _astate(rt, rid)
        await _commit_with_retry(rt, lambda: _write_commit(rt, rid, sha, admin, target, clearing))
        blocks = await _blocks_now(rt, rid)
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    except (ValueError, KeyError, TypeError) as e:
        log.error("commit %s of run %s hit data it cannot use: %r", sha, run_id, e, exc_info=e)
        raise ApiError(500, "internal_error", "the server could not process this request") from e
    return {"audited": True, "blocked": bool(blocks), "blocks": blocks}


async def _astate(rt: Runtime, run_id: RunId) -> None:
    await asyncio.to_thread(rt.state, run_id)  # 404 for an unknown run (RunNotFoundError)


def _write_commit(
    rt: Runtime, run_id: RunId, sha: str, admin: str, target: str, clearing: bool
) -> None:
    key = commit_key(run_id, sha)
    item = rt.store.get(rt.scope, key)
    if item is None:
        raise ApiError(404, "commit_not_found", "no such commit on this run")
    data = dict(item.data)
    if clearing:
        # allowed on a platform commit too: the evaluator applies a trailer's exclusion before it
        # skips a platform commit, so a false one would otherwise be permanent
        coauthors = [dict(e) for e in data.get("coauthors", ())]
        named = [e for e in coauthors if e["actor"] == target]
        if not named:  # a pusher cannot be cleared (PLAN 9.4), nor can someone never named
            raise ApiError(404, "exclusion_not_found", "no co-author exclusion names that actor")
        if all(e.get("cleared_by") for e in named):
            raise ApiError(409, "already_cleared", "that exclusion is already cleared")
        for e in named:
            if not e.get("cleared_by"):  # an earlier clearer stays the one on record
                e["cleared_by"] = admin
        data["coauthors"] = coauthors
        action, detail = "commit.exclusion_cleared", {"sha": sha, "actor": target}
    else:
        if data.get("in_receipts") is True:
            raise ApiError(
                409, "not_attributable", "the platform made this commit; it has no author"
            )
        if data.get("attributed_to") and data.get("attributed_by"):
            raise ApiError(409, "already_attributed", "this commit is already attributed")
        data["attributed_to"], data["attributed_by"] = target, admin
        action, detail = "commit.attributed", {"sha": sha, "attributed_to": target}
    _commit_from(data)  # refuse a record the evaluator would refuse, before writing it
    _commit(rt, run_id, action, admin, detail, Put(key, data, VersionIs(item.version)))


@router.post(
    "/runs/{run_id}/sod-terms:resolve",
    response_model=Changed,
    responses={**NOT_FOUND, 403: {"model": ErrorResponse}},
    summary="Resolve an unknown requester or author",
)
async def resolve_term(run_id: str, body: ResolveIn, rt: RuntimeDep, request: Request) -> Any:
    admin = _admin(request)
    rid = parse_run_id(run_id)
    actors = sorted({_actor("actors", a) for a in body.actors})
    try:
        await _astate(rt, rid)
        await _commit_with_retry(rt, lambda: _write_resolution(rt, rid, admin, body.term, actors))
        blocks = await _blocks_now(rt, rid)
    except RunNotFoundError as e:
        raise ApiError(404, "run_not_found", str(e)) from e
    except StoreConflictError as e:
        raise _busy(e) from e
    except (ValueError, KeyError, TypeError) as e:
        log.error("attribution on run %s hit data it cannot use: %r", run_id, e, exc_info=e)
        raise ApiError(500, "internal_error", "the server could not process this request") from e
    return {"audited": True, "blocked": bool(blocks), "blocks": blocks}


def _write_resolution(rt: Runtime, run_id: RunId, admin: str, term: str, actors: list[str]) -> None:
    """Idempotent: the record is keyed by the term and its sorted actors, so a repeat finds the
    first one and writes nothing more (no second record, no second audit entry)."""
    data = {"term": term, "actors": actors, "resolved_by": admin}
    Resolution(data["term"], frozenset(actors), admin)  # type: ignore[arg-type]
    digest = hashlib.sha256("\n".join(actors).encode()).hexdigest()
    key = Key(run_pk(run_id), f"{_RESOLUTION}{term}#{digest}")
    if rt.store.get(rt.scope, key) is not None:
        return
    detail = {"term": term, "actors": actors}
    _commit(rt, run_id, "sod_term.resolved", admin, detail, Put(key, data, Absent()))
