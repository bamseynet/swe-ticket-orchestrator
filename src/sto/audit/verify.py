"""The verifier: the chain on its own, then against signed checkpoints (T14)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from typing import Any

from sto.audit.checkpoint import SignedCheckpoint
from sto.audit.errors import AuditVerificationError
from sto.audit.port import DEFAULT_PAGE, StoreAuditLog
from sto.domain import RunId
from sto.gates.hooks import GENESIS_HASH, entry_hash
from sto.signing.port import Verifier
from sto.store.ports import Scope, Store, TeamScope

__all__ = [
    "AuditVerificationError",
    "TeamVerification",
    "check_checkpoints",
    "check_entries",
    "verify_run",
    "verify_run_detail",
    "verify_team",
    "walk_run",
]


def team_of(scope: Scope) -> str:
    return scope.team if isinstance(scope, TeamScope) else ""


def check_entries(
    entries: Iterable[Mapping[str, Any]],
    run_id: str,
    team: str,
    *,
    anchor: tuple[int, str] | None = None,
) -> list[tuple[int, str]]:
    """Walk entries and return ``(seq, hash)`` for each. ``anchor`` is ``(seq, hash)`` of the
    entry before the first one given (default: the start of the chain)."""
    seq0, prev = anchor if anchor is not None else (0, GENESIS_HASH)
    out: list[tuple[int, str]] = []
    for n, item in enumerate(entries, start=seq0 + 1):
        body = {k: v for k, v in item.items() if k != "hash"}
        where = f"entry {n} of run {run_id}"
        if body.get("run") != run_id or body.get("team") != team:
            raise AuditVerificationError(f"audit chain broken at {where}: wrong run or team")
        if type(body.get("seq")) is not int or body["seq"] != n or body.get("prev") != prev:
            raise AuditVerificationError(f"audit chain broken at {where}: sequence or link")
        if entry_hash(body) != item.get("hash"):
            raise AuditVerificationError(f"audit chain broken at {where}: hash mismatch")
        prev = str(item["hash"])
        out.append((n, prev))
    return out


def check_checkpoints(
    team: str, checkpoints: Sequence[SignedCheckpoint], verifier: Verifier | None
) -> None:
    """Every checkpoint must carry a valid signature and belong to ``team``."""
    if checkpoints and verifier is None:
        raise AuditVerificationError("a verifier is needed to check checkpoints")
    for cp in checkpoints:
        if verifier is not None and not cp.is_signed_by(verifier):
            raise AuditVerificationError("checkpoint signature does not verify")
        if cp.checkpoint.team != team:
            raise AuditVerificationError("checkpoint belongs to another team")


def check_against_checkpoints(
    run_id: str,
    hashes: Mapping[int, str],
    *,
    last: int,
    to_tip: bool,
    checkpoints: Sequence[SignedCheckpoint],
) -> None:
    """Compare what was seen with every checkpoint that names the run. ``hashes`` maps seq to
    hash for the entries seen (plus the anchor, when the range does not start at 1); the range
    seen ends at ``last``. With ``to_tip`` it must reach each checkpointed count."""
    for cp in checkpoints:
        for head in cp.checkpoint.runs:
            if head.run_id != run_id:
                continue
            at = cp.checkpoint.at
            if head.count in hashes:
                if hashes[head.count] != head.hash:
                    raise AuditVerificationError(
                        f"run {run_id} differs from the checkpoint at {at}: "
                        f"entry {head.count} has another hash"
                    )
            elif head.count > last and to_tip:
                kind = "missing" if last == 0 else "fewer entries than"
                raise AuditVerificationError(
                    f"run {run_id} is {kind} its checkpoint: {last} entries, "
                    f"checkpoint at {at} has {head.count}"
                )


def _walk(store: Store, scope: Scope, run_id: RunId, page_size: int) -> list[tuple[int, str]]:
    """Read the head first, then verify entries up to ``head.seq`` and the hash there. A gate
    that commits meanwhile adds entries past the head we read, which are not examined, so a
    concurrent commit is not mistaken for tampering. One more item is read after them: if there
    is one and the head has not moved forward, something sits past the head (a rolled-back head,
    junk, a gap), and that is refused."""
    log = StoreAuditLog(store, page_size=page_size)
    for _ in range(2):
        head = log.head(scope, run_id)
        stream = log.entries(scope, run_id)
        if head is None:
            walked = check_entries(stream, str(run_id), team_of(scope))
            if not walked:
                return []
            continue  # entries but no head: the first commit may have landed in between
        items = list(islice(stream, head.seq))
        extra = next(stream, None)
        walked = check_entries(items, str(run_id), team_of(scope))
        if len(walked) != head.seq or walked[-1][1] != head.hash:
            raise AuditVerificationError(
                f"audit chain broken for run {run_id}: head does not match the last entry"
            )
        if extra is not None:
            moved = log.head(scope, run_id)  # a commit after our head read moves it forward
            if moved is None or moved.seq <= head.seq:
                raise AuditVerificationError(
                    f"audit chain broken for run {run_id}: entries past the chain head"
                )
        return walked
    raise AuditVerificationError(f"audit chain broken for run {run_id}: entries but no chain head")


def walk_run(
    store: Store, scope: Scope, run_id: RunId, *, page_size: int = DEFAULT_PAGE
) -> tuple[int, str]:
    """Verify a run's chain and head. Returns ``(count, last hash)``."""
    walked = _walk(store, scope, run_id, page_size)
    return walked[-1] if walked else (0, GENESIS_HASH)


def verify_run_detail(
    store: Store,
    scope: Scope,
    run_id: RunId,
    checkpoints: Sequence[SignedCheckpoint],
    page_size: int = DEFAULT_PAGE,
) -> tuple[int, str]:
    """``(count, last hash)`` of a run whose chain and head verify and agree with ``checkpoints``
    (already checked for signature and team). One walk, so a caller that needs the head hash too
    does not read the run twice."""
    walked = _walk(store, scope, run_id, page_size)
    count, last = walked[-1] if walked else (0, GENESIS_HASH)
    check_against_checkpoints(
        str(run_id), dict(walked), last=count, to_tip=True, checkpoints=checkpoints
    )
    return count, last


def verify_run(
    store: Store,
    scope: Scope,
    run_id: RunId,
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    verifier: Verifier | None = None,
    page_size: int = DEFAULT_PAGE,
) -> int:
    """Number of entries; raises ``AuditVerificationError`` on the first break. Without
    checkpoints this is the unkeyed chain check only, which cannot see a removed run or tail:
    use ``verify_team`` for that."""
    check_checkpoints(team_of(scope), checkpoints, verifier)
    return _verify_run(store, scope, run_id, checkpoints, page_size)


def _verify_run(
    store: Store,
    scope: Scope,
    run_id: RunId,
    checkpoints: Sequence[SignedCheckpoint],
    page_size: int = DEFAULT_PAGE,
) -> int:
    return verify_run_detail(store, scope, run_id, checkpoints, page_size)[0]


@dataclass(frozen=True)
class TeamVerification:
    counts: dict[str, int]
    uncovered: tuple[str, ...]  # runs verified as chains that no checkpoint names


def verify_team(
    store: Store,
    scope: Scope,
    run_ids: Iterable[RunId],
    *,
    checkpoints: Sequence[SignedCheckpoint],
    verifier: Verifier | None,
    allow_unanchored: bool = False,
    allow_uncovered: bool = False,
) -> TeamVerification:
    """Verify every run given and every run a checkpoint names, so a run left out of the list
    (or removed) is still checked. Signatures and teams are checked first, even with no runs.

    Without a checkpoint nothing can show that a run was not removed, so that is refused unless
    ``allow_unanchored``. A run that no checkpoint names (begun after the newest one) cannot be
    shown complete either: it is refused unless ``allow_uncovered``, and listed in ``uncovered``."""
    check_checkpoints(team_of(scope), checkpoints, verifier)
    if not checkpoints and not allow_unanchored:
        raise AuditVerificationError("no checkpoint to verify against")
    named = {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    ids = {str(r) for r in run_ids} | named
    counts = {
        run: _verify_run(store, scope, RunId.parse(run), checkpoints)  # signatures checked above
        for run in sorted(ids)
    }
    uncovered = tuple(sorted(ids - named))
    if uncovered and checkpoints and not allow_uncovered:
        raise AuditVerificationError(f"no checkpoint names run(s): {', '.join(uncovered)}")
    return TeamVerification(counts, uncovered)
