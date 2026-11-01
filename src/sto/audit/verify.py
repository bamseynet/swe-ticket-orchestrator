"""The verifier: the chain on its own, then against signed checkpoints (T14)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sto.audit.checkpoint import SignedCheckpoint
from sto.audit.port import DEFAULT_PAGE, StoreAuditLog
from sto.domain import RunId
from sto.gates.hooks import GENESIS_HASH, entry_hash
from sto.signing.port import Verifier
from sto.store.ports import Scope, Store, TeamScope


class AuditVerificationError(ValueError):
    """The audit log does not match its own chain or a signed checkpoint."""


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
        if body.get("seq") != n or body.get("prev") != prev:
            raise AuditVerificationError(f"audit chain broken at {where}: sequence or link")
        if entry_hash(body) != item.get("hash"):
            raise AuditVerificationError(f"audit chain broken at {where}: hash mismatch")
        prev = str(item["hash"])
        out.append((n, prev))
    return out


def _walk(store: Store, scope: Scope, run_id: RunId, page_size: int) -> list[tuple[int, str]]:
    """Verify a run's chain and its head item; return ``(seq, hash)`` for each entry."""
    log = StoreAuditLog(store, page_size=page_size)
    walked = check_entries(log.entries(scope, run_id), str(run_id), team_of(scope))
    count, last = walked[-1] if walked else (0, GENESIS_HASH)
    head = log.head(scope, run_id)
    if (head is None) != (count == 0) or (
        head is not None and (head.seq, head.hash) != (count, last)
    ):
        raise AuditVerificationError(
            f"audit chain broken for run {run_id}: head does not match the last entry"
        )
    return walked


def walk_run(
    store: Store, scope: Scope, run_id: RunId, *, page_size: int = DEFAULT_PAGE
) -> tuple[int, str]:
    """Verify a run's chain and head. Returns ``(count, last hash)``."""
    walked = _walk(store, scope, run_id, page_size)
    return walked[-1] if walked else (0, GENESIS_HASH)


def check_checkpoint_signatures(
    scope_team: str, checkpoints: Sequence[SignedCheckpoint], verifier: Verifier | None
) -> None:
    if checkpoints and verifier is None:
        raise AuditVerificationError("a verifier is needed to check checkpoints")
    for cp in checkpoints:
        if verifier is not None and not cp.is_signed_by(verifier):
            raise AuditVerificationError("checkpoint signature does not verify")
        if cp.checkpoint.team != scope_team:
            raise AuditVerificationError("checkpoint belongs to another team")


def check_against_checkpoints(
    run_id: str, hashes: Mapping[int, str], count: int, checkpoints: Sequence[SignedCheckpoint]
) -> None:
    for cp in checkpoints:
        for head in cp.checkpoint.runs:
            if head.run_id != run_id:
                continue
            if count < head.count:
                kind = "missing" if count == 0 else "fewer entries than"
                raise AuditVerificationError(
                    f"run {run_id} is {kind} its checkpoint: {count} entries, "
                    f"checkpoint at {cp.checkpoint.at} has {head.count}"
                )
            if hashes.get(head.count) != head.hash:
                raise AuditVerificationError(
                    f"run {run_id} differs from the checkpoint at {cp.checkpoint.at}: "
                    f"entry {head.count} has another hash"
                )


def verify_run(
    store: Store,
    scope: Scope,
    run_id: RunId,
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    verifier: Verifier | None = None,
    page_size: int = DEFAULT_PAGE,
) -> int:
    """Number of entries; raises ``AuditVerificationError`` on the first break."""
    check_checkpoint_signatures(team_of(scope), checkpoints, verifier)
    walked = _walk(store, scope, run_id, page_size)
    count = walked[-1][0] if walked else 0
    check_against_checkpoints(str(run_id), dict(walked), count, checkpoints)
    return count


def verify_team(
    store: Store,
    scope: Scope,
    run_ids: Iterable[RunId],
    *,
    checkpoints: Sequence[SignedCheckpoint] = (),
    verifier: Verifier | None = None,
) -> dict[str, int]:
    """Verify every run given and every run a checkpoint names, so a run left out of the list
    (or removed) is still checked."""
    ids = {str(r) for r in run_ids} | {h.run_id for c in checkpoints for h in c.checkpoint.runs}
    return {
        run: verify_run(store, scope, RunId.parse(run), checkpoints=checkpoints, verifier=verifier)
        for run in sorted(ids)
    }
