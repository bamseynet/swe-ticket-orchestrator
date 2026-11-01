"""T14, tampered audit: the chain verifier and the tail-removal test (PLAN 18, STAGES D3-08)."""

from __future__ import annotations

from typing import Any

import pytest

from audit.helpers import (
    RUN,
    RUN2,
    TEAM,
    Recorder,
    audit_items,
    forged_copy,
    rechain,
    signer,
    template_run,
)
from sto.audit.chain import AuditChainWriter
from sto.audit.checkpoint import SignedCheckpoint, create_checkpoint
from sto.audit.verify import AuditVerificationError, verify_run, verify_team
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import TeamScope

RUNS = [RUN, RUN2]


@pytest.fixture
def world() -> tuple[MemoryStore, SignedCheckpoint, int]:
    rec = Recorder()
    service = GateService(rec, audit=AuditChainWriter())
    template_run(service, RUN)
    template_run(service, RUN2)
    cp = create_checkpoint(rec.inner, TEAM, signer(), RUNS, at=1_000)
    return rec.inner, cp, len(audit_items(rec.inner, RUN))


def check(store: MemoryStore, cp: SignedCheckpoint) -> dict[str, int]:
    return verify_team(store, TEAM, RUNS, checkpoints=[cp], verifier=signer())


def test_an_untouched_store_verifies(world: tuple[MemoryStore, SignedCheckpoint, int]) -> None:
    store, cp, n = world
    assert check(store, cp) == {str(RUN): n, str(RUN2): n}


def test_entries_added_after_a_checkpoint_still_verify(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, cp, n = world
    from audit.helpers import subject
    from sto.domain import GateType
    from sto.engine.commands import OpenGate

    GateService(store, audit=AuditChainWriter()).open_gate(
        TEAM, OpenGate(RUN, "extra", GateType.REVIEW, 1, subject("z"))
    )
    assert check(store, cp)[str(RUN)] == n + 1


def edit_field(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if run != RUN:
        return entries
    entries[2] = {**entries[2], "actor": "mallory"}
    return entries


def reorder(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if run != RUN:
        return entries
    entries[1], entries[2] = entries[2], entries[1]
    return entries


def drop_tail(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return entries[:-2] if run == RUN else entries


def drop_middle(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return entries[:3] + entries[4:] if run == RUN else entries


def drop_run(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [] if run == RUN else entries


@pytest.mark.parametrize("rehash", [False, True], ids=["bare", "rechained"])
@pytest.mark.parametrize(
    "edit",
    [edit_field, reorder, drop_middle],
    ids=["edit", "reorder", "drop-middle"],
)
def test_editing_reordering_or_dropping_inside_the_chain_fails(
    world: tuple[MemoryStore, SignedCheckpoint, int], edit: Any, rehash: bool
) -> None:
    store, cp, _ = world

    def forge(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = edit(run, entries)
        return rechain(out) if rehash else out

    forged = forged_copy(store, RUNS, forge)
    with pytest.raises(AuditVerificationError):
        check(forged, cp)


def test_a_consistent_forgery_is_caught_only_by_the_checkpoint(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, cp, _ = world

    def forge(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return rechain(edit_field(run, entries))

    forged = forged_copy(store, RUNS, forge)
    assert verify_run(forged, TEAM, RUN) > 0  # the unkeyed chain alone is satisfied
    with pytest.raises(AuditVerificationError, match="checkpoint"):
        check(forged, cp)


@pytest.mark.parametrize("fix_head", [True, False], ids=["head-fixed", "head-left"])
def test_removing_a_tail_fails_against_a_checkpoint(
    world: tuple[MemoryStore, SignedCheckpoint, int], fix_head: bool
) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_tail, fix_head=fix_head)
    if fix_head:
        assert verify_run(forged, TEAM, RUN) > 0  # a trimmed chain is itself well formed
    with pytest.raises(AuditVerificationError):
        check(forged, cp)


@pytest.mark.parametrize("fix_head", [True, False], ids=["head-fixed", "head-left"])
def test_removing_a_whole_run_fails_against_a_checkpoint(
    world: tuple[MemoryStore, SignedCheckpoint, int], fix_head: bool
) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_run, fix_head=fix_head)
    assert verify_run(forged, TEAM, RUN) == 0  # nothing there to contradict itself
    with pytest.raises(AuditVerificationError, match="missing|removed|fewer"):
        check(forged, cp)


def test_a_run_dropped_from_the_checked_list_is_still_checked(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_run)
    with pytest.raises(AuditVerificationError):
        verify_team(forged, TEAM, [RUN2], checkpoints=[cp], verifier=signer())


def test_a_checkpoint_with_a_wrong_signature_is_refused(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, cp, _ = world
    with pytest.raises(AuditVerificationError, match="signature"):
        verify_team(store, TEAM, RUNS, checkpoints=[cp], verifier=signer("audit-cp-1", b"x" * 40))


def test_a_checkpoint_edited_to_fit_a_forgery_is_refused(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_tail)
    lowered = SignedCheckpoint(
        checkpoint=type(cp.checkpoint)(
            team=cp.checkpoint.team,
            at=cp.checkpoint.at,
            runs=tuple(
                type(h)(h.run_id, h.count - 2, "0" * 64) if h.run_id == str(RUN) else h
                for h in cp.checkpoint.runs
            ),
        ),
        signature=cp.signature,
    )
    with pytest.raises(AuditVerificationError, match="signature"):
        check(forged, lowered)


def test_a_checkpoint_of_another_team_is_refused(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, _, _ = world
    other = create_checkpoint(store, TEAM, signer(), RUNS, at=5)
    wrong = SignedCheckpoint(
        type(other.checkpoint)("t2", other.checkpoint.at, other.checkpoint.runs), other.signature
    )
    with pytest.raises(AuditVerificationError):
        verify_team(store, TEAM, RUNS, checkpoints=[wrong], verifier=signer())


def test_an_entry_moved_to_another_run_fails() -> None:
    rec = Recorder()
    service = GateService(rec, audit=AuditChainWriter())
    template_run(service, RUN)
    forged = forged_copy(rec.inner, [RUN2], lambda _r, _e: audit_items(rec.inner, RUN))
    with pytest.raises(AuditVerificationError, match="run or team"):
        verify_run(forged, TEAM, RUN2)


def test_an_entry_moved_to_another_team_fails() -> None:
    rec = Recorder()
    template_run(GateService(rec, audit=AuditChainWriter()), RUN)
    with pytest.raises(AuditVerificationError, match="run or team"):
        _verify_other_team(rec.inner)


def _verify_other_team(source: MemoryStore) -> None:
    from sto.store.ports import AUDIT, Absent, Key, Put

    other = TeamScope("t2")
    store = MemoryStore()
    for e in audit_items(source, RUN):
        store.transact(other, [Put(Key(f"RUN#{RUN}", f"{e['seq']:012d}", AUDIT), e, Absent())])
    verify_run(store, other, RUN)


def test_verification_pages_through_long_chains() -> None:
    rec = Recorder()
    template_run(GateService(rec, audit=AuditChainWriter()), RUN)
    n = len(audit_items(rec.inner, RUN))
    assert verify_run(rec.inner, TEAM, RUN, page_size=2) == n


def _spliced(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entry 3 gets a wrong ``prev`` but its own hash is recomputed, so only the link is off."""
    from sto.gates.hooks import entry_hash

    if run == RUN:
        body = {k: v for k, v in entries[2].items() if k != "hash"}
        body["prev"] = "f" * 64
        entries[2] = {**body, "hash": entry_hash(body)}
    return entries


def _renumbered(run: Any, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entry 3 claims seq 9 with a recomputed hash: only the sequence is off."""
    from sto.gates.hooks import entry_hash

    if run == RUN:
        body = {k: v for k, v in entries[2].items() if k != "hash"}
        body["seq"] = 9
        entries[2] = {**body, "hash": entry_hash(body)}
    return entries


@pytest.mark.parametrize("forge", [_spliced, _renumbered], ids=["link", "sequence"])
def test_a_broken_link_or_sequence_fails_even_with_a_valid_hash(
    world: tuple[MemoryStore, SignedCheckpoint, int], forge: Any
) -> None:
    store, _, _ = world
    with pytest.raises(AuditVerificationError, match="sequence or link"):
        verify_run(forged_copy(store, RUNS, forge), TEAM, RUN)


def test_a_head_that_disagrees_with_the_last_entry_fails_without_any_checkpoint(
    world: tuple[MemoryStore, SignedCheckpoint, int],
) -> None:
    store, _, _ = world
    stale_head = forged_copy(store, RUNS, drop_tail, fix_head=False)
    with pytest.raises(AuditVerificationError, match="head"):
        verify_run(stale_head, TEAM, RUN)


def test_a_validly_signed_checkpoint_of_another_team_is_refused() -> None:
    from sto.store.ports import TeamScope

    rec = Recorder()
    other = TeamScope("t2")
    from audit.helpers import subject
    from sto.domain import GateType
    from sto.engine.commands import OpenGate

    GateService(rec, audit=AuditChainWriter()).open_gate(
        other, OpenGate(RUN, "review", GateType.REVIEW, 1, subject())
    )
    cp = create_checkpoint(rec.inner, other, signer(), [RUN], at=1)
    assert cp.is_signed_by(signer())
    store = MemoryStore()
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_team(store, TEAM, [RUN], checkpoints=[cp], verifier=signer())
