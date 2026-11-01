"""T14, tampered audit: the chain verifier and the tail-removal test (PLAN 18, STAGES D3-08)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from audit.helpers import (
    RUN,
    RUN2,
    TEAM,
    Recorder,
    append,
    audit_items,
    forged_copy,
    rechain,
    signer,
    subject,
    template_run,
)
from sto.audit.checkpoint import SignedCheckpoint, create_checkpoint
from sto.audit.errors import AuditVerificationError
from sto.audit.verify import verify_run, verify_team
from sto.domain import GateType
from sto.engine.commands import OpenGate
from sto.gates.hooks import ChainedAuditWriter, entry_hash
from sto.gates.service import GateService
from sto.store.memory import MemoryStore
from sto.store.ports import AUDIT, Absent, Key, Put, TeamScope, VersionIs

RUNS = [RUN, RUN2]
Entries = list[dict[str, Any]]
Forge = Callable[[Any, Entries], Entries]
World = tuple[MemoryStore, SignedCheckpoint, int]


@pytest.fixture
def world() -> World:
    rec = Recorder()
    service = GateService(rec, audit=ChainedAuditWriter())
    template_run(service, RUN)
    template_run(service, RUN2)
    cp = create_checkpoint(rec.inner, TEAM, signer(), RUNS, at=1_000, previous=[])
    return rec.inner, cp, len(audit_items(rec.inner, RUN))


def check(store: MemoryStore, *cps: SignedCheckpoint) -> dict[str, int]:
    return verify_team(store, TEAM, RUNS, checkpoints=list(cps), verifier=signer()).counts


def test_an_untouched_store_verifies(world: World) -> None:
    store, cp, n = world
    assert check(store, cp) == {str(RUN): n, str(RUN2): n}


def test_entries_added_after_a_checkpoint_still_verify(world: World) -> None:
    store, cp, n = world
    GateService(store, audit=ChainedAuditWriter()).open_gate(
        TEAM, OpenGate(RUN, "extra", GateType.REVIEW, 1, subject("z"))
    )
    assert check(store, cp)[str(RUN)] == n + 1


def edit_field(run: Any, entries: Entries) -> Entries:
    if run == RUN:
        entries[2] = {**entries[2], "actor": "mallory"}
    return entries


def reorder(run: Any, entries: Entries) -> Entries:
    if run == RUN:
        entries[1], entries[2] = entries[2], entries[1]
    return entries


def drop_tail(run: Any, entries: Entries) -> Entries:
    return entries[:-2] if run == RUN else entries


def drop_middle(run: Any, entries: Entries) -> Entries:
    return entries[:3] + entries[4:] if run == RUN else entries


def drop_run(run: Any, entries: Entries) -> Entries:
    return [] if run == RUN else entries


@pytest.mark.parametrize("rehash", [False, True], ids=["bare", "rechained"])
@pytest.mark.parametrize(
    "edit", [edit_field, reorder, drop_middle], ids=["edit", "reorder", "drop"]
)
def test_editing_reordering_or_dropping_inside_the_chain_fails(
    world: World, edit: Forge, rehash: bool
) -> None:
    store, cp, _ = world

    def forge(run: Any, entries: Entries) -> Entries:
        out = edit(run, entries)
        return rechain(out) if rehash else out

    with pytest.raises(AuditVerificationError):
        check(forged_copy(store, RUNS, forge), cp)


def test_a_consistent_forgery_is_caught_only_by_the_checkpoint(world: World) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, lambda r, e: rechain(edit_field(r, e)))
    assert verify_run(forged, TEAM, RUN) > 0  # the unkeyed chain alone is satisfied
    with pytest.raises(AuditVerificationError, match="checkpoint"):
        check(forged, cp)


@pytest.mark.parametrize("head", ["fixed", "none", "stale"])
def test_removing_a_tail_fails_against_a_checkpoint(world: World, head: str) -> None:
    store, cp, _ = world
    forged = forged_copy(
        store, RUNS, drop_tail, fix_head=head == "fixed", source_head=head == "stale"
    )
    if head == "fixed":
        assert verify_run(forged, TEAM, RUN) > 0  # a trimmed chain is itself well formed
    with pytest.raises(AuditVerificationError):
        check(forged, cp)


@pytest.mark.parametrize("head", ["fixed", "none", "stale"])
def test_removing_a_whole_run_fails_against_a_checkpoint(world: World, head: str) -> None:
    store, cp, _ = world
    forged = forged_copy(
        store, RUNS, drop_run, fix_head=head == "fixed", source_head=head == "stale"
    )
    if head != "stale":
        assert verify_run(forged, TEAM, RUN) == 0  # nothing there to contradict itself
    with pytest.raises(AuditVerificationError, match="missing|head"):
        check(forged, cp)


def test_a_run_dropped_from_the_checked_list_is_still_checked(world: World) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_run)
    with pytest.raises(AuditVerificationError):
        verify_team(forged, TEAM, [RUN2], checkpoints=[cp], verifier=signer())


# --- checkpoints: all of them are used ----------------------------------------------------------


def test_every_checkpoint_is_compared_not_only_the_first(world: World) -> None:
    store, cp1, n = world
    append(store, RUN, [1, 2, 3])
    cp2 = create_checkpoint(store, TEAM, signer(), RUNS, at=2_000, previous=[cp1])
    trimmed = forged_copy(store, RUNS, lambda r, e: e[: n + 1] if r == RUN else e)
    assert verify_run(trimmed, TEAM, RUN, checkpoints=[cp1], verifier=signer()) == n + 1
    for order in ([cp1, cp2], [cp2, cp1]):
        with pytest.raises(AuditVerificationError, match="fewer"):
            verify_run(trimmed, TEAM, RUN, checkpoints=order, verifier=signer())


def test_every_checkpoint_signature_is_checked_not_only_the_first(world: World) -> None:
    store, cp, _ = world
    bad = SignedCheckpoint(cp.checkpoint, cp.signature[:-2] + "AA")
    for order in ([cp, bad], [bad, cp]):
        with pytest.raises(AuditVerificationError, match="signature"):
            verify_team(store, TEAM, RUNS, checkpoints=order, verifier=signer())


def test_checkpoints_need_a_verifier(world: World) -> None:
    store, cp, _ = world
    with pytest.raises(AuditVerificationError, match="verifier"):
        verify_run(store, TEAM, RUN, checkpoints=[cp])
    with pytest.raises(AuditVerificationError, match="verifier"):
        verify_team(store, TEAM, RUNS, checkpoints=[cp], verifier=None)


def test_a_checkpoint_with_a_wrong_signature_is_refused(world: World) -> None:
    store, cp, _ = world
    with pytest.raises(AuditVerificationError, match="signature"):
        verify_team(store, TEAM, RUNS, checkpoints=[cp], verifier=signer("audit-cp-1", b"x" * 40))


def test_a_checkpoint_edited_to_fit_a_forgery_is_refused(world: World) -> None:
    store, cp, _ = world
    forged = forged_copy(store, RUNS, drop_tail)
    wire = cp.to_wire()
    wire["runs"][0]["count"] -= 2
    wire["runs"][0]["hash"] = "0" * 64
    with pytest.raises(AuditVerificationError, match="signature"):
        check(forged, SignedCheckpoint.from_wire(wire))


def foreign_checkpoint() -> SignedCheckpoint:
    rec = Recorder()
    other = TeamScope("t2")
    GateService(rec, audit=ChainedAuditWriter()).open_gate(
        other, OpenGate(RUN, "review", GateType.REVIEW, 1, subject())
    )
    cp = create_checkpoint(rec.inner, other, signer(), [RUN], at=1, previous=[])
    assert cp.is_signed_by(signer())  # genuinely signed, by the same key, for another team
    return cp


def test_a_validly_signed_checkpoint_of_another_team_is_refused(world: World) -> None:
    store, _, _ = world
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_team(store, TEAM, RUNS, checkpoints=[foreign_checkpoint()], verifier=signer())
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_run(store, TEAM, RUN, checkpoints=[foreign_checkpoint()], verifier=signer())


def test_signatures_are_checked_up_front_even_when_no_run_is_listed() -> None:
    empty_team = SignedCheckpoint(foreign_checkpoint().checkpoint.__class__("t9", 0, ()), "bad")
    with pytest.raises(AuditVerificationError):
        verify_team(MemoryStore(), TEAM, [], checkpoints=[empty_team], verifier=signer())
    empty = create_checkpoint(MemoryStore(), TeamScope("t2"), signer(), [], at=1, previous=[])
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_team(MemoryStore(), TEAM, [], checkpoints=[empty], verifier=signer())


# --- verify_team: nothing is anchored by omission -----------------------------------------------


def test_without_a_checkpoint_nothing_shows_a_run_was_not_removed(world: World) -> None:
    store, _, _ = world
    with pytest.raises(AuditVerificationError, match="no checkpoint"):
        verify_team(forged_copy(store, RUNS, drop_run), TEAM, RUNS, checkpoints=[], verifier=None)
    out = verify_team(store, TEAM, RUNS, checkpoints=[], verifier=None, allow_unanchored=True)
    assert set(out.uncovered) == {str(RUN), str(RUN2)}


def test_an_empty_store_is_not_a_verified_run() -> None:
    with pytest.raises(AuditVerificationError, match="no checkpoint"):
        verify_team(MemoryStore(), TEAM, [RUN], checkpoints=[], verifier=None)
    cp = create_checkpoint(MemoryStore(), TEAM, signer(), [], at=1, previous=[])
    with pytest.raises(AuditVerificationError, match="no checkpoint names"):
        verify_team(MemoryStore(), TEAM, [RUN], checkpoints=[cp], verifier=signer())


def test_a_run_begun_after_the_newest_checkpoint_is_reported_and_cannot_vanish_unseen() -> None:
    rec = Recorder()
    service = GateService(rec, audit=ChainedAuditWriter())
    template_run(service, RUN)
    cp = create_checkpoint(rec.inner, TEAM, signer(), [RUN], at=1, previous=[])
    template_run(service, RUN2)
    forged = forged_copy(rec.inner, RUNS, lambda r, e: [] if r == RUN2 else e)
    with pytest.raises(AuditVerificationError, match="no checkpoint names"):
        verify_team(forged, TEAM, RUNS, checkpoints=[cp], verifier=signer())
    seen = verify_team(
        rec.inner, TEAM, RUNS, checkpoints=[cp], verifier=signer(), allow_uncovered=True
    )
    assert seen.uncovered == (str(RUN2),)
    assert seen.counts[str(RUN2)] > 0


# --- the chain itself ---------------------------------------------------------------------------


def _with_body(entries: Entries, i: int, **change: Any) -> Entries:
    body = {k: v for k, v in entries[i].items() if k != "hash"}
    body.update(change)
    entries[i] = {**body, "hash": entry_hash(body)}
    return entries


def spliced(run: Any, entries: Entries) -> Entries:
    return _with_body(entries, 2, prev="f" * 64) if run == RUN else entries


def renumbered(run: Any, entries: Entries) -> Entries:
    return _with_body(entries, 2, seq=9) if run == RUN else entries


@pytest.mark.parametrize("forge", [spliced, renumbered], ids=["link", "seq"])
def test_a_broken_link_or_sequence_fails_even_with_a_valid_hash(world: World, forge: Forge) -> None:
    store, _, _ = world
    with pytest.raises(AuditVerificationError, match="sequence or link"):
        verify_run(forged_copy(store, RUNS, forge), TEAM, RUN)


def test_a_head_ahead_of_the_entries_fails_without_any_checkpoint(world: World) -> None:
    store, _, _ = world
    stale = forged_copy(store, RUNS, drop_tail, source_head=True)
    with pytest.raises(AuditVerificationError, match="head"):
        verify_run(stale, TEAM, RUN)


def test_a_head_with_the_right_seq_but_another_hash_fails(world: World) -> None:
    store, _, _ = world
    forged = forged_copy(store, RUNS, lambda _r, e: e)
    n = len(audit_items(store, RUN))
    forged.transact(TEAM, [Put(Key(f"RUN#{RUN}", "CHAIN"), {"seq": n, "hash": "0" * 64}, None)])
    with pytest.raises(AuditVerificationError, match="head does not match"):
        verify_run(forged, TEAM, RUN)


def test_entries_without_a_head_fail(world: World) -> None:
    store, _, _ = world
    with pytest.raises(AuditVerificationError, match="no chain head"):
        verify_run(forged_copy(store, RUNS, lambda _r, e: e, fix_head=False), TEAM, RUN)


def test_an_entry_moved_to_another_run_fails(world: World) -> None:
    store, _, _ = world
    forged = forged_copy(store, [RUN2], lambda _r, _e: audit_items(store, RUN))
    with pytest.raises(AuditVerificationError, match="run or team"):
        verify_run(forged, TEAM, RUN2)


def test_an_entry_moved_to_another_team_fails(world: World) -> None:
    store, _, _ = world
    other, moved = TeamScope("t2"), MemoryStore()
    for e in audit_items(store, RUN):
        moved.transact(other, [Put(Key(f"RUN#{RUN}", f"{e['seq']:012d}", AUDIT), e, Absent())])
    with pytest.raises(AuditVerificationError, match="run or team"):
        verify_run(moved, other, RUN)


def test_verification_pages_through_long_chains(world: World) -> None:
    store, _, n = world
    assert verify_run(store, TEAM, RUN, page_size=2) == n


# --- a gate that commits while we verify is not tampering ---------------------------------------


class Racy(MemoryStore):
    """Runs ``armed`` once, right after the chain head is read: the commit lands between the
    head read and the entry read."""

    armed: Callable[[], None] | None = None

    def get(self, scope: Any, key: Key) -> Any:
        item = super().get(scope, key)
        if key.sk == "CHAIN" and self.armed is not None:
            fn, self.armed = self.armed, None
            fn()
        return item


def racy_world() -> tuple[Racy, Callable[[], None]]:
    store = Racy()
    service = GateService(store, audit=ChainedAuditWriter())
    template_run(service, RUN)

    def commit() -> None:
        service.open_gate(TEAM, OpenGate(RUN, "live", GateType.REVIEW, 1, subject("q")))

    return store, commit


def test_a_commit_during_verification_is_not_a_tamper_alarm() -> None:
    store, commit = racy_world()
    n = len(audit_items(store, RUN))
    store.armed = commit
    assert verify_run(store, TEAM, RUN) == n  # the entry past the head we read is not examined
    assert verify_run(store, TEAM, RUN) == n + 1


def test_a_commit_during_create_checkpoint_does_not_abort_it() -> None:
    store, commit = racy_world()
    store.armed = commit
    cp = create_checkpoint(store, TEAM, signer(), [RUN], at=1, previous=[])
    assert cp.checkpoint.runs[0].count >= 8
    assert verify_run(store, TEAM, RUN, checkpoints=[cp], verifier=signer()) >= 8


def test_the_first_commit_landing_between_head_and_entries_is_not_tamper() -> None:
    store = Racy()
    service = GateService(store, audit=ChainedAuditWriter())

    def first() -> None:
        service.open_gate(TEAM, OpenGate(RUN, "first", GateType.REVIEW, 1, subject()))

    store.armed = first
    assert verify_run(store, TEAM, RUN) == 1


# --- entries past the head ----------------------------------------------------------------------


def _rolled_back(keep: int) -> MemoryStore:
    store = MemoryStore()
    append(store, RUN, [1, 2, 3, 4, 5, 6, 7, 8])
    entries = audit_items(store, RUN)
    old = store.get(TEAM, Key(f"RUN#{RUN}", "CHAIN"))
    assert old is not None
    last = entries[keep - 1]
    store.transact(
        TEAM,
        [Put(old.key, {"seq": last["seq"], "hash": last["hash"]}, VersionIs(old.version))],
    )
    return store


def test_a_head_rolled_back_behind_the_entries_fails_and_signs_nothing() -> None:
    store = _rolled_back(5)
    with pytest.raises(AuditVerificationError, match="past the chain head"):
        verify_run(store, TEAM, RUN)
    with pytest.raises(AuditVerificationError, match="past the chain head"):
        create_checkpoint(store, TEAM, signer(), [RUN], at=1, previous=[])


def test_a_junk_entry_past_the_head_is_not_clean() -> None:
    store = MemoryStore()
    append(store, RUN, [1, 2, 3])
    store.transact(TEAM, [Put(Key(f"RUN#{RUN}", f"{4:012d}", AUDIT), {"junk": "x"}, Absent())])
    with pytest.raises(AuditVerificationError, match="past the chain head"):
        verify_run(store, TEAM, RUN)


def test_a_head_with_the_right_hash_and_a_wrong_count_fails() -> None:
    store = MemoryStore()
    append(store, RUN, [1, 2, 3])
    entries = audit_items(store, RUN)
    old = store.get(TEAM, Key(f"RUN#{RUN}", "CHAIN"))
    assert old is not None
    store.transact(
        TEAM,
        [Put(old.key, {"seq": 4, "hash": entries[-1]["hash"]}, VersionIs(old.version))],
    )
    with pytest.raises(AuditVerificationError, match="head does not match"):
        verify_run(store, TEAM, RUN)


def test_a_commit_that_lands_after_the_head_read_is_still_not_a_false_alarm() -> None:
    """The entry past the head we read is genuine: the head moved on while we were looking."""
    store, commit = racy_world()
    n = len(audit_items(store, RUN))
    store.armed = commit
    assert verify_run(store, TEAM, RUN) == n


# --- signatures are checked once ----------------------------------------------------------------


def test_verify_team_checks_each_signature_once() -> None:
    class Counting:
        calls = 0

        def verify(self, message: bytes, signature: Any) -> bool:
            Counting.calls += 1
            return signer().verify(message, signature)

        def public_keys(self) -> list[Any]:
            return []

    from sto.domain import RunId

    store = MemoryStore()
    runs = [RunId.parse(f"01J0000000000000000000000{i}") for i in range(1, 6)]
    for r in runs:
        append(store, r, [1])
    cps = [create_checkpoint(store, TEAM, signer(), runs, at=i, previous=[]) for i in range(3)]
    verify_team(store, TEAM, runs, checkpoints=cps, verifier=Counting())
    assert Counting.calls == 3
