"""Signed checkpoints and the export with its verifier."""

from __future__ import annotations

import json
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
    template_run,
)
from sto.audit.checkpoint import SignedCheckpoint, create_checkpoint
from sto.audit.errors import AuditVerificationError
from sto.audit.export import export_team, verify_export
from sto.gates.hooks import ChainedAuditWriter, entry_hash
from sto.gates.service import GateService
from sto.signing.port import Signature
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM

Wire = dict[str, Any]


def built() -> MemoryStore:
    rec = Recorder()
    service = GateService(rec, audit=ChainedAuditWriter())
    template_run(service, RUN)
    template_run(service, RUN2)
    return rec.inner


def jd(x: Any) -> Any:
    out: Any = json.loads(json.dumps(x))
    return out


# --- checkpoints --------------------------------------------------------------------------------


def test_checkpoint_records_count_and_head_per_run_and_round_trips() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=7, previous=[])
    heads = {h.run_id: (h.count, h.hash) for h in cp.checkpoint.runs}
    last = audit_items(store, RUN)[-1]
    assert heads[str(RUN)] == (len(audit_items(store, RUN)), last["hash"])
    assert cp.checkpoint.team == "t1"
    assert cp.checkpoint.at == 7
    assert SignedCheckpoint.from_wire(jd(cp.to_wire())) == cp
    assert Signature.decode(cp.signature).key_id == "audit-cp-1"


@pytest.mark.parametrize(
    "edit",
    [
        lambda w: w.update(at=8),
        lambda w: w.update(team="t2"),
        lambda w: w["runs"][0].update(hash="0" * 64),
        lambda w: w["runs"][0].update(count=1),
        lambda w: w["runs"][0].update(run=str(RUN2)),
        lambda w: w["runs"].pop(),
    ],
    ids=["at", "team", "hash", "count", "run", "run-dropped"],
)
def test_checkpoint_signature_covers_every_field(edit: Callable[[Wire], object]) -> None:
    cp = create_checkpoint(built(), TEAM, signer(), [RUN, RUN2], at=7, previous=[])
    assert cp.is_signed_by(signer())
    wire = jd(cp.to_wire())
    edit(wire)
    assert not SignedCheckpoint.from_wire(wire).is_signed_by(signer())


def test_checkpoint_signature_is_domain_separated() -> None:
    cp = create_checkpoint(built(), TEAM, signer(), [RUN], at=7, previous=[])
    bare = json.dumps(cp.checkpoint.to_wire(), sort_keys=True, separators=(",", ":")).encode()
    sig = Signature.decode(cp.signature)
    assert signer().verify(cp.checkpoint.payload(), sig)
    assert not signer().verify(bare, sig)  # the same bytes without the domain prefix
    assert not signer().verify(json.dumps(cp.to_wire()["runs"]).encode(), sig)


def test_a_malformed_signature_is_just_not_valid() -> None:
    cp = create_checkpoint(built(), TEAM, signer(), [RUN], at=7, previous=[])
    assert not SignedCheckpoint(cp.checkpoint, "not a signature").is_signed_by(signer())
    assert not SignedCheckpoint(cp.checkpoint, "").is_signed_by(signer())


def test_checkpoints_are_per_team_so_a_platform_scope_is_refused() -> None:
    with pytest.raises(ValueError, match="per team"):
        create_checkpoint(MemoryStore(), PLATFORM, signer(), [], at=1, previous=[])


@pytest.mark.parametrize(
    "wire",
    [{}, {"team": "t1"}, {"team": "t1", "at": "1", "runs": [], "signature": "s"},
     {"team": 1, "at": 1, "runs": [], "signature": "s"},
     {"team": "t1", "at": 1, "runs": [{"run": "nope", "count": 1, "hash": "h"}], "signature": "s"},
     {"team": "t1", "at": 1, "runs": [{"run": str(RUN), "count": 0, "hash": "h"}],
      "signature": "s"},
     {"team": "t1", "at": 1, "runs": None, "signature": "s"}],
)  # fmt: skip
def test_a_malformed_checkpoint_is_a_verification_error(wire: Wire) -> None:
    with pytest.raises(AuditVerificationError, match="malformed"):
        SignedCheckpoint.from_wire(wire)


def test_previous_is_required() -> None:
    with pytest.raises(TypeError):
        create_checkpoint(MemoryStore(), TEAM, signer(), [], at=1)  # type: ignore[call-arg]


def test_a_new_checkpoint_carries_every_run_of_the_previous_one() -> None:
    store = built()
    first = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    second = create_checkpoint(store, TEAM, signer(), [RUN], at=2, previous=[first])
    assert {h.run_id for h in second.checkpoint.runs} == {str(RUN), str(RUN2)}


def test_no_checkpoint_is_signed_over_a_store_that_lost_data_since_the_last() -> None:
    store = built()
    first = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    forged = forged_copy(store, [RUN, RUN2], lambda r, e: e[:-1] if r == RUN else e)
    with pytest.raises(AuditVerificationError):
        create_checkpoint(forged, TEAM, signer(), [RUN, RUN2], at=2, previous=[first])


def test_omitting_previous_cannot_bless_a_truncated_store_over_a_known_one() -> None:
    """With ``previous=[]`` nothing is compared, so the caller must hand over the real history;
    a checkpoint made that way still cannot hide a removal that an earlier one records."""
    store = built()
    first = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    forged = forged_copy(store, [RUN, RUN2], lambda r, e: e[:2] if r == RUN else e)
    blessed = create_checkpoint(forged, TEAM, signer(), [RUN], at=5, previous=[])
    with pytest.raises(AuditVerificationError):
        verify_export(
            jd(export_team(forged, TEAM, [RUN], checkpoints=[blessed])),
            signer(),
            team="t1",
            trusted=[first],
        )


def test_an_empty_run_is_not_listed() -> None:
    new = RUN.__class__.new()
    cp = create_checkpoint(built(), TEAM, signer(), [RUN, RUN2, new], at=1, previous=[])
    assert len(cp.checkpoint.runs) == 2


# --- exports ------------------------------------------------------------------------------------


class World:
    """A store with history: ``old`` covers RUN at its first shape, ``new`` covers more."""

    def __init__(self) -> None:
        rec = Recorder()
        self.service = GateService(rec, audit=ChainedAuditWriter())
        self.store = rec.inner
        template_run(self.service, RUN)
        self.n_old = len(audit_items(self.store, RUN))
        self.old = create_checkpoint(self.store, TEAM, signer(), [RUN], at=10, previous=[])
        template_run(self.service, RUN2)
        append(self.store, RUN, [1, 2, 3])  # RUN grows past `old`
        self.new = create_checkpoint(
            self.store, TEAM, signer(), [RUN, RUN2], at=20, previous=[self.old]
        )

    def doc(self, **kw: Any) -> Wire:
        kw.setdefault("checkpoints", [self.old, self.new])
        doc: Wire = jd(export_team(self.store, TEAM, [RUN, RUN2], **kw))
        return doc

    def verify(self, doc: Wire, **kw: Any) -> dict[str, int]:
        kw.setdefault("trusted", [self.new])
        return verify_export(doc, signer(), team="t1", **kw)


@pytest.fixture
def world() -> World:
    return World()


def test_a_complete_export_verifies_against_trusted_checkpoints(world: World) -> None:
    counts = world.verify(world.doc())
    assert counts == {
        str(RUN): len(audit_items(world.store, RUN)),
        str(RUN2): len(audit_items(world.store, RUN2)),
    }


def test_the_caller_must_say_what_to_trust(world: World) -> None:
    with pytest.raises(AuditVerificationError, match="trusted checkpoints or a minimum"):
        verify_export(world.doc(), signer(), team="t1")


def test_a_minimum_checkpoint_time_is_enough_trust_and_is_enforced(world: World) -> None:
    doc = world.doc()
    assert verify_export(doc, signer(), team="t1", min_checkpoint_at=20)
    with pytest.raises(AuditVerificationError, match="older"):
        verify_export(doc, signer(), team="t1", min_checkpoint_at=21)


def edit_actor(d: Wire) -> None:
    d["runs"][str(RUN)]["entries"][2]["actor"] = "mallory"


def reverse(d: Wire) -> None:
    d["runs"][str(RUN)]["entries"].reverse()


def drop_tail(d: Wire) -> None:
    d["runs"][str(RUN)]["entries"].pop()


def cut_run(d: Wire) -> None:
    del d["runs"][str(RUN)]["entries"][world_n_old(d) :]


def world_n_old(d: Wire) -> int:
    return 8  # the template run's entries before the first checkpoint


def drop_run(d: Wire) -> None:
    del d["runs"][str(RUN)]


def edit_checkpoint(d: Wire) -> None:
    d["checkpoints"][0]["runs"][0]["count"] = 1


@pytest.mark.parametrize(
    "tamper",
    [edit_actor, reverse, drop_tail, cut_run, drop_run, edit_checkpoint],
    ids=["edit", "reorder", "drop-tail", "cut-run", "drop-run", "edit-checkpoint"],
)
def test_tampered_exports_fail_verification(world: World, tamper: Callable[[Wire], None]) -> None:
    doc = world.doc()
    tamper(doc)
    with pytest.raises(AuditVerificationError):
        world.verify(doc)


def test_removing_the_newest_checkpoint_from_the_file_does_not_help(world: World) -> None:
    doc = world.doc()
    cut_run(doc)
    del doc["runs"][str(RUN2)]
    doc["checkpoints"] = [world.old.to_wire()]
    with pytest.raises(AuditVerificationError):  # trusted checkpoints still apply
        world.verify(doc)
    with pytest.raises(AuditVerificationError, match="older"):  # and so does a minimum time
        verify_export(doc, signer(), team="t1", min_checkpoint_at=20)


def test_a_replayed_empty_checkpoint_cannot_vouch_for_an_empty_export(world: World) -> None:
    empty = create_checkpoint(MemoryStore(), TEAM, signer(), [], at=0, previous=[])
    doc = {**world.doc(), "runs": {}, "checkpoints": [empty.to_wire()]}
    with pytest.raises(AuditVerificationError, match="older"):
        verify_export(doc, signer(), team="t1", min_checkpoint_at=20)
    with pytest.raises(AuditVerificationError, match="not in the export"):
        verify_export(doc, signer(), team="t1", trusted=[world.new])


def test_a_run_that_no_checkpoint_names_is_refused(world: World) -> None:
    other = "01J00000000000000000000009"
    forged = rechain(
        [{**e, "run": other, "actor": "framed"} for e in audit_items(world.store, RUN)]
    )
    doc = world.doc()
    doc["runs"][other] = {"anchor": None, "entries": forged}
    with pytest.raises(AuditVerificationError, match="no checkpoint names"):
        world.verify(doc)


def test_a_subset_is_not_complete_unless_the_caller_says_so(world: World) -> None:
    doc = world.doc()
    del doc["runs"][str(RUN2)]
    with pytest.raises(AuditVerificationError, match="not in the export"):
        world.verify(doc)
    assert world.verify(doc, all_runs=False) == {str(RUN): len(audit_items(world.store, RUN))}


def test_edits_past_the_newest_checkpoint_are_a_known_limit(world: World) -> None:
    """Documented in checkpoint.py: nothing signed covers entries after the newest count."""
    append(world.store, RUN, [1, 2])
    doc = jd(export_team(world.store, TEAM, [RUN, RUN2], checkpoints=[world.new]))
    entries = doc["runs"][str(RUN)]["entries"]
    entries[-1]["actor"] = "framed"
    doc["runs"][str(RUN)]["entries"] = rechain(entries)
    assert world.verify(doc)  # passes: the checkpoint cannot see past its own count


# --- partial exports ----------------------------------------------------------------------------


def seeded(ats: list[int], *, at: int = 50) -> tuple[MemoryStore, SignedCheckpoint]:
    store = MemoryStore()
    append(store, RUN, ats)
    return store, create_checkpoint(store, TEAM, signer(), [RUN], at=at, previous=[])


def rechain_from(entries: list[Wire], seq0: int, prev: str) -> list[Wire]:
    out = []
    for n, e in enumerate(entries, start=seq0 + 1):
        body = {k: v for k, v in e.items() if k != "hash"}
        body["seq"], body["prev"] = n, prev
        prev = entry_hash(body)
        out.append({**body, "hash": prev})
    return out


def part(doc: Wire, **kw: Any) -> dict[str, int]:
    kw = {"trusted": [], "from_start": False, **kw}
    return verify_export(doc, signer(), team="t1", **kw)


def test_a_range_ending_at_the_tip_verifies_from_its_anchor() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    assert [e["seq"] for e in doc["runs"][str(RUN)]["entries"]] == [3, 4, 5, 6]
    assert doc["runs"][str(RUN)]["anchor"]["seq"] == 2
    assert part(doc, trusted=[cp], since=300) == {str(RUN): 4}
    with pytest.raises(AuditVerificationError, match="beginning"):
        part(doc, trusted=[cp], from_start=True)


def test_a_range_between_checkpoints_is_refused_unless_the_caller_accepts_it() -> None:
    store, cp = seeded([100, 200, 300, 400, 500])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=200, until=400))
    assert [e["seq"] for e in doc["runs"][str(RUN)]["entries"]] == [2, 3]
    with pytest.raises(AuditVerificationError, match="no checkpoint count falls"):
        part(doc, trusted=[cp], to_tip=False)
    assert part(doc, trusted=[cp], to_tip=False, allow_unchecked_range=True) == {str(RUN): 2}
    with pytest.raises(AuditVerificationError, match="fewer"):
        part(doc, trusted=[cp], allow_unchecked_range=True)  # to_tip defaults to True


def test_the_range_bounds_are_since_inclusive_and_until_exclusive() -> None:
    store, cp = seeded([100, 200, 300, 400])
    cases = [(200, 400, [2, 3]), (201, 400, [3]), (200, 300, [2]), (None, 200, [1])]
    for since, until, want in cases:
        doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=since, until=until))
        assert [e["seq"] for e in doc["runs"][str(RUN)]["entries"]] == want, (since, until)
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=500))
    assert doc["runs"][str(RUN)]["entries"] == []


def test_a_quiet_run_is_anchored_at_its_last_entry_and_an_honest_since_export_verifies() -> None:
    store = MemoryStore()
    append(store, RUN, [100, 200, 300, 400, 500, 600, 700, 800])
    append(store, RUN2, [10, 20])
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    doc = jd(export_team(store, TEAM, [RUN, RUN2], checkpoints=[cp], since=300))
    quiet = doc["runs"][str(RUN2)]
    assert quiet["entries"] == []
    assert quiet["anchor"]["seq"] == 2
    assert part(doc, trusted=[cp], since=300) == {str(RUN): 6, str(RUN2): 0}


def test_an_anchor_with_no_entries_is_compared_with_the_checkpoint() -> None:
    store, cp = seeded([100, 200, 300])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=1000))
    assert doc["runs"][str(RUN)]["entries"] == []
    assert part(doc, trusted=[cp], since=1000) == {str(RUN): 0}
    anchor = doc["runs"][str(RUN)]["anchor"]
    body = {k: v for k, v in anchor.items() if k != "hash"} | {"actor": "framed"}
    doc["runs"][str(RUN)]["anchor"] = {**body, "hash": entry_hash(body)}  # a valid entry, not ours
    with pytest.raises(AuditVerificationError, match="differs from the checkpoint"):
        part(doc, trusted=[cp], since=1000)


def test_a_skewed_clock_gives_one_contiguous_range_that_verifies() -> None:
    store, cp = seeded([100, 200, 150, 300])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=180))
    assert [e["seq"] for e in doc["runs"][str(RUN)]["entries"]] == [2, 3, 4]
    assert part(doc, trusted=[cp], since=180)[str(RUN)] == 3
    mid = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=120, until=180))
    assert [e["seq"] for e in mid["runs"][str(RUN)]["entries"]] == [2, 3]


def fabricate(entries: list[Wire], seq0: int, prev: str) -> list[Wire]:
    return rechain_from([{**e, "actor": "framed"} for e in entries], seq0, prev)


def test_a_forged_range_from_the_real_anchor_fails_at_the_checkpointed_tip() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    run = doc["runs"][str(RUN)]
    run["entries"] = fabricate(run["entries"], run["anchor"]["seq"], run["anchor"]["hash"])
    with pytest.raises(AuditVerificationError, match="differs from the checkpoint"):
        part(doc, trusted=[cp])


def test_a_range_fabricated_behind_an_invented_anchor_compares_nothing_and_is_refused() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600, 700, 800])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    run = doc["runs"][str(RUN)]
    first = {k: v for k, v in run["entries"][0].items() if k != "hash"}
    body = {**first, "seq": 100, "actor": "framed", "prev": "a" * 64}
    run["anchor"] = {**body, "hash": entry_hash(body)}
    run["entries"] = fabricate(run["entries"][:6], 100, run["anchor"]["hash"])
    with pytest.raises(AuditVerificationError, match="no checkpoint count falls"):
        part(doc, trusted=[cp])
    assert part(doc, trusted=[cp], allow_unchecked_range=True, to_tip=False)  # only by opting in


def test_an_empty_range_behind_an_invented_anchor_is_refused() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=1000))
    run = doc["runs"][str(RUN)]
    body = {k: v for k, v in run["anchor"].items() if k != "hash"} | {"seq": 3, "prev": "b" * 64}
    run["anchor"] = {**body, "hash": entry_hash(body)}
    with pytest.raises(AuditVerificationError, match="fewer"):
        part(doc, trusted=[cp])
    with pytest.raises(AuditVerificationError, match="no checkpoint count falls"):
        part(doc, trusted=[cp], to_tip=False)


def test_a_range_that_lost_its_tail_fails_when_it_must_reach_the_tip() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    doc["runs"][str(RUN)]["entries"].pop()
    with pytest.raises(AuditVerificationError, match="fewer"):
        part(doc, trusted=[cp])


def test_the_caller_not_the_file_says_what_range_was_asked_for() -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    with pytest.raises(AuditVerificationError, match="anchor is not before"):
        part(doc, trusted=[cp], since=200)  # anchor is the entry at 200
    with pytest.raises(AuditVerificationError, match="starts before"):
        part(doc, trusted=[cp], since=400)
    bounded = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=200, until=400))
    with pytest.raises(AuditVerificationError, match="past the range"):
        part(bounded, trusted=[cp], until=300, to_tip=False, allow_unchecked_range=True)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda a: a.update(seq=0),
        lambda a: a.update(seq="2"),
        lambda a: a.update(seq=-3),
        lambda a: a.update(actor="framed"),  # hash no longer matches
        lambda a: a.update(run="01J00000000000000000000009"),
        lambda a: a.update(team="t2"),
        lambda a: a.pop("prev"),
        lambda a: a.clear(),
    ],
)
def test_a_malformed_or_forged_anchor_is_refused(mangle: Callable[[Wire], object]) -> None:
    store, cp = seeded([100, 200, 300, 400, 500, 600])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=300))
    mangle(doc["runs"][str(RUN)]["anchor"])
    with pytest.raises(AuditVerificationError):
        part(doc, trusted=[cp])


def test_checkpoint_runs_are_exported_even_when_not_asked_for() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    doc = export_team(store, TEAM, [RUN], checkpoints=[cp])
    assert set(doc["runs"]) == {str(RUN), str(RUN2)}


def test_an_export_is_checked_for_the_callers_team_not_the_files() -> None:
    from sto.store.ports import TeamScope

    t2 = TeamScope("t2")
    store = MemoryStore()
    append(store, RUN, [1, 2], scope=t2)
    cp2 = create_checkpoint(store, t2, signer(), [RUN], at=9, previous=[])
    doc = jd(export_team(store, t2, [RUN], checkpoints=[cp2]))
    assert verify_export(doc, signer(), team="t2", min_checkpoint_at=5) == {str(RUN): 2}
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_export(doc, signer(), team="t1", min_checkpoint_at=5)  # same key, wrong auditor
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_export({**doc, "team": "t1"}, signer(), team="t2", min_checkpoint_at=5)
    with pytest.raises(TypeError):
        verify_export(doc, signer(), min_checkpoint_at=5)  # type: ignore[call-arg]


def test_run_keys_that_fold_to_the_same_run_are_refused() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    doc = jd(export_team(store, TEAM, [RUN, RUN2], checkpoints=[cp]))
    doc["runs"][str(RUN).lower()] = doc["runs"][str(RUN)]
    assert str(RUN).lower() != str(RUN)
    with pytest.raises(AuditVerificationError, match="malformed"):
        verify_export(doc, signer(), team="t1", trusted=[cp])


# --- every checkpoint, signature and team is checked --------------------------------------------


def test_every_embedded_and_trusted_checkpoint_must_be_signed_and_ours(world: World) -> None:
    bad = SignedCheckpoint(world.old.checkpoint, world.new.signature)  # second one is the bad one
    doc = world.doc(checkpoints=[world.new, bad])
    with pytest.raises(AuditVerificationError, match="signature"):
        world.verify(doc)
    with pytest.raises(AuditVerificationError, match="signature"):
        verify_export(world.doc(), signer(), team="t1", trusted=[world.new, bad])


def test_a_signed_checkpoint_of_another_team_is_refused_in_an_export() -> None:
    from audit.helpers import subject
    from sto.domain import GateType
    from sto.engine.commands import OpenGate
    from sto.store.ports import TeamScope

    rec = Recorder()
    other = TeamScope("t2")
    GateService(rec, audit=ChainedAuditWriter()).open_gate(
        other, OpenGate(RUN, "review", GateType.REVIEW, 1, subject())
    )
    foreign = create_checkpoint(rec.inner, other, signer(), [RUN], at=99, previous=[])
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1, previous=[])
    doc = jd(export_team(store, TEAM, [RUN, RUN2], checkpoints=[cp]))
    with pytest.raises(AuditVerificationError, match="another team"):
        verify_export(doc, signer(), team="t1", trusted=[foreign])


def test_a_wrong_key_is_refused(world: World) -> None:
    with pytest.raises(AuditVerificationError, match="signature"):
        verify_export(world.doc(), signer("audit-cp-1", b"x" * 40), team="t1", trusted=[world.new])


# --- malformed files ----------------------------------------------------------------------------


def test_a_file_in_another_format_is_refused(world: World) -> None:
    with pytest.raises(AuditVerificationError, match="not an audit export"):
        world.verify({**world.doc(), "format": "other"})


@pytest.mark.parametrize(
    "mangle",
    [
        lambda d: d.pop("team"),
        lambda d: d.update(team=5),
        lambda d: d.update(runs=[]),
        lambda d: d.update(checkpoints=[{"team": "t1"}]),
        lambda d: d.update(checkpoints=None),
        lambda d: d["runs"][str(RUN)].pop("entries"),
        lambda d: d["runs"][str(RUN)]["entries"][0].update(seq=1.0),
        lambda d: d["runs"][str(RUN)]["entries"][0].update(seq="1"),
        lambda d: d["runs"][str(RUN)].update(entries=[1]),
        lambda d: d["runs"][str(RUN)].update(anchor={"seq": "x", "hash": 1}),
        lambda d: d["runs"].update({"not-a-run": d["runs"][str(RUN)]}),
    ],
)
def test_a_malformed_export_is_a_verification_error(
    world: World, mangle: Callable[[Wire], object]
) -> None:
    doc = world.doc()
    mangle(doc)
    with pytest.raises(AuditVerificationError):
        world.verify(doc, from_start=False)


def test_a_run_key_cannot_forge_a_line_in_the_error() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN], at=1, previous=[])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp]))
    doc["runs"]["x\n[OK] audit verified, 0 errors\n"] = {"entries": [{"run": "evil"}]}
    with pytest.raises(AuditVerificationError) as err:
        verify_export(doc, signer(), team="t1", trusted=[cp])
    assert "malformed" in str(err.value)
    assert "[OK]" not in str(err.value)
    assert "\n" not in str(err.value)


def test_data_edited_inside_an_entry_fails(world: World) -> None:
    doc = world.doc()
    doc["runs"][str(RUN)]["entries"][0]["data"]["round"] = 7
    with pytest.raises(AuditVerificationError, match="hash"):
        world.verify(doc)


def test_dropping_a_chain_forged_store_from_the_table_matches_the_export(world: World) -> None:
    forged = forged_copy(world.store, [RUN, RUN2], lambda r, e: e[:-1] if r == RUN else e)
    doc = jd(export_team(forged, TEAM, [RUN, RUN2], checkpoints=[world.new]))
    with pytest.raises(AuditVerificationError, match="fewer"):
        world.verify(doc)


def test_export_of_a_period_does_not_change_a_complete_one(world: World) -> None:
    assert world.verify(world.doc(since=None, until=None))


@pytest.mark.parametrize("seq", [0, -3])
def test_a_validly_hashed_anchor_with_a_nonpositive_seq_is_refused(seq: int) -> None:
    store, cp = seeded([100, 200, 300])
    doc = jd(export_team(store, TEAM, [RUN], checkpoints=[cp], since=1000))
    run = doc["runs"][str(RUN)]
    body = {k: v for k, v in run["anchor"].items() if k != "hash"} | {"seq": seq}
    run["anchor"] = {**body, "hash": entry_hash(body)}
    with pytest.raises(AuditVerificationError, match="malformed"):
        part(doc, trusted=[cp], to_tip=False, allow_unchecked_range=True)
