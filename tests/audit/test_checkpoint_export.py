"""Signed checkpoints and the export with its offline verifier."""

from __future__ import annotations

import json

import pytest

from audit.helpers import RUN, RUN2, TEAM, Recorder, audit_items, signer, template_run
from sto.audit.chain import AuditChainWriter
from sto.audit.checkpoint import SignedCheckpoint, create_checkpoint
from sto.audit.export import export_team, verify_export
from sto.audit.verify import AuditVerificationError
from sto.gates.service import GateService
from sto.signing.port import Signature
from sto.store.memory import MemoryStore


def built() -> MemoryStore:
    rec = Recorder()
    service = GateService(rec, audit=AuditChainWriter())
    template_run(service, RUN)
    template_run(service, RUN2)
    return rec.inner


def test_checkpoint_records_count_and_head_per_run_and_round_trips() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=7)
    heads = {h.run_id: (h.count, h.hash) for h in cp.checkpoint.runs}
    last = audit_items(store, RUN)[-1]
    assert heads[str(RUN)] == (len(audit_items(store, RUN)), last["hash"])
    assert cp.checkpoint.team == "t1"
    assert cp.checkpoint.at == 7
    assert SignedCheckpoint.from_wire(json.loads(json.dumps(cp.to_wire()))) == cp
    assert Signature.decode(cp.signature).key_id == "audit-cp-1"


def test_checkpoint_signature_covers_every_field() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN], at=7)
    wire = cp.to_wire()
    for field, value in (("at", 8), ("team", "t2")):
        bad = SignedCheckpoint.from_wire({**wire, field: value})
        assert not bad.is_signed_by(signer())
    assert cp.is_signed_by(signer())


def test_checkpoint_signature_is_not_a_signature_over_other_audit_bytes() -> None:
    cp = create_checkpoint(built(), TEAM, signer(), [RUN], at=7)
    raw = json.dumps(cp.to_wire()["runs"]).encode()
    assert not signer().verify(raw, Signature.decode(cp.signature))


def test_a_new_checkpoint_carries_every_run_of_the_previous_one() -> None:
    store = built()
    first = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1)
    second = create_checkpoint(store, TEAM, signer(), [RUN], at=2, previous=[first])
    assert {h.run_id for h in second.checkpoint.runs} == {str(RUN), str(RUN2)}


def test_no_checkpoint_is_signed_over_a_store_that_lost_data_since_the_last() -> None:
    from audit.helpers import forged_copy

    store = built()
    first = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1)
    forged = forged_copy(store, [RUN, RUN2], lambda r, e: e[:-1] if r == RUN else e)
    with pytest.raises(AuditVerificationError):
        create_checkpoint(forged, TEAM, signer(), [RUN, RUN2], at=2, previous=[first])


def test_an_empty_run_is_not_listed() -> None:
    cp = create_checkpoint(built(), TEAM, signer(), [RUN, RUN2, RUN.__class__.new()], at=1)
    assert len(cp.checkpoint.runs) == 2


def test_export_verifies_offline_with_only_a_verifier() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1)
    doc = json.loads(json.dumps(export_team(store, TEAM, [RUN, RUN2], checkpoints=[cp])))
    counts = verify_export(doc, signer())
    assert counts == {
        str(RUN): len(audit_items(store, RUN)),
        str(RUN2): len(audit_items(store, RUN2)),
    }


def mutated(doc: dict, fn) -> dict:  # type: ignore[no-untyped-def,type-arg]
    copy: dict = json.loads(json.dumps(doc))  # type: ignore[type-arg]
    fn(copy)
    return copy


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["runs"][str(RUN)]["entries"][2].update(actor="mallory"),
        lambda d: d["runs"][str(RUN)]["entries"].reverse(),
        lambda d: d["runs"][str(RUN)]["entries"].pop(),
        lambda d: d["runs"].pop(str(RUN)),
        lambda d: d["checkpoints"][0]["runs"][0].update(count=1),
        lambda d: d["checkpoints"].clear(),
    ],
    ids=["edit", "reorder", "drop-tail", "drop-run", "edit-checkpoint", "drop-checkpoints"],
)
def test_tampered_exports_fail_verification(tamper) -> None:  # type: ignore[no-untyped-def]
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN, RUN2], at=1)
    doc = json.loads(json.dumps(export_team(store, TEAM, [RUN, RUN2], checkpoints=[cp])))
    with pytest.raises(AuditVerificationError):
        verify_export(mutated(doc, tamper), signer())


def test_export_of_a_period_verifies_from_its_anchor_and_must_be_allowed_to_be_partial() -> None:
    store = built()
    entries = audit_items(store, RUN)
    cp = create_checkpoint(store, TEAM, signer(), [RUN], at=1)
    lo, hi = entries[2]["at"], entries[5]["at"]
    doc = json.loads(
        json.dumps(export_team(store, TEAM, [RUN], checkpoints=[cp], since=lo, until=hi + 1))
    )
    part = doc["runs"][str(RUN)]["entries"]
    assert 0 < len(part) < len(entries)
    with pytest.raises(AuditVerificationError, match="partial|complete"):
        verify_export(doc, signer())
    assert verify_export(doc, signer(), require_complete=False)[str(RUN)] == len(part)


def test_a_complete_export_cannot_hide_its_first_entries_behind_an_anchor() -> None:
    store = built()
    cp = create_checkpoint(store, TEAM, signer(), [RUN], at=1)
    doc = json.loads(json.dumps(export_team(store, TEAM, [RUN], checkpoints=[cp])))
    run = doc["runs"][str(RUN)]
    first = run["entries"].pop(0)
    run["anchor"] = {"seq": first["seq"], "hash": first["hash"]}
    with pytest.raises(AuditVerificationError, match="beginning"):
        verify_export(doc, signer())
