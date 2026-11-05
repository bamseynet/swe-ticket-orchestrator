"""Subject and rounds (D2-08, PLAN 4): digests, patch_id, ticket_revision, rounds, interdiffs."""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from sto.domain import GateId, GateType, PermanentError, Subject, from_wire, to_wire
from sto.gates.evidence import OLDER_BASE_NOTE, Evidence, Validity, Verdict, check_all
from sto.gates.subject import (
    AttentionItems,
    EvidenceInvalidError,
    GateRoundError,
    IncompleteEvidenceError,
    MergedCodeChangedError,
    RoundRecord,
    StoredEvidence,
    TicketFields,
    attention_digest,
    evidence_digest,
    patch_id,
    plan_round,
    ticket_fields,
    ticket_revision,
    validate_verdict,
    verdict_from_data,
    verdict_to_data,
)
from sto.store.ports import canonical_data

HEAD = "a" * 40
HEAD2 = "b" * 40
BASE = "c" * 40
MERGE = "d" * 40
EXTRA = "e" * 40

DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -10,3 +10,4 @@ def main():
     a = 1
+    b = 2
     return a
"""

# The same change replayed on a newer base: other line numbers, other blob ids and other context
# line numbers in the hunk header, same added line.
DIFF_NEW_BASE = """\
diff --git a/app.py b/app.py
index 3333333..4444444 100644
--- a/app.py
+++ b/app.py
@@ -42,3 +42,4 @@ def main():
     a = 1
+    b = 2
     return a
"""

DIFF_WS = DIFF.replace("+    b = 2", "+    b  = 2")
DIFF_RETAB = DIFF.replace("+    b = 2", "+\tb = 2")


def head_subject(**kw: object) -> Subject:
    base: dict[str, object] = {
        "patch_id": "p1",
        "ticket_revision": "t1",
        "head_sha": HEAD,
        "evidence_digest": evidence_digest(()),
        "attention_digest": attention_digest(AttentionItems()),
    }
    base.update(kw)
    return Subject(**base)  # type: ignore[arg-type]


# --- patch_id ---------------------------------------------------------------------------------


def test_same_diff_on_a_new_base_gives_the_same_patch_id() -> None:
    assert patch_id(DIFF) == patch_id(DIFF_NEW_BASE)


def test_patch_id_is_a_git_patch_id_hex_digest() -> None:
    pid = patch_id(DIFF)
    assert len(pid) == 40
    assert set(pid) <= set("0123456789abcdef")


def test_whitespace_only_change_gives_a_different_patch_id() -> None:
    assert patch_id(DIFF_WS) != patch_id(DIFF)
    assert patch_id(DIFF_RETAB) != patch_id(DIFF)


def test_a_different_change_gives_a_different_patch_id() -> None:
    assert patch_id(DIFF.replace("b = 2", "b = 3")) != patch_id(DIFF)


@pytest.mark.parametrize("diff", ["", "\n", "not a diff at all\n"])
def test_a_diff_with_no_patch_is_refused(diff: str) -> None:
    with pytest.raises(ValueError, match="no patch"):
        patch_id(diff)


def test_patch_id_wants_text() -> None:
    with pytest.raises(TypeError):
        patch_id(b"x")  # type: ignore[arg-type]


# --- ticket_revision --------------------------------------------------------------------------


def fields(**kw: object) -> TicketFields:
    base: dict[str, object] = {
        "summary": "Fix login",
        "description": "Users cannot log in.",
        "acceptance_criteria": ("works", "is fast"),
        "route_inputs": {"risk": "High"},
    }
    base.update(kw)
    return TicketFields(**base)  # type: ignore[arg-type]


def test_our_own_comments_and_transitions_do_not_change_ticket_revision() -> None:
    ticket = {
        "summary": "Fix login",
        "description": "Users cannot log in.",
        "acceptance_criteria": ["works", "is fast"],
        "route_inputs": {"risk": "High"},
    }
    noisy = {
        **ticket,
        "comments": [{"author": "sto-bot", "body": "I opened a PR"}],
        "status": "In Review",
        "transitions": ["To Do", "In Review"],
        "updated": "2026-11-05T00:00:00Z",
    }
    assert ticket_revision(ticket_fields(noisy)) == ticket_revision(ticket_fields(ticket))


@pytest.mark.parametrize(
    "change",
    [
        {"summary": "Fix logout"},
        {"description": "Users cannot log out."},
        {"acceptance_criteria": ("works",)},
        {"acceptance_criteria": ("is fast", "works")},
        {"route_inputs": {"risk": "Low"}},
        {"route_inputs": {"risk": "High", "area": "auth"}},
    ],
)
def test_edits_to_the_named_fields_change_ticket_revision(change: dict[str, object]) -> None:
    assert ticket_revision(fields(**change)) != ticket_revision(fields())


def test_ticket_revision_normalises_text() -> None:
    a = fields(summary="Fix login", description="line one\nline two")
    b = fields(summary="  Fix login \r\n", description="line one  \r\nline two\n")
    assert ticket_revision(a) == ticket_revision(b)
    # a unicode composition difference is not an edit
    assert ticket_revision(fields(summary="café")) == ticket_revision(fields(summary="café"))


def test_route_input_order_does_not_matter_but_values_do() -> None:
    a = fields(route_inputs={"risk": "High", "area": "auth"})
    b = fields(route_inputs={"area": "auth", "risk": "High"})
    assert ticket_revision(a) == ticket_revision(b)


def test_ticket_fields_missing_a_named_field_is_refused() -> None:
    with pytest.raises(ValueError, match="summary"):
        ticket_fields({"description": "d", "acceptance_criteria": [], "route_inputs": {}})


def test_ticket_fields_types_are_checked() -> None:
    with pytest.raises(TypeError):
        TicketFields(summary=1, description="d", acceptance_criteria=(), route_inputs={})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        fields(acceptance_criteria="one string")
    with pytest.raises(TypeError):
        fields(route_inputs={"risk": 3})


def test_ticket_revision_is_a_canonical_data_hash() -> None:
    body = {
        "v": 1,
        "summary": "Fix login",
        "description": "Users cannot log in.",
        "acceptance_criteria": ["works", "is fast"],
        "route_inputs": {"risk": "High"},
    }
    blob = json.dumps(canonical_data(body), sort_keys=True, separators=(",", ":"))
    assert ticket_revision(fields()) == hashlib.sha256(blob.encode()).hexdigest()


# --- attention_digest -------------------------------------------------------------------------


def test_attention_digest_ignores_order_and_duplicates() -> None:
    a = AttentionItems(failed_reviewers=("sec", "perf"), red_checks=("lint",))
    b = AttentionItems(failed_reviewers=("perf", "sec", "perf"), red_checks=("lint",))
    assert attention_digest(a) == attention_digest(b)


@pytest.mark.parametrize(
    "items",
    [
        AttentionItems(failed_reviewers=("sec",)),
        AttentionItems(blocking_findings=("sec",)),
        AttentionItems(unverified_criteria=("sec",)),
        AttentionItems(red_checks=("sec",)),
    ],
)
def test_attention_digest_separates_the_categories(items: AttentionItems) -> None:
    others = [
        AttentionItems(),
        AttentionItems(failed_reviewers=("sec",)),
        AttentionItems(blocking_findings=("sec",)),
        AttentionItems(unverified_criteria=("sec",)),
        AttentionItems(red_checks=("sec",)),
    ]
    digests = {attention_digest(o) for o in others}
    assert len(digests) == 5
    assert attention_digest(items) in digests


def test_a_new_attention_item_changes_the_digest() -> None:
    base = AttentionItems(red_checks=("lint",))
    more = AttentionItems(red_checks=("lint", "mypy"))
    assert attention_digest(base) != attention_digest(more)


def test_attention_items_must_be_plain_nonblank_strings() -> None:
    with pytest.raises(TypeError):
        AttentionItems(red_checks="lint")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="blank"):
        AttentionItems(red_checks=(" ",))
    with pytest.raises(TypeError):
        AttentionItems(red_checks=(1,))  # type: ignore[arg-type]


# --- evidence: stored refs, verdict validation, digest ----------------------------------------


def ev(validity: Validity = Validity.SAME_PATCH, **kw: object) -> Evidence:
    base: dict[str, object] = {"tested_sha": HEAD, "patch_id": "p1", "validity": validity}
    base.update(kw)
    return Evidence(**base)  # type: ignore[arg-type]


def test_stored_evidence_extends_evidence_with_artifact_refs() -> None:
    stored = StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=("s3://b/report",))
    assert isinstance(stored, Evidence)
    wire = to_wire(stored)
    assert wire["artifact_refs"] == ["s3://b/report"]
    assert from_wire(StoredEvidence, wire) == stored
    assert from_wire(StoredEvidence, canonical_data(wire)) == stored


def test_plain_evidence_still_rejects_artifact_refs() -> None:
    wire = to_wire(StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=("r",)))
    with pytest.raises(ValueError, match="unexpected fields"):
        from_wire(Evidence, wire)


def test_artifact_refs_are_checked() -> None:
    with pytest.raises(TypeError):
        StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs="one")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="blank"):
        StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=("",))
    with pytest.raises(TypeError):
        StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=(1,))  # type: ignore[arg-type]


def test_from_wire_accepts_a_string_valid_but_validation_refuses_it() -> None:
    wire = to_wire(Verdict(ev(), True))
    wire["valid"] = "false"
    loaded = from_wire(Verdict, wire)  # the generic decoder lets it through ...
    with pytest.raises(TypeError, match="valid"):
        validate_verdict(loaded)  # ... so a persisted verdict is validated


def test_verdict_round_trips_through_stored_data() -> None:
    v = Verdict(
        StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=("r1",)),
        False,
        "tested a, but the subject head is b",
        ("n",),
    )
    data = verdict_to_data(v)
    assert data == canonical_data(data)
    assert verdict_from_data(data) == v


def test_verdict_from_data_validates() -> None:
    data = verdict_to_data(Verdict(ev(), True))
    for bad in ({"valid": "false"}, {"valid": 1}, {"notes": "a note"}, {"reason": 3}):
        with pytest.raises(TypeError):
            verdict_from_data({**data, **bad})


def test_verdict_to_data_validates() -> None:
    with pytest.raises(TypeError):
        verdict_to_data(Verdict(ev(), "false"))  # type: ignore[arg-type]


def test_a_refusal_needs_a_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        validate_verdict(Verdict(ev(), False))
    with pytest.raises(ValueError, match="reason"):
        validate_verdict(Verdict(ev(), True, "but a reason"))


def test_validate_verdict_checks_notes_and_evidence() -> None:
    with pytest.raises(TypeError):
        validate_verdict(Verdict(ev(), True, notes=("ok", 3)))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        validate_verdict(Verdict("x", True))  # type: ignore[arg-type]


def verdicts(*evidence: Evidence, subject: Subject | None = None) -> tuple[Verdict, ...]:
    return check_all(evidence, subject or head_subject()).verdicts


def test_evidence_digest_is_order_independent_and_content_sensitive() -> None:
    a, b = ev(tested_sha=HEAD), ev(tested_sha=HEAD2)
    assert evidence_digest(verdicts(a, b)) == evidence_digest(verdicts(b, a))
    assert evidence_digest(verdicts(a)) != evidence_digest(verdicts(a, b))
    assert evidence_digest(verdicts(a)) != evidence_digest(verdicts(b))


def test_evidence_digest_covers_artifact_refs() -> None:
    plain = StoredEvidence(HEAD, "p1", Validity.EXACT_SHA)
    with_ref = StoredEvidence(HEAD, "p1", Validity.EXACT_SHA, artifact_refs=("r",))
    assert evidence_digest(verdicts(plain)) != evidence_digest(verdicts(with_ref))


def test_evidence_digest_covers_the_also_contains_notes() -> None:
    contain = ev(Validity.CONTAINS_SHA, tested_sha="f" * 40)
    sub = head_subject(merge_sha=MERGE)
    only = check_all([contain], sub, lambda _sha: {MERGE}).verdicts
    more = check_all([contain], sub, lambda _sha: {MERGE, EXTRA}).verdicts
    assert only[0].valid
    assert more[0].valid
    assert more[0].notes == (f"also contains {EXTRA}",)
    assert evidence_digest(only) != evidence_digest(more)


def test_evidence_digest_covers_the_older_base_note() -> None:
    same = verdicts(ev(tested_sha=HEAD))
    older = verdicts(ev(tested_sha=HEAD2))
    assert older[0].notes == (OLDER_BASE_NOTE,)
    assert evidence_digest(same) != evidence_digest(older)


def test_evidence_digest_of_nothing_is_stable_and_hashes_canonical_data() -> None:
    blob = json.dumps(
        canonical_data({"v": 1, "verdicts": []}), sort_keys=True, separators=(",", ":")
    )
    assert evidence_digest(()) == hashlib.sha256(blob.encode()).hexdigest()


def test_evidence_digest_refuses_a_malformed_verdict() -> None:
    with pytest.raises(TypeError):
        evidence_digest([Verdict(ev(), "false")])  # type: ignore[arg-type]


# --- rounds -----------------------------------------------------------------------------------


def record(round: int, *, subject: Subject | None = None, diff_ref: str = "diff-1") -> RoundRecord:
    return RoundRecord(
        gate_id=GateId.new(),
        name="human_review",
        round=round,
        subject=subject or head_subject(),
        diff_ref=diff_ref,
    )


def plan(**kw: object):  # type: ignore[no-untyped-def]
    args: dict[str, object] = {
        "name": "human_review",
        "gate_type": GateType.REVIEW,
        "previous": None,
        "subject": head_subject(),
        "diff_ref": "diff-1",
        "evidence": {},
        "expected_stages": (),
    }
    args.update(kw)
    return plan_round(**args)  # type: ignore[arg-type]


def test_the_first_round_is_round_one_with_no_interdiff() -> None:
    p = plan()
    assert p.round == 1
    assert p.previous_gate_id is None
    assert p.interdiff is None


def test_a_re_entered_gate_is_a_new_round_linked_to_the_last_with_an_interdiff() -> None:
    prev = record(1, subject=head_subject(patch_id="p1"), diff_ref="d1")
    sub = head_subject(patch_id="p2", head_sha=HEAD2)
    p = plan(previous=prev, subject=sub, diff_ref="d2")
    assert p.round == 2
    assert p.previous_gate_id == prev.gate_id
    data = p.interdiff
    assert data is not None
    assert (data.from_round, data.to_round) == (1, 2)
    assert (data.from_rev, data.to_rev) == (HEAD, HEAD2)
    assert (data.from_patch_id, data.to_patch_id) == ("p1", "p2")
    assert (data.from_diff_ref, data.to_diff_ref) == ("d1", "d2")
    assert data.patch_changed is True


def test_interdiff_data_records_an_unchanged_patch() -> None:
    prev = record(1, diff_ref="d1")
    p = plan(previous=prev, subject=head_subject(head_sha=HEAD2), diff_ref="d1")
    assert p.interdiff is not None
    assert p.interdiff.patch_changed is False


def test_round_three_links_to_round_two_not_one() -> None:
    p = plan(previous=record(2), subject=head_subject(head_sha=HEAD2))
    assert p.round == 3
    assert p.interdiff is not None
    assert p.interdiff.from_round == 2


def test_pre_push_rounds_use_the_base_sha_as_revision() -> None:
    pre = Subject.pre_push(base_sha=BASE, patch_id="p1", ticket_revision="t1")
    nxt = Subject.pre_push(base_sha=BASE, patch_id="p2", ticket_revision="t1")
    prev = dataclasses.replace(record(1), subject=pre)
    p = plan(gate_type=GateType.PRE_PUSH, previous=prev, subject=nxt)
    assert p.interdiff is not None
    assert (p.interdiff.from_rev, p.interdiff.to_rev) == (BASE, BASE)


def test_a_round_for_another_gate_is_refused() -> None:
    other = dataclasses.replace(record(1), name="qa_gate")
    with pytest.raises(GateRoundError, match="human_review"):
        plan(previous=other)


def test_a_diff_ref_is_required() -> None:
    with pytest.raises(ValueError, match="diff_ref"):
        plan(diff_ref=" ")


# --- evidence rules when opening ---------------------------------------------------------------


def good_subject_for(evidence: dict[str, list[Evidence]], **kw: object) -> Subject:
    flat = [e for es in evidence.values() for e in es]
    first = check_all(flat, head_subject(**kw)).verdicts
    return head_subject(evidence_digest=evidence_digest(first), **kw)


def test_a_gate_that_expects_evidence_opens_when_all_of_it_is_valid() -> None:
    evidence = {"ci": [ev(Validity.EXACT_SHA)], "review": [ev(Validity.SAME_PATCH)]}
    p = plan(
        subject=good_subject_for(evidence),
        evidence=evidence,
        expected_stages=("ci", "review"),
    )
    assert p.check.valid


def test_a_gate_cannot_open_if_evidence_is_not_valid_for_the_subject() -> None:
    evidence = {"ci": [ev(Validity.EXACT_SHA, tested_sha=HEAD2)]}
    with pytest.raises(EvidenceInvalidError) as exc:
        plan(subject=good_subject_for(evidence), evidence=evidence, expected_stages=("ci",))
    assert exc.value.check.failures
    assert isinstance(exc.value, PermanentError)


def test_one_invalid_piece_among_valid_ones_refuses() -> None:
    evidence = {"ci": [ev(Validity.EXACT_SHA), ev(Validity.EXACT_SHA, tested_sha=HEAD2)]}
    with pytest.raises(EvidenceInvalidError):
        plan(subject=good_subject_for(evidence), evidence=evidence, expected_stages=("ci",))


def test_evidence_from_an_unexpected_stage_still_has_to_be_valid() -> None:
    evidence = {"stray": [ev(Validity.EXACT_SHA, tested_sha=HEAD2)]}
    with pytest.raises(EvidenceInvalidError):
        plan(subject=good_subject_for(evidence), evidence=evidence, expected_stages=())


def test_missing_evidence_from_an_expected_stage_is_incomplete() -> None:
    evidence = {"ci": [ev(Validity.EXACT_SHA)]}
    with pytest.raises(IncompleteEvidenceError, match="review") as exc:
        plan(
            subject=good_subject_for(evidence),
            evidence=evidence,
            expected_stages=("ci", "review"),
        )
    assert exc.value.missing == ("review",)


def test_an_expected_stage_with_an_empty_list_is_incomplete() -> None:
    with pytest.raises(IncompleteEvidenceError):
        plan(evidence={"ci": []}, expected_stages=("ci",))


def test_a_gate_that_expects_no_evidence_opens_on_none() -> None:
    p = plan(gate_type=GateType.CUSTOM, expected_stages=(), evidence={})
    assert p.round == 1
    assert p.check.verdicts == ()


def test_a_review_gate_that_expects_no_evidence_opens_on_none() -> None:
    assert plan(gate_type=GateType.REVIEW).round == 1


def test_a_qa_gate_must_expect_evidence_v14() -> None:
    # V14: a QA gate must have something to judge, so no expectation is refused at run time too.
    with pytest.raises(IncompleteEvidenceError, match="qa"):
        plan(gate_type=GateType.QA, expected_stages=(), evidence={})


def test_a_qa_gate_with_its_evidence_opens() -> None:
    evidence = {"qa_suite": [ev(Validity.EXACT_SHA)]}
    p = plan(
        gate_type=GateType.QA,
        subject=good_subject_for(evidence),
        evidence=evidence,
        expected_stages=("qa_suite",),
    )
    assert p.check.valid


def test_the_subject_must_carry_the_digest_of_the_evidence_checked() -> None:
    evidence = {"ci": [ev(Validity.EXACT_SHA)]}
    with pytest.raises(GateRoundError, match="evidence_digest"):
        plan(
            subject=head_subject(evidence_digest="0" * 64),
            evidence=evidence,
            expected_stages=("ci",),
        )


def test_a_pre_push_gate_has_no_evidence_digest_to_match() -> None:
    pre = Subject.pre_push(base_sha=BASE, patch_id="p1", ticket_revision="t1")
    assert plan(gate_type=GateType.PRE_PUSH, subject=pre).round == 1


def test_also_contains_notes_reach_the_plan_and_the_digest() -> None:
    contain = ev(Validity.CONTAINS_SHA, tested_sha="f" * 40)
    evidence = {"staging": [contain]}
    sub = good_subject_for_contains(evidence, {MERGE, EXTRA})
    p = plan(
        gate_type=GateType.QA,
        subject=sub,
        evidence=evidence,
        expected_stages=("staging",),
        contained=lambda _sha: {MERGE, EXTRA},
    )
    assert p.check.notes == (f"also contains {EXTRA}",)
    assert sub.evidence_digest == evidence_digest(p.check.verdicts)


def good_subject_for_contains(evidence: dict[str, list[Evidence]], held: set[str]) -> Subject:
    flat = [e for es in evidence.values() for e in es]
    probe = head_subject(merge_sha=MERGE)
    first = check_all(flat, probe, lambda _s: held).verdicts
    return head_subject(merge_sha=MERGE, evidence_digest=evidence_digest(first))


@pytest.mark.parametrize("answer", ["abc", ["a"], 5, {1}])
def test_a_malformed_containment_answer_propagates_as_a_type_error(answer: object) -> None:
    evidence = {"staging": [ev(Validity.CONTAINS_SHA, tested_sha="f" * 40)]}
    with pytest.raises(TypeError):
        plan(
            gate_type=GateType.QA,
            subject=head_subject(merge_sha=MERGE),
            evidence=evidence,
            expected_stages=("staging",),
            contained=lambda _sha: answer,
        )


def test_an_unknown_containment_answer_refuses_rather_than_opens() -> None:
    evidence = {"staging": [ev(Validity.CONTAINS_SHA, tested_sha="f" * 40)]}
    with pytest.raises(EvidenceInvalidError):
        plan(
            gate_type=GateType.QA,
            subject=head_subject(merge_sha=MERGE),
            evidence=evidence,
            expected_stages=("staging",),
            contained=lambda _sha: None,
        )


# --- agreement with the reducer's head rules ---------------------------------------------------


def test_merged_code_cannot_change_in_a_later_round() -> None:
    # reducer: once a merge is recorded a report of any other head is Malformed
    prev = record(1, subject=head_subject(merge_sha=MERGE))
    with pytest.raises(MergedCodeChangedError):
        plan(previous=prev, subject=head_subject(head_sha=HEAD2), merged_heads=(HEAD,))
    ok = plan(previous=prev, subject=head_subject(merge_sha=MERGE), merged_heads=(HEAD,))
    assert ok.round == 2


def test_merged_heads_bind_the_first_round_too() -> None:
    with pytest.raises(MergedCodeChangedError):
        plan(subject=head_subject(head_sha=HEAD2), merged_heads=(HEAD,))


def test_a_pre_push_subject_cannot_open_after_a_merge() -> None:
    pre = Subject.pre_push(base_sha=BASE, patch_id="p1", ticket_revision="t1")
    with pytest.raises(MergedCodeChangedError):
        plan(gate_type=GateType.PRE_PUSH, subject=pre, merged_heads=(HEAD,))


def test_subject_shape_must_match_the_gate_type() -> None:
    pre = Subject.pre_push(base_sha=BASE, patch_id="p1", ticket_revision="t1")
    with pytest.raises(GateRoundError, match="pre_push"):
        plan(gate_type=GateType.REVIEW, subject=pre)
    with pytest.raises(GateRoundError, match="pre_push"):
        plan(gate_type=GateType.PRE_PUSH, subject=head_subject())


def test_round_records_are_validated() -> None:
    with pytest.raises(ValueError, match="starts at 1"):
        dataclasses.replace(record(1), round=0)
    with pytest.raises(ValueError, match="blank"):
        dataclasses.replace(record(1), diff_ref="")
    with pytest.raises(TypeError):
        dataclasses.replace(record(1), subject="s")  # type: ignore[arg-type]


# --- guards the mutation pass found untested ---------------------------------------------------


def _fake_git(monkeypatch: pytest.MonkeyPatch, **result: object) -> None:
    import subprocess

    def run(*_a: object, **_k: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            ["git"],
            int(result.get("rc", 0)),  # type: ignore[call-overload]
            result.get("out", b""),  # type: ignore[arg-type]
            result.get("err", b""),  # type: ignore[arg-type]
        )

    monkeypatch.setattr(subprocess, "run", run)


def test_a_git_failure_is_a_patch_id_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from sto.gates.subject import PatchIdError

    _fake_git(monkeypatch, rc=128, out=b"abc 000\n", err=b"fatal: boom")
    with pytest.raises(PatchIdError, match="boom"):
        patch_id(DIFF)


def test_git_not_runnable_is_a_patch_id_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from sto.gates.subject import PatchIdError

    def run(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PatchIdError, match="could not run"):
        patch_id(DIFF)


def test_more_than_one_patch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_git(monkeypatch, out=b"a" * 40 + b" " + b"0" * 40 + b"\n" + b"b" * 40 + b" x\n")
    with pytest.raises(ValueError, match="more than one"):
        patch_id(DIFF)


def test_the_first_token_is_the_patch_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_git(monkeypatch, out=b"abc123 " + b"0" * 40 + b"\n")
    assert patch_id(DIFF) == "abc123"


def test_ticket_field_shapes_are_all_checked() -> None:
    with pytest.raises(TypeError, match="description"):
        fields(description=None)
    with pytest.raises(TypeError, match="mapping"):
        fields(route_inputs=[("risk", "High")])
    with pytest.raises(TypeError, match="strings"):
        fields(route_inputs={1: "High"})
    with pytest.raises(TypeError, match="list of strings"):
        fields(acceptance_criteria=("ok", 2))
    with pytest.raises(TypeError, match="list of strings"):
        fields(acceptance_criteria=5)
    with pytest.raises(TypeError, match="list of strings"):
        AttentionItems(red_checks=5)  # type: ignore[arg-type]


def test_criteria_and_route_texts_are_normalised() -> None:
    a = fields(acceptance_criteria=("works ", "is fast"), route_inputs={"risk": "High"})
    b = fields(acceptance_criteria=("works", " is fast\r\n"), route_inputs={"risk": "High "})
    assert ticket_revision(a) == ticket_revision(b)
    assert b.acceptance_criteria == ("works", "is fast")
    assert b.route_inputs == {"risk": "High"}
    assert list(fields(route_inputs={"b": "1", "a": "2"}).route_inputs) == ["a", "b"]


def test_a_ticket_is_normalised_from_crlf_and_cr() -> None:
    assert ticket_revision(fields(description="a\r\nb")) == ticket_revision(
        fields(description="a\nb")
    )
    assert ticket_revision(fields(description="a\rb")) == ticket_revision(
        fields(description="a\nb")
    )
    assert ticket_revision(fields(description="a\nb")) != ticket_revision(fields(description="a b"))


def test_verdict_validation_checks_every_shape() -> None:
    with pytest.raises(TypeError, match="Verdict"):
        validate_verdict("v")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="notes"):
        validate_verdict(Verdict(ev(), True, notes=["n"]))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="reason"):
        validate_verdict(Verdict(ev(), False, 3))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="blank"):
        validate_verdict(Verdict(ev(), True, notes=(" ",)))


def test_verdict_from_data_shapes() -> None:
    good = verdict_to_data(Verdict(ev(), True))
    with pytest.raises(TypeError, match="object"):
        verdict_from_data([])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unexpected"):
        verdict_from_data({**good, "extra": 1})
    with pytest.raises(TypeError, match="evidence"):
        verdict_from_data({**good, "evidence": "x"})
    with pytest.raises(TypeError, match="notes"):
        verdict_from_data({**good, "notes": "n"})
    missing = {k: v for k, v in good.items() if k != "valid"}
    with pytest.raises(ValueError, match="valid"):
        verdict_from_data(missing)
    assert type(verdict_from_data(good).evidence) is Evidence


def test_plain_evidence_in_a_plan_is_required() -> None:
    with pytest.raises(TypeError, match="Evidence"):
        plan(evidence={"ci": ["x"]}, expected_stages=("ci",))


def test_round_record_types() -> None:
    with pytest.raises(TypeError, match="GateId"):
        dataclasses.replace(record(1), gate_id="g")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="int"):
        dataclasses.replace(record(1), round=True)
    with pytest.raises(ValueError, match="blank"):
        dataclasses.replace(record(1), name=" ")


def test_a_record_is_built_from_a_gate() -> None:
    from sto.domain import Gate, RunId

    gate = Gate(GateId.new(), RunId.new(), "human_review", GateType.REVIEW, 2, head_subject())
    rec = RoundRecord.from_gate(gate, "d9")
    assert (rec.gate_id, rec.name, rec.round, rec.subject, rec.diff_ref) == (
        gate.id,
        "human_review",
        2,
        gate.subject,
        "d9",
    )
