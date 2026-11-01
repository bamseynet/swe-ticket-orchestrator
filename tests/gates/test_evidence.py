"""Evidence records (D2-22, PLAN 4.5): a table of cases per validity, and the gate page notes."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from sto.domain import Subject, from_wire, to_wire
from sto.gates.evidence import (
    OLDER_BASE_NOTE,
    Containment,
    Evidence,
    Validity,
    check_all,
    check_evidence,
)
from sto.gates.hooks import entry_hash
from sto.store.ports import canonical_data

HEAD = "a" * 40
OLD = "b" * 40
MERGE = "c" * 40
NEW = "e" * 40
EXTRA = "d" * 40
PATCH = "p1"


def subject(**kw: object) -> Subject:
    base: dict[str, object] = {
        "patch_id": PATCH,
        "ticket_revision": "t1",
        "head_sha": HEAD,
        "evidence_digest": "e",
        "attention_digest": "a",
    }
    base.update(kw)
    return Subject(**base)  # type: ignore[arg-type]


PRE_PUSH = {"head_sha": None, "base_sha": OLD, "evidence_digest": None, "attention_digest": None}


def fake_containment(answers: dict[str, set[str] | frozenset[str] | None]) -> Containment:
    """A hermetic stand-in for D8-02's answer. A sha it has no entry for is unknown."""

    def contained(tested_sha: str) -> set[str] | frozenset[str] | None:
        return answers.get(tested_sha)

    return contained


def ev_(validity: Validity, tested: str = HEAD, patch: str = PATCH) -> Evidence:
    return Evidence(tested_sha=tested, patch_id=patch, validity=validity)


# (validity, tested_sha, patch_id, subject overrides, valid, notes). exact_sha and same_patch.
CASES = [
    pytest.param(Validity.EXACT_SHA, HEAD, PATCH, {}, True, (), id="exact-same-sha"),
    pytest.param(Validity.EXACT_SHA, OLD, PATCH, {}, False, (), id="exact-other-sha-same-patch"),
    pytest.param(Validity.EXACT_SHA, HEAD, "p0", {}, True, (), id="exact-same-sha-other-patch"),
    pytest.param(Validity.EXACT_SHA, HEAD, PATCH, PRE_PUSH, False, (), id="exact-pre-push"),
    pytest.param(Validity.SAME_PATCH, HEAD, PATCH, {}, True, (), id="patch-same-sha"),
    pytest.param(
        Validity.SAME_PATCH, OLD, PATCH, {}, True, (OLDER_BASE_NOTE,), id="patch-older-base"
    ),
    pytest.param(Validity.SAME_PATCH, HEAD, "p0", {}, False, (), id="patch-changed-same-sha"),
    pytest.param(Validity.SAME_PATCH, OLD, "p0", {}, False, (), id="patch-changed-older-sha"),
    pytest.param(
        Validity.SAME_PATCH, OLD, PATCH, PRE_PUSH, True, (), id="patch-pre-push-same-base"
    ),
    pytest.param(
        Validity.SAME_PATCH,
        OLD,
        PATCH,
        {**PRE_PUSH, "base_sha": NEW},
        True,
        (OLDER_BASE_NOTE,),
        id="patch-pre-push-moved-base",
    ),
    pytest.param(
        Validity.SAME_PATCH,
        OLD,
        "p0",
        {**PRE_PUSH, "base_sha": NEW},
        False,
        (),
        id="patch-pre-push-changed",
    ),
]


@pytest.mark.parametrize(("validity", "tested", "patch", "sub_kw", "valid", "notes"), CASES)
def test_validity_table(
    validity: Validity,
    tested: str,
    patch: str,
    sub_kw: dict[str, object],
    valid: bool,
    notes: tuple[str, ...],
) -> None:
    verdict = check_evidence(ev_(validity, tested, patch), subject(**sub_kw))
    assert verdict.valid is valid
    assert verdict.notes == notes
    assert bool(verdict.reason) is (not valid)  # a refusal always says why


def test_exact_and_same_patch_never_consult_containment() -> None:
    def boom(_: str) -> set[str] | frozenset[str] | None:
        raise AssertionError("containment must only be asked for contains_sha")

    assert check_evidence(ev_(Validity.EXACT_SHA), subject(), boom).valid
    assert check_evidence(ev_(Validity.SAME_PATCH), subject(), boom).valid


MERGED = {"merge_sha": MERGE}
STAGING = "s" * 40


@pytest.mark.parametrize(
    ("answer", "valid", "notes"),
    [
        pytest.param({MERGE}, True, (), id="contains-only-the-merge-sha"),
        pytest.param(
            {EXTRA, STAGING, MERGE},
            True,
            (f"also contains {EXTRA}", f"also contains {STAGING}"),
            id="extras-sorted-and-complete",
        ),
        pytest.param(
            {"z" * 40, MERGE, "f" * 40, EXTRA},
            True,
            (f"also contains {EXTRA}", f"also contains {'f' * 40}", f"also contains {'z' * 40}"),
            id="extras-sorted-whatever-the-source-order",
        ),
        pytest.param({EXTRA}, False, (), id="lacks-merge-sha"),
        pytest.param(set(), False, (), id="empty-answer-is-a-refusal"),
    ],
)
def test_contains_sha_table(answer: set[str], valid: bool, notes: tuple[str, ...]) -> None:
    contained = fake_containment({STAGING: answer})
    verdict = check_evidence(ev_(Validity.CONTAINS_SHA, STAGING), subject(**MERGED), contained)
    assert verdict.valid is valid
    assert verdict.notes == notes
    assert bool(verdict.reason) is (not valid)


def test_contains_sha_asks_about_the_tested_sha() -> None:
    asked: list[str] = []

    def contained(sha: str) -> set[str] | frozenset[str] | None:
        asked.append(sha)
        return {MERGE}

    check_evidence(ev_(Validity.CONTAINS_SHA, STAGING), subject(**MERGED), contained)
    assert asked == [STAGING]


def test_contains_sha_without_an_answer_is_refused_not_valid() -> None:
    e = ev_(Validity.CONTAINS_SHA, MERGE)  # tested_sha equals merge_sha, still not enough
    no_resolver = check_evidence(e, subject(**MERGED))
    unknown = check_evidence(e, subject(**MERGED), fake_containment({}))
    empty = check_evidence(e, subject(**MERGED), fake_containment({MERGE: set()}))
    assert not no_resolver.valid
    assert not unknown.valid
    assert not empty.valid
    # unknown and empty are different facts, and the reasons say so
    assert "not known" in unknown.reason
    assert "lacks" in empty.reason
    assert "no containment answer" in no_resolver.reason
    assert unknown.reason != empty.reason
    assert empty.reason != no_resolver.reason
    assert unknown.reason != no_resolver.reason


def test_contains_sha_before_a_merge_is_refused() -> None:
    contained = fake_containment({STAGING: {MERGE}})
    verdict = check_evidence(ev_(Validity.CONTAINS_SHA, STAGING), subject(), contained)
    assert not verdict.valid
    assert "no merge_sha" in verdict.reason


def test_refusal_reasons_are_pinned() -> None:
    pre_push = subject(**PRE_PUSH)
    assert "no head_sha" in check_evidence(ev_(Validity.EXACT_SHA), pre_push).reason
    assert "no containment answer" in (
        check_evidence(ev_(Validity.CONTAINS_SHA, STAGING), subject(**MERGED)).reason
    )


def test_squash_merge_frozen_subject_works_with_contains_sha() -> None:
    # A squash merge makes a new commit: the PR head_sha is not in the merged history. Staging
    # QA ran on a deployment that contains the merge commit, so contains_sha holds against the
    # frozen subject, and only because the injected answer really has the merge_sha.
    frozen = subject(merge_sha=MERGE)
    staging = ev_(Validity.CONTAINS_SHA, STAGING, "squashed")
    assert check_evidence(staging, frozen, fake_containment({STAGING: {MERGE}})).valid
    stale = ev_(Validity.CONTAINS_SHA, OLD, "squashed")  # a pre-merge deployment
    refused = check_evidence(stale, frozen, fake_containment({OLD: {HEAD}, STAGING: {MERGE}}))
    assert not refused.valid
    # exact_sha is refused because the tested sha is not the head sha; same_patch because the
    # squashed patch differs from the subject's.
    assert not check_evidence(replace(staging, validity=Validity.EXACT_SHA), frozen).valid
    assert not check_evidence(replace(staging, validity=Validity.SAME_PATCH), frozen).valid


def test_check_all_requires_every_piece() -> None:
    good = ev_(Validity.EXACT_SHA)
    stale = ev_(Validity.EXACT_SHA, OLD)
    ok = check_all([good, ev_(Validity.SAME_PATCH, OLD)], subject())
    assert ok.valid
    assert ok.notes == (OLDER_BASE_NOTE,)
    bad = check_all([good, stale], subject())
    assert not bad.valid
    assert len(bad.failures) == 1
    assert bad.failures[0].evidence is stale


def test_check_all_of_nothing_is_not_valid() -> None:
    assert not check_all([], subject()).valid


def test_check_all_keeps_every_verdicts_notes_once_in_order() -> None:
    contained = fake_containment({STAGING: {MERGE, EXTRA}})
    result = check_all(
        [
            ev_(Validity.SAME_PATCH, OLD),  # note first
            ev_(Validity.CONTAINS_SHA, STAGING),
            ev_(Validity.SAME_PATCH, NEW),  # the same note again
            ev_(Validity.EXACT_SHA),  # no notes: must not erase the earlier ones
        ],
        subject(**MERGED),
        contained,
    )
    assert result.valid
    assert result.notes == (OLDER_BASE_NOTE, f"also contains {EXTRA}")


def test_check_all_passes_containment_through() -> None:
    e = ev_(Validity.CONTAINS_SHA, STAGING)
    assert check_all([e], subject(**MERGED), fake_containment({STAGING: {MERGE}})).valid
    assert not check_all([e], subject(**MERGED)).valid


def test_gate_page_data_says_evidence_from_an_older_base() -> None:
    result = check_all([ev_(Validity.SAME_PATCH, OLD)], subject())
    assert result.valid
    assert result.notes == ("evidence from an older base",)


@pytest.mark.parametrize("validity", list(Validity))
def test_evidence_round_trips_the_store_and_the_hash_chain(validity: Validity) -> None:
    e = ev_(validity, OLD)
    wire = to_wire(e)
    assert wire == {"tested_sha": OLD, "patch_id": PATCH, "validity": validity.value}
    stored = canonical_data(wire)
    assert from_wire(Evidence, json.loads(json.dumps(stored))) == e
    assert len(entry_hash(wire)) == 64


@pytest.mark.parametrize("bad", ["", " ", "\t\n"])
def test_evidence_refuses_blank_fields(bad: str) -> None:
    with pytest.raises(ValueError, match="tested_sha"):
        Evidence(tested_sha=bad, patch_id=PATCH, validity=Validity.EXACT_SHA)
    with pytest.raises(ValueError, match="patch_id"):
        Evidence(tested_sha=HEAD, patch_id=bad, validity=Validity.EXACT_SHA)


def test_evidence_refuses_wrong_types() -> None:
    with pytest.raises(TypeError, match="validity"):
        Evidence(tested_sha=HEAD, patch_id=PATCH, validity="exact_sha")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="patch_id"):
        Evidence(tested_sha=HEAD, patch_id=None, validity=Validity.EXACT_SHA)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="tested_sha"):
        Evidence(tested_sha=None, patch_id=PATCH, validity=Validity.EXACT_SHA)  # type: ignore[arg-type]


def test_records_are_frozen() -> None:
    e = ev_(Validity.EXACT_SHA)
    v = check_evidence(e, subject())
    c = check_all([e], subject())
    for obj, field in ((e, "tested_sha"), (v, "valid"), (c, "verdicts")):
        with pytest.raises(FrozenInstanceError):
            setattr(obj, field, None)


MERGED_BAD_ANSWERS = [
    pytest.param(f"deployment does NOT contain {MERGE}", id="error-text-string"),
    pytest.param(MERGE, id="bare-sha-string"),
    pytest.param((s for s in [EXTRA, MERGE, NEW]), id="generator"),
    pytest.param({MERGE: True, EXTRA: True}, id="dict"),
    pytest.param({MERGE: False}, id="dict-merge-false"),
    pytest.param(MERGE.encode(), id="bytes"),
    pytest.param([MERGE, EXTRA], id="list"),
    pytest.param((MERGE, EXTRA), id="tuple"),
    pytest.param({MERGE, None}, id="none-member"),
    pytest.param({MERGE, " "}, id="blank-member"),
    pytest.param({MERGE, 7}, id="non-str-member"),
]


@pytest.mark.parametrize("answer", MERGED_BAD_ANSWERS)
def test_a_malformed_containment_answer_raises_never_valid(answer: object) -> None:
    e = ev_(Validity.CONTAINS_SHA, STAGING)
    with pytest.raises(TypeError, match="containment"):
        check_evidence(e, subject(**MERGED), lambda _: answer)  # type: ignore[arg-type,return-value]
    with pytest.raises(TypeError, match="containment"):
        check_all([e], subject(**MERGED), lambda _: answer)  # type: ignore[arg-type,return-value]


def test_a_frozenset_answer_is_accepted() -> None:
    contained = fake_containment({STAGING: frozenset({MERGE, EXTRA})})
    verdict = check_evidence(ev_(Validity.CONTAINS_SHA, STAGING), subject(**MERGED), contained)
    assert verdict.valid
    assert verdict.notes == (f"also contains {EXTRA}",)


def test_check_all_does_not_drop_an_unknown_verdict() -> None:
    result = check_all(
        [ev_(Validity.EXACT_SHA), ev_(Validity.CONTAINS_SHA, STAGING)],
        subject(**MERGED),
        fake_containment({}),
    )
    assert not result.valid
    assert len(result.failures) == 1
    assert "not known" in result.failures[0].reason


class Boom(Exception):
    pass


def test_a_raising_containment_answer_propagates() -> None:
    def contained(_: str) -> set[str] | frozenset[str] | None:
        raise Boom

    e = ev_(Validity.CONTAINS_SHA, STAGING)
    with pytest.raises(Boom):
        check_evidence(e, subject(**MERGED), contained)
    with pytest.raises(Boom):
        check_all([e], subject(**MERGED), contained)


def test_an_unknown_validity_is_a_bug_not_a_verdict() -> None:
    e = ev_(Validity.EXACT_SHA)
    object.__setattr__(e, "validity", "bogus")
    with pytest.raises(AssertionError):
        check_evidence(e, subject())
