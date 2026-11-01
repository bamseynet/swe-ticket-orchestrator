"""Evidence records (D2-22, PLAN 4.5): a table of cases per validity, and the gate page notes."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sto.domain import Subject
from sto.gates.evidence import (
    OLDER_BASE_NOTE,
    Evidence,
    Validity,
    check_all,
    check_evidence,
)

HEAD = "a" * 40
OLD = "b" * 40
MERGE = "c" * 40
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


def ev(validity: Validity, **kw: object) -> Evidence:
    base: dict[str, object] = {"tested_sha": HEAD, "patch_id": PATCH, "validity": validity}
    base.update(kw)
    return Evidence(**base)  # type: ignore[arg-type]


# (validity, evidence overrides, subject overrides, valid, note substrings)
CASES = [
    # exact_sha: tested_sha must equal head_sha; the patch is irrelevant.
    pytest.param(Validity.EXACT_SHA, {}, {}, True, [], id="exact-same-sha"),
    pytest.param(
        Validity.EXACT_SHA, {"tested_sha": OLD}, {}, False, [], id="exact-other-sha-same-patch"
    ),
    pytest.param(
        Validity.EXACT_SHA,
        {"patch_id": "p0"},
        {},
        True,
        [],
        id="exact-same-sha-other-patch-still-holds",
    ),
    pytest.param(
        Validity.EXACT_SHA,
        {},
        {"head_sha": None, "base_sha": OLD, "evidence_digest": None, "attention_digest": None},
        False,
        [],
        id="exact-pre-push-subject-has-no-head",
    ),
    # same_patch: patch_id must match; an older sha is flagged, not refused.
    pytest.param(Validity.SAME_PATCH, {}, {}, True, [], id="patch-same-sha"),
    pytest.param(
        Validity.SAME_PATCH,
        {"tested_sha": OLD},
        {},
        True,
        [OLDER_BASE_NOTE],
        id="patch-older-base",
    ),
    pytest.param(
        Validity.SAME_PATCH, {"patch_id": "p0"}, {}, False, [], id="patch-changed-same-sha"
    ),
    pytest.param(
        Validity.SAME_PATCH,
        {"tested_sha": OLD, "patch_id": "p0"},
        {},
        False,
        [],
        id="patch-changed-older-sha",
    ),
    pytest.param(
        Validity.SAME_PATCH,
        {"tested_sha": OLD},
        {"head_sha": None, "base_sha": OLD, "evidence_digest": None, "attention_digest": None},
        True,
        [],
        id="patch-pre-push-subject-matches-on-patch-alone",
    ),
    # contains_sha: the deployment must contain merge_sha; extras are listed.
    pytest.param(
        Validity.CONTAINS_SHA,
        {"tested_sha": MERGE},
        {"merge_sha": MERGE},
        True,
        [],
        id="contains-is-the-merge-sha",
    ),
    pytest.param(
        Validity.CONTAINS_SHA,
        {"tested_sha": OLD, "contains": frozenset({MERGE, EXTRA})},
        {"merge_sha": MERGE},
        True,
        [f"also contains {EXTRA}"],
        id="contains-lists-anything-else",
    ),
    pytest.param(
        Validity.CONTAINS_SHA,
        {"tested_sha": OLD, "contains": frozenset({EXTRA})},
        {"merge_sha": MERGE},
        False,
        [],
        id="contains-lacks-merge-sha",
    ),
    pytest.param(
        Validity.CONTAINS_SHA,
        {"tested_sha": MERGE},
        {},
        False,
        [],
        id="contains-subject-not-merged-yet",
    ),
]


@pytest.mark.parametrize(("validity", "ev_kw", "sub_kw", "valid", "notes"), CASES)
def test_validity_table(
    validity: Validity,
    ev_kw: dict[str, object],
    sub_kw: dict[str, object],
    valid: bool,
    notes: list[str],
) -> None:
    verdict = check_evidence(ev(validity, **ev_kw), subject(**sub_kw))
    assert verdict.valid is valid
    for n in notes:
        assert n in verdict.notes
    if not notes:
        assert verdict.notes == ()
    if not valid:
        assert verdict.reason  # a refusal always says why


def test_squash_merge_frozen_subject_works_with_contains_sha() -> None:
    # A squash merge makes a new commit: the PR head_sha is not an ancestor of the merge_sha,
    # and the patch id of the squashed commit may differ. Staging QA ran on a deployment that
    # contains the merge commit, so contains_sha holds against the frozen subject (PLAN 4.5).
    frozen = subject(merge_sha=MERGE)
    staging = ev(
        Validity.CONTAINS_SHA, tested_sha="s" * 40, patch_id="squashed", contains=frozenset({MERGE})
    )
    assert check_evidence(staging, frozen).valid
    # The same record under same_patch or exact_sha would not hold: that is why it is declared.
    assert not check_evidence(replace(staging, validity=Validity.EXACT_SHA), frozen).valid
    assert not check_evidence(replace(staging, validity=Validity.SAME_PATCH), frozen).valid


def test_check_all_requires_every_piece() -> None:
    good = ev(Validity.EXACT_SHA)
    stale = ev(Validity.EXACT_SHA, tested_sha=OLD)
    ok = check_all([good, ev(Validity.SAME_PATCH, tested_sha=OLD)], subject())
    assert ok.valid
    assert OLDER_BASE_NOTE in ok.notes
    bad = check_all([good, stale], subject())
    assert not bad.valid
    assert len(bad.failures) == 1
    assert bad.failures[0].evidence is stale


def test_check_all_of_nothing_is_not_valid() -> None:
    # A gate with no evidence must not open on a vacuous truth.
    assert not check_all([], subject()).valid


def test_gate_page_data_says_evidence_from_an_older_base() -> None:
    result = check_all([ev(Validity.SAME_PATCH, tested_sha=OLD)], subject())
    assert result.valid
    assert result.notes == ("evidence from an older base",)


def test_evidence_validates_fields() -> None:
    with pytest.raises(ValueError, match="tested_sha"):
        Evidence(tested_sha="", patch_id=PATCH, validity=Validity.EXACT_SHA)
    with pytest.raises(TypeError):
        Evidence(tested_sha=HEAD, patch_id=PATCH, validity="exact_sha")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="contains"):
        Evidence(
            tested_sha=HEAD, patch_id=PATCH, validity=Validity.EXACT_SHA, contains=frozenset({""})
        )
