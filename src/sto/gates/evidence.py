"""Evidence records (D2-22, PLAN 4.5): what was tested, and whether that covers a subject.

Every piece of evidence stores ``tested_sha``, ``patch_id`` and a declared ``Validity``.
A gate may open only when all of its evidence is valid for the subject. Pure: no I/O.

| validity       | holds when                                                              |
|----------------|-------------------------------------------------------------------------|
| ``exact_sha``  | ``tested_sha`` equals the subject's ``head_sha``                        |
| ``same_patch`` | ``patch_id`` equals the subject's; an older ``tested_sha`` is flagged   |
| ``contains_sha`` | the tested deployment contains the subject's ``merge_sha``            |

Containment is a fact about the git graph, so it is not stored on the record. ``contains_sha``
is checked through an injected ``Containment``: a callable from ``tested_sha`` to the set of SHAs
the tested deployment contains, or ``None`` when that is not known. No callable, or ``None``,
refuses (never valid); an empty set is a real answer ("contains nothing"), distinct from unknown.
Everything else the answer reports goes on the gate page, sorted. D8-02 owns the real answer.
After a squash merge the frozen subject carries ``merge_sha``, so staging QA checked with
``contains_sha`` works although the PR's ``head_sha`` is not in the merged history.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import assert_never

from sto.domain import Subject

OLDER_BASE_NOTE = "evidence from an older base"

# tested_sha -> the SHAs that deployment contains; None means "not known".
Containment = Callable[[str], Collection[str] | None]


class Validity(StrEnum):
    EXACT_SHA = "exact_sha"
    SAME_PATCH = "same_patch"
    CONTAINS_SHA = "contains_sha"


def _nonblank(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


@dataclass(frozen=True)
class Evidence:
    tested_sha: str
    patch_id: str
    validity: Validity

    def __post_init__(self) -> None:
        _nonblank("evidence tested_sha", self.tested_sha)
        _nonblank("evidence patch_id", self.patch_id)
        if not isinstance(self.validity, Validity):
            raise TypeError("evidence validity must be a Validity")


@dataclass(frozen=True)
class Verdict:
    """One result: ``notes`` go on the gate page, ``reason`` explains a refusal."""

    evidence: Evidence
    valid: bool
    reason: str = ""
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceCheck:
    """The outcome for a gate's whole evidence set."""

    verdicts: tuple[Verdict, ...]

    @property
    def valid(self) -> bool:
        # An empty set is not valid: a gate must not open on a vacuous truth.
        return bool(self.verdicts) and all(v.valid for v in self.verdicts)

    @property
    def failures(self) -> tuple[Verdict, ...]:
        return tuple(v for v in self.verdicts if not v.valid)

    @property
    def notes(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for v in self.verdicts:
            for n in v.notes:
                seen.setdefault(n)
        return tuple(seen)


def check_evidence(
    evidence: Evidence, subject: Subject, contained: Containment | None = None
) -> Verdict:
    """Does this evidence cover ``subject``? A mismatch is a refusal with a reason, not a raise.

    ``contained`` answers what a deployment contains; only ``contains_sha`` consults it.
    """
    match evidence.validity:
        case Validity.EXACT_SHA:
            if subject.head_sha is None:
                return Verdict(evidence, False, "subject has no head_sha to match tested_sha")
            if evidence.tested_sha != subject.head_sha:
                return Verdict(
                    evidence,
                    False,
                    f"tested {evidence.tested_sha}, but the subject head is {subject.head_sha}",
                )
            return Verdict(evidence, True)
        case Validity.SAME_PATCH:
            if evidence.patch_id != subject.patch_id:
                return Verdict(
                    evidence,
                    False,
                    f"patch {evidence.patch_id} is not the subject's patch {subject.patch_id}",
                )
            # A pre-push subject has no head: its base is what the evidence is measured against.
            current = subject.head_sha if subject.head_sha is not None else subject.base_sha
            older = evidence.tested_sha != current
            return Verdict(evidence, True, notes=(OLDER_BASE_NOTE,) if older else ())
        case Validity.CONTAINS_SHA:
            if subject.merge_sha is None:
                return Verdict(evidence, False, "subject has no merge_sha yet")
            if contained is None:
                return Verdict(evidence, False, "no containment answer available")
            held = contained(evidence.tested_sha)
            if held is None:
                return Verdict(
                    evidence, False, f"containment of {evidence.tested_sha} is not known"
                )
            if subject.merge_sha not in held:
                return Verdict(
                    evidence,
                    False,
                    f"tested deployment {evidence.tested_sha} lacks merge_sha {subject.merge_sha}",
                )
            extras = sorted(set(held) - {subject.merge_sha})
            return Verdict(evidence, True, notes=tuple(f"also contains {s}" for s in extras))
        case _:
            assert_never(evidence.validity)


def check_all(
    evidence: Iterable[Evidence], subject: Subject, contained: Containment | None = None
) -> EvidenceCheck:
    return EvidenceCheck(tuple(check_evidence(e, subject, contained) for e in evidence))
