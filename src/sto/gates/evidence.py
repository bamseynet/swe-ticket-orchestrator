"""Evidence records (D2-22, PLAN 4.5): what was tested, and whether that covers a subject.

Every piece of evidence stores ``tested_sha``, ``patch_id`` and a declared ``Validity``.
A gate may open only when all of its evidence is valid for the subject. Pure: no I/O.

| validity       | holds when                                                              |
|----------------|-------------------------------------------------------------------------|
| ``exact_sha``  | ``tested_sha`` equals the subject's ``head_sha``                        |
| ``same_patch`` | ``patch_id`` equals the subject's; an older ``tested_sha`` is flagged   |
| ``contains_sha`` | the tested deployment contains the subject's ``merge_sha``            |

A record for a ``contains_sha`` check lists what the deployment contains in ``contains``
(``tested_sha`` itself counts). Anything other than ``merge_sha`` goes on the gate page.
After a squash merge the frozen subject carries ``merge_sha``, so staging QA checked with
``contains_sha`` still works although the PR's ``head_sha`` is not in the merged history.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from sto.domain import Subject

OLDER_BASE_NOTE = "evidence from an older base"


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
    contains: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _nonblank("evidence tested_sha", self.tested_sha)
        _nonblank("evidence patch_id", self.patch_id)
        if not isinstance(self.validity, Validity):
            raise TypeError("evidence validity must be a Validity")
        object.__setattr__(self, "contains", frozenset(self.contains))
        for sha in self.contains:
            _nonblank("evidence contains entry", sha)


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


def check_evidence(evidence: Evidence, subject: Subject) -> Verdict:
    """Does this evidence cover ``subject``? Never raises for a mismatch; refuses with a reason."""
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
            older = subject.head_sha is not None and evidence.tested_sha != subject.head_sha
            return Verdict(evidence, True, notes=(OLDER_BASE_NOTE,) if older else ())
        case Validity.CONTAINS_SHA:
            if subject.merge_sha is None:
                return Verdict(evidence, False, "subject has no merge_sha yet")
            held = evidence.contains | {evidence.tested_sha}
            if subject.merge_sha not in held:
                return Verdict(
                    evidence, False, f"tested deployment lacks merge_sha {subject.merge_sha}"
                )
            extras = sorted(held - {subject.merge_sha})
            return Verdict(evidence, True, notes=tuple(f"also contains {s}" for s in extras))


def check_all(evidence: Iterable[Evidence], subject: Subject) -> EvidenceCheck:
    return EvidenceCheck(tuple(check_evidence(e, subject) for e in evidence))
