"""Subject and rounds (D2-08, PLAN 4): what a gate approves, and how a re-entered gate opens.

Pure apart from :func:`patch_id`, which pipes a diff through ``git patch-id --verbatim``.

Digests. Every hash is SHA-256 over ``json.dumps`` of :func:`~sto.store.ports.canonical_data`
(sorted keys, compact), the stored form, so a value read back from a store hashes the same.

* :func:`patch_id`: ``git patch-id --verbatim`` over the diff against the merge base. It ignores
  line numbers and blob ids, so the same change on a new base gives the same id, and it keeps
  whitespace (the default mode drops it, so a re-indent that changes behaviour would not move it).
* :func:`ticket_revision`: the normalised summary, description, acceptance criteria and route
  inputs only. :func:`ticket_fields` picks those four and drops everything else, so our own
  comments and transitions never reach the hash. Text is NFC with ``\\n`` line ends and no
  trailing blanks.
* :func:`attention_digest`: failed reviewers, findings at or above ``block_on``, unverified
  criteria and red checks, as names. Free-form text has no field, so it cannot change it.
* :func:`evidence_digest`: the validated verdicts, order-independent. A verdict carries its
  notes, so the "also contains" list of a ``contains_sha`` check and "evidence from an older
  base" are part of what the human saw, and are in the digest.

Evidence. ``Evidence.from_wire`` rejects extra fields, so the artifact refs of PLAN 11 (``EV#``
item) extend it on purpose: :class:`StoredEvidence`. ``Verdict`` has no validation of its own and
``from_wire`` accepts ``valid: "false"``, so every persisted or hashed verdict goes through
:func:`validate_verdict` (:func:`verdict_to_data`, :func:`verdict_from_data`).

Rounds. :func:`plan_round` decides whether a gate round may open:

* A re-entered gate is a new round linked to the last (:class:`RoundRecord`): ``round + 1`` and
  ``previous_gate_id``. From round 2 it carries :class:`Interdiff` data: both revisions, both
  ``patch_id`` and both stored diff refs, so a viewer can render the change since the last round.
* Evidence rule. Each stage the gate expects must have evidence (completeness), and *every*
  piece given, expected or not, must be valid for the subject (``check_all``). A gate that
  expects no evidence opens on none, with an empty check (the only vacuous case; an empty
  ``EvidenceCheck`` is not ``valid``, so the plan never calls ``.valid`` on it). The one
  exception is V14: a ``qa`` gate must expect evidence, because a QA gate must have something to
  judge. D2-04 proves this on the graph; the run-time check backs it. A head subject must carry
  the :func:`evidence_digest` of the verdicts checked.
* A malformed containment answer is a ``TypeError`` from ``check_all`` and propagates. It is a
  fault in the answer's producer, never a verdict.
* Reducer agreement (D2-06). Approvals bind a ``head_sha`` and merged code is immutable: when the
  run has merges (``merges``, ``(merge_sha, head_sha)`` pairs like the reducer's ``Merge``), only
  a head subject whose ``(merge_sha, head_sha)`` is one of them may open, so a forged
  ``merge_sha`` cannot reach ``contains_sha`` evidence; with no merge, ``merge_sha`` must be
  unset. An incomplete merge record (no head) is refused, and so is a pre-push subject once
  anything has merged. A
  ``pr.update_branch`` clears the live subject, and the next gate round is planned with the
  subject reported afterwards; this module keeps no state of its own. Gates are named, as in
  the gate service and ``sod``: a record belongs to a gate name and a round number.

Not here: opening the gate (``GateService``), carry-over (D2-09) or reuse (D2-21).
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unicodedata
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sto.domain import Gate, GateId, GateType, PermanentError, Subject, from_wire, to_wire
from sto.gates.evidence import (
    Containment,
    Evidence,
    EvidenceCheck,
    Verdict,
    check_all,
)
from sto.store.ports import canonical_data

__all__ = [
    "AttentionItems",
    "EvidenceInvalidError",
    "GateRoundError",
    "IncompleteEvidenceError",
    "Interdiff",
    "MergedCodeChangedError",
    "PatchIdError",
    "RoundPlan",
    "RoundRecord",
    "StoredEvidence",
    "TicketFields",
    "attention_digest",
    "evidence_digest",
    "patch_id",
    "plan_round",
    "ticket_fields",
    "ticket_revision",
    "validate_verdict",
    "verdict_from_data",
    "verdict_to_data",
]

_PATCH_ID_TIMEOUT_S = 30


class PatchIdError(PermanentError):
    """``git patch-id`` could not be run."""


class GateRoundError(PermanentError):
    """A gate round cannot open."""


class EvidenceInvalidError(GateRoundError):
    """Some evidence is not valid for the subject. ``check`` has the refusals and their reasons."""

    def __init__(self, message: str, check: EvidenceCheck) -> None:
        super().__init__(message)
        self.check = check


class IncompleteEvidenceError(GateRoundError):
    """An expected stage has no evidence. ``missing`` names those stages, sorted."""

    def __init__(self, message: str, missing: tuple[str, ...]) -> None:
        super().__init__(message)
        self.missing = missing


class MergedCodeChangedError(GateRoundError):
    """The run has merged code and the subject is for something else (merged code is immutable)."""


def _hash(body: dict[str, Any]) -> str:
    blob = json.dumps(canonical_data(body), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _nonblank(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string, not {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _strings(label: str, value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise TypeError(f"{label} must be a list of strings, not {type(value).__name__}")
    return tuple(_nonblank(f"{label} item", v) for v in value)


# --- patch_id ---------------------------------------------------------------------------------


_MIN_GIT = (2, 40)  # --verbatim is 2.31; mode-only and empty-file ids changed in 2.40


@functools.cache
def _check_git() -> None:
    """Refuse a git older than ``_MIN_GIT``, once per process (the version does not change)."""
    try:
        done = subprocess.run(
            ["git", "version"],
            capture_output=True,
            timeout=_PATCH_ID_TIMEOUT_S,
            check=False,
            env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PatchIdError(f"git could not run: {exc}") from exc
    text = done.stdout.decode(errors="replace")
    found = re.search(r"(\d+)\.(\d+)", text)
    if done.returncode != 0 or found is None:
        raise PatchIdError(f"cannot read the git version from {text.strip()!r}")
    if (int(found[1]), int(found[2])) < _MIN_GIT:
        raise PatchIdError(
            f"git {found[0]} is too old for patch_id; need {_MIN_GIT[0]}.{_MIN_GIT[1]} or newer"
        )


def _git_env() -> dict[str, str]:
    # A clean environment: no user or system git config can change how the diff is read.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def patch_id(diff: bytes) -> str:
    """``git patch-id --verbatim`` of ``diff``, a canonical diff against the merge base
    (``git diff --binary --no-color --no-ext-diff --full-index <merge_base> <head>``).

    Bytes, because that is what git produces: text would have to be encoded, and a diff that is
    not UTF-8 would either fail or, if decoded with replacement, collide with another one.

    Raises ``PatchIdError`` when the diff holds no patch (an empty change has no id), when git is
    older than 2.40 or when git cannot run.
    """
    if not isinstance(diff, bytes):
        raise TypeError(f"diff must be bytes, not {type(diff).__name__}")
    _check_git()
    try:
        # cwd is an empty directory, so git finds no repository and reads no repo config.
        with tempfile.TemporaryDirectory() as neutral:
            done = subprocess.run(
                ["git", "patch-id", "--verbatim"],
                input=diff,
                capture_output=True,
                timeout=_PATCH_ID_TIMEOUT_S,
                check=False,
                env=_git_env(),
                cwd=neutral,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PatchIdError(f"git patch-id could not run: {exc}") from exc
    if done.returncode != 0:
        raise PatchIdError(f"git patch-id failed: {done.stderr.decode(errors='replace').strip()}")
    lines = done.stdout.decode().splitlines()
    if not lines:
        raise PatchIdError("diff holds no patch")
    if len(lines) > 1:
        raise PatchIdError("diff holds more than one patch")
    return lines[0].split()[0]


# --- ticket_revision --------------------------------------------------------------------------


def _text(value: str, *, block: bool = False) -> str:
    """NFC, ``\\n`` line ends, no trailing blanks. A one-line value is stripped fully; a
    ``block`` (the description) loses only leading and trailing newlines, so the indentation of
    its first line, which can be code or a list, still counts as an edit."""
    value = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    lines = "\n".join(line.rstrip() for line in value.split("\n"))
    return lines.strip("\n") if block else lines.strip()


@dataclass(frozen=True)
class TicketFields:
    """The only ticket fields that make up ``ticket_revision`` (PLAN 4)."""

    summary: str
    description: str
    acceptance_criteria: tuple[str, ...]
    route_inputs: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.summary, str):
            raise TypeError("ticket summary must be a string")
        if not isinstance(self.description, str):
            raise TypeError("ticket description must be a string")
        object.__setattr__(
            self,
            "acceptance_criteria",
            tuple(_text(c) for c in _crit(self.acceptance_criteria)),
        )
        if not isinstance(self.route_inputs, Mapping):
            raise TypeError("ticket route_inputs must be a mapping")
        inputs: dict[str, str] = {}
        for k, v in self.route_inputs.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("ticket route_inputs must map strings to strings")
            key = _text(k)
            if key in inputs:
                raise ValueError(f"ticket route_inputs has two keys that read as {key!r}")
            inputs[key] = _text(v)
        object.__setattr__(self, "route_inputs", dict(sorted(inputs.items())))


def _crit(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise TypeError("ticket acceptance_criteria must be a list of strings")
    if not all(isinstance(c, str) for c in value):
        raise TypeError("ticket acceptance_criteria must be a list of strings")
    return tuple(value)


_TICKET_KEYS = ("summary", "description", "acceptance_criteria", "route_inputs")


def ticket_fields(ticket: Mapping[str, Any]) -> TicketFields:
    """Pick the four revision fields out of a ticket snapshot. Comments, status, transitions and
    anything else are dropped here, so they cannot reach the hash. A missing field is refused
    rather than read as empty."""
    missing = [k for k in _TICKET_KEYS if k not in ticket]
    if missing:
        raise ValueError(f"ticket is missing {', '.join(missing)}")
    return TicketFields(**{k: ticket[k] for k in _TICKET_KEYS})


def ticket_revision(fields: TicketFields) -> str:
    return _hash(
        {
            "v": 1,
            "summary": _text(fields.summary),
            "description": _text(fields.description, block=True),
            "acceptance_criteria": list(fields.acceptance_criteria),
            "route_inputs": dict(fields.route_inputs),
        }
    )


# --- attention_digest -------------------------------------------------------------------------


@dataclass(frozen=True)
class AttentionItems:
    """What needs a human's attention, as names. Each field is stored sorted and de-duplicated."""

    failed_reviewers: tuple[str, ...] = ()
    blocking_findings: tuple[str, ...] = ()  # at or above the stage's ``block_on``
    unverified_criteria: tuple[str, ...] = ()
    red_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for f in dataclasses.fields(self):
            names = _strings(f"attention {f.name}", getattr(self, f.name))
            object.__setattr__(self, f.name, tuple(sorted(set(names))))


def attention_digest(items: AttentionItems) -> str:
    body: dict[str, Any] = {"v": 1}
    for f in dataclasses.fields(items):
        body[f.name] = list(getattr(items, f.name))
    return _hash(body)


# --- evidence ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class StoredEvidence(Evidence):
    """``Evidence`` plus the artifact refs PLAN 11 stores with it (``EV#stage#ulid``).

    A subclass, not a change to ``Evidence``: ``from_wire(Evidence, ...)`` keeps rejecting extra
    fields, and the validity check never reads the refs.
    """

    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        # a list is accepted and stored as a tuple, so equality and the hash see one form
        object.__setattr__(
            self, "artifact_refs", _strings("evidence artifact_refs", self.artifact_refs)
        )


def validate_verdict(verdict: Verdict) -> Verdict:
    """Strictly check a ``Verdict`` that is about to be persisted or hashed, and return it.

    ``from_wire`` leaves ``valid``, ``reason`` and ``notes`` to the caller, so ``valid: "false"``
    would load as a truthy string. ``TypeError`` for a wrong type, ``ValueError`` for a refusal
    with no reason or an acceptance that carries one.
    """
    if not isinstance(verdict, Verdict):
        raise TypeError(f"expected a Verdict, not {type(verdict).__name__}")
    if not isinstance(verdict.evidence, Evidence):
        raise TypeError("verdict evidence must be an Evidence")
    if type(verdict.valid) is not bool:
        raise TypeError(f"verdict valid must be a bool, not {verdict.valid!r}")
    if not isinstance(verdict.reason, str):
        raise TypeError("verdict reason must be a string")
    if not isinstance(verdict.notes, tuple):
        raise TypeError("verdict notes must be a tuple")
    for note in verdict.notes:
        _nonblank("verdict note", note)
    if verdict.valid and verdict.reason:
        raise ValueError("a valid verdict has no reason")
    if not verdict.valid and not verdict.reason.strip():
        raise ValueError("a refusal needs a reason")
    return verdict


def verdict_to_data(verdict: Verdict) -> dict[str, Any]:
    """The stored form of a validated verdict (plain JSON, ``canonical_data``).

    Empty ``artifact_refs`` are left out, so a ``StoredEvidence`` with no refs and the plain
    ``Evidence`` it extends store, load (as ``Evidence``) and digest the same. Otherwise an
    honest gate whose evidence gained a ``StoredEvidence`` wrapper would see a changed digest.
    """
    wire = to_wire(validate_verdict(verdict))
    if not wire["evidence"].get("artifact_refs", True):
        del wire["evidence"]["artifact_refs"]
    return canonical_data(wire)


def verdict_from_data(data: Mapping[str, Any]) -> Verdict:
    """Rebuild and validate a stored verdict. Evidence with ``artifact_refs`` loads as
    :class:`StoredEvidence`, anything else (refs are not stored when empty) as ``Evidence``."""
    if not isinstance(data, Mapping):
        raise TypeError(f"verdict data must be an object, not {type(data).__name__}")
    extra = set(data) - {"evidence", "valid", "reason", "notes"}
    if extra:
        raise ValueError(f"unexpected fields for Verdict: {sorted(extra)}")
    raw = data.get("evidence")
    if not isinstance(raw, Mapping):
        raise TypeError("verdict evidence must be an object")
    evidence = from_wire(StoredEvidence if "artifact_refs" in raw else Evidence, dict(raw))
    notes = data.get("notes", ())
    if not isinstance(notes, list | tuple):
        raise TypeError("verdict notes must be a list")
    if "valid" not in data:
        raise ValueError("verdict data needs valid")
    return validate_verdict(Verdict(evidence, data["valid"], data.get("reason", ""), tuple(notes)))


def evidence_digest(verdicts: Iterable[Verdict]) -> str:
    """Digest of what the human is shown as evidence: each verdict with its notes and refs, in a
    fixed order. Every verdict is validated first."""
    stored = [verdict_to_data(v) for v in verdicts]
    stored.sort(key=lambda d: json.dumps(d, sort_keys=True))
    return _hash({"v": 1, "verdicts": stored})


# --- rounds -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RoundRecord:
    """A gate round as stored: enough to link the next one and to build its interdiff.
    ``diff_ref`` points at the canonical diff stored for that round."""

    gate_id: GateId
    name: str
    round: int
    subject: Subject
    diff_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.gate_id, GateId):
            raise TypeError("round gate_id must be a GateId")
        _nonblank("round name", self.name)
        if type(self.round) is not int:
            raise TypeError("round number must be an int")
        if self.round < 1:
            raise ValueError("round number starts at 1")
        if not isinstance(self.subject, Subject):
            raise TypeError("round subject must be a Subject")
        _nonblank("round diff_ref", self.diff_ref)

    @classmethod
    def from_gate(cls, gate: Gate, diff_ref: str) -> RoundRecord:
        return cls(gate.id, gate.name, gate.round, gate.subject, diff_ref)


@dataclass(frozen=True)
class Interdiff:
    """What changed since the last round: both revisions, patch ids and stored diffs. The
    revision is ``head_sha``, or ``base_sha`` for a pre-push subject."""

    from_round: int
    to_round: int
    from_rev: str
    to_rev: str
    from_patch_id: str
    to_patch_id: str
    from_diff_ref: str
    to_diff_ref: str

    @property
    def patch_changed(self) -> bool:
        return self.from_patch_id != self.to_patch_id


@dataclass(frozen=True)
class RoundPlan:
    name: str
    round: int
    previous_gate_id: GateId | None
    subject: Subject
    diff_ref: str
    check: EvidenceCheck
    interdiff: Interdiff | None


def _rev(subject: Subject) -> str:
    rev = subject.head_sha if subject.head_sha is not None else subject.base_sha
    assert rev is not None  # Subject guarantees exactly one
    return rev


def _check_merges(
    name: str, subject: Subject, merges: Collection[tuple[str | None, str | None]]
) -> None:
    pairs: set[tuple[str, str]] = set()
    for merge in merges:
        merge_sha, head_sha = merge
        if not (
            isinstance(merge_sha, str)
            and merge_sha.strip()
            and isinstance(head_sha, str)
            and head_sha.strip()
        ):
            raise MergedCodeChangedError(f"gate {name!r}: merge record {merge!r} is incomplete")
        pairs.add((merge_sha, head_sha))
    if not pairs:
        if subject.merge_sha is not None:
            raise MergedCodeChangedError(
                f"gate {name!r}: the subject names merge_sha {subject.merge_sha} but nothing merged"
            )
        return
    if subject.head_sha is None:
        raise MergedCodeChangedError(f"gate {name!r}: merged code cannot change; no head subject")
    if (subject.merge_sha, subject.head_sha) not in pairs:
        raise MergedCodeChangedError(
            f"gate {name!r}: merged code cannot change; "
            f"({subject.merge_sha}, {subject.head_sha}) is not a recorded merge"
        )


def plan_round(
    *,
    name: str,
    gate_type: GateType,
    previous: RoundRecord | None,
    subject: Subject,
    diff_ref: str,
    evidence: Mapping[str, Sequence[Evidence]],
    expected_stages: Collection[str],
    contained: Containment | None = None,
    merges: Collection[tuple[str | None, str | None]] = (),
) -> RoundPlan:
    """Decide whether round ``previous.round + 1`` of gate ``name`` may open, or raise.

    ``evidence`` maps a stage to its records; ``expected_stages`` are the stages whose evidence
    the gate judges (for a ``qa`` gate, V14's evidence stages). ``merges`` are the run's
    confirmed merges as ``(merge_sha, head_sha)`` pairs. See the module docstring for the rules.
    """
    _nonblank("gate name", name)
    _nonblank("diff_ref", diff_ref)
    gate_type = GateType(gate_type)
    if (gate_type is GateType.PRE_PUSH) != (subject.head_sha is None):
        raise GateRoundError(
            f"gate {name!r}: only a pre_push gate takes a pre-push subject, and it must"
        )
    _check_merges(name, subject, merges)
    if previous is not None and previous.name != name:
        raise GateRoundError(
            f"gate {name!r} cannot follow round {previous.round} of gate {previous.name!r}"
        )

    expected = tuple(sorted(set(expected_stages)))
    if gate_type is GateType.QA and not expected:
        raise IncompleteEvidenceError(
            f"gate {name!r}: a qa gate must expect evidence (V14), but expects none", ()
        )
    missing = tuple(s for s in expected if not evidence.get(s))
    if missing:
        raise IncompleteEvidenceError(
            f"gate {name!r} lacks evidence from: {', '.join(missing)}", missing
        )
    records: list[Evidence] = []
    for stage in sorted(evidence):
        for record in evidence[stage]:
            if not isinstance(record, Evidence):
                raise TypeError(f"evidence from {stage!r} must be Evidence")
            records.append(record)
    check = check_all(records, subject, contained)  # a malformed containment answer raises here
    if check.failures:
        reasons = "; ".join(v.reason for v in check.failures)
        raise EvidenceInvalidError(f"gate {name!r} evidence is not valid: {reasons}", check)
    if subject.head_sha is not None and subject.evidence_digest != evidence_digest(check.verdicts):
        raise GateRoundError(
            f"gate {name!r}: the subject's evidence_digest is not that of the evidence checked"
        )

    interdiff = None
    if previous is not None:
        interdiff = Interdiff(
            from_round=previous.round,
            to_round=previous.round + 1,
            from_rev=_rev(previous.subject),
            to_rev=_rev(subject),
            from_patch_id=previous.subject.patch_id,
            to_patch_id=subject.patch_id,
            from_diff_ref=previous.diff_ref,
            to_diff_ref=diff_ref,
        )
    return RoundPlan(
        name=name,
        round=1 if previous is None else previous.round + 1,
        previous_gate_id=None if previous is None else previous.gate_id,
        subject=subject,
        diff_ref=diff_ref,
        check=check,
        interdiff=interdiff,
    )
