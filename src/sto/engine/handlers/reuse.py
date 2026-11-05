"""Same-patch result reuse (D2-21, PLAN 4.5 and 6.2): when may a stage skip running again?

After a base update the head SHA moves but the patch usually does not. A ``review_panel`` and an
``agent`` stage may then reuse the result of their last run, under ``same_patch`` validity (D2-22,
``gates/evidence.py``). A ``checks`` stage never does: CI and QA suites always run at the new SHA.

This module only decides, as a pure function; it plans no command and touches no state. The
driver asks ``decide_reuse`` when it enters a stage, replays ``ReuseDecision.outcome`` when told
to, and stores ``ReuseDecision.to_data()`` so the decision is recorded either way.

Rules, all fail closed (any doubt re-runs, and the reason says which):

* The kind of stage comes from the stage named in the evidence key ``EV#stage#ulid`` looked up in
  the workflow, never from a name the caller passes. A key naming a ``checks`` stage, a stage the
  workflow lacks, or a kind that cannot be reused is refused. A malformed key refuses.
* Only the latest result for the stage decides. An older one is never a fallback, because a newer
  run that did not match is the more recent truth.
* The evidence must be ``same_patch`` and valid for the subject (``check_all`` owns the test, so
  ``patch_id`` comparison is not reimplemented here). A missing subject or evidence re-runs.
* A panel must have run exactly the reviewers it has now, and every ``required`` one of them: a
  new reviewer, required or not, or a dropped one, re-runs it. An agent stage must be the same
  agent. A ``degraded`` panel is never reused.
* The recorded run must have been read-only: a stage that could write code is not reused.

The older-base note of D2-22 is carried on the decision so the gate page can show it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sto.config.schema import AgentStage, ChecksStage, ReviewPanelStage
from sto.config.schema import Workflow as Graph
from sto.domain import Subject
from sto.gates.evidence import Evidence, Validity, check_evidence

_KEY = re.compile(r"EV#([^#\s]+)#([0-9A-HJKMNP-TV-Z]{26})")
_PANEL_REUSABLE = frozenset({"clean", "findings"})  # "degraded" means a reviewer was missing


def parse_evidence_key(key: object) -> tuple[str, str] | None:
    """``EV#stage#ulid`` to ``(stage, ulid)``, or ``None`` when it is not exactly that."""
    if not isinstance(key, str):
        return None
    m = _KEY.fullmatch(key)
    return (m.group(1), m.group(2)) if m else None


@dataclass(frozen=True)
class PriorResult:
    """A stored result of an earlier run of a stage.

    ``participants`` are the reviewers that ran (a panel) or the agent that ran (``(agent,)``).
    ``read_only`` is true when the run had no write access to the workspace.
    """

    key: str
    evidence: Evidence
    outcome: str
    participants: tuple[str, ...]
    read_only: bool


@dataclass(frozen=True)
class ReuseDecision:
    """Reuse the result (``reuse``), or run the stage again (``reason`` says why)."""

    stage: str
    reuse: bool
    reason: str
    key: str | None = None
    outcome: str | None = None
    notes: tuple[str, ...] = ()

    def to_data(self) -> dict[str, Any]:
        """The recorded form: plain JSON."""
        return {
            "stage": self.stage,
            "reuse": self.reuse,
            "reason": self.reason,
            "evidence": self.key,
            "outcome": self.outcome,
            "notes": list(self.notes),
        }


def _run(stage: str, reason: str) -> ReuseDecision:
    return ReuseDecision(stage, False, reason)


def _well_formed(p: object) -> bool:
    return (
        isinstance(p, PriorResult)
        and isinstance(p.outcome, str)
        and isinstance(p.participants, tuple)
        and all(isinstance(x, str) and x.strip() for x in p.participants)
    )


def decide_reuse(
    wf: Graph, stage: str, candidates: Iterable[PriorResult], subject: Subject | None
) -> ReuseDecision:
    """May ``stage`` reuse one of ``candidates`` (earlier results for this run) for ``subject``?"""
    found = list(candidates)
    if not found:
        return _run(stage, "no_prior_result")
    keyed: list[tuple[str, str, PriorResult]] = []
    for p in found:
        parsed = parse_evidence_key(getattr(p, "key", None))
        if parsed is None or not _well_formed(p):
            return _run(stage, "bad_key" if parsed is None else "bad_record")
        keyed.append((parsed[0], parsed[1], p))
    own = [k for k in keyed if k[0] == stage]
    chosen_stage, _, prior = max(own or keyed, key=lambda k: k[1])

    # The kind is the one the key's stage has in the workflow, never a name the caller passes.
    kind = wf.stages.get(chosen_stage)
    if kind is None:
        return _run(stage, "unknown_stage")
    if isinstance(kind, ChecksStage):
        return _run(stage, "checks_never_reused")
    if not isinstance(kind, AgentStage | ReviewPanelStage):
        return _run(stage, "kind_not_reusable")
    if chosen_stage != stage:
        return _run(stage, "stage_mismatch")

    if subject is None:
        return _run(stage, "no_subject")
    if not isinstance(prior.evidence, Evidence):
        return _run(stage, "no_evidence")
    if prior.evidence.validity is not Validity.SAME_PATCH:
        return _run(stage, "validity_not_same_patch")
    if prior.read_only is not True:
        return _run(stage, "not_read_only")

    ran = frozenset(prior.participants)
    if isinstance(kind, ReviewPanelStage):
        if prior.outcome not in _PANEL_REUSABLE:
            return _run(stage, "outcome_not_reusable")
        if ran != frozenset(kind.reviewers) or not frozenset(kind.required) <= ran:
            return _run(stage, "reviewer_set_changed")
    else:
        if prior.outcome not in kind.next:
            return _run(stage, "outcome_not_reusable")
        if prior.participants != (kind.agent,):
            return _run(stage, "agent_changed")

    verdict = check_evidence(prior.evidence, subject)
    if not verdict.valid:
        return _run(stage, "patch_changed")
    return ReuseDecision(stage, True, "same_patch", prior.key, prior.outcome, verdict.notes)
