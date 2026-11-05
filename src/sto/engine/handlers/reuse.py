"""Same-patch result reuse (D2-21, PLAN 4.5, 4.6 and 6.2): when may a stage skip running again?

After a base update the head SHA moves but the patch usually does not. A ``review_panel`` and a
QA ``agent`` stage may then reuse the result of their last run, under ``same_patch`` validity
(D2-22, ``gates/evidence.py``). A ``checks`` stage never does: CI and QA suites always run at the
new SHA.

This module only decides, as a pure function; it plans no command and touches no state. The
workflow and manifest are passed in. The driver asks ``decide_reuse`` when it enters a stage,
replays ``ReuseDecision.outcome`` when told to, and stores ``ReuseDecision.to_data()`` so the
decision is recorded either way. When it records a result it stores ``stage_digest`` with it.

Rules, all fail closed (any doubt re-runs, and the reason says which):

* The kind of stage comes from the stage named in the evidence key ``EV#stage#ulid`` looked up in
  the workflow, never from a name the caller passes. A key naming a ``checks`` stage, a stage the
  workflow lacks, or a kind that cannot be reused is refused. A malformed key refuses, and so does
  a tie for the newest key (ambiguous).
* Only the latest result for the stage decides. An older one is never a fallback, because a newer
  run that did not match is the more recent truth.
* The result must belong to this run's partition (``TEAM#t#RUN#r``).
* The evidence must be ``same_patch`` and valid for the subject (``check_evidence`` owns the
  test, so ``patch_id`` comparison is not reimplemented here). A missing subject or evidence
  re-runs.
* The result is bound to the configuration that produced it: ``stage_digest`` (block_on, required
  and optional reviewers, fail_closed, the agent, model tier, and each profile's tier, tools,
  manifest outcomes and prompt version and digest) must be recorded
  and equal today's, because runs migrate (PLAN 7.4) and org floors are live.
* A panel must have run exactly the reviewers it has now, and every ``required`` one of them. A
  ``degraded`` panel is never reused.
* An agent stage is reused only when it is a QA stage (``qa_evidence_stages``: its profile has
  ``record_evidence``) whose profile cannot write code (``code_changing_stages``); a triage,
  refiner or planner agent is read-only but is never replayed. It must be the same single agent,
  and the QA result must have been recorded for the same ``ticket_revision`` (PLAN 4.6: no carry
  across a QA retest). An ``inconclusive`` result is never reused.
* The recorded run must have been read-only (an extra condition, never the sole basis).

The older-base note of D2-22 is carried on the decision, naming the tested SHA.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sto.agents.prompts.render import PromptTemplate
from sto.config.manifest import Manifest
from sto.config.schema import AgentStage, ChecksStage, ReviewPanelStage
from sto.config.schema import Workflow as Graph
from sto.config.validate_gates import code_changing_stages, qa_evidence_stages
from sto.domain import Subject
from sto.gates.evidence import OLDER_BASE_NOTE, Evidence, Validity, check_evidence

# ULID: 26 Crockford base32 characters, upper case, no I L O U; the first is 0-7 (48-bit time).
_KEY = re.compile(r"EV#([a-z][a-z0-9_]*)#([0-7][0-9A-HJKMNP-TV-Z]{25})")
_PANEL_REUSABLE = frozenset({"clean", "findings"})  # "degraded" means a reviewer was missing
_NOT_REUSABLE_QA = frozenset({"inconclusive"})


def parse_evidence_key(key: object) -> tuple[str, str] | None:
    """``EV#stage#ulid`` to ``(stage, ulid)``, or ``None`` when it is not exactly that."""
    if not isinstance(key, str):
        return None
    m = _KEY.fullmatch(key)
    return (m.group(1), m.group(2)) if m else None


def _bind(
    wf: Graph, manifest: Manifest, stage: str, prompts: Mapping[str, PromptTemplate] | None
) -> tuple[str | None, str]:
    """``(digest, "")``, or ``(None, reason)`` where reason is ``unknown_profile``,
    ``prompt_missing`` or ``not_bindable``."""
    st = wf.stages.get(stage)
    if isinstance(st, ReviewPanelStage):
        names = list(st.reviewers)
    elif isinstance(st, AgentStage):
        names = [st.agent]
    else:
        return None, "not_bindable"

    bound: dict[str, Any] = {}
    for name in sorted(set(names)):
        p = manifest.profiles.get(name)
        if p is None:
            return None, "unknown_profile"
        t = prompts.get(name) if prompts is not None else None
        # Fail closed: a prompt we cannot identify (absent, wrong type, filed under another
        # name, or with a blank version or text) binds nothing, so nothing is reused.
        if (
            not isinstance(t, PromptTemplate)
            or t.name != name
            or not t.version.strip()
            or not t.text.strip()
        ):
            return None, "prompt_missing"
        bound[name] = {
            "role": p.role,
            "tier": p.default_tier,
            "tools": sorted(p.tools),
            "outcomes": sorted(p.outcomes),
            "orchestrator": p.orchestrator,
            # The catalog has no prompt version, so bind the template's own version and its
            # digest (name, version and text): an edit without a version bump still shows.
            "prompt": {"version": t.version, "sha256": t.sha256},
        }

    body: dict[str, Any]
    if isinstance(st, ReviewPanelStage):
        body = {
            "kind": "review_panel",
            "block_on": st.block_on,
            "fail_closed": st.fail_closed,
            "reviewers": sorted(st.reviewers),
            "required": sorted(st.required),
            "profiles": bound,
        }
    else:
        assert isinstance(st, AgentStage)
        body = {
            "kind": "agent",
            "agent": st.agent,
            "model_tier": st.model_tier,
            "outcomes": sorted(st.next),
            "profile": bound[st.agent],
        }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest(), ""


def stage_digest(
    wf: Graph,
    manifest: Manifest,
    stage: str,
    prompts: Mapping[str, PromptTemplate] | None = None,
) -> str | None:
    """A digest of the configuration that decides a panel or agent stage's result, or ``None``.

    ``prompts`` maps each reviewer or agent profile name to its ``PromptTemplate``. The digest
    binds, per profile, the manifest's role, tier, tools and outcomes and the prompt's version
    and digest, so a prompt or outcome change gives a different digest. ``None`` when the stage
    is not a panel or agent stage, a profile it uses is unknown, or a profile has no prompt
    (nothing is bound to what cannot be identified, so nothing is reused)."""
    return _bind(wf, manifest, stage, prompts)[0]


@dataclass(frozen=True)
class PriorResult:
    """A stored result of an earlier run of a stage.

    ``participants`` are the reviewers that ran (a panel) or the agent that ran (``(agent,)``).
    ``read_only`` is true when the run had no write access to the workspace. ``config_digest`` is
    ``stage_digest`` at the time, ``partition`` the ``TEAM#t#RUN#r`` it was stored under, and
    ``ticket_revision`` the ticket text a QA result was judged against.
    """

    key: str
    evidence: Evidence
    outcome: str
    participants: tuple[str, ...]
    read_only: bool
    config_digest: str | None = None
    partition: str | None = None
    ticket_revision: str | None = None


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


def _blank(value: object) -> bool:
    return not isinstance(value, str) or not value.strip()


def decide_reuse(
    wf: Graph,
    manifest: Manifest,
    stage: str,
    candidates: Iterable[PriorResult],
    subject: Subject | None,
    partition: str,
    *,
    prompts: Mapping[str, PromptTemplate] | None = None,
) -> ReuseDecision:
    """May ``stage`` reuse one of ``candidates`` (earlier results) for ``subject``?

    ``partition`` is the ``TEAM#t#RUN#r`` the candidates must have been stored under.
    ``prompts`` maps each reviewer or agent profile name to its prompt; without one the digest
    cannot be checked and the stage re-runs."""
    found = list(candidates)
    if not found:
        return _run(stage, "no_prior_result")
    keyed: list[tuple[str, str, PriorResult]] = []
    for p in found:
        if not isinstance(p, PriorResult) or (parsed := parse_evidence_key(p.key)) is None:
            return _run(stage, "bad_key")
        if not _well_formed(p):
            return _run(stage, "bad_record")
        keyed.append((parsed[0], parsed[1], p))
    pool = [k for k in keyed if k[0] == stage] or keyed
    newest = max(k[1] for k in pool)
    top = [k for k in pool if k[1] == newest]
    if len(top) > 1:
        return _run(stage, "ambiguous")
    chosen_stage, _, prior = top[0]

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

    if _blank(partition) or prior.partition != partition:
        return _run(stage, "other_run")
    if subject is None:
        return _run(stage, "no_subject")
    if not isinstance(prior.evidence, Evidence):
        return _run(stage, "no_evidence")
    if prior.evidence.validity is not Validity.SAME_PATCH:
        return _run(stage, "validity_not_same_patch")
    if prior.read_only is not True:
        return _run(stage, "not_read_only")

    ran = tuple(sorted(prior.participants))  # a tuple, so a participant listed twice shows
    if isinstance(kind, ReviewPanelStage):
        if prior.outcome not in _PANEL_REUSABLE:
            return _run(stage, "outcome_not_reusable")
        if ran != tuple(sorted(kind.reviewers)) or not frozenset(kind.required) <= frozenset(ran):
            return _run(stage, "reviewer_set_changed")
    else:
        if prior.participants != (kind.agent,):
            return _run(stage, "agent_changed")
        # Only a QA agent is replayed; a triage, refiner or planner is read-only but never is.
        if stage not in qa_evidence_stages(wf, manifest) or stage in code_changing_stages(
            wf, manifest
        ):
            return _run(stage, "not_qa_stage")
        if prior.outcome not in kind.next or prior.outcome in _NOT_REUSABLE_QA:
            return _run(stage, "outcome_not_reusable")
        if prior.ticket_revision != subject.ticket_revision:
            return _run(stage, "ticket_changed")

    current, why = _bind(wf, manifest, stage, prompts)
    if current is None:
        return _run(stage, why)
    if _blank(prior.config_digest):
        return _run(stage, "config_digest_missing")
    if prior.config_digest != current:
        return _run(stage, "config_changed")

    verdict = check_evidence(prior.evidence, subject)
    if not verdict.valid:
        return _run(stage, "patch_changed")
    tested = prior.evidence.tested_sha
    notes = tuple(f"{n} ({tested})" if n == OLDER_BASE_NOTE else n for n in verdict.notes)
    return ReuseDecision(stage, True, "same_patch", prior.key, prior.outcome, notes)
