"""Definition-of-done checks (D2-16, PLAN 6.1 ``definition_of_done``).

Machine-evaluated conditions, run **before a gate opens** or before a stage exits. They are a
registry of named evaluators (``CHECKS``); the config names one and the schema has already
restricted the name and checked its ``value``. There are no free-form expressions (ADR-0006).

Everything here is pure and deterministic: no clocks, no context variables, no I/O. The driver
reads the evidence and passes it in as ``DodFacts``; the evaluators only judge it. The rules:

* Fail closed. A fact the driver could not read is ``None``, and ``None`` is never done. A
  malformed fact (NaN coverage, a ``bool`` for a number, an unknown severity or status) is not
  done either, and neither is a check name this registry does not know, a ``value`` the schema
  would have refused, or an evaluator that raises. None of these raises out of ``evaluate``.
* A failure says what is missing, in words a person can act on (``Failure.reason``).
* Check results count only for the head SHA the stage is about (a re-run on another SHA is
  stale evidence).

Wiring (D2-29 owns ``reducer.py`` and ``stages.py``, so it is not done here): ``refusal`` is the
one call. A ``StageEntry.refuse`` for a gate (and the exit of a stage that has entries) builds
``DodFacts`` from the run's evidence and returns ``refusal(wf.definition_of_done, name, facts)``;
a non-``None`` result BLOCKS the run with ``Refusal.reason`` (``definition_of_done_failed``)
before any counter moves, and ``Refusal.detail`` is the message to show. Because the
check happens at entry, a gate is never opened with a failed check.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

from sto.config.schema import SEVERITIES
from sto.domain import BLOCKED_REASONS

BLOCKED_REASON = "definition_of_done_failed"


@BLOCKED_REASONS.register(BLOCKED_REASON)
class DefinitionOfDoneFailed:
    pass


@dataclass(frozen=True)
class CheckStatus:
    """One check's latest status: ``passed``, ``failed``, ``pending`` or ``neutral``."""

    name: str
    status: str


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str


@dataclass(frozen=True)
class DodFacts:
    """The evidence. ``None`` means missing or unreadable, which no check accepts.

    ``check_sha`` is the SHA the ``check_results`` were reported for; ``head_sha`` is the head
    the stage is about. ``required_checks`` (optional) are names that must be present."""

    head_sha: str | None = None
    acceptance_criteria: tuple[str, ...] | None = None
    check_sha: str | None = None
    check_results: tuple[CheckStatus, ...] | None = None
    required_checks: tuple[str, ...] = ()
    coverage: float | None = None
    findings: tuple[Finding, ...] | None = None


class Entry(Protocol):
    """What an evaluation needs of a ``DefinitionOfDone`` config entry."""

    @property
    def stage(self) -> str: ...
    @property
    def check(self) -> str: ...
    @property
    def value(self) -> object: ...


@dataclass(frozen=True)
class Failure:
    stage: str
    check: str
    reason: str


@dataclass(frozen=True)
class Refusal:
    """Why a gate or stage exit is held: the blocked ``reason`` and a readable ``detail``."""

    reason: str
    detail: str
    failures: tuple[Failure, ...]


Evaluator = Callable[[object, DodFacts], str | None]
CHECKS: dict[str, Evaluator] = {}
_PASSING = frozenset({"passed", "neutral"})


def check(name: str) -> Callable[[Evaluator], Evaluator]:
    def deco(fn: Evaluator) -> Evaluator:
        if name in CHECKS:
            raise ValueError(f"definition-of-done check {name!r} already registered")
        CHECKS[name] = fn
        return fn

    return deco


def _number(v: object) -> float | None:
    if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v):
        return None
    return float(v)


@check("ac_present")
def _ac_present(value: object, facts: DodFacts) -> str | None:
    crit = facts.acceptance_criteria
    if crit is None:
        return "the acceptance criteria could not be read"
    if not any(isinstance(c, str) and c.strip() for c in crit):
        return "the ticket has no acceptance criteria"
    return None


@check("checks_green")
def _checks_green(value: object, facts: DodFacts) -> str | None:
    results = facts.check_results
    if not results:
        return "no check results are available"
    head, sha = facts.head_sha, facts.check_sha
    if head is None or sha is None:
        return "the check results cannot be tied to the head commit"
    if sha != head:
        return f"the check results are stale: they are for {sha[:7]}, the head is {head[:7]}"
    seen: dict[str, set[str]] = {}
    for r in results:
        seen.setdefault(r.name, set()).add(r.status)
    missing = [n for n in facts.required_checks if n not in seen]
    bad = sorted(
        (n, ", ".join(sorted(s - _PASSING)) or "reported twice")
        for n, s in seen.items()
        if len(s) > 1 or not s <= _PASSING
    )
    parts = []
    if missing:
        parts.append("missing required checks: " + ", ".join(missing))
    if bad:
        parts.append("not green: " + ", ".join(f"{n} ({st})" for n, st in bad))
    return "; ".join(parts) or None


@check("coverage_at_least")
def _coverage_at_least(value: object, facts: DodFacts) -> str | None:
    need = _number(value)
    if need is None or not 0 <= need <= 100:
        return f"the coverage threshold {value!r} is not a number from 0 to 100"
    have = _number(facts.coverage)
    if have is None or not 0 <= have <= 100:
        return "the coverage could not be read"
    if have < need:
        return f"coverage is {have:g}%, below the required {need:g}%"
    return None


@check("no_findings_above")
def _no_findings_above(value: object, facts: DodFacts) -> str | None:
    if not isinstance(value, str) or value not in SEVERITIES:
        return f"the findings threshold {value!r} is not one of {', '.join(SEVERITIES)}"
    if facts.findings is None:
        return "the findings could not be read"
    limit = SEVERITIES.index(value)
    over = [
        f
        for f in facts.findings
        if f.severity not in SEVERITIES or SEVERITIES.index(f.severity) > limit
    ]
    if not over:
        return None
    names = "; ".join(f"{f.title} ({f.severity})" for f in over)
    return f"{len(over)} finding(s) above {value}: {names}"


def evaluate(entries: Iterable[Entry], stage: str, facts: DodFacts | None) -> tuple[Failure, ...]:
    """The failures of every entry for ``stage``, in config order. Empty means done."""
    out: list[Failure] = []
    for e in entries:
        if e.stage != stage:
            continue
        out.append(f) if (f := _one(e, facts)) else None
    return tuple(out)


def _one(e: Entry, facts: DodFacts | None) -> Failure | None:
    fn = CHECKS.get(e.check)
    if fn is None:
        return Failure(e.stage, e.check, f"unknown check {e.check!r}")
    if facts is None:
        return Failure(e.stage, e.check, "no evidence was supplied")
    try:
        why = fn(e.value, facts)
    except Exception:  # noqa: BLE001 - an evaluator that breaks is not done
        return Failure(e.stage, e.check, "the check could not be evaluated")
    return None if why is None else Failure(e.stage, e.check, why)


def refusal(entries: Iterable[Entry], stage: str, facts: DodFacts | None) -> Refusal | None:
    """``None`` if the stage may open or exit; otherwise the block and what is missing."""
    failures = evaluate(entries, stage, facts)
    if not failures:
        return None
    detail = "; ".join(f"{f.check}: {f.reason}" for f in failures)
    return Refusal(BLOCKED_REASON, f"stage {stage!r} is not done: {detail}", failures)
