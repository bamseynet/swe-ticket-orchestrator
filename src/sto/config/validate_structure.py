"""The structural validator (D2-03): V1, V2, V3, V7, V8, V9, V10, V13 and V15 of PLAN 7.3.

``validate_structure`` is a pure function of a flattened ``Workflow``, the catalog ``Manifest``
and the live ``OrgPolicy``. It reports every problem it finds, never just the first, as an
``Issue`` whose ``path`` names the stage (``stages.<id>...``) and whose message says how to fix
it. The gate-dominance rules (V4, V5, V6, V11, V14) are D2-04's; V17 is ``org_policy``'s.

* **V1** every reference resolves (``start``, ``on_external_commit``, edge targets,
  ``requires_gates``, ``definition_of_done``); every stage is reachable from ``start`` or
  ``on_external_commit``; a terminal is reachable from every stage.
* **V2** every stage has exactly the edges its kind produces: an agent's from its profile, an
  effect's from the catalog, a gate's from its ``decisions`` and ``expire_after``, a route's
  ``default``, and no edge outside the route's ``order``.
* **V3** every cycle contains an edge with a named ``loop`` whose limit is declared, at most the
  platform cap and at most the org's ``max_loop``. The cycle is printed.
* **V7** a gate has eligible roles, each quorum role is eligible and appears once, and a gate
  that sets ``escalate_after`` also sets ``escalate_to`` (the timers refuse it at run time).
  (A gate has no ``auto_approve`` key and no ``timeout`` outcome: the schema refuses both.)
* **V8** an ``expired`` or ``rejected`` edge cannot reach a gated effect. For each effect the
  search does not follow the ``approved`` edge of a gate in that effect's ``requires_gates``,
  since that approval is what earns it; another gate's approval is no help.
* **V9** ``max_steps_per_run``, ``max_run_age`` and loop limits are within the platform caps and
  the org ceilings; every stage duration (wait, checks, gate timeouts) is at most ``max_run_age``
  and ``max_stage_duration``; a route's ``order`` agrees with the org's ordering; a team's budget
  is within ``max_run_usd`` (``check_budget_ceilings``, run by ``validate_structure`` only when
  it is given the ``team_config``; without it no budget is checked). The tier and the tools of a
  profile are fixed by the manifest, which a workflow cannot override, so there is nothing to
  check there.
* **V10** every decision surface is permitted for the gate's type (a type the org does not name
  permits none), ``github`` only on a ``review`` gate, ``waive`` only if the org allows it.
* **V13** a review panel has reviewers and required reviewers (each required one on the panel);
  a ``checks`` stage has a required check or ``team_default`` (re-checked at run time).
* **V15** a mandatory gate (``pre_push``, ``review``, ``qa``) lists only roles the org gives that
  type; ``with`` is typed by the catalog, so an unknown key, a missing required key or a value
  of the wrong type is refused; sandbox images are registered, when a registry is given.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Collection, Iterable, Mapping
from typing import Any

from sto.config.manifest import Manifest, WithKey
from sto.config.org_policy import mandatory_roles, permitted_surfaces
from sto.config.schema import (
    MANDATORY_GATES,
    PLATFORM_MAX_STEPS,
    AgentStage,
    ChecksStage,
    Edge,
    EffectStage,
    GateStage,
    Issue,
    OrgPolicy,
    ReviewPanelStage,
    RouteStage,
    TeamConfig,
    TerminalStage,
    WaitStage,
    Workflow,
    duration_seconds,
)

__all__ = ["check_budget_ceilings", "check_route_orders", "validate_structure"]

_IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
_GATE_ALWAYS = frozenset({"approved", "changes_requested", "rejected"})
_PANEL_OUTCOMES = frozenset({"clean", "findings", "degraded"})
_CHECKS_OUTCOMES = frozenset({"green", "red"})
_WAIT_OUTCOMES = frozenset({"resumed", "timeout"})


def _edges(stage: Any) -> list[tuple[str, str, str | None]]:
    """(outcome, target, loop name) for each edge of a stage; a terminal has none."""
    if isinstance(stage, TerminalStage):
        return []
    out: list[tuple[str, str, str | None]] = []
    for outcome, edge in stage.next.items():
        if isinstance(edge, Edge):
            out.append((outcome, edge.to, edge.loop))
        else:
            out.append((outcome, edge, None))
    return out


def _at(sid: str, *rest: str) -> str:
    return ".".join(("stages", sid, *rest))


def _words(names: Iterable[str]) -> str:
    return ", ".join(sorted(names))


# --- V1 ------------------------------------------------------------------------------------


def _v1(wf: Workflow) -> list[Issue]:
    issues: list[Issue] = []
    stages = wf.stages
    if wf.start not in stages:
        issues.append(
            Issue(
                None,
                "start",
                f"start names {wf.start}, which is not a stage; use one of: {_words(stages)}",
            )
        )
    if wf.on_external_commit is not None and wf.on_external_commit not in stages:
        issues.append(
            Issue(
                None,
                "on_external_commit",
                f"on_external_commit names {wf.on_external_commit}, which is not a "
                "stage; name the stage a commit by someone else re-enters",
            )
        )
    for dod in wf.definition_of_done:
        if dod.stage not in stages:
            issues.append(
                Issue(
                    None,
                    "definition_of_done",
                    f"definition_of_done names stage {dod.stage}, which does not "
                    "exist; name an existing stage",
                )
            )
    for sid, stage in stages.items():
        for outcome, target, _ in _edges(stage):
            if target not in stages:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "next", outcome),
                        f"stage {sid}: the {outcome} edge goes to {target}, which is "
                        "not a stage; fix the name or add the stage",
                    )
                )
        if isinstance(stage, EffectStage):
            for gate_id in stage.requires_gates or ():
                gate = stages.get(gate_id)
                if gate is None:
                    issues.append(
                        Issue(
                            None,
                            _at(sid, "requires_gates"),
                            f"stage {sid} requires gate {gate_id}, which does not "
                            "exist; name a gate stage",
                        )
                    )
                elif not isinstance(gate, GateStage):
                    issues.append(
                        Issue(
                            None,
                            _at(sid, "requires_gates"),
                            f"stage {sid} requires {gate_id}, but {gate_id} is not a "
                            "gate; name a gate stage",
                        )
                    )
    issues.extend(_reachability(wf))
    return issues


def _reachability(wf: Workflow) -> list[Issue]:
    stages = wf.stages
    roots = [r for r in (wf.start, wf.on_external_commit) if r is not None and r in stages]
    seen: set[str] = set()
    queue = deque(roots)
    while queue:
        sid = queue.popleft()
        if sid in seen:
            continue
        seen.add(sid)
        queue.extend(t for _, t, _ in _edges(stages[sid]) if t in stages)
    issues = [
        Issue(
            None,
            _at(sid),
            f"stage {sid} is unreachable from start; add an edge to it from a "
            "reachable stage, or remove it",
        )
        for sid in stages
        if sid not in seen
    ]
    back: dict[str, list[str]] = {sid: [] for sid in stages}
    for sid, stage in stages.items():
        for _, target, _ in _edges(stage):
            if target in back:
                back[target].append(sid)
    ends = {sid for sid, st in stages.items() if isinstance(st, TerminalStage)}
    can_end: set[str] = set()
    queue = deque(ends)
    while queue:
        sid = queue.popleft()
        if sid in can_end:
            continue
        can_end.add(sid)
        queue.extend(back[sid])
    issues.extend(
        Issue(
            None,
            _at(sid),
            f"stage {sid} has no path to a terminal, so a run there is stuck; "
            "add an edge that leads to one",
        )
        for sid in stages
        if sid not in can_end
    )
    return issues


# --- V2 ------------------------------------------------------------------------------------


def _expected_outcomes(
    sid: str, stage: Any, manifest: Manifest
) -> tuple[frozenset[str] | None, list[Issue]]:
    """The outcomes a stage must have edges for, or ``None`` if they cannot be known."""
    if isinstance(stage, AgentStage):
        profile = manifest.profiles.get(stage.agent)
        if profile is None:
            return None, [
                Issue(
                    None,
                    _at(sid, "agent"),
                    f"stage {sid}: agent {stage.agent} is not a profile in the "
                    f"catalog; use one of: {_words(_orchestrators(manifest))}",
                )
            ]
        if profile.role != "orchestrator":
            return None, [
                Issue(
                    None,
                    _at(sid, "agent"),
                    f"stage {sid}: {stage.agent} is a worker, which cannot run a "
                    f"stage; use an orchestrator: {_words(_orchestrators(manifest))}",
                )
            ]
        return profile.outcomes, []
    if isinstance(stage, ReviewPanelStage):
        return _PANEL_OUTCOMES, []
    if isinstance(stage, ChecksStage):
        return _CHECKS_OUTCOMES, []
    if isinstance(stage, WaitStage):
        return _WAIT_OUTCOMES, []
    if isinstance(stage, GateStage):
        gate = stage.gate
        want = set(_GATE_ALWAYS)
        if "retest" in gate.decisions:
            want.add("retest")
        if gate.timeouts is not None and gate.timeouts.expire_after is not None:
            want.add("expired")
        return frozenset(want), []
    if isinstance(stage, EffectStage):
        spec = manifest.effects.get(stage.effect)
        if spec is None:
            return None, [
                Issue(
                    None,
                    _at(sid, "effect"),
                    f"stage {sid}: effect {stage.effect} is not in the effect "
                    "catalog; use a catalogued effect",
                )
            ]
        return spec.outcomes, []
    return None, []


def _orchestrators(manifest: Manifest) -> list[str]:
    return [n for n, p in manifest.profiles.items() if p.role == "orchestrator"]


def _v2(wf: Workflow, manifest: Manifest) -> list[Issue]:
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        if isinstance(stage, TerminalStage):
            continue
        have = set(stage.next)
        if isinstance(stage, RouteStage):
            if "default" not in have:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "next"),
                        f"stage {sid}: a route needs a default edge for a value no "
                        "edge names; add `default: <stage>`",
                    )
                )
            if stage.order is not None:
                for value in sorted(have - {"default"} - set(stage.order)):
                    issues.append(
                        Issue(
                            None,
                            _at(sid, "next", value),
                            f"stage {sid}: the edge for {value} is outside order "
                            f"{list(stage.order)}, so it is never taken; add {value} "
                            "to order or remove the edge",
                        )
                    )
            continue
        want, problems = _expected_outcomes(sid, stage, manifest)
        issues.extend(problems)
        if want is None:
            continue
        for outcome in sorted(want - have):
            issues.append(
                Issue(
                    None,
                    _at(sid, "next"),
                    f"stage {sid} has no edge for outcome {outcome}; add "
                    f"`{outcome}: <stage>` to next",
                )
            )
        for outcome in sorted(have - want):
            issues.append(
                Issue(
                    None,
                    _at(sid, "next", outcome),
                    f"stage {sid}: outcome {outcome} cannot happen here; remove the "
                    f"edge (outcomes: {_words(want)})",
                )
            )
    return issues


# --- V3 ------------------------------------------------------------------------------------


def _v3(wf: Workflow, policy: OrgPolicy) -> list[Issue]:
    issues: list[Issue] = []
    loops = wf.limits.loops
    org_max = policy.ceilings.max_loop
    for name, limit in loops.items():
        if limit > PLATFORM_MAX_STEPS:
            issues.append(
                Issue(
                    None,
                    f"limits.loops.{name}",
                    f"loop {name} allows {limit} visits, over the platform maximum "
                    f"of {PLATFORM_MAX_STEPS}; lower it",
                )
            )
        if org_max is not None and limit > org_max:
            issues.append(
                Issue(
                    None,
                    f"limits.loops.{name}",
                    f"loop {name} allows {limit} visits, over the org ceiling of "
                    f"{org_max}; lower it",
                )
            )
    graph: dict[str, list[tuple[str, str]]] = {}
    for sid, stage in wf.stages.items():
        graph[sid] = []
        for outcome, target, loop in _edges(stage):
            if loop is not None and loop not in loops:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "next", outcome),
                        f"stage {sid}: the {outcome} edge names loop {loop}, which "
                        f"has no limit; add `{loop}: <count>` to limits.loops",
                    )
                )
            if loop is None or loop not in loops:
                graph[sid].append((outcome, target))
    issues.extend(_uncapped_cycles(graph))
    return issues


def _uncapped_cycles(graph: Mapping[str, list[tuple[str, str]]]) -> list[Issue]:
    """One issue per back edge of a depth-first search of the graph without its capped edges. If
    there are none, every cycle of the full graph had a capped edge."""
    issues: list[Issue] = []
    state: dict[str, int] = {}  # 1 on the current path, 2 finished
    for root in graph:
        if root in state:
            continue
        path = [root]
        state[root] = 1
        stack = [iter(graph[root])]
        while stack:
            for outcome, target in stack[-1]:
                if target not in graph:
                    continue
                if state.get(target) == 1:
                    ring = [*path[path.index(target) :], target]
                    source = path[-1]
                    issues.append(
                        Issue(
                            None,
                            _at(source, "next", outcome),
                            f"stage {source}: cycle {' -> '.join(ring)} has no loop "
                            f"limit; put `loop: <name>` on the {outcome} edge and "
                            "give the name a count in limits.loops",
                        )
                    )
                elif target not in state:
                    state[target] = 1
                    path.append(target)
                    stack.append(iter(graph[target]))
                    break
            else:
                state[path.pop()] = 2
                stack.pop()
    return issues


# --- V7 ------------------------------------------------------------------------------------


def _v7(wf: Workflow) -> list[Issue]:
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        if not isinstance(stage, GateStage):
            continue
        gate = stage.gate
        if not gate.eligible_roles:
            issues.append(
                Issue(
                    None,
                    _at(sid, "gate", "eligible_roles"),
                    f"stage {sid}: eligible_roles is empty, so no human can decide "
                    "this gate; list the roles that may",
                )
            )
        t = gate.timeouts
        if t is not None and t.escalate_after is not None and t.escalate_to is None:
            issues.append(
                Issue(
                    None,
                    _at(sid, "gate", "timeouts", "escalate_to"),
                    f"stage {sid}: escalate_after is set but escalate_to is not, so there is "
                    "no one to escalate to; add escalate_to with a role",
                )
            )
        seen: set[str] = set()
        for entry in gate.quorum or ():
            if entry.role in seen:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "gate", "quorum"),
                        f"stage {sid}: quorum lists role {entry.role} twice; list "
                        "each role once and put the total in count",
                    )
                )
            seen.add(entry.role)
            if entry.role not in gate.eligible_roles:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "gate", "quorum"),
                        f"stage {sid}: quorum role {entry.role} is not in "
                        "eligible_roles; add it there or remove it from quorum",
                    )
                )
            if entry.count < 1:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "gate", "quorum"),
                        f"stage {sid}: quorum count for {entry.role} is "
                        f"{entry.count}; it must be at least 1",
                    )
                )
    return issues


# --- V8 ------------------------------------------------------------------------------------


def _v8(wf: Workflow, manifest: Manifest) -> list[Issue]:
    """From each ``rejected`` or ``expired`` edge, look for each gated effect, per effect: the
    search may not pass through the ``approved`` edge of a gate in that effect's
    ``requires_gates`` (that approval is what earns it), but every other gate's approval is
    no help, since the effect did not ask for it."""
    issues: list[Issue] = []
    stages = wf.stages
    effects = {
        eid: st
        for eid, st in stages.items()
        if isinstance(st, EffectStage)
        and (spec := manifest.effects.get(st.effect)) is not None
        and spec.effect_class == "gated"
    }
    for gid, stage in stages.items():
        if not isinstance(stage, GateStage):
            continue
        for outcome, target, _ in _edges(stage):
            if outcome not in ("rejected", "expired") or target not in stages:
                continue
            for eid, effect in effects.items():
                held = set(effect.requires_gates or ())
                parent: dict[str, str | None] = {target: None}
                queue = deque([target])
                while queue and eid not in parent:
                    sid = queue.popleft()
                    for out, nxt, _ in _edges(stages[sid]):
                        if isinstance(stages[sid], GateStage) and out == "approved" and sid in held:
                            continue
                        if nxt in stages and nxt not in parent:
                            parent[nxt] = sid
                            queue.append(nxt)
                if eid not in parent:
                    continue
                chain = [eid]
                while (p := parent[chain[-1]]) is not None:
                    chain.append(p)
                issues.append(
                    Issue(
                        None,
                        _at(gid, "next", outcome),
                        f"stage {gid}: the {outcome} edge reaches gated effect {eid} "
                        f"({' -> '.join(reversed(chain))}) without passing the approval it "
                        "requires; a refusal or an expiry must not run it; send the edge to "
                        "a terminal",
                    )
                )
    return issues


# --- V9 ------------------------------------------------------------------------------------


def _v9(wf: Workflow, policy: OrgPolicy) -> list[Issue]:
    issues: list[Issue] = []
    limits, ceil = wf.limits, policy.ceilings
    if limits.max_steps_per_run > PLATFORM_MAX_STEPS:
        issues.append(
            Issue(
                None,
                "limits.max_steps_per_run",
                f"max_steps_per_run {limits.max_steps_per_run} is over the platform "
                f"maximum of {PLATFORM_MAX_STEPS}; lower it",
            )
        )
    if ceil.max_steps_per_run is not None and limits.max_steps_per_run > ceil.max_steps_per_run:
        issues.append(
            Issue(
                None,
                "limits.max_steps_per_run",
                f"max_steps_per_run {limits.max_steps_per_run} is over the org "
                f"ceiling of {ceil.max_steps_per_run}; lower it",
            )
        )
    run_age = duration_seconds(limits.max_run_age)
    if ceil.max_run_age is not None and run_age > duration_seconds(ceil.max_run_age):
        issues.append(
            Issue(
                None,
                "limits.max_run_age",
                f"max_run_age {limits.max_run_age} is over the org ceiling of "
                f"{ceil.max_run_age}; lower it",
            )
        )
    org_stage = (
        None if ceil.max_stage_duration is None else duration_seconds(ceil.max_stage_duration)
    )
    for sid, stage in wf.stages.items():
        for where, value in _durations(stage):
            seconds = duration_seconds(value)
            if seconds > run_age:
                issues.append(
                    Issue(
                        None,
                        _at(sid, where),
                        f"stage {sid}: {where.rsplit('.', 1)[-1]} {value} is longer "
                        f"than max_run_age {limits.max_run_age}, so the run would "
                        "end first; shorten it or raise max_run_age",
                    )
                )
            if org_stage is not None and seconds > org_stage:
                issues.append(
                    Issue(
                        None,
                        _at(sid, where),
                        f"stage {sid}: {where.rsplit('.', 1)[-1]} {value} is over "
                        f"the org ceiling of {ceil.max_stage_duration} for a stage "
                        "duration; shorten it",
                    )
                )
    return issues


def _durations(stage: Any) -> list[tuple[str, str]]:
    if isinstance(stage, (ChecksStage, WaitStage)):
        return [("timeout", stage.timeout)]
    if isinstance(stage, GateStage) and stage.gate.timeouts is not None:
        t = stage.gate.timeouts
        pairs = (
            ("remind_after", t.remind_after),
            ("escalate_after", t.escalate_after),
            ("expire_after", t.expire_after),
        )
        return [(f"gate.timeouts.{k}", v) for k, v in pairs if v is not None]
    return []


def check_budget_ceilings(config: TeamConfig, policy: OrgPolicy) -> list[Issue]:
    """V9 for a team's budgets: ``run_usd`` and each ``stage_usd`` within ``max_run_usd``."""
    cap = policy.ceilings.max_run_usd
    if cap is None:
        return []
    issues: list[Issue] = []
    budgets = config.budgets
    if budgets.run_usd > cap:
        issues.append(
            Issue(
                None,
                "budgets.run_usd",
                f"run_usd {budgets.run_usd} is over the org ceiling of {cap}; lower it",
            )
        )
    for sid, usd in (budgets.stage_usd or {}).items():
        if usd > cap:
            issues.append(
                Issue(
                    None,
                    f"budgets.stage_usd.{sid}",
                    f"stage_usd for {sid} is {usd}, over the org ceiling of {cap} "
                    "for a run; lower it",
                )
            )
    return issues


def _gates_on(policy: OrgPolicy, team: str, field: str) -> str:
    """The org gates a route on ``field`` could skip for ``team``, for a message."""
    team_policy = policy.teams.get(team)
    named = [
        f"{g.id} (when {field} is {g.when.value})"
        for g in (team_policy.required_gates if team_policy else ())
        if g.when is not None and g.when.field == field
    ]
    return "the org gate " + ", ".join(dict.fromkeys(named)) if named else "an org gate"


def check_route_orders(wf: Workflow, policy: OrgPolicy) -> list[Issue]:
    """A route on a field the org ranks must rank those values the way the org does.

    A value the org does not rank is the team's, but only above the org's highest value. Ranked
    anywhere lower, a route could send it past a required gate and the V17 search (which raises a
    value to all values ranked above it) would not consider it."""
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        org = policy.route_orders.get(stage.field) if isinstance(stage, RouteStage) else None
        if org is None or not isinstance(stage, RouteStage):
            continue
        ranking = " < ".join(org)
        if stage.order is None:
            issues.append(
                Issue(
                    None,
                    _at(sid, "order"),
                    f"stage {sid}: the org ranks {stage.field} ({ranking}); add an "
                    "order that ranks those values the same way",
                )
            )
            continue
        missing = [v for v in org if v not in stage.order]
        if missing:
            issues.append(
                Issue(
                    None,
                    _at(sid, "order"),
                    f"stage {sid}: order leaves out {', '.join(missing)}; the org "
                    f"ranks {stage.field} {ranking}, so include every one",
                )
            )
        ranked_at = [i for i, v in enumerate(stage.order) if v in org]
        first, last = (ranked_at[0], ranked_at[-1]) if ranked_at else (0, -1)
        gates = _gates_on(policy, wf.metadata.team, stage.field)
        for i, value in enumerate(stage.order):
            if value in org or i > last:
                continue
            where = (
                f"below {org[0]}, the org's lowest ranked {stage.field} value"
                if i < first
                else f"below {org[-1]}, the org's highest ranked {stage.field} value"
            )
            issues.append(
                Issue(
                    None,
                    _at(sid, "order"),
                    f"stage {sid}: order ranks {value} {where}, so a route could send "
                    f"{value} past {gates}; move {value} above {org[-1]}",
                )
            )
        theirs = [v for v in stage.order if v in org]
        if theirs != [v for v in org if v in theirs]:
            issues.append(
                Issue(
                    None,
                    _at(sid, "order"),
                    f"stage {sid}: order ranks {stage.field} {' < '.join(theirs)}, "
                    f"but the org ranks it {ranking}; use the org's order",
                )
            )
    return issues


# --- V10 -----------------------------------------------------------------------------------


def _v10(wf: Workflow, policy: OrgPolicy) -> list[Issue]:
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        if not isinstance(stage, GateStage):
            continue
        gate = stage.gate
        allowed = permitted_surfaces(policy, gate.type)
        for surface in gate.decision_surfaces:
            if surface == "github" and gate.type != "review":
                issues.append(
                    Issue(
                        None,
                        _at(sid, "gate", "decision_surfaces"),
                        f"stage {sid}: github is only for review gates, and this is "
                        f"a {gate.type} gate; remove github",
                    )
                )
            elif surface not in allowed:
                have = f"only {_words(allowed)}" if allowed else "none"
                issues.append(
                    Issue(
                        None,
                        _at(sid, "gate", "decision_surfaces"),
                        f"stage {sid}: org policy permits {have} for {gate.type} "
                        f"gates, not {surface}; remove {surface}",
                    )
                )
        if "waive" in gate.decisions and not policy.floors.waive_allowed:
            issues.append(
                Issue(
                    None,
                    _at(sid, "gate", "decisions"),
                    f"stage {sid}: waive is not allowed by org policy; remove waive from decisions",
                )
            )
    return issues


# --- V13 -----------------------------------------------------------------------------------


def _v13(wf: Workflow) -> list[Issue]:
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        if isinstance(stage, ReviewPanelStage):
            if not stage.reviewers:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "reviewers"),
                        f"stage {sid}: reviewers is empty, so nothing reviews; list "
                        "at least one reviewer",
                    )
                )
            if not stage.required:
                issues.append(
                    Issue(
                        None,
                        _at(sid, "required"),
                        f"stage {sid}: required is empty, so the panel can pass with "
                        "no review; name at least one required reviewer",
                    )
                )
            for name in stage.required:
                if name not in stage.reviewers:
                    issues.append(
                        Issue(
                            None,
                            _at(sid, "required"),
                            f"stage {sid}: required reviewer {name} is not in "
                            "reviewers; add it there or remove it",
                        )
                    )
        elif isinstance(stage, ChecksStage) and not stage.required:
            issues.append(
                Issue(
                    None,
                    _at(sid, "required"),
                    f"stage {sid}: required is empty, so any result is green; "
                    "name at least one check, or use team_default",
                )
            )
    return issues


# --- V15 -----------------------------------------------------------------------------------


def _v15(
    wf: Workflow, manifest: Manifest, policy: OrgPolicy, sandbox_images: Collection[str] | None
) -> list[Issue]:
    issues: list[Issue] = []
    for sid, stage in wf.stages.items():
        if isinstance(stage, GateStage) and stage.gate.type in MANDATORY_GATES:
            gate = stage.gate
            roles = mandatory_roles(policy, gate.type)
            listed = [*gate.eligible_roles, *(q.role for q in gate.quorum or ())]
            for role in dict.fromkeys(listed):
                if role not in roles:
                    issues.append(
                        Issue(
                            None,
                            _at(sid, "gate", "eligible_roles"),
                            f"stage {sid}: {role} may not decide a {gate.type} gate; remove {role} "
                            f"(org policy allows only: {_words(roles)})",
                        )
                    )
        elif isinstance(stage, EffectStage):
            issues.extend(_typed_with(sid, stage, manifest))
    if (
        sandbox_images is not None
        and wf.repo is not None
        and wf.repo.sandbox_image not in sandbox_images
    ):
        issues.append(
            Issue(
                None,
                "repo.sandbox_image",
                f"sandbox image {wf.repo.sandbox_image} is not registered; use "
                f"one of: {_words(sandbox_images)}",
            )
        )
    return issues


def _typed_with(sid: str, stage: EffectStage, manifest: Manifest) -> list[Issue]:
    spec = manifest.effects.get(stage.effect)
    if spec is None:
        return []  # V2 reports an effect that is not in the catalog
    given: Mapping[str, Any] = stage.with_ or {}
    keys = spec.with_keys
    where = _at(sid, "with")
    issues: list[Issue] = []
    for key in given:
        if key not in keys:
            hint = (
                f"{stage.effect} takes {_words(keys)}" if keys else f"{stage.effect} takes no keys"
            )
            extra = (
                "; an approval comes only from a human decision at a gate, so use requires_gates"
                if "approv" in key.casefold()
                else ""
            )
            issues.append(
                Issue(
                    None,
                    f"{where}.{key}",
                    f"stage {sid}: with key {key} is not allowed on {stage.effect} "
                    f"({hint}); remove it{extra}",
                )
            )
    for key, rule in keys.items():
        if key not in given:
            if rule.required:
                issues.append(
                    Issue(None, where, f"stage {sid}: {stage.effect} needs with.{key}; add it")
                )
            continue
        problem = _value_problem(rule, given[key])
        if problem:
            issues.append(
                Issue(None, f"{where}.{key}", f"stage {sid}: with.{key} {problem}; fix the value")
            )
    return issues


def _value_problem(rule: WithKey, value: Any) -> str | None:
    if not isinstance(value, str):
        return f"must be text, not {type(value).__name__}"
    if rule.type == "enum" and value not in rule.values:
        return f"is {value!r}; use one of: {', '.join(rule.values)}"
    if rule.type == "ident" and not _IDENT.fullmatch(value):
        return f"is {value!r}; use lowercase letters, digits and underscores"
    if rule.type == "text" and not value.strip():
        return "must not be blank"
    return None


# --- entry point ---------------------------------------------------------------------------


def validate_structure(
    wf: Workflow,
    *,
    manifest: Manifest,
    policy: OrgPolicy,
    sandbox_images: Collection[str] | None = None,
    team_config: TeamConfig | None = None,
) -> list[Issue]:
    """Every structural problem in ``wf``, empty when it passes.

    ``policy`` is required: a rule that reads the org fails closed, so there is no way to ask
    without one. ``sandbox_images`` is the registry of image names; ``None`` skips that check.
    ``team_config`` is the team's, whose budgets V9 checks against the org ceilings; without it
    there are none."""
    return [
        *_v1(wf),
        *_v2(wf, manifest),
        *_v3(wf, policy),
        *_v7(wf),
        *_v8(wf, manifest),
        *_v9(wf, policy),
        *check_route_orders(wf, policy),
        *_v10(wf, policy),
        *_v13(wf),
        *_v15(wf, manifest, policy, sandbox_images),
        *([] if team_config is None else check_budget_ceilings(team_config, policy)),
    ]
