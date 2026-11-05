"""Gate dominance by edge-removal reachability (D2-04): V4, V5, V6, V11 and V14 of PLAN 7.3.

Every rule is the same question asked of the stage graph: remove some edges or stages, then is
something still reachable? The graph has a node per stage and an edge per ``next`` entry, all
outcomes included (a timeout, a rejection and a loop back are paths like any other). The answer
is a path, and a failing rule prints it, so a team can see which way round the gate the run goes.

* V4. A ``gated`` effect lists at least one gate. For each gate it lists, with that gate's
  ``approved`` edge removed, the effect is unreachable from ``start``.
* V5. The same, from every code-changing stage: an approval cannot be reused past a code change.
  Code-changing is derived, never named by the team: an agent whose profile holds
  ``workspace.write``, a ``pr.update_branch`` stage, and the stage a commit by someone else
  re-enters (``on_external_commit``, else every ``ci`` stage, as V17 does). An agent the manifest
  does not know could write anything, so it counts.
* V6. ``pr.merge`` lists a ``review`` gate. ``release.trigger`` and a ``ticket.transition`` to done
  list a ``qa`` gate. With every QA approval removed, terminal ``done`` is unreachable. A merge
  that is reachable that way (merge before QA) must not lead to ``done`` or ``closed`` from its
  ``done`` edge, with the QA approvals removed and ``wait`` timeouts ignored. And a merge must
  not lead to a ``rejected`` terminal on a path with no QA gate, because PLAN 7.7 says a rejected
  run blocks the release, and only a QA decision can say so. V17 allows that shape and leaves
  it to this rule.
* V11. With ``review_panel`` stages removed, no ``review`` gate is reachable from a
  code-changing stage: LLM reviews come before the human review.
* V14. With the QA evidence stages removed (``qa_suite`` checks, and agents whose profile holds
  ``record_evidence``), no ``qa`` gate is reachable from a code-changing stage.

Two boundaries on V6's rejected clause. A path that reaches a code-changing stage ends there: that
is a follow-up change (PLAN 7.7, "fix-forward"), with a review gate of its own, and the engine
handles a rejection of it (PLAN 6.2) by opening a revert. And a merge counts only along its
``done`` edge: ``conflict`` and ``stale`` mean nothing landed.

The rules assume V1 (every edge names a stage); an edge to an unknown stage is skipped here. The
rules that need the manifest take it as a parameter, so tests can pass a modified one.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Collection, Iterable
from typing import Any

from sto.config.manifest import Manifest, load_manifest
from sto.config.schema import (
    AgentStage,
    ChecksStage,
    Edge,
    EffectStage,
    GateStage,
    Issue,
    ReviewPanelStage,
    TerminalStage,
    WaitStage,
    Workflow,
)

__all__ = ["check_gate_dominance", "code_changing_stages", "qa_evidence_stages"]

_WRITES = "workspace.write"
_EVIDENCE_TOOL = "record_evidence"
_UPDATE_BRANCH = "pr.update_branch"
_MAX_PATH = 10  # nodes shown; a longer path keeps its ends and elides the middle

Parents = dict[str, str | None]


def _targets(edges: Any) -> dict[str, str]:
    return {o: e.to if isinstance(e, Edge) else e for o, e in edges.items()}


def _reach(
    wf: Workflow,
    starts: Iterable[str],
    *,
    drop_approved: Collection[str] = (),
    skip: Collection[str] = (),
    stop: Collection[str] = (),
    ignore_timeouts: bool = False,
) -> Parents:
    """Every stage reachable from ``starts``, each with the stage before it on a shortest path.

    ``drop_approved`` gates lose their ``approved`` edge. ``skip`` stages are never entered.
    ``stop`` stages are entered but not left. ``ignore_timeouts`` drops every wait's ``timeout``.
    """
    parents: Parents = {}
    queue: deque[str] = deque()
    for sid in starts:
        if sid in wf.stages and sid not in skip and sid not in parents:
            parents[sid] = None
            queue.append(sid)
    while queue:
        sid = queue.popleft()
        stage = wf.stages[sid]
        if sid in stop or isinstance(stage, TerminalStage):
            continue
        edges = _targets(stage.next)
        if sid in drop_approved:
            edges.pop("approved", None)
        if ignore_timeouts and isinstance(stage, WaitStage):
            edges.pop("timeout", None)
        for target in edges.values():
            if target in wf.stages and target not in skip and target not in parents:
                parents[target] = sid
                queue.append(target)
    return parents


def _path(parents: Parents, to: str) -> list[str]:
    out = [to]
    while (prev := parents[out[-1]]) is not None:
        out.append(prev)
    return out[::-1]


def _show(path: list[str]) -> str:
    if len(path) > _MAX_PATH:
        keep = _MAX_PATH // 2
        path = [*path[:keep], "...", *path[-keep:]]
    return " -> ".join(path)


def _agent_profile_tools(manifest: Manifest, stage: AgentStage) -> frozenset[str] | None:
    profile = manifest.profiles.get(stage.agent)
    return None if profile is None else profile.tools


def code_changing_stages(wf: Workflow, manifest: Manifest | None = None) -> set[str]:
    """Stages after which the code under review may be different (V5, V11, V14)."""
    manifest = manifest or load_manifest()
    out: set[str] = set()
    for sid, stage in wf.stages.items():
        if isinstance(stage, AgentStage):
            tools = _agent_profile_tools(manifest, stage)
            if tools is None or _WRITES in tools:  # unknown: it could write anything
                out.add(sid)
        elif isinstance(stage, EffectStage) and stage.effect == _UPDATE_BRANCH:
            out.add(sid)
    if wf.on_external_commit is not None:
        out.add(wf.on_external_commit)
    else:
        out |= {
            sid
            for sid, st in wf.stages.items()
            if isinstance(st, ChecksStage) and st.source == "ci"
        }
    return {sid for sid in out if sid in wf.stages}


def qa_evidence_stages(wf: Workflow, manifest: Manifest | None = None) -> set[str]:
    """Stages that produce what a QA gate judges (V14). An unknown agent produces none."""
    manifest = manifest or load_manifest()
    out: set[str] = set()
    for sid, stage in wf.stages.items():
        if isinstance(stage, ChecksStage) and stage.source == "qa_suite":
            out.add(sid)
        elif isinstance(stage, AgentStage):
            tools = _agent_profile_tools(manifest, stage)
            if tools is not None and _EVIDENCE_TOOL in tools:
                out.add(sid)
    return out


def _gate_ids(wf: Workflow, gate_type: str) -> set[str]:
    return {
        sid
        for sid, st in wf.stages.items()
        if isinstance(st, GateStage) and st.gate.type == gate_type
    }


def _effects(wf: Workflow) -> list[tuple[str, EffectStage]]:
    return [(sid, st) for sid, st in wf.stages.items() if isinstance(st, EffectStage)]


def _is_done_transition(stage: EffectStage) -> bool:
    if stage.effect != "ticket.transition":
        return False
    # no category at all counts as done, as V17 counts it
    return str((stage.with_ or {}).get("to_status_category", "done")).casefold() == "done"


def _v4_v5(wf: Workflow, manifest: Manifest) -> list[Issue]:
    issues: list[Issue] = []
    gated: list[tuple[str, EffectStage]] = []
    for sid, stage in _effects(wf):
        spec = manifest.effects.get(stage.effect)
        if spec is not None and spec.effect_class != "gated":
            continue  # an effect the catalog does not know is treated as gated
        gated.append((sid, stage))
        if not stage.requires_gates:
            issues.append(
                Issue(
                    None,
                    f"stages.{sid}.requires_gates",
                    f"V4: {sid} ({stage.effect}) is a gated effect and lists no gate; "
                    "list the gates whose approval it needs in requires_gates",
                )
            )
    listed: dict[str, list[tuple[str, EffectStage]]] = {}
    for sid, stage in gated:
        for gid in stage.requires_gates or ():
            listed.setdefault(gid, []).append((sid, stage))
    code = sorted(code_changing_stages(wf, manifest))
    for gid, effects in sorted(listed.items()):
        gate = wf.stages.get(gid)
        if not isinstance(gate, GateStage):
            what = "does not exist" if gate is None else "is not a gate"
            for sid, _ in effects:
                issues.append(
                    Issue(
                        None,
                        f"stages.{sid}.requires_gates",
                        f"V4: {sid} lists {gid} in requires_gates, but {gid} {what}; "
                        "list a gate stage",
                    )
                )
            continue
        if "approved" not in gate.next:
            issues.append(
                Issue(
                    None,
                    f"stages.{gid}.next",
                    f"V4: gate {gid} has no approved edge, so nothing can pass it; add "
                    "approved: <stage>",
                )
            )
            continue
        from_start = _reach(wf, [wf.start], drop_approved={gid})
        for sid, stage in effects:
            if sid in from_start:
                issues.append(
                    Issue(
                        None,
                        f"stages.{sid}.requires_gates",
                        f"V4: {sid} ({stage.effect}) is reachable without {gid}'s approval; "
                        f"route every path to it through {gid}'s approved edge; "
                        f"path: {_show(_path(from_start, sid))}",
                    )
                )
        for cid in code:
            after = _reach(wf, [cid], drop_approved={gid})
            for sid, stage in effects:
                if sid in after and sid != cid:
                    issues.append(
                        Issue(
                            None,
                            f"stages.{sid}.requires_gates",
                            f"V5: {sid} ({stage.effect}) is reachable from {cid}, which can "
                            f"change the code, without a new approval at {gid}; send {cid} back "
                            f"through {gid}; path: {_show(_path(after, sid))}",
                        )
                    )
    return issues


def _v6_floors(wf: Workflow) -> list[Issue]:
    issues: list[Issue] = []
    review, qa = _gate_ids(wf, "review"), _gate_ids(wf, "qa")
    for sid, stage in _effects(wf):
        listed = set(stage.requires_gates or ())
        need: tuple[str, set[str]] | None = None
        if stage.effect == "pr.merge":
            need = ("review", review)
        elif stage.effect == "release.trigger" or _is_done_transition(stage):
            need = ("qa", qa)
        if need and not listed & need[1]:
            kind, _ = need
            issues.append(
                Issue(
                    None,
                    f"stages.{sid}.requires_gates",
                    f"V6: {sid} ({stage.effect}) must list a {kind} gate (a gate stage of "
                    f"type {kind}) in requires_gates",
                )
            )
    return issues


def _v6_paths(wf: Workflow, manifest: Manifest) -> list[Issue]:
    issues: list[Issue] = []
    qa = _gate_ids(wf, "qa")
    without_qa = _reach(wf, [wf.start], drop_approved=qa)
    for sid, stage in wf.stages.items():
        if isinstance(stage, TerminalStage) and stage.result == "done" and sid in without_qa:
            issues.append(
                Issue(
                    None,
                    f"stages.{sid}",
                    f"V6: terminal {sid} (done) is reachable without a QA approval; "
                    f"every path to done must pass a qa gate's approved edge; "
                    f"path: {_show(_path(without_qa, sid))}",
                )
            )
    code = code_changing_stages(wf, manifest)
    merges = [sid for sid, st in _effects(wf) if st.effect == "pr.merge"]
    all_reach = _reach(wf, [wf.start])
    for mid in merges:
        merge = wf.stages[mid]
        assert isinstance(merge, EffectStage)
        landed = _targets(merge.next).get("done")
        if landed is None or landed not in wf.stages:
            continue
        if mid in without_qa:  # merge before QA
            after = _reach(wf, [landed], drop_approved=qa, ignore_timeouts=True)
            for tid, term in wf.stages.items():
                if (
                    isinstance(term, TerminalStage)
                    and term.result in ("done", "closed")
                    and tid in after
                ):
                    issues.append(
                        Issue(
                            None,
                            f"stages.{mid}.next",
                            f"V6: {mid} can merge before QA, and from its done edge terminal "
                            f"{tid} ({term.result}) is reachable without a QA approval; the "
                            f"code is merged, so only a QA decision may end the run that way; "
                            f"path: {_show(_path(without_qa, mid) + _path(after, tid))}",
                        )
                    )
        if mid not in all_reach:
            continue
        after = _reach(wf, [landed], skip=qa, stop=code)
        for tid, term in wf.stages.items():
            if isinstance(term, TerminalStage) and term.result == "rejected" and tid in after:
                issues.append(
                    Issue(
                        None,
                        f"stages.{mid}.next",
                        f"V6: after {mid} merges, terminal {tid} (rejected) is reachable with no "
                        f"qa gate on the path; a rejected run blocks the release, so route it "
                        f"through a qa gate; "
                        f"path: {_show(_path(all_reach, mid) + _path(after, tid))}",
                    )
                )
    return issues


def _v11_v14(wf: Workflow, manifest: Manifest) -> list[Issue]:
    issues: list[Issue] = []
    code = sorted(code_changing_stages(wf, manifest))
    panels = sorted(sid for sid, st in wf.stages.items() if isinstance(st, ReviewPanelStage))
    evidence = sorted(qa_evidence_stages(wf, manifest))
    rules = (
        ("V11", "review", panels, "a review_panel stage", "a review gate"),
        ("V14", "qa", evidence, "a qa_suite checks stage or a QA agent", "a qa gate"),
    )
    for rule, gate_type, removed, fix, label in rules:
        gates = _gate_ids(wf, gate_type)
        reported: set[str] = set()
        for cid in code:
            reach = _reach(wf, [cid], skip=removed)
            for gid in sorted(gates & reach.keys() - reported - {cid}):
                reported.add(gid)
                have = f" (now: {', '.join(removed)})" if removed else ""
                issues.append(
                    Issue(
                        None,
                        f"stages.{gid}",
                        f"{rule}: {label} {gid} is reachable from {cid}, which can change the "
                        f"code, without passing {fix}{have}; put one before {gid} on every path; "
                        f"path: {_show(_path(reach, gid))}",
                    )
                )
    return issues


def check_gate_dominance(wf: Workflow, manifest: Manifest | None = None) -> list[Issue]:
    """Every V4, V5, V6, V11 and V14 failure of ``wf``. Empty means the workflow is accepted."""
    manifest = manifest or load_manifest()
    return [
        *_v4_v5(wf, manifest),
        *_v6_floors(wf),
        *_v6_paths(wf, manifest),
        *_v11_v14(wf, manifest),
    ]
