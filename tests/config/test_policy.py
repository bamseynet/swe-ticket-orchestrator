"""D2-24: TeamConfig and OrgPolicy stored live, the typed read API, and V17.

The floors are read from the store at every call, so a run pinned to a workflow still sees a
tightened floor on its next read. Every question the read API answers fails closed: what the
policy does not name is nothing permitted, never anything.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from sto.config import org_policy, team_config
from sto.config.org_policy import (
    FLOOR_TRACKING,
    MAX_DOCUMENT_BYTES,
    ORG_ADMIN,
    OrgPolicyStore,
    PermissionDeniedError,
    PolicyMissingError,
    Principal,
    allowed_carry_over,
    check_org_required_gates,
    mandatory_roles,
    open_floors,
    permitted_surfaces,
    quorum_floor,
    surface_permitted,
)
from sto.config.schema import Floors, SchemaError, TeamConfig, TeamPolicy, Workflow, load_document
from sto.config.team_config import TeamConfigMissingError, TeamConfigStore
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, ConditionFailedError, Key, TeamScope

ROOT = Path(__file__).resolve().parents[2]
STAGES_MD = (ROOT / "docs" / "STAGES.md").read_text(encoding="utf-8")


def _dump(data: dict[str, Any]) -> str:
    # through JSON so a dict used twice is written out twice: the loader refuses aliases
    return yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False)


ORG_DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "OrgPolicy",
    "floors": {
        "mandatory_gate_roles": {
            "pre_push": ["reviewer"],
            "review": ["reviewer"],
            "qa": ["qa", "reviewer"],
        },
        "decision_surfaces": {"review": ["ui", "slack", "github"], "qa": ["ui", "slack"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    },
    "teams": {
        "ledger": {
            "required_gates": [
                {
                    "id": "security_gate",
                    "role": "security_officer",
                    "when": {"field": "risk", "value": "high"},
                },
                {"id": "review_gate", "role": "reviewer"},
            ],
            "min_quorum": {"review": 2},
            "allowed_carry_over": ["none"],
        }
    },
}


def _gate(
    gtype: str, roles: list[str], nxt: dict[str, Any], *, count: int = 1, carry: str = "none"
) -> dict[str, Any]:
    return {
        "kind": "gate",
        "gate": {
            "type": gtype,
            "eligible_roles": roles,
            "decisions": ["approve", "reject"],
            "decision_surfaces": ["ui"],
            "quorum": [{"role": roles[0], "count": count}],
            "carry_over": carry,
        },
        "next": nxt,
    }


WF_DOC: dict[str, Any] = {
    "apiVersion": "sto/v1",
    "kind": "Workflow",
    "metadata": {"name": "ledger-flow", "team": "ledger"},
    "limits": {"max_steps_per_run": 50, "max_run_age": "30d"},
    "start": "route_risk",
    "stages": {
        "route_risk": {
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"high": "security_gate", "default": "review_gate"},
        },
        "security_gate": _gate(
            "custom", ["security_officer"], {"approved": "review_gate", "rejected": "closed"}
        ),
        "review_gate": _gate(
            "review", ["reviewer"], {"approved": "qa_gate", "rejected": "closed"}, count=2
        ),
        "qa_gate": _gate("qa", ["qa"], {"approved": "done", "rejected": "closed"}),
        "done": {"kind": "terminal", "result": "done"},
        "closed": {"kind": "terminal", "result": "closed"},
    },
}


def _wf(mutate: Any = None) -> Workflow:
    data = copy.deepcopy(WF_DOC)
    if mutate:
        mutate(data["stages"])
    wf = load_document(_dump(data))
    assert isinstance(wf, Workflow)
    return wf


def _policy(mutate: Any = None) -> org_policy.OrgPolicy:
    data = copy.deepcopy(ORG_DOC)
    if mutate:
        mutate(data)
    pol = load_document(_dump(data))
    assert isinstance(pol, org_policy.OrgPolicy)
    return pol


def _save(ops: OrgPolicyStore, who: Principal, text: str) -> Any:
    """Write on top of whatever is stored now, as an editor that has just read would."""
    current = ops.read_versioned()
    return ops.write(who, text, expected_version=None if current is None else current.version)


def _save_team(tcs: TeamConfigStore, scope: TeamScope, who: Principal, text: str) -> Any:
    current = tcs.read_versioned(scope)
    return tcs.write(
        scope, who, text, expected_version=None if current is None else current.version
    )


def _check(wf: Workflow, policy: Any, team: str = "ledger") -> list[Any]:
    return check_org_required_gates(wf, policy, team=team)


ADMIN = Principal("amy", frozenset({ORG_ADMIN}))
TEAM_ADMIN = Principal("tom", frozenset({"team_admin"}), team="ledger")
DEV = Principal(
    "dee", frozenset({"developer", "reviewer", "qa", "team_admin", "auditor"}), team="ledger"
)


# --- the role seam -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [TEAM_ADMIN, DEV, Principal("x", frozenset())],
    ids=["team_admin", "everything_but_org_admin", "no_roles"],
)
def test_only_org_admins_write_org_policy(who: Principal) -> None:
    store = MemoryStore()
    ops = OrgPolicyStore(store)
    with pytest.raises(PermissionDeniedError):
        _save(ops, who, _dump(ORG_DOC))
    assert store.get(PLATFORM, Key("ORG", "POLICY")) is None  # nothing was written
    assert ops.read() is None


def test_org_admin_writes_org_policy_and_it_reads_back_typed() -> None:
    ops = OrgPolicyStore(MemoryStore())
    _save(ops, ADMIN, _dump(ORG_DOC))
    pol = ops.read()
    assert pol is not None
    assert pol.teams["ledger"].min_quorum["review"] == 2


def test_org_admin_role_on_the_principal_is_not_a_team_scoped_claim() -> None:
    # A role string only counts as the exact org_admin role, not a look-alike.
    ops = OrgPolicyStore(MemoryStore())
    for fake in ("org_admin ", "ORG_ADMIN", "org-admin", "admin"):
        with pytest.raises(PermissionDeniedError):
            _save(ops, Principal("x", frozenset({fake})), _dump(ORG_DOC))


def test_a_bad_org_policy_is_refused_and_leaves_the_old_one() -> None:
    ops = OrgPolicyStore(MemoryStore())
    _save(ops, ADMIN, _dump(ORG_DOC))
    bad = copy.deepcopy(ORG_DOC)
    bad["floors"]["mandatory_gate_roles"]["review"] = ["developer"]
    with pytest.raises(SchemaError):
        _save(ops, ADMIN, _dump(bad))
    pol = ops.read()
    assert pol is not None
    assert pol.floors.mandatory_gate_roles["review"] == ("reviewer",)


def test_org_policy_store_refuses_a_document_of_another_kind() -> None:
    ops = OrgPolicyStore(MemoryStore())
    with pytest.raises(SchemaError):
        _save(ops, ADMIN, _dump(WF_DOC))


def test_require_raises_when_no_policy_was_ever_written() -> None:
    with pytest.raises(PolicyMissingError):
        OrgPolicyStore(MemoryStore()).require()


def test_team_config_write_needs_that_teams_admin_or_an_org_admin() -> None:
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
    }
    tcs = TeamConfigStore(MemoryStore())
    scope = TeamScope("ledger")
    with pytest.raises(PermissionDeniedError):
        _save_team(
            tcs,
            scope,
            Principal("d", frozenset({"developer", "reviewer"}), team="ledger"),
            _dump(cfg),
        )
    with pytest.raises(PermissionDeniedError):  # team_admin of another team
        _save_team(tcs, scope, Principal("t", frozenset({"team_admin"}), team="other"), _dump(cfg))
    with pytest.raises(PermissionDeniedError):  # roles with no team are not a team admin anywhere
        _save_team(tcs, scope, Principal("t", frozenset({"team_admin"})), _dump(cfg))
    assert tcs.read(scope) is None
    _save_team(tcs, scope, TEAM_ADMIN, _dump(cfg))
    got = tcs.read(scope)
    assert isinstance(got, TeamConfig)
    assert got.budgets.run_usd == 40
    _save_team(tcs, scope, ADMIN, _dump({**cfg, "wip_limit": 3}))
    got = tcs.read(scope)
    assert got is not None
    assert got.wip_limit == 3


def test_team_config_is_stored_per_team_and_must_name_that_team() -> None:
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "other"},
        "budgets": {"run_usd": 1, "team_monthly_usd": 2},
    }
    store = MemoryStore()
    tcs = TeamConfigStore(store)
    with pytest.raises(SchemaError, match="ledger"):
        _save_team(tcs, TeamScope("ledger"), ADMIN, _dump(cfg))
    _save_team(tcs, TeamScope("other"), ADMIN, _dump(cfg))
    assert tcs.read(TeamScope("ledger")) is None  # team A's scope does not see team B's document
    assert tcs.read(TeamScope("other")) is not None


def test_team_config_store_refuses_an_org_policy() -> None:
    with pytest.raises(SchemaError):
        _save_team(TeamConfigStore(MemoryStore()), TeamScope("ledger"), ADMIN, _dump(ORG_DOC))


# --- live reads ----------------------------------------------------------------------------


def test_a_tightened_floor_changes_the_next_read_on_a_pinned_run() -> None:
    ops = OrgPolicyStore(MemoryStore())
    _save(ops, ADMIN, _dump(ORG_DOC))
    pinned = _wf()  # the run's workflow is immutable and pinned
    first = ops.require()
    assert _check(pinned, first) == []
    assert quorum_floor(first, "ledger", "review") == 2
    assert surface_permitted(first, "review", "github")

    tight = copy.deepcopy(ORG_DOC)
    tight["teams"]["ledger"]["min_quorum"] = {"review": 3}
    tight["floors"]["decision_surfaces"]["review"] = ["ui"]
    _save(ops, ADMIN, _dump(tight))

    second = ops.require()  # the next read, same pinned workflow
    assert quorum_floor(second, "ledger", "review") == 3
    assert not surface_permitted(second, "review", "github")
    issues = _check(pinned, second)
    assert [i.path for i in issues] == ["stages.review_gate.gate.quorum"]
    assert "3" in issues[0].message


def test_a_loosened_floor_is_also_live() -> None:
    ops = OrgPolicyStore(MemoryStore())
    tight = copy.deepcopy(ORG_DOC)
    tight["teams"]["ledger"]["min_quorum"] = {"review": 3}
    _save(ops, ADMIN, _dump(tight))
    assert _check(_wf(), ops.require())
    _save(ops, ADMIN, _dump(ORG_DOC))
    assert _check(_wf(), ops.require()) == []


def test_team_config_reads_are_live_too() -> None:
    tcs = TeamConfigStore(MemoryStore())
    scope = TeamScope("ledger")
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
    }
    _save_team(tcs, scope, TEAM_ADMIN, _dump(cfg))
    cfg["budgets"] = {"run_usd": 10, "team_monthly_usd": 3000}
    _save_team(tcs, scope, TEAM_ADMIN, _dump(cfg))
    got = tcs.read(scope)
    assert got is not None
    assert got.budgets.run_usd == 10


# --- fail-closed reads ---------------------------------------------------------------------


def test_a_gate_type_missing_from_decision_surfaces_permits_nothing() -> None:
    pol = _policy()  # names review and qa, not custom or pre_push
    assert permitted_surfaces(pol, "review") == {"ui", "slack", "github"}
    for gate_type in ("custom", "pre_push"):
        assert permitted_surfaces(pol, gate_type) == frozenset()
        for surface in ("ui", "slack", "github"):
            assert not surface_permitted(pol, gate_type, surface)
    assert not surface_permitted(pol, "review", "carrier_pigeon")
    assert not surface_permitted(pol, "not_a_gate_type", "ui")


def test_mandatory_roles_fail_closed_for_a_gate_that_is_not_mandatory() -> None:
    pol = _policy()
    assert mandatory_roles(pol, "qa") == {"qa", "reviewer"}
    assert mandatory_roles(pol, "custom") == frozenset()
    assert mandatory_roles(pol, "nonsense") == frozenset()


def test_quorum_floor_defaults_to_one_and_unknown_teams_get_no_extra() -> None:
    pol = _policy()
    assert quorum_floor(pol, "ledger", "review") == 2
    assert quorum_floor(pol, "ledger", "qa") == 1
    assert quorum_floor(pol, "nobody", "review") == 1
    assert allowed_carry_over(pol, "ledger") == frozenset({"none"})
    assert allowed_carry_over(pol, "nobody") is None


# --- floors cannot be weakened by a team document ------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"min_quorum": {"review": 1}},
        {"mandatory_gate_roles": {"review": ["developer"]}},
        {"floors": {"single_human_allowed": True}},
        {"required_gates": []},
        {"allowed_carry_over": ["patch_id"]},
        {"decision_surfaces": {"review": ["github"]}},
        {"min_quorum": None},
        {"floors": None},
    ],
    ids=lambda e: next(iter(e)) + ("=null" if next(iter(e.values())) is None else ""),
)
def test_a_team_config_cannot_carry_org_floors_not_even_null(extra: dict[str, Any]) -> None:
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
        **extra,
    }
    with pytest.raises(SchemaError):
        _save_team(TeamConfigStore(MemoryStore()), TEAM_ADMIN_SCOPE, TEAM_ADMIN, _dump(cfg))
    with pytest.raises(SchemaError):
        load_document(_dump(cfg))


TEAM_ADMIN_SCOPE = TeamScope("ledger")


@pytest.mark.parametrize(
    "path",
    [
        ("teams", "ledger", "min_quorum"),
        ("teams", "ledger", "allowed_carry_over"),
        ("teams", "ledger", "required_gates"),
        ("floors", "hold_after_approval_min"),
        ("floors", "mandatory_gate_roles", "review"),
        ("floors", "decision_surfaces", "qa"),
        ("floors", "waive_allowed"),
    ],
    ids=lambda p: ".".join(p),
)
def test_a_null_in_a_policy_document_does_not_remove_a_floor(path: tuple[str, ...]) -> None:
    data = copy.deepcopy(ORG_DOC)
    node: Any = data
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = None
    with pytest.raises(SchemaError, match="null"):
        _save(OrgPolicyStore(MemoryStore()), ADMIN, _dump(data))


@pytest.mark.parametrize(
    "tp",
    [
        {"min_quorum": {"review": 0}},
        {"allowed_carry_over": []},
        {"min_quorum": {"review": -1}},
        {"min_quorum": {"review": True}},
    ],
    ids=["zero", "empty_carry_over", "negative", "bool"],
)
def test_team_policy_floors_cannot_be_zeroed(tp: dict[str, Any]) -> None:
    data = copy.deepcopy(ORG_DOC)
    data["teams"]["ledger"] = tp
    with pytest.raises(SchemaError):
        _save(OrgPolicyStore(MemoryStore()), ADMIN, _dump(data))


def test_a_workflow_that_nulls_out_its_quorum_still_meets_the_floor_or_fails_v17() -> None:
    # An overlay's null can flatten to a gate with no quorum. A missing quorum counts as one
    # approval, never as "no minimum".
    def drop(stages: dict[str, Any]) -> None:
        del stages["review_gate"]["gate"]["quorum"]

    issues = _check(_wf(drop), _policy())
    assert [i.path for i in issues] == ["stages.review_gate.gate.quorum"]


def test_a_gate_with_no_quorum_needs_one_approval_and_meets_a_floor_of_one() -> None:
    def drop(stages: dict[str, Any]) -> None:
        del stages["qa_gate"]["gate"]["quorum"]  # qa has no floor above the default of one

    assert _check(_wf(drop), _policy()) == []


# --- V17 -----------------------------------------------------------------------------------


def test_v17_accepts_a_workflow_that_meets_every_requirement() -> None:
    assert _check(_wf(), _policy()) == []


def test_v17_has_nothing_to_say_about_a_team_with_no_entry() -> None:
    def other_team(data: dict[str, Any]) -> None:
        data["teams"] = {"someone_else": data["teams"]["ledger"]}

    assert _check(_wf(), _policy(other_team)) == []


def test_v17_refuses_a_missing_required_gate() -> None:
    def rm(stages: dict[str, Any]) -> None:
        del stages["security_gate"]
        stages["route_risk"]["next"]["high"] = "review_gate"

    issues = _check(_wf(rm), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]
    assert "security_gate" in issues[0].message
    assert "security_officer" in issues[0].message


def test_v17_refuses_a_required_gate_that_is_not_a_gate() -> None:
    def swap(stages: dict[str, Any]) -> None:
        stages["security_gate"] = {
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "1d",
            "next": {"resumed": "review_gate", "timeout": "closed"},
        }

    issues = _check(_wf(swap), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]


def test_v17_refuses_a_required_gate_without_its_role() -> None:
    def role(stages: dict[str, Any]) -> None:
        g = stages["security_gate"]["gate"]
        g["eligible_roles"] = ["reviewer"]
        g["quorum"] = [{"role": "reviewer", "count": 1}]

    issues = _check(_wf(role), _policy())
    assert [i.path for i in issues] == ["stages.security_gate.gate.eligible_roles"]


def test_v17_refuses_a_required_gate_that_a_path_goes_around() -> None:
    def bypass(stages: dict[str, Any]) -> None:
        stages["qa_gate"]["next"]["approved"] = "done"
        stages["route_risk"]["next"]["default"] = "qa_gate"  # skips review_gate

    issues = _check(_wf(bypass), _policy())
    assert [i.path for i in issues] == ["stages.review_gate"]
    assert "round its approval" in issues[0].message


def test_v17_when_entry_only_binds_on_that_route_value() -> None:
    # security_gate is required when risk == high. Sending high around it is refused;
    # the default route skipping it is fine.
    def around(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["high"] = "review_gate"

    issues = _check(_wf(around), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]
    assert "risk" in issues[0].message
    assert "high" in issues[0].message


def test_v17_when_entry_uses_default_for_a_value_the_route_does_not_name() -> None:
    # No edge for "high": the route takes its default, which skips security_gate.
    def no_high(stages: dict[str, Any]) -> None:
        del stages["route_risk"]["next"]["high"]
        stages["security_gate"] = _gate(
            "custom", ["security_officer"], {"approved": "review_gate", "rejected": "closed"}
        )
        stages["route_risk"]["next"]["low"] = "security_gate"

    issues = _check(_wf(no_high), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]


def test_v17_when_entry_is_satisfied_by_a_default_that_goes_through_the_gate() -> None:
    def via_default(stages: dict[str, Any]) -> None:
        del stages["route_risk"]["next"]["high"]
        stages["route_risk"]["next"]["default"] = "security_gate"

    assert _check(_wf(via_default), _policy()) == []


def test_v17_when_entry_ignores_the_value_of_other_routes() -> None:
    # A route on another field is possible either way: every edge counts.
    def other_route(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["default"] = "route_prio"
        stages["route_prio"] = {
            "kind": "route",
            "field": "priority",
            "next": {"p1": "review_gate", "default": "qa_gate"},
        }

    issues = _check(_wf(other_route), _policy())
    assert [i.path for i in issues] == ["stages.review_gate"]


def test_v17_when_entry_follows_every_edge_of_a_route_on_another_field() -> None:
    # security_gate is required when risk is high. A priority route after the risk route can
    # still send a high-risk change round it, whatever the priority values are called.
    def bypass(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"] = {"high": "route_prio", "default": "review_gate"}
        stages["route_prio"] = {
            "kind": "route",
            "field": "priority",
            "next": {"p1": "review_gate", "default": "security_gate"},
        }

    def only_security(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["required_gates"] = [
            {
                "id": "security_gate",
                "role": "security_officer",
                "when": {"field": "risk", "value": "high"},
            }
        ]

    assert _paths(_check(_wf(bypass), _policy(only_security))) == ["stages.security_gate"]


def test_v17_refuses_quorum_below_the_floor_for_every_gate_of_that_type() -> None:
    def two_reviews(stages: dict[str, Any]) -> None:
        stages["review_gate"]["next"]["approved"] = "review2"
        stages["review2"] = _gate(
            "review", ["reviewer"], {"approved": "qa_gate", "rejected": "closed"}, count=1
        )

    issues = _check(_wf(two_reviews), _policy())
    assert [i.path for i in issues] == ["stages.review2.gate.quorum"]


def test_v17_counts_quorum_across_roles() -> None:
    def split(stages: dict[str, Any]) -> None:
        g = stages["review_gate"]["gate"]
        g["eligible_roles"] = ["reviewer", "security_officer"]
        g["quorum"] = [{"role": "reviewer", "count": 1}, {"role": "security_officer", "count": 1}]

    assert _check(_wf(split), _policy()) == []


def test_v17_refuses_carry_over_outside_the_allowed_set() -> None:
    def carry(stages: dict[str, Any]) -> None:
        stages["review_gate"]["gate"]["carry_over"] = "patch_id"

    issues = _check(_wf(carry), _policy())
    assert [i.path for i in issues] == ["stages.review_gate.gate.carry_over"]
    assert "patch_id" in issues[0].message


def test_v17_carry_over_default_none_is_checked_too() -> None:
    def only_patch(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["allowed_carry_over"] = ["patch_id"]

    issues = _check(_wf(), _policy(only_patch))
    assert {i.path for i in issues} == {
        "stages.security_gate.gate.carry_over",
        "stages.review_gate.gate.carry_over",
        "stages.qa_gate.gate.carry_over",
    }


def test_v17_reports_every_problem_at_once() -> None:
    def many(stages: dict[str, Any]) -> None:
        del stages["security_gate"]
        stages["route_risk"]["next"]["high"] = "review_gate"
        stages["review_gate"]["gate"]["quorum"][0]["count"] = 1
        stages["review_gate"]["gate"]["carry_over"] = "patch_id"

    paths = {i.path for i in _check(_wf(many), _policy())}
    assert paths == {
        "stages.security_gate",
        "stages.review_gate.gate.quorum",
        "stages.review_gate.gate.carry_over",
    }


def _wf_doc(mutate: Any = None) -> dict[str, Any]:
    data = copy.deepcopy(WF_DOC)
    if mutate:
        mutate(data)
    return data


def _load_wf(data: dict[str, Any]) -> Workflow:
    wf = load_document(_dump(data))
    assert isinstance(wf, Workflow)
    return wf


def _paths(issues: list[Any]) -> list[str]:
    return [i.path for i in issues]


# --- review pass 1: scenario 1, the team comes from the scope, never the file --------------


@pytest.mark.parametrize("claimed", ["sandbox", "Ledger", "ledger2", "ledger "], ids=str)
def test_v17_takes_the_team_from_the_scope_not_from_the_file(claimed: str) -> None:
    def weak(data: dict[str, Any]) -> None:
        data["metadata"]["team"] = claimed.strip() if claimed != "ledger " else "ledger2"
        del data["stages"]["security_gate"]
        data["stages"]["route_risk"]["next"]["high"] = "review_gate"
        g = data["stages"]["review_gate"]["gate"]
        g["quorum"][0]["count"] = 1
        g["carry_over"] = "patch_id"

    wf = _load_wf(_wf_doc(weak))
    issues = _check(wf, _policy(), team="ledger")  # published by a ledger admin
    assert "metadata.team" in _paths(issues)
    # and the ledger requirements are still reported, so the author sees every problem
    assert {
        "stages.security_gate",
        "stages.review_gate.gate.quorum",
        "stages.review_gate.gate.carry_over",
    } <= set(_paths(issues))


def test_v17_for_the_matching_team_has_no_team_issue() -> None:
    assert "metadata.team" not in _paths(_check(_wf(), _policy()))


def test_v17_checks_the_scope_teams_entry_only() -> None:
    def other(data: dict[str, Any]) -> None:
        data["teams"] = {"elsewhere": data["teams"]["ledger"]}

    def elsewhere(data: dict[str, Any]) -> None:
        data["metadata"]["team"] = "elsewhere"

    wf = _load_wf(_wf_doc(elsewhere))
    assert _check(wf, _policy(other), team="elsewhere") == []  # elsewhere's entry is met
    assert _check(_wf(), _policy(other), team="ledger") == []  # ledger has no entry


# --- scenario 2: the required role must really be the decider ------------------------------


def test_v17_refuses_a_diluted_role_with_a_quorum_for_someone_else() -> None:
    def dilute(stages: dict[str, Any]) -> None:
        g = stages["security_gate"]["gate"]
        g["eligible_roles"] = ["security_officer", "developer"]
        g["quorum"] = [{"role": "developer", "count": 1}]

    assert _paths(_check(_wf(dilute), _policy())) == ["stages.security_gate.gate.quorum"]


def test_v17_refuses_a_diluted_role_with_no_quorum() -> None:
    def dilute(stages: dict[str, Any]) -> None:
        g = stages["security_gate"]["gate"]
        g["eligible_roles"] = ["security_officer", "developer"]
        del g["quorum"]

    assert _paths(_check(_wf(dilute), _policy())) == ["stages.security_gate.gate.eligible_roles"]


def test_v17_accepts_a_single_role_gate_with_no_quorum_as_in_the_regulated_example() -> None:
    def plain(stages: dict[str, Any]) -> None:
        del stages["security_gate"]["gate"]["quorum"]  # PLAN 7.8: eligible_roles [security_officer]

    assert _check(_wf(plain), _policy()) == []


def test_v17_accepts_a_required_role_among_several_when_the_quorum_names_it() -> None:
    def ok(stages: dict[str, Any]) -> None:
        g = stages["security_gate"]["gate"]
        g["eligible_roles"] = ["security_officer", "developer"]
        g["quorum"] = [{"role": "security_officer", "count": 1}]

    assert _check(_wf(ok), _policy()) == []


# --- scenario 3: a merge is a successful end, whatever terminal follows --------------------

MERGE_STAGE = {
    "kind": "effect",
    "effect": "pr.merge",
    "requires_gates": ["review_gate"],
    "next": {"done": "closed", "conflict": "closed", "stale": "closed"},
}


def _high_skips_security(stages: dict[str, Any]) -> None:
    """high goes straight to review, default through security: the high route is the bypass."""
    stages["route_risk"]["next"] = {"high": "review_gate", "default": "security_gate"}


def test_v17_counts_a_merge_into_any_terminal_as_a_successful_end() -> None:
    def merge_then_closed(stages: dict[str, Any]) -> None:
        _high_skips_security(stages)
        stages["qa_gate"]["next"] = {"approved": "merge_it", "rejected": "closed"}
        stages["merge_it"] = copy.deepcopy(MERGE_STAGE)

    assert _paths(_check(_wf(merge_then_closed), _policy())) == ["stages.security_gate"]


def test_v17_counts_a_release_trigger_as_a_merge() -> None:
    def release(stages: dict[str, Any]) -> None:
        _high_skips_security(stages)
        stages["qa_gate"]["next"] = {"approved": "rel", "rejected": "closed"}
        stages["rel"] = {
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "closed", "stale": "closed"},
        }

    assert _paths(_check(_wf(release), _policy())) == ["stages.security_gate"]


def test_v17_does_not_count_a_merge_that_cannot_succeed() -> None:
    # reachable round the gate, but its only edges are conflict and stale: nothing ships
    def no_done(stages: dict[str, Any]) -> None:
        _high_skips_security(stages)
        stages["qa_gate"]["next"] = {"approved": "merge_it", "rejected": "closed"}
        stages["merge_it"] = {
            **copy.deepcopy(MERGE_STAGE),
            "next": {"conflict": "closed", "stale": "closed"},
        }

    assert _check(_wf(no_done), _policy()) == []


def test_v17_refuses_a_required_gate_that_sits_behind_a_merge() -> None:
    # Pass 2, finding 3: only a QA gate may follow a merge (V6, ADR-0005 item 12).
    def behind(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"] = {"high": "review_gate", "default": "review_gate"}
        stages["review_gate"]["next"]["approved"] = "merge_it"
        stages["merge_it"] = {
            **copy.deepcopy(MERGE_STAGE),
            "next": {"done": "security_gate", "conflict": "closed", "stale": "closed"},
        }
        stages["security_gate"]["next"] = {"approved": "done", "rejected": "closed"}

    def only_security(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["required_gates"] = [
            {"id": "security_gate", "role": "security_officer"}
        ]
        data["teams"]["ledger"]["min_quorum"] = {}

    paths = _paths(_check(_wf(behind), _policy(only_security)))
    assert "stages.security_gate" in paths


def test_v17_counts_done_with_incident_as_a_successful_end() -> None:
    def incident(data: dict[str, Any]) -> None:
        data["stages"]["done2"] = {"kind": "terminal", "result": "done_with_incident"}
        data["stages"]["route_risk"]["next"]["default"] = "done2"

    issues = _check(_load_wf(_wf_doc(incident)), _policy())
    assert _paths(issues) == ["stages.review_gate"]


def test_v17_follows_to_loop_edges() -> None:
    def edge_form(data: dict[str, Any]) -> None:
        data["stages"]["route_risk"]["next"]["default"] = {"to": "done", "loop": "x"}
        data["limits"]["loops"] = {"x": 1}

    assert _paths(_check(_load_wf(_wf_doc(edge_form)), _policy())) == ["stages.review_gate"]


def test_v17_follows_to_loop_edges_through_a_gate_that_is_satisfied() -> None:
    def edge_form(data: dict[str, Any]) -> None:
        data["stages"]["review_gate"]["next"]["approved"] = {"to": "qa_gate", "loop": "x"}
        data["limits"]["loops"] = {"x": 1}

    assert _check(_load_wf(_wf_doc(edge_form)), _policy()) == []


# --- scenario 4: on_external_commit is an entry point --------------------------------------


def _ci_flow(*, external: str | None) -> dict[str, Any]:
    gate = WF_DOC["stages"]["security_gate"]
    data = _wf_doc()
    data["start"] = "ci1"
    if external is not None:
        data["on_external_commit"] = external

    def ci() -> dict[str, Any]:
        return {"kind": "checks", "source": "ci", "required": ["unit"], "timeout": "1h"}

    data["stages"] = {
        "ci1": {**ci(), "next": {"green": "security_gate", "red": "closed"}},
        "security_gate": {
            **copy.deepcopy(gate),
            "next": {"approved": "ci2", "rejected": "closed"},
        },
        "ci2": {**ci(), "next": {"green": "review_gate", "red": "closed"}},
        "review_gate": copy.deepcopy(WF_DOC["stages"]["review_gate"]),
        "qa_gate": copy.deepcopy(WF_DOC["stages"]["qa_gate"]),
        "done": copy.deepcopy(WF_DOC["stages"]["done"]),
        "closed": copy.deepcopy(WF_DOC["stages"]["closed"]),
    }
    return data


def _always_security(data: dict[str, Any]) -> None:
    data["teams"]["ledger"]["required_gates"] = [
        {"id": "security_gate", "role": "security_officer"},
        {"id": "review_gate", "role": "reviewer"},
    ]


def test_v17_refuses_an_external_commit_that_lands_past_a_required_gate() -> None:
    wf = _load_wf(_ci_flow(external="ci2"))
    assert _paths(_check(wf, _policy(_always_security))) == ["stages.security_gate"]


def test_v17_accepts_an_external_commit_that_returns_before_the_gates() -> None:
    wf = _load_wf(_ci_flow(external="ci1"))
    assert _check(wf, _policy(_always_security)) == []


def test_v17_assumes_every_ci_stage_could_take_an_external_commit_when_unset() -> None:
    wf = _load_wf(_ci_flow(external=None))
    assert _paths(_check(wf, _policy(_always_security))) == ["stages.security_gate"]


# --- scenario 5: only approval passes a gate -----------------------------------------------


@pytest.mark.parametrize("outcome", ["changes_requested", "rejected"])
def test_v17_does_not_count_a_non_approval_as_passing(outcome: str) -> None:
    def loopback(stages: dict[str, Any]) -> None:
        stages["review_gate"]["next"] = {"approved": "qa_gate", outcome: "qa_gate"}
        stages["route_risk"]["next"]["default"] = "review_gate"

    assert _paths(_check(_wf(loopback), _policy())) == ["stages.review_gate"]


def test_v17_does_not_let_a_rejected_edge_go_to_done() -> None:
    def rejected_done(stages: dict[str, Any]) -> None:
        stages["review_gate"]["next"]["rejected"] = "done"

    assert _paths(_check(_wf(rejected_done), _policy())) == ["stages.review_gate"]


def test_v17_still_passes_a_gate_whose_other_outcomes_loop_back() -> None:
    def loops(data: dict[str, Any]) -> None:
        data["stages"]["impl"] = {
            "kind": "agent",
            "agent": "implementer",
            "next": {"done": "review_gate"},
        }
        data["stages"]["route_risk"]["next"]["high"] = "security_gate"
        data["stages"]["route_risk"]["next"]["default"] = "impl"
        data["stages"]["review_gate"]["next"] = {
            "approved": "qa_gate",
            "changes_requested": {"to": "impl", "loop": "fix"},
            "rejected": "closed",
        }
        data["limits"]["loops"] = {"fix": 2}

    assert _check(_load_wf(_wf_doc(loops)), _policy()) == []


# --- pass 2: the order of gates and merges, on small flows and on the real PLAN examples ----


def _flow(stages: dict[str, Any], *, start: str = "impl", **top: Any) -> Workflow:
    """A workflow of ``stages`` plus every terminal, for ledger."""
    data = _wf_doc()
    data["start"] = start
    data["limits"] = {"max_steps_per_run": 50, "max_run_age": "30d", "loops": {"fix": 3}}
    data["stages"] = {
        **copy.deepcopy(stages),
        "done": {"kind": "terminal", "result": "done"},
        "closed": {"kind": "terminal", "result": "closed"},
        "rejected_t": {"kind": "terminal", "result": "rejected"},
        "expired_t": {"kind": "terminal", "result": "expired"},
        "incident": {"kind": "terminal", "result": "done_with_incident"},
    }
    data.update(top)
    return _load_wf(data)


def _only(*gates: dict[str, Any]) -> Any:
    def apply(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["required_gates"] = list(gates)
        data["teams"]["ledger"]["min_quorum"] = {}
        data["teams"]["ledger"]["allowed_carry_over"] = ["none", "patch_id"]

    return _policy(apply)


SECURITY = {"id": "security_gate", "role": "security_officer"}
SECURITY_HIGH = {**SECURITY, "when": {"field": "risk", "value": "high"}}
LOOP: dict[str, Any] = {"to": "impl", "loop": "fix"}


def _merge(nxt: dict[str, Any], gates: tuple[str, ...] = ("review_gate", "security_gate")) -> Any:
    return {"kind": "effect", "effect": "pr.merge", "requires_gates": list(gates), "next": nxt}


def _security_flow(**overrides: Any) -> dict[str, Any]:
    """review -> security -> merge, all listed, every other outcome looping back to impl."""
    stages: dict[str, Any] = {
        "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "review_gate"}},
        "review_gate": _gate(
            "review",
            ["reviewer"],
            {"approved": "security_gate", "rejected": "closed", "changes_requested": LOOP},
        ),
        "security_gate": _gate(
            "custom",
            ["security_officer"],
            {"approved": "merge_ok", "rejected": "closed", "changes_requested": LOOP},
        ),
        "merge_ok": _merge({"done": "done", "conflict": "closed", "stale": "closed"}),
    }
    stages.update(copy.deepcopy(overrides))
    return stages


def test_v17_accepts_the_plain_security_flow() -> None:
    assert _check(_flow(_security_flow()), _only(SECURITY)) == []


def _quiet_merge(then: str, gates: tuple[str, ...] = ("review_gate",)) -> dict[str, Any]:
    return {
        "merge_quiet": _merge({"done": then, "conflict": "closed", "stale": "closed"}, gates),
    }


@pytest.mark.parametrize("outcome", ["changes_requested", "rejected", "retest", "expired"])
def test_v17_refuses_a_non_approval_that_leads_to_a_merge(outcome: str) -> None:
    stages = _security_flow(**_quiet_merge("closed"))
    stages["security_gate"]["next"][outcome] = "merge_quiet"
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


@pytest.mark.parametrize("terminal", ["rejected_t", "expired_t", "incident"])
def test_v17_refuses_a_non_approval_merge_whatever_the_terminal_is_called(terminal: str) -> None:
    stages = _security_flow(**_quiet_merge(terminal))
    stages["security_gate"]["next"]["changes_requested"] = "merge_quiet"
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


def test_v17_refuses_a_non_approval_that_leads_to_a_release() -> None:
    stages = _security_flow(
        rel={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "closed", "stale": "closed"},
        }
    )
    stages["security_gate"]["next"]["changes_requested"] = "rel"
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


def test_v17_refuses_a_second_merge_after_the_gate_answered_no() -> None:
    stages = _security_flow(**_quiet_merge("closed"))
    stages["security_gate"]["next"]["changes_requested"] = {"to": "impl", "loop": "fix"}
    stages["impl"]["next"] = {"ready": "review_gate", "blocked": "merge_quiet"}
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


def test_v17_refuses_a_cycle_back_to_before_the_gate_that_merges_round_it() -> None:
    stages = _security_flow(
        route_label={
            "kind": "route",
            "field": "label",
            "next": {"hotfix": "review_alt", "default": "review_gate"},
        },
        review_alt=_gate("review", ["reviewer"], {"approved": "merge_quiet", "rejected": "closed"}),
        **_quiet_merge("closed"),
    )
    stages["impl"]["next"] = {"ready": "route_label"}
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


def test_v17_refuses_a_when_gate_whose_changes_requested_skips_the_route() -> None:
    stages = {
        "route_risk": {
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"high": "security_gate", "default": "review_gate"},
        },
        "security_gate": _gate(
            "custom",
            ["security_officer"],
            {"approved": "review_ok", "changes_requested": "review_gate", "rejected": "closed"},
        ),
        "review_ok": _gate("review", ["reviewer"], {"approved": "merge_ok", "rejected": "closed"}),
        "review_gate": _gate(
            "review", ["reviewer"], {"approved": "merge_quiet", "rejected": "closed"}
        ),
        "merge_ok": _merge(
            {"done": "done", "conflict": "closed", "stale": "closed"},
            ("review_ok", "security_gate"),
        ),
        **_quiet_merge("closed"),
    }
    assert "stages.security_gate" in _paths(
        _check(_flow(stages, start="route_risk"), _only(SECURITY_HIGH))
    )


def _qa_after_merge(**overrides: Any) -> dict[str, Any]:
    stages: dict[str, Any] = {
        "impl": {"kind": "agent", "agent": "implementer", "next": {"ready": "review_gate"}},
        "review_gate": _gate(
            "review", ["reviewer"], {"approved": "merge_it", "rejected": "closed"}
        ),
        "merge_it": _merge(
            {"done": "qa_gate", "conflict": "closed", "stale": "closed"}, ("review_gate",)
        ),
        "qa_gate": _gate("qa", ["qa"], {"approved": "done", "rejected": "rejected_t"}),
        "revert": {"kind": "effect", "effect": "pr.open_revert", "next": {"done": "incident"}},
        "release": {
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["qa_gate"],
            "next": {"done": "closed", "stale": "closed"},
        },
        "merge2": _merge(
            {"done": "closed", "conflict": "closed", "stale": "closed"}, ("review_gate",)
        ),
        "await": {
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "1d",
            "next": {"resumed": "qa_gate", "timeout": "closed"},
        },
    }
    stages.update(copy.deepcopy(overrides))
    return stages


QA = {"id": "qa_gate", "role": "qa"}


def _qa_check(stages: dict[str, Any]) -> list[Any]:
    return _check(_flow(stages), _only(QA))


def _qa_next(**edges: Any) -> dict[str, Any]:
    stages = _qa_after_merge()
    stages["qa_gate"]["next"] = {"approved": "done", **edges}
    return stages


@pytest.mark.parametrize(
    "edges",
    [
        {"rejected": "rejected_t"},
        {"rejected": "expired_t"},
        {"rejected": "revert"},
        {"rejected": "revert", "changes_requested": "revert"},
    ],
    ids=["rejected", "expired", "revert_incident", "revert_both"],
)
def test_v17_lets_a_qa_gate_follow_a_merge_when_a_no_ends_rejected_or_reverted(
    edges: dict[str, Any],
) -> None:
    assert _qa_check(_qa_next(**edges)) == []


@pytest.mark.parametrize(
    "edges",
    [
        {"rejected": "closed"},
        {"rejected": "incident"},
        {"rejected": "done"},
        {"rejected": "rejected_t", "changes_requested": "release"},
        {"rejected": "rejected_t", "changes_requested": "merge2"},
        {"rejected": "rejected_t", "changes_requested": "closed"},
    ],
    ids=[
        "closed_no_revert",
        "incident_no_revert",
        "done",
        "release_after_no",
        "merge_after_no",
        "closed_after_no",
    ],
)
def test_v17_refuses_a_qa_gate_no_that_still_ends_successfully(edges: dict[str, Any]) -> None:
    assert "stages.qa_gate" in _paths(_qa_check(_qa_next(**edges)))


def test_v17_ignores_a_wait_timeout_once_merged() -> None:
    stages = _qa_after_merge()
    stages["merge_it"]["next"]["done"] = "await"  # timeout -> closed, but never taken after a merge
    assert _qa_check(stages) == []


def test_v17_does_not_let_a_second_merge_inherit_the_earlier_answer() -> None:
    # The gate said no, a revert opened, then a new merge shipped more code: closed after that
    # is a successful end again, because the new code has not been through the gate.
    stages = _qa_next(rejected="revert")
    stages["revert"]["next"] = {"done": "merge2"}
    assert "stages.qa_gate" in _paths(_qa_check(stages))


def test_v17_a_merge_before_a_qa_gate_that_ends_in_a_rejected_terminal_with_no_gate_passes() -> (
    None
):
    # Accepted gap, by ruling (V6 tolerates it): merge -> terminal `rejected` with no QA gate on
    # that path passes. This pins the ruling; it is not a bug.
    stages = _qa_after_merge()
    stages["merge_it"]["next"]["done"] = "rejected_t"
    assert _qa_check(stages) == []


# --- entry points: the search starts at start and at on_external_commit ----------------------


def _ci() -> dict[str, Any]:
    return {"kind": "checks", "source": "ci", "required": ["unit"], "timeout": "1h"}


def test_v17_still_searches_from_start_when_on_external_commit_is_set() -> None:
    # start skips the security gate; the external commit enters after it and is fine.
    stages = {
        "ci1": {**_ci(), "next": {"green": "review_gate", "red": "closed"}},
        "review_gate": _gate(
            "review", ["reviewer"], {"approved": "merge_it", "rejected": "closed"}
        ),
        "merge_it": _merge(
            {"done": "done", "conflict": "closed", "stale": "closed"}, ("review_gate",)
        ),
        "security_gate": _gate(
            "custom", ["security_officer"], {"approved": "ci1", "rejected": "closed"}
        ),
    }
    wf = _flow(stages, start="ci1", on_external_commit="security_gate")
    assert "stages.security_gate" in _paths(_check(wf, _only(SECURITY)))


def test_v17_unset_external_commit_means_ci_stages_only_not_every_checks_stage() -> None:
    # The qa_suite checks stage comes after the gate. Treating it as an entry would be a false
    # alarm: only a ci stage takes an external commit by default.
    stages = {
        "ci1": {**_ci(), "next": {"green": "security_gate", "red": "closed"}},
        "security_gate": _gate(
            "custom", ["security_officer"], {"approved": "suite", "rejected": "closed"}
        ),
        "suite": {**_ci(), "source": "qa_suite", "next": {"green": "merge_ok", "red": "closed"}},
        "merge_ok": _merge(
            {"done": "done", "conflict": "closed", "stale": "closed"}, ("security_gate",)
        ),
    }
    assert _check(_flow(stages, start="ci1"), _only(SECURITY)) == []


# --- finding 4: a gate must be listed by every merge or release it precedes ------------------


def test_v17_refuses_a_merge_after_the_gate_that_does_not_list_it() -> None:
    stages = _security_flow()
    stages["merge_ok"]["requires_gates"] = ["review_gate"]
    issues = _check(_flow(stages), _only(SECURITY))
    assert _paths(issues) == ["stages.merge_ok.requires_gates"]
    assert "security_gate" in issues[0].message


def test_v17_refuses_a_release_after_the_gate_that_does_not_list_it() -> None:
    stages = _security_flow(
        rel={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "done", "stale": "closed"},
        }
    )
    stages["security_gate"]["next"]["approved"] = "rel"
    assert _paths(_check(_flow(stages), _only(SECURITY))) == ["stages.rel.requires_gates"]


def test_v17_refuses_a_gate_before_any_code_that_no_merge_lists() -> None:
    stages = _security_flow()
    stages["early"] = _gate(
        "custom", ["security_officer"], {"approved": "impl", "rejected": "closed"}
    )
    stages["merge_ok"]["requires_gates"] = ["review_gate"]
    stages["security_gate"]["gate"]["eligible_roles"] = ["developer"]
    early = {"id": "early", "role": "security_officer"}
    wf = _flow(stages, start="early")
    assert _paths(_check(wf, _only(early))) == ["stages.merge_ok.requires_gates"]


def test_v17_leaves_a_when_entry_to_the_ratchet_for_requires_gates() -> None:
    stages = _security_flow()
    stages["merge_ok"]["requires_gates"] = ["review_gate"]
    stages["route_risk"] = {
        "kind": "route",
        "field": "risk",
        "order": ["low", "medium", "high"],
        "next": {"high": "security_gate", "default": "review_gate"},
    }
    stages["impl"]["next"] = {"ready": "route_risk"}
    stages["review_gate"]["next"]["approved"] = "merge_ok"
    assert _check(_flow(stages), _only(SECURITY_HIGH)) == []


# --- finding 5: a when gate needs the value in the order of every route on its field --------


def _risk_order(order: Any) -> Any:
    def apply(stages: dict[str, Any]) -> None:
        if order is None:
            del stages["route_risk"]["order"]
        else:
            stages["route_risk"]["order"] = order

    return apply


@pytest.mark.parametrize(
    "order", [None, ["low", "medium"], ["high"]][:2], ids=["no_order", "value_missing"]
)
def test_v17_refuses_a_when_route_whose_order_does_not_contain_the_value(order: Any) -> None:
    issues = _check(_wf(_risk_order(order)), _policy())
    assert "stages.route_risk.order" in _paths(issues)


def test_v17_accepts_a_when_route_whose_order_contains_the_value() -> None:
    assert _check(_wf(_risk_order(["low", "high"])), _policy()) == []


def test_v17_checks_the_order_of_every_route_on_the_field() -> None:
    def second(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["default"] = "route_again"
        stages["route_again"] = {
            "kind": "route",
            "field": "risk",
            "next": {"high": "security_gate", "default": "review_gate"},
        }

    assert _paths(_check(_wf(second), _policy())) == ["stages.route_again.order"]


def test_v17_does_not_ask_a_route_on_another_field_for_an_order() -> None:
    def other(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["default"] = "route_prio"
        stages["route_prio"] = {
            "kind": "route",
            "field": "priority",
            "next": {"p1": "review_gate", "default": "review_gate"},
        }

    assert _check(_wf(other), _policy()) == []


def test_v17_a_route_with_neither_the_value_nor_a_default_leads_nowhere() -> None:
    stages = {
        "route_risk": {
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"low": "done"},
        },
        "security_gate": _gate(
            "custom", ["security_officer"], {"approved": "done", "rejected": "closed"}
        ),
    }
    wf = _flow(stages, start="route_risk")
    assert _check(wf, _only(SECURITY_HIGH)) == []


# --- the real PLAN examples -----------------------------------------------------------------

PLAN_77_78 = PLAN_TEXT = (ROOT / "docs" / "PLAN.md").read_text(encoding="utf-8")


def _merge_patch(target: Any, patch: Any) -> Any:
    if not isinstance(patch, dict):
        return patch
    out = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        else:
            out[key] = _merge_patch(out.get(key), value)
    return out


def _plan_docs() -> dict[str, dict[str, Any]]:
    section = PLAN_TEXT[
        PLAN_TEXT.index("## 7. Workflow configuration") : PLAN_TEXT.index("## 8. Agents")
    ]
    docs: dict[str, dict[str, Any]] = {}
    for block in re.findall(r"```yaml\n(.*?)```", section, flags=re.S):
        if "apiVersion: sto/v1" not in block or ": string" in block:
            continue
        data = yaml.safe_load(block)
        meta = data.get("metadata") or {}
        if "name" in meta:
            docs[meta["name"]] = data
    return docs


def _flatten(name: str) -> dict[str, Any]:
    docs = _plan_docs()
    patch = {k: v for k, v in docs[name].items() if k != "extends"}
    flat = _merge_patch(docs["standard"], patch)
    flat["kind"] = "Workflow"
    return flat  # type: ignore[no-any-return]


def _team_policy(
    team: str,
    *gates: dict[str, Any],
    quorum: dict[str, int] | None = None,
    carry: tuple[str, ...] = ("none", "patch_id"),
) -> Any:
    def apply(data: dict[str, Any]) -> None:
        data["teams"] = {
            team: {
                "required_gates": list(gates),
                "min_quorum": quorum or {},
                "allowed_carry_over": list(carry),
            }
        }

    return _policy(apply)


LEDGER = _team_policy(
    "ledger",
    SECURITY,
    {"id": "change_gate", "role": "change_manager", "when": {"field": "risk", "value": "high"}},
    quorum={"review": 2},
    carry=("none",),
)


def test_the_regulated_example_meets_the_org_policy_that_PLAN_describes() -> None:
    wf = _load_wf(_flatten("ledger-regulated"))
    assert _check(wf, LEDGER) == []


def test_the_standard_workflow_meets_a_review_and_qa_requirement() -> None:
    doc = _flatten("standard")
    doc["metadata"] = {"name": "standard", "team": "ledger"}
    both = _team_policy(
        "ledger", {"id": "review_gate", "role": "reviewer"}, {"id": "qa_gate", "role": "qa"}
    )
    assert _check(_load_wf(doc), both) == []


def _kanban(qa_roles: list[str]) -> dict[str, Any]:
    doc = _flatten("platform-kanban")
    doc["metadata"] = {"name": "platform-kanban", "team": "ledger"}
    doc["stages"]["qa_gate"]["gate"]["eligible_roles"] = qa_roles
    return doc


def test_the_kanban_example_meets_a_requirement_on_its_qa_gate() -> None:
    assert _check(_load_wf(_kanban(["qa"])), _team_policy("ledger", QA)) == []


def test_the_kanban_example_meets_a_requirement_on_its_review_gate() -> None:
    review = _team_policy("ledger", {"id": "review_gate", "role": "reviewer"})
    assert _check(_load_wf(_kanban(["qa", "reviewer"])), review) == []


def test_the_kanban_qa_gate_as_written_is_refused_only_for_the_extra_role() -> None:
    # eligible_roles [qa, reviewer] with no quorum: a reviewer alone could pass the QA gate
    issues = _check(_load_wf(_kanban(["qa", "reviewer"])), _team_policy("ledger", QA))
    assert _paths(issues) == ["stages.qa_gate.gate.eligible_roles"]


# --- pass 4 ---------------------------------------------------------------------------------


def _release_to(then: str) -> dict[str, Any]:
    return {
        "kind": "effect",
        "effect": "release.trigger",
        "requires_gates": ["review_gate"],
        "next": {"done": then, "stale": then},
    }


def test_v17_refuses_a_release_after_the_qa_gate_said_no_even_for_an_exempt_gate() -> None:
    stages = _qa_next(rejected="rejected_t", changes_requested="release_bad")
    stages["release_bad"] = _release_to("rejected_t")
    assert "stages.qa_gate" in _paths(_qa_check(stages))


def test_v17_refuses_a_release_straight_after_a_merge_even_for_an_exempt_gate() -> None:
    stages = _qa_next(rejected="rejected_t")
    stages["merge_it"]["next"]["done"] = "release_bad"  # QA is never asked
    stages["release_bad"] = _release_to("rejected_t")
    assert "stages.qa_gate" in _paths(_qa_check(stages))


def test_the_kanban_example_with_a_release_round_its_qa_gate_is_refused() -> None:
    for edit in ("qa_no", "after_merge"):
        doc = _kanban(["qa"])
        st = doc["stages"]
        st["release_bad"] = {
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "closed_rejected", "stale": "closed_rejected"},
        }
        if edit == "qa_no":
            st["qa_gate"]["next"]["changes_requested"] = "release_bad"
        else:
            st["merge"]["next"]["done"] = "release_bad"
        paths = _paths(_check(_load_wf(doc), _team_policy("ledger", QA)))
        assert "stages.qa_gate" in paths, edit


def _wait_after_merge(timeout_to: str) -> dict[str, Any]:
    stages = _qa_after_merge(
        rel_ok={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["qa_gate"],
            "next": {"done": "closed", "stale": "closed"},
        },
        ticket_done={
            "kind": "effect",
            "effect": "ticket.transition",
            "with": {"to_status_category": "done"},
            "next": {"done": "closed"},
        },
    )
    stages["merge_it"]["next"]["done"] = "await"
    stages["await"]["next"] = {"resumed": "qa_gate", "timeout": timeout_to}
    return stages


@pytest.mark.parametrize("timeout_to", ["done", "rel_ok", "ticket_done", "incident"])
def test_v17_follows_a_wait_timeout_after_a_merge_that_does_not_give_up(timeout_to: str) -> None:
    assert "stages.qa_gate" in _paths(_qa_check(_wait_after_merge(timeout_to)))


@pytest.mark.parametrize("timeout_to", ["closed", "rejected_t", "expired_t"])
def test_v17_ignores_a_wait_timeout_after_a_merge_that_only_gives_up(timeout_to: str) -> None:
    assert _qa_check(_wait_after_merge(timeout_to)) == []


def _ungated_by_route(*, late_route: bool) -> dict[str, Any]:
    """security_gate (required when risk is high) reached with no route in front of it."""
    stages = _security_flow(
        late={
            "kind": "route",
            "field": "risk",
            "order": ["low", "medium", "high"],
            "next": {"default": "review_gate"},
        }
    )
    stages["merge_ok"]["requires_gates"] = ["review_gate"]  # nobody lists security_gate
    stages["impl"]["next"] = {"ready": "security_gate"}
    stages["security_gate"]["next"]["approved"] = "late" if late_route else "review_gate"
    stages["review_gate"]["next"]["approved"] = "merge_ok"
    return stages


@pytest.mark.parametrize("late_route", [False, True], ids=["no_route", "route_after_the_gate"])
def test_v17_holds_a_when_gate_that_no_route_reaches_to_requires_gates(late_route: bool) -> None:
    wf = _flow(_ungated_by_route(late_route=late_route))
    assert "stages.merge_ok.requires_gates" in _paths(_check(wf, _only(SECURITY_HIGH)))


def test_v17_does_not_count_a_route_on_another_field_as_holding_a_when_gate() -> None:
    stages = _ungated_by_route(late_route=False)
    stages["impl"]["next"] = {"ready": "route_prio"}
    stages["route_prio"] = {
        "kind": "route",
        "field": "priority",
        "order": ["low", "high"],
        "next": {"default": "security_gate"},
    }
    assert "stages.merge_ok.requires_gates" in _paths(_check(_flow(stages), _only(SECURITY_HIGH)))


def test_the_regulated_example_without_its_route_is_held_to_requires_gates() -> None:
    doc = _flatten("ledger-regulated")
    st = doc["stages"]
    del st["change_route"]
    st["qa_gate"]["next"]["approved"] = "mark_ready"
    st["triage"]["next"]["ready"] = "change_gate"
    st["change_gate"]["next"]["approved"] = "refine"
    doc["on_external_commit"] = "triage"
    assert "stages.merge.requires_gates" in _paths(_check(_load_wf(doc), LEDGER))


@pytest.mark.parametrize(
    "with_",
    [
        {"to_status_category": "Done"},
        {"to_status_category": "DONE"},
        {"to_status": "done"},
        None,
    ],
    ids=["Done", "DONE", "other_key", "no_with"],
)
def test_v17_counts_every_spelling_of_a_ticket_moved_to_done(with_: Any) -> None:
    ticket = _ticket_done()
    if with_ is None:
        del ticket["with"]
    else:
        ticket["with"] = with_
    stages = _security_flow(ticket_done=ticket)
    stages["security_gate"]["next"]["changes_requested"] = "ticket_done"
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


@pytest.mark.parametrize("category", ["in_progress", "In Progress", "todo"])
def test_v17_does_not_count_a_ticket_moved_to_another_category(category: str) -> None:
    ticket = _ticket_done()
    ticket["with"] = {"to_status_category": category}
    stages = _security_flow(ticket_state=ticket)
    stages["security_gate"]["next"]["changes_requested"] = "ticket_state"
    assert _check(_flow(stages), _only(SECURITY)) == []


def _qa_floor_policy(floor: int) -> Any:
    def apply(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["required_gates"] = [QA]
        data["teams"]["ledger"]["min_quorum"] = {"qa": floor}
        data["teams"]["ledger"]["allowed_carry_over"] = ["none"]

    return _policy(apply)


@pytest.mark.parametrize("written_type", ["qa", "custom", "review"])
def test_v17_applies_the_floor_of_the_role_not_only_of_the_written_type(
    written_type: str,
) -> None:
    stages = _qa_after_merge()
    stages["qa_gate"] = _gate(written_type, ["qa"], {"approved": "done", "rejected": "rejected_t"})
    issues = _check(_flow(stages), _qa_floor_policy(2))
    assert _paths(issues) == ["stages.qa_gate.gate.quorum"]  # once, not once per rule


def test_v17_accepts_the_role_floor_when_the_quorum_meets_it() -> None:
    stages = _qa_after_merge()
    stages["qa_gate"] = _gate(
        "custom", ["qa"], {"approved": "done", "rejected": "rejected_t"}, count=2
    )
    assert _check(_flow(stages), _qa_floor_policy(2)) == []


def test_v17_role_floors_leave_gates_the_org_did_not_require_alone() -> None:
    stages = _qa_after_merge()
    stages["other"] = _gate("custom", ["qa"], {"approved": "done", "rejected": "rejected_t"})
    stages["qa_gate"]["next"]["approved"] = "other"
    stages["qa_gate"]["gate"]["quorum"] = [{"role": "qa", "count": 2}]
    assert _check(_flow(stages), _qa_floor_policy(2)) == []


def test_v17_ranks_ignore_a_route_on_another_field() -> None:
    # a priority route whose order holds "high" says nothing about how risk is ranked
    def other_field(stages: dict[str, Any]) -> None:
        stages["security_gate"]["next"]["approved"] = "route_prio"
        stages["route_prio"] = {
            "kind": "route",
            "field": "priority",
            "order": ["low", "high", "urgent"],
            "next": {"default": "review_gate"},
        }

    assert _check(_wf(other_field), _policy()) == []


def _with_hotfix(doc: dict[str, Any], via: str) -> dict[str, Any]:
    """A second review, QA and merge after merge.<via>; the new merge does not list security."""
    doc = copy.deepcopy(doc)
    st = doc["stages"]
    doc["on_external_commit"] = "ci"
    st["impl2"] = {"kind": "agent", "agent": "implementer", "next": {"ready": "review2"}}
    st["review2"] = copy.deepcopy(st["review_gate"])
    st["review2"]["next"] = {
        "approved": "qa2",
        "changes_requested": {"to": "impl2", "loop": "human_review"},
        "rejected": "closed_rejected",
        "expired": "closed_expired",
    }
    st["qa2"] = copy.deepcopy(st["qa_gate"])
    st["qa2"]["next"] = {
        "approved": "merge_hotfix",
        "changes_requested": {"to": "impl2", "loop": "qa_fix"},
        "retest": {"to": "impl2", "loop": "retest"},
        "rejected": "closed_rejected",
        "expired": "closed_expired",
    }
    st["merge_hotfix"] = {
        "kind": "effect",
        "effect": "pr.merge",
        "requires_gates": ["review2", "qa2"],
        "next": {
            "done": "ticket_done2",
            "conflict": {"to": "impl2", "loop": "merge_conflict"},
            "stale": {"to": "impl2", "loop": "merge_stale"},
        },
    }
    st["ticket_done2"] = {
        "kind": "effect",
        "effect": "ticket.transition",
        "with": {"to_status_category": "done"},
        "requires_gates": ["review2", "qa2"],
        "next": {"done": "done"},
    }
    st["merge"]["next"][via] = {
        "to": "impl2",
        "loop": "merge_conflict" if via == "conflict" else "merge_stale",
    }
    return doc


@pytest.mark.parametrize("via", ["conflict", "stale"])
def test_v17_follows_a_failed_merge_into_a_second_merge_that_skips_the_gate(via: str) -> None:
    doc = _with_hotfix(_flatten("ledger-regulated"), via)
    assert "stages.merge_hotfix.requires_gates" in _paths(_check(_load_wf(doc), LEDGER))


def test_v17_follows_a_red_post_merge_check_into_another_merge() -> None:
    doc = _flatten("ledger-regulated")
    st = doc["stages"]
    doc["on_external_commit"] = "ci"
    st["post_merge"]["next"] = {"green": "evidence", "red": "fix2"}
    st["fix2"] = {"kind": "agent", "agent": "implementer", "next": {"ready": "merge_followup"}}
    st["merge_followup"] = {
        "kind": "effect",
        "effect": "pr.merge",
        "requires_gates": ["review_gate", "qa_gate"],
        "next": {"done": "done", "conflict": "closed", "stale": "closed"},
    }
    st["done"] = {"kind": "terminal", "result": "done"}
    paths = _paths(_check(_load_wf(doc), LEDGER))
    assert "stages.merge_followup.requires_gates" in paths


def test_v17_follows_a_stale_kanban_release_into_another_merge() -> None:
    doc = _kanban(["qa"])
    st = doc["stages"]
    doc["on_external_commit"] = "ci"
    st["release"]["next"]["stale"] = "fix3"
    st["fix3"] = {"kind": "agent", "agent": "implementer", "next": {"ready": "merge3"}}
    st["merge3"] = {
        "kind": "effect",
        "effect": "pr.merge",
        "requires_gates": ["review_gate"],
        "next": {"done": "ticket_done", "conflict": "closed", "stale": "closed"},
    }
    # the exemption covers what the removed-approval search reaches; merge3 is reached only past
    # the QA approval, so it must list the gate
    assert "stages.merge3.requires_gates" in _paths(
        _check(_load_wf(doc), _team_policy("ledger", QA))
    )


def test_the_kanban_qa_gate_with_a_quorum_for_qa_passes_with_both_roles_eligible() -> None:
    doc = _kanban(["qa", "reviewer"])
    doc["stages"]["qa_gate"]["gate"]["quorum"] = [{"role": "qa", "count": 1}]
    assert _check(_load_wf(doc), _team_policy("ledger", QA)) == []


@pytest.mark.parametrize(
    ("label", "edit"),
    [
        (
            "changes_requested -> release",
            lambda st: st["qa_gate"]["next"].update(changes_requested="release"),
        ),
        (
            "rejected -> closed with no revert",
            lambda st: st["qa_gate"]["next"].update(rejected="closed"),
        ),
        ("merge -> closed", lambda st: st["merge"]["next"].update(done="closed")),
    ],
)
def test_the_kanban_example_with_a_hole_is_refused(label: str, edit: Any) -> None:
    doc = _kanban(["qa"])
    edit(doc["stages"])
    assert "stages.qa_gate" in _paths(_check(_load_wf(doc), _team_policy("ledger", QA))), label


def test_the_kanban_qa_gate_reaches_release_only_through_its_approval() -> None:
    doc = _kanban(["qa"])
    assert doc["stages"]["release"]["requires_gates"] == ["qa_gate"]
    doc["stages"]["release"]["requires_gates"] = ["review_gate"]
    paths = _paths(_check(_load_wf(doc), _team_policy("ledger", QA)))
    assert paths == ["stages.release.requires_gates"]


# --- pass 3 ---------------------------------------------------------------------------------


def test_v17_refuses_a_revert_that_no_gate_answer_led_to() -> None:
    stages = _qa_after_merge()
    stages["merge_it"]["next"]["done"] = "revert"  # merge -> revert -> incident, gate never asked
    stages["revert"]["next"] = {"done": "closed"}
    assert "stages.qa_gate" in _paths(_qa_check(stages))


def test_v17_follows_a_wait_timeout_before_any_merge() -> None:
    stages = _security_flow(
        wait={
            "kind": "wait",
            "wait_for": "human_answer",
            "timeout": "1d",
            "next": {"resumed": "review_gate", "timeout": "done"},
        }
    )
    stages["impl"]["next"] = {"ready": "wait"}
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


def _typed_behind_a_merge(role: str, gate_type: str, gate_id: str) -> Workflow:
    """The team writes the type: a gate of ``gate_type`` behind a merge, required as ``role``."""
    return _flow(
        {
            "peer": _gate("review", ["reviewer"], {"approved": "merge_it", "rejected": "closed"}),
            "merge_it": _merge(
                {"done": gate_id, "conflict": "closed", "stale": "closed"}, ("peer",)
            ),
            gate_id: _gate(gate_type, [role], {"approved": "done", "rejected": "rejected_t"}),
        },
        start="peer",
    )


@pytest.mark.parametrize(
    ("role", "gate_id"), [("reviewer", "review_gate"), ("security_officer", "security_gate")]
)
def test_v17_gives_no_qa_exemption_to_a_role_the_org_did_not_assign_to_qa(
    role: str, gate_id: str
) -> None:
    wf = _typed_behind_a_merge(role, "qa", gate_id)  # written type: qa, behind the merge
    assert gate_id in [
        p.removeprefix("stages.") for p in _paths(_check(wf, _only({"id": gate_id, "role": role})))
    ]


def test_v17_gives_the_qa_exemption_to_the_role_the_org_assigned_to_qa() -> None:
    wf = _typed_behind_a_merge("qa", "qa", "qa_gate")
    assert _check(wf, _only(QA)) == []


def test_v17_the_exemption_does_not_depend_on_the_written_type() -> None:
    # same role the org assigned to qa, written as a custom gate: still exempt
    wf = _typed_behind_a_merge("qa", "custom", "qa_gate")
    assert _check(wf, _only(QA)) == []


def _regulated_with_order(order: list[str], **edges: str) -> dict[str, Any]:
    doc = _flatten("ledger-regulated")
    route = doc["stages"]["change_route"]
    route["order"] = order
    route["next"] = {"high": "change_gate", "default": "mark_ready", **edges}
    return doc


def test_v17_refuses_a_value_ranked_above_the_orgs_that_skips_the_gate() -> None:
    doc = _regulated_with_order(["low", "medium", "high", "critical"], critical="mark_ready")
    assert "stages.change_gate" in _paths(_check(_load_wf(doc), LEDGER))


def test_v17_refuses_an_order_that_ranks_the_orgs_value_below_the_others() -> None:
    doc = _regulated_with_order(["high", "medium", "low"])
    assert "stages.change_gate" in _paths(_check(_load_wf(doc), LEDGER))


def test_v17_accepts_values_ranked_above_when_they_take_the_gate_too() -> None:
    doc = _regulated_with_order(["low", "medium", "high", "critical"], critical="change_gate")
    assert _check(_load_wf(doc), LEDGER) == []


def test_v17_ignores_values_ranked_below_the_orgs() -> None:
    # low and medium may skip the gate: only high and above are the org's concern
    doc = _regulated_with_order(["low", "medium", "high"], low="mark_ready")
    assert _check(_load_wf(doc), LEDGER) == []


def _ticket_done(then: str = "closed") -> dict[str, Any]:
    return {
        "kind": "effect",
        "effect": "ticket.transition",
        "with": {"to_status_category": "done"},
        "next": {"done": then},
    }


def test_v17_counts_a_ticket_moved_to_done_as_getting_round_a_gate() -> None:
    stages = _security_flow(ticket_done=_ticket_done())
    stages["security_gate"]["next"]["changes_requested"] = "ticket_done"
    assert "stages.security_gate" in _paths(_check(_flow(stages), _only(SECURITY)))


@pytest.mark.parametrize("effect", ["branch.promote", "env.deploy_preview", "pr.mark_ready"])
def test_v17_does_not_count_other_effects_as_an_end(effect: str) -> None:
    stages = _security_flow(side={"kind": "effect", "effect": effect, "next": {"done": "closed"}})
    stages["security_gate"]["next"]["changes_requested"] = "side"
    assert _check(_flow(stages), _only(SECURITY)) == []


def test_v17_does_not_count_a_ticket_transition_to_another_category() -> None:
    other = _ticket_done()
    other["with"] = {"to_status_category": "in_progress"}
    stages = _security_flow(ticket_state=other)
    stages["security_gate"]["next"]["changes_requested"] = "ticket_state"
    assert _check(_flow(stages), _only(SECURITY)) == []


def test_v17_does_not_ask_a_ticket_transition_to_list_the_gate() -> None:
    stages = _security_flow(ticket_done=_ticket_done("done"))
    stages["merge_ok"]["next"]["done"] = "ticket_done"
    assert _check(_flow(stages), _only(SECURITY)) == []


def test_v17_asks_every_merge_after_the_gate_not_only_the_first() -> None:
    stages = _security_flow(
        again=_merge({"done": "done", "conflict": "closed", "stale": "closed"}, ("review_gate",))
    )
    stages["merge_ok"]["next"]["stale"] = "again"
    assert _paths(_check(_flow(stages), _only(SECURITY))) == ["stages.again.requires_gates"]


def test_v17_lets_a_release_after_a_merge_that_listed_the_gate() -> None:
    stages = _security_flow(
        rel={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "done", "stale": "closed"},
        }
    )
    stages["merge_ok"]["next"]["done"] = "rel"
    assert _check(_flow(stages), _only(SECURITY)) == []


def test_v17_does_not_let_a_release_pass_that_follows_an_unlisted_merge() -> None:
    stages = _security_flow(
        rel={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "done", "stale": "closed"},
        }
    )
    stages["merge_ok"]["requires_gates"] = ["review_gate"]  # the merge does not list security
    stages["merge_ok"]["next"]["done"] = "rel"
    paths = _paths(_check(_flow(stages), _only(SECURITY)))
    assert paths == ["stages.merge_ok.requires_gates", "stages.rel.requires_gates"]


def test_v17_does_not_let_a_release_pass_that_follows_no_listed_merge() -> None:
    stages = _security_flow(
        rel={
            "kind": "effect",
            "effect": "release.trigger",
            "requires_gates": ["review_gate"],
            "next": {"done": "done", "stale": "closed"},
        }
    )
    stages["merge_ok"]["next"]["conflict"] = "rel"  # the merge did not succeed
    assert _paths(_check(_flow(stages), _only(SECURITY))) == ["stages.rel.requires_gates"]


def test_the_regulated_example_without_order_on_its_route_is_refused() -> None:
    doc = _flatten("ledger-regulated")
    del doc["stages"]["change_route"]["order"]
    assert "stages.change_route.order" in _paths(_check(_load_wf(doc), LEDGER))


def test_the_regulated_example_with_the_security_gate_moved_before_the_code_is_refused() -> None:
    doc = _flatten("ledger-regulated")
    stages = doc["stages"]
    stages["security_gate"]["next"] = {
        "approved": "refine",
        "changes_requested": {"to": "triage", "loop": "security_fix"},
        "rejected": "closed_rejected",
        "expired": "closed_expired",
    }
    stages["triage"]["next"]["ready"] = "security_gate"
    stages["review_gate"]["next"]["approved"] = "promote"
    for sid in ("promote", "qa_env", "mark_ready", "merge", "ticket_done"):
        stages[sid]["requires_gates"] = [
            g for g in stages[sid]["requires_gates"] if g != "security_gate"
        ]
    doc["on_external_commit"] = "triage"
    paths = _paths(_check(_load_wf(doc), LEDGER))
    assert "stages.merge.requires_gates" in paths


# --- scenario 6: org_admin counts only with no team ----------------------------------------

ORG_ADMIN_IN_A_TEAM = Principal("m", frozenset({ORG_ADMIN}), team="ledger")


def test_an_org_admin_role_held_inside_a_team_cannot_write_org_policy() -> None:
    store = MemoryStore()
    with pytest.raises(PermissionDeniedError):
        _save(OrgPolicyStore(store), ORG_ADMIN_IN_A_TEAM, _dump(ORG_DOC))
    assert store.get(PLATFORM, Key("ORG", "POLICY")) is None


def test_an_org_admin_role_held_inside_a_team_cannot_write_another_teams_config() -> None:
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "other"},
        "budgets": {"run_usd": 1, "team_monthly_usd": 2},
    }
    with pytest.raises(PermissionDeniedError):
        _save_team(
            TeamConfigStore(MemoryStore()), TeamScope("other"), ORG_ADMIN_IN_A_TEAM, _dump(cfg)
        )


# --- scenario 7: no lost updates -----------------------------------------------------------


def test_a_stale_org_policy_save_cannot_undo_a_tightened_floor() -> None:
    ops = OrgPolicyStore(MemoryStore())
    ops.write(ADMIN, _dump(ORG_DOC), expected_version=None)
    a = ops.read_versioned()
    b = ops.read_versioned()
    assert a is not None
    assert b is not None
    tight = copy.deepcopy(ORG_DOC)
    tight["teams"]["ledger"]["min_quorum"] = {"review": 3}
    ops.write(ADMIN, _dump(tight), expected_version=a.version)  # admin A, after an incident
    with pytest.raises(ConditionFailedError):
        ops.write(ADMIN, _dump(ORG_DOC), expected_version=b.version)  # admin B, older copy
    assert quorum_floor(ops.require(), "ledger", "review") == 3


def test_creating_an_org_policy_twice_fails_the_second_time() -> None:
    ops = OrgPolicyStore(MemoryStore())
    ops.write(ADMIN, _dump(ORG_DOC), expected_version=None)
    with pytest.raises(ConditionFailedError):
        ops.write(ADMIN, _dump(ORG_DOC), expected_version=None)


def test_a_write_between_the_read_and_the_put_is_not_overwritten() -> None:
    """The race is in the store, not in the method: a write that lands after read_versioned
    is caught by the condition on the put."""
    store = MemoryStore()
    ops = OrgPolicyStore(store)
    ops.write(ADMIN, _dump(ORG_DOC), expected_version=None)
    seen = ops.read_versioned()
    assert seen is not None
    store.put(PLATFORM, Key("ORG", "POLICY"), {"text": _dump(ORG_DOC)})  # someone else, now
    with pytest.raises(ConditionFailedError):
        ops.write(ADMIN, _dump(ORG_DOC), expected_version=seen.version)


def test_a_stale_team_config_save_cannot_undo_a_change() -> None:
    scope = TeamScope("ledger")
    tcs = TeamConfigStore(MemoryStore())
    base = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
    }
    tcs.write(scope, TEAM_ADMIN, _dump(base), expected_version=None)
    a = tcs.read_versioned(scope)
    b = tcs.read_versioned(scope)
    assert a is not None
    assert b is not None
    tcs.write(scope, TEAM_ADMIN, _dump({**base, "wip_limit": 2}), expected_version=a.version)
    with pytest.raises(ConditionFailedError):
        tcs.write(scope, TEAM_ADMIN, _dump(base), expected_version=b.version)
    with pytest.raises(ConditionFailedError):
        tcs.write(scope, TEAM_ADMIN, _dump(base), expected_version=None)
    got = tcs.require(scope)
    assert got.wip_limit == 2


def test_a_write_to_team_config_between_the_read_and_the_put_is_not_overwritten() -> None:
    scope = TeamScope("ledger")
    store = MemoryStore()
    tcs = TeamConfigStore(store)
    base = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
    }
    tcs.write(scope, TEAM_ADMIN, _dump(base), expected_version=None)
    seen = tcs.read_versioned(scope)
    assert seen is not None
    store.put(scope, Key("TEAM", "CONFIG"), {"text": _dump(base)})
    with pytest.raises(ConditionFailedError):
        tcs.write(scope, TEAM_ADMIN, _dump(base), expected_version=seen.version)


# --- nits ----------------------------------------------------------------------------------

TEAM_CFG = (
    "apiVersion: sto/v1\nkind: TeamConfig\nmetadata: {team: ledger}\n"
    "budgets: {run_usd: 40, team_monthly_usd: 3000}\n"
)


@pytest.mark.parametrize("data", [{}, {"text": None}, {"text": 5}], ids=["missing", "none", "int"])
def test_a_malformed_stored_record_is_a_schema_error_not_a_key_error(data: dict[str, Any]) -> None:
    store = MemoryStore()
    store.put(PLATFORM, Key("ORG", "POLICY"), data)
    for call in (
        OrgPolicyStore(store).read,
        OrgPolicyStore(store).read_versioned,
        OrgPolicyStore(store).require,
    ):
        with pytest.raises(SchemaError):
            call()
    store.put(TeamScope("ledger"), Key("TEAM", "CONFIG"), data)
    for tcall in (
        TeamConfigStore(store).read,
        TeamConfigStore(store).read_versioned,
        TeamConfigStore(store).require,
    ):
        with pytest.raises(SchemaError):
            tcall(TeamScope("ledger"))


def test_a_stored_org_policy_of_another_kind_is_refused_on_read() -> None:
    store = MemoryStore()
    store.put(PLATFORM, Key("ORG", "POLICY"), {"text": _dump(WF_DOC)})
    with pytest.raises(SchemaError, match="not an OrgPolicy"):
        OrgPolicyStore(store).read()


def test_a_stored_team_config_of_another_kind_is_refused_on_read() -> None:
    store = MemoryStore()
    store.put(TeamScope("ledger"), Key("TEAM", "CONFIG"), {"text": _dump(ORG_DOC)})
    with pytest.raises(SchemaError, match="not a TeamConfig"):
        TeamConfigStore(store).read(TeamScope("ledger"))


def test_team_config_read_checks_the_document_names_the_scope_team() -> None:
    store = MemoryStore()
    store.put(
        TeamScope("ledger"), Key("TEAM", "CONFIG"), {"text": TEAM_CFG.replace("ledger", "other")}
    )
    with pytest.raises(SchemaError, match="other"):
        TeamConfigStore(store).read(TeamScope("ledger"))


def test_team_config_require_does_not_return_none() -> None:
    with pytest.raises(TeamConfigMissingError):
        TeamConfigStore(MemoryStore()).require(TeamScope("ledger"))


def test_bytes_are_refused_with_a_schema_error() -> None:
    with pytest.raises(SchemaError, match="text"):
        OrgPolicyStore(MemoryStore()).write(
            ADMIN,
            _dump(ORG_DOC).encode(),  # type: ignore[arg-type]
            expected_version=None,
        )
    with pytest.raises(SchemaError, match="text"):
        TeamConfigStore(MemoryStore()).write(
            TeamScope("ledger"),
            ADMIN,
            TEAM_CFG.encode(),  # type: ignore[arg-type]
            expected_version=None,
        )


def test_an_oversized_document_is_a_schema_error_not_a_store_error() -> None:
    big = TEAM_CFG + "qa: {test_domains: [" + ",".join(["a.example.com"] * 40000) + "]}\n"
    assert len(big.encode()) > MAX_DOCUMENT_BYTES
    with pytest.raises(SchemaError, match="bytes"):
        TeamConfigStore(MemoryStore()).write(TeamScope("ledger"), ADMIN, big, expected_version=None)
    with pytest.raises(SchemaError, match="bytes"):
        OrgPolicyStore(MemoryStore()).write(
            ADMIN, "# " + "x" * MAX_DOCUMENT_BYTES, expected_version=None
        )


def test_an_empty_mandatory_answer_means_not_mandatory() -> None:
    pol = _policy()
    assert all(mandatory_roles(pol, t) for t in ("pre_push", "review", "qa"))  # never empty
    assert mandatory_roles(pol, "custom") == frozenset()


# --- tracking ------------------------------------------------------------------------------


def _all_floor_keys() -> set[str]:
    return {f"floors.{n}" for n in Floors.model_fields} | {
        f"teams.*.{n}" for n in TeamPolicy.model_fields
    }


def test_tracking_lists_every_floor_the_schema_has() -> None:
    assert set(FLOOR_TRACKING) == _all_floor_keys()


def test_every_open_floor_names_issues_that_exist() -> None:
    open_ = open_floors()
    assert open_, "every floor is enforced: replace this tracking test with the enforcement tests"
    for key, issues in open_.items():
        assert issues, key
        for issue in issues:
            assert re.fullmatch(r"D\d+-\d+", issue), (key, issue)
            assert re.search(rf"^#### {issue}: ", STAGES_MD, flags=re.M), (
                f"{key}: {issue} is not in STAGES.md"
            )


def test_a_floor_marked_enforced_points_at_a_real_test() -> None:
    for key, entry in FLOOR_TRACKING.items():
        if not entry.done:
            assert not entry.evidence, key
            continue
        path, _, name = entry.evidence.partition("::")
        text = (ROOT / path).read_text(encoding="utf-8")
        assert re.search(rf"^def {re.escape(name)}\(", text, flags=re.M), f"{key}: {entry.evidence}"


def test_the_v17_floors_stay_open_until_publish_migrate_and_live_call_it() -> None:
    # check_org_required_gates is proved here but nothing calls it yet (PLAN 7.3: publish,
    # migrate and live), so these floors are not enforced and must say who wires them.
    for key in ("teams.*.required_gates", "teams.*.min_quorum", "teams.*.allowed_carry_over"):
        assert not FLOOR_TRACKING[key].done, key
        assert FLOOR_TRACKING[key].issues == ("D2-07", "D2-19", "D3-16"), key


def test_decision_surfaces_waits_for_both_the_validator_and_the_surface_check() -> None:
    # V10 (D2-03) checks them at publish; D3-16 checks the surface of a decision
    assert FLOOR_TRACKING["floors.decision_surfaces"].issues == ("D2-03", "D3-16")


def test_open_floor_report_names_the_issues() -> None:
    report = org_policy.open_floor_report()
    for key, issues in open_floors().items():
        assert f"{key}: {', '.join(issues)}" in report


def test_team_config_module_is_only_documents_and_storage() -> None:
    # TeamConfig has no floors of its own to read; the module must not grow a back door.
    assert not hasattr(team_config, "quorum_floor")
