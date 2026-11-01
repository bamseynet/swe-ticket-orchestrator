"""D2-24: TeamConfig and OrgPolicy stored live, the typed read API, and V17.

The floors are read from the store at every call, so a run pinned to a workflow still sees a
tightened floor on its next read. Every question the read API answers fails closed: what the
policy does not name is nothing permitted, never anything.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from sto.config import org_policy, team_config
from sto.config.org_policy import (
    FLOOR_TRACKING,
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
from sto.config.team_config import TeamConfigStore
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key, TeamScope

ROOT = Path(__file__).resolve().parents[2]
STAGES_MD = (ROOT / "docs" / "STAGES.md").read_text(encoding="utf-8")


def _dump(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False)


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
    gtype: str, roles: list[str], nxt: dict[str, str], *, count: int = 1, carry: str = "none"
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
        ops.write(who, _dump(ORG_DOC))
    assert store.get(PLATFORM, Key("ORG", "POLICY")) is None  # nothing was written
    assert ops.read() is None


def test_org_admin_writes_org_policy_and_it_reads_back_typed() -> None:
    ops = OrgPolicyStore(MemoryStore())
    ops.write(ADMIN, _dump(ORG_DOC))
    pol = ops.read()
    assert pol is not None
    assert pol.teams["ledger"].min_quorum["review"] == 2


def test_org_admin_role_on_the_principal_is_not_a_team_scoped_claim() -> None:
    # A role string only counts as the exact org_admin role, not a look-alike.
    ops = OrgPolicyStore(MemoryStore())
    for fake in ("org_admin ", "ORG_ADMIN", "org-admin", "admin"):
        with pytest.raises(PermissionDeniedError):
            ops.write(Principal("x", frozenset({fake})), _dump(ORG_DOC))


def test_a_bad_org_policy_is_refused_and_leaves_the_old_one() -> None:
    ops = OrgPolicyStore(MemoryStore())
    ops.write(ADMIN, _dump(ORG_DOC))
    bad = copy.deepcopy(ORG_DOC)
    bad["floors"]["mandatory_gate_roles"]["review"] = ["developer"]
    with pytest.raises(SchemaError):
        ops.write(ADMIN, _dump(bad))
    pol = ops.read()
    assert pol is not None
    assert pol.floors.mandatory_gate_roles["review"] == ("reviewer",)


def test_org_policy_store_refuses_a_document_of_another_kind() -> None:
    ops = OrgPolicyStore(MemoryStore())
    with pytest.raises(SchemaError):
        ops.write(ADMIN, _dump(WF_DOC))


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
        tcs.write(
            scope, Principal("d", frozenset({"developer", "reviewer"}), team="ledger"), _dump(cfg)
        )
    with pytest.raises(PermissionDeniedError):  # team_admin of another team
        tcs.write(scope, Principal("t", frozenset({"team_admin"}), team="other"), _dump(cfg))
    with pytest.raises(PermissionDeniedError):  # roles with no team are not a team admin anywhere
        tcs.write(scope, Principal("t", frozenset({"team_admin"})), _dump(cfg))
    assert tcs.read(scope) is None
    tcs.write(scope, TEAM_ADMIN, _dump(cfg))
    got = tcs.read(scope)
    assert isinstance(got, TeamConfig)
    assert got.budgets.run_usd == 40
    tcs.write(scope, ADMIN, _dump({**cfg, "wip_limit": 3}))
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
        tcs.write(TeamScope("ledger"), ADMIN, _dump(cfg))
    tcs.write(TeamScope("other"), ADMIN, _dump(cfg))
    assert tcs.read(TeamScope("ledger")) is None  # team A's scope does not see team B's document
    assert tcs.read(TeamScope("other")) is not None


def test_team_config_store_refuses_an_org_policy() -> None:
    with pytest.raises(SchemaError):
        TeamConfigStore(MemoryStore()).write(TeamScope("ledger"), ADMIN, _dump(ORG_DOC))


# --- live reads ----------------------------------------------------------------------------


def test_a_tightened_floor_changes_the_next_read_on_a_pinned_run() -> None:
    ops = OrgPolicyStore(MemoryStore())
    ops.write(ADMIN, _dump(ORG_DOC))
    pinned = _wf()  # the run's workflow is immutable and pinned
    first = ops.require()
    assert check_org_required_gates(pinned, first) == []
    assert quorum_floor(first, "ledger", "review") == 2
    assert surface_permitted(first, "review", "github")

    tight = copy.deepcopy(ORG_DOC)
    tight["teams"]["ledger"]["min_quorum"] = {"review": 3}
    tight["floors"]["decision_surfaces"]["review"] = ["ui"]
    ops.write(ADMIN, _dump(tight))

    second = ops.require()  # the next read, same pinned workflow
    assert quorum_floor(second, "ledger", "review") == 3
    assert not surface_permitted(second, "review", "github")
    issues = check_org_required_gates(pinned, second)
    assert [i.path for i in issues] == ["stages.review_gate.gate.quorum"]
    assert "3" in issues[0].message


def test_a_loosened_floor_is_also_live() -> None:
    ops = OrgPolicyStore(MemoryStore())
    tight = copy.deepcopy(ORG_DOC)
    tight["teams"]["ledger"]["min_quorum"] = {"review": 3}
    ops.write(ADMIN, _dump(tight))
    assert check_org_required_gates(_wf(), ops.require())
    ops.write(ADMIN, _dump(ORG_DOC))
    assert check_org_required_gates(_wf(), ops.require()) == []


def test_team_config_reads_are_live_too() -> None:
    tcs = TeamConfigStore(MemoryStore())
    scope = TeamScope("ledger")
    cfg = {
        "apiVersion": "sto/v1",
        "kind": "TeamConfig",
        "metadata": {"team": "ledger"},
        "budgets": {"run_usd": 40, "team_monthly_usd": 3000},
    }
    tcs.write(scope, TEAM_ADMIN, _dump(cfg))
    cfg["budgets"] = {"run_usd": 10, "team_monthly_usd": 3000}
    tcs.write(scope, TEAM_ADMIN, _dump(cfg))
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
        TeamConfigStore(MemoryStore()).write(TEAM_ADMIN_SCOPE, TEAM_ADMIN, _dump(cfg))
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
        OrgPolicyStore(MemoryStore()).write(ADMIN, _dump(data))


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
        OrgPolicyStore(MemoryStore()).write(ADMIN, _dump(data))


def test_a_workflow_that_nulls_out_its_quorum_still_meets_the_floor_or_fails_v17() -> None:
    # An overlay's null can flatten to a gate with no quorum. A missing quorum counts as one
    # approval, never as "no minimum".
    def drop(stages: dict[str, Any]) -> None:
        del stages["review_gate"]["gate"]["quorum"]

    issues = check_org_required_gates(_wf(drop), _policy())
    assert [i.path for i in issues] == ["stages.review_gate.gate.quorum"]


def test_a_gate_with_no_quorum_needs_one_approval_and_meets_a_floor_of_one() -> None:
    def drop(stages: dict[str, Any]) -> None:
        del stages["qa_gate"]["gate"]["quorum"]  # qa has no floor above the default of one

    assert check_org_required_gates(_wf(drop), _policy()) == []


# --- V17 -----------------------------------------------------------------------------------


def test_v17_accepts_a_workflow_that_meets_every_requirement() -> None:
    assert check_org_required_gates(_wf(), _policy()) == []


def test_v17_has_nothing_to_say_about_a_team_with_no_entry() -> None:
    def other_team(data: dict[str, Any]) -> None:
        data["teams"] = {"someone_else": data["teams"]["ledger"]}

    assert check_org_required_gates(_wf(), _policy(other_team)) == []


def test_v17_refuses_a_missing_required_gate() -> None:
    def rm(stages: dict[str, Any]) -> None:
        del stages["security_gate"]
        stages["route_risk"]["next"]["high"] = "review_gate"

    issues = check_org_required_gates(_wf(rm), _policy())
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

    issues = check_org_required_gates(_wf(swap), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]


def test_v17_refuses_a_required_gate_without_its_role() -> None:
    def role(stages: dict[str, Any]) -> None:
        g = stages["security_gate"]["gate"]
        g["eligible_roles"] = ["reviewer"]
        g["quorum"] = [{"role": "reviewer", "count": 1}]

    issues = check_org_required_gates(_wf(role), _policy())
    assert [i.path for i in issues] == ["stages.security_gate.gate.eligible_roles"]


def test_v17_refuses_a_required_gate_that_a_path_goes_around() -> None:
    def bypass(stages: dict[str, Any]) -> None:
        stages["qa_gate"]["next"]["approved"] = "done"
        stages["route_risk"]["next"]["default"] = "qa_gate"  # skips review_gate

    issues = check_org_required_gates(_wf(bypass), _policy())
    assert [i.path for i in issues] == ["stages.review_gate"]
    assert "without" in issues[0].message


def test_v17_when_entry_only_binds_on_that_route_value() -> None:
    # security_gate is required when risk == high. Sending high around it is refused;
    # the default route skipping it is fine.
    def around(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["high"] = "review_gate"

    issues = check_org_required_gates(_wf(around), _policy())
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

    issues = check_org_required_gates(_wf(no_high), _policy())
    assert [i.path for i in issues] == ["stages.security_gate"]


def test_v17_when_entry_is_satisfied_by_a_default_that_goes_through_the_gate() -> None:
    def via_default(stages: dict[str, Any]) -> None:
        del stages["route_risk"]["next"]["high"]
        stages["route_risk"]["next"]["default"] = "security_gate"

    assert check_org_required_gates(_wf(via_default), _policy()) == []


def test_v17_when_entry_ignores_the_value_of_other_routes() -> None:
    # A route on another field is possible either way: every edge counts.
    def other_route(stages: dict[str, Any]) -> None:
        stages["route_risk"]["next"]["default"] = "route_prio"
        stages["route_prio"] = {
            "kind": "route",
            "field": "priority",
            "next": {"p1": "review_gate", "default": "qa_gate"},
        }

    issues = check_org_required_gates(_wf(other_route), _policy())
    assert [i.path for i in issues] == ["stages.review_gate"]


def test_v17_refuses_quorum_below_the_floor_for_every_gate_of_that_type() -> None:
    def two_reviews(stages: dict[str, Any]) -> None:
        stages["review_gate"]["next"]["approved"] = "review2"
        stages["review2"] = _gate(
            "review", ["reviewer"], {"approved": "qa_gate", "rejected": "closed"}, count=1
        )

    issues = check_org_required_gates(_wf(two_reviews), _policy())
    assert [i.path for i in issues] == ["stages.review2.gate.quorum"]


def test_v17_counts_quorum_across_roles() -> None:
    def split(stages: dict[str, Any]) -> None:
        g = stages["review_gate"]["gate"]
        g["eligible_roles"] = ["reviewer", "security_officer"]
        g["quorum"] = [{"role": "reviewer", "count": 1}, {"role": "security_officer", "count": 1}]

    assert check_org_required_gates(_wf(split), _policy()) == []


def test_v17_refuses_carry_over_outside_the_allowed_set() -> None:
    def carry(stages: dict[str, Any]) -> None:
        stages["review_gate"]["gate"]["carry_over"] = "patch_id"

    issues = check_org_required_gates(_wf(carry), _policy())
    assert [i.path for i in issues] == ["stages.review_gate.gate.carry_over"]
    assert "patch_id" in issues[0].message


def test_v17_carry_over_default_none_is_checked_too() -> None:
    def only_patch(data: dict[str, Any]) -> None:
        data["teams"]["ledger"]["allowed_carry_over"] = ["patch_id"]

    issues = check_org_required_gates(_wf(), _policy(only_patch))
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

    paths = {i.path for i in check_org_required_gates(_wf(many), _policy())}
    assert paths == {
        "stages.security_gate",
        "stages.review_gate.gate.quorum",
        "stages.review_gate.gate.carry_over",
    }


def test_v17_uses_the_workflows_own_team() -> None:
    def other(data: dict[str, Any]) -> None:
        data["teams"] = {"elsewhere": data["teams"]["ledger"]}

    wf_doc = copy.deepcopy(WF_DOC)
    wf_doc["metadata"]["team"] = "elsewhere"
    wf = load_document(_dump(wf_doc))
    assert isinstance(wf, Workflow)
    assert check_org_required_gates(wf, _policy(other)) == []  # elsewhere's entry is met
    assert check_org_required_gates(_wf(), _policy(other)) == []  # ledger has no entry


# --- tracking ------------------------------------------------------------------------------


def _all_floor_keys() -> set[str]:
    return {f"floors.{n}" for n in Floors.model_fields} | {
        f"teams.*.{n}" for n in TeamPolicy.model_fields
    }


def test_tracking_lists_every_floor_the_schema_has() -> None:
    assert set(FLOOR_TRACKING) == _all_floor_keys()


def test_every_open_floor_names_an_issue_that_exists() -> None:
    open_ = open_floors()
    assert open_, "every floor is enforced: replace this tracking test with the enforcement tests"
    for key, issue in open_.items():
        assert re.fullmatch(r"D\d+-\d+", issue), (key, issue)
        assert re.search(rf"^#### {issue}: ", STAGES_MD, flags=re.M), (
            f"{key}: {issue} is not in STAGES.md"
        )


def test_a_floor_marked_enforced_points_at_a_real_test() -> None:
    done = {k: v for k, v in FLOOR_TRACKING.items() if v.done}
    assert done
    for key, entry in done.items():
        path, _, name = entry.evidence.partition("::")
        text = (ROOT / path).read_text(encoding="utf-8")
        assert re.search(rf"^def {re.escape(name)}\(", text, flags=re.M), f"{key}: {entry.evidence}"
        assert entry.issue == "D2-24"


def test_the_v17_floors_are_the_ones_this_issue_enforces() -> None:
    assert {k for k, v in FLOOR_TRACKING.items() if v.done} == {
        "teams.*.required_gates",
        "teams.*.min_quorum",
        "teams.*.allowed_carry_over",
    }


def test_open_floor_report_names_the_issue() -> None:
    report = org_policy.open_floor_report()
    for key, issue in open_floors().items():
        assert f"{key}: {issue}" in report


def test_team_config_module_is_only_documents_and_storage() -> None:
    # TeamConfig has no floors of its own to read; the module must not grow a back door.
    assert not hasattr(team_config, "quorum_floor")
