"""D3-19: commit attribution and term resolution.

Drives the real app with tokens from the fake issuer (the fixtures of the shared tenancy suite).
Every refusal test has an allowed twin, and the effect on eligibility is judged by the real
evaluator (``sto.gates.sod.evaluate``) on the records the routes wrote.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from test_tenancy import (
    ALPHA,
    BETA,
    ISS,
    TEAM_ROLES,
    World,
    actor_of,
    refused,
    seed_run,
)

from sto.api.auth import (
    ROUTES,
    Permission,
    RouteTableError,
    check_table,
    undeclared_routes,
)
from sto.api.routers.attribution import blockers, commit_key, read_records
from sto.config.org_policy import ORG_ADMIN
from sto.config.schema import Floors
from sto.domain import Gate, GateId, GateType, RunId, Subject
from sto.gates.service import verify_audit_chain
from sto.gates.sod import RunFacts, evaluate
from sto.identity.mapping import UserIdentity
from sto.store.ports import AUDIT

ATTRIBUTE = ("POST", "/runs/{run_id}/commits/{sha}:attribute")
RESOLVE = ("POST", "/runs/{run_id}/sod-terms:resolve")
BLOCKS = ("GET", "/runs/{run_id}/sod-blocks")
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
SHA2 = "b1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
PLATFORM_SHA = "c1b2c3d4e5f60718293a4b5c6d7e8f9012345678"


@pytest.fixture
def world() -> World:  # a fresh store per test: records and audit chains do not leak
    return World()


def call(
    app: FastAPI, method: str, path: str, token: str, body: dict[str, Any] | None = None
) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.request(
                method, path, headers={"Authorization": f"Bearer {token}"}, json=body
            )

    return asyncio.run(asyncio.wait_for(go(), 20))


def put_commit(world: World, run_id: RunId, sha: str = SHA, **over: Any) -> None:
    data: dict[str, Any] = {"sha": sha, "in_receipts": False, "coauthors": [], "pushers": []}
    world.runtime.store.put(world.scope, commit_key(run_id, sha), {**data, **over})


def admin_token(world: World, role: str = "team_admin") -> str:
    return world.token("org", ["org-admins"]) if role == ORG_ADMIN else world.user(ALPHA, role)


def gate(kind: GateType = GateType.REVIEW) -> Gate:
    subject = Subject(
        head_sha="b" * 40,
        patch_id="p1",
        ticket_revision="r1",
        evidence_digest="e1",
        attention_digest="t1",
    )
    return Gate(GateId.new(), RunId.new(), "g", kind, 1, subject)


FLOORS = Floors.model_validate(
    {
        "mandatory_gate_roles": {"review": ["reviewer"], "qa": ["qa"], "pre_push": ["reviewer"]},
        "decision_surfaces": {"review": ["ui"], "qa": ["ui"]},
        "hold_after_approval_min": "10m",
        "identity_max_age": "8h",
    }
)


def verdict(world: World, run_id: RunId, sub: str, *, requester: str | None = "x|y") -> Any:
    """May the reviewer ``sub`` approve a review gate, given the records the routes wrote?"""
    commits, resolutions = read_records(world.runtime.store, world.scope, run_id)
    who = UserIdentity(sub, ISS, frozenset({(ALPHA, "reviewer")}))
    actor = f"{ISS}|{sub}"
    facts = RunFacts(requester=requester, commits=commits, resolutions=resolutions)
    return evaluate(
        who=who,
        linked=True,
        team=ALPHA,
        gate=gate(),
        eligible_roles=frozenset({"reviewer"}),
        opened_with=frozenset({actor}),
        sod=None,
        floors=FLOORS,
        facts=facts,
    )


def stored(world: World, run_id: RunId, sha: str) -> dict[str, Any]:
    item = world.runtime.store.get(world.scope, commit_key(run_id, sha))
    assert item is not None
    return dict(item.data)


def audit(world: World, run_id: RunId) -> list[Any]:
    return [
        i.data for i in world.runtime.store.query(world.scope, f"RUN#{run_id}", table=AUDIT).items
    ]


# --- the routes are declared, and the table still holds -------------------------------------


def test_the_routes_are_declared_and_the_real_app_has_no_undeclared_route(world: World) -> None:
    assert ROUTES[ATTRIBUTE].permission is Permission.ATTRIBUTE_COMMIT
    assert ROUTES[RESOLVE].permission is Permission.ATTRIBUTE_COMMIT
    assert ROUTES[BLOCKS].permission is Permission.VIEW_RUNS
    for key in (ATTRIBUTE, RESOLVE):
        assert not ROUTES[key].service
        assert not ROUTES[key].also
    assert undeclared_routes(world.app()) == []


def test_a_parameter_with_a_colon_suffix_is_matched_and_compared_for_overlap() -> None:
    from sto.api.auth import RouteRule

    view = RouteRule(Permission.VIEW_RUNS)
    check_table({("POST", "/r/{id}:attribute"): view, ("POST", "/r/{id}:other"): view})
    check_table({("POST", "/r/{id}:attribute"): view, ("GET", "/r/fixed:attribute"): view})
    # a parameter is never empty, so the bare suffix is not a value the template matches
    check_table({("POST", "/r/{id}:attribute"): view, ("POST", "/r/:attribute"): view})
    for one, other in [
        ("/r/{id}:attribute", "/r/x:attribute"),  # a literal the template matches
        ("/r/{id}:attribute", "/r/{name}:attribute"),
        ("/r/{id}:attribute", "/r/{name}"),  # a bare parameter matches it too
        ("/r/{id}:attribute", "/r/{name}:{x}"),
    ]:
        with pytest.raises(RouteTableError):
            check_table({("POST", one): view, ("POST", other): view})
    for ok in ("/r/{id}:", "/r/{id}:a:b", "/r/{id}:{x}", "/r/{id}.json", "/r/x{id}:a"):
        with pytest.raises(RouteTableError):
            check_table({("POST", ok): view})


@pytest.mark.parametrize("role", [*TEAM_ROLES, ORG_ADMIN])
def test_who_may_attribute_and_resolve_is_the_matrix_row(world: World, role: str) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    app, token = world.app(), admin_token(world, role)
    attr = call(
        app, "POST", f"/runs/{run_id}/commits/{SHA}:attribute", token, {"attributed_to": "a|b"}
    )
    res = call(
        app,
        "POST",
        f"/runs/{run_id}/sod-terms:resolve",
        token,
        {"term": "requester", "actors": ["a|b"]},
    )
    if role in ("team_admin", ORG_ADMIN):
        assert (attr.status_code, res.status_code) == (200, 200), (attr.text, res.text)
    else:
        refused(attr, 403, "forbidden")
        refused(res, 403, "forbidden")
        assert audit(world, run_id) == []  # a refusal writes nothing
        records = world.runtime.store.query(world.scope, f"RUN#{run_id}", sk_prefix="SODRES#")
        assert records.items == ()
        assert "attributed_to" not in stored(world, run_id, SHA)


def test_another_teams_admin_and_a_service_are_refused(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    app = world.app()
    path = f"/runs/{run_id}/commits/{SHA}:attribute"
    refused(
        call(app, "POST", path, world.user(BETA, "team_admin"), {"attributed_to": "a|b"}),
        403,
        "forbidden",
    )
    svc = world.issuer.issue(
        sub="sto-client", audience="sto-client", groups=["alpha-team_admin"],
        extra={"client_id": "sto-client", "token_use": "access"},
    )  # fmt: skip
    refused(call(app, "POST", path, svc, {"attributed_to": "a|b"}), 403, "service_not_permitted")
    assert audit(world, run_id) == []


# --- attribution ---------------------------------------------------------------------------


def test_an_unattributed_commit_blocks_and_the_gate_report_says_who_can_clear_it(
    world: World,
) -> None:
    run_id = seed_run(world, started_by=actor_of(ALPHA, "developer"))
    put_commit(world, run_id)
    put_commit(world, run_id, PLATFORM_SHA, in_receipts=True)  # platform made it: no block
    r = call(world.app(), "GET", f"/runs/{run_id}/sod-blocks", world.user(ALPHA, "developer"))
    assert r.status_code == 200, r.text
    assert r.json() == {
        "blocked": True,
        "blocks": [
            {
                "reason": f"unattributed_commit:{SHA}",
                "clear_with": f"POST /runs/{{run_id}}/commits/{SHA}:attribute",
                "who_can_clear": ["team_admin", "org_admin"],
            }
        ],
    }


def test_attributing_unblocks_makes_the_actor_ineligible_and_bars_the_admin(world: World) -> None:
    run_id = seed_run(world, started_by=actor_of(ALPHA, "developer"))
    put_commit(world, run_id)
    assert verdict(world, run_id, "rev").reasons == (f"unattributed_commit:{SHA}",)
    target = f"{ISS}|rev"
    r = call(
        world.app(), "POST", f"/runs/{run_id}/commits/{SHA}:attribute",
        world.user(ALPHA, "team_admin"), {"attributed_to": target},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    assert r.json() == {"audited": True, "blocked": False, "blocks": []}
    # the person named is ineligible for the round; everyone else is unblocked
    assert verdict(world, run_id, "rev").reasons == ("committer",)
    assert verdict(world, run_id, "someone-else").allowed
    # the admin who attributed may not approve (admin self-service)
    assert verdict(world, run_id, "alpha-team_admin-user").reasons == ("admin_self_service",)


def test_attribution_is_audited_with_the_authenticated_actor(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    app = world.app()
    # the body cannot name the admin: whatever it says, the token's actor is recorded
    r = call(
        app, "POST", f"/runs/{run_id}/commits/{SHA}:attribute", world.token("org", ["org-admins"]),
        {"attributed_to": f"{ISS}|rev", "attributed_by": "forged|actor"},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    (entry,) = audit(world, run_id)
    assert (entry["action"], entry["actor"]) == ("commit.attributed", f"{ISS}|org")
    assert entry["data"] == {"sha": SHA, "attributed_to": f"{ISS}|rev"}
    record = stored(world, run_id, SHA)
    assert record["attributed_by"] == f"{ISS}|org"
    assert verify_audit_chain(world.runtime.store, world.scope, run_id) == 1


def test_attribution_refusals_write_nothing(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    put_commit(world, run_id, PLATFORM_SHA, in_receipts=True)
    app, tok = world.app(), world.user(ALPHA, "team_admin")
    base = f"/runs/{run_id}/commits"
    ok = {"attributed_to": f"{ISS}|rev"}
    cases: list[tuple[str, dict[str, Any], int, str]] = [
        (f"{base}/{PLATFORM_SHA}:attribute", ok, 409, "not_attributable"),
        (f"{base}/{SHA2}:attribute", ok, 404, "commit_not_found"),  # never observed
        (f"{base}/NOT-A-SHA:attribute", ok, 404, "commit_not_found"),
        (f"/runs/nope/commits/{SHA}:attribute", ok, 404, "run_not_found"),
        (f"{base}/{SHA}:attribute", {}, 422, "one_action_required"),
        (f"{base}/{SHA}:attribute", {**ok, "clear_exclusion": "a|b"}, 422, "one_action_required"),
        (f"{base}/{SHA}:attribute", {"attributed_to": "alice@example.test"}, 422, "invalid_actor"),
        (f"{base}/{SHA}:attribute", {"attributed_to": "iss|"}, 422, "invalid_actor"),
        (
            f"{base}/{SHA}:attribute",
            {"clear_exclusion": f"{ISS}|nobody"},
            404,
            "exclusion_not_found",
        ),
    ]
    for path, body, status, why in cases:
        refused(call(app, "POST", path, tok, body), status, why, (path, body))
    assert audit(world, run_id) == []
    assert "attributed_to" not in stored(world, run_id, SHA)
    # the allowed twin
    assert call(app, "POST", f"{base}/{SHA}:attribute", tok, ok).status_code == 200


def test_a_commit_cannot_be_attributed_twice(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    app, tok = world.app(), world.user(ALPHA, "team_admin")
    path = f"/runs/{run_id}/commits/{SHA}:attribute"
    assert call(app, "POST", path, tok, {"attributed_to": f"{ISS}|one"}).status_code == 200
    refused(
        call(app, "POST", path, tok, {"attributed_to": f"{ISS}|two"}), 409, "already_attributed"
    )
    assert len(audit(world, run_id)) == 1
    assert verdict(world, run_id, "one").reasons == ("committer",)


# --- clearing a false exclusion -------------------------------------------------------------


def coauthored(victim: str) -> dict[str, Any]:
    return {
        "attributed_to": f"{ISS}|author",
        "attributed_by": f"{ISS}|earlier-admin",
        "coauthors": [{"actor": f"{ISS}|{victim}", "source": "trailer", "cleared_by": None}],
        "pushers": [f"{ISS}|pushed"],
    }


def test_an_admin_clears_a_false_trailer_exclusion(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id, **coauthored("rev"))
    assert verdict(world, run_id, "rev").reasons == ("committer",)
    r = call(
        world.app(), "POST", f"/runs/{run_id}/commits/{SHA}:attribute",
        world.user(ALPHA, "team_admin"), {"clear_exclusion": f"{ISS}|rev"},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    assert verdict(world, run_id, "rev").allowed  # no longer excluded
    assert verdict(world, run_id, "alpha-team_admin-user").reasons == ("admin_self_service",)
    (entry,) = audit(world, run_id)
    assert (entry["action"], entry["actor"]) == (
        "commit.exclusion_cleared",
        f"{ISS}|alpha-team_admin-user",
    )
    assert entry["data"] == {"sha": SHA, "actor": f"{ISS}|rev"}


def test_a_person_cannot_clear_their_own_exclusion(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    me = f"{ISS}|alpha-team_admin-user"
    put_commit(world, run_id, coauthors=[{"actor": me, "source": "trailer", "cleared_by": None}],
               attributed_to=f"{ISS}|x", attributed_by=f"{ISS}|y")  # fmt: skip
    app = world.app()
    r = call(
        app, "POST", f"/runs/{run_id}/commits/{SHA}:attribute",
        world.user(ALPHA, "team_admin"), {"clear_exclusion": me},
    )  # fmt: skip
    refused(r, 403, "cannot_clear_own_exclusion")
    assert audit(world, run_id) == []
    assert verdict(world, run_id, "alpha-team_admin-user").reasons == ("committer",)
    # the allowed twin: a different admin may
    other = world.token("org", ["org-admins"])
    r = call(app, "POST", f"/runs/{run_id}/commits/{SHA}:attribute", other, {"clear_exclusion": me})
    assert r.status_code == 200, r.text
    assert verdict(world, run_id, "alpha-team_admin-user").allowed


def test_a_pusher_exclusion_cannot_be_cleared_and_a_clear_is_not_repeated(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id, **coauthored("rev"))
    app, tok = world.app(), world.user(ALPHA, "team_admin")
    path = f"/runs/{run_id}/commits/{SHA}:attribute"
    refused(
        call(app, "POST", path, tok, {"clear_exclusion": f"{ISS}|pushed"}),
        404,
        "exclusion_not_found",
    )
    assert call(app, "POST", path, tok, {"clear_exclusion": f"{ISS}|rev"}).status_code == 200
    refused(call(app, "POST", path, tok, {"clear_exclusion": f"{ISS}|rev"}), 409, "already_cleared")
    assert len(audit(world, run_id)) == 1


# --- term resolution ------------------------------------------------------------------------


def test_an_unknown_requester_blocks_until_an_admin_names_them(world: World) -> None:
    run_id = seed_run(world, started_by=None)  # a Jira automation started it: no requester
    app = world.app()
    r = call(app, "GET", f"/runs/{run_id}/sod-blocks", world.user(ALPHA, "reviewer"))
    assert [b["reason"] for b in r.json()["blocks"]] == ["unresolved_term:requester"]
    assert r.json()["blocks"][0]["who_can_clear"] == ["team_admin", "org_admin"]
    assert verdict(world, run_id, "rev", requester=None).reasons == ("unresolved_term:requester",)

    res = call(
        app, "POST", f"/runs/{run_id}/sod-terms:resolve", world.user(ALPHA, "team_admin"),
        {"term": "requester", "actors": [f"{ISS}|asker", f"{ISS}|asker"]},
    )  # fmt: skip
    assert res.status_code == 200, res.text
    assert res.json() == {"audited": True, "blocked": False, "blocks": []}
    assert verdict(world, run_id, "rev", requester=None).allowed
    assert verdict(world, run_id, "asker", requester=None).reasons == ("requester",)
    assert verdict(world, run_id, "alpha-team_admin-user", requester=None).reasons == (
        "admin_self_service",
    )
    (entry,) = audit(world, run_id)
    assert (entry["action"], entry["actor"]) == (
        "sod_term.resolved",
        f"{ISS}|alpha-team_admin-user",
    )
    assert entry["data"] == {"term": "requester", "actors": [f"{ISS}|asker"]}


def test_a_known_requester_does_not_block(world: World) -> None:
    run_id = seed_run(world, started_by=actor_of(ALPHA, "developer"))
    r = call(world.app(), "GET", f"/runs/{run_id}/sod-blocks", world.user(ALPHA, "auditor"))
    assert r.json() == {"blocked": False, "blocks": []}


def test_a_resolution_naming_nobody_or_nothing_valid_is_refused(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    app, tok = world.app(), world.user(ALPHA, "team_admin")
    path = f"/runs/{run_id}/sod-terms:resolve"
    for body in (
        {"term": "requester", "actors": []},
        {"term": "committer", "actors": [f"{ISS}|a"]},
        {"term": "requester", "actors": ["bob@example.test"]},
        {"term": "requester"},
    ):
        r = call(app, "POST", path, tok, body)
        assert r.status_code == 422, (body, r.text)
    refused(
        call(
            app,
            "POST",
            "/runs/nope/sod-terms:resolve",
            tok,
            {"term": "author", "actors": [f"{ISS}|a"]},
        ),
        404,
        "run_not_found",
    )
    assert audit(world, run_id) == []
    assert world.runtime.store.query(world.scope, f"RUN#{run_id}", sk_prefix="SODRES#").items == ()


# --- the report agrees with the evaluator, and writes survive a lost race --------------------


def test_the_report_names_exactly_what_the_evaluator_blocks_on(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    put_commit(world, run_id, SHA2, attributed_to=f"{ISS}|a", attributed_by=f"{ISS}|b")
    put_commit(world, run_id, PLATFORM_SHA, in_receipts=True)
    commits, resolutions = read_records(world.runtime.store, world.scope, run_id)
    reported = {b.reason for b in blockers(commits, resolutions, requester=None)}
    evaluated = set(verdict(world, run_id, "rev", requester=None).reasons)
    assert reported == evaluated == {f"unattributed_commit:{SHA}", "unresolved_term:requester"}
    assert {
        b.reason for b in blockers(commits, resolutions, requester="a|b", unresolved=["author"])
    } == {
        f"unattributed_commit:{SHA}",
        "unresolved_term:author",
    }


class FlakyOnce:
    """A store whose first transaction loses a race (as a moved audit chain head does)."""

    def __init__(self, inner: Any) -> None:
        self._inner, self.failed = inner, False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def transact(self, scope: Any, ops: Any) -> None:
        if not self.failed:
            self.failed = True
            from sto.store.ports import ConditionFailedError

            raise ConditionFailedError([len(list(ops)) - 1])
        self._inner.transact(scope, ops)


def test_a_lost_race_on_the_audit_chain_is_retried_not_reported(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    flaky = FlakyOnce(world.runtime.store)
    world.runtime.store = flaky
    r = call(
        world.app(), "POST", f"/runs/{run_id}/commits/{SHA}:attribute",
        world.user(ALPHA, "team_admin"), {"attributed_to": f"{ISS}|rev"},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    assert flaky.failed
    assert len(audit(world, run_id)) == 1


class Raced:
    """A store where another admin attributes the same commit between our read and our write."""

    def __init__(self, inner: Any, world: World, run_id: RunId) -> None:
        self._inner, self._world, self._run, self.raced = inner, world, run_id, False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def transact(self, scope: Any, ops: Any) -> None:
        if not self.raced:
            self.raced = True
            item = self._inner.get(scope, commit_key(self._run, SHA))
            self._inner.put(scope, item.key, {**item.data, "attributed_to": f"{ISS}|first",
                                              "attributed_by": f"{ISS}|other-admin"})  # fmt: skip
        self._inner.transact(scope, ops)


def test_two_admins_racing_on_one_commit_cannot_overwrite_each_other(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id)
    raced = Raced(world.runtime.store, world, run_id)
    world.runtime.store = raced
    r = call(
        world.app(), "POST", f"/runs/{run_id}/commits/{SHA}:attribute",
        world.user(ALPHA, "team_admin"), {"attributed_to": f"{ISS}|second"},
    )  # fmt: skip
    refused(r, 409, "already_attributed")
    assert raced.raced
    assert stored(world, run_id, SHA)["attributed_to"] == f"{ISS}|first"
    assert audit(world, run_id) == []  # the loser wrote no audit entry


def test_a_malformed_sha_is_refused_before_any_lookup(world: World) -> None:
    run_id = seed_run(world, started_by=None)
    put_commit(world, run_id, "NOT-A-SHA")  # a record exists, but the name is not a commit id
    r = call(
        world.app(), "POST", f"/runs/{run_id}/commits/NOT-A-SHA:attribute",
        world.user(ALPHA, "team_admin"), {"attributed_to": f"{ISS}|rev"},
    )  # fmt: skip
    refused(r, 404, "commit_not_found")
    assert "attributed_to" not in stored(world, run_id, "NOT-A-SHA")


def test_a_service_identity_never_attributes_even_if_it_reached_the_handler() -> None:
    from types import SimpleNamespace

    from sto.api.auth import Authorized
    from sto.api.routers.attribution import _admin
    from sto.api.routers.runs import ApiError
    from sto.identity.mapping import ServiceIdentity
    from sto.store.ports import PLATFORM

    service = Authorized(ServiceIdentity("svc", ISS, "svc"), PLATFORM)
    request: Any = SimpleNamespace(state=SimpleNamespace(auth=service))
    with pytest.raises(ApiError) as e:
        _admin(request)
    assert e.value.code == "identity_required"
