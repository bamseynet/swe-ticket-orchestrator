"""D4-16: the fake GitHub's App auth, tokens, pagination, rate limits and errors.

Fixtures are synthetic (no real App ID, key, installation or token). Each behaviour asserted here
is documented, with its source URL, in ``server.py``; the live suite later proves it.
"""

from __future__ import annotations

import re

import pytest

from fakes.github.auth import (
    APP_ID,
    CLIENT_ID,
    INSTALLATION_ID,
    INSTALLATION_PERMISSIONS,
    INSTALLATION_REPOS,
    FakeGitHubAuth,
    RateShape,
    Response,
)

MIN = 60.0


@pytest.fixture
def gh() -> FakeGitHubAuth:
    return FakeGitHubAuth()


def installation_token(gh: FakeGitHubAuth) -> str:
    response = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID)
    assert response.status == 201
    return str(response.body["token"])


# --- App authentication: a JSON Web Token ---------------------------------------------------


def test_a_valid_app_jwt_yields_an_installation_token_that_expires_in_an_hour(
    gh: FakeGitHubAuth,
) -> None:
    response = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID)
    assert response.status == 201
    assert str(response.body["token"]).startswith("ghs_")
    assert response.body["expires_at"] == "1970-01-01T01:16:40Z"  # clock 1000 s + 3600 s
    assert gh.handle("read", str(response.body["token"])).status == 200


def test_each_installation_token_is_new(gh: FakeGitHubAuth) -> None:
    assert installation_token(gh) != installation_token(gh)


def test_an_app_jwt_may_live_at_most_ten_minutes(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(ttl=10 * MIN), INSTALLATION_ID).status == 201
    over = gh.create_installation_token(gh.app_jwt(ttl=10 * MIN + 1), INSTALLATION_ID)
    assert over.status == 401


def test_an_expired_app_jwt_is_refused(gh: FakeGitHubAuth) -> None:
    jwt = gh.app_jwt(ttl=60)
    gh.now += 61
    assert gh.create_installation_token(jwt, INSTALLATION_ID).status == 401


def test_an_app_jwt_issued_in_the_future_is_refused(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(iat_offset=120), INSTALLATION_ID).status == 401


def test_clock_drift_inside_a_minute_is_tolerated_for_iat(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(iat_offset=-60), INSTALLATION_ID).status == 201


@pytest.mark.parametrize(
    "jwt",
    ["", "garbage", "a.b", "a.b.c", "e30.e30.e30"],
    ids=["empty", "one-part", "two-parts", "undecodable", "no-claims"],
)
def test_a_jwt_that_cannot_be_decoded_is_refused(gh: FakeGitHubAuth, jwt: str) -> None:
    response = gh.create_installation_token(jwt, INSTALLATION_ID)
    assert response.status == 401
    assert "message" in response.body


def test_a_jwt_signed_with_another_key_is_refused(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(key=b"other"), INSTALLATION_ID).status == 401


def test_a_jwt_for_another_app_is_refused(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(app_id="999"), INSTALLATION_ID).status == 401


def test_an_unknown_installation_is_a_404(gh: FakeGitHubAuth) -> None:
    assert gh.create_installation_token(gh.app_jwt(), 424242).status == 404


def test_the_app_jwt_is_not_an_installation_token(gh: FakeGitHubAuth) -> None:
    assert gh.handle("read", gh.app_jwt()).status == 401


def test_an_app_jwt_may_name_the_app_by_client_id_or_by_app_id_as_text_or_number(
    gh: FakeGitHubAuth,
) -> None:
    for iss in (APP_ID, int(APP_ID), CLIENT_ID):
        assert gh.create_installation_token(gh.app_jwt(app_id=iss), INSTALLATION_ID).status == 201


@pytest.mark.parametrize("alg", ["HS256", "none", "RS512", ""])
def test_an_app_jwt_must_say_alg_rs256(gh: FakeGitHubAuth, alg: str) -> None:
    assert gh.create_installation_token(gh.app_jwt(alg=alg), INSTALLATION_ID).status == 401


def test_an_app_jwt_header_that_is_not_an_object_is_refused(gh: FakeGitHubAuth) -> None:
    good = gh.app_jwt().split(".")
    for header in (b"[]", b"null", b'"RS256"'):
        import base64

        forged = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
        jwt = ".".join([forged, good[1], good[2]])
        assert gh.create_installation_token(jwt, INSTALLATION_ID).status == 401


def test_the_jwt_time_boundaries_are_exact(gh: FakeGitHubAuth) -> None:
    mint = gh.create_installation_token
    assert mint(gh.app_jwt(iat_offset=0), INSTALLATION_ID).status == 201
    assert mint(gh.app_jwt(iat_offset=1), INSTALLATION_ID).status == 401
    assert mint(gh.app_jwt(ttl=1), INSTALLATION_ID).status == 201
    assert mint(gh.app_jwt(ttl=0), INSTALLATION_ID).status == 401


def test_the_app_id_is_synthetic() -> None:
    assert APP_ID == "100001"
    assert INSTALLATION_ID == 200002


# --- installation tokens ---------------------------------------------------------------------


def test_an_unknown_missing_or_expired_token_is_a_401(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    assert gh.handle("read", "ghs_nope").status == 401
    assert gh.handle("read", "").status == 401
    assert gh.handle("read", "ghs_nope").body == {"message": "Bad credentials"}
    gh.now += 3600
    assert gh.handle("read", good).status == 401


def test_a_token_works_until_the_second_it_expires(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.now += 3599
    assert gh.handle("read", good).status == 200


def test_a_revoked_token_is_a_401_and_other_tokens_still_work(gh: FakeGitHubAuth) -> None:
    a, b = installation_token(gh), installation_token(gh)
    gh.revoke(a)
    assert gh.handle("read", a).status == 401
    assert gh.handle("read", b).status == 200


def test_revoke_auth_rejects_every_request_or_one_operation_until_restored(
    gh: FakeGitHubAuth,
) -> None:
    good = installation_token(gh)
    gh.revoke_auth("read")
    assert gh.handle("read", good).status == 401
    assert gh.handle("lookup", good, page=1).status == 200
    gh.restore_auth()
    assert gh.handle("read", good).status == 200
    gh.revoke_auth()
    assert gh.handle("lookup", good, page=1).status == 401
    gh.restore_auth()
    assert gh.handle("lookup", good, page=1).status == 200


def test_expire_token_makes_the_held_token_stop_working_and_a_new_one_work(
    gh: FakeGitHubAuth,
) -> None:
    held = installation_token(gh)
    gh.expire_token(held)
    assert gh.handle("read", held).status == 401
    assert gh.handle("read", installation_token(gh)).status == 200


def test_every_unauthorized_answer_is_counted(gh: FakeGitHubAuth) -> None:
    gh.handle("read", "ghs_nope")
    gh.handle("read", "")
    assert gh.counts["unauthorized"] == 2


# --- the state read --------------------------------------------------------------------------


def test_read_returns_the_current_revision(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.revision = 7
    assert gh.handle("read", good).body["revision"] == 7
    gh.revision = 8
    assert gh.handle("read", good).body["revision"] == 8
    assert gh.counts["read"] == 2


def test_an_unknown_operation_is_a_programming_error_not_a_response(gh: FakeGitHubAuth) -> None:
    with pytest.raises(AssertionError, match="unknown op"):
        gh.handle("delete", installation_token(gh))


# --- pagination: GitHub's, one-based, and the link header says where the rest is --------------


def link(response: Response) -> dict[str, int]:
    """The page numbers of each rel in the link header (what a client must follow)."""
    found = re.findall(
        r"<[^>]*[?&]page=(\d+)[^>]*>; rel=\"(\w+)\"", response.headers.get("link", "")
    )
    return {rel: int(number) for number, rel in found}


def walk(gh: FakeGitHubAuth, token: str, **kw: object) -> list[str]:
    """Follow rel=next from the first page, as a client that never counts pages would."""
    ids: list[str] = []
    page = 1
    while True:
        response = gh.handle("lookup", token, page=page, **kw)
        ids += [i["id"] for i in response.body["items"]]
        nxt = link(response).get("next")
        if nxt is None:
            return ids
        page = nxt


def test_a_list_pages_at_the_requested_size_and_the_link_header_says_where_next_is(
    gh: FakeGitHubAuth,
) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    pages = [gh.handle("lookup", good, page=n, per_page=100) for n in (1, 2, 3)]
    assert [len(p.body["items"]) for p in pages] == [100, 100, 50]
    assert link(pages[0]) == {"next": 2, "last": 3}
    assert link(pages[1]) == {"prev": 1, "next": 3, "first": 1, "last": 3}
    assert link(pages[2]) == {"prev": 2, "first": 1}
    assert len(set(walk(gh, good, per_page=100))) == 250


def test_the_body_carries_no_next_field_only_the_link_header_does(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    assert set(gh.handle("lookup", good, page=1).body) == {"items"}


def test_omitting_page_means_page_one_and_per_page_defaults_to_thirty(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    first = gh.handle("lookup", good)
    assert len(first.body["items"]) == 30
    assert link(first) == {"next": 2, "last": 9}
    assert first.body == gh.handle("lookup", good, page=1).body
    assert len(walk(gh, good)) == 250  # following rel=next from the default reaches every item


def test_following_next_from_any_page_reaches_the_rest(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    second = gh.handle("lookup", good, page=2, per_page=100)
    third = gh.handle("lookup", good, page=link(second)["next"], per_page=100)
    assert len(third.body["items"]) == 50
    assert [i["id"] for i in third.body["items"]] == [
        i["id"] for i in gh.handle("lookup", good, page=3, per_page=100).body["items"]
    ]


def test_per_page_is_capped_at_a_hundred(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(150, "alice")
    assert len(gh.handle("lookup", good, page=1, per_page=1000).body["items"]) == 100
    assert len(gh.handle("lookup", good, page=1, per_page=30).body["items"]) == 30
    assert len(gh.handle("lookup", good, page=1, per_page=1).body["items"]) == 1


@pytest.mark.parametrize("per_page", [0, -5, "abc", ""])
def test_a_per_page_below_one_or_not_a_number_means_the_default_of_thirty(
    gh: FakeGitHubAuth, per_page: object
) -> None:
    """As GitHub answers, checked read-only: not 1 item, the default."""
    good = installation_token(gh)
    gh.seed(100, "alice")
    first = gh.handle("lookup", good, page=1, per_page=per_page)
    assert len(first.body["items"]) == 30
    assert link(first)["next"] == 2


@pytest.mark.parametrize("page", [0, -1, -100, "abc", "", "1.5"])
def test_a_page_below_one_or_not_a_number_is_page_one(gh: FakeGitHubAuth, page: object) -> None:
    """As GitHub answers, checked read-only: the same items and the same next link as page 1,
    so an adapter that starts at page 0 and stops on an empty page still reads the list."""
    good = installation_token(gh)
    gh.seed(100, "alice")
    first = gh.handle("lookup", good, page=1)
    odd = gh.handle("lookup", good, page=page)
    assert odd.status == 200
    assert odd.body == first.body
    assert link(odd) == link(first) == {"next": 2, "last": 4}


def test_a_bad_page_still_matches_a_fault_planted_for_page_one(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.fault_next("lookup", "5xx", page=1)
    assert gh.handle("lookup", good, page="abc").status == 503
    gh.fault_next("lookup", "5xx", page=1)
    assert gh.handle("lookup", good, page=-1).status == 503


def test_the_stand_in_write_stores_one_object_under_the_principal(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    response = gh.handle("write", good, body="hello")
    assert response.status == 201
    assert gh.items[-1].author == "sto-bot"
    assert gh.items[-1].body == "hello"
    assert gh.handle("lookup", good, page=1).body["items"][0]["id"] == response.body["id"]


def test_a_lost_write_is_applied_and_the_caller_sees_a_timeout(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.fault_next("write", "lose")
    with pytest.raises(TimeoutError):
        gh.handle("write", good, body="hello")
    assert [i.body for i in gh.items] == ["hello"]
    assert gh.handle("write", good, body="again").status == 201


def test_a_swallowed_write_answers_success_and_stores_nothing(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.swallow = 1
    assert gh.handle("write", good, body="hello").status == 201
    assert gh.items == []


def test_an_exact_multiple_of_the_page_size_has_no_empty_last_page(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(200, "alice")
    first = gh.handle("lookup", good, page=1, per_page=100)
    assert link(first) == {"next": 2, "last": 2}
    assert link(gh.handle("lookup", good, page=2, per_page=100)).get("next") is None


def test_a_single_page_has_no_link_header(gh: FakeGitHubAuth) -> None:
    gh.seed(5, "alice")
    assert "link" not in gh.handle("lookup", installation_token(gh), page=1).headers


def test_link_urls_are_absolute_on_a_reserved_host(gh: FakeGitHubAuth) -> None:
    gh.seed(60, "alice")
    header = gh.handle("lookup", installation_token(gh), page=1).headers["link"]
    assert header.startswith('<https://api.github.test/items?page=2&per_page=30>; rel="next"')


def test_a_page_past_the_end_is_empty(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(5, "alice")
    past = gh.handle("lookup", good, page=9)
    assert past.status == 200
    assert past.body == {"items": []}


def test_the_list_runs_newest_first_or_oldest_first(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    first = gh.add("alice", "first")
    last = gh.add("alice", "last")
    assert [i["id"] for i in gh.handle("lookup", good, page=1).body["items"]] == [last.id, first.id]
    gh.order = "oldest_first"
    assert [i["id"] for i in gh.handle("lookup", good, page=1).body["items"]] == [first.id, last.id]


def test_older_objects_go_to_the_far_end(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    mid = gh.add("alice", "mid")
    old = gh.add("alice", "old", older=True)
    ids = [i["id"] for i in gh.handle("lookup", good, page=1).body["items"]]
    assert ids == [mid.id, old.id]


def test_every_object_lists_its_author_and_body(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.add("mallory", "hello")
    assert gh.handle("lookup", good, page=1).body["items"][0] == {
        "id": "c-1",
        "author": "mallory",
        "body": "hello",
    }


# --- rate limits ------------------------------------------------------------------------------


def limited(gh: FakeGitHubAuth, shape: RateShape, op: str | None = None) -> Response:
    good = installation_token(gh)
    gh.rate_limit_next(1, shape, op)
    return gh.handle("read", good)


def test_a_primary_limit_can_be_a_429_with_retry_after(gh: FakeGitHubAuth) -> None:
    r = limited(gh, RateShape.PRIMARY_429)
    assert r.status == 429
    assert r.headers["retry-after"] == "30"
    assert r.headers["x-ratelimit-remaining"] == "0"


def test_a_primary_limit_can_be_a_403_that_says_remaining_zero_and_when_it_resets(
    gh: FakeGitHubAuth,
) -> None:
    r = limited(gh, RateShape.PRIMARY_403_REMAINING_ZERO)
    assert r.status == 403
    assert r.headers["x-ratelimit-remaining"] == "0"
    assert int(r.headers["x-ratelimit-reset"]) == int(gh.now) + 45
    assert "retry-after" not in r.headers
    assert r.body["message"] == "API rate limit exceeded"


def test_a_secondary_limit_is_a_403_with_retry_after(gh: FakeGitHubAuth) -> None:
    r = limited(gh, RateShape.SECONDARY_403)
    assert r.status == 403
    assert r.headers["retry-after"] == "30"
    assert "secondary rate limit" in r.body["message"]


def test_a_secondary_limit_may_say_so_only_in_its_message(gh: FakeGitHubAuth) -> None:
    r = limited(gh, RateShape.SECONDARY_403_NO_HEADER)
    assert r.status == 403
    assert "retry-after" not in r.headers
    assert "secondary rate limit" in r.body["message"]


def test_a_429_may_carry_no_header_at_all(gh: FakeGitHubAuth) -> None:
    r = limited(gh, RateShape.PRIMARY_429_NO_HEADER)
    assert r.status == 429
    assert "retry-after" not in r.headers


def test_a_limit_counts_down_one_request_at_a_time_and_is_counted(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.rate_limit_next(2, RateShape.PRIMARY_429)
    assert [gh.handle("read", good).status for _ in range(3)] == [429, 429, 200]
    assert gh.counts["limited"] == 2


def test_a_limit_can_be_restricted_to_one_operation(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.rate_limit_next(1, RateShape.PRIMARY_429, "lookup")
    assert gh.handle("read", good).status == 200
    assert gh.handle("lookup", good, page=1).status == 429


def test_authentication_is_checked_before_the_limit(gh: FakeGitHubAuth) -> None:
    gh.rate_limit_next(1, RateShape.PRIMARY_429)
    assert gh.handle("read", "ghs_nope").status == 401
    assert gh.counts["limited"] == 0


def test_every_answer_says_how_much_of_the_limit_is_left(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    first, second = gh.handle("read", good), gh.handle("read", good)
    assert first.headers["x-ratelimit-limit"] == "5000"
    assert int(first.headers["x-ratelimit-remaining"]) == 4999
    assert int(second.headers["x-ratelimit-remaining"]) == 4998
    assert int(second.headers["x-ratelimit-used"]) == 2
    assert int(second.headers["x-ratelimit-reset"]) == int(gh.now) + 3600
    assert second.headers["x-ratelimit-resource"] == "core"


def test_the_budget_runs_out_for_real_and_comes_back_at_the_reset(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.budget = 2
    assert [gh.handle("read", good).status for _ in range(2)] == [200, 200]
    spent = gh.handle("read", good)
    assert spent.status == 403
    assert spent.headers["x-ratelimit-remaining"] == "0"
    gh.now += 3600  # the window resets, and so has the token's hour: a new one
    assert gh.handle("read", installation_token(gh)).status == 200


# --- plain errors and faults ------------------------------------------------------------------


def test_a_plain_403_or_404_names_no_rate_limit(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.respond_next("read", 403)
    gh.respond_next("read", 404)
    a, b = gh.handle("read", good), gh.handle("read", good)
    assert (a.status, b.status) == (403, 404)
    assert "rate limit" not in str(a.body["message"]).lower()
    assert "retry-after" not in a.headers
    assert gh.handle("read", good).status == 200


@pytest.mark.parametrize(("mode", "status"), [("5xx", 503), ("429", 429), ("401", 401)], ids=str)
def test_a_fault_answers_one_request_that_way(gh: FakeGitHubAuth, mode: str, status: int) -> None:
    good = installation_token(gh)
    gh.fault_next("read", mode)
    assert gh.handle("read", good).status == status
    assert gh.handle("read", good).status == 200


def test_a_timeout_fault_raises_and_applies_nothing(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.fault_next("read", "timeout")
    with pytest.raises(TimeoutError):
        gh.handle("read", good)
    assert gh.handle("read", good).status == 200


def test_a_fault_can_wait_for_a_page_or_skip_requests(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    gh.fault_next("lookup", "5xx", page=2)
    assert gh.handle("lookup", good, page=1).status == 200
    assert gh.handle("lookup", good, page=2).status == 503
    gh.fault_next("read", "5xx", after=2)
    assert [gh.handle("read", good).status for _ in range(4)] == [200, 200, 503, 200]


def test_a_5xx_is_not_counted_as_a_rate_limit(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.fault_next("read", "5xx")
    gh.handle("read", good)
    assert gh.counts["limited"] == 0


def test_the_fake_holds_no_real_looking_secret() -> None:
    gh = FakeGitHubAuth()
    token = installation_token(gh)
    assert len(token) < 20, "short and plainly fake, so no secret scanner mistakes it for a token"


# --- narrowing the token: repositories and permissions ------------------------------------------


def test_a_token_asked_for_nothing_in_particular_gets_all_the_installations(
    gh: FakeGitHubAuth,
) -> None:
    body = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID).body
    assert body["permissions"] == dict(INSTALLATION_PERMISSIONS)
    assert body["repository_selection"] == "all"
    assert "repositories" not in body


def test_a_token_can_be_narrowed_to_repositories_and_the_answer_says_what_was_granted(
    gh: FakeGitHubAuth,
) -> None:
    response = gh.create_installation_token(
        gh.app_jwt(), INSTALLATION_ID, repositories=["app"], permissions={"contents": "read"}
    )
    assert response.status == 201
    assert response.body["permissions"] == {"contents": "read"}
    assert response.body["repository_selection"] == "selected"
    assert response.body["repositories"] == [{"name": "app", "full_name": "acme/app"}]
    grant = gh.grant(str(response.body["token"]))
    assert grant is not None
    assert grant.repositories == ("app",)
    assert grant.permissions == {"contents": "read"}


def test_a_narrowed_token_cannot_reach_another_repository(gh: FakeGitHubAuth) -> None:
    body = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, repositories=["app"]).body
    token = str(body["token"])
    assert gh.handle("read", token, repo="acme/app").status == 200
    other = gh.handle("read", token, repo="acme/lib")
    assert other.status == 404
    assert other.body == {"message": "Not Found"}
    assert gh.handle("read", token).status == 200  # no repository named: nothing to refuse


def test_an_unnarrowed_token_reaches_every_repository_of_the_installation(
    gh: FakeGitHubAuth,
) -> None:
    token = installation_token(gh)
    for repo in INSTALLATION_REPOS:
        assert gh.handle("read", token, repo=f"acme/{repo}").status == 200


def test_a_repository_outside_the_installation_is_a_422(gh: FakeGitHubAuth) -> None:
    for repos in (["other"], ["app", "other"]):
        response = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, repositories=repos)
        assert response.status == 422
        assert "repository" in response.body["message"]
    assert gh.counts["installation_token"] == 2


@pytest.mark.parametrize(
    "permissions",
    [
        {"contents": "admin"},
        {"administration": "read"},
        {"metadata": "write"},
        {"contents": "bogus"},
    ],
)
def test_a_permission_beyond_the_installations_is_a_422(
    gh: FakeGitHubAuth, permissions: dict[str, str]
) -> None:
    response = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, permissions=permissions)
    assert response.status == 422
    assert "permissions" in response.body["message"]


def test_a_lower_level_than_the_installations_is_fine(gh: FakeGitHubAuth) -> None:
    response = gh.create_installation_token(
        gh.app_jwt(), INSTALLATION_ID, permissions={"contents": "read", "checks": "write"}
    )
    assert response.status == 201


def test_a_refused_narrowing_issues_no_token(gh: FakeGitHubAuth) -> None:
    gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, repositories=["other"])
    assert gh.grant("ghs_fake_1") is None


# --- the same controls reach the mint ---------------------------------------------------------


def mint(gh: FakeGitHubAuth) -> Response:
    return gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID)


@pytest.mark.parametrize(("mode", "status"), [("5xx", 503), ("429", 429), ("401", 401)])
def test_a_fault_reaches_the_mint(gh: FakeGitHubAuth, mode: str, status: int) -> None:
    gh.fault_next("installation_token", mode)
    assert mint(gh).status == status
    assert mint(gh).status == 201


def test_a_timeout_fault_reaches_the_mint(gh: FakeGitHubAuth) -> None:
    gh.fault_next("installation_token", "timeout")
    with pytest.raises(TimeoutError):
        mint(gh)
    assert mint(gh).status == 201


def test_a_rate_limit_reaches_the_mint(gh: FakeGitHubAuth) -> None:
    gh.rate_limit_next(1, RateShape.SECONDARY_403, "installation_token")
    assert mint(gh).status == 403
    assert gh.counts["limited"] == 1
    assert mint(gh).status == 201


def test_a_limit_for_another_operation_does_not_reach_the_mint(gh: FakeGitHubAuth) -> None:
    gh.rate_limit_next(1, RateShape.PRIMARY_429, "read")
    assert mint(gh).status == 201


def test_revoke_auth_reaches_the_mint(gh: FakeGitHubAuth) -> None:
    gh.revoke_auth("installation_token")
    assert mint(gh).status == 401
    assert gh.counts["unauthorized"] == 1
    gh.restore_auth()
    assert mint(gh).status == 201
    gh.revoke_auth()
    assert mint(gh).status == 401


def test_a_plain_answer_reaches_the_mint(gh: FakeGitHubAuth) -> None:
    gh.respond_next("installation_token", 403)
    assert mint(gh).status == 403
    assert mint(gh).status == 201


def test_a_bad_jwt_is_counted_unauthorized_and_not_limited(gh: FakeGitHubAuth) -> None:
    gh.rate_limit_next(1, RateShape.PRIMARY_429)
    gh.create_installation_token("garbage", INSTALLATION_ID)
    assert gh.counts["unauthorized"] == 1
    assert gh.counts["limited"] == 0


def test_the_mint_does_not_spend_the_installations_budget(gh: FakeGitHubAuth) -> None:
    gh.budget = 1
    mint(gh)
    mint(gh)
    token = installation_token(gh)
    assert gh.handle("read", token).status == 200


def test_the_429_fault_asks_for_a_wait(gh: FakeGitHubAuth) -> None:
    token = installation_token(gh)
    gh.fault_next("read", "429")
    assert gh.handle("read", token).headers["retry-after"] == "30"


def test_running_out_of_budget_is_counted_as_limited(gh: FakeGitHubAuth) -> None:
    token = installation_token(gh)
    gh.budget = 1
    gh.handle("read", token)
    gh.handle("read", token)
    assert gh.counts["limited"] == 1


def test_repositories_are_bare_names_and_owner_slash_name_is_refused(gh: FakeGitHubAuth) -> None:
    """The docs: "List of repository names", example "Hello-World". Read from the docs, not tried
    on real GitHub, so a correct D4-02 sends ["app"] and a wrong one is refused."""

    def mint_with(repos: list[str]) -> Response:
        return gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, repositories=repos)

    assert mint_with(["app"]).status == 201
    assert mint_with(["app", "lib"]).status == 201
    for wrong in (["acme/app"], ["acme/app", "lib"]):
        refused = mint_with(wrong)
        assert refused.status == 422
        assert "repository" in refused.body["message"]


def test_an_unnarrowed_token_reaches_nothing_outside_the_installation(gh: FakeGitHubAuth) -> None:
    """The 404 is inferred, not tried on real GitHub."""
    token = installation_token(gh)
    for repo in ("evil/other", "acme/other", "other/app", "app", "acme/"):
        response = gh.handle("read", token, repo=repo)
        assert response.status == 404, repo
        assert response.body == {"message": "Not Found"}


def test_a_narrowed_token_with_no_repository_named_gets_a_200(gh: FakeGitHubAuth) -> None:
    """Known limit: there is nothing to refuse."""
    body = gh.create_installation_token(gh.app_jwt(), INSTALLATION_ID, repositories=["app"]).body
    assert gh.handle("read", str(body["token"])).status == 200
