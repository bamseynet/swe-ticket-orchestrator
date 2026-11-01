"""D4-16: the fake GitHub's App auth, tokens, pagination, rate limits and errors.

Fixtures are synthetic (no real App ID, key, installation or token). Each behaviour asserted here
is documented, with its source URL, in ``server.py``; the live suite later proves it.
"""

from __future__ import annotations

import pytest

from fakes.github.auth import (
    APP_ID,
    INSTALLATION_ID,
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
    assert gh.handle("lookup", good, page=0).status == 200
    gh.restore_auth()
    assert gh.handle("read", good).status == 200
    gh.revoke_auth()
    assert gh.handle("lookup", good, page=0).status == 401
    gh.restore_auth()
    assert gh.handle("lookup", good, page=0).status == 200


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
    with pytest.raises(AssertionError, match="no write surface"):
        gh.handle("write", installation_token(gh), body="x")


# --- pagination ------------------------------------------------------------------------------


def test_a_list_pages_at_a_hundred_and_says_where_the_next_page_is(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(250, "alice")
    pages = [gh.handle("lookup", good, page=n) for n in range(3)]
    assert [len(p.body["items"]) for p in pages] == [100, 100, 50]
    assert [p.body["next"] for p in pages] == [1, 2, None]
    assert 'rel="next"' in pages[0].headers["link"]
    assert 'rel="last"' in pages[0].headers["link"]
    assert 'rel="next"' not in pages[2].headers["link"]
    assert 'rel="prev"' in pages[2].headers["link"]
    assert 'rel="first"' in pages[2].headers["link"]
    ids = [i["id"] for p in pages for i in p.body["items"]]
    assert len(set(ids)) == 250


def test_per_page_is_capped_at_a_hundred(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(150, "alice")
    assert len(gh.handle("lookup", good, page=0, per_page=1000).body["items"]) == 100
    assert len(gh.handle("lookup", good, page=0, per_page=30).body["items"]) == 30


def test_a_single_page_has_no_link_header(gh: FakeGitHubAuth) -> None:
    gh.seed(5, "alice")
    assert "link" not in gh.handle("lookup", installation_token(gh), page=0).headers


def test_an_exact_multiple_of_the_page_size_has_no_empty_last_page(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(200, "alice")
    assert gh.handle("lookup", good, page=1).body["next"] is None


def test_a_page_past_the_end_is_empty(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.seed(5, "alice")
    past = gh.handle("lookup", good, page=9)
    assert past.status == 200
    assert past.body == {"items": [], "next": None}


def test_the_list_runs_newest_first_or_oldest_first(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    first = gh.add("alice", "first")
    last = gh.add("alice", "last")
    assert [i["id"] for i in gh.handle("lookup", good, page=0).body["items"]] == [last.id, first.id]
    gh.order = "oldest_first"
    assert [i["id"] for i in gh.handle("lookup", good, page=0).body["items"]] == [first.id, last.id]


def test_older_objects_go_to_the_far_end(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    mid = gh.add("alice", "mid")
    old = gh.add("alice", "old", older=True)
    ids = [i["id"] for i in gh.handle("lookup", good, page=0).body["items"]]
    assert ids == [mid.id, old.id]


def test_every_object_lists_its_author_and_body(gh: FakeGitHubAuth) -> None:
    good = installation_token(gh)
    gh.add("mallory", "hello")
    assert gh.handle("lookup", good, page=0).body["items"][0] == {
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
    assert gh.handle("lookup", good, page=0).status == 429


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
    gh.fault_next("lookup", "5xx", page=1)
    assert gh.handle("lookup", good, page=0).status == 200
    assert gh.handle("lookup", good, page=1).status == 503
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
    assert len(token) < 20, "a real installation token is ghs_ plus 36 characters"
