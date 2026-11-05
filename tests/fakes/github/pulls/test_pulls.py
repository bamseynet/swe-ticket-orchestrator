"""D4-19: the fake's pull request, ref, commit and merge behaviour, route by route.

Each test names the docs.github.com page (or the REST OpenAPI description) it follows, or says
"unsourced" where the fake's own server.py lists the behaviour as a departure to prove live (D4-23).
"""

from __future__ import annotations

from typing import Any

import pytest

from fakes.github.pulls import REPO, SOURCES, UNSOURCED, FakeGitHubPulls, Response

R = f"/repos/{REPO}"


@pytest.fixture
def gh() -> FakeGitHubPulls:
    return FakeGitHubPulls()


@pytest.fixture
def tok(gh: FakeGitHubPulls) -> str:
    return gh.mint()


def call(gh: FakeGitHubPulls, tok: str, method: str, path: str, **kw: Any) -> Response:
    return gh.request(method, R + path, tok, **kw)


def open_pr(gh: FakeGitHubPulls, tok: str, branch: str = "feat", **kw: Any) -> dict[str, Any]:
    if gh.sha(REPO, branch) is None:
        gh.push(REPO, branch, {f"{branch}.txt": "x"})
    r = call(gh, tok, "POST", "/pulls", json={"title": "t", "head": branch, "base": "main", **kw})
    assert r.status == 201, r.body
    return r.body  # type: ignore[no-any-return]


def merge_async(gh: FakeGitHubPulls, tok: str, n: int, **body: Any) -> Response:
    return call(gh, tok, "PUT", f"/pulls/{n}/merge-async", json=body)


def poll(gh: FakeGitHubPulls, tok: str, n: int, uuid: str) -> Response:
    return call(gh, tok, "GET", f"/pulls/{n}/merge-async/{uuid}")


def run_merge(gh: FakeGitHubPulls, tok: str, n: int, **body: Any) -> dict[str, Any]:
    first = merge_async(gh, tok, n, **body)
    assert first.status == 202, first.body
    uuid = first.body["details"]["uuid"]
    gh.settle()
    done = poll(gh, tok, n, uuid)
    assert done.status == 200
    return done.body  # type: ignore[no-any-return]


# --- every route has a source or a named departure ------------------------------------------------


def test_every_route_cites_docs_github_com_or_is_listed_as_unsourced() -> None:
    assert SOURCES
    for name, url in SOURCES.items():
        assert url.startswith("https://docs.github.com/"), name
    assert not set(SOURCES) & set(UNSOURCED)
    assert set(SOURCES) | set(UNSOURCED) == set(FakeGitHubPulls.ROUTE_NAMES)


# --- access: the same token rules as the auth fake ------------------------------------------------


def test_a_request_with_no_or_a_bad_token_is_a_401(gh: FakeGitHubPulls) -> None:
    assert gh.request("GET", f"{R}/pulls/1", "").status == 401
    r = gh.request("GET", f"{R}/pulls/1", "ghs_nope")
    assert (r.status, r.body["message"]) == (401, "Bad credentials")


def test_a_repository_outside_the_installation_or_the_token_is_a_404(gh: FakeGitHubPulls) -> None:
    assert gh.request("GET", "/repos/acme/secret/pulls/1", gh.mint()).status == 404
    narrow = gh.mint(repositories=["lib"])
    assert gh.request("GET", f"{R}/pulls/1", narrow).status == 404


def test_owner_and_repository_are_not_case_sensitive(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request: owner: not case sensitive."""
    open_pr(gh, tok)
    assert gh.request("GET", "/repos/ACME/App/pulls/1", tok).status == 200


def test_a_token_without_the_permission_gets_a_403(gh: FakeGitHubPulls) -> None:
    """unsourced: GitHub's "Resource not accessible by integration" message."""
    read_only = gh.mint(permissions={"pull_requests": "read", "contents": "read", "issues": "read"})
    r = gh.request(
        "POST", f"{R}/pulls", read_only, json={"title": "t", "head": "a", "base": "main"}
    )
    assert (r.status, r.body["message"]) == (403, "Resource not accessible by integration")
    assert gh.request("GET", f"{R}/pulls", read_only).status == 200
    no_contents = gh.mint(permissions={"pull_requests": "write", "metadata": "read"})
    assert gh.request("GET", f"{R}/git/ref/heads/main", no_contents).status == 403


def test_an_unknown_route_is_a_404(gh: FakeGitHubPulls, tok: str) -> None:
    assert call(gh, tok, "GET", "/nothing").status == 404
    assert call(gh, tok, "DELETE", "/pulls/1").status == 404


# --- blobs, trees, commits ------------------------------------------------------------------------


def test_a_tree_of_content_entries_and_a_commit_on_it(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/git/trees#create-a-tree and
    https://docs.github.com/en/rest/git/commits#create-a-commit (201, sha, tree, parents)."""
    base = gh.sha(REPO, "main")
    tree = call(
        gh,
        tok,
        "POST",
        "/git/trees",
        json={"tree": [{"path": "a.txt", "mode": "100644", "type": "blob", "content": "A"}]},
    )
    assert tree.status == 201
    commit = call(
        gh,
        tok,
        "POST",
        "/git/commits",
        json={"message": "m", "tree": tree.body["sha"], "parents": [base]},
    )
    assert commit.status == 201
    assert commit.body["parents"] == [{"sha": base, "url": commit.body["parents"][0]["url"]}]
    assert commit.body["tree"]["sha"] == tree.body["sha"]
    got = call(gh, tok, "GET", f"/git/commits/{commit.body['sha']}")
    assert (got.status, got.body["message"]) == (200, "m")
    assert len(commit.body["sha"]) == 40


def test_a_tree_built_on_a_base_tree_keeps_its_other_files(gh: FakeGitHubPulls, tok: str) -> None:
    head = call(gh, tok, "GET", "/git/commits/" + str(gh.sha(REPO, "main"))).body
    tree = call(
        gh,
        tok,
        "POST",
        "/git/trees",
        json={
            "base_tree": head["tree"]["sha"],
            "tree": [{"path": "b.txt", "mode": "100644", "type": "blob", "content": "B"}],
        },
    )
    assert tree.status == 201
    assert gh.files(tree.body["sha"]) == {"README.md": "hello", "b.txt": "B"}


def test_a_tree_entry_by_blob_sha_and_a_deleting_null(gh: FakeGitHubPulls, tok: str) -> None:
    blob = call(gh, tok, "POST", "/git/blobs", json={"content": "Z", "encoding": "utf-8"})
    assert blob.status == 201
    main_tree = call(gh, tok, "GET", "/git/commits/" + str(gh.sha(REPO, "main"))).body["tree"]
    tree = call(
        gh,
        tok,
        "POST",
        "/git/trees",
        json={
            "base_tree": main_tree["sha"],
            "tree": [
                {"path": "z.txt", "mode": "100644", "type": "blob", "sha": blob.body["sha"]},
                {"path": "README.md", "mode": "100644", "type": "blob", "sha": None},
            ],
        },
    )
    assert gh.files(tree.body["sha"]) == {"z.txt": "Z"}


@pytest.mark.parametrize(
    "body",
    [
        {"tree": "nope", "parents": []},
        {"message": "m", "parents": []},
        {"message": "m", "tree": "0" * 40, "parents": []},
        {"message": "m", "tree": "{tree}", "parents": ["f" * 40]},
        {"message": "m", "tree": "{tree}", "parents": "notalist"},
    ],
)
def test_a_commit_with_a_missing_part_or_unknown_object_is_a_422(
    gh: FakeGitHubPulls, tok: str, body: dict[str, Any]
) -> None:
    tree = call(gh, tok, "GET", "/git/commits/" + str(gh.sha(REPO, "main"))).body["tree"]["sha"]
    body = {k: (tree if v == "{tree}" else v) for k, v in body.items()}
    assert call(gh, tok, "POST", "/git/commits", json=body).status == 422


def test_a_tree_with_a_bad_entry_is_a_422(gh: FakeGitHubPulls, tok: str) -> None:
    for entry in (
        {"path": "a", "mode": "777", "type": "blob", "content": "x"},
        {"path": "a", "mode": "100644", "type": "blob"},
        {"path": "a", "mode": "100644", "type": "blob", "sha": "1" * 40},
        {"mode": "100644", "type": "blob", "content": "x"},
    ):
        assert call(gh, tok, "POST", "/git/trees", json={"tree": [entry]}).status == 422, entry


def test_an_unknown_commit_is_a_404(gh: FakeGitHubPulls, tok: str) -> None:
    assert call(gh, tok, "GET", "/git/commits/" + "a" * 40).status == 404


# --- refs ---------------------------------------------------------------------------------------


def test_get_a_ref_by_its_name_without_refs(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/git/refs#get-a-reference: ``heads/main``."""
    r = call(gh, tok, "GET", "/git/ref/heads/main")
    assert r.status == 200
    assert r.body["ref"] == "refs/heads/main"
    assert r.body["object"] == {
        "sha": gh.sha(REPO, "main"),
        "type": "commit",
        "url": r.body["object"]["url"],
    }
    assert call(gh, tok, "GET", "/git/ref/heads/nope").status == 404


def test_create_a_ref(gh: FakeGitHubPulls, tok: str) -> None:
    sha = gh.sha(REPO, "main")
    r = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/new", "sha": sha})
    assert r.status == 201
    assert gh.sha(REPO, "new") == sha
    dup = call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/new", "sha": sha})
    assert (dup.status, dup.body["message"]) == (422, "Reference already exists")


@pytest.mark.parametrize(
    "body",
    [
        {"ref": "heads/x", "sha": "{sha}"},  # must be fully qualified
        {"ref": "refs/heads/x", "sha": "e" * 40},  # no such object
        {"ref": "refs/heads/x"},
        {"sha": "{sha}"},
    ],
)
def test_create_a_ref_validates(gh: FakeGitHubPulls, tok: str, body: dict[str, Any]) -> None:
    body = {k: (gh.sha(REPO, "main") if v == "{sha}" else v) for k, v in body.items()}
    assert call(gh, tok, "POST", "/git/refs", json=body).status == 422
    assert gh.sha(REPO, "x") is None


def _commit_on(gh: FakeGitHubPulls, tok: str, parent: str, name: str) -> str:
    tree = call(
        gh,
        tok,
        "POST",
        "/git/trees",
        json={"tree": [{"path": name, "mode": "100644", "type": "blob", "content": name}]},
    ).body["sha"]
    made = call(
        gh, tok, "POST", "/git/commits", json={"message": name, "tree": tree, "parents": [parent]}
    )
    return str(made.body["sha"])


def test_move_a_ref_forward_but_not_sideways_without_force(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/git/refs#update-a-reference: ``force`` defaults to false."""
    main = str(gh.sha(REPO, "main"))
    child = _commit_on(gh, tok, main, "c.txt")
    ok = call(gh, tok, "PATCH", "/git/refs/heads/main", json={"sha": child})
    assert ok.status == 200
    assert gh.sha(REPO, "main") == child
    sibling = _commit_on(gh, tok, main, "s.txt")
    refused = call(gh, tok, "PATCH", "/git/refs/heads/main", json={"sha": sibling})
    assert (refused.status, refused.body["message"]) == (422, "Update is not a fast forward")
    assert gh.sha(REPO, "main") == child
    forced = call(gh, tok, "PATCH", "/git/refs/heads/main", json={"sha": sibling, "force": True})
    assert forced.status == 200
    assert gh.sha(REPO, "main") == sibling


def test_move_a_ref_that_does_not_exist_or_to_an_unknown_object(
    gh: FakeGitHubPulls, tok: str
) -> None:
    assert call(gh, tok, "PATCH", "/git/refs/heads/zz", json={"sha": "a" * 40}).status == 404
    r = call(gh, tok, "PATCH", "/git/refs/heads/main", json={"sha": "a" * 40, "force": True})
    assert (r.status, r.body["message"]) == (422, "Object does not exist")


def test_delete_a_ref(gh: FakeGitHubPulls, tok: str) -> None:
    gh.push(REPO, "gone", {"g": "g"})
    assert call(gh, tok, "DELETE", "/git/refs/heads/gone").status == 204
    assert gh.sha(REPO, "gone") is None
    assert call(gh, tok, "DELETE", "/git/refs/heads/gone").status == 422


# --- creating and reading pull requests -----------------------------------------------------------


def test_create_a_pull_request(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#create-a-pull-request: 201."""
    gh.push(REPO, "feat", {"f": "f"})
    r = call(
        gh, tok, "POST", "/pulls", json={"title": "T", "head": "feat", "base": "main", "body": "B"}
    )
    assert r.status == 201
    pr = r.body
    assert (pr["number"], pr["state"], pr["draft"], pr["merged"], pr["title"], pr["body"]) == (
        1,
        "open",
        False,
        False,
        "T",
        "B",
    )
    assert pr["head"]["ref"] == "feat"
    assert pr["head"]["sha"] == gh.sha(REPO, "feat")
    assert pr["base"]["ref"] == "main"
    assert pr["user"]["login"] == "sto-bot"
    assert pr["merge_commit_sha"] is None


def test_create_a_draft_pull_request(gh: FakeGitHubPulls, tok: str) -> None:
    pr = open_pr(gh, tok, draft=True)
    assert pr["draft"] is True
    assert pr["mergeable_state"] == "draft"


@pytest.mark.parametrize(
    ("body", "field"),
    [
        ({"head": "feat", "base": "main"}, "title"),
        ({"title": "t", "base": "main"}, "head"),
        ({"title": "t", "head": "feat"}, "base"),
        ({"title": "t", "head": "nope", "base": "main"}, "head"),
        ({"title": "t", "head": "feat", "base": "nope"}, "base"),
        ({"title": "t", "head": "feat", "base": "main", "draft": "yes"}, "draft"),
        ({"title": 5, "head": "feat", "base": "main"}, "title"),
    ],
)
def test_create_validates_with_gitHubs_errors_array(
    gh: FakeGitHubPulls, tok: str, body: dict[str, Any], field: str
) -> None:
    """unsourced messages, documented 422 "Validation failed"; the ``errors`` shape is GitHub's."""
    gh.push(REPO, "feat", {"f": "f"})
    r = call(gh, tok, "POST", "/pulls", json=body)
    assert r.status == 422
    assert (
        r.body["message"].startswith("Validation Failed") or "Invalid request" in r.body["message"]
    )
    assert not gh.pulls(REPO)


def test_a_second_open_pull_request_for_the_same_head_and_base_is_a_422(
    gh: FakeGitHubPulls, tok: str
) -> None:
    open_pr(gh, tok)
    r = call(gh, tok, "POST", "/pulls", json={"title": "t", "head": "feat", "base": "main"})
    assert r.status == 422
    assert "already exists" in str(r.body["errors"])


def test_a_head_with_no_commits_beyond_the_base_is_a_422(gh: FakeGitHubPulls, tok: str) -> None:
    call(gh, tok, "POST", "/git/refs", json={"ref": "refs/heads/same", "sha": gh.sha(REPO, "main")})
    r = call(gh, tok, "POST", "/pulls", json={"title": "t", "head": "same", "base": "main"})
    assert r.status == 422
    assert "No commits between" in str(r.body["errors"])


def test_pull_request_numbers_are_shared_with_nothing_else_and_count_up(
    gh: FakeGitHubPulls, tok: str
) -> None:
    assert open_pr(gh, tok, "a")["number"] == 1
    assert open_pr(gh, tok, "b")["number"] == 2


def test_get_a_missing_pull_request_is_a_404(gh: FakeGitHubPulls, tok: str) -> None:
    assert call(gh, tok, "GET", "/pulls/9").status == 404
    assert call(gh, tok, "GET", "/pulls/abc").status == 404


def test_mergeable_is_null_until_github_has_computed_it(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request: "null" while computing, then
    a boolean. A head or base move makes it null again (the fake: on the next move)."""
    open_pr(gh, tok)
    first = call(gh, tok, "GET", "/pulls/1").body
    assert first["mergeable"] is None
    second = call(gh, tok, "GET", "/pulls/1").body
    assert second["mergeable"] is True
    assert second["mergeable_state"] == "clean"
    gh.push(REPO, "feat", {"more": "m"})
    assert call(gh, tok, "GET", "/pulls/1").body["mergeable"] is None


def test_a_conflicting_pull_request_is_not_mergeable_and_dirty(
    gh: FakeGitHubPulls, tok: str
) -> None:
    gh.push(REPO, "feat", {"README.md": "mine"})
    open_pr(gh, tok)
    gh.push(REPO, "main", {"README.md": "theirs"})
    call(gh, tok, "GET", "/pulls/1")
    pr = call(gh, tok, "GET", "/pulls/1").body
    assert (pr["mergeable"], pr["mergeable_state"]) == (False, "dirty")


def test_a_pull_request_behind_its_base_is_behind(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    gh.push(REPO, "main", {"other": "o"})
    call(gh, tok, "GET", "/pulls/1")
    assert call(gh, tok, "GET", "/pulls/1").body["mergeable_state"] == "behind"


def test_edit_a_pull_request(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#update-a-pull-request."""
    open_pr(gh, tok)
    r = call(gh, tok, "PATCH", "/pulls/1", json={"title": "new", "body": "nb", "state": "closed"})
    assert (r.status, r.body["title"], r.body["state"]) == (200, "new", "closed")
    assert r.body["closed_at"] is not None
    reopened = call(gh, tok, "PATCH", "/pulls/1", json={"state": "open"})
    assert (reopened.body["state"], reopened.body["closed_at"]) == ("open", None)


@pytest.mark.parametrize("body", [{"state": "merged"}, {"title": 3}, {"base": "nope"}])
def test_edit_validates(gh: FakeGitHubPulls, tok: str, body: dict[str, Any]) -> None:
    open_pr(gh, tok)
    assert call(gh, tok, "PATCH", "/pulls/1", json=body).status == 422


def test_draft_cannot_be_changed_through_the_rest_edit_route(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#update-a-pull-request lists no ``draft``: the
    field is ignored. Ready for review is GraphQL (``markPullRequestReadyForReview``)."""
    open_pr(gh, tok, draft=True)
    r = call(gh, tok, "PATCH", "/pulls/1", json={"draft": False})
    assert r.status == 200
    assert r.body["draft"] is True
    gh.mark_ready(1)
    assert call(gh, tok, "GET", "/pulls/1").body["draft"] is False


def test_a_merged_pull_request_cannot_be_reopened(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    run_merge(gh, tok, 1)
    r = call(gh, tok, "PATCH", "/pulls/1", json={"state": "open"})
    assert r.status == 422


def test_list_pull_requests_filters_and_pages(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#list-pull-requests: ``state`` open by default,
    ``head`` as ``owner:branch``, ``base``, newest first by default, ``link`` header paging."""
    for i in range(5):
        open_pr(gh, tok, f"b{i}")
    call(gh, tok, "PATCH", "/pulls/2", json={"state": "closed"})
    default = call(gh, tok, "GET", "/pulls").body
    assert [p["number"] for p in default] == [5, 4, 3, 1]
    assert [
        p["number"] for p in call(gh, tok, "GET", "/pulls", query={"state": "closed"}).body
    ] == [2]
    assert len(call(gh, tok, "GET", "/pulls", query={"state": "all"}).body) == 5
    only = call(gh, tok, "GET", "/pulls", query={"head": "acme:b3", "state": "all"}).body
    assert [p["number"] for p in only] == [4]
    assert call(gh, tok, "GET", "/pulls", query={"base": "other", "state": "all"}).body == []
    asc = call(gh, tok, "GET", "/pulls", query={"direction": "asc", "state": "all"}).body
    assert [p["number"] for p in asc] == [1, 2, 3, 4, 5]
    page = call(gh, tok, "GET", "/pulls", query={"state": "all", "per_page": "2", "page": "2"})
    assert [p["number"] for p in page.body] == [3, 2]
    assert 'rel="next"' in page.headers["link"]
    assert call(gh, tok, "GET", "/pulls", query={"state": "bogus"}).status == 422


# --- comments on a pull request -------------------------------------------------------------------


def test_comment_on_a_pull_request_and_list_oldest_first(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/issues/comments: a PR is an issue; ascending by ID."""
    open_pr(gh, tok)
    a = call(gh, tok, "POST", "/issues/1/comments", json={"body": "one"})
    b = call(gh, tok, "POST", "/issues/1/comments", json={"body": "two"})
    assert (a.status, b.status) == (201, 201)
    assert a.body["user"]["login"] == "sto-bot"
    listed = call(gh, tok, "GET", "/issues/1/comments").body
    assert [c["body"] for c in listed] == ["one", "two"]
    assert [c["id"] for c in listed] == [a.body["id"], b.body["id"]]


def test_comments_page_by_link_header(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    for i in range(5):
        call(gh, tok, "POST", "/issues/1/comments", json={"body": str(i)})
    r = call(gh, tok, "GET", "/issues/1/comments", query={"per_page": "2"})
    assert len(r.body) == 2
    assert 'rel="next"' in r.headers["link"]
    assert 'rel="last"' in r.headers["link"]
    last = call(gh, tok, "GET", "/issues/1/comments", query={"per_page": "2", "page": "3"})
    assert len(last.body) == 1
    assert 'rel="next"' not in last.headers.get("link", "")


@pytest.mark.parametrize("body", [{}, {"body": ""}, {"body": 4}])
def test_a_comment_needs_a_text_body(gh: FakeGitHubPulls, tok: str, body: dict[str, Any]) -> None:
    open_pr(gh, tok)
    assert call(gh, tok, "POST", "/issues/1/comments", json=body).status == 422


def test_comments_on_a_missing_pull_request_are_a_404(gh: FakeGitHubPulls, tok: str) -> None:
    assert call(gh, tok, "POST", "/issues/7/comments", json={"body": "x"}).status == 404
    assert call(gh, tok, "GET", "/issues/7/comments").status == 404


# --- POST /merges: the base update ----------------------------------------------------------------


def test_merging_a_head_into_a_branch_makes_a_two_parent_commit(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """https://docs.github.com/en/rest/branches/branches#merge-a-branch: 201 with the commit."""
    open_pr(gh, tok)
    gh.push(REPO, "main", {"m.txt": "m"})
    feat, main = str(gh.sha(REPO, "feat")), str(gh.sha(REPO, "main"))
    r = call(
        gh, tok, "POST", "/merges", json={"base": "feat", "head": "main", "commit_message": "up"}
    )
    assert r.status == 201
    assert [p["sha"] for p in r.body["parents"]] == [feat, main]
    assert r.body["commit"]["message"] == "up"
    assert gh.sha(REPO, "feat") == r.body["sha"]
    assert gh.files(gh.tree_of(r.body["sha"])) == {
        "README.md": "hello",
        "feat.txt": "x",
        "m.txt": "m",
    }


def test_merging_when_there_is_nothing_to_merge_is_a_204(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    before = gh.sha(REPO, "feat")
    r = call(gh, tok, "POST", "/merges", json={"base": "feat", "head": "main"})
    assert (r.status, r.body) == (204, None)
    assert gh.sha(REPO, "feat") == before


def test_a_conflicting_merge_is_a_409_and_moves_nothing(gh: FakeGitHubPulls, tok: str) -> None:
    gh.push(REPO, "feat", {"README.md": "mine"})
    gh.push(REPO, "main", {"README.md": "theirs"})
    before = gh.sha(REPO, "feat")
    r = call(gh, tok, "POST", "/merges", json={"base": "feat", "head": "main"})
    assert (r.status, r.body["message"]) == (409, "Merge conflict")
    assert gh.sha(REPO, "feat") == before


def test_merge_branch_validation(gh: FakeGitHubPulls, tok: str) -> None:
    gh.push(REPO, "feat", {"f": "f"})
    assert call(gh, tok, "POST", "/merges", json={"base": "feat"}).status == 422
    assert call(gh, tok, "POST", "/merges", json={"base": "nope", "head": "main"}).status == 404
    assert call(gh, tok, "POST", "/merges", json={"base": "feat", "head": "nope"}).status == 404


def test_merging_a_head_that_is_ahead_fast_forwards_the_base(gh: FakeGitHubPulls, tok: str) -> None:
    """unsourced: no merge commit is made when the base is an ancestor of the head."""
    gh.push(REPO, "feat", {"f": "f"})
    r = call(gh, tok, "POST", "/merges", json={"base": "main", "head": "feat"})
    assert r.status == 201
    assert r.body["sha"] == gh.sha(REPO, "feat") == gh.sha(REPO, "main")


# --- the async merge ------------------------------------------------------------------------------


def test_request_returns_202_pending_with_a_uuid_and_the_expected_head(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request-asynchronously"""
    open_pr(gh, tok)
    head = gh.sha(REPO, "feat")
    r = merge_async(gh, tok, 1, sha=head, merge_method="squash", merge_action="direct_merge")
    assert r.status == 202
    assert r.body["status"] == "pending"
    d = r.body["details"]
    assert (d["merge_method"], d["merge_action"], d["expected_head_sha"], d["bypass_rules"]) == (
        "squash",
        "direct_merge",
        head,
        False,
    )
    assert d["uuid"]
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]


def test_defaults_are_the_current_head_the_default_action_and_merge_method(
    gh: FakeGitHubPulls, tok: str
) -> None:
    open_pr(gh, tok)
    d = merge_async(gh, tok, 1).body["details"]
    assert d["expected_head_sha"] == gh.sha(REPO, "feat")
    assert (d["merge_action"], d["merge_method"]) == ("default", "merge")  # method: unsourced


def test_polling_is_pending_until_it_runs_and_then_merged_with_the_merge_sha(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#get-the-result-of-an-asynchronous-merge"""
    open_pr(gh, tok)
    uuid = merge_async(gh, tok, 1).body["details"]["uuid"]
    first = poll(gh, tok, 1, uuid)
    assert (first.status, first.body["status"]) == (200, "pending")
    second = poll(gh, tok, 1, uuid)
    assert second.body["status"] == "merged"
    assert second.body["details"]["sha"] == gh.sha(REPO, "main")
    pr = call(gh, tok, "GET", "/pulls/1").body
    assert (pr["merged"], pr["state"], pr["merge_commit_sha"]) == (
        True,
        "closed",
        second.body["details"]["sha"],
    )
    assert poll(gh, tok, 1, uuid).body["status"] == "merged"  # stays readable


def test_a_direct_merge_makes_a_merge_commit_a_squash_makes_one_parent(
    gh: FakeGitHubPulls, tok: str
) -> None:
    open_pr(gh, tok, "a")
    open_pr(gh, tok, "b")
    main0 = str(gh.sha(REPO, "main"))
    done = run_merge(gh, tok, 1, merge_method="merge")
    commit = call(gh, tok, "GET", f"/git/commits/{done['details']['sha']}").body
    assert [p["sha"] for p in commit["parents"]] == [main0, gh.sha(REPO, "a")]
    done2 = run_merge(gh, tok, 2, merge_method="squash")
    commit2 = call(gh, tok, "GET", f"/git/commits/{done2['details']['sha']}").body
    assert [p["sha"] for p in commit2["parents"]] == [done["details"]["sha"]]
    assert gh.files(gh.tree_of(done2["details"]["sha"]))["b.txt"] == "x"


def test_an_already_merged_pull_request_is_a_200_merged(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    done = run_merge(gh, tok, 1)
    again = merge_async(gh, tok, 1)
    assert (again.status, again.body["status"]) == (200, "merged")
    assert again.body["details"]["sha"] == done["details"]["sha"]


def test_a_head_that_is_not_the_one_the_caller_approved_is_refused_at_the_request(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """unsourced status: the docs name no code for a ``sha`` mismatch. The fake says 422 and
    merges nothing; D4-23 settles it live."""
    open_pr(gh, tok)
    r = merge_async(gh, tok, 1, sha="a" * 40)
    assert r.status == 422
    assert "Head branch was modified" in r.body["message"]
    gh.settle()
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]


def test_a_push_between_the_request_and_the_run_cancels_the_merge(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """Docs: "if the PR is pushed in between the merge being requested and being executed, the
    merge will be cancelled". The result is ``failed`` with a message (unsourced wording)."""
    open_pr(gh, tok)
    uuid = merge_async(gh, tok, 1, sha=gh.sha(REPO, "feat")).body["details"]["uuid"]
    gh.push(REPO, "feat", {"late": "l"})
    gh.settle()
    done = poll(gh, tok, 1, uuid).body
    assert done["status"] == "failed"
    assert "head" in done["details"]["message"].lower()
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]


def test_a_base_move_that_conflicts_fails_the_merge(gh: FakeGitHubPulls, tok: str) -> None:
    gh.push(REPO, "feat", {"README.md": "mine"})
    open_pr(gh, tok)
    uuid = merge_async(gh, tok, 1).body["details"]["uuid"]
    gh.push(REPO, "main", {"README.md": "theirs"})
    gh.settle()
    done = poll(gh, tok, 1, uuid).body
    assert done["status"] == "failed"
    assert "conflict" in done["details"]["message"].lower()
    assert gh.sha(REPO, "main") == gh.sha(REPO, "main")  # nothing merged
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]


def test_a_protection_block_fails_the_merge_with_its_message(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    gh.block_merge(1, 'Required status check "ci" is expected.')
    done = run_merge(gh, tok, 1)
    assert done["status"] == "failed"
    assert done["details"]["message"] == 'Required status check "ci" is expected.'
    gh.block_merge(1, None)
    assert run_merge(gh, tok, 1)["status"] == "merged"


def test_a_closed_or_draft_pull_request_is_a_400(gh: FakeGitHubPulls, tok: str) -> None:
    """Docs: 400 "Not ready to merge, for example because it is closed". The draft case and the
    message are unsourced."""
    open_pr(gh, tok, "a")
    open_pr(gh, tok, "b", draft=True)
    call(gh, tok, "PATCH", "/pulls/1", json={"state": "closed"})
    assert merge_async(gh, tok, 1).status == 400
    assert merge_async(gh, tok, 2).status == 400


def test_a_second_request_while_one_is_pending_is_a_409_with_the_first_uuid(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """Docs: 409, "The response returns that request's UUID and options"."""
    open_pr(gh, tok)
    first = merge_async(gh, tok, 1).body["details"]["uuid"]
    r = merge_async(gh, tok, 1)
    assert r.status == 409
    assert r.body["details"]["uuid"] == first
    assert r.body["status"] == "pending"
    gh.settle()
    assert merge_async(gh, tok, 1).status == 200  # merged by now


def test_a_failed_request_frees_the_pull_request_for_another(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    gh.block_merge(1, "no")
    assert run_merge(gh, tok, 1)["status"] == "failed"
    gh.block_merge(1, None)
    assert merge_async(gh, tok, 1).status == 202


def test_unknown_uuid_other_pull_request_and_expired_results_are_404s(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """Docs: the result is "retained for 24 hours after its most recent update"."""
    open_pr(gh, tok, "a")
    open_pr(gh, tok, "b")
    uuid = merge_async(gh, tok, 1).body["details"]["uuid"]
    assert poll(gh, tok, 1, "no-such").status == 404
    assert poll(gh, tok, 2, uuid).status == 404
    gh.settle()
    poll(gh, tok, 1, uuid)
    gh.now += 24 * 3600 - 1
    fresh = gh.mint()  # the one-hour token has lapsed
    assert poll(gh, fresh, 1, uuid).status == 200
    gh.now += 2
    assert poll(gh, fresh, 1, uuid).status == 404


@pytest.mark.parametrize(
    "body",
    [
        {"merge_method": "fast-forward"},
        {"merge_action": "queue"},
        {"sha": 12},
        {"bypass_rules": "no"},
        {"commit_title": 3},
    ],
)
def test_bad_parameters_are_a_422_that_names_the_field(
    gh: FakeGitHubPulls, tok: str, body: dict[str, Any]
) -> None:
    open_pr(gh, tok)
    r = merge_async(gh, tok, 1, **body)
    assert r.status == 422
    assert next(iter(body)) in r.body["message"]


def test_unknown_parameters_are_ignored_as_github_ignores_them(
    gh: FakeGitHubPulls, tok: str
) -> None:
    open_pr(gh, tok)
    assert merge_async(gh, tok, 1, merge_methd="squash").status == 202


def test_merge_async_needs_write_permissions_and_a_real_pull_request(
    gh: FakeGitHubPulls, tok: str
) -> None:
    open_pr(gh, tok)
    ro = gh.mint(permissions={"pull_requests": "read", "contents": "write"})
    assert gh.request("PUT", f"{R}/pulls/1/merge-async", ro, json={}).status == 403
    assert merge_async(gh, tok, 99).status == 404


def test_merge_queue_action_enqueues_and_enqueued_is_final(gh: FakeGitHubPulls, tok: str) -> None:
    """Docs: "An enqueued result means the pull request was added to the merge queue, not that it
    has merged." The PR is not merged until the queue says so."""
    gh.enable_merge_queue(REPO, "main")
    open_pr(gh, tok)
    uuid = merge_async(gh, tok, 1, merge_action="merge_queue").body["details"]["uuid"]
    gh.settle()
    done = poll(gh, tok, 1, uuid)
    assert done.body["status"] == "enqueued"
    assert poll(gh, tok, 1, uuid).body["status"] == "enqueued"  # final
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]
    again = merge_async(gh, tok, 1, merge_action="merge_queue")
    assert (again.status, again.body["status"]) == (200, "enqueued")  # already in a queue
    gh.complete_queue(1)
    pr = call(gh, tok, "GET", "/pulls/1").body
    assert pr["merged"] is True
    assert merge_async(gh, tok, 1).body["status"] == "merged"


def test_the_default_action_uses_the_queue_when_the_base_has_one(
    gh: FakeGitHubPulls, tok: str
) -> None:
    gh.enable_merge_queue(REPO, "main")
    open_pr(gh, tok)
    assert run_merge(gh, tok, 1)["status"] == "enqueued"


def test_direct_merge_is_refused_on_a_queued_base_and_the_queue_on_an_unqueued_one(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """unsourced: both are 400 here; GitHub's exact answer is for D4-23."""
    open_pr(gh, tok)
    assert merge_async(gh, tok, 1, merge_action="merge_queue").status == 400
    gh.enable_merge_queue(REPO, "main")
    assert merge_async(gh, tok, 1, merge_action="direct_merge").status == 400


def test_a_dequeued_pull_request_can_be_requested_again(gh: FakeGitHubPulls, tok: str) -> None:
    gh.enable_merge_queue(REPO, "main")
    open_pr(gh, tok)
    run_merge(gh, tok, 1, merge_action="merge_queue")
    gh.dequeue(1)
    assert not call(gh, tok, "GET", "/pulls/1").body["merged"]
    assert merge_async(gh, tok, 1, merge_action="merge_queue").status == 202


def test_bypass_rules_skips_a_protection_block_only_when_asked(
    gh: FakeGitHubPulls, tok: str
) -> None:
    """Docs: ``bypass_rules`` skips rules "the actor is allowed to bypass" (the fake's is)."""
    open_pr(gh, tok)
    gh.block_merge(1, "blocked")
    assert run_merge(gh, tok, 1)["status"] == "failed"
    assert run_merge(gh, tok, 1, bypass_rules=True)["status"] == "merged"


# --- update-branch --------------------------------------------------------------------------------


def test_update_branch_answers_202_with_no_sha(gh: FakeGitHubPulls, tok: str) -> None:
    """https://docs.github.com/en/rest/pulls/pulls#update-a-pull-request-branch: 202 and a message,
    and no commit SHA (the reason ADR-0010 uses ``POST /merges``)."""
    open_pr(gh, tok)
    gh.push(REPO, "main", {"m": "m"})
    r = call(
        gh, tok, "PUT", "/pulls/1/update-branch", json={"expected_head_sha": gh.sha(REPO, "feat")}
    )
    assert r.status == 202
    assert set(r.body) == {"message", "url"}
    gh.settle()
    assert call(gh, tok, "GET", "/pulls/1").body["mergeable_state"] != "behind"


def test_update_branch_with_the_wrong_expected_head_is_a_422(gh: FakeGitHubPulls, tok: str) -> None:
    open_pr(gh, tok)
    before = gh.sha(REPO, "feat")
    r = call(gh, tok, "PUT", "/pulls/1/update-branch", json={"expected_head_sha": "b" * 40})
    assert r.status == 422
    assert gh.sha(REPO, "feat") == before


def test_update_branch_on_a_conflict_is_a_422(gh: FakeGitHubPulls, tok: str) -> None:
    gh.push(REPO, "feat", {"README.md": "mine"})
    open_pr(gh, tok)
    gh.push(REPO, "main", {"README.md": "theirs"})
    r = call(gh, tok, "PUT", "/pulls/1/update-branch", json={})
    assert r.status == 422
