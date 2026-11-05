"""D4-27: the path deny list (PLAN 8.4, T4, ADR-0021).

A SECOND layer only. CI also runs files a change must be able to touch (``package.json`` scripts,
a ``Makefile``, tests), so this list cannot close the CI hole; T18's attestation is the real
control. These tests prove the list refuses what it names, adversarially spelled, and that a
refusal cannot be routed past the push.
"""

from __future__ import annotations

import pytest

from sto.domain.errors import PermanentError
from sto.workspace.path_policy import (
    DEFAULT_DENIED,
    NO_ROUTE_PAST_PUSH,
    RESOLUTIONS,
    ChangeKind,
    PathChange,
    PathPolicy,
    PathPolicyError,
    check_paths,
    normalize_path,
)

POLICY = PathPolicy()

DEFAULT_PATHS = [
    ".github/workflows/ci.yml",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github",
    "CODEOWNERS",
    "docs/CODEOWNERS",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    ".travis.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".buildkite/pipeline.yml",
    ".drone.yml",
    ".gitea/workflows/x.yml",
    ".forgejo/workflows/x.yml",
    ".git/hooks/pre-commit",
    ".sto/workflows/default.yaml",
]


def _modify(path: str) -> PathChange:
    return PathChange(ChangeKind.MODIFY, path)


@pytest.mark.parametrize("path", DEFAULT_PATHS)
def test_each_default_path_is_refused(path: str) -> None:
    result = check_paths([_modify(path)], POLICY)
    assert not result.allowed
    assert [v.path for v in result.violations] == [path]


@pytest.mark.parametrize("path", DEFAULT_PATHS)
@pytest.mark.parametrize("kind", [ChangeKind.ADD, ChangeKind.DELETE, ChangeKind.MODIFY])
def test_every_change_kind_is_refused(path: str, kind: ChangeKind) -> None:
    assert not check_paths([PathChange(kind, path)], POLICY).allowed


@pytest.mark.parametrize("path", DEFAULT_PATHS)
@pytest.mark.parametrize("kind", [ChangeKind.RENAME, ChangeKind.COPY])
def test_rename_or_copy_into_a_denied_path_is_refused(path: str, kind: ChangeKind) -> None:
    result = check_paths([PathChange(kind, path, old_path="src/app.py")], POLICY)
    assert not result.allowed
    assert result.violations[0].path == path


@pytest.mark.parametrize("path", DEFAULT_PATHS)
def test_rename_out_of_a_denied_path_is_refused(path: str) -> None:
    result = check_paths([PathChange(ChangeKind.RENAME, "src/moved.py", old_path=path)], POLICY)
    assert not result.allowed
    assert result.violations[0].path == path


def test_ordinary_rename_is_allowed() -> None:
    change = PathChange(ChangeKind.RENAME, "src/b.py", old_path="src/a.py")
    assert check_paths([change], POLICY).allowed


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "README.md",
        "package.json",  # CI runs it, but a change must touch it: the list cannot close that
        "Makefile",
        "tests/test_x.py",
        "github/workflows/x.yml",  # not the dot directory
        "docs/.github-notes.md",
        "src/.github/x",  # GitHub reads only the root .github
        "my.git/x",
        "a/gitignore",
        "CODEOWNERS.md",
        "MyCodeOwners.txt",
        "src/sto/workspace/path_policy.py",
    ],
)
def test_ordinary_paths_are_allowed(path: str) -> None:
    assert check_paths([_modify(path)], POLICY).allowed


# --- adversarial spellings ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    [
        ".GITHUB/workflows/ci.yml",  # case folding
        ".GitHub/Workflows/CI.yml",
        "./.github/workflows/ci.yml",  # dot segment
        "src/../.github/workflows/ci.yml",  # parent segment: refused outright, see below
        ".github//workflows/ci.yml",  # doubled slash
        ".github/workflows/",  # trailing slash
        ".github/./workflows/ci.yml",
        ".github./workflows/ci.yml",  # trailing dot, ignored by NTFS
        ".github /workflows/ci.yml",  # trailing space, ignored by NTFS
        ".github...//x",
        ".github\\workflows\\ci.yml",  # backslash separator on a Windows checkout
        "\uff0egithub/workflows/ci.yml",  # fullwidth full stop, NFKC
        ".g\u200bithub/workflows/ci.yml",  # zero width space
        ".git\u200chub/workflows/ci.yml",  # zero width non-joiner (HFS+ ignores it)
        ".gi\u00adthub/x",  # soft hyphen
        ".\uff27ithub/x",  # fullwidth G
        "GITHU~1/workflows/ci.yml",  # NTFS 8.3 short name
        "githu~1/x",
        "CODEOW~1",
        "docs/codeowners",
        "docs/CodeOwners",
        "docs/CODEOWNERS.",
        "JENKINSFILE",
        ".GITLAB-CI.YML",
        ".git/config",
        ".GIT/hooks/post-checkout",
        "sub/.git/hooks/x",
        ".sto/../.github/x",
        "a/b/../../.github/x",
        ".github::$DATA",  # NTFS alternate data stream
        ".github::$INDEX_ALLOCATION/x",
        "docs/CODEOWNERS:stream",
    ],
)
def test_adversarial_spellings_are_refused(spelling: str) -> None:
    assert not check_paths([_modify(spelling)], POLICY).allowed, spelling


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "/etc/passwd",
        "/.github/x",
        "//server/share/x",
        "..",
        "../x",
        "a/../../x",
        "src/../x",  # never lexically resolved: after a symlink it lands somewhere else
        "src/\x00.github/x",
        ".github\x00",
        "C:/x",
        "c:\\x",
        "\\\\host\\share",
        "   ",
        ".",
        "./",
        "a\nb",
    ],
)
def test_malformed_or_escaping_paths_are_refused(bad: str) -> None:
    result = check_paths([_modify(bad)], POLICY)
    assert not result.allowed
    assert result.violations[0].rule == "malformed"


def test_normalize_is_idempotent_and_canonical() -> None:
    assert normalize_path("./.GitHub//Workflows/./CI.yml.") == ".github/workflows/ci.yml"
    once = normalize_path("A/b/C.TXT")
    assert once == "a/b/c.txt"
    assert normalize_path(once) == once


def test_normalize_raises_on_malformed() -> None:
    for bad in ["", "/x", "../x", "a\x00b"]:
        with pytest.raises(PathPolicyError):
            normalize_path(bad)


# --- symlinks ----------------------------------------------------------------------------------


def test_new_symlink_pointing_into_a_denied_path_is_refused() -> None:
    change = PathChange(ChangeKind.ADD, "docs/ci", symlink_target="../.github")
    result = check_paths([change], POLICY)
    assert not result.allowed
    assert result.violations[0].rule == "symlink_target"


def test_new_symlink_escaping_the_repo_is_refused() -> None:
    change = PathChange(ChangeKind.ADD, "docs/x", symlink_target="../../etc/passwd")
    assert not check_paths([change], POLICY).allowed
    absolute = PathChange(ChangeKind.ADD, "docs/y", symlink_target="/etc/passwd")
    assert not check_paths([absolute], POLICY).allowed


def test_harmless_symlink_is_allowed() -> None:
    change = PathChange(ChangeKind.ADD, "docs/readme", symlink_target="../README.md")
    assert check_paths([change], POLICY).allowed


def test_write_through_an_existing_symlink_is_refused() -> None:
    # the base tree holds the link ``ci`` -> ``.github`` (repo-relative link path -> target)
    result = check_paths([_modify("ci/workflows/x.yml")], POLICY, symlinks={"ci": ".github"})
    assert not result.allowed
    assert result.violations[0].rule == "via_symlink"
    nested = check_paths([_modify("d/ci/x")], POLICY, symlinks={"d/ci": "../.github"})
    assert not nested.allowed


def test_symlink_chain_and_loop_fail_closed() -> None:
    chain = {"a": "b", "b": "c", "c": ".github"}
    assert not check_paths([_modify("a/x")], POLICY, symlinks=chain).allowed
    loop = {"a": "b", "b": "a"}
    result = check_paths([_modify("a/x")], POLICY, symlinks=loop)
    assert not result.allowed
    assert result.violations[0].rule == "malformed"


def test_symlink_lookup_is_case_folded() -> None:
    assert not check_paths([_modify("CI/x")], POLICY, symlinks={"ci": ".github"}).allowed


def test_unrelated_symlink_does_not_refuse() -> None:
    assert check_paths([_modify("lib/x.py")], POLICY, symlinks={"lib": "src"}).allowed


# --- configuration: upward only ------------------------------------------------------------------


def test_extra_patterns_extend_the_defaults() -> None:
    policy = PathPolicy(extra_denied=("infra/**", "*.tf", "deploy/prod.yaml"))
    assert not check_paths([_modify("infra/a/b.txt")], policy).allowed
    assert not check_paths([_modify("main.tf")], policy).allowed
    assert not check_paths([_modify("x/y/main.TF")], policy).allowed
    assert not check_paths([_modify("deploy/prod.yaml")], policy).allowed
    assert check_paths([_modify("deploy/dev.yaml")], policy).allowed
    # and the defaults still hold
    assert not check_paths([_modify(".github/x")], policy).allowed


def test_defaults_cannot_be_removed_by_configuration() -> None:
    with pytest.raises(TypeError):
        PathPolicy(extra_denied=(), denied=())  # type: ignore[call-arg]
    with pytest.raises(PathPolicyError):
        PathPolicy(extra_denied=("!.github/**",))  # no negation, so no carve-out
    for pattern in ("", "/abs", "../x", "a\x00b"):
        with pytest.raises(PathPolicyError):
            PathPolicy(extra_denied=(pattern,))


def test_default_list_is_immutable_and_nonempty() -> None:
    assert isinstance(DEFAULT_DENIED, tuple)
    assert ".github/**" in DEFAULT_DENIED
    assert "**/CODEOWNERS" in DEFAULT_DENIED
    assert PathPolicy().denied == DEFAULT_DENIED


def test_extra_patterns_are_normalised_like_paths() -> None:
    policy = PathPolicy(extra_denied=("Infra/**",))
    assert not check_paths([_modify("INFRA/x")], policy).allowed


# --- results: every offending path is reported; a refusal is never routed past the push -------


def test_every_violation_is_reported_not_just_the_first() -> None:
    changes = [_modify(".github/a"), _modify("src/ok.py"), _modify("CODEOWNERS")]
    result = check_paths(changes, POLICY)
    assert [v.path for v in result.violations] == [".github/a", "CODEOWNERS"]
    assert all(v.rule for v in result.violations)


def test_empty_patch_is_allowed() -> None:
    assert check_paths([], POLICY).allowed


def test_a_refusal_can_only_be_corrected_or_waived_by_org() -> None:
    result = check_paths([_modify(".github/x")], POLICY)
    assert result.resolutions == RESOLUTIONS == ("corrected_patch", "org_waiver")
    assert "route_to_gate" not in RESOLUTIONS
    assert result.routable_past_push is False
    assert NO_ROUTE_PAST_PUSH is True


def test_allowed_result_has_no_resolutions() -> None:
    result = check_paths([_modify("src/a.py")], POLICY)
    assert result.resolutions == ()
    assert result.routable_past_push is False


def test_raise_if_refused_raises_a_permanent_error() -> None:
    check_paths([_modify("src/a.py")], POLICY).raise_if_refused()
    with pytest.raises(PathPolicyError) as exc:
        check_paths([_modify(".github/x")], POLICY).raise_if_refused()
    assert isinstance(exc.value, PermanentError)  # BLOCKED at once, never retried
    assert not exc.value.retryable
    assert ".github/x" in str(exc.value)


def test_error_message_does_not_echo_control_characters() -> None:
    result = check_paths([_modify("a\x00\n.github/x\x1b[31m")], POLICY)
    for violation in result.violations:
        assert "\x00" not in violation.path
        assert "\n" not in violation.path
        assert "\x1b" not in violation.path
    with pytest.raises(PathPolicyError) as exc:
        result.raise_if_refused()
    assert "\x00" not in str(exc.value)
    assert "\x1b" not in str(exc.value)


def test_policy_is_a_fixed_function_of_its_input() -> None:
    changes = [_modify(".github/x"), PathChange(ChangeKind.RENAME, "b", old_path="a")]
    assert check_paths(changes, POLICY) == check_paths(changes, PathPolicy())


def test_rename_requires_old_path() -> None:
    with pytest.raises(PathPolicyError):
        PathChange(ChangeKind.RENAME, "b")
    with pytest.raises(PathPolicyError):
        PathChange(ChangeKind.COPY, "b")
    with pytest.raises(PathPolicyError):
        PathChange(ChangeKind.MODIFY, "b", old_path="a")
