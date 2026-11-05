"""D4-27: the path deny list (PLAN 8.4, T4, ADR-0021).

A SECOND layer only. CI also runs files a change must be able to touch (``package.json`` scripts,
a ``Makefile``, tests), so this list cannot close the CI hole; T18's attestation is the real
control. These tests prove the list refuses what it names, adversarially spelled, and that a
refusal cannot be routed past the push.
"""

from __future__ import annotations

import signal
import time

import pytest

from sto.domain.errors import PermanentError
from sto.workspace.path_policy import (
    DEFAULT_DENIED,
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
    # review pass 1, item 1
    "buildkite.yml",
    "buildkite.yaml",
    "buildkite.json",
    ".cirrus.star",
    ".drone.star",
    ".teamcity/settings.kts",
    ".tekton/pipeline.yaml",
    "bitrise.yml",
    "codemagic.yaml",
    "cloudbuild.json",
    "buildspec.yaml",
    "buildspec-test.yaml",
    ".gitmodules",
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


# --- review pass 1 -----------------------------------------------------------------------------


def test_gitattributes_is_left_to_the_patch_flow() -> None:
    assert check_paths([_modify(".gitattributes")], POLICY).allowed  # D5-07 handles it


@pytest.mark.parametrize(
    "short",
    [
        "GITLAB~1.YML",
        "TRAVIS~1.YML",
        "APPVEY~1.YML",
        "BITBUC~1.YML",
        "AZURE-~1.YML",
        "JENKIN~1",  # stem from the wildcard pattern Jenkinsfile*
        "AZURE-~1.YAML",
        "BUILDS~1.YML",
        "CLOUDB~1.JSON",
        "GITMOD~1",
        "sub/dir/GITLAB~2.yml",
    ],
)
def test_short_names_with_an_extension_or_from_wildcard_patterns_are_refused(short: str) -> None:
    result = check_paths([_modify(short)], POLICY)
    assert [v.rule for v in result.violations] == ["short_name"]


def test_unrelated_short_looking_names_are_allowed() -> None:
    assert check_paths([_modify("REPORT~1.TXT")], POLICY).allowed
    assert check_paths([_modify("docs/notes~1.md")], POLICY).allowed


def _timed(policy: PathPolicy, parts: int, leaf: str = "x") -> float:
    """Seconds one check takes. A SIGALRM at 5 s fails the test, so a regression to a
    super-linear matcher is a named failure and not a hang."""

    def too_slow(signum: int, frame: object) -> None:
        raise AssertionError("path matching took over 5 s: super-linear glob matcher")

    path = "/".join(["a"] * parts + [leaf])
    previous = signal.signal(signal.SIGALRM, too_slow)
    signal.setitimer(signal.ITIMER_REAL, 5.0)
    try:
        started = time.perf_counter()
        check_paths([PathChange(ChangeKind.ADD, path)], policy)
        return time.perf_counter() - started
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize(
    "pattern",
    [
        "**/a/**/a/**/secret",
        "/".join(["**"] * 5 + ["zz"]),
        "**/a/**/a/**/a/**/a/**/a/**/secret",
        "a/**/a/**/a/**/a/**/a/**/a/**/a/**/zz",
        "**/**/**/**/**/zz",
    ],
)
def test_matching_time_is_bounded_for_adversarial_patterns_and_paths(pattern: str) -> None:
    assert _timed(PathPolicy(extra_denied=(pattern,)), 2000) < 1.0
    assert _timed(PathPolicy(extra_denied=(pattern,)), 2000, leaf="secret") < 1.0


def test_matching_time_is_bounded_against_the_defaults() -> None:
    assert _timed(POLICY, 2000) < 1.0


def test_globstar_semantics_survive_the_rewrite() -> None:
    policy = PathPolicy(extra_denied=("**/a/**/a/**/secret", "x/**/y"))
    assert not check_paths([_modify("a/a/secret")], policy).allowed
    assert not check_paths([_modify("q/a/m/n/a/secret")], policy).allowed
    assert check_paths([_modify("a/secret")], policy).allowed
    assert not check_paths([_modify("x/y")], policy).allowed
    assert not check_paths([_modify("x/1/2/y")], policy).allowed
    assert check_paths([_modify("x/1/2/z")], policy).allowed


@pytest.mark.parametrize(
    "link", ["/usr/bin/tool", "C:/tools/x", "c:\\tools", "\\\\host\\share", "bad\x00target"]
)
def test_an_absolute_base_symlink_does_not_block_unrelated_patches(link: str) -> None:
    links = {"vendor/tool": link}
    assert check_paths([_modify("src/app.py")], POLICY, symlinks=links).allowed
    through = check_paths([_modify("vendor/tool/x")], POLICY, symlinks=links)
    assert not through.allowed
    assert through.violations[0].rule == "malformed"  # recorded as leaving the repository


def test_a_new_absolute_symlink_does_not_block_other_paths() -> None:
    new = PathChange(ChangeKind.ADD, "l", symlink_target="/etc/passwd")
    result = check_paths([_modify("src/app.py"), new], POLICY)
    assert [v.path for v in result.violations] == ["l"]
    through = check_paths([new, _modify("l/x")], POLICY)
    assert [v.path for v in through.violations] == ["l", "l/x"]


def test_modifying_a_base_symlink_that_points_at_a_denied_file_is_refused() -> None:
    result = check_paths([_modify("link")], POLICY, symlinks={"link": ".github/workflows/ci.yml"})
    assert [v.rule for v in result.violations] == ["via_symlink"]


def test_trailing_slash_in_a_team_pattern_means_everything_below() -> None:
    policy = PathPolicy(extra_denied=("infra/",))
    assert not check_paths([_modify("infra/x")], policy).allowed
    assert not check_paths([_modify("infra/a/b")], policy).allowed
    assert check_paths([_modify("other/x")], policy).allowed


def test_a_malformed_base_symlink_entry_raises_instead_of_being_skipped() -> None:
    with pytest.raises(PathPolicyError):
        check_paths([_modify("src/a.py")], POLICY, symlinks={"bad\x00link": "x"})
    with pytest.raises(PathPolicyError):
        check_paths([_modify("src/a.py")], POLICY, symlinks={"": "x"})


def test_a_legitimate_two_link_chain_is_allowed() -> None:
    chain = {"a": "b", "b": "src"}
    assert check_paths([_modify("a/x.py")], POLICY, symlinks=chain).allowed


def test_a_chain_just_under_the_hop_limit_is_followed_and_over_it_fails_closed() -> None:
    def chain(length: int) -> dict[str, str]:
        links = {f"l{i}": f"l{i + 1}" for i in range(length)}
        links[f"l{length}"] = "src"
        return links

    assert check_paths([_modify("l0/x")], POLICY, symlinks=chain(30)).allowed
    over = check_paths([_modify("l0/x")], POLICY, symlinks=chain(60))
    assert [v.rule for v in over.violations] == ["malformed"]


def test_kind_is_coerced_so_a_string_cannot_skip_the_checks() -> None:
    with pytest.raises(PathPolicyError):
        PathChange("delete", "a", symlink_target="b")  # type: ignore[arg-type]
    with pytest.raises(PathPolicyError):
        PathChange("rename", "b")  # type: ignore[arg-type]
    with pytest.raises(PathPolicyError):
        PathChange("nonsense", "b")  # type: ignore[arg-type]
    assert PathChange("add", "b").kind is ChangeKind.ADD  # type: ignore[arg-type]


def test_a_bare_string_is_not_a_list_of_patterns() -> None:
    with pytest.raises(PathPolicyError):
        PathPolicy(extra_denied="*.tf")  # type: ignore[arg-type]
    with pytest.raises(PathPolicyError):
        PathPolicy(extra_denied="tf")  # type: ignore[arg-type]  # every character is a valid pattern


def test_case_folding_can_change_length_and_is_a_known_limit() -> None:
    policy = PathPolicy(extra_denied=("stra?e.cfg",))
    assert check_paths([_modify("straße.cfg")], policy).allowed  # ß folds to ss: documented
    assert not check_paths(
        [_modify("strasse.cfg")], PathPolicy(extra_denied=("strasse.cfg",))
    ).allowed
    assert not check_paths(
        [_modify("straße.cfg")], PathPolicy(extra_denied=("strasse.cfg",))
    ).allowed


def test_the_source_of_a_copy_is_refused_deliberately() -> None:
    change = PathChange(ChangeKind.COPY, "src/copy.yml", old_path=".github/workflows/ci.yml")
    assert not check_paths([change], POLICY).allowed
