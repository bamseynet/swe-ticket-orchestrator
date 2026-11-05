"""Path deny list for agent patches (D4-27; PLAN 8.4 and T4; ADR-0021).

The control plane checks every path in a patch against this list before it commits to a ``sto/*``
branch. The defaults refuse ``.github/**``, other CI systems' config, ``CODEOWNERS``, ``.git/**``
and the GitOps workflow path (``.sto/**``). An org can add patterns; nothing can be removed, and
there is no negation, so the list is configurable upward only.

**This is a second layer only.** CI also runs files a change has to be able to touch
(``package.json`` scripts, a ``Makefile``, tests, a composite action), so a deny list cannot close
the CI hole. T18's CI trust attestation is the real control (ADR-0021). Do not read a clean result
here as "this patch cannot run code in CI".

**A refusal is never routed past the push.** The only resolutions are a corrected patch or a
separate org waiver naming that patch (PLAN 6, route-to-gate). ``routable_past_push`` is a constant
``False`` and ``RESOLUTIONS`` has no route-to-gate entry. Raising uses a ``PermanentError``, so the
step is BLOCKED at once and never retried.

Threats covered (the check is a pure function of strings):

* case folding, Unicode compatibility forms (NFKC, so fullwidth letters and ligatures; NFKC does
  not map cross-script homoglyphs such as Cyrillic ``а``, which are different names on every
  filesystem), and zero-width or other format characters that HFS+ and NTFS ignore;
* ``.`` and empty segments, doubled and trailing slashes, backslash separators, trailing dots and
  spaces (NTFS drops them), NTFS alternate data streams (``name::$DATA``), 8.3 short names
  (``GITHU~1``) and drive letters;
* absolute paths, UNC paths, ``..`` anywhere (refused outright, never resolved lexically, because
  after a symlink it lands elsewhere), NUL, control and line-separator characters;
* a rename or copy into **or out of** a denied path (refusing the source of a copy is deliberate:
  a patch that reads from a protected file into a new one is as suspect as one that writes it), and
  a new symlink whose target is denied or leaves the repo;
* a write through a symlink, when the caller passes the base tree's symlinks (plus any the patch
  adds), including chains, and loops fail closed.

Not covered:

* a symlink the caller does not tell it about: it cannot see the repository, so the caller must
  pass every symlink in the base tree (``symlinks=``);
* case-sensitivity or Unicode behaviour of a filesystem it was not written for: it folds more than
  any one filesystem does, so it over-refuses rather than under-refuses. Case folding can change
  a name's length (``ß`` becomes ``ss``), so a team pattern ``stra?e.cfg`` misses ``straße.cfg``;
  write ``strasse.cfg`` (patterns are folded the same way) or ``stra*e.cfg``;
* what a file does once committed: CI, hooks run elsewhere, git attributes and submodule config
  are not interpreted, and a permitted file can still run code in CI (see above);
* content: it never reads file contents (the secret scan does that);
* a path that the policy permits but a later layer rewrites.
"""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from sto.domain.errors import PermanentError

RESOLUTIONS = ("corrected_patch", "org_waiver")
"""The only ways out of a refusal. There is deliberately no route-to-gate."""

DEFAULT_DENIED: tuple[str, ...] = (
    ".github/**",
    "**/CODEOWNERS",
    "**/.git/**",
    ".sto/**",  # the GitOps workflow path (PLAN 7.1, D13-11)
    # other CI systems
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".gitlab/**",
    ".circleci/**",
    "Jenkinsfile*",
    ".travis.yml",
    ".travis.yaml",
    "azure-pipelines*.yml",
    "azure-pipelines*.yaml",
    ".azure-pipelines/**",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".buildkite/**",
    ".gitea/**",
    ".forgejo/**",
    ".woodpecker/**",
    ".woodpecker.yml",
    ".woodpecker.yaml",
    ".cirrus.yml",
    ".semaphore/**",
    ".teamcity/**",
    ".tekton/**",
    "buildkite.yml",
    "buildkite.yaml",
    "buildkite.json",
    ".cirrus.star",
    ".drone.star",
    "bitrise.yml",
    "codemagic.yaml",
    "cloudbuild.json",
    "buildspec*.yaml",
    ".gitmodules",  # a checkout with submodules fetches whatever URL this names
    "appveyor.yml",
    ".appveyor.yml",
    "cloudbuild.yml",
    "cloudbuild.yaml",
    "buildspec*.yml",
)

_MAX_PATH_CHARS = 4096
_MAX_SYMLINK_HOPS = 40
_BAD_CATEGORIES = frozenset({"Cc", "Cs", "Zl", "Zp"})
_DRIVE = re.compile(r"[a-z]:")
_SHORT_NAME = re.compile(r"(.*)~[0-9]+(\.[^./]*)?")
_GLOBSTAR = "**"


class PathPolicyError(PermanentError):
    """A malformed policy, or a refused patch (``PathPolicyResult.raise_if_refused``)."""


class ChangeKind(StrEnum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    COPY = "copy"


@dataclass(frozen=True)
class PathChange:
    """One path touched by a patch. ``old_path`` is the source of a rename or copy;
    ``symlink_target`` is set when the new entry is a symbolic link."""

    kind: ChangeKind
    path: str
    old_path: str | None = None
    symlink_target: str | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "kind", ChangeKind(self.kind))  # "delete" must not slip by
        except ValueError:
            raise PathPolicyError("unknown change kind") from None
        moves = self.kind in (ChangeKind.RENAME, ChangeKind.COPY)
        if moves and self.old_path is None:
            raise PathPolicyError(f"a {self.kind.value} needs old_path")
        if not moves and self.old_path is not None:
            raise PathPolicyError(f"a {self.kind.value} has no old_path")
        if self.kind is ChangeKind.DELETE and self.symlink_target is not None:
            raise PathPolicyError("a delete has no symlink_target")


@dataclass(frozen=True)
class Violation:
    path: str  # as given, made safe to print; never a normalised guess
    rule: str  # denied | malformed | short_name | via_symlink | symlink_target
    detail: str


@dataclass(frozen=True)
class PathPolicyResult:
    violations: tuple[Violation, ...]

    @property
    def allowed(self) -> bool:
        return not self.violations

    @property
    def resolutions(self) -> tuple[str, ...]:
        return () if self.allowed else RESOLUTIONS

    @property
    def routable_past_push(self) -> bool:
        return False

    def raise_if_refused(self) -> None:
        if self.allowed:
            return
        listing = "; ".join(f"{v.path} ({v.rule}: {v.detail})" for v in self.violations)
        raise PathPolicyError(
            f"path policy refused {len(self.violations)} path(s): {listing}. "
            "Only a corrected patch or an org waiver naming this patch can proceed; "
            "it is never routed past branch.push"
        )


def _safe(raw: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in raw)[:200]


def _fold(text: str) -> str:
    def strip(s: str) -> str:
        return "".join(ch for ch in s if unicodedata.category(ch) != "Cf")

    return strip(
        unicodedata.normalize("NFKC", strip(unicodedata.normalize("NFKC", text)).casefold())
    )


def _components(raw: str, *, allow_parent: bool = False) -> tuple[str, ...]:
    """Canonical components of a repo-relative path, or ``PathPolicyError`` if malformed."""
    if not isinstance(raw, str):
        raise PathPolicyError("malformed path: not a string")
    if len(raw) > _MAX_PATH_CHARS:
        raise PathPolicyError("malformed path: too long")
    if any(unicodedata.category(ch) in _BAD_CATEGORIES for ch in raw):
        raise PathPolicyError("malformed path: control character")
    text = _fold(raw).replace("\\", "/")
    if any(unicodedata.category(ch) in _BAD_CATEGORIES for ch in text):
        raise PathPolicyError("malformed path: control character")
    if text.startswith("/"):
        raise PathPolicyError("malformed path: absolute")
    parts: list[str] = []
    for index, part in enumerate(text.split("/")):
        if index == 0 and _DRIVE.match(part):
            raise PathPolicyError("malformed path: drive letter")
        if part in ("", "."):
            continue
        if part == "..":
            if allow_parent:
                parts.append(part)
                continue
            raise PathPolicyError("malformed path: parent segment")
        part = part.split(":", 1)[0].rstrip(" .")  # NTFS stream and trailing dots/spaces
        if not part:
            raise PathPolicyError("malformed path: empty segment")
        parts.append(part)
    return tuple(parts)


def normalize_path(raw: str) -> str:
    """The canonical form the policy matches on: folded, ``/``-separated, no dot segments.

    Raises ``PathPolicyError`` for an empty, absolute, ``..`` or control-character path."""
    parts = _components(raw)
    if not parts:
        raise PathPolicyError("malformed path: empty")
    return "/".join(parts)


def _compile(pattern: str) -> tuple[str, ...]:
    if not isinstance(pattern, str) or not pattern or pattern.startswith("!"):
        raise PathPolicyError("bad deny pattern: empty or negated")
    if pattern.endswith("/"):
        pattern += _GLOBSTAR
    parts = _components(pattern)
    if not parts:
        raise PathPolicyError("bad deny pattern: empty")
    collapsed = [
        p for i, p in enumerate(parts) if p != _GLOBSTAR or parts[i - 1 : i] != (_GLOBSTAR,)
    ]
    compiled = tuple(collapsed)
    return (_GLOBSTAR, *compiled) if len(compiled) == 1 else compiled


def _match(pattern: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    """Segment glob match in O(len(pattern) * len(parts)): one pass per pattern segment over the
    set of positions in ``parts`` reachable so far. No backtracking, so no adversarial blow-up."""
    size = len(parts)
    reach = [True] + [False] * size
    for segment in pattern:
        following = [False] * (size + 1)
        if segment == _GLOBSTAR:
            seen = False
            for pos in range(size + 1):
                seen = seen or reach[pos]
                following[pos] = seen
        else:
            for pos in range(size):
                if reach[pos] and fnmatch.fnmatchcase(parts[pos], segment):
                    following[pos + 1] = True
        reach = following
    return reach[size]


def _stems(patterns: Iterable[tuple[str, ...]]) -> frozenset[str]:
    """Literal names the patterns protect, as the stem an 8.3 short name is cut from."""
    stems: set[str] = set()
    for pattern in patterns:
        for part in pattern:
            if part == _GLOBSTAR:
                continue
            literal = re.split(r"[*?\[]", part, maxsplit=1)[0]  # prefix before any wildcard
            stem = literal.lstrip(".").split(".")[0]
            if stem:
                stems.add(stem)
    return frozenset(stems)


@dataclass(frozen=True)
class PathPolicy:
    """The defaults plus ``extra_denied`` patterns. Configurable upward only.

    A pattern is matched against the canonical path, case-folded. ``*`` and ``?`` match within one
    segment, ``**`` any number of segments, a trailing ``/`` means everything below. A pattern with
    one segment (``*.tf``) matches that name at any depth; one with a slash is anchored at the root.
    """

    extra_denied: tuple[str, ...] = ()
    _compiled: tuple[tuple[str, tuple[str, ...]], ...] = field(
        init=False, repr=False, compare=False, default=()
    )
    _stem_set: frozenset[str] = field(init=False, repr=False, compare=False, default=frozenset())

    def __post_init__(self) -> None:
        if isinstance(self.extra_denied, str):
            raise PathPolicyError("extra_denied must be a sequence of patterns, not a string")
        extras = tuple(self.extra_denied)
        object.__setattr__(self, "extra_denied", extras)
        compiled = tuple((p, _compile(p)) for p in (*DEFAULT_DENIED, *extras))
        object.__setattr__(self, "_compiled", compiled)
        object.__setattr__(self, "_stem_set", _stems(c for _, c in compiled))

    @property
    def denied(self) -> tuple[str, ...]:
        return (*DEFAULT_DENIED, *self.extra_denied)

    def _denied_by(self, parts: tuple[str, ...]) -> str | None:
        for source, compiled in self._compiled:
            if _match(compiled, parts):
                return source
        return None

    def _short_name(self, parts: tuple[str, ...]) -> bool:
        for part in parts:
            found = _SHORT_NAME.fullmatch(part)
            if not found:
                continue
            prefix = found.group(1).lstrip(".").split(".")[0]
            if prefix and len(prefix) <= 6 and any(s.startswith(prefix) for s in self._stem_set):
                return True
        return False


def _join(base: Sequence[str], target: Sequence[str]) -> tuple[str, ...] | None:
    stack = list(base)
    for part in target:
        if part == "..":
            if not stack:
                return None  # leaves the repository
            stack.pop()
        else:
            stack.append(part)
    return tuple(stack)


def _expansions(
    parts: tuple[str, ...],
    links: Mapping[tuple[str, ...], tuple[str, ...] | None],
    *,
    follow_last: bool = True,
) -> list[tuple[str, ...]]:
    """Every path ``parts`` becomes as symlinks are followed, one hop at a time."""
    states: list[tuple[str, ...]] = []
    current = parts
    for _ in range(_MAX_SYMLINK_HOPS + 1):
        for i in range(1, len(current) + (1 if follow_last else 0)):
            if current[:i] not in links:
                continue
            target = links[current[:i]]
            landed = None if target is None else _join(current[: i - 1], target)
            if landed is None:
                raise PathPolicyError("malformed path: symlink leaves the repository")
            current = (*landed, *current[i:])
            states.append(current)
            break
        else:
            return states
    raise PathPolicyError("malformed path: symlink loop or chain too long")


def _links(
    changes: Sequence[PathChange], base: Mapping[str, str] | None
) -> dict[tuple[str, ...], tuple[str, ...] | None]:
    """Symlinks by canonical path. A target that leaves the repository (relative, absolute, drive
    letter or malformed) is recorded as ``None``: only paths through that link are refused."""
    links: dict[tuple[str, ...], tuple[str, ...] | None] = {}
    entries = [(link, target, True) for link, target in (base or {}).items()]
    entries += [(c.path, c.symlink_target, False) for c in changes if c.symlink_target is not None]
    for link, target, from_base in entries:
        try:
            link_parts = _components(link)
            if not link_parts:
                raise PathPolicyError("malformed path: empty")
        except PathPolicyError as exc:
            if from_base:
                raise PathPolicyError(f"bad symlink map entry: {exc}") from exc
            continue  # a malformed new symlink is reported on its own change
        try:
            links[link_parts] = _components(target, allow_parent=True)
        except PathPolicyError:
            links[link_parts] = None
    return links


def check_paths(
    changes: Iterable[PathChange],
    policy: PathPolicy,
    *,
    symlinks: Mapping[str, str] | None = None,
) -> PathPolicyResult:
    """Check every path a patch touches (both ends of a rename or copy).

    ``symlinks`` maps each symlink in the base tree (repo-relative path) to its target, so a
    write through one is seen. Symlinks the patch adds are included automatically. All
    violations are returned, not just the first."""
    batch = list(changes)
    links = _links(batch, symlinks)
    violations: list[Violation] = []

    def check(
        raw: str,
        *,
        parts: tuple[str, ...] | None = None,
        follow_last: bool = True,
        rule: str | None = None,
    ) -> None:
        """Record at most one violation for ``raw``; ``rule`` overrides the rule name."""
        shown = _safe(raw)
        try:
            canon = parts if parts is not None else _components(raw)
            if not canon:
                raise PathPolicyError("malformed path: empty")
            states = _expansions(canon, links, follow_last=follow_last)
        except PathPolicyError as exc:
            violations.append(Violation(shown, rule or "malformed", str(exc)))
            return
        pattern = policy._denied_by(canon)
        if pattern is not None:
            violations.append(Violation(shown, rule or "denied", f"matches {pattern}"))
        elif policy._short_name(canon):
            violations.append(Violation(shown, rule or "short_name", "8.3 short name"))
        else:
            for state in states:
                hit = policy._denied_by(state) if state else None
                if hit is not None:
                    violations.append(Violation(shown, rule or "via_symlink", f"reaches {hit}"))
                    break

    def check_target(change: PathChange, target: str) -> None:
        shown = _safe(change.path)
        try:
            link_parts = _components(change.path)
            landed = _join(link_parts[:-1], _components(target, allow_parent=True))
            if landed is None:
                raise PathPolicyError("symlink target leaves the repository")
        except PathPolicyError as exc:
            if not any(v.path == shown and v.rule == "malformed" for v in violations):
                violations.append(Violation(shown, "symlink_target", str(exc)))
            return
        if landed:
            check(change.path, parts=landed, rule="symlink_target")

    for change in batch:
        # a new link's own name is not followed through itself; its target is checked below
        check(change.path, follow_last=change.symlink_target is None)
        if change.old_path is not None:
            check(change.old_path)
        if change.symlink_target is not None:
            check_target(change, change.symlink_target)
    return PathPolicyResult(tuple(violations))
