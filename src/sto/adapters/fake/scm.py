"""In-memory ``ScmProvider``, as strict as the real one (PLAN 6.3, 6.4): refs only fast-forward
to known commits, a PR's head is its branch's head, and merges are async and guarded."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sto.adapters.fake.base import FakeBase, parse_changes
from sto.adapters.fake.spy import SpyWriter
from sto.adapters.ports import (
    CheckResult,
    CheckSpec,
    CiTrustReport,
    CommitIntent,
    DispatchSpec,
    ExternalChange,
    IdempotencyKey,
    MergeHandle,
    MergeMethod,
    MergeResult,
    MergeState,
    PatchRef,
    PrRef,
    PrSpec,
    RawWebhook,
    RefusedError,
    RepoRef,
    ScmCapabilities,
    SnapshotLocation,
    StaleHeadError,
    UnknownRefError,
    UpdateResult,
)
from sto.domain.models import Receipt

_OPEN = ("draft", "ready")


@dataclass
class _Pr:
    spec: PrSpec
    state: str = "draft"  # draft, ready, closed or merged
    merged_head: str | None = None
    merge_sha: str | None = None


@dataclass
class _Merge:
    id: str
    pr: PrRef
    head: str  # the head the merge was requested at
    state: MergeState = MergeState.PENDING
    merge_sha: str | None = None
    receipt: Receipt | None = None


def _sha(*parts: str) -> str:
    return hashlib.sha1("\0".join(parts).encode(), usedforsecurity=False).hexdigest()


class FakeScm(FakeBase):
    def __init__(self, spy: SpyWriter | None = None) -> None:
        super().__init__("scm", spy)
        self.capabilities = ScmCapabilities()
        self.trusted = True
        self._heads: dict[tuple[RepoRef, str], str] = {}
        self._commits: dict[tuple[RepoRef, str], CommitIntent | None] = {}
        self._prs: dict[PrRef, _Pr] = {}
        self._merges: dict[str, _Merge] = {}
        self._checks: dict[tuple[RepoRef, str], dict[str, str]] = {}
        self._reverts: dict[str, Receipt] = {}
        self._conflicts: set[PrRef] = set()

    # --- test controls and reads (not writes, so the spy ignores them) ---
    def seed_branch(self, repo: RepoRef, branch: str, sha: str) -> None:
        self._heads[(repo, branch)] = sha
        self._commits.setdefault((repo, sha), None)  # a root commit, no intent

    def set_update_conflict(self, pr: PrRef, conflict: bool) -> None:
        (self._conflicts.add if conflict else self._conflicts.discard)(pr)

    def head(self, repo: RepoRef, branch: str) -> str:
        try:
            return self._heads[(repo, branch)]
        except KeyError:
            raise UnknownRefError(f"no branch {branch} in {repo}") from None

    def pr_head(self, pr: PrRef) -> str:
        spec = self._pr(pr).spec
        return self.head(spec.repo, spec.branch)

    def pr_state(self, pr: PrRef) -> str:
        return self._pr(pr).state

    def merges(self) -> list[MergeHandle]:
        return [MergeHandle(m.id, m.pr) for m in self._merges.values()]

    def _settle(self, handle: MergeHandle) -> _Merge:
        merge = self._resolve(self._merge(handle))
        if merge.state is not MergeState.PENDING:
            raise RefusedError(f"merge {merge.id} is {merge.state}, not pending")
        return merge

    def complete_merge(self, handle: MergeHandle, merge_sha: str) -> None:
        merge = self._settle(handle)
        self._finish(merge, MergeState.MERGED)
        merge.merge_sha = merge_sha
        pr = self._pr(merge.pr)
        pr.state, pr.merged_head, pr.merge_sha = "merged", merge.head, merge_sha

    def fail_merge(self, handle: MergeHandle) -> None:
        self._finish(self._settle(handle), MergeState.FAILED)

    def _pr(self, pr: PrRef) -> _Pr:
        try:
            return self._prs[pr]
        except KeyError:
            raise UnknownRefError(f"no PR {pr.number} in {pr.repo}") from None

    def _merge(self, handle: MergeHandle) -> _Merge:
        try:
            return self._merges[handle.id]
        except KeyError:
            raise UnknownRefError(f"no merge {handle.id}") from None

    def _pr_receipt(self, pr: PrRef) -> Receipt:
        return self._receipt("pr", f"fake://pr/{pr.number}", f"pr-{pr.number}")

    def _finish(self, merge: _Merge, state: MergeState) -> None:
        merge.state = state
        merge.receipt = self._receipt("merge", f"fake://pr/{merge.pr.number}", merge.id)

    def _resolve(self, merge: _Merge) -> _Merge:
        """A moved head cancels a pending merge (PLAN 6.4 guard 7)."""
        if merge.state is MergeState.PENDING and self.pr_head(merge.pr) != merge.head:
            self._finish(merge, MergeState.FAILED)
        return merge

    def _pending(self, pr: PrRef) -> _Merge | None:
        for merge in self._merges.values():
            if merge.pr == pr and self._resolve(merge).state is MergeState.PENDING:
                return merge
        return None

    def _known_commit(self, repo: RepoRef, sha: str) -> None:
        if (repo, sha) not in self._commits:
            raise UnknownRefError(f"no commit {sha} in {repo}")

    def snapshot(self, repo: RepoRef, sha: str) -> SnapshotLocation:
        self._known_commit(repo, sha)
        return SnapshotLocation(f"fake://{repo.owner}/{repo.name}/{sha}")

    def poll_merge(self, handle: MergeHandle) -> MergeResult:
        merge = self._resolve(self._merge(handle))
        return MergeResult(merge.state, merge.merge_sha, merge.receipt)

    def ci_trust(self, repo: RepoRef) -> CiTrustReport:
        return CiTrustReport(self.trusted, () if self.trusted else ("fake: untrusted",))

    def checks(self, repo: RepoRef, sha: str) -> list[CheckResult]:
        return [CheckResult(n, c) for n, c in self._checks.get((repo, sha), {}).items()]

    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]:
        return parse_changes(raw)

    def create_commit(self, repo: RepoRef, patch: PatchRef, parent: str) -> CommitIntent:
        def apply() -> CommitIntent:
            self._known_commit(repo, parent)
            intent = CommitIntent(_sha(repo.owner, repo.name, patch.id, parent), parent, patch)
            self._commits[(repo, intent.sha)] = intent
            return intent

        args = {"repo": repo, "patch": patch, "parent": parent}
        return self._write("create_commit", args, None, apply)

    def move_ref(
        self, repo: RepoRef, branch: str, intent: CommitIntent, expected_head: str
    ) -> Receipt:
        def apply() -> Receipt:
            current = self.head(repo, branch)
            if self._commits.get((repo, intent.sha)) != intent:
                raise RefusedError(f"{intent.sha} is not a commit created here")
            if current != expected_head:
                raise StaleHeadError(f"{branch} head is {current}, not {expected_head}")
            if intent.parent != expected_head:  # without force (PLAN 6.3)
                raise RefusedError(f"{intent.sha} does not fast-forward {expected_head}")
            self._heads[(repo, branch)] = intent.sha
            return self._receipt("ref", f"fake://{repo.name}/{branch}@{intent.sha}")

        args = {"repo": repo, "branch": branch, "intent": intent, "expected_head": expected_head}
        return self._write("move_ref", args, None, apply)

    def promote(self, repo: RepoRef, sha: str, branch: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._known_commit(repo, sha)
            if self._heads.get((repo, branch), sha) != sha:
                raise RefusedError(f"{branch} exists at another commit")
            self._heads[(repo, branch)] = sha
            return self._receipt("promote", f"fake://{repo.name}/{branch}")

        return self._write("promote", {"repo": repo, "sha": sha, "branch": branch}, key, apply)

    def ensure_draft_pr(self, spec: PrSpec, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self.head(spec.repo, spec.branch)
            self.head(spec.repo, spec.base)
            for ref, pr in self._prs.items():  # finds or creates, keyed by branch
                same = pr.spec.repo == spec.repo and pr.spec.branch == spec.branch
                if same and pr.state in _OPEN:
                    return self._pr_receipt(ref)
            ref = PrRef(spec.repo, len(self._prs) + 1)
            self._prs[ref] = _Pr(spec)
            return self._pr_receipt(ref)

        return self._write("ensure_draft_pr", {"spec": spec}, key, apply)

    def mark_ready(self, pr: PrRef, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            state = self._pr(pr)
            if state.state not in _OPEN:
                raise RefusedError(f"PR {pr.number} is {state.state}")
            state.state = "ready"
            return self._pr_receipt(pr)

        return self._write("mark_ready", {"pr": pr}, key, apply)

    def close_pr(self, pr: PrRef, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            state = self._pr(pr)
            if state.state == "merged":
                raise RefusedError(f"PR {pr.number} is already merged")
            state.state = "closed"
            pending = self._pending(pr)
            if pending is not None:  # closing a PR takes it out of the queue
                pending.state = MergeState.DEQUEUED
                pending.receipt = self._receipt("merge", f"fake://pr/{pr.number}", pending.id)
            return self._pr_receipt(pr)

        return self._write("close_pr", {"pr": pr}, key, apply)

    def merge_base_into(self, pr: PrRef, expected_head: str, key: IdempotencyKey) -> UpdateResult:
        # Checked client-side: the real merges endpoint cannot carry an expected head.
        def apply() -> UpdateResult:
            state = self._pr(pr)
            if state.state not in _OPEN:
                raise RefusedError(f"PR {pr.number} is {state.state}")
            repo, branch = state.spec.repo, state.spec.branch
            current = self.head(repo, branch)
            if current != expected_head:
                raise StaleHeadError(f"PR head is {current}, not {expected_head}")
            if pr in self._conflicts:
                return UpdateResult(current, current, None, conflict=True)
            intent = CommitIntent(_sha("base-merge", repo.name, current), current, PatchRef("base"))
            self._commits[(repo, intent.sha)] = intent
            self._heads[(repo, branch)] = intent.sha
            receipt = self._receipt("update", f"fake://pr/{pr.number}@{intent.sha}")
            return UpdateResult(intent.sha, current, receipt)

        args = {"pr": pr, "expected_head": expected_head}
        return self._write("merge_base_into", args, key, apply)

    def open_revert_pr(self, merge_sha: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            if all(p.merge_sha != merge_sha for p in self._prs.values()):
                raise UnknownRefError(f"no merge {merge_sha}")
            # keyed by (run, merge_sha): a declared and an implicit revert open one PR
            if merge_sha not in self._reverts:
                self._reverts[merge_sha] = self._receipt("revert", f"fake://revert/{merge_sha}")
            return self._reverts[merge_sha]

        return self._write("open_revert_pr", {"merge_sha": merge_sha}, key, apply)

    def request_merge(
        self, pr: PrRef, expected_sha: str, method: MergeMethod, key: IdempotencyKey
    ) -> MergeHandle:
        def apply() -> MergeHandle:
            state = self._pr(pr)
            if state.state == "merged":
                if state.merged_head != expected_sha:
                    raise RefusedError(f"PR {pr.number} merged at another commit")
                # already merged at that SHA counts as success (PLAN 6.3)
                done = [m for m in self._merges.values() if m.pr == pr and m.merge_sha]
                return MergeHandle(done[-1].id, pr)
            if state.state != "ready":
                raise RefusedError(f"PR {pr.number} is {state.state}, not ready")
            current = self.pr_head(pr)
            if current != expected_sha:
                raise StaleHeadError(f"PR head is {current}, not {expected_sha}")
            pending = self._pending(pr)
            if pending is not None:
                return MergeHandle(pending.id, pr)
            merge = _Merge(self._next_id("merge"), pr, current)
            self._merges[merge.id] = merge
            return MergeHandle(merge.id, pr)

        args = {"pr": pr, "expected_sha": expected_sha, "method": method}
        return self._write("request_merge", args, key, apply)

    def dequeue(self, pr: PrRef, expected_head: str) -> Receipt:
        def apply() -> Receipt:
            current = self.pr_head(pr)
            if current != expected_head:
                raise StaleHeadError(f"PR head is {current}, not {expected_head}")
            pending = self._pending(pr)
            if pending is None:  # a Stop racing a landed merge must not look like success
                raise RefusedError(f"PR {pr.number} has no pending merge to dequeue")
            self._finish(pending, MergeState.DEQUEUED)
            return self._receipt("dequeue", f"fake://pr/{pr.number}")

        return self._write("dequeue", {"pr": pr, "expected_head": expected_head}, None, apply)

    def trigger_workflow(self, repo: RepoRef, spec: DispatchSpec, key: IdempotencyKey) -> Receipt:
        return self._write(
            "trigger_workflow",
            {"repo": repo, "spec": spec},
            key,
            lambda: self._receipt("run", f"fake://{repo.name}/{spec.workflow}"),
        )

    def publish_check(self, spec: CheckSpec, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._known_commit(spec.repo, spec.sha)
            self._checks.setdefault((spec.repo, spec.sha), {})[spec.name] = spec.conclusion
            return self._receipt("check", f"fake://{spec.repo.name}/{spec.sha}/{spec.name}")

        return self._write("publish_check", {"spec": spec}, key, apply)
