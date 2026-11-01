"""In-memory ``ScmProvider``. Refs, PRs and merges are dictionaries; nothing leaves the process."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

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
    RepoRef,
    ScmCapabilities,
    SnapshotLocation,
    StaleHeadError,
    UpdateResult,
)
from sto.domain.models import Receipt

_PORT = "scm"


@dataclass
class _Pr:
    spec: PrSpec
    state: str = "draft"
    head: str = ""


@dataclass
class _Merge:
    pr: PrRef
    state: MergeState = MergeState.PENDING
    merge_sha: str | None = None


def _sha(*parts: str) -> str:
    return hashlib.sha1("\0".join(parts).encode(), usedforsecurity=False).hexdigest()


class FakeScm:
    def __init__(self, spy: SpyWriter | None = None) -> None:
        self.capabilities = ScmCapabilities()
        self._spy = spy or SpyWriter()
        self._heads: dict[tuple[RepoRef, str], str] = {}
        self._prs: dict[PrRef, _Pr] = {}
        self._pr_by_branch: dict[tuple[RepoRef, str], PrRef] = {}
        self._merges: dict[str, _Merge] = {}
        self._checks: dict[tuple[RepoRef, str], list[CheckResult]] = {}
        self._handles: dict[IdempotencyKey, MergeHandle] = {}
        self.trusted = True

    # --- test controls and reads (not writes, so the spy ignores them) ---
    def seed_branch(self, repo: RepoRef, branch: str, sha: str) -> None:
        self._heads[(repo, branch)] = sha

    def head(self, repo: RepoRef, branch: str) -> str:
        return self._heads[(repo, branch)]

    def set_pr_head(self, pr: PrRef, sha: str) -> None:
        self._prs[pr].head = sha

    def pr_state(self, pr: PrRef) -> str:
        return self._prs[pr].state

    def complete_merge(self, handle: MergeHandle, merge_sha: str) -> None:
        merge = self._merges[handle.id]
        merge.state, merge.merge_sha = MergeState.MERGED, merge_sha

    # --- reads ---
    def snapshot(self, repo: RepoRef, sha: str) -> SnapshotLocation:
        return SnapshotLocation(f"fake://{repo.owner}/{repo.name}/{sha}")

    def poll_merge(self, handle: MergeHandle) -> MergeResult:
        merge = self._merges[handle.id]
        return MergeResult(merge.state, merge.merge_sha)

    def ci_trust(self, repo: RepoRef) -> CiTrustReport:
        return CiTrustReport(self.trusted, () if self.trusted else ("fake: untrusted",))

    def checks(self, repo: RepoRef, sha: str) -> list[CheckResult]:
        return list(self._checks.get((repo, sha), []))

    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]:
        return []

    # --- writes ---
    def create_commit(self, repo: RepoRef, patch: PatchRef, parent: str) -> CommitIntent:
        intent = CommitIntent(_sha(repo.owner, repo.name, patch.id, parent), parent, patch)
        self._spy.record(_PORT, "create_commit", {"repo": repo, "patch": patch, "parent": parent})
        return intent

    def move_ref(
        self, repo: RepoRef, branch: str, intent: CommitIntent, expected_head: str
    ) -> Receipt:
        args = {"repo": repo, "branch": branch, "intent": intent, "expected_head": expected_head}
        self._spy.record(_PORT, "move_ref", args)
        if self._heads.get((repo, branch)) != expected_head:
            raise StaleHeadError(f"{branch} head is not {expected_head}")
        self._heads[(repo, branch)] = intent.sha
        return self._spy.receipt("ref", f"fake://{repo.name}/{branch}@{intent.sha}")

    def promote(self, repo: RepoRef, sha: str, branch: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._heads[(repo, branch)] = sha
            return self._spy.receipt("promote", f"fake://{repo.name}/{branch}")

        return self._spy.write(
            _PORT, "promote", {"repo": repo, "sha": sha, "branch": branch}, key, apply
        )

    def ensure_draft_pr(self, spec: PrSpec, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            existing = self._pr_by_branch.get((spec.repo, spec.branch))
            if existing is not None:  # finds or creates, keyed by branch
                return self._spy.receipt_for(
                    f"pr-{existing.number}", f"fake://pr/{existing.number}"
                )
            number = len(self._prs) + 1
            ref = PrRef(spec.repo, number)
            self._prs[ref] = _Pr(spec)
            self._pr_by_branch[(spec.repo, spec.branch)] = ref
            return self._spy.receipt_for(f"pr-{number}", f"fake://pr/{number}")

        return self._spy.write(_PORT, "ensure_draft_pr", {"spec": spec}, key, apply)

    def mark_ready(self, pr: PrRef, key: IdempotencyKey) -> Receipt:
        return self._set_state("mark_ready", pr, "ready", key)

    def close_pr(self, pr: PrRef, key: IdempotencyKey) -> Receipt:
        return self._set_state("close_pr", pr, "closed", key)

    def _set_state(self, method: str, pr: PrRef, state: str, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._prs[pr].state = state
            return self._spy.receipt_for(f"pr-{pr.number}", f"fake://pr/{pr.number}")

        return self._spy.write(_PORT, method, {"pr": pr}, key, apply)

    def merge_base_into(self, pr: PrRef, expected_head: str, key: IdempotencyKey) -> UpdateResult:
        # Checked client-side: the real merges endpoint cannot carry an expected head.
        state: dict[str, UpdateResult] = {}

        def apply() -> Receipt:
            if self._prs[pr].head != expected_head:
                raise StaleHeadError(f"PR head is not {expected_head}")
            new = _sha("base-merge", expected_head)
            self._prs[pr].head = new
            receipt = self._spy.receipt("update", f"fake://pr/{pr.number}@{new}")
            state["r"] = UpdateResult(new, expected_head, receipt)
            return receipt

        args = {"pr": pr, "expected_head": expected_head}
        receipt = self._spy.write(_PORT, "merge_base_into", args, key, apply)
        if "r" not in state:  # replay
            return UpdateResult(self._prs[pr].head, expected_head, receipt)
        return state["r"]

    def open_revert_pr(self, merge_sha: str, key: IdempotencyKey) -> Receipt:
        return self._spy.write(
            _PORT,
            "open_revert_pr",
            {"merge_sha": merge_sha},
            key,
            lambda: self._spy.receipt("revert", f"fake://revert/{merge_sha}"),
        )

    def request_merge(
        self, pr: PrRef, expected_sha: str, method: MergeMethod, key: IdempotencyKey
    ) -> MergeHandle:
        args = {"pr": pr, "expected_sha": expected_sha, "method": method}
        handles = self._handles
        if key in handles:
            self._spy.write(_PORT, "request_merge", args, key, lambda: self._spy.receipt("m"))
            return handles[key]
        if self._prs[pr].head != expected_sha:
            self._spy.record(_PORT, "request_merge", args, key)
            raise StaleHeadError(f"PR head is not {expected_sha}")

        def apply() -> Receipt:
            hid = self._spy.next_id("merge")
            handles[key] = MergeHandle(hid, pr)
            self._merges[hid] = _Merge(pr)
            return self._spy.receipt("m")

        self._spy.write(_PORT, "request_merge", args, key, apply)
        return handles[key]

    def dequeue(self, pr: PrRef, expected_head: str) -> Receipt:
        self._spy.record(_PORT, "dequeue", {"pr": pr, "expected_head": expected_head})
        if self._prs[pr].head != expected_head:
            raise StaleHeadError(f"PR head is not {expected_head}")
        for merge in self._merges.values():
            if merge.pr == pr and merge.state is MergeState.PENDING:
                merge.state = MergeState.DEQUEUED
        return self._spy.receipt("dequeue", f"fake://pr/{pr.number}")

    def trigger_workflow(self, repo: RepoRef, spec: DispatchSpec, key: IdempotencyKey) -> Receipt:
        return self._spy.write(
            _PORT,
            "trigger_workflow",
            {"repo": repo, "spec": spec},
            key,
            lambda: self._spy.receipt("run", f"fake://{repo.name}/{spec.workflow}"),
        )

    def publish_check(self, spec: CheckSpec, key: IdempotencyKey) -> Receipt:
        def apply() -> Receipt:
            self._checks.setdefault((spec.repo, spec.sha), []).append(
                CheckResult(spec.name, spec.conclusion)
            )
            return self._spy.receipt("check", f"fake://{spec.repo.name}/{spec.sha}/{spec.name}")

        return self._spy.write(_PORT, "publish_check", {"spec": spec}, key, apply)
