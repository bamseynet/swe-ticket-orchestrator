"""Integration SPI (PLAN 10.1): ``TicketSource``, ``ScmProvider`` and ``Notifier``.

Adapters implement these narrow ports; the engine never imports a vendor. Writes take an
``IdempotencyKey`` and return a domain ``Receipt``. The value types here are part of the SPI
and are plain frozen dataclasses so fakes and real adapters share them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError
from sto.domain.models import Receipt

type IdempotencyKey = str


class StaleHeadError(PermanentError):
    """The head the caller expected is not the head now (``expected_head`` / ``expected_sha``)."""


# --- shared value types -------------------------------------------------------------------


@dataclass(frozen=True)
class RawWebhook:
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Page[T]:
    items: tuple[T, ...]
    next_cursor: str | None = None


@dataclass(frozen=True)
class ExternalChange:
    """A nudge that something changed; the adapter re-reads state (PLAN 10.1)."""

    ref: TicketRef
    kind: str = "updated"


@dataclass(frozen=True)
class DecisionRequest:
    gate_id: str
    kind: str  # an approve, request_changes or reject action
    actor: str
    comment: str = ""


# --- tickets ------------------------------------------------------------------------------


@dataclass(frozen=True)
class TicketRef:
    system: str
    key: str


@dataclass(frozen=True)
class Ticket:
    ref: TicketRef
    title: str
    body: str
    status: str
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class TicketSummary:
    ref: TicketRef
    title: str
    status: str


@dataclass(frozen=True)
class IntakeQuery:
    labels: tuple[str, ...] = ()
    status: str | None = None


class StatusIntent(StrEnum):
    """Target by meaning, not by workflow-specific transition ID."""

    TODO = "todo"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    DONE = "done"


@dataclass(frozen=True)
class BoardRef:
    id: str


@dataclass(frozen=True)
class Sprint:
    id: str
    name: str


@dataclass(frozen=True)
class TicketCapabilities:
    webhooks: bool = True
    sprints: bool = False


# --- scm ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str


@dataclass(frozen=True)
class PatchRef:
    id: str


@dataclass(frozen=True)
class SnapshotLocation:
    uri: str


@dataclass(frozen=True)
class CommitIntent:
    """The commit's SHA is known before the ref moves, so a crash leaves it recognisable."""

    sha: str
    parent: str
    patch: PatchRef


@dataclass(frozen=True)
class PrSpec:
    repo: RepoRef
    branch: str
    base: str
    title: str
    body: str


@dataclass(frozen=True)
class PrRef:
    repo: RepoRef
    number: int


class MergeMethod(StrEnum):
    MERGE = "merge"
    SQUASH = "squash"
    REBASE = "rebase"


@dataclass(frozen=True)
class UpdateResult:
    """Outcome of merging the base into a PR branch: the new head and the head it replaced."""

    sha: str
    parent_head: str
    receipt: Receipt


@dataclass(frozen=True)
class MergeHandle:
    """Merges are asynchronous (merge queue): request returns a handle, ``poll_merge`` resolves."""

    id: str
    pr: PrRef


class MergeState(StrEnum):
    PENDING = "pending"
    MERGED = "merged"
    FAILED = "failed"
    DEQUEUED = "dequeued"


@dataclass(frozen=True)
class MergeResult:
    state: MergeState
    merge_sha: str | None = None
    receipt: Receipt | None = None


@dataclass(frozen=True)
class DispatchSpec:
    workflow: str
    ref: str
    inputs: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CiTrustReport:
    trusted: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckResult:
    name: str
    conclusion: str


@dataclass(frozen=True)
class CheckSpec:
    repo: RepoRef
    sha: str
    name: str
    conclusion: str


@dataclass(frozen=True)
class ScmCapabilities:
    check_runs: bool = True
    merge_queue: bool = True


# --- notifier -----------------------------------------------------------------------------


@dataclass(frozen=True)
class GateMessage:
    gate_id: str
    summary: str
    subject_digest: str


@dataclass(frozen=True)
class NotifierCapabilities:
    update_in_place: bool = True


# --- ports --------------------------------------------------------------------------------


@runtime_checkable
class TicketSource(Protocol):
    capabilities: TicketCapabilities

    def get(self, ref: TicketRef) -> Ticket: ...
    def search(
        self, query: IntakeQuery, cursor: str | None, page_size: int = 50
    ) -> Page[TicketSummary]: ...
    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]: ...  # verified before this call
    def comment(self, ref: TicketRef, body: str, key: IdempotencyKey) -> Receipt: ...
    def transition(self, ref: TicketRef, to: StatusIntent, key: IdempotencyKey) -> Receipt: ...
    def current_sprint(self, board: BoardRef) -> Sprint | None: ...


@runtime_checkable
class ScmProvider(Protocol):
    capabilities: ScmCapabilities

    def snapshot(self, repo: RepoRef, sha: str) -> SnapshotLocation: ...
    def create_commit(self, repo: RepoRef, patch: PatchRef, parent: str) -> CommitIntent: ...
    def move_ref(
        self, repo: RepoRef, branch: str, intent: CommitIntent, expected_head: str
    ) -> Receipt: ...
    def promote(self, repo: RepoRef, sha: str, branch: str, key: IdempotencyKey) -> Receipt: ...
    def ensure_draft_pr(self, spec: PrSpec, key: IdempotencyKey) -> Receipt: ...
    def mark_ready(self, pr: PrRef, key: IdempotencyKey) -> Receipt: ...
    def close_pr(self, pr: PrRef, key: IdempotencyKey) -> Receipt: ...
    def merge_base_into(
        self, pr: PrRef, expected_head: str, key: IdempotencyKey
    ) -> UpdateResult: ...
    def open_revert_pr(self, merge_sha: str, key: IdempotencyKey) -> Receipt: ...
    def request_merge(
        self, pr: PrRef, expected_sha: str, method: MergeMethod, key: IdempotencyKey
    ) -> MergeHandle: ...
    def poll_merge(self, handle: MergeHandle) -> MergeResult: ...
    def dequeue(self, pr: PrRef, expected_head: str) -> Receipt: ...
    def trigger_workflow(
        self, repo: RepoRef, spec: DispatchSpec, key: IdempotencyKey
    ) -> Receipt: ...
    def ci_trust(self, repo: RepoRef) -> CiTrustReport: ...
    def checks(self, repo: RepoRef, sha: str) -> list[CheckResult]: ...
    def publish_check(self, spec: CheckSpec, key: IdempotencyKey) -> Receipt: ...
    def parse_event(self, raw: RawWebhook) -> list[ExternalChange]: ...


@runtime_checkable
class Notifier(Protocol):
    capabilities: NotifierCapabilities

    def send(self, message: GateMessage, key: IdempotencyKey) -> Receipt: ...
    def update(self, receipt: Receipt, message: GateMessage) -> Receipt: ...
    def parse_action(self, raw: RawWebhook) -> DecisionRequest | None: ...
