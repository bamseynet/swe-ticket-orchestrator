"""Integration SPI (PLAN 10.1): ``TicketSource``, ``ScmProvider`` and ``Notifier``.

Adapters implement these narrow ports; the engine never imports a vendor. Writes take an
``IdempotencyKey`` and return a domain ``Receipt``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sto.domain.errors import PermanentError
from sto.domain.models import DecisionKind, Receipt

type IdempotencyKey = str


class StaleHeadError(PermanentError):
    """The head the caller expected is not the head now (``expected_head`` / ``expected_sha``).

    Permanent, so it fails closed: nothing retries the same head. Only ``pr.merge`` and
    ``release.trigger`` have a ``stale`` edge (PLAN 859), so D1-07 catches it for those two and
    routes it there. ``move_ref`` and ``merge_base_into`` have none, so it BLOCKS there. On Stop
    (PLAN 14.3: dequeue if possible) the caller catches it from ``dequeue``, and ``RefusedError``
    when the base moved, then polls the merge and reconciles: that merge is already dead.
    """


class UnknownRefError(PermanentError):
    """A ticket, branch, commit, PR, merge or message the service does not know."""


class RefusedError(PermanentError):
    """The target's state forbids the write (closed PR, non-fast-forward, ...)."""


class IdempotencyKeyReuseError(PermanentError):
    """An idempotency key arrived again with different arguments: a key-derivation bug."""


class MalformedWebhookError(PermanentError):
    """A verified delivery whose body cannot be understood."""


# --- shared value types -------------------------------------------------------------------


@dataclass(frozen=True)
class RawWebhook:
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Page[T]:
    items: tuple[T, ...]
    next_cursor: str | None = None


class ChangeKind(StrEnum):
    TICKET = "ticket"
    PR = "pr"
    PUSH = "push"
    CHECK = "check"
    REVIEW = "review"
    MERGE_GROUP = "merge_group"
    INSTALLATION = "installation"  # a GitHub App installation changed (PLAN 10.3)


@dataclass(frozen=True)
class ExternalChange:
    """A nudge that something changed; the adapter re-reads state (PLAN 10.1). Which optional
    fields are set depends on ``kind`` (ticket, PR, push or check event)."""

    kind: ChangeKind
    ticket: TicketRef | None = None
    repo: RepoRef | None = None
    pr: PrRef | None = None
    sha: str | None = None
    branch: str | None = None
    check: str | None = None


@dataclass(frozen=True)
class DecisionRequest:
    """A decision arriving through a notifier; it goes through the same function as the UI."""

    gate_id: str
    kind: DecisionKind
    actor: str
    subject_digest: str | None  # vetoes are exempt from the digest match (PLAN 4), so may omit it
    comment: str = ""

    def __post_init__(self) -> None:
        for name in ("gate_id", "actor", "comment"):
            value = getattr(self, name)
            if not isinstance(value, str) or (name != "comment" and not value):
                raise ValueError(f"decision {name} must be a string")
        digest = self.subject_digest
        if digest is None and not self.kind.is_negative:
            raise ValueError(f"a {self.kind} decision needs a subject_digest")
        if digest is not None and (
            not isinstance(digest, str) or not (digest.strip() or self.kind.is_negative)
        ):
            raise ValueError("decision subject_digest must be a non-blank string")
        if (
            self.kind in (DecisionKind.REJECT, DecisionKind.REQUEST_CHANGES)
            and not self.comment.strip()
        ):
            raise ValueError(f"a {self.kind} decision needs its comment (PLAN T16)")


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
    acceptance_criteria: str = ""
    route_fields: tuple[tuple[str, str], ...] = ()  # (field, value) pairs read for routing
    project: str = ""
    issue_type: str = ""
    editor: str = ""  # who last edited it; a non-member editor pauses the run (T11)

    @property
    def revision(self) -> str:
        """``ticket_revision`` (PLAN 4): the normalised summary, description, acceptance criteria
        and route input fields only, so our own comments and transitions never change it."""

        def norm(text: str) -> str:
            return " ".join(text.split())

        routes = sorted((norm(k), norm(v)) for k, v in self.route_fields)
        canonical = [norm(self.title), norm(self.body), norm(self.acceptance_criteria), routes]
        return hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class TicketSummary:
    ref: TicketRef
    title: str
    status: str


@dataclass(frozen=True)
class IntakeQuery:
    labels: tuple[str, ...] = ()
    status: str | None = None
    project: str | None = None
    issue_types: tuple[str, ...] = ()


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

    @classmethod
    def of(cls, repo: RepoRef, receipt: Receipt) -> PrRef:
        """The route from a PR receipt to a ``PrRef``. A PR receipt's ``external_id`` is the PR
        number (ASCII digits, above zero), never GitHub's global ID."""
        if not re.fullmatch(r"[1-9][0-9]*", receipt.external_id, re.ASCII):
            raise RefusedError(f"{receipt.external_id!r} is not a PR receipt")
        return cls(repo, int(receipt.external_id))


class MergeMethod(StrEnum):
    MERGE = "merge"
    SQUASH = "squash"
    REBASE = "rebase"


@dataclass(frozen=True)
class UpdateResult:
    """Outcome of merging the base into a PR branch: the new head and the head it replaced.

    On a ``conflict`` nothing moved: ``sha`` is the unchanged head and there is no receipt.
    """

    sha: str
    parent_head: str
    receipt: Receipt | None
    conflict: bool = False


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


class MergeReason(StrEnum):
    """Why a merge FAILED, so ``pr.merge`` can choose its ``stale`` or ``conflict`` edge."""

    STALE = "stale"  # the head moved, or the base moved under it
    CONFLICT = "conflict"
    REJECTED = "rejected"  # anything else: checks, protection, ...


@dataclass(frozen=True)
class MergeResult:
    state: MergeState
    merge_sha: str | None = None
    receipt: Receipt | None = None
    reason: MergeReason | None = None  # set when ``state`` is FAILED


@dataclass(frozen=True)
class DispatchSpec:
    workflow: str
    ref: str
    inputs: Mapping[str, str] = field(default_factory=dict)
    expected_head: str | None = (
        None  # the tested SHA: a moved ``ref`` is stale (``release.trigger``)
    )


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
    channel: str = ""  # the channel bound to the team (PLAN 10.5)
    attention: tuple[str, ...] = ()  # the attention list shown on the gate (PLAN 10.5)
    deep_link: str = ""


@dataclass(frozen=True)
class NotifierCapabilities:
    update_in_place: bool = True


# --- ports --------------------------------------------------------------------------------


@runtime_checkable
class TicketSource(Protocol):
    capabilities: TicketCapabilities

    def get(self, ref: TicketRef) -> Ticket: ...
    def search(self, query: IntakeQuery, cursor: str | None) -> Page[TicketSummary]: ...
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
    def open_revert_pr(self, repo: RepoRef, merge_sha: str, key: IdempotencyKey) -> Receipt: ...
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
