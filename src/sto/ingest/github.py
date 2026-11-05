"""GitHub webhooks (D4-04, ADR-0009): the vendor half of the generic ingest in ``core``.

* **Signature.** ``X-Hub-Signature-256`` is ``sha256=`` plus the hex HMAC-SHA256 of the RAW body
  under the webhook secret
  (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries). It is checked
  before anything reads the body, and compared with ``hmac.compare_digest`` so that the time taken
  does not tell an attacker how many leading characters were right. The legacy SHA-1
  ``X-Hub-Signature`` is never accepted. A static test holds every signature comparison under
  ``src/sto/adapters/`` and this file to the same rule.
* **No signed timestamp.** GitHub signs and sends no time, so there is no replay window
  (``signed_timestamp`` False, ``replay_window`` None) and the dedupe record on
  ``X-GitHub-Delivery`` never expires (D4-03). The delivery ID is not covered by the signature, so
  every consumer treats a delivery as a nudge and re-reads GitHub's current state.
* **Order.** Verify, then parse, then claim the delivery, then enqueue. A genuinely signed body that
  cannot be read is refused (``MalformedWebhookError``) before it claims its ID, so GitHub's
  redelivery of a fixed body is not dropped as a duplicate.
* **Events to changes.** ``parse_event`` turns each subscribed event into ``ExternalChange`` values
  that name WHAT changed (repo, PR, SHA, branch, check). It copies no state from the body.
* **Connection state.** ``installation`` and ``installation_repositories`` events also produce a
  ``ConnectionUpdate`` for a ``ConnectionSink``. The sink records that the installation changed and
  must confirm by re-reading the installation: an out-of-order or replayed body is not the truth.
  A sink failure is counted, not fatal, because the queued ``INSTALLATION`` nudge makes the
  consumer re-read anyway.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from sto.adapters.ports import (
    ChangeKind,
    ExternalChange,
    MalformedWebhookError,
    PrRef,
    RawWebhook,
    RepoRef,
    TicketRef,
)
from sto.domain.errors import PermanentError, TransientError
from sto.ingest.core import (
    ACCEPTED,
    DUPLICATE,
    UNAVAILABLE,
    InvalidSignatureError,
    Metrics,
    NudgeQueue,
    WebhookIngest,
    normalise_headers,
)
from sto.store.ports import Store

log = logging.getLogger(__name__)

SURFACE = "github"
SIGNATURE_HEADER = "x-hub-signature-256"
LEGACY_SIGNATURE_HEADER = "x-hub-signature"
DELIVERY_HEADER = "x-github-delivery"
EVENT_HEADER = "x-github-event"
SIGNATURE_PREFIX = "sha256="

# PLAN 10.3: issues, comments, PRs, reviews, pushes, check suites and runs, merge groups,
# installations. ``ping`` is what GitHub sends when a hook is created.
SUBSCRIBED_EVENTS = (
    "ping",
    "issues",
    "issue_comment",
    "pull_request",
    "pull_request_review",
    "push",
    "check_suite",
    "check_run",
    "merge_group",
    "installation",
    "installation_repositories",
)


# --- verifier ---------------------------------------------------------------------------------


class GitHubWebhookVerifier:
    """``WebhookVerifier`` for GitHub (ADR-0009). Never parses the body."""

    signed_timestamp = False
    replay_window: float | None = None
    secret_headers: frozenset[str] = frozenset({SIGNATURE_HEADER, LEGACY_SIGNATURE_HEADER})

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("the webhook secret must be non-empty bytes")
        self._secret = secret

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        try:  # idempotent: ingest already lower-cases, but a caller may hand over raw names
            headers = normalise_headers(headers)
        except PermanentError as exc:
            raise InvalidSignatureError("webhook headers conflict") from exc
        received = headers.get(SIGNATURE_HEADER, "")
        expected = SIGNATURE_PREFIX + hmac.new(self._secret, raw_body, hashlib.sha256).hexdigest()
        # Bytes, so a non-ASCII header is a mismatch rather than a TypeError.
        if not hmac.compare_digest(received.encode("utf-8"), expected.encode("ascii")):
            raise InvalidSignatureError("webhook signature mismatch")
        delivery_id = headers.get(DELIVERY_HEADER, "")
        if not delivery_id:
            raise InvalidSignatureError("webhook has no delivery id")
        return delivery_id


# --- reading a body ---------------------------------------------------------------------------


def ticket_key(repo: RepoRef, number: int) -> str:
    return f"{repo.owner}/{repo.name}#{number}"


def _object(body: bytes) -> dict[str, Any]:
    try:
        loaded = json.loads(body)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        raise MalformedWebhookError("webhook body is not JSON") from exc
    if not isinstance(loaded, dict):
        raise MalformedWebhookError("webhook body is not an object")
    return loaded


def _dict(parent: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise MalformedWebhookError(f"webhook has no object {key!r}")
    return value


def _text(parent: Mapping[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise MalformedWebhookError(f"webhook has no text {key!r}")
    return value


def _number(parent: Mapping[str, Any], key: str) -> int:
    value = parent.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise MalformedWebhookError(f"webhook has no positive number {key!r}")
    return value


def _full_name(value: object) -> RepoRef:
    if not isinstance(value, str):
        raise MalformedWebhookError("webhook repository has no full_name")
    owner, _, name = value.partition("/")
    if not owner or not name or "/" in name:
        raise MalformedWebhookError("webhook repository full_name is not owner/name")
    return RepoRef(owner, name)


def _repo(payload: Mapping[str, Any]) -> RepoRef:
    return _full_name(_dict(payload, "repository").get("full_name"))


def _branch(ref: str) -> str:
    return ref.removeprefix("refs/heads/")


def _pr_numbers(parent: Mapping[str, Any]) -> list[int]:
    listed = parent.get("pull_requests", [])
    if not isinstance(listed, list):
        raise MalformedWebhookError("webhook pull_requests is not a list")
    return [_number(pr, "number") for pr in listed if isinstance(pr, dict)]


def _check_changes(
    repo: RepoRef, parent: Mapping[str, Any], sha: str, branch: str | None, check: str | None
) -> list[ExternalChange]:
    numbers = _pr_numbers(parent)
    if not numbers:
        return [ExternalChange(ChangeKind.CHECK, repo=repo, sha=sha, branch=branch, check=check)]
    return [
        ExternalChange(
            ChangeKind.CHECK, repo=repo, pr=PrRef(repo, n), sha=sha, branch=branch, check=check
        )
        for n in numbers
    ]


def _issue(payload: dict[str, Any]) -> list[ExternalChange]:
    repo = _repo(payload)
    issue = _dict(payload, "issue")
    number = _number(issue, "number")
    if "pull_request" in issue:  # a comment on a PR is a PR event in the issues API
        return [ExternalChange(ChangeKind.PR, repo=repo, pr=PrRef(repo, number))]
    return [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("github", ticket_key(repo, number)))]


def _pull_request(payload: dict[str, Any]) -> list[ExternalChange]:
    repo = _repo(payload)
    pr = _dict(payload, "pull_request")
    head = _dict(pr, "head")
    return [
        ExternalChange(
            ChangeKind.PR,
            repo=repo,
            pr=PrRef(repo, _number(pr, "number")),
            sha=_text(head, "sha"),
            branch=_text(head, "ref"),
        )
    ]


def _review(payload: dict[str, Any]) -> list[ExternalChange]:
    repo = _repo(payload)
    pr = _dict(payload, "pull_request")
    return [
        ExternalChange(
            ChangeKind.REVIEW,
            repo=repo,
            pr=PrRef(repo, _number(pr, "number")),
            sha=_text(_dict(payload, "review"), "commit_id"),
            branch=_text(_dict(pr, "head"), "ref"),
        )
    ]


def _push(payload: dict[str, Any]) -> list[ExternalChange]:
    repo = _repo(payload)
    ref = _text(payload, "ref")
    if not ref.startswith("refs/heads/"):
        return []  # a tag push names no branch we track
    return [
        ExternalChange(ChangeKind.PUSH, repo=repo, sha=_text(payload, "after"), branch=_branch(ref))
    ]


def _check_suite(payload: dict[str, Any]) -> list[ExternalChange]:
    suite = _dict(payload, "check_suite")
    branch = suite.get("head_branch")
    return _check_changes(
        _repo(payload),
        suite,
        _text(suite, "head_sha"),
        branch if isinstance(branch, str) else None,
        None,
    )


def _check_run(payload: dict[str, Any]) -> list[ExternalChange]:
    run = _dict(payload, "check_run")
    suite = run.get("check_suite")
    branch = suite.get("head_branch") if isinstance(suite, dict) else None
    return _check_changes(
        _repo(payload),
        run,
        _text(run, "head_sha"),
        branch if isinstance(branch, str) else None,
        _text(run, "name"),
    )


def _merge_group(payload: dict[str, Any]) -> list[ExternalChange]:
    group = _dict(payload, "merge_group")
    return [
        ExternalChange(
            ChangeKind.MERGE_GROUP,
            repo=_repo(payload),
            sha=_text(group, "head_sha"),
            branch=_branch(_text(group, "head_ref")),
        )
    ]


def _installation(payload: dict[str, Any]) -> list[ExternalChange]:
    _number(_dict(payload, "installation"), "id")
    return [ExternalChange(ChangeKind.INSTALLATION)]


def _ping(payload: dict[str, Any]) -> list[ExternalChange]:
    return []


_PARSERS: Mapping[str, Callable[[dict[str, Any]], list[ExternalChange]]] = {
    "ping": _ping,
    "issues": _issue,
    "issue_comment": _issue,
    "pull_request": _pull_request,
    "pull_request_review": _review,
    "push": _push,
    "check_suite": _check_suite,
    "check_run": _check_run,
    "merge_group": _merge_group,
    "installation": _installation,
    "installation_repositories": _installation,
}
assert set(_PARSERS) == set(SUBSCRIBED_EVENTS)


def parse_event(event: str, body: bytes) -> list[ExternalChange]:
    """The changes a delivery nudges about. An event we do not subscribe to gives none. A body
    that is not what GitHub documents for its event raises ``MalformedWebhookError``."""
    payload = _object(body)
    parser = _PARSERS.get(event)
    return parser(payload) if parser else []


# --- connection state -------------------------------------------------------------------------


class ConnectionStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REMOVED = "removed"
    PERMISSIONS_CHANGED = "permissions_changed"
    REPOSITORIES_CHANGED = "repositories_changed"


_INSTALLATION_ACTIONS = {
    "created": ConnectionStatus.ACTIVE,
    "unsuspend": ConnectionStatus.ACTIVE,
    "suspend": ConnectionStatus.SUSPENDED,
    "deleted": ConnectionStatus.REMOVED,
    "new_permissions_accepted": ConnectionStatus.PERMISSIONS_CHANGED,
}


@dataclass(frozen=True)
class ConnectionUpdate:
    """That an installation changed, as a delivery says it. A hint to re-read, not the truth."""

    installation_id: int
    event: str
    action: str
    status: ConnectionStatus
    repositories_added: tuple[RepoRef, ...] = ()
    repositories_removed: tuple[RepoRef, ...] = ()


class ConnectionSink(Protocol):
    def apply(self, update: ConnectionUpdate) -> None:
        """Record the change and schedule a re-read of the installation. Idempotent."""
        ...


def _repos(payload: Mapping[str, Any], key: str) -> tuple[RepoRef, ...]:
    listed = payload.get(key, [])
    if not isinstance(listed, list):
        raise MalformedWebhookError(f"webhook {key!r} is not a list")
    return tuple(
        _full_name(r.get("full_name")) for r in listed if isinstance(r, dict) and "full_name" in r
    )


def parse_connection_update(event: str, body: bytes) -> ConnectionUpdate | None:
    """The connection-state side of an installation or permission event, else None."""
    if event not in ("installation", "installation_repositories"):
        return None
    payload = _object(body)
    action = payload.get("action")
    if not isinstance(action, str):
        raise MalformedWebhookError("webhook has no action")
    if event == "installation":
        status = _INSTALLATION_ACTIONS.get(action)
        added = () if action == "deleted" else _repos(payload, "repositories")
        removed: tuple[RepoRef, ...] = ()
    else:
        status = ConnectionStatus.REPOSITORIES_CHANGED if action in ("added", "removed") else None
        added, removed = (
            _repos(payload, "repositories_added"),
            _repos(payload, "repositories_removed"),
        )
    if status is None:
        return None
    return ConnectionUpdate(
        _number(_dict(payload, "installation"), "id"), event, action, status, added, removed
    )


# --- the receiver -----------------------------------------------------------------------------


class GitHubWebhooks:
    """Verify, parse, dedupe and enqueue one GitHub delivery. Implements no port: it only receives,
    so it exposes no write method (the conformance suite checks that)."""

    def __init__(
        self,
        secret: bytes,
        store: Store,
        queue: NudgeQueue,
        metrics: Metrics,
        *,
        connections: ConnectionSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.verifier = GitHubWebhookVerifier(secret)
        self._ingest = WebhookIngest(SURFACE, self.verifier, store, queue, metrics, clock=clock)
        self._metrics = metrics
        self._connections = connections

    def receive(self, raw: RawWebhook) -> list[ExternalChange] | None:
        """The changes a new delivery nudges about, or None for a duplicate.

        Raises ``InvalidSignatureError`` (forged, unsigned, no ID), ``MalformedWebhookError`` (a
        genuine body we cannot read; its ID stays unclaimed) or ``TransientError`` (store or queue
        down: GitHub should redeliver, and the ID is not left claimed)."""
        try:
            headers = normalise_headers(raw.headers)
            self.verifier.verify(headers, raw.body)
        except PermanentError as exc:
            self._metrics.incr("webhook.rejected", surface=SURFACE, reason="signature")
            raise InvalidSignatureError("webhook rejected") from exc
        event = headers.get(EVENT_HEADER, "")
        if not event:
            raise MalformedWebhookError("webhook has no event header")
        changes = parse_event(event, raw.body)
        update = parse_connection_update(event, raw.body)
        response = self._ingest.handle(raw.headers, raw.body)
        if response.status == DUPLICATE:
            return None
        if response.status == UNAVAILABLE:
            raise TransientError("webhook could not be queued")
        if response.status != ACCEPTED:
            raise InvalidSignatureError(response.body)
        if update is not None and self._connections is not None:
            self._apply(update)
        return changes

    def _apply(self, update: ConnectionUpdate) -> None:
        assert self._connections is not None
        try:
            self._connections.apply(update)
        except Exception:
            log.exception("connection state update failed", extra={"surface": SURFACE})
            self._metrics.incr("webhook.connection_failed", surface=SURFACE)
