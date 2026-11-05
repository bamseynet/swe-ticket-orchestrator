"""D4-04: GitHub webhooks. Verify ``X-Hub-Signature-256`` on the raw body in constant time,
dedupe by ``X-GitHub-Delivery``, parse each subscribed event to ``ExternalChange``, and track
installations.

Every secret, ID, SHA and payload here is synthetic. The conformance target is the real class
``sto.ingest.github.GitHubWebhooks`` aimed at the D4-16 fake GitHub sender, which signs but never
verifies; the signature and duplicate sections run with ``signed_timestamp=False``.
"""

from __future__ import annotations

import ast
import json
import re
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

from contract.suite import (
    CAPABILITIES,
    AdapterConformance,
    Control,
    ForgeKind,
    Outcome,
    Port,
    Target,
    Vendor,
    run_suite,
)
from fakes.github.webhooks import FakeWebhooks
from fakes.github.webhooks.sender import SECRET
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
from sto.ingest.core import InvalidSignatureError, Nudge, WebhookVerifier
from sto.ingest.github import (
    SUBSCRIBED_EVENTS,
    ConnectionSink,
    ConnectionStatus,
    ConnectionUpdate,
    GitHubWebhooks,
    GitHubWebhookVerifier,
    StoreConnectionSink,
    parse_connection_update,
    parse_event,
    ticket_key,
)
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, ConditionFailedError, Key

pytestmark = pytest.mark.contract

REPO = RepoRef("acme", "app")
SHA = "a" * 40
SHA2 = "b" * 40
REPO_JSON = {"full_name": "acme/app", "name": "app", "owner": {"login": "acme"}}


# --- helpers ----------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class Metrics:
    def __init__(self) -> None:
        self.counts: list[tuple[str, dict[str, str]]] = []

    def incr(self, name: str, **tags: str) -> None:
        self.counts.append((name, tags))

    def names(self) -> list[str]:
        return [n for n, _ in self.counts]


class Queue:
    def __init__(self) -> None:
        self.items: list[Nudge] = []
        self.fail = False

    def enqueue(self, nudge: Nudge) -> None:
        if self.fail:
            raise RuntimeError("queue down")
        self.items.append(nudge)


class Connections:
    def __init__(self) -> None:
        self.updates: list[ConnectionUpdate] = []
        self.fail = False

    def apply(self, update: ConnectionUpdate) -> None:
        if self.fail:
            raise RuntimeError("store down")
        self.updates.append(update)


def gid(name: str) -> str:
    """A GUID, as GitHub sends in ``X-GitHub-Delivery``; stable for a name."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


def make_receiver(
    clock: Clock | None = None,
    store: MemoryStore | None = None,
    queue: Queue | None = None,
    metrics: Metrics | None = None,
    connections: ConnectionSink | None = None,
) -> GitHubWebhooks:
    return GitHubWebhooks(
        SECRET,
        store if store is not None else MemoryStore(),
        queue if queue is not None else Queue(),
        metrics if metrics is not None else Metrics(),
        connections if connections is not None else Connections(),
        clock=clock or Clock(),
    )


def sender(body: Callable[[int, str], bytes] | None = None) -> FakeWebhooks:
    clock = Clock()
    return FakeWebhooks(clock, body=body) if body else FakeWebhooks(clock)


def send(event: str, payload: Mapping[str, Any], delivery: str = gid("g-1")) -> RawWebhook:
    return sender().delivery(1, delivery, event=event, body=json.dumps(payload).encode())


# --- fixtures: one per subscribed event type --------------------------------------------------

PR_JSON = {
    "number": 7,
    "state": "open",
    "head": {"sha": SHA, "ref": "sto/run-1", "repo": {"full_name": "acme/app"}},
    "base": {"ref": "main"},
}

FIXTURES: dict[str, dict[str, Any]] = {
    "ping": {"zen": "synthetic", "hook_id": 300003},
    "issues": {
        "action": "labeled",
        "issue": {"number": 12, "title": "synthetic", "labels": [{"name": "sto"}]},
        "repository": REPO_JSON,
        "sender": {"login": "alice"},
    },
    "issue_comment": {
        "action": "created",
        "issue": {"number": 12, "title": "synthetic"},
        "comment": {"id": 901, "body": "/sto run", "user": {"login": "alice"}},
        "repository": REPO_JSON,
    },
    "pull_request": {
        "action": "synchronize",
        "number": 7,
        "pull_request": PR_JSON,
        "repository": REPO_JSON,
    },
    "pull_request_review": {
        "action": "submitted",
        "review": {"id": 55, "state": "approved", "commit_id": SHA2},
        "pull_request": PR_JSON,
        "repository": REPO_JSON,
    },
    "push": {
        "ref": "refs/heads/sto/run-1",
        "before": "0" * 40,
        "after": SHA,
        "repository": REPO_JSON,
    },
    "check_suite": {
        "action": "completed",
        "check_suite": {
            "head_sha": SHA,
            "head_branch": "sto/run-1",
            "pull_requests": [{"number": 7}, {"number": 8}],
        },
        "repository": REPO_JSON,
    },
    "check_run": {
        "action": "completed",
        "check_run": {
            "name": "ci/unit",
            "head_sha": SHA,
            "check_suite": {"head_branch": "sto/run-1"},
            "pull_requests": [],
        },
        "repository": REPO_JSON,
    },
    "merge_group": {
        "action": "checks_requested",
        "merge_group": {"head_sha": SHA, "head_ref": "refs/heads/gh-readonly-queue/main/pr-7-x"},
        "repository": REPO_JSON,
    },
    "installation": {
        "action": "created",
        "installation": {"id": 200002, "permissions": {"contents": "write"}},
        "repositories": [{"full_name": "acme/app"}],
    },
    "installation_repositories": {
        "action": "added",
        "installation": {"id": 200002},
        "repositories_added": [{"full_name": "acme/app"}],
        "repositories_removed": [{"full_name": "acme/old"}],
    },
}

EXPECTED: dict[str, list[ExternalChange]] = {
    "ping": [],
    "issues": [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("github", "acme/app#12"))],
    "issue_comment": [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("github", "acme/app#12"))],
    "pull_request": [
        ExternalChange(ChangeKind.PR, repo=REPO, pr=PrRef(REPO, 7), sha=SHA, branch="sto/run-1")
    ],
    "pull_request_review": [
        ExternalChange(
            ChangeKind.REVIEW, repo=REPO, pr=PrRef(REPO, 7), sha=SHA2, branch="sto/run-1"
        )
    ],
    "push": [ExternalChange(ChangeKind.PUSH, repo=REPO, sha=SHA, branch="sto/run-1")],
    "check_suite": [
        ExternalChange(ChangeKind.CHECK, repo=REPO, pr=PrRef(REPO, 7), sha=SHA, branch="sto/run-1"),
        ExternalChange(ChangeKind.CHECK, repo=REPO, pr=PrRef(REPO, 8), sha=SHA, branch="sto/run-1"),
    ],
    "check_run": [
        ExternalChange(ChangeKind.CHECK, repo=REPO, sha=SHA, branch="sto/run-1", check="ci/unit")
    ],
    "merge_group": [
        ExternalChange(
            ChangeKind.MERGE_GROUP,
            repo=REPO,
            sha=SHA,
            branch="gh-readonly-queue/main/pr-7-x",
        )
    ],
    "installation": [ExternalChange(ChangeKind.INSTALLATION, installation_id=200002)],
    "installation_repositories": [ExternalChange(ChangeKind.INSTALLATION, installation_id=200002)],
}


def test_each_subscribed_event_type_has_a_fixture_and_an_expectation() -> None:
    assert set(SUBSCRIBED_EVENTS) == set(FIXTURES) == set(EXPECTED)
    # PLAN 10.3: issues, comments, PRs, reviews, pushes, check suites and runs, merge groups,
    # installations.
    assert {
        "issues",
        "issue_comment",
        "pull_request",
        "pull_request_review",
        "push",
        "check_suite",
        "check_run",
        "merge_group",
        "installation",
    } <= set(SUBSCRIBED_EVENTS)


@pytest.mark.parametrize("event", sorted(FIXTURES))
def test_each_fixture_parses_to_its_external_changes(event: str) -> None:
    assert parse_event(event, json.dumps(FIXTURES[event]).encode()) == EXPECTED[event]


@pytest.mark.parametrize("event", sorted(FIXTURES))
def test_each_fixture_is_accepted_end_to_end_and_queued_as_a_nudge(event: str) -> None:
    queue = Queue()
    receiver = make_receiver(queue=queue)
    raw = send(event, FIXTURES[event], gid(f"g-{event}"))
    assert receiver.receive(raw) == EXPECTED[event]
    [nudge] = queue.items
    assert nudge.delivery_id == gid(f"g-{event}")
    assert nudge.body == raw.body
    assert nudge.reread is True
    assert nudge.headers["x-github-event"] == event
    assert "x-hub-signature-256" not in nudge.headers


def test_a_pull_request_comment_is_a_pr_change_not_a_ticket() -> None:
    payload = json.loads(json.dumps(FIXTURES["issue_comment"]))
    payload["issue"]["pull_request"] = {"url": "https://example.invalid/pr/12"}
    [change] = parse_event("issue_comment", json.dumps(payload).encode())
    assert change.kind is ChangeKind.PR
    assert change.pr == PrRef(REPO, 12)


def test_a_tag_push_names_no_branch_and_is_ignored() -> None:
    body = b'{"ref": "refs/tags/v1", "after": "x", "repository": {"full_name": "a/b"}}'
    assert parse_event("push", body) == []


def test_an_unsubscribed_event_is_ignored_not_an_error() -> None:
    assert parse_event("star", b'{"action": "created"}') == []


@pytest.mark.parametrize(
    ("event", "body"),
    [
        ("issues", b"{not json"),
        ("issues", b"[]"),
        ("issues", b'{"issue": {}, "repository": {"full_name": "acme/app"}}'),
        ("issues", b'{"issue": {"number": "x"}, "repository": {"full_name": "acme/app"}}'),
        ("issues", b'{"issue": {"number": 1}, "repository": {"full_name": "no-slash"}}'),
        ("issues", b'{"issue": {"number": true}, "repository": {"full_name": "acme/app"}}'),
        ("push", b'{"ref": "refs/heads/x", "repository": {"full_name": "a/b"}}'),
        ("pull_request", b'{"pull_request": {"number": 1}, "repository": {"full_name": "a/b"}}'),
        ("issues", '{"issue": {"number": 1}, "repository": "é"}'.encode("latin-1")),
        ("issues", b"\xff\xfe"),
    ],
)
def test_a_verified_body_that_cannot_be_read_is_malformed(event: str, body: bytes) -> None:
    with pytest.raises(MalformedWebhookError):
        parse_event(event, body)


def test_ticket_key_is_owner_name_hash_number() -> None:
    assert ticket_key(REPO, 12) == "acme/app#12"


# --- connection state -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "status"),
    [
        ("created", ConnectionStatus.ACTIVE),
        ("unsuspend", ConnectionStatus.ACTIVE),
        ("suspend", ConnectionStatus.SUSPENDED),
        ("deleted", ConnectionStatus.REMOVED),
        ("new_permissions_accepted", ConnectionStatus.PERMISSIONS_CHANGED),
    ],
)
def test_installation_actions_map_to_a_connection_status(
    action: str, status: ConnectionStatus
) -> None:
    payload = {**FIXTURES["installation"], "action": action}
    update = parse_connection_update("installation", json.dumps(payload).encode())
    assert update is not None
    assert update.installation_id == 200002
    assert update.status is status
    assert update.event == "installation"


def test_repositories_added_and_removed_are_carried() -> None:
    update = parse_connection_update(
        "installation_repositories", json.dumps(FIXTURES["installation_repositories"]).encode()
    )
    assert update is not None
    assert update.status is ConnectionStatus.REPOSITORIES_CHANGED
    assert update.repositories_added == (REPO,)
    assert update.repositories_removed == (RepoRef("acme", "old"),)


def test_other_events_carry_no_connection_update() -> None:
    assert parse_connection_update("push", json.dumps(FIXTURES["push"]).encode()) is None


def test_an_unknown_installation_action_is_ignored_for_state() -> None:
    payload = {**FIXTURES["installation"], "action": "something_new"}
    assert parse_connection_update("installation", json.dumps(payload).encode()) is None


def test_an_accepted_installation_event_updates_connection_state_once() -> None:
    connections = Connections()
    receiver = make_receiver(connections=connections)
    raw = send("installation", {**FIXTURES["installation"], "action": "suspend"}, gid("g-i"))
    receiver.receive(raw)
    receiver.receive(raw)  # a redelivery
    assert [u.status for u in connections.updates] == [ConnectionStatus.SUSPENDED]


def test_a_rejected_or_malformed_delivery_never_touches_connection_state() -> None:
    connections = Connections()
    receiver = make_receiver(connections=connections)
    forged = sender().forge(1, gid("g-1"), ForgeKind.WRONG_SECRET, event="installation")
    with pytest.raises(InvalidSignatureError):
        receiver.receive(forged)
    bad = sender().delivery(1, gid("g-2"), event="installation", body=b"{nope")
    with pytest.raises(MalformedWebhookError):
        receiver.receive(bad)
    assert connections.updates == []


def test_a_connection_sink_failure_still_queues_the_nudge_and_is_counted() -> None:
    connections, queue, metrics = Connections(), Queue(), Metrics()
    connections.fail = True
    receiver = make_receiver(connections=connections, queue=queue, metrics=metrics)
    assert receiver.receive(send("installation", FIXTURES["installation"], gid("g-i"))) is not None
    assert len(queue.items) == 1  # the queued nudge makes the consumer re-read the installation
    assert "webhook.connection_failed" in metrics.names()


# --- the receiver -----------------------------------------------------------------------------


def test_the_verifier_agrees_with_the_conformance_capabilities_for_github() -> None:
    verifier = GitHubWebhookVerifier(SECRET)
    caps = CAPABILITIES[Vendor.GITHUB]
    assert verifier.signed_timestamp is caps.signed_timestamp is False
    assert verifier.replay_window is None
    assert isinstance(verifier, WebhookVerifier)
    assert {"x-hub-signature-256", "x-hub-signature"} <= verifier.secret_headers


def test_an_empty_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        GitHubWebhookVerifier(b"")


def test_a_genuine_delivery_returns_its_delivery_id() -> None:
    raw = sender().delivery(1, gid("g-1"))
    headers = {k.lower(): v for k, v in raw.headers.items()}
    assert GitHubWebhookVerifier(SECRET).verify(headers, raw.body) == gid("g-1")


@pytest.mark.parametrize("how", list(ForgeKind))
def test_every_forgery_is_rejected_by_the_verifier(how: ForgeKind) -> None:
    raw = sender().forge(1, gid("g-1"), how)
    headers = {k.lower(): v for k, v in raw.headers.items()}
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_the_sha1_header_alone_is_not_accepted() -> None:
    raw = sender().delivery(1, gid("g-1"))
    headers = {k.lower(): v for k, v in raw.headers.items()}
    headers["x-hub-signature"] = headers.pop("x-hub-signature-256").replace("sha256=", "sha1=")
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_a_non_ascii_signature_is_rejected_not_a_crash() -> None:
    raw = sender().delivery(1, gid("g-1"))
    headers = {k.lower(): v for k, v in raw.headers.items()}
    headers["x-hub-signature-256"] = "sha256=é" + "0" * 63
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_the_signature_is_checked_before_the_body_is_read() -> None:
    """Not-JSON under a wrong signature is a signature failure, never a parse one."""
    forged = sender().forge(1, gid("g-1"))
    garbage = RawWebhook(forged.headers, b"{not json")
    with pytest.raises(InvalidSignatureError):
        make_receiver().receive(garbage)


def test_tampered_and_reserialised_bodies_are_rejected_and_queue_nothing() -> None:
    queue = Queue()
    receiver = make_receiver(queue=queue)
    hooks = sender()
    genuine = hooks.delivery(1, gid("g-1"))
    for changed in (hooks.tamper(genuine), hooks.reserialise(genuine)):
        assert changed.body != genuine.body
        with pytest.raises(InvalidSignatureError):
            receiver.receive(changed)
    assert queue.items == []
    assert receiver.receive(genuine) is not None  # neither burned the delivery ID


def test_a_duplicate_is_dropped_forever_even_after_a_restart() -> None:
    clock, store, queue = Clock(), MemoryStore(), Queue()
    raw = sender().delivery(1, gid("g-1"))
    assert make_receiver(clock, store, queue).receive(raw) is not None
    clock.now += 10.0**10
    fresh = make_receiver(clock, store, queue)
    assert fresh.receive(raw) is None
    assert len(queue.items) == 1


def test_a_failed_enqueue_releases_the_delivery_so_the_retry_is_not_dropped() -> None:
    queue, metrics = Queue(), Metrics()
    receiver = make_receiver(queue=queue, metrics=metrics)
    raw = sender().delivery(1, gid("g-1"))
    queue.fail = True
    with pytest.raises(TransientError):
        receiver.receive(raw)
    queue.fail = False
    assert receiver.receive(raw) is not None
    assert len(queue.items) == 1


def test_a_bad_signature_is_counted() -> None:
    metrics = Metrics()
    receiver = make_receiver(metrics=metrics)
    with pytest.raises(InvalidSignatureError):
        receiver.receive(sender().forge(1, gid("g-1")))
    assert ("webhook.rejected", {"surface": "github", "reason": "signature"}) in metrics.counts


def test_a_missing_event_header_on_a_genuine_delivery_is_malformed() -> None:
    raw = sender().delivery(1, gid("g-1"))
    headers = {k: v for k, v in raw.headers.items() if k.lower() != "x-github-event"}
    with pytest.raises(MalformedWebhookError):
        make_receiver().receive(RawWebhook(headers, raw.body))


def test_the_receiver_exposes_no_port_write_method() -> None:
    from contract.suite import PORT_WRITE_METHODS

    assert not [n for n in PORT_WRITE_METHODS if hasattr(GitHubWebhooks, n)]


# --- conformance: the real class against the fake sender --------------------------------------

WATCHED = ticket_key(REPO, 1)


def _issue_body(revision: int, delivery_id: str) -> bytes:
    return json.dumps(
        {
            "action": "edited",
            "issue": {"number": 1, "title": "synthetic", "revision": revision},
            "repository": REPO_JSON,
            "sender": {"login": "alice"},
        }
    ).encode()


def _guid_id(raw: RawWebhook) -> RawWebhook:
    """The suite names deliveries "d-1"; GitHub sends GUIDs. The ID header is not signed, so this
    rewrites it to a stable GUID per name and touches nothing the signature covers."""
    headers = dict(raw.headers)
    for name, value in raw.headers.items():
        if name.lower() == "x-github-delivery" and value:
            headers[name] = gid(value)
    return RawWebhook(headers, raw.body)


class GitHubWebhookTarget(Target):
    """Thin pass-through: the sender is the fake's; the verifier, dedupe and parsing are ours."""

    name = "github-webhooks"
    vendor = Vendor.GITHUB
    signature_header = "X-Hub-Signature-256"
    watched = WATCHED
    controls = frozenset(
        {Control.SIGNATURE, Control.UNSIGNED, Control.DUPLICATE, Control.REPLAY_WINDOW}
        | {Control.RESTART}
    )

    def __init__(self) -> None:
        self.clock_ = Clock()
        self.hooks = FakeWebhooks(self.clock_, body=_issue_body)
        self.store = MemoryStore()  # durable: survives restart()
        self.queue = Queue()
        self.adapter = self._fresh()
        self.verifier = self.adapter.verifier

    def _fresh(self) -> GitHubWebhooks:
        return GitHubWebhooks(
            SECRET,
            self.store,
            self.queue,
            Metrics(),
            StoreConnectionSink(self.store, self.clock_),
            clock=self.clock_,
        )

    def restart(self) -> None:
        self.adapter = self._fresh()
        self.verifier = self.adapter.verifier

    def deliver(self, raw: RawWebhook) -> Outcome:
        changes = self.adapter.receive(_guid_id(raw))  # type: ignore[attr-defined]
        if changes is None:
            return Outcome(False)
        return Outcome(True, tuple(c.ticket.key for c in changes if c.ticket))

    def queued(self) -> int:
        return len(self.queue.items)

    def clock(self) -> float:
        return self.clock_.now

    def advance_clock(self, seconds: float) -> None:
        self.clock_.now += seconds

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        return self.hooks.delivery(revision, delivery_id)

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        return self.hooks.forge(revision, delivery_id, how)

    def emit_without_id(self, revision: int) -> RawWebhook:
        return self.hooks.without_id(revision)

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        return self.hooks.malformed(delivery_id)

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        return self.hooks.delivery(revision, delivery_id)  # GitHub signs and sends no time

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        headers = {k: v for k, v in raw.headers.items() if k != "X-Timestamp"}
        if value is not None:
            headers["X-Timestamp"] = value  # GitHub sends none: a forger may add one
        return RawWebhook(headers, raw.body)

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        return self.hooks.tamper(raw)

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        return self.hooks.reserialise(raw)


def github_webhooks() -> Target:
    return GitHubWebhookTarget()


class TestGitHubWebhooksConformance(AdapterConformance):
    """Signature, duplicate, replay-window and restart tests, with ``signed_timestamp=False``."""

    port = Port.WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": github_webhooks}


def test_every_test_the_webhook_port_requires_passes() -> None:
    failed = {n: e for n, e in run_suite(github_webhooks, Port.WEBHOOK).items() if e is not None}
    assert failed == {}


def test_the_conformance_target_is_defined_in_sto_ingest_github() -> None:
    target = GitHubWebhookTarget()
    assert type(target.adapter).__module__ == "sto.ingest.github"
    assert not CAPABILITIES[target.vendor].signed_timestamp
    assert target.verifier.signed_timestamp is False  # type: ignore[attr-defined]


# --- static check: constant-time signature comparison -----------------------------------------

ROOT = Path(__file__).resolve().parents[2]
ADAPTERS = ROOT / "src" / "sto" / "adapters"
SIGNATURE_WORDS = re.compile(r"(sig|signature|mac|hmac|digest|token_hash)", re.IGNORECASE)


def _names(node: ast.AST) -> list[str]:
    """Every identifier, attribute and string key that the expression mentions."""
    out: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.append(sub.id)
        elif isinstance(sub, ast.Attribute):
            out.append(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
    return out


CRYPTO_MODULES = {"hmac", "hashlib"}
CRYPTO_METHODS = {"digest", "hexdigest"}
COMPARING_CALLS = {"startswith", "endswith", "eq", "ne", "contains", "lt", "gt", "le", "ge"}


def _is_crypto_call(node: ast.AST) -> bool:
    """A call that makes or reads a MAC or hash: ``hmac.new``, ``hashlib.*``, ``.digest()``,
    ``.hexdigest()``. ``hmac.compare_digest`` is the safe comparison, so it is not one."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    func = node.func
    if func.attr == "compare_digest":
        return False
    base = func.value
    return func.attr in CRYPTO_METHODS or (isinstance(base, ast.Name) and base.id in CRYPTO_MODULES)


def _constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    return isinstance(node, (ast.Tuple, ast.List, ast.Set)) and all(
        isinstance(e, ast.Constant) for e in node.elts
    )


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """Nodes of ``scope``; for a module, those outside every function."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    module = isinstance(scope, ast.Module)
    while stack:
        node = stack.pop()
        if module and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _compare_lines(nodes: list[ast.AST], crypto: bool) -> set[int]:
    lines: set[int] = set()
    for node in nodes:
        mentions = False
        if isinstance(node, ast.Compare):
            if not any(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
                continue
            operands = [node.left, *node.comparators]
            if any(isinstance(o, ast.Constant) and o.value is None for o in operands):
                continue
            if any(
                isinstance(o, ast.Call) and getattr(o.func, "id", "") == "len" for o in operands
            ):
                continue
            if any(_constant(o) for o in operands):
                continue  # against a literal: no secret on the other side is being matched
            mentions = any(SIGNATURE_WORDS.search(n) for o in operands for n in _names(o))
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in COMPARING_CALLS:
                continue
            mentions = any(SIGNATURE_WORDS.search(n) for n in _names(node))
        elif isinstance(node, ast.Match):
            mentions = any(SIGNATURE_WORDS.search(n) for n in _names(node.subject))
        else:
            continue
        if crypto or mentions:
            lines.add(node.lineno)
    return lines


def variable_time_signature_comparisons(source: str) -> list[int]:
    """Lines that compare a secret-derived value in variable time.

    Two rules. By NAME, anywhere: ``==``, ``!=``, ``in``, ``startswith``/``endswith``,
    ``operator.eq`` or ``match`` on something called sig, signature, mac, hmac or digest. By TAINT:
    inside any function (or the module body) that calls ``hmac.new``, ``hashlib.*``,
    ``.digest()`` or ``.hexdigest()``, every one of those, whatever the names, so renaming
    the variable to ``received`` or ``mine`` does not hide it. Only ``hmac.compare_digest`` (a call
    that is not in that list) is exempt, and so are comparisons with ``None``, a literal or
    ``len(...)``."""
    tree = ast.parse(source)
    lines: set[int] = set()
    scopes: list[ast.AST] = [tree]
    scopes += [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        nodes = _own_nodes(scope)
        nodes_all = nodes if isinstance(scope, ast.Module) else [*nodes, *ast.walk(scope)]
        crypto = any(
            _is_crypto_call(n) for n in (nodes if isinstance(scope, ast.Module) else nodes_all)
        )
        lines |= _compare_lines(nodes_all, crypto)
    return sorted(lines)


def signature_files() -> list[Path]:
    files = sorted(ADAPTERS.rglob("*.py"))
    files.append(ROOT / "src" / "sto" / "ingest" / "github.py")
    return files


FLAGGED = {
    "received != expected": (
        "def verify(received, body):\n"
        "    expected = hmac.new(k, body, hashlib.sha256).hexdigest()\n"
        "    if received.encode() != expected.encode():\n"
        "        raise ValueError\n"
    ),
    "jira-style": (
        "def check(header_value, h):\n"
        "    computed = base64.b64encode(h.digest()).decode()\n"
        "    if header_value != computed: pass\n"
    ),
    "slack-style v0": (
        "def check(headers, h):\n"
        '    mine = "v0=" + h.hexdigest()\n'
        '    if mine != headers["x-slack-signature"]: pass\n'
    ),
    "slack-style local names": (
        "def check(headers, h):\n"
        '    mine = "v0=" + h.hexdigest()\n'
        '    got = headers.get("x-slack-signature")\n'
        "    if mine != got: pass\n"
    ),
    "in a tuple": ("def check(got, h):\n    ok = got in (h.digest(), h.hexdigest())\n"),
    "startswith on the computed value": (
        "def check(got, h):\n    ok = h.hexdigest().startswith(got)\n"
    ),
    "endswith": "def check(got, h):\n    ok = got.endswith(h.hexdigest())\n",
    "operator.eq": "import operator\nok = operator.eq(signature, expected)\n",
    "operator.eq in a hashing function": (
        "def check(got, h):\n    return operator.eq(got, h.digest())\n"
    ),
    "match": "match signature:\n    case 'abc': pass\n",
    "match in a hashing function": (
        "def check(got, h):\n    want = h.digest()\n    match got:\n        case _: pass\n"
    ),
    "name rule, startswith": "ok = expected.startswith(signature)\n",
    "nested function": (
        "def outer(h):\n"
        "    want = h.digest()\n"
        "    def inner(got):\n"
        "        return got == want\n"
        "    return inner\n"
    ),
    "module level": "want = hmac.new(k, b, h).digest()\nok = got == want\n",
    "equals": "ok = signature == expected",
    "header subscript": "ok = expected != headers['x-hub-signature-256']",
    "mac in": "ok = computed_mac in (a, b)",
    "hexdigest equals": "ok = hmac.new(k, b, h).hexdigest() == got",
    "digest attribute": "ok = got.digest == want",
    "sig attribute": "if self.sig_header == value: pass",
}

FINE = {
    "compare_digest": (
        "def verify(received, body):\n"
        "    expected = hmac.new(k, body, hashlib.sha256).hexdigest()\n"
        "    if not hmac.compare_digest(received.encode(), expected.encode()):\n"
        "        raise ValueError\n"
    ),
    "is None": "ok = signature is None",
    "!= None": "ok = signature != None",
    "length": "ok = len(signature) == 71",
    "status code": "ok = status == 401",
    "kind": "ok = kind == 'push'",
    "literal in a hashing function": (
        "def f(h):\n    d = h.hexdigest()\n    if mode == 'x': pass\n    return d\n"
    ),
    "no hashing, no signature name": "def f(a, b):\n    return a == b or a.startswith(b)\n",
}


@pytest.mark.parametrize("case", sorted(FLAGGED))
def test_the_checker_flags_each_variable_time_way_to_compare_a_signature(case: str) -> None:
    assert variable_time_signature_comparisons(FLAGGED[case]), case


@pytest.mark.parametrize("case", sorted(FINE))
def test_the_checker_passes_constant_time_and_unrelated_comparisons(case: str) -> None:
    assert variable_time_signature_comparisons(FINE[case]) == [], case


def test_no_signature_is_compared_in_variable_time_anywhere_under_adapters() -> None:
    files = signature_files()
    assert len(files) > 1
    found = {
        str(p.relative_to(ROOT)): lines
        for p in files
        if (lines := variable_time_signature_comparisons(p.read_text()))
    }
    assert found == {}


def test_the_github_verifier_compares_with_compare_digest() -> None:
    import inspect

    import sto.ingest.github as mod

    tree = ast.parse(inspect.getsource(mod))
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "compare_digest"
    ]
    assert calls


def test_the_signature_is_compared_with_compare_digest_at_run_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[bytes, bytes]] = []
    import hmac as real

    original = real.compare_digest

    def spy(a: Any, b: Any) -> bool:
        seen.append((a, b))
        return original(a, b)

    monkeypatch.setattr("sto.ingest.github.hmac.compare_digest", spy)
    raw = sender().delivery(1, gid("g-1"))
    headers = {k.lower(): v for k, v in raw.headers.items()}
    GitHubWebhookVerifier(SECRET).verify(headers, raw.body)
    assert len(seen) == 1
    assert seen[0][0] == seen[0][1] == headers["x-hub-signature-256"].encode()


def test_permanent_error_family_for_rejections() -> None:
    assert issubclass(InvalidSignatureError, PermanentError)


# --- review pass 1 ----------------------------------------------------------------------------


def _pr_payload(**head: Any) -> bytes:
    payload = json.loads(json.dumps(FIXTURES["pull_request"]))
    payload["pull_request"]["head"] = {"sha": "c" * 40, "ref": "sto/run-1", **head}
    return json.dumps(payload).encode()


def test_a_lone_surrogate_signature_is_a_counted_401_not_a_crash() -> None:
    metrics = Metrics()
    raw = sender().delivery(1, gid("g-1"))
    headers = {k: v for k, v in raw.headers.items() if k.lower() != "x-hub-signature-256"}
    headers["X-Hub-Signature-256"] = "sha256=\udc80" + "0" * 63
    with pytest.raises(InvalidSignatureError):
        make_receiver(metrics=metrics).receive(RawWebhook(headers, raw.body))
    assert ("webhook.rejected", {"surface": "github", "reason": "signature"}) in metrics.counts


def test_a_fork_pull_request_carries_no_branch() -> None:
    [change] = parse_event("pull_request", _pr_payload(repo={"full_name": "mallory/app"}))
    assert change.branch is None
    assert change.sha == "c" * 40
    assert change.pr == PrRef(REPO, 7)


@pytest.mark.parametrize("head_repo", [None, {}, {"full_name": 5}])
def test_a_pull_request_whose_head_repo_is_unknown_carries_no_branch(head_repo: Any) -> None:
    [change] = parse_event("pull_request", _pr_payload(repo=head_repo))
    assert change.branch is None


def test_a_same_repo_pull_request_keeps_its_branch() -> None:
    [change] = parse_event("pull_request", _pr_payload(repo={"full_name": "acme/app"}))
    assert change.branch == "sto/run-1"


def test_a_fork_review_carries_no_branch() -> None:
    payload = json.loads(json.dumps(FIXTURES["pull_request_review"]))
    payload["pull_request"]["head"]["repo"] = {"full_name": "mallory/app"}
    [change] = parse_event("pull_request_review", json.dumps(payload).encode())
    assert change.branch is None
    assert change.sha == SHA2


@pytest.mark.parametrize(
    ("after", "extra"),
    [("0" * 40, {"deleted": True}), ("0" * 40, {}), (SHA, {"deleted": True})],
)
def test_a_branch_deletion_is_a_push_with_no_sha(after: str, extra: dict[str, Any]) -> None:
    body = {"ref": "refs/heads/sto/run-1", "after": after, **extra, "repository": REPO_JSON}
    [change] = parse_event("push", json.dumps(body).encode())
    assert change == ExternalChange(ChangeKind.PUSH, repo=REPO, sha=None, branch="sto/run-1")


def test_zero_is_not_an_issue_number() -> None:
    body = json.dumps({"issue": {"number": 0}, "repository": REPO_JSON}).encode()
    with pytest.raises(MalformedWebhookError):
        parse_event("issues", body)


def test_a_full_name_with_an_extra_slash_is_refused() -> None:
    body = json.dumps({"issue": {"number": 1}, "repository": {"full_name": "a/b/c"}}).encode()
    with pytest.raises(MalformedWebhookError):
        parse_event("issues", body)


def test_a_mixed_case_full_name_keeps_the_case_github_sent() -> None:
    body = json.dumps({"issue": {"number": 3}, "repository": {"full_name": "Acme/MyApp"}}).encode()
    [change] = parse_event("issues", body)
    assert change.ticket == TicketRef("github", "Acme/MyApp#3")
    assert ticket_key(RepoRef("Acme", "MyApp"), 3) == "Acme/MyApp#3"


def test_a_deleted_installation_lists_no_repositories_added() -> None:
    payload = {**FIXTURES["installation"], "action": "deleted"}
    update = parse_connection_update("installation", json.dumps(payload).encode())
    assert update is not None
    assert update.status is ConnectionStatus.REMOVED
    assert update.repositories_added == ()


def test_an_unknown_installation_repositories_action_is_ignored_for_state() -> None:
    payload = {**FIXTURES["installation_repositories"], "action": "something_new"}
    assert (
        parse_connection_update("installation_repositories", json.dumps(payload).encode()) is None
    )
    # The nudge still goes out, so the consumer re-reads the installation anyway.
    assert (
        parse_event("installation_repositories", json.dumps(payload).encode())
        == EXPECTED["installation_repositories"]
    )


@pytest.mark.parametrize("branch", [5, ["x"], {"a": 1}, None])
def test_a_check_suite_branch_that_is_not_text_is_no_branch(branch: Any) -> None:
    payload = json.loads(json.dumps(FIXTURES["check_suite"]))
    payload["check_suite"]["head_branch"] = branch
    changes = parse_event("check_suite", json.dumps(payload).encode())
    assert [c.branch for c in changes] == [None, None]


def test_a_non_object_in_pull_requests_is_refused() -> None:
    payload = json.loads(json.dumps(FIXTURES["check_suite"]))
    payload["check_suite"]["pull_requests"] = [{"number": 7}, 8]
    with pytest.raises(MalformedWebhookError):
        parse_event("check_suite", json.dumps(payload).encode())


# delivery IDs


@pytest.mark.parametrize("bad", ["not-a-guid ../#x", "d-1", "g" * 36, gid("x") + "0"])
def test_a_delivery_id_that_is_not_a_guid_is_refused_and_claims_nothing(bad: str) -> None:
    queue, metrics = Queue(), Metrics()
    receiver = make_receiver(queue=queue, metrics=metrics)
    raw = sender().delivery(1, bad)
    with pytest.raises(InvalidSignatureError):
        receiver.receive(raw)
    assert queue.items == []
    assert ("webhook.rejected", {"surface": "github", "reason": "delivery_id"}) in metrics.counts


def test_a_malformed_genuine_body_is_counted() -> None:
    metrics = Metrics()
    with pytest.raises(MalformedWebhookError):
        make_receiver(metrics=metrics).receive(sender().malformed(gid("g-1")))
    assert ("webhook.malformed", {"surface": "github"}) in metrics.counts


def test_the_hmac_is_computed_once_per_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    import hmac as real

    calls: list[int] = []
    original = real.new

    def counting(*a: Any, **k: Any) -> Any:
        calls.append(1)
        return original(*a, **k)

    raw = sender().delivery(1, gid("g-1"))  # signed by the fake, before the count starts
    monkeypatch.setattr("sto.ingest.github.hmac.new", counting)
    assert make_receiver().receive(raw) is not None
    assert len(calls) == 1


def test_a_receiver_cannot_be_built_without_a_connection_sink() -> None:
    with pytest.raises(TypeError):
        GitHubWebhooks(SECRET, MemoryStore(), Queue(), Metrics())  # type: ignore[call-arg]


# the store-backed connection sink

CONN = Key("ORG", "CONN#github#200002")


def _update(status: ConnectionStatus = ConnectionStatus.SUSPENDED) -> ConnectionUpdate:
    return ConnectionUpdate(200002, "installation", "suspend", status)


def test_the_sink_writes_a_hint_and_a_reread_flag_under_org() -> None:
    store = MemoryStore()
    StoreConnectionSink(store, Clock()).apply(
        ConnectionUpdate(
            200002,
            "installation_repositories",
            "added",
            ConnectionStatus.REPOSITORIES_CHANGED,
            (REPO,),
            (RepoRef("acme", "old"),),
        )
    )
    item = store.get(PLATFORM, CONN)
    assert item is not None
    assert item.data["reread_pending"] is True
    assert item.data["installation_id"] == 200002
    assert item.data["hint"]["status"] == "repositories_changed"
    assert item.data["hint"]["repositories_added"] == ["acme/app"]
    assert item.data["hint"]["repositories_removed"] == ["acme/old"]


def test_the_sink_never_sets_status_from_the_body_alone() -> None:
    store = MemoryStore()
    StoreConnectionSink(store, Clock()).apply(_update(ConnectionStatus.SUSPENDED))
    item = store.get(PLATFORM, CONN)
    assert item is not None
    assert "status" not in item.data


def test_the_sink_leaves_an_authoritative_status_untouched_on_a_replayed_suspend() -> None:
    store = MemoryStore()
    store.put(PLATFORM, CONN, {"kind": "github", "status": "active", "installation_id": 200002})
    sink = StoreConnectionSink(store, Clock())
    sink.apply(_update())
    sink.apply(_update())  # the same genuine body again, under another delivery ID
    item = store.get(PLATFORM, CONN)
    assert item is not None
    assert item.data["status"] == "active"  # only a re-read changes it
    assert item.data["reread_pending"] is True


def test_the_sink_is_idempotent() -> None:
    store = MemoryStore()
    sink = StoreConnectionSink(store, Clock())
    sink.apply(_update())
    first = store.get(PLATFORM, CONN)
    sink.apply(_update())
    second = store.get(PLATFORM, CONN)
    assert first is not None
    assert second is not None
    assert first.data == second.data


def test_a_replayed_suspend_body_through_the_receiver_does_not_change_status() -> None:
    store = MemoryStore()
    store.put(PLATFORM, CONN, {"kind": "github", "status": "active", "installation_id": 200002})
    receiver = make_receiver(store=store, connections=StoreConnectionSink(store, Clock()))
    body = {**FIXTURES["installation"], "action": "suspend"}
    receiver.receive(send("installation", body, gid("orig")))
    receiver.receive(send("installation", body, gid("replayed-new-id")))
    item = store.get(PLATFORM, CONN)
    assert item is not None
    assert item.data["status"] == "active"
    assert item.data["reread_pending"] is True


def test_the_sink_merges_again_when_another_writer_got_in_between() -> None:
    class Racy(MemoryStore):
        raced = False

        def put(self, scope: Any, key: Key, data: Any, *, when: Any = None) -> None:
            if not self.raced:
                self.raced = True
                super().put(scope, key, {"kind": "github", "other": 1})
            super().put(scope, key, data, when=when)

    store = Racy()
    StoreConnectionSink(store, Clock()).apply(_update())
    item = store.get(PLATFORM, CONN)
    assert item is not None
    assert item.data["other"] == 1
    assert item.data["reread_pending"] is True


def test_the_sink_gives_up_with_a_transient_error_when_the_record_keeps_changing() -> None:
    class Always(MemoryStore):
        def put(self, scope: Any, key: Key, data: Any, *, when: Any = None) -> None:
            raise ConditionFailedError([0])

    with pytest.raises(TransientError):
        StoreConnectionSink(Always(), Clock()).apply(_update())


def test_the_installation_change_carries_the_installation_id() -> None:
    [change] = parse_event("installation", json.dumps(FIXTURES["installation"]).encode())
    assert change.installation_id == 200002
