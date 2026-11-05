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
    ConnectionStatus,
    ConnectionUpdate,
    GitHubWebhooks,
    GitHubWebhookVerifier,
    parse_connection_update,
    parse_event,
    ticket_key,
)
from sto.store.memory import MemoryStore

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


def make_receiver(
    clock: Clock | None = None,
    store: MemoryStore | None = None,
    queue: Queue | None = None,
    metrics: Metrics | None = None,
    connections: Connections | None = None,
) -> GitHubWebhooks:
    return GitHubWebhooks(
        SECRET,
        store if store is not None else MemoryStore(),
        queue if queue is not None else Queue(),
        metrics if metrics is not None else Metrics(),
        connections=connections,
        clock=clock or Clock(),
    )


def sender(body: Callable[[int, str], bytes] | None = None) -> FakeWebhooks:
    clock = Clock()
    return FakeWebhooks(clock, body=body) if body else FakeWebhooks(clock)


def send(event: str, payload: Mapping[str, Any], delivery: str = "g-1") -> RawWebhook:
    return sender().delivery(1, delivery, event=event, body=json.dumps(payload).encode())


# --- fixtures: one per subscribed event type --------------------------------------------------

PR_JSON = {
    "number": 7,
    "state": "open",
    "head": {"sha": SHA, "ref": "sto/run-1"},
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
    "installation": [ExternalChange(ChangeKind.INSTALLATION)],
    "installation_repositories": [ExternalChange(ChangeKind.INSTALLATION)],
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
    raw = send(event, FIXTURES[event], f"g-{event}")
    assert receiver.receive(raw) == EXPECTED[event]
    [nudge] = queue.items
    assert nudge.delivery_id == f"g-{event}"
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
    raw = send("installation", {**FIXTURES["installation"], "action": "suspend"}, "g-i")
    receiver.receive(raw)
    receiver.receive(raw)  # a redelivery
    assert [u.status for u in connections.updates] == [ConnectionStatus.SUSPENDED]


def test_a_rejected_or_malformed_delivery_never_touches_connection_state() -> None:
    connections = Connections()
    receiver = make_receiver(connections=connections)
    forged = sender().forge(1, "g-1", ForgeKind.WRONG_SECRET, event="installation")
    with pytest.raises(InvalidSignatureError):
        receiver.receive(forged)
    bad = sender().delivery(1, "g-2", event="installation", body=b"{nope")
    with pytest.raises(MalformedWebhookError):
        receiver.receive(bad)
    assert connections.updates == []


def test_a_connection_sink_failure_still_queues_the_nudge_and_is_counted() -> None:
    connections, queue, metrics = Connections(), Queue(), Metrics()
    connections.fail = True
    receiver = make_receiver(connections=connections, queue=queue, metrics=metrics)
    assert receiver.receive(send("installation", FIXTURES["installation"], "g-i")) is not None
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
    raw = sender().delivery(1, "g-1")
    headers = {k.lower(): v for k, v in raw.headers.items()}
    assert GitHubWebhookVerifier(SECRET).verify(headers, raw.body) == "g-1"


@pytest.mark.parametrize("how", list(ForgeKind))
def test_every_forgery_is_rejected_by_the_verifier(how: ForgeKind) -> None:
    raw = sender().forge(1, "g-1", how)
    headers = {k.lower(): v for k, v in raw.headers.items()}
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_the_sha1_header_alone_is_not_accepted() -> None:
    raw = sender().delivery(1, "g-1")
    headers = {k.lower(): v for k, v in raw.headers.items()}
    headers["x-hub-signature"] = headers.pop("x-hub-signature-256").replace("sha256=", "sha1=")
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_a_non_ascii_signature_is_rejected_not_a_crash() -> None:
    raw = sender().delivery(1, "g-1")
    headers = {k.lower(): v for k, v in raw.headers.items()}
    headers["x-hub-signature-256"] = "sha256=é" + "0" * 63
    with pytest.raises(InvalidSignatureError):
        GitHubWebhookVerifier(SECRET).verify(headers, raw.body)


def test_the_signature_is_checked_before_the_body_is_read() -> None:
    """Not-JSON under a wrong signature is a signature failure, never a parse one."""
    forged = sender().forge(1, "g-1")
    garbage = RawWebhook(forged.headers, b"{not json")
    with pytest.raises(InvalidSignatureError):
        make_receiver().receive(garbage)


def test_tampered_and_reserialised_bodies_are_rejected_and_queue_nothing() -> None:
    queue = Queue()
    receiver = make_receiver(queue=queue)
    hooks = sender()
    genuine = hooks.delivery(1, "g-1")
    for changed in (hooks.tamper(genuine), hooks.reserialise(genuine)):
        assert changed.body != genuine.body
        with pytest.raises(InvalidSignatureError):
            receiver.receive(changed)
    assert queue.items == []
    assert receiver.receive(genuine) is not None  # neither burned the delivery ID


def test_a_duplicate_is_dropped_forever_even_after_a_restart() -> None:
    clock, store, queue = Clock(), MemoryStore(), Queue()
    raw = sender().delivery(1, "g-1")
    assert make_receiver(clock, store, queue).receive(raw) is not None
    clock.now += 10.0**10
    fresh = make_receiver(clock, store, queue)
    assert fresh.receive(raw) is None
    assert len(queue.items) == 1


def test_a_failed_enqueue_releases_the_delivery_so_the_retry_is_not_dropped() -> None:
    queue, metrics = Queue(), Metrics()
    receiver = make_receiver(queue=queue, metrics=metrics)
    raw = sender().delivery(1, "g-1")
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
        receiver.receive(sender().forge(1, "g-1"))
    assert ("webhook.rejected", {"surface": "github", "reason": "signature"}) in metrics.counts


def test_a_missing_event_header_on_a_genuine_delivery_is_malformed() -> None:
    raw = sender().delivery(1, "g-1")
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
        return GitHubWebhooks(SECRET, self.store, self.queue, Metrics(), clock=self.clock_)

    def restart(self) -> None:
        self.adapter = self._fresh()
        self.verifier = self.adapter.verifier

    def deliver(self, raw: RawWebhook) -> Outcome:
        changes = self.adapter.receive(raw)  # type: ignore[attr-defined]
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


def variable_time_signature_comparisons(source: str) -> list[int]:
    """Lines where a signature, MAC or digest meets ``==``, ``!=``, ``in`` or ``not in``.

    ``hmac.compare_digest`` is a call, never a ``Compare``, so it is never flagged. A comparison
    with ``None`` or a bare length check is not a content comparison, so it is not either."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        if any(isinstance(o, ast.Constant) and o.value is None for o in operands):
            continue
        if any(isinstance(o, ast.Call) and getattr(o.func, "id", "") == "len" for o in operands):
            continue
        if any(SIGNATURE_WORDS.search(n) for o in operands for n in _names(o)):
            lines.append(node.lineno)
    return lines


def signature_files() -> list[Path]:
    files = sorted(ADAPTERS.rglob("*.py"))
    files.append(ROOT / "src" / "sto" / "ingest" / "github.py")
    return files


def test_the_checker_flags_each_variable_time_way_to_compare_a_signature() -> None:
    bad = [
        "ok = signature == expected",
        "ok = expected != headers['x-hub-signature-256']",
        "ok = computed_mac in (a, b)",
        "ok = hmac.new(k, b, h).hexdigest() == got",
        "ok = got.digest == want",
        "if self.sig_header == value: pass",
    ]
    for line in bad:
        assert variable_time_signature_comparisons(line) == [1], line


def test_the_checker_passes_constant_time_and_unrelated_comparisons() -> None:
    fine = [
        "ok = hmac.compare_digest(a, b)",
        "ok = signature is None",
        "ok = signature != None",
        "ok = len(signature) == 71",
        "ok = status == 401",
        "ok = kind == 'push'",
    ]
    for line in fine:
        assert variable_time_signature_comparisons(line) == [], line


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
    raw = sender().delivery(1, "g-1")
    headers = {k.lower(): v for k, v in raw.headers.items()}
    GitHubWebhookVerifier(SECRET).verify(headers, raw.body)
    assert len(seen) == 1
    assert seen[0][0] == seen[0][1] == headers["x-hub-signature-256"].encode()


def test_permanent_error_family_for_rejections() -> None:
    assert issubclass(InvalidSignatureError, PermanentError)
