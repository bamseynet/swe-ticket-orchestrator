"""D6-05: Jira webhooks. The receiver (``sto.ingest.jira``) and the registration job
(``sto.adapters.jira.webhooks``), driven by the fake Jira's sender and registration API (D6-09).
Every secret, ID and payload is synthetic.

What Atlassian's page does NOT say (fetched while writing this): whether the token of an OAuth 2.0
app's webhook covers the body. So the bearer form is treated as proving WHO sent, never WHAT; the
admin ``X-Hub-Signature`` form is the one that covers the body. Both are tested, and the bearer
tests pin the gap instead of hiding it."""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
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
from fakes.jira.issues.server import EPOCH
from fakes.jira.workflow import ADMIN_SECRET, CLIENT_SECRET, FakeJiraWebhooks, FakeJiraWorkflow
from fakes.jira.workflow.webhooks import IDENT, RETRY, SIGNATURE
from ingest.test_github import variable_time_signature_comparisons
from sto.adapters.jira.webhooks import (
    ApiReply,
    ProjectBindings,
    SiteWebhooks,
    WebhookLimitError,
    WebhookRefusedError,
    webhook_jql,
)
from sto.adapters.ports import ChangeKind, MalformedWebhookError, RawWebhook, TicketRef
from sto.domain.errors import PermanentError, TransientError
from sto.ingest.core import InvalidSignatureError, Nudge
from sto.ingest.jira import (
    SUBSCRIBED_EVENTS,
    TOKEN_MAX_AGE,
    JiraWebhooks,
    JiraWebhookVerifier,
    WebhookForm,
    parse_event,
)
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, ConditionFailedError, Key

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[2]
DAY = 86_400.0
SITE = "site-1"
URL = "https://receiver.example.test/hook"


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


class World:
    """One fake Jira with one issue, a sender, and a receiver on the same fake clock."""

    def __init__(self, site: str = SITE) -> None:
        self.jira = FakeJiraWorkflow()
        self.hooks = FakeJiraWebhooks(self.jira)
        self.key = str(self.jira.add_issue(summary="synthetic")["key"])
        self.store, self.queue, self.metrics = MemoryStore(), Queue(), Metrics()
        self.receiver = self.fresh(site)

    def clock(self) -> float:
        return self.jira.now

    def fresh(self, site: str = SITE, **secrets: Any) -> JiraWebhooks:
        both = {
            "admin_secret": ADMIN_SECRET,
            "client_secret": CLIENT_SECRET,
            "app_issuer": ISSUER,
        } | secrets
        return JiraWebhooks(
            site,
            self.store,
            self.queue,
            self.metrics,
            clock=self.clock,
            **both,
        )

    def post(self, raw: RawWebhook) -> int:
        """What Jira sees: the receiver's HTTP answer, or a raised timeout."""
        try:
            changes = self.receiver.receive(raw)
        except TransientError:
            return 503
        except PermanentError as exc:
            return 400 if isinstance(exc, MalformedWebhookError) else 401
        return 202 if changes is not None else 200


def headers_of(raw: RawWebhook) -> dict[str, str]:
    return {k.lower(): v for k, v in raw.headers.items()}


def sign(body: bytes, secret: bytes = ADMIN_SECRET) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


ISSUER = "synthetic-app"  # the fake sender's ``iss``
T0 = EPOCH + 1_000.0  # "now" for verifiers built by ``make_verifier`` and tokens by ``token``


def make_verifier(
    admin: bytes | None = ADMIN_SECRET,
    client: bytes | None = CLIENT_SECRET,
    clock: Callable[[], float] | None = None,
) -> JiraWebhookVerifier:
    return JiraWebhookVerifier(
        admin, client, app_issuer=ISSUER if client else None, clock=clock or (lambda: T0)
    )


def token(
    header: Mapping[str, Any],
    secret: bytes = CLIENT_SECRET,
    claims: Mapping[str, Any] | None = None,
) -> str:
    """A token as the fake would make it at ``T0``, unless ``claims`` says otherwise."""
    fresh = {"iss": ISSUER, "iat": int(T0) - 10, "exp": int(T0) + 290}
    head = b64(json.dumps(header).encode())
    body = b64(json.dumps(fresh if claims is None else claims).encode())
    mac = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(mac)}"


def signed_raw(body: bytes, ident: str = "i-1") -> RawWebhook:
    return RawWebhook({IDENT: ident, SIGNATURE: sign(body)}, body)


def issue_body(key: str = "SYN-1", event: str = "jira:issue_updated", **extra: Any) -> bytes:
    payload = {"webhookEvent": event, "issue": {"key": key, "id": "10001"}, **extra}
    return json.dumps(payload).encode()


# --- the verifier: both forms ------------------------------------------------------------------


def test_the_two_forms_and_their_delivery_ids() -> None:
    w = World()
    verifier = make_verifier(clock=w.clock)
    admin, bearer = w.hooks.admin_event(w.key), w.hooks.bearer_event(w.key)
    assert verifier.verify(headers_of(admin), admin.body) == admin.headers[IDENT]
    assert verifier.verify(headers_of(bearer), bearer.body) == bearer.headers[IDENT]
    assert verifier.form(headers_of(admin), admin.body) is WebhookForm.ADMIN
    assert verifier.form(headers_of(bearer), bearer.body) is WebhookForm.BEARER
    assert WebhookForm.ADMIN.covers_body
    assert not WebhookForm.BEARER.covers_body


def test_an_empty_or_non_bytes_secret_is_refused_and_one_form_is_enough() -> None:
    for bad in (b"", "text", 5):
        with pytest.raises(ValueError, match="secret"):
            JiraWebhookVerifier(bad, None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="app_issuer"):
        JiraWebhookVerifier(None, CLIENT_SECRET)
    with pytest.raises(ValueError, match="at least one"):
        JiraWebhookVerifier(None, None)
    JiraWebhookVerifier(ADMIN_SECRET, None)
    JiraWebhookVerifier(None, CLIENT_SECRET, app_issuer=ISSUER)


@pytest.mark.parametrize("form", ["admin", "bearer"])
def test_a_wrong_secret_is_rejected_in_either_form(form: str) -> None:
    w = World()
    raw = w.hooks.admin_event(w.key) if form == "admin" else w.hooks.bearer_event(w.key)
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(headers_of(w.hooks.forged(raw)), raw.body)


def test_a_form_whose_secret_is_not_configured_is_refused() -> None:
    w = World()
    admin, bearer = w.hooks.admin_event(w.key), w.hooks.bearer_event(w.key)
    with pytest.raises(InvalidSignatureError):
        make_verifier(None, CLIENT_SECRET).verify(headers_of(admin), admin.body)
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, None).verify(headers_of(bearer), bearer.body)


def test_a_delivery_with_neither_credential_is_refused() -> None:
    raw = signed_raw(issue_body())
    bare = {k: v for k, v in headers_of(raw).items() if k != SIGNATURE.lower()}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(bare, raw.body)


def test_both_credentials_at_once_are_refused_not_picked_between() -> None:
    w = World()
    admin, bearer = w.hooks.admin_event(w.key), w.hooks.bearer_event(w.key)
    both = headers_of(admin) | {"authorization": bearer.headers["Authorization"]}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(both, admin.body)


@pytest.mark.parametrize("method", ["sha1", "md5", "sha512", ""])
def test_only_the_sha256_method_is_accepted(method: str) -> None:
    body = issue_body()
    digest = hmac.new(ADMIN_SECRET, body, hashlib.sha256).hexdigest()
    headers = {"x-atlassian-webhook-identifier": "i-1", "x-hub-signature": f"{method}={digest}"}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(headers, body)


@pytest.mark.parametrize(
    "value", ["", "sha256=", "sha256=00", "sha256", "SHA256=zz", "sha256=\ud800", "sha256=é"]
)
def test_a_garbled_admin_signature_is_a_rejection_not_a_crash(value: str) -> None:
    headers = {"x-atlassian-webhook-identifier": "i-1", "x-hub-signature": value}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(headers, issue_body())


@pytest.mark.parametrize(
    "value",
    [
        "Bearer",
        "Bearer ",
        "Bearer a.b",
        "Bearer a.b.c.d",
        "Basic abc",
        "Bearer \ud800.b.c",
        "Bearer é.é.é",
        "Bearer a..c",
    ],
)
def test_a_garbled_bearer_token_is_a_rejection_not_a_crash(value: str) -> None:
    headers = {"x-atlassian-webhook-identifier": "i-1", "authorization": value}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, CLIENT_SECRET).verify(headers, issue_body())


@pytest.mark.parametrize("header", [{"alg": "none"}, {"alg": "HS512"}, {"alg": "HS256x"}, {}])
def test_a_token_whose_header_is_not_hs256_is_rejected_even_with_a_valid_mac(
    header: dict[str, str],
) -> None:
    headers = {"x-atlassian-webhook-identifier": "i-1", "authorization": f"Bearer {token(header)}"}
    with pytest.raises(InvalidSignatureError):
        make_verifier(None, CLIENT_SECRET).verify(headers, issue_body())
    good = {"x-atlassian-webhook-identifier": "i-1"}
    good["authorization"] = "bEaReR " + token({"alg": "HS256"})  # scheme is case-insensitive
    assert make_verifier(None, CLIENT_SECRET).verify(good, issue_body()) == "i-1"


def test_a_token_header_that_is_not_json_is_rejected() -> None:
    head = b64(b"not json")
    mac = hmac.new(CLIENT_SECRET, f"{head}.e30".encode(), hashlib.sha256).digest()
    headers = {
        "x-atlassian-webhook-identifier": "i-1",
        "authorization": f"Bearer {head}.e30.{b64(mac)}",
    }
    with pytest.raises(InvalidSignatureError):
        make_verifier(None, CLIENT_SECRET).verify(headers, issue_body())


@pytest.mark.parametrize("ident", ["", " ", "a b", "a#b", "a" * 129, "é", "a/b", "a:b"])
def test_a_missing_or_unsafe_identifier_is_refused_never_replaced_by_a_body_hash(
    ident: str,
) -> None:
    body = issue_body()
    raw = RawWebhook({IDENT: ident, SIGNATURE: sign(body)}, body)
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, None).verify(headers_of(raw), raw.body)
    no_id = {k: v for k, v in headers_of(raw).items() if k != IDENT.lower()}
    with pytest.raises(InvalidSignatureError):
        make_verifier(ADMIN_SECRET, None).verify(no_id, raw.body)


# --- the body: admin form covers it, bearer form does not (unconfirmed) ----------------------


def test_a_tampered_body_is_rejected_in_the_admin_form() -> None:
    w = World()
    raw = w.hooks.tampered(w.hooks.admin_event(w.key))
    assert w.post(raw) == 401
    assert w.queue.items == []


def test_the_bearer_token_is_not_taken_as_proof_of_the_body() -> None:
    """Atlassian's page says the token is "signed with the app's client secret" and nothing about
    the body, and the fake's token covers none. So a bearer delivery with a changed body still
    authenticates the SENDER; the receiver therefore counts it and a consumer reads only the
    issue key from it, then re-reads. Revisit when D12 shows what Jira really signs."""
    w = World()
    raw = w.hooks.tampered(w.hooks.bearer_event(w.key))
    assert w.post(raw) == 202
    assert "webhook.body_unauthenticated" in w.metrics.names()
    assert w.queue.items[0].reread is True


def test_an_admin_delivery_is_not_counted_as_unauthenticated() -> None:
    w = World()
    assert w.post(w.hooks.admin_event(w.key)) == 202
    assert "webhook.body_unauthenticated" not in w.metrics.names()


def test_the_signature_is_checked_before_the_body_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise AssertionError("body parsed before verification")

    monkeypatch.setattr("sto.ingest.jira.json.loads", boom)
    raw = RawWebhook({IDENT: "i-1", SIGNATURE: sign(b"x", b"wrong")}, b"{}")
    with pytest.raises(InvalidSignatureError):
        World().receiver.receive(raw)


# --- the replay window must fit Jira's retries ---------------------------------------------------


def test_there_is_no_replay_window_because_retries_come_5_to_15_minutes_apart() -> None:
    verifier = make_verifier(ADMIN_SECRET, CLIENT_SECRET)
    assert verifier.signed_timestamp is False
    assert verifier.replay_window is None
    assert not CAPABILITIES[Vendor.JIRA].signed_timestamp


def test_the_slowest_retry_schedule_is_still_accepted_once() -> None:
    """Five resends, each up to 15 minutes after the last: 75 minutes after the first attempt.
    The receiver is down for all but the last, and the one that lands is queued exactly once."""
    w = World()
    raw = w.hooks.admin_event(w.key)
    attempts = {"n": 0}
    started = w.jira.now

    def post(sent: RawWebhook) -> int:
        attempts["n"] += 1
        if attempts["n"] < 6:
            return 503
        return w.post(sent)

    w.hooks._rng.randint = lambda lo, hi: hi  # type: ignore[assignment,method-assign]  # slowest draw
    report = w.hooks.deliver(post, raw)
    assert report.delivered
    assert len(report.attempts) == 6
    assert w.jira.now - started == 5 * 15 * 60
    assert len(w.queue.items) == 1
    assert report.attempts[-1].status == 202


def test_a_retry_after_a_lost_answer_is_a_duplicate_not_a_second_nudge() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    lost = {"first": True}

    def post(sent: RawWebhook) -> int:
        status = w.post(sent)
        if lost.pop("first", False):
            raise TimeoutError  # queued, but Jira never heard
        return status

    report = w.hooks.deliver(post, raw)
    assert [a.status for a in report.attempts] == [None, 200]
    assert len(w.queue.items) == 1
    assert report.attempts[1].at - report.attempts[0].at in range(5 * 60, 15 * 60 + 1)


def test_a_retry_of_a_rejected_delivery_is_not_burned_by_the_first_attempt() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    w.queue.fail = True
    assert w.post(raw) == 503
    w.queue.fail = False
    assert w.post(RawWebhook({**raw.headers, RETRY: "1"}, raw.body)) == 202


def test_the_duplicate_is_remembered_far_past_any_retry() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    assert w.post(raw) == 202
    w.jira.now += 400 * DAY
    assert w.post(w.hooks.duplicate(raw)) == 200
    assert len(w.queue.items) == 1


def test_the_retry_header_is_not_part_of_the_identity() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    assert w.post(raw) == 202
    assert w.post(RawWebhook({**raw.headers, RETRY: "3"}, raw.body)) == 200


# --- the receiver ------------------------------------------------------------------------------


def test_a_delivery_names_its_ticket_and_nothing_else() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    changes = w.receiver.receive(raw)
    assert changes is not None
    (change,) = changes
    assert change.kind is ChangeKind.TICKET
    assert change.ticket == TicketRef("jira", w.key)
    assert (change.sha, change.branch, change.pr, change.repo) == (None, None, None, None)


def test_secrets_are_not_queued() -> None:
    w = World()
    w.post(w.hooks.bearer_event(w.key))
    w.post(w.hooks.admin_event(w.key))
    for nudge in w.queue.items:
        assert not {"authorization", "x-hub-signature"} & set(nudge.headers)
        assert b"synthetic-app" not in json.dumps(dict(nudge.headers)).encode()


def test_the_surface_is_per_site_so_one_tenants_ids_never_meet_anothers() -> None:
    """The identifier is unique within a tenant only."""
    w = World()
    other = w.fresh("site-2")
    raw = w.hooks.admin_event(w.key)
    assert w.receiver.receive(raw) is not None
    assert w.receiver.receive(raw) is None
    assert other.receive(raw) is not None
    assert {n.surface for n in w.queue.items} == {"jira.site-1", "jira.site-2"}


@pytest.mark.parametrize("site", ["", " ", "a#b", "a b", "é", "x" * 65, "a.b"])
def test_an_unsafe_site_is_refused(site: str) -> None:
    with pytest.raises(ValueError, match="site"):
        World().fresh(site)


def test_a_cloud_id_style_site_is_accepted() -> None:
    World().fresh("0a1b2c3d-4e5f-6789-abcd-ef0123456789")


def test_a_genuine_body_that_cannot_be_read_is_malformed_and_keeps_its_id() -> None:
    w = World()
    for bad in (
        b"not json",
        b"[]",
        b"{}",
        b'{"webhookEvent": 5}',
        b'{"webhookEvent": "jira:issue_updated"}',
    ):
        with pytest.raises(MalformedWebhookError):
            w.receiver.receive(signed_raw(bad, "i-1"))
    assert "webhook.malformed" in w.metrics.names()
    assert w.queue.items == []
    assert w.receiver.receive(signed_raw(issue_body(), "i-1")) is not None  # id was not burned


@pytest.mark.parametrize(
    "key", ["", "syn-1", "SYN-0", "SYN-01", "SYN-", "1SYN-1", "SYN 1", "S-1\n"]
)
def test_an_issue_key_that_is_not_a_jira_key_is_malformed(key: str) -> None:
    with pytest.raises(MalformedWebhookError):
        parse_event(issue_body(key))


def test_a_deep_body_is_malformed_not_a_crash() -> None:
    deep = b"[" * 100_000
    with pytest.raises(MalformedWebhookError):
        parse_event(deep)


@pytest.mark.parametrize(
    "event",
    ["jira:issue_created", "jira:issue_updated", "jira:issue_deleted", "comment_created",
     "comment_updated", "comment_deleted"],
)  # fmt: skip
def test_each_subscribed_event_names_its_issue(event: str) -> None:
    (change,) = parse_event(issue_body("ABC-12", event))
    assert change.ticket == TicketRef("jira", "ABC-12")


@pytest.mark.parametrize("event", ["sprint_started", "jira:version_released", "unknown"])
def test_an_event_we_do_not_subscribe_to_is_ignored_and_not_queued(event: str) -> None:
    w = World()
    body = json.dumps({"webhookEvent": event, "sprint": {"id": 1}}).encode()
    assert w.receiver.receive(signed_raw(body)) == []
    assert w.queue.items == []
    assert "webhook.ignored" in w.metrics.names()


def test_the_body_of_a_delivery_is_never_read_for_state() -> None:
    """Only the issue key leaves the body: no status, no assignee, no changelog."""
    body = issue_body(
        "SYN-3", fields={"status": {"name": "Done"}}, changelog={"items": [{"field": "status"}]}
    )
    (change,) = parse_event(body)
    assert [f for f in vars(change) if getattr(change, f) is not None] == ["kind", "ticket"]


# --- order: out-of-order events change nothing -------------------------------------------------


def test_deliveries_in_any_order_leave_the_same_trace() -> None:
    def run(order: list[int]) -> tuple[list[str], list[object]]:
        w = World()
        events = ("jira:issue_created", "jira:issue_updated", "jira:issue_deleted")
        raws = []
        for i, event in enumerate(events):
            w.jira.now += 1
            made = w.hooks.admin_event(w.key, event)
            raws.append(RawWebhook({**made.headers, IDENT: f"i-{i}"}, made.body))
        changes = [w.receiver.receive(raws[i]) for i in order]
        assert all(c is not None for c in changes)
        return sorted(n.delivery_id for n in w.queue.items), [c for c in changes[:1]]

    forward, backward = run([0, 1, 2]), run([2, 1, 0])
    assert forward[0] == backward[0] == ["i-0", "i-1", "i-2"]
    assert forward[1] == backward[1]  # the same ticket nudge whichever event came first


def test_a_stale_body_cannot_change_what_the_receiver_reports() -> None:
    """The newest delivery arrives first, the oldest last. Each names the same ticket and carries
    no state, so there is nothing for an old one to put back."""
    w = World()
    first = w.hooks.admin_event(w.key)
    w.jira.now += 60
    second = w.hooks.admin_event(w.key)
    a = w.receiver.receive(second)
    b = w.receiver.receive(first)
    assert a is not None
    assert b is not None
    assert a == b
    assert [n.reread for n in w.queue.items] == [True, True]


def test_the_suite_order_helper_changes_nothing_either() -> None:
    w = World()
    raws = [w.hooks.admin_event(w.key) for _ in range(5)]
    mixed = w.hooks.unordered(raws, seed=3)
    assert mixed != raws
    assert all(w.receiver.receive(r) is not None for r in mixed)
    assert sorted(n.delivery_id for n in w.queue.items) == sorted(r.headers[IDENT] for r in raws)


def test_the_receiver_has_no_write_to_jira_and_no_state_but_the_dedupe_record() -> None:
    names = {n for n in dir(JiraWebhooks) if not n.startswith("_")}
    assert names == {"receive"}


# --- conformance: the suite's webhook section, unmodified ----------------------------------------


class JiraWebhookTarget(Target):
    """Thin pass-through over the fake's admin form (the one whose signature covers the body).
    The sender is the fake's; the verifier, dedupe and parsing are ours."""

    name = "jira-webhooks"
    vendor = Vendor.JIRA
    signature_header = SIGNATURE
    controls = frozenset(
        {Control.SIGNATURE, Control.UNSIGNED, Control.DUPLICATE, Control.REPLAY_WINDOW}
        | {Control.RESTART}
    )

    def __init__(self) -> None:
        self.world = World()
        self._emitted: dict[tuple[int, str], RawWebhook] = {}
        self.watched = self.world.key
        self.adapter = self.world.receiver
        self.verifier = self.adapter.verifier

    def restart(self) -> None:
        self.world.receiver = self.world.fresh()  # the store and queue are the durable part
        self.adapter = self.world.receiver
        self.verifier = self.adapter.verifier

    def deliver(self, raw: RawWebhook) -> Outcome:
        changes = self.adapter.receive(raw)  # type: ignore[attr-defined]
        if changes is None:
            return Outcome(False)
        return Outcome(True, tuple(c.ticket.key for c in changes if c.ticket))

    def queued(self) -> int:
        return len(self.world.queue.items)

    def clock(self) -> float:
        return self.world.clock()

    def advance_clock(self, seconds: float) -> None:
        self.world.jira.now += seconds

    def _with_id(self, raw: RawWebhook, delivery_id: str) -> RawWebhook:
        return RawWebhook({**raw.headers, IDENT: delivery_id}, raw.body)  # the id is unsigned

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        """The same arguments give the same bytes (the fake numbers its changelog per call)."""
        if (revision, delivery_id) not in self._emitted:
            raw = self.world.hooks.admin_event(self.watched)
            self._emitted[revision, delivery_id] = self._with_id(raw, delivery_id)
        return self._emitted[revision, delivery_id]

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        raw = self.emit(revision, delivery_id)
        digest = hmac.new(ADMIN_SECRET, raw.body, hashlib.sha256).hexdigest()
        value = {
            ForgeKind.WRONG_SECRET: sign(raw.body, b"synthetic-not-the-secret"),
            ForgeKind.TRUNCATED_MAC: "sha256=" + digest[:-2],
            ForgeKind.EMPTY_MAC: "sha256=",
            ForgeKind.EMPTY_KEY: "sha256=" + hmac.new(b"", raw.body, hashlib.sha256).hexdigest(),
            ForgeKind.BLANK_HEADER: "",
        }[how]
        return RawWebhook({**raw.headers, SIGNATURE: value}, raw.body)

    def emit_without_id(self, revision: int) -> RawWebhook:
        raw = self.world.hooks.admin_event(self.watched)
        return RawWebhook({k: v for k, v in raw.headers.items() if k != IDENT}, raw.body)

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        return self._with_id(signed_raw(b"{not json"), delivery_id)

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        return self.emit(revision, delivery_id)  # Jira signs and sends no time

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        headers = {k: v for k, v in raw.headers.items() if k != "X-Timestamp"}
        if value is not None:
            headers["X-Timestamp"] = value  # Jira sends none: a forger may add one
        return RawWebhook(headers, raw.body)

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        return self.world.hooks.tampered(raw)

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        text = json.dumps(json.loads(raw.body), indent=2, sort_keys=True)
        return RawWebhook(raw.headers, text.encode())


def jira_webhooks() -> Target:
    return JiraWebhookTarget()


class TestJiraWebhooksConformance(AdapterConformance):
    """Signature, duplicate, replay-window and restart tests, with ``signed_timestamp=False``."""

    port = Port.WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": jira_webhooks}


def test_every_test_the_webhook_port_requires_passes() -> None:
    failed = {n: e for n, e in run_suite(jira_webhooks, Port.WEBHOOK).items() if e is not None}
    assert failed == {}


def test_the_conformance_target_is_defined_in_sto_ingest_jira() -> None:
    target = JiraWebhookTarget()
    assert type(target.adapter).__module__ == "sto.ingest.jira"
    assert target.verifier.signed_timestamp is False  # type: ignore[attr-defined]


# --- static: constant-time comparison -------------------------------------------------------------


def test_no_digest_is_compared_in_variable_time_in_the_jira_modules() -> None:
    files = [
        ROOT / "src" / "sto" / "ingest" / "jira.py",
        ROOT / "src" / "sto" / "adapters" / "jira" / "webhooks.py",
    ]
    assert all(p.exists() for p in files)
    found = {
        p.name: lines
        for p in files
        if (lines := variable_time_signature_comparisons(p.read_text()))
    }
    assert found == {}


def test_both_forms_compare_with_compare_digest_at_run_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[bytes, bytes]] = []
    original = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        seen.append((a, b))
        return original(a, b)

    monkeypatch.setattr("sto.ingest.jira.hmac.compare_digest", spy)
    w = World()
    verifier = make_verifier(clock=w.clock)
    for raw in (w.hooks.admin_event(w.key), w.hooks.bearer_event(w.key)):
        seen.clear()
        verifier.verify(headers_of(raw), raw.body)
        assert len(seen) == 1
        assert seen[0][0] == seen[0][1]


def test_the_verifier_source_uses_compare_digest() -> None:
    import ast

    import sto.ingest.jira as mod

    calls = [
        n
        for n in ast.walk(ast.parse(inspect.getsource(mod)))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "compare_digest"
    ]
    assert len(calls) >= 2


# --- registration: one per site, routed by project binding --------------------------------------


class FakeApi:
    """The Jira REST calls the job makes, over the fake, with a fresh OAuth token each time."""

    def __init__(self, jira: FakeJiraWorkflow) -> None:
        self.jira = jira
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}

    def call(self, method: str, path: str, body: Any = None, params: Any = None) -> ApiReply:
        self.calls.append((method, path))
        if (status := self.fail.get(f"{method} {path}")) is not None:
            return ApiReply(status, {})
        reply = self.jira.request(
            method, f"/rest/api/3{path}", auth=self.jira.new_bearer(), params=params, json=body
        )
        return ApiReply(reply.status, reply.body)

    def count(self, method: str, path: str) -> int:
        return self.calls.count((method, path))


class Alerts:
    def __init__(self) -> None:
        self.fired: list[tuple[str, str, dict[str, Any]]] = []

    def alert(self, name: str, message: str, **details: Any) -> None:
        self.fired.append((name, message, details))

    def names(self) -> list[str]:
        return [n for n, _, _ in self.fired]


class Rig:
    def __init__(
        self, projects: Mapping[str, str] | None = None, jira: FakeJiraWorkflow | None = None
    ) -> None:
        self.jira = jira or FakeJiraWorkflow()
        self.api = FakeApi(self.jira)
        self.alerts = Alerts()
        self.metrics = Metrics()
        self.gaps: list[str] = []
        self.bindings = ProjectBindings()
        for team, project in (projects or {"team-a": "SYN"}).items():
            self.bindings.bind(team, project)
        self.store = MemoryStore()
        self.job = SiteWebhooks(
            SITE,
            URL,
            self.store,
            self.api,
            self.bindings,
            self.alerts,
            self.metrics,
            clock=lambda: self.jira.now,
            on_gap=self.gaps.append,
        )

    @classmethod
    def sharing(cls, other: Rig, projects: Mapping[str, str]) -> Rig:
        """Another install of the same app, on the same Jira tenant: its own record and bindings."""
        return cls(projects, jira=other.jira)

    def listed(self) -> list[dict[str, Any]]:
        return list(
            self.jira.request("GET", "/rest/api/3/webhook", auth=self.jira.new_bearer()).body[
                "values"
            ]
        )

    def ids(self) -> list[int]:
        return [h["id"] for h in self.listed()]

    def foreign(self, jql: str = "project = X") -> int:
        """A webhook registered by someone else (another install of the app, or by hand)."""
        return self.register(jql, own=False)

    def register(self, jql: str, own: bool = True, events: list[str] | None = None) -> int:
        body = {
            "url": URL,
            "webhooks": [{"events": events or sorted(SUBSCRIBED_EVENTS), "jqlFilter": jql}],
        }
        reply = self.api.call("POST", "/webhook", body)
        (entry,) = reply.body["webhookRegistrationResult"]
        ident = int(entry["createdWebhookId"])
        if own:
            self.job._own({ident})
        return ident


def test_the_first_run_registers_one_webhook_for_the_bound_projects() -> None:
    rig = Rig({"team-a": "SYN", "team-b": "OTH"})
    report = rig.job.sync()
    (hook,) = rig.listed()
    assert hook["jqlFilter"] == "project in (OTH, SYN)"
    assert set(hook["events"]) == {
        "jira:issue_created",
        "jira:issue_updated",
        "jira:issue_deleted",
        "comment_created",
        "comment_updated",
        "comment_deleted",
    }
    assert report.registered == 1
    assert report.refreshed == 0


def test_many_teams_on_one_site_stay_within_the_limit() -> None:
    rig = Rig({f"team-{i}": f"P{i}" for i in range(40)})
    rig.job.sync()
    assert len(rig.ids()) == 1
    assert len(rig.ids()) < 5  # the per-app, per-user limit
    for i in range(40, 80):  # more teams join over time
        rig.bindings.bind(f"team-{i}", f"P{i}")
        rig.jira.now += DAY
        rig.job.sync()
        assert len(rig.ids()) == 1
    (hook,) = rig.listed()
    assert hook["jqlFilter"].count(",") == 79


def test_a_changed_binding_replaces_the_registration_without_a_gap() -> None:
    rig = Rig()
    rig.job.sync()
    (old,) = rig.ids()
    rig.bindings.bind("team-b", "OTH")
    report = rig.job.sync()
    (new,) = rig.ids()
    assert new != old
    assert report.registered == 1
    assert report.deleted == 1
    # registered before the old one was deleted, so no event window is uncovered
    calls = rig.api.calls
    assert calls.index(("POST", "/webhook")) < len(calls) - 1 - calls[::-1].index(
        ("DELETE", "/webhook")
    )


def test_two_teams_on_one_project_share_it_and_both_receive_its_tickets() -> None:
    rig = Rig({"team-a": "SYN", "team-b": "SYN", "team-c": "OTH"})
    rig.job.sync()
    (hook,) = rig.listed()
    assert hook["jqlFilter"] == "project in (OTH, SYN)"
    assert rig.bindings.teams_for("SYN") == frozenset({"team-a", "team-b"})
    assert rig.bindings.teams_for("OTH") == frozenset({"team-c"})


def test_a_project_nobody_is_bound_to_routes_nowhere() -> None:
    rig = Rig()
    assert rig.bindings.teams_for("ZZZ") == frozenset()
    assert rig.bindings.teams_for("syn") == frozenset()  # keys are upper case, exactly


def test_unbinding_the_last_team_removes_the_registration() -> None:
    rig = Rig()
    rig.job.sync()
    rig.bindings.unbind("team-a")
    report = rig.job.sync()
    assert rig.ids() == []
    assert report.deleted == 1
    assert rig.job.sync().registered == 0  # and nothing is registered for nobody


def test_a_second_run_with_nothing_changed_makes_no_writes() -> None:
    rig = Rig()
    rig.job.sync()
    before = list(rig.api.calls)
    report = rig.job.sync()
    assert (report.registered, report.refreshed, report.deleted) == (0, 0, 0)
    assert [c for c in rig.api.calls[len(before) :] if c[0] != "GET"] == []


@pytest.mark.parametrize(
    "project", ["", "syn", "SYN)", "SYN, X", "S YN", "SYN\n", "1SYN", 'S"', "A" * 11, "S-1"]
)
def test_a_project_key_that_could_alter_the_filter_is_refused(project: str) -> None:
    with pytest.raises(ValueError, match="project key"):
        ProjectBindings().bind("t", project)
    with pytest.raises(ValueError, match="project key"):
        webhook_jql([project])


def test_the_filter_is_sorted_and_deduplicated() -> None:
    assert webhook_jql(["BB", "AA", "BB"]) == "project in (AA, BB)"
    with pytest.raises(ValueError, match="at least one project"):
        webhook_jql([])


def test_another_registration_of_the_app_counts_against_the_limit_and_alerts() -> None:
    rig = Rig()
    foreign = [rig.foreign(f"project = X{i}") for i in range(5)]  # someone filled the five slots
    with pytest.raises(WebhookLimitError):
        rig.job.sync()
    assert "jira.webhook.limit" in rig.alerts.names()
    assert rig.ids() == foreign  # and not one of theirs was touched


# --- the refresh job, on a fake clock -------------------------------------------------------------


def test_the_job_refreshes_well_inside_thirty_days() -> None:
    rig = Rig()
    rig.job.sync()
    (hook,) = rig.listed()
    expiry = hook["expirationDate"] / 1000
    rig.jira.now += 5 * DAY
    assert rig.job.sync().refreshed == 0  # plenty of life left: no write
    rig.jira.now += 6 * DAY  # 11 days old
    assert rig.job.sync().refreshed == 1
    (hook,) = rig.listed()
    assert hook["expirationDate"] / 1000 == rig.jira.now + 30 * DAY > expiry


def test_a_daily_job_over_a_year_never_lets_the_webhook_expire() -> None:
    rig = Rig()
    ident = None
    refreshes = 0
    for _ in range(365):
        report = rig.job.sync()
        refreshes += report.refreshed
        (hook,) = rig.listed()
        ident = ident or hook["id"]
        assert hook["id"] == ident  # refreshed in place, never re-registered
        assert hook["expirationDate"] / 1000 - rig.jira.now >= 18 * DAY
        rig.jira.now += DAY
    assert rig.alerts.fired == []
    assert rig.gaps == []
    assert 30 <= refreshes <= 40  # about every 10 days


def test_a_weekly_job_is_still_inside_the_expiry() -> None:
    rig = Rig()
    for _ in range(60):
        rig.job.sync()
        rig.jira.now += 7 * DAY
    assert rig.alerts.fired == []


def test_the_refresh_asks_for_every_webhook_of_the_site_in_one_call() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 12 * DAY
    rig.job.sync()
    assert rig.api.count("PUT", "/webhook/refresh") == 1


def test_a_failed_refresh_is_transient_and_alerts_nobody_yet() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 12 * DAY
    rig.api.fail["PUT /webhook/refresh"] = 503
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.alerts.fired == []
    del rig.api.fail["PUT /webhook/refresh"]
    assert rig.job.sync().refreshed == 1


def test_a_refresh_refused_for_credentials_is_permanent() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 12 * DAY
    rig.api.fail["PUT /webhook/refresh"] = 401
    with pytest.raises(PermanentError):
        rig.job.sync()


def test_a_listing_that_fails_is_an_error_never_an_empty_list() -> None:
    rig = Rig()
    rig.job.sync()
    rig.api.fail["GET /webhook"] = 500
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.api.count("POST", "/webhook") == 1  # nothing was registered on a guess


# --- expiry: an expired webhook alerts, and the reconciler covers the gap -------------------------


def test_an_expired_webhook_alerts_and_asks_the_reconciler_to_sweep() -> None:
    rig = Rig()
    rig.job.sync()
    (old,) = rig.ids()
    rig.jira.now += 31 * DAY  # the job did not run
    report = rig.job.sync()
    assert "jira.webhook.expired" in rig.alerts.names()
    name, message, details = rig.alerts.fired[0]
    assert SITE in message
    assert details["ids"] == [old]
    assert details["site"] == SITE
    assert rig.gaps == [SITE]
    assert report.expired == 1
    assert report.registered == 1
    (new,) = rig.ids()
    assert new != old
    assert rig.jira.webhook_expired(old) or old not in rig.ids()


def test_the_expired_one_is_deleted_so_it_stops_counting_against_the_limit() -> None:
    rig = Rig()
    rig.job.sync()
    for _ in range(3):
        rig.jira.now += 31 * DAY
        rig.job.sync()
    assert len(rig.ids()) == 1


def test_an_alert_for_each_expiry_not_one_per_run() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 31 * DAY
    rig.job.sync()
    rig.jira.now += DAY
    rig.job.sync()
    assert rig.alerts.names() == ["jira.webhook.expired"]
    assert rig.metrics.names().count("webhook.expired") == 1


def test_a_site_whose_webhook_vanished_is_registered_again_with_a_gap() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.clear_webhooks()  # deleted by an admin, or purged
    report = rig.job.sync()
    assert report.registered == 1
    assert rig.gaps == [SITE]
    assert "jira.webhook.missing" in rig.alerts.names()


def test_a_first_registration_is_not_a_gap() -> None:
    rig = Rig()
    rig.job.sync()
    assert rig.gaps == []
    assert rig.alerts.fired == []


def test_a_failing_gap_callback_does_not_hide_the_registration() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 31 * DAY

    def boom(site: str) -> None:
        raise RuntimeError("reconciler down")

    rig.job._on_gap = boom
    rig.job.sync()
    assert len(rig.ids()) == 1
    assert "webhook.gap_failed" in rig.metrics.names()


# --- mutation pass: boundaries and paging the first tests missed ----------------------------


def test_a_webhook_with_exactly_twenty_days_left_is_refreshed() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 10 * DAY
    assert rig.job.sync().refreshed == 1


def test_a_webhook_whose_expiry_is_this_very_second_is_expired() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 30 * DAY
    assert rig.job.sync().expired == 1
    assert rig.alerts.names() == ["jira.webhook.expired"]


def test_the_filter_lists_projects_in_sorted_order_whatever_the_hash_seed() -> None:
    keys = [f"{a}{b}" for a in "ZQMCA" for b in "XLDB"]
    assert webhook_jql(keys) == f"project in ({', '.join(sorted(keys))})"


def test_every_page_of_the_listing_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sto.adapters.jira.webhooks.PAGE", 2)
    rig = Rig()
    rig.job.sync()
    for _ in range(3):  # three doubles of our own registration, beyond the first page of two
        rig.register("project in (SYN)")
    assert len(rig.ids()) == 4
    rig.job.sync()
    assert len(rig.ids()) == 1


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503])
def test_a_retryable_status_is_transient(status: int) -> None:
    rig = Rig()
    rig.api.fail["GET /webhook"] = status
    with pytest.raises(TransientError):
        rig.job.sync()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409])
def test_any_other_refusal_is_permanent(status: int) -> None:
    rig = Rig()
    rig.api.fail["GET /webhook"] = status
    with pytest.raises(PermanentError):
        rig.job.sync()


# --- review pass 1: bearer claims ---------------------------------------------------------------


def bearer_headers(claims: Mapping[str, Any] | None, ident: str = "i-1") -> dict[str, str]:
    auth = "Bearer " + token({"alg": "HS256"}, claims=claims)
    return {"x-atlassian-webhook-identifier": ident, "authorization": auth}


def claims_at(**over: Any) -> dict[str, Any]:
    return {"iss": ISSUER, "iat": int(T0) - 10, "exp": int(T0) + 290} | over


def test_a_token_with_fresh_claims_for_our_app_is_accepted() -> None:
    assert make_verifier(None).verify(bearer_headers(claims_at()), issue_body()) == "i-1"


@pytest.mark.parametrize(
    "claims",
    [
        claims_at(iss="some-other-app"),
        {"iat": int(T0) - 10, "exp": int(T0) + 290},  # no iss
        {"iss": ISSUER, "exp": int(T0) + 290},  # no iat
        {"iss": ISSUER, "iat": int(T0) - 10},  # no exp
        {},
        claims_at(iss=7),
        claims_at(iat="1767226600"),
        claims_at(exp=True),
        claims_at(iat=float("nan")),
        claims_at(aud="elsewhere", iat=1_000_000_000, exp=1_000_000_300),  # 2001, expired
        claims_at(iat=int(T0) - int(TOKEN_MAX_AGE) - 1, exp=int(T0) + 290),  # too old to be a retry
        claims_at(iat=int(T0) + 301, exp=int(T0) + 900),  # from the future
        claims_at(exp=int(T0) - 10_000),  # long expired, and before its own iat
        claims_at(exp=int(T0) - 10),  # exp equal to iat: not after it
        claims_at(iat=int(T0) - 2_000, exp=int(T0) - 5_000),  # exp before iat
        claims_at(iat=int(T0) - 5_300, exp=int(T0) - 4_900),  # exp older than the retry span + skew
    ],
    ids=lambda c: "-".join(sorted(c)) or "empty",
)
def test_a_token_whose_claims_are_missing_wrong_old_or_early_is_refused(
    claims: dict[str, Any],
) -> None:
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(bearer_headers(claims), issue_body())


@pytest.mark.parametrize("claims_json", [b"[]", b"7", b"not json", b'"text"'])
def test_claims_that_are_not_an_object_are_refused(claims_json: bytes) -> None:
    head = b64(json.dumps({"alg": "HS256"}).encode())
    claims = b64(claims_json)
    mac = hmac.new(CLIENT_SECRET, f"{head}.{claims}".encode(), hashlib.sha256).digest()
    headers = {
        "x-atlassian-webhook-identifier": "i-1",
        "authorization": f"Bearer {head}.{claims}.{b64(mac)}",
    }
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(headers, issue_body())


def test_the_freshness_limits_are_inclusive() -> None:
    oldest_iat = claims_at(iat=int(T0) - int(TOKEN_MAX_AGE), exp=int(T0) - 4_000)
    oldest_exp = claims_at(iat=int(T0) - 5_100, exp=int(T0) - 4_800)  # retry span + skew exactly
    earliest = claims_at(iat=int(T0) + 300, exp=int(T0) + 600)
    for claims in (oldest_iat, oldest_exp, earliest):
        assert make_verifier(None).verify(bearer_headers(claims), issue_body()) == "i-1"


def test_a_captured_token_stops_working_once_it_is_older_than_the_retry_span() -> None:
    """One leaked token no longer works forever, or on a body and identifier of the attacker's."""
    w = World()
    auth = w.hooks.bearer_event(w.key).headers["Authorization"]
    evil = RawWebhook({IDENT: "attacker-1", "Authorization": auth}, issue_body("VICTIM-42"))
    w.jira.now += TOKEN_MAX_AGE + 1
    with pytest.raises(InvalidSignatureError):
        w.receiver.receive(evil)
    assert w.queue.items == []
    # ... and so it cannot squat the identifier of the next genuine delivery either
    nxt = w.hooks.admin_event(w.key)
    squat = RawWebhook({IDENT: nxt.headers[IDENT], "Authorization": auth}, issue_body("J-1"))
    with pytest.raises(InvalidSignatureError):
        w.receiver.receive(squat)
    assert w.receiver.receive(nxt) is not None


def test_a_token_for_another_app_is_refused_by_the_receiver() -> None:
    w = World()
    other = w.fresh(app_issuer="a-different-app")
    with pytest.raises(InvalidSignatureError):
        other.receive(w.hooks.bearer_event(w.key))


def test_the_cross_site_replay_is_bounded_only_by_freshness() -> None:
    """The fake's token names no site, tenant or audience, so a FRESH token from site 1 does pass
    at site 2 with a body of the attacker's. That is listed for D12; what is pinned here is that
    it lapses (above), that the body is not queued, and that only the issue key leaves it."""
    w1, w2 = World(), World("site-2")
    auth = w1.hooks.bearer_event(w1.key).headers["Authorization"]
    raw = RawWebhook({IDENT: "attacker-3", "Authorization": auth}, issue_body("OTHER-1"))
    assert w2.receiver.receive(raw) is not None
    (nudge,) = w2.queue.items
    assert nudge.body == b""
    assert nudge.body_omitted is True


def test_the_slowest_retry_schedule_is_accepted_in_the_bearer_form_too() -> None:
    """The same token and bytes come back 75 minutes later: its exp (iat + 5 min) is long past, and
    that is a genuine retry, not an expired token."""
    w = World()
    raw = w.hooks.bearer_event(w.key)
    attempts = {"n": 0}

    def post(sent: RawWebhook) -> int:
        attempts["n"] += 1
        return 503 if attempts["n"] < 6 else w.post(sent)

    w.hooks._rng.randint = lambda lo, hi: hi  # type: ignore[assignment,method-assign]
    report = w.hooks.deliver(post, raw)
    assert report.delivered
    assert len(report.attempts) == 6
    assert report.attempts[-1].at - report.attempts[0].at == 75 * 60
    assert len(w.queue.items) == 1


def test_a_valid_token_under_another_scheme_is_refused() -> None:
    headers = bearer_headers(claims_at())
    headers["authorization"] = headers["authorization"].replace("Bearer ", "Basic ")
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(headers, issue_body())


# --- review pass 1: what the bearer form queues -------------------------------------------------


def test_a_bearer_delivery_is_queued_without_its_body() -> None:
    w = World()
    raw = w.hooks.bearer_event(w.key)
    assert w.post(raw) == 202
    (nudge,) = w.queue.items
    assert nudge.body_omitted is True
    assert nudge.body == b""
    assert nudge.body_size == len(raw.body)
    assert nudge.reread is True


def test_an_attacker_body_under_a_captured_bearer_token_reaches_nobody() -> None:
    w = World()
    auth = w.hooks.bearer_event(w.key).headers["Authorization"]
    evil = issue_body("VICTIM-42", fields={"status": {"name": "Done"}}, approved=True)
    assert w.receiver.receive(RawWebhook({IDENT: "attacker-4", "Authorization": auth}, evil))
    (nudge,) = w.queue.items
    assert evil not in (nudge.body, json.dumps(dict(nudge.headers)).encode())
    assert b"approved" not in json.dumps(dict(nudge.headers)).encode()


def test_an_admin_delivery_still_carries_its_body() -> None:
    w = World()
    raw = w.hooks.admin_event(w.key)
    w.post(raw)
    (nudge,) = w.queue.items
    assert nudge.body == raw.body
    assert nudge.body_omitted is False


# --- review pass 1: issue keys with trailing junk -----------------------------------------------


@pytest.mark.parametrize("key", ["SYN-1x", "SYN-1 OR x", "SYN-1\n", "SYN-1;", " SYN-1", "SYN-1-2"])
def test_an_issue_key_with_trailing_junk_is_refused(key: str) -> None:
    with pytest.raises(MalformedWebhookError):
        parse_event(issue_body(key))


# --- review pass 1: the job touches only what it registered -------------------------------------


def test_webhooks_someone_else_registered_are_never_deleted() -> None:
    rig = Rig()
    theirs = [rig.foreign(), rig.foreign("project = Y")]
    report = rig.job.sync()
    assert report.registered == 1
    assert report.deleted == 0
    assert set(theirs) <= set(rig.ids())
    rig.bindings.bind("team-b", "OTH")
    assert rig.job.sync().deleted == 1  # our own stale one
    assert set(theirs) <= set(rig.ids())
    assert len(rig.ids()) == 3


def test_a_foreign_webhook_is_never_refreshed_replaced_or_alerted_on_either() -> None:
    rig = Rig()
    (theirs,) = [rig.foreign()]
    rig.job.sync()
    rig.jira.now += 31 * DAY  # theirs and ours both lapse
    rig.job.sync()
    assert theirs in rig.ids()  # an expired foreign hook is left for its owner
    assert rig.alerts.fired[0][2]["ids"] != [theirs]
    assert theirs not in rig.alerts.fired[0][2]["ids"]
    assert rig.api.count("PUT", "/webhook/refresh") == 0


def test_two_installs_sharing_an_app_do_not_delete_each_others_hooks() -> None:
    a = Rig({"team-a": "SYN"})
    b = Rig.sharing(a, {"team-b": "OTH"})
    a.job.sync()
    b.job.sync()
    assert len(a.ids()) == 2
    for _ in range(3):
        a.jira.now += 12 * DAY
        a.job.sync()
        b.job.sync()
    a.bindings.bind("team-c", "NEW")
    a.job.sync()
    assert len(a.ids()) == 2
    assert {h["jqlFilter"] for h in a.listed()} == {"project in (NEW, SYN)", "project in (OTH)"}
    b.bindings.unbind("team-b")
    b.job.sync()
    assert {h["jqlFilter"] for h in a.listed()} == {"project in (NEW, SYN)"}


def test_the_record_lists_exactly_the_ids_this_job_registered() -> None:
    rig = Rig()
    theirs = rig.foreign()
    rig.job.sync()
    mine = {i for i in rig.ids() if i != theirs}
    assert rig.job._owned() == mine
    rig.job.sync()
    assert rig.job._owned() == mine


def test_a_doubled_registration_of_our_own_is_reduced_to_one() -> None:
    rig = Rig()
    rig.job.sync()
    rig.register("project in (SYN)")  # a second of ours, as after a crashed run
    assert len(rig.ids()) == 2
    report = rig.job.sync()
    assert report.deleted == 1
    assert len(rig.ids()) == 1
    assert len(rig.job._owned()) == 1


def test_a_record_that_keeps_changing_is_a_transient_error() -> None:
    from sto.store.ports import ConditionFailedError

    rig = Rig()

    class Racing(MemoryStore):
        def put(self, *a: Any, **k: Any) -> Any:
            raise ConditionFailedError([0])

    rig.job._store = Racing()
    with pytest.raises(TransientError):
        rig.job.sync()


# --- review pass 1: at the limit ----------------------------------------------------------------


def test_at_the_limit_a_binding_change_frees_our_own_stale_hook_and_registers() -> None:
    rig = Rig()
    rig.job.sync()
    theirs = [rig.foreign(f"project = X{i}") for i in range(4)]  # five in all: the limit
    rig.bindings.bind("team-b", "OTH")
    report = rig.job.sync()
    assert report.registered == 1
    assert report.deleted == 1
    assert set(theirs) <= set(rig.ids())
    assert len(rig.ids()) == 5
    assert "jira.webhook.limit" not in rig.alerts.names()
    assert rig.job.sync().registered == 0  # and the next day is quiet


def test_at_the_limit_with_nothing_of_ours_to_free_it_alerts_and_changes_nothing() -> None:
    rig = Rig()
    theirs = [rig.foreign(f"project = X{i}") for i in range(5)]
    for _ in range(3):
        with pytest.raises(WebhookLimitError):
            rig.job.sync()
        rig.jira.now += DAY
    assert rig.ids() == theirs
    assert rig.alerts.names().count("jira.webhook.limit") == 3


def test_a_stale_hook_is_refreshed_before_it_is_replaced() -> None:
    """A working hook due for refresh is refreshed in the same run that replaces it, so a refusal
    to register cannot leave it to lapse."""
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 11 * DAY
    rig.bindings.bind("team-b", "OTH")
    calls_before = len(rig.api.calls)
    report = rig.job.sync()
    assert report.refreshed == 1
    assert report.registered == 1
    order = [c for c in rig.api.calls[calls_before:] if c[0] != "GET"]
    assert order[0] == ("PUT", "/webhook/refresh")
    assert order.index(("POST", "/webhook")) < order.index(("DELETE", "/webhook"))


def test_a_refused_registration_does_not_stop_the_refresh_of_the_working_hook() -> None:
    rig = Rig()
    rig.job.sync()
    (mine,) = rig.ids()
    for i in range(4):
        rig.foreign(f"project = X{i}")
    rig.jira.now += 12 * DAY
    rig.bindings.bind("team-b", "OTH")
    rig.api.fail["POST /webhook"] = 500  # registration keeps failing
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.jira.webhook_expiry(mine) == rig.jira.now + 30 * DAY  # refreshed all the same


# --- review pass 1: unbinding everything --------------------------------------------------------


def test_unbinding_every_team_and_binding_one_again_is_not_a_gap() -> None:
    rig = Rig()
    rig.job.sync()
    rig.bindings.unbind("team-a")
    rig.job.sync()
    rig.bindings.bind("team-z", "ZZ")
    report = rig.job.sync()
    assert report.registered == 1
    assert rig.alerts.fired == []
    assert rig.gaps == []
    assert rig.job._owned() == set(rig.ids())


def test_unbinding_clears_the_record_even_when_jira_lost_our_hook_first() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.clear_webhooks()
    rig.bindings.unbind("team-a")
    rig.job.sync()
    assert rig.job._owned() == set()
    rig.bindings.bind("team-z", "ZZ")
    rig.job.sync()
    assert rig.gaps == []


def test_a_vanished_hook_is_dropped_from_the_record() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.clear_webhooks()
    rig.job.sync()
    assert rig.job._owned() == set(rig.ids())


# --- review pass 1: what Jira's listing may hold ------------------------------------------------


class Mangled(FakeApi):
    def __init__(self, jira: FakeJiraWorkflow, mangle: Callable[[dict[str, Any]], None]) -> None:
        super().__init__(jira)
        self.mangle = mangle

    def call(self, method: str, path: str, body: Any = None, params: Any = None) -> ApiReply:
        reply = super().call(method, path, body, params)
        if (method, path) == ("GET", "/webhook"):
            for hook in reply.body["values"]:
                self.mangle(hook)
        return reply


@pytest.mark.parametrize(
    "mangle",
    [
        lambda h: h.pop("expirationDate"),
        lambda h: h.update(expirationDate="soon"),
        lambda h: h.update(expirationDate=None),
        lambda h: h.update(expirationDate=True),
    ],
    ids=["missing", "text", "null", "bool"],
)
def test_a_listing_without_a_usable_expiry_is_a_permanent_error(
    mangle: Callable[[dict[str, Any]], None],
) -> None:
    rig = Rig()
    rig.job.sync()
    rig.api = Mangled(rig.jira, mangle)
    rig.job._api = rig.api
    with pytest.raises(PermanentError):
        rig.job.sync()


@pytest.mark.parametrize("ident", [None, "7", True, 1.5])
def test_a_listing_with_a_hook_that_has_no_integer_id_is_a_permanent_error(ident: Any) -> None:
    rig = Rig()
    rig.job.sync()
    rig.job._api = Mangled(rig.jira, lambda h: h.update(id=ident))
    with pytest.raises(PermanentError):
        rig.job.sync()


# --- review pass 2: a gap must not be lost ------------------------------------------------------


def stub_posts(rig: Rig, reply: Any) -> None:
    """Every POST /webhook gets ``reply`` (a body, answered 200); everything else is real."""
    real = rig.api.call

    def call(method: str, path: str, body: Any = None, params: Any = None) -> ApiReply:
        if (method, path) == ("POST", "/webhook"):
            return ApiReply(200, reply)
        return real(method, path, body, params)

    rig.job._api = type("Stub", (), {"call": staticmethod(call)})()


def refusal(*errors: str) -> dict[str, Any]:
    return {"webhookRegistrationResult": [{"errors": list(errors)}]}


def test_an_expiry_then_a_refused_registration_still_tells_the_reconciler() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 31 * DAY
    stub_posts(rig, refusal("The JQL query is invalid"))
    with pytest.raises(WebhookRefusedError):
        rig.job.sync()
    assert rig.gaps == [SITE]
    rig.job._api = rig.api
    rig.job.sync()
    assert len(rig.ids()) == 1
    assert rig.gaps == [SITE]  # told once, acknowledged, not told again


def test_an_expiry_then_a_failed_registration_still_tells_the_reconciler() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 31 * DAY
    rig.api.fail["POST /webhook"] = 503
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.gaps == [SITE]
    del rig.api.fail["POST /webhook"]
    rig.job.sync()
    assert len(rig.ids()) == 1
    assert rig.gaps == [SITE]
    assert rig.alerts.names() == ["jira.webhook.expired"]  # and no spurious "missing"


def test_a_vanished_hook_then_a_failed_registration_still_tells_the_reconciler() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.clear_webhooks()
    rig.api.fail["POST /webhook"] = 503
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.gaps == [SITE]
    assert rig.alerts.names() == ["jira.webhook.missing"]
    del rig.api.fail["POST /webhook"]
    rig.job.sync()
    assert rig.gaps == [SITE]
    assert len(rig.ids()) == 1


def test_a_gap_the_reconciler_did_not_acknowledge_is_told_again_next_run() -> None:
    rig = Rig()
    rig.job.sync()
    rig.jira.clear_webhooks()
    calls: list[str] = []

    def flaky(site: str) -> None:
        calls.append(site)
        if len(calls) < 3:
            raise RuntimeError("reconciler down")

    rig.job._on_gap = flaky
    rig.api.fail["POST /webhook"] = 503
    with pytest.raises(TransientError):
        rig.job.sync()
    del rig.api.fail["POST /webhook"]
    rig.job.sync()  # told again at the start of this run: still down
    rig.job.sync()  # and again: acknowledged now
    assert len(calls) == 3
    rig.job.sync()
    assert len(calls) == 3  # the note is cleared once acknowledged
    assert "webhook.gap_failed" in rig.metrics.names()


# --- review pass 2: only a limit may cost us our working hook -----------------------------------


def test_a_refusal_that_is_not_the_limit_keeps_the_working_hook() -> None:
    rig = Rig()
    rig.job.sync()
    (working,) = rig.ids()
    rig.bindings.bind("team-b", "OTH")
    stub_posts(rig, refusal("The JQL query is invalid"))
    with pytest.raises(WebhookRefusedError) as caught:
        rig.job.sync()
    assert not isinstance(caught.value, WebhookLimitError)
    assert rig.ids() == [working]
    assert rig.alerts.names() == ["jira.webhook.refused"]
    assert rig.gaps == []


def test_a_retry_at_the_limit_that_still_fails_has_told_the_reconciler_first() -> None:
    rig = Rig()
    rig.job.sync()
    theirs = [rig.foreign(f"project = X{i}") for i in range(4)]  # five in all: the limit
    rig.bindings.bind("team-b", "OTH")
    stub_posts(rig, refusal("Jira will not take it"))  # even our old filter, in the freed slot
    with pytest.raises(WebhookRefusedError):
        rig.job.sync()
    assert rig.ids() == theirs
    assert rig.gaps == [SITE]


# --- review pass 2: a hook a concurrent run registers -------------------------------------------


def test_a_hook_registered_by_a_concurrent_run_is_neither_dropped_nor_a_gap() -> None:
    rig = Rig()
    other = Rig.sharing(rig, {"team-a": "SYN"})
    other.store = rig.store
    other.job._store = rig.store
    rig.bindings.bind("team-b", "OTH")
    other.bindings.bind("team-b", "OTH")
    real_list = rig.job._list

    def racing_list() -> list[dict[str, Any]]:
        listed = real_list()
        other.job.sync()  # the other run finishes after our listing was taken
        return listed

    rig.job._list = racing_list  # type: ignore[method-assign]
    rig.job.sync()
    assert rig.alerts.fired == []
    assert rig.gaps == []
    assert set(rig.ids()) == rig.job._owned()  # nothing orphaned
    rig.job._list = real_list  # type: ignore[method-assign]
    rig.job.sync()  # the doubled one converges to one
    assert len(rig.ids()) == 1
    assert set(rig.ids()) == rig.job._owned()


def test_the_record_is_read_before_the_listing() -> None:
    rig = Rig()
    order: list[str] = []
    real_owned, real_list = rig.job._owned, rig.job._list

    def owned() -> set[int]:
        order.append("record")
        return real_owned()

    def listed() -> list[dict[str, Any]]:
        order.append("list")
        return real_list()

    rig.job._owned = owned  # type: ignore[method-assign]
    rig.job._list = listed  # type: ignore[method-assign]
    rig.job.sync()
    assert order[:2] == ["record", "list"]


# --- review pass 2: odd answers from Jira -------------------------------------------------------


@pytest.mark.parametrize(
    "reply",
    [
        {},
        None,
        [],
        {"webhookRegistrationResult": []},
        {"webhookRegistrationResult": [{}, {}]},
        {"webhookRegistrationResult": None},
        {"webhookRegistrationResult": [1]},
        {"webhookRegistrationResult": [{}]},
        {"webhookRegistrationResult": [{"errors": "x"}]},
        {"webhookRegistrationResult": [{"errors": [1]}]},
        {"webhookRegistrationResult": [{"errors": []}]},
        {"webhookRegistrationResult": [{"errors": None}]},
        {"webhookRegistrationResult": [{"createdWebhookId": True}]},
        {"webhookRegistrationResult": [{"createdWebhookId": "7"}]},
    ],
    ids=repr,
)
def test_an_unexpected_registration_reply_is_a_permanent_error(reply: Any) -> None:
    rig = Rig()
    stub_posts(rig, reply)
    with pytest.raises(PermanentError):
        rig.job.sync()


def test_a_listing_with_null_events_is_replaced_not_a_crash() -> None:
    rig = Rig()
    rig.job.sync()
    rig.job._api = Mangled(rig.jira, lambda h: h.update(events=None))
    assert rig.job.sync().registered == 1


def test_a_boolean_in_the_record_is_not_an_id() -> None:
    rig = Rig()
    rig.store.put(PLATFORM, Key("ORG", f"JIRAHOOK#{SITE}"), {"site": SITE, "ids": [True, 5]})
    assert rig.job._owned() == {5}


# --- review pass 2: the record's compare-and-set and the same-run delete ------------------------


def test_a_record_write_that_loses_a_race_once_is_retried() -> None:
    rig = Rig()

    class Flaky(MemoryStore):
        failed = False

        def put(self, *a: Any, **k: Any) -> Any:
            if not self.failed and a[1].sk.startswith("JIRAHOOK#"):
                self.failed = True
                raise ConditionFailedError([0])
            return super().put(*a, **k)

    store = Flaky()
    rig.job._store = store
    rig.job.sync()
    assert store.failed
    assert rig.job._owned() == set(rig.ids())
    assert len(rig.ids()) == 1


def test_ids_we_delete_leave_the_record_in_the_same_run() -> None:
    rig = Rig()
    rig.job.sync()
    rig.bindings.bind("team-b", "OTH")
    rig.job.sync()
    assert rig.job._owned() == set(rig.ids())
    assert len(rig.ids()) == 1
    rig.jira.now += 31 * DAY
    rig.api.fail["POST /webhook"] = 503
    with pytest.raises(TransientError):
        rig.job.sync()
    assert rig.job._owned() == set()  # the expired one was deleted, and so is gone from the record


# --- review pass 2: token numbers and keys ------------------------------------------------------


def raw_token(claims_json: str, header: str = '{"alg":"HS256"}') -> str:
    head, body = b64(header.encode()), b64(claims_json.encode())
    mac = hmac.new(CLIENT_SECRET, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(mac)}"


def raw_headers(auth_token: str) -> dict[str, str]:
    return {"x-atlassian-webhook-identifier": "i-1", "authorization": f"Bearer {auth_token}"}


@pytest.mark.parametrize(
    "stamp",
    ["1" + "0" * 400, "-1" + "0" * 400, "Infinity", "-Infinity", "NaN", "1e999", "-1e999"],
)
@pytest.mark.parametrize("which", ["iat", "exp"])
def test_a_token_number_that_is_not_a_finite_float_is_a_rejection_not_a_crash(
    which: str, stamp: str
) -> None:
    fresh = {"iat": str(int(T0) - 10), "exp": str(int(T0) + 290)} | {which: stamp}
    claims = f'{{"iss":"{ISSUER}","iat":{fresh["iat"]},"exp":{fresh["exp"]}}}'
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(raw_headers(raw_token(claims)), issue_body())


def test_an_overflowing_token_number_is_a_401_at_the_receiver_not_a_500() -> None:
    w = World()
    claims = f'{{"iss":"{ISSUER}","iat":1{"0" * 400},"exp":{int(w.jira.now) + 290}}}'
    raw = RawWebhook(raw_headers(raw_token(claims)), issue_body())
    with pytest.raises(InvalidSignatureError):
        w.receiver.receive(raw)
    assert w.queue.items == []


def test_a_token_with_a_duplicate_claim_is_refused() -> None:
    claims = f'{{"iss":"other","iss":"{ISSUER}","iat":{int(T0) - 10},"exp":{int(T0) + 290}}}'
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(raw_headers(raw_token(claims)), issue_body())
    claims = f'{{"iss":"{ISSUER}","iat":{int(T0) - 10},"exp":{int(T0) + 290}}}'
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(
            raw_headers(raw_token(claims, '{"alg":"none","alg":"HS256"}')), issue_body()
        )


def test_the_exp_edge_is_80_minutes_with_literal_numbers() -> None:
    """The retry span (75 min) plus skew (5 min): 4800 s accepted, 4801 s refused."""
    ok = {"iss": ISSUER, "iat": int(T0) - 5_100, "exp": int(T0) - 4_800}
    late = {"iss": ISSUER, "iat": int(T0) - 5_100, "exp": int(T0) - 4_801}
    assert make_verifier(None).verify(bearer_headers(ok), issue_body()) == "i-1"
    with pytest.raises(InvalidSignatureError):
        make_verifier(None).verify(bearer_headers(late), issue_body())


def test_the_iat_edge_is_90_minutes_with_literal_numbers() -> None:
    """5400 s accepted, 5401 s refused, and 300 s ahead accepted, 301 s refused."""
    for age, accepted in ((5_400, True), (5_401, False)):
        claims = {"iss": ISSUER, "iat": int(T0) - age, "exp": int(T0) - 4_700}
        if accepted:
            assert make_verifier(None).verify(bearer_headers(claims), issue_body()) == "i-1"
        else:
            with pytest.raises(InvalidSignatureError):
                make_verifier(None).verify(bearer_headers(claims), issue_body())
    for ahead, accepted in ((300, True), (301, False)):
        claims = {"iss": ISSUER, "iat": int(T0) + ahead, "exp": int(T0) + 900}
        if accepted:
            assert make_verifier(None).verify(bearer_headers(claims), issue_body()) == "i-1"
        else:
            with pytest.raises(InvalidSignatureError):
                make_verifier(None).verify(bearer_headers(claims), issue_body())


# --- review pass 3 ---------------------------------------------------------------------------


def refuse_filter(rig: Rig, containing: str) -> None:
    """POSTs whose filter names ``containing`` are refused as an unknown project; others work."""
    real = rig.api.call

    def call(method: str, path: str, body: Any = None, params: Any = None) -> ApiReply:
        if (method, path) == ("POST", "/webhook") and containing in str(body):
            return ApiReply(200, refusal(f"The value '{containing}' does not exist for 'project'."))
        return real(method, path, body, params)

    rig.job._api = type("Refusing", (), {"call": staticmethod(call)})()


def test_a_refusal_in_the_freed_slot_puts_the_working_hook_back() -> None:
    """Case Z: at the limit, a bound project that no longer exists is refused. It was never the
    limit, so our hook is registered again and the alert says refused."""
    rig = Rig()
    rig.job.sync()
    (first,) = rig.ids()
    for i in range(4):
        rig.foreign(f"project = F{i}X")
    rig.bindings.bind("team-b", "GONE")
    refuse_filter(rig, "GONE")
    with pytest.raises(WebhookRefusedError) as caught:
        rig.job.sync()
    assert not isinstance(caught.value, WebhookLimitError)
    assert rig.alerts.names() == ["jira.webhook.refused"]
    ours = rig.job._owned()
    assert len(ours) == 1
    assert ours != {first}  # re-registered in the slot freed, with the filter that worked
    (back,) = (h for h in rig.listed() if h["id"] in ours)
    assert back["jqlFilter"] == "project in (SYN)"
    assert rig.gaps == [SITE]  # told when the working hook was deleted
    with pytest.raises(
        WebhookRefusedError
    ):  # the next run finds a working hook, not a vanished one
        rig.job.sync()
    assert "jira.webhook.missing" not in rig.alerts.names()
    assert len(rig.job._owned()) == 1


def test_a_working_hook_we_cannot_describe_is_not_re_registered_from_nothing() -> None:
    rig = Rig()
    rig.job._restore({"id": 1, "jqlFilter": None, "events": None})  # nothing to put back
    assert rig.ids() == []


def test_four_foreign_hooks_and_our_expired_one_then_a_refusal_is_refused_not_the_limit() -> None:
    rig = Rig()
    rig.job.sync()
    for i in range(4):
        rig.foreign(f"project = F{i}X")
    rig.jira.now += 31 * DAY
    stub_posts(rig, refusal("The JQL query is invalid"))
    before = len(rig.api.calls)
    with pytest.raises(WebhookRefusedError) as caught:
        rig.job.sync()
    assert not isinstance(caught.value, WebhookLimitError)
    assert "jira.webhook.refused" in rig.alerts.names()
    assert "jira.webhook.limit" not in rig.alerts.names()
    deletes = [c for c in rig.api.calls[before:] if c == ("DELETE", "/webhook")]
    assert len(deletes) == 1  # the expired one only: no delete-and-retry


@pytest.mark.parametrize("stamp", [float("nan"), float("inf"), -float("inf"), 10**400, -(10**400)])
def test_an_expiry_that_is_not_a_finite_number_is_a_permanent_error(stamp: Any) -> None:
    rig = Rig()
    rig.job.sync()
    rig.job._api = Mangled(rig.jira, lambda h: h.update(expirationDate=stamp))
    with pytest.raises(PermanentError):
        rig.job.sync()
    assert len(rig.ids()) == 1  # and no duplicate was registered on the strength of it


def test_a_run_that_replaced_our_hook_between_our_record_read_and_listing_is_no_gap() -> None:
    """Case X: another run (expiry, delete, register) finishes after we read the record."""
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 31 * DAY
    other = Rig.sharing(rig, {"team-a": "SYN"})
    other.job._store = rig.store
    real_owned = rig.job._owned
    raced = {"done": False}

    def owned_then_race() -> set[int]:
        held = real_owned()
        if not raced["done"]:
            raced["done"] = True
            other.job.sync()
        return held

    rig.job._owned = owned_then_race  # type: ignore[method-assign]
    rig.job.sync()
    assert rig.alerts.fired == []  # no spurious "missing"
    assert rig.gaps == []
    assert len(rig.ids()) == 1  # and no duplicate
    assert set(rig.ids()) == rig.job._owned()


def test_a_run_that_replaced_our_hook_between_listing_and_acting_is_clean() -> None:
    """Case Y: another run rebinds, registers and deletes after we listed."""
    rig = Rig()
    rig.job.sync()
    rig.jira.now += 11 * DAY
    other = Rig.sharing(rig, {"team-a": "SYN", "team-b": "OTH"})
    other.job._store = rig.store
    rig.bindings.bind("team-b", "OTH")
    real_list = rig.job._list
    raced = {"done": False}

    def list_then_race() -> list[dict[str, Any]]:
        listed = real_list()
        if not raced["done"]:
            raced["done"] = True
            other.job.sync()
        return listed

    rig.job._list = list_then_race  # type: ignore[method-assign]
    rig.job.sync()
    assert rig.alerts.fired == []
    assert len(rig.ids()) == 1
    assert set(rig.ids()) == rig.job._owned()


def test_a_record_that_changes_on_every_read_is_a_transient_error_not_a_loop() -> None:
    rig = Rig()
    rig.job.sync()
    reads = {"n": 0}

    def churning() -> set[int]:
        reads["n"] += 1
        return {reads["n"]}

    rig.job._owned = churning  # type: ignore[method-assign]
    with pytest.raises(TransientError):
        rig.job.sync()
    assert reads["n"] == 4  # two reads per attempt, two attempts


def test_a_note_another_run_wrote_while_the_callback_ran_is_not_cleared() -> None:
    rig = Rig()
    rig.job.sync()
    key = Key("ORG", f"JIRAGAP#{SITE}")

    def callback(site: str) -> None:
        # while we are inside the callback another run acknowledges the note and finds a new gap
        rig.store.delete(PLATFORM, key)
        rig.store.put(PLATFORM, key, {"site": SITE, "token": "someone-elses"})

    rig.job._on_gap = callback
    rig.job._gap_known()
    assert rig.job._gap_pending()
    item = rig.store.get(PLATFORM, key)
    assert item is not None
    assert item.data["token"] == "someone-elses"


def test_the_note_we_wrote_is_cleared_when_the_callback_returns() -> None:
    rig = Rig()
    rig.job._gap_known()
    assert rig.gaps == [SITE]
    assert not rig.job._gap_pending()


def test_each_gap_note_has_its_own_token() -> None:
    rig = Rig()
    key = Key("ORG", f"JIRAGAP#{SITE}")
    tokens = []

    def down(site: str) -> None:
        raise RuntimeError("reconciler down")

    rig.job._on_gap = down
    for _ in range(2):
        rig.job._gap_known()
        item = rig.store.get(PLATFORM, key)
        assert item is not None
        tokens.append(item.data["token"])
        rig.store.delete(PLATFORM, key)
    assert tokens[0] != tokens[1]


@pytest.mark.parametrize(
    "hook",
    [
        {"jqlFilter": None, "events": ["jira:issue_updated"]},
        {"jqlFilter": "project = SYN", "events": None},
        {"jqlFilter": "project = SYN", "events": [1]},
        {"jqlFilter": 5, "events": []},
    ],
)
def test_a_working_hook_with_an_unusable_description_is_not_registered_again(
    hook: dict[str, Any],
) -> None:
    rig = Rig()
    rig.job._restore({"id": 1, **hook})
    assert rig.ids() == []
