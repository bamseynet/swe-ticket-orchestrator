"""D4-01: the conformance suite, proved against a reference adapter, vendor-shaped honest adapters,
known-bad adapters, the guards, and the merged fakes. See ``suite.py`` for how an adapter reuses it.

The reference is split in two, as a real adapter is: a small stub **server** that holds the truth
(stored comments, pages, signature secret, clock, every 4xx/5xx shape) and an **adapter** with the
production logic (verifier, dedupe, look-up-first, error mapping). The harness (``StubTarget``)
only forwards. Each ``Bad*`` adapter breaks one rule over the same server, and
``test_known_bad_adapters_fail_the_suite`` pins which tests must catch it AND with which exception.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
import textwrap
import types
import urllib.parse
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

import pytest

from contract.suite import (  # noqa: E402
    CAPABILITIES,
    MAX_REPLAY_WINDOW,
    PAGE_SIZE,
    PORT_SECTIONS,
    SECURITY_CONTROLS,
    SHAPE_RETRY_AFTER,
    SUBCLASSES,
    WAIVABLE,
    AdapterConformance,
    AuthRefresh,
    Capabilities,
    Control,
    ForgeKind,
    HarnessError,
    MissingControl,
    Outcome,
    Port,
    PortClaimError,
    RateShape,
    Section,
    Target,
    Vendor,
    applicable,
    check_class,
    check_collection,
    check_not_simulated,
    enforce_outcome,
    is_auth_error,
    is_fake,
    is_reference,
    pending_controls,
    resolve,
    run_suite,
    validate_target,
)
from sto.adapters.fake.notifier import FakeNotifier  # noqa: E402
from sto.adapters.fake.scm import FakeScm  # noqa: E402
from sto.adapters.fake.spy import SpyWriter  # noqa: E402
from sto.adapters.fake.tickets import FakeTicketSource  # noqa: E402
from sto.adapters.ports import (  # noqa: E402
    ChangeKind,
    CheckSpec,
    DecisionRequest,
    ExternalChange,
    GateMessage,
    IdempotencyKeyReuseError,
    MalformedWebhookError,
    RawWebhook,
    RepoRef,
    StaleHeadError,
    Ticket,
    TicketRef,
    UnknownRefError,
)
from sto.domain.errors import PermanentError, TransientError  # noqa: E402
from sto.domain.models import DecisionKind, Receipt  # noqa: E402

# --- the stub server: it holds the truth ----------------------------------------------------

SECRET = b"synthetic-secret"
TOKEN = "good"
PRINCIPAL = "sto-bot"
WINDOW = MAX_REPLAY_WINDOW
TREF = TicketRef("fake", "T-1")
TESTS_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = TESTS_DIR.parent / "src"


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: Any


@dataclass(frozen=True)
class Comment:
    id: str
    author: str
    body: str


class Stub:
    """A vendor-like server: paged comments in either order, every rate-limit shape, a plain 403
    and 404, 401s per operation, token refresh, faults at any request, a clock and a secret."""

    id_in_header = True

    def __init__(self, shape: str = "ticket", ts_signed: bool = True) -> None:
        self.shape, self.ts_signed = shape, ts_signed
        self.now = 1_000.0
        self.comments: list[Comment] = []
        self.revision = 0
        self.counts: Counter[str] = Counter()
        self.faults: defaultdict[str, list[list[Any]]] = defaultdict(list)
        self.plain: defaultdict[str, list[int]] = defaultdict(list)
        self.limited, self.limit_shape = 0, RateShape.PRIMARY_429
        self.limit_op: str | None = None
        self.auth_ok, self.deny_ops, self.valid_token = True, set[str](), TOKEN
        self.swallow = 0
        self.order = "newest_first"
        self._seq = 0

    def add(self, author: str, body: str, *, older: bool = False) -> Comment:
        self._seq += 1
        comment = Comment(f"c-{self._seq}", author, body)
        if older:
            self.comments.insert(0, comment)
        else:
            self.comments.append(comment)
        return comment

    def _limit_response(self) -> Response:
        shape = self.limit_shape
        if shape is RateShape.PRIMARY_429:
            return Response(429, {"retry-after": "30"}, {})
        if shape is RateShape.PRIMARY_429_NO_HEADER:
            return Response(429, {}, {})
        if shape is RateShape.SECONDARY_403:
            return Response(403, {"retry-after": "30"}, {"message": "secondary rate limit"})
        if shape is RateShape.SECONDARY_403_NO_HEADER:
            return Response(403, {}, {"message": "You have exceeded a secondary rate limit."})
        reset = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(self.now) + 45)}
        return Response(403, reset, {"message": "API rate limit exceeded"})

    def _fault(self, op: str, page: int | None) -> str:
        for entry in self.faults[op]:
            mode, want_page, after = entry
            if want_page is not None and want_page != page:
                continue
            if after > 0:
                entry[2] -= 1
                return ""
            self.faults[op].remove(entry)
            return str(mode)
        return ""

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        self.counts[op] += 1
        if op == "refresh":
            return Response(200, {}, {"token": self.valid_token})
        if token != self.valid_token or not self.auth_ok or op in self.deny_ops:
            self.counts["unauthorized"] += 1
            return Response(401, {}, {"message": "Bad credentials"})
        if self.limited > 0 and self.limit_op in (None, op):
            self.limited -= 1
            self.counts["limited"] += 1
            return self._limit_response()
        if self.plain[op]:
            return Response(self.plain[op].pop(0), {}, {"message": "plain error"})
        page: int = int(kw["page"]) if op == "lookup" else -1
        fault = self._fault(op, page)
        if fault == "5xx":
            return Response(503, {}, {})
        if fault == "429":
            return Response(429, {"retry-after": "30"}, {})
        if fault == "401":
            return Response(401, {}, {"message": "Bad credentials"})
        if fault == "timeout":
            raise TimeoutError("timed out")
        if op == "lookup":
            listing = (
                list(reversed(self.comments)) if self.order == "newest_first" else self.comments
            )
            chunk = listing[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
            more = len(listing) > (page + 1) * PAGE_SIZE
            items = [{"id": c.id, "author": c.author, "body": c.body} for c in chunk]
            return Response(200, {}, {"items": items, "next": page + 1 if more else None})
        if op == "read":
            return Response(200, {}, {"revision": self.revision})
        if op == "write":
            if self.swallow > 0:
                self.swallow -= 1
                return Response(201, {}, {"id": "c-swallowed"})
            comment = self.add(PRINCIPAL, kw["body"])
            if fault == "lose":
                raise TimeoutError("response lost")
            return Response(201, {}, {"id": comment.id})
        raise AssertionError(f"unknown op {op}")

    # --- the vendor sending webhooks ---
    def make_body(self, revision: int, delivery_id: str, with_id: bool) -> bytes:
        if self.shape == "decision":
            payload: dict[str, Any] = {
                "decision": {
                    "gate_id": "G-1",
                    "kind": "approve",
                    "actor": "u-1",
                    "subject_digest": "digest",
                }
            }
        else:
            payload = {"changes": [{"kind": "ticket", "ticket": TREF.key}]}
        return json.dumps({**payload, "revision": revision}).encode()

    def delivery(
        self,
        revision: int,
        delivery_id: str,
        *,
        secret: bytes = SECRET,
        mac: str = "full",
        ts: float | None = None,
        with_id: bool = True,
        body: bytes | None = None,
    ) -> RawWebhook:
        raw = self.make_body(revision, delivery_id, with_id) if body is None else body
        stamp = str(self.now if ts is None else ts)
        signed = (stamp + ".").encode() + raw if self.ts_signed else raw
        digest = hmac.new(b"" if mac == "empty_key" else secret, signed, hashlib.sha256).hexdigest()
        sig = {
            "full": f"sha256={digest}",
            "truncated": f"sha256={digest[:8]}",
            "empty": "sha256=",
            "empty_key": f"sha256={digest}",
            "blank": "",
        }[mac]
        headers = {"X-Timestamp": stamp, "X-Signature": sig}
        if with_id and self.id_in_header:
            headers["X-Delivery"] = delivery_id
        return RawWebhook(headers, raw)


class FormStub(Stub):
    """Slack-like: a form-encoded body (``payload=<url-encoded json>``), the ID inside it."""

    id_in_header = False

    def make_body(self, revision: int, delivery_id: str, with_id: bool) -> bytes:
        payload: dict[str, Any] = {
            "decision": {
                "gate_id": "G-1",
                "kind": "approve",
                "actor": "u-1",
                "subject_digest": "digest",
            },
            "revision": revision,
        }
        if with_id:
            payload["trigger_id"] = delivery_id
        return ("payload=" + urllib.parse.quote(json.dumps(payload))).encode()


# --- the adapter: production logic, the thing under test -----------------------------------


class RateLimited(TransientError):
    def __init__(self, retry_after: float | None) -> None:
        super().__init__(f"rate limited; retry after {retry_after}s")
        self.retry_after = retry_after


class HmacVerifier:
    """Raw-body HMAC (over ``timestamp.body`` when the vendor signs it), an optional replay
    window, and a required delivery ID."""

    def __init__(
        self,
        secret: bytes,
        clock: Callable[[], float],
        window: float | None,
        ts_signed: bool = True,
    ) -> None:
        self.secret, self.clock, self.window, self.ts_signed = secret, clock, window, ts_signed

    def _signed_over(self, headers: Mapping[str, str], raw_body: bytes) -> bytes:
        if not self.ts_signed:
            return raw_body
        return f"{headers.get('X-Timestamp', '')}.".encode() + raw_body

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        sent = headers.get("X-Signature")
        if sent is None:
            raise PermanentError("401 unsigned")
        expected = (
            "sha256="
            + hmac.new(
                self.secret, self._signed_over(headers, raw_body), hashlib.sha256
            ).hexdigest()
        )
        if not hmac.compare_digest(sent, expected):
            raise PermanentError("401 bad signature")
        return self._checked(headers, raw_body)

    def _checked(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        if self.window is not None:
            try:
                age = abs(self.clock() - float(headers.get("X-Timestamp", "")))
            except ValueError:
                raise PermanentError("401 bad timestamp") from None
            if age > self.window:
                raise PermanentError("401 outside the replay window")
        delivery_id = self._id(headers, raw_body)
        if not delivery_id:
            raise PermanentError("400 no delivery id")
        return delivery_id

    def _id(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return headers.get("X-Delivery", "")


class FormVerifier(HmacVerifier):
    def _id(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        try:
            form = urllib.parse.parse_qs(raw_body.decode())
            return str(json.loads(form["payload"][0]).get("trigger_id", ""))
        except (KeyError, IndexError, ValueError):
            return ""


@dataclass
class Store:
    """The durable tables of an adapter (the seen-ID table, the queue): they outlive a restart."""

    seen: set[str]
    queue: list[Any]


class Adapter:
    token = TOKEN
    window: float | None = WINDOW
    ts_signed = True
    simulated = True

    def __init__(self, server: Stub, store: Store | None = None) -> None:
        self.server = server
        self.store = store if store is not None else Store(set(), [])
        self.verifier = self._verifier()

    @property
    def queue(self) -> list[Any]:
        return self.store.queue

    def _verifier(self) -> HmacVerifier:
        return HmacVerifier(SECRET, lambda: self.server.now, self.window, self.ts_signed)

    # --- writes: look up first (PLAN 6.3), then post, then read back ---
    @staticmethod
    def marker(key: str, variant: str) -> str:
        return f"<!-- sto:{key}:{hashlib.sha256(variant.encode()).hexdigest()[:8]} -->"

    def _send(self, op: str, **kw: Any) -> Response:
        try:
            return self.server.handle(op, self.token, **kw)
        except TimeoutError as exc:
            raise TransientError(f"{op} timed out") from exc

    def _call(self, op: str, **kw: Any) -> Any:
        return self._unwrap(self._send(op, **kw))

    @staticmethod
    def _retry_after(response: Response, now: float) -> float | None:
        h = response.headers
        if "retry-after" in h:
            return float(h["retry-after"])
        if "x-ratelimit-reset" in h:
            return max(0.0, float(h["x-ratelimit-reset"]) - now)
        return None

    def _unwrap(self, response: Response) -> Any:
        status, h = response.status, response.headers
        if status in (200, 201):
            return response.body
        said = str(response.body.get("message", "")) if isinstance(response.body, dict) else ""
        if status == 429 or (
            status == 403
            and (
                "retry-after" in h or h.get("x-ratelimit-remaining") == "0" or "rate limit" in said
            )
        ):
            raise RateLimited(self._retry_after(response, self.server.now))
        if status == 401:
            raise PermanentError("401 bad credentials")
        if status == 403:
            raise PermanentError("403 forbidden")
        if status == 404:
            raise UnknownRefError("404 not found")
        if status >= 500:
            raise TransientError(f"{status} from the server")
        raise PermanentError(f"{status} from the server")

    def _mine(self, comment: dict[str, str], key: str) -> bool:
        return comment["author"] == PRINCIPAL and f"<!-- sto:{key}:" in comment["body"]

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            body = self._call("lookup", page=page)
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None

    def write(self, key: str, variant: str = "a") -> Receipt:
        marker = self.marker(key, variant)
        found = self._find(key)
        if found is not None:
            if marker not in found["body"]:
                raise IdempotencyKeyReuseError(f"key {key!r} was used for other arguments")
            return Receipt(found["id"], "", True, simulated=self.simulated)
        posted = self._call("write", body=f"{marker} body-{variant}")
        try:  # read back: it is really there; if we cannot tell, it is not verified
            verified = self._find(key) is not None
        except (TransientError, PermanentError):
            verified = False
        return Receipt(posted["id"], "", verified, simulated=self.simulated)

    # --- webhooks: verify, then parse, then remember, then enqueue ---
    def receive(self, raw: RawWebhook) -> Any:
        """``None``: dropped as a duplicate."""
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        if delivery_id in self.store.seen:
            return None
        try:
            result = self._parse(raw)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise MalformedWebhookError("unreadable body") from exc
        self.store.seen.add(delivery_id)
        self.store.queue.append(result)
        return result

    def _parse(self, raw: RawWebhook) -> Any:
        key = json.loads(raw.body)["changes"][0]["ticket"]
        return [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("fake", key))]

    def read_revision(self) -> int:
        return int(self._call("read")["revision"])

    def probe(self) -> None:
        """An honest authenticated request of its own, separate from ``read_revision``."""
        self._call("read")


class DecisionAdapter(Adapter):
    """A Notifier-port adapter: a delivery is a ``DecisionRequest``, not a list of nudges."""

    def _parse(self, raw: RawWebhook) -> Any:
        d = json.loads(raw.body)["decision"]
        return DecisionRequest(
            d["gate_id"], DecisionKind(d["kind"]), d["actor"], d["subject_digest"]
        )


class SlackAdapter(DecisionAdapter):
    """Honest Slack-shaped: a form-encoded body, the ID inside it, a signed timestamp."""

    def _verifier(self) -> HmacVerifier:
        return FormVerifier(SECRET, lambda: self.server.now, self.window, True)

    def _parse(self, raw: RawWebhook) -> Any:
        form = urllib.parse.parse_qs(raw.body.decode())
        d = json.loads(form["payload"][0])["decision"]
        return DecisionRequest(
            d["gate_id"], DecisionKind(d["kind"]), d["actor"], d["subject_digest"]
        )


class GitHubAdapter(Adapter):
    """Honest GitHub-shaped: the signature covers the body only; no header is trusted for time."""

    window: float | None = None
    ts_signed = False


class JiraAdapter(Adapter):
    """Honest Jira-shaped: no signed timestamp, and a 401 gets exactly one refresh and one retry
    (3LO, D6-02)."""

    window: float | None = None
    ts_signed = False

    def _send(self, op: str, **kw: Any) -> Response:
        response = super()._send(op, **kw)
        if response.status == 401:
            self.token = self.server.handle("refresh", self.token).body["token"]
            return super()._send(op, **kw)
        return response


# --- the harness: a thin pass-through ---------------------------------------------------------


class StubTarget(Target):
    name = "stub"
    controls = frozenset(Control)
    watched = TREF.key

    def __init__(
        self,
        adapter_cls: type[Adapter] = Adapter,
        stub: Stub | None = None,
        vendor: Vendor = Vendor.STUB,
        replay_window: float | None = None,
    ) -> None:
        self.vendor = vendor
        self.server = stub or Stub()
        self.adapter_cls, self.store = adapter_cls, Store(set(), [])
        self.adapter: Adapter = adapter_cls(self.server, self.store)
        self.verifier = self.adapter.verifier
        self.watched = "G-1" if self.server.shape == "decision" else TREF.key
        if replay_window is not None:
            self.replay_window = replay_window

    def restart(self) -> None:
        self.adapter = self.adapter_cls(self.server, self.store)
        self.verifier = self.adapter.verifier

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self.adapter.write(key, variant)

    def deliver(self, raw: RawWebhook) -> Outcome:
        result = self.adapter.receive(raw)
        if result is None:
            return Outcome(False)
        if isinstance(result, DecisionRequest):
            return Outcome(True, (result.gate_id,))
        return Outcome(True, tuple(c.ticket.key for c in result if c.ticket))

    def queued(self) -> int:
        return len(self.store.queue)

    def reported_revision(self) -> int:
        return self.adapter.read_revision()

    def stored_ids(self) -> list[str]:
        return [c.id for c in self.server.comments if c.author == PRINCIPAL]

    def stored_id_for(self, key: str) -> str | None:
        for c in self.server.comments:
            if c.author == PRINCIPAL and f"<!-- sto:{key}:" in c.body:
                return c.id
        return None

    def calls(self, op: str) -> int:
        return self.server.counts[op]

    def server_revision(self) -> int:
        return self.server.revision

    def clock(self) -> float:
        return self.server.now

    def probe(self) -> None:
        self.adapter.probe()

    def fault_next(self, op: str, mode: str, page: int | None = None, after: int = 0) -> None:
        self.server.faults[op].append([mode, page, after])

    def respond_next(self, op: str, status: int) -> None:
        self.server.plain[op].append(status)

    def seed_others(self, n: int, newer: bool = True) -> None:
        for i in range(n):
            self.server.add("alice", f"unrelated {i}", older=not newer)

    def set_list_order(self, order: str) -> None:
        self.server.order = order

    def plant_foreign_marker(self, key: str, variant: str = "a", author: str = "mallory") -> None:
        self.server.add(author, self.adapter.marker(key, variant) + " planted")

    def swallow_next_write(self) -> None:
        self.server.swallow += 1

    def rate_limit_next(self, times: int, shape: RateShape, op: str | None = None) -> None:
        self.server.limited, self.server.limit_shape, self.server.limit_op = times, shape, op

    def revoke_auth(self, op: str | None = None) -> None:
        if op is None:
            self.server.auth_ok = False
        else:
            self.server.deny_ops.add(op)

    def restore_auth(self) -> None:
        self.server.auth_ok = True
        self.server.deny_ops.clear()

    def expire_token(self) -> None:
        self.server.valid_token = "good-2"

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        self.server.revision = revision
        return self.server.delivery(revision, delivery_id)

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        mac = {
            ForgeKind.WRONG_SECRET: "full",
            ForgeKind.TRUNCATED_MAC: "truncated",
            ForgeKind.EMPTY_MAC: "empty",
            ForgeKind.EMPTY_KEY: "empty_key",
            ForgeKind.BLANK_HEADER: "blank",
        }[how]
        secret = b"not-the-secret" if how is ForgeKind.WRONG_SECRET else SECRET
        return self.server.delivery(revision, delivery_id, secret=secret, mac=mac)

    def emit_without_id(self, revision: int) -> RawWebhook:
        return self.server.delivery(revision, "", with_id=False)

    def malformed_body(self, delivery_id: str) -> bytes:
        return b'{"oops": 1}'

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        return self.server.delivery(1, delivery_id, body=self.malformed_body(delivery_id))

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        return self.server.delivery(revision, delivery_id, ts=self.server.now + ahead)

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        headers = {k: v for k, v in raw.headers.items() if k != "X-Timestamp"}
        if value is not None:
            headers["X-Timestamp"] = value
        return RawWebhook(headers, raw.body)

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        return RawWebhook(raw.headers, raw.body + b" ")

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        return RawWebhook(raw.headers, json.dumps(json.loads(raw.body), indent=2).encode())

    def advance_clock(self, seconds: float) -> None:
        self.server.now += seconds


class FormTarget(StubTarget):
    def malformed_body(self, delivery_id: str) -> bytes:
        return ("payload=" + urllib.parse.quote(json.dumps({"trigger_id": delivery_id}))).encode()

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        payload = json.loads(urllib.parse.parse_qs(raw.body.decode())["payload"][0])
        return RawWebhook(
            raw.headers, ("payload=" + urllib.parse.quote(json.dumps(payload, indent=2))).encode()
        )


WEBHOOK_CONTROLS = frozenset(
    {Control.SIGNATURE, Control.UNSIGNED, Control.DUPLICATE, Control.REPLAY_WINDOW, Control.RESTART}
)


def reference() -> Target:
    return StubTarget()


def notifier_port() -> Target:
    return StubTarget(DecisionAdapter, Stub("decision"))


def github_shaped() -> Target:
    return StubTarget(GitHubAdapter, Stub(ts_signed=False), Vendor.GITHUB)


def slack_shaped() -> Target:
    return FormTarget(SlackAdapter, FormStub("decision"), Vendor.SLACK)


def jira_refresh_once() -> Target:
    return StubTarget(JiraAdapter, Stub(ts_signed=False), Vendor.JIRA)


class WebhookOnlyTarget(StubTarget):
    controls = WEBHOOK_CONTROLS


def webhook_only() -> Target:
    return WebhookOnlyTarget(GitHubAdapter, Stub(ts_signed=False), Vendor.GITHUB)


class NoWriteTarget(StubTarget):
    """A fake server with no write surface (D4-16): auth, reads, rate limits and webhooks."""

    def write(self, key: str, variant: str = "a") -> Receipt:
        raise HarnessError("this server has no write surface")

    def stored_ids(self) -> list[str]:
        raise HarnessError("this server stores nothing")

    def stored_id_for(self, key: str) -> str | None:
        raise HarnessError("this server stores nothing")


def auth_webhook() -> Target:
    return NoWriteTarget()


class TestReferenceAdapter(AdapterConformance):
    """The reference adapter, observed at the stub server, passes every section."""

    port = Port.TICKET_SOURCE
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": reference}


class TestNotifierPort(AdapterConformance):
    """The Notifier port: a delivery is a ``DecisionRequest | None``. A notifier has no state
    read, so no ordering section; ``send`` returns a Receipt, so read-back (G8) applies."""

    port = Port.NOTIFIER
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": notifier_port}


class TestGitHubShapedAdapter(AdapterConformance):
    """No signed timestamp, four 403/429 shapes, signature over the body alone."""

    port = Port.SCM
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": github_shaped}


class TestSlackShapedAdapter(AdapterConformance):
    """A form-encoded body with the ID inside it: the suite parses nothing itself."""

    port = Port.NOTIFIER
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": slack_shaped}


class TestJiraRefreshOnceAdapter(AdapterConformance):
    """A 401 gets exactly one refresh and one retry (D6-02); no signed timestamp."""

    port = Port.TICKET_SOURCE
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": jira_refresh_once}


class TestWebhookOnlyTarget(AdapterConformance):
    """An ingest target (D4-03, D4-04) is held to the webhook section and nothing else."""

    port = Port.WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": webhook_only}


class TestAuthWebhookTarget(AdapterConformance):
    """A fake server's auth, reads and webhooks, with NO write surface (D4-16)."""

    port = Port.AUTH_WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": auth_webhook}


# --- known-bad adapters: each breaks one rule, and the suite must fail it ---------------------


def _hmac(
    cls: type[HmacVerifier], adapter: Adapter, window: float | None | object = ...
) -> HmacVerifier:
    win = adapter.window if window is ... else window
    return cls(SECRET, lambda: adapter.server.now, win, adapter.ts_signed)  # type: ignore[arg-type]


class _Trusting(HmacVerifier):
    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return self._checked(headers, raw_body)


class _Parsing(HmacVerifier):
    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return super().verify(headers, json.dumps(json.loads(raw_body)).encode())


class _Lax(HmacVerifier):
    """Unsigned is fine, but a missing delivery ID is refused: stripping all headers hides it."""

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        if "X-Signature" not in headers:
            return self._checked(headers, raw_body)
        return super().verify(headers, raw_body)


class _Prefix(HmacVerifier):
    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        sent = headers.get("X-Signature")
        if sent is None:
            raise PermanentError("unsigned")
        digest = hmac.new(self.secret, self._signed_over(headers, raw_body), hashlib.sha256)
        if not ("sha256=" + digest.hexdigest()).startswith(sent):
            raise PermanentError("bad")
        return self._checked(headers, raw_body)


class _AlsoEmptyKey(HmacVerifier):
    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        sent = headers.get("X-Signature")
        if sent is None:
            raise PermanentError("unsigned")
        for key in (self.secret, b""):
            digest = hmac.new(key, self._signed_over(headers, raw_body), hashlib.sha256)
            if hmac.compare_digest(sent, "sha256=" + digest.hexdigest()):
                return self._checked(headers, raw_body)
        raise PermanentError("bad")


class _MintsId(HmacVerifier):
    def _id(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return headers.get("X-Delivery") or uuid.uuid4().hex


class _NoFutureCheck(HmacVerifier):
    def _checked(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        if self.clock() - float(headers.get("X-Timestamp", "0")) > (self.window or 0):
            raise PermanentError("old")
        return self._id(headers, raw_body)


class _RejectsEverything(HmacVerifier):
    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        raise PermanentError("401 no")


def _with_verifier(name: str, cls: type[HmacVerifier], **attrs: Any) -> type[Adapter]:
    class Variant(Adapter):
        def _verifier(self) -> HmacVerifier:
            return _hmac(cls, self, attrs.get("window", ...))

    Variant.__name__ = Variant.__qualname__ = name
    return Variant


BadNoSignatureCheck = _with_verifier("BadNoSignatureCheck", _Trusting)
BadParsedBodySignature = _with_verifier("BadParsedBodySignature", _Parsing)
BadAcceptsMissingSignature = _with_verifier("BadAcceptsMissingSignature", _Lax)
BadPrefixCompare = _with_verifier("BadPrefixCompare", _Prefix)
BadAlsoEmptySecret = _with_verifier("BadAlsoEmptySecret", _AlsoEmptyKey)
BadMintsIdWhenMissing = _with_verifier("BadMintsIdWhenMissing", _MintsId)
BadNoFutureCheck = _with_verifier("BadNoFutureCheck", _NoFutureCheck)
BadRejectsGenuine = _with_verifier("BadRejectsGenuine", _RejectsEverything)
BadNoReplayWindow = _with_verifier("BadNoReplayWindow", HmacVerifier, window=None)
BadHugeWindow = _with_verifier("BadHugeWindow", HmacVerifier, window=10**9)


class BadRejectsInsideWindow(Adapter):
    window = WINDOW - 10


class BadUnsignedWindow(GitHubAdapter):
    """On a vendor whose timestamp is not signed, trusts the unsigned header for replay."""

    window = WINDOW


class BadBumpableTimestamp(Adapter):
    """Claims a signed timestamp but its MAC does not cover it: a bump revives a capture."""

    ts_signed = False


class BadBurnsIdOfForgery(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        try:
            return super().receive(raw)
        except PermanentError:
            self.store.seen.add(raw.headers.get("X-Delivery", ""))
            raise


class BadBurnsIdOnMalformed(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        try:
            return super().receive(raw)
        except MalformedWebhookError:
            self.store.seen.add(raw.headers.get("X-Delivery", ""))
            raise


class BadDuplicateBeforeVerify(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        if raw.headers.get("X-Delivery") in self.store.seen:
            return None  # a forgery with a seen ID is answered "duplicate"
        return super().receive(raw)


class BadForgeryWipesDedupe(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        try:
            return super().receive(raw)
        except PermanentError:
            self.store.seen.clear()
            raise


class BadNoDedupe(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        self.store.seen.clear()
        return super().receive(raw)


class BadDedupeByContent(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        self.verifier.verify(raw.headers, raw.body)
        content = hashlib.sha256(raw.body).hexdigest()
        if content in self.store.seen:
            return None
        self.store.seen.add(content)
        result = self._parse(raw)
        self.store.queue.append(result)
        return result


class BadRemembersLastIdOnly(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        if delivery_id in self.store.seen:
            return None
        self.store.seen.clear()
        self.store.seen.add(delivery_id)
        result = self._parse(raw)
        self.store.queue.append(result)
        return result


class BadDedupeTtl(Adapter):
    """Forgets an ID after 10 s, far inside the replay window."""

    def receive(self, raw: RawWebhook) -> Any:
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        now = self.server.now
        stamps: dict[str, float] = self.store.__dict__.setdefault("stamps", {})
        if delivery_id in stamps and now - stamps[delivery_id] < 10:
            return None
        stamps[delivery_id] = now
        result = self._parse(raw)
        self.store.queue.append(result)
        return result


class BadVolatileDedupe(Adapter):
    """The seen-ID table lives in this process only: a restart forgets it."""

    def __init__(self, server: Stub, store: Store | None = None) -> None:
        super().__init__(server, Store(set(), store.queue if store else []))


class BadCachesDeliveryState(Adapter):
    """Treats the delivery body as the truth: its idea of the revision is the last one delivered."""

    cached: int | None = None

    def receive(self, raw: RawWebhook) -> Any:
        result = super().receive(raw)
        self.cached = json.loads(raw.body)["revision"]
        return result

    def read_revision(self) -> int:
        return self.cached if self.cached is not None else super().read_revision()


class BadMemoisedRead(Adapter):
    memo: int | None = None

    def read_revision(self) -> int:
        if self.memo is None:
            self.memo = super().read_revision()
        return self.memo


class BadWrongNudgeObject(Adapter):
    def _parse(self, raw: RawWebhook) -> Any:
        return [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("fake", "T-0"))]


class BadPermanentReadIsZero(Adapter):
    """The probe is honest and separate; only `read_revision` swallows a permanent failure."""

    def read_revision(self) -> int:
        try:
            return super().read_revision()
        except PermanentError:
            return 0


class BadReadErrorsAreZero(Adapter):
    def read_revision(self) -> int:
        try:
            return super().read_revision()
        except (PermanentError, TransientError):
            return 0


class BadReadAuthIsNotFound(Adapter):
    def read_revision(self) -> int:
        try:
            return super().read_revision()
        except PermanentError as exc:
            raise UnknownRefError("no such ticket") from exc


class BadInProcessKeys(Adapter):
    """Idempotency by a dict in this process: gone after a restart, and never looks up."""

    def __init__(self, server: Stub, store: Store | None = None) -> None:
        super().__init__(server, store)
        self._memo: dict[str, Receipt] = {}

    def write(self, key: str, variant: str = "a") -> Receipt:
        if key in self._memo:
            return self._memo[key]
        posted = self._call("write", body=f"{self.marker(key, variant)} body-{variant}")
        self._memo[key] = Receipt(posted["id"], "", True, simulated=True)
        return self._memo[key]


class BadAssumesApplied(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        try:
            return super().write(key, variant)
        except TransientError:
            return Receipt("assumed-applied", "", True, simulated=True)


class BadNewKeyReturnsOld(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        mine = [c for c in self.server.comments if c.author == PRINCIPAL]
        if mine:
            return Receipt(mine[0].id, "", True, simulated=True)
        return super().write(key, variant)


class BadFirstPageLookup(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        for comment in self._call("lookup", page=0)["items"]:
            if self._mine(comment, key):
                return comment  # type: ignore[no-any-return]
        return None


class BadTwoPageCap(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        for page in (0, 1):
            body = self._call("lookup", page=page)
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            if body["next"] is None:
                break
        return None


class BadLaterPageErrorIsEnd(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            try:
                body = self._call("lookup", page=page)
            except TransientError:
                if page == 0:
                    raise
                return None
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None


class BadLookupErrorIsNotFound(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        try:
            return super()._find(key)
        except TransientError:
            return None


class BadLookupErrorWritesAnyway(Adapter):
    """Raises on a failed look-up, but writes first: a retry then writes a second time."""

    def _find(self, key: str) -> dict[str, str] | None:
        try:
            return super()._find(key)
        except TransientError:
            self._call("write", body=f"{self.marker(key, 'a')} body-a")
            raise


class BadTrustsAnyAuthor(Adapter):
    def _mine(self, comment: dict[str, str], key: str) -> bool:
        return f"<!-- sto:{key}:" in comment["body"]


class BadForeignVariantBlocks(Adapter):
    """Any author's marker for the key with other arguments raises a reuse error."""

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            body = self._call("lookup", page=page)
            for comment in body["items"]:
                if f"<!-- sto:{key}:" in comment["body"]:
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None


class BadAuthorPrefix(Adapter):
    def _mine(self, comment: dict[str, str], key: str) -> bool:
        return comment["author"].startswith("sto") and f"<!-- sto:{key}:" in comment["body"]


class BadKeyPrefix(Adapter):
    def _mine(self, comment: dict[str, str], key: str) -> bool:
        return comment["author"] == PRINCIPAL and f"<!-- sto:{key}" in comment["body"]


class BadAlwaysVerified(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        return replace(super().write(key, variant), read_back_verified=True)


class BadNeverVerified(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        return replace(super().write(key, variant), read_back_verified=False)


class BadReadBackAnyAuthor(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        marker = self.marker(key, variant)
        found = self._find(key)
        if found is not None:
            return Receipt(found["id"], "", True, simulated=True)
        posted = self._call("write", body=f"{marker} body-{variant}")
        everyone = [c for c in self.server.comments if marker in c.body]  # any author
        return Receipt(posted["id"], "", bool(everyone), simulated=True)


class BadReadBackErrorIsVerified(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        marker = self.marker(key, variant)
        if self._find(key) is not None:
            return super().write(key, variant)
        posted = self._call("write", body=f"{marker} body-{variant}")
        try:
            verified = self._find(key) is not None
        except (TransientError, PermanentError):
            verified = True
        return Receipt(posted["id"], "", verified, simulated=True)


class BadHammersOn429(Adapter):
    def _call(self, op: str, **kw: Any) -> Any:
        for attempt in range(3):
            try:
                return super()._call(op, **kw)
            except RateLimited:
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")


class BadLimitIsPermanent(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status in (403, 429) and "message" not in response.body:
            raise PermanentError("rate limited")
        return super()._unwrap(response)


class BadSecondaryIsPermanent(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 403:
            raise PermanentError("forbidden")
        return super()._unwrap(response)


class BadDropsRetryAfter(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 429 or (response.status == 403 and response.headers):
            raise TransientError("limited")
        return super()._unwrap(response)


class BadPost429AssumedApplied(Adapter):
    def _call(self, op: str, **kw: Any) -> Any:
        try:
            return super()._call(op, **kw)
        except RateLimited:
            if op == "write":
                return {"id": "assumed"}
            raise


class BadRetriesAuth(Adapter):
    def _call(self, op: str, **kw: Any) -> Any:
        for attempt in range(10):
            try:
                return super()._call(op, **kw)
            except PermanentError:
                if attempt == 9:
                    raise
        raise AssertionError("unreachable")


class BadAuthIsNotFound(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise UnknownRefError("no such thing")
        return super()._unwrap(response)


class BadPost401IsNotFound(Adapter):
    def _call(self, op: str, **kw: Any) -> Any:
        try:
            return super()._call(op, **kw)
        except PermanentError as exc:
            if op == "write":
                raise UnknownRefError("gone") from exc
            raise


class BadAuthIsTransient(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise TransientError("try again")
        return super()._unwrap(response)


class BadAuthIsStale(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise StaleHeadError("head moved")
        return super()._unwrap(response)


class Bad403IsNotFound(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 403 and not response.headers:
            raise UnknownRefError("nope")
        return super()._unwrap(response)


class BadEvery403IsRateLimit(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 403:
            raise RateLimited(30.0)
        return super()._unwrap(response)


class Bad404IsAuth(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 404:
            raise PermanentError("401 bad credentials")
        return super()._unwrap(response)


class BadRefreshTwice(JiraAdapter):
    def _send(self, op: str, **kw: Any) -> Response:
        response = Adapter._send(self, op, **kw)
        for _ in range(2):
            if response.status != 401:
                break
            self.token = self.server.handle("refresh", self.token).body["token"]
            response = Adapter._send(self, op, **kw)
        return response


class BadRefreshTwiceBeforeRetry(JiraAdapter):
    def _send(self, op: str, **kw: Any) -> Response:
        response = Adapter._send(self, op, **kw)
        if response.status == 401:
            self.server.handle("refresh", self.token)
            self.token = self.server.handle("refresh", self.token).body["token"]
            return Adapter._send(self, op, **kw)
        return response


class BadEnqueuesBeforeVerify(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        self.store.queue.append("unverified")
        return super().receive(raw)


class BadEnqueuesUnsigned(Adapter):
    """Enqueues a delivery that carries no signature, then rejects it."""

    def receive(self, raw: RawWebhook) -> Any:
        if "X-Signature" not in raw.headers:
            self.store.queue.append("unsigned")
        return super().receive(raw)


class BadEnqueuesOnMissingId(Adapter):
    """Enqueues a delivery that carries no ID, then refuses it."""

    def receive(self, raw: RawWebhook) -> Any:
        if not raw.headers.get("X-Delivery"):
            self.store.queue.append("no id")
        return super().receive(raw)


class BadEnqueuesBeforeParse(Adapter):
    """Enqueues a verified delivery before it knows whether the body can be read."""

    def receive(self, raw: RawWebhook) -> Any:
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        if delivery_id in self.store.seen:
            return None
        self.store.queue.append("raw")
        try:
            result = self._parse(raw)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise MalformedWebhookError("unreadable body") from exc
        self.store.seen.add(delivery_id)
        self.store.queue.append(result)
        return result


class BadEnqueuesDuplicates(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        result = super().receive(raw)
        if result is None:
            self.store.queue.append("duplicate")
        return result


class BadDedupeIncludesTimestamp(GitHubAdapter):
    """Keys dedupe on ID plus the (unsigned) timestamp: a bump makes a replay look new."""

    def receive(self, raw: RawWebhook) -> Any:
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        key = delivery_id + raw.headers.get("X-Timestamp", "")
        if key in self.store.seen:
            return None
        self.store.seen.add(key)
        result = self._parse(raw)
        self.store.queue.append(result)
        return result


class BadFreshIdOnReplay(Adapter):
    """A replayed key answers with an invented receipt, not the object the server holds."""

    def write(self, key: str, variant: str = "a") -> Receipt:
        existed = self._find(key) is not None
        receipt = super().write(key, variant)
        return replace(receipt, external_id="again-" + receipt.external_id) if existed else receipt


class BadShrinksRetryAfter(Adapter):
    @staticmethod
    def _retry_after(response: Response, now: float) -> float | None:
        asked = Adapter._retry_after(response, now)
        return None if asked is None else 1.0


class BadRefreshesWhenNotAllowed(JiraAdapter):
    """Refreshes on a 401 for a vendor that does not allow it."""


class BadUnsignedWideWindow(GitHubAdapter):
    """Uses the unsigned header for replay with a window of 200,000 seconds."""

    window = 200_000.0


class BadDedupeTtl100k(GitHubAdapter):
    """Forgets a delivery ID after 100,001 seconds, though nothing bounds a replay."""

    def receive(self, raw: RawWebhook) -> Any:
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        now = self.server.now
        stamps: dict[str, float] = self.store.__dict__.setdefault("stamps", {})
        if delivery_id in stamps and now - stamps[delivery_id] < 100_001:
            return None
        result = self._parse(raw)
        stamps[delivery_id] = now
        self.store.queue.append(result)
        return result


class BadSlackNoWindow(SlackAdapter):
    """A Slack-shaped adapter with no replay window, though Slack signs its timestamp."""

    window = None


class BadEmptyHeaderValue(Adapter):
    def _verifier(self) -> HmacVerifier:
        class Blank(HmacVerifier):
            def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
                if headers.get("X-Signature") == "":
                    return self._checked(headers, raw_body)
                return super().verify(headers, raw_body)

        return _hmac(Blank, self)


class BadAuthIsLocalNotFound(Adapter):
    """An error class of its own that IS a UnknownRefError, for a 401."""

    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise _LocalNotFound("nope")
        return super()._unwrap(response)


class _LocalNotFound(UnknownRefError):
    pass


class BadAuthIsLocalStale(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise _LocalStale("head moved")
        return super()._unwrap(response)


class _LocalStale(StaleHeadError):
    pass


class BadLookupTimeoutIsNotFound(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        try:
            return super()._find(key)
        except TransientError as exc:
            if "timed out" in str(exc):
                return None
            raise


class BadLaterPage429IsEnd(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            try:
                body = self._call("lookup", page=page)
            except RateLimited:
                if page == 0:
                    raise
                return None
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None


class BadLaterPageAuthIsEnd(Adapter):
    """A 401 on a later look-up page ends the list: the key reads as absent and is written twice."""

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            try:
                body = self._call("lookup", page=page)
            except PermanentError:
                if page == 0:
                    raise
                return None
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None


class BadLaterPageErrorPostsThenRaises(Adapter):
    """On an error from a later page it posts the object, then raises: a retry writes twice."""

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        while page is not None:
            try:
                body = self._call("lookup", page=page)
            except TransientError:
                if page > 0:
                    self._call("write", body=f"{self.marker(key, 'a')} body-a")
                raise
            for comment in body["items"]:
                if self._mine(comment, key):
                    return comment  # type: ignore[no-any-return]
            page = body["next"]
        return None


class BadForeignVariantSuppresses(Adapter):
    """Another author's marker for the key, with other arguments, is taken for ours: our write is
    suppressed and the receipt names their object (G9)."""

    def _mine(self, comment: dict[str, str], key: str) -> bool:
        return f"<!-- sto:{key}:" in comment["body"]

    def write(self, key: str, variant: str = "a") -> Receipt:
        found = self._find(key)
        if found is not None:
            return Receipt(found["id"], "", True, simulated=True)
        return super().write(key, variant)


class BadRead429IsZero(Adapter):
    def read_revision(self) -> int:
        try:
            return super().read_revision()
        except RateLimited:
            return 0


class BadReadBack429Or401Verified(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        marker = self.marker(key, variant)
        found = self._find(key)
        if found is not None:
            return super().write(key, variant)
        posted = self._call("write", body=f"{marker} body-{variant}")
        try:
            verified = self._find(key) is not None
        except (RateLimited, PermanentError):
            verified = True
        except TransientError:
            verified = False
        return Receipt(posted["id"], "", verified, simulated=True)


class BadRead403IsNotFound(Adapter):
    def read_revision(self) -> int:
        response = self._send("read")
        if response.status == 403 and not response.headers:
            raise UnknownRefError("no such ticket")
        return int(self._unwrap(response)["revision"])


class BadWrite404IsAuth(Adapter):
    def _call(self, op: str, **kw: Any) -> Any:
        response = self._send(op, **kw)
        if response.status == 404 and op == "write":
            raise PermanentError("401 bad credentials")
        return self._unwrap(response)


def _capped(pages: int) -> type[Adapter]:
    class Capped(Adapter):
        """Stops after ``pages`` pages and calls the key absent, instead of raising."""

        def _find(self, key: str) -> dict[str, str] | None:
            for page in range(pages):
                body = self._call("lookup", page=page)
                for comment in body["items"]:
                    if self._mine(comment, key):
                        return comment  # type: ignore[no-any-return]
                if body["next"] is None:
                    break
            return None

    Capped.__name__ = Capped.__qualname__ = f"BadPageCap{pages}"
    return Capped


BadPageCap8 = _capped(8)
BadPageCap10 = _capped(10)


class BadHeadOnly300(Adapter):
    """Walks every page but searches only the first 300 objects: right for newest-first only."""

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        items: list[dict[str, str]] = []
        while page is not None:
            body = self._call("lookup", page=page)
            items += body["items"]
            page = body["next"]
        return next((c for c in items[:300] if self._mine(c, key)), None)


class BadTailOnly300(Adapter):
    """Walks every page but searches only the last 300 objects: right for oldest-first only."""

    def _find(self, key: str) -> dict[str, str] | None:
        page: int | None = 0
        items: list[dict[str, str]] = []
        while page is not None:
            body = self._call("lookup", page=page)
            items += body["items"]
            page = body["next"]
        return next((c for c in items[-300:] if self._mine(c, key)), None)


class BadReuseCheckInMemoryOnly(Adapter):
    def __init__(self, server: Stub, store: Store | None = None) -> None:
        super().__init__(server, store)
        self._args: dict[str, str] = {}

    def write(self, key: str, variant: str = "a") -> Receipt:
        if key in self._args and self._args[key] != variant:
            raise IdempotencyKeyReuseError("key reused")
        found = self._find(key)
        self._args[key] = variant
        if found is not None:
            return Receipt(found["id"], "", True, simulated=True)
        return super().write(key, variant)


class BadIgnoresArguments(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        found = self._find(key)
        if found is not None:
            return Receipt(found["id"], "", True, simulated=True)
        return super().write(key, variant)


class BadAuthLatches(Adapter):
    """After one 401 every later answer is a 401, even once the credentials work again."""

    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            self.server.__dict__["dead"] = True
        if self.server.__dict__.get("dead"):
            raise PermanentError("401 latched")
        return super()._unwrap(response)


class BadGitHub403IsPermission(GitHubAdapter):
    """Treats every 403 as a permission error, including GitHub's secondary rate limit."""

    def _unwrap(self, response: Response) -> Any:
        if response.status == 403:
            raise PermanentError("403 forbidden")
        return super()._unwrap(response)


class OverridesCapabilities(StubTarget):
    """A target that claims to be GitHub but declares only the 429 shape for itself."""

    capabilities = Capabilities(False, frozenset({RateShape.PRIMARY_429}), AuthRefresh.NONE)


def _with(adapter: type[Adapter], **kw: Any) -> Callable[[], Target]:
    return lambda: StubTarget(adapter, **kw)


def _github(adapter: type[Adapter]) -> Callable[[], Target]:
    return lambda: StubTarget(adapter, Stub(ts_signed=False), Vendor.GITHUB)


def _slack(adapter: type[Adapter]) -> Callable[[], Target]:
    return lambda: FormTarget(adapter, FormStub("decision"), Vendor.SLACK)


A = AssertionError
F = pytest.fail.Exception  # a `pytest.raises` that did not raise, or `pytest.fail`
P, T, K, M = PermanentError, TransientError, IdempotencyKeyReuseError, MalformedWebhookError
U, S = UnknownRefError, StaleHeadError

# bad adapter -> (target factory, port, {test that must fail it: the exception it fails with})
KNOWN_BAD: dict[str, tuple[Callable[[], Target], Port, dict[str, type[BaseException]]]] = {}


def _bad(
    adapter: type[Adapter] | str,
    factory: Callable[[], Target] | None,
    port: Port,
    pinned: dict[str, type[BaseException]],
) -> None:
    name = adapter if isinstance(adapter, str) else adapter.__name__
    if factory is None:
        assert not isinstance(adapter, str)
        factory = _with(adapter)
    KNOWN_BAD[name] = (factory, port, pinned)


TS = Port.TICKET_SOURCE
# PINNED-BEGIN
_bad(
    BadNoSignatureCheck,
    None,
    TS,
    {
        "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing": F,
        "test_t6_the_production_verifier_rejects_every_kind_of_forgery": F,
        "test_t6_tampered_body_is_rejected": F,
        "test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one": F,
        "test_t6_a_delivery_with_only_the_signature_removed_is_rejected": F,
    },
)
_bad(
    BadParsedBodySignature,
    None,
    TS,
    {"test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one": F},
)
_bad(
    BadAcceptsMissingSignature,
    None,
    TS,
    {"test_t6_a_delivery_with_only_the_signature_removed_is_rejected": F},
)
_bad(
    BadPrefixCompare,
    None,
    TS,
    {
        "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing": F,
        "test_t6_the_production_verifier_rejects_every_kind_of_forgery": F,
    },
)
_bad(
    BadAlsoEmptySecret,
    None,
    TS,
    {
        "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing": F,
        "test_t6_the_production_verifier_rejects_every_kind_of_forgery": F,
    },
)
_bad(
    BadEmptyHeaderValue,
    None,
    TS,
    {
        "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing": F,
        "test_t6_the_production_verifier_rejects_every_kind_of_forgery": F,
    },
)
_bad(BadMintsIdWhenMissing, None, TS, {"test_a_delivery_with_no_id_is_refused_not_given_one": F})
_bad(BadNoFutureCheck, None, TS, {"test_t6_a_delivery_dated_in_the_future": F})
_bad(
    BadRejectsGenuine,
    None,
    TS,
    {
        "test_t6_the_production_verifier_accepts_a_genuine_delivery": P,
        "test_t6_genuine_delivery_is_accepted": P,
    },
)
_bad(
    BadNoReplayWindow,
    None,
    TS,
    {
        "test_t6_a_genuine_delivery_older_than_the_window": F,
        "test_t6_a_delivery_dated_in_the_future": F,
    },
)
_bad(BadHugeWindow, None, TS, {"test_t6_a_genuine_delivery_older_than_the_window": F})
_bad(
    BadRejectsInsideWindow,
    None,
    TS,
    {"test_t6_a_genuine_delivery_inside_the_replay_window_is_accepted": P},
)
_bad(
    "BadHugeWindowDeclared",
    lambda: StubTarget(Adapter, replay_window=10**9),
    TS,
    {"test_t6_the_replay_window_is_no_wider_than_the_suite_allows": A},
)
_bad(
    BadBurnsIdOfForgery,
    None,
    TS,
    {"test_t6_a_rejected_delivery_does_not_use_up_its_delivery_id": A},
)
_bad(
    BadBurnsIdOnMalformed,
    None,
    TS,
    {"test_a_verified_but_malformed_body_is_refused_and_does_not_burn_its_id": A},
)
_bad(
    BadDuplicateBeforeVerify,
    None,
    TS,
    {"test_t6_a_forged_delivery_with_a_seen_id_is_rejected_not_dropped": F},
)
_bad(
    BadForgeryWipesDedupe,
    None,
    TS,
    {"test_t6_a_forged_delivery_does_not_wipe_the_dedupe_memory": A},
)
_bad(BadNoDedupe, None, TS, {"test_redelivery_of_the_same_delivery_id_is_dropped": A})
_bad(BadDedupeByContent, None, TS, {"test_a_new_delivery_id_is_not_a_duplicate": A})
_bad(BadRemembersLastIdOnly, None, TS, {"test_dedupe_remembers_every_id_not_just_the_last": A})
_bad(
    BadDedupeTtl,
    None,
    TS,
    {"test_dedupe_does_not_expire_while_the_delivery_can_still_be_replayed": A},
)
_bad(BadVolatileDedupe, None, TS, {"test_dedupe_survives_a_restart": A})
_bad(
    BadEnqueuesBeforeVerify,
    None,
    TS,
    {
        "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing": A,
        "test_t6_genuine_delivery_is_accepted": A,
    },
)
_bad(BadEnqueuesDuplicates, None, TS, {"test_redelivery_of_the_same_delivery_id_is_dropped": A})
_bad(
    BadCachesDeliveryState,
    None,
    TS,
    {
        "test_delivery_order_does_not_change_what_the_adapter_reports": A,
        "test_after_a_delivery_state_is_re_read_from_the_server": A,
    },
)
_bad(BadMemoisedRead, None, TS, {"test_after_a_delivery_state_is_re_read_from_the_server": A})
_bad(
    BadWrongNudgeObject,
    None,
    TS,
    {
        "test_every_nudge_names_the_object_that_changed": A,
        "test_t6_genuine_delivery_is_accepted": A,
    },
)
_bad(
    BadReadErrorsAreZero,
    None,
    TS,
    {
        "test_a_failing_read_is_an_error_not_a_zero": F,
        "test_a_read_refused_for_credentials_is_an_auth_error_never_a_revision": F,
        "test_a_plain_403_or_404_on_a_read_is_an_error_never_a_revision": F,
    },
)
_bad(BadRead429IsZero, None, TS, {"test_a_failing_read_is_an_error_not_a_zero": F})
_bad(
    BadReadAuthIsNotFound,
    None,
    TS,
    {"test_a_read_refused_for_credentials_is_an_auth_error_never_a_revision": A},
)
_bad(
    BadRead403IsNotFound,
    None,
    TS,
    {"test_a_plain_403_or_404_on_a_read_is_an_error_never_a_revision": A},
)
_bad(
    BadInProcessKeys,
    None,
    TS,
    {
        "test_crash_after_the_write_applied_then_a_restart_does_not_write_again": A,
        "test_a_fresh_adapter_replaying_a_key_returns_the_servers_object": A,
    },
)
_bad(
    BadAssumesApplied,
    None,
    TS,
    {"test_crash_when_the_post_is_rejected_then_a_restart_writes_once": F},
)
_bad(BadNewKeyReturnsOld, None, TS, {"test_a_new_key_is_a_new_write": A})
_bad(
    BadFreshIdOnReplay,
    None,
    TS,
    {"test_a_fresh_adapter_replaying_a_key_returns_the_servers_object": A},
)
_bad(
    BadReuseCheckInMemoryOnly,
    None,
    TS,
    {"test_a_key_reused_with_other_arguments_is_refused_even_after_a_restart": F},
)
_bad(
    BadIgnoresArguments,
    None,
    TS,
    {"test_a_key_reused_with_other_arguments_is_refused_even_after_a_restart": F},
)
_bad(
    BadFirstPageLookup,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadTwoPageCap,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadPageCap8,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadPageCap10,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadHeadOnly300,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadTailOnly300,
    None,
    TS,
    {"test_lookup_walks_every_page_in_either_order_and_an_absent_key_costs_a_full_walk": A},
)
_bad(
    BadLaterPageErrorIsEnd,
    None,
    TS,
    {"test_an_error_on_a_later_page_is_not_the_end_of_the_list": F},
)
_bad(
    BadLaterPage429IsEnd, None, TS, {"test_an_error_on_a_later_page_is_not_the_end_of_the_list": F}
)
_bad(
    BadLookupErrorIsNotFound,
    None,
    TS,
    {"test_a_failed_lookup_of_any_kind_is_not_taken_for_not_found": F},
)
_bad(
    BadLookupTimeoutIsNotFound,
    None,
    TS,
    {"test_a_failed_lookup_of_any_kind_is_not_taken_for_not_found": F},
)
_bad(
    BadLookupErrorWritesAnyway,
    None,
    TS,
    {"test_a_failed_lookup_of_any_kind_is_not_taken_for_not_found": A},
)
_bad(
    BadTrustsAnyAuthor,
    None,
    TS,
    {
        "test_a_marker_planted_by_another_author_is_not_trusted": A,
        "test_an_author_whose_name_merely_starts_like_ours_is_not_us": A,
    },
)
_bad(
    BadForeignVariantBlocks,
    None,
    TS,
    {"test_another_authors_marker_with_other_arguments_does_not_block_our_write": K},
)
_bad(BadAuthorPrefix, None, TS, {"test_an_author_whose_name_merely_starts_like_ours_is_not_us": A})
_bad(BadKeyPrefix, None, TS, {"test_a_key_that_is_a_prefix_of_another_key_is_a_different_key": K})
_bad(
    BadAlwaysVerified,
    None,
    TS,
    {"test_a_write_accepted_but_not_applied_is_never_reported_verified": A},
)
_bad(
    "BadAlwaysVerified@notifier",
    lambda: StubTarget(BadAlwaysVerified),
    Port.NOTIFIER,
    {"test_a_write_accepted_but_not_applied_is_never_reported_verified": A},
)
_bad(BadNeverVerified, None, TS, {"test_an_applied_write_is_reported_read_back_verified": A})
_bad(BadReadBackAnyAuthor, None, TS, {"test_read_back_does_not_accept_another_authors_object": A})
_bad(
    BadReadBackErrorIsVerified,
    None,
    TS,
    {"test_a_read_back_that_fails_in_any_way_is_unknown_never_verified": A},
)
_bad(
    "BadReadBackErrorIsVerified@notifier",
    lambda: StubTarget(BadReadBackErrorIsVerified),
    Port.NOTIFIER,
    {"test_a_read_back_that_fails_in_any_way_is_unknown_never_verified": A},
)
_bad(
    BadReadBack429Or401Verified,
    None,
    TS,
    {"test_a_read_back_that_fails_in_any_way_is_unknown_never_verified": A},
)
_bad(
    BadHammersOn429,
    None,
    TS,
    {"test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": F},
)
_bad(
    BadLimitIsPermanent,
    None,
    TS,
    {"test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": P},
)
_bad(
    BadSecondaryIsPermanent,
    None,
    TS,
    {"test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": P},
)
_bad(
    BadDropsRetryAfter,
    None,
    TS,
    {"test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": A},
)
_bad(
    BadShrinksRetryAfter,
    None,
    TS,
    {"test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": A},
)
_bad(
    BadPost429AssumedApplied,
    None,
    TS,
    {"test_a_rate_limited_post_is_transient_and_applies_nothing": F},
)
_bad(BadRetriesAuth, None, TS, {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A})
_bad(
    BadAuthIsNotFound,
    None,
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A},
)
_bad(
    BadAuthIsTransient,
    None,
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": T},
)
_bad(BadAuthIsStale, None, TS, {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A})
_bad(
    BadAuthIsLocalNotFound,
    None,
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A},
)
_bad(
    BadAuthIsLocalStale,
    None,
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A},
)
_bad(BadPost401IsNotFound, None, TS, {"test_a_401_at_any_step_of_a_write_is_an_auth_error": A})
_bad(
    BadAuthLatches,
    None,
    TS,
    {
        "test_the_probe_succeeds_once_auth_is_restored_and_nothing_latches": P,
        "test_the_write_succeeds_once_auth_is_restored": P,
    },
)
_bad(
    Bad403IsNotFound,
    None,
    TS,
    {
        "test_a_plain_403_on_a_read_is_a_permission_error": A,
        "test_a_plain_403_at_any_step_of_a_write_is_a_permission_error": A,
    },
)
_bad(
    BadEvery403IsRateLimit,
    None,
    TS,
    {
        "test_a_plain_403_on_a_read_is_a_permission_error": RateLimited,
        "test_a_plain_403_at_any_step_of_a_write_is_a_permission_error": RateLimited,
    },
)
_bad(
    Bad404IsAuth,
    None,
    TS,
    {
        "test_a_404_on_a_read_is_an_unknown_object_not_a_credential_error": P,
        "test_a_404_at_any_step_of_a_write_is_an_unknown_object": P,
    },
)
_bad(BadWrite404IsAuth, None, TS, {"test_a_404_at_any_step_of_a_write_is_an_unknown_object": P})
_bad(
    BadUnsignedWindow,
    _github(BadUnsignedWindow),
    Port.SCM,
    {"test_t6_a_genuine_delivery_older_than_the_window": P},
)
_bad(
    BadUnsignedWideWindow,
    _github(BadUnsignedWideWindow),
    Port.SCM,
    {"test_t6_a_genuine_delivery_older_than_the_window": P},
)
_bad(
    BadDedupeTtl100k,
    _github(BadDedupeTtl100k),
    Port.SCM,
    {"test_dedupe_does_not_expire_while_the_delivery_can_still_be_replayed": A},
)
_bad(
    BadDedupeIncludesTimestamp,
    _github(BadDedupeIncludesTimestamp),
    Port.SCM,
    {"test_t6_a_bumped_timestamp_cannot_revive_an_old_delivery": A},
)
_bad(
    BadBumpableTimestamp,
    lambda: StubTarget(BadBumpableTimestamp, Stub(ts_signed=False)),
    TS,
    {"test_t6_a_bumped_timestamp_cannot_revive_an_old_delivery": F},
)
_bad(
    BadSlackNoWindow,
    _slack(BadSlackNoWindow),
    Port.NOTIFIER,
    {"test_t6_a_genuine_delivery_older_than_the_window": F},
)
_bad(
    BadRefreshTwice,
    lambda: StubTarget(BadRefreshTwice, Stub(ts_signed=False), Vendor.JIRA),
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A},
)
_bad(
    BadRefreshTwiceBeforeRetry,
    lambda: StubTarget(BadRefreshTwiceBeforeRetry, Stub(ts_signed=False), Vendor.JIRA),
    TS,
    {"test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A},
)
_bad(
    "BadNeverRefreshes",
    lambda: StubTarget(GitHubAdapter, Stub(ts_signed=False), Vendor.JIRA),
    TS,
    {
        "test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A,
        "test_an_expired_token_is_refreshed_only_if_the_vendor_allows_it": P,
    },
)
_bad(
    BadRefreshesWhenNotAllowed,
    lambda: StubTarget(BadRefreshesWhenNotAllowed, Stub(ts_signed=False), Vendor.GITHUB),
    TS,
    {
        "test_a_401_is_an_auth_error_and_is_asked_per_the_refresh_rule": A,
        "test_an_expired_token_is_refreshed_only_if_the_vendor_allows_it": F,
    },
)
_bad(
    "BadGitHub403IsPermission",
    _github(BadGitHub403IsPermission),
    Port.SCM,
    {
        "test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": P,
        "test_a_rate_limited_post_is_transient_and_applies_nothing": P,
    },
)
_bad(
    "BadCapabilityOverride",
    lambda: OverridesCapabilities(BadGitHub403IsPermission, Stub(ts_signed=False), Vendor.GITHUB),
    Port.SCM,
    {
        "test_every_rate_limit_shape_is_transient_carries_its_wait_and_is_not_hammered": PortClaimError  # noqa: E501
    },
)
_bad(
    BadPermanentReadIsZero,
    None,
    TS,
    {
        "test_a_read_refused_for_credentials_is_an_auth_error_never_a_revision": F,
        "test_a_plain_403_or_404_on_a_read_is_an_error_never_a_revision": F,
    },
)
_bad(
    BadEnqueuesUnsigned,
    None,
    TS,
    {"test_t6_a_delivery_with_only_the_signature_removed_is_rejected": A},
)
_bad(BadEnqueuesOnMissingId, None, TS, {"test_a_delivery_with_no_id_is_refused_not_given_one": A})
_bad(
    BadEnqueuesBeforeParse,
    None,
    TS,
    {"test_a_verified_but_malformed_body_is_refused_and_does_not_burn_its_id": A},
)
_bad(
    BadLaterPageErrorPostsThenRaises,
    None,
    TS,
    {"test_an_error_on_a_later_page_is_not_the_end_of_the_list": A},
)
_bad(
    BadForeignVariantSuppresses,
    None,
    TS,
    {"test_another_authors_marker_with_other_arguments_does_not_block_our_write": A},
)
_bad(
    BadLaterPageAuthIsEnd, None, TS, {"test_an_error_on_a_later_page_is_not_the_end_of_the_list": A}
)
# PINNED-END


def test_the_reference_and_vendor_shaped_adapters_pass_every_test() -> None:
    for factory, port in (
        (reference, Port.TICKET_SOURCE),
        (notifier_port, Port.NOTIFIER),
        (github_shaped, Port.SCM),
        (slack_shaped, Port.NOTIFIER),
        (jira_refresh_once, Port.TICKET_SOURCE),
        (webhook_only, Port.WEBHOOK),
        (auth_webhook, Port.AUTH_WEBHOOK),
    ):
        failed = {n: e for n, e in run_suite(factory, port).items() if e is not None}
        assert failed == {}, (factory.__name__, port)


@pytest.mark.parametrize("name", sorted(KNOWN_BAD))
def test_known_bad_adapters_fail_the_suite(name: str) -> None:
    factory, port, pinned = KNOWN_BAD[name]
    results = run_suite(factory, port)
    for test, expected in pinned.items():
        error = results[test]
        assert error is not None, f"{name} slipped past {test}"
        assert type(error) is expected, f"{name} failed {test} with {type(error).__name__}"
    broken = {n: e for n, e in results.items() if isinstance(e, (HarnessError, MissingControl))}
    assert broken == {}, "a bad adapter must fail the contract, not the harness"
    if PortClaimError not in pinned.values():
        assert not any(isinstance(e, PortClaimError) for e in results.values())


def test_every_bad_adapter_is_in_the_table() -> None:
    defined = {k for k, v in globals().items() if k.startswith("Bad") and isinstance(v, type)}
    assert defined <= {k.split("@")[0] for k in KNOWN_BAD}, sorted(
        defined - {k.split("@")[0] for k in KNOWN_BAD}
    )


def test_every_suite_test_is_pinned_by_a_bad_adapter_or_is_a_harness_check() -> None:
    pinned = set().union(*(set(p) for _, _, p in KNOWN_BAD.values()))
    harness_checks = {
        "test_a_forged_delivery_differs_from_a_genuine_one_only_in_its_signature",
        "test_t6_the_replay_window_is_no_wider_than_the_suite_allows",
        "test_t6_tampered_body_is_rejected",
        "test_t6_a_bumped_timestamp_cannot_revive_an_old_delivery",
        "test_t6_a_missing_or_garbage_time_header",
        "test_crash_after_the_write_applied_then_a_restart_does_not_write_again",
        "test_crash_when_the_lookup_fails_then_a_restart_writes_once",
        "test_a_write_accepted_but_not_applied_is_never_reported_verified",
        "test_an_applied_write_is_reported_read_back_verified",
    }
    unpinned = set(applicable(Port.TICKET_SOURCE)) - pinned - harness_checks
    assert unpinned == set(), sorted(unpinned)


def test_a_bare_target_fails_by_missing_control_or_harness_never_passes() -> None:
    class Bare(Target):
        name = "bare"

    failures = run_suite(Bare)
    assert failures
    assert all(isinstance(e, (MissingControl, HarnessError)) for e in failures.values())


def test_an_inconsistent_forge_is_a_harness_error_not_an_adapter_failure() -> None:
    class Sloppy(StubTarget):
        def forge(
            self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
        ) -> RawWebhook:
            return self.server.delivery(revision + 1, delivery_id, secret=b"x")

    name = "test_a_forged_delivery_differs_from_a_genuine_one_only_in_its_signature"
    assert type(run_suite(Sloppy)[name]) is HarnessError


def test_an_adapter_whose_forge_skips_is_a_failure_not_a_pass() -> None:
    class Skipper(StubTarget):
        def forge(
            self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
        ) -> RawWebhook:
            pytest.skip("cannot forge here")

    name = "test_t6_every_kind_of_forgery_is_rejected_and_enqueues_nothing"
    error = run_suite(Skipper)[name]
    assert isinstance(error, pytest.skip.Exception)


# --- sections, ports, vendors -----------------------------------------------------------------


def test_sections_come_from_the_port() -> None:
    assert PORT_SECTIONS[Port.WEBHOOK] == {Section.WEBHOOK}
    assert "test_a_new_key_is_a_new_write" not in applicable(Port.WEBHOOK)
    assert "test_t6_genuine_delivery_is_accepted" in applicable(Port.WEBHOOK)
    assert applicable(Port.TICKET_SOURCE) == applicable(Port.SCM)
    assert set(applicable(Port.AUTH_WEBHOOK)) & set(applicable(Port.WEBHOOK)) == set(
        applicable(Port.WEBHOOK)
    )


def test_a_notifier_has_read_back_and_no_ordering() -> None:
    """``send`` returns a Receipt with ``read_back_verified``, so G8 applies; no state read."""
    notifier = set(applicable(Port.NOTIFIER))
    assert "test_an_applied_write_is_reported_read_back_verified" in notifier
    assert "test_a_write_accepted_but_not_applied_is_never_reported_verified" in notifier
    assert "test_a_read_back_that_fails_in_any_way_is_unknown_never_verified" in notifier
    assert "test_delivery_order_does_not_change_what_the_adapter_reports" not in notifier
    assert Section.ORDERING not in PORT_SECTIONS[Port.NOTIFIER]


def test_a_subclass_of_a_narrow_port_has_no_other_tests_to_fail() -> None:
    assert TestWebhookOnlyTarget.test_a_new_key_is_a_new_write is None
    assert TestNotifierPort.test_delivery_order_does_not_change_what_the_adapter_reports is None
    assert TestReferenceAdapter.test_a_new_key_is_a_new_write is not None


def test_the_auth_webhook_port_needs_no_write_surface() -> None:
    target = auth_webhook()
    with pytest.raises(HarnessError):
        target.write("k")
    for name in applicable(Port.AUTH_WEBHOOK):
        assert "write" not in name
        assert "key" not in name


def test_the_port_is_verified_not_claimed() -> None:
    """An adapter implementing a wider port cannot claim a narrower one."""
    ticket_adapter = types.SimpleNamespace(
        vendor=Vendor.GITHUB, adapter=FakeTicketSource(SpyWriter())
    )
    notifier_adapter = types.SimpleNamespace(vendor=Vendor.SLACK, adapter=FakeNotifier(SpyWriter()))
    with pytest.raises(PortClaimError, match="narrower"):
        validate_target(ticket_adapter, Port.WEBHOOK)  # type: ignore[arg-type]
    with pytest.raises(PortClaimError, match="narrower"):
        validate_target(notifier_adapter, Port.WEBHOOK)  # type: ignore[arg-type]
    validate_target(ticket_adapter, Port.TICKET_SOURCE)  # type: ignore[arg-type]
    validate_target(ticket_adapter, Port.SCM)  # type: ignore[arg-type]
    validate_target(notifier_adapter, Port.NOTIFIER)  # type: ignore[arg-type]
    validate_target(notifier_adapter, Port.TICKET_SOURCE)  # type: ignore[arg-type]


def test_an_adapter_that_implements_no_port_cannot_claim_one() -> None:
    class Plain:
        pass

    target = types.SimpleNamespace(vendor=Vendor.SLACK, adapter=Plain())
    for port in (Port.TICKET_SOURCE, Port.SCM, Port.NOTIFIER):
        with pytest.raises(PortClaimError, match="implements no"):
            validate_target(target, port)  # type: ignore[arg-type]
    validate_target(target, Port.WEBHOOK)  # type: ignore[arg-type]
    validate_target(target, Port.AUTH_WEBHOOK)  # type: ignore[arg-type]


def test_only_the_reference_adapters_are_exempt_from_the_port_check() -> None:
    assert is_reference(Adapter)
    assert is_reference(BadInProcessKeys)
    assert not is_reference(FakeTicketSource)

    class Local(Adapter):  # defined here, but not a module attribute: not the reference
        pass

    assert not is_reference(Local)
    spoofed = types.SimpleNamespace(vendor=Vendor.STUB, adapter=Local(Stub()))
    with pytest.raises(PortClaimError, match="STUB"):
        validate_target(spoofed, Port.WEBHOOK)  # type: ignore[arg-type]


def test_an_unsigned_timestamp_vendor_cannot_be_a_notifier() -> None:
    """A Notifier has no ordering section, so no re-read stands in for a replay window."""
    with pytest.raises(PortClaimError, match="unsigned"):
        validate_target(github_shaped(), Port.NOTIFIER)
    validate_target(slack_shaped(), Port.NOTIFIER)


def test_a_target_must_name_a_vendor() -> None:
    class NoVendor(Target):
        adapter = FakeTicketSource(SpyWriter())

    with pytest.raises(HarnessError, match="Vendor"):
        validate_target(NoVendor(), Port.WEBHOOK)


def test_vendor_capabilities_are_owned_by_the_suite() -> None:
    assert CAPABILITIES[Vendor.SLACK].rate_shapes == {RateShape.PRIMARY_429}
    assert CAPABILITIES[Vendor.SLACK].signed_timestamp
    assert not CAPABILITIES[Vendor.GITHUB].signed_timestamp
    assert RateShape.SECONDARY_403_NO_HEADER in CAPABILITIES[Vendor.GITHUB].rate_shapes
    assert CAPABILITIES[Vendor.JIRA].auth_refresh is AuthRefresh.ONCE
    assert CAPABILITIES[Vendor.STUB].rate_shapes == frozenset(RateShape)
    assert set(SHAPE_RETRY_AFTER) == set(RateShape)
    for caps in CAPABILITIES.values():
        assert caps.rate_shapes
    with pytest.raises(ValueError, match="shape"):
        Capabilities(True, frozenset(), AuthRefresh.NONE)


def test_no_vendor_removes_signature_dedupe_auth_or_idempotency() -> None:
    assert not {Control.SIGNATURE, Control.DUPLICATE, Control.AUTH, Control.CRASH} & WAIVABLE
    assert set(Capabilities.__dataclass_fields__) == {
        "signed_timestamp",
        "rate_shapes",
        "auth_refresh",
    }


def test_a_target_cannot_override_its_vendors_capabilities_by_attribute_or_property() -> None:
    class ByProperty(StubTarget):
        @property
        def capabilities(self) -> Capabilities:
            return Capabilities(True, frozenset({RateShape.PRIMARY_429}), AuthRefresh.NONE)

    for target in (OverridesCapabilities(), ByProperty()):
        with pytest.raises(PortClaimError, match="capabilities belong to the vendor"):
            validate_target(target, Port.WEBHOOK)
    validate_target(reference(), Port.WEBHOOK)


def test_is_auth_error_rejects_every_port_error_and_its_subclasses() -> None:
    assert is_auth_error(PermanentError("401"))
    assert not is_auth_error(TransientError("429"))
    for exc in (UnknownRefError("x"), StaleHeadError("x"), IdempotencyKeyReuseError("x")):
        assert not is_auth_error(exc)
    assert not is_auth_error(_LocalNotFound("x"))
    assert not is_auth_error(_LocalStale("x"))

    class AdapterAuthError(PermanentError):
        pass

    assert is_auth_error(AdapterAuthError("401"))


# --- selection: simulated receipts, typos, every non-fake name --------------------------------


@pytest.mark.parametrize("name", ["live", "staging", "sandbox"])
def test_any_name_but_the_fake_fails_on_a_simulated_receipt(name: str) -> None:
    target = reference()
    target.selected = name
    with pytest.raises(pytest.fail.Exception, match="simulated"):
        check_not_simulated(target, Receipt("x", "", True, simulated=True))
    check_not_simulated(target, Receipt("x", "", True, simulated=False))


def test_the_fake_may_return_simulated_receipts() -> None:
    check_not_simulated(reference(), Receipt("x", "", True, simulated=True))


@pytest.mark.parametrize("name", ["live", "staging"])
def test_a_non_fake_target_backed_by_the_fake_fails_the_write_tests(name: str) -> None:
    def not_really() -> Target:
        t = reference()
        t.selected = name
        return t

    failed = {n for n, e in run_suite(not_really).items() if e is not None}
    assert "test_a_new_key_is_a_new_write" in failed
    assert "test_t6_genuine_delivery_is_accepted" not in failed  # webhooks write no receipt


def test_select_defaults_to_the_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STO_CONFORMANCE_TARGET", raising=False)
    name, target = resolve({"fake": reference})
    assert (name, target.selected) == ("fake", "fake")


@pytest.mark.parametrize("typo", ["lvie", "Live", "live ", "", "fakes"])
def test_a_typo_in_the_value_never_falls_back_to_the_fake(
    monkeypatch: pytest.MonkeyPatch, typo: str
) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", typo)
    with pytest.raises(pytest.UsageError, match="registered"):
        resolve({"fake": reference, "live": reference})


def test_a_target_that_is_not_registered_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "staging")
    with pytest.raises(pytest.UsageError):
        resolve({"fake": reference})


def test_select_reports_which_target_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "staging")
    name, target = resolve({"fake": reference, "staging": reference})
    assert (name, target.selected) == ("staging", "staging")


def test_the_fixture_records_the_target_that_ran() -> None:
    probe = types.SimpleNamespace(user_properties=[])
    fixture = AdapterConformance.target.__wrapped__  # type: ignore[attr-defined]
    holder = types.SimpleNamespace(registry={"fake": reference}, port=Port.TICKET_SOURCE)
    fixture(holder, types.SimpleNamespace(node=probe))
    assert probe.user_properties == [("conformance_target", "fake")]


# --- pending_controls: fake-only by the adapter that runs, pinned --------------------------------


def _probe() -> type[Any]:
    class TestProbe(AdapterConformance):
        port = Port.TICKET_SOURCE
        registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": reference}

    SUBCLASSES.remove(TestProbe)
    return pending_controls(Control.HTTP_ERRORS, reason="the fake has no 403 or 404")(TestProbe)


WAIVED = (
    "test_a_plain_403_on_a_read_is_a_permission_error",
    "test_a_404_on_a_read_is_an_unknown_object_not_a_credential_error",
    "test_a_plain_403_at_any_step_of_a_write_is_a_permission_error",
    "test_a_404_at_any_step_of_a_write_is_an_unknown_object",
)


class FakeBacked(Target):
    """A target whose adapter really is a fake from ``sto.adapters.fake``, with no HTTP errors."""

    name = "fake-backed"
    vendor = Vendor.STUB
    controls: ClassVar[frozenset[Control]] = frozenset()

    def __init__(self, adapter: object, selected: str = "fake") -> None:
        self.adapter = adapter
        self.selected = selected


def test_pending_controls_marks_strict_xfail_on_missing_control_only() -> None:
    probe = _probe()
    for name in WAIVED:
        marks = probe.__dict__[name].pytestmark
        xfails = [m for m in marks if m.name == "xfail"]
        assert len(xfails) == 1, "must be an xfail, not a skip"
        assert xfails[0].kwargs["strict"] is True
        assert xfails[0].kwargs["raises"] is MissingControl
        assert xfails[0].kwargs["reason"] == "the fake has no 403 or 404"
        assert not [m for m in marks if m.name == "skip"]
    assert "test_a_new_key_is_a_new_write" not in probe.__dict__


def test_pending_controls_does_not_mark_the_shared_base_tests() -> None:
    _probe()
    for name in WAIVED:
        assert not hasattr(getattr(AdapterConformance, name), "pytestmark")


@pytest.mark.parametrize("control", sorted(SECURITY_CONTROLS))
def test_pending_controls_refuses_every_non_waivable_control(control: Control) -> None:
    with pytest.raises(ValueError, match="security"):
        pending_controls(control, reason="because")


def test_pending_controls_refuses_a_class_with_every_control() -> None:
    with pytest.raises(ValueError, match="security"):
        pending_controls(*Control, reason="all of them")


def test_only_one_control_can_be_waived_at_all() -> None:
    assert {Control.HTTP_ERRORS} == WAIVABLE


@pytest.mark.parametrize("reason", ["", "   "])
def test_pending_controls_needs_a_reason(reason: str) -> None:
    with pytest.raises(ValueError, match="reason"):
        pending_controls(Control.HTTP_ERRORS, reason=reason)


def test_a_waiver_is_allowed_for_an_adapter_really_defined_as_a_fake() -> None:
    probe = _probe()
    target = FakeBacked(FakeTicketSource(SpyWriter()))
    with pytest.raises(MissingControl):  # past the guard, into the test: the xfail path
        probe().__getattribute__(WAIVED[0])(target)


def test_a_waiver_fails_for_the_adapter_that_runs_when_it_is_not_a_fake() -> None:
    """The running adapter is checked, not a class named when the waiver was written."""
    probe = _probe()
    target = FakeBacked(Bad403IsNotFound(Stub()))
    with pytest.raises(pytest.fail.Exception, match="only for a fake"):
        probe().__getattribute__(WAIVED[0])(target)


@pytest.mark.parametrize("name", ["live", "staging"])
def test_a_waiver_fails_when_the_target_is_not_the_fake(name: str) -> None:
    probe = _probe()
    target = FakeBacked(FakeTicketSource(SpyWriter()), selected=name)
    with pytest.raises(pytest.fail.Exception, match="only for the fake"):
        probe().__getattribute__(WAIVED[0])(target)


def test_is_fake_needs_a_dot_boundary_a_loaded_module_and_the_source_location() -> None:
    assert is_fake(FakeTicketSource)
    assert is_fake(FakeNotifier)
    assert is_fake(FakeScm)

    class Spoof(Adapter):
        pass

    for module in ("sto.adapters.fake.github", "sto.adapters.fake_github", "sto.adapters.fake"):
        Spoof.__module__ = module
        assert not is_fake(Spoof), module  # not loaded, or not this class, or elsewhere on disk

    class Elsewhere:
        pass

    Elsewhere.__module__ = "sto.adapters.fake.tickets"  # a loaded fake module, but not its class
    assert not is_fake(Elsewhere)


def test_a_missing_control_fails_rather_than_skips() -> None:
    with pytest.raises(MissingControl, match="rate_limit"):
        Target().require(Control.RATE_LIMIT)


# --- guards: no route around the suite -----------------------------------------------------


def _try(*bases: type, local: bool = True, **body: Any) -> type:
    """A throwaway subclass. ``local`` makes it look defined inside a function, which the
    session-wide checks leave alone (pytest cannot collect it)."""
    attrs = {"port": Port.TICKET_SOURCE, "registry": {"fake": reference}, **body}
    if local:
        attrs["__qualname__"] = "<locals>.TestRoute"
    return type("TestRoute", (*bases, AdapterConformance), attrs)


def test_a_subclass_cannot_override_a_suite_test() -> None:
    with pytest.raises(TypeError, match="test_t6_genuine_delivery_is_accepted"):
        _try(test_t6_genuine_delivery_is_accepted=lambda self, target: None)


def test_a_subclass_cannot_replace_the_target_fixture() -> None:
    with pytest.raises(TypeError, match="target"):
        _try(target=lambda self: reference())


@pytest.mark.parametrize("attr", ["pytestmark", "__test__"])
def test_a_subclass_cannot_set_marks_or_hide_itself(attr: str) -> None:
    with pytest.raises(TypeError, match=attr):
        _try(**{attr: [pytest.mark.skip] if attr == "pytestmark" else False})  # type: ignore[arg-type]


def test_a_mixin_cannot_supply_the_target_fixture() -> None:
    class Mixin:
        @pytest.fixture
        def target(self) -> Target:
            return reference()

    with pytest.raises(TypeError, match="target"):
        _try(Mixin)


def test_a_mixin_cannot_override_a_suite_test() -> None:
    class Mixin:
        def test_t6_genuine_delivery_is_accepted(self, target: Target) -> None:
            return None

    with pytest.raises(TypeError, match="test_t6_genuine_delivery_is_accepted"):
        _try(Mixin)


def test_a_mixin_overriding_init_subclass_is_caught_at_collection() -> None:
    class Mixin:
        def __init_subclass__(cls, **kwargs: Any) -> None:  # never calls super(): opts out
            pass

    cls = _try(Mixin)  # creation is not refused: the mixin's hook ran instead of the suite's
    try:
        assert cls not in SUBCLASSES
        problems = check_collection([_item(cls, "test_t6_genuine_delivery_is_accepted")], [])
        assert any("never registered" in p for p in problems), problems
        assert any("__init_subclass__" in p for p in check_class(cls))
    finally:
        if cls in SUBCLASSES:
            SUBCLASSES.remove(cls)


def test_collection_rechecks_a_class_whose_fixture_was_swapped_after_creation() -> None:
    cls = _try()
    try:
        cls.target = lambda self: reference()  # type: ignore[attr-defined]
        problems = check_collection([_item(cls, "test_t6_genuine_delivery_is_accepted")], [])
        assert any("target" in p for p in problems), problems
    finally:
        SUBCLASSES.remove(cls)


def test_a_subclass_cannot_add_a_helper_a_hook_or_override_the_suites_machinery() -> None:
    """The allow-list: only `port`, `registry` and Python's own class attributes."""
    with pytest.raises(TypeError, match="_crash_then_retry"):
        _try(_crash_then_retry=lambda self, *a: None)
    with pytest.raises(TypeError, match="pytest_generate_tests"):
        _try(pytest_generate_tests=lambda self, metafunc: None)
    with pytest.raises(TypeError, match="helper"):
        _try(helper=lambda self: None)


def test_a_subclass_removed_from_the_registry_is_still_found_at_collection() -> None:
    cls = _try(local=False, port=Port.WEBHOOK, registry={"fake": webhook_only})
    SUBCLASSES.remove(cls)
    problems = check_collection([], [str(Path(__file__).parent)])
    assert f"{cls.__name__} is a conformance subclass that was never registered" in problems


def test_a_swallowed_init_subclass_with_a_non_test_name_is_found_at_collection() -> None:
    class Mixin:
        def __init_subclass__(cls, **kwargs: Any) -> None:
            pass

    cls = type(
        "NotNamedTest",
        (Mixin, AdapterConformance),
        {"port": Port.WEBHOOK, "registry": {"fake": webhook_only}},
    )
    assert cls not in SUBCLASSES
    problems = check_collection([], [str(Path(__file__).parent)])
    assert any("NotNamedTest" in p and "never registered" in p for p in problems), problems


def test_a_conformance_subclass_must_be_named_test() -> None:
    with pytest.raises(TypeError, match="Test"):
        type(
            "Conformance",
            (AdapterConformance,),
            {"port": Port.SCM, "registry": {"fake": reference}},
        )


@pytest.mark.parametrize("missing", ["port", "registry"])
def test_a_conformance_subclass_must_set_port_and_registry(missing: str) -> None:
    attrs: dict[str, Any] = {"port": Port.SCM, "registry": {"fake": reference}}
    del attrs[missing]
    with pytest.raises(TypeError, match=missing):
        type("TestIncomplete", (AdapterConformance,), attrs)


def _item(cls: type, name: str, fn: Any = None, marks: tuple[str, ...] = ()) -> Any:
    fn = fn or getattr(cls, name)
    return types.SimpleNamespace(
        cls=cls,
        originalname=name,
        function=fn,
        iter_markers=lambda: iter(types.SimpleNamespace(name=m) for m in marks),
    )


def test_check_collection_flags_a_subclass_that_collected_nothing() -> None:
    cls = _try(local=False, port=Port.WEBHOOK, registry={"fake": webhook_only})
    try:
        here = [str(Path(__file__).parent)]
        orphan = f"{__name__}.TestRoute collected no test"
        assert orphan in check_collection([], here)
        items = [_item(cls, n) for n in applicable(Port.WEBHOOK)]
        assert orphan not in check_collection(items, here)
    finally:
        SUBCLASSES.remove(cls)


def test_check_collection_flags_a_subclass_hidden_with_test_false_after_creation() -> None:
    cls = _try(local=False, port=Port.WEBHOOK, registry={"fake": webhook_only})
    cls.__test__ = False  # type: ignore[attr-defined]  # after creation: pytest skips the class
    try:
        problems = check_collection([], [str(Path(__file__).parent)])
        assert f"{__name__}.TestRoute collected no test" in problems
    finally:
        SUBCLASSES.remove(cls)


def test_check_collection_flags_a_replaced_suite_test() -> None:
    name = "test_t6_genuine_delivery_is_accepted"
    items = [_item(TestWebhookOnlyTarget, name, lambda self, target: None)]
    problems = check_collection(items, [f"{__file__}::TestWebhookOnlyTarget"])
    assert f"TestWebhookOnlyTarget.{name} is not the suite's own test" in problems


def test_check_collection_is_quiet_for_a_genuine_item_in_a_named_selection() -> None:
    name = "test_t6_genuine_delivery_is_accepted"
    items = [_item(TestWebhookOnlyTarget, name)]
    assert check_collection(items, [f"{__file__}::TestWebhookOnlyTarget::{name}"]) == []


def test_a_node_id_narrows_the_check_only_to_the_classes_it_names() -> None:
    """Not the whole session: a class the selection does not name is out of it, but a named class
    is held to every test its port requires."""
    names = [n for n in applicable(Port.WEBHOOK) if n != "test_t6_genuine_delivery_is_accepted"]
    items = [_item(TestWebhookOnlyTarget, n) for n in names]
    problems = check_collection(items, [f"{__file__}::TestWebhookOnlyTarget"])
    assert (
        "TestWebhookOnlyTarget.test_t6_genuine_delivery_is_accepted was not collected" in problems
    )
    assert not [p for p in problems if "TestReferenceAdapter" in p]


def test_check_collection_flags_a_test_the_port_requires_but_was_not_collected() -> None:
    names = [n for n in applicable(Port.WEBHOOK) if n != "test_t6_genuine_delivery_is_accepted"]
    items = [_item(TestWebhookOnlyTarget, n) for n in names]
    problems = check_collection(items, [str(Path(__file__).parent)])
    assert (
        "TestWebhookOnlyTarget.test_t6_genuine_delivery_is_accepted was not collected" in problems
    )


@pytest.mark.parametrize("mark", ["live", "integration", "skip", "xfail", "e2e"])
def test_check_collection_flags_an_in_process_class_carrying_an_escape_marker(mark: str) -> None:
    name = "test_t6_genuine_delivery_is_accepted"
    items = [_item(TestWebhookOnlyTarget, name, marks=(mark,))]
    problems = check_collection(items, [f"{__file__}::TestWebhookOnlyTarget::{name}"])
    assert any(mark in p for p in problems), problems


def test_check_collection_allows_the_xfail_pending_controls_made() -> None:
    probe = _probe()
    name = WAIVED[0]
    item = types.SimpleNamespace(
        cls=TestReferenceAdapter,
        originalname=name,
        function=probe.__dict__[name],
        iter_markers=lambda: iter([types.SimpleNamespace(name="xfail")]),
    )
    problems = check_collection([item], [f"{__file__}::TestReferenceAdapter::{name}"])
    assert not [p for p in problems if "xfail" in p], problems


def test_enforce_outcome_turns_a_skip_or_an_xfail_into_a_failure() -> None:
    item = _item(TestReferenceAdapter, "test_a_new_key_is_a_new_write")
    skipped = types.SimpleNamespace(outcome="skipped", longrepr=None)
    enforce_outcome(item, skipped)
    assert skipped.outcome == "failed"
    xfailed = types.SimpleNamespace(outcome="skipped", longrepr=None, wasxfail="because")
    enforce_outcome(item, xfailed)
    assert xfailed.outcome == "failed"
    assert not hasattr(xfailed, "wasxfail")
    passed = types.SimpleNamespace(outcome="passed", longrepr=None)
    enforce_outcome(item, passed)
    assert passed.outcome == "passed"


def test_enforce_outcome_allows_the_xfail_pending_controls_makes() -> None:
    probe = _probe()
    fn = probe.__dict__[WAIVED[0]]
    item = types.SimpleNamespace(cls=TestReferenceAdapter, originalname=WAIVED[0], function=fn)
    report = types.SimpleNamespace(outcome="skipped", longrepr=None, wasxfail="x")
    enforce_outcome(item, report)
    assert report.outcome == "skipped"


def test_the_collection_guard_runs_before_deselection_and_is_a_plugin_for_every_session() -> None:
    import contract

    options = contract.pytest_collection_modifyitems.pytest_impl  # type: ignore[attr-defined]
    assert options["tryfirst"] is True, "it must see items before -m and -k deselect them"
    assert contract.pytest_runtest_makereport.pytest_impl["hookwrapper"] is True  # type: ignore[attr-defined]
    addopts = (TESTS_DIR.parent / "pyproject.toml").read_text()
    assert '"-p", "contract"' in addopts, "loaded for every session, like hermetic_guard"
    assert not (Path(__file__).parent / "conftest.py").exists()


def test_the_plugin_imports_nothing_from_sto(tmp_path: Path) -> None:
    """Else coverage starts after ``sto`` is imported and reports it as unmeasured."""
    out = tmp_path / "imported.txt"
    (tmp_path / "pytest.ini").write_text(
        f"[pytest]\npythonpath = {TESTS_DIR} {SRC_DIR}\naddopts = -p contract -p no:cacheprovider\n"
    )
    (tmp_path / "conftest.py").write_text(
        "import sys\n"
        f"open({str(out)!r}, 'w').write(repr(sorted(m for m in sys.modules "
        "if m == 'sto' or m.startswith('sto.'))))\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert out.read_text() == "[]", result.stdout + result.stderr


# --- the guards, end to end, in a real pytest run -------------------------------------------


def _project(tmp_path: Path, test_source: str, conftest_extra: str = "") -> Path:
    (tmp_path / "pytest.ini").write_text(
        textwrap.dedent(
            f"""\
            [pytest]
            pythonpath = {TESTS_DIR} {SRC_DIR}
            addopts = -p contract -p no:cacheprovider
            markers =
                contract
                live
            """
        )
    )
    (tmp_path / "conftest.py").write_text(
        "import pytest\n\n"
        "def pytest_collection_modifyitems(items):\n"
        "    for item in items:\n"
        "        item.add_marker(pytest.mark.contract)\n" + conftest_extra
    )
    (tmp_path / "test_adapter.py").write_text(
        "import pytest\n"
        "from contract.suite import AdapterConformance, ForgeKind, Port\n"
        "from contract.test_suite import GitHubAdapter, Stub, Vendor, WebhookOnlyTarget\n\n"
        "def webhook_only():\n"
        "    return WebhookOnlyTarget(GitHubAdapter, Stub(ts_signed=False), Vendor.GITHUB)\n\n"
        + textwrap.dedent(test_source)
    )
    return tmp_path


def _run(project: Path, *extra: str, marker: str = "contract") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-m", marker, str(project), *extra],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


HEALTHY = """
    class TestIngest(AdapterConformance):
        port = Port.WEBHOOK
        registry = {"fake": webhook_only}
"""


def test_e2e_a_healthy_subclass_passes_under_the_ci_selector(tmp_path: Path) -> None:
    result = _run(_project(tmp_path, HEALTHY))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "passed" in result.stdout


def test_e2e_a_subclass_that_collects_nothing_fails_under_m_contract(tmp_path: Path) -> None:
    source = (
        HEALTHY
        + """
    class TestOrphan(AdapterConformance):
        port = Port.WEBHOOK
        registry = {"fake": webhook_only}

    TestOrphan.__test__ = False
"""
    )
    result = _run(_project(tmp_path, source))
    assert result.returncode != 0
    assert "TestOrphan collected no test" in result.stdout + result.stderr


def test_e2e_a_class_marked_live_cannot_leave_the_in_process_run(tmp_path: Path) -> None:
    source = (
        HEALTHY
        + """
    pytest.mark.live(TestIngest)
"""
    )
    result = _run(_project(tmp_path, source), marker="contract and not live")
    assert result.returncode != 0, "deselected by `not live` with exit 0 was the hole"
    assert "carries ['live']" in result.stdout + result.stderr


def test_e2e_a_mark_applied_from_outside_cannot_skip_the_suite(tmp_path: Path) -> None:
    skip = "        item.add_marker(pytest.mark.skip(reason='not today'))\n"
    result = _run(_project(tmp_path, HEALTHY, skip))
    assert result.returncode != 0
    assert "may not be skipped or xfailed" in result.stdout + result.stderr


def test_e2e_a_mark_applied_from_outside_cannot_xfail_the_suite(tmp_path: Path) -> None:
    xfail = "        item.add_marker(pytest.mark.xfail(reason='known'))\n"
    result = _run(_project(tmp_path, HEALTHY, xfail))
    assert result.returncode != 0
    assert "may not be skipped or xfailed" in result.stdout + result.stderr


def test_e2e_the_repos_own_pytest_config_guards_a_subclass_in_another_directory(
    tmp_path: Path,
) -> None:
    """From the repo's pyproject (``addopts``), under ``-m contract``, a subclass outside
    ``tests/contract`` whose ``forge()`` skips must fail: the plugin loads for every session."""
    other = tmp_path / "contract"
    other.mkdir()
    (other / "test_other.py").write_text(
        textwrap.dedent(
            """\
            import pytest
            from contract.suite import AdapterConformance, ForgeKind, Port
            from contract.test_suite import GitHubAdapter, Stub, Vendor, WebhookOnlyTarget

            class SkipsToForge(WebhookOnlyTarget):
                def forge(self, revision, delivery_id, how=ForgeKind.WRONG_SECRET):
                    pytest.skip("cannot forge")

            def target():
                return SkipsToForge(GitHubAdapter, Stub(ts_signed=False), Vendor.GITHUB)

            class TestElsewhere(AdapterConformance):
                port = Port.WEBHOOK
                registry = {"fake": target}
            """
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-m",
            "contract",
            "-c",
            str(TESTS_DIR.parent / "pyproject.toml"),
            "--rootdir",
            str(TESTS_DIR.parent),
            "-p",
            "no:cacheprovider",
            str(other / "test_other.py"),
        ],
        cwd=TESTS_DIR.parent,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "may not be skipped or xfailed" in output


# --- the merged fakes (D1-04) -----------------------------------------------------------------
# They verify no signatures, dedupe nothing, limit no rate and fail no auth, and keep their
# idempotency ledger in the object, so a restart is impossible. Waiving security controls is
# refused, so they are held to what they CAN do. Their gaps are findings in the PR body.

REPO = RepoRef("acme", "app")


class _FakeWriter:
    def __init__(self, method: str, make: Callable[[SpyWriter], Any], call: Callable[..., Any]):
        self.method, self.spy = method, SpyWriter()
        self.fake = make(self.spy)
        self._call = call

    def write(self, key: str, variant: str = "a") -> Receipt:
        return self._call(self.fake, key, variant)  # type: ignore[no-any-return]

    def effects(self) -> int:
        return len(self.spy.applied(self.method))


def _tickets() -> _FakeWriter:
    def make(spy: SpyWriter) -> FakeTicketSource:
        fake = FakeTicketSource(spy)
        fake.add_ticket(Ticket(TREF, "t", "b", "open"))
        return fake

    return _FakeWriter("comment", make, lambda f, k, v: f.comment(TREF, f"body-{v}", k))


def _scm() -> _FakeWriter:
    def make(spy: SpyWriter) -> FakeScm:
        fake = FakeScm(spy)
        fake.seed_branch(REPO, "main", "sha0")
        return fake

    return _FakeWriter(
        "publish_check",
        make,
        lambda f, k, v: f.publish_check(CheckSpec(REPO, "sha0", f"check-{v}", "success"), k),
    )


def _notifier() -> _FakeWriter:
    return _FakeWriter(
        "send",
        FakeNotifier,
        lambda f, k, v: f.send(GateMessage(f"gate-{v}", "s", "digest"), k),
    )


@pytest.fixture(params=[_tickets, _scm, _notifier], ids=["tickets", "scm", "notifier"])
def fake_writer(request: pytest.FixtureRequest) -> _FakeWriter:
    return request.param()  # type: ignore[no-any-return]


class TestMergedFakesIdempotency:
    """Same-instance only: the ledger lives in the fake, so there is no restart to test."""

    def test_replaying_a_key_returns_the_first_receipt(self, fake_writer: _FakeWriter) -> None:
        first = fake_writer.write("k1")
        assert fake_writer.write("k1") == first
        assert fake_writer.effects() == 1

    def test_a_new_key_is_a_new_write(self, fake_writer: _FakeWriter) -> None:
        fake_writer.write("k1", "a")
        fake_writer.write("k2", "b")
        assert fake_writer.effects() == 2

    def test_a_key_reused_with_other_arguments_is_refused(self, fake_writer: _FakeWriter) -> None:
        fake_writer.write("k1", "a")
        with pytest.raises(IdempotencyKeyReuseError):
            fake_writer.write("k1", "b")
        assert fake_writer.effects() == 1

    def test_a_lost_response_then_a_retry_writes_once(self, fake_writer: _FakeWriter) -> None:
        fake_writer.fake.lose_response_next(fake_writer.method)
        with pytest.raises(TransientError):
            fake_writer.write("k1")
        assert fake_writer.effects() == 1
        fake_writer.write("k1")
        assert fake_writer.effects() == 1

    def test_a_failure_before_the_write_then_a_retry_writes_once(
        self, fake_writer: _FakeWriter
    ) -> None:
        fake_writer.fake.fail_next(fake_writer.method)
        with pytest.raises(TransientError):
            fake_writer.write("k1")
        assert fake_writer.effects() == 0
        fake_writer.write("k1")
        assert fake_writer.effects() == 1
