"""The fake Jira as a SENDER of webhooks (D6-09): signatures, retries and no ordering.

It sends and signs. It does not verify, dedupe or enqueue: those are the receiver's (D6-05) and
the conformance suite drives the real verifier. Every secret, ID and payload is synthetic.

Sourced to https://developer.atlassian.com/cloud/jira/platform/webhooks/ :

* Admin webhooks with a secret carry the HMAC in ``X-Hub-Signature`` as ``method=signature``
  (here ``sha256=<hex>`` over the raw body).
* Webhooks of an OAuth 2.0 app carry a token in ``Authorization`` "signed with the app's client
  secret" (here a HS256 JWT).
* ``X-Atlassian-Webhook-Identifier`` is unique within a tenant and unchanged across retries;
  ``X-Atlassian-Webhook-Retry`` carries the retry count on retried deliveries only.
* Retries: status 408, 409, 425, 429 and any 5xx, and connection failures and timeouts, are
  retried up to five times, 5 to 15 minutes after the previous attempt. A recipient that has not
  answered successfully within 30 minutes gets a single attempt per webhook until one succeeds.
* Some webhooks are delivered more than once, and no order is documented. Payloads carry
  ``webhookEvent``, ``timestamp`` (milliseconds), and for issue events ``user`` and ``issue``;
  ``changelog`` only on ``jira:issue_updated``; registered webhooks add ``matchedWebhookIds``.

Unsourced departures, to prove in D12:

* Whether the OAuth token covers the body is unconfirmed (D6-05 must settle it). The fake's JWT
  does NOT: its claims are ``iss``, ``iat`` and ``exp`` only, and a tampered body keeps a valid
  token. A receiver must not read that token as proof of the body.
* A retry resends the same bytes and the same token and signature. ``X-Atlassian-Webhook-Retry``
  counts from 1. The wait is a whole number of seconds, chosen from a seeded generator.
* Delivery order is the order the test gives; ``unordered`` produces a seeded permutation.
  ``duplicate`` is a second delivery with the same identifier and no retry header.
* The ``changelog`` is empty of items; the payload's ``user`` is the fake's own account.
* One delivery per URL, listing every matching registration in ``matchedWebhookIds``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from fakes.jira.issues.server import ACCOUNT_ID
from fakes.jira.workflow.server import FakeJiraWorkflow
from sto.adapters.ports import RawWebhook

ADMIN_SECRET = b"synthetic-jira-admin-secret"
CLIENT_SECRET = b"synthetic-jira-client-secret"
WRONG_SECRET = b"synthetic-not-the-secret"
RETRYABLE = frozenset({408, 409, 425, 429})
MAX_RESENDS = 5
SLOW_AFTER = 30 * 60.0
RETRY_MIN, RETRY_MAX = 5 * 60, 15 * 60
IDENT = "X-Atlassian-Webhook-Identifier"
RETRY = "X-Atlassian-Webhook-Retry"
SIGNATURE = "X-Hub-Signature"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def _jwt(secret: bytes, issued: int) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": "synthetic-app", "iat": issued, "exp": issued + 300}).encode())
    mac = hmac.new(secret, f"{head}.{claims}".encode(), hashlib.sha256).digest()
    return f"{head}.{claims}.{_b64(mac)}"


@dataclass(frozen=True)
class Attempt:
    at: float  # fake time
    status: int | None  # None: a timeout or dropped connection


@dataclass(frozen=True)
class DeliveryReport:
    identifier: str
    attempts: tuple[Attempt, ...]

    @property
    def delivered(self) -> bool:
        last = self.attempts[-1].status
        return last is not None and 200 <= last < 300


class FakeJiraWebhooks:
    """Jira sending webhooks about ``jira``'s issues; retries advance ``jira.now``."""

    def __init__(
        self,
        jira: FakeJiraWorkflow,
        *,
        admin_secret: bytes = ADMIN_SECRET,
        client_secret: bytes = CLIENT_SECRET,
        seed: int = 7,
    ) -> None:
        self.jira, self.admin_secret, self.client_secret = jira, admin_secret, client_secret
        self.degraded = False
        self._rng = random.Random(seed)
        self._n = 0

    def _body(self, event: str, key: str, matched: list[int] | None) -> bytes:
        payload: dict[str, Any] = {
            "timestamp": int(self.jira.now * 1000),
            "webhookEvent": event,
            "issue_event_type_name": "issue_generic",
            "user": {"accountId": ACCOUNT_ID},
            "issue": self.jira.issue_snapshot(key),
        }
        if event == "jira:issue_updated":
            payload["changelog"] = {"id": str(self._n), "items": []}
        if matched is not None:
            payload["matchedWebhookIds"] = matched
        return json.dumps(payload, ensure_ascii=False).encode()

    def _next_id(self) -> str:
        self._n += 1
        return f"synthetic-webhook-{self._n:06d}"

    def admin_event(self, key: str, event: str = "jira:issue_updated") -> RawWebhook:
        """An admin webhook with a secret: HMAC in ``X-Hub-Signature``."""
        body = self._body(event, key, None)
        headers = {
            "Content-Type": "application/json",
            IDENT: self._next_id(),
            SIGNATURE: _sign(self.admin_secret, body),
        }
        return RawWebhook(headers, body)

    def bearer_event(
        self, key: str, event: str = "jira:issue_updated", matched: list[int] | None = None
    ) -> RawWebhook:
        """A webhook of an OAuth 2.0 app: a token in ``Authorization``."""
        body = self._body(event, key, matched)
        token = _jwt(self.client_secret, int(self.jira.now))
        headers = {
            "Content-Type": "application/json",
            IDENT: self._next_id(),
            "Authorization": f"Bearer {token}",
        }
        return RawWebhook(headers, body)

    def registered_events(self, event: str, key: str) -> list[RawWebhook]:
        """What Jira would send for ``event`` on ``key`` to live REST registrations."""
        return [
            self.bearer_event(key, event, sorted(ids))
            for ids in self.jira.live_webhooks(event, key).values()
        ]

    def forged(self, raw: RawWebhook) -> RawWebhook:
        """Every byte and header the same but the signature (or token), made with a wrong secret."""
        headers = dict(raw.headers)
        if SIGNATURE in headers:
            headers[SIGNATURE] = _sign(WRONG_SECRET, raw.body)
        else:
            head, claims, _ = headers["Authorization"].removeprefix("Bearer ").split(".")
            mac = hmac.new(WRONG_SECRET, f"{head}.{claims}".encode(), hashlib.sha256).digest()
            headers["Authorization"] = f"Bearer {head}.{claims}.{_b64(mac)}"
        return RawWebhook(headers, raw.body)

    @staticmethod
    def tampered(raw: RawWebhook) -> RawWebhook:
        """The same signature or token over a body with one byte added."""
        return RawWebhook(raw.headers, raw.body + b" ")

    @staticmethod
    def duplicate(raw: RawWebhook) -> RawWebhook:
        """Delivered twice: the same identifier and bytes, and not a retry."""
        return RawWebhook({k: v for k, v in raw.headers.items() if k != RETRY}, raw.body)

    @staticmethod
    def unordered(items: Sequence[RawWebhook], seed: int) -> list[RawWebhook]:
        """The deliveries in a seeded order other than the one given (two or more)."""
        mixed = list(items)
        random.Random(seed).shuffle(mixed)
        if len(mixed) > 1 and mixed == list(items):
            mixed = mixed[1:] + mixed[:1]
        return mixed

    def deliver(self, post: Callable[[RawWebhook], int], raw: RawWebhook) -> DeliveryReport:
        """Send ``raw`` to ``post`` (which returns the receiver's status, or raises on a timeout
        or dropped connection) and retry as Jira does, advancing the fake clock between attempts."""
        attempts: list[Attempt] = []
        allowed = 1 if self.degraded else MAX_RESENDS + 1
        first = self.jira.now
        while True:
            n = len(attempts)
            sent = raw if n == 0 else RawWebhook({**raw.headers, RETRY: str(n)}, raw.body)
            try:
                status: int | None = post(sent)
            except (TimeoutError, ConnectionError, OSError):
                status = None
            attempts.append(Attempt(self.jira.now, status))
            done = status is not None and status not in RETRYABLE and status < 500
            if done or len(attempts) >= allowed:
                break
            self.jira.now += self._rng.randint(RETRY_MIN, RETRY_MAX)
        report = DeliveryReport(raw.headers[IDENT], tuple(attempts))
        if report.delivered:
            self.degraded = False
        elif self.jira.now - first >= SLOW_AFTER or self.degraded:
            self.degraded = True
        return report
