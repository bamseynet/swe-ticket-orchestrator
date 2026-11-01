"""An in-process fake of GitHub sending webhook deliveries (D4-16).

It SENDS and signs. It does not verify, dedupe or enqueue: those are the receiver's, and the
conformance suite drives the real verifier. Every ID, secret and payload is synthetic.

What it models, and where GitHub documents it:

* ``X-Hub-Signature-256`` is ``sha256=`` plus the hex HMAC-SHA256 of the raw body under the
  webhook secret. https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
* ``X-GitHub-Delivery`` (a GUID), ``X-GitHub-Event``, ``X-GitHub-Hook-ID``, the installation target
  headers and a ``GitHub-Hookshot/`` user agent.
  https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
* No timestamp is signed or sent, so no time header may be trusted for replay (the suite's
  ``signed_timestamp=False`` for GitHub).
* A redelivery carries the same GUID, headers and bytes as the original.
  https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries
  Real GitHub only redelivers for three days. This fake never expires a delivery: the receiver's
  seen-ID table must not lean on a lapse (D4-03, dedupe does not expire for GitHub).
* GitHub also sends the SHA-1 ``X-Hub-Signature``. The fake omits it: it is legacy, and a
  receiver must use the SHA-256 one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable

from contract.suite import ForgeKind
from sto.adapters.ports import RawWebhook

SECRET = b"synthetic-webhook-secret"
WRONG_SECRET = b"synthetic-not-the-secret"
HOOK_ID = "300003"  # synthetic
APP_ID = "100001"  # synthetic, as in fakes.github.auth

BodyFactory = Callable[[int, str], bytes]


def _default_body(revision: int, delivery_id: str) -> bytes:
    """A synthetic ``issues`` event. ``revision`` stands in for the state a receiver re-reads."""
    return json.dumps(
        {
            "action": "edited",
            "issue": {"number": 1, "title": "synthetic", "revision": revision},
            "repository": {"full_name": "acme/app"},
            "sender": {"login": "alice"},
            "installation": {"id": 200002},
        }
    ).encode()


def _sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


class FakeWebhooks:
    """GitHub as a sender of webhooks. ``clock`` is the shared fake clock (used for nothing GitHub
    signs; kept so a later fake can stamp its ledger)."""

    def __init__(
        self,
        clock: Callable[[], float],
        secret: bytes = SECRET,
        body: BodyFactory = _default_body,
    ) -> None:
        self.clock, self.secret, self.make_body = clock, secret, body
        self.deliveries: dict[str, RawWebhook] = {}

    def _headers(self, delivery_id: str | None, event: str, signature: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "GitHub-Hookshot/synthetic",
            "X-GitHub-Event": event,
            "X-GitHub-Hook-ID": HOOK_ID,
            "X-GitHub-Hook-Installation-Target-Type": "integration",
            "X-GitHub-Hook-Installation-Target-ID": APP_ID,
            "X-Hub-Signature-256": signature,
        }
        if delivery_id is not None:
            headers["X-GitHub-Delivery"] = delivery_id
        return headers

    def delivery(
        self,
        revision: int,
        delivery_id: str,
        *,
        event: str = "issues",
        body: bytes | None = None,
    ) -> RawWebhook:
        """A genuine delivery. It goes in the ledger, for ``redeliver``."""
        raw = self.make_body(revision, delivery_id) if body is None else body
        sent = RawWebhook(self._headers(delivery_id, event, _sign(self.secret, raw)), raw)
        self.deliveries[delivery_id] = sent
        return sent

    def without_id(self, revision: int, *, event: str = "issues") -> RawWebhook:
        """A genuinely signed delivery that carries no delivery ID."""
        raw = self.make_body(revision, "")
        return RawWebhook(self._headers(None, event, _sign(self.secret, raw)), raw)

    def malformed(self, delivery_id: str, *, event: str = "issues") -> RawWebhook:
        """A genuinely signed delivery whose body is not JSON."""
        return self.delivery(1, delivery_id, event=event, body=b"{not json")

    def forge(
        self,
        revision: int,
        delivery_id: str,
        how: ForgeKind = ForgeKind.WRONG_SECRET,
        *,
        event: str = "issues",
    ) -> RawWebhook:
        """The same delivery in every byte and header but the signature, which is wrong in the way
        ``how`` says. It is not a delivery GitHub made, so it is not in the ledger."""
        raw = self.make_body(revision, delivery_id)
        genuine = _sign(self.secret, raw)
        signature = {
            ForgeKind.WRONG_SECRET: _sign(WRONG_SECRET, raw),
            ForgeKind.TRUNCATED_MAC: genuine[: len("sha256=") + 8],
            ForgeKind.EMPTY_MAC: "sha256=",
            ForgeKind.EMPTY_KEY: _sign(b"", raw),
            ForgeKind.BLANK_HEADER: "",
        }[how]
        return RawWebhook(self._headers(delivery_id, event, signature), raw)

    def redeliver(self, delivery_id: str) -> RawWebhook:
        """``POST .../deliveries/{id}/attempts``: the same delivery again. It never expires."""
        return self.deliveries[delivery_id]

    @staticmethod
    def tamper(raw: RawWebhook) -> RawWebhook:
        """The same signature over a body with one byte changed."""
        return RawWebhook(raw.headers, raw.body + b" ")

    @staticmethod
    def reserialise(raw: RawWebhook) -> RawWebhook:
        """The same content in different bytes."""
        return RawWebhook(raw.headers, json.dumps(json.loads(raw.body), indent=2).encode())
