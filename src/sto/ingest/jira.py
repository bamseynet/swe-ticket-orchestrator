"""Jira webhooks (D6-05, ADR-0009): the vendor half of the generic ingest in ``core``.

Sourced to https://developer.atlassian.com/cloud/jira/platform/webhooks/ :

* **Two forms.** An admin webhook with a secret carries ``X-Hub-Signature: method=signature``, the
  HMAC of the RAW body; only ``sha256`` is accepted. A webhook of an OAuth 2.0 app carries a token
  in ``Authorization`` "signed with the app's client secret" (read here as an HS256 JWT).
* **Does the token cover the body? Unconfirmed.** The page says nothing either way, and the fake
  sender's token does not. So the bearer form is read as proof of WHO sent a delivery and never of
  WHAT it says: the receiver counts it (``webhook.body_unauthenticated``), takes only the issue key
  from the body, and every consumer re-reads the issue. The suite's tamper test is run on the admin
  form only. When D12 shows what Jira signs, a covering token can move up to the admin form's rule.
* **No replay window.** Neither form signs a time, and Jira retries up to five times, 5 to 15
  minutes apart (75 minutes in all, and a recipient that has been failing for 30 minutes gets one
  attempt per webhook until it answers). Any window shorter than that would drop a genuine retry,
  so there is none (``signed_timestamp`` False, ``replay_window`` None, as the suite's capability
  table says for Jira) and the dedupe record on ``X-Atlassian-Webhook-Identifier`` never expires.
* **The identifier** is "unique within a tenant" and unchanged across retries. It is not covered by
  either credential, so it is a dedupe key only. The receiver is built per Jira site and its
  surface is ``jira.<site>``, so one tenant's identifiers never meet another's. A delivery without
  a usable identifier is refused; no key is ever made from the body.
* **Order.** Verify, then parse, then claim, then enqueue. A genuine body that cannot be read is
  ``MalformedWebhookError`` before it claims its ID. Jira documents no order and some deliveries
  repeat, so the nudge carries only the issue key and the consumer re-reads: an old event has no
  state to put back.
* **Filtering** happens after the re-read (webhook JQL supports few clauses): the body's project is
  never used to route.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Any

from sto.adapters.ports import (
    ChangeKind,
    ExternalChange,
    MalformedWebhookError,
    RawWebhook,
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

SURFACE_PREFIX = "jira"
IDENT_HEADER = "x-atlassian-webhook-identifier"
HUB_HEADER = "x-hub-signature"
AUTH_HEADER = "authorization"
HUB_PREFIX = "sha256="

# Events the registration asks for (and so the ones read). Anything else is ignored, uncounted
# as a delivery, and never queued.
SUBSCRIBED_EVENTS = (
    "jira:issue_created",
    "jira:issue_updated",
    "jira:issue_deleted",
    "comment_created",
    "comment_updated",
    "comment_deleted",
)

_SAFE_ID = re.compile(r"[A-Za-z0-9_.\-]{1,128}", re.ASCII)
_SAFE_SITE = re.compile(r"[A-Za-z0-9_\-]{1,64}", re.ASCII)
_ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,9}", re.ASCII)
_SEGMENT = re.compile(r"[A-Za-z0-9_\-]+", re.ASCII)


class WebhookForm(StrEnum):
    ADMIN = "admin"
    BEARER = "bearer"

    @property
    def covers_body(self) -> bool:
        """Only the admin HMAC is known to cover the body (see the module docstring)."""
        return self is WebhookForm.ADMIN


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _header_is_hs256(segment: str) -> bool:
    """Run only AFTER the MAC matched: a token that names another algorithm is refused anyway."""
    try:
        padded = segment + "=" * (-len(segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, binascii.Error, RecursionError):
        return False
    return isinstance(header, dict) and header.get("alg") == "HS256"


class JiraWebhookVerifier:
    """``WebhookVerifier`` for Jira (ADR-0009), both forms. Never parses the body."""

    signed_timestamp = False
    replay_window: float | None = None
    secret_headers: frozenset[str] = frozenset({HUB_HEADER})  # authorization: core's own list

    def __init__(self, admin_secret: bytes | None, client_secret: bytes | None) -> None:
        for secret in (admin_secret, client_secret):
            if secret is not None and (not isinstance(secret, bytes) or not secret):
                raise ValueError("a webhook secret must be non-empty bytes")
        if admin_secret is None and client_secret is None:
            raise ValueError("at least one of the admin secret and the client secret is required")
        self._admin = admin_secret
        self._client = client_secret

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        self.form(headers, raw_body)
        return self._identifier(normalise_headers(headers))

    def form(self, headers: Mapping[str, str], raw_body: bytes) -> WebhookForm:
        """Authenticate on the RAW bytes and say which credential did it."""
        try:  # idempotent: ingest already lower-cases, but a caller may hand over raw names
            headers = normalise_headers(headers)
        except PermanentError as exc:
            raise InvalidSignatureError("webhook headers conflict") from exc
        hub, auth = headers.get(HUB_HEADER), headers.get(AUTH_HEADER)
        if (hub is None) == (auth is None):  # neither, or both: never pick one
            raise InvalidSignatureError("webhook must carry exactly one credential")
        try:
            if hub is not None:
                return self._check_admin(hub, raw_body)
            assert auth is not None
            return self._check_bearer(auth)
        except UnicodeError as exc:  # a lone surrogate cannot be encoded: not a credential
            raise InvalidSignatureError("webhook credential is not text") from exc

    def _check_admin(self, received: str, raw_body: bytes) -> WebhookForm:
        if self._admin is None:
            raise InvalidSignatureError("admin webhooks are not accepted here")
        expected = HUB_PREFIX + hmac.new(self._admin, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(received.encode("utf-8"), expected.encode("ascii")):
            raise InvalidSignatureError("webhook signature mismatch")
        return WebhookForm.ADMIN

    def _check_bearer(self, authorization: str) -> WebhookForm:
        if self._client is None:
            raise InvalidSignatureError("OAuth webhooks are not accepted here")
        scheme, _, token = authorization.partition(" ")
        parts = token.strip().split(".")
        if scheme.lower() != "bearer" or len(parts) != 3 or not all(map(_SEGMENT.fullmatch, parts)):
            raise InvalidSignatureError("webhook token is malformed")
        mac = hmac.new(self._client, f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256)
        expected = _b64(mac.digest())
        if not hmac.compare_digest(parts[2].encode("ascii"), expected.encode("ascii")):
            raise InvalidSignatureError("webhook token mismatch")
        if not _header_is_hs256(parts[0]):
            raise InvalidSignatureError("webhook token is not HS256")
        return WebhookForm.BEARER

    @staticmethod
    def _identifier(headers: Mapping[str, str]) -> str:
        ident = headers.get(IDENT_HEADER, "")
        if not _SAFE_ID.fullmatch(ident):
            raise InvalidSignatureError("webhook has no usable identifier")
        return ident


# --- reading a body ---------------------------------------------------------------------------


def parse_event(body: bytes) -> list[ExternalChange]:
    """The ticket a delivery nudges about, and nothing else from it. An event we did not subscribe
    to gives none. A body that is not what Jira documents raises ``MalformedWebhookError``."""
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError) as exc:  # not JSON, or nested past the parser's depth
        raise MalformedWebhookError("webhook body is not JSON") from exc
    if not isinstance(payload, dict):
        raise MalformedWebhookError("webhook body is not an object")
    event = payload.get("webhookEvent")
    if not isinstance(event, str) or not event:
        raise MalformedWebhookError("webhook has no webhookEvent")
    if event not in SUBSCRIBED_EVENTS:
        return []
    issue = payload.get("issue")
    key = issue.get("key") if isinstance(issue, dict) else None
    if not isinstance(key, str) or not _ISSUE_KEY.fullmatch(key):
        raise MalformedWebhookError("webhook issue has no valid key")
    return [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("jira", key))]


# --- the receiver -----------------------------------------------------------------------------


class _Verified:
    """The verdict of the one check ``receive`` made, handed to ingest so the MAC is not computed
    twice. It checks nothing itself."""

    signed_timestamp = False
    replay_window: float | None = None

    def __init__(self, delivery_id: str, secret_headers: frozenset[str]) -> None:
        self._delivery_id = delivery_id
        self.secret_headers = secret_headers

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return self._delivery_id


class JiraWebhooks:
    """Verify, parse, dedupe and enqueue one Jira delivery for one site. Implements no port: it
    only receives, so it exposes no write method."""

    def __init__(
        self,
        site: str,
        store: Store,
        queue: NudgeQueue,
        metrics: Metrics,
        *,
        admin_secret: bytes | None = None,
        client_secret: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(site, str) or not _SAFE_SITE.fullmatch(site):
            raise ValueError("site must be 1 to 64 letters, digits, '_' or '-' (a cloud ID)")
        self.verifier = JiraWebhookVerifier(admin_secret, client_secret)
        self._surface = f"{SURFACE_PREFIX}.{site}"
        self._store, self._queue, self._metrics, self._clock = store, queue, metrics, clock

    def receive(self, raw: RawWebhook) -> list[ExternalChange] | None:
        """The changes a new delivery nudges about, or None for a duplicate.

        Raises ``InvalidSignatureError`` (forged, unsigned, no or odd identifier),
        ``MalformedWebhookError`` (a genuine body we cannot read; its ID stays unclaimed) or
        ``TransientError`` (store or queue down: Jira retries, and the ID is not left claimed)."""
        surface = self._surface
        try:
            headers = normalise_headers(raw.headers)
            form = self.verifier.form(headers, raw.body)  # the only credential check
            delivery_id = self.verifier._identifier(headers)  # noqa: SLF001
        except PermanentError as exc:
            self._metrics.incr("webhook.rejected", surface=surface, reason="signature")
            raise InvalidSignatureError("webhook rejected") from exc
        try:
            changes = parse_event(raw.body)
        except MalformedWebhookError:
            self._metrics.incr("webhook.malformed", surface=surface)
            raise
        if not changes:
            self._metrics.incr("webhook.ignored", surface=surface, reason="event")
            return []
        if not form.covers_body:
            self._metrics.incr("webhook.body_unauthenticated", surface=surface)
        ingest = WebhookIngest(
            surface,
            _Verified(delivery_id, self.verifier.secret_headers),
            self._store,
            self._queue,
            self._metrics,
            clock=self._clock,
        )
        response = ingest.handle(raw.headers, raw.body)
        if response.status == DUPLICATE:
            return None
        if response.status == UNAVAILABLE:
            raise TransientError("webhook could not be queued")
        if response.status != ACCEPTED:
            raise InvalidSignatureError(response.body)
        return changes


__all__: list[Any] = [
    "JiraWebhookVerifier",
    "JiraWebhooks",
    "WebhookForm",
    "parse_event",
]
