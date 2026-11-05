"""An in-process fake of Slack: signed requests, interactive payloads, the Web API and the timing
rules for ``trigger_id`` and ``response_url`` (D7-01).

It is a SERVER and a SENDER. It signs what it sends and it does not verify: the receiver's verifier
(D7-02) is the one under test. Every ID, secret, token and URL is synthetic. Each behaviour names
the page that documents it, or says "unsourced". The live suite (D12) later proves all of it
against real Slack, and when they disagree the fake is wrong.

Sources:

* [S47] Signing. https://docs.slack.dev/authentication/verifying-requests-from-slack/ says
  ``X-Slack-Signature`` is ``v0=`` plus the hex HMAC-SHA256 of ``v0:<timestamp>:<raw body>`` under
  the signing secret, with the timestamp in ``X-Slack-Request-Timestamp``. The receiver rejects a
  timestamp more than 5 minutes away from its clock, in either direction (an absolute difference,
  so one 5 minutes in the future is refused too). The fake can sign at any age, so a stale request
  is genuinely signed. The raw body is verified before it is deserialised (PLAN T6): the fake sends
  bytes that no parse-and-re-encode reproduces (compact JSON with ``\\/`` escapes), so a verifier
  that re-encodes fails. ``tamper`` and ``reserialise`` make the two
  attacks.
* [S48] Interactivity. https://docs.slack.dev/interactivity/handling-user-interaction/ says an
  interactive request is form-encoded with one ``payload`` field of JSON, needs a 200 within 3
  seconds, and carries a ``trigger_id`` and a ``response_url``. ``trigger_id`` expires in 3 seconds
  and is single use; ``response_url`` allows 5 uses within 30 minutes.
* ``views.open`` errors ``expired_trigger_id``, ``exchanged_trigger_id`` and ``invalid_trigger_id``
  are from https://docs.slack.dev/reference/methods/views.open/ , and so is ``invalid_arguments``
  for a view that is not a modal with a title and blocks.
* Events retries. https://docs.slack.dev/apis/events-api/#retries documents ``X-Slack-Retry-Num``
  and ``X-Slack-Retry-Reason``, and that only Events API deliveries are retried, so ``retry``
  refuses an interactive payload. Slack sends NO delivery ID, so none is sent here: a receiver
  dedupes on ``event_id``. The ``url_verification`` handshake is at
  https://docs.slack.dev/reference/events/url_verification/ .
* Web API. https://docs.slack.dev/apis/web-api/ : an HTTP 200 with ``{"ok": false, "error": ...}``
  for method errors (``not_authed`` for no token, ``invalid_auth`` for a wrong one,
  ``channel_not_found``, ``message_not_found``, ``no_text``), and HTTP 429 with a ``Retry-After``
  header for rate limits (https://docs.slack.dev/apis/web-api/rate-limits/). ``chat.postMessage``
  returns ``channel`` and ``ts``; ``chat.update`` edits by ``channel`` and ``ts``
  (https://docs.slack.dev/reference/methods/chat.postMessage/).

Known departures, each deliberate:

* A ``response_url`` past its 30 minutes answers 404 ``expired_url`` and one past its 5 uses 404
  ``used_url``. Slack's page gives the limits but not the response; the statuses and bodies are
  unsourced, observed behaviour to prove live. The bodies differ so a test can tell the cases
  apart, but an adapter must not branch on either. An empty body (no ``text`` and no ``blocks``) is
  400 ``no_text``, also unsourced. The 30 minutes run from issue, and the edge (exactly 30 minutes)
  is allowed: unsourced.
* ``trigger_id`` is valid for exactly 3 seconds, inclusive. The edge is unsourced.
* A trigger is never marked used when ``views.open`` fails on a bad token, a bad view or an expiry.
* ``ts`` is ``<seconds>.<6-digit microseconds>``, unique and ordered PER CHANNEL, as Slack's is, so
  two channels can share one ``ts`` and an adapter must key a message by channel and ``ts``.
* On a retry Slack re-signs with a fresh timestamp. This is reasoned (a retry after 5 minutes
  could never pass Slack's own check otherwise), not sourced. So a retry's timestamp and
  signature differ from the original's while ``event_id`` does not.
* Rate limiting is injected by ``rate_limit_next`` for one method at a time, not modelled by tier.
* The order in which errors are checked (auth, then arguments, then channel or trigger) is
  unsourced.
* Not modelled until D7-04 needs them: the interactive payload's ``api_app_id``, ``container``,
  ``message``, ``token`` and ``action_ts``, and the real format of a ``trigger_id``. The
  ``url_verification`` body omits the deprecated ``token``.
* A form body writes a space as ``%20``. That is a deliberate, unsourced choice (Slack's form
  bodies likely use ``+``), made so that a re-encoder that writes ``+`` differs; a receiver must
  decode both.
* A ``response_url`` body of ``{"delete_original": "true"}`` (or ``true``) with no ``text`` or
  ``blocks`` deletes the original message and counts as a use, as Slack documents
  (https://docs.slack.dev/interactivity/handling-user-interaction/#message_responses). The fake
  records the URL in ``deleted_originals`` and tracks no message to remove.
* Token revocation (``token_revoked``) is not modelled until D7-07.
* Every Web API method takes ``token`` as a required keyword, so an adapter that never forwards the
  bot token fails with a ``TypeError`` rather than passing. Pass ``None`` for no token
  (``not_authed``).
* Transport details are not modelled here. Content-Type and charset, the ``Bearer`` Authorization
  header, and a view sent as a JSON string in a form post are checked by the D7-08 transport shim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlencode

from sto.adapters.ports import RawWebhook

SIGNING_SECRET = b"synthetic-slack-signing-secret"
WRONG_SECRET = b"synthetic-not-the-secret"
BOT_TOKEN = "xoxb-synthetic-token"  # synthetic
TEAM_ID = "T0SYNTH01"  # synthetic
USER_ID = "U0SYNTH01"  # synthetic
BOT_USER_ID = "U0SYNTHBOT"  # synthetic
CHANNELS = ("C1", "C2")

TRIGGER_TTL = 3.0  # seconds [S48]
RESPONSE_URL_LIMIT = 5  # uses [S48]
RESPONSE_URL_WINDOW = 30 * 60.0  # seconds [S48]
RESPONSE_URL_BASE = "https://hooks.slack.test/actions/"

POST_MESSAGE = "chat.postMessage"
UPDATE_MESSAGE = "chat.update"
VIEWS_OPEN = "views.open"


@dataclass(frozen=True)
class WebResponse:
    """An HTTP answer from the fake Web API."""

    status: int
    json: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class UrlResponse:
    """An HTTP answer from a ``response_url``."""

    status: int
    body: str


def _sign(secret: bytes, timestamp: str, body: bytes) -> str:
    base = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret, base, hashlib.sha256).hexdigest()


def _compact(obj: Any) -> str:
    """Valid JSON that ``json.dumps`` would not write: no spaces, and ``/`` escaped as ``\\/``."""
    return json.dumps(obj, separators=(",", ":")).replace("/", "\\/")


def _ok(**fields: Any) -> WebResponse:
    return WebResponse(200, {"ok": True, **fields})


def _err(error: str) -> WebResponse:
    return WebResponse(200, {"ok": False, "error": error})


class FakeSlack:
    """Slack as a sender of signed requests and a Web API server, on the shared fake ``clock``."""

    def __init__(self, clock: Callable[[], float], secret: bytes = SIGNING_SECRET) -> None:
        self.clock, self.secret = clock, secret
        self.opened_views: list[Mapping[str, Any]] = []
        self.responses: list[Mapping[str, Any]] = []
        self.deleted_originals: list[str] = []  # response_urls used with delete_original
        self.messages: dict[tuple[str, str], dict[str, Any]] = {}
        self._triggers: dict[str, float] = {}  # trigger_id -> issued at
        self._used_triggers: set[str] = set()
        self._urls: dict[str, float] = {}  # response_url -> issued at
        self._uses: Counter[str] = Counter()
        self._seq = 0
        self._last_micro: dict[str, int] = {}  # channel -> last ts, in microseconds
        self._limits: dict[str, list[int]] = {}  # method -> Retry-After values to serve

    # --- sending signed requests -------------------------------------------------------------

    def _headers(self, body: bytes, content_type: str, age: int = 0) -> dict[str, str]:
        timestamp = str(int(self.clock()) - age)
        return {
            "Content-Type": content_type,
            "User-Agent": "Slackbot 1.0 (+https://api.slack.com/robots)",
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": _sign(self.secret, timestamp, body),
        }

    @staticmethod
    def _form(payload: Mapping[str, Any]) -> bytes:
        return ("payload=" + quote(_compact(payload), safe="")).encode()

    def block_actions(
        self, action_id: str, *, value: str = "", timestamp_age: int = 0, user: str = USER_ID
    ) -> RawWebhook:
        """A ``block_actions`` interaction. Each one gets a fresh ``trigger_id`` (live for 3
        seconds, once) and a fresh ``response_url`` (5 uses, 30 minutes)."""
        self._seq += 1
        trigger = f"{self._seq}.{TEAM_ID}.synthtrigger{self._seq:04d}"
        url = f"{RESPONSE_URL_BASE}{TEAM_ID}/{self._seq}/synthurl{self._seq:04d}"
        now = self.clock()
        self._triggers[trigger] = now
        self._urls[url] = now
        payload = {
            "type": "block_actions",
            "user": {"id": user, "username": "synthetic user", "team_id": TEAM_ID},
            "team": {"id": TEAM_ID},
            "channel": {"id": CHANNELS[0]},
            "trigger_id": trigger,
            "response_url": url,
            "actions": [
                {"type": "button", "action_id": action_id, "value": value, "block_id": "b1"}
            ],
        }
        body = self._form(payload)
        return RawWebhook(
            self._headers(body, "application/x-www-form-urlencoded", timestamp_age), body
        )

    def event(self, kind: str, *, timestamp_age: int = 0, channel: str = CHANNELS[0]) -> RawWebhook:
        """An Events API callback (JSON). No delivery ID: Slack sends none, so a receiver dedupes
        on ``event_id``. Each event has its own ``event_id`` and inner ``ts``."""
        self._seq += 1
        body = _compact(
            {
                "type": "event_callback",
                "team_id": TEAM_ID,
                "event": {
                    "type": kind,
                    "user": USER_ID,
                    "channel": channel,
                    "text": f"<@{BOT_USER_ID}> status of https://tickets.test/T-{self._seq}",
                    "ts": f"{int(self.clock())}.{self._seq:06d}",
                },
                "event_time": int(self.clock()),
                "event_id": f"Ev{self._seq:08d}",
            }
        ).encode()
        return RawWebhook(self._headers(body, "application/json", timestamp_age), body)

    def url_verification(self, challenge: str = "synthetic-challenge") -> RawWebhook:
        """The handshake Slack sends when a request URL is set. The receiver answers with the
        ``challenge`` value. It has no ``event_id``."""
        body = _compact({"type": "url_verification", "challenge": challenge}).encode()
        return RawWebhook(self._headers(body, "application/json"), body)

    def retry(self, raw: RawWebhook, attempt: int, reason: str = "http_timeout") -> RawWebhook:
        """The same bytes again, re-signed at the clock's time (reasoned, not sourced), with
        Slack's retry headers. Only Events API deliveries are retried."""
        if (
            raw.headers["Content-Type"] != "application/json"
            or json.loads(raw.body).get("type") != "event_callback"
        ):
            raise ValueError("Slack retries Events API deliveries only")
        headers = self._headers(raw.body, "application/json")
        headers["X-Slack-Retry-Num"] = str(attempt)
        headers["X-Slack-Retry-Reason"] = reason
        return RawWebhook(headers, raw.body)

    def forge(self, raw: RawWebhook) -> RawWebhook:
        """The same bytes and timestamp, signed under the wrong secret."""
        timestamp = raw.headers["X-Slack-Request-Timestamp"]
        return RawWebhook(
            {**raw.headers, "X-Slack-Signature": _sign(WRONG_SECRET, timestamp, raw.body)},
            raw.body,
        )

    @staticmethod
    def tamper(raw: RawWebhook) -> RawWebhook:
        """The same signature over a body with one byte added."""
        return RawWebhook(raw.headers, raw.body + b" ")

    @staticmethod
    def reserialise(raw: RawWebhook) -> RawWebhook:
        """The same content in the bytes a parse-and-re-encode writes, under the old signature."""
        if raw.headers["Content-Type"] == "application/json":
            body = json.dumps(json.loads(raw.body)).encode()
        else:
            payload = json.loads(parse_qs(raw.body.decode())["payload"][0])
            body = urlencode({"payload": json.dumps(payload)}).encode()
        return RawWebhook(raw.headers, body)

    @staticmethod
    def payload_of(raw: RawWebhook) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(parse_qs(raw.body.decode())["payload"][0])
        return loaded

    def trigger_of(self, raw: RawWebhook) -> str:
        return str(self.payload_of(raw)["trigger_id"])

    def response_url_of(self, raw: RawWebhook) -> str:
        return str(self.payload_of(raw)["response_url"])

    # --- the Web API -------------------------------------------------------------------------

    def rate_limit_next(self, retry_after: int = 1, method: str = POST_MESSAGE) -> None:
        """The next call to ``method`` is a 429 with ``Retry-After``."""
        self._limits.setdefault(method, []).append(retry_after)

    def _limited(self, method: str) -> WebResponse | None:
        if not self._limits.get(method):
            return None
        wait = self._limits[method].pop(0)
        return WebResponse(429, {"ok": False, "error": "ratelimited"}, {"Retry-After": str(wait)})

    @staticmethod
    def _auth(token: str | None) -> WebResponse | None:
        if not token:
            return _err("not_authed")
        if token != BOT_TOKEN:
            return _err("invalid_auth")
        return None

    def views_open_response(
        self, trigger_id: str, view: Mapping[str, Any], *, token: str | None
    ) -> WebResponse:
        """``views.open``. A trigger works once, within 3 seconds of the interaction."""
        if (limited := self._limited(VIEWS_OPEN)) is not None:
            return limited
        if (bad := self._auth(token)) is not None:
            return bad
        if (
            view.get("type") != "modal"
            or "title" not in view
            or not isinstance(view.get("blocks"), list)
        ):
            return _err("invalid_arguments")
        issued = self._triggers.get(trigger_id)
        if issued is None:
            return _err("invalid_trigger_id")
        if trigger_id in self._used_triggers:
            return _err("exchanged_trigger_id")
        if self.clock() - issued > TRIGGER_TTL:
            return _err("expired_trigger_id")
        self._used_triggers.add(trigger_id)
        self.opened_views.append(view)
        return _ok(view={"id": f"V{len(self.opened_views)}", **view})

    def views_open(
        self, trigger_id: str, view: Mapping[str, Any], *, token: str | None
    ) -> dict[str, Any]:
        return dict(self.views_open_response(trigger_id, view, token=token).json)

    def chat_post_message_response(
        self,
        channel: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None,
    ) -> WebResponse:
        if (limited := self._limited(POST_MESSAGE)) is not None:
            return limited
        if (bad := self._auth(token)) is not None:
            return bad
        if channel not in CHANNELS:
            return _err("channel_not_found")
        if not text and not blocks:
            return _err("no_text")
        ts = self._next_ts(channel)
        self.messages[(channel, ts)] = {"text": text, "blocks": list(blocks)}
        return _ok(channel=channel, ts=ts)

    def _next_ts(self, channel: str) -> str:
        micro = max(self._last_micro.get(channel, 0) + 1, int(self.clock() * 1_000_000))
        self._last_micro[channel] = micro
        return f"{micro // 1_000_000}.{micro % 1_000_000:06d}"

    def chat_post_message(
        self,
        channel: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None,
    ) -> dict[str, Any]:
        response = self.chat_post_message_response(channel, text=text, blocks=blocks, token=token)
        return dict(response.json)

    def chat_update_response(
        self,
        channel: str,
        ts: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None,
    ) -> WebResponse:
        if (limited := self._limited(UPDATE_MESSAGE)) is not None:
            return limited
        if (bad := self._auth(token)) is not None:
            return bad
        if (channel, ts) not in self.messages:
            return _err("message_not_found")
        if not text and not blocks:
            return _err("no_text")
        self.messages[(channel, ts)] = {"text": text, "blocks": list(blocks)}
        return _ok(channel=channel, ts=ts)

    def chat_update(
        self,
        channel: str,
        ts: str,
        *,
        text: str = "",
        blocks: Sequence[Mapping[str, Any]] = (),
        token: str | None,
    ) -> dict[str, Any]:
        response = self.chat_update_response(channel, ts, text=text, blocks=blocks, token=token)
        return dict(response.json)

    # --- response_url ------------------------------------------------------------------------

    def uses(self, url: str) -> int:
        return self._uses[url]

    def post_response_url(self, url: str, body: Mapping[str, Any]) -> UrlResponse:
        """POST to a ``response_url``: 5 uses within 30 minutes of the interaction."""
        issued = self._urls.get(url)
        if issued is None:
            return UrlResponse(404, "no_such_url")
        if self.clock() - issued > RESPONSE_URL_WINDOW:
            return UrlResponse(404, "expired_url")
        if self._uses[url] >= RESPONSE_URL_LIMIT:
            return UrlResponse(404, "used_url")
        deleting = str(body.get("delete_original", "")).lower() == "true"
        if not deleting and not body.get("text") and not body.get("blocks"):
            return UrlResponse(400, "no_text")
        self._uses[url] += 1
        if deleting and not body.get("text") and not body.get("blocks"):
            self.deleted_originals.append(url)
        else:
            self.responses.append(body)
        return UrlResponse(200, "ok")
