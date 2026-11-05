"""D7-01: the fake Slack's signing and the trigger_id and response_url rules. Synthetic values."""

from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import parse_qs, urlencode

import pytest

from fakes.slack import (
    BOT_TOKEN,
    RESPONSE_URL_LIMIT,
    RESPONSE_URL_WINDOW,
    SIGNING_SECRET,
    TRIGGER_TTL,
    FakeSlack,
)
from sto.adapters.ports import RawWebhook


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


def verifies(raw: RawWebhook, secret: bytes = SIGNING_SECRET) -> bool:
    """A raw-body verifier written independently of the fake: ``v0:<ts>:<raw body>`` HMAC-SHA256."""
    ts = raw.headers["X-Slack-Request-Timestamp"]
    mac = hmac.new(secret, b"v0:" + ts.encode() + b":" + raw.body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("v0=" + mac, raw.headers["X-Slack-Signature"])


def reencoded(raw: RawWebhook) -> RawWebhook:
    """What a WRONG verifier checks: the body parsed, then written back the usual way."""
    if raw.headers["Content-Type"] == "application/json":
        body = json.dumps(json.loads(raw.body)).encode()
    else:
        payload = json.loads(parse_qs(raw.body.decode())["payload"][0])
        body = urlencode({"payload": json.dumps(payload)}).encode()
    return RawWebhook(raw.headers, body)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def slack(clock: Clock) -> FakeSlack:
    return FakeSlack(clock)


VIEW = {"type": "modal", "title": {"type": "plain_text", "text": "Decide"}, "blocks": []}


def test_signature_is_v0_hmac_over_version_timestamp_raw_body(slack: FakeSlack) -> None:
    raw = slack.block_actions("approve")
    ts = raw.headers["X-Slack-Request-Timestamp"]
    base = b"v0:" + ts.encode() + b":" + raw.body
    expected = "v0=" + hmac.new(SIGNING_SECRET, base, hashlib.sha256).hexdigest()
    assert raw.headers["X-Slack-Signature"] == expected


def test_interactive_body_is_form_encoded_payload_json(slack: FakeSlack) -> None:
    raw = slack.block_actions("approve", value="gate-1")
    assert raw.headers["Content-Type"] == "application/x-www-form-urlencoded"
    payload = json.loads(parse_qs(raw.body.decode())["payload"][0])
    assert payload["type"] == "block_actions"
    assert payload["actions"][0]["action_id"] == "approve"
    assert payload["actions"][0]["value"] == "gate-1"
    assert payload["trigger_id"]
    assert payload["response_url"]
    assert "delivery_id" not in payload  # Slack sends no delivery ID
    assert "X-Slack-Delivery" not in raw.headers


def test_stale_timestamp_is_signed_genuinely(slack: FakeSlack, clock: Clock) -> None:
    raw = slack.block_actions("approve", timestamp_age=301)
    assert int(raw.headers["X-Slack-Request-Timestamp"]) == int(clock.now) - 301
    ts = raw.headers["X-Slack-Request-Timestamp"].encode()
    mac = hmac.new(SIGNING_SECRET, b"v0:" + ts + b":" + raw.body, hashlib.sha256).hexdigest()
    assert raw.headers["X-Slack-Signature"] == "v0=" + mac


def test_forged_signature_differs_only_in_signature(slack: FakeSlack) -> None:
    good = slack.block_actions("approve")
    bad = slack.forge(good)
    assert bad.body == good.body
    assert bad.headers["X-Slack-Signature"] != good.headers["X-Slack-Signature"]


def test_retry_is_same_bytes_with_retry_headers(slack: FakeSlack) -> None:
    ev = slack.event("app_mention")
    again = slack.retry(ev, attempt=1)
    assert again.body == ev.body
    assert again.headers["X-Slack-Retry-Num"] == "1"
    assert again.headers["X-Slack-Retry-Reason"] == "http_timeout"
    assert "X-Slack-Retry-Num" not in ev.headers


def test_retries_are_re_signed_with_fresh_timestamps(slack: FakeSlack, clock: Clock) -> None:
    first = slack.event("app_mention")
    clock.now += 360  # a retry this late would fail Slack's own 5 minute check if not re-signed
    again = slack.retry(first, attempt=3)
    assert int(again.headers["X-Slack-Request-Timestamp"]) == int(clock.now)
    assert again.headers["X-Slack-Request-Timestamp"] != first.headers["X-Slack-Request-Timestamp"]
    assert again.headers["X-Slack-Signature"] != first.headers["X-Slack-Signature"]
    assert verifies(again)  # a raw-body verifier at the current time accepts it
    # event_id is the only stable key across the attempts: an adapter deduping on the signature
    # or the timestamp would treat the retry as a new event.
    assert json.loads(again.body)["event_id"] == json.loads(first.body)["event_id"]


def test_retry_refuses_an_interactive_payload(slack: FakeSlack) -> None:
    with pytest.raises(ValueError, match="Events API"):
        slack.retry(slack.block_actions("approve"), attempt=1)


def test_events_are_signed_json_with_unique_ids_and_inner_ts(slack: FakeSlack) -> None:
    a, b = slack.event("app_mention"), slack.event("app_mention")
    assert a.headers["Content-Type"] == "application/json"
    assert verifies(a)
    assert not verifies(slack.forge(a))
    ea, eb = json.loads(a.body), json.loads(b.body)
    assert ea["event_id"] != eb["event_id"]
    assert ea["event"]["ts"] != eb["event"]["ts"]
    assert ea["event"]["channel"] == "C1"
    assert ea["event"]["text"].startswith("<@")


def test_url_verification_is_a_signed_challenge(slack: FakeSlack) -> None:
    raw = slack.url_verification("abc123")
    body = json.loads(raw.body)
    assert body == {"type": "url_verification", "challenge": "abc123"}
    assert verifies(raw)
    assert raw.headers["Content-Type"] == "application/json"


def test_sent_bytes_are_not_what_a_re_encoding_verifier_writes(slack: FakeSlack) -> None:
    for raw in (slack.block_actions("approve"), slack.event("app_mention")):
        assert verifies(raw)
        assert not verifies(reencoded(raw))  # a verifier that parses then re-encodes fails
        assert not verifies(slack.reserialise(raw))
        assert not verifies(slack.tamper(raw))
        # the re-encoding is the same content, so only the raw bytes tell them apart
        assert slack.reserialise(raw).body != raw.body


def test_reserialise_keeps_the_content(slack: FakeSlack) -> None:
    raw = slack.block_actions("approve", value="g")
    assert slack.payload_of(slack.reserialise(raw)) == slack.payload_of(raw)
    ev = slack.event("app_mention")
    assert json.loads(slack.reserialise(ev).body) == json.loads(ev.body)


def test_views_open_succeeds_within_three_seconds(slack: FakeSlack, clock: Clock) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    clock.now += TRIGGER_TTL
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN) == {
        "ok": True,
        "view": {"id": "V1", **VIEW},
    }


def test_expired_trigger_fails_as_documented(slack: FakeSlack, clock: Clock) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    clock.now += TRIGGER_TTL + 0.001
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN) == {
        "ok": False,
        "error": "expired_trigger_id",
    }
    assert slack.opened_views == []


def test_trigger_is_single_use(slack: FakeSlack) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN)["ok"] is True
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN) == {
        "ok": False,
        "error": "exchanged_trigger_id",
    }
    assert len(slack.opened_views) == 1


def test_unknown_trigger_is_invalid(slack: FakeSlack) -> None:
    assert slack.views_open("nope", VIEW, token=BOT_TOKEN) == {
        "ok": False,
        "error": "invalid_trigger_id",
    }


def test_each_interaction_gets_its_own_trigger(slack: FakeSlack) -> None:
    a = slack.trigger_of(slack.block_actions("approve"))
    b = slack.trigger_of(slack.block_actions("approve"))
    assert a != b


def test_response_url_allows_five_uses(slack: FakeSlack) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    for _ in range(RESPONSE_URL_LIMIT):
        assert slack.post_response_url(url, {"text": "x"}).status == 200
    assert len(slack.responses) == RESPONSE_URL_LIMIT


def test_response_url_sixth_use_is_refused(slack: FakeSlack) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    for _ in range(RESPONSE_URL_LIMIT):
        slack.post_response_url(url, {"text": "x"})
    refused = slack.post_response_url(url, {"text": "sixth"})
    assert (refused.status, refused.body) == (404, "used_url")
    assert len(slack.responses) == RESPONSE_URL_LIMIT


def test_response_url_expires_after_thirty_minutes(slack: FakeSlack, clock: Clock) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    clock.now += RESPONSE_URL_WINDOW
    assert slack.post_response_url(url, {"text": "edge"}).status == 200
    clock.now += 1
    expired = slack.post_response_url(url, {"text": "late"})
    assert (expired.status, expired.body) == (404, "expired_url")


def test_expired_url_does_not_count_a_use(slack: FakeSlack, clock: Clock) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    clock.now += RESPONSE_URL_WINDOW + 1
    slack.post_response_url(url, {"text": "late"})
    assert slack.uses(url) == 0


def test_unknown_response_url_is_404(slack: FakeSlack) -> None:
    missing = slack.post_response_url("https://hooks.slack.test/actions/none", {"text": "x"})
    assert missing.status == 404


def test_post_message_returns_ts_and_update_edits_in_place(slack: FakeSlack) -> None:
    posted = slack.chat_post_message(
        "C1", blocks=[{"type": "divider"}], text="gate", token=BOT_TOKEN
    )
    assert posted["ok"]
    assert posted["channel"] == "C1"
    ts = posted["ts"]
    assert slack.chat_update("C1", ts, text="closed", token=BOT_TOKEN)["ok"] is True
    assert slack.messages[("C1", ts)]["text"] == "closed"
    assert len(slack.messages) == 1


def test_update_unknown_message_fails(slack: FakeSlack) -> None:
    assert slack.chat_update("C1", "1.1", text="x", token=BOT_TOKEN) == {
        "ok": False,
        "error": "message_not_found",
    }


def test_message_ts_is_unique_and_ordered(slack: FakeSlack) -> None:
    a = slack.chat_post_message("C1", text="a", token=BOT_TOKEN)["ts"]
    b = slack.chat_post_message("C1", text="b", token=BOT_TOKEN)["ts"]
    assert float(b) > float(a)


def test_bad_token_is_invalid_auth(slack: FakeSlack) -> None:
    assert slack.chat_post_message("C1", text="x", token="xoxb-wrong") == {
        "ok": False,
        "error": "invalid_auth",
    }
    assert slack.views_open("t", VIEW, token="xoxb-wrong")["error"] == "invalid_auth"
    assert slack.chat_update("C1", "1.1", text="x", token="xoxb-wrong")["error"] == "invalid_auth"


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_is_not_authed(slack: FakeSlack, token: str | None) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    posted = slack.chat_post_message("C1", text="x", token=BOT_TOKEN)
    assert slack.chat_post_message("C1", text="x", token=token) == {
        "ok": False,
        "error": "not_authed",
    }
    assert slack.views_open(trigger, VIEW, token=token)["error"] == "not_authed"
    assert slack.chat_update("C1", posted["ts"], text="y", token=token)["error"] == "not_authed"
    assert (
        slack.views_open(trigger, VIEW, token=BOT_TOKEN)["ok"] is True
    )  # the refused call spent nothing
    assert len(slack.messages) == 1


def test_empty_messages_are_refused_as_no_text(slack: FakeSlack) -> None:
    assert slack.chat_post_message("C1", token=BOT_TOKEN) == {"ok": False, "error": "no_text"}
    assert slack.messages == {}
    ts = slack.chat_post_message("C1", text="a", token=BOT_TOKEN)["ts"]
    assert slack.chat_update("C1", ts, text="", token=BOT_TOKEN)["error"] == "no_text"
    assert slack.messages[("C1", ts)]["text"] == "a"  # not blanked


@pytest.mark.parametrize(
    "view",
    [
        {"nonsense": 1},
        {},
        {"type": "home", "title": {}, "blocks": []},
        {"type": "modal", "blocks": []},
        {"type": "modal", "title": {}},
    ],
)
def test_bad_views_are_invalid_arguments_and_spend_no_trigger(
    slack: FakeSlack, view: dict[str, object]
) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    assert slack.views_open(trigger, view, token=BOT_TOKEN) == {
        "ok": False,
        "error": "invalid_arguments",
    }
    assert slack.opened_views == []
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN)["ok"] is True


def test_empty_response_url_body_is_refused_and_uncounted(slack: FakeSlack) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    empty = slack.post_response_url(url, {})
    assert (empty.status, empty.body) == (400, "no_text")
    assert slack.uses(url) == 0
    assert slack.responses == []
    assert slack.post_response_url(url, {"blocks": [{"type": "divider"}]}).status == 200


def test_expired_trigger_is_not_burned(slack: FakeSlack, clock: Clock) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    clock.now += TRIGGER_TTL + 1
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN)["error"] == "expired_trigger_id"
    assert (
        slack.views_open(trigger, VIEW, token=BOT_TOKEN)["error"] == "expired_trigger_id"
    )  # not exchanged_


def test_bad_token_does_not_burn_a_trigger(slack: FakeSlack) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    assert slack.views_open(trigger, VIEW, token="xoxb-wrong")["ok"] is False
    assert slack.views_open(trigger, VIEW, token=BOT_TOKEN)["ok"] is True


@pytest.mark.parametrize("method", ["views.open", "chat.update", "chat.postMessage"])
def test_any_method_can_be_rate_limited(slack: FakeSlack, method: str) -> None:
    trigger = slack.trigger_of(slack.block_actions("approve"))
    ts = slack.chat_post_message("C1", text="a", token=BOT_TOKEN)["ts"]
    slack.rate_limit_next(retry_after=9, method=method)
    calls = {
        "views.open": lambda: slack.views_open_response(trigger, VIEW, token=BOT_TOKEN),
        "chat.update": lambda: slack.chat_update_response("C1", ts, text="b", token=BOT_TOKEN),
        "chat.postMessage": lambda: slack.chat_post_message_response(
            "C1", text="c", token=BOT_TOKEN
        ),
    }
    limited = calls[method]()
    assert limited.status == 429
    assert limited.headers["Retry-After"] == "9"
    assert calls[method]().status == 200
    others = [m for m in calls if m != method]
    slack.rate_limit_next(method=method)
    assert calls[others[0]]().status == 200  # a limit is per method


def test_ts_is_per_channel_so_channels_can_share_one(slack: FakeSlack) -> None:
    a = slack.chat_post_message("C1", text="a", token=BOT_TOKEN)["ts"]
    b = slack.chat_post_message("C2", text="b", token=BOT_TOKEN)["ts"]
    assert a == b  # same second, same sequence: key a message by (channel, ts)
    assert set(slack.messages) == {("C1", a), ("C2", b)}
    assert slack.chat_update("C2", a, text="b2", token=BOT_TOKEN)["ok"] is True
    assert slack.messages[("C1", a)]["text"] == "a"  # the other channel's message is untouched


def test_ts_ordering_holds_past_999999_in_one_second(slack: FakeSlack) -> None:
    slack._last_micro["C1"] = int(slack.clock()) * 1_000_000 + 999_998
    stamps = [slack.chat_post_message("C1", text="x", token=BOT_TOKEN)["ts"] for _ in range(4)]
    assert [float(t) for t in stamps] == sorted(float(t) for t in stamps)
    assert len(set(stamps)) == 4
    assert all(len(t.split(".")[1]) == 6 for t in stamps)
    assert stamps[-1].startswith(str(int(slack.clock()) + 1) + ".")


def test_rate_limit_is_429_with_retry_after(slack: FakeSlack) -> None:
    slack.rate_limit_next(retry_after=7)
    limited = slack.chat_post_message_response("C1", text="x", token=BOT_TOKEN)
    assert limited.status == 429
    assert limited.headers["Retry-After"] == "7"
    assert limited.json == {"ok": False, "error": "ratelimited"}
    assert slack.chat_post_message_response("C1", text="x", token=BOT_TOKEN).status == 200


def test_posting_to_unknown_channel_fails(slack: FakeSlack) -> None:
    assert (
        slack.chat_post_message("C404", text="x", token=BOT_TOKEN)["error"] == "channel_not_found"
    )


def test_token_is_a_required_keyword_on_every_web_api_method(slack: FakeSlack) -> None:
    with pytest.raises(TypeError):
        slack.chat_post_message("C1", text="x")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        slack.chat_update("C1", "1.1", text="x")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        slack.views_open("t", VIEW)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        slack.chat_post_message_response("C1", text="x")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        slack.chat_update_response("C1", "1.1", text="x")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        slack.views_open_response("t", VIEW)  # type: ignore[call-arg]


@pytest.mark.parametrize("flag", ["true", "True", True])
def test_delete_original_is_accepted_without_text_and_counts_a_use(
    slack: FakeSlack, flag: object
) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    assert slack.post_response_url(url, {"delete_original": flag}).status == 200
    assert slack.deleted_originals == [url]
    assert slack.uses(url) == 1
    assert slack.responses == []


@pytest.mark.parametrize("flag", ["false", "", False, "no"])
def test_delete_original_must_be_truthy(slack: FakeSlack, flag: object) -> None:
    url = slack.response_url_of(slack.block_actions("approve"))
    assert slack.post_response_url(url, {"delete_original": flag}).body == "no_text"
    assert slack.deleted_originals == []
    assert slack.uses(url) == 0


def test_retry_refuses_a_url_verification(slack: FakeSlack) -> None:
    with pytest.raises(ValueError, match="Events API"):
        slack.retry(slack.url_verification(), attempt=1)


def test_url_verification_challenge_with_a_slash_round_trips(slack: FakeSlack) -> None:
    raw = slack.url_verification("a/b/c")
    assert verifies(raw)
    assert json.loads(raw.body)["challenge"] == "a/b/c"
    assert not verifies(reencoded(raw))


def test_docs_and_sources_are_linked() -> None:
    import fakes.slack.server as server

    doc = server.__doc__ or ""
    for url in (
        "https://docs.slack.dev/authentication/verifying-requests-from-slack/",
        "https://docs.slack.dev/interactivity/handling-user-interaction/",
        "https://docs.slack.dev/reference/methods/views.open/",
        "https://docs.slack.dev/apis/events-api/#retries",
        "https://docs.slack.dev/apis/web-api/rate-limits/",
    ):
        assert url in doc
    assert "unsourced" in doc  # departures from the docs are named


def test_sent_bytes_are_non_canonical_in_the_ways_a_re_encoder_misses(slack: FakeSlack) -> None:
    form = slack.block_actions("approve")
    assert b"%20" in form.body  # a space, where urlencode writes "+"
    assert b"+" not in form.body
    assert b"%5C%2F" in form.body  # the JSON escape \/
    event = slack.event("app_mention")
    assert b"\\/" in event.body
    assert b", " not in event.body  # compact separators, where json.dumps writes ", "
