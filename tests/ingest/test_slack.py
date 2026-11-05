"""D7-02: Slack verification and the ack path. Synthetic secrets, the D7-01 fake as the sender.

The signature is checked on the raw bytes (the fake's bytes are deliberately non-canonical), a
request more than 5 minutes from the clock is refused, a retry is deduped on ``event_id``, and an
interaction on its ``trigger_id`` (which the suite only READS, as a key: its 3 second expiry is the
fake's and D7-04's business). Slack has no delivery ID, so the key is what these tests pin.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import inspect
import json
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from typing import ClassVar
from urllib.parse import parse_qs, quote, urlencode

import pytest

from contract.suite import (
    CAPABILITIES,
    MAX_REPLAY_WINDOW,
    AdapterConformance,
    Control,
    ForgeKind,
    Outcome,
    Port,
    Target,
    Vendor,
    run_suite,
)
from fakes.slack import CHANNELS, SIGNING_SECRET, WRONG_SECRET, FakeSlack
from sto.adapters.ports import MalformedWebhookError, RawWebhook
from sto.domain.errors import TransientError
from sto.ingest import slack as slack_module
from sto.ingest.core import IngestResponse, InvalidSignatureError, Nudge
from sto.ingest.slack import SlackIngest, SlackVerifier
from sto.store.memory import MemoryStore
from sto.store.ports import PLATFORM, Key

NOW = 1_700_000_000.0


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


class Queue:
    def __init__(self) -> None:
        self.items: list[Nudge] = []

    def enqueue(self, nudge: Nudge) -> None:
        self.items.append(nudge)


class Metrics:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.reasons: list[tuple[str, str]] = []

    def incr(self, name: str, **tags: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
        if "reason" in tags:
            self.reasons.append((name, tags["reason"]))


class Rig:
    def __init__(self) -> None:
        self.clock = Clock()
        self.store = MemoryStore()
        self.queue = Queue()
        self.metrics = Metrics()
        self.slack = FakeSlack(self.clock)
        self.ingest = SlackIngest(
            SIGNING_SECRET, self.store, self.queue, self.metrics, clock=self.clock
        )

    def events(self, raw: RawWebhook) -> tuple[int, str]:
        r = self.ingest.events(raw.headers, raw.body)
        return r.status, r.body

    def interact(self, raw: RawWebhook) -> tuple[int, str]:
        r = self.ingest.interactivity(raw.headers, raw.body)
        return r.status, r.body


@pytest.fixture
def rig() -> Rig:
    return Rig()


def signed(body: bytes, ts: float = NOW, secret: bytes = SIGNING_SECRET) -> RawWebhook:
    stamp = str(int(ts))
    mac = hmac.new(secret, b"v0:" + stamp.encode() + b":" + body, hashlib.sha256).hexdigest()
    return RawWebhook({"X-Slack-Request-Timestamp": stamp, "X-Slack-Signature": "v0=" + mac}, body)


# --- acknowledgement ----------------------------------------------------------------------------


def test_genuine_event_is_acked_200_and_queued_with_its_raw_bytes(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    assert rig.events(raw) == (200, "")
    (nudge,) = rig.queue.items
    assert nudge.body == raw.body
    assert nudge.reread is True
    assert nudge.surface == "slack"


def test_genuine_interaction_is_acked_200_and_queued(rig: Rig) -> None:
    raw = rig.slack.block_actions("approve", value="g1")
    assert rig.interact(raw) == (200, "")
    (nudge,) = rig.queue.items
    assert nudge.body == raw.body
    assert nudge.surface == "slack.interactive"


def test_credential_header_is_not_queued(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    rig.events(raw)
    assert "x-slack-signature" not in rig.queue.items[0].headers


def test_form_body_with_plus_or_percent20_spaces_is_decoded(rig: Rig) -> None:
    payload = (
        '{"type":"block_actions","trigger_id":"1.2.abc","user":{"id":"U1"},'
        '"actions":[{"action_id":"a b"}]}'
    )
    body = urlencode({"payload": payload}).encode()  # '+' for spaces
    assert b"+" in body
    assert rig.interact(signed(body))[0] == 200
    assert rig.queue.items[0].delivery_id == "1.2.abc"


# --- verification -------------------------------------------------------------------------------


@pytest.mark.parametrize("age", [301, 3600])
def test_old_timestamps_are_refused(rig: Rig, age: int) -> None:
    raw = rig.slack.event("app_mention", timestamp_age=age)
    assert rig.events(raw)[0] == 401
    assert rig.queue.items == []
    assert rig.metrics.counts["webhook.rejected"] == 1


def test_timestamps_exactly_five_minutes_off_are_accepted_either_way(rig: Rig) -> None:
    assert rig.events(rig.slack.event("app_mention", timestamp_age=300))[0] == 200
    assert rig.events(rig.slack.event("app_mention", timestamp_age=-300))[0] == 200


def test_a_timestamp_in_the_future_beyond_the_window_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.event("app_mention", timestamp_age=-301))[0] == 401


def test_old_interaction_is_refused(rig: Rig) -> None:
    assert rig.interact(rig.slack.block_actions("approve", timestamp_age=301))[0] == 401
    assert rig.queue.items == []


def test_forged_signature_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.forge(rig.slack.event("app_mention")))[0] == 401
    assert rig.interact(rig.slack.forge(rig.slack.block_actions("a")))[0] == 401
    assert rig.queue.items == []


def test_tampered_body_is_refused(rig: Rig) -> None:
    assert rig.events(rig.slack.tamper(rig.slack.event("app_mention")))[0] == 401
    assert rig.interact(rig.slack.tamper(rig.slack.block_actions("a")))[0] == 401


def test_the_signature_is_over_the_raw_bytes_not_a_re_encoding(rig: Rig) -> None:
    ev = rig.slack.event("app_mention")
    assert rig.slack.reserialise(ev).body != ev.body
    assert rig.events(rig.slack.reserialise(ev))[0] == 401
    ba = rig.slack.block_actions("a")
    assert rig.interact(rig.slack.reserialise(ba))[0] == 401
    # and the genuine non-canonical bytes pass
    assert rig.events(ev)[0] == 200


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: {k: v for k, v in h.items() if k != "X-Slack-Signature"},
        lambda h: {k: v for k, v in h.items() if k != "X-Slack-Request-Timestamp"},
        lambda h: {**h, "X-Slack-Signature": "v1=" + h["X-Slack-Signature"][3:]},
        lambda h: {**h, "X-Slack-Signature": h["X-Slack-Signature"][3:]},
        lambda h: {**h, "X-Slack-Signature": h["X-Slack-Signature"][:-2]},
        lambda h: {**h, "X-Slack-Signature": ""},
        lambda h: {**h, "X-Slack-Signature": "v0=é"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "abc"},
        lambda h: {**h, "X-Slack-Request-Timestamp": ""},
        lambda h: {**h, "X-Slack-Request-Timestamp": "-1"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "1e9"},
        lambda h: {**h, "X-Slack-Request-Timestamp": "١٢٣"},
    ],
)
def test_malformed_headers_are_refused(rig: Rig, mutate: object) -> None:
    raw = rig.slack.event("app_mention")
    headers: Mapping[str, str] = mutate(dict(raw.headers))  # type: ignore[operator]
    assert rig.ingest.events(headers, raw.body).status == 401
    assert rig.queue.items == []


def test_a_wrong_secret_is_refused() -> None:
    other = Rig()
    other.ingest = SlackIngest(
        WRONG_SECRET, other.store, other.queue, other.metrics, clock=other.clock
    )
    assert other.events(other.slack.event("app_mention"))[0] == 401


@pytest.mark.parametrize(
    "events_body",
    [
        b"not json",
        b"[1]",
        b'{"type":"event_callback"}',
        b'{"type":"event_callback","event_id":12345}',
        b'{"type":"event_callback","event_id":"x#y"}',
        b'{"type":"event_callback","event_id":""}',
        b'{"type":"event_callback","event_id":"Ev1","api_app_id":7}',
        b'{"type":"url_verification"}',
        b'{"type":"url_verification","challenge":123}',
        b'{"type":"url_verification","challenge":null}',
        b'{"type":"url\\u005fverification","challenge":["a"]}',
    ],
)
def test_signed_but_malformed_events_are_refused_as_malformed_not_as_forged(
    rig: Rig, events_body: bytes
) -> None:
    r = rig.ingest.events(*_parts(signed(events_body)))
    assert r.status == 400
    assert r.body != "invalid signature"
    assert rig.queue.items == []
    assert rig.metrics.reasons == [("webhook.rejected", "malformed")]


@pytest.mark.parametrize(
    "body",
    [
        b"payload=",  # blank
        b"other=1",
        b"payload=%7B",  # not JSON
        b"payload=%5B1%5D",  # payload=[1]: JSON, but not an object
        b"payload=1",
        b"payload=%7B%7D",  # no trigger_id
        b"payload=%7B%22trigger_id%22%3A7%7D",  # trigger_id=7
        b"payload=%7B%22trigger_id%22%3Anull%7D",
        b"payload=%7B%22trigger_id%22%3A%22%22%7D",
        b"payload=%7B%22trigger_id%22%3A%22a%23b%22%7D",  # a '#' would forge a key separator
        b"payload=%7B%22trigger_id%22%3A%22a%20b%22%7D",
        b"payload=%7B%22trigger_id%22%3A%22%C3%A9%22%7D",  # not ASCII
        b"payload=%7B%7D&payload=%7B%7D",  # two payloads
        "payload=é".encode(),
    ],
)
def test_signed_but_malformed_interactions_are_refused_as_malformed_not_as_forged(
    rig: Rig, body: bytes
) -> None:
    r = rig.ingest.interactivity(*_parts(signed(body)))
    assert r.status == 400
    assert rig.queue.items == []
    assert rig.metrics.reasons == [("webhook.rejected", "malformed")]


def test_a_bad_signature_is_still_counted_as_a_signature_failure(rig: Rig) -> None:
    rig.events(rig.slack.forge(rig.slack.event("app_mention")))
    assert rig.metrics.reasons == [("webhook.rejected", "signature")]


def test_a_malformed_body_does_not_burn_its_id(rig: Rig) -> None:
    assert (
        rig.events(signed(b'{"type":"event_callback","event_id":"Ev1","api_app_id":7}'))[0] == 400
    )
    assert rig.events(signed(b'{"type":"event_callback","event_id":"Ev1"}'))[0] == 200


def _parts(raw: RawWebhook) -> tuple[Mapping[str, str], bytes]:
    return raw.headers, raw.body


def test_an_event_body_on_the_interactivity_path_is_refused(rig: Rig) -> None:
    """Genuine, but the wrong shape for the endpoint: malformed, and nothing is queued."""
    assert rig.interact(rig.slack.event("app_mention"))[0] == 400
    assert rig.events(rig.slack.block_actions("a"))[0] == 400
    assert rig.queue.items == []


def test_verifier_declares_the_window_slack_signs_and_agrees_with_the_contract_suite() -> None:
    v = SlackVerifier(SIGNING_SECRET, Clock(), kind="events")
    caps = CAPABILITIES[Vendor.SLACK]
    assert v.replay_window == MAX_REPLAY_WINDOW
    assert v.signed_timestamp is True
    assert caps.signed_timestamp is True
    assert "x-slack-signature" in v.secret_headers


def test_dedupe_record_expires_past_twice_the_window(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    rig.events(raw)
    eid = rig.queue.items[0].delivery_id
    item = rig.store.get(PLATFORM, Key(f"HOOK#slack#{eid}", "SEEN"))
    assert item is not None
    assert item.data["ttl"] == int(NOW + 600)


_DIGEST_CALLS = {"new", "sha256", "sha1", "sha512", "md5", "blake2b", "digest", "hexdigest"}


def _computes_digest(fn: ast.FunctionDef) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in _DIGEST_CALLS:
                return True
    return False


def _comparison_problems(fn: ast.FunctionDef) -> list[str]:
    """Any way to compare a value other than ``hmac.compare_digest``, inside ``fn``."""
    problems = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, ast.Eq | ast.NotEq | ast.In | ast.NotIn):
                    problems.append(f"{type(op).__name__} at line {node.lineno}")
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name in {"startswith", "endswith", "eq", "ne", "index", "find", "count"}:
                problems.append(f"{name}() at line {node.lineno}")
    return problems


def _compare_digest_calls(fn: ast.FunctionDef) -> int:
    return sum(
        1
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "compare_digest"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "hmac"
    )


def test_signature_comparison_is_constant_time_and_nothing_else_compares_in_that_function() -> None:
    """D4-04's review: no ==, !=, in, startswith/endswith or operator.eq on any value in a
    function that computes an HMAC or a digest; ``hmac.compare_digest`` is the only comparison, and
    it must be called INSIDE that function (one elsewhere does not satisfy this)."""
    tree = ast.parse(inspect.getsource(slack_module))
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and _computes_digest(n)]
    assert [f.name for f in fns] == ["_authenticate"]
    for fn in fns:
        assert _comparison_problems(fn) == [], fn.name
        assert _compare_digest_calls(fn) >= 1, fn.name


def test_the_static_check_catches_each_forbidden_comparison() -> None:
    bad = [
        "def f(a, b):\n    hmac.new(k, m, h)\n    return a == b",
        "def f(a, b):\n    hmac.new(k, m, h)\n    return a != b",
        "def f(a, b):\n    hmac.new(k, m, h)\n    return a in (b,)",
        "def f(a, b):\n    hmac.new(k, m, h)\n    return a.startswith(b)",
        "def f(a, b):\n    hmac.new(k, m, h)\n    return operator.eq(a, b)",
    ]
    for src in bad:
        fn = ast.parse(src).body[0]
        assert isinstance(fn, ast.FunctionDef)
        assert _comparison_problems(fn), src
    stray = ast.parse("def f(a, b):\n    hmac.new(k, m, h)\n    return a is None").body[0]
    assert isinstance(stray, ast.FunctionDef)
    assert _compare_digest_calls(stray) == 0  # a compare_digest elsewhere would not count


def test_an_uppercase_hex_signature_is_refused(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    sig = raw.headers["X-Slack-Signature"]
    upper = {**raw.headers, "X-Slack-Signature": "v0=" + sig[3:].upper()}
    assert sig[3:] != sig[3:].upper()
    assert rig.ingest.events(upper, raw.body).status == 401
    assert rig.ingest.events(raw.headers, raw.body).status == 200


# --- url_verification ---------------------------------------------------------------------------


def test_url_verification_echoes_the_challenge_and_queues_nothing(rig: Rig) -> None:
    status, body = rig.events(rig.slack.url_verification("abc-123"))
    assert (status, body) == (200, "abc-123")
    assert rig.queue.items == []


def test_the_handshake_is_decided_from_the_parsed_body_not_a_substring(rig: Rig) -> None:
    escaped = signed(b'{"type":"url\\u005fverification","challenge":"abc"}')
    assert rig.events(escaped) == (200, "abc")
    assert rig.queue.items == []


def test_a_handshake_is_never_queued_even_when_the_word_is_elsewhere(rig: Rig) -> None:
    body = b'{"type":"event_callback","event_id":"Ev1","event":{"text":"url_verification"}}'
    assert rig.events(signed(body))[0] == 200
    assert len(rig.queue.items) == 1
    assert rig.queue.items[0].delivery_id == "Ev1"


def test_the_production_verifier_refuses_a_handshake_as_a_delivery() -> None:
    v = SlackVerifier(SIGNING_SECRET, Clock(), kind="events")
    raw = FakeSlack(Clock()).url_verification("abc")
    with pytest.raises(MalformedWebhookError):
        v.verify({k.lower(): x for k, x in raw.headers.items()}, raw.body)


def test_a_tampered_handshake_is_refused_not_echoed(rig: Rig) -> None:
    assert rig.events(rig.slack.tamper(rig.slack.url_verification("abc")))[0] == 401
    assert rig.events(rig.slack.reserialise(rig.slack.url_verification("abc")))[0] == 401


def test_url_verification_is_verified_first(rig: Rig) -> None:
    raw = rig.slack.forge(rig.slack.url_verification("abc-123"))
    assert rig.events(raw) == (401, "invalid signature")
    old = rig.slack.url_verification("abc-123")
    stale = RawWebhook({**old.headers, "X-Slack-Request-Timestamp": str(int(NOW) - 400)}, old.body)
    assert rig.events(stale)[0] == 401


# --- retries and the dedupe key -----------------------------------------------------------------


def test_retries_are_deduped_on_event_id_though_re_signed_with_a_fresh_timestamp(
    rig: Rig,
) -> None:
    first = rig.slack.event("app_mention")
    assert rig.events(first)[0] == 200
    rig.clock.now += 100
    one = rig.slack.retry(first, 1)
    two = rig.slack.retry(first, 2, reason="http_error")
    assert one.headers["X-Slack-Request-Timestamp"] != first.headers["X-Slack-Request-Timestamp"]
    assert one.headers["X-Slack-Signature"] != first.headers["X-Slack-Signature"]
    assert rig.events(one) == (200, "")
    assert rig.events(two) == (200, "")
    assert len(rig.queue.items) == 1
    assert rig.metrics.counts["webhook.duplicate"] == 2


def test_the_dedupe_key_is_unique_per_delivery_and_stable_across_retries(rig: Rig) -> None:
    events = [rig.slack.event("app_mention", channel=CHANNELS[i % 2]) for i in range(25)]
    interactions = [rig.slack.block_actions("approve", value="same") for _ in range(25)]
    for raw in events:
        assert rig.events(raw)[0] == 200
    for raw in interactions:
        assert rig.interact(raw)[0] == 200
    ids = [n.delivery_id for n in rig.queue.items]
    assert len(ids) == 50
    assert len(set(ids)) == 50  # every delivery its own key
    # a retry of each event lands on the key it already holds
    for raw in events:
        assert rig.events(rig.slack.retry(raw, 1))[0] == 200
    assert len(rig.queue.items) == 50
    # a retry's key is the original's, not merely a distinct one
    assert {n.delivery_id for n in rig.queue.items if n.surface == "slack"} == {
        f"Ev{i:08d}" for i in range(1, 26)
    }


def test_two_clicks_of_the_same_button_are_two_deliveries(rig: Rig) -> None:
    a = rig.slack.block_actions("approve", value="g1")
    b = rig.slack.block_actions("approve", value="g1")
    assert rig.interact(a)[0] == rig.interact(b)[0] == 200
    assert len(rig.queue.items) == 2


def test_the_same_interaction_delivered_twice_is_deduped(rig: Rig) -> None:
    a = rig.slack.block_actions("approve")
    rig.interact(a)
    assert rig.interact(a) == (200, "")
    assert len(rig.queue.items) == 1


def test_the_same_event_id_from_two_apps_is_two_deliveries(rig: Rig) -> None:
    for app in ("A1", "A2"):
        body = json.dumps(
            {"type": "event_callback", "event_id": "Ev1", "team_id": "T1", "api_app_id": app}
        ).encode()
        assert rig.events(signed(body)) == (200, "")
    assert [n.delivery_id for n in rig.queue.items] == ["A1:Ev1", "A2:Ev1"]
    # the same app's retry is still one delivery
    again = json.dumps(
        {"type": "event_callback", "event_id": "Ev1", "team_id": "T1", "api_app_id": "A1"}
    ).encode()
    assert rig.events(signed(again)) == (200, "")
    assert len(rig.queue.items) == 2


def test_the_same_event_id_from_two_teams_in_one_app_is_still_one_delivery(rig: Rig) -> None:
    """Slack's event_id is global: only the app is added to the namespace."""
    for team in ("T1", "T2"):
        body = json.dumps(
            {"type": "event_callback", "event_id": "Ev1", "team_id": team, "api_app_id": "A1"}
        ).encode()
        rig.events(signed(body))
    assert len(rig.queue.items) == 1


def test_a_rejected_delivery_claims_nothing(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    assert rig.events(rig.slack.forge(raw))[0] == 401
    assert rig.events(raw)[0] == 200
    assert len(rig.queue.items) == 1


# --- failures -----------------------------------------------------------------------------------


def test_a_queue_failure_is_503_so_slack_retries_and_the_retry_is_not_dropped(rig: Rig) -> None:
    raw = rig.slack.event("app_mention")
    original = rig.queue.enqueue

    def boom(n: Nudge) -> None:
        raise RuntimeError("down")

    rig.queue.enqueue = boom  # type: ignore[method-assign,assignment]
    assert rig.events(raw)[0] == 503
    rig.queue.enqueue = original  # type: ignore[method-assign]
    assert rig.events(rig.slack.retry(raw, 1))[0] == 200
    assert len(rig.queue.items) == 1


# --- the budget ---------------------------------------------------------------------------------


def test_handler_has_no_heavy_imports_and_imports_inside_the_budget() -> None:
    """Fresh interpreter: nothing outside the standard library and the light ``sto`` modules."""
    code = (
        "import sys, time\n"
        "before = set(sys.modules)\n"
        "t = time.perf_counter()\n"
        "import sto.ingest.slack\n"
        "dt = time.perf_counter() - t\n"
        "new = set(sys.modules) - before\n"
        "std = sys.stdlib_module_names\n"
        "top = lambda m: m.split('.')[0]\n"
        "third = sorted(m for m in new if top(m) not in std and top(m) != 'sto')\n"
        "heavy = sorted(m for m in new if m.startswith(('sto.engine', 'sto.gates')))\n"
        "print(repr(third), repr(heavy), dt)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=30
    ).stdout.split()
    assert out[0] == "[]", out
    assert out[1] == "[]", out
    assert float(out[2]) < 1.0


def test_ack_path_completes_inside_one_second_measured(rig: Rig) -> None:
    raws = [rig.slack.event("app_mention") for _ in range(20)]
    raws += [rig.slack.block_actions("approve") for _ in range(20)]
    worst = 0.0
    for raw in raws:
        start = time.perf_counter()
        if raw.headers["Content-Type"] == "application/json":
            status = rig.ingest.events(raw.headers, raw.body).status
        else:
            status = rig.ingest.interactivity(raw.headers, raw.body).status
        worst = max(worst, time.perf_counter() - start)
        assert status == 200
    assert worst < 1.0


# --- the conformance suite's webhook section, through both endpoints ----------------------------
#
# The suite's ``Port.WEBHOOK`` section runs UNMODIFIED against the production verifier and the
# production ingest. The D7-01 fake supplies the forged, tampered and re-serialised variants; the
# bodies are built here only because the fake's own senders pick their own ``event_id`` and
# ``trigger_id``, and the suite chooses its delivery IDs. They keep the fake's non-canonical bytes
# (compact, ``\/`` escapes; form-encoded with ``%20``), and are signed under the fake's secret.

WATCHED = "T-1"
_JSON = "application/json"
_FORM = "application/x-www-form-urlencoded"


def _compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":")).replace("/", "\\/")


class _SlackTarget(Target):
    vendor = Vendor.SLACK
    signature_header = "X-Slack-Signature"
    watched = WATCHED
    controls = frozenset(
        {
            Control.SIGNATURE,
            Control.UNSIGNED,
            Control.DUPLICATE,
            Control.REPLAY_WINDOW,
            Control.RESTART,
        }
    )
    content_type = _JSON

    def __init__(self) -> None:
        self.now = Clock()
        self.store = MemoryStore()
        self.queue = Queue()
        self.metrics = Metrics()
        self.slack = FakeSlack(self.now)
        self.adapter: SlackIngest = self._fresh()
        self.verifier = self._verifier()

    def _fresh(self) -> SlackIngest:
        return SlackIngest(SIGNING_SECRET, self.store, self.queue, self.metrics, clock=self.now)

    def _verifier(self) -> SlackVerifier:
        raise NotImplementedError

    def _endpoint(self, raw: RawWebhook) -> IngestResponse:
        raise NotImplementedError

    def body(self, delivery_id: str) -> bytes:
        raise NotImplementedError

    def _sign(self, body: bytes, at: float) -> RawWebhook:
        raw = signed(body, at)
        return RawWebhook({**raw.headers, "Content-Type": self.content_type}, raw.body)

    # --- adapter calls ---
    def restart(self) -> None:
        self.adapter = self._fresh()
        self.verifier = self._verifier()

    def deliver(self, raw: RawWebhook) -> Outcome:
        before = len(self.queue.items)
        response = self._endpoint(raw)
        if response.status == 400:
            raise MalformedWebhookError(response.body)
        if response.status == 401:
            raise InvalidSignatureError(response.body)
        if response.status == 503:
            raise TransientError(response.body)
        assert response.status == 200
        if len(self.queue.items) == before:
            return Outcome(False)
        return Outcome(True, self.names(self.queue.items[-1]))

    def names(self, nudge: Nudge) -> tuple[str, ...]:
        raise NotImplementedError

    def queued(self) -> int:
        return len(self.queue.items)

    def clock(self) -> float:
        return self.now.now

    def advance_clock(self, seconds: float) -> None:
        self.now.now += seconds

    # --- the vendor sending webhooks ---
    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        return self._sign(self.body(delivery_id), self.now.now)

    def forge(
        self, revision: int, delivery_id: str, how: ForgeKind = ForgeKind.WRONG_SECRET
    ) -> RawWebhook:
        genuine = self.emit(revision, delivery_id)
        wrong = self.slack.forge(genuine).headers[self.signature_header]  # the fake's wrong secret
        real = genuine.headers[self.signature_header]
        value = {
            ForgeKind.WRONG_SECRET: wrong,
            ForgeKind.TRUNCATED_MAC: real[: len(real) // 2],
            ForgeKind.EMPTY_MAC: "v0=",
            ForgeKind.EMPTY_KEY: self._sign_with(b"", genuine),
            ForgeKind.BLANK_HEADER: "",
        }[how]
        return RawWebhook({**genuine.headers, self.signature_header: value}, genuine.body)

    @staticmethod
    def _sign_with(secret: bytes, raw: RawWebhook) -> str:
        stamp = raw.headers["X-Slack-Request-Timestamp"].encode()
        mac = hmac.new(secret, b"v0:" + stamp + b":" + raw.body, hashlib.sha256).hexdigest()
        return "v0=" + mac

    def emit_without_id(self, revision: int) -> RawWebhook:
        return self._sign(self.body(""), self.now.now)

    def emit_malformed(self, delivery_id: str) -> RawWebhook:
        return self._sign(b"{" + self.body(delivery_id)[:-1], self.now.now)

    def future_dated(self, revision: int, delivery_id: str, ahead: float) -> RawWebhook:
        return self._sign(self.body(delivery_id), self.now.now + ahead)

    def set_timestamp(self, raw: RawWebhook, value: str | None) -> RawWebhook:
        headers = {k: v for k, v in raw.headers.items() if k != "X-Slack-Request-Timestamp"}
        if value is not None:
            headers["X-Slack-Request-Timestamp"] = value
        return RawWebhook(headers, raw.body)

    def tamper(self, raw: RawWebhook) -> RawWebhook:
        return self.slack.tamper(raw)

    def reserialise(self, raw: RawWebhook) -> RawWebhook:
        return self.slack.reserialise(raw)


class SlackEventsTarget(_SlackTarget):
    name = "slack-events"
    content_type = _JSON

    def _verifier(self) -> SlackVerifier:
        return self.adapter.events_verifier

    def _endpoint(self, raw: RawWebhook) -> IngestResponse:
        return self.adapter.events(raw.headers, raw.body)

    def body(self, delivery_id: str) -> bytes:
        event: dict[str, object] = {
            "type": "app_mention",
            "text": f"<@U0SYNTHBOT> status of {WATCHED}",
        }
        payload: dict[str, object] = {"type": "event_callback", "team_id": "T0SYNTH01"}
        payload["event"] = event
        if delivery_id:
            payload["event_id"] = delivery_id
        return _compact(payload).encode()

    def names(self, nudge: Nudge) -> tuple[str, ...]:
        text = json.loads(nudge.body)["event"]["text"]
        return tuple(w for w in text.split() if w.startswith("T-"))


class SlackInteractivityTarget(_SlackTarget):
    name = "slack-interactivity"
    content_type = _FORM

    def _verifier(self) -> SlackVerifier:
        return self.adapter.interactivity_verifier

    def _endpoint(self, raw: RawWebhook) -> IngestResponse:
        return self.adapter.interactivity(raw.headers, raw.body)

    def body(self, delivery_id: str) -> bytes:
        payload: dict[str, object] = {
            "type": "block_actions",
            "user": {"id": "U0SYNTH01"},
            "actions": [{"type": "button", "action_id": "open", "value": WATCHED}],
        }
        if delivery_id:
            payload["trigger_id"] = delivery_id
        return ("payload=" + quote(_compact(payload), safe="")).encode()

    def names(self, nudge: Nudge) -> tuple[str, ...]:
        fields = parse_qs(nudge.body.decode())
        return (json.loads(fields["payload"][0])["actions"][0]["value"],)


def slack_events() -> Target:
    return SlackEventsTarget()


def slack_interactivity() -> Target:
    return SlackInteractivityTarget()


class TestSlackEventsConformance(AdapterConformance):
    """The Events API endpoint: JSON, the ID inside the body (``event_id``)."""

    port = Port.WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": slack_events}


class TestSlackInteractivityConformance(AdapterConformance):
    """The interactivity endpoint: a form body with one ``payload`` field (``trigger_id``). This
    is the AC "the suite reads Slack's form-encoded body through the target"."""

    port = Port.WEBHOOK
    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": slack_interactivity}


def test_both_endpoints_pass_every_test_the_webhook_port_requires() -> None:
    for make in (slack_events, slack_interactivity):
        failed = {n: e for n, e in run_suite(make, Port.WEBHOOK).items() if e is not None}
        assert failed == {}


def test_the_interactivity_target_really_sends_a_form_body_and_the_events_target_json() -> None:
    form = slack_interactivity().emit(1, "1.2.abc")
    events = slack_events().emit(1, "Ev1")
    assert form.headers["Content-Type"] == _FORM
    assert form.body.startswith(b"payload=%7B")
    assert events.headers["Content-Type"] == _JSON
    assert b"\\/" in events.body or b"/" not in events.body  # the fake's non-canonical style


def test_the_production_verifier_accepts_headers_in_any_case() -> None:
    v = SlackVerifier(SIGNING_SECRET, Clock(), kind="events")
    raw = FakeSlack(Clock()).event("app_mention")
    assert v.verify(raw.headers, raw.body).startswith("Ev")
    assert v.verify({k.lower(): x for k, x in raw.headers.items()}, raw.body).startswith("Ev")


def _signed_at_stamp(body: bytes, stamp: str) -> RawWebhook:
    """Genuinely signed over an arbitrary timestamp STRING, which ``signed`` cannot write."""
    mac = hmac.new(SIGNING_SECRET, b"v0:" + stamp.encode() + b":" + body, hashlib.sha256)
    return RawWebhook(
        {"X-Slack-Request-Timestamp": stamp, "X-Slack-Signature": "v0=" + mac.hexdigest()}, body
    )


@pytest.mark.parametrize(
    "stamp",
    ["1700000000x", "1700000000 ", "١٧٠٠٠٠٠٠٠٠"],
)
def test_a_genuinely_signed_but_non_ascii_digit_timestamp_is_refused_not_a_crash(
    rig: Rig, stamp: str
) -> None:
    raw = _signed_at_stamp(b'{"type":"event_callback","event_id":"Ev1"}', stamp)
    assert rig.ingest.events(raw.headers, raw.body).status == 401
    assert rig.queue.items == []


def test_a_forged_body_that_is_also_malformed_is_a_signature_failure_not_malformed(
    rig: Rig,
) -> None:
    """Authenticate first: an unauthenticated sender learns nothing about body parsing."""
    forged = rig.slack.forge(signed(b"not json"))
    assert rig.events(forged) == (401, "invalid signature")
    assert rig.metrics.reasons == [("webhook.rejected", "signature")]


def test_a_non_ascii_form_body_is_malformed(rig: Rig) -> None:
    body = b"payload=%7B%22trigger_id%22%3A%22t1%22%7D&note=" + "é".encode()
    assert rig.interact(signed(body))[0] == 400


def test_two_payload_fields_are_malformed_not_first_wins(rig: Rig) -> None:
    one = quote('{"trigger_id":"t1"}', safe="")
    two = quote('{"trigger_id":"t2"}', safe="")
    assert rig.interact(signed(f"payload={one}&payload={two}".encode()))[0] == 400
    assert rig.queue.items == []


def test_an_empty_signing_secret_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="signing secret"):
        SlackVerifier(b"", Clock(), kind="events")
