"""D4-03: generic webhook ingest. Verify on the raw body, dedupe, enqueue, answer in time.

Everything runs on the in-memory store with a fake clock, queue and metrics sink. Secrets and
signatures here are synthetic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

import pytest

from sto.domain.errors import PermanentError, TransientError
from sto.ingest.core import (
    DEFAULT_MAX_BODY_BYTES,
    HEADER_BUDGET_BYTES,
    MAX_BODY_BYTES_CEILING,
    NUDGE_BUDGET_BYTES,
    SQS_MESSAGE_LIMIT,
    InvalidSignatureError,
    Nudge,
    WebhookIngest,
    WebhookVerifier,
    normalise_headers,
    serialise_nudge,
)
from sto.store.memory import MemoryStore
from sto.store.ports import (
    PLATFORM,
    Item,
    Key,
    TransactionOutcomeUnknownError,
)

SECRET = b"synthetic-secret-not-real"
SIG = "x-signature"
ID = "x-delivery-id"


class HmacVerifier:
    """A minimal reference verifier: HMAC-SHA256 of the raw body, constant-time compare."""

    secret_headers: frozenset[str] = frozenset()

    def __init__(self, replay_window: float | None = None) -> None:
        self.replay_window = replay_window
        self.signed_timestamp = replay_window is not None
        self.seen_headers: list[Mapping[str, str]] = []
        self.seen_bodies: list[bytes] = []

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        self.seen_headers.append(headers)
        self.seen_bodies.append(raw_body)
        got = headers.get(SIG, "")
        want = hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(got.encode(), want.encode()):
            raise InvalidSignatureError("bad signature")
        delivery = headers.get(ID, "")
        if not delivery:
            raise InvalidSignatureError("no delivery id")
        return delivery


def sign(body: bytes) -> str:
    return hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def delivery(body: bytes = b'{"a":1}', delivery_id: str = "d-1") -> tuple[dict[str, str], bytes]:
    return {"X-Signature": sign(body), "X-Delivery-Id": delivery_id}, body


class Queue:
    def __init__(self) -> None:
        self.items: list[Nudge] = []
        self.fail: Exception | None = None

    def enqueue(self, nudge: Nudge) -> None:
        if self.fail is not None:
            raise self.fail
        self.items.append(nudge)


class Metrics:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.tags: list[tuple[str, dict[str, str]]] = []

    def incr(self, name: str, **tags: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
        self.tags.append((name, tags))


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def queue() -> Queue:
    return Queue()


@pytest.fixture
def metrics() -> Metrics:
    return Metrics()


@pytest.fixture
def clock() -> Clock:
    return Clock()


def make(
    store: MemoryStore,
    queue: Queue,
    metrics: Metrics,
    clock: Clock,
    *,
    verifier: HmacVerifier | None = None,
    surface: str = "hub",
    **options: Any,
) -> WebhookIngest:
    return WebhookIngest(
        surface=surface,
        verifier=verifier or HmacVerifier(),
        store=store,
        queue=queue,
        metrics=metrics,
        clock=clock,
        **options,
    )


def seen_item(store: MemoryStore, surface: str = "hub", delivery_id: str = "d-1") -> Item | None:
    return store.get(PLATFORM, Key(f"HOOK#{surface}#{delivery_id}", "SEEN"))


# --- header normalisation ---------------------------------------------------------------------


def test_header_names_are_lowercased_and_values_stripped() -> None:
    assert normalise_headers({"X-Hub-Signature-256": " sha256=ab ", "CONTENT-type": "x"}) == {
        "x-hub-signature-256": "sha256=ab",
        "content-type": "x",
    }


def test_header_names_differing_only_in_case_with_different_values_are_refused() -> None:
    with pytest.raises(PermanentError):
        normalise_headers({"X-Sig": "a", "x-sig": "b"})


def test_header_names_differing_only_in_case_with_the_same_value_collapse() -> None:
    assert normalise_headers({"X-Sig": "a", "x-sig": "a"}) == {"x-sig": "a"}


def test_the_verifier_gets_normalised_headers_and_the_untouched_raw_body(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    verifier = HmacVerifier()
    ingest = make(store, queue, metrics, clock, verifier=verifier)
    headers, body = delivery(b'{ "spaced" :  1 }\n')
    assert ingest.handle(headers, body).status == 202
    assert verifier.seen_bodies == [b'{ "spaced" :  1 }\n']
    assert set(verifier.seen_headers[0]) == {SIG, ID}


def test_the_verifier_port_is_a_runtime_checkable_protocol() -> None:
    assert isinstance(HmacVerifier(), WebhookVerifier)
    assert not isinstance(object(), WebhookVerifier)


# --- bad signatures ---------------------------------------------------------------------------


def test_a_bad_signature_gets_401_and_a_metric_and_nothing_else(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    headers["X-Signature"] = "0" * 64
    response = ingest.handle(headers, body)
    assert response.status == 401
    assert metrics.counts == {"webhook.rejected": 1}
    assert metrics.tags == [("webhook.rejected", {"surface": "hub", "reason": "signature"})]
    assert queue.items == []
    assert seen_item(store) is None


def test_a_tampered_body_gets_401(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    assert ingest.handle(headers, body + b" ").status == 401
    assert queue.items == []


def test_a_missing_signature_header_gets_401(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    _, body = delivery()
    assert ingest.handle({"X-Delivery-Id": "d-1"}, body).status == 401


def test_any_permanent_verifier_error_is_a_401_not_a_crash(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class Odd:
        signed_timestamp = False
        replay_window: float | None = None
        secret_headers: frozenset[str] = frozenset()

        def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
            raise PermanentError("stale timestamp")

    ingest = WebhookIngest("hub", Odd(), store, queue, metrics, clock=clock)
    assert ingest.handle({}, b"x").status == 401
    assert metrics.counts == {"webhook.rejected": 1}


def test_conflicting_duplicate_headers_get_401(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    headers["x-signature"] = "other"
    assert ingest.handle(headers, body).status == 401
    assert queue.items == []


def test_a_verifier_bug_that_is_not_a_store_error_fails_loud_and_the_vendor_retries(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class Broken:
        signed_timestamp = False
        replay_window: float | None = None
        secret_headers: frozenset[str] = frozenset()

        def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
            raise RuntimeError("boom")

    ingest = WebhookIngest("hub", Broken(), store, queue, metrics, clock=clock)
    with pytest.raises(RuntimeError):
        ingest.handle({}, b"x")
    assert queue.items == []


# --- enqueue and dedupe -----------------------------------------------------------------------


def test_a_genuine_delivery_is_enqueued_once_and_accepted(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    response = ingest.handle(headers, body)
    assert response.status == 202
    assert len(queue.items) == 1
    nudge = queue.items[0]
    assert (nudge.surface, nudge.delivery_id, nudge.body) == ("hub", "d-1", body)
    assert nudge.received_at == clock.now
    assert metrics.counts == {"webhook.accepted": 1}


def test_a_nudge_always_says_to_re_read_and_cannot_be_built_otherwise() -> None:
    n = Nudge(surface="hub", delivery_id="d", body=b"", headers={}, received_at=0.0)
    assert n.reread is True
    with pytest.raises(ValueError, match="re-read"):
        Nudge(surface="hub", delivery_id="d", body=b"", headers={}, received_at=0.0, reread=False)


# --- nudge size and shape (D4-29) -------------------------------------------------------------


def test_a_body_under_the_limit_is_carried_and_not_marked(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, max_body_bytes=100)
    headers, body = delivery(b"x" * 100)
    assert ingest.handle(headers, body).status == 202
    nudge = queue.items[0]
    assert (nudge.body, nudge.body_omitted, nudge.body_size) == (body, False, 100)


def test_a_body_over_the_limit_queues_one_bodyless_marked_nudge_and_no_503(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, max_body_bytes=100, event_header="x-event")
    headers, body = delivery(b"x" * 101)
    headers["X-Event"] = "push"
    response = ingest.handle(headers, body)
    assert response.status == 202
    assert len(queue.items) == 1
    nudge = queue.items[0]
    assert nudge.body == b""
    assert nudge.body_omitted is True
    assert nudge.body_size == 101
    assert nudge.reread is True
    assert (nudge.surface, nudge.delivery_id, nudge.event) == ("hub", "d-1", "push")
    assert nudge.headers["x-event"] == "push"
    assert metrics.counts == {"webhook.accepted": 1, "webhook.body_omitted": 1}
    # The delivery stays claimed: the vendor's retry is a duplicate, not a second nudge.
    assert ingest.handle(headers, body).status == 200
    assert len(queue.items) == 1


def test_a_megabytes_delivery_is_verified_on_the_full_raw_body_before_being_dropped(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    verifier = HmacVerifier()
    ingest = make(store, queue, metrics, clock, verifier=verifier)
    headers, body = delivery(b"y" * (5 * 1024 * 1024))
    assert ingest.handle(headers, body).status == 202
    assert verifier.seen_bodies == [body]
    assert queue.items[0].body_omitted is True
    assert ingest.handle({**headers, "X-Signature": "00"}, body).status == 401


def test_the_event_is_none_without_an_event_header(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="x-event")
    headers, body = delivery()
    ingest.handle(headers, body)
    assert queue.items[0].event is None


@pytest.mark.parametrize("limit", [0, -1, MAX_BODY_BYTES_CEILING + 1, True, 1.5, 100.0])
def test_a_body_limit_that_is_not_well_below_the_queue_limit_is_refused(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock, limit: int
) -> None:
    with pytest.raises(ValueError, match="max_body_bytes"):
        make(store, queue, metrics, clock, max_body_bytes=limit)


def test_the_range_error_names_its_unit(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    with pytest.raises(ValueError, match="bytes"):
        make(store, queue, metrics, clock, max_body_bytes=0)


def test_the_surface_is_validated_before_the_limit(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    with pytest.raises(ValueError, match="surface"):
        make(store, queue, metrics, clock, surface="", max_body_bytes=0)


def test_a_nudge_that_omits_its_body_must_be_empty_and_a_carried_body_must_match_its_size() -> None:
    with pytest.raises(ValueError, match="body"):
        Nudge("hub", "d", b"abc", {}, 0.0, body_omitted=True, body_size=3)
    with pytest.raises(ValueError, match="body"):
        Nudge("hub", "d", b"abc", {}, 0.0, body_size=9)


@pytest.mark.parametrize("size", [-5, 0, None, True])
def test_an_omitted_body_must_say_a_positive_size(size: Any) -> None:
    with pytest.raises(ValueError, match="positive body_size"):
        Nudge("hub", "d", b"", {}, 0.0, body_omitted=True, body_size=size)


def test_body_size_defaults_to_the_length_of_a_carried_body() -> None:
    assert Nudge("hub", "d", b"abc", {}, 0.0).body_size == 3
    assert Nudge("hub", "d", b"", {}, 0.0).body_size == 0


def test_the_ceiling_the_default_and_the_budgets_are_pinned() -> None:
    assert DEFAULT_MAX_BODY_BYTES == 128 * 1024
    assert MAX_BODY_BYTES_CEILING == 160 * 1024
    assert NUDGE_BUDGET_BYTES < SQS_MESSAGE_LIMIT
    assert DEFAULT_MAX_BODY_BYTES < MAX_BODY_BYTES_CEILING


def test_a_body_exactly_at_the_ceiling_is_accepted_and_carried(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, max_body_bytes=MAX_BODY_BYTES_CEILING)
    headers, body = delivery(b"x" * MAX_BODY_BYTES_CEILING)
    assert ingest.handle(headers, body).status == 202
    assert queue.items[0].body_omitted is False


# --- wire size: encoded, with headers (review pass 1) -----------------------------------------


def maximal_headers() -> dict[str, str]:
    """Headers right at the budget: many distinct names, long values."""
    out: dict[str, str] = {}
    n = 0
    while len(json.dumps(out)) < HEADER_BUDGET_BYTES - 200:
        out[f"x-pad-{n}"] = "p" * 100
        n += 1
    return out


def test_a_ceiling_sized_nudge_with_maximal_headers_serialises_under_the_sqs_limit(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(
        store, queue, metrics, clock, max_body_bytes=MAX_BODY_BYTES_CEILING, event_header="x-event"
    )
    headers, body = delivery(b"\xff" * MAX_BODY_BYTES_CEILING, delivery_id="d" * 512)
    headers.update(maximal_headers())
    headers["X-Event"] = "e" * 256
    assert ingest.handle(headers, body).status == 202
    nudge = queue.items[0]
    assert nudge.body_omitted is False
    wire = serialise_nudge(nudge)
    assert len(wire.encode()) <= NUDGE_BUDGET_BYTES < SQS_MESSAGE_LIMIT


@pytest.mark.parametrize("char", ["\u4e2d", "\U0001f600"], ids=["cjk", "emoji"])
def test_a_multibyte_body_is_sized_by_its_wire_form_and_fits(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock, char: str
) -> None:
    ingest = make(store, queue, metrics, clock)
    width = len(char.encode())
    body = (char * (DEFAULT_MAX_BODY_BYTES // width)).encode()
    assert len(body) <= DEFAULT_MAX_BODY_BYTES
    headers, _ = delivery(body)
    assert ingest.handle(headers, body).status == 202
    wire = serialise_nudge(queue.items[0])
    assert wire.isascii()
    assert len(wire.encode()) < SQS_MESSAGE_LIMIT
    assert queue.items[0].body_omitted is False
    assert base64.b64decode(json.loads(wire)["body_b64"]) == body


def test_the_wire_form_is_base64_json_that_round_trips_the_body() -> None:
    n = Nudge("hub", "d-1", b"\x00\xff{}", {"a": "b"}, 1.5, event="push")
    wire = json.loads(serialise_nudge(n))
    assert base64.b64decode(wire["body_b64"]) == b"\x00\xff{}"
    assert wire["event"] == "push"
    assert wire["body_omitted"] is False
    assert wire["body_size"] == 4
    assert wire["reread"] is True


def test_the_body_is_omitted_when_its_wire_form_does_not_fit_the_budget(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock, monkeypatch: Any
) -> None:
    monkeypatch.setattr("sto.ingest.core.NUDGE_BUDGET_BYTES", 600)
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery(b"x" * 1000)
    assert ingest.handle(headers, body).status == 202
    assert queue.items[0].body_omitted is True
    assert queue.items[0].body_size == 1000


def test_oversized_headers_keep_only_the_routing_ones(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="x-event", routing_headers=["X-Route"])
    headers, body = delivery()
    headers.update({"X-Event": "push", "X-Route": "r", "Content-Type": "application/json"})
    headers["X-Pad"] = "p" * HEADER_BUDGET_BYTES
    assert ingest.handle(headers, body).status == 202
    nudge = queue.items[0]
    assert set(nudge.headers) == {"x-event", "x-route", "content-type"}
    assert nudge.event == "push"
    assert metrics.counts["webhook.headers_trimmed"] == 1


def test_routing_headers_that_do_not_fit_are_refused_as_malformed_and_claim_nothing(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="x-event")
    headers, body = delivery()
    headers["X-Event"] = "e" * (HEADER_BUDGET_BYTES + 1)
    response = ingest.handle(headers, body)
    assert response.status == 400
    assert queue.items == []
    assert seen_item(store) is None
    assert metrics.counts["webhook.rejected"] == 1
    assert ("webhook.rejected", {"surface": "hub", "reason": "headers_too_large"}) in metrics.tags


def test_headers_just_under_the_budget_are_all_kept(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    headers.update(maximal_headers())
    assert ingest.handle(headers, body).status == 202
    assert "x-pad-0" in queue.items[0].headers
    assert "webhook.headers_trimmed" not in metrics.counts


# --- the event header (review pass 1) ---------------------------------------------------------


@pytest.mark.parametrize("name", ["Authorization", "cookie", " Proxy-Authorization "])
def test_an_event_header_naming_a_credential_header_is_refused(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock, name: str
) -> None:
    with pytest.raises(ValueError, match="event_header"):
        make(store, queue, metrics, clock, event_header=name)


def test_an_event_header_naming_a_verifier_secret_header_is_refused(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    verifier = HmacVerifier()
    verifier.secret_headers = frozenset({"x-signature"})
    with pytest.raises(ValueError, match="event_header"):
        make(store, queue, metrics, clock, verifier=verifier, event_header="X-Signature")


def test_the_event_header_name_is_lowercased_and_stripped(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="  X-Event ")
    headers, body = delivery()
    headers["x-event"] = "push"
    ingest.handle(headers, body)
    assert queue.items[0].event == "push"


def test_an_empty_event_header_value_gives_none(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="x-event")
    headers, body = delivery()
    headers["X-Event"] = "  "
    ingest.handle(headers, body)
    assert queue.items[0].event is None


def test_an_overlong_event_is_dropped_to_none(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, event_header="x-event")
    headers, body = delivery()
    headers["X-Event"] = "e" * 257
    assert ingest.handle(headers, body).status == 202
    assert queue.items[0].event is None


def test_an_over_limit_delivery_whose_enqueue_fails_is_released_and_retried_to_one_nudge(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, max_body_bytes=10)
    headers, body = delivery(b"z" * 50)
    queue.fail = RuntimeError("sqs down")
    assert ingest.handle(headers, body).status == 503
    assert seen_item(store) is None
    assert "webhook.body_omitted" not in metrics.counts
    queue.fail = None
    assert ingest.handle(headers, body).status == 202
    assert len(queue.items) == 1
    assert queue.items[0].body_omitted is True
    assert metrics.counts["webhook.body_omitted"] == 1


def test_a_duplicate_is_dropped_with_a_200_and_a_metric(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    assert ingest.handle(headers, body).status == 202
    again = ingest.handle(headers, body)
    assert again.status == 200
    assert len(queue.items) == 1
    assert metrics.counts == {"webhook.accepted": 1, "webhook.duplicate": 1}


def test_the_same_id_with_a_different_signed_body_is_still_a_duplicate(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    """The port says a delivery ID outside the signature stops nobody, so the ID alone never
    lets a second body in: the nudge is dropped and the consumer re-reads state anyway."""
    ingest = make(store, queue, metrics, clock)
    ingest.handle(*delivery(b'{"n":1}', "d-1"))
    assert ingest.handle(*delivery(b'{"n":2}', "d-1")).status == 200
    assert len(queue.items) == 1


def test_different_ids_are_not_duplicates(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    ingest.handle(*delivery(delivery_id="d-1"))
    ingest.handle(*delivery(delivery_id="d-2"))
    assert [n.delivery_id for n in queue.items] == ["d-1", "d-2"]


def test_surfaces_do_not_share_dedupe_records(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    make(store, queue, metrics, clock, surface="a").handle(*delivery())
    assert make(store, queue, metrics, clock, surface="b").handle(*delivery()).status == 202
    assert len(queue.items) == 2


def test_a_rejected_delivery_does_not_burn_its_id(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    """An attacker who guesses a delivery ID must not be able to block the genuine one."""
    ingest = make(store, queue, metrics, clock)
    headers, body = delivery()
    bad = dict(headers, **{"X-Signature": "0" * 64})
    assert ingest.handle(bad, body).status == 401
    assert ingest.handle(headers, body).status == 202


# --- queue failure ----------------------------------------------------------------------------


def test_a_queue_failure_returns_an_error_so_the_vendor_retries(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    queue.fail = TransientError("sqs down")
    response = ingest.handle(*delivery())
    assert response.status == 503
    assert metrics.counts == {"webhook.enqueue_failed": 1}


def test_a_queue_failure_releases_the_dedupe_record_so_the_retry_is_not_dropped(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    queue.fail = TransientError("sqs down")
    assert ingest.handle(*delivery()).status == 503
    assert seen_item(store) is None
    queue.fail = None
    assert ingest.handle(*delivery()).status == 202
    assert len(queue.items) == 1


def test_any_queue_exception_is_a_503_not_a_crash(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock)
    queue.fail = OSError("connection reset")
    assert ingest.handle(*delivery()).status == 503
    assert seen_item(store) is None


def test_a_failed_release_still_answers_503_and_says_so(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class StuckStore(MemoryStore):
        def delete(self, *args: object, **kwargs: object) -> None:
            raise TransientError("cannot delete")

    stuck = StuckStore()
    ingest = make(stuck, queue, metrics, clock)
    queue.fail = TransientError("sqs down")
    assert ingest.handle(*delivery()).status == 503
    assert metrics.counts == {"webhook.enqueue_failed": 1, "webhook.release_failed": 1}


def test_a_store_failure_on_the_dedupe_write_returns_503_and_enqueues_nothing(
    queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class DownStore(MemoryStore):
        def transact(self, *args: object, **kwargs: object) -> None:
            raise TransientError("dynamo throttled")

        def put(self, *args: object, **kwargs: object) -> None:
            raise TransientError("dynamo throttled")

    ingest = make(DownStore(), queue, metrics, clock)
    assert ingest.handle(*delivery()).status == 503
    assert queue.items == []
    assert metrics.counts == {"webhook.store_failed": 1}


# --- TTL: only for vendors with a signed timestamp ---------------------------------------------


def test_no_signed_timestamp_means_the_dedupe_record_never_expires(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    make(store, queue, metrics, clock, verifier=HmacVerifier()).handle(*delivery())
    item = seen_item(store)
    assert item is not None
    assert "ttl" not in item.data


def test_a_signed_timestamp_vendor_gets_a_ttl_beyond_the_replay_window(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, verifier=HmacVerifier(replay_window=300.0))
    ingest.handle(*delivery())
    item = seen_item(store)
    assert item is not None
    assert item.data["ttl"] == int(clock.now + 2 * 300.0)


def test_the_ttl_comes_from_the_verifiers_own_window_and_rounds_up(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    clock.now = 1000.9
    make(store, queue, metrics, clock, verifier=HmacVerifier(replay_window=0.5)).handle(*delivery())
    item = seen_item(store)
    assert item is not None
    assert item.data["ttl"] == 1002  # ceil(1000.9 + 1.0); never below now + window


def test_a_verifier_that_says_signed_timestamp_without_a_window_is_refused() -> None:
    v = HmacVerifier(replay_window=300.0)
    v.replay_window = None
    with pytest.raises(ValueError, match="replay_window"):
        WebhookIngest("hub", v, MemoryStore(), Queue(), Metrics())


def test_a_window_on_a_verifier_without_a_signed_timestamp_is_refused() -> None:
    v = HmacVerifier()
    v.replay_window = 300.0
    with pytest.raises(ValueError, match="never expires"):
        WebhookIngest("hub", v, MemoryStore(), Queue(), Metrics())


def test_a_non_positive_window_is_refused() -> None:
    v = HmacVerifier(replay_window=300.0)
    v.replay_window = 0.0
    with pytest.raises(ValueError, match="positive"):
        WebhookIngest("hub", v, MemoryStore(), Queue(), Metrics())


def test_surface_must_be_a_plain_name() -> None:
    for bad in ("", "a#b", " a"):
        with pytest.raises(ValueError, match="surface"):
            WebhookIngest(bad, HmacVerifier(), MemoryStore(), Queue(), Metrics())


def test_a_delivery_id_with_a_hash_cannot_reach_another_surfaces_partition(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    """Surface ``a`` + id ``b#x`` must not collide with surface ``a#b`` + id ``x``."""
    ingest = make(store, queue, metrics, clock, surface="a")
    assert ingest.handle(*delivery(delivery_id="b#x")).status == 202
    other = make(store, queue, metrics, clock, surface="ab")
    assert other.handle(*delivery(delivery_id="x")).status == 202
    assert seen_item(store, "a", "b#x") is not None
    assert len(queue.items) == 2


# --- pass 1 fixes -------------------------------------------------------------------------------


class AppliedThenLost(MemoryStore):
    """The put lands, but the answer is lost."""

    def put(self, *args: object, **kwargs: object) -> None:
        super().put(*args, **kwargs)  # type: ignore[arg-type]
        raise TransactionOutcomeUnknownError("answer lost")


def test_an_unknown_outcome_on_the_claim_releases_it_so_the_retry_is_enqueued(
    queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    store = AppliedThenLost()
    ingest = make(store, queue, metrics, clock)
    assert ingest.handle(*delivery()).status == 503
    assert seen_item(store) is None
    assert metrics.counts == {"webhook.store_failed": 1}
    store_ok = MemoryStore()
    assert make(store_ok, queue, metrics, clock).handle(*delivery()).status == 202


class IdVerifier(HmacVerifier):
    def __init__(self, delivery_id: object) -> None:
        super().__init__()
        self.delivery_id = delivery_id

    def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
        return self.delivery_id  # type: ignore[return-value]


@pytest.mark.parametrize("bad", ["", "   ", None, 7, b"x", "x" * 513])
def test_an_unusable_delivery_id_is_rejected_and_claims_nothing(
    bad: object, store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    ingest = make(store, queue, metrics, clock, verifier=IdVerifier(bad))
    assert ingest.handle(*delivery()).status == 401
    assert metrics.tags == [("webhook.rejected", {"surface": "hub", "reason": "delivery_id"})]
    assert queue.items == []
    assert store.query(PLATFORM, "HOOK#hub#").items == ()


def test_a_transient_verifier_error_is_503_with_a_metric_and_claims_nothing(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class Flaky(HmacVerifier):
        def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
            raise TransientError("jwks fetch failed")

    ingest = make(store, queue, metrics, clock, verifier=Flaky())
    assert ingest.handle(*delivery()).status == 503
    assert metrics.counts == {"webhook.verify_failed": 1}
    assert queue.items == []


def test_the_nudge_carries_normalised_headers_without_credentials(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    verifier = HmacVerifier()
    verifier.secret_headers = frozenset({"x-vendor-token"})
    ingest = make(store, queue, metrics, clock, verifier=verifier)
    headers, body = delivery()
    headers.update(
        {
            "Authorization": "Bearer synthetic",
            "COOKIE": "s=synthetic",
            "Proxy-Authorization": "Basic synthetic",
            "X-Vendor-Token": "synthetic",
            "X-Event": "push",
        }
    )
    assert ingest.handle(headers, body).status == 202
    assert dict(queue.items[0].headers) == {
        SIG: sign(body),
        ID: "d-1",
        "x-event": "push",
    }


def test_the_dedupe_record_says_when_it_was_seen(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    make(store, queue, metrics, clock).handle(*delivery())
    item = seen_item(store)
    assert item is not None
    assert item.data == {"surface": "hub", "seen_at": clock.now}


def test_a_verifier_bug_is_counted_before_it_escapes(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    class Buggy(HmacVerifier):
        def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
            raise KeyError("x-signature")

    ingest = make(store, queue, metrics, clock, verifier=Buggy())
    with pytest.raises(KeyError):
        ingest.handle(*delivery())
    assert metrics.counts == {"webhook.verify_error": 1}


def test_a_non_string_header_value_is_a_counted_401_not_a_crash(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    headers, body = delivery()
    headers["X-Extra"] = None  # type: ignore[assignment]
    ingest = make(store, queue, metrics, clock)
    assert ingest.handle(headers, body).status == 401
    assert metrics.tags == [("webhook.rejected", {"surface": "hub", "reason": "headers"})]


def test_a_header_conflict_is_counted_as_headers_not_signature(
    store: MemoryStore, queue: Queue, metrics: Metrics, clock: Clock
) -> None:
    headers, body = delivery()
    headers["x-signature"] = "other"
    make(store, queue, metrics, clock).handle(headers, body)
    assert metrics.tags == [("webhook.rejected", {"surface": "hub", "reason": "headers"})]
