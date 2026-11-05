"""D4-03: generic webhook ingest. Verify on the raw body, dedupe, enqueue, answer in time.

Everything runs on the in-memory store with a fake clock, queue and metrics sink. Secrets and
signatures here are synthetic.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

import pytest

from sto.domain.errors import PermanentError, TransientError
from sto.ingest.core import (
    InvalidSignatureError,
    Nudge,
    WebhookIngest,
    WebhookVerifier,
    normalise_headers,
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
) -> WebhookIngest:
    return WebhookIngest(
        surface=surface,
        verifier=verifier or HmacVerifier(),
        store=store,
        queue=queue,
        metrics=metrics,
        clock=clock,
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
