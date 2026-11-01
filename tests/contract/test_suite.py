"""D4-01: the conformance suite, proved against a reference adapter, known-bad adapters, and the
merged fakes. See ``suite.py`` for how an adapter reuses it.

The reference is split in two, as a real adapter is: a small stub **server** that holds the truth
(stored comments, pages, signature secret, clock, 429/401/5xx/timeouts) and an **adapter** with
the production logic (verifier, dedupe, look-up-first, error mapping). The harness
(``StubTarget``) only forwards. Each ``Bad*`` adapter breaks exactly one rule over the same server,
and ``test_known_bad_adapters_fail_the_suite`` pins which tests must catch it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import types
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any, ClassVar

import pytest

pytest.register_assert_rewrite("suite")
from suite import (  # noqa: E402
    SECURITY_CONTROLS,
    SUBCLASSES,
    AdapterConformance,
    Control,
    CrashPoint,
    MissingControl,
    Outcome,
    RateShape,
    Target,
    check_not_simulated,
    needs,
    pending_controls,
    resolve,
    run_suite,
    uncollected,
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
    RawWebhook,
    RepoRef,
    Ticket,
    TicketRef,
    UnknownRefError,
)
from sto.domain.errors import PermanentError, TransientError  # noqa: E402
from sto.domain.models import DecisionKind, Receipt  # noqa: E402

# --- the stub server: it holds the truth ----------------------------------------------------

PAGE = 30
SECRET = b"synthetic-secret"
TOKEN = "good"
PRINCIPAL = "sto-bot"
WINDOW = 300.0
TREF = TicketRef("fake", "T-1")


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
    """A vendor-like server: paged newest-first comments, a 429/403/401/5xx/timeout menu, a clock
    and a signing secret. Shape ``decision`` makes its webhooks carry a Slack-like action."""

    def __init__(self, shape: str = "ticket") -> None:
        self.shape = shape
        self.now = 1_000.0
        self.comments: list[Comment] = []
        self.revision = 0
        self.counts: Counter[str] = Counter()
        self.faults: defaultdict[str, list[str]] = defaultdict(list)
        self.limited = 0
        self.limit_shape = RateShape.PRIMARY_429
        self.auth_ok = True
        self.swallow = 0
        self._seq = 0

    def add(self, author: str, body: str) -> Comment:
        self._seq += 1
        comment = Comment(f"c-{self._seq}", author, body)
        self.comments.append(comment)
        return comment

    def handle(self, op: str, token: str, **kw: Any) -> Response:
        self.counts[op] += 1
        if token != TOKEN or not self.auth_ok:
            self.counts["unauthorized"] += 1
            return Response(401, {}, {"message": "Bad credentials"})
        if self.limited > 0:
            self.limited -= 1
            self.counts["limited"] += 1
            if self.limit_shape is RateShape.PRIMARY_429:
                return Response(429, {"retry-after": "30"}, {})
            msg = {"message": "You have exceeded a secondary rate limit"}
            return Response(403, {"retry-after": "30"}, msg)
        fault = self.faults[op].pop(0) if self.faults[op] else ""
        if fault == "5xx":
            return Response(503, {}, {})
        if op == "lookup":
            page = int(kw["page"])
            newest_first = list(reversed(self.comments))
            chunk = newest_first[page * PAGE : (page + 1) * PAGE]
            more = len(newest_first) > (page + 1) * PAGE
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
    def delivery(self, revision: int, delivery_id: str, secret: bytes) -> RawWebhook:
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
        body = json.dumps({**payload, "revision": revision}).encode()
        ts = str(self.now)
        mac = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        headers = {"X-Delivery": delivery_id, "X-Timestamp": ts, "X-Signature": f"sha256={mac}"}
        return RawWebhook(headers, body)


# --- the adapter: production logic, the thing under test -----------------------------------


class RateLimited(TransientError):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"rate limited; retry after {retry_after}s")
        self.retry_after = retry_after


class HmacVerifier:
    """Raw-body HMAC over ``timestamp.body``, a replay window, and a required delivery ID."""

    def __init__(self, secret: bytes, clock: Callable[[], float], window: float) -> None:
        self.secret, self.clock, self.window = secret, clock, window

    def _signed_over(self, headers: Mapping[str, str], raw_body: bytes) -> bytes:
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
        return self._checked(headers)

    def _checked(self, headers: Mapping[str, str]) -> str:
        try:
            age = abs(self.clock() - float(headers.get("X-Timestamp", "")))
        except ValueError:
            raise PermanentError("401 bad timestamp") from None
        if age > self.window:
            raise PermanentError("401 outside the replay window")
        delivery_id = headers.get("X-Delivery", "")
        if not delivery_id:
            raise PermanentError("400 no delivery id")
        return delivery_id


class Adapter:
    token = TOKEN
    window = WINDOW
    simulated = True

    def __init__(self, server: Stub) -> None:
        self.server = server
        self.verifier = self._verifier()
        self.queue: list[Any] = []
        self._seen: set[str] = set()

    def _verifier(self) -> HmacVerifier:
        return HmacVerifier(SECRET, lambda: self.server.now, self.window)

    # --- writes: look up first (PLAN 6.3), then post, then read back ---
    @staticmethod
    def marker(key: str, variant: str) -> str:
        return f"<!-- sto:{key}:{hashlib.sha256(variant.encode()).hexdigest()[:8]} -->"

    def _call(self, op: str, **kw: Any) -> Any:
        try:
            response = self.server.handle(op, self.token, **kw)
        except TimeoutError as exc:
            raise TransientError(f"{op} timed out") from exc
        return self._unwrap(response)

    def _unwrap(self, response: Response) -> Any:
        if response.status in (200, 201):
            return response.body
        limited = response.status == 429 or (
            response.status == 403 and "retry-after" in response.headers
        )
        if limited:
            raise RateLimited(float(response.headers["retry-after"]))
        if response.status == 401:
            raise PermanentError("401 bad credentials")
        if response.status >= 500:
            raise TransientError(f"{response.status} from the server")
        raise PermanentError(f"{response.status} from the server")

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
        verified = self._find(key) is not None  # read back: it is really there
        return Receipt(posted["id"], "", verified, simulated=self.simulated)

    # --- webhooks ---
    def receive(self, raw: RawWebhook) -> Any:
        """Verify on the raw body, then dedupe, then enqueue. ``None``: dropped as a duplicate."""
        delivery_id = self.verifier.verify(raw.headers, raw.body)
        if delivery_id in self._seen:
            return None
        self._seen.add(delivery_id)
        result = self._parse(raw)
        self.queue.append(result)
        return result

    def _parse(self, raw: RawWebhook) -> Any:
        key = json.loads(raw.body)["changes"][0]["ticket"]
        return [ExternalChange(ChangeKind.TICKET, ticket=TicketRef("fake", key))]

    def read_revision(self) -> int:
        return int(self._call("read")["revision"])


class DecisionAdapter(Adapter):
    """A Notifier-shaped adapter: a delivery is a ``DecisionRequest``, not a list of nudges."""

    def _parse(self, raw: RawWebhook) -> Any:
        d = json.loads(raw.body)["decision"]
        return DecisionRequest(
            d["gate_id"], DecisionKind(d["kind"]), d["actor"], d["subject_digest"]
        )


# --- the harness: a thin pass-through ---------------------------------------------------------


class StubTarget(Target):
    name = "stub"
    controls = frozenset(Control)
    signature_header = "X-Signature"
    replay_window = WINDOW
    retry_after_hint = 30.0

    def __init__(self, adapter_cls: type[Adapter] = Adapter, shape: str = "ticket") -> None:
        self.server = Stub(shape)
        self.adapter_cls = adapter_cls
        self.adapter = adapter_cls(self.server)
        self.verifier = self.adapter.verifier
        self.watched = "G-1" if shape == "decision" else TREF.key

    def restart(self) -> None:
        self.adapter = self.adapter_cls(self.server)
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
        return len(self.adapter.queue)

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

    def crash(self, point: CrashPoint) -> None:
        mode = {
            CrashPoint.LOOKUP_FAILS: ("lookup", "5xx"),
            CrashPoint.REJECTED_BEFORE_APPLY: ("write", "5xx"),
            CrashPoint.RESPONSE_LOST_AFTER_APPLY: ("write", "lose"),
        }[point]
        self.server.faults[mode[0]].append(mode[1])

    def seed_others(self, n: int) -> None:
        for i in range(n):
            self.server.add("alice", f"unrelated {i}")

    def plant_foreign_marker(self, key: str) -> None:
        self.server.add("mallory", self.adapter.marker(key, "a") + " planted")

    def swallow_next_write(self) -> None:
        self.server.swallow += 1

    def rate_limit_next(self, times: int, shape: RateShape) -> None:
        self.server.limited, self.server.limit_shape = times, shape

    def revoke_auth(self) -> None:
        self.server.auth_ok = False

    def restore_auth(self) -> None:
        self.server.auth_ok = True

    def emit(self, revision: int, delivery_id: str) -> RawWebhook:
        self.server.revision = revision
        return self.server.delivery(revision, delivery_id, SECRET)

    def forge(self, revision: int, delivery_id: str) -> RawWebhook:
        return self.server.delivery(revision, delivery_id, b"not-the-secret")

    def advance_clock(self, seconds: float) -> None:
        self.server.now += seconds


def reference() -> Target:
    return StubTarget()


def decision_shaped() -> Target:
    return StubTarget(DecisionAdapter, "decision")


class TestReferenceAdapter(AdapterConformance):
    """The reference adapter passes every section, observed at the stub server."""

    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": reference}


class TestDecisionShapedAdapter(AdapterConformance):
    """A delivery that is a ``DecisionRequest | None`` (the Notifier port) maps to an Outcome."""

    registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": decision_shaped}


# --- known-bad adapters: each breaks one rule, and the suite must fail it ---------------------


class BadNoSignatureCheck(Adapter):
    def _verifier(self) -> HmacVerifier:
        class Trusting(HmacVerifier):
            def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
                return self._checked(headers)

        return Trusting(SECRET, lambda: self.server.now, self.window)


class BadParsedBodySignature(Adapter):
    def _verifier(self) -> HmacVerifier:
        class Parsing(HmacVerifier):
            def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
                return super().verify(headers, json.dumps(json.loads(raw_body)).encode())

        return Parsing(SECRET, lambda: self.server.now, self.window)


class BadAcceptsMissingSignature(Adapter):
    """Unsigned is fine, but a missing delivery ID is refused: stripping all headers hides it."""

    def _verifier(self) -> HmacVerifier:
        class Lax(HmacVerifier):
            def verify(self, headers: Mapping[str, str], raw_body: bytes) -> str:
                if "X-Signature" not in headers:
                    return self._checked(headers)
                return super().verify(headers, raw_body)

        return Lax(SECRET, lambda: self.server.now, self.window)


class BadBurnsIdOfForgery(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        try:
            return super().receive(raw)
        except PermanentError:
            self._seen.add(raw.headers.get("X-Delivery", ""))
            raise


class BadDuplicateBeforeVerify(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        if raw.headers.get("X-Delivery") in self._seen:
            return None  # a forgery with a seen ID is answered "duplicate"
        return super().receive(raw)


class BadForgeryWipesDedupe(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        try:
            return super().receive(raw)
        except PermanentError:
            self._seen.clear()
            raise


class BadNoDedupe(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        self._seen.clear()
        return super().receive(raw)


class BadDedupeByContent(Adapter):
    def receive(self, raw: RawWebhook) -> Any:
        self.verifier.verify(raw.headers, raw.body)
        seen_key = hashlib.sha256(raw.body).hexdigest()
        if seen_key in self._seen:
            return None
        self._seen.add(seen_key)
        result = self._parse(raw)
        self.queue.append(result)
        return result


class BadNoReplayWindow(Adapter):
    window = math.inf


class BadCachesDeliveryState(Adapter):
    """Treats the delivery body as the truth: its idea of the revision is the last one delivered."""

    cached: int | None = None

    def receive(self, raw: RawWebhook) -> Any:
        result = super().receive(raw)
        self.cached = json.loads(raw.body)["revision"]
        return result

    def read_revision(self) -> int:
        return self.cached if self.cached is not None else super().read_revision()


class BadInProcessKeys(Adapter):
    """Idempotency by a dict in this process: gone after a restart, and never looks up."""

    def __init__(self, server: Stub) -> None:
        super().__init__(server)
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


class BadFirstPageLookup(Adapter):
    def _find(self, key: str) -> dict[str, str] | None:
        for comment in self._call("lookup", page=0)["items"]:
            if self._mine(comment, key):
                return comment  # type: ignore[no-any-return]
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


class BadAlwaysVerified(Adapter):
    def write(self, key: str, variant: str = "a") -> Receipt:
        return replace(super().write(key, variant), read_back_verified=True)


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
        if response.status in (403, 429):
            raise PermanentError("rate limited")
        return super()._unwrap(response)


class BadAnyForbiddenIsPermanent(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 403:
            raise PermanentError("forbidden")
        return super()._unwrap(response)


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


class BadAuthIsTransient(Adapter):
    def _unwrap(self, response: Response) -> Any:
        if response.status == 401:
            raise TransientError("try again")
        return super()._unwrap(response)


KNOWN_BAD: list[tuple[type[Adapter], set[str]]] = [
    (BadNoSignatureCheck, {"test_t6_forged_signature_is_rejected_and_enqueues_nothing"}),
    (BadParsedBodySignature, {"test_t6_signature_is_checked_on_the_raw_body_not_the_parsed_one"}),
    (
        BadAcceptsMissingSignature,
        {"test_t6_a_delivery_with_only_the_signature_removed_is_rejected"},
    ),
    (BadBurnsIdOfForgery, {"test_t6_a_rejected_delivery_does_not_use_up_its_delivery_id"}),
    (
        BadDuplicateBeforeVerify,
        {"test_t6_a_forged_delivery_with_a_seen_id_is_rejected_not_dropped"},
    ),
    (BadForgeryWipesDedupe, {"test_t6_a_forged_delivery_does_not_wipe_the_dedupe_memory"}),
    (BadNoDedupe, {"test_redelivery_of_the_same_delivery_id_is_dropped"}),
    (BadDedupeByContent, {"test_a_new_delivery_id_is_not_a_duplicate"}),
    (BadNoReplayWindow, {"test_t6_a_genuine_delivery_outside_the_replay_window_is_rejected"}),
    (
        BadCachesDeliveryState,
        {
            "test_delivery_order_does_not_change_what_the_adapter_reports",
            "test_after_a_delivery_state_is_re_read_from_the_server",
        },
    ),
    (
        BadInProcessKeys,
        {"test_crash_after_the_write_applied_then_a_restart_does_not_write_again"},
    ),
    (BadAssumesApplied, {"test_crash_when_the_post_is_rejected_then_a_restart_writes_once"}),
    (BadFirstPageLookup, {"test_lookup_reads_past_the_first_page"}),
    (BadLookupErrorIsNotFound, {"test_a_server_error_on_lookup_is_not_taken_for_not_found"}),
    (BadLookupErrorWritesAnyway, {"test_a_server_error_on_lookup_is_not_taken_for_not_found"}),
    (BadTrustsAnyAuthor, {"test_a_marker_planted_by_another_author_is_not_trusted"}),
    (BadAlwaysVerified, {"test_a_write_accepted_but_not_applied_is_never_reported_verified"}),
    (BadHammersOn429, {"test_a_429_is_transient_applies_nothing_and_is_not_hammered"}),
    (BadLimitIsPermanent, {"test_a_429_is_transient_applies_nothing_and_is_not_hammered"}),
    (
        BadAnyForbiddenIsPermanent,
        {"test_githubs_403_secondary_limit_is_transient_not_a_permission_error"},
    ),
    (BadRetriesAuth, {"test_a_401_is_permanent_applies_nothing_and_is_asked_once"}),
    (BadAuthIsNotFound, {"test_a_401_is_permanent_applies_nothing_and_is_asked_once"}),
    (BadAuthIsTransient, {"test_a_401_is_permanent_applies_nothing_and_is_asked_once"}),
]


def test_the_reference_adapter_passes_every_test() -> None:
    failed = {n: e for n, e in run_suite(reference).items() if e is not None}
    assert failed == {}


@pytest.mark.parametrize(("bad", "must_fail"), KNOWN_BAD, ids=[b.__name__ for b, _ in KNOWN_BAD])
def test_known_bad_adapters_fail_the_suite(bad: type[Adapter], must_fail: set[str]) -> None:
    failed = {n for n, e in run_suite(lambda: StubTarget(bad)).items() if e is not None}
    assert must_fail <= failed, f"{bad.__name__} slipped past {sorted(must_fail - failed)}"


def test_every_known_bad_adapter_is_in_the_table() -> None:
    bad = {c for c in globals().values() if isinstance(c, type) and c.__name__.startswith("Bad")}
    assert bad == {b for b, _ in KNOWN_BAD}


def test_a_bad_adapter_with_no_controls_is_a_failure_not_a_pass() -> None:
    class Bare(Target):
        name = "bare"

    failures = run_suite(Bare)
    assert failures
    assert all(isinstance(e, MissingControl) for e in failures.values())


# --- live: nothing may be waived, simulated receipts fail, typos fail ------------------------


def test_a_live_run_fails_on_a_simulated_receipt() -> None:
    target = reference()
    target.selected = "live"
    with pytest.raises(pytest.fail.Exception, match="simulated"):
        check_not_simulated(target, Receipt("x", "", True, simulated=True))
    check_not_simulated(target, Receipt("x", "", True, simulated=False))


def test_a_live_selected_fake_backed_target_fails_the_write_tests() -> None:
    def live_but_fake() -> Target:
        t = reference()
        t.selected = "live"
        return t

    failed = {n for n, e in run_suite(live_but_fake).items() if e is not None}
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


def test_live_that_is_not_registered_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "live")
    with pytest.raises(pytest.UsageError):
        resolve({"fake": reference})


def test_select_reports_which_target_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "live")
    name, target = resolve({"fake": reference, "live": reference})
    assert (name, target.selected) == ("live", "live")


def test_the_fixture_records_the_target_that_ran(request: pytest.FixtureRequest) -> None:
    # the property is appended by the inherited fixture on every conformance test
    probe = types.SimpleNamespace(user_properties=[])
    fake_request = types.SimpleNamespace(node=probe)
    fixture = AdapterConformance.target.__wrapped__  # type: ignore[attr-defined]
    holder = types.SimpleNamespace(registry={"fake": reference})
    fixture(holder, fake_request)
    assert probe.user_properties == [("conformance_target", "fake")]


# --- pending_controls: pinned mechanism ---------------------------------------------------


def _marked() -> type[Any]:
    @pending_controls(Control.RATE_LIMIT, Control.AUTH, reason="the fake has no 429 yet")
    class Probe:
        @needs(Control.AUTH)
        def test_a(self) -> None: ...

        @needs(Control.RATE_LIMIT)
        def test_b(self) -> None: ...

        @needs(Control.READ_BACK)
        def test_c(self) -> None: ...

    return Probe


def test_pending_controls_marks_strict_xfail_on_missing_control_only() -> None:
    probe = _marked()
    for name in ("test_a", "test_b"):
        marks = [m for m in probe.__dict__[name].pytestmark if m.name == "xfail"]
        assert len(marks) == 1, "must be an xfail, not a skip"
        assert marks[0].kwargs["strict"] is True
        assert marks[0].kwargs["raises"] is MissingControl
        assert marks[0].kwargs["reason"] == "the fake has no 429 yet"
        assert not [m for m in probe.__dict__[name].pytestmark if m.name == "skip"]
    assert not hasattr(probe.__dict__["test_c"], "pytestmark")


def test_pending_controls_does_not_mark_the_shared_base_tests() -> None:
    _marked()
    assert not hasattr(
        AdapterConformance.test_a_401_is_permanent_applies_nothing_and_is_asked_once, "pytestmark"
    )


@pytest.mark.parametrize("control", sorted(SECURITY_CONTROLS))
def test_pending_controls_refuses_every_security_control(control: Control) -> None:
    with pytest.raises(ValueError, match="security"):
        pending_controls(control, reason="because")


def test_pending_controls_refuses_a_class_with_every_control() -> None:
    with pytest.raises(ValueError, match="security"):
        pending_controls(*Control, reason="all of them")


@pytest.mark.parametrize("reason", ["", "   "])
def test_pending_controls_needs_a_reason(reason: str) -> None:
    with pytest.raises(ValueError, match="reason"):
        pending_controls(Control.AUTH, reason=reason)


def test_pending_controls_is_refused_under_a_live_run(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = _marked()
    monkeypatch.setenv("STO_CONFORMANCE_TARGET", "live")
    with pytest.raises(pytest.fail.Exception, match="live"):
        probe().test_a()


def test_a_missing_control_fails_rather_than_skips() -> None:
    with pytest.raises(MissingControl, match="rate_limit"):
        Target().require(Control.RATE_LIMIT)


# --- reuse checks ---------------------------------------------------------------------------


def test_a_conformance_subclass_must_be_named_test() -> None:
    with pytest.raises(TypeError, match="Test"):

        class Conformance(AdapterConformance):
            registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": reference}


def test_a_conformance_subclass_must_set_a_registry() -> None:
    with pytest.raises(TypeError, match="registry"):

        class TestNoRegistry(AdapterConformance):
            pass


def test_uncollected_finds_a_subclass_with_no_tests() -> None:
    class TestOrphan(AdapterConformance):
        registry: ClassVar[Mapping[str, Callable[[], Target]]] = {"fake": reference}

    try:
        assert uncollected([TestOrphan], []) == [f"{__name__}.TestOrphan"]
        assert uncollected([TestOrphan], [types.SimpleNamespace(cls=TestOrphan)]) == []
    finally:
        SUBCLASSES.remove(TestOrphan)


def test_every_conformance_subclass_in_this_session_collected_tests(
    request: pytest.FixtureRequest,
) -> None:
    config = request.config
    if config.getoption("keyword") or config.getoption("markexpr"):
        return  # a filtered run legitimately collects a subset
    if any("::" in str(arg) for arg in config.args):
        return
    assert uncollected(SUBCLASSES, request.session.items) == []


# --- the merged fakes (D1-04) -----------------------------------------------------------------
# They are not run through the full suite: they verify no signatures, dedupe nothing, limit no
# rate, fail no auth, and keep their idempotency ledger in the object, so a restart is not
# possible. Waiving those security controls is refused (`pending_controls`), so what they CAN be
# held to is below, and the rest is a finding in the PR body.

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
