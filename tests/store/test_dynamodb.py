"""The DynamoDB store (D3-09): the shared contract suite on moto, plus what a real table does that
an in-memory one does not.

Everything here is hermetic: moto patches botocore in-process, so there is no socket and no Docker.
``DynamoServerTests`` holds the checks that need a server's behaviour (limits, paging, reserved
words, tenancy in the key). It runs on moto here and on DynamoDB Local in CI's integration job
(``tests/integration/test_dynamodb_local.py``). The fault-injection tests (throttling, per-item
cancellation reasons) use a wrapper around the client and only run on moto.
"""

from __future__ import annotations

import contextlib
import io
import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    HTTPClientError,
    ProxyConnectionError,
    ReadTimeoutError,
    SSLError,
)
from moto import mock_aws
from store_contract import StoreContract, race_claims

from sto.domain.errors import PermanentError
from sto.store import dynamodb
from sto.store.dynamodb import DynamoDbStore, create_tables, estimate_item_bytes
from sto.store.ports import (
    AUDIT,
    PLATFORM,
    TEAM_ROOT,
    Absent,
    Check,
    ConditionFailedError,
    Delete,
    FieldEquals,
    Key,
    Put,
    TeamScope,
    TransactionConflictError,
    TransactionOutcomeUnknownError,
    VersionIs,
)

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

A = TeamScope("team-a")
B = TeamScope("team-b")
RUN = Key("RUN#1", "META")
MAIN_TABLE = "sto-main"
AUDIT_TABLE = "sto-audit"
NO_RETRY = Config(retries={"total_max_attempts": 1, "mode": "standard"})


def client_error(
    code: str, message: str = "boom", reasons: list[dict[str, str]] | None = None
) -> Any:
    response: dict[str, Any] = {"Error": {"Code": code, "Message": message}}
    if reasons is not None:
        response["CancellationReasons"] = reasons
    return ClientError(response, "Op")  # type: ignore[arg-type]


@dataclass
class AfterCall:
    """Scripted fault: the call reaches the server and is applied, then the answer is lost."""

    error: BaseException


class EmptyPageWithNextKey:
    """Scripted response: the first Query page is empty yet has a LastEvaluatedKey (which DynamoDB
    may do when a filter or the 1 MB cap leaves nothing in a page)."""


class SpyClient:
    """Wraps a boto3 client: records every call, can raise scripted errors, and can cut query
    pages short the way DynamoDB does at 1 MB. Anything else passes straight through."""

    def __init__(self, inner: Any, *, serialize: bool = True) -> None:
        self.inner = inner
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.script: dict[str, list[Any]] = {}
        self.page_cap: int | None = None
        # moto's backend is not thread-safe, so two simultaneous transactions can both pass the
        # same condition. DynamoDB serializes them. This lock stands in for that, so the race tests
        # here check the store's conditions; DynamoDB Local in CI proves the real thing, so the
        # lock is off there (``serialize=False``) and concurrent calls reach the engine.
        self._serial: Any = threading.Lock() if serialize else contextlib.nullcontext()

    def named(self, name: str) -> list[dict[str, Any]]:
        return [kw for n, kw in self.calls if n == name]

    def fail(self, method: str, *errors: Any) -> None:
        self.script[method] = list(errors)

    def __getattr__(self, name: str) -> Any:
        target = getattr(self.inner, name)
        if not callable(target):
            return target

        def call(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            queue = self.script.get(name)
            scripted = queue.pop(0) if queue else None
            if isinstance(scripted, BaseException):
                raise scripted
            if scripted is EmptyPageWithNextKey:
                start = kwargs["ExpressionAttributeValues"][":pk"]
                return {"Items": [], "LastEvaluatedKey": {"pk": start, "sk": {"S": ""}}}
            with self._serial:
                response = target(**kwargs)
            if isinstance(scripted, AfterCall):
                raise scripted.error
            if name == "query" and self.page_cap and len(response["Items"]) > self.page_cap:
                response["Items"] = response["Items"][: self.page_cap]
                response["LastEvaluatedKey"] = {k: response["Items"][-1][k] for k in ("pk", "sk")}
            return response

        return call


@dataclass
class Env:
    client: SpyClient
    store: DynamoDbStore
    main: str = MAIN_TABLE
    audit: str = AUDIT_TABLE

    def raw_items(self, table: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        token: dict[str, Any] = {}
        while True:
            page = self.client.inner.scan(
                TableName=table or self.main, ConsistentRead=True, **token
            )
            out += page["Items"]
            if "LastEvaluatedKey" not in page:
                return out
            token = {"ExclusiveStartKey": page["LastEvaluatedKey"]}


@pytest.fixture
def env() -> Iterator[Env]:
    with mock_aws():
        inner = boto3.client(
            "dynamodb",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            config=NO_RETRY,
        )
        create_tables(inner, main_table=MAIN_TABLE, audit_table=AUDIT_TABLE)
        spy = SpyClient(inner)
        yield Env(
            spy,
            DynamoDbStore(
                cast("DynamoDBClient", spy), main_table=MAIN_TABLE, audit_table=AUDIT_TABLE
            ),
        )


# --- what a real table does that an in-memory one does not -------------------------------------


class DynamoServerTests:
    """Needs an ``env`` fixture. Runs on moto here and on DynamoDB Local in CI."""

    def test_a_transaction_is_bounded_to_100_items_before_anything_is_sent(self, env: Env) -> None:
        ops = [Put(Key("RUN#1", f"S#{i:03}"), {"i": i}) for i in range(101)]
        with pytest.raises(ValueError, match="at most 100"):
            env.store.transact(A, ops)
        assert env.client.named("transact_write_items") == []  # refused here, not by the server
        env.store.transact(A, ops[:100])
        (sent,) = env.client.named("transact_write_items")
        assert len(sent["TransactItems"]) == 100  # exactly the server's cap goes through
        assert len(env.store.query(A, "RUN#1").items) == 100

    def test_the_servers_own_cap_is_the_one_the_store_enforces(self, env: Env) -> None:
        too_many = [
            {"Put": {"TableName": env.main, "Item": {"pk": {"S": "x"}, "sk": {"S": str(i)}}}}
            for i in range(101)
        ]
        with pytest.raises(ClientError, match="100"):
            env.client.inner.transact_write_items(TransactItems=too_many)
        assert dynamodb.MAX_TRANSACTION_OPS == 100

    def test_one_item_gets_one_operation_per_transaction(self, env: Env) -> None:
        env.store.put(A, RUN, {"n": 0})
        sent_before = len(env.client.named("transact_write_items"))
        pairs: list[list[Any]] = [
            [Put(RUN, {"n": 1}), Check(RUN, FieldEquals("n", 0))],
            [Delete(RUN), Put(RUN, {"n": 2})],
            [Check(RUN, FieldEquals("n", 0)), Delete(RUN)],
        ]
        for ops in pairs:
            with pytest.raises(ValueError, match="more than once"):
                env.store.transact(A, ops)
        assert len(env.client.named("transact_write_items")) == sent_before  # nothing was sent
        # The same key in two partitions is two items, so that is allowed.
        org = Key("ORG", "META")
        env.store.transact(A, [Put(org, {"n": 1}), Put(org, {"n": 1}, scope=PLATFORM)])

    def test_an_item_the_server_would_size_over_400kb_is_refused_without_writing(
        self, env: Env
    ) -> None:
        # About 300 KB of JSON ("0," each), but DynamoDB charges a number and a list slot each.
        fat = {"n": [0] * 150_000}
        assert len(json.dumps(fat, separators=(",", ":"))) < 400 * 1024
        assert estimate_item_bytes(fat) > 400 * 1024
        with pytest.raises(ValueError, match="item is"):
            env.store.put(A, RUN, fat)
        with pytest.raises(ValueError, match="item is"):
            env.store.transact(A, [Put(Key("OK", "1"), {"a": 1}), Put(RUN, fat)])
        assert env.client.named("transact_write_items") == []
        assert env.store.get(A, Key("OK", "1")) is None
        env.store.put(A, RUN, {"blob": "x" * (390 * 1024)})  # large but under the limit

    def test_a_transaction_the_server_would_size_over_4mb_is_refused(self, env: Env) -> None:
        blob = {"blob": "x" * (390 * 1024)}
        with pytest.raises(ValueError, match="transaction is"):
            env.store.transact(A, [Put(Key("BLOB", f"S#{i}"), blob) for i in range(11)])
        assert env.client.named("transact_write_items") == []

    def test_a_transaction_json_counts_under_4mb_but_dynamodb_counts_over_is_refused(
        self, env: Env
    ) -> None:
        item = {"n": [0] * 125_000}  # 250 KB of JSON, about 375 KB to DynamoDB
        ops = [Put(Key("FAT", f"S#{i}"), item) for i in range(12)]
        assert sum(o.size for o in ops) < 4 * 1024 * 1024 < 12 * estimate_item_bytes(item)
        with pytest.raises(ValueError, match="transaction is"):
            env.store.transact(A, ops)
        assert env.client.named("transact_write_items") == []

    def test_query_follows_the_servers_one_megabyte_pages(self, env: Env) -> None:
        payload = "x" * (100 * 1024)
        for i in range(14):  # 1.4 MB in one partition: one Query call cannot return it all
            env.store.put(A, Key("BIG", f"I#{i:02}"), {"i": i, "pad": payload})
        everything = env.store.query(A, "BIG")
        assert [i.data["i"] for i in everything.items] == list(range(14))
        assert everything.cursor is None
        assert len(env.client.named("query")) >= 2  # the first page ended at the 1 MB cap
        paged: list[int] = []
        cursor = None
        for _ in range(20):
            page = env.store.query(A, "BIG", limit=5, cursor=cursor)
            assert len(page.items) <= 5
            paged += [i.data["i"] for i in page.items]
            cursor = page.cursor
            if cursor is None:
                break
        assert paged == list(range(14))
        full = env.store.query(A, "BIG", limit=13)  # a limit above what one page holds
        assert len(full.items) == 13
        assert full.cursor is not None
        assert env.store.query(A, "BIG", limit=14).cursor is None  # exact fit: no phantom page

    def test_data_named_like_reserved_words_and_key_attributes_is_safe(self, env: Env) -> None:
        names = ["status", "name", "data", "value", "ttl", "type", "timestamp", "ORDER", "a.b",
                 "a-b", "a b", "#x", ":v", "pk", "sk", "v", "d", "0", "$"]  # fmt: skip
        data = {n: f"val-{n}" for n in names}
        env.store.put(A, RUN, data, when=Absent())
        got = env.store.get(A, RUN)
        assert got is not None
        assert (got.data, got.version) == (data, 1)
        for n in names:
            env.store.transact(
                A, [Check(RUN, FieldEquals(n, f"val-{n}")), Put(Key("W", n), {"ok": True})]
            )
            with pytest.raises(ConditionFailedError):
                env.store.transact(A, [Check(RUN, FieldEquals(n, "wrong"))])
        env.store.put(A, RUN, {"status": "closed"}, when=FieldEquals("status", "val-status"))
        env.store.put(A, RUN, {"pk": "evil", "sk": "evil", "v": 99}, when=VersionIs(2))
        again = env.store.get(A, RUN)
        assert again is not None
        assert (again.data, again.version) == ({"pk": "evil", "sk": "evil", "v": 99}, 3)

    def test_empty_strings_are_stored_and_matched(self, env: Env) -> None:
        data = {"a": "", "b": [""], "c": {"k": ""}, "d": ["", {"e": ""}]}
        env.store.put(A, RUN, data)
        got = env.store.get(A, RUN)
        assert got is not None
        assert got.data == data
        env.store.put(A, RUN, {"a": "", "z": 1}, when=FieldEquals("a", ""))
        with pytest.raises(ConditionFailedError):
            env.store.put(A, RUN, {"a": "x"}, when=FieldEquals("a", "not-empty"))
        with pytest.raises(ConditionFailedError):
            env.store.put(A, RUN, {"a": "x"}, when=FieldEquals("missing", ""))

    def test_floats_round_trip_exactly(self, env: Env) -> None:
        values = [0.1, 0.5, -2.75, 1e-7, 1.2345678901234567e-5, 3.141592653589793, 1.5e-37, 1e-100]
        env.store.put(A, RUN, {"f": values, "big": 10**38 - 1, "neg": -(10**37), "one": 1.0})
        got = env.store.get(A, RUN)
        assert got is not None
        assert got.data["f"] == values
        assert all(isinstance(x, float) for x in got.data["f"])
        assert got.data["big"] == 10**38 - 1
        assert got.data["neg"] == -(10**37)
        assert got.data["one"] == 1
        assert type(got.data["one"]) is int  # 1.0 is stored as the one DynamoDB number 1
        env.store.put(A, RUN, {"x": 0.5})
        env.store.put(A, RUN, {"x": 0.5}, when=FieldEquals("x", 0.5))  # type: ignore[arg-type]
        with pytest.raises(ConditionFailedError):
            env.store.put(A, RUN, {"x": 1}, when=FieldEquals("x", 0.25))  # type: ignore[arg-type]
        env.store.put(A, Key("R", "2"), {"x": 1.0})
        env.store.put(A, Key("R", "2"), {"x": 2}, when=FieldEquals("x", 1))

    def test_reads_are_strongly_consistent(self, env: Env) -> None:
        env.store.put(A, RUN, {"n": 1})
        env.store.get(A, RUN)
        for i in range(3):
            env.store.put(A, Key("P", f"S#{i}"), {"i": i})
        env.client.page_cap = 1
        env.store.query(A, "P")
        gets, queries = env.client.named("get_item"), env.client.named("query")
        assert len(gets) == 1
        assert len(queries) >= 3  # every page of a multi-page query, not just the first
        assert all(kw["ConsistentRead"] is True for kw in gets + queries)

    def test_a_write_is_visible_to_the_next_read(self, env: Env) -> None:
        for n in range(1, 30):
            env.store.put(A, RUN, {"n": n})
            got = env.store.get(A, RUN)
            assert got is not None
            assert (got.data, got.version) == ({"n": n}, n)
            assert [i.data for i in env.store.query(A, "RUN#1").items] == [{"n": n}]

    def test_the_team_comes_from_the_key_so_no_team_reaches_anothers_items(self, env: Env) -> None:
        a_odd = TeamScope("a")
        env.store.put(A, RUN, {"who": "A"})
        env.store.put(B, RUN, {"who": "B"})
        env.store.put(A, Key(TEAM_ROOT, "META"), {"who": "A root"})
        env.store.put(a_odd, Key("b#RUN#1", "META"), {"who": "a with a team-like pk"})
        env.store.put(TeamScope("b"), Key("RUN#1", "META"), {"who": "b"})
        env.store.put(A, Key("ORG", "META"), {"who": "A, a pk that is a platform name"})
        env.store.put(PLATFORM, Key("ORG", "META"), {"who": "org"})
        stored = sorted(i["pk"]["S"] for i in env.raw_items())
        assert stored == [
            "ORG",
            "TEAM#a#b#RUN#1",
            "TEAM#b#RUN#1",
            "TEAM#team-a",
            "TEAM#team-a#ORG",
            "TEAM#team-a#RUN#1",
            "TEAM#team-b#RUN#1",
        ]
        for scope, who in ((A, "A"), (B, "B")):
            got = env.store.get(scope, RUN)
            assert got is not None
            assert got.data == {"who": who}
            assert [i.data["who"] for i in env.store.query(scope, "RUN#1").items] == [who]
        assert [i.data["who"] for i in env.store.query(A, "ORG").items] == [
            "A, a pk that is a platform name"
        ]
        assert [i.data["who"] for i in env.store.query(PLATFORM, "ORG").items] == ["org"]
        assert env.store.get(TeamScope("team"), RUN) is None
        assert env.store.get(TeamScope("team-"), RUN) is None

    def test_main_and_audit_items_live_in_their_own_tables(self, env: Env) -> None:
        audit = Key("RUN#1", "AUD#1", AUDIT)
        env.store.transact(A, [Put(RUN, {"n": 1}), Put(audit, {"seq": 1}, when=Absent())])
        assert [i["sk"]["S"] for i in env.raw_items(env.main)] == ["META"]
        assert [i["sk"]["S"] for i in env.raw_items(env.audit)] == ["AUD#1"]
        with pytest.raises(ConditionFailedError):
            env.store.put(A, audit, {"seq": 2}, when=Absent())

    def test_a_missing_table_is_an_error_not_an_empty_store(self, env: Env) -> None:
        lost = DynamoDbStore(
            cast("DynamoDBClient", env.client), main_table="nope", audit_table=env.audit
        )
        for call in (
            lambda: lost.get(A, RUN),
            lambda: lost.query(A, "RUN#1"),
            lambda: lost.put(A, RUN, {"n": 1}),
        ):
            with pytest.raises(ClientError) as info:
                call()
            assert info.value.response["Error"]["Code"] == "ResourceNotFoundException"


class TestDynamoDbStoreOnMoto(StoreContract, DynamoServerTests):
    @pytest.fixture
    def store(self, env: Env) -> DynamoDbStore:
        return env.store


def test_claims_stay_exclusive_on_moto(env: Env) -> None:
    assert race_claims(env.store, rounds=5) == [1] * 5


# --- errors: every store speaks the port's error types ---------------------------------------

THROTTLES = [
    "ThrottlingException",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "TransactionConflictException",
]
MAYBE_APPLIED = [
    "InternalServerError",
    "InternalFailure",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "TransactionInProgressException",
]
WRITES = ("put", "delete", "transact")
READS = ("get", "query")
OPERATIONS: dict[str, tuple[str, Callable[[DynamoDbStore], object]]] = {
    "get": ("get_item", lambda s: s.get(A, RUN)),
    "query": ("query", lambda s: s.query(A, "RUN#1")),
    "put": ("transact_write_items", lambda s: s.put(A, RUN, {"n": 1})),
    "delete": ("transact_write_items", lambda s: s.delete(A, RUN)),
    "transact": ("transact_write_items", lambda s: s.transact(A, [Put(RUN, {"n": 1})])),
}


@pytest.mark.parametrize("code", THROTTLES)
@pytest.mark.parametrize("op", OPERATIONS)
def test_throttling_is_a_transaction_conflict_on_every_call_including_reads(
    env: Env, op: str, code: str
) -> None:
    """Callers retry on TransactionConflictError, so reads raise it too (it is a TransientError)."""
    method, call = OPERATIONS[op]
    cause = client_error(code)
    env.client.fail(method, cause)
    with pytest.raises(TransactionConflictError) as info:
        call(env.store)
    assert info.value.retryable
    assert not isinstance(info.value, TransactionOutcomeUnknownError)  # nothing was applied
    assert info.value.__cause__ is cause
    assert code in str(info.value)
    call(env.store)  # the next attempt goes through: nothing was cached or half-applied


@pytest.mark.parametrize("code", MAYBE_APPLIED)
@pytest.mark.parametrize("op", OPERATIONS)
def test_a_server_failure_may_have_applied_a_write_but_never_a_read(
    env: Env, op: str, code: str
) -> None:
    method, call = OPERATIONS[op]
    env.client.fail(method, client_error(code))
    expected = TransactionOutcomeUnknownError if op in WRITES else TransactionConflictError
    with pytest.raises(expected) as info:
        call(env.store)
    assert info.value.retryable
    assert isinstance(info.value, TransactionOutcomeUnknownError) == (op in WRITES)


@pytest.mark.parametrize("op", OPERATIONS)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_any_5xx_even_a_gateways_html_error_is_retryable(env: Env, op: str, status: int) -> None:
    method, call = OPERATIONS[op]
    exc = client_error(str(status), "<html>bad gateway</html>")
    exc.response["ResponseMetadata"] = {"HTTPStatusCode": status}
    env.client.fail(method, exc)
    with pytest.raises(TransactionConflictError) as info:
        call(env.store)
    assert isinstance(info.value, TransactionOutcomeUnknownError) == (op in WRITES)


TRANSPORT_FAILURES: list[Callable[[], BaseException]] = [
    lambda: ReadTimeoutError(endpoint_url="http://x"),
    lambda: ConnectionClosedError(endpoint_url="http://x"),
    lambda: HTTPClientError(error=OSError("boom")),
    lambda: ConnectTimeoutError(endpoint_url="http://x"),  # the SDK may have retried a landed write
    lambda: EndpointConnectionError(endpoint_url="http://x"),
    lambda: SSLError(endpoint_url="http://x", error=OSError("tls while reading the answer")),
    lambda: ProxyConnectionError(proxy_url="http://p"),
]


@pytest.mark.parametrize("make", TRANSPORT_FAILURES)
@pytest.mark.parametrize("op", OPERATIONS)
def test_every_transport_failure_on_a_write_is_unknown_and_on_a_read_a_plain_conflict(
    env: Env, op: str, make: Callable[[], BaseException]
) -> None:
    method, call = OPERATIONS[op]
    exc = make()
    env.client.fail(method, exc)
    with pytest.raises(TransactionConflictError) as info:
        call(env.store)
    assert isinstance(info.value, TransactionOutcomeUnknownError) == (op in WRITES)
    assert info.value.__cause__ is exc


def test_a_write_that_landed_before_the_timeout_says_so_and_a_reread_reconciles(
    env: Env,
) -> None:
    env.store.put(A, RUN, {"n": 0})
    env.client.fail("transact_write_items", AfterCall(ReadTimeoutError(endpoint_url="http://x")))
    with pytest.raises(TransactionOutcomeUnknownError):
        env.store.put(A, RUN, {"n": 1}, when=VersionIs(1))
    landed = env.store.get(A, RUN)
    assert landed is not None
    assert (landed.data, landed.version) == ({"n": 1}, 2)  # it did apply
    with pytest.raises(ConditionFailedError):  # a blind retry would now lose to its own success
        env.store.put(A, RUN, {"n": 1}, when=VersionIs(1))


@pytest.mark.parametrize(
    "code", ["ResourceNotFoundException", "AccessDeniedException", "UnrecognizedClientException"]
)
def test_errors_that_retrying_cannot_fix_are_not_disguised(env: Env, code: str) -> None:
    for method, call in OPERATIONS.values():
        env.client.fail(method, client_error(code))
        with pytest.raises(ClientError) as info:
            call(env.store)
        assert info.value.response["Error"]["Code"] == code
        assert info.value.__cause__ is None  # raised as it was, not chained to itself


def ok(n: int) -> list[dict[str, str]]:
    return [{"Code": "None"} for _ in range(n)]


def cancelled(*codes: str, message: str = "m") -> Any:
    reasons = [{"Code": c, "Message": message} if c != "None" else {"Code": "None"} for c in codes]
    return client_error("TransactionCanceledException", "Transaction cancelled", reasons)


THREE = [Put(Key("T", f"S#{i}"), {"i": i}) for i in range(3)]


def test_a_lost_condition_names_every_failed_item(env: Env) -> None:
    env.client.fail("transact_write_items", cancelled("None", "ConditionalCheckFailed", "None"))
    with pytest.raises(ConditionFailedError) as info:
        env.store.transact(A, THREE)
    assert info.value.failed == (1,)
    env.client.fail(
        "transact_write_items",
        cancelled("ConditionalCheckFailed", "None", "ConditionalCheckFailed"),
    )
    with pytest.raises(ConditionFailedError) as info:
        env.store.transact(A, THREE)
    assert info.value.failed == (0, 2)


def test_a_conflict_on_one_item_is_retryable_and_keeps_every_reason(env: Env) -> None:
    env.client.fail("transact_write_items", cancelled("None", "TransactionConflict", "None"))
    with pytest.raises(TransactionConflictError) as info:
        env.store.transact(A, THREE)
    assert [r.code for r in info.value.reasons] == ["None", "TransactionConflict", "None"]  # type: ignore[attr-defined]
    assert "TransactionConflict" in str(info.value)
    assert "1" in str(info.value)  # which operation


@pytest.mark.parametrize("code", ["ThrottlingError", "ProvisionedThroughputExceeded"])
def test_throttled_items_in_a_cancelled_transaction_are_retryable(env: Env, code: str) -> None:
    env.client.fail("transact_write_items", cancelled(code, "None", code))
    with pytest.raises(TransactionConflictError) as info:
        env.store.transact(A, THREE)
    assert [r.code for r in info.value.reasons] == [code, "None", code]  # type: ignore[attr-defined]


def test_a_lost_condition_wins_over_a_conflict_but_the_conflict_is_not_lost(env: Env) -> None:
    env.client.fail(
        "transact_write_items", cancelled("TransactionConflict", "ConditionalCheckFailed", "None")
    )
    with pytest.raises(ConditionFailedError) as info:
        env.store.transact(A, THREE)
    assert info.value.failed == (1,)
    assert [r.code for r in info.value.reasons] == [  # type: ignore[attr-defined]
        "TransactionConflict",
        "ConditionalCheckFailed",
        "None",
    ]


def test_a_validation_failure_on_one_item_is_a_value_error_with_its_message(env: Env) -> None:
    env.client.fail(
        "transact_write_items",
        cancelled("None", "ValidationError", message="Item size has exceeded the maximum"),
    )
    with pytest.raises(ValueError, match=r"operation 1.*Item size has exceeded"):
        env.store.transact(A, THREE)


def test_an_unknown_cancellation_reason_is_permanent_and_named(env: Env) -> None:
    env.client.fail("transact_write_items", cancelled("None", "ItemCollectionSizeLimitExceeded"))
    with pytest.raises(PermanentError, match="ItemCollectionSizeLimitExceeded") as info:
        env.store.transact(A, THREE)
    assert not isinstance(info.value, ConditionFailedError | TransactionConflictError)


def test_a_cancellation_without_reasons_is_retryable_not_a_lost_condition(env: Env) -> None:
    env.client.fail("transact_write_items", client_error("TransactionCanceledException", "why"))
    with pytest.raises(TransactionConflictError, match="why"):
        env.store.transact(A, THREE)


def test_a_server_side_size_refusal_is_a_value_error(env: Env) -> None:
    env.client.fail(
        "transact_write_items",
        client_error("ValidationException", "Item size has exceeded the maximum allowed size"),
    )
    with pytest.raises(ValueError, match="Item size"):
        env.store.put(A, RUN, {"n": 1})
    env.client.fail("transact_write_items", client_error("ValidationException", "Some other rule"))
    with pytest.raises(ValueError, match="Some other rule"):
        env.store.put(A, RUN, {"n": 1})


def test_a_real_lost_condition_on_moto_reports_each_failed_item(env: Env) -> None:
    env.store.put(A, Key("R", "1"), {"n": 1})
    with pytest.raises(ConditionFailedError) as info:
        env.store.transact(
            A,
            [
                Put(Key("R", "1"), {"n": 2}, when=VersionIs(5)),
                Put(Key("R", "2"), {"n": 1}),
                Check(Key("R", "3"), FieldEquals("n", 1)),
            ],
        )
    assert info.value.failed == (0, 2)
    assert [r.code for r in info.value.reasons] == [  # type: ignore[attr-defined]
        "ConditionalCheckFailed",
        "None",
        "ConditionalCheckFailed",
    ]
    assert env.store.get(A, Key("R", "2")) is None


def test_the_conflict_retry_contract_a_retry_after_a_conflict_succeeds(env: Env) -> None:
    env.store.put(A, RUN, {"owner": None})
    env.client.fail(
        "transact_write_items",
        cancelled("TransactionConflict"),
        client_error("TransactionConflictException"),
        None,
    )
    attempts = 0
    while True:
        attempts += 1
        try:
            env.store.transact(A, [Put(RUN, {"owner": "me"}, when=VersionIs(1))])
            break
        except TransactionConflictError:
            continue
    assert attempts == 3
    got = env.store.get(A, RUN)
    assert got is not None
    assert (got.data, got.version) == ({"owner": "me"}, 2)  # applied once, not three times


def test_the_sdk_sends_an_idempotency_token_so_its_own_retries_are_safe(env: Env) -> None:
    bodies: list[dict[str, Any]] = []

    def capture(params: dict[str, Any], **_: Any) -> None:
        bodies.append(json.loads(params["body"]))

    env.client.inner.meta.events.register("before-call.dynamodb.TransactWriteItems", capture)
    env.store.put(A, RUN, {"n": 1})
    env.store.put(A, RUN, {"n": 2})
    tokens = [b.get("ClientRequestToken") for b in bodies]
    assert len(tokens) == 2
    assert all(isinstance(t, str) and len(t) >= 16 for t in tokens)
    assert tokens[0] != tokens[1]  # one per call; a retry of the same call reuses its own


# --- paging, with the cut a real server makes ----------------------------------------------------


def test_a_query_cut_short_by_the_server_is_followed_to_the_end(env: Env) -> None:
    for i in range(10):
        env.store.put(A, Key("P", f"S#{i}"), {"i": i})
    env.client.page_cap = 3
    assert [i.data["i"] for i in env.store.query(A, "P").items] == list(range(10))
    page = env.store.query(A, "P", limit=7)
    assert [i.data["i"] for i in page.items] == list(range(7))
    assert page.cursor is not None
    rest = env.store.query(A, "P", limit=7, cursor=page.cursor)
    assert [i.data["i"] for i in rest.items] == [7, 8, 9]
    assert rest.cursor is None
    assert [i.data["i"] for i in env.store.query(A, "P", sk_prefix="S#", limit=10).items] == list(
        range(10)
    )
    assert env.store.query(A, "P", limit=10).cursor is None


def test_a_prefix_query_asks_for_a_literal_prefix_in_the_key_condition(env: Env) -> None:
    env.store.put(A, Key("P", "a%b"), {})
    env.store.put(A, Key("P", "aXb"), {})
    assert [i.key.sk for i in env.store.query(A, "P", sk_prefix="a%").items] == ["a%b"]
    (call,) = env.client.named("query")
    assert "begins_with" in call["KeyConditionExpression"]
    assert "FilterExpression" not in call  # filtering after the read would page wrongly


# --- values DynamoDB cannot hold ------------------------------------------------------------------


def test_the_smallest_number_dynamodb_holds_works(env: Env) -> None:
    env.store.put(A, RUN, {"x": 1e-130})
    got = env.store.get(A, RUN)
    assert got is not None
    assert got.data == {"x": 1e-130}


@pytest.mark.parametrize("text", ["\udc00", "a\ud800b"])
def test_strings_that_are_not_utf8_are_refused_in_keys_and_data(env: Env, text: str) -> None:
    for call in (
        lambda: env.store.put(A, RUN, {"s": text}),
        lambda: env.store.put(A, RUN, {text: 1}),
        lambda: env.store.put(A, RUN, {"a": 1}, when=FieldEquals("s", text)),
        lambda: env.store.put(A, Key("P", text), {}),
        lambda: env.store.get(A, Key("P", text)),
        lambda: env.store.query(A, "P", sk_prefix=text),
        lambda: env.store.query(A, text),
    ):
        with pytest.raises(ValueError, match="(?i)utf-8"):
            call()
    assert env.client.calls == []


# --- the size estimate follows DynamoDB's accounting ---------------------------------------


def test_the_size_estimate_follows_the_documented_rules() -> None:
    # The stored item is {pk, sk, v, d}: names count, strings count their UTF-8 bytes, a number is
    # about one byte per two digits plus one, null and bool take one byte, and a map or list takes
    # 3 bytes plus 1 per element.
    base = estimate_item_bytes({})
    assert estimate_item_bytes({"abc": "xyz"}) - base == 3 + 3 + 1  # name, value, element
    assert estimate_item_bytes({"é": "é"}) - base == 2 + 2 + 1  # bytes, not characters
    assert estimate_item_bytes({"a": True}) - base == 1 + 1 + 1
    assert estimate_item_bytes({"a": None}) - base == 1 + 1 + 1
    assert estimate_item_bytes({"a": 12345}) - base == 1 + (3 + 1) + 1  # 5 digits: 3 bytes + 1
    assert estimate_item_bytes({"a": [1, 2]}) - base == 1 + (3 + 2 * (2 + 1)) + 1
    assert estimate_item_bytes({"a": {"b": "c"}}) - base == 1 + (3 + (1 + 1 + 1)) + 1
    assert estimate_item_bytes({"a": 0}) - base == 1 + 2 + 1  # zero is one byte plus one
    assert estimate_item_bytes({"a": -12345}) - base == 1 + (3 + 1 + 1) + 1  # a sign: one more
    assert estimate_item_bytes({"a": 1200}) == estimate_item_bytes({"a": 12})  # zeros are free
    exact = 10**37 + 1  # 38 digits: normalize() under the default 28-digit context would round
    assert estimate_item_bytes({"a": exact}) - base == 1 + (19 + 1) + 1
    assert estimate_item_bytes({"a": 10**30}) < estimate_item_bytes({"a": 123456789 * 10**20})


def test_the_key_counts_toward_the_estimate_with_its_team_prefix() -> None:
    assert estimate_item_bytes({}, pk="TEAM#team-a#RUN#1", sk="META") > estimate_item_bytes(
        {}, pk="RUN#1", sk="META"
    )


# --- tables ---------------------------------------------------------------------------------


def test_create_tables_makes_two_on_demand_tables_keyed_pk_sk() -> None:
    with mock_aws():
        c = boto3.client(
            "dynamodb", region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t"
        )
        create_tables(c, main_table="m", audit_table="a")
        for name in ("m", "a"):
            table = c.describe_table(TableName=name)["Table"]
            assert [(k["AttributeName"], k["KeyType"]) for k in table["KeySchema"]] == [
                ("pk", "HASH"),
                ("sk", "RANGE"),
            ]
            assert table["BillingModeSummary"]["BillingMode"] == "PAY_PER_REQUEST"
        create_tables(c, main_table="m", audit_table="a")  # idempotent


def test_the_two_table_names_must_differ_and_be_given() -> None:
    inner: Any = object()
    with pytest.raises(ValueError, match="differ"):
        DynamoDbStore(inner, main_table="t", audit_table="t")
    with pytest.raises(ValueError, match="table"):
        DynamoDbStore(inner, main_table="", audit_table="a")


# --- concurrency ----------------------------------------------------------------------------


def test_threads_sharing_one_store_get_exactly_one_winner_per_item(env: Env) -> None:
    results: list[str] = []
    env.store.put(A, RUN, {"owner": None})
    barrier = threading.Barrier(6)

    def claim(n: int) -> None:
        barrier.wait()
        try:
            env.store.transact(A, [Put(RUN, {"owner": n}, when=VersionIs(1))])
            results.append("won")
        except (ConditionFailedError, TransactionConflictError):
            results.append("lost")

    pool = [threading.Thread(target=claim, args=(n,)) for n in range(6)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    assert results.count("won") == 1
    got = env.store.get(A, RUN)
    assert got is not None
    assert got.version == 2


def test_decimal_helpers_are_not_leaked_into_returned_data(env: Env) -> None:
    env.store.put(A, RUN, {"i": 3, "f": 0.25, "nested": [{"n": 7}]})
    got = env.store.get(A, RUN)
    assert got is not None

    def types(v: Any) -> set[type]:
        if isinstance(v, dict):
            return {t for x in v.values() for t in types(x)}
        if isinstance(v, list):
            return {t for x in v for t in types(x)}
        return {type(v)}

    assert Decimal not in types(got.data)
    assert types(got.data) == {int, float}


# --- review pass 1 -------------------------------------------------------------------------------


def test_audit_entries_go_out_as_a_native_put_and_main_items_as_an_update(env: Env) -> None:
    """The app role may be denied UpdateItem on the audit table (ADR-0017); TransactWriteItems
    checks permission per operation, so the operation kind on the wire matters."""
    audit = Key("RUN#1", "AUD#1", AUDIT)
    env.store.transact(
        A,
        [
            Put(RUN, {"n": 1}),
            Put(audit, {"seq": 1}, when=Absent()),
            Check(Key("RUN#1", "X"), Absent()),
            Delete(Key("RUN#1", "Y")),
        ],
    )
    (sent,) = env.client.named("transact_write_items")
    kinds = {
        op_body["TableName"]: kind
        for op in sent["TransactItems"]
        for kind, op_body in op.items()
        if kind in ("Update", "Put")
    }
    assert kinds == {MAIN_TABLE: "Update", AUDIT_TABLE: "Put"}
    (put,) = [op["Put"] for op in sent["TransactItems"] if "Put" in op]
    assert put["ConditionExpression"] == "attribute_not_exists(#pk)"
    assert put["Item"]["v"] == {"N": "1"}
    assert not any(
        "Update" in op and op["Update"]["TableName"] == AUDIT_TABLE for op in sent["TransactItems"]
    )
    got = env.store.get(A, audit)
    assert got is not None
    assert (got.data, got.version) == ({"seq": 1}, 1)
    with pytest.raises(ConditionFailedError):
        env.store.put(A, audit, {"seq": 2}, when=Absent())


def test_every_key_the_store_sends_carries_the_teams_prefix(env: Env) -> None:
    """On the wire, for each call kind on its own, so a missing prefix in any one path shows."""
    env.store.put(A, RUN, {"n": 1})
    env.store.get(A, RUN)
    env.store.query(A, "RUN#1")
    env.store.delete(A, RUN)
    env.store.transact(A, [Check(Key("RUN#1", "C"), Absent())])
    sent: list[str] = []
    for name, kw in env.client.calls:
        if name == "get_item":
            sent.append(kw["Key"]["pk"]["S"])
        elif name == "query":
            sent.append(kw["ExpressionAttributeValues"][":pk"]["S"])
        else:
            for op in kw["TransactItems"]:
                body = next(iter(op.values()))
                sent.append(body["Key"]["pk"]["S"] if "Key" in body else body["Item"]["pk"]["S"])
    assert len(sent) == 5  # put, get, query, delete, check
    assert all(pk == "TEAM#team-a#RUN#1" for pk in sent)


def test_query_keeps_going_past_an_empty_page_that_has_a_next_key(env: Env) -> None:
    for i in range(3):
        env.store.put(A, Key("P", f"S#{i}"), {"i": i})
    env.client.fail("query", EmptyPageWithNextKey)
    assert [i.data["i"] for i in env.store.query(A, "P").items] == [0, 1, 2]
    env.client.fail("query", EmptyPageWithNextKey)
    assert [i.data["i"] for i in env.store.query(A, "P", limit=2).items] == [0, 1]


def test_a_validation_failure_beats_a_lost_condition(env: Env) -> None:
    env.client.fail(
        "transact_write_items",
        cancelled("ConditionalCheckFailed", "ValidationError", message="too big"),
    )
    with pytest.raises(ValueError, match="too big"):
        env.store.transact(A, THREE)


# --- the SDK's own retries (real botocore, not scripted around it) -------------------------------

SECOND_ATTEMPT: dict[str, Callable[[], Any]] = {
    "connect timeout": lambda: (None, ConnectTimeoutError(endpoint_url="http://x")),
    "endpoint unreachable": lambda: (None, EndpointConnectionError(endpoint_url="http://x")),
    "throttled": lambda: (_answer("ThrottlingException"), None),
    "transaction conflict": lambda: (_answer("TransactionConflictException"), None),
    "expired credentials": lambda: (_answer("ExpiredTokenException"), None),
    "validation": lambda: (_answer("ValidationException"), None),
    "access denied": lambda: (_answer("AccessDeniedException"), None),
    "table missing": lambda: (_answer("ResourceNotFoundException"), None),
}


def _answer(code: str) -> Any:
    from botocore.awsrequest import AWSResponse

    class Raw(io.BytesIO):
        def stream(self, *_: Any, **__: Any) -> Iterator[bytes]:
            yield self.read()

    body = json.dumps({"__type": code, "message": "after a retry"}).encode()
    http = AWSResponse("https://x", 400, {}, Raw(body))  # type: ignore[arg-type]
    parsed = {
        "Error": {"Code": code, "Message": "after a retry"},
        "ResponseMetadata": {"HTTPStatusCode": 400, "HTTPHeaders": {}},
    }
    return http, parsed


@pytest.mark.parametrize("second", SECOND_ATTEMPT)
def test_a_write_that_landed_on_the_first_attempt_is_unknown_whatever_the_retry_hits(
    second: str,
) -> None:
    """Attempt 1 is applied by the server and its answer is lost; the SDK retries and attempt 2
    fails differently. The caller must not be told nothing was applied."""
    with mock_aws():
        client = boto3.client(
            "dynamodb",
            region_name="us-east-1",
            aws_access_key_id="t",
            aws_secret_access_key="t",
            config=Config(retries={"total_max_attempts": 2, "mode": "standard"}),
        )
        create_tables(client, main_table=MAIN_TABLE, audit_table=AUDIT_TABLE)
        store = DynamoDbStore(client, main_table=MAIN_TABLE, audit_table=AUDIT_TABLE)
        store.put(A, RUN, {"n": 0})
        endpoint = client._endpoint  # type: ignore[attr-defined]
        real = endpoint._do_get_response
        tokens: list[str] = []

        def flaky(request: Any, operation_model: Any, context: Any) -> Any:
            if operation_model.name != "TransactWriteItems":
                return real(request, operation_model, context)
            tokens.append(json.loads(request.body)["ClientRequestToken"])
            if len(tokens) == 1:
                real(request, operation_model, context)  # the server applies it
                return None, ReadTimeoutError(endpoint_url="http://x")
            return SECOND_ATTEMPT[second]()

        endpoint._do_get_response = flaky
        try:
            with pytest.raises(TransactionOutcomeUnknownError):
                store.put(A, RUN, {"n": 1}, when=VersionIs(1))
        finally:
            endpoint._do_get_response = real
        assert len(tokens) == 2
        assert len(set(tokens)) == 1  # the same token, so a replay is safe for the SDK
        landed = store.get(A, RUN)
        assert landed is not None
        assert (landed.data, landed.version) == ({"n": 1}, 2)
        with pytest.raises(ConditionFailedError):  # what a blind retry would have hit
            store.put(A, RUN, {"n": 1}, when=VersionIs(1))


def test_a_server_refusal_after_sdk_retries_is_unknown_for_a_write_but_not_a_read(
    env: Env,
) -> None:
    after_retries = client_error("ThrottlingException")
    after_retries.response["ResponseMetadata"] = {"HTTPStatusCode": 400, "RetryAttempts": 2}
    env.client.fail("transact_write_items", after_retries)
    with pytest.raises(TransactionOutcomeUnknownError):
        env.store.put(A, RUN, {"n": 1})
    env.client.fail("get_item", after_retries)
    with pytest.raises(TransactionConflictError) as info:
        env.store.get(A, RUN)
    assert not isinstance(info.value, TransactionOutcomeUnknownError)
    verdict = cancelled("TransactionConflict")  # a verdict on the transaction itself
    verdict.response["ResponseMetadata"] = {"HTTPStatusCode": 400, "RetryAttempts": 2}
    env.client.fail("transact_write_items", verdict)
    with pytest.raises(TransactionConflictError) as info:
        env.store.put(A, RUN, {"n": 1})
    assert not isinstance(info.value, TransactionOutcomeUnknownError)
