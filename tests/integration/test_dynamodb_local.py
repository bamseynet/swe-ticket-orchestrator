"""The DynamoDB store against DynamoDB Local (D3-09): the shared contract suite plus the
server-behaviour checks, on a real DynamoDB engine. CI only (``integration`` marker, Docker).

DynamoDB Local never reports a transaction conflict (32 threads by 150 transactions: none), so
real conflicts are not shown here (D12-07); scripted ones run on moto.
The same ``DynamoServerTests`` run on moto in ``tests/store/test_dynamodb.py``. Only what a fake
cannot show is here: claims with no lock in front of the client, the server's own size and
validation refusals, type-strict conditions, and the 1 MB query page.
"""

from __future__ import annotations

import socket
import threading
import uuid
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, cast

import boto3
import pytest
from _pytest.mark.expression import Expression
from botocore.config import Config
from store_contract import StoreContract
from test_dynamodb import DynamoServerTests, Env, SpyClient

from _dynamodb import DDB_PORT
from hermetic_guard import allow_loopback_bind
from sto.store.dynamodb import DynamoDbStore, create_tables
from sto.store.ports import (
    ConditionFailedError,
    Key,
    Put,
    Store,
    TeamScope,
    TransactionConflictError,
    VersionIs,
)

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient


executed: list[str] = []


def _only_integration(name: str, /, **_: str | int | bool | None) -> bool:
    return name == "integration"


def _integration_selected(markexpr: object) -> bool:
    """True when ``-m`` selects a test carrying only the ``integration`` marker. ``-m contract``
    and ``-m "not integration"`` do not, whatever text they contain."""
    if not markexpr:
        return False
    return bool(Expression.compile(str(markexpr)).evaluate(_only_integration))


@pytest.fixture
def env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    # The class inherits StoreContract's `contract` marker, so `-m contract` collects it; only
    # the integration job (which has DynamoDB Local) may run it.
    if not _integration_selected(request.config.getoption("markexpr")):
        pytest.skip("needs DynamoDB Local: runs in the integration job only")

    def loopback_only(host: str, port: int, *_: object, **__: object) -> list[Any]:
        # urllib3 resolves even an IP literal through getaddrinfo, which the guard blocks.
        if host != "127.0.0.1":
            raise OSError(f"name lookups are blocked: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

    monkeypatch.setattr(socket, "getaddrinfo", loopback_only)
    suffix = uuid.uuid4().hex[:12]  # DynamoDB Local runs -sharedDb: tests must not share tables
    main, audit = f"sto-main-{suffix}", f"sto-audit-{suffix}"
    with allow_loopback_bind():
        inner = boto3.client(
            "dynamodb",
            endpoint_url=f"http://127.0.0.1:{DDB_PORT}",
            region_name="us-east-1",
            aws_access_key_id="local",
            aws_secret_access_key="local",
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
        create_tables(inner, main_table=main, audit_table=audit)
        executed.append(request.node.name)
        spy = SpyClient(inner, serialize=False)  # concurrent calls must reach the engine
        store = DynamoDbStore(cast("DynamoDBClient", spy), main_table=main, audit_table=audit)
        try:
            yield Env(spy, store, main, audit)
        finally:
            for name in (main, audit):
                inner.delete_table(TableName=name)


@pytest.mark.integration
class TestDynamoDbStoreOnDynamoDbLocal(StoreContract, DynamoServerTests):
    @pytest.fixture
    def store(self, env: Env) -> Store:
        return env.store


def _join(pool: list[threading.Thread], what: str, seconds: float = 120) -> None:
    for t in pool:
        t.join(timeout=seconds)
    stuck = sum(t.is_alive() for t in pool)
    assert stuck == 0, f"{what}: {stuck} thread(s) still running after {seconds}s"


@pytest.mark.integration
def test_unserialized_claims_have_one_winner_and_no_update_is_lost(env: Env) -> None:
    """No lock sits in front of the client here (``serialize=False``), so these are real concurrent
    transactions. DynamoDB Local never reports a conflict: 32 threads by 150 transactions over three
    items (about 4,800) produced none, so it serializes them. This test therefore asserts what
    holds there: one winner per claim, and every counter increment survives. A real conflict from
    live DynamoDB is not shown here (D12-07)."""
    team = TeamScope("team-a")
    threads, rounds = 16, 10
    for r in range(rounds):
        key = Key("CLAIM", f"R{r}")
        env.store.put(team, key, {"owner": None})
        barrier = threading.Barrier(threads)
        won: list[int] = []

        def claim(
            n: int,
            key: Key = key,
            barrier: threading.Barrier = barrier,
            won: list[int] = won,
        ) -> None:
            barrier.wait()
            for _ in range(50):
                try:
                    env.store.transact(team, [Put(key, {"owner": n}, when=VersionIs(1))])
                    won.append(n)
                except TransactionConflictError:
                    continue  # a real conflict would be retried, as callers do
                except ConditionFailedError:
                    pass
                return

        pool = [threading.Thread(target=claim, args=(n,)) for n in range(threads)]
        for t in pool:
            t.start()
        _join(pool, f"claim round {r}")
        assert len(won) == 1
        got = env.store.get(team, key)
        assert got is not None
        assert (got.data, got.version) == ({"owner": won[0]}, 2)

    counter = Key("COUNTER", "C")
    env.store.put(team, counter, {"n": 0})
    per_thread = 15

    gave_up: list[str] = []

    def bump() -> None:
        for _ in range(per_thread):
            for _attempt in range(1000):  # bounded: a stuck loop must fail by name, not hang
                seen = env.store.get(team, counter)
                assert seen is not None
                try:
                    env.store.transact(
                        team,
                        [Put(counter, {"n": seen.data["n"] + 1}, when=VersionIs(seen.version))],
                    )
                    break
                except (ConditionFailedError, TransactionConflictError):
                    continue
            else:
                gave_up.append("increment")
                return

    pool = [threading.Thread(target=bump) for _ in range(threads)]
    for t in pool:
        t.start()
    _join(pool, "counter increments")
    assert gave_up == [], "an increment never succeeded in 1000 attempts"
    final = env.store.get(team, counter)
    assert final is not None
    assert final.data["n"] == threads * per_thread  # no lost update
    assert final.version == threads * per_thread + 1


@pytest.mark.integration
def test_the_whole_contract_suite_ran_on_dynamodb_local(request: pytest.FixtureRequest) -> None:
    """Last in the file: the skip in ``env`` must not hide a run that executed nothing."""
    assert _integration_selected(request.config.getoption("markexpr")), "not an integration run"
    assert executed, "nothing ran on DynamoDB Local: the suite was deselected or skipped"
    expected = {
        n for cls in (StoreContract, DynamoServerTests) for n in dir(cls) if n.startswith("test_")
    } | {test_unserialized_claims_have_one_winner_and_no_update_is_lost.__name__}
    ran = {name.split("[")[0] for name in executed} & expected
    assert len(ran) == len(expected), f"not run on DynamoDB Local: {sorted(expected - ran)}"


@pytest.mark.parametrize(
    ("expr", "selected"),
    [
        ("integration", True),
        ("integration or e2e", True),
        ("contract", False),
        ("not integration", False),
        ("contract and not integration", False),
        ("", False),
        (None, False),
    ],
)
def test_the_marker_check_reads_the_expression_not_the_text(
    expr: str | None, selected: bool
) -> None:
    assert _integration_selected(expr) is selected
