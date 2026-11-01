"""The DynamoDB store against DynamoDB Local (D3-09): the shared contract suite plus the
server-behaviour checks, on a real DynamoDB engine. CI only (``integration`` marker, Docker).

The same ``DynamoServerTests`` run on moto in ``tests/store/test_dynamodb.py``. Only what a fake
cannot show is here: real transaction serialization (``race_claims`` retries
``TransactionConflictError`` as callers must), the server's own size and validation refusals,
type-strict conditions, and the 1 MB query page.
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
    Key,
    Put,
    Store,
    TeamScope,
    TransactionConflictError,
    TransactionOutcomeUnknownError,
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


@pytest.mark.integration
def test_concurrent_transactions_on_one_item_really_conflict_and_say_so(env: Env) -> None:
    """Nothing serializes calls here (``serialize=False``), so DynamoDB itself must refuse some
    overlapping transactions. Each refusal must surface as a plain TransactionConflictError: not a
    lost condition (no condition is set), and not an unknown outcome (nothing was applied)."""
    team = TeamScope("team-a")
    keys = [Key("HOT", f"ITEM#{i}") for i in range(3)]
    for k in keys:
        env.store.put(team, k, {"n": 0})
    conflicts: list[BaseException] = []
    other: list[BaseException] = []
    threads = 32
    barrier = threading.Barrier(threads)

    def hammer(n: int) -> None:
        barrier.wait()
        for i in range(150):
            # Overlapping item sets in different orders, so transactions contend on several items.
            chosen = keys[n % 3 :] + keys[: n % 3]
            ops = [Put(k, {"n": n, "i": i}) for k in chosen[: 2 + (i % 2)]]
            try:
                env.store.transact(team, ops)
            except TransactionConflictError as exc:
                conflicts.append(exc)
            except BaseException as exc:
                other.append(exc)

    pool = [threading.Thread(target=hammer, args=(n,)) for n in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    assert other == []
    assert conflicts, "DynamoDB Local never reported a conflict: the test is not exercising it"
    assert not any(isinstance(c, TransactionOutcomeUnknownError) for c in conflicts)


@pytest.mark.integration
def test_the_whole_contract_suite_ran_on_dynamodb_local(request: pytest.FixtureRequest) -> None:
    """Last in the file: the skip in ``env`` must not hide a run that executed nothing."""
    assert _integration_selected(request.config.getoption("markexpr")), "not an integration run"
    assert executed, "nothing ran on DynamoDB Local: the suite was deselected or skipped"
    expected = {
        n for cls in (StoreContract, DynamoServerTests) for n in dir(cls) if n.startswith("test_")
    }
    ran = {name for name in executed if name.removesuffix("]") in expected}
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
