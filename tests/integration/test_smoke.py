"""Smoke tests for the CI-only tiers (D0-09): integration (Docker), ui_browser, and the
whole-stack check the e2e job runs. Later stages put their heavy tests beside these.

These never run locally: ``integration`` and ``ui_browser`` are deselected unless ``-m`` selects
them (tier_guard). CI starts DynamoDB Local with ``docker compose`` before the integration jobs.
"""

from __future__ import annotations

import importlib
import json
import os
import urllib.request
from collections.abc import Iterator

import pytest

from hermetic_guard import allow_loopback_bind

DDB_ENDPOINT = f"http://127.0.0.1:{os.environ.get('STO_DDB_PORT', '8720')}"
# DynamoDB Local does not verify signatures, but insists the request looks signed.
FAKE_AUTH = (
    "AWS4-HMAC-SHA256 Credential=fake/20260101/us-east-1/dynamodb/aws4_request, "
    "SignedHeaders=host, Signature=fake"
)


@pytest.fixture
def loopback() -> Iterator[None]:
    with allow_loopback_bind():
        yield


def _list_tables() -> dict[str, object]:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback http URL
        DDB_ENDPOINT,
        data=b"{}",
        method="POST",
        headers={
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": "DynamoDB_20120810.ListTables",
            "Authorization": FAKE_AUTH,
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        body: dict[str, object] = json.load(response)
    return body


@pytest.mark.integration
def test_dynamodb_local_answers_list_tables(loopback: None) -> None:
    assert "TableNames" in _list_tables()


@pytest.mark.integration
def test_stack_smoke_dynamodb_local_is_the_only_service_so_far(loopback: None) -> None:
    """The e2e job's placeholder: the whole local stack is up and answering.

    D1-10 replaces this with the walking-skeleton journey under tests/e2e/.
    """
    assert _list_tables().get("TableNames") == []


@pytest.mark.ui_browser
def test_headless_browser_renders_a_page() -> None:
    # Playwright comes from the CI job (`uv run --with playwright`), not from pyproject.
    sync_playwright = importlib.import_module("playwright.sync_api").sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.set_content("<title>sto smoke</title><h1>hello</h1>")
            assert page.title() == "sto smoke"
            assert page.locator("h1").inner_text() == "hello"
        finally:
            browser.close()
