"""Smoke tests for the CI-only tiers (D0-09): integration (Docker), ui_browser, and the
whole-stack check the e2e job runs. Later stages put their heavy tests beside these.

These never run locally: ``integration`` and ``ui_browser`` are deselected unless ``-m`` selects
them (tier_guard). CI starts DynamoDB Local with ``docker compose`` before the integration jobs.
"""

from __future__ import annotations

import importlib
import json
import os
import socket
from collections.abc import Iterator

import pytest

from hermetic_guard import allow_loopback_bind

DDB_PORT = int(os.environ.get("STO_DDB_PORT", "8720"))
# DynamoDB Local does not verify signatures, but insists the request looks signed.
FAKE_AUTH = (
    "AWS4-HMAC-SHA256 Credential=fake/20260101/us-east-1/dynamodb/aws4_request, "
    "SignedHeaders=host, Signature=fake"
)


@pytest.fixture
def loopback() -> Iterator[None]:
    with allow_loopback_bind():
        yield


def list_tables() -> dict[str, object]:
    """POST ListTables over a raw loopback socket (name lookups stay blocked by the guard)."""
    payload = b"{}"
    head = (
        f"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        f"Content-Type: application/x-amz-json-1.0\r\n"
        f"X-Amz-Target: DynamoDB_20120810.ListTables\r\n"
        f"Authorization: {FAKE_AUTH}\r\nContent-Length: {len(payload)}\r\n\r\n"
    ).encode()
    chunks: list[bytes] = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(("127.0.0.1", DDB_PORT))
        conn.sendall(head + payload)
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    header, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    assert header.startswith(b"HTTP/1.1 200"), header
    parsed: dict[str, object] = json.loads(body[body.index(b"{") :])
    return parsed


@pytest.mark.integration
def test_dynamodb_local_answerslist_tables(loopback: None) -> None:
    assert "TableNames" in list_tables()


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
