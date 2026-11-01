"""Smoke tests for the CI-only tiers (D0-09): integration (Docker), ui_browser, and the
whole-stack check the e2e job runs. Later stages put their heavy tests beside these.

These never run locally: ``integration`` and ``ui_browser`` are deselected unless ``-m`` selects
them (tier_guard). CI starts DynamoDB Local with ``docker compose`` before the integration jobs.
"""

from __future__ import annotations

import importlib

import pytest

from _dynamodb import list_tables


@pytest.mark.integration
def test_dynamodb_local_answers_list_tables() -> None:
    assert "TableNames" in list_tables()


@pytest.mark.ui_browser
def test_headless_browser_renders_a_page() -> None:
    # Playwright comes from the CI job (`uv sync --group browser`), not a default dependency.
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
