"""UI v0 (D1-09) in a real browser, against the real local API (no mocks).

CI's ``ui-browser`` job runs this. It builds nothing special: ``vite preview`` serves the built
bundle and forwards ``/api`` to the API (the same proxy ``make dev`` uses), the API is the
``build_local`` stack over a temporary SQLite file, and Playwright drives Chromium through the
demo. Every subprocess and wait has a hard timeout.
"""

from __future__ import annotations

import importlib
import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

from sto.api.app import build_local

WEB = Path(__file__).resolve().parents[2] / "web"
SHORT = 15_000  # ms: one UI step
LONG = 45_000  # ms: the run has to move (poll interval 2s in the UI)


def free_port() -> int:
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as s:  # family explicit: the guard needs it
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def sh(args: list[str], env: dict[str, str], timeout: float) -> None:
    done = subprocess.run(  # noqa: S603 - fixed argv
        args, cwd=WEB, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )
    assert done.returncode == 0, f"{args} failed:\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}"


@pytest.fixture
def stack(tmp_path: Path, allow_loopback: None) -> Iterator[str]:
    node_env = {**os.environ, "npm_config_engine_strict": "false"}  # the runner's Node may be older
    if not (WEB / "node_modules").exists():
        sh(["npm", "ci", "--no-audit", "--no-fund"], node_env, 300)
    sh(["npx", "vite", "build", "--outDir", str(tmp_path / "dist")], node_env, 120)

    api_port, web_port = free_port(), free_port()
    app = build_local(
        {"STO_MODE": "local", "STO_DB": str(tmp_path / "db" / "x.db"), "STO_POLL_INTERVAL": "0.2"}
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    web = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            "npx",
            "vite",
            "preview",
            "--outDir",
            str(tmp_path / "dist"),
            "--host",
            "127.0.0.1",
            "--port",
            str(web_port),
            "--strictPort",
        ],
        cwd=WEB,
        env={**node_env, "STO_API_PORT": str(api_port)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", web_port), 1).close()
                socket.create_connection(("127.0.0.1", api_port), 1).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError("the web preview or the API did not come up in 30s")
        yield f"http://127.0.0.1:{web_port}"
    finally:
        web.terminate()
        try:
            web.wait(10)
        except subprocess.TimeoutExpired:
            web.kill()
        server.should_exit = True
        thread.join(10)
        shutil.rmtree(tmp_path / "dist", ignore_errors=True)


@pytest.mark.ui_browser
def test_person_completes_the_demo_in_a_browser(stack: str) -> None:
    # Playwright is in the CI-only `browser` group, so it is imported here, untyped.
    pw_api = importlib.import_module("playwright.sync_api")
    expect, sync_playwright = pw_api.expect, pw_api.sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.set_default_timeout(SHORT)
            page.goto(f"{stack}/runs")
            expect(page.get_by_test_id("simulated-banner")).to_contain_text("simulated")

            page.get_by_role("button", name="Start a run").click()
            page.locator("li a").first.click()
            page.get_by_role("link", name="review_gate round 1").click(timeout=LONG)

            # A required comment is enforced: nothing is sent, the gate stays open.
            page.get_by_role("button", name="Reject").click()
            expect(page.get_by_role("alert")).to_contain_text("comment is required")
            expect(page.get_by_test_id("gate-status")).to_have_text("OPEN")

            page.get_by_role("button", name="Approve").click()
            # A closed gate shows who closed it, and offers no decision any more.
            expect(page.get_by_test_id("closed-by")).to_contain_text("closed by dev", timeout=LONG)
            expect(page.get_by_role("button", name="Approve")).to_have_count(0)

            page.get_by_role("link", name="Back to run").click()
            page.get_by_role("link", name="qa_gate round 1").click(timeout=LONG)
            page.get_by_label("Comment").fill("fine")
            page.get_by_role("button", name="Approve").click()
            expect(page.get_by_test_id("closed-by")).to_contain_text("closed by dev", timeout=LONG)

            page.get_by_role("link", name="Back to run").click()
            expect(page.get_by_text("gate.closed").first).to_be_visible(timeout=LONG)
            expect(page.get_by_text("DONE", exact=False).first).to_be_visible(timeout=LONG)
        finally:
            browser.close()
