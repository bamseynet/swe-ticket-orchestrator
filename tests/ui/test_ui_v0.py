"""UI v0 (D1-09) in a real browser, against the real local API (no mocks).

CI's ``ui-browser`` job runs this. The job has no web setup of its own, so the test installs the
web dependencies when they are missing (``npm ci``) and builds the bundle itself. ``vite preview``
then serves it and forwards ``/api`` to the API (the same proxy ``make dev`` uses), the API is the
``build_local`` stack over a temporary SQLite file, and Playwright drives Chromium through the
demo, including a Request changes that opens round 2. Every subprocess and wait has a timeout.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import shutil
import signal
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
    web_log = tmp_path / "preview.log"
    web_log_file = web_log.open("w")
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
        stdout=web_log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # npx starts node: stop the whole group, not just npx
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                for port in (web_port, api_port):  # a raw socket: name lookup is blocked
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                        probe.settimeout(1)
                        probe.connect(("127.0.0.1", port))
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError(
                f"the web preview or the API did not come up in 30s; preview said:\n"
                f"{web_log.read_text()[-2000:]}"
            )
        yield f"http://127.0.0.1:{web_port}"
    finally:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(web.pid, sig)
            try:
                web.wait(10)
                break
            except subprocess.TimeoutExpired:
                continue
        server.should_exit = True
        thread.join(10)
        web_log_file.close()
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
            page.wait_for_url("**/runs/*")  # Start goes to the new run
            page.get_by_role("link", name="review_gate round 1").click(timeout=LONG)

            # A required comment is enforced: nothing is sent, the gate stays open.
            page.get_by_role("button", name="Reject").click()
            expect(page.get_by_role("alert")).to_contain_text("comment is required")
            expect(page.get_by_test_id("gate-status")).to_have_text("OPEN")

            # Request changes (with its comment) closes round 1 and opens round 2.
            page.get_by_label("Comment").fill("please redo")
            page.get_by_role("button", name="Request changes").click()
            expect(page.get_by_role("status").filter(has_text="Decision recorded.")).to_be_visible()
            # A closed gate shows who closed it, and offers no decision any more.
            expect(page.get_by_test_id("closed-by")).to_have_text(
                "CHANGES_REQUESTED, closed by dev"
            )
            expect(page.get_by_role("button", name="Approve")).to_have_count(0)

            page.get_by_role("link", name="Back to run").click()
            page.get_by_role("link", name="review_gate round 2").click(timeout=LONG)
            expect(page.get_by_test_id("gate-status")).to_have_text("OPEN")
            page.get_by_role("button", name="Approve").click()
            expect(page.get_by_role("status").filter(has_text="Decision recorded.")).to_be_visible()
            expect(page.get_by_test_id("closed-by")).to_have_text("APPROVED, closed by dev")

            page.get_by_role("link", name="Back to run").click()
            page.get_by_role("link", name="qa_gate round 1").click(timeout=LONG)
            page.get_by_label("Comment").fill("fine")
            page.get_by_role("button", name="Approve").click()
            expect(page.get_by_role("status").filter(has_text="Decision recorded.")).to_be_visible()
            expect(page.get_by_test_id("closed-by")).to_have_text("APPROVED, closed by dev")

            page.get_by_role("link", name="Back to run").click()
            expect(page.get_by_test_id("run-status")).to_have_text("DONE", timeout=LONG)
            expect(page.get_by_text("gate.closed").first).to_be_visible()
        finally:
            browser.close()
