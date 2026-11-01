"""D0-08: test tiers, the tier guard, `scripts/test_changed.py` and the core CI jobs."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "test_changed", ROOT / "scripts" / "test_changed.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


test_changed = load_script()


def make_tree(root: Path, files: list[str]) -> None:
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")


# ---- scripts/test_changed.py: direct tests only, with a selection budget ----


def test_domain_change_selects_only_its_direct_test(tmp_path: Path) -> None:
    make_tree(
        tmp_path,
        [
            "src/sto/domain/ids.py",
            "src/sto/domain/runs.py",
            "tests/domain/test_ids.py",
            "tests/domain/test_runs.py",
            "tests/engine/test_reducer.py",
        ],
    )
    selection = test_changed.select(["src/sto/domain/ids.py"], tmp_path)
    assert selection.paths == ["tests/domain/test_ids.py"]


def test_package_module_maps_to_test_directory(tmp_path: Path) -> None:
    make_tree(tmp_path, ["src/sto/engine/__init__.py", "tests/engine/test_engine.py"])
    # No direct test file for __init__.py: nothing is selected, the rest is left to CI.
    assert test_changed.select(["src/sto/engine/__init__.py"], tmp_path).paths == []


def test_changed_test_file_selects_itself(tmp_path: Path) -> None:
    make_tree(tmp_path, ["tests/store/test_memory.py", "tools/backlog/test_sync.py"])
    selection = test_changed.select(
        ["tests/store/test_memory.py", "tools/backlog/test_sync.py"], tmp_path
    )
    assert selection.paths == ["tests/store/test_memory.py", "tools/backlog/test_sync.py"]


def test_tool_and_script_map_to_sibling_tests(tmp_path: Path) -> None:
    make_tree(
        tmp_path,
        [
            "tools/backlog/test_sync_issues.py",
            "tests/scripts/test_doctor.py",
            "tests/scripts/test_other.py",
        ],
    )
    changed = ["tools/backlog/sync_issues.py", "scripts/doctor.py"]
    selection = test_changed.select(changed, tmp_path)
    assert selection.paths == ["tests/scripts/test_doctor.py", "tools/backlog/test_sync_issues.py"]


def test_conftest_selects_only_sibling_tests_not_recursively(tmp_path: Path) -> None:
    make_tree(tmp_path, ["tests/test_a.py", "tests/store/test_b.py", "tests/conftest.py"])
    selection = test_changed.select(["tests/conftest.py"], tmp_path)
    assert selection.paths == ["tests/test_a.py"]


def test_budget_caps_selection_and_reports_the_rest(tmp_path: Path) -> None:
    names = [f"m{i:03d}" for i in range(30)]
    make_tree(tmp_path, [f"src/sto/domain/{n}.py" for n in names])
    make_tree(tmp_path, [f"tests/domain/test_{n}.py" for n in names])
    changed = [f"src/sto/domain/{n}.py" for n in names]
    selection = test_changed.select(changed, tmp_path, budget=10)
    assert len(selection.paths) == 10
    assert len(selection.over_budget) == 20
    assert "left to CI" in selection.message()


def test_default_budget_is_modest() -> None:
    assert 1 <= test_changed.DEFAULT_BUDGET <= 40


def test_docs_deleted_and_shared_files_select_nothing(tmp_path: Path) -> None:
    make_tree(tmp_path, ["tests/test_x.py"])
    changed = ["docs/PLAN.md", "uv.lock", ".github/workflows/ci.yml", "tests/test_gone.py"]
    selection = test_changed.select(changed, tmp_path)
    assert selection.paths == []
    assert "no direct tests" in selection.message()


def record(ran: list[list[str]], code: int) -> Callable[[list[str]], int]:
    def runner(cmd: list[str]) -> int:
        ran.append(cmd)
        return code

    return runner


def test_main_runs_nothing_and_exits_zero_when_nothing_selected(tmp_path: Path) -> None:
    ran: list[list[str]] = []
    code = test_changed.main(["--files", "docs/PLAN.md"], root=tmp_path, runner=record(ran, 0))
    assert (code, ran) == (0, [])


def test_main_passes_selected_paths_to_pytest(tmp_path: Path) -> None:
    make_tree(tmp_path, ["tests/test_a.py"])
    ran: list[list[str]] = []
    code = test_changed.main(["--files", "tests/test_a.py"], root=tmp_path, runner=record(ran, 3))
    assert code == 3
    assert ran[0][-1] == "tests/test_a.py"
    assert "pytest" in ran[0]


# ---- the tier guard plugin ----


def run_pytest(tmp_path: Path, test_source: str, *args: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "test_case.py").write_text(textwrap.dedent(test_source))
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join([str(TESTS_DIR), os.environ.get("PYTHONPATH", "")]),
    }
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "tier_guard", "-p", "no:cacheprovider", "-q", *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


DOCKER_TEST = """
    import subprocess
    import pytest
    {marker}
    def test_uses_docker():
        try:
            subprocess.run(["docker", "version"], check=False)
        except FileNotFoundError:
            pass  # the guard let it through; this machine just has no docker
"""


def test_unmarked_docker_use_fails(tmp_path: Path) -> None:
    result = run_pytest(tmp_path, DOCKER_TEST.format(marker=""))
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout
    assert "integration" in result.stdout


def test_wrongly_marked_docker_use_fails(tmp_path: Path) -> None:
    result = run_pytest(tmp_path, DOCKER_TEST.format(marker="@pytest.mark.unit"))
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout


def test_docker_socket_connect_without_marker_fails(tmp_path: Path) -> None:
    source = """
        import socket
        def test_docker_sock():
            s = socket.socket(socket.AF_UNIX)
            s.connect("/var/run/docker.sock")
    """
    result = run_pytest(tmp_path, source)
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout


def test_integration_marked_docker_use_is_allowed_when_selected(tmp_path: Path) -> None:
    result = run_pytest(
        tmp_path, DOCKER_TEST.format(marker="@pytest.mark.integration"), "-m", "integration"
    )
    assert result.returncode == 0, result.stdout


def test_unmarked_browser_launch_fails_and_ui_browser_is_allowed(tmp_path: Path) -> None:
    source = """
        import subprocess
        import pytest
        {marker}
        def test_browser():
            try:
                subprocess.run(["chromium", "--version"], check=False)
            except FileNotFoundError:
                pass
    """
    bad = run_pytest(tmp_path, source.format(marker=""))
    assert bad.returncode == 1, bad.stdout
    assert "ui_browser" in bad.stdout
    good = run_pytest(tmp_path, source.format(marker="@pytest.mark.ui_browser"), "-m", "ui_browser")
    assert good.returncode == 0, good.stdout


def test_heavy_tiers_are_deselected_by_default(tmp_path: Path) -> None:
    source = """
        import pytest
        @pytest.mark.integration
        def test_i(): raise AssertionError("must not run locally")
        @pytest.mark.ui_browser
        def test_b(): raise AssertionError("must not run locally")
        @pytest.mark.live
        def test_l(): raise AssertionError("must not run locally")
        def test_plain(): pass
    """
    result = run_pytest(tmp_path, source)
    assert result.returncode == 0, result.stdout
    assert "1 passed" in result.stdout
    assert "3 deselected" in result.stdout


def test_unmarked_tests_count_as_unit(tmp_path: Path) -> None:
    source = """
        import pytest
        def test_plain(): pass
        @pytest.mark.contract
        def test_contract(): pass
    """
    result = run_pytest(tmp_path, source, "-m", "unit")
    assert result.returncode == 0, result.stdout
    assert "1 passed" in result.stdout
    assert "1 deselected" in result.stdout


def test_all_six_tier_markers_are_registered(tmp_path: Path) -> None:
    result = run_pytest(tmp_path, "def test_x(): pass\n", "--markers")
    for tier in ("unit", "contract", "gate", "integration", "ui_browser", "live"):
        assert re.search(rf"@pytest\.mark\.{tier}:", result.stdout), tier


# Smoke tests so `-m contract` and `-m gate` select something from day one.
# (Later issues add the real contract suites and gate scenarios.)


@pytest.mark.contract
def test_contract_tier_is_selectable() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-m",
            "contract",
            "tests/test_tiers.py",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "test_contract_tier_is_selectable" in result.stdout


@pytest.mark.gate
def test_gate_tier_is_selectable() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-m",
            "gate",
            "tests/test_tiers.py",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "test_gate_tier_is_selectable" in result.stdout


# ---- CI wiring and make targets ----


def test_core_jobs_exist_and_feed_ci_required() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    needs = workflow["jobs"]["ci-required"]["needs"]
    for job in ("contract", "gate-integrity", "coverage"):
        assert job in workflow["jobs"], job
        assert job in needs, job
    # Gate integrity is never path-filtered on backend changes: it keys off the full `code` output.
    assert workflow["jobs"]["gate-integrity"]["if"] == "needs.filter.outputs.code == 'true'"


def test_make_check_documents_itself_as_the_occasional_full_run() -> None:
    makefile = (ROOT / "Makefile").read_text()
    line = next(ln for ln in makefile.splitlines() if ln.startswith("check:"))
    assert "occasional" in line
    assert "full" in line.lower()


def test_make_test_changed_uses_the_script() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert "scripts/test_changed.py" in makefile


def test_package_is_importable_for_coverage() -> None:
    import sto

    assert sto.__name__ == "sto"
