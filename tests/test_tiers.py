"""D0-08: test tiers, the tier guard, `scripts/test_changed.py` and the core CI jobs."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import textwrap
import tomllib
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


def collected(tier: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", tier, "tests/test_tiers.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    return result.stdout


@pytest.mark.contract
def test_contract_tier_selects_only_contract_tests() -> None:
    contract, unit = collected("contract"), collected("unit")
    assert "test_contract_tier_selects_only_contract_tests" in contract
    assert "test_gate_tier_selects_only_gate_tests" not in contract
    assert "test_contract_tier_selects_only_contract_tests" not in unit  # not run again as unit


@pytest.mark.gate
def test_gate_tier_selects_only_gate_tests() -> None:
    gate, unit = collected("gate"), collected("unit")
    assert "test_gate_tier_selects_only_gate_tests" in gate
    assert "test_contract_tier_selects_only_contract_tests" not in gate
    assert "test_gate_tier_selects_only_gate_tests" not in unit


# ---- review round 1: bypasses of the Docker and browser guards ----

BYPASSES = {
    "shell_string": 'import subprocess\nsubprocess.run("docker version", shell=True)',
    "sh_dash_c": 'import subprocess\nsubprocess.run(["sh", "-c", "docker version"])',
    "env_docker": 'import subprocess\nsubprocess.run(["/usr/bin/env", "docker", "version"])',
    "docker_path": 'import subprocess\nsubprocess.run(["/usr/local/bin/docker", "ps"])',
    "os_system": 'import os\nos.system("docker version")',
    "posix_spawn": 'import os\nos.posix_spawn("/usr/bin/env", ["env", "docker", "ps"], {})',
    "posix_spawnp": 'import os\nos.posix_spawnp("docker", ["docker", "ps"], {})',
    "connect_ex": (
        'import socket\ns = socket.socket(socket.AF_UNIX)\ns.connect_ex("/var/run/docker.sock")'
    ),
    "playwright_driver": (
        "import subprocess\n"
        'subprocess.run(["/venv/lib/python3.12/site-packages/playwright/driver/node", "cli.js"])'
    ),
    "browser_via_shell": 'import subprocess\nsubprocess.run("chromium --headless", shell=True)',
    "browser_via_env": 'import subprocess\nsubprocess.run(["env", "google-chrome", "--version"])',
    "exec": 'import os\nos.execvp("docker", ["docker", "version"])',
    "execl": 'import os\nos.execl("/usr/bin/env", "env", "docker", "ps")',
    "spawnv": 'import os\nos.spawnv(os.P_WAIT, "/usr/bin/env", ["env", "docker", "ps"])',
    "spawnlp": 'import os\nos.spawnlp(os.P_WAIT, "docker", "docker", "ps")',
    "pty_spawn": 'import pty\npty.spawn(["docker", "ps"])',
    "chained_shell": 'import subprocess\nsubprocess.run("cd /tmp && docker ps", shell=True)',
    "env_with_assignment": (
        'import subprocess\nsubprocess.run(["env", "FOO=1", "-i", "docker", "ps"])'
    ),
}


# ---- D0-08a: remaining Docker launch gaps ----

GAPS = {
    "backtick_in_shell_string": 'import subprocess\nsubprocess.run("echo `docker ps`", shell=True)',
    "dollar_paren_in_shell_string": (
        'import subprocess\nsubprocess.run("echo $(docker ps)", shell=True)'
    ),
    "substitution_inside_double_quotes": (
        "import subprocess\nsubprocess.run('echo \"$(docker ps)\"', shell=True)"
    ),
    "popen_executable": 'import subprocess\nsubprocess.Popen(["x", "ps"], executable="docker")',
    "xargs_wrapper": 'import subprocess\nsubprocess.run(["xargs", "docker", "rm"], input=b"")',
    "xargs_with_options": (
        'import subprocess\nsubprocess.run(["xargs", "-n", "1", "-I", "{}", "docker", "rm", "{}"])'
    ),
    "xargs_in_shell_string": (
        'import subprocess\nsubprocess.run("echo a | xargs -r docker rm", shell=True)'
    ),
    # review pass 1
    "apostrophe_in_double_quotes": (
        "import subprocess\nsubprocess.run('echo \"it\\'s $(docker ps)\"', shell=True)"
    ),
    "apostrophe_then_backtick": (
        "import subprocess\nsubprocess.run('echo \"it\\'s `docker ps`\"', shell=True)"
    ),
    "xargs_gnu_i": 'import subprocess\nsubprocess.run(["xargs", "-i", "docker", "rm", "{}"])',
    "xargs_long_option": (
        'import subprocess\nsubprocess.run(["xargs", "--max-args", "1", "docker", "rm"])'
    ),
    "xargs_option_cluster": (
        'import subprocess\nsubprocess.run(["xargs", "-rn", "1", "docker", "rm"])'
    ),
    "shell_true_with_executable": (
        'import subprocess\nsubprocess.Popen("ps", shell=True, executable="docker")'
    ),
    "nested_escaped_backticks": (
        'import subprocess\nsubprocess.run(r"echo `echo \\`docker ps\\``", shell=True)'
    ),
    "newline_separated": 'import subprocess\nsubprocess.run("echo hi\\ndocker ps", shell=True)',
    "absurd_nesting_fails_closed": (
        'import subprocess\nsubprocess.run("$(" * 3000 + "docker ps" + ")" * 3000, shell=True)'
    ),
}


CONTINUATIONS = [
    "echo hi && \\\n docker ps",
    "xargs \\\n docker rm",
    "FOO=1 \\\n docker ps",
    "sudo \\\n docker ps",
    'echo hi && "\\\n"docker ps',
]


@pytest.mark.parametrize("command", CONTINUATIONS)
def test_line_continuation_does_not_hide_docker(tmp_path: Path, command: str) -> None:
    source = f"""
        import subprocess
        def test_gap():
            subprocess.run({command!r}, shell=True)
    """
    result = run_pytest(tmp_path, source)
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout


@pytest.mark.parametrize("name", sorted(GAPS))
def test_docker_launch_gap_is_blocked(tmp_path: Path, name: str) -> None:
    body = textwrap.indent(GAPS[name], "    ")
    result = run_pytest(tmp_path, f"def test_gap():\n{body}\n")
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout


@pytest.mark.parametrize("name", sorted(BYPASSES))
def test_guard_bypass_is_blocked(tmp_path: Path, name: str) -> None:
    body = textwrap.indent(BYPASSES[name], "    ")
    result = run_pytest(tmp_path, f"def test_bypass():\n{body}\n")
    assert result.returncode == 1, result.stdout
    assert "TierViolationError" in result.stdout


INNOCENT = [
    'subprocess.run(["grep", "-r", "docker", "."], check=False)',
    'subprocess.run("grep -r docker .", shell=True, check=False)',
    'subprocess.run(["echo", "fix firefox"], check=True)',
    "subprocess.run(\"echo 'fix firefox; docker ps'\", shell=True, check=True)",
    'subprocess.run(["ls", "chrome-test-dir"], check=True)',
    'subprocess.run(["cat", "node_modules/playwright/package.json"], check=True)',
    'subprocess.run(["sh", "-c", "echo docker"], check=True)',
    'assert os.system("echo chromium") == 0',
    "subprocess.run(\"echo 'literal `docker ps` and $(docker ps)'\", shell=True, check=True)",
    'subprocess.run("echo `echo hi`", shell=True, check=True)',
    'subprocess.run("echo $(echo hi)", shell=True, check=True)',
    'subprocess.run(["echo", "$(docker ps)"], check=True)',
    'subprocess.run(["echo", "x"], executable="/bin/echo", check=True)',
    'subprocess.run(["xargs", "echo", "docker"], input=b"a", check=True)',
    'subprocess.run(["xargs", "-n", "1", "echo"], input=b"docker", check=True)',
    'subprocess.run(["xargs", "-i", "echo", "docker"], input=b"a", check=True)',
    'subprocess.run(["xargs", "--max-args", "1", "echo", "docker"], input=b"a", check=True)',
    'subprocess.run("echo \\"it\'s\\" \'$(docker ps)\'", shell=True, check=True)',
    "subprocess.run(\"grep ';' firefox.txt\", shell=True, check=False)",
    'subprocess.run("echo hi # $(docker ps)", shell=True, check=True)',
]


@pytest.mark.parametrize("call", INNOCENT)
def test_innocent_commands_are_not_blocked(tmp_path: Path, call: str) -> None:
    source = f"""
        import os, subprocess
        def test_ok(tmp_path, monkeypatch):
            monkeypatch.chdir(tmp_path)
            (tmp_path / "chrome-test-dir").mkdir()
            (tmp_path / "node_modules" / "playwright").mkdir(parents=True)
            (tmp_path / "node_modules" / "playwright" / "package.json").write_text("{{}}")
            {call}
    """
    result = run_pytest(tmp_path, source)
    assert result.returncode == 0, result.stdout


def test_shell_string_with_marker_is_allowed(tmp_path: Path) -> None:
    source = """
        import pytest, subprocess
        @pytest.mark.integration
        def test_ok():
            subprocess.run("docker version", shell=True)
    """
    assert run_pytest(tmp_path, source, "-m", "integration").returncode == 0


# ---- review round 1: tier from the directory ----


def test_directory_assigns_the_tier(tmp_path: Path) -> None:
    for folder in ("gates", "contract", "other"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / f"test_{folder}.py").write_text("def test_it(): pass\n")
    gate = run_pytest(tmp_path, "def test_root(): pass\n", "-m", "gate", "--collect-only", "-q")
    assert "gates/test_gates.py" in gate.stdout
    assert "contract/" not in gate.stdout
    contract = run_pytest(
        tmp_path, "def test_root(): pass\n", "-m", "contract", "--collect-only", "-q"
    )
    assert "contract/test_contract.py" in contract.stdout
    unit = run_pytest(tmp_path, "def test_root(): pass\n", "-m", "unit", "--collect-only", "-q")
    assert "other/test_other.py" in unit.stdout
    assert "gates/" not in unit.stdout
    assert "contract/" not in unit.stdout


# ---- review round 1: test_changed failure modes and overrides ----


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_missing_base_is_an_error_with_a_fetch_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    git(tmp_path, "init", "-q")
    git(tmp_path, "commit", "-q", "--allow-empty", "-m", "x")
    code = test_changed.main(["--base", "origin/main"], root=tmp_path, runner=record([], 0))
    assert code != 0
    assert "git fetch" in capsys.readouterr().err


def test_not_a_git_repository_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = test_changed.main([], root=tmp_path, runner=record([], 0))
    assert code != 0
    assert "git" in capsys.readouterr().err


def test_guard_and_script_changes_select_their_tests(tmp_path: Path) -> None:
    make_tree(tmp_path, ["tests/test_guards.py", "tests/test_tiers.py"])
    changed = ["tests/hermetic_guard.py", "tests/tier_guard.py", "scripts/test_changed.py"]
    assert test_changed.select(changed, tmp_path).paths == [
        "tests/test_guards.py",
        "tests/test_tiers.py",
    ]


def test_over_budget_files_are_named(tmp_path: Path) -> None:
    names = [f"m{i}" for i in range(4)]
    make_tree(
        tmp_path,
        [f"src/sto/domain/{n}.py" for n in names] + [f"tests/domain/test_{n}.py" for n in names],
    )
    selection = test_changed.select([f"src/sto/domain/{n}.py" for n in names], tmp_path, budget=2)
    message = selection.message()
    assert "tests/domain/test_m2.py" in message
    assert "tests/domain/test_m3.py" in message


# ---- review round 1: unit job excludes the other hermetic tiers; coverage sources ----


def test_unit_job_runs_unit_only_and_coverage_measures_real_code() -> None:
    makefile = (ROOT / "Makefile").read_text()
    fast = makefile.split("test-fast:", 1)[1].splitlines()[1]
    assert "-m unit" in fast
    source = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["coverage"]["run"][
        "source"
    ]
    assert {"sto", "tools", "scripts"} <= set(source)


def test_coverage_omits_tests_but_not_scripts_named_test_something() -> None:
    import fnmatch

    omit = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["coverage"]["run"]["omit"]

    def omitted(path: str) -> bool:
        return any(fnmatch.fnmatch(str(ROOT / path), pat) for pat in omit)

    assert not omitted("scripts/test_changed.py")
    assert omitted("tests/test_tiers.py")
    assert omitted("tests/scripts/test_doctor.py")
    assert omitted("tools/backlog/test_sync_issues.py")
    assert not omitted("tools/backlog/sync_issues.py")


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
