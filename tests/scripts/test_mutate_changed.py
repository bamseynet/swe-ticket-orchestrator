"""Tests for ``scripts/mutate_changed.py`` on a synthetic module (one killed, one survivor)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "mutate_changed.py"
_spec = importlib.util.spec_from_file_location("mutate_changed", _PATH)
assert _spec is not None
assert _spec.loader is not None
mc = importlib.util.module_from_spec(_spec)
sys.modules["mutate_changed"] = mc
_spec.loader.exec_module(mc)

MODULE = '''"""doc with a == b and True."""


def double(x):
    return x + x


def is_big(x):
    return x > 10  # pragma: no mutate


def flag():
    return x_flag


x_flag = True
'''

PRAGMA_FREE = "def pick(a, b):\n    return a == b\n"


def test_generate_skips_docstrings_and_pragma_lines() -> None:
    muts = mc.generate_mutants(MODULE, "m.py")
    lines = {m.line for m in muts}
    assert 1 not in lines  # docstring
    assert 9 not in lines  # pragma line
    assert {5, 16} <= lines
    one = next(m for m in muts if m.line == 5)
    assert one.original == "return x + x"
    assert one.mutated == "return x - x"


def test_generate_limits_to_changed_lines_and_skips_unary_signs() -> None:
    assert [m.line for m in mc.generate_mutants(MODULE, "m.py", {16})] == [16]
    assert mc.generate_mutants("y = -x\n", "m.py") == []


def test_generate_drops_uncompilable_mutants() -> None:
    assert all(compile(m.source, "m", "exec") for m in mc.generate_mutants(PRAGMA_FREE, "m.py"))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "src" / "sto").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "sto" / "m.py").write_text(
        "def double(x):\n    return x + x\n\n\n"
        "def label(x):\n    return 'neg' if x < 0 else 'pos'\n"
    )
    (tmp_path / "tests" / "test_m.py").write_text(
        "import sys\nsys.path.insert(0, 'src/sto')\nimport m\n\n\n"
        "def test_double():\n    assert m.double(3) == 6\n\n\n"
        "def test_label_negative():\n    assert m.label(-5) == 'neg'\n"
    )
    return tmp_path


def test_one_killed_one_survivor(project: Path) -> None:
    before = (project / "src" / "sto" / "m.py").read_text()
    res = mc.mutate_file(
        "src/sto/m.py", ["tests/test_m.py"], project, deadline=float("inf"), only_lines={2, 6}
    )
    assert res.skipped == ""
    by_line = {m.line: m for m in res.mutants if m.description == "'+' -> '-'" or m.line == 6}
    assert by_line[2].outcome == mc.KILLED  # x - x == 0, test expects 6
    # `x < 0` -> `x >= 0` flips the only asserted case and is killed; `0` -> `1` survives
    survivors = [m for m in res.mutants if m.outcome == mc.SURVIVED]
    assert [m.mutated for m in survivors] == ["return 'neg' if x < 1 else 'pos'"]
    assert any(m.outcome == mc.KILLED and m.line == 6 for m in res.mutants)
    assert (project / "src" / "sto" / "m.py").read_text() == before  # always restored


def test_main_writes_report_and_json(
    project: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    out = tmp_path_factory.mktemp("out")
    rc = mc.main(
        ["--files", "src/sto/m.py", "--all-lines", "--out", str(out)],
        root=project,
    )
    assert rc == 0
    md = (out / "mutation-report.md").read_text()
    assert "Surviving mutants" in md
    assert "`src/sto/m.py:6`" in md
    data = json.loads((out / "mutation-report.json").read_text())
    assert data["counts"]["survived"] >= 1
    assert data["counts"]["killed"] >= 1


def test_no_python_source_changed_is_a_clean_skip(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert mc.main(["--files", "docs/README.md", "--out", str(out)], root=tmp_path) == 0
    assert "No Python source changed" in (out / "mutation-report.md").read_text()


def test_timeout_and_memory_are_not_kills(project: Path) -> None:
    calls = iter([(mc.SURVIVED, 0, ""), (mc.TIMEOUT, -9, ""), (mc.MEMORY, 1, "")])

    def fake(*_a: object, **_k: object) -> tuple[str, int, str]:
        return next(calls)

    res = mc.mutate_file(
        "src/sto/m.py",
        ["tests/test_m.py"],
        project,
        float("inf"),
        {6},
        runner=fake,
    )
    assert [m.outcome for m in res.mutants] == [mc.TIMEOUT, mc.MEMORY][: len(res.mutants)]
    c = mc.counts([res])
    assert (c[mc.KILLED], c[mc.TIMEOUT], c[mc.MEMORY]) == (0, 1, 1)


def test_time_budget_reports_unfinished(project: Path) -> None:
    res = mc.mutate_file(
        "src/sto/m.py",
        ["tests/test_m.py"],
        project,
        deadline=0.0,
        only_lines={2},
        runner=lambda *a, **k: (mc.SURVIVED, 0, ""),
    )
    assert res.mutants == []
    assert res.unfinished >= 1
