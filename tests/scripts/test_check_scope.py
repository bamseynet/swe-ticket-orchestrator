"""Tests for ``scripts/check_scope.py`` (D0-10). The GitHub API is a fake, so no network."""

# ruff: noqa: E501  (STAGES fixture lines mirror the real file)
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_scope.py"
_spec = importlib.util.spec_from_file_location("check_scope", _PATH)
assert _spec is not None
assert _spec.loader is not None
cs = importlib.util.module_from_spec(_spec)
sys.modules["check_scope"] = cs
_spec.loader.exec_module(cs)

STAGES = """\
#### D0-10: Declared-files check
Body.
**AC:** x.
**Deps:** D0-08. **Size:** S. **Run:** serial. **Files:** `scripts/check_scope.py`, `tests/scripts/test_check_scope.py`, `.github/workflows/ci.yml`.

#### D0-11: Something parallel
**Deps:** D0-08. **Size:** S. **Run:** parallel. **Files:** `src/sto/store/memory.py`, `web/src/pages/runs/`, `README.md`.

#### D1-02: Reducer
**Deps:** none. **Size:** M. **Run:** serial. **Files:** `src/sto/engine/reducer.py`, `src/sto/engine/commands.py`, `tests/engine/test_reducer.py`.
"""

ISSUE_BODY = """\
## Spec

- **Files:** `scripts/other.py`, `src/sto/thing/`
- **Size:** S
- **Mode:** parallel
- **Stage:** D0: Foundations

_generated_
"""


class FakeApi:
    def __init__(
        self,
        *,
        body: str = "Closes #11\n",
        files: list[str] | None = None,
        issues: dict[int, dict[str, Any]] | None = None,
        events: list[dict[str, Any]] | None = None,
        labels: list[str] | None = None,
        stages: str | None = STAGES,
    ) -> None:
        self.body = body
        self.files = files if files is not None else ["scripts/check_scope.py"]
        self.issues = issues or {
            11: {
                "title": "[D0-10] Declared-files check",
                "body": ISSUE_BODY,
                "labels": ["mode:serial"],
            }
        }
        self.events = events or []
        self.labels = labels or []
        self.stages = stages

    def pr(self) -> dict[str, Any]:
        return {"body": self.body, "labels": self.labels}

    def pr_files(self) -> list[str]:
        return self.files

    def issue(self, number: int) -> dict[str, Any] | None:
        return self.issues.get(number)

    def label_events(self) -> list[dict[str, Any]]:
        return self.events

    def stages_text(self) -> str | None:
        return self.stages


def ev(action: str, actor: str, label: str = "scope-override") -> dict[str, Any]:
    return {"event": action, "actor": actor, "label": label}


# ---------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("Closes #11", [11]),
        ("intro\n\ncloses #11\n\nmore", [11]),
        ("Fixes: #4\n", [4]),
        ("Closes #11\nCloses #11\n", [11]),
        ("Closes #11\nResolves #12\n", [11, 12]),
        ("see Closes #11 in prose", []),
        ("<!-- Closes #99 -->\nCloses #11", [11]),
        ("Closes #", []),
        ("", []),
        (None, []),
    ],
)
def test_parse_closing_issues(body: str | None, expected: list[int]) -> None:
    assert cs.parse_closing_issues(body) == expected


def test_issue_id_from_title() -> None:
    assert cs.issue_id_from_title("[D0-10] Declared-files check") == "D0-10"
    assert cs.issue_id_from_title("no id here") is None


def test_declared_from_stages_reads_files_and_run() -> None:
    d = cs.declared_from_stages(STAGES, "D0-10")
    assert d is not None
    assert d.files == [
        "scripts/check_scope.py",
        "tests/scripts/test_check_scope.py",
        ".github/workflows/ci.yml",
    ]
    assert d.serial is True
    d2 = cs.declared_from_stages(STAGES, "D0-11")
    assert d2 is not None
    assert d2.serial is False
    assert cs.declared_from_stages(STAGES, "D9-99") is None


def test_declared_from_issue_body_uses_generated_format() -> None:
    d = cs.declared_from_issue_body(ISSUE_BODY)
    assert d is not None
    assert d.files == ["scripts/other.py", "src/sto/thing/"]
    assert d.serial is False
    assert cs.declared_from_issue_body("nothing") is None
    assert cs.declared_from_issue_body(None) is None


# ---------------------------------------------------------------- matching


def declared(*files: str, serial: bool = False) -> Any:
    return cs.Declared(files=list(files), serial=serial)


@pytest.mark.parametrize(
    "path",
    [
        "scripts/a.py",  # exact
        "web/src/pages/runs/index.tsx",  # directory prefix
        "tests/scripts/test_a.py",  # sibling test of a declared script
        "tests/store/test_memory.py",  # sibling test of src/sto/store/memory.py
        "uv.lock",
        "web/package-lock.json",
        "pyproject.toml",
        "Makefile",
        "web/package.json",
        "docs/adr/0001.md",
        "README.md",
        "CONTRIBUTING.md",
    ],
)
def test_allowed_paths(path: str) -> None:
    d = declared("scripts/a.py", "src/sto/store/memory.py", "web/src/pages/runs/")
    assert cs.is_allowed(path, d)


@pytest.mark.parametrize(
    "path",
    [
        "scripts/b.py",
        "src/sto/store/other.py",
        "web/src/pages/runsx/a.tsx",
        "infra/package.json",
        "src/sto/x.py",
    ],
)
def test_disallowed_paths(path: str) -> None:
    d = declared("scripts/a.py", "src/sto/store/memory.py", "web/src/pages/runs/")
    assert not cs.is_allowed(path, d)


def test_serial_areas_touched() -> None:
    touched = cs.serial_areas_touched(
        [
            ".github/workflows/ci.yml",
            "src/sto/domain/models.py",
            "src/sto/engine/reducer.py",
            "src/sto/engine/commands.py",
            "src/sto/gates/service.py",
            "src/sto/domainx/a.py",
            "src/sto/gates/hooks.py",
        ]
    )
    assert touched == [
        ".github/workflows/ci.yml",
        "src/sto/domain/models.py",
        "src/sto/engine/reducer.py",
        "src/sto/engine/commands.py",
        "src/sto/gates/service.py",
    ]


# ---------------------------------------------------------------- override


def test_override_needs_actor_on_list() -> None:
    assert cs.override_active([ev("labeled", "peter")], {"scope-override"}, {"peter"})
    assert not cs.override_active([ev("labeled", "worker-bot")], {"scope-override"}, {"peter"})


def test_override_ignores_other_labels_and_removed_labels() -> None:
    assert not cs.override_active([ev("labeled", "peter", "bug")], {"bug"}, {"peter"})
    assert not cs.override_active([ev("labeled", "peter")], set(), {"peter"})
    assert not cs.override_active(
        [ev("labeled", "peter"), ev("unlabeled", "peter")], {"scope-override"}, {"peter"}
    )


def test_worker_relabel_after_human_is_ignored() -> None:
    events = [ev("labeled", "peter"), ev("unlabeled", "worker"), ev("labeled", "worker")]
    assert not cs.override_active(events, {"scope-override"}, {"peter"})


def test_actor_match_is_case_insensitive() -> None:
    assert cs.override_active([ev("labeled", "Peter")], {"scope-override"}, {"peter"})


# ---------------------------------------------------------------- check()


def run(api: FakeApi, actors: set[str] | None = None) -> Any:
    return cs.check(api, override_actors=actors if actors is not None else {"peter"})


def test_clean_pr_passes() -> None:
    r = run(
        FakeApi(
            files=[
                "scripts/check_scope.py",
                "tests/scripts/test_check_scope.py",
                ".github/workflows/ci.yml",
            ]
        )
    )
    assert r.errors == []


def test_undeclared_file_fails_naming_the_issue() -> None:
    r = run(FakeApi(files=["scripts/check_scope.py", "src/sto/rogue.py"]))
    assert len(r.errors) == 1
    assert "#11" in r.errors[0]
    assert "D0-10" in r.errors[0]
    assert "src/sto/rogue.py" in r.errors[0]


def test_no_linked_issue_fails() -> None:
    r = run(FakeApi(body="no closing line"))
    assert r.errors
    assert "Closes #N" in r.errors[0]


def test_multiple_closes_fails() -> None:
    r = run(FakeApi(body="Closes #11\nCloses #12\n"))
    assert r.errors
    assert "one issue" in r.errors[0].lower()


def test_missing_issue_fails() -> None:
    r = run(FakeApi(body="Closes #404"))
    assert r.errors
    assert "#404" in r.errors[0]


def test_deletions_and_renames_count_as_touched_paths() -> None:
    # The API reports both sides of a rename; the old path is touched too.
    r = run(FakeApi(files=["scripts/check_scope.py", "src/sto/old_name.py", "src/sto/new_name.py"]))
    assert "src/sto/old_name.py" in r.errors[0]
    assert "src/sto/new_name.py" in r.errors[0]


def test_serial_area_needs_serial_issue() -> None:
    issues = {
        12: {"title": "[D0-11] Something parallel", "body": "", "labels": ["mode:parallel"]},
    }
    api = FakeApi(
        body="Closes #12",
        issues=issues,
        files=["src/sto/store/memory.py", ".github/workflows/ci.yml"],
    )
    r = run(api)
    assert any("serial" in e and "#12" in e and ".github/workflows/ci.yml" in e for e in r.errors)


def test_serial_issue_may_touch_declared_serial_area() -> None:
    r = run(FakeApi(files=[".github/workflows/ci.yml"]))
    assert r.errors == []


def test_serial_area_declared_but_issue_not_serial_still_fails() -> None:
    stages = STAGES.replace(
        "**Run:** serial. **Files:** `scripts", "**Run:** parallel. **Files:** `scripts"
    )
    r = run(
        FakeApi(
            stages=stages,
            files=[".github/workflows/ci.yml"],
            issues={11: {"title": "[D0-10] x", "body": "", "labels": ["mode:serial"]}},
        )
    )
    assert any("serial" in e for e in r.errors)


def test_falls_back_to_issue_body_when_not_in_stages() -> None:
    issues = {7: {"title": "[D9-99] New", "body": ISSUE_BODY, "labels": []}}
    ok = run(
        FakeApi(body="Closes #7", issues=issues, files=["scripts/other.py", "src/sto/thing/a.py"])
    )
    assert ok.errors == []
    bad = run(FakeApi(body="Closes #7", issues=issues, files=["scripts/zzz.py"]))
    assert "#7" in bad.errors[0]


def test_issue_without_any_declaration_fails() -> None:
    issues = {7: {"title": "plain title", "body": "no files", "labels": []}}
    r = run(FakeApi(body="Closes #7", issues=issues))
    assert r.errors
    assert "#7" in r.errors[0]


def test_stages_authority_beats_issue_body() -> None:
    # An issue body (editable by others) cannot widen what STAGES.md declares.
    issues = {
        11: {
            "title": "[D0-10] x",
            "body": "- **Files:** `src/sto/rogue.py`\n",
            "labels": ["mode:serial"],
        }
    }
    r = run(FakeApi(issues=issues, files=["src/sto/rogue.py"]))
    assert r.errors


def test_override_by_listed_human_passes_with_note() -> None:
    api = FakeApi(
        files=["src/sto/rogue.py"], labels=["scope-override"], events=[ev("labeled", "peter")]
    )
    r = run(api)
    assert r.errors == []
    assert any("override" in n.lower() for n in r.notes)


def test_override_by_worker_is_ignored() -> None:
    api = FakeApi(
        files=["src/sto/rogue.py"], labels=["scope-override"], events=[ev("labeled", "worker")]
    )
    r = run(api)
    assert r.errors


def test_override_label_without_event_is_ignored() -> None:
    api = FakeApi(files=["src/sto/rogue.py"], labels=["scope-override"], events=[])
    assert run(api).errors


# ---------------------------------------------------------------- main()


def test_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert cs.main([], api=FakeApi()) == 0
    assert cs.main([], api=FakeApi(files=["nope.py"])) == 1
    assert "#11" in capsys.readouterr().out


def test_main_requires_environment_without_injected_api(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for var in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "PR_NUMBER", "BASE_SHA"):
        monkeypatch.delenv(var, raising=False)
    assert cs.main([]) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().out
