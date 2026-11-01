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

#### D0-11a: Follow-up
**Deps:** D0-11. **Size:** S. **Run:** parallel. **Files:** `src/sto/store/follow.py`.

#### D1-02: Reducer
**Deps:** none. **Size:** M. **Run:** serial. **Files:** `src/sto/engine/reducer.py`, `src/sto/engine/commands.py`, `tests/engine/test_reducer.py`.
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
        title: str = "[D0-10] Declared-files check",
    ) -> None:
        self.title = title
        self.body = body
        self.files = files if files is not None else ["scripts/check_scope.py"]
        self.issues = issues or {11: issue("[D0-10] Declared-files check")}
        self.events = events or []
        self.labels = labels or []
        self.stages = stages

    def pr(self) -> dict[str, Any]:
        return {"title": self.title, "body": self.body, "labels": self.labels}

    def pr_files(self) -> list[str]:
        return self.files

    def issue(self, number: int) -> dict[str, Any] | None:
        return self.issues.get(number)

    def label_events(self) -> list[dict[str, Any]]:
        return self.events

    def stages_text(self) -> str | None:
        return self.stages


def issue(title: str, state: str = "open") -> dict[str, Any]:
    return {"title": title, "state": state}


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
        ("Closes #11\r\n", [11]),
        ("intro\r\n\r\nCloses #11\r\nResolves #12\r\n", [11, 12]),
        ("Closes #", []),
        ("", []),
        (None, []),
    ],
)
def test_parse_closing_issues(body: str | None, expected: list[int]) -> None:
    assert cs.parse_closing_issues(body) == expected


def test_issue_id_from_title() -> None:
    assert cs.issue_id_from_title("[D0-10] Declared-files check") == "D0-10"
    assert cs.issue_id_from_title("[D4-24a] Follow-up") == "D4-24a"
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
    d3 = cs.declared_from_stages(STAGES, "D0-11a")
    assert d3 is not None
    assert d3.files == ["src/sto/store/follow.py"]


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
        "docs/PLAN.md",
        "docs/sub/notes.md",
        "README.md",
    ],
)
def test_allowed_paths(path: str) -> None:
    d = declared("scripts/a.py", "src/sto/store/memory.py", "web/src/pages/runs/")
    assert cs.is_allowed(path, d)


@pytest.mark.parametrize(
    "path",
    [
        "docs/STAGES.md",
        "docs/adr/0001-x.md",
        "CONTRIBUTING.md",
        "CLAUDE.md",
        "src/notes.md",
        "web/README.md",
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
    api = FakeApi(
        body="Closes #12",
        title="[D0-11] Something parallel",
        issues={12: issue("[D0-11] Something parallel")},
        files=["src/sto/store/memory.py", ".github/workflows/ci.yml"],
    )
    r = run(api)
    assert any("serial" in e and "#12" in e and ".github/workflows/ci.yml" in e for e in r.errors)


def test_serial_issue_may_touch_declared_serial_area() -> None:
    r = run(FakeApi(files=[".github/workflows/ci.yml"]))
    assert r.errors == []


def test_serial_comes_from_stages_not_labels() -> None:
    stages = STAGES.replace(
        "**Run:** serial. **Files:** `scripts", "**Run:** parallel. **Files:** `scripts"
    )
    issues = {11: {**issue("[D0-10] x"), "labels": ["mode:serial"]}}
    r = run(FakeApi(stages=stages, files=[".github/workflows/ci.yml"], issues=issues))
    assert any("serial" in e for e in r.errors)


def test_issue_not_in_stages_fails_even_if_its_body_declares_files() -> None:
    # The live issue body is editable by workers, so it is never trusted.
    issues = {7: {**issue("[D9-99] New"), "body": "- **Files:** `scripts/other.py`\n"}}
    r = run(
        FakeApi(body="Closes #7", title="[D9-99] New", issues=issues, files=["scripts/other.py"])
    )
    assert len(r.errors) == 1
    assert "#7" in r.errors[0]
    assert "add it to STAGES.md first" in r.errors[0]


def test_stages_unreadable_fails() -> None:
    r = run(FakeApi(stages=None))
    assert any("STAGES.md" in e for e in r.errors)


def test_follow_up_id_resolves() -> None:
    api = FakeApi(
        body="Closes #20",
        title="[D0-11a] Follow-up",
        issues={20: issue("[D0-11a] Follow-up")},
        files=["src/sto/store/follow.py"],
    )
    assert run(api).errors == []


def test_closed_issue_fails() -> None:
    api = FakeApi(issues={11: issue("[D0-10] Declared-files check", state="closed")})
    r = run(api)
    assert any("not open" in e and "#11" in e for e in r.errors)


def test_issue_without_id_fails() -> None:
    r = run(FakeApi(issues={11: issue("Declared-files check")}))
    assert any("ID" in e for e in r.errors)


@pytest.mark.parametrize("title", ["[D0-11] Other", "No id", "[D0-10a] Follow-up"])
def test_pr_title_id_must_equal_issue_id(title: str) -> None:
    r = run(FakeApi(title=title))
    assert any("title" in e and "D0-10" in e for e in r.errors)


def test_crlf_body_from_web_editor_links_the_issue() -> None:
    assert run(FakeApi(body="Summary\r\n\r\nCloses #11\r\n")).errors == []


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


def test_empty_actor_list_disables_override() -> None:
    api = FakeApi(
        files=["src/sto/rogue.py"], labels=["scope-override"], events=[ev("labeled", "peter")]
    )
    assert cs.check(api).errors
    assert run(api, actors=set()).errors


def test_override_label_without_event_is_ignored() -> None:
    api = FakeApi(files=["src/sto/rogue.py"], labels=["scope-override"], events=[])
    assert run(api).errors


# ---------------------------------------------------------------- main()


def test_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert cs.main([], api=FakeApi()) == 0
    assert cs.main([], api=FakeApi(files=["nope.py"])) == 1
    assert "#11" in capsys.readouterr().out


def test_parse_actors() -> None:
    assert cs.parse_actors(" Peter, ,alice ,") == {"peter", "alice"}
    assert cs.parse_actors("") == frozenset()
    assert cs.parse_actors(None) == frozenset()


def test_main_reads_override_actors_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    api = FakeApi(
        files=["src/sto/rogue.py"], labels=["scope-override"], events=[ev("labeled", "peter")]
    )
    monkeypatch.delenv("SCOPE_OVERRIDE_ACTORS", raising=False)
    assert cs.main([], api=api) == 1  # empty variable: nobody can override
    monkeypatch.setenv("SCOPE_OVERRIDE_ACTORS", "peter")
    assert cs.main([], api=api) == 0


def test_main_requires_environment_without_injected_api(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for var in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "PR_NUMBER", "BASE_SHA"):
        monkeypatch.delenv(var, raising=False)
    assert cs.main([]) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().out


@pytest.mark.parametrize("path", [".github/workflows/scope.yml", "scripts/check_scope.py"])
def test_check_machinery_is_editable_only_by_d0_10(path: str) -> None:
    # Even an issue whose STAGES entry declares the file cannot touch the check itself.
    stages = STAGES + f"\n#### D0-12: Declares it\n**Run:** serial. **Files:** `{path}`.\n"
    api = FakeApi(
        body="Closes #12",
        title="[D0-12] Declares it",
        issues={12: issue("[D0-12] Declares it")},
        files=[path],
        stages=stages,
    )
    r = run(api)
    assert any("D0-10" in e and path in e and "#12" in e for e in r.errors)


def test_check_machinery_editable_by_d0_10_itself() -> None:
    api = FakeApi(files=[".github/workflows/scope.yml", "scripts/check_scope.py"])
    stages = STAGES.replace("`.github/workflows/ci.yml`.", "`.github/workflows/scope.yml`.", 1)
    api.stages = stages
    assert run(api).errors == []


# ---------------------------------------------------------------- workflow and ruleset

ROOT = Path(__file__).resolve().parents[2]


def _scope_workflow() -> dict[str, Any]:
    import yaml

    data = yaml.safe_load((ROOT / ".github/workflows/scope.yml").read_text())
    assert isinstance(data, dict)
    return data


def _scope_run_script() -> str:
    steps = _scope_workflow()["jobs"]["scope"]["steps"]
    return str(next(st["run"] for st in steps if "run" in st))


def _run_step(base: Path, script_exit: int | None) -> Any:
    """Run the workflow's shell step in a fake base checkout; the script, if present, exits ``script_exit``."""
    import subprocess

    if script_exit is not None:
        (base / "scripts").mkdir()
        (base / "scripts" / "check_scope.py").write_text(
            f"import sys\nprint('REAL CHECK RAN')\nsys.exit({script_exit})\n"
        )
    return subprocess.run(  # noqa: S603 - fixed local interpreter, no network
        ["bash", "-ec", _scope_run_script()],  # noqa: S607
        cwd=base,
        capture_output=True,
        text=True,
        check=False,
    )


def test_bootstrap_skip_only_while_base_lacks_the_script(tmp_path: Path) -> None:
    r = _run_step(tmp_path, None)
    assert r.returncode == 0
    assert "skipping" in r.stdout
    assert "REAL CHECK RAN" not in r.stdout


def test_once_base_has_the_script_it_runs_and_its_failure_fails_the_job(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    ok = _run_step(tmp_path / "a", 0)
    assert ok.returncode == 0
    assert "REAL CHECK RAN" in ok.stdout
    assert "skipping" not in ok.stdout
    (tmp_path / "b").mkdir()
    bad = _run_step(tmp_path / "b", 1)
    assert bad.returncode == 1
    assert "REAL CHECK RAN" in bad.stdout


def test_scope_workflow_shape() -> None:
    wf = _scope_workflow()
    triggers: dict[str, Any] = wf.get("on") or wf[True]  # type: ignore[index]  # YAML 1.1: `on` is True
    # pull_request_target runs the BASE copy of this file, so a PR cannot switch the check off.
    assert set(triggers) == {"pull_request_target"}
    assert {"labeled", "unlabeled", "edited"} <= set(triggers["pull_request_target"]["types"])
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["scope"]
    assert job["permissions"] == {"contents": "read", "issues": "read", "pull-requests": "read"}
    steps = job["steps"]
    checkouts = [st for st in steps if "uses" in st]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    assert checkouts[0]["with"]["persist-credentials"] is False
    text = (ROOT / ".github/workflows/scope.yml").read_text()
    assert "pull_request.head" not in text  # never the PR head ref or sha
    assert "github.head_ref" not in text
    assert "refs/pull" not in text
    assert "${{ secrets" not in text
    run_step = next(st for st in steps if "run" in st)
    assert run_step["env"]["SCOPE_OVERRIDE_ACTORS"] == "${{ vars.SCOPE_OVERRIDE_ACTORS }}"


def test_ci_yml_does_not_carry_the_scope_job_or_label_triggers() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "labeled" not in text
    assert "check_scope" not in text


def test_ruleset_requires_scope_as_a_second_check() -> None:
    import json

    rules = json.loads((ROOT / "deploy/ruleset-main.json").read_text())["rules"]
    params = next(r for r in rules if r["type"] == "required_status_checks")["parameters"]
    checks = {c["context"]: c["integration_id"] for c in params["required_status_checks"]}
    assert checks == {"ci-required": 15368, "scope": 15368}
