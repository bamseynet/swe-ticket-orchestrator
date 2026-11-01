"""Targeted tests for the STAGES.md parser and body/label rendering."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sync_issues as s  # noqa: E402

FIXTURE = """# Delivery stages

## D0: Foundations

**Goal:** a repo where later PRs work.

**Scope:** stuff.

**Exit criteria:** CI runs on a PR,
and a ruleset enforces it.

<!-- waves:D0 -->
| Wave | Parallel | Serial, one at a time |
|---|---|---|
| 1 | - | D0-01 |
| 2 | D0-02 | - |

#### D0-01: Python skeleton
Create `src/sto` and `pyproject.toml`.
Second line.
**AC:** `make test-fast` passes; a socket test fails (as `a; b`); done.
**Deps:** none. **Size:** S. **Run:** serial. **Files:** `pyproject.toml`, `tests/conftest.py`.

#### D0-02: Live GitHub docs
Write the docs.
**AC:** it renders.
**Deps:** D0-01, D1-01. **Size:** M. **Run:** parallel. **Files:** `docs/X.md`.

---

## D1: Next

**Goal:** g1.

**Exit criteria:** e1.

<!-- waves:D1 -->
| Wave | Parallel | Serial, one at a time |
|---|---|---|
| 1 | D1-01 | - |

#### D1-01: Store
Store things.
**AC:** works.
**Deps:** D0-01. **Size:** L. **Run:** parallel. **Files:** `src/sto/store/ports.py`.

## Traceability

#### D9-99: not part of a stage
"""


def test_parse_fixture_clean():
    d = s.parse(FIXTURE)
    assert [i.id for i in d.issues] == ["D0-01", "D0-02", "D1-01"]
    assert list(d.stages) == ["D0", "D1"]
    assert d.stages["D0"].title == "D0: Foundations"
    assert d.stages["D0"].goal == "a repo where later PRs work."
    assert d.stages["D0"].exit_criteria == "CI runs on a PR,\nand a ruleset enforces it."


def test_issue_fields():
    d = s.parse(FIXTURE)
    a, b, c = d.issues
    assert a.description == "Create `src/sto` and `pyproject.toml`.\nSecond line."
    assert a.ac == ["`make test-fast` passes", "a socket test fails (as `a; b`)", "done"]
    assert a.deps == []
    assert a.size == "S"
    assert a.run == "serial"
    assert a.files == ["pyproject.toml", "tests/conftest.py"]
    assert (a.wave, b.wave, c.wave) == (1, 2, 1)
    assert b.deps == ["D0-01", "D1-01"]


def test_warnings_for_unknown_dep_and_malformed():
    bad = FIXTURE.replace("**Deps:** D0-01, D1-01.", "**Deps:** D0-01, D7-77.")
    assert any("unknown issue D7-77" in w for w in s.parse(bad).warnings)
    bad = FIXTURE.replace("**Size:** S.", "**Size:** XL.")
    assert any("unknown size" in w for w in s.parse(bad).warnings)
    bad = FIXTURE.replace("**AC:** it renders.\n", "")
    assert any("D0-02: no **AC:**" in w for w in s.parse(bad).warnings)


def test_orphan_issue_after_stage_flagged():
    d = s.parse(FIXTURE)
    assert any("D9-99" in w for w in d.warnings)


def test_real_doc_has_249_issues_and_no_warnings():
    d = s.parse(s.STAGES_PATH.read_text())
    assert len(d.issues) == 249
    assert d.warnings == []


def test_github_slug():
    assert (
        s.github_slug("D4-16: Fake GitHub: auth and webhooks")
        == "d4-16-fake-github-auth-and-webhooks"
    )


def test_labels():
    d = s.parse(FIXTURE)
    a, b, c = d.issues
    assert s.labels_for(a)[:2] == ["stage:D0", "size:S"]
    assert "mode:serial" in s.labels_for(a)
    assert "offline" in s.labels_for(a)
    assert "type:docs" in s.labels_for(b)
    assert "live" in s.labels_for(b)
    assert "needs:peter" in s.labels_for(b)
    assert "needs:peter" not in s.labels_for(c)


def test_body_resolves_deps_and_keeps_ticks():
    d = s.parse(FIXTURE)
    a, b, _ = d.issues
    old = "- [x] done\n- [ ] done too"
    body = s.render_body(a, d, "o/r", {}, old)
    assert "- [x] done\n" in body
    assert "- [ ] `make test-fast` passes" in body
    assert "Depends on: none" in body
    body = s.render_body(b, d, "o/r", {"D0-01": 7, "D1-01": 9})
    assert "Depends on: #7 (D0-01), #9 (D1-01)" in body
    assert "STAGES.md#d0-02-live-github-docs" in body
    # rendering is stable, so a second run edits nothing
    assert body == s.render_body(b, d, "o/r", {"D0-01": 7, "D1-01": 9}, body)


def test_id_re_accepts_follow_up_suffix() -> None:
    import re

    assert re.findall(s.ID_RE, "D0-07, D0-08a and D1-08.") == ["D0-07", "D0-08a", "D1-08"]
    assert re.fullmatch(s.ID_RE, "D0-08ab") is None
