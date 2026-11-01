"""Structural checks on .github/workflows/ci.yml, so a later job cannot be added without
being wired into the ci-required aggregator (the only required check)."""

import copy
import re
from pathlib import Path
from typing import Any

import yaml

CI_PATH = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
AGGREGATOR = "ci-required"


def load_ci() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(CI_PATH.read_text())
    return data


def problems(workflow: dict[str, Any]) -> list[str]:
    jobs: dict[str, Any] = workflow["jobs"]
    found: list[str] = []
    needs = jobs[AGGREGATOR].get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for name in jobs:
        if name != AGGREGATOR and name not in needs:
            found.append(f"job {name!r} is not in {AGGREGATOR}.needs")
    filter_outputs = set(jobs["filter"].get("outputs", {}))
    for name, job in jobs.items():
        for out in re.findall(r"needs\.filter\.outputs\.(\w+)", str(job.get("if", ""))):
            if out not in filter_outputs:
                found.append(f"job {name!r} uses undefined filter output {out!r}")
    return found


def test_ci_workflow_is_wired() -> None:
    assert problems(load_ci()) == []


def test_unwired_job_is_detected() -> None:
    wf = copy.deepcopy(load_ci())
    wf["jobs"]["newjob"] = {"needs": "filter", "if": "needs.filter.outputs.code == 'true'"}
    assert problems(wf) == ["job 'newjob' is not in ci-required.needs"]


def test_undefined_filter_output_is_detected() -> None:
    wf = copy.deepcopy(load_ci())
    wf["jobs"]["unit"]["if"] = "needs.filter.outputs.nope == 'true'"
    assert problems(wf) == ["job 'unit' uses undefined filter output 'nope'"]
