"""D0-06: the contribution rules exist and carry the delivery rules in docs/STAGES.md."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
STAGES = (ROOT / "docs" / "STAGES.md").read_text()

# One phrase per delivery rule (STAGES.md "Delivery rules") and standing criterion.
RULE_PHRASES = [
    "No stacked PRs",
    "One issue, one PR",
    "Tests first",
    "Independent review",
    "capped at 3 rounds",
    "Gate suite",
    "Hermetic",
    "Unverified until D12",
    "Nothing real is committed",
    "lockfiles",
    "make test-changed",
    "make test T=",
    "ci-required",
    "Declared files",
    "never moved to a laptop",
]


def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"{rel} is missing"
    return path.read_text()


@pytest.mark.parametrize("doc", ["CONTRIBUTING.md", "CLAUDE.md"])
@pytest.mark.parametrize("phrase", RULE_PHRASES)
def test_rules_doc_carries_rule(doc: str, phrase: str) -> None:
    assert phrase.lower() in read(doc).lower()


def test_delivery_rules_are_still_those_in_stages() -> None:
    # If STAGES.md changes its rules, this reminds us to update the docs.
    assert "Review loops are capped at 3 rounds" in STAGES
    assert "**Independent review on every PR,**" in STAGES


def test_pr_template_requires_key_sections() -> None:
    text = read(".github/PULL_REQUEST_TEMPLATE.md")
    for needle in [
        "Closes #",
        "## Acceptance criteria",
        "## Unverified until D12",
        "## Independent review",
        "## Files outside the issue's declared list",
        "ci-required",
    ]:
        assert needle in text, needle


def test_issue_templates_are_valid_forms() -> None:
    folder = ROOT / ".github" / "ISSUE_TEMPLATE"
    forms = sorted(folder.glob("*.yml"))
    assert len(forms) >= 2
    for form in forms:
        data = yaml.safe_load(form.read_text())
        if form.name == "config.yml":
            assert "blank_issues_enabled" in data
            continue
        assert {"name", "description", "body"} <= set(data), form.name
        assert all("type" in item for item in data["body"]), form.name
        ids = [i["id"] for i in data["body"] if "id" in i]
        assert len(ids) == len(set(ids)), form.name
