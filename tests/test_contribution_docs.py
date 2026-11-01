"""D0-06: the contribution rules exist and carry the delivery rules in docs/STAGES.md."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
STAGES = (ROOT / "docs" / "STAGES.md").read_text()

# Standing acceptance criteria (STAGES.md), checked verbatim and case-sensitively.
STANDING_PHRASES = [
    "make test-changed",
    "make test T=",
    "`ci-required`",
    "hermetic",
    "`integration` or `ui_browser`",
    "never moved to a laptop",
]
NEW_WORKER_RULES = ["Workers never merge", "RESEARCH.md", "ADR-0014", "untrusted data"]


def delivery_rule_leads(stages: str) -> list[str]:
    """The bold lead of each numbered rule under '## Delivery rules' in STAGES.md."""
    match = re.search(r"^## Delivery rules\n(.*?)(?=^#{1,2} )", stages, re.S | re.M)
    assert match, "no '## Delivery rules' section in STAGES.md"
    leads = re.findall(r"^\d+\.\s+\*\*(.+?)\*\*", match.group(1), re.M)
    return [lead.rstrip(".,:") for lead in leads]


def missing_rules(doc_text: str, leads: list[str]) -> list[str]:
    return [lead for lead in leads if f"**{lead}" not in doc_text]


def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"{rel} is missing"
    return path.read_text()


def test_stages_has_ten_delivery_rules() -> None:
    assert len(delivery_rule_leads(STAGES)) == 10


def test_contributing_carries_every_delivery_rule() -> None:
    assert missing_rules(read("CONTRIBUTING.md"), delivery_rule_leads(STAGES)) == []


def test_rule_check_fails_when_a_rule_is_removed() -> None:
    leads = delivery_rule_leads(STAGES)
    for lead in leads:
        text = "\n".join(
            line for line in read("CONTRIBUTING.md").splitlines() if f"**{lead}" not in line
        )
        assert missing_rules(text, leads) == [lead]


@pytest.mark.parametrize("doc", ["CONTRIBUTING.md", "CLAUDE.md"])
@pytest.mark.parametrize("phrase", STANDING_PHRASES)
def test_standing_criteria_present(doc: str, phrase: str) -> None:
    assert phrase in read(doc)


@pytest.mark.parametrize("doc", ["CONTRIBUTING.md", "CLAUDE.md"])
@pytest.mark.parametrize("phrase", NEW_WORKER_RULES)
def test_worker_rules_present(doc: str, phrase: str) -> None:
    assert phrase in read(doc)


def test_claude_md_does_not_ban_live_work_outright() -> None:
    text = read("CLAUDE.md")
    assert "labelled `live`" in text
    assert "D12" in text


def test_issue_forms_apply_type_labels() -> None:
    # The repo needs these labels to exist (created with `gh label create`; not checkable offline).
    for form in (ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"):
        if form.name != "config.yml":
            labels = yaml.safe_load(form.read_text()).get("labels", [])
            assert labels
            assert all(label.startswith("type:") for label in labels)


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
