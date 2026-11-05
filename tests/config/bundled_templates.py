"""The bundled templates (D2-05) as an importable helper, so later suites run against all of them.

    from bundled_templates import BUNDLED, flattened, policy

    @pytest.mark.parametrize("name", BUNDLED)
    def test_something(name: str) -> None:
        wf = flattened(name)

Everything goes through the real loaders and ``flatten``; nothing here restates a rule.
"""

from __future__ import annotations

from pathlib import Path

from sto.config.overlays import flatten
from sto.config.schema import OrgPolicy, Workflow, WorkflowOverlay, load_document

__all__ = [
    "BUNDLED",
    "OVERLAY_NAMES",
    "ROOT",
    "SANDBOX_IMAGES",
    "TEAM",
    "TEMPLATES",
    "TEMPLATE_REF",
    "flattened",
    "overlay",
    "policy",
    "template",
    "template_file",
]

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "templates"
TEMPLATE_REF = "standard@1"
BUNDLED = ("standard", "kanban", "regulated")  # pytest-ready: parametrize("name", BUNDLED)
OVERLAY_NAMES = ("kanban", "regulated")
TEAM = {"kanban": "platform", "regulated": "ledger"}  # the team each overlay is written for
SANDBOX_IMAGES = frozenset({"java21", "go1"})  # the registry the overlays' repos name


def template_file(name: str) -> Path:
    return TEMPLATES / name / ("workflow.yaml" if name == "standard" else "overlay.yaml")


def _load(path: Path) -> object:
    return load_document(path.read_text(encoding="utf-8"), source=str(path.relative_to(ROOT)))


def template() -> Workflow:
    doc = _load(template_file("standard"))
    assert isinstance(doc, Workflow)
    return doc


def overlay(name: str) -> WorkflowOverlay:
    doc = _load(template_file(name))
    assert isinstance(doc, WorkflowOverlay)
    return doc


def policy() -> OrgPolicy:
    doc = _load(TEMPLATES / "org-policy.yaml")
    assert isinstance(doc, OrgPolicy)
    return doc


def flattened(name: str) -> Workflow:
    """The workflow as it would be published: ``standard`` itself, or an overlay flattened on it."""
    if name == "standard":
        return template()
    return flatten(template(), overlay(name), template_ref=TEMPLATE_REF).workflow
