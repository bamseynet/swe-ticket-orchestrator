"""Atlassian Document Format (ADF) helpers for the fake Jira (D6-01).

Source: https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/
(a document is ``{"type": "doc", "version": 1, "content": [block nodes]}``; a text node needs a
non-empty ``text``). The node list below is the subset the fake accepts; any other type is refused,
which is the departure to remember: real Jira knows more nodes and applies further nesting rules
that are not modelled.
"""

from __future__ import annotations

from typing import Any

BLOCKS = frozenset(
    {
        "paragraph",
        "heading",
        "bulletList",
        "orderedList",
        "listItem",
        "codeBlock",
        "blockquote",
        "rule",
        "panel",
        "mediaSingle",
        "media",
    }
)
INLINES = frozenset({"text", "hardBreak", "mention", "emoji", "inlineCard", "status", "date"})
MARKS = frozenset({"strong", "em", "code", "strike", "underline", "link", "textColor"})
_ATTR_TEXT = {"mention": "text", "emoji": "text", "status": "text", "inlineCard": "url"}


def adf(text: str) -> dict[str, Any]:
    """A document of one paragraph per blank-line-separated chunk of ``text``."""
    chunks = [c for c in text.split("\n\n") if c]
    paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": c}]} for c in chunks]
    return {"type": "doc", "version": 1, "content": paragraphs}


def adf_to_text(node: Any) -> str:
    """Plain text of a document or node: text nodes, paragraphs split by a blank line."""
    if not isinstance(node, dict):
        return ""
    kind = node.get("type")
    if kind == "text":
        return str(node.get("text", ""))
    if kind == "hardBreak":
        return "\n"
    attrs = node.get("attrs") or {}
    if kind in _ATTR_TEXT and isinstance(attrs, dict):
        return str(attrs.get(_ATTR_TEXT[str(kind)], ""))
    parts = [adf_to_text(child) for child in node.get("content") or []]
    return ("\n\n" if kind in ("doc", "listItem") else "").join(parts)


def adf_error(doc: Any, *, require_content: bool) -> str | None:
    """Why ``doc`` is not a document the fake accepts, or None when it is."""
    if not isinstance(doc, dict) or doc.get("type") != "doc":
        return "Operation value must be an Atlassian Document"
    if doc.get("version") != 1 or not isinstance(doc.get("content"), list):
        return "Operation value must be an Atlassian Document"
    if require_content and not doc["content"]:
        return "Comment body is not valid!"
    for node in doc["content"]:
        problem = _node_error(node, top=True)
        if problem:
            return problem
    return None


def _node_error(node: Any, *, top: bool) -> str | None:
    bad = "Operation value must be an Atlassian Document"
    if not isinstance(node, dict):
        return bad
    kind = node.get("type")
    if kind not in BLOCKS | INLINES or (top and kind not in BLOCKS):
        return bad
    for mark in node.get("marks") or []:
        if not isinstance(mark, dict) or mark.get("type") not in MARKS:
            return bad
    if kind == "text" and (not isinstance(node.get("text"), str) or not node["text"]):
        return bad
    content = node.get("content") or []
    if not isinstance(content, list) or (kind == "text" and content):
        return bad
    for child in content:
        problem = _node_error(child, top=False)
        if problem:
            return problem
    return None
