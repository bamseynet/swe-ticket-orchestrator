"""Atlassian Document Format (ADF) helpers for the fake Jira (D6-01).

Source: https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/
(a document is ``{"type": "doc", "version": 1, "content": [block nodes]}``; a text node needs a
non-empty ``text``; list items live in lists, ``media`` in ``mediaSingle``). The node table below
is the subset the fake accepts, with the children each may hold; any other node or mark is
refused. Real Jira knows more nodes and applies further rules (attribute checks, nesting limits)
that are not modelled.
"""

from __future__ import annotations

from typing import Any

_BAD = "Operation value must be an Atlassian Document"
_INLINE = frozenset({"text", "hardBreak", "mention", "emoji", "inlineCard", "status", "date"})
_BLOCKS_IN_BLOCKS = frozenset({"paragraph", "bulletList", "orderedList", "codeBlock"})
# node type -> the child types it may hold
CHILDREN: dict[str, frozenset[str]] = {
    "paragraph": _INLINE,
    "heading": _INLINE,
    "codeBlock": frozenset({"text"}),
    "bulletList": frozenset({"listItem"}),
    "orderedList": frozenset({"listItem"}),
    "listItem": _BLOCKS_IN_BLOCKS,
    "blockquote": frozenset({"paragraph", "bulletList", "orderedList", "codeBlock"}),
    "panel": frozenset({"paragraph", "heading", "bulletList", "orderedList"}),
    "mediaSingle": frozenset({"media"}),
    "media": frozenset(),
    "rule": frozenset(),
    **{kind: frozenset() for kind in _INLINE if kind != "text"},
    "text": frozenset(),
}
TOP_LEVEL = frozenset(
    {
        "paragraph",
        "heading",
        "bulletList",
        "orderedList",
        "codeBlock",
        "blockquote",
        "rule",
        "panel",
        "mediaSingle",
    }
)
MARKS = frozenset({"strong", "em", "code", "strike", "underline", "link", "textColor"})
_ATTR_TEXT = {"mention": "text", "emoji": "text", "status": "text", "inlineCard": "url"}
_SEPARATOR = {
    "doc": "\n\n",
    "blockquote": "\n\n",
    "panel": "\n\n",
    "bulletList": "\n",
    "orderedList": "\n",
    "listItem": "\n",
}


def adf(text: str) -> dict[str, Any]:
    """A document of one paragraph per blank-line-separated chunk of ``text``."""
    chunks = [c for c in text.split("\n\n") if c]
    paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": c}]} for c in chunks]
    return {"type": "doc", "version": 1, "content": paragraphs}


def adf_to_text(node: Any) -> str:
    """Plain text of a document or node. Blocks are separated by a blank line (document, quote,
    panel) or a newline (lists and their items), so ``one`` and ``two`` never run together."""
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
    return _SEPARATOR.get(str(kind), "").join(parts)


def adf_error(doc: Any, *, require_content: bool) -> str | None:
    """Why ``doc`` is not a document the fake accepts, or None when it is."""
    if not isinstance(doc, dict) or doc.get("type") != "doc":
        return _BAD
    if doc.get("version") != 1 or not isinstance(doc.get("content"), list):
        return _BAD
    if require_content and not doc["content"]:
        return "Comment body is not valid!"
    for node in doc["content"]:
        if _node_error(node, TOP_LEVEL):
            return _BAD
    return None


def _node_error(node: Any, allowed: frozenset[str]) -> bool:
    if not isinstance(node, dict) or node.get("type") not in allowed:
        return True
    kind = str(node["type"])
    marks = node.get("marks") or []
    if not isinstance(marks, list):
        return True
    if any(not isinstance(m, dict) or m.get("type") not in MARKS for m in marks):
        return True
    if marks and kind != "text":
        return True
    if kind == "text" and (not isinstance(node.get("text"), str) or not node["text"]):
        return True
    content = node.get("content") or []
    if not isinstance(content, list):
        return True
    return any(_node_error(child, CHILDREN[kind]) for child in content)
