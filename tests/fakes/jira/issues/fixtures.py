"""Synthetic ADF bodies for tests (D6-01): names, URLs and IDs are all invented."""

from __future__ import annotations

from typing import Any

ACTIVE_CONTENT_ADF: dict[str, Any] = {
    "type": "doc",
    "version": 1,
    "content": [
        {
            "type": "paragraph",
            "content": [
                {
                    "type": "text",
                    "text": "click me",
                    "marks": [{"type": "link", "attrs": {"href": "javascript:alert(1)"}}],
                },
                {"type": "hardBreak"},
                {"type": "mention", "attrs": {"id": "5bsynthetic0009", "text": "@someone"}},
                {"type": "inlineCard", "attrs": {"url": "https://example.test/browse/SYN-1"}},
            ],
        },
        {
            "type": "mediaSingle",
            "content": [
                {
                    "type": "media",
                    "attrs": {"type": "external", "url": "https://example.test/x.png"},
                }
            ],
        },
        {"type": "codeBlock", "content": [{"type": "text", "text": "print('synthetic')"}]},
    ],
}
